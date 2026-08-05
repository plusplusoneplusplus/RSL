//! Deterministic fuzz smoke test for the framing decoders — stable toolchain,
//! always on in CI. The `fuzz/` cargo-fuzz target (`packet_decode`) asserts the
//! same invariants under coverage guidance; this is the floor.
//!
//! Invariants:
//!
//! 1. **No panic** on any input, for either framing.
//! 2. **Whatever is accepted re-encodes to the bytes it came from** — a decoder
//!    that accepts a frame it could not have produced is a desync bug.
//! 3. **Bounded allocation**: a header announcing a legal-but-huge frame must
//!    not cost memory until the bytes actually arrive.

mod common;

use std::io::{Cursor, Read};

use rsl_net::framing::{learn, packet};
use rsl_net::{Limits, ReadError};
use rsl_wire::MsgKind;

/// Tiny deterministic xorshift64* PRNG (no `rand` dep, reproducible in CI).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

fn check_packets(bytes: &[u8], limits: Limits) {
    let mut packets = packet::Packets::new(bytes, limits);
    let mut rebuilt = Vec::new();
    for item in packets.by_ref() {
        match item {
            Ok((hdr, payload)) => {
                assert!(hdr.size_in_range(&limits), "accepted an out-of-range size");
                assert_eq!(
                    hdr.size as usize,
                    packet::HDR_LEN + payload.len(),
                    "payload length disagrees with the header"
                );
                // The dead header fields are checksummed, so a frame that has
                // them set (only a fuzzer produces one) needs them carried over.
                rebuilt.extend_from_slice(&packet::encode_packet_with(
                    hdr.proto_version,
                    hdr.xid,
                    payload,
                ));
            }
            Err(_) => break,
        }
    }
    let consumed = packets.consumed();
    assert_eq!(
        rebuilt,
        bytes[..consumed],
        "accepted frames do not re-encode to their own bytes"
    );

    // The blocking reader must reach the same verdict on the same bytes.
    let mut cursor = Cursor::new(bytes.to_vec());
    let mut reader_consumed = 0usize;
    while let Ok(Some((hdr, _))) = packet::read_packet(&mut cursor, &limits) {
        reader_consumed += hdr.size as usize;
    }
    assert_eq!(reader_consumed, consumed, "reader and decoder disagree");
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x2f61_a1c3_9d4e_5b07);
    let small = Limits::from_config_mb(1, 0).unwrap();

    for i in 0..60_000u32 {
        let len = (rng.next() % 200) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(rng.byte());
        }
        let limits = if i % 3 == 0 { small } else { Limits::default() };
        check_packets(&buf, limits);
        let _ = learn::parse_message(&buf, MsgKind::Base, small.effective_max());
    }
}

/// Mutating any byte of a valid frame must never yield a *different* accepted
/// packet: every byte is inside the checksum's domain except the checksum field
/// itself, which is compared.
#[test]
fn single_byte_mutations_never_produce_a_different_packet() {
    let mut rng = Rng(0x51ed_270b_5b3d_1f19);
    let limits = Limits::default();

    for len in [0usize, 1, 7, 64, 300] {
        let payload: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let frame = packet::encode_packet(&payload);
        for i in 0..frame.len() {
            for bit in [0x01u8, 0x80] {
                let mut mutated = frame.clone();
                mutated[i] ^= bit;
                if let Ok(packet::Step::Packet { payload: got, .. }) =
                    packet::decode_packet(&mutated, &limits)
                {
                    assert_eq!(got, &payload[..], "mutation at {i} changed the payload");
                    assert_eq!(mutated, frame, "a mutated frame verified");
                }
            }
        }
    }
}

/// A reader that hands out one byte at a time and counts what was pulled: a
/// hostile size field must not cause the whole frame to be read or allocated.
struct StingyReader<'a> {
    data: &'a [u8],
    served: usize,
}

impl Read for StingyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.served >= self.data.len() || buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.data[self.served];
        self.served += 1;
        Ok(1)
    }
}

#[test]
fn a_huge_declared_size_costs_nothing_until_the_bytes_arrive() {
    // 100 MB announced, 20 bytes delivered.
    let mut header = packet::encode_packet(&[]);
    header[0..4].copy_from_slice(&(100u32 * 1024 * 1024).to_le_bytes());

    // Under the default cap the size is legal, so the decoder asks for more
    // rather than rejecting -- and asks without touching memory.
    let limits = Limits::default();
    assert!(matches!(
        packet::decode_packet(&header, &limits),
        Ok(packet::Step::NeedMore { needed }) if needed == 100 * 1024 * 1024
    ));

    // The blocking reader stops at EOF having pulled only the bytes that exist.
    let mut reader = StingyReader {
        data: &header,
        served: 0,
    };
    let result = packet::read_packet(&mut reader, &limits);
    assert!(
        matches!(result, Err(ReadError::UnexpectedEof)),
        "{result:?}"
    );
    assert_eq!(reader.served, header.len(), "read past the available bytes");

    // With a 1 MB cap configured, the same header is rejected outright.
    let capped = Limits::from_config_mb(1, 0).unwrap();
    assert!(matches!(
        packet::decode_packet(&header, &capped),
        Err(packet::FrameError::InvalidSize { .. })
    ));

    // Same shape on the learn port: a 2 GB length is refused from six bytes.
    let mut head = [0u8; learn::HDR_LEN];
    head[0..2].copy_from_slice(&6u16.to_le_bytes());
    head[2..6].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    let mut reader = StingyReader {
        data: &head,
        served: 0,
    };
    assert!(matches!(
        learn::read_message(&mut reader, MsgKind::Base, capped.effective_max()),
        Err(ReadError::Framing(learn::LearnError::TooLarge { .. }))
    ));
    assert_eq!(reader.served, head.len());
}

/// Corpus-seeded mutations: start from the real frames the C++ produced.
#[test]
fn corpus_mutations_never_panic() {
    let (packets, learns, _) = common::load();
    let mut rng = Rng(0x7b41_9c2a_0e5d_3311);

    for vector in &packets {
        let limits = Limits::from_raw(vector.max_size, vector.max_alert);
        for _ in 0..200 {
            let mut bytes = vector.bytes.clone();
            if !bytes.is_empty() {
                let n = (rng.next() % 4) as usize + 1;
                for _ in 0..n {
                    let i = (rng.next() as usize) % bytes.len();
                    bytes[i] ^= rng.byte();
                }
            }
            check_packets(&bytes, limits);
        }
    }

    for vector in &learns {
        for _ in 0..200 {
            let mut bytes = vector.bytes.clone();
            if !bytes.is_empty() {
                let i = (rng.next() as usize) % bytes.len();
                bytes[i] ^= rng.byte();
            }
            let _ = learn::parse_message(&bytes, MsgKind::Base, vector.max_size);
            let _ = learn::parse_message_checked(&bytes, MsgKind::Base, vector.max_size);
        }
    }
}
