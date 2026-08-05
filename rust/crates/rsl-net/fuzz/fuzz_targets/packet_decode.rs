//! Coverage-guided fuzz target for the packet decoder.
//!
//! ```sh
//! cargo install cargo-fuzz
//! cd rust/crates/rsl-net
//! cargo +nightly fuzz run packet_decode
//! ```
//!
//! Invariants (the same ones `tests/fuzz_smoke.rs` asserts on stable):
//!
//! * arbitrary bytes never panic the decoder or the blocking reader;
//! * anything accepted re-encodes to exactly the bytes it was decoded from;
//! * allocation stays bounded — a header announcing a 100 MB frame costs
//!   nothing until those bytes arrive, so libFuzzer's `-rss_limit_mb` is a real
//!   check here.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use rsl_net::framing::packet;
use rsl_net::Limits;

fuzz_target!(|data: &[u8]| {
    // First byte selects the cap so both the default and a small configured
    // limit get exercised; the rest is the stream.
    let (Some(&sel), Some(buf)) = (data.first(), data.get(1..)) else {
        return;
    };
    let limits = match sel % 3 {
        0 => Limits::default(),
        1 => Limits::from_config_mb(1, 0).unwrap(),
        _ => Limits::from_raw(64, 32),
    };

    let mut packets = packet::Packets::new(buf, limits);
    let mut rebuilt = Vec::new();
    for item in packets.by_ref() {
        match item {
            Ok((hdr, payload)) => {
                assert!(hdr.size_in_range(&limits));
                assert_eq!(hdr.size as usize, packet::HDR_LEN + payload.len());
                // The two dead header fields are inside the checksum's domain, so
                // reproducing a frame means carrying them over. RSL only ever
                // sends zeroes there; a fuzzer does not.
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
    assert_eq!(rebuilt, buf[..consumed], "accepted frames do not re-encode");

    // The blocking reader must agree with the slice decoder byte for byte.
    let mut cursor = Cursor::new(buf.to_vec());
    let mut reader_consumed = 0usize;
    while let Ok(Some((hdr, _))) = packet::read_packet(&mut cursor, &limits) {
        reader_consumed += hdr.size as usize;
    }
    assert_eq!(reader_consumed, consumed, "reader and decoder disagree");
});
