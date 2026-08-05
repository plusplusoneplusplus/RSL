//! Property tests for both framings.
//!
//! These cover the shapes the golden corpus cannot enumerate: arbitrary
//! payloads, arbitrary packet counts per read buffer, and arbitrary TCP-style
//! chunk boundaries.

use std::io::{Cursor, Read};

use proptest::prelude::*;
use rsl_net::framing::{learn, packet};
use rsl_net::{Limits, ReadError};
use rsl_wire::messages::MSG_STATUS_QUERY;
use rsl_wire::{BallotNumber, Header, MemberId, Msg, MsgKind, ProtocolVersion};

/// A reader that serves the stream in fixed-size chunks — the shape a real
/// socket has, where one `read` rarely lines up with one frame.
struct ChunkedReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl Read for ChunkedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn base_message(decree: u64) -> Msg {
    Msg::Base(Header::new(
        ProtocolVersion::V6,
        MSG_STATUS_QUERY,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(3, MemberId::from_str("202")),
        0,
    ))
}

proptest! {
    /// encode → decode is the identity on payloads.
    #[test]
    fn packet_round_trips(payload in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let frame = packet::encode_packet(&payload);
        prop_assert_eq!(frame.len(), packet::HDR_LEN + payload.len());

        let limits = Limits::default();
        match packet::decode_packet(&frame, &limits) {
            Ok(packet::Step::Packet { hdr, payload: got }) => {
                prop_assert_eq!(got, &payload[..]);
                prop_assert_eq!(hdr.size as usize, frame.len());
                // The two dead header fields stay zero on the wire.
                prop_assert_eq!(hdr.proto_version, 0);
                prop_assert_eq!(hdr.xid, 0);
            }
            other => prop_assert!(false, "own frame did not decode: {:?}", other),
        }
    }

    /// Any number of packets may share a read buffer, and the decoder must
    /// return them all, in order, with nothing left over.
    #[test]
    fn many_packets_in_one_buffer(
        payloads in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..64), 0..16)
    ) {
        let mut buf = Vec::new();
        for payload in &payloads {
            buf.extend_from_slice(&packet::encode_packet(payload));
        }

        let limits = Limits::default();
        let mut packets = packet::Packets::new(&buf, limits);
        let decoded: Vec<Vec<u8>> = packets
            .by_ref()
            .map(|item| item.expect("valid frame").1.to_vec())
            .collect();

        prop_assert_eq!(decoded, payloads);
        prop_assert_eq!(packets.consumed(), buf.len());
        prop_assert!(packets.remainder().is_empty());
    }

    /// Truncating a stream anywhere yields "need more", never a rejection and
    /// never a bogus packet.
    #[test]
    fn truncation_is_always_need_more(
        payload in proptest::collection::vec(any::<u8>(), 0..512),
        cut in 0usize..512,
    ) {
        let frame = packet::encode_packet(&payload);
        let cut = cut.min(frame.len().saturating_sub(1));
        let limits = Limits::default();

        match packet::decode_packet(&frame[..cut], &limits) {
            Ok(packet::Step::NeedMore { needed }) => {
                prop_assert!(needed >= packet::HDR_LEN);
                prop_assert!(needed > cut);
            }
            other => prop_assert!(false, "truncation at {} gave {:?}", cut, other),
        }
    }

    /// Chunk boundaries are invisible to the blocking reader.
    #[test]
    fn chunked_reads_reassemble(
        payloads in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128), 1..6),
        chunk in 1usize..97,
    ) {
        let mut data = Vec::new();
        for payload in &payloads {
            data.extend_from_slice(&packet::encode_packet(payload));
        }
        let mut reader = ChunkedReader { data, pos: 0, chunk };

        let limits = Limits::default();
        let mut got = Vec::new();
        while let Some((_, payload)) = packet::read_packet(&mut reader, &limits)
            .map_err(|e| TestCaseError::fail(format!("{e}")))?
        {
            got.push(payload);
        }
        prop_assert_eq!(got, payloads);
    }

    /// The cap is enforced on the announced size, whatever the real length is.
    #[test]
    fn the_cap_rejects_by_the_header_alone(size in 0u32..=u32::MAX, max_mb in 1u32..64) {
        let limits = Limits::from_config_mb(max_mb, 0).unwrap();
        let mut frame = packet::encode_packet(&[]);
        frame[0..4].copy_from_slice(&size.to_le_bytes());

        let in_range = size >= packet::HDR_LEN as u32 && size <= limits.effective_max();
        let decoded = packet::decode_packet(&frame, &limits);
        prop_assert_eq!(
            matches!(decoded, Err(packet::FrameError::InvalidSize { .. })),
            !in_range
        );
    }

    /// Learn port: a marshaled message is its own frame, and reading it back
    /// through the blocking reader reproduces it.
    #[test]
    fn learn_round_trips(decree in any::<u64>(), trailing in 0usize..16) {
        let msg = base_message(decree);
        let mut stream = learn::encode_message(&msg).unwrap();
        let len = stream.len();
        stream.extend(std::iter::repeat_n(0xaa, trailing));

        let (parsed, consumed) =
            learn::parse_message(&stream, MsgKind::Base, 1024 * 1024).unwrap();
        prop_assert_eq!(consumed, len);
        prop_assert_eq!(learn::encode_message(&parsed).unwrap(), &stream[..len]);

        let mut cursor = Cursor::new(stream);
        let read = learn::read_message(&mut cursor, MsgKind::Base, 1024 * 1024).unwrap();
        prop_assert!(read.is_some());
    }

    /// Learn port: arbitrary bytes never panic, and a rejection is always one
    /// of the documented reasons.
    #[test]
    fn learn_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = learn::parse_message(&bytes, MsgKind::Base, 1024);
        let mut cursor = Cursor::new(bytes);
        match learn::read_message(&mut cursor, MsgKind::Base, 1024) {
            Ok(_) | Err(ReadError::UnexpectedEof) | Err(ReadError::Framing(_)) => {}
            Err(ReadError::Io(e)) => prop_assert!(false, "unexpected io error: {}", e),
        }
    }
}
