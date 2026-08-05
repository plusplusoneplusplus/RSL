//! Phase-4a `PACKET` corpus: every byte stream the C++ receive path was run
//! over must produce the same decision here — and every accepted packet must be
//! re-encodable to the exact bytes the C++ produced.

mod common;

use std::io::Cursor;

use rsl_net::framing::packet::{self, FrameError, Packets};
use rsl_net::{Limits, ReadError};

/// Replay one vector through the streaming decoder, returning the C++'s outcome
/// vocabulary plus what was decoded.
fn replay(bytes: &[u8], limits: Limits) -> (String, usize, Vec<Vec<u8>>, Option<FrameError>) {
    let mut packets = Packets::new(bytes, limits);
    let mut payloads = Vec::new();
    let mut error = None;
    for item in packets.by_ref() {
        match item {
            Ok((_, payload)) => payloads.push(payload.to_vec()),
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    let consumed = packets.consumed();

    let outcome = match error {
        Some(FrameError::InvalidSize { .. }) => "reject-header",
        Some(FrameError::Checksum { .. }) => "reject-checksum",
        // `NetCxn::ReadReadyInternal` reports Accept only when the buffer was
        // drained exactly; a trailing partial packet leaves the connection open.
        None if !payloads.is_empty() && consumed == bytes.len() => "accept",
        None => "need-more",
    };
    (outcome.to_string(), consumed, payloads, error)
}

#[test]
fn every_packet_vector_matches_the_cpp_decision() {
    let (packets, _, _) = common::load();

    for vector in &packets {
        let limits = Limits::from_raw(vector.max_size, vector.max_alert);
        let (outcome, consumed, payloads, error) = replay(&vector.bytes, limits);

        assert_eq!(outcome, vector.outcome, "{}: outcome", vector.desc);
        assert_eq!(consumed, vector.consumed, "{}: consumed", vector.desc);
        assert_eq!(payloads, vector.payloads, "{}: payloads", vector.desc);

        // The reject reason is reported in the C++'s own wording, so the whole
        // string is comparable (the corpus may prefix an alert note).
        if let Some(error) = error {
            let rendered = error.to_string();
            assert!(
                vector.detail.ends_with(&rendered),
                "{}: detail {:?} does not end with {:?}",
                vector.desc,
                vector.detail,
                rendered
            );
        }
    }
}

#[test]
fn every_accepted_packet_re_encodes_byte_for_byte() {
    let (packets, _, _) = common::load();

    for vector in &packets {
        if vector.payloads.is_empty() {
            continue;
        }
        let mut rebuilt = Vec::new();
        for payload in &vector.payloads {
            rebuilt.extend_from_slice(&packet::encode_packet(payload));
        }
        assert_eq!(
            rebuilt,
            vector.bytes[..vector.consumed],
            "{}: re-encoded frames differ",
            vector.desc
        );
    }
}

#[test]
fn the_alert_threshold_logs_but_never_rejects() {
    let (packets, _, _) = common::load();

    for vector in &packets {
        let limits = Limits::from_raw(vector.max_size, vector.max_alert);
        let alerted = vector.detail.contains("alert:");
        if alerted {
            // The C++ alerted, so this vector must be over the threshold here
            // too — and must still have been accepted.
            let hdr = packet::PacketHdr::decode(&vector.bytes).expect("header");
            assert!(limits.alerts_on(hdr.size), "{}: alert", vector.desc);
            assert_eq!(vector.outcome, "accept", "{}: alert rejected", vector.desc);
        }
    }
}

/// The same vectors through the blocking reader, which enforces the cap before
/// it sizes anything from the header.
#[test]
fn the_blocking_reader_agrees_with_the_streaming_decoder() {
    let (packets, _, _) = common::load();

    for vector in &packets {
        let limits = Limits::from_raw(vector.max_size, vector.max_alert);
        let mut cursor = Cursor::new(vector.bytes.clone());

        let mut read = Vec::new();
        let error = loop {
            match packet::read_packet(&mut cursor, &limits) {
                Ok(Some((_, payload))) => read.push(payload),
                Ok(None) => break None,
                Err(e) => break Some(e),
            }
        };

        // Whatever the stream decoder accepted, the reader accepted too.
        assert_eq!(read, vector.payloads, "{}: payloads", vector.desc);

        match vector.outcome.as_str() {
            "accept" => assert!(error.is_none(), "{}: unexpected error", vector.desc),
            // A partial frame is EOF to a blocking reader: same "no packet
            // delivered", reached by running out of bytes rather than by
            // running out of buffer.
            "need-more" => assert!(
                error.is_none() || matches!(error, Some(ReadError::UnexpectedEof)),
                "{}: expected eof, got {error:?}",
                vector.desc
            ),
            "reject-header" => assert!(
                matches!(
                    error,
                    Some(ReadError::Framing(FrameError::InvalidSize { .. }))
                ),
                "{}: expected InvalidSize, got {error:?}",
                vector.desc
            ),
            "reject-checksum" => assert!(
                matches!(error, Some(ReadError::Framing(FrameError::Checksum { .. }))),
                "{}: expected Checksum, got {error:?}",
                vector.desc
            ),
            other => panic!("{}: unknown outcome {other}", vector.desc),
        }
    }
}

/// Corpus messages framed by this crate must be byte-identical to the C++'s
/// frames for the same payload — the send direction of the interop.
#[test]
fn framing_a_corpus_message_reproduces_the_cpp_frame() {
    let (packets, _, messages) = common::load();
    assert!(!messages.is_empty(), "corpus has no RECORD blocks");

    let mut checked = 0;
    for vector in &packets {
        if vector.payloads.len() != 1 {
            continue;
        }
        let payload = &vector.payloads[0];
        if !messages.iter().any(|m| &m.bytes == payload) {
            continue; // a synthetic payload, covered by the re-encode test
        }
        assert_eq!(
            packet::encode_packet(payload),
            vector.bytes[..vector.consumed],
            "{}: frame differs",
            vector.desc
        );
        checked += 1;
    }
    assert!(
        checked >= 7,
        "expected one packet per message type, got {checked}"
    );
}
