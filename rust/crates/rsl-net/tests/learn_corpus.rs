//! Phase-4a `LEARN` corpus: `Message::ReadFromSocket`'s decision table,
//! vector by vector.
//!
//! The C++ reads every learn-port stream into a plain `Message`, so these
//! parse with [`MsgKind::Base`] — including the `StatusResponse` vector, which
//! the base parser accepts by reading just the header (as the C++ does).

mod common;

use std::io::Cursor;

use rsl_net::framing::learn::{self, LearnError};
use rsl_net::ReadError;
use rsl_wire::MsgKind;

fn outcome_name(result: &Result<(rsl_wire::Msg, usize), LearnError>) -> &'static str {
    match result {
        Ok(_) => "accept",
        Err(LearnError::ShortHeader) => "reject-short-header",
        Err(LearnError::BadVersion(_)) => "reject-version",
        Err(LearnError::TooLarge { .. }) => "reject-too-large",
        // The C++ port reports both of these as a short body: for a length below
        // the 6-byte header it never gets to allocate (see LengthBelowHeader).
        Err(LearnError::ShortBody { .. }) | Err(LearnError::LengthBelowHeader { .. }) => {
            "reject-short-body"
        }
        Err(LearnError::Unmarshal) => "reject-unmarshal",
        Err(LearnError::Checksum) => "reject-checksum",
    }
}

#[test]
fn every_learn_vector_matches_the_cpp_decision() {
    let (_, learns, _) = common::load();

    for vector in &learns {
        let result = learn::parse_message(&vector.bytes, MsgKind::Base, vector.max_size);
        assert_eq!(
            outcome_name(&result),
            vector.outcome,
            "{}: outcome ({result:?})",
            vector.desc
        );

        if let Ok((_, consumed)) = &result {
            // Exactly `length` bytes are consumed; trailing bytes stay put.
            assert_eq!(
                *consumed, vector.msg_len as usize,
                "{}: consumed",
                vector.desc
            );
            assert!(vector.bytes.len() >= *consumed, "{}: overrun", vector.desc);
        }
    }
}

/// The 6-byte header parse must agree with the C++ on the version and length it
/// extracted, wherever the C++ got that far.
#[test]
fn header_fields_match_wherever_the_cpp_parsed_them() {
    let (_, learns, _) = common::load();

    for vector in &learns {
        if vector.outcome == "reject-short-header" {
            continue; // the C++ never parsed a header here
        }
        let raw_version = u16::from_le_bytes(vector.bytes[0..2].try_into().unwrap());
        let raw_len = u32::from_le_bytes(vector.bytes[2..6].try_into().unwrap());
        assert_eq!(raw_version, vector.version, "{}: version", vector.desc);
        assert_eq!(raw_len, vector.msg_len, "{}: length", vector.desc);
    }
}

/// Vectors the C++ could not be run on safely (`EXEC no`) are exactly the
/// documented divergence — a length below the 6-byte framing header, where the
/// original overflows its allocation.
#[test]
fn non_executed_vectors_are_the_documented_divergence() {
    let (_, learns, _) = common::load();

    let diverging: Vec<_> = learns.iter().filter(|v| !v.executed).collect();
    assert_eq!(diverging.len(), 1, "unexpected set of EXEC-no vectors");

    for vector in diverging {
        assert!(
            matches!(
                learn::parse_message(&vector.bytes, MsgKind::Base, vector.max_size),
                Err(LearnError::LengthBelowHeader { .. })
            ),
            "{}: expected LengthBelowHeader",
            vector.desc
        );
    }
}

/// A wrong message checksum is accepted by the C++ (it never verifies) and by
/// [`learn::parse_message`] — but `parse_message_checked` catches it.
#[test]
fn checksum_verification_is_opt_in() {
    let (_, learns, _) = common::load();

    let vector = learns
        .iter()
        .find(|v| v.desc.contains("wrong message checksum"))
        .expect("corpus has the wrong-checksum vector");

    assert_eq!(vector.outcome, "accept");
    assert!(learn::parse_message(&vector.bytes, MsgKind::Base, vector.max_size).is_ok());
    assert_eq!(
        learn::parse_message_checked(&vector.bytes, MsgKind::Base, vector.max_size).err(),
        Some(LearnError::Checksum)
    );
}

#[test]
fn the_blocking_reader_agrees_with_the_slice_parser() {
    let (_, learns, _) = common::load();

    for vector in &learns {
        let mut cursor = Cursor::new(vector.bytes.clone());
        let read = learn::read_message(&mut cursor, MsgKind::Base, vector.max_size);

        match vector.outcome.as_str() {
            "accept" => assert!(read.is_ok(), "{}: {read:?}", vector.desc),
            // Too few bytes for the header is a clean close if there are none at
            // all, and a torn frame otherwise.
            "reject-short-header" => assert!(
                matches!(read, Ok(None) | Err(ReadError::UnexpectedEof)),
                "{}: {read:?}",
                vector.desc
            ),
            "reject-short-body" => assert!(
                matches!(read, Err(ReadError::UnexpectedEof))
                    || matches!(
                        read,
                        Err(ReadError::Framing(LearnError::LengthBelowHeader { .. }))
                    ),
                "{}: {read:?}",
                vector.desc
            ),
            "reject-version" => assert!(
                matches!(read, Err(ReadError::Framing(LearnError::BadVersion(_)))),
                "{}: {read:?}",
                vector.desc
            ),
            "reject-too-large" => assert!(
                matches!(read, Err(ReadError::Framing(LearnError::TooLarge { .. }))),
                "{}: {read:?}",
                vector.desc
            ),
            "reject-unmarshal" => assert!(
                matches!(read, Err(ReadError::Framing(LearnError::Unmarshal))),
                "{}: {read:?}",
                vector.desc
            ),
            other => panic!("{}: unknown outcome {other}", vector.desc),
        }
    }
}

/// Round-trip: a corpus message written for the learn port is its own framing.
#[test]
fn encoding_for_the_learn_port_is_the_bare_message() {
    let (_, learns, _) = common::load();

    let vector = learns
        .iter()
        .find(|v| v.desc.contains("a whole StatusResponse"))
        .expect("corpus has the StatusResponse vector");

    let (msg, consumed) =
        learn::parse_message(&vector.bytes, MsgKind::StatusResponse, vector.max_size)
            .expect("parses as a StatusResponse");
    assert_eq!(consumed, vector.bytes.len());
    assert_eq!(learn::encode_message(&msg).unwrap(), vector.bytes);
}
