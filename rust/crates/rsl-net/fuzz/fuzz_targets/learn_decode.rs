//! Coverage-guided fuzz target for the learn-port framing
//! (`Message::ReadFromSocket`).
//!
//! ```sh
//! cd rust/crates/rsl-net
//! cargo +nightly fuzz run learn_decode
//! ```
//!
//! Invariants: arbitrary bytes never panic; an accepted message consumes
//! exactly its own length field and reaches a byte fixpoint under
//! marshal/parse; and the blocking reader reaches the same verdict as the slice
//! parser.
//!
//! Note the fixpoint is *not* "re-marshals to the input bytes": a message whose
//! length field is larger than its canonical marshaled length parses (both here
//! and in the C++, which checks only `un_marshal_len >= GetBaseSize()`) and is
//! re-emitted at its canonical length.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use rsl_net::framing::learn;
use rsl_wire::{MarshalError, MsgKind};

const KINDS: [MsgKind; 7] = [
    MsgKind::Base,
    MsgKind::Vote,
    MsgKind::Join,
    MsgKind::Prepare,
    MsgKind::PrepareAccepted,
    MsgKind::StatusResponse,
    MsgKind::Bootstrap,
];

fuzz_target!(|data: &[u8]| {
    let (Some(&sel), Some(buf)) = (data.first(), data.get(1..)) else {
        return;
    };
    let kind = KINDS[sel as usize % KINDS.len()];
    let max = 1024 * 1024;

    let parsed = learn::parse_message(buf, kind, max);
    if let Ok((msg, consumed)) = &parsed {
        assert!(*consumed <= buf.len());
        match learn::encode_message(msg) {
            Ok(bytes) => {
                // What this crate writes must be re-readable by this crate, and
                // re-reading it must reach a fixpoint.
                let (msg2, consumed2) =
                    learn::parse_message(&bytes, kind, max).expect("own output did not re-parse");
                assert_eq!(consumed2, bytes.len(), "own output has a stale length field");
                assert_eq!(
                    learn::encode_message(&msg2).expect("re-marshal"),
                    bytes,
                    "not idempotent under marshal/parse"
                );
            }
            // The one accepted-but-unwritable shape inherited from rsl-wire: a
            // reconfiguration vote with trailing bytes.
            Err(MarshalError::ReconfigurationVoteWithRequests) => {}
            Err(e) => panic!("unexpected marshal error: {e}"),
        }
    }

    let mut cursor = Cursor::new(buf.to_vec());
    // `Ok(None)` is the reader's "clean close with nothing pending", which the
    // slice parser reports as a short header.
    let read = learn::read_message(&mut cursor, kind, max);
    assert_eq!(
        matches!(read, Ok(Some(_))),
        parsed.is_ok(),
        "reader and parser disagree"
    );
});
