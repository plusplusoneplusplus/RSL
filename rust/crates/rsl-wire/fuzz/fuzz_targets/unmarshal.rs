//! Coverage-guided fuzz target (plan item 8).
//!
//! Run with a nightly toolchain and cargo-fuzz:
//! ```sh
//! cargo install cargo-fuzz
//! cd rust/crates/rsl-wire
//! cargo +nightly fuzz run unmarshal
//! ```
//!
//! Invariants (identical to `tests/fuzz_smoke.rs`, the stable always-on floor):
//! arbitrary bytes must never panic/OOM `unmarshal`, and any accepted buffer
//! must reach a byte fixpoint under `marshal(parse(..))`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rsl_wire::{Msg, MsgKind};

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
    // First byte selects which parser to exercise; the rest is the message.
    let (Some(&sel), Some(buf)) = (data.first(), data.get(1..)) else {
        return;
    };
    let kind = KINDS[sel as usize % KINDS.len()];

    if let Some(msg) = Msg::unmarshal(kind, buf) {
        let b1 = msg.marshal_with_checksum();
        assert!(rsl_wire::messages::verify_checksum(&b1));
        let msg2 = Msg::unmarshal(kind, &b1).expect("re-parse of own output failed");
        assert_eq!(b1, msg2.marshal_with_checksum(), "not idempotent");
    }
});
