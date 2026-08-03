//! Deterministic fuzz smoke test (plan item 8) that runs on stable in CI —
//! no nightly, no cargo-fuzz. It hammers `unmarshal` with pseudo-random and
//! corpus-mutated bytes and asserts the two core invariants:
//!
//! 1. **No panic / no crash** on any input (a panic fails the test).
//! 2. **Idempotence when accepted**: if a buffer parses, marshaling it and
//!    re-parsing reaches a byte fixpoint — `marshal(parse(b)) ==
//!    marshal(parse(marshal(parse(b))))`.
//!
//! The `fuzz/` cargo-fuzz target asserts the same invariants for coverage-guided
//! runs; this test is the always-on floor.

mod common;

use rsl_wire::{MarshalError, Msg, MsgKind};

const KINDS: [MsgKind; 7] = [
    MsgKind::Base,
    MsgKind::Vote,
    MsgKind::Join,
    MsgKind::Prepare,
    MsgKind::PrepareAccepted,
    MsgKind::StatusResponse,
    MsgKind::Bootstrap,
];

/// Assert the two invariants for one (kind, buffer) pair.
fn check(kind: MsgKind, buf: &[u8]) {
    if let Some(msg) = Msg::unmarshal(kind, buf) {
        let b1 = match msg.marshal_with_checksum() {
            Ok(b) => b,
            // The one accepted-but-unwritable shape: a reconfiguration vote
            // with trailing bytes parses (the reader is permissive where the
            // C++ aborts — see the whitelist in the crate docs), but the
            // writer refuses to re-emit it.
            Err(MarshalError::ReconfigurationVoteWithRequests) => return,
            Err(e) => panic!("unexpected marshal error from a parsed message: {e}"),
        };
        // Marshaling a parsed message yields a self-consistent, verifiable blob.
        assert!(
            rsl_wire::messages::verify_checksum(&b1),
            "checksum of re-marshaled message does not verify"
        );
        let msg2 = Msg::unmarshal(kind, &b1).expect("re-parse of own output failed");
        let b2 = msg2.marshal_with_checksum().expect("re-marshal failed");
        assert_eq!(b1, b2, "not idempotent under marshal/parse");
    }
}

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

#[test]
fn random_bytes_never_panic_and_reparse_is_idempotent() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..80_000 {
        let len = (rng.next() % 200) as usize;
        let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        for &kind in &KINDS {
            check(kind, &buf);
        }
    }
}

#[test]
fn corpus_mutations_never_panic() {
    let (records, _) = common::load();
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for rec in &records {
        // Feed the pristine bytes to every kind (not just the record's own).
        for &kind in &KINDS {
            check(kind, &rec.bytes);
        }
        // Single- and multi-byte mutations, plus random truncations.
        for _ in 0..200 {
            let mut buf = rec.bytes.clone();
            if !buf.is_empty() {
                let flips = 1 + (rng.next() % 4) as usize;
                for _ in 0..flips {
                    let idx = (rng.next() as usize) % buf.len();
                    buf[idx] ^= rng.byte();
                }
                if rng.next().is_multiple_of(4) {
                    let keep = (rng.next() as usize) % (buf.len() + 1);
                    buf.truncate(keep);
                }
            }
            for &kind in &KINDS {
                check(kind, &buf);
            }
        }
    }
}
