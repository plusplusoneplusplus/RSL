# rsl-wire

A **byte-exact, pure-Rust port of the RSL Paxos wire format** — the marshaling
layer, the Rabin-64 message checksum, and every RSL message type across protocol
versions 1–6. It reads and writes each message identically to the original C++
(`src/common/src/marshal.cpp`, `src/common/src/msn_fprint.cpp`,
`src/RSL/src/message.cpp`), proven against the golden corpus emitted by
`tools/golden-gen`.

- **Zero I/O**, **zero `unsafe`** (`unsafe_code = "forbid"`), **zero runtime
  dependencies**.
- Little-endian targets only; big-endian fails to compile (the C++ big-endian
  fingerprint path is an unported byte-swapped mirror).

This is Phase 2 of the RSL Rust port. The on-disk formats live in
[`rsl-storage`](../rsl-storage) (Phase 3 — checkpoints today, the log file next),
and NetPacket framing is Phase 4. The one storage-adjacent type kept here is
`ConfigurationInfo`: only checkpoint headers marshal it, but its encoding is the
same versioned `MemberSet` vocabulary as everything else in `types`.

## Layout

| Module | Ports |
| --- | --- |
| `fprint` | Rabin-64 fingerprint (`msn_fprint.cpp`) — poly `0xa795d0f29b4dcdf8` |
| `marshal` | `MarshalData` reader/writer (`marshal.cpp`) — LE primitives, `u32`-prefixed strings, 1/4-byte back-patched containers |
| `types` | `MemberId`, `BallotNumber`, `RslNode`, `MemberSet`, `ConfigurationInfo` |
| `messages` | common `Header` + `Vote`, `JoinMessage`, `PrepareMsg`, `PrepareAccepted`, `StatusResponse`, `BootstrapMsg` |
| `version` | `ProtocolVersion` (1–6) and the per-version field rules |

## Correctness

The crate is validated by five independent harnesses, all run by `cargo test`:

1. **`golden`** — for every one of the 122 corpus records: unmarshal succeeds,
   the checksum verifies and equals the stated value, and re-marshal is
   **byte-identical** to the reference bytes. All 7 raw Rabin-64 vectors match.
   **`containers`** additionally rebuilds the 7 raw `MarshalData`
   `CONTAINER` vectors (1/4-byte back-patched lengths, incl. nesting)
   byte-identically.
2. **`fields`** — each message is **independently reconstructed** from the
   corpus's machine-readable `FIELDS` metadata (never from parsing the bytes)
   and must reproduce the reference bytes. This closes the round-trip loophole
   where a reader bug can be masked by a mirrored writer bug.
3. **`proptest`** — arbitrary valid messages across all versions reach a byte
   fixpoint under marshal/parse.
4. **`fuzz_smoke`** — pseudo-random and corpus-mutated bytes never panic
   `unmarshal`, and any accepted buffer is idempotent under marshal/parse. The
   coverage-guided equivalent lives in `fuzz/` (see below).

Where the C++ `LogAssert`-**aborts** on hostile input, this crate accepts or
cleanly rejects instead; the exhaustive list (needed to whitelist a future
C++-vs-Rust differential fuzzer) is in the crate-level rustdoc
(`src/lib.rs`). One shape is accepted by the reader but refused by the
writer: a reconfiguration vote carrying requests — marshaling returns
`Err(MarshalError::ReconfigurationVoteWithRequests)` because a C++ peer
would abort parsing it.

## Fuzzing

A [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) target enforces the
same invariants under coverage-guided fuzzing:

```sh
cargo install cargo-fuzz
cd rust/crates/rsl-wire
cargo +nightly fuzz run unmarshal
```

The `fuzz/` crate is detached from the workspace (it needs nightly + libfuzzer),
so a plain stable `cargo build`/`test` skips it; `fuzz_smoke` is the always-on
floor in CI, plus a ~60 s bounded `cargo fuzz` smoke step. The generated corpus
under `fuzz/corpus/unmarshal/` is **not** checked in (it's marshal data, not
source — see `fuzz/.gitignore`); it accumulates locally across runs, and CI
starts each smoke run from an empty corpus.

## Benchmarks

`cargo bench -p rsl-wire`. Indicative numbers on the CI-class 2-core machine
(GitHub-hosted `ubuntu-latest`, `--release`); treat as a baseline for later
phases, not absolute figures:

| Benchmark | Time | Throughput |
| --- | --- | --- |
| `fingerprint` / 16 B | ~9 ns | ~1.6 GiB/s |
| `fingerprint` / 256 B | ~149 ns | ~1.6 GiB/s |
| `fingerprint` / 4 KiB | ~2.31 µs | ~1.65 GiB/s |
| `fingerprint` / 64 KiB | ~37.1 µs | ~1.64 GiB/s |
| `marshal_vote_v6` (2 requests) | ~159 ns | — |
| `unmarshal_vote_v6` (2 requests) | ~114 ns | — |

The Rabin-64 fingerprint uses the same slice-by-8 tables as the C++, so
throughput tracks it closely.

## Example

```rust
use rsl_wire::{Msg, MsgKind, messages::verify_checksum};

// `kind` is chosen by the receiver (a message id may be a bare header or a
// subclass), exactly as in the C++.
if let Some(msg) = Msg::unmarshal(MsgKind::Vote, bytes) {
    assert!(verify_checksum(bytes)); // `bytes` must be exactly one message
    let reencoded = msg.marshal_with_checksum().unwrap(); // byte-identical
    assert_eq!(reencoded, bytes);
}
```
