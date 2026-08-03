# rsl-storage

The RSL **on-disk formats** in pure Rust. Phase 3b of the port covers the
checkpoint (`<decree>.codex`) file: the `CheckpointHeader` and the
block-checksummed user-state stream that `RSLCheckpointStreamWriter` /
`RSLCheckpointStreamReader` (`src/RSL/src/rsl.cpp`) produce and consume.

- Files written here are **byte-identical** to the C++ ones; files written by the
  C++ parse here with the **same accept/reject decisions**, proven against the
  Phase-3a golden corpus (`tools/golden-gen --storage`).
- **Zero `unsafe`** (`unsafe_code = "forbid"`), one dependency (`rsl-wire`).
- **Bounded memory**: neither direction ever holds a whole checkpoint.

The log file (`.log`) reader/writer is Phase 3c and is not here yet.

## Layout

| Module | Ports |
| --- | --- |
| `checkpoint` | `CheckpointHeader` (`legislator.cpp:820-1030`), `CheckpointWriter`/`CheckpointReader` (`rsl.cpp:161-620`), the commit sequence in `Legislator::SaveCheckpoint` |
| `durability` | fsync/rename policy — the seam Phase 3d builds on |

`ConfigurationInfo` lives in `rsl-wire::types` alongside `MemberSet`: only
checkpoints marshal it, but its encoding is plain versioned wire vocabulary.

## On-disk layout

```text
+--------------------------------------------------+ 0
| CheckpointHeader, zero-padded to RoundUpToPage    |
+--------------------------------------------------+ header.marshal_len()
| user data (blockSize - 8 bytes) | Rabin-64 (8 B)  |   block 0
+--------------------------------------------------+
| ...                                              |
+--------------------------------------------------+
| user data (<= blockSize - 8)    | Rabin-64 (8 B)  |   last, possibly partial
+--------------------------------------------------+ header.size
```

`blockSize` is the header's `checksumBlockSize`, normally 4 MiB. At v3 the state
follows the header raw (no block checksums); below v3 there is no header at all,
just the page-rounded vote.

## Durability

The C++ relies on Windows semantics — unbuffered writes plus
`MoveFileEx(..., MOVEFILE_WRITE_THROUGH)`. On Linux the equivalent is explicit,
and `CheckpointWriter::finish` does it in order:

1. seal the last block and patch the header with the final size,
2. `fsync` the file,
3. rename `…​.codex.tmp` → `…​.codex`,
4. `fsync` the containing directory.

A `CheckpointWriter` dropped without `finish` removes its `.tmp`, so a partial
checkpoint is never published. Swap the policy (e.g. `NoSync` in tests) via
`CheckpointWriter::create_with`.

## Example

```rust
use std::io::{Read, Write};
use std::path::Path;
use rsl_storage::checkpoint::{CheckpointHeader, CheckpointReader, CheckpointWriter};

// `next_vote` is the vote at decree+1; `configuration` is the replica set.
let mut header = CheckpointHeader::new(next_vote);   // v>=4 ⇒ 4 MiB blocks
header.state_configuration = Some(configuration);

let path = Path::new("1000.codex");
let mut writer = CheckpointWriter::create(path, header)?;
writer.write_all(state)?;              // any sizes; blocks are internal
let header = writer.finish()?;         // fsync → rename → fsync dir

let mut reader = CheckpointReader::open(path)?;
let mut restored = Vec::new();
reader.read_to_end(&mut restored)?;    // every block verified before use
```

## Correctness

`cargo test` runs four harnesses:

1. **`corpus`** — every `.codex` sample in the Phase-3a corpus parses with the
   outcome, `detail` wording, version, header length and recovered user-data size
   the MANIFEST recorded; each accepted sample's state streams back exactly; and
   re-writing header+state with the Rust writer reproduces the C++ file
   **byte-for-byte**.
2. **`interop`** — the reverse direction: Rust-written checkpoints (v3–v6, at and
   across the 4 MiB boundary) are read by the extracted **C++** reader via
   `golden-gen --verify-storage`, which must accept them and report the same
   user-data sizes — and must reject a corrupted one for the same reason we do.
3. **`roundtrip`** — write→read properties: state sizes 0, 1, 4 MiB−1, 4 MiB,
   4 MiB+1 and multi-block; chunked writes and chunked reads produce identical
   bytes; the file size matches the format's arithmetic; `.tmp` staging and
   drop-cleanup behave.
4. **mutation tests** (in `roundtrip`) — a flip in any block's data or checksum
   token, a corrupted header, a bad version, truncation and extension are each
   rejected with the specific reason the C++ gives.

The corpus samples are generated test data and not committed. Tests locate them
via `$RSL_STORAGE_CORPUS`, then `tools/golden-gen/corpus/storage`, and finally by
running `golden-gen --storage` if the binary is built; with none of those
available the corpus/interop tests print a skip instead of failing.

Where the C++ `LogAssert`-**aborts** on a malformed file, this crate returns an
error instead. The exhaustive list (needed to whitelist a future C++-vs-Rust
differential fuzzer) is in the crate-level rustdoc (`src/lib.rs`).

## Benchmarks

`cargo bench -p rsl-storage`. Indicative numbers on the development machine
(`--release`, `NoSync`, files in `/tmp`); treat as a baseline, not absolutes:

| Benchmark | Time | Throughput |
| --- | --- | --- |
| `checkpoint_write` / 64 KiB | ~1.49 ms | ~42 MiB/s |
| `checkpoint_write` / 4 MiB | ~3.37 ms | ~1.16 GiB/s |
| `checkpoint_write` / 16 MiB | ~13.1 ms | ~1.19 GiB/s |
| `checkpoint_read` / 64 KiB | ~43 µs | ~1.41 GiB/s |
| `checkpoint_read` / 4 MiB | ~2.68 ms | ~1.46 GiB/s |
| `checkpoint_read` / 16 MiB | ~10.9 ms | ~1.44 GiB/s |

Read throughput tracks the Rabin-64 rate (~1.6 GiB/s in `rsl-wire`), as expected:
the checksum is the only per-byte work either direction does. The 64 KiB *write*
figure is not a throughput measurement — each iteration creates, closes and
renames a file, and that fixed ~1.3 ms dominates at small sizes.
