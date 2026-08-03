# rsl-storage

The RSL **on-disk formats** in pure Rust: everything a replica's data directory
holds. Phase 3b covered the checkpoint (`<decree>.codex`) file — the
`CheckpointHeader` and the block-checksummed user-state stream that
`RSLCheckpointStreamWriter` / `RSLCheckpointStreamReader` (`src/RSL/src/rsl.cpp`)
produce and consume. Phase 3c adds the log (`<decree>.log`) writer, its
decree→offset index and the startup recovery scan (`Legislator::ReadNextMessage`
+ `RestoreState`), plus directory naming/enumeration, `defunct.txt`, and the
log/checkpoint retention rule (`CleanupLogsAndCheckpoint`).

- Files written here are **byte-identical** to the C++ ones; files written by the
  C++ parse here with the **same accept/reject decisions**, proven against the
  Phase-3a golden corpus (`tools/golden-gen --storage`).
- **Zero `unsafe`** (`unsafe_code = "forbid"`), one dependency (`rsl-wire`).
- **Bounded memory**: no path ever holds a whole checkpoint or a whole log.

## Layout

| Module | Ports |
| --- | --- |
| `checkpoint` | `CheckpointHeader` (`legislator.cpp:820-1030`), `CheckpointWriter`/`CheckpointReader` (`rsl.cpp:161-620`), the commit sequence in `Legislator::SaveCheckpoint` |
| `log` | `LogFile` (`legislator.cpp:495-780`), the `ReadNextMessage` recovery loop (`legislator.cpp:3851`) and the `RestoreState` scan that drives it (`:5993`) |
| `dir` | file naming (`legislator.cpp:516`/`:1082`), `GetFileNumbers` (`:5766`), `Read`/`UpdateDefunctFile` (`:7198`/`:7330`) |
| `gc` | `CleanupLogsAndCheckpoint` (`legislator.cpp:5675`) |
| `durability` | fsync/rename policy — the seam Phase 3d builds on |

`ConfigurationInfo` lives in `rsl-wire::types` alongside `MemberSet`: only
checkpoints marshal it, but its encoding is plain versioned wire vocabulary.

## On-disk layouts

A checkpoint:

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

A log is a bare concatenation of records — no file header, no trailer:

```text
+-----------------------------------------------+ 0
| marshaled message | pad to RoundUpToPage       |   record 0
+-----------------------------------------------+ padded_len
| marshaled message | pad                        |   record 1
+-----------------------------------------------+
| ...                                           |
+-----------------------------------------------+ data_len
```

Each record carries its own length and Rabin-64 in the message header, and only
three ids are ever logged: `Vote`, `Prepare`, `ReconfigurationDecision`. The
checksum covers the message only, so readers tolerate arbitrary pad bytes — but
this writer always zeroes them, because recovery reads an all-zero header page as
the clean end of the log.

Recovery ends one of three ways, matching the C++ decision for decision:

| Outcome | Meaning |
| --- | --- |
| `accept` | every record valid, consumed exactly to EOF |
| `stop-at-offset` | valid records then a tolerated tail — a zero region, a torn last record, or a trailing checksum mismatch over zeros — which is discarded and overwritten |
| `reject` | hard corruption; the C++ replica refuses to start |

## Durability

The C++ relies on Windows semantics — unbuffered writes plus
`MoveFileEx(..., MOVEFILE_WRITE_THROUGH)`. On Linux the equivalent is explicit.
`CheckpointWriter::finish` does it in order:

1. seal the last block and patch the header with the final size,
2. `fsync` the file,
3. rename `…​.codex.tmp` → `…​.codex`,
4. `fsync` the containing directory.

A `CheckpointWriter` dropped without `finish` removes its `.tmp`, so a partial
checkpoint is never published. Logs have no rename step — they are appended in
place — so the log layer exposes both halves and lets the caller pick the commit
points: `append` / `append_batch` write, `sync` flushes, `append_durable` does
both. Phase 5's engine decides where the sync points go. Swap the policy (e.g.
`NoSync` in tests) via `CheckpointWriter::create_with` / `LogWriter::open_with`.

## Example

```rust
use std::io::{Read, Write};
use std::path::Path;
use rsl_storage::checkpoint::{CheckpointHeader, CheckpointReader, CheckpointWriter};
use rsl_storage::log::{LogReader, LogWriter};

// --- checkpoint ---------------------------------------------------------
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

// --- log ----------------------------------------------------------------
let dir = Path::new("/var/lib/rsl");
// Opening scans the existing file, rebuilds the index, and positions the
// write pointer past any tail recovery discarded.
let mut log = LogWriter::open(dir, 1000)?;        // <dir>/1000.log
log.append_durable(&[&vote_bytes, &prepare_bytes])?;  // one writev + fsync

// Replaying from a decree, e.g. for the execute queue's read-behind path.
let log = LogReader::open(dir, 1000)?;
if let Some(mut records) = log.replay_from(1042)? {
    while let Some(record) = records.next_record()? {
        let msg = record.parse().expect("validated by the scan");
    }
}
```

## Correctness

`cargo test` runs six harnesses:

1. **`corpus`** — every `.codex` sample in the Phase-3a corpus parses with the
   outcome, `detail` wording, version, header length and recovered user-data size
   the MANIFEST recorded; each accepted sample's state streams back exactly; and
   re-writing header+state with the Rust writer reproduces the C++ file
   **byte-for-byte**.
2. **`log_corpus`** — every `.log` sample scans with the MANIFEST's outcome, stop
   offset, `detail` and full per-record list (offset, id, decree, lengths,
   checksum); rebuilding those messages and appending them through `LogWriter`
   reproduces each sample **byte-for-byte**; and batched appends produce the same
   file as one-at-a-time.
3. **`interop`** — the reverse direction, via `golden-gen --verify-storage`: the
   extracted **C++** readers accept Rust-written checkpoints (v3–v6, at and across
   the 4 MiB boundary) and Rust-written logs (empty, mixed record kinds,
   multi-page votes, 32-record runs), reporting the same sizes, record counts and
   stop offsets — and reject damaged ones for the *same reason* we do.
4. **`log_roundtrip`** — reopen → append → rescan idempotence over zero and torn
   tails; the decree index (re-votes, non-indexed record kinds, decree lengths)
   against `LogFile`'s rules; replay-from-decree; writer strictness; and property
   tests over random record sequences, batch splits and arbitrary truncation.
5. **mutation tests** (in `log_roundtrip` and `roundtrip`) — every pad byte flip
   must leave a record valid, every body flip must stop or reject exactly where
   the C++ does, and a flip in any checkpoint block's data or checksum token, a
   corrupted header, a bad version, truncation and extension are each rejected
   with the specific reason the C++ gives.
6. **`dir_gc`** — name parsing and enumeration order, `defunct.txt` round trips
   (against the corpus samples), and retention scenarios: which files survive a
   checkpoint at decree N, with and without a checkpoint present.

The corpus samples are generated test data and not committed. Tests locate them
via `$RSL_STORAGE_CORPUS`, then `tools/golden-gen/corpus/storage`, and finally by
running `golden-gen --storage` if the binary is built; with none of those
available the corpus/interop tests print a skip instead of failing.

Where the C++ `LogAssert`-**aborts** on a malformed file, this crate returns an
error instead. The exhaustive list (needed to whitelist a future C++-vs-Rust
differential fuzzer) is in the crate-level rustdoc (`src/lib.rs`).

## Benchmarks

`cargo bench -p rsl-storage`. Indicative numbers on the development machine
(`--release`, files in `/tmp`); treat as a baseline, not absolutes:

| Benchmark | Time | Throughput |
| --- | --- | --- |
| `checkpoint_write` / 64 KiB | ~1.49 ms | ~42 MiB/s |
| `checkpoint_write` / 4 MiB | ~3.37 ms | ~1.16 GiB/s |
| `checkpoint_write` / 16 MiB | ~13.1 ms | ~1.19 GiB/s |
| `checkpoint_read` / 64 KiB | ~43 µs | ~1.41 GiB/s |
| `checkpoint_read` / 4 MiB | ~2.68 ms | ~1.46 GiB/s |
| `checkpoint_read` / 16 MiB | ~10.9 ms | ~1.44 GiB/s |
| `log/append` batched, 1024 × 512 B (`NoSync`) | ~217 µs | ~2.2 GiB/s |
| `log/append` one-at-a-time, 1024 × 512 B | ~962 µs | ~520 MiB/s |
| `log/append` batched, 1024 × 4 KiB | ~898 µs | ~4.3 GiB/s |
| `log/group-commit` 1 record (`SyncAll`) | ~4.9 ms | — |
| `log/group-commit` 128 records (`SyncAll`) | ~4.7 ms | ~13 MiB/s |
| `log/recovery-scan` 4096 × 512 B | ~1.29 ms | ~1.51 GiB/s |
| `log/recovery-scan` 4096 × 4 KiB | ~13.2 ms | ~1.18 GiB/s |

Checkpoint read throughput tracks the Rabin-64 rate (~1.6 GiB/s in `rsl-wire`),
as expected: the checksum is the only per-byte work either direction does. The
same holds for the recovery scan. Two shapes are worth reading carefully: the
64 KiB *checkpoint write* figure is not a throughput measurement (each iteration
creates, closes and renames a file, and that fixed ~1.3 ms dominates), and the
group-commit row is the disk's `fsync` latency — ~4.7 ms whether the batch holds
1 record or 128, which is exactly why the engine batches.
