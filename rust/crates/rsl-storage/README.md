# rsl-storage

The RSL **on-disk formats** in pure Rust: checkpoints, logs, directory metadata,
and retention behavior. The checkpoint (`<decree>.codex`) file contains the
`CheckpointHeader` and the block-checksummed user-state stream that
`RSLCheckpointStreamWriter` / `RSLCheckpointStreamReader` (`src/RSL/src/rsl.cpp`)
produce and consume. The log (`<decree>.log`) writer, its
decree→offset index and the startup recovery scan (`Legislator::ReadNextMessage`
+ `RestoreState`), plus directory naming/enumeration, `defunct.txt`, and the
log/checkpoint retention rule (`CleanupLogsAndCheckpoint`).

- Production Windows artifacts and recovery verdicts are checked through
  `RSLWindowsOracle`; the Linux storage model adds deterministic POSIX and
  corruption coverage.
- **Zero `unsafe`** (`unsafe_code = "forbid"`), one dependency (`rsl-wire`).
- **Bounded memory**: no path ever holds a whole checkpoint or a whole log.

## Layout

| Module | Ports |
| --- | --- |
| `checkpoint` | `CheckpointHeader` (`legislator.cpp:820-1030`), `CheckpointWriter`/`CheckpointReader` (`rsl.cpp:161-620`), the commit sequence in `Legislator::SaveCheckpoint` |
| `log` | `LogFile` (`legislator.cpp:495-780`), the `ReadNextMessage` recovery loop (`legislator.cpp:3851`) and the `RestoreState` scan that drives it (`:5993`); `LogSet` is the whole-directory read side `HandleFetchVotesMsg` serves from (`:3633`) |
| `dir` | file naming (`legislator.cpp:516`/`:1082`), `GetFileNumbers` (`:5766`), `Read`/`UpdateDefunctFile` (`:7198`/`:7330`) |
| `gc` | `CleanupLogsAndCheckpoint` (`legislator.cpp:5675`) |
| `durability` | the open/write/sync/rename seam every write goes through — `APSEQWRITE` + `MOVEFILE_WRITE_THROUGH` spelled out for Linux |
| `sim` | `SimCrash`: a shadow filesystem that records the write/sync/rename journal so a crash can be replayed at any prefix (test support) |

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

Recovery exposes the production-compatible three-way outcome:

| Outcome | Meaning |
| --- | --- |
| `accept` | every record valid, consumed exactly to EOF |
| `stop-at-offset` | valid records then a tolerated tail — a zero region, a torn last record, or a trailing checksum mismatch over zeros — which is discarded and overwritten |
| `reject` | hard corruption; the C++ replica refuses to start |

### Reading a live directory

`LogSet::open` scans every `<decree>.log` at once and hands back the decree
index for each, so a caller can ask "which spans of which files answer
`FetchVotes(decree)`?" (`LogSet::votes_from`). This is what the learn port in
[`rsl-net`](../rsl-net) serves from, and it is deliberately a **snapshot**: each
file's readable length is fixed when the set is opened and never re-read, so a
response cannot chase records appended while it is being sent.

That is what the C++ does too, by accident of its I/O layer: `SendFile` opens
the file with `APSEQREAD::DoInit`, which captures `GetFileSize` once
(`apdiskio.cpp:146`), and computes `length = FileSize() - offset` from that one
value (`legislator.cpp:4515`). The only difference is *what* is snapshotted —
the raw file size there, the end of the last valid record here — which matters
solely for a file ending in a torn or zeroed tail.

## Durability

The C++ relies on Windows semantics — unbuffered write-through handles plus
`MoveFileEx(..., MOVEFILE_WRITE_THROUGH)`. On Linux every part of that is
explicit, and **[`DURABILITY.md`](DURABILITY.md) states the exact guarantee at
each API**. In short:

- `LogWriter::append_durable` — the batch survives power loss when it returns.
  This is the contract Phase 5 acknowledges decrees against.
- `LogWriter::open` — fsyncs the *directory* when it creates the log, because
  `fdatasync` on ext4/xfs does not publish a new file's name. Appends then need
  only `fdatasync`.
- `CheckpointWriter::finish` — fsync → rename → fsync-dir, so a reader sees the
  whole old file or the whole new one. Dropped without `finish`, the `.tmp` is
  removed and nothing is published.
- `gc::apply` — unlinks, then fsyncs the directory; any prefix of the deletions
  leaves a startable directory.

All of it goes through the `durability::Durability` trait, so the policy is
swappable: `NoSync` for benchmarks, and `sim::SimCrash` — a shadow filesystem
that journals every operation — for the crash harness. Reads and recovery stay
on the real filesystem; the harness materializes a crashed directory to disk and
runs the real code against it.

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

`cargo test` runs eight harnesses:

1. **`corpus`** — every `.codex` Linux model sample parses with the
   outcome, `detail` wording, version, header length and recovered user-data size
   the MANIFEST recorded; each accepted sample's state streams back exactly; and
   re-writing header+state with the Rust writer reproduces the model file
   **byte-for-byte**.
2. **`log_corpus`** — every `.log` sample scans with the MANIFEST's outcome, stop
   offset, `detail` and full per-record list (offset, id, decree, lengths,
   checksum); rebuilding those messages and appending them through `LogWriter`
   reproduces each sample **byte-for-byte**; and batched appends produce the same
   file as one-at-a-time.
3. **`interop`** — reverse checks against the optional Linux storage model:
   Rust-written checkpoints/logs, damaged tails, and whole-directory takeover
   scenarios. These are supplemental model comparisons, not production Windows
   recovery evidence.
4. **`log_roundtrip`** — reopen → append → rescan idempotence over zero and torn
   tails; the decree index (re-votes, non-indexed record kinds, decree lengths)
   against `LogFile`'s rules; replay-from-decree; writer strictness; and property
   tests over random record sequences, batch splits and arbitrary truncation.
5. **mutation tests** (in `log_roundtrip` and `roundtrip`) — every pad byte flip
   must leave a record valid, while body/checkpoint mutations exercise stable
   stop/reject behavior. A flip in any checkpoint block's data or checksum token, a
   corrupted header, a bad version, truncation and extension are rejected with
   stable Rust/model diagnostics.
6. **`dir_gc`** — name parsing and enumeration order, `defunct.txt` round trips
   (against the corpus samples), and retention scenarios: which files survive a
   checkpoint at decree N, with and without a checkpoint present.
7. **`crash`** — four scripted workloads (append votes, publish checkpoints,
   garbage-collect, crash-and-reopen) run against the `SimCrash` shadow
   filesystem, then replayed at **every** prefix of the recorded operation
   sequence under six crash policies. Each materialized directory goes through
   the real recovery code, asserting that nothing acknowledged is lost, recovery
   always reaches a decision, survivors are a prefix and never a hole, and a
   published checkpoint is whole. Two tests deliberately break the policy (drop
   the directory fsync; publish without syncing the contents) to prove the
   harness detects both, and one `SIGKILL`s a real child writer as a
   sanity layer. See [`DURABILITY.md`](DURABILITY.md).
8. **`sim` unit tests** — the shadow filesystem's own model: unsynced names can
   vanish, synced bytes never can, tears land on sector boundaries, and a rename
   is all-or-nothing.

Linux proxy corpus samples are generated test data and not committed. Tests locate them
via `$RSL_STORAGE_CORPUS` and otherwise regenerate them by running
`rsl-linux-proxy --storage` if the binary is built; with neither of those
available the corpus/interop tests print a skip instead of failing.

Production Windows storage fixtures are likewise generated rather than committed
(they are literal, non-byte-stable Windows outputs). `--test windows_oracle`
uses `$RSL_WINDOWS_STORAGE` when a validated CI artifact is present, otherwise
regenerates the corpus with `RSLWindowsOracle.exe --storage` from
`$RSL_WINDOWS_ORACLE`, and skips when neither is available.

Where production C++ `LogAssert`-**aborts** on a malformed file, this crate returns an
error instead. The exhaustive list (needed to whitelist a future C++-vs-Rust
differential fuzzer) is in the crate-level rustdoc (`src/lib.rs`).

## Benchmarks

`cargo bench -p rsl-storage`. Indicative numbers on the development machine
(`--release`, files in `/tmp`); treat as a baseline, not absolutes:

These are the portable storage baseline; production Windows artifacts add the
native compatibility gate.

| Benchmark | Time | Throughput |
| --- | --- | --- |
| `checkpoint_write` / 64 KiB | ~1.53 ms | ~41 MiB/s |
| `checkpoint_write` / 4 MiB | ~11 ms (noisy) | ~376 MiB/s |
| `checkpoint_write` / 16 MiB | ~13.8 ms | ~1.13 GiB/s |
| `checkpoint_read` / 64 KiB | ~44 µs | ~1.40 GiB/s |
| `checkpoint_read` / 4 MiB | ~2.71 ms | ~1.36 GiB/s |
| `checkpoint_read` / 16 MiB | ~11.0 ms | ~1.40 GiB/s |
| `log/append` batched, 1024 × 512 B (`NoSync`) | ~216 µs | ~2.26 GiB/s |
| `log/append` one-at-a-time, 1024 × 512 B | ~980 µs | ~510 MiB/s |
| `log/append` batched, 1024 × 4 KiB | ~938 µs | ~4.17 GiB/s |
| `log/group-commit` 1 record (`SyncAll`) | ~4.79 ms | ~0.1 MiB/s |
| `log/group-commit` 16 records | ~3.86 ms | ~2.0 MiB/s |
| `log/group-commit` 64 records | ~3.82 ms | ~8.2 MiB/s |
| `log/group-commit` 256 records | ~3.80 ms | ~32.9 MiB/s |
| `log/sync` `fdatasync` (one append) | ~4.90 ms | — |
| `log/sync` `fsync` (bare 512 B write) | ~4.95 ms | — |
| `log/sync` create + directory fsync | ~3.42 ms | — |
| `log/recovery-scan` 4096 × 512 B | ~1.35 ms | ~1.44 GiB/s |
| `log/recovery-scan` 4096 × 4 KiB | ~13.2 ms | ~1.18 GiB/s |

Checkpoint read throughput tracks the Rabin-64 rate (~1.6 GiB/s in `rsl-wire`),
as expected: the checksum is the only per-byte work either direction does. The
same holds for the recovery scan. Four rows want reading carefully:

- The 64 KiB and 4 MiB *checkpoint write* figures are not throughput
  measurements — each iteration creates, closes, renames and deletes a file, and
  that fixed cost dominates. The 4 MiB point is also very noisy on this machine
  (a ±25 % confidence interval); the 16 MiB row, which writes four 4 MiB blocks
  for ~3.45 ms each, is the reliable steady-state number.
- **Group commit is the whole story.** Latency is flat in batch size — one
  device flush whether the batch holds 1 record or 256 — so batching buys ~320×
  the throughput for no added latency. This is exactly why the engine batches,
  and it matches what the C++ gets from `WriteFileGather` + write-through.
- `fdatasync` and `fsync` are indistinguishable here (within the noise of a
  single flush). The port uses `fdatasync` for appends on correctness and
  portability grounds, not for a measured win.
- The directory fsync a new log pays is one-off (~3.4 ms per *file*, not per
  append), which is why it is affordable to make a log's name durable at
  creation.

**O_DIRECT / io_uring decision: not opened.** The Phase-3d gate was to open that
work item only if group-commit latency came in materially worse than the C++
baseline. It does not: the cost is one device flush, and `LogWriter` adds nothing
measurable over a bare `write` + `fsync` (4.90 ms vs 4.95 ms). It is
format-invariant, so it can be revisited from a Phase-5/6 profile without
touching anything on disk. Reasoning in [`DURABILITY.md`](DURABILITY.md).
