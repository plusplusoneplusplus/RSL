# Durability contract

What `rsl-storage` promises across power loss, per API. Phase 5 acknowledges
decrees against this, so changing anything here changes what a replica is allowed
to acknowledge.

The C++ never has to write any of this down, because Windows does it. Log and
checkpoint handles are opened `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH`
(`APSEQWRITE`, `legislator.cpp:513`), so a write that returns is already on the
platter, and the checkpoint is published with `MoveFileEx(...,
MOVEFILE_WRITE_THROUGH)` (`legislator.cpp:5645`). On Linux none of that is
implicit, so it is spelled out below and checked by `tests/crash.rs`.

## The guarantees

| API | After it returns `Ok` |
| --- | --- |
| `LogWriter::open` / `open_with` | The log file exists durably (a new file's directory entry is fsynced), and the writer sits past everything recovery kept. Any discarded tail has been truncated away. |
| `LogWriter::append` / `append_batch` | Nothing. The bytes are in the page cache. A crash can lose them, tear them, or land them out of order. |
| `LogWriter::sync` | Every record appended so far survives power loss. |
| `LogWriter::append_durable` | Every record in the batch survives power loss. Do not acknowledge a decree before this returns. |
| `CheckpointWriter::finish` | The checkpoint is published. A reader sees the whole new file under its final name, or the whole previous file, never a mixture. |
| `CheckpointWriter` dropped without `finish` | The staging `.tmp` is removed. A partial checkpoint is never published. |
| `dir::write_defunct` | The new value survives power loss. The file is one 4-byte word, so an in-place overwrite cannot tear across a sector. |
| `gc::apply` / `cleanup` | The deletions survive power loss, and any prefix of them leaves a directory a replica can still start from. |

None of this is transactional across files. Two calls that both return `Ok` are
each durable on their own; nothing promises what order a crash sees them in
beyond what the sequences below establish.

## Why each sync is where it is

**Appends use `fdatasync`, not `fsync`.** A log is only ever extended, and
`fdatasync` covers the one inode field that matters for that, the file's length.
On the development machine the two are the same to within noise (4.90 ms vs
4.95 ms, both just one device flush), so this is a correctness and portability
choice rather than a measured win. On a filesystem that writes more inode
metadata it costs nothing to have made it.

**The directory fsync when a log is created is not optional.** `fdatasync` on
ext4 and xfs does not publish a newly created file's directory entry. Skip the
`sync_dir` and a vote can be fsynced, acknowledged, and then disappear along with
the entire file it was written to. So `LogWriter::open_with` fsyncs the directory
once, at creation; every append after that needs only `fdatasync`.
`tests/crash.rs::the_harness_catches_a_missing_dir_fsync` runs the same workload
with `sync_dir` stubbed out and checks that the harness actually notices the log
vanish.

**Publishing a checkpoint is fsync, rename, fsync-dir** (`rename_durable`). The
contents have to be durable before the name pointing at them is, or the rename
can publish a file full of holes. The rename has to be durable too, or the
checkpoint quietly reverts to the previous one. `tests/crash.rs` catches either
half going missing.

**GC unlinks everything, then fsyncs the directory once.** The retention plan
never contains the newest checkpoint or a log still needed to reach it, so any
prefix of the deletions leaves a startable directory. Syncing per file would only
buy extra flushes.

## What a crash can still do

Two outcomes are expected, and neither is a durability violation.

**The unsynced tail is lost.** Records appended without a sync are exactly the
records the engine never acknowledged. Recovery discards them; the next append
overwrites the space.

**Recovery refuses to start.** If the tail is damaged in a way the C++ decision
table calls corruption — a bad checksum with non-zero data behind it — the scan
returns `Outcome::Reject` and the replica does not start, matching `RestoreState`
returning `false` (`legislator.cpp:5993`). A crash can genuinely reach this: lose
one 512-byte sector inside a region whose later sectors landed and you get a
record that fails its checksum with real data after it, which no reader can
write off as a zero tail. That is the `holey-tail` policy in `sim.rs`. It is
fail-stop rather than silent loss, and the harness checks that the rejection is
always past the last acknowledged record, so no acknowledged decree is ever lost
or misreported. Doing anything else here would mean diverging from the C++
reader, which the Phase-3a corpus pins.

## Residual gaps

- **Sector size.** `SimCrash` tears at 512 bytes, matching the format's
  `s_PageSize` assumption. A 4K-native device tears at 4096. Every 512-boundary
  tear the model makes is a cut a 4K device could not make, so in that direction
  the enumerated states are a superset. But a 4K device can also lose a whole
  4 KiB region where the model only damages part of one. The record checksum
  covers the whole record either way, so a partially lost record is caught either
  way; the gap is in which states get enumerated, not in what the format can
  detect.
- **Hardware that lies.** A drive whose write cache ignores `FLUSH` defeats all
  of the above, and no software can tell. It is a deployment requirement, as it
  was for the C++ on Windows.
- **`sync_dir` where the filesystem rejects it.** `SyncAll::sync_dir` treats
  `EINVAL` on a directory handle as success, because not every filesystem
  supports it. There, the directory-entry guarantee is whatever the filesystem
  gives you by default.
- **No cross-file atomicity.** Recovery is written to tolerate any interleaving —
  a checkpoint published without the log GC that would have followed it, say —
  which is why the harness enumerates whole-directory states rather than
  per-file ones.

## How this is verified

`tests/crash.rs` runs four scripted workloads (appending votes, publishing
checkpoints, garbage collection, and crash-then-reopen) against the `SimCrash`
shadow filesystem in `src/sim.rs`. It then materializes the disk state at every
prefix of the recorded operation sequence, under six crash policies:

| Policy | The unsynced state after the crash |
| --- | --- |
| `nothing-in-flight` | no unsynced write and no unsynced name change survived |
| `everything-in-flight` | it all reached the platter first (the luckiest crash) |
| `no-dir-ops` | data landed, directory entries did not |
| `torn-tail` | all but the last write landed; that one is cut at a sector boundary |
| `holey-tail` | the last write landed with alternate sectors missing |
| `reordered-tail` | only the last write of each file landed |

Each materialized directory goes through the real recovery code on a real
filesystem, checking four things: nothing acknowledged is lost, recovery always
reaches a decision, what survives is a prefix and never a hole, and a published
checkpoint is whole. The append workload also checks that all three recovery
outcomes (`accept`, `stop-at-offset`, `reject`) actually turn up somewhere in the
enumeration, so the harness cannot pass by never damaging anything.

`a_killed_writer_leaves_a_recoverable_log` adds a real-filesystem sanity check: a
child process appending durable votes gets `SIGKILL`ed mid-stream, and the log
has to recover to a contiguous prefix and still be appendable. The exhaustive
coverage comes from the simulator; that test only guards against the model having
drifted from the real thing.

## O_DIRECT / io_uring: not opened

Phase 3d had a decision gate: open an `O_DIRECT`/`io_uring` work item only if
`fdatasync` group-commit latency came in materially worse than the C++ baseline.
Measured with `cargo bench -p rsl-storage` on the development machine, files in
`/tmp`:

| Batch | `append_durable` latency | Throughput |
| --- | --- | --- |
| 1 record | 4.79 ms | 0.1 MiB/s |
| 4 records | 4.59 ms | 0.4 MiB/s |
| 16 records | 3.86 ms | 2.0 MiB/s |
| 64 records | 3.82 ms | 8.2 MiB/s |
| 256 records | 3.80 ms | 32.9 MiB/s |

Latency is flat in batch size. The cost is one device flush, which is also what
the C++ pays for `WriteFileGather` plus a write-through commit, and batching buys
about 320x the throughput for no extra latency. A bare 512-byte `write` +
`fsync` outside this crate costs 4.95 ms, so `LogWriter` adds nothing measurable
over the raw syscall pair. There is no software overhead here for `O_DIRECT` to
recover, so the work item stays closed. It is format-invariant either way, so it
can be reopened from a Phase-5/6 profile without touching anything on disk.
