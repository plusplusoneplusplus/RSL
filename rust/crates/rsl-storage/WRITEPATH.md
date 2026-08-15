# The write path

The C++ engine has two write paths, and only one of them is `APSEQWRITE`.

The **vote log** is not this document. `LogFile` writes with `WriteFileGather`
(logfile.cpp:160) on a handle opened
`FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED`
(logfile.cpp:38), never touching `APSEQWRITE`. Its gate was measured and closed
in [`DURABILITY.md`](DURABILITY.md): latency flat at ~4.79 ms, one device flush,
`LogWriter` adding nothing measurable over a bare `write` + `fsync`. Nothing
here reopens it.

`APSEQWRITE` (`src/common/src/apdiskio.{h,cpp}`) serves the **bulk writers**:
the checkpoint stream (`RSLCheckpointStreamWriter`, rsl.cpp:449, at the
caller's `blockSize`), the learner's checkpoint copy (learn_protocol.cpp:234, at
the 128 KiB default) and the defunct-config write (legislator.cpp:6917, also
default). It is a ring of `m_numWrites` page-aligned buffers over a handle
opened `FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED` — note **no**
`WRITE_THROUGH`, unlike `LogFile` — with `PrepareNext` issuing the buffer just
filled, advancing, and then blocking on that slot's previous write
(apdiskio.cpp:797-831): the write-side mirror of `ReadNext`.

This records what the port's `BufWriter` cost against that, and what replacing
it bought.

## APSEQWRITE: ported, as `SeqWriter`

Gate: build an `APSEQWRITE`-style ring writer only if correctly-sized buffering
plus the page cache leaves a gap a portable design can actually close.

**Verdict: built.** [`seqwrite::SeqWriter`](src/seqwrite.rs) reaches 96% of
`APSEQWRITE` at the checkpoint's own shape and 2.7x the best buffered writer, in
safe Rust with no FFI, no `unsafe`, and no platform API beyond one open flag.

The read side's answer does not transfer. There, capacity was worth 3.7x and the
remaining gap needed concurrency. Here **capacity is worth 1.3x and then the
page cache is the ceiling**: every buffered writer, at every capacity from 8 KiB
to 10 MiB, lands between 1.2 and 1.6 GB/s, while the unbuffered ring reaches
4.4. A buffered write is a memcpy into cache plus writeback the caller never
overlaps with, and no buffer size changes that.

### How this was measured, and what turned out not to be measurable

The read side's three confounds were about the page cache being warm. The write
side's are different, and were found the same way — the hard way.

**1. The durability endpoint is the comparison.** `APSEQWRITE` is
`NO_BUFFERING` but not `WRITE_THROUGH`: when a run returns, the data is past the
page cache but may still be in the device's write cache. A `BufWriter` with no
sync has done *strictly less* work at that point; with `sync_all`, *strictly
more*. Neither is a fair default, so every row below states its discipline, and
the load-bearing table pairs both sides at the same endpoint — everything
durable to the device (`--fsync` on the C++, `--sync all` on the Rust).

**2. Position in a gapless batch dominates, and it is not the configuration.**
Six 4 GiB rewrites back to back with no idle: the *last* row collapses to
765–828 MiB/s regardless of which configuration is last, reproducibly, across
two independent runs. Rows measured in that position are contaminated and are
dropped below rather than reported with a caveat. The sweep used to leave 20 s
of idle after every row for this reason; it no longer does. The shape is wrong
for a draining cache — that decays progressively rather than cliffing at one
position — and confound 4's homogeneous gapless batch shows nothing like it, so
padding every row was buying nothing measurable. It stays on the record below as
an open question, not as a constant to design around.

**3. LBA position is removable here, unlike on the read side.** `APSEQWRITE` is
`OPEN_ALWAYS` and never truncates (deliberately, to avoid fragmentation — see
the comment in `Flush`), so every row rewrites *one* pre-generated 4 GiB fixture
in place. After the first write, NTFS allocation and extension are out of the
measurement and every row lands on identical LBAs. This is the one confound the
write side has an answer to that the read side did not.

**4. The SLC cliff was looked for and not found.** The fixture drive is
DRAM-less TLC with a pseudo-SLC region, so a sustained run should eventually
collapse. Eight back-to-back 4 GiB rewrites — 32 GiB with no idle — stayed
within 3830–3972 MiB/s, a 3.7% spread with no trend. At 4 GiB per row the
configurations below all sit inside the cache. **A sweep with larger rows would
need this re-checked**; the cliff is not absent, it is beyond 32 GiB.

Machine: Intel Core Ultra 7 265KF, 63.6 GiB RAM, Kingston SNV3S1000G NVMe
(the D: volume), NTFS, Windows 11. Harness:
`src/RSL/UnitTest/SeqIoBench` (`write` subcommand) driven by `run-sweep.ps1`;
`SeqWriter` through its own gated measurement (`measure_against_apseqwrite`,
`RSL_SEQWRITE_FIXTURE`) over the same fixture and the same fill, cross-checked
by the `fold` column agreeing exactly with the C++ rows. 4 GiB per row, 4 KiB
logical records.

### The result that matters

Everything durable to the device on both sides. Medians of three repetitions for
the C++ rows, two for `SeqWriter`.

| Writer | MiB/s | vs APSEQWRITE |
| --- | --- | --- |
| `APSEQWRITE` 2 x 4 MiB, zero-copy — *checkpoint's own shape* | **4444** | — |
| `SeqWriter` 2 x 2 x 4 MiB, zero-copy | **4253** | **95.7%** |
| `SeqWriter` 4 x 4 x 4 MiB, zero-copy | 4223 | 95.0% |
| `SeqWriter` 4 x 4 x 4 MiB, copying | 4074 | 91.7% |
| `APSEQWRITE` 2 x 128 KiB, copying — *learner, defunct* | 3047 | — |
| best buffered: `write_all` of 4 MiB blocks + `sync_all` | 1597 | 35.9% |
| `BufWriter` 4 MiB + `sync_all` | 1569 | 35.3% |
| **checkpoint today — `BufWriter::new`, 8 KiB + `sync_all`** | **1209** | **27.2%** |

Two things this says. `SeqWriter` reaches parity within ~4% at the shape the
checkpoint actually runs, at 16 MiB of buffers against the C++'s 8 MiB — it
needs a wider ring than `APSEQWRITE` because a thread handoff is a coarser
mechanism than an overlapped queue, and that is the honest cost. And **today's
checkpoint writer runs at 27% of the C++**, which is the same headline the read
side had, arrived at for a completely different reason.

The latency distributions invert the read-side result. `APSEQWRITE` at
2 x 4 MiB: p50 600 ns, p99 3.2 µs, p99.9 43 µs, p99.99 250 µs. `BufWriter` at
4 MiB: p50 600 ns, p99 **1.4 µs**, p99.9 90–117 µs, p99.99 810 µs. The buffered
writer has the *better* p99 and the worse deep tail and worse throughput —
because the page cache defers the work rather than avoiding it, so the cost
shows up later and in larger lumps. On the read side `APSEQREAD` won the worst
case; on the write side neither side wins it cleanly (max 4.2 ms buffered
against 5.9 ms for the ring, with one 31.9 ms `APSEQWRITE` outlier).

### What the port was leaving on the floor

All buffered, all `--sync all`, all on the same fixture, so comparable to each
other. Means of two repetitions.

| Buffered writer | MiB/s |
| --- | --- |
| bare `File`, one `write` per 4 KiB record | 1041 |
| `BufWriter::new`, 8 KiB — **checkpoint today** (checkpoint.rs:846) | 1232 |
| `BufWriter` 64 KiB | 1501 |
| `BufWriter` 1 MiB | 1552 |
| `write_all` of 1 MiB blocks | 1575 |
| `BufWriter` 4 MiB | 1569 |
| `write_all` of 4 MiB blocks | 1597 |

**Capacity is worth 1.3x, and that is all it is worth.** 8 KiB → 64 KiB gets
almost the whole of it (1232 → 1501); everything past 64 KiB is inside 6% of
itself. The 10 MiB row is not in the table: both its measurements landed in the
contaminated last-row position of a gapless batch (374 and 1559 MiB/s), and one
number that disagrees with itself by 4x is not a measurement.

Compare with the read side, where 8 KiB → 1 MiB was worth 3.7x and the ceiling
was the device. Here the ceiling is ~1.6 GB/s of page-cache-plus-writeback and
the device is three times faster than that. **Raising the capacity is a real
one-line win and it recovers a quarter of the gap.** The rest needs the cache
out of the path.

### The APSEQWRITE shapes themselves

All bare (its native discipline, no `FlushFileBuffers`), all on one fixture, so
comparable to each other but not to the tables above. Means of two repetitions.
The shapes the engine actually runs are marked.

| depth x block | copying | zero-copy |
| --- | --- | --- |
| 4 x 4 MiB | 4033 | — |
| 2 x 4 MiB — *checkpoint* | 3878 | **4536** |
| 4 x 1 MiB | 4028 | — |
| 2 x 1 MiB | 3774 | — |
| 8 x 128 KiB | 3207 | — |
| 4 x 128 KiB | 3085 | — |
| 2 x 128 KiB — *learner copy, defunct config* | 3061 | 3176 |
| 2 x 64 KiB | 2425 | — |
| 1 x 128 KiB | 1594 | — |

**Depth 1 is legal and it halves throughput.** `DoInit` accepts
`maxWrites >= 1` (apdiskio.cpp:661) where the reader demands `> 1`
(apdiskio.cpp:90), so a caller can configure a ring that overlaps nothing:
1594 against depth 2's 3061, a 1.92x cliff between the two shallowest legal
settings. No caller in the tree does this, but nothing stops one.

**Block size matters more than depth.** 64 KiB → 4 MiB at depth 2 is worth
1.6x; depth 2 → 8 at 128 KiB is worth 1.05x. Past depth 2 the curve is flat,
which is why the C++ default of 2 is a reasonable choice and the 128 KiB default
is not.

**The zero-copy API earns its keep, at the large block.**
`GetAvailable`/`CommitAvailable` is worth **17%** at 4 MiB (3878 → 4536) and
3.8% at 128 KiB. `RSLCheckpointStreamWriter` uses it throughout (rsl.cpp:478,
:487, :495, :516, :531, :591) and is the one caller at 4 MiB, so it is
collecting essentially all of the available benefit. That is why `SeqWriter`
exposes [`available`](src/seqwrite.rs)/`commit` rather than only `Write`: the
measurement said the memcpy is real.

**The defunct-config write is the write side's `2 x 512 B`.** It writes four
bytes (legislator.cpp:6918) through a 128 KiB ring, so the file costs one full
128 KiB device write plus a `SetEndOfFile` to trim it back to 4 bytes. Harmless
at its frequency, and it is the same *kind* of mismatch the read side found in
the 2 x 512 B defunct read — the I/O layer's defaults are sized for
checkpoints and the small callers just inherit them.

### Warm, where the format is the ceiling

`cargo bench -p rsl-storage --bench writepath`, 32 MiB in 4 KiB records to the
temp directory, `NoSync`, everything landing in the page cache. This measures
the *relative* capacity question with the device taken out, and is the one place
`BufWriter` sizing can be reasoned about without a device confound. It is
deliberately not compared to any table above: nothing here is durable.

| Writer | Throughput |
| --- | --- |
| bare `File`, one `write` per record | 0.96 GiB/s |
| `BufWriter` 8 KiB (checkpoint today) | 1.16 |
| `BufWriter` 64 KiB | 1.82 |
| **`BufWriter` 128 KiB** | **1.96** |
| `BufWriter` 1 MiB | 1.94 |

Warm, capacity is worth 1.7x from 8 KiB to 128 KiB and then stops — 1 MiB is
already marginally *worse* than 128 KiB, the same L2/L3 pressure effect the read
side saw at 10 MiB. Note that 128 KiB is exactly `c_writeBufSizeDefault`
(apdiskio.h:99); whatever else is wrong with the C++ defaults, the buffer size
is the right one.

The 10 MiB, large-block and `writepath/checkpoint/today` rows are missing
because the run was terminated early by the harness collecting it, not because
they measured anything awkward. The bench is committed and reproducible; the
cold tables above are what the decision rests on.

### What was not inherited

`SeqWriter` is not a transliteration. Five `APSEQWRITE` behaviours are
deliberately absent, four of them demonstrated by execution rather than asserted
from reading — the standard `skiptest` set on the read side. The demos live in
`seqiobench` (`tailtest`, `rwbound`, `reflush`, `accounting`).

**The crash tail (`tailtest`).** `IssueWrite` always writes the full
`m_cbBufSize` regardless of `m_cbUsed` (apdiskio.cpp:755) while `m_offsetNext`
advances by `m_cbUsed`, and only `Flush`'s `SetEndOfFile` establishes the
length. Killing a writer before `Flush`, at a 128 KiB block:

| Scenario | Wrote | File left at | Contents |
| --- | --- | --- | --- |
| fresh file | 1,000,000 B | 917,504 B | clean prefix of 7 full buffers; **82,496 accepted bytes simply gone** |
| 300,000 B over an existing 2,000,000 B file | 300,000 B | 2,002,944 B | 262,144 B of new data, then the **old file's tail** from byte 262,144 on |

The second row is the dangerous one. `OPEN_ALWAYS` never truncated, so a reader
of that file sees new data flowing seamlessly into stale data with nothing
marking the join — and it is only safe today because `SaveCheckpoint` writes to
a temp name and `CheckpointDone` renames (legislator.cpp:5051-5083), so a file
in this state is never published. `SeqWriter` creates truncated and zero-fills
the pad past the logical end; `CheckpointWriter` stages under `.tmp` and renames
regardless.

**Accounting that outruns the data (`accounting`).** In `WriteInternal`'s
straddling path the `memcpy` after `PrepareNext` is guarded by `if (!ec)` but
`m_cbUsed += (cbWrite - cbUsed)` is not (apdiskio.cpp:899). Forcing the issue to
fail — `DoInit` accepts a non-sector-multiple buffer size, so an unbuffered
`WriteFile` of that length fails with `ERROR_INVALID_PARAMETER`, the same path a
full disk takes:

```
DoInit(cbWrite=1000)  -> 0        (a non-sector-multiple buffer is accepted)
Write(600)            -> 0        BytesIssued=600
Write(600)            -> 87       BytesIssued=1200   (1000 buffered, 0 on disk)
```

Public `BytesIssued()` reports 1200 bytes for a file with nothing in it, and
that value is what `CheckpointHeader::SetBytesIssued` stamps as the checkpoint's
size. In `SeqWriter` a failed write poisons the ring and every later call
returns the error; `bytes_written` counts only what was copied.

**`RandomWrite`'s bound (`rwbound`).** The guard is
`offset + cbWrite >= m_offsetNext` (apdiskio.cpp:979) — a `>=` where `>` would
do — and `m_offsetNext` excludes the buffer currently filling, while `Flush`
issues that buffer *without* advancing it. After writing two full 128 KiB blocks
and flushing, so that 262,144 bytes are durably in the file:

| Target | Result |
| --- | --- |
| offset 0 | ok |
| last 4 bytes of block 0 (131,068) | **rejected**, `ERROR_INVALID_PARAMETER` |
| first 4 bytes of block 1 (131,072) | **rejected** |
| last 4 bytes of durable data (262,140) | **rejected** |

Half the file is durably on disk and unreachable through the API meant to
rewrite it. There is no `RandomWrite` in `SeqWriter`; a caller rewriting a
header does it with a positional write on its own handle after `finish`, which
is what `CheckpointWriter::finish` already does.

**Repeated `Flush` re-writes the whole buffer (`reflush`).** `Flush` does not
advance `m_offsetNext` or clear `m_cbUsed`, so a Flush/Write/Flush loop
re-issues the current buffer, entire, every time. Measured with
`GetProcessIoCounters`, 256 appends of 4 KiB into a 128 KiB buffer:

```
logical_bytes=1048576  device_bytes=34603008  amplification=33.0x
per_flush_device_bytes=135168   content_intact=yes
```

**Not quadratic** — the candidate list suspected it might be, and it is not;
it is `flushes x block`, linear, with a `block / append` constant. The content
stays correct, so this is waste rather than corruption, and no caller in the
tree does it (every `Flush` is a close: rsl.cpp:583, :614, :618,
learn_protocol.cpp:307). `SeqWriter::finish` consumes the writer, which removes
the pattern instead of pricing it.

**Two candidates did not survive.** The swallowed `PrepareNext` return in
`if (!m_pbWrite) PrepareNext();` (apdiskio.cpp:885) cannot produce the NULL
`memcpy` it looks like it should: `m_pbWrite` is only NULL before the first
`PrepareNext`, and that first call issues nothing and can only fail if the ring
was never allocated, which `DoInit` already refused. And the `ERROR_DISK_FULL`
mislabel in `GetOverlappedResultAndCheckSize` (apdiskio.cpp:852) is real by
inspection — any short write is reported as a full disk — but it needs a
genuine short overlapped write to trigger and no fault injection short of a
filter driver produced one. Reported as unconfirmed, not as a finding.

### Cost, honestly

**One OS thread per configured writer, and more memory than the C++.** Parity
needed 2 x 2 x 4 MiB = 16 MiB against `APSEQWRITE`'s 2 x 4 MiB = 8 MiB. A thread
handoff is coarser than an overlapped queue and the ring has to be wider to
cover it. For checkpointing, which runs one at a time, this is affordable; for
anything running many at once it is not, and the learner's copy path should be
sized separately or left alone.

**`finish` ends in a `sync_all`, which `APSEQWRITE::Flush` does not do.** The
C++ leaves the data in the device cache and relies on the checkpoint's rename
being write-through. `SeqWriter` is used through
[`Durability`](src/durability.rs) by callers that need the sync anyway, and
having it in one place beats having each caller remember.

**Alignment is caller-visible, as it is for `SeqReader`.**
`SeqWriterConfig::block` must be a multiple of `SECTOR` (4096). A short final
block is padded to the sector above with explicit zeros and then truncated by
`set_len`, so the logical length is exact and the pad is never a recycled
buffer's contents.

**Portability is real but not free.** Windows `FILE_FLAG_NO_BUFFERING`, Linux
`O_DIRECT`, both through the safe `OpenOptionsExt::custom_flags`, so the crate
keeps `unsafe_code = "forbid"`. macOS has no `O_DIRECT`, so there the open is
ordinary and buffered — correct, just not fast.

### Reopening

Format-invariant: nothing here changes a byte on disk, so any of it can be
revisited from a profile. The open questions are whether the thread handoff can
be tightened enough to close the last 4% (real async submission via IOCP or
io_uring would, at the cost of `unsafe` or a wrapper crate) and where the SLC
cliff actually is for runs larger than 32 GiB. The learner copy path's question
is closed: it has a ring, sized against the C++'s defaults rather than this
crate's — see the migration table below.

## Follow-up: migrating the call sites

| Path | Was | Is now |
| --- | --- | --- |
| Checkpoint write (checkpoint.rs) | `BufWriter::new` — 8 KiB | `SeqWriter`, default config, through `available`/`commit` |
| Learner checkpoint copy (rsl-net `learnport/client.rs`) | `tokio::fs::File` + `write_all` | `SeqWriter`, 2 threads x 4 slots x the streaming chunk |
| Defunct config (`dir::write_defunct`) | small buffered write | unchanged — 4 bytes, and a ring would be pure overhead |

### The learner's copy, and why the thread objection did not apply

This table used to read "still open — thread-per-writer is wrong for many
concurrent copies", which was the right worry aimed at the wrong side of the
protocol. Inbound copies are not the many-at-once case: a replica fetches a
checkpoint when it has fallen too far behind to catch up from the log, and it
fetches *one*, from *one* peer. The many-at-once case is the replica serving
those fetches, and that one is settled in [`READPATH.md`](READPATH.md) — it
keeps `tokio::fs`.

Sized against the C++ rather than against `SeqWriterConfig::default()`, the cost
is small enough that the objection dissolves. `CopyCheckpoint` runs `APSEQWRITE`
at `c_maxWritesDefault` — 2 writes in flight — and the table above shows the
depth curve flat past 2 (2 x 128 KiB at 3061 MiB/s against 8 x 128 KiB's 3207).
So the port runs `threads: 2`, and `slots: 4` rather than 2 because a thread
handoff is coarser than an overlapped queue and the caller wants a spare buffer
to fill while both writers are busy — the same reason parity at the checkpoint's
shape needed 2 x 2 x 4 MiB against the C++'s 2 x 4 MiB. That is two OS threads
and 1 MiB of buffers per copy in progress, against the default config's four
threads and 16 MiB.

The block is `LearnConfig::stream_chunk` rounded up to `SECTOR`, so one socket
read fills exactly one ring block. That tie is the C++'s own arrangement, not a
convenience: `CopyCheckpoint` stages into a buffer sized to
`c_writeBufSizeDefault` for precisely this reason (`learn_protocol.cpp:234`).

**The measured win is not the one this document's tables predict.** Those
compare a ring against a `BufWriter` with the device as the ceiling. Here the
socket is the ceiling and the page cache had room, so the 2.7x above is not
available. What *is* available is that the copied file is re-read immediately,
unbuffered, by `checkpoint::verify_file` — so writing it through the page cache
buys nothing and costs twice, once in evicting everything else on the machine
and once in writeback contending with the verify pass. That is confound 3 from
[`READPATH.md`](READPATH.md) arriving on the write side. `cargo bench -p rsl-net
--bench learnport`, loopback, full fetch-verify-publish:

| Checkpoint state | `tokio::fs` | `SeqWriter` |
| --- | --- | --- |
| 1 MiB | 62.3 MiB/s | **92.2** (+50%) |
| 8 MiB | 200.5 | **302.8** (+57%) |
| 32 MiB | 424.7 | 528.7 (+15%, inside the noise) |

Criterion calls the first two improvements and the third no change. The effect
shrinking as the file grows is the shape to expect if it is cache contention
rather than throughput: the fixed cost of the verify pass is what the larger
runs amortize.

### Driving a blocking ring from async

`SeqWriter` is blocking `std::io` and `copy_checkpoint` is an `async fn`
interleaving socket reads with file writes, so the two do not compose directly —
blocking a Tokio worker inside the copy loop would stall the executor.

`RingSink` bridges them by handing the writer *through* `spawn_blocking` and
taking it back with the result, once per block. Three candidates were weighed
and this is the cheapest:

* **A dedicated thread per copy owning the ring, with a channel to the async
  side.** Removes the per-block task handoff and adds a third OS thread to do
  it, on a path already running two. The handoff it removes is not the expensive
  part.
* **Restructuring so the writer threads read the socket directly.** The socket
  is async and the response is ordered; this is a rewrite of the protocol loop
  to save a memcpy the table above prices at 3.8% at this block size.
* **`spawn_blocking` per block.** One task handoff per block rather than per
  byte, wrapping a call that is normally just a `memcpy` into a free slot — the
  ring's own threads are what wait on the device. At the default chunk that is a
  few thousand handoffs a second on a path bounded by a network.

### How the ring got behind the durability seam

The obstacle was never in the numbers. `CheckpointWriter` writes through the
[`Durability`](src/durability.rs) trait so that [`sim::SimCrash`](src/sim.rs)
can substitute a shadow filesystem and `tests/crash.rs` can cut power at every
prefix of a workload, while `SeqWriter` opened its own real handles. The two
ways out were to teach the trait to hand out a ring writer, or to let the crash
harness exercise a different writer from production. The second was not
acceptable, so the first is what happened:

* `SeqWriter` no longer opens files. It issues whole blocks at explicit offsets
  through a `BlockDevice`, which hands out one `BlockWriter` handle per writer
  thread and, at the end, establishes the file's length.
* `Durability` gained a `Bulk: BlockDevice` associated type. `SyncAll` and
  `NoSync` supply `RealDevice` (unbuffered handles, differing only in whether
  the final `set_len` is followed by an `fsync`); `SimCrash` supplies
  `SimDevice`, whose handles write into the shadow filesystem and journal every
  block.
* `SimDevice` asks for `inline` issue — every block written on the caller's
  thread — because a journal replayed at every prefix has to be deterministic,
  which a pool cannot promise. It also tunes the ring down to 1 thread x 2
  slots x one sector, since none of the sizing means anything without a device
  to overlap against and the production default would allocate 16 MiB per
  writer in a harness that builds one per crash point.

The bytes on disk are identical either way: the blocks tile the same file at
the same offsets and the tail is padded to the sector before `set_len` cuts it
back. `tests/corpus.rs` still reproduces the C++ samples byte for byte.

### The header rewrite

The ring cannot be rewound, so `finish` drains it and establishes the length
*first*, then reopens the staging `.tmp` through `Durability::open` and writes
the marshaled header over the region reserved at offset 0. That is the plain
positional write this document's `RandomWrite` note calls for, in place of
`APSEQWRITE`'s bounds-broken version (apdiskio.cpp:979).
