# The read path

The C++ engine reads files through `APSEQREAD` (`src/common/src/apdiskio.{h,cpp}`):
`FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED`, page-aligned `VirtualAlloc`
buffers, and a circular queue of `m_numReads` overlapped reads kept permanently
in flight — `Reset` primes the whole ladder at open (apdiskio.cpp:329) and
`ReadNext` re-issues on the buffer the caller just released *before* blocking on
the oldest one (apdiskio.cpp:252-283), so queue depth stays constant.

The port originally had no equivalent. It carried over the observable behaviour
— the open-time size snapshot, the 64 KiB chunk as `LearnConfig::stream_chunk` —
and read with whatever the standard library offered. This records what that
cost, and what replacing it bought.

## APSEQREAD: ported, as `SeqReader`

Gate: build an `APSEQREAD`-style reader only if correctly-sized buffering plus
the OS page cache leaves a gap that a portable design can actually close.

**Verdict: built.** [`seqread::SeqReader`](src/seqread.rs) reaches parity with
`APSEQREAD` — 99.5%–104.5% across two file regions and two independent
measurement runs, at the same buffer memory — in safe Rust with no FFI, no
`unsafe`, and no platform API beyond one open flag.

### How this was measured, and what turned out not to be measurable

`APSEQREAD` bypasses the page cache. A `BufReader` does not. That single
difference makes most of the obvious comparisons untrustworthy on real hardware,
and three separate confounds had to be found the hard way before any number here
was worth reporting. They are recorded because the harness still cannot remove
two of them, and anyone re-running it will hit them again.

**1. Position on the device dominates.** The *same* `APSEQREAD` configuration
reads 4037 MiB/s over the first 6 GiB of a freshly-written 60 GiB fixture and
5823 MiB/s over the last 6 GiB — a 1.44x spread from LBA alone, on a DRAM-less
drive whose recently-written tail is still in SLC while the head has folded down
to TLC. Any sweep that gives each configuration its own region is measuring the
region as much as the configuration.

**2. That position effect decays.** The same tail region measured 5823 MiB/s
shortly after the fixture was written and 3921 MiB/s hours later, as the drive
finished folding. Absolute numbers are only comparable within a single run.

**3. Buffered and unbuffered readers interfere.** An unbuffered read immediately
following a buffered 6 GiB read comes back badly depressed — on the same LBAs,
`APSEQREAD` measured 5170 MiB/s before a buffered pass over that window and
2470 MiB/s after it. Presumably standby-list reclaim contending with the
unbuffered path. It is reproducible in direction and erratic in size.

Together these mean:

| Comparison | Trustworthy? |
| --- | --- |
| Unbuffered vs unbuffered, same window, repeated | **Yes** — both are cache-independent, so the window can be reread and position and cache state are held constant |
| Buffered vs buffered, each on a fresh window | Directionally — position adds up to ~1.4x of error, so large effects survive and small ones do not |
| Buffered vs unbuffered | **No** — carries confounds 1 and 3 at once, and 3 has no bound |

So the load-bearing claim below is an unbuffered-vs-unbuffered one. Everything
involving a `BufReader` is reported as directional and should not be quoted to
two significant figures.

Machine: Intel Core Ultra 7 265KF, 63.6 GiB RAM, Kingston SNV3S1000G NVMe, NTFS,
Windows 11. Harnesses: `src/RSL/UnitTest/SeqIoBench` (C++) and
`benches/readpath.rs` (Rust), driven by `run-sweep.ps1`. 6 GiB windows,
4 KiB logical reads.

### The result that matters: SeqReader against APSEQREAD

Both unbuffered, so both are cache-independent and the same window can be read
repeatedly. `SeqReader` at 8 threads x 8 slots x 1 MiB allocates 8 MiB, exactly
what `APSEQREAD` allocates at depth 8 x 1 MiB. Means of three repetitions:

| Run | Region | `APSEQREAD` | `SeqReader` | Ratio |
| --- | --- | --- | --- | --- |
| A | tail (SLC-resident) | 5823 | 5793 | **99.5%** |
| A | head | 4037 | 4028 | **99.8%** |
| B | tail (folded) | 3921 | 4099 | **104.5%** |
| B | head | 4038 | 4017 | **99.5%** |
| C (`run-sweep.ps1` phase 1) | tail | 5815 | 5813 | **100.0%** |
| C (`run-sweep.ps1` phase 1) | head | 4028 | 4022 | **99.9%** |

Parity, at four different device speeds, across three runs — the last of them
the committed harness driving itself end to end. Medians of three repetitions;
the first repetition over a window tends to read low and is a first-touch
artifact. Latency matches too: p99 800 ns for both, p99.9 113 µs against
116 µs, p99.99 175 µs against 165 µs.

Larger rings do not help much and are not free — 16 slots measured 5883 (101.0%)
against 8 slots' 5793, for twice the memory. The default is 8.

The one place `APSEQREAD` is still better is the single worst call: its max
sits at a steady 726–740 µs where `SeqReader` ranges 0.9–2.1 ms with occasional
outliers. That is thread scheduling, which `APSEQREAD` does not have to do.
Everything at p99.99 and below is indistinguishable.

### What the port was leaving on the floor

Confound 3 accumulates and cannot be reset without emptying the standby list, so
there is exactly **one** buffered-against-unbuffered ratio in the whole sweep
worth quoting: the first one, taken on window 0 straight after phase 1 while
nothing buffered had yet run. Same window, both cold.

| Window 0, phase 2a | MiB/s |
| --- | --- |
| `APSEQREAD` 8 x 1 MiB | 4029 |
| Log replay today — `BufReader::new`, 8 KiB | 676 |

**Today's replay reader runs at 17% of `APSEQREAD` on identical LBAs.** Every
other cross-type pairing in earlier drafts of this document was contaminated,
and an earlier version of this file quoted a table of eight such ratios that
should not have been believed.

Among buffered readers the comparison is sound — they are all affected by
confound 3 the same way — though each sits on its own window, so only effects
larger than the ~1.4x position spread mean anything:

| Buffered reader | MiB/s |
| --- | --- |
| bare `File`, 4 KiB reads — log scan today (log.rs:319) | 655 |
| `BufReader::new`, 8 KiB — log replay today (log.rs:522, :737) | 676 |
| `tokio::fs`, 64 KiB chunks — learner streaming today (server.rs:405) | 959 |
| `BufReader` 64 KiB | 1017 |
| `File` + `read_exact`, 64 KiB blocks — checkpoint today (checkpoint.rs:694) | 1030 |
| `BufReader` 1 MiB | 2475 |
| `BufReader` 10 MiB | 2608 |
| `File` + `read_exact`, 10 MiB blocks | 2938 |

Two conclusions survive comfortably, both far larger than 1.4x.

**Capacity is worth about 3.7x.** Every `BufReader` in this crate is
`BufReader::new`, the 8 KiB default; 1 MiB is 676 → 2475. That is a one-line
change and it is the single largest available win.

**Capacity alone does not finish the job.** A read-then-consume loop leaves the
device idle while the caller drains the buffer, and issues one read at a time,
which gives an NVMe a queue depth of one. Growing the buffer fixes neither: 1
MiB → 10 MiB buys 1.05x for 10x the memory. Recovering the rest needs
concurrency, which is what the ring provides — and which is why `SeqReader`
reaches 4022 on the same window where the best buffered reader manages 2608.

### The APSEQREAD shapes themselves

All unbuffered on one window, so comparable to each other. The three
configurations the C++ engine actually runs are marked.

| depth x block | MiB/s |
| --- | --- |
| 8 x 1 MiB | 5797 |
| 64 x 64 KiB | 5631 |
| 4 x 1 MiB | 5601 |
| 2 x 10 MiB — *replay, checkpoint header* | 4669 |
| 4 x 64 KiB — *learner streaming* | 2465 |
| 2 x 64 KiB | 1378 |
| 2 x 512 B — *defunct-config read* | **31** |

Bytes in flight is what governs, and the engine's own choices are off the
optimum in both directions: 2 x 10 MiB carries 20 MiB in flight for less
throughput than 8 x 1 MiB's 8 MiB, while the defunct-config read at 2 x 512 B
manages 31 MiB/s because `block == record` makes every `GetData` a disk round
trip. That last one is slower than *any* buffered Rust reader in the table
above, by a factor of twenty — `APSEQREAD` is not uniformly a win, and one of
its three production configurations is a liability.

### Warm, where the parser is the ceiling

`cargo bench -p rsl-storage --bench readpath`, a 32 MiB log in the temp
directory, fully cached, through the real `log::scan`:

| Reader | Throughput |
| --- | --- |
| bare `File` | 0.68 GiB/s |
| `BufReader` 8 KiB (today) | 1.06 |
| `BufReader` 64 KiB | 1.36 |
| `BufReader` 1 MiB | 1.40 |
| `BufReader` 10 MiB | 1.25 |
| **`SeqReader` 4x4x1 MiB / 8x8x1 MiB** | **1.68 / 1.68** |

This is the one comparison where the cache asymmetry runs *against* `SeqReader`
— every `BufReader` row is reading out of RAM while `SeqReader` is unbuffered
and going to the disk — and it still wins by 20% over the best of them.

The reason is that `log::scan` is parser-bound at roughly 1.5 GiB/s, and a
`BufReader` refill *stalls* the parser: read, parse, read, parse. `SeqReader`
parses on the caller's thread while its readers fill the ring, so the two
overlap. Removing the refill stalls is worth more than reading from RAM.

`SeqReader` 4x4 and 8x8 measuring identically (1.6798 against 1.6795) confirms
it: on this path the parser is the limit, and threads past 4 buy nothing.

Note also that `BufReader` at 10 MiB is *worse* than at 1 MiB in this table.
Cold, bigger is better; warm, a 10 MiB buffer is L2/L3 pressure with nothing to
show for it. 1 MiB is the size that survives both, which is why it is
`SeqReaderConfig`'s default block and not the 10 MB the C++ uses.

### What was not inherited

`SeqReader` is not a transliteration. Three `APSEQREAD` defects are deliberately
absent, and the module docs say so at each site:

**The lossy partial tail.** `GetDataPointer` with `pcbRead == NULL`
(apdiskio.cpp:460-479) copies the straddling bytes into its scratch buffer and
then returns `ERROR_HANDLE_EOF` without handing them back. `GetData` always
passes `NULL` (apdiskio.cpp:513), so every `GetData` caller is on that path.

**The `Skip` overshoot.** The large-skip branch (apdiskio.cpp:560) resumes at
`Reset(m_offsetNext + m_cbLeft + dwNumBytes)`, but `m_offsetNext` is the
prefetch frontier, sitting `m_numReads` buffers ahead of the caller, and
`m_cbLeft` needs subtracting rather than adding. `seqiobench skiptest`
demonstrates it against a file whose every word holds its own offset:

| depth | block | prefix | skip | expected | landed | overshoot |
| --- | --- | --- | --- | --- | --- | --- |
| 4 | 64 KiB | 1,000 | 100,000 | 101,000 | 426,680 | +325,680 |
| 2 | 64 KiB | 4,096 | 200,000 | 204,096 | 392,512 | +188,416 |
| 4 | 64 KiB | 1,000 | 30,000 | 31,000 | 31,000 | 0 (other branch) |

The overshoot is exactly `2 * m_cbLeft + (depth - 1) * block`, so the prefetch
depth — an I/O tuning knob — silently changes where a `Skip` lands. `SeqReader`
has no `Skip`; seeking is `open_at`, expressed in caller-visible file offsets
with no notion of a frontier.

**Stale end-of-file flags.** `Reset` breaks out of its priming loop on the first
`ERROR_HANDLE_EOF` (apdiskio.cpp:334-338), leaving buffers past that index
holding the `m_fNotEof` from an earlier `Reset`. Narrow — it needs a second
`Reset` after one that broke early — but it exists because the reader keeps
state for buffers it has not issued. Slot state in the ring is reset per block.

### Cost, honestly

**One OS thread per configured reader.** Right for replay and checkpoint reads,
which run one at a time. Wrong for the learn port serving many concurrent peers,
where the count multiplies — that path should keep a plain reader, or share a
pool, and the migration has to make that call per call site.

**Alignment is now a caller-visible constraint.** `SeqReaderConfig::block` must
be a multiple of `SECTOR` (4096), because unbuffered reads are rejected outright
otherwise. `open_at` takes an arbitrary offset and handles the sector prefix
itself, so callers do not have to, but a misconfigured block size is an error at
open rather than a silent slowdown.

**Portability is real but not free.** Windows uses `FILE_FLAG_NO_BUFFERING` and
Linux `O_DIRECT`; both go through `OpenOptionsExt::custom_flags`, which is safe,
so the crate keeps `unsafe_code = "forbid"`. macOS has no `O_DIRECT` —
`F_NOCACHE` is a post-open `fcntl` — so there the open is ordinary and buffered.
Correctness is unaffected; only cache behaviour and throughput are.

### Reopening

Format-invariant, so any of this can be revisited from a profile without
touching anything on disk. The open questions are the worst-case latency gap
(thread scheduling, which real async submission via IOCP or io_uring would
remove, at the cost of `unsafe` or a wrapper crate) and whether the learn port
wants a shared reader pool.

## Follow-up: migrating the call sites

| Path | Was | Is now |
| --- | --- | --- |
| Log replay (log.rs:522, :737) | `BufReader::new` — 8 KiB | **still open** |
| Log scan (log.rs:319) | bare `File::open` | **still open** |
| Checkpoint read (checkpoint.rs) | `File` + `read_exact` per block | `SeqReader`, default config |
| Learner streaming (server.rs:405-421) | `tokio::fs` + one `stream_chunk` buffer | **still open** — thread-per-reader is the wrong shape for many concurrent peers |

`CheckpointReader::open` and `checkpoint::verify_file` now read the header off
an ordinary handle — it is a page or two, and a ring of read-ahead over that is
pure setup cost — and stream the user state through a `SeqReader` opened at the
header's end. `open_at` is the reader's whole notion of seeking, which is why
the position is chosen at open time rather than sought to afterwards; the
non-seeking half of `CheckpointReader::new` is factored out as `assemble` so
both constructors share the same validation.

The log paths are still open, and the learner one needs a decision about
threads before it needs any code.
