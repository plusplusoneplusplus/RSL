# SeqIoBench

Measures the sequential I/O classes in `src/common/src/apdiskio.{h,cpp}`, so the
Rust port has a baseline to be compared against. This is a benchmark, not a
test — it asserts nothing and nothing gates on it.

It covers `APSEQREAD`, the async sequential reader, under the `read`
subcommand, and `APSEQWRITE`, the async sequential writer, under `write` —
same file, same overlapped-queue design, shared fixture generator and result
format.

The verdict `read` was built to produce is recorded in
[`rust/crates/rsl-storage/READPATH.md`](../../../../rust/crates/rsl-storage/READPATH.md);
the verdict for `write` in
[`WRITEPATH.md`](../../../../rust/crates/rsl-storage/WRITEPATH.md). Neither
overlaps [`DURABILITY.md`](../../../../rust/crates/rsl-storage/DURABILITY.md),
which closed the *vote log* gate — `LogFile` writes through
`WriteFileGather` on a `WRITE_THROUGH` handle and never touches `APSEQWRITE`;
`write` here measures the bulk writers (checkpoint, learner copy, defunct
config), which is what `APSEQWRITE` actually serves.

## Why the write side is shaped like this

The read side's problem was the page cache; the write side's is *durability
asymmetry*. `APSEQWRITE` opens `FILE_FLAG_NO_BUFFERING` but **not**
`FILE_FLAG_WRITE_THROUGH` (apdiskio.cpp:698): when a run finishes, the data is
past the page cache but possibly still in the device's write cache. A buffered
Rust writer with no sync has done strictly less work at that point; with
`sync_all`, strictly more. Neither default is a fair pairing, so `write` takes
`--fsync` (a `FlushFileBuffers` after `Flush`), the Rust half takes
`--sync none|all`, and `run-sweep.ps1` pairs rows only at equal endpoints,
stating the discipline in every label.

Two more write-side facts the sweep leans on. `APSEQWRITE` is `OPEN_ALWAYS`
and never truncates (deliberately, to avoid fragmentation — see the comment in
`Flush`), so rewriting one pre-generated fixture of exactly `--length` bytes in
place keeps every row on the same LBAs. And the fixture drive's pseudo-SLC
cache makes sustained writes history-dependent, so phase W0 probes for the
cliff with back-to-back rewrites, and every later row is followed by idle time.

`write` also exposes the zero-copy `GetAvailable`/`CommitAvailable` API as
`--mode commit` (the shape `RSLCheckpointStreamWriter` actually uses,
rsl.cpp:478) against `--mode copy` for plain `Write`, so the memcpy that API
exists to avoid has a price tag.

## Why the read side is shaped like this

`APSEQREAD` opens with `FILE_FLAG_NO_BUFFERING` (apdiskio.cpp:134), so it never
consults the OS page cache. Every Rust read path does. Measured warm, the Rust
side reads out of RAM and the C++ side reads off the disk, and the comparison
means nothing.

The usual Windows answer is `RAMMap -Et` or `EmptyStandbyList.exe` between runs.
Both need Administrator. `run-sweep.ps1` takes the other route: a fixture far
larger than RAM, carved into windows, with each configuration reading its own
window exactly once. `seqiobench gen` writes the fixture **unbuffered**, so no
part of it is resident before its one read — coldness needs no eviction step and
no privilege, because a window that was never cached cannot be warm.

Two things the sweep measures rather than assumes: that the first read of a
window really is cold (`verify-cold` vs `verify-warm`, the same window read
twice), and that `APSEQREAD` really is indifferent to cache state
(`cpp-control-2nd`).

## Building

```powershell
. .\ossbuild\ossbuild.ps1 -Platform x64
msbuild src\RSL\UnitTest\SeqIoBench\SeqIoBench.vcxproj /m /nologo /v:minimal `
  /p:Configuration=Release /p:Platform=x64

cd rust
cargo build --release -p rsl-storage --bin seqio_bench
```

`seqiobench.exe` lands in `out\retail-amd64\SeqIoBench\`; the Rust half in
`rust\target\release\`. Build Release — Debug measures the harness.

## Running

```powershell
.\tools\seqio-bench\run-sweep.ps1 -Root D:\rslbench -Out results.tsv
```

Needs `WindowSizeGiB * 10` of free disk (60 GiB by default) and takes a few
minutes on an NVMe. `-SkipGen` reuses an existing fixture, but only for a repeat
of the *same* sweep: once a window has been read, it is warm, and re-running
gives warm numbers under cold labels. Delete the fixture between real runs.

The two halves can also be driven directly, and share an output format so their
rows can be concatenated:

```powershell
seqiobench.exe  read <file> --depth 4 --block 65536 --record 4096 --label X --header
seqio_bench.exe read <file> --mode bufreader:65536 --record 4096 --label Y

seqiobench.exe  write <file> --length 4294967296 --depth 2 --block 131072 --mode commit --fsync --label X
seqio_bench.exe write <file> --length 4294967296 --mode bufwriter:4194304 --sync all --label Y
```

`--offset`/`--length` select the window; `--record` is the logical read size the
caller asks for, which both sides hold equal so the latency columns compare.

The `fold` column is a wrapping sum of the first 8 bytes of each record. It
exists to stop the copy being optimized away, but it doubles as a cross-language
check: for the same window and the same `--record`, the C++ and Rust rows must
agree exactly. They do. A mismatch means the two sides did not read the same
bytes and the row should be thrown away.

## Reading the output

One tab-separated row per configuration:

| Column | Meaning |
|---|---|
| `impl` | `APSEQREAD`, or the Rust reader (`bufreader`, `file`, `block`, `tokio`) |
| `depth` | Reads in flight. Always 1 for Rust — none of its paths prefetch |
| `block` | Bytes requested from the OS per read |
| `record` | Bytes the caller asked for per call |
| `mibps` | Throughput over the window |
| `p50_ns` … `max_ns` | Per-call latency distribution |

The latency distribution is the reason this reports percentiles rather than a
mean. Most calls are a memcpy out of a buffer that is already full; one call in
`block / record` has to go to the disk. A mean smears those together, and the
whole question of whether prefetching is worth having lives in the tail.

**Read the deep percentiles, not p99.** Stalls land on one call in
`block / record`. At a 10 MiB block and a 4 KiB record that is 1 call in 2560 —
0.039% — so p99 sits entirely inside the memcpy population and reports the same
~100 ns for a reader that stalls for 10 ms every 2560 calls as for one that
never stalls at all. `p999_ns`, `p9999_ns` and `max_ns` are where prefetching
shows up. A comparison drawn from p99 alone concludes the opposite of the truth.

`depth` is capped at `c_maxReads = 64`, and `DoInit` rejects anything below 2
(apdiskio.cpp:90) — depth 1 is not a point on the curve.

## `skiptest`

`APSEQREAD::Skip` has a third mode that is not a benchmark:

```powershell
seqiobench.exe skiptest <scratchfile> --depth 4 --block 65536 --skip 100000 --prefix 1000
```

It writes a scratch file whose every 8-byte word holds its own offset, so one
`GetData` after a `Skip` reports where the reader actually landed. The
large-skip branch (apdiskio.cpp:560) resumes at
`Reset(m_offsetNext + m_cbLeft + dwNumBytes)`, but `m_offsetNext` is the
prefetch frontier rather than the caller's position — it sits `m_numReads`
buffers ahead — and `m_cbLeft` needs subtracting rather than adding. The
observed overshoot is `2 * m_cbLeft + (depth - 1) * block`, exactly. Skips
below `block` take a different branch and are exact.

`Skip` has one caller in the tree, the public `RSLCheckpointStreamReader::Skip`
(rsl.cpp:404), so nothing inside the engine reaches it.

## The write-side defect demos

Four more subcommands demonstrate, by execution, what `APSEQWRITE` does on its
edges. None is a benchmark; `WRITEPATH.md` records what each one showed.

```powershell
seqiobench.exe tailtest <scratch> --block 131072 --depth 2 --bytes 1000000 [--precreate 2000000]
seqiobench.exe rwbound <scratch> --block 131072
seqiobench.exe reflush <scratch> --block 131072 --append 4096 --appends 256
seqiobench.exe accounting <scratch>
```

* `tailtest` — the on-disk state if the process dies before `Flush`
  (simulated by leaking the writer). Fresh file: a clean prefix of *full*
  buffers only — up to a whole buffer of accepted data is simply gone, because
  partial buffers are issued nowhere but `Flush`. Rewriting a longer existing
  file: the old length and the old tail survive past the new data, because
  `OPEN_ALWAYS` never truncated and only `Flush`'s `SetEndOfFile` would have.
* `rwbound` — `RandomWrite`'s `offset + cbWrite >= m_offsetNext` bound
  (apdiskio.cpp:979): the `>=` makes the last byte of the issued region
  unreachable, and because `m_offsetNext` only advances at issue time (and
  `Flush` issues without advancing it), data that is already durable in the
  file can still be rejected as "too close to the end".
* `reflush` — prices the Flush/Write/Flush pattern with
  `GetProcessIoCounters`: every incremental `Flush` re-writes the *entire*
  current buffer (`IssueWrite` always writes `m_cbBufSize`, apdiskio.cpp:755),
  so device bytes are `flushes x block` — linear, not quadratic, but a
  `block / append` amplification. Content stays correct; no caller in the tree
  does this today.
* `accounting` — `DoInit` accepts a non-sector-multiple buffer size, which
  makes the first buffer issue fail exactly the way a full disk would, and the
  straddling path's unguarded `m_cbUsed += ...` (apdiskio.cpp:899) then leaves
  public `BytesIssued()` counting bytes that were never copied anywhere —
  1200 reported, 1000 accepted, 0 on disk.
