# SeqIoBench

Measures the sequential I/O classes in `src/common/src/apdiskio.{h,cpp}`, so the
Rust port has a baseline to be compared against. This is a benchmark, not a
test — it asserts nothing and nothing gates on it.

Today it covers `APSEQREAD`, the async sequential reader, under the `read`
subcommand. `APSEQWRITE` belongs here too under a `write` subcommand: it is the
same file, the same overlapped-queue design, and the fixture generator and
result format are already shared, so adding it should not disturb `read`. The
subcommand exists rather than a bare argument list precisely so that can happen
without breaking callers.

The verdict `read` was built to produce is recorded in
[`rust/crates/rsl-storage/READPATH.md`](../../../../rust/crates/rsl-storage/READPATH.md).
The write side already has its decision recorded separately, in
[`DURABILITY.md`](../../../../rust/crates/rsl-storage/DURABILITY.md) — a
`write` subcommand would be extending that argument, not opening a new one.

## Why it is shaped like this

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
cargo build --release -p rsl-storage --example seqio_bench
```

`seqiobench.exe` lands in `out\retail-amd64\SeqIoBench\`; the Rust half in
`rust\target\release\examples\`. Build Release — Debug measures the harness.

## Running

```powershell
.\src\RSL\UnitTest\SeqIoBench\run-sweep.ps1 -Root D:\rslbench -Out results.tsv
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
