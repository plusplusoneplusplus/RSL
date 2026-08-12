<#
.SYNOPSIS
    Drives the C++ APSEQREAD/APSEQWRITE harness and the Rust read and write
    paths over shared fixtures and emits a single tab-separated table.

    The harness it drives is src\RSL\UnitTest\SeqIoBench (whose README covers
    the subcommands and the output columns) plus the seqio_bench binary in
    rust\crates\rsl-storage. This script lives here rather than beside either
    one because it needs both built.

.DESCRIPTION
    The comparison only means anything cold. APSEQREAD opens with
    FILE_FLAG_NO_BUFFERING and never consults the page cache; every buffered
    Rust reader does. Measured warm, the buffered side reads out of RAM and the
    C++ reads off the disk, which is not a comparison of anything.

    Getting cold on Windows normally means RAMMap -Et or EmptyStandbyList
    between runs, both of which need Administrator. This script uses the other
    option: a fixture far larger than RAM, carved into windows. `seqiobench gen`
    writes it unbuffered, so no part of it is resident before it is read.

    THREE CONFOUNDS, found the hard way. Read this before trusting a number.

    1. LBA POSITION DOMINATES. The same APSEQREAD configuration measured
       4037 MiB/s over window 0 and 5823 MiB/s over window 9 of a freshly
       written 60 GiB fixture -- a 1.44x spread from position alone, on a
       DRAM-less drive whose recently written tail is still in SLC. An earlier
       version of this script gave every configuration its own window and put
       the C++ on the last one; it was measuring the region as much as the
       reader, and it reported a ~2x gap that mostly was not there.

    2. THE POSITION EFFECT DECAYS. That same tail measured 5823 MiB/s shortly
       after the write and 3921 MiB/s hours later as the drive folded SLC down
       to TLC. Absolute numbers are comparable only within one run.

    3. BUFFERED AND UNBUFFERED READERS INTERFERE. An unbuffered read straight
       after a buffered 6 GiB read comes back depressed -- on identical LBAs,
       5170 MiB/s before a buffered pass over that window and 2470 MiB/s after.
       Reproducible in direction, erratic in size, and not bounded.

    So the script runs two phases with different guarantees, and labels them:

      * PHASE 1, the trustworthy one. Unbuffered readers only -- APSEQREAD and
        SeqReader -- alternating over the SAME window, repeated. Both are
        cache-independent, so a window can be reread and position, cache state
        and drift are all held constant. This is the phase whose numbers may be
        quoted as a ratio.

      * PHASE 2a, one clean cross-type pair. APSEQREAD then the 8 KiB reader
        over the SAME window, run immediately after phase 1 so nothing buffered
        has happened yet. Confound 3 accumulates -- every later buffered pass
        depresses every later unbuffered measurement, and nothing short of
        emptying the standby list resets it -- so this is the ONLY
        buffered-against-unbuffered ratio in the whole run that can be quoted.

      * PHASE 2b, buffered capacity sweep. Buffered readers only, one per
        window, reported as absolute throughput. Compare these to EACH OTHER,
        never to an unbuffered row. Position still costs up to ~1.4x between
        rows, so only effects larger than that mean anything.

    A settling pass runs first: writing 60 GiB leaves the drive doing
    housekeeping that otherwise drains into the first few measurements.

.PARAMETER Root
    Directory for the fixture. Needs WindowSizeGiB * 10 free.

.PARAMETER WindowSizeGiB
    Bytes each configuration reads. Large enough that per-window startup noise
    does not dominate.

.PARAMETER Reps
    Repetitions per configuration in phase 1.

.PARAMETER Sweep
    Which side to run: `read`, `write`, or `both`. The write sweep has its own
    fixture and its own confounds -- see the W-phase comments below.

.PARAMETER WriteGiB
    Bytes each write configuration writes. Sized to sit inside the drive's
    pseudo-SLC region (phase W0 measures where that gives out).

.EXAMPLE
    .\run-sweep.ps1 -Root D:\rslbench -Out D:\rslbench\results.tsv -Sweep write
#>
[CmdletBinding()]
param(
    [string] $Root = "D:\rslbench",
    [string] $Out = "",
    [int]    $WindowSizeGiB = 6,
    [int]    $Reps = 3,
    [ValidateSet("read", "write", "both")]
    [string] $Sweep = "both",
    [int]    $WriteGiB = 4,
    [int]    $WriteReps = 3,
    [switch] $SkipGen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$cpp = Join-Path $repo "out\retail-amd64\SeqIoBench\seqiobench.exe"
$rust = Join-Path $repo "rust\target\release\seqio_bench.exe"

foreach ($exe in @($cpp, $rust)) {
    if (-not (Test-Path -PathType Leaf $exe)) {
        throw "missing $exe -- build it first (see src\RSL\UnitTest\SeqIoBench\README.md)."
    }
}

$window = [int64]$WindowSizeGiB * 1GB
$windows = 10
$fixture = Join-Path $Root "seqread-fixture.bin"

if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Force $Root | Out-Null }

$totalMiB = [int64]($window * $windows / 1MB)
if (-not $SkipGen -and $Sweep -ne "write") {
    Write-Host "Generating $([int]($totalMiB/1024)) GiB fixture at $fixture (unbuffered; this does not warm it)..."
    & $cpp gen $fixture $totalMiB
    if ($LASTEXITCODE -ne 0) { throw "fixture generation failed" }
}

$physGiB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
Write-Host "Physical memory: $physGiB GiB. Fixture: $([int]($totalMiB/1024)) GiB in $windows windows of $WindowSizeGiB GiB."

$lines = New-Object System.Collections.Generic.List[string]
$first = $true

function Invoke-Row {
    param([string[]] $Argv, [string] $Exe, [string] $What)
    $argv2 = if ($script:first) { $Argv + @("--header") } else { $Argv }
    $output = & $Exe @argv2
    if ($LASTEXITCODE -ne 0) { throw "$What failed" }
    foreach ($l in $output) { $script:lines.Add($l) | Out-Null }
    $script:first = $false
}

function Invoke-Cpp {
    param([int64] $Offset, [int] $Depth, [int] $Block, [string] $Label,
          [int64] $Length = 0, [int] $Record = 4096)
    $len = if ($Length -gt 0) { $Length } else { $script:window }
    Invoke-Row -Exe $script:cpp -What $Label -Argv @(
        "read", $script:fixture, "--offset", "$Offset", "--length", "$len",
        "--depth", "$Depth", "--block", "$Block", "--record", "$Record", "--label", $Label)
}

function Invoke-Rust {
    param([int64] $Offset, [string] $Mode, [string] $Label)
    Invoke-Row -Exe $script:rust -What $Label -Argv @(
        "read", $script:fixture, "--mode", $Mode, "--offset", "$Offset",
        "--length", "$script:window", "--record", "4096", "--label", $Label)
}

if ($Sweep -ne "write") {

# Writing the fixture leaves the drive busy. Two unbuffered full passes settle
# it without warming anything.
Write-Host "`nSettling the drive after the write (two unbuffered full passes)..."
foreach ($i in 1..2) {
    & $cpp read $fixture --depth 8 --block 1048576 --record 4096 --label "settle$i" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "settling pass failed" }
}

# ---------------------------------------------------------------------------
# Phase 1 -- unbuffered only, same window, alternating. Quotable.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase 1: unbuffered, same window, alternating (trustworthy) =="
# SeqReader's ring is sized to allocate what APSEQREAD does at depth 8 x 1 MiB:
# 8 threads x 8 slots x 1 MiB = 8 MiB.
foreach ($w in @(0, 9)) {
    $off = [int64]$w * $window
    foreach ($rep in 1..$Reps) {
        Write-Host "  window $w rep $rep"
        Invoke-Cpp  -Offset $off -Depth 8 -Block 1048576   -Label "p1-APSEQREAD-8x1MiB-w$w-r$rep"
        Invoke-Rust -Offset $off -Mode "ring:8x8x1048576"  -Label "p1-SeqReader-8x8x1MiB-w$w-r$rep"
    }
}

# ---------------------------------------------------------------------------
# Phase 2a -- the one clean cross-type pair.
#
# Phase 1 was unbuffered throughout, so nothing has entered the page cache yet
# and this APSEQREAD reference is uncontaminated. The 8 KiB reader then reads
# the SAME still-cold window, so position cancels too. From here on, confound 3
# is in play and no further unbuffered measurement is comparable to a buffered
# one -- which is why there is exactly one pair here and not eight.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase 2a: the one quotable cross-type pair (window 0) =="
$off0 = [int64]0 * $window
Invoke-Cpp  -Offset $off0 -Depth 8 -Block 1048576 -Label "p2a-APSEQREAD-ref-w0"
Invoke-Rust -Offset $off0 -Mode "bufreader:8192"  -Label "p2a-replay-today-8KiB"

# ---------------------------------------------------------------------------
# Phase 2b -- buffered capacity sweep. Buffered only, so cross-type
# contamination is irrelevant: every row here is affected the same way.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase 2b: buffered capacity sweep (compare to each other only) =="
# The former `tokio:65536` learner-streaming row is gone with the tokio
# dev-dependency (commit 4f2fc24); READPATH.md keeps its one measured number.
$buffered = @(
    @{ W = 1; Mode = "bufreader:65536";    Label = "p2b-replay-64KiB" }
    @{ W = 2; Mode = "bufreader:1048576";  Label = "p2b-replay-1MiB" }
    @{ W = 3; Mode = "bufreader:10485760"; Label = "p2b-replay-10MiB" }
    @{ W = 4; Mode = "file";               Label = "p2b-scan-unbuffered-4KiB" }
    @{ W = 5; Mode = "block:65536";        Label = "p2b-checkpoint-64KiB" }
    @{ W = 6; Mode = "block:10485760";     Label = "p2b-checkpoint-10MiB" }
)
foreach ($p in $buffered) {
    Write-Host "  window $($p.W): $($p.Label)"
    Invoke-Rust -Offset ([int64]$p.W * $window) -Mode $p.Mode -Label $p.Label
}

# ---------------------------------------------------------------------------
# Phase 3 -- the APSEQREAD shape sweep. All rows are unbuffered and on one
# window, so they are comparable to each other even though confound 3 has
# depressed them all by whatever phase 2 cost. Do not compare these to phase 1.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase 3: APSEQREAD shape sweep (window 8; compare to each other only) =="
$off8 = [int64]8 * $window
#   depth 2 / 10 MiB -- checkpoint header, log replay (legislator.cpp:638, :1489)
#   depth 4 / 64 KiB -- learner streaming (learn_protocol.cpp:84)
#   depth 2 / 512 B  -- defunct-config read (legislator.cpp:6767); short window,
#                       since at its rate a full one takes minutes and it is
#                       cache-independent so the rate does not depend on length.
Invoke-Cpp -Offset $off8 -Depth 2  -Block 10485760 -Label "p3-inuse-replay-2x10MiB"
Invoke-Cpp -Offset $off8 -Depth 4  -Block 65536    -Label "p3-inuse-learner-4x64KiB"
Invoke-Cpp -Offset $off8 -Depth 2  -Block 512      -Label "p3-inuse-defunct-2x512B" -Length 512MB -Record 512
Invoke-Cpp -Offset $off8 -Depth 2  -Block 65536    -Label "p3-sweep-2x64KiB"
Invoke-Cpp -Offset $off8 -Depth 8  -Block 1048576  -Label "p3-sweep-8x1MiB"
Invoke-Cpp -Offset $off8 -Depth 64 -Block 65536    -Label "p3-sweep-64x64KiB"
Invoke-Cpp -Offset $off8 -Depth 4  -Block 1048576  -Label "p3-sweep-4x1MiB"

} # end read sweep

# ===========================================================================
# The write sweep. Different confounds from the read side, so a different
# structure:
#
#   1. SLC CACHE EXHAUSTION, LOOKED FOR AND NOT FOUND AT THIS ROW SIZE. The
#      fixture drive is DRAM-less TLC with a pseudo-SLC region, so a sustained
#      run should eventually collapse. Phase W0 is the probe: eight 4 GiB
#      rewrites back to back, 32 GiB with zero idle, stayed within
#      3830-3972 MiB/s -- a 3.7% spread with no trend (WRITEPATH.md records
#      it). At $WriteGiB per row every configuration here sits inside the
#      cache, so the sweep runs gapless: the idle that used to follow every
#      row was padding against a cliff W0 itself says is beyond 32 GiB. A
#      sweep with LARGER rows would need W0 re-checked before trusting that.
#
#   2. DRIVE STATE IS HISTORY-DEPENDENT. A row still inherits the drive the
#      previous row left. Interleaved repetition (medians, not means) is the
#      mitigation, and is why W1 quotes medians of alternating reps rather
#      than any single pair. One shape remains unexplained: in an early
#      heterogeneous gapless batch the LAST row collapsed to 765-828 MiB/s
#      whatever it was, across two runs. It is on the record in WRITEPATH.md
#      as an open question -- W0's homogeneous gapless batch shows nothing
#      like it, and a cliff would decay progressively rather than fire at one
#      position, so it is not a constant to pad around.
#
#   3. THE SYNC DISCIPLINE IS THE COMPARISON. APSEQWRITE is NO_BUFFERING but
#      NOT WRITE_THROUGH: past the page cache, not past the device cache. A
#      buffered Rust writer with no sync has done strictly less when it
#      returns; with sync_all, strictly more. So W1 pairs both sides at the
#      same endpoint -- everything durable to the device (--fsync / --sync
#      all) -- and W2 shows the undisciplined pair once, labelled as such.
#
#   4. LBA POSITION. Both sides rewrite ONE fixture of exactly $WriteGiB in
#      place -- APSEQWRITE's own OPEN_ALWAYS-never-truncate behaviour -- so
#      every row lands on the same LBAs and NTFS allocation is out of the
#      picture after the first write.
# ===========================================================================
if ($Sweep -ne "read") {

$wlen = [int64]$WriteGiB * 1GB
$wfixture = Join-Path $Root "seqwrite-fixture.bin"

function Invoke-CppWrite {
    param([int] $Depth, [int] $Block, [string] $Label, [string] $Mode = "copy",
          [switch] $Fsync, [int] $Record = 4096)
    $argv = @("write", $script:wfixture, "--length", "$script:wlen",
              "--depth", "$Depth", "--block", "$Block", "--record", "$Record",
              "--mode", $Mode, "--label", $Label)
    if ($Fsync) { $argv += "--fsync" }
    Invoke-Row -Exe $script:cpp -What $Label -Argv $argv
}

function Invoke-RustWrite {
    param([string] $Mode, [string] $Label, [string] $Sync = "all")
    Invoke-Row -Exe $script:rust -What $Label -Argv @(
        "write", $script:wfixture, "--mode", $Mode, "--length", "$script:wlen",
        "--record", "4096", "--sync", $Sync, "--label", $Label)
}

if (-not (Test-Path $wfixture) -or (Get-Item $wfixture).Length -ne $wlen) {
    Write-Host "`nGenerating $WriteGiB GiB write fixture at $wfixture..."
    & $cpp gen $wfixture ([int64]($wlen / 1MB))
    if ($LASTEXITCODE -ne 0) { throw "write fixture generation failed" }
}

# ---------------------------------------------------------------------------
# Phase W0 -- SLC-cliff probe. The same configuration rewriting the same
# LBAs back to back with no idle; if a cliff exists inside reps x $WriteGiB
# of sustained writing, the reps stop agreeing. Rows are comparable only to
# each other.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase W0: SLC-cliff probe ($($WriteReps + 5) back-to-back rewrites, no idle) =="
foreach ($rep in 1..($WriteReps + 5)) {
    Write-Host "  cliff rep $rep"
    Invoke-CppWrite -Depth 4 -Block 1048576 -Label "w0-cliff-4x1MiB-r$rep"
}

# ---------------------------------------------------------------------------
# Phase W1 -- the load-bearing pairs, at the same durability endpoint.
# Alternating over the same fixture, $WriteReps reps, back to back -- W0 is
# the evidence that idle between rows buys nothing at this row size.
# The five rows: the two shapes the engine actually runs (checkpoint
# 2 x 4 MiB zero-copy, learner/defunct 2 x 128 KiB), the Rust checkpoint
# writer today (BufWriter::new = 8 KiB), the one-line fix (BufWriter at the
# 4 MiB block), and the block-writer shape.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase W1: matched durability (--fsync / --sync all), alternating =="
foreach ($rep in 1..$WriteReps) {
    Write-Host "  rep $rep"
    Invoke-CppWrite -Depth 2 -Block 4194304 -Mode commit -Fsync -Label "w1-APSEQWRITE-ckpt-2x4MiB-commit-fsync-r$rep"
    Invoke-CppWrite -Depth 2 -Block 131072  -Mode copy   -Fsync -Label "w1-APSEQWRITE-2x128KiB-copy-fsync-r$rep"
    Invoke-RustWrite -Mode "bufwriter:8192"    -Sync all -Label "w1-ckpt-today-8KiB-syncall-r$rep"
    Invoke-RustWrite -Mode "bufwriter:4194304" -Sync all -Label "w1-bufwriter-4MiB-syncall-r$rep"
    Invoke-RustWrite -Mode "big:4194304"       -Sync all -Label "w1-big-4MiB-syncall-r$rep"
}

# ---------------------------------------------------------------------------
# Phase W2 -- the undisciplined pair, once, so the difference the sync makes
# is on the record. APSEQWRITE bare returns with data past the page cache but
# maybe in the device cache; the bufwriter row returns with data merely in
# the PAGE cache. Not an apples comparison -- that is the point of the row.
# Neither row needs idle behind it to keep its writeback out of the next row:
# seqio_bench already does an untimed sync_all after the clock stops when
# --sync none (seqio_bench.rs:637), and the APSEQWRITE row is NO_BUFFERING, so
# there is no page cache to drain -- only the device cache it is measuring.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase W2: the undisciplined pair (no fsync / --sync none) =="
Invoke-CppWrite -Depth 2 -Block 131072 -Mode copy -Label "w2-APSEQWRITE-2x128KiB-nosync"
Invoke-RustWrite -Mode "bufwriter:4194304" -Sync none -Label "w2-bufwriter-4MiB-nosync"

# ---------------------------------------------------------------------------
# Phase W3 -- the APSEQWRITE shape sweep, bare (its native discipline), all
# on the same fixture so comparable to each other. Depth 1 is legal for the
# writer (DoInit accepts >= 1, apdiskio.cpp:661, unlike the reader's > 1)
# and so is a real point on this curve. copy-vs-commit at the two production
# shapes prices the memcpy GetAvailable exists to avoid.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase W3: APSEQWRITE shape sweep (bare, compare to each other only) =="
foreach ($rep in 1..2) {
    Write-Host "  rep $rep"
    Invoke-CppWrite -Depth 1 -Block 131072   -Label "w3-1x128KiB-r$rep"
    Invoke-CppWrite -Depth 2 -Block 131072   -Label "w3-2x128KiB-inuse-r$rep"
    Invoke-CppWrite -Depth 4 -Block 131072   -Label "w3-4x128KiB-r$rep"
    Invoke-CppWrite -Depth 8 -Block 131072   -Label "w3-8x128KiB-r$rep"
    Invoke-CppWrite -Depth 2 -Block 65536    -Label "w3-2x64KiB-r$rep"
    Invoke-CppWrite -Depth 2 -Block 1048576  -Label "w3-2x1MiB-r$rep"
    Invoke-CppWrite -Depth 4 -Block 1048576  -Label "w3-4x1MiB-r$rep"
    Invoke-CppWrite -Depth 2 -Block 4194304  -Label "w3-2x4MiB-inuse-r$rep"
    Invoke-CppWrite -Depth 4 -Block 4194304  -Label "w3-4x4MiB-r$rep"
    Invoke-CppWrite -Depth 2 -Block 131072  -Mode commit -Label "w3-2x128KiB-commit-r$rep"
    Invoke-CppWrite -Depth 2 -Block 4194304 -Mode commit -Label "w3-2x4MiB-commit-r$rep"
}

# ---------------------------------------------------------------------------
# Phase W4 -- the Rust capacity sweep at the durable endpoint, comparable to
# each other and to the W1 Rust rows.
# ---------------------------------------------------------------------------
Write-Host "`n== Phase W4: Rust write capacity sweep (--sync all) =="
foreach ($rep in 1..2) {
    Write-Host "  rep $rep"
    Invoke-RustWrite -Mode "file"                -Label "w4-file-per-record-r$rep"
    Invoke-RustWrite -Mode "bufwriter:8192"      -Label "w4-bufwriter-8KiB-r$rep"
    Invoke-RustWrite -Mode "bufwriter:65536"     -Label "w4-bufwriter-64KiB-r$rep"
    Invoke-RustWrite -Mode "bufwriter:1048576"   -Label "w4-bufwriter-1MiB-r$rep"
    Invoke-RustWrite -Mode "bufwriter:10485760"  -Label "w4-bufwriter-10MiB-r$rep"
    Invoke-RustWrite -Mode "big:1048576"         -Label "w4-big-1MiB-r$rep"
}

} # end write sweep

$text = $lines -join "`r`n"
Write-Host "`n$text"
if ($Out) {
    Set-Content -Path $Out -Value $text -Encoding utf8
    Write-Host "`nWrote $Out"
}

Write-Host @"

Reading the output:
  p1-*   quotable. Same window, alternating, both unbuffered. Compare directly.
  p2a-*  the single quotable buffered-against-unbuffered ratio. Same window,
         and taken before any buffered pass had happened.
  p2b-*  buffered rows against EACH OTHER only. Never against p1, p2a or p3.
  p3-*   APSEQREAD shapes against each other only, on one window.

  The first phase-1 repetition of each window tends to read low; it is a
  first-touch artifact. Take the median, not the mean.

  w0-*   SLC-cliff probe: back-to-back rewrites, no idle. Divergence across
         reps is the pseudo-SLC cache draining. Compare to each other only.
  w1-*   the load-bearing write rows: both sides end with everything durable
         to the device. Medians across reps; quotable against each other.
  w2-*   the undisciplined pair, once, for the record. Not comparable to w1.
  w3-*   APSEQWRITE shapes, bare, against each other only.
  w4-*   Rust write capacities at --sync all, against each other and w1.
"@
