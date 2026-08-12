//! The Rust half of the sequential-I/O comparison against `apdiskio.cpp`.
//!
//! This mirrors `src/RSL/UnitTest/SeqIoBench/main.cpp` exactly: same
//! subcommand, same fixture file, same `--offset`/`--length` window, same
//! logical record size, same fold over the bytes, and the same tab-separated
//! `RESULT` line. Only the reader underneath changes. Run both against the same
//! file on the same machine and the columns line up.
//!
//! Today only `read` exists, against `APSEQREAD`. A `write` subcommand
//! comparing the port's append path against `APSEQWRITE` belongs here too, and
//! the shared pieces — argument shape, percentile reporting, result line — are
//! factored so it can be added without touching `read`.
//!
//! The C++ side is cache-independent by construction — `APSEQREAD` opens with
//! `FILE_FLAG_NO_BUFFERING` and never consults the page cache. Every buffered
//! reader here does. So the cold/warm distinction is entirely a problem for
//! *this* binary, which is why it takes a window: stripe a larger-than-RAM
//! fixture and a region is evicted long before it is revisited.
//!
//! ```text
//! cargo run --release -p rsl-storage --example seqio_bench -- \
//!     read <path> --mode bufreader:65536 --offset 0 --length 10737418240 --record 4096
//! ```
//!
//! Modes:
//!
//! | Mode | Models |
//! | --- | --- |
//! | `file` | `LogScanner::open` — bare `File`, one syscall per record (log.rs:319) |
//! | `bufreader:<cap>` | log replay — `BufReader` (log.rs:522, :737); `cap` 8192 is today's default |
//! | `block:<n>` | checkpoint read — `File` + `read_exact` per block (checkpoint.rs:694) |
//! | `tokio:<chunk>` | learner streaming — `tokio::fs::File` into one reused chunk (server.rs:405) |
//! | `ring:<threads>x<slots>x<block>` | the shipped [`SeqReader`] — unbuffered ring, the port's `APSEQREAD` |
//!
//! Candidate designs that lost to `ring` — a `FILE_FLAG_SEQUENTIAL_SCAN`
//! `BufReader`, a single prefetch thread buffered and unbuffered, and static
//! striding across N threads — are not here. `READPATH.md` records what they
//! measured and why each was dropped.

use rsl_storage::seqread::{SeqReader, SeqReaderConfig, SECTOR};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::time::Instant;

/// What the harness measures. Each variant is one of the port's real read
/// strategies, named after the call site it comes from.
enum Mode {
    /// Bare `File`: one `read` syscall per logical record.
    Bare,
    /// `BufReader` with an explicit capacity.
    Buffered(usize),
    /// `read_exact` a whole block, then serve records out of it.
    Block(usize),
    /// `tokio::fs::File` read into a single reused chunk buffer.
    Tokio(usize),
    /// The shipped [`SeqReader`]: a circular queue of read slots, the shape
    /// `APSEQREAD` itself uses. Slots are read-ahead distance; thread count is
    /// device queue depth. Always unbuffered.
    Ring {
        threads: usize,
        slots: usize,
        block: usize,
    },
}

impl Mode {
    fn parse(s: &str) -> Result<Mode, String> {
        let (kind, arg) = match s.split_once(':') {
            Some((k, a)) => (k, Some(a)),
            None => (s, None),
        };
        let size = || -> Result<usize, String> {
            arg.ok_or_else(|| format!("mode `{kind}` needs a size, e.g. `{kind}:65536`"))?
                .parse::<usize>()
                .map_err(|e| format!("bad size in `{s}`: {e}"))
        };
        match kind {
            "file" => Ok(Mode::Bare),
            "bufreader" => Ok(Mode::Buffered(size()?)),
            "block" => Ok(Mode::Block(size()?)),
            "tokio" => Ok(Mode::Tokio(size()?)),
            // `<threads>x<slots>x<block>`. Every term is explicit: the sizing is
            // the thing under test, so it may not come from ambient state.
            "ring" => {
                let a = arg.ok_or_else(|| {
                    "mode `ring` needs `<threads>x<slots>x<block>`, e.g. `ring:8x8x1048576`"
                        .to_string()
                })?;
                let mut parts = a.split('x');
                let mut term = |what: &str| -> Result<usize, String> {
                    parts
                        .next()
                        .ok_or_else(|| {
                            format!("bad ring spec `{a}`, want `<threads>x<slots>x<block>`")
                        })?
                        .parse::<usize>()
                        .map_err(|e| format!("bad {what} in `{a}`: {e}"))
                };
                let threads = term("thread count")?;
                let slots = term("slot count")?;
                let block = term("block")?;
                if parts.next().is_some() {
                    return Err(format!(
                        "bad ring spec `{a}`, want `<threads>x<slots>x<block>`"
                    ));
                }
                if !block.is_multiple_of(SECTOR) {
                    return Err(format!(
                        "ring block {block} must be a multiple of {SECTOR}: unbuffered \
                         reads are rejected outright if length is not sector-aligned"
                    ));
                }
                Ok(Mode::Ring {
                    threads,
                    slots,
                    block,
                })
            }
            _ => Err(format!("unknown mode `{kind}`")),
        }
    }

    /// The `block` column of the result line: how much this reader asks the OS
    /// for at a time. `file` asks for exactly one record.
    fn block(&self, record: usize) -> usize {
        match *self {
            Mode::Bare => record,
            Mode::Buffered(n) | Mode::Block(n) | Mode::Tokio(n) => n,
            Mode::Ring { block, .. } => block,
        }
    }

    /// Reads the OS may be working on at once. Only `ring` exceeds 1 — the rest
    /// are strictly read-then-consume.
    fn depth(&self) -> usize {
        match *self {
            Mode::Ring { threads, .. } => threads,
            _ => 1,
        }
    }

    fn label(&self) -> &'static str {
        match *self {
            Mode::Bare => "file",
            Mode::Buffered(_) => "bufreader",
            Mode::Block(_) => "block",
            Mode::Tokio(_) => "tokio",
            Mode::Ring { .. } => "ring",
        }
    }
}

/// Timing for one run: per-call latencies in nanoseconds plus the fold.
struct Sample {
    latencies: Vec<f64>,
    bytes: u64,
    seconds: f64,
    fold: u64,
}

/// Accumulates one run into a [`Sample`].
///
/// Every measurement loop below goes through this, so `bytes`, `seconds` and
/// the fold are computed in exactly one place. That matters most for the fold:
/// it is a correctness check against the C++ harness rather than decoration, so
/// three private copies of the arithmetic would be three chances for one reader
/// to disagree with the others for a reason that is not the reader.
struct Recorder {
    latencies: Vec<f64>,
    bytes: u64,
    fold: u64,
    start: Instant,
}

impl Recorder {
    /// `calls` is the expected delivery count, used only to size the latency
    /// vector. The clock starts here, after the allocation.
    fn new(calls: u64) -> Recorder {
        Recorder {
            latencies: Vec::with_capacity(calls as usize + 1),
            bytes: 0,
            fold: 0,
            start: Instant::now(),
        }
    }

    /// One delivery that started at `call` and returned `record`.
    ///
    /// The fold is the C++ harness's — the first 8 bytes, wrapping. Enough to
    /// keep the copy from being optimized away, cheap enough not to register
    /// next to the I/O. A delivery shorter than that is still timed and still
    /// counted, it just has no head to fold; only the chunked reader can
    /// produce one, at end of file.
    fn delivered(&mut self, call: Instant, record: &[u8]) {
        self.latencies.push(call.elapsed().as_nanos() as f64);
        self.bytes += record.len() as u64;
        if record.len() >= 8 {
            let head = u64::from_le_bytes(record[..8].try_into().expect("8 bytes checked"));
            self.fold = self.fold.wrapping_add(head);
        }
    }

    fn finish(self) -> Sample {
        Sample {
            seconds: self.start.elapsed().as_secs_f64(),
            latencies: self.latencies,
            bytes: self.bytes,
            fold: self.fold,
        }
    }
}

/// Drive any blocking `Read` a record at a time, timing each call.
fn measure_reads<R: Read>(mut r: R, want: u64, record: usize) -> io::Result<Sample> {
    let mut buf = vec![0u8; record];
    let mut rec = Recorder::new(want / record as u64);

    let mut read = 0u64;
    while read + record as u64 <= want {
        let call = Instant::now();
        match r.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        rec.delivered(call, &buf);
        read += record as u64;
    }
    Ok(rec.finish())
}

/// The checkpoint shape: `read_exact` a whole block, then hand out records from
/// it. Timing is per *record* so the column means the same thing as everywhere
/// else — which puts the whole block read's cost on one record in every
/// `block / record`, exactly as `APSEQREAD`'s wait lands on one `GetData` in
/// every `block / record`.
fn measure_blocked(mut f: File, want: u64, record: usize, block: usize) -> io::Result<Sample> {
    let mut blk = vec![0u8; block];
    let mut rec = Recorder::new(want / record as u64);

    let mut read = 0u64;
    let mut pos = block; // force a fill on the first record
    while read + record as u64 <= want {
        let call = Instant::now();
        if pos + record > block {
            match f.read_exact(&mut blk) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            pos = 0;
        }
        rec.delivered(call, &blk[pos..pos + record]);
        pos += record;
        read += record as u64;
    }
    Ok(rec.finish())
}

/// The learner-streaming shape: `tokio::fs::File` into one reused chunk buffer,
/// awaited on a current-thread runtime. `learnport` writes each chunk to a
/// socket; here the fold stands in for that, so what is left is the read.
///
/// Timed per chunk rather than per record — a chunk is the unit the streaming
/// loop actually deals in — and the record column is reported as the chunk size
/// so the latency column is not silently comparing different things.
fn measure_tokio(path: &str, offset: u64, want: u64, chunk: usize) -> io::Result<Sample> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncSeekExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let mut f = tokio::fs::File::open(path).await?;
        if offset > 0 {
            f.seek(SeekFrom::Start(offset)).await?;
        }
        let mut buf = vec![0u8; chunk];
        let mut rec = Recorder::new(want / chunk as u64);

        let mut remaining = want;
        while remaining > 0 {
            let take = remaining.min(chunk as u64) as usize;
            let call = Instant::now();
            let got = f.read(&mut buf[..take]).await?;
            // Timed before the end-of-file test, so a call that returns nothing
            // still costs what it cost.
            rec.delivered(call, &buf[..got]);
            if got == 0 {
                break;
            }
            remaining -= got as u64;
        }
        Ok(rec.finish())
    })
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = (q * (sorted.len() - 1) as f64 + 0.5) as usize;
    sorted[i.min(sorted.len() - 1)]
}

struct Args {
    path: String,
    mode: Mode,
    label: String,
    offset: u64,
    length: u64,
    record: usize,
    header: bool,
}

const USAGE: &str = "usage: seqio_bench read <path> [--mode M] [--offset B] [--length B] \
                     [--record B] [--label S] [--header]";

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);

    // Subcommand, so `write` can be added against `APSEQWRITE` without this
    // one's argument shape having to change.
    match argv.next().ok_or(USAGE)?.as_str() {
        "read" => {}
        other => return Err(format!("unknown subcommand `{other}`\n{USAGE}")),
    }
    let path = argv.next().ok_or(USAGE)?;

    let mut a = Args {
        path,
        mode: Mode::Buffered(8192),
        label: String::new(),
        offset: 0,
        length: 0,
        record: 4096,
        header: false,
    };

    while let Some(flag) = argv.next() {
        if flag == "--header" {
            a.header = true;
            continue;
        }
        let value = argv
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--mode" => a.mode = Mode::parse(&value)?,
            "--label" => a.label = value,
            "--offset" => a.offset = value.parse().map_err(|e| format!("--offset: {e}"))?,
            "--length" => a.length = value.parse().map_err(|e| format!("--length: {e}"))?,
            "--record" => a.record = value.parse().map_err(|e| format!("--record: {e}"))?,
            _ => return Err(format!("unknown argument {flag}")),
        }
    }

    if a.record < 8 {
        return Err("--record must be at least 8 (the fold reads 8 bytes)".into());
    }
    Ok(a)
}

fn run(a: &Args) -> io::Result<()> {
    let file_size = std::fs::metadata(&a.path)?.len();
    if a.offset >= file_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("offset {} past end of file {}", a.offset, file_size),
        ));
    }
    let want = if a.length == 0 {
        file_size - a.offset
    } else {
        a.length.min(file_size - a.offset)
    };

    // Every mode but `tokio` and `ring` opens and seeks the same way, so the
    // only thing that differs between them is the reader wrapped around the
    // handle. `ring` does its own opening: it needs one unbuffered handle per
    // reader thread, and it takes the offset directly.
    let open = || -> io::Result<File> {
        let mut f = File::open(&a.path)?;
        if a.offset > 0 {
            f.seek(SeekFrom::Start(a.offset))?;
        }
        Ok(f)
    };

    let (sample, unit) = match a.mode {
        Mode::Bare => (measure_reads(open()?, want, a.record)?, a.record),
        Mode::Buffered(cap) => (
            measure_reads(BufReader::with_capacity(cap, open()?), want, a.record)?,
            a.record,
        ),
        Mode::Block(n) => (measure_blocked(open()?, want, a.record, n)?, a.record),
        Mode::Tokio(n) => (measure_tokio(&a.path, a.offset, want, n)?, n),
        // The shipped reader, so the benchmark measures what actually ships.
        Mode::Ring {
            threads,
            slots,
            block,
        } => (
            measure_reads(
                SeqReader::open_at(
                    std::path::Path::new(&a.path),
                    a.offset,
                    SeqReaderConfig {
                        threads,
                        slots,
                        block,
                    },
                )?,
                want,
                a.record,
            )?,
            a.record,
        ),
    };

    let mut latencies = sample.latencies;
    latencies.sort_by(|x, y| x.partial_cmp(y).expect("no NaN latencies"));

    let mib = sample.bytes as f64 / (1024.0 * 1024.0);
    let mibps = if sample.seconds > 0.0 {
        mib / sample.seconds
    } else {
        0.0
    };

    // A refill only lands on one call in (block / record) -- for a 10 MiB
    // buffer and a 4 KiB record that is 1 call in 2560, or 0.039%. p99 does not
    // reach it, and a p99 that misses the stall makes an unbuffered read look
    // like a fast one. The deep percentiles are where the difference lives.
    if a.header {
        println!(
            "impl\tlabel\tdepth\tblock\trecord\tbytes\tseconds\tmibps\tcalls\
             \tp50_ns\tp90_ns\tp99_ns\tp999_ns\tp9999_ns\tmax_ns\tfold"
        );
    }
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{:.2}\t{}\
         \t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{}",
        a.mode.label(),
        a.label,
        a.mode.depth(),
        a.mode.block(a.record),
        unit,
        sample.bytes,
        sample.seconds,
        mibps,
        latencies.len(),
        percentile(&latencies, 0.50),
        percentile(&latencies, 0.90),
        percentile(&latencies, 0.99),
        percentile(&latencies, 0.999),
        percentile(&latencies, 0.9999),
        latencies.last().copied().unwrap_or(0.0),
        sample.fold,
    );
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&args) {
        eprintln!("seqio_bench: {e}");
        std::process::exit(1);
    }
}
