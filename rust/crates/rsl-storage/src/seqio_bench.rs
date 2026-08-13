//! The Rust half of the sequential-I/O comparison against `apdiskio.cpp`.
//!
//! This mirrors `src/RSL/UnitTest/SeqIoBench/main.cpp` exactly: same
//! subcommands, same fixture file, same `--offset`/`--length` window, same
//! logical record size, same fold over the bytes, and the same tab-separated
//! `RESULT` line. Only the reader or writer underneath changes. Run both
//! against the same file on the same machine and the columns line up.
//!
//! `read` compares against `APSEQREAD` (verdict in `READPATH.md`), `write`
//! against `APSEQWRITE` (verdict in `WRITEPATH.md`). The C++ side of both is
//! cache-independent by construction — `FILE_FLAG_NO_BUFFERING` — while every
//! buffered read path here is not, which is why the read sweeps are driven cold.
//!
//! ```text
//! cargo run --release -p rsl-storage --bin seqio_bench -- \
//!     read <path> --mode bufreader:65536 --offset 0 --length 10737418240 --record 4096
//! cargo run --release -p rsl-storage --bin seqio_bench -- \
//!     write <path> --mode ring:4x4x4194304 --length 6442450944 --record 4096
//! ```
//!
//! Read modes:
//!
//! | Mode | Models |
//! | --- | --- |
//! | `file` | `LogScanner::open` — bare `File`, one syscall per record (log.rs:319) |
//! | `bufreader:<cap>` | log replay — `BufReader` (log.rs:522, :737); `cap` 8192 is today's default |
//! | `block:<n>` | checkpoint read — `File` + `read_exact` per block (checkpoint.rs:694) |
//! | `ring:<threads>x<slots>x<block>` | the shipped [`SeqReader`] — unbuffered ring, the port's `APSEQREAD` |
//!
//! (The former `tokio:<chunk>` learner-streaming mode is gone with the tokio
//! dev-dependency; `READPATH.md` keeps its one measured number.)
//!
//! The `write` subcommand goes through [`SeqWriter`] — the shipped unbuffered
//! ring writer, the port's `APSEQWRITE`. Records are fed via `write_all`.
//! The ring shape is specified as `--mode ring:<threads>x<slots>x<block>`.
//! `SeqWriter::finish` drains the ring, sets the file length, and syncs, so
//! durability is baked into the writer.

use rsl_storage::seqread::{SeqReader, SeqReaderConfig, SECTOR};
use rsl_storage::seqwrite::{SeqWriter, SeqWriterConfig};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::time::Instant;

/// What the read harness measures. Each variant is one of the port's real read
/// strategies, named after the call site it comes from.
enum Mode {
    /// Bare `File`: one `read` syscall per logical record.
    Bare,
    /// `BufReader` with an explicit capacity.
    Buffered(usize),
    /// `read_exact` a whole block, then serve records out of it.
    Block(usize),
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
            Mode::Buffered(n) | Mode::Block(n) => n,
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
/// private copies of the arithmetic would be chances for one reader to disagree
/// with the others for a reason that is not the reader.
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

/// The C++ harness's `FillPattern` (main.cpp): xorshift over a golden-ratio
/// seed derived from the byte offset. Cheap to produce, not compressible enough
/// for the drive to shortcut, distinguishable per offset. Identical on both
/// sides, so the fold column cross-checks that the two writers produced the
/// same logical stream.
fn fill_pattern(buf: &mut [u8], offset: u64) {
    let mut x = offset.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    for chunk in buf.chunks_exact_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
}

/// Feed records into the [`SeqWriter`] via `write_all`, timing fill + write
/// per record — the same timed region as the C++ `write` loop, which fills its
/// scratch buffer inside the clock too. `SeqWriter::finish` is called
/// separately in the caller so its `set_len` + `sync_all` lands in the
/// finish-time accounting.
fn measure_writes(w: &mut SeqWriter, want: u64, record: usize) -> io::Result<Sample> {
    let mut buf = vec![0u8; record];
    let mut rec = Recorder::new(want / record as u64);

    let mut written = 0u64;
    while written + record as u64 <= want {
        let call = Instant::now();
        fill_pattern(&mut buf, written);
        w.write_all(&buf)?;
        rec.delivered(call, &buf);
        written += record as u64;
    }
    Ok(rec.finish())
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = (q * (sorted.len() - 1) as f64 + 0.5) as usize;
    sorted[i.min(sorted.len() - 1)]
}

/// Parse a `<threads>x<slots>x<block>` ring spec from a `--mode ring:...`
/// argument.
fn parse_ring_spec(s: &str) -> Result<SeqWriterConfig, String> {
    let mut parts = s.split('x');
    let mut term = |what: &str| -> Result<usize, String> {
        parts
            .next()
            .ok_or_else(|| format!("bad ring spec `{s}`, want `<threads>x<slots>x<block>`"))?
            .parse::<usize>()
            .map_err(|e| format!("bad {what} in `{s}`: {e}"))
    };
    let threads = term("thread count")?;
    let slots = term("slot count")?;
    let block = term("block")?;
    if parts.next().is_some() {
        return Err(format!(
            "bad ring spec `{s}`, want `<threads>x<slots>x<block>`"
        ));
    }
    if !block.is_multiple_of(SECTOR) {
        return Err(format!(
            "ring block {block} must be a multiple of {SECTOR}: unbuffered \
             writes are rejected outright if length is not sector-aligned"
        ));
    }
    Ok(SeqWriterConfig {
        threads,
        slots,
        block,
    })
}

struct Args {
    write: bool,
    path: String,
    mode: Option<Mode>,
    wconfig: Option<SeqWriterConfig>,
    label: String,
    offset: u64,
    length: u64,
    record: usize,
    header: bool,
}

const USAGE: &str = "usage: seqio_bench read  <path> [--mode M] [--offset B] [--length B] \
                     [--record B] [--label S] [--header]\n\
                     \x20      seqio_bench write <path> --mode ring:TxSxB [--length B] [--record B] \
                     [--label S] [--header]";

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);

    let write = match argv.next().ok_or(USAGE)?.as_str() {
        "read" => false,
        "write" => true,
        other => return Err(format!("unknown subcommand `{other}`\n{USAGE}")),
    };
    let path = argv.next().ok_or(USAGE)?;

    let mut a = Args {
        write,
        path,
        mode: None,
        wconfig: None,
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
            "--mode" if write => {
                let (kind, arg) = value.split_once(':').ok_or_else(|| {
                    "write --mode requires ring:<threads>x<slots>x<block>".to_string()
                })?;
                if kind != "ring" {
                    return Err(format!("unknown write mode `{kind}`, expected `ring`"));
                }
                a.wconfig = Some(parse_ring_spec(arg)?);
            }
            "--mode" => a.mode = Some(Mode::parse(&value)?),
            "--label" => a.label = value,
            "--offset" => a.offset = value.parse().map_err(|e| format!("--offset: {e}"))?,
            "--length" => a.length = value.parse().map_err(|e| format!("--length: {e}"))?,
            "--record" => a.record = value.parse().map_err(|e| format!("--record: {e}"))?,
            _ => return Err(format!("unknown argument {flag}")),
        }
    }

    if a.record < 8 || a.record % 8 != 0 {
        return Err("--record must be a multiple of 8 (the fold reads 8-byte words)".into());
    }
    if a.write {
        if a.wconfig.is_none() {
            a.wconfig = Some(SeqWriterConfig::default());
        }
        if a.length == 0 {
            return Err("--length is required for write".into());
        }
        if a.offset != 0 {
            return Err("write does not take --offset; it writes from 0".into());
        }
    } else if a.mode.is_none() {
        a.mode = Some(Mode::Buffered(8192));
    }
    Ok(a)
}

fn print_row(
    impl_name: &str,
    label: &str,
    depth: usize,
    block: usize,
    unit: usize,
    sample: Sample,
    header: bool,
) {
    let mut latencies = sample.latencies;
    latencies.sort_by(|x, y| x.partial_cmp(y).expect("no NaN latencies"));

    let mib = sample.bytes as f64 / (1024.0 * 1024.0);
    let mibps = if sample.seconds > 0.0 {
        mib / sample.seconds
    } else {
        0.0
    };

    // A refill/drain only lands on one call in (block / record) — p99 does not
    // reach it. The deep percentiles are where buffering shows up.
    if header {
        println!(
            "impl\tlabel\tdepth\tblock\trecord\tbytes\tseconds\tmibps\tcalls\
             \tp50_ns\tp90_ns\tp99_ns\tp999_ns\tp9999_ns\tmax_ns\tfold"
        );
    }
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{:.2}\t{}\
         \t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{:.0}\t{}",
        impl_name,
        label,
        depth,
        block,
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
}

fn run_read(a: &Args) -> io::Result<()> {
    let mode = a.mode.as_ref().expect("read mode defaulted");
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

    // Every mode but `ring` opens and seeks the same way, so the only thing
    // that differs between them is the reader wrapped around the handle.
    // `ring` does its own opening: it needs one unbuffered handle per reader
    // thread, and it takes the offset directly.
    let open = || -> io::Result<File> {
        let mut f = File::open(&a.path)?;
        if a.offset > 0 {
            f.seek(SeekFrom::Start(a.offset))?;
        }
        Ok(f)
    };

    let sample = match *mode {
        Mode::Bare => measure_reads(open()?, want, a.record)?,
        Mode::Buffered(cap) => measure_reads(BufReader::with_capacity(cap, open()?), want, a.record)?,
        Mode::Block(n) => measure_blocked(open()?, want, a.record, n)?,
        // The shipped reader, so the benchmark measures what actually ships.
        Mode::Ring {
            threads,
            slots,
            block,
        } => measure_reads(
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
    };

    print_row(
        mode.label(),
        &a.label,
        mode.depth(),
        mode.block(a.record),
        a.record,
        sample,
        a.header,
    );
    Ok(())
}

fn run_write(a: &Args) -> io::Result<()> {
    let config = a.wconfig.expect("write config defaulted");
    let path = std::path::Path::new(&a.path);

    let mut w = SeqWriter::create_with(path, config)?;
    let mut sample = measure_writes(&mut w, a.length, a.record)?;

    // `finish` drains the ring, sets the file length, and syncs —
    // the same endpoint as `APSEQWRITE::Flush` + `SetEndOfFile`.
    let finish_start = Instant::now();
    w.finish()?;
    let finish = finish_start.elapsed();
    sample.seconds += finish.as_secs_f64();
    eprintln!(
        "write: finish (ring drain+sync) took {:.1} ms",
        finish.as_secs_f64() * 1e3
    );

    print_row(
        "seqwriter",
        &a.label,
        config.threads,
        config.block,
        a.record,
        sample,
        a.header,
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
    let r = if args.write {
        run_write(&args)
    } else {
        run_read(&args)
    };
    if let Err(e) = r {
        eprintln!("seqio_bench: {e}");
        std::process::exit(1);
    }
}