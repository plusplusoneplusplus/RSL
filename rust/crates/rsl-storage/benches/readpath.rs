//! Criterion benchmarks: what buffer capacity costs the log replay scan.
//!
//! Run with `cargo bench -p rsl-storage --bench readpath`.
//!
//! **These are warm-cache numbers, and that is deliberate.** The comparison
//! against the C++ `APSEQREAD` baseline has to be cold, because `APSEQREAD`
//! opens with `FILE_FLAG_NO_BUFFERING` and never sees the page cache — that
//! comparison needs a larger-than-RAM fixture driven outside
//! criterion. What criterion is good at, and what this file is
//! for, is the *relative* question: holding the cache constant, how much of the
//! replay scan is buffer-capacity choice rather than disk? Every reader here
//! parses the same records with the same `log::scan`, so the only variable is
//! how many bytes each one asks the OS for at a time.
//!
//! `bufreader/8192` is not an arbitrary point on the sweep. It is what
//! `log::scan_file` (log.rs:522) and `LogReader::seek_to` (log.rs:737) use
//! today, because `BufReader::new` is the 8 KiB default.
//!
//! # The `seqreader` row is not like the others
//!
//! [`SeqReader`] opens unbuffered, so it is the one reader here that does *not*
//! read out of the page cache. Its number is therefore the same warm or cold —
//! which is the entire point of it — while every `bufreader` row above is
//! reading from RAM and would be roughly half as fast cold. Do not read the
//! comparison as "`BufReader` beats `SeqReader`". Read it as: this is what each
//! reader costs when the data is already resident, and only one of them still
//! delivers that number when it is not. `READPATH.md` has the cold table.
//!
//! It also pays a fixed cost criterion exaggerates: every iteration opens a
//! reader, which spawns `threads` OS threads for a 32 MiB file. Real callers
//! open one reader per log file, not one per 32 MiB.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use rsl_storage::seqread::{SeqReader, SeqReaderConfig};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rsl_storage::durability::NoSync;
use rsl_storage::log::{self, LogWriter};
use rsl_wire::messages::MSG_VOTE;
use rsl_wire::{BallotNumber, Header, MemberId, ProtocolVersion, Vote};

mod common;
use common::scratch;

/// Roughly 32 MiB of log at ~4 KiB a record — big enough that buffer capacity
/// matters, small enough that criterion's default sample count is not a
/// multi-minute wait.
const RECORDS: u64 = 8192;
const REQUEST_LEN: usize = 3500;

fn vote_record(decree: u64) -> Vec<u8> {
    let mut vote = Vote::new(Header::new(
        ProtocolVersion::V6,
        MSG_VOTE,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(3, MemberId::from_str("202")),
        0,
    ));
    vote.add_request(vec![b'r'; REQUEST_LEN]);
    vote.marshal_with_checksum().unwrap()
}

/// Lay down one log file and hand back its path and on-disk length.
fn fixture(dir: &Path) -> (PathBuf, u64) {
    let batch: Vec<Vec<u8>> = (0..RECORDS).map(vote_record).collect();
    let refs: Vec<&[u8]> = batch.iter().map(|r| r.as_slice()).collect();
    let mut writer = LogWriter::open_with(dir, 1, NoSync).unwrap();
    writer.append_batch(&refs).unwrap();
    drop(writer);
    let path = dir.join("1.log");
    let len = std::fs::metadata(&path).unwrap().len();
    (path, len)
}

/// The replay scan over the same file through readers of different capacity.
/// `log::scan` is identical in every case — only the `Read` under it changes —
/// so the spread is buffering and nothing else.
fn scan_capacity(c: &mut Criterion) {
    let dir = scratch("readpath", "scan");
    let (path, len) = fixture(&dir);

    let mut group = c.benchmark_group("readpath/scan");
    group.throughput(Throughput::Bytes(len));

    // Bare `File`: what `LogScanner::open` (log.rs:319) does — no buffering at
    // all, so the scanner's header-sized reads go straight to the OS.
    group.bench_function("file/unbuffered", |b| {
        b.iter(|| {
            let scan = log::scan(File::open(&path).unwrap()).unwrap();
            assert_eq!(scan.records.len(), RECORDS as usize);
        });
    });

    for cap in [8 * 1024usize, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024] {
        group.bench_with_input(BenchmarkId::new("bufreader", cap), &cap, |b, &cap| {
            b.iter(|| {
                let f = File::open(&path).unwrap();
                let scan = log::scan(BufReader::with_capacity(cap, f)).unwrap();
                assert_eq!(scan.records.len(), RECORDS as usize);
            });
        });
    }

    // The shipped reader, through the same parser. The `assert_eq!` is doing
    // real work here beyond keeping the optimizer honest: it is the integration
    // check that a ring of unbuffered reads reassembles into exactly the byte
    // stream `log::scan` expects, over a file whose length is not a multiple of
    // the block size.
    for (threads, slots) in [(4usize, 4usize), (8, 8)] {
        let cfg = SeqReaderConfig {
            threads,
            slots,
            block: 1 << 20,
        };
        group.bench_with_input(
            BenchmarkId::new("seqreader", format!("{threads}x{slots}x1MiB")),
            &cfg,
            |b, &cfg| {
                b.iter(|| {
                    let r = SeqReader::open_with(&path, cfg).unwrap();
                    let scan = log::scan(r).unwrap();
                    assert_eq!(scan.records.len(), RECORDS as usize);
                });
            },
        );
    }

    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same sweep with the parsing taken away: `read_exact` the file in 4 KiB
/// logical records and touch each one. This is the shape the cross-language
/// harness measures, kept here so the criterion run shows how much of the
/// scan's spread is I/O delivery and how much is `log::scan` itself.
fn deliver_capacity(c: &mut Criterion) {
    let dir = scratch("readpath", "deliver");
    let (path, len) = fixture(&dir);

    let mut group = c.benchmark_group("readpath/deliver");
    group.throughput(Throughput::Bytes(len));

    fn drain<R: Read>(mut r: R, record: usize) -> u64 {
        let mut buf = vec![0u8; record];
        let mut acc = 0u64;
        loop {
            match r.read_exact(&mut buf) {
                Ok(()) => acc = acc.wrapping_add(u64::from_le_bytes(buf[..8].try_into().unwrap())),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return acc,
                Err(e) => panic!("{e}"),
            }
        }
    }

    group.bench_function("file/unbuffered", |b| {
        b.iter(|| drain(File::open(&path).unwrap(), 4096));
    });

    for cap in [8 * 1024usize, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024] {
        group.bench_with_input(BenchmarkId::new("bufreader", cap), &cap, |b, &cap| {
            b.iter(|| {
                drain(
                    BufReader::with_capacity(cap, File::open(&path).unwrap()),
                    4096,
                )
            });
        });
    }

    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

criterion_group!(benches, scan_capacity, deliver_capacity);
criterion_main!(benches);
