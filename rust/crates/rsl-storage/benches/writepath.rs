//! Criterion benchmarks: what buffer capacity costs the checkpoint write path.
//!
//! Run with `cargo bench -p rsl-storage --bench writepath`.
//!
//! **These are page-cache numbers, and that is deliberate.** The comparison
//! against the C++ `APSEQWRITE` baseline needs a real device and a stated sync
//! discipline — that is the cross-language harness
//! (`src/RSL/UnitTest/SeqIoBench`, `write` subcommand) driven by
//! `run-sweep.ps1`. What criterion is good at is the *relative* question:
//! holding the cache constant, how much of a write path is buffer-capacity
//! choice rather than disk? Every writer here produces the same records with
//! the same fill, so the only variable is how many bytes each one hands the OS
//! at a time.
//!
//! `bufwriter/8192` is not an arbitrary point on the sweep. It is what
//! `CheckpointWriter` used before it moved onto `SeqWriter`, because
//! `BufWriter::new` is the 8 KiB default — the exact mirror of the read side's
//! `BufReader::new` finding. It stays here as the baseline the migration is
//! measured against.
//!
//! The `checkpoint/today` row is the real `CheckpointWriter` (blocks,
//! Rabin-64, header rewrite, rename) with `NoSync`. Since the migration that
//! row writes *unbuffered*, so it is no longer a page-cache number and no
//! longer commensurable with the `bufwriter/*` rows beside it: read it against
//! the cross-language `SeqIoBench` sweep, not against this file's own sweep.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rsl_storage::checkpoint::{CheckpointHeader, CheckpointWriter};
use rsl_storage::durability::NoSync;
use rsl_wire::messages::MSG_VOTE;
use rsl_wire::{
    BallotNumber, ConfigurationInfo, Header, MemberId, MemberSet, ProtocolVersion, RslNode, Vote,
};

mod common;
use common::scratch;

/// 32 MiB in 4 KiB records — the same shape as `readpath.rs`'s deliver sweep,
/// so the two files' numbers sit on the same axes.
const TOTAL: u64 = 32 * 1024 * 1024;
const RECORD: usize = 4096;

/// The cross-language harness's record fill (`FillPattern`, main.cpp): kept
/// identical so a criterion row and a harness row describe the same work.
fn fill_pattern(buf: &mut [u8], offset: u64) {
    let mut x = offset.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    for chunk in buf.chunks_exact_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
}

/// Write `TOTAL` bytes in `RECORD`-sized fills through any `Write`. The final
/// flush is inside the measurement — a writer that defers all its work to the
/// end must still pay for it here.
fn deliver<W: Write>(mut w: W) {
    let mut buf = vec![0u8; RECORD];
    let mut written = 0u64;
    while written < TOTAL {
        fill_pattern(&mut buf, written);
        w.write_all(&buf).expect("write");
        written += RECORD as u64;
    }
    w.flush().expect("flush");
}

fn deliver_capacity(c: &mut Criterion) {
    let dir = scratch("writepath", "deliver");
    let path = dir.join("out.bin");

    let mut group = c.benchmark_group("writepath/deliver");
    group.throughput(Throughput::Bytes(TOTAL));

    // Bare `File`: one `write` syscall per record.
    group.bench_function("file/unbuffered", |b| {
        b.iter(|| deliver(File::create(&path).expect("create")));
    });

    for cap in [8 * 1024usize, 64 * 1024, 128 * 1024, 1024 * 1024, 10 * 1024 * 1024] {
        group.bench_with_input(BenchmarkId::new("bufwriter", cap), &cap, |b, &cap| {
            b.iter(|| {
                deliver(BufWriter::with_capacity(
                    cap,
                    File::create(&path).expect("create"),
                ))
            });
        });
    }

    // Direct large blocks: records accumulate in one block buffer and the file
    // sees only block-sized writes — `BufWriter` without its per-record
    // bookkeeping.
    for block in [128 * 1024usize, 1024 * 1024] {
        group.bench_with_input(BenchmarkId::new("big", block), &block, |b, &block| {
            b.iter(|| {
                let mut f = File::create(&path).expect("create");
                let mut blk = vec![0u8; block];
                let mut written = 0u64;
                let mut pos = 0usize;
                while written < TOTAL {
                    fill_pattern(&mut blk[pos..pos + RECORD], written);
                    pos += RECORD;
                    if pos + RECORD > block {
                        f.write_all(&blk[..pos]).expect("write");
                        pos = 0;
                    }
                    written += RECORD as u64;
                }
                if pos > 0 {
                    f.write_all(&blk[..pos]).expect("write");
                }
            });
        });
    }

    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

fn header() -> CheckpointHeader {
    let vote = Vote::new(Header::new(
        ProtocolVersion::V6,
        MSG_VOTE,
        MemberId::from_str("101"),
        1001,
        7,
        BallotNumber::new(5, MemberId::from_str("202")),
        0,
    ));
    let mut header = CheckpointHeader::new(vote);
    header.member_id = MemberId::from_str("101");
    header.max_ballot = BallotNumber::new(9, MemberId::from_str("202"));
    header.state_configuration = Some(ConfigurationInfo::new(
        1,
        1001,
        MemberSet {
            members: vec![RslNode {
                member_id: MemberId::from_str("101"),
                ip: 0x0100_007f,
                rsl_port: 8080,
                rsl_learn_port: 8081,
                app_port: 0,
                host_name: b"host-a".to_vec(),
            }],
            cookie: Vec::new(),
        },
    ));
    header
}

/// The real checkpoint writer over the same payload, `NoSync` so the device
/// flush does not drown the pipeline. The spread between this and the raw
/// rows above is blocking + Rabin-64 + the header rewrite, not buffering.
fn checkpoint_today(c: &mut Criterion) {
    let dir = scratch("writepath", "checkpoint");
    let path = dir.join("out.codex");

    let mut group = c.benchmark_group("writepath/checkpoint");
    group.throughput(Throughput::Bytes(TOTAL));
    group.bench_function("today", |b| {
        b.iter(|| {
            let mut w =
                CheckpointWriter::create_with(&path, header(), NoSync).expect("create");
            let mut buf = vec![0u8; RECORD];
            let mut written = 0u64;
            while written < TOTAL {
                fill_pattern(&mut buf, written);
                w.write_all(&buf).expect("write");
                written += RECORD as u64;
            }
            w.finish().expect("finish");
        });
    });
    group.finish();

    let _ = std::fs::remove_dir_all(Path::new(&dir));
}

criterion_group!(benches, deliver_capacity, checkpoint_today);
criterion_main!(benches);
