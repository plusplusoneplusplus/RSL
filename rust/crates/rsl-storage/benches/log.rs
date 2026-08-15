//! Criterion benchmarks: log append throughput and recovery-scan speed.
//!
//! Run with `cargo bench -p rsl-storage`. Writes go to the system temp
//! directory. Two durability policies are measured separately: [`NoSync`]
//! isolates the encode/`writev` path, while `SyncAll` adds one `fsync` per
//! commit — the difference is the disk's latency, not this crate's.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rsl_storage::durability::{NoSync, SyncAll};
use rsl_storage::log::{self, LogWriter};
use rsl_wire::messages::{MSG_PREPARE, MSG_VOTE};
use rsl_wire::{BallotNumber, Header, MemberId, PrepareMsg, ProtocolVersion, Vote};

mod common;
use common::scratch;

/// A vote record carrying `request_len` bytes of payload.
fn vote_record(decree: u64, request_len: usize) -> Vec<u8> {
    let mut vote = Vote::new(Header::new(
        ProtocolVersion::V6,
        MSG_VOTE,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(3, MemberId::from_str("202")),
        0,
    ));
    if request_len > 0 {
        vote.add_request(vec![b'r'; request_len]);
    }
    vote.marshal_with_checksum().unwrap()
}

fn records(count: u64, request_len: usize) -> Vec<Vec<u8>> {
    (0..count).map(|i| vote_record(i, request_len)).collect()
}

/// A prepare record: same size class as a vote, but never entered in the decree
/// index — so the same batch can be appended over and over without tripping the
/// vote-sequence rule.
fn prepare_record(decree: u64) -> Vec<u8> {
    PrepareMsg {
        header: Header::new(
            ProtocolVersion::V6,
            MSG_PREPARE,
            MemberId::from_str("101"),
            decree,
            7,
            BallotNumber::new(3, MemberId::from_str("202")),
            0,
        ),
        primary_cookie: vec![b'c'; 200],
    }
    .marshal_with_checksum()
}

fn on_disk_len(records: &[Vec<u8>]) -> u64 {
    records
        .iter()
        .map(|r| u64::from(rsl_storage::round_up_to_page(r.len() as u32)))
        .sum()
}

/// Append 1024 records as one batch versus one at a time, for a small and a
/// large record size. Both arms go through `append_unsynced`, so this measures
/// the write path alone — the flush is `group_commit`'s subject.
fn append(c: &mut Criterion) {
    let dir = scratch("log", "append");
    let mut group = c.benchmark_group("log/append");

    for request_len in [0usize, 3500] {
        let batch = records(1024, request_len);
        let refs: Vec<&[u8]> = batch.iter().map(|r| r.as_slice()).collect();
        group.throughput(Throughput::Bytes(on_disk_len(&batch)));

        group.bench_with_input(
            BenchmarkId::new("batched", request_len),
            &refs,
            |b, refs| {
                let mut decree = 0u64;
                b.iter(|| {
                    decree += 1;
                    let path = dir.join(format!("{decree}.log"));
                    let mut writer = LogWriter::open_with(&dir, decree, NoSync).unwrap();
                    let _ = writer.append_unsynced(refs).unwrap();
                    drop(writer);
                    std::fs::remove_file(path).unwrap();
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("one-at-a-time", request_len),
            &refs,
            |b, refs| {
                let mut decree = 1_000_000u64;
                b.iter(|| {
                    decree += 1;
                    let path = dir.join(format!("{decree}.log"));
                    let mut writer = LogWriter::open_with(&dir, decree, NoSync).unwrap();
                    for record in refs.iter() {
                        let _ = writer
                            .append_unsynced(std::slice::from_ref(record))
                            .unwrap();
                    }
                    drop(writer);
                    std::fs::remove_file(path).unwrap();
                });
            },
        );
    }
    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

/// One group commit — append a batch and `fsync` — which is the engine's vote
/// path. Dominated by the disk, and measured to keep that visible. The records
/// are prepares so the same batch can be re-appended every iteration.
fn group_commit(c: &mut Criterion) {
    let dir = scratch("log", "commit");
    let mut group = c.benchmark_group("log/group-commit");

    for batch_size in [1u64, 4, 16, 64, 256] {
        let batch: Vec<Vec<u8>> = (0..batch_size).map(prepare_record).collect();
        let refs: Vec<&[u8]> = batch.iter().map(|r| r.as_slice()).collect();
        group.throughput(Throughput::Bytes(on_disk_len(&batch)));
        group.bench_with_input(
            BenchmarkId::new("append_batch", batch_size),
            &refs,
            |b, refs| {
                let mut writer = LogWriter::open_with(&dir, 1, SyncAll).unwrap();
                b.iter(|| {
                    writer.append_batch(refs).unwrap();
                });
            },
        );
        let _ = std::fs::remove_file(dir.join("1.log"));

        // The same batch without the flush, so the device cost stays visible as
        // the difference between the two arms.
        group.bench_with_input(
            BenchmarkId::new("append_unsynced", batch_size),
            &refs,
            |b, refs| {
                let mut writer = LogWriter::open_with(&dir, 1, SyncAll).unwrap();
                b.iter(|| {
                    let _ = writer.append_unsynced(refs).unwrap();
                });
            },
        );
        let _ = std::fs::remove_file(dir.join("1.log"));
    }
    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The individual durability primitives, so the cost of each sync point in
/// `DURABILITY.md` is a measured number rather than an assumption:
///
/// * `fdatasync` — what every append pays.
/// * `fsync` — what `fdatasync` saves by not writing inode metadata.
/// * `create+fsync-dir` — what publishing a *new* log's name costs, paid once
///   per log file rather than once per append.
fn sync_cost(c: &mut Criterion) {
    let dir = scratch("log", "sync");
    let mut group = c.benchmark_group("log/sync");
    let record = prepare_record(1);

    let mut writer = LogWriter::open_with(&dir, 1, SyncAll).unwrap();
    group.bench_function("fdatasync", |b| {
        b.iter(|| {
            // Unsynced, then flushed explicitly: `append` would flush itself
            // and leave `sync` a no-op, measuring nothing.
            let _ = writer.append_unsynced(&[&record[..]]).unwrap();
            writer.sync().unwrap();
        });
    });
    drop(writer);
    let _ = std::fs::remove_file(dir.join("1.log"));

    // The same append, but paying for full inode metadata as well.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dir.join("fsync.bin"))
        .unwrap();
    group.bench_function("fsync", |b| {
        b.iter(|| {
            use std::io::Write;
            file.write_all(&[0u8; 512]).unwrap();
            file.sync_all().unwrap();
        });
    });
    drop(file);

    let mut decree = 0u64;
    group.bench_function("create+fsync-dir", |b| {
        b.iter(|| {
            decree += 1;
            let writer = LogWriter::open_with(&dir, decree, SyncAll).unwrap();
            drop(writer);
            std::fs::remove_file(dir.join(format!("{decree}.log"))).unwrap();
        });
    });

    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The startup recovery scan: parse and checksum every record in a log.
fn recovery_scan(c: &mut Criterion) {
    let dir = scratch("log", "scan");
    let mut group = c.benchmark_group("log/recovery-scan");

    for request_len in [0usize, 3500] {
        let batch = records(4096, request_len);
        let refs: Vec<&[u8]> = batch.iter().map(|r| r.as_slice()).collect();
        let decree = request_len as u64;
        let path = dir.join(format!("{decree}.log"));
        let mut writer = LogWriter::open_with(&dir, decree, NoSync).unwrap();
        let _ = writer.append_unsynced(&refs).unwrap();
        drop(writer);

        group.throughput(Throughput::Bytes(on_disk_len(&batch)));
        group.bench_with_input(
            BenchmarkId::new("scan_file", request_len),
            &path,
            |b, path| {
                b.iter(|| {
                    let scan = log::scan_file(path).unwrap();
                    assert_eq!(scan.records.len(), 4096);
                });
            },
        );
    }
    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

criterion_group!(benches, append, group_commit, sync_cost, recovery_scan);
criterion_main!(benches);
