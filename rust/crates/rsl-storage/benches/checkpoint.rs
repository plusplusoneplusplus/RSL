//! Criterion benchmarks: checkpoint block-stream throughput.
//!
//! Run with `cargo bench -p rsl-storage`. Numbers feed the crate README as a
//! baseline for later phases. Writes go to the system temp directory and use
//! the [`NoSync`] durability policy, so the figures measure the block/checksum
//! pipeline rather than the disk's `fsync` latency (`SyncAll` adds one file and
//! one directory sync per checkpoint, independent of size).

use std::io::Write;
use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rsl_storage::checkpoint::{CheckpointHeader, CheckpointReader, CheckpointWriter};
use rsl_storage::durability::NoSync;
use rsl_wire::messages::MSG_VOTE;
use rsl_wire::{
    BallotNumber, ConfigurationInfo, Header, MemberId, MemberSet, ProtocolVersion, RslNode, Vote,
};

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

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rsl-storage-bench-{name}.codex"))
}

fn bench_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint_write");
    for &size in &[64usize * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let state: Vec<u8> = (0..size).map(|i| i as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &state, |b, state| {
            let path = scratch("write");
            b.iter(|| {
                let mut writer =
                    CheckpointWriter::create_with(&path, header(), NoSync).expect("create");
                writer.write_all(state).expect("write");
                writer.finish().expect("finish");
            });
            let _ = std::fs::remove_file(&path);
        });
    }
    group.finish();
}

fn bench_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint_read");
    for &size in &[64usize * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let state: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let path = scratch(&format!("read-{size}"));
        {
            let mut writer =
                CheckpointWriter::create_with(&path, header(), NoSync).expect("create");
            writer.write_all(&state).expect("write");
            writer.finish().expect("finish");
        }

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &path, |b, path| {
            b.iter(|| {
                let mut reader = CheckpointReader::open(path).expect("open");
                reader.verify_all().expect("verify")
            })
        });
        let _ = std::fs::remove_file(&path);
    }
    group.finish();
}

criterion_group!(benches, bench_write, bench_read);
criterion_main!(benches);
