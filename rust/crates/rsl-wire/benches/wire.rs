//! Criterion benchmarks: Rabin-64 throughput and full message marshal.
//!
//! Run with `cargo bench -p rsl-wire`. Numbers feed the crate README as a
//! baseline for later phases' perf work. The C++ side can time itself via
//! `golden-gen` for comparison.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rsl_wire::messages::{Header, MSG_VOTE};
use rsl_wire::{fingerprint, BallotNumber, MemberId, ProtocolVersion, Vote};

fn bench_fingerprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("fingerprint");
    for &size in &[16usize, 256, 4096, 65536] {
        let data: Vec<u8> = (0..size).map(|i| (i * 2654435761_usize) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| fingerprint(std::hint::black_box(data)))
        });
    }
    group.finish();
}

fn sample_vote() -> Vote {
    let header = Header::new(
        ProtocolVersion::V6,
        MSG_VOTE,
        MemberId::from_str("101"),
        0xabcdef,
        7,
        BallotNumber::new(43, MemberId::from_str("202")),
        0,
    );
    let mut vote = Vote::new(header);
    vote.add_request(&b"hello-decree"[..]);
    vote.add_request(&b"second-request-payload"[..]);
    vote
}

fn bench_marshal(c: &mut Criterion) {
    let vote = sample_vote();
    c.bench_function("marshal_vote_v6", |b| {
        b.iter(|| std::hint::black_box(&vote).marshal_with_checksum())
    });

    let bytes = vote.marshal_with_checksum().unwrap();
    c.bench_function("unmarshal_vote_v6", |b| {
        b.iter(|| Vote::unmarshal(std::hint::black_box(&bytes)))
    });
}

criterion_group!(benches, bench_fingerprint, bench_marshal);
criterion_main!(benches);
