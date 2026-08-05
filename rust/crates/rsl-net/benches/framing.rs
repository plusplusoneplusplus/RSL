//! Criterion benchmarks: packet encode/decode throughput and the learn-port
//! header parse.
//!
//! Run with `cargo bench -p rsl-net`. Everything is in memory; what is being
//! measured is the framing itself — one Rabin-64 pass over the frame in each
//! direction, plus the copy that `encode_packet` makes.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rsl_net::framing::{learn, packet};
use rsl_net::Limits;

/// Payload sizes spanning a bare header, a typical vote, and a big batch.
const SIZES: [usize; 5] = [0, 64, 1024, 64 * 1024, 1024 * 1024];

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i & 0xff) as u8).collect()
}

fn encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet/encode");
    for size in SIZES {
        let data = payload(size);
        group.throughput(Throughput::Bytes((packet::HDR_LEN + size) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| packet::encode_packet(data))
        });
    }
    group.finish();
}

fn decode(c: &mut Criterion) {
    let limits = Limits::default();
    let mut group = c.benchmark_group("packet/decode");
    for size in SIZES {
        let frame = packet::encode_packet(&payload(size));
        group.throughput(Throughput::Bytes(frame.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &frame, |b, frame| {
            b.iter(|| packet::decode_packet(frame, &limits).unwrap())
        });
    }
    group.finish();
}

/// Draining many packets out of one read buffer — the `NetCxn` receive loop.
fn decode_stream(c: &mut Criterion) {
    let limits = Limits::default();
    let one = packet::encode_packet(&payload(512));
    let mut buf = Vec::new();
    for _ in 0..64 {
        buf.extend_from_slice(&one);
    }

    let mut group = c.benchmark_group("packet/decode_stream");
    group.throughput(Throughput::Bytes(buf.len() as u64));
    group.bench_function("64x512B", |b| {
        b.iter(|| packet::Packets::new(&buf, limits).count())
    });
    group.finish();
}

/// The learn port's whole cost before the body arrives: 6 bytes, two integer
/// loads and two range checks.
fn learn_header(c: &mut Criterion) {
    let mut head = [0u8; learn::HDR_LEN];
    head[0..2].copy_from_slice(&6u16.to_le_bytes());
    head[2..6].copy_from_slice(&4096u32.to_le_bytes());

    c.bench_function("learn/parse_header", |b| {
        b.iter(|| learn::parse_header(&head, 1024 * 1024).unwrap())
    });
}

criterion_group!(benches, encode, decode, decode_stream, learn_header);
criterion_main!(benches);
