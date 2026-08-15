//! Learn-port transfer benchmarks: how fast a lagging replica catches up, and
//! how much of the 5-second inactivity window that leaves.
//!
//! Two transfers are measured end to end over loopback TCP, server and client
//! both in-process:
//!
//! * **`fetch_votes`** — a log set streamed out raw and parsed back record by
//!   record. The per-record work (page read, header parse, Rabin-64 over the
//!   body) is what scales here, so records of different sizes are measured
//!   separately.
//! * **`fetch_checkpoint`** — a `.codex` copied to a temp file, verified and
//!   renamed. Verification re-reads and re-checksums the whole file, so it is
//!   deliberately inside the measurement: it is part of what a real fetch pays.
//!
//! ### Reading the numbers
//!
//! The protocol has no overall deadline — only a per-operation 5 s timeout (see
//! `LearnConfig`). So the number that matters operationally is not the total
//! transfer time but the **stall budget**: how long the stream may go quiet
//! before the transfer is abandoned. That is a flat 5 s regardless of size, and
//! the throughput below is what says whether a transfer of a given size can
//! finish at all on a link that keeps stalling. `README.md` records the
//! measured figures.
//!
//! ```sh
//! cargo bench -p rsl-net --bench learnport
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rsl_net::learnport::{
    DirSource, LearnClient, LearnConfig, LearnServer, Requester, StatusProvider,
};
use rsl_storage::checkpoint::{CheckpointHeader, CheckpointWriter};
use rsl_storage::durability::NoSync;
use rsl_storage::log::LogWriter;
use rsl_wire::messages::{Header, StatusResponse, MSG_STATUS_RESPONSE, MSG_VOTE};
use rsl_wire::{
    BallotNumber, ConfigurationInfo, MemberId, MemberSet, ProtocolVersion, RslNode, Vote,
};
use tokio::runtime::Runtime;

/// Bytes to move per sample, so the big cases do not run for minutes.
const TRANSFER_BUDGET: usize = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn scratch(prefix: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("bench-{prefix}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create scratch dir");
    path
}

fn header(msg_id: u16, decree: u64) -> Header {
    Header::new(
        ProtocolVersion::V6,
        msg_id,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(3, MemberId::from_str("202")),
        0,
    )
}

/// A status provider that answers a fixed checkpoint.
struct Fixed {
    decree: Option<u64>,
    size: u64,
}

impl StatusProvider for Fixed {
    fn status(&self, request: &Header) -> Option<StatusResponse> {
        Some(StatusResponse {
            header: header(MSG_STATUS_RESPONSE, 0),
            query_decree: request.decree,
            query_ballot: request.ballot.clone(),
            last_received_ago: 0,
            min_decree_in_log: 0,
            checkpointed_decree: self.decree.unwrap_or(0),
            checkpoint_size: self.size,
            max_ballot: BallotNumber::default(),
            state: 0,
        })
    }

    fn checkpointed_decree(&self) -> Option<u64> {
        self.decree
    }
}

/// Write a log holding `count` votes of `request_len` bytes each. Returns the
/// directory and the log's byte length.
fn a_log(request_len: usize, count: u64) -> (PathBuf, u64) {
    let dir = scratch("votes");
    let records: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let mut vote = Vote::new(header(MSG_VOTE, 100 + i));
            if request_len > 0 {
                vote.add_request(vec![b'r'; request_len]);
            }
            vote.marshal_with_checksum().expect("marshal")
        })
        .collect();
    let mut writer = LogWriter::open_with(&dir, 100, NoSync).expect("open log");
    let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let _ = writer.append_unsynced(&refs).expect("append");
    let len = writer.data_len();
    (dir, len)
}

/// Write a checkpoint of `state_len` user bytes. Returns the directory and the
/// file size a client must ask for.
fn a_checkpoint(state_len: usize) -> (PathBuf, u64) {
    let dir = scratch("codex");
    let mut vote = Vote::new(header(MSG_VOTE, 501));
    let mut cp = CheckpointHeader::new(vote.clone());
    vote.primary_cookie = Vec::new();
    cp.member_id = MemberId::from_str("101");
    cp.state_configuration = Some(ConfigurationInfo::new(
        7,
        1,
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

    let path = dir.join("500.codex");
    let mut writer = CheckpointWriter::create_with(&path, cp, NoSync).expect("create codex");
    let block = vec![0x5au8; 64 * 1024];
    let mut written = 0;
    while written < state_len {
        let want = (state_len - written).min(block.len());
        std::io::Write::write_all(&mut writer, &block[..want]).expect("write state");
        written += want;
    }
    let size = writer.finish().expect("finish").size;
    (dir, size)
}

fn serve(runtime: &Runtime, dir: &Path, status: Fixed) -> LearnServer {
    let dir = dir.to_path_buf();
    runtime.block_on(async move {
        LearnServer::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            Arc::new(DirSource::new(dir, status)),
            LearnConfig::default(),
        )
        .await
        .expect("bind")
    })
}

fn requester() -> Requester {
    Requester::new(ProtocolVersion::V6, MemberId::from_str("102"), 7)
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Stream a whole log set and parse every record.
fn bench_fetch_votes(c: &mut Criterion) {
    let runtime = Runtime::new().expect("runtime");
    let mut group = c.benchmark_group("learnport/fetch_votes");

    // (request bytes per vote, votes) — a small-record log where per-record
    // work dominates, and a large-record one where the copy does.
    for (request_len, count) in [(0usize, 4096u64), (700, 2048), (64 * 1024, 256)] {
        let (dir, bytes) = a_log(request_len, count);
        let server = serve(
            &runtime,
            &dir,
            Fixed {
                decree: None,
                size: 0,
            },
        );
        let addr = server.local_addr();

        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(
            BenchmarkId::new("request_bytes", request_len),
            &addr,
            |b, &addr| {
                b.iter(|| {
                    runtime.block_on(async {
                        let mut stream = LearnClient::new()
                            .fetch_votes(
                                addr,
                                &requester().fetch_votes(100, BallotNumber::default()),
                            )
                            .await
                            .expect("fetch votes");
                        let mut records = 0u64;
                        while stream.next().await.expect("stream").is_some() {
                            records += 1;
                        }
                        assert_eq!(records, count);
                    })
                })
            },
        );

        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }
    group.finish();
}

/// Copy a checkpoint, verify it, publish it.
fn bench_fetch_checkpoint(c: &mut Criterion) {
    let runtime = Runtime::new().expect("runtime");
    let mut group = c.benchmark_group("learnport/fetch_checkpoint");

    for state_len in [1024 * 1024usize, 8 * 1024 * 1024, 32 * 1024 * 1024] {
        let (dir, size) = a_checkpoint(state_len);
        let server = serve(
            &runtime,
            &dir,
            Fixed {
                decree: Some(500),
                size,
            },
        );
        let addr = server.local_addr();
        let dest = scratch("codex-dst");

        // Keep the wall clock per sample bounded for the big sizes.
        group.sample_size(if state_len > TRANSFER_BUDGET / 4 {
            10
        } else {
            20
        });
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(
            BenchmarkId::new("state_bytes", state_len),
            &addr,
            |b, &addr| {
                b.iter(|| {
                    runtime.block_on(async {
                        let fetched = LearnClient::new()
                            .fetch_checkpoint(addr, &requester().fetch_checkpoint(500), size, &dest)
                            .await
                            .expect("fetch checkpoint");
                        // Publishing renames onto the destination, so clear it
                        // for the next iteration.
                        let _ = std::fs::remove_file(&fetched.path);
                    })
                })
            },
        );

        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dest);
    }
    group.finish();
}

criterion_group!(benches, bench_fetch_votes, bench_fetch_checkpoint);
criterion_main!(benches);
