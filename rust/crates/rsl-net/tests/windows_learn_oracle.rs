//! Authoritative learn-port interop through production Windows RSL paths.

mod common;
mod learnfixture;

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use learnfixture::{write_checkpoint, write_log, StubStatus, TempDir};
use rsl_net::learnport::{DirSource, LearnClient, LearnConfig, LearnServer, Requester};
use rsl_storage::checkpoint::{CheckpointHeader, CheckpointWriter};
use rsl_storage::durability::NoSync;
use rsl_wire::messages::MSG_VOTE;
use rsl_wire::{BallotNumber, Header, MemberId, Msg, ProtocolVersion, Vote};

struct LearnServerProcess {
    child: Child,
    addr: SocketAddr,
}

impl LearnServerProcess {
    fn start(
        directory: &TempDir,
        connections: usize,
        version: ProtocolVersion,
    ) -> Option<LearnServerProcess> {
        let oracle = common::windows_oracle()?;
        let mut child = Command::new(oracle)
            .args(["--learn-server", "0", "--dir"])
            .arg(directory.path())
            .args([
                "--connections",
                &connections.to_string(),
                "--version",
                &version.raw().to_string(),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn production learn server");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read PORT line");
        let port = line
            .strip_prefix("PORT ")
            .unwrap_or_else(|| panic!("unexpected greeting {line:?}"))
            .trim()
            .parse()
            .expect("port");
        Some(LearnServerProcess {
            child,
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        })
    }

    fn finish(mut self) {
        let status = self.child.wait().expect("wait for production learn server");
        assert!(status.success(), "production learn server exited {status}");
    }
}

impl Drop for LearnServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn versions() -> [ProtocolVersion; 6] {
    [
        ProtocolVersion::V1,
        ProtocolVersion::V2,
        ProtocolVersion::V3,
        ProtocolVersion::V4,
        ProtocolVersion::V5,
        ProtocolVersion::V6,
    ]
}

fn requester(version: ProtocolVersion) -> Requester {
    Requester::new(version, MemberId::from_str("102"), 7)
}

fn ballot() -> BallotNumber {
    BallotNumber::new(3, MemberId::from_str("202"))
}

fn data_dir(name: &str) -> TempDir {
    let directory = TempDir::new(name);
    write_log(directory.path(), 100, &[100, 101, 102], 0);
    write_log(directory.path(), 103, &[103, 104], 700);
    write_log(directory.path(), 105, &[105, 106], 0);
    directory
}

fn versioned_data_dir(name: &str, version: ProtocolVersion) -> TempDir {
    let directory = TempDir::new(name);
    let records: Vec<Vec<u8>> = [100u64, 101]
        .into_iter()
        .map(|decree| {
            Vote::new(Header::new(
                version,
                MSG_VOTE,
                MemberId::from_str("101"),
                decree,
                7,
                BallotNumber::new(3, MemberId::from_str("202")),
                0,
            ))
            .marshal_with_checksum()
            .expect("marshal versioned vote")
        })
        .collect();
    learnfixture::write_log_records(directory.path(), 100, &records);
    directory
}

fn write_versioned_checkpoint(
    directory: &TempDir,
    version: ProtocolVersion,
    decree: u64,
    state: &[u8],
) -> u64 {
    let vote = Vote::new(Header::new(
        version,
        MSG_VOTE,
        MemberId::from_str("101"),
        decree + 1,
        7,
        BallotNumber::new(5, MemberId::from_str("202")),
        0,
    ));
    let mut header = CheckpointHeader::new(vote);
    header.member_id = MemberId::from_str("101");
    header.last_executed_decree = decree;
    header.max_ballot = BallotNumber::new(9, MemberId::from_str("202"));
    header.state_configuration = Some(learnfixture::configuration());
    let path = directory.join(&format!("{decree}.codex"));
    let mut writer =
        CheckpointWriter::create_with(&path, header, NoSync).expect("create checkpoint");
    std::io::Write::write_all(&mut writer, state).expect("write checkpoint");
    writer.finish().expect("finish checkpoint").size
}

#[tokio::test]
async fn rust_reads_production_status_for_every_protocol_version() {
    let Some(_) = common::windows_oracle() else {
        eprintln!("production learn oracle not requested");
        return;
    };
    let directory = data_dir("windows-learn-status");
    let checkpoint_size = write_checkpoint(directory.path(), 500, b"state");
    for version in versions() {
        let server = LearnServerProcess::start(&directory, 1, version).expect("server");
        let status = LearnClient::new()
            .query_status(server.addr, &requester(version).status_query())
            .await
            .expect("status");
        assert_eq!(status.header.version, version);
        assert_eq!(status.min_decree_in_log, 100);
        assert_eq!(status.checkpointed_decree, 500);
        assert_eq!(status.checkpoint_size, checkpoint_size);
        assert_eq!(status.max_ballot.ballot_id, 9);
        server.finish();
    }
}

#[tokio::test]
async fn production_server_emits_exact_log_ranges_to_rust() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(_) = common::windows_oracle() else {
        eprintln!("production learn oracle not requested");
        return;
    };
    let directory = data_dir("windows-learn-votes");
    for from in [100u64, 102, 103, 104, 106] {
        let server = LearnServerProcess::start(&directory, 1, ProtocolVersion::V6).expect("server");
        let request = requester(ProtocolVersion::V6).fetch_votes(from, ballot());
        let bytes = rsl_net::learn::encode_message(&Msg::Base(request)).expect("marshal request");
        let mut stream = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("connect");
        stream.write_all(&bytes).await.expect("request");
        stream.shutdown().await.expect("shutdown write");
        let mut actual = Vec::new();
        stream.read_to_end(&mut actual).await.expect("read stream");

        let logs = rsl_storage::log::LogSet::open(directory.path()).expect("open logs");
        let spans = logs.votes_from(from).expect("known decree");
        let mut expected = Vec::new();
        for span in spans {
            let file = std::fs::read(&span.path).expect("read log");
            expected
                .extend_from_slice(&file[span.offset as usize..(span.offset + span.len) as usize]);
        }

        assert_eq!(actual, expected, "exact bytes from decree {from}");
        server.finish();
    }
}

#[tokio::test]
async fn vote_streams_cross_both_directions_for_every_protocol_version() {
    let Some(oracle) = common::windows_oracle() else {
        eprintln!("production learn oracle not requested");
        return;
    };

    for version in versions() {
        let directory =
            versioned_data_dir(&format!("windows-learn-version-{}", version.raw()), version);

        let production =
            LearnServerProcess::start(&directory, 1, version).expect("production server");
        let mut stream = LearnClient::new()
            .fetch_votes(
                production.addr,
                &requester(version).fetch_votes(100, ballot()),
            )
            .await
            .expect("Rust fetches production votes");
        let mut count = 0;
        while let Some(message) = stream.next().await.expect("vote stream") {
            assert_eq!(message.header().version, version);
            count += 1;
        }
        assert_eq!(count, 2);
        production.finish();

        let rust = rust_server(&directory, StubStatus::new().with_log_range(100, 101)).await;
        let output = run_client_async(
            oracle.clone(),
            rust.local_addr(),
            vec![
                "--mode".into(),
                "votes".into(),
                "--version".into(),
                version.raw().to_string(),
                "--decree".into(),
                "100".into(),
            ],
        )
        .await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout
                .lines()
                .filter(|line| line.starts_with(&format!("VOTE version={} ", version.raw())))
                .count(),
            2
        );
    }
}

#[tokio::test]
async fn rust_fetches_production_checkpoint_and_unknown_requests_close() {
    let Some(_) = common::windows_oracle() else {
        eprintln!("production learn oracle not requested");
        return;
    };
    let source = data_dir("windows-learn-checkpoint-source");
    let destination = TempDir::new("windows-learn-checkpoint-destination");
    let state: Vec<u8> = (0..(4 * 1024 * 1024 + 5000u32))
        .map(|value| value as u8)
        .collect();
    let size = write_checkpoint(source.path(), 500, &state);
    let server = LearnServerProcess::start(&source, 3, ProtocolVersion::V6).expect("server");
    let client = LearnClient::new();
    let fetched = client
        .fetch_checkpoint(
            server.addr,
            &requester(ProtocolVersion::V6).fetch_checkpoint(500),
            size,
            destination.path(),
        )
        .await
        .expect("fetch checkpoint");
    assert_eq!(
        std::fs::read(&fetched.path).expect("read fetched"),
        std::fs::read(source.join("500.codex")).expect("read source")
    );

    let mut missing_votes = client
        .fetch_votes(
            server.addr,
            &requester(ProtocolVersion::V6).fetch_votes(99, ballot()),
        )
        .await
        .expect("connect");
    assert!(missing_votes.next().await.expect("close").is_none());
    let error = client
        .fetch_checkpoint(
            server.addr,
            &requester(ProtocolVersion::V6).fetch_checkpoint(42),
            size,
            destination.path(),
        )
        .await
        .expect_err("unknown checkpoint");
    assert!(matches!(error, rsl_net::learnport::TransferError::Closed));
    server.finish();
}

async fn rust_server(directory: &TempDir, status: StubStatus) -> LearnServer {
    LearnServer::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(DirSource::new(directory.path(), status)),
        LearnConfig::default(),
    )
    .await
    .expect("bind Rust learn server")
}

fn run_client(oracle: &std::path::Path, addr: SocketAddr, args: &[&str]) -> Output {
    Command::new(oracle)
        .args(["--learn-client", "127.0.0.1", &addr.port().to_string()])
        .args(args)
        .output()
        .expect("run production learn client")
}

async fn run_client_async(
    oracle: std::path::PathBuf,
    addr: SocketAddr,
    args: Vec<String>,
) -> Output {
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_client(&oracle, addr, &refs)
    })
    .await
    .expect("join production client")
}

#[tokio::test]
async fn production_client_reads_rust_status_and_votes_for_every_version() {
    let Some(oracle) = common::windows_oracle() else {
        eprintln!("production learn oracle not requested");
        return;
    };
    let directory = data_dir("windows-learn-rust-server");
    let server = rust_server(&directory, StubStatus::new().with_log_range(100, 106)).await;
    let addr = server.local_addr();

    for version in versions() {
        let status = run_client_async(
            oracle.clone(),
            addr,
            vec![
                "--mode".into(),
                "status".into(),
                "--version".into(),
                version.raw().to_string(),
            ],
        )
        .await;
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stdout)
        );
        assert!(
            String::from_utf8_lossy(&status.stdout).contains(&format!("version={}", version.raw()))
        );
    }

    for from in [100u64, 103, 106] {
        let output = run_client_async(
            oracle.clone(),
            addr,
            vec![
                "--mode".into(),
                "votes".into(),
                "--version".into(),
                "6".into(),
                "--decree".into(),
                from.to_string(),
            ],
        )
        .await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("VOTES "));
    }
}

#[tokio::test]
async fn production_checkpoint_client_rewrites_max_ballot_and_rejects_truncation() {
    let Some(oracle) = common::windows_oracle() else {
        eprintln!("production learn oracle not requested");
        return;
    };
    let source = TempDir::new("windows-learn-rewrite-source");
    let destination = TempDir::new("windows-learn-rewrite-destination");
    let state: Vec<u8> = (0..9000u32).map(|value| value as u8).collect();
    let size = write_checkpoint(source.path(), 500, &state);
    let server = rust_server(&source, StubStatus::new().with_checkpoint(500, size)).await;
    let output_path = destination.join("copied.codex");
    let output_arg = output_path.to_str().expect("utf-8");
    let output = run_client_async(
        oracle.clone(),
        server.local_addr(),
        vec![
            "--mode".into(),
            "checkpoint".into(),
            "--version".into(),
            "6".into(),
            "--decree".into(),
            "500".into(),
            "--size".into(),
            size.to_string(),
            "--out".into(),
            output_arg.into(),
            "--max-ballot".into(),
            "99".into(),
        ],
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("writtenMaxBallot=99"));
    let reader = rsl_storage::checkpoint::CheckpointReader::open(&output_path)
        .expect("open rewritten checkpoint");
    assert_eq!(reader.header().max_ballot.ballot_id, 99);
    assert_eq!(reader.user_data_size(), state.len() as u64);

    let truncated_server = LearnServer::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(DirSource::new(
            source.path(),
            StubStatus::new().with_checkpoint(500, size),
        )),
        LearnConfig {
            stream_chunk: 4096,
            ..LearnConfig::default()
        },
    )
    .await
    .expect("bind truncated server");
    let truncated_addr = truncated_server.local_addr();
    let truncated_output = destination.join("truncated.codex");
    let truncated_arg = truncated_output.to_str().expect("utf-8").to_string();
    let oracle_for_client = oracle.clone();
    let client = tokio::task::spawn_blocking(move || {
        run_client(
            &oracle_for_client,
            truncated_addr,
            &[
                "--mode",
                "checkpoint",
                "--version",
                "6",
                "--decree",
                "500",
                "--size",
                &size.to_string(),
                "--out",
                &truncated_arg,
            ],
        )
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    drop(truncated_server);
    let output = client.await.expect("join");
    assert!(!output.status.success());
    assert!(
        !truncated_output.exists(),
        "partial checkpoint was retained"
    );
}

#[tokio::test]
async fn checkpoint_transfer_crosses_both_directions_for_header_versions() {
    let Some(oracle) = common::windows_oracle() else {
        eprintln!("production learn oracle not requested");
        return;
    };
    for version in [
        ProtocolVersion::V3,
        ProtocolVersion::V4,
        ProtocolVersion::V5,
        ProtocolVersion::V6,
    ] {
        let source = TempDir::new(&format!("windows-checkpoint-v{}", version.raw()));
        let rust_destination = TempDir::new(&format!("windows-checkpoint-rust-v{}", version.raw()));
        let cpp_destination = TempDir::new(&format!("windows-checkpoint-cpp-v{}", version.raw()));
        let state: Vec<u8> = (0..9000u32).map(|value| value as u8).collect();
        let size = write_versioned_checkpoint(&source, version, 500, &state);

        let production = LearnServerProcess::start(&source, 1, version).expect("server");
        let fetched = LearnClient::new()
            .fetch_checkpoint(
                production.addr,
                &requester(version).fetch_checkpoint(500),
                size,
                rust_destination.path(),
            )
            .await
            .expect("Rust fetches production checkpoint");
        assert_eq!(
            rsl_storage::checkpoint::CheckpointReader::open(&fetched.path)
                .expect("open Rust copy")
                .header()
                .version,
            version
        );
        production.finish();

        let rust = rust_server(&source, StubStatus::new().with_checkpoint(500, size)).await;
        let output_path = cpp_destination.join("copied.codex");
        let output = run_client_async(
            oracle.clone(),
            rust.local_addr(),
            vec![
                "--mode".into(),
                "checkpoint".into(),
                "--version".into(),
                version.raw().to_string(),
                "--decree".into(),
                "500".into(),
                "--size".into(),
                size.to_string(),
                "--out".into(),
                output_path.to_str().expect("utf-8").into(),
                "--max-ballot".into(),
                "99".into(),
            ],
        )
        .await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let mut reader = rsl_storage::checkpoint::CheckpointReader::open(&output_path)
            .expect("open production copy");
        assert_eq!(reader.header().version, version);
        assert_eq!(reader.header().max_ballot.ballot_id, 99);
        assert_eq!(reader.read_all().expect("read state"), state);
    }
}
