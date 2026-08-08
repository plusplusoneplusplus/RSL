//! Portable learn-port proxy interop in both directions.
//!
//! `rsl-linux-proxy --learn-server` runs the ported `HandleFetchRequest` /
//! `SendFile` paths over a real socket, serving a data directory this test
//! built with `rsl-storage`; `rsl-linux-proxy --learn-client` runs the ported
//! `ReadNextMessage` / checkpoint-copy loops against the Rust server. Between
//! them, every byte of every one of the three protocols crosses the boundary in
//! both directions and is checked against what the files on disk actually say.
//! Production Windows Legislator/file paths are covered by
//! `windows_learn_oracle.rs`.
//!
//! The peer binary needs cmake + g++, so these tests skip (with a message) when
//! it has not been built. CI builds it.

mod learnfixture;

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use learnfixture::{linux_proxy, warn_no_peer, write_checkpoint, write_log, StubStatus, TempDir};
use rsl_net::learnport::{
    DirSource, LearnClient, LearnConfig, LearnServer, Requester, TransferError,
};
use rsl_storage::log::LogSet;
use rsl_wire::{BallotNumber, MemberId, Msg, ProtocolVersion};

fn requester() -> Requester {
    Requester::new(ProtocolVersion::V6, MemberId::from_str("102"), 7)
}

fn ballot() -> BallotNumber {
    BallotNumber::new(3, MemberId::from_str("202"))
}

// ---------------------------------------------------------------------------
// The Linux proxy server
// ---------------------------------------------------------------------------

/// A spawned `rsl-linux-proxy --learn-server`, killed on drop.
struct ProxyServer {
    child: Child,
    addr: SocketAddr,
}

impl ProxyServer {
    /// Serve `dir` for `connections` sequential requests.
    fn start(dir: &TempDir, connections: usize) -> Option<ProxyServer> {
        let binary = linux_proxy()?;
        let mut child = Command::new(binary)
            .args(["--learn-server", "0", "--dir"])
            .arg(dir.path())
            .args(["--connections", &connections.to_string()])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn rsl-linux-proxy learn server");

        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read PORT line");
        let port: u16 = line
            .strip_prefix("PORT ")
            .unwrap_or_else(|| panic!("unexpected greeting {line:?}"))
            .trim()
            .parse()
            .expect("port number");

        Some(ProxyServer {
            child,
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        })
    }

    fn finish(mut self) {
        let status = self.child.wait().expect("wait for server");
        assert!(
            status.success(),
            "Linux proxy learn server exited with {status}"
        );
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// The Linux proxy client
// ---------------------------------------------------------------------------

/// Run `rsl-linux-proxy --learn-client` against `addr` and return its stdout lines.
fn proxy_client(addr: SocketAddr, args: &[&str]) -> Option<Vec<String>> {
    let binary = linux_proxy()?;
    let output = Command::new(binary)
        .args(["--learn-client", "127.0.0.1", &addr.port().to_string()])
        .args(args)
        .output()
        .expect("run rsl-linux-proxy learn client");
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_string)
            .collect(),
    )
}

/// The value of `key=` in a whitespace-separated `KEY k=v k=v` line.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key}= in {line:?}"))
}

/// Every message a `FetchVotes(decree)` response *should* carry, read straight
/// off the files with `rsl-storage`. This is the oracle both directions are
/// compared against.
fn expected_records(dir: &TempDir, from_decree: u64) -> Vec<(u16, u64, u32)> {
    let logs = LogSet::open(dir.path()).expect("open log set");
    let spans = logs.votes_from(from_decree).expect("decree is in the log");

    let mut out = Vec::new();
    for span in spans {
        let bytes = std::fs::read(&span.path).expect("read log");
        let region = &bytes[span.offset as usize..(span.offset + span.len) as usize];
        let scan = rsl_storage::log::scan_bytes(region);
        for record in &scan.records {
            out.push((record.msg_id, record.decree, record.un_marshal_len));
        }
    }
    out
}

fn a_data_dir(name: &str) -> TempDir {
    let dir = TempDir::new(name);
    write_log(dir.path(), 100, &[100, 101, 102], 0);
    write_log(dir.path(), 103, &[103, 104], 700); // records spanning two pages
    write_log(dir.path(), 105, &[105, 106], 0);
    dir
}

// ---------------------------------------------------------------------------
// Direction A: the Linux proxy serves, Rust fetches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rust_fetches_votes_from_the_linux_proxy_server() {
    let Some(_) = linux_proxy() else {
        warn_no_peer("rust_fetches_votes_from_the_linux_proxy_server");
        return;
    };
    let dir = a_data_dir("interop-a-votes");

    // One connection per request: the protocol is one-shot.
    for from in [100u64, 102, 103, 104, 106] {
        let server = ProxyServer::start(&dir, 1).expect("start Linux proxy server");
        let mut stream = LearnClient::new()
            .fetch_votes(server.addr, &requester().fetch_votes(from, ballot()))
            .await
            .expect("fetch votes");

        let mut got = Vec::new();
        while let Some(msg) = stream.next().await.expect("vote stream") {
            let header = msg.header();
            got.push((header.msg_id, header.decree, header.un_marshal_len));
        }
        assert_eq!(
            got,
            expected_records(&dir, from),
            "records served by the Linux proxy from decree {from}"
        );
        server.finish();
    }
}

#[tokio::test]
async fn rust_fetches_a_checkpoint_from_the_linux_proxy_server() {
    let Some(_) = linux_proxy() else {
        warn_no_peer("rust_fetches_a_checkpoint_from_the_linux_proxy_server");
        return;
    };
    let source = TempDir::new("interop-a-cp-src");
    let dest = TempDir::new("interop-a-cp-dst");
    write_log(source.path(), 100, &[100, 101], 0);
    // Straddles the 4 MiB checksum-block boundary, so the copy exercises more
    // than one block on the way through.
    let state: Vec<u8> = (0..(4 * 1024 * 1024 + 5000u32)).map(|i| i as u8).collect();
    let size = write_checkpoint(source.path(), 500, &state);

    // Two connections: a status query to learn the size, then the fetch — which
    // is exactly the sequence the engine runs (legislator.cpp:1396-1408).
    let server = ProxyServer::start(&source, 2).expect("start Linux proxy server");
    let client = LearnClient::new();

    let status = client
        .query_status(server.addr, &requester().status_query())
        .await
        .expect("status query");
    assert_eq!(status.checkpointed_decree, 500);
    assert_eq!(
        status.checkpoint_size, size,
        "the Linux proxy reports the file size"
    );
    assert_eq!(status.min_decree_in_log, 100);

    let fetched = client
        .fetch_checkpoint(
            server.addr,
            &requester().fetch_checkpoint(status.checkpointed_decree),
            status.checkpoint_size,
            dest.path(),
        )
        .await
        .expect("fetch checkpoint");

    assert_eq!(fetched.size, size);
    assert_eq!(
        std::fs::read(&fetched.path).expect("read copy"),
        std::fs::read(source.join("500.codex")).expect("read source"),
        "the copy must be byte-identical to what the Linux proxy served"
    );
    assert!(rsl_storage::checkpoint::verify_file(&fetched.path)
        .expect("verify")
        .accepted());
    server.finish();
}

/// The negative case the wire cannot express: a decree the Linux proxy does not have
/// produces a close with no bytes at all.
#[tokio::test]
async fn the_linux_proxy_server_closes_silently_on_an_unknown_decree() {
    let Some(_) = linux_proxy() else {
        warn_no_peer("the_linux_proxy_server_closes_silently_on_an_unknown_decree");
        return;
    };
    let dir = a_data_dir("interop-a-missing");
    // A checkpoint *does* exist — at 500, not at the 42 asked for below. The
    // The model compares against its configured checkpointed decree.
    let size = write_checkpoint(dir.path(), 500, b"state");

    let server = ProxyServer::start(&dir, 2).expect("start Linux proxy server");
    let client = LearnClient::new();

    let mut stream = client
        .fetch_votes(server.addr, &requester().fetch_votes(99, ballot()))
        .await
        .expect("connect");
    assert!(
        stream.next().await.expect("clean close").is_none(),
        "the Linux proxy answered a decree it does not have"
    );

    // Same for a checkpoint decree that is not *the* checkpointed one.
    let err = client
        .fetch_checkpoint(
            server.addr,
            &requester().fetch_checkpoint(42),
            size,
            dir.path(),
        )
        .await
        .expect_err("must be refused");
    assert!(matches!(err, TransferError::Closed), "got {err:?}");
    server.finish();
}

// ---------------------------------------------------------------------------
// Direction B: Rust serves, the Linux proxy fetches
// ---------------------------------------------------------------------------

async fn rust_server(dir: &TempDir, status: StubStatus) -> LearnServer {
    LearnServer::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(DirSource::new(dir.path(), status)),
        LearnConfig::default(),
    )
    .await
    .expect("bind")
}

#[tokio::test]
async fn the_proxy_client_reads_votes_from_the_rust_server() {
    let Some(_) = linux_proxy() else {
        warn_no_peer("the_proxy_client_reads_votes_from_the_rust_server");
        return;
    };
    let dir = a_data_dir("interop-b-votes");
    let server = rust_server(&dir, StubStatus::new().with_log_range(100, 106)).await;
    let addr = server.local_addr();

    for from in [100u64, 103, 106] {
        let expected = expected_records(&dir, from);
        let lines = tokio::task::spawn_blocking(move || {
            proxy_client(addr, &["--mode", "votes", "--decree", &from.to_string()])
        })
        .await
        .expect("join")
        .expect("run client");

        let votes: Vec<(u16, u64, u32)> = lines
            .iter()
            .filter(|l| l.starts_with("VOTE "))
            .map(|l| {
                (
                    field(l, "msgId").parse().unwrap(),
                    field(l, "decree").parse().unwrap(),
                    field(l, "len").parse().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            votes, expected,
            "Linux proxy client reading from decree {from}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l == &format!("VOTES {}", expected.len())),
            "expected a VOTES count line in {lines:?}"
        );
    }
}

#[tokio::test]
async fn the_proxy_client_reads_status_and_a_checkpoint_from_the_rust_server() {
    let Some(_) = linux_proxy() else {
        warn_no_peer("the_proxy_client_reads_status_and_a_checkpoint_from_the_rust_server");
        return;
    };
    let dir = TempDir::new("interop-b-cp");
    let out = TempDir::new("interop-b-cp-out");
    write_log(dir.path(), 100, &[100, 101], 0);
    let state: Vec<u8> = (0..9000u32).map(|i| i as u8).collect();
    let size = write_checkpoint(dir.path(), 500, &state);

    let server = rust_server(
        &dir,
        StubStatus::new()
            .with_checkpoint(500, size)
            .with_log_range(100, 101),
    )
    .await;
    let addr = server.local_addr();

    let lines = tokio::task::spawn_blocking(move || proxy_client(addr, &["--mode", "status"]))
        .await
        .expect("join")
        .expect("run client");
    let status = lines
        .iter()
        .find(|l| l.starts_with("STATUS "))
        .unwrap_or_else(|| panic!("no STATUS line in {lines:?}"));
    assert_eq!(field(status, "checkpointDecree"), "500");
    assert_eq!(field(status, "checkpointSize"), size.to_string());
    assert_eq!(field(status, "minDecree"), "100");

    let copy = out.join("copied.codex");
    let copy_arg = copy.to_str().expect("utf-8 path").to_string();
    let lines = tokio::task::spawn_blocking(move || {
        proxy_client(
            addr,
            &[
                "--mode",
                "checkpoint",
                "--decree",
                "500",
                "--size",
                &size.to_string(),
                "--out",
                &copy_arg,
            ],
        )
    })
    .await
    .expect("join")
    .expect("run client");

    let line = lines
        .iter()
        .find(|l| l.starts_with("CHECKPOINT "))
        .unwrap_or_else(|| panic!("no CHECKPOINT line in {lines:?}"));
    assert_eq!(field(line, "outcome"), "accept");
    assert_eq!(field(line, "size"), size.to_string());
    // The Linux proxy verifier's own fingerprint of the copy must equal the source's.
    let original = std::fs::read(dir.join("500.codex")).expect("read source");
    assert_eq!(
        field(line, "fp64"),
        format!("{:016x}", rsl_wire::fingerprint(&original))
    );
    assert_eq!(std::fs::read(&copy).expect("read copy"), original);
}

/// The Rust server's silent close is one the Linux proxy client handles: it reports an
/// empty stream, not a protocol error.
#[tokio::test]
async fn the_proxy_client_sees_the_rust_servers_silent_close() {
    let Some(_) = linux_proxy() else {
        warn_no_peer("the_proxy_client_sees_the_rust_servers_silent_close");
        return;
    };
    let dir = a_data_dir("interop-b-missing");
    let server = rust_server(&dir, StubStatus::new().with_log_range(100, 106)).await;
    let addr = server.local_addr();

    let lines = tokio::task::spawn_blocking(move || {
        proxy_client(addr, &["--mode", "votes", "--decree", "99"])
    })
    .await
    .expect("join")
    .expect("run client");
    assert_eq!(lines, vec!["ERROR closed".to_string()], "got {lines:?}");
}

/// A Rust server that dies mid-stream: what the Linux proxy client does about it is
/// *recorded from an actual run*, not assumed. It reports the short body — the
/// `restore = false` path has no tolerated tail — and publishes nothing.
#[tokio::test]
async fn the_proxy_client_reports_a_rust_server_killed_mid_stream() {
    let Some(_) = linux_proxy() else {
        warn_no_peer("the_proxy_client_reports_a_rust_server_killed_mid_stream");
        return;
    };
    let dir = TempDir::new("interop-b-torn");
    let out = TempDir::new("interop-b-torn-out");
    // Big enough that the transfer cannot complete inside one chunk.
    let state = vec![0x5au8; 8 * 1024 * 1024];
    let size = write_checkpoint(dir.path(), 500, &state);

    let config = LearnConfig {
        stream_chunk: 512,
        ..LearnConfig::default()
    };
    let server = LearnServer::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(DirSource::new(
            dir.path(),
            StubStatus::new().with_checkpoint(500, size),
        )),
        config,
    )
    .await
    .expect("bind");
    let addr = server.local_addr();

    let copy = out.join("torn.codex");
    let copy_arg = copy.to_str().expect("utf-8 path").to_string();
    let client = tokio::task::spawn_blocking(move || {
        proxy_client(
            addr,
            &[
                "--mode",
                "checkpoint",
                "--decree",
                "500",
                "--size",
                &size.to_string(),
                "--out",
                &copy_arg,
            ],
        )
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if copy
                .metadata()
                .is_ok_and(|metadata| metadata.len() > 1024 && metadata.len() < size)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("proxy client never began the checkpoint copy");
    drop(server); // kill the server mid-transfer

    let lines = client.await.expect("join").expect("run client");
    assert!(
        lines.iter().any(|l| l == "ERROR incomplete checkpoint"),
        "executed proxy behavior changed: {lines:?}"
    );
    // Its `lError` path deletes the partial file, so nothing is left.
    assert!(
        !copy.exists(),
        "the Linux proxy client kept a partial checkpoint"
    );
}

/// Both implementations must agree that the request framing is the *message's
/// own* six bytes: a bad version is refused with no reply by the Linux proxy server,
/// exactly as the Rust one refuses it.
#[tokio::test]
async fn a_bad_request_version_is_refused_by_the_linux_proxy_server() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(_) = linux_proxy() else {
        warn_no_peer("a_bad_request_version_is_refused_by_the_linux_proxy_server");
        return;
    };
    let dir = a_data_dir("interop-a-badversion");
    let server = ProxyServer::start(&dir, 1).expect("start Linux proxy server");

    let mut bytes =
        rsl_net::learn::encode_message(&Msg::Base(requester().fetch_votes(100, ballot())))
            .expect("marshal");
    bytes[0..2].copy_from_slice(&7u16.to_le_bytes()); // one past the last version

    let mut stream = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let _ = stream.write_all(&bytes).await;
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest).await;
    assert!(
        rest.is_empty(),
        "the Linux proxy replied to a bad version: {rest:?}"
    );
    drop(stream);
    server.finish();
}
