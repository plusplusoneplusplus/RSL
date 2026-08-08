#![cfg(windows)]

//! Authoritative mutual-TLS interoperability with production Windows SChannel.

mod certs;
mod common;
mod harness;
mod learnfixture;
mod windows_certs;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use certs::{Ca, Leaf, LeafSpec};
use harness::Recorder;
use learnfixture::{write_log, StubStatus, TempDir};
use rsl_net::learnport::{DirSource, LearnClient, LearnConfig, LearnServer, Requester};
use rsl_net::svc::{Packet, PacketSvc, SvcConfig, TxRxStatus};
use rsl_net::tls::{Tls, TlsConfig};
use rsl_wire::{MemberId, ProtocolVersion};
use windows_certs::{configure_oracle, configure_subject, WindowsCertStore};

struct Fixture {
    store: WindowsCertStore,
    ca: Ca,
    cpp_old: Leaf,
    cpp_new: Leaf,
    rust: Leaf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let ca = Ca::new(&format!("{name} Root"));
        let cpp_old = ca.issue(LeafSpec::named("cpp-old").with_serial(1).rsa());
        let cpp_new = ca.issue(LeafSpec::named("cpp-new").with_serial(2).rsa());
        let rust = ca.issue(LeafSpec::named("rust-replica").with_serial(3).rsa());
        let mut store = WindowsCertStore::new(name);
        store.install_identity(&cpp_old, "cpp-old");
        store.install_identity(&cpp_new, "cpp-new");
        store.trust_peer(&rust, "rust-replica");
        Fixture {
            store,
            ca,
            cpp_old,
            cpp_new,
            rust,
        }
    }

    fn rust_tls(&self, identity: &Leaf, accepts: &[&Leaf]) -> Arc<Tls> {
        let mut config = TlsConfig {
            identity: identity.identity(),
            roots: vec![self.ca.der()],
            ..TlsConfig::default()
        };
        config.thumbprint_a = accepts.first().map(|leaf| leaf.thumbprint());
        config.thumbprint_b = accepts.get(1).map(|leaf| leaf.thumbprint());
        Tls::new(config).expect("Rust TLS config")
    }
}

struct OracleServer {
    child: Child,
    port: u16,
    stdout: BufReader<std::process::ChildStdout>,
}

impl OracleServer {
    fn start(mut command: Command) -> OracleServer {
        let mut child = command
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn SChannel oracle server");
        let mut line = String::new();
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        stdout.read_line(&mut line).expect("read PORT");
        let port = line
            .strip_prefix("PORT ")
            .unwrap_or_else(|| panic!("unexpected oracle greeting {line:?}"))
            .trim()
            .parse()
            .expect("port");
        OracleServer {
            child,
            port,
            stdout,
        }
    }

    fn addr(&self) -> std::net::SocketAddrV4 {
        std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port)
    }

    fn finish(mut self) {
        let status = self.child.wait().expect("wait for SChannel server");
        let mut output = String::new();
        let _ = std::io::Read::read_to_string(&mut self.stdout, &mut output);
        assert!(
            status.success(),
            "SChannel server exited {status}: {output}"
        );
    }

    fn finish_rejected(mut self) {
        let status = self
            .child
            .wait()
            .expect("wait for rejected SChannel server");
        assert!(
            !status.success(),
            "rejected SChannel server reported success"
        );
    }
}

impl Drop for OracleServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn oracle() -> std::path::PathBuf {
    common::windows_oracle().expect("authoritative mode requires Windows oracle")
}

fn packet_server_command(
    local: &Leaf,
    peer: Option<&Leaf>,
    count: usize,
    wait_disconnect: bool,
) -> Command {
    let mut command = Command::new(oracle());
    command.args([
        "--net-server",
        "0",
        "--mode",
        "echo",
        "--count",
        &count.to_string(),
        "--wait-disconnect",
        if wait_disconnect { "yes" } else { "no" },
    ]);
    configure_oracle(&mut command, local, peer, false);
    command
}

async fn rust_packet_to_schannel(
    tls: Arc<Tls>,
    server: OracleServer,
    payload: &[u8],
    expect_server_success: bool,
) -> TxRxStatus {
    let (handler, mut events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(
        tls.dialer(Ipv4Addr::LOCALHOST),
        handler,
        SvcConfig::default(),
    );
    assert_eq!(
        client.send(
            Arc::new(Packet::to_server(server.addr(), payload.to_vec())),
            Duration::from_secs(10),
        ),
        TxRxStatus::Success
    );
    let (_, status) = events.next_send().await;
    if status == TxRxStatus::Success {
        let received = tokio::time::timeout(Duration::from_secs(10), events.next_receive())
            .await
            .expect("SChannel echo timeout");
        assert_eq!(received.payload, payload);
    }
    if expect_server_success {
        server.finish();
    } else {
        server.finish_rejected();
    }
    drop(client);
    status
}

struct Echo(tokio::sync::mpsc::UnboundedSender<Arc<Packet>>);

impl rsl_net::svc::PacketHandler for Echo {
    fn process_send(&self, _: &Arc<Packet>, _: TxRxStatus) {}

    fn process_receive(&self, packet: Arc<Packet>) {
        let _ = self.0.send(packet);
    }
}

async fn rust_packet_server(tls: Arc<Tls>) -> Arc<PacketSvc> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let server = Arc::new(
        PacketSvc::start_as_server_with(
            0,
            tls.acceptor(),
            Arc::new(Echo(tx)),
            SvcConfig {
                bind_ip: Ipv4Addr::LOCALHOST,
                ..SvcConfig::default()
            },
        )
        .expect("Rust TLS packet server"),
    );
    let echo = server.clone();
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            echo.send(
                Arc::new(Packet::to_client(packet.client, packet.payload.clone())),
                Duration::from_secs(5),
            );
        }
    });
    server
}

fn run_oracle_client(mut command: Command) -> Output {
    command.output().expect("run SChannel oracle client")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutual_tls12_packets_cross_schannel_in_both_directions() {
    let fixture = Fixture::new("schannel-packet");
    let _keep_store_alive = &fixture.store;

    let mut server_command = packet_server_command(&fixture.cpp_old, Some(&fixture.rust), 1, false);
    server_command.env("RSL_TLS_VALIDATE_CHAIN", "no");
    let server = OracleServer::start(server_command);
    let rust = fixture.rust_tls(&fixture.rust, &[&fixture.cpp_old]);
    assert_eq!(
        rust_packet_to_schannel(rust, server, b"rust to schannel tls12", true).await,
        TxRxStatus::Success
    );

    let rust = fixture.rust_tls(&fixture.rust, &[&fixture.cpp_old]);
    let server = rust_packet_server(rust).await;
    let mut command = Command::new(oracle());
    command.args([
        "--net-client",
        "127.0.0.1",
        &server.local_addr().port().to_string(),
        "--payload",
        "736368616e6e656c20746f2072757374",
        "--count",
        "1",
        "--expect",
        "echo",
    ]);
    configure_oracle(&mut command, &fixture.cpp_old, Some(&fixture.rust), false);
    let output = run_oracle_client(command);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("TLS negotiated"),
        "SChannel did not report its negotiated TLS 1.2 cipher"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schannel_subject_and_chain_rules_accept_and_reject_expected_identities() {
    let fixture = Fixture::new("schannel-rules");
    let _keep_store_alive = &fixture.store;

    let mut accepted = packet_server_command(&fixture.cpp_old, None, 1, false);
    configure_subject(&mut accepted, "A", "rust-replica", &fixture.ca);
    let server = OracleServer::start(accepted);
    let rust = fixture.rust_tls(&fixture.rust, &[&fixture.cpp_old]);
    assert_eq!(
        rust_packet_to_schannel(rust, server, b"subject accepted", true).await,
        TxRxStatus::Success
    );

    let mut rejected = packet_server_command(&fixture.cpp_old, None, 0, true);
    configure_subject(&mut rejected, "A", "wrong-name", &fixture.ca);
    let server = OracleServer::start(rejected);
    let rust = fixture.rust_tls(&fixture.rust, &[&fixture.cpp_old]);
    assert_ne!(
        rust_packet_to_schannel(rust, server, b"subject rejected", true).await,
        TxRxStatus::Success
    );

    let bad_ca = Ca::new("Untrusted Root");
    let bad_leaf = bad_ca.issue(LeafSpec::named("untrusted-rust").rsa());
    let mut enforced = packet_server_command(&fixture.cpp_old, None, 0, true);
    configure_oracle(&mut enforced, &fixture.cpp_old, None, true);
    configure_subject(&mut enforced, "A", "untrusted-rust", &bad_ca);
    let server = OracleServer::start(enforced);
    let rust = Tls::new(TlsConfig {
        identity: bad_leaf.identity(),
        thumbprint_a: Some(fixture.cpp_old.thumbprint()),
        roots: vec![fixture.ca.der()],
        ..TlsConfig::default()
    })
    .expect("untrusted peer TLS");
    assert_ne!(
        rust_packet_to_schannel(rust, server, b"chain rejected", true).await,
        TxRxStatus::Success
    );

    let mut log_only = packet_server_command(&fixture.cpp_old, None, 1, false);
    configure_oracle(&mut log_only, &fixture.cpp_old, None, false);
    configure_subject(&mut log_only, "A", "untrusted-rust", &bad_ca);
    let server = OracleServer::start(log_only);
    let rust = Tls::new(TlsConfig {
        identity: bad_leaf.identity(),
        thumbprint_a: Some(fixture.cpp_old.thumbprint()),
        roots: vec![fixture.ca.der()],
        ..TlsConfig::default()
    })
    .expect("untrusted peer TLS");
    assert_eq!(
        rust_packet_to_schannel(rust, server, b"chain log only", true).await,
        TxRxStatus::Success
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_and_learn_ports_require_mutual_tls_and_report_failures() {
    let fixture = Fixture::new("schannel-ports");
    let _keep_store_alive = &fixture.store;

    let server = OracleServer::start(packet_server_command(&fixture.cpp_old, None, 0, true));
    let rust = fixture.rust_tls(&fixture.rust, &[&fixture.cpp_old]);
    assert_ne!(
        rust_packet_to_schannel(rust, server, b"unlisted client", true).await,
        TxRxStatus::Success
    );

    let plaintext_server = OracleServer::start(packet_server_command(
        &fixture.cpp_old,
        Some(&fixture.rust),
        0,
        true,
    ));
    let mut plaintext =
        std::net::TcpStream::connect(plaintext_server.addr()).expect("plaintext connect");
    plaintext
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    plaintext
        .write_all(&rsl_net::framing::packet::encode_packet(b"plaintext"))
        .expect("plaintext write");
    let mut response = Vec::new();
    let _ = plaintext.read_to_end(&mut response);
    assert!(response.is_empty(), "SChannel answered plaintext");
    drop(plaintext);
    plaintext_server.finish();

    let rejecting_rust = fixture.rust_tls(&fixture.rust, &[&fixture.rust]);
    let rust_server = rust_packet_server(rejecting_rust).await;
    let mut command = Command::new(oracle());
    command.args([
        "--net-client",
        "127.0.0.1",
        &rust_server.local_addr().port().to_string(),
        "--payload",
        "756e6c6973746564",
        "--count",
        "1",
        "--expect",
        "disconnect",
    ]);
    configure_oracle(&mut command, &fixture.cpp_old, Some(&fixture.rust), false);
    let output = run_oracle_client(command);
    assert!(
        !output.status.success(),
        "rejected identity reported success"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("received=0"));
    assert!(stdout.contains("outcome=reject"));

    let directory = TempDir::new("schannel-learn-source");
    write_log(directory.path(), 100, &[100, 101], 0);
    let mut command = Command::new(oracle());
    command
        .args(["--learn-server", "0", "--dir"])
        .arg(directory.path())
        .args(["--connections", "1", "--version", "6"]);
    configure_oracle(&mut command, &fixture.cpp_old, Some(&fixture.rust), false);
    let server = OracleServer::start(command);
    let rust = fixture.rust_tls(&fixture.rust, &[&fixture.cpp_old]);
    let client = LearnClient::new().over(rust.connector());
    let requester = Requester::new(ProtocolVersion::V6, MemberId::from_str("102"), 7);
    let status = client
        .query_status(server.addr().into(), &requester.status_query())
        .await
        .expect("Rust status over SChannel");
    assert_eq!(status.min_decree_in_log, 100);
    server.finish();

    let mut command = Command::new(oracle());
    command
        .args(["--learn-server", "0", "--dir"])
        .arg(directory.path())
        .args(["--connections", "1", "--version", "6"]);
    configure_oracle(&mut command, &fixture.cpp_old, Some(&fixture.rust), false);
    let plaintext_server = OracleServer::start(command);
    let error = LearnClient::new()
        .query_status(plaintext_server.addr().into(), &requester.status_query())
        .await
        .expect_err("plaintext client reached SChannel learn port");
    assert!(
        matches!(
            error,
            rsl_net::learnport::TransferError::Io(_) | rsl_net::learnport::TransferError::Closed
        ),
        "{error:?}"
    );
    plaintext_server.finish_rejected();

    let rust = fixture.rust_tls(&fixture.rust, &[&fixture.cpp_old]);
    let source = Arc::new(DirSource::new(
        directory.path(),
        StubStatus::new().with_log_range(100, 101),
    ));
    let rust_server = LearnServer::bind_with(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        rust.connector(),
        source,
        LearnConfig::default(),
    )
    .await
    .expect("Rust TLS learn server");
    let mut command = Command::new(oracle());
    command.args([
        "--learn-client",
        "127.0.0.1",
        &rust_server.local_addr().port().to_string(),
        "--mode",
        "status",
        "--version",
        "6",
    ]);
    configure_oracle(&mut command, &fixture.cpp_old, Some(&fixture.rust), false);
    let output = tokio::task::spawn_blocking(move || run_oracle_client(command))
        .await
        .expect("join SChannel learn client");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staged_ab_rotation_accepts_mixed_identities_then_removes_old_slot() {
    let fixture = Fixture::new("schannel-rotation");
    let _keep_store_alive = &fixture.store;

    let mut staged_command =
        packet_server_command(&fixture.cpp_old, Some(&fixture.cpp_new), 2, false);
    staged_command
        .env(
            "RSL_TLS_ROTATE_THUMBPRINT_A",
            fixture.cpp_new.thumbprint().to_string(),
        )
        .env(
            "RSL_TLS_ROTATE_THUMBPRINT_B",
            fixture.cpp_old.thumbprint().to_string(),
        );
    let staged = OracleServer::start(staged_command);
    let old_rust = fixture.rust_tls(&fixture.cpp_old, &[&fixture.cpp_old, &fixture.cpp_new]);
    let (handler, mut events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(
        old_rust.dialer(Ipv4Addr::LOCALHOST),
        handler,
        SvcConfig::default(),
    );
    for payload in [b"before rotation".as_slice(), b"after rotation"] {
        assert_eq!(
            client.send(
                Arc::new(Packet::to_server(staged.addr(), payload.to_vec())),
                Duration::from_secs(10),
            ),
            TxRxStatus::Success
        );
        assert_eq!(events.next_send().await.1, TxRxStatus::Success);
        assert_eq!(events.next_receive().await.payload, payload);
    }
    staged.finish();
    drop(client);

    let rolled = OracleServer::start(packet_server_command(
        &fixture.cpp_new,
        Some(&fixture.cpp_old),
        1,
        false,
    ));
    let old_rust = fixture.rust_tls(&fixture.cpp_old, &[&fixture.cpp_old, &fixture.cpp_new]);
    assert_eq!(
        rust_packet_to_schannel(old_rust, rolled, b"new A old B", true).await,
        TxRxStatus::Success
    );

    let rolled_rust = fixture.rust_tls(&fixture.cpp_new, &[&fixture.cpp_new, &fixture.cpp_old]);
    let rolled_server = rust_packet_server(rolled_rust).await;
    let mut command = Command::new(oracle());
    command.args([
        "--net-client",
        "127.0.0.1",
        &rolled_server.local_addr().port().to_string(),
        "--payload",
        "726f7461746564",
        "--count",
        "1",
        "--expect",
        "echo",
    ]);
    configure_oracle(
        &mut command,
        &fixture.cpp_new,
        Some(&fixture.cpp_old),
        false,
    );
    assert!(run_oracle_client(command).status.success());

    let removed = OracleServer::start(packet_server_command(&fixture.cpp_new, None, 0, true));
    let old_rust = fixture.rust_tls(&fixture.cpp_old, &[&fixture.cpp_new]);
    assert_ne!(
        rust_packet_to_schannel(old_rust, removed, b"old removed", true).await,
        TxRxStatus::Success
    );
}
