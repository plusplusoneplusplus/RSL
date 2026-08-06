//! rustls against a TLS stack that is not rustls.
//!
//! The peer here is `golden-gen --tls-peer` / `--tls-client`: the real C++
//! packet framing, over OpenSSL. It is a **proxy oracle** — the C++ RSL speaks
//! TLS through SChannel, which cannot run on Linux — and it exists to catch the
//! failure mode two rustls peers cannot: a version, cipher suite, chain
//! encoding or client-certificate exchange that only rustls agrees with.
//!
//! Skipped, loudly, when `golden-gen` has not been built or was built without
//! OpenSSL. See `TLS.md` for the residual SChannel risk this does not close.

mod certs;
mod harness;
mod learnfixture;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use certs::{Ca, LeafSpec};
use harness::Recorder;
use learnfixture::{golden_gen, warn_no_peer, TempDir};
use rsl_net::svc::{Packet, PacketSvc, SvcConfig, TxRxStatus};
use rsl_net::tls::{Tls, TlsConfig};

/// A CA, a certificate for each side, and PEM files on disk for the C++ peer.
struct Fixture {
    dir: TempDir,
    ca: Ca,
    ours: certs::Leaf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = TempDir::new(name);
        let ca = Ca::new("RSL Interop Root");
        let ours = ca.issue(LeafSpec::named("rust-replica"));
        let theirs = ca.issue(LeafSpec::named("cpp-replica").with_serial(2));

        write(&dir.join("ca.pem"), ca.pem().as_bytes());
        write(&dir.join("peer.pem"), theirs.cert_pem().as_bytes());
        write(&dir.join("peer.key"), theirs.key_pem().as_bytes());
        write(&dir.join("ours.pem"), ours.cert_pem().as_bytes());
        write(&dir.join("ours.key"), ours.key_pem().as_bytes());

        Fixture { dir, ca, ours }
    }

    /// Our side: present `ours`, accept anything the interop CA issued whose
    /// common name is one of the two we minted.
    ///
    /// The subject rule rather than a thumbprint pin is deliberate — it is the
    /// path that depends on the *presented chain* being encoded the way we
    /// expect, which is exactly what a foreign TLS stack can get differently.
    fn tls(&self) -> Arc<Tls> {
        Tls::new(TlsConfig {
            identity: self.ours.identity(),
            subject_a: Some(rsl_net::tls::SubjectRule {
                subject: "cpp-replica".into(),
                parents: vec![self.ca.thumbprint()],
            }),
            subject_b: Some(rsl_net::tls::SubjectRule {
                subject: "rust-replica".into(),
                parents: vec![self.ca.thumbprint()],
            }),
            roots: vec![self.ca.der()],
            ..TlsConfig::default()
        })
        .expect("config")
    }

    fn arg(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    std::fs::File::create(path)
        .expect("create pem")
        .write_all(bytes)
        .expect("write pem");
}

/// True when the built `golden-gen` has the OpenSSL peer compiled in.
fn tls_peer_available(bin: &std::path::Path) -> bool {
    let out = Command::new(bin)
        .arg("--tls-peer")
        .arg("0")
        .output()
        .expect("run golden-gen");
    // Exit 3 is the "built without OpenSSL" path; 2 is "arguments missing",
    // which means the peer is there.
    out.status.code() != Some(3)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rust_client_talks_to_an_openssl_server() {
    let Some(bin) = golden_gen() else {
        return warn_no_peer("a_rust_client_talks_to_an_openssl_server");
    };
    if !tls_peer_available(&bin) {
        eprintln!(
            "a_rust_client_talks_to_an_openssl_server: SKIPPED — golden-gen was built \
             without OpenSSL (install libssl-dev and re-run cmake)"
        );
        return;
    }

    let fixture = Fixture::new("tls-interop-server");
    let mut peer = Command::new(&bin)
        .args(["--tls-peer", "0"])
        .args(["--cert", &fixture.arg("peer.pem")])
        .args(["--key", &fixture.arg("peer.key")])
        .args(["--ca", &fixture.arg("ca.pem")])
        .args(["--mode", "echo"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn peer");

    let port = read_port(&mut peer);

    let tls = fixture.tls();
    let (handler, mut events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(
        tls.dialer(Ipv4Addr::LOCALHOST),
        handler,
        SvcConfig::default(),
    );

    let payload = b"phase 4d over openssl".to_vec();
    let status = client.send(
        Arc::new(Packet::to_server(
            std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
            payload.clone(),
        )),
        Duration::from_secs(10),
    );
    assert_eq!(status, TxRxStatus::Success);

    let (_, status) = events.next_send().await;
    assert_eq!(status, TxRxStatus::Success, "the OpenSSL peer refused us");

    // The echo comes back through the same TLS session and parses as a packet:
    // the framing is intact on top of a foreign record layer.
    let echoed = tokio::time::timeout(Duration::from_secs(10), events.next_receive())
        .await
        .expect("no echo from the OpenSSL peer");
    assert_eq!(echoed.payload, payload);

    drop(client);
    let _ = peer.wait();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_openssl_client_talks_to_a_rust_server() {
    let Some(bin) = golden_gen() else {
        return warn_no_peer("an_openssl_client_talks_to_a_rust_server");
    };
    if !tls_peer_available(&bin) {
        eprintln!(
            "an_openssl_client_talks_to_a_rust_server: SKIPPED — golden-gen was built \
             without OpenSSL"
        );
        return;
    }

    let fixture = Fixture::new("tls-interop-client");
    let tls = fixture.tls();

    // A server that echoes every packet it receives, so the C++ client can
    // count what came back and the round trip is proven end to end.
    struct Forward(tokio::sync::mpsc::UnboundedSender<Arc<Packet>>);
    impl rsl_net::svc::PacketHandler for Forward {
        fn process_send(&self, _: &Arc<Packet>, _: TxRxStatus) {}
        fn process_receive(&self, packet: Arc<Packet>) {
            let _ = self.0.send(packet);
        }
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let server = Arc::new(
        PacketSvc::start_as_server_with(
            0,
            tls.acceptor(),
            Arc::new(Forward(tx)),
            SvcConfig {
                bind_ip: Ipv4Addr::LOCALHOST,
                ..SvcConfig::default()
            },
        )
        .expect("listen"),
    );
    let addr = server.local_addr();

    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let echo_svc = server.clone();
    tokio::spawn(async move {
        let mut seen_tx = Some(seen_tx);
        while let Some(packet) = rx.recv().await {
            if let Some(tx) = seen_tx.take() {
                let _ = tx.send(packet.payload.clone());
            }
            echo_svc.send(
                Arc::new(Packet::to_client(packet.client, packet.payload.clone())),
                Duration::from_secs(5),
            );
        }
    });

    let peer = Command::new(&bin)
        .args(["--tls-client", "127.0.0.1", &addr.port().to_string()])
        .args(["--cert", &fixture.arg("peer.pem")])
        .args(["--key", &fixture.arg("peer.key")])
        .args(["--ca", &fixture.arg("ca.pem")])
        .args(["--payload", "from the cpp side"])
        .args(["--count", "1"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn peer");

    // The packet must arrive, authenticated, with its payload intact.
    let received = tokio::time::timeout(Duration::from_secs(10), seen_rx)
        .await
        .expect("the OpenSSL client never got through")
        .expect("echo task alive");
    assert_eq!(received, b"from the cpp side".to_vec());

    // And the echo must get back to it: the peer exits 0 only when every
    // packet it sent came back through the same TLS session.
    let out = peer.wait_with_output().expect("peer exit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ECHOED 1"),
        "the OpenSSL client did not get its packet back: {stdout}"
    );
    assert!(out.status.success(), "peer exited {:?}", out.status);
}

/// Read the `PORT <n>` line the peer prints before it blocks in `accept`.
fn read_port(peer: &mut std::process::Child) -> u16 {
    let stdout = peer.stdout.take().expect("piped stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read PORT line");
    line.trim()
        .strip_prefix("PORT ")
        .expect("PORT line")
        .parse()
        .expect("a port")
}
