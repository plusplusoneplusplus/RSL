//! What TLS costs: the handshake, and the bytes afterwards.
//!
//! Two questions, and they have different answers:
//!
//! * **Handshake latency.** Paid once per connection — but "once per
//!   connection" in RSL means once per reconnect, and a replica that flaps
//!   pays it every time. This measures a full mutual-TLS handshake over
//!   loopback, both certificate chains verified by the real acceptance rule.
//! * **Steady-state throughput.** Paid per byte. The comparison is against the
//!   identical plaintext stack from `transport.rs`, so the difference is the
//!   record layer and nothing else.
//!
//! ```sh
//! cargo bench -p rsl-net --bench tls
//! ```
//!
//! Both run over loopback, so the numbers include the kernel. The ratio between
//! the plaintext and TLS lines is the part worth reading.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rsl_net::learnport::{Acceptor, Connector};
use rsl_net::svc::{Packet, PacketHandler, PacketSvc, SvcConfig, TxRxStatus};
use rsl_net::tls::{CertificateDer, Identity, Thumbprint, Tls, TlsConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

const TIMEOUT: Duration = Duration::from_secs(30);
const SIZES: [usize; 3] = [1024, 100 * 1024, 10 * 1024 * 1024];

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A self-signed CA and one leaf, pinned by thumbprint. Minted here rather than
/// shared with `tests/certs` because a bench is not a test target and cannot
/// see it.
fn tls() -> Arc<Tls> {
    let ca_key = KeyPair::generate().expect("keygen");
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Bench Root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("self-sign");

    let leaf_key = KeyPair::generate().expect("keygen");
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "bench-replica");
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let leaf = leaf_params
        .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
        .expect("sign");

    let chain: Vec<CertificateDer<'static>> = vec![leaf.der().clone(), ca.der().clone()];
    Tls::new(TlsConfig {
        identity: Identity::from_der(chain, leaf_key.serialize_der()),
        thumbprint_a: Some(Thumbprint::of_der(leaf.der())),
        roots: vec![ca.der().clone()],
        ..TlsConfig::default()
    })
    .expect("config")
}

struct Forward {
    tx: UnboundedSender<Arc<Packet>>,
}

impl PacketHandler for Forward {
    fn process_send(&self, _packet: &Arc<Packet>, _status: TxRxStatus) {}
    fn process_receive(&self, packet: Arc<Packet>) {
        let _ = self.tx.send(packet);
    }
}

fn config() -> SvcConfig {
    SvcConfig {
        bind_ip: Ipv4Addr::LOCALHOST,
        ..SvcConfig::default()
    }
}

/// A client service and an echo server, either plaintext or over TLS.
struct Stack {
    client: PacketSvc,
    peer: SocketAddrV4,
    echoes: UnboundedReceiver<Arc<Packet>>,
    _server: Arc<PacketSvc>,
}

fn stack(runtime: &Runtime, tls: Option<&Arc<Tls>>) -> Stack {
    let _guard = runtime.enter();

    let (received_tx, mut received) = unbounded_channel();
    let handler = Arc::new(Forward { tx: received_tx });
    let server = Arc::new(
        match tls {
            Some(tls) => PacketSvc::start_as_server_with(0, tls.acceptor(), handler, config()),
            None => PacketSvc::start_as_server(0, handler, config()),
        }
        .expect("bind echo server"),
    );
    let peer = server.local_addr();

    let echo = server.clone();
    runtime.spawn(async move {
        while let Some(packet) = received.recv().await {
            let reply = Packet::to_client(packet.client, packet.payload.clone());
            echo.send(Arc::new(reply), TIMEOUT);
        }
    });

    let (echo_tx, echoes) = unbounded_channel();
    let handler = Arc::new(Forward { tx: echo_tx });
    let client = match tls {
        Some(tls) => {
            PacketSvc::start_as_client_with(tls.dialer(Ipv4Addr::LOCALHOST), handler, config())
        }
        None => PacketSvc::start_as_client(handler, config()),
    };

    Stack {
        client,
        peer,
        echoes,
        _server: server,
    }
}

impl Stack {
    fn round_trip(&mut self, runtime: &Runtime, packet: &Arc<Packet>) {
        runtime.block_on(async {
            self.client.send(packet.clone(), TIMEOUT);
            self.echoes.recv().await.expect("echo");
        });
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// One full mutual handshake, connection setup included, over the learn port's
/// connector/acceptor pair — the shortest path to a handshake this crate has.
fn handshake(c: &mut Criterion) {
    let runtime = Runtime::new().expect("runtime");
    let tls = tls();

    let mut group = c.benchmark_group("tls/handshake");
    group.sample_size(50);
    group.bench_function("mutual", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                let addr = listener.local_addr().expect("addr");
                let acceptor = tls.connector();
                let serve = tokio::spawn(async move {
                    let (sock, _) = listener.accept().await.expect("accept");
                    let mut stream = Acceptor::accept(&*acceptor, sock).await.expect("handshake");
                    stream.write_all(b"o").await.expect("write");
                });
                let connector = tls.connector();
                let mut stream = Connector::connect(&*connector, addr)
                    .await
                    .expect("handshake");
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.expect("read");
                serve.await.expect("server task");
            });
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Throughput
// ---------------------------------------------------------------------------

fn round_trip(c: &mut Criterion) {
    let runtime = Runtime::new().expect("runtime");
    let tls = tls();

    let mut group = c.benchmark_group("tls/round_trip");
    let mut plain = stack(&runtime, None);
    let mut encrypted = stack(&runtime, Some(&tls));

    for size in SIZES {
        group.sample_size(if size >= 1024 * 1024 { 20 } else { 100 });
        group.throughput(Throughput::Bytes(2 * size as u64));

        let payload = Arc::new(Packet::to_server(plain.peer, vec![0x5a; size]));
        group.bench_with_input(BenchmarkId::new("plaintext", size), &size, |b, _| {
            b.iter(|| plain.round_trip(&runtime, &payload));
        });

        let payload = Arc::new(Packet::to_server(encrypted.peer, vec![0x5a; size]));
        group.bench_with_input(BenchmarkId::new("tls", size), &size, |b, _| {
            b.iter(|| encrypted.round_trip(&runtime, &payload));
        });
    }
    group.finish();
}

criterion_group!(benches, handshake, round_trip);
criterion_main!(benches);
