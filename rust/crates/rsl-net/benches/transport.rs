//! Transport benchmarks: what a packet costs end to end.
//!
//! Two peers are measured. The **Rust** peer is a full `PacketSvc` server that
//! echoes each packet back down the accepted connection, so a round trip covers
//! both services completely — dial, frame, write, decode, callback, and the
//! same again in reverse. The optional peer is the Linux packet model over a
//! real socket; it is a portable comparison point, not a production benchmark.
//!
//! Round trips go over loopback TCP, so absolute numbers include the kernel;
//! what is worth reading is the shape across sizes and the gap between the two
//! peers.
//!
//! ```sh
//! cargo bench -p rsl-net --bench transport
//! ```

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use rsl_net::svc::{Packet, PacketHandler, PacketSvc, SvcConfig, TxRxStatus};

const TIMEOUT: Duration = Duration::from_secs(30);
const SIZES: [usize; 3] = [1024, 100 * 1024, 10 * 1024 * 1024];
/// Bytes to push through per throughput sample, so the big sizes do not run for
/// minutes.
const THROUGHPUT_BUDGET: usize = 16 * 1024 * 1024;

fn config() -> SvcConfig {
    SvcConfig {
        bind_ip: Ipv4Addr::LOCALHOST,
        ..SvcConfig::default()
    }
}

/// Forwards received packets to whoever is driving the benchmark.
struct Forward {
    tx: UnboundedSender<Arc<Packet>>,
}

impl PacketHandler for Forward {
    fn process_send(&self, _packet: &Arc<Packet>, _status: TxRxStatus) {}

    fn process_receive(&self, packet: Arc<Packet>) {
        let _ = self.tx.send(packet);
    }
}

/// A client service plus the echo peer it talks to.
struct Stack {
    client: PacketSvc,
    peer: SocketAddrV4,
    echoes: UnboundedReceiver<Arc<Packet>>,
    // Kept alive for the duration of the benchmark.
    _server: Option<Arc<PacketSvc>>,
    _child: Option<PeerProcess>,
}

impl Stack {
    /// One packet out, its echo back.
    fn round_trip(&mut self, runtime: &Runtime, packet: &Arc<Packet>) {
        runtime.block_on(async {
            self.client.send(packet.clone(), TIMEOUT);
            self.echoes.recv().await.expect("echo");
        });
    }

    /// `n` packets out, all `n` echoes back.
    fn pipeline(&mut self, runtime: &Runtime, packet: &Arc<Packet>, n: usize) {
        runtime.block_on(async {
            for _ in 0..n {
                self.client.send(packet.clone(), TIMEOUT);
            }
            for _ in 0..n {
                self.echoes.recv().await.expect("echo");
            }
        });
    }
}

/// A `PacketSvc` server that echoes every packet back to its sender.
fn rust_stack(runtime: &Runtime) -> Stack {
    let _guard = runtime.enter();

    let (received_tx, mut received) = unbounded_channel();
    let server = Arc::new(
        PacketSvc::start_as_server(0, Arc::new(Forward { tx: received_tx }), config())
            .expect("bind echo server"),
    );
    let peer = server.local_addr();

    // The echo loop holds the only extra reference to the server, so there is
    // no handler → service cycle.
    let echo = server.clone();
    runtime.spawn(async move {
        while let Some(packet) = received.recv().await {
            // A fresh packet addressed back at the sender; the payload copy is
            // the echo's own cost, not the transport's.
            let reply = Packet::to_client(packet.client, packet.payload.clone());
            echo.send(Arc::new(reply), TIMEOUT);
        }
    });

    let (echo_tx, echoes) = unbounded_channel();
    let client = PacketSvc::start_as_client(Arc::new(Forward { tx: echo_tx }), config());

    Stack {
        client,
        peer,
        echoes,
        _server: Some(server),
        _child: None,
    }
}

/// The Linux proxy peer, if it has been built.
fn proxy_stack(runtime: &Runtime) -> Option<Stack> {
    let child = PeerProcess::start()?;
    let peer = child.addr;
    let _guard = runtime.enter();
    let (echo_tx, echoes) = unbounded_channel();
    let client = PacketSvc::start_as_client(Arc::new(Forward { tx: echo_tx }), config());
    Some(Stack {
        client,
        peer,
        echoes,
        _server: None,
        _child: Some(child),
    })
}

struct PeerProcess {
    child: Child,
    addr: SocketAddrV4,
}

impl PeerProcess {
    fn start() -> Option<PeerProcess> {
        let binary = Self::proxy_binary()?;
        if !binary.is_file() {
            return None;
        }

        let mut child = Command::new(binary)
            .args(["--packet-peer", "0", "--mode", "echo"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut stdout = BufReader::new(child.stdout.take()?);
        let mut line = String::new();
        stdout.read_line(&mut line).ok()?;
        let port: u16 = line.strip_prefix("PORT ")?.trim().parse().ok()?;
        Some(PeerProcess {
            child,
            addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        })
    }

    fn proxy_binary() -> Option<std::path::PathBuf> {
        if let Some(path) = std::env::var_os("RSL_LINUX_PROXY") {
            return Some(std::path::PathBuf::from(path));
        }
        #[cfg(unix)]
        {
            Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../tools/linux-proxy/build/rsl-linux-proxy"),
            )
        }
        #[cfg(not(unix))]
        None
    }
}

impl Drop for PeerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn packet(peer: SocketAddrV4, size: usize) -> Arc<Packet> {
    Arc::new(Packet::to_server(peer, vec![0x5a; size]))
}

fn round_trip(c: &mut Criterion) {
    let runtime = Runtime::new().expect("runtime");
    let mut group = c.benchmark_group("svc/round_trip");

    let mut rust = rust_stack(&runtime);
    let mut proxy = proxy_stack(&runtime);
    if proxy.is_none() {
        eprintln!("svc/round_trip: no rsl-linux-proxy binary; skipping the proxy peer");
    }

    for size in SIZES {
        // 10 MiB round trips are slow enough that the default 100 samples turn
        // into a minute per case.
        group.sample_size(if size >= 1024 * 1024 { 20 } else { 100 });
        group.throughput(Throughput::Bytes(2 * size as u64));

        let payload = packet(rust.peer, size);
        group.bench_with_input(BenchmarkId::new("rust_peer", size), &size, |b, _| {
            b.iter(|| rust.round_trip(&runtime, &payload))
        });

        if let Some(proxy) = proxy.as_mut() {
            let payload = packet(proxy.peer, size);
            group.bench_with_input(BenchmarkId::new("linux_proxy", size), &size, |b, _| {
                b.iter(|| proxy.round_trip(&runtime, &payload))
            });
        }
    }
    group.finish();
}

fn throughput(c: &mut Criterion) {
    let runtime = Runtime::new().expect("runtime");
    let mut group = c.benchmark_group("svc/throughput");
    group.sample_size(20);

    let mut rust = rust_stack(&runtime);
    let mut proxy = proxy_stack(&runtime);

    for size in SIZES {
        let n = (THROUGHPUT_BUDGET / size).max(1);
        group.throughput(Throughput::Bytes(2 * (n * size) as u64));

        let payload = packet(rust.peer, size);
        group.bench_with_input(BenchmarkId::new("rust_peer", size), &size, |b, _| {
            b.iter(|| rust.pipeline(&runtime, &payload, n))
        });

        if let Some(proxy) = proxy.as_mut() {
            let payload = packet(proxy.peer, size);
            group.bench_with_input(BenchmarkId::new("linux_proxy", size), &size, |b, _| {
                b.iter(|| proxy.pipeline(&runtime, &payload, n))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, round_trip, throughput);
criterion_main!(benches);
