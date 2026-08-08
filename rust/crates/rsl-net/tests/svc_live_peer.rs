//! Portable transport proxy coverage over a real socket.
//!
//! `tests/live_peer.rs` (Phase 4a) proved the *bytes* agree by driving the
//! Linux receive model from a hand-written socket. Authoritative
//! production Windows service/IOCP coverage lives in
//! `windows_network_oracle.rs`.
//!
//! The peer binary needs cmake + g++, so these skip (with a message) when it
//! has not been built. CI builds it.

mod harness;

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

mod common;

use harness::Recorder;
use rsl_net::svc::{ConnectState, Packet, PacketSvc, SvcConfig, TxRxStatus};
use rsl_net::Limits;

const TIMEOUT: Duration = Duration::from_secs(30);

/// A spawned peer, killed on drop so a failing assertion cannot leak it.
struct Peer {
    child: Child,
    addr: SocketAddrV4,
}

impl Peer {
    fn start(mode: &str) -> Option<Peer> {
        let binary = common::linux_proxy()?;
        let mut child = Command::new(binary)
            .args(["--packet-peer", "0", "--mode", mode])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn rsl-linux-proxy peer");

        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read PORT line");
        let port: u16 = line
            .strip_prefix("PORT ")
            .unwrap_or_else(|| panic!("unexpected peer greeting {line:?}"))
            .trim()
            .parse()
            .expect("port number");

        Some(Peer {
            child,
            addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        })
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn client(handler: Arc<Recorder>, limits: Limits) -> PacketSvc {
    PacketSvc::start_as_client(
        handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            limits,
            ..SvcConfig::default()
        },
    )
}

/// A sustained exchange: many packets across a range of sizes go out through
/// the service, are validated and echoed by the proxy, and come back through the
/// service's receive path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sustained_exchange_with_the_linux_proxy_peer() {
    let Some(peer) = Peer::start("echo") else {
        common::warn_no_peer("a_sustained_exchange_with_the_linux_proxy_peer");
        return;
    };
    let (recorder, mut events) = Recorder::new();
    let svc = client(recorder, Limits::default());

    let payloads: Vec<Vec<u8>> = (0..24u32)
        .map(|i| {
            let len = match i % 4 {
                0 => 0,
                1 => 1,
                2 => 1024,
                _ => 64 * 1024,
            };
            let mut payload = vec![(i & 0xff) as u8; len];
            if len >= 4 {
                payload[..4].copy_from_slice(&i.to_le_bytes());
            }
            payload
        })
        .collect();

    for payload in &payloads {
        assert_eq!(
            svc.send(
                Arc::new(Packet::to_server(peer.addr, payload.clone())),
                TIMEOUT
            ),
            TxRxStatus::Success
        );
    }

    // Every packet is acknowledged, and every echo comes back intact and in
    // order — the proxy writes them back in acceptance order.
    for _ in &payloads {
        assert_eq!(events.next_send().await.1, TxRxStatus::Success);
    }
    for expected in &payloads {
        assert_eq!(&events.next_receive().await.payload, expected);
    }

    assert_eq!(svc.connections(), vec![peer.addr], "one connection, reused");
}

/// The proxy closing the connection part-way through a frame is a disconnect,
/// not a framing error: no half packet is surfaced, and the service reports
/// `DisConnected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_peer_dying_mid_packet_is_a_clean_disconnect() {
    let Some(peer) = Peer::start("truncate") else {
        common::warn_no_peer("the_peer_dying_mid_packet_is_a_clean_disconnect");
        return;
    };
    let (recorder, mut events) = Recorder::new();
    // Fail rather than retry, so the outcome does not depend on how fast the
    // OS refuses a connection to a port that has gone away.
    let svc = PacketSvc::start_as_client(
        recorder,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            fail_on_disconnect: true,
            ..SvcConfig::default()
        },
    );

    // The first packet is echoed whole; the second is answered with half a
    // frame and then the peer closes.
    svc.send(Arc::new(Packet::to_server(peer.addr, vec![1; 64])), TIMEOUT);
    assert_eq!(events.next_send().await.1, TxRxStatus::Success);
    assert_eq!(events.next_receive().await.payload, vec![1; 64]);

    svc.send(
        Arc::new(Packet::to_server(peer.addr, vec![2; 4096])),
        TIMEOUT,
    );
    assert_eq!(events.next_send().await.1, TxRxStatus::Success);

    assert_eq!(
        events.next_connect_where(ConnectState::DisConnected).await,
        ConnectState::DisConnected
    );
    // The truncated frame is never delivered.
    events.assert_quiet_of_receives();
}

/// A frame the peer is happy to send but this service is configured to refuse
/// closes the connection — the receive cap is enforced on the header alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversize_frame_from_the_linux_proxy_peer_closes_the_connection() {
    let Some(peer) = Peer::start("echo") else {
        common::warn_no_peer("an_oversize_frame_from_the_linux_proxy_peer_closes_the_connection");
        return;
    };
    let (recorder, mut events) = Recorder::new();
    // 1 MB cap here; the peer keeps the 100 MB default, so it will happily
    // echo back something we must refuse.
    let svc = client(recorder, Limits::from_config_mb(1, 0).expect("valid"));

    let oversize = vec![0x5a; 2 * 1024 * 1024];
    assert_eq!(
        svc.send(Arc::new(Packet::to_server(peer.addr, oversize)), TIMEOUT),
        TxRxStatus::Success,
        "the send path intentionally has no cap"
    );
    assert_eq!(events.next_send().await.1, TxRxStatus::Success);

    assert_eq!(
        events.next_connect_where(ConnectState::DisConnected).await,
        ConnectState::DisConnected
    );
    events.assert_quiet_of_receives();
}
