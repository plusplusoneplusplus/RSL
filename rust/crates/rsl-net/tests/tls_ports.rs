//! TLS as the two ports actually use it: one config gating both, packets held
//! across a handshake, and a certificate rotation performed on a live fleet.
//!
//! These run over real loopback sockets. The rule matrix lives in
//! `tls_rules.rs`; nothing here re-tests a rule, it tests the wiring.

mod certs;
mod harness;
mod learnfixture;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use certs::{Ca, Leaf, LeafSpec};
use harness::Recorder;
use learnfixture::{StubStatus, TempDir};
use rsl_net::learnport::{DirSource, LearnClient, LearnConfig, LearnServer, Requester};
use rsl_net::svc::{ConnectState, Packet, PacketSvc, SvcConfig, TxRxStatus};
use rsl_net::tls::{Tls, TlsConfig};
use rsl_wire::{MemberId, ProtocolVersion};

/// A fleet where every replica presents `leaf` and accepts exactly the pins in
/// `accepts`.
fn tls_for(leaf: &Leaf, ca: &Ca, accepts: &[&Leaf]) -> Arc<Tls> {
    let mut config = TlsConfig {
        identity: leaf.identity(),
        roots: vec![ca.der()],
        ..TlsConfig::default()
    };
    config.thumbprint_a = accepts.first().map(|l| l.thumbprint());
    config.thumbprint_b = accepts.get(1).map(|l| l.thumbprint());
    Tls::new(config).expect("config")
}

// ---------------------------------------------------------------------------
// One config, both ports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_packet_port_moves_a_packet_over_tls() {
    let ca = Ca::new("Root");
    let leaf = ca.issue(LeafSpec::named("replica"));
    let tls = tls_for(&leaf, &ca, &[&leaf]);

    let (server_handler, mut server_events) = Recorder::new();
    let server = PacketSvc::start_as_server_with(
        0,
        tls.acceptor(),
        server_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    )
    .expect("listen");
    let addr = server.local_addr();

    let (client_handler, mut client_events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(
        tls.dialer(Ipv4Addr::LOCALHOST),
        client_handler,
        SvcConfig::default(),
    );

    let status = client.send(
        Arc::new(Packet::to_server(addr, b"hello over tls".to_vec())),
        Duration::from_secs(5),
    );
    assert_eq!(status, TxRxStatus::Success);

    let (_, status) = client_events.next_send().await;
    assert_eq!(status, TxRxStatus::Success);
    let received = server_events
        .next_where(|e| e.payload() == Some(b"hello over tls".as_slice()))
        .await;
    assert_eq!(received.payload(), Some(b"hello over tls".as_slice()));
}

#[tokio::test]
async fn a_plaintext_client_cannot_reach_a_tls_packet_port() {
    // The point of the phase, stated as a test: with TLS configured, the wire
    // is not RSL framing any more.
    let ca = Ca::new("Root");
    let leaf = ca.issue(LeafSpec::named("replica"));
    let tls = tls_for(&leaf, &ca, &[&leaf]);

    let (server_handler, mut server_events) = Recorder::new();
    let server = PacketSvc::start_as_server_with(
        0,
        tls.acceptor(),
        server_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    )
    .expect("listen");
    let addr = server.local_addr();

    let (client_handler, mut client_events) = Recorder::new();
    let client = PacketSvc::start_as_client(client_handler, SvcConfig::default());
    client.send(
        Arc::new(Packet::to_server(addr, b"plaintext".to_vec())),
        Duration::from_millis(500),
    );

    // The client's send *succeeds*: `TxSuccess` has always meant "these bytes
    // reached the socket", and a TCP write to a peer that is about to hang up
    // does. What matters is what happens next — the server makes nothing of a
    // ClientHello-shaped-like-an-RSL-packet, closes, and the client sees the
    // disconnect.
    let (_, status) = client_events.next_send().await;
    assert_eq!(status, TxRxStatus::Success);
    assert_eq!(
        client_events
            .next_connect_where(ConnectState::DisConnected)
            .await,
        ConnectState::DisConnected
    );

    // And nothing was ever delivered to the server's handler.
    let delivered = tokio::time::timeout(Duration::from_millis(200), server_events.recv()).await;
    assert!(
        !matches!(delivered, Ok(Some(ref e)) if e.payload().is_some()),
        "a plaintext payload reached the handler: {delivered:?}"
    );
}

#[tokio::test]
async fn the_learn_port_serves_a_status_query_over_the_same_config() {
    let ca = Ca::new("Root");
    let leaf = ca.issue(LeafSpec::named("replica"));
    let tls = tls_for(&leaf, &ca, &[&leaf]);

    let dir = TempDir::new("tls-learn");
    let status = StubStatus::new().with_log_range(1, 9);
    let source = Arc::new(DirSource::new(dir.path(), status));
    let server = LearnServer::bind_with(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        tls.connector(),
        source,
        LearnConfig::default(),
    )
    .await
    .expect("bind");

    let who = Requester::new(ProtocolVersion::V6, MemberId::from_str("7"), 1);
    let client = LearnClient::new().over(tls.connector());
    let response = client
        .query_status(server.local_addr(), &who.status_query())
        .await
        .expect("status over tls");
    assert_eq!(response.min_decree_in_log, 1);
    assert_eq!(response.header.decree, 9);
}

#[tokio::test]
async fn a_plaintext_client_cannot_reach_a_tls_learn_port() {
    let ca = Ca::new("Root");
    let leaf = ca.issue(LeafSpec::named("replica"));
    let tls = tls_for(&leaf, &ca, &[&leaf]);

    let dir = TempDir::new("tls-learn-plain");
    let source = Arc::new(DirSource::new(
        dir.path(),
        StubStatus::new().with_log_range(1, 9),
    ));
    let server = LearnServer::bind_with(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        tls.connector(),
        source,
        LearnConfig::default(),
    )
    .await
    .expect("bind");

    let who = Requester::new(ProtocolVersion::V6, MemberId::from_str("7"), 1);
    let plaintext = LearnClient::new();
    let result = plaintext
        .query_status(server.local_addr(), &who.status_query())
        .await;
    assert!(result.is_err(), "a plaintext status query was answered");
}

// ---------------------------------------------------------------------------
// Sends before the handshake completes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn packets_queued_before_the_handshake_are_held_and_then_delivered() {
    // `NetSslCxn::EnqueuePacket` skips `WriteReadyInternal` until
    // `IsSspiAuthCompleted()`; the queue is the holding area. Here the packets
    // are handed to a client service that has not connected to anything yet,
    // so all four are queued before a single TLS record exists.
    let ca = Ca::new("Root");
    let leaf = ca.issue(LeafSpec::named("replica"));
    let tls = tls_for(&leaf, &ca, &[&leaf]);

    let (server_handler, mut server_events) = Recorder::new();
    let server = PacketSvc::start_as_server_with(
        0,
        tls.acceptor(),
        server_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    )
    .expect("listen");
    let addr = server.local_addr();

    let (client_handler, mut client_events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(
        tls.dialer(Ipv4Addr::LOCALHOST),
        client_handler,
        SvcConfig::default(),
    );

    for i in 0u8..4 {
        let status = client.send(
            Arc::new(Packet::to_server(addr, vec![i; 8])),
            Duration::from_secs(5),
        );
        assert_eq!(status, TxRxStatus::Success, "packet {i} was not accepted");
    }

    // Every one of them is delivered, in order, once the handshake finishes.
    for i in 0u8..4 {
        let (packet, status) = client_events.next_send().await;
        assert_eq!(status, TxRxStatus::Success);
        assert_eq!(packet.payload, vec![i; 8]);
        let received = server_events.next_where(|e| e.payload().is_some()).await;
        assert_eq!(received.payload(), Some(vec![i; 8].as_slice()));
    }
}

#[tokio::test]
async fn connected_is_reported_only_after_the_handshake_succeeds() {
    // A peer whose certificate we refuse must never produce a `Connected`
    // callback: the C++ fires it from the `AuthDataEnd` branch, after
    // validation, and the engine treats `Connected` as "this replica is
    // reachable".
    let ca = Ca::new("Root");
    let mine = ca.issue(LeafSpec::named("mine"));
    let theirs = ca.issue(LeafSpec::named("theirs").with_serial(2));

    // The server presents `theirs`; the client accepts only `mine`.
    let server_tls = tls_for(&theirs, &ca, &[&mine, &theirs]);
    let client_tls = tls_for(&mine, &ca, &[&mine]);

    let (server_handler, _server_events) = Recorder::new();
    let server = PacketSvc::start_as_server_with(
        0,
        server_tls.acceptor(),
        server_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    )
    .expect("listen");
    let addr = server.local_addr();

    let (client_handler, mut client_events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(
        client_tls.dialer(Ipv4Addr::LOCALHOST),
        client_handler,
        SvcConfig::default(),
    );
    client.send(
        Arc::new(Packet::to_server(addr, b"nope".to_vec())),
        Duration::from_millis(300),
    );

    // The packet fails, and no `Connected` is ever seen.
    let (_, status) = client_events.next_send().await;
    assert_ne!(status, TxRxStatus::Success);
    let seen = client_events.drain();
    assert!(
        !seen
            .iter()
            .any(|e| e.state() == Some(ConnectState::Connected)),
        "Connected fired for a peer we refused: {seen:?}"
    );
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rotation_leaves_live_connections_alone_and_applies_to_new_ones() {
    // The A/B roll, played out:
    //   1. everyone runs `old`, pinning `old`
    //   2. `new` is staged in slot B — both are accepted
    //   3. the fleet rolls its own credential to `new`
    //   4. `old` is demoted
    // A connection established at step 1 must survive all of it.
    let ca = Ca::new("Root");
    let old = ca.issue(LeafSpec::named("replica").with_serial(1));
    let new = ca.issue(LeafSpec::named("replica").with_serial(2));

    let stage1 = || TlsConfig {
        identity: old.identity(),
        thumbprint_a: Some(old.thumbprint()),
        roots: vec![ca.der()],
        ..TlsConfig::default()
    };
    let tls = Tls::new(stage1()).expect("config");

    let (server_handler, mut server_events) = Recorder::new();
    let server = PacketSvc::start_as_server_with(
        0,
        tls.acceptor(),
        server_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    )
    .expect("listen");
    let addr = server.local_addr();

    let (client_handler, mut client_events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(
        tls.dialer(Ipv4Addr::LOCALHOST),
        client_handler,
        SvcConfig::default(),
    );
    client.send(
        Arc::new(Packet::to_server(addr, b"before".to_vec())),
        Duration::from_secs(5),
    );
    let (_, status) = client_events.next_send().await;
    assert_eq!(status, TxRxStatus::Success);

    // Step 2 + 3 + 4 in one swap: present `new`, accept only `new`. The live
    // connection was authenticated under the old rule and must not be touched.
    tls.swap(TlsConfig {
        identity: new.identity(),
        thumbprint_a: Some(new.thumbprint()),
        roots: vec![ca.der()],
        ..TlsConfig::default()
    })
    .expect("rotate");

    client.send(
        Arc::new(Packet::to_server(addr, b"after".to_vec())),
        Duration::from_secs(5),
    );
    let (_, status) = client_events.next_send().await;
    assert_eq!(
        status,
        TxRxStatus::Success,
        "the rotation disturbed a live connection"
    );
    server_events
        .next_where(|e| e.payload() == Some(b"after".as_slice()))
        .await;

    // A *new* connection now uses the new configuration end to end.
    let (fresh_handler, mut fresh_events) = Recorder::new();
    let fresh = PacketSvc::start_as_client_with(
        tls.dialer(Ipv4Addr::LOCALHOST),
        fresh_handler,
        SvcConfig::default(),
    );
    fresh.send(
        Arc::new(Packet::to_server(addr, b"rotated".to_vec())),
        Duration::from_secs(5),
    );
    let (_, status) = fresh_events.next_send().await;
    assert_eq!(status, TxRxStatus::Success);
    server_events
        .next_where(|e| e.payload() == Some(b"rotated".as_slice()))
        .await;
}

#[tokio::test]
async fn a_peer_still_on_the_old_certificate_is_accepted_while_both_slots_are_staged() {
    // Step 2 of the roll on its own: this is what makes a rotation possible at
    // all, and it is the whole reason the A/B pair exists.
    let ca = Ca::new("Root");
    let old = ca.issue(LeafSpec::named("replica").with_serial(1));
    let new = ca.issue(LeafSpec::named("replica").with_serial(2));

    let staged = |identity: &Leaf| {
        Tls::new(TlsConfig {
            identity: identity.identity(),
            thumbprint_a: Some(new.thumbprint()),
            thumbprint_b: Some(old.thumbprint()),
            roots: vec![ca.der()],
            ..TlsConfig::default()
        })
        .expect("config")
    };

    let rolled = staged(&new);
    let not_yet = staged(&old);

    let (server_handler, mut server_events) = Recorder::new();
    let server = PacketSvc::start_as_server_with(
        0,
        rolled.acceptor(),
        server_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    )
    .expect("listen");
    let addr: SocketAddrV4 = server.local_addr();

    let (client_handler, mut client_events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(
        not_yet.dialer(Ipv4Addr::LOCALHOST),
        client_handler,
        SvcConfig::default(),
    );
    client.send(
        Arc::new(Packet::to_server(addr, b"mixed fleet".to_vec())),
        Duration::from_secs(5),
    );
    let (_, status) = client_events.next_send().await;
    assert_eq!(status, TxRxStatus::Success);
    server_events
        .next_where(|e| e.payload() == Some(b"mixed fleet".as_slice()))
        .await;
}
