//! The Phase-4b behaviour contract, deterministically.
//!
//! Every test here runs on `tokio::io::duplex` under `tokio::time::pause()`, so
//! reconnect backoffs and multi-second packet timeouts cost no wall-clock and
//! the outcome cannot depend on scheduling luck. What is being pinned is not
//! the bytes (Phase 4a did that) but the *decisions*: which status a packet
//! gets, when a queue is kept and when it is failed, what a suspended
//! connection does with bytes already in flight.

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::{addr, settle, test_config, Event, MockDialer, Peer, Recorder};
use rsl_net::framing::packet;
use rsl_net::svc::{ConnectState, Link, Packet, PacketSvc, SvcConfig, TxRxStatus};
use rsl_net::Limits;

const BIG: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

fn payload(tag: u8, len: usize) -> Vec<u8> {
    vec![tag; len]
}

// ---------------------------------------------------------------- happy paths

/// A client has no connection until it needs one, and the first packet creates
/// it: `Connecting` → `Connected` → the bytes → `TxSuccess`, in that order.
#[tokio::test(start_paused = true)]
async fn a_client_dials_on_the_first_packet() {
    let (dialer, control) = MockDialer::new(BIG);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());
    let peer_addr = addr(7000);

    assert!(svc.connections().is_empty());
    let status = svc.send(
        Arc::new(Packet::to_server(peer_addr, b"hello".to_vec())),
        TIMEOUT,
    );
    assert_eq!(status, TxRxStatus::Success);

    let mut peer = control.accept().await;
    assert_eq!(peer.read_packet().await, b"hello");

    assert_eq!(events.next().await.state(), Some(ConnectState::Connecting));
    assert_eq!(events.next().await.state(), Some(ConnectState::Connected));
    assert_eq!(events.next().await.status(), Some(TxRxStatus::Success));
    assert_eq!(svc.connections(), vec![peer_addr]);
    assert_eq!(control.dials(), 1);
}

/// The connection is reused, and packets go out in the order they were sent —
/// one at a time (`ProcessQueuedPacketsForWrite`).
#[tokio::test(start_paused = true)]
async fn packets_are_delivered_fifo_on_one_connection() {
    let (dialer, control) = MockDialer::new(BIG);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());

    for i in 0..8u8 {
        assert_eq!(
            svc.send(Arc::new(Packet::to_server(addr(7000), vec![i])), TIMEOUT),
            TxRxStatus::Success
        );
    }
    let mut peer = control.accept().await;
    let got = peer.read_packets(8).await;
    assert_eq!(got, (0..8u8).map(|i| vec![i]).collect::<Vec<_>>());

    for i in 0..8u8 {
        let (packet, status) = events.next_send().await;
        assert_eq!(status, TxRxStatus::Success);
        assert_eq!(packet.payload, vec![i], "callbacks are FIFO too");
    }
    assert_eq!(control.dials(), 1, "one connection for all eight packets");
}

/// Received packets are stamped with both addresses, role-dependently
/// (`NetCxn.cpp:239-248`).
#[tokio::test(start_paused = true)]
async fn received_packets_carry_both_addresses() {
    // Client: the remote is the *server* address, our socket is the client one.
    let (dialer, control) = MockDialer::new(BIG);
    let (recorder, mut events) = Recorder::new();
    let client = PacketSvc::start_as_client_with(dialer, recorder, test_config());
    client.send(Arc::new(Packet::to_server(addr(7000), vec![1])), TIMEOUT);
    let mut peer = control.accept().await;
    peer.read_packet().await;
    peer.write_packet(b"response").await;

    let packet = events.next_receive().await;
    assert_eq!(packet.payload, b"response");
    assert_eq!(
        packet.server,
        addr(7000),
        "remote end of a client connection"
    );
    assert_eq!(packet.client, addr(40000), "our own socket");

    // Server: the other way round.
    let (recorder, mut events) = Recorder::new();
    let server = PacketSvc::start_as_server_detached(addr(9000), recorder, test_config());
    let (theirs, ours) = tokio::io::duplex(BIG);
    assert!(server.attach(Link::new(ours, addr(9000), addr(5555))));
    let mut client_peer = Peer::new(theirs);
    client_peer.write_packet(b"request").await;

    let packet = events.next_receive().await;
    assert_eq!(packet.payload, b"request");
    assert_eq!(
        packet.client,
        addr(5555),
        "remote end of a server connection"
    );
    assert_eq!(packet.server, addr(9000), "our own socket");
}

// ------------------------------------------------------- queue across an outage

/// The property the engine leans on hardest: a client's queue is **not**
/// failed by a disconnect (`NetCxn.cpp:400`). The packet that was mid-write
/// when the peer died is re-sent whole on the new connection.
#[tokio::test(start_paused = true)]
async fn the_client_sendq_survives_a_disconnect_and_retries() {
    // A tiny duplex buffer means a large packet cannot finish writing until the
    // peer reads — which it never does, so the packet is still queued when the
    // connection dies.
    let (dialer, control) = MockDialer::new(1024);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());

    let body = payload(0xab, 8192);
    assert_eq!(
        svc.send(
            Arc::new(Packet::to_server(addr(7000), body.clone())),
            TIMEOUT
        ),
        TxRxStatus::Success
    );
    let peer = control.accept().await;
    settle().await;
    events.assert_quiet_of_sends();

    // The peer crashes without ever reading.
    peer.kill();

    // The service reconnects and sends the whole packet again.
    let mut peer = control.accept().await;
    assert_eq!(peer.read_packet().await, body);
    let (_, status) = events.next_send().await;
    assert_eq!(status, TxRxStatus::Success);

    assert_eq!(control.dials(), 2);
    let states: Vec<_> = events.history().iter().filter_map(Event::state).collect();
    assert_eq!(
        states,
        vec![
            ConnectState::Connecting,
            ConnectState::Connected,
            ConnectState::DisConnected,
            ConnectState::Connecting,
            ConnectState::Connected,
        ]
    );
}

/// `SetFailPacketsOnDisconnect(true)` opts out of that: the queue is failed
/// immediately with `TxNoConnection` instead of waiting for a reconnect.
#[tokio::test(start_paused = true)]
async fn fail_on_disconnect_gives_up_instead_of_retrying() {
    let (dialer, control) = MockDialer::new(1024);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(
        dialer,
        recorder,
        SvcConfig {
            fail_on_disconnect: true,
            ..test_config()
        },
    );

    svc.send(
        Arc::new(Packet::to_server(addr(7000), payload(1, 8192))),
        TIMEOUT,
    );
    let peer = control.accept().await;
    peer.kill();

    let (_, status) = events.next_send().await;
    assert_eq!(status, TxRxStatus::NoConnection);
    settle().await;
    assert_eq!(control.dials(), 1, "no reconnect attempt");
    assert!(svc.connections().is_empty());
}

/// A dial that keeps failing does not fail the packet — only its own deadline
/// does. This is the timeout-racing-a-reconnect case, and the packet must be
/// called back exactly once.
#[tokio::test(start_paused = true)]
async fn a_packet_times_out_while_the_connection_is_down() {
    let (dialer, control) = MockDialer::new(BIG);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());
    control.fail_next(usize::MAX);

    assert_eq!(
        svc.send(
            Arc::new(Packet::to_server(addr(7000), vec![7])),
            Duration::from_secs(1)
        ),
        TxRxStatus::Success
    );

    let (_, status) = events.next_send().await;
    assert_eq!(status, TxRxStatus::TimedOut);

    // Nothing else is owed, and with an empty queue the connection gives up.
    settle().await;
    events.assert_quiet_of_sends();
    assert!(control.dials() > 1, "it did keep retrying meanwhile");
    assert!(svc.connections().is_empty());
}

/// A deadline that fires while the frame is already on the wire fails the
/// packet but does **not** truncate the frame — the C++ duplicates the buffer
/// and lets the I/O finish for exactly this reason.
#[tokio::test(start_paused = true)]
async fn a_timeout_mid_write_still_sends_the_whole_frame() {
    let (dialer, control) = MockDialer::new(1024);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());

    let body = payload(0x5a, 8192);
    svc.send(
        Arc::new(Packet::to_server(addr(7000), body.clone())),
        Duration::from_secs(1),
    );
    let mut peer = control.accept().await;

    let (_, status) = events.next_send().await;
    assert_eq!(status, TxRxStatus::TimedOut);

    // The peer starts reading only now: the frame is intact and complete.
    assert_eq!(peer.read_packet().await, body);
    // And the completed write produces no second callback.
    settle().await;
    events.assert_quiet_of_sends();
}

// ---------------------------------------------------------------- send statuses

/// A server can only answer on a connection the client opened
/// (`NetPacketSvc.cpp:345` — only a client creates one). The refusal is the
/// return value, so no callback follows.
#[tokio::test(start_paused = true)]
async fn a_server_send_without_a_connection_is_refused_inline() {
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_server_detached(addr(9000), recorder, test_config());

    let status = svc.send(Arc::new(Packet::to_client(addr(5555), vec![1])), TIMEOUT);
    assert_eq!(status, TxRxStatus::NoConnection);

    settle().await;
    events.assert_quiet();
}

/// `send_on_existing` makes a client behave the same way.
#[tokio::test(start_paused = true)]
async fn send_on_existing_never_opens_a_connection() {
    let (dialer, control) = MockDialer::new(BIG);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());

    let status = svc.send_with(
        Arc::new(Packet::to_server(addr(7000), vec![1])),
        TIMEOUT,
        true,
    );
    assert_eq!(status, TxRxStatus::NoConnection);
    assert_eq!(control.dials(), 0);
    settle().await;
    events.assert_quiet();
}

/// After `stop()`, every send is refused inline with `TxAbort`.
#[tokio::test(start_paused = true)]
async fn sends_after_stop_are_aborted_inline() {
    let (dialer, _control) = MockDialer::new(BIG);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());

    svc.stop();
    assert!(svc.is_stopped());
    let status = svc.send(Arc::new(Packet::to_server(addr(7000), vec![1])), TIMEOUT);
    assert_eq!(status, TxRxStatus::Abort);

    settle().await;
    events.assert_quiet();
}

/// `stop()` flushes everything already queued with `TxAbort` — including the
/// packet that was mid-write.
#[tokio::test(start_paused = true)]
async fn stop_aborts_every_queued_packet() {
    let (dialer, control) = MockDialer::new(1024);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());

    for i in 0..4u8 {
        svc.send(
            Arc::new(Packet::to_server(addr(7000), payload(i, 8192))),
            TIMEOUT,
        );
    }
    let _peer = control.accept().await;
    settle().await;
    events.assert_quiet_of_sends();

    svc.stop();
    for _ in 0..4 {
        let (_, status) = events.next_send().await;
        assert_eq!(status, TxRxStatus::Abort);
    }
    settle().await;
    events.assert_quiet_of_sends();
}

/// `close_connection` does the same for one connection
/// (`NetPacketSvc.h:243` — "TxAbort for all outstanding sends").
#[tokio::test(start_paused = true)]
async fn close_connection_aborts_that_connections_queue() {
    let (dialer, control) = MockDialer::new(1024);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());

    svc.send(
        Arc::new(Packet::to_server(addr(7000), payload(3, 8192))),
        TIMEOUT,
    );
    let _peer = control.accept().await;
    settle().await;

    svc.close_connection(*addr(7000).ip(), 7000);
    let (_, status) = events.next_send().await;
    assert_eq!(status, TxRxStatus::Abort);

    settle().await;
    assert!(svc.connections().is_empty(), "the entry is gone afterwards");
    // The service still works: the next send opens a fresh connection.
    assert_eq!(
        svc.send(Arc::new(Packet::to_server(addr(7000), vec![9])), TIMEOUT),
        TxRxStatus::Success
    );
    let mut peer = control.accept().await;
    assert_eq!(peer.read_packet().await, vec![9]);
}

// -------------------------------------------------------------- accept + close

/// A second connection from the same `(ip, port)` is dropped and the original
/// kept ("Duplicate Connection", `PacketUtil.cpp:349`).
#[tokio::test(start_paused = true)]
async fn a_duplicate_accept_is_rejected_and_the_original_kept() {
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_server_detached(addr(9000), recorder, test_config());

    let (theirs, ours) = tokio::io::duplex(BIG);
    assert!(svc.attach(Link::new(ours, addr(9000), addr(5555))));

    let (dup_theirs, dup_ours) = tokio::io::duplex(BIG);
    assert!(
        !svc.attach(Link::new(dup_ours, addr(9000), addr(5555))),
        "same remote address"
    );
    // A different port is a different connection.
    let (_other_theirs, other_ours) = tokio::io::duplex(BIG);
    assert!(svc.attach(Link::new(other_ours, addr(9000), addr(5556))));

    // The rejected stream is closed, the original still delivers.
    let mut duplicate = Peer::new(dup_theirs);
    assert!(duplicate.read_to_end().await.is_empty());

    let mut original = Peer::new(theirs);
    original.write_packet(b"still here").await;
    assert_eq!(events.next_receive().await.payload, b"still here");
}

/// A framing reject closes the connection rather than resynchronizing, and the
/// packets that preceded it in the same buffer are still delivered.
#[tokio::test(start_paused = true)]
async fn a_corrupt_frame_closes_the_connection() {
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_server_detached(addr(9000), recorder, test_config());
    let (theirs, ours) = tokio::io::duplex(BIG);
    assert!(svc.attach(Link::new(ours, addr(9000), addr(5555))));
    let mut peer = Peer::new(theirs);

    let mut bytes = packet::encode_packet(b"good");
    let mut corrupt = packet::encode_packet(b"bad");
    *corrupt.last_mut().expect("non-empty") ^= 0x01;
    bytes.extend_from_slice(&corrupt);
    bytes.extend_from_slice(&packet::encode_packet(b"never seen"));
    peer.write_bytes(&bytes).await;

    assert_eq!(events.next_connect().await, ConnectState::Connected);
    assert_eq!(events.next_receive().await.payload, b"good");
    assert_eq!(events.next_connect().await, ConnectState::DisConnected);
    settle().await;
    assert!(svc.connections().is_empty());
    events.assert_quiet_of_receives();
}

/// A size field past the cap is refused on the header alone, before the body
/// is awaited.
#[tokio::test(start_paused = true)]
async fn an_oversize_frame_closes_the_connection() {
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_server_detached(
        addr(9000),
        recorder,
        SvcConfig {
            limits: Limits::from_config_mb(1, 0).expect("valid"),
            ..test_config()
        },
    );
    let (theirs, ours) = tokio::io::duplex(BIG);
    assert!(svc.attach(Link::new(ours, addr(9000), addr(5555))));
    let mut peer = Peer::new(theirs);

    let mut frame = packet::encode_packet(b"");
    frame[0..4].copy_from_slice(&(100u32 * 1024 * 1024).to_le_bytes());
    peer.write_bytes(&frame).await;

    assert_eq!(events.next_connect().await, ConnectState::Connected);
    assert_eq!(events.next_connect().await, ConnectState::DisConnected);
    settle().await;
    assert!(svc.connections().is_empty());
}

// ------------------------------------------------------------ suspend / resume

/// Suspending stops delivery and stops consuming the socket; bytes already
/// buffered — including a half-arrived packet — survive until resume.
#[tokio::test(start_paused = true)]
async fn suspend_holds_a_half_arrived_packet_until_resume() {
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_server_detached(addr(9000), recorder, test_config());
    let (theirs, ours) = tokio::io::duplex(BIG);
    assert!(svc.attach(Link::new(ours, addr(9000), addr(5555))));
    let mut peer = Peer::new(theirs);

    let body = payload(0x11, 4096);
    let frame = packet::encode_packet(&body);
    let (head, tail) = frame.split_at(100);

    // Half the packet arrives, then the service is suspended, then the rest.
    peer.write_bytes(head).await;
    settle().await;
    svc.suspend_receive();
    assert!(svc.is_receive_suspended());
    peer.write_bytes(tail).await;
    settle().await;
    events.assert_quiet_of_receives();

    svc.resume_receive();
    assert_eq!(events.next_receive().await.payload, body);
}

/// A connection created while suspended inherits the state
/// (`NetCxn.cpp:28` — `m_ReceiveSuspended = svc->m_ReceiveSuspended`).
#[tokio::test(start_paused = true)]
async fn a_new_connection_inherits_the_suspended_flag() {
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_server_detached(addr(9000), recorder, test_config());
    svc.suspend_receive();

    let (theirs, ours) = tokio::io::duplex(BIG);
    assert!(svc.attach(Link::new(ours, addr(9000), addr(5555))));
    let mut peer = Peer::new(theirs);
    peer.write_packet(b"queued").await;
    settle().await;
    events.assert_quiet_of_receives();

    svc.resume_receive();
    assert_eq!(events.next_receive().await.payload, b"queued");
}

/// Suspending the receive path does not touch the send path.
#[tokio::test(start_paused = true)]
async fn suspend_does_not_stop_sending() {
    let (dialer, control) = MockDialer::new(BIG);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, test_config());
    svc.suspend_receive();

    svc.send(Arc::new(Packet::to_server(addr(7000), vec![4])), TIMEOUT);
    let mut peer = control.accept().await;
    assert_eq!(peer.read_packet().await, vec![4]);
    let (_, status) = events.next_send().await;
    assert_eq!(status, TxRxStatus::Success);
}
