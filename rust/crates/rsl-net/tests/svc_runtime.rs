//! The parts of the contract that are about *where* code runs, and one full
//! pass over real TCP.
//!
//! These deliberately do not pause the clock: the callback-thread guarantees
//! are properties of the real scheduler, and the loopback test is the smallest
//! thing that exercises the whole stack — listener, dialer, framing, both
//! services — the way the engine will.

mod harness;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use harness::{addr, MockDialer, Recorder};
use rsl_net::svc::{ConnectState, Packet, PacketSvc, SvcConfig, TxRxStatus};

const TIMEOUT: Duration = Duration::from_secs(30);

/// "The handler is never called on the caller's call stack"
/// (`NetPacketSvc.h:208`) — in the default mode that means a dedicated thread,
/// which is neither the caller's nor a runtime worker's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn callbacks_never_run_on_the_senders_thread() {
    let (dialer, control) = MockDialer::new(64 * 1024);
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client_with(dialer, recorder, SvcConfig::default());

    let sender_thread = std::thread::current().id();
    svc.send(Arc::new(Packet::to_server(addr(7000), vec![1])), TIMEOUT);
    let mut peer = control.accept().await;
    peer.read_packet().await;
    peer.write_packet(b"response").await;

    let mut kinds = 0;
    while kinds < 3 {
        let event = events.next().await;
        assert_ne!(
            event.thread(),
            sender_thread,
            "callback ran on the caller's thread: {event:?}"
        );
        // One of each kind proves it holds for all three callbacks.
        match event {
            harness::Event::Send(..) | harness::Event::Receive(..) => kinds += 1,
            harness::Event::Connect(_, _, ConnectState::Connected, _) => kinds += 1,
            _ => {}
        }
    }
}

/// The C++ tolerates a slow handler — it logs past 100 ms and carries on. A
/// handler that blocks must therefore not stall the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocking_handler_does_not_stall_the_service() {
    let (dialer, control) = MockDialer::new(64 * 1024);
    let (recorder, mut events) = Recorder::new();
    *recorder.delay.lock().expect("delay poisoned") = Some(Duration::from_millis(20));
    let svc = PacketSvc::start_as_client_with(dialer, recorder, SvcConfig::default());

    for i in 0..8u8 {
        assert_eq!(
            svc.send(Arc::new(Packet::to_server(addr(7000), vec![i])), TIMEOUT),
            TxRxStatus::Success
        );
    }

    // The packets go out while the handler is still working through its queue.
    let mut peer = control.accept().await;
    let got = peer.read_packets(8).await;
    assert_eq!(got, (0..8u8).map(|i| vec![i]).collect::<Vec<_>>());

    for _ in 0..8 {
        assert_eq!(events.next_send().await.1, TxRxStatus::Success);
    }
}

/// The whole stack over loopback TCP: a client service's request arrives on the
/// server service, and the server's answer goes back down the *accepted*
/// connection — the request/response asymmetry the engine is built on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_and_a_response_travel_over_real_tcp() {
    let (server_handler, mut server_events) = Recorder::new();
    let server = PacketSvc::start_as_server(
        0,
        server_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    )
    .expect("bind");
    let server_addr = server.local_addr();

    let (client_handler, mut client_events) = Recorder::new();
    let client = PacketSvc::start_as_client(
        client_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    );

    assert_eq!(
        client.send(
            Arc::new(Packet::to_server(server_addr, b"request".to_vec())),
            TIMEOUT
        ),
        TxRxStatus::Success
    );
    assert_eq!(client_events.next_send().await.1, TxRxStatus::Success);

    let request = server_events.next_receive().await;
    assert_eq!(request.payload, b"request");
    assert_eq!(request.server, server_addr);

    // Answering means sending to the client address the packet was stamped
    // with; there is a connection for it because the client opened one.
    assert_eq!(
        server.send(
            Arc::new(Packet::to_client(request.client, b"response".to_vec())),
            TIMEOUT
        ),
        TxRxStatus::Success
    );
    assert_eq!(server_events.next_send().await.1, TxRxStatus::Success);

    let response = client_events.next_receive().await;
    assert_eq!(response.payload, b"response");
    assert_eq!(response.server, server_addr);
}

/// A server has nothing to send on until a client connects, and once that
/// client goes away the entry goes with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_forgets_a_client_that_disconnects() {
    let (server_handler, mut server_events) = Recorder::new();
    let server = PacketSvc::start_as_server(
        0,
        server_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    )
    .expect("bind");
    let server_addr = server.local_addr();

    let (client_handler, _client_events) = Recorder::new();
    let client = PacketSvc::start_as_client(
        client_handler,
        SvcConfig {
            bind_ip: Ipv4Addr::LOCALHOST,
            ..SvcConfig::default()
        },
    );
    client.send(
        Arc::new(Packet::to_server(server_addr, b"hi".to_vec())),
        TIMEOUT,
    );

    let request = server_events.next_receive().await;
    let peer = request.client;
    assert_eq!(server.connections(), vec![peer]);

    client.stop();
    assert_eq!(
        server_events
            .next_connect_where(ConnectState::DisConnected)
            .await,
        ConnectState::DisConnected
    );
    // The table entry is dropped with the connection, so a later answer is
    // refused rather than queued forever.
    for _ in 0..100 {
        if server.connections().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(server.connections().is_empty());
    assert_eq!(
        server.send(Arc::new(Packet::to_client(peer, vec![1])), TIMEOUT),
        TxRxStatus::NoConnection
    );
}
