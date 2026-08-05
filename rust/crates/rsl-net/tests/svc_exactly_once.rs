//! The one property everything else rests on: **every packet the service
//! accepts gets exactly one `ProcessSend`, and every packet it refuses gets
//! none.**
//!
//! This is not a nicety. The engine counts outstanding sends per replica
//! (`m_numOutstanding`) and decrements on the callback; a packet that never
//! calls back leaks a slot forever, and one that calls back twice
//! double-decrements. Either way the replica eventually stops being sent to and
//! the cluster loses a voter — a Phase-5 liveness bug whose root cause is here.
//!
//! Proptest drives random sequences of sends, peer deaths, dial failures,
//! closes and clock advances at a client service, then checks the invariant
//! over every packet in the run. Time is paused, so a case that covers minutes
//! of reconnect backoff costs microseconds.

mod harness;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;

use harness::{addr, settle, test_config, Event, MockControl, MockDialer, Peer, Recorder};
use rsl_net::svc::{Packet, PacketHandler, PacketSvc, TxRxStatus};

#[derive(Clone, Debug)]
enum Op {
    /// Send a packet with the given deadline.
    Send { tag: u8, timeout_ms: u16 },
    /// The peer crashes.
    KillPeer,
    /// The next `n` dials fail.
    FailDials(u8),
    /// Let the peer consume a packet, unblocking a stalled write.
    PeerReads,
    /// `close_connection` on the one address in play.
    Close,
    /// Let time pass, firing deadlines and reconnect timers.
    Advance { ms: u16 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (any::<u8>(), 1u16..400).prop_map(|(tag, timeout_ms)| Op::Send { tag, timeout_ms }),
        2 => Just(Op::KillPeer),
        2 => (0u8..3).prop_map(Op::FailDials),
        3 => Just(Op::PeerReads),
        1 => Just(Op::Close),
        4 => (0u16..500).prop_map(|ms| Op::Advance { ms }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn every_packet_is_called_back_exactly_once(ops in prop::collection::vec(op(), 1..14)) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("runtime");
        runtime.block_on(run(ops))?;
    }
}

async fn run(ops: Vec<Op>) -> Result<(), TestCaseError> {
    // A small duplex buffer so a packet can sit half-written and be caught by a
    // kill or a deadline; that is where double- and non-callbacks hide.
    let (dialer, control) = MockDialer::new(256);
    let (recorder, mut events) = Recorder::new();
    let handler: Arc<dyn PacketHandler> = recorder;
    let svc = PacketSvc::start_as_client_with(dialer, handler, test_config());
    let peer_addr = addr(7000);

    let mut peer: Option<Peer> = None;
    // Packets the service took responsibility for. Identified by a serial
    // number in the payload rather than by address, so a freed packet's
    // allocation being reused cannot be mistaken for a duplicate.
    let mut accepted: HashSet<u32> = HashSet::new();
    let mut serial: u32 = 0;

    for op in ops {
        match op {
            Op::Send { tag, timeout_ms } => {
                let id = serial;
                serial += 1;
                let mut payload = vec![tag; 400];
                payload[..4].copy_from_slice(&id.to_le_bytes());
                let packet = Arc::new(Packet::to_server(peer_addr, payload));
                let status = svc.send(packet, Duration::from_millis(timeout_ms.into()));
                match status {
                    TxRxStatus::Success => {
                        prop_assert!(accepted.insert(id), "serial numbers are unique");
                    }
                    // A client only ever refuses when stopped, which this run
                    // never does mid-way.
                    other => prop_assert_eq!(other, TxRxStatus::Abort),
                }
            }
            Op::KillPeer => {
                peer = None;
            }
            Op::FailDials(n) => control.fail_next(n.into()),
            Op::PeerReads => {
                refresh(&control, &mut peer);
                if let Some(peer) = peer.as_mut() {
                    // Bounded so a peer with nothing to read cannot hang the
                    // case; under a paused clock this costs no wall time.
                    let _ = tokio::time::timeout(Duration::from_millis(50), peer.try_read_packet())
                        .await;
                }
            }
            Op::Close => svc.close_connection(*peer_addr.ip(), peer_addr.port()),
            Op::Advance { ms } => tokio::time::advance(Duration::from_millis(ms.into())).await,
        }
        settle().await;
        refresh(&control, &mut peer);
    }

    // Shut down and let every outstanding packet reach its callback.
    drop(peer);
    svc.stop();
    drop(svc);

    let mut called_back: HashSet<u32> = HashSet::new();
    let drain = async {
        while called_back.len() < accepted.len() {
            match events.recv().await {
                Some(Event::Send(packet, _, _)) => {
                    let id = u32::from_le_bytes(
                        packet.payload[..4]
                            .try_into()
                            .expect("payload carries its serial"),
                    );
                    prop_assert!(called_back.insert(id), "a packet was called back twice");
                    prop_assert!(
                        accepted.contains(&id),
                        "a packet the service refused was called back anyway"
                    );
                }
                Some(_) => {}
                None => break,
            }
        }
        Ok(())
    };
    // Paused time means a genuine leak shows up as this deadline firing rather
    // than as a hung test.
    tokio::time::timeout(Duration::from_secs(3600), drain)
        .await
        .map_err(|_| TestCaseError::fail("a packet never got its callback"))??;

    prop_assert_eq!(
        called_back.len(),
        accepted.len(),
        "not every accepted packet was called back"
    );
    Ok(())
}

/// Pick up a connection the service opened since we last looked.
fn refresh(control: &MockControl, peer: &mut Option<Peer>) {
    if let Some(fresh) = control.try_accept() {
        *peer = Some(fresh);
    }
}
