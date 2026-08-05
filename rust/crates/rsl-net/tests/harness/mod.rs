//! Scaffolding for the Phase-4b transport tests: a recording handler, an
//! in-process dialer over `tokio::io::duplex`, and a peer that speaks the
//! framing by hand.
//!
//! Nothing here touches a real socket, so the whole contract matrix runs under
//! `tokio::time::pause()` and finishes in milliseconds regardless of the
//! timeouts and backoffs it exercises.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, Notify};

use rsl_net::framing::packet;
use rsl_net::svc::{
    CallbackMode, ConnectState, Dialer, Link, Packet, PacketHandler, SvcConfig, TxRxStatus,
};
use rsl_net::Limits;

pub fn addr(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

/// Config for a deterministic test: callbacks on a runtime task so the paused
/// clock cannot auto-advance while a test waits for one.
pub fn test_config() -> SvcConfig {
    SvcConfig {
        callbacks: CallbackMode::Task,
        ..SvcConfig::default()
    }
}

// ---------------------------------------------------------------- the handler

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Send(Arc<Packet>, TxRxStatus, ThreadId),
    Receive(Arc<Packet>, ThreadId),
    Connect(Ipv4Addr, u16, ConnectState, ThreadId),
}

impl Event {
    pub fn status(&self) -> Option<TxRxStatus> {
        match self {
            Event::Send(_, status, _) => Some(*status),
            _ => None,
        }
    }

    pub fn state(&self) -> Option<ConnectState> {
        match self {
            Event::Connect(_, _, state, _) => Some(*state),
            _ => None,
        }
    }

    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Event::Send(p, _, _) | Event::Receive(p, _) => Some(&p.payload),
            _ => None,
        }
    }

    pub fn thread(&self) -> ThreadId {
        match self {
            Event::Send(_, _, t) | Event::Receive(_, t) | Event::Connect(_, _, _, t) => *t,
        }
    }
}

/// A handler that records everything, so a test can assert on the exact
/// sequence a real handler would have seen.
pub struct Recorder {
    tx: mpsc::UnboundedSender<Event>,
    /// Set to make every callback block for this long — used to prove a slow
    /// handler cannot stall the service.
    pub delay: Mutex<Option<Duration>>,
}

impl Recorder {
    pub fn new() -> (Arc<Recorder>, Events) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Recorder {
                tx,
                delay: Mutex::new(None),
            }),
            Events {
                rx,
                buffered: VecDeque::new(),
                seen: Vec::new(),
            },
        )
    }

    fn record(&self, event: Event) {
        if let Some(delay) = *self.delay.lock().expect("delay poisoned") {
            std::thread::sleep(delay);
        }
        let _ = self.tx.send(event);
    }
}

impl PacketHandler for Recorder {
    fn process_send(&self, packet: &Arc<Packet>, status: TxRxStatus) {
        self.record(Event::Send(
            packet.clone(),
            status,
            std::thread::current().id(),
        ));
    }

    fn process_receive(&self, packet: Arc<Packet>) {
        self.record(Event::Receive(packet, std::thread::current().id()));
    }

    fn process_connect(&self, ip: Ipv4Addr, port: u16, state: ConnectState) {
        self.record(Event::Connect(ip, port, state, std::thread::current().id()));
    }

    fn slow_callback(&self, _kind: &str, _elapsed: Duration) {}
}

/// The receiving end of a [`Recorder`].
pub struct Events {
    rx: mpsc::UnboundedReceiver<Event>,
    /// Events pulled off the channel while looking for a different one.
    buffered: VecDeque<Event>,
    seen: Vec<Event>,
}

impl Events {
    /// The next event of any kind.
    pub async fn next(&mut self) -> Event {
        self.recv().await.expect("service dropped its handler")
    }

    /// The next event, or `None` once the service is gone and its queue has
    /// drained.
    pub async fn recv(&mut self) -> Option<Event> {
        if let Some(event) = self.buffered.pop_front() {
            return Some(event);
        }
        let event = self.rx.recv().await?;
        self.seen.push(event.clone());
        Some(event)
    }

    /// The next event matching `pred`; anything before it is buffered so a
    /// later assertion can still see it.
    pub async fn next_where(&mut self, pred: impl Fn(&Event) -> bool) -> Event {
        let mut skipped = VecDeque::new();
        let found = loop {
            let event = self.next().await;
            if pred(&event) {
                break event;
            }
            skipped.push_back(event);
        };
        while let Some(event) = skipped.pop_back() {
            self.buffered.push_front(event);
        }
        found
    }

    pub async fn next_send(&mut self) -> (Arc<Packet>, TxRxStatus) {
        match self.next_where(|e| matches!(e, Event::Send(..))).await {
            Event::Send(packet, status, _) => (packet, status),
            _ => unreachable!(),
        }
    }

    pub async fn next_receive(&mut self) -> Arc<Packet> {
        match self.next_where(|e| matches!(e, Event::Receive(..))).await {
            Event::Receive(packet, _) => packet,
            _ => unreachable!(),
        }
    }

    /// The next `ProcessConnect` reporting exactly `want`.
    pub async fn next_connect_where(&mut self, want: ConnectState) -> ConnectState {
        match self
            .next_where(|e| matches!(e, Event::Connect(_, _, state, _) if *state == want))
            .await
        {
            Event::Connect(_, _, state, _) => state,
            _ => unreachable!(),
        }
    }

    pub async fn next_connect(&mut self) -> ConnectState {
        match self.next_where(|e| matches!(e, Event::Connect(..))).await {
            Event::Connect(_, _, state, _) => state,
            _ => unreachable!(),
        }
    }

    /// Everything already delivered, without waiting.
    pub fn drain(&mut self) -> Vec<Event> {
        let mut out: Vec<Event> = self.buffered.drain(..).collect();
        while let Ok(event) = self.rx.try_recv() {
            self.seen.push(event.clone());
            out.push(event);
        }
        out
    }

    /// Assert nothing has arrived. Only meaningful right after an `await` that
    /// gave the service a chance to run.
    pub fn assert_quiet(&mut self) {
        let extra = self.drain();
        assert!(extra.is_empty(), "unexpected callbacks: {extra:?}");
    }

    /// Assert no callback of a given kind has arrived, keeping the others for
    /// later assertions.
    fn assert_none_where(&mut self, label: &str, pred: impl Fn(&Event) -> bool) {
        let seen = self.drain();
        let unexpected: Vec<_> = seen.iter().filter(|e| pred(e)).collect();
        assert!(unexpected.is_empty(), "unexpected {label}: {unexpected:?}");
        for event in seen.into_iter().rev() {
            self.buffered.push_front(event);
        }
    }

    pub fn assert_quiet_of_sends(&mut self) {
        self.assert_none_where("send callbacks", |e| matches!(e, Event::Send(..)));
    }

    pub fn assert_quiet_of_receives(&mut self) {
        self.assert_none_where("receive callbacks", |e| matches!(e, Event::Receive(..)));
    }

    /// Every event seen so far, in order.
    pub fn history(&self) -> &[Event] {
        &self.seen
    }
}

// ----------------------------------------------------------------- the dialer

/// A [`Dialer`] that hands back one end of a `duplex` pair and keeps the other
/// for the test.
pub struct MockDialer {
    state: Arc<MockState>,
}

struct MockState {
    capacity: usize,
    local: SocketAddrV4,
    fail_next: AtomicUsize,
    dials: AtomicUsize,
    peers: Mutex<VecDeque<DuplexStream>>,
    arrived: Notify,
}

impl MockDialer {
    /// `capacity` is the duplex buffer size: make it small to stall writes on a
    /// peer that is not reading.
    pub fn new(capacity: usize) -> (Arc<MockDialer>, MockControl) {
        let state = Arc::new(MockState {
            capacity,
            local: addr(40000),
            fail_next: AtomicUsize::new(0),
            dials: AtomicUsize::new(0),
            peers: Mutex::new(VecDeque::new()),
            arrived: Notify::new(),
        });
        (
            Arc::new(MockDialer {
                state: state.clone(),
            }),
            MockControl { state },
        )
    }
}

impl Dialer for MockDialer {
    fn dial(
        &self,
        remote: SocketAddrV4,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Link>> + Send + 'static>>
    {
        let state = self.state.clone();
        Box::pin(async move {
            state.dials.fetch_add(1, Ordering::SeqCst);
            if state
                .fail_next
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                state.arrived.notify_waiters();
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"));
            }
            let (ours, theirs) = tokio::io::duplex(state.capacity);
            state
                .peers
                .lock()
                .expect("peers poisoned")
                .push_back(theirs);
            state.arrived.notify_waiters();
            Ok(Link::new(ours, state.local, remote))
        })
    }
}

/// The test's side of a [`MockDialer`].
pub struct MockControl {
    state: Arc<MockState>,
}

impl MockControl {
    /// Make the next `n` dials fail with `ECONNREFUSED`.
    pub fn fail_next(&self, n: usize) {
        self.state.fail_next.store(n, Ordering::SeqCst);
    }

    pub fn dials(&self) -> usize {
        self.state.dials.load(Ordering::SeqCst)
    }

    /// Take a peer end if the service has already dialed one.
    pub fn try_accept(&self) -> Option<Peer> {
        self.state
            .peers
            .lock()
            .expect("peers poisoned")
            .pop_front()
            .map(Peer::new)
    }

    /// Wait for the next connection the service opens and take the peer end.
    pub async fn accept(&self) -> Peer {
        loop {
            // `enable()` registers before we look, so a dial landing between
            // the check and the await is not missed.
            let notified = self.state.arrived.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(stream) = self.state.peers.lock().expect("peers poisoned").pop_front() {
                return Peer::new(stream);
            }
            notified.await;
        }
    }
}

// ------------------------------------------------------------------- the peer

/// The far end of a connection, speaking the packet framing by hand.
pub struct Peer {
    stream: DuplexStream,
    buf: Vec<u8>,
}

impl Peer {
    pub fn new(stream: DuplexStream) -> Peer {
        Peer {
            stream,
            buf: Vec::new(),
        }
    }

    /// Read one whole packet's payload, or `None` if the connection closed
    /// first (which a randomized test expects to happen).
    pub async fn try_read_packet(&mut self) -> Option<Vec<u8>> {
        loop {
            let limits = Limits::default();
            match packet::decode_packet(&self.buf, &limits).expect("peer got a bad frame") {
                packet::Step::Packet { hdr, payload } => {
                    let payload = payload.to_vec();
                    self.buf.drain(..hdr.size as usize);
                    return Some(payload);
                }
                packet::Step::NeedMore { .. } => {
                    let mut chunk = [0u8; 4096];
                    let n = self.stream.read(&mut chunk).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    self.buf.extend_from_slice(&chunk[..n]);
                }
            }
        }
    }

    /// Read one whole packet's payload.
    pub async fn read_packet(&mut self) -> Vec<u8> {
        loop {
            let limits = Limits::default();
            match packet::decode_packet(&self.buf, &limits).expect("peer got a bad frame") {
                packet::Step::Packet { hdr, payload } => {
                    let payload = payload.to_vec();
                    self.buf.drain(..hdr.size as usize);
                    return payload;
                }
                packet::Step::NeedMore { .. } => {
                    let mut chunk = [0u8; 4096];
                    let n = self
                        .stream
                        .read(&mut chunk)
                        .await
                        .expect("peer read failed");
                    assert!(n > 0, "connection closed mid-packet");
                    self.buf.extend_from_slice(&chunk[..n]);
                }
            }
        }
    }

    /// Read `n` packets.
    pub async fn read_packets(&mut self, n: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.read_packet().await);
        }
        out
    }

    pub async fn write_packet(&mut self, payload: &[u8]) {
        self.write_bytes(&packet::encode_packet(payload)).await;
    }

    pub async fn write_bytes(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("peer write");
        self.stream.flush().await.expect("peer flush");
    }

    /// Drop the connection, as a peer that crashed would.
    pub fn kill(self) {}

    /// Read whatever arrives until the connection closes.
    pub async fn read_to_end(&mut self) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.buf);
        let _ = self.stream.read_to_end(&mut out).await;
        out
    }
}

/// Give spawned tasks a chance to run without letting the paused clock jump.
pub async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}
