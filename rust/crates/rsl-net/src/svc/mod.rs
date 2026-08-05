//! `PacketSvc` — the packet transport, on tokio.
//!
//! This is the replacement for `NetPacketSvc` + `NetCxn` + the IOCP
//! `NetProcessor` (`src/NetworkLib/`). The framing comes from
//! [`crate::framing::packet`]; what lives here is the *behaviour* the RSL
//! engine depends on, reproduced decision for decision:
//!
//! * A **server** service listens and only ever talks back on connections its
//!   peers opened; a **client** service dials lazily on the first packet. The
//!   engine runs one of each (`legislator.cpp:6374-6384`), which is why
//!   requests always travel over the dialed connection and responses over the
//!   accepted one.
//! * Every accepted packet gets **exactly one** [`TxRxStatus`] through
//!   [`PacketHandler::process_send`], and every rejected one gets none — the
//!   status is [`send`](PacketSvc::send)'s return value instead.
//! * A client's send queue **survives a disconnect**. Packets leave it only on
//!   success or on their own deadline, so a peer that bounces does not lose
//!   traffic. `set_fail_packets_on_disconnect(true)` opts out, exactly as in
//!   the C++.
//! * Callbacks never run on the caller's stack (see [`dispatch`]).
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::net::{Ipv4Addr, SocketAddrV4};
//! # use std::time::Duration;
//! # use rsl_net::svc::*;
//! # struct H;
//! # impl PacketHandler for H {
//! #     fn process_send(&self, _: &Arc<Packet>, _: TxRxStatus) {}
//! #     fn process_receive(&self, _: Arc<Packet>) {}
//! # }
//! # async fn example() -> std::io::Result<()> {
//! let client = PacketSvc::start_as_client(Arc::new(H), SvcConfig::default());
//! let peer = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7000);
//! let status = client.send(
//!     Arc::new(Packet::to_server(peer, marshaled_message())),
//!     Duration::from_secs(5),
//! );
//! assert_eq!(status, TxRxStatus::Success); // a callback will follow
//! # Ok(())
//! # }
//! # fn marshaled_message() -> Vec<u8> { Vec::new() }
//! ```
//!
//! # Deliberate divergences from the C++
//!
//! All of them are invisible on the wire; each is here because the original
//! behaviour is either unsafe or an artifact of the IOCP design.
//!
//! * **Reconnect backoff.** A flat 20 ms retry becomes exponential-with-jitter
//!   — see [`BackoffConfig`].
//! * **Timeouts are exact.** The C++ sweeps a sorted timeout queue every 20 ms,
//!   so a packet can be failed up to 20 ms late; here each packet has its own
//!   deadline.
//! * **`ProcessConnect(Connecting)` is not on the caller's stack.** The C++
//!   documents that it may be (`NetPacketSvc.h:104`); every callback here goes
//!   through the callback thread. Strictly safer, and nothing in the engine
//!   depends on the synchronous ordering.
//! * **A packet handed to a connection that is closing gets a callback, not a
//!   synchronous status.** `NetCxn::EnqueuePacket` can return `TxNoConnection`
//!   inline in a race the C++ documents at length (`NetPacketSvc.h:252-266`);
//!   [`send`](PacketSvc::send) resolves that race through the queue instead, so
//!   the packet is failed by callback. Both are legal outcomes for the same
//!   packet in the C++ depending on which side won the lock.
//! * **`send_on_existing` is strict.** The C++ enqueues such a packet anyway if
//!   the queue is non-empty, on the grounds that a reconnect is imminent
//!   (`NetCxn.cpp:71-77`); here "existing" means connected. The engine never
//!   uses this flag.
//! * **Bounded reads** — inherited from Phase 4a, see the crate docs.

mod conn;
mod dispatch;
pub mod transport;

mod handler;

pub use dispatch::CallbackMode;
pub use handler::{
    ConnectState, Packet, PacketHandler, TxRxStatus, MAX_CALLBACK_DELAY, UNSPECIFIED,
};
pub use transport::{BackoffConfig, Dialer, Link, Stream, TcpDialer};

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use conn::{Conn, ConnHandle, Ctx};
use dispatch::Dispatcher;
use transport::BackoffConfig as Backoff;

use crate::framing::packet::HDR_LEN;
use crate::limits::Limits;

/// Knobs a service is started with.
#[derive(Clone, Copy, Debug)]
pub struct SvcConfig {
    /// Per-connection read chunk — `NetPacketSvc(readBufferSize)`. The engine
    /// passes 32 KiB (`legislator.cpp:6374`). Must be at least
    /// [`HDR_LEN`](crate::framing::packet::HDR_LEN), as the C++ `LogAssert`s.
    pub read_buffer_size: usize,
    /// The received-frame size cap (`PacketFactory`'s `m_MaxPacketSize`).
    pub limits: Limits,
    /// Local address to bind outgoing connections and the listener to —
    /// `NetPacketSvc::m_BindIp`. `0.0.0.0` means "any".
    pub bind_ip: Ipv4Addr,
    /// `SetFailPacketsOnDisconnect` (`NetPacketSvc.cpp:407`). When `true` a
    /// client fails queued packets on disconnect instead of reconnecting.
    pub fail_on_disconnect: bool,
    /// Reconnect pacing — this port's one behavioural improvement.
    pub backoff: BackoffConfig,
    /// Where handler callbacks run. Leave at [`CallbackMode::Thread`] unless
    /// every callback is known to return promptly.
    pub callbacks: CallbackMode,
}

impl Default for SvcConfig {
    fn default() -> SvcConfig {
        SvcConfig {
            read_buffer_size: 32 * 1024,
            limits: Limits::default(),
            bind_ip: Ipv4Addr::UNSPECIFIED,
            fail_on_disconnect: false,
            backoff: BackoffConfig::default(),
            callbacks: CallbackMode::Thread,
        }
    }
}

/// Shared service state. Connection actors hold this; the public
/// [`PacketSvc`] is a handle to it.
pub(crate) struct Svc {
    is_server: bool,
    limits: Limits,
    read_buffer_size: usize,
    backoff: Backoff,
    dialer: Arc<dyn Dialer>,
    runtime: tokio::runtime::Handle,

    stopped: AtomicBool,
    fail_on_disconnect: AtomicBool,
    suspend: watch::Sender<bool>,

    cxns: Mutex<HashMap<SocketAddrV4, ConnHandle>>,
    next_ctx_id: AtomicU64,
    next_generation: AtomicU64,

    local_addr: SocketAddrV4,
    acceptor: Mutex<Option<JoinHandle<()>>>,

    // Dropped last: joins the callback thread once every connection actor has
    // released its sender, so nothing queued is lost.
    dispatcher: Dispatcher,
}

impl Svc {
    pub(crate) fn callbacks(&self) -> dispatch::Sender {
        self.dispatcher.sender()
    }

    pub(crate) fn suspend_rx(&self) -> watch::Receiver<bool> {
        self.suspend.subscribe()
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    pub(crate) fn fail_on_disconnect(&self) -> bool {
        self.fail_on_disconnect.load(Ordering::Acquire)
    }

    /// Remove a finished connection, unless a successor for the same address
    /// has already taken its place.
    pub(crate) fn unregister(&self, remote: SocketAddrV4, generation: u64) {
        let mut table = self.cxns.lock().expect("connection table poisoned");
        if table
            .get(&remote)
            .is_some_and(|h| h.generation == generation)
        {
            table.remove(&remote);
        }
    }
}

/// A packet client or server. Dropping it stops the service.
pub struct PacketSvc {
    inner: Arc<Svc>,
}

impl PacketSvc {
    /// Start in **client** mode (`NetPacketSvc::StartAsClient`): no listener,
    /// connections are dialed lazily on the first packet to an address.
    ///
    /// Must be called from within a Tokio runtime.
    pub fn start_as_client(handler: Arc<dyn PacketHandler>, config: SvcConfig) -> PacketSvc {
        let dialer = Arc::new(TcpDialer {
            bind_ip: config.bind_ip,
        });
        PacketSvc::start_as_client_with(dialer, handler, config)
    }

    /// Client mode over a caller-supplied [`Dialer`] — TLS in Phase 4d, an
    /// in-process `tokio::io::duplex` pair in the contract tests.
    pub fn start_as_client_with(
        dialer: Arc<dyn Dialer>,
        handler: Arc<dyn PacketHandler>,
        config: SvcConfig,
    ) -> PacketSvc {
        PacketSvc {
            inner: Svc::new(false, dialer, handler, config, UNSPECIFIED, None),
        }
    }

    /// Start in **server** mode (`NetPacketSvc::StartAsServer`): bind `port`,
    /// accept connections, and send only on connections a peer opened.
    ///
    /// Must be called from within a Tokio runtime. Pass port 0 for an ephemeral
    /// port and read it back with [`local_addr`](PacketSvc::local_addr).
    pub fn start_as_server(
        port: u16,
        handler: Arc<dyn PacketHandler>,
        config: SvcConfig,
    ) -> io::Result<PacketSvc> {
        let listener = std::net::TcpListener::bind(SocketAddrV4::new(config.bind_ip, port))?;
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let local = transport::v4(listener.local_addr()?);

        let svc = PacketSvc::start_as_server_detached(local, handler, config);
        let inner = svc.inner.clone();
        let task = inner.runtime.spawn(accept_loop(inner.clone(), listener));
        *svc.inner.acceptor.lock().expect("acceptor poisoned") = Some(task);
        Ok(svc)
    }

    /// Server semantics without a listener: connections are handed in with
    /// [`attach`](PacketSvc::attach).
    ///
    /// This is how the contract tests drive the server side over
    /// `tokio::io::duplex`, and how Phase 4d will front the service with a TLS
    /// acceptor — the C++ does the same thing by swapping `NetCxn` for
    /// `NetSslCxn` under the acceptor (`PacketUtil.cpp:356`).
    pub fn start_as_server_detached(
        local: SocketAddrV4,
        handler: Arc<dyn PacketHandler>,
        config: SvcConfig,
    ) -> PacketSvc {
        let dialer = Arc::new(TcpDialer {
            bind_ip: config.bind_ip,
        });
        PacketSvc {
            inner: Svc::new(true, dialer, handler, config, local, None),
        }
    }

    /// Take over an accepted connection — `NetServerAcceptor::HandleEvent`
    /// (`PacketUtil.cpp:334`).
    ///
    /// Returns `false` and drops `link` when a connection from the same
    /// `(ip, port)` already exists ("Duplicate Connection", `PacketUtil.cpp:349`)
    /// or the service is stopped.
    pub fn attach(&self, link: Link) -> bool {
        self.inner.attach(link)
    }

    /// Send a packet, with a deadline `timeout` from now
    /// (`NetPacketSvc::Send`, `NetPacketSvc.cpp:237`).
    ///
    /// * [`TxRxStatus::Success`] — accepted; **exactly one**
    ///   [`PacketHandler::process_send`] callback will follow, with the real
    ///   outcome.
    /// * [`TxRxStatus::NoConnection`] — server only: no connection to that
    ///   client. No callback follows.
    /// * [`TxRxStatus::Abort`] — the service is stopped. No callback follows.
    ///
    /// A client service always accepts: if there is no connection it makes one,
    /// which is why the engine asserts `TxSuccess` on the client path
    /// (`legislator.cpp:4646`).
    ///
    /// Call from within the runtime: the deadline is taken from tokio's clock
    /// and a new connection is spawned on the current runtime.
    pub fn send(&self, packet: Arc<Packet>, timeout: Duration) -> TxRxStatus {
        self.send_with(packet, timeout, false)
    }

    /// `Send(packet, timeout, sendOnExisting)` — with `send_on_existing`, a
    /// client will not open a connection just for this packet.
    pub fn send_with(
        &self,
        packet: Arc<Packet>,
        timeout: Duration,
        send_on_existing: bool,
    ) -> TxRxStatus {
        self.inner.send(packet, timeout, send_on_existing)
    }

    /// Close the connection to `(ip, port)` if there is one
    /// (`NetPacketSvc::CloseConnection`, `NetPacketSvc.cpp:224`).
    ///
    /// Everything queued on it is called back with [`TxRxStatus::Abort`], on
    /// the callback thread — this call does not wait for that.
    pub fn close_connection(&self, ip: Ipv4Addr, port: u16) {
        let table = self.inner.cxns.lock().expect("connection table poisoned");
        if let Some(handle) = table.get(&SocketAddrV4::new(ip, port)) {
            handle.close(true);
        }
    }

    /// Stop delivering received packets (`SuspendReceive`,
    /// `NetPacketSvc.cpp:388`).
    ///
    /// Every connection stops consuming from its socket; buffered bytes and
    /// half-decoded packets are kept, and connections created while suspended
    /// inherit the state. Sends are unaffected.
    pub fn suspend_receive(&self) {
        // `send_replace`, not `send`: the value must stick even when no
        // connection exists yet, so the next one inherits it.
        self.inner.suspend.send_replace(true);
    }

    /// Resume delivery (`ResumeReceive`).
    pub fn resume_receive(&self) {
        self.inner.suspend.send_replace(false);
    }

    /// Whether receiving is currently suspended.
    pub fn is_receive_suspended(&self) -> bool {
        *self.inner.suspend.borrow()
    }

    /// `SetFailPacketsOnDisconnect` (`NetPacketSvc.cpp:407`). Client only: when
    /// `true`, queued packets are failed with [`TxRxStatus::NoConnection`] on a
    /// disconnect or failed dial instead of waiting for a reconnect.
    pub fn set_fail_packets_on_disconnect(&self, flag: bool) {
        self.inner.fail_on_disconnect.store(flag, Ordering::Release);
    }

    /// Stop the service (`NetPacketSvc::Stop`, `NetPacketSvc.cpp:152`).
    ///
    /// Stops accepting, closes every connection, and calls back every
    /// outstanding packet with [`TxRxStatus::Abort`]. Later sends return
    /// `TxAbort`. Like the C++, the caller is not called back on this stack —
    /// the aborts arrive on the callback thread.
    pub fn stop(&self) {
        if self.inner.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(task) = self
            .inner
            .acceptor
            .lock()
            .expect("acceptor poisoned")
            .take()
        {
            task.abort();
        }
        let table = self.inner.cxns.lock().expect("connection table poisoned");
        for handle in table.values() {
            handle.close(true);
        }
    }

    /// Whether [`stop`](PacketSvc::stop) has been called.
    pub fn is_stopped(&self) -> bool {
        self.inner.stopped()
    }

    /// The listening address (server), or `0.0.0.0:0` (client).
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.inner.local_addr
    }

    /// Remote addresses with a live connection entry. Test and diagnostic aid.
    pub fn connections(&self) -> Vec<SocketAddrV4> {
        self.inner
            .cxns
            .lock()
            .expect("connection table poisoned")
            .keys()
            .copied()
            .collect()
    }
}

impl Drop for PacketSvc {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Svc {
    #[allow(clippy::too_many_arguments)]
    fn new(
        is_server: bool,
        dialer: Arc<dyn Dialer>,
        handler: Arc<dyn PacketHandler>,
        config: SvcConfig,
        local_addr: SocketAddrV4,
        runtime: Option<tokio::runtime::Handle>,
    ) -> Arc<Svc> {
        assert!(
            config.read_buffer_size >= HDR_LEN,
            "read buffer must hold a packet header (LogAssert, NetPacketSvc.cpp:28)"
        );
        let runtime = runtime.unwrap_or_else(|| {
            tokio::runtime::Handle::try_current()
                .expect("PacketSvc must be started from within a Tokio runtime")
        });
        let (suspend, _) = watch::channel(false);
        let dispatcher = Dispatcher::start(handler, config.callbacks, &runtime);
        Arc::new(Svc {
            is_server,
            limits: config.limits,
            read_buffer_size: config.read_buffer_size,
            backoff: config.backoff,
            dialer,
            runtime,
            stopped: AtomicBool::new(false),
            fail_on_disconnect: AtomicBool::new(config.fail_on_disconnect),
            suspend,
            cxns: Mutex::new(HashMap::new()),
            next_ctx_id: AtomicU64::new(0),
            next_generation: AtomicU64::new(0),
            local_addr,
            acceptor: Mutex::new(None),
            dispatcher,
        })
    }

    fn send(
        self: &Arc<Self>,
        packet: Arc<Packet>,
        timeout: Duration,
        send_on_existing: bool,
    ) -> TxRxStatus {
        // `TxRxStatus status = (m_Stopped) ? TxAbort : TxNoConnection;`
        // (NetPacketSvc.cpp:338)
        if self.stopped() {
            return TxRxStatus::Abort;
        }
        let remote = packet.destination(self.is_server);
        let deadline = Instant::now() + timeout;

        let mut table = self.cxns.lock().expect("connection table poisoned");
        let mut packet = packet;
        if let Some(handle) = table.get(&remote) {
            // `NetCxn::EnqueuePacket` (NetCxn.cpp:69): a closed server
            // connection, or a send-on-existing to one, is refused inline.
            if !handle.is_connected() && (self.is_server || send_on_existing) {
                return TxRxStatus::NoConnection;
            }
            let ctx = Ctx::new(self.next_ctx_id(), packet, deadline);
            match handle.enqueue(ctx) {
                Ok(()) => return TxRxStatus::Success,
                // The actor finished between our lookup and this send, which
                // the table lock is meant to prevent; fall through and treat it
                // as if there had been no connection at all.
                Err(ctx) => {
                    table.remove(&remote);
                    packet = ctx.recall();
                }
            }
        }

        // Only a client opens a connection to send (NetPacketSvc.cpp:345).
        if self.is_server || send_on_existing {
            return TxRxStatus::NoConnection;
        }

        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let (conn, handle, rx) = Conn::create(self.clone(), remote, generation);
        let ctx = Ctx::new(self.next_ctx_id(), packet, deadline);
        handle
            .enqueue(ctx)
            .unwrap_or_else(|_| unreachable!("a fresh connection channel is open"));
        table.insert(remote, handle);
        drop(table);

        self.runtime.spawn(conn.run(rx, None));
        TxRxStatus::Success
    }

    fn next_ctx_id(&self) -> u64 {
        self.next_ctx_id.fetch_add(1, Ordering::Relaxed)
    }

    fn attach(self: &Arc<Self>, link: Link) -> bool {
        let remote = link.remote;
        let mut table = self.cxns.lock().expect("connection table poisoned");
        if self.stopped() || table.contains_key(&remote) {
            // `vc->IOClose(); return 0;` — the duplicate is dropped, the
            // original is kept (PacketUtil.cpp:349-354).
            return false;
        }
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let (conn, handle, rx) = Conn::create(self.clone(), remote, generation);
        table.insert(remote, handle);
        drop(table);

        self.runtime.spawn(conn.run(rx, Some(link)));
        true
    }
}

async fn accept_loop(svc: Arc<Svc>, listener: tokio::net::TcpListener) {
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(accepted) => accepted,
            // `NET_EVENT_ACCEPT_FAILED` is a `LogAssert(!"accept failed")` in
            // the C++. Transient errors (EMFILE, a peer that vanished between
            // the SYN and the accept) should not take the process down, so we
            // keep listening.
            Err(e) => {
                eprintln!("rsl-net: accept failed ({e})");
                if svc.stopped() {
                    return;
                }
                continue;
            }
        };
        if transport::configure(&stream).is_err() {
            continue;
        }
        let local = match stream.local_addr() {
            Ok(addr) => transport::v4(addr),
            Err(_) => continue,
        };
        let remote = transport::v4(remote);
        if !svc.attach(Link::new(stream, local, remote)) {
            eprintln!("rsl-net: duplicate connection from {remote} -- dropped");
        }
    }
}
