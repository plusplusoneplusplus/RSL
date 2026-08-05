//! One connection = one task.
//!
//! This is `NetCxn` (`src/NetworkLib/src/NetCxn.cpp`) without the IOCP event
//! machinery: a single actor owns the send queue and the connection state, a
//! reader task owns the read half, a writer task owns the write half. Nothing
//! shares a lock, so the C++'s try-lock-and-reschedule maze
//! (`NetPacketSvc::TrySend` → `ScheduleSendRetry` → `m_SendRetryQ`) has no
//! counterpart here: an `mpsc` queue is the retry queue, and it can never miss.
//!
//! The behaviour that *is* reproduced exactly:
//!
//! * **One packet in flight** (`ProcessQueuedPacketsForWrite`, `NetCxn.cpp:118`)
//!   and strict FIFO order per connection.
//! * **The client send queue survives a disconnect** (`NetCxn.cpp:400-406`): on
//!   a client, unless `fail_on_disconnect` is set, queued packets are *not*
//!   failed — the connection reconnects and sends them, and they leave the
//!   queue only on success or on their own deadline.
//! * **A timeout can fire mid-write** (`TimeoutHandler::EventTimeout`,
//!   `PacketUtil.cpp:186-215`): the packet is failed with `TxTimedOut`
//!   immediately, but the frame already handed to the socket is allowed to
//!   finish so the stream stays framed. The C++ duplicates the buffer for the
//!   same reason.
//! * **Exactly one `ProcessSend` per accepted packet.** [`Ctx`] carries a debug
//!   assertion that catches a leak at the point it happens: a packet dropped
//!   without a callback is what wedges the engine's `m_numOutstanding`
//!   accounting in Phase 5.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::dispatch::{self, Callback};
use super::handler::{ConnectState, Packet, TxRxStatus};
use super::transport::{Backoff, Link};
use super::Svc;
use crate::framing::packet;

/// A packet in flight through the service: `NetPacketCtx` (`PacketUtil.h:70`).
///
/// The `delivered` flag makes the exactly-once callback property checkable
/// rather than merely intended.
pub(crate) struct Ctx {
    pub(crate) id: u64,
    pub(crate) packet: Arc<Packet>,
    /// `ctx.m_Timeout = m_TimeoutH->m_Time + timeout` (`NetPacketSvc.cpp:249`).
    pub(crate) deadline: Instant,
    delivered: bool,
}

impl Ctx {
    pub(crate) fn new(id: u64, packet: Arc<Packet>, deadline: Instant) -> Ctx {
        Ctx {
            id,
            packet,
            deadline,
            delivered: false,
        }
    }

    /// Give the packet back without a callback. Only legal before the send path
    /// has told the caller its packet was accepted — the caller then produces
    /// the outcome as `send`'s return value instead, which is the same
    /// one-outcome-per-packet rule seen from the other side.
    pub(crate) fn recall(mut self) -> Arc<Packet> {
        self.delivered = true;
        self.packet.clone()
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        debug_assert!(
            self.delivered || std::thread::panicking(),
            "packet dropped without a ProcessSend callback — this is the leak \
             that wedges the engine's outstanding-send accounting"
        );
    }
}

/// What the service tells a connection to do.
pub(crate) enum ConnMsg {
    Send(Ctx),
    /// `NetCxn::CloseConnection(abort)`. `abort` distinguishes an explicit
    /// close/stop (`TxAbort`) from the transport going away (`TxNoConnection`).
    Close {
        abort: bool,
    },
}

/// The service's handle on a connection.
pub(crate) struct ConnHandle {
    /// Guards against removing a successor connection from the table when a
    /// predecessor for the same address finishes.
    pub(crate) generation: u64,
    tx: mpsc::UnboundedSender<ConnMsg>,
    connected: Arc<AtomicBool>,
}

impl ConnHandle {
    /// Whether the transport is up right now. Used by the send path to
    /// reproduce `NetCxn::EnqueuePacket`'s early `TxNoConnection`
    /// (`NetCxn.cpp:69-78`).
    pub(crate) fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Hand a packet to the connection. Fails (returning the packet) only if
    /// the actor has already finished, which the table lock makes impossible
    /// for a handle read out of the table.
    pub(crate) fn enqueue(&self, ctx: Ctx) -> Result<(), Ctx> {
        self.tx.send(ConnMsg::Send(ctx)).map_err(|e| match e.0 {
            ConnMsg::Send(ctx) => ctx,
            ConnMsg::Close { .. } => unreachable!("we just sent a Send"),
        })
    }

    pub(crate) fn close(&self, abort: bool) {
        let _ = self.tx.send(ConnMsg::Close { abort });
    }
}

/// Why the connected phase ended.
enum Disconnect {
    /// The peer, the transport, or a write error.
    Lost,
    /// `close_connection()` or `stop()`.
    Closed { abort: bool },
}

/// Why the connecting phase ended.
enum Connect {
    Established(Link),
    /// No further connection will be made: either the queue drained while we
    /// were down, or `fail_on_disconnect` told us not to retry. Whatever is
    /// still queued is failed by `finish`.
    Done,
    Closed {
        abort: bool,
    },
}

pub(crate) struct Conn {
    svc: Arc<Svc>,
    remote: SocketAddrV4,
    generation: u64,
    cb: dispatch::Sender,
    connected: Arc<AtomicBool>,
    sendq: VecDeque<Ctx>,
}

impl Conn {
    /// Create a connection and its handle. `run` must then be spawned with the
    /// returned receiver.
    pub(crate) fn create(
        svc: Arc<Svc>,
        remote: SocketAddrV4,
        generation: u64,
    ) -> (Conn, ConnHandle, mpsc::UnboundedReceiver<ConnMsg>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let connected = Arc::new(AtomicBool::new(false));
        let conn = Conn {
            cb: svc.callbacks(),
            svc,
            remote,
            generation,
            connected: connected.clone(),
            sendq: VecDeque::new(),
        };
        let handle = ConnHandle {
            generation,
            tx,
            connected,
        };
        (conn, handle, rx)
    }

    /// The connection's whole life. `first` is `Some` for an accepted server
    /// connection (the transport already exists) and `None` for a client one,
    /// which dials lazily.
    pub(crate) async fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<ConnMsg>,
        first: Option<Link>,
    ) {
        let mut backoff = Backoff::new(self.svc.backoff);
        let mut link = first;
        let mut aborted = false;

        loop {
            let established = match link.take() {
                Some(link) => link,
                None => match self.connect(&mut rx, &mut backoff).await {
                    Connect::Established(link) => {
                        backoff.reset();
                        link
                    }
                    Connect::Done => break,
                    Connect::Closed { abort } => {
                        aborted = abort;
                        break;
                    }
                },
            };

            match self.serve(&mut rx, established).await {
                Disconnect::Closed { abort } => {
                    aborted = abort;
                    break;
                }
                Disconnect::Lost => {
                    // `NetCxn::CloseConnection` (NetCxn.cpp:400): a server
                    // connection never reconnects, and neither does a client
                    // told to fail packets on disconnect — both flush the queue
                    // in `finish`. Otherwise the queue is kept and retried on a
                    // new connection, which is the behaviour the engine's
                    // retransmit-free design depends on.
                    if self.svc.is_server || self.svc.fail_on_disconnect() {
                        break;
                    }
                    // Whether there is anything left to reconnect *for* is
                    // decided by `connect`, which drains the inbox first.
                }
            }
        }

        self.finish(rx, aborted).await;
    }

    // ---------------------------------------------------------------- connect

    async fn connect(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<ConnMsg>,
        backoff: &mut Backoff,
    ) -> Connect {
        loop {
            // A packet accepted by `send` may still be in the inbox rather than
            // the queue; take everything before judging the queue empty.
            if let Some(abort) = self.drain_ready(rx) {
                self.emit(ConnectState::ConnectFailed).await;
                return Connect::Closed { abort };
            }
            // `NetCxn::CloseCleanup` (NetCxn.cpp:500): reconnect only while
            // there is something to send. An empty queue means the connection
            // is finished.
            if self.sendq.is_empty() {
                return Connect::Done;
            }
            if self.svc.stopped() {
                return Connect::Closed { abort: true };
            }

            self.emit(ConnectState::Connecting).await;

            // The dial runs in its own task so that servicing a control
            // message or a packet deadline cannot cancel it half-way.
            let (tx, mut dialed) = oneshot::channel();
            let dial = self.svc.dialer.dial(self.remote);
            tokio::spawn(async move {
                let _ = tx.send(dial.await);
            });

            let result = loop {
                let deadline = self.next_deadline();
                tokio::select! {
                    biased;
                    msg = rx.recv() => match msg {
                        Some(ConnMsg::Send(ctx)) => self.sendq.push_back(ctx),
                        Some(ConnMsg::Close { abort }) => {
                            // The transport never came up, so this is a failed
                            // connect from the handler's point of view
                            // (NetCxn.cpp:443).
                            self.emit(ConnectState::ConnectFailed).await;
                            return Connect::Closed { abort };
                        }
                        None => return Connect::Closed { abort: false },
                    },
                    result = &mut dialed => break result,
                    _ = sleep_until(deadline) => self.expire(Instant::now()).await,
                }
            };

            match result {
                // `Connected` is emitted by `serve`, which is `NetCxn::Start` —
                // the one place both a successful dial and an accepted socket
                // converge (NetCxn.cpp:550).
                Ok(Ok(link)) => return Connect::Established(link),
                Ok(Err(_)) | Err(_) => {
                    self.emit(ConnectState::ConnectFailed).await;
                    if self.svc.fail_on_disconnect() {
                        // `SetFailPacketsOnDisconnect(true)`: give up now
                        // rather than retry (NetCxn.cpp:587).
                        return Connect::Done;
                    }
                    let until = Instant::now() + backoff.next_delay();
                    if let Some(closed) = self.wait_until(rx, until).await {
                        return closed;
                    }
                }
            }
        }
    }

    /// Sleep until `until`, servicing control messages and deadlines. `Some` if
    /// the connection was closed while waiting.
    async fn wait_until(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<ConnMsg>,
        until: Instant,
    ) -> Option<Connect> {
        loop {
            if Instant::now() >= until {
                return None;
            }
            let deadline = Some(match self.next_deadline() {
                Some(d) => d.min(until),
                None => until,
            });
            tokio::select! {
                biased;
                msg = rx.recv() => match msg {
                    Some(ConnMsg::Send(ctx)) => self.sendq.push_back(ctx),
                    Some(ConnMsg::Close { abort }) => {
                        self.emit(ConnectState::ConnectFailed).await;
                        return Some(Connect::Closed { abort });
                    }
                    None => return Some(Connect::Closed { abort: false }),
                },
                _ = sleep_until(deadline) => {
                    self.expire(Instant::now()).await;
                    // Nothing left to reconnect for; let `connect` finish us.
                    if self.sendq.is_empty() {
                        return None;
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------- connected

    async fn serve(&mut self, rx: &mut mpsc::UnboundedReceiver<ConnMsg>, link: Link) -> Disconnect {
        let Link {
            stream,
            local,
            remote,
        } = link;
        // `NetCxn::Start` (NetCxn.cpp:540) — reached both by a client whose
        // dial succeeded and by a server that just accepted.
        self.connected.store(true, Ordering::Release);
        self.emit(ConnectState::Connected).await;
        let (read_half, write_half) = tokio::io::split(stream);

        // The reader owns the read half; its task ending (EOF, transport error,
        // or a framing reject) is the disconnect signal.
        let (reader_done_tx, mut reader_done) = oneshot::channel();
        let reader = tokio::spawn(read_loop(
            read_half,
            self.svc.clone(),
            self.cb.clone(),
            local,
            remote,
            reader_done_tx,
        ));

        // The writer owns the write half. Handing it whole frames — instead of
        // writing from the select loop — is what lets a deadline fire without
        // truncating a frame that is already on the wire.
        let (frame_tx, frame_rx) = mpsc::channel::<Vec<u8>>(1);
        let (written_tx, mut written) = mpsc::channel::<io::Result<()>>(1);
        let writer = tokio::spawn(write_loop(write_half, frame_rx, written_tx));

        // The id of the packet currently with the writer, if any.
        let mut writing: Option<u64> = None;

        let outcome = loop {
            // `ProcessQueuedPacketsForWrite`: only ever one packet in flight.
            if writing.is_none() {
                if let Some(ctx) = self.sendq.front() {
                    let frame = packet::encode_packet(&ctx.packet.payload);
                    writing = Some(ctx.id);
                    if frame_tx.send(frame).await.is_err() {
                        break Disconnect::Lost;
                    }
                }
            }

            let deadline = self.next_deadline();
            tokio::select! {
                biased;
                msg = rx.recv() => match msg {
                    Some(ConnMsg::Send(ctx)) => self.sendq.push_back(ctx),
                    Some(ConnMsg::Close { abort }) => break Disconnect::Closed { abort },
                    None => break Disconnect::Lost,
                },
                result = written.recv() => match result {
                    Some(Ok(())) => {
                        let id = writing.take();
                        // If the packet is no longer at the head, its deadline
                        // fired while the frame was on the wire and it has
                        // already been called back with TxTimedOut. The bytes
                        // still went out — same as the C++ letting the
                        // duplicated buffer's I/O complete.
                        if self.sendq.front().map(|c| c.id) == id {
                            let ctx = self.sendq.pop_front().expect("checked above");
                            self.deliver(ctx, TxRxStatus::Success).await;
                        }
                    }
                    _ => break Disconnect::Lost,
                },
                _ = &mut reader_done => break Disconnect::Lost,
                _ = sleep_until(deadline) => self.expire(Instant::now()).await,
            }
        };

        self.connected.store(false, Ordering::Release);
        reader.abort();
        drop(frame_tx);
        writer.abort();
        // `m_Vc` existed, so this is a disconnect and not a failed connect
        // (NetCxn.cpp:437).
        self.emit(ConnectState::DisConnected).await;
        outcome
    }

    // ----------------------------------------------------------------- common

    /// Fail every packet whose deadline has passed, wherever it sits in the
    /// queue — `TimeoutHandler::EventTimeout` (`PacketUtil.cpp:186`). The C++
    /// polls this every 20 ms; here each packet has its own deadline, so a
    /// timeout is exact instead of up to 20 ms late.
    async fn expire(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.sendq.len() {
            if self.sendq[i].deadline <= now {
                let ctx = self.sendq.remove(i).expect("index in range");
                self.deliver(ctx, TxRxStatus::TimedOut).await;
            } else {
                i += 1;
            }
        }
    }

    /// Move everything already in the inbox into the send queue, without
    /// waiting. `Some(abort)` if a close was queued behind the packets.
    fn drain_ready(&mut self, rx: &mut mpsc::UnboundedReceiver<ConnMsg>) -> Option<bool> {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                ConnMsg::Send(ctx) => self.sendq.push_back(ctx),
                ConnMsg::Close { abort } => return Some(abort),
            }
        }
        None
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.sendq.iter().map(|c| c.deadline).min()
    }

    /// The single place a packet's outcome is produced.
    async fn deliver(&self, mut ctx: Ctx, status: TxRxStatus) {
        ctx.delivered = true;
        let _ = self
            .cb
            .send(Callback::Send(ctx.packet.clone(), status))
            .await;
    }

    async fn emit(&self, state: ConnectState) {
        let _ = self
            .cb
            .send(Callback::Connect(
                *self.remote.ip(),
                self.remote.port(),
                state,
            ))
            .await;
    }

    /// Leave the table and call back everything still owed a status —
    /// `NetCxn::CloseCleanup` (`NetCxn.cpp:486-498`), whose
    /// `status = m_Abort ? TxAbort : TxNoConnection` this reproduces.
    async fn finish(mut self, mut rx: mpsc::UnboundedReceiver<ConnMsg>, aborted: bool) {
        // Unregister first, under the table lock, so no further packet can be
        // handed to us; then drain what the lock let through before that.
        self.svc.unregister(self.remote, self.generation);
        rx.close();

        let status = if aborted || self.svc.stopped() {
            TxRxStatus::Abort
        } else {
            TxRxStatus::NoConnection
        };

        while let Some(ctx) = self.sendq.pop_front() {
            self.deliver(ctx, status).await;
        }
        while let Ok(msg) = rx.try_recv() {
            if let ConnMsg::Send(ctx) = msg {
                self.deliver(ctx, status).await;
            }
        }
    }
}

/// `None` means "never" — used for the deadline branch of a `select!` when
/// there is nothing queued.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// `NetCxn::ReadReadyInternal` (`NetCxn.cpp:179`) as a task.
///
/// Ends — closing the connection — on EOF, a transport error, or a framing
/// reject. RSL never resynchronizes a stream, so a bad size or checksum is
/// fatal to the connection by design.
async fn read_loop(
    mut read_half: impl AsyncReadExt + Unpin,
    svc: Arc<Svc>,
    cb: dispatch::Sender,
    local: SocketAddrV4,
    remote: SocketAddrV4,
    _done: oneshot::Sender<()>,
) {
    let mut suspend = svc.suspend_rx();
    let mut buf: Vec<u8> = Vec::with_capacity(svc.read_buffer_size);

    loop {
        // `if (m_ReceiveSuspended) return;` — stop consuming from the socket
        // entirely. Whatever is already buffered, including a half-decoded
        // packet, is kept; TCP's window applies the backpressure.
        loop {
            if !*suspend.borrow_and_update() {
                break;
            }
            if suspend.changed().await.is_err() {
                return;
            }
        }

        // Drain every complete packet in the buffer — one read can carry many.
        let (payloads, consumed, rejected) = {
            let mut packets = packet::Packets::new(&buf, svc.limits);
            let mut payloads = Vec::new();
            let mut rejected = None;
            for item in packets.by_ref() {
                match item {
                    Ok((_, payload)) => payloads.push(payload.to_vec()),
                    Err(e) => {
                        rejected = Some(e);
                        break;
                    }
                }
            }
            (payloads, packets.consumed(), rejected)
        };
        buf.drain(..consumed);

        for payload in payloads {
            // `NetCxn.cpp:239-248`: the remote goes into the role-opposite
            // field and our own socket address into the other.
            let packet = if svc.is_server {
                Packet {
                    payload,
                    client: remote,
                    server: local,
                }
            } else {
                Packet {
                    payload,
                    client: local,
                    server: remote,
                }
            };
            if cb.send(Callback::Receive(Arc::new(packet))).await.is_err() {
                return;
            }
        }

        if let Some(e) = rejected {
            // The C++ logs "Invalid packet" with both addresses and closes.
            eprintln!("rsl-net: invalid packet from {remote} ({e}) -- closing connection");
            return;
        }

        let base = buf.len();
        buf.resize(base + svc.read_buffer_size, 0);
        match read_half.read(&mut buf[base..]).await {
            Ok(0) => {
                buf.truncate(base);
                return;
            }
            Ok(n) => buf.truncate(base + n),
            Err(_) => {
                buf.truncate(base);
                return;
            }
        }
    }
}

/// Writes whole frames, one at a time, and reports each outcome back to the
/// connection actor. Owning the write half here is what makes a mid-write
/// timeout safe: the actor can fail the packet without truncating the frame.
async fn write_loop(
    mut write_half: impl AsyncWriteExt + Unpin,
    mut frames: mpsc::Receiver<Vec<u8>>,
    written: mpsc::Sender<io::Result<()>>,
) {
    while let Some(frame) = frames.recv().await {
        let result = write_half.write_all(&frame).await;
        let failed = result.is_err();
        if written.send(result).await.is_err() || failed {
            return;
        }
    }
    let _ = write_half.shutdown().await;
}
