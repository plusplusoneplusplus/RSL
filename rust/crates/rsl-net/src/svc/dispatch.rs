//! The callback pump.
//!
//! Every handler callback goes through one bounded queue drained by one
//! dedicated OS thread. That buys three properties the C++ has for free (or
//! pays for with its try-lock retry maze) and which the rest of this module
//! then relies on:
//!
//! * **Never on the caller's stack** — `NetPacketSvc.h:208`. A handler that
//!   calls back into the service (`send`, `close_connection`, `stop`) cannot
//!   deadlock or recurse into the connection actor.
//! * **Blocking is allowed** — it is a plain thread, not a runtime worker, so a
//!   slow handler cannot stall the reactor. The C++ tolerates slow handlers and
//!   merely logs past `MAX_CALLBACK_DELAY`; so do we.
//! * **Backpressure** — the queue is bounded, so a slow handler eventually
//!   stops the connection reader from consuming the socket and TCP's window
//!   does the rest, matching the C++'s inline `ProcessReceive`.
//!
//! No lock is ever held across a dispatch, which is the whole reason the C++
//! needs `MUTEX_TRY_LOCK` + `ScheduleSendRetry` (`NetPacketSvc.cpp:262-289`)
//! and we do not.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread::JoinHandle;

use tokio::sync::mpsc;

use super::handler::{ConnectState, Packet, PacketHandler, TxRxStatus, MAX_CALLBACK_DELAY};

/// How many callbacks may be queued before producers start waiting. Large
/// enough that a handler doing normal work never sees it, small enough that a
/// wedged handler bounds memory instead of growing without limit.
const QUEUE_DEPTH: usize = 1024;

/// One queued callback.
pub(crate) enum Callback {
    Send(Arc<Packet>, TxRxStatus),
    Receive(Arc<Packet>),
    Connect(Ipv4Addr, u16, ConnectState),
}

/// The producer end. Cloned into every connection actor.
pub(crate) type Sender = mpsc::Sender<Callback>;

/// Where the pump runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackMode {
    /// A dedicated OS thread. The default, and the only mode that reproduces
    /// the C++'s tolerance of a handler that blocks.
    Thread,
    /// A task on the service's runtime. Cheaper by one thread, but a handler
    /// that blocks now stalls a runtime worker — only pick this if every
    /// callback returns promptly.
    ///
    /// It is also what makes `tokio::time::pause()` usable: with the pump on a
    /// foreign thread, a test awaiting a callback leaves the runtime idle and
    /// the paused clock auto-advances underneath it.
    Task,
}

/// Owns the pump; on drop, releases its sender so the pump drains what is
/// queued and exits.
pub(crate) struct Dispatcher {
    tx: Option<Sender>,
    #[allow(dead_code)]
    thread: Option<JoinHandle<()>>,
}

impl Dispatcher {
    pub(crate) fn start(
        handler: Arc<dyn PacketHandler>,
        mode: CallbackMode,
        runtime: &tokio::runtime::Handle,
    ) -> Dispatcher {
        let (tx, mut rx) = mpsc::channel(QUEUE_DEPTH);
        let thread = match mode {
            CallbackMode::Thread => Some(
                std::thread::Builder::new()
                    .name("rsl-net-callbacks".to_string())
                    .spawn(move || {
                        // `blocking_recv` is the supported way to drive a tokio
                        // channel from a non-async thread; it parks, not spins.
                        while let Some(cb) = rx.blocking_recv() {
                            run(handler.as_ref(), cb);
                        }
                    })
                    .expect("spawn callback thread"),
            ),
            CallbackMode::Task => {
                runtime.spawn(async move {
                    while let Some(cb) = rx.recv().await {
                        run(handler.as_ref(), cb);
                    }
                });
                None
            }
        };
        Dispatcher {
            tx: Some(tx),
            thread,
        }
    }

    pub(crate) fn sender(&self) -> Sender {
        self.tx
            .clone()
            .expect("dispatcher sender taken only on drop")
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        // Release our sender; the pump ends once every connection actor has
        // released its own, having first drained whatever is queued.
        //
        // Deliberately *not* joined. This drop runs wherever the last reference
        // to the service lands — often a runtime worker, or the runtime's own
        // shutdown — and the senders we would be waiting on live in tasks that
        // same shutdown is responsible for dropping. Joining here deadlocks
        // against it. Callbacks already queued are still delivered, up to the
        // point the process itself goes away.
        self.tx = None;
    }
}

fn run(handler: &dyn PacketHandler, cb: Callback) {
    let start = std::time::Instant::now();
    let kind = match cb {
        Callback::Send(packet, status) => {
            handler.process_send(&packet, status);
            "process_send"
        }
        Callback::Receive(packet) => {
            handler.process_receive(packet);
            "process_receive"
        }
        Callback::Connect(ip, port, state) => {
            handler.process_connect(ip, port, state);
            "process_connect"
        }
    };
    let elapsed = start.elapsed();
    if elapsed > MAX_CALLBACK_DELAY {
        handler.slow_callback(kind, elapsed);
    }
}
