//! The application-facing contract: what a packet is, what the four send
//! statuses mean, and the handler the service calls back.
//!
//! Ported from `src/NetworkLib/inc/NetPacketSvc.h` (`TxRxStatus`, `SendHandler`,
//! `ReceiveHandler`, `ConnectHandler`) and the `Packet` address fields in
//! `src/NetworkLib/inc/NetPacket.h`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

/// The outcome of a send (`TxRxStatus`, `NetPacketSvc.h:38`).
///
/// Every packet accepted by [`PacketSvc::send`](super::PacketSvc::send)
/// produces **exactly one** of these through
/// [`PacketHandler::process_send`]. Phase 5's replica-failure accounting
/// branches on the value, so the mapping is part of the contract:
///
/// | Status | Means |
/// | --- | --- |
/// | [`Success`](TxRxStatus::Success) | the whole frame reached the socket |
/// | [`TimedOut`](TxRxStatus::TimedOut) | the per-packet deadline passed first. The frame may still be delivered — if it was mid-write the write is allowed to finish, exactly as the C++ duplicates the buffer and lets the I/O complete (`PacketUtil.cpp:198-204`) |
/// | [`NoConnection`](TxRxStatus::NoConnection) | there was no connection to send on, and none will be made |
/// | [`Abort`](TxRxStatus::Abort) | the service was stopped, or the connection was explicitly closed |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxRxStatus {
    /// `TxSuccess`.
    Success,
    /// `TxTimedOut`.
    TimedOut,
    /// `TxNoConnection`.
    NoConnection,
    /// `TxAbort`.
    Abort,
}

impl std::fmt::Display for TxRxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TxRxStatus::Success => "TxSuccess",
            TxRxStatus::TimedOut => "TxTimedOut",
            TxRxStatus::NoConnection => "TxNoConnection",
            TxRxStatus::Abort => "TxAbort",
        };
        f.write_str(s)
    }
}

/// Connection-state transitions (`ConnectHandler::ConnectState`,
/// `NetPacketSvc.h:93`).
///
/// A client connection sees all four; a server connection only ever sees
/// [`Connected`](ConnectState::Connected) and
/// [`DisConnected`](ConnectState::DisConnected).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectState {
    /// About to dial (client only).
    Connecting,
    /// The dial failed, or the connection was closed while dialing (client
    /// only).
    ConnectFailed,
    /// The connection is up.
    Connected,
    /// An established connection went away — peer, transport, or a local
    /// close.
    DisConnected,
}

/// A packet: a marshaled message plus the two addresses the C++ `Packet`
/// carries (`NetPacket.h`'s `m_ClientIp`/`m_ClientPort` and
/// `m_ServerIp`/`m_ServerPort`).
///
/// Which address is the destination depends on the service's role, exactly as
/// in `NetPacketSvc::Send` (`NetPacketSvc.cpp:252`): a **server** sends to the
/// client address, a **client** sends to the server address. On receive both
/// are stamped (`NetCxn.cpp:239-248`) — the remote end into the role-opposite
/// field, the local socket address into the other.
///
/// `payload` is the marshaled message *without* the 20-byte frame header; the
/// service frames it with [`crate::framing::packet::encode_packet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The marshaled message.
    pub payload: Vec<u8>,
    /// `m_ClientIp` / `m_ClientPort`.
    pub client: SocketAddrV4,
    /// `m_ServerIp` / `m_ServerPort`.
    pub server: SocketAddrV4,
}

/// `0.0.0.0:0` — the C++ `Packet`'s zero-initialized address fields.
pub const UNSPECIFIED: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);

impl Packet {
    /// A packet a **client** service sends to `server`.
    pub fn to_server(server: SocketAddrV4, payload: Vec<u8>) -> Packet {
        Packet {
            payload,
            client: UNSPECIFIED,
            server,
        }
    }

    /// A packet a **server** service sends to `client` (only deliverable on a
    /// connection that client already opened).
    pub fn to_client(client: SocketAddrV4, payload: Vec<u8>) -> Packet {
        Packet {
            payload,
            client,
            server: UNSPECIFIED,
        }
    }

    /// Where this packet goes, given the sending service's role
    /// (`NetPacketSvc.cpp:252-253`).
    pub fn destination(&self, is_server: bool) -> SocketAddrV4 {
        if is_server {
            self.client
        } else {
            self.server
        }
    }
}

/// The callbacks a service makes. One trait for what the C++ splits into
/// `SendHandler`, `ReceiveHandler` and `ConnectHandler` (the engine passes the
/// same object as all three — `legislator.cpp:6375`).
///
/// ## Task context
///
/// Every callback runs on the service's **dedicated callback thread**, never on
/// the caller's stack (`NetPacketSvc.h:208` — "The handler is never called on
/// the caller's call stack") and never on a runtime worker. Blocking is
/// therefore allowed: the C++ tolerates slow handlers and only logs when one
/// exceeds `NetProcessor::MAX_CALLBACK_DELAY` (100 ms), which
/// [`PacketHandler::slow_callback`] reproduces.
///
/// Callbacks are delivered in the order the service produced them, so a
/// handler sees `Connected` before the receives on that connection and
/// `DisConnected` before the resulting send failures. A slow handler applies
/// backpressure to the receive path (the reader stops consuming from the
/// socket, and TCP's window does the rest) — the same effect as the C++ calling
/// `ProcessReceive` inline on its I/O thread.
pub trait PacketHandler: Send + Sync + 'static {
    /// `SendHandler::ProcessSend`. Called exactly once for every packet that
    /// [`PacketSvc::send`](super::PacketSvc::send) accepted (i.e. returned
    /// [`TxRxStatus::Success`] for), and never for one it rejected.
    fn process_send(&self, packet: &Arc<Packet>, status: TxRxStatus);

    /// `ReceiveHandler::ProcessReceive`. `packet`'s addresses are stamped as
    /// described on [`Packet`].
    fn process_receive(&self, packet: Arc<Packet>);

    /// `ConnectHandler::ProcessConnect`. `ip`/`port` are the **remote** end.
    /// Optional in the C++ (the engine passes `NULL`), so it defaults to a
    /// no-op here.
    fn process_connect(&self, _ip: Ipv4Addr, _port: u16, _state: ConnectState) {}

    /// Called when one of the above took longer than
    /// `NetProcessor::MAX_CALLBACK_DELAY` (100 ms), mirroring the C++'s
    /// "long delay in ProcessReceive" warning (`NetCxn.cpp:268`). `kind` is
    /// `"process_send"`, `"process_receive"` or `"process_connect"`.
    ///
    /// The default prints to stderr; override to route it into a real log.
    fn slow_callback(&self, kind: &str, elapsed: Duration) {
        eprintln!("rsl-net: long delay in {kind} ({} us)", elapsed.as_micros());
    }
}

/// `NetProcessor::MAX_CALLBACK_DELAY` — `NetProcessor.cpp:17`.
pub const MAX_CALLBACK_DELAY: Duration = Duration::from_millis(100);
