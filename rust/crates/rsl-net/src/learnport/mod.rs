//! The learn port — how a lagging replica catches up.
//!
//! Three request/response protocols share one TCP port (the replica's
//! `rslLearnPort`, `rslPort + 1` by default). All three have the same shape:
//!
//! ```text
//! client                                        server
//!   |-- connect ------------------------------------>|
//!   |-- one marshaled Message (learn framing) ------>|   Message::ReadFromSocket
//!   |<------------------------------- response bytes-|   no envelope, no length
//!   |<------------------------------------------ FIN-|   FIN *is* the terminator
//! ```
//!
//! * **`StatusQuery`** (id 6) → one marshaled [`StatusResponse`].
//!   `Legislator::HandleStatusQueryMsg`, `legislator.cpp:3300`.
//! * **`FetchVotes`** (id 8) → the raw, page-aligned bytes of the log from the
//!   requested decree's record to the end of the log set.
//!   `HandleFetchVotesMsg`, `legislator.cpp:3633`.
//! * **`FetchCheckpoint`** (id 9) → the whole `<decree>.codex` file.
//!   `HandleFetchCheckpointMsg`, `legislator.cpp:3681`.
//!
//! Anything else on the port is dropped and the connection closed
//! (`HandleFetchRequest`, `legislator.cpp:5330`).
//!
//! ## Failure is silence
//!
//! There is no error message on this wire. A decree the server does not have, a
//! checkpoint decree that is not *its* checkpointed decree, a primary that is
//! relinquishing — every one of them closes the connection with nothing written.
//! The client sees a short or empty stream and moves on to another replica.
//! That is the whole error protocol, in both directions, and this port keeps it:
//! [`server`] never writes a diagnostic, and [`client`] turns a short stream
//! into [`TransferError::Closed`] or [`TransferError::Truncated`].
//!
//! ## Two framings, deliberately not unified
//!
//! The *request* uses the learn-port framing ([`crate::framing::learn`]): a bare
//! marshaled message whose own first six bytes size the read. The `FetchVotes`
//! *response* uses neither that nor the 4b packet framing — it is the raw log
//! file, so records are page-aligned and the reader walks 512 bytes at a time
//! ([`client::VoteStream`]). They share `rsl-wire` and nothing else; keeping
//! them separate is what keeps each faithful.
//!
//! ## Timeouts
//!
//! Every socket operation gets [`LearnConfig::recv_timeout`] /
//! [`LearnConfig::send_timeout`] (5 s each, from `RSLConfig`'s
//! `m_receiveTimeoutSec`/`m_sendTimeoutSec` defaults, `rsl.cpp:1365-1366`).
//! There is deliberately **no** overall deadline for a transfer: a slow but
//! alive peer streaming a multi-gigabyte checkpoint is legal, and the only
//! thing that matters is that bytes keep arriving. The inherited weakness is
//! that a peer which keeps dribbling a byte every four seconds can hold a
//! transfer open forever; that is the original's behaviour and it is not
//! "fixed" here silently. See `README.md` for the measured stall budget.
//!
//! ## Module name
//!
//! This is `learnport`, not `learn`, because [`crate::learn`] is already the
//! *framing* (`Message::ReadFromSocket`) that this module's requests travel in.

pub mod client;
pub mod server;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use rsl_wire::{BallotNumber, Header, MemberId, MsgKind, ProtocolVersion};
use tokio::net::TcpStream;

use crate::framing::learn::{self, LearnError, HDR_LEN};
use crate::limits::Limits;
use crate::svc::Stream;

pub use client::{FetchedCheckpoint, LearnClient, TransferError, VoteStream};
pub use server::{DirSource, LearnServer, LearnSource, StatusProvider};

// ---------------------------------------------------------------------------
// The stream seam
// ---------------------------------------------------------------------------

/// What a [`Connector`] or [`Acceptor`] produces: a byte stream, once whatever
/// it takes to get one — a connect, a handshake, or nothing at all — is done.
pub type StreamFuture = Pin<Box<dyn Future<Output = io::Result<Box<dyn Stream>>> + Send + 'static>>;

/// How the learn client opens a connection to a peer's learn port.
///
/// Plaintext is [`PlainConnector`]; [`crate::tls::TlsConnector`] adds the
/// handshake. This is the *only* thing TLS changes about this module — the
/// C++'s equivalent seam is `StreamSocket::CreateStreamSocket` returning either
/// a `StreamSocket` or an `SslSocket` (`StreamIO.cpp:37`).
pub trait Connector: Send + Sync + 'static {
    fn connect(&self, addr: SocketAddr) -> StreamFuture;
}

/// How the learn server turns an accepted socket into a stream.
pub trait Acceptor: Send + Sync + 'static {
    fn accept(&self, stream: TcpStream) -> StreamFuture;
}

/// A plain TCP connect, with `TCP_NODELAY` set.
pub struct PlainConnector;

impl Connector for PlainConnector {
    fn connect(&self, addr: SocketAddr) -> StreamFuture {
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            Ok(Box::new(stream) as Box<dyn Stream>)
        })
    }
}

/// The accepted socket, as it is.
pub struct PlainAcceptor;

impl Acceptor for PlainAcceptor {
    fn accept(&self, stream: TcpStream) -> StreamFuture {
        Box::pin(async move { Ok(Box::new(stream) as Box<dyn Stream>) })
    }
}

/// The learn port a replica listens on when its config leaves it unset:
/// `m_node.m_rslLearnPort = m_node.m_rslPort + 1` (`message.cpp:36-41`).
pub fn default_learn_port(rsl_port: u16) -> u16 {
    rsl_port.wrapping_add(1)
}

/// `m_pFetchSocket->BindAndListen(port, 1024, 120, 1)` — the learn listener's
/// backlog (`legislator.cpp:6395`).
pub const LISTEN_BACKLOG: u32 = 1024;

/// Knobs shared by both sides of the learn port.
#[derive(Clone, Debug)]
pub struct LearnConfig {
    /// Per-operation receive timeout — `RSLConfig::ReceiveTimeout()`.
    pub recv_timeout: Duration,
    /// Per-operation send timeout — `RSLConfig::SendTimeout()`.
    pub send_timeout: Duration,
    /// The cap on a *request* message, `RSLConfig::MaxMessageSize()`
    /// (`legislator.cpp:5342`). Responses are file streams and are not capped.
    pub limits: Limits,
    /// How many bytes move per read/write while streaming a file. The C++ uses
    /// `APSEQREAD::c_readBufSize` on the server side and
    /// `APSEQWRITE::c_writeBufSizeDefault` on the client side; both are
    /// buffer-pool constants with no format meaning, so this is one knob.
    pub stream_chunk: usize,
}

/// `APSEQREAD::c_readBufSize` (`apdiskio.h`) — the streaming chunk both sides
/// default to.
pub const DEFAULT_STREAM_CHUNK: usize = 256 * 1024;

impl Default for LearnConfig {
    /// The C++ defaults: 5 s each way, the configured 100 MB message cap.
    fn default() -> LearnConfig {
        LearnConfig {
            recv_timeout: Duration::from_secs(5),
            send_timeout: Duration::from_secs(5),
            limits: Limits::from_config_mb(crate::limits::DEFAULT_MAX_MESSAGE_SIZE_MB, 0)
                .expect("the default MB value is in range"),
            stream_chunk: DEFAULT_STREAM_CHUNK,
        }
    }
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

/// The fields every learn-port request carries. The three request kinds differ
/// only in their message id and in which of these the server reads.
#[derive(Clone, Debug)]
pub struct Requester {
    /// The protocol version to speak — `Legislator::m_version`.
    pub version: ProtocolVersion,
    /// Who is asking (`m_memberId`).
    pub member_id: MemberId,
    /// `PaxosConfiguration()`. `FetchVotes` responses from a *different*
    /// configuration are rejected by the client (`legislator.cpp:3765`).
    pub configuration_number: u32,
}

impl Requester {
    /// A requester with the given identity.
    pub fn new(version: ProtocolVersion, member_id: MemberId, configuration_number: u32) -> Self {
        Requester {
            version,
            member_id,
            configuration_number,
        }
    }

    /// `Message(m_version, Message_StatusQuery, m_memberId, 0, 1, BallotNumber())`
    /// — decree and configuration are dummies here (`legislator.cpp:1370-1376`).
    pub fn status_query(&self) -> Header {
        Header::new(
            self.version,
            rsl_wire::messages::MSG_STATUS_QUERY,
            self.member_id.clone(),
            0,
            1,
            BallotNumber::default(),
            0,
        )
    }

    /// `Message(m_version, Message_FetchVotes, m_memberId, decree, config, ballot)`
    /// (`legislator.cpp:3727-3733`). The server ignores the ballot.
    pub fn fetch_votes(&self, decree: u64, ballot: BallotNumber) -> Header {
        Header::new(
            self.version,
            rsl_wire::messages::MSG_FETCH_VOTES,
            self.member_id.clone(),
            decree,
            self.configuration_number,
            ballot,
            0,
        )
    }

    /// `Message(m_version, Message_FetchCheckpoint, m_memberId, decree, 1,
    /// BallotNumber())` — the configuration number is a literal dummy `1` here
    /// and the ballot is ignored (`legislator.cpp:5506-5512`).
    pub fn fetch_checkpoint(&self, decree: u64) -> Header {
        Header::new(
            self.version,
            rsl_wire::messages::MSG_FETCH_CHECKPOINT,
            self.member_id.clone(),
            decree,
            1,
            BallotNumber::default(),
            0,
        )
    }
}

// ---------------------------------------------------------------------------
// Async learn framing
// ---------------------------------------------------------------------------

/// Read one learn-framed message from an async stream, applying `timeout` to
/// each individual read.
///
/// The decisions are [`crate::framing::learn::parse_header`]'s — this is only
/// the async plumbing around them, with the same bounded growth: the body is
/// never allocated before the size cap has passed.
///
/// `Ok(None)` is a clean close *between* messages, the peer simply having
/// nothing to say.
pub(crate) async fn read_message<R>(
    r: &mut R,
    kind: MsgKind,
    limits: Limits,
    timeout: Duration,
) -> Result<Option<rsl_wire::Msg>, TransferError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; HDR_LEN];
    if !read_exact_or_eof(r, &mut buf, timeout).await? {
        return Ok(None);
    }

    let hdr = learn::parse_header(&buf, limits.effective_max()).map_err(TransferError::Framing)?;
    let body = hdr.len as usize - HDR_LEN;
    // Grow as the bytes arrive rather than trusting the length field, exactly
    // as the sync reader does (see the crate-level divergence note).
    let mut filled = HDR_LEN;
    while filled < hdr.len as usize {
        let want = (hdr.len as usize - filled).min(64 * 1024);
        buf.resize(filled + want, 0);
        if !read_exact_or_eof(r, &mut buf[filled..], timeout).await? {
            return Err(TransferError::Framing(LearnError::ShortBody {
                len: hdr.len,
                available: filled as u32,
            }));
        }
        filled += want;
    }
    debug_assert_eq!(buf.len(), HDR_LEN + body);

    rsl_wire::Msg::unmarshal(kind, &buf)
        .map(Some)
        .ok_or(TransferError::Framing(LearnError::Unmarshal))
}

/// Fill `buf`, or report a clean EOF *before its first byte*. An EOF partway
/// through is [`TransferError::Truncated`].
pub(crate) async fn read_exact_or_eof<R>(
    r: &mut R,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<bool, TransferError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut filled = 0;
    while filled < buf.len() {
        let got = with_timeout(timeout, r.read(&mut buf[filled..])).await??;
        if got == 0 {
            return if filled == 0 {
                Ok(false)
            } else {
                Err(TransferError::Truncated {
                    got: filled as u64,
                    expected: buf.len() as u64,
                })
            };
        }
        filled += got;
    }
    Ok(true)
}

/// Write every byte, applying `timeout` to each write.
pub(crate) async fn write_all<W>(
    w: &mut W,
    mut buf: &[u8],
    timeout: Duration,
) -> Result<(), TransferError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    while !buf.is_empty() {
        let wrote = with_timeout(timeout, w.write(buf)).await??;
        if wrote == 0 {
            return Err(TransferError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "learn-port write made no progress",
            )));
        }
        buf = &buf[wrote..];
    }
    Ok(())
}

/// `tokio::time::timeout` with the elapsed case mapped to our own error.
pub(crate) async fn with_timeout<F: std::future::Future>(
    timeout: Duration,
    f: F,
) -> Result<F::Output, TransferError> {
    tokio::time::timeout(timeout, f)
        .await
        .map_err(|_| TransferError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_learn_port_is_one_past_the_rsl_port() {
        assert_eq!(default_learn_port(8080), 8081);
    }

    #[test]
    fn the_default_config_is_the_cpp_five_second_pair() {
        let config = LearnConfig::default();
        assert_eq!(config.recv_timeout, Duration::from_secs(5));
        assert_eq!(config.send_timeout, Duration::from_secs(5));
        assert_eq!(config.limits.effective_max(), 100 * 1024 * 1024 + 1024);
    }

    #[test]
    fn requests_carry_the_ids_the_server_dispatches_on() {
        let who = Requester::new(ProtocolVersion::V6, MemberId::from_str("101"), 7);
        assert_eq!(
            who.status_query().msg_id,
            rsl_wire::messages::MSG_STATUS_QUERY
        );
        // The status query's decree and configuration are dummies.
        assert_eq!(who.status_query().decree, 0);
        assert_eq!(who.status_query().configuration_number, 1);

        let votes = who.fetch_votes(42, BallotNumber::new(3, MemberId::from_str("202")));
        assert_eq!(votes.msg_id, rsl_wire::messages::MSG_FETCH_VOTES);
        assert_eq!(votes.decree, 42);
        assert_eq!(votes.configuration_number, 7);

        // FetchCheckpoint hard-codes configuration 1 (legislator.cpp:5510).
        let checkpoint = who.fetch_checkpoint(9);
        assert_eq!(checkpoint.msg_id, rsl_wire::messages::MSG_FETCH_CHECKPOINT);
        assert_eq!(checkpoint.decree, 9);
        assert_eq!(checkpoint.configuration_number, 1);
    }
}
