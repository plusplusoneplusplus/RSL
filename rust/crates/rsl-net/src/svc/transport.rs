//! What a connection is made of, and how one is dialed.
//!
//! The service never names `TcpStream` directly. Everything goes through
//! [`Link`] (a byte stream plus the two socket addresses the receive path
//! stamps into packets) and [`Dialer`] (how a client obtains one). Real
//! deployments use [`TcpDialer`]; the contract tests use `tokio::io::duplex`
//! pairs, and Phase 4d slots rustls in the same way — the C++ does exactly this
//! with `NetSslCxn::CreateNetCxn` sitting where `NetCxn` would.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Anything the connection actor can read from and write to.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

/// An established connection: the byte stream plus the addresses
/// `NetCxn::ReadReadyInternal` stamps into every received packet
/// (`NetCxn.cpp:239-248`).
pub struct Link {
    pub stream: Box<dyn Stream>,
    /// Our end (`m_Vc->GetLocalIp()` / `GetLocalPort()`).
    pub local: SocketAddrV4,
    /// The peer (`m_Vc->GetRemoteIp()` / `GetRemotePort()`).
    pub remote: SocketAddrV4,
}

impl Link {
    /// Wrap an already-connected stream. `local`/`remote` are only used for
    /// packet address stamping and the connection table key.
    pub fn new(stream: impl Stream, local: SocketAddrV4, remote: SocketAddrV4) -> Link {
        Link {
            stream: Box::new(stream),
            local,
            remote,
        }
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("local", &self.local)
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

/// How a client service opens a connection (`NetProcessor::Connect`, reached
/// from `NetCxn::Connect`, `NetCxn.cpp:667`).
pub trait Dialer: Send + Sync + 'static {
    fn dial(
        &self,
        remote: SocketAddrV4,
    ) -> Pin<Box<dyn Future<Output = io::Result<Link>> + Send + 'static>>;
}

/// How a server service turns an accepted socket into a [`Link`].
///
/// The plaintext implementation ([`PlainAcceptor`]) just wraps the socket; the
/// TLS one ([`crate::tls::TlsAcceptor`]) runs a handshake first and only
/// produces a `Link` if it succeeds. This is the mirror of [`Dialer`], and the
/// only place a server service learns that TLS exists.
pub trait Acceptor: Send + Sync + 'static {
    fn accept(
        &self,
        stream: TcpStream,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Pin<Box<dyn Future<Output = io::Result<Link>> + Send + 'static>>;
}

/// The accepted socket, as it is.
pub struct PlainAcceptor;

impl Acceptor for PlainAcceptor {
    fn accept(
        &self,
        stream: TcpStream,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Pin<Box<dyn Future<Output = io::Result<Link>> + Send + 'static>> {
        Box::pin(async move { Ok(Link::new(stream, local, remote)) })
    }
}

/// The real thing: a TCP connect from `bind_ip`, with `TCP_NODELAY` set.
///
/// `bind_ip` is `NetPacketSvc::m_BindIp` — the engine passes the replica's own
/// IP unless `s_ListenOnAllIPs` (`legislator.cpp:6384`).
pub struct TcpDialer {
    pub bind_ip: Ipv4Addr,
}

impl Dialer for TcpDialer {
    fn dial(
        &self,
        remote: SocketAddrV4,
    ) -> Pin<Box<dyn Future<Output = io::Result<Link>> + Send + 'static>> {
        let bind_ip = self.bind_ip;
        Box::pin(async move {
            let socket = tokio::net::TcpSocket::new_v4()?;
            if !bind_ip.is_unspecified() {
                socket.bind(SocketAddr::V4(SocketAddrV4::new(bind_ip, 0)))?;
            }
            let stream = socket.connect(SocketAddr::V4(remote)).await?;
            configure(&stream)?;
            let local = v4(stream.local_addr()?);
            Ok(Link::new(stream, local, remote))
        })
    }
}

/// `TCP_NODELAY`, as `NetProcessor` sets on every socket: RSL's packets are
/// small and latency-critical, and Nagle would batch a vote with the next one.
pub(crate) fn configure(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)
}

/// Narrow a `SocketAddr` to v4. RSL addresses are `UInt32` ip + `UInt16` port
/// throughout, so a v6 socket has nowhere to go; `0.0.0.0:0` keeps the address
/// stamping well-defined instead of panicking on an address we cannot express.
pub(crate) fn v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => super::handler::UNSPECIFIED,
    }
}

/// Reconnect pacing.
///
/// **Divergence from the C++, deliberate.** `NetCxn::CONNECT_RETRY_TIME` is a
/// flat 20 ms (`NetCxn.cpp:9`), so a replica that is down gets hammered 50
/// times a second by every peer for as long as it stays down. Nothing about the
/// retry interval is peer-observable — no message carries it and no timeout
/// depends on it — so this port backs off exponentially with jitter instead.
/// The first retry still happens after 20 ms, which is what the latency of a
/// transient blip depends on.
#[derive(Clone, Copy, Debug)]
pub struct BackoffConfig {
    /// First retry delay. Defaults to `CONNECT_RETRY_TIME` (20 ms).
    pub base: Duration,
    /// Ceiling for the doubling. Defaults to 1 s.
    pub max: Duration,
    /// Fraction of the delay to randomize away, in `[0, 1)`. Defaults to 0.25,
    /// so peers that all lost the same replica do not resynchronize into a
    /// thundering herd.
    pub jitter: f64,
}

impl Default for BackoffConfig {
    fn default() -> BackoffConfig {
        BackoffConfig {
            base: Duration::from_millis(20),
            max: Duration::from_secs(1),
            jitter: 0.25,
        }
    }
}

/// The per-connection backoff state.
pub(crate) struct Backoff {
    config: BackoffConfig,
    attempt: u32,
    /// xorshift64 state, seeded per connection from the process's random hash
    /// seed so we need no `rand` dependency.
    rng: u64,
}

impl Backoff {
    pub(crate) fn new(config: BackoffConfig) -> Backoff {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(0x9e37_79b9_7f4a_7c15);
        Backoff {
            config,
            attempt: 0,
            rng: hasher.finish() | 1,
        }
    }

    /// Reset after a successful connect, so a flapping link starts from 20 ms
    /// again rather than inheriting the previous outage's ceiling.
    pub(crate) fn reset(&mut self) {
        self.attempt = 0;
    }

    /// The next delay, doubling per attempt up to `max`, minus up to
    /// `jitter × delay`.
    pub(crate) fn next_delay(&mut self) -> Duration {
        let shift = self.attempt.min(16);
        self.attempt = self.attempt.saturating_add(1);

        let base = self.config.base.as_nanos() as u64;
        let capped = base
            .saturating_mul(1u64 << shift)
            .min(u64::try_from(self.config.max.as_nanos()).unwrap_or(u64::MAX));

        let jitter = self.config.jitter.clamp(0.0, 1.0);
        if jitter == 0.0 {
            return Duration::from_nanos(capped);
        }
        // xorshift64*, then scale into [0, jitter × capped].
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let unit = (self.rng >> 11) as f64 / (1u64 << 53) as f64;
        let cut = (capped as f64 * jitter * unit) as u64;
        Duration::from_nanos(capped - cut.min(capped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_at_the_cpp_retry_time_and_is_capped() {
        let config = BackoffConfig {
            jitter: 0.0,
            ..BackoffConfig::default()
        };
        let mut backoff = Backoff::new(config);
        assert_eq!(backoff.next_delay(), Duration::from_millis(20));
        assert_eq!(backoff.next_delay(), Duration::from_millis(40));
        assert_eq!(backoff.next_delay(), Duration::from_millis(80));
        for _ in 0..20 {
            assert!(backoff.next_delay() <= config.max);
        }
        assert_eq!(backoff.next_delay(), config.max);
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(20));
    }

    #[test]
    fn jitter_only_ever_shortens_the_delay() {
        let mut backoff = Backoff::new(BackoffConfig::default());
        for _ in 0..1000 {
            let d = backoff.next_delay();
            assert!(d <= Duration::from_secs(1));
            assert!(d >= Duration::from_millis(15));
        }
    }
}
