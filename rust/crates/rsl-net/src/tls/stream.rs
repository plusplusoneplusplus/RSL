//! Where TLS actually meets a socket: one wrapper per direction per port, and
//! nothing below them knows.
//!
//! Every type here does the same three things — take a byte stream, run a
//! handshake on it, hand back a byte stream — and each is plugged into the seam
//! its port already had: [`crate::svc::Dialer`] / [`crate::svc::Acceptor`] for
//! the packet port, [`crate::learnport::Connector`] /
//! [`crate::learnport::Acceptor`] for the learn port.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;

use super::Tls;
use crate::svc::{Dialer, Link, Stream};

/// Dials, then hands the socket to rustls. The [`Link`] only exists once the
/// handshake has succeeded, so [`crate::svc::ConnectState::Connected`] fires
/// after authentication and not before — which is what the C++ does by calling
/// `CallConnectHandler(Connected)` from the `AuthDataEnd` branch of
/// `ProcessEncryptedBuffer` (`NetSSLCxn.cpp:244`) rather than from `Start`.
///
/// Packets sent before that are not lost: they sit in the connection's send
/// queue, which is exactly where the C++ leaves them (`EnqueuePacket` skips
/// `WriteReadyInternal` until `IsSspiAuthCompleted()`, `NetSSLCxn.cpp:118`).
pub struct TlsDialer {
    pub(crate) inner: Arc<dyn Dialer>,
    pub(crate) tls: Arc<Tls>,
}

impl Dialer for TlsDialer {
    fn dial(
        &self,
        remote: SocketAddrV4,
    ) -> Pin<Box<dyn Future<Output = io::Result<Link>> + Send + 'static>> {
        let dial = self.inner.dial(remote);
        let config = self.tls.live().client.clone();
        Box::pin(async move {
            let link = dial.await?;
            let connector = tokio_rustls::TlsConnector::from(config);
            let stream = connector
                .connect(name_for(IpAddr::V4(*remote.ip())), link.stream)
                .await?;
            Ok(Link::new(stream, link.local, link.remote))
        })
    }
}

/// The packet port's server side.
pub struct TlsAcceptor {
    pub(crate) tls: Arc<Tls>,
}

impl crate::svc::Acceptor for TlsAcceptor {
    fn accept(
        &self,
        stream: TcpStream,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Pin<Box<dyn Future<Output = io::Result<Link>> + Send + 'static>> {
        let config = self.tls.live().server.clone();
        Box::pin(async move {
            let stream = tokio_rustls::TlsAcceptor::from(config)
                .accept(stream)
                .await?;
            Ok(Link::new(stream, local, remote))
        })
    }
}

/// The learn port, both sides. One object because the learn port's two roles
/// are two methods rather than two services.
pub struct TlsConnector {
    pub(crate) tls: Arc<Tls>,
}

impl crate::learnport::Connector for TlsConnector {
    fn connect(&self, addr: SocketAddr) -> crate::learnport::StreamFuture {
        let config = self.tls.live().client.clone();
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            let stream = tokio_rustls::TlsConnector::from(config)
                .connect(name_for(addr.ip()), stream)
                .await?;
            Ok(Box::new(stream) as Box<dyn Stream>)
        })
    }
}

impl crate::learnport::Acceptor for TlsConnector {
    fn accept(
        &self,
        stream: TcpStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Stream>>> + Send + 'static>> {
        let config = self.tls.live().server.clone();
        Box::pin(async move {
            let stream = tokio_rustls::TlsAcceptor::from(config)
                .accept(stream)
                .await?;
            Ok(Box::new(stream) as Box<dyn Stream>)
        })
    }
}

/// The `ServerName` rustls insists on having, from the address we dialed.
///
/// It is never checked against anything — the verifier ignores it, as the C++
/// does by passing `pwszServerName = NULL` — but rustls needs *a* name to build
/// a client connection with. An IP is the honest one: RSL dials replicas by IP
/// and no other name exists. Sending it also means no SNI extension goes out,
/// matching a `NULL` target name on the SChannel side.
fn name_for(ip: IpAddr) -> ServerName<'static> {
    ServerName::IpAddress(rustls::pki_types::IpAddr::from(ip))
}
