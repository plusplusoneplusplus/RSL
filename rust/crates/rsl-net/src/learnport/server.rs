//! The learn-port server: accept loop + per-connection dispatch.
//!
//! One tokio task per accepted connection (the C++ uses a thread per request).
//! The response shape is unchanged: one message read, one stream out, close.
//! Nothing is framed, nothing is acknowledged, and every refusal is a silent
//! close.

use std::io::{self, SeekFrom};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rsl_storage::log::{FileSpan, LogSet};
use rsl_wire::messages::{
    Header, Msg, MsgKind, StatusResponse, MSG_FETCH_CHECKPOINT, MSG_FETCH_VOTES, MSG_STATUS_QUERY,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::{write_all, Acceptor, LearnConfig, PlainAcceptor, TransferError, LISTEN_BACKLOG};

/// The engine state a learn-port response is built from. Both methods may
/// return `None`, meaning "close the connection without answering".
pub trait StatusProvider: Send + Sync + 'static {
    /// Build the [`StatusResponse`] for `request`, or `None` to refuse.
    fn status(&self, request: &Header) -> Option<StatusResponse>;

    /// The only decree a `FetchCheckpoint` will be served for. `None` when the
    /// replica has no checkpoint.
    fn checkpointed_decree(&self) -> Option<u64>;
}

/// Where a learn-port response's bytes come from. Every method is **blocking**
/// — the server dispatches them on a blocking pool thread.
pub trait LearnSource: Send + Sync + 'static {
    fn status(&self, request: &Header) -> Option<StatusResponse>;

    /// The byte spans that answer `FetchVotes(decree)`, or `None` when no log
    /// holds that decree.
    fn votes_from(&self, decree: u64) -> io::Result<Option<Vec<FileSpan>>>;

    /// The checkpoint file for `decree`, or `None` when `decree` is not this
    /// replica's checkpointed decree.
    fn checkpoint(&self, decree: u64) -> io::Result<Option<PathBuf>>;
}

/// A [`LearnSource`] over a real data directory. The log set is re-opened per
/// request, giving each response a snapshot as of request arrival.
pub struct DirSource<S: StatusProvider> {
    dir: PathBuf,
    status: S,
}

impl<S: StatusProvider> DirSource<S> {
    pub fn new(dir: impl Into<PathBuf>, status: S) -> DirSource<S> {
        DirSource {
            dir: dir.into(),
            status,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn status_provider(&self) -> &S {
        &self.status
    }
}

impl<S: StatusProvider> LearnSource for DirSource<S> {
    fn status(&self, request: &Header) -> Option<StatusResponse> {
        self.status.status(request)
    }

    fn votes_from(&self, decree: u64) -> io::Result<Option<Vec<FileSpan>>> {
        let logs = LogSet::open(&self.dir).map_err(io::Error::other)?;
        Ok(logs.votes_from(decree))
    }

    fn checkpoint(&self, decree: u64) -> io::Result<Option<PathBuf>> {
        if self.status.checkpointed_decree() != Some(decree) {
            return Ok(None);
        }
        let path = self
            .dir
            .join(rsl_storage::dir::checkpoint_file_name(decree));
        Ok(path.is_file().then_some(path))
    }
}

/// A running learn port. Dropping it stops the listener and all in-flight
/// transfers.
pub struct LearnServer {
    local_addr: SocketAddr,
    acceptor: JoinHandle<()>,
    shutdown: watch::Sender<bool>,
}

impl LearnServer {
    /// Bind `addr` and start serving. Port 0 picks an ephemeral port.
    pub async fn bind(
        addr: SocketAddr,
        source: Arc<dyn LearnSource>,
        config: LearnConfig,
    ) -> io::Result<LearnServer> {
        LearnServer::bind_with(addr, Arc::new(PlainAcceptor), source, config).await
    }

    /// Like [`bind`](LearnServer::bind) with an explicit acceptor (e.g. TLS).
    /// The handshake runs inside the per-connection task.
    pub async fn bind_with(
        addr: SocketAddr,
        acceptor: Arc<dyn Acceptor>,
        source: Arc<dyn LearnSource>,
        config: LearnConfig,
    ) -> io::Result<LearnServer> {
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        let listener = socket.listen(LISTEN_BACKLOG)?;
        Ok(LearnServer::from_listener_with(
            listener, acceptor, source, config,
        ))
    }

    pub fn from_listener(
        listener: TcpListener,
        source: Arc<dyn LearnSource>,
        config: LearnConfig,
    ) -> LearnServer {
        LearnServer::from_listener_with(listener, Arc::new(PlainAcceptor), source, config)
    }

    /// Like [`from_listener`](LearnServer::from_listener) with an explicit
    /// acceptor.
    pub fn from_listener_with(
        listener: TcpListener,
        stream_acceptor: Arc<dyn Acceptor>,
        source: Arc<dyn LearnSource>,
        config: LearnConfig,
    ) -> LearnServer {
        let local_addr = listener
            .local_addr()
            .expect("bound listener has an address");
        let (shutdown, _) = watch::channel(false);
        let acceptor = tokio::spawn(accept_loop(
            listener,
            stream_acceptor,
            source,
            config,
            shutdown.subscribe(),
            shutdown.clone(),
        ));
        LearnServer {
            local_addr,
            acceptor,
            shutdown,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop accepting and cancel all in-flight transfers. Does not wait for
    /// tasks to unwind.
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
        self.acceptor.abort();
    }
}

impl Drop for LearnServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn accept_loop(
    listener: TcpListener,
    stream_acceptor: Arc<dyn Acceptor>,
    source: Arc<dyn LearnSource>,
    config: LearnConfig,
    mut stop: watch::Receiver<bool>,
    shutdown: watch::Sender<bool>,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = stop.changed() => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, _peer) = match accepted {
            Ok(accepted) => accepted,
            Err(_) => continue,
        };
        let _ = stream.set_nodelay(true);
        let source = source.clone();
        let config = config.clone();
        let stop = shutdown.subscribe();
        let handshake = stream_acceptor.accept(stream);
        tokio::spawn(async move {
            let Ok(stream) = handshake.await else {
                return;
            };
            let _ = serve(stream, source, config, stop).await;
        });
    }
}

/// Read one request message, dispatch on its id, close.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    source: Arc<dyn LearnSource>,
    config: LearnConfig,
    mut stop: watch::Receiver<bool>,
) -> Result<(), TransferError> {
    let request = tokio::select! {
        biased;
        _ = stop.changed() => return Ok(()),
        request = super::read_message(
            &mut stream,
            MsgKind::Base,
            config.limits,
            config.recv_timeout,
        ) => request?,
    };
    let Some(Msg::Base(request)) = request else {
        return Ok(());
    };

    match request.msg_id {
        MSG_STATUS_QUERY => serve_status(&mut stream, &source, &request, &config).await,
        MSG_FETCH_VOTES => serve_votes(&mut stream, &source, &request, &config, stop).await,
        MSG_FETCH_CHECKPOINT => {
            serve_checkpoint(&mut stream, &source, &request, &config, stop).await
        }
        _ => Ok(()),
    }
}

async fn serve_status<S: AsyncWrite + Unpin>(
    stream: &mut S,
    source: &Arc<dyn LearnSource>,
    request: &Header,
    config: &LearnConfig,
) -> Result<(), TransferError> {
    let source = source.clone();
    let request = request.clone();
    let Some(response) = blocking(move || source.status(&request)).await? else {
        return Ok(());
    };
    let bytes = response.marshal_with_checksum();
    write_all(stream, &bytes, config.send_timeout).await
}

async fn serve_votes<S: AsyncWrite + Unpin>(
    stream: &mut S,
    source: &Arc<dyn LearnSource>,
    request: &Header,
    config: &LearnConfig,
    stop: watch::Receiver<bool>,
) -> Result<(), TransferError> {
    let source = source.clone();
    let decree = request.decree;
    let spans = blocking(move || source.votes_from(decree))
        .await?
        .map_err(TransferError::Io)?;
    let Some(spans) = spans else {
        return Ok(());
    };

    for span in spans {
        send_file(
            stream,
            &span.path,
            span.offset,
            Some(span.len),
            config,
            &stop,
        )
        .await?;
    }
    Ok(())
}

async fn serve_checkpoint<S: AsyncWrite + Unpin>(
    stream: &mut S,
    source: &Arc<dyn LearnSource>,
    request: &Header,
    config: &LearnConfig,
    stop: watch::Receiver<bool>,
) -> Result<(), TransferError> {
    let source = source.clone();
    let decree = request.decree;
    let path = blocking(move || source.checkpoint(decree))
        .await?
        .map_err(TransferError::Io)?;
    let Some(path) = path else {
        return Ok(());
    };
    send_file(stream, &path, 0, None, config, &stop).await
}

/// Stream a file (or a range of it) to the peer in
/// [`LearnConfig::stream_chunk`]-sized pieces. `length == None` means
/// everything from `offset` to EOF.
async fn send_file<S: AsyncWrite + Unpin>(
    stream: &mut S,
    path: &Path,
    offset: u64,
    length: Option<u64>,
    config: &LearnConfig,
    stop: &watch::Receiver<bool>,
) -> Result<(), TransferError> {
    let mut file = tokio::fs::File::open(path).await?;
    let file_size = file.metadata().await?.len();
    if offset > 0 {
        file.seek(SeekFrom::Start(offset)).await?;
    }
    let mut remaining = length.unwrap_or_else(|| file_size.saturating_sub(offset));

    let mut chunk = vec![0u8; config.stream_chunk];
    while remaining > 0 {
        if *stop.borrow() {
            return Ok(());
        }
        let want = remaining.min(chunk.len() as u64) as usize;
        let got = file.read(&mut chunk[..want]).await?;
        if got == 0 {
            return Ok(());
        }
        write_all(stream, &chunk[..got], config.send_timeout).await?;
        remaining -= got as u64;
    }
    stream.flush().await?;
    Ok(())
}

/// Run a blocking source call on the blocking pool.
async fn blocking<T, F>(f: F) -> Result<T, TransferError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| TransferError::Io(io::Error::other(e)))
}
