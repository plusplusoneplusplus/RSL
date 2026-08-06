//! The learn-port server: `FetchServerLoop` + `HandleFetchRequest` and the
//! three handlers behind them (`legislator.cpp:5300-5363`).
//!
//! The C++ runs an accept loop on its own thread and spawns a *thread per
//! request* (`RunThread(&Legislator::HandleFetchRequest, ...)`,
//! `legislator.cpp:5325`). Here it is a tokio task per accepted connection —
//! the only structural change, and it is invisible on the wire.
//!
//! What is *not* changed is the shape of a response: one message read, one
//! stream out, close. Nothing is framed, nothing is acknowledged, and every
//! refusal is a silent close.

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

// ---------------------------------------------------------------------------
// What the server needs from the engine
// ---------------------------------------------------------------------------

/// The engine state a learn-port response is built from. Phase 5's legislator
/// implements this; tests stub it.
///
/// Both methods may return `None`, which means "close the connection without
/// answering" — the C++ has exactly two such cases and they are noted on each
/// method.
pub trait StatusProvider: Send + Sync + 'static {
    /// Build the [`StatusResponse`] for `request`
    /// (`HandleStatusQueryMsg`, `legislator.cpp:3300`).
    ///
    /// `None` is the `m_relinquishPrimary` early return (`legislator.cpp:3302`):
    /// the query is dropped and the socket closed.
    fn status(&self, request: &Header) -> Option<StatusResponse>;

    /// `m_checkpointedDecree` — the *only* decree a `FetchCheckpoint` will be
    /// served for (`legislator.cpp:3690`). `None` when the replica has no
    /// checkpoint, so every fetch is refused.
    fn checkpointed_decree(&self) -> Option<u64>;
}

/// Where a learn-port response's bytes come from.
///
/// Split out from [`StatusProvider`] so a test can serve a fixed directory
/// without an engine, and so Phase 5 can serve from live engine state without
/// re-deriving file layout. [`DirSource`] is the directory-backed
/// implementation and is what a real replica uses.
///
/// Every method is **blocking** — it scans and opens files. The server calls
/// them on a blocking pool thread, so an implementation need not be async.
pub trait LearnSource: Send + Sync + 'static {
    /// See [`StatusProvider::status`].
    fn status(&self, request: &Header) -> Option<StatusResponse>;

    /// The byte spans that answer `FetchVotes(decree)`, or `None` when no log
    /// holds that decree (`legislator.cpp:3656` — close, say nothing).
    fn votes_from(&self, decree: u64) -> io::Result<Option<Vec<FileSpan>>>;

    /// The checkpoint file for `decree`, or `None` when `decree` is not this
    /// replica's `m_checkpointedDecree` (`legislator.cpp:3690`).
    fn checkpoint(&self, decree: u64) -> io::Result<Option<PathBuf>>;
}

/// A [`LearnSource`] over a real data directory.
///
/// The log set is re-opened **per request**, which is what gives a response its
/// snapshot: it serves the log as it stood when the request arrived, and never
/// chases appends made while it streams. See [`LogSet`] for why that matches
/// the C++.
pub struct DirSource<S: StatusProvider> {
    dir: PathBuf,
    status: S,
}

impl<S: StatusProvider> DirSource<S> {
    /// Serve `dir`, taking engine state from `status`.
    pub fn new(dir: impl Into<PathBuf>, status: S) -> DirSource<S> {
        DirSource {
            dir: dir.into(),
            status,
        }
    }

    /// The directory being served.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The status provider, for a caller that also holds it as engine state.
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
        // The decree must be *the* checkpointed decree, not merely a checkpoint
        // that happens to be on disk: the C++ compares against
        // `m_checkpointedDecree` under the lock and nothing else.
        if self.status.checkpointed_decree() != Some(decree) {
            return Ok(None);
        }
        let path = self
            .dir
            .join(rsl_storage::dir::checkpoint_file_name(decree));
        Ok(path.is_file().then_some(path))
    }
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

/// A running learn port. Dropping it stops the listener and every in-flight
/// transfer.
pub struct LearnServer {
    local_addr: SocketAddr,
    acceptor: JoinHandle<()>,
    shutdown: watch::Sender<bool>,
}

impl LearnServer {
    /// Bind `addr` and start serving. Port 0 picks an ephemeral port; read it
    /// back with [`local_addr`](LearnServer::local_addr).
    ///
    /// The listen backlog is [`LISTEN_BACKLOG`], as in `BindAndListen`
    /// (`legislator.cpp:6395`). Must be called from within a Tokio runtime.
    pub async fn bind(
        addr: SocketAddr,
        source: Arc<dyn LearnSource>,
        config: LearnConfig,
    ) -> io::Result<LearnServer> {
        LearnServer::bind_with(addr, Arc::new(PlainAcceptor), source, config).await
    }

    /// [`bind`](LearnServer::bind) with every accepted socket going through
    /// `acceptor` first — `tls.connector()` for a TLS deployment.
    ///
    /// The handshake runs inside the per-connection task, so a peer that
    /// connects and stalls costs a task and nothing else; the accept loop is
    /// never blocked on it.
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

    /// Serve on an already-bound listener.
    pub fn from_listener(
        listener: TcpListener,
        source: Arc<dyn LearnSource>,
        config: LearnConfig,
    ) -> LearnServer {
        LearnServer::from_listener_with(listener, Arc::new(PlainAcceptor), source, config)
    }

    /// [`from_listener`](LearnServer::from_listener) with an explicit acceptor.
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

    /// The address being listened on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop accepting and cancel every in-flight transfer.
    ///
    /// This does not wait for the tasks to unwind — a connection that is mid
    /// `write` finishes that syscall and then notices. As in the C++, a peer
    /// reading from a shut-down replica just sees the stream stop, which is
    /// already a case it must handle.
    pub fn shutdown(&self) {
        // `send_replace`, not `send`: it must stick even with no live receiver.
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
            // `RSLError("Accept failed"); continue;` (legislator.cpp:5322).
            Err(_) => continue,
        };
        let _ = stream.set_nodelay(true);
        let source = source.clone();
        let config = config.clone();
        let stop = shutdown.subscribe();
        let handshake = stream_acceptor.accept(stream);
        // A thread per request in the C++ (legislator.cpp:5325); a task here.
        tokio::spawn(async move {
            // A failed handshake is a connection that closes without a byte of
            // response — indistinguishable, to the peer, from every other
            // refusal this port expresses (see the module docs).
            let Ok(stream) = handshake.await else {
                return;
            };
            let _ = serve(stream, source, config, stop).await;
        });
    }
}

/// `Legislator::HandleFetchRequest` (`legislator.cpp:5330`): read exactly one
/// message, dispatch on its id, close.
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
    // A close before the request, or a message that will not parse, is the
    // `RSLError("Failed to unmarshal message"); return;` path — nothing is
    // written back either way.
    let Some(Msg::Base(request)) = request else {
        return Ok(());
    };

    match request.msg_id {
        MSG_STATUS_QUERY => serve_status(&mut stream, &source, &request, &config).await,
        MSG_FETCH_VOTES => serve_votes(&mut stream, &source, &request, &config, stop).await,
        MSG_FETCH_CHECKPOINT => {
            serve_checkpoint(&mut stream, &source, &request, &config, stop).await
        }
        // `RSLError("Invalid message")` — drop it and close.
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
    // `HandleFetchVotesMsg` ignores the ballot entirely: "// ignore the ballot
    // number / send all proposals >= msg->Decree()" (legislator.cpp:3635).
    let spans = blocking(move || source.votes_from(decree))
        .await?
        .map_err(TransferError::Io)?;
    // No log holds the decree — close, silently.
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
    // Not *the* checkpointed decree — close, silently.
    let Some(path) = path else {
        return Ok(());
    };
    send_file(stream, &path, 0, None, config, &stop).await
}

/// `Legislator::SendFile(file, offset, length, sock)` (`legislator.cpp:4484`).
///
/// `length == None` is the C++'s `length < 0`: "everything from `offset` to the
/// size the file had when it was opened" (`legislator.cpp:4513-4516`, where
/// `APSEQREAD::FileSize()` is the size captured by `DoInit`,
/// `apdiskio.cpp:146`).
///
/// Bytes go out in [`LearnConfig::stream_chunk`] pieces and are never all
/// resident: a 40 GB checkpoint costs one chunk of memory.
async fn send_file<S: AsyncWrite + Unpin>(
    stream: &mut S,
    path: &Path,
    offset: u64,
    length: Option<u64>,
    config: &LearnConfig,
    stop: &watch::Receiver<bool>,
) -> Result<(), TransferError> {
    let mut file = tokio::fs::File::open(path).await?;
    // `reader->FileSize()` is read once, at open — the snapshot the whole
    // response is served from.
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
            // The file shrank under us (only reachable if something outside the
            // engine truncated it). The peer sees a short stream and retries
            // elsewhere, which is the same outcome as any other read failure in
            // `SendFile`.
            return Ok(());
        }
        write_all(stream, &chunk[..got], config.send_timeout).await?;
        remaining -= got as u64;
    }
    stream.flush().await?;
    Ok(())
}

/// Run a blocking source call on the blocking pool. A panicking source is
/// reported as an I/O error rather than taking the server down.
async fn blocking<T, F>(f: F) -> Result<T, TransferError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| TransferError::Io(io::Error::other(e)))
}
