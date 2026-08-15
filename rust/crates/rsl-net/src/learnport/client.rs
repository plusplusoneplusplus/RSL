//! The learn-port client: the three "go and get it" paths a lagging replica
//! runs — status query, vote fetch, and checkpoint fetch.
//!
//! Each one is: connect, write one request, read until the peer closes. There is
//! no reply envelope and no error code — a peer that will not serve the request
//! just closes, so a short stream *is* the failure signal.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rsl_storage::checkpoint::{self, CheckpointHeader};
use rsl_storage::durability::{Durability, SyncAll};
use rsl_storage::seqread::SECTOR;
use rsl_storage::seqwrite::{SeqWriter, SeqWriterConfig};
use rsl_storage::{round_up_to_page, PAGE_SIZE};
use rsl_wire::messages::{
    unmarshal_base, verify_checksum, Header, Msg, MsgKind, StatusResponse, MSG_PREPARE,
    MSG_RECONFIGURATION_DECISION, MSG_VOTE,
};
use rsl_wire::BallotNumber;
use tokio::io::{AsyncRead, AsyncWriteExt};

use super::{read_exact_or_eof, write_all, Connector, LearnConfig, PlainConnector};
use crate::framing::learn::{self, LearnError};
use crate::svc::Stream;

/// Why a learn-port transfer failed. There is no "server said no" variant — a
/// refusal arrives as [`Closed`](TransferError::Closed) or
/// [`Truncated`](TransferError::Truncated).
#[derive(Debug)]
pub enum TransferError {
    Io(io::Error),
    Timeout,
    /// The peer closed without writing anything — it refused the request.
    Closed,
    Truncated { got: u64, expected: u64 },
    Framing(LearnError),
    Record(RecordError),
    Checkpoint(CheckpointFailure),
}

/// Why a `FetchVotes` stream was rejected — each variant aborts catch-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    ShortHeaderPage { got: usize },
    /// Unlike recovery, an all-zero page is *not* tolerated here.
    HeaderUnmarshal,
    /// Only `Vote`, `Prepare`, and `ReconfigurationDecision` are valid.
    UnknownMessageId(u16),
    ShortBody { got: u64, expected: u64 },
    ChecksumMismatch,
    Unmarshal,
}

/// Why a fetched checkpoint was not published.
#[derive(Debug)]
pub enum CheckpointFailure {
    /// Verification failed. The temp file has been deleted.
    ///
    /// **Divergence:** the C++ aborts here. This port deletes the temp file and
    /// returns, letting the caller try another replica.
    Invalid(checkpoint::RejectReason),
    Header(String),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::Io(e) => write!(f, "learn-port I/O error: {e}"),
            TransferError::Timeout => f.write_str("learn-port operation timed out"),
            TransferError::Closed => f.write_str("peer closed without answering"),
            TransferError::Truncated { got, expected } => {
                write!(f, "peer closed after {got} of {expected} bytes")
            }
            TransferError::Framing(e) => write!(f, "malformed response: {e}"),
            TransferError::Record(e) => write!(f, "malformed vote stream: {e}"),
            TransferError::Checkpoint(e) => write!(f, "checkpoint not published: {e}"),
        }
    }
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::ShortHeaderPage { got } => {
                write!(f, "{got} of {PAGE_SIZE} header bytes")
            }
            RecordError::HeaderUnmarshal => f.write_str("record header did not parse"),
            RecordError::UnknownMessageId(id) => write!(f, "message id {id} is never logged"),
            RecordError::ShortBody { got, expected } => {
                write!(f, "{got} of {expected} body bytes")
            }
            RecordError::ChecksumMismatch => f.write_str("record checksum mismatch"),
            RecordError::Unmarshal => f.write_str("record body did not parse"),
        }
    }
}

impl std::fmt::Display for CheckpointFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointFailure::Invalid(reason) => write!(f, "verification failed: {reason}"),
            CheckpointFailure::Header(detail) => write!(f, "header unusable: {detail}"),
        }
    }
}

impl std::error::Error for TransferError {}
impl std::error::Error for RecordError {}
impl std::error::Error for CheckpointFailure {}

impl From<io::Error> for TransferError {
    fn from(e: io::Error) -> TransferError {
        TransferError::Io(e)
    }
}

/// A learn-port client. Stateless; one instance can drive any number of
/// concurrent transfers.
#[derive(Clone)]
pub struct LearnClient {
    config: LearnConfig,
    connector: Arc<dyn Connector>,
}

impl Default for LearnClient {
    fn default() -> LearnClient {
        LearnClient::with_config(LearnConfig::default())
    }
}

impl std::fmt::Debug for LearnClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LearnClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LearnClient {
    pub fn new() -> LearnClient {
        LearnClient::default()
    }

    pub fn with_config(config: LearnConfig) -> LearnClient {
        LearnClient {
            config,
            connector: Arc::new(PlainConnector),
        }
    }

    /// Use `connector` for connections (e.g. TLS).
    pub fn over(self, connector: Arc<dyn Connector>) -> LearnClient {
        LearnClient { connector, ..self }
    }

    pub fn config(&self) -> &LearnConfig {
        &self.config
    }

    /// `StatusQuery` → one [`StatusResponse`].
    pub async fn query_status(
        &self,
        addr: SocketAddr,
        request: &Header,
    ) -> Result<StatusResponse, TransferError> {
        let mut stream = self.request(addr, request).await?;
        let response = super::read_message(
            &mut stream,
            MsgKind::StatusResponse,
            self.config.limits,
            self.config.recv_timeout,
        )
        .await?;
        match response {
            Some(Msg::StatusResponse(status)) => Ok(status),
            Some(_) => Err(TransferError::Framing(LearnError::Unmarshal)),
            None => Err(TransferError::Closed),
        }
    }

    /// `FetchVotes` → a [`VoteStream`] of logged messages. An immediately empty
    /// stream means the peer does not have the requested decree.
    pub async fn fetch_votes(
        &self,
        addr: SocketAddr,
        request: &Header,
    ) -> Result<VoteStream, TransferError> {
        let stream = self.request(addr, request).await?;
        Ok(VoteStream {
            stream,
            recv_timeout: self.config.recv_timeout,
            buf: Vec::with_capacity(PAGE_SIZE as usize),
            offset: 0,
            done: false,
        })
    }

    /// `FetchCheckpoint` → a verified, durably renamed `<decree>.codex` in
    /// `dest_dir`. `expected_size` must come from a prior
    /// [`StatusResponse::checkpoint_size`] since the protocol has no in-band
    /// length. On failure the temp file is deleted.
    pub async fn fetch_checkpoint(
        &self,
        addr: SocketAddr,
        request: &Header,
        expected_size: u64,
        dest_dir: &Path,
    ) -> Result<FetchedCheckpoint, TransferError> {
        self.fetch_checkpoint_with(addr, request, expected_size, dest_dir, None)
            .await
    }

    /// Like [`fetch_checkpoint`](LearnClient::fetch_checkpoint), but raises the
    /// copied header's `max_ballot` to `raise_max_ballot` when the incoming one
    /// is lower (re-marshaling the header on the way to disk).
    ///
    /// **Divergence:** the C++ always re-marshals; the default here
    /// (`raise_max_ballot = None`) keeps the file bit-identical to its source.
    pub async fn fetch_checkpoint_with(
        &self,
        addr: SocketAddr,
        request: &Header,
        expected_size: u64,
        dest_dir: &Path,
        raise_max_ballot: Option<BallotNumber>,
    ) -> Result<FetchedCheckpoint, TransferError> {
        let decree = request.decree;
        let temp = temp_path(dest_dir);
        let mut stream = self.request(addr, request).await?;

        let result = self
            .copy_checkpoint(&mut stream, expected_size, &temp, raise_max_ballot)
            .await;
        match result {
            Ok(()) => {}
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                return Err(e);
            }
        }

        let dest = dest_dir.join(rsl_storage::dir::checkpoint_file_name(decree));
        let published = tokio::task::spawn_blocking(move || publish(&temp, &dest))
            .await
            .map_err(|e| TransferError::Io(io::Error::other(e)))?;
        published.map(|path| FetchedCheckpoint {
            path,
            decree,
            size: expected_size,
        })
    }

    async fn request(
        &self,
        addr: SocketAddr,
        request: &Header,
    ) -> Result<Box<dyn Stream>, TransferError> {
        let bytes = learn::encode_message(&Msg::Base(request.clone()))
            .expect("a base-class message always marshals");

        let mut stream =
            super::with_timeout(self.config.send_timeout, self.connector.connect(addr))
                .await?
                .map_err(TransferError::Io)?;
        write_all(&mut stream, &bytes, self.config.send_timeout).await?;
        stream.flush().await?;
        Ok(stream)
    }

    /// Optionally rewrite the header, then stream bytes through a [`RingSink`]
    /// until `expected_size` have been read in total (header included).
    async fn copy_checkpoint<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        expected_size: u64,
        temp: &Path,
        raise_max_ballot: Option<BallotNumber>,
    ) -> Result<(), TransferError> {
        let mut sink = RingSink::create(temp, self.config.ring_block()).await?;
        let mut read_so_far = 0u64;

        if let Some(floor) = raise_max_ballot {
            let (header, raw_len) = self.read_checkpoint_header(stream, expected_size).await?;
            read_so_far += raw_len;
            let mut header = header;
            if header.max_ballot < floor {
                header.max_ballot = floor;
            }
            let bytes = header
                .marshal()
                .map_err(|e| TransferError::Checkpoint(CheckpointFailure::Header(e.to_string())))?;
            sink.write_all(bytes).await?;
        }

        while read_so_far < expected_size {
            let want = (expected_size - read_so_far).min(sink.block() as u64) as usize;
            if !read_exact_or_eof(stream, &mut sink.stage()[..want], self.config.recv_timeout)
                .await?
            {
                return Err(if read_so_far == 0 {
                    TransferError::Closed
                } else {
                    TransferError::Truncated {
                        got: read_so_far,
                        expected: expected_size,
                    }
                });
            }
            sink.push(want).await?;
            read_so_far += want as u64;
        }

        sink.finish().await?;
        Ok(())
    }

    /// Read the page-rounded checkpoint header off the socket and parse it,
    /// returning it with the number of bytes consumed.
    async fn read_checkpoint_header<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        file_size: u64,
    ) -> Result<(CheckpointHeader, u64), TransferError> {
        let mut blob = vec![0u8; PAGE_SIZE as usize];
        if !read_exact_or_eof(stream, &mut blob, self.config.recv_timeout).await? {
            return Err(TransferError::Closed);
        }
        let marshal_len = u32::from_le_bytes(blob[2..6].try_into().expect("a full page"));
        let write_size = round_up_to_page(marshal_len).max(PAGE_SIZE);
        if u64::from(write_size) > file_size {
            return Err(TransferError::Checkpoint(CheckpointFailure::Header(
                format!("declared header size {write_size} exceeds the file's {file_size}"),
            )));
        }
        if write_size > PAGE_SIZE {
            blob.resize(write_size as usize, 0);
            if !read_exact_or_eof(
                stream,
                &mut blob[PAGE_SIZE as usize..],
                self.config.recv_timeout,
            )
            .await?
            {
                return Err(TransferError::Truncated {
                    got: u64::from(PAGE_SIZE),
                    expected: u64::from(write_size),
                });
            }
        }

        let header = checkpoint::read_header(&mut &blob[..], file_size)
            .map_err(|e| TransferError::Checkpoint(CheckpointFailure::Header(e.to_string())))?;
        Ok((header, u64::from(write_size)))
    }
}

impl LearnConfig {
    fn chunk_size(&self) -> usize {
        self.stream_chunk.max(PAGE_SIZE as usize)
    }

    /// [`chunk_size`](Self::chunk_size) rounded up to a [`SECTOR`] multiple
    /// for unbuffered writes.
    fn ring_block(&self) -> usize {
        self.chunk_size().next_multiple_of(SECTOR)
    }
}

/// A [`SeqWriter`] driven from async code, plus the socket staging buffer that
/// feeds it. Writes bypass the page cache so the verify pass that follows does
/// not contend with writeback.
///
/// Uses 2 write threads and 4 slots — 2 in flight, 2 spare so a socket read
/// never waits for a free slot. Each blocking `SeqWriter` call is dispatched
/// via `spawn_blocking`.
struct RingSink {
    /// `None` only while a blocking call is in flight.
    inner: Option<(SeqWriter, Vec<u8>)>,
    block: usize,
}

impl RingSink {
    /// Create `path` with a ring of `block`-sized buffers.
    async fn create(path: &Path, block: usize) -> io::Result<RingSink> {
        let config = SeqWriterConfig {
            threads: 2,
            slots: 4,
            block,
        };
        let path = path.to_path_buf();
        let writer = tokio::task::spawn_blocking(move || SeqWriter::create_with(&path, config))
            .await
            .map_err(io::Error::other)??;
        Ok(RingSink {
            inner: Some((writer, vec![0u8; block])),
            block,
        })
    }

    fn block(&self) -> usize {
        self.block
    }

    fn stage(&mut self) -> &mut [u8] {
        &mut self
            .inner
            .as_mut()
            .expect("the sink is live between calls")
            .1
    }

    async fn push(&mut self, n: usize) -> io::Result<()> {
        self.with(move |writer, stage| writer.write_all(&stage[..n]))
            .await
    }

    async fn write_all(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        self.with(move |writer, _| writer.write_all(&bytes)).await
    }

    async fn finish(mut self) -> io::Result<u64> {
        let (writer, _) = self.inner.take().expect("the sink is live until finished");
        tokio::task::spawn_blocking(move || writer.finish())
            .await
            .map_err(io::Error::other)?
    }

    async fn with<T, F>(&mut self, f: F) -> io::Result<T>
    where
        F: FnOnce(&mut SeqWriter, &mut Vec<u8>) -> io::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let (mut writer, mut stage) = self.inner.take().expect("the sink is live between calls");
        let (result, writer, stage) = tokio::task::spawn_blocking(move || {
            let result = f(&mut writer, &mut stage);
            (result, writer, stage)
        })
        .await
        .map_err(io::Error::other)?;
        self.inner = Some((writer, stage));
        result
    }
}

/// Verify a copied checkpoint and publish it durably, or delete it.
fn publish(temp: &Path, dest: &Path) -> Result<PathBuf, TransferError> {
    let verification = match checkpoint::verify_file(temp) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(temp);
            return Err(TransferError::Io(e));
        }
    };
    if let Some(reason) = verification.reject {
        let _ = std::fs::remove_file(temp);
        return Err(TransferError::Checkpoint(CheckpointFailure::Invalid(
            reason,
        )));
    }

    let durability = SyncAll;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temp)?;
    durability.rename_durable(&file, temp, dest)?;
    Ok(dest.to_path_buf())
}

/// Generate a unique temp path using process id + counter.
fn temp_path(dir: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("Codex{}-{n}.tmp", std::process::id()))
}

/// A checkpoint that has been fetched, verified and published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedCheckpoint {
    pub path: PathBuf,
    pub decree: u64,
    pub size: u64,
}

/// The `FetchVotes` response, parsed record by record.
///
/// Records are page-aligned: one 512-byte header page, then the rest of the
/// padded body, then a Rabin-64 checksum. [`next`](VoteStream::next) yields
/// `Ok(None)` at a clean end (EOF on a page boundary). A torn record, zero
/// page, or bad checksum all abort catch-up.
pub struct VoteStream {
    stream: Box<dyn Stream>,
    recv_timeout: Duration,
    buf: Vec<u8>,
    offset: u64,
    done: bool,
}

impl VoteStream {
    /// The next logged message, or `None` at end of stream.
    pub async fn next(&mut self) -> Result<Option<Msg>, TransferError> {
        if self.done {
            return Ok(None);
        }
        match self.read_one().await {
            Ok(msg) => {
                if msg.is_none() {
                    self.done = true;
                }
                Ok(msg)
            }
            Err(e) => {
                self.done = true;
                Err(e)
            }
        }
    }

    pub fn bytes_read(&self) -> u64 {
        self.offset
    }

    async fn read_one(&mut self) -> Result<Option<Msg>, TransferError> {
        self.buf.clear();
        self.buf.resize(PAGE_SIZE as usize, 0);
        let got = read_up_to(&mut self.stream, &mut self.buf, self.recv_timeout).await?;
        if got == 0 {
            return Ok(None);
        }
        if got < PAGE_SIZE as usize {
            return Err(TransferError::Record(RecordError::ShortHeaderPage { got }));
        }

        let header =
            unmarshal_base(&self.buf).ok_or(TransferError::Record(RecordError::HeaderUnmarshal))?;
        if !is_loggable(header.msg_id) {
            return Err(TransferError::Record(RecordError::UnknownMessageId(
                header.msg_id,
            )));
        }

        let padded_len = round_up_to_page(header.un_marshal_len);
        let mut filled = PAGE_SIZE as usize;
        while filled < padded_len as usize {
            let want = (padded_len as usize - filled).min(64 * 1024);
            self.buf.resize(filled + want, 0);
            let got =
                read_up_to(&mut self.stream, &mut self.buf[filled..], self.recv_timeout).await?;
            filled += got;
            if got < want {
                return Err(TransferError::Record(RecordError::ShortBody {
                    got: filled as u64 - u64::from(PAGE_SIZE),
                    expected: u64::from(padded_len) - u64::from(PAGE_SIZE),
                }));
            }
        }

        let message = &self.buf[..header.un_marshal_len as usize];
        if !verify_checksum(message) {
            return Err(TransferError::Record(RecordError::ChecksumMismatch));
        }
        let kind = kind_of(header.msg_id).expect("checked loggable above");
        let msg =
            Msg::unmarshal(kind, message).ok_or(TransferError::Record(RecordError::Unmarshal))?;

        self.offset += u64::from(padded_len);
        Ok(Some(msg))
    }
}

/// The three ids that are ever written to a log.
fn is_loggable(msg_id: u16) -> bool {
    msg_id == MSG_VOTE || msg_id == MSG_PREPARE || msg_id == MSG_RECONFIGURATION_DECISION
}

/// Which parser a logged id selects.
fn kind_of(msg_id: u16) -> Option<MsgKind> {
    match msg_id {
        MSG_VOTE => Some(MsgKind::Vote),
        MSG_PREPARE => Some(MsgKind::Prepare),
        MSG_RECONFIGURATION_DECISION => Some(MsgKind::Base),
        _ => None,
    }
}

/// Fill `buf` as far as the peer allows; short return means stream ended.
async fn read_up_to<R>(r: &mut R, buf: &mut [u8], timeout: Duration) -> Result<usize, TransferError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut filled = 0;
    while filled < buf.len() {
        let got = super::with_timeout(timeout, r.read(&mut buf[filled..])).await??;
        if got == 0 {
            break;
        }
        filled += got;
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_logged_ids_are_accepted_mid_stream() {
        assert!(is_loggable(MSG_VOTE));
        assert!(is_loggable(MSG_PREPARE));
        assert!(is_loggable(MSG_RECONFIGURATION_DECISION));
        for id in [0u16, 2, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14] {
            assert!(!is_loggable(id), "id {id} must not be accepted");
        }
    }

    #[test]
    fn temp_paths_do_not_collide() {
        let dir = Path::new("/tmp");
        assert_ne!(temp_path(dir), temp_path(dir));
    }
}
