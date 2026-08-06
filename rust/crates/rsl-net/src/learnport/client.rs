//! The learn-port client: the three "go and get it" paths a lagging replica
//! runs — `SendStatusRequestMessage`/`CopyCheckpointFromReplica`
//! (`legislator.cpp:1367`), `LearnVotes` (`legislator.cpp:3719`) and
//! `CopyCheckpoint` (`legislator.cpp:5485`).
//!
//! Each one is: connect, write one request, read until the peer closes. There is
//! no reply envelope and no error code — a peer that will not serve the request
//! just closes, so a short stream *is* the failure signal.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rsl_storage::checkpoint::{self, CheckpointHeader};
use rsl_storage::durability::{Durability, SyncAll};
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

/// Why a learn-port transfer failed.
///
/// Note what is *not* here: there is no "server said no". A refusal arrives as
/// [`Closed`](TransferError::Closed) (nothing at all) or
/// [`Truncated`](TransferError::Truncated) (a partial stream), because that is
/// all the protocol can express.
#[derive(Debug)]
pub enum TransferError {
    /// Socket or file I/O failed.
    Io(io::Error),
    /// One socket operation exceeded [`LearnConfig::recv_timeout`] /
    /// [`LearnConfig::send_timeout`].
    Timeout,
    /// The peer closed without writing anything: it refused the request.
    Closed,
    /// The peer closed part-way through.
    Truncated { got: u64, expected: u64 },
    /// The response's own learn framing was malformed.
    Framing(LearnError),
    /// A record in a `FetchVotes` stream was malformed.
    Record(RecordError),
    /// The copied checkpoint did not verify, or could not be published.
    Checkpoint(CheckpointFailure),
}

/// Why a `FetchVotes` stream was rejected. Every one of these is
/// `Legislator::ReadNextMessage` returning `false` with `restore == false`
/// (`legislator.cpp:3851`), which aborts the whole catch-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Fewer than [`PAGE_SIZE`] bytes arrived where a record header must start
    /// (`legislator.cpp:3873`).
    ShortHeaderPage { got: usize },
    /// The header page did not parse (`legislator.cpp:3882`). Unlike recovery,
    /// an all-zero page is *not* tolerated here: `restore` is false in
    /// `LearnVotes`, so the zero-stream escape at `legislator.cpp:3886` is
    /// unreachable and a zero page is hard corruption.
    HeaderUnmarshal,
    /// A message id other than `Vote`, `Prepare` or `ReconfigurationDecision`
    /// (`legislator.cpp:3897`).
    UnknownMessageId(u16),
    /// The record's body did not arrive in full (`legislator.cpp:3930`).
    ShortBody { got: u64, expected: u64 },
    /// The record's own Rabin-64 did not match (`legislator.cpp:3951`). A
    /// close, never a resynchronize.
    ChecksumMismatch,
    /// The body failed to parse despite a good checksum
    /// (`legislator.cpp:3973`).
    Unmarshal,
}

/// Why a fetched checkpoint was not published.
#[derive(Debug)]
pub enum CheckpointFailure {
    /// The copied file failed [`checkpoint::verify_file`]. The temp file has
    /// been deleted.
    ///
    /// **Divergence:** the C++ `LogAssert(false)`s here — "terminating the
    /// process to prevent codex corruption" (`legislator.cpp:5573`). This port
    /// deletes the temp file and returns, leaving the caller to try another
    /// replica; nothing corrupt has been published either way.
    Invalid(checkpoint::RejectReason),
    /// The header could not be parsed while rewriting it.
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

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// A learn-port client. Stateless apart from its [`LearnConfig`] and its
/// [`Connector`]; one instance can drive any number of concurrent transfers.
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
    /// A client with the C++ default timeouts.
    pub fn new() -> LearnClient {
        LearnClient::default()
    }

    /// A client with explicit configuration.
    pub fn with_config(config: LearnConfig) -> LearnClient {
        LearnClient {
            config,
            connector: Arc::new(PlainConnector),
        }
    }

    /// The same client, connecting through `connector` —
    /// `tls.connector()` for a TLS deployment.
    pub fn over(self, connector: Arc<dyn Connector>) -> LearnClient {
        LearnClient { connector, ..self }
    }

    /// The configuration in force.
    pub fn config(&self) -> &LearnConfig {
        &self.config
    }

    /// `StatusQuery` → one [`StatusResponse`] (`legislator.cpp:1367-1400`).
    ///
    /// [`TransferError::Closed`] is a peer that refused to answer — a primary
    /// relinquishing, in the C++.
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

    /// `FetchVotes` → a stream of logged messages (`LearnVotes`,
    /// `legislator.cpp:3719`).
    ///
    /// The returned [`VoteStream`] parses the raw log bytes page-wise. An
    /// *immediately* empty stream (the first
    /// [`next`](VoteStream::next) returning `Ok(None)`) is the peer refusing:
    /// it does not have the decree. The C++ makes no distinction — `LearnVotes`
    /// simply falls out of its loop and returns `false` — so neither does this,
    /// beyond letting the caller count what arrived.
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
    /// `dest_dir` (`CopyCheckpoint`, `legislator.cpp:5485`).
    ///
    /// `expected_size` comes from a prior [`StatusResponse::checkpoint_size`]:
    /// the protocol has no in-band length, so the client must already know how
    /// many bytes to expect — that is the only reason this parameter exists.
    ///
    /// On any failure the temp file is deleted and nothing is published.
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

    /// [`fetch_checkpoint`](LearnClient::fetch_checkpoint) with the C++'s
    /// header rewrite: "reset the maxballot in the header"
    /// (`legislator.cpp:5535-5541`) raises the copied header's `max_ballot` to
    /// `raise_max_ballot` when the incoming one is lower, and the header is
    /// re-marshaled on the way to disk.
    ///
    /// **Divergence:** the C++ *always* takes that path, so a copied checkpoint
    /// is always a re-marshal of the original header rather than a byte copy.
    /// The default here is the byte copy (`raise_max_ballot = None`), which
    /// keeps a fetched file bit-identical to its source and makes an interop
    /// assertion possible; pass `Some(ballot)` for the C++ behaviour. The two
    /// differ only in bytes no reader inspects — the header's own checksum
    /// field is never computed or verified (see the `rsl-storage` whitelist) —
    /// plus the ballot itself.
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
                // `lError: seqWrite->DoDispose(); DeleteFileA(file);`
                // (legislator.cpp:5605).
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

    /// Connect, write the request, and hand back the socket positioned at the
    /// start of the response.
    async fn request(
        &self,
        addr: SocketAddr,
        request: &Header,
    ) -> Result<Box<dyn Stream>, TransferError> {
        let bytes = learn::encode_message(&Msg::Base(request.clone()))
            .expect("a base-class message always marshals");

        // The connect *and*, for TLS, the handshake are under the send timeout:
        // the C++ sets `SO_SNDTIMEO`/`SO_RCVTIMEO` on the socket before
        // `SslSocket::Connect` runs its SSPI loop, so the handshake inherits the
        // same budget (`StreamIO.cpp:82-95`).
        let mut stream =
            super::with_timeout(self.config.send_timeout, self.connector.connect(addr))
                .await?
                .map_err(TransferError::Io)?;
        write_all(&mut stream, &bytes, self.config.send_timeout).await?;
        stream.flush().await?;
        Ok(stream)
    }

    /// The `CopyCheckpoint` body: optionally rewrite the header, then copy
    /// bytes until `expected_size` have been read *in total*
    /// (`legislator.cpp:5551` counts `reader.BytesRead()`, the header
    /// included).
    async fn copy_checkpoint<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        expected_size: u64,
        temp: &Path,
        raise_max_ballot: Option<BallotNumber>,
    ) -> Result<(), TransferError> {
        let mut file = tokio::fs::File::create(temp).await?;
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
            tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;
        }

        let mut chunk = vec![0u8; self.config.chunk_size()];
        while read_so_far < expected_size {
            let want = (expected_size - read_so_far).min(chunk.len() as u64) as usize;
            if !read_exact_or_eof(stream, &mut chunk[..want], self.config.recv_timeout).await? {
                return Err(if read_so_far == 0 {
                    TransferError::Closed
                } else {
                    TransferError::Truncated {
                        got: read_so_far,
                        expected: expected_size,
                    }
                });
            }
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk[..want]).await?;
            read_so_far += want as u64;
        }

        file.flush().await?;
        Ok(())
    }

    /// Read exactly the page-rounded checkpoint header off the socket and parse
    /// it, returning it with the number of bytes consumed. Mirrors
    /// `CheckpointHeader::UnMarshal(StreamReader*)` (`legislator.cpp:1032`):
    /// one page first, then the rest of the declared length.
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

        // The parse decisions themselves are `rsl-storage`'s, unchanged.
        let header = checkpoint::read_header(&mut &blob[..], file_size)
            .map_err(|e| TransferError::Checkpoint(CheckpointFailure::Header(e.to_string())))?;
        Ok((header, u64::from(write_size)))
    }
}

impl LearnConfig {
    /// The streaming chunk, never below one page (a smaller one would make the
    /// checkpoint copy issue absurdly many syscalls without changing a byte).
    fn chunk_size(&self) -> usize {
        self.stream_chunk.max(PAGE_SIZE as usize)
    }
}

/// Verify a copied checkpoint and publish it durably, or delete it.
///
/// `VerifyCheckpoint(file)` then `CheckpointDone` → `MoveFileEx(...,
/// MOVEFILE_WRITE_THROUGH)` (`legislator.cpp:5570-5583`, `:5645`). The Linux
/// spelling of that rename is [`Durability::rename_durable`].
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
    let file = std::fs::File::open(temp)?;
    durability.rename_durable(&file, temp, dest)?;
    Ok(dest.to_path_buf())
}

/// `GetTempFileNameA(m_tempDir, "Codex", 0, file)` (`legislator.cpp:5497`).
/// Uniqueness comes from the process id plus a counter, so two concurrent
/// fetches in one process cannot collide either.
fn temp_path(dir: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("Codex{}-{n}.tmp", std::process::id()))
}

/// A checkpoint that has been fetched, verified and published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedCheckpoint {
    /// Final path — `<dest_dir>/<decree>.codex`.
    pub path: PathBuf,
    /// The decree it was fetched for.
    pub decree: u64,
    /// Bytes transferred (the `expected_size` that was asked for).
    pub size: u64,
}

// ---------------------------------------------------------------------------
// The vote stream
// ---------------------------------------------------------------------------

/// The `FetchVotes` response, parsed record by record.
///
/// The response is raw log bytes, so it is read exactly the way a log file is:
/// one 512-byte page for the header, then the rest of
/// `RoundUpToPage(un_marshal_len)`, then the record's own Rabin-64
/// (`Legislator::ReadNextMessage`, `legislator.cpp:3851`, with `restore =
/// false`).
///
/// [`next`](VoteStream::next) yields `Ok(None)` at a clean end — EOF landing
/// exactly on a page boundary. Anything else that ends the stream is an error:
/// with `restore` false there is no tolerated tail, so a torn record, a zero
/// page or a bad checksum all abort the catch-up rather than truncating it.
///
/// This is an inherent `async fn next`, not a `futures::Stream` impl: the crate
/// has no futures-core dependency and this is the whole surface a caller needs.
/// Wrapping it in a `Stream` is three lines in a consumer that wants one.
pub struct VoteStream {
    stream: Box<dyn Stream>,
    recv_timeout: Duration,
    buf: Vec<u8>,
    offset: u64,
    done: bool,
}

impl VoteStream {
    /// The next logged message, or `Ok(None)` at a clean end of stream.
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

    /// Bytes consumed by the records yielded so far — the stream's equivalent of
    /// a log offset.
    pub fn bytes_read(&self) -> u64 {
        self.offset
    }

    async fn read_one(&mut self) -> Result<Option<Msg>, TransferError> {
        // `stream->Read(buf, s_PageSize, &bytesRead)` (legislator.cpp:3865).
        self.buf.clear();
        self.buf.resize(PAGE_SIZE as usize, 0);
        let got = read_up_to(&mut self.stream, &mut self.buf, self.recv_timeout).await?;
        if got == 0 {
            // `ERROR_HANDLE_EOF` — the clean end (legislator.cpp:3869).
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
        // Bounded growth, as everywhere else in this crate: a corrupt length
        // near 4 GiB costs one chunk, not a 4 GiB allocation.
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

/// The three ids that are ever written to a log, and therefore the only three a
/// `FetchVotes` stream may carry (`legislator.cpp:3897`).
fn is_loggable(msg_id: u16) -> bool {
    msg_id == MSG_VOTE || msg_id == MSG_PREPARE || msg_id == MSG_RECONFIGURATION_DECISION
}

/// Which parser a logged id selects (`Legislator::UnMarshalMessage`).
fn kind_of(msg_id: u16) -> Option<MsgKind> {
    match msg_id {
        MSG_VOTE => Some(MsgKind::Vote),
        MSG_PREPARE => Some(MsgKind::Prepare),
        MSG_RECONFIGURATION_DECISION => Some(MsgKind::Base),
        _ => None,
    }
}

/// Fill `buf` as far as the peer allows; a short return means the stream ended.
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
