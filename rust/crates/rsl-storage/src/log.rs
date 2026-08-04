//! The log (`<decree>.log`) file: appended messages, the decree→offset index,
//! and the startup recovery scan.
//!
//! ## On-disk layout
//!
//! A log is a bare concatenation of records. There is no file header and no
//! trailer; the file *is* the record stream.
//!
//! ```text
//! +-----------------------------------------------+ 0
//! | marshaled message (un_marshal_len bytes)       |
//! | pad to RoundUpToPage(un_marshal_len)           |   record 0
//! +-----------------------------------------------+ padded_len
//! | marshaled message | pad                        |   record 1
//! +-----------------------------------------------+
//! | ...                                           |
//! +-----------------------------------------------+ data_len
//! ```
//!
//! Each record is one message marshaled by `rsl-wire` — its own header carries
//! the length and the Rabin-64 that covers it — padded out to a 512-byte
//! boundary. The checksum covers only the message body, never the pad, which is
//! why a reader tolerates arbitrary pad bytes ([`scan`] accepts the corpus's
//! `garbage-pad` sample) while this writer always zeroes them: the recovery scan
//! treats an all-zero header page as a clean end-of-log, and that only works if
//! the tail of the file is genuinely zero.
//!
//! Only three message ids are ever logged (`Legislator::ReadNextMessage`,
//! `legislator.cpp:3897`): [`MSG_VOTE`], [`MSG_PREPARE`] and
//! [`MSG_RECONFIGURATION_DECISION`]. Anything else in the stream is corruption.
//!
//! ## Recovery
//!
//! [`scan`] is the port of the `ReadNextMessage` loop that `RestoreState`
//! (`legislator.cpp:5993`) drives with `restore = true`. It walks records
//! page-aligned from offset 0 and ends in exactly one of three ways, matching
//! the C++ decision for decision:
//!
//! * [`Outcome::Accept`] — every record valid, consumed exactly to EOF.
//! * [`Outcome::Stop`] — valid records then a *tolerated* tail: an all-zero
//!   region, a torn last record, or a trailing checksum mismatch over zeros.
//!   Records before [`ScanResult::stop_offset`] are kept; the tail is discarded
//!   and overwritten by the next append.
//! * [`Outcome::Reject`] — hard corruption. The C++ `RestoreState` returns
//!   `false` here and the replica refuses to start.
//!
//! ## Divergences from C++
//!
//! * **Zeroed pads on write** (see above). The Windows writer hands
//!   `WriteFileGather` whatever the marshal buffer held past the message —
//!   zero for votes (`VirtualAlloc`), heap garbage for other paths.
//! * **[`DecreeIndex::add_message`] returns an error** where
//!   `LogFile::AddMessage` `LogAssert`-aborts on an out-of-sequence vote
//!   (`legislator.cpp:722`).
//! * **[`RejectReason::RecordUnmarshal`]** has no Phase-3a corpus sample: it is
//!   the C++ `UnMarshalMessage` failure at `legislator.cpp:3973`, which sits
//!   *after* the checksum test and so is unreachable for any record whose
//!   Rabin-64 verifies. The Phase-3a extraction stops at the checksum and never
//!   emits this `detail` string.

use std::fs::File;
use std::io::{self, IoSlice, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rsl_wire::messages::{
    unmarshal_base, verify_checksum, Header, Msg, MsgKind, MSG_PREPARE,
    MSG_RECONFIGURATION_DECISION, MSG_VOTE,
};

use crate::durability::{Durability, OpenMode, StorageFile, SyncAll};
use crate::{round_up_to_page, PAGE_SIZE};

/// `MAX_SINGLE_IO_SIZE` (`legislator.cpp:21`) — the largest single unbuffered
/// I/O the Windows engine issues. POSIX has no such limit, but keeping append
/// batches bounded by it keeps write sizes (and therefore benchmarks) comparable
/// with the original.
pub const MAX_SINGLE_IO_SIZE: usize = 32 * 1024 * 1024;

/// How many buffers one `writev` may carry. Each record contributes at most two
/// (its bytes and its pad), so this is 32 records per system call. Well under
/// Linux's `IOV_MAX` of 1024, and small enough to live on the stack.
const IOV_CHUNK: usize = 64;

/// How much of a record body the scanner reads (and allocates) at a time.
const BODY_READ_CHUNK: usize = 64 * 1024;

/// A page of zeros, the source of every pad this writer emits.
static ZERO_PAGE: [u8; PAGE_SIZE as usize] = [0; PAGE_SIZE as usize];

/// Is `msg_id` one of the three ids the engine ever writes to a log?
/// (`legislator.cpp:3897`.)
pub fn is_loggable(msg_id: u16) -> bool {
    msg_id == MSG_VOTE || msg_id == MSG_PREPARE || msg_id == MSG_RECONFIGURATION_DECISION
}

/// Which concrete parser a logged message id selects
/// (`Legislator::UnMarshalMessage`, `legislator.cpp:1482`).
fn kind_of(msg_id: u16) -> Option<MsgKind> {
    match msg_id {
        MSG_VOTE => Some(MsgKind::Vote),
        MSG_PREPARE => Some(MsgKind::Prepare),
        MSG_RECONFIGURATION_DECISION => Some(MsgKind::Base),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Scan outcomes
// ---------------------------------------------------------------------------

/// The three ways a recovery scan can end. The names match the Phase-3a
/// MANIFEST `outcome` strings via [`Outcome::name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every record valid, consumed exactly to EOF.
    Accept,
    /// Valid records followed by a tolerated tail, discarded.
    Stop,
    /// Hard corruption; the C++ replica refuses to start.
    Reject,
}

impl Outcome {
    /// The MANIFEST `outcome` string.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Accept => "accept",
            Outcome::Stop => "stop-at-offset",
            Outcome::Reject => "reject",
        }
    }
}

/// Why a scan stopped early but kept what it had read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// An all-zero page with nothing but zeros after it — the clean end of a
    /// log whose tail was never written (`VerifyZeroStream`,
    /// `legislator.cpp:3879`).
    ZeroRegion,
    /// A record header followed by fewer body bytes than it declares: the last
    /// append was torn by a crash (`legislator.cpp:3930`).
    TornTail,
    /// A record whose checksum fails with nothing but zeros after it — a
    /// half-written last record (`legislator.cpp:3952`).
    TrailingChecksumMismatch,
}

/// Why a scan rejected the file outright.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// Fewer than [`PAGE_SIZE`] bytes remain: too short to be a record header,
    /// and the engine's page read fails hard.
    PartialHeaderPage,
    /// The header page did not parse and is not part of a zero tail.
    HeaderUnmarshal,
    /// A message id that is never logged (`legislator.cpp:3897`).
    UnknownMessageId,
    /// A record's Rabin-64 did not match, with non-zero data following.
    ChecksumMismatch,
    /// The full message failed to parse even though its checksum verified
    /// (`legislator.cpp:3973`). See the module-level divergence note.
    RecordUnmarshal,
}

/// How a scan ended, carrying the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanEnd {
    /// Consumed exactly to EOF with every record valid.
    Eof,
    /// Stopped at [`ScanResult::stop_offset`], keeping the records before it.
    Stop(StopReason),
    /// Rejected at [`ScanResult::stop_offset`].
    Reject(RejectReason),
}

impl ScanEnd {
    /// The MANIFEST `outcome` for this ending.
    pub fn outcome(self) -> Outcome {
        match self {
            ScanEnd::Eof => Outcome::Accept,
            ScanEnd::Stop(_) => Outcome::Stop,
            ScanEnd::Reject(_) => Outcome::Reject,
        }
    }

    /// The MANIFEST `detail` wording for this ending. These strings are
    /// compared against the corpus, so they are part of the crate's contract.
    pub fn detail(self) -> &'static str {
        match self {
            ScanEnd::Eof => "all records valid to EOF",
            ScanEnd::Stop(StopReason::ZeroRegion) => "zero region (clean EOF)",
            ScanEnd::Stop(StopReason::TornTail) => "incomplete trailing message (torn tail)",
            ScanEnd::Stop(StopReason::TrailingChecksumMismatch) => {
                "trailing checksum mismatch over zero tail (discarded)"
            }
            ScanEnd::Reject(RejectReason::PartialHeaderPage) => {
                "partial header page (< s_PageSize) at tail"
            }
            ScanEnd::Reject(RejectReason::HeaderUnmarshal) => {
                "unmarshal failed on non-zero page (corrupt stream)"
            }
            ScanEnd::Reject(RejectReason::UnknownMessageId) => "unknown message id in log",
            ScanEnd::Reject(RejectReason::ChecksumMismatch) => {
                "checksum mismatch with non-zero data following (corrupt)"
            }
            ScanEnd::Reject(RejectReason::RecordUnmarshal) => {
                "failed to unmarshal message body (corrupt stream)"
            }
        }
    }

    /// Whether recovery may continue with the records read so far.
    pub fn recoverable(self) -> bool {
        !matches!(self, ScanEnd::Reject(_))
    }
}

impl std::fmt::Display for ScanEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail())
    }
}

/// The metadata the MANIFEST records for one recovered record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordInfo {
    /// Byte offset of the record within the log.
    pub offset: u64,
    /// `Message_Vote` / `Message_Prepare` / `Message_ReconfigurationDecision`.
    pub msg_id: u16,
    /// The decree this record votes on / prepares for.
    pub decree: u64,
    /// The message's own declared length — the checksum-covered region.
    pub un_marshal_len: u32,
    /// `RoundUpToPage(un_marshal_len)`: the record's on-disk footprint.
    pub padded_len: u32,
    /// The Rabin-64 stored in the message header.
    pub checksum: u64,
}

/// A record plus its bytes, yielded by [`LogScanner::next_record`].
#[derive(Debug)]
pub struct Record<'a> {
    /// Offsets, ids and lengths for this record.
    pub info: RecordInfo,
    /// The record's on-disk bytes *including* the pad.
    pub padded: &'a [u8],
}

impl Record<'_> {
    /// The marshaled message without its pad.
    pub fn message_bytes(&self) -> &[u8] {
        &self.padded[..self.info.un_marshal_len as usize]
    }

    /// Parse the message. Always `Some` for a record a scan yielded (the scan
    /// parses it to decide the record is valid); re-parsing is how a caller
    /// gets an owned [`Msg`] without the scanner's borrow.
    pub fn parse(&self) -> Option<Msg> {
        Msg::unmarshal(kind_of(self.info.msg_id)?, self.message_bytes())
    }
}

/// The result of scanning a whole log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanResult {
    /// How the scan ended.
    pub end: ScanEnd,
    /// Bytes consumed before the ending — the offset the next append starts at.
    /// For a rejection this is where the corruption begins.
    pub stop_offset: u64,
    /// Every valid record before `stop_offset`, in file order. Populated even
    /// for a rejection (the C++ logs the same prefix before giving up).
    pub records: Vec<RecordInfo>,
}

impl ScanResult {
    /// The MANIFEST `outcome` string.
    pub fn outcome(&self) -> &'static str {
        self.end.outcome().name()
    }

    /// The MANIFEST `detail` string.
    pub fn detail(&self) -> &'static str {
        self.end.detail()
    }

    /// Rebuild the decree→offset index from the recovered records.
    pub fn index(&self) -> Result<DecreeIndex, IndexError> {
        let mut index = DecreeIndex::new();
        for record in &self.records {
            index.add_message(record.msg_id, record.decree, record.padded_len)?;
        }
        Ok(index)
    }
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// A streaming recovery scan: hands back one record at a time and never holds
/// more than a single record in memory.
///
/// Iteration ends when [`next_record`](Self::next_record) returns `None`; the
/// ending is then available from [`end`](Self::end).
pub struct LogScanner<R> {
    inner: R,
    offset: u64,
    buf: Vec<u8>,
    info: Option<RecordInfo>,
    end: Option<ScanEnd>,
}

impl LogScanner<File> {
    /// Scan `path` from the beginning.
    pub fn open(path: &Path) -> io::Result<LogScanner<File>> {
        Ok(LogScanner::new(File::open(path)?))
    }
}

impl<R: Read> LogScanner<R> {
    /// Scan the record stream `inner`, which must start on a record boundary.
    pub fn new(inner: R) -> LogScanner<R> {
        LogScanner {
            inner,
            offset: 0,
            buf: Vec::with_capacity(PAGE_SIZE as usize),
            info: None,
            end: None,
        }
    }

    /// Start counting offsets at `offset` rather than 0. Used when seeking into
    /// the middle of a log to replay from a known record boundary, so the
    /// reported offsets stay file-absolute.
    pub fn at_offset(mut self, offset: u64) -> LogScanner<R> {
        self.offset = offset;
        self
    }

    /// How the scan ended, or `None` while records remain.
    pub fn end(&self) -> Option<ScanEnd> {
        self.end
    }

    /// The offset just past the last record yielded — the scan's stop offset
    /// once it has ended.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The next valid record, or `None` once the scan has ended (for any of the
    /// three reasons — check [`end`](Self::end)).
    ///
    /// `Err` means a real I/O failure, never a malformed log.
    pub fn next_record(&mut self) -> io::Result<Option<Record<'_>>> {
        if self.end.is_some() {
            return Ok(None);
        }
        match self.read_one()? {
            Some(info) => {
                self.info = Some(info);
                let record = Record {
                    info,
                    padded: &self.buf[..info.padded_len as usize],
                };
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Read and validate the record at the current offset, updating `self.end`
    /// when the scan is over.
    fn read_one(&mut self) -> io::Result<Option<RecordInfo>> {
        // ReadNextMessage reads one page first (legislator.cpp:3865). Nothing
        // left at all is the clean end of the stream; a short read is a record
        // header that cannot exist.
        self.buf.clear();
        self.buf.resize(PAGE_SIZE as usize, 0);
        let got = read_up_to(&mut self.inner, &mut self.buf)?;
        if got == 0 {
            self.end = Some(ScanEnd::Eof);
            return Ok(None);
        }
        if got < PAGE_SIZE as usize {
            self.end = Some(ScanEnd::Reject(RejectReason::PartialHeaderPage));
            return Ok(None);
        }

        let Some(header) = unmarshal_base(&self.buf) else {
            // legislator.cpp:3879 — an unparsable page is the clean end of the
            // log only if it, and everything after it, is zero.
            if is_zero(&self.buf) && self.rest_is_zero()? {
                self.end = Some(ScanEnd::Stop(StopReason::ZeroRegion));
            } else {
                self.end = Some(ScanEnd::Reject(RejectReason::HeaderUnmarshal));
            }
            return Ok(None);
        };

        if !is_loggable(header.msg_id) {
            self.end = Some(ScanEnd::Reject(RejectReason::UnknownMessageId));
            return Ok(None);
        }

        let padded_len = round_up_to_page(header.un_marshal_len);
        // Read the body in bounded steps, growing the buffer only as bytes
        // actually arrive. A corrupt header can declare a length near 4 GiB;
        // the C++ `ResizeBuffer`s to it outright, which on a torn log means a
        // multi-gigabyte allocation for a record that was never written.
        let mut filled = PAGE_SIZE as usize;
        while filled < padded_len as usize {
            let want = (padded_len as usize - filled).min(BODY_READ_CHUNK);
            self.buf.resize(filled + want, 0);
            let got = read_up_to(&mut self.inner, &mut self.buf[filled..])?;
            filled += got;
            if got < want {
                // legislator.cpp:3930 — the body ran into EOF. Under restore
                // this is the tolerated last incomplete message.
                self.end = Some(ScanEnd::Stop(StopReason::TornTail));
                return Ok(None);
            }
        }

        if !verify_checksum(&self.buf[..header.un_marshal_len as usize]) {
            // legislator.cpp:3952 — a bad checksum is the half-written last
            // record if nothing but zeros follows, otherwise real corruption.
            if self.rest_is_zero()? {
                self.end = Some(ScanEnd::Stop(StopReason::TrailingChecksumMismatch));
            } else {
                self.end = Some(ScanEnd::Reject(RejectReason::ChecksumMismatch));
            }
            return Ok(None);
        }

        // legislator.cpp:3973 — the engine parses the message before accepting
        // it. Unreachable for a record whose checksum verified; see the module
        // divergence note.
        let kind = kind_of(header.msg_id).expect("loggable id");
        if Msg::unmarshal(kind, &self.buf[..header.un_marshal_len as usize]).is_none() {
            self.end = Some(ScanEnd::Reject(RejectReason::RecordUnmarshal));
            return Ok(None);
        }

        let info = record_info(&header, self.offset, padded_len);
        self.offset += u64::from(padded_len);
        Ok(Some(info))
    }

    /// `Legislator::VerifyZeroStream` (`legislator.cpp:3980`): is everything
    /// from here to EOF zero? Stops at the first non-zero byte — the scan ends
    /// either way, so there is nothing left to read past.
    fn rest_is_zero(&mut self) -> io::Result<bool> {
        let mut chunk = [0u8; 8192];
        loop {
            let got = read_up_to(&mut self.inner, &mut chunk)?;
            if got == 0 {
                return Ok(true);
            }
            if !is_zero(&chunk[..got]) {
                return Ok(false);
            }
        }
    }
}

fn record_info(header: &Header, offset: u64, padded_len: u32) -> RecordInfo {
    RecordInfo {
        offset,
        msg_id: header.msg_id,
        decree: header.decree,
        un_marshal_len: header.un_marshal_len,
        padded_len,
        checksum: header.checksum,
    }
}

/// Fill `buf` as far as the reader allows, returning how many bytes landed.
/// A short return means EOF, not an error.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn is_zero(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}

/// Scan a whole record stream and collect the outcome.
pub fn scan<R: Read>(inner: R) -> io::Result<ScanResult> {
    let mut scanner = LogScanner::new(inner);
    let mut records = Vec::new();
    while let Some(record) = scanner.next_record()? {
        records.push(record.info);
    }
    Ok(ScanResult {
        end: scanner.end().expect("scan ended"),
        stop_offset: scanner.offset(),
        records,
    })
}

/// Scan an in-memory log image. This is the exact shape of the Phase-3a C++
/// oracle `rsl_storage::ScanLog`, and cannot fail: a slice has no I/O errors.
pub fn scan_bytes(buf: &[u8]) -> ScanResult {
    scan(buf).expect("in-memory scan cannot fail")
}

/// Scan a log file on disk.
pub fn scan_file(path: &Path) -> io::Result<ScanResult> {
    scan(io::BufReader::new(File::open(path)?))
}

// ---------------------------------------------------------------------------
// Decree index
// ---------------------------------------------------------------------------

/// An out-of-sequence vote offered to [`DecreeIndex::add_message`], where the
/// C++ `LogAssert`-aborts (`legislator.cpp:722`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexError {
    /// The decree that was offered.
    pub decree: u64,
    /// The highest decree already in the index.
    pub max_decree: u64,
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "vote for decree {} is not {} or {} (out of sequence)",
            self.decree,
            self.max_decree,
            self.max_decree + 1
        )
    }
}

impl std::error::Error for IndexError {}

/// decree → offset within one log file: the port of `LogFile::m_decreeOffsets`
/// (`legislator.h:208`).
///
/// Only votes are indexed. Decrees are contiguous from
/// [`min_decree`](DecreeIndex::min_decree), so the
/// map is a vector: `offsets[decree - min_decree]`. A re-vote on the current
/// maximum decree (a higher ballot for the same decree) replaces its entry, so
/// a lookup always finds the *last* record for that decree — which is the one
/// recovery kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecreeIndex {
    min_decree: u64,
    offsets: Vec<u64>,
    data_len: u64,
}

impl DecreeIndex {
    /// An empty index for a fresh log.
    pub fn new() -> DecreeIndex {
        DecreeIndex::default()
    }

    /// Account for a record of `padded_len` bytes, indexing it if it is a vote.
    /// (`LogFile::AddMessage`, `legislator.cpp:712`.)
    pub fn add_message(
        &mut self,
        msg_id: u16,
        decree: u64,
        padded_len: u32,
    ) -> Result<(), IndexError> {
        if msg_id == MSG_VOTE {
            if self.offsets.is_empty() {
                self.min_decree = decree;
            } else {
                let max = self.max_decree();
                if decree != max && decree != max + 1 {
                    return Err(IndexError {
                        decree,
                        max_decree: max,
                    });
                }
                if decree == max {
                    self.offsets.pop();
                }
            }
            self.offsets.push(self.data_len);
        }
        self.data_len += u64::from(padded_len);
        Ok(())
    }

    /// The lowest indexed decree (0 when empty, as in the C++).
    pub fn min_decree(&self) -> u64 {
        self.min_decree
    }

    /// The highest indexed decree, or 0 when empty (`LogFile::MaxDecree`,
    /// `legislator.cpp:762` — the C++ returns 0 for an empty index too).
    pub fn max_decree(&self) -> u64 {
        if self.offsets.is_empty() {
            0
        } else {
            self.min_decree + self.offsets.len() as u64 - 1
        }
    }

    /// Total bytes accounted for — where the next record goes
    /// (`LogFile::m_dataLen`).
    pub fn data_len(&self) -> u64 {
        self.data_len
    }

    /// How many decrees are indexed.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Is nothing indexed yet?
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Does this log hold `decree`? (`LogFile::HasDecree`.)
    pub fn has_decree(&self, decree: u64) -> bool {
        !self.offsets.is_empty() && self.min_decree <= decree && decree <= self.max_decree()
    }

    /// The offset of `decree`'s record, or `None` if this log does not hold it.
    ///
    /// The C++ `GetOffset` `LogAssert`s on an out-of-range decree
    /// (`legislator.cpp:738`); returning `None` is the whole difference.
    pub fn offset(&self, decree: u64) -> Option<u64> {
        if !self.has_decree(decree) {
            return None;
        }
        self.offsets
            .get((decree - self.min_decree) as usize)
            .copied()
    }

    /// Bytes occupied by `decree`'s record — up to the next decree, or to the
    /// end of the data for the last one (`LogFile::GetLengthOfDecree`).
    pub fn length_of_decree(&self, decree: u64) -> Option<u64> {
        let start = self.offset(decree)?;
        let end = if decree < self.max_decree() {
            self.offset(decree + 1)?
        } else {
            self.data_len
        };
        Some(end - start)
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// An opened log file: the recovery scan's result plus the rebuilt index, and
/// the ability to replay records from any indexed decree.
///
/// This is the read side Phase 5's `ExecuteQueue` read-behind path needs: find
/// the log holding a decree ([`DecreeIndex::has_decree`]), then stream forward
/// from it ([`replay_from`](Self::replay_from)).
pub struct LogReader {
    path: PathBuf,
    file_decree: u64,
    scan: ScanResult,
    index: DecreeIndex,
}

impl LogReader {
    /// Open and scan `<dir>/<decree>.log`.
    pub fn open(dir: &Path, decree: u64) -> Result<LogReader, LogError> {
        LogReader::open_path(&dir.join(crate::dir::log_file_name(decree)), decree)
    }

    /// Open and scan a log at an explicit path, recording `file_decree` as the
    /// decree its name encodes.
    pub fn open_path(path: &Path, file_decree: u64) -> Result<LogReader, LogError> {
        let scan = scan_file(path)?;
        let index = scan.index()?;
        Ok(LogReader {
            path: path.to_path_buf(),
            file_decree,
            scan,
            index,
        })
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The decree in the file's name — the lowest decree it was opened to hold.
    /// (`LogFile::m_minDecree` is set from the first vote *written*; for a log
    /// recovered from disk the two agree.)
    pub fn file_decree(&self) -> u64 {
        self.file_decree
    }

    /// The recovery scan's result.
    pub fn scan(&self) -> &ScanResult {
        &self.scan
    }

    /// The rebuilt decree→offset index.
    pub fn index(&self) -> &DecreeIndex {
        &self.index
    }

    /// Replay records from `decree` onward, or `None` if this log does not hold
    /// it. Offsets reported by the scanner stay file-absolute.
    pub fn replay_from(&self, decree: u64) -> io::Result<Option<LogScanner<io::BufReader<File>>>> {
        match self.index.offset(decree) {
            Some(offset) => self.replay_from_offset(offset).map(Some),
            None => Ok(None),
        }
    }

    /// Replay records from a byte offset, which must be a record boundary.
    pub fn replay_from_offset(&self, offset: u64) -> io::Result<LogScanner<io::BufReader<File>>> {
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(LogScanner::new(io::BufReader::new(file)).at_offset(offset))
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Why an append or an open failed.
#[derive(Debug)]
pub enum LogError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// The log's tail is corrupt, so it cannot be opened for append. Carries
    /// the scan that found it.
    Corrupt(Box<ScanResult>),
    /// A record's bytes are not exactly the length its own header declares.
    LengthMismatch {
        /// The header's `un_marshal_len`.
        declared: u32,
        /// The buffer actually offered.
        actual: usize,
    },
    /// A record's header did not parse at all.
    NotAMessage,
    /// A message id the engine never logs (`legislator.cpp:3897`); no reader
    /// would accept the resulting file.
    NotLoggable(u16),
    /// An out-of-sequence vote (see [`IndexError`]).
    Index(IndexError),
}

impl From<io::Error> for LogError {
    fn from(e: io::Error) -> LogError {
        LogError::Io(e)
    }
}

impl From<IndexError> for LogError {
    fn from(e: IndexError) -> LogError {
        LogError::Index(e)
    }
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogError::Io(e) => write!(f, "log I/O error: {e}"),
            LogError::Corrupt(scan) => write!(
                f,
                "log is corrupt at offset {}: {}",
                scan.stop_offset,
                scan.detail()
            ),
            LogError::LengthMismatch { declared, actual } => write!(
                f,
                "record is {actual} bytes but its header declares {declared}"
            ),
            LogError::NotAMessage => f.write_str("record does not parse as a message header"),
            LogError::NotLoggable(id) => write!(f, "message id {id} is never written to a log"),
            LogError::Index(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LogError::Io(e) => Some(e),
            LogError::Index(e) => Some(e),
            _ => None,
        }
    }
}

/// Appends records to one `<decree>.log`, maintaining the decree index.
///
/// The write path is allocation-free: the caller passes already-marshaled bytes
/// (from `rsl-wire`), pads come from a shared zero page, and the scatter list is
/// reused across appends — the vectored-write equivalent of the C++
/// `WriteFileGather` group commit (`LogFile::Write`, `legislator.cpp:546`).
///
/// Durability is the caller's call, as in the engine: [`append`](Self::append)
/// only writes, [`append_durable`](Self::append_durable) writes and syncs, and
/// [`sync`](Self::sync) flushes a batch of earlier appends. The engine's
/// contract for Phase 5 is that a decree may only be acknowledged after an
/// `append_durable` (or an `append` followed by a `sync`) has returned — see
/// `DURABILITY.md`.
///
/// Creating the file is itself made durable: `open` fsyncs the *directory* when
/// it had to create the log, because on ext4/xfs an `fdatasync` of the file does
/// not publish its name. Every later append then needs only `fdatasync`.
pub struct LogWriter<D: Durability = SyncAll> {
    file: D::File,
    path: PathBuf,
    file_decree: u64,
    index: DecreeIndex,
    durability: D,
}

impl<D: Durability> std::fmt::Debug for LogWriter<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogWriter")
            .field("path", &self.path)
            .field("file_decree", &self.file_decree)
            .field("data_len", &self.data_len())
            .finish_non_exhaustive()
    }
}

/// What an append needs to know about a validated record: enough to index it
/// and to size its pad.
struct RecordShape {
    msg_id: u16,
    decree: u64,
    padded_len: u32,
}

impl LogWriter<SyncAll> {
    /// Create or open `<dir>/<decree>.log` for append with the real durability
    /// policy. An existing file is scanned first; see [`open`](Self::open).
    pub fn open(dir: &Path, decree: u64) -> Result<LogWriter<SyncAll>, LogError> {
        LogWriter::open_with(dir, decree, SyncAll)
    }
}

impl<D: Durability> LogWriter<D> {
    /// Create or open `<dir>/<decree>.log` for append.
    ///
    /// Mirrors `LogFile::Open` + `SetWritePointer` (`legislator.cpp:513`/`769`):
    /// the file is created if missing (`OPEN_ALWAYS`), and an existing one is
    /// recovered by a full scan, positioning the write pointer at the scan's
    /// stop offset so a torn or zero tail is overwritten by the next append.
    /// A [`Outcome::Reject`] scan fails with [`LogError::Corrupt`] instead of
    /// silently truncating.
    ///
    /// **Divergence:** the discarded tail is also *truncated away*, where the
    /// C++ only moves the write pointer and leaves the old bytes past it. With
    /// a seek alone, a tail longer than what the next append overwrites
    /// survives — a 188-byte torn remnant behind a fresh 512-byte record would
    /// make the *next* recovery reject a log this one already declared good.
    /// Truncating is what makes reopen → append → rescan idempotent.
    pub fn open_with(dir: &Path, decree: u64, durability: D) -> Result<LogWriter<D>, LogError> {
        let path = dir.join(crate::dir::log_file_name(decree));
        let existed = durability.exists(&path);
        let mut file = durability.open(&path, OpenMode::Append)?;

        let index = if existed {
            let scan = scan(io::BufReader::new(&mut file))?;
            if !scan.end.recoverable() {
                return Err(LogError::Corrupt(Box::new(scan)));
            }
            scan.index()?
        } else {
            // A brand-new log's *name* is not durable until the directory is.
            // Without this an `fdatasync`ed vote can still be lost, because the
            // file it landed in never existed as far as the directory is
            // concerned (see `DURABILITY.md`).
            durability.sync_new_file(&path)?;
            DecreeIndex::new()
        };

        if file.size()? > index.data_len() {
            file.set_size(index.data_len())?;
        }
        file.seek(SeekFrom::Start(index.data_len()))?;

        Ok(LogWriter {
            file,
            path,
            file_decree: decree,
            index,
            durability,
        })
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The decree in the file's name.
    pub fn file_decree(&self) -> u64 {
        self.file_decree
    }

    /// Bytes written so far (`LogFile::m_dataLen`).
    pub fn data_len(&self) -> u64 {
        self.index.data_len()
    }

    /// The decree→offset index.
    pub fn index(&self) -> &DecreeIndex {
        &self.index
    }

    /// Should the engine roll over to a new log file? `LogFile::m_dataLen >
    /// m_maxLogLen` (`legislator.cpp:5106`) — the engine additionally requires
    /// the vote to advance the decree, and names the new file after that decree.
    pub fn needs_rollover(&self, max_log_len: u64) -> bool {
        self.data_len() > max_log_len
    }

    /// Append one record. Returns its offset.
    pub fn append(&mut self, record: &[u8]) -> Result<u64, LogError> {
        self.append_batch(std::slice::from_ref(&record))
    }

    /// Append a batch of records in as few writes as possible, then make them
    /// durable. This is the group-commit shape the engine's vote path uses.
    ///
    /// **Contract:** once this returns `Ok`, every record in the batch survives
    /// power loss. A decree must not be acknowledged before it does.
    pub fn append_durable(&mut self, records: &[&[u8]]) -> Result<u64, LogError> {
        let offset = self.append_batch(records)?;
        self.sync()?;
        Ok(offset)
    }

    /// Append a batch of records. Returns the offset of the first one.
    ///
    /// Every record is padded to its own page boundary — the C++ pads per
    /// message, not per batch (`LogFile::AddMessage` sizes each record at
    /// `RoundUpToPage(GetMarshalLen())`, and the Phase-3a `multi-record` sample
    /// pins the resulting offsets).
    ///
    /// All records are validated before anything is written, so a rejected
    /// batch leaves the file untouched. A failure *during* the write can still
    /// leave a partial record on disk; that is precisely the torn tail the
    /// recovery scan discards.
    pub fn append_batch(&mut self, records: &[&[u8]]) -> Result<u64, LogError> {
        let start = self.data_len();
        if records.is_empty() {
            return Ok(start);
        }

        // Validate everything first: parse each header, check the declared
        // length against the buffer, and refuse ids no reader would accept.
        let mut shapes = Vec::with_capacity(records.len());
        for record in records {
            let header = unmarshal_base(record).ok_or(LogError::NotAMessage)?;
            if header.un_marshal_len as usize != record.len() {
                return Err(LogError::LengthMismatch {
                    declared: header.un_marshal_len,
                    actual: record.len(),
                });
            }
            if !is_loggable(header.msg_id) {
                return Err(LogError::NotLoggable(header.msg_id));
            }
            shapes.push(RecordShape {
                msg_id: header.msg_id,
                decree: header.decree,
                padded_len: round_up_to_page(header.un_marshal_len),
            });
        }

        // Reject an out-of-sequence batch before writing, by index-checking a
        // scratch copy.
        let mut next = self.index.clone();
        for shape in &shapes {
            next.add_message(shape.msg_id, shape.decree, shape.padded_len)?;
        }

        self.write_records(records, &shapes)?;
        self.index = next;
        Ok(start)
    }

    /// Issue the vectored writes for a validated batch.
    ///
    /// The scatter list is a fixed stack array, so the write path allocates
    /// nothing at all: record bytes are referenced in place and pads point into
    /// the shared [`ZERO_PAGE`]. Batches are flushed when the list fills or when
    /// they reach [`MAX_SINGLE_IO_SIZE`].
    fn write_records(&mut self, records: &[&[u8]], infos: &[RecordShape]) -> io::Result<()> {
        let mut list = [IoSlice::new(&ZERO_PAGE[..0]); IOV_CHUNK];
        let mut queued = 0usize;
        let mut n = 0usize;

        for (record, shape) in records.iter().zip(infos) {
            let pad = shape.padded_len as usize - record.len();
            list[n] = IoSlice::new(record);
            n += 1;
            queued += record.len();
            if pad > 0 {
                list[n] = IoSlice::new(&ZERO_PAGE[..pad]);
                n += 1;
                queued += pad;
            }
            // Leave room for the next record's data+pad pair.
            if n + 2 > IOV_CHUNK || queued >= MAX_SINGLE_IO_SIZE {
                write_all_vectored(&mut self.file, &mut list[..n])?;
                n = 0;
                queued = 0;
            }
        }
        if n > 0 {
            write_all_vectored(&mut self.file, &mut list[..n])?;
        }
        Ok(())
    }

    /// Flush everything appended so far to stable storage.
    ///
    /// `fdatasync`, not `fsync`: a log is only ever extended, and `fdatasync`
    /// already covers the one metadata field that matters for that — the file's
    /// length. What it does *not* cover is the directory entry, which is why
    /// [`open_with`](Self::open_with) fsyncs the directory when it creates the
    /// file.
    pub fn sync(&self) -> io::Result<()> {
        self.durability.sync_data(&self.file)
    }
}

/// Write every byte of `slices`, tolerating partial vectored writes.
fn write_all_vectored<W: Write>(file: &mut W, slices: &mut [IoSlice<'_>]) -> io::Result<()> {
    let mut bufs = slices;
    while !bufs.is_empty() {
        match file.write_vectored(bufs) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "log write made no progress",
                ))
            }
            Ok(n) => IoSlice::advance_slices(&mut bufs, n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
