//! The checkpoint (`<decree>.codex`) file: header + block-checksummed user state.
//!
//! ## On-disk layout
//!
//! ```text
//! +--------------------------------------------------+ 0
//! | CheckpointHeader, zero-padded to RoundUpToPage    |
//! +--------------------------------------------------+ header.marshal_len()
//! | user data (blockSize - 8 bytes) | Rabin-64 (8 B)  |   block 0
//! +--------------------------------------------------+
//! | ...                                              |
//! +--------------------------------------------------+
//! | user data (<= blockSize - 8)    | Rabin-64 (8 B)  |   last, possibly partial
//! +--------------------------------------------------+ header.size
//! ```
//!
//! The header itself is, in order (`CheckpointHeader::Marshal`,
//! `legislator.cpp:893`):
//!
//! * `v >= 3`: `u16` version, `u32` marshal length (page-rounded), `u64`
//!   checksum, member id, `u64` last executed decree, max ballot,
//!   [`ConfigurationInfo`].
//! * `v >= 4`: `bool` state-saved, `u64` file size, `u32` checksum block size.
//! * always: the next [`Vote`], page-rounded.
//!
//! At `v < 3` there is no header at all — the file is just the page-rounded
//! vote — and at `v == 3` the user state follows raw, with no block checksums.

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rsl_wire::marshal::{Reader, Writer};
use rsl_wire::messages::verify_checksum;
use rsl_wire::{BallotNumber, ConfigurationInfo, MarshalError, MemberId, ProtocolVersion, Vote};

use crate::durability::{Durability, OpenMode, SyncAll};
use crate::{round_up_to_page, CHECKSUM_BLOCK_SIZE, CHECKSUM_SIZE, PAGE_SIZE};

/// Why a checkpoint file was rejected.
///
/// [`RejectReason::detail`] returns the same wording the Phase-3a MANIFEST
/// records for that outcome, so corpus tests can compare reasons and not just
/// accept/reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The file is smaller than one page, so it cannot even hold a header.
    ShortFile,
    /// The version field is not one of the six valid protocol versions.
    InvalidVersion,
    /// The file is shorter than the header length it declares.
    TruncatedHeader,
    /// The header fields (or its embedded next vote, including that vote's own
    /// Rabin-64) did not parse.
    HeaderUnmarshal,
    /// `fileSize != header.size` (`RSLCheckpointStreamReader::Init`,
    /// `rsl.cpp:211`).
    SizeMismatch,
    /// A trailing block too small to carry its 8-byte checksum token.
    BlockTooShort,
    /// A block's Rabin-64 did not match its data.
    BlockChecksum,
}

impl RejectReason {
    /// The MANIFEST `detail` wording for this outcome.
    pub fn detail(self) -> &'static str {
        match self {
            RejectReason::ShortFile => "file shorter than one page",
            RejectReason::InvalidVersion => "invalid checkpoint version",
            RejectReason::TruncatedHeader => "file shorter than header length (truncated)",
            RejectReason::HeaderUnmarshal => "checkpoint header unmarshal failed",
            RejectReason::SizeMismatch => "file size differs from header m_size",
            RejectReason::BlockTooShort => "trailing block smaller than a checksum token",
            RejectReason::BlockChecksum => "block checksum mismatch",
        }
    }
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail())
    }
}

/// A header state that has no valid on-disk form, so the writer refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// `version >= 3` without a [`ConfigurationInfo`]: `CheckpointHeader::Marshal`
    /// dereferences `m_stateConfiguration` unconditionally there.
    MissingConfiguration,
    /// `checksumBlockSize` is not a multiple of [`PAGE_SIZE`]; the C++
    /// `LogAssert`s on both the read and write paths (`rsl.cpp:200`/`:467`).
    BlockSizeNotPageMultiple(u32),
    /// The block size is not larger than the 8-byte checksum token, so no block
    /// could hold any data.
    BlockSizeTooSmall(u32),
    /// The marshaled header would not fit in a `u32` length field.
    HeaderTooLarge,
    /// The embedded next vote cannot be marshaled (see [`MarshalError`]).
    Vote(MarshalError),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::MissingConfiguration => {
                write!(
                    f,
                    "checkpoint header at version >= 3 without a configuration"
                )
            }
            WriteError::BlockSizeNotPageMultiple(n) => {
                write!(
                    f,
                    "checksum block size {n} is not a multiple of {PAGE_SIZE}"
                )
            }
            WriteError::BlockSizeTooSmall(n) => {
                write!(f, "checksum block size {n} leaves no room for data")
            }
            WriteError::HeaderTooLarge => write!(f, "marshaled checkpoint header exceeds 4 GiB"),
            WriteError::Vote(e) => write!(f, "next vote cannot be marshaled: {e}"),
        }
    }
}

impl std::error::Error for WriteError {}

/// Anything that can go wrong reading or writing a checkpoint.
#[derive(Debug)]
pub enum CheckpointError {
    /// The file was rejected as malformed or corrupt.
    Reject(RejectReason),
    /// The header could not be written.
    Write(WriteError),
    /// Underlying I/O failure.
    Io(io::Error),
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointError::Reject(r) => write!(f, "checkpoint rejected: {r}"),
            CheckpointError::Write(e) => write!(f, "{e}"),
            CheckpointError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckpointError::Io(e) => Some(e),
            CheckpointError::Write(e) => Some(e),
            CheckpointError::Reject(_) => None,
        }
    }
}

impl From<io::Error> for CheckpointError {
    fn from(e: io::Error) -> Self {
        CheckpointError::Io(e)
    }
}

impl From<RejectReason> for CheckpointError {
    fn from(r: RejectReason) -> Self {
        CheckpointError::Reject(r)
    }
}

impl From<WriteError> for CheckpointError {
    fn from(e: WriteError) -> Self {
        CheckpointError::Write(e)
    }
}

impl From<CheckpointError> for io::Error {
    fn from(e: CheckpointError) -> io::Error {
        match e {
            CheckpointError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

/// Recover a [`CheckpointError`] that was wrapped in an [`io::Error`] by the
/// [`Read`] adapter, leaving genuine I/O errors alone.
fn from_io(err: io::Error) -> CheckpointError {
    match reject_reason(&err) {
        Some(reason) => CheckpointError::Reject(reason),
        None => CheckpointError::Io(err),
    }
}

/// The rejection reason behind an [`io::Error`] produced by the [`Read`]
/// adapter on [`CheckpointReader`], if it was a rejection rather than real I/O.
pub fn reject_reason(err: &io::Error) -> Option<RejectReason> {
    match err.get_ref()?.downcast_ref::<CheckpointError>()? {
        CheckpointError::Reject(r) => Some(*r),
        _ => None,
    }
}

/// The checkpoint file header. Field-for-field port of `CheckpointHeader`
/// (`RSL/src/checkpoint.h`).
///
/// `un_marshal_len` and `size` are stamped by the writer
/// ([`CheckpointHeader::marshal`] writes the computed marshal length;
/// [`CheckpointWriter::finish`] fills in the final file size), so setting them
/// by hand only matters when re-marshaling a parsed header.
#[derive(Clone, Debug)]
pub struct CheckpointHeader {
    pub version: ProtocolVersion,
    /// The length field as read off disk (always the page-rounded header size).
    pub un_marshal_len: u32,
    /// Marshaled verbatim and never verified — see the crate-level whitelist.
    pub checksum: u64,
    /// The member that produced this checkpoint.
    pub member_id: MemberId,
    /// The decree executed at this checkpoint.
    pub last_executed_decree: u64,
    pub max_ballot: BallotNumber,
    /// Required at `version >= 3`; absent below that.
    pub state_configuration: Option<ConfigurationInfo>,
    /// The vote *after* the checkpoint (decree `last_executed_decree + 1`).
    pub next_vote: Vote,
    /// Whether the application's state was saved alongside the header.
    pub state_saved: bool,
    /// Whole checkpoint file size (`v >= 4` only).
    pub size: u64,
    /// User-state block size, `0` for the unblocked v3 layout (`v >= 4` only).
    pub checksum_block_size: u32,
}

impl CheckpointHeader {
    /// A header for `next_vote` at that vote's protocol version, with the
    /// version-appropriate defaults (`state_saved`, and the standard 4 MiB
    /// checksum block size at `v >= 4`).
    pub fn new(next_vote: Vote) -> CheckpointHeader {
        let version = next_vote.header.version;
        CheckpointHeader {
            version,
            un_marshal_len: 0,
            checksum: 0,
            member_id: MemberId::empty(),
            last_executed_decree: next_vote.header.decree.wrapping_sub(1),
            max_ballot: next_vote.header.ballot.clone(),
            state_configuration: None,
            next_vote,
            state_saved: true,
            size: 0,
            checksum_block_size: if version.has_checkpoint_blocks() {
                CHECKSUM_BLOCK_SIZE
            } else {
                0
            },
        }
    }

    /// Page-rounded on-disk size of the header (`CheckpointHeader::GetMarshalLen`,
    /// `legislator.cpp:820`).
    ///
    /// `None` if the header has no on-disk form: a `v >= 3` header without a
    /// configuration, or a length that overflows `u32`.
    pub fn marshal_len(&self) -> Option<u32> {
        let vote = u64::from(round_up_to_page(self.next_vote.marshal_len()));
        let len = u64::from(self.next_vote_offset()?) + vote;
        let len = u32::try_from(len).ok()?;
        Some(round_up_to_page(len))
    }

    /// Byte offset of the embedded next vote within the marshaled header — i.e.
    /// the size of the header's own fields. `None` under the same conditions as
    /// [`CheckpointHeader::marshal_len`].
    pub fn next_vote_offset(&self) -> Option<u32> {
        let v = self.version;
        let mut len = 0u64;
        if v.has_checkpoint_header() {
            let config = self.state_configuration.as_ref()?;
            len += 2 // version
                + 4 // length
                + 8 // old checksum
                + u64::from(MemberId::base_size(v))
                + 8 // last executed decree
                + u64::from(BallotNumber::base_size(v))
                + u64::from(config.marshal_len(v));
        }
        if v.has_checkpoint_blocks() {
            len += 1 // stateSaved
                + 8 // checkpoint size
                + 4; // checksum block size
        }
        u32::try_from(len).ok()
    }

    /// Marshal the header into its page-rounded on-disk blob.
    ///
    /// The pad between the last field and the page boundary is zero-filled. (The
    /// Windows engine marshals into a fresh allocation and leaves that tail
    /// uninitialized; no reader ever looks at it, and the Phase-3a corpus zeroes
    /// it too, so this is a determinism fix rather than a format change.)
    pub fn marshal(&self) -> Result<Vec<u8>, WriteError> {
        let v = self.version;
        if v.has_checkpoint_header() && self.state_configuration.is_none() {
            return Err(WriteError::MissingConfiguration);
        }
        let marshal_len = self.marshal_len().ok_or(WriteError::HeaderTooLarge)?;

        let mut w = Writer::with_capacity(marshal_len as usize);
        if v.has_checkpoint_header() {
            w.write_u16(v.raw());
            w.write_u32(marshal_len);
            w.write_u64(self.checksum);
            self.member_id.marshal(&mut w, v);
            w.write_u64(self.last_executed_decree);
            self.max_ballot.marshal(&mut w, v);
            self.state_configuration
                .as_ref()
                .expect("checked above")
                .marshal(&mut w, v);
        }
        if v.has_checkpoint_blocks() {
            w.write_bool(self.state_saved);
            w.write_u64(self.size);
            w.write_u32(self.checksum_block_size);
        }

        // The vote goes in as its own page-rounded buffer (`Vote::GetBuffers`,
        // `message.cpp:1045`), checksum already patched in.
        let vote = self
            .next_vote
            .marshal_with_checksum()
            .map_err(WriteError::Vote)?;
        let vote_padded = round_up_to_page(vote.len() as u32) as usize;
        w.write_data(&vote);

        let mut bytes = w.into_bytes();
        bytes.resize(bytes.len() + (vote_padded - vote.len()), 0);
        // `marshal->SetMarshaledLength(marshalLen)` — the header occupies the
        // full page-rounded reservation.
        debug_assert!(bytes.len() <= marshal_len as usize);
        bytes.resize(marshal_len as usize, 0);
        Ok(bytes)
    }

    /// Parse a header out of `buf`, which must be exactly the marshaled header
    /// region (its declared length, *not* the whole file). Port of
    /// `CheckpointHeader::UnMarshal(MarshalData*)` (`legislator.cpp:948`);
    /// `None` mirrors its `false`.
    ///
    /// Verifies the embedded next vote's own Rabin-64 and, at `v >= 3`, that
    /// `max_ballot >= next_vote.ballot`.
    pub fn unmarshal(buf: &[u8]) -> Option<CheckpointHeader> {
        let mut r = Reader::new(buf);
        let version = ProtocolVersion::from_wire(r.read_u16()?)?;

        // Fields present only from v3; below that the file is a bare vote.
        let mut fields = None;
        if version.has_checkpoint_header() {
            let un_marshal_len = r.read_u32()?;
            let checksum = r.read_u64()?;
            let member_id = MemberId::unmarshal(&mut r, version)?;
            let last_executed_decree = r.read_u64()?;
            let max_ballot = BallotNumber::unmarshal(&mut r, version)?;
            let state_configuration = ConfigurationInfo::unmarshal(&mut r, version)?;
            let (state_saved, size, checksum_block_size) = if version.has_checkpoint_blocks() {
                (r.read_bool()?, r.read_u64()?, r.read_u32()?)
            } else {
                (true, 0, 0)
            };
            fields = Some((
                un_marshal_len,
                checksum,
                member_id,
                last_executed_decree,
                max_ballot,
                state_configuration,
                state_saved,
                size,
                checksum_block_size,
            ));
        } else {
            // Rewind over the version field we peeked at: the vote starts at 0.
            r.rewind_read_pointer(2);
        }

        let start = r.read_pointer() as usize;
        let next_vote = Vote::unmarshal(buf.get(start..)?)?;
        // `Vote::VerifyChecksum(marshaled + startOffset, m_unMarshalLen)`.
        let vote_len = next_vote.header.un_marshal_len as usize;
        if !verify_checksum(buf.get(start..start.checked_add(vote_len)?)?) {
            return None;
        }

        let header = match fields {
            Some((
                un_marshal_len,
                checksum,
                member_id,
                last_executed_decree,
                max_ballot,
                state_configuration,
                state_saved,
                size,
                checksum_block_size,
            )) => {
                if max_ballot < next_vote.header.ballot {
                    return None;
                }
                CheckpointHeader {
                    version,
                    un_marshal_len,
                    checksum,
                    member_id,
                    last_executed_decree,
                    max_ballot,
                    state_configuration: Some(state_configuration),
                    next_vote,
                    state_saved,
                    size,
                    checksum_block_size,
                }
            }
            // Pre-v3 the vote is the only source for these.
            None => CheckpointHeader {
                version,
                un_marshal_len: 0,
                checksum: 0,
                member_id: next_vote.header.member_id.clone(),
                last_executed_decree: next_vote.header.decree.wrapping_sub(1),
                max_ballot: next_vote.header.ballot.clone(),
                state_configuration: None,
                next_vote,
                state_saved: true,
                size: 0,
                checksum_block_size: 0,
            },
        };
        Some(header)
    }

    /// Whether the user state is written in checksummed blocks. False for the
    /// pre-v4 layout (and for a `v >= 4` header that explicitly sets block size
    /// `0`), where the state follows the header raw.
    pub fn uses_blocks(&self) -> bool {
        self.version.has_checkpoint_blocks() && self.checksum_block_size > 0
    }
}

/// What [`verify_file`] found — the mirror of the C++ `VerifyCheckpointFile`
/// used to generate the Phase-3a MANIFEST.
#[derive(Clone, Debug)]
pub struct Verification {
    /// `None` if the file was rejected before the version could be read.
    pub version: Option<u16>,
    /// Page-rounded header size, `0` if it was never parsed.
    pub header_len: u32,
    pub file_size: u64,
    /// User bytes recovered (blocks minus their checksums); `0` on rejection.
    pub user_data_size: u64,
    pub checksum_block_size: u32,
    pub state_saved: bool,
    /// `None` means the file was accepted.
    pub reject: Option<RejectReason>,
}

impl Verification {
    /// True if the file was accepted.
    pub fn accepted(&self) -> bool {
        self.reject.is_none()
    }

    /// `"accept"` / `"reject"`, matching the MANIFEST `outcome` field.
    pub fn outcome(&self) -> &'static str {
        if self.accepted() {
            "accept"
        } else {
            "reject"
        }
    }

    /// The MANIFEST `detail` wording.
    pub fn detail(&self) -> &'static str {
        match self.reject {
            None => "checkpoint valid",
            Some(r) => r.detail(),
        }
    }
}

/// Read a whole checkpoint file and verify every block, reporting the same
/// accept/reject decision (and the same `detail` wording) as the C++.
///
/// `Err` is reserved for genuine I/O failures; a malformed *file* comes back as
/// `Ok` with [`Verification::reject`] set.
pub fn verify_file(path: &Path) -> io::Result<Verification> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();

    // Parse the header first so its fields can be reported even when a later
    // check (the file-size cross-check) rejects the file — this is what the
    // MANIFEST records for e.g. the truncated sample.
    let mut verification = Verification {
        version: None,
        header_len: 0,
        file_size,
        user_data_size: 0,
        checksum_block_size: 0,
        state_saved: false,
        reject: None,
    };
    match read_header(&mut file, file_size) {
        Ok(header) => {
            verification.version = Some(header.version.raw());
            verification.header_len = header.marshal_len().unwrap_or(0);
            verification.checksum_block_size = header.checksum_block_size;
            verification.state_saved = header.state_saved;
        }
        Err(CheckpointError::Reject(reason)) => {
            verification.reject = Some(reason);
            return Ok(verification);
        }
        Err(e) => return Err(e.into()),
    }

    file.seek(SeekFrom::Start(0))?;
    let mut reader = match CheckpointReader::new(file, file_size) {
        Ok(r) => r,
        Err(CheckpointError::Reject(reason)) => {
            verification.reject = Some(reason);
            return Ok(verification);
        }
        Err(e) => return Err(e.into()),
    };

    match reader.verify_all() {
        Ok(user_data_size) => verification.user_data_size = user_data_size,
        Err(CheckpointError::Reject(reason)) => verification.reject = Some(reason),
        Err(e) => return Err(e.into()),
    }
    Ok(verification)
}

/// Streaming reader over a checkpoint's user state, verifying each block's
/// Rabin-64 before any of its bytes are handed out.
///
/// Port of `RSLCheckpointStreamReader` (`rsl.cpp:161`). Implements [`Read`] over
/// the verified stream; [`CheckpointReader::next_block`] exposes the same data
/// a block at a time.
///
/// At most one block (`checksum_block_size`, normally 4 MiB) is held in memory,
/// regardless of the checkpoint's size.
pub struct CheckpointReader<R> {
    inner: R,
    header: CheckpointHeader,
    header_len: u32,
    file_size: u64,
    /// `None` for the unblocked pre-v4 layout: bytes pass through unverified.
    block_size: Option<u32>,
    /// The current verified block's data (no checksum token).
    block: Vec<u8>,
    /// Read offset within `block`.
    pos: usize,
    /// Bytes of the file after the header not yet consumed.
    remaining: u64,
    /// Total user bytes in the file, computed like `Init` (`rsl.cpp:216`).
    user_data_size: u64,
}

impl CheckpointReader<File> {
    /// Open a checkpoint file and parse (and validate) its header.
    pub fn open(path: &Path) -> Result<CheckpointReader<File>, CheckpointError> {
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();
        CheckpointReader::new(file, file_size)
    }
}

/// Read just the checkpoint header off a stream, leaving the user state alone.
///
/// Port of `CheckpointHeader::UnMarshal(StreamReader*)` (`legislator.cpp:1032`):
/// read one page, take the version and declared length out of it, then read the
/// rest of the page-rounded header and parse it. `file_size` bounds how much is
/// read, so a bogus length field cannot make this allocate.
///
/// This is what the engine uses to inspect a checkpoint (its decree, member set
/// and size) without streaming the state; [`CheckpointReader::new`] calls it
/// first. The stream is left positioned just after the page-rounded header.
pub fn read_header<R: Read>(
    inner: &mut R,
    file_size: u64,
) -> Result<CheckpointHeader, CheckpointError> {
    if file_size < u64::from(PAGE_SIZE) {
        return Err(RejectReason::ShortFile.into());
    }
    let mut blob = vec![0u8; PAGE_SIZE as usize];
    inner.read_exact(&mut blob)?;

    let mut peek = Reader::new(&blob);
    let raw_version = peek.read_u16().expect("a full page was read");
    let marshal_len = peek.read_u32().expect("a full page was read");
    if ProtocolVersion::from_wire(raw_version).is_none() {
        return Err(RejectReason::InvalidVersion.into());
    }

    let write_size = round_up_to_page(marshal_len);
    if file_size < u64::from(write_size) {
        return Err(RejectReason::TruncatedHeader.into());
    }
    blob.resize(write_size.max(PAGE_SIZE) as usize, 0);
    if write_size > PAGE_SIZE {
        inner.read_exact(&mut blob[PAGE_SIZE as usize..])?;
    }

    // Reads are bounded by the declared marshal length, exactly as the C++
    // `SetMarshaledLength(marshalLen)` does, so a bogus vote length inside the
    // header cannot reach into the user data behind it.
    CheckpointHeader::unmarshal(&blob[..marshal_len as usize])
        .ok_or_else(|| RejectReason::HeaderUnmarshal.into())
}

impl<R: Read + Seek> CheckpointReader<R> {
    /// Parse the header off `inner` and prepare to stream the user state.
    /// `file_size` is the total size of the checkpoint, which the `v >= 4`
    /// header cross-checks (`rsl.cpp:211`).
    pub fn new(mut inner: R, file_size: u64) -> Result<CheckpointReader<R>, CheckpointError> {
        let header = read_header(&mut inner, file_size)?;

        let header_len = header
            .marshal_len()
            .expect("a parsed v>=3 header always carries a configuration");
        let mut reader = CheckpointReader {
            inner,
            header_len,
            file_size,
            block_size: None,
            block: Vec::new(),
            pos: 0,
            remaining: file_size.saturating_sub(u64::from(header_len)),
            user_data_size: 0,
            header,
        };

        if reader.header.uses_blocks() {
            if reader.file_size != reader.header.size {
                return Err(RejectReason::SizeMismatch.into());
            }
            let block_size = reader.header.checksum_block_size;
            reader.block_size = Some(block_size);
            reader.user_data_size = user_data_size(reader.remaining, block_size);
        } else {
            // Pre-v4 (or block size 0): the state is everything past the header,
            // with no integrity check (`Size()`, rsl.cpp:437).
            reader.user_data_size = reader.remaining;
        }

        // The user state starts at the header's *recomputed* length, which is
        // what the C++ seeks to (`m_offset = header->GetMarshalLen()` then
        // `m_reader->Reset(m_offset)`, rsl.cpp:193/265) — not at the length the
        // file declared. For any well-formed file the two are equal.
        reader.inner.seek(SeekFrom::Start(u64::from(header_len)))?;
        Ok(reader)
    }
}

impl<R: Read> CheckpointReader<R> {
    /// The parsed header.
    pub fn header(&self) -> &CheckpointHeader {
        &self.header
    }

    /// Page-rounded header size — the offset the user state starts at.
    pub fn header_len(&self) -> u32 {
        self.header_len
    }

    /// Total user bytes in this checkpoint (`RSLCheckpointStreamReader::Size`).
    pub fn user_data_size(&self) -> u64 {
        self.user_data_size
    }

    /// Read, verify and return the next block of user data, or `None` at end of
    /// file. Port of `ReadNextDataBlock` (`rsl.cpp:271`).
    pub fn next_block(&mut self) -> Result<Option<&[u8]>, CheckpointError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let Some(block_size) = self.block_size else {
            // Unblocked layout: hand back the raw bytes in block-sized bites.
            let want = self.remaining.min(u64::from(CHECKSUM_BLOCK_SIZE)) as usize;
            self.block.resize(want, 0);
            self.inner.read_exact(&mut self.block)?;
            self.remaining -= want as u64;
            self.pos = 0;
            return Ok(Some(&self.block));
        };

        let on_disk = self.remaining.min(u64::from(block_size)) as usize;
        if on_disk <= CHECKSUM_SIZE as usize {
            return Err(RejectReason::BlockTooShort.into());
        }
        self.block.resize(on_disk, 0);
        self.inner.read_exact(&mut self.block)?;
        self.remaining -= on_disk as u64;

        let data_len = on_disk - CHECKSUM_SIZE as usize;
        let stored = u64::from_le_bytes(
            self.block[data_len..]
                .try_into()
                .expect("checksum token is 8 bytes"),
        );
        if rsl_wire::fingerprint(&self.block[..data_len]) != stored {
            return Err(RejectReason::BlockChecksum.into());
        }
        self.block.truncate(data_len);
        self.pos = 0;
        Ok(Some(&self.block))
    }

    /// Stream every remaining block, verifying each, and return the number of
    /// user bytes seen. Nothing is retained.
    pub fn verify_all(&mut self) -> Result<u64, CheckpointError> {
        let mut total = 0u64;
        while let Some(block) = self.next_block()? {
            total += block.len() as u64;
        }
        Ok(total)
    }

    /// Read the whole user state into memory.
    ///
    /// Convenience for small checkpoints and tests; a real application should
    /// stream via [`Read`] or [`CheckpointReader::next_block`] instead.
    pub fn read_all(&mut self) -> Result<Vec<u8>, CheckpointError> {
        let mut out = Vec::new();
        self.read_to_end(&mut out).map_err(from_io)?;
        Ok(out)
    }
}

/// `RSLCheckpointStreamReader::Init`'s user-data arithmetic (`rsl.cpp:216`):
/// every full block contributes `blockSize - 8`, and the partial last block
/// contributes its size minus the checksum token.
fn user_data_size(total: u64, block_size: u32) -> u64 {
    let block_size = u64::from(block_size);
    let full = total / block_size;
    let last = total - full * block_size;
    let mut size = full * (block_size - u64::from(CHECKSUM_SIZE));
    if last > u64::from(CHECKSUM_SIZE) {
        size += last - u64::from(CHECKSUM_SIZE);
    }
    size
}

impl<R: Read> Read for CheckpointReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos == self.block.len() && self.next_block()?.is_none() {
            return Ok(0);
        }
        let n = buf.len().min(self.block.len() - self.pos);
        buf[..n].copy_from_slice(&self.block[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Streaming writer for a checkpoint file: reserves the header, splits the
/// application's bytes into checksummed blocks, then patches the header with the
/// final size and publishes the file atomically.
///
/// Port of `RSLCheckpointStreamWriter` (`rsl.cpp:459`) plus the commit sequence
/// in `Legislator::SaveCheckpoint` / `CheckpointDone` (`legislator.cpp:5411`,
/// `:5645`): write to a temporary file, stamp the header, then rename over the
/// destination. On Linux that needs an explicit `fsync` of the file before the
/// rename and of the directory after it — see [`Durability`].
///
/// Memory use is constant: user bytes stream straight to the file while being
/// folded into the running block checksum, so nothing larger than the caller's
/// own buffer is held.
pub struct CheckpointWriter<D: Durability = SyncAll> {
    header: CheckpointHeader,
    header_len: u32,
    tmp_path: PathBuf,
    final_path: PathBuf,
    file: Option<BufWriter<D::File>>,
    durability: D,
    /// `None` for the unblocked pre-v4 layout.
    block_size: Option<u32>,
    /// Bytes written into the current block's data region.
    data_offset: u32,
    /// Running Rabin-64 over the current block's data.
    checksum: u64,
    /// Everything issued so far, header reservation included
    /// (`RSLCheckpointStreamWriter::BytesIssued`).
    bytes_issued: u64,
    user_bytes: u64,
}

impl CheckpointWriter<SyncAll> {
    /// Create `path` (via `path.tmp`) and reserve room for `header`.
    ///
    /// The header is re-marshaled with the final size by
    /// [`CheckpointWriter::finish`]; only then is the file renamed into place.
    pub fn create(
        path: &Path,
        header: CheckpointHeader,
    ) -> Result<CheckpointWriter<SyncAll>, CheckpointError> {
        CheckpointWriter::create_with(path, header, SyncAll)
    }
}

impl<D: Durability> CheckpointWriter<D> {
    /// [`CheckpointWriter::create`] with an explicit durability policy.
    pub fn create_with(
        path: &Path,
        header: CheckpointHeader,
        durability: D,
    ) -> Result<CheckpointWriter<D>, CheckpointError> {
        // Reject a header with no on-disk form before touching the filesystem.
        if header.version.has_checkpoint_header() && header.state_configuration.is_none() {
            return Err(WriteError::MissingConfiguration.into());
        }
        let header_len = header.marshal_len().ok_or(WriteError::HeaderTooLarge)?;

        let block_size = if header.uses_blocks() {
            let size = header.checksum_block_size;
            // `LogAssert(blockSize % s_PageSize == 0)` (rsl.cpp:467).
            if !size.is_multiple_of(PAGE_SIZE) {
                return Err(WriteError::BlockSizeNotPageMultiple(size).into());
            }
            if size <= CHECKSUM_SIZE {
                return Err(WriteError::BlockSizeTooSmall(size).into());
            }
            Some(size)
        } else {
            None
        };

        let tmp_path = tmp_path_for(path);
        let file = durability.open(&tmp_path, OpenMode::Create)?;
        let mut file = BufWriter::new(file);
        // Reserve the header region (`Init`, rsl.cpp:473 commits `GetMarshalLen`
        // bytes before any user data). It is overwritten in `finish`.
        write_zeros(&mut file, u64::from(header_len))?;

        Ok(CheckpointWriter {
            header,
            header_len,
            tmp_path,
            final_path: path.to_path_buf(),
            file: Some(file),
            durability,
            block_size,
            data_offset: 0,
            checksum: 0,
            bytes_issued: u64::from(header_len),
            user_bytes: 0,
        })
    }

    /// The header as it will be written (its `size` is only final after
    /// [`CheckpointWriter::finish`]).
    pub fn header(&self) -> &CheckpointHeader {
        &self.header
    }

    /// User bytes accepted so far (checksum tokens excluded).
    pub fn user_bytes(&self) -> u64 {
        self.user_bytes
    }

    /// Bytes issued to the file so far, header reservation and checksum tokens
    /// included (`RSLCheckpointStreamWriter::BytesIssued`).
    pub fn bytes_issued(&self) -> u64 {
        self.bytes_issued + u64::from(self.pending_checksum_len())
    }

    fn pending_checksum_len(&self) -> u32 {
        if self.block_size.is_some() && self.data_offset > 0 {
            CHECKSUM_SIZE
        } else {
            0
        }
    }

    fn out(&mut self) -> &mut BufWriter<D::File> {
        self.file.as_mut().expect("writer used after finish")
    }

    /// Append user state. Port of `RSLCheckpointStreamWriter::Write`
    /// (`rsl.cpp:500`).
    fn write_state(&mut self, mut data: &[u8]) -> io::Result<()> {
        let Some(block_size) = self.block_size else {
            self.out().write_all(data)?;
            self.bytes_issued += data.len() as u64;
            self.user_bytes += data.len() as u64;
            return Ok(());
        };

        let data_only = block_size - CHECKSUM_SIZE;
        while !data.is_empty() {
            if self.data_offset == data_only {
                // Block full: seal it with its checksum.
                let checksum = self.checksum;
                self.out().write_all(&checksum.to_le_bytes())?;
                self.bytes_issued += u64::from(CHECKSUM_SIZE);
                self.data_offset = 0;
            }
            let take = data.len().min((data_only - self.data_offset) as usize);
            let (chunk, rest) = data.split_at(take);
            self.checksum = if self.data_offset == 0 {
                rsl_wire::fingerprint(chunk)
            } else {
                rsl_wire::fingerprint_with(self.checksum, chunk)
            };
            self.out().write_all(chunk)?;
            self.bytes_issued += take as u64;
            self.user_bytes += take as u64;
            self.data_offset += take as u32;
            data = rest;
        }
        Ok(())
    }

    /// Seal the last block, stamp the header with the final file size, flush and
    /// `fsync`, then rename the temporary file over the destination and `fsync`
    /// its directory. Returns the header as written.
    pub fn finish(mut self) -> Result<CheckpointHeader, CheckpointError> {
        // `Close()` (rsl.cpp:576): flush a partial trailing block.
        if self.block_size.is_some() && self.data_offset > 0 {
            let checksum = self.checksum;
            self.out().write_all(&checksum.to_le_bytes())?;
            self.bytes_issued += u64::from(CHECKSUM_SIZE);
            self.data_offset = 0;
        }

        // `header.SetBytesIssued(&writer)` then `header.Marshal(file)`
        // (legislator.cpp:5460): the size covers the whole file.
        self.header.size = self.bytes_issued;
        let blob = self.header.marshal()?;
        debug_assert_eq!(blob.len(), self.header_len as usize);
        self.header.un_marshal_len = self.header_len;

        let mut file = self.file.take().expect("writer used after finish");
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&blob)?;
        file.flush()?;
        let file = file.into_inner().map_err(|e| e.into_error())?;

        // Publish: fsync the contents, rename, fsync the directory entry — the
        // Linux spelling of the C++ `MOVEFILE_WRITE_THROUGH`. A crash anywhere
        // in here leaves the destination name holding the whole old file or the
        // whole new one, never a mixture.
        self.durability
            .rename_durable(&file, &self.tmp_path, &self.final_path)?;

        Ok(self.header.clone())
    }
}

impl<D: Durability> std::fmt::Debug for CheckpointWriter<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointWriter")
            .field("path", &self.final_path)
            .field("version", &self.header.version)
            .field("block_size", &self.block_size)
            .field("user_bytes", &self.user_bytes)
            .field("bytes_issued", &self.bytes_issued())
            .finish()
    }
}

impl<D: Durability> Write for CheckpointWriter<D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_state(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_state(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out().flush()
    }
}

impl<D: Durability> Drop for CheckpointWriter<D> {
    fn drop(&mut self) {
        // Dropped without `finish`: the temporary file holds a half-written
        // checkpoint under a name nothing reads, so remove it.
        if self.file.take().is_some() {
            let _ = self.durability.remove_file(&self.tmp_path);
        }
    }
}

/// `<path>.tmp` — the staging name a checkpoint is built under.
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

/// Write `count` zero bytes (the header reservation).
fn write_zeros(out: &mut impl Write, mut count: u64) -> io::Result<()> {
    let zeros = [0u8; 4096];
    while count > 0 {
        let n = count.min(zeros.len() as u64) as usize;
        out.write_all(&zeros[..n])?;
        count -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsl_wire::messages::MSG_VOTE;
    use rsl_wire::{Header, MemberSet, RslNode};

    fn sample_vote(version: ProtocolVersion, decree: u64) -> Vote {
        Vote::new(Header::new(
            version,
            MSG_VOTE,
            MemberId::from_str("101"),
            decree,
            7,
            BallotNumber::new(5, MemberId::from_str("202")),
            0,
        ))
    }

    pub(crate) fn sample_header(version: ProtocolVersion, decree: u64) -> CheckpointHeader {
        let mut header = CheckpointHeader::new(sample_vote(version, decree + 1));
        header.member_id = MemberId::from_str("101");
        header.last_executed_decree = decree;
        header.max_ballot = BallotNumber::new(9, MemberId::from_str("202"));
        if version.has_checkpoint_header() {
            header.state_configuration = Some(ConfigurationInfo::new(
                0x0a0b_0c0d,
                decree + 1,
                MemberSet {
                    members: vec![RslNode {
                        member_id: MemberId::from_str("101"),
                        ip: 0x0100_007f,
                        rsl_port: 8080,
                        rsl_learn_port: 8081,
                        app_port: 0,
                        host_name: b"host-a".to_vec(),
                    }],
                    cookie: b"cfg".to_vec(),
                },
            ));
        }
        header
    }

    #[test]
    fn header_blob_is_page_rounded_and_round_trips() {
        for version in [ProtocolVersion::V3, ProtocolVersion::V6] {
            let header = sample_header(version, 0x1000);
            let blob = header.marshal().unwrap();
            let len = header.marshal_len().unwrap();
            assert_eq!(blob.len() as u32, len);
            assert!(len.is_multiple_of(PAGE_SIZE));

            let parsed = CheckpointHeader::unmarshal(&blob[..len as usize]).unwrap();
            assert_eq!(parsed.version, version);
            assert_eq!(parsed.un_marshal_len, len);
            assert_eq!(parsed.last_executed_decree, header.last_executed_decree);
            assert_eq!(parsed.member_id, header.member_id);
            assert_eq!(parsed.max_ballot, header.max_ballot);
            // The configuration's node ports are version-gated (v3 marshals the
            // deprecated app port), so compare what actually went on the wire.
            let cfg_bytes = |cfg: &Option<ConfigurationInfo>| {
                let mut w = Writer::new();
                cfg.as_ref().unwrap().marshal(&mut w, version);
                w.into_bytes()
            };
            assert_eq!(
                cfg_bytes(&parsed.state_configuration),
                cfg_bytes(&header.state_configuration)
            );
            assert_eq!(
                parsed.next_vote.header.decree,
                header.next_vote.header.decree
            );
            assert_eq!(parsed.marshal_len(), header.marshal_len());
            // Re-marshaling a parsed header reproduces the bytes exactly.
            assert_eq!(parsed.marshal().unwrap(), blob);
        }
    }

    #[test]
    fn header_at_v3_has_no_block_fields() {
        let v3 = sample_header(ProtocolVersion::V3, 1);
        assert!(!v3.uses_blocks());
        assert_eq!(v3.checksum_block_size, 0);

        let v4 = sample_header(ProtocolVersion::V4, 1);
        assert!(v4.uses_blocks());
        assert_eq!(v4.checksum_block_size, CHECKSUM_BLOCK_SIZE);
    }

    #[test]
    fn header_without_configuration_is_refused() {
        let mut header = sample_header(ProtocolVersion::V6, 1);
        header.state_configuration = None;
        assert_eq!(header.marshal_len(), None);
        assert_eq!(header.marshal(), Err(WriteError::MissingConfiguration));
    }

    #[test]
    fn header_rejects_a_low_max_ballot() {
        // `m_maxBallot < m_nextVote->m_ballot` is a rejection (legislator.cpp:199).
        let mut header = sample_header(ProtocolVersion::V6, 1);
        header.max_ballot = BallotNumber::new(1, MemberId::from_str("202"));
        let blob = header.marshal().unwrap();
        assert!(
            CheckpointHeader::unmarshal(&blob[..header.marshal_len().unwrap() as usize]).is_none()
        );
    }

    #[test]
    fn header_rejects_a_corrupted_vote() {
        let header = sample_header(ProtocolVersion::V6, 1);
        let len = header.marshal_len().unwrap() as usize;
        let blob = header.marshal().unwrap();

        // Flip a byte inside the embedded vote: its own checksum must catch it.
        let vote_start = header.next_vote_offset().unwrap() as usize;
        let mut corrupt = blob.clone();
        corrupt[vote_start + 40] ^= 0xff;
        assert!(CheckpointHeader::unmarshal(&corrupt[..len]).is_none());
    }

    #[test]
    fn header_rejects_truncation_before_the_vote_ends() {
        let header = sample_header(ProtocolVersion::V6, 1);
        let blob = header.marshal().unwrap();
        // Everything through the vote must be present; the page pad after it is
        // never read (the C++ stops at the vote too).
        let vote_end =
            header.next_vote_offset().unwrap() as usize + header.next_vote.marshal_len() as usize;
        for cut in 0..vote_end {
            assert!(
                CheckpointHeader::unmarshal(&blob[..cut]).is_none(),
                "truncation to {cut} bytes parsed"
            );
        }
        assert!(CheckpointHeader::unmarshal(&blob[..vote_end]).is_some());
    }

    #[test]
    fn user_data_size_arithmetic_matches_init() {
        let block = 1024u32;
        let data_only = u64::from(block - CHECKSUM_SIZE);
        assert_eq!(user_data_size(0, block), 0);
        // One partial block.
        assert_eq!(user_data_size(108, block), 100);
        // Exactly one full block.
        assert_eq!(user_data_size(u64::from(block), block), data_only);
        // Full block + a 1-byte partial.
        assert_eq!(user_data_size(u64::from(block) + 9, block), data_only + 1);
    }
}
