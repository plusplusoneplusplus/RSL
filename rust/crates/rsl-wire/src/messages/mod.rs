//! RSL messages: the common header plus the six concrete subclasses that carry
//! their own payload. Ports of the `Message` hierarchy in `message.cpp`.
//!
//! Every message shares a fixed header (version, length, checksum, magic,
//! message id, member id, decree, configuration number, ballot, payload). The
//! twelve "base" message ids carry nothing beyond the header; the six subclasses
//! append type-specific fields. Which parser applies is chosen by the *caller*
//! (the receiver knows what it asked for), exactly as in the C++ — so the same
//! message id can appear as a bare [`Header`] or as a subclass.

mod bootstrap;
mod join;
mod prepare;
mod prepare_accepted;
mod status_response;
mod vote;

pub use bootstrap::BootstrapMsg;
pub use join::JoinMessage;
pub use prepare::PrepareMsg;
pub use prepare_accepted::PrepareAccepted;
pub use status_response::StatusResponse;
pub use vote::Vote;

use crate::fprint::fingerprint;
use crate::marshal::{Reader, Writer};
use crate::types::{BallotNumber, MemberId};
use crate::version::ProtocolVersion;

/// `s_MessageMagic` — marks the start of a valid message header.
pub const MAGIC: u32 = 0xF00D_FACE;

/// `s_ChecksumOffset` — byte offset of the 8-byte checksum field (2 version + 4
/// length). The checksum covers everything after this field.
pub const CHECKSUM_OFFSET: usize = 6;

// Message ids (`Message_*` in message.h).
pub const MSG_NONE: u16 = 0;
pub const MSG_VOTE: u16 = 1;
pub const MSG_VOTE_ACCEPTED: u16 = 2;
pub const MSG_PREPARE: u16 = 3;
pub const MSG_PREPARE_ACCEPTED: u16 = 4;
pub const MSG_NOT_ACCEPTED: u16 = 5;
pub const MSG_STATUS_QUERY: u16 = 6;
pub const MSG_STATUS_RESPONSE: u16 = 7;
pub const MSG_FETCH_VOTES: u16 = 8;
pub const MSG_FETCH_CHECKPOINT: u16 = 9;
pub const MSG_RECONFIGURATION_DECISION: u16 = 10;
pub const MSG_DEFUNCT_CONFIGURATION: u16 = 11;
pub const MSG_JOIN: u16 = 12;
pub const MSG_JOIN_REQUEST: u16 = 13;
pub const MSG_BOOTSTRAP: u16 = 14;

/// The fixed message header carried by every RSL message.
///
/// `un_marshal_len` and `checksum` are recomputed on marshal, so setting them is
/// only meaningful when re-marshaling a parsed message (where they should equal
/// what was parsed). `magic` is always [`MAGIC`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: ProtocolVersion,
    pub un_marshal_len: u32,
    pub checksum: u64,
    pub magic: u32,
    pub msg_id: u16,
    pub member_id: MemberId,
    pub decree: u64,
    pub configuration_number: u32,
    pub ballot: BallotNumber,
    pub payload: u64,
}

impl Header {
    /// Build a header with `magic`/`checksum`/`un_marshal_len` at their defaults
    /// (they are filled in on marshal). Mirrors `Message::InitMessage`.
    pub fn new(
        version: ProtocolVersion,
        msg_id: u16,
        member_id: MemberId,
        decree: u64,
        configuration_number: u32,
        ballot: BallotNumber,
        payload: u64,
    ) -> Header {
        Header {
            version,
            un_marshal_len: 0,
            checksum: 0,
            magic: MAGIC,
            msg_id,
            member_id,
            decree,
            configuration_number,
            ballot,
            payload,
        }
    }

    /// On-wire size of the header for `version` (`Message::GetBaseSize`).
    pub fn base_size(version: ProtocolVersion) -> u32 {
        let mut size = 2 // version
            + 4 // length
            + 8 // checksum
            + 4 // magic
            + 2 // message id
            + MemberId::base_size(version)
            + 8 // decree
            + BallotNumber::base_size(version);
        if version.has_configuration_number() {
            size += 4;
        }
        if version.has_payload() {
            size += 8;
        }
        size
    }

    /// Write the header, stamping `marshal_len` into the length field.
    /// (`Message::Marshal`.)
    fn write(&self, w: &mut Writer, marshal_len: u32) {
        w.write_u16(self.version.raw());
        w.write_u32(marshal_len);
        w.write_u64(self.checksum);
        w.write_u32(self.magic);
        w.write_u16(self.msg_id);
        self.member_id.marshal(w, self.version);
        w.write_u64(self.decree);
        if self.version.has_configuration_number() {
            w.write_u32(self.configuration_number);
        }
        self.ballot.marshal(w, self.version);
        if self.version.has_payload() {
            w.write_u64(self.payload);
        }
    }

    /// Read the header (`Message::UnMarshal`). Rejects unknown versions, bad
    /// magic, and an `un_marshal_len` smaller than the header itself.
    pub fn unmarshal(r: &mut Reader) -> Option<Header> {
        let version = ProtocolVersion::from_wire(r.read_u16()?)?;
        let un_marshal_len = r.read_u32()?;
        let checksum = r.read_u64()?;
        let magic = r.read_u32()?;
        let msg_id = r.read_u16()?;
        let member_id = MemberId::unmarshal(r, version)?;
        let decree = r.read_u64()?;
        let configuration_number = if version.has_configuration_number() {
            r.read_u32()?
        } else {
            1
        };
        let ballot = BallotNumber::unmarshal(r, version)?;
        let payload = if version.has_payload() {
            r.read_u64()?
        } else {
            0
        };

        let header = Header {
            version,
            un_marshal_len,
            checksum,
            magic,
            msg_id,
            member_id,
            decree,
            configuration_number,
            ballot,
            payload,
        };

        // These two checks come after the full header is read, matching the C++.
        if un_marshal_len < Header::base_size(version) {
            return None;
        }
        if magic != MAGIC {
            return None;
        }
        Some(header)
    }
}

/// Marshal a bare base-class message (header only): the twelve `Message_*` ids
/// that carry no subclass payload. `Message::GetMarshalLen == GetBaseSize`.
pub fn marshal_base(header: &Header) -> Vec<u8> {
    let len = Header::base_size(header.version);
    let mut w = Writer::with_capacity(len as usize);
    header.write(&mut w, len);
    finalize(w.into_bytes())
}

/// Parse a bare base-class message: just the header.
pub fn unmarshal_base(buf: &[u8]) -> Option<Header> {
    let mut r = Reader::new(buf);
    Header::unmarshal(&mut r)
}

/// Recompute the Rabin-64 checksum over the post-checksum region and patch it
/// into the 8-byte checksum field. Shared by every top-level marshal.
/// (`Message::CalculateChecksum` / the golden-gen driver.)
pub(crate) fn finalize(mut bytes: Vec<u8>) -> Vec<u8> {
    let data_off = CHECKSUM_OFFSET + 8;
    debug_assert!(bytes.len() >= data_off);
    let checksum = fingerprint(&bytes[data_off..]);
    bytes[CHECKSUM_OFFSET..data_off].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

/// Verify a message's stored checksum against a recomputation over its bytes.
/// (`Message::VerifyChecksum`.) `buf` must be the full message.
pub fn verify_checksum(buf: &[u8]) -> bool {
    let data_off = CHECKSUM_OFFSET + 8;
    if buf.len() < data_off {
        return false;
    }
    let stored = u64::from_le_bytes(buf[CHECKSUM_OFFSET..data_off].try_into().unwrap());
    fingerprint(&buf[data_off..]) == stored
}

/// A parsed RSL message, tagged by concrete type. The variant is selected by the
/// caller's [`MsgKind`], never inferred from the message id (a `Prepare` id, for
/// instance, may be a bare [`Header`] or a [`PrepareMsg`]).
#[derive(Clone, Debug)]
pub enum Msg {
    Base(Header),
    Vote(Vote),
    Join(JoinMessage),
    Prepare(PrepareMsg),
    PrepareAccepted(PrepareAccepted),
    StatusResponse(StatusResponse),
    Bootstrap(BootstrapMsg),
}

/// Which concrete parser to apply to a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgKind {
    Base,
    Vote,
    Join,
    Prepare,
    PrepareAccepted,
    StatusResponse,
    Bootstrap,
}

impl Msg {
    /// Parse `buf` as the concrete type named by `kind`.
    pub fn unmarshal(kind: MsgKind, buf: &[u8]) -> Option<Msg> {
        Some(match kind {
            MsgKind::Base => Msg::Base(unmarshal_base(buf)?),
            MsgKind::Vote => Msg::Vote(Vote::unmarshal(buf)?),
            MsgKind::Join => Msg::Join(JoinMessage::unmarshal(buf)?),
            MsgKind::Prepare => Msg::Prepare(PrepareMsg::unmarshal(buf)?),
            MsgKind::PrepareAccepted => Msg::PrepareAccepted(PrepareAccepted::unmarshal(buf)?),
            MsgKind::StatusResponse => Msg::StatusResponse(StatusResponse::unmarshal(buf)?),
            MsgKind::Bootstrap => Msg::Bootstrap(BootstrapMsg::unmarshal(buf)?),
        })
    }

    /// Marshal to bytes with the checksum patched in.
    pub fn marshal_with_checksum(&self) -> Vec<u8> {
        match self {
            Msg::Base(h) => marshal_base(h),
            Msg::Vote(m) => m.marshal_with_checksum(),
            Msg::Join(m) => m.marshal_with_checksum(),
            Msg::Prepare(m) => m.marshal_with_checksum(),
            Msg::PrepareAccepted(m) => m.marshal_with_checksum(),
            Msg::StatusResponse(m) => m.marshal_with_checksum(),
            Msg::Bootstrap(m) => m.marshal_with_checksum(),
        }
    }

    /// The common header.
    pub fn header(&self) -> &Header {
        match self {
            Msg::Base(h) => h,
            Msg::Vote(m) => &m.header,
            Msg::Join(m) => &m.header,
            Msg::Prepare(m) => &m.header,
            Msg::PrepareAccepted(m) => &m.header,
            Msg::StatusResponse(m) => &m.header,
            Msg::Bootstrap(m) => &m.header,
        }
    }
}
