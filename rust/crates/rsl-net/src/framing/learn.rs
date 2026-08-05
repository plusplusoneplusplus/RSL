//! Learn-port framing — `Message::ReadFromSocket`, `src/RSL/src/message.cpp:639`.
//!
//! The fetch/status sockets carry bare marshaled messages: there is no extra
//! prefix, the reader just consumes the message's own first six bytes
//!
//! ```text
//! offset 0  u16  version   must be one of RSLProtocolVersion_1..6
//!        2  u32  length    total message length, these 6 bytes included
//! ```
//!
//! and uses them to size the rest of the read.
//!
//! Two behaviours here regularly surprise people, and both are faithful:
//!
//! * **The checksum is not verified.** `ReadFromSocket` calls `UnMarshalBuf`,
//!   which runs `Message::UnMarshal` only. A message with a wrong Rabin-64 is
//!   accepted. [`parse_message_checked`] adds the verification for callers that
//!   want it; [`parse_message`] is the C++-parity path.
//! * **Trailing bytes are ignored.** Exactly `length` bytes are consumed;
//!   whatever follows belongs to the next read.

use std::io::Read;

use rsl_wire::{Msg, MsgKind, ProtocolVersion};

use super::{read_exact_or_eof, read_incrementally, ReadError};

/// `const int HeaderSize = 6;` (`message.cpp:641`).
pub const HDR_LEN: usize = 6;

/// Why a learn-port message was refused. Every variant closes the connection in
/// the C++ (the caller just gives up on the socket).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LearnError {
    /// Fewer than 6 bytes: `socket->Read(&header, HeaderSize, ..)` came up short.
    ShortHeader,
    /// `!Message::IsVersionValid(version)`.
    BadVersion(u16),
    /// `length > maxMessageSize`.
    TooLarge { len: u32, max: u32 },
    /// The body did not arrive in full.
    ShortBody { len: u32, available: u32 },
    /// `UnMarshalBuf` failed.
    Unmarshal,
    /// `length < 6`. **Divergence:** the C++ `malloc`s `length` bytes and then
    /// `memcpy`s the 6-byte header into it (`message.cpp:672-674`), overflowing
    /// the allocation. There is no faithful outcome to copy, so this port
    /// refuses the length.
    LengthBelowHeader { len: u32 },
    /// The message's own Rabin-64 does not match. Only ever produced by
    /// [`parse_message_checked`]; the C++ does not check here at all.
    Checksum,
}

impl std::fmt::Display for LearnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LearnError::ShortHeader => write!(f, "short read of the {HDR_LEN}-byte header"),
            LearnError::BadVersion(v) => write!(f, "unknown message version {v}"),
            LearnError::TooLarge { len, max } => {
                write!(f, "discarding large message: length {len} > max {max}")
            }
            LearnError::ShortBody { len, available } => {
                write!(
                    f,
                    "short read of the message body: {available} of {len} bytes"
                )
            }
            LearnError::Unmarshal => write!(f, "failed to unmarshal message"),
            LearnError::LengthBelowHeader { len } => {
                write!(f, "length {len} below the {HDR_LEN}-byte header")
            }
            LearnError::Checksum => write!(f, "message checksum mismatch"),
        }
    }
}

impl std::error::Error for LearnError {}

/// The 6-byte framing header, once parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LearnHdr {
    pub version: ProtocolVersion,
    /// Total message length, the 6 header bytes included.
    pub len: u32,
}

/// Validate the 6-byte prefix — version validity and the size cap — without
/// touching the body. This is the whole "is it safe to size a read from this?"
/// decision, in the same order as `message.cpp:656-670`.
pub fn parse_header(head: &[u8], max_message_size: u32) -> Result<LearnHdr, LearnError> {
    let head = head.get(..HDR_LEN).ok_or(LearnError::ShortHeader)?;
    let raw_version = u16::from_le_bytes(head[0..2].try_into().unwrap());
    let len = u32::from_le_bytes(head[2..6].try_into().unwrap());

    let version =
        ProtocolVersion::from_wire(raw_version).ok_or(LearnError::BadVersion(raw_version))?;
    if len > max_message_size {
        return Err(LearnError::TooLarge {
            len,
            max: max_message_size,
        });
    }
    if (len as usize) < HDR_LEN {
        return Err(LearnError::LengthBelowHeader { len });
    }
    Ok(LearnHdr { version, len })
}

/// Parse one message from the front of `buf`, returning it and the number of
/// bytes consumed (`hdr.len`). Trailing bytes are left for the next call.
///
/// Mirrors `Message::ReadFromSocket` exactly, checksum included: it is **not**
/// verified. Use [`parse_message_checked`] when you want it verified.
pub fn parse_message(
    buf: &[u8],
    kind: MsgKind,
    max_message_size: u32,
) -> Result<(Msg, usize), LearnError> {
    let hdr = parse_header(buf, max_message_size)?;
    let len = hdr.len as usize;
    if buf.len() < len {
        return Err(LearnError::ShortBody {
            len: hdr.len,
            available: buf.len() as u32,
        });
    }
    let msg = Msg::unmarshal(kind, &buf[..len]).ok_or(LearnError::Unmarshal)?;
    Ok((msg, len))
}

/// [`parse_message`] plus the message's own Rabin-64 check. Not what the C++
/// learn port does — offered because a Rust peer can afford it.
pub fn parse_message_checked(
    buf: &[u8],
    kind: MsgKind,
    max_message_size: u32,
) -> Result<(Msg, usize), LearnError> {
    let (msg, len) = parse_message(buf, kind, max_message_size)?;
    if !rsl_wire::verify_checksum(&buf[..len]) {
        return Err(LearnError::Checksum);
    }
    Ok((msg, len))
}

/// Read one whole message from a blocking reader.
///
/// `Ok(None)` is a clean close between messages. As with packets, the length is
/// checked against `max_message_size` before any body allocation.
pub fn read_message<R: Read>(
    r: &mut R,
    kind: MsgKind,
    max_message_size: u32,
) -> Result<Option<Msg>, ReadError<LearnError>> {
    let mut buf = vec![0u8; HDR_LEN];
    if !read_exact_or_eof::<R, LearnError>(r, &mut buf)? {
        return Ok(None);
    }

    let hdr = parse_header(&buf, max_message_size).map_err(ReadError::Framing)?;
    read_incrementally::<R, LearnError>(r, &mut buf, hdr.len as usize - HDR_LEN)?;

    let msg = Msg::unmarshal(kind, &buf).ok_or(ReadError::Framing(LearnError::Unmarshal))?;
    Ok(Some(msg))
}

/// Marshal a message for the learn port: the bare message bytes, since its own
/// header *is* the framing.
pub fn encode_message(msg: &Msg) -> Result<Vec<u8>, rsl_wire::MarshalError> {
    msg.marshal_with_checksum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_rejections_follow_the_cpp_order() {
        // Version is checked before the length cap.
        let mut head = [0u8; HDR_LEN];
        head[0..2].copy_from_slice(&99u16.to_le_bytes());
        head[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse_header(&head, 1024), Err(LearnError::BadVersion(99)));

        // ... and the cap before the below-header check.
        head[0..2].copy_from_slice(&6u16.to_le_bytes());
        head[2..6].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            parse_header(&head, 1),
            Err(LearnError::TooLarge { len: 2, max: 1 })
        );
        assert_eq!(
            parse_header(&head, 1024),
            Err(LearnError::LengthBelowHeader { len: 2 })
        );
    }
}
