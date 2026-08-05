//! The 20-byte RSL packet frame.
//!
//! Wire layout (little-endian, `PacketHdr::Serialize`, `NetPacket.cpp:34`):
//!
//! ```text
//! offset  0   u32  size          total frame length, header included
//!         4   u32  protoVersion  always 0 (never assigned by RSL)
//!         8   u32  xid           always 0 (never assigned by RSL)
//!        12   u64  checksum      Rabin-64 over the whole frame with this
//!                                field zeroed
//!        20   ..   payload       a marshaled rsl-wire message
//! ```
//!
//! `protoVersion`/`xid` are dead fields — `PacketHdr`'s constructor zeroes them
//! and nothing in RSL ever writes them — but they are covered by the checksum,
//! so they must still be emitted (and preserved) exactly.
//!
//! Receive decisions come from `NetCxn::ReadReadyInternal`
//! (`src/NetworkLib/src/NetCxn.cpp:177-250`) and are deliberately unforgiving:
//! a size out of range or a checksum mismatch closes the connection. There is
//! no resynchronization anywhere in the protocol.

use std::io::Read;

use rsl_wire::{fingerprint, fingerprint_with, MarshalError, Msg};

use super::{read_exact_or_eof, read_incrementally, ReadError};
use crate::limits::Limits;

/// `PacketHdr::SerialLen` — `NetPacket.h:52`.
pub const HDR_LEN: usize = 20;

/// Offset of the checksum field inside the header (`PacketHdr::SetChecksum`).
pub const CHECKSUM_OFFSET: usize = 12;

/// The parsed packet header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketHdr {
    /// Total frame length **including** these 20 bytes.
    pub size: u32,
    /// Always zero on the wire; kept so a frame round-trips bit-for-bit.
    pub proto_version: u32,
    /// Always zero on the wire; kept so a frame round-trips bit-for-bit.
    pub xid: u32,
    /// Rabin-64 over the frame with this field zeroed.
    pub checksum: u64,
}

impl PacketHdr {
    /// Serialize the header (`PacketHdr::Serialize`).
    pub fn encode(&self) -> [u8; HDR_LEN] {
        let mut out = [0u8; HDR_LEN];
        out[0..4].copy_from_slice(&self.size.to_le_bytes());
        out[4..8].copy_from_slice(&self.proto_version.to_le_bytes());
        out[8..12].copy_from_slice(&self.xid.to_le_bytes());
        out[12..20].copy_from_slice(&self.checksum.to_le_bytes());
        out
    }

    /// Parse the header (`PacketHdr::DeSerialize`). `None` only when fewer than
    /// [`HDR_LEN`] bytes are available — the C++ `LogAssert`s on that, and every
    /// caller here checks first.
    pub fn decode(buf: &[u8]) -> Option<PacketHdr> {
        let head = buf.get(..HDR_LEN)?;
        Some(PacketHdr {
            size: u32::from_le_bytes(head[0..4].try_into().unwrap()),
            proto_version: u32::from_le_bytes(head[4..8].try_into().unwrap()),
            xid: u32::from_le_bytes(head[8..12].try_into().unwrap()),
            checksum: u64::from_le_bytes(head[12..20].try_into().unwrap()),
        })
    }

    /// Whether this header's `size` passes `Packet::DeSerializeHeader`'s range
    /// check (`NetPacket.cpp:464`).
    pub fn size_in_range(&self, limits: &Limits) -> bool {
        self.size >= HDR_LEN as u32 && self.size <= limits.effective_max()
    }
}

/// A framing failure. Both variants mean the same thing to the caller: **close
/// the connection**. RSL never skips a bad packet and keeps reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// `m_Hdr.m_Size < PacketHdr::SerialLen || m_Hdr.m_Size > m_MaxPacketSize`.
    InvalidSize { size: u32, max: u32 },
    /// `Packet::VerifyChecksum` failed.
    Checksum { header: u64, computed: u64 },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::InvalidSize { size, max } => {
                write!(f, "invalid packet size {size} (min {HDR_LEN} max {max})")
            }
            FrameError::Checksum { header, computed } => {
                write!(
                    f,
                    "checksum mismatch: header {header:016x} computed {computed:016x}"
                )
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Frame `payload` (`Packet::Serialize`, `NetPacket.cpp:389`).
///
/// Like the C++, no size cap is applied on the send path — the cap belongs to
/// the receiver. Use [`Limits::effective_max`] if a sender wants to check.
pub fn encode_packet(payload: &[u8]) -> Vec<u8> {
    encode_packet_with(0, 0, payload)
}

/// Frame `payload`, choosing the two header fields RSL always leaves at zero.
///
/// Only useful for re-emitting a frame received from somewhere else bit-for-bit
/// (a proxy, a test): both fields are inside the checksum's domain, so they have
/// to be carried along to reproduce a frame that had them set.
pub fn encode_packet_with(proto_version: u32, xid: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HDR_LEN + payload.len());
    let hdr = PacketHdr {
        size: (HDR_LEN + payload.len()) as u32,
        proto_version,
        xid,
        checksum: 0,
    };
    frame.extend_from_slice(&hdr.encode());
    frame.extend_from_slice(payload);

    let checksum = fingerprint(&frame);
    frame[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 8].copy_from_slice(&checksum.to_le_bytes());
    frame
}

/// Marshal `msg` and frame it.
pub fn encode_message(msg: &Msg) -> Result<Vec<u8>, MarshalError> {
    Ok(encode_packet(&msg.marshal_with_checksum()?))
}

/// Recompute a frame's checksum (`Packet::VerifyChecksum`): the Rabin-64 over
/// `frame[..hdr.size]` with the checksum field zeroed.
///
/// Note this domain is *not* the message checksum's domain — that one covers
/// the message after its own 8-byte checksum field. A frame can pass one and
/// fail the other; the packet layer never looks inside the payload.
///
/// The C++ zeroes the field in place and hashes the buffer; the Rabin-64 chains
/// across buffer boundaries (that is how `Vote::CalculateChecksum` works), so
/// the same value comes out of three chained passes without copying the frame.
///
/// # Panics
/// If `frame` is shorter than [`HDR_LEN`]. Callers have already validated the
/// header by this point.
pub fn frame_checksum(frame: &[u8]) -> u64 {
    assert!(frame.len() >= HDR_LEN, "frame shorter than its header");
    const ZEROED_FIELD: [u8; 8] = [0; 8];
    let fp = fingerprint(&frame[..CHECKSUM_OFFSET]);
    let fp = fingerprint_with(fp, &ZEROED_FIELD);
    fingerprint_with(fp, &frame[CHECKSUM_OFFSET + 8..])
}

/// One step of the receive loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step<'a> {
    /// A complete, checksum-verified packet.
    Packet { hdr: PacketHdr, payload: &'a [u8] },
    /// Not enough bytes yet: keep the buffer and read more. `needed` is the
    /// total frame length once the header has been parsed, or [`HDR_LEN`] while
    /// even the header is incomplete.
    NeedMore { needed: usize },
}

/// Decode the first packet in `buf` (`Packet::DeSerializeHeader` +
/// `Packet::DeSerialize`).
///
/// Leaves `buf` untouched; on [`Step::Packet`] the caller consumes `hdr.size`
/// bytes.
pub fn decode_packet<'a>(buf: &'a [u8], limits: &Limits) -> Result<Step<'a>, FrameError> {
    // `while (m_Read.m_NetBuffer->ReadAvail() >= (int) PacketHdr::SerialLen)`
    let Some(hdr) = PacketHdr::decode(buf) else {
        return Ok(Step::NeedMore { needed: HDR_LEN });
    };

    // The header is validated the moment it is complete -- before the body is
    // read, and before anything is sized from it.
    if !hdr.size_in_range(limits) {
        return Err(FrameError::InvalidSize {
            size: hdr.size,
            max: limits.effective_max(),
        });
    }

    let size = hdr.size as usize;
    if buf.len() < size {
        return Ok(Step::NeedMore { needed: size });
    }

    let frame = &buf[..size];
    let computed = frame_checksum(frame);
    if computed != hdr.checksum {
        return Err(FrameError::Checksum {
            header: hdr.checksum,
            computed,
        });
    }

    Ok(Step::Packet {
        hdr,
        payload: &frame[HDR_LEN..],
    })
}

/// Every complete packet in one read buffer, in order — the `while` loop of
/// `NetCxn::ReadReadyInternal`, which drains as many packets as arrived
/// together.
///
/// Iteration stops at the first [`FrameError`] (yielded as the final item) or
/// when the remaining bytes are incomplete. [`Packets::consumed`] then says how
/// much of the buffer to discard.
pub struct Packets<'a> {
    buf: &'a [u8],
    limits: Limits,
    consumed: usize,
    done: bool,
}

impl<'a> Packets<'a> {
    pub fn new(buf: &'a [u8], limits: Limits) -> Packets<'a> {
        Packets {
            buf,
            limits,
            consumed: 0,
            done: false,
        }
    }

    /// Bytes covered by the packets yielded so far.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// The unconsumed tail (a partial packet, or nothing).
    pub fn remainder(&self) -> &'a [u8] {
        &self.buf[self.consumed..]
    }
}

impl<'a> Iterator for Packets<'a> {
    type Item = Result<(PacketHdr, &'a [u8]), FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match decode_packet(&self.buf[self.consumed..], &self.limits) {
            Ok(Step::Packet { hdr, payload }) => {
                self.consumed += hdr.size as usize;
                Some(Ok((hdr, payload)))
            }
            Ok(Step::NeedMore { .. }) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Read one whole packet from a blocking reader, returning its payload.
///
/// `Ok(None)` is a clean close between packets (no bytes at all). The size cap
/// is enforced on the header before a single payload byte is read or allocated
/// — the C++ sizes its buffer from the untrusted header first.
pub fn read_packet<R: Read>(
    r: &mut R,
    limits: &Limits,
) -> Result<Option<(PacketHdr, Vec<u8>)>, ReadError<FrameError>> {
    let mut frame = vec![0u8; HDR_LEN];
    if !read_exact_or_eof::<R, FrameError>(r, &mut frame)? {
        return Ok(None);
    }

    let hdr = PacketHdr::decode(&frame).expect("header buffer is HDR_LEN bytes");
    if !hdr.size_in_range(limits) {
        return Err(ReadError::Framing(FrameError::InvalidSize {
            size: hdr.size,
            max: limits.effective_max(),
        }));
    }

    let body = hdr.size as usize - HDR_LEN;
    read_incrementally::<R, FrameError>(r, &mut frame, body)?;

    let computed = frame_checksum(&frame);
    if computed != hdr.checksum {
        return Err(ReadError::Framing(FrameError::Checksum {
            header: hdr.checksum,
            computed,
        }));
    }

    frame.drain(..HDR_LEN);
    Ok(Some((hdr, frame)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_including_the_dead_fields() {
        let hdr = PacketHdr {
            size: 0x1234_5678,
            proto_version: 0xdead_beef,
            xid: 0x0bad_c0de,
            checksum: 0x0102_0304_0506_0708,
        };
        assert_eq!(PacketHdr::decode(&hdr.encode()), Some(hdr));
        assert_eq!(PacketHdr::decode(&[0u8; HDR_LEN - 1]), None);
    }

    #[test]
    fn empty_payload_is_a_bare_header() {
        let frame = encode_packet(&[]);
        assert_eq!(frame.len(), HDR_LEN);
        let limits = Limits::default();
        assert!(matches!(
            decode_packet(&frame, &limits),
            Ok(Step::Packet { payload, .. }) if payload.is_empty()
        ));
    }

    #[test]
    fn size_is_checked_before_the_body_is_awaited() {
        // A 100 MB size field with 20 bytes in hand must reject immediately, not
        // ask for more bytes (that is the DoS shape the cap exists for).
        let limits = Limits::from_config_mb(1, 0).unwrap();
        let mut frame = encode_packet(&[]);
        frame[0..4].copy_from_slice(&(100u32 * 1024 * 1024).to_le_bytes());
        assert!(matches!(
            decode_packet(&frame, &limits),
            Err(FrameError::InvalidSize { .. })
        ));
    }
}
