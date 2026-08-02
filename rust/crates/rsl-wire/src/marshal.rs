//! `MarshalData` reader/writer — a deliberate transliteration of
//! `src/common/src/marshal.cpp`.
//!
//! This module *is* the little-endian wire encoding spec: fixed-width integers
//! are little-endian, strings are a `u32` length prefix followed by raw bytes,
//! and containers reserve a 1- or 4-byte length that is back-patched on close.
//! The API mirrors the C++ `MarshalData` closely so the port stays auditable
//! against the original.

/// Buffer-backed writer, the write half of `MarshalData`.
///
/// Unlike the C++ `StandardMarshalMemoryManager` there is no fixed-vs-growable
/// distinction and no power-of-two rounding: those only affect the C++
/// allocator, never the bytes produced, so a plain growable `Vec` is exact.
#[derive(Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

/// Records where a container's back-patched length field lives, returned by
/// [`Writer::start_container`]. Port of `MarshalStartPlaceHolder`.
#[must_use = "a started container must be closed with close_container"]
pub struct Placeholder {
    length_offset: usize,
    data_start_offset: usize,
    short_length: bool,
}

impl Writer {
    /// A fresh, empty writer.
    pub fn new() -> Writer {
        Writer { buf: Vec::new() }
    }

    /// A writer with capacity reserved (an allocation hint only).
    pub fn with_capacity(cap: usize) -> Writer {
        Writer {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Number of bytes written so far — `GetMarshaledLength()`.
    pub fn len(&self) -> u32 {
        self.buf.len() as u32
    }

    /// True if nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow the marshaled bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the writer and return the marshaled bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// `WriteUInt8`.
    pub fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    /// `WriteBool` — a single byte, `1` or `0`.
    pub fn write_bool(&mut self, val: bool) {
        self.write_u8(u8::from(val));
    }

    /// `WriteUInt16` (little-endian).
    pub fn write_u16(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    /// `WriteUInt32` (little-endian).
    pub fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    /// `WriteUInt64` (little-endian).
    pub fn write_u64(&mut self, val: u64) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    /// `WriteFloat` — the raw IEEE-754 bits as a little-endian `u32`.
    pub fn write_float(&mut self, val: f32) {
        self.write_u32(val.to_bits());
    }

    /// `WriteData` — copy bytes verbatim, with no length prefix.
    pub fn write_data(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// `WriteString` — a `u32` length prefix followed by the bytes. A null
    /// string in C++ becomes length 0; an empty slice here is the same.
    pub fn write_string(&mut self, s: &[u8]) {
        self.write_u32(s.len() as u32);
        if !s.is_empty() {
            self.write_data(s);
        }
    }

    /// `StartContainer` — reserve a zeroed length field (1 byte if `short`, else
    /// 4) and remember where it is so [`Writer::close_container`] can fill it in.
    pub fn start_container(&mut self, short: bool) -> Placeholder {
        let length_offset = self.buf.len();
        if short {
            self.write_u8(0);
        } else {
            self.write_u32(0);
        }
        let data_start_offset = self.buf.len();
        Placeholder {
            length_offset,
            data_start_offset,
            short_length: short,
        }
    }

    /// `CloseContainer` — back-patch the container's length field with the
    /// number of bytes written since the start. Panics if a 1-byte length was
    /// requested but the body exceeds 255 bytes, matching the C++ `LogAssert`.
    pub fn close_container(&mut self, ph: Placeholder) {
        let current = self.buf.len();
        assert!(
            current >= ph.data_start_offset,
            "close_container: buffer shrank below the container start"
        );
        let length = (current - ph.data_start_offset) as u32;

        if ph.short_length {
            assert!(length < 256, "short container overflow: {length} >= 256");
            self.buf[ph.length_offset] = length as u8;
        } else {
            self.buf[ph.length_offset..ph.length_offset + 4].copy_from_slice(&length.to_le_bytes());
        }
    }

    /// Overwrite an already-written little-endian `u64` at `offset`. Used to
    /// patch the checksum field after the body has been marshaled
    /// (`Message::CalculateChecksum`). Panics if `offset + 8` is out of range.
    pub fn patch_u64_at(&mut self, offset: usize, val: u64) {
        self.buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
    }
}

/// Cursor-based reader, the read half of `MarshalData`.
///
/// The `overshoot` flag is sticky exactly as in C++: once a read runs past the
/// end, every subsequent read fails until the pointer is repositioned via
/// [`Reader::reset_read_pointer`], [`Reader::set_read_pointer`], etc.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    overshoot: bool,
}

impl<'a> Reader<'a> {
    /// Attach a reader to `buf`, with the read pointer at 0.
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader {
            buf,
            pos: 0,
            overshoot: false,
        }
    }

    /// `GetMarshaledLength()` — total length of the attached buffer.
    pub fn marshaled_length(&self) -> u32 {
        self.buf.len() as u32
    }

    /// `GetOvershoot()`.
    pub fn overshoot(&self) -> bool {
        self.overshoot
    }

    /// `ResetOvershoot()`.
    pub fn reset_overshoot(&mut self) {
        self.overshoot = false;
    }

    /// `GetReadPointer()`.
    pub fn read_pointer(&self) -> u32 {
        self.pos as u32
    }

    /// `SetReadPointer` — clears overshoot; returns false (and rewinds to 0) if
    /// `offset` is past the end.
    pub fn set_read_pointer(&mut self, offset: u32) -> bool {
        self.overshoot = false;
        if offset as usize > self.buf.len() {
            self.pos = 0;
            false
        } else {
            self.pos = offset as usize;
            true
        }
    }

    /// `RewindReadPointer` — back up `length` bytes; false (and rewind to 0) if
    /// `length >= readPointer`.
    pub fn rewind_read_pointer(&mut self, length: u32) -> bool {
        self.overshoot = false;
        let rp = self.pos as u32;
        if length >= rp {
            self.pos = 0;
            false
        } else {
            self.pos = (rp - length) as usize;
            true
        }
    }

    /// `ForwardReadPointer` — advance `length` bytes; false (and clamp to end)
    /// if that would overrun.
    pub fn forward_read_pointer(&mut self, length: u32) -> bool {
        self.overshoot = false;
        let end = self.pos as u32 + length;
        if end > self.buf.len() as u32 {
            self.pos = self.buf.len();
            false
        } else {
            self.pos = end as usize;
            true
        }
    }

    /// `ResetReadPointer()`.
    pub fn reset_read_pointer(&mut self) {
        self.pos = 0;
        self.overshoot = false;
    }

    /// `TestReadRemaining` — true if at least `len` bytes remain; otherwise sets
    /// the sticky overshoot flag and returns false.
    pub fn test_read_remaining(&mut self, len: u32) -> bool {
        if self.overshoot || self.pos + len as usize > self.buf.len() {
            self.overshoot = true;
            false
        } else {
            true
        }
    }

    /// Common guard shared by every read: honor sticky overshoot and bounds.
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.overshoot || self.pos + len > self.buf.len() {
            self.overshoot = true;
            return None;
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Some(out)
    }

    /// `ReadUInt8`.
    pub fn read_u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    /// `ReadBool`.
    pub fn read_bool(&mut self) -> Option<bool> {
        self.read_u8().map(|b| b != 0)
    }

    /// `ReadUInt16`.
    pub fn read_u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    }

    /// `ReadUInt32`.
    pub fn read_u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// `ReadUInt64`.
    pub fn read_u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }

    /// `ReadFloat`.
    pub fn read_float(&mut self) -> Option<f32> {
        self.read_u32().map(f32::from_bits)
    }

    /// `ReadData` — read exactly `len` bytes.
    pub fn read_data(&mut self, len: u32) -> Option<&'a [u8]> {
        self.take(len as usize)
    }

    /// `ReadString` — a `u32` length prefix followed by the bytes. Length 0
    /// yields an empty slice (the C++ returns a null string). On overshoot the
    /// read pointer is not left partway: the length read already failed.
    pub fn read_string(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u32()?;
        if len == 0 {
            return Some(&[]);
        }
        self.take(len as usize)
    }

    /// `PeekDataPointer` — borrow `len` bytes at the read pointer without
    /// advancing it.
    pub fn peek_data_pointer(&mut self, len: u32) -> Option<&'a [u8]> {
        if self.overshoot || self.pos + len as usize > self.buf.len() {
            self.overshoot = true;
            return None;
        }
        Some(&self.buf[self.pos..self.pos + len as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_round_trip_little_endian() {
        let mut w = Writer::new();
        w.write_u8(0x12);
        w.write_u16(0x3456);
        w.write_u32(0x789a_bcde);
        w.write_u64(0x0102_0304_0506_0708);
        w.write_bool(true);
        let bytes = w.into_bytes();
        assert_eq!(bytes[0], 0x12);
        assert_eq!(&bytes[1..3], &[0x56, 0x34]);
        assert_eq!(&bytes[3..7], &[0xde, 0xbc, 0x9a, 0x78]);

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8(), Some(0x12));
        assert_eq!(r.read_u16(), Some(0x3456));
        assert_eq!(r.read_u32(), Some(0x789a_bcde));
        assert_eq!(r.read_u64(), Some(0x0102_0304_0506_0708));
        assert_eq!(r.read_bool(), Some(true));
        assert!(r.read_u8().is_none());
        assert!(r.overshoot());
    }

    #[test]
    fn string_uses_u32_prefix() {
        let mut w = Writer::new();
        w.write_string(b"abc");
        let bytes = w.into_bytes();
        assert_eq!(&bytes[..4], &[3, 0, 0, 0]);
        assert_eq!(&bytes[4..], b"abc");

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_string(), Some(&b"abc"[..]));
    }

    #[test]
    fn short_and_long_containers_backpatch() {
        let mut w = Writer::new();
        let ph = w.start_container(true);
        w.write_data(b"hello");
        w.close_container(ph);

        let ph = w.start_container(false);
        w.write_data(&[0u8; 300]);
        w.close_container(ph);

        let bytes = w.into_bytes();
        assert_eq!(bytes[0], 5); // 1-byte length
        assert_eq!(&bytes[1..6], b"hello");
        // 4-byte length after the short container.
        assert_eq!(&bytes[6..10], &300u32.to_le_bytes());
    }

    #[test]
    #[should_panic(expected = "short container overflow")]
    fn short_container_overflow_panics() {
        let mut w = Writer::new();
        let ph = w.start_container(true);
        w.write_data(&[0u8; 256]);
        w.close_container(ph);
    }

    #[test]
    fn overshoot_is_sticky() {
        let bytes = [1u8, 2, 3];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u16(), Some(0x0201));
        assert!(r.read_u32().is_none()); // only 1 byte left
        assert!(r.overshoot());
        assert!(r.read_u8().is_none()); // sticky: still fails despite a byte remaining
        r.reset_read_pointer();
        assert_eq!(r.read_u8(), Some(1));
    }
}
