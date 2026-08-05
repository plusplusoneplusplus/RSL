//! Byte-level framing: [`packet`] (20-byte `PacketHdr`) and [`learn`]
//! (6-byte message-header prefix). Pure bytes plus thin [`std::io::Read`]
//! adapters — no runtime, no sockets.

pub mod learn;
pub mod packet;

use std::fmt;
use std::io;

/// Failure of a blocking read helper: transport trouble, a peer that stopped
/// mid-frame, or the framing decision itself (`E` is
/// [`packet::FrameError`] or [`learn::LearnError`]).
#[derive(Debug)]
pub enum ReadError<E> {
    /// The underlying reader failed.
    Io(io::Error),
    /// The stream ended part-way through a frame. The C++ treats a short
    /// `Read` exactly like a failed one: the message is dropped and the
    /// connection is torn down.
    UnexpectedEof,
    /// The bytes arrived but the framing rejects them; the connection must be
    /// closed (RSL never resynchronizes a stream).
    Framing(E),
}

impl<E> From<io::Error> for ReadError<E> {
    fn from(e: io::Error) -> ReadError<E> {
        ReadError::Io(e)
    }
}

impl<E: fmt::Display> fmt::Display for ReadError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "i/o error: {e}"),
            ReadError::UnexpectedEof => write!(f, "stream ended mid-frame"),
            ReadError::Framing(e) => write!(f, "{e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for ReadError<E> {}

/// Read exactly `buf.len()` bytes. Distinguishes "nothing at all was there"
/// (`Ok(false)`, i.e. a clean connection close between frames) from a partial
/// frame (`UnexpectedEof`).
pub(crate) fn read_exact_or_eof<R: io::Read, E>(
    r: &mut R,
    buf: &mut [u8],
) -> Result<bool, ReadError<E>> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(ReadError::UnexpectedEof),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ReadError::Io(e)),
        }
    }
    Ok(true)
}

/// Append exactly `len` more bytes to `out`, growing it in bounded steps.
///
/// This is the safety fix over the C++, which allocates the full untrusted size
/// up front (`NetPacket.cpp:428` / `message.cpp:672`). `len` has already been
/// checked against the cap by every caller; capping the *allocation* as well
/// means a peer that announces a legal-but-huge frame and then stalls costs us
/// one chunk, not the whole frame.
pub(crate) fn read_incrementally<R: io::Read, E>(
    r: &mut R,
    out: &mut Vec<u8>,
    len: usize,
) -> Result<(), ReadError<E>> {
    const CHUNK: usize = 64 * 1024;

    let target = out.len() + len;
    while out.len() < target {
        let want = (target - out.len()).min(CHUNK);
        let base = out.len();
        out.resize(base + want, 0);
        let mut filled = 0;
        while filled < want {
            match r.read(&mut out[base + filled..]) {
                Ok(0) => {
                    out.truncate(base + filled);
                    return Err(ReadError::UnexpectedEof);
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    out.truncate(base + filled);
                    return Err(ReadError::Io(e));
                }
            }
        }
    }
    Ok(())
}
