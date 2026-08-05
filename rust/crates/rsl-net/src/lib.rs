//! `rsl-net` — the RSL network framing layer, ported byte-exactly from the
//! original C++ and kept free of any async runtime.
//!
//! Two framings exist in RSL and both live in [`framing`]:
//!
//! * **Packet framing** ([`framing::packet`]) — the 20-byte `PacketHdr`
//!   (`src/NetworkLib/src/NetPacket.cpp`) that wraps every replica-to-replica
//!   message, plus the receive decision table from `NetCxn::ReadReadyInternal`.
//! * **Learn-port framing** ([`framing::learn`]) — the fetch/status sockets,
//!   where a message's own first six bytes (`u16` version + `u32` length) size
//!   the read (`Message::ReadFromSocket`, `src/RSL/src/message.cpp:639`).
//!
//! The [`Limits`] type carries the `maxMessageSize` cap (the Phase-2
//! carry-forward) shared by both.
//!
//! ## No runtime, no I/O model
//!
//! Everything here works on byte slices; the only I/O adapters take a
//! [`std::io::Read`]. Phase 4b/4c pick their own I/O model (tokio) on top, and
//! the tests stay deterministic.
//!
//! ## Deliberate divergences from the C++
//!
//! The port matches the C++ byte-for-byte and decision-for-decision, with these
//! documented exceptions — all of them places where the original is unsafe:
//!
//! * **Bounded reads.** The C++ receive path allocates a buffer from the
//!   untrusted header size *before* it has all the bytes. The readers here
//!   check the size cap first and then grow incrementally
//!   ([`framing::packet::read_packet`], [`framing::learn::read_message`]), so a
//!   hostile 100 MB size field costs nothing until the bytes actually arrive.
//! * **Learn length below the 6-byte header.** `Message::ReadFromSocket`
//!   `malloc`s `length` bytes and then `memcpy`s 6 into it — a heap overflow for
//!   `length < 6`. Here that is
//!   [`framing::learn::LearnError::LengthBelowHeader`]. The golden corpus marks
//!   this vector `EXEC no` because no faithful C++ outcome exists for it.
//!
//! Everything else — including the two *different* checksum domains (the packet
//! checksum covers the whole frame with a zeroed checksum field; the message
//! checksum covers the message after its own checksum field) — is reproduced
//! exactly.

pub mod framing;
pub mod limits;

pub use framing::learn::{self, LearnError};
pub use framing::packet::{self, FrameError, PacketHdr};
pub use framing::ReadError;
pub use limits::{ConfigError, Limits};
