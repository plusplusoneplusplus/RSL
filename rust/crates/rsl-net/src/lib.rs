//! `rsl-net` — the RSL network layer: the framing, ported byte-exactly from the
//! original C++, and the packet transport built on it.
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
//! ## The framing has no runtime
//!
//! Everything in [`framing`] works on byte slices; its only I/O adapters take a
//! [`std::io::Read`]. That keeps the byte-exact kernel testable without a
//! scheduler — and `default-features = false` drops tokio entirely for a
//! consumer that wants nothing but the bytes.
//!
//! ## The learn port
//!
//! [`learnport`] (feature `learnport`, on by default) is the state-transfer
//! side: the `StatusQuery` / `FetchVotes` / `FetchCheckpoint` server and client
//! a lagging replica catches up with. It is the one part of this crate that
//! touches the disk, so it pulls in `rsl-storage`.
//!
//! ## The transport
//!
//! [`svc`] (feature `svc`, on by default) is `PacketSvc`: the tokio port of
//! `NetPacketSvc`/`NetCxn`/`NetProcessor`. Same four send statuses, same
//! send-queue-survives-a-disconnect rule, same suspend/resume, same connection
//! identity — see that module's docs for the contract and for the five
//! documented divergences.
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

#[cfg(feature = "learnport")]
pub mod learnport;
#[cfg(feature = "svc")]
pub mod svc;

pub use framing::learn::{self, LearnError};
pub use framing::packet::{self, FrameError, PacketHdr};
pub use framing::ReadError;
pub use limits::{ConfigError, Limits};

#[cfg(feature = "svc")]
pub use svc::{ConnectState, Packet, PacketHandler, PacketSvc, SvcConfig, TxRxStatus};

#[cfg(feature = "learnport")]
pub use learnport::{LearnClient, LearnConfig, LearnServer, Requester, TransferError};
