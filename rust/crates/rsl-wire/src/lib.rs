//! `rsl-wire` — a byte-exact, pure-Rust port of the RSL Paxos wire format.
//!
//! This crate reads and writes every RSL message identically to the original
//! C++ (`src/common/src/marshal.cpp`, `src/common/src/msn_fprint.cpp`,
//! `src/RSL/src/message.cpp`), proven against the golden corpus emitted by
//! `tools/golden-gen`. It performs zero I/O, contains zero `unsafe`, and has no
//! runtime dependencies.
//!
//! ## Layout
//! * [`fprint`] — Rabin-64 fingerprint (the message checksum).
//! * [`marshal`] — little-endian [`marshal::Reader`] / [`marshal::Writer`].
//! * [`types`] — [`MemberId`], [`BallotNumber`], [`RslNode`], [`MemberSet`].
//! * [`messages`] — the [`Header`] and the six concrete message types.
//! * [`version`] — [`ProtocolVersion`] and the per-version field rules.
//!
//! ## Endianness
//! Only the little-endian encoding path is ported; big-endian targets fail to
//! compile (see [`fprint`]).

pub mod fprint;
pub mod marshal;
pub mod messages;
pub mod types;
pub mod version;

pub use fprint::{fingerprint, fingerprint_with};
pub use messages::{
    marshal_base, unmarshal_base, verify_checksum, BootstrapMsg, Header, JoinMessage, Msg, MsgKind,
    PrepareAccepted, PrepareMsg, StatusResponse, Vote, MAGIC,
};
pub use types::{BallotNumber, MemberId, MemberSet, RslNode};
pub use version::ProtocolVersion;
