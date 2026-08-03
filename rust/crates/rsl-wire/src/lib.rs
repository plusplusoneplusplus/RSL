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
//! * [`types`] — [`MemberId`], [`BallotNumber`], [`RslNode`], [`MemberSet`],
//!   [`ConfigurationInfo`].
//! * [`messages`] — the [`Header`] and the six concrete message types.
//! * [`version`] — [`ProtocolVersion`] and the per-version field rules.
//!
//! ## Endianness
//! Only the little-endian encoding path is ported; big-endian targets fail to
//! compile (see [`fprint`]).
//!
//! ## Differential-fuzzer whitelist (intentional divergences from C++)
//!
//! For every byte the writer emits for representable messages, and for
//! accept/reject on well-formed input, this crate matches the C++ observably.
//! The known exceptions are inputs where the C++ `LogAssert`-**aborts** the
//! whole process; there the Rust stays safe (accepts or cleanly rejects)
//! instead of crashing. A future C++-vs-Rust differential fuzzer (Phase 4/6)
//! must whitelist these, or it will flag them as port bugs:
//!
//! * **Oversized hostname in a `MemberSet` node** — a `u16` hostname length
//!   `>= 64` aborts the C++ reader (`LogAssert(hostNameLength <
//!   sizeof(node.m_hostName))`, `rsl.cpp:1161`); the Rust reader accepts any
//!   length the buffer can satisfy.
//! * **Reconfiguration vote with trailing bytes** — the C++ vote parser aborts
//!   on any bytes after the member set (`LogAssert(!m_isReconfiguration)`,
//!   `message.cpp:953`); the Rust reader parses them as requests. The Rust
//!   *writer* refuses to emit that shape
//!   ([`messages::MarshalError::ReconfigurationVoteWithRequests`]), so the
//!   port can never produce a message that would kill a C++ peer.
//! * **`verify_checksum` on a wrong-length buffer** — the C++ asserts
//!   `len == m_unMarshalLen` (`message.cpp:559`); [`verify_checksum`] returns
//!   `false` instead.
//! * **v>=4 member id with no NUL in its 64-byte field** — both sides reject
//!   (C++ via `StringCbLengthA`, `message.cpp:174-180`); listed only because
//!   pre-closure builds of this crate accepted it.
//! * **Invalid v<=3 member-id string on the *writer* path** — trailing
//!   garbage / no digits made the C++ `LogAssert`-abort in
//!   `RSLNode::ParseMemberIdAsUInt64` (`rsl.cpp:30-38`); the Rust panics with
//!   the same trigger condition (not reachable from parsed input).

pub mod fprint;
pub mod marshal;
pub mod messages;
pub mod types;
pub mod version;

pub use fprint::{fingerprint, fingerprint_with};
pub use messages::{
    marshal_base, unmarshal_base, verify_checksum, BootstrapMsg, Header, JoinMessage, MarshalError,
    Msg, MsgKind, PrepareAccepted, PrepareMsg, StatusResponse, Vote, MAGIC,
};
pub use types::{BallotNumber, ConfigurationInfo, MemberId, MemberSet, RslNode};
pub use version::ProtocolVersion;
