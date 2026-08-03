//! RSL protocol versions (`RSLProtocolVersion` in `rsl.h`) and the per-version
//! field-presence rules the wire format keys off.
//!
//! Ports of the version-gated branches in `message.cpp` / `rsl.cpp` are written
//! against the predicate methods here, so the field rules live in exactly one
//! place. See the C++ `enum RSLProtocolVersion` (`src/inc/rsl.h`).

/// A protocol version, wire-encoded as a little-endian `u16`.
///
/// Only the six documented versions (`1..=6`) are valid on the wire; anything
/// else is rejected by [`ProtocolVersion::from_wire`], mirroring
/// `Message::IsVersionValid`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// First protocol version.
    pub const V1: ProtocolVersion = ProtocolVersion(1);
    /// Adds a primary cookie carried in the message body.
    pub const V2: ProtocolVersion = ProtocolVersion(2);
    /// Adds replica-set management (configuration number, member sets,
    /// 64-byte member ids).
    pub const V3: ProtocolVersion = ProtocolVersion(3);
    /// Adds checkpoint checksum + bootstrap.
    pub const V4: ProtocolVersion = ProtocolVersion(4);
    /// Adds the `relinquishPrimary` flag on votes.
    pub const V5: ProtocolVersion = ProtocolVersion(5);
    /// Adds a payload on votes from secondaries.
    pub const V6: ProtocolVersion = ProtocolVersion(6);

    /// Every valid version, in ascending order.
    pub const ALL: [ProtocolVersion; 6] =
        [Self::V1, Self::V2, Self::V3, Self::V4, Self::V5, Self::V6];

    /// Parse a version off the wire, rejecting unknown values.
    ///
    /// Mirrors `Message::IsVersionValid`.
    pub fn from_wire(raw: u16) -> Option<ProtocolVersion> {
        match raw {
            1..=6 => Some(ProtocolVersion(raw)),
            _ => None,
        }
    }

    /// The raw `u16` written to / read from the wire.
    pub fn raw(self) -> u16 {
        self.0
    }

    /// Member ids are marshaled as a fixed 64-byte field once `version > 3`;
    /// at `version <= 3` they are a `u64`. (`MemberId::Marshal`.)
    pub fn member_id_is_fixed64(self) -> bool {
        self.0 > 3
    }

    /// The configuration number is present from v3 onward. (`Message::Marshal`.)
    pub fn has_configuration_number(self) -> bool {
        self.0 >= 3
    }

    /// Votes carry a payload from v6 onward. (`Message::Marshal`.)
    pub fn has_payload(self) -> bool {
        self.0 >= 6
    }

    /// The primary cookie is marshaled into Vote/Prepare bodies from v2 onward.
    pub fn has_primary_cookie(self) -> bool {
        self.0 >= 2
    }

    /// Reconfiguration byte + member set live in the Vote body from v3 onward.
    pub fn has_reconfiguration(self) -> bool {
        self.0 >= 3
    }

    /// The `relinquishPrimary` byte lives in the Vote body from v5 onward.
    pub fn has_relinquish_primary(self) -> bool {
        self.0 >= 5
    }

    /// A checkpoint header carries its own fields (version, length, checksum,
    /// member id, last executed decree, max ballot, configuration) from v3
    /// onward; before that a checkpoint file is a bare page-rounded vote.
    /// (`CheckpointHeader::Marshal`, `legislator.cpp:893`.)
    pub fn has_checkpoint_header(self) -> bool {
        self.0 >= 3
    }

    /// A checkpoint header carries `stateSaved` + file size + checksum block
    /// size — and therefore the block-checksummed user-state stream — from v4
    /// onward. (`CheckpointHeader::Marshal`, `legislator.cpp:914`.)
    pub fn has_checkpoint_blocks(self) -> bool {
        self.0 >= 4
    }

    /// In a `MemberSet`, node ports are marshaled as `rslLearnPort` once
    /// `version > 3`, otherwise as the deprecated `appPort`.
    /// (`MemberSet::Marshal`, note the strict `>`: v3 still uses `appPort`.)
    pub fn member_set_uses_learn_port(self) -> bool {
        self.0 > 3
    }
}
