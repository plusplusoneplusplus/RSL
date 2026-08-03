//! Wire types shared across messages: [`MemberId`], [`BallotNumber`],
//! [`RslNode`], [`MemberSet`]. Ports of the same-named C++ classes in
//! `message.cpp` (member id / ballot) and `rsl.cpp` (node / member set,
//! extracted into `engine_min.cpp`).

use crate::marshal::{Reader, Writer};
use crate::version::ProtocolVersion;

/// Fixed on-wire size of a v>=4 member id (`MemberId::Size`).
pub const MEMBER_ID_SIZE: usize = 64;

/// Maximum member-id string length (`RSLNode::MaxMemberIdLength`); the 64th byte
/// is always the NUL terminator.
pub const MAX_MEMBER_ID_LEN: usize = 63;

/// Cap on a member-set configuration cookie
/// (`RSLMemberSet::s_MaxMemberSetCookieLength`).
pub const MAX_MEMBER_SET_COOKIE_LEN: u32 = 8192;

/// A replica member id.
///
/// The logical value is the ASCII id with no trailing NUL or padding. Its wire
/// form depends on the protocol version:
///
/// * `version <= 3`: a `u64` — the id parsed as an integer (empty id ⇒ `0`).
/// * `version >= 4`: a fixed 64-byte field, the value zero-padded to width.
///
/// A reader must tolerate non-zero padding after the NUL (the value stops at the
/// first NUL); a writer always zero-fills. See `MemberId::Marshal` /
/// `MemberId::UnMarshal`.
#[derive(Clone, Default, Debug)]
pub struct MemberId {
    value: Vec<u8>,
}

impl MemberId {
    /// Empty member id (marshals to `0` pre-v3, all-zero field at v>=4).
    pub fn empty() -> MemberId {
        MemberId { value: Vec::new() }
    }

    /// Build a member id from a string. Panics if it does not fit in the 64-byte
    /// field (mirrors the C++ `LogAssert(len < sizeof(m_value))`).
    #[allow(clippy::should_implement_trait)] // infallible convenience ctor, not FromStr
    pub fn from_str(s: &str) -> MemberId {
        Self::from_bytes(s.as_bytes())
    }

    /// Build a member id from raw value bytes (no NUL/padding). Panics if longer
    /// than [`MAX_MEMBER_ID_LEN`].
    pub fn from_bytes(bytes: &[u8]) -> MemberId {
        assert!(
            bytes.len() <= MAX_MEMBER_ID_LEN,
            "member id too long: {} > {MAX_MEMBER_ID_LEN}",
            bytes.len()
        );
        MemberId {
            value: bytes.to_vec(),
        }
    }

    /// The logical id bytes (no NUL/padding).
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The value as a UTF-8 string if it is valid UTF-8 (corpus ids always are).
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }

    /// On-wire size for `version` (`MemberId::GetBaseSize`).
    pub fn base_size(version: ProtocolVersion) -> u32 {
        if version.member_id_is_fixed64() {
            MEMBER_ID_SIZE as u32
        } else {
            8
        }
    }

    /// `MemberId::Marshal`.
    pub fn marshal(&self, w: &mut Writer, version: ProtocolVersion) {
        if version.member_id_is_fixed64() {
            let mut field = [0u8; MEMBER_ID_SIZE];
            field[..self.value.len()].copy_from_slice(&self.value);
            w.write_data(&field);
        } else {
            w.write_u64(parse_member_id_u64(&self.value));
        }
    }

    /// `MemberId::UnMarshal`. Returns `None` on a short buffer, or on a v>=4
    /// field with no NUL terminator (the C++ rejects via `StringCbLengthA`,
    /// `message.cpp:174-180`; this also preserves the crate's own
    /// [`MAX_MEMBER_ID_LEN`] invariant).
    pub fn unmarshal(r: &mut Reader, version: ProtocolVersion) -> Option<MemberId> {
        if version.member_id_is_fixed64() {
            let field = r.read_data(MEMBER_ID_SIZE as u32)?;
            // Value is everything up to the first NUL; ignore trailing padding.
            // A field with no NUL at all is rejected, matching the C++.
            let end = field.iter().position(|&b| b == 0)?;
            Some(MemberId {
                value: field[..end].to_vec(),
            })
        } else {
            let value = r.read_u64()?;
            // 0 ⇒ empty string; otherwise the decimal rendering ("%I64u").
            let value = if value == 0 {
                Vec::new()
            } else {
                value.to_string().into_bytes()
            };
            Some(MemberId { value })
        }
    }

    /// `MemberId::Compare` — equal-length ids compare byte-wise; otherwise the
    /// shorter id sorts first (the C++ returns the signed length difference).
    pub fn compare(&self, other: &MemberId) -> std::cmp::Ordering {
        self.cmp(other)
    }
}

impl PartialEq for MemberId {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for MemberId {}
impl PartialOrd for MemberId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for MemberId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.value.len() == other.value.len() {
            self.value.cmp(&other.value)
        } else {
            self.value.len().cmp(&other.value.len())
        }
    }
}

/// Parse a member-id string exactly as `RSLNode::ParseMemberIdAsUInt64`
/// (`rsl.cpp:30-38`) does: empty ⇒ 0, otherwise `_strtoui64(s, &end, 0)`
/// followed by `LogAssert(*end == 0)`.
///
/// `strtoull` semantics with base 0: optional leading whitespace and sign, base
/// auto-detected from the prefix (`0x` hex, leading `0` octal, else decimal),
/// overflow saturates to `u64::MAX`, a `-` negates by two's-complement wrap.
/// Anything left over after the digit run (including a string with no digits at
/// all) made the C++ `LogAssert`-abort; this port panics there instead —
/// unreachable for legally-configured clusters, and never reachable from the
/// reader (which only produces canonical decimal ids pre-v4).
///
/// Corpus ids are plain decimals; the full semantics keep writer-side value
/// parity with the C++ for any v<=3 id an application might have used.
fn parse_member_id_u64(value: &[u8]) -> u64 {
    if value.is_empty() {
        return 0;
    }

    let mut i = 0;
    // Leading whitespace (C `isspace`).
    while i < value.len() && (value[i] == b' ' || (0x09..=0x0d).contains(&value[i])) {
        i += 1;
    }
    // Optional sign.
    let mut negative = false;
    if i < value.len() && (value[i] == b'+' || value[i] == b'-') {
        negative = value[i] == b'-';
        i += 1;
    }
    // Base detection ("0x" only counts as a hex prefix if a hex digit follows;
    // otherwise the "0" is consumed as an octal digit and the "x" is garbage).
    let radix: u32 = if value.get(i) == Some(&b'0') {
        if matches!(value.get(i + 1), Some(b'x') | Some(b'X'))
            && value.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            i += 2;
            16
        } else {
            8
        }
    } else {
        10
    };

    let digits_start = i;
    let mut acc: u64 = 0;
    let mut overflow = false;
    while i < value.len() {
        let Some(d) = (value[i] as char).to_digit(radix) else {
            break;
        };
        let (v, o1) = acc.overflowing_mul(u64::from(radix));
        let (v, o2) = v.overflowing_add(u64::from(d));
        overflow |= o1 || o2;
        acc = v;
        i += 1;
    }

    // C++: LogAssert(*endPtr == NULL) — abort on trailing garbage, or when no
    // digits were converted (endPtr then points at the first character).
    assert!(
        i == value.len() && i > digits_start,
        "invalid v<=3 member id {:?}: not a full strtoull number (C++ LogAssert)",
        String::from_utf8_lossy(value)
    );

    if overflow {
        u64::MAX
    } else if negative {
        acc.wrapping_neg()
    } else {
        acc
    }
}

/// A Paxos ballot number: a `u32` id paired with the member that owns it.
/// Port of `BallotNumber`.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct BallotNumber {
    pub ballot_id: u32,
    pub member_id: MemberId,
}

impl BallotNumber {
    /// Construct a ballot.
    pub fn new(ballot_id: u32, member_id: MemberId) -> BallotNumber {
        BallotNumber {
            ballot_id,
            member_id,
        }
    }

    /// On-wire size for `version` (`BallotNumber::GetBaseSize`).
    pub fn base_size(version: ProtocolVersion) -> u32 {
        4 + MemberId::base_size(version)
    }

    /// `BallotNumber::Marshal`.
    pub fn marshal(&self, w: &mut Writer, version: ProtocolVersion) {
        w.write_u32(self.ballot_id);
        self.member_id.marshal(w, version);
    }

    /// `BallotNumber::UnMarshal`.
    pub fn unmarshal(r: &mut Reader, version: ProtocolVersion) -> Option<BallotNumber> {
        let ballot_id = r.read_u32()?;
        let member_id = MemberId::unmarshal(r, version)?;
        Some(BallotNumber {
            ballot_id,
            member_id,
        })
    }

    /// Ordering per the C++ comparison operators: by `ballot_id`, then by
    /// `member_id`.
    pub fn compare(&self, other: &BallotNumber) -> std::cmp::Ordering {
        self.cmp(other)
    }
}

impl PartialOrd for BallotNumber {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BallotNumber {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ballot_id
            .cmp(&other.ballot_id)
            .then_with(|| self.member_id.cmp(&other.member_id))
    }
}

/// A member of a replica set. Mirrors the marshaled subset of `RSLNode`
/// (`MemberSet::Marshal`); non-marshaled fields like `m_priority` are omitted.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct RslNode {
    pub member_id: MemberId,
    pub ip: u32,
    pub rsl_port: u16,
    /// Learn port; marshaled when `version > 3`.
    pub rsl_learn_port: u16,
    /// Deprecated app port; marshaled in place of the learn port when
    /// `version <= 3`.
    pub app_port: u16,
    pub host_name: Vec<u8>,
}

/// A replica set plus an opaque configuration cookie. Port of `MemberSet`
/// (`engine_min.cpp`).
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct MemberSet {
    pub members: Vec<RslNode>,
    pub cookie: Vec<u8>,
}

impl MemberSet {
    /// `MemberSet::Marshal`.
    pub fn marshal(&self, w: &mut Writer, version: ProtocolVersion) {
        w.write_u16(self.members.len() as u16);
        for node in &self.members {
            node.member_id.marshal(w, version);
            w.write_u32(node.ip);
            w.write_u16(node.rsl_port);
            if version.member_set_uses_learn_port() {
                w.write_u16(node.rsl_learn_port);
            } else {
                w.write_u16(node.app_port);
            }
            w.write_u16(node.host_name.len() as u16);
            w.write_data(&node.host_name);
        }
        w.write_u32(self.cookie.len() as u32);
        w.write_data(&self.cookie);
    }

    /// `MemberSet::UnMarshal`. Returns `None` on a short buffer or an
    /// over-length cookie.
    pub fn unmarshal(r: &mut Reader, version: ProtocolVersion) -> Option<MemberSet> {
        let num_members = r.read_u16()?;
        let mut members = Vec::with_capacity(num_members as usize);
        for _ in 0..num_members {
            let member_id = MemberId::unmarshal(r, version)?;
            let ip = r.read_u32()?;
            let rsl_port = r.read_u16()?;
            let (rsl_learn_port, app_port) = if version.member_set_uses_learn_port() {
                (r.read_u16()?, 0)
            } else {
                (0, r.read_u16()?)
            };
            let host_len = r.read_u16()?;
            let host_name = r.read_data(host_len as u32)?.to_vec();
            members.push(RslNode {
                member_id,
                ip,
                rsl_port,
                rsl_learn_port,
                app_port,
                host_name,
            });
        }

        let cookie_len = r.read_u32()?;
        if cookie_len > MAX_MEMBER_SET_COOKIE_LEN {
            return None;
        }
        let cookie = r.read_data(cookie_len)?.to_vec();

        Some(MemberSet { members, cookie })
    }

    /// `MemberSet::GetMarshalLen`.
    pub fn marshal_len(&self, version: ProtocolVersion) -> u32 {
        let node_fixed = MemberId::base_size(version) + 4 + 2 + 2 + 2;
        let mut len = node_fixed as usize * self.members.len() + 6 + self.cookie.len();
        for node in &self.members {
            len += node.host_name.len();
        }
        len as u32
    }
}

/// A replica-set configuration: the configuration number, the decree it takes
/// effect at, and the [`MemberSet`] itself. Port of `ConfigurationInfo`
/// (`RSL/src/checkpoint.h`, methods in `legislator.cpp:784-818`).
///
/// Only checkpoint headers marshal this type, but its encoding is plain wire
/// vocabulary — the same versioned `MemberSet` rules — so it lives here with the
/// other shared types rather than in `rsl-storage`.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ConfigurationInfo {
    pub configuration_number: u32,
    pub initial_decree: u64,
    pub member_set: MemberSet,
}

impl ConfigurationInfo {
    /// Build a configuration.
    pub fn new(
        configuration_number: u32,
        initial_decree: u64,
        member_set: MemberSet,
    ) -> ConfigurationInfo {
        ConfigurationInfo {
            configuration_number,
            initial_decree,
            member_set,
        }
    }

    /// `ConfigurationInfo::Marshal`.
    pub fn marshal(&self, w: &mut Writer, version: ProtocolVersion) {
        w.write_u32(self.configuration_number);
        w.write_u64(self.initial_decree);
        self.member_set.marshal(w, version);
    }

    /// `ConfigurationInfo::UnMarshal`. Returns `None` on a short buffer or an
    /// unparsable member set.
    pub fn unmarshal(r: &mut Reader, version: ProtocolVersion) -> Option<ConfigurationInfo> {
        let configuration_number = r.read_u32()?;
        let initial_decree = r.read_u64()?;
        let member_set = MemberSet::unmarshal(r, version)?;
        Some(ConfigurationInfo {
            configuration_number,
            initial_decree,
            member_set,
        })
    }

    /// `ConfigurationInfo::GetMarshalLen` — `4 + 8 + memberSet`.
    pub fn marshal_len(&self, version: ProtocolVersion) -> u32 {
        4 + 8 + self.member_set.marshal_len(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_info_round_trips_and_sizes_match() {
        let member_set = MemberSet {
            members: vec![
                RslNode {
                    member_id: MemberId::from_str("101"),
                    ip: 0x0100_007f,
                    rsl_port: 8080,
                    rsl_learn_port: 8081,
                    app_port: 0,
                    host_name: b"host-a".to_vec(),
                },
                RslNode {
                    member_id: MemberId::from_str("202"),
                    ip: 0x0100_017f,
                    rsl_port: 9090,
                    rsl_learn_port: 9091,
                    app_port: 0,
                    host_name: b"host-b".to_vec(),
                },
            ],
            cookie: b"cfg".to_vec(),
        };
        let cfg = ConfigurationInfo::new(0x0a0b_0c0d, 0x1001, member_set);

        for version in [ProtocolVersion::V4, ProtocolVersion::V6] {
            let mut w = Writer::new();
            cfg.marshal(&mut w, version);
            let bytes = w.into_bytes();
            assert_eq!(bytes.len() as u32, cfg.marshal_len(version));
            // The fixed prefix is the configuration number then the decree.
            assert_eq!(&bytes[..4], &0x0a0b_0c0du32.to_le_bytes());
            assert_eq!(&bytes[4..12], &0x1001u64.to_le_bytes());

            let mut r = Reader::new(&bytes);
            assert_eq!(
                ConfigurationInfo::unmarshal(&mut r, version),
                Some(cfg.clone())
            );
        }
    }

    #[test]
    fn configuration_info_rejects_short_buffers() {
        let cfg = ConfigurationInfo::new(1, 2, MemberSet::default());
        let mut w = Writer::new();
        cfg.marshal(&mut w, ProtocolVersion::V6);
        let bytes = w.into_bytes();
        for cut in 0..bytes.len() {
            let mut r = Reader::new(&bytes[..cut]);
            assert!(ConfigurationInfo::unmarshal(&mut r, ProtocolVersion::V6).is_none());
        }
    }

    #[test]
    fn member_id_pre_v3_is_u64() {
        let id = MemberId::from_str("101");
        let mut w = Writer::new();
        id.marshal(&mut w, ProtocolVersion::V1);
        assert_eq!(w.as_bytes(), &101u64.to_le_bytes());

        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let back = MemberId::unmarshal(&mut r, ProtocolVersion::V1).unwrap();
        assert_eq!(back.value(), b"101");
    }

    #[test]
    fn member_id_v4_is_zero_padded_64() {
        let id = MemberId::from_str("202");
        let mut w = Writer::new();
        id.marshal(&mut w, ProtocolVersion::V4);
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[..3], b"202");
        assert!(bytes[3..].iter().all(|&b| b == 0));

        // Reader must tolerate garbage padding after the NUL.
        let mut noisy = bytes.clone();
        noisy[10] = 0xff;
        let mut r = Reader::new(&noisy);
        let back = MemberId::unmarshal(&mut r, ProtocolVersion::V4).unwrap();
        assert_eq!(back.value(), b"202");
    }

    #[test]
    fn member_id_v4_without_nul_is_rejected() {
        // D1: a 64-byte field with no NUL anywhere must not parse (C++ rejects
        // via StringCbLengthA; accepting it would break the 63-byte invariant).
        let field = [b'A'; MEMBER_ID_SIZE];
        let mut r = Reader::new(&field);
        assert!(MemberId::unmarshal(&mut r, ProtocolVersion::V4).is_none());

        // NUL in the last byte (a full 63-char id) is still fine.
        let mut field = [b'A'; MEMBER_ID_SIZE];
        field[63] = 0;
        let mut r = Reader::new(&field);
        let id = MemberId::unmarshal(&mut r, ProtocolVersion::V4).unwrap();
        assert_eq!(id.value().len(), MAX_MEMBER_ID_LEN);
    }

    #[test]
    fn member_id_u64_parse_matches_strtoull() {
        // D4: writer-side value parity with _strtoui64(s, &end, 0).
        let parse = |s: &str| parse_member_id_u64(s.as_bytes());
        assert_eq!(parse(""), 0);
        assert_eq!(parse("101"), 101);
        assert_eq!(parse("0x1f"), 0x1f);
        assert_eq!(parse("017"), 0o17);
        assert_eq!(parse("0"), 0);
        assert_eq!(parse(" \t42"), 42);
        assert_eq!(parse("+7"), 7);
        // '-' negates by unsigned wraparound.
        assert_eq!(parse("-1"), u64::MAX);
        // Overflow saturates to ULLONG_MAX (C++ wrote that value; the old Rust
        // code silently wrote 0).
        assert_eq!(parse("18446744073709551615"), u64::MAX);
        assert_eq!(parse("18446744073709551616"), u64::MAX);
        assert_eq!(parse("99999999999999999999999"), u64::MAX);
        assert_eq!(parse("0xffffffffffffffffff"), u64::MAX);
    }

    #[test]
    #[should_panic(expected = "invalid v<=3 member id")]
    fn member_id_u64_trailing_garbage_panics() {
        // C++ LogAssert(*endPtr == NULL) aborts on "123abc".
        parse_member_id_u64(b"123abc");
    }

    #[test]
    #[should_panic(expected = "invalid v<=3 member id")]
    fn member_id_u64_no_digits_panics() {
        // strtoull converts nothing; endPtr stays at 'a' — C++ aborts.
        parse_member_id_u64(b"abc");
    }

    #[test]
    fn empty_member_id_pre_v3_is_zero() {
        let mut w = Writer::new();
        MemberId::empty().marshal(&mut w, ProtocolVersion::V2);
        assert_eq!(w.as_bytes(), &[0u8; 8]);
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(
            MemberId::unmarshal(&mut r, ProtocolVersion::V2)
                .unwrap()
                .value(),
            b""
        );
    }
}
