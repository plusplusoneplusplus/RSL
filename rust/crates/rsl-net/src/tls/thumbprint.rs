//! Certificate thumbprints — the identity pins the whole trust model rests on.
//!
//! A thumbprint is the SHA-1 of a certificate's DER encoding: what Windows
//! calls `CERT_SHA1_HASH_PROP_ID` (`SSLAuth::GetCertificateThumbprint`,
//! `SSLImpl.cpp:712`) and what an operator copies out of `certmgr.msc`.
//!
//! **SHA-1 is used here as an identity pin, not as a signature.** A collision
//! would have to be against a certificate an operator explicitly listed, in a
//! deployment where that same operator controls the issuing CA; the property
//! being relied on is second-preimage resistance of SHA-1 over a DER blob
//! whose structure the attacker does not control end to end. That is a
//! different (and far stronger) position than SHA-1-in-a-signature. It stays
//! SHA-1 because the pins are operator-facing configuration shared with the
//! C++ fleet during migration — changing the hash changes every config file.

use std::fmt;

use sha1::{Digest, Sha1};

/// The 20 bytes of a SHA-1 certificate thumbprint (`SHA1_HASH_SIZE`).
pub const LEN: usize = 20;

/// A SHA-1 certificate thumbprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Thumbprint([u8; LEN]);

impl Thumbprint {
    /// The thumbprint of a DER-encoded certificate.
    ///
    /// The input must be the *certificate's own* DER, exactly as it appeared in
    /// the TLS `Certificate` message — not a re-encoding. rustls hands
    /// verifiers the original bytes, so there is nothing to get wrong here as
    /// long as callers never round-trip through a parser.
    pub fn of_der(der: &[u8]) -> Thumbprint {
        Thumbprint(Sha1::digest(der).into())
    }

    /// The raw 20 bytes.
    pub fn as_bytes(&self) -> &[u8; LEN] {
        &self.0
    }

    /// Build from raw bytes.
    pub fn from_bytes(bytes: [u8; LEN]) -> Thumbprint {
        Thumbprint(bytes)
    }

    /// Parse the hex form an operator configures —
    /// `SSLAuth::ConvertStringThumbprintToByteArray` (`SSLImpl.cpp:675`).
    ///
    /// Two deliberate details, both matched to the C++ on purpose:
    ///
    /// * The length rule is `s.len() / 2 == 20`, so a 41-character string is
    ///   accepted and its last character ignored — the C++ computes
    ///   `strlen(thumbprint) / 2` and compares that. Configs in the wild have
    ///   trailing junk (`certmgr` copies the thumbprint with a leading
    ///   invisible `U+200E`, which operators strip by hand and sometimes
    ///   miscount); rejecting those would fail a fleet the C++ accepts.
    /// * **Divergence:** a non-hex character is an error here. `HexToDec`
    ///   returns `0` for anything it does not recognize, so in the C++ a
    ///   mistyped thumbprint silently becomes a *different, valid-looking* pin
    ///   — the one failure mode of an identity pin that must never be silent.
    pub fn parse(s: &str) -> Result<Thumbprint, ParseError> {
        let bytes = s.as_bytes();
        if bytes.len() / 2 != LEN {
            return Err(ParseError::Length { got: bytes.len() });
        }
        let mut out = [0u8; LEN];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = hex(bytes[i * 2])?;
            let lo = hex(bytes[i * 2 + 1])?;
            *slot = hi * 16 + lo;
        }
        Ok(Thumbprint(out))
    }

    /// Parse the `;`-separated list form used for parent pins —
    /// `ConvertStringThumbprintsToArrayOfByteArray` (`SSLImpl.cpp:565`).
    ///
    /// The C++ splits on `;` and parses every field including the one after the
    /// last separator, so a trailing `;` produces an empty field and fails the
    /// whole list. Same here.
    pub fn parse_list(s: &str) -> Result<Vec<Thumbprint>, ParseError> {
        s.split(';').map(Thumbprint::parse).collect()
    }
}

fn hex(c: u8) -> Result<u8, ParseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ParseError::NotHex { c: c as char }),
    }
}

/// Lowercase hex, as `SSLAuth::HexToString` (`SSLImpl.cpp:660`) produces for
/// the log lines an operator greps.
impl fmt::Display for Thumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Thumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Thumbprint({self})")
    }
}

/// Why a configured thumbprint string is not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Not 20 bytes' worth of hex.
    Length { got: usize },
    /// A character that is not a hex digit.
    NotHex { c: char },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Length { got } => write!(
                f,
                "a thumbprint is 40 hex characters (SHA-1); got {got} characters"
            ),
            ParseError::NotHex { c } => write!(f, "{c:?} is not a hex digit"),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "1b32891adb56d3f7115e7e031cc41e1793252015";

    #[test]
    fn hex_round_trips_through_the_cpp_spelling() {
        let t = Thumbprint::parse(HEX).expect("valid");
        assert_eq!(t.to_string(), HEX);
        // Uppercase parses to the same pin; `HexToString` always emits lower.
        assert_eq!(Thumbprint::parse(&HEX.to_uppercase()).expect("valid"), t);
    }

    #[test]
    fn the_length_rule_is_the_cpp_strlen_over_two() {
        // 40 and 41 characters both give `strlen / 2 == 20`.
        assert!(Thumbprint::parse(HEX).is_ok());
        assert!(Thumbprint::parse(&format!("{HEX}0")).is_ok());
        assert_eq!(
            Thumbprint::parse(&format!("{HEX}00")),
            Err(ParseError::Length { got: 42 })
        );
        assert_eq!(
            Thumbprint::parse(&HEX[..38]),
            Err(ParseError::Length { got: 38 })
        );
    }

    #[test]
    fn a_non_hex_character_is_rejected_rather_than_read_as_zero() {
        // The C++ `HexToDec` would turn this into ...20`0`5 and pin a
        // certificate the operator never named.
        assert_eq!(
            Thumbprint::parse(&HEX.replace("15", "1z")),
            Err(ParseError::NotHex { c: 'z' })
        );
    }

    #[test]
    fn a_list_splits_on_semicolons_and_rejects_a_trailing_one() {
        let list = Thumbprint::parse_list(&format!("{HEX};{HEX}")).expect("valid");
        assert_eq!(list.len(), 2);
        assert!(Thumbprint::parse_list(&format!("{HEX};")).is_err());
    }

    #[test]
    fn the_digest_is_sha1_of_the_der() {
        // SHA-1 of the empty input, the one vector everyone knows.
        assert_eq!(
            Thumbprint::of_der(b"").to_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }
}
