//! The message-size cap shared by both framings.
//!
//! Ported from `ConfigParam::Init` (`src/RSL/src/rslconfig.cpp:59-60,118-124`)
//! and the `Packet` constructor (`src/NetworkLib/src/NetPacket.cpp:302-311`).

use std::fmt;

/// `MaxNetPacketSize` — `src/NetworkLib/inc/NetPacket.h:33`.
pub const MAX_NET_PACKET_SIZE: u32 = 100 * 1024 * 1024;

/// `MaxNetPacketAlertSize` — `NetPacket.h:35`. Zero means "no alert".
pub const MAX_NET_PACKET_ALERT_SIZE: u32 = 0;

/// `RSLConfig::s_MaxMessageLen` — `src/RSL/src/rslconfig.h:62`, in MB.
pub const DEFAULT_MAX_MESSAGE_SIZE_MB: u32 = 100;

const ONE_MB: u32 = 1024 * 1024;

/// Rejected configuration, mirroring the `Get`/`GetMax` macros in
/// `rslconfig.cpp` (which log "Configuration Error" and fail `Init`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `Get(m_maxMessageSizeMB, .., 1, INT_MAX)` — must be in `[1, i32::MAX]`.
    MaxMessageSizeMb(u32),
    /// `GetMax(m_maxMessageAlertSizeMB, .., INT_MAX)` — must be `<= i32::MAX`.
    MaxMessageAlertSizeMb(u32),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MaxMessageSizeMb(v) => {
                write!(f, "maxMessageSizeMB {v} outside [1, {}]", i32::MAX)
            }
            ConfigError::MaxMessageAlertSizeMb(v) => {
                write!(f, "maxMessageAlertSizeMB {v} above {}", i32::MAX)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// The size cap (and optional alert threshold) applied to received frames.
///
/// Both values are stored exactly as the C++ `PacketFactory` receives them
/// (`legislator.cpp:6372`), i.e. **zero means "use the `NetPacket.h` default"**:
/// zero max → [`MAX_NET_PACKET_SIZE`], zero alert → no alert. Use
/// [`Limits::effective_max`] / [`Limits::effective_alert`] to resolve them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    max_size: u32,
    alert_size: u32,
}

impl Default for Limits {
    /// The `PacketFactory`'s own defaults: the 100 MB `NetPacket.h` cap, no alert.
    fn default() -> Limits {
        Limits {
            max_size: 0,
            alert_size: 0,
        }
    }
}

impl Limits {
    /// Take the two byte counts as-is (zero = "default", as above). This is the
    /// form the golden corpus records, so tests can replay `MAXSIZE`/`MAXALERT`
    /// verbatim.
    pub fn from_raw(max_size: u32, alert_size: u32) -> Limits {
        Limits {
            max_size,
            alert_size,
        }
    }

    /// Build from the RSL config knobs, in MB, exactly as `ConfigParam::Init`
    /// does: validate the range, multiply by 1 MiB, then add 1 KB "for rsl
    /// message headers" (`rslconfig.cpp:118-124`).
    ///
    /// `alert_mb == 0` disables the alert.
    ///
    /// # Overflow
    ///
    /// The C++ does this arithmetic in a `UInt32` and wraps: 4096 MB becomes
    /// `4096 * 1 MiB == 2^32 → 0`, plus 1024, i.e. a **1 KB** cap. That is
    /// faithfully reproduced here rather than saturated, because a Rust node
    /// must agree with a C++ node configured the same way. Configurations at or
    /// above 4096 MB are therefore a footgun in both implementations.
    pub fn from_config_mb(max_mb: u32, alert_mb: u32) -> Result<Limits, ConfigError> {
        if max_mb < 1 || max_mb > i32::MAX as u32 {
            return Err(ConfigError::MaxMessageSizeMb(max_mb));
        }
        if alert_mb > i32::MAX as u32 {
            return Err(ConfigError::MaxMessageAlertSizeMb(alert_mb));
        }

        let max_size = max_mb.wrapping_mul(ONE_MB).wrapping_add(1024);
        let alert_size = if alert_mb > 0 {
            alert_mb.wrapping_mul(ONE_MB).wrapping_add(1024)
        } else {
            0
        };
        Ok(Limits {
            max_size,
            alert_size,
        })
    }

    /// The raw configured maximum (zero = default).
    pub fn raw_max(&self) -> u32 {
        self.max_size
    }

    /// The raw configured alert threshold (zero = off).
    pub fn raw_alert(&self) -> u32 {
        self.alert_size
    }

    /// The cap actually enforced — `(maxSize) ? maxSize : MaxNetPacketSize`.
    pub fn effective_max(&self) -> u32 {
        if self.max_size != 0 {
            self.max_size
        } else {
            MAX_NET_PACKET_SIZE
        }
    }

    /// The alert threshold actually applied, or `None` when alerting is off.
    pub fn effective_alert(&self) -> Option<u32> {
        let alert = if self.alert_size != 0 {
            self.alert_size
        } else {
            MAX_NET_PACKET_ALERT_SIZE
        };
        (alert > 0).then_some(alert)
    }

    /// Whether a frame of `size` bytes trips the alert threshold. Purely
    /// informational: the C++ logs and keeps going (`NetPacket.cpp:457-462`).
    pub fn alerts_on(&self, size: u32) -> bool {
        self.effective_alert().is_some_and(|alert| size > alert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_the_netpacket_header() {
        let limits = Limits::default();
        assert_eq!(limits.effective_max(), MAX_NET_PACKET_SIZE);
        assert_eq!(limits.effective_alert(), None);
    }

    #[test]
    fn config_mb_adds_the_1kb_header_allowance() {
        let limits = Limits::from_config_mb(DEFAULT_MAX_MESSAGE_SIZE_MB, 0).unwrap();
        assert_eq!(limits.effective_max(), 100 * 1024 * 1024 + 1024);
        assert_eq!(limits.effective_alert(), None);

        let limits = Limits::from_config_mb(1, 1).unwrap();
        assert_eq!(limits.effective_max(), 1024 * 1024 + 1024);
        assert_eq!(limits.effective_alert(), Some(1024 * 1024 + 1024));
    }

    #[test]
    fn config_mb_rejects_out_of_range_values() {
        assert_eq!(
            Limits::from_config_mb(0, 0),
            Err(ConfigError::MaxMessageSizeMb(0))
        );
        let too_big = i32::MAX as u32 + 1;
        assert_eq!(
            Limits::from_config_mb(too_big, 0),
            Err(ConfigError::MaxMessageSizeMb(too_big))
        );
        assert_eq!(
            Limits::from_config_mb(1, too_big),
            Err(ConfigError::MaxMessageAlertSizeMb(too_big))
        );
    }

    #[test]
    fn config_mb_wraps_exactly_like_the_cpp_uint32() {
        // 4096 MB * 1 MiB overflows a UInt32 to zero; +1024 leaves a 1 KB cap.
        assert_eq!(
            Limits::from_config_mb(4096, 0).unwrap().effective_max(),
            1024
        );
    }
}
