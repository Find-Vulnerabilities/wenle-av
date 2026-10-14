//! The rules the vault enforces on itself: how big an item may be, how big the
//! whole vault may grow, and how long anything stays.
//!
//! Kept as a distinct type from [`av_core::config::QuarantineConfig`] rather
//! than passing the configuration section through, for two reasons. The vault
//! has settings the configuration document has no business carrying — how many
//! times to retry a deletion, whether to re-verify a payload before writing it
//! back — and the configuration carries policy the vault does not act on, like
//! whether to prompt before quarantining. The conversion between them is one
//! function, written out, so a new configuration field has to be considered
//! here rather than silently ignored.

use std::time::Duration;

use av_core::config::QuarantineConfig;

/// What the vault enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinePolicy {
    /// Encrypt item payloads at rest. The index is always sealed regardless:
    /// it is small, it is written rarely, and it is what a restore reads a
    /// destination path out of.
    pub encrypt: bool,
    /// Largest single file the vault will accept.
    pub max_item_size: u64,
    /// Ceiling on the total size of live items. The oldest are evicted when it
    /// is crossed.
    pub max_vault_size: u64,
    /// How long an item is kept. `None` keeps everything until the user says
    /// otherwise.
    pub retention: Option<Duration>,
    /// Re-verify a payload's digest before writing it back to disk.
    ///
    /// On by default, and the cost is one SHA-256 of the file being restored —
    /// which is nothing next to the cost of being wrong. A restore writes an
    /// executable into the filesystem and, if the user ticks the box, into an
    /// exclusion; handing back bytes that are not the bytes that were
    /// quarantined would be the worst thing this crate could do.
    pub verify_on_restore: bool,
    /// How many times to try deleting an original before giving up on it.
    pub max_removal_attempts: u32,
}

impl Default for QuarantinePolicy {
    fn default() -> Self {
        Self {
            encrypt: true,
            // Larger than the scanner's own 256 MiB file limit, because the
            // vault is also the destination for things the scanner did not
            // choose to read, and refusing a file *because* it is large is a
            // fine reason to scan it and a terrible reason to leave it running.
            max_item_size: 512 * 1024 * 1024,
            max_vault_size: 2 * 1024 * 1024 * 1024,
            retention: Some(Duration::from_secs(30 * 24 * 60 * 60)),
            verify_on_restore: true,
            max_removal_attempts: 10,
        }
    }
}

impl From<&QuarantineConfig> for QuarantinePolicy {
    fn from(config: &QuarantineConfig) -> Self {
        Self {
            encrypt: config.encrypt,
            max_vault_size: config.max_size_bytes,
            retention: config
                .retention_days
                .map(|days| Duration::from_secs(days.saturating_mul(24 * 60 * 60))),
            ..Self::default()
        }
    }
}

impl QuarantinePolicy {
    /// A policy with no limits and no retention, for tests and for a forensic
    /// workstation where nothing should ever be discarded.
    pub fn unlimited() -> Self {
        Self {
            max_item_size: u64::MAX,
            max_vault_size: u64::MAX,
            retention: None,
            ..Self::default()
        }
    }

    /// Turn encryption off. Documented as a diagnostic setting: see
    /// [`crate::crypto`].
    pub fn without_encryption(mut self) -> Self {
        self.encrypt = false;
        self
    }

    /// Keep everything forever.
    pub fn keeping_everything(mut self) -> Self {
        self.retention = None;
        self
    }

    /// The largest item this policy accepts, as a byte count.
    pub fn accepts_size(&self, size: u64) -> bool {
        size <= self.max_item_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_encrypts_and_verifies() {
        let p = QuarantinePolicy::default();
        assert!(p.encrypt);
        assert!(p.verify_on_restore);
        assert!(p.retention.is_some());
    }

    #[test]
    fn the_configuration_is_carried_across() {
        let config = QuarantineConfig {
            encrypt: false,
            retention_days: Some(7),
            max_size_bytes: 4096,
            ..QuarantineConfig::default()
        };
        let p = QuarantinePolicy::from(&config);
        assert!(!p.encrypt);
        assert_eq!(p.max_vault_size, 4096);
        assert_eq!(p.retention, Some(Duration::from_secs(7 * 24 * 60 * 60)));
        // Settings the configuration does not carry keep the vault's defaults.
        assert!(p.verify_on_restore);
    }

    #[test]
    fn a_configuration_keeping_items_forever_maps_to_no_retention() {
        let config = QuarantineConfig {
            retention_days: None,
            ..QuarantineConfig::default()
        };
        assert_eq!(QuarantinePolicy::from(&config).retention, None);
    }

    #[test]
    fn an_absurd_retention_cannot_overflow_the_duration() {
        let config = QuarantineConfig {
            retention_days: Some(u64::MAX),
            ..QuarantineConfig::default()
        };
        // Saturating rather than wrapping: a retention that wrapped would
        // purge the vault instead of keeping it.
        assert!(QuarantinePolicy::from(&config).retention.is_some());
    }

    #[test]
    fn the_item_limit_is_inclusive() {
        let p = QuarantinePolicy {
            max_item_size: 100,
            ..QuarantinePolicy::default()
        };
        assert!(p.accepts_size(100));
        assert!(!p.accepts_size(101));
    }

    #[test]
    fn the_unlimited_policy_accepts_anything_and_keeps_it() {
        let p = QuarantinePolicy::unlimited();
        assert!(p.accepts_size(u64::MAX));
        assert_eq!(p.retention, None);
    }
}
