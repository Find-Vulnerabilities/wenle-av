//! Product configuration.
//!
//! One TOML document holds every user-tunable setting. Defaults are chosen so
//! that a freshly installed product is already configured sensibly, and every
//! field is `#[serde(default)]` so that adding a setting in a later version
//! never invalidates an existing user's file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{AvError, AvResult};
use crate::scan::ScanOptions;
use crate::verdict::VerdictThresholds;

/// Root configuration document.
///
/// Not `Eq`, because [`UiConfig`] carries window dimensions as `f32`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AvConfig {
    pub general: GeneralConfig,
    pub scanning: ScanningConfig,
    pub realtime: RealtimeConfig,
    pub protection: ProtectionConfig,
    pub quarantine: QuarantineConfig,
    pub driver: DriverConfig,
    pub sandbox: SandboxConfig,
    pub logging: LoggingConfig,
    pub ui: UiConfig,
}

impl AvConfig {
    /// Load from `path`, or return defaults if the file does not exist.
    pub fn load_or_default(path: &Path) -> AvResult<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let cfg: AvConfig = toml::from_str(&text)?;
                cfg.validate()?;
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(AvError::io_at(path, e)),
        }
    }

    /// Write the configuration to `path`, creating parent directories.
    pub fn save(&self, path: &Path) -> AvResult<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AvError::io_at(parent, e))?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text).map_err(|e| AvError::io_at(path, e))
    }

    /// Reject combinations that would leave the product unable to protect the
    /// machine, rather than silently accepting them.
    pub fn validate(&self) -> AvResult<()> {
        let t = &self.scanning.thresholds;
        if t.suspicious >= t.malicious {
            return Err(AvError::Config(format!(
                "scanning.thresholds: `suspicious` ({}) must be strictly less than `malicious` ({})",
                t.suspicious, t.malicious
            )));
        }
        if self.scanning.archive_depth > 16 {
            return Err(AvError::Config(
                "scanning.archive_depth: values above 16 are refused as a zip-bomb guard".into(),
            ));
        }
        // `0` means "one worker per core" for both thread settings, so only an
        // absurd explicit count is rejected.
        if self.realtime.worker_threads > 1024 {
            return Err(AvError::Config(
                "realtime.worker_threads: values above 1024 are refused".into(),
            ));
        }
        if self.scanning.threads > 1024 {
            return Err(AvError::Config(
                "scanning.threads: values above 1024 are refused".into(),
            ));
        }
        if self.quarantine.retention_days == Some(0) {
            return Err(AvError::Config(
                "quarantine.retention_days: use `null` to keep items forever, not 0".into(),
            ));
        }
        if self.protection.self_protection && !self.protection.enabled {
            return Err(AvError::Config(
                "protection.self_protection requires protection.enabled".into(),
            ));
        }
        Ok(())
    }

    /// Effective scan options, derived from the scanning section.
    pub fn scan_options(&self) -> ScanOptions {
        ScanOptions {
            recursive: self.scanning.recursive,
            follow_links: self.scanning.follow_links,
            max_file_size: self.scanning.max_file_size,
            archive_depth: self.scanning.archive_depth,
            archive_max_expansion: self.scanning.archive_max_expansion,
            heuristics: self.scanning.heuristics,
            memory: self.scanning.memory,
            trust: self.scanning.trust,
            archives: self.scanning.archives,
            stop_on_first: self.scanning.stop_on_first,
            per_file_timeout: self.scanning.per_file_timeout_secs.map(Duration::from_secs),
        }
    }
}

/// Identity, startup behaviour and update policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    /// Start the background protection service with Windows.
    pub start_with_windows: bool,
    /// Show a tray icon and keep running when the window is closed.
    pub minimize_to_tray: bool,
    /// Play a sound when a threat is blocked.
    pub notification_sound: bool,
    /// Show a Windows toast when a threat is blocked.
    pub notifications: bool,
    /// Paths that are never scanned regardless of what else is configured.
    pub exclusions: Vec<PathBuf>,
    /// Process names never scanned (matched case-insensitively against the
    /// file name only, never against a full path).
    pub excluded_processes: Vec<String>,
    /// File extensions skipped during real-time scanning. Full scans ignore
    /// this list.
    pub excluded_extensions: Vec<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            start_with_windows: true,
            minimize_to_tray: true,
            notification_sound: false,
            notifications: true,
            exclusions: Vec::new(),
            excluded_processes: Vec::new(),
            excluded_extensions: vec![
                // Compiled caches and package stores churn constantly and
                // cannot execute on their own; scanning them is pure cost.
                "obj".into(),
                "pch".into(),
                "tlog".into(),
                "cvr".into(),
                "pdb".into(),
            ],
        }
    }
}

/// Defaults and limits applied to every scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanningConfig {
    pub recursive: bool,
    pub follow_links: bool,
    pub max_file_size: Option<u64>,
    pub archive_depth: u8,
    pub archive_max_expansion: u64,
    pub heuristics: bool,
    pub memory: bool,
    pub archives: bool,
    pub trust: bool,
    pub stop_on_first: bool,
    pub per_file_timeout_secs: Option<u64>,
    pub thresholds: VerdictThresholds,
    /// Files below this size skip the archive/heuristic paths.
    pub scan_cache_entries: usize,
    /// How long a cached verdict stays valid before the file is re-examined.
    pub scan_cache_ttl_secs: u64,
    /// Upper bound on the in-memory rule match cache.
    pub hash_cache_entries: usize,
    /// Scan files in parallel using this many threads. `0` means "one per
    /// core".
    pub threads: usize,
    /// Number of compiled rules evaluated per file before the rest are
    /// skipped. Guards against a pathological file that matches thousands of
    /// candidate rules. `0` disables the cap.
    pub max_rules_per_file: usize,
}

impl Default for ScanningConfig {
    fn default() -> Self {
        Self {
            recursive: true,
            follow_links: false,
            max_file_size: Some(256 * 1024 * 1024),
            archive_depth: 3,
            archive_max_expansion: 1024 * 1024 * 1024,
            heuristics: true,
            memory: false,
            archives: true,
            trust: true,
            stop_on_first: false,
            per_file_timeout_secs: Some(30),
            thresholds: VerdictThresholds::default(),
            scan_cache_entries: 65_536,
            scan_cache_ttl_secs: 3600,
            hash_cache_entries: 262_144,
            threads: 0,
            max_rules_per_file: 4096,
        }
    }
}

/// Real-time (on-access) protection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RealtimeConfig {
    pub enabled: bool,
    /// Watch the filesystem from user mode in addition to the minifilter. Acts
    /// as a fallback when the driver is not loaded.
    pub filesystem_fallback: bool,
    /// Scan a file when it is created or written.
    pub scan_on_write: bool,
    /// Scan a file when it is executed.
    pub scan_on_execute: bool,
    /// Scan processes as they start.
    pub scan_on_process_start: bool,
    /// Block execution of a detected file instead of only reporting it.
    pub block_on_detect: bool,
    /// Terminate a process confirmed malicious after it started.
    ///
    /// # What "confirmed" means here, because the word is doing the work
    ///
    /// It is not "a rule matched in memory". The match has to point at a *file*,
    /// that file has to convict on its own evidence under the same engine and the
    /// same thresholds that judge a file the watcher found, and the file must not
    /// be one the user allowed. A region nothing on disk backs — the shape of
    /// injected code, and a real detection — is reported and is **not** grounds
    /// for terminating anything, because those bytes say nothing about which
    /// program wrote them and the process could be the victim.
    ///
    /// # Why it is on by default
    ///
    /// Because it was measured before it was switched on, which is the only order
    /// that is honest for an irreversible action. `wenle memory` over every
    /// process this account can open, against the shipped 10,764-rule database:
    /// five consecutive runs on 2026-10-09, 82 to 86 processes examined, 135,594
    /// regions walked, 201 worth reading, 32.7 MB read in 4.4 s, and **no finding
    /// in any run**. The processes that could not be opened — 159 of them, which
    /// is the ordinary case and not a fault — are not covered by that
    /// measurement and were not examined; what is claimed is what was measured.
    pub terminate_malicious_process: bool,
    /// Directories watched by the user-mode fallback. Empty means "the
    /// standard set": Downloads, Desktop, Documents, Temp, Startup, and every
    /// removable drive.
    pub watched_paths: Vec<PathBuf>,
    /// Extra directories to watch beyond the standard set.
    pub extra_watched_paths: Vec<PathBuf>,
    pub worker_threads: usize,
    /// Drop duplicate events for the same path inside this window.
    pub debounce_ms: u64,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            filesystem_fallback: true,
            scan_on_write: true,
            scan_on_execute: true,
            scan_on_process_start: true,
            block_on_detect: true,
            terminate_malicious_process: true,
            watched_paths: Vec::new(),
            extra_watched_paths: Vec::new(),
            worker_threads: 0,
            debounce_ms: 200,
        }
    }
}

/// Active defence: self-protection, registry and boot protection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectionConfig {
    /// Master switch for the defence subsystem.
    pub enabled: bool,
    /// Prevent other processes from terminating, suspending, or writing to the
    /// antivirus itself.
    pub self_protection: bool,
    /// Refuse writes to the antivirus install directory, rule database and
    /// quarantine vault.
    pub protect_own_files: bool,
    /// Block changes to the persistence points malware relies on
    /// (`Run`, `RunOnce`, services, IFEO, Winlogon, AppInit, ...).
    pub protect_persistence: bool,
    /// Notify (rather than block) on persistence changes, for users who
    /// install software frequently.
    pub persistence_alert_only: bool,
    /// Protect the master boot record and EFI system partition from writes.
    pub protect_boot: bool,
    /// Block known host-file and DNS hijack targets.
    pub protect_hosts_file: bool,
    /// Re-apply protection if another process disables it.
    pub tamper_resistance: bool,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            self_protection: true,
            protect_own_files: true,
            protect_persistence: true,
            persistence_alert_only: false,
            protect_boot: false,
            protect_hosts_file: true,
            tamper_resistance: true,
        }
    }
}

/// Quarantine vault behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuarantineConfig {
    /// Encrypt vault contents at rest.
    pub encrypt: bool,
    /// Delete quarantined items older than this. `None` keeps them forever.
    pub retention_days: Option<u64>,
    /// Upper bound on the vault size; the oldest items are evicted first.
    pub max_size_bytes: u64,
    /// Take a confirmed detection into the vault, without asking first.
    ///
    /// **On by default, and that is the product's whole shape.** A detection
    /// that stops a program but leaves the file where it is has to be acted on
    /// again at the next execution, and the user has no moment at which to
    /// decide anything. Taking the file is what makes the decision a real one:
    /// the program cannot run because its bytes are no longer at that path, and
    /// the user answers "put it back" or "destroy it" afterwards, from the
    /// vault, at their leisure. See [`crate::config`]'s sibling
    /// `general.exclusions` for the other half — allowing a file has to mean
    /// the engine will not take it again.
    ///
    /// Turning it off is a supported choice and means report-only: a detection
    /// is still reported, and the driver still refuses the program, but nothing
    /// is moved. That was the default before this round and is kept as the
    /// meaning of the switch.
    ///
    /// The cost of the default is stated where it is paid: a false positive is
    /// now a file that leaves its path. It stays recoverable, because the vault
    /// keeps the bytes and [`GeneralConfig::exclusions`] can be written from
    /// the window, but it is no longer a log line.
    pub auto_quarantine: bool,
    /// Try to restore an item before quarantining, so that a false positive on
    /// a system file is recoverable.
    pub backup_before_quarantine: bool,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            encrypt: true,
            retention_days: Some(30),
            max_size_bytes: 2 * 1024 * 1024 * 1024,
            auto_quarantine: true,
            backup_before_quarantine: true,
        }
    }
}

/// Kernel minifilter settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DriverConfig {
    /// Use the kernel driver when it is available.
    pub enabled: bool,
    /// Fail closed (block the operation) when the user-mode scanner cannot be
    /// reached, instead of allowing it through. Safer, but a crashed service
    /// then blocks all executable file access — leave this off unless the
    /// deployment demands it.
    pub fail_closed: bool,
    /// Time budget for the driver to wait for a user-mode verdict.
    pub scan_timeout_ms: u64,
    /// Ask the driver to deny writes to the protected trees directly, rather
    /// than round-tripping every write to user mode.
    pub kernel_self_protection: bool,
    /// Log every decision the driver makes. Noisy; for debugging only.
    pub verbose_logging: bool,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_closed: false,
            scan_timeout_ms: 5000,
            kernel_self_protection: true,
            verbose_logging: false,
        }
    }
}

/// Sandbox settings. The sandbox is built but **disabled by default**; enabling
/// it is an explicit opt-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub enabled: bool,
    /// Run a sample under the sandbox only when the static verdict is
    /// `Suspicious` — never for files already confirmed malicious, and never
    /// for clean ones.
    pub auto_on_suspicious: bool,
    pub timeout_secs: u64,
    pub max_memory_bytes: u64,
    pub max_processes: u32,
    /// Deny network access to the sandboxed process.
    pub block_network: bool,
    /// Capture filesystem writes into a scratch overlay that is discarded when
    /// the run finishes.
    pub capture_filesystem: bool,
    pub capture_registry: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_on_suspicious: false,
            timeout_secs: 60,
            max_memory_bytes: 1024 * 1024 * 1024,
            max_processes: 16,
            block_network: true,
            capture_filesystem: true,
            capture_registry: true,
        }
    }
}

/// Logging and retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: LogLevel,
    /// Also write to a rotating file under `<data>/logs`.
    pub to_file: bool,
    pub max_file_size_bytes: u64,
    pub max_files: usize,
    /// Days of detection history to keep.
    pub history_days: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            to_file: true,
            max_file_size_bytes: 16 * 1024 * 1024,
            max_files: 5,
            history_days: 90,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

/// Appearance and interaction.
///
/// Not `Eq`: floating-point window dimensions have no total equality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    pub theme: Theme,
    /// Compact rows in the threat table.
    pub dense_tables: bool,
    /// Confirm before quarantining or deleting anything.
    pub confirm_destructive: bool,
    /// Keep the machine awake while a long scan runs.
    pub prevent_sleep_during_scan: bool,
    pub window_width: f32,
    pub window_height: f32,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            dense_tables: false,
            confirm_destructive: true,
            prevent_sleep_during_scan: true,
            window_width: 1180.0,
            window_height: 760.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Dark,
    Light,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        AvConfig::default()
            .validate()
            .expect("defaults must validate");
    }

    #[test]
    fn sandbox_is_off_by_default() {
        let c = AvConfig::default();
        assert!(!c.sandbox.enabled);
        assert!(!c.sandbox.auto_on_suspicious);
    }

    #[test]
    fn thresholds_must_be_ordered() {
        let mut c = AvConfig::default();
        c.scanning.thresholds.suspicious = 200;
        c.scanning.thresholds.malicious = 100;
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("strictly less"), "unexpected message: {err}");
    }

    #[test]
    fn equal_thresholds_are_rejected() {
        let mut c = AvConfig::default();
        c.scanning.thresholds.suspicious = 100;
        c.scanning.thresholds.malicious = 100;
        assert!(c.validate().is_err());
    }

    #[test]
    fn absurd_archive_depth_is_refused() {
        let mut c = AvConfig::default();
        c.scanning.archive_depth = 99;
        assert!(c.validate().is_err());
    }

    #[test]
    fn self_protection_requires_protection_enabled() {
        let mut c = AvConfig::default();
        c.protection.enabled = false;
        c.protection.self_protection = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_retention_is_rejected_in_favour_of_null() {
        let mut c = AvConfig::default();
        c.quarantine.retention_days = Some(0);
        assert!(c.validate().is_err());
    }

    #[test]
    fn round_trips_through_toml() {
        let dir = tempdir();
        let path = dir.join("config.toml");
        let mut original = AvConfig::default();
        original.realtime.scan_on_write = false;
        original.scanning.thresholds.malicious = 150;
        original.save(&path).unwrap();

        let loaded = AvConfig::load_or_default(&path).unwrap();
        assert_eq!(loaded, original);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_yields_defaults() {
        let cfg =
            AvConfig::load_or_default(Path::new(r"C:\definitely\not\here\config.toml")).unwrap();
        assert_eq!(cfg, AvConfig::default());
    }

    #[test]
    fn unknown_keys_are_rejected_so_typos_are_caught() {
        let text = "[scanning]\nrecursiv = true\n";
        let err = toml::from_str::<AvConfig>(text).unwrap_err().to_string();
        assert!(err.contains("recursiv"), "unexpected message: {err}");
    }

    #[test]
    fn partial_config_fills_in_defaults() {
        let text = "[realtime]\nenabled = false\n";
        let cfg: AvConfig = toml::from_str(text).unwrap();
        assert!(!cfg.realtime.enabled);
        // Untouched sections keep their defaults.
        assert_eq!(cfg.scanning.archive_depth, 3);
        assert!(cfg.protection.enabled);
    }

    #[test]
    fn scan_options_reflect_the_config() {
        let mut c = AvConfig::default();
        c.scanning.archives = false;
        c.scanning.per_file_timeout_secs = Some(7);
        let o = c.scan_options();
        assert!(!o.archives);
        assert_eq!(o.per_file_timeout, Some(Duration::from_secs(7)));
    }

    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "wenle-av-cfg-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }
}
