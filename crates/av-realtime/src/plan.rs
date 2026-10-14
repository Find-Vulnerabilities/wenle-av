//! Turning a [`RealtimeConfig`] into the set of directories to watch.
//!
//! # Why the configuration is not read directly by the watcher
//!
//! Because deciding what to watch involves four judgements that are not in the
//! configuration file — resolving the standard set, dropping roots that are
//! inside the product's own data, dropping roots that are not there, and noting
//! which configured settings this crate cannot honour — and all four are worth
//! testing. Doing them here, once, means the watcher starts with a list and the
//! tests assert on [`WatchPlan`] instead of standing up a filesystem.
//!
//! # The standard set
//!
//! [`RealtimeConfig::watched_paths`] empty means "the standard set", which the
//! configuration's own documentation defines as Downloads, Desktop, Documents,
//! Temp, Startup and every removable drive. That is the set that catches a
//! dropper arriving by browser, by email attachment, by extraction and by USB
//! stick, and it is deliberately not "the whole disk": a recursive watch on
//! `C:\` sees every build artifact and every database journal on the machine,
//! and the cost of that is paid by the user's disk and this process's CPU rather
//! than by anything the watcher finds.
//!
//! # What this crate cannot honour
//!
//! The realtime section of the configuration was written to describe the whole
//! subsystem, including the parts that need the kernel driver. Four of its
//! switches are therefore unanswerable in user mode, and a plan that silently
//! ignored them would let a user believe they had turned on protection they do
//! not have. They are listed in [`WatchPlan::unhonoured`] and the console is
//! expected to print them, which is the same shape as
//! `av-cli`'s existing gap warning for memory scanning.

use std::path::{Path, PathBuf};
use std::time::Duration;

use av_core::config::RealtimeConfig;
use av_core::AvPaths;

use crate::debounce::effective_window;
use crate::filter::ExclusionSet;

/// How large a notification buffer each watched root gets.
///
/// The kernel writes records into the buffer until it is full and then reports
/// an overflow, so the size is the width of the window between "we are keeping
/// up" and "we stopped keeping up". 64 KiB holds several hundred records of
/// ordinary length, which is well beyond what a browser, an extractor or a
/// package manager produces between two of our reads.
///
/// The cost is real but small: `ReadDirectoryChangesW` is given this buffer and
/// holds it until it completes, so it is 64 KiB of kernel pooled memory per
/// watched root, allocated once and reused. Raising it makes overflow rarer and
/// a burst of events more expensive to drain; lowering it makes both happen
/// sooner. There is no setting for it because there is no measurement that would
/// tell a user which value to pick.
pub const BUFFER_BYTES: u32 = 64 * 1024;

/// Whether a watched root is watched recursively.
///
/// Always true, and not a setting, because the alternative is not a smaller
/// watch: it is a watch that misses `Downloads\sub\dropper.exe`. Every directory
/// in the standard set is one a user drags folders into.
pub const WATCH_SUBTREE: bool = true;

/// How many files one overflow re-scan will look at before giving up.
///
/// A re-scan is the response to the kernel telling us it dropped events, and
/// what it is guarding against is a blind spot. It is bounded because the tree
/// it walks can be `%TEMP%` with fifty thousand files in it, and a re-scan that
/// runs for ten minutes holds up every event behind it — turning one overflow
/// into a second one. When the limit is reached the notice says so, so the
/// coverage that was achieved is reported rather than assumed.
pub const RESCAN_FILE_LIMIT: usize = 4096;

/// Why a configured root is not being watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The root is the product's own data, its install directory or its vault.
    /// See [`ExclusionSet`] for what this costs.
    Excluded,
    /// The path does not exist.
    Missing,
    /// The path exists and is not a directory.
    NotADirectory,
}

impl SkipReason {
    /// The sentence the console prints.
    pub const fn describe(self) -> &'static str {
        match self {
            SkipReason::Excluded => "it is inside the product's own data or install directory",
            SkipReason::Missing => "it does not exist",
            SkipReason::NotADirectory => "it is not a directory",
        }
    }
}

/// A configured root that is not being watched, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRoot {
    /// The path as it was configured.
    pub path: PathBuf,
    /// Why it was dropped.
    pub reason: SkipReason,
}

/// A configured setting this crate does not implement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unhonoured {
    /// The configuration key, spelled as it appears in the file.
    pub setting: &'static str,
    /// What the user does not get, in one sentence.
    pub reason: &'static str,
}

/// Why no directory is being watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledBy {
    /// `realtime.enabled` is false.
    NotEnabled,
    /// `realtime.filesystem_fallback` is false. This crate *is* the user-mode
    /// fallback, so turning it off asks for something this workspace cannot
    /// provide: the minifilter, which is a separate crate and a separate
    /// toolchain.
    FallbackTurnedOff,
}

/// The directories to watch, the directories never to watch, and what the
/// configuration asked for that this crate does not do.
#[derive(Debug, Clone)]
pub struct WatchPlan {
    /// The roots to watch, deduplicated and in the order they will be watched.
    pub roots: Vec<PathBuf>,
    /// Trees that are never watched and never scanned.
    pub exclusions: ExclusionSet,
    /// Whether a modification is a scan candidate. See
    /// [`crate::filter::is_scan_candidate`].
    pub scan_on_write: bool,
    /// How long a path must be quiet before it is scanned. Floored at
    /// [`crate::debounce::SETTLE_FLOOR_MS`].
    pub window: Duration,
    /// Roots that were configured and are not being watched.
    pub skipped: Vec<SkippedRoot>,
    /// Configured settings that this crate cannot honour.
    pub unhonoured: Vec<Unhonoured>,
    /// Set when the plan watches nothing.
    pub disabled_by: Option<DisabledBy>,
}

impl WatchPlan {
    /// A plan that watches nothing, and says why.
    pub fn disabled(reason: DisabledBy) -> Self {
        Self {
            roots: Vec::new(),
            exclusions: ExclusionSet::default(),
            scan_on_write: false,
            window: effective_window(0),
            skipped: Vec::new(),
            unhonoured: Vec::new(),
            disabled_by: Some(reason),
        }
    }

    /// Build the plan for a configuration.
    ///
    /// `paths` supplies the install, data and vault directories that must not be
    /// watched. Everything else comes from `config`.
    pub fn from_config(config: &RealtimeConfig, paths: &AvPaths) -> Self {
        let exclusions = ExclusionSet::for_paths(paths);

        if !config.enabled {
            return Self::disabled(DisabledBy::NotEnabled);
        }
        if !config.filesystem_fallback {
            return Self::disabled(DisabledBy::FallbackTurnedOff);
        }

        let configured: Vec<PathBuf> = if config.watched_paths.is_empty() {
            standard_paths()
        } else {
            config.watched_paths.clone()
        }
        .into_iter()
        .chain(config.extra_watched_paths.iter().cloned())
        .collect();

        let mut roots: Vec<PathBuf> = Vec::new();
        let mut skipped: Vec<SkippedRoot> = Vec::new();
        for root in configured {
            if exclusions.excludes(&root) {
                skipped.push(SkippedRoot {
                    path: root,
                    reason: SkipReason::Excluded,
                });
                continue;
            }
            match std::fs::metadata(&root) {
                Ok(meta) if !meta.is_dir() => skipped.push(SkippedRoot {
                    path: root,
                    reason: SkipReason::NotADirectory,
                }),
                Ok(_) => {
                    // Deduplicated on the same normalization the exclusion set
                    // uses, so `C:\Temp` and `c:\temp\` are one root. The first
                    // spelling wins, because that is the one the user wrote.
                    if !roots.iter().any(|kept| same_path(kept, &root)) {
                        roots.push(root);
                    }
                }
                Err(e) => {
                    log::debug!("not watching {}: {e}", root.display());
                    skipped.push(SkippedRoot {
                        path: root,
                        reason: SkipReason::Missing,
                    });
                }
            }
        }

        let mut unhonoured = Vec::new();
        if config.scan_on_execute {
            unhonoured.push(Unhonoured {
                setting: "realtime.scan_on_execute",
                reason: "this crate watches the filesystem, and a filesystem does not say \
                         whether a file is about to be executed",
            });
        }
        if config.scan_on_process_start {
            unhonoured.push(Unhonoured {
                setting: "realtime.scan_on_process_start",
                reason: "this watcher sees the filesystem, and a process starting is not a \
                         filesystem event; the setting is acted on by the service, not by this \
                         watcher, through the driver's process-creation notifications — and so \
                         only while a driver is loaded and connected",
            });
        }
        if config.block_on_detect {
            unhonoured.push(Unhonoured {
                setting: "realtime.block_on_detect",
                reason: "a user-mode watcher is told about a file after it exists, so it can \
                         quarantine it but cannot refuse it; only the driver can block",
            });
        }
        if config.worker_threads != 1 {
            unhonoured.push(Unhonoured {
                setting: "realtime.worker_threads",
                reason: "one scan runs at a time, on purpose: a scan is the most \
                         processor-hungry thing the product does and it runs while the user \
                         is working, so a pool sized to the core count would take the machine \
                         for the length of a temp-directory storm",
            });
        }
        if config.terminate_malicious_process {
            unhonoured.push(Unhonoured {
                setting: "realtime.terminate_malicious_process",
                reason: "this watcher never learns which process, if any, opened a file, so it \
                         has nothing to terminate; the setting is acted on by the service, not \
                         by this watcher, and only for a process the driver reported starting, \
                         whose memory was then found to hold a file the engine convicts",
            });
        }

        Self {
            roots,
            exclusions,
            scan_on_write: config.scan_on_write,
            window: effective_window(config.debounce_ms),
            skipped,
            unhonoured,
            disabled_by: None,
        }
    }

    /// True when at least one directory will be watched.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// True when two paths name the same directory for our purposes.
fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().to_lowercase().trim_end_matches('\\')
        == b.to_string_lossy().to_lowercase().trim_end_matches('\\')
}

/// The directories the product watches when the configuration does not name any.
///
/// The user's own folders first, then every local profile's, then the machine's
/// scratch space and every removable drive that is mounted. A folder that does
/// not exist is left out — `dirs` returns `None` for a Desktop that has been
/// moved to OneDrive, for instance — rather than being created, because creating
/// it would put a directory on the user's disk to satisfy a watcher.
///
/// # Why every profile and not just this process's
///
/// The process asking is usually the service, and the service runs as
/// `LocalSystem`, whose own Desktop, Downloads and Documents are
/// `C:\Windows\System32\config\systemprofile\...` — three real directories that
/// stay empty. A watch plan built only from "the current user" therefore reports
/// full coverage while covering nothing a person will ever put a file in, which
/// is the worst shape a protection failure can take. [`av_integration::profiles`]
/// answers with the machine's actual people instead; the current user's own
/// folders are kept alongside, because that is where a profile with no registry
/// entry and a OneDrive-redirected Desktop are still recorded.
pub fn standard_paths() -> Vec<PathBuf> {
    // Annotated rather than inferred: the first use of `out` is a call that
    // takes `&Path`, and an inference that resolves that to `Vec<Path>` from the
    // call site is a compile error five lines later rather than here.
    let mut out: Vec<PathBuf> = Vec::new();
    for candidate in [
        dirs::download_dir(),
        dirs::desktop_dir(),
        dirs::document_dir(),
        Some(std::env::temp_dir()),
        startup_dir(),
    ]
    .into_iter()
    .flatten()
    {
        push_unique(&mut out, candidate);
    }
    for profile in av_integration::profiles::roots() {
        for folder in av_integration::profiles::folders(&profile) {
            push_unique(&mut out, folder);
        }
    }
    for root in removable_drive_roots() {
        push_unique(&mut out, root);
    }
    out
}

/// Add `candidate` unless something naming the same directory is already there.
///
/// The same question [`same_path`] answers, asked about the whole list: two
/// profiles can name one directory — a machine where a user's `Desktop` is a
/// junction to a shared folder — and a root listed twice is a second watch thread
/// scanning every file a second time.
fn push_unique(out: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !out.iter().any(|kept| same_path(kept, &candidate)) {
        out.push(candidate);
    }
}

/// `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.
///
/// Kept in the standard set because a file placed here runs at every logon, so
/// it is the one directory where a sample's *first* appearance is also its last
/// chance to be caught before it runs. With the watcher's `window` delay it may
/// still be caught after it has been registered rather than before, which is the
/// limitation this whole crate is documented around.
fn startup_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|config| {
        config
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup")
    })
}

/// The roots of every currently mounted removable drive.
#[cfg(windows)]
fn removable_drive_roots() -> Vec<PathBuf> {
    // SAFETY: `GetLogicalDrives` takes no arguments and returns a bitmask; it
    // has no preconditions and cannot fail in a way that matters here, since a
    // zero return means "no drives" and produces an empty list.
    let mask = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
    roots_from_drive_mask(mask)
        .into_iter()
        .filter(|root| {
            let wide = to_wide(root);
            // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the
            // call, which is exactly what `GetDriveTypeW` documents as its
            // requirement. The return value is a plain `u32` classification and
            // carries no ownership.
            let kind = unsafe {
                windows::Win32::Storage::FileSystem::GetDriveTypeW(windows::core::PCWSTR(
                    wide.as_ptr(),
                ))
            };
            kind == DRIVE_REMOVABLE
        })
        .map(PathBuf::from)
        .collect()
}

/// Platforms without `GetLogicalDrives` have no removable drive to enumerate
/// here, and this crate watches nothing on them anyway.
#[cfg(not(windows))]
fn removable_drive_roots() -> Vec<PathBuf> {
    Vec::new()
}

/// `DRIVE_REMOVABLE`. Written as a literal rather than imported from
/// `Win32::System::WindowsProgramming`, which would pull a whole feature in for
/// one `u32` whose value Microsoft documents as 2 and has never changed.
const DRIVE_REMOVABLE: u32 = 2;

/// The drive roots named by a `GetLogicalDrives` bitmask: bit 0 is `A:`, bit 25
/// is `Z:`.
///
/// Split out from the call so that the mapping is testable, because the two
/// mistakes it can make — an off-by-one in the bit and a wrong offset in the
/// letter — both produce a watch on a drive that exists and is not the one
/// meant, which is a failure that looks like success.
fn roots_from_drive_mask(mask: u32) -> Vec<String> {
    (0..26u32)
        .filter(|bit| mask & (1 << bit) != 0)
        .filter_map(|bit| char::from_u32(u32::from(b'A') + bit))
        .map(|letter| format!("{letter}:\\"))
        .collect()
}

/// NUL-terminate a string for a `PCWSTR` argument.
#[cfg(windows)]
fn to_wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> AvPaths {
        AvPaths::with_data_dir(r"C:\Program Files\WenleAV", r"C:\ProgramData\WenleAV")
    }

    fn config_with(roots: Vec<&str>) -> RealtimeConfig {
        RealtimeConfig {
            watched_paths: roots.into_iter().map(PathBuf::from).collect(),
            ..RealtimeConfig::default()
        }
    }

    #[test]
    fn a_disabled_configuration_watches_nothing_and_says_so() {
        let config = RealtimeConfig {
            enabled: false,
            ..RealtimeConfig::default()
        };
        let plan = WatchPlan::from_config(&config, &paths());
        assert!(plan.is_empty());
        assert_eq!(plan.disabled_by, Some(DisabledBy::NotEnabled));
        // Nothing is reported as unhonoured, because nothing was asked for.
        assert!(plan.unhonoured.is_empty());
    }

    /// Every local profile's folders are in the default set, not just this
    /// process's.
    ///
    /// This is the assertion that fails on the broken version, and it is
    /// deliberately not "the plan contains no system profile": a test process
    /// runs as a *user*, so `dirs::desktop_dir()` answers with that user's real
    /// Desktop and a system-profile check passes whether or not the profile list
    /// was consulted at all. What breaks in production is that the service, as
    /// `LocalSystem`, gets only the system profile — and the falsifiable form of
    /// that is "every profile on this machine is covered", which on this machine
    /// fails for every profile but the current one without the fix.
    #[test]
    fn the_default_plan_covers_every_profile_on_the_machine() {
        let watched = standard_paths();
        let profiles = av_integration::profiles::roots();
        for profile in &profiles {
            for folder in av_integration::profiles::folders(profile) {
                assert!(
                    watched.iter().any(|root| same_path(root, &folder)),
                    "{} belongs to a local profile and is not watched: {watched:?}",
                    folder.display()
                );
            }
        }
        // And the profile list is not the only source: a profile with no registry
        // entry still has the current user's folders, which is what `dirs`
        // answers. Empty on a machine where the list cannot be read, which is the
        // documented degradation and not a failure.
        if let Some(desktop) = dirs::desktop_dir() {
            assert!(
                watched.iter().any(|root| same_path(root, &desktop)),
                "{} is this user's Desktop and is not watched: {watched:?}",
                desktop.display()
            );
        }
        for root in &watched {
            let lowered = root.to_string_lossy().to_lowercase();
            assert!(
                !lowered.contains("systemprofile"),
                "{} is a service account's profile, which no user puts files in: {watched:?}",
                root.display()
            );
        }
    }

    /// Everything in the default set names a different directory.
    ///
    /// Two roots that are the same directory are two watch threads scanning every
    /// file twice, and the profile list is a second source for a question the
    /// shell's known folders already answered.
    #[test]
    fn the_default_set_names_each_directory_once() {
        let watched = standard_paths();
        for (index, root) in watched.iter().enumerate() {
            assert!(
                root.is_dir(),
                "{} is in the default set and is not a directory: {watched:?}",
                root.display()
            );
            for other in &watched[index + 1..] {
                assert!(
                    !same_path(root, other),
                    "{} and {} are the same directory, listed twice: {watched:?}",
                    root.display(),
                    other.display()
                );
            }
        }
    }

    #[test]
    fn turning_off_the_fallback_disables_the_watcher_rather_than_ignoring_the_setting() {
        // `filesystem_fallback = false` means "use the driver, not the user-mode
        // watcher". Running the watcher anyway would be this crate overriding an
        // explicit instruction, so it stops — and names the crate that would
        // have answered the request.
        let config = RealtimeConfig {
            filesystem_fallback: false,
            ..RealtimeConfig::default()
        };
        let plan = WatchPlan::from_config(&config, &paths());
        assert!(plan.is_empty());
        assert_eq!(plan.disabled_by, Some(DisabledBy::FallbackTurnedOff));
    }

    #[test]
    fn a_root_inside_the_product_data_is_skipped_with_a_reason() {
        // Nobody configures this on purpose, but a portable install with its
        // data directory in the user's profile makes it one line away, and the
        // result is the write storm.
        //
        // The survivor is the system temp directory and not a literal like
        // `C:\Temp`, because `from_config` skips a root that does not exist and
        // a literal would make this test pass or fail according to what happens
        // to be on the machine.
        let survivor = std::env::temp_dir();
        assert!(survivor.is_dir(), "the system temp directory exists");
        let config = config_with(vec![
            r"C:\ProgramData\WenleAV\quarantine",
            survivor.to_str().unwrap(),
        ]);
        let plan = WatchPlan::from_config(&config, &paths());
        assert_eq!(plan.roots, vec![survivor]);
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].reason, SkipReason::Excluded);
        assert_eq!(
            plan.skipped[0].path,
            PathBuf::from(r"C:\ProgramData\WenleAV\quarantine")
        );
    }

    #[test]
    fn a_root_that_does_not_exist_is_skipped_rather_than_created() {
        let missing = std::env::temp_dir().join("wenle-av-does-not-exist-8f3a1c");
        assert!(!missing.exists());
        let config = RealtimeConfig {
            watched_paths: vec![missing.clone()],
            ..RealtimeConfig::default()
        };
        let plan = WatchPlan::from_config(&config, &paths());
        assert!(plan.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].reason, SkipReason::Missing);
        // And the path is still not there: a watcher that cannot watch a
        // directory must not put one on the disk to fix that.
        assert!(!missing.exists());
    }

    #[test]
    fn a_file_where_a_directory_was_configured_is_skipped() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("not-a-directory.txt");
        std::fs::write(&file, b"x").expect("writing the file");
        let config = RealtimeConfig {
            watched_paths: vec![file.clone()],
            ..RealtimeConfig::default()
        };
        let plan = WatchPlan::from_config(&config, &paths());
        assert!(plan.is_empty());
        assert_eq!(plan.skipped[0].reason, SkipReason::NotADirectory);
    }

    #[test]
    fn extra_roots_are_added_to_the_configured_ones_and_deduplicated() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let first = dir.path().join("watched");
        let second = dir.path().join("also-watched");
        std::fs::create_dir_all(&first).expect("creating the directory");
        std::fs::create_dir_all(&second).expect("creating the directory");

        let config = RealtimeConfig {
            watched_paths: vec![first.clone(), first.clone()],
            extra_watched_paths: vec![second.clone(), first.clone()],
            ..RealtimeConfig::default()
        };
        let plan = WatchPlan::from_config(&config, &paths());
        assert_eq!(plan.roots.len(), 2, "{:?}", plan.roots);
        assert_eq!(plan.roots[0], first);
        assert_eq!(plan.roots[1], second);
    }

    #[test]
    fn the_five_settings_this_crate_cannot_honour_are_listed_when_asked_for() {
        // This list is not "what the user asked for that we ignored" but "what
        // this crate cannot do", so all five are present on the shipped
        // configuration: `scan_on_execute`, `scan_on_process_start`,
        // `block_on_detect` and `terminate_malicious_process` all default to true
        // and none of them is something a filesystem watcher can act on, and
        // `worker_threads` defaults to 0 (auto), which is a pool this crate
        // deliberately does not run.
        //
        // That the service *does* honour two of these — through the driver rather
        // than through this watcher — is why the reasons are worded the way they
        // are. Each says what this watcher cannot do and names the component that
        // can, because a user reading the product's disclosures must not conclude
        // from this list that nothing watches process starts.
        let plan = WatchPlan::from_config(&RealtimeConfig::default(), &paths());
        let settings: Vec<&str> = plan.unhonoured.iter().map(|u| u.setting).collect();
        assert_eq!(settings.len(), 5, "{settings:?}");
        for expected in [
            "realtime.scan_on_execute",
            "realtime.scan_on_process_start",
            "realtime.block_on_detect",
            "realtime.terminate_malicious_process",
            "realtime.worker_threads",
        ] {
            assert!(settings.contains(&expected), "{settings:?} is missing {expected}");
        }
        for unhonoured in &plan.unhonoured {
            assert!(!unhonoured.reason.is_empty());
        }

        // The two the service acts on say so, rather than reading as "nobody
        // does this". Asserted on the text because the text *is* the disclosure:
        // there is no state behind it for a client to check.
        for setting in [
            "realtime.scan_on_process_start",
            "realtime.terminate_malicious_process",
        ] {
            let reason = plan
                .unhonoured
                .iter()
                .find(|entry| entry.setting == setting)
                .map(|entry| entry.reason)
                .expect("the setting is listed");
            assert!(
                reason.contains("service"),
                "{setting} must name what does act on it: {reason}"
            );
        }

        // And the settings this crate *can* act on are never listed.
        let all = RealtimeConfig {
            terminate_malicious_process: true,
            worker_threads: 4,
            ..RealtimeConfig::default()
        };
        let plan = WatchPlan::from_config(&all, &paths());
        let settings: Vec<&str> = plan.unhonoured.iter().map(|u| u.setting).collect();
        assert_eq!(settings.len(), 5, "{settings:?}");
        assert!(
            !settings.iter().any(|s| s.contains("scan_on_write")),
            "scan_on_write is implemented and must not be reported as a gap"
        );

        // And a single worker thread is exactly what happens, so it is not a
        // gap to report.
        let one = RealtimeConfig {
            worker_threads: 1,
            ..RealtimeConfig::default()
        };
        let settings: Vec<&str> = WatchPlan::from_config(&one, &paths())
            .unhonoured
            .iter()
            .map(|u| u.setting)
            .collect();
        assert!(
            !settings.contains(&"realtime.worker_threads"),
            "{settings:?}"
        );
    }

    #[test]
    fn the_window_comes_from_the_configuration_but_not_below_the_floor() {
        let config = RealtimeConfig {
            debounce_ms: 0,
            ..RealtimeConfig::default()
        };
        let plan = WatchPlan::from_config(&config, &paths());
        assert_eq!(
            plan.window,
            Duration::from_millis(crate::debounce::SETTLE_FLOOR_MS)
        );

        let config = RealtimeConfig {
            debounce_ms: 750,
            ..RealtimeConfig::default()
        };
        let plan = WatchPlan::from_config(&config, &paths());
        assert_eq!(plan.window, Duration::from_millis(750));
    }

    #[test]
    fn scan_on_write_comes_straight_from_the_configuration() {
        let config = RealtimeConfig {
            scan_on_write: false,
            ..RealtimeConfig::default()
        };
        assert!(!WatchPlan::from_config(&config, &paths()).scan_on_write);
        assert!(WatchPlan::from_config(&RealtimeConfig::default(), &paths()).scan_on_write);
    }

    #[test]
    fn the_drive_mask_maps_bits_to_letters_the_way_windows_documents() {
        // Bit 0 is A: and bit 25 is Z:. An off-by-one here watches the wrong
        // drive, which is a failure that looks like success.
        assert_eq!(roots_from_drive_mask(0b1), vec!["A:\\"]);
        assert_eq!(roots_from_drive_mask(1 << 2), vec!["C:\\"]);
        assert_eq!(roots_from_drive_mask(1 << 25), vec!["Z:\\"]);
        assert_eq!(roots_from_drive_mask(0), Vec::<String>::new());

        // A typical machine: C: and D: fixed, E: removable.
        assert_eq!(
            roots_from_drive_mask(0b1_0000 | 0b1000 | 0b100),
            vec!["C:\\", "D:\\", "E:\\"]
        );
        // Bits above the drive letters are ignored rather than producing
        // punctuation as a drive name.
        assert_eq!(
            roots_from_drive_mask(0xFC00_0000),
            Vec::<String>::new(),
            "bits 26..32 name no drive"
        );
    }

    #[test]
    fn the_standard_set_is_not_empty_and_holds_no_duplicates() {
        let standard = standard_paths();
        // Temp is always resolvable, so the set is never empty on any machine
        // this product runs on — and an empty set would mean watching nothing
        // while reporting success.
        assert!(!standard.is_empty());
        let mut seen: Vec<String> = standard
            .iter()
            .map(|p| p.to_string_lossy().to_lowercase())
            .collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "the standard set repeats a directory");
    }
}
