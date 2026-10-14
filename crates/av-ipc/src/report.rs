//! The picture a client is given: what the service is, what it is watching,
//! what it is protecting with, and what it is doing.
//!
//! Every field here is a question a user interface asks, and each one is
//! answered with the value the component that owns it reports rather than with
//! a plausible-looking default. The three that need saying out loud are
//! [`DriverStatus`], [`RealtimeState`] and [`SettingDisclosure`], because each
//! of them is a place where the tempting answer is a comfortable one:
//!
//! * "Is the driver loaded?" has three answers, and two of them are not
//!   "yes". [`DriverPresence`] names all three rather than folding `Unknown`
//!   into `Absent`, because a service that cannot tell says so instead of
//!   reporting a protection state it has not checked.
//! * "How many files are watched?" has no honest numeric answer from a
//!   directory watch at all — `ReadDirectoryChangesW` reports what happens
//!   after it is armed and does not enumerate — so what is reported is the
//!   roots that are armed and the count of files actually examined.
//! * "Did my settings take effect?" is answered by
//!   [`ConfigReport::unhonoured`], which lists the keys this build stores and
//!   does not act on, following `av_realtime::plan::WatchPlan::unhonoured`.
//!   Dropping them on the floor is how a user comes to believe a protection is
//!   on.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use av_core::config::AvConfig;
use av_core::{Severity, Verdict};

use crate::detect::Detection;

/// Where the service is in its life.
///
/// The same four states the SCM is told, and reported here so that a client can
/// find out without asking the SCM — which an unprivileged client cannot do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// Starting up. The control pipe is not accepting yet.
    Starting,
    /// Running and accepting.
    Running,
    /// Asked to stop, and stopping.
    Stopping,
    /// Not running. A client that reads this is talking to something that is
    /// about to close the connection.
    Stopped,
}

impl ServiceState {
    /// The word used in the user interface.
    pub const fn as_str(self) -> &'static str {
        match self {
            ServiceState::Starting => "starting",
            ServiceState::Running => "running",
            ServiceState::Stopping => "stopping",
            ServiceState::Stopped => "stopped",
        }
    }
}

/// What the service knows about the kernel driver.
///
/// Three answers, not two. `Unknown` is what a build that does not link the
/// driver's protocol reports, and it is a different answer from `Absent` — a
/// client that showed "no driver" for `Unknown` would be reporting a missing
/// protection it has not checked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverPresence {
    /// The driver's control device was opened, so the driver is loaded.
    Loaded,
    /// The driver's control device is not there, so the driver is not loaded.
    Absent,
    /// This build cannot tell.
    Unknown,
}

impl DriverPresence {
    /// True only when the driver was confirmed loaded.
    ///
    /// Deliberately not `!matches!(Absent)`: see this type's documentation.
    pub const fn is_loaded(self) -> bool {
        matches!(self, DriverPresence::Loaded)
    }

    /// The word used in the user interface.
    pub const fn as_str(self) -> &'static str {
        match self {
            DriverPresence::Loaded => "loaded",
            DriverPresence::Absent => "not-loaded",
            DriverPresence::Unknown => "unknown",
        }
    }
}

/// The driver's state, with the reason for it.
///
/// `detail` exists because a bare `Absent` invites the question "why", and the
/// answer is different for every failure: the device was not there, or it was
/// there and would not open, or this build never looked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverStatus {
    /// What the service concluded.
    pub presence: DriverPresence,
    /// One sentence saying how it concluded it.
    pub detail: String,
    /// The name of the device that was checked, when one was.
    pub device: Option<String>,
}

impl DriverStatus {
    /// A status for a build that does not look.
    pub fn unknown(detail: impl Into<String>) -> Self {
        Self {
            presence: DriverPresence::Unknown,
            detail: detail.into(),
            device: None,
        }
    }
}

/// What rule set the engine loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseStatus {
    /// The file it was read from.
    pub path: PathBuf,
    /// How many rules are in it.
    pub rules: usize,
    /// The format version of the file, as `av_rules::database::FORMAT_VERSION`
    /// reports it. Carried because "the rules are a year old" and "the rules
    /// are the wrong format" are different problems with different fixes.
    pub format_version: u32,
    /// Size on disk.
    pub bytes: u64,
}

/// What the user-mode filesystem watcher is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeState {
    /// Whether the configuration asks for it.
    pub enabled: bool,
    /// Whether at least one directory is actually armed.
    ///
    /// Distinct from `enabled`, and both are reported because the interesting
    /// state is the one where they disagree: enabled and not watching means
    /// the user was told they are protected and are not.
    pub watching: bool,
    /// The directories being watched.
    pub roots: Vec<PathBuf>,
    /// Why nothing is watched, when nothing is.
    pub disabled_by: Option<String>,
    /// Settings the watcher stores and does not honour.
    pub disclosures: Vec<SettingDisclosure>,
    /// Directories that were watched and stopped.
    ///
    /// A field of its own rather than a convention about `roots`, because the two
    /// answer different questions and the difference is the whole point: `roots`
    /// is what is watched *now*, and this is what stopped and why. The failure it
    /// prevents is a client that goes on drawing a green shield over a directory
    /// nothing is watching any more because the status never said otherwise.
    ///
    /// Additive, hence `serde(default)`: a report from a build that predates it
    /// carries no such record, which is true of a watcher that has not lost one.
    #[serde(default)]
    pub lost_roots: Vec<LostRoot>,
    /// The most recent window in which nothing was watched.
    ///
    /// Real-time protection has a hole whenever the kernel drops notification
    /// events, and the catch-up walk that follows does not close it: anything
    /// that happened and left no trace on disk — a process that ran from a path
    /// since deleted — was never seen. `None` means no window has been missed
    /// this session, which is not the same as a clean machine, and a client that
    /// showed the two the same way would report a gap in the coverage as a
    /// coverage.
    #[serde(default)]
    pub missed: Option<MissedWindow>,
}

/// A watched directory that stopped being watched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LostRoot {
    /// The directory.
    pub root: PathBuf,
    /// What ended the watch, as the watcher reported it.
    pub reason: String,
}

/// A window in which nothing was watched, and the walk that covered it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissedWindow {
    /// The tree that was walked to make up for it.
    pub root: PathBuf,
    /// Why the events were lost.
    pub because: String,
    /// Files the catch-up walk examined.
    pub files: u64,
    /// Directories the walk could not list, so neither they nor anything under
    /// them were examined.
    pub unreadable: u64,
    /// Whether the walk stopped with files still unexamined.
    ///
    /// A client that shows this must show it as "the catch-up scan was
    /// incomplete", never as "the catch-up scan found nothing else".
    pub truncated: bool,
    /// How many findings it produced.
    pub findings: usize,
}

impl RealtimeState {
    /// The nothing-is-watched state, with the reason.
    pub fn off(reason: impl Into<String>) -> Self {
        Self {
            enabled: false,
            watching: false,
            roots: Vec::new(),
            disabled_by: Some(reason.into()),
            disclosures: Vec::new(),
            lost_roots: Vec::new(),
            missed: None,
        }
    }

    /// A watched directory stopped being watched.
    ///
    /// Takes the root out of [`RealtimeState::roots`] — a list that goes on
    /// naming a directory nothing is watching is the list a client draws a green
    /// shield over — records it in [`RealtimeState::lost_roots`] with the reason,
    /// and recomputes [`RealtimeState::watching`]. `enabled` is left alone: the
    /// configuration still asks for protection, and a state that reported
    /// otherwise would say the user had turned it off rather than that it had
    /// stopped.
    ///
    /// Returns whether anything is still watched, which is the question the
    /// caller has to act on: a watcher with no roots left cannot be restarted
    /// from, because every restart path asks whether a watcher is already
    /// running.
    pub fn root_lost(&mut self, root: &Path, reason: impl Into<String>) -> bool {
        let reason = reason.into();
        // Built first, because the record below takes ownership of `reason`.
        let disabled_by = format!("every watched directory stopped: {reason}");
        self.roots.retain(|armed| armed != root);
        match self.lost_roots.iter_mut().find(|lost| lost.root == root) {
            // A root can stop, be re-armed by a restart and stop again. The
            // latest reason describes the machine the user is in; keeping the
            // first would describe a failure that has since been replaced.
            Some(lost) => lost.reason = reason,
            None => self.lost_roots.push(LostRoot {
                root: root.to_path_buf(),
                reason,
            }),
        }
        self.watching = !self.roots.is_empty();
        if !self.watching {
            // `disabled_by` is documented as "why nothing is watched, when
            // nothing is", and this is the one way to reach that state with the
            // configuration still asking for a watcher. Left as it was, a client
            // asking why would be told nothing.
            self.disabled_by = Some(disabled_by);
        }
        self.watching
    }

    /// Record a window in which nothing was watched.
    pub fn missed_window(&mut self, window: MissedWindow) {
        // The latest one, not a list: the question this answers is "is there a
        // hole in the coverage the user should know about", and a session that
        // lost events twice has the same answer as one that lost them once. The
        // count is in the log, which is where a history belongs.
        self.missed = Some(window);
    }
}

/// What the service's tamper checks have found.
///
/// # Why this is a state and not a stream of events
///
/// The three things it reports are "protection that had been undone was put
/// back", "the product's files no longer match what was recorded", and "files
/// that are not the product's are in the directories they live in". All are
/// facts about the machine *now*, and the last two are facts a client asks about
/// rather than acts on: nothing in this product's protocol can un-tamper a file,
/// and the service deliberately never re-records the manifest — see
/// `av_service::tamper`. So this is read beside [`RealtimeState`] and
/// [`DriverStatus`] rather than pushed at a client, and a client that was
/// disconnected when a check ran still gets the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperState {
    /// Whether the configuration asks for tamper resistance.
    ///
    /// Distinct from [`TamperState::checking`] for the reason
    /// [`RealtimeState::enabled`] is distinct from [`RealtimeState::watching`]:
    /// enabled and not checking is a user who was told they are protected and
    /// are not.
    pub enabled: bool,
    /// Whether a worker is running the checks.
    pub checking: bool,
    /// Why nothing is being checked, when nothing is.
    pub disabled_by: Option<String>,
    /// How many cheap passes have completed.
    ///
    /// A cheap pass re-reads this process's own access list and the product
    /// directories', and puts back anything it finds undone. It is the half that
    /// is cheap enough to run every few minutes.
    pub passes: u64,
    /// How many times protection was found undone and put back — the process
    /// counts once and each directory counts once.
    ///
    /// The number that makes tamper resistance visible: zero on a machine nobody
    /// has interfered with, and non-zero on one where something tried.
    pub reapplied: u64,
    /// What the last pass found still not in place, in one sentence per thing.
    ///
    /// Non-empty means the product is running unprotected and could not fix it,
    /// which is a different and worse fact than [`TamperState::reapplied`] being
    /// non-zero — that one means it noticed and recovered.
    pub unresolved: Vec<String>,
    /// How many expensive passes have completed.
    ///
    /// An expensive pass hashes every file the manifest names and verifies the
    /// signatures of the four programs. It runs once at start-up and then rarely,
    /// and it never repairs anything.
    pub manifest_checks: u64,
    /// What the last expensive pass found.
    pub manifest: ManifestVerdict,
    /// The differences the last expensive pass reported, one sentence each,
    /// capped.
    ///
    /// Capped because this is a report and not a listing: a machine where
    /// everything was replaced would otherwise put every file's sentence into
    /// every status answer for the life of the service. The count is in
    /// [`ManifestVerdict::Changed`].
    pub changes: Vec<String>,
}

impl TamperState {
    /// Nothing is being checked, and this says why.
    ///
    /// `enabled` is passed rather than derived, because the two ways of not
    /// checking are different facts: a configuration that turned tamper
    /// resistance off, and a configuration that asked for it on a layout this
    /// product refuses to harden — a cargo build tree, where the permissions
    /// being re-applied are an installation's and would lock the build.
    pub fn off(enabled: bool, reason: impl Into<String>) -> Self {
        Self {
            enabled,
            checking: false,
            disabled_by: Some(reason.into()),
            passes: 0,
            reapplied: 0,
            unresolved: Vec::new(),
            manifest_checks: 0,
            manifest: ManifestVerdict::NotChecked,
            changes: Vec::new(),
        }
    }

    /// Whether a check has found something a user has to be warned about.
    ///
    /// The union of the two unhappy facts, and deliberately not "the machine is
    /// tampered with": protection that was undone and put back has already been
    /// dealt with, and reporting it as a current problem would be reporting a
    /// state the machine is no longer in. What it is for is deciding whether a
    /// status line leads with a warning.
    ///
    /// [`ManifestVerdict::Unexpected`] is deliberately not one of them. Files
    /// that are not the product's, in a directory the product owns, are worth
    /// saying and are not a hole: nothing the manifest names is different. A
    /// warning here would be a warning on every installation that keeps a readme
    /// beside the program, and [`ManifestVerdict::Unexpected`]'s own
    /// documentation has the measurement of what that costs.
    pub fn has_findings(&self) -> bool {
        !self.unresolved.is_empty()
            || matches!(
                self.manifest,
                ManifestVerdict::Changed { .. } | ManifestVerdict::Unavailable(_)
            )
    }
}

/// What the last expensive check said about the product's recorded files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestVerdict {
    /// No expensive pass has finished, so nothing has been compared.
    ///
    /// A build that has not looked must not be read as a machine with nothing
    /// wrong, which is the same rule [`DriverPresence::Unknown`] follows.
    NotChecked,
    /// There is no manifest, so there has been nothing to compare against since
    /// the product was installed.
    ///
    /// The normal state of a fresh installation, and not an alarm: taking a
    /// manifest is a command an administrator runs. A client that showed this as
    /// a problem would report every new install as broken.
    Absent,
    /// Nothing was found: every file the manifest names is unchanged and nothing
    /// is in the directories they live in that the manifest does not name.
    /// `files` is how many were compared.
    ///
    /// A machine where files appeared but nothing named changed is *not* clean —
    /// that is [`ManifestVerdict::Unexpected`], and keeping the two apart is
    /// what stops one of them being reported in the other's words.
    Clean {
        /// How many files the manifest names.
        files: usize,
    },
    /// The comparison was made and found differences. `differences` is how many
    /// files the manifest names no longer match it, or appeared where an entry
    /// recorded that nothing was — the two kinds that mean interference.
    Changed {
        /// How many such differences were found.
        differences: usize,
    },
    /// Every file the manifest names is unchanged, and files that are not the
    /// product's are in the directories they live in. `appeared` is how many.
    ///
    /// A state of its own rather than a [`ManifestVerdict::Changed`] with a
    /// smaller number, because the two are not the same finding and the
    /// sentences a user reads must not be either. Measured in the VM on
    /// 2026-10-10: an installation whose directory held a readme, a test
    /// certificate and copies of earlier binaries — none of the product's files
    /// touched — was reported by every surface as "20 of the product's own files
    /// no longer match the manifest". Nothing in this product changed that day
    /// except a sentence.
    ///
    /// Not an alarm: nothing about the product's files is different, and the
    /// files listed are the ones an installation also holds by accident (an
    /// uninstaller, a readme, a user's own notes beside the program). It is
    /// reported because a file that appeared is a question, and silence about it
    /// would be the product not saying what it saw.
    Unexpected {
        /// How many files were there that the manifest does not name.
        appeared: usize,
    },
    /// Nothing was compared, and this is why — the manifest could not be read,
    /// it was taken against a different installation, or a file could not be
    /// hashed. The sentence is `av-guard`'s own.
    Unavailable(String),
}

impl Default for TamperState {
    /// Nothing checked, and why: the value a report that does not carry the
    /// field at all is read as. See [`StatusReport::tamper`].
    fn default() -> Self {
        Self::off(
            false,
            "this report carries no tamper state, so it came from a build that does not check",
        )
    }
}

impl ManifestVerdict {
    /// The word used in a user interface.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ManifestVerdict::NotChecked => "not checked",
            ManifestVerdict::Absent => "no manifest",
            ManifestVerdict::Clean { .. } => "unchanged",
            ManifestVerdict::Changed { .. } => "changed",
            ManifestVerdict::Unexpected { .. } => "unexpected files",
            ManifestVerdict::Unavailable(_) => "not comparable",
        }
    }
}

/// A setting that is stored, and something the user should know about it.
///
/// The same shape as `av_realtime::plan::Unhonoured`, and for the same reason:
/// the failure this prevents is a configuration file that says one thing and a
/// product that does another, with nothing anywhere saying so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingDisclosure {
    /// The key, spelled as it appears in `config.toml`.
    pub setting: String,
    /// What the user does not get, in one sentence.
    pub reason: String,
}

impl SettingDisclosure {
    /// Build one.
    pub fn new(setting: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            setting: setting.into(),
            reason: reason.into(),
        }
    }
}

/// What the service is and what it is doing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    /// Where the service is in its life.
    pub state: ServiceState,
    /// The product version this build reports.
    pub version: String,
    /// How long the service has been running.
    pub uptime_secs: u64,
    /// What is known about the kernel driver.
    pub driver: DriverStatus,
    /// The rule set, when one loaded.
    ///
    /// `None` is a service running without rules, which is a state a service
    /// has to be able to report: it is not "no detections", it is "no ability
    /// to detect", and a client that showed the two the same way would report a
    /// broken installation as a clean machine.
    pub database: Option<DatabaseStatus>,
    /// What the watcher is doing.
    pub realtime: RealtimeState,
    /// How many items the vault holds.
    pub quarantine_items: usize,
    /// How many scans are running.
    pub scans_running: usize,
    /// How many files the process has examined since it started.
    ///
    /// Files *examined*, not files *watched*. A directory watch does not
    /// enumerate the tree it is armed on — `ReadDirectoryChangesW` reports what
    /// happens from the moment it is issued, and `av_realtime` documents the
    /// measurement — so there is no honest count of how many files are sitting
    /// in a watched tree, and reporting one would be inventing it.
    pub files_examined: u64,
    /// What the tamper checks have found.
    ///
    /// Additive, hence `serde(default)`, and the default is the honest value for
    /// a report from a build that predates it: [`TamperState`]'s own `Default`
    /// has `checking` false and a `disabled_by` naming the build that sent it, so
    /// an old service's report is read as "nothing is being checked" rather than
    /// as a clean machine.
    #[serde(default)]
    pub tamper: TamperState,
}

/// One scan's identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ScanId(u64);

impl ScanId {
    /// Wrap a value, which the service assigns from its own counter.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The value on the wire.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ScanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How a running scan is getting on.
///
/// `total` is an `Option` because it is genuinely unknown for the first part of
/// a walk — the file count of a directory tree is not known until it has been
/// enumerated — and a progress bar that showed a fabricated total would jump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Which scan.
    pub id: ScanId,
    /// Files examined so far.
    pub scanned: u64,
    /// Files the walk expects to examine, when that is known.
    pub total: Option<u64>,
    /// What is being examined now.
    pub current: Option<PathBuf>,
    /// Detections so far.
    pub detections: u64,
    /// Bytes read so far.
    pub bytes: u64,
}

/// What a scan found and what was done about it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Files examined.
    pub files: u64,
    /// Bytes read.
    pub bytes: u64,
    /// Files the engine called a detection.
    pub detections: u64,
    /// Files taken into the vault.
    pub quarantined: u64,
    /// Files the engine called a detection and the vault would not take.
    ///
    /// Counted separately from `detections` because it is the number that says
    /// how many malicious files are still on the disk.
    pub quarantine_failed: u64,
    /// Files the engine could not read.
    ///
    /// Never folded into `files`: "we examined it and it was clean" and "we
    /// could not examine it" are different answers, and a scan that reported
    /// the second as the first would be lying about its coverage.
    pub unreadable: u64,
    /// Directories the walk could not list, and therefore did not descend
    /// into.
    pub unreadable_dirs: u64,
    /// How long it took.
    pub duration_ms: u64,
    /// True when the scan stopped because it was cancelled or because it hit
    /// its own limit, rather than because it finished.
    pub incomplete: bool,
    /// Why it stopped early, when it did.
    pub incomplete_reason: Option<String>,
    /// The detections, newest first.
    pub results: Vec<Detection>,
    /// How many detections were left out of `results`.
    ///
    /// A full scan of a large disk can produce thousands, and a progress reply
    /// that carried all of them would be a multi-megabyte frame. `detections`
    /// is the true count whatever this is.
    pub results_omitted: usize,
    /// When it ended.
    pub at: DateTime<Utc>,
}

impl ScanSummary {
    /// True when `results` carries every detection there was.
    pub const fn results_are_complete(&self) -> bool {
        self.results_omitted == 0
    }

    /// True when the scan examined the whole of what it was pointed at.
    ///
    /// The predicate a caller should show as "nothing was found" rather than as
    /// "everything was checked": a scan that could not read a directory did not
    /// clear it.
    pub const fn covered_everything(&self) -> bool {
        !self.incomplete && self.unreadable == 0 && self.unreadable_dirs == 0
    }
}

/// What scanning a buffer found.
///
/// Answers [`crate::Request::ScanBuffer`]. Not a [`ScanSummary`] and not a
/// [`Detection`], and the reason is the same in both cases: those two are about
/// a file. A `Detection` names a path and a file name because a notification
/// offers to quarantine what it names, and a scan of bytes that arrived from a
/// running script has no such thing to offer — so a `Detection` here would
/// carry a path that does not exist, and the first consumer to trust it would
/// try to open it.
///
/// # The verdict is the whole point, and `Unknown` is not `Clean`
///
/// [`Verdict::Unknown`] means the bytes were not examined — the buffer was over
/// the size cap, or the engine refused it. A caller must not read that as a
/// clean bill of health; it means this service has no opinion. The AMSI
/// provider distinguishes the two in its return value, and that mapping is the
/// one place in this product where getting it wrong silently disables a
/// protection rather than breaking something visibly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BufferScan {
    /// What the caller called the content, echoed back.
    ///
    /// Echoed rather than trusted: it came from `AMSI_ATTRIBUTE_CONTENT_NAME`
    /// and is a label in a log line, never a path anything is opened by.
    pub name: String,
    /// The verdict the engine reached.
    pub verdict: Verdict,
    /// The engine's accumulated score, on the scale
    /// [`av_core::VerdictThresholds`] reads its bands off.
    pub score: u16,
    /// The worst severity among the detections, when any fired.
    pub severity: Option<Severity>,
    /// The identifiers of the rules that fired, in the order the engine listed
    /// them.
    pub rules: Vec<String>,
    /// One sentence naming what was found, for a log or a notification.
    pub summary: String,
    /// Set when the bytes could not be examined. The verdict is then
    /// [`Verdict::Unknown`].
    pub error: Option<String>,
    /// How many bytes were examined.
    pub size: u64,
    /// How long the engine took, in milliseconds.
    ///
    /// Reported because the caller is a synchronous hook inside somebody else's
    /// process: an AMSI provider that makes PowerShell wait is a performance bug
    /// a user will notice long before they notice a detection, and the number
    /// that says whether that is happening has to exist somewhere.
    pub duration_ms: u64,
}

/// The configuration, and what of it is not in force.
///
/// Returned by both [`crate::Request::ConfigGet`] and
/// [`crate::Request::ConfigSet`], so that a caller that has just written a
/// setting is told in the same breath whether it will be acted on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigReport {
    /// The configuration in force, defaults filled in for an absent file.
    pub config: Box<AvConfig>,
    /// Set when `config.toml` exists and could not be read.
    ///
    /// The defaults in `config` are then *not* what the user asked for, and
    /// this is the only thing that says so. Silently falling back to defaults
    /// is how a user's exclusions and their threshold settings disappear
    /// without a word.
    pub load_error: Option<String>,
    /// Settings that are stored and not acted on by this build.
    pub unhonoured: Vec<SettingDisclosure>,
    /// Settings this service acts on somewhere other than where the user would
    /// expect, with a sentence saying where.
    ///
    /// A third list rather than a comment in the second, because "we do not do
    /// this" and "we do this, over there" are different answers, and putting
    /// the second in the unhonoured list would teach a user to ignore that list.
    pub handled_elsewhere: Vec<SettingDisclosure>,
}

impl ConfigReport {
    /// True when nothing about this configuration needs explaining.
    pub fn is_wholly_honoured(&self) -> bool {
        self.load_error.is_none() && self.unhonoured.is_empty() && self.handled_elsewhere.is_empty()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::detect::DetectionAction;

    /// A status a message-round-trip test can use.
    pub(crate) fn sample_status() -> StatusReport {
        StatusReport {
            state: ServiceState::Running,
            version: "0.1.0".to_string(),
            uptime_secs: 4242,
            driver: DriverStatus {
                presence: DriverPresence::Absent,
                detail: "the control device could not be opened".to_string(),
                device: Some(r"\\.\WenleAvFilter".to_string()),
            },
            database: Some(DatabaseStatus {
                path: PathBuf::from(r"C:\ProgramData\WenleAV\db\rules.avdb"),
                rules: 10_764,
                format_version: 9,
                bytes: 17 * 1024 * 1024,
            }),
            realtime: RealtimeState {
                enabled: true,
                watching: true,
                // Two of three still watched, so a round trip proves `roots`
                // and `lost_roots` are two different lists rather than one
                // filtered view of the other.
                roots: vec![
                    PathBuf::from(r"C:\Users\me\Downloads"),
                    PathBuf::from(r"C:\Users\me\Documents"),
                ],
                disabled_by: None,
                disclosures: vec![SettingDisclosure::new(
                    "realtime.scan_on_execute",
                    "a filesystem event does not say whether a file is about to be executed",
                )],
                lost_roots: vec![LostRoot {
                    root: PathBuf::from(r"C:\Users\me\Desktop"),
                    reason: "the directory handle was closed".to_string(),
                }],
                missed: Some(MissedWindow {
                    root: PathBuf::from(r"C:\Users\me\Downloads"),
                    because: "more changes arrived at once than the notification buffer could hold"
                        .to_string(),
                    files: 214,
                    unreadable: 3,
                    truncated: true,
                    findings: 1,
                }),
            },
            quarantine_items: 3,
            scans_running: 1,
            files_examined: 91_233,
            // Two of the five verdicts would round-trip through `NotChecked`
            // trivially; `Changed` with a carried sentence and a `reapplied`
            // count is the one that proves the field is really on the wire.
            tamper: TamperState {
                enabled: true,
                checking: true,
                disabled_by: None,
                passes: 41,
                reapplied: 2,
                unresolved: vec![
                    "this process's protection was found undone and could not be put back: \
                     access was denied"
                        .to_string(),
                ],
                manifest_checks: 1,
                manifest: ManifestVerdict::Changed { differences: 1 },
                changes: vec!["the file C:\\Program Files\\WenleAV\\wenle.exe is 4 bytes larger \
                               than the manifest records"
                    .to_string()],
            },
        }
    }

    /// A summary a message-round-trip test can use.
    pub(crate) fn sample_summary() -> ScanSummary {
        ScanSummary {
            files: 1200,
            bytes: 900 * 1024 * 1024,
            detections: 2,
            quarantined: 1,
            quarantine_failed: 1,
            unreadable: 4,
            unreadable_dirs: 1,
            duration_ms: 31_000,
            incomplete: false,
            incomplete_reason: None,
            results: vec![crate::detect::tests::sample_detection()],
            results_omitted: 1,
            at: Utc::now(),
        }
    }

    #[test]
    fn a_driver_that_was_not_checked_is_not_reported_as_absent() {
        // The distinction the type exists for: a build that cannot tell must
        // not answer a question about protection with a confident no.
        assert!(!DriverPresence::Unknown.is_loaded());
        assert!(!DriverPresence::Absent.is_loaded());
        assert!(DriverPresence::Loaded.is_loaded());
        assert_eq!(DriverPresence::Unknown.as_str(), "unknown");
        assert_ne!(
            DriverPresence::Unknown.as_str(),
            DriverPresence::Absent.as_str()
        );
    }

    /// A directory that stopped being watched leaves the list of what is
    /// watched and lands in the record of what stopped.
    ///
    /// The first half is the one that matters: a `roots` list that goes on
    /// naming a directory nothing is watching is what a client draws a green
    /// shield over, and before this existed the status could not say otherwise.
    #[test]
    fn a_lost_root_leaves_the_watched_list_and_is_recorded() {
        let first = PathBuf::from(r"C:\one");
        let second = PathBuf::from(r"C:\two");
        let mut state = RealtimeState {
            enabled: true,
            watching: true,
            roots: vec![first.clone(), second.clone()],
            disabled_by: None,
            disclosures: Vec::new(),
            lost_roots: Vec::new(),
            missed: None,
        };

        assert!(
            state.root_lost(&first, "the directory handle was closed"),
            "one of two roots is still watched"
        );
        assert_eq!(
            state.roots,
            vec![second.clone()],
            "a directory nothing is watching must not stay in the list"
        );
        assert_eq!(state.lost_roots.len(), 1);
        assert_eq!(state.lost_roots[0].root, first);
        assert!(
            state.enabled,
            "the configuration still asks for protection: the watcher stopped, it was not turned off"
        );
        assert!(
            state.disabled_by.is_none(),
            "something is still watched, so there is nothing to explain: {:?}",
            state.disabled_by
        );

        assert!(
            !state.root_lost(&second, "the volume went away"),
            "the last root leaving means nothing is watched"
        );
        assert!(state.roots.is_empty());
        assert_eq!(state.lost_roots.len(), 2);
        assert!(
            state
                .disabled_by
                .as_deref()
                .is_some_and(|why| why.contains("the volume went away")),
            "a client asking why nothing is watched must be told: {:?}",
            state.disabled_by
        );
        assert!(
            !state.watching,
            "nothing is armed, so nothing may be reported as armed"
        );
    }

    /// A root that stops, comes back and stops again keeps one record, with the
    /// reason that describes the machine the user is in.
    #[test]
    fn a_root_that_stops_twice_keeps_one_record_and_the_latest_reason() {
        let root = PathBuf::from(r"C:\only");
        let mut state = RealtimeState {
            enabled: true,
            watching: true,
            roots: vec![root.clone()],
            disabled_by: None,
            disclosures: Vec::new(),
            lost_roots: Vec::new(),
            missed: None,
        };

        state.root_lost(&root, "the first reason");
        // Back, as a restart would bring it back.
        state.roots.push(root.clone());
        state.watching = true;
        state.root_lost(&root, "the second reason");

        assert_eq!(
            state.lost_roots.len(),
            1,
            "one directory, one record: {:?}",
            state.lost_roots
        );
        assert_eq!(state.lost_roots[0].reason, "the second reason");
    }

    #[test]
    fn a_scan_that_could_not_read_everything_did_not_cover_everything() {
        let whole = ScanSummary {
            unreadable: 0,
            unreadable_dirs: 0,
            incomplete: false,
            ..sample_summary()
        };
        assert!(whole.covered_everything());
        // A locked file, a directory that refused to be listed, and a scan
        // that was cancelled are three different holes and none of them is
        // "clean".
        assert!(!ScanSummary {
            unreadable: 1,
            ..whole.clone()
        }
        .covered_everything());
        assert!(!ScanSummary {
            unreadable_dirs: 1,
            ..whole.clone()
        }
        .covered_everything());
        assert!(!ScanSummary {
            incomplete: true,
            ..whole
        }
        .covered_everything());
        assert!(!sample_summary().results_are_complete());
    }

    #[test]
    fn a_configuration_that_needs_explaining_says_so() {
        let quiet = ConfigReport {
            config: Box::new(AvConfig::default()),
            load_error: None,
            unhonoured: Vec::new(),
            handled_elsewhere: Vec::new(),
        };
        assert!(quiet.is_wholly_honoured());
        // Each of the three ways it can stop being whole, separately: a
        // configuration file that would not parse, a setting that is stored and
        // not acted on, and a setting acted on somewhere unexpected.
        assert!(!ConfigReport {
            load_error: Some("unknown field `scannig`".to_string()),
            ..quiet.clone()
        }
        .is_wholly_honoured());
        assert!(!ConfigReport {
            unhonoured: vec![SettingDisclosure::new("driver.enabled", "no driver")],
            ..quiet.clone()
        }
        .is_wholly_honoured());
        assert!(!ConfigReport {
            handled_elsewhere: vec![SettingDisclosure::new(
                "realtime.block_on_detect",
                "the control plane takes the file"
            )],
            ..quiet
        }
        .is_wholly_honoured());
    }

    #[test]
    fn realtime_can_be_enabled_and_not_watching() {
        // The state that matters, and the reason `enabled` and `watching` are
        // two fields rather than one.
        let state = RealtimeState {
            enabled: true,
            watching: false,
            roots: Vec::new(),
            disabled_by: Some("every configured root is excluded".to_string()),
            disclosures: Vec::new(),
            lost_roots: Vec::new(),
            missed: None,
        };
        assert!(state.enabled);
        assert!(!state.watching);
        let off = RealtimeState::off("realtime.enabled is false");
        assert!(!off.enabled);
        assert!(!off.watching);
        assert!(off.disabled_by.is_some());
    }

    #[test]
    fn a_detection_action_knows_whether_the_file_is_still_there() {
        assert!(!DetectionAction::Reported.is_contained());
        assert!(DetectionAction::Quarantined {
            id: av_quarantine::QuarantineId::new()
        }
        .is_contained());
        // A failed quarantine means the file is still on disk, and the type
        // must not let that read as handled.
        assert!(!DetectionAction::QuarantineFailed {
            reason: "the vault is full".to_string()
        }
        .is_contained());
    }
}
