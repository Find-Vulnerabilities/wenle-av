//! Scan targets, options, progress and reports.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::archive::ArchiveSummary;
use crate::error::AvError;
use crate::verdict::{Assessment, Detection, Verdict};

/// The slowest rate a scan of one byte is taken to run at, from measurement.
///
/// # Where this number comes from, and what it is for
///
/// Anything in this product that has to wait for, or bound, a scan needs to
/// know how long a scan takes. A flat number of seconds cannot answer that,
/// because "how long" is a function of "how much" — and two separate flat
/// numbers had already produced two separate faults before this constant was
/// extracted:
///
/// * the scan-memory budget waited a flat thirty seconds for a file's
///   reservation to come back, which a file at the default size cap outlives;
/// * the per-file time budget was a flat thirty seconds, which made every file
///   above about thirty megabytes permanently `Unknown` — `libclang.dll`,
///   81.7 MB, completed in 27.6 s and was still reported as one.
///
/// Both were the same mistake with the same shape, so they now share one
/// number.
///
/// # The measurement
///
/// A large executable is scanned at about 3 MB/s on one core — 81,704,960
/// bytes in 27.6 s, measured. The figure here is the pessimistic *floor* and
/// not the measurement, because everything that reads it is computing a bound
/// rather than a prediction, and a bound that a slow machine can exceed is not
/// a bound. It is a third of what was measured, which is the margin a machine
/// with a busier disk, a colder cache or a slower core is expected to need.
///
/// It is deliberately a rate and not a duration: a caller multiplies it by
/// what it is waiting for, which is the whole point of extracting it.
pub const FLOOR_BYTES_PER_SEC: u64 = 1024 * 1024;

/// What the user asked us to scan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanTarget {
    File(PathBuf),
    Directory(PathBuf),
    /// A volume root such as `C:\`.
    Drive(PathBuf),
    /// A running process, by PID. The name is carried alongside purely so that
    /// reports stay readable after the process has exited.
    Process {
        pid: u32,
        name: String,
    },
    /// Every process we can open.
    AllProcesses,
    /// The registry hives that hold persistence points.
    Registry,
    /// Master boot record / EFI system partition.
    BootSector,
    /// All of the above, minus removable media.
    FullSystem,
}

impl ScanTarget {
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            ScanTarget::File(p) | ScanTarget::Directory(p) | ScanTarget::Drive(p) => Some(p),
            _ => None,
        }
    }

    /// Short label for the UI.
    pub fn label(&self) -> String {
        match self {
            ScanTarget::File(p) => p.display().to_string(),
            ScanTarget::Directory(p) => p.display().to_string(),
            ScanTarget::Drive(p) => p.display().to_string(),
            ScanTarget::Process { pid, name } => format!("{name} (PID {pid})"),
            ScanTarget::AllProcesses => "All running processes".into(),
            ScanTarget::Registry => "Registry persistence points".into(),
            ScanTarget::BootSector => "Boot sectors".into(),
            ScanTarget::FullSystem => "Full system".into(),
        }
    }
}

/// Broad classification of a file, used to decide which rules are worth
/// evaluating. Skipping rules that cannot possibly apply is the cheapest large
/// speed-up available to a scanner — a `.txt` file has no import table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// Native Windows executable image (EXE/DLL/SYS/OCX).
    Pe,
    /// .NET managed assembly (also a PE, but analysed differently).
    DotNet,
    /// Shell scripts: .bat/.cmd/.ps1/.vbs/.js/.hta.
    Script,
    /// OLE/OpenXML documents that can carry macros.
    Document,
    /// Archives and installers.
    Archive,
    /// PDF, RTF, LNK and other formats abused as droppers.
    Exploit,
    /// Shortcut files.
    Shortcut,
    /// Anything else.
    Other,
    /// Could not be determined because the file could not be read.
    Unknown,
}

impl FileKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            FileKind::Pe => "pe",
            FileKind::DotNet => "dotnet",
            FileKind::Script => "script",
            FileKind::Document => "document",
            FileKind::Archive => "archive",
            FileKind::Exploit => "exploit",
            FileKind::Shortcut => "shortcut",
            FileKind::Other => "other",
            FileKind::Unknown => "unknown",
        }
    }
}

/// Knobs controlling how thoroughly a target is examined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOptions {
    pub recursive: bool,
    /// Follow directory symlinks and junctions. Off by default: on Windows this
    /// readily produces infinite loops through `C:\Users\...\Application Data`.
    pub follow_links: bool,
    /// Files larger than this are hashed but not pattern-scanned beyond the
    /// first chunk. `None` disables the limit.
    pub max_file_size: Option<u64>,
    /// How deep to descend into nested archives. 0 disables archive scanning.
    pub archive_depth: u8,
    /// Total bytes read from an archive before we stop expanding it, guarding
    /// against zip bombs.
    pub archive_max_expansion: u64,
    /// Run static heuristics (entropy, packing, imports) alongside signatures.
    pub heuristics: bool,
    /// Evaluate rules against the executable memory of running processes.
    ///
    /// Read by the layer that enumerates processes, not by the engine: the
    /// engine is handed bytes and a path, cannot open a process, and so has no
    /// way to obtain the memory this asks about. A caller that does not itself
    /// own a process list is free to leave it at `false`, which every default
    /// here does.
    pub memory: bool,
    /// Consult the trust layer (signature, path, publisher reputation) and let
    /// it discount weak detections.
    pub trust: bool,
    /// Scan inside archives.
    pub archives: bool,
    /// Stop the whole scan at the first malicious verdict.
    pub stop_on_first: bool,
    /// Per-file wall-clock budget *for a file of no size at all*.
    ///
    /// This is the slack, not the budget: the budget a file is actually held
    /// to is this plus the time its own size justifies, which is what
    /// [`ScanOptions::per_file_budget_for`] computes. A file that exceeds that
    /// is recorded as [`Verdict::Unknown`] rather than silently reported
    /// clean.
    ///
    /// # Why the size is added rather than configured
    ///
    /// Because a flat number is the wrong shape for a budget over an operation
    /// whose cost is proportional to what it is given, and this one had already
    /// gone wrong in exactly that way: at a flat thirty seconds and a measured
    /// three megabytes a second, **every file larger than about thirty
    /// megabytes was permanently `Unknown`** — including a legitimate, signed
    /// 81.7 MB DLL that the engine scanned correctly and then threw away. A
    /// file is not slow because it is big. It is slow because something is
    /// wrong with it, and that is what this budget is for: it fires on a small
    /// file that took far longer than its size can explain.
    pub per_file_timeout: Option<Duration>,
}

/// How long a file of `size` bytes is allowed to take beyond the slack.
///
/// See [`FLOOR_BYTES_PER_SEC`] for the rate and for the two faults that put it
/// here.
fn size_allowance(size: u64) -> Duration {
    Duration::from_secs(size / FLOOR_BYTES_PER_SEC)
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            follow_links: false,
            max_file_size: Some(256 * 1024 * 1024),
            archive_depth: 3,
            archive_max_expansion: 1024 * 1024 * 1024,
            heuristics: true,
            memory: false,
            trust: true,
            archives: true,
            stop_on_first: false,
            per_file_timeout: Some(Duration::from_secs(30)),
        }
    }
}

impl ScanOptions {
    /// The wall-clock budget a file of `size` bytes is held to.
    ///
    /// `None` when this configuration sets no budget at all. See
    /// [`ScanOptions::per_file_timeout`] for why the configured number is a
    /// slack that the file's own size is added to.
    pub fn per_file_budget_for(&self, size: u64) -> Option<Duration> {
        self.per_file_timeout.map(|slack| slack + size_allowance(size))
    }

    /// Fast, low-cost scan for real-time interception: no archives, no
    /// heuristics, tight timeout. Matches what a file-open hook can afford.
    pub fn realtime() -> Self {
        Self {
            recursive: false,
            heuristics: false,
            archives: false,
            memory: false,
            per_file_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        }
    }

    /// Deep scan used by the "Full scan" action.
    pub fn deep() -> Self {
        Self {
            heuristics: true,
            archives: true,
            archive_depth: 5,
            memory: false,
            max_file_size: None,
            per_file_timeout: None,
            ..Default::default()
        }
    }
}

/// Content hashes computed for a scanned file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digests {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

impl Digests {
    pub fn is_empty(&self) -> bool {
        self.md5.is_none() && self.sha1.is_none() && self.sha256.is_none()
    }

    /// Blake2b-style short fingerprint used for cache keys and for showing a
    /// file identity in the UI without the full 64-character digest.
    pub fn short(&self) -> Option<&str> {
        self.sha256
            .as_deref()
            .map(|s| &s[..s.len().min(16)])
            .or(self.sha1.as_deref().map(|s| &s[..s.len().min(12)]))
    }
}

/// Result of scanning one file (or one archive member).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanReport {
    pub path: PathBuf,
    pub kind: FileKind,
    pub size: u64,
    pub digests: Digests,
    pub assessment: Assessment,
    pub duration: Duration,
    /// Bytes actually read and examined. Lower than `size` when the file was
    /// skipped past the size cap.
    pub scanned_bytes: u64,
    /// True when the verdict came from the scan cache instead of fresh work.
    pub from_cache: bool,
    /// Set when the file could not be scanned. The verdict is then
    /// [`Verdict::Unknown`]; it is never silently reported clean.
    pub error: Option<String>,
    /// What was found inside this file when it was opened as a container.
    ///
    /// `None` means the file was scanned as the single file it is: either it is
    /// not a container, or archive scanning is off, or the options set
    /// `archive_depth` to zero. `Some` with `examined == 0` is a different
    /// statement — the file *is* a container, it was opened, and nothing in it
    /// was worth reading. A report that could not tell those apart would make
    /// "we looked inside" and "we never looked" read the same.
    ///
    /// Note that a member's findings are detections on *this* report, not
    /// reports of their own: the report list stays one entry per file on disk,
    /// which is what every consumer — quarantine, statistics, exit codes —
    /// already assumes. Where inside the container a finding was is carried by
    /// [`MatchLocation::container`](crate::MatchLocation::container).
    pub archive: Option<ArchiveSummary>,
}

impl FileScanReport {
    pub fn verdict(&self) -> Verdict {
        self.assessment.verdict
    }

    pub fn is_detection(&self) -> bool {
        self.assessment.is_detection()
    }
}

/// Running totals for a scan in progress.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub bytes_scanned: u64,
    pub threats_found: u64,
    pub errors: u64,
    /// Files whose verdict came from cache.
    pub cache_hits: u64,
    /// Files the engine opened, recognised as data it must not run its own
    /// rules against, and therefore did not examine.
    ///
    /// One counter for both kinds of recognition, and the front end is where
    /// they are told apart if it can: the console does, by digest against
    /// shape, because it has the report in hand. A front end that only has the
    /// totals says what is true of both — which is that they were recognised
    /// and not examined.
    pub files_declined: u64,
    /// The size of those files, as read.
    ///
    /// Kept beside [`ScanStats::files_scanned`] rather than inside it: a scan
    /// reports the bytes it examined, and a rule corpus is a file made of the
    /// strings its own rules search for, so counting it as examined is the
    /// error the recognition exists to prevent.
    pub bytes_declined: u64,
    /// Rule sources the engine declined *inside* files that it did examine,
    /// counted in members.
    ///
    /// A count and not a size, because a member's length is not a fact about
    /// the container's — see `av_scan::own::declined_members`, which is where
    /// the note this is read from is written. Nothing is subtracted from
    /// [`ScanStats::files_scanned`] or [`ScanStats::bytes_scanned`] for it: the
    /// container was opened, walked and scanned, and this says that a part of
    /// it was not.
    pub declined_members: u64,
}

impl ScanStats {
    /// Fold another worker's totals into this one.
    ///
    /// Saturating rather than wrapping: a counter that has reached `u64::MAX`
    /// is already nonsense, and wrapping it to a small number would make a
    /// finished scan report a plausible-looking wrong total. Saturating leaves
    /// it obviously absurd instead.
    pub fn merge(&mut self, other: &ScanStats) {
        self.files_scanned = self.files_scanned.saturating_add(other.files_scanned);
        self.files_skipped = self.files_skipped.saturating_add(other.files_skipped);
        self.bytes_scanned = self.bytes_scanned.saturating_add(other.bytes_scanned);
        self.threats_found = self.threats_found.saturating_add(other.threats_found);
        self.errors = self.errors.saturating_add(other.errors);
        self.cache_hits = self.cache_hits.saturating_add(other.cache_hits);
        self.files_declined = self.files_declined.saturating_add(other.files_declined);
        self.bytes_declined = self.bytes_declined.saturating_add(other.bytes_declined);
        self.declined_members = self.declined_members.saturating_add(other.declined_members);
    }
}

/// A progress tick emitted while a scan runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Best-effort completion in `0.0..=1.0`. `None` when the total is not
    /// knowable (scanning a live process list, for example).
    pub fraction: Option<f32>,
    pub current: PathBuf,
    pub stats: ScanStats,
    pub elapsed: Duration,
}

/// The complete outcome of a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: ScanTarget,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration: Duration,
    pub stats: ScanStats,
    /// Every file that produced a non-clean verdict, most severe first.
    pub detections: Vec<FileScanReport>,
    /// Files that could not be scanned, with the reason.
    pub failures: Vec<(PathBuf, String)>,
    /// Files the rules matched and trust then cleared, so that they are not in
    /// [`Self::detections`] and not in [`Self::failures`] either.
    ///
    /// The third thing a scan of a whole disk can do to a file, and the one with
    /// no line of its own until this counter existed: the file is not reported
    /// (the verdict is `Clean`), it did not fail, and it is not merely quiet —
    /// rules were run against it and some of them matched. What cleared it is on
    /// the file's own [`Assessment::remediation_withheld`], which is where a
    /// reader who wants the rule ids and the reason should go; this is the tally
    /// a summary needs so that "nothing found" is not said over a run that threw
    /// matches away.
    ///
    /// [`Assessment::remediation_withheld`]: crate::Assessment::remediation_withheld
    pub cleared: usize,
    /// True when the user or a policy stopped the scan before it finished.
    pub cancelled: bool,
}

impl ScanReport {
    pub fn new(target: ScanTarget) -> Self {
        Self {
            target,
            started_at: chrono::Utc::now(),
            duration: Duration::ZERO,
            stats: ScanStats::default(),
            detections: Vec::new(),
            failures: Vec::new(),
            cleared: 0,
            cancelled: false,
        }
    }

    pub fn worst_verdict(&self) -> Verdict {
        self.detections
            .iter()
            .map(|d| d.verdict())
            .max_by_key(|v| match v {
                Verdict::Malicious => 2,
                Verdict::Suspicious => 1,
                _ => 0,
            })
            .unwrap_or(Verdict::Clean)
    }

    /// Every detection across every file, flattened for the threat list UI.
    pub fn all_detections(&self) -> impl Iterator<Item = (&PathBuf, &Detection)> {
        self.detections
            .iter()
            .flat_map(|r| r.assessment.detections.iter().map(move |d| (&r.path, d)))
    }

    /// Sort detections so the most dangerous appear first.
    pub fn sort_by_severity(&mut self) {
        self.detections.sort_by(|a, b| {
            b.assessment
                .score
                .cmp(&a.assessment.score)
                .then_with(|| a.path.cmp(&b.path))
        });
    }
}

/// A non-fatal problem encountered while scanning, kept separate from
/// [`AvError`] so it can be recorded per file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFailure {
    pub path: PathBuf,
    pub reason: String,
    /// Mirrors [`AvError::is_transient`], so the UI can say "locked, try again"
    /// instead of "corrupt".
    pub transient: bool,
}

impl ScanFailure {
    pub fn new(path: impl Into<PathBuf>, reason: impl Into<String>, transient: bool) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
            transient,
        }
    }

    pub fn from_error(path: impl Into<PathBuf>, err: &AvError) -> Self {
        Self::new(path, err.to_string(), err.is_transient())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realtime_options_skip_expensive_work() {
        let o = ScanOptions::realtime();
        assert!(!o.archives);
        assert!(!o.heuristics);
        assert!(!o.memory);
        assert_eq!(o.per_file_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn deep_options_remove_size_and_time_caps() {
        let o = ScanOptions::deep();
        assert_eq!(o.max_file_size, None);
        assert_eq!(o.per_file_timeout, None);
        assert!(o.archives);
    }

    #[test]
    fn a_files_time_budget_grows_with_the_file() {
        // The fault this is written against: a flat thirty-second budget made
        // every file above about thirty megabytes permanently `Unknown`. The
        // one that exposed it was a legitimate 81.7 MB DLL, `libclang.dll`,
        // which the engine scanned correctly in 27.6 s and then threw away —
        // and the budget did not even save the time, because it is applied
        // after the scan rather than interrupting it.
        let options = ScanOptions::default();
        let empty = options.per_file_budget_for(0).expect("the default sets one");
        assert_eq!(empty, Duration::from_secs(30), "the slack is the whole budget for nothing");

        let libclang = options
            .per_file_budget_for(81_704_960)
            .expect("the default sets one");
        assert!(
            libclang > Duration::from_secs(60),
            "{libclang:?} is not enough for a file that takes 27.6 s to scan"
        );

        // Monotone, so a bigger file is never held to a tighter budget.
        let capped = options
            .per_file_budget_for(256 * 1024 * 1024)
            .expect("the default sets one");
        assert!(capped > libclang, "{capped:?} vs {libclang:?}");
    }

    #[test]
    fn a_file_is_held_to_a_budget_its_size_can_explain() {
        // What the budget is *for*: a small file that took far longer than its
        // size can account for is the pathological case, and it still fires.
        // Ten megabytes is ten seconds of allowance, so a ten-megabyte file
        // that took a minute is over — which the flat budget caught too, and
        // this must not have lost.
        let options = ScanOptions::default();
        let small = options.per_file_budget_for(10 * 1024 * 1024).expect("set");
        assert!(small < Duration::from_secs(60), "{small:?}");
        assert!(small > Duration::from_secs(30), "{small:?}");
    }

    #[test]
    fn a_configuration_with_no_budget_still_has_none() {
        // The size allowance is added to a budget that exists; it does not
        // invent one. `--deep` sets no budget on purpose.
        let options = ScanOptions::deep();
        assert_eq!(options.per_file_budget_for(0), None);
        assert_eq!(options.per_file_budget_for(512 * 1024 * 1024), None);
    }

    #[test]
    fn worst_verdict_picks_malicious_over_suspicious() {
        let mut report = ScanReport::new(ScanTarget::FullSystem);
        let mut a = Assessment::clean();
        a.verdict = Verdict::Suspicious;
        report.detections.push(FileScanReport {
            path: PathBuf::from("a"),
            kind: FileKind::Pe,
            size: 0,
            digests: Digests::default(),
            assessment: a,
            duration: Duration::ZERO,
            scanned_bytes: 0,
            from_cache: false,
            error: None,
            archive: None,
        });
        let mut b = Assessment::clean();
        b.verdict = Verdict::Malicious;
        report.detections.push(FileScanReport {
            path: PathBuf::from("b"),
            kind: FileKind::Pe,
            size: 0,
            digests: Digests::default(),
            assessment: b,
            duration: Duration::ZERO,
            scanned_bytes: 0,
            from_cache: false,
            error: None,
            archive: None,
        });
        assert_eq!(report.worst_verdict(), Verdict::Malicious);
    }

    #[test]
    fn empty_report_is_clean() {
        let report = ScanReport::new(ScanTarget::FullSystem);
        assert_eq!(report.worst_verdict(), Verdict::Clean);
    }

    #[test]
    fn stats_merge_accumulates_every_counter() {
        let mut a = ScanStats {
            files_scanned: 1,
            files_skipped: 2,
            bytes_scanned: 3,
            threats_found: 4,
            errors: 5,
            cache_hits: 6,
            ..ScanStats::default()
        };
        a.merge(&a.clone());
        assert_eq!(a.files_scanned, 2);
        assert_eq!(a.cache_hits, 12);
    }

    #[test]
    fn the_declined_counters_are_folded_in_with_the_rest() {
        // The three counters a merge can silently drop, because a scan of a
        // tree is walked by several workers and each of them can decline a file:
        // a merge that carried the examined totals and not these would report a
        // run as having examined a rule corpus, which is the one claim this
        // product's own accounting is built not to make.
        let mut a = ScanStats {
            files_declined: 1,
            bytes_declined: 2,
            declined_members: 3,
            ..ScanStats::default()
        };
        a.merge(&a.clone());
        assert_eq!(a.files_declined, 2);
        assert_eq!(a.bytes_declined, 4);
        assert_eq!(a.declined_members, 6);
        // And the examined totals are untouched by them.
        assert_eq!(a.files_scanned, 0);
        assert_eq!(a.bytes_scanned, 0);
    }

    #[test]
    fn short_digest_prefers_sha256() {
        let d = Digests {
            md5: Some("a".repeat(32)),
            sha1: Some("b".repeat(40)),
            sha256: Some("c".repeat(64)),
        };
        assert_eq!(d.short().unwrap().len(), 16);
    }
}
