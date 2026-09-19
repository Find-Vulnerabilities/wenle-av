//! Scan targets, options, progress and reports.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::AvError;
use crate::verdict::{Assessment, Detection, Verdict};

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
    Process { pid: u32, name: String },
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
    /// Evaluate rules against executable memory of running processes.
    pub memory: bool,
    /// Consult the trust layer (signature, path, publisher reputation) and let
    /// it discount weak detections.
    pub trust: bool,
    /// Scan inside archives.
    pub archives: bool,
    /// Stop the whole scan at the first malicious verdict.
    pub stop_on_first: bool,
    /// Per-file wall-clock budget. A file that exceeds it is recorded as
    /// [`Verdict::Unknown`] rather than silently reported clean.
    pub per_file_timeout: Option<Duration>,
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
    /// Path of the containing archive, when this entry came from one.
    pub container: Option<PathBuf>,
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
}

impl ScanStats {
    pub fn merge(&mut self, other: &ScanStats) {
        self.files_scanned += other.files_scanned;
        self.files_skipped += other.files_skipped;
        self.bytes_scanned += other.bytes_scanned;
        self.threats_found += other.threats_found;
        self.errors += other.errors;
        self.cache_hits += other.cache_hits;
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
            container: None,
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
            container: None,
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
        };
        a.merge(&a.clone());
        assert_eq!(a.files_scanned, 2);
        assert_eq!(a.cache_hits, 12);
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
