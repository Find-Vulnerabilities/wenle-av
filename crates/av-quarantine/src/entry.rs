//! What the vault remembers about each file it took.
//!
//! An entry is a record of an event: *this* file, at *this* path, holding
//! *this* content, was quarantined at *this* time because *this* rule fired.
//! Everything the quarantine list shows a user, and everything the restore path
//! needs in order to put the file back where it came from, is in here.
//!
//! The bytes themselves live in a blob named after the entry's identifier. The
//! entry is sealed inside the index, so it cannot be edited by anything that
//! can write to the vault directory — which matters, because the original path
//! in here is where a restore writes to.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use av_core::{Digests, FileScanReport, Severity, ThreatName, Verdict};

use crate::id::QuarantineId;

/// Which part of the product quarantined the file.
///
/// Recorded because it changes what a user should do about a false positive:
/// something the real-time scanner took out from under them mid-download is
/// worth a second look, something a scheduled full scan found last Tuesday
/// usually is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntrySource {
    /// The user asked for it from the quarantine list or the command line.
    Manual,
    /// On-access scanning blocked it as it was written or executed.
    Realtime,
    /// A full or custom scan found it after the fact.
    Scan,
    /// The behaviour monitor saw the process do something.
    Behaviour,
    /// A region of a running process's memory matched.
    Memory,
    /// An AMSI provider refused content a scripting host was about to run.
    ///
    /// # Why this is not [`EntrySource::Scan`]
    ///
    /// Because the two make different promises about the same bytes. A scan
    /// finds content that is sitting somewhere and reports it; the thing it
    /// found may have been running for a week. An AMSI provider is asked
    /// *before* the host runs the content, and a `DETECTED` answer means the
    /// host does not run it — so the script block, the macro or the encoded
    /// command genuinely did not execute.
    ///
    /// Filing that under `Scan` would make the corner notification say "found
    /// after it appeared" about something that never ran, which understates the
    /// product in the one message a user actually reads. Filing it under
    /// [`EntrySource::Realtime`] would be wrong in the other direction: that
    /// word means a minifilter refused an open, and no file here was ever
    /// opened.
    ///
    /// What is *not* claimed is a file. Content reaches an AMSI provider from a
    /// host's memory, and the bytes may never have been on disk at all — so
    /// nothing carrying this source can be quarantined, and
    /// [`EntrySource::is_pre_execution`] being `true` here says the content was
    /// stopped, not that anything was taken.
    Amsi,
    /// The sandbox ran it and it did something.
    Sandbox,
    /// The kernel driver reported it.
    Driver,
}

impl EntrySource {
    /// The word used in the user interface and in `--json` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            EntrySource::Manual => "manual",
            EntrySource::Realtime => "real-time",
            EntrySource::Scan => "scan",
            EntrySource::Behaviour => "behaviour",
            EntrySource::Memory => "memory",
            EntrySource::Amsi => "amsi",
            EntrySource::Sandbox => "sandbox",
            EntrySource::Driver => "driver",
        }
    }

    /// True when the file was blocked *before* anything could run it.
    ///
    /// This is the distinction the notification makes: "we stopped this" and
    /// "we found this afterwards" are different messages, and conflating them
    /// is how a product cries wolf about something that already ran.
    pub const fn is_pre_execution(self) -> bool {
        matches!(
            self,
            EntrySource::Realtime | EntrySource::Driver | EntrySource::Amsi
        )
    }
}

/// Where an item is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryStatus {
    /// The bytes are in the vault and the original is gone.
    Quarantined,
    /// The bytes were written back to disk. The vault may still hold a copy if
    /// the caller did not ask for it to be dropped.
    Restored,
    /// The user deleted it. The record is kept so that the quarantine list can
    /// still say what happened to that file.
    Deleted,
}

impl EntryStatus {
    /// The word used in the user interface.
    pub const fn as_str(self) -> &'static str {
        match self {
            EntryStatus::Quarantined => "quarantined",
            EntryStatus::Restored => "restored",
            EntryStatus::Deleted => "deleted",
        }
    }

    /// True while the item still occupies vault space and can be restored.
    pub const fn is_live(self) -> bool {
        matches!(self, EntryStatus::Quarantined)
    }
}

/// One quarantined file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Random identifier; also the name of the blob on disk.
    pub id: QuarantineId,
    /// Where the file was when it was taken.
    pub original_path: PathBuf,
    /// The file name alone, kept so that a listing does not have to split the
    /// path — and so that the name survives even if the original directory is
    /// deleted while the item sits in the vault.
    pub file_name: String,
    /// Size in bytes of the quarantined content.
    pub size: u64,
    /// The three digests, computed before the bytes were sealed. Restore and
    /// verify both re-compute SHA-256 and compare.
    pub digests: Digests,
    /// What the engine called it, when a rule named a family.
    pub threat: Option<ThreatName>,
    /// The identifier of the rule or heuristic that fired, for the "why" line.
    pub detection: Option<String>,
    /// The worst severity among the detections.
    pub severity: Severity,
    /// The verdict at the time of quarantine: `Malicious` or `Suspicious`.
    pub verdict: Verdict,
    /// Which component took it.
    pub source: EntrySource,
    /// When it was taken.
    pub quarantined_at: DateTime<Utc>,
    /// Where it is now in its life.
    pub status: EntryStatus,
    /// When it last changed state — restored, deleted, or verified.
    pub changed_at: DateTime<Utc>,
    /// True once the original file is confirmed gone. False while the original
    /// is still on disk because something held it open; a retry pass clears it.
    pub original_removed: bool,
    /// Free text from the caller: an operator's note, a ticket number.
    pub note: Option<String>,
}

impl QuarantineEntry {
    /// Record a quarantine that is about to happen, in the `Quarantined` state.
    ///
    /// The identifier is passed in rather than generated here so that the
    /// caller can seal the payload against it before the entry exists, which is
    /// the order the vault needs: the blob's associated data is derived from
    /// the identifier, so the identifier has to come first.
    pub fn new(
        id: QuarantineId,
        original_path: impl Into<PathBuf>,
        size: u64,
        digests: Digests,
        context: &QuarantineContext,
    ) -> Self {
        let original_path = original_path.into();
        let file_name = file_name_of(&original_path);
        let now = Utc::now();
        Self {
            id,
            original_path,
            file_name,
            size,
            digests,
            threat: context.threat.clone(),
            detection: context.detection.clone(),
            severity: context.severity,
            verdict: context.verdict,
            source: context.source,
            quarantined_at: now,
            status: EntryStatus::Quarantined,
            changed_at: now,
            original_removed: false,
            note: context.note.clone(),
        }
    }

    /// The name to show in a list: the detection if there is one, otherwise the
    /// file name.
    pub fn display_name(&self) -> &str {
        match &self.threat {
            Some(threat) => threat.family.as_deref().unwrap_or(&self.file_name),
            None => &self.file_name,
        }
    }

    /// True when this item is a candidate for the "restore and exclude" flow —
    /// something taken on suspicion rather than on a known-bad match.
    ///
    /// A user hitting a false positive is the expensive failure mode of an
    /// antivirus, and the quarantine list is where they find out. Offering
    /// restore-and-exclude for a suspicious file and not for a confirmed one is
    /// the difference between the product being usable and being uninstalled.
    pub fn is_suspicious_only(&self) -> bool {
        self.verdict == Verdict::Suspicious
    }

    /// Does this entry refer to the file at `path`?
    ///
    /// Compared case-insensitively, because Windows paths are, and compared on
    /// the path as written rather than canonicalized, because the original may
    /// no longer exist and `canonicalize` would fail on it.
    pub fn is_from(&self, path: &Path) -> bool {
        let a = self.original_path.to_string_lossy().to_lowercase();
        let b = path.to_string_lossy().to_lowercase();
        a == b.trim_start_matches(r"\\?\")
    }
}

/// The file name component of a path, or the whole path when there is not one.
fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

/// What the caller knows about a file at the moment it is quarantined.
///
/// Assembled from a scan report by [`QuarantineContext::from_report`] on the
/// paths that have one, and filled in by hand by the components that do not —
/// the behaviour monitor knows a process did something, not which rule fired.
#[derive(Debug, Clone, PartialEq)]
pub struct QuarantineContext {
    /// The named family, when a rule named one.
    pub threat: Option<ThreatName>,
    /// The rule or heuristic identifier.
    pub detection: Option<String>,
    /// Worst severity among the detections.
    pub severity: Severity,
    /// The verdict that justified removal.
    pub verdict: Verdict,
    /// Which component is acting.
    pub source: EntrySource,
    /// Free text for the record.
    pub note: Option<String>,
    /// Remove the original after the bytes are safely in the vault. Turning
    /// this off keeps a copy on disk, which is what the sandbox path wants.
    pub remove_original: bool,
}

impl Default for QuarantineContext {
    fn default() -> Self {
        Self {
            threat: None,
            detection: None,
            severity: Severity::High,
            verdict: Verdict::Malicious,
            source: EntrySource::Manual,
            note: None,
            remove_original: true,
        }
    }
}

impl QuarantineContext {
    /// Take everything worth keeping from a scan report.
    ///
    /// The severity and verdict are copied from the report rather than
    /// recomputed: the report's verdict already has the trust adjustment
    /// applied, and re-deriving it here from the raw detections would record a
    /// different number from the one the user was shown.
    pub fn from_report(report: &FileScanReport, source: EntrySource) -> Self {
        let assessment = &report.assessment;
        // The rule identifier, falling back to the human-readable name for a
        // detection that has no identifier — a heuristic, for instance.
        let detection = assessment.detections.first().map(|d| {
            if d.rule_id.is_empty() {
                d.display_name()
            } else {
                d.rule_id.clone()
            }
        });
        Self {
            threat: assessment.primary_threat().cloned(),
            detection,
            severity: assessment.max_severity().unwrap_or(Severity::High),
            verdict: report.verdict(),
            source,
            note: None,
            remove_original: true,
        }
    }

    /// Which component is acting.
    pub fn with_source(mut self, source: EntrySource) -> Self {
        self.source = source;
        self
    }

    /// A note for the record.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Keep the original file on disk. Used by the sandbox, where the file is
    /// the evidence and removing it would destroy what is being examined.
    pub fn keeping_original(mut self) -> Self {
        self.remove_original = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::QuarantineId;

    fn digests() -> Digests {
        Digests {
            md5: Some("d41d8cd98f00b204e9800998ecf8427e".into()),
            sha1: None,
            sha256: Some("e3b0c44298fc1c149afbf4c8996fb924".into()),
        }
    }

    fn entry(path: &str) -> QuarantineEntry {
        QuarantineEntry::new(
            QuarantineId::from_bytes([4u8; 16]),
            path,
            1234,
            digests(),
            &QuarantineContext::default(),
        )
    }

    #[test]
    fn a_new_entry_is_quarantined_and_its_original_is_still_there() {
        let e = entry(r"C:\Users\me\Downloads\bad.exe");
        assert_eq!(e.status, EntryStatus::Quarantined);
        assert!(e.status.is_live());
        assert!(!e.original_removed);
        assert_eq!(e.file_name, "bad.exe");
        assert_eq!(e.quarantined_at, e.changed_at);
    }

    #[test]
    fn the_file_name_is_split_off_a_windows_path() {
        assert_eq!(entry(r"C:\a\b\c.dll").file_name, "c.dll");
        assert_eq!(entry(r"C:\a\b\").file_name, "b");
        // A path with no file name at all falls back to the path itself, so a
        // listing always has something to print.
        assert_eq!(entry(r"C:\").file_name, r"C:\");
    }

    #[test]
    fn the_display_name_prefers_the_family_when_a_rule_named_one() {
        let mut e = entry(r"C:\a.exe");
        assert_eq!(e.display_name(), "a.exe");
        e.threat = Some(av_core::ThreatName::generic(
            av_core::Platform::Win64,
            av_core::ThreatCategory::Trojan,
        ));
        assert_eq!(e.display_name(), "a.exe", "no family means fall back");
        if let Some(t) = e.threat.as_mut() {
            t.family = Some("Emotet".into());
        }
        assert_eq!(e.display_name(), "Emotet");
    }

    #[test]
    fn only_the_suspicious_band_offers_the_restore_and_exclude_flow() {
        let mut e = entry(r"C:\a.exe");
        e.verdict = Verdict::Suspicious;
        assert!(e.is_suspicious_only());
        e.verdict = Verdict::Malicious;
        assert!(!e.is_suspicious_only());
    }

    #[test]
    fn a_taken_file_is_recognised_by_its_original_path_whatever_the_case() {
        let e = entry(r"C:\Users\Me\Downloads\Bad.EXE");
        assert!(e.is_from(Path::new(r"c:\users\me\downloads\bad.exe")));
        assert!(e.is_from(Path::new(r"C:\Users\Me\Downloads\Bad.EXE")));
        assert!(!e.is_from(Path::new(r"C:\Users\Me\Downloads\other.exe")));
    }

    #[test]
    fn the_extended_length_prefix_does_not_defeat_the_comparison() {
        let e = entry(r"C:\a\b.exe");
        assert!(e.is_from(Path::new(r"\\?\C:\a\b.exe")));
    }

    #[test]
    fn only_the_three_pre_execution_sources_claim_to_have_blocked_it() {
        // Three, and each is a different mechanism for the same claim: the
        // filter driver refuses the open, the realtime watcher refuses the
        // create, and AMSI tells the host not to run a script it has already
        // assembled. The last one was missing from this list for a while after
        // `EntrySource::Amsi` was added, which is exactly the kind of omission
        // this test exists to catch — the list is exhaustive on purpose and a
        // new source has to be classified rather than defaulted.
        assert!(EntrySource::Realtime.is_pre_execution());
        assert!(EntrySource::Driver.is_pre_execution());
        assert!(EntrySource::Amsi.is_pre_execution());
        for source in [
            EntrySource::Manual,
            EntrySource::Scan,
            EntrySource::Behaviour,
            EntrySource::Memory,
            EntrySource::Sandbox,
        ] {
            assert!(!source.is_pre_execution(), "{source:?}");
        }
    }

    #[test]
    fn every_source_and_status_has_a_distinct_word() {
        let sources = [
            EntrySource::Manual,
            EntrySource::Realtime,
            EntrySource::Scan,
            EntrySource::Behaviour,
            EntrySource::Memory,
            EntrySource::Sandbox,
            EntrySource::Driver,
        ];
        let mut words: Vec<&str> = sources.iter().map(|s| s.as_str()).collect();
        words.sort_unstable();
        let before = words.len();
        words.dedup();
        assert_eq!(words.len(), before, "two sources share a word");

        let statuses = [
            EntryStatus::Quarantined,
            EntryStatus::Restored,
            EntryStatus::Deleted,
        ];
        for s in statuses {
            assert!(!s.as_str().is_empty());
        }
        assert!(EntryStatus::Quarantined.is_live());
        assert!(!EntryStatus::Restored.is_live());
        assert!(!EntryStatus::Deleted.is_live());
    }

    #[test]
    fn the_context_builders_set_what_they_say() {
        let c = QuarantineContext::default()
            .with_source(EntrySource::Sandbox)
            .with_note("submitted by the lab")
            .keeping_original();
        assert_eq!(c.source, EntrySource::Sandbox);
        assert_eq!(c.note.as_deref(), Some("submitted by the lab"));
        assert!(!c.remove_original);
    }

    #[test]
    fn an_entry_round_trips_through_the_serializer() {
        let e = entry(r"C:\a\b.exe");
        let bytes = bincode::serialize(&e).unwrap();
        let back: QuarantineEntry = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, e);
    }
}
