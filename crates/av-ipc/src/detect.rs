//! The detection payload: everything a notification needs, and the one field
//! that stops it claiming something that did not happen.
//!
//! # The claim, and how the type refuses to make it
//!
//! The bottom-right notification is the most visible thing this product does,
//! and it says one of two things:
//!
//! * "this file was stopped before it could run"
//! * "this file was found after it appeared"
//!
//! Those are different promises. The first is a claim that something was
//! prevented, and a product that makes it while only finding files after the
//! fact teaches its users to trust a protection that is not there. It is worse
//! than the missed detection, because it survives every future detection that
//! does work.
//!
//! `av_quarantine::EntrySource::is_pre_execution` answers `true` for
//! [`EntrySource::Realtime`], and that word means *a minifilter refused an open*
//! — not *a user-mode watcher noticed a write*. `av-realtime` is the second
//! thing and is filed under the same word, which is why
//! `av_realtime::finding::Phase::observed` takes **both** what the source says
//! it is and whether anything was actually stopped, and reports pre-execution
//! only when both hold. This crate carries that same derivation, and
//! [`Phase`] is the type that makes it the only one available: it is a struct
//! with a private field, so [`Phase::observed`] is the only way to make one and
//! there is no syntax in which a service can write down
//! `Phase::PreExecution` about a watcher that blocks nothing.
//!
//! An enum would not have done. An enum's variants are constructible by anyone
//! who can name them, so the mistake this exists to prevent would be one line
//! away in the crate least likely to be reviewed for it.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use av_core::scan::FileScanReport;
use av_core::{Severity, ThreatName, Verdict};
use av_quarantine::{EntrySource, QuarantineEntry, QuarantineId};

/// When, relative to the file running, a component saw it.
///
/// Not an enum, and [`Phase::observed`] is the reason — see this module's
/// documentation. The two states are the same two
/// `av_realtime::finding::Phase` has, and `av-service` maps between them
/// exhaustively so that a third state there stops the build here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Phase(bool);

impl Phase {
    /// The phase to report for a file that a `source`-classified component
    /// acted on, given whether it actually stopped the file.
    ///
    /// `blocked` is a parameter and not a constant because the honest value for
    /// a user-mode watcher is `false` and only the caller knows which component
    /// it is. `av_realtime::RealtimeService::BLOCKS_NOTHING` is that `false` at
    /// the call site, named so it can be found.
    pub const fn observed(source: EntrySource, blocked: bool) -> Self {
        Self(source.is_pre_execution() && blocked)
    }

    /// True when the file was stopped before anything could run it.
    pub const fn is_pre_execution(self) -> bool {
        self.0
    }

    /// True when reporting this phase means claiming a file was stopped.
    ///
    /// The predicate a test asserts on, rather than a string comparison: the
    /// property that matters is "does this claim stop something", and it should
    /// stay checkable if the wording changes.
    pub const fn claims_a_block(self) -> bool {
        self.0
    }

    /// The word used in `--json` output and in a user interface.
    pub const fn as_str(self) -> &'static str {
        if self.0 {
            "pre-execution"
        } else {
            "after-the-fact"
        }
    }

    /// The factual half-sentence a notification is built around.
    ///
    /// This crate owns the claim and the caller owns the sentence. The phrase
    /// says what happened and nothing about what did not: the after-the-fact
    /// branch does not contain the word "blocked", so a notification composed
    /// from it cannot make the claim by accident.
    pub const fn describe(self) -> &'static str {
        if self.0 {
            "was blocked before it could run"
        } else {
            "was found after it appeared"
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serialised as its name rather than as a boolean.
///
/// The wire form is the one a `--json` consumer and a log reader see, and
/// `true` would be a number with a meaning attached somewhere else. The two
/// spellings are the ones `Phase::as_str` returns, so there is one list of them
/// in this crate and not two.
impl Serialize for Phase {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Phase {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        match text.as_str() {
            "pre-execution" => Ok(Phase(true)),
            "after-the-fact" => Ok(Phase(false)),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["pre-execution", "after-the-fact"],
            )),
        }
    }
}

/// What was done about a detection.
///
/// Four outcomes in three variants, because "did it find something" and "did it
/// act" are different questions. The two that act are separate variants rather
/// than a flag, because a service that could not take a file has to say so:
/// a malicious file that is still on disk is a fact the user has to be told,
/// and a boolean would let that fact go missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionAction {
    /// Reported, and the file was left where it was.
    Reported,
    /// Taken into the vault.
    Quarantined {
        /// Which item, so a caller can offer restore without a second round
        /// trip to look the path up.
        id: QuarantineId,
    },
    /// A quarantine was attempted and the vault refused.
    QuarantineFailed {
        /// Why, in a sentence a user can read.
        reason: String,
    },
}

impl DetectionAction {
    /// True when the file is no longer where it was found.
    ///
    /// The only true thing this protocol can say that resembles "handled". It
    /// is not the same as blocking: the file had a life before it was found.
    pub const fn is_contained(&self) -> bool {
        matches!(self, DetectionAction::Quarantined { .. })
    }

    /// The word used in `--json` output.
    pub const fn as_str(&self) -> &'static str {
        match self {
            DetectionAction::Reported => "reported",
            DetectionAction::Quarantined { .. } => "quarantined",
            DetectionAction::QuarantineFailed { .. } => "quarantine-failed",
        }
    }
}

/// One detection, in the form a notification is rendered from.
///
/// Everything the toast needs is here — the name, the full path, the verdict,
/// the score, the rule identifiers, what was done and whether anything was
/// stopped — so that rendering it costs no second round trip. The wording is
/// the caller's, the claim is [`Detection::phase`]'s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    /// Where the file was when it was scanned.
    pub path: PathBuf,
    /// The file name alone.
    ///
    /// Carried rather than split off by the caller, following
    /// `av_quarantine::QuarantineEntry::file_name`: a path split in a
    /// notification and a path split in a quarantine listing must not be able
    /// to differ, and on Windows they can — `C:\x\` has no file name and
    /// `C:\x` has one called `x`.
    pub file_name: String,
    /// The verdict the engine reached.
    pub verdict: Verdict,
    /// The engine's accumulated score, on the scale
    /// [`av_core::VerdictThresholds`] reads its bands off.
    pub score: u16,
    /// The worst severity among the detections.
    pub severity: Severity,
    /// The family, when a rule named one.
    pub threat: Option<ThreatName>,
    /// The identifiers of the rules that fired, in the order the engine listed
    /// them. A detection with an empty identifier is carried under its readable
    /// name, which is what `av-quarantine` does with the same list.
    pub rules: Vec<String>,
    /// What was done about it.
    pub action: DetectionAction,
    /// Which component acted.
    pub source: EntrySource,
    /// Size in bytes at the time of the scan.
    pub size: u64,
    /// When it was seen.
    pub at: DateTime<Utc>,
    /// Where inside a running process the bytes were found, when the detection
    /// came from memory rather than from a file on disk.
    ///
    /// `None` for every detection a file scan produces, which is all of them
    /// but one kind. `Some` for a finding from a process's memory, spelled
    /// `explorer.exe:0x7ff6a1b20000` — the same attribution
    /// `av_memory::ProcessRef::container` builds, so that a client does not
    /// have to learn a second spelling. (That path is written out rather than
    /// linked because this crate does not depend on `av-memory`, and a link to
    /// a crate that is not a dependency is a link rustdoc cannot resolve.)
    ///
    /// A field of its own rather than an overloading of [`Detection::path`],
    /// because they answer different questions and a memory finding needs both:
    /// the path is the *file* the finding is about — the thing that has to be
    /// dealt with, and the thing [`DetectionAction`] acts on — and this is
    /// *where in the machine* the bytes were found. Folding the second into the
    /// first would produce a "path" that is not a path, which is the kind of
    /// value that ends up in a file dialog.
    #[serde(default)]
    pub in_process: Option<String>,
    /// Whether the process this was found in was terminated because of it.
    ///
    /// False for every detection a file scan produces, and meaningless unless
    /// [`Detection::in_process`] is `Some` — there is no process in the story
    /// for this field to be true about. A memory finding whose process the
    /// product killed carries `true`; one from a process that is still running
    /// carries `false`, which is the honest answer both for a scan a user asked
    /// for and for a finding whose file the process was allowed to keep.
    ///
    /// A field of its own rather than a [`DetectionAction`] variant, because
    /// the action is about the *file* — taken, left, or untakeable — and a
    /// termination happens whether or not there was a file to take. A region
    /// whose bytes are backed by no file can end with a stopped process and an
    /// empty vault, and that is exactly the case no action variant could
    /// express. It is also not folded into [`Detection::phase`]: terminating a
    /// process that is already running stops it from running *further*, and
    /// `Phase` is about whether the file was stopped before it ran at all.
    #[serde(default)]
    pub terminated: bool,
    /// Whether the file was stopped before it could run.
    ///
    /// Public, and impossible to set wrongly: [`Phase`] has no public
    /// constructor that does not take the two facts this is derived from.
    pub phase: Phase,
}

impl Detection {
    /// Take the reportable parts of a scan report.
    ///
    /// The verdict, score, severity and threat are copied out of the report's
    /// own assessment rather than recomputed, for the reason
    /// `av_quarantine::QuarantineContext::from_report` gives: those are the
    /// numbers the user was shown, and a second derivation is a second answer.
    pub fn from_report(
        report: &FileScanReport,
        source: EntrySource,
        blocked: bool,
        action: DetectionAction,
    ) -> Self {
        let assessment = &report.assessment;
        Self {
            path: report.path.clone(),
            file_name: file_name_of(&report.path),
            verdict: report.verdict(),
            score: assessment.score,
            severity: assessment.max_severity().unwrap_or(Severity::High),
            threat: assessment.primary_threat().cloned(),
            rules: assessment
                .detections
                .iter()
                .map(|detection| {
                    if detection.rule_id.is_empty() {
                        detection.display_name()
                    } else {
                        detection.rule_id.clone()
                    }
                })
                .collect(),
            action,
            source,
            size: report.size,
            at: Utc::now(),
            // A report is about a file on disk. Where the file was found is
            // what `path` already says, and there is no process in the story.
            in_process: None,
            // Nor is there a process to have terminated. A report is built from
            // a scan of bytes at a path; nothing in this constructor saw a
            // running program, so `true` is not available here even by mistake.
            terminated: false,
            phase: Phase::observed(source, blocked),
        }
    }

    /// True when rendering this detection means claiming a block.
    ///
    /// Forwarded from [`Phase::claims_a_block`] so that a caller holding a
    /// detection does not have to reach through it; the field is public either
    /// way and this is the predicate a test should assert on.
    pub const fn claims_a_block(&self) -> bool {
        self.phase.claims_a_block()
    }

    /// The name to show: the threat family, or the file name.
    pub fn display_name(&self) -> &str {
        match &self.threat {
            Some(threat) => threat.family.as_deref().unwrap_or(&self.file_name),
            None => &self.file_name,
        }
    }

    /// True when the file is no longer at [`Detection::path`].
    pub const fn is_contained(&self) -> bool {
        self.action.is_contained()
    }
}

impl std::fmt::Display for Detection {
    /// The name, the path and the phase, which is the sentence a log line
    /// wants. The notification builds its own wording around
    /// [`Phase::describe`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) {}",
            self.display_name(),
            self.path.display(),
            self.phase.describe()
        )
    }
}

/// What the vault holds, as a listing.
///
/// `omitted` rather than a longer reply: a machine can have tens of thousands
/// of quarantined items and a reply that carried all of them would be a
/// multi-megabyte frame every time a window is opened. A client that is told
/// the list was cut short can ask for more; one that is not told believes it
/// has seen everything, and the items it did not see are the ones it will not
/// offer to restore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineListing {
    /// The entries, newest first.
    pub entries: Vec<QuarantineEntry>,
    /// How many the vault holds in total, whatever was returned.
    pub total: usize,
    /// How many were left out of this reply.
    pub omitted: usize,
}

impl QuarantineListing {
    /// True when the reply does not carry the whole vault.
    pub const fn is_truncated(&self) -> bool {
        self.omitted > 0
    }
}

/// The file name component of a path, or the whole path when there is not one.
///
/// The same fallback `av-quarantine` uses, and duplicated deliberately rather
/// than reached for: this is called on the way into a notification, and a
/// detection whose name came out as an empty string would render a blank line
/// where a file name belongs.
fn file_name_of(path: &std::path::Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use av_core::scan::{Digests, FileKind};
    use av_core::{Assessment, Detection as CoreDetection, DetectionSource};

    /// A report that reached `verdict` with one detection of `severity`.
    ///
    /// Built by hand rather than by scanning, so the phase rules can be tested
    /// over every source without needing a file that produces one.
    pub(crate) fn sample_report(
        verdict: Verdict,
        severity: Severity,
        rule: &str,
    ) -> FileScanReport {
        let detection = CoreDetection::new(
            rule,
            "a test detection",
            severity,
            DetectionSource::Signature,
        );
        FileScanReport {
            path: PathBuf::from(r"C:\Users\me\Downloads\invoice.exe"),
            kind: FileKind::Pe,
            size: 4096,
            digests: Digests::default(),
            assessment: Assessment {
                detections: vec![detection],
                score: severity.default_score(),
                verdict,
                ..Assessment::default()
            },
            duration: std::time::Duration::from_millis(3),
            scanned_bytes: 4096,
            from_cache: false,
            error: None,
            archive: None,
        }
    }

    /// A detection a message-round-trip test can use.
    pub(crate) fn sample_detection() -> Detection {
        Detection::from_report(
            &sample_report(Verdict::Malicious, Severity::High, "Trojan.Generic"),
            EntrySource::Scan,
            false,
            DetectionAction::Reported,
        )
    }

    #[test]
    fn a_component_that_blocks_nothing_cannot_produce_a_pre_execution_phase() {
        // The whole point of the module, as a differential. `EntrySource`
        // says realtime is pre-execution, and `av-realtime` is filed under
        // that name while blocking nothing. The same source with `blocked =
        // true` is the driver-backed case and must still come out
        // pre-execution, so the test distinguishes "derived" from
        // "always after-the-fact".
        assert_eq!(
            Phase::observed(EntrySource::Realtime, false),
            Phase::observed(EntrySource::Scan, false)
        );
        assert!(!Phase::observed(EntrySource::Realtime, false).claims_a_block());
        assert!(Phase::observed(EntrySource::Realtime, true).claims_a_block());
        // A full scan cannot claim a block whatever it does.
        assert!(!Phase::observed(EntrySource::Scan, true).claims_a_block());
        assert!(Phase::observed(EntrySource::Driver, true).claims_a_block());
    }

    #[test]
    fn the_vault_calls_realtime_pre_execution_and_this_derivation_does_not_follow_it_blindly() {
        // Pinned deliberately: this is the disagreement the derivation exists
        // to handle, and if `av-quarantine` ever changes its mind the
        // notification wording should be revisited rather than silently
        // following.
        assert!(
            EntrySource::Realtime.is_pre_execution(),
            "the vault classifies a realtime entry as blocked before execution"
        );
        assert_eq!(
            Phase::observed(EntrySource::Realtime, false).as_str(),
            "after-the-fact"
        );
    }

    #[test]
    fn a_detection_carries_the_engines_own_numbers_and_not_a_second_opinion() {
        let detection = Detection::from_report(
            &sample_report(Verdict::Malicious, Severity::Critical, "Trojan.A"),
            EntrySource::Scan,
            false,
            DetectionAction::Reported,
        );
        assert_eq!(detection.verdict, Verdict::Malicious);
        assert_eq!(detection.severity, Severity::Critical);
        assert_eq!(detection.score, Severity::Critical.default_score());
        assert_eq!(detection.rules, vec!["Trojan.A".to_string()]);
        assert_eq!(detection.size, 4096);
        assert_eq!(detection.file_name, "invoice.exe");
        // A detection with no family still has a name to show, and it is the
        // file's rather than an empty string.
        assert_eq!(detection.display_name(), "invoice.exe");
        assert!(!detection.is_contained());
        // And the sentence a log line gets never says blocked, because nothing
        // was.
        assert!(detection.to_string().contains("found after it appeared"));
        assert!(!detection.to_string().contains("was blocked before"));
    }

    #[test]
    fn a_quarantined_detection_says_the_file_is_gone_and_still_not_that_it_was_blocked() {
        let detection = Detection::from_report(
            &sample_report(Verdict::Malicious, Severity::High, "Trojan.A"),
            EntrySource::Realtime,
            false,
            DetectionAction::Quarantined {
                id: QuarantineId::new(),
            },
        );
        assert!(detection.is_contained());
        assert!(!detection.claims_a_block());
        assert_eq!(detection.action.as_str(), "quarantined");
        // The two facts a notification has to keep apart: the file is gone,
        // and it had a life before it was found.
        assert!(detection.is_contained());
        assert!(!detection.claims_a_block());
    }

    #[test]
    fn a_phase_survives_the_round_trip_as_a_readable_string() {
        // The wire form is what a `--json` consumer sees. `true` would be a
        // number whose meaning lives somewhere else, and the string is the same
        // one `as_str` returns so there is one list of spellings.
        for phase in [
            Phase::observed(EntrySource::Driver, true),
            Phase::observed(EntrySource::Realtime, false),
        ] {
            let json = serde_json::to_string(&phase).expect("serialises");
            assert_eq!(json, format!("\"{}\"", phase.as_str()));
            let back: Phase = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, phase);
        }
        // And a third spelling is refused rather than guessed at.
        assert!(serde_json::from_str::<Phase>("\"probably\"").is_err());
        assert!(serde_json::from_str::<Phase>("true").is_err());
    }

    #[test]
    fn a_detection_built_from_a_file_report_never_claims_a_process_was_terminated() {
        // The field is about a running program, and a file scan has not got
        // one. A detection that carried `true` here would tell a notification
        // to say a program was stopped that nothing had even looked at.
        let detection = Detection::from_report(
            &sample_report(Verdict::Malicious, Severity::High, "Trojan.A"),
            EntrySource::Scan,
            false,
            DetectionAction::Reported,
        );
        assert!(!detection.terminated);
        assert!(detection.in_process.is_none());

        // The two travel together on the wire, and an older peer that never
        // heard of the field is read as "no process was terminated" rather than
        // as a failure to deserialise.
        let json = serde_json::to_string(&detection).expect("serialises");
        assert!(json.contains("\"terminated\":false"), "{json}");
        let without: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let mut without = without.as_object().expect("an object").clone();
        without.remove("terminated");
        let back: Detection =
            serde_json::from_value(serde_json::Value::Object(without)).expect("deserialises");
        assert!(!back.terminated);
        assert_eq!(back, detection);
    }

    #[test]
    fn a_quarantine_listing_says_when_it_is_incomplete() {
        let whole = QuarantineListing {
            entries: Vec::new(),
            total: 4,
            omitted: 0,
        };
        assert!(!whole.is_truncated());
        let cut = QuarantineListing {
            entries: Vec::new(),
            total: 10_000,
            omitted: 9_996,
        };
        assert!(cut.is_truncated());
    }
}
