//! What this crate reports, and what it is allowed to claim.
//!
//! # The claim that must not be made
//!
//! A file watched from user mode is scanned *after* it is written. By the time
//! the scan starts, the bytes are on disk and any process that wanted to open
//! them could have. Nothing in this crate can prevent that: refusing a write
//! needs a filter driver in the kernel, which is a different crate's job, and
//! the configuration field that would turn on blocking
//! ([`RealtimeConfig::block_on_detect`](av_core::config::RealtimeConfig::block_on_detect))
//! is listed as unhonoured by [`crate::WatchPlan`] rather than silently ignored.
//!
//! So the message a user is shown must be "this file was found and is gone now"
//! and never "this file was blocked". Those are different promises, and a
//! product that makes the second one when it means the first teaches its users
//! to trust a protection that is not there — which is worse than the missed
//! detection, because it survives every future detection that does work.
//!
//! # Why the phase is derived instead of hardcoded
//!
//! The vault records which component acted, and
//! [`EntrySource::is_pre_execution`] is that component's own answer to "did you
//! stop it before it ran". For a realtime entry the answer is `true`, because
//! the enum's realtime means a minifilter blocking an open, not a user-mode
//! watcher noticing a write. This crate is the second thing and is filed under
//! the same word.
//!
//! [`Phase::observed`] therefore takes *both* facts — what the source says it is,
//! and whether anything was actually stopped — and reports pre-execution only
//! when both hold. Hardcoding [`Phase::AfterTheFact`] here would have been
//! correct today and wrong the moment a driver feeds this crate; deriving it from
//! a flag this crate sets to `false` keeps the difference visible at exactly one
//! call site.

use std::path::PathBuf;

use av_core::scan::FileScanReport;
use av_core::{Severity, ThreatName, Verdict};
use av_quarantine::{EntrySource, QuarantineId};

use crate::notify::FileAction;

/// When, relative to the file running, this crate saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The file was already on disk when it was scanned, and may already have
    /// been opened. Nothing was prevented.
    AfterTheFact,
    /// The file was stopped before anything could run it.
    PreExecution,
}

impl Phase {
    /// The phase to report for a file a component that was
    /// `source`-classified acted on, given whether it actually stopped the
    /// file.
    ///
    /// `blocked` is what makes this honest:
    /// [`EntrySource::Realtime`] reports
    /// [`is_pre_execution() == true`](EntrySource::is_pre_execution), and a
    /// user-mode watcher filing itself under that name while blocking nothing
    /// would produce a report claiming a block that never happened. Both
    /// conditions are required, so a component that says it is pre-execution
    /// and did not block lands on [`Phase::AfterTheFact`], where it belongs.
    pub const fn observed(source: EntrySource, blocked: bool) -> Self {
        if source.is_pre_execution() && blocked {
            Phase::PreExecution
        } else {
            Phase::AfterTheFact
        }
    }

    /// The word used in the user interface and in `--json` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Phase::AfterTheFact => "after-the-fact",
            Phase::PreExecution => "pre-execution",
        }
    }

    /// True when reporting this phase means claiming a file was stopped.
    ///
    /// The predicate a test asserts against, rather than a string comparison:
    /// the property that matters is "does this claim stop something", and it
    /// should stay checkable if the wording changes.
    pub const fn claims_a_block(self) -> bool {
        matches!(self, Phase::PreExecution)
    }
}

/// What the service does about a scan result.
///
/// Four outcomes rather than two, because "did it find something" and "did it
/// act" are different questions and a single boolean answer to both would either
/// delete on a weak match or leave a strong one in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Nothing fired. The scan is over.
    Ignore,
    /// Record it in the statistics and do not tell the user.
    ///
    /// Reserved for a file that could not be read at all
    /// ([`Verdict::Unknown`]). It is not [`Disposition::Ignore`] — the gap is
    /// counted and can be displayed — and it is deliberately not
    /// [`Disposition::Report`], because a locked system file, a file open in an
    /// editor and a password-protected archive all land here, and a popup for
    /// each is how a notification area gets ignored wholesale.
    Count,
    /// Surface it to the caller and leave the file alone.
    Report,
    /// Surface it and take the file into the vault.
    Quarantine,
}

/// Decide what to do about one scan result.
///
/// `act_on_detection` is whether this installation acts on a confirmed
/// detection at all — the configuration's `block_on_detect` on a platform that
/// honours it, or `false` for a watcher that is only observing. It is a
/// parameter and not a constant because the honest value here is `false` in a
/// user-mode build (see the module documentation) and a caller has to be able to
/// say so.
///
/// The interesting rows are the middle two:
///
/// * [`Verdict::Suspicious`] is *reported and not acted on*. The scoring model
///   in `av-core` puts a lone generic string rule at `Suspicious` precisely so
///   it is surfaced without being destructive; a realtime component that
///   deleted on `Suspicious` would delete on a single weak match, and the file
///   it deleted would be the user's, mid-download, with no way back but the
///   vault.
/// * [`Verdict::Unknown`] is *never* treated as clean and never acted on. "We
///   could not read it" is not evidence about the file, so destroying it would
///   be acting on nothing.
pub fn disposition(verdict: Verdict, act_on_detection: bool) -> Disposition {
    match verdict {
        Verdict::Clean => Disposition::Ignore,
        Verdict::Suspicious => Disposition::Report,
        Verdict::Malicious => {
            if act_on_detection {
                Disposition::Quarantine
            } else {
                Disposition::Report
            }
        }
        Verdict::Unknown => Disposition::Count,
    }
}

/// One detection the watcher produced.
///
/// Carries the honest [`Phase`] alongside the report's own numbers, so that
/// everything needed to word a notification correctly is in one place and the
/// wording cannot be reconstructed wrongly somewhere else.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Where the file was when it was scanned.
    pub path: PathBuf,
    /// When, relative to the file running, this was seen.
    pub phase: Phase,
    /// The verdict the engine reached.
    pub verdict: Verdict,
    /// The worst severity among the detections.
    pub severity: Severity,
    /// The family, when a rule named one.
    pub threat: Option<ThreatName>,
    /// The identifier of the rule or heuristic that fired.
    pub detection: Option<String>,
    /// Size in bytes at the time of the scan.
    pub size: u64,
    /// The event that led here, or `None` when the file was found by a re-scan
    /// of a tree rather than by an event naming it.
    pub action: Option<FileAction>,
    /// The vault entry, when the file was taken.
    pub quarantined: Option<QuarantineId>,
    /// Why it was not taken, when [`Disposition::Quarantine`] was chosen and the
    /// vault refused.
    ///
    /// A field rather than a log line: a malicious file that is still on disk is
    /// a fact the user has to be told, and a log line is not told to anyone.
    pub quarantine_error: Option<String>,
}

impl Finding {
    /// Take the reportable parts of a scan report.
    ///
    /// The severity, threat and detection are copied out of the report's own
    /// assessment rather than recomputed, for the reason
    /// [`QuarantineContext::from_report`](av_quarantine::QuarantineContext::from_report)
    /// gives: the report's numbers are the ones the user was shown, and a second
    /// derivation is a second answer.
    pub fn from_report(report: &FileScanReport, phase: Phase, action: Option<FileAction>) -> Self {
        let assessment = &report.assessment;
        let detection = assessment.detections.first().map(|d| {
            if d.rule_id.is_empty() {
                d.display_name()
            } else {
                d.rule_id.clone()
            }
        });
        Self {
            path: report.path.clone(),
            phase,
            verdict: report.verdict(),
            severity: assessment.max_severity().unwrap_or(Severity::High),
            threat: assessment.primary_threat().cloned(),
            detection,
            size: report.size,
            action,
            quarantined: None,
            quarantine_error: None,
        }
    }

    /// Record that the file was taken into the vault.
    #[must_use]
    pub fn with_quarantine(mut self, id: QuarantineId) -> Self {
        self.quarantined = Some(id);
        self
    }

    /// Record that taking the file into the vault failed.
    #[must_use]
    pub fn with_quarantine_error(mut self, reason: impl Into<String>) -> Self {
        self.quarantine_error = Some(reason.into());
        self
    }

    /// True when the file is no longer at [`Finding::path`].
    ///
    /// The only true thing this crate can say that resembles "handled". It is
    /// not the same as blocking: the file had a life before it was found.
    pub fn is_contained(&self) -> bool {
        self.quarantined.is_some()
    }

    /// The name to show: the threat family, or the file name.
    pub fn display_name(&self) -> String {
        match &self.threat {
            Some(threat) => threat.to_string(),
            None => self
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| self.path.display().to_string()),
        }
    }

    /// The sentence a notification or a log line should show.
    ///
    /// Every branch that reports [`Phase::AfterTheFact`] says so in words, and
    /// none of them contains the word "blocked" — because it did not block
    /// anything, and a user who is told otherwise will not go and check whether
    /// the file ran. The [`Phase::PreExecution`] branch exists for the day a
    /// driver feeds this crate; it is reachable only through
    /// [`Phase::observed`] with `blocked` true.
    pub fn message(&self) -> String {
        let name = self.display_name();
        let path = self.path.display();
        match (
            self.phase,
            self.quarantined.is_some(),
            &self.quarantine_error,
        ) {
            (Phase::PreExecution, _, _) => {
                format!("{name} was blocked before it could run ({path})")
            }
            (Phase::AfterTheFact, true, _) => format!(
                "{name} was found at {path} after it appeared there. It has been moved to \
                 quarantine, but it was not blocked first — it may already have been opened or run."
            ),
            (Phase::AfterTheFact, false, Some(reason)) => format!(
                "{name} was found at {path} after it appeared there, and could not be moved to \
                 quarantine ({reason}). The file is still in place and was not blocked first."
            ),
            (Phase::AfterTheFact, false, None) => format!(
                "{name} was found at {path} after it appeared there. The file has been left in \
                 place; nothing was blocked."
            ),
        }
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report that reached `verdict` with one detection of `severity`.
    ///
    /// Built by hand rather than by scanning, so the disposition table can be
    /// tested over every verdict without needing a file that produces it.
    fn report(verdict: Verdict, severity: Severity, rule: &str) -> FileScanReport {
        use av_core::scan::{Digests, FileKind};
        use av_core::{Assessment, Detection, DetectionSource};

        let detection = Detection::new(
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

    #[test]
    fn a_watcher_that_blocks_nothing_never_claims_pre_execution() {
        // The whole point of this module, as a differential. `EntrySource`
        // says realtime is pre-execution, and this crate is filed under that
        // name while blocking nothing. The same source with `blocked = true` is
        // the driver-backed case, and it must still come out pre-execution, so
        // the test distinguishes "derived" from "always after-the-fact".
        assert_eq!(
            Phase::observed(EntrySource::Realtime, false),
            Phase::AfterTheFact
        );
        assert!(!Phase::observed(EntrySource::Realtime, false).claims_a_block());
        assert_eq!(
            Phase::observed(EntrySource::Realtime, true),
            Phase::PreExecution
        );
        // And a full scan cannot claim a block whatever it does.
        assert_eq!(
            Phase::observed(EntrySource::Scan, true),
            Phase::AfterTheFact
        );
        assert_eq!(
            Phase::observed(EntrySource::Driver, true),
            Phase::PreExecution
        );
    }

    #[test]
    fn the_vault_calls_realtime_pre_execution_and_this_crate_does_not() {
        // Pinned deliberately: this is the disagreement the module exists to
        // handle, and if `av-quarantine` ever changes its mind the report
        // wording should be revisited rather than silently following.
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
    fn the_message_never_says_blocked_when_nothing_was_blocked() {
        let found = Finding::from_report(
            &report(Verdict::Malicious, Severity::High, "T.1"),
            Phase::AfterTheFact,
            Some(FileAction::Added),
        );
        for message in [
            found.message(),
            found
                .clone()
                .with_quarantine_error("access denied")
                .message(),
            found.clone().with_quarantine(QuarantineId::new()).message(),
        ] {
            // The claim that must not be made is "we blocked it", so the phrase
            // checked for is the pre-execution one and not the bare word — the
            // after-the-fact branches say "was not blocked" and "nothing was
            // blocked", which are the denial rather than the claim.
            assert!(
                !message.contains("was blocked before it could run"),
                "a report about a non-blocking watcher claimed a block: {message}"
            );
            assert!(
                message.contains("after it appeared"),
                "a report did not say the file was found after it appeared: {message}"
            );
        }
        // The pre-execution branch is the only one that may say it.
        let blocked = Finding::from_report(
            &report(Verdict::Malicious, Severity::High, "T.1"),
            Phase::PreExecution,
            None,
        );
        assert!(blocked
            .message()
            .contains("was blocked before it could run"));
    }

    #[test]
    fn a_quarantined_finding_says_where_the_file_went_and_what_it_cost() {
        let finding = Finding::from_report(
            &report(Verdict::Malicious, Severity::Critical, "Trojan.Generic"),
            Phase::AfterTheFact,
            Some(FileAction::RenamedNewName),
        );
        assert!(!finding.is_contained());
        let contained = finding.clone().with_quarantine(QuarantineId::new());
        assert!(contained.is_contained());
        let message = contained.message();
        assert!(message.contains("moved to quarantine"));
        assert!(message.contains("was not blocked first"), "{message}");
        // The path is in the message, because "which file" is the first thing a
        // user asks and the second thing a log needs.
        assert!(message.contains("invoice.exe"));
    }

    #[test]
    fn a_vault_that_refuses_leaves_a_report_that_says_the_file_is_still_there() {
        let finding = Finding::from_report(
            &report(Verdict::Malicious, Severity::High, "T.1"),
            Phase::AfterTheFact,
            None,
        )
        .with_quarantine_error("the vault is full");
        assert!(!finding.is_contained());
        let message = finding.message();
        assert!(message.contains("still in place"), "{message}");
        assert!(message.contains("the vault is full"), "{message}");
    }

    #[test]
    fn the_disposition_table_acts_on_confirmed_only() {
        assert_eq!(disposition(Verdict::Clean, true), Disposition::Ignore);
        // Suspicious is surfaced and never acted on, whatever the switch says:
        // the scoring model put it there precisely so it would not be.
        assert_eq!(disposition(Verdict::Suspicious, true), Disposition::Report);
        assert_eq!(disposition(Verdict::Suspicious, false), Disposition::Report);
        assert_eq!(
            disposition(Verdict::Malicious, true),
            Disposition::Quarantine
        );
        assert_eq!(disposition(Verdict::Malicious, false), Disposition::Report);
        // Unreadable is counted, never ignored and never deleted.
        assert_eq!(disposition(Verdict::Unknown, true), Disposition::Count);
        assert_eq!(disposition(Verdict::Unknown, false), Disposition::Count);
    }

    #[test]
    fn a_finding_carries_the_engines_own_numbers_and_not_a_second_opinion() {
        let finding = Finding::from_report(
            &report(Verdict::Malicious, Severity::Critical, "Trojan.A"),
            Phase::AfterTheFact,
            None,
        );
        assert_eq!(finding.verdict, Verdict::Malicious);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.detection.as_deref(), Some("Trojan.A"));
        assert_eq!(finding.size, 4096);
        // A detection with no family still has a name to show, and it is the
        // file's rather than an empty string.
        assert_eq!(finding.display_name(), "invoice.exe");
    }
}
