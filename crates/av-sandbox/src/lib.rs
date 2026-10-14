//! What a sample *would* do, judged from its structure, without running it.
//!
//! # Why this is rules and not a sandbox
//!
//! A real sandbox runs a sample in a contained machine and watches what it
//! touches. Building one is a project of its own, and the decision taken for
//! this product was to write the rules and leave the containment for later. What
//! is here is the *judgement* half, the part that decides whether a sample's
//! observed or declared behaviour is malicious. It is built so that the
//! containment half can be added underneath it without changing any of it.
//!
//! **Nothing in this crate executes anything, and nothing in it may.** That is
//! not a limitation to be worked around later; it is the property that makes it
//! shippable today. It reads a file's headers, imports, sections and resources,
//! and answers what that structure implies.
//!
//! # Disabled by default, and what that means
//!
//! [`av_core::config::SandboxConfig`] carries the switch, and it is off. An
//! unconfigured product must not behave differently from a configured one in a
//! way the user did not ask for, so the entry point takes the configuration and
//! returns nothing at all when it is disabled. It does not return an empty
//! verdict, which would be indistinguishable from "I looked and found nothing".
//! It returns no findings and a report that says it did not run.
//!
//! Of that configuration's fields, only `enabled` is a question this crate can
//! answer. The rest describe a *run* (a timeout, a memory ceiling, a network
//! policy, a scratch filesystem) and nothing here runs.
//!
//! # What the rules are about
//!
//! Each rule is one behaviour a sample's structure implies it will perform, and
//! the score it carries is the [`av_core::Severity`] every other detection in
//! this product carries. A sandbox finding is therefore banded by exactly the
//! same thresholds as a signature match, and a middle-band result notifies
//! without acting. The rules are about behaviour rather than identity: a sample
//! whose bytes match nothing in the rule database still has to do *something*,
//! and that something is much harder to change than a hash.
//!
//! The crate does not decide a verdict. It reports findings and leaves the
//! scoring, the trust adjustment and the thresholds to the caller, which is the
//! same path every other detection in the product takes: see
//! [`Report::push_into`].
//!
//! # The false-positive corpus
//!
//! A behaviour rule is cheap to write and expensive to be wrong about, so every
//! rule in this crate was measured against the machine's own software before it
//! was written: every `*.dll` and `*.exe` in `C:\Windows\System32`, 4,000 PE
//! files, scanned with a throwaway probe, then again through the crate itself by
//! the `#[ignore]`d test in `crate::rules`. `System32` is not a malware corpus.
//! It is the hardest available *false-positive* corpus, a few thousand unrelated
//! programs written by thousands of people over thirty years. A rule that cannot
//! survive it will not survive a user's `Program Files` either.
//!
//! The number of the 4,000 files that satisfy each rule:
//!
//! | Rule | Fires on |
//! |------|----------|
//! | `sandbox/evasion/security-service-reconfigure` | 0 |
//! | `sandbox/evasion/lotl-encoded-command` | 0 |
//! | `sandbox/evasion/entry-point-outside-sections` | 0 |
//! | `sandbox/dropper/appended-image` | 0 |
//! | `sandbox/credential/lsass-dump` | 0 |
//! | `sandbox/anti-analysis/analysis-tool-artefact` | 0 |
//! | `sandbox/impact/backup-destruction` | 0 |
//! | `sandbox/lateral-movement/remote-share-service` | 0 |
//!
//! Eight zeroes are not evidence by themselves: a rule that fires on nothing at
//! all would print the same row. What makes them mean something is the second
//! table, the forms each rule was **narrowed away from**, with the count that
//! killed them. Every one of these fires on ordinary Windows binaries, and the
//! labels are the ones the `#[ignore]`d measurement prints, so a run on this
//! machine can be read against this table line by line:
//!
//! | Form | Fires on |
//! |------|----------|
//! | service APIs plus a security product's service name | 3 |
//! | service APIs plus a registry write | 224 |
//! | service APIs plus a user-writable path | 32 |
//! | a registry write plus a Run key | 39 |
//! | …and a path under the user's profile | 11 |
//! | …the same form, single-byte spelling only | 1 |
//! | a registry write plus Image File Execution Options | 32 |
//! | a registry write plus `AppInit_DLLs` | 4 |
//! | a registry write plus the name `userinit` | 42 |
//! | `TerminateProcess` plus three security service names | 3 |
//! | a process dump import without the store's name | 4 |
//! | writing into a process and starting a thread there | 4 |
//! | unmapping a process and writing into it | 2 |
//! | …and starting one as well | 2 |
//! | a keyboard hook and the key state | 1 |
//! | a write plus the hosts file | 2 |
//! | a write plus the Startup directory | 7 |
//! | a process plus `schtasks /create` | 2 |
//! | a process plus `netsh advfirewall` | 2 |
//! | `IsDebuggerPresent` | 2,651 |
//! | `QueryPerformanceCounter` | 3,499 |
//! | both timing APIs | 2,638 |
//! | `Sleep` | 2,239 |
//! | locates, deletes and schedules its own removal | 160 |
//! | the debugger window class `gdbg` | 6 |
//! | a share name (`admin$`) | 11 |
//! | two hidden-command idioms | 4 |
//! | one analysis-product name | 1 |
//! | crypto, walk, delete plus four shadow-copy commands | 1 |
//! | an image in a resource | 1 |
//!
//! The named counterexamples matter as much as the counts, because they are what
//! a rule would have been *wrong* about. The Run-key rows are
//! `OneDriveSetup.exe`, which installs a per-user service out of
//! `%LocalAppData%` by design, together with `AcLayers.dll`, `advpack.dll` and
//! `cmstp.exe`, which are the shim and installation machinery that writes
//! startup entries on behalf of whatever is being installed. The service rows
//! are `advapi32.dll`, which is the code that implements the APIs whose names it
//! contains, and `AcGenral.dll` and `acmigration.dll`, which apply compatibility
//! settings to services. The dump row is `WerFault.exe` and `WerFaultSecure.exe`,
//! Windows' own crash reporters, which import the memory-dump API and have no
//! business naming `lsass`. The hosts row is `dnsapi.dll` and `dnsrslvr.dll`,
//! the DNS client itself. The debugger-window-class row is six files that
//! contain `gdbg` inside a longer name (`dbgeng.dll`, `kdnet.dll` and `MRT.exe`
//! among them), and the resource row is `MRT.exe`, Microsoft's Malicious
//! Software Removal Tool, whose oldest resource really is a second executable.
//! A rule that flags a crash reporter, an installer or the operating system's
//! own API library is worse than no rule, because it teaches the user to ignore
//! the report.
//!
//! Four of the measurements above are worth reading before adding a rule. The
//! timing one is the clearest. It is the classic static heuristic for a sandbox
//! detector, a sample that checks how fast it is running, and it cannot be
//! written at all from the structure, because the APIs it would key on are
//! imported by most of the operating system. `QueryPerformanceCounter` alone is
//! imported by 3,499 of the 4,000 files, which is 87% of `System32`, and asking
//! for it *together with* `IsDebuggerPresent` still leaves 2,638. The rule that
//! was *not* written is the one that would have flagged two thirds of the
//! operating system. The second is the service chain: the service APIs together
//! with a registry write fire on 224 files, and only the *name* of a security
//! product's own service takes that to three and then, with the API list
//! narrowed to the two calls that install or change a service, to zero. The
//! third is the pair of behaviours that cannot be written at all: `Sleep` is in
//! 2,239 files and self-removal in 160, and neither count says anything about
//! *order*. A sample that waits before it acts and one that waits after it acts
//! have the same import table. That ordering is the thing the deferred sandbox
//! would answer and this crate refuses to guess. The fourth is the one that
//! *became* a rule: of everything in the headers, the entry point outside every
//! section was the single measurement that came out at zero for a reason a human
//! can state.
//!
//! # What is not judged
//!
//! `av-pe` exposes more than the rules use, and each unused part was measured
//! before being left out rather than assumed harmless:
//!
//! * **The entry point.** 400 of the 4,000 files declare an entry point of
//!   **zero** (one in ten, which is how a library with nothing to initialise is
//!   built) and **0** declare one outside every section. That zero is a rule
//!   (`sandbox/evasion/entry-point-outside-sections`, in the private
//!   `rules` table), and the
//!   400 are the reason it excludes zero explicitly rather than asking the
//!   section question on its own.
//! * **`DllCharacteristics`.** 6 files opt into neither ASLR nor DEP, 6 opt out
//!   of ASLR and 10 out of DEP. A rule built on a missing mitigation would be a
//!   rule about six files, and those six are shipped by Microsoft: opting out is
//!   a decision a linker makes for a program that manages its own memory, not a
//!   property of malware, and the population is far too small to band a file on.
//! * **TLS callbacks and delay-loaded imports.** `av-pe` reads the directory
//!   *table* and not the tables those entries point at, so the only question it
//!   can answer is "is the directory declared", and 1,164 files declare a TLS
//!   directory and 1,948 a delay-load one, between a quarter and a half of the
//!   corpus in both cases. Windows' own binaries declare these for their own
//!   reasons (a library with thread-local state, a program that may not need the
//!   library it links against), so the answer is worth nothing as evidence. What
//!   a rule would want to ask, is there a TLS *callback* that runs before the
//!   entry point, is not a question this parser can answer, and the count is why
//!   nobody tried to approximate it.
//!
//! # Example
//!
//! ```no_run
//! use av_core::config::SandboxConfig;
//! use av_core::{Assessment, VerdictThresholds};
//! use av_sandbox::{evaluate, Judgement};
//!
//! let config = SandboxConfig::default(); // disabled
//! let data = std::fs::read("suspect.exe").unwrap_or_default();
//! match evaluate(&data, &config) {
//!     Judgement::NotRun(reason) => {
//!         // Nothing was looked at, and the reason is reportable.
//!         eprintln!("sandbox rules did not run: {reason}");
//!     }
//!     Judgement::Ran(report) => {
//!         // The findings join the scan's own detections and are banded with
//!         // them, by the scan's thresholds rather than by any of this crate's.
//!         let mut assessment = Assessment::clean();
//!         report.push_into(&mut assessment);
//!         assessment.finalize(&VerdictThresholds::default());
//!         for finding in report.findings() {
//!             eprintln!("{}: {}", finding.rule_id, finding.description);
//!         }
//!         eprintln!("verdict: {}", assessment.verdict);
//!     }
//! }
//! ```
//!
//! # Nothing here runs, and the shape of the crate says so
//!
//! There is no `Result` in the public API and no error type, because nothing
//! this crate does can fail in a way a caller could act on. The only two ways to
//! get nowhere, the sandbox being off or the bytes not being a PE image, are
//! [`Judgement::NotRun`] outcomes, and the reason is a [`NotRunReason`] rather
//! than an error string. A rule condition is a predicate over structure, and a
//! malformed file makes predicates false rather than making them fail.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod evidence;
mod rule;
mod rules;
mod text;

use std::fmt;

use av_core::config::SandboxConfig;
use av_core::{Assessment, Detection, Severity};
use serde::{Deserialize, Serialize};

pub use crate::evidence::{EmbeddedImages, Evidence, TextMatch};
pub use crate::rule::{Rule, Trigger};
pub use crate::rules::RULES;

/// Judge a sample's structure without running it.
///
/// Returns [`Judgement::NotRun`] when the sandbox is disabled — the common case,
/// since it is off by default — and when the bytes are not a PE image. Returns
/// [`Judgement::Ran`] otherwise, with one finding per rule the sample satisfies.
///
/// Costs one parse of the sample's headers, one import walk, one resource walk,
/// and one linear scan of the buffer per rule that gets past its import
/// conditions. Allocates a finding per rule that fires and nothing per rule that
/// does not.
pub fn evaluate(data: &[u8], config: &SandboxConfig) -> Judgement {
    if !config.enabled {
        return Judgement::NotRun(NotRunReason::Disabled);
    }
    let Some(evidence) = Evidence::parse(data) else {
        return Judgement::NotRun(NotRunReason::NotPe);
    };
    let mut findings = Vec::new();
    for rule in RULES {
        if let Some(detection) = rule.evaluate(&evidence) {
            findings.push(detection);
        }
    }
    Judgement::Ran(Report { findings })
}

/// Whether the rules ran, and what they found if they did.
///
/// The two outcomes are deliberately not collapsed into one: an empty list of
/// findings from a disabled sandbox and an empty list from a clean file are
/// different answers to "why did you not flag this?", and a report that could
/// not tell them apart would be lying to the user in one of the two cases.
#[derive(Debug, Clone, PartialEq)]
pub enum Judgement {
    /// No rule looked at anything.
    NotRun(NotRunReason),
    /// Every rule was evaluated. The report may still be empty.
    Ran(Report),
}

impl Judgement {
    /// The findings, when the rules ran; nothing when they did not.
    ///
    /// For callers that only want the detections. A caller that needs to
    /// distinguish "did not run" from "ran and found nothing" must match on the
    /// variant instead, which is the point of it being an enum.
    pub fn findings(&self) -> &[Detection] {
        match self {
            Judgement::NotRun(_) => &[],
            Judgement::Ran(report) => report.findings(),
        }
    }

    /// Whether the rules ran at all.
    pub fn ran(&self) -> bool {
        matches!(self, Judgement::Ran(_))
    }
}

impl fmt::Display for Judgement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Judgement::NotRun(reason) => write!(f, "sandbox rules did not run: {reason}"),
            Judgement::Ran(report) => write!(
                f,
                "sandbox rules ran: {} finding(s), highest severity {}",
                report.len(),
                report
                    .severity()
                    .map_or("none".to_string(), |s| s.as_str().to_string()),
            ),
        }
    }
}

/// Why no rule was evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotRunReason {
    /// [`av_core::config::SandboxConfig::enabled`] is `false`.
    Disabled,
    /// The configuration is on, but the bytes are not a PE image.
    ///
    /// Every rule in this crate reads PE structure, so none of them had
    /// anything to read. Distinct from an empty [`Report`] for the same reason
    /// [`Judgement`] is an enum: "this format is not something these rules can
    /// judge" and "these rules judged it and found nothing" are different
    /// statements, and only the second one is a clean bill of health.
    NotPe,
}

impl fmt::Display for NotRunReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NotRunReason::Disabled => "the sandbox is disabled",
            NotRunReason::NotPe => "the sample is not a PE image",
        })
    }
}

/// What the rules found in one sample.
///
/// The findings are [`av_core::Detection`]s like any other — same severity
/// ladder, same score, same report shape — which is what lets the caller feed
/// them into the same accumulator as everything else and get one verdict rather
/// than a sandbox verdict bolted onto a scan verdict.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// One finding per rule the sample satisfied, in the order the rules are
    /// listed in [`RULES`].
    findings: Vec<Detection>,
}

impl Report {
    /// The findings.
    pub fn findings(&self) -> &[Detection] {
        &self.findings
    }

    /// How many rules fired.
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Whether no rule fired.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// The highest severity among the findings.
    pub fn severity(&self) -> Option<Severity> {
        self.findings.iter().map(|finding| finding.severity).max()
    }

    /// The identifiers of the rules that fired.
    pub fn rule_ids(&self) -> impl Iterator<Item = &str> {
        self.findings.iter().map(|finding| finding.rule_id.as_str())
    }

    /// Add every finding to the caller's accumulator.
    ///
    /// This is how a finding joins the rest of the scan: the caller pushes them
    /// into the same [`Assessment`] as its signature and heuristic detections
    /// and finalizes once, so a sample that trips one behaviour rule at
    /// [`Severity::Low`] and one signature rule at [`Severity::Medium`] is
    /// banded on their sum rather than twice on each.
    ///
    /// The caller's thresholds, not this crate's, decide the outcome: nothing
    /// here calls [`Assessment::finalize`], because the thresholds belong to the
    /// scan configuration and a crate that finalized its own findings would
    /// invent a second verdict to reconcile with the real one.
    pub fn push_into(&self, assessment: &mut Assessment) {
        for finding in &self.findings {
            assessment.push(finding.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{DetectionSource, Verdict, VerdictThresholds};
    use av_pe::testing::{add_imports, minimal_pe32};

    /// A sample with the imports for one behaviour, and nothing else.
    fn sample(libraries: &[(&str, &[&str])]) -> Vec<u8> {
        let mut pe = minimal_pe32();
        add_imports(&mut pe, libraries);
        pe
    }

    #[test]
    fn a_disabled_sandbox_reads_nothing_and_says_so() {
        let config = SandboxConfig {
            enabled: false,
            ..SandboxConfig::default()
        };
        // Even a sample that would trip several rules.
        let data = sample(&[(
            "advapi32.dll",
            &["OpenSCManagerW", "CreateServiceW", "RegSetValueExW"],
        )]);
        let judgement = evaluate(&data, &config);
        assert_eq!(judgement, Judgement::NotRun(NotRunReason::Disabled));
        assert!(!judgement.ran());
        assert!(judgement.findings().is_empty());
        // And it says so in words, for a log line.
        assert!(judgement.to_string().contains("disabled"));
    }

    #[test]
    fn a_disabled_sandbox_is_not_reported_as_a_clean_scan() {
        // The distinction the whole outcome type exists for. A caller that
        // treated "no findings" as "clean" would report every file as clean
        // while the sandbox is off, which is the default.
        let config = SandboxConfig::default();
        assert!(!config.enabled, "the sandbox must be off by default");
        let judgement = evaluate(b"MZ", &config);
        assert_ne!(judgement, Judgement::Ran(Report::default()));
        assert!(!matches!(judgement, Judgement::Ran(_)));
    }

    #[test]
    fn the_shipped_configuration_cannot_reach_these_rules() {
        // The standing constraint on this crate: the rules are built and the
        // sandbox stays off. This asserts it against the *product's* default
        // configuration rather than against this crate's own idea of it, so a
        // change anywhere in `av-core` that turned the sandbox on by default
        // fails here rather than in a user's scan.
        let config = av_core::AvConfig::default();
        assert!(
            !config.sandbox.enabled,
            "the sandbox must stay off in the shipped configuration"
        );
        let data = sample(&[
            (
                "advapi32.dll",
                &["OpenSCManagerW", "CreateServiceW", "RegSetValueExW"],
            ),
            ("kernel32.dll", &["CreateProcessW"]),
            ("dbghelp.dll", &["MiniDumpWriteDump"]),
        ]);
        assert_eq!(
            evaluate(&data, &config.sandbox),
            Judgement::NotRun(NotRunReason::Disabled),
            "nothing in the default path may reach a rule"
        );
    }

    #[test]
    fn an_enabled_sandbox_that_finds_nothing_ran() {
        let config = SandboxConfig {
            enabled: true,
            ..SandboxConfig::default()
        };
        let data = minimal_pe32();
        let judgement = evaluate(&data, &config);
        match &judgement {
            Judgement::Ran(report) => {
                assert!(report.is_empty());
                assert_eq!(report.severity(), None);
                assert_eq!(report.rule_ids().count(), 0);
            }
            Judgement::NotRun(reason) => panic!("should have run: {reason}"),
        }
        assert!(judgement.to_string().contains("ran"));
    }

    #[test]
    fn a_non_pe_is_not_a_clean_scan_either() {
        let config = SandboxConfig {
            enabled: true,
            ..SandboxConfig::default()
        };
        assert_eq!(
            evaluate(b"#!/bin/sh\necho hi\n", &config),
            Judgement::NotRun(NotRunReason::NotPe)
        );
        assert_eq!(
            evaluate(&[], &config),
            Judgement::NotRun(NotRunReason::NotPe)
        );
    }

    #[test]
    fn findings_score_and_band_like_every_other_detection() {
        let config = SandboxConfig {
            enabled: true,
            ..SandboxConfig::default()
        };
        // Two Medium behaviours: the sandbox on its own, in a sample that is
        // not otherwise suspicious, reaches the band that acts.
        let data = sample(&[
            (
                "advapi32.dll",
                &["OpenSCManagerW", "CreateServiceW", "RegSetValueExW"],
            ),
            ("kernel32.dll", &["CreateProcessW", "TerminateProcess"]),
        ]);
        let judgement = evaluate(&data, &config);
        let report = match judgement {
            Judgement::Ran(report) => report,
            Judgement::NotRun(reason) => panic!("should have run: {reason}"),
        };

        let mut assessment = Assessment::clean();
        report.push_into(&mut assessment);
        let before = assessment.score;
        assessment.finalize(&VerdictThresholds::default());
        assert_eq!(assessment.score, before, "finalize must not rescore");
        for finding in report.findings() {
            assert_eq!(finding.source, DetectionSource::Behavior);
            assert!(!finding.decisive);
        }
        // Whatever it found, the band is the ordinary band for that score.
        assert_eq!(
            assessment.verdict,
            VerdictThresholds::default().classify(assessment.score)
        );
        assert_ne!(assessment.verdict, Verdict::Unknown);
    }

    #[test]
    fn a_report_is_serialisable_so_it_can_be_logged() {
        let report = Report::default();
        let json = serde_json::to_string(&report).expect("serialises");
        assert_eq!(json, r#"{"findings":[]}"#);
        let back: Report = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
    }
}
