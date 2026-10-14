//! The scan engine: a rule set and a file become a verdict.
//!
//! # What a scan produces, and what it refuses to produce
//!
//! A [`av_core::FileScanReport`] holding digests, a file kind, an ordered list of
//! [`av_core::Detection`]s, and a three-band [`av_core::Verdict`]:
//!
//! | Band | Meaning | What a caller does |
//! |---|---|---|
//! | `Clean` | Nothing worth saying | nothing |
//! | `Suspicious` | Enough to mention, not enough to act on | notify, never touch the file |
//! | `Malicious` | The evidence is decisive or the score crossed the line | remediate |
//! | `Unknown` | The file could not be looked at properly | say so; do not call it clean |
//!
//! The middle band is the point of the whole design. A packer, a high-entropy
//! section, an import table that can inject code: each is worth something and
//! none is worth acting on, and a scanner with only two bands has to choose
//! between ignoring them and deleting files over them. The thresholds are
//! [`av_core::VerdictThresholds`] and this crate never second-guesses them.
//!
//! # What this crate does not do
//!
//! It does not act. No file is quarantined, deleted, blocked or renamed here.
//! A scan is a question and a report is an answer; the decision belongs to the
//! layer that knows whether the user asked for a full scan or a file-open
//! interceptor, because those two want opposite things from the same verdict.
//!
//! # The stages
//!
//! | Module | Answers |
//! |---|---|
//! | [`kind`] | What sort of file is this? |
//! | [`blocklist`] | Is this file one the rule set already knows by content? |
//! | [`rules`] | Which rules matched, and what are they worth? |
//! | [`heuristics`] | What does the file's structure say about it? |
//! | [`archive`] | What is inside it, if it is a container? |
//! | [`trust`] | What argues in the file's favour? |
//! | [`engine`] | In what order, and what does it add up to? |
//!
//! # Every stage is additive except the last
//!
//! Detections accumulate. Nothing sets a verdict by itself and nothing
//! overwrites anything else: a decisive detection short-circuits the
//! comparison, and one trust result subtracts a bounded amount, and other than
//! those two everything is a term in a sum. That is what makes a verdict
//! explainable: a user asking "why is this red" gets the list, and the list is
//! the reason.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod archive;
pub mod blocklist;
pub mod engine;
pub mod heuristics;
pub mod kind;
pub mod own;
pub mod rules;
pub mod trust;

pub use blocklist::{BlockHit, Blocklist};
pub use engine::{DigestPolicy, ScanEngine};
pub use heuristics::HeuristicConfig;
pub use kind::{classify, refine};
pub use own::OwnFiles;
pub use trust::{TrustAssessment, TrustPolicy, TrustReason};

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{ScanOptions, Verdict};

    /// The crate's own contract, exercised through the public API only: a
    /// buffer in, a verdict out, and the middle band reachable.
    #[test]
    fn the_public_surface_is_enough_to_scan_and_get_a_band() {
        let (database, report) = av_rules::database::RuleDatabase::compile(
            r#"
rule packer_shaped {
    meta:
        severity = "medium"
    strings:
        $a = "WENLE-BAND-CHECK"
        $b = "WENLE-BAND-CHECK-TWO"
    condition:
        all of them
}
"#,
        );
        assert_eq!(report.refusals.len(), 0, "{:?}", report.refusals);

        let engine = ScanEngine::new(database);
        let options = ScanOptions {
            heuristics: false,
            trust: false,
            ..ScanOptions::default()
        };

        let clean = engine.scan_bytes(
            std::path::Path::new("C:\\band\\clean.bin"),
            b"nothing",
            &options,
        );
        assert_eq!(clean.verdict(), Verdict::Clean);

        let suspicious = engine.scan_bytes(
            std::path::Path::new("C:\\band\\maybe.bin"),
            b"WENLE-BAND-CHECK..WENLE-BAND-CHECK-TWO",
            &options,
        );
        assert_eq!(suspicious.verdict(), Verdict::Suspicious);
        // And the crate offers no way to act on it, which is the point: the
        // report is data, and a caller that acts on a yellow band is a caller
        // that decided to.
        assert!(suspicious.is_detection());
        assert_eq!(suspicious.assessment.score, 60);
    }

    #[test]
    fn the_re_exports_name_the_types_the_documentation_promises() {
        // A cheap guard against a re-export being dropped in a refactor: the
        // crate documentation and the engine's own signatures both name these.
        let _: Option<DigestPolicy> = Some(DigestPolicy::Needed);
        let _: Option<HeuristicConfig> = Some(HeuristicConfig::default());
        let _: Option<TrustPolicy> = Some(TrustPolicy::default());
        let _: Option<Blocklist> = Some(Blocklist::default());
        let _ = classify(None, b"");
        let _ = TrustReason::Unsigned.magnitude();
    }
}
