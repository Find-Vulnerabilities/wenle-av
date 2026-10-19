//! Behaviour rules: a TOML rule language over the events the driver reports,
//! evaluated on a sliding window.
//!
//! # What this crate is for
//!
//! `av-rules` decides what a **file** is, by looking at its bytes. That answers
//! "is this program known-bad or structurally suspicious", and it cannot answer
//! *"what is this program doing"* — a renamed document, a value written under
//! `Run`, `winword.exe` starting `cmd.exe`. The driver was taught to report
//! those as three ordinary telemetry streams in October 2026 (file renames and
//! deletes, process lineage, registry changes), and this crate is what reads
//! them.
//!
//! The rule language is not YARA and is deliberately not byte-oriented: see
//! [`dsl`] for why. It is a table of predicates over an event's own fields, and
//! a [`RuleSet`] is a TOML document.
//!
//! | Module | What it holds |
//! |---|---|
//! | [`dsl`] | the language: [`Rule`], [`RuleSet`], and the validation that refuses a rule that could never fire |
//! | [`event`] | [`Record`], the engine's smaller copy of a driver event |
//! | [`engine`] | [`Engine`]: per-(rule, process) sliding windows and the lineage table |
//! | [`error`] | [`LoadError`] |
//!
//! # Every shipped rule is in the warning band
//!
//! A finding from this engine is **evidence, not a verdict**. Every rule in
//! [`RULES_TOML`] scores below [`av_core::VerdictThresholds::default`]'s
//! malicious threshold *on its own*, so no single behaviour event can quarantine
//! or delete anything — a rule firing adds to a score, and only a score that
//! crosses the threshold the rest of the product already uses can act. That is a
//! policy choice with a measurement behind it: a behaviour rule that convicts on
//! its own is a rule whose one measurement (this name, this count, this parent)
//! is treated as if it were a file's contents, and the difference between those
//! two kinds of evidence is the whole reason `av-rules` exists separately.
//!
//! `every_shipped_rule_is_in_the_warning_band` in this file is that policy as a
//! test.
//!
//! # Where it is wired in
//!
//! `av_service::host::Host::drain_driver`: every driver event that is not a
//! connection report is handed to [`Engine::observe_driver`] at the **top** of
//! that loop, before the arms that log it and route it, because several of those
//! arms `continue` — and a process start in particular teaches the engine who
//! started whom and then leaves through one of them. A returned [`Finding`] is
//! published as a [`av_ipc::Detection`] with [`av_ipc::DetectionAction::Reported`],
//! and only in the warning band.
//!
//! The order of work is the reason this note exists: the driver's three
//! telemetry streams were verified on a virtual machine first, and this crate is
//! written against what those streams were measured to contain. Connecting it
//! before that verification would have meant debugging a rule and a driver at
//! the same time.
//!
//! # Exclusions are a predicate, not a lower count
//!
//! [`Rule::path_excludes`] disqualifies a path that Windows churns by design —
//! measured: `svchost.exe` deleting keys under `\REGISTRY\A\{…}` fired the mass
//! key-delete rule on a healthy machine. Raising `count` would have let a real
//! sweep hide under the noise; an exclusion cannot make a rule match anything,
//! so it can only narrow.
//!
//! # Loading
//!
//! ```
//! let engine = av_behaviour::builtin().expect("the shipped rules parse");
//! assert!(engine.rules().len() >= 30);
//! ```
//!
//! [`av_ipc::Detection`]: av_ipc::Detection

#![forbid(unsafe_code)]
// Unwrapping is how a test asserts. The same exception every crate in the
// workspace makes, and only under `cfg(test)`: the engine itself returns
// `Result` and never panics on a rule file.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod dsl;
mod engine;
mod error;
mod event;

pub use dsl::{Action, Detail, Rule, RuleSet, Subject};
pub use engine::{Engine, Finding, TICKS_PER_SECOND};
pub use error::LoadError;
pub use event::Record;

/// The rules shipped with the product, embedded in the binary.
///
/// Embedded rather than read from disk for the reason the detection rules are
/// not read from a user-writable directory: a file that decides what is
/// suspicious is a file an attacker would like to edit, and an embedded copy
/// cannot be. (The detection rules' larger corpus is on disk because it is
/// forty thousand lines and updatable; these are forty.)
pub const RULES_TOML: &str = include_str!("rules.toml");

/// An engine over [`RULES_TOML`].
pub fn builtin() -> Result<Engine, LoadError> {
    Engine::from_toml(RULES_TOML)
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::VerdictThresholds;

    #[test]
    fn the_shipped_rules_parse() {
        let engine = builtin().expect("the shipped rule file parses and validates");
        assert!(engine.rules().len() >= 30, "the rule set shrank");
    }

    #[test]
    fn every_shipped_rule_is_in_the_warning_band() {
        // The policy from this module's header, as a test: no behaviour rule may
        // reach the malicious threshold by itself. `VerdictThresholds::classify`
        // is the same function the product uses, so this cannot drift from it.
        let thresholds = VerdictThresholds::default();
        let engine = builtin().expect("the shipped rules parse");
        for rule in engine.rules() {
            assert!(
                rule.score() < thresholds.malicious,
                "{} ({}) scores {}, which reaches the malicious threshold by \
                 itself; a behaviour rule must be evidence, not a verdict",
                rule.id,
                rule.name,
                rule.score()
            );
        }
    }

    #[test]
    fn every_shipped_rule_says_what_it_would_mean() {
        let engine = builtin().expect("the shipped rules parse");
        for rule in engine.rules() {
            assert!(
                rule.id.starts_with("BEH-"),
                "{} does not use the behaviour id prefix",
                rule.id
            );
            assert!(!rule.name.trim().is_empty(), "{} has no name", rule.id);
            assert!(
                rule.description.ends_with('.'),
                "{}'s description is not a sentence, so it will read badly in a \
                 warning: {:?}",
                rule.id,
                rule.description
            );
        }
    }

    #[test]
    fn the_shipped_rules_use_every_stream_the_driver_was_taught() {
        // If a whole telemetry stream has no rule, the increment that added it
        // is not being used — which is worth a failing test rather than a
        // paragraph in a report.
        let engine = builtin().expect("the shipped rules parse");
        let rules = engine.rules();
        for (what, wanted) in [
            ("a file rename rule", Action::FileRenamed),
            ("a file delete rule", Action::FileDeleted),
            ("a process start rule", Action::ProcessStarted),
            ("a registry rule", Action::RegistryChanged),
        ] {
            assert!(
                rules.iter().any(|rule| rule.action.contains(&wanted)),
                "there is no {what}"
            );
        }
        assert!(
            rules.iter().any(|rule| rule.subject == Subject::Registry),
            "no rule is about the registry"
        );
    }

    /// A registry event, in the shape `Record::from_driver` makes.
    fn registry_record(path: &str, at: u64, process_id: u32) -> Record {
        Record {
            timestamp: at,
            subject: Subject::Registry,
            action: Action::RegistryChanged,
            detail: Detail::RegistryKeyDeleted.code(),
            path: Some(path.to_string()),
            folded_path: Some(path.to_ascii_lowercase()),
            process_id,
            parent_process_id: 4,
        }
    }

    #[test]
    fn an_excluded_path_cannot_satisfy_a_rule() {
        // The mechanism on a rule of its own, so the shipped rules' use of it is
        // not the only thing holding it up: an exclusion refuses, and a path
        // that does not contain it is unaffected.
        let mut engine = Engine::from_toml(
            r#"
            [[rule]]
            id = "BEH-9001"
            name = "test rule"
            description = "A test rule."
            subject = "registry"
            action = ["registry_changed"]
            path_contains = ["\\software\\"]
            path_excludes = ["\\scratch\\"]
            "#,
        )
        .expect("parses");
        let at = 10 * TICKS_PER_SECOND;
        assert!(
            engine
                .observe(&registry_record(
                    r"\REGISTRY\MACHINE\SOFTWARE\Scratch\Key",
                    at,
                    7
                ))
                .is_empty(),
            "the excluded path satisfied the rule"
        );
        assert_eq!(
            engine
                .observe(&registry_record(
                    r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Key",
                    at,
                    7
                ))
                .len(),
            1
        );
    }

    #[test]
    fn an_exclusion_refusal_is_tellable_apart_from_a_plain_non_match() {
        // What the engine's `trace` line rests on. `matches` answers yes or no,
        // and a "no" from an exclusion reads exactly like a "no" from an event
        // that never qualified — which is why an exclusion could only ever be
        // measured by the absence of a warning. `verdict` keeps the difference.
        use crate::dsl::Verdict;

        let engine = builtin().expect("the shipped rules parse");
        let rule = engine
            .rules()
            .iter()
            .find(|rule| rule.id == "BEH-0027")
            .expect("BEH-0027 is shipped");

        let instance = registry_record(
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\AarSvc_73452\Security",
            0,
            1,
        );
        assert!(
            matches!(
                rule.verdict(&instance, None, None),
                Verdict::Excluded(pattern)
                    if pattern == r"\registry\machine\system\controlset*\services\*_*"
            ),
            "the per-user instance path was not refused by the instance exclusion"
        );

        let elsewhere = registry_record(r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Product\Key", 0, 1);
        assert!(matches!(
            rule.verdict(&elsewhere, None, None),
            Verdict::Matches
        ));

        let mut other_detail = elsewhere;
        other_detail.detail = Detail::RegistryValueSet.code();
        assert!(
            matches!(rule.verdict(&other_detail, None, None), Verdict::NoMatch),
            "an event the rule never described was reported as excluded"
        );
    }

    #[test]
    fn a_mass_delete_outside_the_application_hive_fires_through_the_driver_shape() {
        // The test VM's positive control, as code, and through
        // `Record::from_driver` rather than a hand-built `Record` so that a
        // mapping defect cannot hide behind the helper: thirty key deletes under
        // `HKCU\Software` in one second, which is what the VM produced on
        // 2026-10-18 20:02:13 and what the installed build did not warn about.
        let mut engine = builtin().expect("the shipped rules parse");
        let mut fired = Vec::new();
        for step in 0..30u64 {
            let event = av_ipc::DriverEvent {
                sequence: step,
                timestamp_100ns: 2_000 * TICKS_PER_SECOND + step,
                action: av_ipc::DriverEventAction::RegistryChanged,
                subject: av_ipc::DriverSubject::Registry,
                path: Some(std::path::PathBuf::from(format!(
                    r"\REGISTRY\USER\S-1-5-21-3068414794-1231551665-1067906926-1001\Software\WenleBulk{step}"
                ))),
                process_id: 8620,
                parent_process_id: 0,
                thread_id: 0,
                detail: Detail::RegistryKeyDeleted.code(),
                driver_state: None,
            };
            fired.extend(engine.observe_driver(&event));
        }
        assert_eq!(
            fired.len(),
            1,
            "the VM's positive control does not fire here either: {fired:?}"
        );
        assert_eq!(fired[0].rule_id, "BEH-0027");
    }

    #[test]
    fn the_mass_key_delete_rule_ignores_per_user_service_instances() {
        // Measured in the test VM on 2026-10-19: twenty-four per-user service
        // instances under `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\
        // <name>_<hex>`, holding twenty-four `Security` and six `TriggerInfo`
        // subkeys. The Service Control Manager deletes all thirty when a
        // session ends, so a healthy machine warned at every boot. Both halves
        // are kept true: quiet on that shape, and still firing elsewhere.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 1_000 * TICKS_PER_SECOND;
        let mut fired = Vec::new();
        for step in 0..30u64 {
            let subkey = if step < 24 { "Security" } else { "TriggerInfo" };
            let path = format!(
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\PerUserSvc{step:02}_{:05x}\{subkey}",
                73_452 + step
            );
            fired.extend(engine.observe(&registry_record(&path, at + step, 844)));
            assert!(
                fired.is_empty(),
                "a per-user service instance fired the rule: {fired:?}"
            );
        }
        for step in 0..30 {
            fired.extend(engine.observe(&registry_record(
                r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Product\Key",
                at + 1_000 + step,
                844,
            )));
        }
        assert_eq!(
            fired.len(),
            1,
            "the rule stopped working outside the instance keys: {fired:?}"
        );
        assert_eq!(fired[0].rule_id, "BEH-0027");
    }

    #[test]
    fn the_mass_key_delete_rule_ignores_the_search_index() {
        // Measured in the test VM on 2026-10-19: `SearchIndexer` deleted thirty
        // keys under `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows Search\
        // Gather\Windows\SystemIndex\Sites\LocalHost\Paths\…` at a session end.
        // The index deletes and rebuilds that tree by design.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 1_000 * TICKS_PER_SECOND;
        let mut fired = Vec::new();
        for step in 0..30u64 {
            let path = format!(
                r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows Search\Gather\Windows\SystemIndex\Sites\LocalHost\Paths\{step}"
            );
            fired.extend(engine.observe(&registry_record(&path, at + step, 7_304)));
            assert!(
                fired.is_empty(),
                "the search index fired the rule: {fired:?}"
            );
        }
        for step in 0..30 {
            fired.extend(engine.observe(&registry_record(
                r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Product\Key",
                at + 1_000 + step,
                7_304,
            )));
        }
        assert_eq!(
            fired.len(),
            1,
            "the rule stopped working outside the search index: {fired:?}"
        );
        assert_eq!(fired[0].rule_id, "BEH-0027");
    }

    #[test]
    fn the_mass_key_delete_rule_ignores_the_application_hive() {
        // Measured in the test VM on 2026-10-18: one `svchost.exe` (pid 968)
        // deleted thirty keys under `\REGISTRY\A\{…}\WorkItems\{…}` in half a
        // minute, and the rule warned about a healthy machine. The hive is
        // excluded, and this test keeps both halves true: it stays quiet there,
        // and it still fires somewhere else.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 1_000 * TICKS_PER_SECOND;
        for step in 0..30 {
            let findings = engine.observe(&registry_record(
                r"\REGISTRY\A\{6577a0ab-0e60-4ac9-af65-4a25c0ae1b5f}\WorkItems\{4c9276ce-0ea2-4f66-aacc-8cf1dd988ea6}",
                at + step,
                968,
            ));
            assert!(
                findings.is_empty(),
                "the application hive fired: {findings:?}"
            );
        }
        let mut fired = Vec::new();
        for step in 0..30 {
            fired.extend(engine.observe(&registry_record(
                r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Product\Key",
                at + 1_000 + step,
                968,
            )));
        }
        assert_eq!(
            fired.len(),
            1,
            "the rule stopped working outside the application hive"
        );
        assert_eq!(fired[0].rule_id, "BEH-0027");
    }
}
