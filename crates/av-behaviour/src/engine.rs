//! The evaluator: a sliding window per (rule, process), and a table of who
//! started whom.
//!
//! # Why a window and not a counter
//!
//! "Twenty renames" is not a fact about a machine unless it is twenty renames
//! *in a short time*. A lifetime counter would make a backup program that
//! renames a file a day accumulate a finding over a year, and there is nothing
//! in the event that would ever clear it. So each rule's evidence is a queue of
//! timestamps that are dropped as they fall out of the rule's own window, and a
//! rule fires when the queue reaches the rule's count.
//!
//! # Every degradation loses evidence and never invents it
//!
//! Both tables here can grow without bound on a machine that runs long enough —
//! one key per (rule, process), one entry per process — so both have a cap. When
//! the cap is reached the engine **drops** the least useful entries, and the
//! only consequence is that a count rule may take longer to reach its threshold
//! or a lineage rule may stop matching for a process it no longer remembers.
//! Neither can produce a finding that the events did not support, which is the
//! property that matters: a detector whose memory management can convict is a
//! detector that convicts under load.
//!
//! # Where it is wired in
//!
//! `av_service::host::Host::drain_driver` hands every driver event to
//! [`Engine::observe_driver`] at the top of that loop, before the arms that
//! route it, and publishes a returned [`crate::Finding`] as a detection in the
//! warning band. `crate`'s header explains why the position matters.

use std::collections::{HashMap, VecDeque};

use av_core::Severity;

use crate::dsl::{Rule, RuleSet, Verdict};
use crate::error::LoadError;
use crate::event::Record;
use crate::Action;

/// 100-nanosecond units in one second — the driver's timestamp unit.
pub const TICKS_PER_SECOND: u64 = 10_000_000;

/// How many (rule, process) series are remembered before the least useful are
/// dropped.
///
/// Sized so that a machine with a few thousand processes and the shipped rule
/// set is comfortably inside it: the entries are per process *per rule that has
/// matched at least once*, not per process.
const MAX_TRACKED_SERIES: usize = 4096;

/// How many processes' lineage is remembered.
const MAX_TRACKED_PROCESSES: usize = 8192;

/// One finding: a rule, the event that satisfied it, and the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule that fired.
    pub rule_id: String,
    /// Its short name.
    pub name: String,
    /// The sentence to show a person.
    pub description: String,
    /// How damaging this would be if genuine.
    pub severity: Severity,
    /// What it contributes to a verdict. Every shipped rule is below the
    /// malicious threshold on its own — see [`crate::RULES_TOML`].
    pub score: u16,
    /// The path the event named, in its original case.
    pub path: Option<String>,
    /// The registry value's data, when the event carried one and a rule
    /// matched on it.
    ///
    /// Carried into the finding for the same reason the path is: a warning that
    /// says only `Run\Zoom` is a warning about a name, and the reason this rule
    /// fired is in the data it names.
    pub value: Option<String>,
    /// The process responsible.
    pub process_id: u32,
    /// The process that created it, when the event says.
    pub parent_process_id: u32,
    /// The responsible process's image name, folded, when the engine knows it.
    pub process_image: Option<String>,
    /// Its creator's image name, folded, when the engine knows it.
    pub parent_image: Option<String>,
    /// How many matching events were in the window when this fired.
    pub count: u32,
    /// The window they were in.
    pub window_seconds: u64,
}

/// What the engine remembers about one process.
#[derive(Debug, Clone)]
struct ProcessInfo {
    /// The image's file name, folded. `None` when the start event named no path.
    image: Option<String>,
    /// The creator's image name, folded, when it had been seen starting.
    parent: Option<String>,
    /// Insertion order, for eviction.
    order: u64,
}

/// The evidence for one rule about one process.
#[derive(Debug, Default)]
struct Series {
    /// When the matching events happened, oldest first.
    hits: VecDeque<u64>,
    /// When this rule last fired for this process, for the quiet period.
    last_fired: Option<u64>,
}

/// The rule engine.
#[derive(Debug)]
pub struct Engine {
    rules: Vec<Rule>,
    series: HashMap<(usize, u32), Series>,
    processes: HashMap<u32, ProcessInfo>,
    order: u64,
}

impl Engine {
    /// An engine over a parsed rule set.
    pub fn new(rules: RuleSet) -> Engine {
        Engine {
            rules: rules.rules,
            series: HashMap::new(),
            processes: HashMap::new(),
            order: 0,
        }
    }

    /// An engine over a rule file.
    pub fn from_toml(text: &str) -> Result<Engine, LoadError> {
        Ok(Engine::new(RuleSet::parse(text)?))
    }

    /// The rules this engine evaluates.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Offer one event, returning every rule it completed.
    ///
    /// The event's own timestamp is "now": the engine has no clock of its own,
    /// which is what makes a test of a sixty-second window run in a
    /// microsecond.
    pub fn observe(&mut self, record: &Record) -> Vec<Finding> {
        if record.action == Action::ProcessStarted {
            self.learn_process(record);
        }
        let image = self
            .processes
            .get(&record.process_id)
            .and_then(|info| info.image.clone());
        let parent = self
            .processes
            .get(&record.process_id)
            .and_then(|info| info.parent.clone());

        let mut findings = Vec::new();
        for index in 0..self.rules.len() {
            match self.rules[index].verdict(record, image.as_deref(), parent.as_deref()) {
                Verdict::NoMatch => continue,
                Verdict::Excluded(pattern) => {
                    // The one thing a rule does that would otherwise leave no
                    // trace. At `trace` and not at `info`: the application hive
                    // alone produces hundreds of these on a healthy machine,
                    // and what they are worth is a diagnostic, not a warning.
                    log::trace!(
                        "behaviour: {} excluded {} by path_excludes entry `{pattern}`",
                        self.rules[index].id,
                        record.path.as_deref().unwrap_or("")
                    );
                    continue;
                }
                Verdict::ExcludedByValue(pattern) => {
                    // The third refusal, named against the same event the other
                    // two name. A registry value is the only event that has
                    // one, and a rule written against a value that refuses it
                    // is the narrowest statement in the file — the trace line
                    // is how the exclusion can be shown to be doing its job.
                    log::trace!(
                        "behaviour: {} excluded {} by value_excludes entry `{pattern}` (the value was `{}`)",
                        self.rules[index].id,
                        record.path.as_deref().unwrap_or(""),
                        record.value.as_deref().unwrap_or("")
                    );
                    continue;
                }
                Verdict::ExcludedByImage(pattern) => {
                    // Same reasoning, and the image is named in the line because
                    // the path alone cannot explain why the event was refused:
                    // the same delete by any other process is still reported.
                    log::trace!(
                        "behaviour: {} excluded {} by process_image_excludes entry `{pattern}` (the acting image was {})",
                        self.rules[index].id,
                        record.path.as_deref().unwrap_or(""),
                        image.as_deref().unwrap_or("unknown")
                    );
                    continue;
                }
                Verdict::Matches => {}
            }
            let (count, window, dedupe) = {
                let rule = &self.rules[index];
                (rule.count, rule.window_seconds, rule.dedupe_seconds())
            };
            let Some(hits) = self.record_hit(
                index,
                record.process_id,
                record.timestamp,
                count,
                window,
                dedupe,
            ) else {
                continue;
            };
            let rule = &self.rules[index];
            findings.push(Finding {
                rule_id: rule.id.clone(),
                name: rule.name.clone(),
                description: rule.description.clone(),
                severity: rule.severity,
                score: rule.score(),
                path: record.path.clone(),
                value: record.value.clone(),
                process_id: record.process_id,
                parent_process_id: record.parent_process_id,
                process_image: image.clone(),
                parent_image: parent.clone(),
                count: hits,
                window_seconds: rule.window_seconds,
            });
        }
        self.trim(record.timestamp);
        findings
    }

    /// Offer a driver event. `None`-shaped events — the driver's own state and
    /// anything this build has no name for — produce no findings.
    pub fn observe_driver(&mut self, event: &av_ipc::DriverEvent) -> Vec<Finding> {
        match Record::from_driver(event) {
            Some(record) => self.observe(&record),
            None => Vec::new(),
        }
    }

    /// Remember who started whom, from a process start.
    fn learn_process(&mut self, record: &Record) {
        let Some(image) = record.image_name() else {
            // A start event with no image path teaches the engine nothing —
            // least of all a name to match on.
            return;
        };
        let parent = if record.parent_process_id == 0 {
            None
        } else {
            self.processes
                .get(&record.parent_process_id)
                .and_then(|info| info.image.clone())
        };
        if !self.processes.contains_key(&record.process_id)
            && self.processes.len() >= MAX_TRACKED_PROCESSES
        {
            let oldest = self
                .processes
                .iter()
                .min_by_key(|(_, info)| info.order)
                .map(|(pid, _)| *pid);
            if let Some(pid) = oldest {
                self.processes.remove(&pid);
            }
        }
        self.order += 1;
        self.processes.insert(
            record.process_id,
            ProcessInfo {
                image: Some(image),
                parent,
                order: self.order,
            },
        );
    }

    /// Record one matching event and report the window's count **if the rule
    /// should fire now**.
    ///
    /// The quiet period is checked last and only when the count is reached, so a
    /// burst costs one timestamp lookup per event rather than a finding per
    /// event: the first event of a ransomware sweep fires, the next twenty
    /// thousand are recorded and stay quiet.
    fn record_hit(
        &mut self,
        index: usize,
        process_id: u32,
        now: u64,
        count: u32,
        window_seconds: u64,
        dedupe_seconds: u64,
    ) -> Option<u32> {
        let window = window_seconds.saturating_mul(TICKS_PER_SECOND);
        let dedupe = dedupe_seconds.saturating_mul(TICKS_PER_SECOND);
        let oldest = now.saturating_sub(window);
        let series = self.series.entry((index, process_id)).or_default();
        while series.hits.front().is_some_and(|&at| at < oldest) {
            series.hits.pop_front();
        }
        series.hits.push_back(now);
        let hits = series.hits.len() as u32;
        if hits < count {
            return None;
        }
        if let Some(last) = series.last_fired {
            if now.saturating_sub(last) < dedupe {
                return None;
            }
        }
        series.last_fired = Some(now);
        Some(hits)
    }

    /// Drop series that can no longer produce evidence, and clear the table if
    /// that was not enough.
    ///
    /// Runs only when the table is over its cap, so the ordinary case pays one
    /// comparison. See this module's header for why dropping is safe.
    fn trim(&mut self, now: u64) {
        if self.series.len() <= MAX_TRACKED_SERIES {
            return;
        }
        let bounds: Vec<(u64, u64)> = self
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.window_seconds.saturating_mul(TICKS_PER_SECOND),
                    rule.dedupe_seconds().saturating_mul(TICKS_PER_SECOND),
                )
            })
            .collect();
        self.series.retain(|&(index, _), series| {
            let (window, dedupe) = bounds[index];
            let oldest = now.saturating_sub(window);
            while series.hits.front().is_some_and(|&at| at < oldest) {
                series.hits.pop_front();
            }
            !series.hits.is_empty()
                || series
                    .last_fired
                    .is_some_and(|last| now.saturating_sub(last) < dedupe)
        });
        if self.series.len() > MAX_TRACKED_SERIES {
            log::debug!(
                "behaviour: {} evidence series survive a trim; clearing them, which can only \
                 delay a count rule, never fire one",
                self.series.len()
            );
            self.series.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Record;
    use crate::{Detail, Subject};

    fn record(action: Action, subject: Subject, path: &str, pid: u32, at: u64) -> Record {
        Record {
            timestamp: at,
            subject,
            action,
            detail: 0,
            path: Some(path.to_string()),
            folded_path: Some(path.to_ascii_lowercase()),
            value: None,
            folded_value: None,
            command_line: None,
            process_id: pid,
            parent_process_id: 0,
        }
    }

    fn start(path: &str, pid: u32, parent: u32, at: u64) -> Record {
        let mut record = record(Action::ProcessStarted, Subject::Process, path, pid, at);
        record.parent_process_id = parent;
        record
    }

    fn engine(rules: &str) -> Engine {
        Engine::from_toml(rules).expect("the test's rules parse")
    }

    /// One rule with everything spelled out, so a test reads about the engine
    /// rather than about TOML's quoting.
    const ONE_RENAME_RULE: &str = r#"
        [[rule]]
        id = "T-1"
        name = "n"
        description = "d"
        severity = "low"
        subject = "file"
        action = ["file_renamed"]
        path_suffix = [".locked"]
    "#;

    #[test]
    fn a_single_matching_event_fires_a_count_one_rule() {
        let mut engine = engine(ONE_RENAME_RULE);
        let findings = engine.observe(&record(
            Action::FileRenamed,
            Subject::File,
            r"C:\docs\a.docx.locked",
            10,
            0,
        ));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "T-1");
        assert_eq!(findings[0].count, 1);
    }

    #[test]
    fn an_event_the_rule_does_not_name_does_not_fire_it() {
        let mut engine = engine(ONE_RENAME_RULE);
        for (action, subject, path) in [
            (Action::FileDeleted, Subject::File, r"C:\docs\a.docx.locked"),
            (Action::FileRenamed, Subject::File, r"C:\docs\a.docx"),
            (
                Action::FileRenamed,
                Subject::Registry,
                r"C:\docs\a.docx.locked",
            ),
        ] {
            assert!(
                engine
                    .observe(&record(action, subject, path, 10, 0))
                    .is_empty(),
                "{action:?}/{subject:?}/{path} fired a rule that does not name it"
            );
        }
    }

    #[test]
    fn a_count_rule_fires_on_the_event_that_reaches_its_count_and_not_before() {
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-2"
            name = "n"
            description = "d"
            subject = "file"
            action = ["file_renamed"]
            path_suffix = [".locked"]
            count = 3
            window_seconds = 60
            "#,
        );
        let mut fired = Vec::new();
        for step in 0..5u64 {
            let findings = engine.observe(&record(
                Action::FileRenamed,
                Subject::File,
                &format!(r"C:\docs\{step}.locked"),
                10,
                step * TICKS_PER_SECOND,
            ));
            if !findings.is_empty() {
                fired.push((step, findings[0].count));
            }
        }
        assert_eq!(fired, vec![(2, 3)], "the third event fires, once");
    }

    #[test]
    fn events_outside_the_window_do_not_count_towards_it() {
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-3"
            name = "n"
            description = "d"
            subject = "file"
            action = ["file_renamed"]
            path_suffix = [".locked"]
            count = 2
            window_seconds = 10
            "#,
        );
        // One now, one eleven seconds later: the first has left the window.
        assert!(engine
            .observe(&record(
                Action::FileRenamed,
                Subject::File,
                r"C:\docs\a.locked",
                10,
                0
            ))
            .is_empty());
        assert!(
            engine
                .observe(&record(
                    Action::FileRenamed,
                    Subject::File,
                    r"C:\docs\b.locked",
                    10,
                    11 * TICKS_PER_SECOND
                ))
                .is_empty(),
            "an event eleven seconds old was counted in a ten-second window"
        );
    }

    #[test]
    fn the_window_boundary_is_inclusive() {
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-4"
            name = "n"
            description = "d"
            subject = "file"
            action = ["file_renamed"]
            path_suffix = [".locked"]
            count = 2
            window_seconds = 10
            "#,
        );
        assert!(engine
            .observe(&record(
                Action::FileRenamed,
                Subject::File,
                r"C:\a.locked",
                10,
                0
            ))
            .is_empty());
        assert_eq!(
            engine
                .observe(&record(
                    Action::FileRenamed,
                    Subject::File,
                    r"C:\b.locked",
                    10,
                    10 * TICKS_PER_SECOND
                ))
                .len(),
            1,
            "an event exactly one window old is still inside it"
        );
    }

    #[test]
    fn counts_are_per_process_not_global() {
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-5"
            name = "n"
            description = "d"
            subject = "file"
            action = ["file_renamed"]
            path_suffix = [".locked"]
            count = 2
            window_seconds = 60
            "#,
        );
        assert!(engine
            .observe(&record(
                Action::FileRenamed,
                Subject::File,
                r"C:\a.locked",
                10,
                0
            ))
            .is_empty());
        assert!(
            engine
                .observe(&record(
                    Action::FileRenamed,
                    Subject::File,
                    r"C:\b.locked",
                    11,
                    TICKS_PER_SECOND
                ))
                .is_empty(),
            "two processes renamed one file each; neither reached a count of two"
        );
    }

    #[test]
    fn a_fired_rule_stays_quiet_for_its_quiet_period() {
        let mut engine = engine(ONE_RENAME_RULE);
        let first = engine.observe(&record(
            Action::FileRenamed,
            Subject::File,
            r"C:\a.locked",
            10,
            0,
        ));
        assert_eq!(first.len(), 1);
        // One second later, same process: still quiet (the default quiet period
        // is the rule's window, sixty seconds).
        assert!(engine
            .observe(&record(
                Action::FileRenamed,
                Subject::File,
                r"C:\b.locked",
                10,
                TICKS_PER_SECOND
            ))
            .is_empty());
        // Past it: fires again, because a second outbreak is a second event.
        assert_eq!(
            engine
                .observe(&record(
                    Action::FileRenamed,
                    Subject::File,
                    r"C:\c.locked",
                    10,
                    61 * TICKS_PER_SECOND
                ))
                .len(),
            1
        );
    }

    #[test]
    fn a_different_process_is_not_silenced_by_another_processs_finding() {
        let mut engine = engine(ONE_RENAME_RULE);
        assert_eq!(
            engine
                .observe(&record(
                    Action::FileRenamed,
                    Subject::File,
                    r"C:\a.locked",
                    10,
                    0
                ))
                .len(),
            1
        );
        assert_eq!(
            engine
                .observe(&record(
                    Action::FileRenamed,
                    Subject::File,
                    r"C:\b.locked",
                    11,
                    TICKS_PER_SECOND
                ))
                .len(),
            1,
            "the quiet period is per rule and process, not per rule"
        );
    }

    #[test]
    fn a_lineage_rule_matches_the_child_it_names_and_leaves_its_siblings_alone() {
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-6"
            name = "n"
            description = "d"
            subject = "process"
            action = ["process_started"]
            parent_image = ["winword.exe"]
            path_suffix = ["\\cmd.exe"]
            "#,
        );
        // The parent starts, so the engine knows its image by name.
        engine.observe(&start(r"C:\Program Files\Office\WINWORD.EXE", 100, 1, 0));
        let from_word = engine.observe(&start(r"C:\Windows\System32\cmd.exe", 101, 100, 1));
        assert_eq!(from_word.len(), 1, "winword.exe starting cmd.exe");
        assert_eq!(from_word[0].parent_image.as_deref(), Some("winword.exe"));
        // The same executable started by explorer.exe does not fire.
        assert!(engine
            .observe(&start(r"C:\Windows\explorer.exe", 102, 1, 2))
            .is_empty());
        assert!(engine
            .observe(&start(r"C:\Windows\System32\cmd.exe", 103, 102, 3))
            .is_empty());
    }

    #[test]
    fn an_unknown_parent_is_not_a_match() {
        // The whole asymmetry the design rests on: a rule that names
        // `explorer.exe` must not fire for a process whose creator was never
        // seen starting — that would convict every process that outlived the
        // service's own start.
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-7"
            name = "n"
            description = "d"
            subject = "process"
            action = ["process_started"]
            parent_image = ["explorer.exe"]
            "#,
        );
        assert!(
            engine
                .observe(&start(r"C:\Windows\System32\cmd.exe", 101, 999, 0))
                .is_empty(),
            "pid 999 was never seen starting, so its image is unknown, not \
             absent"
        );
    }

    #[test]
    fn a_process_start_event_can_be_matched_by_the_image_it_starts() {
        // The table is filled before the rules are evaluated, so a rule about
        // the child's own name works on the very event that names it.
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-8"
            name = "n"
            description = "d"
            subject = "process"
            action = ["process_started"]
            process_image = ["mshta.exe"]
            "#,
        );
        assert_eq!(
            engine
                .observe(&start(r"C:\Windows\System32\MSHTA.exe", 101, 1, 0))
                .len(),
            1
        );
    }

    #[test]
    fn a_detail_condition_only_matches_under_its_own_action() {
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-9"
            name = "n"
            description = "d"
            subject = "registry"
            action = ["registry_changed"]
            detail = ["registry_value_set"]
            path_contains = ["\\currentversion\\run\\"]
            "#,
        );
        let mut set_value = record(
            Action::RegistryChanged,
            Subject::Registry,
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
            10,
            0,
        );
        set_value.detail = Detail::RegistryValueSet.code();
        assert_eq!(engine.observe(&set_value).len(), 1);

        let mut deleted = set_value.clone();
        deleted.detail = Detail::RegistryValueDeleted.code();
        assert!(
            engine.observe(&deleted).is_empty(),
            "a value deletion satisfied a rule that asked for a value set"
        );
    }

    #[test]
    fn a_rule_with_a_path_condition_cannot_fire_on_an_event_with_no_path() {
        let mut engine = engine(ONE_RENAME_RULE);
        let mut no_path = record(Action::FileRenamed, Subject::File, "", 10, 0);
        no_path.path = None;
        no_path.folded_path = None;
        assert!(engine.observe(&no_path).is_empty());
    }

    #[test]
    fn a_driver_subject_no_rule_speaks_about_produces_no_findings() {
        let mut engine = engine(ONE_RENAME_RULE);
        let event = av_ipc::DriverEvent {
            sequence: 1,
            timestamp_100ns: 0,
            action: av_ipc::DriverEventAction::StateChanged,
            subject: av_ipc::DriverSubject::Protection,
            path: Some(std::path::PathBuf::from(r"C:\a.locked")),
            process_id: 10,
            parent_process_id: 0,
            thread_id: 0,
            detail: 0,
            value: None,
            command_line: None,
            driver_state: None,
        };
        assert!(engine.observe_driver(&event).is_empty());
    }

    #[test]
    fn dropping_evidence_can_only_lose_a_finding_not_make_one() {
        // Fill the process table past its cap, then check that the rule for the
        // evicted process simply stops matching while the newest still does.
        let mut engine = engine(
            r#"
            [[rule]]
            id = "T-10"
            name = "n"
            description = "d"
            subject = "process"
            action = ["process_started"]
            process_image = ["rare.exe"]
            "#,
        );
        engine.observe(&start(r"C:\a\rare.exe", 1, 0, 0));
        for pid in 2..(MAX_TRACKED_PROCESSES as u32 + 2) {
            engine.observe(&start(r"C:\a\ordinary.exe", pid, 0, 0));
        }
        assert_eq!(
            engine.processes.len(),
            MAX_TRACKED_PROCESSES,
            "the table is capped"
        );
        assert!(
            !engine.processes.contains_key(&1),
            "the oldest process was not the one evicted"
        );
        // A rule that matches the newest process still works.
        assert_eq!(
            engine
                .observe(&start(
                    r"C:\a\rare.exe",
                    MAX_TRACKED_PROCESSES as u32 + 99,
                    0,
                    0
                ))
                .len(),
            1
        );
    }
}
