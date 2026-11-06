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

use av_core::{Severity, VerdictThresholds};

use crate::dsl::{Precision, Response, Rule, RuleSet, Verdict};
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

/// How long a run of exclusions by one pattern is folded into one line.
///
/// An exclusion is a rule doing its job, and on a healthy machine it happens
/// hundreds of times an hour: measured 2026-10-31 in the test VM, `BEH-0003`
/// excluded every `\Windows\System32\SRU\*.log` the service wrote, and a log
/// line per event made the log itself the slowest part of the loop -- behaviour
/// findings arrived 13 to 23 seconds after their command at `trace` level.
///
/// A minute is short enough that a diagnostic still reads as "now", and long
/// enough that a busy exclusion costs one line instead of hundreds.
const EXCLUSION_QUIET_SECONDS: u64 = 60;

/// The identifier of the finding several rules' evidence adds up to.
///
/// Not a rule in the file: the engine builds this one, which is why the service
/// may treat it differently from a shipped rule -- see `observe_behaviour` in
/// `av-service`, where every other finding outside the warning band is a rule
/// file mistake and this one is the point.
pub const AGREEMENT_RULE_ID: &str = "BEH-AGG";

/// How long several rules' evidence stays able to add up, in seconds.
///
/// The same order as the rules' own windows: a ransomware sweep concentrates its
/// tells inside a minute, and a process that takes longer than this between two
/// of them is a process doing different things at different times.
const AGREEMENT_WINDOW_SECONDS: u64 = 60;

/// How long after an aggregate fires the same process may fire another.
///
/// Longer than the window on purpose. The aggregate's response is a termination,
/// and terminating the same process twice in a minute is either a race this
/// engine cannot win or a process that survived the first attempt -- neither is
/// worth a second attempt on evidence that has not changed.
const AGREEMENT_QUIET_SECONDS: u64 = 120;

/// How many processes may have partially-accumulated evidence at once.
///
/// Bounded for the same reason every other table here is: the keys are process
/// identifiers chosen by the machine, and a leak is a table that grows with
/// uptime.
const MAX_TRACKED_AGREEMENTS: usize = 1024;

/// How many distinct (rule, pattern) pairs are remembered.
///
/// Bounded because the key is a pair of strings: a rule with a wide exclusion
/// list seen against many paths would otherwise be a slow leak. When the bound
/// is reached the table is cleared, which costs at most one extra line.
const MAX_EXCLUSION_KEYS: usize = 256;

/// How many events one (rule, pattern) pair has excluded since its last line.
#[derive(Debug, Clone, Copy)]
struct ExclusionRun {
    /// When the line that opened this run was written.
    last: u64,
    /// How many events have been excluded since, not counting that one.
    count: u64,
}

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
    /// What the product may do about this finding -- see [Response].
    ///
    /// Carried for the same reason the precision is: the layer that acts is not
    /// the layer that evaluated the rule, and a rule that asked to terminate a
    /// process must not have its request lost on the way.
    pub response: Response,
    /// What one match of the rule is worth on its own -- see [Precision].
    ///
    /// Carried so the layer above can act on the difference: an `exact` rule
    /// names a key or a command nothing ordinary writes, and that is the class
    /// that may be allowed to terminate a process. A `burst` rule counts how
    /// often something ordinary happens and must never be given that power.
    pub precision: Precision,
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
    /// One entry per (rule, pattern) that is currently excluding things. See
    /// [`Engine::note_exclusion`].
    exclusions: HashMap<(usize, String), ExclusionRun>,
    /// One entry per process whose rules are adding up. See [`Engine::agree`].
    agreement: HashMap<u32, Agreement>,
}

/// What several rules have said about one process, and when.
///
/// The evidence a single rule carries is capped deliberately -- every shipped
/// rule is below the malicious threshold on its own -- so a conviction has to
/// come from independent signals agreeing. Measured in the test VM on
/// 2026-11-06 with a real WannaCry sample: one process produced
/// `BEH-0001` (a `.WNCRY` file), `BEH-0004` (twenty-five deletes in half a
/// minute) and `BEH-0054` (forty documents written in half a minute) inside
/// eight seconds, and each was reported and nothing else. This is the table
/// that makes those three one statement.
#[derive(Debug, Default)]
struct Agreement {
    /// Rule identifier to its score, for the rules that fired inside the
    /// window. A `HashMap` because the same rule firing twice is one signal and
    /// must not be counted twice.
    scores: HashMap<String, u16>,
    /// Whether any contributing rule could convict on its own class of
    /// evidence -- see [`Precision`]. A pile of `burst` rules is a busy machine
    /// and nothing more; the combination needs at least one rule whose evidence
    /// is about what the process *did* rather than how much of it.
    corroborated: bool,
    /// When the aggregate last fired, so a process that keeps the total over
    /// the threshold is stopped once and not once per event.
    last_fired: Option<u64>,
    /// The newest event that contributed, for expiry.
    newest: u64,
}

impl Engine {
    /// An engine over a parsed rule set.
    pub fn new(rules: RuleSet) -> Engine {
        Engine {
            rules: rules.rules,
            series: HashMap::new(),
            processes: HashMap::new(),
            order: 0,
            exclusions: HashMap::new(),
            agreement: HashMap::new(),
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
            // The refusal is copied out of the verdict before anything touches
            // `self` again: `Verdict` borrows the rule's own strings, and the
            // counting below needs `&mut self`.
            enum Refusal {
                Path(String),
                Image(String),
                Value(String),
            }
            let refusal = match self.rules[index].verdict(record, image.as_deref(), parent.as_deref()) {
                Verdict::NoMatch => continue,
                Verdict::Matches => None,
                Verdict::Excluded(pattern) => Some(Refusal::Path(pattern.to_string())),
                Verdict::ExcludedByImage(pattern) => Some(Refusal::Image(pattern.to_string())),
                Verdict::ExcludedByValue(pattern) => Some(Refusal::Value(pattern.to_string())),
            };
            if let Some(refusal) = refusal {
                // The one thing a rule does that would otherwise leave no trace.
                // At `trace` and not at `info`: the application hive alone
                // produces hundreds of these on a healthy machine, and what they
                // are worth is a diagnostic, not a warning. Throttled because
                // that volume is also what made the log the slowest part of the
                // loop -- see `EXCLUSION_QUIET_SECONDS`.
                let line = match &refusal {
                    Refusal::Path(pattern) => self.note_exclusion(
                        index,
                        pattern,
                        record.timestamp,
                        || format!("last: {}", record.path.as_deref().unwrap_or("")),
                    ),
                    Refusal::Image(pattern) => self.note_exclusion(
                        index,
                        pattern,
                        record.timestamp,
                        || format!("the acting image was {}", image.as_deref().unwrap_or("unknown")),
                    ),
                    Refusal::Value(pattern) => self.note_exclusion(
                        index,
                        pattern,
                        record.timestamp,
                        || format!("the value was `{}`", record.value.as_deref().unwrap_or("")),
                    ),
                };
                if let Some(line) = line {
                    log::trace!("{line}");
                }
                continue;
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
                precision: rule.precision,
                response: rule.response,
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
        // Several independent rules naming one process is a stronger statement
        // than any of them alone -- see [`Agreement`]. Added after the per-rule
        // findings so that the aggregate can say which ones contributed.
        if let Some(aggregate) = self.agree(record, &findings) {
            findings.push(aggregate);
        }
        self.trim(record.timestamp);
        findings
    }

    /// Add up what several rules have said about one process, and turn the total
    /// into one actionable finding when it reaches the malicious threshold.
    ///
    /// Returns the aggregate on the event that first crosses the threshold and
    /// nothing otherwise. The per-rule findings are untouched: every one of them
    /// is still reported, and this is the one the service may act on.
    ///
    /// # Why a pile of `burst` rules is not enough
    ///
    /// Eight folder-sized operations fire four burst rules at once on a healthy
    /// machine -- measured in the test VM on 2026-11-06, creating three hundred
    /// files and renaming a hundred of them produced `BEH-0003`, `BEH-0004`,
    /// `BEH-0005`, `BEH-0006` and `BEH-0054` in one go. Allowing that to convict
    /// would make every installer an incident, so the total only counts when at
    /// least one contributing rule is evidence about *what* the process did
    /// rather than how much of it.
    fn agree(&mut self, record: &Record, findings: &[Finding]) -> Option<Finding> {
        if findings.is_empty() {
            return None;
        }
        let pid = record.process_id;
        let at = record.timestamp;
        let window = AGREEMENT_WINDOW_SECONDS.saturating_mul(TICKS_PER_SECOND);
        let quiet = AGREEMENT_QUIET_SECONDS.saturating_mul(TICKS_PER_SECOND);

        if self
            .agreement
            .get(&pid)
            .is_some_and(|state| at.saturating_sub(state.newest) >= window)
        {
            self.agreement.remove(&pid);
        }
        if self.agreement.len() >= MAX_TRACKED_AGREEMENTS && !self.agreement.contains_key(&pid) {
            if let Some(oldest) = self
                .agreement
                .iter()
                .min_by_key(|(_, state)| state.newest)
                .map(|(pid, _)| *pid)
            {
                self.agreement.remove(&oldest);
            }
        }

        let state = self.agreement.entry(pid).or_default();
        state.newest = at;
        for finding in findings {
            state.scores.insert(finding.rule_id.clone(), finding.score);
            if finding.precision != Precision::Burst {
                state.corroborated = true;
            }
        }

        let total: u32 = state.scores.values().map(|score| u32::from(*score)).sum();
        let threshold = u32::from(VerdictThresholds::default().malicious);
        if total < threshold || !state.corroborated {
            return None;
        }
        if state
            .last_fired
            .is_some_and(|last| at.saturating_sub(last) < quiet)
        {
            return None;
        }
        state.last_fired = Some(at);

        let mut rules: Vec<&str> = state.scores.keys().map(String::as_str).collect();
        rules.sort_unstable();
        let image = findings.iter().find_map(|finding| finding.process_image.clone());
        Some(Finding {
            rule_id: AGREEMENT_RULE_ID.to_string(),
            name: "several independent signals agree".to_string(),
            description: format!(
                "{} behaviour rules named this process within {} seconds: {}",
                rules.len(),
                AGREEMENT_WINDOW_SECONDS,
                rules.join(", ")
            ),
            severity: Severity::High,
            // `Exact` on purpose: this is the finding the service is allowed to
            // act on, and it must not be able to reach that decision through a
            // class of evidence that cannot carry it.
            precision: Precision::Exact,
            response: Response::Terminate,
            score: total.min(u32::from(u16::MAX)) as u16,
            path: record.path.clone(),
            value: None,
            process_id: pid,
            parent_process_id: record.parent_process_id,
            process_image: image,
            parent_image: None,
            count: rules.len() as u32,
            window_seconds: AGREEMENT_WINDOW_SECONDS,
        })
    }

    /// Count one exclusion, and return the line to write if it is time to.
    ///
    /// The first exclusion by a (rule, pattern) pair is written immediately, so
    /// a diagnostic still shows *when* an exclusion started. The rest are
    /// counted, and folded into one line when the quiet window ends. `detail`
    /// is a closure because building it is the one allocation that would
    /// otherwise be paid for every excluded event.
    fn note_exclusion(
        &mut self,
        rule: usize,
        pattern: &str,
        at: u64,
        detail: impl FnOnce() -> String,
    ) -> Option<String> {
        let id = self.rules[rule].id.clone();
        let quiet = EXCLUSION_QUIET_SECONDS.saturating_mul(TICKS_PER_SECOND);
        let key = (rule, pattern.to_string());
        match self.exclusions.get_mut(&key) {
            Some(run) if at.saturating_sub(run.last) < quiet => {
                run.count += 1;
                None
            }
            Some(run) => {
                let count = run.count + 1;
                run.count = 0;
                run.last = at;
                Some(format!(
                    "behaviour: {id} excluded {count} more events in {EXCLUSION_QUIET_SECONDS} s \
                     by `{pattern}` ({})",
                    detail()
                ))
            }
            None => {
                if self.exclusions.len() >= MAX_EXCLUSION_KEYS {
                    self.exclusions.clear();
                }
                self.exclusions.insert(key, ExclusionRun { last: at, count: 0 });
                Some(format!(
                    "behaviour: {id} excluded an event by `{pattern}` ({})",
                    detail()
                ))
            }
        }
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

    #[test]
    fn an_exclusion_is_said_at_once_and_then_counted_into_one_line() {
        // The first line has to appear immediately: its job is to say *when* a
        // rule started refusing things, and a count that only shows up a minute
        // later would not answer that. The rest are folded, because writing one
        // line per excluded event is what made the log the slowest part of the
        // loop in the test VM on 2026-10-31.
        let mut engine = Engine::from_toml(
            r#"
            [[rule]]
            id = "BEH-9301"
            name = "n"
            description = "d"
            precision = "burst"
            response = "report"
            subject = "file"
            action = ["file_renamed"]
            path_suffix = [".log"]
            count = 20
            window_seconds = 60
            path_excludes = ["\\windows\\system32\\sru\\"]
            "#,
        )
        .expect("the rule parses");
        let pattern = "\\windows\\system32\\sru\\";
        let first = engine.note_exclusion(0, pattern, 0, || "first".to_string());
        assert!(first.expect("said at once").contains("excluded an event"));

        for n in 1..=3 {
            let silent = engine.note_exclusion(0, pattern, n * 10 * TICKS_PER_SECOND, || "x".to_string());
            assert!(silent.is_none(), "line {n} should have been counted");
        }

        let line = engine
            .note_exclusion(0, pattern, 70 * TICKS_PER_SECOND, || "last".to_string())
            .expect("time to say it");
        assert!(line.contains("4 more events"), "{line}");
        assert!(line.contains("60 s"), "{line}");

        // A different pattern is a different run, and says its own first line.
        let other = engine.note_exclusion(0, "\\other\\", 71 * TICKS_PER_SECOND, || "y".to_string());
        assert!(other.expect("its own line").contains("\\other\\"));
    }

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
    fn a_finding_carries_the_precision_of_the_rule_that_made_it() {
        // The layer above is allowed to act on `exact` and must never act on
        // `burst`, so the class has to travel with the finding. A finding that
        // lost it would either be treated as contextual (harmless) or, if
        // something defaulted the other way, be allowed to act on statistics.
        let mut engine = engine(
            r#"
            [[rule]]
            id = "BEH-9101"
            name = "exact one"
            description = "d"
            precision = "exact"
            subject = "file"
            action = ["file_renamed"]
            path_suffix = [".locked"]

            [[rule]]
            id = "BEH-9102"
            name = "burst one"
            description = "d"
            precision = "burst"
            subject = "file"
            action = ["file_renamed"]
            path_suffix = [".locked"]
            count = 2
            window_seconds = 60
            "#,
        );
        let fired = engine.observe(&record(
            Action::FileRenamed,
            Subject::File,
            r"C:\Users\me\a.locked",
            4242,
            10,
        ));
        let exact = fired
            .iter()
            .find(|f| f.rule_id == "BEH-9101")
            .expect("the exact rule fired");
        assert_eq!(exact.precision, crate::Precision::Exact);
        // The burst rule needs two events, so it is not in this first round.
        assert!(fired.iter().all(|f| f.rule_id != "BEH-9102"));
        let fired = engine.observe(&record(
            Action::FileRenamed,
            Subject::File,
            r"C:\Users\me\b.locked",
            4242,
            20,
        ));
        let burst = fired
            .iter()
            .find(|f| f.rule_id == "BEH-9102")
            .expect("the burst rule fired on its second event");
        assert_eq!(burst.precision, crate::Precision::Burst);
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
