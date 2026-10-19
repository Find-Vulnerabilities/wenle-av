//! The rule language: a TOML file, parsed into [`RuleSet`], validated once.
//!
//! # Why a format of its own rather than YARA
//!
//! These rules are about *sequences of events*, not about bytes. A YARA rule
//! matches a file's contents; none of the evidence here is in a file — a
//! document being renamed to `7f3a91c2.locked`, a value written under
//! `...\CurrentVersion\Run`, `winword.exe` starting `cmd.exe` — and expressing
//! that in a byte-pattern language means matching names inside a log rather than
//! matching the event itself. So the language is a table of predicates over the
//! event's own fields, and the engine below is the only thing that evaluates it.
//!
//! # What a rule may name
//!
//! Only fields an event actually carries, which is a shorter list than it looks:
//! the subject, the action, an action-specific `detail`, a path, the acting
//! process and its creator. There is deliberately no condition on command
//! lines, file contents or hashes, because the driver never sees them and a
//! condition the engine cannot answer is a rule that never fires — or worse, one
//! that fires because "unknown" was treated as "match".
//!
//! # A condition with no answer is not a match
//!
//! The process-image and parent-image conditions read a table the engine fills
//! from process-start events. When that table has no entry for a pid — an old
//! process that started before the service did — the condition is **false**, not
//! true. That asymmetry is the whole reason a rule can name `explorer.exe`
//! without convicting every process whose creator is unknown.

use av_core::Severity;
use serde::Deserialize;

use crate::error::LoadError;

/// What an event is about, as a rule may name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subject {
    /// A file being opened, written, renamed or deleted.
    File,
    /// A process being created.
    Process,
    /// A registry key or value.
    Registry,
}

impl Subject {
    /// The name a rule writes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Subject::File => "file",
            Subject::Process => "process",
            Subject::Registry => "registry",
        }
    }

    /// The protocol's subject for a driver event, or `None` for one of the
    /// subjects no rule may speak about.
    ///
    /// `DriverSubject::Driver`, `Protection` and `Configuration` are about the
    /// driver itself rather than about something happening on the machine, and
    /// every rule is about the machine. `Image` and `Unrecognised` are likewise
    /// left out — an image load carries no path in this build (the driver's
    /// events for it name the process, not the DLL) and an unrecognised subject
    /// is by definition one this build cannot reason about.
    pub fn from_driver(subject: av_ipc::DriverSubject) -> Option<Self> {
        match subject {
            av_ipc::DriverSubject::File => Some(Subject::File),
            av_ipc::DriverSubject::Process => Some(Subject::Process),
            av_ipc::DriverSubject::Registry => Some(Subject::Registry),
            av_ipc::DriverSubject::Image
            | av_ipc::DriverSubject::Driver
            | av_ipc::DriverSubject::Protection
            | av_ipc::DriverSubject::Configuration
            | av_ipc::DriverSubject::Unrecognised { .. } => None,
        }
    }
}

/// What happened, as a rule may name it.
///
/// The set is `av_ipc::DriverEventAction`'s minus `Unrecognised`: an action this
/// build has no name for cannot match anything, and a rule that named it would
/// be a rule about a code number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// A process creation or a file execution was refused before it happened.
    ExecutionBlocked,
    /// Something was written to a file the rules care about.
    FileWritten,
    /// An image was mapped into a process.
    ImageLoaded,
    /// A process was created.
    ProcessStarted,
    /// A write was refused.
    WriteBlocked,
    /// The driver is alive.
    Heartbeat,
    /// The driver's state changed.
    StateChanged,
    /// The driver's event queue overflowed.
    EventsDropped,
    /// A file was renamed or moved.
    FileRenamed,
    /// A delete was requested on a file.
    FileDeleted,
    /// A registry key or value changed.
    RegistryChanged,
}

impl Action {
    /// The protocol's action for a driver event, or `None` for `Unrecognised`.
    ///
    /// Exhaustive on purpose: a new action on the driver's side stops this
    /// build rather than being silently unmatchable.
    pub fn from_driver(action: av_ipc::DriverEventAction) -> Option<Self> {
        match action {
            av_ipc::DriverEventAction::ExecutionBlocked => Some(Action::ExecutionBlocked),
            av_ipc::DriverEventAction::FileWritten => Some(Action::FileWritten),
            av_ipc::DriverEventAction::ImageLoaded => Some(Action::ImageLoaded),
            av_ipc::DriverEventAction::ProcessStarted => Some(Action::ProcessStarted),
            av_ipc::DriverEventAction::WriteBlocked => Some(Action::WriteBlocked),
            av_ipc::DriverEventAction::Heartbeat => Some(Action::Heartbeat),
            av_ipc::DriverEventAction::StateChanged => Some(Action::StateChanged),
            av_ipc::DriverEventAction::EventsDropped => Some(Action::EventsDropped),
            av_ipc::DriverEventAction::FileRenamed => Some(Action::FileRenamed),
            av_ipc::DriverEventAction::FileDeleted => Some(Action::FileDeleted),
            av_ipc::DriverEventAction::RegistryChanged => Some(Action::RegistryChanged),
            av_ipc::DriverEventAction::Unrecognised { .. } => None,
        }
    }

    /// The name a rule writes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::ExecutionBlocked => "execution_blocked",
            Action::FileWritten => "file_written",
            Action::ImageLoaded => "image_loaded",
            Action::ProcessStarted => "process_started",
            Action::WriteBlocked => "write_blocked",
            Action::Heartbeat => "heartbeat",
            Action::StateChanged => "state_changed",
            Action::EventsDropped => "events_dropped",
            Action::FileRenamed => "file_renamed",
            Action::FileDeleted => "file_deleted",
            Action::RegistryChanged => "registry_changed",
        }
    }
}

/// An action-specific `detail` value a rule may require.
///
/// Spelled as a name rather than a number because the numbers collide across
/// actions — `FileRenamed` puts 1 in `detail` for "the target could not be
/// resolved", and `RegistryChanged` puts 1 there for "a key was created". A
/// number in a rule file would be a rule that silently matched the wrong thing
/// the day a second action started using it, so [`Detail::action`] says which
/// action each name belongs to and [`RuleSet::validate`] refuses a rule that
/// pairs one with the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    /// `FileRenamed`'s detail 1: the target name could not be resolved, so the
    /// path is the old name.
    RenameTargetUnresolved,
    /// A key was created.
    RegistryKeyCreated,
    /// A key was deleted.
    RegistryKeyDeleted,
    /// A value was set.
    RegistryValueSet,
    /// A value was deleted.
    RegistryValueDeleted,
    /// A key was renamed.
    RegistryKeyRenamed,
}

impl Detail {
    /// The number the driver puts in `detail` for this condition.
    pub const fn code(self) -> u32 {
        match self {
            // `FileRenamed` sets no bit for a resolved target, so the only
            // number it puts here is the one for "could not resolve it".
            Detail::RenameTargetUnresolved => 1,
            Detail::RegistryKeyCreated => av_driver_proto::event::EventAction::REGISTRY_KEY_CREATED,
            Detail::RegistryKeyDeleted => av_driver_proto::event::EventAction::REGISTRY_KEY_DELETED,
            Detail::RegistryValueSet => av_driver_proto::event::EventAction::REGISTRY_VALUE_SET,
            Detail::RegistryValueDeleted => {
                av_driver_proto::event::EventAction::REGISTRY_VALUE_DELETED
            }
            Detail::RegistryKeyRenamed => av_driver_proto::event::EventAction::REGISTRY_KEY_RENAMED,
        }
    }

    /// The one action this condition belongs to.
    pub const fn action(self) -> Action {
        match self {
            Detail::RenameTargetUnresolved => Action::FileRenamed,
            Detail::RegistryKeyCreated
            | Detail::RegistryKeyDeleted
            | Detail::RegistryValueSet
            | Detail::RegistryValueDeleted
            | Detail::RegistryKeyRenamed => Action::RegistryChanged,
        }
    }

    /// The name a rule writes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Detail::RenameTargetUnresolved => "rename_target_unresolved",
            Detail::RegistryKeyCreated => "registry_key_created",
            Detail::RegistryKeyDeleted => "registry_key_deleted",
            Detail::RegistryValueSet => "registry_value_set",
            Detail::RegistryValueDeleted => "registry_value_deleted",
            Detail::RegistryKeyRenamed => "registry_key_renamed",
        }
    }
}

/// One rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier, `BEH-NNNN`.
    pub id: String,
    /// Short name for a human.
    pub name: String,
    /// The sentence a finding shows.
    pub description: String,
    /// How serious this is if genuine. Defaults to `medium`.
    #[serde(default = "default_severity")]
    pub severity: Severity,
    /// Score contribution. Defaults to [`Severity::default_score`].
    #[serde(default)]
    pub score: Option<u16>,
    /// What the event is about.
    pub subject: Subject,
    /// Which actions satisfy this rule. At least one.
    pub action: Vec<Action>,
    /// Required `detail` values, any one of which satisfies the rule. Empty
    /// means "any detail".
    #[serde(default)]
    pub detail: Vec<Detail>,
    /// Case-insensitive suffixes the path must end with, any one of which
    /// satisfies the rule.
    #[serde(default)]
    pub path_suffix: Vec<String>,
    /// Case-insensitive substrings the path must contain.
    #[serde(default)]
    pub path_contains: Vec<String>,
    /// Case-insensitive prefixes the path must start with.
    #[serde(default)]
    pub path_prefix: Vec<String>,
    /// Case-insensitive substrings that **disqualify** a path: an event whose
    /// path contains any one of them does not satisfy the rule, whatever else
    /// it matches.
    ///
    /// It exists for places Windows churns by design, where a count rule would
    /// otherwise fire on a healthy machine. The measurement that added it: the
    /// mass-key-delete rule warned on `svchost.exe` deleting thirty keys under
    /// `\REGISTRY\A\{…}\WorkItems\{…}` in thirty seconds, which is the
    /// application (AppContainer) hive's own bookkeeping. An exclusion is a
    /// weaker statement than the positive fields and is applied after them, so
    /// it can only ever narrow what a rule matches.
    ///
    /// An entry containing `*` is a wildcard that must match somewhere in the
    /// path, with `*` standing for any run of characters — none included, and
    /// **including the separators**. That form exists because some churn is
    /// only identifiable by shape: the second measurement, on the test VM on
    /// 2026-10-19, was twenty-four per-user service instances under
    /// `…\ControlSet001\Services\<name>_<hex>`, whose `Security` and
    /// `TriggerInfo` subkeys the Service Control Manager deletes when a
    /// session ends — thirty deletes at every boot. The underscore is what
    /// marks an instance name, and a name cannot be enumerated in advance.
    /// An entry made only of `*` is refused at load: it would silence its rule.
    #[serde(default)]
    pub path_excludes: Vec<String>,
    /// File names (not paths) the acting process's image must be, any one of.
    #[serde(default)]
    pub process_image: Vec<String>,
    /// File names the acting process's creator must be, any one of.
    #[serde(default)]
    pub parent_image: Vec<String>,
    /// How many matching events within [`Self::window_seconds`] are needed.
    /// One is the common case and means "this event alone".
    #[serde(default = "default_count")]
    pub count: u32,
    /// The window the count is measured over.
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    /// How long this rule stays quiet for one process after it fires.
    /// Defaults to the window, so a burst produces one finding rather than one
    /// per event.
    #[serde(default)]
    pub dedupe_seconds: Option<u64>,
}

fn default_severity() -> Severity {
    Severity::Medium
}

fn default_count() -> u32 {
    1
}

fn default_window_seconds() -> u64 {
    60
}

impl Rule {
    /// The score this rule contributes, resolved.
    pub fn score(&self) -> u16 {
        self.score.unwrap_or_else(|| self.severity.default_score())
    }

    /// How long the rule stays quiet after firing for one process.
    pub fn dedupe_seconds(&self) -> u64 {
        self.dedupe_seconds.unwrap_or(self.window_seconds)
    }

    /// Whether one event satisfies every predicate this rule states.
    ///
    /// The two image arguments are the *acting* process's image name and its
    /// creator's, already folded, looked up by the caller. `None` means the
    /// engine does not know — and a condition it cannot answer is **false**,
    /// never true, which is the difference between "the parent was not
    /// `explorer.exe`" and "the parent was not recorded".
    ///
    /// The checks run cheapest first: subject and action are a comparison each,
    /// and a rule that fails them never looks at a string. That ordering is why
    /// forty rules over a busy event stream is affordable.
    pub fn matches(
        &self,
        record: &crate::Record,
        process_image: Option<&str>,
        parent_image: Option<&str>,
    ) -> bool {
        matches!(
            self.verdict(record, process_image, parent_image),
            Verdict::Matches
        )
    }

    /// The same question as [`Rule::matches`], answered with the reason.
    ///
    /// The engine needs one distinction `matches` throws away: a path that
    /// **would** have matched and was refused by [`Rule::path_excludes`]. That
    /// refusal is otherwise invisible, and an exclusion which leaves no trace
    /// can only be measured by the absence of a warning — which is not
    /// evidence, because an event that never arrived produces the same
    /// silence. Everything else that fails a predicate is [`Verdict::NoMatch`],
    /// so a refusal cannot be confused with an event that never qualified.
    pub(crate) fn verdict<'a>(
        &'a self,
        record: &crate::Record,
        process_image: Option<&str>,
        parent_image: Option<&str>,
    ) -> Verdict<'a> {
        if self.subject != record.subject || !self.action.contains(&record.action) {
            return Verdict::NoMatch;
        }
        // A detail condition only counts against the action it was written for,
        // so a rule naming two actions and one detail cannot match the detail's
        // number under the other action. `RuleSet::validate` refuses the plain
        // version of that mistake; this refuses the version where both actions
        // happen to share a number.
        if !self.detail.is_empty()
            && !self
                .detail
                .iter()
                .any(|detail| detail.action() == record.action && detail.code() == record.detail)
        {
            return Verdict::NoMatch;
        }
        if !self.process_image.is_empty() && !names_any(&self.process_image, process_image) {
            return Verdict::NoMatch;
        }
        if !self.parent_image.is_empty() && !names_any(&self.parent_image, parent_image) {
            return Verdict::NoMatch;
        }
        let Some(path) = record.folded() else {
            // A rule that names a path condition cannot be satisfied by an
            // event that has no path.
            return if self.path_suffix.is_empty()
                && self.path_contains.is_empty()
                && self.path_prefix.is_empty()
            {
                Verdict::Matches
            } else {
                Verdict::NoMatch
            };
        };
        if !self.path_suffix.is_empty()
            && !self
                .path_suffix
                .iter()
                .any(|suffix| ends_with_ascii(path, suffix))
        {
            return Verdict::NoMatch;
        }
        if !self.path_contains.is_empty()
            && !self
                .path_contains
                .iter()
                .any(|needle| contains_ascii(path, needle))
        {
            return Verdict::NoMatch;
        }
        if !self.path_prefix.is_empty()
            && !self
                .path_prefix
                .iter()
                .any(|prefix| starts_with_ascii(path, prefix))
        {
            return Verdict::NoMatch;
        }
        // Last, and only ever a refusal: an exclusion cannot make a rule match
        // something it would not otherwise have matched.
        if let Some(pattern) = self
            .path_excludes
            .iter()
            .find(|pattern| excluded(path, pattern))
        {
            return Verdict::Excluded(pattern);
        }
        Verdict::Matches
    }
}

/// What one rule made of one event.
///
/// [`Verdict::Excluded`] exists for observability rather than for matching:
/// the event cleared every predicate the rule states and was then refused by
/// one of its [`Rule::path_excludes`] entries. The engine logs that — at
/// `trace`, with the rule, the path and the entry — so that an exclusion which
/// is doing its job leaves a record instead of a hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict<'a> {
    /// Every predicate passed.
    Matches,
    /// Every predicate passed, but this exclusion entry refused the path.
    Excluded(&'a str),
    /// Some predicate other than an exclusion failed.
    NoMatch,
}

/// Whether `actual` is one of `names`, ignoring ASCII case.
fn names_any(names: &[String], actual: Option<&str>) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    names.iter().any(|name| name.eq_ignore_ascii_case(actual))
}

/// `haystack` ends with `needle`, ignoring ASCII case.
///
/// Byte-wise rather than `str::to_lowercase` so that nothing is allocated per
/// rule per event, and so that a needle whose length falls inside a multi-byte
/// character cannot panic the way slicing a `str` at a non-boundary would.
fn ends_with_ascii(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    haystack.len() >= needle.len()
        && haystack[haystack.len() - needle.len()..].eq_ignore_ascii_case(needle)
}

/// `haystack` starts with `needle`, ignoring ASCII case.
fn starts_with_ascii(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

/// `haystack` contains `needle`, ignoring ASCII case.
fn contains_ascii(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    if needle.is_empty() {
        return true;
    }
    haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Whether one `path_excludes` entry refuses `path`.
///
/// A plain entry is a substring; an entry with a `*` is a wildcard that must
/// match somewhere in the path. Matching ignores ASCII case, like every other
/// path condition here.
fn excluded(path: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        wildcard_contains(path, pattern)
    } else {
        contains_ascii(path, pattern)
    }
}

/// `haystack` contains a match for `pattern`, ignoring ASCII case, where `*`
/// matches any run of characters.
fn wildcard_contains(haystack: &str, pattern: &str) -> bool {
    let haystack = haystack.as_bytes();
    let pattern = pattern.as_bytes();
    // Every start offset is tried, which is what makes the meaning one
    // sentence long: the pattern matches *somewhere* in the path, exactly like
    // the plain substring form.
    (0..=haystack.len()).any(|start| wildcard_matches(&haystack[start..], pattern))
}

/// Whether all of `text` is a match for `pattern`, ignoring ASCII case, with
/// `*` standing for any run of characters — including none, and including the
/// path separators.
fn wildcard_matches(text: &[u8], pattern: &[u8]) -> bool {
    let (mut t, mut p) = (0, 0);
    let mut star: Option<usize> = None;
    let mut resume = 0;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            resume = t;
            p += 1;
        } else if p < pattern.len() && text[t].eq_ignore_ascii_case(&pattern[p]) {
            t += 1;
            p += 1;
        } else if let Some(at) = star {
            // Backtrack: let the most recent `*` swallow one more byte.
            resume += 1;
            t = resume;
            p = at + 1;
        } else {
            return false;
        }
    }
    pattern[p.min(pattern.len())..]
        .iter()
        .all(|&byte| byte == b'*')
}

/// A parsed rule file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    /// The rules, as `[[rule]]` tables.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Parse a TOML rule file.
    pub fn parse(text: &str) -> Result<Self, LoadError> {
        let parsed: RuleSet = toml::from_str(text).map_err(|source| LoadError::Syntax {
            message: source.to_string(),
        })?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Check the invariants a rule has to satisfy to be evaluable.
    ///
    /// Every check here is a mistake that would otherwise produce a rule that
    /// never fires — which looks exactly like a rule that fires on nothing.
    pub fn validate(&self) -> Result<(), LoadError> {
        let mut seen: Vec<&str> = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err(LoadError::Invalid {
                    id: rule.id.clone(),
                    reason: "the id is empty".to_string(),
                });
            }
            if seen.contains(&rule.id.as_str()) {
                return Err(LoadError::Invalid {
                    id: rule.id.clone(),
                    reason: "the id is used by another rule".to_string(),
                });
            }
            seen.push(&rule.id);

            if rule.action.is_empty() {
                return Err(LoadError::Invalid {
                    id: rule.id.clone(),
                    reason: "no action is named, so nothing can satisfy it".to_string(),
                });
            }
            if rule.count == 0 {
                return Err(LoadError::Invalid {
                    id: rule.id.clone(),
                    reason: "count is zero, so it can never be reached".to_string(),
                });
            }
            if rule.window_seconds == 0 {
                return Err(LoadError::Invalid {
                    id: rule.id.clone(),
                    reason: "window_seconds is zero, so no event could fall inside it".to_string(),
                });
            }
            // A `detail` condition belongs to exactly one action. Pairing it
            // with another is the mistake the enum's own documentation warns
            // about — the numbers collide across actions.
            for detail in &rule.detail {
                if !rule.action.contains(&detail.action()) {
                    return Err(LoadError::Invalid {
                        id: rule.id.clone(),
                        reason: format!(
                            "detail `{}` belongs to `{}`, and this rule does not name that action",
                            detail.as_str(),
                            detail.action().as_str()
                        ),
                    });
                }
            }
            // An uppercase suffix is not an error — the match is case
            // insensitive — but an empty one matches everything, which is a
            // rule that says less than its author meant.
            for (what, list) in [
                ("path_suffix", &rule.path_suffix),
                ("path_contains", &rule.path_contains),
                ("path_prefix", &rule.path_prefix),
                ("path_excludes", &rule.path_excludes),
                ("process_image", &rule.process_image),
                ("parent_image", &rule.parent_image),
            ] {
                if list.iter().any(|item| item.trim().is_empty()) {
                    return Err(LoadError::Invalid {
                        id: rule.id.clone(),
                        reason: format!("{what} contains an empty string, which matches anything"),
                    });
                }
            }
            // The wildcard form has its own version of that mistake: an entry
            // made only of `*` refuses every path, which silences the rule it
            // is written on — the opposite of a detection.
            if let Some(pattern) = rule
                .path_excludes
                .iter()
                .find(|pattern| pattern.trim().chars().all(|character| character == '*'))
            {
                return Err(LoadError::Invalid {
                    id: rule.id.clone(),
                    reason: format!("path_excludes entry `{pattern}` matches every path"),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_rule_parses_and_defaults_are_the_harmless_ones() {
        let set = RuleSet::parse(
            r#"
            [[rule]]
            id = "BEH-0001"
            name = "a name"
            description = "a description"
            subject = "file"
            action = ["file_renamed"]
            "#,
        )
        .expect("parses");
        let rule = &set.rules[0];
        assert_eq!(rule.severity, Severity::Medium);
        assert_eq!(rule.score(), Severity::Medium.default_score());
        assert_eq!(rule.count, 1);
        assert_eq!(rule.window_seconds, 60);
        // Quiet for a window by default: a burst produces one finding.
        assert_eq!(rule.dedupe_seconds(), 60);
    }

    #[test]
    fn a_rule_with_no_action_is_refused() {
        let error = RuleSet::parse(
            r#"
            [[rule]]
            id = "BEH-0002"
            name = "n"
            description = "d"
            subject = "file"
            action = []
            "#,
        )
        .expect_err("refused");
        assert!(
            error.to_string().contains("no action"),
            "the reason a rule cannot fire is not in the error: {error}"
        );
    }

    #[test]
    fn a_duplicate_id_is_refused() {
        let error = RuleSet::parse(
            r#"
            [[rule]]
            id = "BEH-0003"
            name = "n"
            description = "d"
            subject = "file"
            action = ["file_renamed"]

            [[rule]]
            id = "BEH-0003"
            name = "n2"
            description = "d2"
            subject = "file"
            action = ["file_deleted"]
            "#,
        )
        .expect_err("refused");
        assert!(error.to_string().contains("another rule"), "{error}");
    }

    #[test]
    fn a_detail_condition_paired_with_the_wrong_action_is_refused() {
        // The exact mistake the design exists to catch: `registry_value_set` is
        // detail 3, and no file action uses 3. A rule written that way would
        // match nothing, silently.
        let error = RuleSet::parse(
            r#"
            [[rule]]
            id = "BEH-0004"
            name = "n"
            description = "d"
            subject = "file"
            action = ["file_renamed"]
            detail = ["registry_value_set"]
            "#,
        )
        .expect_err("refused");
        assert!(error.to_string().contains("belongs to"), "{error}");
    }

    #[test]
    fn an_empty_matcher_is_refused_because_it_matches_anything() {
        let error = RuleSet::parse(
            r#"
            [[rule]]
            id = "BEH-0005"
            name = "n"
            description = "d"
            subject = "file"
            action = ["file_renamed"]
            path_suffix = [""]
            "#,
        )
        .expect_err("refused");
        assert!(error.to_string().contains("empty string"), "{error}");
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        // A typo in a condition's name would otherwise be a condition the engine
        // never reads and a rule that fires on everything the rest of it allows.
        let error = RuleSet::parse(
            r#"
            [[rule]]
            id = "BEH-0006"
            name = "n"
            description = "d"
            subject = "file"
            action = ["file_renamed"]
            path_sufix = [".locked"]
            "#,
        )
        .expect_err("refused");
        assert!(
            error.to_string().contains("path_sufix") || error.to_string().contains("unknown field"),
            "{error}"
        );
    }

    #[test]
    fn a_wildcard_exclusion_matches_by_shape_and_not_only_by_literal_text() {
        // The per-user service instance exclusion: the name is not knowable in
        // advance, so one entry covers every instance's subtree under any
        // ControlSet. `*` spans the separators.
        let pattern = r"\registry\machine\system\controlset*\services\*_*";
        for path in [
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\AarSvc_73452\Security",
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\P9RdrService_73452",
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet002\Services\webthreatdefusersvc_73452\TriggerInfo",
        ] {
            assert!(excluded(path, pattern), "{path} was not excluded");
        }
        for path in [
            // The plain service key has no underscore, so a mass delete there
            // is still evidence.
            r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\P9RdrService",
            r"\REGISTRY\USER\S-1-5-21-1\Software\WenleYN_1",
        ] {
            assert!(!excluded(path, pattern), "{path} was excluded");
        }
        // A pattern without `*` keeps the substring meaning it always had.
        assert!(excluded(r"\REGISTRY\A\{x}\WorkItems\{y}", r"\registry\a\"));
        assert!(!excluded(r"\REGISTRY\MACHINE\SOFTWARE\A", r"\registry\a\"));
    }

    #[test]
    fn an_exclusion_that_matches_every_path_is_refused() {
        let error = RuleSet::parse(
            r#"
            [[rule]]
            id = "BEH-9002"
            name = "n"
            description = "d"
            subject = "registry"
            action = ["registry_changed"]
            path_excludes = ["*"]
            "#,
        )
        .expect_err("refused");
        assert!(error.to_string().contains("matches every path"), "{error}");
    }

    #[test]
    fn the_detail_codes_are_the_protocols_own_constants() {
        // The engine's names are this crate's; the numbers are the driver's.
        // They are pinned together here, which is the only place both are in
        // scope together in a test — so a rename on the driver's side breaks
        // this build rather than silently changing what a rule matches.
        use av_driver_proto::event::EventAction;
        assert_eq!(
            Detail::RegistryKeyCreated.code(),
            EventAction::REGISTRY_KEY_CREATED
        );
        assert_eq!(
            Detail::RegistryKeyDeleted.code(),
            EventAction::REGISTRY_KEY_DELETED
        );
        assert_eq!(
            Detail::RegistryValueSet.code(),
            EventAction::REGISTRY_VALUE_SET
        );
        assert_eq!(
            Detail::RegistryValueDeleted.code(),
            EventAction::REGISTRY_VALUE_DELETED
        );
        assert_eq!(
            Detail::RegistryKeyRenamed.code(),
            EventAction::REGISTRY_KEY_RENAMED
        );
    }
}
