//! Detection results and the scoring model that turns them into a verdict.
//!
//! # Why scoring instead of first-match
//!
//! Classic pattern matchers return a boolean: the first rule that fires decides
//! the outcome. That model is the single largest source of false positives in
//! signature-only engines, because one weak rule firing on a legitimate
//! program is indistinguishable from a confirmed infection.
//!
//! This engine instead accumulates a **score**. Every rule carries a weight
//! derived from its severity and from the quality metadata its author attached.
//! The accumulated score is compared against two thresholds to yield
//! [`Verdict::Suspicious`] or [`Verdict::Malicious`]. Strong indicators (an
//! exact hash match, an Authenticode-verified malicious publisher) are marked
//! [`Detection::decisive`] and short-circuit the score entirely.
//!
//! The practical effect: a lone generic string rule on an unsigned binary lands
//! at `Suspicious` and is surfaced without being acted on destructively, while
//! an exact known-bad hash is `Malicious` immediately.

use serde::{Deserialize, Serialize};

use crate::threat::ThreatName;

/// How damaging a finding would be if it is genuine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Default score contribution for a detection at this severity, used when a
    /// rule does not specify its own weight.
    ///
    /// The ladder is calibrated against [`VerdictThresholds::default`]
    /// (`suspicious = 30`, `malicious = 100`) so that it reads naturally:
    ///
    /// | Severity | Score | Alone reaches |
    /// |----------|-------|---------------|
    /// | Info     | 0     | *(nothing — recorded but never actionable)* |
    /// | Low      | 30    | Suspicious |
    /// | Medium   | 60    | Suspicious (two of them: Malicious) |
    /// | High     | 100   | Malicious |
    /// | Critical | 150   | Malicious |
    ///
    /// A single `Info` detection must never colour a verdict; it exists so the
    /// engine can record "I looked, and here is a neutral observation".
    pub const fn default_score(self) -> u16 {
        match self {
            Severity::Info => 0,
            Severity::Low => 30,
            Severity::Medium => 60,
            Severity::High => 100,
            Severity::Critical => 150,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn try_from_str(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Severity::Info,
            "low" => Severity::Low,
            "medium" | "moderate" => Severity::Medium,
            "high" => Severity::High,
            "critical" | "severe" => Severity::Critical,
            _ => return None,
        })
    }

    /// Parse a severity, defaulting to [`Severity::Medium`] for anything
    /// unrecognised.
    ///
    /// Prefer [`Severity::try_from_str`] anywhere the caller can report the
    /// problem. A misspelled `severity = hgih` silently becoming `Medium` gives
    /// a rule a plausible-looking score of 60 when the author meant 100, which
    /// is exactly the kind of quiet wrongness that produces false positives.
    pub fn from_str_lossy(s: &str) -> Self {
        Self::try_from_str(s).unwrap_or(Severity::Medium)
    }
}

/// The conclusion reached about a scan target.
///
/// [`Verdict::Clean`] is the `Default`. That is the right default for an
/// accumulator that has not run any detectors yet, but note that the scanner
/// must set [`Verdict::Unknown`] explicitly when it fails to read a target —
/// never leave a file at the default because it could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No indicator fired, or every indicator was suppressed by trust.
    #[default]
    Clean,
    /// Something fired, but not enough to justify blocking or deleting.
    Suspicious,
    /// Confirmed. Safe to quarantine or block.
    Malicious,
    /// The target could not be scanned (unreadable, password-protected, too
    /// large for the configured limits). Deliberately distinct from `Clean`:
    /// reporting an unscanned file as clean is how engines miss malware.
    Unknown,
}

impl Verdict {
    pub const fn is_detection(self) -> bool {
        matches!(self, Verdict::Suspicious | Verdict::Malicious)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
            Verdict::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which subsystem produced a detection. Used for reporting, and to let the
/// user switch off a whole class of detection (e.g. heuristics) without
/// touching the signature database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    /// A rule in the compiled signature database matched.
    Signature,
    /// Static heuristics: entropy, packing, suspicious imports, structure.
    Heuristic,
    /// Observed runtime behaviour.
    Behavior,
    /// A pattern found in the memory of a running process.
    Memory,
    /// Hash or certificate reputation.
    Reputation,
    /// The user marked this file explicitly.
    User,
}

impl DetectionSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            DetectionSource::Signature => "signature",
            DetectionSource::Heuristic => "heuristic",
            DetectionSource::Behavior => "behavior",
            DetectionSource::Memory => "memory",
            DetectionSource::Reputation => "reputation",
            DetectionSource::User => "user",
        }
    }
}

/// Where inside the scanned buffer something matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchLocation {
    /// Offset from the start of the scanned buffer.
    pub offset: u64,
    pub length: u32,
    /// The rule string identifier that matched (`$a`, `$str1`, ...).
    pub identifier: String,
    /// A short, safe rendering of the matched bytes: printable ASCII is kept,
    /// everything else becomes `.`. Capped in length so a rule matching a large
    /// region cannot blow up the report.
    pub preview: String,
}

impl MatchLocation {
    /// Longest preview we will render for a single match.
    pub const MAX_PREVIEW: usize = 64;

    pub fn new(offset: u64, length: u32, identifier: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            offset,
            length,
            identifier: identifier.into(),
            preview: render_preview(bytes),
        }
    }
}

/// Render matched bytes for human display without leaking control characters
/// into a log file or a GUI label.
pub fn render_preview(bytes: &[u8]) -> String {
    let mut out =
        String::with_capacity(bytes.len().min(MatchLocation::MAX_PREVIEW).saturating_add(3));
    for &b in bytes.iter().take(MatchLocation::MAX_PREVIEW) {
        match b {
            0x20..=0x7E => out.push(b as char),
            _ => out.push('.'),
        }
    }
    if bytes.len() > MatchLocation::MAX_PREVIEW {
        out.push_str("...");
    }
    out
}

/// A single reason the scanner flagged a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Stable rule identifier, e.g. `ransomware/lockbit_note`.
    pub rule_id: String,
    /// Human-readable explanation shown in the UI.
    pub description: String,
    pub severity: Severity,
    pub source: DetectionSource,
    /// Score contribution. Defaults to [`Severity::default_score`] but a rule
    /// may override it.
    pub score: u16,
    /// Structured name, when the rule attributes the finding to a known family.
    pub threat: Option<ThreatName>,
    pub locations: Vec<MatchLocation>,
    /// When true this detection alone justifies [`Verdict::Malicious`],
    /// regardless of the configured threshold. Reserved for indicators with no
    /// meaningful false-positive rate: exact hashes of known-bad samples,
    /// verified malicious signer certificates.
    pub decisive: bool,
}

impl Detection {
    pub fn new(
        rule_id: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        source: DetectionSource,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            description: description.into(),
            severity,
            source,
            score: severity.default_score(),
            threat: None,
            locations: Vec::new(),
            decisive: false,
        }
    }

    pub fn with_score(mut self, score: u16) -> Self {
        self.score = score;
        self
    }

    pub fn with_threat(mut self, threat: ThreatName) -> Self {
        self.threat = Some(threat);
        self
    }

    pub fn decisive(mut self) -> Self {
        self.decisive = true;
        self
    }

    pub fn with_location(mut self, location: MatchLocation) -> Self {
        self.locations.push(location);
        self
    }

    /// The name to show the user. Falls back to a generic name derived from the
    /// source when the rule did not attribute a family.
    pub fn display_name(&self) -> String {
        match &self.threat {
            Some(t) => t.to_string(),
            None => self.rule_id.clone(),
        }
    }
}

/// Thresholds that convert an accumulated score into a [`Verdict`].
///
/// Defaults are deliberately conservative: `Suspicious` starts low enough that
/// nothing interesting is hidden, while `Malicious` requires either a decisive
/// indicator or several independent signals agreeing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictThresholds {
    pub suspicious: u16,
    pub malicious: u16,
}

impl Default for VerdictThresholds {
    fn default() -> Self {
        Self {
            suspicious: 30,
            malicious: 100,
        }
    }
}

impl VerdictThresholds {
    /// Classify a score. A score of zero is [`Verdict::Clean`]; note that this
    /// function never returns [`Verdict::Unknown`] — that state is decided by
    /// the scanner, which knows whether it actually managed to look at the
    /// target.
    pub fn classify(&self, score: u16) -> Verdict {
        if score >= self.malicious {
            Verdict::Malicious
        } else if score >= self.suspicious {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        }
    }
}

/// The aggregated result of evaluating every detector against one target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Assessment {
    pub detections: Vec<Detection>,
    /// Sum of the score contributions of all detections, saturated at
    /// [`Assessment::MAX_SCORE`].
    pub score: u16,
    pub verdict: Verdict,
    /// Rule identifiers that matched but were suppressed because the target is
    /// trusted. Kept for auditability — users ask "why was this not detected?"
    /// far more often than they ask "why was this detected?".
    pub suppressed: Vec<String>,
}

impl Assessment {
    /// Upper bound on the accumulated score. Bounded so that a file matching
    /// hundreds of weak rules cannot overflow, and so scores stay comparable
    /// across scans.
    pub const MAX_SCORE: u16 = 1000;

    pub fn clean() -> Self {
        Self {
            detections: Vec::new(),
            score: 0,
            verdict: Verdict::Clean,
            suppressed: Vec::new(),
        }
    }

    /// A target that could not be scanned at all.
    pub fn unknown(reason: impl Into<String>) -> Self {
        let mut a = Self::clean();
        a.verdict = Verdict::Unknown;
        a.detections.push(
            Detection::new(
                "scan/incomplete",
                reason,
                Severity::Info,
                DetectionSource::Heuristic,
            )
            .with_score(0),
        );
        a
    }

    pub fn push(&mut self, detection: Detection) {
        self.score = self.score.saturating_add(detection.score).min(Self::MAX_SCORE);
        self.detections.push(detection);
    }

    /// Record that a rule matched but was overridden by trust.
    pub fn suppress(&mut self, rule_id: impl Into<String>) {
        self.suppressed.push(rule_id.into());
    }

    /// Apply thresholds (and the decisive short-circuit) to produce the final
    /// verdict. Must be called after all detections are pushed.
    pub fn finalize(&mut self, thresholds: &VerdictThresholds) {
        if self.detections.iter().any(|d| d.decisive) {
            self.verdict = Verdict::Malicious;
            return;
        }
        self.verdict = thresholds.classify(self.score);
    }

    /// Apply a trust adjustment: a negative `adjustment` reduces the score
    /// (trusted publisher, known-good path), a positive one raises it.
    ///
    /// Trust can never turn a decisive detection into a non-detection, and can
    /// never push a score below zero.
    pub fn apply_trust(&mut self, adjustment: i32) {
        if self.detections.iter().any(|d| d.decisive) {
            return;
        }
        // Saturating: `adjustment` comes from a trust provider, and a value
        // near `i32::MIN` must clamp to zero rather than wrap into a huge
        // positive score.
        let adjusted = (self.score as i32)
            .saturating_add(adjustment)
            .clamp(0, Self::MAX_SCORE as i32);
        self.score = adjusted as u16;
    }

    /// The highest severity among all detections.
    pub fn max_severity(&self) -> Option<Severity> {
        self.detections.iter().map(|d| d.severity).max()
    }

    /// The most specific threat name available, preferring detections with a
    /// higher severity.
    pub fn primary_threat(&self) -> Option<&ThreatName> {
        self.detections
            .iter()
            .filter_map(|d| d.threat.as_ref().map(|t| (d.severity, t)))
            .max_by_key(|(s, _)| *s)
            .map(|(_, t)| t)
    }

    pub fn is_detection(&self) -> bool {
        self.verdict.is_detection()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::{Platform, ThreatCategory};

    fn detection(severity: Severity) -> Detection {
        Detection::new("test/rule", "test", severity, DetectionSource::Signature)
    }

    #[test]
    fn single_low_detection_is_suspicious_but_not_malicious() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Low));
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 30);
        assert_eq!(a.verdict, Verdict::Suspicious);
    }

    #[test]
    fn medium_detection_alone_does_not_reach_malicious() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Medium));
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.verdict, Verdict::Suspicious);
    }

    #[test]
    fn two_medium_detections_cross_the_malicious_threshold() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Medium));
        a.push(detection(Severity::Medium));
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 120);
        assert_eq!(a.verdict, Verdict::Malicious);
    }

    #[test]
    fn a_single_high_detection_is_already_malicious() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::High));
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.verdict, Verdict::Malicious);
    }

    #[test]
    fn info_only_never_colours_a_verdict() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Info));
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 0);
        assert_eq!(a.verdict, Verdict::Clean);
        // The observation is still recorded for the report.
        assert_eq!(a.detections.len(), 1);
    }

    #[test]
    fn decisive_detection_wins_even_with_zero_score() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Low).with_score(1).decisive());
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.verdict, Verdict::Malicious);
    }

    #[test]
    fn trust_cannot_override_a_decisive_detection() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Critical).decisive());
        a.apply_trust(-10_000);
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.verdict, Verdict::Malicious);
    }

    #[test]
    fn trust_can_neutralise_weak_signals() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Medium));
        a.apply_trust(-60);
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 0);
        assert_eq!(a.verdict, Verdict::Clean);
    }

    #[test]
    fn partial_trust_downgrades_severity_without_erasing_the_finding() {
        // A signed binary from a reputable publisher halves the score: a High
        // signature match drops from Malicious to Suspicious but is still
        // reported.
        let mut a = Assessment::clean();
        a.push(detection(Severity::High));
        a.apply_trust(-50);
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 50);
        assert_eq!(a.verdict, Verdict::Suspicious);
        assert_eq!(a.detections.len(), 1);
    }

    #[test]
    fn trust_never_drives_the_score_negative() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Low));
        a.apply_trust(-10_000);
        assert_eq!(a.score, 0);
    }

    #[test]
    fn score_is_saturated_at_the_cap() {
        let mut a = Assessment::clean();
        for _ in 0..500 {
            a.push(detection(Severity::Critical));
        }
        assert_eq!(a.score, Assessment::MAX_SCORE);
    }

    #[test]
    fn unknown_is_distinct_from_clean() {
        let a = Assessment::unknown("password protected archive");
        assert_eq!(a.verdict, Verdict::Unknown);
        assert!(!a.verdict.is_detection());
        assert_ne!(a.verdict, Verdict::Clean);
    }

    #[test]
    fn primary_threat_prefers_the_most_severe() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Low).with_threat(ThreatName::new(
            Platform::Win32,
            ThreatCategory::Adware,
        )));
        a.push(detection(Severity::Critical).with_threat(
            ThreatName::new(Platform::Win32, ThreatCategory::Ransomware).with_family("LockBit"),
        ));
        assert_eq!(
            a.primary_threat().unwrap().to_string(),
            "Win32.Ransomware.LockBit"
        );
    }

    #[test]
    fn preview_escapes_control_bytes() {
        assert_eq!(render_preview(b"hello\x00\x01world"), "hello..world");
    }

    #[test]
    fn preview_is_capped_and_marked() {
        let long = vec![b'A'; 100];
        let preview = render_preview(&long);
        assert!(preview.ends_with("..."));
        assert_eq!(preview.len(), MatchLocation::MAX_PREVIEW + 3);
    }
}
