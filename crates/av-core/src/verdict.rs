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
    /// True when something fired, whether or not it is enough to act on.
    ///
    /// The distinction from [`Verdict::blocks`] is the whole of the product's
    /// escalation policy, and the two are read by different callers on purpose:
    /// this one decides whether the user is told, that one decides whether
    /// anything is *done*. A notification fires for both bands; only the upper
    /// one moves a file or refuses a script.
    pub const fn is_detection(self) -> bool {
        matches!(self, Verdict::Suspicious | Verdict::Malicious)
    }

    /// True when this verdict justifies acting — taking a file, refusing to let
    /// a script run.
    ///
    /// # The three bands, and why this predicate exists rather than a `==`
    ///
    /// * `Malicious` is the red band: the engine is prepared to say so, and the
    ///   product acts.
    /// * `Suspicious` is the yellow band: enough fired to be worth telling the
    ///   user, not enough to justify removing a file they may have written
    ///   themselves. It **warns and never acts**.
    /// * `Clean` and `Unknown` are not the same thing — an unreadable file is
    ///   not a clean one — and neither is grounds for acting.
    ///
    /// Written once here because it used to be written twice. [`Verdict`] is
    /// read by an AMSI provider deciding whether to answer `AMSI_RESULT_DETECTED`
    /// and by the service deciding whether to move a file into the vault, and
    /// two spellings of "the yellow band does not act" is one spelling that
    /// quietly stops agreeing with the other. The AMSI provider was the second
    /// reader, and it is the reason this moved down here: a `Suspicious` script
    /// answered with `Detected` would have a host refuse to run content this
    /// product's own policy says it must not refuse.
    pub const fn blocks(self) -> bool {
        match self {
            Verdict::Malicious => true,
            // Spelled out rather than `_ => false` so that a variant added
            // upstream stops this build and forces the question to be asked.
            Verdict::Suspicious | Verdict::Clean | Verdict::Unknown => false,
        }
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
    ///
    /// When [`MatchLocation::container`] is set this is an offset into the
    /// archive *member*, not into the file on disk — the file on disk is the
    /// archive, and an offset into a compressed stream names nothing a reader
    /// could go and look at.
    pub offset: u64,
    pub length: u32,
    /// The rule string identifier that matched (`$a`, `$str1`, ...).
    pub identifier: String,
    /// A short, safe rendering of the matched bytes: printable ASCII is kept,
    /// everything else becomes `.`. Capped in length so a rule matching a large
    /// region cannot blow up the report.
    pub preview: String,
    /// The archive member this offset is inside, when the match was found
    /// inside an archive rather than in the file's own bytes.
    ///
    /// `None` — the overwhelmingly common case — means the offset is from the
    /// start of the file on disk. When it is set, the name is the chain of
    /// member names from the outermost archive down, joined with `/`:
    /// `payload/inner.exe` for a file directly inside the scanned archive, and
    /// `outer.zip/inner.exe` for one a level further down. Forward slashes
    /// throughout, whatever separator the archive itself used, because a name
    /// inside an archive is not a path on the machine reading it — and a name
    /// built from a backslash would read as one.
    pub container: Option<String>,
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
            container: None,
        }
    }

    /// Record that this match was found inside an archive member.
    ///
    /// The offset is the caller's to re-base: a location inside a member
    /// carries an offset into that member, and this method only names which
    /// member it was.
    #[must_use]
    pub fn within(mut self, member: impl Into<String>) -> Self {
        self.container = Some(member.into());
        self
    }
}

/// Render matched bytes for human display without leaking control characters
/// into a log file or a GUI label.
pub fn render_preview(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(
        bytes
            .len()
            .min(MatchLocation::MAX_PREVIEW)
            .saturating_add(3),
    );
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
    /// When true, evidence about who published the file may not argue with this
    /// detection — see [`Self::decisive`] for the axis this is *not*.
    ///
    /// # Two axes, and why they are not one
    ///
    /// [`Self::decisive`] is arithmetic: this detection does not need the rest
    /// of the list to agree before the verdict may act, so one rule can convict
    /// where ten weak ones could not. This field is epistemic: no other
    /// evidence may overrule it, so trust cannot discount it, cap it, or call a
    /// file clean because of it.
    ///
    /// They come apart because a rule can be decisive on a *reading* of itself
    /// rather than on its author's rating, and there are two such readings.
    ///
    /// The first is the title. A rule whose name identifies a family and one of
    /// its instances (`SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1`) convicts on
    /// its own — that is the point of reading the name — while its author's own
    /// rating of that rule was ordinary, and an ordinary rating is not a claim
    /// about a particular file that a publisher's verified signature cannot
    /// answer.
    ///
    /// The second is the condition. A rule saying `$marker` where `$marker` is
    /// a twenty-byte build string convicts on its own for the same reason and
    /// by a different route: nothing ordinary contains that string, so the
    /// condition is a claim about *this* sample even when the rule's name is a
    /// bare family label and its rating is unremarkable. Whether a condition is
    /// of that kind is decided in `av_rules::content`, by an algebra over the
    /// strings the condition can be satisfied by — not by anything in the
    /// rule's metadata.
    ///
    /// The distinction is load-bearing, and it was measured rather than
    /// reasoned: the rule above, an IOC rule for a *Linux and macOS* LockBit
    /// variant, matched `System32\MRT.exe` — Microsoft's Malicious Software
    /// Removal Tool, a signed Microsoft binary, whose own signature database
    /// holds that malware's URLs XOR-encoded so that it can recognise them.
    /// Without this field the match was incontestable and the file was reported
    /// malicious, which on a clean Windows machine means the removal tool is
    /// one click from quarantine. A title is not worth that; a hash is, and an
    /// author's own rating of `decisive` is.
    ///
    /// Invariant: `incontestable` implies `decisive`. Nothing may be beyond
    /// argument and still need corroboration.
    #[serde(default)]
    pub incontestable: bool,
    /// The archive member this finding is about, when it is about one.
    ///
    /// The same chain [`MatchLocation::container`] carries, and stated here as
    /// well because the two answer different questions. A location's container
    /// says what its offset is an offset *into*; this says what the finding is
    /// *about*, and it is set even when there are no locations at all — which is
    /// the ordinary case for a rule whose condition is structural, such as one
    /// that reads a PE header field. A detection with no locations and no
    /// container is a finding about the file; a detection with no locations and
    /// a container is a finding about a member of it, and a report that could
    /// not tell those apart would point a user at the wrong file.
    #[serde(default)]
    pub container: Option<String>,
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
            incontestable: false,
            container: None,
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

    /// Make this detection convict on its own, and leave it open to argument by
    /// evidence about who published the file.
    ///
    /// This is the builder for a detection that is decisive on a *name* — see
    /// [`Self::incontestable`]. Anything decisive on a *rating* must chain
    /// [`Self::incontestable`] after it, because a rule the author rated
    /// decisive is a claim about the sample and a certificate is not an answer
    /// to it.
    pub fn decisive(mut self) -> Self {
        self.decisive = true;
        self
    }

    /// Make this detection beyond trust's reach, as well as decisive.
    ///
    /// Sets [`Self::decisive`] as well, because the two are not independent:
    /// nothing is incontestable and still short of deciding the verdict.
    pub fn incontestable(mut self) -> Self {
        self.decisive = true;
        self.incontestable = true;
        self
    }

    pub fn with_location(mut self, location: MatchLocation) -> Self {
        self.locations.push(location);
        self
    }

    /// Record that this finding is about a member of an archive rather than
    /// about the file on disk.
    ///
    /// Every location the detection already carries is re-based onto the same
    /// member, because a detection's locations are all inside its subject — a
    /// rule was run against one buffer and every offset it reported is an offset
    /// into that buffer.
    #[must_use]
    pub fn within(mut self, container: impl Into<String>) -> Self {
        let container = container.into();
        for location in &mut self.locations {
            location.container = Some(container.clone());
        }
        self.container = Some(container);
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
    /// Whether trust held the verdict out of the band that acts on a file.
    ///
    /// Distinct from [`Assessment::suppressed`], which is about detections that
    /// were thrown away. Nothing is thrown away here: every detection is still
    /// listed and the score is still whatever it was. What changed is the band
    /// the score is read in — and a report that showed only "suspicious" would
    /// leave a user unable to tell "nothing worse than this was found" from
    /// "worse was found and deliberately not acted on", which are different
    /// answers to "why did you not remove this?".
    #[serde(default)]
    pub remediation_withheld: bool,
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
            remediation_withheld: false,
        }
    }

    /// Record that the verdict was held out of the remediated band.
    ///
    /// Lowering the verdict is the caller's job — this only records that it
    /// happened, so the two cannot drift apart in a report.
    pub fn withhold_remediation(&mut self) {
        self.remediation_withheld = true;
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
        self.score = self
            .score
            .saturating_add(detection.score)
            .min(Self::MAX_SCORE);
        self.detections.push(detection);
    }

    /// Record that a rule matched but was overridden by trust.
    pub fn suppress(&mut self, rule_id: impl Into<String>) {
        self.suppressed.push(rule_id.into());
    }

    /// Apply thresholds (and the decisive short-circuit) to produce the final
    /// verdict. Must be called after all detections are pushed.
    ///
    /// # The band that acts needs one signal that would have acted alone
    ///
    /// Accumulation reaches [`Verdict::Suspicious`] and stops there. A total
    /// over the malicious threshold is not by itself enough: some single
    /// detection in the assessment must reach that same threshold on its own,
    /// or be decisive, or the verdict is capped one band below.
    ///
    /// The reason is what the two bands *do*. `Suspicious` is reported and
    /// nothing else — no file moves, no write is refused. `Malicious` is the
    /// band [`Verdict::blocks`] answers true for, and it is what quarantine, the
    /// real-time watcher and the driver act on. A report that is wrong is a
    /// nuisance; a quarantine that is wrong takes a file the user needs and puts
    /// it somewhere they did not ask for. The two bands do not deserve the same
    /// standard of proof and this is where they stop sharing one.
    ///
    /// So the question asked here is not "is the total high enough" but "did
    /// anything here recognise this file". Ten weak signals agreeing is evidence
    /// that a file is *shaped* like something, which is a true thing to tell a
    /// user and not a thing to act on. The measured difference is sharp: before
    /// this rule existed, 86% of the rule set this product ships weighed 75
    /// points against a 100-point threshold, so **any two rules matching one
    /// file convicted it**, and a scan of a user's own downloads produced
    /// detections on a CMake release archive and a GitHub Desktop installer.
    /// Calibration in the rule compiler fixes what one ordinary rule is worth;
    /// this fixes what a pile of them can do.
    ///
    /// Nothing that could convict alone loses the ability to. A decisive
    /// detection short-circuits above. A blocklist hit is `Critical` and
    /// decisive. A rule genuinely confident on its own weighs at
    /// [`Severity::High`]'s rung or above. And trust, which may only ever argue
    /// a file down, is applied after this and cannot lift one back up.
    pub fn finalize(&mut self, thresholds: &VerdictThresholds) {
        if self.detections.iter().any(|d| d.decisive) {
            self.verdict = Verdict::Malicious;
            return;
        }
        let mut verdict = thresholds.classify(self.score);
        if verdict == Verdict::Malicious
            && !self
                .detections
                .iter()
                .any(|d| d.score >= thresholds.malicious)
        {
            verdict = Verdict::Suspicious;
        }
        self.verdict = verdict;
    }

    /// Discount the score by evidence that the target is trustworthy — a
    /// trusted publisher, a known-good path, a catalog listing.
    ///
    /// The parameter is a *magnitude* and is subtracted. That is the whole
    /// design, not a convenience: trust may only ever argue a file *down*, so
    /// there is deliberately no way to express a bonus. Every route from the
    /// suspicious band to the malicious band has to run through a detector that
    /// claims to recognise *this* sample. Evidence about who published a file
    /// cannot corroborate a detection — if it could, a signed sample would be
    /// easier to convict than an unsigned one, which is the wrong way round.
    ///
    /// An **incontestable** detection is not discounted at all: it has already
    /// decided the verdict, and it is the detection rather than the score that
    /// carries it. A decisive-but-contestable one is discounted like anything
    /// else, because what took it past the threshold was this product's own
    /// reading of the rule — its title, or the shape of its condition — and a
    /// reading is a claim evidence about the publisher has standing on — see
    /// [`Detection::incontestable`].
    pub fn apply_trust(&mut self, discount: u16) {
        if self.detections.iter().any(|d| d.incontestable) {
            return;
        }
        // Saturating, so a discount larger than the score floors at zero rather
        // than wrapping into a large positive one.
        self.score = self.score.saturating_sub(discount);
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
    fn two_medium_detections_cross_the_threshold_and_still_do_not_convict() {
        // The reversal, and it is the whole point of the rule in `finalize`.
        // Two `Medium` detections total 120 against a threshold of 100, so the
        // arithmetic crosses the line — and neither reaches the line on its
        // own, so the verdict stops one band lower. Before this, the arithmetic
        // was the entire decision, which is what let 86% of a 10,764-rule
        // corpus weigh 75 points against a 100-point threshold and convict a
        // file on any two matches.
        let mut a = Assessment::clean();
        a.push(detection(Severity::Medium));
        a.push(detection(Severity::Medium));
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 120, "the score is still the arithmetic");
        assert_eq!(
            a.verdict,
            Verdict::Suspicious,
            "but the band that acts needs one signal that would have acted alone"
        );
    }

    #[test]
    fn a_pile_of_weak_signals_never_convicts_however_high_it_gets() {
        // Ten `Low` is 300, three times the threshold, and still one band below
        // it. This is the shape a scan of a user's own downloads produced: five
        // pack and import heuristics agreeing about a CMake release archive.
        let mut a = Assessment::clean();
        for _ in 0..10 {
            a.push(detection(Severity::Low));
        }
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 300);
        assert_eq!(a.verdict, Verdict::Suspicious);
    }

    #[test]
    fn one_confident_signal_carries_a_pile_of_weak_ones_over_the_line() {
        // The other direction, and the reason the rule is not "weak signals
        // never convict". A file that trips a heuristic and *also* matches a
        // rule its author was confident about is a file to act on; what the
        // rule forbids is convicting on the pile alone.
        let mut a = Assessment::clean();
        a.push(detection(Severity::Low));
        a.push(detection(Severity::High));
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 130);
        assert_eq!(a.verdict, Verdict::Malicious);
    }

    #[test]
    fn the_rung_a_signal_must_reach_is_the_configured_threshold() {
        // Not a hard-coded `High`. An operator who raises the threshold to 150
        // is saying that only a `Critical` match convicts on its own, and the
        // rule reads the threshold rather than the ladder's default rung.
        let raised = VerdictThresholds {
            suspicious: 30,
            malicious: 150,
        };
        let mut a = Assessment::clean();
        a.push(detection(Severity::High));
        a.finalize(&raised);
        assert_eq!(a.score, 100);
        assert_eq!(a.verdict, Verdict::Suspicious, "100 no longer reaches it");

        let mut b = Assessment::clean();
        b.push(detection(Severity::Critical));
        b.finalize(&raised);
        assert_eq!(b.verdict, Verdict::Malicious);
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
    fn trust_cannot_override_an_incontestable_detection() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Critical).incontestable());
        a.apply_trust(u16::MAX);
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.verdict, Verdict::Malicious);
    }

    /// The two axes, and the case they were told apart for.
    ///
    /// Decisive is arithmetic — one rule is enough, so the verdict acts.
    /// Incontestable is epistemic — no other evidence may answer it. A rule
    /// this product convicts on a *reading* of — its name, or a condition
    /// nothing ordinary satisfies — is the first without being the second, and
    /// this test is the whole of that claim in four lines.
    #[test]
    fn a_decisive_detection_is_not_necessarily_incontestable() {
        let mut read = Assessment::clean();
        read.push(detection(Severity::High).decisive());
        assert!(read.detections[0].decisive);
        assert!(!read.detections[0].incontestable);
        read.finalize(&VerdictThresholds::default());
        assert_eq!(read.verdict, Verdict::Malicious, "it convicts alone");
        read.apply_trust(60);
        assert_eq!(read.score, 40, "and trust can still take its points");

        let mut rated = Assessment::clean();
        rated.push(detection(Severity::High).incontestable());
        assert!(rated.detections[0].decisive, "incontestable implies decisive");
        rated.apply_trust(60);
        assert_eq!(rated.score, 100, "trust has no standing here");
    }

    #[test]
    fn trust_can_neutralise_weak_signals() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Medium));
        a.apply_trust(60);
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
        a.apply_trust(50);
        a.finalize(&VerdictThresholds::default());
        assert_eq!(a.score, 50);
        assert_eq!(a.verdict, Verdict::Suspicious);
        assert_eq!(a.detections.len(), 1);
    }

    #[test]
    fn trust_never_drives_the_score_negative() {
        let mut a = Assessment::clean();
        a.push(detection(Severity::Low));
        a.apply_trust(u16::MAX);
        assert_eq!(a.score, 0);
    }

    #[test]
    fn trust_can_only_ever_lower_the_score() {
        // The policy this pins down: evidence about *who published* a file may
        // argue it down and never up. Every route into the malicious band runs
        // through a detector claiming to recognise the sample itself, because
        // the alternative — a signed file being easier to convict than an
        // unsigned one — is the wrong way round. `apply_trust` takes a
        // magnitude and subtracts it, so there is no value a caller could pass
        // to raise a score; this test exists so that changing the parameter back
        // to a signed one has to delete a failing test rather than pass quietly.
        let mut a = Assessment::clean();
        a.push(detection(Severity::Critical));
        let before = a.score;
        for discount in [0u16, 1, 50, u16::MAX] {
            a.apply_trust(discount);
            assert!(
                a.score <= before,
                "a discount of {discount} raised the score from {before} to {}",
                a.score
            );
            a.score = before;
        }
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
        a.push(
            detection(Severity::Low)
                .with_threat(ThreatName::new(Platform::Win32, ThreatCategory::Adware)),
        );
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

    #[test]
    fn only_the_red_band_acts_and_the_yellow_band_is_still_a_detection() {
        // The two questions, side by side, because the whole point of having
        // both is that they give different answers to the same verdict. A
        // `Suspicious` file is reported to the user and is not touched; a
        // `Clean` one is neither.
        assert!(Verdict::Malicious.blocks());
        assert!(!Verdict::Suspicious.blocks());
        assert!(!Verdict::Clean.blocks());
        assert!(!Verdict::Unknown.blocks());

        assert!(Verdict::Malicious.is_detection());
        assert!(Verdict::Suspicious.is_detection());
        assert!(!Verdict::Clean.is_detection());
        // An unreadable file is not a detection and is emphatically not clean.
        // `blocks` answering `false` for it is the honest answer — there is
        // nothing to act on — and not a claim that it is safe.
        assert!(!Verdict::Unknown.is_detection());
        assert_ne!(Verdict::Unknown, Verdict::Clean);
    }
}
