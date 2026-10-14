//! What a rule is, and the namespace its identifiers live in.
//!
//! # One rule, one behaviour
//!
//! A rule here is not a pattern and not a family. It is a behaviour the sample's
//! structure implies — "it arranges to run at boot by two independent
//! mechanisms" — plus the severity that behaviour carries, plus a function that
//! decides whether this sample has it. Behaviour rather than identity is the
//! whole point of the crate: a sample whose bytes match nothing in a signature
//! database still has to *do* something, and doing something leaves a shape in
//! the import table, the resources and the strings that is far more expensive
//! to change than a hash.
//!
//! # The identifier namespace
//!
//! `sandbox/<class>/<behaviour>`, lower case and hyphenated, the same shape as
//! the heuristic identifiers in `av-scan` (`heuristic/imports/process-injection`,
//! `heuristic/packed/section-entropy`). The `sandbox/` prefix is what keeps a
//! behaviour rule distinguishable from a heuristic rule in a report and in a
//! user's exclusion list, which is the only thing that prefix is for.
//!
//! The classes in use:
//!
//! | Class | The kind of behaviour |
//! |-------|-----------------------|
//! | `persistence` | survives a reboot or a logon — **no rule uses this class** |
//! | `evasion` | avoids, disables or blinds something that would stop it |
//! | `dropper` | carries and starts another program |
//! | `credential` | takes secrets the user did not give it |
//! | `anti-analysis` | behaves differently when it thinks it is watched |
//! | `impact` | destroys data |
//! | `lateral-movement` | reaches another machine |
//!
//! `persistence` is listed without a rule behind it on purpose. Every form of
//! that behaviour which can be written from structure was measured against the
//! machine's own software and fired on ordinary Windows binaries — the counts
//! are in [`crate::rules`] — so no rule was shipped for it. The class stays
//! because a class is half of an identifier and an identifier is permanent: a
//! rule about boot persistence filed under `evasion` because `persistence` had
//! been deleted would be a rule nobody looking for persistence would find.
//!
//! An identifier is permanent. It is what an exclusion list holds and what a
//! support conversation quotes, so a rule that is deleted leaves its identifier
//! unused rather than handing it to a different behaviour — an exclusion the
//! user wrote for one thing must never silently come to mean another.
//!
//! # Severity, and why nothing here is decisive
//!
//! Every rule carries an [`av_core::Severity`] and scores
//! [`Severity::default_score`], so a behaviour finding is banded by exactly the
//! same two thresholds as a signature match: a `Low` observation notifies, a
//! `High` one acts. No rule in this crate is
//! [`decisive`](av_core::Detection::decisive) and none may become so: a
//! decisive detection acts on a file regardless of thresholds, which is only
//! defensible for evidence with no meaningful false-positive rate — an exact
//! hash, a verified malicious signer. A judgement about behaviour inferred from
//! a file's structure is not that, however strong it is.
//!
//! # No family names
//!
//! Rules here never set [`av_core::Detection::threat`]. A behaviour is not a
//! family, and a report that named a family on the strength of an import table
//! would be inventing attribution the evidence does not support. The field is
//! left empty for a signature rule to fill in when one matches the same sample.

use av_core::{Detection, DetectionSource, MatchLocation, Severity};

use crate::evidence::{Evidence, TextMatch};

/// One behaviour, and how to decide whether a sample has it.
///
/// Constructed only in `crate::rules`, where the table lives, because a rule
/// whose behaviour and condition are written in different files is a rule whose
/// doc comment stops being true.
#[derive(Debug)]
pub struct Rule {
    /// Stable identifier, `sandbox/<class>/<behaviour>`.
    pub id: &'static str,
    /// What the sample is judged to do, as a clause: lowercase, no full stop,
    /// phrased as something the program *does* rather than something it *is*.
    /// A report reads it after the identifier, and a user decides what to do
    /// from it, so "installs a service and a logon entry to survive a reboot"
    /// is right and "suspicious" is not.
    pub behaviour: &'static str,
    /// The severity the behaviour carries on its own.
    pub severity: Severity,
    /// The condition.
    ///
    /// A function pointer rather than a boxed closure so the whole table can be
    /// a `static`: there is no state here, and a rule that needed state would
    /// be a rule that could differ between two scans of one file.
    condition: for<'a> fn(&Evidence<'a>) -> Option<Trigger>,
}

impl Rule {
    /// Build a rule. Public because [`crate::rules::RULES`] is built from it,
    /// and documented because a rule that is not in that table is not run.
    pub const fn new(
        id: &'static str,
        behaviour: &'static str,
        severity: Severity,
        condition: for<'a> fn(&Evidence<'a>) -> Option<Trigger>,
    ) -> Self {
        Self {
            id,
            behaviour,
            severity,
            condition,
        }
    }

    /// Whether this sample has the behaviour, and what it was in the sample
    /// that says so.
    pub fn evaluate(&self, evidence: &Evidence<'_>) -> Option<Detection> {
        let trigger = (self.condition)(evidence)?;
        let mut detection = Detection::new(
            self.id,
            self.description(&trigger),
            self.severity,
            DetectionSource::Behavior,
        );
        if let Some(location) = trigger.location {
            detection = detection.with_location(location);
        }
        Some(detection)
    }

    /// The sentence a report shows.
    ///
    /// The detail is not decoration: two findings with the same identifier are
    /// indistinguishable in a report without it, and "names a security product"
    /// is an assertion where "names a security product: `windefend`" is a
    /// statement the user can check.
    fn description(&self, trigger: &Trigger) -> String {
        if trigger.detail.is_empty() {
            self.behaviour.to_string()
        } else {
            format!("{}: {}", self.behaviour, trigger.detail)
        }
    }
}

/// What a rule matched on: a short phrase for the report, and where in the
/// sample it is.
///
/// Rules build one of these when their condition is satisfied, so the finding
/// carries evidence rather than only an assertion.
#[derive(Debug, Clone)]
pub struct Trigger {
    /// A phrase naming what was found, appended to the rule's behaviour in the
    /// description: a symbol name, a string, "an executable in a resource".
    pub detail: String,
    /// Where it is, when it is somewhere.
    ///
    /// `None` for a finding about the file as a whole — a combination of imports
    /// is not at an offset, and `av_core` documents that a structural detection
    /// has no locations rather than an invented one.
    pub location: Option<MatchLocation>,
}

impl Trigger {
    /// A trigger found at a known place in the sample's bytes.
    pub(crate) fn at(
        evidence: &Evidence<'_>,
        offset: u64,
        length: usize,
        identifier: &str,
    ) -> Self {
        let length_u32 = u32::try_from(length).unwrap_or(u32::MAX);
        let end = offset.saturating_add(u64::from(length_u32));
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let end = usize::try_from(end).unwrap_or(usize::MAX);
        let bytes = evidence.data().get(start..end).unwrap_or_default();
        Self {
            detail: identifier.to_string(),
            location: Some(MatchLocation::new(offset, length_u32, identifier, bytes)),
        }
    }

    /// A trigger that is a name found in the sample, in whichever spelling.
    pub(crate) fn text(evidence: &Evidence<'_>, needle: &str, found: TextMatch) -> Self {
        let identifier = if found.wide {
            format!("{needle} (utf-16le)")
        } else {
            needle.to_string()
        };
        Self::at(
            evidence,
            found.offset as u64,
            found.byte_length(needle),
            &identifier,
        )
    }

    /// A trigger that is a combination of facts rather than a place.
    ///
    /// The detail names the symbols, because "it imports the symbols that dump
    /// another process's memory: MiniDumpWriteDump" is checkable and "it dumps
    /// memory" is not.
    pub(crate) fn structural(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            location: None,
        }
    }
}
