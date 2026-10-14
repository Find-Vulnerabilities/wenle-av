//! Turning a rule match into a detection.
//!
//! The rule engine answers whether a condition held. What that *means* — how
//! much it is worth, what to call it, which bytes to show the user — is a
//! question about this product rather than about the rule language, and it
//! lives here.
//!
//! # Score, severity and decisiveness all come from the rule's own metadata
//!
//! Nothing is inferred *here* from the rule's name, its tags or its string
//! count. A rule that declares `severity = high` is worth what its author said
//! it was worth, and a rule that declares nothing takes
//! [`av_core::Severity::Medium`] — which is a claim the author has to live
//! with, because a rule that contributed nothing to a verdict would be a rule
//! that could never be noticed.
//!
//! The metadata this module reads has already been calibrated, and calibration
//! does read a rule's name — [`av_rules::family`] — for the one question the
//! corpus's own fields cannot answer: whether a rule identifies a named
//! instance of a family or only the family. This module's job is to carry the
//! result across, including the distinction between a rule its author rated
//! decisive and one that is merely decisive on its title.
//!
//! # What is capped, and why
//!
//! The number of locations reported per detection. A rule with two hundred
//! strings can match in two hundred places, and a report that lists all of them
//! is a report nobody reads and a serialised record nobody wants. The first
//! few, in the order the file held them, are enough to show what the rule
//! recognised and where.

use av_core::{Detection, DetectionSource, MatchLocation};
use av_rules::database::CompiledRule;
use av_rules::matches::Match;
use av_rules::scanner::RuleMatch;

/// How many match locations one detection carries.
pub const MAX_LOCATIONS: usize = 8;

/// The detection a rule match represents.
///
/// `data` is the buffer the rule was run against, and is used only to render
/// the matched bytes; every offset is bounds-checked against it, because an
/// offset that came out of a matcher is still a number derived from a file.
pub fn detection(rule: &CompiledRule, matched: &RuleMatch, data: &[u8]) -> Detection {
    let metadata = &rule.metadata;
    let mut detection = Detection::new(
        rule.name.clone(),
        describe(rule),
        metadata.effective_severity(),
        DetectionSource::Signature,
    )
    .with_score(metadata.score());
    if metadata.decisive {
        // Two routes reach here and they are not the same claim: a rule its
        // author rated decisive, and a rule whose *name* identifies a family
        // and one of its instances. Both convict alone; only the first is
        // beyond trust's reach. See [`av_core::Detection::incontestable`].
        detection = detection.decisive();
        if metadata.incontestable {
            detection = detection.incontestable();
        }
    }
    if let Some(threat) = metadata.threat() {
        detection = detection.with_threat(threat);
    }
    for location in locations(rule, matched, data) {
        detection = detection.with_location(location);
    }
    detection
}

/// What to tell the user the rule found.
///
/// The author's own description when there is one, because it is the only text
/// that knows what the rule was written for. When there is not, a sentence
/// naming what the rule identified — and never the rule's name left to stand
/// alone as a description, which is what a report looks like when nobody wrote
/// the second half of it.
fn describe(rule: &CompiledRule) -> String {
    if let Some(text) = &rule.metadata.description {
        return text.clone();
    }
    match rule.metadata.threat() {
        Some(threat) => format!("The file matches a rule identifying {threat}."),
        None => format!("The rule `{}` matched this file.", rule.name),
    }
}

/// Where each of the rule's strings was found, up to [`MAX_LOCATIONS`].
///
/// A rule whose condition is entirely structural — `pe.entry_point > ...` — has
/// no strings and therefore no locations. That is not a gap: the detection is
/// still reported, with the rule's own description, and a caller that wants to
/// show the user where in the file it applies has the rule's condition text.
fn locations(rule: &CompiledRule, matched: &RuleMatch, data: &[u8]) -> Vec<MatchLocation> {
    let mut out = Vec::new();
    for slot in 0..rule.program.string_count {
        for m in matched.strings.matches(slot) {
            if out.len() >= MAX_LOCATIONS {
                return out;
            }
            out.push(location(rule, slot, m, data));
        }
    }
    out
}

/// One match, rendered.
fn location(rule: &CompiledRule, slot: u32, m: &Match, data: &[u8]) -> MatchLocation {
    let start = m.offset as usize;
    let end = start.saturating_add(m.length as usize).min(data.len());
    // `start` can be past the end of the buffer when the match came from
    // something other than a byte search, and `get` returns `None` for an
    // inverted range as well as an out-of-bounds one — which is what makes this
    // one call rather than three checks.
    let bytes = data.get(start..end).unwrap_or(&[]);
    MatchLocation::new(
        u64::from(m.offset),
        m.length,
        rule.string_id(slot).unwrap_or("$?"),
        bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_rules::database::RuleDatabase;

    /// Compile a one-rule source and return the database, so that the metadata
    /// under test is the metadata a real rule produces rather than a struct
    /// built by hand.
    fn compile(source: &str) -> RuleDatabase {
        let (database, report) = RuleDatabase::compile(source);
        assert_eq!(report.refusals.len(), 0, "{:?}", report.refusals);
        assert_eq!(database.len(), 1, "expected one rule");
        database
    }

    fn matched(rule: &CompiledRule, slots: &[(u32, u32, u32)]) -> RuleMatch {
        let mut strings =
            av_rules::matches::MatchSet::with_capacity(rule.program.string_count as usize);
        for &(slot, offset, length) in slots {
            strings.push(slot, Match::new(offset, length));
        }
        strings.sort();
        RuleMatch {
            rule: 0,
            strings,
            role: av_rules::scanner::MatchRole::Detection,
        }
    }

    const DECLARED: &str = r#"
rule declared {
    meta:
        description = "A file that does the thing this rule is about."
        severity = "high"
        category = "trojan"
        family = "Emotet"
        weight = 120
    strings:
        $a = "needle"
    condition:
        $a
}
"#;

    #[test]
    fn a_rule_with_declarations_produces_what_it_declared() {
        let database = compile(DECLARED);
        let rule = &database.rules()[0];
        let detection = detection(
            rule,
            &matched(rule, &[(0, 16, 6)]),
            b"................needle....",
        );
        assert_eq!(detection.rule_id, "declared");
        assert_eq!(
            detection.description,
            "A file that does the thing this rule is about."
        );
        assert_eq!(detection.severity, av_core::Severity::High);
        // The explicit weight overrides the severity's default of 100.
        assert_eq!(detection.score, 120);
        assert_eq!(detection.source, DetectionSource::Signature);
        assert!(!detection.decisive);
        let threat = detection.threat.as_ref().expect("a category was declared");
        assert_eq!(threat.family.as_deref(), Some("Emotet"));
        assert_eq!(detection.display_name(), threat.to_string());
    }

    #[test]
    fn a_rule_with_no_declarations_still_says_something() {
        let database = compile("rule bare {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let rule = &database.rules()[0];
        let detection = detection(rule, &matched(rule, &[(0, 0, 1)]), b"x");
        // An undeclared severity is Medium, which is 60 and enough to be
        // noticed, rather than Info, which is zero and would make the rule
        // inert.
        assert_eq!(detection.severity, av_core::Severity::Medium);
        assert_eq!(detection.score, 60);
        assert!(detection.threat.is_none());
        assert!(
            detection.description.contains("bare"),
            "{}",
            detection.description
        );
    }

    #[test]
    fn the_matched_bytes_reach_the_report() {
        let database = compile(DECLARED);
        let rule = &database.rules()[0];
        let data = b"................needle....";
        let detection = detection(rule, &matched(rule, &[(0, 16, 6)]), data);
        let location = detection.locations.first().expect("one location");
        assert_eq!(location.offset, 16);
        assert_eq!(location.length, 6);
        assert_eq!(location.preview, "needle");
    }

    #[test]
    fn a_match_that_runs_past_the_buffer_is_clamped_rather_than_panicking() {
        // The offset came out of a matcher, but a matcher ran against a buffer
        // that a caller could have changed under it. Reading past the end would
        // be a panic in the scan path, which is the one place it must not be.
        let database = compile(DECLARED);
        let rule = &database.rules()[0];
        let detection = detection(rule, &matched(rule, &[(0, 4, 4096)]), b"abc");
        let location = detection.locations.first().expect("one location");
        assert_eq!(location.offset, 4);
        assert_eq!(location.preview, "", "nothing readable at that offset");
    }

    #[test]
    fn a_rule_with_no_strings_has_no_locations_and_is_still_a_detection() {
        let database = compile("rule structural {\n condition:\n  uint16(0) == 0x5A4D\n}");
        let rule = &database.rules()[0];
        assert_eq!(rule.program.string_count, 0);
        let detection = detection(rule, &matched(rule, &[]), b"MZ");
        assert!(detection.locations.is_empty());
        assert!(detection.score > 0);
        assert!(!detection.description.is_empty());
    }

    #[test]
    fn the_number_of_locations_is_capped() {
        // Twenty occurrences, eight reported. The cap is what keeps a report
        // about one file from being a report about one rule's string table.
        let database = compile(DECLARED);
        let rule = &database.rules()[0];
        let occurrences: Vec<(u32, u32, u32)> =
            (0..20).map(|i| (0u32, i as u32 * 8, 6u32)).collect();
        let data = vec![b'.'; 8 * 20 + 8];
        let detection = detection(rule, &matched(rule, &occurrences), &data);
        assert_eq!(detection.locations.len(), MAX_LOCATIONS);
        // And the ones reported are the first in the buffer, not an arbitrary
        // subset chosen by the matcher's internal order.
        let offsets: Vec<u64> = detection.locations.iter().map(|l| l.offset).collect();
        assert_eq!(offsets, vec![0, 8, 16, 24, 32, 40, 48, 56]);
    }

    #[test]
    fn a_decisive_rule_produces_a_decisive_detection() {
        let database = compile(
            "rule certain {\n meta:\n  decisive = true\n  severity = \"critical\"\n condition:\n  true\n}",
        );
        let rule = &database.rules()[0];
        let detection = detection(rule, &matched(rule, &[]), b"");
        assert!(detection.decisive);
        assert_eq!(detection.score, 150);
    }
}
