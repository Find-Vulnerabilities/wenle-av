//! What a rule's *condition* demands, read as evidence about the rule.
//!
//! # Why the condition, and not a field
//!
//! [`crate::family`] reads a rule's name and separates a signature from a
//! family-wide hunt. That reading covers 1,396 rules. It cannot cover this one:
//!
//! ```text
//! rule CAPE_Azorult {
//!     strings:
//!         $code1 = {C7 07 3C 00 00 00 8D 45 80 ...}          // 110 bytes of code
//!         $string1 = "SELECT DATETIME( ((visits.visit_time/1000000)-11644473600),\"unixepoch\")"
//!     condition:
//!         uint16( 0 ) == 0x5A4D and all of them
//! }
//! ```
//!
//! Its `score` is 75, so [`crate::calibrate`]'s bands put it at 60. Its
//! `quality` is 70, below [`crate::calibrate::DECISIVE_QUALITY`], so the rating
//! route passes it by. Its name names a family and no instance of it, so
//! [`crate::family`] reads it as [`crate::family::Claim::Family`] and the name
//! route passes it by too. It is reported `Suspicious` — a band that never acts
//! — while its condition says a file cannot satisfy it without carrying a
//! hundred and ten bytes of Azorult's own code.
//!
//! **The condition knows what the name does not say.** That is what this module
//! reads, and it is the third route to a conviction.
//!
//! # The question, and why it is not "how long are the strings"
//!
//! Asking whether a rule has a long string in it is the wrong question, and the
//! measurement says so: **71.7% of the corpus has a string of 24 bytes or more**,
//! so a reading that promoted on string length would make most of the corpus
//! convict on its own. That is the false-positive disaster
//! [`crate::calibrate::weight_for`] exists to prevent, arrived at from the other
//! side.
//!
//! Length is still the proxy the walk uses for a *single* string, because a
//! local reading has nothing else to go on, and `MIN_SPECIFIC` records what
//! the proxy cost when it was set too low. What this module owes the reader is
//! the shape of the condition; what it cannot know is whether a string that
//! clears the line is rare in the world. That is a question only a scan of real
//! software answers, and it is answered outside this file.
//!
//! The question is whether a file can satisfy the condition **without** carrying
//! anything specific. A condition is a tree of `and`, `or`, and quantifiers over
//! string sets, and it demands a specific indicator exactly when *every* path
//! through it passes through one. Two rules with the same strings differ in what
//! they demand:
//!
//! ```text
//! $code1 and $string1                    // both, so either one carries it
//! any of them                            // one is enough, so nothing carries it
//! all of them                            // every one, so one specific carries it
//! ```
//!
//! So the walk below propagates two operations: `and` takes the **stronger** of
//! its sides (both must hold, so whichever side demands something is the side
//! that decides), and `or` takes the **weaker** (either may hold, so the rule is
//! only as demanding as its easiest way in). A quantifier takes the *n*-th
//! weakest string in its set, because `N of them` is satisfied by the *N*
//! easiest strings and an author choosing `1 of them` has said one is enough.
//!
//! # The direction of the error
//!
//! Reading a condition as more demanding than it is makes a rule convict that
//! should not have, which deletes a file the user needed. Reading it as less
//! demanding leaves a rule in the suspicious band, which costs a glance at a
//! report. So every construct this module cannot evaluate is read as the
//! *weaker* answer:
//!
//! * A regex is not a literal and its body length says nothing about what it
//!   matches, so it is never specific.
//! * A count that is an expression rather than an integer
//!   (`pe.number_of_sections of them`) is read as one, the weakest count there
//!   is.
//! * A percentage is rounded **down**, for the same reason.
//! * A `not`, a `for` over integers, and anything about file structure rather
//!   than content contribute no evidence at all, because a condition satisfied
//!   by `filesize < 10MB` alone is satisfied by most files in the world.
//!
//! The one thing this module will not do is guess upward. There is no construct
//! whose unknown answer is read as "specific".

use crate::ast::{Expr, Quantifier, StringDef, StringSet, StringValue};

/// Shortest string that can be evidence about a file.
///
/// Below this a byte sequence is one an ordinary program can contain — `cmd.exe`
/// is 7, `.onion` is 6, `MZ` is 2 — and a rule that can be satisfied by one of
/// those is a hunting rule whatever its condition looks like.
///
/// # How 36 was arrived at, and what it costs
///
/// The first version of this module shipped 12, chosen by argument: `cmd.exe`
/// and `.onion` are far shorter, so 12 looked safely clear of them. It was then
/// measured, and it was wrong. A scan of 80,638 installed files — under
/// `Program Files`, `Program Files (x86)` and `%LOCALAPPDATA%\Programs` —
/// reported 54 files in the malicious band and **every one of them was a
/// conviction this route reached**. Forty-six were Microsoft Office's own
/// bundled JavaScript, from `SIGNATURE_BASE_Apt_CN_Tetrisplugins_JS` matching
/// `$e1`: thirty-three bytes of a Babel error message, `Cannot call a class as a
/// function`, which every bundle carrying that helper contains. Thirty-three
/// bytes of framework prose is not an indicator, and *no length says it is not*
/// — so what this round of the line can do is clear the measured cases and be
/// honest that length is a proxy.
///
/// The five rules the probe convicted with, the line each stops convicting at,
/// and the string each is decided by, are printed by
/// `every_rule_that_convicted_ordinary_software_is_read_at_every_candidate_line`:
///
/// | rule | stops at | decided by |
/// |---|---|---|
/// | `SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell` | 16 | 14 — `p0wnedShellx86` |
/// | `SIGNATURE_BASE_Apt_CN_Tetrisplugins_JS` | 24 | 22 — `['configurable']=!![];` |
/// | `DELIVRTO_SUSP_HTML_WASM_Smuggling` | 24 | 23 — `WebAssembly.instantiate` |
/// | `MALPEDIA_Win_Bqtlock_Auto` | 36 | 34 — the 7th-weakest of ten hex runs |
/// | `SECUINFRA_SUSP_Powershell_Base64_Decode` | 36 | 35 — `[System.Convert]::FromBase64String(` |
///
/// So 36 is the smallest line that clears the measured set, and it is the one
/// that ships — with one byte of margin over the longest string in the table,
/// which is the whole of the argument for it. Note what the two middle rows say
/// about the first finding in this doc: the Office files were *matched* on the
/// rule's `$e1`, thirty-three bytes of a Babel error message, but the rule is
/// held specific by a twenty-two-byte obfuscator artifact on another path. Those
/// are two different facts, and only the second is the one this line moves.
///
/// The cost is on the other side of the same table. Of the corpus's 10,764
/// rules, the number this route promotes falls from **8,034 (74.6%)** at 12 to
/// **2,979 (27.7%)** at 36, and the number that convict on a single string —
/// the population a false positive is drawn from — from **669 to 317**. What is
/// left at 36 is a better population than what was left at 12: the shortest
/// convictions become `CAPE_Xworm`'s own code, `s:\workspace\ccleaner\branches\v5.33`,
/// `# Obfuscation by Allatori Obfuscator`, a Cobalt Strike beacon's decrypt
/// sequence — build paths, packer markers and code, rather than the DLL names
/// and language keywords that a 12-byte line admits.
///
/// Distinct from [`crate::atoms::MIN_ATOM_LEN`], which is 3 and answers a
/// different question: that constant is the shortest run the index can hold, and
/// a three-byte run is a perfectly good index entry and no evidence at all.
const MIN_SPECIFIC: usize = 36;

/// What a rule's condition demands of the file it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demand {
    /// No path through the condition is satisfied without a specific indicator.
    ///
    /// This is a statement about *shape*, not about the malware: a rule that
    /// cannot fire on a file without a hundred bytes of somebody's code is a
    /// rule worth convicting on, and this is the module saying so.
    Specific,
    /// Some path through the condition is satisfied without one.
    ///
    /// `any of them`, a single `$a`, an `or` with a structural check on one side
    /// — each of these is a way in that needs nothing distinctive, and a rule
    /// with one is a rule that reports rather than acts.
    Loose,
    /// Nothing here to read: no strings, or no condition.
    None,
}

/// How much a subexpression contributes to the demand.
///
/// Ordered, because the two operations over it are [`Ord::max`] and
/// [`Ord::min`]: `and` keeps the stronger side and `or` the weaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Strength {
    /// Nothing about *what this file is*. A file-size bound, a PE header check,
    /// the absence of something. True of too many files to be evidence.
    NoEvidence,
    /// A short string: `cmd.exe`, `.onion`, `MZ`. Worth matching and worth
    /// reporting, and a coincidence waiting to happen.
    Generic,
    /// A string long enough that ordinary software does not contain it.
    Specific,
}

/// Read a rule's condition and say what it demands.
///
/// `strings` is the rule's whole string list, which the condition refers to by
/// identifier; `condition` is the parsed `condition:` block. A rule with no
/// strings cannot demand anything, because there is nothing for a condition to
/// be about.
pub fn demand(strings: &[StringDef], condition: &Expr) -> Demand {
    demand_with(strings, condition, MIN_SPECIFIC)
}

/// [`demand`] at a line other than the one this product ships.
///
/// The line is a parameter rather than a constant read in place so that moving
/// it is a decision that can be measured before it is made: the profile test
/// below reads the whole corpus at several candidate lines and prints what each
/// one would do. A constant that could only be changed and then re-measured
/// would be changed on a hunch.
///
/// `pub(crate)` because the line is this module's opinion and not a knob the
/// product exposes: a caller outside the crate states what it wants by calling
/// [`demand`].
pub(crate) fn demand_with(strings: &[StringDef], condition: &Expr, min_specific: usize) -> Demand {
    if strings.is_empty() {
        return Demand::None;
    }
    match strength_of(condition, strings, min_specific) {
        Strength::Specific => Demand::Specific,
        Strength::Generic | Strength::NoEvidence => Demand::Loose,
    }
}

/// Walk one subexpression and say how much it contributes.
fn strength_of(expr: &Expr, strings: &[StringDef], min_specific: usize) -> Strength {
    match expr {
        Expr::StringMatch(id) => named_strength(id, strings, min_specific),

        // `$a at 0x1000`, `$a in (0..100)`, `#a > 3`, `@a[1] == 0x40`: each is
        // still a fact about that one string, and where it matched is a
        // refinement rather than evidence of its own.
        Expr::StringAt(id, _)
        | Expr::StringIn(id, _, _)
        | Expr::StringCount(id)
        | Expr::StringOffset(id, _)
        | Expr::StringLength(id, _) => named_strength(id, strings, min_specific),

        Expr::Of { quantifier, set } => quantified_strength(quantifier, set, strings, min_specific),

        // The set is the same; the range constrains *where* each member matched,
        // which cannot make a weak member strong. Read as the plain set.
        Expr::OfIn {
            quantifier, set, ..
        } => quantified_strength(quantifier, set, strings, min_specific),

        // `for any of ($a*) : ( $ )` — the body sees `$` bound to each match and
        // can only refine where it matched, never add an indicator that was not
        // in the set. The quantifier is the part that decides, exactly as in
        // `Of`.
        Expr::ForOf {
            quantifier, set, ..
        } => quantified_strength(quantifier, set, strings, min_specific),

        // Both sides must hold, so whichever side demands something is the side
        // that decides.
        Expr::And(lhs, rhs) => {
            strength_of(lhs, strings, min_specific).max(strength_of(rhs, strings, min_specific))
        }

        // Either side may hold, so the rule is only as demanding as its easiest
        // way in.
        Expr::Or(lhs, rhs) => {
            strength_of(lhs, strings, min_specific).min(strength_of(rhs, strings, min_specific))
        }

        // A negation is never evidence that a file is anything.
        Expr::Not(_) => Strength::NoEvidence,

        // The placeholder is the set member, already counted where the set was.
        Expr::ForOfPlaceholder | Expr::Variable(_) => Strength::NoEvidence,

        // Everything else is a fact about file structure, a bound, or an
        // arithmetic combination of the two: `filesize < 10MB`,
        // `uint16(0) == 0x5A4D`, `pe.number_of_sections > 5`,
        // `for any i in (0..10) : (...)`. True of too many files to be evidence,
        // and reading any of them as specific is the failure this module's
        // documentation warns about.
        _ => Strength::NoEvidence,
    }
}

/// How much a quantifier over a set contributes.
fn quantified_strength(
    quantifier: &Quantifier,
    set: &StringSet,
    strings: &[StringDef],
    min_specific: usize,
) -> Strength {
    let mut members: Vec<Strength> = resolve(set, strings)
        .into_iter()
        .map(|def| string_strength(def, min_specific))
        .collect();

    if members.is_empty() {
        // `all of them` over nothing is vacuously true and `any of them` over
        // nothing is never true, and neither is evidence about a file. A rule
        // whose condition names strings it does not define is a broken rule, not
        // a strong one.
        return Strength::NoEvidence;
    }
    members.sort_unstable();

    match quantifier {
        // One is enough, so the weakest member is a way in.
        Quantifier::Any => members[0],
        // Every one must match, so the strongest member is required.
        Quantifier::All => members[members.len() - 1],
        // `none of them` is satisfied by absence, and absence is not evidence.
        Quantifier::None => Strength::NoEvidence,
        // `N of them` is satisfied by the N easiest, so the demand is set by the
        // N-th weakest. An N of zero is satisfiable by nothing at all.
        Quantifier::Count(count) => match constant(count) {
            Some(0) => Strength::NoEvidence,
            Some(n) => members[(n - 1).min(members.len() - 1)],
            // A count that is an expression — `pe.number_of_sections of them` is
            // a real and common construct — cannot be known here, and one is the
            // weakest count there is.
            None => members[0],
        },
        // Rounded down, because a smaller count is the weaker reading.
        Quantifier::Percentage(percent) => {
            let n = (members.len() * usize::from(*percent) / 100).max(1);
            members[(n - 1).min(members.len() - 1)]
        }
    }
}

/// The integer a count expression denotes, when it denotes one.
fn constant(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Int(n) if *n >= 0 => Some(*n as usize),
        _ => None,
    }
}

/// Resolve a set to the strings it names.
///
/// [`StringSet::All`] is every string in the rule. A list names identifiers
/// exactly and prefixes by wildcard; a prefix matches an identifier that starts
/// with it, which is how YARA reads `($a*)` and is why `$a` also selects `$ab`.
/// A bare `($*)` is the prefix `""`, which selects everything — the same set as
/// `them`, by a different spelling.
fn resolve<'a>(set: &StringSet, strings: &'a [StringDef]) -> Vec<&'a StringDef> {
    match set {
        StringSet::All => strings.iter().collect(),
        StringSet::List { names, prefixes } => strings
            .iter()
            .filter(|def| {
                let bare = bare_id(&def.id);
                names.iter().any(|name| name == bare)
                    || prefixes
                        .iter()
                        .any(|prefix| bare.starts_with(prefix.as_str()))
            })
            .collect(),
    }
}

/// How much one named string is worth, by the rule's own definition of it.
fn named_strength(id: &str, strings: &[StringDef], min_specific: usize) -> Strength {
    strings
        .iter()
        .find(|def| bare_id(&def.id) == id)
        .map(|def| string_strength(def, min_specific))
        // A condition naming a string the rule does not define is a broken rule.
        // It cannot be evidence.
        .unwrap_or(Strength::NoEvidence)
}

/// A string's identifier without the `$` the declaration writes and the
/// reference does not.
///
/// The parser keeps the sigil on the definition (`StringDef::id` is `"$a"`) and
/// drops it from every reference to it (`Expr::StringMatch` is `"a"`, and a set
/// lists `"a"` or the prefix `"a"`). Comparing the two without this is a
/// comparison that never matches, which reads as "every rule names strings it
/// does not define" and makes this module answer `Loose` to everything.
fn bare_id(id: &str) -> &str {
    id.strip_prefix('$').unwrap_or(id)
}

/// How much one string definition is worth.
fn string_strength(def: &StringDef, min_specific: usize) -> Strength {
    match &def.value {
        // The number of bytes a file must contain. Text is measured in bytes
        // rather than characters, which is what the matcher counts.
        StringValue::Text(bytes) => sized(bytes.len(), min_specific),
        // The *shortest* thing the pattern can match, because a pattern with
        // wildcards is only as specific as its narrowest reading.
        StringValue::Hex(pattern) => sized(pattern.length_bounds().0, min_specific),
        // A regex is a shape rather than a sequence, and the length of its body
        // says nothing about the length of what it matches: `/a.{0,200}b/` is
        // five characters of body and two hundred of file. Never specific.
        StringValue::Regex { .. } => Strength::Generic,
        // Unreachable: this runs on the source, and a database is only shed
        // after everything has been compiled from it. Answered as "a shape of
        // unknown length", which is the conservative reading — it under-claims
        // strength rather than over-claiming it, so a mistake here reports a
        // rule as weaker than it is instead of convicting on it.
        StringValue::Shed => Strength::Generic,
    }
}

/// The one place a length becomes a verdict, so the line is stated once.
fn sized(bytes: usize, min_specific: usize) -> Strength {
    if bytes >= min_specific {
        Strength::Specific
    } else {
        Strength::Generic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    /// Parse a rule and read its condition. Going through the parser rather than
    /// building `Expr` values by hand is deliberate: the construct that reaches
    /// this module is the one the parser produces, and a test that builds its
    /// own tree is a test of the tree, not of the corpus's syntax.
    fn read(source: &str) -> Demand {
        let file = parser::parse_file(source).expect("the fixture parses");
        let rule = file.rules.first().expect("the fixture has a rule");
        demand(&rule.strings, &rule.condition)
    }

    /// The rule this module was written for, with its own strings shortened to
    /// keep the fixture readable. Both are specific, the condition needs both,
    /// and the answer has to be `Specific` — the defect was that this rule was
    /// reported `Suspicious`.
    #[test]
    fn a_condition_that_needs_two_specific_strings_demands_one() {
        assert_eq!(
            read(
                r#"
rule CAPE_Azorult {
    strings:
        $code1 = { C7 07 3C 00 00 00 8D 45 80 89 47 04 C7 47 08 20 00 00 00 }
        $string1 = "SELECT DATETIME( ((visits.visit_time/1000000)-11644473600)"
    condition:
        uint16( 0 ) == 0x5A4D and all of them
}
"#
            ),
            Demand::Specific
        );
    }

    /// `any of them` is only a hunt when the set has a weak member. Over a set
    /// where *every* member is specific, one of them is still a specific
    /// indicator, and a file satisfying the rule still has to carry one — so
    /// this shape demands as much as `all of them` does, by a different route.
    ///
    /// This is the case that decides whether the reading is worth having: a rule
    /// that lists five of a family's C2 domains under `any of them` is a
    /// signature of that family, and reading it as a hunt because of the word
    /// `any` would leave it unable to act.
    #[test]
    fn any_of_them_over_only_specific_strings_still_demands_one() {
        assert_eq!(
            read(
                r#"
rule Domains {
    strings:
        $x1 = "hus31m7c7ad9x2k4p8qzvbn3m5w7rta72k.onion"
        $x2 = "iw6v2p3cruy4mnbvcxz9q8w7e6r5t4y8u.net"
    condition:
        any of them
}
"#
            ),
            Demand::Specific
        );
    }

    /// And the same word over a set with a short member in it is a hunt,
    /// because the short member is a way in. The two tests together are the
    /// claim that this module reads *sets*, not keywords.
    #[test]
    fn any_of_them_over_a_set_with_a_short_member_demands_nothing() {
        assert_eq!(
            read(
                r#"
rule Hunt {
    strings:
        $s1 = ".onion"
        $x1 = "hus31m7c7ad.onion"
        $x2 = "iw6v2p3cruy4mnbvcxz.net"
    condition:
        any of them
}
"#
            ),
            Demand::Loose
        );
    }

    /// `all of them` is only as good as its weakest requirement, and one short
    /// string among specific ones is a way in for a file that merely contains
    /// `cmd.exe` twice over — every member must match, so the short one is
    /// required rather than merely permitted. But `all` also means a specific
    /// member is required, so this is `Specific` and the test says so.
    ///
    /// The case that is *not* specific is the next test.
    #[test]
    fn all_of_them_is_carried_by_its_strongest_member() {
        assert_eq!(
            read(
                r#"
rule Mixed {
    strings:
        $a = "cmd.exe"
        $b = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        all of them
}
"#
            ),
            Demand::Specific
        );
    }

    /// `1 of them` where the set contains a short string: the file needs one
    /// indicator and the short one will do. That is the shape of a hunting rule
    /// whatever else is in the set.
    #[test]
    fn one_of_them_with_a_short_member_demands_nothing() {
        assert_eq!(
            read(
                r#"
rule Hunt {
    strings:
        $a = "cmd.exe"
        $b = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        1 of them
}
"#
            ),
            Demand::Loose
        );
    }

    /// `2 of them` over a set whose two weakest members are both short is still
    /// satisfiable without anything specific, and the walk says so by taking the
    /// second-weakest rather than the weakest.
    #[test]
    fn a_count_takes_the_nth_weakest_member() {
        assert_eq!(
            read(
                r#"
rule Two {
    strings:
        $a = "cmd.exe"
        $b = ".onion"
        $c = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        2 of them
}
"#
            ),
            Demand::Loose
        );
        // Three, and the third-weakest is the long one.
        assert_eq!(
            read(
                r#"
rule Three {
    strings:
        $a = "cmd.exe"
        $b = ".onion"
        $c = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        3 of them
}
"#
            ),
            Demand::Specific
        );
    }

    /// An `or` is only as demanding as its easiest way in. A structural check on
    /// one side of it is a way in that needs no indicator at all, so the whole
    /// condition is satisfied by any small file.
    #[test]
    fn an_or_with_a_structural_check_on_one_side_demands_nothing() {
        assert_eq!(
            read(
                r#"
rule Either {
    strings:
        $a = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        filesize < 10MB or $a
}
"#
            ),
            Demand::Loose
        );
    }

    /// An `and` is decided by whichever side demands something, so a structural
    /// check beside a specific string does not weaken it. This is the shape the
    /// Azorult rule has, and reading it as `Loose` would leave the defect open.
    #[test]
    fn an_and_with_a_structural_check_beside_a_specific_string_demands_one() {
        assert_eq!(
            read(
                r#"
rule Guarded {
    strings:
        $a = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        uint16( 0 ) == 0x5A4D and $a
}
"#
            ),
            Demand::Specific
        );
    }

    /// A regex is a shape, not a sequence, and its body length measures the
    /// shape rather than what it matches. Reading one as specific would let
    /// `/a.{0,200}b/` convict on its own.
    #[test]
    fn a_regex_is_never_specific() {
        assert_eq!(
            read(
                r#"
rule Regex {
    strings:
        $a = /SOFTWARE.Microsoft.Windows.NT.CurrentVersion.Run/
    condition:
        $a
}
"#
            ),
            Demand::Loose
        );
    }

    /// A negation is never evidence that a file is anything, and a rule whose
    /// only condition is an absence has nothing to convict on.
    #[test]
    fn a_negation_contributes_nothing() {
        assert_eq!(
            read(
                r#"
rule Absent {
    strings:
        $a = "cmd.exe"
    condition:
        not $a
}
"#
            ),
            Demand::Loose
        );
    }

    /// A rule with no strings cannot demand anything: there is nothing for its
    /// condition to be about, and a rule that matches on file structure alone is
    /// a description of a format.
    #[test]
    fn a_rule_with_no_strings_demands_nothing() {
        assert_eq!(
            read(
                r#"
rule Structural {
    condition:
        uint16( 0 ) == 0x5A4D and filesize < 10MB
}
"#
            ),
            Demand::None
        );
    }

    /// `all of them` over a set the condition names but the rule does not define
    /// is a broken rule, and a broken rule is not a strong one. This is the
    /// direction the whole module errs in, asserted where it is cheapest to get
    /// wrong: an empty set must not read as vacuously `all`.
    #[test]
    fn an_empty_set_is_not_vacuously_everything() {
        assert_eq!(
            read(
                r#"
rule Dangling {
    strings:
        $a = "cmd.exe"
    condition:
        all of ($zz*)
}
"#
            ),
            Demand::Loose
        );
    }

    /// The counts the corpus actually writes. `pe.number_of_sections of them` is
    /// an expression this module cannot evaluate, and one is the weakest count
    /// there is — so a rule whose set holds a short string is not read as
    /// demanding.
    #[test]
    fn a_count_that_is_an_expression_is_read_as_one() {
        assert_eq!(
            read(
                r#"
rule ExprCount {
    strings:
        $a = "cmd.exe"
        $b = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        pe.number_of_sections of them
}
"#
            ),
            Demand::Loose
        );
    }

    /// A percentage is rounded down, because a smaller count is the weaker
    /// reading and the weaker reading is the safe one.
    #[test]
    fn a_percentage_is_rounded_down() {
        // 50% of three is 1.5, and the weaker reading is one.
        assert_eq!(
            read(
                r#"
rule Half {
    strings:
        $a = "cmd.exe"
        $b = ".onion"
        $c = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        50% of them
}
"#
            ),
            Demand::Loose
        );
    }

    /// A set written as an explicit list is resolved by identifier, and a
    /// prefix wildcard selects by prefix. Both are ways of saying which strings
    /// the quantifier ranges over, and the reading must agree with the matcher
    /// about which ones those are.
    #[test]
    fn a_list_and_a_prefix_select_the_same_way_the_matcher_does() {
        // `$s*` selects the two short ones, so one of them is a way in.
        assert_eq!(
            read(
                r#"
rule Prefix {
    strings:
        $s1 = "cmd.exe"
        $s2 = ".onion"
        $long = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        1 of ($s*)
}
"#
            ),
            Demand::Loose
        );
        // Naming only the long one is a different rule.
        assert_eq!(
            read(
                r#"
rule Named {
    strings:
        $s1 = "cmd.exe"
        $s2 = ".onion"
        $long = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        $long
}
"#
            ),
            Demand::Specific
        );
    }

    /// `for any of ($a*) : ( $ )` is a quantifier over a set, and the body can
    /// only refine where a member matched. The quantifier is what decides.
    #[test]
    fn a_for_over_a_set_is_read_by_its_quantifier() {
        assert_eq!(
            read(
                r#"
rule ForAny {
    strings:
        $a1 = "cmd.exe"
        $a2 = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        for any of ($a*) : ( $ )
}
"#
            ),
            Demand::Loose
        );
        assert_eq!(
            read(
                r#"
rule ForAll {
    strings:
        $a1 = "cmd.exe"
        $a2 = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
    condition:
        for all of ($a*) : ( $ )
}
"#
            ),
            Demand::Specific
        );
    }

    /// A hex pattern with wildcards is only as specific as its narrowest
    /// reading, so the bounds are read at their minimum.
    #[test]
    fn a_hex_pattern_is_measured_at_its_shortest_match() {
        // Forty-one fixed bytes with a gap that can be empty. The gap is the
        // part being tested: read at its widest the pattern is longer, and the
        // reading has to be the narrower one, which is still over the line.
        assert_eq!(
            read(
                r#"
rule HexLong {
    strings:
        $a = { 53 4F 46 54 57 41 52 45 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E [0-4] 63 }
    condition:
        $a
}
"#
            ),
            Demand::Specific
        );
        // Four fixed bytes and a gap that can be empty: four bytes of evidence.
        assert_eq!(
            read(
                r#"
rule HexShort {
    strings:
        $a = { 4D 5A [0-4] 50 45 }
    condition:
        $a
}
"#
            ),
            Demand::Loose
        );
    }

    /// The threshold itself, asserted from both sides so that moving it is a
    /// decision rather than an accident.
    #[test]
    fn the_line_between_generic_and_specific_is_where_it_says_it_is() {
        let at = "x".repeat(MIN_SPECIFIC);
        let below = "x".repeat(MIN_SPECIFIC - 1);
        for (value, expected) in [(at, Demand::Specific), (below, Demand::Loose)] {
            assert_eq!(
                read(&format!(
                    "rule Line {{ strings: $a = \"{value}\" condition: $a }}"
                )),
                expected,
                "{value}"
            );
        }
    }

    /// The measurement that decides where the line goes.
    ///
    /// The line is the one number in this module that is a judgement rather than
    /// a reading, and the judgement is expensive in one direction: set it too
    /// low and ordinary software carries something a rule asks for, so the rule
    /// convicts a file the user needs. The first version of this module shipped
    /// a line of 12 chosen by argument; this test exists so the next move is
    /// chosen by measurement.
    ///
    /// It reads the corpus this product ships and prints, for each candidate
    /// line, how many rules would demand something specific — and of those, how
    /// many demand it through a condition a *single* string satisfies, which is
    /// the only shape where one ordinary byte sequence is the whole conviction.
    /// A rule requiring three specific strings is not the risk; a rule requiring
    /// one twelve-byte string is.
    ///
    /// Ignored, because it reads a 17 MB vendored corpus and prints rather than
    /// asserts. Run it with:
    ///
    /// ```text
    /// cargo test -p av-rules --lib the_line -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "reads the vendored corpus and prints a table"]
    fn the_line_is_chosen_by_measurement() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/converted/yara-forge-extended-0.9.1.yar"
        );
        let Ok(source) = std::fs::read_to_string(path) else {
            eprintln!("the corpus is not vendored here; nothing to measure");
            return;
        };
        // Split the way the compiler splits, so the rules measured here are the
        // rules that ship: the corpus does not parse as one file, because a
        // handful of its rules use constructs this engine refuses, and refusing
        // a rule is not a reason to have no measurement.
        let split = crate::ruleset::split_rule_chunks(&source);
        let rules: Vec<crate::ast::Rule> = split
            .chunks
            .iter()
            .filter_map(|chunk| parser::parse_file(chunk.text).ok())
            .flat_map(|file| file.rules)
            .collect();
        println!("\n  {} rules", rules.len());
        println!(
            "  {:>4}  {:>8}  {:>7}  {:>10}  {:>9}",
            "line", "specific", "share", "one string", "1-str share"
        );
        for line in [8usize, 10, 12, 16, 20, 24, 32, 36, 40, 48] {
            let mut specific = 0usize;
            let mut single = 0usize;
            for rule in &rules {
                if demand_with(&rule.strings, &rule.condition, line) != Demand::Specific {
                    continue;
                }
                specific += 1;
                // "One string satisfies it" is `$a` on its own, or a quantifier
                // whose weakest member is already specific — the shapes where a
                // single ordinary-looking string is the entire evidence.
                if single_string_conviction(&rule.strings, &rule.condition, line) {
                    single += 1;
                }
            }
            let total = rules.len().max(1) as f64;
            println!(
                "  {:>4}  {:>8}  {:>6.1}%  {:>10}  {:>8.1}%",
                line,
                specific,
                specific as f64 * 100.0 / total,
                single,
                single as f64 * 100.0 / total,
            );
        }

        // The count above says how many rules rest on one string. It does not
        // say whether those strings are the kind of thing ordinary software
        // contains, which is the question the count is a proxy for. So: the
        // shortest deciding string of every such rule, shortest first. If the
        // head of this list is `Program Files` and `.dll`, the line is too low
        // whatever the count says; if it is fragmentary code, it is not.
        let mut shortest: Vec<(usize, String)> = Vec::new();
        for rule in &rules {
            if demand_with(&rule.strings, &rule.condition, MIN_SPECIFIC) != Demand::Specific {
                continue;
            }
            if let Some((def, len)) = weakest_deciding_string(&rule.strings, &rule.condition, MIN_SPECIFIC)
            {
                shortest.push((len, format!("{}  ← {}", describe(&def.value), rule.name)));
            }
        }
        shortest.sort_by_key(|(len, _)| *len);
        println!("\n  the {} shortest single-string convictions:", shortest.len());
        for (len, what) in shortest.iter().take(60) {
            println!("  {len:>4}  {what}");
        }
        println!();
    }

    /// Every rule that convicted ordinary installed software, read at every
    /// candidate line.
    ///
    /// The corpus-wide count above says how many rules a line promotes. It
    /// cannot say whether the rules it promotes are right, because the corpus
    /// contains no verdicts — only the strings. The false-positive probe does
    /// say, and it named five rules. This is those five, and the line each one
    /// stops convicting at.
    ///
    /// The names are the evidence rather than an illustration: a probe over
    /// 80,638 installed files reported 54 malicious findings and every one of
    /// them was a conviction this route reached, 46 of them from
    /// `SIGNATURE_BASE_Apt_CN_Tetrisplugins_JS` alone, matching `$e1` — the
    /// base64 of `Cannot call a class as a function`, a Babel error message
    /// that every bundle containing the helper carries. Thirty-three bytes of
    /// framework prose is not an indicator, and no length says it is not.
    ///
    /// Ignored, because it reads the vendored corpus and prints rather than
    /// asserts. Run it with:
    ///
    /// ```text
    /// cargo test -p av-rules --lib every_rule_that_convicted -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "reads the vendored corpus and prints a table"]
    fn every_rule_that_convicted_ordinary_software_is_read_at_every_candidate_line() {
        const CONVICTED_ORDINARY_SOFTWARE: [&str; 5] = [
            "SIGNATURE_BASE_Apt_CN_Tetrisplugins_JS",
            "DELIVRTO_SUSP_HTML_WASM_Smuggling",
            "MALPEDIA_Win_Bqtlock_Auto",
            "SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell",
            "SECUINFRA_SUSP_Powershell_Base64_Decode",
        ];

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/converted/yara-forge-extended-0.9.1.yar"
        );
        let Ok(source) = std::fs::read_to_string(path) else {
            eprintln!("the corpus is not vendored here; nothing to measure");
            return;
        };
        let split = crate::ruleset::split_rule_chunks(&source);
        let rules: Vec<crate::ast::Rule> = split
            .chunks
            .iter()
            .filter_map(|chunk| parser::parse_file(chunk.text).ok())
            .flat_map(|file| file.rules)
            .collect();

        println!();
        for name in CONVICTED_ORDINARY_SOFTWARE {
            let Some(rule) = rules.iter().find(|rule| rule.name == name) else {
                println!("  {name}: not in this corpus");
                continue;
            };
            let mut reads = Vec::new();
            for line in [12usize, 16, 20, 24, 28, 32, 36, 40, 48, 64] {
                let demand = demand_with(&rule.strings, &rule.condition, line);
                let weakest = weakest_deciding_string(&rule.strings, &rule.condition, line)
                    .map(|(def, len)| format!("{len:>4}  {}", describe(&def.value)));
                reads.push(format!(
                    "    {line:>3}  {:?}{}",
                    demand,
                    weakest.map(|w| format!("  ← {w}")).unwrap_or_default()
                ));
            }
            println!("  {name}");
            // The strings, with their lengths, because the line a rule stops
            // convicting at is a fact about `demand` and the deciding string is
            // a fact about `weakest_deciding_string`, and those are different
            // questions. `$a and $b` is `Specific` and has no single deciding
            // string at all, so a table of lines alone cannot say *what* in the
            // rule the line is being measured against.
            let mut inventory: Vec<(usize, String)> = rule
                .strings
                .iter()
                .map(|def| {
                    (
                        {
                            match &def.value {
                                StringValue::Text(bytes) => bytes.len(),
                                StringValue::Hex(pattern) => pattern.length_bounds().0,
                                StringValue::Regex { .. } => usize::MAX,
                                // Unreachable; see `string_strength`.
                                StringValue::Shed => usize::MAX,
                            }
                        },
                        format!("{:<10} {}", bare_id(&def.id), describe(&def.value)),
                    )
                })
                .collect();
            inventory.sort_by_key(|(len, _)| *len);
            for (len, what) in &inventory {
                println!("      {len:>4}  {what}");
            }
            println!(
                "      condition: {}",
                describe_expr(&rule.condition, &rule.strings)
            );
            for read in reads {
                println!("{read}");
            }
        }
        println!();
    }

    /// The condition, rendered flat, for a human reading a diagnostic table.
    fn describe_expr(expr: &Expr, strings: &[StringDef]) -> String {
        match expr {
            Expr::StringMatch(id) => bare_id(id).to_string(),
            Expr::And(lhs, rhs) => format!(
                "({} and {})",
                describe_expr(lhs, strings),
                describe_expr(rhs, strings)
            ),
            Expr::Or(lhs, rhs) => format!(
                "({} or {})",
                describe_expr(lhs, strings),
                describe_expr(rhs, strings)
            ),
            Expr::Of { quantifier, set } => {
                let members: Vec<String> = resolve(set, strings)
                    .iter()
                    .map(|def| bare_id(&def.id).to_string())
                    .collect();
                format!("{quantifier:?} of [{}]", members.join(", "))
            }
            other => format!("{other:?}"),
        }
    }

    /// A one-line, human-readable rendering of a string definition.
    fn describe(value: &StringValue) -> String {
        match value {
            StringValue::Text(bytes) => {
                let text: String = bytes
                    .iter()
                    .map(|b| {
                        if b.is_ascii_graphic() || *b == b' ' {
                            char::from(*b)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                format!("text {text:?}")
            }
            StringValue::Hex(pattern) => {
                format!("hex  {} bytes", pattern.length_bounds().0)
            }
            StringValue::Regex { body, .. } => {
                format!("regex {body:?}")
            }
            StringValue::Shed => "value shed".to_owned(),
        }
    }

    /// The weakest string that can satisfy the condition on its own, with its
    /// length — the single byte sequence a false positive would be made of.
    ///
    /// Shares [`single_string_conviction`]'s reading, and returns `Some` on
    /// exactly the rules that function answers `true` for, so the list below is
    /// the population the count above is counting rather than a second guess at
    /// it.
    fn weakest_deciding_string<'a>(
        strings: &'a [StringDef],
        condition: &Expr,
        min_specific: usize,
    ) -> Option<(&'a StringDef, usize)> {
        fn len_of(def: &StringDef) -> usize {
            match &def.value {
                StringValue::Text(bytes) => bytes.len(),
                StringValue::Hex(pattern) => pattern.length_bounds().0,
                StringValue::Regex { .. } => usize::MAX,
                // Unreachable; see `string_strength`.
                StringValue::Shed => usize::MAX,
            }
        }
        fn walk<'a>(
            expr: &Expr,
            strings: &'a [StringDef],
            min_specific: usize,
        ) -> Option<&'a StringDef> {
            let specific = |id: &str| {
                strings
                    .iter()
                    .find(|def| bare_id(&def.id) == id)
                    .filter(|def| string_strength(def, min_specific) == Strength::Specific)
            };
            match expr {
                Expr::StringMatch(id)
                | Expr::StringAt(id, _)
                | Expr::StringIn(id, _, _)
                | Expr::StringCount(id)
                | Expr::StringOffset(id, _)
                | Expr::StringLength(id, _) => specific(id),
                // Two strings, so there is no single one that decides it.
                Expr::And(..) => None,
                Expr::Or(lhs, rhs) => {
                    let (a, b) = (
                        walk(lhs, strings, min_specific),
                        walk(rhs, strings, min_specific),
                    );
                    match (a, b) {
                        (Some(a), Some(b)) => Some(if len_of(a) <= len_of(b) { a } else { b }),
                        (a, b) => a.or(b),
                    }
                }
                Expr::Of { quantifier, set } => {
                    let mut members: Vec<&StringDef> = resolve(set, strings)
                        .into_iter()
                        .filter(|def| string_strength(def, min_specific) == Strength::Specific)
                        .collect();
                    members.sort_by_key(|def| len_of(def));
                    let only = members.len() == 1;
                    match quantifier {
                        Quantifier::Any => members.first().copied(),
                        Quantifier::All => only.then(|| members[0]),
                        Quantifier::Count(count) => {
                            (constant(count) == Some(1)).then(|| members.first().copied())?
                        }
                        Quantifier::Percentage(percent) => {
                            let n = (members.len() * usize::from(*percent) / 100).max(1);
                            (n == 1).then(|| members.first().copied())?
                        }
                        Quantifier::None => None,
                    }
                }
                _ => None,
            }
        }
        walk(condition, strings, min_specific).map(|def| (def, len_of(def)))
    }

    /// Whether one string, on its own, is enough to satisfy the condition.
    ///
    /// The companion question to [`demand`], and the sharper one: a condition
    /// that needs three specific strings is a signature, and a condition that
    /// needs any one of three specific strings is a signature too — but only the
    /// second is a single byte sequence away from convicting, which is where a
    /// false positive comes from. So this reads `and` and `all of them` and
    /// `N of them` for `N > 1` as **no**, and `or` and `any of them` and
    /// `1 of them` as **yes when their weakest member is specific**.
    fn single_string_conviction(
        strings: &[StringDef],
        condition: &Expr,
        min_specific: usize,
    ) -> bool {
        fn walk(expr: &Expr, strings: &[StringDef], min_specific: usize) -> bool {
            match expr {
                Expr::StringMatch(id)
                | Expr::StringAt(id, _)
                | Expr::StringIn(id, _, _)
                | Expr::StringCount(id)
                | Expr::StringOffset(id, _)
                | Expr::StringLength(id, _) => strings
                    .iter()
                    .find(|def| bare_id(&def.id) == id)
                    .is_some_and(|def| string_strength(def, min_specific) == Strength::Specific),
                // Both sides must hold, so the rule is never one string away
                // from firing — it is two, and two specific strings is the
                // shape this question is *not* about. `$a and $b` over two
                // long strings is a signature, and it is not a coincidence.
                Expr::And(..) => false,
                // One side is enough.
                Expr::Or(lhs, rhs) => {
                    walk(lhs, strings, min_specific) || walk(rhs, strings, min_specific)
                }
                Expr::Of { quantifier, set } => {
                    let mut members: Vec<Strength> = resolve(set, strings)
                        .into_iter()
                        .map(|def| string_strength(def, min_specific))
                        .collect();
                    members.sort_unstable();
                    // One member, so `all of them` is `any of them` and the
                    // quantifier has nothing to choose between.
                    let only = members.len() == 1;
                    match quantifier {
                        Quantifier::Any => members.first() == Some(&Strength::Specific),
                        Quantifier::All => only && members[0] == Strength::Specific,
                        Quantifier::None => false,
                        // `N of them` is one string away only when N is one.
                        Quantifier::Count(count) => {
                            constant(count) == Some(1) && members.first() == Some(&Strength::Specific)
                        }
                        Quantifier::Percentage(percent) => {
                            let n = (members.len() * usize::from(*percent) / 100).max(1);
                            n == 1 && members.first() == Some(&Strength::Specific)
                        }
                    }
                }
                _ => false,
            }
        }
        walk(condition, strings, min_specific)
    }
}
