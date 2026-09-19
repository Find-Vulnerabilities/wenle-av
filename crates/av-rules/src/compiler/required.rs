//! What a condition cannot be true without.
//!
//! The prefilter decides which rules are worth evaluating, and it works from
//! atoms alone — it never reads the condition. That is why its rule-level test
//! is a *disjunction*: "some string of this rule might be present". With seven
//! strings in a rule and any one of them enough to select it, a rule survives
//! whenever any one of its seven indicators is a common byte sequence. On a
//! Windows DLL that is most of them, which is why a scan of `shell32.dll`
//! selected 72% of the rule set.
//!
//! The condition is known here, at compile time, and most conditions are
//! conjunctions — `$a and $b and $c and uint16(0) == 0x5A4D`. For those a rule
//! is worth evaluating only when *every* one of those strings is still
//! possible, which is a far stronger test than "any". This module recovers that
//! conjunction and hands it to the prefilter.
//!
//! # Soundness
//!
//! [`required_slots`] must never return a slot the condition can be true
//! without. Each slot returned is a promise that the rule may be dropped when
//! that string is absent, and a slot returned in error is a detection that
//! silently never fires — the exact failure this whole engine is arranged to
//! avoid. So the analysis is deliberately asymmetric: where it is unsure it
//! returns *nothing*, and an empty result costs only speed. It is allowed to be
//! smaller than the truth, never larger.

use crate::ast::{Expr, Quantifier, StringSet};
use crate::compiler::StringTable;

/// String slots that must all match for `expr` to be true.
///
/// Sorted, deduplicated, and possibly empty. An empty result means "nothing
/// could be proven", which the prefilter reads as a disjunction — the safe
/// reading, and the one that needs no special case.
///
/// # What each node contributes
///
/// | node | result | why |
/// |---|---|---|
/// | `$a` | `{a}` | true only if `$a` matched |
/// | `$a at 0x100`, `$a in (0..9)` | `{a}` | both are about a match of `$a` |
/// | `a and b` | `a ∪ b` | both must hold |
/// | `a or b` | `a ∩ b` | one of them holds, so their shared demand does |
/// | `all of them` | every slot in the set | each must match |
/// | `all of ($a*) in (0..9)` | every slot in the set | same, inside a range |
/// | `any of them`, `2 of them`, `50% of them` | `{}` | one string is enough |
/// | `none of them` | `{}` | the opposite is wanted |
/// | `not a` | `{}` | `a` being false is what is wanted |
/// | `#a`, `@a`, `!a` | `{}` | `#a == 0` and `not defined @a` are both writable |
/// | `for ...` | `{}` | vacuous truth makes the bounds unknowable here |
/// | `pe.x`, `uint16(0)`, literals | `{}` | no string is involved |
///
/// The `{}` rows are not oversights. `any of them` genuinely can be true with
/// one string matching, `#a` genuinely can be zero, and a `for` loop over an
/// empty range is genuinely true — so demanding a string from any of them would
/// drop rules that match. Each is a place a later refinement could do better
/// with more careful reasoning; none is a place to guess.
pub fn required_slots(expr: &Expr, strings: &StringTable) -> Vec<u32> {
    let mut out = Vec::new();
    collect(expr, strings, &mut out);
    out.sort_unstable();
    out.dedup();
    out
}

/// Accumulate the required slots of `expr` into `out`.
///
/// `out` is left unsorted and possibly duplicated; [`required_slots`] sorts and
/// dedups. The intermediate results of `or` are collected into scratch vectors
/// because an intersection needs both sides complete before it can run.
fn collect(expr: &Expr, strings: &StringTable, out: &mut Vec<u32>) {
    match expr {
        // A string the condition is about. `$a at x` and `$a in (x..y)` are
        // true only when `$a` matched, at the offset or in the range, so both
        // demand the match itself.
        Expr::StringMatch(name) | Expr::StringAt(name, _) | Expr::StringIn(name, _, _) => {
            if let Some(slot) = strings.resolve(name) {
                out.push(slot);
            }
        }

        // Both halves must hold, so everything either half needs is needed.
        Expr::And(lhs, rhs) => {
            collect(lhs, strings, out);
            collect(rhs, strings, out);
        }

        // At least one half holds. Whatever both halves need is therefore
        // needed — `(($a and $b) or ($a and $c))` cannot be true without `$a`
        // — and anything only one half needs is not.
        Expr::Or(lhs, rhs) => {
            let mut left = Vec::new();
            let mut right = Vec::new();
            collect(lhs, strings, &mut left);
            collect(rhs, strings, &mut right);
            out.extend(left.iter().copied().filter(|slot| right.contains(slot)));
        }

        // `all of them` is a conjunction written longhand: every string in the
        // set must match. `any of`, `N of` and `P% of` are not, and are left
        // to the catch-all below — including `N of them` where `N` happens to
        // equal the set size, because `N` is usually a module field whose value
        // is not known until the file is parsed.
        Expr::Of {
            quantifier: Quantifier::All,
            set,
        } => {
            let (slots, _) = expand(set, strings);
            out.extend(slots);
        }
        Expr::OfIn {
            quantifier: Quantifier::All,
            set,
            ..
        } => {
            let (slots, _) = expand(set, strings);
            out.extend(slots);
        }

        // Not, `defined`, arithmetic, comparisons, `contains`/`matches`,
        // module fields, builtin calls, indexing, loop variables and every
        // other quantifier. None of them can be shown to require a particular
        // string, and claiming otherwise would drop a rule that matches.
        _ => {}
    }
}

/// Expand a string set to slots.
///
/// [`StringTable::expand`] returns a description alongside the slots for
/// diagnostics; that is not needed here, and the slots are what the analysis
/// works in. An unresolvable name is already reported as a compile error, so a
/// name that does not resolve contributes no slot rather than failing here.
fn expand(set: &StringSet, strings: &StringTable) -> (Vec<u32>, String) {
    strings.expand(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Modifiers, Span, StringDef, StringValue};
    use crate::parser::parse_condition;

    /// The required slots of `condition`, against strings named `$a`, `$b`, `$c`.
    ///
    /// The slots are positions in the table, and the table is built from the
    /// definitions in the order given, so `$a` is 0 and `$b` is 1 — the same
    /// numbering the prefilter and the interpreter use. Asserting on slot
    /// numbers rather than on names is deliberate: it is the numbering that
    /// reaches the prefilter, so a name-to-slot mistake has to fail here rather
    /// than be hidden by a lookup that agrees with itself.
    fn required(condition: &str) -> Vec<u32> {
        let defs: Vec<StringDef> = ["$a", "$b", "$c"]
            .iter()
            .map(|id| StringDef {
                id: (*id).to_string(),
                value: StringValue::Text(b"needle".to_vec()),
                modifiers: Modifiers::default(),
                span: Span::default(),
            })
            .collect();
        let table = StringTable::from_defs(&defs);
        let expr = parse_condition(condition).expect("test condition must parse");
        required_slots(&expr, &table)
    }

    #[test]
    fn a_bare_string_requires_itself() {
        assert_eq!(required("$a"), vec![0]);
        assert_eq!(required("$b"), vec![1]);
    }

    #[test]
    fn at_and_in_require_the_match_they_are_about() {
        // `$a at 0x100` is false when `$a` did not match anywhere, so a rule
        // that cannot have `$a` cannot match.
        assert_eq!(required("$a at 0x100"), vec![0]);
        assert_eq!(required("$a in (0..512)"), vec![0]);
    }

    #[test]
    fn a_conjunction_requires_every_operand() {
        assert_eq!(required("$a and $b"), vec![0, 1]);
        assert_eq!(required("$a and $b and $c"), vec![0, 1, 2]);
        // The module half demands nothing, and must not dilute the string half.
        assert_eq!(required("uint16(0) == 0x5A4D and $a and $b"), vec![0, 1]);
    }

    #[test]
    fn a_disjunction_requires_only_what_both_sides_require() {
        // One of the two holds, so anything both need is needed.
        assert_eq!(required("($a and $b) or ($a and $c)"), vec![0]);
        // Nothing is common to both, so nothing can be relied on.
        assert_eq!(required("$a or $b"), Vec::<u32>::new());
        // A disjunction with itself is just a conjunction.
        assert_eq!(required("$a or $a"), vec![0]);
    }

    #[test]
    fn all_of_them_requires_all_of_them() {
        assert_eq!(required("all of them"), vec![0, 1, 2]);
        assert_eq!(required("all of ($a, $b)"), vec![0, 1]);
        // `$a*` is a prefix, not a wildcard: it names `$a` and nothing else
        // here, because `$b` and `$c` do not begin with an `a`. Reading it as
        // "all the strings" would demand two strings the condition never
        // mentions, which is the direction that drops rules.
        assert_eq!(required("all of ($a*)"), vec![0]);
    }

    #[test]
    fn a_weaker_quantifier_requires_nothing() {
        // Each of these can be true with a single string matching, or with
        // none. Demanding a string from any of them would drop a rule that
        // matches — the one error this module must not make.
        assert_eq!(required("any of them"), Vec::<u32>::new());
        assert_eq!(required("2 of them"), Vec::<u32>::new());
        assert_eq!(required("50% of them"), Vec::<u32>::new());
        assert_eq!(required("none of them"), Vec::<u32>::new());
    }

    #[test]
    fn negation_requires_nothing_from_what_it_negates() {
        // `not $a` is *more* likely to be true when `$a` is absent. Reading it
        // as a requirement would invert the rule.
        assert_eq!(required("not $a"), Vec::<u32>::new());
        assert_eq!(required("not ($a and $b)"), Vec::<u32>::new());
    }

    #[test]
    fn a_negated_disjunction_does_not_leak_its_operands() {
        // The `or` rule intersects its operands. Wrapped in a `not`, that
        // intersection is a requirement for the *opposite* of what is wanted.
        assert_eq!(required("not (($a and $b) or ($a and $c))"), Vec::<u32>::new());
    }

    #[test]
    fn counts_and_offsets_require_nothing() {
        // `#a == 0` is writable, and a rule that says it must not be dropped
        // for want of `$a`.
        assert_eq!(required("#a == 0"), Vec::<u32>::new());
        assert_eq!(required("#a > 2"), Vec::<u32>::new());
        assert_eq!(required("@a[1] > 100"), Vec::<u32>::new());
        assert_eq!(required("!a < 10"), Vec::<u32>::new());
    }

    #[test]
    fn a_loop_requires_nothing_from_its_body() {
        // `for all i in (0..0)` is vacuously true, and `for any` over an empty
        // range is false whatever the body says. The bounds are not known here.
        assert_eq!(
            required("for all i in (0..10) : ($a at i)"),
            Vec::<u32>::new()
        );
        assert_eq!(required("for any of ($a*) : ($)"), Vec::<u32>::new());
    }

    #[test]
    fn module_and_literal_conditions_require_nothing() {
        assert_eq!(required("filesize < 100"), Vec::<u32>::new());
        assert_eq!(required("true"), Vec::<u32>::new());
        assert_eq!(
            required("pe.number_of_sections > 3 and pe.is_dll()"),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn a_repeated_string_is_counted_once() {
        // The prefilter tallies required strings as a set. A duplicate would
        // make the tally never reach zero and the rule would never be
        // selected — a rule that silently stops firing because it mentioned
        // `$a` twice.
        assert_eq!(required("$a and $a"), vec![0]);
        assert_eq!(required("($a and $b) or ($a and $b and $c)"), vec![0, 1]);
    }

    #[test]
    fn the_result_is_sorted_so_the_encoding_is_stable() {
        // The slot list is part of what gets serialised into the database. Two
        // compilations of the same rule set must produce the same bytes.
        assert_eq!(required("$c and $a and $b"), vec![0, 1, 2]);
    }
}
