//! What the compiler refuses.

use std::fmt;

use crate::ast::Span;

/// A condition that could not be compiled.
///
/// # Why `feature` exists
///
/// Compiling a third-party rule set is an exercise in finding out which
/// language features matter. A message alone answers that one rule at a time;
/// a stable tag answers it for ten thousand rules at once, because the caller
/// can histogram on it and learn that, say, 4,100 rules need `pe.sections` and
/// eleven need regexes. That ordering is the whole basis for deciding what to
/// implement next, so the tag is part of the type rather than something a
/// caller has to recover by parsing the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    /// Explanation, naming the construct at fault.
    pub message: String,
    /// Stable short tag for the missing feature, e.g. `module field`.
    ///
    /// Drawn from a closed set of literals so that a histogram over many rules
    /// counts kinds of gap rather than kinds of wording.
    pub feature: &'static str,
    /// The particular thing that was refused, in the same closed vocabulary.
    ///
    /// `feature` says *what kind* of gap this is; this says *which one*. For a
    /// module field it is the path — `pe.number_of_signatures` — so that a
    /// histogram can rank the fields rather than the categories. That ranking
    /// is what decides which of `pe`'s two hundred members to implement, and
    /// guessing it would waste the work.
    ///
    /// Not free-form: a caller must be able to group on it, so it is the
    /// construct's own name and nothing else.
    pub detail: String,
    /// Where the problem is.
    ///
    /// The span of the whole condition, because [`crate::ast::Expr`] does not
    /// carry spans. Threading them through the AST would give per-node
    /// precision; until that is worth the churn, the message names the
    /// construct instead, which is what a reader needs anyway when the rule is
    /// one line of condition.
    pub span: Span,
}

impl CompileError {
    /// A construct the compiler does not implement yet.
    pub fn unsupported(feature: &'static str, what: impl fmt::Display, span: Span) -> Self {
        Self {
            message: format!("{feature} is not compiled yet: {what}"),
            feature,
            detail: what.to_string(),
            span,
        }
    }

    /// A condition referring to a string the rule never defined.
    ///
    /// Always an author error rather than a gap in the compiler, which is why
    /// it gets its own tag: it should never show up in a coverage histogram,
    /// and if it does, the set-expansion code is wrong.
    pub fn undefined_string(name: &str, span: Span) -> Self {
        Self {
            message: format!(
                "`${}` is used in the condition but never defined",
                strip(name)
            ),
            feature: "undefined string",
            detail: strip(name).to_string(),
            span,
        }
    }

    /// A set that expands to no strings at all — `any of ($a*)` where the rule
    /// defines no `$a...`.
    ///
    /// Refused rather than treated as vacuously false because it is almost
    /// always a typo, and a rule that silently never fires is invisible: it
    /// costs a detection and reports nothing.
    pub fn empty_set(set: &str, span: Span) -> Self {
        Self {
            message: format!("`{set}` names no strings defined by this rule"),
            feature: "empty string set",
            detail: set.to_string(),
            span,
        }
    }

    /// The rule defines more strings than a slot index can address.
    ///
    /// Only reachable from a generated rule; a hand-written one would have to
    /// name four billion strings.
    pub fn too_many_strings(count: usize, span: Span) -> Self {
        Self {
            message: format!("rule defines {count} strings, more than the engine can index"),
            feature: "too many strings",
            detail: count.to_string(),
            span,
        }
    }

    /// A rule that cannot be used because of another rule in the set.
    ///
    /// The three shapes are a reference to a rule that did not compile, a
    /// reference to a name the set defines twice, and a cycle. All three are
    /// properties of the *set* rather than of the condition, which is why they
    /// get their own tag: they are counted separately from missing language
    /// features, because implementing a feature never fixes one of them.
    ///
    /// `detail` is the name of the rule being refused and not the one at fault,
    /// so a histogram ranks the rules that were lost. The message names both.
    pub fn dependency(rule: String, span: Span, message: String) -> Self {
        Self {
            message,
            feature: "rule dependency",
            detail: rule,
            span,
        }
    }

    /// The handler is a bug in the compiler, not a gap in its coverage.
    pub fn internal(message: impl fmt::Display, span: Span) -> Self {
        Self {
            message: format!("internal compiler error: {message}"),
            feature: "internal",
            detail: message.to_string(),
            span,
        }
    }
}

fn strip(name: &str) -> &str {
    name.strip_prefix('$').unwrap_or(name)
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CompileError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undefined_string_is_named_without_a_doubled_dollar() {
        let e = CompileError::undefined_string("a", Span::new(0, 1));
        assert!(e.message.contains("`$a`"), "{}", e.message);
        let e = CompileError::undefined_string("$a", Span::new(0, 1));
        assert!(e.message.contains("`$a`"), "{}", e.message);
        assert!(!e.message.contains("$$"), "{}", e.message);
    }

    #[test]
    fn the_feature_tag_is_the_stable_part_of_the_error() {
        // The tag must not move when the wording does — it is what a coverage
        // histogram groups on.
        let e = CompileError::unsupported("module field", "pe.imphash", Span::new(0, 1));
        assert_eq!(e.feature, "module field");
        assert!(e.message.contains("pe.imphash"));
    }
}
