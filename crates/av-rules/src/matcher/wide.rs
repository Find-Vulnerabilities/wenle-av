//! Rewriting a pattern so that it matches UTF-16LE text.
//!
//! # The problem
//!
//! ```text
//! $a = /eval\s*\(/ wide
//! ```
//!
//! A `wide` string is the same text encoded as UTF-16LE, so every character
//! occupies two bytes: `e` is `65 00`, and the pattern has to match against
//! those bytes. For a plain string that is a mechanical transformation —
//! [`crate::matcher::text::variants`] inserts a null after each byte and is done. For a regular
//! expression it is not, because the pattern is not a sequence of bytes but a
//! description of one, and inserting nulls into the *source* would put them in
//! the wrong places: `\s` is one character, `[abc]` is one character, `a{2,4}`
//! is between two and four, and a null appended to the text of any of those
//! produces a pattern that means something else.
//!
//! # The transformation
//!
//! So the pattern is rewritten *structurally*, after parsing and not before.
//! Every element that denotes one character becomes that character's two bytes,
//! and every element that combines or repeats other elements is rebuilt around
//! them:
//!
//! ```text
//! ab        ->  \x61\x00\x62\x00
//! [a-c]     ->  [\x61-\x63]\x00
//! .         ->  [\x00-\x09\x0b-\xff]\x00
//! \s        ->  [\x09-\x0d\x20]\x00
//! a{2,4}    ->  (?:\x61\x00){2,4}
//! (ab|c)    ->  (?:\x61\x00\x62\x00|\x63\x00)
//! ```
//!
//! The escapes are the two-digit `\xHH` form rather than `\x{HH}`, because the
//! pattern is compiled with `unicode(false)` and the braced form is a Unicode
//! escape there — `\x{ff}` is rejected outright while `\xff` is the byte.
//!
//! Each rewritten element is exactly the two bytes a UTF-16LE decoder would
//! read for one character, so a match on the rewritten pattern is a match on
//! the original pattern over the decoded text. It is a translation rather than
//! an approximation.
//!
//! One consequence is worth stating because it is the reason the work is done
//! on the parse tree: a character whose code unit is above `0xff` cannot be
//! written as two bytes, and no byte-oriented class denotes one. The classes
//! here are byte classes — the parser is asked for `unicode(false)`, so `.` is a
//! class over bytes and not over code points — and that is what makes the
//! translation total: every class the parser can produce is a set of code units
//! below `0x100`, and every one of those has a two-byte encoding.
//!
//! Anchors are kept, because they are assertions about a *position* rather than
//! about the characters around it: `^` and `\A` mean the same thing before and
//! after the rewrite, and a match at the start of the widened stream is a match
//! at the start of the text.
//!
//! # Word boundaries
//!
//! A word boundary is the one construct that is not a rewrite. It is an
//! assertion about the characters on *both* sides of a position, and in the
//! widened stream the byte before a position is the *high* half of the previous
//! character — almost always `00` — while the byte after is the low half of the
//! next. Kept as it is, `\beval` would match the `eval` inside `aeval`, which is
//! a rule firing on a file its author excluded. There is no rewrite of `\b` into
//! the constructs this engine has: it is a one-byte lookbehind, and the regex
//! engine has no lookbehind.
//!
//! So the boundary is taken *out* of the pattern and asked about the match
//! afterwards. [`widen`] returns it as a [`Boundary`] beside the text, and
//! [`Boundary::holds`] answers whether a span the rewritten pattern matched is
//! delimited the way the assertion asked. Nothing here is approximate: the
//! assertion is about the characters around the match, and the caller has the
//! match. It just cannot be made *inside* one, which is why it is not in the
//! pattern.
//!
//! What that restricts is where a boundary may sit. A leading `\b` is a check on
//! the character before `start` and a trailing one a check on the character at
//! `end`, so a boundary in the middle of a match — `a\bb`, or one inside a
//! repetition, where how many characters precede it depends on how many times
//! the repetition ran — is not something either check can answer. Those are
//! refused rather than checked at the wrong end. So is an alternation whose
//! branches disagree: `(?:\bfoo|bar)` is checked once for the whole match, and
//! the `bar` branch would be filtered by an assertion its author never wrote.
//!
//! The corpus asks for a leading boundary in 206 of the 220 `wide` patterns
//! that write one and a trailing boundary in 11 more, so this covers all but a
//! handful — and the handful are refused by name rather than matched loosely.

use regex_syntax::hir::{Capture, Class, Hir, HirKind, Look, Repetition};

use super::MatcherError;

/// The hexadecimal digits, for writing a byte into a pattern.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Rewrite `hir` so that it matches the UTF-16LE encoding of what it described.
///
/// Returns the pattern text, to be compiled by whoever asked, and the word
/// boundaries the pattern asserted but could not carry. A construct that cannot
/// be rewritten exactly is an error rather than an approximation.
pub fn widen(hir: &Hir) -> Result<Widened, MatcherError> {
    // Dead branches go first, so that the two walks and the rewrite below all
    // see the same tree. A branch is dead when a word boundary inside it cannot
    // hold there whatever the input is, and dropping it changes nothing about
    // what the pattern matches — see [`prune`]. It has to happen before the
    // walks rather than inside them: a branch dropped from one walk and not the
    // other would misalign the assertion lists, and a branch dropped from the
    // walks but left in the pattern would have its `\b` evaluated by the regex
    // engine against the widened bytes, which is the mistake this whole module
    // exists to avoid.
    let Some(hir) = prune(hir) else {
        return Err(every_path_is_impossible());
    };
    let boundary = Boundary::of(&hir)?;
    let mut out = String::new();
    write(&hir, &mut out)?;
    Ok(Widened {
        pattern: out,
        boundary,
    })
}

/// Drop every way through `hir` that can never match, or `None` if that is all
/// of them.
///
/// # What makes a branch dead
///
/// A word boundary that cannot hold at the position it sits in. `\b` holds
/// exactly when one of the characters around its position is a word character
/// and the other is not, so between two word characters — `Web\browsers`, and
/// the `\b` there is a corpus typo for `\s` — it is false at every position, and
/// so is `\B` between a word character and a non-word one.
///
/// # Why this is exact rather than an approximation
///
/// A dead branch matches no input, so removing it from the alternation it
/// belongs to removes nothing from the pattern's language. The analysis is
/// deliberately one-sided: a byte that is certainly a word character or
/// certainly not one comes only from a literal, and a class or a nested
/// alternation answers "unknown" and is left alone, which costs a missed
/// pruning and never a wrong one. A pattern whose every path is dead is refused
/// rather than compiled to something that never fires, for the reason `\b\B` is
/// refused.
fn prune(hir: &Hir) -> Option<Hir> {
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => {
            Some(hir.clone())
        }
        HirKind::Capture(capture) => {
            let sub = prune(&capture.sub)?;
            Some(Hir::capture(Capture {
                sub: Box::new(sub),
                ..capture.clone()
            }))
        }
        HirKind::Repetition(repetition) => match prune(&repetition.sub) {
            Some(sub) => Some(Hir::repetition(Repetition {
                sub: Box::new(sub),
                ..repetition.clone()
            })),
            // A repetition whose body can never match still matches the empty
            // string when it is allowed zero of them, and nothing at all
            // otherwise.
            None if repetition.min == 0 => Some(Hir::empty()),
            None => None,
        },
        HirKind::Concat(parts) => {
            let kept: Vec<Hir> = parts.iter().filter_map(prune).collect();
            if asserts_an_impossible_boundary(&kept) {
                return None;
            }
            Some(Hir::concat(kept))
        }
        HirKind::Alternation(parts) => {
            let kept: Vec<Hir> = parts.iter().filter_map(prune).collect();
            if kept.is_empty() {
                return None;
            }
            Some(Hir::alternation(kept))
        }
    }
}

/// Whether a sequence asserts a word boundary that cannot hold where it sits.
///
/// Only the boundaries written directly between two elements of the sequence
/// are looked at. One at either end of it is a boundary of the *match* when the
/// sequence is the whole pattern, and it is [`Boundary::of`] that decides
/// whether it can be checked — a leading or trailing `\b` is supported and must
/// not be pruned away.
fn asserts_an_impossible_boundary(parts: &[Hir]) -> bool {
    parts.iter().enumerate().any(|(index, part)| {
        let HirKind::Look(look) = part.kind() else {
            return false;
        };
        let before = index.checked_sub(1).and_then(|i| ends_with_word(&parts[i]));
        let after = parts.get(index + 1).and_then(starts_with_word);
        // `None` on either side is "not known", which is never grounds for
        // pruning: a boundary next to a class, a repetition or another
        // alternation stays exactly where its author put it.
        match (look, before, after) {
            (Look::WordAscii, Some(before), Some(after)) => before == after,
            (Look::WordAsciiNegate, Some(before), Some(after)) => before != after,
            _ => false,
        }
    })
}

/// Whether every string this element can match ends with an ASCII word byte, or
/// `None` when that cannot be told from the tree.
fn ends_with_word(hir: &Hir) -> Option<bool> {
    match hir.kind() {
        HirKind::Literal(literal) => literal.0.last().map(|byte| is_word_byte(*byte)),
        _ => None,
    }
}

/// Whether every string this element can match starts with an ASCII word byte.
fn starts_with_word(hir: &Hir) -> Option<bool> {
    match hir.kind() {
        HirKind::Literal(literal) => literal.0.first().map(|byte| is_word_byte(*byte)),
        _ => None,
    }
}

/// The word-character test [`Assertion::holds`] applies to a decoded character,
/// for a byte of the pattern's own text.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// A widened pattern: the text to compile, and what to ask of a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Widened {
    /// The pattern, over the bytes of a UTF-16LE stream.
    pub pattern: String,
    /// The word boundaries the pattern asserted, to be checked against each
    /// match of `pattern` — see [`Boundary`].
    pub boundary: Boundary,
}

/// The word-boundary assertions a widened pattern carries.
///
/// Each is about a position the match has, so each is a predicate on the match
/// rather than a part of the pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Boundary {
    /// What the pattern asserts at the position the match starts, if anything.
    leading: Option<Assertion>,
    /// What it asserts at the position the match ends.
    trailing: Option<Assertion>,
}

impl Boundary {
    /// Whether there is nothing to check, so that a caller can skip the work —
    /// and, more to the point, take the plain non-overlapping search.
    pub fn is_none(&self) -> bool {
        self.leading.is_none() && self.trailing.is_none()
    }

    /// Whether a match covering `start..end` is delimited the way the pattern
    /// asked.
    ///
    /// `data` is the whole buffer and the offsets are into it, because the
    /// characters either side of a match are outside it: the check is on the
    /// text around the match, not on the match.
    pub fn holds(&self, data: &[u8], start: usize, end: usize) -> bool {
        let leading = match self.leading {
            Some(assertion) => assertion.holds(data, start),
            None => true,
        };
        let trailing = match self.trailing {
            Some(assertion) => assertion.holds(data, end),
            None => true,
        };
        leading && trailing
    }

    /// Read the boundary assertions out of a parse tree, in terms of the ends of
    /// a match.
    ///
    /// Two walks, because "does anything come before this position" and "does
    /// anything come after it" are answered in opposite directions. They visit
    /// the assertions in the same order — every arm below walks its children in
    /// the order they are written — so the two lists line up.
    fn of(hir: &Hir) -> Result<Self, MatcherError> {
        let mut before = Vec::new();
        let mut after = Vec::new();
        walk_before(hir, false, &mut before)?;
        walk_after(hir, false, &mut after)?;
        // Not reachable while the two walks agree on the order, and checked
        // rather than assumed: a misaligned pair would silently check one
        // assertion against the other end of the match, which is a rule that
        // fires on the wrong files.
        if before.len() != after.len() {
            return Err(MatcherError::unsupported(
                "wide regex",
                "the word boundaries of this `wide` regular expression cannot be placed",
            ));
        }
        let mut boundary = Boundary::default();
        for ((assertion, preceded), (_, followed)) in before.iter().zip(after.iter()) {
            if !preceded {
                boundary.set(Side::Leading, *assertion)?;
            } else if !followed {
                boundary.set(Side::Trailing, *assertion)?;
            } else {
                return Err(MatcherError::unsupported(
                    "wide regex",
                    "a `wide` regular expression with a word boundary in the middle of a match \
                     is not supported: the assertion is about the characters either side of a \
                     position, and the engine can only be asked about the position a match \
                     starts at or the one it ends at",
                ));
            }
        }
        Ok(boundary)
    }

    /// Record an assertion about one end of the match.
    ///
    /// Two assertions about the same end have to agree, which is what `\b\b`
    /// does and `\b\B` does not. The second is a pattern that matches nothing:
    /// refused, because the alternative is a rule that never fires and a
    /// diagnostic that never explains why.
    fn set(&mut self, side: Side, assertion: Assertion) -> Result<(), MatcherError> {
        let slot = match side {
            Side::Leading => &mut self.leading,
            Side::Trailing => &mut self.trailing,
        };
        match slot {
            Some(existing) if *existing != assertion => Err(MatcherError::unsupported(
                "wide regex",
                "a `wide` regular expression asserts both a word boundary and its opposite at \
                 one end of a match, so it can never match anything",
            )),
            _ => {
                *slot = Some(assertion);
                Ok(())
            }
        }
    }
}

/// Which end of a match an assertion is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Leading,
    Trailing,
}

/// A word-boundary assertion, as the one question there is to ask of a position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assertion {
    /// `\b` — exactly one of the characters around the position is a word
    /// character.
    Boundary,
    /// `\B` — the two agree.
    NotBoundary,
}

impl Assertion {
    /// Whether the assertion holds at `at`, a byte offset into a UTF-16LE
    /// stream.
    fn holds(self, data: &[u8], at: usize) -> bool {
        let before = is_word_at(data, at, -1);
        let after = is_word_at(data, at, 0);
        match self {
            Assertion::Boundary => before != after,
            Assertion::NotBoundary => before == after,
        }
    }
}

/// Whether the character `delta` characters from `at` is a word character.
///
/// A character of a UTF-16LE stream is two bytes, little-endian, so the one
/// before a position is the two bytes before it. Above ASCII the high byte is
/// not `00`, and below it the character is a word character exactly when it is
/// a letter, a digit or an underscore — the ASCII definition, which is the one
/// every regex engine uses for a byte-oriented `\b`.
///
/// Off either end of the buffer there is no character, and no character is not
/// a word character: `\b` holds at the start of a text whose first character is
/// a word character and fails at one whose first character is not.
fn is_word_at(data: &[u8], at: usize, delta: i8) -> bool {
    let offset = at as i64 + i64::from(delta) * 2;
    let Ok(offset) = usize::try_from(offset) else {
        return false;
    };
    let Some(end) = offset.checked_add(2) else {
        return false;
    };
    let Some(pair) = data.get(offset..end) else {
        return false;
    };
    pair[1] == 0 && (pair[0].is_ascii_alphanumeric() || pair[0] == b'_')
}

/// Collect every assertion in `hir` with whether a character precedes it.
///
/// `preceded` is whether something before this subtree, on the path the walk
/// came by, consumes a character.
fn walk_before(
    hir: &Hir,
    preceded: bool,
    out: &mut Vec<(Assertion, bool)>,
) -> Result<(), MatcherError> {
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) => Ok(()),

        HirKind::Look(look) => {
            if let Some(assertion) = assertion_of(*look) {
                out.push((assertion, preceded));
            }
            Ok(())
        }

        // A boundary inside a repetition is at neither end of the match: how
        // many characters precede it depends on how many times the repetition
        // ran, and the caller can only be asked about the two ends.
        HirKind::Repetition(repetition) => {
            if has_boundary(&repetition.sub) {
                return Err(inside_a_repetition());
            }
            Ok(())
        }

        HirKind::Capture(capture) => walk_before(&capture.sub, preceded, out),

        HirKind::Concat(parts) => {
            let mut preceded = preceded;
            for part in parts {
                walk_before(part, preceded, out)?;
                preceded |= consumes(part);
            }
            Ok(())
        }

        // Every branch contributes to the same match, so the branches have to
        // agree about the assertions they make: an assertion is checked once,
        // for whichever branch matched, and a branch that does not make it would
        // have its matches filtered by something its author never wrote.
        HirKind::Alternation(parts) => {
            let mut branches = Vec::with_capacity(parts.len());
            for part in parts {
                let mut here = Vec::new();
                walk_before(part, preceded, &mut here)?;
                branches.push(here);
            }
            let Some((first, rest)) = branches.split_first() else {
                return Ok(());
            };
            if rest.iter().any(|other| other != first) {
                return Err(disagreeing_branches());
            }
            out.extend(first.iter().copied());
            Ok(())
        }
    }
}

/// Collect every assertion in `hir` with whether a character follows it.
///
/// The same walk as [`walk_before`] in the other direction, and it has to visit
/// the assertions in the same order — so a concatenation is walked from its last
/// element to its first while the results are assembled the other way round.
fn walk_after(
    hir: &Hir,
    followed: bool,
    out: &mut Vec<(Assertion, bool)>,
) -> Result<(), MatcherError> {
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) => Ok(()),

        HirKind::Look(look) => {
            if let Some(assertion) = assertion_of(*look) {
                out.push((assertion, followed));
            }
            Ok(())
        }

        HirKind::Repetition(repetition) => {
            if has_boundary(&repetition.sub) {
                return Err(inside_a_repetition());
            }
            Ok(())
        }

        HirKind::Capture(capture) => walk_after(&capture.sub, followed, out),

        HirKind::Concat(parts) => {
            let mut followed = followed;
            let mut collected: Vec<(Assertion, bool)> = Vec::new();
            for part in parts.iter().rev() {
                let mut here = Vec::new();
                walk_after(part, followed, &mut here)?;
                here.extend(collected);
                collected = here;
                followed |= consumes(part);
            }
            out.extend(collected);
            Ok(())
        }

        HirKind::Alternation(parts) => {
            let mut branches = Vec::with_capacity(parts.len());
            for part in parts {
                let mut here = Vec::new();
                walk_after(part, followed, &mut here)?;
                branches.push(here);
            }
            let Some((first, rest)) = branches.split_first() else {
                return Ok(());
            };
            if rest.iter().any(|other| other != first) {
                return Err(disagreeing_branches());
            }
            out.extend(first.iter().copied());
            Ok(())
        }
    }
}

/// The assertion a look denotes, for the two forms a word boundary has here.
///
/// `None` for everything else, including the Unicode word boundaries and the
/// half-boundaries: the parser cannot produce them with `unicode(false)` set,
/// and [`look_to_look`] refuses them by name rather than letting a look this
/// module does not implement pass as one it does.
fn assertion_of(look: Look) -> Option<Assertion> {
    match look {
        Look::WordAscii => Some(Assertion::Boundary),
        Look::WordAsciiNegate => Some(Assertion::NotBoundary),
        _ => None,
    }
}

/// Whether a subtree contains a word-boundary assertion.
fn has_boundary(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) => false,
        HirKind::Look(look) => assertion_of(*look).is_some(),
        HirKind::Repetition(repetition) => has_boundary(&repetition.sub),
        HirKind::Capture(capture) => has_boundary(&capture.sub),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => parts.iter().any(has_boundary),
    }
}

/// Whether a subtree consumes a character on some path through it.
///
/// A `true` where the subtree turns out to consume nothing would make a leading
/// boundary look like an inner one and the pattern be refused — the safe
/// direction. A `false` where it does consume would make an inner boundary look
/// leading and be checked at the wrong end, which is not; so a repetition counts
/// as consuming when its lower bound is non-zero and its body does, and an
/// alternation when any branch does.
fn consumes(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => false,
        HirKind::Literal(literal) => !literal.0.is_empty(),
        HirKind::Class(_) => true,
        HirKind::Repetition(repetition) => repetition.min > 0 && consumes(&repetition.sub),
        HirKind::Capture(capture) => consumes(&capture.sub),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => parts.iter().any(consumes),
    }
}

fn inside_a_repetition() -> MatcherError {
    MatcherError::unsupported(
        "wide regex",
        "a `wide` regular expression with a word boundary inside a repetition is not supported: \
         how many characters come before the assertion depends on how many times the repetition \
         ran, so it is at neither end of the match",
    )
}

fn every_path_is_impossible() -> MatcherError {
    MatcherError::unsupported(
        "wide regex",
        "every way through this `wide` regular expression asserts a word boundary that cannot \
         hold where it sits — `\\b` between two word characters, or between two that are not word \
         characters — so the pattern can never match anything",
    )
}

fn disagreeing_branches() -> MatcherError {
    MatcherError::unsupported(
        "wide regex",
        "a `wide` regular expression whose alternatives do not all assert the same word \
         boundary at the same end is not supported: the assertion is checked once for the \
         match, so a branch without it would be filtered by one it does not make",
    )
}

fn write(hir: &Hir, out: &mut String) -> Result<(), MatcherError> {
    match hir.kind() {
        HirKind::Empty => Ok(()),

        // One character per byte, so each byte becomes a code unit. This is the
        // arm the whole module exists for: the nulls go after the characters,
        // not after the escapes.
        HirKind::Literal(literal) => {
            for &byte in literal.0.iter() {
                unit(out, byte);
            }
            Ok(())
        }

        // A class denotes one character, so it becomes a class over the low
        // bytes followed by the high byte, which is `00` for every code unit a
        // byte class can name.
        HirKind::Class(class) => {
            class_to_class(out, class);
            out.push_str("\\x00");
            Ok(())
        }

        HirKind::Look(look) => look_to_look(*look, out),

        // The quantifier applies to a rewritten element, which is two bytes
        // rather than one, so it has to be grouped or it would bind to the last
        // byte alone: `a{2}` is `aa`, and `\x{61}\x{00}{2}` is `a` followed by
        // two nulls.
        HirKind::Repetition(Repetition {
            min,
            max,
            greedy,
            sub,
        }) => {
            out.push_str("(?:");
            write(sub, out)?;
            out.push(')');
            quantifier(out, *min, *max, *greedy);
            Ok(())
        }

        // Kept as a group rather than flattened, because a backreference would
        // need the same numbering — and because the numbering is the only thing
        // a caller can observe about it.
        HirKind::Capture(capture) => {
            out.push('(');
            write(&capture.sub, out)?;
            out.push(')');
            Ok(())
        }

        HirKind::Concat(parts) => {
            for part in parts {
                write(part, out)?;
            }
            Ok(())
        }

        // Grouped, so that the surrounding concatenation cannot capture the
        // last alternative: `ab|cd` rewritten bare would be `a b|c d` and the
        // `b` would belong to the first branch only.
        HirKind::Alternation(parts) => {
            out.push_str("(?:");
            for (index, part) in parts.iter().enumerate() {
                if index > 0 {
                    out.push('|');
                }
                write(part, out)?;
            }
            out.push(')');
            Ok(())
        }
    }
}

/// One code unit, as the two bytes a UTF-16LE decoder reads for it.
///
/// The high byte is `00` because the parser is asked for `unicode(false)`: a
/// literal is a sequence of bytes, and each one is a character below `0x100`
/// whose code unit is itself. This is the function that does the interleaving,
/// so it is also the one place where getting it wrong makes every pattern here
/// match ASCII.
fn unit(out: &mut String, byte: u8) {
    push_byte(out, byte);
    out.push_str("\\x00");
}

/// One byte, as the escape `unicode(false)` accepts.
///
/// The braced `\x{ff}` form is the one a Unicode-mode pattern uses and this
/// compiler is not in Unicode mode: it is matching bytes, and there `\x{ff}` is
/// an error while `\xff` is the byte. Writing the two-digit form everywhere
/// keeps one spelling for every pattern this module produces.
fn push_byte(out: &mut String, byte: u8) {
    out.push_str("\\x");
    push_hex(out, byte);
}

/// A byte class as a pattern class, without the trailing high byte.
fn class_to_class(out: &mut String, class: &Class) {
    out.push('[');
    match class {
        Class::Bytes(bytes) => {
            if bytes.iter().next().is_none() {
                // A class that matches nothing — `[^\x00-\xff]`, which a rule
                // can write. `[]` is a syntax error rather than an empty class,
                // so the empty set is spelled as the negation of everything.
                out.push_str("^\\x00-\\xff");
            }
            for range in bytes.iter() {
                // Always written as explicit escapes: a range whose end is a
                // `]` or whose start is a `-` would otherwise be read as the
                // end of the class or as a literal dash.
                push_byte(out, range.start());
                out.push('-');
                push_byte(out, range.end());
            }
        }
        // Unreachable while the parser is asked for `unicode(false)`, and
        // written out anyway so that a future caller that turns Unicode on gets
        // the code units it asked for rather than a silently narrower class.
        Class::Unicode(unicode) => {
            for range in unicode.iter() {
                push_byte(out, range.start() as u8);
                out.push('-');
                push_byte(out, range.end() as u8);
            }
        }
    }
    out.push(']');
}

/// A `{min,max}` suffix, written in the shortest form that means it.
fn quantifier(out: &mut String, min: u32, max: Option<u32>, greedy: bool) {
    match (min, max) {
        (0, None) => out.push('*'),
        (1, None) => out.push('+'),
        (0, Some(1)) => out.push('?'),
        (min, Some(max)) if min == max => {
            out.push('{');
            push_u32(out, min);
            out.push('}');
        }
        (min, Some(max)) => {
            out.push('{');
            push_u32(out, min);
            out.push(',');
            push_u32(out, max);
            out.push('}');
        }
        (min, None) => {
            out.push('{');
            push_u32(out, min);
            out.push_str(",}");
        }
    }
    // The rewriting does not change which repetition the author asked for, so
    // a lazy quantifier stays lazy rather than being quietly made greedy.
    if !greedy {
        out.push('?');
    }
}

/// An assertion about a position, kept or refused.
fn look_to_look(look: Look, out: &mut String) -> Result<(), MatcherError> {
    let text = match look {
        Look::Start => "\\A",
        Look::StartLF => "^",
        Look::End => "\\z",
        Look::EndLF => "$",
        // Only produced under a CRLF mode this engine does not enable. Refused
        // rather than spelled as `^`, because the two differ on a buffer whose
        // lines end in `\r\n` and a rule written for one is not the other.
        Look::StartCRLF | Look::EndCRLF => {
            return Err(MatcherError::unsupported(
                "wide regex",
                "a `wide` regular expression using CRLF line anchors is not supported",
            ));
        }
        // Written as nothing at all, because it is not a thing the pattern can
        // say: the assertion is about the characters on both sides of a
        // position, and in UTF-16LE the byte before a position is the *high*
        // half of the previous character — always `00` for ASCII — so left in
        // place `\beval` would match the `eval` inside `aeval`. [`Boundary`]
        // carries it out of the pattern and checks it against the match.
        Look::WordAscii | Look::WordAsciiNegate => return Ok(()),

        // The rest of the word-boundary family, refused by name rather than
        // rewritten as if it were `\b`. They are unreachable with
        // `unicode(false)` set — which is how every pattern here is parsed — and
        // they are listed exhaustively so that a future variant fails to compile
        // in this arm instead of being silently accepted as one of the two above.
        // The Unicode forms would need a Unicode word-character class and the
        // half-boundaries a definition of a word edge this engine does not have.
        Look::WordUnicode
        | Look::WordUnicodeNegate
        | Look::WordStartAscii
        | Look::WordEndAscii
        | Look::WordStartUnicode
        | Look::WordEndUnicode
        | Look::WordStartHalfAscii
        | Look::WordEndHalfAscii
        | Look::WordStartHalfUnicode
        | Look::WordEndHalfUnicode => {
            return Err(MatcherError::unsupported(
                "wide regex",
                "a `wide` regular expression using a half-boundary or a Unicode word boundary \
                 is not supported: this engine matches bytes, and only `\\b` and `\\B` over \
                 ASCII word characters are defined over them",
            ));
        }
    };
    out.push_str(text);
    Ok(())
}

fn push_hex(out: &mut String, byte: u8) {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

fn push_u32(out: &mut String, value: u32) {
    // A repetition bound is a number the parser already accepted, so this is
    // formatting rather than parsing; `u32::to_string` is the decimal the
    // pattern language wants.
    out.push_str(&value.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex_syntax::ParserBuilder;

    /// Widen a pattern body the way `compile` does.
    fn widen_body(body: &str) -> Widened {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(body)
            .expect("the test pattern must parse");
        widen(&hir).expect("the test pattern must widen")
    }

    /// The rewritten pattern text, for the tests that are about the rewrite
    /// rather than about what it matches.
    fn widened(body: &str) -> String {
        widen_body(body).pattern
    }

    /// Widen, then compile and run against a buffer: the only test that says
    /// the rewrite means what it claims.
    ///
    /// Compiled with `unicode(false)`, the same way `build_regex` compiles it.
    /// A test that compiled it the other way would be testing a pattern the
    /// scanner never builds, and the two differ exactly where it matters: a
    /// negated class over the whole byte range matches invalid UTF-8 in one
    /// mode and not the other, and a wide stream is full of nulls.
    fn matches(body: &str, data: &[u8]) -> bool {
        span(body, data).is_some()
    }

    /// Where the first match the *whole* string accepts is, as a byte range.
    ///
    /// The boundary is checked here because it is checked in the scanner, and a
    /// test that skipped it would be testing a pattern the engine does not use.
    ///
    /// The length is the assertion most of these tests are really making: a
    /// widened pattern that matched the right characters for the wrong number
    /// of bytes would pass an `is_match` and still be wrong on the next element
    /// of the pattern.
    fn span(body: &str, data: &[u8]) -> Option<(usize, usize)> {
        let widened = widen_body(body);
        let re = regex::bytes::RegexBuilder::new(&widened.pattern)
            .unicode(false)
            .build()
            .expect("the widened pattern must compile");
        let mut at = 0;
        while at <= data.len() {
            let m = re.find_at(data, at)?;
            at = m.start() + 1;
            if m.is_empty() {
                continue;
            }
            if !widened.boundary.holds(data, m.start(), m.end()) {
                continue;
            }
            return Some((m.start(), m.end()));
        }
        None
    }

    /// A string as UTF-16LE, which is what a `wide` pattern is written for.
    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A string as ASCII, which is not.
    fn ascii(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    #[test]
    fn a_literal_becomes_the_bytes_a_wide_decoder_reads() {
        assert_eq!(widened("abc"), "\\x61\\x00\\x62\\x00\\x63\\x00");
        assert!(matches("abc", &utf16("abc")));
        // The point of the whole transformation: the same bytes are not the
        // ASCII text, so an ASCII file must not match a wide pattern.
        assert!(!matches("abc", &ascii("abc")));
    }

    #[test]
    fn a_match_is_found_wherever_the_text_sits_in_the_buffer() {
        // A non-text header in front of the wide text, because a real file is
        // never only the string a rule is looking for.
        let mut data = vec![b'M', b'Z', 0x90, 0x00];
        data.extend_from_slice(&utf16("xxeval(yy)"));
        assert!(matches(r"eval\s*\(", &data));
    }

    #[test]
    fn a_class_is_one_character_and_so_gets_one_null() {
        assert_eq!(
            widened("[a-c]"),
            "[\\x61-\\x63]\\x00",
            "the null goes after the class, not after each member"
        );
        assert!(matches("[a-c]", &utf16("b")));
        assert!(!matches("[a-c]", &utf16("d")));
        // One character, so the match is the class and its null and nothing
        // more. A rewrite that appended a null per *member* of the class would
        // still match the first two bytes here; this is what says it does not.
        assert_eq!(span("[a-c]", &utf16("b")), Some((0, 2)));
        assert_eq!(span("[a-c]", &utf16("bbb")), Some((0, 2)));
    }

    #[test]
    fn a_negated_class_keeps_its_negation() {
        assert!(matches(r#"[^"]"#, &utf16("x")));
        assert!(!matches(r#"[^"]"#, &utf16("\"")));
    }

    #[test]
    fn the_dot_takes_the_newline_rule_from_the_pattern_rather_than_the_rewrite() {
        // `.` is a class before the rewrite and stays one after it, so whether
        // it matches a newline is decided by the flag the author wrote and not
        // by the widening.
        assert!(!matches("a.b", &utf16("a\nb")), "`.` excludes a newline");
        assert!(matches("a.b", &utf16("axb")));
    }

    #[test]
    fn a_quantifier_binds_to_the_whole_character() {
        assert_eq!(widened("a{2,3}"), "(?:\\x61\\x00){2,3}");
        assert!(matches("a{2,3}", &utf16("aa")));
        assert!(matches("a{2,3}", &utf16("aaa")));
        assert!(!matches("a{2,3}", &utf16("a")));
        // Two characters, so the match is four bytes and not the `a`, `\0`, `\0`
        // a quantifier bound to the last byte alone would have taken.
        assert_eq!(span("a{2}", &utf16("aa")), Some((0, 4)));
        assert_eq!(span("a{3}", &utf16("aaa")), Some((0, 6)));
    }

    #[test]
    fn a_lazy_quantifier_stays_lazy() {
        assert_eq!(widened("a+?"), "(?:\\x61\\x00)+?");
    }

    #[test]
    fn an_alternation_is_grouped_so_a_branch_does_not_swallow_what_follows() {
        assert_eq!(
            widened("ab|cd"),
            "(?:\\x61\\x00\\x62\\x00|\\x63\\x00\\x64\\x00)"
        );
        assert!(matches("ab|cd", &utf16("cd")));
        // Without the group the rewrite would be `a b|c d`, whose first branch
        // is `ab` and whose second is `cd` — but a following element would bind
        // to the second branch alone. This checks the grouped form.
        assert!(matches("ab|cd", &utf16("ab")));
        assert!(!matches("ab|cd", &utf16("ad")));
    }

    #[test]
    fn a_perl_class_becomes_the_code_units_it_names() {
        // `\s` and `\w` are byte classes here, so each is one character
        // followed by one null rather than a set of characters the pattern
        // would then have to interleave.
        assert!(matches(r"\s", &utf16(" ")));
        assert!(matches(r"\s", &utf16("\t")));
        assert!(!matches(r"\s", &utf16("x")));
        assert!(matches(r"\w", &utf16("_")));
        assert!(!matches(r"\w", &utf16("-")));

        // The literal case the corpus writes over and over.
        assert!(matches(r"eval\s*\(", &utf16("eval (")));
        assert!(matches(r"eval\s*\(", &utf16("eval(")));
        assert!(matches(r"eval\s*\(", &utf16("eval   (")));
        assert!(!matches(r"eval\s*\(", &utf16("evall(")));
    }

    #[test]
    fn a_group_keeps_its_structure_and_its_contents_are_widened() {
        assert_eq!(widened("(ab)+"), "(?:(\\x61\\x00\\x62\\x00))+");
        assert!(matches("(ab)+", &utf16("abab")));
        // `aba` contains one `ab`, and the repetition stops there rather than
        // reaching into the trailing `a` — which is what a `+` bound to a
        // single byte would have done.
        assert_eq!(span("(ab)+", &utf16("aba")), Some((0, 4)));
    }

    #[test]
    fn an_anchor_keeps_meaning_the_place_rather_than_the_bytes_around_it() {
        assert!(matches("^abc", &utf16("abc")));
        assert!(!matches("^abc", utf16("xabc").as_slice()));
        assert!(matches("abc$", &utf16("xabc")));
        assert!(!matches("abc$", utf16("abcx").as_slice()));
    }

    // -- word boundaries ---------------------------------------------------

    #[test]
    fn a_word_boundary_comes_out_of_the_pattern_and_into_the_check() {
        // Nothing of the assertion is left in the text — the pattern is just
        // the word — and the check it stands for is carried beside it.
        let word = widen_body(r"\beval");
        assert_eq!(word.pattern, widened(r"eval"));
        assert_eq!(word.boundary.leading, Some(Assertion::Boundary));
        assert_eq!(word.boundary.trailing, None);
    }

    #[test]
    fn a_leading_boundary_is_the_character_before_the_match() {
        // The failure this exists for: with `\b` left in the pattern, the
        // assertion before `e` reads the high byte of the previous character —
        // always `00`, never a word byte — and reports a boundary, so `\beval`
        // would match the `eval` inside `aeval`.
        assert!(matches(r"\beval", &utf16("eval")));
        assert!(matches(r"\beval", &utf16(" eval")));
        assert!(!matches(r"\beval", &utf16("aeval")));
        // At the start of the buffer there is no character, which is not a word
        // character, so a boundary does hold there.
        assert_eq!(span(r"\beval", &utf16("eval")), Some((0, 8)));
    }

    #[test]
    fn a_trailing_boundary_is_the_character_after_the_match() {
        assert!(matches(r"eval\b", &utf16("eval ")));
        assert!(matches(r"eval\b", &utf16("eval")));
        assert!(!matches(r"eval\b", &utf16("evals")));
        // Two bytes per character, so the `eval` at character 2 ends at byte 12.
        assert_eq!(span(r"eval\b", &utf16("x eval!")), Some((4, 12)));
    }

    #[test]
    fn a_boundary_at_both_ends_is_checked_at_both() {
        assert!(matches(r"\beval\b", &utf16("run eval(x)")));
        assert!(!matches(r"\beval\b", &utf16("run aeval(x)")));
        assert!(!matches(r"\beval\b", &utf16("run evals(x)")));
    }

    #[test]
    fn the_negated_boundary_is_the_same_check_the_other_way_round() {
        assert_eq!(
            widen_body(r"\Beval").boundary.leading,
            Some(Assertion::NotBoundary)
        );
        assert!(!matches(r"\Beval", &utf16(" eval")));
        assert!(matches(r"\Beval", &utf16("aeval")));
    }

    #[test]
    fn a_word_character_is_a_letter_a_digit_or_an_underscore() {
        // The ASCII definition, which is the one a byte-oriented `\b` uses, and
        // which is decided on the *character* rather than on either of its two
        // bytes.
        assert!(matches(r"\b_x", &utf16("_x")));
        assert!(matches(r"\b7x", &utf16("7x")));
        assert!(!matches(r"\b-x", &utf16("-x")));
        assert!(!matches(r"\b.x", &utf16(".x")));
        // Above ASCII the high byte is not `00`, so the character is not one a
        // byte-oriented word class names.
        assert!(!matches(r"\b\u{e9}x", &utf16("\u{e9}x")));
    }

    #[test]
    fn a_boundary_in_the_middle_of_a_match_is_refused() {
        // `a\Bb`: the assertion can hold there — `\B` says the two characters
        // around the position agree, and two word characters do — but it is at
        // neither end of the match, so there is no position the caller can be
        // asked about.
        //
        // `a\bb` is the same shape and is refused a step earlier, by [`prune`],
        // because a `\b` between two word characters holds nowhere and the
        // pattern can never match at all. The two refusals are different
        // diagnoses of different mistakes and the corpus contains both.
        let error = widen_body_error(r"a\Bb");
        assert_eq!(error.feature, Some("wide regex"));
        assert!(error.message.contains("middle"), "{}", error.message);
    }

    #[test]
    fn a_boundary_inside_a_repetition_is_refused() {
        // How many characters precede it depends on how many times the
        // repetition ran, so it is at neither end of the match.
        for body in [r"(?:\bfoo)+", r"\b?foo", r"(?:ab\b){2,3}"] {
            let error = widen_body_error(body);
            assert_eq!(error.feature, Some("wide regex"), "{body}");
            assert!(
                error.message.contains("repetition"),
                "{body}: {}",
                error.message
            );
        }
    }

    #[test]
    fn an_alternation_whose_branches_agree_about_the_boundary_is_accepted() {
        // Every branch asserts it, so the one check the match gets is one each
        // of them makes.
        let widened = widen_body(r"(?:\beval|\bassert)");
        assert_eq!(widened.boundary.leading, Some(Assertion::Boundary));
        // Both branches are the same shape, so the text is the alternation of
        // the two words with nothing of the assertion left in it.
        assert!(matches(r"(?:\beval|\bassert)", &utf16("x assert(")));
        assert!(!matches(r"(?:\beval|\bassert)", &utf16("xassert(")));
    }

    #[test]
    fn an_alternation_whose_branches_disagree_is_refused() {
        // The check is made once for the match, so the `assert` branch would be
        // filtered by an assertion its author never wrote.
        for body in [r"(?:\beval|assert)", r"(?:\beval|\bassert\b)"] {
            let error = widen_body_error(body);
            assert_eq!(error.feature, Some("wide regex"), "{body}");
            assert!(
                error.message.contains("alternatives"),
                "{body}: {}",
                error.message
            );
        }
    }

    #[test]
    fn a_branch_whose_boundary_can_never_hold_is_dropped_rather_than_refusing_the_pattern() {
        // The corpus's own case, from `DITEKSHEN_INDICATOR_TOOL_Extpassword`:
        // `Web\browsers`, where the `\b` sits between two word characters and is
        // false at every position. That branch matches nothing, so a pattern
        // that is the same except for it matches exactly the same files — and
        // the eight branches beside it are the ones the rule was written for.
        let body = r"Scanning\s(Credentials\sfolder|Chromium-based\Web\browsers|Windows\sVault)";
        let widened = widen_body(body);
        assert!(
            !widened.pattern.contains("Chromium"),
            "the dead branch is still in the pattern: {}",
            widened.pattern
        );
        assert!(widened.boundary.is_none(), "nothing was asserted at an end");
        assert!(matches(body, &utf16("Scanning Credentials folder")));
        assert!(matches(body, &utf16("Scanning Windows Vault")));
        // And what the branch would have matched with the assertion ignored —
        // `\W` standing in for the author's typo'd `\s` — is not matched, since
        // the branch is gone rather than loosened.
        assert!(!matches(body, &utf16("Scanning Chromium-basedXebrowsers")));
    }

    #[test]
    fn a_pattern_that_asserts_an_impossible_boundary_everywhere_is_refused() {
        // Every path through it is dead, so there is nothing left to compile.
        // Refused by name, the way `\b\B` is, rather than compiled to a pattern
        // that can never fire.
        for body in [r"ab\bcd", r"a\bb", r"(?:ab\bcd|ef\bgh)", r"ab\B-cd"] {
            let error = widen_body_error(body);
            assert_eq!(error.feature, Some("wide regex"), "{body}");
            assert!(
                error.message.contains("can never match"),
                "{body}: {}",
                error.message
            );
        }
    }

    #[test]
    fn a_boundary_the_analysis_cannot_place_is_left_where_its_author_put_it() {
        // `\b` between a word character and a class is not known to be
        // impossible — the class may hold a non-word byte — so the branch
        // survives the pruning and is refused by the middle-of-a-match rule
        // instead. Pruning only what is provably dead is what keeps the two
        // apart: a looser analysis would silently drop a live branch here.
        let error = widen_body_error(r"ab\b.cd");
        assert_eq!(error.feature, Some("wide regex"));
        assert!(
            error.message.contains("middle of a match"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_boundary_at_the_end_of_a_sequence_is_not_an_impossible_one() {
        // `\bfoo\b` is the shape 206 of the corpus's 220 boundary patterns
        // write, and both of its assertions are about the ends of the match.
        // A pruning rule that looked at "the element before" and "the element
        // after" without noticing that one of them is missing would call this
        // dead — the leading `\b` has nothing before it inside the pattern.
        let widened = widen_body(r"\beval\b");
        assert_eq!(widened.boundary.leading, Some(Assertion::Boundary));
        assert_eq!(widened.boundary.trailing, Some(Assertion::Boundary));
        assert!(matches(r"\beval\b", &utf16("x eval y")));
        assert!(!matches(r"\beval\b", &utf16("xeval y")));
    }

    #[test]
    fn two_boundaries_at_one_end_have_to_be_the_same_assertion() {
        // `\b\b` is one assertion written twice and is fine; `\b\B` asks for a
        // position to be both a boundary and not one, which no position is.
        assert_eq!(
            widen_body(r"\b\beval").boundary.leading,
            Some(Assertion::Boundary)
        );
        let error = widen_body_error(r"\b\Beval");
        assert_eq!(error.feature, Some("wide regex"));
        assert!(
            error.message.contains("can never match"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_half_boundary_is_refused_by_name() {
        let error = widen_body_error(r"\b{start}eval");
        assert_eq!(error.feature, Some("wide regex"));
        assert!(error.message.contains("half-boundary"), "{}", error.message);
    }

    /// The error widening a pattern that must not widen produces.
    fn widen_body_error(body: &str) -> MatcherError {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(body)
            .unwrap_or_else(|e| panic!("{body} must parse: {e}"));
        widen(&hir).expect_err("the pattern must be refused")
    }

    #[test]
    fn a_class_that_matches_nothing_is_written_as_the_negation_of_everything() {
        // `[]` is a syntax error, so the empty class needs a spelling. It comes
        // up when a pattern negates the whole byte range.
        let text = widened(r"[^\x00-\xff]");
        assert_eq!(text, "[^\\x00-\\xff]\\x00");
        assert!(
            regex::bytes::RegexBuilder::new(&text)
                .unicode(false)
                .build()
                .is_ok(),
            "the empty class must still be a pattern the compiler takes"
        );
    }

    #[test]
    fn a_byte_that_would_end_the_class_is_written_as_an_escape() {
        // A class holding `]` or `-` written literally would change what the
        // pattern means, so every range is written as an escape.
        let text = widened("[]-]");
        assert!(!text.contains("[]"), "{text}");
        assert!(matches("[]-]", &utf16("]")));
    }

    #[test]
    fn a_pattern_that_is_only_an_empty_alternation_widens_to_something_compilable() {
        assert_eq!(widened(""), "");
        assert!(hash_compiles(&widened("")));
    }

    fn hash_compiles(body: &str) -> bool {
        regex::bytes::Regex::new(body).is_ok()
    }
}
