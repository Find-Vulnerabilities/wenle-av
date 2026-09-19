//! Reading third-party rule set files.
//!
//! A `.yar` file is a sequence of rule blocks with no outer structure. The
//! parser wants one rule at a time, both because a single syntax error
//! otherwise aborts the whole file — which tells you nothing about a
//! 337,000-line rule set — and because the importer needs to handle each rule
//! independently so that one it cannot translate costs one rule rather than
//! all ten thousand.
//!
//! # Why the split is line-based
//!
//! Counting brace depth would need to know about regex literals, because
//! `/ab{2}/` contains a brace that is not a block delimiter. In practice every
//! rule set writes one rule per block with the closing brace alone on a line,
//! so splitting on `rule`-header lines and `^}` lines is both simpler and more
//! reliable — provided the splitter also knows when it is inside a hex string,
//! which is what [`split_rule_chunks`] is mostly about.
//!
//! The splitter verifies its own work rather than trusting the heuristic: a
//! chunk that does not begin with `rule`, end with `}`, and contain a
//! `condition:` section is counted as malformed instead of being handed to the
//! parser, so a truncation shows up as a number rather than as a rule that
//! quietly lost its condition.

/// One rule's source text and the line it started on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    /// 1-based line number of the `rule` header.
    pub line: usize,
    pub text: &'a str,
}

/// What a split pass produced.
#[derive(Debug, Clone, Default)]
pub struct Split<'a> {
    pub chunks: Vec<Chunk<'a>>,
    /// `rule` header lines seen.
    ///
    /// The splitter's contract has a sharp edge: it needs the rule's closing
    /// brace alone on a line. A rule written on one line — `rule a { condition:
    /// true }` — yields no chunk *and* no malformed count, so without this
    /// number it would vanish silently. A caller compares `headers` against
    /// `chunks.len() + malformed` and treats any remainder as rules the
    /// splitter dropped, which is the difference between a heuristic that is
    /// documented and one that lies.
    pub headers: usize,
    /// Blocks that looked like a rule but were not a complete one.
    ///
    /// Non-zero means the heuristic failed on this file, and any count taken
    /// from `chunks` is an undercount.
    pub malformed: usize,
}

impl Split<'_> {
    /// Rules a `rule` header announced that no chunk accounts for.
    ///
    /// Should be zero. Anything else means the splitter dropped rules that the
    /// parser was never offered, which no other count in the pipeline would
    /// reveal.
    pub fn unaccounted(&self) -> usize {
        self.headers
            .saturating_sub(self.chunks.len())
            .saturating_sub(self.malformed)
    }
}

/// Split a rule set into individual rules.
///
/// A hex string closes with a brace alone on a line — `        }` — which is
/// character-for-character what a rule's closing brace looks like. Taking that
/// for the end of the rule truncates it: the remaining strings and the whole
/// `condition:` block vanish, and the fragment that survives parses as a rule
/// that is merely missing its condition. So the splitter tracks whether it is
/// inside a hex block, and only a brace outside one ends the rule.
pub fn split_rule_chunks(source: &str) -> Split<'_> {
    let mut out = Split::default();
    let mut start: Option<(usize, usize)> = None; // (line, byte offset)
    let mut in_hex = false;
    let mut hex_depth = 0i32;

    // `str::lines` yields subslices of `source`, so a line's distance from the
    // start of the source is just its pointer difference. That is how each
    // chunk gets a byte range without re-scanning for offsets.
    let base = source.as_ptr() as usize;

    for (index, line) in source.lines().enumerate() {
        let line_no = index.saturating_add(1);
        let line_offset = line.as_ptr() as usize - base;
        let trimmed = line.trim();

        if start.is_none() {
            if is_rule_header(line.trim_start()) {
                out.headers += 1;
                start = Some((line_no, line_offset));
            }
            continue;
        }

        if in_hex {
            // Brace depth, not "a brace alone on a line". A hex body whose
            // closing brace shares a line with its last bytes — `41 42 }` — is
            // perfectly ordinary, and waiting for a lone `}` would leave the
            // splitter inside the hex block for the rest of the file: every
            // following rule swallowed into one chunk, no chunk ever emitted,
            // and not one of them counted as malformed. Depth cannot get stuck
            // that way, because hex bodies contain no braces of their own.
            hex_depth += brace_delta(line);
            if hex_depth <= 0 {
                in_hex = false;
            }
            continue;
        }

        if let Some(depth) = hex_open_depth(line) {
            hex_depth = depth;
            in_hex = depth > 0;
            continue;
        }

        if trimmed != "}" {
            continue;
        }

        let Some((from_line, offset)) = start.take() else {
            // Unreachable: a missing `start` was handled above, and the only
            // other exit from this loop leaves it untouched.
            continue;
        };
        let text = &source[offset..line_offset + line.len()];
        if is_complete_rule(text) {
            out.chunks.push(Chunk {
                line: from_line,
                text,
            });
        } else {
            out.malformed += 1;
        }
    }

    // A rule still open at the end of input was truncated, not absent. Leaving
    // `start` set without counting it is the same silent drop the `headers`
    // count exists to prevent.
    if start.is_some() {
        out.malformed += 1;
    }
    out
}

/// Net brace count on a line, for tracking a hex block's extent.
fn brace_delta(line: &str) -> i32 {
    let open = i32::try_from(line.matches('{').count()).unwrap_or(i32::MAX);
    let close = i32::try_from(line.matches('}').count()).unwrap_or(i32::MAX);
    open - close
}

/// The brace depth a line leaves behind if it opens a hex block.
///
/// `$a = {` and `$a = { 4D 5A 90` both open one; `$a = { 4D 5A }` opens and
/// closes it on the same line, and returns a depth of zero.
///
/// Requiring the `{` to be the assigned *value* rather than merely present on a
/// line that mentions a `$` matters: `$a = "text {"` is a text string whose
/// literal contains a brace, and treating it as the start of a hex body hides
/// the rest of the rule from the splitter. The `=` is unambiguous because a
/// string definition's first `=` is its assignment.
fn hex_open_depth(line: &str) -> Option<i32> {
    let (lhs, rhs) = line.split_once('=')?;
    if !lhs.contains('$') {
        return None;
    }
    if !rhs.trim_start().starts_with('{') {
        return None;
    }
    Some(brace_delta(line))
}

/// True when the text is a whole rule rather than a fragment of one.
fn is_complete_rule(text: &str) -> bool {
    text.trim_start().contains("rule ")
        && text.trim_end().ends_with('}')
        && has_condition(text)
}

/// True when some line of the rule opens a `condition:` section.
fn has_condition(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim_start();
        t.strip_prefix("condition")
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    })
}

/// True for `rule name : tags` and its `private`/`global` prefixes.
pub fn is_rule_header(trimmed: &str) -> bool {
    let mut rest = trimmed;
    loop {
        if let Some(r) = rest.strip_prefix("private") {
            rest = r.trim_start();
        } else if let Some(r) = rest.strip_prefix("global") {
            rest = r.trim_start();
        } else {
            break;
        }
    }
    let Some(rest) = rest.strip_prefix("rule") else {
        return false;
    };
    // The name must follow, so `rulex` is not a header. Neither is
    // `ruleset_version = 3`, which a generator will happily emit.
    matches!(rest.chars().next(), Some(c) if c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rule a { condition: true }` with the brace on its own line, which is
    /// the form the splitter's contract requires.
    const ONE: &str = "rule a {\n condition: true\n}\n";
    const TWO: &str = "rule a {\n condition: true\n}\nrule b {\n condition: false\n}\n";

    #[test]
    fn splits_two_rules() {
        let split = split_rule_chunks(TWO);
        assert_eq!(split.chunks.len(), 2);
        assert_eq!(split.malformed, 0);
        assert_eq!(split.unaccounted(), 0);
        assert_eq!(split.chunks[0].line, 1);
        assert_eq!(split.chunks[1].line, 4);
    }

    #[test]
    fn a_one_line_rule_is_counted_as_malformed_rather_than_dropped() {
        // The splitter needs the closing brace on its own line, so this rule
        // yields no chunk. What must not happen is that it disappears without a
        // trace: the rule is still open when the input ends, which the
        // end-of-input check counts. `unaccounted()` is the backstop for any
        // path that check does not cover.
        let source = "rule a { condition: true }\n";
        let split = split_rule_chunks(source);
        assert!(split.chunks.is_empty());
        assert_eq!(split.headers, 1);
        assert_eq!(split.malformed, 1);
        assert_eq!(split.unaccounted(), 0);
    }

    #[test]
    fn a_one_line_rule_followed_by_a_normal_one_is_absorbed_into_its_chunk() {
        // `rule a { ... }` on one line leaves the splitter waiting, so the next
        // rule's body becomes the end of the same chunk. Both rules reach the
        // parser — `parse_file` returns every rule it finds — so nothing is
        // lost, but it is worth pinning down that the count still adds up.
        //
        // `headers` stays at one because it counts rule *starts*, and a header
        // reached while already inside a rule is not one. That is also why
        // `unaccounted()` is zero here rather than a false alarm: the second
        // rule is accounted for by the chunk that carries it.
        let source = "rule a { condition: true }\nrule b {\n condition: true\n}\n";
        let split = split_rule_chunks(source);
        assert_eq!(split.headers, 1);
        assert_eq!(split.chunks.len(), 1);
        assert_eq!(split.unaccounted(), 0);
        assert!(split.chunks[0].text.starts_with("rule a"), "{}", split.chunks[0].text);
        assert!(split.chunks[0].text.contains("rule b"), "{}", split.chunks[0].text);
    }

    #[test]
    fn a_hex_body_closing_brace_does_not_end_the_rule() {
        // The bug this exists for: the hex body's `}` is byte-identical to the
        // rule's, and taking it for the end truncates the rule so that the
        // condition disappears — turning a working rule into a dead one.
        let source = "\
rule a {
    strings:
        $h = { 4D 5A 90 00
               41 42 }
    condition:
        $h
}
";
        let split = split_rule_chunks(source);
        assert_eq!(split.chunks.len(), 1, "{split:?}");
        assert_eq!(split.malformed, 0);
        assert_eq!(split.unaccounted(), 0);
        assert!(split.chunks[0].text.contains("condition:"), "{}", split.chunks[0].text);
        assert!(split.chunks[0].text.contains("41 42"), "{}", split.chunks[0].text);
    }

    #[test]
    fn a_hex_body_started_on_its_own_line_is_tracked() {
        // `$a = {` with nothing after it is the common formatting.
        let source = "rule a {\n strings:\n  $h = {\n   4D 5A\n  }\n condition:\n  $h\n}\n";
        let split = split_rule_chunks(source);
        assert_eq!(split.chunks.len(), 1);
        assert!(split.chunks[0].text.contains("4D 5A"), "{}", split.chunks[0].text);
    }

    #[test]
    fn a_hex_body_wholly_on_one_line_does_not_open_a_block() {
        // `$h = { 4D 5A }` opens and closes on the same line. Treating it as
        // open would swallow every rule that follows.
        let source = "rule a {\n strings:\n  $h = { 4D 5A }\n condition:\n  $h\n}\nrule b {\n condition: true\n}\n";
        let split = split_rule_chunks(source);
        assert_eq!(split.chunks.len(), 2, "{split:?}");
        assert_eq!(split.unaccounted(), 0);
    }

    #[test]
    fn a_text_string_containing_a_brace_is_not_a_hex_block() {
        // `$a = "text {"` mentions a `$` and has an unbalanced brace. Read as
        // the start of a hex body it hides the rest of the rule.
        let source = "rule a {\n strings:\n  $a = \"text {\"\n condition:\n  $a\n}\nrule b {\n condition: true\n}\n";
        let split = split_rule_chunks(source);
        assert_eq!(split.chunks.len(), 2, "{split:?}");
        assert_eq!(split.unaccounted(), 0);
    }

    #[test]
    fn a_rule_without_a_condition_is_counted_as_malformed() {
        // This is what a truncated chunk looks like. Counting it is what turns
        // a splitter bug into a visible number.
        let source = "rule a {\n strings:\n  $x = \"y\"\n}\n";
        let split = split_rule_chunks(source);
        assert!(split.chunks.is_empty());
        assert_eq!(split.malformed, 1);
        assert_eq!(split.unaccounted(), 0);
    }

    #[test]
    fn a_rule_left_open_at_end_of_input_is_counted_as_malformed() {
        let source = "rule a {\n condition: true\n";
        let split = split_rule_chunks(source);
        assert!(split.chunks.is_empty());
        assert_eq!(split.malformed, 1);
        assert_eq!(split.unaccounted(), 0);
    }

    #[test]
    fn the_chunks_are_subslices_of_the_source() {
        // They have to be: the caller parses them without copying, and a chunk
        // that were its own allocation would make the tool's memory use
        // proportional to the rule set twice over.
        let split = split_rule_chunks(ONE);
        assert_eq!(split.chunks[0].text.len(), ONE.trim_end().len());
    }

    #[test]
    fn private_and_global_rules_start_a_chunk() {
        for header in ["rule r", "private rule r", "global rule r", "private global rule r"] {
            let source = format!("{header} {{\n condition: true\n}}\n");
            let split = split_rule_chunks(&source);
            assert_eq!(split.chunks.len(), 1, "{header}: {split:?}");
        }
    }

    #[test]
    fn a_line_that_merely_starts_with_rule_is_not_a_header() {
        for line in ["rulex {", "ruleset_version = 3", "rulebook"] {
            assert!(!is_rule_header(line), "{line}");
        }
    }

    #[test]
    fn text_before_the_first_rule_is_ignored() {
        let source = "// a comment\nimport \"pe\"\n\nrule a {\n condition: true\n}\n";
        let split = split_rule_chunks(source);
        assert_eq!(split.chunks.len(), 1);
        assert_eq!(split.headers, 1, "the comment is not a header");
        assert_eq!(split.chunks[0].line, 4);
        assert!(split.chunks[0].text.starts_with("rule a"));
    }

    #[test]
    fn an_empty_source_produces_nothing() {
        let split = split_rule_chunks("");
        assert!(split.chunks.is_empty());
        assert_eq!(split.malformed, 0);
        assert_eq!(split.headers, 0);
    }
}
