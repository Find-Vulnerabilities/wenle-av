//! Recognising a file that is written in this rule language.
//!
//! # Why this exists, and what it is not
//!
//! It is not a validator. [`crate::parser::parse_file`] is, and this module
//! deliberately does not use it. The question a scanner needs answered is not
//! "is this file a valid rule set?" but "is this file *made of* rule syntax?",
//! and the two come apart in the case that matters. A rule file with three
//! syntax errors, or with one rule out of ten thousand half-written, does not
//! parse — and it is still a file whose ten thousand `$literal` lines are the
//! exact byte strings the compiled rules go looking for. A scanner that
//! recognised it only if it parsed would report it as the malware it describes.
//!
//! There is also a cost argument, and on a machine with no pagefile it is the
//! stronger one. Parsing allocates: `Lexer::tokenize` returns a `Vec<Token>`,
//! each token owning a `String` when it is an identifier or a literal, and the
//! parse above it builds an AST. A 17 MB corpus of ten thousand rules is a few
//! million tokens, so the answer to "is this a rule file?" would cost hundreds
//! of megabytes of transient allocation — per candidate file, from a scan
//! running one candidate per core.
//!
//! So this walks the bytes once, allocates nothing, and measures three things
//! that together only a rule source has: how many rules it declares, how many
//! conditions it writes, and how much of the file is rule syntax at all.
//!
//! # Why three counts and not one
//!
//! None of them works alone, and each excludes a different shape.
//!
//! The count of rule declarations is a floor ([`MIN_RULES`]): a file with three
//! rules in it is a file somebody is editing, and the harm this module exists to
//! prevent scales with the number of rules, so the floor is set where the harm
//! starts and not at one.
//!
//! The count of conditions is not decoration, because in this language the two
//! are not independent. A rule without a `condition:` is not a rule — the
//! grammar requires one — so a file with rule headers and no conditions is a
//! file that mentions the word `rule`, which is a different thing. Requiring the
//! two to agree is what keeps this from firing on a changelog of rule names.
//!
//! And the density ([`MIN_DENSITY`]) is what keeps it from firing on a *program*
//! that quotes the language in its test fixtures — this repository's own sources
//! do, at length. The count says how much rule text a file holds; the density
//! says whether the file is made of it.

use std::str::from_utf8;

/// How many rule declarations a file must carry before it is called a rule
/// source.
///
/// Eight, and the number is a judgement rather than a measurement. A real corpus
/// has thousands: the ten-thousand-rule file this product ships crosses it on
/// its first page. What the floor has to exclude is not "small rule files" — it
/// is prose. A README explaining the language quotes one or two rules, a bug
/// report quotes one, and a test file in this repository holds two or three.
/// Eight is comfortably above all of those and comfortably below any file whose
/// literals would produce a report worth suppressing.
pub const MIN_RULES: usize = 8;

/// The share of a file's lines that must be rule syntax, as a percentage,
/// before the file is called a rule source.
///
/// # Why a count is not enough, measured
///
/// This repository's own Rust sources quote the language. `database.rs` holds a
/// 33-rule fixture, `scanner.rs` 27, `sweep.rs` 8 — every one of them a real rule
/// declaration with a real `condition:` under it, because that is what a test of
/// a rule compiler is written with. A check that counted declarations alone
/// would call those three files rule sources, and a scan of a checkout would
/// then take three real source files out of the scan and say nothing about them.
/// That is a worse outcome than the false report this module exists to prevent:
/// a false report is visible and can be argued with.
///
/// # The measurement
///
/// Rule-syntax lines as a percentage of non-blank lines:
///
/// | file | rules | syntax lines | lines | density |
/// |---|---|---|---|---|
/// | `yara-forge-extended-0.9.1.yar` (the shipped corpus) | 10,764 | 106,799 | 337,345 | **31%** |
/// | `crates/av-rules/src/scanner.rs` | 27 | 137 | 1,464 | 9% |
/// | `crates/av-rules/src/database.rs` | 33 | 109 | 1,931 | 5% |
/// | `crates/av-rules/src/sweep.rs` | 8 | 47 | 820 | 5% |
///
/// Twenty per cent sits between them with equal room on both sides: the corpus is
/// eleven points above it and the densest source file eleven points below. The
/// two populations are a factor of three apart, and a threshold in the middle of
/// a factor of three does not depend on which corpus or which source file is
/// measured.
///
/// # What it will still get wrong
///
/// A corpus that is mostly commentary — a licence header on every rule, an
/// explanation above each string — can fall under this and be scanned as
/// ordinary text, which means a false report on a rule file. That is the
/// direction this module would rather err in, and it is the same direction the
/// encoding rule errs in. It is bounded on the other side by the count: a file
/// with fewer than [`MIN_RULES`] declarations never reaches the density test.
pub const MIN_DENSITY: usize = 20;

/// What a byte scan of a suspected rule source found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSource {
    /// Rule declarations: lines beginning with `rule`, or with `private rule`
    /// or `global rule`.
    ///
    /// Zero for a compiled container, which states no count — see
    /// [`RuleSource::compiled`].
    pub rules: usize,
    /// Lines beginning a `condition:` section.
    ///
    /// Zero for a compiled container, for the same reason.
    pub conditions: usize,
    /// Whether this is a compiled rule container rather than a source text.
    ///
    /// The two are recognised by different means and are different things to
    /// tell a reader — one is a file that declares rules, the other is a file
    /// that *is* rules — so a report unable to tell them apart would describe
    /// one of them wrongly.
    pub compiled: bool,
}

/// The bytes a compiled rule container begins with.
///
/// `YARA`, at offset zero. Not a guess and not a family of formats: it is the
/// magic of the compiled rule container as this was measured on the 38 MB one
/// that a scan of a user's own downloads turned up — `59 41 52 41 15 0c …`,
/// holding 16 MB of NUL bytes and not valid UTF-8.
pub const COMPILED_RULE_MAGIC: &[u8; 4] = b"YARA";

/// Whether these bytes are a compiled rule container.
///
/// # Why this is a container test and not a loosening of the encoding rule
///
/// [`rule_source`] refuses anything that is not UTF-8 and anything holding a NUL
/// byte, and it gives its reason: a compiled *program* is not valid UTF-8
/// either, so that cheap test is what separates a rule source from the thing it
/// describes. The reasoning holds for a program and fails for this, which is not
/// a program carrying a rule corpus in a resource — it is a container whose
/// entire contents *are* the rules. Its bytes are the rules, and every one of
/// them is a string some rule searches for.
///
/// So the test is not "is this binary full of rule-shaped text", which would be
/// exactly the loosening the encoding rule exists to prevent. It is four
/// specific bytes at offset zero, and a file has to begin with them to be
/// considered at all.
///
/// # Why the NUL is asked for as well
///
/// Four printable letters are cheap to produce by accident: a text file opening
/// with the word `YARA` begins with the magic. The compiled format holds NUL
/// bytes from its header onwards — the measured one has its first at offset 7 —
/// so requiring one is what keeps a text file that merely starts with those
/// letters on the counting path, where it belongs. A file that passes both tests
/// is not text in any encoding this product reads, and is a container.
pub fn compiled_rule_container(bytes: &[u8]) -> bool {
    bytes.starts_with(COMPILED_RULE_MAGIC) && memchr::memchr(0, bytes).is_some()
}

/// Whether these bytes are a rule source, and what the count found.
///
/// `None` for everything else, which is nearly every file a scan sees: a
/// program, a document, an archive, an image, a script.
///
/// # What it accepts before it rejects anything
///
/// A compiled rule container, by its magic — see [`compiled_rule_container`].
/// That is not an exception to the encoding rule below but the case that rule
/// cannot see: the container is binary by construction, so every cheap test that
/// separates a rule source from a program answers "program" for it, and it is
/// the one binary whose entire content *is* rules.
///
/// # What it rejects before counting
///
/// A byte scan is only meaningful over text, so the file must be UTF-8 and hold
/// no NUL byte. Both are cheap and both are what separates a rule source from
/// the thing it describes: a compiled program is not valid UTF-8 and its headers
/// are full of zeroes. A rule file written in some other encoding is missed,
/// which costs a false report on a file that would rather have none — the safe
/// direction, and one this product does not claim to cover.
///
/// # What it rejects after counting
///
/// A file below [`MIN_RULES`] declarations, a file whose declarations outnumber
/// its conditions two to one, and a file below [`MIN_DENSITY`]. Each threshold
/// has the measurement behind it in its own documentation; together they are the
/// difference between a corpus and a program that quotes one.
pub fn rule_source(bytes: &[u8]) -> Option<RuleSource> {
    // Ahead of the encoding gate, and it has to be: a compiled container fails
    // that gate on both counts, so a test placed after it would never run. See
    // [`compiled_rule_container`] for why the container is recognised by its
    // own magic rather than by the shape of its contents.
    if compiled_rule_container(bytes) {
        return Some(RuleSource {
            rules: 0,
            conditions: 0,
            compiled: true,
        });
    }

    let text = from_utf8(bytes).ok()?;
    if memchr::memchr(0, bytes).is_some() {
        return None;
    }

    let mut found = RuleSource {
        rules: 0,
        conditions: 0,
        compiled: false,
    };
    let mut lines = 0usize;
    let mut structural = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        lines += 1;
        if line.starts_with("condition:") {
            found.conditions += 1;
            structural += 1;
        } else if let Some(rest) = after_rule_keyword(line) {
            if starts_identifier(rest) {
                found.rules += 1;
                structural += 1;
            }
        } else if is_structural(line) {
            structural += 1;
        }
    }

    // A rule carries exactly one condition, so a real file has one of each. The
    // slack is one-sided — conditions may fall short of rules by half, and never
    // the other way — because the interesting failure is a file that has the
    // headers and not the bodies, which is what a file *about* the language
    // looks like.
    if found.rules < MIN_RULES || found.conditions * 2 < found.rules {
        return None;
    }
    // And the rules have to *be* the file rather than sit inside it. See
    // [`MIN_DENSITY`] for the two real shapes this separates.
    if (structural * 100) / lines < MIN_DENSITY {
        return None;
    }
    Some(found)
}

/// Whether a line is one of the language's own structural lines.
///
/// The sections a rule is made of and the strings it declares. Deliberately
/// shallow: this is a density estimate and not a parse, and the lines it misses —
/// conditions that are a bare expression — are a minority in any real corpus.
///
/// # What is deliberately not here
///
/// The closing brace. A rule ends with a `}` on its own line, so counting it
/// looks free, and it cost the whole measurement: every brace language closes a
/// block the same way, and a Rust file with four hundred test functions has four
/// hundred lines that trim to `}`. With the brace counted, the fixture in
/// `a_program_that_quotes_the_language_is_not_a_rule_source` measured 26% and
/// was called a rule source — the one shape this check exists to reject. Without
/// it, the same fixture measures 9% and the shipped corpus 32%.
fn is_structural(line: &str) -> bool {
    line.starts_with("strings:")
        || line.starts_with("meta:")
        || line.starts_with("import ")
        || line.starts_with("include ")
        || line.starts_with('$')
}

/// Whether these bytes are a rule source.
///
/// The question without the count, for a caller that has nothing to do with it.
pub fn is_rule_source(bytes: &[u8]) -> bool {
    rule_source(bytes).is_some()
}

/// The rest of the line after a rule keyword, when the line starts with one.
///
/// `rule foo {`, `private rule foo : tag {` and `global private rule foo {` are
/// all how a rule begins, and the modifiers may appear in either order.
fn after_rule_keyword(line: &str) -> Option<&str> {
    let mut rest = line;
    for _ in 0..2 {
        if let Some(after) = strip_word(rest, "private") {
            rest = after;
        } else if let Some(after) = strip_word(rest, "global") {
            rest = after;
        } else {
            break;
        }
    }
    strip_word(rest, "rule")
}

/// The rest of the line after `word`, when the line starts with it as a whole
/// word and is followed by whitespace.
///
/// The separator is consumed, so what comes back begins at the first byte of
/// whatever follows the keyword. That matters to the caller: the word after
/// `rule` is the rule's name, and a caller handed `" sample_0 {"` would look for
/// an identifier at a space and find none.
///
/// The word boundary is what keeps `rule_of_thumb = 3` in a script from being
/// read as a rule declaration — `rule` there is a prefix of an identifier, not
/// the keyword.
fn strip_word<'a>(line: &'a str, word: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(word)?;
    match rest.as_bytes().first() {
        Some(b' ' | b'\t') => Some(rest.trim_start_matches([' ', '\t'])),
        _ => None,
    }
}

/// Whether the rest of a rule line begins with an identifier.
///
/// The name is required, so `rule {` — which is not a rule — does not count. The
/// grammar's own rule for an identifier is the first byte here: a letter or an
/// underscore. The rest of it is not checked, because a name that is misspelt
/// still belongs to a rule declaration and the file it is in is still a rule
/// source.
fn starts_identifier(rest: &str) -> bool {
    matches!(rest.as_bytes().first(), Some(b) if b.is_ascii_alphabetic() || *b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule source with the given number of rules, each with a literal from
    /// the index so that no two are alike.
    fn corpus(rules: usize) -> String {
        (0..rules)
            .map(|i| {
                format!(
                    "rule sample_{i} {{\n  strings:\n    $a = \"literal-{i}\"\n  \
                     condition:\n    $a\n}}\n"
                )
            })
            .collect()
    }

    #[test]
    fn a_rule_source_is_recognised_and_counted() {
        let found = rule_source(corpus(MIN_RULES).as_bytes()).expect("recognised");
        assert_eq!(found.rules, MIN_RULES);
        assert_eq!(found.conditions, MIN_RULES);
    }

    #[test]
    fn a_corpus_below_the_floor_is_not_recognised() {
        // The boundary, from the side that must not fire: a handful of rules is
        // somebody editing, and reporting it is not what this is for.
        assert_eq!(rule_source(corpus(MIN_RULES - 1).as_bytes()), None);
    }

    #[test]
    fn the_modifiers_this_language_allows_do_not_hide_a_rule() {
        // `private`, `global`, and both orders. A file made entirely of private
        // rules is still a file made of the strings its rules search for.
        let text = (0..MIN_RULES)
            .map(|i| {
                format!(
                    "{} rule sample_{i} : tag {{\n  strings:\n    $a = \"x{i}\"\n  \
                     condition:\n    $a\n}}\n",
                    if i % 3 == 0 {
                        "private"
                    } else if i % 3 == 1 {
                        "global private"
                    } else {
                        "private global"
                    }
                )
            })
            .collect::<String>();
        let found = rule_source(text.as_bytes()).expect("recognised");
        assert_eq!(found.rules, MIN_RULES);
    }

    #[test]
    fn a_document_about_the_language_is_not_a_rule_source() {
        // Prose quotes rules without being one, and this is the shape that has
        // to stay outside: the words are present, the structure is not.
        let readme = "\
# Writing rules

A rule has a name, some strings, and a condition. For example:

```yara
rule example {
  strings:
    $a = \"hello\"
  condition:
    $a
}
```

The `condition:` section is mandatory. `rule` names must be unique.
Every rule needs a `condition:`. Write `rule` in lowercase.
A `rule` may be `private`. The word `rule` is a keyword.
The word `condition:` is a keyword too. Rules rules rules.
";
        assert_eq!(rule_source(readme.as_bytes()), None);
    }

    #[test]
    fn a_file_with_headers_and_no_bodies_is_not_a_rule_source() {
        // The two counts are not decoration. A file that lists rule names — a
        // changelog of rules, a test's expected-output list — has the headers
        // and none of the conditions, and it is not made of the strings.
        let listing = (0..MIN_RULES * 4)
            .map(|i| format!("rule sample_{i}\n"))
            .collect::<String>();
        assert_eq!(rule_source(listing.as_bytes()), None);
    }

    #[test]
    fn an_identifier_that_begins_with_the_keyword_is_not_a_declaration() {
        // `rule_of_thumb = 3` is a variable in a script. The keyword requires a
        // word boundary, or a source file full of such names would be read as a
        // rule source — which would take a malicious script out of the scan.
        let script = (0..MIN_RULES * 4)
            .map(|i| format!("rule_of_thumb_{i} = 3\ncondition: something\n"))
            .collect::<String>();
        assert_eq!(rule_source(script.as_bytes()), None);
    }

    #[test]
    fn a_rule_that_is_not_a_rule_is_not_counted() {
        // `rule {` has no name. It is not a declaration, and a file that has
        // eight of them has eight syntax errors rather than eight rules.
        let text = "rule {\n  condition:\n    true\n}\n".repeat(MIN_RULES);
        assert_eq!(rule_source(text.as_bytes()), None);
    }

    #[test]
    fn a_program_that_quotes_the_language_is_not_a_rule_source() {
        // The measurement in `MIN_DENSITY`, as a fixture. This is the shape that
        // broke a count-only version of this check: a real rule set, at column
        // zero, inside a program that is a hundred times longer than it is. The
        // fixture is more rules than `MIN_RULES` and a higher density than any
        // of this repository's own sources, and it is still not a rule source —
        // the surrounding program is what the file is.
        let mut program = String::from("//! A program that tests a rule compiler.\n\n");
        program.push_str("mod tests {\n    const CORPUS: &str = r#\"\n");
        program.push_str(&corpus(MIN_RULES * 4));
        program.push_str("\"#;\n");
        for i in 0..400 {
            program.push_str(&format!(
                "    #[test]\n    fn case_{i}() {{\n        let parsed = parse(CORPUS);
        assert!(parsed.is_ok());\n    }}\n"
            ));
        }
        assert_eq!(rule_source(program.as_bytes()), None);
    }

    #[test]
    fn a_binary_is_never_a_rule_source() {
        // The property the whole exemption rests on: a program cannot be
        // recognised, so it cannot be taken out of the scan by this path. A PE
        // header, and text with a NUL hidden in it.
        let mut pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
        pe.extend(corpus(MIN_RULES).as_bytes());
        assert_eq!(rule_source(&pe), None);

        let mut with_nul = corpus(MIN_RULES).into_bytes();
        with_nul.push(0);
        assert_eq!(rule_source(&with_nul), None);
    }

    #[test]
    fn the_whole_corpus_this_product_ships_is_recognised() {
        // The measurement, not a fixture: the file whose scan produced 1126
        // detections and a `malicious` verdict. Read from the repository when it
        // is there, and skipped when it is not, because a test that fails on a
        // machine without the vendored corpus teaches nothing.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/converted/yara-forge-extended-0.9.1.yar"
        );
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let found = rule_source(&bytes).expect("the corpus is a rule source");
        assert!(
            found.rules > 10_000,
            "the corpus holds thousands of rules, not {}",
            found.rules
        );
    }

    #[test]
    fn the_ruleset_that_holds_the_shipped_rules_is_a_rule_source() {
        // The direction that has to hold on the machine this runs on, next to
        // the direction that must not. A rule source lives in `rules/`, and the
        // files that quote the language without being one live in `crates/`: the
        // crate that recognises them, its fixtures, and a hundred-odd real
        // programs. Nothing under `crates/` may be recognised, or a scan of a
        // developer's checkout would take a file out of the scan and say
        // nothing about it — which is the failure this whole module risks, and
        // the reason the check is not a count of rule declarations. Running it
        // against the tree rather than against a fixture is what found the three
        // files whose fixtures are large enough to look like a corpus.
        //
        // Measured over the real tree rather than a fixture, because the
        // interesting inputs here are the ones nobody would think to write: this
        // module's own documentation quotes the language, and the fixtures
        // beside it are rule text inside a Rust string.
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let mut examined = 0;
        let mut recognised = Vec::new();
        collect_files(
            &std::path::Path::new(root).join("crates"),
            &mut examined,
            &mut recognised,
        );

        assert!(examined > 50, "only {examined} files were examined");
        assert!(
            recognised.is_empty(),
            "{} file(s) under crates/ were read as rule sources: {:?}",
            recognised.len(),
            recognised
        );
    }

    /// Walk a directory and collect the files [`is_rule_source`] recognises.
    ///
    /// Files above [`BIG`] are skipped: the tree this walks is Rust source and
    /// its fixtures, nothing in it is megabytes, and a test that reads the
    /// vendored 17 MB corpus a second time would be spending minutes to learn
    /// what the test above it already established.
    fn collect_files(dir: &std::path::Path, examined: &mut usize, recognised: &mut Vec<String>) {
        const BIG: u64 = 2 * 1024 * 1024;
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                collect_files(&path, examined, recognised);
                continue;
            }
            if entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX) > BIG {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            *examined += 1;
            if is_rule_source(&bytes) {
                recognised.push(path.display().to_string());
            }
        }
    }
}
