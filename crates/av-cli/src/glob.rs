//! The little pattern language `--exclude` takes.
//!
//! # Why not a glob crate
//!
//! Because the whole language is three metacharacters and the semantics that
//! matter here are the ones a *path* has, not the ones a shell has: a `*` that
//! crossed directory separators would make `--exclude "C:\Users\*\AppData"`
//! also exclude `C:\Users\me\Documents\AppData`, and a scanner that silently
//! skipped a file the user did not ask it to skip is the failure this whole
//! product is arranged against. Writing the twenty lines is cheaper than
//! auditing a dependency for a rule it was never designed to have.
//!
//! # The language
//!
//! | Pattern | Matches |
//! |---|---|
//! | `*` | any run of characters, except a path separator |
//! | `**` | any run of characters, separators included |
//! | `?` | exactly one character, not a separator |
//! | anything else | itself |
//!
//! Matching is case-insensitive and separator-agnostic: the pattern is compared
//! on `/`-separated text whatever the platform uses, so a rule written on one
//! machine means the same thing on another. Both a whole path and a bare file
//! name are tried, because `--exclude "*.tmp"` is what a user writes meaning
//! "anywhere" and `--exclude "C:\Windows\**"` is what they write meaning
//! "here".

/// Whether `pattern` matches `text`.
pub fn matches(pattern: &str, text: &str) -> bool {
    let pattern = normalize(pattern);
    let text = normalize(text);
    glob(pattern.as_bytes(), text.as_bytes())
}

/// Whether `pattern` matches either the whole path or just its file name.
pub fn matches_path(pattern: &str, path: &std::path::Path) -> bool {
    let normalized = path.to_string_lossy();
    if matches(pattern, &normalized) {
        return true;
    }
    path.file_name()
        .is_some_and(|name| matches(pattern, &name.to_string_lossy()))
}

/// Lowercase and use `/` throughout.
fn normalize(text: &str) -> String {
    text.replace('\\', "/").to_ascii_lowercase()
}

/// The matcher itself, over bytes.
///
/// Recursive rather than iterative-with-backtracking, because the patterns are
/// short, there is no memoisation to get wrong, and the version of this
/// function that a reader can check by eye is the one that ships.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let Some((&head, rest)) = pattern.split_first() else {
        // An exhausted pattern matches an exhausted text. Anything left over is
        // text the pattern did not account for, which is not a match.
        return text.is_empty();
    };
    match head {
        b'*' => {
            let (double, rest) = match rest.split_first() {
                Some((&b'*', rest)) => (true, rest),
                _ => (false, rest),
            };
            // A single star stops at the next separator; a double star does
            // not. Everything up to that point is a prefix it may swallow.
            let limit = if double {
                text.len()
            } else {
                text.iter().position(|&c| c == b'/').unwrap_or(text.len())
            };
            (0..=limit).any(|swallowed| glob(rest, &text[swallowed..]))
        }
        b'?' => match text.split_first() {
            Some((&c, tail)) => c != b'/' && glob(rest, tail),
            None => false,
        },
        _ => match text.split_first() {
            Some((&c, tail)) => c == head && glob(rest, tail),
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn path(text: &str) -> &Path {
        Path::new(text)
    }

    #[test]
    fn a_pattern_with_no_metacharacter_is_an_equality_test() {
        assert!(matches("C:/Windows", "C:/Windows"));
        assert!(!matches("C:/Windows", "C:/Windows/System32"));
    }

    #[test]
    fn a_single_star_does_not_cross_a_separator() {
        assert!(matches("*.tmp", "note.tmp"));
        assert!(matches("C:/Users/*/note.tmp", "C:/Users/me/note.tmp"));
        // The whole point of the distinction: a `*` that crossed separators
        // would make this pattern exclude something it does not name.
        assert!(!matches(
            "C:/Users/*/note.tmp",
            "C:/Users/me/Documents/note.tmp"
        ));
    }

    #[test]
    fn a_double_star_crosses_one() {
        assert!(matches(
            "C:/Users/**/note.tmp",
            "C:/Users/me/Documents/note.tmp"
        ));
        assert!(matches(
            "C:/Windows/**",
            "C:/Windows/System32/drivers/etc/hosts"
        ));
        // Including the empty run, so the pattern names the directory itself.
        assert!(matches("C:/Windows/**", "C:/Windows/x"));
    }

    #[test]
    fn a_question_mark_is_exactly_one_character() {
        assert!(matches("a?c", "abc"));
        assert!(!matches("a?c", "ac"));
        assert!(!matches("a?c", "abbc"));
        assert!(!matches("a?c", "a/c"), "and not a separator");
    }

    #[test]
    fn matching_ignores_case_and_the_kind_of_separator() {
        // A rule written on one machine has to mean the same on another, and
        // the separators a user types are the ones their shell shows them.
        assert!(matches("c:/WINDOWS/**", "C:\\Windows\\System32"));
        assert!(matches("C:\\Windows\\**", "c:/windows/system32"));
    }

    #[test]
    fn a_bare_name_matches_a_file_anywhere() {
        // `--exclude "*.tmp"` is what a user writes meaning "anywhere", so the
        // file name is tried as well as the whole path.
        assert!(matches_path("*.tmp", path("C:/deep/tree/note.tmp")));
        assert!(matches_path(
            "C:/Windows/**",
            path("C:/Windows/System32/kernel32.dll")
        ));
        assert!(!matches_path("*.tmp", path("C:/deep/tree/note.txt")));
    }

    #[test]
    fn an_empty_pattern_matches_only_an_empty_path() {
        assert!(matches("", ""));
        assert!(!matches("", "a"));
    }

    #[test]
    fn a_pattern_of_only_stars_matches_everything() {
        assert!(matches("*", "anything"));
        assert!(matches("**", "any/thing/at/all"));
        // And still only the whole string, because the match is anchored at
        // both ends — a pattern that matched a prefix would exclude more than
        // it names.
        assert!(!matches("a*", "ba"));
    }

    #[test]
    fn a_trailing_star_reaches_the_end_of_the_text() {
        assert!(matches("kernel*", "kernel32.dll"));
        assert!(matches("**/node_modules/**", "C:/app/node_modules/x/y.js"));
    }
}
