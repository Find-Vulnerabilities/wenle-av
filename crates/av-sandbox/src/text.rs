//! Case-insensitive byte search, because half the rules here are string rules.
//!
//! # Why not `str::to_ascii_lowercase`
//!
//! The haystack is a whole file — on this machine's System32 alone, files up to
//! `MRT.exe` at 133 MB — and a sandbox rule asks a handful of separate questions
//! of it. Lower-casing the buffer once per question would copy the file once per
//! question, so a sample that is 133 MB costs 133 MB of allocation per string
//! rule and a pass over those bytes that the comparison then makes a second
//! time. This module folds case as it compares instead: no allocation, one pass,
//! and the caller's buffer is read only.
//!
//! # Why `memchr`
//!
//! The candidate positions are found with [`memchr::memchr2`] over the two
//! spellings of the needle's first byte. That is the only reason this crate
//! depends on `memchr`, and it is load-bearing rather than cosmetic: in the dev
//! and test profiles the workspace compiles this crate's own code without
//! optimisation while compiling its dependencies with it
//! (`[profile.dev.package."*"] opt-level = 2`), so a hand-written search loop in
//! *this* crate is roughly an order of magnitude slower than the vectorised
//! routine in a dependency. The measurement that forced the choice: a naive
//! `iter().position()` scan of ~26 string conditions across the 4,000 PE files
//! in `C:\Windows\System32` (12 GB) did not finish in fifteen minutes, while the
//! same conditions over the same files through `memchr` finished in 180 s.
//!
//! # Why every search has two spellings
//!
//! A Windows program that names something the *user* or the *system* will read —
//! a registry path, a service name, a command line, the title of a window —
//! usually holds it as UTF-16LE, because that is what the wide entry points
//! take. A program that names something the *loader* will resolve — an imported
//! symbol, a DLL it calls `LoadLibrary` on — holds it as single-byte text. Both
//! spellings turn up, sometimes in the same file, and a search for one that does
//! not look for the other has a false-negative rate nobody can see: the rule
//! simply never fires, the report says nothing, and nothing looks wrong. So
//! every string question here is asked twice, once for each encoding, and the
//! rule that asks cannot tell the difference except in the location it reports.
//!
//! # What "case-insensitive" means here
//!
//! ASCII only, deliberately. Every needle in this crate is a Windows API name,
//! a service name or a path fragment, all of which are ASCII, and the bytes
//! being searched are a PE file where the same is true of anything worth
//! finding. Non-ASCII bytes are compared exactly — no Unicode case folding, no
//! locale, no normalisation. A rule that needed those would be a rule matching
//! on text a human wrote, and this crate has none: it matches on structure and
//! on the names the loader itself resolves.

/// Which of the two spellings of a string a match was found in.
///
/// Carried out of the search because it changes the length of the match: the
/// same name is half as many bytes in one spelling as in the other, and a
/// location that reported the wrong length would point a reader at the wrong
/// part of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// Single-byte ASCII, the spelling an import table uses.
    Narrow,
    /// UTF-16LE, the spelling a registry path or a command line uses.
    Wide,
}

/// Where a needle was found: how far in, and in which spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Found {
    /// Offset of the first byte of the match.
    pub(crate) offset: usize,
    /// The spelling it was found in.
    pub(crate) encoding: Encoding,
}

/// Whether `needle` occurs at all in either spelling.
pub(crate) fn contains_ignore_ascii_case(haystack: &[u8], needle: &str) -> bool {
    find_either(haystack, needle).is_some()
}

/// Where `needle` first occurs in either spelling, preferring the single-byte
/// one when both are present.
pub(crate) fn find_either(haystack: &[u8], needle: &str) -> Option<Found> {
    let narrow = needle.as_bytes();
    if let Some(offset) = find_narrow(haystack, narrow) {
        return Some(Found {
            offset,
            encoding: Encoding::Narrow,
        });
    }
    find_wide(haystack, narrow).map(|offset| Found {
        offset,
        encoding: Encoding::Wide,
    })
}

/// The first of `needles` to occur, and where.
///
/// The needle's order in the caller's table decides which one is reported when
/// several are present, and not the order they appear in the file: a rule table
/// is written with the strongest evidence first, so the finding names the
/// strongest thing the sample actually contains.
pub(crate) fn find_any_ignore_ascii_case<'n>(
    haystack: &[u8],
    needles: &[&'n str],
) -> Option<(&'n str, Found)> {
    needles
        .iter()
        .find_map(|needle| find_either(haystack, needle).map(|found| (*needle, found)))
}

/// How many of `needles` are present, in either spelling.
///
/// For the rules whose evidence is *several* independent names agreeing rather
/// than one — a sample that names two different security products is a
/// different thing from one that names a single product, because the second
/// name cannot be its own.
pub(crate) fn count_ignore_ascii_case(haystack: &[u8], needles: &[&str]) -> usize {
    needles
        .iter()
        .filter(|needle| contains_ignore_ascii_case(haystack, needle))
        .count()
}

/// The single-byte search.
fn find_narrow(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let (first_lower, first_upper) = case_pair(needle[0]);
    // The last offset at which a match can start. Non-empty, so no underflow.
    let last_start = haystack.len() - needle.len();
    let mut searched = 0usize;
    while searched <= last_start {
        let window = &haystack[searched..=last_start];
        let found = memchr::memchr2(first_lower, first_upper, window)?;
        let start = searched + found;
        if haystack[start..start + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(start);
        }
        // Overlapping matches are possible, so advance by one byte rather than
        // by the needle's length: `AAAB` contains `AAB` only if the search is
        // allowed to re-examine the second `A`.
        searched = start + 1;
    }
    None
}

/// The UTF-16LE search.
///
/// Every character of the needle becomes its own byte followed by a zero byte.
/// A needle longer than half the buffer cannot fit and is rejected without
/// arithmetic that could overflow.
fn find_wide(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let span = needle.len().checked_mul(2)?;
    if haystack.len() < span {
        return None;
    }
    let (first_lower, first_upper) = case_pair(needle[0]);
    let last_start = haystack.len() - span;
    let mut searched = 0usize;
    while searched <= last_start {
        let window = &haystack[searched..=last_start];
        let found = memchr::memchr2(first_lower, first_upper, window)?;
        let start = searched + found;
        if span > haystack.len() - start {
            return None;
        }
        if wide_equals_ignore_ascii_case(&haystack[start..start + span], needle) {
            return Some(start);
        }
        searched = start + 1;
    }
    None
}

/// Whether `wide` is `narrow` spelled as UTF-16LE with ASCII case folded.
fn wide_equals_ignore_ascii_case(wide: &[u8], narrow: &[u8]) -> bool {
    if wide.len() != narrow.len().saturating_mul(2) {
        return false;
    }
    for (index, &byte) in narrow.iter().enumerate() {
        // The high byte of an ASCII character is always zero, which is also
        // what stops two adjacent bytes of arbitrary data from being read as
        // one wide character.
        if wide[index * 2 + 1] != 0 || !wide[index * 2].eq_ignore_ascii_case(&byte) {
            return false;
        }
    }
    true
}

/// The byte's two case spellings, or the byte twice when it has only one.
///
/// Returns the lower-case spelling first so that a needle written in lower case
/// — which every needle in this crate is — probes with its own byte as the
/// primary `memchr` byte, which is the case `memchr2` is fastest at.
fn case_pair(byte: u8) -> (u8, u8) {
    if byte.is_ascii_alphabetic() {
        (byte.to_ascii_lowercase(), byte.to_ascii_uppercase())
    } else {
        (byte, byte)
    }
}

/// Spell an ASCII string as UTF-16LE, for tests and for building fixtures.
#[cfg(test)]
pub(crate) fn to_utf16le(text: &str) -> Vec<u8> {
    text.bytes().flat_map(|byte| [byte, 0]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The obvious implementation, used to check the fast one.
    ///
    /// This test is differential on purpose: an assertion that
    /// `contains_ignore_ascii_case(b"kernel32.dll", "KERNEL32")` is true passes
    /// against a stub that returns `true` unconditionally, so the property
    /// worth testing is that this function agrees with a straightforward
    /// lower-case-then-search implementation on every input, including the
    /// ones that must be `false`.
    fn naive(haystack: &[u8], needle: &str) -> bool {
        let needle = needle.as_bytes();
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        let lowered: Vec<u8> = haystack.iter().map(u8::to_ascii_lowercase).collect();
        let needle: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
        lowered
            .windows(needle.len())
            .any(|w| w == needle.as_slice())
    }

    #[test]
    fn agrees_with_the_naive_implementation() {
        let haystacks: &[&[u8]] = &[
            b"",
            b"a",
            b"MZ",
            b"kernel32.dll",
            b"KERNEL32.DLL",
            b"Kernel32.Dll",
            b"the quick brown fox jumps over the lazy dog",
            b"AAAAAB",
            b"aaab",
            b"\x00\x01\x02MZ\x90\x00",
            b"OpenSCManagerW\x00CreateServiceW\x00",
            b"windefend",
            b"WINDEFEND",
            b"WinDefend",
            b"..\\..\\windows\\system32\\lsass.exe",
        ];
        let needles: &[&str] = &[
            "",
            "a",
            "A",
            "MZ",
            "mz",
            "Mz",
            "kernel32",
            "KERNEL32",
            "Kernel32.Dll",
            "32.dll",
            "DLL",
            "aaaaab",
            "AAAB",
            "aaab",
            "defend",
            "WinDefend",
            "windefend",
            "lsass",
            "lsass.exe",
            "SYSTEM32",
            "quick brown",
            "q",
            "z",
            "zz",
        ];
        for haystack in haystacks {
            for needle in needles {
                assert_eq!(
                    contains_ignore_ascii_case(haystack, needle),
                    naive(haystack, needle),
                    "disagreement on haystack {haystack:?} needle {needle:?}"
                );
            }
        }
    }

    #[test]
    fn overlapping_candidates_are_not_skipped() {
        // The first-byte search finds the `A` at 0, the full comparison fails
        // against `AAB`, and the match is at offset 1 — so a search that
        // advanced by the needle's length instead of by one would miss it.
        assert!(contains_ignore_ascii_case(b"xAAAB", "AAB"));
        assert!(contains_ignore_ascii_case(b"AAAAAB", "AAAB"));
    }

    #[test]
    fn an_empty_needle_matches_nothing() {
        assert!(!contains_ignore_ascii_case(b"anything", ""));
        assert!(!contains_ignore_ascii_case(b"", ""));
    }

    #[test]
    fn a_needle_longer_than_the_haystack_matches_nothing() {
        assert!(!contains_ignore_ascii_case(b"ab", "abc"));
    }

    #[test]
    fn counting_needs_every_needle_present() {
        let hay = b"windefend msmpeng";
        assert_eq!(count_ignore_ascii_case(hay, &["windefend", "msmpeng"]), 2);
        assert_eq!(count_ignore_ascii_case(hay, &["windefend", "mssense"]), 1);
        assert_eq!(count_ignore_ascii_case(hay, &["mssense", "sgrmbroker"]), 0);
    }

    #[test]
    fn a_found_offset_points_at_the_match() {
        let hay = b"prefix-WINDEFEND-suffix";
        let found = find_either(hay, "windefend").expect("present");
        assert_eq!(found.encoding, Encoding::Narrow);
        assert_eq!(
            &hay[found.offset..found.offset + "windefend".len()],
            b"WINDEFEND"
        );
    }

    #[test]
    fn find_any_reports_the_first_needle_in_the_table_not_in_the_file() {
        // `msmpeng` appears later in the buffer than `windefend`, and is still
        // the one reported, because a rule table is ordered strongest-evidence
        // -first and the report should name the strongest thing present.
        let hay = b"windefend ... msmpeng";
        let (needle, found) =
            find_any_ignore_ascii_case(hay, &["msmpeng", "windefend"]).expect("one");
        assert_eq!(needle, "msmpeng");
        assert_eq!(found.offset, hay.len() - "msmpeng".len());

        // And with the table the other way round, the other one is reported.
        let (needle, found) =
            find_any_ignore_ascii_case(hay, &["windefend", "msmpeng"]).expect("one");
        assert_eq!(needle, "windefend");
        assert_eq!(found.offset, 0);
    }

    #[test]
    fn find_any_of_nothing_present_is_none() {
        assert!(find_any_ignore_ascii_case(b"nothing here", &["a", "b"]).is_none());
        assert!(find_any_ignore_ascii_case(b"nothing here", &[]).is_none());
    }

    #[test]
    fn a_wide_string_is_found_where_a_narrow_search_would_miss_it() {
        // The point of the second spelling: this buffer contains no `run` as
        // single-byte text at all, and a rule that named a registry path would
        // never fire on it.
        let wide = to_utf16le("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        let found = find_either(&wide, "currentversion\\run").expect("found as UTF-16");
        assert_eq!(found.encoding, Encoding::Wide);
        assert_eq!(
            &wide[found.offset..found.offset + "currentversion\\run".len() * 2],
            to_utf16le("CurrentVersion\\Run").as_slice()
        );
        // Non-ASCII bytes around it change nothing.
        let mut padded = vec![0xFFu8; 7];
        padded.extend_from_slice(&wide);
        assert!(contains_ignore_ascii_case(&padded, "currentversion\\run"));
    }

    #[test]
    fn a_wide_search_does_not_match_two_loose_bytes() {
        // `v` then `s` with a non-zero high byte is not `vs`. Without the
        // high-byte check, any two bytes anywhere would spell any two-character
        // needle.
        assert!(!contains_ignore_ascii_case(b"\x76\x01\x73\x01", "vs"));
        assert!(contains_ignore_ascii_case(b"\x76\x00\x73\x00", "vs"));
    }

    #[test]
    fn a_narrow_match_is_preferred_and_reported_as_narrow() {
        // Both spellings present: the single-byte one is found first and the
        // location says so, so the length it reports is the right length.
        let mut hay = to_utf16le("windefend");
        hay.extend_from_slice(b"windefend");
        let found = find_either(&hay, "windefend").expect("present");
        assert_eq!(found.encoding, Encoding::Narrow);
        assert_eq!(found.offset, 18);
    }

    #[test]
    fn a_needle_that_cannot_fit_wide_is_not_a_match() {
        // Neither spelling occurs: the wide one does not fit in five bytes, and
        // the single-byte search is defeated by the zero bytes interleaved in
        // what is there.
        assert!(!contains_ignore_ascii_case(b"a\x00b\x00c", "abc"));
        // And a buffer that does hold the wide spelling matches.
        assert!(contains_ignore_ascii_case(b"a\x00b\x00c\x00", "abc"));
        assert!(contains_ignore_ascii_case(b"abc", "abc"));
    }
}
