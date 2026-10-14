//! Turning a member's stored name into a string that is safe to print.
//!
//! # What a name can be
//!
//! A zip's member name is between one and 65,535 arbitrary bytes chosen by
//! whoever built the archive. Everything about that is a problem for a program
//! that wants to put it in a report:
//!
//! * It can contain a newline, which forges a line in a log or a console
//!   report. This is the one that actually matters. A finding whose text reads
//!   `evil.exe\n  nothing found` is a finding a human reads wrongly.
//! * It can contain terminal escape sequences, which on a console can move the
//!   cursor, recolour text, or — with the right sequences — rewrite the lines
//!   above it.
//! * It can claim to be a path: `..\..\Windows\System32\evil.dll`, an absolute
//!   path, or a drive-qualified one. Nothing here is extracted to disk, so
//!   there is no traversal to defend against, but a report that prints
//!   `C:\Windows\System32\evil.dll` for something that is inside a zip is
//!   telling the user something false about their machine.
//! * It can be enormous, which makes a report unreadable.
//! * It can be in one of two encodings, and which one is a flag in the entry.
//!
//! # What this module does about each
//!
//! [`decode`] settles the encoding, [`sanitize`] settles everything else, and
//! the two are separate because they answer different questions and a caller
//! occasionally wants only the first.

/// The upper half of code page 437, which is what a zip member's name means
/// when its entry does not set the UTF-8 flag.
///
/// Zip predates the assumption that a filename is Unicode. An archive written
/// by an old Windows tool stores OEM bytes with no flag saying which code page
/// they are, and CP437 is the one the format's own specification names as the
/// default. Decoding those bytes as UTF-8 would produce a row of replacement
/// characters — technically safe, and useless to the user who is trying to
/// recognise a filename they can see in Explorer.
const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ',
    'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ',
    'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕',
    '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦',
    '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐',
    '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

/// Decode a member name's bytes.
///
/// `utf8` is the entry's EFS flag: when it is set the name is UTF-8 by
/// definition, and when it is not the name is CP437. A name that claims to be
/// UTF-8 and is not is decoded lossily rather than refused — a malformed name
/// is not a reason to leave a member unexamined, and the replacement characters
/// are visible in the report rather than hidden.
pub fn decode(bytes: &[u8], utf8: bool) -> String {
    if utf8 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    bytes
        .iter()
        .map(|&b| match b {
            0x20..=0x7E => char::from(b),
            b'\n' | b'\r' | b'\t' => char::from(b),
            0x00..=0x1F | 0x7F => '\u{fffd}',
            _ => CP437_HIGH[usize::from(b - 0x80)],
        })
        .collect()
}

/// How long a single member's name may be before it is cut short.
///
/// Long enough for any name a person typed, and far short of the 65,535 a zip
/// permits. The tail is what is kept on a path so that the file's own name —
/// the part a user recognises — survives the cut.
pub const MAX_NAME: usize = 160;

/// How long the whole outermost-to-innermost chain may be.
///
/// Four times a single name, so three levels of nesting fit before anything is
/// trimmed.
pub const MAX_CHAIN: usize = 480;

/// Make a decoded name safe to put in a report.
///
/// Every rule here is about not lying to the reader:
///
/// * Control characters and terminal escapes become `.`, so a name cannot
///   forge a line or move a cursor.
/// * Backslashes become forward slashes. A member name is not a path on this
///   machine, and printing one with Windows separators would suggest it is.
/// * A leading `/` or a drive prefix is dropped: the member is inside the
///   archive, not at that location.
/// * Empty segments and `.` segments are dropped; `..` is kept, because an
///   archive that is trying to look like it escapes its own directory is worth
///   the user seeing.
/// * The result is capped at [`MAX_NAME`], keeping the tail.
pub fn sanitize(decoded: &str) -> String {
    let normalized = decoded.replace('\\', "/");
    let mut segments: Vec<&str> = normalized
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();

    // A leading drive prefix is dropped, and only a leading one: `C:` as the
    // first segment is a claim about where on a machine the member lives, which
    // is false. A segment that merely contains a colon is part of a name.
    if segments
        .first()
        .is_some_and(|segment| is_drive_prefix(segment))
    {
        segments.remove(0);
    }

    let body = segments
        .into_iter()
        .map(clean_segment)
        .collect::<Vec<_>>()
        .join("/");

    if body.is_empty() {
        return String::new();
    }
    truncate_keeping_tail(&body, MAX_NAME)
}

/// True for a segment shaped like a drive: one ASCII letter and a colon.
fn is_drive_prefix(segment: &str) -> bool {
    let mut chars = segment.chars();
    matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(c), Some(':'), None) if c.is_ascii_alphabetic()
    )
}

/// Replace everything in one path segment that must not reach a report.
fn clean_segment(segment: &str) -> String {
    segment
        .chars()
        .map(|c| match c {
            c if c.is_control() => '.',
            // The bidirectional and zero-width formatting characters are the
            // other way to make a name read as something it is not: a name
            // containing U+202E displays reversed, so `exe.txt` renders as
            // `txt.exe`. They are ordinary characters to a terminal and are
            // stripped here for the same reason control characters are.
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => '.',
            c => c,
        })
        .collect()
}

/// Cut a string to `max` bytes, keeping both ends and marking the cut.
///
/// By bytes rather than characters, and then backed off to a character
/// boundary, because the cap exists to bound what is printed and a count in
/// characters bounds nothing about the bytes.
pub fn truncate_keeping_tail(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    const MARKER: &str = "...";
    let keep = max.saturating_sub(MARKER.len());
    // A quarter from the front, the rest from the back: a nested member's
    // useful part is its own name, and the directories above it are only
    // useful for telling two archives apart.
    let head_wanted = keep / 4;
    let tail_wanted = keep - head_wanted;
    let head = floor_char_boundary(text, head_wanted);
    let tail_start = ceil_char_boundary(text, text.len() - tail_wanted);
    format!("{}{MARKER}{}", &text[..head], &text[tail_start..])
}

/// Join an outer member chain to an inner name, capped at [`MAX_CHAIN`].
pub fn join_chain(outer: Option<&str>, inner: &str) -> String {
    match outer {
        None => inner.to_owned(),
        Some(outer) => truncate_keeping_tail(&format!("{outer}/{inner}"), MAX_CHAIN),
    }
}

/// The largest index at or below `index` that is a character boundary.
fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// The smallest index at or above `index` that is a character boundary.
fn ceil_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ascii_name_is_left_alone() {
        assert_eq!(sanitize("docs/report.pdf"), "docs/report.pdf");
        assert_eq!(sanitize("evil.exe"), "evil.exe");
    }

    #[test]
    fn a_newline_cannot_forge_a_line_in_a_report() {
        // The case this module exists for. A name that could put a line break
        // into a report could make a finding read as two lines, the second of
        // which the scanner never wrote.
        let cleaned = sanitize("evil.exe\n  scan complete: 0 threats found");
        assert!(!cleaned.contains('\n'), "{cleaned}");
        // The newline becomes a single dot, not a doubled one: the two spaces
        // that followed it are ordinary characters and are kept, which is what
        // makes the forged text still *look* like a report line while being
        // unmistakably part of the name.
        assert_eq!(cleaned, "evil.exe.  scan complete: 0 threats found");
    }

    #[test]
    fn an_escape_sequence_cannot_move_the_cursor() {
        let cleaned = sanitize("a\u{1b}[2Kb.exe");
        assert!(!cleaned.chars().any(char::is_control), "{cleaned}");
    }

    #[test]
    fn a_name_that_claims_to_be_a_windows_path_is_shown_inside_the_archive() {
        // Nothing here is extracted, so there is no traversal — but printing
        // this as `C:\Windows\System32\evil.dll` would tell a user something
        // false about their machine.
        let cleaned = sanitize(r"..\..\Windows\System32\evil.dll");
        assert_eq!(cleaned, "../../Windows/System32/evil.dll");
        assert_eq!(sanitize("/etc/passwd"), "etc/passwd");
        assert_eq!(sanitize(r"C:\temp\x.exe"), "temp/x.exe");
        assert_eq!(sanitize(r"C:/temp/x.exe"), "temp/x.exe");
    }

    #[test]
    fn the_drive_strip_does_not_eat_an_ordinary_name() {
        // The narrowness matters: `a:` is a drive prefix, `abc` is a filename.
        assert_eq!(sanitize("abc.txt"), "abc.txt");
        assert_eq!(sanitize("a.txt"), "a.txt");
        assert_eq!(sanitize("a:/b.txt"), "b.txt");
        // A name that is only a drive prefix has nothing left.
        assert_eq!(sanitize("C:"), "");
    }

    #[test]
    fn empty_and_dot_segments_are_dropped_and_dotdot_is_kept() {
        assert_eq!(sanitize("a//b/./c"), "a/b/c");
        assert_eq!(sanitize("./a"), "a");
        assert_eq!(sanitize("../../a"), "../../a");
    }

    #[test]
    fn a_name_that_is_only_separators_becomes_empty() {
        assert_eq!(sanitize("/"), "");
        assert_eq!(sanitize("///"), "");
        assert_eq!(sanitize("."), "");
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn a_bidirectional_override_cannot_reverse_what_the_name_looks_like() {
        // `exe.txt` with RLO renders as `txt.exe` in many terminals. The
        // character is stripped so the report shows what is stored.
        let cleaned = sanitize("exe\u{202e}txt");
        assert_eq!(cleaned, "exe.txt");
        assert_eq!(sanitize("a\u{200b}b"), "a.b");
    }

    #[test]
    fn a_utf8_name_is_decoded_as_utf8_when_the_entry_says_so() {
        let bytes = "文件/報告.pdf".as_bytes();
        assert_eq!(decode(bytes, true), "文件/報告.pdf");
        assert_eq!(sanitize(&decode(bytes, true)), "文件/報告.pdf");
    }

    #[test]
    fn a_legacy_name_is_decoded_as_code_page_437() {
        // 0x81 is ü in CP437 and is not valid UTF-8. Decoding it as UTF-8 would
        // give a replacement character; a user looking at the same file in
        // Explorer sees the ü.
        assert_eq!(decode(&[b'f', 0x81, b'.', b't'], false), "fü.t");
        // And when the entry claims UTF-8 and is not, the replacement character
        // is visible rather than hidden.
        assert_eq!(decode(&[b'a', 0x81], true), "a\u{fffd}");
    }

    #[test]
    fn every_code_page_437_slot_has_a_character() {
        // The table is a literal and a missing entry would be a compile error,
        // but a *wrong* entry is invisible. This at least asserts that the
        // table is the shape the format needs.
        assert_eq!(CP437_HIGH.len(), 128);
        assert_eq!(CP437_HIGH[0], 'Ç');
        assert_eq!(CP437_HIGH[127], '\u{a0}');
        assert_eq!(decode(&[0xb0], false), "░");
    }

    #[test]
    fn an_enormous_name_is_cut_short_keeping_its_own_name() {
        let long = format!("{}/payload.exe", "d".repeat(5000));
        let cleaned = sanitize(&long);
        assert!(cleaned.len() <= MAX_NAME, "{}", cleaned.len());
        assert!(cleaned.ends_with("payload.exe"), "{cleaned}");
        assert!(cleaned.contains("..."), "{cleaned}");
    }

    #[test]
    fn truncation_never_splits_a_character() {
        // A multi-byte character cut in half is a panic in safe Rust and a
        // mojibake name in the report; both are avoidable by backing off to a
        // boundary.
        let text = "文".repeat(200);
        let cut = truncate_keeping_tail(&text, 51);
        assert!(cut.len() <= 51);
        assert!(cut.is_char_boundary(cut.len()));
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
    }

    #[test]
    fn a_chain_is_joined_with_forward_slashes_and_bounded() {
        assert_eq!(join_chain(None, "inner.exe"), "inner.exe");
        assert_eq!(
            join_chain(Some("outer.zip"), "inner.exe"),
            "outer.zip/inner.exe"
        );
        let deep = join_chain(Some(&"x".repeat(400)), &"y".repeat(400));
        assert!(deep.len() <= MAX_CHAIN, "{}", deep.len());
    }
}
