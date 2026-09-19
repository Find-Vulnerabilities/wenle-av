//! Matching the literal forms of a text string.
//!
//! A `$a = "text" xor(1-255) wide base64` definition is not one pattern, it is
//! hundreds: the ASCII form, the UTF-16 form, each XOR key over each of those,
//! and the base64 encodings of both. All of them are plain byte sequences, so
//! they all reduce to the same primitive — find every occurrence of a fixed
//! needle — and this module exists to make that primitive fast and then to
//! generate the variants correctly, because the variants are where the subtle
//! mistakes live.
//!
//! # Why search rather than prefilter
//!
//! The rule-level prefilter ([`crate::prefilter`]) is what keeps a scan from
//! running ten thousand rules against every file, and it works on atoms shared
//! across the whole rule set. Once a rule has been selected, though, the honest
//! thing is to find its strings properly: a scan of one needle with `memchr` is
//! SIMD-accelerated and runs at gigabytes per second, which is fast enough that
//! a second, cleverer layer between the prefilter and the answer would cost
//! more in complexity than it saves in time.

use smallvec::SmallVec;

use crate::ast::{Base64Alphabet, Modifiers};

/// The largest number of literal variants one string may expand to.
///
/// `nocase wide xor(1-255) base64` expands to over a thousand, and every one of
/// them is a separate pass over the buffer. A rule that broad is almost
/// certainly a mistake, and one that silently made scans a thousand times
/// slower would be a far worse outcome than refusing it. The limit sits well
/// above what an ordinary rule needs — `xor(1-255)` on its own, the widest
/// modifier in common use, comes to 256 — and an over-limit string is refused
/// by name rather than quietly accepted.
pub const MAX_VARIANTS: usize = 512;

/// One fixed byte sequence to search for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Literal {
    pub bytes: Vec<u8>,
    /// Compare ASCII case-insensitively.
    pub nocase: bool,
    /// Require non-alphanumeric bytes on both sides.
    pub fullword: bool,
}

impl Literal {
    fn new(bytes: Vec<u8>, nocase: bool, fullword: bool) -> Self {
        Self {
            bytes,
            nocase,
            fullword,
        }
    }

    /// Find every occurrence of this literal in `data`, appending to `out`.
    ///
    /// Offsets are appended in increasing order, which the table relies on but
    /// does not require — [`crate::matches::MatchSet::sort`] is the backstop.
    pub fn find_all(&self, data: &[u8], out: &mut Vec<(u32, u32)>) {
        if self.bytes.is_empty() {
            // An empty needle "matches" at every offset. Expanded, that is a
            // string with `filesize + 1` matches, which makes `#a` meaningless
            // and `@a` always zero. No valid rule reaches here — the parser
            // rejects an empty string and base64 generation drops the variants
            // that would be empty — so this is a guard, not a case.
            return;
        }
        if self.bytes.len() > data.len() {
            return;
        }
        if self.nocase {
            self.find_nocase(data, out);
        } else {
            // Advanced one byte past each hit rather than by the needle's
            // length. `memmem::find_iter` yields only non-overlapping
            // occurrences, so `aa` in `aaaa` would be reported twice instead of
            // three times, and `#a == 3` is a condition rules are actually
            // written against. The rescan after a hit costs the second byte
            // onwards, which is nothing next to the SIMD pass that found it.
            let finder = memchr::memmem::Finder::new(&self.bytes);
            let mut from = 0usize;
            while from + self.bytes.len() <= data.len() {
                let Some(rel) = finder.find(&data[from..]) else {
                    return;
                };
                let at = from + rel;
                self.push_if_whole(data, at, out);
                from = at + 1;
            }
        }
    }

    /// Case-insensitive search.
    ///
    /// Not done by lowercasing the buffer first: that costs a full pass and an
    /// allocation per string, and a rule set has tens of thousands of strings.
    /// Instead the first byte is matched against both its cases with
    /// `memchr2`, which is the same SIMD scan, and the candidate is then
    /// verified. Most candidates fail on the second byte, so the verification
    /// is nearly free.
    fn find_nocase(&self, data: &[u8], out: &mut Vec<(u32, u32)>) {
        let first = self.bytes[0];
        let (a, b) = (first.to_ascii_lowercase(), first.to_ascii_uppercase());
        let mut from = 0usize;
        // The last offset a needle of this length can start at.
        let Some(last_start) = data.len().checked_sub(self.bytes.len()) else {
            return;
        };
        while from <= last_start {
            let Some(rel) = memchr::memchr2(a, b, &data[from..=last_start]) else {
                return;
            };
            let at = from + rel;
            let window = &data[at..at + self.bytes.len()];
            if window
                .iter()
                .zip(&self.bytes)
                .all(|(x, y)| x.eq_ignore_ascii_case(y))
            {
                self.push_if_whole(data, at, out);
            }
            // Advance past the byte just tried. Advancing by the needle length
            // instead would miss overlapping matches, and `#a` counting one
            // occurrence where a file has two is a rule that quietly stops
            // firing.
            from = at + 1;
        }
    }

    /// Record a hit at `at` if `fullword` is satisfied.
    fn push_if_whole(&self, data: &[u8], at: usize, out: &mut Vec<(u32, u32)>) {
        if self.fullword && !is_whole_word(data, at, self.bytes.len()) {
            return;
        }
        // Both fit: the match lies inside the buffer, whose length is a
        // `usize` that came from a slice, so it cannot exceed `u32::MAX` on any
        // target this engine runs on without the conversion failing first.
        if let (Ok(offset), Ok(length)) = (u32::try_from(at), u32::try_from(self.bytes.len())) {
            out.push((offset, length));
        }
    }
}

/// Whether the bytes at `at..at+len` are delimited by non-word bytes.
///
/// The delimiter set is `[A-Za-z0-9_]`, which is what "word character" means
/// everywhere else in this codebase. Two consequences worth stating: a match at
/// the very start or end of the buffer counts as delimited, because there is
/// nothing there to contradict it; and a byte that is not ASCII — one half of a
/// UTF-8 sequence, say — is not a word character, so it delimits.
fn is_whole_word(data: &[u8], at: usize, len: usize) -> bool {
    let before = at.checked_sub(1).and_then(|i| data.get(i)).copied();
    let after = data.get(at + len).copied();
    let is_word = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
    !is_word(before) && !is_word(after)
}

/// One spelling of a string before the modifiers are applied.
struct Form {
    /// The bytes as they would appear in the file, before XOR or base64.
    bytes: Vec<u8>,
    /// Whether this is the UTF-16 expansion.
    wide: bool,
}

/// Expand a text string into every fixed byte sequence it should be found as.
///
/// Returns an error when the expansion is too large to search, so that a rule
/// author gets told rather than getting a scan that takes a thousand times
/// longer than they expected.
pub fn variants(bytes: &[u8], modifiers: &Modifiers) -> Result<Vec<Literal>, &'static str> {
    if bytes.is_empty() {
        return Err("an empty string matches everywhere");
    }
    let mut out: Vec<Literal> = Vec::new();
    let (nocase, fullword) = (modifiers.nocase, modifiers.fullword);

    // `ascii` defaults to true when neither form was named, which is what the
    // language specifies and what every rule author assumes. `wide` alone means
    // *only* the UTF-16 form. Both flags being false is read as the default,
    // since that is the only reading that does not silently search for nothing.
    let mut forms: SmallVec<[Form; 2]> = SmallVec::new();
    if modifiers.ascii || !modifiers.wide {
        forms.push(Form {
            bytes: bytes.to_vec(),
            wide: false,
        });
    }
    if modifiers.wide {
        forms.push(Form {
            bytes: to_wide(bytes),
            wide: true,
        });
    }

    for form in &forms {
        out.push(Literal::new(form.bytes.clone(), nocase, fullword));
        if let Some(range) = modifiers.xor {
            for key in range.min..=range.max {
                out.push(Literal::new(xor_bytes(&form.bytes, key), nocase, fullword));
            }
        }
    }

    // Base64 is generated from the *un-XORed* forms, and never combined with
    // XOR: the two describe different ways the string reaches the file, and
    // base64-of-XOR is not one of them. `base64` alone encodes the bytes as
    // written; `base64wide` asks for the encoding of the UTF-16 expansion too.
    if let Some(alphabet) = modifiers.base64 {
        for form in &forms {
            if form.wide && !alphabet.wide {
                continue;
            }
            base64_variants(&form.bytes, alphabet, nocase, fullword, &mut out);
        }
    }

    if out.len() > MAX_VARIANTS {
        return Err("expands to too many variants to search");
    }
    Ok(out)
}

/// The UTF-16LE expansion: every byte followed by a zero.
///
/// Applied to bytes rather than characters, which is what the language means —
/// a rule may write a `wide` string containing bytes that are not valid UTF-8,
/// and re-encoding through a `String` would fail or mangle them.
fn to_wide(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(*b);
        out.push(0);
    }
    out
}

fn xor_bytes(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.iter().map(|b| b ^ key).collect()
}

/// Generate the base64 forms of a string and append them as literals.
///
/// # What "find the base64 of X" means
///
/// The string does not appear in the file — its *encoding* does, and where in
/// the encoding it starts is not known. Base64 works on three-byte groups, so
/// there are three cases: the string begins at a group boundary, one byte in,
/// or two bytes in. Encoding the string directly only covers the first.
///
/// For the other two, the standard trick is to prepend dummy bytes to make the
/// alignment come out right, encode, and then discard the characters whose
/// value depends on a byte we do not know. At the front that is
/// `ceil(padding_bits / 6)` characters; at the back it is one character,
/// whenever the string does not end on a group boundary and the next byte —
/// unknown — shares that character's six bits.
///
/// What is left is a run of characters determined entirely by the string, so it
/// can be searched for literally. It is a *substring* of the encoding rather
/// than the whole of it, which is why `$a at N` against a base64 string means
/// "the encoding of `$a` covers the bytes at N" only loosely — the match begins
/// where the determined run begins, not where the encoded string begins. YARA
/// has the same behaviour.
fn base64_variants(
    bytes: &[u8],
    alphabet: Base64Alphabet,
    nocase: bool,
    fullword: bool,
    out: &mut Vec<Literal>,
) {
    let mut encoded: SmallVec<[Vec<u8>; 4]> = SmallVec::new();
    for alignment in 0..3usize {
        let mut padded = vec![0u8; alignment];
        padded.extend_from_slice(bytes);
        let text = encode_base64(&padded);

        // Characters covering the dummy prefix, plus the one that shares its
        // low bits with the first real byte.
        let front = (alignment * 8).div_ceil(6);
        // `n` counts the dummy bytes too, because the final group is aligned to
        // the start of the padded buffer, not to the string.
        let n = padded.len();
        let tail = if n % 3 == 0 { 0 } else { 1 };
        if front + tail >= text.len() {
            // Nothing is determined: a one-byte string at an awkward alignment
            // has no character that does not also depend on a neighbouring
            // byte. Skipping the variant is correct — the alternative is
            // searching for a character that would match the wrong thing.
            continue;
        }
        encoded.push(text[front..text.len() - tail].to_vec());
    }

    for bytes in encoded {
        push_alphabet_variants(&bytes, alphabet, nocase, fullword, out);
    }
}

/// Append the standard and URL-safe spellings of an encoded run.
///
/// The alphabets differ in exactly two characters, so the URL-safe form is
/// derived rather than encoded again.
fn push_alphabet_variants(
    bytes: &[u8],
    alphabet: Base64Alphabet,
    nocase: bool,
    fullword: bool,
    out: &mut Vec<Literal>,
) {
    if alphabet.standard {
        out.push(Literal::new(bytes.to_vec(), nocase, fullword));
    }
    if alphabet.url_safe {
        let url: Vec<u8> = bytes
            .iter()
            .map(|b| match b {
                b'+' => b'-',
                b'/' => b'_',
                other => *other,
            })
            .collect();
        if url != bytes {
            out.push(Literal::new(url, nocase, fullword));
        }
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, with the trailing `=` padding removed.
///
/// The padding is dropped deliberately: what follows the encoded string in the
/// file is unknown, so a literal ending in `=` would only match when the string
/// happened to be the last thing encoded — which is the case the alignment pass
/// already covers by discarding the final, undetermined character.
fn encode_base64(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let b0 = u32::from(group[0]);
        let b1 = group.get(1).copied().map_or(0, u32::from);
        let b2 = group.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let chars = [
            (triple >> 18) & 0x3F,
            (triple >> 12) & 0x3F,
            (triple >> 6) & 0x3F,
            triple & 0x3F,
        ];
        // A group of one byte produces two characters, two bytes produce three.
        // The fourth and third respectively encode nothing but zero bits.
        let keep = group.len() + 1;
        for c in chars.iter().take(keep) {
            out.push(ALPHABET[*c as usize]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::XorRange;

    fn text(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    fn plain() -> Modifiers {
        Modifiers {
            ascii: true,
            ..Modifiers::default()
        }
    }

    fn find(literal: &Literal, data: &[u8]) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        literal.find_all(data, &mut out);
        out
    }

    // -- the search primitive ---------------------------------------------

    #[test]
    fn finds_every_occurrence_in_order() {
        let l = Literal::new(text(b"ab"), false, false);
        assert_eq!(find(&l, b"ab_ab_ab"), vec![(0, 2), (3, 2), (6, 2)]);
    }

    #[test]
    fn finds_overlapping_occurrences() {
        // "aa" occurs at 0, 1 and 2 in "aaaa". Advancing by the needle length
        // after a hit would report one, and a rule counting occurrences would
        // then undercount.
        let l = Literal::new(text(b"aa"), false, false);
        assert_eq!(find(&l, b"aaaa"), vec![(0, 2), (1, 2), (2, 2)]);
    }

    #[test]
    fn a_needle_longer_than_the_buffer_finds_nothing() {
        let l = Literal::new(text(b"abcdef"), false, false);
        assert!(find(&l, b"abc").is_empty());
        assert!(find(&l, b"").is_empty());
    }

    #[test]
    fn a_needle_that_ends_exactly_at_the_end_is_found() {
        let l = Literal::new(text(b"cd"), false, false);
        assert_eq!(find(&l, b"abcd"), vec![(2, 2)]);
    }

    #[test]
    fn case_insensitive_search_finds_both_cases() {
        let l = Literal::new(text(b"AbC"), true, false);
        assert_eq!(find(&l, b"abcABC aBc"), vec![(0, 3), (3, 3), (7, 3)]);
    }

    #[test]
    fn case_insensitive_search_finds_overlapping_matches() {
        let l = Literal::new(text(b"aA"), true, false);
        assert_eq!(find(&l, b"aaaa"), vec![(0, 2), (1, 2), (2, 2)]);
    }

    #[test]
    fn case_insensitive_search_ignores_non_ascii_bytes() {
        // Folding is ASCII-only: 0xC0 is not the uppercase of 0xE0 outside a
        // specific Latin-1 reading, and a rule that matched differently
        // depending on locale would be a rule that matches differently on
        // different machines.
        let l = Literal::new(vec![0xE0], true, false);
        assert!(find(&l, &[0xC0]).is_empty());
        assert_eq!(find(&l, &[0xE0]), vec![(0, 1)]);
    }

    #[test]
    fn an_empty_needle_is_not_searched() {
        // Guarded rather than expanded: an empty needle occurs at every offset,
        // which would make `#a` equal the file size.
        let l = Literal::new(Vec::new(), false, false);
        assert!(find(&l, b"abc").is_empty());
    }

    // -- fullword ----------------------------------------------------------

    #[test]
    fn fullword_rejects_a_match_inside_a_longer_word() {
        let l = Literal::new(text(b"cat"), false, true);
        assert_eq!(find(&l, b"a cat sat"), vec![(2, 3)]);
        assert!(find(&l, b"concatenate").is_empty());
    }

    #[test]
    fn fullword_accepts_a_match_at_either_end_of_the_buffer() {
        let l = Literal::new(text(b"cat"), false, true);
        assert_eq!(find(&l, b"cat"), vec![(0, 3)]);
        assert_eq!(find(&l, b"cat!"), vec![(0, 3)]);
        assert_eq!(find(&l, b"!cat"), vec![(1, 3)]);
    }

    #[test]
    fn fullword_treats_underscore_and_digits_as_word_bytes() {
        let l = Literal::new(text(b"cat"), false, true);
        assert!(find(&l, b"cat_").is_empty(), "underscore is a word byte");
        assert!(find(&l, b"cat1").is_empty(), "a digit is a word byte");
        assert_eq!(find(&l, b"cat-"), vec![(0, 3)], "a hyphen is not");
    }

    #[test]
    fn fullword_treats_a_non_ascii_byte_as_a_delimiter() {
        let l = Literal::new(text(b"cat"), false, true);
        assert_eq!(find(&l, b"\xE9cat\xE9"), vec![(1, 3)]);
    }

    // -- variant generation ------------------------------------------------

    #[test]
    fn a_plain_string_is_one_literal() {
        let v = variants(b"abc", &plain()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].bytes, b"abc");
    }

    #[test]
    fn wide_expands_every_byte_with_a_zero() {
        let m = Modifiers {
            ascii: true,
            wide: true,
            ..Modifiers::default()
        };
        let v = variants(b"ab", &m).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].bytes, b"ab");
        assert_eq!(v[1].bytes, b"a\0b\0");
    }

    #[test]
    fn wide_alone_does_not_also_emit_the_ascii_form() {
        let m = Modifiers {
            ascii: false,
            wide: true,
            ..Modifiers::default()
        };
        let v = variants(b"ab", &m).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].bytes, b"a\0b\0");
    }

    #[test]
    fn xor_adds_one_literal_per_key() {
        let m = Modifiers {
            ascii: true,
            xor: Some(XorRange { min: 1, max: 3 }),
            ..Modifiers::default()
        };
        let v = variants(b"\x00", &m).unwrap();
        assert_eq!(v.len(), 4, "the plain form plus three keys");
        assert_eq!(v[1].bytes, vec![1]);
        assert_eq!(v[3].bytes, vec![3]);
    }

    #[test]
    fn xor_is_applied_to_the_wide_form_too() {
        let m = Modifiers {
            ascii: true,
            wide: true,
            xor: Some(XorRange { min: 1, max: 2 }),
            ..Modifiers::default()
        };
        let v = variants(b"A", &m).unwrap();
        // plain, xor1, xor2, wide, wide-xor1, wide-xor2
        assert_eq!(v.len(), 6);
        assert_eq!(v[4].bytes, vec![b'A' ^ 1, 1]);
    }

    #[test]
    fn an_empty_string_is_refused() {
        assert!(variants(b"", &plain()).is_err());
    }

    #[test]
    fn an_expansion_past_the_limit_is_refused_rather_than_run() {
        let m = Modifiers {
            ascii: true,
            wide: true,
            nocase: true,
            xor: Some(XorRange::FULL),
            base64: Some(Base64Alphabet::default()),
            ..Modifiers::default()
        };
        // 2 forms x 256 (plain + 255 keys) = 512, plus base64 variants, which
        // takes it over the limit.
        let err = variants(b"abcdefgh", &m).unwrap_err();
        assert!(err.contains("too many variants"), "{err}");
    }

    // -- base64 ------------------------------------------------------------

    fn base64_only() -> Modifiers {
        Modifiers {
            ascii: true,
            base64: Some(Base64Alphabet {
                standard: true,
                url_safe: false,
                wide: false,
            }),
            ..Modifiers::default()
        }
    }

    #[test]
    fn our_base64_encoder_agrees_with_the_standard() {
        assert_eq!(encode_base64(b""), b"");
        assert_eq!(encode_base64(b"f"), b"Zg");
        assert_eq!(encode_base64(b"fo"), b"Zm8");
        assert_eq!(encode_base64(b"foo"), b"Zm9v");
        assert_eq!(encode_base64(b"foob"), b"Zm9vYg");
        assert_eq!(encode_base64(b"fooba"), b"Zm9vYmE");
        assert_eq!(encode_base64(b"foobar"), b"Zm9vYmFy");
    }

    #[test]
    fn the_group_boundary_alignment_finds_the_whole_encoding() {
        // "foobar" at a group boundary is exactly its encoding, since six bytes
        // is a whole number of groups.
        let v = variants(b"foobar", &base64_only()).unwrap();
        assert!(
            v.iter().any(|l| l.bytes == b"Zm9vYmFy"),
            "{:?}",
            v.iter().map(|l| String::from_utf8_lossy(&l.bytes)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_other_two_alignments_are_found_in_a_longer_encoded_stream() {
        // The real test of the alignment pass: encode a buffer, embed the
        // string at each of the three byte offsets inside it, and check that the
        // variant for that alignment occurs in the result.
        let secret = b"foobar";
        for offset in 0..3usize {
            let mut data = vec![0u8; offset];
            data.extend_from_slice(secret);
            data.extend_from_slice(b"tail");
            let encoded = encode_base64(&data);
            let literals = variants(secret, &base64_only()).unwrap();
            assert!(
                literals.iter().any(|l| {
                    let mut hits = Vec::new();
                    l.find_all(&encoded, &mut hits);
                    !hits.is_empty()
                }),
                "no variant of {secret:?} found in {encoded:?} at offset {offset}"
            );
        }
    }

    #[test]
    fn a_base64_match_is_a_substring_of_the_encoding_not_the_whole_of_it() {
        // Pinning the documented limitation rather than pretending it does not
        // exist: with the string one byte into a group, the determined run
        // starts mid-group.
        let v = variants(b"foobar", &base64_only()).unwrap();
        let longest = v.iter().max_by_key(|l| l.bytes.len()).unwrap();
        assert!(longest.bytes.len() <= 8);
    }

    #[test]
    fn the_url_safe_alphabet_is_generated_beside_the_standard_one() {
        // ">" encodes to a run containing '+', so the two alphabets differ and
        // both spellings must be present.
        let m = Modifiers {
            ascii: true,
            base64: Some(Base64Alphabet {
                standard: true,
                url_safe: true,
                wide: false,
            }),
            ..Modifiers::default()
        };
        let v = variants(b"\xfb\xff\xbf", &m).unwrap();
        let has = |needle: &[u8]| v.iter().any(|l| l.bytes == needle);
        assert!(has(b"+/+/") || has(b"+/+") || has(b"v7+/"), "{v:?}");
        assert!(
            v.iter().any(|l| l.bytes.contains(&b'-') || l.bytes.contains(&b'_')),
            "the URL-safe spelling must be present: {v:?}"
        );
    }

    #[test]
    fn a_one_byte_string_has_no_variant_at_one_alignment() {
        // A single byte landing one byte into a group has its eight bits spread
        // across two characters, and each of those also carries bits from an
        // unknown neighbour — so neither is determined, and the alignment
        // contributes nothing. The other two alignments each pin exactly one
        // character, and the ascii form is present because the string is also a
        // literal.
        let v = variants(b"f", &base64_only()).unwrap();
        let found: Vec<&[u8]> = v.iter().map(|l| l.bytes.as_slice()).collect();
        assert!(found.contains(&b"f".as_slice()), "the ascii form: {v:?}");
        assert!(found.contains(&b"Z".as_slice()), "at a group boundary: {v:?}");
        assert!(found.contains(&b"m".as_slice()), "two bytes in: {v:?}");
        assert_eq!(found.len(), 3, "and nothing from alignment one: {v:?}");
    }

    #[test]
    fn base64_without_the_wide_flag_does_not_encode_the_wide_form() {
        let m = Modifiers {
            ascii: true,
            wide: true,
            base64: Some(Base64Alphabet {
                standard: true,
                url_safe: false,
                wide: false,
            }),
            ..Modifiers::default()
        };
        let v = variants(b"ab", &m).unwrap();
        let wide_encoding = encode_base64(b"a\0b\0");
        assert!(
            !v.iter().any(|l| l.bytes == wide_encoding || wide_encoding.starts_with(&l.bytes) && l.bytes.len() > 3),
            "the wide form must not be base64-encoded: {v:?}"
        );
    }

    #[test]
    fn the_end_of_the_encoding_is_dropped_because_the_next_byte_is_unknown() {
        // "foobar" is six bytes, a whole number of groups, so every character
        // is determined by the string alone.
        let v = variants(b"foobar", &base64_only()).unwrap();
        assert!(v.iter().any(|l| l.bytes == b"Zm9vYmFy"), "{v:?}");

        // "fooba" is not. The final group is `b a ?`, and the character that
        // would be `E` takes four of its six bits from the low nibble of `a`
        // but two from the top of the unknown byte — so it is not determined
        // and the run stops at `Zm9vYm`. Searching for the `E` would match a
        // file whose following byte happened to agree and miss every other
        // one, which is worse than not searching for it.
        let v = variants(b"fooba", &base64_only()).unwrap();
        assert!(
            v.iter().any(|l| l.bytes == b"Zm9vYm"),
            "the determined run ends one character early: {v:?}"
        );
        assert!(
            !v.iter().any(|l| l.bytes.contains(&b'=')),
            "padding is always stripped: {v:?}"
        );
    }

}
