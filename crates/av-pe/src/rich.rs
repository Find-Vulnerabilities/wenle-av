//! The Rich header: the linker's own record of which tools built the file.
//!
//! # What it is
//!
//! Between the DOS stub and the PE header — in the gap the format reserves and
//! nothing uses — every image the Microsoft toolchain links carries a small
//! structure recording, per build tool, how many times that tool contributed to
//! the binary. It is not part of the format, no loader reads it, and its only
//! purpose was to let Microsoft count which compiler versions were in use. It is
//! useful to a scanner for the same reason it was useful to Microsoft: it is a
//! fingerprint of the toolchain, stable across every sample a given builder
//! produces and awkward to forge without knowing the structure.
//!
//! # The layout, exactly
//!
//! Every field is a little-endian `u32`. Written as the bytes that are in the
//! file:
//!
//! ```text
//! <dans>       DanS ^ key        the marker, encrypted
//!              padding[0] ^ key   three zero dwords, encrypted
//!              padding[1] ^ key
//!              padding[2] ^ key
//!              compid[0] ^ key    one (compid, count) pair per entry
//!              count[0] ^ key
//!              ...
//! <rich>       Rich              the marker, in the clear
//! <rich + 4>   key               the XOR key, in the clear
//! ```
//!
//! `DanS` is `0x536E6144` and `Rich` is `0x68636952`, both read as little-endian
//! dwords — which is why the second marker is the string `Rich` on disk and the
//! first is not the string `DanS`.
//!
//! The encoding is the whole of the obfuscation. Every dword from `DanS` to the
//! last entry is XORed with `key`; the two words that let a reader find the
//! region are left alone. Decoding is symmetric, so one pass both finds and
//! decrypts.
//!
//! # Finding it
//!
//! A reader starts from `Rich` — it is in the clear and its position is recorded
//! nowhere — reads the key after it, and walks *backwards* a dword at a time,
//! XORing as it goes, until a dword decodes to `DanS`. The three encrypted zero
//! dwords that follow the marker are what make that walk safe: a chance dword
//! decodes to `DanS` with probability `2^-32`, and requiring the next three to
//! decode to zero as well takes it to `2^-128`. Nothing in a hostile file
//! satisfies that by accident.
//!
//! The distance from `DanS` to `Rich` is `16 + 8n` for `n` entries — four dwords
//! of header and two per entry — so the walk steps eight bytes at a time from
//! the smallest possible header and visits every position the marker can
//! legitimately be at, rather than every fourth one and then a divisibility
//! test.
//!
//! # `length`, and which bytes it counts
//!
//! [`RichSignature::length`] is the span that was decoded: `DanS` through the
//! last entry. It is deliberately **not** eight more than that. The `Rich`
//! marker and the key are the decoder rather than the payload — they are not
//! encrypted, they hold nothing about what built the file, and a structure
//! describing itself as including its own decryption key would be describing
//! something no rule can use. So `length` and `clear_data` describe the same
//! bytes, and the encoder's own arithmetic is `16 + 8n`.
//!
//! # What a rule asks
//!
//! ```text
//! pe.rich_signature.length >= 104 and pe.rich_signature.length <= 112
//! pe.rich_signature.toolid ( 147 , 30729 ) == 11
//! hash.md5 ( pe.rich_signature.clear_data ) == "06b2ec5892ac9ad566693b04cf427f3f"
//! ```
//!
//! A file with no Rich header — everything not linked by Microsoft's toolchain,
//! which includes most malware built with a cross-compiler, and everything whose
//! header a packer has stripped — has an empty one, and every member of an empty
//! one is zero or absent. That is not an error. "This file has no linker
//! fingerprint" is a fact a rule can be written about, and it is the fact that
//! most of this module's answers carry.

use crate::headers::dos_pe_offset;
use crate::pe::PeFile;
use crate::read::Reader;

/// The marker at the start of the decoded region, `DanS` as a little-endian
/// dword.
const DANS_MARKER: u32 = 0x536E_6144;

/// The marker at the end of the encrypted region, as the four bytes on disk.
const RICH_MARKER: &[u8; 4] = b"Rich";

/// The four dwords of header: the `DanS` marker and three zero dwords.
const HEADER_LEN: usize = 16;

/// The two dwords of one entry.
const ENTRY_LEN: usize = 8;

/// The eight bytes after the last entry: the `Rich` marker and the key.
const TRAILER_LEN: usize = 8;

/// How far past the DOS header the search for `Rich` will look.
///
/// The Rich header sits in the DOS stub, which is a few hundred bytes in every
/// real image — the stub's own `This program cannot be run in DOS mode` message
/// and the header together come to well under a kilobyte. Sixty-four kilobytes
/// is far past any stub and bounds three things at once: the byte scan for the
/// marker, the length of the backward walk, and therefore the size of the region
/// that can be decoded and allocated. At the very worst that is sixteen thousand
/// entries and sixty-four kilobytes of `clear_data`, which is nothing next to
/// the cost of having read the file in the first place — and it is a bound the
/// file cannot raise, because a file that claims its PE header starts four
/// gigabytes in does not get a four-gigabyte search.
const SEARCH_LIMIT: usize = 0x1_0000;

/// The Rich header of a file, decoded.
///
/// Empty for a file that has none, which is the common case and not an error.
#[derive(Debug, Clone, Default)]
pub struct RichSignature {
    /// Where the decoded region starts, as a file offset.
    offset: u64,
    /// The XOR key the region was encoded with, as the file stores it.
    key: u32,
    /// The decoded bytes: `DanS` through the last entry.
    clear_data: Vec<u8>,
    /// The `(compid, count)` pairs, in the order the file lists them.
    entries: Vec<(u32, u32)>,
}

impl RichSignature {
    /// Where the `DanS` marker is, as a file offset, or zero for a file with no
    /// Rich header.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// How many bytes the decoded region is — `DanS` through the last entry, and
    /// not the `Rich` marker or the key that follow it. See the module docs.
    pub fn length(&self) -> usize {
        self.clear_data.len()
    }

    /// The XOR key, or zero for a file with no Rich header.
    ///
    /// Zero is also a real key value, so nothing should use this to decide
    /// whether a header is present: [`is_empty`](Self::is_empty) is that
    /// question's answer.
    pub fn key(&self) -> u32 {
        self.key
    }

    /// The decoded region, as the bytes `hash.md5` is asked to hash.
    pub fn clear_data(&self) -> &[u8] {
        &self.clear_data
    }

    /// The `(compid, count)` pairs.
    ///
    /// The compid packs two numbers: the tool or product id in the high sixteen
    /// bits and the build number in the low sixteen. [`toolid`](Self::toolid) is
    /// the accessor that unpacks it.
    pub fn entries(&self) -> &[(u32, u32)] {
        &self.entries
    }

    /// Whether the file has a Rich header at all.
    pub fn is_empty(&self) -> bool {
        self.clear_data.is_empty()
    }

    /// How many times the entry for `(tool, version)` contributed to the file,
    /// or zero when there is no such entry.
    ///
    /// Zero and "no such entry" are the same answer because they mean the same
    /// thing to a rule: this file was not built that many times by that tool.
    /// The corpus compares the result with `>=`, `<=` and `==` and never tests
    /// for the entry's presence separately, which is what makes the two
    /// equivalent in use as well as in meaning.
    ///
    /// `version` is masked to sixteen bits rather than validated, because that
    /// is the field's width: a rule that wrote a larger number wrote one that
    /// cannot be an entry, and truncating it to the bits the format has is the
    /// same answer as any other way of saying "no such entry" — except that it
    /// could name a *different* entry, which is why the mask is here in the open
    /// rather than left to the shift.
    pub fn toolid(&self, tool: u32, version: u32) -> u32 {
        let wanted = (tool << 16) | (version & 0xffff);
        self.entries
            .iter()
            .find(|(compid, _)| *compid == wanted)
            .map_or(0, |(_, count)| *count)
    }
}

/// Read a file's Rich header.
///
/// Returns an empty one for any file without a well-formed header, which is
/// every file not linked by Microsoft's toolchain and every file whose header
/// has been stripped — deliberately, or by a packer. There is nothing to report
/// as an error: the header's absence is itself the fact.
pub fn read(pe: &PeFile<'_>) -> RichSignature {
    let empty = RichSignature::default();
    let data = pe.data();
    let reader = pe.reader();

    // The header lives before the PE header. `e_lfanew` is a number the file
    // chose, so the window is the smallest of it, the whole buffer and the
    // search limit — three independent reasons to stop, and the smallest one
    // wins. Reading it through the same accessor `PeFile::parse` used means the
    // bound is the offset that was actually validated, not a second reading of
    // the same field that could disagree with it.
    let Ok(lfanew) = dos_pe_offset(reader) else {
        return empty;
    };
    let limit = lfanew.min(data.len()).min(SEARCH_LIMIT);
    if limit < HEADER_LEN + TRAILER_LEN {
        return empty;
    }

    // Every occurrence of `Rich` is tried, in order, and the first that decodes
    // to a valid header wins. A file can contain those four bytes for reasons of
    // its own — a string in the stub, an unlucky instruction — and stopping at
    // the first one would report no header for a file that has one.
    let mut from = 0usize;
    while from + RICH_MARKER.len() <= limit {
        let Some(found) = data[from..limit]
            .windows(RICH_MARKER.len())
            .position(|w| w == RICH_MARKER)
        else {
            return empty;
        };
        let rich = from + found;
        from = rich + 1;
        if let Some(header) = decode(reader, rich) {
            return header;
        }
    }
    empty
}

/// Decode the header whose `Rich` marker is at `rich`, if one really is there.
///
/// `None` when the walk backwards does not find a `DanS` with the three zero
/// dwords that must follow it — the answer for the far likelier case that the
/// four bytes were a coincidence.
fn decode(reader: &Reader<'_>, rich: usize) -> Option<RichSignature> {
    let key = reader.u32(rich + 4).ok()?;
    // The marker is `16 + 8n` bytes before `Rich`, so stepping eight at a time
    // from the smallest possible header visits every position it can be at and
    // no others. `checked_sub` ends the walk at the start of the buffer rather
    // than wrapping around it.
    let mut dans = rich.checked_sub(HEADER_LEN)?;
    loop {
        if let Some(entries) = header_at(reader, dans, rich, key) {
            // The region is `dans` through the last entry, so undoing the
            // encryption is XORing the same key back over the same dwords. One
            // pass, and the only thing that differs between encoding and
            // decoding is which direction it runs.
            let mut clear_data = Vec::with_capacity(rich - dans);
            let mut at = dans;
            while at < rich {
                let word = reader.u32(at).ok()?;
                clear_data.extend_from_slice(&(word ^ key).to_le_bytes());
                at += 4;
            }
            return Some(RichSignature {
                offset: dans as u64,
                key,
                clear_data,
                entries,
            });
        }
        dans = dans.checked_sub(ENTRY_LEN)?;
    }
}

/// The entries of a header starting at `dans`, if one starts there.
///
/// This is the validity test the backward walk is built on, and it is checked in
/// the order that rejects a wrong position fastest: the marker first, then the
/// three zero dwords. A `dans` that is not the real one fails on one of the
/// first four dwords with overwhelming probability, so the walk is cheap even
/// though it reads four bytes at a time through the whole stub.
fn header_at(reader: &Reader<'_>, dans: usize, rich: usize, key: u32) -> Option<Vec<(u32, u32)>> {
    let word = |index: usize| reader.u32(dans + index * 4).ok().map(|w| w ^ key);
    if word(0)? != DANS_MARKER {
        return None;
    }
    // The three zero dwords. They are what makes the marker a marker rather than
    // a number that happens to be `0x536E6144`.
    for index in 1..=3 {
        if word(index)? != 0 {
            return None;
        }
    }

    // What is left between the header and the marker is the entries. The walk
    // steps by eight, so this divides exactly; the check is here because the
    // division is what the count is, and a caller that ever reached this
    // function from somewhere else would otherwise get a truncated count
    // silently.
    let span = rich.checked_sub(dans)?.checked_sub(HEADER_LEN)?;
    if span % ENTRY_LEN != 0 {
        return None;
    }
    let count = span / ENTRY_LEN;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let at = 4 + index * 2;
        entries.push((word(at)?, word(at + 1)?));
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{add_rich_header, minimal_pe32};
    use crate::PeFile;

    /// The `compid` for a tool and build, as the field packs them.
    fn compid(tool: u32, build: u32) -> u32 {
        (tool << 16) | build
    }

    /// Whether a file the parser accepted reports an empty Rich header.
    fn no_rich(image: &[u8]) -> bool {
        read(&PeFile::parse(image).expect("the fixture is a PE")).is_empty()
    }

    #[test]
    fn a_file_with_no_rich_header_has_an_empty_one() {
        let image = minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        let rich = read(&pe);
        assert!(rich.is_empty());
        assert_eq!(rich.length(), 0);
        assert_eq!(rich.offset(), 0);
        assert!(rich.entries().is_empty());
        assert!(rich.clear_data().is_empty());
        // Every count is zero, which is the answer a rule comparing against a
        // threshold wants from a file that has no such entry.
        assert_eq!(rich.toolid(147, 30729), 0);
    }

    #[test]
    fn an_image_that_is_not_a_pe_at_all_reports_nothing() {
        // `read` takes a parsed image, so this is really a statement about the
        // contract above it — but the empty case has to survive a buffer with no
        // `e_lfanew` to read, and the only way to reach it is a file that is not
        // a PE.
        // 0x3C is where `e_lfanew` is, so anything up to and including 0x40
        // bytes cannot hold one — and past that there is no PE to parse.
        for len in [0usize, 4, 0x3C, 0x40] {
            assert!(PeFile::parse(&vec![0u8; len]).is_err(), "{len}");
        }
    }

    #[test]
    fn the_decoded_region_begins_with_the_marker_and_three_zero_dwords() {
        // The format's own self-consistency check, and the assertion that pins
        // where the region starts: a decoder beginning one dword late or early
        // would produce a region whose first four dwords are not this.
        let mut image = minimal_pe32();
        add_rich_header(
            &mut image,
            &[(compid(147, 30729), 11), (compid(264, 24215), 16)],
        );
        let pe = PeFile::parse(&image).unwrap();
        let rich = read(&pe);

        assert!(!rich.is_empty());
        let clear = rich.clear_data();
        assert_eq!(&clear[0..4], b"DanS");
        assert_eq!(&clear[4..16], &[0u8; 12], "three zero dwords");
    }

    #[test]
    fn the_length_is_the_header_and_the_entries_and_not_the_trailer() {
        // `16 + 8n`. The two bytes the trailer would add if it were counted are
        // the difference this test exists to pin, and at the corpus's scale —
        // the rule at line 72045 bounds the member at `>= 104 and <= 112` —
        // `n` is eleven or twelve.
        assert_eq!(HEADER_LEN + 11 * ENTRY_LEN, 104, "the corpus's lower bound");
        assert_eq!(HEADER_LEN + 12 * ENTRY_LEN, 112, "and its upper one");
        for entries in 0..=5usize {
            let mut image = minimal_pe32();
            let pairs: Vec<(u32, u32)> = (0..entries)
                .map(|i| (compid(147 + i as u32, 30729), i as u32 + 1))
                .collect();
            add_rich_header(&mut image, &pairs);
            let pe = PeFile::parse(&image).unwrap();
            let rich = read(&pe);
            assert_eq!(rich.length(), HEADER_LEN + entries * ENTRY_LEN, "{entries}");
            assert_eq!(rich.length(), rich.clear_data().len());
            assert_eq!(rich.entries().len(), entries);
        }
    }

    #[test]
    fn the_entries_come_back_decoded_and_in_order() {
        let mut image = minimal_pe32();
        let pairs = [
            (compid(241, 40116), 7),
            (compid(147, 30729), 11),
            (compid(264, 24215), 16),
            (compid(1, 0), 3),
        ];
        add_rich_header(&mut image, &pairs);
        let pe = PeFile::parse(&image).unwrap();
        assert_eq!(read(&pe).entries(), &pairs);
    }

    #[test]
    fn a_toolid_is_the_count_of_the_entry_that_names_it() {
        // The lookup the corpus writes thirty-nine times, and the shape of the
        // arguments: the tool in the high half of the compid, the build in the
        // low half.
        let mut image = minimal_pe32();
        add_rich_header(
            &mut image,
            &[
                (compid(241, 40116), 7),
                (compid(147, 30729), 11),
                (compid(264, 24215), 16),
                (compid(1, 0), 3),
            ],
        );
        let pe = PeFile::parse(&image).unwrap();
        let rich = read(&pe);

        assert_eq!(rich.toolid(241, 40116), 7);
        assert_eq!(rich.toolid(147, 30729), 11);
        assert_eq!(rich.toolid(264, 24215), 16);
        // `toolid(1, 0)` — a build number of zero, which the corpus writes — must
        // not be confused with an absent entry.
        assert_eq!(rich.toolid(1, 0), 3);

        // The two halves are not interchangeable: asking for the build as the
        // tool finds nothing, and neither does the right tool with a wrong build.
        assert_eq!(rich.toolid(30729, 147), 0);
        assert_eq!(rich.toolid(147, 40116), 0);
        assert_eq!(rich.toolid(999, 40116), 0);
        assert_eq!(rich.toolid(241, 999), 0);
    }

    #[test]
    fn the_key_is_reported_and_the_region_really_was_decoded_with_it() {
        // A decoder that ignored the key would leave the region reading `DanS`
        // only when the key happened to be zero. The fixture writes a non-zero
        // one precisely so that this cannot pass by accident.
        let mut image = minimal_pe32();
        add_rich_header(&mut image, &[(compid(147, 30729), 11)]);
        let pe = PeFile::parse(&image).unwrap();
        let rich = read(&pe);
        assert_eq!(rich.key(), 0xA5A5_5A5A);
        assert_eq!(&rich.clear_data()[0..4], b"DanS");
        // And the bytes in the file are not those bytes, which is what makes the
        // line above a statement about decoding rather than about copying.
        let at = rich.offset() as usize;
        assert_ne!(&pe.data()[at..at + 4], b"DanS");
        assert_eq!(
            &pe.data()[at..at + 4],
            &(DANS_MARKER ^ rich.key()).to_le_bytes(),
            "the marker on disk is the marker XOR the key"
        );
    }

    #[test]
    fn four_bytes_that_say_rich_but_decode_to_nothing_are_not_a_header() {
        // A file can contain `Rich` for its own reasons. The three zero dwords
        // are what tells the two apart, and this fixture is a marker with a key
        // that decrypts nothing in particular before it.
        let mut image = minimal_pe32();
        for at in [0x40usize, 0x60] {
            image[at..at + 4].copy_from_slice(RICH_MARKER);
            image[at + 4..at + 8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        }
        assert!(no_rich(&image));
    }

    #[test]
    fn a_marker_whose_padding_is_not_zero_is_not_a_header() {
        // The other half of the validity test. A `DanS` with the right key but a
        // non-zero dword where the padding must be is a coincidence, not a
        // header, and accepting it would decode entries out of whatever follows.
        let mut image = minimal_pe32();
        let key = 0x0BAD_F00Du32;
        let dans = 0x40usize;
        let rich = dans + HEADER_LEN + ENTRY_LEN;
        let put = |image: &mut Vec<u8>, at: usize, word: u32| {
            image[at..at + 4].copy_from_slice(&(word ^ key).to_le_bytes());
        };
        put(&mut image, dans, DANS_MARKER);
        put(&mut image, dans + 4, 0);
        put(&mut image, dans + 8, 1);
        put(&mut image, dans + 12, 0);
        put(&mut image, dans + HEADER_LEN, compid(147, 30729));
        put(&mut image, dans + HEADER_LEN + 4, 11);
        image[rich..rich + 4].copy_from_slice(RICH_MARKER);
        image[rich + 4..rich + 8].copy_from_slice(&key.to_le_bytes());
        assert!(no_rich(&image));
    }

    #[test]
    fn a_file_with_two_markers_reads_the_one_that_decodes() {
        // The first `Rich` in the file belongs to something else, so the search
        // has to move past it rather than give up — and the second has to be
        // found without the first having been mistaken for a header.
        let mut image = minimal_pe32();
        let key = 0x0BAD_F00Du32;
        let dans = 0x48usize;
        let rich = dans + HEADER_LEN + ENTRY_LEN;
        // A decoy marker and key at the bottom of the gap, decoding to nothing.
        image[0x40..0x44].copy_from_slice(RICH_MARKER);
        image[0x44..0x48].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let put = |image: &mut Vec<u8>, at: usize, word: u32| {
            image[at..at + 4].copy_from_slice(&(word ^ key).to_le_bytes());
        };
        put(&mut image, dans, DANS_MARKER);
        for index in 1..=3 {
            put(&mut image, dans + index * 4, 0);
        }
        put(&mut image, dans + HEADER_LEN, compid(147, 30729));
        put(&mut image, dans + HEADER_LEN + 4, 11);
        image[rich..rich + 4].copy_from_slice(RICH_MARKER);
        image[rich + 4..rich + 8].copy_from_slice(&key.to_le_bytes());

        let pe = PeFile::parse(&image).unwrap();
        let found = read(&pe);
        assert!(!found.is_empty(), "the second marker must be tried");
        assert_eq!(found.offset(), dans as u64);
        assert_eq!(found.toolid(147, 30729), 11);
    }

    #[test]
    fn the_search_stops_where_the_structure_cannot_be() {
        // `e_lfanew` bounds the scan, because the header lives in the DOS stub
        // and nowhere else. A well-formed structure placed past the PE header —
        // in `.text`, say, where a packer would have to put it — is not found.
        // This is the bound that keeps the walk from reading a section's code as
        // a linker fingerprint and reporting a toolid for it.
        let mut image = minimal_pe32();
        image.resize(0x800, 0);
        let key = 0x0BAD_F00Du32;
        let dans = 0x300usize;
        let rich = dans + HEADER_LEN + ENTRY_LEN;
        let put = |image: &mut Vec<u8>, at: usize, word: u32| {
            image[at..at + 4].copy_from_slice(&(word ^ key).to_le_bytes());
        };
        put(&mut image, dans, DANS_MARKER);
        for index in 1..=3 {
            put(&mut image, dans + index * 4, 0);
        }
        put(&mut image, dans + HEADER_LEN, compid(147, 30729));
        put(&mut image, dans + HEADER_LEN + 4, 11);
        image[rich..rich + 4].copy_from_slice(RICH_MARKER);
        image[rich + 4..rich + 8].copy_from_slice(&key.to_le_bytes());

        // The structure is well-formed: it decodes, if the reader is pointed at
        // it directly.
        let pe = PeFile::parse(&image).unwrap();
        assert!(
            decode(pe.reader(), rich).is_some(),
            "the fixture must be a header the reader would accept"
        );
        assert!(
            read(&pe).is_empty(),
            "but it is past the PE header, so it is not this file's"
        );
    }

    #[test]
    fn the_walk_backwards_ends_at_the_start_of_the_buffer() {
        // A `Rich` marker near the beginning has no room for a header before it,
        // and the walk runs off the front. It must stop there rather than read
        // before the buffer or wrap around to its end.
        let mut image = minimal_pe32();
        image[0x40..0x44].copy_from_slice(RICH_MARKER);
        image[0x44..0x48].copy_from_slice(&0xA5A5_5A5Au32.to_le_bytes());
        assert!(no_rich(&image));
    }

    #[test]
    fn a_stub_with_no_marker_at_all_is_walked_once_and_refused() {
        // The ordinary case for a non-Microsoft binary, and the one that has to
        // be cheap: no marker, so no walk, so no decode.
        let mut image = minimal_pe32();
        image[0x40..0x80].fill(0xCC);
        assert!(no_rich(&image));
    }
}
