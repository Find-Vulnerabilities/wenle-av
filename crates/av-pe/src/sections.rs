//! The section table, and the RVA-to-offset mapping built from it.
//!
//! The section table is what turns a relative virtual address — the only kind
//! of address the optional header and every directory entry use — into a place
//! in the file. Almost everything interesting in a PE is found that way, so a
//! wrong mapping here does not produce a slightly wrong answer; it produces
//! reads from an unrelated part of the file.

use crate::headers::CoffHeader;
use crate::read::Reader;

/// Size of one section table entry.
pub const SECTION_ENTRY_LEN: usize = 40;

/// `IMAGE_SCN_MEM_EXECUTE`.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_READ`.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// `IMAGE_SCN_MEM_WRITE`.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// `IMAGE_SCN_CNT_CODE`.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// `IMAGE_SCN_CNT_INITIALIZED_DATA`.
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;

/// One entry of the section table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The name, as up to eight bytes with everything from the first NUL on
    /// dropped.
    ///
    /// Kept as bytes rather than a `String` because the format does not require
    /// them to be text — long names live in the string table behind a `/`
    /// prefix — and a rule comparing `pe.sections[0].name == ".text"` must not
    /// be defeated by one that is not UTF-8. [`Section::name`] is the lossy
    /// view for rules that treat it as a string.
    pub raw_name: [u8; 8],
    /// How many bytes the section occupies once loaded.
    ///
    /// May exceed `size_of_raw_data`, and the difference is the zero-filled tail
    /// that has no bytes in the file. May also be zero, which some linkers emit;
    /// see [`Section::contains_rva`].
    pub virtual_size: u32,
    /// The RVA the section loads at.
    pub virtual_address: u32,
    /// How many bytes of the section are in the file.
    pub size_of_raw_data: u32,
    /// Where those bytes start, as a file offset.
    pub pointer_to_raw_data: u32,
    /// File offset of the base relocations for this section.
    pub pointer_to_relocations: u32,
    /// File offset of the line numbers, which only ever appear in
    /// debug-built images.
    pub pointer_to_linenumbers: u32,
    /// How many base relocations there are.
    pub number_of_relocations: u16,
    /// How many line number entries there are.
    pub number_of_linenumbers: u16,
    /// `IMAGE_SCN_*` flags: contents, and whether the section is executable,
    /// readable or writable.
    pub characteristics: u32,
}

impl Section {
    /// The name with trailing NULs removed.
    ///
    /// Lossy: a name that is not valid UTF-8 comes back with replacement
    /// characters. That is the right direction for a rule, which is doing a
    /// string comparison and would otherwise have to handle a byte string it
    /// has no syntax for.
    pub fn name(&self) -> String {
        String::from_utf8_lossy(self.name_bytes()).into_owned()
    }

    /// The section's name as the eight bytes the header holds, up to the first
    /// NUL and no further.
    ///
    /// This is what a rule compares against. `pe.sections[i].name == ".text"`
    /// is a comparison of bytes, and the `String` above goes through
    /// `from_utf8_lossy`, which turns any byte that is not UTF-8 into `U+FFFD`.
    /// For a section name — eight bytes chosen by whoever linked the file — that
    /// is a real possibility, and a lossy round trip would make a name that
    /// genuinely equals the rule's literal compare as unequal. A rule that
    /// misses a file is a false negative, which is the direction this crate
    /// takes seriously.
    pub fn name_bytes(&self) -> &[u8] {
        // The eight bytes are NUL-padded, not NUL-terminated: a name that fills
        // all eight has no terminator at all, which is why the search is for a
        // position and the fallback is the whole field.
        let end = self
            .raw_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.raw_name.len());
        &self.raw_name[..end]
    }

    /// The end of the section's data in the file.
    ///
    /// Saturating rather than wrapping: both operands come from the file, and a
    /// crafted pair that overflowed would otherwise produce an end *before* the
    /// start, which every `contains` test downstream would then read as an
    /// empty range instead of an out-of-bounds one.
    pub fn raw_end(&self) -> u64 {
        u64::from(self.pointer_to_raw_data).saturating_add(u64::from(self.size_of_raw_data))
    }

    /// Whether the section can be executed.
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Whether the section is writable.
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// Whether `rva` falls inside this section.
    ///
    /// The bound is `virtual_size` where it is set and `size_of_raw_data` where
    /// it is not: linkers are supposed to set `VirtualSize`, but some leave it
    /// zero, and treating a zero as "this section is empty" would lose every
    /// section of such a file.
    pub fn contains_rva(&self, rva: u32) -> bool {
        if rva < self.virtual_address {
            return false;
        }
        let span = if self.virtual_size != 0 {
            self.virtual_size
        } else {
            self.size_of_raw_data
        };
        // `rva - virtual_address` cannot underflow: the check above proved it
        // is not negative.
        rva - self.virtual_address < span
    }
}

/// Read the section table.
///
/// A section whose entry runs past the end of the file is skipped rather than
/// failing the whole parse, and the walk stops at the first one that does. The
/// count is the file's own claim and is routinely wrong — sometimes wildly — so
/// demanding all of it would be a way for a two-byte edit to make the scanner
/// report nothing about a sample.
pub fn read_sections(
    reader: &Reader<'_>,
    sections_offset: usize,
    coff: &CoffHeader,
) -> Vec<Section> {
    let mut out = Vec::with_capacity(coff.number_of_sections.min(96) as usize);
    for index in 0..u64::from(coff.number_of_sections) {
        let Ok(entry) = reader.item(sections_offset, index, SECTION_ENTRY_LEN as u64) else {
            break;
        };
        let entry = Reader::new(entry);
        // Every field is within the 40 bytes just read, so none of these can
        // fail; the `unwrap_or_default` is a statement of that rather than an
        // error path, and it keeps a short entry from being a panic.
        let mut raw_name = [0u8; 8];
        if let Ok(name) = entry.slice(0, 8) {
            raw_name.copy_from_slice(name);
        }
        out.push(Section {
            raw_name,
            virtual_size: entry.u32(8).unwrap_or_default(),
            virtual_address: entry.u32(12).unwrap_or_default(),
            size_of_raw_data: entry.u32(16).unwrap_or_default(),
            pointer_to_raw_data: entry.u32(20).unwrap_or_default(),
            pointer_to_relocations: entry.u32(24).unwrap_or_default(),
            pointer_to_linenumbers: entry.u32(28).unwrap_or_default(),
            number_of_relocations: entry.u16(32).unwrap_or_default(),
            number_of_linenumbers: entry.u16(34).unwrap_or_default(),
            characteristics: entry.u32(36).unwrap_or_default(),
        });
    }
    out
}

/// Turn a relative virtual address into an offset in the file.
///
/// `None` when the address is in no section. The headers are not a section, and
/// a rule asking for the raw offset of an RVA inside them gets `None` — YARA's
/// own `pe` module reports the address unchanged in that case, which is a
/// deliberate quirk of its `rva_to_offset` and is reproduced by
/// [`crate::pe::PeFile::rva_to_offset`] rather than here.
pub fn rva_to_offset(sections: &[Section], rva: u32) -> Option<u64> {
    for section in sections {
        if section.contains_rva(rva) {
            let delta = rva - section.virtual_address;
            // Only the part of the section that is actually in the file can be
            // pointed at. A section's virtual size is routinely larger than its
            // raw size — that is where uninitialised data lives — and an offset
            // computed into that tail would name a byte past the section's own
            // data.
            if delta >= section.size_of_raw_data {
                return None;
            }
            return Some(u64::from(section.pointer_to_raw_data) + u64::from(delta));
        }
    }
    None
}

/// The section an RVA falls in, and how far into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHit {
    /// Which entry of the section table, counting from zero.
    pub index: usize,
    /// The offset from the start of the section's virtual space.
    pub delta: u32,
}

/// Which section holds `rva`.
///
/// Unlike [`rva_to_offset`] this answers for RVAs in a section's uninitialised
/// tail too, because `pe.section_index` and YARA both ask the question about
/// the address rather than about the file.
pub fn section_for_rva(sections: &[Section], rva: u32) -> Option<SectionHit> {
    sections.iter().enumerate().find_map(|(index, section)| {
        section.contains_rva(rva).then(|| SectionHit {
            index,
            delta: rva - section.virtual_address,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(name: &str, va: u32, vsize: u32, raw: u32, rawsize: u32) -> Section {
        let mut raw_name = [0u8; 8];
        let bytes = name.as_bytes();
        raw_name[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
        Section {
            raw_name,
            virtual_size: vsize,
            virtual_address: va,
            size_of_raw_data: rawsize,
            pointer_to_raw_data: raw,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        }
    }

    #[test]
    fn a_name_is_read_up_to_its_first_nul() {
        let s = section(".text", 0x1000, 0x800, 0x200, 0x400);
        assert_eq!(s.name(), ".text");
    }

    #[test]
    fn a_name_that_fills_all_eight_bytes_has_no_terminator() {
        let s = section(".longnam", 0, 0, 0, 0);
        assert_eq!(s.name(), ".longnam");
    }

    #[test]
    fn a_name_that_is_not_text_still_compares() {
        let mut s = section("", 0, 0, 0, 0);
        s.raw_name = [0xFF, 0xFE, b'x', 0, 0, 0, 0, 0];
        // Lossy, but present — a rule sees something rather than nothing.
        assert!(s.name().ends_with('x'));
        assert_eq!(s.raw_name[0], 0xFF, "the raw bytes are still there");
    }

    #[test]
    fn an_rva_maps_into_the_section_that_holds_it() {
        let sections = vec![
            section(".text", 0x1000, 0x800, 0x200, 0x400),
            section(".data", 0x2000, 0x200, 0x600, 0x200),
        ];
        assert_eq!(rva_to_offset(&sections, 0x1000), Some(0x200));
        assert_eq!(rva_to_offset(&sections, 0x1004), Some(0x204));
        assert_eq!(rva_to_offset(&sections, 0x2000), Some(0x600));
        assert_eq!(rva_to_offset(&sections, 0x0FFF), None, "before any section");
        assert_eq!(rva_to_offset(&sections, 0x3000), None, "after them all");
    }

    #[test]
    fn an_rva_in_a_sections_uninitialised_tail_is_not_in_the_file() {
        // `virtual_size` past `size_of_raw_data` is where zero-filled data
        // lives. There is no byte in the file to point at, and returning the
        // offset it *would* have had would read the next section's data.
        let sections = vec![section(".data", 0x2000, 0x1000, 0x600, 0x200)];
        assert_eq!(rva_to_offset(&sections, 0x2000), Some(0x600));
        assert_eq!(
            rva_to_offset(&sections, 0x21FF),
            Some(0x7FF),
            "last raw byte"
        );
        assert_eq!(rva_to_offset(&sections, 0x2200), None, "into the tail");
    }

    #[test]
    fn a_section_with_no_virtual_size_is_measured_by_its_raw_size() {
        // Some linkers leave `VirtualSize` zero. Reading that as an empty
        // section would lose every section of such a file.
        let sections = vec![section(".text", 0x1000, 0, 0x200, 0x400)];
        assert_eq!(rva_to_offset(&sections, 0x1000), Some(0x200));
        assert_eq!(rva_to_offset(&sections, 0x13FF), Some(0x5FF));
        assert_eq!(rva_to_offset(&sections, 0x1400), None);
    }

    #[test]
    fn section_index_answers_for_the_uninitialised_tail_too() {
        // `pe.section_index(rva)` is a question about the address, not about
        // whether the file has a byte there.
        let sections = vec![section(".data", 0x2000, 0x1000, 0x600, 0x200)];
        assert_eq!(section_for_rva(&sections, 0x2400).map(|h| h.index), Some(0));
        assert_eq!(
            section_for_rva(&sections, 0x2400).map(|h| h.delta),
            Some(0x400)
        );
        assert_eq!(section_for_rva(&sections, 0x1000), None);
        assert_eq!(
            rva_to_offset(&sections, 0x2400),
            None,
            "the same address is not in the file"
        );
    }

    #[test]
    fn a_section_whose_raw_end_would_overflow_saturates() {
        let s = section(".text", 0, 0, u32::MAX, u32::MAX);
        assert_eq!(s.raw_end(), u64::from(u32::MAX) * 2);
        assert!(s.raw_end() > u64::from(s.pointer_to_raw_data));
    }
}
