//! The parsed file, and the values rules ask it for.
//!
//! # Where the conversions live
//!
//! [`crate::headers`] and [`crate::sections`] are the file: offsets, counts and
//! addresses exactly as the format records them. This module is the *module* —
//! the answer to `pe.<something>` — and the two are not the same thing. An
//! entry point is an RVA in the header and a file offset in a rule; a
//! timestamp is four bytes of `time_t` in the header and an integer in a rule.
//! Doing those conversions here rather than there is what lets a rule written
//! against YARA keep meaning what it meant.

use crate::error::PeError;
use crate::headers::{self, directory, CoffHeader, DataDirectory, OptionalHeader, IMAGE_FILE_DLL};
use crate::read::Reader;
use crate::sections::{self, Section};

/// Where the optional header starts, relative to the `PE\0\0` signature: the
/// four signature bytes and the twenty-byte COFF header.
const OPTIONAL_HEADER_AT: usize = 24;

/// A PE file, parsed as far as its headers and section table.
///
/// Borrows the buffer rather than owning it: the scanner maps a file once and
/// every layer below reads from that same mapping, so a parse that copied would
/// double the memory cost of a scan for no gain.
#[derive(Debug, Clone)]
pub struct PeFile<'a> {
    reader: Reader<'a>,
    /// Offset of the `PE\0\0` signature.
    pub pe_offset: usize,
    /// The COFF file header.
    pub coff: CoffHeader,
    /// The optional header, normalised across PE32 and PE32+.
    pub optional: OptionalHeader,
    /// The section table, as far as the file actually holds it.
    pub sections: Vec<Section>,
}

impl<'a> PeFile<'a> {
    /// Parse a buffer as a PE, or say why it is not one.
    ///
    /// Only the headers and the section table are read. Everything behind a
    /// data directory — imports, exports, resources, the signature — is parsed
    /// on demand by its own accessor, because most files have most of them
    /// absent and a scan that parsed all of them for every file would pay for
    /// the ones no rule asks about.
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        let reader = Reader::new(data);
        let pe_offset = headers::dos_pe_offset(&reader)?;
        let coff = headers::coff_header(&reader, pe_offset)?;
        let layout = headers::layout(&reader, pe_offset, &coff)?;
        let optional = headers::optional_header(&reader, layout.optional_offset)?;
        let sections = sections::read_sections(&reader, layout.sections_offset, &coff);
        Ok(Self {
            reader,
            pe_offset,
            coff,
            optional,
            sections,
        })
    }

    /// The whole buffer.
    pub fn data(&self) -> &'a [u8] {
        self.reader.data()
    }

    /// The bounds-checked reader over the whole buffer.
    ///
    /// Exposed for the readers that live in their own module — the import and
    /// export tables — so that each of them takes the same checked reads rather
    /// than reaching for the buffer directly. `Reader` is `Copy`, so handing it
    /// out costs nothing.
    pub fn reader(&self) -> &Reader<'a> {
        &self.reader
    }

    // -- identity ----------------------------------------------------------

    /// Always true for a parsed file, and present anyway because rules test it.
    ///
    /// `pe.is_pe` is how a rule says "and this is a PE at all" without relying
    /// on the file-type gate having run first, which matters for rules applied
    /// to memory or to a buffer with no name.
    pub fn is_pe(&self) -> bool {
        true
    }

    /// Whether the file is a library rather than an executable.
    pub fn is_dll(&self) -> bool {
        self.coff.characteristics & IMAGE_FILE_DLL != 0
    }

    /// Whether the optional header is the 32-bit layout.
    pub fn is_32bit(&self) -> bool {
        !self.optional.is_64()
    }

    /// Whether the optional header is the 64-bit layout.
    pub fn is_64bit(&self) -> bool {
        self.optional.is_64()
    }

    // -- header fields -----------------------------------------------------

    /// `IMAGE_FILE_MACHINE_*`. Advisory: a 32-bit payload labelled as ARM still
    /// runs.
    pub fn machine(&self) -> u32 {
        u32::from(self.coff.machine)
    }

    /// `TimeDateStamp`, which is a Unix timestamp the linker wrote.
    ///
    /// Reported as-is rather than as a date: it is frequently zero, frequently
    /// a lie, and rules compare it against epoch seconds.
    pub fn timestamp(&self) -> u32 {
        self.coff.time_date_stamp
    }

    /// `IMAGE_FILE_*` flags, for the rules that test them by bit.
    pub fn characteristics(&self) -> u32 {
        u32::from(self.coff.characteristics)
    }

    /// `IMAGE_SUBSYSTEM_*`.
    pub fn subsystem(&self) -> u32 {
        u32::from(self.optional.subsystem)
    }

    /// `IMAGE_DLLCHARACTERISTICS_*` — ASLR, DEP, and their absence.
    pub fn dll_characteristics(&self) -> u32 {
        u32::from(self.optional.dll_characteristics)
    }

    /// The entry point as a file offset.
    ///
    /// YARA's `pe.entry_point` is documented as the raw offset, matching the
    /// `entrypoint` keyword, and that is what this returns — through
    /// [`PeFile::rva_to_offset`], so it inherits the same fallback for an entry
    /// point outside every section.
    pub fn entry_point(&self) -> u64 {
        self.rva_to_offset(self.optional.address_of_entry_point)
    }

    /// `AddressOfEntryPoint` unconverted.
    ///
    /// YARA added this in 4.1 because the conversion above loses the original,
    /// and a rule that wants to compare against a section's virtual address
    /// needs the RVA. Both are exposed for the same reason.
    pub fn entry_point_raw(&self) -> u32 {
        self.optional.address_of_entry_point
    }

    /// The address the image prefers to load at.
    pub fn image_base(&self) -> u64 {
        self.optional.image_base
    }

    /// The size the image occupies once loaded.
    pub fn size_of_image(&self) -> u32 {
        self.optional.size_of_image
    }

    /// The size of everything before the first section.
    pub fn size_of_headers(&self) -> u32 {
        self.optional.size_of_headers
    }

    /// The image's checksum — zero in everything not signed by Microsoft.
    pub fn checksum(&self) -> u32 {
        self.optional.checksum
    }

    /// Section alignment in memory. Below 0x1000 is a packer tell.
    pub fn section_alignment(&self) -> u32 {
        self.optional.section_alignment
    }

    /// Section alignment in the file.
    pub fn file_alignment(&self) -> u32 {
        self.optional.file_alignment
    }

    /// How many data directories the header declares.
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        self.optional.number_of_rva_and_sizes
    }

    /// The RVA where the code sections begin.
    pub fn base_of_code(&self) -> u32 {
        self.optional.base_of_code
    }

    /// The RVA where the data sections begin; zero in a PE32+ file.
    pub fn base_of_data(&self) -> u32 {
        self.optional.base_of_data
    }

    /// Total size of the code sections.
    pub fn size_of_code(&self) -> u32 {
        self.optional.size_of_code
    }

    /// Total size of the initialised data sections.
    pub fn size_of_initialized_data(&self) -> u32 {
        self.optional.size_of_initialized_data
    }

    /// Total size of the uninitialised data sections.
    pub fn size_of_uninitialized_data(&self) -> u32 {
        self.optional.size_of_uninitialized_data
    }

    /// Stack reservation, in bytes.
    pub fn size_of_stack_reserve(&self) -> u64 {
        self.optional.size_of_stack_reserve
    }

    /// Stack commitment, in bytes.
    pub fn size_of_stack_commit(&self) -> u64 {
        self.optional.size_of_stack_commit
    }

    /// Heap reservation, in bytes.
    pub fn size_of_heap_reserve(&self) -> u64 {
        self.optional.size_of_heap_reserve
    }

    /// Heap commitment, in bytes.
    pub fn size_of_heap_commit(&self) -> u64 {
        self.optional.size_of_heap_commit
    }

    /// The linker version's major half.
    ///
    /// The four version pairs below are **two members each**, not one packed
    /// integer. A rule reads `pe.linker_version.major`; a rule reading a packed
    /// `pe.linker_version` would be a rule written against some other engine.
    ///
    /// The widths are the format's own and are not uniform: the linker version
    /// is two bytes, the other three are two words each. Widening the linker
    /// version to match would invite a caller to pack the pair back together,
    /// which is the mistake these accessors exist to prevent.
    pub fn linker_version_major(&self) -> u8 {
        self.optional.major_linker_version
    }

    /// The linker version's minor half.
    pub fn linker_version_minor(&self) -> u8 {
        self.optional.minor_linker_version
    }

    /// The minimum OS version's major half.
    pub fn os_version_major(&self) -> u16 {
        self.optional.major_operating_system_version
    }

    /// The minimum OS version's minor half.
    pub fn os_version_minor(&self) -> u16 {
        self.optional.minor_operating_system_version
    }

    /// The image version's major half.
    pub fn image_version_major(&self) -> u16 {
        self.optional.major_image_version
    }

    /// The image version's minor half.
    pub fn image_version_minor(&self) -> u16 {
        self.optional.minor_image_version
    }

    /// The minimum subsystem version's major half.
    pub fn subsystem_version_major(&self) -> u16 {
        self.optional.major_subsystem_version
    }

    /// The minimum subsystem version's minor half.
    pub fn subsystem_version_minor(&self) -> u16 {
        self.optional.minor_subsystem_version
    }

    // -- the header fields with no conversion ---------------------------------

    /// The optional header's magic, which is what tells PE32 from PE32+.
    pub fn opthdr_magic(&self) -> u16 {
        self.optional.magic
    }

    /// File offset of the COFF symbol table.
    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.coff.pointer_to_symbol_table
    }

    /// Entries in the COFF symbol table.
    pub fn number_of_symbols(&self) -> u32 {
        self.coff.number_of_symbols
    }

    /// The length the COFF header claims for the optional header.
    pub fn size_of_optional_header(&self) -> u16 {
        self.coff.size_of_optional_header
    }

    /// The loader flags, which no linker sets and some packers use.
    pub fn loader_flags(&self) -> u32 {
        self.optional.loader_flags
    }

    /// `Win32VersionValue`, reserved and expected to be zero.
    pub fn win32_version_value(&self) -> u32 {
        self.optional.win32_version_value
    }

    // -- overlay --------------------------------------------------------------

    /// Data appended after the last section: `(offset, size)`.
    ///
    /// Both are zero when there is no overlay, and both are zero for a file
    /// whose sections are all empty — which is YARA's rule and is deliberately
    /// not the arithmetic answer. "The overlay starts at 0 and is the whole
    /// file" is true of a file with no sections and useless to a rule; it would
    /// also make every such file look like it carried a payload.
    ///
    /// The attribute certificate table is *not* excluded from this, even though
    /// it sits outside the sections: a signed file therefore has an overlay, and
    /// that is what YARA reports too.
    pub fn overlay(&self) -> Overlay {
        let end = self
            .sections
            .iter()
            .map(Section::raw_end)
            .max()
            .unwrap_or(0);
        let file_size = self.reader.len() as u64;
        if end != 0 && file_size > end {
            Overlay {
                offset: end,
                size: file_size - end,
            }
        } else {
            Overlay { offset: 0, size: 0 }
        }
    }

    // -- sections ----------------------------------------------------------

    /// How many sections were read, which is not the count the header claims.
    ///
    /// The claim is often wrong; this is the number of them that exist.
    pub fn number_of_sections(&self) -> u32 {
        self.sections.len() as u32
    }

    /// The section at `index`, or `None` past the end of the table.
    ///
    /// An index is a number a rule computed, so out of range is an ordinary
    /// answer rather than a fault.
    pub fn section(&self, index: usize) -> Option<&Section> {
        self.sections.get(index)
    }

    // -- data directories --------------------------------------------------

    /// The directory at `index`, empty if the header does not declare it.
    pub fn data_directory(&self, index: usize) -> DataDirectory {
        self.optional.directory(index)
    }

    /// The attribute certificate table: where Authenticode signatures live.
    ///
    /// Its address is a file offset rather than an RVA, so it is looked up
    /// directly instead of through the section table.
    pub fn security_directory(&self) -> DataDirectory {
        self.optional.directory(directory::SECURITY)
    }

    /// The bytes the security directory points at.
    pub fn security_directory_data(&self) -> Result<&'a [u8], PeError> {
        let entry = self.security_directory();
        if !entry.is_present() {
            return Err(PeError::Absent {
                what: "attribute certificate table",
            });
        }
        self.reader
            .slice(entry.virtual_address as usize, entry.size as usize)
    }

    // -- where the digest's two holes are ----------------------------------
    //
    // These two are a pair and exist for one caller. Authenticode's file digest
    // is computed over the image with `CheckSum` and the security directory
    // entry cut out of the header, so a catalog lookup — which is a lookup by
    // that digest — cannot be done without knowing where the two fields are.
    //
    // They give an offset rather than a value because that is the whole point:
    // the *value* of each field is in the digest's way, and reading it is the
    // one thing the computation must not do.
    //
    // Neither is bounds-checked against the buffer. A header too short to hold
    // the field is a file whose digest cannot be computed, and the caller that
    // cares is the one holding the slice — checking here as well would put the
    // same length test in two places and let them disagree.

    /// The file offset of the optional header's `CheckSum` field.
    ///
    /// The same offset in PE32 and PE32+, because every field whose width
    /// differs between the two sits in front of it.
    pub fn checksum_field_offset(&self) -> usize {
        self.pe_offset + OPTIONAL_HEADER_AT + headers::checksum_at()
    }

    /// The file offset of the `IMAGE_DIRECTORY_ENTRY_SECURITY` entry, whose
    /// `VirtualAddress` is the file offset of the attribute certificate table.
    pub fn security_directory_entry_offset(&self) -> usize {
        self.pe_offset
            + OPTIONAL_HEADER_AT
            + headers::directory_entry_at(self.optional.is_64(), directory::SECURITY)
    }

    // -- addresses ---------------------------------------------------------

    /// An RVA as a file offset, in the manner of YARA's `pe` module.
    ///
    /// # The fallback
    ///
    /// An RVA that falls in no section is returned *unchanged*. That is not an
    /// oversight — it is what YARA does, and rules depend on it: `pe.entry_point`
    /// for a file whose entry point is inside the headers then equals the RVA,
    /// which is at least a stable number, where returning nothing would make
    /// every comparison against it false and silently lose the rule.
    ///
    /// [`sections::rva_to_offset`] is the version without the quirk, and is
    /// what a caller that needs to know whether the address is really in the
    /// file should use.
    pub fn rva_to_offset(&self, rva: u32) -> u64 {
        sections::rva_to_offset(&self.sections, rva).unwrap_or(u64::from(rva))
    }

    /// The inverse of [`PeFile::rva_to_offset`], for a file offset in a section.
    pub fn offset_to_rva(&self, offset: u64) -> Option<u32> {
        for section in &self.sections {
            let start = u64::from(section.pointer_to_raw_data);
            let end = section.raw_end();
            if offset >= start && offset < end {
                let delta = offset - start;
                // Both fit in `u32` because they came out of `u32` fields.
                let delta = u32::try_from(delta).ok()?;
                return section.virtual_address.checked_add(delta);
            }
        }
        None
    }

    /// The bytes of a section, as they are in the file.
    pub fn section_data(&self, index: usize) -> Option<&'a [u8]> {
        let section = self.sections.get(index)?;
        self.reader
            .slice(
                section.pointer_to_raw_data as usize,
                section.size_of_raw_data as usize,
            )
            .ok()
    }

    /// Which section holds a file offset.
    ///
    /// `pe.section_index(offset)` in a rule. YARA accepts a name as well as an
    /// offset; that form is handled by the caller, which is where the string is
    /// known.
    pub fn section_index_of_offset(&self, offset: u64) -> Option<usize> {
        self.sections.iter().position(|section| {
            offset >= u64::from(section.pointer_to_raw_data) && offset < section.raw_end()
        })
    }

    /// Which section holds an RVA — `pe.section_index(rva)`.
    pub fn section_index_of_rva(&self, rva: u32) -> Option<usize> {
        sections::section_for_rva(&self.sections, rva).map(|hit| hit.index)
    }

    /// The index of the section with this name.
    ///
    /// Compared against the raw eight bytes with trailing NULs dropped, not
    /// against the lossy string: a name that is not valid UTF-8 must still be
    /// findable by a rule that spells its bytes some other way.
    pub fn section_index_of_name(&self, name: impl AsRef<[u8]>) -> Option<usize> {
        let name = name.as_ref();
        self.sections
            .iter()
            .position(|section| section.name_bytes() == name)
    }
}

/// Data appended after the last section, as [`PeFile::overlay`] reports it.
///
/// Both fields are zero together or neither is: there is no such thing as an
/// overlay of size zero at a meaningful offset, and a rule that tests one field
/// should not have to test the other to know whether it is looking at a real
/// answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overlay {
    /// Where the overlay starts, as a file offset.
    pub offset: u64,
    /// How many bytes follow it to the end of the file.
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::OPTIONAL_MAGIC_PE32;
    use crate::testing::{minimal_pe32, minimal_pe64};

    #[test]
    fn a_minimal_image_reports_its_own_headers() {
        let data = minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        assert!(pe.is_pe());
        assert!(!pe.is_dll());
        assert!(pe.is_32bit());
        assert!(!pe.is_64bit());
        assert_eq!(pe.machine(), 0x014C);
        assert_eq!(pe.timestamp(), 0x6000_0000);
        assert_eq!(pe.subsystem(), 2);
        assert_eq!(pe.number_of_sections(), 2);
        assert_eq!(pe.image_base(), 0x0040_0000);
        assert_eq!(pe.size_of_image(), 0x3000);
        assert_eq!(pe.linker_version_major(), 14);
        assert_eq!(pe.linker_version_minor(), 0);
        assert_eq!(pe.opthdr_magic(), OPTIONAL_MAGIC_PE32);
        assert_eq!(pe.size_of_optional_header(), 224);
    }

    #[test]
    fn the_overlay_starts_after_the_last_section_and_is_empty_when_there_is_none() {
        // The fixture is 0x400 bytes and `.text` ends at 0x200 + 0x400 = 0x600,
        // which is past the end of the buffer — so there is no overlay, and the
        // answer is a pair of zeros rather than a negative size.
        let mut data = minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.overlay(), Overlay { offset: 0, size: 0 });

        // Extend the file past where `.data` ends (0x600 + 0x200 = 0x800) and
        // the tail becomes an overlay. The highest section is `.data`, not
        // `.text`, which is what the `max` is for.
        data.resize(0x900, 0xAA);
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(
            pe.overlay(),
            Overlay {
                offset: 0x800,
                size: 0x100
            }
        );
    }

    #[test]
    fn a_file_whose_sections_are_all_empty_has_no_overlay() {
        // The arithmetic answer would be "the overlay is the whole file", which
        // is true and useless — every headerless blob would look like it carried
        // a payload. YARA reports zeros, and so does this.
        let mut data = minimal_pe32();
        let sec = 0x80 + 4 + 20 + 224;
        for entry in [sec, sec + 40] {
            data[entry + 16..entry + 20].copy_from_slice(&0u32.to_le_bytes());
            data[entry + 20..entry + 24].copy_from_slice(&0u32.to_le_bytes());
        }
        data.resize(0x800, 0xAA);
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.overlay(), Overlay { offset: 0, size: 0 });
    }

    #[test]
    fn the_entry_point_is_reported_as_a_file_offset() {
        // RVA 0x1000 is the first byte of `.text`, which the section table puts
        // at file offset 0x200.
        let data = minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.entry_point_raw(), 0x1000, "the header's own value");
        assert_eq!(pe.entry_point(), 0x200, "converted for the rule");
    }

    #[test]
    fn an_entry_point_outside_every_section_comes_back_unchanged() {
        // YARA's fallback, kept because rules rely on it. The honest answer is
        // available too, and this test pins the difference so that neither can
        // change without the other being noticed.
        let mut data = minimal_pe32();
        let opt = 0x80 + 4 + 20;
        data[opt + 16..opt + 20].copy_from_slice(&0x99u32.to_le_bytes());
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(sections::rva_to_offset(&pe.sections, 0x99), None);
        assert_eq!(pe.rva_to_offset(0x99), 0x99);
        assert_eq!(pe.entry_point(), 0x99);
    }

    #[test]
    fn sections_are_read_with_their_names_and_addresses() {
        let data = minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        let text = pe.section(0).unwrap();
        assert_eq!(text.name(), ".text");
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.virtual_size, 0x800);
        assert_eq!(text.pointer_to_raw_data, 0x200);
        assert_eq!(text.size_of_raw_data, 0x400);
        assert_eq!(pe.section(1).unwrap().name(), ".data");
        assert!(pe.section(2).is_none());
    }

    #[test]
    fn a_section_name_can_be_looked_up_by_index() {
        let data = minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.section_index_of_name(".data"), Some(1));
        assert_eq!(pe.section_index_of_name(".text"), Some(0));
        assert_eq!(pe.section_index_of_name(".rsrc"), None);
    }

    #[test]
    fn data_directories_are_exposed_by_index() {
        let data = minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.data_directory(directory::EXPORT).virtual_address, 0x2000);
        assert_eq!(pe.data_directory(directory::EXPORT).size, 0x100);
        assert!(!pe.data_directory(directory::IMPORT).is_present());
    }

    #[test]
    fn the_security_directory_is_a_file_offset_not_an_rva() {
        // Every other directory address is an RVA and has to be mapped through
        // the section table first. This one is not, and mapping it would put the
        // signature somewhere else entirely.
        //
        // The value is chosen so that the two readings *disagree*: 0x1200 as an
        // RVA is inside `.text` and maps to file offset 0x400, so a reader that
        // mapped it would read the wrong bytes. An address below 0x1000 would
        // prove nothing, because YARA's fallback returns an unmapped RVA
        // unchanged and the two readings would then coincide.
        let mut data = minimal_pe32();
        data.resize(0x1400, 0);
        let opt = 0x80 + 4 + 20;
        let security = opt + 96 + directory::SECURITY * 8;
        data[security..security + 4].copy_from_slice(&0x1200u32.to_le_bytes());
        data[security + 4..security + 8].copy_from_slice(&8u32.to_le_bytes());
        data[0x1200..0x1208].copy_from_slice(b"certdata");

        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.security_directory().virtual_address, 0x1200);
        assert_eq!(pe.security_directory_data().unwrap(), b"certdata");
        assert_eq!(pe.rva_to_offset(0x1200), 0x400, "the reading that is wrong");
    }

    #[test]
    fn a_file_without_a_signature_says_so_rather_than_failing() {
        let data = minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        let error = pe.security_directory_data().unwrap_err();
        assert!(error.is_absence(), "{error}");
    }

    #[test]
    fn a_truncated_section_table_yields_the_sections_that_are_there() {
        // The header claims two sections; the file has room for one. Reporting
        // none would lose a detection, so the one that is present is kept.
        let full = minimal_pe32();
        let cut = 0x178 + 40 + 8;
        let data = &full[..cut];
        let pe = PeFile::parse(data).unwrap();
        assert_eq!(pe.number_of_sections(), 1);
        assert_eq!(pe.section(0).unwrap().name(), ".text");
    }

    #[test]
    fn a_file_that_is_not_a_pe_is_refused() {
        assert!(PeFile::parse(b"not a PE file at all, just some text").is_err());
        assert!(PeFile::parse(&[]).is_err());
    }

    #[test]
    fn a_64_bit_image_reports_itself_as_one() {
        let data = minimal_pe64();
        let pe = PeFile::parse(&data).unwrap();
        assert!(pe.is_64bit());
        assert!(!pe.is_32bit());
        assert_eq!(pe.image_base(), 0x0000_0001_4000_0000);
        assert_eq!(pe.number_of_sections(), 1);
    }

    #[test]
    fn a_file_offset_maps_back_to_its_rva() {
        let data = minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.offset_to_rva(0x200), Some(0x1000));
        assert_eq!(pe.offset_to_rva(0x5FF), Some(0x13FF));
        assert_eq!(pe.offset_to_rva(0x100), None, "in the headers");
        // The round trip holds for every byte of both sections.
        for section in &pe.sections {
            for delta in [0u32, 1, section.size_of_raw_data / 2] {
                let offset = u64::from(section.pointer_to_raw_data) + u64::from(delta);
                assert_eq!(
                    pe.offset_to_rva(offset),
                    Some(section.virtual_address + delta)
                );
                assert_eq!(pe.rva_to_offset(section.virtual_address + delta), offset);
            }
        }
    }
}
