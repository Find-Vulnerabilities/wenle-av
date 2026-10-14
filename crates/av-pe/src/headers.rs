//! The DOS stub, the COFF file header, the optional header and the data
//! directories.
//!
//! The field names here are the format's own, because every one of them is
//! reachable from a rule as `pe.<something>` and a rule that says
//! `pe.number_of_sections` has to mean what the format's `NumberOfSections`
//! means. Where YARA's `pe` module exposes a field under a different name or
//! with a converted value, that conversion happens in [`crate::pe`], not here —
//! this module is the file, and the module is what rules are written against.

use crate::error::PeError;
use crate::read::Reader;

/// `MZ`.
const DOS_MAGIC: u16 = 0x5A4D;
/// `PE\0\0`.
const PE_MAGIC: u32 = 0x0000_4550;
/// `PE32` — a 32-bit optional header.
pub const OPTIONAL_MAGIC_PE32: u16 = 0x010B;
/// `PE32+` — a 64-bit optional header.
pub const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x020B;

/// Size of the DOS header up to and including `e_lfanew`.
const DOS_HEADER_LEN: usize = 64;

/// Number of data directory slots the format defines.
pub const DATA_DIRECTORY_COUNT: usize = 16;

/// Size of one data directory entry: an address and a size.
pub const DATA_DIRECTORY_ENTRY_LEN: usize = 8;

/// Offset of `CheckSum` inside the optional header.
///
/// The same number in PE32 and PE32+ — every field that differs between the two
/// widths sits in front of it — which is why nothing here branches on the
/// magic.
const CHECKSUM_AT: usize = 64;

/// Offset of the data directory array inside a PE32 optional header.
const DIRECTORIES_AT_PE32: usize = 96;
/// Offset of the data directory array inside a PE32+ optional header.
const DIRECTORIES_AT_PE32_PLUS: usize = 112;

/// Where data directory `index` sits, relative to the start of the optional
/// header.
///
/// Exported because the offset is not merely how this crate finds a directory's
/// *value*. Authenticode's digest is computed over the file with two fields
/// cut out of the header, and one of them is this array's security entry — so a
/// caller that has to reproduce the digest needs the address, not the contents.
pub const fn directory_entry_at(is_64: bool, index: usize) -> usize {
    let base = if is_64 {
        DIRECTORIES_AT_PE32_PLUS
    } else {
        DIRECTORIES_AT_PE32
    };
    base + index * DATA_DIRECTORY_ENTRY_LEN
}

/// Offset of `CheckSum`, relative to the start of the optional header.
///
/// See [`directory_entry_at`] for why this is exported rather than private.
pub const fn checksum_at() -> usize {
    CHECKSUM_AT
}

/// Offset of each directory in the data directory array, by index.
pub mod directory {
    /// The export table.
    pub const EXPORT: usize = 0;
    /// The import table.
    pub const IMPORT: usize = 1;
    /// The resource tree.
    pub const RESOURCE: usize = 2;
    /// The exception table.
    pub const EXCEPTION: usize = 3;
    /// The attribute certificate table — where Authenticode signatures live.
    ///
    /// Its `VirtualAddress` is a *file offset*, not an RVA, which is the one
    /// place in the format where that is true and the reason this is called out
    /// here rather than left to the reader of the spec.
    pub const SECURITY: usize = 4;
    /// Base relocations.
    pub const BASE_RELOCATION: usize = 5;
    /// The debug directory.
    pub const DEBUG: usize = 6;
    /// Architecture-specific data.
    pub const ARCHITECTURE: usize = 7;
    /// The global pointer register's RVA.
    pub const GLOBAL_PTR: usize = 8;
    /// Thread local storage.
    pub const TLS: usize = 9;
    /// The load configuration table.
    pub const LOAD_CONFIG: usize = 10;
    /// Bound imports.
    pub const BOUND_IMPORT: usize = 11;
    /// The import address table.
    pub const IAT: usize = 12;
    /// Delay-loaded imports.
    pub const DELAY_IMPORT: usize = 13;
    /// The CLR (managed) header — what makes a file .NET.
    pub const COM_DESCRIPTOR: usize = 14;
}

/// One entry of the data directory array.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataDirectory {
    /// The RVA of the table — except for [`directory::SECURITY`], where it is a
    /// file offset.
    pub virtual_address: u32,
    /// How many bytes the table occupies.
    pub size: u32,
}

impl DataDirectory {
    /// Whether the entry is present.
    ///
    /// Both fields zero is how the format spells "this directory is not in the
    /// file", and it is the common case for most of the sixteen. A directory
    /// with a size but no address, or the reverse, is malformed; treating it as
    /// absent is the reading that cannot produce a wild pointer.
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// The COFF file header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoffHeader {
    /// `IMAGE_FILE_MACHINE_*` — the target architecture, which is advisory and
    /// frequently wrong in malware.
    pub machine: u16,
    /// How many section table entries the file *claims*.
    ///
    /// Not how many there are. [`crate::sections::read_sections`] reads as many
    /// as the file actually holds, and `pe.number_of_sections` reports that
    /// count rather than this one.
    pub number_of_sections: u16,
    /// When the linker wrote the file, as a Unix timestamp.
    pub time_date_stamp: u32,
    /// File offset of the COFF symbol table, which is stripped in every
    /// production binary and therefore a common place to hide data.
    pub pointer_to_symbol_table: u32,
    /// Entries in the symbol table.
    pub number_of_symbols: u32,
    /// Length of the optional header, which is how the section table is found.
    ///
    /// "Optional" is a misnomer: it is mandatory in every image the loader will
    /// run, and this field is the only thing that says where the section table
    /// starts.
    pub size_of_optional_header: u16,
    /// `IMAGE_FILE_*` flags, among them `DLL`, `EXECUTABLE_IMAGE`, and the
    /// `RELOCS_STRIPPED` bit that marks a file as non-relocatable.
    pub characteristics: u16,
}

/// `IMAGE_FILE_DLL`.
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// `IMAGE_FILE_RELOCS_STRIPPED`.
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;

/// `IMAGE_FILE_EXECUTABLE_IMAGE`.
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;

/// The optional header, normalised across PE32 and PE32+.
///
/// The two layouts differ only in where `ImageBase` and the four stack and heap
/// sizes sit and how wide they are, so they are read once here into a form with
/// the difference already resolved. Every later reader then has one layout to
/// think about instead of two, which is what stops a 64-bit file from having
/// its image base read out of the middle of its entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalHeader {
    /// [`OPTIONAL_MAGIC_PE32`] or [`OPTIONAL_MAGIC_PE32_PLUS`].
    pub magic: u16,
    /// The linker's major version — `14` for every Visual Studio since 2015,
    /// and a value packers routinely forge.
    pub major_linker_version: u8,
    /// The linker's minor version.
    pub minor_linker_version: u8,
    /// Total size of the code sections, as a multiple of `file_alignment`.
    pub size_of_code: u32,
    /// Total size of the initialised data sections.
    pub size_of_initialized_data: u32,
    /// Total size of the uninitialised data sections.
    pub size_of_uninitialized_data: u32,
    /// The entry point as an RVA. [`crate::pe::PeFile::entry_point`] converts it.
    pub address_of_entry_point: u32,
    /// The RVA where the code sections begin.
    pub base_of_code: u32,
    /// The RVA where the data sections begin. Absent in PE32+, where it is zero
    /// rather than missing.
    pub base_of_data: u32,
    /// The address the image prefers to be loaded at.
    ///
    /// Zero in a DLL is not a bug: it means "anywhere", which is what an
    /// ASLR-aware linker emits.
    pub image_base: u64,
    /// The alignment of sections in memory — conventionally 0x1000.
    ///
    /// A value smaller than the page size is one of the oldest packer tells
    /// there is, because it means the file cannot be loaded as written.
    pub section_alignment: u32,
    /// The alignment of sections in the file — conventionally 0x200.
    pub file_alignment: u32,
    /// The minimum operating system version, major part.
    pub major_operating_system_version: u16,
    /// The minimum operating system version, minor part.
    pub minor_operating_system_version: u16,
    /// The image's own version, major part.
    pub major_image_version: u16,
    /// The image's own version, minor part.
    pub minor_image_version: u16,
    /// The minimum subsystem version, major part.
    pub major_subsystem_version: u16,
    /// The minimum subsystem version, minor part.
    pub minor_subsystem_version: u16,
    /// Reserved; must be zero. Non-zero in some packers, which is why it is
    /// read rather than skipped.
    pub win32_version_value: u32,
    /// The size the image occupies once loaded, in bytes.
    ///
    /// Compared against the sum of the sections' virtual sizes it exposes a file
    /// whose header does not describe its own contents.
    pub size_of_image: u32,
    /// The size of everything before the first section — DOS stub, headers and
    /// section table — rounded up to `file_alignment`.
    pub size_of_headers: u32,
    /// The image's checksum, which is zero in any file not signed by Microsoft.
    pub checksum: u32,
    /// `IMAGE_SUBSYSTEM_*` — GUI (2) or console (3) for an executable.
    pub subsystem: u16,
    /// `IMAGE_DLLCHARACTERISTICS_*`, among them `DYNAMIC_BASE` (ASLR) and
    /// `NX_COMPAT` (DEP), whose absence is a weak packer tell.
    pub dll_characteristics: u16,
    /// Stack reservation, in bytes. A value far from the 1 MB default is a
    /// linker that is not the one the file claims.
    pub size_of_stack_reserve: u64,
    /// Stack commitment, in bytes.
    pub size_of_stack_commit: u64,
    /// Heap reservation, in bytes.
    pub size_of_heap_reserve: u64,
    /// Heap commitment, in bytes.
    pub size_of_heap_commit: u64,
    /// Reserved; must be zero.
    pub loader_flags: u32,
    /// How many of the sixteen data directory slots the header actually
    /// declares.
    ///
    /// The bound on the array, not a copy of its length — see
    /// [`OptionalHeader::directory`].
    pub number_of_rva_and_sizes: u32,
    /// The sixteen directories, in the format's own order.
    ///
    /// Read through [`OptionalHeader::directory`] rather than directly, so that
    /// the declared count is respected.
    pub data_directories: [DataDirectory; DATA_DIRECTORY_COUNT],
}

impl OptionalHeader {
    /// Whether this is a 64-bit image.
    pub fn is_64(&self) -> bool {
        self.magic == OPTIONAL_MAGIC_PE32_PLUS
    }

    /// The directory at `index`, or an empty one if the header does not declare
    /// that many.
    ///
    /// `NumberOfRvaAndSizes` is routinely smaller than sixteen and is
    /// occasionally a lie. Reading past the declared count would take bytes
    /// that belong to whatever follows the header, so the declared count is the
    /// bound and a slot beyond it reads as absent.
    pub fn directory(&self, index: usize) -> DataDirectory {
        if index >= DATA_DIRECTORY_COUNT || index as u32 >= self.number_of_rva_and_sizes {
            return DataDirectory::default();
        }
        self.data_directories[index]
    }
}

/// Where the PE signature and headers begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Offset of `PE\0\0`.
    pub pe_offset: usize,
    /// Offset of the COFF header, 4 bytes after `pe_offset`.
    pub coff_offset: usize,
    /// Offset of the optional header, 24 bytes after `pe_offset`.
    pub optional_offset: usize,
    /// Offset of the section table, which follows the optional header — whose
    /// length the COFF header declares, and which is therefore the only way to
    /// find it.
    pub sections_offset: usize,
}

/// The DOS header's only field this crate needs.
///
/// `e_lfanew` is the offset of the PE signature. Everything before it is the
/// DOS stub, kept in real files so that a DOS loader prints "This program
/// cannot be run in DOS mode" rather than executing whatever follows.
pub fn dos_pe_offset(reader: &Reader<'_>) -> Result<usize, PeError> {
    if reader.len() < DOS_HEADER_LEN {
        return Err(PeError::Truncated {
            offset: 0,
            wanted: DOS_HEADER_LEN,
            available: reader.len(),
        });
    }
    if reader.u16(0)? != DOS_MAGIC {
        return Err(PeError::NoDosMagic);
    }
    let lfanew = reader.u32(0x3C)?;
    let pe_offset = lfanew as usize;
    if reader.u32(pe_offset).ok() != Some(PE_MAGIC) {
        return Err(PeError::NoPeSignature { at: lfanew });
    }
    Ok(pe_offset)
}

/// Read the COFF header at `pe_offset + 4`.
pub fn coff_header(reader: &Reader<'_>, pe_offset: usize) -> Result<CoffHeader, PeError> {
    let at = pe_offset + 4;
    Ok(CoffHeader {
        machine: reader.u16(at)?,
        number_of_sections: reader.u16(at + 2)?,
        time_date_stamp: reader.u32(at + 4)?,
        pointer_to_symbol_table: reader.u32(at + 8)?,
        number_of_symbols: reader.u32(at + 12)?,
        size_of_optional_header: reader.u16(at + 16)?,
        characteristics: reader.u16(at + 18)?,
    })
}

/// Read the optional header at `pe_offset + 24`.
///
/// The magic is read first and decides the rest of the layout. A magic that is
/// neither PE32 nor PE32+ is refused rather than guessed at: the fields after
/// it differ enough between the two that assuming one would read an image base
/// out of an entry point.
pub fn optional_header(reader: &Reader<'_>, at: usize) -> Result<OptionalHeader, PeError> {
    let magic = reader.u16(at)?;
    let is_64 = match magic {
        OPTIONAL_MAGIC_PE32 => false,
        OPTIONAL_MAGIC_PE32_PLUS => true,
        other => return Err(PeError::BadOptionalMagic { magic: other }),
    };

    // The fields up to `BaseOfCode` are laid out identically, and so is
    // everything from `SectionAlignment` on. Only `ImageBase` and the four
    // sizes in between move, which is why they are the only ones branched on.
    let base = if is_64 { at + 24 } else { at + 28 };
    let alignment = at + 32;
    let tail = at + 32;

    let mut data_directories = [DataDirectory::default(); DATA_DIRECTORY_COUNT];
    let directories_at = at
        + if is_64 {
            DIRECTORIES_AT_PE32_PLUS
        } else {
            DIRECTORIES_AT_PE32
        };
    // Filled only as far as the file actually goes. A header truncated in the
    // middle of the directory array is a file with fewer directories, not a
    // file that failed to parse — the directories before the cut are real and
    // useful, and the ones after it are the ones that are missing.
    for (index, slot) in data_directories.iter_mut().enumerate() {
        let entry = directories_at + index * DATA_DIRECTORY_ENTRY_LEN;
        let Ok(address) = reader.u32(entry) else {
            break;
        };
        let Ok(size) = reader.u32(entry + 4) else {
            break;
        };
        *slot = DataDirectory {
            virtual_address: address,
            size,
        };
    }

    Ok(OptionalHeader {
        magic,
        major_linker_version: reader.u8(at + 2)?,
        minor_linker_version: reader.u8(at + 3)?,
        size_of_code: reader.u32(at + 4)?,
        size_of_initialized_data: reader.u32(at + 8)?,
        size_of_uninitialized_data: reader.u32(at + 12)?,
        address_of_entry_point: reader.u32(at + 16)?,
        base_of_code: reader.u32(at + 20)?,
        base_of_data: if is_64 { 0 } else { reader.u32(at + 24)? },
        image_base: if is_64 {
            reader.u64(base)?
        } else {
            u64::from(reader.u32(base)?)
        },
        section_alignment: reader.u32(alignment)?,
        file_alignment: reader.u32(alignment + 4)?,
        major_operating_system_version: reader.u16(tail + 8)?,
        minor_operating_system_version: reader.u16(tail + 10)?,
        major_image_version: reader.u16(tail + 12)?,
        minor_image_version: reader.u16(tail + 14)?,
        major_subsystem_version: reader.u16(tail + 16)?,
        minor_subsystem_version: reader.u16(tail + 18)?,
        win32_version_value: reader.u32(tail + 20)?,
        size_of_image: reader.u32(tail + 24)?,
        size_of_headers: reader.u32(tail + 28)?,
        checksum: reader.u32(at + CHECKSUM_AT)?,
        subsystem: reader.u16(tail + 36)?,
        dll_characteristics: reader.u16(tail + 38)?,
        size_of_stack_reserve: if is_64 {
            reader.u64(tail + 40)?
        } else {
            u64::from(reader.u32(tail + 40)?)
        },
        size_of_stack_commit: if is_64 {
            reader.u64(tail + 48)?
        } else {
            u64::from(reader.u32(tail + 44)?)
        },
        size_of_heap_reserve: if is_64 {
            reader.u64(tail + 56)?
        } else {
            u64::from(reader.u32(tail + 48)?)
        },
        size_of_heap_commit: if is_64 {
            reader.u64(tail + 64)?
        } else {
            u64::from(reader.u32(tail + 52)?)
        },
        loader_flags: reader.u32(if is_64 { tail + 72 } else { tail + 56 })?,
        number_of_rva_and_sizes: reader.u32(if is_64 { tail + 76 } else { tail + 60 })?,
        data_directories,
    })
}

/// Find the three offsets the rest of the parse needs.
///
/// The section table is located from `SizeOfOptionalHeader` rather than from a
/// constant, because a file is allowed to declare a longer optional header than
/// this crate knows about and the sections are still where it says they are.
pub fn layout(reader: &Reader<'_>, pe_offset: usize, coff: &CoffHeader) -> Result<Layout, PeError> {
    let coff_offset = pe_offset + 4;
    let optional_offset = coff_offset + 20;
    let sections_offset = optional_offset
        .checked_add(coff.size_of_optional_header as usize)
        .ok_or(PeError::Truncated {
            offset: optional_offset,
            wanted: coff.size_of_optional_header as usize,
            available: reader.len(),
        })?;
    Ok(Layout {
        pe_offset,
        coff_offset,
        optional_offset,
        sections_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{minimal_pe32, minimal_pe64};

    #[test]
    fn a_dos_header_without_a_pe_signature_is_refused() {
        let mut data = vec![0u8; 128];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let r = Reader::new(&data);
        assert!(matches!(
            dos_pe_offset(&r),
            Err(PeError::NoPeSignature { at: 0x40 })
        ));
    }

    #[test]
    fn a_file_that_does_not_start_with_mz_is_refused() {
        let r = Reader::new(&[0u8; 128]);
        assert!(matches!(dos_pe_offset(&r), Err(PeError::NoDosMagic)));
    }

    #[test]
    fn a_dos_header_shorter_than_its_own_length_is_refused() {
        // `e_lfanew` is at 0x3C, so a 32-byte file cannot have one.
        let r = Reader::new(b"MZ");
        assert!(matches!(
            dos_pe_offset(&r),
            Err(PeError::Truncated { wanted: 64, .. })
        ));
    }

    #[test]
    fn pe32_fields_are_read_from_their_own_offsets() {
        let data = minimal_pe32();
        let r = Reader::new(&data);
        let pe = dos_pe_offset(&r).unwrap();
        assert_eq!(pe, 0x80);
        let coff = coff_header(&r, pe).unwrap();
        assert_eq!(coff.machine, 0x014C);
        assert_eq!(coff.number_of_sections, 2);
        assert_eq!(coff.time_date_stamp, 0x6000_0000);
        assert_eq!(coff.characteristics & IMAGE_FILE_DLL, 0);

        let opt = optional_header(&r, pe + 24).unwrap();
        assert!(!opt.is_64());
        assert_eq!(opt.magic, OPTIONAL_MAGIC_PE32);
        assert_eq!(opt.address_of_entry_point, 0x1000);
        assert_eq!(opt.image_base, 0x0040_0000);
        assert_eq!(opt.subsystem, 2);
        assert_eq!(opt.directory(directory::EXPORT).virtual_address, 0x2000);
        assert!(!opt.directory(directory::IMPORT).is_present());
    }

    #[test]
    fn pe32_plus_reads_a_wide_image_base_from_the_shorter_offset() {
        // The two layouts differ by exactly the fields between `BaseOfCode` and
        // `SectionAlignment`. Reading a 64-bit file with the 32-bit layout is
        // the mistake this test exists to catch, and it would show up as an
        // image base of `0x400000` — the low half of the real one.
        let data = minimal_pe64();
        let r = Reader::new(&data);
        let pe = dos_pe_offset(&r).unwrap();
        let opt = optional_header(&r, pe + 24).unwrap();
        assert!(opt.is_64());
        assert_eq!(opt.image_base, 0x0000_0001_4000_0000);
        assert_eq!(opt.address_of_entry_point, 0x1000);
        // The directories moved with it.
        assert_eq!(opt.directory(directory::EXPORT).virtual_address, 0x2000);
    }

    #[test]
    fn an_unknown_optional_magic_is_refused_rather_than_guessed() {
        let mut data = minimal_pe32();
        let opt = 0x80 + 4 + 20;
        data[opt..opt + 2].copy_from_slice(&0x0107u16.to_le_bytes());
        let r = Reader::new(&data);
        assert!(matches!(
            optional_header(&r, opt),
            Err(PeError::BadOptionalMagic { magic: 0x0107 })
        ));
    }

    #[test]
    fn a_directory_beyond_the_declared_count_is_absent() {
        // `NumberOfRvaAndSizes` bounds the array. A file that declares sixteen
        // but is truncated, or declares four and has sixteen, must not have the
        // bytes past its own declaration read as directories.
        let mut data = minimal_pe32();
        let opt = 0x80 + 4 + 20;
        data[opt + 92..opt + 96].copy_from_slice(&4u32.to_le_bytes());
        let r = Reader::new(&data);
        let header = optional_header(&r, opt).unwrap();
        assert!(header.directory(0).is_present(), "declared");
        assert!(
            !header.directory(5).is_present(),
            "past the declared count, so absent even though the bytes are there"
        );
    }

    #[test]
    fn the_section_table_is_found_from_the_declared_optional_header_size() {
        // A file may declare a longer optional header than this crate knows
        // about. Trusting a constant instead of the field would put the section
        // table in the middle of the optional header.
        let data = minimal_pe32();
        let r = Reader::new(&data);
        let pe = dos_pe_offset(&r).unwrap();
        let coff = coff_header(&r, pe).unwrap();
        let l = layout(&r, pe, &coff).unwrap();
        assert_eq!(l.sections_offset, 0x80 + 4 + 20 + 224);
        assert_eq!(l.sections_offset, 0x178);
    }
}
