//! The export table: which symbols a DLL offers the loader.
//!
//! # What a rule asks
//!
//! ```text
//! pe.number_of_exports == 1 and pe.exports ( "WaitPrompt" )
//! pe.number_of_exports == 2 and pe.exports ( "DllRegisterServer" )
//! ```
//!
//! # The two numbers an export directory holds, and which one a rule means
//!
//! An export directory carries two counts that are not the same:
//!
//! - `NumberOfFunctions`, the size of the export address table — one entry per
//!   exported *address*, indexed by ordinal.
//! - `NumberOfNames`, the size of the name pointer table — one entry per
//!   exported *name*.
//!
//! They differ whenever a DLL exports something by ordinal only, which real
//! libraries do. A rule that says `pe.number_of_exports == 1 and
//! pe.exports("Main")` means "this DLL does one thing and it is called Main",
//! and the honest answer to "how many things does it export" is the address
//! table.
//!
//! The corpus is consistent with that reading and not with the other: the rule
//! at line 170585 pairs `pe.exports ( "Init" )` with `pe.number_of_exports == 2`,
//! which a count of names could not produce on a DLL exporting exactly what the
//! rule names. So `number_of_exports` answers with `NumberOfFunctions`, and
//! [`Exports::name_count`] is the other number for anything that wants it.
//!
//! # Forwarders
//!
//! An export address table entry is not an address: it is an RVA, and when that
//! RVA falls inside the export directory itself the entry is a *forwarder* — a
//! string naming another module and symbol, `NTDLL.RtlAllocateHeap`. Forwarded
//! exports are counted like any other and are not followed, because a rule asks
//! what a DLL exports and not what those exports resolve to. Following one would
//! mean reading a second file to answer a question about this one.

use crate::headers::directory;
use crate::pe::PeFile;
use crate::read::Reader;

/// How much of the export directory this reader needs.
///
/// The fields it reads are `Base` at 16, `NumberOfFunctions` at 20,
/// `NumberOfNames` at 24, `AddressOfFunctions` at 28, `AddressOfNames` at 32 and
/// `AddressOfNameOrdinals` at 36, so the directory has to reach 40 bytes. The
/// check is made once, up front, so that a directory too short to hold them is
/// refused once rather than six times in six different places.
const DIRECTORY_MIN_LEN: usize = 40;

/// Offset of `Base` — the ordinal the first address table entry has.
const ORDINAL_BASE_AT: usize = 16;
/// Offset of `NumberOfFunctions`.
const NUMBER_OF_FUNCTIONS_AT: usize = 20;
/// Offset of `NumberOfNames`.
const NUMBER_OF_NAMES_AT: usize = 24;
/// Offset of `AddressOfFunctions` — the export address table.
const ADDRESS_OF_FUNCTIONS_AT: usize = 28;
/// Offset of `AddressOfNames` — the name pointer table.
const ADDRESS_OF_NAMES_AT: usize = 32;
/// Offset of `AddressOfNameOrdinals` — the index into the address table each
/// name belongs to.
const ADDRESS_OF_NAME_ORDINALS_AT: usize = 36;

/// The longest export name that will be read.
///
/// Real names are short — the longest in the corpus's own literals is a mangled
/// C++ name of 24 characters — and the bound is what stops a name pointer aimed
/// at a region of non-zero bytes from reading to the end of the mapping.
const MAX_NAME: usize = 512;

/// The most names that will be walked.
///
/// `NumberOfNames` comes out of the file and is used to reach into it. A
/// hundred thousand exported names is far past any real library and bounds the
/// walk independently of the file's own claim.
const MAX_NAMES: usize = 100_000;

/// The most address table entries that will be walked.
///
/// The same bound as [`MAX_NAMES`] and for the same reason: `NumberOfFunctions`
/// is a number the file chose. It differs from the name count in that
/// `pe.number_of_exports` reports it *as declared* — a rule comparing it against
/// a literal is comparing against the file's claim, which is the point of the
/// member — while [`ExportDetail`]s are only produced for the entries that are
/// really there. A file claiming four billion functions therefore answers
/// `pe.number_of_exports == 4000000000` truthfully and yields no details.
const MAX_FUNCTIONS: usize = 100_000;

/// One entry of the export address table, which is one element of a rule's
/// `pe.export_details`.
///
/// # Why the address table and not the name table
///
/// The two tables have different lengths whenever a DLL exports something by
/// ordinal only, and a rule can tell which one it is walking. The corpus settles
/// it: a rule iterates `for all i in (0 .. pe.number_of_exports - 1)` and reads
/// `pe.export_details[i].name`, and `pe.number_of_exports` is the address table.
/// Were the array the name table, that loop would read past its end on a file
/// with fewer names than functions — which is exactly the file it was written
/// for.
///
/// An entry with no name is therefore a real entry with `name` absent, not a
/// missing entry. That is the distinction the `Option`s carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDetail<'a> {
    ordinal: u32,
    offset: u64,
    name: Option<&'a [u8]>,
    forward_name: Option<&'a [u8]>,
}

impl<'a> ExportDetail<'a> {
    /// The ordinal the loader knows this export by: the table index plus the
    /// directory's `Base`.
    ///
    /// Not the table index, which is what a reader that skipped `Base` would
    /// report. Real libraries export from ordinal 1, so the two differ by one on
    /// almost every file that has exports at all.
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Where the exported code is, as a **file offset**.
    ///
    /// A file offset and not an RVA, matching `pe.resources[i].offset`: a rule
    /// reads bytes at it — `$c in (export.offset .. export.offset + 100)` is the
    /// corpus's shape — and an RVA would name a different byte whenever the
    /// sections move.
    ///
    /// A `u64` because that is what the reader produces and what a rule's
    /// integer is. Narrowing it to `u32` here would be a silent truncation of a
    /// value the file chose, and the one file it could matter on is a file whose
    /// export address is nonsense.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The export's name, or `None` when it is exported by ordinal alone.
    pub fn name(&self) -> Option<&'a [u8]> {
        self.name
    }

    /// The `Module.Symbol` this export forwards to, or `None` when it is code
    /// in this file.
    pub fn forward_name(&self) -> Option<&'a [u8]> {
        self.forward_name
    }
}

/// The export table of a file.
///
/// Holds the names as borrowed bytes plus the two counts, which is everything
/// the members a rule can read are derived from — and, separately, the address
/// table entries the `export_details` members are read from. The two are kept
/// apart rather than derived from one another because they are genuinely two
/// tables: [`Exports::names`] is the name table in the file's order, which is
/// what `pe.exports("x")` searches, and [`Exports::details`] is the address
/// table in ordinal order, which is what a loop walks.
#[derive(Debug, Clone)]
pub struct Exports<'a> {
    names: Vec<&'a [u8]>,
    functions: usize,
    details: Vec<ExportDetail<'a>>,
}

impl<'a> Exports<'a> {
    /// The exported names, in the order the name pointer table lists them.
    ///
    /// The order is the file's, not sorted: DER's canonical ordering does not
    /// apply to a PE, and a reader that sorted would be inventing one.
    pub fn names(&self) -> &[&'a [u8]] {
        &self.names
    }

    /// How many addresses the export address table holds.
    ///
    /// This is what `pe.number_of_exports` answers. See the module docs for why
    /// it is this count and not the number of names.
    pub fn function_count(&self) -> usize {
        self.functions
    }

    /// How many of the exported addresses also have a name.
    pub fn name_count(&self) -> usize {
        self.names.len()
    }

    /// The address table, in ordinal order, as far as it could be read.
    ///
    /// Shorter than [`Exports::function_count`] when the file declares more
    /// entries than `MAX_FUNCTIONS`, or when the table runs off the end of the
    /// file — the declared count is the file's claim and this is what is really
    /// there.
    pub fn details(&self) -> &[ExportDetail<'a>] {
        &self.details
    }

    /// Whether the file exports `name`.
    ///
    /// Case-sensitive, like the symbol half of [`crate::imports`]: an exported
    /// name is an exact byte string that the loader matches exactly, so a rule
    /// naming `Main` does not name `main`. Answering otherwise would be a
    /// detection that fires on a file the rule was not written about.
    pub fn has_name(&self, name: impl AsRef<[u8]>) -> bool {
        self.names.contains(&name.as_ref())
    }
}

/// Read a file's export table.
///
/// A file with no export directory, or with one that points nowhere, yields an
/// empty table rather than an error. Most executables export nothing — only DLLs
/// and a handful of system binaries do — so making the ordinary case an error
/// would make the error the common path.
pub fn read<'a>(pe: &PeFile<'a>) -> Exports<'a> {
    let empty = Exports {
        names: Vec::new(),
        functions: 0,
        details: Vec::new(),
    };
    let entry = pe.data_directory(directory::EXPORT);
    if !entry.is_present() {
        return empty;
    }
    let reader = pe.reader();
    let Ok(base) = usize::try_from(pe.rva_to_offset(entry.virtual_address)) else {
        return empty;
    };
    if reader.slice(base, DIRECTORY_MIN_LEN).is_err() {
        return empty;
    }

    let mut exports = Exports {
        names: Vec::new(),
        functions: 0,
        details: Vec::new(),
    };
    if let Some(count) = read_u32(reader, pe, entry.virtual_address, NUMBER_OF_FUNCTIONS_AT) {
        exports.functions = count as usize;
    }
    let Some(name_count) = read_u32(reader, pe, entry.virtual_address, NUMBER_OF_NAMES_AT) else {
        return exports;
    };
    let ordinal_base = read_u32(reader, pe, entry.virtual_address, ORDINAL_BASE_AT).unwrap_or(0);

    // The name table first, because the address table walk wants the name each
    // entry has and that mapping is the name table's whole purpose. The names
    // are collected in the file's order as well, since `pe.exports("x")` is
    // asked about the name table and not about the address table.
    let mut names_by_index: Vec<Option<&'a [u8]>> = Vec::new();
    if let Some(names_rva) = read_u32(reader, pe, entry.virtual_address, ADDRESS_OF_NAMES_AT) {
        let ordinals_rva = read_u32(
            reader,
            pe,
            entry.virtual_address,
            ADDRESS_OF_NAME_ORDINALS_AT,
        )
        .unwrap_or(0);
        let limit = (name_count as usize).min(MAX_NAMES);
        names_by_index = vec![None; limit.min(exports.functions)];
        for index in 0..limit {
            // The name pointer table is an array of `u32` RVAs, so the index
            // scales by four. A table that runs off the end of the file ends the
            // walk rather than failing it: the names that were there are still
            // real.
            let Some(offset) = u32::try_from(index.saturating_mul(4)).ok() else {
                break;
            };
            let Some(name_rva) = names_rva.checked_add(offset) else {
                break;
            };
            let Some(name_rva) = read_u32(reader, pe, name_rva, 0) else {
                break;
            };
            if name_rva == 0 {
                continue;
            }
            let Some(file_offset) = usize::try_from(pe.rva_to_offset(name_rva)).ok() else {
                continue;
            };
            // Clamped to what is left in the buffer, for the same reason as the
            // import reader: a name near the end of a small file has fewer bytes
            // after it than the cap, and demanding the full window would turn a
            // short file into a file with no exports.
            let available = reader.len().saturating_sub(file_offset).min(MAX_NAME);
            if available == 0 {
                continue;
            }
            let Ok(name) = reader.cstr(file_offset, available) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            exports.names.push(name);
            // Which address table entry this name belongs to. The ordinal table
            // is an array of `u16`s parallel to the name table, and a name whose
            // index is past the address table is a name for a function that is
            // not exported — kept in `names`, where `pe.exports` can still find
            // it, and not attached to an entry that does not exist.
            if ordinals_rva == 0 || names_by_index.is_empty() {
                continue;
            }
            let Some(at) = u32::try_from(index.saturating_mul(2)).ok() else {
                break;
            };
            let Some(ordinal_rva) = ordinals_rva.checked_add(at) else {
                break;
            };
            let Some(slot) = read_u16(reader, pe, ordinal_rva) else {
                break;
            };
            if let Some(cell) = names_by_index.get_mut(usize::from(slot)) {
                *cell = Some(name);
            }
        }
    }

    // The address table, which is what `pe.export_details` is an array of. The
    // entries are read whether or not there is a name table at all, because a
    // DLL that exports by ordinal alone still has addresses and still has
    // details; it is only the names that are missing.
    let functions_rva = read_u32(reader, pe, entry.virtual_address, ADDRESS_OF_FUNCTIONS_AT);
    if let Some(functions_rva) = functions_rva.filter(|rva| *rva != 0) {
        let limit = exports.functions.min(MAX_FUNCTIONS);
        for index in 0..limit {
            let Some(at) = u32::try_from(index.saturating_mul(4)).ok() else {
                break;
            };
            let Some(slot_rva) = functions_rva.checked_add(at) else {
                break;
            };
            let Some(address) = read_u32(reader, pe, slot_rva, 0) else {
                break;
            };
            let ordinal = ordinal_base.wrapping_add(index as u32);
            let offset = pe.rva_to_offset(address);
            let forward_name = forwarder(reader, pe, entry, address);
            exports.details.push(ExportDetail {
                ordinal,
                offset,
                name: names_by_index.get(index).copied().flatten(),
                forward_name,
            });
        }
    }
    exports
}

/// The `Module.Symbol` string at `address`, when `address` is a forwarder.
///
/// An address table entry is not an address: it is an RVA, and when that RVA
/// falls inside the export directory the entry names a string in the directory
/// rather than naming code. See [`is_forwarder`] for the test itself.
fn forwarder<'a>(
    reader: &Reader<'a>,
    pe: &PeFile<'a>,
    entry: crate::headers::DataDirectory,
    address: u32,
) -> Option<&'a [u8]> {
    if !is_forwarder(address, entry.virtual_address, entry.size) {
        return None;
    }
    let at = usize::try_from(pe.rva_to_offset(address)).ok()?;
    let available = reader.len().saturating_sub(at).min(MAX_NAME);
    if available == 0 {
        return None;
    }
    let name = reader.cstr(at, available).ok()?;
    // An empty string is not a forwarder name. `contains ""` is true of it, so
    // answering with one would make `foreach ... forward_name contains "x"`
    // depend on a string that is not there — the same reason the rule engine
    // answers `Undefined` rather than `""` for an absent member.
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// A `u32` field of the export directory, addressed by RVA and offset within it.
fn read_u32(reader: &Reader<'_>, pe: &PeFile<'_>, base_rva: u32, at: usize) -> Option<u32> {
    let offset = u32::try_from(at).ok()?;
    let rva = base_rva.checked_add(offset)?;
    let file_offset = usize::try_from(pe.rva_to_offset(rva)).ok()?;
    reader.u32(file_offset).ok()
}

/// A single `u16` read the same way, for the ordinal table.
fn read_u16(reader: &Reader<'_>, pe: &PeFile<'_>, rva: u32) -> Option<u16> {
    let file_offset = usize::try_from(pe.rva_to_offset(rva)).ok()?;
    reader.u16(file_offset).ok()
}

/// Whether the export address table entry at `value` is a forwarder.
///
/// An RVA that falls inside the export directory names a string in it rather
/// than code.
fn is_forwarder(value: u32, directory_rva: u32, directory_size: u32) -> bool {
    value >= directory_rva && value < directory_rva.saturating_add(directory_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{add_exports, add_forwarded_exports, minimal_pe32};

    #[test]
    fn a_file_with_no_export_directory_has_an_empty_table() {
        // Most executables export nothing, so this is the ordinary case.
        let image = minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        assert_eq!(exports.function_count(), 0);
        assert_eq!(exports.name_count(), 0);
        assert!(!exports.has_name("main"));
    }

    #[test]
    fn the_export_count_is_the_address_table_and_the_name_count_is_the_name_table() {
        // The distinction the corpus pins at line 170585: one name, two exports.
        let mut image = minimal_pe32();
        add_exports(&mut image, &["Init"], 2);
        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        assert_eq!(exports.function_count(), 2, "the address table");
        assert_eq!(exports.name_count(), 1, "the name table");
        assert!(exports.has_name("Init"));
        assert!(!exports.has_name("init"));
    }

    #[test]
    fn the_names_come_back_in_the_files_own_order() {
        let mut image = minimal_pe32();
        add_exports(
            &mut image,
            &["DllRegisterServer", "DllUnregisterServer", "Add"],
            3,
        );
        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        assert_eq!(exports.name_count(), 3);
        assert_eq!(
            exports.names()[0],
            b"DllRegisterServer".as_slice(),
            "the order is the file's, not sorted"
        );
        for name in ["DllRegisterServer", "DllUnregisterServer", "Add"] {
            assert!(exports.has_name(name), "{name}");
        }
    }

    #[test]
    fn a_name_the_file_does_not_export_is_not_found() {
        let mut image = minimal_pe32();
        add_exports(&mut image, &["Main"], 1);
        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        assert!(exports.has_name("Main"));
        assert!(!exports.has_name("ServiceMain"));
        assert!(!exports.has_name("Mai"));
        assert!(!exports.has_name(""));
    }

    #[test]
    fn a_declared_name_count_past_the_end_of_the_file_ends_the_walk() {
        // `NumberOfNames` is a number the file chose, and it is used to index
        // into the file. A file claiming a million names must yield the names it
        // actually holds rather than reading a million times into nothing.
        let mut image = minimal_pe32();
        add_exports(&mut image, &["First", "Second"], 2);
        // Overwrite `NumberOfNames` with a value far past the table.
        let pe = PeFile::parse(&image).unwrap();
        let entry = pe.data_directory(directory::EXPORT);
        let at = usize::try_from(pe.rva_to_offset(entry.virtual_address)).unwrap();
        let names_at = at + NUMBER_OF_NAMES_AT;
        image[names_at..names_at + 4].copy_from_slice(&1_000_000u32.to_le_bytes());

        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        assert_eq!(exports.name_count(), 2, "the names the file really holds");
    }

    #[test]
    fn a_forwarder_rva_is_recognised_as_one() {
        // Not used by the reader, but stated here because it is a fact about the
        // structure the reader walks.
        assert!(is_forwarder(0x2000, 0x2000, 0x100));
        assert!(is_forwarder(0x20FF, 0x2000, 0x100));
        assert!(!is_forwarder(0x2100, 0x2000, 0x100));
        assert!(!is_forwarder(0x1000, 0x2000, 0x100));
    }

    #[test]
    fn the_details_are_the_address_table_and_each_entry_knows_its_ordinal() {
        // The array `pe.export_details` is an array of. Corpus line 219468
        // walks it `0 .. pe.number_of_exports - 1` and reads `.name`, and
        // `number_of_exports` is `NumberOfFunctions` — so the array has one
        // element per address table entry, whether or not the entry has a name.
        let mut image = minimal_pe32();
        add_exports(&mut image, &["Init"], 2);
        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        let details = exports.details();
        assert_eq!(details.len(), 2);
        assert_eq!(details.len(), exports.function_count());

        assert_eq!(details[0].name(), Some(b"Init".as_slice()));
        assert_eq!(
            details[1].name(),
            None,
            "exported by ordinal alone is an entry with no name, not a missing entry"
        );

        // The ordinal is the directory's own `Base` plus the index. A reader
        // that reported the index would be off by one here — which is why the
        // fixture writes a base of 1 rather than 0: the two are then different
        // numbers and the test can tell them apart.
        assert_eq!(details[0].ordinal(), crate::testing::ORDINAL_BASE);
        assert_eq!(details[1].ordinal(), crate::testing::ORDINAL_BASE + 1);
        assert_ne!(details[0].ordinal(), 0, "not the table index");

        // The offset is a file offset, not the RVA the table holds: the fixture
        // puts `.text` at RVA 0x1000 and file offset 0x200.
        assert_eq!(details[0].offset(), 0x200);
        assert_eq!(details[1].offset(), 0x210);

        // Neither entry forwards anywhere.
        assert_eq!(details[0].forward_name(), None);
        assert_eq!(details[1].forward_name(), None);
    }

    #[test]
    fn a_forwarded_entry_names_its_target_and_the_others_have_none() {
        // An address table entry whose RVA lands inside the export directory is
        // a forwarder, and the string it lands on is `Module.Symbol`. Corpus
        // rules read `forward_name contains "Dll"`, so `None` here has to be
        // distinct from `Some("")`: `contains ""` is true of any string, and a
        // rule written that way would fire on every entry in the table.
        let mut image = minimal_pe32();
        add_forwarded_exports(&mut image, &["Init"], 2, &[(1, "NTDLL.RtlAllocateHeap")]);
        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        let details = exports.details();
        assert_eq!(details.len(), 2);
        assert_eq!(
            details[1].forward_name(),
            Some(b"NTDLL.RtlAllocateHeap".as_slice())
        );
        assert_eq!(details[0].forward_name(), None, "code, not a forwarder");
        // The name is its own member, and a forwarded entry keeps it.
        assert!(
            details[1].name().is_none(),
            "the fixture names only entry 0"
        );
        assert_eq!(details[0].name(), Some(b"Init".as_slice()));
    }

    #[test]
    fn a_file_with_no_export_directory_has_no_details_and_no_ordinals() {
        let image = minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        assert!(exports.details().is_empty());
        assert_eq!(exports.function_count(), 0);
    }

    #[test]
    fn a_declared_function_count_past_the_end_of_the_file_ends_the_walk() {
        // `NumberOfFunctions` is a number the file chose, and it is the bound of
        // a loop over the address table. A file claiming a million functions
        // must yield the entries it actually holds: the walk reads each slot and
        // stops at the one that is not in the file, rather than reading a
        // million times into nothing.
        let mut image = minimal_pe32();
        add_exports(&mut image, &["First", "Second"], 2);
        let pe = PeFile::parse(&image).unwrap();
        let entry = pe.data_directory(directory::EXPORT);
        let at = usize::try_from(pe.rva_to_offset(entry.virtual_address)).unwrap();
        let functions_at = at + NUMBER_OF_FUNCTIONS_AT;
        image[functions_at..functions_at + 4].copy_from_slice(&1_000_000u32.to_le_bytes());

        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        assert_eq!(exports.name_count(), 2);
        assert!(
            exports.details().len() < 1_000_000,
            "a declared count is not a promise the file keeps"
        );
        // The entries it does hold still carry the right ordinals, so a rule
        // that got this far is reading a real entry and not a past-the-end one.
        assert_eq!(exports.details()[0].ordinal(), crate::testing::ORDINAL_BASE);
    }

    #[test]
    fn a_forwarder_string_that_is_empty_is_no_string_at_all() {
        // `forwarder` reads a NUL-terminated string out of the directory. An
        // empty one would satisfy `contains ""`, so it is reported as absent.
        let mut image = minimal_pe32();
        add_forwarded_exports(&mut image, &["Init"], 2, &[(1, "")]);
        let pe = PeFile::parse(&image).unwrap();
        let exports = read(&pe);
        assert_eq!(exports.details()[1].forward_name(), None);
    }
}
