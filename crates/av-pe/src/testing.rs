//! Minimal PE images, built in memory.
//!
//! Not fixtures on disk. A checked-in binary is opaque — a test that says
//! `assert_eq!(pe.entry_point(), 0x200)` against one cannot show where the
//! `0x200` came from, and changing a field means running a linker. These are
//! built field by field so that each test can point at the byte it depends on,
//! and so that a test can vary exactly one field and say what it is varying.
//!
//! Public rather than `#[cfg(test)]` because the crates above — the rule engine
//! and the scanner — need a PE to point rules at, and a second copy of these
//! builders would be a second thing to keep in step with the format.

use crate::headers::{OPTIONAL_MAGIC_PE32, OPTIONAL_MAGIC_PE32_PLUS};

/// Offset of `e_lfanew` in the DOS header.
const LFANEW_AT: usize = 0x3C;
/// Where the fixture puts its PE signature.
const PE_AT: usize = 0x80;
/// A conventional `sizeof(IMAGE_OPTIONAL_HEADER32)`.
const OPTIONAL_LEN_32: u16 = 224;
/// `sizeof(IMAGE_OPTIONAL_HEADER64)`.
const OPTIONAL_LEN_64: u16 = 240;

/// A minimal but well-formed PE32 image with two sections.
///
/// `.text` is at RVA `0x1000`, 0x800 bytes of virtual size, 0x400 bytes of raw
/// data at file offset 0x200. `.data` is at RVA `0x2000` with 0x200 bytes of raw
/// data at file offset 0x600. The entry point is the first byte of `.text`, so
/// it is RVA 0x1000 and file offset 0x200 — a pair a test can check both halves
/// of.
///
/// The buffer is 0x400 bytes, which is the whole of `.text` and none of
/// `.data`; tests that need the later section extend it.
pub fn minimal_pe32() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    data[0..2].copy_from_slice(b"MZ");
    data[LFANEW_AT..LFANEW_AT + 4].copy_from_slice(&(PE_AT as u32).to_le_bytes());

    data[PE_AT..PE_AT + 4].copy_from_slice(b"PE\0\0");
    let coff = PE_AT + 4;
    data[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // IMAGE_FILE_MACHINE_I386
    data[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
    data[coff + 4..coff + 8].copy_from_slice(&0x6000_0000u32.to_le_bytes()); // timestamp
    data[coff + 16..coff + 18].copy_from_slice(&OPTIONAL_LEN_32.to_le_bytes());
    data[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // EXECUTABLE | 32BIT

    let opt = coff + 20;
    data[opt..opt + 2].copy_from_slice(&OPTIONAL_MAGIC_PE32.to_le_bytes());
    data[opt + 2] = 14; // linker major
    data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point RVA
    data[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image base
    data[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
    data[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
    data[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
    data[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
    data[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // subsystem: GUI
    data[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // rva and sizes

    // Directory 0: an export table at RVA 0x2000, 0x100 bytes.
    let dirs = opt + 96;
    data[dirs..dirs + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    data[dirs + 4..dirs + 8].copy_from_slice(&0x100u32.to_le_bytes());

    // The section table follows the optional header.
    let sec = PE_AT + 4 + 20 + OPTIONAL_LEN_32 as usize;
    data[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    data[sec + 8..sec + 12].copy_from_slice(&0x800u32.to_le_bytes()); // virtual size
    data[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
    data[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes()); // raw size
    data[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw offset
    data[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXECUTE|READ

    let sec2 = sec + 40;
    data[sec2..sec2 + 8].copy_from_slice(b".data\0\0\0");
    data[sec2 + 8..sec2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    data[sec2 + 12..sec2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    data[sec2 + 16..sec2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    data[sec2 + 20..sec2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    data[sec2 + 36..sec2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes()); // INIT_DATA|READ|WRITE

    data
}

/// Append `bytes` and point the security directory at them.
///
/// Returns the file offset they landed at. The attribute certificate table is
/// addressed by **file offset** rather than by RVA, so its contents belong to
/// no section — which is why this appends to the image instead of adding one,
/// and is also why the directory has to be written here: nothing else in the
/// header would describe it.
///
/// The caller supplies the record bytes. What goes in them — a
/// `WIN_CERTIFICATE` holding a PKCS#7 blob — is not PE knowledge and is built
/// by whoever is testing the signature parser.
pub fn append_security_directory(pe: &mut Vec<u8>, bytes: &[u8]) -> u64 {
    let opt = PE_AT + 4 + 20;
    // The data directories sit at +96 in a PE32 optional header and +112 in a
    // PE32+, so the offset is read from the magic rather than assumed. Assuming
    // would put the entry inside the 64-bit header's own fields, and the test
    // would fail somewhere far from the mistake.
    let dirs = match u16::from_le_bytes([pe[opt], pe[opt + 1]]) {
        OPTIONAL_MAGIC_PE32_PLUS => opt + 112,
        _ => opt + 96,
    };

    let offset = pe.len() as u64;
    pe.extend_from_slice(bytes);

    const DIRECTORY_ENTRY_SECURITY: usize = 4;
    let entry = dirs + DIRECTORY_ENTRY_SECURITY * 8;
    pe[entry..entry + 4].copy_from_slice(&(offset as u32).to_le_bytes());
    pe[entry + 4..entry + 8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    offset
}

/// [`minimal_pe32`] widened to a PE32+ header, with a single section.
///
/// The two layouts differ only in the fields between `BaseOfCode` and
/// `SectionAlignment`, so the fixture is rebuilt from the 32-bit one rather than
/// written out again — which is also what makes a test that reads a 64-bit image
/// with the 32-bit layout fail loudly instead of plausibly.
pub fn minimal_pe64() -> Vec<u8> {
    let mut data = minimal_pe32();
    let opt = PE_AT + 4 + 20;
    data[opt..opt + 2].copy_from_slice(&OPTIONAL_MAGIC_PE32_PLUS.to_le_bytes());

    // Everything from `ImageBase` to the data directories sits at a different
    // offset in the two layouts, so that whole span is cleared before the 64-bit
    // fields are written into it. Patching field by field instead would leave
    // the 32-bit fixture's `NumberOfRvaAndSizes` at +92 to be read back at +108
    // as zero — the fixture making exactly the mistake it exists to catch.
    data[opt + 24..opt + 112].fill(0);
    data[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    data[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
    data[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
    data[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // subsystem: GUI
    data[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // rva and sizes

    // And the directory array itself. It moves sixteen bytes further in as well,
    // so entries 1 through 15 land on bytes the 32-bit fixture wrote — entry 14
    // lands on the old `.text` section name, and a reader asking whether this
    // image has a COM descriptor would be told it does. The array is the fixture's
    // own, and all sixteen entries of it are written here rather than only the
    // one this builder happens to use.
    let dirs = opt + 112;
    data[dirs..dirs + 16 * 8].fill(0);
    data[dirs..dirs + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    data[dirs + 4..dirs + 8].copy_from_slice(&0x100u32.to_le_bytes());

    // A 240-byte optional header, and a section table that follows it. The
    // table moves sixteen bytes further into the file, which lands it on top of
    // the two entries the 32-bit fixture wrote — so every field of the entry is
    // rewritten rather than only the name, or the stale bytes of the old
    // `.data` entry would be read as this section's addresses.
    let coff = PE_AT + 4;
    data[coff + 16..coff + 18].copy_from_slice(&OPTIONAL_LEN_64.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    let sec = PE_AT + 4 + 20 + OPTIONAL_LEN_64 as usize;
    data[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    data[sec + 8..sec + 12].copy_from_slice(&0x800u32.to_le_bytes()); // virtual size
    data[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
    data[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes()); // raw size
    data[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw offset
    data[sec + 24..sec + 28].copy_from_slice(&0u32.to_le_bytes());
    data[sec + 28..sec + 32].copy_from_slice(&0u32.to_le_bytes());
    data[sec + 32..sec + 34].copy_from_slice(&0u16.to_le_bytes());
    data[sec + 34..sec + 36].copy_from_slice(&0u16.to_le_bytes());
    data[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    // And whatever the 32-bit table left past the end of the new one.
    data[sec + 40..sec + 80].fill(0);
    data
}

// -- single header fields ----------------------------------------------------

/// A little-endian `u32` at `at`, read a byte at a time.
///
/// A slice and `try_into` would need an `expect` for the four-byte conversion,
/// and this module is library code: the crate denies `unwrap_used` and
/// `expect_used` here and relaxes them only under `cfg(test)`. Indexing panics on
/// a short buffer, which is the documented behaviour of the setters below and the
/// only way they can be handed something that is not a fixture.
fn le_u32(pe: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([pe[at], pe[at + 1], pe[at + 2], pe[at + 3]])
}

/// A little-endian `u16` at `at`. See [`le_u32`].
fn le_u16(pe: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([pe[at], pe[at + 1]])
}

/// `e_lfanew`, the offset the fixture's PE header starts at.
fn lfanew(pe: &[u8]) -> usize {
    le_u32(pe, LFANEW_AT) as usize
}

/// Where `IMAGE_FILE_HEADER.Machine` starts, from the start of the file.
fn machine_field(pe: &[u8]) -> usize {
    lfanew(pe) + 4
}

/// Where `IMAGE_OPTIONAL_HEADER.Subsystem` starts, from the start of the file.
///
/// The field sits at the same offset in both optional header layouts — the two
/// differ only from `ImageBase` onward, and `Subsystem` is well past that — which
/// is why one function serves both fixtures.
fn subsystem_field(pe: &[u8]) -> usize {
    let coff = lfanew(pe) + 4;
    let optional_len = usize::from(le_u16(pe, coff + 16));
    // The header itself ends before the section table, so a `Subsystem` offset
    // past the declared length would be a field the parser never reads — and a
    // setter that wrote there would look like it had worked.
    assert!(68 + 2 <= optional_len, "the optional header is too short to hold Subsystem");
    coff + 20 + 68
}

/// Set `IMAGE_FILE_HEADER.Machine`.
///
/// # Why these two exist
///
/// [`minimal_pe32`] and [`minimal_pe64`] hardcode `IMAGE_FILE_MACHINE_I386` and
/// `IMAGE_SUBSYSTEM_WINDOWS_GUI`, which is the right default for a fixture a
/// rule is pointed at. A caller testing something that *branches* on those
/// fields — a driver installer refusing a file that is not a native image, a
/// rule that fires on a subsystem — needs to vary exactly one of them, and a
/// caller that patched `data[opt + 68]` itself would be a second copy of the
/// header layout living in another crate. That is the thing most likely to be
/// silently wrong, so the offsets are here.
///
/// # Panics
///
/// If `pe` is not a fixture this module built — there is no `e_lfanew` to read,
/// or the optional header is too short to contain the field.
pub fn set_machine(pe: &mut [u8], machine: u16) {
    let at = machine_field(pe);
    pe[at..at + 2].copy_from_slice(&machine.to_le_bytes());
}

/// Set `IMAGE_OPTIONAL_HEADER.Subsystem`. See [`set_machine`].
///
/// # Panics
///
/// As [`set_machine`].
pub fn set_subsystem(pe: &mut [u8], subsystem: u16) {
    let at = subsystem_field(pe);
    pe[at..at + 2].copy_from_slice(&subsystem.to_le_bytes());
}

// -- the DOS stub ------------------------------------------------------------

/// Write a Rich header into the DOS stub of `pe` and return where it starts.
///
/// # Why this writes into the gap rather than appending
///
/// The Rich header belongs between the DOS header and the PE header, and that is
/// the only place a reader looks for it — the search is bounded by `e_lfanew`.
/// Appending one to the end of the fixture, as every other helper here does with
/// its table, would produce a file whose Rich header is not where the format
/// puts one, and a test using it would be testing the parser against a fixture
/// the parser is right to refuse.
///
/// So the room is the fixture's own stub: `0x40` to `0x80`, sixty-four bytes,
/// which holds a header of up to five entries. That is fewer than the eleven or
/// twelve a real MSVC image carries, and it is enough: the decoder's work does
/// not depend on the count, and the arithmetic the count feeds —
/// `16 + 8`·`n` — is checked at the corpus's own scale in the module's tests.
///
/// # Panics
///
/// If the entries do not fit in the stub. A fixture that quietly wrote past
/// `e_lfanew` would produce a file whose Rich header is somewhere the reader
/// does not look, and the test using it would fail for a reason it could not
/// name.
pub fn add_rich_header(pe: &mut [u8], entries: &[(u32, u32)]) -> usize {
    /// Where the fixed key this helper writes puts things.
    const KEY: u32 = 0xA5A5_5A5A;
    const STUB_AT: usize = 0x40;
    const ENTRY_LEN: usize = 8;

    let dans = STUB_AT;
    let rich = dans + 16 + entries.len() * ENTRY_LEN;
    let end = rich + 8;
    assert!(
        pe.len() >= end && end <= PE_AT,
        "a Rich header of {} entries does not fit in the {} bytes the DOS stub has \
         before e_lfanew at {PE_AT:#x}",
        entries.len(),
        PE_AT - STUB_AT
    );

    let mut put = |at: usize, word: u32| {
        pe[at..at + 4].copy_from_slice(&(word ^ KEY).to_le_bytes());
    };
    // `DanS` and the three zero dwords, which is what a reader's backward walk
    // looks for.
    put(dans, 0x536E_6144);
    for index in 1..=3 {
        put(dans + index * 4, 0);
    }
    for (index, (compid, count)) in entries.iter().enumerate() {
        put(dans + 16 + index * ENTRY_LEN, *compid);
        put(dans + 16 + index * ENTRY_LEN + 4, *count);
    }
    // The marker and the key, in the clear: they are what makes the region
    // findable, so encrypting them would be encrypting the map.
    pe[rich..rich + 4].copy_from_slice(b"Rich");
    pe[rich + 4..rich + 8].copy_from_slice(&KEY.to_le_bytes());
    dans
}

// -- tables behind a data directory ------------------------------------------

/// The index of a data directory entry, for the helpers below.
///
/// Visible to the crate so that a test in another module can point a directory
/// at a file offset that is not there, which is the only way to build the
/// malformed header those readers have to answer for.
pub(crate) const DIRECTORY_EXPORT: usize = 0;
pub(crate) const DIRECTORY_IMPORT: usize = 1;

/// The file offset and length of the data directory array.
fn directories(pe: &[u8]) -> (usize, usize) {
    let opt = PE_AT + 4 + 20;
    // PE32+ puts the array sixteen bytes further in, because every field
    // between `ImageBase` and it is wider. Reading the offset from the magic
    // rather than assuming is what keeps a 64-bit fixture from having its
    // directory entry written into its own `SizeOfStackReserve`.
    let dirs = match u16::from_le_bytes([pe[opt], pe[opt + 1]]) {
        OPTIONAL_MAGIC_PE32_PLUS => opt + 112,
        _ => opt + 96,
    };
    (dirs, 16 * 8)
}

/// Point data directory `index` at `rva` for `len` bytes.
pub(crate) fn set_directory(pe: &mut [u8], index: usize, rva: u32, len: u32) {
    let (dirs, _) = directories(pe);
    let at = dirs + index * 8;
    pe[at..at + 4].copy_from_slice(&rva.to_le_bytes());
    pe[at + 4..at + 8].copy_from_slice(&len.to_le_bytes());
}

/// The size of one thunk in this image.
fn thunk_len(pe: &[u8]) -> u32 {
    let opt = PE_AT + 4 + 20;
    if u16::from_le_bytes([pe[opt], pe[opt + 1]]) == OPTIONAL_MAGIC_PE32_PLUS {
        8
    } else {
        4
    }
}

/// The value written into a thunk to mark it as an ordinal import.
fn ordinal_flag(pe: &[u8]) -> u64 {
    if thunk_len(pe) == 8 {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    }
}

/// One entry a library's import list can hold.
enum ImportEntry<'a> {
    /// A symbol named in the file.
    Named(&'a str),
    /// A symbol identified only by its ordinal.
    Ordinal(u16),
}

/// A fixture buffer's length as the `u32` the format's fields are written in.
///
/// The narrowing below has no failing case to answer for — the fixtures are a
/// few hundred bytes and the appenders assert their geometry at the end — so the
/// bound is stated here, before the conversion, in the terms that matter rather
/// than left to a branch that cannot be taken. A buffer past `0x1000` has
/// already grown into `.text`, which is the failure the appender's own assertion
/// is about.
fn fixture_len(bytes: &[u8]) -> u32 {
    assert!(
        bytes.len() < 0x1000,
        "a fixture's tables live below .text at RVA 0x1000, and this one has grown past it"
    );
    bytes.len() as u32
}

/// Append an import table and point the import directory at it.
///
/// # Why the addresses below are file offsets
///
/// The import directory is an RVA, and the block this appends sits past the last
/// section, where no section claims it. An RVA in no section is returned
/// unchanged by [`crate::PeFile::rva_to_offset`] — a documented behaviour this
/// crate keeps because rules depend on it — so an RVA equal to the file offset
/// resolves to that file offset. Every address written into the block is
/// therefore `file offset + offset within the block`.
///
/// The assertion at the end is what keeps that honest: a block long enough to
/// reach RVA 0x1000 would have some of its addresses resolve into `.text`, and
/// the test that used it would fail somewhere far from the cause.
fn add_import_table(pe: &mut Vec<u8>, libraries: &[(&str, &[ImportEntry<'_>])]) {
    let base = fixture_len(pe);
    let stride = thunk_len(pe);

    // Lay the block out first, recording where each piece lands, then write the
    // addresses once they are known.
    let mut block: Vec<u8> = vec![0; (libraries.len() + 1) * 20];

    let mut thunk_at = Vec::new();
    for (_, entries) in libraries {
        thunk_at.push(block.len() as u32);
        // One thunk per entry plus the zero that terminates the list.
        block.resize(
            block.len() + (entries.len() as u32 + 1) as usize * stride as usize,
            0,
        );
    }

    let mut library_at = Vec::new();
    for (library, _) in libraries {
        library_at.push(block.len() as u32);
        block.extend_from_slice(library.as_bytes());
        block.push(0);
    }

    // Each thunk's value is computed as the name it points at is written, which
    // is the only pass that knows where that name landed. A named entry
    // therefore has no "and if there is no offset" case to answer for: the
    // value and the bytes are produced by the same arm.
    let flag = ordinal_flag(pe);
    let mut thunks = Vec::new();
    for (_, entries) in libraries {
        let mut per_library = Vec::new();
        for entry in *entries {
            per_library.push(match entry {
                ImportEntry::Named(name) => {
                    let at = base + block.len() as u32;
                    // `IMAGE_IMPORT_BY_NAME` is a `u16` hint followed by the
                    // name. The hint is written as zero because nothing reads
                    // it and a wrong value would be a wrong value either way.
                    block.extend_from_slice(&0u16.to_le_bytes());
                    block.extend_from_slice(name.as_bytes());
                    block.push(0);
                    u64::from(at)
                }
                ImportEntry::Ordinal(ordinal) => flag | u64::from(*ordinal),
            });
        }
        thunks.push(per_library);
    }

    for index in 0..libraries.len() {
        let descriptor = index * 20;
        let ilt = base + thunk_at[index];
        block[descriptor..descriptor + 4].copy_from_slice(&ilt.to_le_bytes());
        block[descriptor + 12..descriptor + 16]
            .copy_from_slice(&(base + library_at[index]).to_le_bytes());
        block[descriptor + 16..descriptor + 20].copy_from_slice(&ilt.to_le_bytes());

        for (position, value) in thunks[index].iter().enumerate() {
            let at = thunk_at[index] as usize + position * stride as usize;
            block[at..at + stride as usize]
                .copy_from_slice(&value.to_le_bytes()[..stride as usize]);
        }
    }

    // The terminating descriptor is the all-zero one the block was sized for
    // and never written to, which is how the format ends the array.
    let length = fixture_len(&block);
    pe.extend_from_slice(&block);
    set_directory(pe, DIRECTORY_IMPORT, base, length);

    assert!(
        base + length <= 0x1000,
        "the import block reached .text; a shorter list or a wider fixture is needed"
    );
}

/// Append an import table of named symbols and point the directory at it.
///
/// Each pair is a library and the symbols imported from it, in order.
pub fn add_imports(pe: &mut Vec<u8>, libraries: &[(&str, &[&str])]) {
    let owned: Vec<(&str, Vec<ImportEntry<'_>>)> = libraries
        .iter()
        .map(|(library, names)| {
            (
                *library,
                names.iter().map(|name| ImportEntry::Named(name)).collect(),
            )
        })
        .collect();
    let borrowed: Vec<(&str, &[ImportEntry<'_>])> = owned
        .iter()
        .map(|(library, entries)| (*library, entries.as_slice()))
        .collect();
    add_import_table(pe, &borrowed);
}

/// Append an import table holding only ordinal imports.
pub fn add_ordinal_import(pe: &mut Vec<u8>, library: &str, ordinals: &[u16]) {
    let entries: Vec<ImportEntry<'_>> = ordinals.iter().map(|o| ImportEntry::Ordinal(*o)).collect();
    add_import_table(pe, &[(library, entries.as_slice())]);
}

/// Append an export table and point the export directory at it.
///
/// `functions` is what the export address table declares — the number a rule
/// reads as `pe.number_of_exports` — and is allowed to exceed `names.len()`,
/// which is what a DLL exporting some symbols by ordinal only looks like.
pub fn add_exports(pe: &mut Vec<u8>, names: &[&str], functions: u32) {
    add_export_table(pe, names, functions, &[]);
}

/// Append an export table in which some of the address table entries forward.
///
/// `forwarded` pairs an index into the address table with the `Module.Symbol`
/// it forwards to. The strings are written *inside* the export directory, which
/// is what makes the entry a forwarder at all: an address table entry holds an
/// RVA, and an RVA inside the directory names a string in it rather than code.
/// A fixture that put the string elsewhere would be a fixture whose forwarder
/// is not detectable as one.
pub fn add_forwarded_exports(
    pe: &mut Vec<u8>,
    names: &[&str],
    functions: u32,
    forwarded: &[(u32, &str)],
) {
    add_export_table(pe, names, functions, forwarded);
}

fn add_export_table(pe: &mut Vec<u8>, names: &[&str], functions: u32, forwarded: &[(u32, &str)]) {
    let base = fixture_len(pe);
    const DIRECTORY_LEN: usize = 40;

    let mut block = vec![0u8; DIRECTORY_LEN];
    // The export address table, one `u32` per function. The values are dummy
    // RVAs in `.text` rather than zero, because a zero entry means "not
    // exported" and a fixture full of them would be testing a hole.
    let address_table_at = block.len() as u32;
    for index in 0..functions {
        block.extend_from_slice(&(0x1000 + index * 16).to_le_bytes());
    }

    let name_table_at = block.len() as u32;
    block.resize(block.len() + names.len() * 4, 0);

    let ordinal_table_at = block.len() as u32;
    for index in 0..names.len() {
        block.extend_from_slice(&(index as u16).to_le_bytes());
    }

    let mut names_at = Vec::new();
    for name in names {
        names_at.push(block.len() as u32);
        block.extend_from_slice(name.as_bytes());
        block.push(0);
    }

    // The forwarder strings, in the directory so that their RVAs fall inside
    // it, and patched into the address table afterwards because the table is
    // written before them.
    for (index, target) in forwarded {
        let at = block.len() as u32;
        block.extend_from_slice(target.as_bytes());
        block.push(0);
        let entry = address_table_at as usize + *index as usize * 4;
        if entry + 4 <= block.len() {
            block[entry..entry + 4].copy_from_slice(&(base + at).to_le_bytes());
        }
    }

    block[16..20].copy_from_slice(&ORDINAL_BASE.to_le_bytes());
    block[20..24].copy_from_slice(&functions.to_le_bytes());
    block[24..28].copy_from_slice(&(names.len() as u32).to_le_bytes());
    block[28..32].copy_from_slice(&(base + address_table_at).to_le_bytes());
    block[32..36].copy_from_slice(&(base + name_table_at).to_le_bytes());
    block[36..40].copy_from_slice(&(base + ordinal_table_at).to_le_bytes());

    for (index, at) in names_at.iter().enumerate() {
        let entry = name_table_at as usize + index * 4;
        block[entry..entry + 4].copy_from_slice(&(base + at).to_le_bytes());
    }

    let length = fixture_len(&block);
    pe.extend_from_slice(&block);
    set_directory(pe, DIRECTORY_EXPORT, base, length);

    assert!(
        base + length <= 0x1000,
        "the export block reached .text; a shorter list or a wider fixture is needed"
    );
}

/// The ordinal the first export address table entry has in these fixtures.
///
/// `1`, the way a real linker numbers them, and not `0`. A reader that reported
/// the table index as the ordinal would agree with the fixture if this were
/// zero, so it is deliberately the value that makes the two differ.
pub const ORDINAL_BASE: u32 = 1;

// -- the CLI header and metadata tables --------------------------------------

/// Data directory 14, the CLI header, which is what makes a PE managed.
const DIRECTORY_COM_DESCRIPTOR: usize = 14;

/// The three table ids [`add_dotnet`] writes by name, plus the one a linked
/// resource points into. Everything else is whatever the caller asks for.
const TABLE_ASSEMBLY: u8 = 0x20;
const TABLE_ASSEMBLY_REF: u8 = 0x23;
const TABLE_FILE: u8 = 0x26;
const TABLE_MANIFEST_RESOURCE: u8 = 0x28;

/// A table placed before the ones a reader is looking for, with a size the
/// caller states.
///
/// # Why the row length is the caller's
///
/// Because it is the fixture's own claim about the format. ECMA-335 II.22 says
/// how wide every column of every table is, and a fixture that asked the reader
/// for those widths would agree with the reader about a mistake — the test would
/// pass on a reader that placed `ManifestResource` two bytes off, since both
/// halves would be off by the same two. Stating the width here means a wrong one
/// moves the rows the reader reads and the names come out as rubbish, which is
/// what the tests below assert against.
///
/// The ids in use are also deliberately varied: tables with three strings, with
/// a coded index, with a `u32`, with a blob index, so that a reader that got any
/// one of those widths wrong lands somewhere else. `MethodDef` is the awkward
/// one at fourteen bytes.
#[derive(Debug, Clone, Copy)]
pub struct ExtraTable {
    /// The table id, per ECMA-335 II.22.
    pub id: u8,
    /// How many rows it has.
    pub rows: u32,
    /// How many bytes each row takes.
    pub row_len: usize,
}

impl ExtraTable {
    /// A table of `rows` zero rows, `row_len` bytes each.
    pub fn new(id: u8, rows: u32, row_len: usize) -> Self {
        Self { id, rows, row_len }
    }
}

/// A manifest resource for [`add_dotnet`]: a name, and either its bytes or
/// `None` for a resource that is linked into another file.
///
/// The distinction is the one this reader's `length` member turns on. A linked
/// resource has no meaningful offset in this file at all — real assemblies write
/// zero there — so a fixture that had no way to express one could not test that
/// a reader says so rather than reporting the field.
#[derive(Debug, Clone, Copy)]
pub struct DotNetResourceSpec<'a> {
    /// The resource's name.
    pub name: &'a str,
    /// Its bytes, or `None` when it is linked.
    pub data: Option<&'a [u8]>,
}

impl<'a> DotNetResourceSpec<'a> {
    /// An embedded resource.
    pub fn embedded(name: &'a str, data: &'a [u8]) -> Self {
        Self {
            name,
            data: Some(data),
        }
    }

    /// A resource that lives in another file.
    pub fn linked(name: &'a str) -> Self {
        Self { name, data: None }
    }
}

/// An `AssemblyRef` row for [`add_dotnet`].
#[derive(Debug, Clone, Copy)]
pub struct AssemblyRefSpec<'a> {
    /// The referenced assembly's name.
    pub name: &'a str,
    /// Its version, as `[major, minor, build, revision]`.
    pub version: [u16; 4],
}

/// What [`add_dotnet`] should build.
#[derive(Debug, Clone, Default)]
pub struct DotNetSpec<'a> {
    /// The runtime version string in the metadata root. `"v4.0.30319"` for
    /// anything built against .NET Framework 4, which is what the corpus's
    /// `dotnet.version == "v4.0.30319"` is asking about.
    pub runtime_version: &'a str,
    /// The `Assembly` row: a name and a version, or `None` for a module that is
    /// not an assembly.
    pub assembly: Option<(&'a str, [u16; 4])>,
    /// The `AssemblyRef` rows, in table order.
    pub assembly_refs: Vec<AssemblyRefSpec<'a>>,
    /// The `ManifestResource` rows, in table order.
    pub resources: Vec<DotNetResourceSpec<'a>>,
    /// Tables to place before the three a reader reads, so that a reader that
    /// cannot measure them finds the wrong rows. See [`ExtraTable`].
    pub extra_tables: Vec<ExtraTable>,
}

impl<'a> DotNetSpec<'a> {
    /// A spec with nothing but a runtime version.
    pub fn new(runtime_version: &'a str) -> Self {
        Self {
            runtime_version,
            ..Self::default()
        }
    }

    /// Add an `Assembly` row.
    pub fn assembly(mut self, name: &'a str, version: [u16; 4]) -> Self {
        self.assembly = Some((name, version));
        self
    }

    /// Add an `AssemblyRef` row.
    pub fn reference(mut self, name: &'a str, version: [u16; 4]) -> Self {
        self.assembly_refs.push(AssemblyRefSpec { name, version });
        self
    }

    /// Add an embedded manifest resource.
    pub fn resource(mut self, name: &'a str, data: &'a [u8]) -> Self {
        self.resources
            .push(DotNetResourceSpec::embedded(name, data));
        self
    }

    /// Add a manifest resource that lives in another file.
    pub fn linked_resource(mut self, name: &'a str) -> Self {
        self.resources.push(DotNetResourceSpec::linked(name));
        self
    }

    /// Put a table in front of the ones a reader is looking for.
    pub fn extra_table(mut self, table: ExtraTable) -> Self {
        self.extra_tables.push(table);
        self
    }
}

/// Where [`add_dotnet`] put the three structures, as file offsets.
///
/// Returned so that a test can damage one field of one of them and watch the
/// reader answer for it, which is the only way the checks in that reader are
/// tested against something other than a file that is entirely correct.
#[derive(Debug, Clone, Copy)]
pub struct DotNetLayout {
    /// The CLI header.
    pub cli_header: usize,
    /// The metadata root's `BSJB` signature.
    pub metadata: usize,
    /// The Resources data area.
    pub resources: usize,
}

/// The strings of a `#Strings` heap, built as names are asked for.
///
/// Index zero is the empty string and is written by [`StringHeap::new`]: the
/// heap begins with a NUL for exactly that reason, and a fixture without one
/// would make every zero index in every row read as the first name in the file.
#[derive(Debug, Default)]
struct StringHeap {
    bytes: Vec<u8>,
    index: Vec<(String, u16)>,
}

impl StringHeap {
    fn new() -> Self {
        Self {
            bytes: vec![0],
            index: Vec::new(),
        }
    }

    /// The index of `name`, adding it to the heap if it is not there yet.
    ///
    /// Stops the test rather than truncating when the heap has outgrown the
    /// two-byte indices these fixtures write. A fixture that needs a wider index
    /// needs a `HeapSizes` flag this builder does not write, and a truncated
    /// index would produce a file whose name columns point at the wrong strings
    /// — a test failing for a reason nothing names.
    fn intern(&mut self, name: &str) -> u16 {
        if let Some((_, index)) = self.index.iter().find(|(text, _)| text == name) {
            return *index;
        }
        // Only the index has to fit, not the heap: what a row stores is an
        // offset into the heap, and a heap longer than 64 KiB is fine as long as
        // every offset into it is not. The check is repeated on each call, so a
        // later name that *would* need a wider index still stops the test.
        assert!(
            self.bytes.len() <= usize::from(u16::MAX),
            "the fixture's string heap has outgrown the two-byte indices it writes"
        );
        let index = self.bytes.len() as u16;
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        self.index.push((name.to_owned(), index));
        index
    }
}

/// Append a CLI header, a metadata root with a `#~` and a `#Strings` stream, and
/// a Resources data area; point data directory 14 at the header.
///
/// # What it writes, and in what order
///
/// The whole managed structure goes inside `.data`, because every address in it
/// is an **RVA** and this fixture's point is to be read the way a real assembly
/// is. Appended past the last section, as the import and export builders do, an
/// unmapped RVA is returned unchanged by [`crate::PeFile::rva_to_offset`] and the
/// fixture would be testing a file whose addresses need no mapping at all —
/// leaving the one conversion the reader performs unexercised.
///
/// The tables are written in table-id order, as the format requires, with the
/// caller's [`ExtraTable`]s and the `File` rows for any linked resource placed
/// before the three this reader reads. Row widths are the fixture's own claim:
/// every index is two bytes, which is what `HeapSizes == 0` and a row count
/// below 65,536 mean, and which keeps the arithmetic in the tests below readable.
/// Each embedded resource is its four-byte length, its bytes, and padding to the
/// next eight-byte boundary, which is the alignment real assemblies use.
///
/// # Panics
///
/// If the result would not fit in the fixture's data section, or if a name's
/// index would need more than two bytes. Both are the caller asking for
/// something this builder cannot express, and a fixture that quietly wrote a
/// truncated index would be a file whose name columns point at the wrong
/// strings.
pub fn add_dotnet(pe: &mut Vec<u8>, spec: &DotNetSpec<'_>) -> DotNetLayout {
    /// `sizeof(IMAGE_COR20_HEADER)`.
    const CLI_HEADER: usize = 72;
    /// The metadata root's fixed part, up to the version string.
    const ROOT_FIXED: usize = 16;
    /// `#~`, the tables.
    const STREAM_TABLES: &[u8] = b"#~";
    /// `#Strings`, the names.
    const STREAM_STRINGS: &[u8] = b"#Strings";

    let mut heap = StringHeap::new();

    // -- the rows, built before the header that counts them ----------------
    //
    // One plan per table, in table-id order, holding the row bytes. The rows
    // cannot be written until the strings they name have indices and the strings
    // cannot be laid out until every name is known, so this is the pass that
    // resolves both.
    struct Plan {
        id: u8,
        rows: u32,
        bytes: Vec<u8>,
    }
    let mut plans: Vec<Plan> = Vec::new();

    let mut extra: Vec<ExtraTable> = spec.extra_tables.clone();
    extra.sort_by_key(|table| table.id);
    for table in &extra {
        // Zero bytes, which is a row whose every column is zero: a valid row of
        // a table this reader never reads, and the widest thing a fixture needs
        // to make it step over.
        // Saturating rather than checked: the caller is a test, and a row count
        // large enough to saturate is one that fails the size assertion below
        // rather than one that needs an error of its own.
        let len = table.row_len.saturating_mul(table.rows as usize);
        plans.push(Plan {
            id: table.id,
            rows: table.rows,
            bytes: vec![0; len],
        });
    }

    // The `File` table, one row per linked resource, since that is the table an
    // `Implementation` column points into. Written only when there is one, so
    // that a fixture about embedded resources has no table it does not need.
    let linked: Vec<usize> = spec
        .resources
        .iter()
        .enumerate()
        .filter(|(_, resource)| resource.data.is_none())
        .map(|(index, _)| index)
        .collect();
    if !linked.is_empty() {
        let mut bytes = Vec::new();
        for resource in &linked {
            let name = heap.intern(spec.resources[*resource].name);
            // `Flags` (u32, zero for a resource file), `Name` (a string index),
            // `HashValue` (a blob index, zero for an empty hash).
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&name.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
        }
        plans.push(Plan {
            id: TABLE_FILE,
            rows: linked.len() as u32,
            bytes,
        });
    }

    if let Some((name, version)) = spec.assembly {
        let name = heap.intern(name);
        let mut bytes = Vec::new();
        // HashAlgId: SHA-1, which is what every compiler writes and what a
        // reader comparing against a constant would need to be right about.
        bytes.extend_from_slice(&0x8004u32.to_le_bytes());
        for field in version {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        bytes.extend_from_slice(&0u32.to_le_bytes()); // Flags
        bytes.extend_from_slice(&0u16.to_le_bytes()); // PublicKey: none
        bytes.extend_from_slice(&name.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes()); // Culture: none
        plans.push(Plan {
            id: TABLE_ASSEMBLY,
            rows: 1,
            bytes,
        });
    }

    if !spec.assembly_refs.is_empty() {
        let mut bytes = Vec::new();
        for reference in &spec.assembly_refs {
            for field in reference.version {
                bytes.extend_from_slice(&field.to_le_bytes());
            }
            bytes.extend_from_slice(&0u32.to_le_bytes()); // Flags
            bytes.extend_from_slice(&0u16.to_le_bytes()); // PublicKeyOrToken
            let name = heap.intern(reference.name);
            bytes.extend_from_slice(&name.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes()); // Culture
            bytes.extend_from_slice(&0u16.to_le_bytes()); // HashValue
        }
        plans.push(Plan {
            id: TABLE_ASSEMBLY_REF,
            rows: spec.assembly_refs.len() as u32,
            bytes,
        });
    }

    // The resources and the area their bytes go in, laid out together so that
    // each row's `Offset` is the length-prefixed blob's own position. The area
    // is what the CLI header's `Resources` directory covers, and a resource's
    // `Offset` is relative to it.
    let mut area: Vec<u8> = Vec::new();
    let mut resource_rows: Vec<u8> = Vec::new();
    let mut file_row = 0u32;
    for resource in &spec.resources {
        let name = heap.intern(resource.name);
        let (relative, implementation) = match resource.data {
            Some(data) => {
                let relative = area.len() as u32;
                // A `u32` length, then the bytes, then padding to the eight-byte
                // boundary the next one starts on — which is the boundary real
                // assemblies use, measured, not four. This prefix is what the
                // reader reports as `length`; see `crate::dotnet`.
                area.extend_from_slice(&(data.len() as u32).to_le_bytes());
                area.extend_from_slice(data);
                while area.len() % 8 != 0 {
                    area.push(0);
                }
                (relative, 0u32)
            }
            None => {
                // A linked resource writes zero here, as real assemblies do, and
                // an `Implementation` naming its `File` row: tag zero is that
                // table, so the coded index is the row number shifted by two.
                file_row += 1;
                (0u32, file_row << 2)
            }
        };
        resource_rows.extend_from_slice(&relative.to_le_bytes());
        resource_rows.extend_from_slice(&0u32.to_le_bytes()); // Flags
        resource_rows.extend_from_slice(&name.to_le_bytes());
        resource_rows.extend_from_slice(&(implementation as u16).to_le_bytes());
    }
    if !spec.resources.is_empty() {
        // Placed last of the three that matter, so the tables before it are the
        // ones a reader has to measure to reach it.
        plans.push(Plan {
            id: TABLE_MANIFEST_RESOURCE,
            rows: spec.resources.len() as u32,
            bytes: resource_rows,
        });
    }

    plans.sort_by_key(|plan| plan.id);

    // -- the `#~` stream ---------------------------------------------------
    let mut tables = Vec::new();
    tables.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    tables.push(2); // MajorVersion
    tables.push(0); // MinorVersion
    tables.push(0); // HeapSizes: every index two bytes
    tables.push(1); // Reserved, and required to be one
    let mut valid = 0u64;
    for plan in &plans {
        valid |= 1u64 << plan.id;
    }
    tables.extend_from_slice(&valid.to_le_bytes());
    tables.extend_from_slice(&0u64.to_le_bytes()); // Sorted: nothing is
    for plan in &plans {
        tables.extend_from_slice(&plan.rows.to_le_bytes());
    }
    for plan in &plans {
        tables.extend_from_slice(&plan.bytes);
    }

    // -- the metadata root -------------------------------------------------
    let version = spec.runtime_version.as_bytes();
    // `VersionLength` covers the string and its terminator, rounded up to the
    // four-byte boundary the stream count starts at. Measured against a real
    // assembly: `mscorlib.dll` says 12 for the eleven characters of
    // `v4.0.30319`.
    let version_length = align(version.len() + 1, 4);

    let stream_headers = [STREAM_TABLES, STREAM_STRINGS];
    let header_len: usize = stream_headers
        .iter()
        .map(|name| 8 + align(name.len() + 1, 4))
        .sum();
    let first_stream = ROOT_FIXED + version_length + 4 + header_len;

    let tables_at = first_stream;
    let strings_at = align(tables_at + tables.len(), 4);

    let mut root = Vec::new();
    root.extend_from_slice(&0x424A_5342u32.to_le_bytes()); // "BSJB"
    root.extend_from_slice(&1u16.to_le_bytes()); // MajorVersion
    root.extend_from_slice(&1u16.to_le_bytes()); // MinorVersion
    root.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    root.extend_from_slice(&(version_length as u32).to_le_bytes());
    root.extend_from_slice(version);
    root.resize(ROOT_FIXED + version_length, 0);
    root.extend_from_slice(&0u16.to_le_bytes()); // Flags
    root.extend_from_slice(&(stream_headers.len() as u16).to_le_bytes());
    // The stream offsets are relative to the root, and the sizes are the
    // streams' own lengths rather than where the next one starts.
    let sizes = [tables.len(), heap.bytes.len()];
    let offsets = [tables_at, strings_at];
    for (index, name) in stream_headers.iter().enumerate() {
        root.extend_from_slice(&(offsets[index] as u32).to_le_bytes());
        root.extend_from_slice(&(sizes[index] as u32).to_le_bytes());
        root.extend_from_slice(name);
        // The name is terminated, and *then* padded. `#Strings` is eight bytes
        // and eight is already a multiple of four, so padding without the
        // terminator first would leave the next header's offset field starting
        // where the NUL should be.
        root.push(0);
        root.resize(align(root.len(), 4), 0);
    }
    debug_assert_eq!(root.len(), first_stream);
    root.extend_from_slice(&tables);
    // The padding between the tables' end and the next stream is part of
    // neither, and the offsets in the headers are what say so.
    root.resize(strings_at, 0);
    root.extend_from_slice(&heap.bytes);
    root.resize(strings_at + heap.bytes.len(), 0);

    // -- the CLI header, and the whole thing into `.data` ------------------
    let meta_len = root.len();
    let cli_at = 0usize;
    let meta_at = align(cli_at + CLI_HEADER, 4);
    let res_at = align(meta_at + meta_len, 4);
    let total = res_at + area.len();

    let mut cli = vec![0u8; CLI_HEADER];
    cli[0..4].copy_from_slice(&(CLI_HEADER as u32).to_le_bytes());
    cli[4..6].copy_from_slice(&2u16.to_le_bytes()); // MajorRuntimeVersion
    cli[6..8].copy_from_slice(&5u16.to_le_bytes()); // MinorRuntimeVersion
    cli[8..12].copy_from_slice(&(DATA_RVA + meta_at as u32).to_le_bytes());
    cli[12..16].copy_from_slice(&(meta_len as u32).to_le_bytes());
    cli[16..20].copy_from_slice(&1u32.to_le_bytes()); // Flags: ILONLY
    cli[24..28].copy_from_slice(&(DATA_RVA + res_at as u32).to_le_bytes());
    cli[28..32].copy_from_slice(&(area.len() as u32).to_le_bytes());

    assert!(
        total < 0x4000,
        "the managed structure has outgrown the fixture's data section; a shorter name or a \
         smaller resource is needed"
    );
    let base = DATA_AT;
    grow_data_section(pe, base + total);
    pe[base..base + CLI_HEADER].copy_from_slice(&cli);
    pe[base + meta_at..base + meta_at + meta_len].copy_from_slice(&root);
    pe[base + res_at..base + res_at + area.len()].copy_from_slice(&area);
    set_directory(pe, DIRECTORY_COM_DESCRIPTOR, DATA_RVA, CLI_HEADER as u32);

    DotNetLayout {
        cli_header: base + cli_at,
        metadata: base + meta_at,
        resources: base + res_at,
    }
}

/// Append a CodeView debug directory naming `path`, and point directory 6 at it.
///
/// Returns the file offset of the `IMAGE_DEBUG_DIRECTORY` entry.
///
/// Appended past the last section rather than placed in one, which is where the
/// attribute certificate table goes and for the same reason: the entry's
/// `PointerToRawData` is a file offset, and a reader that prefers it — which
/// [`crate::debug`] does — needs no section to resolve it. The directory's own
/// address is then in no section either, and `rva_to_offset` returns it
/// unchanged, which is the accident described in that module's documentation.
pub fn add_pdb_path(pe: &mut Vec<u8>, path: &str) -> usize {
    /// `IMAGE_DEBUG_TYPE_CODEVIEW`.
    const TYPE_CODEVIEW: u32 = 2;
    /// `sizeof(IMAGE_DEBUG_DIRECTORY)`.
    const ENTRY_LEN: usize = 28;
    /// The bytes between the `RSDS` signature and the path: a GUID and an age.
    const RSDS_HEADER: usize = 24;

    let mut record = Vec::new();
    record.extend_from_slice(b"RSDS");
    record.extend_from_slice(&[0x11; 16]); // a GUID, not read by anything here
    record.extend_from_slice(&1u32.to_le_bytes()); // age
    record.extend_from_slice(path.as_bytes());
    record.push(0);

    let at = pe.len();
    pe.resize(at + ENTRY_LEN + record.len(), 0);
    pe[at + 12..at + 16].copy_from_slice(&TYPE_CODEVIEW.to_le_bytes());
    pe[at + 16..at + 20].copy_from_slice(&(record.len() as u32).to_le_bytes());
    // The RVA is deliberately unmappable so that a reader preferring it finds
    // nothing: the file offset is the field that is correct here.
    pe[at + 20..at + 24].copy_from_slice(&0xDEAD_0000u32.to_le_bytes());
    pe[at + 24..at + 28].copy_from_slice(&((at + ENTRY_LEN) as u32).to_le_bytes());
    pe[at + ENTRY_LEN..].copy_from_slice(&record);

    let dirs = PE_AT + 4 + 20 + 96;
    const DIRECTORY_ENTRY_DEBUG: usize = 6;
    let entry = dirs + DIRECTORY_ENTRY_DEBUG * 8;
    pe[entry..entry + 4].copy_from_slice(&(at as u32).to_le_bytes());
    pe[entry + 4..entry + 8].copy_from_slice(&(ENTRY_LEN as u32).to_le_bytes());
    // `RSDS_HEADER` is what the reader has to skip; asserted here so that a
    // change to one without the other breaks this rather than the reader.
    debug_assert_eq!(RSDS_HEADER, 24);
    at
}

/// A `VS_VERSIONINFO` blob holding one `StringFileInfo` table of `entries`.
///
/// The tree the format describes, built to the format's own alignment rule: a
/// root whose value is the fifty-two-byte fixed file information, a
/// `StringFileInfo` container, one string table, and one node per entry.
///
/// Public because two crates need it: [`crate::version`]'s tests, which check
/// the walk, and the rule engine's, which point a rule at a file that has a
/// version resource and check that `pe.version_info["CompanyName"]` finds it.
/// A second copy of this layout in the other crate would be a second thing to
/// keep in step with the format, and the two would disagree the first time one
/// of them was corrected.
pub fn version_resource(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut strings = Vec::new();
    for (key, value) in entries {
        strings.extend_from_slice(&version_node(key, 1, &utf16_bytes(value), &[]));
    }
    let table = version_node("040904b0", 1, &[], &strings);
    let file_info = version_node("StringFileInfo", 1, &[], &table);
    version_node("VS_VERSION_INFO", 0, &[0u8; 52], &file_info)
}

/// Add `entries` to `pe` as a type-16 resource.
///
/// The whole path in one call: a caller that wants a file with a version
/// resource is not interested in the tree that carries it.
pub fn add_version_resource(pe: &mut Vec<u8>, entries: &[(&str, &str)]) -> ResourceLayout {
    let blob = version_resource(entries);
    add_resources(pe, &[ResourceSpec::new(16u32, 1u32, &[1033u32], &blob)])
}

/// One node of a `VS_VERSIONINFO` tree.
///
/// `kind` is the format's `wType`: `1` for text, whose `wValueLength` counts
/// UTF-16 units, and `0` for binary, whose counts bytes. `value` is written as
/// given; a caller building a text node passes [`utf16_bytes`].
pub fn version_node(key: &str, kind: u16, value: &[u8], children: &[u8]) -> Vec<u8> {
    let mut name = utf16_bytes(key);
    while (VERSION_HEADER_LEN + name.len()) % 4 != 0 {
        name.push(0);
    }

    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // length, patched below
    let value_length = match kind {
        1 => value.len() / 2,
        _ => value.len(),
    };
    out.extend_from_slice(&(value_length as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&name);
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(children);

    let length = out.len() as u16;
    out[0..2].copy_from_slice(&length.to_le_bytes());
    out
}

/// `text` as UTF-16LE with a NUL terminator.
pub fn utf16_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// The six bytes of header every `VS_VERSIONINFO` node begins with.
const VERSION_HEADER_LEN: usize = 6;

/// One level of a resource tree in a fixture: an integer id, or a name.
///
/// The two are different resources — `10` and `"10"` are not the same type, and
/// the format records which one an entry holds in a single bit. A test that
/// could not tell them apart could not test that a reader tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelSpec<'a> {
    /// An integer id.
    Id(u32),
    /// A name, written to the image as UTF-16LE.
    Name(&'a str),
}

impl<'a> From<u32> for LevelSpec<'a> {
    fn from(id: u32) -> Self {
        LevelSpec::Id(id)
    }
}

impl<'a> From<&'a str> for LevelSpec<'a> {
    fn from(name: &'a str) -> Self {
        LevelSpec::Name(name)
    }
}

/// One resource for [`add_resources`] to build: a path down the tree, and the
/// bytes at the end of it.
#[derive(Debug, Clone)]
pub struct ResourceSpec<'a> {
    type_level: LevelSpec<'a>,
    name_level: LevelSpec<'a>,
    languages: Vec<LevelSpec<'a>>,
    data: &'a [u8],
    declared_length: Option<u32>,
}

impl<'a> ResourceSpec<'a> {
    /// A resource of type `type_level` and name `name_level`, present in each of
    /// `languages`, whose bytes are `data`.
    ///
    /// Each argument takes either a `u32` or a `&str`, because every level can
    /// be either.
    pub fn new<T, N, L>(type_level: T, name_level: N, languages: &[L], data: &'a [u8]) -> Self
    where
        T: Into<LevelSpec<'a>>,
        N: Into<LevelSpec<'a>>,
        L: Into<LevelSpec<'a>> + Copy,
    {
        Self {
            type_level: type_level.into(),
            name_level: name_level.into(),
            languages: languages
                .iter()
                .map(|language| (*language).into())
                .collect(),
            data,
            declared_length: None,
        }
    }

    /// Declare a length other than the data's own, which is what a file that
    /// lies about a resource's size looks like.
    ///
    /// The bytes are still written where they are; only the number in the data
    /// entry changes. A declared length longer than the data therefore reads on
    /// into whatever follows, which is the whole point of being able to set it.
    pub fn with_length(mut self, length: u32) -> Self {
        self.declared_length = Some(length);
        self
    }
}

/// Where `.data`'s header sits in the fixture, and where its raw data starts.
const DATA_SECTION: usize = PE_AT + 4 + 20 + OPTIONAL_LEN_32 as usize + 40;
const DATA_AT: usize = 0x600;
const DATA_RVA: u32 = 0x2000;
/// Set in a directory entry's name or offset field to mark it as a name or a
/// subdirectory.
const HIGH_BIT: u32 = 0x8000_0000;

/// One language of one name, and the bytes behind it.
struct Leaf<'a> {
    language: LevelSpec<'a>,
    data: &'a [u8],
    declared_length: Option<u32>,
    /// Filled in by the layout pass.
    entry_at: usize,
    data_at: usize,
    name_at: usize,
}

/// One name: its language directory, and where everything under it goes.
struct NameDir<'a> {
    name: LevelSpec<'a>,
    at: usize,
    name_at: usize,
    leaves: Vec<Leaf<'a>>,
}

/// One type's names, as they are grouped before the layout pass: each name with
/// the languages it is present in.
type GroupedNames<'a> = Vec<(LevelSpec<'a>, Vec<Leaf<'a>>)>;

/// One type: its name directory, and where it goes.
struct TypeDir<'a> {
    type_level: LevelSpec<'a>,
    at: usize,
    name_at: usize,
    names: Vec<NameDir<'a>>,
}

impl<'a> TypeDir<'a> {
    /// The text of this level's name. Only called when it has one.
    fn type_level_text(&self) -> &'a str {
        match self.type_level {
            LevelSpec::Name(text) => text,
            LevelSpec::Id(_) => "",
        }
    }
}

impl<'a> NameDir<'a> {
    /// The text of this level's name. Only called when it has one.
    fn name_text(&self) -> &'a str {
        match self.name {
            LevelSpec::Name(text) => text,
            LevelSpec::Id(_) => "",
        }
    }
}

impl<'a> Leaf<'a> {
    /// The text of this level's name. Only called when it has one.
    fn language_text(&self) -> &'a str {
        match self.language {
            LevelSpec::Name(text) => text,
            LevelSpec::Id(_) => "",
        }
    }
}

/// Round `value` up to a multiple of `to`.
fn align(value: usize, to: usize) -> usize {
    value.div_ceil(to) * to
}

/// Whether a level is a name, for the named-before-id ordering the format wants.
fn is_name(level: LevelSpec<'_>) -> bool {
    matches!(level, LevelSpec::Name(_))
}

/// The value of an entry's name field for a level.
fn level_field(level: LevelSpec<'_>, name_at: usize) -> u32 {
    match level {
        LevelSpec::Id(id) => id,
        LevelSpec::Name(_) => HIGH_BIT | name_at as u32,
    }
}

/// Write a directory's two counts, which is all of its header that is not zero.
fn put_directory(block: &mut [u8], at: usize, named: u16, by_id: u16) {
    block[at + 12..at + 14].copy_from_slice(&named.to_le_bytes());
    block[at + 14..at + 16].copy_from_slice(&by_id.to_le_bytes());
}

/// Write one directory entry.
fn put_entry(block: &mut [u8], at: usize, name: u32, offset: u32) {
    block[at..at + 4].copy_from_slice(&name.to_le_bytes());
    block[at + 4..at + 8].copy_from_slice(&offset.to_le_bytes());
}

/// Write a name as the format stores it: a `u16` count of UTF-16 code units,
/// then the code units, and no terminator.
fn put_name(block: &mut [u8], at: usize, text: &str) {
    let units: Vec<u16> = text.encode_utf16().collect();
    block[at..at + 2].copy_from_slice(&(units.len() as u16).to_le_bytes());
    for (index, unit) in units.iter().enumerate() {
        block[at + 2 + index * 2..at + 4 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
}

/// Grow `.data` so that its raw data reaches `needed` bytes.
///
/// The resource block goes inside `.data` rather than past the last section, and
/// a section only maps the part of itself that has raw data: an RVA past
/// `SizeOfRawData` maps to nothing, and the reader would report every resource
/// as absent. Both the virtual and the raw size are raised together, which is
/// what the section table is for.
fn grow_data_section(pe: &mut Vec<u8>, needed: usize) {
    const FILE_ALIGNMENT: usize = 0x200;
    let len = align(needed, FILE_ALIGNMENT);
    if len > pe.len() {
        pe.resize(len, 0);
    }
    let raw = (pe.len() - DATA_AT) as u32;
    pe[DATA_SECTION + 8..DATA_SECTION + 12].copy_from_slice(&raw.to_le_bytes());
    pe[DATA_SECTION + 16..DATA_SECTION + 20].copy_from_slice(&raw.to_le_bytes());
}

/// Where [`add_resources`] put things, for a test that needs to corrupt one
/// field of the tree and watch the reader answer for it.
#[derive(Debug, Clone)]
pub struct ResourceLayout {
    /// The file offset of the resource directory itself — the root, whose
    /// entries are the types.
    pub directory: usize,
    /// The file offset of each leaf's third-level entry: the one whose offset
    /// field points at that leaf's data entry. In the order the specs were
    /// given.
    ///
    /// Not the data entry itself. The two are eight bytes and one indirection
    /// apart, and a test that flipped a bit in the wrong one would be flipping a
    /// length rather than a pointer while still looking like it worked.
    pub language_entries: Vec<usize>,
}

/// Build a resource tree and point the resource directory at it.
///
/// Returns where it put the parts a test may want to reach into. See
/// [`ResourceLayout`].
///
/// # Where it goes, and why
///
/// Inside `.data`, not appended past the last section as the import and export
/// builders do. A resource's data entry holds an **RVA**, and only a section
/// makes an RVA map to a different file offset: appended past the sections, an
/// unmapped RVA is returned unchanged by [`crate::PeFile::rva_to_offset`] and
/// the two members come out equal, which would leave the distinction between
/// them — the one a rule reads — untestable.
///
/// # What it writes
///
/// The real three-level tree: a root directory whose entries are types, a
/// directory per type whose entries are names, and a directory per name whose
/// entries are languages, each pointing at a data entry. Within every directory
/// the named entries are written before the id entries and the header says how
/// many of each, because that is what the format declares and what a loader
/// binary-searches over.
pub fn add_resources(pe: &mut Vec<u8>, specs: &[ResourceSpec<'_>]) -> ResourceLayout {
    // Group by type, then by name, in the order they were listed. Vectors rather
    // than maps because a fixture has a handful of specs and the listing order
    // is the order the tree lists them, which is what a test indexing
    // `pe.resources[0]` depends on.
    let mut types: Vec<(LevelSpec<'_>, GroupedNames<'_>)> = Vec::new();
    for spec in specs {
        let type_index = match types
            .iter()
            .position(|(level, _)| *level == spec.type_level)
        {
            Some(index) => index,
            None => {
                types.push((spec.type_level, Vec::new()));
                types.len() - 1
            }
        };
        let names = &mut types[type_index].1;
        let name_index = match names
            .iter()
            .position(|(level, _)| *level == spec.name_level)
        {
            Some(index) => index,
            None => {
                names.push((spec.name_level, Vec::new()));
                names.len() - 1
            }
        };
        for language in &spec.languages {
            names[name_index].1.push(Leaf {
                language: *language,
                data: spec.data,
                declared_length: spec.declared_length,
                entry_at: 0,
                data_at: 0,
                name_at: 0,
            });
        }
    }

    // The format puts named entries before id entries and says how many of each,
    // so the two groups have to be contiguous. A stable sort keeps the caller's
    // order inside each group.
    types.sort_by_key(|(level, _)| !is_name(*level));
    for (_, names) in &mut types {
        names.sort_by_key(|(level, _)| !is_name(*level));
    }

    let mut dirs: Vec<TypeDir<'_>> = types
        .into_iter()
        .map(|(type_level, names)| TypeDir {
            type_level,
            at: 0,
            name_at: 0,
            names: names
                .into_iter()
                .map(|(name, leaves)| NameDir {
                    name,
                    at: 0,
                    name_at: 0,
                    leaves,
                })
                .collect(),
        })
        .collect();

    // The layout: every offset is known before a byte is written, so the two
    // passes cannot disagree. Directory entries are relative to the start of the
    // resource directory, which is where the block begins.
    let mut at = 16 + dirs.len() * 8;
    for dir in &mut dirs {
        dir.at = at;
        at += 16 + dir.names.len() * 8;
    }
    for dir in &mut dirs {
        for name in &mut dir.names {
            name.at = at;
            at += 16 + name.leaves.len() * 8;
        }
    }
    at = align(at, 4);
    for dir in &mut dirs {
        for name in &mut dir.names {
            for leaf in &mut name.leaves {
                leaf.entry_at = at;
                at += 16;
            }
        }
    }
    for dir in &mut dirs {
        if is_name(dir.type_level) {
            at = align(at, 2);
            dir.name_at = at;
            at += 2 + dir.type_level_text().len() * 2;
        }
        for name in &mut dir.names {
            if is_name(name.name) {
                at = align(at, 2);
                name.name_at = at;
                at += 2 + name.name_text().len() * 2;
            }
            for leaf in &mut name.leaves {
                if is_name(leaf.language) {
                    at = align(at, 2);
                    leaf.name_at = at;
                    at += 2 + leaf.language_text().len() * 2;
                }
            }
        }
    }
    at = align(at, 4);
    for dir in &mut dirs {
        for name in &mut dir.names {
            for leaf in &mut name.leaves {
                leaf.data_at = at;
                at += leaf.data.len();
                at = align(at, 4);
            }
        }
    }

    let mut block = vec![0u8; at];
    // Collected as the tree is written, since that is the pass that knows where
    // each entry landed.
    let mut language_entries = Vec::new();

    // The root: one entry per type.
    put_directory(
        &mut block,
        0,
        dirs.iter().filter(|dir| is_name(dir.type_level)).count() as u16,
        dirs.iter().filter(|dir| !is_name(dir.type_level)).count() as u16,
    );
    for (index, dir) in dirs.iter().enumerate() {
        put_entry(
            &mut block,
            16 + index * 8,
            level_field(dir.type_level, dir.name_at),
            HIGH_BIT | dir.at as u32,
        );
    }

    for dir in &dirs {
        // One entry per name, pointing at that name's language directory.
        put_directory(
            &mut block,
            dir.at,
            dir.names.iter().filter(|name| is_name(name.name)).count() as u16,
            dir.names.iter().filter(|name| !is_name(name.name)).count() as u16,
        );
        for (index, name) in dir.names.iter().enumerate() {
            put_entry(
                &mut block,
                dir.at + 16 + index * 8,
                level_field(name.name, name.name_at),
                HIGH_BIT | name.at as u32,
            );
        }

        for name in &dir.names {
            // One entry per language, pointing at a data entry — the last level,
            // whose offset field has the high bit clear.
            put_directory(
                &mut block,
                name.at,
                name.leaves
                    .iter()
                    .filter(|leaf| is_name(leaf.language))
                    .count() as u16,
                name.leaves
                    .iter()
                    .filter(|leaf| !is_name(leaf.language))
                    .count() as u16,
            );
            for (index, leaf) in name.leaves.iter().enumerate() {
                let entry_at = name.at + 16 + index * 8;
                put_entry(
                    &mut block,
                    entry_at,
                    level_field(leaf.language, leaf.name_at),
                    leaf.entry_at as u32,
                );
                language_entries.push(entry_at);
                let length = leaf.declared_length.unwrap_or(leaf.data.len() as u32);
                block[leaf.entry_at..leaf.entry_at + 4]
                    .copy_from_slice(&(DATA_RVA + leaf.data_at as u32).to_le_bytes());
                block[leaf.entry_at + 4..leaf.entry_at + 8].copy_from_slice(&length.to_le_bytes());
                block[leaf.data_at..leaf.data_at + leaf.data.len()].copy_from_slice(leaf.data);
            }
        }
    }

    for dir in &dirs {
        if is_name(dir.type_level) {
            put_name(&mut block, dir.name_at, dir.type_level_text());
        }
        for name in &dir.names {
            if is_name(name.name) {
                put_name(&mut block, name.name_at, name.name_text());
            }
            for leaf in &name.leaves {
                if is_name(leaf.language) {
                    put_name(&mut block, leaf.name_at, leaf.language_text());
                }
            }
        }
    }

    assert!(
        block.len() < 0x4000,
        "the resource block has outgrown the fixture's data section; a shorter list is needed"
    );
    let base = DATA_AT;
    grow_data_section(pe, base + block.len());
    pe[base..base + block.len()].copy_from_slice(&block);
    set_directory(
        pe,
        crate::headers::directory::RESOURCE,
        DATA_RVA,
        block.len() as u32,
    );

    ResourceLayout {
        directory: base,
        language_entries: language_entries
            .into_iter()
            .map(|entry_at| base + entry_at)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PeFile;

    #[test]
    fn the_machine_setter_writes_the_field_the_parser_reads() {
        // The pair this module's two setters exist for. A caller that patched a
        // raw offset would be a second copy of the COFF header's layout in
        // another crate, and getting it wrong produces a fixture whose machine
        // type is whatever byte happened to be next to it — a test that passes
        // for a reason nobody can name.
        let mut pe = minimal_pe64();
        assert_eq!(PeFile::parse(&pe).unwrap().machine(), 0x014C, "the builder's own value");
        set_machine(&mut pe, 0x8664);
        assert_eq!(PeFile::parse(&pe).unwrap().machine(), 0x8664);
    }

    #[test]
    fn the_subsystem_setter_writes_the_field_the_parser_reads() {
        let mut pe = minimal_pe64();
        assert_eq!(PeFile::parse(&pe).unwrap().subsystem(), 2, "the builder's own value");
        set_subsystem(&mut pe, 1);
        assert_eq!(PeFile::parse(&pe).unwrap().subsystem(), 1);
    }

    #[test]
    fn both_setters_work_on_both_optional_header_layouts() {
        // `Subsystem` is past the point where the two layouts diverge, which is
        // what lets one offset serve both — and is exactly the assumption that
        // would be wrong if somebody moved it. `Machine` is in the COFF header
        // and is layout-independent, checked here so that the claim is tested on
        // both fixtures rather than asserted about one.
        for mut pe in [minimal_pe32(), minimal_pe64()] {
            set_machine(&mut pe, 0xAA64);
            set_subsystem(&mut pe, 3);
            let parsed = PeFile::parse(&pe).unwrap();
            assert_eq!(parsed.machine(), 0xAA64, "is_64bit={}", parsed.is_64bit());
            assert_eq!(parsed.subsystem(), 3, "is_64bit={}", parsed.is_64bit());
        }
    }

    #[test]
    fn the_setters_do_not_disturb_the_fields_around_them() {
        // `Machine` sits between the PE signature and `NumberOfSections`, and
        // `Subsystem` sits between `MinorSubsystemVersion` and
        // `Win32VersionValue`. A setter that wrote one byte too many would be
        // caught by the neighbouring field rather than by a test of its own.
        let mut pe = minimal_pe64();
        // Read into numbers rather than holding the parsed image, which borrows
        // the bytes the setters are about to write into.
        let before = {
            let parsed = PeFile::parse(&pe).unwrap();
            (
                parsed.is_64bit(),
                parsed.entry_point(),
                parsed.image_base(),
                parsed.section_alignment(),
                parsed.subsystem_version_major(),
                parsed.subsystem_version_minor(),
            )
        };
        set_machine(&mut pe, 0x8664);
        set_subsystem(&mut pe, 1);
        let parsed = PeFile::parse(&pe).unwrap();

        assert_eq!(
            (
                parsed.is_64bit(),
                parsed.entry_point(),
                parsed.image_base(),
                parsed.section_alignment(),
                parsed.subsystem_version_major(),
                parsed.subsystem_version_minor(),
            ),
            before,
            "a setter wrote outside the field it was asked to change"
        );
    }
}
