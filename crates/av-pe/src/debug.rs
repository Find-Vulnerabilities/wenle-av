//! The debug directory, and the one thing in it a rule reads: the path of the
//! PDB the linker was given.
//!
//! # What is in there
//!
//! `IMAGE_DIRECTORY_ENTRY_DEBUG` points at an array of `IMAGE_DEBUG_DIRECTORY`
//! entries, twenty-eight bytes each. Most of them describe something the
//! toolchain emitted for a debugger — line-number tables, frame data, a
//! precompiled type server — and one kind, `IMAGE_DEBUG_TYPE_CODEVIEW`,
//! describes the *source*: which program database the linker was reading when it
//! produced this image.
//!
//! # Why a scanner cares
//!
//! Because a build server is a fixed thing. The path recorded in a CodeView
//! record is the path on the machine that linked the file, and it is not
//! something an author usually remembers to scrub: it names the project
//! directory, often the author's account name, and sometimes the malware
//! family's own working title. The corpus reads it as a fingerprint of a build
//! environment — `pe.pdb_path contains "\\FlowCloud\\trunk\\"` selects
//! everything one particular builder produced, whether or not this sample's
//! code has changed since.
//!
//! It is also *stable*. Two samples from the same builder share the prefix even
//! when nothing else about them matches, which makes this the cheapest
//! family-level signal in the header — the whole reader is a directory walk and
//! a string comparison, with no parsing of the code.
//!
//! # The two record formats
//!
//! Both are terminated by a NUL and both are preceded by a fixed header:
//!
//! ```text
//! RSDS   signature   "RSDS"   4 bytes
//!        guid       16 bytes
//!        age         4 bytes
//!        path        the PDB path, NUL-terminated
//!
//! NB10   signature   "NB10"   4 bytes
//!        offset      4 bytes
//!        timestamp   4 bytes
//!        age         4 bytes
//!        path        the PDB path, NUL-terminated
//! ```
//!
//! `RSDS` is what every current toolchain writes and `NB10` is the format
//! Microsoft's older compilers wrote. Both are still declared as
//! `IMAGE_DEBUG_TYPE_CODEVIEW` — the signature is the only thing that
//! distinguishes them — so a reader that knows only `RSDS` reports no PDB for
//! anything built before roughly 1998, which is a real category of sample
//! precisely because old binaries are cheap to keep and still run.
//!
//! # Where the bytes are
//!
//! An entry locates its payload twice: `AddressOfRawData` is an RVA and
//! `PointerToRawData` is a file offset. They usually agree. Two things make a
//! reader prefer the file offset:
//!
//! - The debug directory is one of the few structures Windows reads from the
//!   file rather than from the loaded image, so a linker is entitled to write
//!   the offset, and some do.
//! - An RVA can only be resolved through the section table, and a section table
//!   is exactly what a packer withholds. The file offset does not depend on it.
//!
//! So the offset is read first and the RVA is the fallback, which is the
//! reverse of the order for every other directory in this crate — and the reason
//! the order is worth stating rather than assuming.
//!
//! [`crate::pe::PeFile::rva_to_offset`]'s quirk — an RVA in no section is
//! returned unchanged — is what makes the fallback work for the files that need
//! it. Those files store a file offset in the RVA field, and a value that is a
//! file offset is by definition in no section, so it comes back exactly as it
//! went in. The value that was written is the value that is read.

use crate::headers::directory;
use crate::pe::PeFile;
use crate::read::Reader;

/// The size of one `IMAGE_DEBUG_DIRECTORY`.
const ENTRY_LEN: usize = 28;

/// How many entries the walk examines.
///
/// A real image has a handful. The bound is here because the count comes from
/// the directory's size, which the file chooses, and a directory claiming four
/// gigabytes of entries must not become four gigabytes of reading.
const MAX_ENTRIES: usize = 64;

/// `IMAGE_DEBUG_TYPE_CODEVIEW`, the only kind this module reads.
const TYPE_CODEVIEW: u32 = 2;

/// The two CodeView signatures.
const RSDS: &[u8] = b"RSDS";
const NB10: &[u8] = b"NB10";

/// Bytes between the `RSDS` signature and the path: a GUID and an age.
const RSDS_HEADER: usize = 24;

/// Bytes between the `NB10` signature and the path: an offset, a timestamp and
/// an age.
const NB10_HEADER: usize = 16;

/// How long a PDB path may be.
///
/// A bound rather than a fact: the record is NUL-terminated, and this is the
/// largest window the terminator is looked for in. Windows' own limit on a path
/// is 32,767 characters, so 4,096 is generous for a path that is being used as a
/// fingerprint, and it stops a record whose NUL is missing from running to the
/// end of the file.
const MAX_PATH: usize = 4096;

/// A file's debug directory, as far as a rule can read it.
///
/// Empty for a file with no debug directory, no CodeView record, or a record
/// whose payload does not lie inside the file — none of which is an error.
/// "This image was stripped" is a fact about a file, and a common one: every
/// release build Microsoft shipped for thirty years was stripped, and so is
/// everything a packer has been through.
#[derive(Debug, Clone, Default)]
pub struct DebugDirectory<'a> {
    /// The CodeView path, without its terminating NUL. Empty when there is none.
    pdb_path: &'a [u8],
    /// How many entries were examined.
    entries: usize,
    /// The signature of the record the path came from, when there was one:
    /// `RSDS` or `NB10`. Kept so that "no PDB" and "a PDB with an empty path"
    /// are distinguishable to a caller that wants to know which it has.
    signature: Option<&'a [u8]>,
}

impl<'a> DebugDirectory<'a> {
    /// The path of the PDB the linker read, without its terminating NUL.
    ///
    /// Empty when the file carries no CodeView record, which is the answer for
    /// every stripped image. Not an error and not `None`: `pe.pdb_path` is a
    /// string in every rule that names it, and a rule comparing it against
    /// something is asking whether this file came from that build machine. The
    /// answer for a stripped file is no.
    pub fn pdb_path(&self) -> &'a [u8] {
        self.pdb_path
    }

    /// How many debug directory entries were examined.
    pub fn number_of_entries(&self) -> usize {
        self.entries
    }

    /// Whether a CodeView record was found at all.
    ///
    /// The distinction from an empty [`pdb_path`](Self::pdb_path): a file whose
    /// record is present but names no path is a file that *has* a debug
    /// directory, which is itself worth a rule, and this is how a caller tells
    /// that case from the far more common stripped one.
    pub fn has_codeview(&self) -> bool {
        self.signature.is_some()
    }

    /// Whether the directory held nothing readable.
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}

/// Read a file's debug directory.
///
/// Returns an empty one for any file without a readable CodeView record. See
/// [`DebugDirectory`] for why that is the answer rather than an error.
pub fn read<'a>(pe: &PeFile<'a>) -> DebugDirectory<'a> {
    let empty = DebugDirectory::default();
    let debug = pe.data_directory(directory::DEBUG);
    if !debug.is_present() {
        return empty;
    }
    let reader = pe.reader();

    // The directory's own address is an RVA in every linker that writes one; the
    // fallback is the same accident described in the module docs, and it costs
    // one line to accept.
    let start = pe.rva_to_offset(debug.virtual_address) as usize;
    let Ok(table) = reader.slice(start, debug.size as usize) else {
        return empty;
    };
    let entries = (table.len() / ENTRY_LEN).min(MAX_ENTRIES);

    let mut found = DebugDirectory { entries, ..empty };
    for index in 0..entries {
        let at = start + index * ENTRY_LEN;
        // A malformed entry is skipped rather than ending the walk: the array is
        // a list of independent records, and one the file got wrong says nothing
        // about the next.
        if reader.u32(at + 12).ok() != Some(TYPE_CODEVIEW) {
            continue;
        }
        let size = reader.u32(at + 16).unwrap_or(0) as usize;
        let rva = reader.u32(at + 20).unwrap_or(0);
        let raw = reader.u32(at + 24).unwrap_or(0);
        for offset in [raw as usize, pe.rva_to_offset(rva) as usize] {
            let Some((signature, path)) = codeview(reader, offset, size) else {
                continue;
            };
            found.signature = Some(signature);
            found.pdb_path = path;
            return found;
        }
    }
    found
}

/// The signature and path of the CodeView record at `offset`, if one is there.
///
/// `None` when the record does not lie inside the file or does not begin with a
/// signature this module knows. The second case matters: an entry of type
/// `CODEVIEW` whose payload is something else is a file contradicting itself,
/// and guessing at an unknown layout would read bytes out of the middle of a
/// structure and offer them to a rule as a path.
fn codeview<'a>(reader: &Reader<'a>, offset: usize, size: usize) -> Option<(&'a [u8], &'a [u8])> {
    // The window is the entry's own declared size, capped at the file. A record
    // claiming more than the file holds is read up to the end of the file rather
    // than refused: the header is still there, and the path is usually short.
    let limit = size.min(reader.len().saturating_sub(offset));
    let signature = reader.slice(offset, 4).ok()?;
    let header = match signature {
        s if s == RSDS => RSDS_HEADER,
        s if s == NB10 => NB10_HEADER,
        _ => return None,
    };
    if limit <= header {
        return None;
    }
    let path = reader
        .cstr(offset + header, (limit - header).min(MAX_PATH))
        .ok()?;
    Some((signature, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::minimal_pe32;

    /// A PE with a debug directory holding one CodeView record.
    ///
    /// Built by hand rather than through a helper, because the point of these
    /// tests is the layout: an encoder that shared code with the reader would
    /// agree with it about a wrong layout.
    fn with_debug(record: &[u8]) -> Vec<u8> {
        let mut data = minimal_pe32();
        // Both grew past the fixture's 0x400 bytes, so the buffer is extended
        // and the new tail is what the directory points at.
        let table_at = data.len();
        data.resize(table_at + ENTRY_LEN + record.len(), 0);
        let entry = table_at;
        // Characteristics and timestamp stay zero.
        data[entry + 12..entry + 16].copy_from_slice(&TYPE_CODEVIEW.to_le_bytes());
        data[entry + 16..entry + 20].copy_from_slice(&(record.len() as u32).to_le_bytes());
        // The RVA is deliberately wrong, so that a reader preferring it over the
        // file offset finds nothing. `PointerToRawData` is the one that is right.
        let payload = (table_at + ENTRY_LEN) as u32;
        data[entry + 20..entry + 24].copy_from_slice(&0xDEAD_0000u32.to_le_bytes());
        data[entry + 24..entry + 28].copy_from_slice(&payload.to_le_bytes());
        data[table_at + ENTRY_LEN..].copy_from_slice(record);

        // And point the data directory at the table. The fixture is PE32, so the
        // directory array starts 96 bytes into the optional header.
        let dirs = optional_header(&data) + 96;
        let at = dirs + directory::DEBUG * 8;
        data[at..at + 4].copy_from_slice(&(table_at as u32).to_le_bytes());
        data[at + 4..at + 8].copy_from_slice(&(ENTRY_LEN as u32).to_le_bytes());
        data
    }

    /// Where the optional header starts, read the way the loader reads it.
    fn optional_header(data: &[u8]) -> usize {
        let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        lfanew + 4 + 20
    }

    /// The file offset of one entry in the data directory array.
    ///
    /// `96` is where the array starts in a PE32 optional header, which is the
    /// only width these fixtures have. Written once here rather than in each
    /// test because the first version of these tests left the `96` out, and the
    /// mistake is invisible: the write lands inside the optional header, the
    /// entry the test meant to change is untouched, and the assertion that fails
    /// is several steps away from the arithmetic that was wrong.
    fn directory_entry(data: &[u8], index: usize) -> usize {
        optional_header(data) + 96 + index * 8
    }

    /// The `(virtual_address, size)` pair a directory entry holds.
    fn directory_at(data: &[u8], index: usize) -> (u32, u32) {
        let at = directory_entry(data, index);
        let word = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        (word(at), word(at + 4))
    }

    fn rsds(path: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(RSDS);
        record.extend_from_slice(&[0x11; 16]); // a GUID
        record.extend_from_slice(&1u32.to_le_bytes()); // age
        record.extend_from_slice(path);
        record.push(0);
        record
    }

    fn nb10(path: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(NB10);
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&1u32.to_le_bytes());
        record.extend_from_slice(path);
        record.push(0);
        record
    }

    fn read_path(data: &[u8]) -> String {
        let pe = PeFile::parse(data).expect("the fixture is a PE");
        String::from_utf8_lossy(read(&pe).pdb_path()).into_owned()
    }

    #[test]
    fn an_rsds_record_yields_its_path() {
        // The corpus's own shape: a build machine's directory, backslashes and
        // all, which is what makes this a fingerprint rather than a filename.
        let data = with_debug(&rsds(b"C:\\build\\FlowCloud\\trunk\\agent.pdb"));
        assert_eq!(
            read_path(&data),
            "C:\\build\\FlowCloud\\trunk\\agent.pdb",
            "the path is the bytes after the twenty-four-byte header"
        );
    }

    #[test]
    fn an_nb10_record_yields_its_path() {
        // The older layout, which is sixteen bytes of header rather than
        // twenty-four. Reading it as `RSDS` would slice eight bytes off the
        // front of the path and eight off the end, which is the mistake this
        // test exists to catch.
        let data = with_debug(&nb10(b"D:\\src\\legacy\\thing.pdb"));
        assert_eq!(read_path(&data), "D:\\src\\legacy\\thing.pdb");
    }

    #[test]
    fn a_file_with_no_debug_directory_has_no_path() {
        let data = minimal_pe32();
        let pe = PeFile::parse(&data).expect("the fixture is a PE");
        let debug = read(&pe);
        assert!(debug.pdb_path().is_empty());
        assert!(!debug.has_codeview());
        assert!(debug.is_empty());
        assert_eq!(debug.number_of_entries(), 0);
    }

    #[test]
    fn a_debug_directory_with_no_codeview_entry_has_no_path() {
        // The entry is there and is a different kind — line numbers, say. The
        // directory is not empty, and the path still is: a reader that answered
        // "there is a path" from the directory's presence alone would offer a
        // rule whatever bytes followed the entry.
        let mut data = with_debug(&rsds(b"x.pdb"));
        let (table, _) = directory_at(&data, directory::DEBUG);
        let entry = table as usize;
        data[entry + 12..entry + 16].copy_from_slice(&9u32.to_le_bytes());
        let pe = PeFile::parse(&data).expect("the fixture is a PE");
        let debug = read(&pe);
        assert_eq!(debug.number_of_entries(), 1);
        assert!(!debug.has_codeview());
        assert!(debug.pdb_path().is_empty());
    }

    #[test]
    fn an_unknown_signature_is_not_a_path() {
        // Type `CODEVIEW` with a payload that is not one. The bytes after the
        // signature are a real string, and reading them anyway would be reading
        // a structure this reader does not know the layout of.
        let mut record = Vec::new();
        record.extend_from_slice(b"XXXX");
        record.extend_from_slice(b"not-a-path-at-all\0");
        assert_eq!(read_path(&with_debug(&record)), "");
    }

    #[test]
    fn the_file_offset_is_preferred_over_the_rva() {
        // The fixture writes a deliberately unmappable RVA. That the path still
        // comes back is the whole assertion: the order of the two candidates is
        // what makes a stripped-section file readable.
        let data = with_debug(&rsds(b"C:\\a.pdb"));
        assert_eq!(read_path(&data), "C:\\a.pdb");
    }

    #[test]
    fn a_record_past_the_end_of_the_file_is_no_path() {
        // A truncated file: the directory is intact and the record it points at
        // is not. The scan data is not truncated, so this is a file that lied
        // rather than one that was cut short.
        let mut data = with_debug(&rsds(b"C:\\a.pdb"));
        let (table, _) = directory_at(&data, directory::DEBUG);
        let entry = table as usize;
        data[entry + 24..entry + 28].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        let pe = PeFile::parse(&data).expect("the fixture is a PE");
        assert!(read(&pe).pdb_path().is_empty());
    }

    #[test]
    fn a_path_with_no_terminator_stops_at_the_record() {
        // The NUL is missing, which happens when a tool truncates the record.
        // The path must stop where the record does rather than running into
        // whatever the file put next.
        let mut record = Vec::new();
        record.extend_from_slice(RSDS);
        record.extend_from_slice(&[0x11; 16]);
        record.extend_from_slice(&1u32.to_le_bytes());
        record.extend_from_slice(b"C:\\no-terminator.pdb");
        assert_eq!(read_path(&with_debug(&record)), "C:\\no-terminator.pdb");
    }
}
