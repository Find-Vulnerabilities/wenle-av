//! The import table: which libraries a file binds to, and which symbols in them.
//!
//! # What a rule asks
//!
//! Three shapes, all of them predicates over this table:
//!
//! ```text
//! pe.number_of_imports > 16 and pe.number_of_imports < 19
//! pe.imports ( "ADVAPI32.dll" )
//! pe.imports ( "kernel32.dll" , "VirtualAlloc" )
//! pe.imphash ( ) == "655ad5439db0832c5a3f86d0a68ddaac"
//! ```
//!
//! # The count is libraries, not symbols
//!
//! `pe.number_of_imports` answers with the number of *descriptors* — the number
//! of distinct libraries the file binds to — and not the number of imported
//! functions. The corpus fixes this rather than a preference: the rule at line
//! 209349 lists seventeen DLL names and then bounds the member with
//! `> 16 and < 19`. A count of functions would not track a list of libraries.
//!
//! [`Imports::function_count`] is the other number, and it is available for
//! anything that wants it. The two are kept apart because a single member
//! answering whichever one the caller assumed is a rule that silently means
//! something else.
//!
//! # What can go wrong in a hostile file
//!
//! Every field below is an offset or a count read out of the file, and each one
//! is used to reach further into the same file. The classic failures — a
//! descriptor count of four billion, a thunk chain that loops back on itself,
//! a name pointer into the middle of the header — are each handled by a bound
//! rather than by trust, and the bounds are named constants so that a reader can
//! see what the ceiling is instead of inferring it.

use crate::headers::{directory, DataDirectory};
use crate::pe::PeFile;
use crate::read::Reader;

/// Size of one `IMAGE_IMPORT_DESCRIPTOR`.
const DESCRIPTOR_LEN: usize = 20;

/// Size of one thunk in a PE32 file.
const THUNK_LEN_32: usize = 4;
/// Size of one thunk in a PE32+ file.
const THUNK_LEN_64: usize = 8;

/// Set in a PE32 thunk when the entry is an ordinal rather than a name.
const ORDINAL_FLAG_32: u32 = 0x8000_0000;
/// The same bit in a PE32+ thunk.
const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000;

/// The low sixteen bits of a PE32 ordinal thunk.
const ORDINAL_MASK: u64 = 0xffff;

/// The most descriptors that will be walked.
///
/// A file can declare an import directory of any size; the array's real end is
/// the all-zero descriptor, which a hostile file can simply never write. Four
/// thousand libraries is far past any real binary — the largest Windows system
/// binaries import from around a hundred — and costs nothing to allow.
const MAX_DESCRIPTORS: usize = 4096;

/// The most thunks that will be walked in one descriptor.
///
/// The same reasoning one level down. Sixty-five thousand symbols from a single
/// library is past any real import table and bounds the walk independently of
/// the descriptor bound, so a file with one descriptor and a self-referencing
/// thunk chain still terminates.
const MAX_THUNKS: usize = 65_536;

/// The longest library or symbol name that will be read.
///
/// Real names are far shorter; the limit is what stops a file whose name pointer
/// lands in a region of non-zero bytes from reading to the end of the mapping
/// looking for a terminator that is not there.
const MAX_NAME: usize = 512;

/// One imported symbol.
///
/// Borrows from the file's own bytes rather than owning a `String`: a scan
/// walks this table for its hash, for a name comparison, and for a count, and
/// allocating a `String` for each of the thousands of symbols in a large binary
/// would be paid on every scan for values most rules never look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Import<'a> {
    /// The library's name as the file writes it, without a terminator.
    pub library: &'a [u8],
    /// The symbol's name, or `None` when the file imports it by ordinal.
    pub name: Option<&'a [u8]>,
    /// The ordinal, meaningful only when `name` is `None`.
    pub ordinal: u16,
}

impl Import<'_> {
    /// The symbol as text, or `None` if the bytes are not UTF-8.
    pub fn name_text(&self) -> Option<&str> {
        self.name.and_then(|n| std::str::from_utf8(n).ok())
    }

    /// The library as text, or `None` if the bytes are not UTF-8.
    pub fn library_text(&self) -> Option<&str> {
        std::str::from_utf8(self.library).ok()
    }
}

/// The import table of a file.
///
/// One pass over the descriptors, done once and kept, because a rule set asks
/// the same file for the same table several times over — a count, a library
/// presence check per rule, an imphash — and re-walking the thunk chains for
/// each of those is the same work repeated on the scan's hot path.
#[derive(Debug, Clone)]
pub struct Imports<'a> {
    entries: Vec<Import<'a>>,
    /// The number of descriptors, which is what `pe.number_of_imports` answers.
    libraries: usize,
}

impl<'a> Imports<'a> {
    /// Every imported symbol, in the order the file lists them.
    pub fn entries(&self) -> &[Import<'a>] {
        &self.entries
    }

    /// How many libraries the file binds to — the descriptors, not the symbols.
    pub fn library_count(&self) -> usize {
        self.libraries
    }

    /// How many symbols are imported in total.
    pub fn function_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether the file imports anything at all from `library`.
    ///
    /// The comparison is ASCII-case-insensitive, because a library name reaches
    /// the file as a filename and Windows resolves filenames without regard to
    /// case. The corpus depends on this: one rule writes `ADVAPI32.dll`,
    /// `GDI32.dll`, `WINSPOOL.DRV` and `gdiplus.dll` in a single condition, in
    /// three different cases, against files that each hold one spelling.
    pub fn has_library(&self, library: impl AsRef<[u8]>) -> bool {
        let library = library.as_ref();
        self.entries
            .iter()
            .any(|entry| eq_ignore_ascii_case(entry.library, library))
    }

    /// Whether the file imports `symbol` from `library`.
    ///
    /// The symbol comparison is **case-sensitive** where the library one is not,
    /// and the asymmetry is deliberate. A library name is a filename, which
    /// Windows resolves case-insensitively, so two spellings really do name the
    /// same library. A symbol name is an exact byte string that the loader
    /// matches exactly, so `CreateFileW` and `createfilew` are different symbols
    /// and a rule naming one does not name the other. Answering `true` for the
    /// second would be a detection that fires on a file the rule was not written
    /// about, which is the failure worth avoiding.
    pub fn has_function(&self, library: impl AsRef<[u8]>, symbol: impl AsRef<[u8]>) -> bool {
        let (library, symbol) = (library.as_ref(), symbol.as_ref());
        self.entries
            .iter()
            .any(|entry| eq_ignore_ascii_case(entry.library, library) && entry.name == Some(symbol))
    }

    /// Whether the file imports `symbol` from any library.
    pub fn has_symbol(&self, symbol: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.name == Some(symbol.as_bytes()))
    }

    /// The MD5 of the normalized import list — the "imphash".
    ///
    /// # What it is
    ///
    /// The imports are rewritten as `library.symbol`, both lowercased, with the
    /// library's extension dropped when it is `.dll`, `.ocx` or `.sys`; joined
    /// with commas in the file's own order; and hashed. It is not a security
    /// primitive — it is a grouping key. Two builds of the same malware family
    /// compiled with the same libraries and the same link order produce the same
    /// imphash, and it survives the byte-level changes that break a byte
    /// signature. 371 rules in this corpus compare against it, which makes it
    /// the second-largest single lever in the rule set after the certificates.
    ///
    /// # The one case it does not match a table-carrying tool on
    ///
    /// An import by ordinal has no name in the file. The usual implementation
    /// substitutes the published name for the ordinal, but only for `ws2_32.dll`
    /// and `oleaut32.dll` — the two libraries whose ordinal-to-name mapping is
    /// documented — and falls back to `ord<N>` for everything else, which is
    /// exactly what this does for *everything*.
    ///
    /// So a sample that imports from those two libraries by ordinal hashes
    /// differently here than it would under a tool carrying the table, and a
    /// rule written against such a sample does not match. The table is around
    /// nine hundred hand-transcribed names; a single wrong entry in it is a
    /// silently wrong hash for every sample that touches that ordinal, and
    /// nothing in a scan would report the error. Reporting `ord<N>` uniformly
    /// is a bounded, statable gap; a mis-transcribed table is an unbounded one.
    ///
    /// A file that imports nothing hashes the empty string, which is the
    /// algorithm's answer and not an error: `d41d8cd98f00b204e9800998ecf8427e`.
    pub fn imphash(&self) -> String {
        let mut text = String::with_capacity(self.entries.len() * 24);
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                text.push(',');
            }
            for byte in strip_library_extension(entry.library) {
                text.push(byte.to_ascii_lowercase() as char);
            }
            text.push('.');
            match entry.name {
                Some(name) => {
                    for &byte in name {
                        text.push(byte.to_ascii_lowercase() as char);
                    }
                }
                None => {
                    text.push_str("ord");
                    text.push_str(&entry.ordinal.to_string());
                }
            }
        }
        use md5::{Digest, Md5};
        colon_free_hex(&Md5::digest(text.as_bytes()))
    }
}

/// The library name with a trailing `.dll`, `.ocx` or `.sys` removed.
///
/// Only those three, and only in that position: the algorithm's definition, and
/// a file that names its library something else keeps the whole name. Removing
/// a different extension would move the hash away from every rule written
/// against a tool that removes exactly these.
fn strip_library_extension(library: &[u8]) -> &[u8] {
    const EXTENSIONS: [&[u8]; 3] = [b"dll", b"ocx", b"sys"];
    let Some(dot) = library.iter().rposition(|&b| b == b'.') else {
        return library;
    };
    let extension = &library[dot + 1..];
    if EXTENSIONS
        .iter()
        .any(|known| eq_ignore_ascii_case(extension, known))
    {
        &library[..dot]
    } else {
        library
    }
}

/// Lowercase hex, no separators — the form a hash comparison uses.
///
/// Deliberately not the colon-separated form [`crate::pe`] uses for certificate
/// serials. The two live in the same rule files and the corpus distinguishes
/// them: every `imphash` literal is 32 characters and every `serial` literal is
/// 47 or 50.
fn colon_free_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// ASCII-case-insensitive equality, without allocating.
fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Read a file's import table.
///
/// A file with no import directory, or with one that points nowhere, yields an
/// empty table rather than an error: a resource-only DLL is a legal and ordinary
/// file, and making its absence an error would make the common path the error
/// path.
pub fn read<'a>(pe: &PeFile<'a>) -> Imports<'a> {
    let entry = pe.data_directory(directory::IMPORT);
    if !entry.is_present() {
        return Imports {
            entries: Vec::new(),
            libraries: 0,
        };
    }
    let reader = pe.reader();
    let mut entries = Vec::new();
    let mut libraries = 0usize;
    let thunk_len = if pe.is_64bit() {
        THUNK_LEN_64
    } else {
        THUNK_LEN_32
    };

    for index in 0..MAX_DESCRIPTORS {
        let Some(at) = descriptor_offset(pe, &entry, index) else {
            break;
        };
        let descriptor = match reader.slice(at, DESCRIPTOR_LEN) {
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        // The array ends with an all-zero descriptor rather than a count.
        if descriptor.iter().all(|&b| b == 0) {
            break;
        }
        let original_first_thunk =
            u32::from_le_bytes([descriptor[0], descriptor[1], descriptor[2], descriptor[3]]);
        let name_rva = u32::from_le_bytes([
            descriptor[12],
            descriptor[13],
            descriptor[14],
            descriptor[15],
        ]);
        let first_thunk = u32::from_le_bytes([
            descriptor[16],
            descriptor[17],
            descriptor[18],
            descriptor[19],
        ]);

        libraries += 1;

        let Some(library) = read_name(reader, pe, name_rva) else {
            continue;
        };
        // The ILT is the authoritative list. A file that has been bound has had
        // its IAT overwritten with resolved addresses, so the IAT is only a
        // fallback for the files — older and hand-written ones — that leave
        // `OriginalFirstThunk` zero.
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        if thunk_rva == 0 {
            continue;
        }

        for thunk_index in 0..MAX_THUNKS {
            let Some(entry_value) = read_thunk(pe, reader, thunk_rva, thunk_index, thunk_len)
            else {
                break;
            };
            if entry_value == 0 {
                break;
            }
            let ordinal_flag = if thunk_len == THUNK_LEN_64 {
                ORDINAL_FLAG_64
            } else {
                u64::from(ORDINAL_FLAG_32)
            };
            if entry_value & ordinal_flag != 0 {
                entries.push(Import {
                    library,
                    name: None,
                    ordinal: (entry_value & ORDINAL_MASK) as u16,
                });
                continue;
            }
            // A named import points at an `IMAGE_IMPORT_BY_NAME`: a `u16` hint
            // followed by the name. The hint is skipped rather than read,
            // because the loader may or may not honour it and no rule asks.
            let name_rva = entry_value as u32;
            let Some(symbol) = read_name(reader, pe, name_rva.wrapping_add(2)) else {
                continue;
            };
            entries.push(Import {
                library,
                name: Some(symbol),
                ordinal: 0,
            });
        }
    }

    Imports { entries, libraries }
}

/// The file offset of the `index`-th descriptor.
///
/// The descriptors are an array of `DESCRIPTOR_LEN` bytes starting at the
/// import directory's address, which is an RVA like any other. The multiplication
/// is checked because `index` is bounded only by [`MAX_DESCRIPTORS`] and the sum
/// by the directory's own address, which the file chose.
fn descriptor_offset(pe: &PeFile<'_>, entry: &DataDirectory, index: usize) -> Option<usize> {
    let offset = u32::try_from(index.checked_mul(DESCRIPTOR_LEN)?).ok()?;
    let rva = entry.virtual_address.checked_add(offset)?;
    usize::try_from(pe.rva_to_offset(rva)).ok()
}

/// One thunk, or `None` if it cannot be read.
fn read_thunk<'a>(
    pe: &PeFile<'a>,
    reader: &Reader<'a>,
    thunk_rva: u32,
    index: usize,
    thunk_len: usize,
) -> Option<u64> {
    let offset = index.checked_mul(thunk_len)?;
    if offset > u64::from(u32::MAX) as usize {
        return None;
    }
    let rva = thunk_rva.checked_add(offset as u32)?;
    let file_offset = usize::try_from(pe.rva_to_offset(rva)).ok()?;
    if thunk_len == THUNK_LEN_64 {
        reader.u64(file_offset).ok()
    } else {
        reader.u32(file_offset).ok().map(u64::from)
    }
}

/// A NUL-terminated name at an RVA, if there is one.
///
/// A name that is not valid UTF-8 is still a name — the format does not require
/// it to be — so the bytes are returned as they are and the text accessors
/// answer `None` for them. Refusing the whole table because one symbol has a
/// byte above 0x7f would lose every other import in the file.
fn read_name<'a>(reader: &Reader<'a>, pe: &PeFile<'a>, rva: u32) -> Option<&'a [u8]> {
    if rva == 0 {
        return None;
    }
    let file_offset = usize::try_from(pe.rva_to_offset(rva)).ok()?;
    // The window is clamped to what is actually left in the buffer rather than
    // being a flat `MAX_NAME`. A name near the end of a small file has fewer
    // than `MAX_NAME` bytes after it, and asking for the full window would make
    // the read fail — turning a short file into a file with no imports at all.
    let available = reader.len().saturating_sub(file_offset).min(MAX_NAME);
    if available == 0 {
        return None;
    }
    let name = reader.cstr(file_offset, available).ok()?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        add_imports, minimal_pe32, minimal_pe64, set_directory, DIRECTORY_IMPORT,
    };

    #[test]
    fn a_file_with_no_import_directory_has_an_empty_table() {
        // An ordinary case, not an error: a resource-only DLL imports nothing.
        let image = minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        let imports = read(&pe);
        assert_eq!(imports.library_count(), 0);
        assert_eq!(imports.function_count(), 0);
        assert!(!imports.has_library("kernel32.dll"));
        assert!(!imports.has_function("kernel32.dll", "CreateFileW"));
        assert!(!imports.has_symbol("CreateFileW"));
    }

    #[test]
    fn a_named_import_is_read_with_its_library() {
        let mut image = minimal_pe32();
        add_imports(
            &mut image,
            &[("KERNEL32.dll", &["CreateFileW", "VirtualAlloc"])],
        );
        let pe = PeFile::parse(&image).unwrap();
        let imports = read(&pe);
        assert_eq!(imports.library_count(), 1);
        assert_eq!(imports.function_count(), 2);
        assert!(imports.has_library("KERNEL32.dll"));
        assert!(imports.has_function("KERNEL32.dll", "CreateFileW"));
        assert!(imports.has_function("KERNEL32.dll", "VirtualAlloc"));
        assert!(!imports.has_function("KERNEL32.dll", "CreateFileA"));
        assert_eq!(imports.entries()[0].name_text(), Some("CreateFileW"));
        assert_eq!(imports.entries()[0].library_text(), Some("KERNEL32.dll"));
    }

    #[test]
    fn the_library_comparison_ignores_case_and_the_symbol_one_does_not() {
        // The rule at line 209349 writes `ADVAPI32.dll`, `GDI32.dll` and
        // `gdiplus.dll` in one condition; a file holds one spelling of each.
        // The same rule's `pe.imports("kernel32.dll", "VirtualAlloc")` names a
        // symbol the loader matches exactly.
        let mut image = minimal_pe32();
        add_imports(&mut image, &[("KERNEL32.dll", &["VirtualAlloc"])]);
        let pe = PeFile::parse(&image).unwrap();
        let imports = read(&pe);

        for spelling in ["KERNEL32.dll", "kernel32.dll", "Kernel32.DLL"] {
            assert!(imports.has_library(spelling), "{spelling}");
        }
        assert!(!imports.has_library("KERNEL32"));

        assert!(imports.has_function("kernel32.dll", "VirtualAlloc"));
        assert!(!imports.has_function("kernel32.dll", "virtualalloc"));
    }

    #[test]
    fn a_one_argument_check_asks_only_whether_the_library_is_there() {
        let mut image = minimal_pe32();
        add_imports(&mut image, &[("USER32.dll", &["MessageBoxA"])]);
        let pe = PeFile::parse(&image).unwrap();
        let imports = read(&pe);
        assert!(imports.has_library("USER32.dll"));
        assert!(imports.has_symbol("MessageBoxA"));
        assert!(!imports.has_symbol("MessageBoxW"));
    }

    #[test]
    fn the_import_count_is_the_number_of_libraries_not_of_symbols() {
        // The corpus pins this: seventeen DLL names sit beside
        // `pe.number_of_imports > 16 and pe.number_of_imports < 19`.
        let mut image = minimal_pe32();
        add_imports(
            &mut image,
            &[
                ("ADVAPI32.dll", &["RegOpenKeyExW", "RegSetValueExW"]),
                ("GDI32.dll", &["BitBlt"]),
                ("USER32.dll", &["MessageBoxA", "CreateWindowExW", "GetDC"]),
            ],
        );
        let pe = PeFile::parse(&image).unwrap();
        let imports = read(&pe);
        assert_eq!(imports.library_count(), 3, "three libraries");
        assert_eq!(imports.function_count(), 6, "six symbols");
    }

    #[test]
    fn the_imphash_is_the_md5_of_the_normalized_library_dot_symbol_list() {
        // Computed from the algorithm's definition rather than from a recorded
        // value: lowercase, the library's extension dropped, joined with commas.
        let mut image = minimal_pe32();
        add_imports(
            &mut image,
            &[
                ("KERNEL32.dll", &["CreateFileW", "VirtualAlloc"]),
                ("USER32.dll", &["MessageBoxA"]),
            ],
        );
        let pe = PeFile::parse(&image).unwrap();
        let imports = read(&pe);
        // The digest of that exact string, taken from an independent MD5 rather
        // than from this crate's own hasher — so the test is a cross-check of
        // the *normalization* and not two calls to the same function agreeing:
        //
        //   printf '%s' 'kernel32.createfilew,...' | md5sum
        assert_eq!(
            imports.imphash(),
            "73f978df3b6a9b2bb9d2866e501af07a".to_string()
        );
        assert_eq!(imports.imphash().len(), 32);
        // A different normalization — the extension kept, or the case preserved
        // — hashes to something else entirely, which is what makes the
        // normalization the thing worth testing.
        assert_ne!(
            format!("{:x}", {
                use md5::{Digest, Md5};
                Md5::digest(
                    b"KERNEL32.dll.CreateFileW,KERNEL32.dll.VirtualAlloc,USER32.dll.MessageBoxA",
                )
            }),
            imports.imphash()
        );
    }

    #[test]
    fn only_dll_ocx_and_sys_are_stripped_from_a_library_name() {
        assert_eq!(strip_library_extension(b"KERNEL32.dll"), b"KERNEL32");
        assert_eq!(strip_library_extension(b"KERNEL32.DLL"), b"KERNEL32");
        assert_eq!(strip_library_extension(b"MSCOMCTL.ocx"), b"MSCOMCTL");
        assert_eq!(strip_library_extension(b"driver.sys"), b"driver");
        // Not an extension the algorithm removes, so it stays.
        assert_eq!(strip_library_extension(b"WINSPOOL.DRV"), b"WINSPOOL.DRV");
        assert_eq!(strip_library_extension(b"noextension"), b"noextension");
        assert_eq!(
            strip_library_extension(b"api-ms-win-core.dll"),
            b"api-ms-win-core"
        );
        // An empty extension is not one of the three.
        assert_eq!(strip_library_extension(b"trailing."), b"trailing.");
    }

    #[test]
    fn an_empty_import_table_hashes_the_empty_string() {
        // The algorithm's answer for a file that imports nothing, and the value
        // a rule comparing against the MD5 of nothing would be written with.
        let image = minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        assert_eq!(
            read(&pe).imphash(),
            "d41d8cd98f00b204e9800998ecf8427e".to_string()
        );
    }

    #[test]
    fn an_ordinal_import_is_read_as_an_ordinal() {
        let mut image = minimal_pe32();
        crate::testing::add_ordinal_import(&mut image, "WS2_32.dll", &[3, 4]);
        let pe = PeFile::parse(&image).unwrap();
        let imports = read(&pe);
        assert_eq!(imports.function_count(), 2);
        assert_eq!(imports.entries()[0].name, None);
        assert_eq!(imports.entries()[0].ordinal, 3);
        assert_eq!(imports.entries()[1].ordinal, 4);
        // The hash reports the ordinal rather than a name it does not have.
        // Independently taken: `printf '%s' 'ws2_32.ord3,ws2_32.ord4' | md5sum`.
        assert_eq!(
            imports.imphash(),
            "65d8e6227924d79d1f53449bc559b814".to_string()
        );
    }

    #[test]
    fn the_sixty_four_bit_thunks_are_read_at_eight_bytes_each() {
        // Reading a PE32+ table at four bytes a thunk walks into the middle of
        // each entry and produces names that are not names.
        let mut image = minimal_pe64();
        add_imports(&mut image, &[("KERNEL32.dll", &["CreateFileW"])]);
        let pe = PeFile::parse(&image).unwrap();
        assert!(pe.is_64bit());
        let imports = read(&pe);
        assert_eq!(imports.function_count(), 1);
        assert_eq!(imports.entries()[0].name_text(), Some("CreateFileW"));
    }

    #[test]
    fn an_import_directory_past_the_end_of_the_file_is_an_empty_table() {
        // The directory's RVA comes out of the header and is used to index into
        // the file. A file whose header claims a directory that is not there
        // must yield no imports rather than a read past the buffer — and must
        // not fail either, because a damaged sample with an intact header is
        // still a sample worth scanning.
        let mut image = minimal_pe32();
        add_imports(&mut image, &[("KERNEL32.dll", &["CreateFileW"])]);

        let past_end = u32::try_from(image.len()).unwrap() + 0x1000;
        set_directory(&mut image, DIRECTORY_IMPORT, past_end, 0x40);

        let pe = PeFile::parse(&image).unwrap();
        let imports = read(&pe);
        assert_eq!(imports.library_count(), 0);
        assert_eq!(imports.function_count(), 0);
        // The hash of nothing, which is what the algorithm defines for a file
        // with no imports and not a special case in the reader.
        assert_eq!(
            imports.imphash(),
            "d41d8cd98f00b204e9800998ecf8427e".to_string()
        );
    }
}
