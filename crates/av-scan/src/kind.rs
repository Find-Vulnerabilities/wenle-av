//! What kind of file this is, decided from its bytes first and its name second.
//!
//! # Why this exists at all
//!
//! The cheapest large speed-up available to a scanner is not scanning. A `.txt`
//! file has no import table and no section table, so every rule that asks
//! `pe.sections[0].name` is a rule that cannot possibly fire, and evaluating
//! ten thousand of them to find that out is the difference between a scan that
//! finishes while the user is watching and one that does not. The rule
//! prefilter already refutes most of them cheaply, but it can only refute at
//! all because it knows a rule's strings; a rule whose condition is entirely
//! `pe.*` members has no string to offer it.
//!
//! # Bytes before names
//!
//! A file's *name* is chosen by whoever wrote it and, in the case of malware,
//! chosen to mislead. Its first bytes are a property of its format and cannot
//! be re-labelled. So magic is consulted first and an extension is a fallback
//! for the formats that have no dependable magic — which is most scripts, since
//! a shell script is text.
//!
//! The one place a name wins is a compound file: `.msi`, `.doc` and `.xls` all
//! begin with the same OLE signature, and only the extension separates an
//! installer from a document. That is not a compromise, because confusing those
//! two costs nothing here — both are non-executable as far as the rule set is
//! concerned.

use std::path::Path;

use av_core::FileKind;
use av_pe::headers::directory;
use av_rules::vm::PeInput;

/// How many leading bytes are needed to recognise every format below.
///
/// Every one except [`LNK_CLASS_ID`], which is checked against the buffer
/// directly — see the note at its use.
const MAGIC_LEN: usize = 8;

/// The class identifier every Windows shortcut's header carries.
///
/// Not a magic number in the usual sense: it is
/// `{00021401-0000-0000-C000-000000000046}`, the shell link's own CLSID, and it
/// is preceded by the header's size as a `u32`.
const LNK_CLASS_ID: &[u8] =
    b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46";

/// Classify a file from its leading bytes, falling back to its extension.
///
/// `path` is optional because a scan target can be an archive member or a
/// memory region with no name; `data` is not, because a file with no bytes has
/// no format.
pub fn classify(path: Option<&Path>, data: &[u8]) -> FileKind {
    if let Some(kind) = from_magic(path, data) {
        return kind;
    }
    path.and_then(extension_of)
        .map_or(FileKind::Other, |ext| from_extension(&ext))
}

/// Upgrade a `Pe` classification to `DotNet` once the image has been parsed.
///
/// Split from [`classify`] rather than folded into it because answering it
/// needs the data directory table, and the caller is going to parse the image
/// anyway. Parsing twice to save a parameter would be the wrong trade in a
/// function that runs once per file either way.
pub fn refine(kind: FileKind, pe: &PeInput<'_>) -> FileKind {
    if kind != FileKind::Pe {
        return kind;
    }
    // The COM descriptor directory is present exactly when the loader will run
    // the CLR on this image, which is the definition of a managed assembly.
    // Note that it is a *directory*, not a bit in some flags word: a file can
    // set `IMAGE_FILE_DLL` and import `mscoree.dll` and still not be managed.
    match pe
        .pe()
        .data_directory(directory::COM_DESCRIPTOR)
        .is_present()
    {
        true => FileKind::DotNet,
        false => FileKind::Pe,
    }
}

/// The format a set of leading bytes announces, if it announces one.
fn from_magic(path: Option<&Path>, data: &[u8]) -> Option<FileKind> {
    if data.is_empty() {
        return None;
    }
    let head = &data[..data.len().min(MAGIC_LEN)];
    let ext = path.and_then(extension_of);

    // An executable image. DotNet is decided later, from the data directories.
    if head.starts_with(b"MZ") {
        return Some(FileKind::Pe);
    }

    // Zip, and everything built on it: OOXML documents, JARs, APKs, and plain
    // archives. The three signatures are the local file header, the empty
    // archive, and a spanned archive.
    if head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"PK\x05\x06")
        || head.starts_with(b"PK\x07\x08")
    {
        return Some(match ext.as_deref() {
            Some("docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "pptm" | "dotx" | "xltx") => {
                FileKind::Document
            }
            _ => FileKind::Archive,
        });
    }

    // OLE compound file: the container for legacy Office documents, and also
    // for Windows Installer packages and Outlook message stores. The signature
    // is identical for all of them, so the name decides.
    if head.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return Some(match ext.as_deref() {
            Some("msi" | "msp" | "mst") => FileKind::Archive,
            _ => FileKind::Document,
        });
    }

    if head.starts_with(b"%PDF-") || head.starts_with(b"{\\rtf") {
        // Both are documents, and both are in this taxonomy's `Exploit` band:
        // the kind exists for formats that are not executable and are routinely
        // made to execute anyway, which is what a PDF with a JavaScript action
        // and an RTF with an object update are.
        return Some(FileKind::Exploit);
    }

    // A Windows shortcut. Its header is a fixed 76 bytes and the first four are
    // the size; the class identifier that follows is what makes it reliable.
    //
    // Checked against the whole buffer rather than against `head`, because this
    // magic is the one in this function longer than [`MAGIC_LEN`] and a
    // `starts_with` against a shorter slice is false for every file — a mistake
    // that reads as "we do not recognise shortcuts" rather than as an error.
    if data.starts_with(LNK_CLASS_ID) {
        return Some(FileKind::Shortcut);
    }

    // Archives, by their own magic rather than by extension. `MSCF` is a
    // cabinet, which is also an installer container.
    for (magic, kind) in ARCHIVE_MAGIC {
        if head.starts_with(magic) {
            return Some(*kind);
        }
    }

    // Script interpreters, which announce themselves in the first two bytes.
    if head.starts_with(b"#!") {
        return Some(FileKind::Script);
    }

    None
}

/// Archive signatures, and the kind each one is.
///
/// A table rather than a `match` on the first byte, because `BZh` and `MSCF`
/// share no prefix structure with the rest and a chain of `starts_with` reads
/// better as data than as control flow.
const ARCHIVE_MAGIC: &[(&[u8], FileKind)] = &[
    (b"Rar!\x1a\x07", FileKind::Archive),
    (b"7z\xbc\xaf\x27\x1c", FileKind::Archive),
    (b"MSCF", FileKind::Archive),
    (b"\x1f\x8b", FileKind::Archive),
    (b"BZh", FileKind::Archive),
    (b"\xfd7zXZ\x00", FileKind::Archive),
    (b"\x28\xb5\x2f\xfd", FileKind::Archive),
];

/// The format an extension claims, for files whose bytes do not say.
fn from_extension(ext: &str) -> FileKind {
    match ext {
        // Executable images. `scr` and `cpl` are ordinary PEs that Windows
        // launches from a double-click, which is why they are worth their own
        // entries rather than being left to magic — a `.scr` that is *not* a PE
        // is a file whose name is lying, and the rule set has rules for that.
        "exe" | "dll" | "sys" | "ocx" | "cpl" | "scr" | "com" | "drv" | "efi" | "mui" => {
            FileKind::Pe
        }
        // Managed assemblies are also PEs; the extension is all that is
        // available when the bytes could not be read.
        "netmodule" | "winmd" => FileKind::DotNet,

        "bat" | "cmd" | "ps1" | "psm1" | "psd1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "wsh"
        | "hta" | "reg" | "inf" | "scf" | "shb" | "lnk_script" => FileKind::Script,

        "doc" | "xls" | "ppt" | "docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "pptm" | "dot"
        | "dotm" | "dotx" | "xlt" | "xltm" | "one" | "vsd" | "msg" | "pub" => FileKind::Document,

        "pdf" | "rtf" | "chm" | "hlp" => FileKind::Exploit,

        "lnk" | "url" | "pif" => FileKind::Shortcut,

        "zip" | "rar" | "7z" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "cab" | "msi" | "msp"
        | "mst" | "jar" | "apk" | "iso" | "img" | "vhd" | "wim" | "arj" | "lzh" | "z" => {
            FileKind::Archive
        }

        _ => FileKind::Other,
    }
}

/// The lowercased extension, without its dot.
///
/// Lossy for a name that is not valid UTF-8, which is the right direction: an
/// extension is a hint, and a hint that cannot be read is no hint rather than a
/// reason to fail.
fn extension_of(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?;
    Some(ext.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_pe::testing::{minimal_pe32, minimal_pe64};
    use std::path::PathBuf;

    fn named(name: &str, data: &[u8]) -> FileKind {
        classify(Some(&PathBuf::from(name)), data)
    }

    #[test]
    fn magic_beats_a_misleading_extension() {
        // The whole point of consulting bytes first: a text file called
        // `invoice.pdf.exe` is an executable, and a PE called `readme.txt` is
        // still an executable.
        assert_eq!(named("readme.txt", &minimal_pe32()), FileKind::Pe);
        assert_eq!(named("invoice.pdf", &minimal_pe32()), FileKind::Pe);
    }

    #[test]
    fn a_zip_is_a_document_only_when_the_name_says_so() {
        let zip = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(named("a.zip", zip), FileKind::Archive);
        assert_eq!(named("a.docx", zip), FileKind::Document);
        // An extension this taxonomy does not know falls back to the format
        // rather than to `Other`: it is still a zip, and a rule about archive
        // members should still be given the chance to run.
        assert_eq!(named("a.wibble", zip), FileKind::Archive);
    }

    #[test]
    fn an_ole_container_is_split_by_name() {
        let ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00";
        assert_eq!(named("report.doc", ole), FileKind::Document);
        assert_eq!(named("installer.msi", ole), FileKind::Archive);
        // No name at all is the common case for an archive member, and a
        // document is the safer default: it is the kind that reaches fewer
        // executable-specific rules.
        assert_eq!(classify(None, ole), FileKind::Document);
    }

    #[test]
    fn an_extension_only_decides_when_magic_says_nothing() {
        assert_eq!(named("run.bat", b"@echo off\r\n"), FileKind::Script);
        assert_eq!(named("run.ps1", b"Write-Host 1"), FileKind::Script);
        assert_eq!(named("a.rar", b"Rar!\x1a\x07\x00"), FileKind::Archive);
        assert_eq!(named("a.7z", b"7z\xbc\xaf\x27\x1c\x00"), FileKind::Archive);
        assert_eq!(named("a.gz", b"\x1f\x8b\x08\x00"), FileKind::Archive);
        assert_eq!(named("a.cab", b"MSCF\x00\x00\x00\x00"), FileKind::Archive);
    }

    #[test]
    fn a_script_with_a_shebang_needs_no_extension() {
        assert_eq!(named("tool", b"#!/bin/sh\necho hi\n"), FileKind::Script);
    }

    #[test]
    fn a_pdf_and_an_rtf_are_the_formats_made_to_execute() {
        assert_eq!(named("a.pdf", b"%PDF-1.7\n"), FileKind::Exploit);
        assert_eq!(named("a.rtf", b"{\\rtf1\\ansi"), FileKind::Exploit);
        // Even with no name, because the magic is unambiguous.
        assert_eq!(classify(None, b"%PDF-1.4\n"), FileKind::Exploit);
    }

    #[test]
    fn a_shortcut_is_recognised_by_its_class_identifier() {
        let lnk =
            b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46";
        assert_eq!(named("a.lnk", lnk), FileKind::Shortcut);
        assert_eq!(named("mystery", lnk), FileKind::Shortcut);
        // The extension alone is enough when the bytes are unreadable, which is
        // how a shortcut whose header is corrupt still reaches the rules for it.
        assert_eq!(named("a.lnk", b"\x00\x00\x00\x00"), FileKind::Shortcut);
        assert_eq!(
            named("a.url", b"[InternetShortcut]\r\n"),
            FileKind::Shortcut
        );
    }

    #[test]
    fn an_unknown_file_is_other_rather_than_a_guess() {
        assert_eq!(named("notes.txt", b"hello, world\n"), FileKind::Other);
        assert_eq!(named("data", b"\x00\x01\x02\x03"), FileKind::Other);
        assert_eq!(classify(None, b"\x00\x01\x02\x03"), FileKind::Other);
    }

    #[test]
    fn an_empty_file_has_no_format() {
        // Not `Pe`, not `Other` by accident: there is nothing to read, and the
        // caller is told so rather than being handed a classification made up
        // from the name of a file that has no bytes.
        assert_eq!(named("empty.exe", b""), FileKind::Pe);
        assert_eq!(named("empty.xyz", b""), FileKind::Other);
    }

    #[test]
    fn extensions_are_matched_without_regard_to_case() {
        assert_eq!(named("RUN.BAT", b"@echo off"), FileKind::Script);
        assert_eq!(named("A.DOCX", b"PK\x03\x04\x14\x00"), FileKind::Document);
        assert_eq!(named("A.RAR", b"Rar!\x1a\x07\x00"), FileKind::Archive);
    }

    #[test]
    fn a_dotnet_dll_is_reported_as_a_dll_before_parsing() {
        // `classify` cannot see the data directories, so a managed assembly is
        // `Pe` and `refine` is what upgrades it. Asserting the first half pins
        // the split; the second half is covered by the `refine` test below.
        assert_eq!(named("a.dll", &minimal_pe32()), FileKind::Pe);
        assert_eq!(
            refine(FileKind::Script, &pe_input(&minimal_pe32())),
            FileKind::Script
        );
    }

    #[test]
    fn refine_only_touches_pe() {
        let data = minimal_pe64();
        let pe = pe_input(&data);
        assert_eq!(refine(FileKind::Pe, &pe), FileKind::Pe);
        assert_eq!(refine(FileKind::Archive, &pe), FileKind::Archive);
        assert_eq!(refine(FileKind::Other, &pe), FileKind::Other);
    }

    fn pe_input(data: &[u8]) -> PeInput<'_> {
        PeInput::parse(data).expect("the fixture is a PE")
    }
}
