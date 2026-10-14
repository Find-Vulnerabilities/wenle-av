//! The interpreter.
//!
//! Runs a compiled condition against a buffer and a table of string matches.
//!
//! # One machine, reused
//!
//! A scan runs thousands of conditions over the same buffer. [`Vm`] holds the
//! operand stack and a scratch of its own so that running a rule allocates
//! nothing: the scanner creates one `Vm` and calls [`Vm::run`] per rule. That
//! is the whole reason the compiler computes `max_stack` rather than letting
//! the interpreter grow a `Vec` as it goes.
//!
//! # Undefined, again
//!
//! Every operation that cannot be given a meaning yields [`Value::Undefined`]
//! rather than an error or a zero: `uint32(0xFFFFFFF0)` on a short buffer,
//! `@a[5]` on a string that matched twice, `1 / 0`. The rule then fails its
//! comparison, which is the correct outcome — the file has not been shown to be
//! malicious — and it fails without a special case at every call site. Turning
//! any of these into `0` would be much worse than it sounds: `pe.entry_point`
//! reading as `0` makes `pe.entry_point == 0` fire on every file that is not a
//! PE, which is precisely the false positive this design exists to avoid.
//!
//! # Bounds
//!
//! Nothing here indexes a program without checking. A [`Program`] can arrive
//! from a memory-mapped database, and a database is a file — one bit-flip in an
//! instruction operand must not become an out-of-bounds read in the scanner.
//! Every jump target, constant index and string slot is verified, and a
//! malformed program yields [`VmError`] rather than undefined behaviour.
//! Conditions from the compiler are correct by construction, so these checks
//! never fire in practice; they are what makes the database format safe to
//! trust.

use std::collections::HashMap;

use av_core::stats;
use av_pe::{
    DebugDirectory, DotNet, Exports, Imports, PeError, PeFile, Resources, RichSignature, Section,
    VersionInfo,
};
use av_signatures::Certificate;

use crate::ast::CmpOp;
use crate::matches::MatchSet;
use crate::program::{
    Cmp, DotNetElement, DotNetField, ModuleFunc, Op, PeElement, PeField, PeFunc, Program,
    RegexSpec, Value, MAX_LOOP_ITERATIONS,
};

/// A parsed PE together with everything the `pe` module reads out of it.
///
/// # Why it is one value
///
/// Each of these is read *through* the PE — the certificate table, the import
/// descriptors and the export directory are all found by a header field — so
/// none of them can be extracted without one. Keeping them in separate fields
/// of [`Input`] would let a caller attach a PE and forget the tables, and the
/// symptom would be `pe.number_of_signatures == 0` for a signed file, or an
/// empty import list for a file that has one: a rule that silently stops
/// matching, which is the failure mode this whole engine is built to avoid.
/// Pairing them means the mistake cannot be written down.
///
/// # Why they are read eagerly
///
/// A scan runs ten thousand conditions over one buffer. Parsing inside the
/// interpreter would be ten thousand parses, so every table is read once here
/// and kept. The cost of reading a table no rule asks about is one walk of a
/// small structure; the cost of not having read one a rule *does* ask about is
/// a false negative, and those are not the same size of mistake.
#[derive(Debug)]
pub struct PeInput<'a> {
    pe: PeFile<'a>,
    signatures: Vec<Certificate<'a>>,
    imports: Imports<'a>,
    exports: Exports<'a>,
    resources: Resources<'a>,
    rich: RichSignature,
    debug: DebugDirectory<'a>,
    version: VersionInfo,
    dotnet: DotNet<'a>,
}

impl<'a> PeInput<'a> {
    /// Parse `data` as a PE and read every table the module exposes.
    ///
    /// Fails only when the buffer is not a PE at all. A file with no signature,
    /// no imports, no exports or no resources is not a failure — each is the
    /// ordinary case for some kind of file, and each yields an empty table.
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        let pe = PeFile::parse(data)?;
        let signatures = av_signatures::certificates(&pe);
        let imports = av_pe::imports::read(&pe);
        let exports = av_pe::exports::read(&pe);
        let resources = av_pe::resources::read(&pe);
        let rich = av_pe::rich::read(&pe);
        let debug = av_pe::debug::read(&pe);
        let version = av_pe::version::read(&pe, resources.leaves());
        let dotnet = av_pe::dotnet::read(&pe);
        Ok(Self {
            pe,
            signatures,
            imports,
            exports,
            resources,
            rich,
            debug,
            version,
            dotnet,
        })
    }

    /// The parsed image.
    pub fn pe(&self) -> &PeFile<'a> {
        &self.pe
    }

    /// Every certificate in the attribute certificate table, in file order.
    pub fn signatures(&self) -> &[Certificate<'a>] {
        &self.signatures
    }

    /// The file's import table.
    pub fn imports(&self) -> &Imports<'a> {
        &self.imports
    }

    /// The file's export table.
    pub fn exports(&self) -> &Exports<'a> {
        &self.exports
    }

    /// The file's resource tree, flattened to its leaves.
    pub fn resources(&self) -> &Resources<'a> {
        &self.resources
    }

    /// The file's Rich header, or an empty one when it has none.
    pub fn rich_signature(&self) -> &RichSignature {
        &self.rich
    }

    /// The file's debug directory, which is where `pe.pdb_path` comes from.
    pub fn debug(&self) -> &DebugDirectory<'a> {
        &self.debug
    }

    /// The file's version resource, which is what `pe.version_info` reads.
    pub fn version_info(&self) -> &VersionInfo {
        &self.version
    }

    /// The file's managed metadata, which is what the `dotnet` module reads.
    pub fn dotnet(&self) -> &DotNet<'a> {
        &self.dotnet
    }
}

/// The buffer a condition is evaluated against.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    pub data: &'a [u8],
    /// Entry point offset, when the file-type layer identified one.
    ///
    /// `None` for anything that is not an executable image, which makes
    /// `entrypoint` undefined rather than zero.
    pub entry_point: Option<u64>,
    /// The parsed PE and its signatures, when the buffer is one.
    ///
    /// Borrowed rather than owned so that this type stays `Copy`.
    pub pe: Option<&'a PeInput<'a>>,
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            entry_point: None,
            pe: None,
        }
    }

    pub fn with_entry_point(data: &'a [u8], entry_point: Option<u64>) -> Self {
        Self {
            data,
            entry_point,
            pe: None,
        }
    }

    /// Attach a parsed PE.
    ///
    /// Attaching one also fills in `entrypoint`, which for a PE is the file
    /// offset of `AddressOfEntryPoint` — the same value the deprecated
    /// `entrypoint` keyword reported, and therefore the value rules were
    /// written against. Setting it here rather than leaving it to the caller is
    /// what stops the two from disagreeing.
    pub fn with_pe(data: &'a [u8], pe: &'a PeInput<'a>) -> Self {
        Self {
            data,
            entry_point: Some(pe.pe().entry_point()),
            pe: Some(pe),
        }
    }
}

/// `pe.<member>` for a file, or `Undefined` when it is not a PE.
///
/// [`PeField::IsPe`] is the exception and the reason this takes the input rather
/// than the file: it is the one member a rule can ask of a buffer that is not a
/// PE, and it answers `0` rather than nothing.
fn pe_field(input: &Input<'_>, member: PeField) -> Value {
    if member == PeField::IsPe {
        return Value::Int(i64::from(input.pe.is_some()));
    }
    let Some(image) = input.pe else {
        return Value::Undefined;
    };
    let pe = image.pe();
    let int = |v: u64| Value::Int(v as i64);
    match member {
        // Handled above; repeated so that adding a member is a compile error
        // here rather than a silently wrong answer.
        PeField::IsPe => Value::Int(1),
        PeField::IsDll => int(u64::from(pe.is_dll())),
        PeField::Is32Bit => int(u64::from(pe.is_32bit())),
        PeField::Is64Bit => int(u64::from(pe.is_64bit())),
        PeField::Machine => int(u64::from(pe.machine())),
        PeField::Timestamp => int(u64::from(pe.timestamp())),
        PeField::Characteristics => int(u64::from(pe.characteristics())),
        PeField::Subsystem => int(u64::from(pe.subsystem())),
        PeField::DllCharacteristics => int(u64::from(pe.dll_characteristics())),
        PeField::EntryPoint => int(pe.entry_point()),
        PeField::EntryPointRaw => int(u64::from(pe.entry_point_raw())),
        PeField::ImageBase => int(pe.image_base()),
        PeField::SizeOfImage => int(u64::from(pe.size_of_image())),
        PeField::SizeOfHeaders => int(u64::from(pe.size_of_headers())),
        PeField::Checksum => int(u64::from(pe.checksum())),
        PeField::SectionAlignment => int(u64::from(pe.section_alignment())),
        PeField::FileAlignment => int(u64::from(pe.file_alignment())),
        PeField::NumberOfRvaAndSizes => int(u64::from(pe.number_of_rva_and_sizes())),
        PeField::BaseOfCode => int(u64::from(pe.base_of_code())),
        PeField::BaseOfData => int(u64::from(pe.base_of_data())),
        PeField::SizeOfCode => int(u64::from(pe.size_of_code())),
        PeField::SizeOfInitializedData => int(u64::from(pe.size_of_initialized_data())),
        PeField::SizeOfUninitializedData => int(u64::from(pe.size_of_uninitialized_data())),
        PeField::SizeOfStackReserve => int(pe.size_of_stack_reserve()),
        PeField::SizeOfStackCommit => int(pe.size_of_stack_commit()),
        PeField::SizeOfHeapReserve => int(pe.size_of_heap_reserve()),
        PeField::SizeOfHeapCommit => int(pe.size_of_heap_commit()),
        PeField::LinkerVersionMajor => int(u64::from(pe.linker_version_major())),
        PeField::LinkerVersionMinor => int(u64::from(pe.linker_version_minor())),
        PeField::OsVersionMajor => int(u64::from(pe.os_version_major())),
        PeField::OsVersionMinor => int(u64::from(pe.os_version_minor())),
        PeField::ImageVersionMajor => int(u64::from(pe.image_version_major())),
        PeField::ImageVersionMinor => int(u64::from(pe.image_version_minor())),
        PeField::SubsystemVersionMajor => int(u64::from(pe.subsystem_version_major())),
        PeField::SubsystemVersionMinor => int(u64::from(pe.subsystem_version_minor())),
        PeField::OpthdrMagic => int(u64::from(pe.opthdr_magic())),
        PeField::PointerToSymbolTable => int(u64::from(pe.pointer_to_symbol_table())),
        PeField::NumberOfSymbols => int(u64::from(pe.number_of_symbols())),
        PeField::SizeOfOptionalHeader => int(u64::from(pe.size_of_optional_header())),
        PeField::LoaderFlags => int(u64::from(pe.loader_flags())),
        PeField::Win32VersionValue => int(u64::from(pe.win32_version_value())),
        PeField::OverlayOffset => int(pe.overlay().offset),
        PeField::OverlaySize => int(pe.overlay().size),
        PeField::NumberOfSections => int(u64::from(pe.number_of_sections())),
        PeField::NumberOfSignatures => int(image.signatures().len() as u64),
        PeField::NumberOfImports => int(image.imports().library_count() as u64),
        PeField::NumberOfExports => int(image.exports().function_count() as u64),
        PeField::NumberOfResources => int(image.resources().len() as u64),
        PeField::RichSignatureLength => int(image.rich_signature().length() as u64),
        // The bytes themselves. Not a string in any encoding and not hashed
        // here: the twenty corpus rules that read this member hash it
        // themselves, and hashing it in the module would be a second
        // implementation of `hash.md5` that no rule asked for.
        PeField::RichSignatureClearData => {
            Value::Bytes(std::sync::Arc::from(image.rich_signature().clear_data()))
        }
        // The path the linker recorded, as the bytes the file holds — not
        // decoded and not lossily converted. A rule comparing it against a
        // build directory is comparing bytes, and a path with a character the
        // `char` type cannot represent must not become a different path on the
        // way through.
        PeField::PdbPath => Value::Bytes(std::sync::Arc::from(image.debug().pdb_path())),
    }
}

/// `dotnet.<member>` for a file, or `Undefined` when it is not an assembly.
///
/// [`DotNetField::IsDotNet`] is the exception here for the reason
/// [`PeField::IsPe`] is the exception in [`pe_field`]: it is the one member a
/// rule can ask of a buffer that is not an assembly, and it answers `0` rather
/// than nothing. Unlike `IsPe` it does not need the `input` rather than the
/// file — it is the *presence* of the module that it reports, and the module is
/// present for any buffer whose PE parse produced a CLI-header directory.
/// Asking it before the `input.pe` check is still what makes it answer for a
/// buffer that is not a PE at all.
///
/// `Undefined` rather than zero for every other member of a file that is not an
/// assembly, which is the distinction [`DotNetField::NumberOfResources`] is
/// written around: a count read from a table that was never there is not a
/// count of zero.
fn dotnet_field(input: &Input<'_>, member: DotNetField) -> Value {
    let present = input.pe.is_some_and(|image| image.dotnet().is_dotnet());
    if member == DotNetField::IsDotNet {
        return Value::Int(i64::from(present));
    }
    let Some(image) = input.pe else {
        return Value::Undefined;
    };
    let assembly = image.dotnet();
    let int = |v: u64| Value::Int(v as i64);
    match member {
        // Handled above; repeated so that adding a member is a compile error
        // here rather than a silently wrong answer.
        DotNetField::IsDotNet => Value::Int(1),
        // Absent rather than empty, for the same reason
        // `pe.version_info["X"]` is: `dotnet.version contains ""` must be true
        // of a managed file whose version string is empty and false of a native
        // executable, and the two are different files.
        DotNetField::Version => match assembly.version() {
            Some(version) => Value::Bytes(std::sync::Arc::from(version)),
            None => Value::Undefined,
        },
        // The count itself is zero for a file that is not managed — the reader
        // holds no rows — so the `present` flag and not the count is what
        // separates "an assembly that declares none" from "not an assembly".
        // This is the member the distinction was written for: see
        // [`DotNetField::NumberOfResources`].
        DotNetField::NumberOfResources if !present => Value::Undefined,
        DotNetField::NumberOfResources => int(assembly.number_of_resources() as u64),
        // The `Assembly` table's one row. A netmodule has none, and so does an
        // image whose metadata is damaged past the point where the table could
        // be read — both are `Undefined`, because a rule reading the identity of
        // an assembly that declares none must not be handed `0.0.0.0`.
        DotNetField::AssemblyVersionMajor => match assembly.assembly() {
            Some((_, version)) => int(u64::from(version.major)),
            None => Value::Undefined,
        },
        DotNetField::AssemblyVersionMinor => match assembly.assembly() {
            Some((_, version)) => int(u64::from(version.minor)),
            None => Value::Undefined,
        },
        DotNetField::AssemblyVersionBuild => match assembly.assembly() {
            Some((_, version)) => int(u64::from(version.build)),
            None => Value::Undefined,
        },
        DotNetField::AssemblyVersionRevision => match assembly.assembly() {
            Some((_, version)) => int(u64::from(version.revision)),
            None => Value::Undefined,
        },
    }
}

/// `dotnet.<array>[i].<member>`, with `i` already evaluated.
///
/// The shape of [`pe_element`], and the same choices: a non-integer index and an
/// out-of-range one are both `Undefined` rather than an error, because the index
/// a rule passes is usually computed and a computed index that fell outside the
/// array is a question about an element that is not there.
fn dotnet_element(input: &Input<'_>, member: DotNetElement, index: &Value) -> Value {
    let Some(image) = input.pe else {
        return Value::Undefined;
    };
    let assembly = image.dotnet();
    // A float is the interesting case, exactly as it is for `pe_element`: a rule
    // that computed `i / 2` meant something, and truncating it would read an
    // element the rule did not name.
    let Value::Int(index) = index else {
        return Value::Undefined;
    };
    let Ok(index) = usize::try_from(*index) else {
        return Value::Undefined;
    };
    match member {
        DotNetElement::AssemblyRefName => match assembly.assembly_refs().get(index) {
            Some(reference) => Value::Bytes(std::sync::Arc::from(reference.name)),
            None => Value::Undefined,
        },
        DotNetElement::ResourceName => match assembly.resources().get(index) {
            Some(resource) => Value::Bytes(std::sync::Arc::from(resource.name)),
            None => Value::Undefined,
        },
        DotNetElement::ResourceLength => match assembly.resources().get(index) {
            // A linked resource has no bytes in this file, so it has no length —
            // see [`DotNetElement::ResourceLength`]. Zero is a length a real
            // embedded resource can have, so the two cannot share an answer.
            Some(resource) => match resource.length {
                Some(length) => Value::Int(i64::from(length)),
                None => Value::Undefined,
            },
            None => Value::Undefined,
        },
    }
}

/// `pe.version_info[key]`, with the key already evaluated.
///
/// A key that is not a string is `Undefined` rather than an error. Nothing in
/// the corpus indexes this array with anything else, and a rule that computed a
/// key is a rule asking about a name it built — there is no integer whose value
/// as a name is meaningful, so there is nothing to coerce it to.
fn version_info(input: &Input<'_>, key: &Value) -> Value {
    let Some(image) = input.pe else {
        return Value::Undefined;
    };
    let Value::Bytes(key) = key else {
        return Value::Undefined;
    };
    match image.version_info().get(key) {
        Some(value) => Value::Bytes(std::sync::Arc::from(value)),
        // Absent rather than empty. `pe.version_info["X"] contains ""` is true
        // of an empty string and must not be true of a file that never declared
        // X, which is the same distinction the module draws between a resource
        // that is not there and one that is zero bytes long.
        None => Value::Undefined,
    }
}

/// `pe.<array>[i].<member>`, with `i` already evaluated.
fn pe_element(input: &Input<'_>, member: PeElement, index: &Value) -> Value {
    let Some(image) = input.pe else {
        return Value::Undefined;
    };
    let pe = image.pe();
    // A non-integer index is undefined rather than an error. A float is the
    // interesting case: a rule that computed `i / 2` meant something, and
    // truncating it to an integer would read a section the rule did not name.
    let Value::Int(index) = index else {
        return Value::Undefined;
    };
    let Ok(index) = usize::try_from(*index) else {
        return Value::Undefined;
    };

    let name = |section: &Section| Value::Bytes(std::sync::Arc::from(section.name_bytes()));
    let int = |v: u64| Value::Int(v as i64);

    match member {
        // The signature array is read from the certificates rather than from
        // the header, so it is dispatched before the section lookup. Listed
        // exhaustively rather than through a catch-all so that adding a member
        // is a compile error here until it is placed in one array or the other.
        PeElement::SignatureSerial
        | PeElement::SignatureSubject
        | PeElement::SignatureIssuer
        | PeElement::SignatureNotBefore
        | PeElement::SignatureNotAfter
        | PeElement::SignatureThumbprint
        | PeElement::SignatureVersion => signature_element(image, member, index),
        // Likewise: the resource array is read from the resource directory and
        // has nothing to do with the section table the arm below indexes into.
        PeElement::ResourceType
        | PeElement::ResourceId
        | PeElement::ResourceLanguage
        | PeElement::ResourceOffset
        | PeElement::ResourceLength
        | PeElement::ResourceNameString
        | PeElement::ResourceTypeString
        | PeElement::ResourceLanguageString => resource_element(image, member, index),
        // And the export array, whose entries come from the export directory's
        // address table rather than from the section table.
        PeElement::ExportName
        | PeElement::ExportForwardName
        | PeElement::ExportOffset
        | PeElement::ExportOrdinal => export_element(image, member, index),
        PeElement::DirectoryVirtualAddress | PeElement::DirectorySize => {
            // A directory past the count the header declares is `Undefined`, not
            // zero, and the difference is observable: rules write
            // `pe.data_directories[IMAGE_DIRECTORY_ENTRY_SECURITY].size != 0` to
            // mean "signed", and a file declaring fewer than five directories
            // must not answer that with a `0` that reads as "not signed". The
            // header's own field is what bounds the array — it is a count of
            // *valid* entries, and the sixteen slots after it are the format's
            // fixed-width storage, not sixteen directories.
            if index as u64 >= u64::from(pe.number_of_rva_and_sizes()) {
                return Value::Undefined;
            }
            let entry = pe.data_directory(index);
            match member {
                PeElement::DirectoryVirtualAddress => int(u64::from(entry.virtual_address)),
                _ => int(u64::from(entry.size)),
            }
        }
        _ => {
            let Some(section) = pe.section(index) else {
                return Value::Undefined;
            };
            match member {
                PeElement::SectionName => name(section),
                PeElement::SectionVirtualAddress => int(u64::from(section.virtual_address)),
                PeElement::SectionVirtualSize => int(u64::from(section.virtual_size)),
                PeElement::SectionRawDataOffset => int(u64::from(section.pointer_to_raw_data)),
                PeElement::SectionRawDataSize => int(u64::from(section.size_of_raw_data)),
                PeElement::SectionCharacteristics => int(u64::from(section.characteristics)),
                PeElement::SectionPointerToRelocations => {
                    int(u64::from(section.pointer_to_relocations))
                }
                PeElement::SectionNumberOfRelocations => {
                    int(u64::from(section.number_of_relocations))
                }
                // The member names are YARA's, with underscores; the struct's
                // fields are the format's, without them. The mapping is here
                // and not in `av-pe`, which has no reason to know how a rule
                // spells a field.
                PeElement::SectionPointerToLineNumbers => {
                    int(u64::from(section.pointer_to_linenumbers))
                }
                PeElement::SectionNumberOfLineNumbers => {
                    int(u64::from(section.number_of_linenumbers))
                }
                // Handled above; unreachable, and answered rather than panicked.
                PeElement::DirectoryVirtualAddress | PeElement::DirectorySize => Value::Undefined,
                // Handled above, in the same sense: these are not section
                // members, and reaching here would mean the outer match had
                // been reordered.
                PeElement::SignatureSerial
                | PeElement::SignatureSubject
                | PeElement::SignatureIssuer
                | PeElement::SignatureNotBefore
                | PeElement::SignatureNotAfter
                | PeElement::SignatureThumbprint
                | PeElement::SignatureVersion => Value::Undefined,
                // And the resource members, in the same sense.
                PeElement::ResourceType
                | PeElement::ResourceId
                | PeElement::ResourceLanguage
                | PeElement::ResourceOffset
                | PeElement::ResourceLength
                | PeElement::ResourceNameString
                | PeElement::ResourceTypeString
                | PeElement::ResourceLanguageString => Value::Undefined,
                // And the export members, in the same sense.
                PeElement::ExportName
                | PeElement::ExportForwardName
                | PeElement::ExportOffset
                | PeElement::ExportOrdinal => Value::Undefined,
            }
        }
    }
}

/// `pe.resources[i].<member>`, with `i` already checked to be a `usize`.
///
/// # Why the absent members are `Undefined` rather than zero or empty
///
/// A resource level carries either an id or a name, never both, so at least one
/// of `type`/`type_string` is always absent — and the corpus reads both. A
/// missing id answered as `0` would make `pe.resources[i].type == 0` true of
/// every named resource, and a missing name answered as `""` would make
/// `pe.resources[i].name_string == ""` true of every resource named by an id.
/// `Undefined` compares false against everything, including `!=`, so neither
/// can happen.
fn resource_element<'a>(image: &PeInput<'a>, member: PeElement, index: usize) -> Value {
    let Some(resource) = image.resources().leaves().get(index) else {
        return Value::Undefined;
    };
    let int = |v: u64| Value::Int(v as i64);
    // The names are the file's own bytes: raw UTF-16LE, no terminator. Not
    // decoded, because `"1\x000\x000\x00"` is not a string a `String` can hold
    // and the corpus compares it as the bytes it is.
    let bytes = |v: Option<&'a [u8]>| match v {
        Some(b) => Value::Bytes(std::sync::Arc::from(b)),
        None => Value::Undefined,
    };

    match member {
        PeElement::ResourceType => resource
            .type_id
            .map_or(Value::Undefined, |id| int(u64::from(id))),
        PeElement::ResourceId => resource
            .id
            .map_or(Value::Undefined, |id| int(u64::from(id))),
        PeElement::ResourceLanguage => resource
            .language
            .map_or(Value::Undefined, |id| int(u64::from(id))),
        // A file offset, which is the member the corpus reads to find an
        // executable embedded in an image. See `av_pe::Resource::offset`.
        PeElement::ResourceOffset => int(resource.offset),
        PeElement::ResourceLength => int(resource.length),
        PeElement::ResourceNameString => bytes(resource.name_string),
        PeElement::ResourceTypeString => bytes(resource.type_string),
        PeElement::ResourceLanguageString => bytes(resource.language_string),
        // Every other member is dispatched before this function is reached, and
        // answering rather than panicking is what keeps that a choice.
        _ => Value::Undefined,
    }
}

/// `pe.export_details[i].<member>`, with `i` already checked to be a `usize`.
///
/// # Why the absent members are `Undefined` rather than empty
///
/// The array is the export *address* table, so an entry with no name is an
/// entry that is exported by ordinal alone: it exists, and its name is not
/// there. That is `Undefined`, and the difference is observable — the corpus
/// walks this array with `for any fn in pe.export_details : ( fn.forward_name
/// contains "Dll" )`, and were a non-forwarder's `forward_name` the empty
/// string, `contains ""` would be true of it and the loop would fire on every
/// DLL. The same argument applies to `name`, where the empty string is a name
/// a file can really have.
///
/// An index past the end of the address table is `Undefined` too, which is what
/// makes the corpus's `for all i in (0 .. pe.number_of_exports - 1)` shape safe:
/// the range is inclusive at both ends, so the last iteration reads one past
/// what the reader could produce on a file that declares more entries than it
/// holds, and the body must be false there rather than answered from whatever
/// slot came next.
fn export_element(image: &PeInput<'_>, member: PeElement, index: usize) -> Value {
    let Some(detail) = image.exports().details().get(index) else {
        return Value::Undefined;
    };
    let bytes = |v: Option<&[u8]>| match v {
        Some(b) => Value::Bytes(std::sync::Arc::from(b)),
        None => Value::Undefined,
    };
    match member {
        PeElement::ExportName => bytes(detail.name()),
        PeElement::ExportForwardName => bytes(detail.forward_name()),
        PeElement::ExportOffset => Value::Int(detail.offset() as i64),
        PeElement::ExportOrdinal => Value::Int(i64::from(detail.ordinal())),
        // Every other member is dispatched before this function is reached, and
        // answering rather than panicking is what keeps that a choice.
        _ => Value::Undefined,
    }
}

/// `pe.signatures[i].<member>`, with `i` already an index.
///
/// An out-of-range index is `Undefined`, and the corpus depends on it: the
/// loop bound rules write is `for any i in ( 0 .. pe.number_of_signatures )`,
/// which is inclusive at both ends, so the final iteration is one past the last
/// certificate. Answering that with anything other than `Undefined` would make
/// the loop's last iteration able to satisfy a body written about a certificate
/// that does not exist.
fn signature_element(image: &PeInput<'_>, member: PeElement, index: usize) -> Value {
    let Some(certificate) = image.signatures().get(index) else {
        return Value::Undefined;
    };
    let text = |s: String| Value::Bytes(std::sync::Arc::from(s.as_bytes()));
    // A field that cannot be rendered is `Undefined` rather than the empty
    // string: `contains ""` is true of every string, so an empty name would
    // make `pe.signatures[i].subject contains "..."` — and any rule that
    // compared against nothing — behave as though the certificate had matched.
    let or_undefined = |r: Result<String, av_signatures::SignatureError>| match r {
        Ok(s) => text(s),
        Err(_) => Value::Undefined,
    };
    match member {
        PeElement::SignatureSerial => text(certificate.serial()),
        PeElement::SignatureSubject => or_undefined(certificate.subject()),
        PeElement::SignatureIssuer => or_undefined(certificate.issuer()),
        PeElement::SignatureNotBefore => match certificate.not_before() {
            Ok(t) => Value::Int(t.seconds()),
            Err(_) => Value::Undefined,
        },
        PeElement::SignatureNotAfter => match certificate.not_after() {
            Ok(t) => Value::Int(t.seconds()),
            Err(_) => Value::Undefined,
        },
        PeElement::SignatureThumbprint => text(certificate.thumbprint()),
        PeElement::SignatureVersion => Value::Int(i64::from(certificate.version())),
        // Every other member belongs to the header, and the caller has already
        // branched on `is_signature_member` before reaching here.
        _ => Value::Undefined,
    }
}

/// `pe.<function>(...)`, with the operands already evaluated.
fn pe_call(input: &Input<'_>, func: PeFunc, args: &[Value]) -> Value {
    let Some(image) = input.pe else {
        return Value::Undefined;
    };
    let pe = image.pe();
    match func {
        PeFunc::SectionIndex => {
            let Some(arg) = args.first() else {
                return Value::Undefined;
            };
            let found = match arg {
                Value::Int(offset) => u64::try_from(*offset)
                    .ok()
                    .and_then(|offset| pe.section_index_of_offset(offset)),
                Value::Bytes(name) => pe.section_index_of_name(name),
                // `pe.section_index(pe.some_field)` in a file where that field
                // is undefined. There is no section to name.
                _ => None,
            };
            match found {
                Some(index) => Value::Int(index as i64),
                None => Value::Undefined,
            }
        }
        // The three the compiler also accepts without parentheses, answering
        // through the same accessors so the two spellings cannot drift.
        PeFunc::IsDll => Value::Int(i64::from(pe.is_dll())),
        PeFunc::Is32Bit => Value::Int(i64::from(pe.is_32bit())),
        PeFunc::Is64Bit => Value::Int(i64::from(pe.is_64bit())),

        // The predicates answer `Int(0)` or `Int(1)` rather than a boolean,
        // matching the members they sit beside. A file that is not a PE never
        // reaches here — the `else` above returns `Undefined` — so a rule that
        // forgot its `pe.is_pe` guard gets a false rather than a match.
        // The hash is a string, so a rule compares it with `==` against a
        // thirty-two character literal. A file with no imports hashes the empty
        // string, which is the algorithm's answer and not an error — the rule
        // simply does not match it.
        PeFunc::Imphash => {
            let hash = image.imports().imphash();
            Value::Bytes(std::sync::Arc::from(hash.as_bytes()))
        }
        PeFunc::Imports => match args.first().and_then(text) {
            Some(library) => Value::Int(i64::from(image.imports().has_library(library))),
            // A library name that came from an undefined member, which is not an
            // empty library name: there is nothing to look up.
            None => Value::Undefined,
        },
        PeFunc::ImportsSymbol => {
            match (args.first().and_then(text), args.get(1).and_then(text)) {
                // The symbol comparison is case-sensitive and the library one is
                // not; `av_pe::imports` carries the reasoning.
                (Some(library), Some(symbol)) => {
                    Value::Int(i64::from(image.imports().has_function(library, symbol)))
                }
                _ => Value::Undefined,
            }
        }
        PeFunc::Exports => match args.first().and_then(text) {
            Some(name) => Value::Int(i64::from(image.exports().has_name(name))),
            None => Value::Undefined,
        },
        PeFunc::RichSignatureToolid => match (args.first(), args.get(1)) {
            (Some(tool), Some(version)) => match (tool.as_index(), version.as_index()) {
                // Whole numbers only, through the same conversion every other
                // index in the engine uses: `toolid(1, 2)` and `toolid(1.0, 2.0)`
                // are the same question, and `toolid(i / 2)` — which is not
                // whole — is a rule that computed a tool id rather than named
                // one. There is no half of a tool.
                (Some(tool), Some(version)) => {
                    let tool = u32::try_from(tool).unwrap_or(u32::MAX);
                    let version = u32::try_from(version).unwrap_or(u32::MAX);
                    Value::Int(i64::from(image.rich_signature().toolid(tool, version)))
                }
                _ => Value::Undefined,
            },
            _ => Value::Undefined,
        },
    }
}

/// A `Value` as a byte string, or `None` for anything that is not one.
///
/// A `pe` predicate's arguments are strings in every use the corpus has; an
/// integer argument is a rule that computed the wrong thing, and `Undefined` is
/// the answer that makes it fail visibly rather than compare against a
/// decimal rendering nobody wrote.
///
/// Bytes rather than `&str` because the argument is usually a field of the file
/// — `pe.imports(pe.sections[i].name)` and similar — and naming a library is
/// not a place to require UTF-8 of an attacker-supplied name.
fn text(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Bytes(s) => Some(s.as_ref()),
        _ => None,
    }
}

/// `hash.<algorithm>(...)` and `math.<statistic>(...)`, with the operands
/// already evaluated.
///
/// The region functions share one argument convention, which is worth stating
/// once: an offset and a size, both as the rule computed them, both possibly
/// nonsense. [`stats::region`] is what turns them into a slice, and it never
/// fails — it shortens. So `math.entropy(0x400, filesize)` on a 100-byte file
/// is the entropy of nothing, which is `0.0`, and not a read past the buffer
/// and not an error.
fn module_call(input: &Input<'_>, func: ModuleFunc, args: &[Value]) -> Value {
    match func {
        // The one function here that does not read the file. Its argument is a
        // string the `pe` module produced — `pe.rich_signature.clear_data` is
        // the only one the corpus hashes — and `Undefined` propagates, so a rule
        // that hashes a member of a module that could not answer gets
        // `Undefined` rather than the digest of the empty string. That
        // distinction is the difference between a rule that does not fire and
        // one that fires on every file with the same MD5 as nothing.
        ModuleFunc::HashStr(kind) => match args.first() {
            Some(Value::Bytes(s)) => Value::Bytes(std::sync::Arc::from(kind.digest(s).as_bytes())),
            _ => Value::Undefined,
        },

        ModuleFunc::HashRange(kind) => match (offset(args, 0), offset(args, 1)) {
            (Some(at), Some(size)) => Value::Bytes(std::sync::Arc::from(
                kind.digest(stats::region(input.data, at, size)).as_bytes(),
            )),
            _ => Value::Undefined,
        },

        ModuleFunc::Entropy => match (offset(args, 0), offset(args, 1)) {
            (Some(at), Some(size)) => {
                Value::Float(stats::entropy(stats::region(input.data, at, size)))
            }
            _ => Value::Undefined,
        },

        ModuleFunc::Mean => match (offset(args, 0), offset(args, 1)) {
            (Some(at), Some(size)) => {
                Value::Float(stats::mean(stats::region(input.data, at, size)))
            }
            _ => Value::Undefined,
        },

        ModuleFunc::Count => match (byte(args, 0), offset(args, 1), offset(args, 2)) {
            (Some(byte), Some(at), Some(size)) => {
                Value::Int(stats::count(stats::region(input.data, at, size), byte) as i64)
            }
            _ => Value::Undefined,
        },

        ModuleFunc::Percentage => match (byte(args, 0), offset(args, 1), offset(args, 2)) {
            (Some(byte), Some(at), Some(size)) => {
                let region = stats::region(input.data, at, size);
                if region.is_empty() {
                    // No division, because the answer would be `NaN` and `NaN`
                    // makes every comparison false — including the ones a rule
                    // would write to exclude a file. Zero is the fraction of a
                    // region that is not there, and it compares.
                    Value::Float(0.0)
                } else {
                    let hits = stats::count(region, byte) as f64;
                    Value::Float(hits * 100.0 / region.len() as f64)
                }
            }
            _ => Value::Undefined,
        },

        // `math.min` and `math.max` compare two *numbers*, and the corpus uses
        // them on an integer count. A float argument is compared as a float, so
        // `math.min(1.5, 2)` is `1.5` and not `1`: truncating would make the
        // result depend on which argument the caller put first.
        ModuleFunc::Min => match (number(args, 0), number(args, 1)) {
            (Some(a), Some(b)) => number_value(a.min(b)),
            _ => Value::Undefined,
        },
        ModuleFunc::Max => match (number(args, 0), number(args, 1)) {
            (Some(a), Some(b)) => number_value(a.max(b)),
            _ => Value::Undefined,
        },

        ModuleFunc::Abs => match number(args, 0) {
            Some(v) => number_value(v.abs()),
            // `math.abs` of a string is a rule that computed the wrong thing.
            None => Value::Undefined,
        },

        // `math.to_number(true)` is `1`. The argument is a predicate, and a
        // predicate that is undefined is not false — `to_number` of it is
        // undefined too, which keeps `math.to_number(pe.something) == 0` from
        // being true on a file that is not a PE.
        ModuleFunc::ToNumber => match args.first() {
            Some(Value::Bool(b)) => Value::Int(i64::from(*b)),
            Some(Value::Int(i)) => Value::Int(i64::from(*i != 0)),
            _ => Value::Undefined,
        },

        // Inclusive at both ends, which is the reading the name has and the one
        // the corpus assumes. Written as two comparisons rather than as a
        // `Range::contains` so that a `NaN` bound makes it false rather than
        // panicking, which is what `contains` does on a partially ordered type.
        ModuleFunc::InRange => match (number(args, 0), number(args, 1), number(args, 2)) {
            (Some(x), Some(low), Some(high)) => Value::Int(i64::from(x >= low && x <= high)),
            _ => Value::Undefined,
        },

        ModuleFunc::Deviation => match (offset(args, 0), offset(args, 1), number(args, 2)) {
            (Some(at), Some(size), Some(mean)) => {
                Value::Float(stats::deviation(stats::region(input.data, at, size), mean))
            }
            _ => Value::Undefined,
        },

        // The string form. `Undefined` propagates rather than hashing the empty
        // string, for the same reason [`ModuleFunc::HashStr`] does it: a rule
        // that asked about a member the `pe` module could not produce must not
        // be answered about a string that is not there.
        ModuleFunc::DeviationStr => match (args.first(), number(args, 1)) {
            (Some(Value::Bytes(s)), Some(mean)) => Value::Float(stats::deviation(s, mean)),
            _ => Value::Undefined,
        },

        ModuleFunc::StringLength => match args.first() {
            Some(Value::Bytes(s)) => Value::Int(s.len() as i64),
            _ => Value::Undefined,
        },

        ModuleFunc::StringToInt => match args.first() {
            Some(Value::Bytes(s)) => to_int(s, None),
            _ => Value::Undefined,
        },

        ModuleFunc::StringToIntBase => match (args.first(), number(args, 1)) {
            // The base is an integer the rule wrote, and a base outside the
            // range the module accepts makes the conversion undefined rather
            // than a guess at which base was meant. A base with a fractional
            // part is not a base either: `math.min(16, 16.5)` is a value a rule
            // can compute, and truncating it would convert in a base nobody
            // wrote. `as` saturates rather than wrapping, and `to_int` refuses
            // anything outside `0..=36`, so the saturated ends are refused too.
            (Some(Value::Bytes(s)), Some(base)) => {
                if base.fract() == 0.0 {
                    to_int(s, Some(base as i64))
                } else {
                    Value::Undefined
                }
            }
            _ => Value::Undefined,
        },
    }
}

/// `string.to_int` — a byte string read as a signed integer.
///
/// # The syntax, and why it is this strict
///
/// `base` of `None` means the literal's own prefix decides: `0x` is sixteen,
/// a leading `0` is eight, and anything else is ten. An explicit base of zero
/// means the same, and any base from two to thirty-six means exactly that base
/// with no prefix rule. A sign may precede all of it.
///
/// Everything else is [`Value::Undefined`], and that includes the cases a
/// permissive parser would accept: trailing bytes after the digits, a digit
/// outside the base, an empty digit run, a base outside `0..=36`, and a
/// magnitude that does not fit an `i64`. The reason is the one this engine
/// applies everywhere else — `Undefined` makes every comparison false, so a
/// rule asking `string.to_int(x) == 8` does not fire on a string this code could
/// not read. The permissive alternative is to answer zero, and a rule asking
/// whether a name decodes to zero would then fire on every name that does not
/// decode at all.
fn to_int(bytes: &[u8], base: Option<i64>) -> Value {
    let mut at = 0usize;
    let negative = match bytes.first() {
        Some(b'-') => {
            at = 1;
            true
        }
        Some(b'+') => {
            at = 1;
            false
        }
        _ => false,
    };
    let rest = &bytes[at..];
    if rest.is_empty() {
        return Value::Undefined;
    }

    // Which base the digits are in. An explicit base of zero asks for the
    // prefix rule, exactly as an absent one does.
    let (base, rest) = match base {
        Some(0) | None => match rest {
            [b'0', b'x' | b'X', ..] => (16u32, &rest[2..]),
            [b'0', ..] => (8u32, rest),
            _ => (10u32, rest),
        },
        Some(base) => match u32::try_from(base) {
            Ok(base) if (2..=36).contains(&base) => {
                // A prefix is still stripped when it agrees with the base the
                // rule named: `string.to_int("0x11", 16)` is seventeen, and a
                // reader would be surprised by anything else.
                match (base, rest) {
                    (16, [b'0', b'x' | b'X', ..]) => (base, &rest[2..]),
                    _ => (base, rest),
                }
            }
            _ => return Value::Undefined,
        },
    };
    if rest.is_empty() {
        return Value::Undefined;
    }

    let mut magnitude: i64 = 0;
    for &byte in rest {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'z' => u32::from(byte - b'a') + 10,
            b'A'..=b'Z' => u32::from(byte - b'A') + 10,
            _ => return Value::Undefined,
        };
        if digit >= base {
            return Value::Undefined;
        }
        // Checked rather than wrapping: a literal too large for the type is not
        // a number this engine can compare, and `Undefined` says so.
        let Some(shifted) = magnitude.checked_mul(i64::from(base)) else {
            return Value::Undefined;
        };
        let Some(sum) = shifted.checked_add(i64::from(digit)) else {
            return Value::Undefined;
        };
        magnitude = sum;
    }
    // The magnitude never exceeded `i64::MAX` — the accumulation is checked —
    // so negating it cannot overflow. `-9223372036854775808` is therefore
    // undefined rather than negative: its magnitude is one past what the
    // accumulation will hold, which the checked multiply above already refused.
    if negative {
        Value::Int(-magnitude)
    } else {
        Value::Int(magnitude)
    }
}

/// Argument `n` as a buffer offset or size.
///
/// A float is not converted. A rule that computed `filesize / 2` in a language
/// where `/` is real division has a float, and silently truncating it would read
/// a region the rule did not name — the same argument [`AsOffset`] makes for
/// `Value::as_offset`, and the reason the two agree.
fn offset(args: &[Value], n: usize) -> Option<i64> {
    match args.get(n) {
        Some(Value::Int(i)) => Some(*i),
        _ => None,
    }
}

/// Argument `n` as a byte value. Only `0 ..= 255` is a byte.
fn byte(args: &[Value], n: usize) -> Option<u8> {
    let Some(Value::Int(i)) = args.get(n) else {
        return None;
    };
    u8::try_from(*i).ok()
}

/// Argument `n` as a number, integer or floating point.
fn number(args: &[Value], n: usize) -> Option<f64> {
    match args.get(n) {
        Some(Value::Int(i)) => Some(*i as f64),
        Some(Value::Float(f)) => Some(*f),
        _ => None,
    }
}

/// A computed number back as a value, staying an integer when it is one.
///
/// The distinction is visible to the rule: `math.min(2, 3) == 2` is true and
/// `math.min(2, 3) == 2.0` is also true, but `math.min(#a, #b)` printed into a
/// report reads better as `2` than as `2.0`, and `#a == math.min(...)` compares
/// an integer with an integer.
fn number_value(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 9.007_199_254_740_992e15 {
        Value::Int(v as i64)
    } else {
        Value::Float(v)
    }
}

/// A program that could not be executed.
///
/// Every variant means the program itself is malformed — never that the file
/// being scanned is unusual. A file's contents can only ever produce
/// `Undefined`; reaching one of these means the rule database is corrupt, and
/// the scanner counts it rather than treating it as a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    /// A jump to an address past the end of the program.
    BadJump { at: usize, target: u32 },
    /// A constant index past the end of the pool.
    BadConstant { at: usize, index: u32 },
    /// An instruction ran out of operands.
    StackUnderflow { at: usize, op: Op },
    /// A variable slot past the end of the register file.
    BadVariable { at: usize, slot: u32 },
    /// A `rule_ref` to a result slot that does not exist.
    ///
    /// Unreachable for a caller that ran [`Vm::begin_scan`] with the rule
    /// database's own [`result_len`](crate::database::RuleDatabase::result_len) and
    /// evaluates in the order the compiler produced: every name a rule uses has
    /// been evaluated, and written, by the time the rule runs. It is an error
    /// rather than a `false` because both readings it could be given are wrong
    /// in a way that surfaces as a verdict rather than as a fault — `false`
    /// turns `OTHER and $a` into a detection that never fires, and `not OTHER`
    /// into a condition true of every file on the disk. Which of the two a
    /// given rule means is not something the interpreter can see.
    MissingRuleResult { at: usize, rule: u32 },
    /// Execution did not finish within the program's own step bound.
    ///
    /// Unreachable for a well-formed program: the bound accounts for every
    /// loop's iterations, so a program that exceeds it has a jump table that
    /// does not match its own limits, which is what a corrupt database looks
    /// like.
    StepLimit { limit: u32 },
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmError::BadJump { at, target } => {
                write!(
                    f,
                    "instruction {at} jumps to {target}, past the end of the program"
                )
            }
            VmError::BadConstant { at, index } => {
                write!(
                    f,
                    "instruction {at} reads constant {index}, which does not exist"
                )
            }
            VmError::StackUnderflow { at, op } => {
                write!(f, "instruction {at} ({op:?}) has no operand to pop")
            }
            VmError::BadVariable { at, slot } => {
                write!(
                    f,
                    "instruction {at} uses variable {slot}, which does not exist"
                )
            }
            VmError::MissingRuleResult { at, rule } => {
                write!(
                    f,
                    "instruction {at} reads rule {rule}, which has no result slot \
                     in this scan"
                )
            }
            VmError::StepLimit { limit } => {
                write!(f, "execution exceeded its {limit}-instruction bound")
            }
        }
    }
}

impl std::error::Error for VmError {}

/// How many compiled `matches` patterns the interpreter keeps.
///
/// A cache bound rather than a limit on the language: a real rule set has a
/// handful of these — the corpus has one — and the number is set well past that
/// so that reaching it means the database is not one this engine produced. See
/// [`Vm::compiled_regex`] for what happens there.
const MAX_COMPILED_REGEXES: usize = 4096;

/// The interpreter's operand stack and registers.
///
/// Reusable: [`Vm::run`] resets the stack height and leaves it at zero, so one
/// `Vm` can run every rule of a scan in sequence.
#[derive(Debug, Default, Clone)]
pub struct Vm {
    stack: Vec<Value>,
    /// Loop variables, bounds and accumulators, indexed by the slots the
    /// compiler allocated. Empty for the great majority of rules, which have
    /// no loops and therefore no variables.
    vars: Vec<Value>,
    /// One verdict per rule of the corpus being scanned, refusals included —
    /// the slots [`Op::RuleRef`] indexes.
    ///
    /// Scan state rather than input, which is why it lives here and not in
    /// [`Input`]: it is not a fact about the file, and a rule reads it only to
    /// find out what another rule said. The scanner writes each verdict as the
    /// rule is evaluated; see [`Vm::record`].
    results: Vec<bool>,
    /// Deepest the stack has ever been, across every run.
    ///
    /// Kept for tuning `Program::max_stack` against reality rather than against
    /// the compiler's own arithmetic, which over-estimates at branches by
    /// design.
    pub peak_stack: usize,
    /// Compiled `matches` patterns, by the spec they were compiled from.
    ///
    /// A [`Program`] carries the pattern text rather than a compiled automaton
    /// — see [`RegexSpec`] — so the compiling happens here. The interpreter
    /// outlives the scan of any one file, which is what makes this a cache
    /// rather than a per-file cost: the pattern is compiled once and every
    /// later file reuses it.
    regexes: HashMap<RegexSpec, regex::bytes::Regex>,
}

impl Vm {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a scan over `len` corpus rules, clearing every verdict.
    ///
    /// `len` is the rule database's
    /// [`result_len`](crate::database::RuleDatabase::result_len) — one slot per rule the
    /// corpus held, refusals included, because that is what [`Op::RuleRef`]
    /// indexes. Calling this is what makes a rule that reads another rule work;
    /// a caller that never calls it holds no result slots at all, and the first
    /// such rule reports [`VmError::MissingRuleResult`] rather than reading a
    /// verdict nobody wrote.
    pub fn begin_scan(&mut self, len: usize) {
        self.results.clear();
        self.results.resize(len, false);
    }

    /// Record one rule's verdict for the rules that read it.
    ///
    /// Out of range is ignored rather than a panic: the length came from the
    /// database, and no rule can be stored with a `corpus_index` past it, so
    /// this is unreachable — but a scan is the wrong place to find out that it
    /// is not.
    pub fn record(&mut self, slot: u32, matched: bool) {
        if let Some(entry) = self.results.get_mut(slot as usize) {
            *entry = matched;
        }
    }

    /// How many result slots the current scan has.
    pub fn result_len(&self) -> usize {
        self.results.len()
    }

    /// The compiled form of a `matches` pattern, compiling it if this is the
    /// first time it has been asked for.
    ///
    /// `None` when the pattern does not compile. That cannot happen for a rule
    /// that came out of [`crate::compiler`], which compiles the pattern before
    /// it emits the opcode, and it can happen for a database that did not — so
    /// the answer is `Undefined` rather than a panic, and a rule that cannot be
    /// evaluated is a rule that does not fire.
    ///
    /// The cache is bounded by [`MAX_COMPILED_REGEXES`]. `Program::regexes`
    /// comes out of the rule database, so a database claiming a million
    /// distinct patterns must not be able to make this hold a million automata;
    /// past the bound the cache is emptied and refilled, which costs a
    /// recompile and never grows.
    fn compiled_regex(&mut self, spec: &RegexSpec) -> Option<&regex::bytes::Regex> {
        if !self.regexes.contains_key(spec) {
            let compiled = crate::matcher::compile_condition_regex(&spec.body, &spec.flags).ok()?;
            if self.regexes.len() >= MAX_COMPILED_REGEXES {
                self.regexes.clear();
            }
            self.regexes.insert(spec.clone(), compiled);
        }
        self.regexes.get(spec)
    }

    /// Run a condition. `Ok(true)` means the rule matched.
    pub fn run(
        &mut self,
        program: &Program,
        strings: &MatchSet,
        input: &Input<'_>,
    ) -> Result<bool, VmError> {
        self.stack.clear();
        let code = &program.code;
        // Only a jump table that does not match the program's own limits can
        // exceed this: `max_steps` already carries an allowance for every loop
        // running its maximum number of times. The program's length is taken as
        // a floor so that a program with no computed limits still cannot run
        // away.
        let limit = program.max_steps.max(code.len() as u32).saturating_add(1);
        let mut steps = 0u32;
        let mut pc = 0usize;
        // Loop iterations left in the rule's budget, shared by all its loops —
        // see `MAX_LOOP_ITERATIONS`. A loop that finds it empty yields
        // undefined rather than a truncated answer.
        let mut iterations = MAX_LOOP_ITERATIONS;
        self.vars.clear();
        self.vars
            .resize(program.var_slots as usize, Value::Undefined);

        // The locals below are the interpreter's registers. Hoisting the stack
        // into a slice and pushing to it directly keeps the hot loop from
        // re-borrowing `self` on every instruction.
        let mut stack: Vec<Value> = std::mem::take(&mut self.stack);
        let result = 'run: loop {
            let Some(op) = code.get(pc) else {
                break Err(VmError::BadJump {
                    at: pc,
                    target: pc as u32,
                });
            };
            let here = pc;
            pc += 1;
            steps = steps.saturating_add(1);
            if steps > limit {
                break Err(VmError::StepLimit { limit });
            }

            macro_rules! pop {
                () => {
                    match stack.pop() {
                        Some(v) => v,
                        None => {
                            break 'run Err(VmError::StackUnderflow { at: here, op: *op });
                        }
                    }
                };
            }

            match *op {
                Op::Push(index) => match program.constants.get(index as usize) {
                    Some(c) => stack.push(c.to_value()),
                    None => break Err(VmError::BadConstant { at: here, index }),
                },

                Op::Filesize => stack.push(Value::Int(input.data.len() as i64)),
                Op::EntryPoint => stack.push(match input.entry_point {
                    Some(e) => Value::Int(e as i64),
                    None => Value::Undefined,
                }),

                Op::ReadU8 => {
                    // The 8-bit read has no endianness — one byte is one byte —
                    // which is why the compiler emits `ReadU8` for `uint8` and
                    // `uint8be` alike.
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 1, Endian::Little, false));
                }
                Op::ReadU16 => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 2, Endian::Little, false));
                }
                Op::ReadU32 => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 4, Endian::Little, false));
                }
                Op::ReadI8 => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 1, Endian::Little, true));
                }
                Op::ReadI16 => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 2, Endian::Little, true));
                }
                Op::ReadI32 => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 4, Endian::Little, true));
                }
                Op::ReadU16Be => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 2, Endian::Big, false));
                }
                Op::ReadU32Be => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 4, Endian::Big, false));
                }
                Op::ReadI16Be => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 2, Endian::Big, true));
                }
                Op::ReadI32Be => {
                    let at = pop!();
                    stack.push(read(input.data, at.as_offset(), 4, Endian::Big, true));
                }

                Op::StrMatch(slot) => stack.push(Value::Bool(strings.has(slot))),
                Op::StrCount(slot) => stack.push(Value::Int(i64::from(strings.count(slot)))),
                Op::StrOffsetFirst(slot) => stack.push(match strings.first(slot) {
                    Some(m) => Value::Int(i64::from(m.offset)),
                    None => Value::Undefined,
                }),
                Op::StrLenFirst(slot) => stack.push(match strings.first(slot) {
                    Some(m) => Value::Int(i64::from(m.length)),
                    None => Value::Undefined,
                }),
                Op::StrOffsetNth(slot) => {
                    let index = pop!();
                    stack.push(match index.as_index().and_then(|i| strings.nth(slot, i)) {
                        Some(m) => Value::Int(i64::from(m.offset)),
                        None => Value::Undefined,
                    });
                }
                Op::StrLenNth(slot) => {
                    let index = pop!();
                    stack.push(match index.as_index().and_then(|i| strings.nth(slot, i)) {
                        Some(m) => Value::Int(i64::from(m.length)),
                        None => Value::Undefined,
                    });
                }
                Op::StrAt(slot) => {
                    let at = pop!();
                    stack.push(Value::Bool(
                        at.as_offset().is_some_and(|o| strings.at(slot, o)),
                    ));
                }
                Op::StrIn(slot) => {
                    let to = pop!();
                    let from = pop!();
                    let hit = match (from.as_index(), to.as_index()) {
                        (Some(from), Some(to)) => strings.in_range(slot, from, to),
                        _ => false,
                    };
                    stack.push(Value::Bool(hit));
                }

                Op::OfAny(n) => {
                    let mut hit = false;
                    for _ in 0..n {
                        // Every operand is popped even once the answer is
                        // known: the stack has to be at the same height after
                        // the instruction whatever the values were.
                        hit |= pop!().is_truthy();
                    }
                    stack.push(Value::Bool(hit));
                }
                Op::OfAll(n) => {
                    let mut all = true;
                    for _ in 0..n {
                        all &= pop!().is_truthy();
                    }
                    stack.push(Value::Bool(all));
                }
                Op::OfNone(n) => {
                    let mut any = false;
                    for _ in 0..n {
                        any |= pop!().is_truthy();
                    }
                    stack.push(Value::Bool(!any));
                }
                Op::OfCount(n) => {
                    let mut hits = 0i64;
                    for _ in 0..n {
                        if pop!().is_truthy() {
                            hits += 1;
                        }
                    }
                    // The count sits below the results, because the compiler
                    // emits it first to keep the run of string tests
                    // contiguous.
                    let need = pop!();
                    stack.push(Value::Bool(match need.as_index() {
                        Some(need) => hits >= need,
                        // An undefined required count cannot be met: the rule
                        // has not established how many strings must match, and
                        // assuming zero would make it fire on every file.
                        None => false,
                    }));
                }

                Op::Not => {
                    let v = pop!();
                    stack.push(Value::Bool(!v.is_truthy()));
                }
                Op::Negate => {
                    let v = pop!();
                    stack.push(match v {
                        Value::Int(i) => Value::Int(i.wrapping_neg()),
                        Value::Float(f) => Value::Float(-f),
                        _ => Value::Undefined,
                    });
                }
                Op::BitNot => {
                    let v = pop!();
                    stack.push(match v {
                        Value::Int(i) => Value::Int(!i),
                        _ => Value::Undefined,
                    });
                }
                Op::IsDefined => {
                    let v = pop!();
                    stack.push(Value::Bool(!v.is_undefined()));
                }

                Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Mod => {
                    let b = pop!();
                    let a = pop!();
                    stack.push(arith(*op, a, b));
                }
                Op::BitAnd | Op::BitOr | Op::BitXor | Op::Shl | Op::Shr => {
                    let b = pop!();
                    let a = pop!();
                    stack.push(bitwise(*op, a, b));
                }
                Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                    let b = pop!();
                    let a = pop!();
                    stack.push(Value::Bool(compare(cmp_of(*op), &a, &b)));
                }
                Op::Cmp(kind) => {
                    let b = pop!();
                    let a = pop!();
                    stack.push(Value::Bool(text_cmp(kind, &a, &b)));
                }

                Op::Matches(index) => {
                    let subject = pop!();
                    // One operand: the pattern is not on the stack, because it
                    // is not a value. `None` from either lookup is `Undefined`,
                    // which makes every comparison against the result false —
                    // the direction that does not fire a rule on a file whose
                    // pattern could not be read.
                    let value = match subject {
                        Value::Bytes(text) => match program.regexes.get(index as usize) {
                            Some(spec) => match self.compiled_regex(spec) {
                                Some(regex) => Value::Bool(regex.is_match(&text)),
                                None => Value::Undefined,
                            },
                            None => Value::Undefined,
                        },
                        _ => Value::Undefined,
                    };
                    stack.push(value);
                }

                Op::Jump(target) => {
                    if target as usize > code.len() {
                        break Err(VmError::BadJump { at: here, target });
                    }
                    pc = target as usize;
                }
                Op::JumpIfFalse(target) => {
                    let v = pop!();
                    if !v.is_truthy() {
                        if target as usize > code.len() {
                            break Err(VmError::BadJump { at: here, target });
                        }
                        pc = target as usize;
                    }
                }
                Op::JumpIfTrue(target) => {
                    let v = pop!();
                    if v.is_truthy() {
                        if target as usize > code.len() {
                            break Err(VmError::BadJump { at: here, target });
                        }
                        pc = target as usize;
                    }
                }

                Op::ForBegin {
                    var,
                    end,
                    acc,
                    kind,
                    done,
                } => {
                    let to = pop!();
                    let from = pop!();
                    if done as usize > code.len() {
                        break Err(VmError::BadJump {
                            at: here,
                            target: done,
                        });
                    }
                    if acc as usize >= self.vars.len() {
                        break Err(VmError::BadVariable {
                            at: here,
                            slot: acc,
                        });
                    }
                    // Before anything else, so that the unknown bound below
                    // leaves the accumulator already right.
                    self.vars[acc as usize] = kind.identity();

                    match (from, to) {
                        (Value::Int(from), Value::Int(to)) => {
                            if var as usize >= self.vars.len() || end as usize >= self.vars.len() {
                                break Err(VmError::BadVariable {
                                    at: here,
                                    slot: var.max(end),
                                });
                            }
                            // `(a..b)` is the integers from `a` to `b`
                            // *inclusive*, in whichever direction they run —
                            // the same set as writing them out. So `(1..3)` is
                            // `1, 2, 3` and `(0..0)` is one iteration, not
                            // none. There is no empty range here: a range with
                            // two integer bounds always contains its first
                            // bound, and `ForStep` decides whether there is a
                            // second.
                            //
                            // This is the semantics YARA documents, and it is
                            // load-bearing: the idiom `for any i in
                            // (0..pe.number_of_sections - 1)` walks *every*
                            // section only if the upper bound is included. A
                            // half-open reading would drop the last one from
                            // every such rule in the corpus — silently, and in
                            // the direction of a missed detection.
                            self.vars[var as usize] = Value::Int(from);
                            self.vars[end as usize] = Value::Int(to);
                        }
                        // A bound that is not a number: an undefined module
                        // field, most likely. The loop has no answer, and
                        // undefined says exactly that rather than inventing one
                        // by treating the bound as zero.
                        _ => {
                            self.vars[acc as usize] = Value::Undefined;
                            pc = done as usize;
                        }
                    }
                }

                Op::ForEachBegin {
                    var,
                    end,
                    acc,
                    kind,
                    done,
                } => {
                    let count = pop!();
                    if done as usize > code.len() {
                        break Err(VmError::BadJump {
                            at: here,
                            target: done,
                        });
                    }
                    if acc as usize >= self.vars.len() {
                        break Err(VmError::BadVariable {
                            at: here,
                            slot: acc,
                        });
                    }
                    // As in `ForBegin`: the accumulator is right before the
                    // loop's length is even known, so that an array whose length
                    // is undefined still answers vacuously rather than
                    // poisoning the result.
                    self.vars[acc as usize] = kind.identity();

                    match count {
                        // An empty array runs the loop zero times, and the
                        // accumulator already holds the answer for that: false
                        // for `any`, true for `all` and none held zero times for
                        // `none`. Jumping out here rather than entering with a
                        // bound of `-1` keeps the body from ever seeing an index
                        // that names no element.
                        Value::Int(count) if count <= 0 => pc = done as usize,
                        Value::Int(count) => {
                            if var as usize >= self.vars.len() || end as usize >= self.vars.len() {
                                break Err(VmError::BadVariable {
                                    at: here,
                                    slot: var.max(end),
                                });
                            }
                            // The bound is inclusive in `ForStep`, so it is the
                            // last index and not the length.
                            self.vars[var as usize] = Value::Int(0);
                            self.vars[end as usize] = Value::Int(count - 1);
                        }
                        // A length that is not a number. Only reachable if the
                        // count expression was undefined — `pe.resources` on a
                        // file with no resource directory — and undefined is the
                        // honest answer for a loop over an array that is not
                        // there.
                        _ => {
                            self.vars[acc as usize] = Value::Undefined;
                            pc = done as usize;
                        }
                    }
                }

                Op::ForStep {
                    var,
                    end,
                    acc,
                    kind,
                    back,
                } => {
                    let body = pop!().is_truthy();
                    if var as usize >= self.vars.len()
                        || end as usize >= self.vars.len()
                        || acc as usize >= self.vars.len()
                    {
                        break Err(VmError::BadVariable {
                            at: here,
                            slot: var.max(end).max(acc),
                        });
                    }
                    self.vars[acc as usize] = kind.fold(&self.vars[acc as usize], body);

                    // `any` is settled by the first true body and `all` by the
                    // first false one, so the rest of the range need not be
                    // walked. A count has to see every iteration.
                    let done = kind.decided(&self.vars[acc as usize]);
                    // The direction is the bound's, read afresh each time
                    // rather than latched at entry: comparing is cheaper than
                    // carrying a step in a fourth slot, and it cannot overflow
                    // the way `bound - i` would at the ends of the range.
                    let (current, bound) =
                        match (&self.vars[var as usize], &self.vars[end as usize]) {
                            (Value::Int(i), Value::Int(b)) => (*i, *b),
                            // Unreachable: `ForBegin` either set both to
                            // integers or skipped the body entirely. Stopping
                            // is the safe reading of it if that ever changes.
                            _ => (0, 0),
                        };
                    if done || current == bound {
                        // Falls through to the instruction after the body,
                        // which is where `done` points.
                    } else if iterations == 0 {
                        // The rule's loop budget is spent. Undefined rather
                        // than the accumulator so far: a truncated `for all`
                        // would be true where the rule said otherwise, and a
                        // false positive is worse than a detection that does
                        // not fire.
                        self.vars[acc as usize] = Value::Undefined;
                    } else {
                        iterations -= 1;
                        let next = if current < bound {
                            current + 1
                        } else {
                            current - 1
                        };
                        self.vars[var as usize] = Value::Int(next);
                        if back as usize > code.len() {
                            break Err(VmError::BadJump {
                                at: here,
                                target: back,
                            });
                        }
                        pc = back as usize;
                    }
                }

                Op::VarLoad(slot) => match self.vars.get(slot as usize) {
                    Some(v) => stack.push(v.clone()),
                    None => break Err(VmError::BadVariable { at: here, slot }),
                },

                Op::RuleRef(index) => match self.results.get(index as usize) {
                    Some(matched) => stack.push(Value::Bool(*matched)),
                    None => {
                        break Err(VmError::MissingRuleResult {
                            at: here,
                            rule: index,
                        })
                    }
                },

                Op::PeField(member) => stack.push(pe_field(input, member)),

                Op::DotNetField(member) => stack.push(dotnet_field(input, member)),

                Op::PeIndexed(member) => {
                    let index = pop!();
                    stack.push(pe_element(input, member, &index));
                }

                Op::DotNetIndexed(member) => {
                    let index = pop!();
                    stack.push(dotnet_element(input, member, &index));
                }

                Op::PeVersionInfo => {
                    let key = pop!();
                    stack.push(version_info(input, &key));
                }

                Op::PeCall(func) => {
                    // Popped as a block, so the operands end up in written
                    // order. The count is the variant's own, which is why
                    // `pe.imports` has two variants: the interpreter cannot ask
                    // how many operands the compiler emitted, so the compiler
                    // has to have committed to one when it chose the opcode.
                    let arity = func.arity() as usize;
                    if stack.len() < arity {
                        break Err(VmError::StackUnderflow { at: here, op: *op });
                    }
                    let args: Vec<Value> = stack.split_off(stack.len() - arity);
                    stack.push(pe_call(input, func, &args));
                }

                Op::ModuleCall(func) => {
                    let arity = func.arity() as usize;
                    if stack.len() < arity {
                        break Err(VmError::StackUnderflow { at: here, op: *op });
                    }
                    let args: Vec<Value> = stack.split_off(stack.len() - arity);
                    stack.push(module_call(input, func, &args));
                }

                Op::Ret => {
                    let v = pop!();
                    break Ok(v.is_truthy());
                }
            }
        };

        self.peak_stack = self.peak_stack.max(stack.len());
        stack.clear();
        self.stack = stack;
        result
    }
}

/// `Value::as_offset` and `Value::as_index` are the same conversion under two
/// names, because the two uses read better apart: an offset is a position in
/// the buffer, an index is a position in a list.
trait AsOffset {
    fn as_offset(&self) -> Option<i64>;
    fn as_index(&self) -> Option<i64>;
}

impl AsOffset for Value {
    /// A buffer offset. Only integers address memory; a float offset comes from
    /// arithmetic that has lost track of what it was counting.
    fn as_offset(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// A list index. `Bool` and `Float` are accepted here where they are not
    /// offsets, because `@a[1]` and `@a[some_float]` are the same question asked
    /// in different words, and refusing the second only makes an author hunt
    /// for a type error they cannot see.
    fn as_index(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Bool(b) => Some(i64::from(*b)),
            Value::Float(f) if f.fract() == 0.0 => Some(*f as i64),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

/// Read an unsigned integer, or `None` if it does not fit in the buffer.
fn read_int(data: &[u8], at: Option<i64>, width: usize, endian: Endian) -> Option<i64> {
    let at = usize::try_from(at?).ok()?;
    let end = at.checked_add(width)?;
    let bytes = data.get(at..end)?;
    let mut value: i64 = 0;
    for (index, byte) in bytes.iter().enumerate() {
        // Little-endian means the first byte read is the least significant, so
        // the shift counts from the front; big-endian counts back from the
        // last byte. Shifting the first byte up and then shifting back down
        // would be a bit reversal, which is a different function.
        let shift = match endian {
            Endian::Little => 8 * index,
            Endian::Big => 8 * (width - 1 - index),
        };
        value |= i64::from(*byte) << shift;
    }
    Some(value)
}

/// Read an integer of `width` bytes, sign-extended when `signed`.
fn read(data: &[u8], at: Option<i64>, width: usize, endian: Endian, signed: bool) -> Value {
    let Some(mut value) = read_int(data, at, width, endian) else {
        return Value::Undefined;
    };
    if signed {
        let bits = (width * 8) as u32;
        // Sign-extend by shifting the sign bit up and then arithmetically down.
        value = (value << (64 - bits)) >> (64 - bits);
    }
    Value::Int(value)
}

/// Integer and floating-point arithmetic, with the type rules the language has.
///
/// Integer stays integer: `uint32(0)` can carry the top bit set, and routing it
/// through `f64` would lose the low bits and change which files match. Division
/// by zero and the one overflowing division yield `Undefined` rather than
/// trapping — a rule dividing by a field that happens to be zero is a rule that
/// does not match, not a scanner that crashes.
fn arith(op: Op, a: Value, b: Value) -> Value {
    if let (Value::Int(x), Value::Int(y)) = (&a, &b) {
        let (x, y) = (*x, *y);
        return match op {
            Op::Add => Value::Int(x.wrapping_add(y)),
            Op::Sub => Value::Int(x.wrapping_sub(y)),
            Op::Mul => Value::Int(x.wrapping_mul(y)),
            Op::Div => match x.checked_div(y) {
                Some(v) => Value::Int(v),
                None => Value::Undefined,
            },
            Op::Mod => match x.checked_rem(y) {
                Some(v) => Value::Int(v),
                None => Value::Undefined,
            },
            _ => Value::Undefined,
        };
    }
    let (Some(x), Some(y)) = (a.as_number(), b.as_number()) else {
        return Value::Undefined;
    };
    match op {
        Op::Add => Value::Float(x + y),
        Op::Sub => Value::Float(x - y),
        Op::Mul => Value::Float(x * y),
        Op::Div => {
            if y == 0.0 {
                Value::Undefined
            } else {
                Value::Float(x / y)
            }
        }
        Op::Mod => {
            if y == 0.0 {
                Value::Undefined
            } else {
                Value::Float(x % y)
            }
        }
        _ => Value::Undefined,
    }
}

/// Bitwise operations, integers only.
///
/// A shift of 64 or more is `Undefined` rather than a masked shift. Masking
/// would make `1 << 64` equal `1`, so a rule using a computed shift width could
/// match a file it has no business matching; refusing to answer is the honest
/// outcome, and the comparison that consumes it fails.
fn bitwise(op: Op, a: Value, b: Value) -> Value {
    let (Value::Int(x), Value::Int(y)) = (&a, &b) else {
        return Value::Undefined;
    };
    let (x, y) = (*x, *y);
    match op {
        Op::BitAnd => Value::Int(x & y),
        Op::BitOr => Value::Int(x | y),
        Op::BitXor => Value::Int(x ^ y),
        Op::Shl => match u32::try_from(y).ok().and_then(|s| x.checked_shl(s)) {
            Some(v) => Value::Int(v),
            None => Value::Undefined,
        },
        Op::Shr => match u32::try_from(y).ok().and_then(|s| x.checked_shr(s)) {
            Some(v) => Value::Int(v),
            None => Value::Undefined,
        },
        _ => Value::Undefined,
    }
}

fn cmp_of(op: Op) -> CmpOp {
    match op {
        Op::Eq => CmpOp::Eq,
        Op::Ne => CmpOp::Ne,
        Op::Lt => CmpOp::Lt,
        Op::Le => CmpOp::Le,
        Op::Gt => CmpOp::Gt,
        _ => CmpOp::Ge,
    }
}

/// Compare two values.
///
/// `Undefined` makes every comparison false, `!=` included. This is the one
/// place the language is deliberately not like a C programmer's intuition, and
/// it is what makes a missing field harmless: a rule asking whether a field
/// that does not exist is *not* something gets `false`, so the rule fails,
/// which is what "we could not establish this" should mean.
fn compare(op: CmpOp, a: &Value, b: &Value) -> bool {
    use std::cmp::Ordering;

    if a.is_undefined() || b.is_undefined() {
        return false;
    }
    let ordering = match (a, b) {
        // Byte order, not `str` order: for the ASCII that every corpus literal
        // is written in the two agree, and for the rest only this one is a total
        // order over the values the engine can actually hold.
        (Value::Bytes(x), Value::Bytes(y)) => x.as_ref().cmp(y.as_ref()),
        _ => {
            // Integer against integer compares as integers, so that values with
            // the top bit set compare exactly. Anything involving a float goes
            // through `f64`.
            match (a, b) {
                (Value::Int(x), Value::Int(y)) => x.cmp(y),
                _ => {
                    let (Some(x), Some(y)) = (a.as_number(), b.as_number()) else {
                        // A string against a number has no ordering, but
                        // equality still has an answer: they are not equal.
                        return matches!(op, CmpOp::Ne);
                    };
                    x.partial_cmp(&y).unwrap_or(Ordering::Equal)
                }
            }
        }
    };
    match op {
        CmpOp::Eq => ordering.is_eq(),
        CmpOp::Ne => ordering.is_ne(),
        CmpOp::Lt => ordering.is_lt(),
        CmpOp::Le => ordering.is_le(),
        CmpOp::Gt => ordering.is_gt(),
        CmpOp::Ge => ordering.is_ge(),
    }
}

/// The `contains` family.
///
/// Case-insensitive comparison is ASCII-only, deliberately. Folding Unicode
/// would make `ı` equal `i` in one locale and not another, so a rule would
/// match different files on different machines — and the strings being compared
/// are import names, registry keys and file paths, which are ASCII by
/// construction.
fn text_cmp(kind: Cmp, a: &Value, b: &Value) -> bool {
    let (Value::Bytes(haystack), Value::Bytes(needle)) = (a, b) else {
        return false;
    };
    let (haystack, needle) = (haystack.as_ref(), needle.as_ref());
    match kind {
        Cmp::Contains => contains(haystack, needle, false),
        Cmp::IContains => contains(haystack, needle, true),
        Cmp::StartsWith => starts_with(haystack, needle, false),
        Cmp::IStartsWith => starts_with(haystack, needle, true),
        Cmp::EndsWith => ends_with(haystack, needle, false),
        Cmp::IEndsWith => ends_with(haystack, needle, true),
        Cmp::IEquals => eq_ignore_ascii_case(haystack, needle),
    }
}

fn contains(haystack: &[u8], needle: &[u8], fold: bool) -> bool {
    if needle.is_empty() {
        // Every string contains the empty string. Answering `false` would make
        // `x contains ""` a rule that never fires, which is not what the author
        // wrote, but answering `true` here is what every other implementation
        // does.
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    if !fold {
        return haystack.windows(needle.len()).any(|w| w == needle);
    }
    haystack
        .windows(needle.len())
        .any(|w| eq_ignore_ascii_case(w, needle))
}

fn starts_with(haystack: &[u8], needle: &[u8], fold: bool) -> bool {
    let Some(head) = haystack.get(..needle.len()) else {
        return false;
    };
    if fold {
        eq_ignore_ascii_case(head, needle)
    } else {
        head == needle
    }
}

fn ends_with(haystack: &[u8], needle: &[u8], fold: bool) -> bool {
    let Some(tail) = haystack
        .len()
        .checked_sub(needle.len())
        .and_then(|at| haystack.get(at..))
    else {
        return false;
    };
    if fold {
        eq_ignore_ascii_case(tail, needle)
    } else {
        tail == needle
    }
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_condition, StringTable};
    use crate::matches::Match;
    use crate::parser::parse_file;

    /// Compile the first rule of a snippet and run it.
    fn run_with(source: &str, data: &[u8], matches: &[(u32, u32, u32)]) -> bool {
        let file = parse_file(source).expect("test source must parse");
        let rule = &file.rules[0];
        let table = StringTable::from_defs(&rule.strings);
        let program = compile_condition(&rule.condition, &table, rule.span)
            .expect("test source must compile");
        let mut set = MatchSet::with_capacity(program.string_count as usize);
        for (slot, offset, length) in matches {
            set.push(*slot, Match::new(*offset, *length));
        }
        set.sort();
        Vm::new()
            .run(&program, &set, &Input::new(data))
            .expect("a compiled program must run")
    }

    fn run(source: &str, data: &[u8]) -> bool {
        run_with(source, data, &[])
    }

    /// Whether a snippet is refused before it can run.
    ///
    /// Used where the point of the test is that something *does not* compile —
    /// a member that was never implemented, a struct read without its field, a
    /// function given the wrong number of arguments. Those must fail at compile
    /// time, because the alternative is a rule that runs and answers wrongly.
    fn compile_fails(source: &str) -> bool {
        let Ok(file) = parse_file(source) else {
            return true;
        };
        let Some(rule) = file.rules.first() else {
            return true;
        };
        let table = StringTable::from_defs(&rule.strings);
        compile_condition(&rule.condition, &table, rule.span).is_err()
    }

    /// Run a condition against a buffer that has been parsed as a PE.
    ///
    /// The parse is done here rather than inside the interpreter because that
    /// is where it belongs in production too: once per file, not once per rule.
    /// `pub(super)` because the real-file checks in the sibling module below run
    /// through it too, rather than each growing its own copy of the compile and
    /// evaluate steps.
    pub(super) fn run_pe(source: &str, data: &[u8]) -> bool {
        let image = PeInput::parse(data).expect("the fixture must parse as a PE");
        run_pe_with(source, data, &image)
    }

    fn run_pe_with(source: &str, data: &[u8], image: &PeInput<'_>) -> bool {
        let file = parse_file(source).expect("test source must parse");
        let rule = &file.rules[0];
        let table = StringTable::from_defs(&rule.strings);
        let program = compile_condition(&rule.condition, &table, rule.span)
            .expect("test source must compile");
        let set = MatchSet::with_capacity(program.string_count as usize);
        Vm::new()
            .run(&program, &set, &Input::with_pe(data, image))
            .expect("a compiled program must run")
    }

    // -- constants and arithmetic -----------------------------------------

    #[test]
    fn integer_arithmetic_stays_exact_at_the_top_of_the_range() {
        // `uint32(0)` with the top bit set is the case that catches an
        // implementation routing integers through `f64`.
        assert!(run("rule r { condition: 0xFFFFFFFF == 4294967295 }", b""));
        assert!(run("rule r { condition: 0xFFFFFFFF > 0 }", b""));
    }

    #[test]
    fn division_and_modulo_follow_the_usual_rules() {
        assert!(run("rule r { condition: 7 / 2 == 3 }", b""));
        assert!(run("rule r { condition: 7 % 2 == 1 }", b""));
        assert!(run("rule r { condition: -7 / 2 == -3 }", b""));
    }

    #[test]
    fn division_by_zero_is_undefined_rather_than_a_crash() {
        // A rule dividing by a field that happens to be zero must not take the
        // scanner down with it.
        assert!(!run("rule r { condition: 1 / 0 == 0 }", b""));
        assert!(!run("rule r { condition: 1 % 0 == 0 }", b""));
        assert!(run("rule r { condition: not (1 / 0 == 0) }", b""));
    }

    #[test]
    fn floating_point_arithmetic_is_available() {
        assert!(run("rule r { condition: 1.5 + 1.5 == 3.0 }", b""));
        assert!(run("rule r { condition: 3.0 / 2.0 == 1.5 }", b""));
        // Float division by zero is `Undefined`, like the integer case, so the
        // comparison fails rather than the result being infinity.
        assert!(!run("rule r { condition: 1.0 / 0.0 == 0.0 }", b""));
    }

    #[test]
    fn bitwise_operators_work_on_integers() {
        assert!(run("rule r { condition: 0xF0 & 0x0F == 0 }", b""));
        assert!(run("rule r { condition: 0xF0 | 0x0F == 0xFF }", b""));
        assert!(run("rule r { condition: 0xFF ^ 0x0F == 0xF0 }", b""));
        assert!(run("rule r { condition: 1 << 4 == 16 }", b""));
        assert!(run("rule r { condition: 256 >> 4 == 16 }", b""));
    }

    #[test]
    fn a_shift_past_the_word_width_is_undefined_not_wrapped() {
        // Masking the shift would make `1 << 64` equal `1`, so a rule with a
        // computed shift width could match a file it has no business matching.
        assert!(!run("rule r { condition: 1 << 64 == 1 }", b""));
        assert!(!run("rule r { condition: 1 << 64 == 0 }", b""));
    }

    #[test]
    fn negation_and_complement_work() {
        assert!(run("rule r { condition: -5 == 0 - 5 }", b""));
        assert!(run("rule r { condition: ~0 == -1 }", b""));
    }

    // -- comparison --------------------------------------------------------

    #[test]
    fn string_comparison_is_bytewise() {
        assert!(run(r#"rule r { condition: "abc" == "abc" }"#, b""));
        assert!(run(r#"rule r { condition: "abc" < "abd" }"#, b""));
        assert!(run(r#"rule r { condition: "Z" < "a" }"#, b""));
        assert!(!run(r#"rule r { condition: "abc" == "ABC" }"#, b""));
    }

    #[test]
    fn undefined_makes_every_comparison_false_including_not_equal() {
        // The one place the language is deliberately not like C. This is what
        // makes a missing field harmless: "not equal to X" is false, so the
        // rule fails, which is what "we could not establish this" should mean.
        for source in [
            "rule r { condition: entrypoint == 0 }",
            "rule r { condition: entrypoint != 0 }",
            "rule r { condition: entrypoint > 0 }",
            "rule r { condition: entrypoint <= 0 }",
        ] {
            assert!(
                !run(source, b"MZ"),
                "{source} must be false with no entry point"
            );
        }
    }

    #[test]
    fn a_present_entry_point_is_used() {
        let file = parse_file("rule r { condition: entrypoint == 0x1000 }").unwrap();
        let rule = &file.rules[0];
        let table = StringTable::default();
        let program = compile_condition(&rule.condition, &table, rule.span).unwrap();
        let hit = Vm::new()
            .run(
                &program,
                &MatchSet::default(),
                &Input::with_entry_point(b"MZ", Some(0x1000)),
            )
            .unwrap();
        assert!(hit);
    }

    #[test]
    fn a_different_type_pair_still_answers_equality() {
        assert!(!run(r#"rule r { condition: "1" == 1 }"#, b""));
        assert!(run(r#"rule r { condition: "1" != 1 }"#, b""));
    }

    // -- buffer readers ----------------------------------------------------

    #[test]
    fn readers_decode_little_endian_by_default() {
        assert!(run(
            "rule r { condition: uint16(0) == 0x5A4D }",
            b"MZ\x90\x00"
        ));
        assert!(run(
            "rule r { condition: uint32(0) == 0x00905A4D }",
            b"MZ\x90\x00"
        ));
        assert!(run("rule r { condition: uint8(0) == 0x4D }", b"MZ"));
    }

    #[test]
    fn big_endian_readers_swap_the_byte_order() {
        assert!(run("rule r { condition: uint16be(0) == 0x4D5A }", b"MZ"));
        assert!(run(
            "rule r { condition: uint32be(0) == 0x4D5A9000 }",
            b"MZ\x90\x00"
        ));
    }

    #[test]
    fn signed_readers_sign_extend() {
        assert!(run(r#"rule r { condition: int8(0) == -1 }"#, b"\xFF"));
        assert!(run(r#"rule r { condition: int16(0) == -1 }"#, b"\xFF\xFF"));
        // The unsigned spelling of the same bytes is the all-ones value.
        assert!(run("rule r { condition: uint8(0) == 255 }", b"\xFF"));
    }

    #[test]
    fn a_read_past_the_end_of_the_buffer_is_undefined() {
        for source in [
            "rule r { condition: uint8(2) == 0 }",
            "rule r { condition: uint16(1) == 0 }",
            "rule r { condition: uint32(0) == 0 }",
            "rule r { condition: uint8(-1) == 0 }",
            "rule r { condition: uint16(0x7FFFFFFF) == 0 }",
        ] {
            assert!(!run(source, b"MZ"), "{source} must be undefined");
        }
    }

    #[test]
    fn a_read_exactly_at_the_last_byte_is_in_range() {
        // One past the end is undefined; the last byte itself is not.
        assert!(run("rule r { condition: uint8(1) == 0x5A }", b"MZ"));
        assert!(!run("rule r { condition: uint8(2) == 0 }", b"MZ"));
    }

    #[test]
    fn filesize_is_the_buffer_length() {
        assert!(run("rule r { condition: filesize == 3 }", b"abc"));
        assert!(run("rule r { condition: filesize == 0 }", b""));
    }

    // -- strings -----------------------------------------------------------

    #[test]
    fn a_bare_string_reference_tests_for_any_match() {
        let s = r#"rule r { strings: $a = "x" condition: $a }"#;
        assert!(run_with(s, b"", &[(0, 10, 1)]));
        assert!(!run_with(s, b"", &[]));
    }

    #[test]
    fn a_count_is_the_number_of_matches() {
        let s = r#"rule r { strings: $a = "x" condition: #a == 3 }"#;
        assert!(run_with(s, b"", &[(0, 1, 1), (0, 5, 1), (0, 9, 1)]));
        assert!(!run_with(s, b"", &[(0, 1, 1), (0, 5, 1)]));
    }

    #[test]
    fn the_first_offset_is_the_lowest_offset_whatever_order_the_matches_arrived_in() {
        // "First" means leftmost in the file, not the first one a matcher
        // happened to report. Feeding the same two matches in the opposite
        // order must give the same answer, which is the whole reason the table
        // is sorted before the interpreter sees it.
        let s = r#"rule r { strings: $a = "x" condition: @a == 5 }"#;
        assert!(run_with(s, b"", &[(0, 5, 1), (0, 40, 1)]));
        assert!(run_with(s, b"", &[(0, 40, 1), (0, 5, 1)]));
    }

    #[test]
    fn an_indexed_offset_selects_the_nth_match_from_one() {
        let s = r#"rule r { strings: $a = "x" condition: @a[2] == 40 }"#;
        assert!(run_with(s, b"", &[(0, 5, 1), (0, 40, 1)]));
        assert!(!run_with(s, b"", &[(0, 5, 1)]), "there is no second match");
    }

    #[test]
    fn an_offset_with_no_match_is_undefined_rather_than_zero() {
        // Undefined means the comparison fails, which is right. Zero would mean
        // "matched at the start of the file", which is a detection invented out
        // of nothing.
        let s = r#"rule r { strings: $a = "x" condition: @a == 0 }"#;
        assert!(!run_with(s, b"", &[]));
    }

    #[test]
    fn a_length_comes_from_the_match_not_the_definition() {
        // A pattern with a variable jump matches different lengths at
        // different offsets, so the length cannot be read off the rule.
        let s = r#"rule r { strings: $a = "x" condition: !a == 7 }"#;
        assert!(run_with(s, b"", &[(0, 5, 7)]));
        assert!(!run_with(s, b"", &[(0, 5, 4)]));
    }

    #[test]
    fn at_requires_the_match_to_begin_there() {
        let s = r#"rule r { strings: $a = "x" condition: $a at 4096 }"#;
        assert!(run_with(s, b"", &[(0, 4096, 8)]));
        assert!(!run_with(s, b"", &[(0, 4097, 8)]));
    }

    #[test]
    fn in_requires_the_whole_match_inside_the_range() {
        let s = r#"rule r { strings: $a = "x" condition: $a in (0..512) }"#;
        assert!(
            run_with(s, b"", &[(0, 500, 12)]),
            "ends exactly at the bound"
        );
        assert!(!run_with(s, b"", &[(0, 500, 13)]), "overruns the bound");
        assert!(!run_with(s, b"", &[(0, 512, 4)]));
    }

    // -- sets and quantifiers ----------------------------------------------

    #[test]
    fn any_of_them_needs_one_match() {
        let s = r#"rule r { strings: $a = "x" $b = "y" condition: any of them }"#;
        assert!(run_with(s, b"", &[(1, 0, 1)]));
        assert!(!run_with(s, b"", &[]));
    }

    #[test]
    fn all_of_them_needs_every_string() {
        let s = r#"rule r { strings: $a = "x" $b = "y" condition: all of them }"#;
        assert!(run_with(s, b"", &[(0, 0, 1), (1, 9, 1)]));
        assert!(!run_with(s, b"", &[(0, 0, 1)]));
    }

    #[test]
    fn none_of_them_is_true_when_nothing_matched() {
        let s = r#"rule r { strings: $a = "x" $b = "y" condition: none of them }"#;
        assert!(run_with(s, b"", &[]));
        assert!(!run_with(s, b"", &[(1, 0, 1)]));
    }

    #[test]
    fn a_counted_set_needs_that_many() {
        let s = r#"rule r { strings: $a = "x" $b = "y" $c = "z" condition: 2 of them }"#;
        assert!(run_with(s, b"", &[(0, 0, 1), (2, 9, 1)]));
        assert!(!run_with(s, b"", &[(0, 0, 1)]));
    }

    #[test]
    fn a_count_beyond_the_set_size_never_matches() {
        let s = r#"rule r { strings: $a = "x" condition: 2 of them }"#;
        assert!(!run_with(s, b"", &[(0, 0, 1)]));
    }

    #[test]
    fn the_quantifier_does_not_depend_on_the_stack_order_of_the_results() {
        // The count sits below the results; if the interpreter popped it first
        // it would read the last match result as the required count.
        let s = r#"rule r { strings: $a = "x" $b = "y" $c = "z" condition: 3 of them }"#;
        assert!(run_with(s, b"", &[(0, 0, 1), (1, 1, 1), (2, 2, 1)]));
        assert!(!run_with(s, b"", &[(0, 0, 1), (1, 1, 1)]));
    }

    #[test]
    fn a_percentage_of_a_set_is_evaluated_against_its_size() {
        let s = r#"rule r { strings: $a = "x" $b = "y" $c = "z" $d = "w" condition: 50% of them }"#;
        assert!(
            run_with(s, b"", &[(0, 0, 1), (1, 1, 1)]),
            "two of four is 50%"
        );
        assert!(!run_with(s, b"", &[(0, 0, 1)]));
    }

    // -- for .. in range ---------------------------------------------------

    /// A rule whose condition is a `for` over a range.
    fn loop_rule(condition: &str) -> String {
        format!("rule r {{ condition: {condition} }}")
    }

    #[test]
    fn a_range_includes_both_of_its_ends() {
        // The documented equivalence: `(1..3)` is the same as writing out
        // `1, 2, 3`. The corpus leans on this — `for any i in (0 ..
        // pe.number_of_sections - 1)` visits every section only if the upper
        // bound is one of them.
        assert!(run(&loop_rule("for any i in (1..3) : ( i == 3 )"), b""));
        assert!(!run(&loop_rule("for any i in (1..3) : ( i == 4 )"), b""));
        for expected in [1, 2, 3] {
            assert!(
                run(
                    &loop_rule(&format!("for any i in (1..3) : ( i == {expected} )")),
                    b""
                ),
                "{expected} is inside 1..3"
            );
        }
    }

    #[test]
    fn a_range_that_begins_and_ends_together_is_one_iteration() {
        // `(0..0)` is the set containing zero, not the empty set. Under a
        // half-open reading it would be empty and `for all` would come out
        // vacuously true — a rule that fires on every file.
        assert!(run(&loop_rule("for any i in (0..0) : ( i == 0 )"), b""));
        assert!(run(&loop_rule("for all i in (0..0) : ( i == 0 )"), b""));
        assert!(!run(&loop_rule("for all i in (0..0) : ( i == 1 )"), b""));
    }

    #[test]
    fn a_range_may_run_backwards() {
        assert!(run(&loop_rule("for any i in (3..1) : ( i == 1 )"), b""));
        assert!(run(
            &loop_rule("for all i in (3..1) : ( i >= 1 and i <= 3 )"),
            b""
        ));
        // Three values either way, so a count of three holds in both
        // directions and a count of four does not.
        assert!(run(&loop_rule("for 3 i in (3..1) : ( true )"), b""));
        assert!(!run(&loop_rule("for 4 i in (3..1) : ( true )"), b""));
    }

    #[test]
    fn each_quantifier_means_what_it_says_over_a_range() {
        assert!(run(&loop_rule("for any i in (1..4) : ( i == 2 )"), b""));
        assert!(!run(&loop_rule("for any i in (1..4) : ( i == 9 )"), b""));

        assert!(run(&loop_rule("for all i in (1..4) : ( i >= 1 )"), b""));
        assert!(!run(&loop_rule("for all i in (1..4) : ( i >= 2 )"), b""));

        assert!(run(&loop_rule("for none i in (1..4) : ( i == 9 )"), b""));
        assert!(!run(&loop_rule("for none i in (1..4) : ( i == 2 )"), b""));

        assert!(run(&loop_rule("for 4 i in (1..4) : ( true )"), b""));
        assert!(!run(&loop_rule("for 5 i in (1..4) : ( true )"), b""));
        // Zero of anything is trivially satisfied, including of a body that is
        // false every time.
        assert!(run(&loop_rule("for 0 i in (1..4) : ( false )"), b""));
    }

    #[test]
    fn a_count_is_allowed_to_be_an_expression() {
        // `for pe.number_of_sections i in ...` is the real shape of this, so
        // the count is an expression rather than a literal the parser folds.
        assert!(run(&loop_rule("for 1 + 1 i in (1..4) : ( true )"), b""));
        assert!(!run(&loop_rule("for 1 + 4 i in (1..4) : ( true )"), b""));
    }

    #[test]
    fn loops_nest_and_an_inner_variable_shadows_an_outer_one() {
        assert!(run(
            &loop_rule("for any i in (1..3) : ( for any j in (1..3) : ( i == 2 and j == 3 ) )"),
            b""
        ));
        assert!(!run(
            &loop_rule("for any i in (1..3) : ( for any j in (1..3) : ( i == 9 and j == 9 ) )"),
            b""
        ));
        // Both loops name `i`. The inner one wins inside its own body, and the
        // outer one is still itself once the inner loop is over.
        assert!(run(
            &loop_rule("for any i in (1..2) : ( for any i in (5..6) : ( i == 5 ) and i == 1 )"),
            b""
        ));
    }

    #[test]
    fn the_loop_variable_can_be_read_as_well_as_compared() {
        // `@a[i]` and `uint8(i)` are why the variable exists. A compiler that
        // only handled it in comparisons would pass the tests above.
        assert!(run(
            &loop_rule("for any i in (0..3) : ( uint8(i) == 0x41 )"),
            b"AAAA"
        ));
        assert!(!run(
            &loop_rule("for any i in (0..3) : ( uint8(i) == 0x42 )"),
            b"AAAA"
        ));
    }

    #[test]
    fn a_string_offset_indexed_by_the_loop_variable_is_reachable() {
        // The idiom the range loops in the corpus are actually written for.
        let s = r#"rule r { strings: $a = "MZ" condition: for any i in (1..2) : ( @a[i] == 4 ) }"#;
        assert!(run_with(s, b"....MZ..MZ", &[(0, 4, 2), (0, 8, 2)]));
        assert!(!run_with(s, b"MZ......MZ", &[(0, 0, 2), (0, 8, 2)]));
    }

    #[test]
    fn a_bound_that_is_not_a_number_makes_the_loop_undefined() {
        // `1 / 0` is undefined, and so is any module field that could not be
        // read. The loop must not fall back on its identity: for `none`, whose
        // identity is *true*, that would be a rule that fires on every file.
        assert!(!run(
            &loop_rule("for none i in (0..(1 / 0)) : ( false )"),
            b""
        ));
        assert!(!run(
            &loop_rule("for any i in (0..(1 / 0)) : ( true )"),
            b""
        ));
        assert!(!run(
            &loop_rule("for all i in (0..(1 / 0)) : ( true )"),
            b""
        ));
        assert!(!run(&loop_rule("for 0 i in (0..(1 / 0)) : ( true )"), b""));
        // The same body over a real range, to show the difference is the bound
        // and not the body.
        assert!(run(&loop_rule("for none i in (0..3) : ( false )"), b""));
    }

    #[test]
    fn a_range_longer_than_the_iteration_budget_is_undefined_not_truncated() {
        // The budget is per rule and finite, so a range of a million has to
        // give up somewhere. Answering with what it managed to see would make
        // `for all` true and `for any` false on a prefix — one a false
        // positive, the other a false negative. Undefined is neither.
        assert!(!run(
            &loop_rule("for all i in (0..1000000) : ( i >= 0 )"),
            b""
        ));
        assert!(!run(
            &loop_rule("for any i in (0..1000000) : ( i == 999999 )"),
            b""
        ));
        assert!(!run(
            &loop_rule("for none i in (0..1000000) : ( i == 999999 )"),
            b""
        ));
        // A range that stays inside the budget still answers.
        assert!(run(&loop_rule("for all i in (0..1000) : ( i >= 0 )"), b""));
    }

    #[test]
    fn a_settled_quantifier_stops_walking_the_range() {
        // Not just an optimisation: `for any i in (0..1000000) : ( i == 0 )` is
        // decided by its first iteration, so it must not exhaust the budget and
        // turn into `Undefined`.
        assert!(run(
            &loop_rule("for any i in (0..1000000) : ( i == 0 )"),
            b""
        ));
        assert!(!run(
            &loop_rule("for all i in (0..1000000) : ( i > 0 )"),
            b""
        ));
        assert!(!run(
            &loop_rule("for none i in (0..1000000) : ( i == 0 )"),
            b""
        ));
    }

    #[test]
    fn a_looping_rule_completes_within_the_step_bound_it_reports() {
        // The step bound is what stops a runaway rule from hanging a scan. If
        // it were computed too low, these would come back as `StepLimit` rather
        // than an answer — so running to completion *is* the assertion.
        let sources = [
            loop_rule("for any i in (0..3) : ( i == 1 )"),
            loop_rule("for all i in (0..2000) : ( i >= 0 )"),
            loop_rule("for any i in (0..2000) : ( false )"),
            loop_rule("for any i in (3..0) : ( false )"),
            loop_rule("for any i in (0..50) : ( for any j in (0..50) : ( i + j == 98 ) )"),
            loop_rule("for 3 i in (0..10) : ( i > 1 )"),
            loop_rule("for any i in (0..3) : ( for none j in (0..3) : ( j == i ) )"),
        ];
        for source in sources {
            let file = parse_file(&source).expect("test source must parse");
            let rule = &file.rules[0];
            let table = StringTable::from_defs(&rule.strings);
            let program = compile_condition(&rule.condition, &table, rule.span)
                .expect("test source must compile");
            let set = MatchSet::with_capacity(program.string_count as usize);
            let outcome = Vm::new().run(&program, &set, &Input::new(b""));
            assert!(
                outcome.is_ok(),
                "{source}: {:?} with a bound of {} steps",
                outcome.unwrap_err(),
                program.max_steps
            );
        }
    }

    // -- short circuit -----------------------------------------------------

    #[test]
    fn and_and_or_follow_the_truth_table_including_undefined() {
        // `filesize == 2` on two bytes is the true operand, `filesize == 9` the
        // false one, and `entrypoint == 0` the undefined one — no entry point
        // was given, so it compares false either way. The rows with `undefined`
        // are the ones worth having: they are where a three-valued logic either
        // behaves or quietly turns into two-valued.
        let t = "filesize == 2";
        let f = "filesize == 9";
        let u = "entrypoint == 0";
        let cases = [
            (format!("{t} and {t}"), true),
            (format!("{t} and {f}"), false),
            (format!("{f} and {t}"), false),
            (format!("{f} and {f}"), false),
            (format!("{t} and {u}"), false),
            (format!("{u} and {t}"), false),
            (format!("{u} and {u}"), false),
            (format!("{t} or {t}"), true),
            (format!("{t} or {f}"), true),
            (format!("{f} or {t}"), true),
            (format!("{f} or {f}"), false),
            (format!("{f} or {u}"), false),
            (format!("{u} or {t}"), true),
            (format!("{u} or {u}"), false),
        ];
        for (expr, expected) in cases {
            assert_eq!(
                run(&format!("rule r {{ condition: {expr} }}"), b"MZ"),
                expected,
                "{expr}"
            );
        }
    }

    #[test]
    fn a_conditional_jump_selects_between_the_two_arms() {
        // Short-circuiting cannot be observed from a rule's answer — conditions
        // are pure, so evaluating the right-hand side anyway gives the same
        // result, only slower. What can be observed is whether the jump happens,
        // so this builds the shape by hand. The jump consumes its condition and
        // each arm pushes its own result, exactly as the compiler emits it:
        //
        //   0  Push(<condition>)
        //   1  JumpIfFalse(4)      ; or JumpIfTrue
        //   2  Push(<falls through to>)
        //   3  Ret
        //   4  Push(<jumps to>)
        //   5  Ret
        use crate::ast::Span;
        use crate::program::{Const, Program};

        let build = |condition: bool, jump_if_false: bool, arms: (bool, bool)| {
            let mut program = Program::new(Span::new(0, 0));
            let c = program.constant(Const::Bool(condition));
            let yes = program.constant(Const::Bool(arms.0));
            let no = program.constant(Const::Bool(arms.1));
            program.emit(Op::Push(c));
            program.emit(if jump_if_false {
                Op::JumpIfFalse(4)
            } else {
                Op::JumpIfTrue(4)
            });
            program.emit(Op::Push(yes));
            program.emit(Op::Ret);
            program.emit(Op::Push(no));
            program.emit(Op::Ret);
            program.compute_limits();
            program
        };

        let evaluate = |program: &crate::program::Program| {
            Vm::new()
                .run(program, &MatchSet::default(), &Input::new(b""))
                .unwrap()
        };

        for jump_if_false in [true, false] {
            for condition in [true, false] {
                // The question the instruction answers is "do I jump?", and
                // that is what the four combinations vary. Writing it this way
                // rather than tabulating expected answers keeps the assertion
                // about the jump rather than about an incidental coincidence
                // between the two jump kinds.
                let jumps = if jump_if_false { !condition } else { condition };
                let kind = if jump_if_false {
                    "JumpIfFalse"
                } else {
                    "JumpIfTrue"
                };

                // The jump arm pushes false, so a jump answers false.
                let program = build(condition, jump_if_false, (true, false));
                assert_eq!(
                    evaluate(&program),
                    !jumps,
                    "{kind} with a {condition} condition"
                );

                // Swapping the arms inverts the answer. Without this the test
                // above would pass on a machine that ignored the jump entirely,
                // as long as both arms happened to push the same value.
                let program = build(condition, jump_if_false, (false, true));
                assert_eq!(
                    evaluate(&program),
                    jumps,
                    "{kind} with a {condition} condition and swapped arms"
                );
            }
        }
    }

    #[test]
    fn both_paths_of_a_short_circuit_leave_the_stack_at_the_same_height() {
        // If one path pushed a value the other did not, the extra value would
        // survive to the end of the program and the next instruction would read
        // it — so a wrong answer here is the symptom. Each case takes a
        // different route through the four merges of a two-branch expression.
        let s = r#"rule r { strings: $a = "x" condition: (1 == 1 and $a) or (2 == 2 and filesize == 2) }"#;
        // The left branch decides; the right is jumped over.
        assert!(run_with(s, b"MZ", &[(0, 0, 1)]));
        // The left branch is false, so the answer comes from the far side.
        assert!(run_with(s, b"MZ", &[]));
        // Neither branch: the second operand of the left `and` is false and the
        // second operand of the right `and` is too.
        let f = r#"rule r { strings: $a = "x" condition: (1 == 1 and $a) or (2 == 2 and filesize == 9) }"#;
        assert!(!run_with(f, b"MZ", &[]));
    }

    // -- program safety ----------------------------------------------------

    #[test]
    fn a_jump_past_the_end_of_the_program_is_an_error() {
        use crate::ast::Span;
        use crate::program::Program;
        let mut program = Program::new(Span::new(0, 0));
        program.emit(Op::Jump(999));
        program.emit(Op::Ret);
        program.compute_limits();
        let err = Vm::new()
            .run(&program, &MatchSet::default(), &Input::new(b""))
            .unwrap_err();
        assert!(matches!(err, VmError::BadJump { .. }), "{err}");
    }

    #[test]
    fn an_out_of_range_constant_is_an_error() {
        use crate::ast::Span;
        use crate::program::Program;
        let mut program = Program::new(Span::new(0, 0));
        program.emit(Op::Push(7));
        program.emit(Op::Ret);
        program.compute_limits();
        let err = Vm::new()
            .run(&program, &MatchSet::default(), &Input::new(b""))
            .unwrap_err();
        assert!(matches!(err, VmError::BadConstant { .. }), "{err}");
    }

    #[test]
    fn an_empty_program_is_an_error_rather_than_a_panic() {
        // A truncated entry in a corrupt database looks like this.
        use crate::ast::Span;
        use crate::program::Program;
        let program = Program::new(Span::new(0, 0));
        assert!(Vm::new()
            .run(&program, &MatchSet::default(), &Input::new(b""))
            .is_err());
    }

    #[test]
    fn a_string_slot_past_the_table_is_false_rather_than_a_panic() {
        use crate::ast::Span;
        use crate::program::Program;
        let mut program = Program::new(Span::new(0, 0));
        program.emit(Op::StrMatch(99));
        program.emit(Op::Ret);
        program.compute_limits();
        let hit = Vm::new()
            .run(&program, &MatchSet::with_capacity(1), &Input::new(b""))
            .unwrap();
        assert!(!hit);
    }

    #[test]
    fn the_stack_never_grows_past_the_compiled_bound() {
        // The bound is what lets the interpreter keep a reused stack instead of
        // growing one on the hot path. If it were too small the interpreter
        // would still be correct — the stack is a `Vec` — but the figure the
        // scanner reports and sizes buffers from would be a lie.
        let sources = [
            "rule r { condition: 1 + 2 * 3 - 4 / 5 }",
            "rule r { condition: (1 == 1 and 2 == 2) or (3 == 3 and 4 == 4) }",
            r#"rule r { strings: $a = "x" $b = "y" $c = "z" condition: any of them }"#,
            r#"rule r { strings: $a = "x" $b = "y" condition: 2 of them and #a > 1 }"#,
        ];
        for source in sources {
            let file = parse_file(source).unwrap();
            let rule = &file.rules[0];
            let table = StringTable::from_defs(&rule.strings);
            let program = compile_condition(&rule.condition, &table, rule.span).unwrap();
            let mut set = MatchSet::with_capacity(program.string_count as usize);
            for slot in 0..program.string_count {
                set.push(slot, Match::new(0, 1));
            }
            let mut vm = Vm::new();
            vm.run(&program, &set, &Input::new(b"MZ")).unwrap();
            assert!(
                vm.peak_stack as u32 <= program.max_stack.max(1),
                "{source}: peaked at {} with a bound of {}",
                vm.peak_stack,
                program.max_stack
            );
        }
    }

    #[test]
    fn a_vm_can_run_several_rules_in_sequence() {
        // The scanner keeps one `Vm` for a whole scan, so a run must not leave
        // anything behind for the next one to trip over.
        let file = parse_file(r#"rule r { strings: $a = "x" condition: $a and #a == 1 }"#).unwrap();
        let rule = &file.rules[0];
        let table = StringTable::from_defs(&rule.strings);
        let program = compile_condition(&rule.condition, &table, rule.span).unwrap();
        let mut vm = Vm::new();

        let mut absent = MatchSet::with_capacity(1);
        absent.sort();
        assert!(!vm.run(&program, &absent, &Input::new(b"")).unwrap());

        let mut present = MatchSet::with_capacity(1);
        present.push(0, Match::new(5, 1));
        present.sort();
        assert!(vm.run(&program, &present, &Input::new(b"")).unwrap());

        assert!(!vm.run(&program, &absent, &Input::new(b"")).unwrap());
    }

    // -- the pe module -----------------------------------------------------

    /// The fixture's own numbers, spelled out once so the tests below read as
    /// assertions about the *conversion* rather than about magic values.
    ///
    /// `.text` is RVA 0x1000 / raw 0x200, `.data` is RVA 0x2000 / raw 0x600, and
    /// the entry point is the first byte of `.text`.
    const TEXT_RVA: u64 = 0x1000;
    const TEXT_RAW: u64 = 0x200;
    const DATA_RVA: u64 = 0x2000;
    const DATA_RAW: u64 = 0x600;

    #[test]
    fn the_entry_point_is_the_file_offset_and_the_raw_member_is_the_rva() {
        // This is the pair most worth pinning: YARA's `pe.entry_point` is *not*
        // the field in the header, and a rule set written against YARA that is
        // read by an implementation returning the RVA would silently match the
        // wrong files rather than fail to compile.
        let pe32 = av_pe::testing::minimal_pe32();
        assert!(run_pe(
            &format!("rule r {{ condition: pe.entry_point == {TEXT_RAW} }}"),
            &pe32
        ));
        assert!(!run_pe(
            &format!("rule r {{ condition: pe.entry_point == {TEXT_RVA} }}"),
            &pe32
        ));
        assert!(run_pe(
            &format!("rule r {{ condition: pe.entry_point_raw == {TEXT_RVA} }}"),
            &pe32
        ));
    }

    #[test]
    fn the_header_members_read_their_own_fields() {
        let pe = av_pe::testing::minimal_pe32();
        for (condition, why) in [
            ("pe.is_pe == 1", "the file has a PE signature"),
            ("pe.is_32bit == 1", "the optional header is PE32"),
            ("pe.is_64bit == 0", "and it is not PE32+"),
            ("pe.is_dll == 0", "the characteristics lack IMAGE_FILE_DLL"),
            ("pe.machine == 0x14c", "IMAGE_FILE_MACHINE_I386"),
            ("pe.number_of_sections == 2", "the file header says two"),
            ("pe.timestamp == 0x60000000", "the linker stamp"),
            ("pe.characteristics == 0x0102", "EXECUTABLE | 32BIT"),
            ("pe.subsystem == 2", "IMAGE_SUBSYSTEM_WINDOWS_GUI"),
            ("pe.image_base == 0x400000", "the 32-bit default"),
            ("pe.section_alignment == 0x1000", "as the fixture writes it"),
            ("pe.file_alignment == 0x200", "as the fixture writes it"),
            ("pe.size_of_image == 0x3000", "as the fixture writes it"),
            ("pe.size_of_headers == 0x200", "as the fixture writes it"),
            ("pe.number_of_rva_and_sizes == 16", "a full directory table"),
            ("pe.checksum == 0", "the fixture leaves it zero"),
            ("pe.dll_characteristics == 0", "the fixture leaves it zero"),
            ("pe.opthdr_magic == 0x10b", "PE32's optional header magic"),
            (
                "pe.size_of_optional_header == 224",
                "what the COFF header says",
            ),
            (
                "pe.pointer_to_symbol_table == 0",
                "stripped, so no symbol table",
            ),
            ("pe.number_of_symbols == 0", "and no symbols in it"),
            ("pe.loader_flags == 0", "reserved and unset"),
            ("pe.win32_version_value == 0", "reserved and unset"),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} ({why})"
            );
        }
    }

    #[test]
    fn a_section_name_that_is_not_utf8_is_compared_as_the_bytes_it_is() {
        // The whole path this pins, in one test: a rule literal containing
        // `\xff`, through the lexer's escape decoder, the parser, the constant
        // pool, the stack and the comparison.
        //
        // Every step of that used to hold a `String`, and the conversions in the
        // middle were `String::from_utf8_lossy`. A single `\xff` in a rule
        // therefore became the three bytes of `U+FFFD` — so the rule compiled,
        // went into the database, and could never match the file it was written
        // about. The section name is the smallest case of this: eight bytes the
        // linker chose, which are not required to be text and in a packed or
        // deliberately obfuscated file are not.
        let mut pe = av_pe::testing::minimal_pe32();
        let sec = 0x80 + 4 + 20 + 224;
        pe[sec..sec + 8].copy_from_slice(b".\xff\xfe\x90\x00\x00\x00\x00");
        assert_eq!(
            av_pe::PeFile::parse(&pe)
                .unwrap()
                .section(0)
                .unwrap()
                .name_bytes(),
            b".\xff\xfe\x90",
            "the fixture names the section with bytes that are not UTF-8"
        );

        for (condition, why) in [
            (
                r#"pe.sections[0].name == ".\xff\xfe\x90""#,
                "the bytes the rule wrote, compared against the bytes the file holds",
            ),
            (
                r#"pe.sections[0].name contains "\xff""#,
                "a byte, not a code point",
            ),
            (
                r#"pe.sections[0].name endswith "\x90""#,
                "and at the end, where the NUL padding begins",
            ),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} ({why})"
            );
        }

        // And the other direction. The replacement character is written as the
        // three bytes UTF-8 gives it, because that is exactly what a lossy
        // conversion of `\xff` produces — so this is the literal a rule would
        // effectively have been comparing after one.
        for condition in [
            r#"pe.sections[0].name == ".\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd""#,
            r#"pe.sections[0].name == ".\xff\xfe\x90\x00""#,
            r#"pe.sections[0].name contains "\xef\xbf\xbd""#,
        ] {
            assert!(
                !run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} must not match"
            );
        }
    }

    #[test]
    fn section_members_are_indexed_and_undefined_past_the_end() {
        let pe = av_pe::testing::minimal_pe32();
        for (condition, why) in [
            (r#"pe.sections[0].name == ".text""#, "the first entry"),
            (r#"pe.sections[1].name == ".data""#, "the second entry"),
            (
                &format!("pe.sections[0].virtual_address == {TEXT_RVA}"),
                "the RVA, not the offset",
            ),
            (
                &format!("pe.sections[0].raw_data_offset == {TEXT_RAW}"),
                "the file offset",
            ),
            (
                "pe.sections[0].virtual_size == 0x800",
                "as the fixture writes it",
            ),
            (
                "pe.sections[0].raw_data_size == 0x400",
                "as the fixture writes it",
            ),
            (
                "pe.sections[0].characteristics == 0x60000020",
                "CODE | EXECUTE | READ",
            ),
            (
                "pe.sections[1].characteristics == 0xC0000040",
                "INIT_DATA | READ | WRITE",
            ),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} ({why})"
            );
        }

        // Past the end is `Undefined`, and every comparison against `Undefined`
        // is false — including against `""`. Comparing with `""` is therefore
        // the discriminating test: an implementation returning an empty string
        // for a missing section would make this true.
        assert!(!run_pe(
            r#"rule r { condition: pe.sections[2].name == "" }"#,
            &pe
        ));
        assert!(!run_pe(
            r#"rule r { condition: pe.sections[9].name == ".text" }"#,
            &pe
        ));
        assert!(!run_pe(
            "rule r { condition: pe.sections[0xFFFFFFFF].name == \".text\" }",
            &pe
        ));
        // A negative index is not a wrapped-to-the-end index either.
        assert!(!run_pe(
            r#"rule r { condition: pe.sections[-1].name == ".data" }"#,
            &pe
        ));
        // Nor is an index that is not a number at all.
        assert!(!run_pe(
            r#"rule r { condition: pe.sections["0"].name == ".text" }"#,
            &pe
        ));
    }

    #[test]
    fn data_directories_stop_at_the_count_in_the_header() {
        let pe = av_pe::testing::minimal_pe32();
        assert!(run_pe(
            &format!(
                "rule r {{ condition: pe.data_directories[0].virtual_address == {DATA_RVA} }}"
            ),
            &pe
        ));
        assert!(run_pe(
            "rule r { condition: pe.data_directories[0].size == 0x100 }",
            &pe
        ));
        // The fixture declares sixteen directories but only writes the first, so
        // directory 15 is present-and-zero while 16 is past the declared count.
        assert!(run_pe(
            "rule r { condition: pe.data_directories[15].size == 0 }",
            &pe
        ));
        assert!(!run_pe(
            "rule r { condition: pe.data_directories[16].size == 0 }",
            &pe
        ));
    }

    #[test]
    fn section_index_accepts_either_a_name_or_an_offset() {
        let pe = av_pe::testing::minimal_pe32();
        for (condition, why) in [
            (r#"pe.section_index(".text") == 0"#, "by name"),
            (r#"pe.section_index(".data") == 1"#, "by name"),
            (
                &format!("pe.section_index({DATA_RAW}) == 1"),
                "by a file offset inside the section",
            ),
            (
                &format!("pe.section_index({DATA_RAW} + 0x100) == 1"),
                "an offset later in the section is still in it",
            ),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} ({why})"
            );
        }

        // A name no section has, and an offset no section covers. The offset
        // case is deliberate: `pe.entry_point` is a file offset and callers
        // reach for `section_index(pe.entry_point)` to identify the entry
        // section, so an offset that maps nowhere has to be undefined rather
        // than index 0.
        assert!(!run_pe(
            r#"rule r { condition: pe.section_index(".nope") == 0 }"#,
            &pe
        ));
        assert!(!run_pe(
            "rule r { condition: pe.section_index(0x10) == 0 }",
            &pe
        ));
    }

    #[test]
    fn the_version_pairs_are_structs_of_two_members_and_not_packed_integers() {
        // The fixture has major linker version 14 and minor 0. Packed, that is
        // 0x0E00 — so a test asserting only `major == 14` cannot tell the two
        // implementations apart. The pair of assertions below can: the packed
        // reading would answer `major` with 0x0E00 and `minor` with nothing.
        let pe = av_pe::testing::minimal_pe32();
        assert!(run_pe(
            "rule r { condition: pe.linker_version.major == 14 }",
            &pe
        ));
        assert!(run_pe(
            "rule r { condition: pe.linker_version.minor == 0 }",
            &pe
        ));
        assert!(!run_pe(
            "rule r { condition: pe.linker_version.major == 0x0E00 }",
            &pe
        ));

        // The bare name is a type error, not a packed integer. It has to fail to
        // compile: a rule that reads it would otherwise be silently answered by
        // whichever half happened to be at that opcode.
        let file = parse_file("rule r { condition: pe.linker_version == 0x0E00 }").unwrap();
        let rule = &file.rules[0];
        let table = StringTable::from_defs(&rule.strings);
        assert!(
            compile_condition(&rule.condition, &table, rule.span).is_err(),
            "a struct with no `.major` or `.minor` must be refused"
        );

        for (condition, why) in [
            ("pe.os_version.major == 0", "the fixture leaves it zero"),
            ("pe.os_version.minor == 0", "the fixture leaves it zero"),
            ("pe.image_version.major == 0", "the fixture leaves it zero"),
            (
                "pe.subsystem_version.major == 0",
                "the fixture leaves it zero",
            ),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} ({why})"
            );
        }
    }

    #[test]
    fn pe_constants_are_available_as_values() {
        let pe = av_pe::testing::minimal_pe32();
        // `pe.characteristics & pe.DLL` is the idiom these exist for: the
        // fixture sets 0x0102, which has neither the DLL bit nor EXECUTABLE
        // clear.
        for (condition, why) in [
            ("pe.DLL == 0x2000", "IMAGE_FILE_DLL"),
            (
                "pe.EXECUTABLE_IMAGE == 0x0002",
                "and the bit the fixture sets",
            ),
            (
                "pe.characteristics & pe.DLL == 0",
                "a fixture .exe is not a DLL",
            ),
            (
                "pe.characteristics & pe.EXECUTABLE_IMAGE != 0",
                "but it is executable",
            ),
            ("pe.machine == pe.MACHINE_I386", "the fixture's machine"),
            (
                "pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI",
                "the fixture's subsystem",
            ),
            (
                "pe.IMAGE_DIRECTORY_ENTRY_SECURITY == 4",
                "the security directory's index",
            ),
            (
                "pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR == 14",
                "the CLR directory's",
            ),
            (
                "pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC == 0x10b",
                "which is `opthdr_magic`",
            ),
            (
                "pe.SECTION_MEM_EXECUTE == 0x20000000",
                "a section characteristic",
            ),
            (
                "pe.sections[0].characteristics & pe.SECTION_MEM_EXECUTE != 0",
                "and the fixture's `.text` has it",
            ),
            (
                "pe.sections[0].characteristics & pe.SECTION_CNT_CODE != 0",
                "as well as the code bit",
            ),
            ("pe.RESOURCE_TYPE_MANIFEST == 24", "a resource type"),
            (
                "pe.IMAGE_DEBUG_TYPE_CODEVIEW == 2",
                "a debug directory type",
            ),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} ({why})"
            );
        }

        // A name that is neither a member nor a constant is still refused, and
        // the refusal is what keeps a typo from reading as a member.
        assert!(compile_fails(
            "rule r { condition: pe.NOT_A_CONSTANT == 1 }"
        ));
    }

    #[test]
    fn the_parenthesised_and_bare_spellings_of_the_boolean_members_agree() {
        // YARA declares these as functions; rule sets in the wild write them
        // both ways. Both must work and must not disagree.
        let pe32 = av_pe::testing::minimal_pe32();
        for (bare, called) in [
            ("pe.is_dll", "pe.is_dll()"),
            ("pe.is_32bit", "pe.is_32bit()"),
            ("pe.is_64bit", "pe.is_64bit()"),
        ] {
            for value in ["0", "1"] {
                let a = run_pe(&format!("rule r {{ condition: {bare} == {value} }}"), &pe32);
                let b = run_pe(
                    &format!("rule r {{ condition: {called} == {value} }}"),
                    &pe32,
                );
                assert_eq!(a, b, "{bare} and {called} disagree about `== {value}`");
            }
        }
        assert!(run_pe("rule r { condition: pe.is_32bit() == 1 }", &pe32));
        assert!(run_pe("rule r { condition: pe.is_64bit() == 0 }", &pe32));

        // And the PE32+ fixture, where the answers invert.
        let pe64 = av_pe::testing::minimal_pe64();
        assert!(run_pe("rule r { condition: pe.is_64bit() == 1 }", &pe64));
        assert!(run_pe("rule r { condition: pe.is_32bit() == 0 }", &pe64));

        // They are functions of no arguments, so one is an error rather than
        // being ignored.
        assert!(compile_fails("rule r { condition: pe.is_dll(1) == 1 }"));
    }

    #[test]
    fn overlay_members_are_both_zero_when_there_is_no_overlay() {
        let mut data = av_pe::testing::minimal_pe32();
        assert!(run_pe(
            "rule r { condition: pe.overlay.offset == 0 }",
            &data
        ));
        assert!(run_pe("rule r { condition: pe.overlay.size == 0 }", &data));

        // `.data` ends at 0x800; anything past that is an overlay.
        data.resize(0x900, 0xAA);
        assert!(run_pe(
            "rule r { condition: pe.overlay.offset == 0x800 }",
            &data
        ));
        assert!(run_pe(
            "rule r { condition: pe.overlay.size == 0x100 }",
            &data
        ));
    }

    #[test]
    fn the_section_members_a_packer_leaves_behind_are_readable() {
        // The fixture leaves all four at zero, so the test is that they are
        // readable at all and that the two "line numbers" ones map onto the
        // struct's single-word field names.
        let pe = av_pe::testing::minimal_pe32();
        for member in [
            "pointer_to_relocations",
            "number_of_relocations",
            "pointer_to_line_numbers",
            "number_of_line_numbers",
        ] {
            assert!(
                run_pe(
                    &format!("rule r {{ condition: pe.sections[0].{member} == 0 }}"),
                    &pe
                ),
                "pe.sections[0].{member}"
            );
        }
        assert!(!run_pe(
            "rule r { condition: pe.sections[9].number_of_relocations == 0 }",
            &pe
        ));
    }

    #[test]
    fn a_pe32_plus_header_is_read_with_the_wider_layout() {
        // The two layouts put the same fields at different offsets. A reader
        // using the 32-bit offsets on this image would report an image base of
        // zero and one section of garbage, so the image base below is the test:
        // nothing in the fixture's `0x140000000` appears at the 32-bit offset.
        let pe = av_pe::testing::minimal_pe64();
        for (condition, why) in [
            ("pe.is_64bit == 1", "PE32+"),
            ("pe.is_32bit == 0", "and not PE32"),
            ("pe.is_pe == 1", "still a PE"),
            ("pe.image_base == 0x140000000", "the 64-bit default"),
            ("pe.number_of_sections == 1", "the fixture has one"),
            ("pe.machine == 0x14c", "the machine field is shared"),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} ({why})"
            );
        }
        // The RVA mapping is layout-independent, so the entry point converts the
        // same way in both.
        assert!(run_pe(
            &format!("rule r {{ condition: pe.entry_point == {TEXT_RAW} }}"),
            &pe
        ));
    }

    #[test]
    fn a_file_that_is_not_a_pe_answers_only_is_pe() {
        // `pe.is_pe` is the one member defined for every file: it is what a rule
        // uses to ask whether the rest is worth asking about. Everything else
        // must be `Undefined` rather than a zero, or a rule reading a field of a
        // non-PE would quietly match every text file the scanner walks past.
        let file = parse_file(
            r#"rule r {
                strings: $a = "x"
                condition: $a and pe.number_of_sections == 0
            }"#,
        )
        .unwrap();
        let rule = &file.rules[0];
        let table = StringTable::from_defs(&rule.strings);
        let program = compile_condition(&rule.condition, &table, rule.span).unwrap();

        let mut set = MatchSet::with_capacity(1);
        // A match is supplied so that the only thing that can make this false is
        // the `pe` half of the condition.
        set.push(0, Match::new(0, 1));
        set.sort();
        let mut vm = Vm::new();

        let data = b"MZ but not really a PE";
        assert!(!vm.run(&program, &set, &Input::new(data)).unwrap());
        // An entry point alone does not make the rest of the module defined:
        // `with_entry_point` is for the loader-style rule that only needs
        // `entrypoint`, and it deliberately does not imply a parse.
        assert!(!vm
            .run(&program, &set, &Input::with_entry_point(data, Some(0)))
            .unwrap());

        // The same program with `is_pe` in place of the field is what the rule
        // set is meant to write, and it is false here for the same reason.
        let guard = parse_file(
            r#"rule r {
                strings: $a = "x"
                condition: $a and pe.is_pe == 1
            }"#,
        )
        .unwrap();
        let guard_rule = &guard.rules[0];
        let guard_table = StringTable::from_defs(&guard_rule.strings);
        let guard_program =
            compile_condition(&guard_rule.condition, &guard_table, guard_rule.span).unwrap();
        assert!(!vm.run(&guard_program, &set, &Input::new(data)).unwrap());

        let pe = av_pe::testing::minimal_pe32();
        let image = PeInput::parse(&pe).unwrap();
        assert!(vm
            .run(&guard_program, &set, &Input::with_pe(&pe, &image))
            .unwrap());
    }

    // -- the signature members ---------------------------------------------

    /// The serial the fixtures below are built with, as a rule would write it.
    const SERIAL: &str = "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8";
    /// The same serial as the bytes a certificate carries.
    const SERIAL_BYTES: &[u8] = &[
        0x0d, 0xbf, 0x15, 0x2d, 0xea, 0xf0, 0xb9, 0x81, 0xa8, 0xa9, 0x38, 0xd5, 0x3f, 0x76, 0x9d,
        0xb8,
    ];

    #[test]
    fn a_signed_file_reports_its_certificates_and_an_unsigned_one_reports_none() {
        let signed = av_signatures::testing::pe_with_one_signature(SERIAL_BYTES, "Atera Networks");
        let unsigned = av_pe::testing::minimal_pe32();
        for (condition, expected, why) in [
            (
                "pe.number_of_signatures == 1",
                true,
                "one record, one certificate",
            ),
            ("pe.number_of_signatures == 0", false, "and not zero"),
            (
                "pe.number_of_signatures > 0",
                true,
                "the guard a rule writes",
            ),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &signed) == expected,
                "{condition} ({why})"
            );
        }
        // The unsigned file is the ordinary case, so it must answer zero rather
        // than `Undefined`: a rule guarding on `> 0` has to work on both.
        assert!(run_pe(
            "rule r { condition: pe.number_of_signatures == 0 }",
            &unsigned
        ));
        assert!(!run_pe(
            "rule r { condition: pe.number_of_signatures > 0 }",
            &unsigned
        ));
    }

    #[test]
    fn the_serial_a_rule_literally_writes_is_the_one_that_comes_back() {
        // The single most-read member in the corpus: 1,886 rules. The comparison
        // is against a literal taken from a real rule file, so a change to the
        // separator, the case, or the treatment of the leading sign byte fails
        // here rather than in production.
        let signed = av_signatures::testing::pe_with_one_signature(SERIAL_BYTES, "Atera Networks");
        assert!(run_pe(
            &format!("rule r {{ condition: pe.signatures[0].serial == \"{SERIAL}\" }}"),
            &signed
        ));
        assert!(!run_pe(
            &format!(
                "rule r {{ condition: pe.signatures[0].serial == \"{}\" }}",
                &SERIAL[3..]
            ),
            &signed
        ));
    }

    #[test]
    fn the_subject_is_the_slash_form_and_the_issuer_is_readable_too() {
        let signed = av_signatures::testing::pe_with_one_signature(SERIAL_BYTES, "Atera Networks");
        assert!(run_pe(
            r#"rule r { condition: pe.signatures[0].subject == "/CN=Atera Networks" }"#,
            &signed
        ));
        assert!(run_pe(
            r#"rule r { condition: pe.signatures[0].subject contains "Atera" }"#,
            &signed
        ));
        // The issuer is rendered the same way, from the other name.
        assert!(run_pe(
            r#"rule r { condition: pe.signatures[0].issuer == "/O=Test CA" }"#,
            &signed
        ));
    }

    #[test]
    fn the_validity_dates_come_back_as_unix_seconds() {
        let signed = av_signatures::testing::pe_with_one_signature(SERIAL_BYTES, "Atera Networks");
        // 110616000000Z is 2011-06-16 and 140615000000Z is 2014-06-15. The
        // literal in the corpus is written as a number, so the member has to be
        // one, not a date string.
        assert!(run_pe(
            "rule r { condition: pe.signatures[0].not_before == 1308182400 }",
            &signed
        ));
        assert!(run_pe(
            "rule r { condition: pe.signatures[0].not_after == 1402790400 }",
            &signed
        ));
        assert!(run_pe(
            "rule r { condition: pe.signatures[0].not_before < pe.signatures[0].not_after }",
            &signed
        ));
    }

    // -- references to other rules -------------------------------------------

    /// A corpus of three rules where one is written in terms of another.
    ///
    /// `GATE` is the shared precondition the extended corpus states once and
    /// refers to from thirty places; `USER` reads it positively and `NEGATED`
    /// negatively, because those two are the cases that fail in opposite
    /// directions when a reference is resolved wrongly.
    const GATE_AND_USER: &str = r#"
        private rule GATE { condition: uint16(0) == 0x5a4d }
        rule USER {
            strings: $a = "x"
            condition: GATE and $a
        }
        rule NEGATED { condition: not GATE }
    "#;

    /// Run the rule at `index` of a corpus, with the results of earlier rules
    /// and the strings it should see as matched.
    ///
    /// Compiling the set is what makes the reference resolve at all, and the
    /// result slots are false except where the caller says otherwise — which is
    /// what a scan looks like part of the way through. Matching is supplied
    /// rather than performed because these rules are about a reference, not
    /// about searching: the caller has to be able to say that the gate held and
    /// the string did not, which is the case a reference and a conjunct are told
    /// apart by.
    fn run_corpus(
        source: &str,
        index: usize,
        data: &[u8],
        earlier: &[(usize, bool)],
        matched_slots: &[u32],
    ) -> bool {
        let file = parse_file(source).expect("test source must parse");
        let corpus = crate::compiler::compile_corpus(&file.rules);
        assert_eq!(
            corpus.refused().count(),
            0,
            "{:?}",
            corpus.refused().collect::<Vec<_>>()
        );
        let mut vm = Vm::new();
        vm.begin_scan(file.rules.len());
        for (at, matched) in earlier {
            vm.record(*at as u32, *matched);
        }
        let program = corpus.rules()[index].as_ref().expect("compiled");
        let mut set = MatchSet::with_capacity(program.string_count as usize);
        for slot in matched_slots {
            set.push(*slot, Match::new(0, 1));
        }
        set.sort();
        vm.run(program, &set, &Input::new(data))
            .expect("a compiled program must run")
    }

    #[test]
    fn a_rule_reference_reads_the_result_the_caller_supplied() {
        // One rule, one condition, two different answers about the rule it
        // names. Nothing about `USER`'s own condition changed, so the verdict
        // can only have come through the reference.
        assert!(run_corpus(GATE_AND_USER, 1, b"MZ", &[(0, true)], &[0]));
        assert!(!run_corpus(GATE_AND_USER, 1, b"MZ", &[(0, false)], &[0]));
        // The reference is a conjunct and not the whole condition: with the
        // gate satisfied and `$a` absent, `USER` is still false.
        assert!(!run_corpus(GATE_AND_USER, 1, b"MZ", &[(0, true)], &[]));
        // And the gate's own value is not read from the file: `b"MZ"` really
        // does start with `MZ`, so a `USER` that computed `GATE` itself could
        // not be made false here.
        assert!(run_corpus(GATE_AND_USER, 0, b"MZ", &[], &[]));
    }

    #[test]
    fn a_negated_reference_is_the_case_a_missing_result_would_invert() {
        assert!(!run_corpus(GATE_AND_USER, 2, b"MZ", &[(0, true)], &[]));
        assert!(run_corpus(GATE_AND_USER, 2, b"MZ", &[(0, false)], &[]));

        // With no result slots at all — a VM that was never told how many rules
        // the scan has — the answer must be a fault rather than a `false`,
        // because `false` here is `true` for every file on the disk.
        let file = parse_file(GATE_AND_USER).unwrap();
        let corpus = crate::compiler::compile_corpus(&file.rules);
        let program = corpus.rules()[2].as_ref().unwrap();
        let error = Vm::new()
            .run(program, &MatchSet::with_capacity(0), &Input::new(b"MZ"))
            .expect_err("a reference with no result slot must be a fault");
        assert!(
            matches!(error, VmError::MissingRuleResult { rule: 0, .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_corpus_runs_in_the_order_the_compiler_gave() {
        // The whole pipeline: compile the set, then run the rules in the order
        // given, filling the result array as a scan does. `USER` must see
        // `GATE`'s real verdict — true for an `MZ` buffer, false otherwise —
        // and `NEGATED` must be its complement.
        let file = parse_file(GATE_AND_USER).unwrap();
        let corpus = crate::compiler::compile_corpus(&file.rules);
        // The private rule first, because the two that read it come after it.
        assert_eq!(corpus.order(), [0, 1, 2]);

        for data in [b"MZ\x00\x00".as_slice(), b"not a pe at all".as_slice()] {
            let mut results = vec![false; file.rules.len()];
            let mut vm = Vm::new();
            vm.begin_scan(results.len());
            for &index in corpus.order() {
                let program = corpus.rules()[index as usize].as_ref().unwrap();
                let set = MatchSet::with_capacity(program.string_count as usize);
                let matched = vm
                    .run(program, &set, &Input::new(data))
                    .expect("a compiled program must run");
                results[index as usize] = matched;
                vm.record(index, matched);
            }
            assert_eq!(results[0], data.starts_with(b"MZ"), "{data:?}");
            // `USER` also needs its string, which nothing matched here.
            assert!(!results[1], "{data:?}");
            // The reference carried a real value: `NEGATED` inverts `GATE`.
            assert_ne!(results[2], results[0], "{data:?}");
        }
    }

    // -- the resource array --------------------------------------------------

    /// A PE carrying three resources of one type, each under its own language.
    ///
    /// Three of the *same* type so a counted loop has something to count: `for
    /// 3 resource in pe.resources` has to reach all three, and the body has to
    /// be able to tell them apart — by name, by language, and by the length of
    /// the data each one points at, which is three different members of the same
    /// element.
    fn pe_with_three_resources() -> Vec<u8> {
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_resources(
            &mut image,
            &[
                av_pe::testing::ResourceSpec::new(10u32, "RC1", &[1033u32], b"one"),
                av_pe::testing::ResourceSpec::new(10u32, "RC2", &[1034u32], b"two2"),
                av_pe::testing::ResourceSpec::new(10u32, "RC3", &[1035u32], b"three"),
            ],
        );
        image
    }

    #[test]
    fn a_counted_resource_loop_counts_the_resources() {
        let pe = pe_with_three_resources();
        // The corpus's own spelling: `for 12 resource in pe.resources`, guarded
        // by `pe.number_of_resources >= 13`. The count is what the loop is
        // asked for and the guard is the same number read directly, so the two
        // have to agree about how many there are.
        assert!(run_pe(
            "rule r { condition: pe.number_of_resources == 3 and \
             for 3 resource in pe.resources : ( resource.type == 10 ) }",
            &pe
        ));
        assert!(!run_pe(
            "rule r { condition: for 4 resource in pe.resources : ( resource.type == 10 ) }",
            &pe
        ));
        assert!(run_pe(
            "rule r { condition: for 2 resource in pe.resources : ( resource.type == 10 ) }",
            &pe
        ));
    }

    #[test]
    fn a_resource_loop_reaches_every_resource_in_turn() {
        let pe = pe_with_three_resources();
        // All three languages, which is only true if the loop visited each
        // resource rather than any one of them three times.
        assert!(run_pe(
            "rule r { condition: for all resource in pe.resources : \
             ( resource.language >= 1033 and resource.language <= 1035 ) }",
            &pe
        ));
        // Each of the three, reached by a member only that one has.
        assert!(run_pe(
            r#"rule r { condition: for any resource in pe.resources : ( resource.name_string == "R\x00C\x002\x00" ) }"#,
            &pe
        ));
        assert!(run_pe(
            "rule r { condition: for any resource in pe.resources : ( resource.length == 4 ) }",
            &pe
        ));
        // Only one of the three is four bytes, so `all` must not hold — which
        // is the difference between walking the array and asking about one
        // element of it.
        assert!(!run_pe(
            "rule r { condition: for all resource in pe.resources : ( resource.length == 4 ) }",
            &pe
        ));
    }

    #[test]
    fn a_resource_loop_over_nothing_is_vacuously_true_for_all() {
        // The unsigned fixture has no resource directory at all, so the array is
        // empty and the loop has to answer for that without entering the body.
        // A bound of `length - 1` would be `-1` here, and an index of `-1` names
        // no element: the `any` case would read a resource that is not there,
        // and the counted case would count a body that never ran.
        let pe = av_pe::testing::minimal_pe32();
        assert!(run_pe(
            "rule r { condition: for all resource in pe.resources : ( resource.type == 10 ) }",
            &pe
        ));
        assert!(run_pe(
            "rule r { condition: for none resource in pe.resources : ( resource.type == 10 ) }",
            &pe
        ));
        assert!(!run_pe(
            "rule r { condition: for any resource in pe.resources : ( resource.type == 10 ) }",
            &pe
        ));
        assert!(!run_pe(
            "rule r { condition: for 1 resource in pe.resources : ( resource.type == 10 ) }",
            &pe
        ));
        assert!(run_pe(
            "rule r { condition: pe.number_of_resources == 0 }",
            &pe
        ));
    }

    #[test]
    fn a_resources_offset_is_a_file_offset_the_readers_can_use() {
        // The corpus's own test of this: `uint16(pe.resources[i].offset) ==
        // 0x5A4D`. A reader reads the file at the offset it is given, so if this
        // were an RVA the read would land on mapped bytes and answer something
        // else entirely. The first resource's data is `one`.
        let pe = pe_with_three_resources();
        assert!(run_pe(
            "rule r { condition: for any resource in pe.resources : \
             ( uint16(resource.offset) == 0x6e6f ) }",
            &pe
        ));
        // And the range form over the same array, written the way the corpus
        // writes it by hand, reaches the same bytes.
        assert!(run_pe(
            "rule r { condition: for any i in (0..pe.number_of_resources - 1) : \
             ( uint16(pe.resources[i].offset) == 0x6e6f ) }",
            &pe
        ));
    }

    #[test]
    fn a_section_loop_reads_the_section_the_variable_is_on() {
        // The other array, and the other spelling in the corpus: `for any s in
        // pe.sections : ( s.name == ".profile" )`. The fixture's one section is
        // `.text`, so the loop must find it and must not find anything else.
        let pe = av_pe::testing::minimal_pe32();
        assert!(run_pe(
            r#"rule r { condition: for any s in pe.sections : ( s.name == ".text" ) }"#,
            &pe
        ));
        assert!(!run_pe(
            r#"rule r { condition: for any s in pe.sections : ( s.name == ".profile" ) }"#,
            &pe
        ));
        // The equivalent range loop, which is what the array form compiles to.
        assert!(run_pe(
            "rule r { condition: for any i in (0..pe.number_of_sections - 1) : \
             ( pe.sections[i].name == \".text\" ) }",
            &pe
        ));
    }

    #[test]
    fn the_version_member_reports_the_encoded_number() {
        let signed = av_signatures::testing::pe_with_one_signature(SERIAL_BYTES, "Atera Networks");
        // v3 is encoded as 2; the fixture writes `[0] INTEGER 2`.
        assert!(run_pe(
            "rule r { condition: pe.signatures[0].version == 2 }",
            &signed
        ));
    }

    #[test]
    fn the_thumbprint_has_the_colon_separated_shape_the_literals_use() {
        let signed = av_signatures::testing::pe_with_one_signature(SERIAL_BYTES, "Atera Networks");
        // The value the crate computes, so this pins the *format* rather than
        // restating it: 20 bytes, lowercase, `:` between.
        let der = av_signatures::testing::certificate(
            SERIAL_BYTES,
            "Atera Networks",
            "110616000000Z",
            "140615000000Z",
        );
        let expected = av_signatures::Certificate::parse(&der)
            .unwrap()
            .thumbprint();
        assert_eq!(expected.len(), 59, "twenty bytes and nineteen colons");
        assert!(run_pe(
            &format!("rule r {{ condition: pe.signatures[0].thumbprint == \"{expected}\" }}"),
            &signed
        ));
        // The same twenty bytes written without the separators is the form one
        // literal in the corpus uses, and it is deliberately not the one
        // implemented: a rule written that way matches nothing, which is the
        // same outcome it had before this member existed.
        let bare = expected.replace(':', "");
        assert_eq!(bare.len(), 40);
        assert!(!run_pe(
            &format!("rule r {{ condition: pe.signatures[0].thumbprint == \"{bare}\" }}"),
            &signed
        ));
    }

    #[test]
    fn an_index_past_the_end_is_undefined_rather_than_an_empty_string() {
        // This is what the corpus's loop bound depends on. `for any i in
        // (0 .. pe.number_of_signatures)` runs one iteration past the last
        // certificate — the range is inclusive at both ends — and that
        // iteration has to be `Undefined` for the loop to answer what its
        // author meant. Were it an empty string, `serial == ""` would be a
        // match, and were it a panic the scanner would die on every signed file.
        let signed = av_signatures::testing::pe_with_one_signature(SERIAL_BYTES, "Atera Networks");
        for member in ["serial", "subject", "issuer", "thumbprint"] {
            assert!(
                !run_pe(
                    &format!(
                        "rule r {{ condition: pe.signatures[1].{member} == \"\" or \
                         pe.signatures[1].{member} contains \"\" }}"
                    ),
                    &signed
                ),
                "an out-of-range {member} must compare equal to nothing"
            );
        }
        // And the comparison a real rule writes on it is false, not true.
        assert!(!run_pe(
            &format!("rule r {{ condition: pe.signatures[1].serial == \"{SERIAL}\" }}"),
            &signed
        ));
        assert!(!run_pe(
            "rule r { condition: pe.signatures[1].not_before == 0 }",
            &signed
        ));
    }

    #[test]
    fn the_loop_shape_the_corpus_writes_selects_the_file_it_was_written_for() {
        // The rule from the crate documentation, reduced to its structure: a
        // guard, an inclusive range that overruns by one, and a comparison
        // inside. This is the shape of 1,601 rules in the corpus, so it is worth
        // one test that runs it as written.
        let signed = av_signatures::testing::pe_with_one_signature(SERIAL_BYTES, "Atera Networks");
        let unsigned = av_pe::testing::minimal_pe32();
        let rule = |serial: &str| {
            format!(
                r#"rule r {{
                    condition:
                        uint16(0) == 0x5a4d and
                        for any i in ( 0 .. pe.number_of_signatures ) : (
                            pe.signatures[i].serial == "{serial}"
                        )
                }}"#
            )
        };
        assert!(run_pe(&rule(SERIAL), &signed));
        assert!(!run_pe(&rule("00:11:22"), &signed));
        // On an unsigned file the range is `(0 .. 0)`, which is one iteration
        // reading index 0 of an empty list — `Undefined`, so false.
        assert!(!run_pe(&rule(SERIAL), &unsigned));
    }

    #[test]
    fn a_certificate_chain_is_indexed_in_the_order_the_blob_lists_it() {
        let first =
            av_signatures::testing::certificate(&[0x01], "First", "110616000000Z", "140615000000Z");
        let second = av_signatures::testing::certificate(
            &[0x02],
            "Second",
            "110616000000Z",
            "140615000000Z",
        );
        // A leaf and its issuer: the leaf comes first, which is the order the
        // corpus's `signatures[0]` assumes.
        let signed = av_signatures::testing::signed_pe(&[first, second]);
        assert!(run_pe(
            r#"rule r {
                condition:
                    pe.number_of_signatures == 2 and
                    pe.signatures[0].subject == "/CN=First" and
                    pe.signatures[1].subject == "/CN=Second"
            }"#,
            &signed
        ));
    }

    #[test]
    fn a_signature_member_read_from_a_file_with_no_pe_is_undefined() {
        // `pe.number_of_signatures` is defined as zero only when there *is* a
        // PE. On a text file the whole module is `Undefined`, so the guard a
        // rule writes does not accidentally fire on every file the scanner
        // walks past. `run` rather than `run_pe`, because this is the case
        // where the file does not parse as one.
        let data = b"MZ but not really a PE";
        assert!(!run(
            "rule r { condition: pe.number_of_signatures == 0 }",
            data
        ));
        assert!(!run(
            r#"rule r { condition: pe.signatures[0].serial == "" }"#,
            data
        ));
    }

    #[test]
    fn a_signature_record_that_is_not_pkcs7_yields_no_certificates_rather_than_failing() {
        // A file can carry a `WIN_CERTIFICATE` of another type — an X.509
        // certificate on its own, a reserved type — and that is not a malformed
        // file. It is a file with nothing this module can read, so the count is
        // zero and every member is `Undefined`.
        let mut pe = av_pe::testing::minimal_pe32();
        let mut record = Vec::new();
        record.extend_from_slice(&10u32.to_le_bytes());
        record.extend_from_slice(&0x0200u16.to_le_bytes());
        // WIN_CERT_TYPE_X509, which is not a PKCS#7 blob.
        record.extend_from_slice(&0x0001u16.to_le_bytes());
        record.extend_from_slice(&[0x30, 0x00]);
        while record.len() % 8 != 0 {
            record.push(0);
        }
        av_pe::testing::append_security_directory(&mut pe, &record);

        assert!(run_pe(
            "rule r { condition: pe.number_of_signatures == 0 }",
            &pe
        ));
        assert!(!run_pe(
            r#"rule r { condition: pe.signatures[0].serial == "" }"#,
            &pe
        ));
    }

    #[test]
    fn the_number_of_signatures_counts_certificates_not_records() {
        // The member is named for the records but answers with certificates,
        // because it is the loop bound for `pe.signatures[i]`. A file with one
        // record carrying a two-certificate chain has two readable signatures,
        // and a bound of one would hide the second.
        let chain = vec![
            av_signatures::testing::certificate(&[0x01], "Leaf", "110616000000Z", "140615000000Z"),
            av_signatures::testing::certificate(&[0x02], "Root", "110616000000Z", "140615000000Z"),
        ];
        let signed = av_signatures::testing::signed_pe(&chain);
        assert!(run_pe(
            "rule r { condition: pe.number_of_signatures == 2 }",
            &signed
        ));
        assert!(run_pe(
            r#"rule r { condition: pe.signatures[1].subject == "/CN=Root" }"#,
            &signed
        ));
    }

    // -- the import and export tables ---------------------------------------

    #[test]
    fn the_import_count_is_the_libraries_and_the_symbol_members_read_them() {
        // Corpus line 209349 lists exactly seventeen library names and bounds
        // `pe.number_of_imports` between them, which is why the member counts
        // descriptors rather than symbols.
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_imports(
            &mut image,
            &[
                ("ADVAPI32.dll", &["RegOpenKeyExW", "RegSetValueExW"]),
                ("WS2_32.dll", &["socket", "connect"]),
            ],
        );

        for (condition, expected) in [
            ("pe.number_of_imports == 2", true),
            ("pe.number_of_imports == 4", false),
            (
                "pe.number_of_imports > 16 and pe.number_of_imports < 19",
                false,
            ),
            (r#"pe.imports("ADVAPI32.dll")"#, true),
            (r#"pe.imports("WS2_32.dll")"#, true),
            (r#"pe.imports("KERNEL32.dll")"#, false),
            // The library is compared the way the loader compares it: as a
            // filename, so the case does not matter.
            (r#"pe.imports("advapi32.DLL")"#, true),
            (r#"pe.imports("ADVAPI32.dll", "RegOpenKeyExW")"#, true),
            (r#"pe.imports("ADVAPI32.dll", "socket")"#, false),
            // The symbol is compared the way the loader compares it: exactly.
            (r#"pe.imports("ADVAPI32.dll", "regopenkeyexw")"#, false),
            (r#"pe.imports("missing.dll", "socket")"#, false),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &image) == expected,
                "{condition}"
            );
        }
    }

    #[test]
    fn an_ordinal_only_import_is_counted_but_has_no_name_to_find() {
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_ordinal_import(&mut image, "WS2_32.dll", &[3, 4]);
        for (condition, expected) in [
            ("pe.number_of_imports == 1", true),
            (r#"pe.imports("WS2_32.dll")"#, true),
            // The symbol half is a name lookup, and an ordinal has no name.
            (r#"pe.imports("WS2_32.dll", "3")"#, false),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &image) == expected,
                "{condition}"
            );
        }
    }

    #[test]
    fn the_imphash_comes_back_in_the_form_the_literals_are_written_in() {
        // The one member whose value cannot be checked by construction: the
        // expected digests here were computed with `md5sum` over the exact
        // normalized string the algorithm defines, so this compares against an
        // outside tool rather than against the code that produced the value.
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_imports(
            &mut image,
            &[
                ("KERNEL32.dll", &["CreateFileW", "VirtualAlloc"]),
                ("USER32.dll", &["MessageBoxA"]),
            ],
        );
        assert!(run_pe(
            r#"rule r { condition: pe.imphash() == "73f978df3b6a9b2bb9d2866e501af07a" }"#,
            &image
        ));
        assert!(!run_pe(
            r#"rule r { condition: pe.imphash() == "d41d8cd98f00b204e9800998ecf8427e" }"#,
            &image
        ));

        // A file with no imports hashes the empty string. That is the
        // algorithm's answer, so the rule is false rather than undefined — and
        // the member still has to be a string for the comparison to happen at
        // all, which is what the second half checks.
        let bare = av_pe::testing::minimal_pe32();
        assert!(run_pe(
            r#"rule r { condition: pe.imphash() == "d41d8cd98f00b204e9800998ecf8427e" }"#,
            &bare
        ));
        assert!(!run_pe(
            r#"rule r { condition: pe.imphash() == "73f978df3b6a9b2bb9d2866e501af07a" }"#,
            &bare
        ));
    }

    #[test]
    fn the_export_members_answer_the_address_table_and_the_names_separately() {
        // Corpus line 170585: one name exported, two addresses in the table.
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_exports(&mut image, &["Init"], 2);
        for (condition, expected) in [
            // The count is the address table, so it is two and not one.
            ("pe.number_of_exports == 2", true),
            ("pe.number_of_exports == 1", false),
            (r#"pe.exports("Init")"#, true),
            // Case-sensitive, like the loader.
            (r#"pe.exports("init")"#, false),
            (r#"pe.exports("DllMain")"#, false),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &image) == expected,
                "{condition}"
            );
        }
    }

    #[test]
    fn a_file_with_no_import_or_export_directory_answers_zero_rather_than_undefined() {
        // Most executables do neither, so the ordinary case must be a number and
        // an empty table rather than `Undefined`: a rule guarding on `> 0` has
        // to work on every file, not only the ones that have the table.
        let image = av_pe::testing::minimal_pe32();
        for (condition, expected) in [
            ("pe.number_of_imports == 0", true),
            ("pe.number_of_imports > 0", false),
            ("pe.number_of_exports == 0", true),
            ("pe.number_of_exports > 0", false),
            (r#"pe.imports("KERNEL32.dll")"#, false),
            (r#"pe.exports("Init")"#, false),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &image) == expected,
                "{condition}"
            );
        }
    }

    #[test]
    fn an_export_detail_is_an_entry_of_the_address_table_and_carries_its_own_name() {
        // Corpus line 219468: one name exported, two addresses in the table,
        // walked `0 .. pe.number_of_exports - 1`. The array is the address
        // table, so entry 1 is a real entry with no name rather than a missing
        // entry — and `Undefined` is how "no name" is spelled, which makes
        // `contains ""` false instead of true.
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_exports(&mut image, &["Init"], 2);
        for (condition, expected) in [
            (r#"pe.export_details[0].name == "Init""#, true),
            (r#"pe.export_details[1].name == "Init""#, false),
            (r#"pe.export_details[1].name != "Init""#, false),
            // The ordinal is the table's own base plus the index, not the
            // index: a reader that reported the index would be off by one and
            // every ordinal check in the corpus would be off with it.
            ("pe.export_details[0].ordinal == 1", true),
            ("pe.export_details[1].ordinal == 2", true),
            ("pe.export_details[0].ordinal == 0", false),
            // The offset is a file offset, which is what the corpus's
            // `contains "libvlc_"` loop is read next to.
            ("pe.export_details[0].offset == 0x200", true),
            ("pe.export_details[1].offset == 0x210", true),
            // Past the end of the table is `Undefined`, not a crash.
            ("pe.export_details[2].ordinal == 3", false),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &image) == expected,
                "{condition}"
            );
        }
    }

    #[test]
    fn a_forwarded_export_names_the_module_and_symbol_it_points_at() {
        // An address table entry whose RVA lands inside the export directory is
        // a forwarder, and the string it lands on is `Module.Symbol`. The
        // corpus's loop is `fn.forward_name contains "Dll"`, so the difference
        // between an absent forwarder and an empty one is the difference
        // between a rule that fires on forwarders and one that fires on every
        // entry in the table.
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_forwarded_exports(
            &mut image,
            &["Init"],
            2,
            &[(1, "NTDLL.RtlAllocateHeap")],
        );
        for (condition, expected) in [
            (
                r#"pe.export_details[1].forward_name == "NTDLL.RtlAllocateHeap""#,
                true,
            ),
            (
                r#"pe.export_details[1].forward_name contains "NTDLL""#,
                true,
            ),
            // The named entry is code, not a forwarder.
            (r#"pe.export_details[0].forward_name != """#, false),
            (r#"pe.export_details[0].forward_name contains "Dll""#, false),
            // And the name is still its own member on a forwarded entry.
            (r#"pe.export_details[0].name == "Init""#, true),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &image) == expected,
                "{condition}"
            );
        }
    }

    #[test]
    fn the_export_walk_the_corpus_writes_selects_the_entries_it_was_written_for() {
        // The shape at corpus line 219468, spelled in the language: every entry
        // in the address table whose name begins with the prefix. The bound of
        // the walk is `pe.number_of_exports`, so an entry with no name must
        // fail the `contains` rather than satisfy a `contains ""`.
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_exports(&mut image, &["libvlc_new", "libvlc_media"], 4);
        let some = r#"rule r { condition: for any i in (0 .. pe.number_of_exports - 1) : ( pe.export_details[i].name contains "libvlc_" ) }"#;
        assert!(run_pe(some, &image));

        let all = r#"rule r { condition: for all i in (0 .. pe.number_of_exports - 1) : ( pe.export_details[i].name contains "libvlc_" ) }"#;
        assert!(
            !run_pe(all, &image),
            "two of the four entries have no name at all"
        );

        // The `for ... in` spelling of the same walk, which is the one the
        // language adds over the corpus.
        let walk = r#"rule r { condition: for any fn in pe.export_details : ( fn.name contains "libvlc_media" ) }"#;
        assert!(run_pe(walk, &image));

        let empty = av_pe::testing::minimal_pe32();
        assert!(!run_pe(walk, &empty), "no export directory, no entries");
    }

    #[test]
    fn an_import_member_read_from_a_file_with_no_pe_is_undefined() {
        // `run` rather than `run_pe`, because this is the case where the file
        // does not parse as one. Every one of these must be `Undefined` and not
        // a zero, or a text file would satisfy `pe.number_of_imports == 0` and
        // every rule that forgot its `pe.is_pe` guard would fire on it.
        let data = b"MZ but not really a PE";
        for condition in [
            "pe.number_of_imports == 0",
            "pe.number_of_exports == 0",
            r#"pe.imports("KERNEL32.dll")"#,
            r#"pe.imports("KERNEL32.dll", "CreateFileW")"#,
            r#"pe.exports("Init")"#,
            r#"pe.imphash() == "" "#,
        ] {
            assert!(
                !run(&format!("rule r {{ condition: {condition} }}"), data),
                "{condition} on a non-PE"
            );
        }
    }

    // -- the hash and math modules -----------------------------------------

    #[test]
    fn a_hash_over_a_region_is_the_published_digest_of_that_region() {
        // The digests of `abc`, which is what `hash.md5(0, 3)` must be over a
        // buffer whose first three bytes are those. Comparing against the
        // published vectors rather than against another call to the same
        // function, because a hash that is self-consistently wrong is exactly
        // the failure mode a rule would never notice.
        assert!(run(
            r#"rule r { condition: hash.md5(0, 3) == "900150983cd24fb0d6963f7d28e17f72" }"#,
            b"abcdef"
        ));
        assert!(run(
            r#"rule r { condition: hash.sha1(0, 3) == "a9993e364706816aba3e25717850c26c9cd0d89d" }"#,
            b"abcdef"
        ));
        assert!(run(
            r#"rule r { condition: hash.sha256(0, 3) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }"#,
            b"abcdef"
        ));
    }

    #[test]
    fn a_hash_covers_the_region_and_not_the_whole_buffer() {
        // The offset and size are the whole question. A hash function that
        // ignored them would still satisfy the test above, because that region
        // starts at zero.
        assert!(!run(
            r#"rule r { condition: hash.md5(3, 3) == "900150983cd24fb0d6963f7d28e17f72" }"#,
            b"abcdef"
        ));
        assert!(run(
            r#"rule r { condition: hash.md5(3, 3) == "900150983cd24fb0d6963f7d28e17f72" }"#,
            b"defabc"
        ));
    }

    #[test]
    fn a_hash_of_a_string_hashes_the_string() {
        // The form the corpus uses on a decoded structure rather than on a
        // region of the file.
        assert!(run(
            r#"rule r { condition: hash.md5("abc") == "900150983cd24fb0d6963f7d28e17f72" }"#,
            b""
        ));
        // And not the file: the same call on a buffer that starts with `abc`
        // answers the same thing, which is the property that makes it a
        // function of its argument.
        assert!(run(
            r#"rule r { condition: hash.md5("abc") == "900150983cd24fb0d6963f7d28e17f72" }"#,
            b"abcdef"
        ));
    }

    #[test]
    fn a_hash_of_something_undefined_is_undefined_rather_than_the_hash_of_nothing() {
        // `hash.md5(pe.rich_signature.clear_data)` on a file with no rich
        // header. The digest of the empty string is a real, well-known value,
        // and a rule comparing against it would fire on every such file if the
        // undefined argument were treated as empty. It must not.
        assert!(!run(
            r#"rule r { condition: hash.md5(pe.imphash()) == "d41d8cd98f00b204e9800998ecf8427e" }"#,
            b"not a PE"
        ));
    }

    #[test]
    fn a_region_that_runs_past_the_end_is_hashed_short() {
        // `hash.md5(0, filesize)` on a four-byte file is the digest of four
        // bytes. A read past the buffer would be a crash on a memory-mapped
        // file whose last page ends at the mapping.
        assert!(run(
            r#"rule r { condition: hash.md5(0, filesize) == "900150983cd24fb0d6963f7d28e17f72" }"#,
            b"abc"
        ));
        assert!(run(
            r#"rule r { condition: hash.md5(0, 4096) == "900150983cd24fb0d6963f7d28e17f72" }"#,
            b"abc"
        ));
    }

    #[test]
    fn entropy_is_the_statistic_the_rules_were_written_against() {
        // The two ends and a middle. `math.entropy(0, filesize) > 7.5` is the
        // shape five corpus rules use to ask whether a body is compressed.
        let flat = vec![0u8; 1024];
        assert!(run(
            "rule r { condition: math.entropy(0, filesize) == 0.0 }",
            &flat
        ));
        assert!(!run(
            "rule r { condition: math.entropy(0, filesize) > 7.5 }",
            &flat
        ));

        let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(run(
            "rule r { condition: math.entropy(0, filesize) > 7.9 }",
            &all
        ));
    }

    #[test]
    fn the_region_statistics_take_an_offset_and_a_size_that_a_rule_computed() {
        // `math.mean(500, filesize - 500) > 80`: the corpus's shape, and the
        // one where a short file makes the size negative.
        let data: Vec<u8> = std::iter::repeat_n(0u8, 500)
            .chain(std::iter::repeat_n(0xf0u8, 500))
            .collect();
        assert!(run(
            "rule r { condition: math.mean(500, filesize - 500) > 200 }",
            &data
        ));
        assert!(run("rule r { condition: math.mean(0, 500) == 0.0 }", &data));

        // A file shorter than the header offset: the region does not exist, and
        // the answer is the one that makes every threshold false. Clamping the
        // negative size to zero would instead measure the whole file, which is
        // the header the rule was written to skip.
        let short = vec![0xf0u8; 100];
        assert!(!run(
            "rule r { condition: math.entropy(500, filesize - 500) > 0.5 }",
            &short
        ));
        assert!(run(
            "rule r { condition: math.entropy(500, filesize - 500) == 0.0 }",
            &short
        ));
    }

    #[test]
    fn the_deviation_is_the_absolute_one_from_the_mean_the_rule_supplies() {
        // The module's own worked example: over a region holding each byte
        // value equally often, the deviation from `math.MEAN_BYTES` is 64.0.
        // The standard deviation of the same region is 73.9, so a rule written
        // with a threshold between the two is the one this distinguishes.
        let even: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(run(
            "rule r { condition: math.deviation(0, filesize, math.MEAN_BYTES) == 64.0 }",
            &even
        ));
        assert!(!run(
            "rule r { condition: math.deviation(0, filesize, math.MEAN_BYTES) > 70.0 }",
            &even
        ));

        // A region of one value deviates from its own value by nothing, and
        // from the byte mean by the distance to it — the second is what makes
        // the mean an argument rather than a constant.
        let flat = vec![0u8; 512];
        assert!(run(
            "rule r { condition: math.deviation(0, filesize, 0.0) == 0.0 }",
            &flat
        ));
        assert!(run(
            "rule r { condition: math.deviation(0, filesize, math.MEAN_BYTES) == 127.5 }",
            &flat
        ));
        assert!(run(
            "rule r { condition: math.deviation(0, filesize, 255.0) == 255.0 }",
            &flat
        ));
    }

    #[test]
    fn the_deviation_has_a_form_that_takes_bytes() {
        // The corpus writes the region form. The string form is for a rule
        // holding bytes that were decoded out of a structure — a base64 body,
        // an encoded configuration blob — where there is no offset in the file
        // they came from. `89.0` is the mean of the base64 alphabet, which is
        // the mean the corpus's thresholds were calibrated against.
        assert!(run(
            r#"rule r { condition: math.deviation("abc", 89.0) == 9.0 }"#,
            b""
        ));
        // An empty string has no bytes to average, so the answer is zero and
        // not a division by zero. `NaN` would make both `> 0` and `<= 0` false,
        // and a rule negating one of them would fire on every file.
        assert!(run(
            r#"rule r { condition: math.deviation("", 0.0) == 0.0 }"#,
            b""
        ));
        assert!(run(
            r#"rule r { condition: math.deviation("", 0.0) < 1.0 }"#,
            b""
        ));
    }

    #[test]
    fn the_string_module_measures_and_converts_bytes() {
        // The length is bytes, and a NUL inside is a byte like any other — a
        // decoded string is not a C string.
        assert!(run(
            r#"rule r { condition: string.length("A\0BC") == 4 }"#,
            b""
        ));
        assert!(run(r#"rule r { condition: string.length("") == 0 }"#, b""));

        // The base is a choice, and the choice is the documented one: `0x` is
        // sixteen, a leading zero is eight, and no prefix means ten — which is
        // what makes `string.to_int` agree with the encoder that wrote the
        // bytes.
        assert!(run(
            r#"rule r { condition: string.to_int("11") == 11 }"#,
            b""
        ));
        assert!(run(
            r#"rule r { condition: string.to_int("0x11") == 17 }"#,
            b""
        ));
        assert!(run(
            r#"rule r { condition: string.to_int("011") == 9 }"#,
            b""
        ));
        assert!(run(
            r#"rule r { condition: string.to_int("-11") == -11 }"#,
            b""
        ));
        assert!(run(
            r#"rule r { condition: string.to_int("+11") == 11 }"#,
            b""
        ));
        assert!(run(
            r#"rule r { condition: string.to_int("11", 8) == 9 }"#,
            b""
        ));
        assert!(run(
            r#"rule r { condition: string.to_int("ff", 16) == 255 }"#,
            b""
        ));
    }

    #[test]
    fn a_string_that_is_not_a_number_has_no_integer_rather_than_zero() {
        // Zero is the one answer that must not be given: `string.to_int(x) == 0`
        // is how a rule asks whether a field was zero, and a decoder that read
        // garbage would answer yes and let the sample through.
        for source in [
            // A digit the base does not have.
            r#"rule r { condition: string.to_int("12", 2) == 0 }"#,
            // Trailing bytes past the digits.
            r#"rule r { condition: string.to_int("12x") == 0 }"#,
            // No digits at all.
            r#"rule r { condition: string.to_int("") == 0 }"#,
            r#"rule r { condition: string.to_int("x") == 0 }"#,
            // A sign with nothing after it.
            r#"rule r { condition: string.to_int("-") == 0 }"#,
            // A base outside the ones the syntax defines. One is not a base,
            // and neither is thirty-seven.
            r#"rule r { condition: string.to_int("1", 1) == 0 }"#,
            r#"rule r { condition: string.to_int("1", 37) == 0 }"#,
        ] {
            assert!(!run(source, b""), "{source}");
        }
    }

    #[test]
    fn the_matches_operator_runs_its_pattern_against_the_value() {
        // The pattern is in the program and the value is on the stack, so these
        // exercise the whole path: the compiler stores the spec, the
        // interpreter compiles it on first use, and the second call finds it in
        // the cache.
        for (condition, expected) in [
            (r#""abc" matches /b/"#, true),
            (r#""abc" matches /^b/"#, false),
            (r#""abc" matches /B/"#, false),
            (r#""abc" matches /B/i"#, true),
            (r#""abc" matches /a.c/"#, true),
            // `s` is the flag that lets `.` cross a newline, and it is a flag
            // rather than a default because a rule that means either one has to
            // be able to say which.
            (r#""a\nc" matches /a.c/"#, false),
            (r#""a\nc" matches /a.c/s"#, true),
            // Byte semantics: a pattern may name a byte that is not UTF-8, and
            // an explicit NUL is what the corpus writes to step over the high
            // half of a UTF-16 code unit.
            (r#""A\0B" matches /A\x00B/"#, true),
        ] {
            assert!(
                run(&format!("rule r {{ condition: {condition} }}"), b"") == expected,
                "{condition}"
            );
        }
    }

    #[test]
    fn a_pattern_applied_to_something_that_is_not_a_string_is_undefined() {
        // Not false: the operator produces `Undefined`, which is what every
        // other operation on a value of the wrong type produces here, and which
        // is falsy — so the rule does not fire, and the negation of it does.
        // That second half is the shape a rule author would have to write by
        // accident, because a pattern is only ever applied to a string in a
        // rule that means anything.
        assert!(!run(r#"rule r { condition: 1 matches /1/ }"#, b""));
        assert!(run(r#"rule r { condition: not ( 1 matches /1/ ) }"#, b""));
    }

    #[test]
    fn the_corpus_rule_that_uses_matches_reads_a_resource_name() {
        // Corpus line 209332: `string.length(pe.resources[0].name_string) == 8
        // and pe.resources[0].name_string matches /[0-9]\x00[0-9]\x00[0-9]\x00[0-9]\x00/`.
        // The resource here is named `RC1`, so its name is three UTF-16 code
        // units — one of them a digit, which is what the two bounds below
        // separate.
        let pe = pe_with_three_resources();
        for (condition, expected) in [
            (r#"pe.resources[0].name_string matches /[0-9]\x00/"#, true),
            (
                r#"pe.resources[0].name_string matches /[0-9]\x00[0-9]\x00/"#,
                false,
            ),
            (
                r#"pe.resources[0].name_string matches /[0-9]\x00[0-9]\x00[0-9]\x00[0-9]\x00/"#,
                false,
            ),
            // The same pattern against the same member of a second resource,
            // which is what makes it a test of the value rather than of the
            // pattern: `RC3` also ends in one digit.
            (r#"pe.resources[2].name_string matches /C\x003\x00/"#, true),
        ] {
            assert!(
                run_pe(&format!("rule r {{ condition: {condition} }}"), &pe) == expected,
                "{condition}"
            );
        }
    }

    #[test]
    fn count_and_percentage_agree_with_each_other() {
        let data = [0u8, 1, 0, 1, 0, 1, 0, 1];
        assert!(run(
            "rule r { condition: math.count(0, 0, filesize) == 4 }",
            &data
        ));
        assert!(run(
            "rule r { condition: math.count(1, 0, filesize) == 4 }",
            &data
        ));
        assert!(run(
            "rule r { condition: math.count(2, 0, filesize) == 0 }",
            &data
        ));
        assert!(run(
            "rule r { condition: math.percentage(0, 0, filesize) == 50.0 }",
            &data
        ));
        // A byte value outside `0 ..= 255` is not a byte, and asking how often
        // it occurs in a buffer of bytes has no answer. Zero would be an answer
        // — the wrong one — so this is `Undefined` and every comparison against
        // it is false, including the one that asks for zero.
        assert!(!run(
            "rule r { condition: math.count(256, 0, filesize) == 0 }",
            &data
        ));
    }

    #[test]
    fn the_percentage_of_a_region_that_is_not_there_is_zero_rather_than_nan() {
        // `NaN` would make both `< 50` and `> 50` false, so a rule negating one
        // of those comparisons would fire on every file. Zero compares.
        let short = vec![7u8; 10];
        assert!(run(
            "rule r { condition: math.percentage(0, 500, 500) == 0.0 }",
            &short
        ));
        assert!(run(
            "rule r { condition: math.percentage(0, 500, 500) < 50 }",
            &short
        ));
    }

    #[test]
    fn min_and_max_take_two_values_and_keep_the_one_they_should() {
        // The corpus's use: clamping a string count so that a loop has a bound.
        assert!(run("rule r { condition: math.min(3, 100) == 3 }", b""));
        assert!(run("rule r { condition: math.min(100, 3) == 3 }", b""));
        assert!(run("rule r { condition: math.max(3, 100) == 100 }", b""));
        // A float stays a float rather than being truncated to the argument
        // order, which would make the answer depend on which side it was on.
        assert!(run("rule r { condition: math.min(1.5, 2) == 1.5 }", b""));
        assert!(run("rule r { condition: math.min(-3, 2) == -3 }", b""));
    }

    #[test]
    fn abs_to_number_and_in_range_are_the_small_predicates_they_look_like() {
        assert!(run("rule r { condition: math.abs(-5) == 5 }", b""));
        assert!(run("rule r { condition: math.abs(5) == 5 }", b""));
        assert!(run("rule r { condition: math.to_number(true) == 1 }", b""));
        assert!(run("rule r { condition: math.to_number(false) == 0 }", b""));
        assert!(run("rule r { condition: math.in_range(5, 0, 10) }", b""));
        // Inclusive at both ends, which is what the name promises.
        assert!(run("rule r { condition: math.in_range(0, 0, 10) }", b""));
        assert!(run("rule r { condition: math.in_range(10, 0, 10) }", b""));
        assert!(!run("rule r { condition: math.in_range(11, 0, 10) }", b""));
    }

    #[test]
    fn a_predicate_that_is_undefined_does_not_become_a_zero_through_to_number() {
        // `math.to_number(pe.something)` on a file that is not a PE. Zero would
        // make `== 0` true, which is a rule firing on a file it knows nothing
        // about — the failure that `Undefined` exists to prevent.
        assert!(!run(
            "rule r { condition: math.to_number(pe.is_64bit) == 0 }",
            b"not a PE"
        ));
        assert!(!run(
            "rule r { condition: math.abs(pe.entry_point) == 0 }",
            b"not a PE"
        ));
    }

    // -- the version resource and the debug directory -----------------------

    #[test]
    fn a_version_info_key_is_read_from_the_resource() {
        let mut pe = av_pe::testing::minimal_pe32();
        av_pe::testing::add_version_resource(
            &mut pe,
            &[
                ("CompanyName", "Microsoft Corporation"),
                ("InternalName", "SERVICE.EXE"),
            ],
        );
        assert!(run_pe(
            r#"rule r { condition: pe.version_info["InternalName"] contains "SERVICE.EXE" }"#,
            &pe
        ));
        assert!(run_pe(
            r#"rule r { condition: pe.version_info["CompanyName"] == "Microsoft Corporation" }"#,
            &pe
        ));
        // And a key the file does not have is not answered from another one.
        assert!(!run_pe(
            r#"rule r { condition: pe.version_info["ProductName"] == "Microsoft Corporation" }"#,
            &pe
        ));
    }

    #[test]
    fn a_version_info_key_that_is_absent_is_undefined_rather_than_empty() {
        // The distinction the whole module rests on. If an absent key were an
        // empty string, `contains ""` would be true of every file on the disk
        // and a rule written as a conjunction would match on the strength of a
        // key that is not there.
        let mut pe = av_pe::testing::minimal_pe32();
        av_pe::testing::add_version_resource(&mut pe, &[("CompanyName", "Acme")]);
        assert!(run_pe(
            r#"rule r { condition: pe.version_info["CompanyName"] contains "" }"#,
            &pe
        ));
        assert!(!run_pe(
            r#"rule r { condition: pe.version_info["ProductName"] contains "" }"#,
            &pe
        ));
    }

    #[test]
    fn version_info_of_a_buffer_that_is_not_a_pe_is_undefined() {
        assert!(!run(
            r#"rule r { condition: pe.version_info["CompanyName"] == "Acme" }"#,
            b"not a PE at all"
        ));
    }

    #[test]
    fn a_pdb_path_is_read_from_the_debug_directory() {
        let mut pe = av_pe::testing::minimal_pe32();
        av_pe::testing::add_pdb_path(&mut pe, "C:\\build\\FlowCloud\\trunk\\agent.pdb");
        // The corpus's own shape: a build machine's directory, which is what
        // makes the path a fingerprint of the builder rather than a filename.
        assert!(run_pe(
            r#"rule r { condition: pe.pdb_path contains "\\FlowCloud\\trunk\\" }"#,
            &pe
        ));
        assert!(!run_pe(
            r#"rule r { condition: pe.pdb_path contains "\\OtherVendor\\" }"#,
            &pe
        ));
        // A file with no debug directory has an empty path, so a rule asking
        // whether it names one does not fire.
        let plain = av_pe::testing::minimal_pe32();
        assert!(!run_pe(
            r#"rule r { condition: pe.pdb_path contains "FlowCloud" }"#,
            &plain
        ));
    }

    // -- the dotnet module ---------------------------------------------------

    #[test]
    fn is_dotnet_answers_for_a_buffer_that_is_not_an_image_at_all() {
        // The one member of the module defined for every file, for the reason
        // `pe.is_pe` is: it is how a rule asks whether the rest is worth asking
        // about. A rule gated on it must not need the file to be a PE first.
        assert!(run(
            r#"rule r { condition: dotnet.is_dotnet == 0 }"#,
            b"hello"
        ));
        assert!(!run(
            r#"rule r { condition: dotnet.is_dotnet == 1 }"#,
            b"hello"
        ));
    }

    #[test]
    fn a_native_image_is_not_managed() {
        let pe = av_pe::testing::minimal_pe32();
        assert!(run_pe(
            r#"rule r { condition: dotnet.is_dotnet == 0 }"#,
            &pe
        ));
    }

    #[test]
    fn a_dotnet_member_of_a_native_image_is_undefined_rather_than_zero() {
        // The distinction the whole module is arranged around. A rule writing
        // `dotnet.number_of_resources == 0` is a plausible way to say "a managed
        // file with no resources" and would be true of every native executable on
        // the disk if this answered zero.
        let pe = av_pe::testing::minimal_pe32();
        for member in [
            "dotnet.version",
            "dotnet.number_of_resources",
            "dotnet.assembly.version.major",
            "dotnet.assembly.version.minor",
            "dotnet.assembly.version.build",
            "dotnet.assembly.version.revision",
        ] {
            assert!(
                !run_pe(&format!("rule r {{ condition: {member} defined }}"), &pe),
                "{member} must be undefined for a native image"
            );
        }
        // And nothing at all, which is not even a PE.
        assert!(!run(
            r#"rule r { condition: dotnet.version defined }"#,
            b"hello"
        ));
    }

    #[test]
    fn a_dotnet_array_index_is_undefined_for_a_native_image() {
        let pe = av_pe::testing::minimal_pe32();
        for condition in [
            r#"dotnet.resources[0].name defined"#,
            r#"dotnet.resources[0].length defined"#,
            r#"dotnet.assembly_refs[0].name defined"#,
        ] {
            assert!(
                !run_pe(&format!("rule r {{ condition: {condition} }}"), &pe),
                "{condition} must be undefined for a native image"
            );
        }
    }

    #[test]
    fn a_dotnet_member_that_is_not_implemented_is_refused() {
        // Refused rather than compiled, because a member the interpreter cannot
        // answer would answer `Undefined` for every file and make every rule
        // naming it stop matching while still looking supported.
        for condition in [
            "dotnet.guids[0]",
            "dotnet.streams[0].name",
            "dotnet.user_strings[0]",
            "dotnet.assembly.name",
            "dotnet.assembly.culture",
            "dotnet.assembly.version.patch",
            "dotnet.resources[0].type",
            "dotnet.assembly_refs[0].version.major",
            // The two members whose names differ by a segment, and the pair a
            // reader is most likely to conflate.
            "dotnet.assembly.version",
        ] {
            assert!(
                compile_fails(&format!("rule r {{ condition: {condition} == 0 }}")),
                "{condition} must be refused"
            );
        }
    }

    #[test]
    fn the_dotnet_paths_the_corpus_writes_compile() {
        // The exact spellings the 10,764-rule set uses, so that a change to the
        // path mapping shows up here rather than as a refusal in a build report.
        for condition in [
            "dotnet.is_dotnet",
            r#"dotnet.version == "v4.0.30319""#,
            "dotnet.number_of_resources > 4",
            "dotnet.number_of_resources < 6",
            r#"dotnet.assembly_refs[1].name contains "protobuf-net""#,
            "dotnet.resources[0].length > 300KB",
            r#"dotnet.resources[0].name == "Quasar.Client*""#,
            "dotnet.assembly.version.major == 0",
            "dotnet.assembly.version.minor == 0",
        ] {
            let source = format!("rule r {{ strings: $a = \"x\" condition: {condition} and $a }}");
            let file = parse_file(&source).expect("the spelling must parse");
            let rule = &file.rules[0];
            let table = StringTable::from_defs(&rule.strings);
            assert!(
                compile_condition(&rule.condition, &table, rule.span).is_ok(),
                "{condition} must compile"
            );
        }
    }
}

/// The real-assembly checks for the `dotnet` module, which are opt-in because
/// they read files that only exist on a machine with the .NET Framework
/// installed.
///
/// ```text
/// cargo test -p av-rules -- --ignored
/// ```
///
/// They are `#[ignore]`d rather than skipped-when-missing for the reason the
/// `av-pe` ones are: a test that quietly passes when the file it reads is not
/// there reports success for having read nothing. Every number asserted below is
/// one `av-pe`'s real-file tests already established from an independent reader,
/// so what these add is not the value but the path — that the compiler maps the
/// corpus's spelling onto the right opcode, that the interpreter reads the right
/// field, and that a rule written the way the corpus writes it selects the file
/// it was written for.
#[cfg(test)]
mod real_dotnet_files {
    use super::tests::run_pe;
    use std::path::Path;

    /// Where the 64-bit .NET Framework 4 assemblies live.
    const FRAMEWORK: &str = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319";

    /// Read an assembly and run one condition against it.
    ///
    /// The condition is wrapped in a rule here rather than at each call, so that
    /// the assertions below read as the conditions the corpus writes. A rule
    /// with no strings is legal — `dotnet.is_dotnet` on its own is one — which
    /// is what makes the wrapper this short.
    fn matches(assembly: &str, condition: &str) -> bool {
        let path = Path::new(FRAMEWORK).join(assembly);
        let bytes = std::fs::read(&path).expect("the .NET Framework must be installed");
        run_pe(&format!("rule r {{ condition: {condition} }}"), &bytes)
    }

    #[test]
    #[ignore = "reads the installed .NET Framework assemblies"]
    fn a_real_assembly_answers_every_member_the_corpus_names() {
        // `mscorlib.dll`: the one assembly every managed file on the machine
        // references, and the one the corpus's own `dotnet.version` rule was
        // written against.
        assert!(matches("mscorlib.dll", "dotnet.is_dotnet"));
        assert!(matches("mscorlib.dll", r#"dotnet.version == "v4.0.30319""#));
        assert!(matches("mscorlib.dll", "dotnet.number_of_resources == 8"));
        assert!(matches(
            "mscorlib.dll",
            r#"dotnet.assembly.version.major == 4 and dotnet.assembly.version.minor == 0"#
        ));
        assert!(matches(
            "mscorlib.dll",
            "dotnet.assembly.version.build == 0 and dotnet.assembly.version.revision == 0"
        ));
        // The name a resource carries, which is what a rule matching
        // `"Quasar.Client*"` is matching against — the assembly's own name for
        // it, not the name of the file the assembly was shipped in.
        assert!(matches(
            "mscorlib.dll",
            r#"dotnet.resources[0].name == "normidna.nlp""#
        ));
        assert!(matches(
            "mscorlib.dll",
            r#"dotnet.resources[7].name == "codepages.nlp""#
        ));
        // And the distinction the member was written around: five of
        // `mscorlib.dll`'s eight resources are *linked* to other files, so they
        // have no bytes here and therefore no length. A reader that reported the
        // offset field for them would answer all five with the length of
        // whichever resource sits first in the data area.
        assert!(matches(
            "mscorlib.dll",
            "not (dotnet.resources[0].length defined)"
        ));
        assert!(matches(
            "mscorlib.dll",
            "not (dotnet.resources[4].length defined)"
        ));
        // The three that are embedded, with the lengths the data area's own `u32`
        // headers declare.
        assert!(matches(
            "mscorlib.dll",
            "dotnet.resources[5].length == 353031"
        ));
        assert!(matches(
            "mscorlib.dll",
            "dotnet.resources[6].length == 36992"
        ));
        assert!(matches(
            "mscorlib.dll",
            "dotnet.resources[7].length == 612764"
        ));
        // One past the last resource is `Undefined`, not a wrap-around to the
        // first: the corpus iterates with `for any i in (0 .. n - 1)`.
        assert!(matches(
            "mscorlib.dll",
            "not (dotnet.resources[8].length defined)"
        ));
        // mscorlib references nothing, which is what `av-pe` asserts too.
        assert!(matches(
            "mscorlib.dll",
            "not (dotnet.assembly_refs[0].name defined)"
        ));
    }

    #[test]
    #[ignore = "reads the installed .NET Framework assemblies"]
    fn the_assembly_reference_index_is_the_table_order() {
        // `System.dll`'s second `AssemblyRef` row, which is the exact condition
        // in rule `RUSSIANPANDA_Purecrypter`. A reader that walked the table
        // backwards, or that read names out of the heap in the order they
        // happen to sit there, would answer one of the other two.
        assert!(matches(
            "System.dll",
            r#"dotnet.assembly_refs[1].name contains "System.Configuration""#
        ));
        assert!(matches(
            "System.dll",
            r#"dotnet.assembly_refs[0].name == "mscorlib""#
        ));
        assert!(matches(
            "System.dll",
            r#"dotnet.assembly_refs[2].name == "System.Xml""#
        ));
        assert!(matches(
            "System.dll",
            r#"not (dotnet.assembly_refs[3].name defined)"#
        ));
        assert!(matches(
            "System.dll",
            r#"dotnet.assembly.version.major == 4 and dotnet.assembly.version.minor == 0"#
        ));
    }

    #[test]
    #[ignore = "reads the installed .NET Framework assemblies"]
    fn a_native_image_in_the_same_directory_is_not_managed() {
        // The control. A module that answered from the file's *name*, or from
        // anything about the directory it sits in, would call this one managed.
        let path = Path::new(FRAMEWORK).join("mscorlib.dll");
        let managed = std::fs::read(&path).expect("the .NET Framework must be installed");
        let Some(root) = std::env::var_os("SystemRoot") else {
            return;
        };
        let native = std::fs::read(Path::new(&root).join("System32").join("kernel32.dll"))
            .expect("a Windows installation");
        assert!(run_pe("rule r { condition: dotnet.is_dotnet }", &managed));
        assert!(run_pe(
            "rule r { condition: dotnet.is_dotnet == 0 }",
            &native
        ));
        assert!(run_pe(
            "rule r { condition: not (dotnet.version defined) \
             and not (dotnet.number_of_resources defined) }",
            &native
        ));
    }
}
