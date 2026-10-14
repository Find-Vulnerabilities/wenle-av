//! The CLI header and the metadata tables a managed assembly carries.
//!
//! This module answers one kind of question: *what does the `dotnet` module say
//! about this file?* A .NET assembly is a PE whose meaning is in a set of tables
//! hanging off data directory 14, and those tables are the only way to tell a
//! C# or VB.NET program from the native image it is dressed as.
//!
//! # The path to the tables
//!
//! Four structures deep, each one an offset into the last, each one a pair of
//! numbers out of the file that has to be checked before it is used:
//!
//! ```text
//! data directory 14          (RVA, size)   -- present for any managed image
//!   └── CLI header          72 bytes       -- ECMA-335 II.25.3.3
//!         ├── MetaData      (RVA, size)    -- +8
//!         │     └── root    "BSJB"         -- II.24.2.1
//!         │           ├── version string   -- the `dotnet.version` member
//!         │           └── stream headers   -- "#~", "#Strings", ...
//!         │                 ├── "#~"       -- the tables, II.24.2.6
//!         │                 └── "#Strings" -- the names, II.24.2.3
//!         └── Resources     (RVA, size)    -- +24, where `resources[i]` lives
//! ```
//!
//! # The tables, and why reading them means reading all of them
//!
//! The `#~` stream holds one run of rows per table, and the tables are laid out
//! in **table-id order with no index of their own**: the only way to reach row
//! `r` of table `0x28` is to know the size of every row of every table before
//! it and multiply. So `SCHEMA` covers all forty-five tables, not the three
//! this module reads, because a table that cannot be measured cannot be skipped
//! and a wrong width anywhere before `ManifestResource` moves every resource in
//! the file.
//!
//! That is also why the schema is written from ECMA-335 II.22 rather than from
//! what these three tables need, and why the validation below is the arithmetic
//! rather than a checksum: a mistake in one column width produces names that
//! decode to plausible rubbish rather than an error, so there is no cheap way to
//! notice one at run time.
//!
//! # What was measured rather than assumed
//!
//! Two members are not what the names suggest, and both were settled by reading
//! real assemblies rather than by reading a document.
//!
//! * **`resources[i].offset` points at a four-byte length, not at the data.**
//!   `ManifestResource.Offset` is an offset into the CLI header's Resources data
//!   area, and the bytes there are a `u32` length followed by the resource. On
//!   `System.dll` every embedded resource's `offset` holds a `u32` equal to the
//!   size of the blob that follows it — `824` before `"BM"` and 824 bytes of
//!   bitmap — so [`DotNetResource::length`] is that prefix and
//!   [`DotNetResource::offset`] is where the *data* starts, four bytes later.
//!   The three assemblies measured agree to the byte: the embedded resources of
//!   `System.dll`, `mscorlib.dll` and `System.Core.dll` sum to 217,809,
//!   1,002,799 and 78,449 bytes against declared data areas of 217,840,
//!   1,002,808 and 78,456, the difference being alignment padding — to **eight**
//!   bytes, which is what those three files' offsets say: `System.dll`'s 824-byte
//!   bitmaps sit 832 bytes apart, and padding to four would put them 828 apart.
//!
//! * **A resource with a non-zero `Implementation` has no offset and no length
//!   at all.** When that column names a `File` row the resource is *linked* —
//!   it lives in another file — and the offset field is zero and meaningless.
//!   Five of `mscorlib.dll`'s eight manifest resources are like that, and all
//!   five carry `Offset == 0`, so a reader that reported the field would answer
//!   every one of them with the length of whichever resource happened to be
//!   first in the data area: 353,031 bytes for all five. They are
//!   [`Option::None`] here, and `dotnet.resources[i].length` is `Undefined` for
//!   them, which is what a rule comparing a length must be told instead of a
//!   number belonging to a different resource.
//!
//! # What is deliberately absent
//!
//! The `#US`, `#GUID` and `#Blob` heaps are located and sized but not read;
//! nothing in this product's corpus asks for a string from them.
//! `dotnet.guids` and `dotnet.streams` are not implemented for the same reason
//! — see the rule engine's `DotNetField` for the policy, which is to refuse a
//! member by name rather than answer it with a zero.

use crate::headers::directory;
use crate::pe::PeFile;
use crate::read::Reader;

/// `sizeof(IMAGE_COR20_HEADER)`, and the only value `cb` is allowed to be.
///
/// Checked as a minimum rather than for equality: a file declaring a larger
/// header is describing a structure this reader does not know the end of, but
/// every field it needs is in the first seventy-two bytes either way.
const CLI_HEADER_LEN: usize = 72;

/// Where each field this module reads sits in the CLI header. ECMA-335 II.25.3.3.
///
/// Only the three that are read. The header also carries
/// `MajorRuntimeVersion`/`MinorRuntimeVersion` at 4, `Flags` at 16,
/// `EntryPointToken` at 20, and three more directories — the strong name
/// signature, the vtable fixups and the managed native header — and none of them
/// has a member in the rule language, so none has a constant here. A constant
/// nothing reads is a second description of the format to keep in step.
mod cli {
    /// `cb`, the header's own size.
    pub const SIZE: usize = 0;
    /// `MetaData`, a directory: RVA then size.
    pub const METADATA: usize = 8;
    /// `Resources`, a directory: RVA then size.
    pub const RESOURCES: usize = 24;
}

/// The signature every metadata root begins with, `BSJB` little-endian.
const METADATA_SIGNATURE: u32 = 0x424A_5342;

/// Where each field of the metadata root sits. ECMA-335 II.24.2.1.
mod root {
    pub const SIGNATURE: usize = 0;
    pub const VERSION_LENGTH: usize = 12;
    pub const VERSION: usize = 16;
    /// `Flags` then `Streams`, the count of stream headers that follow.
    pub const FLAGS_AND_STREAMS: usize = 4;
}

/// The `#~` stream's own header. ECMA-335 II.24.2.6.
mod tables_header {
    pub const HEAP_SIZES: usize = 6;
    pub const VALID: usize = 8;
    pub const SORTED: usize = 16;
    /// The row counts start here, one `u32` per set bit of `VALID`.
    pub const ROW_COUNTS: usize = 24;
}

/// `HeapSizes` bits. A set bit widens that heap's index from two bytes to four.
const STRING_HEAP_WIDE: u8 = 0x01;
const GUID_HEAP_WIDE: u8 = 0x02;
const BLOB_HEAP_WIDE: u8 = 0x04;

/// The table ids this module reads by name. The rest are here only so that they
/// can be measured and skipped.
pub mod table {
    /// `Assembly`.
    pub const ASSEMBLY: u8 = 0x20;
    /// `AssemblyRef`.
    pub const ASSEMBLY_REF: u8 = 0x23;
    /// `File`, which a linked manifest resource points into.
    pub const FILE: u8 = 0x26;
    /// `ManifestResource`.
    pub const MANIFEST_RESOURCE: u8 = 0x28;
    /// The highest table id ECMA-335 defines, so one past the last entry of
    /// `SCHEMA`.
    pub const COUNT: usize = 0x2D;
}

/// A table index whose high bits name which table it is.
///
/// ECMA-335 II.24.2.6 calls these "coded indexes": one column that can refer to
/// a row of any of several tables, with the low two, three or five bits saying
/// which. The width of the column depends on the largest row count among the
/// tables it can name, so the list of tables is not documentation — it is the
/// input to the width computation, and a table missing from a list yields a
/// column two bytes narrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodedIndex {
    /// `TypeDef`, `TypeRef` or `TypeSpec`. The base type of a `TypeDef`, the
    /// interface of an `InterfaceImpl`, a `Property`'s type.
    TypeDefOrRef,
    /// `Field`, `Param` or `Property`: what a `Constant` is the value of.
    HasConstant,
    /// Twenty-two tables, the widest tag in the format. Every `CustomAttribute`
    /// names its owner through this.
    HasCustomAttribute,
    /// `Field` or `Param`. A `FieldMarshal`'s owner.
    HasFieldMarshal,
    /// `TypeDef`, `MethodDef` or `Assembly`. A `DeclSecurity`'s owner.
    HasDeclSecurity,
    /// `TypeDef`, `TypeRef`, `ModuleRef`, `MethodDef` or `TypeSpec`: what a
    /// `MemberRef` is a member of.
    MemberRefParent,
    /// `Event` or `Property`. Which one a `MethodSemantics` row is about.
    HasSemantics,
    /// `MethodDef` or `MemberRef`: a method, defined here or referenced.
    MethodDefOrRef,
    /// `Field` or `MethodDef`: what an `ImplMap` forwards.
    MemberForwarded,
    /// `File`, `AssemblyRef` or `ExportedType` — the column this module reads.
    /// Non-zero on a `ManifestResource` means the resource is linked rather than
    /// embedded, which is why `resources[i].length` can be absent.
    Implementation,
    /// `MethodDef` or `MemberRef`. Three tag values of five are spoken for,
    /// which is why [`CodedIndex::tables`] has two entries for this one.
    CustomAttributeType,
    /// `Module`, `ModuleRef`, `AssemblyRef` or `TypeRef`: where a `TypeRef` is
    /// defined.
    ResolutionScope,
    /// `TypeDef` or `MethodDef`: the owner of a `GenericParam`.
    TypeOrMethodDef,
}

impl CodedIndex {
    /// How many bits of the index are the tag.
    pub const fn tag_bits(self) -> u32 {
        match self {
            CodedIndex::HasCustomAttribute => 5,
            CodedIndex::MemberRefParent
            | CodedIndex::CustomAttributeType
            | CodedIndex::ResolutionScope => 3,
            CodedIndex::TypeDefOrRef
            | CodedIndex::HasConstant
            | CodedIndex::HasDeclSecurity
            | CodedIndex::Implementation => 2,
            CodedIndex::HasFieldMarshal
            | CodedIndex::HasSemantics
            | CodedIndex::MethodDefOrRef
            | CodedIndex::MemberForwarded
            | CodedIndex::TypeOrMethodDef => 1,
        }
    }

    /// The tables a value of this column can name.
    ///
    /// The order is the tag order and matters only for decoding, which this
    /// module does not do — it reads `Implementation == 0` and nothing else —
    /// so the lists are here for their row counts and the order is ECMA-335's.
    pub const fn tables(self) -> &'static [u8] {
        match self {
            CodedIndex::TypeDefOrRef => &[0x02, 0x01, 0x1B],
            CodedIndex::HasConstant => &[0x04, 0x08, 0x17],
            CodedIndex::HasCustomAttribute => &[
                0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B,
                0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2B, 0x2C,
            ],
            CodedIndex::HasFieldMarshal => &[0x04, 0x08],
            CodedIndex::HasDeclSecurity => &[0x02, 0x06, 0x20],
            CodedIndex::MemberRefParent => &[0x02, 0x01, 0x1A, 0x06, 0x1B],
            CodedIndex::HasSemantics => &[0x14, 0x17],
            CodedIndex::MethodDefOrRef => &[0x06, 0x0A],
            CodedIndex::MemberForwarded => &[0x04, 0x06],
            CodedIndex::Implementation => &[0x26, 0x23, 0x27],
            // Five slots with the first, second and fifth unused, because the
            // three-bit tag is the format's and only three of its values are
            // spoken for. The unused slots name no table and so contribute no
            // row count to the width, which is the only thing this list feeds.
            CodedIndex::CustomAttributeType => &[0x06, 0x0A],
            CodedIndex::ResolutionScope => &[0x00, 0x1A, 0x23, 0x01],
            CodedIndex::TypeOrMethodDef => &[0x02, 0x06],
        }
    }
}

/// One column of a table row.
///
/// The four widths that are not fixed — the three heaps and the two kinds of
/// index — are what makes this a program rather than a table of numbers, and
/// they are resolved against the file's own `HeapSizes` and row counts by
/// `Tables::width`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    /// A two-byte integer. `Constant.Type` is stored as one byte plus a padding
    /// byte, and is the reason there is no one-byte variant here.
    U16,
    /// A four-byte integer: a row count, a file offset, a runtime version, a
    /// token, a `TypeDef`'s flags.
    U32,
    /// An index into the `#Strings` heap.
    String,
    /// An index into the `#Blob` heap.
    Blob,
    /// An index into the `#GUID` heap.
    Guid,
    /// An index into one table, two bytes unless that table has 65,536 rows.
    Table(u8),
    /// An index into several tables, at a width the row counts decide.
    Coded(CodedIndex),
}

/// `Table(0x04)` is written this often below, so it earns a name.
const FIELD: Column = Column::Table(0x04);
const METHOD_DEF: Column = Column::Table(0x06);
const PARAM: Column = Column::Table(0x08);
const EVENT: Column = Column::Table(0x14);
const PROPERTY: Column = Column::Table(0x17);
const ASSEMBLY_REF: Column = Column::Table(table::ASSEMBLY_REF);
const TYPE_DEF: Column = Column::Table(0x02);

/// Every table's columns, indexed by table id. ECMA-335 II.22.
///
/// All forty-five, because the tables are one run of bytes with no index: a
/// table this module does not read still has to be measured to be stepped over,
/// and a wrong width in `TypeDef` moves every `ManifestResource` row in the
/// file. The tables this module actually reads are `0x20`, `0x23` and `0x28`,
/// and they are marked below.
static SCHEMA: [&[Column]; table::COUNT] = [
    // 0x00 Module
    &[
        Column::U16,
        Column::String,
        Column::Guid,
        Column::Guid,
        Column::Guid,
    ],
    // 0x01 TypeRef
    &[
        Column::Coded(CodedIndex::ResolutionScope),
        Column::String,
        Column::String,
    ],
    // 0x02 TypeDef
    &[
        Column::U32,
        Column::String,
        Column::String,
        Column::Coded(CodedIndex::TypeDefOrRef),
        FIELD,
        METHOD_DEF,
    ],
    // 0x03 FieldPtr
    &[FIELD],
    // 0x04 Field
    &[Column::U16, Column::String, Column::Blob],
    // 0x05 MethodPtr
    &[METHOD_DEF],
    // 0x06 MethodDef
    &[
        Column::U32,
        Column::U16,
        Column::U16,
        Column::String,
        Column::Blob,
        PARAM,
    ],
    // 0x07 ParamPtr
    &[PARAM],
    // 0x08 Param
    &[Column::U16, Column::U16, Column::String],
    // 0x09 InterfaceImpl
    &[TYPE_DEF, Column::Coded(CodedIndex::TypeDefOrRef)],
    // 0x0A MemberRef
    &[
        Column::Coded(CodedIndex::MemberRefParent),
        Column::String,
        Column::Blob,
    ],
    // 0x0B Constant
    &[
        Column::U16,
        Column::Coded(CodedIndex::HasConstant),
        Column::Blob,
    ],
    // 0x0C CustomAttribute
    &[
        Column::Coded(CodedIndex::HasCustomAttribute),
        Column::Coded(CodedIndex::CustomAttributeType),
        Column::Blob,
    ],
    // 0x0D FieldMarshal
    &[Column::Coded(CodedIndex::HasFieldMarshal), Column::Blob],
    // 0x0E DeclSecurity
    &[
        Column::U16,
        Column::Coded(CodedIndex::HasDeclSecurity),
        Column::Blob,
    ],
    // 0x0F ClassLayout
    &[Column::U16, Column::U32, TYPE_DEF],
    // 0x10 FieldLayout
    &[Column::U32, FIELD],
    // 0x11 StandAloneSig
    &[Column::Blob],
    // 0x12 EventMap
    &[TYPE_DEF, EVENT],
    // 0x13 EventPtr
    &[EVENT],
    // 0x14 Event
    &[
        Column::U16,
        Column::String,
        Column::Coded(CodedIndex::TypeDefOrRef),
    ],
    // 0x15 PropertyMap
    &[TYPE_DEF, PROPERTY],
    // 0x16 PropertyPtr
    &[PROPERTY],
    // 0x17 Property
    &[Column::U16, Column::String, Column::Blob],
    // 0x18 MethodSemantics
    &[
        Column::U16,
        METHOD_DEF,
        Column::Coded(CodedIndex::HasSemantics),
    ],
    // 0x19 MethodImpl
    &[
        TYPE_DEF,
        Column::Coded(CodedIndex::MethodDefOrRef),
        Column::Coded(CodedIndex::MethodDefOrRef),
    ],
    // 0x1A ModuleRef
    &[Column::String],
    // 0x1B TypeSpec
    &[Column::Blob],
    // 0x1C ImplMap
    &[
        Column::U16,
        Column::Coded(CodedIndex::MemberForwarded),
        Column::String,
        Column::Table(0x1A),
    ],
    // 0x1D FieldRVA
    &[Column::U32, FIELD],
    // 0x1E ENCLog
    &[Column::U32, Column::U32],
    // 0x1F ENCMap
    &[Column::U32],
    // 0x20 Assembly — read
    &[
        Column::U32,
        Column::U16,
        Column::U16,
        Column::U16,
        Column::U16,
        Column::U32,
        Column::Blob,
        Column::String,
        Column::String,
    ],
    // 0x21 AssemblyProcessor
    &[Column::U32],
    // 0x22 AssemblyOS
    &[Column::U32, Column::U32, Column::U32],
    // 0x23 AssemblyRef — read
    &[
        Column::U16,
        Column::U16,
        Column::U16,
        Column::U16,
        Column::U32,
        Column::Blob,
        Column::String,
        Column::String,
        Column::Blob,
    ],
    // 0x24 AssemblyRefProcessor
    &[Column::U32, ASSEMBLY_REF],
    // 0x25 AssemblyRefOS
    &[Column::U32, Column::U32, Column::U32, ASSEMBLY_REF],
    // 0x26 File
    &[Column::U32, Column::String, Column::Blob],
    // 0x27 ExportedType
    &[
        Column::U32,
        Column::U32,
        Column::String,
        Column::String,
        Column::Coded(CodedIndex::Implementation),
    ],
    // 0x28 ManifestResource — read
    &[
        Column::U32,
        Column::U32,
        Column::String,
        Column::Coded(CodedIndex::Implementation),
    ],
    // 0x29 NestedClass
    &[TYPE_DEF, TYPE_DEF],
    // 0x2A GenericParam
    &[
        Column::U16,
        Column::U16,
        Column::Coded(CodedIndex::TypeOrMethodDef),
        Column::String,
    ],
    // 0x2B MethodSpec
    &[Column::Coded(CodedIndex::MethodDefOrRef), Column::Blob],
    // 0x2C GenericParamConstraint
    &[Column::Table(0x2A), Column::Coded(CodedIndex::TypeDefOrRef)],
];

/// A version, as four `u16` fields.
///
/// Not an integer packed out of them, because the fields are not a number: the
/// assembly version of `System.dll` is `4.0.0.0` and the comparison a rule makes
/// is against `major` or `minor`, never against the whole thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AssemblyVersion {
    /// `MajorVersion`.
    pub major: u16,
    /// `MinorVersion`.
    pub minor: u16,
    /// `BuildNumber`.
    pub build: u16,
    /// `RevisionNumber`.
    pub revision: u16,
}

/// One `ManifestResource` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DotNetResource<'a> {
    /// The resource's name, out of the `#Strings` heap.
    pub name: &'a [u8],
    /// Where the resource's **bytes** are, as a file offset — four bytes past
    /// the length this reader read. `None` for a linked resource.
    pub offset: Option<u64>,
    /// The `u32` that precedes the resource's bytes in the Resources data area.
    /// `None` for a linked resource.
    pub length: Option<u32>,
}

/// One `AssemblyRef` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyRef<'a> {
    /// The referenced assembly's name.
    pub name: &'a [u8],
    /// The version it was compiled against.
    pub version: AssemblyVersion,
}

/// The `#Strings` heap: NUL-terminated UTF-8, addressed by byte offset.
///
/// Index zero is defined to be the empty string — the heap begins with a NUL for
/// exactly that purpose — so a column holding zero reads as `""` and not as the
/// first name in the heap.
#[derive(Debug, Clone, Copy, Default)]
struct Strings<'a> {
    bytes: &'a [u8],
}

impl<'a> Strings<'a> {
    /// The string at `index`, or an empty one when the index is not in the heap.
    ///
    /// An index past the end is empty rather than an error, and that is the
    /// direction the choice is made in for the same reason every other absence
    /// here is: a name a rule cannot match is a rule that does not fire, and a
    /// name invented out of adjacent bytes is a rule that fires on the wrong
    /// file. A file with a corrupt heap gets no detections rather than wrong
    /// ones.
    fn get(&self, index: u64) -> &'a [u8] {
        let Ok(index) = usize::try_from(index) else {
            return &[];
        };
        let Some(tail) = self.bytes.get(index..) else {
            return &[];
        };
        match tail.iter().position(|&b| b == 0) {
            Some(end) => &tail[..end],
            // The last name in the heap has its terminator, so an unterminated
            // one is a file that lied about the heap's size. Taking the tail is
            // the reading that keeps the name's own bytes.
            None => tail,
        }
    }
}

/// The `#~` stream, walked far enough to index any table.
#[derive(Debug, Clone)]
struct Tables<'a> {
    /// The stream, from its header onwards.
    data: &'a [u8],
    /// Where each table's first row starts, relative to `data`. `None` for a
    /// table the file does not have.
    at: [Option<usize>; table::COUNT],
    /// How many rows each table has.
    rows: [u32; table::COUNT],
    /// Whether each heap index is four bytes rather than two.
    string_wide: bool,
    guid_wide: bool,
    blob_wide: bool,
}

impl<'a> Tables<'a> {
    /// Read the stream's header and locate every table's rows.
    ///
    /// `None` when the header is not readable — a stream too short for its own
    /// row counts, or a bit set in `Valid` with no room for the count that goes
    /// with it. A file in that state has no tables this reader can trust, and
    /// answering with an empty set is the same answer as a managed module with
    /// no resources, which is a case that exists.
    fn read(data: &'a [u8]) -> Option<Self> {
        let reader = Reader::new(data);
        let heap_sizes = reader.u8(tables_header::HEAP_SIZES).ok()?;
        let valid = reader.u64(tables_header::VALID).ok()?;
        // `Sorted` is read past rather than checked: it is an optimisation
        // hint for a binary search, and every table here is walked in order.
        let _ = reader.u64(tables_header::SORTED).ok()?;

        // One `u32` per set bit, in table-id order, so the walk is over the
        // valid bits and the cursor advances only where a bit is set. A bit set
        // past the end of the stream is what makes this `None` rather than a
        // table with no rows.
        let mut rows = [0u32; table::COUNT];
        let mut count_at = tables_header::ROW_COUNTS;
        for (id, row_count) in rows.iter_mut().enumerate() {
            if valid >> id & 1 == 1 {
                *row_count = reader.u32(count_at).ok()?;
                count_at += 4;
            }
        }

        let mut tables = Tables {
            data,
            at: [None; table::COUNT],
            rows,
            string_wide: heap_sizes & STRING_HEAP_WIDE != 0,
            guid_wide: heap_sizes & GUID_HEAP_WIDE != 0,
            blob_wide: heap_sizes & BLOB_HEAP_WIDE != 0,
        };

        // Walked into a local rather than into `tables.at`, because measuring a
        // table is a method on `tables` and the borrow of the field would still
        // be live.
        let mut starts = [None; table::COUNT];
        let mut at = count_at;
        for (index, start) in starts.iter_mut().enumerate() {
            if valid >> index & 1 == 1 {
                *start = Some(at);
                let id = u8::try_from(index).ok()?;
                at = at.checked_add(tables.table_len(id)?)?;
            }
        }
        tables.at = starts;
        Some(tables)
    }

    /// How many bytes one row of `table` takes.
    fn row_len(&self, table: u8) -> Option<usize> {
        let schema = SCHEMA.get(usize::from(table))?;
        let mut len = 0usize;
        for column in *schema {
            len = len.checked_add(self.width(*column)?)?;
        }
        Some(len)
    }

    /// How many bytes every row of `table` takes.
    fn table_len(&self, table: u8) -> Option<usize> {
        let rows = usize::try_from(*self.rows.get(usize::from(table))?).ok()?;
        self.row_len(table)?.checked_mul(rows)
    }

    /// How wide one column is, in bytes.
    ///
    /// The two rules, and they are the whole of the format's variability: a heap
    /// index is four bytes when the file's `HeapSizes` says so, and an index into
    /// a table is four bytes when that table has at least 65,536 rows — because
    /// two bytes can address 65,536 of them and no more. A coded index widens a
    /// step earlier, since its low bits are the tag: it fits in two bytes while
    /// the largest row count it can name still fits in `16 - tag_bits`.
    fn width(&self, column: Column) -> Option<usize> {
        Some(match column {
            Column::U16 => 2,
            Column::U32 => 4,
            Column::String => self.heap_width(self.string_wide),
            Column::Guid => self.heap_width(self.guid_wide),
            Column::Blob => self.heap_width(self.blob_wide),
            Column::Table(id) => self.table_width(id),
            Column::Coded(coded) => {
                let widest = coded
                    .tables()
                    .iter()
                    .filter_map(|id| self.rows.get(usize::from(*id)))
                    .copied()
                    .max()
                    .unwrap_or(0);
                // 65,536 rows with a two-bit tag needs 18 bits, so it widens.
                if (u64::from(widest) << coded.tag_bits()) < (1 << 16) {
                    2
                } else {
                    4
                }
            }
        })
    }

    fn heap_width(&self, wide: bool) -> usize {
        if wide {
            4
        } else {
            2
        }
    }

    /// How wide an index into one table is.
    fn table_width(&self, table: u8) -> usize {
        match self.rows.get(usize::from(table)) {
            Some(&rows) if rows >= 65_536 => 4,
            _ => 2,
        }
    }

    /// Where a column of a row starts, relative to the start of the stream.
    fn cell(&self, table: u8, row: u32, column: usize) -> Option<usize> {
        let first = self.at.get(usize::from(table)).copied().flatten()?;
        let stride = self.row_len(table)?;
        let offset = usize::try_from(row).ok()?.checked_mul(stride)?;
        let mut at = first.checked_add(offset)?;
        let schema = SCHEMA.get(usize::from(table))?;
        for earlier in schema.iter().take(column) {
            at = at.checked_add(self.width(*earlier)?)?;
        }
        Some(at)
    }

    /// The `column`-th field of a row, as an integer of whatever width it has.
    ///
    /// Returns `None` when the bytes are not there, which is what a row count
    /// larger than the stream accounts for: a file claiming ten million rows in
    /// a stream of a kilobyte yields nothing rather than a walk off the end.
    fn field(&self, table: u8, row: u32, column: usize) -> Option<u64> {
        let at = self.cell(table, row, column)?;
        let schema = SCHEMA.get(usize::from(table))?;
        let width = self.width(*schema.get(column)?)?;
        self.data_at(at, width)
    }

    /// A little-endian integer of `width` bytes at `at`.
    fn data_at(&self, at: usize, width: usize) -> Option<u64> {
        let bytes = self.data.get(at..at.checked_add(width)?)?;
        let mut value = 0u64;
        for (index, byte) in bytes.iter().enumerate() {
            value |= u64::from(*byte) << (index * 8);
        }
        Some(value)
    }
}

/// A managed assembly's CLI header, metadata tables and manifest resources.
///
/// Empty rather than absent when the file is not managed, so that every member
/// answers without a caller having to ask whether there is anything to ask.
#[derive(Debug, Clone, Default)]
pub struct DotNet<'a> {
    /// Whether the file has a CLI header directory at all.
    present: bool,
    /// The runtime version string out of the metadata root, which is the
    /// `dotnet.version` member. `v4.0.30319` for anything built against .NET
    /// Framework 4.
    version: Option<&'a [u8]>,
    /// The `Assembly` table's one row, absent for a module that is not an
    /// assembly.
    assembly: Option<(&'a [u8], AssemblyVersion)>,
    /// Every `AssemblyRef` row, in table order.
    assembly_refs: Vec<AssemblyRef<'a>>,
    /// Every `ManifestResource` row, in table order.
    resources: Vec<DotNetResource<'a>>,
}

impl<'a> DotNet<'a> {
    /// Whether the file is managed.
    ///
    /// The presence of data directory 14, which is what the format uses to say
    /// so and what this product's file classification already tests. It is
    /// deliberately not "and the metadata is readable": a file whose CLI header
    /// is present but damaged *is* a .NET file — that is what the header says —
    /// and answering `false` would make every rule gated on this member skip a
    /// file whose tables the next rule would have read.
    pub fn is_dotnet(&self) -> bool {
        self.present
    }

    /// The runtime version string, without its terminator.
    pub fn version(&self) -> Option<&'a [u8]> {
        self.version
    }

    /// The assembly's name and version, or `None` for a module with no
    /// `Assembly` row.
    pub fn assembly(&self) -> Option<(&'a [u8], AssemblyVersion)> {
        self.assembly
    }

    /// The referenced assemblies, in table order.
    pub fn assembly_refs(&self) -> &[AssemblyRef<'a>] {
        &self.assembly_refs
    }

    /// How many `ManifestResource` rows there are — what
    /// `dotnet.number_of_resources` answers.
    ///
    /// Rows, not embedded resources. Five of `mscorlib.dll`'s eight are linked
    /// to other files and still counted, because the number a rule compares
    /// against is a count of what the assembly *declares*, and a reader that
    /// counted only the embedded ones would disagree with the table the number
    /// comes from.
    pub fn number_of_resources(&self) -> usize {
        self.resources.len()
    }

    /// The manifest resources, in table order.
    pub fn resources(&self) -> &[DotNetResource<'a>] {
        &self.resources
    }
}

/// Read the CLI header and the tables behind it.
///
/// Never fails. A file that is not managed, one whose CLI header is unreadable,
/// and one whose metadata root is missing all yield an empty [`DotNet`], because
/// the caller is a rule asking a question and not a loader deciding whether to
/// run the file.
pub fn read<'a>(pe: &PeFile<'a>) -> DotNet<'a> {
    let entry = pe.data_directory(directory::COM_DESCRIPTOR);
    if !entry.is_present() {
        return DotNet::default();
    }
    let mut found = DotNet {
        present: true,
        ..DotNet::default()
    };

    // The RVA is mapped with `rva_to_offset`, which returns an unmapped address
    // unchanged. That is the crate's documented behaviour and is what lets a
    // packed image whose section table lies about the CLI header still be read —
    // and it is safe here because nothing below trusts the result: the metadata
    // root has to begin with `BSJB`, the stream headers have to name streams
    // that fit, and the tables have to be arithmetically consistent. A wrong
    // offset fails one of those long before it produces a name.
    let Some(header) = header_at(pe, entry.virtual_address) else {
        return found;
    };
    found.version = metadata_version(pe, header);
    found.assembly_refs = assembly_refs(pe, header);
    found.resources = resources(pe, header);
    found.assembly = assembly(pe, header);
    found
}

/// The CLI header's first [`CLI_HEADER_LEN`] bytes.
fn header_at<'a>(pe: &PeFile<'a>, rva: u32) -> Option<&'a [u8]> {
    let at = usize::try_from(pe.rva_to_offset(rva)).ok()?;
    let reader = Reader::new(pe.data());
    // `cb` first: a file whose own header says it is shorter than the structure
    // being read is not one to read the rest of, and this is the field the
    // format provides for saying so.
    let size = reader.u32(at + cli::SIZE).ok()?;
    if usize::try_from(size).ok()? < CLI_HEADER_LEN {
        return None;
    }
    reader.slice(at, CLI_HEADER_LEN).ok()
}

/// A directory field of the CLI header: the RVA, the size, and the bytes.
fn directory_of<'a>(pe: &PeFile<'a>, header: &[u8], field: usize) -> Option<(u32, u32, &'a [u8])> {
    let bytes = header.get(field..field + 8)?;
    let rva = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if rva == 0 || size == 0 {
        return None;
    }
    let at = usize::try_from(pe.rva_to_offset(rva)).ok()?;
    let size = usize::try_from(size).ok()?;
    let data = Reader::new(pe.data()).slice(at, size).ok()?;
    Some((rva, size as u32, data))
}

/// The metadata root, with its stream headers already resolved.
struct Metadata<'a> {
    /// The root and every stream, as one slice from the root onwards.
    ///
    /// One buffer rather than one per stream because every stream's offset is
    /// relative to the root: keeping them together is what makes
    /// [`Metadata::stream`] a subtraction instead of a second mapping.
    data: &'a [u8],
    /// The runtime version string.
    version: &'a [u8],
    /// The stream headers: offset within `data`, size, and name.
    streams: Vec<(usize, usize, &'a [u8])>,
}

impl<'a> Metadata<'a> {
    /// Parse the root at `data`, which starts at the `BSJB` signature.
    fn parse(data: &'a [u8]) -> Option<Self> {
        let reader = Reader::new(data);
        if reader.u32(root::SIGNATURE).ok()? != METADATA_SIGNATURE {
            return None;
        }
        let version_length = usize::try_from(reader.u32(root::VERSION_LENGTH).ok()?).ok()?;
        let version = reader.cstr(root::VERSION, version_length).ok()?;

        // The version string is padded to a four-byte boundary, which is where
        // the stream count is rather than at a fixed offset.
        let padded = version_length.checked_add(3)? / 4 * 4;
        let counts = root::VERSION.checked_add(padded)?;
        let (flags, count) = (reader.u16(counts).ok()?, reader.u16(counts + 2).ok()?);
        // `Flags` is a reserved field that is documented as zero. Read so that a
        // future reader can see it was considered, not checked because nothing
        // in the format assigns it a meaning.
        let _ = flags;

        let mut at = counts.checked_add(root::FLAGS_AND_STREAMS)?;
        let mut streams = Vec::new();
        for _ in 0..count {
            let offset = usize::try_from(reader.u32(at).ok()?).ok()?;
            let size = usize::try_from(reader.u32(at + 4).ok()?).ok()?;
            // A stream's name is NUL-terminated and the next header begins at
            // the following four-byte boundary, so the name is read to its
            // terminator and then rounded up.
            let name_at = at.checked_add(8)?;
            let terminator = data
                .get(name_at..)?
                .iter()
                .position(|&b| b == 0)?
                .checked_add(name_at)?;
            let name = data.get(name_at..terminator)?;
            at = terminator.checked_add(1)?.div_ceil(4).checked_mul(4)?;
            streams.push((offset, size, name));
        }

        Some(Metadata {
            data,
            version,
            streams,
        })
    }

    /// The bytes of the stream named `name`, if it is there and inside the root.
    fn stream(&self, name: &[u8]) -> Option<&'a [u8]> {
        let (offset, size, _) = self
            .streams
            .iter()
            .find(|(_, _, candidate)| *candidate == name)?;
        self.data.get(*offset..offset.checked_add(*size)?)
    }
}

/// The metadata root this CLI header points at.
fn metadata<'a>(pe: &PeFile<'a>, header: &[u8]) -> Option<Metadata<'a>> {
    let (_, _, data) = directory_of(pe, header, cli::METADATA)?;
    Metadata::parse(data)
}

/// The runtime version string.
fn metadata_version<'a>(pe: &PeFile<'a>, header: &[u8]) -> Option<&'a [u8]> {
    Some(metadata(pe, header)?.version)
}

/// The `#~` stream, with the `#Strings` heap to resolve names against.
fn tables<'a>(pe: &PeFile<'a>, header: &[u8]) -> Option<(Tables<'a>, Strings<'a>)> {
    let metadata = metadata(pe, header)?;
    // `#-` is the uncompressed form of the same stream, which the format allows
    // for images that are edited in place. Read the same way; a file with both
    // is malformed and the compressed one wins, as a loader's would.
    let stream = metadata.stream(b"#~").or_else(|| metadata.stream(b"#-"))?;
    let tables = Tables::read(stream)?;
    let strings = Strings {
        bytes: metadata.stream(b"#Strings").unwrap_or(&[]),
    };
    Some((tables, strings))
}

/// The `Assembly` table's single row.
fn assembly<'a>(pe: &PeFile<'a>, header: &[u8]) -> Option<(&'a [u8], AssemblyVersion)> {
    let (tables, strings) = tables(pe, header)?;
    // One row by definition: an assembly has exactly one identity, and a file
    // whose table has more is malformed. The first row is the one a loader
    // reads, so it is the one a rule is answered with.
    if tables.rows[usize::from(table::ASSEMBLY)] == 0 {
        return None;
    }
    let id = table::ASSEMBLY;
    let name = strings.get(tables.field(id, 0, 7)?);
    Some((name, version_at(&tables, id, 0, 1)))
}

/// The four `u16` version fields of a row, starting at `column`.
fn version_at(tables: &Tables<'_>, table: u8, row: u32, column: usize) -> AssemblyVersion {
    let field = |index: usize| -> u16 {
        tables
            .field(table, row, column + index)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(0)
    };
    AssemblyVersion {
        major: field(0),
        minor: field(1),
        build: field(2),
        revision: field(3),
    }
}

/// The `AssemblyRef` table.
fn assembly_refs<'a>(pe: &PeFile<'a>, header: &[u8]) -> Vec<AssemblyRef<'a>> {
    let Some((tables, strings)) = tables(pe, header) else {
        return Vec::new();
    };
    let id = table::ASSEMBLY_REF;
    let count = tables.rows[usize::from(id)];
    let mut refs = Vec::new();
    for row in 0..count {
        // The name is column 6 and the version columns 0 to 3, per the schema
        // above. A row whose bytes are not there stops the walk rather than
        // yielding a reference with an empty name, because a truncated table is
        // a table whose remaining rows are not readable either.
        let Some(index) = tables.field(id, row, 6) else {
            break;
        };
        refs.push(AssemblyRef {
            name: strings.get(index),
            version: version_at(&tables, id, row, 0),
        });
    }
    refs
}

/// The `ManifestResource` table, with each embedded resource's length resolved
/// against the CLI header's Resources data area.
fn resources<'a>(pe: &PeFile<'a>, header: &[u8]) -> Vec<DotNetResource<'a>> {
    let Some((tables, strings)) = tables(pe, header) else {
        return Vec::new();
    };
    // The data area is optional in the sense that a file with no embedded
    // resources has no reason to have one, so its absence is not an error: the
    // names and the count still come from the table.
    let area = directory_of(pe, header, cli::RESOURCES);

    let id = table::MANIFEST_RESOURCE;
    let count = tables.rows[usize::from(id)];
    let mut found = Vec::new();
    for row in 0..count {
        let (Some(relative), Some(index)) = (tables.field(id, row, 0), tables.field(id, row, 2))
        else {
            break;
        };
        let name = strings.get(index);
        // A non-zero `Implementation` means the resource is *linked* — it lives
        // in another file — and then the offset field is zero and says nothing.
        // Five of `mscorlib.dll`'s eight resources are linked, and reporting the
        // field for them would answer all five with the length of whichever
        // resource is first in the data area.
        let linked = tables.field(id, row, 3).unwrap_or(0) != 0;
        let (offset, length) = match (linked, area) {
            (false, Some((rva, _, data))) => {
                // The row's field is relative to the data area, and the area is
                // addressed by an RVA, so the offset a rule is given is the two
                // added together: an offset it can read the file at, which is
                // what a rule comparing it against another file offset means.
                // Left relative it would be a number that agrees with the file
                // only when the resources happen to be the first thing in it.
                let base = pe.rva_to_offset(rva);
                let (offset, length) = resource_at(relative, data);
                (offset.map(|at| at.saturating_add(base)), length)
            }
            _ => (None, None),
        };
        found.push(DotNetResource {
            name,
            offset,
            length,
        });
    }
    found
}

/// One resource's data offset and length, from the length prefix in the data
/// area.
///
/// Returns `(None, None)` when the prefix is not readable. A resource whose
/// declared offset runs past the data area is a file that lied about where its
/// resources are, and the honest answer is that the length is unknown rather
/// than that it is the bytes of something else.
fn resource_at(relative: u64, area: &[u8]) -> (Option<u64>, Option<u32>) {
    // Every step below can fail, and every failure answers the same way, so the
    // work is done in a closure returning `Option` and flattened once rather
    // than with six early returns that each have to be kept in step.
    let found = (|| {
        let relative = usize::try_from(relative).ok()?;
        let prefix = area.get(relative..relative.checked_add(4)?)?;
        let length = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        let data_at = relative.checked_add(4)?;
        // The data has to be inside the area. A length that runs past the end is
        // a file whose own two fields disagree, and the honest answer is that
        // the length is unknown rather than a number no byte in the file
        // supports — a rule comparing it would otherwise be comparing the size
        // of whatever the area happens to be followed by.
        let end = data_at.checked_add(usize::try_from(length).ok()?)?;
        if end > area.len() {
            return None;
        }
        Some((data_at as u64, length))
    })();
    match found {
        Some((offset, length)) => (Some(offset), Some(length)),
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{add_dotnet, minimal_pe32, DotNetSpec, ExtraTable};
    use crate::PeFile;

    /// Parse a fixture and read its managed structures.
    ///
    /// The `PeFile` is dropped at the end of this function and the [`DotNet`]
    /// that comes back borrows the *file*, not the parse of it, which is why
    /// that is allowed.
    fn managed(data: &[u8]) -> DotNet<'_> {
        let pe = PeFile::parse(data).expect("the fixture must be a PE");
        read(&pe)
    }

    /// The name and version of every reference, as a rule would see them.
    fn references<'a>(dotnet: &DotNet<'a>) -> Vec<(&'a str, AssemblyVersion)> {
        dotnet
            .assembly_refs()
            .iter()
            .map(|reference| {
                (
                    std::str::from_utf8(reference.name).expect("a name"),
                    reference.version,
                )
            })
            .collect()
    }

    /// A `#~` stream carrying nothing but a header and the row counts the caller
    /// names, for the tests that are about widths rather than about tables.
    ///
    /// Built here rather than through the fixture builder because the point of
    /// these tests is a header the builder has no way to produce: one whose
    /// `HeapSizes` is set, or whose row count crosses 65,536.
    fn stream(heap_sizes: u8, tables: &[(u8, u32)]) -> Vec<u8> {
        // Sorted by id, because that is the order the format writes the counts
        // in — the reader walks the valid bits in id order and pairs each with
        // the next count, so a helper that kept the caller's order would build a
        // header whose tables have each other's row counts.
        let mut tables = tables.to_vec();
        tables.sort_by_key(|(id, _)| *id);

        let mut valid = 0u64;
        let mut counts = Vec::new();
        for (id, rows) in &tables {
            valid |= 1u64 << id;
            counts.extend_from_slice(&rows.to_le_bytes());
        }
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        data.push(2); // MajorVersion
        data.push(0); // MinorVersion
        data.push(heap_sizes);
        data.push(1); // Reserved
        data.extend_from_slice(&valid.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes()); // Sorted
        data.extend_from_slice(&counts);
        data
    }

    #[test]
    fn a_file_that_is_not_managed_reports_nothing() {
        let data = minimal_pe32();
        let dotnet = managed(&data);
        assert!(
            !dotnet.is_dotnet(),
            "a fixture with no CLI header is not managed"
        );
        assert_eq!(dotnet.version(), None);
        assert_eq!(dotnet.assembly(), None);
        assert_eq!(dotnet.number_of_resources(), 0);
        assert!(dotnet.assembly_refs().is_empty());
        assert!(dotnet.resources().is_empty());
    }

    #[test]
    fn an_unreadable_cli_header_still_makes_the_file_managed() {
        // A `cb` of four bytes: the header exists, so the file is managed, and
        // nothing behind it can be read. Both halves matter — a reader that
        // answered `false` here would skip a file whose tables the next rule
        // would have read.
        let mut data = minimal_pe32();
        let layout = add_dotnet(&mut data, &DotNetSpec::new("v4.0.30319"));
        data[layout.cli_header..layout.cli_header + 4].copy_from_slice(&4u32.to_le_bytes());
        let dotnet = managed(&data);
        assert!(dotnet.is_dotnet());
        assert_eq!(dotnet.version(), None);
        assert_eq!(dotnet.assembly(), None);
    }

    #[test]
    fn a_metadata_root_without_the_signature_is_not_read() {
        let mut data = minimal_pe32();
        let layout = add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319").assembly("Example", [2, 1, 0, 0]),
        );
        data[layout.metadata..layout.metadata + 4].copy_from_slice(b"XXXX");
        let dotnet = managed(&data);
        assert!(dotnet.is_dotnet(), "the CLI header is still there");
        assert_eq!(dotnet.version(), None);
        assert_eq!(dotnet.assembly(), None, "the tables are behind the root");
    }

    #[test]
    fn the_runtime_version_is_the_string_from_the_metadata_root() {
        // The corpus's `dotnet.version == "v4.0.30319"` is a string comparison
        // against this, leading `v` included. A reader that stripped the `v`
        // would never match, and the rule that asks would never fire.
        let mut data = minimal_pe32();
        add_dotnet(&mut data, &DotNetSpec::new("v4.0.30319"));
        assert_eq!(managed(&data).version(), Some(&b"v4.0.30319"[..]));
    }

    #[test]
    fn a_version_of_a_length_that_needs_padding_is_terminated() {
        // Ten characters and a terminator is eleven bytes, so the field is
        // padded to twelve and the NUL is not the last byte of the string. A
        // reader that read the field's whole length as the string would report
        // the terminator and the padding as part of the version.
        let mut data = minimal_pe32();
        add_dotnet(&mut data, &DotNetSpec::new("v2.0.5072"));
        assert_eq!(managed(&data).version(), Some(&b"v2.0.5072"[..]));
    }

    #[test]
    fn the_assembly_row_gives_a_name_and_four_version_numbers() {
        let mut data = minimal_pe32();
        add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319").assembly("Example.Library", [2, 1, 3, 4]),
        );
        let dotnet = managed(&data);
        let (name, version) = dotnet.assembly().expect("an assembly row");
        assert_eq!(name, b"Example.Library");
        assert_eq!(
            version,
            AssemblyVersion {
                major: 2,
                minor: 1,
                build: 3,
                revision: 4,
            }
        );
    }

    #[test]
    fn a_module_with_no_assembly_row_has_no_assembly() {
        // `.netmodule` files are managed and are not assemblies. Answering with
        // an empty name would make `dotnet.assembly.name == "..."` fire on a
        // file that has no such name.
        let mut data = minimal_pe32();
        add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319").reference("mscorlib", [4, 0, 0, 0]),
        );
        let dotnet = managed(&data);
        assert!(dotnet.is_dotnet());
        assert_eq!(dotnet.assembly(), None);
        assert_eq!(references(&dotnet).len(), 1, "the refs are still there");
    }

    #[test]
    fn assembly_references_come_back_in_table_order() {
        // The corpus has `dotnet.assembly_refs[1].name contains "protobuf-net"`.
        // An index into this member is an index into the table, so the order the
        // reader reports is the whole of what makes that rule mean anything.
        let mut data = minimal_pe32();
        add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319")
                .assembly("Example", [1, 0, 0, 0])
                .reference("mscorlib", [4, 0, 0, 0])
                .reference("protobuf-net", [2, 4, 6, 0])
                .reference("System.Xml", [4, 0, 0, 0]),
        );
        let found = references(&managed(&data));
        assert_eq!(
            found,
            vec![
                (
                    "mscorlib",
                    AssemblyVersion {
                        major: 4,
                        minor: 0,
                        build: 0,
                        revision: 0,
                    }
                ),
                (
                    "protobuf-net",
                    AssemblyVersion {
                        major: 2,
                        minor: 4,
                        build: 6,
                        revision: 0,
                    }
                ),
                (
                    "System.Xml",
                    AssemblyVersion {
                        major: 4,
                        minor: 0,
                        build: 0,
                        revision: 0,
                    }
                ),
            ]
        );
    }

    #[test]
    fn a_manifest_resource_reports_the_length_of_its_prefix() {
        // The corpus has `dotnet.resources[0].length > 300KB`, and the field in
        // the file is an offset to a four-byte length followed by the bytes.
        // Measured against three real assemblies rather than assumed: the `u32`
        // at the row's `Offset` *is* the length, and the data starts four bytes
        // past it.
        let payload = vec![0xABu8; 4_000];
        let mut data = minimal_pe32();
        let layout = add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319")
                .assembly("Example", [1, 0, 0, 0])
                .resource("Example.data", &payload),
        );
        let dotnet = managed(&data);
        assert_eq!(dotnet.number_of_resources(), 1);
        let resource = dotnet.resources()[0];
        assert_eq!(resource.name, b"Example.data");
        assert_eq!(resource.length, Some(4_000));
        // The offset is where the *bytes* are, so the file at that offset holds
        // the payload and the four bytes before it hold the length.
        let at = usize::try_from(resource.offset.expect("an offset")).expect("fits");
        assert_eq!(data[at..at + 4_000], payload[..]);
        assert_eq!(
            &data[at - 4..at],
            &4_000u32.to_le_bytes()[..],
            "the length is the four bytes before the offset"
        );
        assert!(at > layout.resources, "and it is inside the resources area");
    }

    #[test]
    fn a_linked_resource_has_neither_offset_nor_length() {
        // The false positive this reader was rewritten to avoid. A linked
        // resource's `Offset` is zero and means nothing — real assemblies write
        // zero there — so a reader that reported the field would answer a rule
        // about `length` with whatever blob happens to begin the resources area.
        // Measured: all five of `mscorlib.dll`'s linked resources carry zero,
        // and a reader reporting the field gave all five the same 353,031.
        let mut data = minimal_pe32();
        add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319")
                .assembly("Example", [1, 0, 0, 0])
                .resource("Example.embedded", &[7u8; 64])
                .linked_resource("Example.linked"),
        );
        let dotnet = managed(&data);
        assert_eq!(dotnet.number_of_resources(), 2, "rows, not embedded ones");
        assert_eq!(dotnet.resources()[0].length, Some(64));
        let linked = dotnet.resources()[1];
        assert_eq!(linked.name, b"Example.linked");
        assert_eq!(linked.offset, None);
        assert_eq!(linked.length, None);
    }

    #[test]
    fn resources_are_reported_in_table_order_with_their_own_lengths() {
        // Three resources of different sizes, one linked, so that a reader that
        // walked the area by accumulating lengths instead of following each
        // row's offset would report the wrong one for at least one of them.
        let mut data = minimal_pe32();
        add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319")
                .assembly("Example", [1, 0, 0, 0])
                .resource("first", &[1u8; 9])
                .linked_resource("second")
                .resource("third", &[3u8; 30]),
        );
        let dotnet = managed(&data);
        let found: Vec<(&[u8], Option<u32>)> = dotnet
            .resources()
            .iter()
            .map(|resource| (resource.name, resource.length))
            .collect();
        assert_eq!(
            found,
            vec![
                (&b"first"[..], Some(9)),
                (&b"second"[..], None),
                (&b"third"[..], Some(30)),
            ]
        );
    }

    #[test]
    fn the_embedded_lengths_reconcile_with_the_resources_directory() {
        // The check that caught a wrong column width in the table schema when it
        // was written: every embedded resource is a four-byte length and its
        // bytes, so the sum of `length + 4` over the embedded rows *is* the size
        // of the data area the CLI header points at, up to the padding that
        // aligns each blob. Measured on three real assemblies: 217,809 of
        // 217,840; 1,002,799 of 1,002,808; 78,449 of 78,456.
        //
        // A wrong width anywhere in the schema moves the `ManifestResource`
        // rows, and the offsets that come back no longer sum to the directory's
        // size. That is why this is a test and not a comment.
        let mut data = minimal_pe32();
        add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319")
                .assembly("Example", [1, 0, 0, 0])
                .resource("a", &[1u8; 5])
                .resource("bb", &[2u8; 11])
                .linked_resource("ccc")
                .resource("dddd", &[4u8; 32]),
        );
        let dotnet = managed(&data);
        let embedded: u64 = dotnet
            .resources()
            .iter()
            .filter_map(|resource| resource.length)
            .map(|length| u64::from(length) + 4)
            .sum();
        assert_eq!(embedded, (4 + 5) + (4 + 11) + (4 + 32));

        // The directory's own size, read straight out of the CLI header rather
        // than out of the reader being tested: a field of the fixture, at the
        // offset the format puts it at.
        let pe = PeFile::parse(&data).expect("the fixture must be a PE");
        let at =
            usize::try_from(pe.rva_to_offset(pe.data_directory(14).virtual_address)).expect("fits");
        let directory = &data[at + 24..at + 32];
        let size = u32::from_le_bytes([directory[4], directory[5], directory[6], directory[7]]);
        // Five bytes, eleven and thirty-two: each blob is its four-byte length
        // and its bytes, padded to the next eight-byte boundary, and the three
        // boundaries are at 9 → 16, 16+15 = 31 → 32, and 32+36 = 68 → 72.
        assert_eq!(embedded, 5 + 4 + 11 + 4 + 32 + 4);
        assert_eq!(
            size, 72,
            "nine to sixteen, thirty-one to thirty-two, sixty-eight to seventy-two"
        );

        // And the invariant those two numbers are an instance of: the data area
        // is never smaller than the blobs and never larger than the blobs padded.
        let padded: u64 = dotnet
            .resources()
            .iter()
            .filter_map(|resource| resource.length)
            .map(|length| (u64::from(length) + 4).div_ceil(8) * 8)
            .sum();
        assert!(embedded <= u64::from(size) && u64::from(size) <= padded);
    }

    #[test]
    fn a_table_before_the_ones_being_read_is_stepped_over() {
        // The reader has to measure every table that precedes `ManifestResource`
        // to find it, because the format writes no index. `extra_tables` states
        // each row's width independently of the reader — so if the reader
        // computed one of these widths differently the rows move and the
        // resource names come back as rubbish from the wrong heap offsets.
        //
        // The widths are ECMA-335 II.22: `MethodDef` is 4+2+2+2+2 = 14 bytes
        // with the two-byte indices this fixture writes, `Field` is
        // 2+2+2 = 6, `ModuleRef` and `TypeSpec` are one index each.
        let mut data = minimal_pe32();
        add_dotnet(
            &mut data,
            &DotNetSpec::new("v4.0.30319")
                .assembly("Example", [1, 0, 0, 0])
                .extra_table(ExtraTable::new(0x06, 300, 14)) // MethodDef
                .extra_table(ExtraTable::new(0x1A, 40, 2)) // ModuleRef
                .extra_table(ExtraTable::new(0x1B, 7, 2)) // TypeSpec
                .extra_table(ExtraTable::new(0x04, 500, 6)) // Field
                .reference("mscorlib", [4, 0, 0, 0])
                .resource("Example.data", &[9u8; 100]),
        );
        let dotnet = managed(&data);
        assert_eq!(dotnet.version(), Some(&b"v4.0.30319"[..]));
        let (name, _) = dotnet.assembly().expect("an assembly row");
        assert_eq!(name, b"Example");
        assert_eq!(
            references(&dotnet),
            vec![(
                "mscorlib",
                AssemblyVersion {
                    major: 4,
                    minor: 0,
                    build: 0,
                    revision: 0,
                }
            )]
        );
        assert_eq!(dotnet.resources()[0].name, b"Example.data");
        assert_eq!(dotnet.resources()[0].length, Some(100));
    }

    #[test]
    fn a_heap_index_is_four_bytes_only_when_the_heap_says_so() {
        let narrow_bytes = stream(0, &[(0x28, 1)]);
        let narrow = Tables::read(&narrow_bytes).expect("a readable header");
        assert_eq!(narrow.width(Column::String), Some(2));
        assert_eq!(narrow.width(Column::Blob), Some(2));

        // Bit zero is `#Strings`, bit two is `#Blob`; `#GUID` is bit one and is
        // deliberately left clear, so a reader that read one flag for all three
        // heaps fails here.
        let wide_bytes = stream(0b101, &[(0x28, 1)]);
        let wide = Tables::read(&wide_bytes).expect("a readable header");
        assert_eq!(wide.width(Column::String), Some(4));
        assert_eq!(wide.width(Column::Blob), Some(4));
        assert_eq!(wide.width(Column::Guid), Some(2), "bit one is clear");
    }

    #[test]
    fn a_table_index_is_two_bytes_until_the_table_is_full() {
        // 65,535 rows fit in two bytes and 65,536 do not, and the threshold is
        // the count rather than the largest row number — a compiler that chose
        // four bytes and a reader that chose two would disagree about where
        // every following row starts.
        let edge_bytes = stream(0, &[(0x28, 1), (0x02, 65_535)]);
        let edge = Tables::read(&edge_bytes).expect("a readable header");
        assert_eq!(edge.width(Column::Table(0x02)), Some(2));

        let over_bytes = stream(0, &[(0x28, 1), (0x02, 65_536)]);
        let over = Tables::read(&over_bytes).expect("a readable header");
        assert_eq!(over.width(Column::Table(0x02)), Some(4));
    }

    #[test]
    fn a_coded_index_widens_a_step_before_the_table_it_names() {
        // The tag shares the two bytes, so `Implementation` — two tag bits,
        // naming `File`, `AssemblyRef` and `ExportedType` — fits only while the
        // largest of those has fewer than 2^14 rows. ECMA-335 II.24.2.6 puts the
        // threshold on the row count, which is what a compiler used, and not on
        // the largest value that could be encoded, which would be one further.
        let under_bytes = stream(0, &[(0x28, 1), (0x26, 16_383)]);
        let under = Tables::read(&under_bytes).expect("a readable header");
        assert_eq!(
            under.width(Column::Coded(CodedIndex::Implementation)),
            Some(2)
        );

        let edge_bytes = stream(0, &[(0x28, 1), (0x26, 16_384)]);
        let edge = Tables::read(&edge_bytes).expect("a readable header");
        assert_eq!(
            edge.width(Column::Coded(CodedIndex::Implementation)),
            Some(4)
        );

        // And it is a maximum over the tables it can name, not the first of
        // them: `AssemblyRef` is large here while `File` has no rows at all.
        let other_bytes = stream(0, &[(0x28, 1), (0x23, 40_000)]);
        let other = Tables::read(&other_bytes).expect("a readable header");
        assert_eq!(
            other.width(Column::Coded(CodedIndex::Implementation)),
            Some(4)
        );
    }

    #[test]
    fn a_table_the_file_does_not_have_has_no_rows_rather_than_failing() {
        // An assembly with no resources at all is the common case, and it is a
        // bit that is clear in `Valid` rather than a row count of zero.
        let bytes = stream(0, &[(0x20, 1)]);
        let tables = Tables::read(&bytes).expect("a readable header");
        assert_eq!(tables.rows[usize::from(table::MANIFEST_RESOURCE)], 0);
        assert_eq!(tables.at[usize::from(table::MANIFEST_RESOURCE)], None);
        assert_eq!(tables.rows[usize::from(table::ASSEMBLY)], 1);
    }

    #[test]
    fn a_stream_too_short_for_its_row_counts_is_not_read() {
        // `Valid` says two tables are present and the stream holds no counts at
        // all. Answering with an empty table set is the same answer as a file
        // with nothing in it, and is the only safe one: the alternative is
        // reading whatever bytes follow as a row count.
        let mut data = stream(0, &[]);
        data[8..16].copy_from_slice(&0b11u64.to_le_bytes());
        assert!(Tables::read(&data).is_none());
    }

    #[test]
    fn a_string_index_past_the_end_of_the_heap_is_empty_rather_than_invented() {
        // A name a rule cannot match is a rule that does not fire; a name made
        // out of whatever follows the heap is a rule that fires on the wrong
        // file. Only the first is acceptable.
        let heap = Strings { bytes: b"\0abc\0" };
        assert_eq!(heap.get(0), b"");
        assert_eq!(heap.get(1), b"abc");
        assert_eq!(heap.get(4), b"");
        assert_eq!(heap.get(9_000), b"");
        assert_eq!(Strings::default().get(1), b"");
    }
}

/// The real-assembly checks, which are opt-in because they read files that only
/// exist on a machine with the .NET Framework installed.
///
/// ```text
/// cargo test -p av-pe -- --ignored
/// ```
///
/// They are `#[ignore]`d rather than skipped-when-missing on purpose. A test
/// that quietly passes when the file it reads is not there reports success for
/// having read nothing, and these are the only checks in the crate that run the
/// reader over bytes a compiler wrote rather than bytes a fixture wrote.
#[cfg(test)]
mod real_files {
    use crate::dotnet::{read, DotNet};
    use crate::PeFile;
    use std::path::{Path, PathBuf};

    /// Where the 64-bit .NET Framework 4 assemblies live.
    const FRAMEWORK: &str = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319";

    /// The resource names, as strings.
    fn names(dotnet: &DotNet<'_>) -> Vec<String> {
        dotnet
            .resources()
            .iter()
            .map(|resource| String::from_utf8_lossy(resource.name).into_owned())
            .collect()
    }

    /// The CLI header's Resources directory: where it is, and how big the data
    /// area it covers is.
    ///
    /// Read from the header rather than from the reader under test, so that the
    /// number the lengths are reconciled against is not one this crate produced.
    fn resources_directory(bytes: &[u8]) -> (usize, u32) {
        let pe = PeFile::parse(bytes).expect("a PE");
        let entry = pe.data_directory(14);
        let at = pe.rva_to_offset(entry.virtual_address) as usize;
        let field = &bytes[at + 24..at + 32];
        (
            at,
            u32::from_le_bytes([field[4], field[5], field[6], field[7]]),
        )
    }

    /// Every embedded resource's `length` and its four-byte prefix, which is
    /// what the data area has to account for.
    fn embedded_bytes(dotnet: &DotNet<'_>) -> u64 {
        dotnet
            .resources()
            .iter()
            .filter_map(|resource| resource.length)
            .map(|length| u64::from(length) + 4)
            .sum()
    }

    /// How many resources are embedded rather than linked.
    fn embedded_count(dotnet: &DotNet<'_>) -> usize {
        dotnet
            .resources()
            .iter()
            .filter(|resource| resource.length.is_some())
            .count()
    }

    /// The next multiple of eight.
    ///
    /// The data area's blobs start on eight-byte boundaries, not four: measured
    /// on `System.dll`, whose bitmap resources are 824 bytes each and sit 832
    /// apart, and on `mscorlib.dll`, whose first two resources end at 353,035
    /// and 390,036 and are followed by blobs at 353,040 and 390,040. Four-byte
    /// alignment would leave a one-byte and a four-byte gap instead of a
    /// five-byte and a four-byte one, and the totals would not come out.
    fn align8(value: u64) -> u64 {
        value.div_ceil(8) * 8
    }

    /// What the data area would be if every blob were padded to the next
    /// eight-byte boundary. The real size is between this and the un-padded sum.
    fn padded_bytes(dotnet: &DotNet<'_>) -> u64 {
        dotnet
            .resources()
            .iter()
            .filter_map(|resource| resource.length)
            .map(|length| align8(u64::from(length) + 4))
            .sum()
    }

    #[test]
    #[ignore = "reads the installed .NET Framework assemblies"]
    fn mscorlib_answers_exactly_what_an_independent_reader_says() {
        // The numbers below came from `target/probe_dotnet.py`, a reader written
        // from the ECMA-335 tables rather than from the Rust, so agreeing with
        // them is evidence about the format and not about this code agreeing
        // with itself.
        let path = Path::new(FRAMEWORK).join("mscorlib.dll");
        let bytes = std::fs::read(&path).expect("the .NET Framework must be installed");
        let pe = PeFile::parse(&bytes).expect("a PE");
        let dotnet = read(&pe);

        assert!(dotnet.is_dotnet());
        assert_eq!(dotnet.version(), Some(&b"v4.0.30319"[..]));
        let (name, version) = dotnet.assembly().expect("an assembly row");
        assert_eq!(name, b"mscorlib");
        assert_eq!(
            (
                version.major,
                version.minor,
                version.build,
                version.revision
            ),
            (4, 0, 0, 0)
        );
        assert!(
            dotnet.assembly_refs().is_empty(),
            "mscorlib references nothing"
        );

        assert_eq!(dotnet.number_of_resources(), 8);
        assert_eq!(
            names(&dotnet),
            vec![
                "normidna.nlp",
                "normnfc.nlp",
                "normnfd.nlp",
                "normnfkc.nlp",
                "normnfkd.nlp",
                "mscorlib.resources",
                "charinfo.nlp",
                "codepages.nlp",
            ]
        );
        // Five are linked to other files and have no length in this one. This is
        // the false positive the reader was rewritten to avoid: all five store
        // zero in their offset field, so a reader that reported the field would
        // hand every one of them the 353,031 bytes of the first *embedded*
        // resource — index 0 among them, which is what the corpus's
        // `dotnet.resources[0].length > 300KB` reads.
        let lengths: Vec<Option<u32>> = dotnet
            .resources()
            .iter()
            .map(|resource| resource.length)
            .collect();
        assert_eq!(
            lengths,
            vec![
                None,
                None,
                None,
                None,
                None,
                Some(353_031),
                Some(36_992),
                Some(612_764),
            ]
        );

        // And an offset is a file offset: the four bytes before it are that
        // resource's length prefix, which holds only if the data area's own
        // position has been added to the field.
        for resource in dotnet.resources().iter().filter(|r| r.length.is_some()) {
            let at = usize::try_from(resource.offset.expect("an offset")).expect("fits");
            let length = resource.length.expect("a length");
            assert_eq!(
                u32::from_le_bytes([bytes[at - 4], bytes[at - 3], bytes[at - 2], bytes[at - 1]]),
                length,
                "the prefix at {} must be the length that was reported",
                at - 4
            );
            assert!(
                at + usize::try_from(length).expect("fits") <= bytes.len(),
                "the bytes of a resource must be inside the file"
            );
        }
        // The first embedded one is a `.resources` blob, and those begin with
        // the magic the resource reader looks for. The other two are `.nlp`
        // tables, which begin with UTF-16 text, so this is asserted of the one
        // whose content the probe recorded and not as a rule about all three.
        let at = usize::try_from(dotnet.resources()[5].offset.expect("an offset")).expect("fits");
        assert_eq!(&bytes[at..at + 4], &[0xCE, 0xCA, 0xEF, 0xBE]);

        let (_, size) = resources_directory(&bytes);
        assert_eq!(embedded_bytes(&dotnet), 1_002_799);
        assert_eq!(size, 1_002_808);
        assert!(embedded_bytes(&dotnet) <= u64::from(size));
        assert!(u64::from(size) <= padded_bytes(&dotnet));
    }

    #[test]
    #[ignore = "reads the installed .NET Framework assemblies"]
    fn assembly_references_of_a_real_file_are_in_table_order() {
        let path = Path::new(FRAMEWORK).join("System.dll");
        let bytes = std::fs::read(&path).expect("the .NET Framework must be installed");
        let pe = PeFile::parse(&bytes).expect("a PE");
        let dotnet = read(&pe);

        let (name, version) = dotnet.assembly().expect("an assembly row");
        assert_eq!(name, b"System");
        assert_eq!((version.major, version.minor), (4, 0));

        // `dotnet.assembly_refs[1].name` is an index into this list. The probe
        // says the second row is `System.Configuration`; a reader that walked
        // the table backwards, or that read the names out of the heap in the
        // order they happen to appear there, would answer something else.
        let refs: Vec<String> = dotnet
            .assembly_refs()
            .iter()
            .map(|reference| String::from_utf8_lossy(reference.name).into_owned())
            .collect();
        assert_eq!(
            refs,
            vec!["mscorlib", "System.Configuration", "System.Xml"],
            "in table order"
        );

        assert_eq!(dotnet.number_of_resources(), 8);
        assert_eq!(embedded_count(&dotnet), 8, "all eight are embedded");
        let (_, size) = resources_directory(&bytes);
        assert_eq!(embedded_bytes(&dotnet), 217_809);
        assert_eq!(size, 217_840);
    }

    #[test]
    #[ignore = "reads the installed .NET Framework assemblies"]
    fn every_assembly_in_the_framework_reconciles() {
        // The same check as the two above, run over every assembly Microsoft
        // shipped, because one file agreeing with one measurement is a fact
        // about that file while a thousand agreeing is a fact about the reader.
        //
        // A wrong column width, a table laid out in the wrong order, a wrong
        // index-width rule — each of them moves the `ManifestResource` rows, and
        // the lengths that come back stop accounting for the data area the CLI
        // header declares. The shortfall is alignment padding, at most three
        // bytes per embedded resource, and nothing else.
        let directory = Path::new(FRAMEWORK);
        let mut assemblies: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("the .NET Framework must be installed; this test is opt-in")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "dll" || extension == "exe")
            })
            .collect();
        assemblies.sort();

        let mut managed = 0usize;
        let mut resources = 0usize;
        let mut embedded = 0usize;
        let mut linked = 0usize;
        let mut assemblies_with_resources = 0usize;
        for path in &assemblies {
            let bytes = std::fs::read(path).expect("readable");
            let Ok(pe) = PeFile::parse(&bytes) else {
                continue;
            };
            let dotnet = read(&pe);
            if !dotnet.is_dotnet() {
                continue;
            }
            managed += 1;
            if dotnet.number_of_resources() == 0 {
                continue;
            }
            assemblies_with_resources += 1;

            let (_, size) = resources_directory(&bytes);
            let size = u64::from(size);
            let accounted = embedded_bytes(&dotnet);
            let padded = padded_bytes(&dotnet);
            assert!(
                accounted <= size,
                "{}: the embedded resources account for {accounted} bytes of a {size}-byte area, \
                 which is more than is there",
                path.display()
            );
            assert!(
                size <= padded,
                "{}: the data area is {size} bytes but the embedded resources account for only \
                 {accounted}, and padding them to eight bytes reaches just {padded} — so some \
                 resource's offset or length is being read out of the wrong row",
                path.display()
            );
            resources += dotnet.number_of_resources();
            embedded += embedded_count(&dotnet);
            linked += dotnet.number_of_resources() - embedded_count(&dotnet);
        }

        println!(
            "{managed} managed assemblies of {}, {assemblies_with_resources} with resources, \
             {resources} manifest resources ({embedded} embedded, {linked} linked)",
            assemblies.len()
        );
        // Floors, so that a directory that came back nearly empty fails instead
        // of reporting a clean sweep of nothing.
        assert!(
            managed > 100,
            "only {managed} managed assemblies were found, so this test is not measuring what it \
             claims to"
        );
        assert!(
            assemblies_with_resources > 30,
            "only {assemblies_with_resources} assemblies with resources were found"
        );
        assert!(
            linked > 0,
            "some assembly must link a resource, or the linked path is untested here"
        );
    }
}
