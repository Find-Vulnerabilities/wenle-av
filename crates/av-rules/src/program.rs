//! The bytecode a compiled rule is made of.
//!
//! A rule's condition compiles to a straight-line program for a stack machine.
//! The alternative — keeping the AST and walking it — costs an indirect branch
//! and a `match` on a wide enum for every node, on every rule, for every file
//! scanned. Compiling to a flat instruction array instead means the interpreter
//! loop is one `match` on a small integer, the operands are already resolved
//! into indices, and the whole program is a contiguous allocation that can be
//! memory-mapped straight out of the rule database.
//!
//! # Shape of the machine
//!
//! Values live on a stack. Every opcode pops its operands and pushes its result,
//! so a compiler that emits `a`, then `b`, then `Add` has computed `a + b`.
//! Control flow is jumps over that same instruction array; there are no nested
//! scopes and no call stack, because a condition has neither.
//!
//! The one place this gets interesting is `and`/`or`, which must not evaluate
//! their right-hand side when the left already decides the answer — both because
//! that is what the language means and because the right-hand side is often the
//! expensive half (`pe.imphash() == "..." and $a`). Those compile to a jump over
//! the second operand, with both paths pushing exactly one boolean so the stack
//! height is the same either way.
//!
//! # Undefined
//!
//! [`Value::Undefined`] is a first-class value rather than an error, because
//! that is what the language means: `pe.entry_point` in a file with no entry
//! point is not zero, it is unknown, and every comparison against it is false.
//! Collapsing that into `0` would make `pe.entry_point == 0` fire on every
//! non-executable file — a false positive manufactured out of a missing field.

use av_core::HashKind;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::sync::Arc;

use crate::ast::Span;

/// How many times the loops in one rule may run between them, per file.
///
/// A `for` loop's bounds are runtime values — `pe.number_of_sections`,
/// `#a`, `filesize` — so the interpreter cannot know from the program how long
/// a loop will be, and a rule written as `for any i in (0..filesize)` would
/// otherwise run once per byte of every file scanned.
///
/// The budget is for the whole rule rather than for each loop, which is what
/// makes [`Program::max_steps`] a bound: every iteration anywhere in the
/// program is one of these. Exhausting it does not truncate a result — a
/// truncated `for all` would be *true* where the rule said otherwise, and a
/// false positive is the one thing this engine must not produce. The loop
/// yields undefined instead, which propagates as "unknown" and leaves the rule
/// unmatched. A detection that does not fire is a gap; a file deleted for the
/// wrong reason is not recoverable.
///
/// Sixty-five thousand is far past what the rule set asks for — the real loops
/// iterate a section count, a string's match count, or a small constant — and
/// small enough that the worst case a rule can cost per file is a few
/// hundred thousand instructions.
pub const MAX_LOOP_ITERATIONS: u32 = 65_536;

/// A value on the virtual machine's stack.
///
/// # Why the string case holds bytes
///
/// [`Value::Bytes`] is `Arc<[u8]>` and not `Arc<str>`, which is a decision worth
/// stating because the rule language calls the type a string.
///
/// Every string in this engine that did not come from a rule literal came out of
/// a file, and a file is bytes. A section name is eight arbitrary bytes; a
/// resource name is UTF-16; the decrypted Rich header — which the corpus hashes
/// with `hash.md5(pe.rich_signature.clear_data)` — is a run of dwords whose
/// bytes are whatever the linker wrote. Converting any of those through `str`
/// means `String::from_utf8_lossy`, which replaces every byte sequence that is
/// not UTF-8 with `U+FFFD`. For a comparison that is merely a detection that
/// never fires, but for a *hash* it is worse than that: the digest of the
/// lossily-converted bytes is a well-formed MD5 of the wrong input, so the rule
/// looks like it is working and the hash it publishes can never match.
///
/// So the representation is the honest one and the comparisons are byte
/// comparisons, which is what the language means by `==` on a string anyway.
///
/// The `Arc` is not about that: the interpreter hands the same constant out
/// repeatedly, and cloning an `Arc` is a refcount bump where cloning a `Vec`
/// would be an allocation per comparison.
///
/// # Why `Arc` and not `Rc`
///
/// Because a [`crate::database::RuleDatabase`] is read by every scanning thread
/// at once. An `Rc` anywhere inside a [`Program`] makes the whole database
/// `!Sync`, and the cost of that is not a slow scan — it is a scanner that
/// cannot be run on more than one core at all, discovered at the call site
/// where somebody finally tried. The atomic refcount is paid on every clone and
/// buys the thing the product is: a scan that uses the machine it is running
/// on. See `crates/av-cli/src/commands/scan.rs`, which is where that was found.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// The result of reading a field that does not exist for this file, or of
    /// any operation involving one. Behaves as "false" in a boolean context and
    /// makes every comparison false.
    Undefined,
    Int(i64),
    Float(f64),
    Bool(bool),
    /// A byte string. See the note above on why this is not `Arc<str>`.
    Bytes(Arc<[u8]>),
}

impl Value {
    /// Interpret the value as a condition result.
    ///
    /// Only `Undefined`, `false`, `0` and an empty string are false. Note that
    /// a float is compared against zero rather than truncated.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Undefined => false,
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Bytes(s) => !s.is_empty(),
        }
    }

    pub fn is_undefined(&self) -> bool {
        matches!(self, Value::Undefined)
    }

    /// Numeric view of the value, for arithmetic.
    ///
    /// A `Bool` converts (`true` is 1) because rules do write `uint16(0) + $a`,
    /// and the alternative is refusing to evaluate rather than picking the
    /// reading the author obviously meant.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Bytes(_) | Value::Undefined => None,
        }
    }

    /// Whether the value is an integer rather than a float.
    ///
    /// Integer arithmetic must stay in `i64`: rules compare `uint32(0)` against
    /// values with the top bit set, and routing that through `f64` loses the low
    /// bits and silently changes which files match.
    pub fn is_integer(&self) -> bool {
        matches!(self, Value::Int(_))
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Undefined => "undefined",
            Value::Int(_) => "integer",
            Value::Float(_) => "float",
            Value::Bool(_) => "boolean",
            Value::Bytes(_) => "string",
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Undefined => f.write_str("undefined"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::Bool(b) => write!(f, "{b}"),
            // A byte string is written as quoted text so that it is
            // distinguishable from a number in a message, and read lossily
            // because this is a diagnostic and not a value: a message that said
            // `[0x90, 0x00]` for a section name would be useless to the person
            // reading it, and nothing downstream parses this back.
            Value::Bytes(s) => write!(f, "\"{}\"", String::from_utf8_lossy(s)),
        }
    }
}

/// A constant in a program's pool.
///
/// `Op::Push` carries an index into this rather than the value, which keeps
/// every instruction the same small size whether it pushes `1` or a 4 KiB
/// string literal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Const {
    Bool(bool),
    Int(i64),
    Float(f64),
    /// A string literal from a rule, as bytes. See [`Value::Bytes`] for why the
    /// two are the same type.
    ///
    /// Serialised through the `shared_bytes` module rather than by turning on
    /// serde's `rc` feature: that feature would apply to every `Rc` and `Arc`
    /// in the workspace, which is a large change to make for one field, and it
    /// makes shared ownership silently serialisable in places where sharing is
    /// meaningless.
    ///
    /// The refcount is not written to the file and is not read back from it.
    /// Two rules that shared one literal in memory get two allocations when the
    /// database is loaded, which costs a few bytes per rule and keeps the
    /// on-disk format independent of a pointer's representation.
    #[serde(with = "shared_bytes")]
    Str(Arc<[u8]>),
}

/// Serde adapter for a reference-counted byte string.
///
/// It is written as a byte string and read back as one. The refcount is
/// deliberately not preserved: what comes back is a fresh `Arc` holding the same
/// bytes, which is what the interpreter wants and what makes the round-trip
/// test meaningful.
///
/// The read side goes through `Vec<u8>` rather than through a `&[u8]` borrowed
/// from the deserializer, because bincode's byte-string form and its `Vec<u8>`
/// form are the same encoding — a length prefix and then the raw bytes — and
/// the owned form is the one that can be stored in an `Arc` with no lifetime.
mod shared_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::sync::Arc;

    pub fn serialize<S: Serializer>(value: &Arc<[u8]>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Arc<[u8]>, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Arc::from(bytes.as_slice()))
    }
}

impl Const {
    pub fn to_value(&self) -> Value {
        match self {
            Const::Bool(b) => Value::Bool(*b),
            Const::Int(i) => Value::Int(*i),
            Const::Float(x) => Value::Float(*x),
            Const::Str(s) => Value::Bytes(Arc::clone(s)),
        }
    }
}

/// String predicates that compare two values as text.
///
/// Each gets its own opcode rather than a shared opcode with a modifier byte:
/// the interpreter dispatches on a single integer either way, and separate
/// opcodes keep the disassembly readable when a rule misbehaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Cmp {
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    IEquals,
}

impl Cmp {
    pub const fn as_str(self) -> &'static str {
        match self {
            Cmp::Contains => "contains",
            Cmp::IContains => "icontains",
            Cmp::StartsWith => "startswith",
            Cmp::IStartsWith => "istartswith",
            Cmp::EndsWith => "endswith",
            Cmp::IEndsWith => "iendswith",
            Cmp::IEquals => "iequals",
        }
    }
}

/// One bytecode instruction.
///
/// Kept to a single machine word so a program is a compact array. The payload of
/// every variant is an index or a small count — never a value — which is what
/// makes that possible with a data-carrying enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Op {
    /// Push `constants[0]`.
    Push(u32),

    /// `filesize` — the length of the buffer being scanned.
    Filesize,
    /// `entrypoint` — the entry point offset reported by the file-type layer.
    EntryPoint,

    /// `uint8(<offset>)` — pops the offset, pushes the byte there.
    ReadU8,
    /// `uint16(<offset>)` — pops the offset, pushes the little-endian word.
    ReadU16,
    /// `uint32(<offset>)`.
    ReadU32,
    /// `int8(<offset>)`.
    ReadI8,
    /// `int16(<offset>)`.
    ReadI16,
    /// `int32(<offset>)`.
    ReadI32,
    /// `uint16be(<offset>)` — big-endian.
    ReadU16Be,
    /// `uint32be(<offset>)`.
    ReadU32Be,
    /// `int16be(<offset>)`.
    ReadI16Be,
    /// `int32be(<offset>)`.
    ReadI32Be,

    /// `$a` — whether string 0 matched anywhere.
    StrMatch(u32),
    /// `#a` — how many times string 0 matched.
    StrCount(u32),
    /// `@a` — offset of the first match of string 0.
    StrOffsetFirst(u32),
    /// `@a[i]` — offset of the i-th match; pops the index.
    StrOffsetNth(u32),
    /// `!a` — length of the first match of string 0.
    StrLenFirst(u32),
    /// `!a[i]` — length of the i-th match; pops the index.
    StrLenNth(u32),
    /// `$a at <offset>` — pops the offset, pushes whether a match starts there.
    StrAt(u32),
    /// `$a in (<from>..<to>)` — pops `to` then `from`.
    StrIn(u32),

    /// `any of (...)` — pops `n` booleans.
    OfAny(u32),
    /// `all of (...)` — pops `n` booleans.
    OfAll(u32),
    /// `none of (...)` — pops `n` booleans.
    OfNone(u32),
    /// `<count> of (...)` — pops `n` booleans, then the required count.
    ///
    /// The required count is pushed first so that the string results, which the
    /// compiler emits as a run, stay contiguous on the stack.
    OfCount(u32),

    /// Logical negation; any type is accepted and read for truth.
    Not,
    /// Arithmetic negation.
    Negate,
    /// Bitwise complement; integers only.
    BitNot,
    /// `defined <expr>` — replaces a value with whether it is not `Undefined`.
    IsDefined,

    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,

    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,

    /// `a.contains(b)`, and each of the other [`Cmp`] predicates.
    Cmp(Cmp),

    /// `<string> matches /regex/` — pops the string, pushes whether the pattern
    /// is found in it.
    ///
    /// One operand rather than two, because the pattern is not a value: it is
    /// written into the rule as a literal, so it is compiled once and indexed
    /// by this opcode rather than pushed and matched at run time. The index is
    /// into [`Program::regexes`], and the pattern is compiled on first use —
    /// see [`RegexSpec`] for why it is not carried compiled.
    Matches(u32),

    /// Jump to `target` unconditionally.
    Jump(u32),
    /// Pop a value and jump to `target` if it is false.
    JumpIfFalse(u32),
    /// Pop a value and jump to `target` if it is true.
    JumpIfTrue(u32),

    /// `for <quant> <var> in (<from>..<to>) : ( ... )` — enter a loop.
    ///
    /// Pops `to`, then `from`. On a range with nothing in it the loop is over
    /// before it starts and this jumps straight to `done`, which is also where
    /// a loop that has finished arrives — so the code after the loop is written
    /// once and both paths reach it with the accumulator in `acc`.
    ForBegin {
        /// Slot the iteration variable lives in.
        var: u32,
        /// Slot the exclusive upper bound is kept in, for [`Op::ForStep`].
        end: u32,
        /// Slot the running result lives in.
        acc: u32,
        kind: LoopKind,
        done: u32,
    },
    /// `for <quant> <var> in pe.resources : ( ... )` — enter an array loop.
    ///
    /// Pops the array's length. The counterpart of [`Op::ForBegin`] for an
    /// array whose elements are not on the stack but are fetched by index, so
    /// the loop iterates `0 .. length`. A length of zero ends the loop before
    /// it starts, which is why the bound is `length - 1` in the `end` slot
    /// rather than `length`: `-1` would be an index the element fetch would
    /// have to refuse, and `for all` has to be vacuously true over no
    /// resources rather than undefined.
    ForEachBegin {
        /// Slot the iteration variable (the index) lives in.
        var: u32,
        /// Slot the inclusive upper bound is kept in, for [`Op::ForStep`].
        end: u32,
        /// Slot the running result lives in.
        acc: u32,
        kind: LoopKind,
        done: u32,
    },
    /// The end of a loop body: fold the body's result into the accumulator,
    /// advance the variable, and jump back to the matching [`Op::ForBegin`]
    /// while there is more to do.
    ///
    /// The only backward jump the compiler emits, and the reason
    /// [`Program::max_steps`] is not simply the program's length.
    ForStep {
        var: u32,
        end: u32,
        acc: u32,
        kind: LoopKind,
        back: u32,
    },
    /// `i` — the current value of a loop variable, from slot `0`.
    VarLoad(u32),

    /// The result of another rule, by its index in the corpus.
    ///
    /// A rule may be written in terms of another rule's verdict —
    /// `OTHER_RULE and $a` — which is how a corpus states a shared condition
    /// once and turns it on from thirty places. The rule named is evaluated
    /// before this one, and its result is handed to the interpreter rather
    /// than recomputed, because the alternative is re-evaluating a whole
    /// condition once per rule that mentions it.
    ///
    /// The index is a position in the caller's own result array and not an
    /// evaluation order: the scanner decides the order, and the compiler
    /// guarantees only that a rule is placed after everything it names. See
    /// `compile_corpus`.
    RuleRef(u32),

    /// `pe.<member>` — push one field of the parsed PE.
    ///
    /// Undefined when the buffer is not a PE, except for
    /// [`PeField::IsPe`], which is false — see [`PeField`].
    PeField(PeField),
    /// `dotnet.<member>` — push one field of the parsed assembly.
    ///
    /// [`DotNetField::IsDotNet`] answers for any buffer, including one that is
    /// not an image at all; every other member is `Undefined` for a file that
    /// is not an assembly — see [`DotNetField`].
    DotNetField(DotNetField),
    /// `dotnet.<array>[<index>].<member>` — pops the index, pushes that member
    /// of that element.
    ///
    /// Undefined when the buffer is not an assembly or the index is past the end
    /// of the array — see [`DotNetElement`] for why an out-of-range index is
    /// nothing rather than a default.
    DotNetIndexed(DotNetElement),
    /// `pe.<array>[<index>].<member>` — pops the index, pushes that member of
    /// that element.
    ///
    /// Undefined when the buffer is not a PE or the index is past the end of the
    /// array, which is the ordinary case for an index a rule computed.
    PeIndexed(PeElement),
    /// `pe.version_info[<key>]` — pops the key, pushes that entry of the file's
    /// version resource.
    ///
    /// Undefined when the buffer is not a PE or the resource has no such key,
    /// which is the ordinary case: most files carry no version resource at all,
    /// and most of those that do say nothing under the key a rule asked for.
    ///
    /// Its own opcode rather than a [`PeElement`], because the index is a string
    /// where every other `pe` array is indexed by an integer — and because the
    /// value comes from a resource rather than from a table in the header, which
    /// is the same reason `pe.resources` has its own members.
    PeVersionInfo,
    /// A `pe` module function — pops [`PeFunc::arity`] operands, pushes one
    /// result.
    PeCall(PeFunc),
    /// A function of any other module — `hash.md5`, `math.entropy`. Pops
    /// [`ModuleFunc::arity`] operands, pushes one result.
    ///
    /// A separate opcode from [`Op::PeCall`] rather than a wider `PeFunc`,
    /// because the two take their arguments from different places: a `pe`
    /// function reads the parsed image, and these read the raw buffer or
    /// nothing at all. Folding them together would give the interpreter an
    /// enum whose variants need different inputs, which is a `match` at the
    /// call site deciding which module it is in — the thing the opcode is for.
    ModuleCall(ModuleFunc),

    /// Pop the condition and finish. The rule matches if it was true.
    Ret,
}

/// A member of the `pe` module that belongs to the file as a whole.
///
/// The enum exists so that [`Op`] stays small and `Copy`. The module has some
/// two hundred members and will grow all of them; a variant of [`Op`] for each
/// would make every instruction in every rule as wide as the widest operand,
/// and every `match` in the interpreter and the disassembler as long as the
/// member list.
///
/// # Only what is implemented is listed
///
/// A member appears here once it can be answered correctly for every file, not
/// when its name is known. A member that returned [`Value::Undefined`] for a
/// field that is merely unimplemented would make the rules that use it silently
/// stop matching — a false negative, which is the one failure this engine must
/// not have. Until a member is here, the compiler refuses the rule that names
/// it and the refusal is reported.
///
/// `pe.number_of_signatures` is the standing example: it is the single most
/// requested member in the corpus and it stays out until Authenticode parsing
/// can count signatures properly, because the alternative is reporting zero for
/// a signed file.
///
/// # Why integers for the predicates
///
/// [`PeField::IsPe`] and its siblings yield `Int(0)` or `Int(1)` rather than a
/// boolean, because that is what YARA's module yields and rules are written
/// against it — `pe.is_dll == 1` is a comparison a rule makes, and it would be
/// false against a boolean even though both mean the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PeField {
    /// Whether the buffer is a PE at all. The one member defined for a file that
    /// is not one.
    IsPe,
    IsDll,
    Is32Bit,
    Is64Bit,
    Machine,
    Timestamp,
    Characteristics,
    Subsystem,
    DllCharacteristics,
    /// The entry point as a file offset — see `av_pe::PeFile::entry_point`.
    EntryPoint,
    /// The entry point as the RVA the header holds.
    EntryPointRaw,
    ImageBase,
    SizeOfImage,
    SizeOfHeaders,
    Checksum,
    SectionAlignment,
    FileAlignment,
    NumberOfRvaAndSizes,
    BaseOfCode,
    BaseOfData,
    SizeOfCode,
    SizeOfInitializedData,
    SizeOfUninitializedData,
    SizeOfStackReserve,
    SizeOfStackCommit,
    SizeOfHeapReserve,
    SizeOfHeapCommit,
    /// The four version pairs, which are four structs of two members each and
    /// not four packed integers. Reaching one without its `.major` or `.minor`
    /// is a type error, so there is no bare `pe.linker_version` here to read.
    LinkerVersionMajor,
    LinkerVersionMinor,
    OsVersionMajor,
    OsVersionMinor,
    ImageVersionMajor,
    ImageVersionMinor,
    SubsystemVersionMajor,
    SubsystemVersionMinor,
    /// The optional header's magic, which is what distinguishes PE32 from
    /// PE32+ when it matters more than `pe.is_64bit` does.
    OpthdrMagic,
    /// COFF symbol table location and size, stripped in production binaries and
    /// therefore a place data gets hidden.
    PointerToSymbolTable,
    NumberOfSymbols,
    /// The length the header claims for the optional header.
    SizeOfOptionalHeader,
    LoaderFlags,
    Win32VersionValue,
    /// Where data appended after the last section starts, and how much there is.
    /// Both zero together when there is none.
    OverlayOffset,
    OverlaySize,
    /// How many sections were read, which is not what the header claims.
    NumberOfSections,
    /// `pe.number_of_signatures` — how many certificates the attribute
    /// certificate table holds, across every signature in it.
    ///
    /// Counts *certificates*, not signatures, which is what the corpus's loop
    /// bounds depend on: `for any i in ( 0 .. pe.number_of_signatures )` is
    /// inclusive at both ends, so the final iteration is out of range and has
    /// to be `Undefined`. Counting `WIN_CERTIFICATE` records instead would
    /// leave the last certificate of a multi-certificate chain unreachable.
    NumberOfSignatures,
    /// `pe.number_of_imports` — how many libraries the file binds to.
    ///
    /// The descriptors, not the symbols. The corpus fixes this: the rule at
    /// line 209349 lists seventeen DLL names beside
    /// `> 16 and < 19`, and a count of functions would not track a list of
    /// libraries. `pe.number_of_imported_functions` is the other number and is
    /// not implemented, because no rule here asks for it.
    NumberOfImports,
    /// `pe.number_of_exports` — how many entries the export address table holds.
    ///
    /// The address table, not the name table. A DLL that exports something by
    /// ordinal only has more addresses than names, and the corpus's
    /// `pe.exports("Init") and pe.number_of_exports == 2` is that case.
    NumberOfExports,
    /// `pe.number_of_resources` — how many leaves the resource tree has.
    ///
    /// Leaves, not directories. One icon present in five languages is five
    /// resources, and the corpus's loop bound depends on that: a rule writing
    /// `for any i in (0 .. pe.number_of_resources - 1)` walks the flattened
    /// array, so a count of directory entries would leave the last resource
    /// unreachable.
    NumberOfResources,
    /// `pe.rich_signature.length` — the size of the decoded region, in bytes.
    ///
    /// The decoded region and not the structure: it is
    /// `pe.rich_signature.clear_data`'s length, so that the two members describe
    /// the same bytes. The `Rich` marker and the key that decodes the rest are
    /// the decoder, not the payload — a structure whose length included its own
    /// decryption key would be a number no rule could check against anything.
    RichSignatureLength,
    /// `pe.rich_signature.clear_data` — the decoded region, as bytes.
    ///
    /// The one member of this enum whose value is a string rather than an
    /// integer, and the reason [`Value`] is byte-typed end to end: twenty rules
    /// in the corpus hash these bytes, and a lossy conversion anywhere on the
    /// way would turn each of them into a digest of the wrong input — a rule
    /// that compiles, enters the database and can never match.
    RichSignatureClearData,
    /// `pe.pdb_path` — the path of the program database the linker read, out of
    /// the CodeView record in the debug directory.
    ///
    /// A string, the second of the two members here that are. The corpus
    /// compares it with `contains`, against a build server's own directory: the
    /// path is a fingerprint of the machine that linked the file, and it is not
    /// one an author usually remembers to strip. Empty for a stripped image,
    /// which is most of them.
    PdbPath,
}

/// A member of an element of one of the `pe` module's arrays.
///
/// A member of the `dotnet` module — `dotnet.is_dotnet` and its neighbours.
///
/// # Why this is its own enum rather than more of [`PeField`]
///
/// Because the two answer about different files. Every `pe` member is read from
/// the header of any image, so a `pe` member asked of a buffer that is not an
/// image is a question about a table that was never there and is `Undefined`.
/// `dotnet.is_dotnet` is the opposite kind of question: it is the one member
/// whose answer is meaningful *because* the file is not managed, so it cannot
/// live in an enum whose every other member means "and the file is a PE".
///
/// # Only what is implemented is listed
///
/// A member appears here once it can be answered correctly for every file, not
/// when it is first parsed. The reader in `av-pe` exposes more — the assembly's
/// culture, its module name — and each is added here when a rule asks for it, on
/// the principle the `pe` module already follows: a member compiled before it
/// can be answered would answer `Undefined` forever and make every rule naming
/// it stop matching while still looking supported. That is the failure this
/// whole design is arranged to prevent, and the reason
/// `pe.number_of_imported_functions` is absent too.
///
/// The members below are the ones the 10,764-rule set this engine is validated
/// against names, plus the rest of the assembly version quad, which is one
/// struct: a rule that reads `major` and one that reads `revision` are asking
/// the same question of the same four fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DotNetField {
    /// `dotnet.is_dotnet` — whether the file carries a CLI header.
    ///
    /// An integer rather than a boolean, because rules compare it. It is also
    /// the one member here defined for a file that is not an assembly, which is
    /// what [`DotNetField`]'s opening note is about: it answers `0` rather than
    /// nothing, exactly as [`PeField::IsPe`] does for a buffer that is not an
    /// image.
    IsDotNet,
    /// `dotnet.version` — the runtime version string out of the metadata root,
    /// `v4.0.30319` for anything built against .NET Framework 4.
    ///
    /// The second member in this file whose value is a string, and the reason
    /// [`Value`] is byte-typed end to end: the string is read without its NUL
    /// terminator and compared as bytes.
    ///
    /// `Undefined` for a file that is not an assembly, which is not the same as
    /// empty — see [`DotNetField::NumberOfResources`].
    Version,
    /// `dotnet.number_of_resources` — how many `ManifestResource` rows the
    /// assembly declares.
    ///
    /// Rows, not embedded resources: five of `mscorlib.dll`'s eight are linked
    /// to other files and still counted, because the number a rule compares
    /// against is a count of what the assembly declares.
    ///
    /// `Undefined` rather than zero for a file that is not an assembly, and
    /// that choice decides real verdicts. A rule writing
    /// `dotnet.number_of_resources == 0` — a plausible way to say "a managed
    /// file with no resources" — would be true of *every* native executable if
    /// this answered `0`, because a table that was never read has no rows. It
    /// stays out of the database matching nothing instead.
    NumberOfResources,
    /// `dotnet.assembly.version.major` — the assembly's `MajorVersion`.
    ///
    /// Part of the `Assembly` table's single row, so it is `Undefined` for a
    /// module that has no `Assembly` row — a netmodule, or an image whose
    /// metadata is too damaged to carry one. That is a third state and not a
    /// synonym for "not managed": the file *is* an assembly in the loose sense
    /// every rule means, and it simply declares no identity.
    AssemblyVersionMajor,
    /// `dotnet.assembly.version.minor` — the assembly's `MinorVersion`.
    AssemblyVersionMinor,
    /// `dotnet.assembly.version.build` — the assembly's `BuildNumber`.
    AssemblyVersionBuild,
    /// `dotnet.assembly.version.revision` — the assembly's `RevisionNumber`.
    AssemblyVersionRevision,
}

impl DotNetField {
    /// How the member reads back in a disassembly.
    pub const fn as_str(self) -> &'static str {
        match self {
            DotNetField::IsDotNet => "dotnet.is_dotnet",
            DotNetField::Version => "dotnet.version",
            DotNetField::NumberOfResources => "dotnet.number_of_resources",
            DotNetField::AssemblyVersionMajor => "dotnet.assembly.version.major",
            DotNetField::AssemblyVersionMinor => "dotnet.assembly.version.minor",
            DotNetField::AssemblyVersionBuild => "dotnet.assembly.version.build",
            DotNetField::AssemblyVersionRevision => "dotnet.assembly.version.revision",
        }
    }

    /// The member of `dotnet.assembly.version` a name refers to.
    ///
    /// Its own lookup rather than more of [`DotNetField::as_str`], because the
    /// caller has already consumed the two path segments that lead here: it
    /// holds the *last* one and nothing else. Keeping the mapping in one place
    /// means a name added to the enum is a name added to both.
    pub const fn assembly_version(name: &str) -> Option<Self> {
        match name.as_bytes() {
            b"major" => Some(DotNetField::AssemblyVersionMajor),
            b"minor" => Some(DotNetField::AssemblyVersionMinor),
            b"build" => Some(DotNetField::AssemblyVersionBuild),
            b"revision" => Some(DotNetField::AssemblyVersionRevision),
            _ => None,
        }
    }
}

/// A member of an element of one of the `dotnet` module's arrays.
///
/// Used with [`Op::DotNetIndexed`], which pops the index. The array a member
/// belongs to is part of its name, so a `ResourceName` can never be read out of
/// the assembly-reference array — the pairing is decided by the compiler from
/// the path text and cannot be got wrong at run time. That is [`PeElement`]'s
/// arrangement, kept for the same reason.
///
/// # Why `Undefined` and not a default
///
/// An index past the end of the array, a negative index, and an index that is
/// not an integer at all are all `Undefined`. The corpus iterates these arrays
/// with a `for` loop bounded by the count member beside them, so an index out of
/// range means a computed index rather than a literal one, and a rule that
/// computed an index meant to read *that* element. Answering `0` or `""` would
/// let it read the element it did not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DotNetElement {
    /// `dotnet.assembly_refs[i].name` — the referenced assembly's name, out of
    /// the `#Strings` heap.
    AssemblyRefName,
    /// `dotnet.resources[i].name` — the manifest resource's name.
    ///
    /// A `ManifestResource` row is named by a `#Strings` index, and a rule
    /// matching `"Quasar.Client*"` against it is matching a name the assembly
    /// itself carries rather than one the file was renamed to. That is why the
    /// member exists at all.
    ResourceName,
    /// `dotnet.resources[i].length` — the byte length the resource's own
    /// `u32` header declares.
    ///
    /// `Undefined` for a *linked* resource, which has no bytes in this file and
    /// therefore no length. Zero is a length a real embedded resource can have,
    /// and a rule writing `dotnet.resources[i].length > 300KB` would read a
    /// linked resource as an empty one — see [`DotNetField::NumberOfResources`]
    /// for the same distinction made the same way.
    ResourceLength,
}

impl DotNetElement {
    /// How the member reads back in a disassembly.
    pub const fn as_str(self) -> &'static str {
        match self {
            DotNetElement::AssemblyRefName => "dotnet.assembly_refs[].name",
            DotNetElement::ResourceName => "dotnet.resources[].name",
            DotNetElement::ResourceLength => "dotnet.resources[].length",
        }
    }
}

/// Used with [`Op::PeIndexed`], which pops the index. The array a member
/// belongs to is part of its name, so a `SectionName` can never be read out of
/// the data directory array — the pairing is decided by the compiler from the
/// path text and cannot be got wrong at run time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PeElement {
    /// `pe.sections[i].name` — a string, trimmed at its first NUL.
    SectionName,
    SectionVirtualAddress,
    SectionVirtualSize,
    SectionRawDataOffset,
    SectionRawDataSize,
    SectionCharacteristics,
    /// Relocation and debug-line metadata. Rarely read, and worth having because
    /// it is the part of a section header an ordinary linker fills in and a
    /// packer that rebuilds the headers usually does not.
    SectionPointerToRelocations,
    SectionNumberOfRelocations,
    SectionPointerToLineNumbers,
    SectionNumberOfLineNumbers,
    /// `pe.data_directories[i].virtual_address`.
    DirectoryVirtualAddress,
    /// `pe.data_directories[i].size`.
    DirectorySize,
    /// `pe.signatures[i].serial` — the certificate's serial number, raw DER
    /// content bytes as colon-separated lowercase hex.
    SignatureSerial,
    /// `pe.signatures[i].subject` — the subject distinguished name.
    SignatureSubject,
    /// `pe.signatures[i].issuer` — the issuer distinguished name.
    SignatureIssuer,
    /// `pe.signatures[i].not_before` — a Unix timestamp.
    SignatureNotBefore,
    /// `pe.signatures[i].not_after` — a Unix timestamp.
    SignatureNotAfter,
    /// `pe.signatures[i].thumbprint` — SHA-1 of the certificate, colon hex.
    SignatureThumbprint,
    /// `pe.signatures[i].version` — 0 for v1, 1 for v2, 2 for v3.
    SignatureVersion,
    /// `pe.resources[i].type` — the type level's id, and `Undefined` when that
    /// level is a name rather than an id.
    ///
    /// `Undefined` rather than zero, because zero is a real type id. A rule
    /// asking for `pe.RESOURCE_TYPE_RCDATA` must not be answered by a resource
    /// whose type is the *name* `"10"`, and it must not be answered by a `0`
    /// either — the two are different resources, not two spellings of one.
    ResourceType,
    /// `pe.resources[i].id` — the name level's id, when it is an id.
    ResourceId,
    /// `pe.resources[i].language` — the language level's id, when it is an id.
    ResourceLanguage,
    /// `pe.resources[i].offset` — where the resource's bytes are, as a **file
    /// offset**.
    ///
    /// Not an RVA, which the corpus depends on: `uint16(pe.resources[i].offset)
    /// == 0x5A4D` finds a second executable embedded in the first, and an RVA
    /// would name a different byte whenever the sections move.
    ResourceOffset,
    /// `pe.resources[i].length` — the size the data entry declares.
    ResourceLength,
    /// `pe.resources[i].name_string` — the name level's name, as raw UTF-16LE
    /// with no terminator.
    ///
    /// Raw, because the corpus compares it against literals such as
    /// `"1\x000\x000\x00"` and matches a regex of four `[0-9]\x00` pairs. It is
    /// not text in any encoding a `String` can hold, and decoding it would make
    /// every one of those comparisons false.
    ResourceNameString,
    /// `pe.resources[i].type_string` — the type level's name, likewise raw.
    ResourceTypeString,
    /// `pe.resources[i].language_string` — the language level's name, likewise
    /// raw.
    ResourceLanguageString,
    /// `pe.export_details[i].name` — the name the export is known by.
    ///
    /// `Undefined` for an entry exported by ordinal alone, which is a real
    /// entry: the array is the export *address* table, so an entry with no name
    /// is there and unnamed rather than absent. See [`crate::vm`]'s
    /// `export_element` for why the distinction is not cosmetic.
    ExportName,
    /// `pe.export_details[i].forward_name` — the `Module.Symbol` this entry
    /// forwards to.
    ///
    /// `Undefined` when the entry is code in this file, rather than an empty
    /// string. A rule asking `forward_name contains ""` must not be answered
    /// `true` by every export in every DLL.
    ExportForwardName,
    /// `pe.export_details[i].offset` — where the exported code is, as a **file
    /// offset**.
    ExportOffset,
    /// `pe.export_details[i].ordinal` — the ordinal the loader knows the export
    /// by, which is the address table index plus the directory's `Base`.
    ExportOrdinal,
}

/// A function in the `pe` module.
///
/// The arity is in [`PeFunc::arity`]; the interpreter pops that many operands
/// and pushes one result, so every one of these has a stack delta of
/// `1 - arity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PeFunc {
    /// `pe.section_index(offset_or_name)` — which section holds a file offset,
    /// or the one with a given name.
    ///
    /// One opcode for both forms rather than two: the argument's type is only
    /// known at run time when it is an expression, and dispatching on the value
    /// the interpreter already has is cheaper than making the compiler prove
    /// which form a rule meant.
    SectionIndex,
    /// `pe.is_dll()`, `pe.is_32bit()`, `pe.is_64bit()` — the same answers as the
    /// members of the same name.
    ///
    /// YARA declares these as functions, so a rule written against it calls
    /// them. Rule sets in the wild just as often write them without the
    /// parentheses, because they read like the fields they are about; both
    /// spellings are accepted and answer identically, which is a deliberate
    /// superset rather than an accident.
    IsDll,
    Is32Bit,
    Is64Bit,
    /// `pe.imphash()` — the MD5 of the normalized import list.
    ///
    /// 371 rules in the corpus compare against it, which makes it the largest
    /// single member after the certificates.
    Imphash,
    /// `pe.imports ( library )` — whether anything is imported from a library.
    ///
    /// The two-argument form is a separate variant rather than an optional
    /// operand, because the interpreter pops a fixed count decided at compile
    /// time. A single variant claiming arity two would pop one operand too many
    /// on the seventeen one-argument checks in a single corpus rule.
    Imports,
    /// `pe.imports ( library , symbol )` — whether one symbol is imported.
    ImportsSymbol,
    /// `pe.exports(name)`.
    Exports,
    /// `pe.rich_signature.toolid(tool, version)` — how many times a tool built
    /// this image, as the Rich header records it.
    ///
    /// The Rich header is the one part of a PE that records *how* a file was
    /// built rather than what is in it: a list of (tool, version) pairs with a
    /// count each, accumulated by every linker and librarian that touched the
    /// object files. Tool 0 is the `Import0` entry, tool 1 the linker. A count
    /// of zero is what a file whose header was stripped, rebuilt or forged
    /// answers, which is why 39 corpus rules read it.
    ///
    /// Two operands, so it is a separate variant from every other function here
    /// — the interpreter pops a count the compiler committed to when it chose
    /// the opcode.
    RichSignatureToolid,
}

impl PeFunc {
    /// How many operands the interpreter pops.
    pub const fn arity(self) -> u32 {
        match self {
            PeFunc::SectionIndex | PeFunc::Exports | PeFunc::Imports => 1,
            PeFunc::ImportsSymbol | PeFunc::RichSignatureToolid => 2,
            PeFunc::IsDll | PeFunc::Is32Bit | PeFunc::Is64Bit | PeFunc::Imphash => 0,
        }
    }

    /// The argument counts the call accepts.
    ///
    /// A range rather than a count for [`PeFunc::Imports`] alone, which the
    /// compiler consults before choosing the variant to emit. Everything else
    /// answers with the single count [`PeFunc::arity`] reports.
    pub const fn arity_range(self) -> (u32, u32) {
        match self {
            PeFunc::Imports => (1, 2),
            other => {
                let n = other.arity();
                (n, n)
            }
        }
    }

    /// The variant to emit for a call that supplied `args` arguments.
    ///
    /// Widens [`PeFunc::Imports`] to [`PeFunc::ImportsSymbol`] and is the
    /// identity for everything else, so the family a name belongs to is stated
    /// once and the widening once, rather than a name appearing twice in the
    /// compiler's lookup.
    pub const fn for_arity(self, args: u32) -> Self {
        match (self, args) {
            (PeFunc::Imports, 2) => PeFunc::ImportsSymbol,
            _ => self,
        }
    }

    /// How the call reads back in a disassembly.
    pub const fn as_str(self) -> &'static str {
        match self {
            PeFunc::SectionIndex => "pe.section_index",
            PeFunc::IsDll => "pe.is_dll",
            PeFunc::Is32Bit => "pe.is_32bit",
            PeFunc::Is64Bit => "pe.is_64bit",
            PeFunc::Imphash => "pe.imphash",
            // Both spellings read back as one name, because they are one name in
            // the language; the argument count is what tells them apart and a
            // disassembly that showed the internal split would be showing an
            // implementation detail.
            PeFunc::Imports | PeFunc::ImportsSymbol => "pe.imports",
            PeFunc::Exports => "pe.exports",
            PeFunc::RichSignatureToolid => "pe.rich_signature.toolid",
        }
    }
}

/// A function of a module other than `pe`.
///
/// One variant per function *and argument count*, which is the same shape
/// [`PeFunc`] takes and for the same reason: the interpreter pops a count the
/// compiler committed to when it chose the opcode, so a function that accepts
/// two spellings of its arguments needs two variants. `hash.md5` has exactly
/// that — `hash.md5("some string")` and `hash.md5(offset, size)`.
///
/// # What is not here
///
/// `math.mode`, `math.serial_correlation` and `math.monte_carlo_pi`, and
/// `hash.crc32`. Each of them has a definition that is a *choice* rather than a
/// consequence of the input — how a tie for the most frequent byte is broken,
/// what textual form a checksum takes — and the corpus's thresholds were
/// calibrated against one particular set of choices. A variant here that made a
/// different choice would be a rule that fires on files its author excluded,
/// which is the failure the whole engine is arranged against. They are refused
/// by name instead, and the refusal is reported.
///
/// `math.deviation` was in that list until its definition could be pinned rather
/// than guessed. It is a *choice* only until one reads the module's own example:
/// over an evenly distributed sample of all 256 byte values the answer is
/// `64.0`, which is the mean absolute deviation from `127.5` and not the
/// standard deviation of the same sample, `73.9`. One of those is a fact about
/// the statistic and the other is a fact about this engine's implementation
/// history, and only the first is worth compiling against. See
/// [`av_core::stats::deviation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleFunc {
    /// `hash.<algorithm>(string)` — the digest of a string's bytes.
    ///
    /// One argument, so a separate variant from [`ModuleFunc::HashRange`].
    /// Unlike every other function in either module, this one does not read the
    /// file: it reads a value the interpreter already has, which is how a rule
    /// hashes something the `pe` module decoded — `pe.rich_signature.clear_data`
    /// is the one in the corpus.
    HashStr(HashKind),
    /// `hash.<algorithm>(offset, size)` — the digest of a region of the file.
    HashRange(HashKind),

    /// `math.entropy(offset, size)` — Shannon entropy in bits per byte.
    Entropy,
    /// `math.mean(offset, size)` — the arithmetic mean of the region's bytes.
    Mean,
    /// `math.count(byte, offset, size)` — how often one byte value occurs.
    Count,
    /// `math.percentage(byte, offset, size)` — the same as a fraction of the
    /// region, in `0.0 ..= 100.0`.
    Percentage,
    /// `math.min(a, b)`.
    Min,
    /// `math.max(a, b)`.
    Max,
    /// `math.abs(x)`.
    Abs,
    /// `math.to_number(boolean)` — `1` or `0`.
    ToNumber,
    /// `math.in_range(x, lower, upper)` — whether `lower <= x <= upper`.
    InRange,
    /// `math.deviation(offset, size, mean)` — the mean absolute deviation of the
    /// region's bytes from a mean the rule supplies.
    ///
    /// The mean is an argument rather than computed from the region, which is
    /// what makes the statistic describe a *kind* of data rather than this
    /// file's own spread. The corpus supplies `89.0`, the mean of the base64
    /// alphabet.
    Deviation,
    /// `math.deviation(string, mean)` — the same statistic over a string the
    /// `pe` module decoded rather than over a region of the file.
    ///
    /// A separate variant rather than a flag, because the interpreter pops a
    /// count the compiler committed to: one argument is a string and three are
    /// a region, and no single opcode can be told which it was given.
    DeviationStr,

    /// `string.length(string)` — the string's length in bytes.
    ///
    /// Bytes and not characters, and NULs count: the module's own example is
    /// `string.length("AXS\x00ERS") == 7`. The strings this is asked about are
    /// the `pe` module's raw fields, which are byte strings in no encoding at
    /// all, so a character count would not be defined for them.
    StringLength,
    /// `string.to_int(string)` — a decimal, hexadecimal or octal literal read as
    /// a signed integer.
    StringToInt,
    /// `string.to_int(string, base)` — the same, with the base the rule names.
    StringToIntBase,
}

impl ModuleFunc {
    /// How many operands the interpreter pops.
    pub const fn arity(self) -> u32 {
        match self {
            ModuleFunc::HashStr(_)
            | ModuleFunc::Abs
            | ModuleFunc::ToNumber
            | ModuleFunc::StringLength
            | ModuleFunc::StringToInt => 1,
            ModuleFunc::HashRange(_)
            | ModuleFunc::Entropy
            | ModuleFunc::Mean
            | ModuleFunc::Min
            | ModuleFunc::Max
            | ModuleFunc::DeviationStr
            | ModuleFunc::StringToIntBase => 2,
            // Three: the byte or value being asked about, and then the region.
            ModuleFunc::Count
            | ModuleFunc::Percentage
            | ModuleFunc::InRange
            | ModuleFunc::Deviation => 3,
        }
    }

    /// How the call reads back in a disassembly.
    ///
    /// The algorithm is named for `hash`, which is the one place where the
    /// variant carries a payload a reader needs to see.
    pub fn as_str(self) -> &'static str {
        match self {
            ModuleFunc::HashStr(HashKind::Md5) | ModuleFunc::HashRange(HashKind::Md5) => "hash.md5",
            ModuleFunc::HashStr(HashKind::Sha1) | ModuleFunc::HashRange(HashKind::Sha1) => {
                "hash.sha1"
            }
            ModuleFunc::HashStr(HashKind::Sha256) | ModuleFunc::HashRange(HashKind::Sha256) => {
                "hash.sha256"
            }
            ModuleFunc::Entropy => "math.entropy",
            ModuleFunc::Mean => "math.mean",
            ModuleFunc::Count => "math.count",
            ModuleFunc::Percentage => "math.percentage",
            ModuleFunc::Min => "math.min",
            ModuleFunc::Max => "math.max",
            ModuleFunc::Abs => "math.abs",
            ModuleFunc::ToNumber => "math.to_number",
            ModuleFunc::InRange => "math.in_range",
            ModuleFunc::Deviation | ModuleFunc::DeviationStr => "math.deviation",
            ModuleFunc::StringLength => "string.length",
            ModuleFunc::StringToInt | ModuleFunc::StringToIntBase => "string.to_int",
        }
    }

    /// The module this function belongs to, for a refusal that names it.
    pub const fn module(self) -> &'static str {
        match self {
            ModuleFunc::HashStr(_) | ModuleFunc::HashRange(_) => "hash",
            ModuleFunc::StringLength | ModuleFunc::StringToInt | ModuleFunc::StringToIntBase => {
                "string"
            }
            _ => "math",
        }
    }
}

impl PeField {
    /// How the member reads back in a disassembly.
    pub const fn as_str(self) -> &'static str {
        match self {
            PeField::IsPe => "pe.is_pe",
            PeField::IsDll => "pe.is_dll",
            PeField::Is32Bit => "pe.is_32bit",
            PeField::Is64Bit => "pe.is_64bit",
            PeField::Machine => "pe.machine",
            PeField::Timestamp => "pe.timestamp",
            PeField::Characteristics => "pe.characteristics",
            PeField::Subsystem => "pe.subsystem",
            PeField::DllCharacteristics => "pe.dll_characteristics",
            PeField::EntryPoint => "pe.entry_point",
            PeField::EntryPointRaw => "pe.entry_point_raw",
            PeField::ImageBase => "pe.image_base",
            PeField::SizeOfImage => "pe.size_of_image",
            PeField::SizeOfHeaders => "pe.size_of_headers",
            PeField::Checksum => "pe.checksum",
            PeField::SectionAlignment => "pe.section_alignment",
            PeField::FileAlignment => "pe.file_alignment",
            PeField::NumberOfRvaAndSizes => "pe.number_of_rva_and_sizes",
            PeField::BaseOfCode => "pe.base_of_code",
            PeField::BaseOfData => "pe.base_of_data",
            PeField::SizeOfCode => "pe.size_of_code",
            PeField::SizeOfInitializedData => "pe.size_of_initialized_data",
            PeField::SizeOfUninitializedData => "pe.size_of_uninitialized_data",
            PeField::SizeOfStackReserve => "pe.size_of_stack_reserve",
            PeField::SizeOfStackCommit => "pe.size_of_stack_commit",
            PeField::SizeOfHeapReserve => "pe.size_of_heap_reserve",
            PeField::SizeOfHeapCommit => "pe.size_of_heap_commit",
            PeField::LinkerVersionMajor => "pe.linker_version.major",
            PeField::LinkerVersionMinor => "pe.linker_version.minor",
            PeField::OsVersionMajor => "pe.os_version.major",
            PeField::OsVersionMinor => "pe.os_version.minor",
            PeField::ImageVersionMajor => "pe.image_version.major",
            PeField::ImageVersionMinor => "pe.image_version.minor",
            PeField::SubsystemVersionMajor => "pe.subsystem_version.major",
            PeField::SubsystemVersionMinor => "pe.subsystem_version.minor",
            PeField::OpthdrMagic => "pe.opthdr_magic",
            PeField::PointerToSymbolTable => "pe.pointer_to_symbol_table",
            PeField::NumberOfSymbols => "pe.number_of_symbols",
            PeField::SizeOfOptionalHeader => "pe.size_of_optional_header",
            PeField::LoaderFlags => "pe.loader_flags",
            PeField::Win32VersionValue => "pe.win32_version_value",
            PeField::OverlayOffset => "pe.overlay.offset",
            PeField::OverlaySize => "pe.overlay.size",
            PeField::NumberOfSections => "pe.number_of_sections",
            PeField::NumberOfSignatures => "pe.number_of_signatures",
            PeField::NumberOfImports => "pe.number_of_imports",
            PeField::NumberOfExports => "pe.number_of_exports",
            PeField::NumberOfResources => "pe.number_of_resources",
            PeField::RichSignatureLength => "pe.rich_signature.length",
            PeField::RichSignatureClearData => "pe.rich_signature.clear_data",
            PeField::PdbPath => "pe.pdb_path",
        }
    }
}

impl PeElement {
    /// How the member reads back in a disassembly.
    pub const fn as_str(self) -> &'static str {
        match self {
            PeElement::SectionName => "pe.sections[].name",
            PeElement::SectionVirtualAddress => "pe.sections[].virtual_address",
            PeElement::SectionVirtualSize => "pe.sections[].virtual_size",
            PeElement::SectionRawDataOffset => "pe.sections[].raw_data_offset",
            PeElement::SectionRawDataSize => "pe.sections[].raw_data_size",
            PeElement::SectionCharacteristics => "pe.sections[].characteristics",
            PeElement::SectionPointerToRelocations => "pe.sections[].pointer_to_relocations",
            PeElement::SectionNumberOfRelocations => "pe.sections[].number_of_relocations",
            PeElement::SectionPointerToLineNumbers => "pe.sections[].pointer_to_line_numbers",
            PeElement::SectionNumberOfLineNumbers => "pe.sections[].number_of_line_numbers",
            PeElement::DirectoryVirtualAddress => "pe.data_directories[].virtual_address",
            PeElement::DirectorySize => "pe.data_directories[].size",
            PeElement::SignatureSerial => "pe.signatures[].serial",
            PeElement::SignatureSubject => "pe.signatures[].subject",
            PeElement::SignatureIssuer => "pe.signatures[].issuer",
            PeElement::SignatureNotBefore => "pe.signatures[].not_before",
            PeElement::SignatureNotAfter => "pe.signatures[].not_after",
            PeElement::SignatureThumbprint => "pe.signatures[].thumbprint",
            PeElement::SignatureVersion => "pe.signatures[].version",
            PeElement::ResourceType => "pe.resources[].type",
            PeElement::ResourceId => "pe.resources[].id",
            PeElement::ResourceLanguage => "pe.resources[].language",
            PeElement::ResourceOffset => "pe.resources[].offset",
            PeElement::ResourceLength => "pe.resources[].length",
            PeElement::ResourceNameString => "pe.resources[].name_string",
            PeElement::ResourceTypeString => "pe.resources[].type_string",
            PeElement::ResourceLanguageString => "pe.resources[].language_string",
            PeElement::ExportName => "pe.export_details[].name",
            PeElement::ExportForwardName => "pe.export_details[].forward_name",
            PeElement::ExportOffset => "pe.export_details[].offset",
            PeElement::ExportOrdinal => "pe.export_details[].ordinal",
        }
    }
}

/// Which quantifier a `for` loop was written with.
///
/// The count in `for 2 i in ...` is an *expression* — often a module field —
/// and is evaluated before the loop begins, so the interpreter only ever needs
/// which of the four rules to apply to the results. Keeping the AST's
/// [`Quantifier`](crate::ast::Quantifier) in the instruction would put an
/// expression tree in the bytecode to no purpose, and would cost `Op` its
/// `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LoopKind {
    /// `for any i in ...` — true when the body held at least once.
    Any,
    /// `for all i in ...` — true when the body held every time, and true when
    /// the range was empty.
    All,
    /// `for none i in ...` — true when the body never held.
    None,
    /// `for <n> i in ...` — true when the body held at least `n` times. `n` is
    /// pushed before the loop and compared against the count after it, so this
    /// variant only ever means "count the times the body held".
    Count,
}

impl LoopKind {
    /// The accumulator's value before the first iteration.
    ///
    /// Chosen so that the empty range is already the right answer: `any` over
    /// nothing is false, `all` over nothing is vacuously true, and none of
    /// them held zero times.
    pub const fn identity(self) -> Value {
        match self {
            LoopKind::Any => Value::Bool(false),
            LoopKind::All | LoopKind::None => Value::Bool(true),
            LoopKind::Count => Value::Int(0),
        }
    }

    /// Fold one iteration's result into the accumulator.
    ///
    /// `body` has already been read for truth, so an undefined body counts as
    /// false — the same reading [`Op::OfAny`] and its siblings take of the
    /// string results they are handed.
    pub fn fold(self, acc: &Value, body: bool) -> Value {
        match self {
            LoopKind::Any => Value::Bool(acc.is_truthy() || body),
            LoopKind::All => Value::Bool(acc.is_truthy() && body),
            LoopKind::None => Value::Bool(acc.is_truthy() && !body),
            LoopKind::Count => {
                let count = match acc {
                    Value::Int(n) => *n,
                    _ => 0,
                };
                Value::Int(count + i64::from(body))
            }
        }
    }

    /// Whether the answer can no longer change, so the loop may stop early.
    ///
    /// A count cannot be decided before the last iteration, which is the whole
    /// difference between it and the other three.
    pub fn decided(self, acc: &Value) -> bool {
        match self {
            LoopKind::Any => acc.is_truthy(),
            LoopKind::All | LoopKind::None => !acc.is_truthy(),
            LoopKind::Count => false,
        }
    }

    /// How the loop reads back in a disassembly.
    pub const fn as_str(self) -> &'static str {
        match self {
            LoopKind::Any => "any",
            LoopKind::All => "all",
            LoopKind::None => "none",
            LoopKind::Count => "count",
        }
    }
}

impl Op {
    /// Net change this instruction makes to the operand stack.
    ///
    /// Used to compute [`Program::max_stack`]. Must agree with the interpreter:
    /// a delta that is too small under-reserves the stack, and the interpreter
    /// trusts this number instead of growing.
    pub const fn stack_delta(self) -> i32 {
        match self {
            Op::Push(_) | Op::Filesize | Op::EntryPoint => 1,
            Op::ReadU8
            | Op::ReadU16
            | Op::ReadU32
            | Op::ReadI8
            | Op::ReadI16
            | Op::ReadI32
            | Op::ReadU16Be
            | Op::ReadU32Be
            | Op::ReadI16Be
            | Op::ReadI32Be => 0, // pops the offset, pushes the value
            Op::StrMatch(_) | Op::StrCount(_) | Op::StrOffsetFirst(_) | Op::StrLenFirst(_) => 1,
            Op::StrOffsetNth(_) | Op::StrLenNth(_) | Op::StrAt(_) => 0,
            Op::StrIn(_) => -1, // pops two bounds, pushes one result
            Op::OfAny(n) | Op::OfAll(n) | Op::OfNone(n) => 1 - n as i32,
            // Pops the count and the n results, pushes one result.
            Op::OfCount(n) => -(n as i32),
            Op::Not | Op::Negate | Op::BitNot | Op::IsDefined => 0,
            Op::Add
            | Op::Sub
            | Op::Mul
            | Op::Div
            | Op::Mod
            | Op::BitAnd
            | Op::BitOr
            | Op::BitXor
            | Op::Shl
            | Op::Shr
            | Op::Eq
            | Op::Ne
            | Op::Lt
            | Op::Le
            | Op::Gt
            | Op::Ge
            | Op::Cmp(_) => -1,
            Op::Jump(_) => 0,
            Op::JumpIfFalse(_) | Op::JumpIfTrue(_) => -1,
            // Pops the two bounds.
            Op::ForBegin { .. } => -2,
            // Pops the array's length.
            Op::ForEachBegin { .. } => -1,
            // Pops the body's result.
            Op::ForStep { .. } => -1,
            Op::VarLoad(_) => 1,
            Op::RuleRef(_) => 1,
            // Whole-file members need nothing from the stack.
            Op::PeField(_) => 1,
            Op::DotNetField(_) => 1,
            // Pops the index, pushes the member.
            Op::PeIndexed(_) => 0,
            Op::DotNetIndexed(_) => 0,
            // Pops the key, pushes the value.
            Op::PeVersionInfo => 0,
            Op::Matches(_) => 0,
            Op::PeCall(f) => 1 - f.arity() as i32,
            Op::ModuleCall(f) => 1 - f.arity() as i32,
            Op::Ret => -1,
        }
    }
}

/// A `/regex/` a condition applies to a string with `matches`.
///
/// # Why the pattern and not the automaton
///
/// Because a [`Program`] is serialised into the rule database and deserialised
/// on every start, and a compiled automaton is not a thing that survives that
/// round trip: it holds pointers into its own memory and a DFA cache. What
/// survives is the text, so the text is what is stored and the automaton is
/// built on first use and kept by the interpreter — see [`crate::vm::Vm`].
///
/// The flags are the letters after the closing slash, exactly as written. They
/// are part of the identity of the pattern: `/re/i` and `/re/` match different
/// bytes, so two specs that differ only in flags are two specs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegexSpec {
    /// The text between the slashes, as the author wrote it.
    pub body: String,
    /// The flag letters that followed them, e.g. `i` in `/re/i`.
    pub flags: String,
}

/// A compiled condition.
///
/// Produced by `compiler::compile_condition` and executed by `vm::run`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Program {
    pub code: Vec<Op>,
    pub constants: Vec<Const>,
    /// The `matches` patterns this condition applies, indexed by
    /// [`Op::Matches`].
    ///
    /// Empty for every rule that does not use the operator, which is nearly all
    /// of them.
    #[serde(default)]
    pub regexes: Vec<RegexSpec>,
    /// How many strings the rule defines.
    ///
    /// Kept with the program because `them` and `$a*` in the condition expand to
    /// this many string slots at compile time, so the interpreter must know how
    /// many results the matcher will hand it.
    pub string_count: u32,
    /// How many variable slots the program uses, for loop variables, loop
    /// bounds and loop accumulators.
    ///
    /// The compiler allocates three per `for` loop and reuses them between
    /// loops that cannot be live at the same time, so this is the high-water
    /// mark of nesting rather than a count of loops. The interpreter sizes its
    /// register file from it once per rule.
    ///
    /// Zero for a program with no loops, which is nearly all of them.
    pub var_slots: u32,
    /// Most instructions this program can execute.
    ///
    /// Static, so the scanner can bound the work a rule can cost before running
    /// it. Every jump is forward except a loop's back edge, and a loop runs at
    /// most [`MAX_LOOP_ITERATIONS`] times, so this is finite — see
    /// [`Program::compute_limits`] for how the loop allowance is folded in.
    pub max_steps: u32,
    /// Deepest the operand stack ever gets.
    ///
    /// Computed at compile time so the interpreter can allocate its stack once,
    /// as one block, instead of growing a `Vec` on the hot path. The VM also
    /// checks this against its own capacity, which is what stops a corrupt rule
    /// database from pushing the interpreter past its guard.
    pub max_stack: u32,
    /// String slots the condition cannot be true without.
    ///
    /// From [`crate::compiler::required_slots`], and read by the prefilter
    /// rather than the interpreter. A conjunction of strings — `$a and $b` —
    /// means the rule is only worth evaluating when both are still possible,
    /// which is a far stronger filter than the "any string might be present"
    /// the atom tables alone can support. Empty means nothing could be proven,
    /// which the prefilter reads as that weaker disjunction.
    ///
    /// Sorted and deduplicated, and every slot is within `string_count`. The
    /// prefilter relies on the sort: the list is serialised into the rule
    /// database, so two compilations of one rule set have to produce the same
    /// bytes.
    pub required_strings: Vec<u32>,
    /// Source span of the condition, for diagnostics.
    pub span: Span,
}

impl Program {
    pub fn new(span: Span) -> Self {
        Self {
            code: Vec::new(),
            constants: Vec::new(),
            regexes: Vec::new(),
            string_count: 0,
            var_slots: 0,
            max_steps: 0,
            max_stack: 0,
            required_strings: Vec::new(),
            span,
        }
    }

    /// Add a constant, reusing an identical one.
    ///
    /// Machine-generated rules repeat the same literals heavily — a long `or`
    /// chain over resource names quotes a handful of strings dozens of times —
    /// so deduplicating keeps the pool proportional to the distinct literals
    /// rather than to the source text.
    pub fn constant(&mut self, value: Const) -> u32 {
        if let Some(index) = self.constants.iter().position(|c| *c == value) {
            return u32::try_from(index).unwrap_or(u32::MAX);
        }
        let index = self.constants.len();
        self.constants.push(value);
        u32::try_from(index).unwrap_or(u32::MAX)
    }

    /// Add a `matches` pattern, reusing an identical one.
    ///
    /// Interning for the same reason [`Program::constant`] interns: a rule that
    /// applies one pattern to four different fields writes it once, and a
    /// pattern carried into the database twice would be compiled twice on first
    /// use and would occupy two entries of the interpreter's cache.
    pub fn regex(&mut self, spec: RegexSpec) -> u32 {
        if let Some(index) = self.regexes.iter().position(|r| *r == spec) {
            return u32::try_from(index).unwrap_or(u32::MAX);
        }
        let index = self.regexes.len();
        self.regexes.push(spec);
        u32::try_from(index).unwrap_or(u32::MAX)
    }

    /// The rules this program reads, in order and deduplicated.
    ///
    /// Read out of the bytecode rather than the AST, which is the only way this
    /// can be guaranteed to agree with what the program actually does: the
    /// compiler has already resolved every name, so `Op::RuleRef`'s operand is
    /// the answer, not a second guess at it.
    ///
    /// A caller ordering a set of rules needs this; a rule that reads another
    /// has to run after it. Two callers do — [`crate::compiler::compile_corpus`]
    /// when it decides an evaluation order, and the rule database when it
    /// re-checks that order after dropping rules of its own.
    pub fn rule_refs(&self) -> Vec<u32> {
        let mut seen = Vec::new();
        for op in &self.code {
            if let Op::RuleRef(index) = op {
                if !seen.contains(index) {
                    seen.push(*index);
                }
            }
        }
        seen
    }

    pub fn emit(&mut self, op: Op) -> u32 {
        let at = self.code.len();
        self.code.push(op);
        u32::try_from(at).unwrap_or(u32::MAX)
    }

    /// Overwrite an instruction, used to patch a forward jump once its target
    /// is known.
    pub fn patch(&mut self, at: u32, op: Op) {
        if let Some(slot) = self.code.get_mut(at as usize) {
            *slot = op;
        }
    }

    /// The address one past the last instruction.
    pub fn here(&self) -> u32 {
        u32::try_from(self.code.len()).unwrap_or(u32::MAX)
    }

    /// Fill in [`Program::max_steps`] and [`Program::max_stack`].
    ///
    /// Called once, after the last instruction is emitted. Both are static
    /// properties of the finished program, and computing them here rather than
    /// tracking them as the compiler emits keeps the emission code free of
    /// bookkeeping it would only get wrong.
    ///
    /// # Steps
    ///
    /// The longest *acyclic* path, found by a backward pass, plus an allowance
    /// for the loops. Every jump is forward except a loop's back edge, so
    /// treating the back edge as "the loop ends here" leaves a DAG whose
    /// successors have all been computed by the time their predecessor is
    /// reached, and one pass suffices without a worklist.
    ///
    /// The loops are then accounted for on top: the longest body, times the
    /// most times any loop may run. That is an over-estimate when a program has
    /// several loops and a slight one when loops nest, and over-estimating is
    /// the only safe direction here — this figure is the interpreter's step
    /// budget, so too small would abort a rule that was going to match, while
    /// too large only means a malformed rule takes longer to give up.
    ///
    /// # Stack
    ///
    /// An upper bound, from a linear walk that sums [`Op::stack_delta`]. At a
    /// branch, walking straight through both arms adds the heights they would
    /// each have had, so the figure can exceed what any real path needs. That
    /// is the safe direction: over-reserving wastes a few slots, under-serving
    /// would let the interpreter write past its stack. The interpreter checks
    /// its depth against this anyway, so a program from a corrupt database
    /// cannot use a dishonest figure to escape its guard.
    pub fn compute_limits(&mut self) {
        let n = self.code.len();

        // `steps[i]` is the longest path from instruction `i` to the end,
        // ignoring loop back edges. The body of the longest loop is remembered
        // on the way past, because the loop allowance below needs it.
        let mut steps = vec![0u32; n.saturating_add(1)];
        // `None` until a loop is seen, so that a program without one is bounded
        // by its own length rather than by an allowance for loops it does not
        // have — the difference between "a few steps" and 131,072 of them.
        let mut longest_body = None;
        for i in (0..n).rev() {
            let target = |t: u32| steps.get(t as usize).copied().unwrap_or(0);
            let after = steps[i.saturating_add(1)];
            steps[i] = 1u32.saturating_add(match self.code[i] {
                Op::Ret => 0,
                Op::Jump(t) => target(t),
                Op::JumpIfFalse(t) | Op::JumpIfTrue(t) => after.max(target(t)),
                // Either falls through into the body or skips to the end.
                Op::ForBegin { done, .. } => after.max(target(done)),
                Op::ForEachBegin { done, .. } => after.max(target(done)),
                Op::ForStep { back, .. } => {
                    // The back edge is the loop itself, so it is not a path to
                    // the end; falling out of the bottom is. This instruction
                    // is the last one in its body, so `i - back + 1` is the
                    // body's length in instructions.
                    if back as usize <= i {
                        let body = i as u32 - back + 1;
                        longest_body = Some(longest_body.map_or(body, |b: u32| b.max(body)));
                    }
                    after
                }
                _ => after,
            });
        }
        let straight = steps.first().copied().unwrap_or(0);
        // The whole rule shares one iteration budget, so a back edge is crossed
        // at most `MAX_LOOP_ITERATIONS` times in total however many loops there
        // are; charging each crossing the *longest* body is therefore sound,
        // and exact when there is only one loop. Two instructions of slack per
        // crossing cover the `ForStep` itself and the `for_begin` that entered
        // the loop.
        let looping = longest_body.map_or(0, |body: u32| {
            body.saturating_add(2).saturating_mul(MAX_LOOP_ITERATIONS)
        });
        self.max_steps = straight.saturating_add(looping);

        let mut depth: i32 = 0;
        let mut peak: i32 = 0;
        for op in &self.code {
            depth = depth.saturating_add(op.stack_delta());
            peak = peak.max(depth);
        }
        self.max_stack = u32::try_from(peak.max(0)).unwrap_or(0);
    }

    /// Render the program as text.
    ///
    /// Used by `Debug`, by the CLI's rule-explaining mode, and by tests that
    /// want to assert on the shape of generated code without hard-coding
    /// instruction indices that shift whenever the compiler emits something
    /// extra.
    pub fn disassemble(&self) -> String {
        let mut out = String::new();
        for (index, op) in self.code.iter().enumerate() {
            let _ = writeln!(out, "{index:>4}  {}", self.render_op(op));
        }
        out
    }

    /// Render a single instruction with its operand resolved.
    pub fn render_op(&self, op: &Op) -> String {
        let constant = |i: u32| match self.constants.get(i as usize) {
            // Quoted text rather than the byte-list `{:?}` would give an
            // `Arc<[u8]>`: this is a disassembly a person reads, and the bytes
            // are a string literal in every case the compiler produces.
            Some(Const::Str(s)) => format!("{:?}", String::from_utf8_lossy(s)),
            Some(Const::Int(v)) => v.to_string(),
            Some(Const::Float(v)) => v.to_string(),
            Some(Const::Bool(v)) => v.to_string(),
            None => format!("<const {i} out of range>"),
        };
        match op {
            Op::Push(i) => format!("push {}({i})", constant(*i)),
            Op::Filesize => "filesize".into(),
            Op::EntryPoint => "entrypoint".into(),
            Op::ReadU8 => "read_u8".into(),
            Op::ReadU16 => "read_u16".into(),
            Op::ReadU32 => "read_u32".into(),
            Op::ReadI8 => "read_i8".into(),
            Op::ReadI16 => "read_i16".into(),
            Op::ReadI32 => "read_i32".into(),
            Op::ReadU16Be => "read_u16be".into(),
            Op::ReadU32Be => "read_u32be".into(),
            Op::ReadI16Be => "read_i16be".into(),
            Op::ReadI32Be => "read_i32be".into(),
            Op::StrMatch(i) => format!("str_match    ${i}"),
            Op::StrCount(i) => format!("str_count    ${i}"),
            Op::StrOffsetFirst(i) => format!("str_offset   ${i}"),
            Op::StrOffsetNth(i) => format!("str_offset_n ${i}"),
            Op::StrLenFirst(i) => format!("str_len      ${i}"),
            Op::StrLenNth(i) => format!("str_len_n    ${i}"),
            Op::StrAt(i) => format!("str_at       ${i}"),
            Op::StrIn(i) => format!("str_in       ${i}"),
            Op::OfAny(n) => format!("of_any       {n}"),
            Op::OfAll(n) => format!("of_all       {n}"),
            Op::OfNone(n) => format!("of_none      {n}"),
            Op::OfCount(n) => format!("of_count     {n}"),
            Op::ForBegin {
                var,
                end,
                acc,
                kind,
                done,
            } => format!(
                "for_begin    {} v{var} (end v{end}, acc v{acc}) -> {done}",
                kind.as_str()
            ),
            Op::ForEachBegin {
                var,
                end,
                acc,
                kind,
                done,
            } => format!(
                "for_each     {} v{var} (end v{end}, acc v{acc}) -> {done}",
                kind.as_str()
            ),
            Op::ForStep {
                var,
                acc,
                kind,
                back,
                ..
            } => format!("for_step     {} v{var} acc v{acc} -> {back}", kind.as_str()),
            Op::VarLoad(slot) => format!("var_load     v{slot}"),
            Op::RuleRef(index) => format!("rule_ref     r{index}"),
            Op::PeField(m) => format!("pe_field     {}", m.as_str()),
            Op::DotNetField(m) => format!("dotnet_field {}", m.as_str()),
            Op::DotNetIndexed(m) => format!("dotnet_index {}", m.as_str()),
            Op::PeIndexed(m) => format!("pe_indexed   {}", m.as_str()),
            Op::PeVersionInfo => "pe_verinfo".to_owned(),
            Op::Matches(index) => format!(
                "matches      /{}/",
                self.regexes
                    .get(*index as usize)
                    .map_or("?", |spec| spec.body.as_str())
            ),
            Op::PeCall(f) => format!("pe_call      {}", f.as_str()),
            Op::ModuleCall(f) => format!("module_call  {} ({})", f.as_str(), f.arity()),
            Op::Not => "not".into(),
            Op::Negate => "negate".into(),
            Op::BitNot => "bit_not".into(),
            Op::IsDefined => "is_defined".into(),
            Op::Add => "add".into(),
            Op::Sub => "sub".into(),
            Op::Mul => "mul".into(),
            Op::Div => "div".into(),
            Op::Mod => "mod".into(),
            Op::BitAnd => "bit_and".into(),
            Op::BitOr => "bit_or".into(),
            Op::BitXor => "bit_xor".into(),
            Op::Shl => "shl".into(),
            Op::Shr => "shr".into(),
            Op::Eq => "eq".into(),
            Op::Ne => "ne".into(),
            Op::Lt => "lt".into(),
            Op::Le => "le".into(),
            Op::Gt => "gt".into(),
            Op::Ge => "ge".into(),
            Op::Cmp(c) => c.as_str().into(),
            Op::Jump(t) => format!("jump         {t}"),
            Op::JumpIfFalse(t) => format!("jump_if_false {t}"),
            Op::JumpIfTrue(t) => format!("jump_if_true {t}"),
            Op::Ret => "ret".into(),
        }
    }
}

impl std::fmt::Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.disassemble())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undefined_is_false_and_every_comparison_against_it_is_false() {
        assert!(!Value::Undefined.is_truthy());
        assert!(Value::Undefined.is_undefined());
        // The point: a missing field must not read as zero.
        assert_ne!(Value::Undefined, Value::Int(0));
    }

    #[test]
    fn zero_and_the_empty_string_are_false() {
        assert!(!Value::Int(0).is_truthy());
        assert!(!Value::Float(0.0).is_truthy());
        assert!(!Value::Bytes(Arc::from(b"".as_slice())).is_truthy());
        assert!(!Value::Bool(false).is_truthy());
        assert!(Value::Int(1).is_truthy());
        assert!(Value::Int(-1).is_truthy());
        assert!(Value::Bytes(Arc::from(b"x".as_slice())).is_truthy());
    }

    #[test]
    fn booleans_convert_to_numbers_for_arithmetic() {
        assert_eq!(Value::Bool(true).as_number(), Some(1.0));
        assert_eq!(Value::Bool(false).as_number(), Some(0.0));
        assert_eq!(Value::Bytes(Arc::from(b"1".as_slice())).as_number(), None);
        assert_eq!(Value::Undefined.as_number(), None);
    }

    #[test]
    fn identical_constants_are_stored_once() {
        let mut p = Program::new(Span::new(0, 0));
        let a = p.constant(Const::Str(Arc::from(b"kernel32.dll".as_slice())));
        let b = p.constant(Const::Str(Arc::from(b"kernel32.dll".as_slice())));
        let c = p.constant(Const::Str(Arc::from(b"ntdll.dll".as_slice())));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(p.constants.len(), 2);
    }

    #[test]
    fn patching_rewrites_the_instruction_in_place() {
        let mut p = Program::new(Span::new(0, 0));
        let at = p.emit(Op::Jump(u32::MAX));
        p.emit(Op::Ret);
        p.patch(at, Op::Jump(p.here()));
        assert_eq!(p.code[0], Op::Jump(2));
    }

    #[test]
    fn patching_out_of_range_is_ignored_rather_than_panicking() {
        // A patch address comes from the compiler's own bookkeeping, so an
        // out-of-range one is a compiler bug — but the rule database is loaded
        // from disk, and a corrupt file must not be able to index arbitrarily.
        let mut p = Program::new(Span::new(0, 0));
        p.patch(99, Op::Ret);
        assert!(p.code.is_empty());
    }

    #[test]
    fn disassembly_resolves_constants() {
        let mut p = Program::new(Span::new(0, 0));
        let k = p.constant(Const::Str(Arc::from(b"MZ".as_slice())));
        p.emit(Op::Push(k));
        p.emit(Op::StrMatch(0));
        p.emit(Op::Eq);
        p.emit(Op::Ret);
        let text = p.disassemble();
        assert!(text.contains(r#"push "MZ"(0)"#), "{text}");
        assert!(text.contains("str_match    $0"), "{text}");
        assert!(text.contains("ret"), "{text}");
    }

    #[test]
    fn disassembly_survives_a_constant_index_that_is_out_of_range() {
        // Only reachable from a corrupt database, but the disassembler is the
        // tool used to diagnose exactly that, so it must not panic on it.
        let mut p = Program::new(Span::new(0, 0));
        p.emit(Op::Push(7));
        assert!(p.disassemble().contains("out of range"));
    }
}
