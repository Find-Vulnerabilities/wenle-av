//! The compiler: a rule's condition becomes bytecode.
//!
//! # What this compiles, and what it refuses
//!
//! Everything below is implemented for the constructs the engine's own rules
//! and the vast majority of third-party rules use:
//!
//! * constants, `filesize`, `entrypoint`, and the buffer readers `uint8`
//!   through `int32be`
//! * the whole arithmetic, bitwise, comparison and logic layer, with `and` and
//!   `or` short-circuiting
//! * every string reference: `$a`, `#a`, `@a`, `@a[i]`, `!a`, `!a[i]`,
//!   `$a at <offset>`, `$a in (<from>..<to>)`
//! * `N of <set>` with `any`, `all`, `none`, an integer count, and a
//!   percentage, over `them`, an explicit list, or a prefix wildcard
//!
//! What it refuses, it refuses *by name*, through [`CompileError::feature`].
//! That is deliberate: the way to decide what to implement next is to compile
//! ten thousand real rules and histogram the refusals, and a refusal that says
//! only "unsupported" cannot be counted. `examples/compile_ruleset.rs` does
//! exactly that.
//!
//! Refusing is always safe. A rule that does not compile does not enter the
//! database, so it can never contribute a false positive; the cost of a gap is
//! a detection that does not fire, which is visible in the histogram and
//! fixable. The one thing this must never do is compile a construct to
//! something that *almost* means the same thing — a rule that fires when its
//! source says it should not is how an antivirus deletes a user's files.
//!
//! # Short-circuiting
//!
//! `a and b` must not evaluate `b` when `a` is false, and not only because the
//! language says so. `pe.is_dll() and $config` costs a module parse for the
//! second operand; `$a and pe.imphash() == "..."` costs one for the first. The
//! compiler emits a jump over the unevaluated half, and both paths push exactly
//! one boolean so that whatever follows sees a stack of the same height either
//! way.

mod corpus;
mod error;
mod required;
mod strings;

pub use corpus::{compile_corpus, Corpus};
pub use error::CompileError;
pub use required::required_slots;
pub use strings::StringTable;

use std::collections::BTreeMap;

use crate::ast::{
    ArithOp, BitOp, CmpOp, Expr, MemberPath, PathSegment, Quantifier, Rule, Span, StringOp,
};
use crate::program::{
    Cmp, Const, DotNetElement, DotNetField, LoopKind, ModuleFunc, Op, PeElement, PeField, PeFunc,
    Program, RegexSpec,
};
use av_core::HashKind;

/// Deepest expression nesting the compiler will descend.
///
/// The parser already bounds what it builds (`parser::MAX_DEPTH`), and this is
/// the same guard applied at the other end. It is here because compiling
/// recurses exactly as hard as parsing did, so a tree that reached the compiler
/// without going through the parser — an importer, a test, a future editor —
/// would otherwise walk straight past the guard that exists for this purpose
/// and overflow the stack anyway.
///
/// It is *lower* than the parser's bound because a compiler frame is larger
/// than a parser frame. Measured on a debug build against a one-megabyte stack,
/// over a left-nested `or` chain: 72 terms compile and 73 overflow, so one
/// level — `compile` into `compile_inner` into `compile_or` and back — costs
/// about fourteen kilobytes, and a megabyte carries only those 72.
///
/// The bound used to be 128, which is a number a one-megabyte stack cannot
/// reach. That made it useless in the way that matters: it did not fire, because
/// the stack was already gone by the time the depth counter got there. A rule
/// with 87 `or` terms in a 10,764-rule third-party set is what demonstrated it.
/// 32 is less than half of what the measurement allows.
///
/// A long `or` or `and` chain does not arrive here deep in the first place —
/// the parser folds those into balanced trees, so five hundred alternatives
/// descend nine levels. What this bound is left to catch is a long chain of an
/// operator that cannot be re-bracketed, `a - b - c - ...` and its kind, which
/// no real rule writes.
const MAX_DEPTH: u32 = 32;

/// `math.MEAN_BYTES` — the mean of an evenly distributed sample of all 256 byte
/// values, and the reference mean the module's own examples use.
///
/// The exact value is not arbitrary: `(Σ b) / 256` over `0..=255` is `127.5`,
/// and it is the point at which [`av_core::stats::deviation`] answers exactly
/// `64.0` for such a sample — the number in the module's documentation. A
/// constant that were merely close would make every rule written against that
/// example land on the far side of its own threshold.
const MEAN_BYTES: f64 = 127.5;

/// How `math.MEAN_BYTES` is spelled.
const MEAN_BYTES_NAME: &str = "MEAN_BYTES";

/// The rule names a condition may refer to, and the index each one means.
///
/// A bare name in a condition is either a `for` loop's variable or another
/// rule's name; this is the second half of that. The index is the rule's
/// position in the corpus the caller compiled, which is also the position in
/// the result array the scanner fills in as it evaluates — so the map is what
/// ties a name in the source to a slot in the scan.
///
/// Built before anything is compiled, from the names alone, because a rule may
/// be named by a rule that appears before it in the file.
#[derive(Debug, Clone, Default)]
pub struct RuleRefs {
    /// First index for each name. A name defined twice keeps its first index
    /// and is listed in `duplicates`, and a reference to it is refused rather
    /// than silently resolved to one of the two definitions.
    index: BTreeMap<String, u32>,
    /// Names defined by more than one rule, in sorted order.
    duplicates: Vec<String>,
}

impl RuleRefs {
    /// An empty table: no name is a rule, so every bare name is a loop
    /// variable or a typo.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build the table from a corpus.
    pub fn from_rules(rules: &[Rule]) -> Self {
        Self::from_names(rules.iter().map(|rule| rule.name.as_str()))
    }

    /// Build the table from rule names.
    pub fn from_names<'a, I>(names: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut index: BTreeMap<String, u32> = BTreeMap::new();
        let mut duplicates = Vec::new();
        for (position, name) in names.into_iter().enumerate() {
            let position = position as u32;
            match index.get(name) {
                Some(_) => {
                    let name = name.to_string();
                    if !duplicates.contains(&name) {
                        duplicates.push(name);
                    }
                }
                None => {
                    index.insert(name.to_string(), position);
                }
            }
        }
        duplicates.sort();
        Self { index, duplicates }
    }

    /// The index of the rule a name refers to, or `None`.
    pub fn get(&self, name: &str) -> Option<u32> {
        self.index.get(name).copied()
    }

    /// Whether the name is defined by more than one rule.
    ///
    /// A reference to such a name is refused, because the corpus does not say
    /// which of the definitions was meant and picking one would be inventing
    /// an answer.
    pub fn is_duplicate(&self, name: &str) -> bool {
        self.duplicates.iter().any(|d| d == name)
    }

    /// Every name defined more than once, sorted.
    pub fn duplicates(&self) -> &[String] {
        &self.duplicates
    }

    /// How many rules the table can name.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

/// Compile a rule's condition.
///
/// A rule that refers to another rule cannot be compiled this way — the name
/// has nothing to resolve against — so any bare name that is not a loop
/// variable is refused. Use [`compile_rule_with`] with a [`RuleRefs`] built
/// from the corpus, or [`compile_corpus`] to compile the whole set at once.
pub fn compile_rule(rule: &Rule) -> Result<Program, CompileError> {
    compile_rule_with(rule, &RuleRefs::empty())
}

/// Compile a rule's condition with a table of the rule names it may use.
pub fn compile_rule_with(rule: &Rule, refs: &RuleRefs) -> Result<Program, CompileError> {
    compile_condition_with(
        &rule.condition,
        &StringTable::from_defs(&rule.strings),
        rule.span,
        refs,
    )
}

/// Compile a condition against a set of string definitions.
///
/// `span` is reported in errors; the AST does not carry one per node.
///
/// The resulting program carries `string_count` from the table, and that field
/// is what the scanner sizes its match table from. Leaving it to the caller
/// would be a trap rather than an inconvenience: a program compiled here with a
/// zero count silently drops every match it is handed, so a rule with strings
/// would evaluate as though none of them were present and never fire — with no
/// error anywhere to say why.
pub fn compile_condition(
    condition: &Expr,
    strings: &StringTable,
    span: Span,
) -> Result<Program, CompileError> {
    compile_condition_with(condition, strings, span, &RuleRefs::empty())
}

/// Compile a condition, allowing bare names to refer to other rules.
///
/// `refs` is the corpus's name table; see [`RuleRefs`]. The two entry points
/// differ only in it, and the one without a table is the one that refuses every
/// rule reference — which is the correct reading for a caller scanning a single
/// rule, where there is no corpus for a name to mean anything in.
pub fn compile_condition_with(
    condition: &Expr,
    strings: &StringTable,
    span: Span,
    refs: &RuleRefs,
) -> Result<Program, CompileError> {
    let mut compiler = Compiler {
        program: Program::new(span),
        strings,
        span,
        depth: 0,
        vars: Vec::new(),
        next_slot: 0,
        peak_slots: 0,
        refs,
    };
    compiler.compile(condition)?;
    compiler.program.emit(Op::Ret);
    compiler.program.compute_limits();
    compiler.program.string_count = u32::try_from(strings.len())
        .map_err(|_| CompileError::too_many_strings(strings.len(), span))?;
    // The high-water mark, not the count of loops: slots are reused between
    // loops that cannot be live together, and the interpreter sizes its
    // register file from this once per rule.
    compiler.program.var_slots = compiler.peak_slots;
    // What the condition cannot be true without, for the prefilter. Computed
    // here rather than by whoever builds a rule database because this is the
    // last point at which the condition is still an AST — after this it is
    // bytecode, and recovering the conjunction from jumps is a different and
    // much harder problem.
    compiler.program.required_strings = required_slots(condition, strings);
    Ok(compiler.program)
}

/// One `for` loop variable that is in scope.
///
/// The array is carried alongside the slot because a name bound by `for any s
/// in pe.sections` means something different from one bound by `for any i in
/// (0..9)`: the first can be written `s.name`, and the second cannot be written
/// `i.name` at all. Which members a name offers is decided by what it iterates,
/// so the binding has to remember that and not only where the value is kept.
#[derive(Debug, Clone)]
struct Binding {
    name: String,
    slot: u32,
    /// The module array this variable indexes, or `None` for a range loop.
    array: Option<ArrayKind>,
}

/// A module array that `for <var> in pe.<array>` can walk.
///
/// Only the four whose elements the interpreter can actually read are listed.
/// A loop over an array whose members all answered `Undefined` would compile,
/// load, run, and never be true — a detection that silently does not fire,
/// which is the failure this engine is arranged to avoid above all others. So
/// an array outside this list is refused where the rule's author sees the
/// message, rather than accepted and quietly inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArrayKind {
    Sections,
    DataDirectories,
    Signatures,
    Resources,
    ExportDetails,
}

impl ArrayKind {
    /// The array a `pe.<name>` path names, or `None` if it is not one.
    fn of(root: &str, name: &str) -> Option<Self> {
        if root != "pe" {
            return None;
        }
        Some(match name {
            "sections" => ArrayKind::Sections,
            "data_directories" => ArrayKind::DataDirectories,
            "signatures" => ArrayKind::Signatures,
            "resources" => ArrayKind::Resources,
            "export_details" => ArrayKind::ExportDetails,
            _ => return None,
        })
    }

    /// The `pe` field holding how many elements the array has.
    ///
    /// Read through the ordinary field opcode rather than a length opcode of
    /// its own, because these counts are members of the language in their own
    /// right — the corpus writes `pe.number_of_resources >= 13` — and a loop
    /// that obtained the same number by another route would be a second
    /// implementation of it. Two implementations of one number can disagree,
    /// and this one is the bound of an array walk.
    fn length_field(self) -> PeField {
        match self {
            ArrayKind::Sections => PeField::NumberOfSections,
            // The number of data directories *is* the size of the array, which
            // is what `pe.number_of_rva_and_sizes` reports.
            ArrayKind::DataDirectories => PeField::NumberOfRvaAndSizes,
            ArrayKind::Signatures => PeField::NumberOfSignatures,
            ArrayKind::Resources => PeField::NumberOfResources,
            // The address table's size, which is what `pe.number_of_exports`
            // reports. That the array is the *address* table and not the name
            // table is what makes this pairing right rather than merely
            // convenient; see `av_pe::exports::ExportDetail`.
            ArrayKind::ExportDetails => PeField::NumberOfExports,
        }
    }

    /// How the array is written in a rule, for diagnostics.
    fn name(self) -> &'static str {
        match self {
            ArrayKind::Sections => "sections",
            ArrayKind::DataDirectories => "data_directories",
            ArrayKind::Signatures => "signatures",
            ArrayKind::Resources => "resources",
            ArrayKind::ExportDetails => "export_details",
        }
    }
}

/// The module array a `for ... in` iterable names, if it names one.
///
/// The iterable has to be the whole array — `pe.resources` — and not an element
/// of one: `for any r in pe.resources[0]` is a loop over nothing, and requiring
/// the path to be exactly `pe.<name>` is what stops it being read as one.
fn iterable_array(iterable: &Expr) -> Option<ArrayKind> {
    let Expr::Field { path } = iterable else {
        return None;
    };
    match path.segments.as_slice() {
        [PathSegment::Field(name)] => ArrayKind::of(&path.root, name),
        _ => None,
    }
}

struct Compiler<'a> {
    program: Program,
    strings: &'a StringTable,
    span: Span,
    depth: u32,
    /// The loop variables that are in scope, innermost last.
    ///
    /// A stack rather than a map because a name may be shadowed by an inner
    /// loop, and because the only question ever asked of it is "which slot does
    /// this name mean here", which is a search from the top.
    vars: Vec<Binding>,
    /// First slot not yet allocated.
    ///
    /// Rises while loops nest and is rolled back when one ends, so two loops
    /// that cannot be live at the same time share their slots.
    next_slot: u32,
    /// The rule names a bare name may resolve to, and the index each means.
    ///
    /// Empty for a single-rule compilation, which makes every rule reference a
    /// refusal rather than a guess.
    refs: &'a RuleRefs,
    /// The most slots that were ever allocated at once.
    ///
    /// Kept separately from `next_slot` precisely because that one goes back
    /// down: reading the register-file size off it after the last loop has been
    /// rolled back would report zero, and the interpreter sizes its registers
    /// from this — so every loop would fail on a slot that does not exist.
    peak_slots: u32,
}

impl Compiler<'_> {
    fn compile(&mut self, expr: &Expr) -> Result<(), CompileError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            return Err(CompileError::unsupported(
                "expression nesting",
                "condition nests deeper than the compiler will descend",
                self.span,
            ));
        }
        let result = self.compile_inner(expr);
        self.depth -= 1;
        result
    }

    fn compile_inner(&mut self, expr: &Expr) -> Result<(), CompileError> {
        match expr {
            Expr::Bool(b) => {
                let k = self.program.constant(Const::Bool(*b));
                self.program.emit(Op::Push(k));
            }
            Expr::Int(i) => {
                let k = self.program.constant(Const::Int(*i));
                self.program.emit(Op::Push(k));
            }
            Expr::Float(x) => {
                let k = self.program.constant(Const::Float(*x));
                self.program.emit(Op::Push(k));
            }
            Expr::Str(s) => {
                let k = self.program.constant(Const::Str(s.as_slice().into()));
                self.program.emit(Op::Push(k));
            }

            Expr::Filesize => {
                self.program.emit(Op::Filesize);
            }
            Expr::EntryPoint => {
                self.program.emit(Op::EntryPoint);
            }

            // -- string references ------------------------------------------
            Expr::StringMatch(name) => {
                let slot = self.slot(name)?;
                self.program.emit(Op::StrMatch(slot));
            }
            Expr::StringCount(name) => {
                let slot = self.slot(name)?;
                self.program.emit(Op::StrCount(slot));
            }
            Expr::StringAt(name, offset) => {
                let slot = self.slot(name)?;
                self.compile(offset)?;
                self.program.emit(Op::StrAt(slot));
            }
            Expr::StringIn(name, from, to) => {
                let slot = self.slot(name)?;
                self.compile(from)?;
                self.compile(to)?;
                self.program.emit(Op::StrIn(slot));
            }
            Expr::StringOffset(name, index) => {
                let slot = self.slot(name)?;
                match index {
                    Some(i) => {
                        self.compile(i)?;
                        self.program.emit(Op::StrOffsetNth(slot));
                    }
                    None => {
                        self.program.emit(Op::StrOffsetFirst(slot));
                    }
                }
            }
            Expr::StringLength(name, index) => {
                let slot = self.slot(name)?;
                match index {
                    Some(i) => {
                        self.compile(i)?;
                        self.program.emit(Op::StrLenNth(slot));
                    }
                    None => {
                        self.program.emit(Op::StrLenFirst(slot));
                    }
                }
            }

            // -- string sets -------------------------------------------------
            Expr::Of { quantifier, set } => {
                let (slots, rendered) = self.strings.expand(set);
                if slots.is_empty() {
                    return Err(CompileError::empty_set(&rendered, self.span));
                }
                self.compile_of(quantifier, &slots)?;
            }
            Expr::OfIn {
                quantifier,
                set,
                from,
                to,
            } => {
                let (slots, rendered) = self.strings.expand(set);
                if slots.is_empty() {
                    return Err(CompileError::empty_set(&rendered, self.span));
                }
                self.compile_of_in(quantifier, &slots, from, to)?;
            }

            // -- logic -------------------------------------------------------
            Expr::Not(inner) => {
                self.compile(inner)?;
                self.program.emit(Op::Not);
            }
            Expr::Defined(inner) => {
                self.compile(inner)?;
                self.program.emit(Op::IsDefined);
            }
            Expr::And(a, b) => self.compile_and(a, b)?,
            Expr::Or(a, b) => self.compile_or(a, b)?,

            // -- operators ---------------------------------------------------
            Expr::Arithmetic { op, lhs, rhs } => {
                self.compile(lhs)?;
                self.compile(rhs)?;
                self.program.emit(arith_op(*op));
            }
            Expr::Bitwise { op, lhs, rhs } => {
                self.compile(lhs)?;
                self.compile(rhs)?;
                self.program.emit(bit_op(*op));
            }
            Expr::Compare { op, lhs, rhs } => {
                self.compile(lhs)?;
                self.compile(rhs)?;
                self.program.emit(cmp_op(*op));
            }
            Expr::Negate(inner) => {
                self.compile(inner)?;
                self.program.emit(Op::Negate);
            }
            Expr::BitNot(inner) => {
                self.compile(inner)?;
                self.program.emit(Op::BitNot);
            }
            Expr::StringOp { op, lhs, rhs } => {
                // `matches` is the one of these that does not compile to a
                // comparison. Its right-hand side is a pattern rather than a
                // value, so it is compiled here and indexed by the opcode; the
                // other five are two-operand predicates.
                if *op == StringOp::Matches {
                    return self.compile_matches(lhs, rhs);
                }
                let Some(op) = string_op(*op) else {
                    return Err(CompileError::unsupported(
                        "regex",
                        "`matches` needs the regular expression engine",
                        self.span,
                    ));
                };
                self.compile(lhs)?;
                self.compile(rhs)?;
                self.program.emit(op);
            }

            // -- calls -------------------------------------------------------
            Expr::Call { path, args } => self.compile_call(expr, path, args)?,

            // -- refused, by name --------------------------------------------
            Expr::Regex { .. } => {
                return Err(CompileError::unsupported(
                    "regex",
                    "a `/regex/` literal outside `matches`",
                    self.span,
                ));
            }
            Expr::Field { path } => {
                // A loop variable's member first: `s.name` inside `for any s in
                // pe.sections` is a path whose root is not a module, and the
                // check is a search of the bindings rather than of the module
                // tables, so it is the cheaper of the two as well as the one
                // that has to win when a loop variable happens to be named
                // `pe`.
                if self.compile_loop_element(path)? {
                    return Ok(());
                }
                if !self.compile_module_path(path)? {
                    return Err(CompileError::unsupported(
                        "module field",
                        path.render(),
                        self.span,
                    ));
                }
            }
            Expr::Index { .. } => {
                return Err(CompileError::unsupported(
                    "index",
                    "indexing a module array",
                    self.span,
                ));
            }
            // A bare name is one of two things, and which one is decided by
            // scope rather than by spelling: inside a `for` body it is that
            // loop's variable, and anywhere else it is another rule. The loop
            // wins, because a loop's variable is the nearer binding — a rule
            // named `i` does not make `i` inside `for any i in (0..3)` mean the
            // rule.
            Expr::Variable(name) => {
                if let Some(slot) = self.variable(name) {
                    self.program.emit(Op::VarLoad(slot));
                } else if let Some(index) = self.refs.get(name) {
                    self.program.emit(Op::RuleRef(index));
                } else {
                    return Err(CompileError::unsupported(
                        "unresolved name",
                        format!(
                            "`{name}` is not a loop variable in scope and not a rule \
                             in this set — a reference to a rule defined elsewhere, or \
                             a typo, and neither can be guessed at"
                        ),
                        self.span,
                    ));
                }
            }
            Expr::ForOfPlaceholder => {
                return Err(CompileError::unsupported(
                    "`$` placeholder",
                    "`$` is only meaningful inside `for ... of`",
                    self.span,
                ));
            }
            Expr::ForOf { .. } => {
                return Err(CompileError::unsupported(
                    "for .. of",
                    "iterating the matches of a string set",
                    self.span,
                ));
            }
            Expr::ForIn {
                quantifier,
                var,
                from,
                to,
                body,
            } => self.compile_for_in(quantifier, var, from, to, body)?,
            Expr::ForEach {
                quantifier,
                var,
                iterable,
                body,
            } => self.compile_for_each(quantifier, var, iterable, body)?,
        }
        Ok(())
    }

    fn compile_call(
        &mut self,
        whole: &Expr,
        path: &crate::ast::MemberPath,
        args: &[Expr],
    ) -> Result<(), CompileError> {
        // `uint16(0)`. A reader is the only builtin compiled so far, and it is
        // worth having early: the buffer readings appear in thousands of real
        // rules, more than every other builtin combined.
        if path.segments.is_empty() {
            if let Some(op) = read_builtin(&path.root) {
                let Some(arg) = single_arg(args) else {
                    return Err(CompileError::unsupported(
                        "function call",
                        format!("`{}(...)` takes exactly one offset", path.root),
                        self.span,
                    ));
                };
                self.compile(arg)?;
                self.program.emit(op);
                return Ok(());
            }
        }
        if let Some(func) = Self::pe_function(path) {
            // A range rather than a count, because `pe.imports` takes either
            // one argument or two. Refusing the one-argument form would lose the
            // seventeen `pe.imports ( "ADVAPI32.dll" )` checks in a single rule.
            let (min, max) = func.arity_range();
            if args.len() < min as usize || args.len() > max as usize {
                let wanted = if min == max {
                    format!("{min} argument(s)")
                } else {
                    format!("{min} or {max} arguments")
                };
                return Err(CompileError::unsupported(
                    "function call",
                    format!("`{}` takes {wanted}", func.as_str()),
                    self.span,
                ));
            }
            for arg in args {
                self.compile(arg)?;
            }
            // The variant for this argument count, which for everything but
            // `pe.imports` is the one the lookup already returned.
            self.program
                .emit(Op::PeCall(func.for_arity(args.len() as u32)));
            return Ok(());
        }
        // `hash.<algorithm>`, whose argument count decides which operation it
        // is rather than only how many operands to pop. One argument is a
        // string and two are a region, so the two forms are separate variants
        // and the choice is made here, where the count is known.
        if let Some(kind) = Self::hash_algorithm(path) {
            let func = match args.len() {
                1 => ModuleFunc::HashStr(kind),
                2 => ModuleFunc::HashRange(kind),
                n => {
                    return Err(CompileError::unsupported(
                        "function call",
                        format!(
                            "`hash.{}` takes either a string to hash or an offset and a size, \
                             and {n} arguments were given",
                            kind.as_str()
                        ),
                        self.span,
                    ));
                }
            };
            for arg in args {
                self.compile(arg)?;
            }
            self.program.emit(Op::ModuleCall(func));
            return Ok(());
        }
        // The `math` and `string` modules, which take their argument count for
        // the same reason `hash` does: a name with two forms is two opcodes.
        let named = Self::math_function(path, args.len())
            .or_else(|| Self::string_function(path, args.len()));
        if let Some(func) = named {
            let arity = func.arity() as usize;
            if args.len() != arity {
                return Err(CompileError::unsupported(
                    "function call",
                    format!(
                        "`{}` takes {arity} argument(s) and {} were given",
                        func.as_str(),
                        args.len()
                    ),
                    self.span,
                ));
            }
            for arg in args {
                self.compile(arg)?;
            }
            self.program.emit(Op::ModuleCall(func));
            return Ok(());
        }
        let _ = whole;
        Err(CompileError::unsupported(
            "function call",
            path.render(),
            self.span,
        ))
    }

    /// The algorithm of a `hash.<name>` path, or `None` if the path is not one.
    ///
    /// Separate from the call compilation because a `hash` *member* is not a
    /// thing: every name in the module is a function, so a path that resolves
    /// here and is then called with the wrong number of arguments is a mistake
    /// worth its own message rather than a bare "unknown function".
    ///
    /// `hash.crc32` is deliberately absent and therefore refused by name. See
    /// [`ModuleFunc`] for why a checksum whose textual form is a choice is not
    /// compiled.
    fn hash_algorithm(path: &MemberPath) -> Option<HashKind> {
        if path.root != "hash" {
            return None;
        }
        let [PathSegment::Field(name)] = path.segments.as_slice() else {
            return None;
        };
        match name.as_str() {
            "md5" => Some(HashKind::Md5),
            "sha1" => Some(HashKind::Sha1),
            "sha256" => Some(HashKind::Sha256),
            _ => None,
        }
    }

    /// The `math` function a path names with `argc` arguments, or `None`.
    ///
    /// The argument count is a parameter rather than checked afterwards because
    /// `math.deviation` is one name with two forms — a region and a mean, or a
    /// decoded string and a mean — and the two are different opcodes. Everything
    /// else here ignores it; the check against [`ModuleFunc::arity`] happens at
    /// the call site, where the message can name the arity the function wanted.
    ///
    /// Absent, and therefore refused by name: `math.mode`,
    /// `math.serial_correlation` and `math.monte_carlo_pi`. Each is a statistic
    /// whose value depends on a normalization or a tie-break that is a choice
    /// rather than a consequence of the input, and the corpus's thresholds were
    /// calibrated against a particular set of those choices. Compiling a
    /// different one would not produce a slightly different number; it would
    /// produce a rule that fires on files its author wrote it to exclude.
    ///
    /// `math.min` and `math.max` take two arguments rather than a region, which
    /// is why they are not grouped with the region statistics in the reader's
    /// mind even though they are grouped here. The corpus uses `math.min` to
    /// clamp a string count — `for any i in (0 .. math.min(#s1, 100))` — which
    /// is the shape they exist for.
    fn math_function(path: &MemberPath, argc: usize) -> Option<ModuleFunc> {
        if path.root != "math" {
            return None;
        }
        let [PathSegment::Field(name)] = path.segments.as_slice() else {
            return None;
        };
        Some(match name.as_str() {
            "entropy" => ModuleFunc::Entropy,
            "mean" => ModuleFunc::Mean,
            "count" => ModuleFunc::Count,
            "percentage" => ModuleFunc::Percentage,
            "min" => ModuleFunc::Min,
            "max" => ModuleFunc::Max,
            "abs" => ModuleFunc::Abs,
            "to_number" => ModuleFunc::ToNumber,
            "in_range" => ModuleFunc::InRange,
            // Two arguments: a string and a mean. Three: a region and a mean.
            // Any other count falls through to the arity check, which reports
            // the count the *two*-argument form wanted — the smaller of the two,
            // and the one a reader who wrote one argument probably meant.
            "deviation" => match argc {
                2 => ModuleFunc::DeviationStr,
                _ => ModuleFunc::Deviation,
            },
            _ => return None,
        })
    }

    /// The `string` function a path names with `argc` arguments, or `None`.
    ///
    /// The module's own members are what a rule reaches for when a `pe` field
    /// gives it bytes in no encoding at all — `pe.resources[i].name_string` is
    /// raw UTF-16LE — and it needs a number out of them.
    ///
    /// `string.to_int` is one name with two forms, like `math.deviation`, and
    /// for the same reason: the base is either inferred from the literal or
    /// named by the rule.
    fn string_function(path: &MemberPath, argc: usize) -> Option<ModuleFunc> {
        if path.root != "string" {
            return None;
        }
        let [PathSegment::Field(name)] = path.segments.as_slice() else {
            return None;
        };
        Some(match name.as_str() {
            "length" => ModuleFunc::StringLength,
            "to_int" => match argc {
                2 => ModuleFunc::StringToIntBase,
                _ => ModuleFunc::StringToInt,
            },
            _ => return None,
        })
    }

    /// Compile `pe.<...>`, or report that this path is not one the compiler
    /// knows.
    ///
    /// A `false` return means nothing was emitted, so the caller can fall back
    /// to refusing the whole path under its own tag — which is what keeps the
    /// refusal histogram counting `pe.number_of_signatures` rather than
    /// silently dropping it.
    ///
    /// # What is deliberately absent
    ///
    /// Every member that the parser accepts and the engine cannot yet answer.
    /// `pe.number_of_signatures` is the largest of them by far and stays out
    /// until Authenticode parsing exists, because a member compiled to a
    /// constant zero would make every rule that names it stop matching while
    /// still appearing to be supported — the failure mode this whole design is
    /// arranged to prevent.
    fn compile_module_path(&mut self, path: &MemberPath) -> Result<bool, CompileError> {
        // `math.MEAN_BYTES`, the only non-`pe` member any module has. It is a
        // constant rather than a member read from the file — `127.5`, the mean
        // of an evenly distributed sample of all 256 byte values — and it is
        // here rather than in `pe_constant` because that function's whole
        // contract is that it answers about the `pe` module.
        if path.root == "math" {
            if let [PathSegment::Field(name)] = path.segments.as_slice() {
                if name == MEAN_BYTES_NAME {
                    let k = self.program.constant(Const::Float(MEAN_BYTES));
                    self.program.emit(Op::Push(k));
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        if path.root == "dotnet" {
            return self.compile_dotnet_path(path);
        }
        if path.root != "pe" {
            return Ok(false);
        }
        match path.segments.as_slice() {
            [PathSegment::Field(name)] => {
                // A constant first: `pe.DLL` and `pe.machine` are both single
                // field paths and the name is what tells them apart, so the
                // order between these two lookups is the whole distinction.
                if let Some(value) = Self::pe_constant(name) {
                    let k = self.program.constant(Const::Int(value));
                    self.program.emit(Op::Push(k));
                    return Ok(true);
                }
                match Self::pe_field(name) {
                    Some(member) => {
                        self.program.emit(Op::PeField(member));
                        Ok(true)
                    }
                    None => Ok(false),
                }
            }
            [PathSegment::Field(struct_name), PathSegment::Field(member)] => {
                // A member of a plain struct: `pe.linker_version.major`,
                // `pe.overlay.offset`. These carry no index, so they compile to
                // the same [`Op::PeField`] a bare member does.
                match Self::pe_struct_field(struct_name, member) {
                    Some(field) => {
                        self.program.emit(Op::PeField(field));
                        Ok(true)
                    }
                    None => Ok(false),
                }
            }
            // `pe.version_info["CompanyName"]` — a module array indexed by a
            // string. Read from the version resource rather than from a table in
            // the header, so it is not a [`PeElement`] and does not share the arm
            // below.
            [PathSegment::Field(array), PathSegment::Index(index)] if array == "version_info" => {
                // Compiled only after the name is known good, for the same reason
                // the arm below compiles its index late: a refusal must not leave
                // half an expression on the stack.
                self.compile(index)?;
                self.program.emit(Op::PeVersionInfo);
                Ok(true)
            }
            [PathSegment::Field(array), PathSegment::Index(index), PathSegment::Field(member)] => {
                let Some(element) = Self::pe_element(array, member) else {
                    return Ok(false);
                };
                // The index is compiled only after the member is known good, so
                // that a refusal here cannot leave half an expression on the
                // stack for the caller's fallback to trip over.
                self.compile(index)?;
                self.program.emit(Op::PeIndexed(element));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// `dotnet.<...>` — the managed-metadata module.
    ///
    /// The `pe` arms' shape, and their ordering rule: the member is resolved
    /// *before* the index is compiled, so that a refusal cannot leave half an
    /// expression on the stack for the caller's fallback to trip over.
    ///
    /// # What is deliberately absent
    ///
    /// `dotnet.guids`, `dotnet.streams` and `dotnet.user_strings` — the three
    /// members of YARA's module this reader does not produce — and
    /// `dotnet.assembly.name` / `dotnet.assembly.culture`, which the reader
    /// *does* have and no rule in the validated corpus asks for. A member that
    /// compiled to a constant would make every rule naming it stop matching
    /// while still looking supported, which is the failure this design exists to
    /// prevent.
    fn compile_dotnet_path(&mut self, path: &MemberPath) -> Result<bool, CompileError> {
        match path.segments.as_slice() {
            [PathSegment::Field(name)] => match Self::dotnet_field(name) {
                Some(member) => {
                    self.program.emit(Op::DotNetField(member));
                    Ok(true)
                }
                None => Ok(false),
            },
            // `dotnet.assembly.version.major` — three segments, because the
            // assembly's identity is a struct inside a struct. `pe` has no
            // three-segment arm to copy from, so this one stands alone rather
            // than being folded into the two-segment one: a name is matched
            // against `assembly.version` and not against `assembly`, and
            // `dotnet.assembly.version` on its own is not a value.
            [PathSegment::Field(outer), PathSegment::Field(inner), PathSegment::Field(member)]
                if outer == "assembly" && inner == "version" =>
            {
                match DotNetField::assembly_version(member) {
                    Some(field) => {
                        self.program.emit(Op::DotNetField(field));
                        Ok(true)
                    }
                    None => Ok(false),
                }
            }
            [PathSegment::Field(array), PathSegment::Index(index), PathSegment::Field(member)] => {
                let Some(element) = Self::dotnet_element(array, member) else {
                    return Ok(false);
                };
                self.compile(index)?;
                self.program.emit(Op::DotNetIndexed(element));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// The `dotnet` member a bare field name means, or `None` if it is not
    /// implemented.
    fn dotnet_field(name: &str) -> Option<DotNetField> {
        Some(match name {
            "is_dotnet" => DotNetField::IsDotNet,
            "version" => DotNetField::Version,
            "number_of_resources" => DotNetField::NumberOfResources,
            // The version quad is reached through `dotnet.assembly.version.*`
            // and deliberately not through a bare name: `dotnet.version` is the
            // *runtime* version string and `dotnet.assembly.version` is the
            // assembly's own four numbers, and two members whose names differ by
            // one segment are exactly the pair a reader gets wrong.
            _ => return None,
        })
    }

    /// The `dotnet` member an indexed path means, or `None`.
    fn dotnet_element(array: &str, member: &str) -> Option<DotNetElement> {
        match (array, member) {
            ("assembly_refs", "name") => Some(DotNetElement::AssemblyRefName),
            ("resources", "name") => Some(DotNetElement::ResourceName),
            ("resources", "length") => Some(DotNetElement::ResourceLength),
            // `dotnet.assembly_refs[i].version.major` is a four-segment path
            // through a struct inside an array element, and no rule in the
            // corpus writes one — see `compile_dotnet_path`.
            _ => None,
        }
    }

    /// The value of a `pe` constant, or `None` if the name is not one.
    ///
    /// Constants are pushed as literals rather than stored as members, because
    /// they do not depend on the file: `pe.DLL` is `0x2000` for every input, and
    /// an opcode that read a constant from the `pe` module would put a lookup
    /// between a rule and a number known at compile time.
    ///
    /// They are still *implemented* rather than folded away by the parser, and
    /// the list is exhaustive over what YARA declares, because a rule using an
    /// unknown constant must be refused rather than have the name read as a
    /// typo'd member.
    fn pe_constant(name: &str) -> Option<i64> {
        // Values are `IMAGE_*` from winnt.h, which is where YARA's come from.
        let value: i64 = match name {
            // -- machine types -------------------------------------------------
            "MACHINE_UNKNOWN" => 0x0000,
            "MACHINE_AM33" => 0x01d3,
            "MACHINE_AMD64" => 0x8664,
            "MACHINE_ARM" => 0x01c0,
            "MACHINE_ARMNT" => 0x01c4,
            "MACHINE_ARM64" => 0xaa64,
            "MACHINE_EBC" => 0x0ebc,
            "MACHINE_I386" => 0x014c,
            "MACHINE_IA64" => 0x0200,
            "MACHINE_M32R" => 0x9041,
            "MACHINE_MIPS16" => 0x0266,
            "MACHINE_MIPSFPU" => 0x0366,
            "MACHINE_MIPSFPU16" => 0x0466,
            "MACHINE_POWERPC" => 0x01f0,
            "MACHINE_POWERPCFP" => 0x01f1,
            "MACHINE_R4000" => 0x0166,
            "MACHINE_SH3" => 0x01a2,
            "MACHINE_SH3DSP" => 0x01a3,
            "MACHINE_SH4" => 0x01a6,
            "MACHINE_SH5" => 0x01a8,
            "MACHINE_THUMB" => 0x01c2,
            "MACHINE_WCEMIPSV2" => 0x0169,
            "MACHINE_TARGET_HOST" => 0x0001,
            "MACHINE_R3000" => 0x0162,
            "MACHINE_R10000" => 0x0168,
            "MACHINE_ALPHA" => 0x0184,
            "MACHINE_SH3E" => 0x01a4,
            "MACHINE_ALPHA64" => 0x0284,
            "MACHINE_AXP64" => 0x0284,
            "MACHINE_TRICORE" => 0x0520,
            "MACHINE_CEF" => 0x0cef,
            "MACHINE_CEE" => 0xc0ee,
            // -- subsystems -----------------------------------------------------
            "SUBSYSTEM_UNKNOWN" => 0,
            "SUBSYSTEM_NATIVE" => 1,
            "SUBSYSTEM_WINDOWS_GUI" => 2,
            "SUBSYSTEM_WINDOWS_CUI" => 3,
            "SUBSYSTEM_OS2_CUI" => 5,
            "SUBSYSTEM_POSIX_CUI" => 7,
            "SUBSYSTEM_NATIVE_WINDOWS" => 8,
            "SUBSYSTEM_WINDOWS_CE_GUI" => 9,
            "SUBSYSTEM_EFI_APPLICATION" => 10,
            "SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER" => 11,
            "SUBSYSTEM_EFI_RUNTIME_DRIVER" => 12,
            "SUBSYSTEM_EFI_ROM_IMAGE" => 13,
            "SUBSYSTEM_XBOX" => 14,
            "SUBSYSTEM_WINDOWS_BOOT_APPLICATION" => 16,
            // -- DLL characteristics --------------------------------------------
            "HIGH_ENTROPY_VA" => 0x0020,
            "DYNAMIC_BASE" => 0x0040,
            "FORCE_INTEGRITY" => 0x0080,
            "NX_COMPAT" => 0x0100,
            "NO_ISOLATION" => 0x0200,
            "NO_SEH" => 0x0400,
            "NO_BIND" => 0x0800,
            "APPCONTAINER" => 0x1000,
            "WDM_DRIVER" => 0x2000,
            "GUARD_CF" => 0x4000,
            "TERMINAL_SERVER_AWARE" => 0x8000,
            // -- file characteristics -------------------------------------------
            "RELOCS_STRIPPED" => 0x0001,
            "EXECUTABLE_IMAGE" => 0x0002,
            "LINE_NUMS_STRIPPED" => 0x0004,
            "LOCAL_SYMS_STRIPPED" => 0x0008,
            // Spelled with one `G` in winnt.h, and therefore in YARA too.
            "AGGRESIVE_WS_TRIM" => 0x0010,
            "LARGE_ADDRESS_AWARE" => 0x0020,
            "BYTES_REVERSED_LO" => 0x0080,
            "MACHINE_32BIT" => 0x0100,
            "DEBUG_STRIPPED" => 0x0200,
            "REMOVABLE_RUN_FROM_SWAP" => 0x0400,
            "NET_RUN_FROM_SWAP" => 0x0800,
            "SYSTEM" => 0x1000,
            "DLL" => 0x2000,
            "UP_SYSTEM_ONLY" => 0x4000,
            "BYTES_REVERSED_HI" => 0x8000,
            // -- data directory indices ------------------------------------------
            "IMAGE_DIRECTORY_ENTRY_EXPORT" => 0,
            "IMAGE_DIRECTORY_ENTRY_IMPORT" => 1,
            "IMAGE_DIRECTORY_ENTRY_RESOURCE" => 2,
            "IMAGE_DIRECTORY_ENTRY_EXCEPTION" => 3,
            "IMAGE_DIRECTORY_ENTRY_SECURITY" => 4,
            "IMAGE_DIRECTORY_ENTRY_BASERELOC" => 5,
            "IMAGE_DIRECTORY_ENTRY_DEBUG" => 6,
            "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE" => 7,
            "IMAGE_DIRECTORY_ENTRY_COPYRIGHT" => 7,
            "IMAGE_DIRECTORY_ENTRY_GLOBALPTR" => 8,
            "IMAGE_DIRECTORY_ENTRY_TLS" => 9,
            "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG" => 10,
            "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT" => 11,
            "IMAGE_DIRECTORY_ENTRY_IAT" => 12,
            "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT" => 13,
            "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR" => 14,
            // -- resource types --------------------------------------------------
            //
            // `RT_*` from winnt.h, which is where YARA's come from. The corpus
            // uses two of them, `RCDATA` and `VERSION`; the rest are here
            // because a rule that names `RT_ICON` should get the icon type and
            // not a refusal, and because the list is the format's and not a
            // judgement about which rules exist.
            //
            // Note that these are the *id* form. A resource whose type level is
            // the name `"10"` is a different resource from one whose type is the
            // id 10, and `pe.resources[i].type` is `Undefined` for it — which is
            // why comparing against one of these cannot match it by accident.
            "RESOURCE_TYPE_CURSOR" => 1,
            "RESOURCE_TYPE_BITMAP" => 2,
            "RESOURCE_TYPE_ICON" => 3,
            "RESOURCE_TYPE_MENU" => 4,
            "RESOURCE_TYPE_DIALOG" => 5,
            "RESOURCE_TYPE_STRING" => 6,
            "RESOURCE_TYPE_FONTDIR" => 7,
            "RESOURCE_TYPE_FONT" => 8,
            "RESOURCE_TYPE_ACCELERATOR" => 9,
            "RESOURCE_TYPE_RCDATA" => 10,
            "RESOURCE_TYPE_MESSAGETABLE" => 11,
            "RESOURCE_TYPE_GROUP_CURSOR" => 12,
            "RESOURCE_TYPE_GROUP_ICON" => 14,
            "RESOURCE_TYPE_VERSION" => 16,
            "RESOURCE_TYPE_DLGINCLUDE" => 17,
            "RESOURCE_TYPE_PLUGPLAY" => 19,
            "RESOURCE_TYPE_VXD" => 20,
            "RESOURCE_TYPE_ANICURSOR" => 21,
            "RESOURCE_TYPE_ANIICON" => 22,
            "RESOURCE_TYPE_HTML" => 23,
            "RESOURCE_TYPE_MANIFEST" => 24,
            // -- optional header magic -------------------------------------------
            "IMAGE_NT_OPTIONAL_HDR32_MAGIC" => 0x010b,
            "IMAGE_NT_OPTIONAL_HDR64_MAGIC" => 0x020b,
            "IMAGE_ROM_OPTIONAL_HDR_MAGIC" => 0x0107,
            // -- section characteristics -----------------------------------------
            "SECTION_NO_PAD" => 0x0000_0008,
            "SECTION_CNT_CODE" => 0x0000_0020,
            "SECTION_CNT_INITIALIZED_DATA" => 0x0000_0040,
            "SECTION_CNT_UNINITIALIZED_DATA" => 0x0000_0080,
            "SECTION_LNK_OTHER" => 0x0000_0100,
            "SECTION_LNK_INFO" => 0x0000_0200,
            "SECTION_LNK_REMOVE" => 0x0000_0800,
            "SECTION_LNK_COMDAT" => 0x0000_1000,
            "SECTION_NO_DEFER_SPEC_EXC" => 0x0000_4000,
            "SECTION_GPREL" => 0x0000_8000,
            "SECTION_MEM_FARDATA" => 0x0000_8000,
            "SECTION_MEM_PURGEABLE" => 0x0002_0000,
            "SECTION_MEM_16BIT" => 0x0002_0000,
            "SECTION_MEM_LOCKED" => 0x0004_0000,
            "SECTION_MEM_PRELOAD" => 0x0008_0000,
            "SECTION_ALIGN_1BYTES" => 0x0010_0000,
            "SECTION_ALIGN_2BYTES" => 0x0020_0000,
            "SECTION_ALIGN_4BYTES" => 0x0030_0000,
            "SECTION_ALIGN_8BYTES" => 0x0040_0000,
            "SECTION_ALIGN_16BYTES" => 0x0050_0000,
            "SECTION_ALIGN_32BYTES" => 0x0060_0000,
            "SECTION_ALIGN_64BYTES" => 0x0070_0000,
            "SECTION_ALIGN_128BYTES" => 0x0080_0000,
            "SECTION_ALIGN_256BYTES" => 0x0090_0000,
            "SECTION_ALIGN_512BYTES" => 0x00a0_0000,
            "SECTION_ALIGN_1024BYTES" => 0x00b0_0000,
            "SECTION_ALIGN_2048BYTES" => 0x00c0_0000,
            "SECTION_ALIGN_4096BYTES" => 0x00d0_0000,
            "SECTION_ALIGN_8192BYTES" => 0x00e0_0000,
            "SECTION_ALIGN_MASK" => 0x00f0_0000,
            "SECTION_LNK_NRELOC_OVFL" => 0x0100_0000,
            "SECTION_MEM_DISCARDABLE" => 0x0200_0000,
            "SECTION_MEM_NOT_CACHED" => 0x0400_0000,
            "SECTION_MEM_NOT_PAGED" => 0x0800_0000,
            "SECTION_MEM_SHARED" => 0x1000_0000,
            "SECTION_MEM_EXECUTE" => 0x2000_0000,
            "SECTION_MEM_READ" => 0x4000_0000,
            "SECTION_MEM_WRITE" => 0x8000_0000,
            "SECTION_SCALE_INDEX" => 0x0000_0001,
            // -- debug directory types --------------------------------------------
            "IMAGE_DEBUG_TYPE_UNKNOWN" => 0,
            "IMAGE_DEBUG_TYPE_COFF" => 1,
            "IMAGE_DEBUG_TYPE_CODEVIEW" => 2,
            "IMAGE_DEBUG_TYPE_FPO" => 3,
            "IMAGE_DEBUG_TYPE_MISC" => 4,
            "IMAGE_DEBUG_TYPE_EXCEPTION" => 5,
            "IMAGE_DEBUG_TYPE_FIXUP" => 6,
            "IMAGE_DEBUG_TYPE_OMAP_TO_SRC" => 7,
            "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC" => 8,
            "IMAGE_DEBUG_TYPE_BORLAND" => 9,
            "IMAGE_DEBUG_TYPE_RESERVED10" => 10,
            "IMAGE_DEBUG_TYPE_CLSID" => 11,
            "IMAGE_DEBUG_TYPE_VC_FEATURE" => 12,
            "IMAGE_DEBUG_TYPE_POGO" => 13,
            "IMAGE_DEBUG_TYPE_ILTCG" => 14,
            "IMAGE_DEBUG_TYPE_MPX" => 15,
            "IMAGE_DEBUG_TYPE_REPRO" => 16,
            // -- import kinds ------------------------------------------------------
            "IMPORT_DELAYED" => 1,
            "IMPORT_STANDARD" => 2,
            "IMPORT_ANY" => 3,
            _ => return None,
        };
        Some(value)
    }

    /// A member of one of the `pe` structs that is not an array.
    ///
    /// Kept apart from [`Self::pe_field`] because the *shape* of the path
    /// differs: these are only ever reached through two field segments, and
    /// folding them into the bare-name table would make `pe.major` a member of
    /// the `pe` module.
    fn pe_struct_field(struct_name: &str, member: &str) -> Option<PeField> {
        Some(match (struct_name, member) {
            ("linker_version", "major") => PeField::LinkerVersionMajor,
            ("linker_version", "minor") => PeField::LinkerVersionMinor,
            ("os_version", "major") => PeField::OsVersionMajor,
            ("os_version", "minor") => PeField::OsVersionMinor,
            ("image_version", "major") => PeField::ImageVersionMajor,
            ("image_version", "minor") => PeField::ImageVersionMinor,
            ("subsystem_version", "major") => PeField::SubsystemVersionMajor,
            ("subsystem_version", "minor") => PeField::SubsystemVersionMinor,
            ("overlay", "offset") => PeField::OverlayOffset,
            ("overlay", "size") => PeField::OverlaySize,
            ("rich_signature", "length") => PeField::RichSignatureLength,
            ("rich_signature", "clear_data") => PeField::RichSignatureClearData,
            _ => return None,
        })
    }

    /// The `pe` member a bare field name means, or `None` if it is not
    /// implemented.
    fn pe_field(name: &str) -> Option<PeField> {
        Some(match name {
            "is_pe" => PeField::IsPe,
            "is_dll" => PeField::IsDll,
            "is_32bit" => PeField::Is32Bit,
            "is_64bit" => PeField::Is64Bit,
            "machine" => PeField::Machine,
            "timestamp" => PeField::Timestamp,
            "characteristics" => PeField::Characteristics,
            "subsystem" => PeField::Subsystem,
            "dll_characteristics" => PeField::DllCharacteristics,
            "entry_point" => PeField::EntryPoint,
            "entry_point_raw" => PeField::EntryPointRaw,
            "image_base" => PeField::ImageBase,
            "size_of_image" => PeField::SizeOfImage,
            "size_of_headers" => PeField::SizeOfHeaders,
            "checksum" => PeField::Checksum,
            "section_alignment" => PeField::SectionAlignment,
            "file_alignment" => PeField::FileAlignment,
            "number_of_rva_and_sizes" => PeField::NumberOfRvaAndSizes,
            "base_of_code" => PeField::BaseOfCode,
            "base_of_data" => PeField::BaseOfData,
            "size_of_code" => PeField::SizeOfCode,
            "size_of_initialized_data" => PeField::SizeOfInitializedData,
            "size_of_uninitialized_data" => PeField::SizeOfUninitializedData,
            "size_of_stack_reserve" => PeField::SizeOfStackReserve,
            "size_of_stack_commit" => PeField::SizeOfStackCommit,
            "size_of_heap_reserve" => PeField::SizeOfHeapReserve,
            "size_of_heap_commit" => PeField::SizeOfHeapCommit,
            "opthdr_magic" => PeField::OpthdrMagic,
            "pointer_to_symbol_table" => PeField::PointerToSymbolTable,
            "number_of_symbols" => PeField::NumberOfSymbols,
            "size_of_optional_header" => PeField::SizeOfOptionalHeader,
            "loader_flags" => PeField::LoaderFlags,
            "win32_version_value" => PeField::Win32VersionValue,
            "number_of_sections" => PeField::NumberOfSections,
            "number_of_signatures" => PeField::NumberOfSignatures,
            "number_of_imports" => PeField::NumberOfImports,
            "number_of_exports" => PeField::NumberOfExports,
            "number_of_resources" => PeField::NumberOfResources,
            "pdb_path" => PeField::PdbPath,
            _ => return None,
        })
    }

    /// The element member `pe.<array>[i].<field>` means, or `None`.
    ///
    /// The array name is checked as well as the member, so that
    /// `pe.data_directories[i].name` is a refusal rather than a section name
    /// read out of the wrong table.
    fn pe_element(array: &str, member: &str) -> Option<PeElement> {
        match (array, member) {
            ("sections", "name") => Some(PeElement::SectionName),
            ("sections", "virtual_address") => Some(PeElement::SectionVirtualAddress),
            ("sections", "virtual_size") => Some(PeElement::SectionVirtualSize),
            ("sections", "raw_data_offset") => Some(PeElement::SectionRawDataOffset),
            ("sections", "raw_data_size") => Some(PeElement::SectionRawDataSize),
            ("sections", "characteristics") => Some(PeElement::SectionCharacteristics),
            ("sections", "pointer_to_relocations") => Some(PeElement::SectionPointerToRelocations),
            ("sections", "number_of_relocations") => Some(PeElement::SectionNumberOfRelocations),
            ("sections", "pointer_to_line_numbers") => Some(PeElement::SectionPointerToLineNumbers),
            ("sections", "number_of_line_numbers") => Some(PeElement::SectionNumberOfLineNumbers),
            ("data_directories", "virtual_address") => Some(PeElement::DirectoryVirtualAddress),
            ("data_directories", "size") => Some(PeElement::DirectorySize),
            ("signatures", "serial") => Some(PeElement::SignatureSerial),
            ("signatures", "subject") => Some(PeElement::SignatureSubject),
            ("signatures", "issuer") => Some(PeElement::SignatureIssuer),
            ("signatures", "not_before") => Some(PeElement::SignatureNotBefore),
            ("signatures", "not_after") => Some(PeElement::SignatureNotAfter),
            ("signatures", "thumbprint") => Some(PeElement::SignatureThumbprint),
            ("signatures", "version") => Some(PeElement::SignatureVersion),
            ("resources", "type") => Some(PeElement::ResourceType),
            ("resources", "id") => Some(PeElement::ResourceId),
            ("resources", "language") => Some(PeElement::ResourceLanguage),
            ("resources", "offset") => Some(PeElement::ResourceOffset),
            ("resources", "length") => Some(PeElement::ResourceLength),
            ("resources", "name_string") => Some(PeElement::ResourceNameString),
            ("resources", "type_string") => Some(PeElement::ResourceTypeString),
            ("resources", "language_string") => Some(PeElement::ResourceLanguageString),
            ("export_details", "name") => Some(PeElement::ExportName),
            ("export_details", "forward_name") => Some(PeElement::ExportForwardName),
            ("export_details", "offset") => Some(PeElement::ExportOffset),
            ("export_details", "ordinal") => Some(PeElement::ExportOrdinal),
            // `.verified` is deliberately absent. Verifying an Authenticode
            // signature means implementing chain validation — trust anchors,
            // expiry at signing time, revocation, the countersignature — and a
            // member that answered `false` for every file would make
            // `not pe.signatures[i].verified` select the entire disk. A rule
            // using it is refused at compile time, which is a rule that does
            // not load rather than a verdict that is confidently inverted.
            _ => None,
        }
    }

    /// The `pe` function a call path means, or `None`.
    fn pe_function(path: &MemberPath) -> Option<PeFunc> {
        if path.root != "pe" {
            return None;
        }
        match path.segments.as_slice() {
            [PathSegment::Field(name)] => match name.as_str() {
                "section_index" => Some(PeFunc::SectionIndex),
                // The parenthesised spellings of the three members that YARA
                // declares as functions. The bare spellings go through
                // `pe_field`, and both answer the same.
                "is_dll" => Some(PeFunc::IsDll),
                "is_32bit" => Some(PeFunc::Is32Bit),
                "is_64bit" => Some(PeFunc::Is64Bit),
                "imphash" => Some(PeFunc::Imphash),
                // One name, two arities: `pe.imports("dll")` asks whether the
                // library is imported at all, and `pe.imports("dll", "symbol")`
                // asks about one symbol in it. Both appear in the corpus.
                "imports" => Some(PeFunc::Imports),
                "exports" => Some(PeFunc::Exports),
                _ => None,
            },
            // The one function that hangs off a struct rather than directly off
            // `pe`, and so the one path with two segments. Matching a bare field
            // here would make `pe.rich_signature.toolid` the name `toolid`,
            // which is not a member of anything.
            [PathSegment::Field(owner), PathSegment::Field(member)]
                if owner == "rich_signature" && member == "toolid" =>
            {
                Some(PeFunc::RichSignatureToolid)
            }
            _ => None,
        }
    }

    /// `<string> matches /regex/`.
    ///
    /// The pattern has to be a literal, and that is checked rather than
    /// assumed: `matches` takes a value on the left and a *pattern* on the
    /// right, and a rule that computed the pattern at run time would be a rule
    /// whose meaning this compiler cannot see. YARA has the same restriction for
    /// the same reason, so refusing here refuses nothing a rule author wrote.
    ///
    /// The pattern is compiled now and compiled again on first use. This call
    /// is the one that matters for a rule author: a pattern the engine cannot
    /// compile is a rule that does not enter the database, rather than a rule
    /// that enters it and never fires.
    fn compile_matches(&mut self, lhs: &Expr, rhs: &Expr) -> Result<(), CompileError> {
        let Expr::Regex { body, flags } = rhs else {
            return Err(CompileError::unsupported(
                "regex",
                "the right-hand side of `matches` has to be a `/regex/` literal",
                self.span,
            ));
        };
        let spec = RegexSpec {
            body: body.clone(),
            flags: flags.clone(),
        };
        crate::matcher::compile_condition_regex(&spec.body, &spec.flags).map_err(|e| {
            CompileError::unsupported(
                "invalid regex",
                format!("{}: {}", spec.body, e.message),
                self.span,
            )
        })?;
        self.compile(lhs)?;
        let index = self.program.regex(spec);
        self.program.emit(Op::Matches(index));
        Ok(())
    }

    fn compile_and(&mut self, a: &Expr, b: &Expr) -> Result<(), CompileError> {
        self.compile(a)?;
        let first = self.program.emit(Op::JumpIfFalse(u32::MAX));
        self.compile(b)?;
        let second = self.program.emit(Op::JumpIfFalse(u32::MAX));
        let t = self.program.constant(Const::Bool(true));
        self.program.emit(Op::Push(t));
        let done = self.program.emit(Op::Jump(u32::MAX));
        let false_at = self.program.here();
        let f = self.program.constant(Const::Bool(false));
        self.program.emit(Op::Push(f));
        let end = self.program.here();
        self.program.patch(first, Op::JumpIfFalse(false_at));
        self.program.patch(second, Op::JumpIfFalse(false_at));
        self.program.patch(done, Op::Jump(end));
        Ok(())
    }

    fn compile_or(&mut self, a: &Expr, b: &Expr) -> Result<(), CompileError> {
        self.compile(a)?;
        let first = self.program.emit(Op::JumpIfTrue(u32::MAX));
        self.compile(b)?;
        let second = self.program.emit(Op::JumpIfTrue(u32::MAX));
        let f = self.program.constant(Const::Bool(false));
        self.program.emit(Op::Push(f));
        let done = self.program.emit(Op::Jump(u32::MAX));
        let true_at = self.program.here();
        let t = self.program.constant(Const::Bool(true));
        self.program.emit(Op::Push(t));
        let end = self.program.here();
        self.program.patch(first, Op::JumpIfTrue(true_at));
        self.program.patch(second, Op::JumpIfTrue(true_at));
        self.program.patch(done, Op::Jump(end));
        Ok(())
    }

    /// `any of ...` and the rest. The slots are already resolved, so this is
    /// only about the quantifier.
    fn compile_of(&mut self, quantifier: &Quantifier, slots: &[u32]) -> Result<(), CompileError> {
        let n = slots.len() as u32;
        match quantifier {
            Quantifier::Any => {
                self.push_matches(slots);
                self.program.emit(Op::OfAny(n));
            }
            Quantifier::All => {
                self.push_matches(slots);
                self.program.emit(Op::OfAll(n));
            }
            Quantifier::None => {
                self.push_matches(slots);
                self.program.emit(Op::OfNone(n));
            }
            Quantifier::Count(count) => {
                // The count is pushed first so that the run of string results
                // stays contiguous above it — `OfCount` pops the results and
                // then the count.
                self.compile(count)?;
                self.push_matches(slots);
                self.program.emit(Op::OfCount(n));
            }
            Quantifier::Percentage(percent) => {
                // The set size is known here, so a percentage is a constant and
                // the interpreter never sees one. It rounds up: `50% of them`
                // over three strings asks for two, because rounding down would
                // let a rule fire on half the evidence its author demanded.
                let need = percentage_count(slots.len(), *percent);
                let k = self.program.constant(Const::Int(need as i64));
                self.program.emit(Op::Push(k));
                self.push_matches(slots);
                self.program.emit(Op::OfCount(n));
            }
        }
        Ok(())
    }

    /// `N of ($a*) in (0..100)`.
    ///
    /// The range is compiled once per string rather than once for the set,
    /// because `StrIn` consumes its operands and there is no opcode that reads
    /// the top two stack slots without popping them. For the common case — a
    /// pair of constants — the constant pool makes each repeat a single push,
    /// so the cost is a few instructions and no recomputation. A range built
    /// from a module call would be re-evaluated per string; that is worth
    /// avoiding, but not worth an opcode until a real rule set needs it.
    fn compile_of_in(
        &mut self,
        quantifier: &Quantifier,
        slots: &[u32],
        from: &Expr,
        to: &Expr,
    ) -> Result<(), CompileError> {
        let n = slots.len() as u32;
        match quantifier {
            Quantifier::Count(count) => self.compile(count)?,
            Quantifier::Percentage(percent) => {
                let need = percentage_count(slots.len(), *percent);
                let k = self.program.constant(Const::Int(need as i64));
                self.program.emit(Op::Push(k));
            }
            // `all of` and `none of` are not short-circuited here either, for
            // the same reason the plain form is not: the string results are
            // computed by the matcher ahead of the interpreter, so there is
            // nothing to skip.
            Quantifier::Any | Quantifier::All | Quantifier::None => {}
        }
        for slot in slots {
            self.compile(from)?;
            self.compile(to)?;
            self.program.emit(Op::StrIn(*slot));
        }
        let op = match quantifier {
            Quantifier::Any => Op::OfAny(n),
            Quantifier::All => Op::OfAll(n),
            Quantifier::None => Op::OfNone(n),
            Quantifier::Count(_) | Quantifier::Percentage(_) => Op::OfCount(n),
        };
        self.program.emit(op);
        Ok(())
    }

    fn push_matches(&mut self, slots: &[u32]) {
        for slot in slots {
            self.program.emit(Op::StrMatch(*slot));
        }
    }

    fn slot(&self, name: &str) -> Result<u32, CompileError> {
        self.strings
            .resolve(name)
            .ok_or_else(|| CompileError::undefined_string(name, self.span))
    }

    /// The slot a loop variable means here, searching from the innermost loop
    /// outwards so that an inner loop may shadow an outer one's name.
    fn variable(&self, name: &str) -> Option<u32> {
        self.vars
            .iter()
            .rev()
            .find(|binding| binding.name == name)
            .map(|binding| binding.slot)
    }

    /// The slot and array of a variable bound by `for <var> in pe.<array>`.
    ///
    /// `None` both for a name that is not in scope and for a range loop's
    /// variable, because a number has no members: `i.name` in `for any i in
    /// (0..9)` is a typo rather than a member of a module array, and it should
    /// be reported as one.
    fn array_variable(&self, name: &str) -> Option<(u32, ArrayKind)> {
        self.vars
            .iter()
            .rev()
            .find(|binding| binding.name == name)
            .and_then(|binding| binding.array.map(|array| (binding.slot, array)))
    }

    /// `s.name` — a member of the element a `for <var> in pe.<array>` loop is
    /// currently on.
    ///
    /// The variable holds an index rather than the element, so this is the same
    /// opcode as `pe.sections[2].name`: the index operand is a `var_load`
    /// rather than a literal, and nothing downstream can tell the two apart.
    /// That is also what makes the counted form work — `for 12 resource in
    /// pe.resources` reaches each resource the same way a hand-written
    /// `pe.resources[i]` would.
    ///
    /// `Ok(false)` when the path does not start with a loop variable, with the
    /// stack left as it was found, so the caller can fall through to the module
    /// lookup.
    fn compile_loop_element(&mut self, path: &MemberPath) -> Result<bool, CompileError> {
        // Exactly one segment: `s.name` is a member, and `s.a.b` is not
        // something any module array has, so it is left to the module lookup to
        // refuse rather than being guessed at here.
        let [PathSegment::Field(member)] = path.segments.as_slice() else {
            return Ok(false);
        };
        let Some((slot, array)) = self.array_variable(&path.root) else {
            return Ok(false);
        };
        // The member has to be one the array actually has. `s.name` is a
        // section name; `s.nmae` is a typo, and answering it with undefined
        // would make the loop body false for every file rather than telling
        // the author.
        let Some(element) = Self::pe_element(array.name(), member) else {
            return Err(CompileError::unsupported(
                "loop element member",
                format!("`{member}` on the elements of `pe.{}`", array.name()),
                self.span,
            ));
        };
        self.program.emit(Op::VarLoad(slot));
        self.program.emit(Op::PeIndexed(element));
        Ok(true)
    }

    /// `for <quant> <var> in (<from>..<to>) : (body)`.
    ///
    /// # The shape of the code
    ///
    /// ```text
    ///     [needed]                      ; only `for <n> i in ...`, pushed first
    ///     <from> <to>
    ///     for_begin  v0 (end v1, acc v2) -> done
    /// back:                             ; the body, not the for_begin
    ///     <body>                        ; pushes exactly one boolean
    ///     for_step   v0 acc v2 -> back  ; folds it in, advances, or stops
    /// done:
    ///     var_load   v2                 ; the loop's result
    ///     le                            ; only `for <n> i in ...`
    /// ```
    ///
    /// Three slots per loop, allocated on entry and released on exit, so two
    /// loops side by side in one condition share them and only nesting grows
    /// the register file.
    ///
    /// # Why the count is pushed before the loop
    ///
    /// `for 2 i in (0..10)` asks whether the body held at least twice. The
    /// count is an arbitrary expression, so it is compiled and left under the
    /// loop's result, where one comparison after the loop settles it — rather
    /// than carried through every iteration as a comparison the interpreter
    /// would rerun.
    fn compile_for_in(
        &mut self,
        quantifier: &Quantifier,
        name: &str,
        from: &Expr,
        to: &Expr,
        body: &Expr,
    ) -> Result<(), CompileError> {
        let Some(kind) = loop_kind(quantifier) else {
            // `50% i in (0..10)` would mean "half the range", which is not what
            // a percentage means anywhere else in the language — there it is a
            // fraction of a *string set*. Refused rather than guessed at.
            return Err(CompileError::unsupported(
                "for .. in range",
                "a percentage quantifier on a loop, whose denominator would have \
                 to be the length of the range",
                self.span,
            ));
        };

        if let Quantifier::Count(count) = quantifier {
            self.compile(count)?;
        }

        let var = self.next_slot;
        let end = var + 1;
        let acc = var + 2;
        self.next_slot += 3;
        self.peak_slots = self.peak_slots.max(self.next_slot);

        self.compile(from)?;
        self.compile(to)?;
        let begin = self.program.emit(Op::ForBegin {
            var,
            end,
            acc,
            kind,
            // Filled in below: the target is the far end of the body, which
            // does not exist yet.
            done: u32::MAX,
        });

        // Where the back edge lands: the first instruction of the body, not the
        // `for_begin`. Jumping back to `for_begin` would re-run it, and it pops
        // the two bounds that the first pass already consumed — the second
        // iteration would fault on an empty stack.
        let body_start = self.program.here();

        self.vars.push(Binding {
            name: name.to_string(),
            slot: var,
            array: None,
        });
        let body_compiled = self.compile(body);
        self.vars.pop();
        body_compiled?;

        self.program.emit(Op::ForStep {
            var,
            end,
            acc,
            kind,
            back: body_start,
        });
        let done = self.program.here();
        self.program.patch(
            begin,
            Op::ForBegin {
                var,
                end,
                acc,
                kind,
                done,
            },
        );

        self.program.emit(Op::VarLoad(acc));
        if matches!(quantifier, Quantifier::Count(_)) {
            // The stack is `[needed, count]`, so this reads `needed <= count` —
            // the other way round from how it is written, and the way that
            // makes `for 0 i in ...` true and `for 5 i in (0..0)` false.
            self.program.emit(Op::Le);
        }

        // Released for a sibling loop to reuse. Safe after the `var_load`
        // above, which is the last read of any of them, and safe inside an
        // outer loop because the outer loop's slots are below `var`.
        self.next_slot = var;
        Ok(())
    }

    /// `for <quant> <var> in pe.<array> : (body)`.
    ///
    /// # The same shape as the range loop, on purpose
    ///
    /// Everything after the entry is identical to [`Compiler::compile_for_in`]:
    /// the same three slots, the same back edge, the same accumulator, the same
    /// comparison against the count. That is not a coincidence to be factored
    /// out but a consequence of the variable holding the *index* rather than
    /// the element — so a body written `for any s in pe.sections : (s.name ==
    /// ".text")` and one written `for any i in (0..pe.number_of_sections - 1) :
    /// (pe.sections[i].name == ".text")` are the same program, and the only
    /// thing `Op::ForEachBegin` adds over `Op::ForBegin` is that it takes a
    /// length where that one takes two bounds.
    ///
    /// # Why the length is read as a field
    ///
    /// `pe.number_of_resources` and not a dedicated length opcode, because the
    /// count is already a member of the language and a rule may write it
    /// directly. The corpus does: the two counted resource loops are both
    /// guarded by `pe.number_of_resources >= 6` immediately before them, and a
    /// second implementation of that number could disagree with the first about
    /// where the array ends.
    fn compile_for_each(
        &mut self,
        quantifier: &Quantifier,
        name: &str,
        iterable: &Expr,
        body: &Expr,
    ) -> Result<(), CompileError> {
        let Some(kind) = loop_kind(quantifier) else {
            // Refused for the same reason as over a range: a percentage needs a
            // denominator, and this one would be the length of the array, which
            // is not what a percentage means anywhere else in the language.
            return Err(CompileError::unsupported(
                "for .. in array",
                "a percentage quantifier on a loop, whose denominator would have \
                 to be the length of the array",
                self.span,
            ));
        };
        let Some(array) = iterable_array(iterable) else {
            return Err(CompileError::unsupported(
                "for .. in array",
                match iterable {
                    Expr::Field { path } => format!(
                        "iterating `{}`, which is not a module array whose length \
                         this engine can read",
                        path.render()
                    ),
                    _ => "iterating an expression that is not a module array".to_string(),
                },
                self.span,
            ));
        };

        if let Quantifier::Count(count) = quantifier {
            self.compile(count)?;
        }
        // Left under the loop's result, the way `compile_for_in` leaves the
        // range's bounds under it, so the one comparison after the loop settles
        // a count for both forms.
        self.program.emit(Op::PeField(array.length_field()));

        let var = self.next_slot;
        let end = var + 1;
        let acc = var + 2;
        self.next_slot += 3;
        self.peak_slots = self.peak_slots.max(self.next_slot);

        let begin = self.program.emit(Op::ForEachBegin {
            var,
            end,
            acc,
            kind,
            // Filled in below, as in `compile_for_in`: the far end of the body
            // does not exist yet.
            done: u32::MAX,
        });

        let body_start = self.program.here();

        self.vars.push(Binding {
            name: name.to_string(),
            slot: var,
            array: Some(array),
        });
        let body_compiled = self.compile(body);
        self.vars.pop();
        body_compiled?;

        self.program.emit(Op::ForStep {
            var,
            end,
            acc,
            kind,
            back: body_start,
        });
        let done = self.program.here();
        self.program.patch(
            begin,
            Op::ForEachBegin {
                var,
                end,
                acc,
                kind,
                done,
            },
        );

        self.program.emit(Op::VarLoad(acc));
        if matches!(quantifier, Quantifier::Count(_)) {
            self.program.emit(Op::Le);
        }

        self.next_slot = var;
        Ok(())
    }
}

/// The interpreter's view of a `for` header's quantifier.
///
/// `None` for a percentage, which has no meaning over a range — see
/// [`Compiler::compile_for_in`].
fn loop_kind(quantifier: &Quantifier) -> Option<LoopKind> {
    match quantifier {
        Quantifier::Any => Some(LoopKind::Any),
        Quantifier::All => Some(LoopKind::All),
        Quantifier::None => Some(LoopKind::None),
        Quantifier::Count(_) => Some(LoopKind::Count),
        Quantifier::Percentage(_) => None,
    }
}

/// The percentage of `total` a `p%` quantifier demands, rounded up.
fn percentage_count(total: usize, percent: u8) -> usize {
    // `+ 99` before dividing is ceiling division, written out because the
    // alternative — a `div_ceil` call — hides the rounding direction, and the
    // rounding direction is the whole content of this function.
    total.saturating_mul(percent as usize).saturating_add(99) / 100
}

/// The buffer-reading builtins, mapped to their opcode.
///
/// An 8-bit read has no endianness, so `uint8be` and `int8be` are the same
/// operation as their little-endian spellings rather than separate opcodes.
fn read_builtin(name: &str) -> Option<Op> {
    Some(match name {
        "uint8" | "uint8be" => Op::ReadU8,
        "uint16" => Op::ReadU16,
        "uint16be" => Op::ReadU16Be,
        "uint32" => Op::ReadU32,
        "uint32be" => Op::ReadU32Be,
        "int8" | "int8be" => Op::ReadI8,
        "int16" => Op::ReadI16,
        "int16be" => Op::ReadI16Be,
        "int32" => Op::ReadI32,
        "int32be" => Op::ReadI32Be,
        _ => return None,
    })
}

fn single_arg(args: &[Expr]) -> Option<&Expr> {
    match args {
        [only] => Some(only),
        _ => None,
    }
}

fn arith_op(op: ArithOp) -> Op {
    match op {
        ArithOp::Add => Op::Add,
        ArithOp::Sub => Op::Sub,
        ArithOp::Mul => Op::Mul,
        ArithOp::Div => Op::Div,
        ArithOp::Mod => Op::Mod,
    }
}

fn bit_op(op: BitOp) -> Op {
    match op {
        BitOp::And => Op::BitAnd,
        BitOp::Or => Op::BitOr,
        BitOp::Xor => Op::BitXor,
        BitOp::Shl => Op::Shl,
        BitOp::Shr => Op::Shr,
    }
}

fn cmp_op(op: CmpOp) -> Op {
    match op {
        CmpOp::Eq => Op::Eq,
        CmpOp::Ne => Op::Ne,
        CmpOp::Lt => Op::Lt,
        CmpOp::Le => Op::Le,
        CmpOp::Gt => Op::Gt,
        CmpOp::Ge => Op::Ge,
    }
}

/// `None` for the one string operator with no opcode yet.
///
/// `equals` maps onto the ordinary equality opcode rather than a `Cmp` of its
/// own, because `"a" == "b"` and `"a" equals "b"` are the same question and
/// giving them separate opcodes would be two code paths to keep in step.
fn string_op(op: StringOp) -> Option<Op> {
    Some(match op {
        StringOp::Contains => Op::Cmp(Cmp::Contains),
        StringOp::IContains => Op::Cmp(Cmp::IContains),
        StringOp::StartsWith => Op::Cmp(Cmp::StartsWith),
        StringOp::IStartsWith => Op::Cmp(Cmp::IStartsWith),
        StringOp::EndsWith => Op::Cmp(Cmp::EndsWith),
        StringOp::IEndsWith => Op::Cmp(Cmp::IEndsWith),
        StringOp::IEquals => Op::Cmp(Cmp::IEquals),
        StringOp::Equals => Op::Eq,
        StringOp::Matches => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_file;

    /// Compile the first rule of a source snippet.
    fn compile(source: &str) -> Result<Program, CompileError> {
        let file = parse_file(source).expect("the test source must parse");
        compile_rule(&file.rules[0])
    }

    /// Compile and return the disassembly, which is what most tests assert on.
    fn dis(source: &str) -> String {
        compile(source)
            .expect("the test source must compile")
            .disassemble()
    }

    /// Compile a condition built directly as an AST.
    ///
    /// For the constructs the parser refuses to build but the compiler still
    /// has to answer for — the type permits them whether or not the grammar
    /// does, and the answer must not be a wrong one.
    fn compile_expr(expr: &Expr) -> Result<Program, CompileError> {
        compile_condition(expr, &StringTable::default(), Span::default())
    }

    fn feature(source: &str) -> &'static str {
        compile(source).expect_err("expected a refusal").feature
    }

    #[test]
    fn constants_and_comparisons_compile() {
        let text = dis("rule r { condition: filesize > 1024 }");
        assert!(text.contains("filesize"), "{text}");
        assert!(text.contains("push 1024"), "{text}");
        assert!(text.contains("gt"), "{text}");
    }

    #[test]
    fn the_program_always_ends_with_ret() {
        let p = compile("rule r { condition: true }").unwrap();
        assert_eq!(p.code.last(), Some(&Op::Ret));
    }

    #[test]
    fn a_string_reference_becomes_a_slot() {
        assert!(dis(r#"rule r { strings: $a = "x" condition: $a }"#).contains("str_match    $0"));
    }

    #[test]
    fn a_count_and_an_offset_and_a_length_each_compile() {
        let text =
            dis(r#"rule r { strings: $a = "x" condition: #a > 1 and @a < 100 and !a == 2 }"#);
        assert!(text.contains("str_count    $0"), "{text}");
        assert!(text.contains("str_offset   $0"), "{text}");
        assert!(text.contains("str_len      $0"), "{text}");
    }

    #[test]
    fn an_indexed_offset_pushes_the_index_first() {
        let text = dis(r#"rule r { strings: $a = "x" condition: @a[2] == 0 }"#);
        let push = text.find("push 2").expect("the index is pushed");
        let read = text.find("str_offset_n $0").expect("the indexed read");
        assert!(push < read, "index must precede the read:\n{text}");
    }

    #[test]
    fn a_string_at_takes_an_arbitrary_offset_expression() {
        let text = dis(r#"rule r { strings: $a = "x" condition: $a at 0x400 + 16 }"#);
        assert!(text.contains("str_at       $0"), "{text}");
        assert!(text.contains("add"), "{text}");
    }

    #[test]
    fn a_string_in_pushes_both_bounds_before_the_test() {
        let text = dis(r#"rule r { strings: $a = "x" condition: $a in (0..100) }"#);
        assert!(text.contains("str_in       $0"), "{text}");
        let first = text.find("push 0").unwrap();
        let second = text.find("push 100").unwrap();
        let test = text.find("str_in").unwrap();
        assert!(
            first < second && second < test,
            "bounds precede the test:\n{text}"
        );
    }

    #[test]
    fn any_of_them_pushes_one_match_test_per_string() {
        let text = dis(r#"rule r { strings: $a = "x" $b = "y" condition: any of them }"#);
        assert!(text.contains("str_match    $0"), "{text}");
        assert!(text.contains("str_match    $1"), "{text}");
        assert!(text.contains("of_any       2"), "{text}");
    }

    #[test]
    fn all_and_none_of_a_set_use_their_own_opcodes() {
        assert!(dis(r#"rule r { strings: $a = "x" condition: all of them }"#).contains("of_all"));
        assert!(dis(r#"rule r { strings: $a = "x" condition: none of them }"#).contains("of_none"));
    }

    #[test]
    fn a_counted_set_pushes_the_count_below_the_results() {
        // `OfCount` pops the results first and then the count, so the count
        // has to be emitted before them. Getting this backwards reads the last
        // match result as the count.
        let p = compile(r#"rule r { strings: $a = "x" $b = "y" condition: 2 of them }"#).unwrap();
        let count_at = p
            .code
            .iter()
            .position(|op| *op == Op::Push(0))
            .expect("count pushed");
        let of_at = p
            .code
            .iter()
            .position(|op| matches!(op, Op::OfCount(_)))
            .unwrap();
        assert!(count_at < of_at, "{}", p.disassemble());
        assert_eq!(p.code[of_at], Op::OfCount(2));
    }

    #[test]
    fn a_percentage_becomes_a_constant_rounded_up() {
        // Three strings, 50% — two, not one.
        let text = dis(r#"rule r { strings: $a = "x" $b = "y" $c = "z" condition: 50% of them }"#);
        assert!(text.contains("push 2"), "{text}");
        assert!(text.contains("of_count     3"), "{text}");
    }

    #[test]
    fn a_percentage_of_one_string_still_demands_that_string() {
        // Ceiling is what stops `1% of them` from becoming `0 of them`, which
        // is trivially true and would make the rule fire on every file.
        let text = dis(r#"rule r { strings: $a = "x" condition: 1% of them }"#);
        assert!(text.contains("push 1"), "{text}");
    }

    #[test]
    fn a_counted_quantifier_accepts_an_expression() {
        let text = dis(r#"rule r { strings: $a = "x" condition: filesize of them }"#);
        assert!(text.contains("filesize"), "{text}");
        assert!(text.contains("of_count     1"), "{text}");
    }

    #[test]
    fn and_pushes_exactly_one_boolean_on_both_paths() {
        let p = compile("rule r { condition: 1 == 1 and 2 == 2 }").unwrap();
        let text = p.disassemble();
        assert!(text.contains("jump_if_false"), "{text}");
        assert!(text.contains("push true"), "{text}");
        assert!(text.contains("push false"), "{text}");
        // Two comparisons and exactly two return-path pushes: any more would
        // mean a branch left a value behind.
        let pushes = p.code.iter().filter(|op| matches!(op, Op::Push(_))).count();
        assert_eq!(pushes, 6, "{text}");
    }

    #[test]
    fn or_pushes_exactly_one_boolean_on_both_paths() {
        let text = dis("rule r { condition: 1 == 1 or 2 == 2 }");
        assert!(text.contains("jump_if_true"), "{text}");
    }

    #[test]
    fn every_jump_lands_inside_the_program() {
        // A patch that used a placeholder address would show up here as a jump
        // to u32::MAX. Every real rule set compiles a few thousand jumps, and
        // one bad patch is a wild branch at scan time.
        for source in [
            "rule r { condition: 1 == 1 and 2 == 2 }",
            "rule r { condition: 1 == 1 or 2 == 2 }",
            "rule r { condition: (1 == 1 and 2 == 2) or (3 == 3 and 4 == 4) }",
            "rule r { condition: not (1 == 1 and 2 == 2) }",
            "rule r { strings: $a = \"x\" condition: $a and #a > 1 or any of them }",
        ] {
            let p = compile(source).unwrap();
            for (index, op) in p.code.iter().enumerate() {
                let target = match op {
                    Op::Jump(t) | Op::JumpIfFalse(t) | Op::JumpIfTrue(t) => Some(*t),
                    _ => None,
                };
                if let Some(t) = target {
                    assert!(
                        (t as usize) <= p.code.len(),
                        "{source}: instruction {index} jumps to {t}, past {} instructions",
                        p.code.len()
                    );
                    assert_ne!(
                        t,
                        u32::MAX,
                        "{source}: instruction {index} kept its placeholder"
                    );
                }
            }
        }
    }

    #[test]
    fn no_jump_goes_backwards() {
        // The step bound in `compute_limits` assumes an acyclic program. A
        // backward jump would make `max_steps` an under-estimate and could
        // loop forever at scan time.
        for source in [
            "rule r { condition: 1 == 1 and 2 == 2 }",
            "rule r { condition: 1 == 1 or 2 == 2 }",
            "rule r { strings: $a = \"x\" condition: all of them and $a }",
        ] {
            let p = compile(source).unwrap();
            for (index, op) in p.code.iter().enumerate() {
                let target = match op {
                    Op::Jump(t) | Op::JumpIfFalse(t) | Op::JumpIfTrue(t) => Some(*t),
                    _ => None,
                };
                if let Some(t) = target {
                    assert!(
                        t as usize >= index.saturating_sub(1),
                        "{source}: back jump at {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn and_short_circuits_over_its_right_hand_side() {
        // The second comparison must sit behind a jump, not before it.
        let p = compile("rule r { condition: filesize == 0 and entrypoint == 1 }").unwrap();
        let text = p.disassemble();
        let jump = text.find("jump_if_false").unwrap();
        let rhs = text.find("entrypoint").unwrap();
        assert!(
            jump < rhs,
            "the right-hand side must be jumped over:\n{text}"
        );
    }

    // -- refusals, by name -----------------------------------------------

    #[test]
    fn a_module_field_is_refused_under_its_own_tag() {
        // The examples have to be members that are in fact *still* refused, or
        // the test stops testing the histogram and starts testing nothing. Both
        // of these are refused on purpose rather than for want of an
        // implementation — see `pe_element` — which is what makes them durable
        // examples where a member that is merely unimplemented is not: that one
        // graduates, and the test that named it has to be rewritten.
        //
        // The first is a name the language does not have: a data directory is
        // an address and a size, and there is no `name` member on one. Naming a
        // member that does not exist rather than one that is merely unimplemented
        // is what makes this line survive the next member that gets implemented.
        assert_eq!(
            feature("rule r { condition: pe.data_directories[0].name == \"x\" }"),
            "module field"
        );
        // The second is the deliberate refusal: verifying an Authenticode
        // signature means implementing chain validation, and a member that
        // answered `false` for every file would make `not pe.signatures[i].verified`
        // select the entire disk.
        assert_eq!(
            feature("rule r { condition: pe.signatures[0].verified }"),
            "module field"
        );
    }

    #[test]
    fn a_resource_member_now_compiles_instead_of_being_refused() {
        // The other half of the test above. `pe.number_of_resources` was the
        // standing example of a member that was not implemented, and it is one
        // now; kept as its own test because the two answer different questions.
        // That one asks whether a refusal still refuses, which is what keeps the
        // refusal histogram honest as the module grows. This one asks whether a
        // member that used to be refused has actually become a reader, which is
        // the direction that produces missed detections when it is wrong.
        let text = dis(
            "rule r { condition: pe.number_of_resources > 2 and              pe.resources[0].offset == 0 and pe.rich_signature.toolid(1, 2) > 0 }",
        );
        assert!(
            text.contains("pe_field     pe.number_of_resources"),
            "{text}"
        );
        assert!(
            text.contains("pe_indexed   pe.resources[].offset"),
            "{text}"
        );
        assert!(
            text.contains("pe_call      pe.rich_signature.toolid"),
            "{text}"
        );
    }

    #[test]
    fn a_signature_member_now_compiles_instead_of_being_refused() {
        // `pe.number_of_signatures` used to be the standing example of a member
        // that was not implemented, and this is the other half of that test:
        // the members that *are* implemented compile, and the one whose refusal
        // is a decision rather than a backlog does not.
        let text = dis("rule r { condition: pe.number_of_signatures > 0 and \
             pe.signatures[0].serial == \"0d:bf\" }");
        assert!(
            text.contains("pe_field     pe.number_of_signatures"),
            "{text}"
        );
        assert!(
            text.contains("pe_indexed   pe.signatures[].serial"),
            "{text}"
        );

        // `.verified` is refused on purpose. Answering it `false` for every
        // file would make `not pe.signatures[i].verified` select the whole
        // disk, so a rule that asks is a rule that does not load.
        assert_eq!(
            feature("rule r { condition: pe.signatures[0].verified }"),
            "module field"
        );
    }

    #[test]
    fn an_array_loop_compiles_to_the_array_form_of_the_loop() {
        // `for 12 resource in pe.resources` is the corpus's own spelling, at
        // line 71995 of the extended set. The count goes on the stack first and
        // the length after it, so the single `le` after the loop reads
        // `needed <= count`.
        let text =
            dis("rule r { condition: for 12 resource in pe.resources : ( resource.type == 10 ) }");
        assert!(text.contains("push 12"), "{text}");
        assert!(
            text.contains("pe_field     pe.number_of_resources"),
            "{text}"
        );
        assert!(text.contains("for_each     count"), "{text}");
        assert!(text.contains("for_step     count"), "{text}");
        assert!(text.contains("pe_indexed   pe.resources[].type"), "{text}");
        // The index is the loop variable, read from its slot.
        assert!(text.contains("var_load     v0"), "{text}");
        assert!(text.contains("le"), "{text}");
    }

    #[test]
    fn an_array_loops_variable_is_the_index_and_not_the_element() {
        // `s.name` has to reach `pe.sections[i].name` with `i` in the variable
        // slot — the same opcode a hand-written `pe.sections[2].name` uses. If
        // this ever compiled the element itself onto the stack, the loop body
        // would compare a section's *name* and the array lookup would take a
        // string where an index belongs.
        let text = dis(r#"rule r { condition: for any s in pe.sections : ( s.name == ".text" ) }"#);
        let load = text.find("var_load     v0").expect(&text);
        let indexed = text.find("pe_indexed   pe.sections[].name").expect(&text);
        assert!(
            load < indexed,
            "the index is read before the lookup:\n{text}"
        );
        assert!(text.contains("for_each     any"), "{text}");
    }

    #[test]
    fn an_array_that_cannot_be_walked_is_refused_by_name() {
        // Every one of these is a loop over something the interpreter cannot
        // read an element of. Accepting them would produce a rule that loads,
        // runs, and is never true — the silent missed detection, arrived at
        // through the front door.
        //
        // Each shape here is one that cannot stop being refused, which is what
        // keeps the list from having to be rewritten as the module grows. A loop
        // over an array the engine merely has not implemented yet — which is what
        // stood here, over `pe.export_details`, until that array was read — is
        // the one kind of example that graduates.
        for condition in [
            // A name that is not an array: a typo, and correctly refused as one.
            "for any s in pe.sectons : ( s.name == \"x\" )",
            // An element rather than the array.
            "for any r in pe.resources[0] : ( r.type == 10 )",
            // Not a module array at all.
            "for any x in filesize : ( x == 1 )",
            // A member that is not on the element.
            //
            // A percentage is absent from this list because the grammar does
            // not build one here — `for 50%` is not a loop quantifier, only a
            // set quantifier — so there is no parse to refuse. The compiler
            // still answers for one, because `Expr::ForEach` is a public type
            // the parser is not the only possible author of.
            "for any r in pe.resources : ( r.entropy > 0.0 )",
        ] {
            let source = format!("rule r {{ condition: {condition} }}");
            assert!(
                compile(&source).is_err(),
                "{condition} should have been refused"
            );
        }
    }

    #[test]
    fn a_range_loops_variable_offers_no_members() {
        // `i` is a number and `i.name` is a typo, not a member of a module
        // array. The distinction is what the binding's array records, and
        // without it this would compile to a section name indexed by the loop
        // counter — a rule that reads the wrong field of the right file.
        assert!(
            compile("rule r { condition: for any i in (0..3) : ( i.name == \"x\" ) }").is_err()
        );
    }

    #[test]
    fn a_member_that_is_not_implemented_is_refused_rather_than_defaulted() {
        // The failure this guards against is a member compiling to a constant
        // zero, which would make every rule that names it stop matching while
        // looking supported. Refusing costs a detection that does not fire and
        // says so in the histogram; defaulting costs one that nobody ever sees.
        //
        // Every name in this list is one the *language* does not define, which
        // is what makes the list durable. `pe.export_details[0].name` used to be
        // in it and is a member now, so the line that named it had to be
        // rewritten; a member that does not exist cannot graduate that way.
        for condition in [
            "pe.sections[0].entropy > 0.0",
            "pe.data_directories[0].name == \"x\"",
            "pe.signatures[0].verified",
            "pe.resources[0].entropy > 0.0",
        ] {
            let source = format!("rule r {{ condition: {condition} }}");
            let error = compile(&source).unwrap_err();
            assert!(
                matches!(error.feature, "module field" | "function call"),
                "{condition}: refused as {:?}",
                error.feature
            );
        }
    }

    #[test]
    fn the_implemented_members_compile_to_the_op_that_reads_them() {
        let text = dis("rule r { condition: pe.number_of_sections > 2 and pe.is_dll }");
        assert!(
            text.contains("pe_field     pe.number_of_sections"),
            "{text}"
        );
        assert!(text.contains("pe_field     pe.is_dll"), "{text}");
    }

    #[test]
    fn an_indexed_member_compiles_its_index_before_the_read() {
        // The index is an arbitrary expression — `pe.sections[pe.number_of_sections - 1]`
        // is the last section — so it has to be pushed before the op that pops
        // it, and the op has to be the one the member names.
        let text =
            dis("rule r { condition: pe.sections[pe.number_of_sections - 1].name == \".text\" }");
        let number = text.find("pe_field     pe.number_of_sections").unwrap();
        let indexed = text.find("pe_indexed   pe.sections[].name").unwrap();
        assert!(number < indexed, "{text}");
    }

    #[test]
    fn a_section_member_may_not_be_read_from_the_directory_array() {
        // The array name is part of the member lookup. Without that check this
        // would compile, and read a section name out of the data directories.
        assert_eq!(
            feature("rule r { condition: pe.data_directories[0].name == \".text\" }"),
            "module field"
        );
    }

    #[test]
    fn a_pe_function_with_the_wrong_number_of_arguments_is_refused() {
        assert_eq!(
            feature("rule r { condition: pe.section_index(0, 1) == 0 }"),
            "function call"
        );
        assert_eq!(
            feature("rule r { condition: pe.section_index() == 0 }"),
            "function call"
        );
    }

    #[test]
    fn a_pe_function_compiles_when_it_is_called_correctly() {
        let text = dis("rule r { condition: pe.section_index(0) == 0 }");
        assert!(text.contains("pe_call      pe.section_index"), "{text}");
    }

    /// The `pe` function the first `PeCall` in a compiled condition names.
    ///
    /// Read off the opcode rather than the disassembly, because the two
    /// `pe.imports` variants deliberately print the same name — a rule author
    /// wrote one name and should see one name — so the disassembly cannot tell
    /// them apart and cannot be asked to.
    fn pe_call_of(source: &str) -> PeFunc {
        let program = compile(source).expect("the test source must compile");
        program
            .code
            .iter()
            .find_map(|op| match op {
                Op::PeCall(func) => Some(*func),
                _ => None,
            })
            .expect("the program must contain a pe call")
    }

    #[test]
    fn the_two_spellings_of_imports_compile_to_the_two_variants() {
        // The interpreter pops a fixed number of operands per opcode, so the
        // one-argument and two-argument forms cannot share a variant: one of the
        // two would pop the wrong count, and a wrong count on a stack machine is
        // every later expression reading its operand from the wrong slot.
        assert_eq!(
            pe_call_of(r#"rule r { condition: pe.imports("ADVAPI32.dll") }"#),
            PeFunc::Imports
        );
        assert_eq!(
            pe_call_of(r#"rule r { condition: pe.imports("ADVAPI32.dll", "RegOpenKeyExW") }"#),
            PeFunc::ImportsSymbol
        );
        // Both are one name to a reader, which is what the disassembly shows and
        // what an error message has to say.
        assert_eq!(PeFunc::Imports.as_str(), PeFunc::ImportsSymbol.as_str());
    }

    #[test]
    fn a_three_argument_imports_is_refused_with_the_range_it_accepts() {
        // The message has to name both arities: a rule author who wrote three
        // would otherwise be told the function takes one and left to guess that
        // two is also allowed.
        let error = compile(r#"rule r { condition: pe.imports("a", "b", "c") }"#)
            .expect_err("three arguments must be refused");
        assert_eq!(error.feature, "function call");
        assert!(
            error.message.contains("1 or 2 arguments"),
            "{}",
            error.message
        );
        // The name as a rule writes it, without the parentheses the message
        // frames it in — so the author can find it in their own file.
        assert!(error.message.contains("pe.imports"), "{}", error.message);
    }

    #[test]
    fn the_exports_and_imphash_members_are_no_longer_refused() {
        // These three were refused until the tables behind them were read. The
        // test is here rather than only in the VM because a member that the
        // parser accepts and the compiler drops would be a rule that loads and
        // silently matches nothing.
        for source in [
            r#"rule r { condition: pe.exports("Init") }"#,
            "rule r { condition: pe.imphash() == \"x\" }",
            "rule r { condition: pe.number_of_imports > 0 }",
            "rule r { condition: pe.number_of_exports > 0 }",
        ] {
            let text = dis(source);
            assert!(
                text.contains("pe_call") || text.contains("pe_field"),
                "{source} -> {text}"
            );
        }
    }

    #[test]
    fn a_regex_is_refused_under_its_own_tag() {
        // `matches` is compiled. A `/regex/` in an operand position is not,
        // because there is nothing for it to be applied to — and the lexer
        // cannot even produce one there, since it only opens a regex after
        // `matches` or after `=`. So this is built as a tree, which is the only
        // way to reach the arm: the type permits it whether or not the grammar
        // does, and the answer for it must not be a wrong one.
        let expr = Expr::Arithmetic {
            op: ArithOp::Add,
            lhs: Box::new(Expr::Int(1)),
            rhs: Box::new(Expr::Regex {
                body: "a+".to_owned(),
                flags: String::new(),
            }),
        };
        let e = compile_expr(&expr).unwrap_err();
        assert_eq!(e.feature, "regex");
        assert!(e.message.contains("matches"), "{}", e.message);
    }

    #[test]
    fn the_loop_that_is_still_missing_is_refused_under_its_own_tag() {
        assert_eq!(
            feature(r#"rule r { strings: $a = "x" condition: for any of them : ( $ at 0 ) }"#),
            "for .. of"
        );
    }

    #[test]
    fn a_percentage_over_a_range_is_refused_rather_than_guessed_at() {
        // `for 50% i in (0..10)` cannot be written: the parser only takes a
        // count or a keyword there, because a percentage of a range is not a
        // thing YARA has either. The compiler still refuses it, so that the
        // parser being widened later cannot quietly turn it into 50 *per cent
        // of what*, which is the kind of guess a detection must not make.
        let ast = Expr::ForIn {
            quantifier: Quantifier::Percentage(50),
            var: "i".into(),
            from: Box::new(Expr::Int(0)),
            to: Box::new(Expr::Int(10)),
            body: Box::new(Expr::Bool(true)),
        };
        let error = compile_expr(&ast).expect_err("a percentage of a range is not defined");
        assert_eq!(error.feature, "for .. in range");
    }

    #[test]
    fn an_unknown_name_is_refused_as_an_unresolved_one() {
        // `i` is neither bound by a `for` nor a rule of this set — and this
        // entry point has no set, so every name is unknown here. The tag says
        // which of the two readings was unavailable rather than blaming the
        // loop, which is what it used to say when rule references did not
        // exist.
        assert_eq!(feature("rule r { condition: i == 1 }"), "unresolved name");
        assert_eq!(
            feature("rule r { condition: SOME_OTHER_RULE }"),
            "unresolved name"
        );
    }

    #[test]
    fn a_name_alone_compiles_as_a_rule_reference_when_there_is_a_set() {
        // The same bare name that is refused above resolves here, because the
        // table says what it means. The two entry points differ in exactly this
        // and nothing else.
        let file = parse_file("rule OTHER { condition: true } rule r { condition: OTHER }")
            .expect("the test source must parse");
        let refs = RuleRefs::from_rules(&file.rules);
        let program = compile_rule_with(&file.rules[1], &refs).expect("OTHER is a rule here");
        assert!(
            program.code.contains(&Op::RuleRef(0)),
            "{}",
            program.disassemble()
        );
    }

    #[test]
    fn a_loop_variable_shadows_a_rule_of_the_same_name() {
        // The nearer binding wins: a rule named `i` does not make `i` inside
        // the loop mean the rule, which is what makes the two forms of a bare
        // name distinguishable by scope rather than by spelling.
        let source = "rule i { condition: true } \
                      rule r { condition: for any i in (0..3) : ( i == 1 ) }";
        let file = parse_file(source).expect("the test source must parse");
        let refs = RuleRefs::from_rules(&file.rules);
        let program = compile_rule_with(&file.rules[1], &refs).expect("the loop's `i` is nearer");
        assert!(
            !program.code.contains(&Op::RuleRef(0)),
            "{}",
            program.disassemble()
        );
        assert!(program.disassemble().contains("var_load"), "{program:?}");
    }

    #[test]
    fn an_undefined_string_is_its_own_error() {
        // Not a coverage gap — an author error, and the tag says so.
        assert_eq!(
            feature(r#"rule r { strings: $a = "x" condition: $b }"#),
            "undefined string"
        );
    }

    #[test]
    fn an_empty_string_set_is_refused_rather_than_never_firing() {
        // `any of ($zz*)` where the rule defines no `$zz...`. Treated as false
        // it would be a rule that silently never matches; refused, it is a typo
        // its author finds immediately.
        assert_eq!(
            feature(r#"rule r { strings: $a = "x" condition: any of ($zz*) }"#),
            "empty string set"
        );
    }

    #[test]
    fn the_buffer_readers_all_compile() {
        for name in [
            "uint8", "uint16", "uint32", "int8", "int16", "int32", "uint16be", "uint32be",
            "int16be", "int32be", "uint8be", "int8be",
        ] {
            let source = format!("rule r {{ condition: {name}(0) == 1 }}");
            let p = compile(&source).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                p.code
                    .iter()
                    .any(|op| !matches!(op, Op::Push(_) | Op::Eq | Op::Ret)),
                "{name} produced no read:\n{}",
                p.disassemble()
            );
        }
    }

    #[test]
    fn a_reader_with_the_wrong_number_of_arguments_is_refused() {
        assert_eq!(
            feature("rule r { condition: uint16(0, 1) == 1 }"),
            "function call"
        );
        assert_eq!(
            feature("rule r { condition: uint16() == 1 }"),
            "function call"
        );
    }

    #[test]
    fn equals_maps_onto_ordinary_equality() {
        // Two spellings of one question must not become two code paths.
        assert!(dis("rule r { condition: \"a\" equals \"a\" }").contains("eq"));
    }

    #[test]
    fn an_unknown_dotted_call_names_the_path_in_its_message() {
        let e = compile("rule r { condition: cuckoo.hash() == 1 }").unwrap_err();
        assert_eq!(e.feature, "function call");
        assert!(e.message.contains("cuckoo.hash"), "{}", e.message);
    }

    #[test]
    fn the_statistics_that_are_a_choice_rather_than_a_consequence_are_refused() {
        // Every one of these could be given *a* value. The problem is that the
        // value depends on a normalization or a tie-break that the corpus's
        // thresholds were calibrated against, so compiling a different choice
        // would give a rule that fires on files its author excluded. They are
        // refused by name, and the name is in the message, which is what makes
        // the refusal actionable.
        //
        // `math.deviation` stood at the head of this list until its definition
        // could be pinned rather than chosen; see `ModuleFunc`.
        for (source, named) in [
            ("math.mode(0, filesize) == 0", "math.mode"),
            (
                "math.serial_correlation(0, filesize) > 0.1",
                "math.serial_correlation",
            ),
            ("hash.crc32(0, filesize) == \"1\"", "hash.crc32"),
        ] {
            let e = compile(&format!("rule r {{ condition: {source} }}")).unwrap_err();
            assert_eq!(e.feature, "function call", "{source}");
            assert!(e.message.contains(named), "{source}: {}", e.message);
        }
    }

    #[test]
    fn the_two_forms_of_the_deviation_compile_to_the_two_variants() {
        // One name, two opcodes, chosen by the argument count — the same shape
        // `hash.md5` takes. The region form is the one the corpus writes; the
        // string form exists because a rule that has just decoded a structure
        // out of the `pe` module has bytes and no region they came from.
        assert_eq!(
            module_call_of("rule r { condition: math.deviation(0, 16, 89.0) > 1 }"),
            ModuleFunc::Deviation
        );
        assert_eq!(
            module_call_of("rule r { condition: math.deviation(\"abc\", 89.0) > 1 }"),
            ModuleFunc::DeviationStr
        );
        // Both read back as one name in a disassembly, because they are one
        // name in the language.
        assert_eq!(
            ModuleFunc::Deviation.as_str(),
            ModuleFunc::DeviationStr.as_str()
        );
    }

    #[test]
    fn mean_bytes_is_the_constant_the_module_documents() {
        let text =
            dis("rule r { condition: math.deviation(0, filesize, math.MEAN_BYTES) == 64.0 }");
        assert!(text.contains("push 127.5"), "{text}");
    }

    #[test]
    fn the_string_module_members_compile_to_their_ops() {
        assert_eq!(
            module_call_of("rule r { condition: string.length(\"abc\") == 3 }"),
            ModuleFunc::StringLength
        );
        assert_eq!(
            module_call_of("rule r { condition: string.to_int(\"12\") == 12 }"),
            ModuleFunc::StringToInt
        );
        assert_eq!(
            module_call_of("rule r { condition: string.to_int(\"11\", 8) == 9 }"),
            ModuleFunc::StringToIntBase
        );
    }

    #[test]
    fn the_matches_operator_puts_the_pattern_in_the_program_and_the_value_on_the_stack() {
        // Corpus line 209332, the one rule in the corpus that uses it:
        // `pe.resources[0].name_string matches /[0-9]\x00[0-9]\x00/`. The
        // pattern is a literal, so it is compiled once and indexed rather than
        // pushed — which is why the opcode takes one operand and the stack
        // effect is zero.
        let p = compile(
            r#"rule r { condition: pe.resources[0].name_string matches /[0-9]\x00[0-9]\x00/ }"#,
        )
        .unwrap();
        assert_eq!(p.regexes.len(), 1);
        assert_eq!(p.regexes[0].body, r"[0-9]\x00[0-9]\x00");
        assert_eq!(p.regexes[0].flags, "");
        assert!(p.code.contains(&Op::Matches(0)));
        assert_eq!(Op::Matches(0).stack_delta(), 0);
    }

    #[test]
    fn one_pattern_applied_twice_is_written_into_the_program_once() {
        let p = compile(
            r#"rule r { condition: pe.sections[0].name matches /x/ and pe.sections[1].name matches /x/ }"#,
        )
        .unwrap();
        assert_eq!(p.regexes.len(), 1);
    }

    #[test]
    fn the_matches_flags_are_part_of_the_pattern() {
        // `/x/i` and `/x/` match different bytes, so they are different specs
        // and each gets its own entry.
        let p = compile(
            r#"rule r { condition: pe.sections[0].name matches /x/ and pe.sections[1].name matches /x/i }"#,
        )
        .unwrap();
        assert_eq!(p.regexes.len(), 2);
        assert_eq!(p.regexes[1].flags, "i");
    }

    #[test]
    fn a_matches_pattern_that_does_not_compile_is_refused_rather_than_stored() {
        // The whole reason the pattern is compiled at compile time: a rule that
        // entered the database with a pattern the engine cannot build is a rule
        // that silently never fires, and a rule that never fires is a gap in
        // the verdict that nothing reports.
        // `/(/ ` is a regex whose body is a single opening parenthesis: it
        // lexes, and the regex parser is what refuses it.
        let e = compile("rule r { condition: pe.sections[0].name matches /(/ }").unwrap_err();
        assert_eq!(e.feature, "invalid regex");
        assert!(e.message.contains("unclosed group"), "{}", e.message);
    }

    #[test]
    fn a_matches_pattern_with_a_flag_the_engine_lacks_is_refused_by_name() {
        let e = compile(r#"rule r { condition: pe.sections[0].name matches /x/q }"#).unwrap_err();
        assert_eq!(e.feature, "invalid regex");
        assert!(e.message.contains("/.../q"), "{}", e.message);
    }

    #[test]
    fn a_matches_whose_right_hand_side_is_not_a_pattern_is_refused_by_name() {
        let e = compile(r#"rule r { condition: pe.sections[0].name matches pe.sections[1].name }"#)
            .unwrap_err();
        assert_eq!(e.feature, "regex");
        assert!(e.message.contains("literal"), "{}", e.message);
    }

    #[test]
    fn a_string_call_with_the_wrong_number_of_arguments_is_refused_by_arity() {
        let e = compile("rule r { condition: string.length(\"a\", \"b\") == 1 }").unwrap_err();
        assert_eq!(e.feature, "function call");
        assert!(e.message.contains("string.length"), "{}", e.message);
        assert!(e.message.contains("takes 1"), "{}", e.message);
    }

    #[test]
    fn the_two_spellings_of_a_hash_compile_to_the_two_variants() {
        assert_eq!(
            module_call_of(r#"rule r { condition: hash.md5(0, 16) == "x" }"#),
            ModuleFunc::HashRange(HashKind::Md5)
        );
        // The string form, which is how the corpus hashes a decoded structure
        // rather than a region of the file.
        assert_eq!(
            module_call_of(r#"rule r { condition: hash.md5("abc") == "x" }"#),
            ModuleFunc::HashStr(HashKind::Md5)
        );
        // Both read back as one name, because they are one name in the
        // language — the argument count is what tells them apart.
        assert_eq!(
            ModuleFunc::HashStr(HashKind::Md5).as_str(),
            ModuleFunc::HashRange(HashKind::Md5).as_str()
        );
    }

    #[test]
    fn a_hash_call_with_neither_one_nor_two_arguments_says_what_it_accepts() {
        let e = compile("rule r { condition: hash.md5(0, 16, 32) == \"x\" }").unwrap_err();
        assert_eq!(e.feature, "function call");
        assert!(e.message.contains("hash.md5"), "{}", e.message);
        assert!(e.message.contains("offset and a size"), "{}", e.message);
    }

    #[test]
    fn a_math_call_with_the_wrong_number_of_arguments_is_refused_by_arity() {
        let e = compile("rule r { condition: math.entropy(0) > 7 }").unwrap_err();
        assert_eq!(e.feature, "function call");
        assert!(e.message.contains("math.entropy"), "{}", e.message);
        assert!(e.message.contains("takes 2"), "{}", e.message);
    }

    #[test]
    fn every_compiled_module_function_has_the_arity_the_lookup_claims() {
        // The table and the arity are written in two places, and a mismatch is
        // an interpreter that pops one operand too many — which does not fail,
        // it reads whatever was underneath. This is the assertion that keeps
        // the two in step.
        for (source, args) in [
            ("math.entropy(0, 16) > 1", 2),
            ("math.mean(0, 16) > 1", 2),
            ("math.count(0, 0, 16) > 1", 3),
            ("math.percentage(0, 0, 16) > 1", 3),
            ("math.min(1, 2) > 1", 2),
            ("math.max(1, 2) > 1", 2),
            ("math.abs(-1) > 1", 1),
            ("math.to_number(true) > 1", 1),
            ("math.in_range(1, 0, 2) > 0", 3),
            // One name, two arities: the count is what picks the opcode, so
            // both have to be in the table.
            ("math.deviation(0, 16, 89.0) > 1", 3),
            ("math.deviation(\"ab\", 89.0) > 1", 2),
            ("string.length(\"a\") > 0", 1),
            ("string.to_int(\"1\") > 0", 1),
            ("string.to_int(\"1\", 8) > 0", 2),
        ] {
            let func = module_call_of(&format!("rule r {{ condition: {source} }}"));
            assert_eq!(func.arity() as usize, args, "{source}");
        }
    }

    /// The module function the first `ModuleCall` in a compiled condition names.
    fn module_call_of(source: &str) -> ModuleFunc {
        let program = compile(source).expect("the test source must compile");
        program
            .code
            .iter()
            .find_map(|op| match op {
                Op::ModuleCall(func) => Some(*func),
                _ => None,
            })
            .expect("the program must contain a module call")
    }

    #[test]
    fn nesting_past_the_bound_is_refused_rather_than_overflowing() {
        // Constructed directly rather than parsed, because the parser refuses
        // to build this in the first place — which is the point: the guard here
        // covers trees that did not come through the parser.
        let mut expr = Expr::Int(1);
        for _ in 0..(MAX_DEPTH + 10) {
            expr = Expr::Not(Box::new(expr));
        }
        let table = StringTable::default();
        let err = compile_condition(&expr, &table, Span::new(0, 0)).unwrap_err();
        assert_eq!(err.feature, "expression nesting");
    }

    #[test]
    fn a_condition_that_fits_the_bound_compiles() {
        let mut expr = Expr::Int(1);
        for _ in 0..(MAX_DEPTH / 4) {
            expr = Expr::Not(Box::new(expr));
        }
        let table = StringTable::default();
        let p = compile_condition(&expr, &table, Span::new(0, 0)).unwrap();
        assert_eq!(p.code.last(), Some(&Op::Ret));
    }

    #[test]
    fn a_rule_compiles_with_its_own_string_count() {
        let p = compile(r#"rule r { strings: $a = "x" $b = "y" condition: any of them }"#).unwrap();
        assert_eq!(p.string_count, 2);
    }

    // -- the limits the interpreter relies on ------------------------------

    #[test]
    fn a_straight_line_program_reports_its_own_length() {
        let p = compile("rule r { condition: 1 }").unwrap();
        // push, ret — two instructions, so the longest path is two.
        assert_eq!(p.code.len(), 2);
        assert_eq!(p.max_steps, 2);
        assert_eq!(p.max_stack, 1);
    }

    #[test]
    fn a_branching_program_reports_the_longer_path() {
        let p = compile("rule r { condition: 1 == 1 and 2 == 2 }").unwrap();
        // Both operands run when the left is true, and that is the longer path.
        assert!(
            p.max_steps >= 6,
            "{} steps:\n{}",
            p.max_steps,
            p.disassemble()
        );
        assert!(
            p.max_steps <= p.code.len() as u32,
            "a path cannot exceed the program"
        );
    }

    #[test]
    fn the_step_bound_never_exceeds_the_program_length() {
        // The interpreter uses this to cap its work; a bound larger than the
        // program would be no bound at all.
        for source in [
            "rule r { condition: 1 == 1 and 2 == 2 }",
            "rule r { condition: 1 == 1 or 2 == 2 }",
            "rule r { strings: $a = \"x\" condition: any of them and #a > 2 }",
            "rule r { condition: not ((1 == 1 or 2 == 2) and (3 == 3)) }",
        ] {
            let p = compile(source).unwrap();
            assert!(
                p.max_steps <= p.code.len() as u32,
                "{source}: {} steps over {} instructions",
                p.max_steps,
                p.code.len()
            );
        }
    }

    #[test]
    fn the_stack_bound_covers_the_deepest_expression() {
        let p = compile("rule r { condition: 1 + 2 * 3 - 4 / 5 }").unwrap();
        // A left-deep arithmetic chain never holds more than two intermediates.
        assert!(
            p.max_stack >= 2 && p.max_stack <= 4,
            "max_stack {}",
            p.max_stack
        );
    }

    #[test]
    fn the_stack_bound_is_reported_for_a_string_set() {
        // `OfAny(n)` pops n and pushes one, so the results are all live at once.
        let p = compile(r#"rule r { strings: $a = "x" $b = "y" $c = "z" condition: any of them }"#)
            .unwrap();
        assert!(p.max_stack >= 3, "max_stack {}", p.max_stack);
    }
}
