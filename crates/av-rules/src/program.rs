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

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::rc::Rc;

use crate::ast::Span;

/// A value on the virtual machine's stack.
///
/// Strings are `Rc<str>` rather than `String`: the interpreter hands the same
/// constant out repeatedly, and cloning an `Rc` is a refcount bump where
/// cloning a `String` is an allocation per comparison.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// The result of reading a field that does not exist for this file, or of
    /// any operation involving one. Behaves as "false" in a boolean context and
    /// makes every comparison false.
    Undefined,
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(Rc<str>),
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
            Value::Str(s) => !s.is_empty(),
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
            Value::Str(_) | Value::Undefined => None,
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
            Value::Str(_) => "string",
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
            Value::Str(s) => write!(f, "{s}"),
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
    /// Serialised through the `rc_str` module rather than by turning on serde's `rc`
    /// feature: that feature would apply to every `Rc` and `Arc` in the
    /// workspace, which is a large change to make for one field, and it makes
    /// shared ownership silently serialisable in places where sharing is
    /// meaningless.
    #[serde(with = "rc_str")]
    Str(Rc<str>),
}

/// Serde adapter for a reference-counted string.
///
/// It is written and read as a plain string. The refcount is deliberately not
/// preserved: what comes back is a fresh `Rc` holding the same text, which is
/// what the interpreter wants and what makes the round-trip test meaningful.
mod rc_str {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::rc::Rc;

    pub fn serialize<S: Serializer>(value: &Rc<str>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Rc<str>, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(Rc::from(text.as_str()))
    }
}

impl Const {
    pub fn to_value(&self) -> Value {
        match self {
            Const::Bool(b) => Value::Bool(*b),
            Const::Int(i) => Value::Int(*i),
            Const::Float(x) => Value::Float(*x),
            Const::Str(s) => Value::Str(Rc::clone(s)),
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

    /// Jump to `target` unconditionally.
    Jump(u32),
    /// Pop a value and jump to `target` if it is false.
    JumpIfFalse(u32),
    /// Pop a value and jump to `target` if it is true.
    JumpIfTrue(u32),

    /// Pop the condition and finish. The rule matches if it was true.
    Ret,
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
            Op::Ret => -1,
        }
    }
}

/// A compiled condition.
///
/// Produced by `compiler::compile_condition` and executed by `vm::run`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Program {
    pub code: Vec<Op>,
    pub constants: Vec<Const>,
    /// How many strings the rule defines.
    ///
    /// Kept with the program because `them` and `$a*` in the condition expand to
    /// this many string slots at compile time, so the interpreter must know how
    /// many results the matcher will hand it.
    pub string_count: u32,
    /// Longest execution path, in instructions.
    ///
    /// Static, so the scanner can bound the work a rule can cost before running
    /// it. A condition is acyclic — there are no backward jumps — so this is
    /// finite and cheap to compute once at compile time.
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
            string_count: 0,
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
    /// The longest acyclic path, found by a backward pass. Jump targets are
    /// always forward — the compiler never emits a loop — so every successor
    /// has already been computed when its predecessor is reached, and one pass
    /// suffices without a worklist.
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

        // `steps[i]` is the longest path from instruction `i` to the end.
        let mut steps = vec![0u32; n.saturating_add(1)];
        for i in (0..n).rev() {
            let target = |t: u32| steps.get(t as usize).copied().unwrap_or(0);
            let after = steps[i.saturating_add(1)];
            steps[i] = 1u32.saturating_add(match self.code[i] {
                Op::Ret => 0,
                Op::Jump(t) => target(t),
                Op::JumpIfFalse(t) | Op::JumpIfTrue(t) => after.max(target(t)),
                _ => after,
            });
        }
        self.max_steps = steps.first().copied().unwrap_or(0);

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
            Some(Const::Str(s)) => format!("{s:?}"),
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
        assert!(!Value::Str(Rc::from("")).is_truthy());
        assert!(!Value::Bool(false).is_truthy());
        assert!(Value::Int(1).is_truthy());
        assert!(Value::Int(-1).is_truthy());
        assert!(Value::Str(Rc::from("x")).is_truthy());
    }

    #[test]
    fn booleans_convert_to_numbers_for_arithmetic() {
        assert_eq!(Value::Bool(true).as_number(), Some(1.0));
        assert_eq!(Value::Bool(false).as_number(), Some(0.0));
        assert_eq!(Value::Str(Rc::from("1")).as_number(), None);
        assert_eq!(Value::Undefined.as_number(), None);
    }

    #[test]
    fn identical_constants_are_stored_once() {
        let mut p = Program::new(Span::new(0, 0));
        let a = p.constant(Const::Str(Rc::from("kernel32.dll")));
        let b = p.constant(Const::Str(Rc::from("kernel32.dll")));
        let c = p.constant(Const::Str(Rc::from("ntdll.dll")));
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
        let k = p.constant(Const::Str(Rc::from("MZ")));
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
