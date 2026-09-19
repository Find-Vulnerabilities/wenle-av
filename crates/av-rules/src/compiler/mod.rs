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

mod error;
mod strings;

pub use error::CompileError;
pub use strings::StringTable;

use crate::ast::{ArithOp, BitOp, CmpOp, Expr, Quantifier, Rule, Span, StringOp};
use crate::program::{Cmp, Const, Op, Program};

/// Deepest expression nesting the compiler will descend.
///
/// The parser already bounds what it builds (`parser::MAX_DEPTH`), and this is
/// the same bound applied at the other end. It is here because compiling
/// recurses exactly as hard as parsing did, so a tree that reached the compiler
/// without going through the parser — an importer, a test, a future editor —
/// would otherwise walk straight past the guard that exists for this purpose
/// and overflow the stack anyway.
const MAX_DEPTH: u32 = 128;

/// Compile a rule's condition.
pub fn compile_rule(rule: &Rule) -> Result<Program, CompileError> {
    compile_condition(
        &rule.condition,
        &StringTable::from_defs(&rule.strings),
        rule.span,
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
    let mut compiler = Compiler {
        program: Program::new(span),
        strings,
        span,
        depth: 0,
    };
    compiler.compile(condition)?;
    compiler.program.emit(Op::Ret);
    compiler.program.compute_limits();
    compiler.program.string_count = u32::try_from(strings.len())
        .map_err(|_| CompileError::too_many_strings(strings.len(), span))?;
    Ok(compiler.program)
}

struct Compiler<'a> {
    program: Program,
    strings: &'a StringTable,
    span: Span,
    depth: u32,
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
                let k = self.program.constant(Const::Str(s.as_str().into()));
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
                return Err(CompileError::unsupported(
                    "module field",
                    path.render(),
                    self.span,
                ));
            }
            Expr::Index { .. } => {
                return Err(CompileError::unsupported(
                    "index",
                    "indexing a module array",
                    self.span,
                ));
            }
            Expr::Variable(name) => {
                return Err(CompileError::unsupported(
                    "loop variable",
                    format!("`{name}` is only meaningful inside a `for` loop"),
                    self.span,
                ));
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
            Expr::ForIn { .. } => {
                return Err(CompileError::unsupported(
                    "for .. in range",
                    "iterating an integer range",
                    self.span,
                ));
            }
            Expr::ForEach { .. } => {
                return Err(CompileError::unsupported(
                    "for .. in array",
                    "iterating a module array",
                    self.span,
                ));
            }
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
        let _ = whole;
        Err(CompileError::unsupported(
            "function call",
            path.render(),
            self.span,
        ))
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
        compile(source).expect("the test source must compile").disassemble()
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
        let text = dis(r#"rule r { strings: $a = "x" condition: #a > 1 and @a < 100 and !a == 2 }"#);
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
        assert!(first < second && second < test, "bounds precede the test:\n{text}");
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
        let count_at = p.code.iter().position(|op| *op == Op::Push(0)).expect("count pushed");
        let of_at = p.code.iter().position(|op| matches!(op, Op::OfCount(_))).unwrap();
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
        let pushes = p
            .code
            .iter()
            .filter(|op| matches!(op, Op::Push(_)))
            .count();
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
                    assert_ne!(t, u32::MAX, "{source}: instruction {index} kept its placeholder");
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
        assert!(jump < rhs, "the right-hand side must be jumped over:\n{text}");
    }

    // -- refusals, by name -----------------------------------------------

    #[test]
    fn a_module_field_is_refused_under_its_own_tag() {
        assert_eq!(feature("rule r { condition: pe.number_of_sections > 2 }"), "module field");
    }

    #[test]
    fn a_module_call_is_refused_under_its_own_tag() {
        assert_eq!(feature("rule r { condition: pe.imphash() == \"x\" }"), "function call");
    }

    #[test]
    fn a_regex_is_refused_under_its_own_tag() {
        assert_eq!(feature("rule r { condition: \"a\" matches /a+/ }"), "regex");
    }

    #[test]
    fn a_loop_is_refused_under_a_tag_naming_the_loop() {
        assert_eq!(feature("rule r { condition: for any i in (0..10) : ( i == 1 ) }"), "for .. in range");
        assert_eq!(
            feature(r#"rule r { strings: $a = "x" condition: for any of them : ( $ at 0 ) }"#),
            "for .. of"
        );
    }

    #[test]
    fn an_undefined_string_is_its_own_error() {
        // Not a coverage gap — an author error, and the tag says so.
        assert_eq!(feature(r#"rule r { strings: $a = "x" condition: $b }"#), "undefined string");
    }

    #[test]
    fn an_empty_string_set_is_refused_rather_than_never_firing() {
        // `any of ($zz*)` where the rule defines no `$zz...`. Treated as false
        // it would be a rule that silently never matches; refused, it is a typo
        // its author finds immediately.
        assert_eq!(feature(r#"rule r { strings: $a = "x" condition: any of ($zz*) }"#), "empty string set");
    }

    #[test]
    fn the_buffer_readers_all_compile() {
        for name in [
            "uint8", "uint16", "uint32", "int8", "int16", "int32", "uint16be", "uint32be",
            "int16be", "int32be", "uint8be", "int8be",
        ] {
            let source = format!("rule r {{ condition: {name}(0) == 1 }}");
            let p = compile(&source).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(p.code.iter().any(|op| !matches!(op, Op::Push(_) | Op::Eq | Op::Ret)),
                "{name} produced no read:\n{}", p.disassemble());
        }
    }

    #[test]
    fn a_reader_with_the_wrong_number_of_arguments_is_refused() {
        assert_eq!(feature("rule r { condition: uint16(0, 1) == 1 }"), "function call");
        assert_eq!(feature("rule r { condition: uint16() == 1 }"), "function call");
    }

    #[test]
    fn equals_maps_onto_ordinary_equality() {
        // Two spellings of one question must not become two code paths.
        assert!(dis("rule r { condition: \"a\" equals \"a\" }").contains("eq"));
    }

    #[test]
    fn an_unknown_dotted_call_names_the_path_in_its_message() {
        let e = compile("rule r { condition: math.entropy(0, filesize) > 7 }").unwrap_err();
        assert_eq!(e.feature, "function call");
        assert!(e.message.contains("math.entropy"), "{}", e.message);
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
        assert!(p.max_steps >= 6, "{} steps:\n{}", p.max_steps, p.disassemble());
        assert!(p.max_steps <= p.code.len() as u32, "a path cannot exceed the program");
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
        assert!(p.max_stack >= 2 && p.max_stack <= 4, "max_stack {}", p.max_stack);
    }

    #[test]
    fn the_stack_bound_is_reported_for_a_string_set() {
        // `OfAny(n)` pops n and pushes one, so the results are all live at once.
        let p = compile(r#"rule r { strings: $a = "x" $b = "y" $c = "z" condition: any of them }"#).unwrap();
        assert!(p.max_stack >= 3, "max_stack {}", p.max_stack);
    }
}
