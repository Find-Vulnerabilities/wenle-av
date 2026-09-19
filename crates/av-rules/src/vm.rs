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

use crate::ast::CmpOp;
use crate::matches::MatchSet;
use crate::program::{Cmp, Op, Program, Value};

/// The buffer a condition is evaluated against.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    pub data: &'a [u8],
    /// Entry point offset, when the file-type layer identified one.
    ///
    /// `None` for anything that is not an executable image, which makes
    /// `entrypoint` undefined rather than zero.
    pub entry_point: Option<u64>,
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            entry_point: None,
        }
    }

    pub fn with_entry_point(data: &'a [u8], entry_point: Option<u64>) -> Self {
        Self { data, entry_point }
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
    /// Execution did not finish within the program's own step bound.
    ///
    /// Unreachable for a well-formed program, which is acyclic and therefore
    /// runs each instruction at most once. It is a backstop for a corrupt jump
    /// table that points backwards.
    StepLimit { limit: u32 },
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmError::BadJump { at, target } => {
                write!(f, "instruction {at} jumps to {target}, past the end of the program")
            }
            VmError::BadConstant { at, index } => {
                write!(f, "instruction {at} reads constant {index}, which does not exist")
            }
            VmError::StackUnderflow { at, op } => {
                write!(f, "instruction {at} ({op:?}) has no operand to pop")
            }
            VmError::StepLimit { limit } => {
                write!(f, "execution exceeded its {limit}-instruction bound")
            }
        }
    }
}

impl std::error::Error for VmError {}

/// The interpreter's operand stack and registers.
///
/// Reusable: [`Vm::run`] resets the stack height and leaves it at zero, so one
/// `Vm` can run every rule of a scan in sequence.
#[derive(Debug, Default, Clone)]
pub struct Vm {
    stack: Vec<Value>,
    /// Deepest the stack has ever been, across every run.
    ///
    /// Kept for tuning `Program::max_stack` against reality rather than against
    /// the compiler's own arithmetic, which over-estimates at branches by
    /// design.
    pub peak_stack: usize,
}

impl Vm {
    pub fn new() -> Self {
        Self::default()
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
        // A program is acyclic by construction, so no instruction executes
        // twice and the program's own length is a hard bound on the work. The
        // compiler's `max_steps` is the tighter figure for a real path; this
        // one holds even if that figure is wrong.
        let limit = program.max_steps.max(code.len() as u32).saturating_add(1);
        let mut steps = 0u32;
        let mut pc = 0usize;

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
        (Value::Str(x), Value::Str(y)) => x.as_bytes().cmp(y.as_bytes()),
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
    let (Value::Str(haystack), Value::Str(needle)) = (a, b) else {
        return false;
    };
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
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
    let Some(tail) = haystack.len().checked_sub(needle.len()).and_then(|at| haystack.get(at..))
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
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
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
            assert!(!run(source, b"MZ"), "{source} must be false with no entry point");
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
        assert!(run("rule r { condition: uint16(0) == 0x5A4D }", b"MZ\x90\x00"));
        assert!(run("rule r { condition: uint32(0) == 0x00905A4D }", b"MZ\x90\x00"));
        assert!(run("rule r { condition: uint8(0) == 0x4D }", b"MZ"));
    }

    #[test]
    fn big_endian_readers_swap_the_byte_order() {
        assert!(run("rule r { condition: uint16be(0) == 0x4D5A }", b"MZ"));
        assert!(run("rule r { condition: uint32be(0) == 0x4D5A9000 }", b"MZ\x90\x00"));
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
        assert!(run_with(s, b"", &[(0, 500, 12)]), "ends exactly at the bound");
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
        assert!(run_with(s, b"", &[(0, 0, 1), (1, 1, 1)]), "two of four is 50%");
        assert!(!run_with(s, b"", &[(0, 0, 1)]));
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
            assert_eq!(run(&format!("rule r {{ condition: {expr} }}"), b"MZ"), expected, "{expr}");
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
                let kind = if jump_if_false { "JumpIfFalse" } else { "JumpIfTrue" };

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
        let file = parse_file(
            r#"rule r { strings: $a = "x" condition: $a and #a == 1 }"#,
        )
        .unwrap();
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
}
