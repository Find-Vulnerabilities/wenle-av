//! The native rule engine.
//!
//! # Why not YARA
//!
//! YARA is a fine offline triage tool, but it is the wrong foundation for a
//! real-time antivirus:
//!
//! * **It is a boolean matcher.** The first rule that fires decides the result.
//!   A real engine needs to weigh weak and strong evidence against a threshold,
//!   which is what keeps false positives off a user's machine.
//! * **Rule names carry no meaning.** Detection quality depends on the engine
//!   knowing whether a rule identifies a family (report `Win32.Ransomware.X`)
//!   or merely observes a technique.
//! * **Loading 10,000 rules costs seconds**, because a `.yar` file is compiled
//!   at load time. A real engine ships a pre-compiled, memory-mappable database.
//! * **Every scan re-derives what it needs.** YARA's own prefilter is good, but
//!   it is not integrated with the file-type gating, the trust layer or the
//!   scan cache that a resident scanner depends on.
//!
//! This crate implements the replacement: a compiler that turns AVRL source
//! into a compact bytecode program plus a set of pattern matchers, and a
//! virtual machine that evaluates those programs against a buffer.
//!
//! # Pipeline
//!
//! ```text
//!   .avrule source
//!        │  lexer      (lexer.rs)
//!        ▼
//!     tokens
//!        │  parser     (parser.rs)
//!        ▼
//!       AST          (ast.rs)
//!        │  compiler   (compiler/)
//!        ▼
//!   Program  ──►  atoms  ──►  Aho-Corasick prefilter
//!        │
//!        ▼
//!   RuleDatabase  (.avdb, memory-mapped)
//!        │
//!        ▼
//!    scanner  ──►  bytecode VM  ──►  Vec<RuleMatch>
//! ```
//!
//! The prefilter is what makes scanning fast: every string in every rule
//! contributes its highest-quality literal atoms to a single Aho-Corasick
//! automaton, and one pass over the buffer tells us which handful of rules
//! could possibly match. Only those rules reach the virtual machine.

// Tests opt out of the panic-family lints: unwrapping is how an assertion is
// written, and a panic in a test is the desired outcome, not a defect.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod ast;
pub mod hex;
pub mod lexer;

pub use ast::{
    ArithOp, BitOp, CmpOp, Expr, HexPattern, HexToken, MemberPath, MetaValue, Modifiers,
    PathSegment, Quantifier, Rule, RuleMeta, Span, StringDef, StringOp, StringSet, StringValue,
    XorRange,
};
