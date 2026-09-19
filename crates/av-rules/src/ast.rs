//! Abstract syntax tree for the AVRL rule language.
//!
//! The language is a cleaned-up dialect of YARA. Keeping the surface syntax
//! close to YARA is a deliberate choice: it means the importer that ingests
//! third-party rule sets is close to a pass-through for the constructs we
//! support, and it means anyone who has written a YARA rule can write an AVRL
//! rule without reading documentation.
//!
//! What AVRL adds on top of YARA is everything the scoring model in `av-core`
//! needs: a declared severity, a malware category and family, an explicit score
//! weight, and a `decisive` marker. In YARA those all live in free-form `meta`
//! strings that nothing validates; here they are typed and checked at compile
//! time.

use av_core::{Platform, Severity, ThreatCategory};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// A byte range in the source text, used for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    pub fn join(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// A complete rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    /// `private rule` — matches are recorded internally but never reported.
    pub private: bool,
    /// `global rule` — must match for any other rule in the file to be
    /// considered. Used to gate a rule set on, say, "this is a PE file".
    pub global: bool,
    pub tags: Vec<String>,
    pub meta: RuleMeta,
    pub strings: Vec<StringDef>,
    pub condition: Expr,
    pub span: Span,
}

/// Typed rule metadata.
///
/// `extra` preserves any meta key we do not model so that a round-trip through
/// the importer does not silently discard an author's annotations.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RuleMeta {
    pub description: Option<String>,
    pub author: Option<String>,
    pub reference: Vec<String>,
    pub date: Option<String>,
    pub source: Option<String>,
    pub license: Option<String>,
    /// Hash of a known sample of this family. Harvested into the exact-match
    /// blocklist at compile time.
    pub hashes: Vec<String>,
    pub severity: Option<Severity>,
    pub category: Option<ThreatCategory>,
    pub platform: Option<Platform>,
    pub family: Option<String>,
    pub variant: Option<String>,
    /// Explicit score override. When absent the compiler derives a score from
    /// the severity.
    pub weight: Option<u16>,
    /// Mark the detection as needing no corroboration.
    pub decisive: bool,
    /// External quality rating, as carried by third-party rule sets.
    pub quality: Option<u8>,
    /// Free-form keys we do not model.
    pub extra: BTreeMap<String, MetaValue>,
}

/// A meta value, in the types the language allows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetaValue {
    Text(String),
    Integer(i64),
    Boolean(bool),
}

impl fmt::Display for MetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetaValue::Text(s) => f.write_str(s),
            MetaValue::Integer(i) => write!(f, "{i}"),
            MetaValue::Boolean(b) => write!(f, "{b}"),
        }
    }
}

/// One `$name = ...` string definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StringDef {
    /// Identifier including the leading `$`, e.g. `$a`. Anonymous strings are
    /// given a synthesised identifier by the parser.
    pub id: String,
    pub value: StringValue,
    pub modifiers: Modifiers,
    pub span: Span,
}

/// The three kinds of string a rule can define.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StringValue {
    /// A literal text string, stored as raw bytes because the source may use
    /// escape sequences that do not form valid UTF-8.
    Text(Vec<u8>),
    /// A pattern in the `{ 4D 5A ?? [4-6] (41|42) }` hex syntax.
    Hex(HexPattern),
    /// A regular expression: the text between the slashes, plus the flag
    /// letters that followed them.
    ///
    /// The flags live here rather than being folded into [`Modifiers`] because
    /// `/re/i` and `"re" nocase` are different syntaxes for the same idea, and
    /// collapsing them would lose the distinction between "the author wrote a
    /// flag" and "the author wrote a modifier" if either ever grows a meaning
    /// the other lacks.
    Regex {
        body: String,
        /// Flag letters as written, e.g. `i` in `/re/i`.
        flags: String,
    },
}

/// A parsed hex pattern.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HexPattern {
    pub tokens: Vec<HexToken>,
}

impl HexPattern {
    /// The shortest and longest byte length this pattern can match. Used to
    /// decide whether a string can possibly fit in the remaining buffer, and to
    /// weight atoms.
    pub fn length_bounds(&self) -> (usize, usize) {
        let mut min = 0usize;
        let mut max = 0usize;
        for token in &self.tokens {
            let (lo, hi) = token.length_bounds();
            min = min.saturating_add(lo);
            max = max.saturating_add(hi);
        }
        (min, max)
    }

    /// True when the pattern has no wildcards, jumps or alternatives, meaning
    /// it matches exactly one byte sequence. Such patterns can be turned into a
    /// plain literal and fed to the Aho-Corasick prefilter whole.
    ///
    /// A single-branch alternative such as `( 4D 5A )` is exact too; the
    /// parser leaves that wrapper in place, and treating it as inexact would
    /// needlessly push a precisely known pattern through the general matcher.
    pub fn as_exact_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        if collect_fixed(&self.tokens, &mut out) {
            Some(out)
        } else {
            None
        }
    }

    /// Number of leading bytes that are fully determined — the longest exact
    /// prefix. A long fixed prefix makes an excellent prefilter atom.
    pub fn exact_prefix(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Whether the tail was fixed is irrelevant here: whatever was collected
        // before the walk stopped is the prefix.
        let _ = collect_fixed(&self.tokens, &mut out);
        out
    }
}

/// Append every byte whose value is known, stopping at the first token that is
/// not fully determined. Returns whether the entire run was fixed.
///
/// `as_exact_bytes` wants that boolean; `exact_prefix` discards it and keeps
/// whatever was collected. Sharing one walk is what makes a parenthesised
/// pattern such as `( 4D 5A )` behave exactly like `4D 5A`.
fn collect_fixed(tokens: &[HexToken], out: &mut Vec<u8>) -> bool {
    for token in tokens {
        match token {
            HexToken::Byte(b) => out.push(*b),
            HexToken::Nibble {
                high: Some(h),
                low: Some(l),
            } => out.push((h << 4) | l),
            // `( ... )` with one branch constrains nothing extra.
            HexToken::Alternative(branches) if branches.len() == 1 => {
                // Propagating the failure matters: if the branch ran into a
                // wildcard, the prefix ends inside it and the caller must not
                // keep appending the bytes that follow the parentheses.
                if !collect_fixed(&branches[0], out) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// One element inside a hex pattern.
///
/// Not `Copy`: the alternative and negation variants own their sub-patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HexToken {
    /// A fully specified byte: `4D`.
    Byte(u8),
    /// A byte with wildcard nibbles: `4?`, `?D`, `??`.
    ///
    /// `??` is kept as `Nibble { high: None, low: None }` rather than a
    /// separate variant so the matcher has one case to handle.
    Nibble {
        high: Option<u8>,
        low: Option<u8>,
    },
    /// A gap: `[4]` exactly four bytes, `[2-6]` between two and six,
    /// `[4-]` four or more.
    Jump { min: u32, max: Option<u32> },
    /// A choice between alternatives: `( 41 | 42 43 )`.
    Alternative(Vec<Vec<HexToken>>),
    /// Negated alternatives introduced by `~`: match any byte that is not one
    /// of these sequences. Compiled to a bounded scan.
    Not(Vec<Vec<HexToken>>),
}

impl HexToken {
    fn length_bounds(&self) -> (usize, usize) {
        match self {
            HexToken::Byte(_) | HexToken::Nibble { .. } => (1, 1),
            // Widen before defaulting: `usize::MAX as u32` truncates to
            // 0xFFFF_FFFF on a 64-bit target, which would silently cap an
            // unbounded jump at 4 GiB.
            HexToken::Jump { min, max } => (*min as usize, max.map_or(usize::MAX, |m| m as usize)),
            HexToken::Alternative(alts) => {
                let mut lo = usize::MAX;
                let mut hi = 0usize;
                for alt in alts {
                    let mut a_lo = 0usize;
                    let mut a_hi = 0usize;
                    for t in alt {
                        let (l, h) = t.length_bounds();
                        a_lo = a_lo.saturating_add(l);
                        a_hi = a_hi.saturating_add(h);
                    }
                    lo = lo.min(a_lo);
                    hi = hi.max(a_hi);
                }
                if lo == usize::MAX { (0, 0) } else { (lo, hi) }
            }
            HexToken::Not(alts) => {
                let mut hi = 0usize;
                for alt in alts {
                    let mut a_hi = 0usize;
                    for t in alt {
                        let (_, h) = t.length_bounds();
                        a_hi = a_hi.saturating_add(h);
                    }
                    hi = hi.max(a_hi);
                }
                (1, hi.max(1))
            }
        }
    }

    /// Whether this token forces at least one specific byte value, which is
    /// what makes it usable in a prefilter atom.
    pub fn is_fixed(&self) -> bool {
        matches!(
            self,
            HexToken::Byte(_)
                | HexToken::Nibble {
                    high: Some(_),
                    low: Some(_)
                }
        )
    }
}

/// Modifiers applied to a string definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Modifiers {
    /// Match the bytes as stored. Defaults to true when neither `ascii` nor
    /// `wide` is given, matching YARA's behaviour.
    pub ascii: bool,
    /// Also match the UTF-16LE expansion.
    pub wide: bool,
    pub nocase: bool,
    /// Require the match to be delimited by non-alphanumeric bytes.
    pub fullword: bool,
    /// Also match the string XORed with each key in the range.
    pub xor: Option<XorRange>,
    /// Also match the base64 encoding of the string.
    pub base64: Option<Base64Alphabet>,
    /// `private` strings record matches but never appear in a report.
    pub private: bool,
}

/// Inclusive range of single-byte XOR keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XorRange {
    pub min: u8,
    pub max: u8,
}

impl XorRange {
    pub const FULL: XorRange = XorRange { min: 1, max: 255 };

    /// Number of distinct keys in the range, inclusive of both ends.
    pub fn len(self) -> usize {
        (self.max as usize).saturating_sub(self.min as usize).saturating_add(1)
    }

    /// Always false: a range is empty only if `max < min`, and the parser
    /// rejects that. Present so `len()` has its conventional companion.
    pub fn is_empty(self) -> bool {
        self.max < self.min
    }
}

/// Which base64 alphabet a `base64` modifier should generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Base64Alphabet {
    /// Include the standard alphabet's first encoding.
    pub standard: bool,
    /// Include the URL-safe variant (`-` and `_` instead of `+` and `/`).
    pub url_safe: bool,
    /// Also generate the encoding of the wide (UTF-16LE) form.
    pub wide: bool,
}

impl Default for Base64Alphabet {
    fn default() -> Self {
        Self {
            standard: true,
            url_safe: true,
            wide: false,
        }
    }
}

impl Modifiers {
    /// Whether the string is matched against raw bytes at all. A string that is
    /// `wide` only still matches bytes; this is always true, but the helper
    /// keeps call sites readable.
    pub fn matches_bytes(&self) -> bool {
        true
    }
}

/// Expressions allowed in a `condition:` block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    Bool(bool),
    Int(i64),
    Float(f64),
    /// A quoted string literal, as used with `contains` and friends.
    Str(String),
    /// A `/regex/` literal. Only meaningful as the right-hand side of
    /// `matches`; the compiler rejects it anywhere else.
    Regex {
        body: String,
        flags: String,
    },
    /// The `filesize` keyword.
    Filesize,
    /// The `entrypoint` keyword.
    EntryPoint,

    /// `$a` — the string matched somewhere.
    StringMatch(String),
    /// `$a at 0x1000` — matched at a specific offset.
    StringAt(String, Box<Expr>),
    /// `$a in (0..100)` — matched inside a range.
    StringIn(String, Box<Expr>, Box<Expr>),
    /// `#a` — number of matches.
    StringCount(String),
    /// `@a` or `@a[2]` — offset of the n-th match.
    StringOffset(String, Option<Box<Expr>>),
    /// `!a` or `!a[2]` — length of the n-th match.
    StringLength(String, Option<Box<Expr>>),

    /// `any of them`, `all of ($a*)`, `2 of ($a, $b)`.
    Of {
        quantifier: Quantifier,
        set: StringSet,
    },
    /// `any of ($t*) in (0..504)` — the set must match inside the range.
    ///
    /// Distinct from [`Expr::Of`] because the range constrains where each
    /// string matches, so the operand cannot be evaluated as a plain set.
    OfIn {
        quantifier: Quantifier,
        set: StringSet,
        from: Box<Expr>,
        to: Box<Expr>,
    },
    /// `for any of ($a*) : ( $ )` — the body sees `$` bound to each match.
    ForOf {
        quantifier: Quantifier,
        set: StringSet,
        body: Box<Expr>,
    },
    /// `for any i in (0..pe.number_of_sections) : ( ... )` — an integer range.
    ///
    /// Carries the quantifier because it is not decorative: `for all i in
    /// (0..n)` and `for any i in (0..n)` differ exactly the way `all` and `any`
    /// differ elsewhere, and dropping it silently turns one into the other.
    ForIn {
        quantifier: Quantifier,
        var: String,
        from: Box<Expr>,
        to: Box<Expr>,
        body: Box<Expr>,
    },
    /// `for any s in pe.sections : ( ... )` — iterating a module array.
    ///
    /// Separate from [`Expr::ForIn`] because the operands are different kinds
    /// of thing: one counts between two integers, the other walks a sequence
    /// whose length is only known once the module has been evaluated.
    ForEach {
        quantifier: Quantifier,
        var: String,
        iterable: Box<Expr>,
        body: Box<Expr>,
    },
    /// The `$` placeholder inside a `for ... of` body.
    ForOfPlaceholder,
    /// A reference to a `for` loop's index variable.
    Variable(String),

    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    /// Short-circuiting `and`/`or` are the same node with a flag in YARA; kept
    /// separate here because the compiler emits different jumps.
    Defined(Box<Expr>),

    Arithmetic {
        op: ArithOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Bitwise {
        op: BitOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Compare {
        op: CmpOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Negate(Box<Expr>),
    BitNot(Box<Expr>),

    /// `expr contains expr`, `expr matches expr`, `expr startswith expr`, and
    /// the case-insensitive `i`-prefixed variants.
    StringOp {
        op: StringOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },

    /// A builtin call: `uint16(0)`, `math.entropy(0, filesize)`, `pe.imphash()`.
    Call {
        path: MemberPath,
        args: Vec<Expr>,
    },
    /// A module field: `pe.number_of_sections`, `pe.rich_signature.clear_data`.
    Field { path: MemberPath },
    /// Indexing into a module array or a call result: `pe.sections[i].name`.
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
    },
}

/// A dotted accessor chain rooted at a module name or a loop variable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberPath {
    /// First identifier: `pe`, `math`, `hash`, `file`, `dotnet`, or a variable.
    pub root: String,
    pub segments: Vec<PathSegment>,
}

/// One step in a [`MemberPath`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PathSegment {
    Field(String),
    Index(Box<Expr>),
}

impl MemberPath {
    pub fn new(root: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            segments: Vec::new(),
        }
    }

    /// Render back to source form, for diagnostics.
    pub fn render(&self) -> String {
        let mut out = self.root.clone();
        for seg in &self.segments {
            match seg {
                PathSegment::Field(f) => {
                    out.push('.');
                    out.push_str(f);
                }
                PathSegment::Index(_) => out.push_str("[..]"),
            }
        }
        out
    }
}

/// How many strings in a set must match.
///
/// Not `Copy` or `Eq`: [`Quantifier::Count`] carries an expression, and
/// expressions contain floats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Quantifier {
    Any,
    All,
    None,
    /// `N of them`. An expression rather than an integer because the count is
    /// often a module field — `pe.number_of_sections of them` is a real and
    /// common construct.
    Count(Box<Expr>),
    /// `50% of them`. Bounded to `0..=100` by the parser.
    Percentage(u8),
}

/// The set of strings a quantifier ranges over.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StringSet {
    /// `them` — every string in the rule.
    All,
    /// An explicit list, `($a, $b)`, or a prefix wildcard, `($a*)`.
    List {
        /// Exact identifiers named.
        names: Vec<String>,
        /// Prefix identifiers, stored with the trailing `*` stripped.
        prefixes: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitOp {
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringOp {
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    Matches,
    Equals,
    IEquals,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> HexPattern {
        HexPattern {
            tokens: bytes.iter().map(|b| HexToken::Byte(*b)).collect(),
        }
    }

    #[test]
    fn exact_hex_pattern_becomes_a_literal() {
        assert_eq!(hex(&[0x4D, 0x5A, 0x90]).as_exact_bytes(), Some(vec![0x4D, 0x5A, 0x90]));
    }

    #[test]
    fn wildcard_prevents_literal_conversion() {
        let p = HexPattern {
            tokens: vec![
                HexToken::Byte(0x4D),
                HexToken::Byte(0x5A),
                HexToken::Nibble { high: None, low: None },
            ],
        };
        assert_eq!(p.as_exact_bytes(), None);
    }

    #[test]
    fn fully_specified_nibbles_count_as_exact() {
        let p = HexPattern {
            tokens: vec![
                HexToken::Byte(0x4D),
                HexToken::Nibble {
                    high: Some(0x5),
                    low: Some(0xA),
                },
            ],
        };
        assert_eq!(p.as_exact_bytes(), Some(vec![0x4D, 0x5A]));
    }

    #[test]
    fn exact_prefix_stops_at_the_first_wildcard() {
        let p = HexPattern {
            tokens: vec![
                HexToken::Byte(0x4D),
                HexToken::Byte(0x5A),
                HexToken::Nibble { high: None, low: None },
                HexToken::Byte(0x90),
            ],
        };
        assert_eq!(p.exact_prefix(), vec![0x4D, 0x5A]);
    }

    #[test]
    fn exact_prefix_stops_inside_a_parenthesised_branch() {
        // Regression: the walk must not resume after the closing parenthesis.
        // `4D ( 5A ?? ) 90` has prefix `4D 5A`, not `4D 5A 90`.
        let p = HexPattern {
            tokens: vec![
                HexToken::Byte(0x4D),
                HexToken::Alternative(vec![vec![
                    HexToken::Byte(0x5A),
                    HexToken::Nibble { high: None, low: None },
                ]]),
                HexToken::Byte(0x90),
            ],
        };
        assert_eq!(p.exact_prefix(), vec![0x4D, 0x5A]);
        assert_eq!(p.as_exact_bytes(), None);
    }

    #[test]
    fn a_single_branch_alternative_is_transparent_to_exactness() {
        let p = HexPattern {
            tokens: vec![HexToken::Alternative(vec![vec![
                HexToken::Byte(0x4D),
                HexToken::Byte(0x5A),
            ]])],
        };
        assert_eq!(p.as_exact_bytes(), Some(vec![0x4D, 0x5A]));
        assert_eq!(p.exact_prefix(), vec![0x4D, 0x5A]);
    }

    #[test]
    fn length_bounds_of_a_jump_are_inclusive() {
        let p = HexPattern {
            tokens: vec![
                HexToken::Byte(0x41),
                HexToken::Jump { min: 2, max: Some(6) },
                HexToken::Byte(0x42),
            ],
        };
        assert_eq!(p.length_bounds(), (4, 8));
    }

    #[test]
    fn unbounded_jump_reports_unbounded_maximum() {
        let p = HexPattern {
            tokens: vec![HexToken::Jump { min: 4, max: None }],
        };
        assert_eq!(p.length_bounds().1, usize::MAX);
    }

    #[test]
    fn alternatives_report_the_widest_branch() {
        let p = HexPattern {
            tokens: vec![HexToken::Alternative(vec![
                vec![HexToken::Byte(1)],
                vec![HexToken::Byte(2), HexToken::Byte(3), HexToken::Byte(4)],
            ])],
        };
        assert_eq!(p.length_bounds(), (1, 3));
    }

    #[test]
    fn default_modifiers_match_ascii_only() {
        let m = Modifiers::default();
        assert!(!m.ascii, "parser sets this explicitly");
        assert!(!m.wide);
        assert!(m.matches_bytes());
    }


    #[test]
    fn member_path_renders_dimensions() {
        let mut p = MemberPath::new("pe");
        p.segments.push(PathSegment::Field("sections".into()));
        p.segments.push(PathSegment::Index(Box::new(Expr::Int(0))));
        p.segments.push(PathSegment::Field("name".into()));
        assert_eq!(p.render(), "pe.sections[..].name");
    }

    #[test]
    fn span_join_covers_both() {
        let a = Span::new(2, 5);
        let b = Span::new(9, 12);
        assert_eq!(a.join(b), Span { start: 2, end: 12 });
    }
}
