//! Recursive-descent parser: tokens to AST.
//!
//! # Why the parser owns the keywords
//!
//! The lexer hands back every keyword as a plain identifier. That is not
//! laziness — it is what makes `$all`, `$any` and `for` usable as string names.
//! `all of them` and `$all` differ only in the sigil, so the decision belongs
//! where the sigil is visible, which is here.
//!
//! # Operator precedence
//!
//! Lowest binds loosest, matching YARA so that rules port over unchanged:
//!
//! | Level | Operators |
//! |-------|-----------|
//! | 1 | `or` |
//! | 2 | `and` |
//! | 3 | `<` `<=` `>` `>=` `==` `!=` `contains` `icontains` `startswith` `istartswith` `endswith` `iendswith` `iequals` `matches` |
//! | 4 | `\|` |
//! | 5 | `^` |
//! | 6 | `&` |
//! | 7 | `<<` `>>` |
//! | 8 | `+` `-` |
//! | 9 | `*` `/` `%` |
//!
//! `not`, unary `-` and `~` bind tighter still, and `defined` is a postfix
//! operator that binds tightest of all.
//!
//! # What this parser deliberately does not do
//!
//! It does not resolve names. A bare identifier becomes
//! [`Expr::Variable`], and `pe.number_of_sections` becomes [`Expr::Field`],
//! without asking whether `pe` was imported. Scope is the compiler's business,
//! and keeping the two apart is what lets the same AST be re-checked after a
//! module is added.

use std::fmt;

use av_core::{Platform, Severity, ThreatCategory};

use crate::ast::{
    ArithOp, BitOp, CmpOp, Expr, MemberPath, MetaValue, Modifiers, PathSegment, Quantifier, Rule,
    RuleMeta, Span, StringDef, StringOp, StringSet, StringValue, XorRange, Base64Alphabet,
};
use crate::hex;
use crate::lexer::{LexError, Lexer, Token, TokenKind};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A syntax error, positioned in the source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    /// 1-based line.
    pub line: u32,
    /// 1-based column.
    pub column: u32,
    /// Byte offset from the start of the source.
    pub offset: u32,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for ParseError {}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        Self {
            message: e.message,
            line: e.line,
            column: e.column,
            offset: e.offset,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Everything a rule file declares.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedFile {
    /// Module names pulled in with `import`, in source order.
    pub imports: Vec<String>,
    /// Files pulled in with `include`, in source order.
    pub includes: Vec<String>,
    pub rules: Vec<Rule>,
}

/// Parse a rule file into its rules, imports and includes.
pub fn parse_file(src: &str) -> Result<ParsedFile, ParseError> {
    let tokens = Lexer::new(src).tokenize()?;
    Parser::new(tokens).parse_file()
}

/// Parse a single condition expression, for tests and for the CLI's
/// `--explain` mode.
pub fn parse_condition(src: &str) -> Result<Expr, ParseError> {
    let tokens = Lexer::new(src).tokenize()?;
    let mut p = Parser::new(tokens);
    let expr = p.parse_expr()?;
    p.expect_eof()?;
    Ok(expr)
}

// Precedence levels, loosest first.
const PREC_OR: u8 = 1;
const PREC_AND: u8 = 2;
const PREC_CMP: u8 = 3;
const PREC_BITOR: u8 = 4;
const PREC_BITXOR: u8 = 5;
const PREC_BITAND: u8 = 6;
const PREC_SHIFT: u8 = 7;
const PREC_ADD: u8 = 8;
const PREC_MUL: u8 = 9;

/// Stand-in returned by [`Parser::peek`] if the token list is ever exhausted.
/// `Lexer::tokenize` always appends `Eof`, so this exists only so that a
/// future change to the lexer cannot turn into a panic here.
const EOF_TOKEN: Token = Token {
    kind: TokenKind::Eof,
    start: 0,
    end: 0,
    line: 1,
    column: 1,
};

/// A binary operator, with the affinity it was parsed at.
#[derive(Debug, Clone, Copy)]
enum BinOp {
    Or,
    And,
    Cmp(CmpOp),
    Str(StringOp),
    Arith(ArithOp),
    Bit(BitOp),
}

/// Deepest expression nesting the parser will build.
///
/// Both the parser and everything downstream — the compiler, the VM, and even
/// `Drop` on the tree — walk the AST recursively, so the depth of that tree is
/// what decides whether the engine survives its input. Left alone, a file
/// consisting of a hundred thousand `(` characters is not a syntax error, it is
/// a stack overflow in the shipping binary. Rule files are read from disk and
/// the rule set is a plugin surface, so this is a denial of service, not a
/// hypothetical.
///
/// The bound has to be low enough to be safe on a stack the engine does not
/// control. Descending one nesting level costs several frames — `parse_binary`,
/// `parse_operand`, `parse_unary`, `parse_postfix`, `parse_primary` and back
/// into `parse_binary` — and an unoptimised build makes each of those frames
/// large, so a bound that merely feels generous is not a bound at all. At 128 a
/// pathological input needs well under a megabyte, which fits the smallest
/// stack this is likely to run on.
///
/// Real rules are nowhere near it: the deepest construct in a 10,764-rule
/// third-party set nests a handful of levels, and 128 still leaves room for
/// tens of levels of nesting. Note that a long `or` chain produces a deep
/// *tree* while parsing iteratively, so [`MAX_NODES`] covers that shape.
const MAX_DEPTH: u32 = 128;

/// Largest expression a single condition may build.
///
/// [`MAX_DEPTH`] bounds how deep the parser recurses, but not how deep the tree
/// it returns is: `a or b or c or ...` is parsed by a loop, so a million-term
/// chain costs the parser constant stack and produces a million-deep tree.
///
/// The saving grace is that a tree's depth can never exceed its node count, so
/// bounding the nodes bounds the depth as well — and depth is what has to be
/// bounded, because dropping the tree recurses just as hard as building it did.
/// Refusing a condition at 4,096 nodes keeps every later traversal, `Drop`
/// included, inside about a megabyte even in an unoptimised build.
///
/// The largest conditions in a 10,764-rule third-party set are a few hundred
/// nodes — long `or` chains of resource names — so this leaves an order of
/// magnitude of headroom.
const MAX_NODES: usize = 4_096;

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// Current expression nesting depth, checked against [`MAX_DEPTH`].
    depth: u32,
    /// Expression nodes built so far in the condition being parsed, checked
    /// against [`MAX_NODES`].
    nodes: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            depth: 0,
            nodes: 0,
        }
    }

    /// Account for one more node, refusing the condition once it is implausibly
    /// large. Called from the two places that create nodes, so the count tracks
    /// the tree rather than the token stream.
    fn note_node(&mut self) -> Result<(), ParseError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NODES {
            return Err(self.error_here("condition is too large"));
        }
        Ok(())
    }

    // -- token access -------------------------------------------------------

    fn peek(&self) -> &Token {
        // Never panics and never runs off the end: a parser bug on hostile
        // input should produce a confusing error, not a crash.
        self.tokens
            .get(self.pos)
            .or_else(|| self.tokens.last())
            .unwrap_or(&EOF_TOKEN)
    }

    fn peek_at(&self, n: usize) -> &Token {
        let at = self.pos.saturating_add(n);
        self.tokens
            .get(at)
            .or_else(|| self.tokens.last())
            .unwrap_or(&EOF_TOKEN)
    }

    fn advance(&mut self) -> Token {
        let tok = self.peek().clone();
        if self.pos < self.tokens.len().saturating_sub(1) {
            self.pos += 1;
        }
        tok
    }

    fn check(&self, pred: impl FnOnce(&TokenKind) -> bool) -> bool {
        pred(&self.peek().kind)
    }

    fn eat(&mut self, pred: impl FnOnce(&TokenKind) -> bool) -> Option<Token> {
        if self.check(pred) {
            Some(self.advance())
        } else {
            None
        }
    }

    fn check_word(&self, word: &str) -> bool {
        self.peek().is_word(word)
    }

    fn eat_word(&mut self, word: &str) -> Option<Token> {
        if self.check_word(word) {
            Some(self.advance())
        } else {
            None
        }
    }

    fn eat_kind(&mut self, kind: fn(&TokenKind) -> bool) -> bool {
        self.eat(kind).is_some()
    }

    // -- errors -------------------------------------------------------------

    fn error_at(&self, tok: &Token, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            line: tok.line,
            column: tok.column,
            offset: tok.start,
        }
    }

    fn error_here(&self, message: impl Into<String>) -> ParseError {
        let tok = self.peek();
        self.error_at(tok, format!("{}, found {}", message.into(), tok.kind))
    }

    // -- expectations -------------------------------------------------------

    fn expect_word(&mut self, word: &str) -> Result<Token, ParseError> {
        if self.check_word(word) {
            Ok(self.advance())
        } else {
            Err(self.error_here(format!("expected `{word}`")))
        }
    }

    fn expect_identifier(&mut self, what: &str) -> Result<String, ParseError> {
        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::Identifier(name) => {
                self.advance();
                Ok(name.clone())
            }
            _ => Err(self.error_at(&tok, format!("expected {what}"))),
        }
    }

    fn expect_eof(&mut self) -> Result<(), ParseError> {
        if self.check(|k| matches!(k, TokenKind::Eof)) {
            Ok(())
        } else {
            Err(self.error_here("expected end of input"))
        }
    }

    fn expect_token(
        &mut self,
        kind: fn(&TokenKind) -> bool,
        what: &str,
    ) -> Result<Token, ParseError> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            Err(self.error_here(format!("expected {what}")))
        }
    }

    // -- file ---------------------------------------------------------------

    fn parse_file(&mut self) -> Result<ParsedFile, ParseError> {
        let mut out = ParsedFile::default();
        loop {
            if self.check(|k| matches!(k, TokenKind::Eof)) {
                break;
            }
            let tok = self.peek().clone();
            if tok.is_word("import") {
                self.advance();
                out.imports.push(self.expect_text_literal("a module name")?);
            } else if tok.is_word("include") {
                self.advance();
                out.includes.push(self.expect_text_literal("a file path")?);
            } else if tok.is_word("rule") || tok.is_word("private") || tok.is_word("global") {
                out.rules.push(self.parse_rule()?);
            } else {
                return Err(
                    self.error_at(&tok, "expected `import`, `include` or a rule definition")
                );
            }
        }
        Ok(out)
    }

    fn expect_text_literal(&mut self, what: &str) -> Result<String, ParseError> {
        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::Literal(bytes) => {
                let text = String::from_utf8_lossy(bytes).into_owned();
                self.advance();
                Ok(text)
            }
            _ => Err(self.error_at(&tok, format!("expected a quoted {what}"))),
        }
    }

    // -- rules --------------------------------------------------------------

    fn parse_rule(&mut self) -> Result<Rule, ParseError> {
        let start = self.peek().start;

        let mut private = false;
        let mut global = false;
        loop {
            if self.eat_word("private").is_some() {
                private = true;
            } else if self.eat_word("global").is_some() {
                global = true;
            } else {
                break;
            }
        }

        self.expect_word("rule")?;
        let name = self.expect_identifier("a rule name")?;

        let mut tags = Vec::new();
        if self.eat_kind(|k| matches!(k, TokenKind::Colon)) {
            while let TokenKind::Identifier(tag) = &self.peek().kind {
                tags.push(tag.clone());
                self.advance();
            }
            if tags.is_empty() {
                return Err(self.error_here("expected at least one tag after `:`"));
            }
        }

        self.expect_token(|k| matches!(k, TokenKind::LBrace), "`{` to open the rule body")?;

        let mut meta = RuleMeta::default();
        if self.check_word("meta") {
            self.advance();
            self.expect_token(|k| matches!(k, TokenKind::Colon), "`:` after `meta`")?;
            self.parse_meta(&mut meta)?;
        }

        let mut strings = Vec::new();
        if self.check_word("strings") {
            self.advance();
            self.expect_token(|k| matches!(k, TokenKind::Colon), "`:` after `strings`")?;
            self.parse_strings(&mut strings)?;
        }

        self.expect_word("condition")?;
        self.expect_token(|k| matches!(k, TokenKind::Colon), "`:` after `condition`")?;
        let condition = self.parse_expr()?;

        let end = self.peek().end;
        self.expect_token(|k| matches!(k, TokenKind::RBrace), "`}` to close the rule")?;

        Ok(Rule {
            name,
            private,
            global,
            tags,
            meta,
            strings,
            condition,
            span: Span::new(start as usize, end as usize),
        })
    }

    /// True at the point where a section ends and the next one begins, or at
    /// the end of the rule body.
    ///
    /// The `:` lookahead is what makes this exact: a meta key may legitimately
    /// be called `strings` or `condition`, and only the section header is
    /// followed by a colon.
    fn at_section_end(&self) -> bool {
        if self.check(|k| matches!(k, TokenKind::RBrace | TokenKind::Eof)) {
            return true;
        }
        (self.check_word("strings") || self.check_word("condition"))
            && matches!(self.peek_at(1).kind, TokenKind::Colon)
    }

    fn parse_meta(&mut self, meta: &mut RuleMeta) -> Result<(), ParseError> {
        while !self.at_section_end() {
            let key = self.expect_identifier("a meta key")?;
            self.expect_token(
                |k| matches!(k, TokenKind::Assign),
                "`=` after the meta key",
            )?;

            // `quality = -107`. Machine-scored rule sets use a signed meta
            // value as a score adjustment, so a leading `-` is a value and not
            // an error. It is only consumed when a number actually follows, so
            // a stray `-` still produces the error the author needs to see.
            let negative = self.check(|k| matches!(k, TokenKind::Minus))
                && matches!(
                    self.peek_at(1).kind,
                    TokenKind::Integer(_) | TokenKind::Float(_)
                );
            if negative {
                self.advance();
            }

            let val_tok = self.peek().clone();
            let value = match &val_tok.kind {
                TokenKind::Literal(bytes) => {
                    let text = String::from_utf8_lossy(bytes).into_owned();
                    self.advance();
                    MetaValue::Text(text)
                }
                TokenKind::Integer(i) => {
                    let i = if negative { i.saturating_neg() } else { *i };
                    self.advance();
                    MetaValue::Integer(i)
                }
                TokenKind::Float(x) => {
                    // `RuleMeta` has no float slot, and a float meta value is
                    // almost always a mistaken version string anyway.
                    let x = if negative { -x } else { *x };
                    let text = x.to_string();
                    self.advance();
                    MetaValue::Text(text)
                }
                TokenKind::Boolean(b) => {
                    let b = *b;
                    self.advance();
                    MetaValue::Boolean(b)
                }
                // Bare words are extremely common in third-party rule sets
                // (`severity = high`), so accept them as text.
                TokenKind::Identifier(word) => {
                    let word = word.clone();
                    self.advance();
                    MetaValue::Text(word)
                }
                _ => {
                    return Err(self.error_at(&val_tok, "expected a meta value after `=`"));
                }
            };

            apply_meta(meta, &key, value);
        }
        Ok(())
    }

    fn parse_strings(&mut self, out: &mut Vec<StringDef>) -> Result<(), ParseError> {
        let mut anonymous = 0usize;
        while self.check(|k| matches!(k, TokenKind::StringRef(_))) {
            let id_tok = self.peek().clone();
            let TokenKind::StringRef(raw_name) = id_tok.kind.clone() else {
                // Guarded by the `while let` above.
                break;
            };
            self.advance();

            let id = if raw_name.is_empty() {
                anonymous = anonymous.saturating_add(1);
                format!("$anon{anonymous}")
            } else {
                format!("${raw_name}")
            };
            if out.iter().any(|s| s.id == id) {
                return Err(self.error_at(&id_tok, format!("`{id}` is defined twice")));
            }

            self.expect_token(
                |k| matches!(k, TokenKind::Assign),
                "`=` after the string identifier",
            )?;

            let val_tok = self.peek().clone();
            let value = match &val_tok.kind {
                TokenKind::Literal(bytes) => {
                    let bytes = bytes.clone();
                    self.advance();
                    StringValue::Text(bytes)
                }
                TokenKind::Regex { body, flags } => {
                    let body = body.clone();
                    let flags = flags.clone();
                    self.advance();
                    StringValue::Regex { body, flags }
                }
                TokenKind::HexBlock(body) => {
                    let body = body.clone();
                    self.advance();
                    let pattern = hex::parse(&body).map_err(|e| {
                        // Hex offsets are relative to the body, which begins
                        // one byte after the opening brace. Skipping that
                        // `+ 1` puts the caret one character to the left of
                        // the problem.
                        let delta = u32::try_from(e.offset).unwrap_or(0).saturating_add(1);
                        ParseError {
                            message: format!("invalid hex pattern: {}", e.message),
                            line: val_tok.line,
                            column: val_tok.column.saturating_add(delta),
                            offset: val_tok.start.saturating_add(delta),
                        }
                    })?;
                    StringValue::Hex(pattern)
                }
                _ => {
                    return Err(self.error_at(
                        &val_tok,
                        "expected a string, hex pattern or regex after `=`",
                    ));
                }
            };

            let modifiers = self.parse_string_modifiers()?;
            out.push(StringDef {
                id,
                value,
                modifiers,
                span: id_tok.span(),
            });
        }
        Ok(())
    }

    fn parse_string_modifiers(&mut self) -> Result<Modifiers, ParseError> {
        let mut m = Modifiers::default();
        loop {
            let tok = self.peek().clone();
            let TokenKind::Identifier(word) = &tok.kind else {
                break;
            };
            match word.as_str() {
                "ascii" => {
                    self.advance();
                    m.ascii = true;
                }
                "wide" => {
                    self.advance();
                    m.wide = true;
                }
                "nocase" => {
                    self.advance();
                    m.nocase = true;
                }
                "fullword" => {
                    self.advance();
                    m.fullword = true;
                }
                "private" => {
                    self.advance();
                    m.private = true;
                }
                "xor" => {
                    self.advance();
                    m.xor = Some(self.parse_xor_range()?);
                }
                "base64" | "base64wide" => {
                    self.advance();
                    let alphabet = self.parse_base64_alphabet()?;
                    // `base64` and `base64wide` may both appear; each widens
                    // the set of encodings rather than replacing it.
                    m.base64 = Some(merge_base64(m.base64, alphabet));
                }
                _ => break,
            }
        }
        Ok(m)
    }

    /// `xor` on its own means every key from 1 to 255.
    fn parse_xor_range(&mut self) -> Result<XorRange, ParseError> {
        if !self.eat_kind(|k| matches!(k, TokenKind::LParen)) {
            return Ok(XorRange::FULL);
        }
        let min = self.parse_byte_literal()?;
        let max = if self.eat_kind(|k| matches!(k, TokenKind::Minus)) {
            self.parse_byte_literal()?
        } else {
            min
        };
        self.expect_token(|k| matches!(k, TokenKind::RParen), "`)` after the xor range")?;
        if min > max {
            return Err(self.error_here(format!("xor range 0x{min:02X}-0x{max:02X} is inverted")));
        }
        Ok(XorRange { min, max })
    }

    fn parse_byte_literal(&mut self) -> Result<u8, ParseError> {
        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::Integer(v) => {
                let v = *v;
                self.advance();
                u8::try_from(v).map_err(|_| {
                    self.error_at(&tok, format!("{v} does not fit in a single byte"))
                })
            }
            _ => Err(self.error_at(&tok, "expected a byte value such as `1` or `0xFF`")),
        }
    }

    /// `base64` and `base64wide` with no argument include both the standard and
    /// the URL-safe alphabet, matching YARA.
    fn parse_base64_alphabet(&mut self) -> Result<Base64Alphabet, ParseError> {
        if !self.eat_kind(|k| matches!(k, TokenKind::LParen)) {
            return Ok(Base64Alphabet::default());
        }
        // The only argument YARA defines is a custom alphabet string, which we
        // do not support. Report it rather than ignoring it: a rule that thinks
        // it is matching a custom alphabet would otherwise look like a rule
        // that simply never fires, which is far harder to diagnose.
        Err(self.error_here(
            "custom base64 alphabets are not supported; use bare `base64` or `base64wide`",
        ))
    }

    // -- expressions --------------------------------------------------------

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_binary(PREC_OR)
    }

    /// Checked entry point for expression parsing.
    ///
    /// Every recursive descent into an expression passes through here or
    /// through [`Parser::parse_unary`], so the depth counter measures the tree
    /// the parser is building rather than the call stack it happens to have.
    fn parse_binary(&mut self, min_prec: u8) -> Result<Expr, ParseError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.error_here("expression nests too deeply"));
        }
        self.depth = self.depth.saturating_add(1);
        let result = self.parse_binary_inner(min_prec);
        self.depth = self.depth.saturating_sub(1);
        result
    }

    fn parse_binary_inner(&mut self, min_prec: u8) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_operand(min_prec)?;
        while let Some((prec, op)) = self.peek_binary_op() {
            if prec < min_prec {
                break;
            }
            self.note_node()?;
            self.advance();
            // Left-associative: the right operand must bind strictly tighter.
            let rhs = self.parse_binary(prec.saturating_add(1))?;
            lhs = apply_binary(op, lhs, rhs);
        }
        Ok(lhs)
    }

    fn peek_binary_op(&self) -> Option<(u8, BinOp)> {
        let tok = self.peek();
        let by_token = |op: BinOp, prec: u8| Some((prec, op));
        match &tok.kind {
            TokenKind::Pipe => by_token(BinOp::Bit(BitOp::Or), PREC_BITOR),
            TokenKind::Caret => by_token(BinOp::Bit(BitOp::Xor), PREC_BITXOR),
            TokenKind::Amp => by_token(BinOp::Bit(BitOp::And), PREC_BITAND),
            TokenKind::Shl => by_token(BinOp::Bit(BitOp::Shl), PREC_SHIFT),
            TokenKind::Shr => by_token(BinOp::Bit(BitOp::Shr), PREC_SHIFT),
            TokenKind::Plus => by_token(BinOp::Arith(ArithOp::Add), PREC_ADD),
            TokenKind::Minus => by_token(BinOp::Arith(ArithOp::Sub), PREC_ADD),
            TokenKind::Star => by_token(BinOp::Arith(ArithOp::Mul), PREC_MUL),
            TokenKind::Slash => by_token(BinOp::Arith(ArithOp::Div), PREC_MUL),
            TokenKind::Percent => by_token(BinOp::Arith(ArithOp::Mod), PREC_MUL),
            TokenKind::Eq => by_token(BinOp::Cmp(CmpOp::Eq), PREC_CMP),
            TokenKind::Ne => by_token(BinOp::Cmp(CmpOp::Ne), PREC_CMP),
            TokenKind::Lt => by_token(BinOp::Cmp(CmpOp::Lt), PREC_CMP),
            TokenKind::Le => by_token(BinOp::Cmp(CmpOp::Le), PREC_CMP),
            TokenKind::Gt => by_token(BinOp::Cmp(CmpOp::Gt), PREC_CMP),
            TokenKind::Ge => by_token(BinOp::Cmp(CmpOp::Ge), PREC_CMP),
            TokenKind::Identifier(word) => match word.as_str() {
                "or" => by_token(BinOp::Or, PREC_OR),
                "and" => by_token(BinOp::And, PREC_AND),
                "contains" => by_token(BinOp::Str(StringOp::Contains), PREC_CMP),
                "icontains" => by_token(BinOp::Str(StringOp::IContains), PREC_CMP),
                "startswith" => by_token(BinOp::Str(StringOp::StartsWith), PREC_CMP),
                "istartswith" => by_token(BinOp::Str(StringOp::IStartsWith), PREC_CMP),
                "endswith" => by_token(BinOp::Str(StringOp::EndsWith), PREC_CMP),
                "iendswith" => by_token(BinOp::Str(StringOp::IEndsWith), PREC_CMP),
                "iequals" => by_token(BinOp::Str(StringOp::IEquals), PREC_CMP),
                "matches" => by_token(BinOp::Str(StringOp::Matches), PREC_CMP),
                _ => None,
            },
            _ => None,
        }
    }

    /// Parse one operand, applying the prefix `not` if this position is loose
    /// enough to allow it.
    ///
    /// `not` sits between `and` and comparison in the precedence table, so
    /// `not a > b` means `not (a > b)`. Handling it inside [`Parser::parse_unary`]
    /// instead would bind it tighter than `>`, silently inverting the meaning of
    /// any rule that writes `not filesize > 100`.
    fn parse_operand(&mut self, min_prec: u8) -> Result<Expr, ParseError> {
        if min_prec <= PREC_CMP && self.check_word("not") {
            self.advance();
            // Operand parsed at comparison level: it swallows the whole
            // comparison chain but stops before `and` and `or`.
            let inner = self.parse_binary(PREC_CMP)?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_unary()
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        // A run of prefix operators — `----x`, `~~~~x` — recurses without
        // passing through `parse_binary`, so it needs the same bound.
        if self.depth >= MAX_DEPTH {
            return Err(self.error_here("expression nests too deeply"));
        }
        self.depth = self.depth.saturating_add(1);
        let result = self.parse_unary_inner();
        self.depth = self.depth.saturating_sub(1);
        result
    }

    fn parse_unary_inner(&mut self) -> Result<Expr, ParseError> {
        if self.eat_kind(|k| matches!(k, TokenKind::Minus)) {
            let inner = self.parse_unary()?;
            // Fold `-1` here: negative literals are everywhere in rules, and a
            // `Negate` node around a constant would make the compiler's
            // constant folding do work it never needs to do.
            return Ok(match inner {
                Expr::Int(n) => Expr::Int(n.saturating_neg()),
                Expr::Float(x) => Expr::Float(-x),
                other => Expr::Negate(Box::new(other)),
            });
        }
        if self.eat_kind(|k| matches!(k, TokenKind::Tilde)) {
            let inner = self.parse_unary()?;
            return Ok(match inner {
                Expr::Int(n) => Expr::Int(!n),
                other => Expr::BitNot(Box::new(other)),
            });
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary()?;
        loop {
            if self.check_word("of") {
                self.advance();
                let quantifier = Quantifier::Count(Box::new(expr));
                expr = self.parse_of_body(quantifier)?;
            } else if self.check(|k| matches!(k, TokenKind::LBracket)) {
                self.advance();
                let index = self.parse_expr()?;
                self.expect_token(|k| matches!(k, TokenKind::RBracket), "`]`")?;
                expr = Expr::Index {
                    base: Box::new(expr),
                    index: Box::new(index),
                };
            } else if self.eat_word("defined").is_some() {
                expr = Expr::Defined(Box::new(expr));
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        self.note_node()?;
        let tok = self.peek().clone();

        if tok.is_word("for") {
            self.advance();
            return self.parse_for();
        }

        if let Some(quantifier) = quantifier_keyword(&tok) {
            self.advance();
            self.expect_word("of")?;
            return self.parse_of_body(quantifier);
        }

        match &tok.kind {
            TokenKind::Integer(v) => {
                let v = *v;
                self.advance();
                // `50% of them` must be recognised before `%` is read as the
                // modulo operator. Requiring `of` right after the `%` is what
                // keeps `filesize % 2` working.
                if self.check(|k| matches!(k, TokenKind::Percent)) && self.peek_at(1).is_word("of") {
                    self.advance(); // `%`
                    self.advance(); // `of`
                    let percent = u8::try_from(v).unwrap_or(0).min(100);
                    return self.parse_of_body(Quantifier::Percentage(percent));
                }
                Ok(Expr::Int(v))
            }
            TokenKind::Float(x) => {
                let x = *x;
                self.advance();
                Ok(Expr::Float(x))
            }
            TokenKind::Boolean(b) => {
                let b = *b;
                self.advance();
                Ok(Expr::Bool(b))
            }
            TokenKind::Literal(bytes) => {
                let text = String::from_utf8_lossy(bytes).into_owned();
                self.advance();
                Ok(Expr::Str(text))
            }
            TokenKind::StringRef(name) => {
                let name = name.clone();
                self.advance();
                self.parse_string_reference(name)
            }
            TokenKind::CountRef(name) => {
                let name = name.clone();
                self.advance();
                Ok(Expr::StringCount(name))
            }
            TokenKind::OffsetRef(name) => {
                let name = name.clone();
                self.advance();
                let index = self.parse_optional_index()?;
                Ok(Expr::StringOffset(name, index))
            }
            TokenKind::LengthRef(name) => {
                let name = name.clone();
                self.advance();
                let index = self.parse_optional_index()?;
                Ok(Expr::StringLength(name, index))
            }
            TokenKind::Identifier(name) => {
                let name = name.clone();
                self.advance();
                match name.as_str() {
                    "filesize" => Ok(Expr::Filesize),
                    "entrypoint" => Ok(Expr::EntryPoint),
                    _ => self.parse_path_or_call(&name),
                }
            }
            TokenKind::LParen => {
                self.advance();
                let inner = self.parse_expr()?;
                self.expect_token(|k| matches!(k, TokenKind::RParen), "`)`")?;
                Ok(inner)
            }
            // A regex is only reachable here as the right-hand side of
            // `matches`, which is exactly where it is meaningful. Whether it
            // appears anywhere else is a question about the expression's
            // context, and context is the compiler's business.
            TokenKind::Regex { body, flags } => {
                let (body, flags) = (body.clone(), flags.clone());
                self.advance();
                Ok(Expr::Regex { body, flags })
            }
            TokenKind::HexBlock(_) => Err(self.error_at(
                &tok,
                "a hex pattern belongs in the `strings` section, not in a condition",
            )),
            // Outside the `strings` section the lexer has no reason to treat
            // `{` as a hex pattern, so it arrives as a plain brace. Say what
            // the author probably meant rather than "expected an expression".
            TokenKind::LBrace => Err(self.error_at(
                &tok,
                "expected an expression; a hex pattern belongs in the `strings` section",
            )),
            _ => Err(self.error_here("expected an expression")),
        }
    }

    /// `$a`, `$a at 0x40`, `$a in (0..filesize)`, or the bare `$` of a
    /// `for ... of` body.
    fn parse_string_reference(&mut self, name: String) -> Result<Expr, ParseError> {
        // `at` and `in` are checked first: inside a `for ... of` body the bare
        // `$` is a legal operand for both (`for any of them : ( $ at entrypoint )`),
        // so bailing out early on the empty name would reject valid rules.
        if self.eat_word("at").is_some() {
            // Bind tighter than comparison but looser than `*`: `$a at ep + 4`
            // takes the whole sum, while `$a at 0 and $b` splits at `and`.
            let offset = self.parse_binary(PREC_ADD)?;
            return Ok(Expr::StringAt(name, Box::new(offset)));
        }
        if self.eat_word("in").is_some() {
            self.expect_token(|k| matches!(k, TokenKind::LParen), "`(` after `in`")?;
            let from = self.parse_expr()?;
            self.expect_token(|k| matches!(k, TokenKind::DotDot), "`..` in the range")?;
            let to = self.parse_expr()?;
            self.expect_token(|k| matches!(k, TokenKind::RParen), "`)` closing the range")?;
            return Ok(Expr::StringIn(name, Box::new(from), Box::new(to)));
        }
        if name.is_empty() {
            return Ok(Expr::ForOfPlaceholder);
        }
        Ok(Expr::StringMatch(name))
    }

    fn parse_optional_index(&mut self) -> Result<Option<Box<Expr>>, ParseError> {
        if !self.eat_kind(|k| matches!(k, TokenKind::LBracket)) {
            return Ok(None);
        }
        let index = self.parse_expr()?;
        self.expect_token(|k| matches!(k, TokenKind::RBracket), "`]`")?;
        Ok(Some(Box::new(index)))
    }

    /// A dotted path, optionally called: `pe.number_of_sections`,
    /// `pe.sections[i].name`, `hash.md5(0, filesize)`, or a bare loop variable.
    fn parse_path_or_call(&mut self, root: &str) -> Result<Expr, ParseError> {
        let mut path = MemberPath::new(root);
        loop {
            if self.eat_kind(|k| matches!(k, TokenKind::Dot)) {
                let field = self.expect_identifier("a field name after `.`")?;
                path.segments.push(PathSegment::Field(field));
            } else if self.eat_kind(|k| matches!(k, TokenKind::LBracket)) {
                let index = self.parse_expr()?;
                self.expect_token(|k| matches!(k, TokenKind::RBracket), "`]`")?;
                path.segments.push(PathSegment::Index(Box::new(index)));
            } else {
                break;
            }
        }

        if self.check(|k| matches!(k, TokenKind::LParen)) {
            let args = self.parse_call_args()?;
            return Ok(Expr::Call { path, args });
        }

        if path.segments.is_empty() {
            // A bare name. Which one it is — a `for` index, a module constant,
            // a typo — is a scope question, and scope is the compiler's job.
            return Ok(Expr::Variable(root.to_string()));
        }
        Ok(Expr::Field { path })
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expr>, ParseError> {
        self.expect_token(|k| matches!(k, TokenKind::LParen), "`(`")?;
        let mut args = Vec::new();
        if self.eat_kind(|k| matches!(k, TokenKind::RParen)) {
            return Ok(args);
        }
        loop {
            args.push(self.parse_expr()?);
            if self.eat_kind(|k| matches!(k, TokenKind::Comma)) {
                continue;
            }
            self.expect_token(|k| matches!(k, TokenKind::RParen), "`)` closing the arguments")?;
            break;
        }
        Ok(args)
    }

    fn parse_of_body(&mut self, quantifier: Quantifier) -> Result<Expr, ParseError> {
        let set = self.parse_string_set()?;
        // `any of ($t*) in (8..504)`. The range restricts where each string may
        // match, so this is a different question from `any of ($t*)` and cannot
        // be expressed by wrapping the set in a `StringIn`.
        if self.eat_word("in").is_some() {
            self.expect_token(|k| matches!(k, TokenKind::LParen), "`(` after `in`")?;
            let from = self.parse_expr()?;
            self.expect_token(|k| matches!(k, TokenKind::DotDot), "`..` in the range")?;
            let to = self.parse_expr()?;
            self.expect_token(
                |k| matches!(k, TokenKind::RParen),
                "`)` closing the `of ... in` range",
            )?;
            return Ok(Expr::OfIn {
                quantifier,
                set,
                from: Box::new(from),
                to: Box::new(to),
            });
        }
        Ok(Expr::Of { quantifier, set })
    }

    fn parse_string_set(&mut self) -> Result<StringSet, ParseError> {
        if self.eat_word("them").is_some() {
            return Ok(StringSet::All);
        }
        self.expect_token(|k| matches!(k, TokenKind::LParen), "`them` or `(` after `of`")?;
        if self.check(|k| matches!(k, TokenKind::RParen)) {
            return Err(self.error_here("an `of` set must name at least one string"));
        }

        let mut names = Vec::new();
        let mut prefixes = Vec::new();
        loop {
            let tok = self.peek().clone();
            let TokenKind::StringRef(raw) = &tok.kind else {
                return Err(self.error_at(&tok, "expected a string identifier such as `$a`"));
            };
            let raw = raw.clone();
            self.advance();
            if let Some(prefix) = raw.strip_suffix('*') {
                // `$*` stores the empty prefix, which matches every string.
                prefixes.push(prefix.to_string());
            } else if raw.is_empty() {
                return Err(self.error_at(
                    &tok,
                    "`$` on its own is only valid inside a `for ... of` body",
                ));
            } else {
                names.push(raw);
            }

            if self.eat_kind(|k| matches!(k, TokenKind::Comma)) {
                continue;
            }
            self.expect_token(|k| matches!(k, TokenKind::RParen), "`)` closing the set")?;
            break;
        }

        if names.is_empty() && prefixes.is_empty() {
            return Err(self.error_here("an `of` set must name at least one string"));
        }
        Ok(StringSet::List { names, prefixes })
    }

    /// `for any of ($a*) : ( $ )`, `for all i in (0..n) : ( ... )`, and
    /// `for any s in pe.sections : ( ... )`.
    fn parse_for(&mut self) -> Result<Expr, ParseError> {
        let Some(quantifier) = self.peek_for_quantifier() else {
            return Err(self.error_here("expected `any`, `all`, `none` or a count after `for`"));
        };
        self.advance();

        if self.eat_word("of").is_some() {
            let set = self.parse_string_set()?;
            self.expect_token(|k| matches!(k, TokenKind::Colon), "`:` before the loop body")?;
            let body = self.parse_loop_body()?;
            return Ok(Expr::ForOf {
                quantifier,
                set,
                body: Box::new(body),
            });
        }

        let var = self.expect_identifier("a loop variable")?;
        self.expect_word("in")?;

        // Two operands are possible here. `(a..b)` is an integer range;
        // anything else — `pe.sections`, a call, a parenthesised expression —
        // is a sequence to walk. The range form is recognised by the `..`
        // after the first expression, so the leading `(` cannot decide it.
        if self.check(|k| matches!(k, TokenKind::LParen)) {
            self.advance();
            let first = self.parse_expr()?;
            if self.eat_kind(|k| matches!(k, TokenKind::DotDot)) {
                let to = self.parse_expr()?;
                self.expect_token(|k| matches!(k, TokenKind::RParen), "`)` closing the loop range")?;
                self.expect_token(|k| matches!(k, TokenKind::Colon), "`:` before the loop body")?;
                let body = self.parse_loop_body()?;
                return Ok(Expr::ForIn {
                    quantifier,
                    var,
                    from: Box::new(first),
                    to: Box::new(to),
                    body: Box::new(body),
                });
            }
            self.expect_token(
                |k| matches!(k, TokenKind::RParen),
                "`)` closing the loop iterable",
            )?;
            // `( expr )` is `expr`, so the parentheses need no node of their own.
            return self.finish_foreach(quantifier, var, first);
        }

        let iterable = self.parse_expr()?;
        self.finish_foreach(quantifier, var, iterable)
    }

    fn finish_foreach(
        &mut self,
        quantifier: Quantifier,
        var: String,
        iterable: Expr,
    ) -> Result<Expr, ParseError> {
        self.expect_token(|k| matches!(k, TokenKind::Colon), "`:` before the loop body")?;
        let body = self.parse_loop_body()?;
        Ok(Expr::ForEach {
            quantifier,
            var,
            iterable: Box::new(iterable),
            body: Box::new(body),
        })
    }

    fn parse_loop_body(&mut self) -> Result<Expr, ParseError> {
        self.expect_token(|k| matches!(k, TokenKind::LParen), "`(` opening the loop body")?;
        let body = self.parse_expr()?;
        self.expect_token(|k| matches!(k, TokenKind::RParen), "`)` closing the loop body")?;
        Ok(body)
    }

    /// The quantifier after `for`: a keyword, or a count.
    ///
    /// `for 12 resource in pe.resources : ( ... )` requires at least twelve of
    /// the resources to satisfy the body. Only the keyword forms used to be
    /// accepted, so a counted loop was a syntax error.
    fn peek_for_quantifier(&self) -> Option<Quantifier> {
        if let TokenKind::Integer(v) = self.peek().kind {
            return Some(Quantifier::Count(Box::new(Expr::Int(v))));
        }
        quantifier_keyword(self.peek())
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

fn quantifier_keyword(tok: &Token) -> Option<Quantifier> {
    let TokenKind::Identifier(word) = &tok.kind else {
        return None;
    };
    match word.as_str() {
        "any" => Some(Quantifier::Any),
        "all" => Some(Quantifier::All),
        "none" => Some(Quantifier::None),
        _ => None,
    }
}

fn apply_binary(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
    match op {
        BinOp::Or => Expr::Or(Box::new(lhs), Box::new(rhs)),
        BinOp::And => Expr::And(Box::new(lhs), Box::new(rhs)),
        BinOp::Cmp(op) => Expr::Compare {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        },
        BinOp::Str(op) => Expr::StringOp {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        },
        BinOp::Arith(op) => Expr::Arithmetic {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        },
        BinOp::Bit(op) => Expr::Bitwise {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        },
    }
}

fn merge_base64(existing: Option<Base64Alphabet>, add: Base64Alphabet) -> Base64Alphabet {
    match existing {
        None => add,
        Some(a) => Base64Alphabet {
            standard: a.standard || add.standard,
            url_safe: a.url_safe || add.url_safe,
            wide: a.wide || add.wide,
        },
    }
}

/// Route a `key = value` pair into the typed metadata, falling back to
/// [`RuleMeta::extra`] for anything unrecognised.
fn apply_meta(meta: &mut RuleMeta, key: &str, value: MetaValue) {
    let text = |v: &MetaValue| v.to_string();
    match key {
        "description" => set_once(&mut meta.description, text(&value)),
        "author" => set_once(&mut meta.author, text(&value)),
        "date" => set_once(&mut meta.date, text(&value)),
        "source" => set_once(&mut meta.source, text(&value)),
        "license" => set_once(&mut meta.license, text(&value)),
        "reference" => meta.reference.push(text(&value)),
        // Several spellings of "a hash of a known sample" appear in the wild.
        "hash" | "sha256" | "sha1" | "md5" => {
            // Normalise: the blocklist compares lowercase hex, and rule authors
            // are inconsistent about case.
            meta.hashes.push(text(&value).trim().to_ascii_lowercase());
        }
        // An unrecognised severity is left unset rather than forced to a
        // default, and the original text is kept so a diagnostic can show it.
        "severity" => match Severity::try_from_str(&text(&value)) {
            Some(s) => set_once(&mut meta.severity, s),
            None => {
                meta.extra.insert(key.to_string(), value);
            }
        },
        "category" | "type" => {
            if let Some(c) = ThreatCategory::from_tag(&text(&value)) {
                set_once(&mut meta.category, c);
            } else {
                meta.extra.insert(key.to_string(), value);
            }
        }
        "platform" => {
            if let Some(p) = Platform::from_tag(&text(&value)) {
                set_once(&mut meta.platform, p);
            } else {
                meta.extra.insert(key.to_string(), value);
            }
        }
        "family" => set_once(&mut meta.family, text(&value)),
        "variant" => set_once(&mut meta.variant, text(&value)),
        // Both of these are `u16`/`u8` in the typed metadata, so a value that
        // does not fit is kept verbatim in `extra` instead of being dropped.
        // Silently discarding `quality = -107` would leave a rule looking
        // unscored when its author had in fact supplied a score.
        "weight" => match parse_u16(&value) {
            Some(w) => set_once(&mut meta.weight, w),
            None => {
                meta.extra.insert(key.to_string(), value);
            }
        },
        "quality" => match parse_u16(&value).and_then(|q| u8::try_from(q).ok()) {
            Some(q) => set_once(&mut meta.quality, q),
            None => {
                meta.extra.insert(key.to_string(), value);
            }
        },
        "decisive" => {
            meta.decisive = match &value {
                MetaValue::Boolean(b) => *b,
                other => matches!(other.to_string().to_ascii_lowercase().as_str(), "true" | "yes" | "1"),
            };
        }
        _ => {
            meta.extra.insert(key.to_string(), value);
        }
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

fn parse_u16(value: &MetaValue) -> Option<u16> {
    match value {
        MetaValue::Integer(i) => u16::try_from(*i).ok(),
        other => other.to_string().trim().parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::HexToken;

    fn cond(src: &str) -> Expr {
        parse_condition(src).unwrap_or_else(|e| panic!("`{src}` should parse: {e}"))
    }

    fn err(src: &str) -> ParseError {
        parse_file(src).expect_err("source should be rejected")
    }

    // -- rule structure -----------------------------------------------------

    #[test]
    fn parses_a_minimal_rule() {
        let file = parse_file(r#"rule hello { condition: true }"#).unwrap();
        assert_eq!(file.rules.len(), 1);
        let rule = &file.rules[0];
        assert_eq!(rule.name, "hello");
        assert!(!rule.private);
        assert!(!rule.global);
        assert_eq!(rule.condition, Expr::Bool(true));
    }

    #[test]
    fn parses_imports_and_includes() {
        let file = parse_file(
            r#"
            import "pe"
            import "math"
            include "common.yar"
            rule r { condition: true }
            "#,
        )
        .unwrap();
        assert_eq!(file.imports, vec!["pe", "math"]);
        assert_eq!(file.includes, vec!["common.yar"]);
        assert_eq!(file.rules.len(), 1);
    }

    #[test]
    fn private_and_global_modifiers_stack_in_any_order() {
        let file = parse_file("global private rule r { condition: true }").unwrap();
        assert!(file.rules[0].private);
        assert!(file.rules[0].global);
    }

    #[test]
    fn parses_tags() {
        let file = parse_file("rule r : ransomware lockbit { condition: true }").unwrap();
        assert_eq!(file.rules[0].tags, vec!["ransomware", "lockbit"]);
    }

    #[test]
    fn an_empty_tag_list_is_rejected() {
        assert!(err("rule r : { condition: true }").message.contains("at least one tag"));
    }

    #[test]
    fn a_rule_without_a_condition_is_rejected() {
        let e = err("rule r { strings: $a = \"x\" }");
        assert!(e.message.contains("condition"), "got: {e}");
    }

    #[test]
    fn trailing_input_after_a_rule_is_rejected() {
        let e = err("rule r { condition: true } }");
        assert!(e.message.contains("rule definition"), "got: {e}");
    }

    // -- strings section ----------------------------------------------------

    #[test]
    fn parses_text_hex_and_regex_strings() {
        let file = parse_file(
            r#"
            rule r {
                strings:
                    $text = "hello"
                    $hex  = { 4D 5A ?? }
                    $re   = /ab+c/
                condition:
                    any of them
            }
            "#,
        )
        .unwrap();
        let strings = &file.rules[0].strings;
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].id, "$text");
        assert_eq!(strings[0].value, StringValue::Text(b"hello".to_vec()));
        assert!(matches!(strings[1].value, StringValue::Hex(_)));
        assert_eq!(
            strings[2].value,
            StringValue::Regex {
                body: "ab+c".into(),
                flags: String::new()
            }
        );
    }

    #[test]
    fn regex_flags_are_captured_verbatim() {
        let file =
            parse_file(r#"rule r { strings: $a = /ab/i condition: $a }"#).unwrap();
        assert_eq!(
            file.rules[0].strings[0].value,
            StringValue::Regex {
                body: "ab".into(),
                flags: "i".into()
            }
        );
    }

    #[test]
    fn parses_string_modifiers() {
        let file = parse_file(
            r#"rule r { strings: $a = "x" ascii wide nocase fullword private
               condition: $a }"#,
        )
        .unwrap();
        let m = file.rules[0].strings[0].modifiers;
        assert!(m.ascii && m.wide && m.nocase && m.fullword && m.private);
    }

    #[test]
    fn bare_xor_covers_every_key() {
        let file = parse_file(r#"rule r { strings: $a = "x" xor condition: $a }"#).unwrap();
        assert_eq!(file.rules[0].strings[0].modifiers.xor, Some(XorRange::FULL));
    }

    #[test]
    fn xor_accepts_an_explicit_range() {
        let file =
            parse_file(r#"rule r { strings: $a = "x" xor(0x01-0x10) condition: $a }"#).unwrap();
        assert_eq!(
            file.rules[0].strings[0].modifiers.xor,
            Some(XorRange { min: 1, max: 16 })
        );
    }

    #[test]
    fn an_inverted_xor_range_is_rejected() {
        let e = err(r#"rule r { strings: $a = "x" xor(10-2) condition: $a }"#);
        assert!(e.message.contains("inverted"), "got: {e}");
    }

    #[test]
    fn a_custom_base64_alphabet_is_refused_rather_than_ignored() {
        let e = err(r#"rule r { strings: $a = "x" base64("ABC") condition: $a }"#);
        assert!(e.message.contains("not supported"), "got: {e}");
    }

    #[test]
    fn anonymous_strings_get_synthesised_identifiers() {
        let file = parse_file(
            r#"rule r { strings: $ = "a" $ = "b" condition: any of them }"#,
        )
        .unwrap();
        let ids: Vec<&str> = file.rules[0]
            .strings
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(ids, vec!["$anon1", "$anon2"]);
    }

    #[test]
    fn duplicate_string_identifiers_are_rejected() {
        let e = err(r#"rule r { strings: $a = "x" $a = "y" condition: $a }"#);
        assert!(e.message.contains("defined twice"), "got: {e}");
    }

    #[test]
    fn a_hex_error_points_at_the_offending_character() {
        let e = err(r#"rule r { strings: $a = { 4D ZZ } condition: $a }"#);
        assert!(e.message.contains("not a hex digit"), "got: {e}");
        // In `rule r { strings: $a = { 4D ZZ } ...` the opening brace is at
        // byte 23, so the body starts at 24 and the bad `Z` is at 28.
        assert_eq!(e.offset, 28, "got column {}", e.column);
        assert_eq!(e.column, 29);
    }

    // -- meta ---------------------------------------------------------------

    #[test]
    fn typed_meta_lands_in_the_right_fields() {
        let file = parse_file(
            r#"
            rule r {
                meta:
                    description = "A test"
                    author = "nobody"
                    severity = "high"
                    category = "ransomware"
                    platform = "win32"
                    family = "LockBit"
                    variant = "3"
                    weight = 120
                    quality = 80
                    decisive = true
                    reference = "https://example.invalid/1"
                    reference = "https://example.invalid/2"
                condition:
                    true
            }
            "#,
        )
        .unwrap();
        let m = &file.rules[0].meta;
        assert_eq!(m.description.as_deref(), Some("A test"));
        assert_eq!(m.author.as_deref(), Some("nobody"));
        assert_eq!(m.severity, Some(Severity::High));
        assert_eq!(m.category, Some(ThreatCategory::Ransomware));
        assert_eq!(m.platform, Some(Platform::Win32));
        assert_eq!(m.family.as_deref(), Some("LockBit"));
        assert_eq!(m.variant.as_deref(), Some("3"));
        assert_eq!(m.weight, Some(120));
        assert_eq!(m.quality, Some(80));
        assert!(m.decisive);
        assert_eq!(m.reference.len(), 2);
    }

    #[test]
    fn hashes_are_lowercased_so_the_blocklist_can_compare_them() {
        let file = parse_file(
            r#"rule r { meta: hash = "AABBCCDD" condition: true }"#,
        )
        .unwrap();
        assert_eq!(file.rules[0].meta.hashes, vec!["aabbccdd"]);
    }

    #[test]
    fn a_misspelled_severity_is_preserved_rather_than_guessed() {
        // Defaulting to `Medium` would hand the rule a score of 60 the author
        // never asked for.
        let file = parse_file(r#"rule r { meta: severity = "hgih" condition: true }"#).unwrap();
        let m = &file.rules[0].meta;
        assert_eq!(m.severity, None);
        assert_eq!(
            m.extra.get("severity"),
            Some(&MetaValue::Text("hgih".into()))
        );
    }

    #[test]
    fn unknown_meta_keys_are_preserved() {
        let file =
            parse_file(r#"rule r { meta: tlp = "WHITE" condition: true }"#).unwrap();
        assert_eq!(
            file.rules[0].meta.extra.get("tlp"),
            Some(&MetaValue::Text("WHITE".into()))
        );
    }

    #[test]
    fn a_meta_key_named_condition_does_not_end_the_section_early() {
        // Only a section header is followed by `:`.
        let file = parse_file(
            r#"rule r { meta: condition = "looks like a header" condition: true }"#,
        )
        .unwrap();
        assert_eq!(
            file.rules[0].meta.extra.get("condition"),
            Some(&MetaValue::Text("looks like a header".into()))
        );
    }

    // -- expression precedence ----------------------------------------------

    #[test]
    fn and_binds_tighter_than_or() {
        // `a or b and c` must be `a or (b and c)`, or a rule that lists
        // alternatives would silently mean something else.
        let e = cond("true or false and true");
        match e {
            Expr::Or(lhs, rhs) => {
                assert_eq!(*lhs, Expr::Bool(true));
                assert!(matches!(*rhs, Expr::And(_, _)), "got {rhs:?}");
            }
            other => panic!("expected `or` at the root, got {other:?}"),
        }
    }

    #[test]
    fn arithmetic_binds_tighter_than_comparison() {
        let e = cond("filesize + 4 > 100");
        match e {
            Expr::Compare { op: CmpOp::Gt, lhs, .. } => {
                assert!(matches!(*lhs, Expr::Arithmetic { op: ArithOp::Add, .. }));
            }
            other => panic!("expected a comparison at the root, got {other:?}"),
        }
    }

    #[test]
    fn multiplication_binds_tighter_than_addition() {
        let e = cond("1 + 2 * 3");
        match e {
            Expr::Arithmetic { op: ArithOp::Add, rhs, .. } => {
                assert!(matches!(*rhs, Expr::Arithmetic { op: ArithOp::Mul, .. }));
            }
            other => panic!("expected addition at the root, got {other:?}"),
        }
    }

    #[test]
    fn bitwise_or_binds_looser_than_bitwise_and() {
        let e = cond("1 | 2 & 3");
        match e {
            Expr::Bitwise { op: BitOp::Or, rhs, .. } => {
                assert!(matches!(*rhs, Expr::Bitwise { op: BitOp::And, .. }));
            }
            other => panic!("expected `|` at the root, got {other:?}"),
        }
    }

    #[test]
    fn subtraction_is_left_associative() {
        let e = cond("10 - 3 - 2");
        match e {
            Expr::Arithmetic { op: ArithOp::Sub, lhs, .. } => {
                assert!(matches!(*lhs, Expr::Arithmetic { op: ArithOp::Sub, .. }));
            }
            other => panic!("expected `-` at the root, got {other:?}"),
        }
    }

    #[test]
    fn negative_literals_are_folded_at_parse_time() {
        assert_eq!(cond("-1"), Expr::Int(-1));
        assert_eq!(cond("- 0x10"), Expr::Int(-16));
    }

    #[test]
    fn not_applies_to_the_whole_comparison() {
        let e = cond("not filesize > 10");
        assert!(matches!(e, Expr::Not(inner) if matches!(*inner, Expr::Compare { .. })));
    }

    #[test]
    fn defined_is_postfix() {
        let e = cond("pe.entry_point defined");
        assert!(matches!(e, Expr::Defined(inner) if matches!(*inner, Expr::Field { .. })));
    }

    #[test]
    fn parenthesised_expressions_override_precedence() {
        let e = cond("(true or false) and true");
        assert!(matches!(e, Expr::And(lhs, _) if matches!(*lhs, Expr::Or(_, _))));
    }

    // -- string references --------------------------------------------------

    #[test]
    fn parses_string_reference_forms() {
        assert_eq!(cond("$a"), Expr::StringMatch("a".into()));
        assert_eq!(cond("#a"), Expr::StringCount("a".into()));
        assert_eq!(cond("@a"), Expr::StringOffset("a".into(), None));
        assert_eq!(cond("!a"), Expr::StringLength("a".into(), None));
        assert_eq!(cond("@a[2]"), Expr::StringOffset("a".into(), Some(Box::new(Expr::Int(2)))));
        assert_eq!(cond("!a[3]"), Expr::StringLength("a".into(), Some(Box::new(Expr::Int(3)))));
    }

    #[test]
    fn parses_at_and_in() {
        assert_eq!(
            cond("$a at 0x40"),
            Expr::StringAt("a".into(), Box::new(Expr::Int(0x40)))
        );
        assert_eq!(
            cond("$a in (0..100)"),
            Expr::StringIn(
                "a".into(),
                Box::new(Expr::Int(0)),
                Box::new(Expr::Int(100))
            )
        );
    }

    #[test]
    fn at_takes_the_whole_sum_but_not_the_comparison() {
        let e = cond("$a at 4 + 4 and true");
        match e {
            Expr::And(lhs, _) => match *lhs {
                Expr::StringAt(_, offset) => {
                    assert!(matches!(*offset, Expr::Arithmetic { op: ArithOp::Add, .. }));
                }
                other => panic!("expected `at` on the left, got {other:?}"),
            },
            other => panic!("expected `and` at the root, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_dollar_is_the_for_of_placeholder() {
        assert_eq!(cond("$"), Expr::ForOfPlaceholder);
    }

    // -- quantification -----------------------------------------------------

    #[test]
    fn parses_of_them() {
        let e = cond("any of them");
        assert_eq!(
            e,
            Expr::Of {
                quantifier: Quantifier::Any,
                set: StringSet::All
            }
        );
    }

    #[test]
    fn parses_all_three_quantifier_keywords() {
        for (src, want) in [
            ("all of them", Quantifier::All),
            ("none of them", Quantifier::None),
        ] {
            match cond(src) {
                Expr::Of { quantifier, .. } => assert_eq!(quantifier, want),
                other => panic!("expected `of`, got {other:?}"),
            }
        }
    }

    #[test]
    fn parses_a_count_quantifier() {
        match cond("3 of them") {
            Expr::Of { quantifier: Quantifier::Count(n), .. } => assert_eq!(*n, Expr::Int(3)),
            other => panic!("expected a count, got {other:?}"),
        }
    }

    #[test]
    fn a_count_may_be_a_module_field() {
        // `pe.number_of_sections of them` is real and common.
        match cond("pe.number_of_sections of them") {
            Expr::Of { quantifier: Quantifier::Count(n), .. } => {
                assert!(matches!(*n, Expr::Field { .. }));
            }
            other => panic!("expected a computed count, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_percentage_quantifier() {
        match cond("50% of them") {
            Expr::Of { quantifier: Quantifier::Percentage(p), .. } => assert_eq!(p, 50),
            other => panic!("expected a percentage, got {other:?}"),
        }
    }

    #[test]
    fn modulo_is_not_mistaken_for_a_percentage() {
        // The `%` only means "percent" when `of` follows it.
        let e = cond("filesize % 2 == 0");
        match e {
            Expr::Compare { lhs, .. } => {
                assert!(matches!(*lhs, Expr::Arithmetic { op: ArithOp::Mod, .. }));
            }
            other => panic!("expected a modulo comparison, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_string_set_with_names_and_prefixes() {
        match cond("2 of ($a, $b, $c*)") {
            Expr::Of { set: StringSet::List { names, prefixes }, .. } => {
                assert_eq!(names, vec!["a", "b"]);
                assert_eq!(prefixes, vec!["c"]);
            }
            other => panic!("expected a list set, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_star_prefix_matches_every_string() {
        match cond("any of ($*)") {
            Expr::Of { set: StringSet::List { prefixes, .. }, .. } => {
                assert_eq!(prefixes, vec![""]);
            }
            other => panic!("expected a list set, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_of_set_is_rejected() {
        let e = err("rule r { condition: any of () }");
        assert!(e.message.contains("at least one string"), "got: {e}");
    }

    // -- loops --------------------------------------------------------------

    #[test]
    fn parses_a_for_of_loop() {
        match cond("for any of ($a*) : ( $ at entrypoint )") {
            Expr::ForOf { quantifier, set, body } => {
                assert_eq!(quantifier, Quantifier::Any);
                assert!(matches!(set, StringSet::List { .. }));
                assert!(matches!(*body, Expr::StringAt(_, _)));
            }
            other => panic!("expected a for-of loop, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_for_in_loop() {
        match cond("for any i in (0..pe.number_of_sections) : ( true )") {
            Expr::ForIn { var, from, to, .. } => {
                assert_eq!(var, "i");
                assert_eq!(*from, Expr::Int(0));
                assert!(matches!(*to, Expr::Field { .. }));
            }
            other => panic!("expected a for-in loop, got {other:?}"),
        }
    }

    #[test]
    fn a_loop_variable_is_just_an_identifier_at_parse_time() {
        // Whether `i` is in scope is the compiler's question.
        assert_eq!(cond("i"), Expr::Variable("i".into()));
    }

    #[test]
    fn a_for_without_a_quantifier_is_rejected() {
        let e = err("rule r { condition: for i in (0..1) : ( true ) }");
        assert!(e.message.contains("after `for`"), "got: {e}");
    }

    // -- module paths and calls ---------------------------------------------

    #[test]
    fn parses_a_module_field() {
        match cond("pe.number_of_sections") {
            Expr::Field { path } => {
                assert_eq!(path.root, "pe");
                assert_eq!(path.segments, vec![PathSegment::Field("number_of_sections".into())]);
            }
            other => panic!("expected a field, got {other:?}"),
        }
    }

    #[test]
    fn parses_an_indexed_module_field() {
        match cond("pe.sections[i].name") {
            Expr::Field { path } => {
                assert_eq!(path.segments.len(), 3);
                assert!(matches!(path.segments[1], PathSegment::Index(_)));
                assert_eq!(path.segments[2], PathSegment::Field("name".into()));
            }
            other => panic!("expected an indexed field, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_call_with_arguments() {
        match cond("hash.md5(0, filesize)") {
            Expr::Call { path, args } => {
                assert_eq!(path.root, "hash");
                assert_eq!(path.segments, vec![PathSegment::Field("md5".into())]);
                assert_eq!(args, vec![Expr::Int(0), Expr::Filesize]);
            }
            other => panic!("expected a call, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_call_with_no_arguments() {
        match cond("pe.imphash()") {
            Expr::Call { args, .. } => assert!(args.is_empty()),
            other => panic!("expected a call, got {other:?}"),
        }
    }

    #[test]
    fn parses_string_operators() {
        for (src, want) in [
            ("\"a\" contains \"b\"", StringOp::Contains),
            ("\"a\" icontains \"b\"", StringOp::IContains),
            ("\"a\" startswith \"b\"", StringOp::StartsWith),
            ("\"a\" endswith \"b\"", StringOp::EndsWith),
            ("\"a\" iequals \"b\"", StringOp::IEquals),
            ("\"a\" matches /b/", StringOp::Matches),
        ] {
            match cond(src) {
                Expr::StringOp { op, .. } => assert_eq!(op, want, "for `{src}`"),
                other => panic!("expected a string operator for `{src}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_regex_operand_keeps_its_body_and_flags() {
        match cond("\"a\" matches /ab+c/i") {
            Expr::StringOp { op: StringOp::Matches, rhs, .. } => {
                assert_eq!(
                    *rhs,
                    Expr::Regex {
                        body: "ab+c".into(),
                        flags: "i".into()
                    }
                );
            }
            other => panic!("expected `matches`, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_dollar_supports_at_inside_a_loop_body() {
        // `$ at entrypoint` is the usual way to say "the current string, at the
        // entry point", and an empty name is how the placeholder is spelled.
        match cond("for any of them : ( $ at entrypoint )") {
            Expr::ForOf { body, .. } => {
                assert_eq!(*body, Expr::StringAt(String::new(), Box::new(Expr::EntryPoint)));
            }
            other => panic!("expected a for-of loop, got {other:?}"),
        }
    }

    #[test]
    fn parses_filesize_and_entrypoint() {
        assert_eq!(cond("filesize"), Expr::Filesize);
        assert_eq!(cond("entrypoint"), Expr::EntryPoint);
    }

    // -- diagnostics --------------------------------------------------------

    #[test]
    fn errors_carry_a_line_and_column() {
        let e = err("rule r {\n  condition: )\n}");
        assert_eq!(e.line, 2, "got: {e}");
        assert!(e.column > 1);
    }

    #[test]
    fn a_hex_pattern_in_a_condition_is_refused_with_a_useful_message() {
        // Outside the `strings` section the lexer emits a plain brace, so the
        // parser has to recognise the shape and point at the right section.
        let e = err("rule r { condition: { 4D 5A } }");
        assert!(e.message.contains("`strings` section"), "got: {e}");
    }

    // -- round trip ---------------------------------------------------------

    #[test]
    fn a_realistic_rule_parses_end_to_end() {
        let file = parse_file(
            r#"
            import "pe"

            rule Ransomware_LockBit_Strings : ransomware lockbit
            {
                meta:
                    description = "Detects LockBit loader strings"
                    author      = "Wenle"
                    severity    = "critical"
                    category    = "ransomware"
                    platform    = "win32"
                    family      = "LockBit"
                    hash        = "0A1B2C3D"
                    decisive    = false

                strings:
                    $marker = "LockBit" ascii wide nocase
                    $note   = "All your files have been encrypted"
                    $stub   = { 48 8B ?? ?? 48 85 C0 74 [1-4] }
                    $re     = /restore[-_]?files/i

                condition:
                    uint16(0) == 0x5A4D
                    and filesize < 5MB
                    and pe.number_of_sections > 2
                    and (
                        2 of ($marker, $note, $re)
                        or $stub at pe.entry_point
                    )
                    and not pe.imphash() == "d41d8cd98f00b204e9800998ecf8427e"
            }
            "#,
        )
        .unwrap();

        assert_eq!(file.imports, vec!["pe"]);
        let rule = &file.rules[0];
        assert_eq!(rule.name, "Ransomware_LockBit_Strings");
        assert_eq!(rule.tags, vec!["ransomware", "lockbit"]);
        assert_eq!(rule.meta.severity, Some(Severity::Critical));
        assert_eq!(rule.meta.hashes, vec!["0a1b2c3d"]);
        assert_eq!(rule.strings.len(), 4);
        assert_eq!(
            rule.strings[2].value,
            StringValue::Hex(crate::hex::parse("48 8B ?? ?? 48 85 C0 74 [1-4]").unwrap())
        );
        // The top-level shape is a chain of `and`s.
        assert!(matches!(rule.condition, Expr::And(_, _)));
    }

    #[test]
    fn hex_patterns_survive_the_round_trip_through_the_lexer() {
        // The lexer captures the body verbatim, so the parser has to feed it
        // to the hex parser unaltered — including the braces being adjacent to
        // the bytes.
        let file =
            parse_file(r#"rule r { strings: $a = {4D5A} condition: $a }"#).unwrap();
        match &file.rules[0].strings[0].value {
            StringValue::Hex(p) => {
                assert_eq!(p.tokens, vec![HexToken::Byte(0x4D), HexToken::Byte(0x5A)]);
            }
            other => panic!("expected a hex pattern, got {other:?}"),
        }
    }

    // -- constructs found in third-party rule sets --------------------------

    #[test]
    fn a_negative_meta_value_keeps_its_sign() {
        // `quality = -107` appears in machine-scored rule sets, where the value
        // is a signed adjustment rather than a count or a version.
        let file = parse_file(r#"rule r { meta: quality = -107 condition: true }"#).unwrap();
        assert_eq!(
            file.rules[0].meta.extra.get("quality"),
            Some(&MetaValue::Integer(-107))
        );
    }

    #[test]
    fn a_negative_sign_without_a_number_is_still_an_error() {
        let e = err(r#"rule r { meta: author = -"x" condition: true }"#);
        assert!(e.message.contains("meta value"), "{e}");
    }

    #[test]
    fn an_of_set_can_be_constrained_to_a_range() {
        // `any of ($t*) in (8..504)` asks whether the set matches *within* the
        // range, which is a different question from `any of ($t*)`.
        let e = cond("any of ($t*) in (8 .. 504)");
        match e {
            Expr::OfIn {
                quantifier,
                set,
                from,
                to,
            } => {
                assert_eq!(quantifier, Quantifier::Any);
                assert_eq!(
                    set,
                    StringSet::List {
                        names: vec![],
                        prefixes: vec!["t".into()]
                    }
                );
                assert_eq!(*from, Expr::Int(8));
                assert_eq!(*to, Expr::Int(504));
            }
            other => panic!("expected an `of ... in`, got {other:?}"),
        }
    }

    #[test]
    fn an_of_set_without_a_range_is_still_a_plain_of() {
        assert!(matches!(cond("any of them"), Expr::Of { .. }));
    }

    #[test]
    fn a_for_loop_quantifier_may_be_a_count() {
        // `for 12 resource in pe.resources : ( ... )` means at least twelve of
        // the resources must satisfy the body.
        let e = cond("for 12 resource in pe.resources : ( resource.type == 10 )");
        match e {
            Expr::ForEach {
                quantifier, var, ..
            } => {
                assert_eq!(quantifier, Quantifier::Count(Box::new(Expr::Int(12))));
                assert_eq!(var, "resource");
            }
            other => panic!("expected a counted `for .. in`, got {other:?}"),
        }
    }

    #[test]
    fn a_for_loop_can_iterate_a_module_array() {
        let e = cond(r#"for any s in pe.sections : ( s.name == ".text" )"#);
        match e {
            Expr::ForEach {
                quantifier,
                var,
                iterable,
                ..
            } => {
                assert_eq!(quantifier, Quantifier::Any);
                assert_eq!(var, "s");
                match *iterable {
                    Expr::Field { path } => assert_eq!(path.render(), "pe.sections"),
                    other => panic!("expected the array field, got {other:?}"),
                }
            }
            other => panic!("expected a `for .. in` over an array, got {other:?}"),
        }
    }

    #[test]
    fn a_parenthesised_iterable_is_the_same_as_a_bare_one() {
        // `( expr )` carries no meaning of its own, so it must not become a
        // separate node that the compiler then has to understand.
        let bare = cond("for any s in pe.sections : ( s.id == 1 )");
        let wrapped = cond("for any s in (pe.sections) : ( s.id == 1 )");
        assert_eq!(bare, wrapped);
    }

    #[test]
    fn a_for_range_keeps_its_quantifier() {
        // The quantifier is not decorative: `for all i in (0..n)` and
        // `for any i in (0..n)` ask opposite questions. It used to be dropped
        // while parsing, which silently turned one into the other.
        let e = cond("for all i in (0 .. pe.number_of_sections) : ( i > 0 )");
        match e {
            Expr::ForIn { quantifier, var, .. } => {
                assert_eq!(quantifier, Quantifier::All);
                assert_eq!(var, "i");
            }
            other => panic!("expected a `for .. in` range, got {other:?}"),
        }
    }

    #[test]
    fn a_for_range_and_a_for_array_are_distinguished_by_the_dotdot() {
        assert!(matches!(
            cond("for any i in (0 .. 10) : ( i > 0 )"),
            Expr::ForIn { .. }
        ));
        assert!(matches!(
            cond("for any i in pe.sections : ( i > 0 )"),
            Expr::ForEach { .. }
        ));
    }

    #[test]
    fn a_for_loop_needs_a_quantifier() {
        let e = err("rule r { condition: for in (0..1) : ( true ) }");
        assert!(e.message.contains("after `for`"), "{e}");
    }

    // -- hostile input ------------------------------------------------------

    #[test]
    fn deeply_nested_parentheses_are_refused_rather_than_overflowing() {
        // Without a bound this is not a syntax error, it is a stack overflow —
        // and the file it overflows on is whatever is on disk.
        let src = format!(
            "rule r {{ condition: {}{}{} }}",
            "(".repeat(2000),
            "true",
            ")".repeat(2000)
        );
        let e = err(&src);
        assert!(e.message.contains("nests too deeply"), "{e}");
    }

    #[test]
    fn a_long_run_of_prefix_operators_is_refused_rather_than_overflowing() {
        // `-----...-1` recurses through `parse_unary`, which the depth check in
        // `parse_binary` never sees.
        let src = format!("rule r {{ condition: {}1 }}", "-".repeat(2000));
        let e = err(&src);
        assert!(e.message.contains("nests too deeply"), "{e}");
    }

    #[test]
    fn an_enormous_conditional_chain_is_refused() {
        // Parsed by a loop, so it costs no parser stack — but it builds a tree
        // one node deep per term, and the partial tree is dropped on the error
        // path, which recurses. The bound that matters is on the tree, not the
        // parse, which is why it is a node count and not a loop counter.
        let terms = vec!["uint16(0) == 1"; 40_000].join(" or ");
        let src = format!("rule r {{ condition: {terms} }}");
        let e = err(&src);
        assert!(e.message.contains("too large"), "{e}");
    }

    #[test]
    fn a_long_but_plausible_chain_still_parses() {
        // The bound has to clear what real rules actually do: a few hundred
        // `or` terms selecting resource names is the largest condition shape in
        // the 10,764-rule set this parser is validated against.
        let terms = vec!["resource.name_string == \"1\"".to_string(); 500].join(" or ");
        let src = format!("rule r {{ condition: {terms} }}");
        let file = parse_file(&src).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(file.rules[0].condition, Expr::Or(_, _)));
    }

    #[test]
    fn a_deeply_nested_hex_alternative_is_refused() {
        let e = err(&format!(
            "rule r {{ strings: $a = {{ {}4D{} }} condition: $a }}",
            "(".repeat(200),
            ")".repeat(200)
        ));
        assert!(e.message.contains("nests too deeply"), "{e}");
    }
}
