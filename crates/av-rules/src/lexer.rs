//! Tokeniser for the AVRL rule language.
//!
//! The lexer is deliberately context-light: keywords are returned as ordinary
//! identifiers and resolved by the parser. That matters because AVRL — like
//! YARA — uses words such as `any`, `all`, `of` and `them` as operators, and a
//! rule author is perfectly entitled to name a string `$all`. Deciding what
//! `all` means from the surrounding tokens is the parser's job.
//!
//! The one genuinely context-sensitive case is `/`. A lone slash is a division
//! operator in a condition but opens a regex literal after `=`. The lexer
//! resolves it from the previous token: `/` directly after `=` starts a regex,
//! everywhere else it divides.

use std::fmt;

/// A token together with where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    /// Byte offset of the first character.
    pub start: u32,
    /// Byte offset one past the last character.
    pub end: u32,
    /// 1-based line, for diagnostics.
    pub line: u32,
    /// 1-based column, for diagnostics.
    pub column: u32,
}

impl Token {
    pub fn span(&self) -> crate::ast::Span {
        crate::ast::Span {
            start: self.start,
            end: self.end,
        }
    }

    /// True when this token is the identifier `word`.
    pub fn is_word(&self, word: &str) -> bool {
        matches!(&self.kind, TokenKind::Identifier(s) if s == word)
    }
}

/// What a token is.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    Identifier(String),
    /// A quoted string, already unescaped into raw bytes.
    Literal(Vec<u8>),
    /// The body of a `/.../ ` regex, without the slashes, plus flags.
    Regex {
        body: String,
        flags: String,
    },
    /// The raw inner text of a `{ ... }` hex pattern, un-tokenised.
    HexBlock(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),

    /// `$name` — the string matched.
    StringRef(String),
    /// `#name` — match count.
    CountRef(String),
    /// `@name` — match offset.
    OffsetRef(String),
    /// `!name` — match length.
    LengthRef(String),

    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Dot,
    /// `..` — an inclusive range.
    DotDot,
    Colon,
    Assign,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Shl,
    Shr,

    Eof,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Identifier(s) => write!(f, "`{s}`"),
            TokenKind::Literal(_) => f.write_str("a string literal"),
            TokenKind::Regex { .. } => f.write_str("a regex literal"),
            TokenKind::HexBlock(_) => f.write_str("a hex pattern"),
            TokenKind::Integer(i) => write!(f, "`{i}`"),
            TokenKind::Float(x) => write!(f, "`{x}`"),
            TokenKind::Boolean(b) => write!(f, "`{b}`"),
            TokenKind::StringRef(s) => write!(f, "`${s}`"),
            TokenKind::CountRef(s) => write!(f, "`#{s}`"),
            TokenKind::OffsetRef(s) => write!(f, "`@{s}`"),
            TokenKind::LengthRef(s) => write!(f, "`!{s}`"),
            TokenKind::LParen => f.write_str("`(`"),
            TokenKind::RParen => f.write_str("`)`"),
            TokenKind::LBracket => f.write_str("`[`"),
            TokenKind::RBracket => f.write_str("`]`"),
            TokenKind::LBrace => f.write_str("`{`"),
            TokenKind::RBrace => f.write_str("`}`"),
            TokenKind::Comma => f.write_str("`,`"),
            TokenKind::Dot => f.write_str("`.`"),
            TokenKind::DotDot => f.write_str("`..`"),
            TokenKind::Colon => f.write_str("`:`"),
            TokenKind::Assign => f.write_str("`=`"),
            TokenKind::Eq => f.write_str("`==`"),
            TokenKind::Ne => f.write_str("`!=`"),
            TokenKind::Lt => f.write_str("`<`"),
            TokenKind::Le => f.write_str("`<=`"),
            TokenKind::Gt => f.write_str("`>`"),
            TokenKind::Ge => f.write_str("`>=`"),
            TokenKind::Plus => f.write_str("`+`"),
            TokenKind::Minus => f.write_str("`-`"),
            TokenKind::Star => f.write_str("`*`"),
            TokenKind::Slash => f.write_str("`/`"),
            TokenKind::Percent => f.write_str("`%`"),
            TokenKind::Amp => f.write_str("`&`"),
            TokenKind::Pipe => f.write_str("`|`"),
            TokenKind::Caret => f.write_str("`^`"),
            TokenKind::Tilde => f.write_str("`~`"),
            TokenKind::Shl => f.write_str("`<<`"),
            TokenKind::Shr => f.write_str("`>>`"),
            TokenKind::Eof => f.write_str("end of input"),
        }
    }
}

/// A lexical error, carrying enough position information to point at the
/// offending character.
#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub message: String,
    pub line: u32,
    pub column: u32,
    pub offset: u32,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for LexError {}

/// Streaming tokeniser over a rule source.
#[derive(Debug)]
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    line_start: usize,
    /// True when the previous significant token promises a value next, which
    /// is what makes a following `/` a regex rather than a division.
    ///
    /// Two tokens do that: `=`, as in `$a = /re/`, and `matches`, as in
    /// `$a matches /re/`. Both are exact — `=` never appears in a condition
    /// (comparison is `==`), and `matches` is only ever a binary operator.
    value_expected: bool,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
            line_start: 0,
            value_expected: false,
        }
    }

    /// Tokenise the whole input.
    pub fn tokenize(mut self) -> Result<Vec<Token>, LexError> {
        let mut out = Vec::new();
        loop {
            let token = self.next_token()?;
            let is_eof = token.kind == TokenKind::Eof;
            out.push(token);
            if is_eof {
                return Ok(out);
            }
        }
    }

    fn column(&self, offset: usize) -> u32 {
        (offset.saturating_sub(self.line_start) + 1) as u32
    }

    fn error(&self, message: impl Into<String>, offset: usize) -> LexError {
        LexError {
            message: message.into(),
            line: self.line,
            column: self.column(offset),
            offset: offset as u32,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.src.get(self.pos + n).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.line_start = self.pos;
        }
        Some(b)
    }

    /// Skip whitespace and comments. Returns an error for an unterminated
    /// block comment.
    fn skip_trivia(&mut self) -> Result<(), LexError> {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.bump();
                }
                Some(b'/') if self.peek_at(1) == Some(b'/') => {
                    while let Some(b) = self.peek() {
                        if b == b'\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some(b'/') if self.peek_at(1) == Some(b'*') => {
                    let start = self.pos;
                    self.bump();
                    self.bump();
                    loop {
                        match self.peek() {
                            None => {
                                return Err(self.error("unterminated block comment", start));
                            }
                            Some(b'*') if self.peek_at(1) == Some(b'/') => {
                                self.bump();
                                self.bump();
                                break;
                            }
                            _ => {
                                self.bump();
                            }
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn make(&self, kind: TokenKind, start: usize) -> Token {
        Token {
            kind,
            start: start as u32,
            end: self.pos as u32,
            line: self.line,
            column: self.column(start),
        }
    }

    fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_trivia()?;
        let start = self.pos;
        let b = match self.peek() {
            None => return Ok(self.make(TokenKind::Eof, start)),
            Some(b) => b,
        };

        // Identifiers and keywords. `$`/`#`/`@`/`!` prefixes are handled below
        // because they introduce string references.
        if b.is_ascii_alphabetic() || b == b'_' {
            return Ok(self.lex_identifier(start));
        }

        if b.is_ascii_digit() {
            return self.lex_number(start);
        }

        match b {
            b'"' => self.lex_string(start),
            b'$' | b'#' | b'@' => self.lex_string_ref(start, b),
            // `!` is ambiguous: `!a` is the length of string `a`, but `!=` is
            // the inequality operator. Only the former is a string reference.
            b'!' if matches!(self.peek_at(1), Some(c) if c.is_ascii_alphanumeric() || c == b'_') => {
                self.lex_string_ref(start, b)
            }
            // `{` opens the rule body, but a `{` where a value is expected
            // opens a hex pattern. The same one-token lookback that
            // disambiguates `/` settles this too.
            b'{' if self.value_expected => self.lex_hex_block(start),
            b'/' if self.value_expected => self.lex_regex(start),
            _ => self.lex_operator(start, b),
        }
    }

    fn lex_identifier(&mut self, start: usize) -> Token {
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.bump();
            } else {
                break;
            }
        }
        let text = String::from_utf8_lossy(&self.src[start..self.pos]).into_owned();
        let kind = match text.as_str() {
            "true" => TokenKind::Boolean(true),
            "false" => TokenKind::Boolean(false),
            _ => TokenKind::Identifier(text),
        };
        // `matches` is the one identifier that promises a value: its right-hand
        // side is a regex literal, `$a matches /re/`.
        self.value_expected = matches!(&kind, TokenKind::Identifier(w) if w == "matches");
        self.make(kind, start)
    }

    fn lex_number(&mut self, start: usize) -> Result<Token, LexError> {
        // Hexadecimal.
        if self.peek() == Some(b'0') && matches!(self.peek_at(1), Some(b'x' | b'X')) {
            self.bump();
            self.bump();
            let digits_start = self.pos;
            while let Some(b) = self.peek() {
                if b.is_ascii_hexdigit() {
                    self.bump();
                } else {
                    break;
                }
            }
            if self.pos == digits_start {
                return Err(self.error("`0x` must be followed by hex digits", start));
            }
            let text = std::str::from_utf8(&self.src[digits_start..self.pos])
                .map_err(|_| self.error("invalid hex literal", start))?;
            let value = i64::from_str_radix(text, 16).map_err(|_| {
                self.error(
                    format!("hex literal `0x{text}` does not fit in 64 bits"),
                    start,
                )
            })?;
            self.value_expected = false;
            return Ok(self.make(TokenKind::Integer(value), start));
        }

        while matches!(self.peek(), Some(b) if b.is_ascii_digit() || b == b'_') {
            self.bump();
        }

        // Fractional part, but only when followed by a digit — `1..5` is a
        // range, not the float `1.`.
        let mut is_float = false;
        if self.peek() == Some(b'.') && matches!(self.peek_at(1), Some(b) if b.is_ascii_digit()) {
            is_float = true;
            self.bump();
            while matches!(self.peek(), Some(b) if b.is_ascii_digit() || b == b'_') {
                self.bump();
            }
        }

        // Size suffix: KB, MB, GB (base 1024, as YARA defines them). A suffix
        // is only a suffix when the `B` is actually there; `10X` is the integer
        // 10 followed by an identifier, not a scale factor.
        let mut multiplier: i64 = 1;
        if let Some(b) = self.peek() {
            let upper = b.to_ascii_uppercase();
            if matches!(upper, b'K' | b'M' | b'G') && matches!(self.peek_at(1), Some(b'B' | b'b')) {
                self.bump();
                self.bump();
                multiplier = match upper {
                    b'K' => 1024,
                    b'M' => 1024 * 1024,
                    _ => 1024 * 1024 * 1024,
                };
            }
        }

        let text: String = std::str::from_utf8(&self.src[start..self.pos])
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_ascii_alphabetic())
            .collect();
        let text = text.replace('_', "");

        self.value_expected = false;
        let kind = if is_float {
            let value: f64 = text
                .parse()
                .map_err(|_| self.error(format!("invalid float `{text}`"), start))?;
            TokenKind::Float(value)
        } else {
            let value: i64 = text
                .parse()
                .map_err(|_| self.error(format!("integer `{text}` is out of range"), start))?;
            TokenKind::Integer(value.saturating_mul(multiplier))
        };
        Ok(self.make(kind, start))
    }

    fn lex_string(&mut self, start: usize) -> Result<Token, LexError> {
        self.bump(); // opening quote
        let mut out = Vec::new();
        loop {
            let b = match self.bump() {
                None => return Err(self.error("unterminated string literal", start)),
                Some(b) => b,
            };
            match b {
                b'"' => break,
                b'\\' => {
                    let esc = self
                        .bump()
                        .ok_or_else(|| self.error("unterminated escape sequence", start))?;
                    match esc {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'0' => out.push(0),
                        b'\\' => out.push(b'\\'),
                        b'"' => out.push(b'"'),
                        b'\'' => out.push(b'\''),
                        b'x' => {
                            let hi = self
                                .bump()
                                .ok_or_else(|| self.error("`\\x` needs two hex digits", start))?;
                            let lo = self
                                .bump()
                                .ok_or_else(|| self.error("`\\x` needs two hex digits", start))?;
                            let hex = [hi, lo];
                            let text = std::str::from_utf8(&hex)
                                .map_err(|_| self.error("`\\x` needs two hex digits", start))?;
                            let value = u8::from_str_radix(text, 16).map_err(|_| {
                                self.error(format!("`\\x{text}` is not a valid byte escape"), start)
                            })?;
                            out.push(value);
                        }
                        other => {
                            return Err(self.error(
                                format!("unknown escape sequence `\\{}`", other as char),
                                start,
                            ));
                        }
                    }
                }
                other => out.push(other),
            }
        }
        self.value_expected = false;
        Ok(self.make(TokenKind::Literal(out), start))
    }

    /// `$name`, `#name`, `@name`, `!name`.
    ///
    /// `$` on its own is legal and means "the current string" inside a
    /// `for ... of` body.
    fn lex_string_ref(&mut self, start: usize, sigil: u8) -> Result<Token, LexError> {
        // `next_token` already peeked the sigil and passed it in, so consume it
        // here. Not a `\n`, so the line counter is untouched.
        debug_assert_eq!(self.peek(), Some(sigil));
        self.pos += 1;
        let name_start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'*' {
                self.bump();
            } else {
                break;
            }
        }
        let name = String::from_utf8_lossy(&self.src[name_start..self.pos]).into_owned();
        self.value_expected = false;
        let kind = match sigil {
            b'$' => TokenKind::StringRef(name),
            b'#' => {
                if name.is_empty() {
                    return Err(self.error("`#` must be followed by a string name", start));
                }
                TokenKind::CountRef(name)
            }
            b'@' => {
                if name.is_empty() {
                    return Err(self.error("`@` must be followed by a string name", start));
                }
                TokenKind::OffsetRef(name)
            }
            _ => {
                if name.is_empty() {
                    return Err(self.error("`!` must be followed by a string name", start));
                }
                TokenKind::LengthRef(name)
            }
        };
        Ok(self.make(kind, start))
    }

    /// A `/.../` regex literal. Flags after the closing slash are accepted for
    /// compatibility; only `i` (case-insensitive) is meaningful and it is
    /// folded into the compiled pattern.
    fn lex_regex(&mut self, start: usize) -> Result<Token, LexError> {
        self.bump(); // opening slash
        let mut body = String::new();
        loop {
            let b = match self.bump() {
                None => return Err(self.error("unterminated regex literal", start)),
                Some(b) => b,
            };
            match b {
                b'/' => break,
                // A newline inside a regex is almost always a missing closing
                // slash; failing here gives a far better message than letting
                // the regex engine report a syntax error later.
                b'\n' => return Err(self.error("unterminated regex literal", start)),
                b'\\' => {
                    body.push('\\');
                    let next = self
                        .bump()
                        .ok_or_else(|| self.error("unterminated regex escape", start))?;
                    body.push(next as char);
                }
                _ => body.push(b as char),
            }
        }
        let mut flags = String::new();
        while let Some(b) = self.peek() {
            if b.is_ascii_alphabetic() {
                flags.push(b as char);
                self.bump();
            } else {
                break;
            }
        }
        self.value_expected = false;
        Ok(self.make(TokenKind::Regex { body, flags }, start))
    }

    /// A `{ ... }` hex pattern. The body is captured verbatim and parsed by
    /// [`crate::hex`] — braces nest inside alternatives, so a plain
    /// character-level scan with a depth counter is simpler and less
    /// error-prone than tokenising here.
    fn lex_hex_block(&mut self, start: usize) -> Result<Token, LexError> {
        self.bump(); // opening brace
        let body_start = self.pos;
        let mut depth = 1usize;
        loop {
            let b = match self.bump() {
                None => return Err(self.error("unterminated hex pattern", start)),
                Some(b) => b,
            };
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        let body_end = self.pos - 1;
                        let body =
                            String::from_utf8_lossy(&self.src[body_start..body_end]).into_owned();
                        self.value_expected = false;
                        return Ok(self.make(TokenKind::HexBlock(body), start));
                    }
                }
                _ => {}
            }
        }
    }

    fn lex_operator(&mut self, start: usize, b: u8) -> Result<Token, LexError> {
        // Passed in by `next_token`, which already peeked it. No operator
        // contains a `\n`, so advancing by one is equivalent to `bump`.
        debug_assert_eq!(self.peek(), Some(b));
        self.pos += 1;
        let kind = match b {
            b'{' => TokenKind::LBrace,
            b'(' => TokenKind::LParen,
            b')' => TokenKind::RParen,
            b'[' => TokenKind::LBracket,
            b']' => TokenKind::RBracket,
            b'}' => TokenKind::RBrace,
            b',' => TokenKind::Comma,
            b':' => TokenKind::Colon,
            b'+' => TokenKind::Plus,
            b'-' => TokenKind::Minus,
            b'*' => TokenKind::Star,
            b'/' => TokenKind::Slash,
            b'%' => TokenKind::Percent,
            b'^' => TokenKind::Caret,
            b'~' => TokenKind::Tilde,
            b'.' => {
                if self.peek() == Some(b'.') {
                    self.bump();
                    TokenKind::DotDot
                } else {
                    TokenKind::Dot
                }
            }
            b'=' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    self.value_expected = false;
                    TokenKind::Eq
                } else {
                    self.value_expected = true;
                    TokenKind::Assign
                }
            }
            b'!' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::Ne
                } else {
                    return Err(self.error("`!` must be followed by a string name or `=`", start));
                }
            }
            b'<' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::Le
                } else if self.peek() == Some(b'<') {
                    self.bump();
                    TokenKind::Shl
                } else {
                    TokenKind::Lt
                }
            }
            b'>' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::Ge
                } else if self.peek() == Some(b'>') {
                    self.bump();
                    TokenKind::Shr
                } else {
                    TokenKind::Gt
                }
            }
            b'&' => TokenKind::Amp,
            b'|' => TokenKind::Pipe,
            other => {
                return Err(self.error(format!("unexpected character `{}`", other as char), start));
            }
        };
        if !matches!(kind, TokenKind::Assign) {
            self.value_expected = false;
        }
        Ok(self.make(kind, start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        Lexer::new(src)
            .tokenize()
            .expect("source should lex")
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    fn err(src: &str) -> LexError {
        Lexer::new(src).tokenize().expect_err("source should fail")
    }

    #[test]
    fn lexes_a_minimal_rule_skeleton() {
        let k = kinds("rule Foo : bar { condition: true }");
        assert_eq!(
            k,
            vec![
                TokenKind::Identifier("rule".into()),
                TokenKind::Identifier("Foo".into()),
                TokenKind::Colon,
                TokenKind::Identifier("bar".into()),
                TokenKind::LBrace,
                TokenKind::Identifier("condition".into()),
                TokenKind::Colon,
                TokenKind::Boolean(true),
                TokenKind::RBrace,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn string_reference_sigils_are_distinguished() {
        let k = kinds("$a #a @a !a $");
        assert_eq!(
            k,
            vec![
                TokenKind::StringRef("a".into()),
                TokenKind::CountRef("a".into()),
                TokenKind::OffsetRef("a".into()),
                TokenKind::LengthRef("a".into()),
                TokenKind::StringRef(String::new()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn inequality_is_not_mistaken_for_a_length_reference() {
        // `!a` is the length of `$a`; `!=` is comparison. They share a sigil.
        let k = kinds("$a != 0");
        assert_eq!(
            k,
            vec![
                TokenKind::StringRef("a".into()),
                TokenKind::Ne,
                TokenKind::Integer(0),
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn a_bare_bang_is_rejected() {
        assert!(err("$a ! 0").message.contains("`!`"));
    }

    #[test]
    fn hex_pattern_body_is_captured_verbatim() {
        let k = kinds("$a = { 4D 5A ?? [1-3] ( 41 | 42 ) }");
        assert_eq!(
            k,
            vec![
                TokenKind::StringRef("a".into()),
                TokenKind::Assign,
                TokenKind::HexBlock(" 4D 5A ?? [1-3] ( 41 | 42 ) ".into()),
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn slash_after_assign_opens_a_regex() {
        let k = kinds("$a = /ab+c/i");
        assert_eq!(
            k,
            vec![
                TokenKind::StringRef("a".into()),
                TokenKind::Assign,
                TokenKind::Regex {
                    body: "ab+c".into(),
                    flags: "i".into()
                },
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn slash_elsewhere_is_division() {
        let k = kinds("filesize / 2");
        assert_eq!(
            k,
            vec![
                TokenKind::Identifier("filesize".into()),
                TokenKind::Slash,
                TokenKind::Integer(2),
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn slash_after_matches_opens_a_regex() {
        // `matches` promises a value just as `=` does, so `/` there is a regex
        // and not a division. Without this, `$a matches /re/` lexed as a
        // division and could never be written.
        let k = kinds("$a matches /ab+c/i");
        assert_eq!(
            k,
            vec![
                TokenKind::StringRef("a".into()),
                TokenKind::Identifier("matches".into()),
                TokenKind::Regex {
                    body: "ab+c".into(),
                    flags: "i".into()
                },
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn an_identifier_is_only_a_value_promise_when_it_is_matches() {
        // A variable called `matcher` must not turn the next `/` into a regex.
        let k = kinds("matcher / 2");
        assert_eq!(
            k,
            vec![
                TokenKind::Identifier("matcher".into()),
                TokenKind::Slash,
                TokenKind::Integer(2),
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn integer_suffixes_scale_by_1024() {
        assert_eq!(kinds("1KB")[0], TokenKind::Integer(1024));
        assert_eq!(kinds("2MB")[0], TokenKind::Integer(2 * 1024 * 1024));
        assert_eq!(kinds("1GB")[0], TokenKind::Integer(1024 * 1024 * 1024));
    }

    #[test]
    fn a_bare_letter_after_a_number_is_not_a_suffix() {
        // `10X` must not be silently read as `10`.
        let k = kinds("10X");
        assert_eq!(k[0], TokenKind::Integer(10));
        assert_eq!(k[1], TokenKind::Identifier("X".into()));
    }

    #[test]
    fn hex_literals_and_underscores_parse() {
        assert_eq!(kinds("0x5A4D")[0], TokenKind::Integer(0x5A4D));
        assert_eq!(kinds("1_000_000")[0], TokenKind::Integer(1_000_000));
    }

    #[test]
    fn ranges_are_not_confused_with_floats() {
        let k = kinds("0..10");
        assert_eq!(
            k,
            vec![
                TokenKind::Integer(0),
                TokenKind::DotDot,
                TokenKind::Integer(10),
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn actual_floats_parse() {
        assert_eq!(kinds("1.5")[0], TokenKind::Float(1.5));
    }

    #[test]
    fn string_escapes_are_decoded() {
        let k = kinds(r#""a\n\t\x41\\""#);
        assert_eq!(k[0], TokenKind::Literal(b"a\n\tA\\".to_vec()));
    }

    #[test]
    fn comments_are_skipped() {
        let k = kinds("// line\n/* block */ 1");
        assert_eq!(k, vec![TokenKind::Integer(1), TokenKind::Eof]);
    }

    #[test]
    fn tracks_line_and_column() {
        let tokens = Lexer::new("rule\n  Foo").tokenize().unwrap();
        assert_eq!(tokens[0].line, 1);
        assert_eq!(tokens[1].line, 2);
        assert_eq!(tokens[1].column, 3);
    }

    #[test]
    fn unterminated_constructs_are_reported() {
        assert!(err(r#""abc"#).message.contains("unterminated string"));
        assert!(err("$a = { 4D 5A").message.contains("unterminated hex"));
        assert!(err("/* nope")
            .message
            .contains("unterminated block comment"));
        assert!(err("$a = /abc").message.contains("unterminated regex"));
    }

    #[test]
    fn unexpected_character_reports_position() {
        let e = err("rule ?");
        assert!(e.message.contains("unexpected character"), "got: {e}");
        assert_eq!(e.line, 1);
        assert_eq!(e.column, 6);
    }

    #[test]
    fn an_at_sign_must_name_a_string() {
        assert!(err("rule @").message.contains("`@`"));
    }

    #[test]
    fn a_brace_after_assign_is_a_hex_pattern_but_otherwise_opens_a_body() {
        // This is the ambiguity that makes `{` context-sensitive.
        assert!(matches!(kinds("$a = { 4D 5A }")[2], TokenKind::HexBlock(_)));
        assert_eq!(kinds("rule R { }")[2], TokenKind::LBrace);
        assert_eq!(kinds("rule R { }")[3], TokenKind::RBrace);
    }

    #[test]
    fn empty_source_yields_only_eof() {
        assert_eq!(kinds(""), vec![TokenKind::Eof]);
        assert_eq!(kinds("   \n\t "), vec![TokenKind::Eof]);
    }
}
