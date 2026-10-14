//! A DER reader, sized to what a certificate actually needs.
//!
//! # Why this is not a general ASN.1 library
//!
//! There is no schema, no object model, no encoder. A certificate enters the
//! scanner as an array of bytes inside a file the scanner did not write, and
//! what it is asked for is a handful of fields. Everything else a general
//! library would provide is surface that would have to be fuzzed and would
//! never be called.
//!
//! What it does need is to be safe on hostile input, and the shape of that is
//! the same as everywhere else in this workspace: every length in a DER stream
//! is a number from the file, and the classic parser failure is to trust one.
//! [`Der`] returns a `Result` for every element and never indexes without a
//! bound, so there is no read that has not been checked.
//!
//! # What is rejected
//!
//! Indefinite lengths (`0x80`) are refused. They are legal BER, illegal DER,
//! and reading one means scanning for an end-of-contents marker, which makes
//! every nested read depend on a search that can itself be wrong. Windows
//! rejects them in certificates too.
//!
//! Non-minimal lengths are *accepted*, which is the opposite trade and
//! deliberate: `0x81 0x05` where `0x05` would do is also illegal DER, but
//! parsers in the wild emit it and Windows loads the result. A certificate
//! Windows treats as valid is one this has to read, or the scanner disagrees
//! with the operating system about what a file says.

use crate::error::SignatureError;

/// The tag number of a universal `SEQUENCE` or `SET`.
pub const SEQUENCE: u8 = 0x30;
/// The tag number of a universal `SET`, which is what a `SET OF` uses.
pub const SET: u8 = 0x31;
/// The tag number of a universal `INTEGER`.
pub const INTEGER: u8 = 0x02;
/// The tag number of a universal `BIT STRING`.
pub const BIT_STRING: u8 = 0x03;
/// The tag number of a universal `OCTET STRING`.
pub const OCTET_STRING: u8 = 0x04;
/// The tag number of a universal `OBJECT IDENTIFIER`.
pub const OBJECT_IDENTIFIER: u8 = 0x06;
/// The tag number of a universal `UTCTime`.
pub const UTC_TIME: u8 = 0x17;
/// The tag number of a universal `GeneralizedTime`.
pub const GENERALIZED_TIME: u8 = 0x18;
/// The tag number of a universal `BOOLEAN`.
pub const BOOLEAN: u8 = 0x01;
/// The tag number of a universal `NULL`.
pub const NULL: u8 = 0x05;
/// The tag number of a universal `PrintableString`.
pub const PRINTABLE_STRING: u8 = 0x13;
/// The tag number of a universal `UTF8String`.
pub const UTF8_STRING: u8 = 0x0c;
/// The tag number of a universal `IA5String`.
pub const IA5_STRING: u8 = 0x16;

/// The first tag byte of a context-specific element `[n]`, constructed.
///
/// `[0]` through `[30]` fit the short form, which is every context tag a
/// certificate uses. The long form is not reachable here and returns a tag no
/// comparison matches, so an element using it is skipped rather than misread.
pub const fn context(n: u8) -> u8 {
    0xa0 | (n & 0x1f)
}

/// The first tag byte of a context-specific element `[n]`, primitive.
pub const fn context_primitive(n: u8) -> u8 {
    0x80 | (n & 0x1f)
}

/// One tag-length-value element.
///
/// Holds a borrow of the content rather than a copy: a certificate is a slice
/// of the file being scanned, and a parse that copied would allocate once per
/// element for a structure that is read a few fields deep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The first tag byte. A multi-byte tag is reported by this byte alone,
    /// which is enough because nothing in a certificate uses one.
    pub tag: u8,
    /// The element's content, without its tag or length.
    pub content: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Whether this element has the given tag byte.
    pub fn is(&self, tag: u8) -> bool {
        self.tag == tag
    }

    /// Whether this element is context-specific tag `n`, constructed.
    pub fn is_context(&self, n: u8) -> bool {
        self.tag == context(n)
    }

    /// Whether this element is context-specific tag `n`, primitive.
    pub fn is_context_primitive(&self, n: u8) -> bool {
        self.tag == context_primitive(n)
    }

    /// The content as a nested sequence of elements.
    pub fn elements(&self) -> Der<'a> {
        Der::new(self.content)
    }

    /// The content, requiring this to be a constructed type.
    ///
    /// Used where the format says `SEQUENCE` and reading it as anything else
    /// would silently give back bytes that are not elements.
    pub fn sequence(&self) -> Result<Der<'a>, SignatureError> {
        if !is_constructed(self.tag) {
            return Err(SignatureError::NotConstructed { tag: self.tag });
        }
        Ok(self.elements())
    }

    /// The content of an `INTEGER`, with any leading zero bytes removed.
    ///
    /// DER encodes a signed integer big-endian, so a positive value whose top
    /// bit is set carries a leading `0x00` to keep it positive. That byte is
    /// part of the encoding and **not** part of the number — but it is part of
    /// the *serial string* a rule compares against, which is why
    /// [`Tlv::integer_bytes`] exists separately and why the two must not be
    /// confused.
    pub fn unsigned(&self) -> Result<u64, SignatureError> {
        let bytes = self.integer_bytes()?;
        let trimmed = trim_sign_byte(bytes);
        if trimmed.len() > 8 {
            return Err(SignatureError::IntegerTooLarge { len: trimmed.len() });
        }
        let mut value = 0u64;
        for &b in trimmed {
            value = (value << 8) | u64::from(b);
        }
        Ok(value)
    }

    /// The raw content bytes of an `INTEGER`, exactly as the file holds them.
    ///
    /// This is what the serial-number string is built from: the comparison a
    /// rule makes is against the encoded bytes, sign byte included, so
    /// trimming here would break every serial that has one.
    pub fn integer_bytes(&self) -> Result<&'a [u8], SignatureError> {
        if !self.is(INTEGER) {
            return Err(SignatureError::UnexpectedTag {
                wanted: INTEGER,
                found: self.tag,
            });
        }
        if self.content.is_empty() {
            return Err(SignatureError::EmptyInteger);
        }
        Ok(self.content)
    }

    /// The content of an `OBJECT IDENTIFIER` as its dotted arcs.
    ///
    /// Returned as numbers rather than a rendered string because the callers
    /// either compare against a known OID or render it themselves, and an
    /// allocation per OID for a certificate with a dozen of them is a cost with
    /// no payer.
    pub fn oid(&self) -> Result<Vec<u64>, SignatureError> {
        if !self.is(OBJECT_IDENTIFIER) {
            return Err(SignatureError::UnexpectedTag {
                wanted: OBJECT_IDENTIFIER,
                found: self.tag,
            });
        }
        let bytes = self.content;
        let mut arcs = Vec::new();
        let mut value: u64 = 0;
        let mut pending = false;
        for &b in bytes {
            // `0x80` continues an arc while contributing zero, which encodes a
            // leading zero the minimal form would not have. DER forbids it, and
            // accepting it would let two byte sequences mean one OID — so a
            // blocklist comparing OIDs would have a second spelling to miss.
            if b == 0x80 {
                return Err(SignatureError::BadOid);
            }
            value = value
                .checked_mul(128)
                .and_then(|v| v.checked_add(u64::from(b & 0x7f)))
                .ok_or(SignatureError::BadOid)?;
            if b & 0x80 == 0 {
                if arcs.is_empty() {
                    // The first byte packs the first two arcs: X*40 + Y.
                    let (x, y) = if value < 40 {
                        (0, value)
                    } else if value < 80 {
                        (1, value - 40)
                    } else {
                        (2, value - 80)
                    };
                    arcs.push(x);
                    arcs.push(y);
                } else {
                    arcs.push(value);
                }
                value = 0;
                pending = false;
            } else {
                pending = true;
            }
        }
        // A final byte with the continuation bit set means the last arc never
        // terminated.
        if pending {
            return Err(SignatureError::BadOid);
        }
        Ok(arcs)
    }

    /// The content of a `BIT STRING` with its unused-bits byte removed.
    pub fn bit_string(&self) -> Result<&'a [u8], SignatureError> {
        if !self.is(BIT_STRING) {
            return Err(SignatureError::UnexpectedTag {
                wanted: BIT_STRING,
                found: self.tag,
            });
        }
        // The first content byte says how many bits of the last byte are
        // unused. It is never zero-length; a BIT STRING with no content byte at
        // all is malformed.
        self.content
            .split_first()
            .map(|(_, rest)| rest)
            .ok_or(SignatureError::EmptyBitString)
    }

    /// The content of a `UTCTime` or `GeneralizedTime` as ASCII.
    ///
    /// Separate from [`Tlv::text`] because a time is not one of the string
    /// types a name uses: its tag is `0x17` or `0x18`, and a reader that
    /// accepted only `PrintableString` would refuse every validity date in
    /// every certificate ever issued.
    pub fn time_text(&self) -> Result<String, SignatureError> {
        if !matches!(self.tag, UTC_TIME | GENERALIZED_TIME) {
            return Err(SignatureError::UnexpectedTag {
                wanted: UTC_TIME,
                found: self.tag,
            });
        }
        Ok(String::from_utf8_lossy(self.content).into_owned())
    }

    /// The content of the string types a distinguished name uses.
    ///
    /// Decoded as UTF-8 lossily. DER allows several string types here —
    /// `PrintableString`, `UTF8String`, `T61String`, `BMPString` — and a
    /// certificate in the wild uses whichever its CA preferred. Only the two
    /// byte-oriented ones are decoded as text; `BMPString` is UTF-16 and would
    /// come back as interleaved NULs, which is why it is refused rather than
    /// guessed at. Nothing in the corpus needs it.
    pub fn text(&self) -> Result<String, SignatureError> {
        match self.tag {
            PRINTABLE_STRING | UTF8_STRING | IA5_STRING => {
                Ok(String::from_utf8_lossy(self.content).into_owned())
            }
            // `T61String` is close enough to Latin-1 that reading it as UTF-8
            // with replacement characters is better than refusing a whole
            // certificate over one attribute value.
            0x14 => Ok(String::from_utf8_lossy(self.content).into_owned()),
            _ => Err(SignatureError::UnexpectedTag {
                wanted: UTF8_STRING,
                found: self.tag,
            }),
        }
    }
}

/// Whether a tag byte marks a constructed type.
pub const fn is_constructed(tag: u8) -> bool {
    tag & 0x20 != 0
}

/// Drop a leading `0x00` that exists only to keep a positive integer positive.
fn trim_sign_byte(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        _ => bytes,
    }
}

/// A cursor over a run of DER elements.
///
/// Elements are yielded in order and the cursor stops cleanly at the end, so a
/// caller can read the fields it wants and ignore the rest — which is what
/// every caller here does, because a certificate's extensions are parsed by
/// nobody.
#[derive(Debug, Clone, Copy)]
pub struct Der<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Der<'a> {
    /// A cursor over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    /// Whether every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.at >= self.data.len()
    }

    /// How many bytes are left.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }

    /// The next element together with the bytes it occupies.
    ///
    /// The span is what a caller needs to hash or re-parse an element as a
    /// standalone document — a certificate's thumbprint is the SHA-1 of its
    /// complete encoding, tag and length included, so an element read without
    /// its header is not enough to compute it.
    pub fn next_with_span(&mut self) -> Option<Result<(Tlv<'a>, &'a [u8]), SignatureError>> {
        if self.is_empty() {
            return None;
        }
        let start = self.at;
        Some(self.read().map(|tlv| (tlv, &self.data[start..self.at])))
    }

    fn read(&mut self) -> Result<Tlv<'a>, SignatureError> {
        let start = self.at;
        let rest = &self.data[start..];
        let (&tag, after_tag) = rest
            .split_first()
            .ok_or(SignatureError::Truncated { at: start })?;

        // A tag number of 0x1f means the number continues into following
        // bytes. Nothing in a certificate uses one, and following it would mean
        // a second length-parsing path; the byte is reported as-is and
        // comparisons against it simply do not match.
        let (&first_len, after_len_byte) = after_tag
            .split_first()
            .ok_or(SignatureError::Truncated { at: start })?;

        let (content_len, header_len) = if first_len < 0x80 {
            (usize::from(first_len), 2usize)
        } else if first_len == 0x80 {
            return Err(SignatureError::IndefiniteLength { at: start });
        } else {
            let count = usize::from(first_len & 0x7f);
            // A length of more than eight bytes cannot describe a slice of any
            // real buffer, and reading one would overflow the shift below.
            if count > 8 {
                return Err(SignatureError::LengthTooLong { at: start, count });
            }
            let mut value: usize = 0;
            for &b in after_len_byte.iter().take(count) {
                value = (value << 8) | usize::from(b);
            }
            let header_len = 2 + count;
            (value, header_len)
        };

        let content_at = start
            .checked_add(header_len)
            .ok_or(SignatureError::Truncated { at: start })?;
        let end = content_at
            .checked_add(content_len)
            .ok_or(SignatureError::Truncated { at: start })?;
        let content = self
            .data
            .get(content_at..end)
            .ok_or(SignatureError::Truncated { at: start })?;
        self.at = end;
        Ok(Tlv { tag, content })
    }

    /// The next element, requiring it to have a particular tag.
    pub fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, SignatureError> {
        match self.next() {
            Some(Ok(tlv)) if tlv.is(tag) => Ok(tlv),
            Some(Ok(tlv)) => Err(SignatureError::UnexpectedTag {
                wanted: tag,
                found: tlv.tag,
            }),
            Some(Err(e)) => Err(e),
            None => Err(SignatureError::UnexpectedEnd { wanted: tag }),
        }
    }

    /// Skip `n` elements, however they are tagged.
    ///
    /// Named `skip_n` rather than `skip` so that it cannot be confused with
    /// [`Iterator::skip`], which returns a lazy adapter rather than advancing
    /// and can fail. Every use here is inside a parse that has to report a
    /// truncated buffer, and an adapter would swallow that.
    pub fn skip_n(&mut self, n: usize) -> Result<(), SignatureError> {
        for _ in 0..n {
            match self.next() {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => return Err(SignatureError::UnexpectedEnd { wanted: 0 }),
            }
        }
        Ok(())
    }
}

impl<'a> Iterator for Der<'a> {
    type Item = Result<Tlv<'a>, SignatureError>;

    /// The next element, or `None` at the end.
    ///
    /// The `Result` inside the `Option` is deliberate: "there is no next
    /// element" and "the next element is malformed" are different answers, and
    /// collapsing them would make a truncated certificate look like a
    /// certificate that simply ended.
    fn next(&mut self) -> Option<Self::Item> {
        self.next_with_span().map(|r| r.map(|(tlv, _)| tlv))
    }
}

/// Parse a buffer that holds exactly one element and return it.
///
/// Trailing bytes are refused: DER says a value is followed by nothing, and
/// accepting them would let a file carry a second, different structure after
/// the one that was parsed.
pub fn parse_one(data: &[u8]) -> Result<Tlv<'_>, SignatureError> {
    let mut der = Der::new(data);
    let tlv = match der.next() {
        Some(Ok(tlv)) => tlv,
        Some(Err(e)) => return Err(e),
        None => return Err(SignatureError::Empty),
    };
    if !der.is_empty() {
        return Err(SignatureError::TrailingBytes {
            count: der.remaining(),
        });
    }
    Ok(tlv)
}

/// Read the element at the front of `data`, and how many bytes it occupies.
///
/// [`parse_one`] requires the element to be the *whole* buffer, which is what a
/// blob handed to a parser should be. This is for the other case: a buffer that
/// is a container around the element and is allowed to be longer than it. The
/// caller gets the element and its exact size and decides for itself what the
/// rest is — which is a decision only the caller's format can make.
pub fn parse_prefix(data: &[u8]) -> Result<(Tlv<'_>, usize), SignatureError> {
    let mut der = Der::new(data);
    let tlv = match der.next() {
        Some(Ok(tlv)) => tlv,
        Some(Err(e)) => return Err(e),
        None => return Err(SignatureError::Empty),
    };
    Ok((tlv, data.len() - der.remaining()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_are_read_in_order() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let data = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let seq = parse_one(&data).unwrap();
        assert!(seq.is(SEQUENCE));
        let mut inner = seq.elements();
        assert_eq!(inner.expect(INTEGER).unwrap().unsigned().unwrap(), 1);
        assert_eq!(inner.expect(INTEGER).unwrap().unsigned().unwrap(), 2);
        assert!(inner.is_empty());
    }

    #[test]
    fn a_long_form_length_is_read_big_endian() {
        // A 300-byte OCTET STRING needs `0x82 0x01 0x2C`.
        let mut data = vec![0x04, 0x82, 0x01, 0x2c];
        data.resize(4 + 300, 0xAA);
        let tlv = parse_one(&data).unwrap();
        assert_eq!(tlv.content.len(), 300);
    }

    #[test]
    fn a_length_past_the_end_is_refused_rather_than_clamped() {
        // The header says 8 bytes but only 2 follow. Clamping would hand back a
        // shorter element than the file described, which is exactly how a
        // parser is made to read one field's bytes as another's.
        let data = [0x04, 0x08, 0xAA, 0xBB];
        assert!(matches!(
            parse_one(&data),
            Err(SignatureError::Truncated { .. })
        ));
    }

    #[test]
    fn an_indefinite_length_is_refused() {
        let data = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
        assert!(matches!(
            parse_one(&data),
            Err(SignatureError::IndefiniteLength { .. })
        ));
    }

    #[test]
    fn a_length_that_would_overflow_is_refused() {
        // Nine length bytes cannot describe anything, and shifting them into a
        // `usize` would wrap on a 32-bit target.
        let data = [0x04, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert!(matches!(
            parse_one(&data),
            Err(SignatureError::LengthTooLong { count: 9, .. })
        ));
    }

    #[test]
    fn trailing_bytes_after_the_value_are_refused() {
        let data = [0x02, 0x01, 0x01, 0xFF];
        assert!(matches!(
            parse_one(&data),
            Err(SignatureError::TrailingBytes { count: 1 })
        ));
    }

    #[test]
    fn parse_prefix_reports_the_size_of_the_element_it_read() {
        // The same three bytes `trailing_bytes_after_the_value_are_refused`
        // refuses. The element is the same element; what differs is that the
        // caller has said the rest of the buffer is its own business.
        let data = [0x02, 0x01, 0x01, 0xFF];
        let (tlv, size) = parse_prefix(&data).unwrap();
        assert_eq!(size, 3);
        assert_eq!(tlv.unsigned().unwrap(), 1);
        assert_eq!(&data[size..], &[0xFF]);
    }

    #[test]
    fn parse_prefix_counts_a_long_form_length_in_the_size() {
        // A 300-byte element costs four header bytes, so an encoded size that
        // assumed two would leave 298 bytes of the element itself looking like
        // something the container had added.
        let mut data = vec![0x04, 0x82, 0x01, 0x2c];
        data.resize(4 + 300, 0xAA);
        let (tlv, size) = parse_prefix(&data).unwrap();
        assert_eq!(tlv.content.len(), 300);
        assert_eq!(size, data.len());
    }

    #[test]
    fn parse_prefix_on_an_element_that_is_the_whole_buffer_agrees_with_parse_one() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x07];
        let (_, size) = parse_prefix(&data).unwrap();
        assert_eq!(size, data.len());
        assert_eq!(parse_one(&data).unwrap().content, &data[2..]);
    }

    #[test]
    fn parse_prefix_refuses_what_parse_one_refuses() {
        assert!(matches!(parse_prefix(&[]), Err(SignatureError::Empty)));
        assert!(matches!(
            parse_prefix(&[0x04, 0x08, 0xAA]),
            Err(SignatureError::Truncated { .. })
        ));
    }

    #[test]
    fn a_non_minimal_length_is_accepted() {
        // `0x81 0x01` where `0x01` would do is illegal DER, but parsers emit it
        // and Windows loads the certificate. Refusing would make the scanner
        // disagree with the operating system about what a file says.
        let data = [0x02, 0x81, 0x01, 0x2A];
        assert_eq!(parse_one(&data).unwrap().unsigned().unwrap(), 42);
    }

    #[test]
    fn an_integer_drops_its_sign_byte_for_arithmetic() {
        // `00 FF` is 255, not 255 with a leading zero.
        let data = [0x02, 0x02, 0x00, 0xFF];
        assert_eq!(parse_one(&data).unwrap().unsigned().unwrap(), 255);
    }

    #[test]
    fn an_integer_keeps_its_sign_byte_for_the_serial_string() {
        // The same element, read the way the serial-number string needs it.
        let data = [0x02, 0x02, 0x00, 0xFF];
        let tlv = parse_one(&data).unwrap();
        assert_eq!(tlv.integer_bytes().unwrap(), &[0x00, 0xFF]);
    }

    #[test]
    fn an_integer_too_large_for_a_u64_is_refused() {
        let data = [0x02, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert!(matches!(
            parse_one(&data).unwrap().unsigned(),
            Err(SignatureError::IntegerTooLarge { len: 9 })
        ));
    }

    #[test]
    fn an_empty_integer_is_refused() {
        let data = [0x02, 0x00];
        assert!(matches!(
            parse_one(&data).unwrap().integer_bytes(),
            Err(SignatureError::EmptyInteger)
        ));
    }

    #[test]
    fn an_oid_decodes_to_its_arcs() {
        // 2.5.4.3 is the `commonName` attribute type, and its encoding starts
        // with the packed first two arcs: 2*40+5 = 85 = 0x55.
        let data = [0x06, 0x03, 0x55, 0x04, 0x03];
        assert_eq!(parse_one(&data).unwrap().oid().unwrap(), vec![2, 5, 4, 3]);

        // 1.2.840.113549.1.7.2 — `signedData`. 840 and 113549 need the
        // continuation bit, so this exercises the multi-byte path.
        let data = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        ];
        assert_eq!(
            parse_one(&data).unwrap().oid().unwrap(),
            vec![1, 2, 840, 113549, 1, 7, 2]
        );
    }

    #[test]
    fn an_oid_that_never_terminates_is_refused() {
        // The last byte has the continuation bit set, so the final arc never
        // ends.
        let data = [0x06, 0x02, 0x55, 0x84];
        assert!(matches!(
            parse_one(&data).unwrap().oid(),
            Err(SignatureError::BadOid)
        ));
    }

    #[test]
    fn an_oid_whose_arc_would_overflow_is_refused() {
        let data = [
            0x06, 0x0b, 0x55, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(matches!(
            parse_one(&data).unwrap().oid(),
            Err(SignatureError::BadOid)
        ));
    }

    #[test]
    fn a_bit_string_drops_its_unused_bits_byte() {
        let data = [0x03, 0x03, 0x00, 0xAA, 0xBB];
        assert_eq!(
            parse_one(&data).unwrap().bit_string().unwrap(),
            &[0xAA, 0xBB]
        );
    }

    #[test]
    fn an_empty_bit_string_is_refused() {
        let data = [0x03, 0x00];
        assert!(matches!(
            parse_one(&data).unwrap().bit_string(),
            Err(SignatureError::EmptyBitString)
        ));
    }

    #[test]
    fn context_tags_are_recognised() {
        // [0] constructed is 0xA0; [3] primitive is 0x83.
        let data = [0xa0, 0x03, 0x02, 0x01, 0x01];
        assert!(parse_one(&data).unwrap().is_context(0));
        let data = [0x83, 0x01, 0x00];
        assert!(parse_one(&data).unwrap().is_context_primitive(3));
    }

    #[test]
    fn a_sequence_tag_read_as_a_sequence_is_fine_and_an_integer_is_not() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        assert!(parse_one(&data).unwrap().sequence().is_ok());
        let data = [0x02, 0x01, 0x01];
        assert!(matches!(
            parse_one(&data).unwrap().sequence(),
            Err(SignatureError::NotConstructed { tag: INTEGER })
        ));
    }

    #[test]
    fn a_truncated_header_is_refused() {
        assert!(matches!(
            parse_one(&[0x30]),
            Err(SignatureError::Truncated { .. })
        ));
        assert!(matches!(parse_one(&[]), Err(SignatureError::Empty)));
    }

    #[test]
    fn text_decodes_the_string_types_a_name_uses() {
        let data = [0x13, 0x02, b'O', b'K'];
        assert_eq!(parse_one(&data).unwrap().text().unwrap(), "OK");
        let data = [0x0c, 0x02, 0xC3, 0xA9];
        assert_eq!(parse_one(&data).unwrap().text().unwrap(), "é");
        // BMPString is UTF-16 and is refused rather than read as interleaved
        // NULs.
        let data = [0x1e, 0x02, 0x00, b'A'];
        assert!(parse_one(&data).unwrap().text().is_err());
    }

    #[test]
    fn a_deeply_nested_structure_stops_at_its_bounds() {
        // The reader must not run past the end of an inner sequence into
        // whatever follows it.
        let data = [
            0x30, 0x03, // outer, 3 bytes
            0x02, 0x01, 0x01, // inner INTEGER 1
            0x02, 0x01, 0x02, // this is outside the outer sequence
        ];
        let outer = parse_one(&data[..5]).unwrap();
        let mut inner = outer.elements();
        inner.expect(INTEGER).unwrap();
        assert!(inner.is_empty(), "the cursor must stop at the sequence end");
    }
}
