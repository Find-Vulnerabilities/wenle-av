//! Distinguished names, rendered the way the rules compare them.
//!
//! # The format is a contract, not a preference
//!
//! A rule in this corpus reads:
//!
//! ```text
//! pe.signatures[i].subject contains "/C=GB/postalCode=RM6 4DE/ST=ROMFORD/L=ROMFORD/street=8 Quarles Park Road/O=3AN LIMITED/CN=3AN LIMITED"
//! ```
//!
//! That literal fixes every choice this module makes: a leading `/`, `/`
//! between attributes, `NAME=value` with no spaces around the `=`, the
//! attribute spellings from [`crate::oid`], and the attributes in the order the
//! certificate encodes them. Seven other literals in the corpus depend on the
//! same shape, and the fifteen hundred `subject contains` rules that name only
//! a value — `contains "VANKY TECHNOLOGY LIMITED"` — depend on the value being
//! present verbatim.
//!
//! A comma-separated form was considered and rejected on the evidence: no
//! literal in the corpus contains `KEY=value, KEY=value`, so a format using
//! `, ` would make every one of those eight literals fail while matching
//! nothing that the slash form does not.
//!
//! # What is *not* escaped
//!
//! A value containing `/` or `+` is written through unchanged. OpenSSL's
//! `X509_NAME_oneline` — the format these literals were written against —
//! writes printable ASCII verbatim, and the corpus confirms it: a literal here
//! contains a space (`3AN LIMITED`) and a hyphen (`Gangnam-gu`), neither of
//! which would survive an escaping pass. Inventing an escape for the two
//! structural characters would produce a string no rule in this corpus expects,
//! which is a worse failure than the ambiguity it would resolve.
//!
//! # The two string types that are not what they look like
//!
//! `PrintableString` and `UTF8String` are read as UTF-8. `BMPString` is
//! **UTF-16 big-endian**, and reading its bytes as UTF-8 yields interleaved NUL
//! characters — a `CN` of `AB` would render as `A\0B\0` and match nothing.
//! It is converted properly here, because a CA that emits one is not doing
//! anything wrong and a rule naming that CA has to keep working.

use crate::der::{Tlv, OBJECT_IDENTIFIER, SEQUENCE, SET};
use crate::error::SignatureError;
use crate::oid;

/// The `BMPString` tag, whose content is UTF-16 big-endian.
const BMP_STRING: u8 = 0x1e;

/// Render a `Name` — a `SEQUENCE OF` relative distinguished name.
///
/// An empty name renders as the empty string rather than as `/`: a certificate
/// with an empty subject is legal (a CA certificate uses one to mean "any
/// subject"), and a bare `/` would be a value no rule expects.
pub fn render(name: &Tlv<'_>) -> Result<String, SignatureError> {
    let mut out = String::new();
    for rdn in name.sequence()? {
        let rdn = rdn?;
        // A relative distinguished name is a `SET OF`, and DER requires the
        // attributes inside it to be sorted. The order is read as written
        // rather than re-sorted: it is already canonical, and sorting again
        // would be a second opinion about a file that was checked once.
        if !rdn.is(SET) && !rdn.is(SEQUENCE) {
            return Err(SignatureError::BadName);
        }
        for (position, atv) in rdn.elements().enumerate() {
            let atv = atv?;
            let mut fields = atv.sequence()?;
            let kind = fields.expect(OBJECT_IDENTIFIER)?;
            let value = match fields.next() {
                Some(Ok(value)) => value,
                Some(Err(e)) => return Err(e),
                None => return Err(SignatureError::BadName),
            };
            // `+` joins the attributes of one multi-valued RDN, `/` separates
            // the RDNs. Getting these two the same would merge two attributes
            // into a pair of names that reads as neither.
            out.push(if position == 0 { '/' } else { '+' });
            match oid::attribute_short_name(kind.content) {
                Some(name) => out.push_str(name),
                None => out.push_str(&oid::dotted(kind.content)),
            }
            out.push('=');
            out.push_str(&value_text(&value));
        }
    }
    Ok(out)
}

/// A value as text, for the string types a name uses.
///
/// Falls back to `#` followed by hex for a value that is not a string at all.
/// That form is RFC 2253's, and it is chosen so the attribute is not silently
/// dropped: an attribute that vanishes would make the rendered name shorter
/// than the certificate's, and a rule comparing two attributes across a
/// separator would then see them adjacent and match a name that does not exist.
fn value_text(value: &Tlv<'_>) -> String {
    if value.is(BMP_STRING) {
        return utf16_be(value.content);
    }
    if let Ok(text) = value.text() {
        return text;
    }
    let mut out = String::with_capacity(value.content.len() * 2 + 1);
    out.push('#');
    for b in value.content {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode UTF-16 big-endian, replacing an unpaired surrogate.
fn utf16_be(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Read a `Name` from a buffer that holds exactly one.
#[cfg(test)]
pub fn render_one(data: &[u8]) -> Result<String, SignatureError> {
    render(&crate::der::parse_one(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{name, oid, printable, seq, set, tlv, utf8};

    /// Wrap already-built RDNs in the `SEQUENCE` a `Name` is.
    fn name_of(rdns: &[Vec<u8>]) -> Vec<u8> {
        seq(rdns)
    }

    /// One `AttributeTypeAndValue`, for the tests that need a string type other
    /// than `PrintableString`.
    fn atv(arcs: &[u64], value: Vec<u8>) -> Vec<u8> {
        seq(&[oid(arcs), value])
    }

    #[test]
    fn a_name_renders_with_a_leading_slash_and_slash_separators() {
        let der = name(&[
            (&[2, 5, 4, 6], printable("GB")),
            (&[2, 5, 4, 3], printable("3AN LIMITED")),
        ]);
        assert_eq!(render_one(&der).unwrap(), "/C=GB/CN=3AN LIMITED");
    }

    #[test]
    fn the_corpus_literal_is_reproduced_exactly() {
        // The one literal in the corpus that names several attributes, and the
        // reason the separator and the attribute spellings are what they are.
        let der = name(&[
            (&[2, 5, 4, 6], printable("GB")),
            (&[2, 5, 4, 17], printable("RM6 4DE")),
            (&[2, 5, 4, 8], printable("ROMFORD")),
            (&[2, 5, 4, 7], printable("ROMFORD")),
            (&[2, 5, 4, 9], printable("8 Quarles Park Road")),
            (&[2, 5, 4, 10], printable("3AN LIMITED")),
            (&[2, 5, 4, 3], printable("3AN LIMITED")),
        ]);
        assert_eq!(
            render_one(&der).unwrap(),
            "/C=GB/postalCode=RM6 4DE/ST=ROMFORD/L=ROMFORD/street=8 Quarles Park Road/O=3AN LIMITED/CN=3AN LIMITED"
        );
    }

    #[test]
    fn one_attribute_still_carries_the_leading_slash() {
        let der = name(&[(&[2, 5, 4, 3], printable("Atera Networks Ltd"))]);
        assert_eq!(render_one(&der).unwrap(), "/CN=Atera Networks Ltd");
    }

    #[test]
    fn an_empty_name_renders_as_the_empty_string() {
        // A CA certificate may carry an empty subject. A bare `/` would be a
        // value no rule expects, and `contains` would match it.
        let der = name_of(&[]);
        assert_eq!(render_one(&der).unwrap(), "");
    }

    #[test]
    fn a_multi_valued_rdn_joins_its_attributes_with_a_plus() {
        // One `SET` holding two `SEQUENCE`s, which is how a certificate encodes
        // two attributes that belong to the same RDN.
        let rdn = set(&[
            atv(&[2, 5, 4, 3], printable("A")),
            atv(&[2, 5, 4, 10], printable("B")),
        ]);
        let der = name_of(&[rdn]);
        assert_eq!(render_one(&der).unwrap(), "/CN=A+O=B");
    }

    #[test]
    fn a_bmp_string_is_decoded_as_utf16_rather_than_read_as_interleaved_nuls() {
        // `AB` in UTF-16BE is `00 41 00 42`. Read as UTF-8 that is
        // "\0A\0B", which compares equal to no rule literal.
        let rdn = set(&[atv(&[2, 5, 4, 3], tlv(0x1e, &[0x00, b'A', 0x00, b'B']))]);
        let der = name_of(&[rdn]);
        assert_eq!(render_one(&der).unwrap(), "/CN=AB");
    }

    #[test]
    fn a_utf8_value_survives_into_the_rendered_name() {
        // The corpus has rules whose literals are raw UTF-8 written as `\x`
        // escapes, so the bytes have to arrive unchanged.
        let value = "雷霆（武汉）信息技术有限公司";
        let rdn = set(&[atv(&[2, 5, 4, 3], utf8(value))]);
        let der = name_of(&[rdn]);
        assert_eq!(render_one(&der).unwrap(), format!("/CN={value}"));
    }

    #[test]
    fn an_attribute_with_no_short_name_renders_as_its_dotted_oid() {
        // Dropping it would make the name shorter than the certificate's and
        // could put two known attributes next to each other across a separator.
        let der = name(&[
            (&[2, 5, 4, 3], printable("A")),
            (&[1, 2, 3, 4], printable("B")),
            (&[2, 5, 4, 10], printable("C")),
        ]);
        assert_eq!(render_one(&der).unwrap(), "/CN=A/1.2.3.4=B/O=C");
    }

    #[test]
    fn a_name_that_is_not_a_sequence_is_refused() {
        let der = [0x02, 0x01, 0x01];
        assert!(render_one(&der).is_err());
    }

    #[test]
    fn a_truncated_name_is_refused_rather_than_partially_rendered() {
        // A name that rendered the attributes it managed to read would compare
        // `contains` successfully against a rule naming only those, which is a
        // match on a certificate the file did not contain.
        let der = name(&[(&[2, 5, 4, 3], printable("AB"))]);
        let truncated = &der[..der.len() - 2];
        assert!(render_one(truncated).is_err());
    }
}
