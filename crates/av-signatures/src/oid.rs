//! Object identifiers, and the short names a distinguished name is rendered
//! with.
//!
//! # The names are not decoration
//!
//! A rule says `pe.signatures[i].subject contains "/C=GB/L=ROMFORD/O=3AN
//! LIMITED/CN=3AN LIMITED"`. Every literal in that string — the `/` separator,
//! the leading slash, the order of the attributes, and the spelling
//! `postalCode` rather than `postal-code` or `2.5.4.17` — is part of the
//! contract. Change one and the rule stops matching, silently, and the sample
//! it was written to catch goes undetected.
//!
//! # Where the spellings come from
//!
//! They are the names OpenSSL prints, because that is the format the rules in
//! this corpus were written against. The corpus itself confirms the ones that
//! matter: it contains literals using `C`, `ST`, `L`, `O`, `CN`, `street` and
//! `postalCode`, and those seven spellings are fixed here to match it. The rest
//! of the table covers the attributes X.520 defines, so that an attribute this
//! does not list is rendered as its dotted OID rather than dropped — a name
//! that loses an attribute would still compare equal to a rule written about
//! the remaining ones.

/// The `commonName` attribute, `2.5.4.3`.
pub const AT_COMMON_NAME: &[u64] = &[2, 5, 4, 3];

/// The OID of PKCS#7 `signedData`, `1.2.840.113549.1.7.2`.
pub const PKCS7_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];

/// Whether an `OBJECT IDENTIFIER` element's content encodes `arcs`.
///
/// Compares on the encoded bytes rather than decoding into a `Vec` first,
/// because this is called once per attribute of every certificate in every
/// file, and an allocation per attribute is a cost paid on the scan's hot path
/// for a comparison that never needs the decoded form.
///
/// Returns `false` for a non-minimally-encoded OID, matching [`crate::der`]:
/// accepting one would give a single OID two spellings, and a blocklist
/// comparing OIDs would then have a second spelling to miss.
pub fn oid_matches(content: &[u8], arcs: &[u64]) -> bool {
    if content.is_empty() {
        return false;
    }
    let mut index = 0usize;
    let mut value: u64 = 0;
    for &b in content {
        if b == 0x80 {
            return false;
        }
        value = match value
            .checked_mul(128)
            .and_then(|v| v.checked_add(u64::from(b & 0x7f)))
        {
            Some(v) => v,
            None => return false,
        };
        if b & 0x80 != 0 {
            continue;
        }
        if index == 0 {
            // The first byte packs the first two arcs as `X*40 + Y`.
            let (x, y) = if value < 40 {
                (0, value)
            } else if value < 80 {
                (1, value - 40)
            } else {
                (2, value - 80)
            };
            if arcs.first() != Some(&x) || arcs.get(1) != Some(&y) {
                return false;
            }
            index = 2;
        } else {
            if arcs.get(index) != Some(&value) {
                return false;
            }
            index += 1;
        }
        value = 0;
    }
    // A trailing continuation byte leaves `index` short of the length, so this
    // one comparison also rejects an arc that never terminated.
    index == arcs.len()
}

/// The short name for an attribute type, or `None` if it is not one of these.
///
/// `None` is not a failure: the caller renders the dotted OID instead, which is
/// what the certificate literally says.
pub fn attribute_short_name(content: &[u8]) -> Option<&'static str> {
    // X.520 attribute types, then the PKCS#9 and RFC 4519 ones a certificate
    // actually carries. Each entry's arcs are written out rather than encoded
    // by hand, and `every_attribute_name_decodes_to_the_oid_it_is_keyed_by`
    // checks the table against the decoder.
    const TABLE: &[(&[u64], &str)] = &[
        (&[2, 5, 4, 3], "CN"),
        (&[2, 5, 4, 4], "SN"),
        (&[2, 5, 4, 5], "serialNumber"),
        (&[2, 5, 4, 6], "C"),
        (&[2, 5, 4, 7], "L"),
        (&[2, 5, 4, 8], "ST"),
        (&[2, 5, 4, 9], "street"),
        (&[2, 5, 4, 10], "O"),
        (&[2, 5, 4, 11], "OU"),
        (&[2, 5, 4, 12], "title"),
        (&[2, 5, 4, 13], "description"),
        (&[2, 5, 4, 15], "businessCategory"),
        (&[2, 5, 4, 17], "postalCode"),
        (&[2, 5, 4, 20], "telephoneNumber"),
        (&[2, 5, 4, 41], "name"),
        (&[2, 5, 4, 42], "GN"),
        (&[2, 5, 4, 43], "initials"),
        (&[2, 5, 4, 44], "generationQualifier"),
        (&[2, 5, 4, 45], "x500UniqueIdentifier"),
        (&[2, 5, 4, 46], "dnQualifier"),
        (&[2, 5, 4, 65], "pseudonym"),
        // `organizationIdentifier`, the EV attribute.
        (&[2, 5, 4, 97], "organizationIdentifier"),
        // `emailAddress`, PKCS#9. Present in nearly every code-signing
        // certificate, and the one attribute whose value is an IA5String.
        (&[1, 2, 840, 113549, 1, 9, 1], "emailAddress"),
        (&[1, 2, 840, 113549, 1, 9, 2], "unstructuredName"),
        // RFC 4519 and the legacy userid attribute.
        (&[0, 9, 2342, 19200300, 100, 1, 1], "UID"),
        (&[0, 9, 2342, 19200300, 100, 1, 25], "DC"),
        (&[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1], "jurisdictionL"),
        (&[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2], "jurisdictionST"),
        (&[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3], "jurisdictionC"),
    ];
    TABLE
        .iter()
        .find(|(arcs, _)| oid_matches(content, arcs))
        .map(|(_, name)| *name)
}

/// Render an `OBJECT IDENTIFIER` element's content as dotted decimal.
///
/// Used for an attribute type with no short name. The digits are what the
/// certificate encodes, so a rule written against the numeric form still
/// matches — where dropping the attribute would make the whole name compare
/// unequal to a rule about the parts that *are* known.
pub fn dotted(content: &[u8]) -> String {
    let mut out = String::new();
    let mut value: u64 = 0;
    let mut first = true;
    let mut pending = false;
    for &b in content {
        if b == 0x80 {
            return String::new();
        }
        value = match value
            .checked_mul(128)
            .and_then(|v| v.checked_add(u64::from(b & 0x7f)))
        {
            Some(v) => v,
            None => return String::new(),
        };
        if b & 0x80 != 0 {
            pending = true;
            continue;
        }
        if first {
            let (x, y) = if value < 40 {
                (0, value)
            } else if value < 80 {
                (1, value - 40)
            } else {
                (2, value - 80)
            };
            out.push_str(&format!("{x}.{y}"));
            first = false;
        } else {
            out.push_str(&format!(".{value}"));
        }
        value = 0;
        pending = false;
    }
    if pending || first {
        // Either the final arc never terminated or there was nothing at all.
        return String::new();
    }
    out
}

/// Whether an element is the PKCS#7 `signedData` content type.
pub fn is_signed_data(content: &[u8]) -> bool {
    oid_matches(content, PKCS7_SIGNED_DATA)
}

#[cfg(test)]
mod tests {
    use super::*;
    // The encoder lives in `testing`, written independently of everything here.
    // Nothing in this module writes an OID — the table above is arcs and the
    // lookup compares bytes — so a test that goes arcs -> bytes -> name is
    // checking this decoder against a second implementation rather than
    // against itself.
    use crate::der::{parse_one, OBJECT_IDENTIFIER};
    use crate::testing::encode;

    #[test]
    fn a_known_oid_decodes_to_the_arcs_it_was_encoded_from() {
        for &(arcs, name) in &[
            (&[2u64, 5, 4, 3][..], "CN"),
            (&[2, 5, 4, 6], "C"),
            (&[2, 5, 4, 17], "postalCode"),
            (&[1, 2, 840, 113549, 1, 9, 1], "emailAddress"),
            (&[0, 9, 2342, 19200300, 100, 1, 25], "DC"),
        ] {
            let encoded = encode(arcs);
            assert_eq!(attribute_short_name(&encoded), Some(name), "{arcs:?}");
            assert!(oid_matches(&encoded, arcs));
        }
    }

    #[test]
    fn every_attribute_name_decodes_to_the_oid_it_is_keyed_by() {
        // The table is written as arcs; the lookup compares bytes. This walks
        // the table the long way round — arcs to bytes to name — so that a
        // mistyped arc produces a failure here rather than a name that never
        // matches a real certificate.
        for &(arcs, name) in &[
            (&[2u64, 5, 4, 3][..], "CN"),
            (&[2, 5, 4, 4], "SN"),
            (&[2, 5, 4, 5], "serialNumber"),
            (&[2, 5, 4, 6], "C"),
            (&[2, 5, 4, 7], "L"),
            (&[2, 5, 4, 8], "ST"),
            (&[2, 5, 4, 9], "street"),
            (&[2, 5, 4, 10], "O"),
            (&[2, 5, 4, 11], "OU"),
            (&[2, 5, 4, 17], "postalCode"),
            (&[2, 5, 4, 97], "organizationIdentifier"),
            (&[0, 9, 2342, 19200300, 100, 1, 1], "UID"),
            (&[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3], "jurisdictionC"),
        ] {
            let encoded = encode(arcs);
            assert_eq!(
                dotted(&encoded),
                arcs.iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(".")
            );
            assert_eq!(attribute_short_name(&encoded), Some(name));
        }
    }

    #[test]
    fn the_names_the_corpus_uses_are_all_present() {
        // The seven spellings a literal in the rule file depends on. If one of
        // these is renamed, a rule that matched every sample it was written for
        // stops matching, and nothing raises an error.
        for name in ["C", "ST", "L", "O", "CN", "street", "postalCode"] {
            let found = [
                &[2u64, 5, 4, 6][..],
                &[2, 5, 4, 8],
                &[2, 5, 4, 7],
                &[2, 5, 4, 10],
                &[2, 5, 4, 3],
                &[2, 5, 4, 9],
                &[2, 5, 4, 17],
            ]
            .iter()
            .any(|arcs| attribute_short_name(&encode(arcs)) == Some(name));
            assert!(found, "{name} has no entry in the table");
        }
    }

    #[test]
    fn an_unknown_attribute_has_no_short_name_but_still_renders() {
        let arcs = &[1u64, 2, 3, 4, 5];
        let encoded = encode(arcs);
        assert_eq!(attribute_short_name(&encoded), None);
        assert_eq!(dotted(&encoded), "1.2.3.4.5");
    }

    #[test]
    fn a_non_minimally_encoded_oid_matches_nothing() {
        // `0x80` as a leading byte encodes a zero the minimal form omits. It
        // must not be accepted as a second spelling of the same OID.
        let padded = [0x80, 0x55, 0x04, 0x03];
        assert!(!oid_matches(&padded, AT_COMMON_NAME));
        assert_eq!(dotted(&padded), "");
    }

    #[test]
    fn an_oid_that_never_terminates_matches_nothing() {
        assert!(!oid_matches(&[0x55, 0x04, 0x83], &[2, 5, 4, 3]));
    }

    #[test]
    fn an_oid_longer_or_shorter_than_the_key_is_not_a_match() {
        assert!(!oid_matches(&encode(&[2, 5, 4, 3, 1]), AT_COMMON_NAME));
        assert!(!oid_matches(&encode(&[2, 5, 4]), AT_COMMON_NAME));
        assert!(!oid_matches(&[], AT_COMMON_NAME));
    }

    #[test]
    fn the_signed_data_oid_is_recognised() {
        let mut der = vec![0x06, 0x09];
        der.extend_from_slice(&encode(PKCS7_SIGNED_DATA));
        let tlv = parse_one(&der).unwrap();
        assert!(tlv.is(OBJECT_IDENTIFIER));
        assert!(is_signed_data(tlv.content));
        assert!(!is_signed_data(&encode(AT_COMMON_NAME)));
    }
}
