//! The attribute certificate table: where Authenticode signatures live.
//!
//! # The record
//!
//! ```text
//! WIN_CERTIFICATE {
//!     DWORD dwLength;           -- the whole record, header included
//!     WORD  wRevision;          -- 0x0100 or 0x0200
//!     WORD  wCertificateType;   -- 0x0002 means PKCS#7 SignedData
//!     BYTE  bCertificate[dwLength - 8];
//! }
//! ```
//!
//! Records follow one another and each starts on an **eight-byte boundary**, so
//! `dwLength` is rounded up before advancing. Advancing by `dwLength` exactly
//! works for a single record and reads the next one's header from the middle of
//! its padding, which is the kind of error that only shows up on a file signed
//! twice — which is to say, on the files written to exploit it.
//!
//! # The padding is counted, and the blob has to be trimmed
//!
//! Measured over the 2363 records in an installed `System32`: every record
//! declared a `dwLength` that was a multiple of eight, and 2084 of them were
//! one to seven bytes longer than the PKCS#7 blob inside, with every one of
//! those bytes zero. So Windows writes the alignment padding *inside*
//! `dwLength` — which is the opposite of what the format's own description
//! says, and which means the body handed to the PKCS#7 reader is longer than
//! the DER it carries. That reader requires its blob to be consumed exactly, so
//! it refused every real signature and every signed file in the installation
//! read as unsigned. `without_padding` is the trim, and it accepts either
//! convention by measuring the element instead of trusting either length.
//!
//! # Why the length is not trusted
//!
//! `dwLength` comes from the file. A record claiming a length shorter than its
//! own header would make the advance run backwards and the walk never
//! terminate; one claiming more than the table holds would read past its end.
//! Both are checked before the value is used, and a record that fails is where
//! the walk stops rather than an error the caller has to handle: a table with a
//! good record followed by a malformed one still has a good record in it, and
//! the file it describes is still signed.
//!
//! # Why the certificates are flattened
//!
//! `pe.signatures[i]` indexes a *certificate*, not a signature. A file signed
//! twice has two `WIN_CERTIFICATE` records and each carries a PKCS#7 blob with
//! a chain of two to four certificates, and the corpus reads one certificate's
//! subject and issuer at the same index:
//!
//! ```text
//! for any i in ( 0 .. pe.number_of_signatures ) : (
//!     pe.signatures[i].issuer contains "DigiCert ..." and
//!     pe.signatures[i].serial == "0d:bf:15:..." )
//! ```
//!
//! Both members name the leaf — its issuer is the intermediate — so an index
//! that ranged over *records* would have one `serial` per index and no way to
//! also name the issuer of the same certificate. Flattening the chains into one
//! list is what makes that rule work, and `pe.number_of_signatures` counts
//! certificates for the same reason.

use av_pe::PeFile;

use crate::pkcs7;
use crate::x509::Certificate;

/// The revision numbers a `WIN_CERTIFICATE` may carry.
const REVISION_1_0: u16 = 0x0100;
/// The revision Authenticode 2.0 records use.
const REVISION_2_0: u16 = 0x0200;
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA`, the only type that holds a signature.
const TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
/// The size of the `WIN_CERTIFICATE` header.
const HEADER_LEN: usize = 8;
/// Records start on this boundary.
const ALIGNMENT: usize = 8;

/// Every certificate in a PE's attribute certificate table.
///
/// Empty when the file has no signature, which is the ordinary case and is not
/// an error — the caller is counting them.
pub fn certificates<'a>(pe: &PeFile<'a>) -> Vec<Certificate<'a>> {
    match pe.security_directory_data() {
        Ok(data) => from_table(data),
        Err(_) => Vec::new(),
    }
}

/// The certificates in a raw attribute certificate table.
///
/// Split from [`certificates`] so that the record walk can be tested against
/// bytes a test built, rather than against a whole PE image.
pub fn from_table<'a>(table: &'a [u8]) -> Vec<Certificate<'a>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + HEADER_LEN <= table.len() {
        let header = &table[at..at + HEADER_LEN];
        let length = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let revision = u16::from_le_bytes([header[4], header[5]]);
        let kind = u16::from_le_bytes([header[6], header[7]]);

        // A record shorter than its own header would make `at` go backwards and
        // the walk never end. This is the check that makes the loop terminate
        // on any input rather than only on well-formed input.
        if length < HEADER_LEN {
            break;
        }
        let Some(end) = at.checked_add(length) else {
            break;
        };
        let Some(body) = table.get(at + HEADER_LEN..end) else {
            break;
        };

        let revision_is_known = revision == REVISION_1_0 || revision == REVISION_2_0;
        if revision_is_known && kind == TYPE_PKCS_SIGNED_DATA {
            // A blob that does not parse contributes nothing, but the walk
            // continues: a second record further along is unaffected by this
            // one, and abandoning the table would lose it.
            if let Some(blob) = without_padding(body) {
                if let Ok(found) = pkcs7::certificates(blob) {
                    out.extend(found);
                }
            }
        }

        // The next record starts on an eight-byte boundary. Rounding up rather
        // than advancing by `length` is what makes a file signed twice readable
        // — and a file signed twice is what a written-to-exploit sample is.
        let padded = length.div_ceil(ALIGNMENT) * ALIGNMENT;
        match at.checked_add(padded) {
            Some(next) if next > at => at = next,
            _ => break,
        }
    }
    out
}

/// The PKCS#7 blob inside a record, with the record's alignment padding removed.
///
/// `dwLength` counts the padding. Measured over the 2363 records in an
/// installed `System32`, every one of them declared a length that was a
/// multiple of eight and 2084 of them were one to seven bytes longer than the
/// DER they carried, with every one of those bytes zero. The format's own
/// description says the opposite — that padding is not part of `dwLength` —
/// so a reader has to cope with both, and the only length that is true either
/// way is the element's own.
///
/// Handing the padded slice to [`pkcs7::certificates`] gets a refusal: that
/// reader requires the blob it is given to be consumed exactly, which is the
/// right requirement for a blob and the wrong one for a container. Before this
/// was trimmed, every real Windows signature in `System32` read as unsigned.
fn without_padding(body: &[u8]) -> Option<&[u8]> {
    let (_, encoded) = crate::der::parse_prefix(body).ok()?;
    let padding = body.get(encoded..)?;
    // At most the alignment's own rounding, and only zeros. A body longer than
    // its element by anything else is not the shape that was measured, and a
    // certificate read out of a record that is not that shape would be one this
    // crate invented.
    if padding.len() >= ALIGNMENT || padding.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(&body[..encoded])
}

/// The bytes of the first PKCS#7 record in a table, if there is one.
///
/// Exposed for a diagnostic that wants the blob itself rather than the
/// certificates in it.
pub fn first_blob(table: &[u8]) -> Option<&[u8]> {
    let mut at = 0usize;
    while at + HEADER_LEN <= table.len() {
        let header = &table[at..at + HEADER_LEN];
        let length = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let kind = u16::from_le_bytes([header[6], header[7]]);
        if length < HEADER_LEN {
            return None;
        }
        let end = at.checked_add(length)?;
        // A record whose body is malformed is stepped over rather than ending
        // the walk, the same as in `from_table`: the record after it is
        // unaffected by this one.
        if let Some(body) = table
            .get(at + HEADER_LEN..end)
            .and_then(without_padding)
            .filter(|_| kind == TYPE_PKCS_SIGNED_DATA)
        {
            if pkcs7::is_signed_data(body) {
                return Some(body);
            }
        }
        let padded = length.div_ceil(ALIGNMENT) * ALIGNMENT;
        at = at.checked_add(padded)?;
    }
    None
}

/// Whether a table's contents look like a signature this crate can read.
///
/// Used to tell "no signature" from "a signature that could not be parsed" in
/// a scan report, which are different things to a user looking at why a file
/// was or was not flagged.
pub fn is_parseable(table: &[u8]) -> bool {
    first_blob(table).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    /// One `WIN_CERTIFICATE` record wrapping `body`, the way Windows writes it.
    ///
    /// `dwLength` is rounded up to the alignment and the padding is counted
    /// inside it. That is what the measurement over `System32` says: 2363 of
    /// 2363 records declared a length that was a multiple of eight, and the
    /// ones that carried padding carried it within the declared length. So
    /// every test below hands a slightly-too-long body to `from_table`, which
    /// is the shape the reader used to refuse.
    fn record(body: &[u8], revision: u16, kind: u16) -> Vec<u8> {
        let padded = (HEADER_LEN + body.len()).div_ceil(ALIGNMENT) * ALIGNMENT;
        let mut out = record_body_verbatim(body, revision, kind, padded);
        out.resize(padded, 0);
        out
    }

    /// The same record with `dwLength` naming only the header and the body.
    ///
    /// The format's own description says the padding is *not* part of
    /// `dwLength`, and a record written that way leaves the padding outside the
    /// declared length instead of inside it. Both shapes are in the wild — only
    /// one of them is in this installation — and a reader that coped with one
    /// would step into the other's padding.
    fn record_with_unrounded_length(body: &[u8], revision: u16, kind: u16) -> Vec<u8> {
        record_body_verbatim(body, revision, kind, HEADER_LEN + body.len())
    }

    /// A record whose declared length is given rather than computed, so a test
    /// can write a length that disagrees with the body on purpose.
    fn record_body_verbatim(body: &[u8], revision: u16, kind: u16, declared: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&(declared as u32).to_le_bytes());
        out.extend_from_slice(&revision.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    fn signed_data(chain: &[Vec<u8>]) -> Vec<u8> {
        let certs = tlv(0xa0, &chain.concat());
        let data = seq(&[
            integer(1),
            set(&[algorithm()]),
            seq(&[oid(&[1, 2, 840, 113549, 1, 7, 1]), tlv(0xa0, &[])]),
            certs,
            set(&[]),
        ]);
        seq(&[oid(&[1, 2, 840, 113549, 1, 7, 2]), tlv(0xa0, &data)])
    }

    fn leaf() -> Vec<u8> {
        certificate(&[0x01], "Leaf", "110616000000Z", "140615000000Z")
    }

    #[test]
    fn one_record_yields_its_certificates() {
        let table = record(&signed_data(&[leaf()]), REVISION_2_0, TYPE_PKCS_SIGNED_DATA);
        let certs = from_table(&table);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Leaf");
    }

    #[test]
    fn a_second_record_is_found_past_the_first_ones_padding() {
        // The records are eight-byte aligned. A walk that advanced by
        // `dwLength` exactly would read the second header from inside the first
        // record's padding — which is a file signed twice, and a file signed
        // twice is what a crafted sample looks like.
        //
        // The first record here declares an unrounded length, so the padding
        // follows it in the buffer rather than being counted inside it. That is
        // the shape where the alignment matters to the walk; the other shape,
        // which is what Windows writes and what `record` builds, has nothing to
        // step over. Both are read, and both are built in this test.
        let mut table = record_with_unrounded_length(
            &signed_data(&[leaf()]),
            REVISION_2_0,
            TYPE_PKCS_SIGNED_DATA,
        );
        // `dwLength` as the record declares it — not the padded size the buffer
        // occupies. If the declared length is already a multiple of eight there
        // is no padding to step over and this test would pass against a walk
        // that ignored alignment entirely.
        let declared = u32::from_le_bytes([table[0], table[1], table[2], table[3]]) as usize;
        assert_ne!(
            declared % ALIGNMENT,
            0,
            "the fixture must actually need padding, or this proves nothing"
        );
        while table.len() % ALIGNMENT != 0 {
            table.push(0);
        }
        table.extend_from_slice(&record(
            &signed_data(&[certificate(
                &[0x02],
                "Second",
                "110616000000Z",
                "140615000000Z",
            )]),
            REVISION_2_0,
            TYPE_PKCS_SIGNED_DATA,
        ));
        let certs = from_table(&table);
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Leaf");
        assert_eq!(certs[1].subject().unwrap(), "/CN=Second");
    }

    #[test]
    fn the_padding_inside_a_declared_length_is_trimmed_before_the_blob_is_read() {
        // The regression for the bug that made every signed file in an
        // installation read as unsigned. `record` counts the alignment padding
        // inside `dwLength`, which is what Windows writes, so the body handed
        // to the PKCS#7 reader is longer than the DER it carries — and that
        // reader requires exact consumption.
        let blob = signed_data(&[leaf()]);
        let table = record(&blob, REVISION_2_0, TYPE_PKCS_SIGNED_DATA);
        let declared = u32::from_le_bytes([table[0], table[1], table[2], table[3]]) as usize;
        assert_eq!(
            declared % ALIGNMENT,
            0,
            "the fixture must count its padding, or this is the other shape"
        );
        assert!(
            declared - HEADER_LEN > blob.len(),
            "the fixture must carry padding, or there is nothing to trim"
        );
        let certs = from_table(&table);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Leaf");
    }

    #[test]
    fn padding_that_is_not_zero_is_refused_rather_than_read_through() {
        // A body longer than its element by anything but zero padding is not
        // the shape that was measured, and reading a certificate out of it
        // would be reading one this crate invented.
        let mut body = signed_data(&[leaf()]);
        let (_, encoded) = crate::der::parse_prefix(&body).unwrap();
        body.truncate(encoded);
        body.extend_from_slice(&[0xFF, 0xFE]);
        let table = record_body_verbatim(
            &body,
            REVISION_2_0,
            TYPE_PKCS_SIGNED_DATA,
            HEADER_LEN + body.len(),
        );
        assert!(from_table(&table).is_empty());
        assert!(first_blob(&table).is_none());
    }

    #[test]
    fn a_body_longer_than_its_element_by_a_whole_record_is_not_padding() {
        // Two extra bytes could be alignment. Sixty could not: the trim is
        // bounded by the alignment, so a record whose declared length is far
        // past its element is refused instead of read through to whatever
        // happens to follow.
        let mut body = signed_data(&[leaf()]);
        let (_, encoded) = crate::der::parse_prefix(&body).unwrap();
        body.truncate(encoded);
        body.resize(encoded + ALIGNMENT * 8, 0);
        let table = record_body_verbatim(
            &body,
            REVISION_2_0,
            TYPE_PKCS_SIGNED_DATA,
            HEADER_LEN + body.len(),
        );
        assert!(from_table(&table).is_empty());
    }

    #[test]
    fn a_record_whose_element_is_its_whole_body_still_yields_its_certificates() {
        // The other convention, and the one the format's description implies:
        // no padding inside the declared length at all. A trim written to
        // always cut something off would break this case.
        let blob = signed_data(&[leaf()]);
        let (_, encoded) = crate::der::parse_prefix(&blob).unwrap();
        assert_eq!(encoded, blob.len(), "the fixture has no padding to trim");
        let table = record_with_unrounded_length(&blob, REVISION_2_0, TYPE_PKCS_SIGNED_DATA);
        let certs = from_table(&table);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Leaf");
    }

    #[test]
    fn a_record_shorter_than_its_header_ends_the_walk_rather_than_looping() {
        // A length of 0 would make the advance zero and the walk never
        // terminate. This test finishing at all is the assertion.
        let mut table = record(&signed_data(&[leaf()]), REVISION_2_0, TYPE_PKCS_SIGNED_DATA);
        table.extend_from_slice(&[0, 0, 0, 0, 0x00, 0x02, 0x02, 0x00]);
        let certs = from_table(&table);
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn a_record_claiming_more_than_the_table_holds_ends_the_walk() {
        let table = [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00];
        assert!(from_table(&table).is_empty());
    }

    #[test]
    fn a_record_of_an_unknown_type_is_skipped_but_the_walk_continues() {
        let mut table = record(b"not a signature", REVISION_2_0, 0x0001);
        table.extend_from_slice(&record(
            &signed_data(&[leaf()]),
            REVISION_2_0,
            TYPE_PKCS_SIGNED_DATA,
        ));
        let certs = from_table(&table);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Leaf");
    }

    #[test]
    fn a_record_with_a_known_type_but_a_bad_blob_contributes_nothing() {
        let table = record(b"\x30\x05garbage", REVISION_2_0, TYPE_PKCS_SIGNED_DATA);
        assert!(from_table(&table).is_empty());
    }

    #[test]
    fn a_table_that_is_only_padding_yields_nothing() {
        assert!(from_table(&[0u8; 32]).is_empty());
        assert!(from_table(&[]).is_empty());
    }

    #[test]
    fn a_file_with_no_security_directory_has_no_certificates() {
        let data = av_pe::testing::minimal_pe32();
        let pe = PeFile::parse(&data).unwrap();
        assert!(certificates(&pe).is_empty());
    }

    #[test]
    fn a_signature_appended_to_a_real_pe_is_found_through_the_directory() {
        // The end-to-end path: header field to table to record to PKCS#7 to
        // certificate. Everything above tests one layer; this is the one that
        // fails if the security directory is read as an RVA instead of a file
        // offset, which is the mistake the format invites.
        let mut data = av_pe::testing::minimal_pe32();
        let table = record(&signed_data(&[leaf()]), REVISION_2_0, TYPE_PKCS_SIGNED_DATA);
        av_pe::testing::append_security_directory(&mut data, &table);

        let pe = PeFile::parse(&data).unwrap();
        let certs = certificates(&pe);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Leaf");
        assert_eq!(certs[0].serial(), "01");
        assert!(is_parseable(pe.security_directory_data().unwrap()));
    }

    #[test]
    fn the_first_blob_is_exposed_for_a_diagnostic() {
        let table = record(&signed_data(&[leaf()]), REVISION_2_0, TYPE_PKCS_SIGNED_DATA);
        assert!(first_blob(&table).is_some());
        assert!(first_blob(&[0u8; 16]).is_none());
    }
}
