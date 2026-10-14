//! The product's own files, recognised by digest.
//!
//! # The failure this exists to prevent, measured
//!
//! A rule is a description of bytes to look for, written down in a file that
//! contains those bytes. `$a = "CreateRemoteThread"` is a string in the corpus
//! and a string in the binary the rule is about, and a scanner that reads the
//! corpus finds the first one. Not "might find" — the corpus is *made* of the
//! patterns, so every literal rule matches its own source.
//!
//! Measured on the corpus this product ships — `yara-forge-extended-0.9.1.yar`,
//! 17.5 MB, 10,764 rules — scanning that one file produced **43 detections and
//! a `malicious` verdict**. The product convicted its own signature data. That
//! is not an exotic case either: the file sits in the source tree, in the
//! installation, in whatever directory a user unpacked a copy into, and behind
//! every one of those is a scan that a user can run and will.
//!
//! # Why a digest and not a path
//!
//! The product already refuses to scan its own *directories* —
//! [`av_core::AvPaths::is_protected`] — and that is the right answer for the
//! vault, the logs and the database in its installed place. It is the wrong
//! answer for a copy of a rule source, because a path is a claim about where a
//! file is and the question is what a file *is*. The same corpus in a build
//! tree, in `%ProgramData%`, in a backup and in a chat download folder is one
//! file in four places, and three of those four are outside every directory
//! this product owns.
//!
//! So the answer is content: SHA-256 of the file's bytes. The digests come from
//! [`RuleDatabase::sources`] and [`RuleDatabase::file_digest`], which is why
//! the database format carries them — see [`av_rules::database::RuleSource`].
//! A file that has a digest the database names is the product's own data,
//! wherever it is sitting, whatever it is called, and whoever put it there.
//!
//! # What this is not
//!
//! It is not the user's allowlist. A digest here is a statement about
//! provenance — this is the corpus this product was built from — and it is
//! checked before the file is examined. The user's allowlist
//! ([`TrustReason::UserAllowed`](crate::trust::TrustReason::UserAllowed)) is a
//! statement about intent, it is the user's to make, and it discounts a
//! detection that has already been made. The two never meet: this module is
//! consulted before any rule runs, and nothing here can be added to by a scan.
//!
//! It is also not a claim about the *product's executables*. A copy of
//! `wenle.exe` outside the installation is not recognised here, and would be
//! scanned like any other file. That is a real gap and it is left open
//! deliberately: the honest way to close it is for the installation to record
//! its own binaries' digests when it writes them, which is a job for the
//! installer, and inventing a second source of hashes in the engine would put
//! two answers where there is one question.

use std::collections::HashMap;

use av_core::{FileKind, FileScanReport};
use av_rules::database::RuleDatabase;

/// The rule identifier the engine attaches to the note it writes for a file it
/// recognised as the product's own.
///
/// A `pub const` rather than a literal in two places, because the identifier is
/// how a front end asks the question [`is_product_file`] answers, and a front
/// end holding a stale copy of the string would silently stop asking it.
pub const PRODUCT_FILE_RULE: &str = "scan/product-file";

/// The rule identifier the engine attaches to the note it writes for a file it
/// recognised as a rule source that this product did not write.
///
/// Distinct from [`PRODUCT_FILE_RULE`] because the two are different claims and
/// a front end says different things about them. This one is not the product's
/// data — it is somebody's rule file, and the report says so rather than
/// counting it among the product's own.
pub const RULE_SOURCE_RULE: &str = "scan/rule-source";

/// The rule identifier the engine attaches to the note it writes when it
/// declines a rule source it found *inside* a container rather than one
/// standing on its own.
///
/// # Why this is a third identifier and not the one above
///
/// Because the two notes are answers to two different questions, and a front
/// end asks one of them. [`RULE_SOURCE_RULE`] is a statement about the file: a
/// rule source, standalone, not examined. This one is a statement about
/// something the file *contained*: the file was opened and its members walked,
/// and one of those members is a rule corpus.
///
/// Sharing one identifier made the second fact answer the first question, and
/// the error ran in the direction that costs: a front end that files a report
/// under `Outcome::Source` on the strength of the note subtracts the whole file
/// from what it says it scanned. Measured on
/// `Rust-antivirus-main (1).zip` — 22.09 MiB, opened, walked, its code members
/// examined, and one nested member a compiled rule container — the scan
/// reported "1 rule source(s) this product did not write, not examined
/// (23,161,231 bytes), 0 scanned". Every number in that sentence is false about
/// that file, and the note that produced it was about a member 7.79 MB into it.
pub const RULE_SOURCE_MEMBER_RULE: &str = "scan/rule-source-member";

/// Whether a report is the engine saying it recognised the file and did not
/// examine it.
///
/// # Why a front end needs this and not just the verdict
///
/// Such a report is `Clean`, which is the same verdict as a file that was
/// examined and had nothing in it — and those two are the whole difference this
/// product is built around. A front end that adds them together prints a byte
/// total for reading that did not happen and a clean bill of health for a file
/// no rule was run against. This is the question that separates them, and it is
/// asked of the report rather than of the file because the report is the only
/// thing that knows the engine declined.
///
/// The test is on the rule identifier and not on `scanned_bytes == 0`, which
/// would also be true of an empty file, nor on the score, which an ordinary
/// clean file shares.
pub fn is_product_file(report: &FileScanReport) -> bool {
    notes(report, PRODUCT_FILE_RULE)
}

/// Whether a report is the engine saying it recognised the file as a rule
/// source it did not write.
///
/// Separate from [`is_product_file`] on purpose. Both are declines, and a front
/// end that reported them as one thing would be telling the user that a rule
/// file they downloaded is this product's own data, which is a different and
/// checkable statement.
///
/// # What this deliberately does not answer
///
/// Rule sources the engine declined *inside* the file — see
/// [`RULE_SOURCE_MEMBER_RULE`]. A container that held one was examined and the
/// count of what it declined is [`declined_members`]; this predicate stays
/// `false` for it, because the file is not a rule source.
pub fn is_foreign_rule_source(report: &FileScanReport) -> bool {
    notes(report, RULE_SOURCE_RULE)
}

/// Whether a report is the engine saying it declined a rule source it found
/// inside a container that it did examine.
///
/// True of a file whose members were walked and whose own contents were
/// scanned, one of the members being a rule corpus. A front end that treats
/// this like [`is_foreign_rule_source`] takes the whole file out of what it
/// says it examined, which is the defect [`RULE_SOURCE_MEMBER_RULE`] records.
pub fn is_foreign_rule_source_member(report: &FileScanReport) -> bool {
    declined_members(report) > 0
}

/// How many rule sources the engine declined inside this file.
///
/// A count and not a size, and that is not an oversight: the note is written
/// where the member's bytes are known but a [`Detection`](av_core::Detection)
/// carries no size, and the member's length is not a fact about the file's
/// anyway. What a report can honestly say is how many, and that is what a front
/// end prints — a byte total beside it would be a number about members standing
/// in a column of numbers about files.
pub fn declined_members(report: &FileScanReport) -> usize {
    report
        .assessment
        .detections
        .iter()
        .filter(|detection| detection.rule_id == RULE_SOURCE_MEMBER_RULE)
        .count()
}

/// Whether a report carries an informational note with this identifier.
fn notes(report: &FileScanReport, rule_id: &str) -> bool {
    report
        .assessment
        .detections
        .iter()
        .any(|detection| detection.rule_id == rule_id)
}

/// Whether a file is a rule source this product did not write, and how much of
/// one it is.
///
/// # Why the digest above is not enough, and this is not a duplicate of it
///
/// [`OwnFiles`] answers for the exact bytes this product compiled. The rule
/// files a scan actually meets are mostly not those bytes:
///
/// * a corpus downloaded from the project that publishes it, at a version this
///   product never compiled;
/// * a copy of our own corpus that the publisher has since edited, so the digest
///   is one byte different and the whitelist does not cover it;
/// * the near-copy this whole module was written because of — the old tree's
///   `yara-rules-extended.yar`, 17,506,017 bytes against our recorded
///   17,506,756, which a digest answers "no" to and which scans to **1,126
///   detections and a `malicious` verdict**;
/// * a rule file the user is writing.
///
/// Every one of those is a file made of the strings its own rules search for,
/// and every one of them produces a report that is wrong in the way that costs
/// the most: it names a malware family that is not there.
///
/// # The gate is on the kind, and it is what keeps this narrow
///
/// Only [`FileKind::Other`] is eligible. A PE, a .NET assembly, a script, a
/// document, an archive, an exploit carrier and a shortcut are each a thing that
/// can be *executed* or *opened* — the kinds a malware author writes — and none
/// of them may be talked out of a scan by being full of text that looks like
/// rules. A binary never reaches the density test at all: [`rule_source`]
/// refuses anything that is not UTF-8 or that holds a NUL byte, so a program
/// carrying a rule corpus in a resource is still scanned.
///
/// And an exact blocklist hit still fires. The engine asks this question only
/// when the blocklist had nothing to say, because a file whose digest is on the
/// blocklist has been named as a sample by something that knew more about it than
/// a lexical scan does. A rule file that is *itself* a known sample is not
/// exempt.
///
/// [`rule_source`]: av_rules::source::rule_source
pub fn foreign_rule_source(kind: &FileKind, data: &[u8]) -> Option<av_rules::source::RuleSource> {
    if *kind != FileKind::Other {
        return None;
    }
    av_rules::source::rule_source(data)
}

/// The files this product wrote, as the digests it knows about them.
///
/// Built from the rule database, which is the only thing in a scan that has
/// evidence about where anything came from: a database knows the sources it was
/// compiled from and it knows the file it was read from.
#[derive(Debug, Clone, Default)]
pub struct OwnFiles {
    /// SHA-256 (lowercase hex) to a description of what the file is, for the
    /// sentence a report prints.
    by_digest: HashMap<String, String>,
}

impl OwnFiles {
    /// Nothing known, which is the state of a scan whose database recorded no
    /// sources.
    ///
    /// Not an error and not a failure: a database compiled in memory from a
    /// string nobody kept has no sources to name, and the only cost is that the
    /// corpus is scanned like any other file. See
    /// [`RuleDatabase::with_sources`].
    pub fn new() -> Self {
        Self::default()
    }

    /// The files a rule database can name: its own sources, and the file it was
    /// read from.
    ///
    /// The database's own file is included because it is the same hazard in a
    /// different container — a `.avdb` is a compiled rule set, so it holds the
    /// literals too, and one copied to a desktop would otherwise be reported as
    /// the malware its own rules describe.
    pub fn from_database(database: &RuleDatabase) -> Self {
        let mut own = Self::new();
        for source in database.sources() {
            own.by_digest.insert(
                source.sha256.clone(),
                format!("the rule source `{}`", source.name),
            );
        }
        if let Some(digest) = database.file_digest() {
            own.by_digest.insert(
                digest.to_owned(),
                "this product's compiled rule database".to_owned(),
            );
        }
        own
    }

    /// Record one more file this product wrote.
    ///
    /// For a caller that knows about an artefact the database does not — a
    /// catalog index, in a front end that loaded one.
    pub fn insert(&mut self, sha256: impl Into<String>, what: impl Into<String>) {
        self.by_digest.insert(sha256.into(), what.into());
    }

    /// What this product knows a file with that digest to be, if anything.
    ///
    /// `None` is the ordinary answer for nearly every file a scan sees, and the
    /// only one that leads to the file being examined.
    pub fn describes(&self, sha256: &str) -> Option<&str> {
        self.by_digest.get(sha256).map(String::as_str)
    }

    /// How many files are recognised. For the report and for tests.
    pub fn len(&self) -> usize {
        self.by_digest.len()
    }

    /// Whether nothing is recognised at all.
    pub fn is_empty(&self) -> bool {
        self.by_digest.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{Assessment, Detection, DetectionSource, Digests, FileKind, Severity};
    use av_rules::database::RuleSource;

    const SOURCE: &str = r#"
rule marker {
  strings:
    $a = "WENLE_OWN_MARKER"
  condition:
    $a
}
"#;

    #[test]
    fn a_database_names_its_own_sources_and_its_own_file() {
        let bytes = SOURCE.as_bytes();
        let (database, _) = RuleDatabase::compile(SOURCE);
        let database = database.with_sources(vec![RuleSource::of("corpus.yar", bytes)]);
        let own = OwnFiles::from_database(&database);

        let digest = av_core::hash::HashKind::Sha256.digest(bytes);
        let what = own.describes(&digest).expect("the source is recognised");
        assert!(what.contains("corpus.yar"), "{what}");
    }

    #[test]
    fn a_database_compiled_from_a_string_recognises_nothing() {
        // The safe direction: no sources recorded means nothing is vouched
        // for, rather than everything.
        let (database, _) = RuleDatabase::compile(SOURCE);
        let own = OwnFiles::from_database(&database);
        assert!(own.is_empty(), "{:?}", own);
        assert_eq!(own.describes(&av_core::hash::HashKind::Sha256.digest(SOURCE.as_bytes())), None);
    }

    #[test]
    fn a_digest_that_differs_by_one_byte_is_not_recognised() {
        // The whole value of the mechanism is that it is an equality test over
        // content. A prefix match, a name match or a length match would each
        // recognise a file that is not the one that was compiled.
        let (database, _) = RuleDatabase::compile(SOURCE);
        let database = database.with_sources(vec![RuleSource::of("corpus.yar", SOURCE.as_bytes())]);
        let own = OwnFiles::from_database(&database);

        let mut altered = SOURCE.as_bytes().to_vec();
        altered.push(b'\n');
        assert_eq!(
            own.describes(&av_core::hash::HashKind::Sha256.digest(&altered)),
            None
        );
    }

    /// A file report carrying one informational note, or none at all.
    fn report_noting(rule_id: Option<&str>) -> FileScanReport {
        let mut assessment = Assessment::clean();
        if let Some(rule_id) = rule_id {
            assessment.push(Detection::new(
                rule_id,
                "a note",
                Severity::Info,
                DetectionSource::Heuristic,
            ));
        }
        FileScanReport {
            path: std::path::PathBuf::from("corpus.yar"),
            kind: FileKind::Other,
            size: SOURCE.len() as u64,
            digests: Digests::default(),
            assessment,
            duration: std::time::Duration::ZERO,
            scanned_bytes: 0,
            from_cache: false,
            error: None,
            archive: None,
        }
    }

    #[test]
    fn the_note_the_engine_writes_is_what_marks_a_file_as_the_products_own() {
        assert!(is_product_file(&report_noting(Some(PRODUCT_FILE_RULE))));
    }

    #[test]
    fn a_file_with_no_note_at_all_is_not_the_products_own() {
        // The direction that matters. A front end subtracts the files this
        // answers `true` for from what it says it scanned, so a predicate that
        // answered `true` too readily would take real files out of a report.
        assert!(!is_product_file(&report_noting(None)));
    }

    #[test]
    fn another_informational_note_does_not_mark_a_file_as_the_products_own() {
        // The engine writes informational notes for other reasons — a scan over
        // its byte budget writes one — and every one of them is a `Clean` verdict
        // with a detection in the list. Matching on "has a note" rather than on
        // which note would classify those files as the product's own data, which
        // is how a report ends up saying it examined less than it did.
        assert!(!is_product_file(&report_noting(Some("scan/over-budget"))));
    }

    #[test]
    fn the_two_declines_are_not_each_other() {
        // They are both `Clean` and both a decline, and a front end reports them
        // in different words: one is this product's data, the other is a rule
        // file the user has. Answering either question with `true` for the other
        // note is how a report comes to call a downloaded corpus our own.
        let own = report_noting(Some(PRODUCT_FILE_RULE));
        let foreign = report_noting(Some(RULE_SOURCE_RULE));
        assert!(is_product_file(&own) && !is_foreign_rule_source(&own));
        assert!(is_foreign_rule_source(&foreign) && !is_product_file(&foreign));
    }

    /// A file report carrying a member decline, as the archive walk writes it.
    fn report_declining_members(members: usize) -> FileScanReport {
        let mut report = report_noting(None);
        for i in 0..members {
            report.assessment.push(
                Detection::new(
                    RULE_SOURCE_MEMBER_RULE,
                    format!("the member `member-{i}.yarac` is a rule source"),
                    Severity::Info,
                    DetectionSource::Heuristic,
                )
                .within(format!("member-{i}.yarac")),
            );
        }
        report
    }

    #[test]
    fn a_member_decline_is_counted_and_is_not_a_statement_about_the_file() {
        // The defect this pair of predicates separates, as a test. An archive
        // holding one rule corpus is a file whose members were walked and whose
        // own bytes were scanned; the front end has to be able to ask "is this
        // file a rule source?" and be told no, while still being able to say how
        // many members were declined. One identifier for both answered the first
        // question yes, and the run then reported the whole archive as not
        // examined.
        let report = report_declining_members(1);
        assert_eq!(declined_members(&report), 1);
        assert!(is_foreign_rule_source_member(&report));
        assert!(!is_foreign_rule_source(&report), "a member note condemned the file");
        assert!(!is_product_file(&report));
    }

    #[test]
    fn the_member_count_is_every_member_and_not_merely_whether_there_was_one() {
        let report = report_declining_members(3);
        assert_eq!(declined_members(&report), 3);
    }

    #[test]
    fn a_file_with_no_declined_member_says_zero() {
        // The direction that matters for a summary line: a count that was
        // reported for every archive would put a number in front of a user that
        // describes nothing that happened.
        assert_eq!(declined_members(&report_noting(None)), 0);
        assert_eq!(declined_members(&report_noting(Some(RULE_SOURCE_RULE))), 0);
        assert!(!is_foreign_rule_source_member(&report_noting(None)));
    }

    /// The fixture `foreign_rule_source` is asked about, with a kind it can
    /// choose.
    fn source_text(rules: usize) -> String {
        let mut text = String::new();
        for i in 0..rules {
            text.push_str(&format!(
                "rule sample_{i} {{\n  strings:\n    $a = \"literal-{i}\"\n  \
                 condition:\n    $a\n}}\n"
            ));
        }
        text
    }

    #[test]
    fn a_rule_file_that_is_not_ours_is_recognised_as_one() {
        let found = foreign_rule_source(&FileKind::Other, source_text(16).as_bytes())
            .expect("a rule source");
        assert_eq!(found.rules, 16);
    }

    #[test]
    fn a_kind_that_can_be_executed_is_never_excused_by_being_text() {
        // The gate, and the reason it is on the kind rather than on the bytes.
        // A `.ps1` that is mostly rule text, a `.docm`, a `.zip`, a `.lnk`, a
        // `.pdf` — each is something the operating system will act on, and each
        // is a thing a rule corpus can be carried inside. The same bytes are
        // recognised as `Other` and refused as anything else.
        let bytes = source_text(32);
        assert!(foreign_rule_source(&FileKind::Other, bytes.as_bytes()).is_some());
        for kind in [
            FileKind::Pe,
            FileKind::DotNet,
            FileKind::Script,
            FileKind::Document,
            FileKind::Archive,
            FileKind::Exploit,
            FileKind::Shortcut,
            FileKind::Unknown,
        ] {
            assert_eq!(
                foreign_rule_source(&kind, bytes.as_bytes()),
                None,
                "{} was excused",
                kind.as_str()
            );
        }
    }

    #[test]
    fn an_ordinary_text_file_is_not_a_rule_source() {
        // The false-positive direction, on the kind this check is willing to
        // look at. A README, a config, a log — the files that make up most of
        // what a scan of a folder meets, and none of which may be taken out of
        // it.
        let prose = "The quick brown fox jumps over the lazy dog.\n".repeat(200);
        assert_eq!(foreign_rule_source(&FileKind::Other, prose.as_bytes()), None);
    }

    #[test]
    fn a_program_is_never_a_rule_source_whatever_its_kind_says() {
        // A PE header, mismatched with the kind a caller guessed from the
        // extension. The refusal has to come from the bytes as well: a file with
        // a `.txt` name and an `MZ` header is a program, and the extension is
        // the least reliable thing about it.
        let mut pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
        pe.extend_from_slice(source_text(32).as_bytes());
        assert_eq!(foreign_rule_source(&FileKind::Other, &pe), None);
    }
}
