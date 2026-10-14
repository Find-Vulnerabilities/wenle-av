//! What is inside a file, scanned as if it were a file.
//!
//! # Where this sits
//!
//! Between the file's own stages and the verdict. The bytes of a container are
//! not interesting on their own — a zip of a hundred documents is a hundred
//! documents, and the file's own rules have nothing to say about the compressed
//! stream they are in. So this stage opens the container, produces each member,
//! and runs the same content stages over it that the engine runs over a file:
//! the same rule set, the same heuristics, the same blocklist.
//!
//! What it does *not* run is trust. Trust asks about a path, a signer and a
//! directory, and a member has none of those: it is a name inside somebody
//! else's file. The outer file's trust already ran, and it discounts the whole
//! assessment including everything found in here — which is the right scope,
//! because what a user trusts is the file on their disk.
//!
//! # Findings belong to the outer file, and say which member
//!
//! A member does not get a `FileScanReport` of its own. The report list is one
//! entry per file on disk, and every consumer — quarantine, statistics, exit
//! codes, progress — is built on that. So a member's detections are pushed into
//! the outer file's assessment, each carrying the chain of member names that
//! leads to it. That is what [`Detection::within`] is for, and it matters most
//! for the detections that have no locations at all: a structural rule matching
//! a PE header inside a zip reports where in the file it applies by saying which
//! member it was about.
//!
//! # A member that was not read is recorded, never passed over
//!
//! Every way a member can go unexamined produces an
//! [`av_core::ArchiveSkip`] on the summary, with the reason. The summary is what
//! a caller asks before calling the file clean, and
//! [`av_core::ArchiveSummary::is_complete`] is the question. This module never
//! decides that a skipped member is fine; it records the skip and lets the
//! caller decide what to say about it.

use av_archive::{ArchiveFormat, Container, ExpansionBudget};
use av_core::{ArchiveSummary, Detection, ScanOptions, Severity, SkipReason};
use av_rules::scanner::ScanOutcome;
use av_rules::vm::{Input, PeInput};

use crate::engine::ScanEngine;

/// What walking a container produced.
///
/// Not a [`FileScanReport`](av_core::FileScanReport): a container is a file, and
/// the file's own report is the one the engine builds. This is the part of it
/// that came from inside.
#[derive(Debug)]
pub(crate) struct ArchiveWalk {
    /// What was and was not examined. Always present, including for a container
    /// that could not be opened — see [`ArchiveSummary::unopened`].
    pub summary: ArchiveSummary,
    /// Findings from the members, strongest first.
    pub detections: Vec<Detection>,
}

/// Walk `data` as a container, if it is one and the options ask for it.
///
/// `None` means the file is not a container, or archive scanning is off — the
/// two cases a report shows identically because they mean the same thing about
/// this file: it was scanned as the single file it is. A file that *is* a
/// container and could not be opened is `Some` with
/// [`ArchiveSummary::unopened`] set, because that is a fact about the file and
/// not a setting.
pub(crate) fn walk<'e, 's, 'd>(
    engine: &'e ScanEngine,
    scanner: &'s mut av_rules::scanner::Scanner<'d>,
    data: &[u8],
    options: &ScanOptions,
) -> Option<ArchiveWalk> {
    if !options.archives || options.archive_depth == 0 {
        return None;
    }

    let mut budget =
        ExpansionBudget::new(options.archive_max_expansion, options.archive_max_expansion);
    let container = match Container::open(data, &mut budget) {
        Ok(Some(container)) => container,
        // Not a container at all. The ordinary answer for most files.
        Ok(None) => return None,
        Err(error) => {
            // A container this build recognises and cannot open. Falling back to
            // `None` here would make a password-protected 7z read as "scanned as
            // a single file, nothing found", which is the exact confusion this
            // whole type exists to prevent.
            let format = ArchiveFormat::detect(data)
                .map(ArchiveFormat::name)
                .unwrap_or("container");
            return Some(ArchiveWalk {
                summary: ArchiveSummary::unopened(format, error.to_string()),
                detections: Vec::new(),
            });
        }
    };

    let mut walk = Walk {
        engine,
        scanner,
        limits: Limits::from(options),
        budget,
        detections: Vec::new(),
    };
    let declared = container.declared_member_count();
    let mut summary = ArchiveSummary::new(container.format().name(), declared);
    walk.members(&container, "", 1, &mut summary);

    // Strongest first, and by rule within a severity, so that two runs over one
    // file produce the same report in the same order — the same ordering the
    // engine applies to the file's own rule detections.
    let mut detections = walk.detections;
    detections.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.container.cmp(&b.container))
    });
    Some(ArchiveWalk {
        summary,
        detections,
    })
}

/// The three settings a walk reads, copied out of the options.
///
/// Copied rather than borrowed so that this type does not carry a fourth
/// lifetime for a reference it reads three `bool`s and a `u8` through. The
/// options cannot change under a scan in any case — a scan takes `&ScanOptions`
/// — so a copy is the same answer with less plumbing.
#[derive(Debug, Clone, Copy)]
struct Limits {
    depth: u8,
    heuristics: bool,
}

impl From<&ScanOptions> for Limits {
    fn from(options: &ScanOptions) -> Self {
        Self {
            depth: options.archive_depth,
            heuristics: options.heuristics,
        }
    }
}

/// The state one walk carries down the recursion.
struct Walk<'e, 's, 'd> {
    engine: &'e ScanEngine,
    scanner: &'s mut av_rules::scanner::Scanner<'d>,
    limits: Limits,
    budget: ExpansionBudget,
    detections: Vec<Detection>,
}

impl Walk<'_, '_, '_> {
    /// Every member of `container`, at `depth`, inside `prefix`.
    ///
    /// `prefix` is the chain of enclosing member names, empty at the outermost
    /// container. A member's own report name is the prefix joined to its name,
    /// which is what makes `payload/inner.exe` and `outer.zip/inner.exe` read
    /// the way they do: the first is a file inside the scanned archive, the
    /// second is a file inside a member of it.
    fn members(
        &mut self,
        container: &Container<'_>,
        prefix: &str,
        depth: u8,
        summary: &mut ArchiveSummary,
    ) {
        let members = container.members();
        for (index, member) in members.iter().enumerate() {
            let chain = av_archive::name::join_chain(
                match prefix.is_empty() {
                    true => None,
                    false => Some(prefix),
                },
                &member.name,
            );

            // The reasons a member is refused *before* anything is read. Each is
            // cheaper than reading and each is a fact about the member rather
            // than about the scan, so deciding them here means a report says
            // "encrypted" rather than "the budget ran out while reading it".
            if member.name.is_empty() {
                summary.skip(&chain, SkipReason::Unnamed);
                continue;
            }
            if member.encrypted {
                summary.skip(&chain, SkipReason::Encrypted);
                continue;
            }
            if let Some(method) = &member.unreadable_method {
                summary.skip(
                    &chain,
                    SkipReason::Unsupported {
                        method: method.clone(),
                    },
                );
                continue;
            }
            if !self.budget.admits(member.declared_size) {
                // Two different claims, and the member's own declared size is
                // the one to make when it is the reason: a member the archive
                // says is enormous is refused on its own account, while a
                // member that no longer fits because of what came before it is
                // refused on the scan's.
                let reason = match member.declared_size > self.budget.max_member() {
                    true => SkipReason::TooLarge {
                        declared: member.declared_size,
                    },
                    false => SkipReason::Budget,
                };
                let spent = matches!(reason, SkipReason::Budget);
                summary.skip(&chain, reason);
                if spent {
                    summary.exhausted = true;
                }
                continue;
            }

            let extracted = match container.read(index, &mut self.budget) {
                Ok(extracted) => extracted,
                Err(error) => {
                    summary.skip(&chain, error.skip_reason());
                    if matches!(error, av_archive::ArchiveError::Budget { .. }) {
                        summary.exhausted = true;
                    }
                    continue;
                }
            };

            // A member that is itself a container. Decided from the member's
            // bytes rather than its name, for the same reason the outermost
            // container's was. Note that this branch is taken *before* the
            // member is counted as examined: a member this walk refuses to go
            // into was not examined, and counting it as both examined and
            // skipped is a summary that disagrees with itself.
            if let Some(format) = ArchiveFormat::detect(&extracted.bytes) {
                if depth >= self.limits.depth {
                    summary.skip(&chain, SkipReason::Depth);
                    continue;
                }
                if !format.is_readable() {
                    // A nested container of a format this build has no reader
                    // for — an `.tar.gz` holding a 7z, say. The member's own
                    // bytes were read, but what is inside them was not, and
                    // `leaves_contents_unknown` is the whole point of the skip.
                    summary.skip(
                        &chain,
                        SkipReason::Unsupported {
                            method: format.name().to_owned(),
                        },
                    );
                    continue;
                }
                match Container::open(&extracted.bytes, &mut self.budget) {
                    Ok(Some(inner)) => {
                        let declared = inner.declared_member_count();
                        let mut inner_summary =
                            ArchiveSummary::new(inner.format().name(), declared);
                        self.members(&inner, &chain, depth + 1, &mut inner_summary);
                        // The inner summary is not attached to the report — a
                        // report carries one summary per file on disk — so what
                        // it found is already a detection on this report with
                        // the chain naming where, and what it could not read is
                        // folded up so that "everything inside was examined"
                        // cannot be said while a nested member was skipped.
                        summary.fold_nested(&inner_summary);
                        summary.examined_member(extracted.bytes.len() as u64);
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        summary.skip(&chain, error.skip_reason());
                        if matches!(error, av_archive::ArchiveError::Budget { .. }) {
                            summary.exhausted = true;
                        }
                        continue;
                    }
                }
            }

            // A member that is a rule source. The same hazard as one standing
            // alone, and the file-level gate cannot reach in here: what the
            // engine classified is the container, and a zip is a zip. Without
            // this, a zip holding a rule corpus reports the corpus as the
            // malware its own rules describe — measured on the 38 MB compiled
            // `anti.yarac` a scan of a user's downloads turned up, where the
            // container and its only member both reached `Malicious` on one
            // signature.
            //
            // Placed above the `examined_member` below, and that placement is
            // the point of it: that call adds the member's bytes to the
            // summary's expanded total, and this member's bytes were not
            // scanned. `SkipReason` is deliberately not the mechanism here —
            // every variant of it asserts `leaves_contents_unknown`, and a rule
            // source's contents are known. This is the decline the engine
            // already makes for a rule source on disk, one level in.
            //
            // The identifier is the member one and not the file one, which is
            // load-bearing: this note is written into the *container's* report,
            // and a front end that reads it as "this file is a rule source"
            // subtracts the container from what it says it scanned. See
            // [`crate::own::RULE_SOURCE_MEMBER_RULE`] for the measurement.
            {
                let kind = crate::kind::classify(None, &extracted.bytes);
                if crate::own::foreign_rule_source(&kind, &extracted.bytes).is_some() {
                    self.detections.push(
                        info(
                            crate::own::RULE_SOURCE_MEMBER_RULE,
                            format!(
                                "The member `{chain}` is a rule source this product did not \
                                 compile. It was not examined: a rule source contains the very \
                                 strings its rules search for, so scanning one reports the \
                                 corpus as the malware it describes."
                            ),
                        )
                        .within(chain),
                    );
                    continue;
                }
            }

            summary.examined_member(extracted.bytes.len() as u64);

            if !extracted.verified {
                // The bytes are real — they came out of the file — but the
                // container's own check disagrees with them. Worth a line,
                // because either the file is damaged or it was altered after it
                // was built, and both are things a user should be told.
                self.detections.push(info(
                    "scan/archive-member-unverified",
                    format!(
                        "The member `{chain}` does not match the checksum its own archive \
                         records for it. Its contents were scanned, but the archive is either \
                         damaged or was modified after it was built.",
                    ),
                ));
            }

            self.content(&extracted.bytes, &chain);
        }
    }

    /// Run the content stages over one member.
    ///
    /// The same stages the engine runs over a file, minus trust and minus the
    /// verdict: a member's findings are findings about the outer file, and the
    /// verdict is decided once, over all of them together. No file kind is
    /// computed either — a report has one kind, for the file on disk, and
    /// overwriting it with a member's would make `invoice.zip` report as an
    /// executable.
    fn content(&mut self, data: &[u8], chain: &str) {
        // Parsed once and handed to both stages, exactly as the engine does for
        // the file's own bytes: a packed executable inside a zip deserves the
        // same structural judgement it would get standing alone.
        let image = PeInput::parse(data).ok();

        let outcome = match &image {
            Some(image) => self.scanner.scan_with(data, &Input::with_pe(data, image)),
            None => self.scanner.scan_with(data, &Input::new(data)),
        };
        for detection in self.rule_detections(&outcome, data) {
            self.detections.push(detection.within(chain));
        }

        if self.limits.heuristics {
            for detection in
                crate::heuristics::evaluate(data, image.as_ref(), self.engine.heuristics())
            {
                self.detections.push(detection.within(chain));
            }
        }
    }

    /// The detections a member's rule matches represent.
    ///
    /// The same conversion the engine applies, written here rather than shared
    /// because the one difference is the point: every location is re-based onto
    /// the member by [`Detection::within`].
    fn rule_detections(&self, outcome: &ScanOutcome, data: &[u8]) -> Vec<Detection> {
        outcome
            .reportable()
            .filter_map(|matched| {
                let rule = self.engine.database().rule(matched.rule)?;
                Some(crate::rules::detection(rule, matched, data))
            })
            .collect()
    }
}

/// A note recorded for something seen in a member. Scores nothing.
fn info(id: &str, description: impl Into<String>) -> Detection {
    Detection::new(
        id,
        description,
        Severity::Info,
        av_core::DetectionSource::Heuristic,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_rules::database::RuleDatabase;

    fn engine_with(source: &str) -> ScanEngine {
        let (database, report) = RuleDatabase::compile(source);
        assert_eq!(report.refusals.len(), 0, "{:?}", report.refusals);
        ScanEngine::new(database)
    }

    /// A zip holding one member, built as bytes.
    fn zip_of(name: &str, content: &[u8]) -> Vec<u8> {
        av_archive::testing::zip_deflate(&[(name, content)])
    }

    #[test]
    fn a_file_that_is_not_a_container_produces_nothing() {
        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let mut scanner = engine.scanner();
        assert!(walk(
            &engine,
            &mut scanner,
            b"MZ\x90\x00 not an archive",
            &ScanOptions::default()
        )
        .is_none());
    }

    #[test]
    fn archive_scanning_being_off_produces_nothing_even_for_a_container() {
        // The options decide, and the file being a zip does not override them.
        // This is what makes `realtime()` cheap.
        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let data = zip_of("payload.bin", b"nothing in particular");
        let mut scanner = engine.scanner();
        let off = ScanOptions {
            archives: false,
            ..ScanOptions::default()
        };
        assert!(walk(&engine, &mut scanner, &data, &off).is_none());

        let zero_depth = ScanOptions {
            archive_depth: 0,
            ..ScanOptions::default()
        };
        assert!(walk(&engine, &mut scanner, &data, &zero_depth).is_none());
    }

    #[test]
    fn a_member_is_scanned_and_its_finding_names_the_member() {
        let engine = engine_with(
            r#"
rule member_hit {
    meta:
        severity = "high"
    strings:
        $a = "WENLE-MEMBER-NEEDLE"
    condition:
        $a
}
"#,
        );
        let data = zip_of("payload.bin", b"....WENLE-MEMBER-NEEDLE....");
        let mut scanner = engine.scanner();
        let walk =
            walk(&engine, &mut scanner, &data, &ScanOptions::default()).expect("a container");

        assert_eq!(walk.summary.format, "zip");
        assert_eq!(walk.summary.declared, 1);
        assert_eq!(walk.summary.examined, 1);
        assert!(walk.summary.is_complete());

        let detection = walk.detections.first().expect("the member matched");
        assert_eq!(detection.rule_id, "member_hit");
        assert_eq!(detection.container.as_deref(), Some("payload.bin"));
        // The offset is into the member. `within` is what says so — without it a
        // reader would go looking at that offset in the zip, which is a
        // compressed stream and holds nothing of the sort.
        let location = detection.locations.first().expect("one location");
        assert_eq!(location.container.as_deref(), Some("payload.bin"));
        assert_eq!(location.preview, "WENLE-MEMBER-NEEDLE");
    }

    #[test]
    fn the_outer_file_is_not_itself_matched_by_what_is_inside_it() {
        // A rule for content that exists only inside the member. The member's
        // bytes are not the file's bytes, so a detection found here must be
        // attributed to the member — and there must be exactly one, not one for
        // the member and one for the whole file.
        let engine = engine_with(
            r#"
rule inside_only {
    strings:
        $a = "WENLE-ONLY-INSIDE"
    condition:
        $a
}
"#,
        );
        let data = zip_of("payload.bin", b"WENLE-ONLY-INSIDE");
        let mut scanner = engine.scanner();
        let walk =
            walk(&engine, &mut scanner, &data, &ScanOptions::default()).expect("a container");
        assert_eq!(walk.detections.len(), 1);
        assert_eq!(walk.detections[0].container.as_deref(), Some("payload.bin"));
    }

    #[test]
    fn a_nested_archive_reports_the_chain_of_names_that_leads_to_the_member() {
        let engine = engine_with(
            r#"
rule deep {
    strings:
        $a = "WENLE-DEEP-NEEDLE"
    condition:
        $a
}
"#,
        );
        let inner = zip_of("inner.bin", b"WENLE-DEEP-NEEDLE");
        let outer = zip_of("nested.zip", &inner);
        let mut scanner = engine.scanner();
        let walk =
            walk(&engine, &mut scanner, &outer, &ScanOptions::default()).expect("a container");

        let detection = walk.detections.first().expect("the inner member matched");
        assert_eq!(
            detection.container.as_deref(),
            Some("nested.zip/inner.bin"),
            "the chain names both levels, outermost first"
        );
        assert!(walk.summary.is_complete(), "{:?}", walk.summary);
    }

    #[test]
    fn a_nesting_limit_records_the_depth_rather_than_passing_the_member_over() {
        let engine = engine_with(
            r#"
rule deep {
    strings:
        $a = "WENLE-DEEP-NEEDLE"
    condition:
        $a
}
"#,
        );
        let inner = zip_of("inner.bin", b"WENLE-DEEP-NEEDLE");
        let outer = zip_of("nested.zip", &inner);
        let mut scanner = engine.scanner();
        let options = ScanOptions {
            archive_depth: 1,
            ..ScanOptions::default()
        };
        let walk = walk(&engine, &mut scanner, &outer, &options).expect("a container");

        // The inner archive was not entered, so nothing was found in it — and
        // the summary says why rather than reporting the outer archive clean.
        assert!(walk.detections.is_empty());
        assert!(!walk.summary.is_complete());
        assert_eq!(walk.summary.skipped_count(), 1);
        assert_eq!(walk.summary.skipped[0].reason, SkipReason::Depth);
        assert_eq!(walk.summary.skipped[0].member, "nested.zip");
    }

    /// A rule source this product did not compile, holding the needle below.
    ///
    /// Sixteen rules with distinct literals, which is the shape
    /// [`av_rules::source::rule_source`] recognises: a corpus, not a file that
    /// happens to mention a rule. The literal in each rule is a suffix of the
    /// one the engine's own rule searches for, so the engine's rule would fire
    /// on this member if the member were examined.
    fn foreign_corpus() -> String {
        let mut text = String::new();
        for i in 0..16 {
            text.push_str(&format!(
                "rule foreign_{i} {{\n  strings:\n    $a = \"WENLE-MEMBER-NEEDLE-{i}\"\n  \
                 condition:\n    $a\n}}\n"
            ));
        }
        text
    }

    #[test]
    fn a_rule_source_inside_a_container_is_declined_and_the_container_is_not() {
        // The measured defect, in miniature. The container is a zip: opened,
        // walked, its members accounted for. The member is a rule corpus, and
        // the corpus holds the strings its own rules search for, so examining
        // it convicts it — the engine's rule below fires on this member's text.
        //
        // What must not happen is the note about the member being read as a
        // statement about the file. That is what
        // `scan/rule-source-member` exists to prevent, and the two assertions
        // at the end are the ones a front end's coverage figures rest on.
        let engine = engine_with(
            r#"
rule member_hit {
    meta:
        severity = "high"
    strings:
        $a = "WENLE-MEMBER-NEEDLE"
    condition:
        $a
}
"#,
        );
        let corpus = foreign_corpus();
        let data = zip_of("corpus.yar", corpus.as_bytes());
        let mut scanner = engine.scanner();
        let walk =
            walk(&engine, &mut scanner, &data, &ScanOptions::default()).expect("a container");

        assert_eq!(walk.summary.declared, 1);
        assert_eq!(
            walk.summary.examined, 0,
            "a member that is a rule source is not examined"
        );
        assert_eq!(walk.summary.expanded, 0, "and its bytes are not counted as read");

        assert_eq!(walk.detections.len(), 1, "{:?}", walk.detections);
        let note = &walk.detections[0];
        assert_eq!(note.rule_id, "scan/rule-source-member");
        assert_eq!(note.container.as_deref(), Some("corpus.yar"));
        assert_eq!(note.severity, Severity::Info);
        assert!(
            note.description.contains("corpus.yar"),
            "the note names the member: {}",
            note.description
        );
    }

    #[test]
    fn a_container_holding_only_a_rule_source_is_a_file_that_was_examined() {
        // The same walk, read the way a front end reads it. The distinction
        // this asserts is the whole reason the member note has its own
        // identifier: `is_foreign_rule_source` answering `true` here subtracts
        // the container from the bytes a run says it examined, which is what
        // happened to a 22.09 MiB archive whose code members were in fact read.
        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let data = zip_of("corpus.yar", foreign_corpus().as_bytes());
        let report = engine.scan_bytes(
            std::path::Path::new("corpus.zip"),
            &data,
            &ScanOptions::default(),
        );

        assert_eq!(
            report.verdict(),
            av_core::Verdict::Clean,
            "{:?}",
            report.assessment
        );
        assert_eq!(
            crate::own::declined_members(&report),
            1,
            "the report says how many members it declined"
        );
        assert!(crate::own::is_foreign_rule_source_member(&report));
        assert!(
            !crate::own::is_foreign_rule_source(&report),
            "the container is not itself a rule source"
        );
        assert!(!crate::own::is_product_file(&report));
    }

    #[test]
    fn an_encrypted_member_is_recorded_rather_than_read_as_noise() {
        let engine = engine_with(
            r#"
rule anything {
    strings:
        $a = "WENLE"
    condition:
        $a
}
"#,
        );
        let mut member = av_archive::testing::FixtureMember::deflated("secret.bin", b"WENLE");
        member.flags |= 1; // the encrypted bit
        let data = av_archive::testing::zip_from_members(&[member], &[]);

        let mut scanner = engine.scanner();
        let walk =
            walk(&engine, &mut scanner, &data, &ScanOptions::default()).expect("a container");
        assert!(walk.detections.is_empty());
        assert!(!walk.summary.is_complete());
        assert_eq!(walk.summary.skipped[0].reason, SkipReason::Encrypted);
        assert_eq!(walk.summary.skipped[0].member, "secret.bin");
    }

    #[test]
    fn a_member_too_large_to_expand_is_refused_by_its_declared_size() {
        // The declared size is what makes a small file that expands hugely cost
        // nothing: it is refused before a byte is decompressed.
        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let content = vec![b'A'; 4096];
        let data = zip_of("big.bin", &content);
        let mut scanner = engine.scanner();
        let options = ScanOptions {
            archive_max_expansion: 1024,
            ..ScanOptions::default()
        };
        let walk = walk(&engine, &mut scanner, &data, &options).expect("a container");
        assert!(walk.detections.is_empty());
        assert!(!walk.summary.is_complete());
        // Refused on the member's own account, not the scan's, because the
        // budget was untouched when the decision was made.
        assert_eq!(
            walk.summary.skipped[0].reason,
            SkipReason::TooLarge { declared: 4096 }
        );
        assert!(!walk.summary.exhausted);
    }

    #[test]
    fn a_budget_spent_by_earlier_members_is_the_scans_reason_and_exhausts_the_walk() {
        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let big = vec![b'A'; 3000];
        let data = av_archive::testing::zip_deflate(&[("a.bin", &big), ("b.bin", &big)]);
        let mut scanner = engine.scanner();
        let options = ScanOptions {
            // Enough for one member, not two.
            archive_max_expansion: 4000,
            ..ScanOptions::default()
        };
        let walk = walk(&engine, &mut scanner, &data, &options).expect("a container");
        assert_eq!(walk.summary.examined, 1);
        assert!(!walk.summary.is_complete());
        assert_eq!(walk.summary.skipped[0].member, "b.bin");
        assert_eq!(walk.summary.skipped[0].reason, SkipReason::Budget);
        assert!(walk.summary.exhausted);
    }

    #[test]
    fn an_archive_this_build_cannot_open_says_so_and_is_not_reported_as_a_plain_file() {
        // The failure this guards: a 7z scans as "not a container", the report
        // shows no archive at all, and a user reads that as "nothing inside".
        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let seven_zip = b"7z\xbc\xaf\x27\x1c\x00\x04 and then some bytes";
        let mut scanner = engine.scanner();
        let walk = walk(&engine, &mut scanner, seven_zip, &ScanOptions::default())
            .expect("recognised as a container");
        assert_eq!(walk.summary.format, "7z");
        assert!(walk.summary.unopened.is_some());
        assert!(!walk.summary.is_complete());
        assert!(walk.detections.is_empty());
        assert!(walk.summary.describe().contains("could not be opened"));
    }

    #[test]
    fn a_malformed_zip_is_reported_as_a_failed_container_and_not_as_a_clean_file() {
        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let mut scanner = engine.scanner();
        let walk = walk(
            &engine,
            &mut scanner,
            b"PK\x03\x04 and then not really a zip at all",
            &ScanOptions::default(),
        )
        .expect("recognised as a container");
        assert_eq!(walk.summary.format, "zip");
        assert!(!walk.summary.is_complete());
    }

    #[test]
    fn a_note_about_an_unverified_member_scores_nothing() {
        // The note is [`Severity::Info`], which is zero, so a damaged archive
        // cannot push a file into a band on its own. Damage is worth saying and
        // is not evidence of malware.
        let note = info("scan/x", "y");
        assert_eq!(note.severity, Severity::Info);
        assert_eq!(note.score, 0);
    }

    #[test]
    fn within_moves_every_location_onto_the_member_and_keeps_its_offset() {
        // Stated directly, because `Detection::within` is what the whole
        // attribution rests on and a container test can only show one case. The
        // offset is not adjusted: it is an offset into the member, and the
        // container field is what says so.
        let detection =
            Detection::new("r", "d", Severity::Low, av_core::DetectionSource::Signature)
                .with_location(av_core::MatchLocation::new(16, 4, "$a", b"needle"))
                .with_location(av_core::MatchLocation::new(40, 4, "$b", b"nail"));
        let detection = detection.within("outer.zip/inner.bin");
        assert_eq!(detection.container.as_deref(), Some("outer.zip/inner.bin"));
        for location in &detection.locations {
            assert_eq!(location.container.as_deref(), Some("outer.zip/inner.bin"));
        }
        assert_eq!(detection.locations[0].offset, 16);
        assert_eq!(detection.locations[1].offset, 40);
    }

    #[test]
    fn a_member_finding_keeps_the_severity_and_score_the_rule_declared() {
        // The archive stage is a stage: it does not re-score anything. A rule
        // that declared a weight contributes that weight wherever it matched.
        let engine = engine_with(
            r#"
rule weighted {
    meta:
        severity = "high"
        weight = 120
    strings:
        $a = "WENLE-WEIGHTED"
    condition:
        $a
}
"#,
        );
        let data = zip_of("payload.bin", b"WENLE-WEIGHTED");
        let mut scanner = engine.scanner();
        let walk =
            walk(&engine, &mut scanner, &data, &ScanOptions::default()).expect("a container");
        let detection = walk.detections.first().expect("a hit");
        assert_eq!(detection.severity, Severity::High);
        assert_eq!(detection.score, 120);
    }

    #[test]
    fn a_member_of_a_readable_nested_archive_is_counted_at_its_own_level() {
        // The accounting this design exists for. The outer container has one
        // member, that member is a zip, and inside it one file is encrypted.
        // The outer walked its only member in full — so "1 of 1 examined" is
        // true — and the skip belongs to a level down, which is what
        // `nested_skipped` is for.
        let inner = av_archive::testing::zip_from_members(
            &[av_archive::testing::FixtureMember::deflated(
                "secret.bin",
                b"nothing",
            )],
            &[],
        );
        let data = av_archive::testing::zip_from_members(
            &[av_archive::testing::FixtureMember::deflated(
                "inner.zip",
                &inner,
            )],
            &[],
        );

        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let mut scanner = engine.scanner();
        let walk =
            walk(&engine, &mut scanner, &data, &ScanOptions::default()).expect("a container");

        assert_eq!(walk.summary.declared, 1);
        assert_eq!(walk.summary.examined, 1);
        assert_eq!(walk.summary.own_skipped_count(), 0);
        assert_eq!(walk.summary.skipped_count(), 0);
        // Nothing was skipped anywhere, so the archive is complete.
        assert!(walk.summary.is_complete());
    }

    #[test]
    fn a_skip_inside_a_nested_archive_makes_the_outer_one_incomplete_too() {
        // The same shape, except the inner archive's one member is encrypted.
        // The outer's own accounting is untouched and every count still adds up
        // — and the answer is still not "clean", because there is something
        // inside this file that nobody read.
        let inner = av_archive::testing::zip_from_members(
            &[av_archive::testing::FixtureMember::deflated(
                "secret.bin",
                b"nothing",
            )],
            &[],
        );
        // Flip the encrypted bit on the inner archive's member.
        let mut data = inner.clone();
        let cursor = data
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("a central directory");
        data[cursor + 8] |= 1;
        let inner = data;

        let data = av_archive::testing::zip_from_members(
            &[av_archive::testing::FixtureMember::deflated(
                "inner.zip",
                &inner,
            )],
            &[],
        );

        let engine = engine_with("rule r {\n strings:\n  $a = \"x\"\n condition:\n  $a\n}");
        let mut scanner = engine.scanner();
        let walk =
            walk(&engine, &mut scanner, &data, &ScanOptions::default()).expect("a container");

        assert!(!walk.summary.is_complete());
        assert_eq!(walk.summary.nested_skipped, 1);
        assert_eq!(walk.summary.own_skipped_count(), 0);
        // The name carries the chain, so nothing about where it is was lost.
        assert_eq!(walk.summary.skipped[0].member, "inner.zip/secret.bin");
        assert_eq!(walk.summary.skipped[0].reason, SkipReason::Encrypted);
    }
}
