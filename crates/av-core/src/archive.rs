//! What a scan found when it opened a file as a container.
//!
//! # Why this is a report type and not a log line
//!
//! An archive is the one input where "nothing was found" and "nothing was
//! looked at" are easy to confuse, and where confusing them is expensive. A
//! password-protected zip is the standard way to walk a sample past a scanner,
//! and a scanner that opens it, fails, and reports the archive clean has not
//! been defeated by a clever trick — it has defeated itself. The same is true of
//! a member compressed with a method this build cannot read, of an archive
//! nested deeper than the configured limit, and of a walk that stopped because
//! the expansion budget ran out after two hundred members.
//!
//! So every member is accounted for. [`ArchiveSummary::examined`] plus
//! [`ArchiveSummary::skipped`] plus the directory entries the format itself
//! carries is the archive's own member count, and a member that is in neither
//! is a bug rather than a policy. Nothing downstream has to guess which of the
//! two happened, and a caller that wants to refuse to call a partly-examined
//! archive clean can ask [`ArchiveSummary::is_complete`].

use serde::{Deserialize, Serialize};

/// A member that was not examined, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveSkip {
    /// The member's name, as the archive spells it.
    pub member: String,
    /// Why it was left alone.
    pub reason: SkipReason,
}

impl ArchiveSkip {
    pub fn new(member: impl Into<String>, reason: SkipReason) -> Self {
        Self {
            member: member.into(),
            reason,
        }
    }

    /// One line for a report, in the form `name: reason`.
    pub fn describe(&self) -> String {
        format!("{}: {}", self.member, self.reason.describe())
    }
}

/// Why a member was left unexamined.
///
/// Every variant is a statement about *this* build or *this* scan, never about
/// the member's contents. That distinction is deliberate: a scanner is allowed
/// to say "I could not read this", and is not allowed to say "this is fine".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SkipReason {
    /// The member is encrypted. The bytes are there and this product will not
    /// guess the password, so what is inside is unknown — which is a fact worth
    /// reporting, because an archive that is encrypted for no reason a user can
    /// account for is itself worth a look.
    Encrypted,

    /// The member's compression method is one this build has no reader for.
    /// `method` names it as the archive does, because "unsupported" without
    /// saying what was unsupported is a message nobody can act on.
    Unsupported {
        /// The method, as the container spells it: `"deflate64"`, `"lzma"`,
        /// `"ppmd"`.
        method: String,
    },

    /// The expansion budget for this archive ran out before the member was
    /// reached. See [`ArchiveSummary::exhausted`].
    Budget,

    /// The archive is nested deeper than the configured limit allows. The
    /// member is itself a container; this scan stopped at its edge.
    Depth,

    /// The member is larger than this scan is willing to expand. Its declared
    /// size is the reason it was refused, so a small file that expands hugely
    /// is caught at the door rather than after the memory has been spent.
    TooLarge {
        /// The size the archive declares for the member, in bytes.
        declared: u64,
    },

    /// The member's header is malformed, or its data is not what its header
    /// claims. This is reported rather than treated as an error of the scan,
    /// because a container that disagrees with itself is a property of the
    /// container.
    Corrupt {
        /// What was wrong, phrased to follow a colon.
        detail: String,
    },

    /// The member carries no name. A zip entry with a zero-length name is legal
    /// and says nothing about its contents; it cannot be reported usefully and
    /// it is not worth guessing at.
    Unnamed,
}

impl SkipReason {
    /// A sentence fragment that reads after the member's name.
    pub fn describe(&self) -> String {
        match self {
            SkipReason::Encrypted => {
                "the member is password-protected, so its contents were not examined".into()
            }
            SkipReason::Unsupported { method } => format!(
                "the member is compressed with {method}, which this build has no reader for"
            ),
            SkipReason::Budget => {
                "the archive's expansion budget was exhausted before this member was reached".into()
            }
            SkipReason::Depth => {
                "the archive is nested deeper than the scan is configured to go".into()
            }
            SkipReason::TooLarge { declared } => format!(
                "the member declares {declared} bytes, above the size this scan will expand"
            ),
            SkipReason::Corrupt { detail } => format!("the member could not be read: {detail}"),
            SkipReason::Unnamed => "the member has no name".into(),
        }
    }

    /// True when the reason means the member's contents are unknown rather than
    /// known to be uninteresting.
    ///
    /// All of them do, which is the point of the type — it exists so that a
    /// caller cannot accidentally treat one of these as "looked at, fine". The
    /// method is here so that the intent is stated rather than assumed, and so
    /// that a future variant which *is* a conclusion has somewhere to say so.
    pub const fn leaves_contents_unknown(&self) -> bool {
        true
    }
}

/// What a scan did with a file it treated as a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveSummary {
    /// The format, as the reader named it: `"zip"`, `"gzip"`, `"tar"`.
    pub format: String,
    /// File members the container's own directory declares. Directory entries
    /// are not members and are not counted.
    pub declared: u32,
    /// File members that were opened and scanned.
    pub examined: u32,
    /// File members that were not, each with its reason.
    pub skipped: Vec<ArchiveSkip>,
    /// Total bytes of member content produced by this walk.
    pub expanded: u64,
    /// True when the walk stopped before the container was exhausted — a budget
    /// ran out, a nesting limit was reached, or the member count ceiling was
    /// hit. "Nothing was found in the first two hundred members" and "nothing
    /// was found" are different claims and a report that made them read the
    /// same would be lying about the second.
    pub exhausted: bool,

    /// How many of [`ArchiveSummary::skipped`] are members of a *nested*
    /// container rather than of this one.
    ///
    /// Kept separate because the two are not the same claim about the counts.
    /// This container examined the member an inner archive lives in; what the
    /// inner archive could not read is a fact one level down. Adding those to
    /// this container's own tally produces the arithmetic `1 of 1 members
    /// examined, 1 encrypted`, which is a line that contradicts itself, and a
    /// report whose own numbers do not add up is one a user stops reading.
    #[serde(default)]
    pub nested_skipped: u32,
    /// Why the container could not be opened at all, when it could not be.
    ///
    /// `Some` covers the case that would otherwise be indistinguishable from
    /// "not a container": the file's bytes identify it as an archive of a
    /// format this product knows, and opening it failed — a zip whose central
    /// directory is gone, a 7z this build has no reader for. That is a stronger
    /// statement than anything `declared` and `examined` can make, because those
    /// are both zero, and zero of zero reads as "nothing inside" when the truth
    /// is "nothing looked at".
    #[serde(default)]
    pub unopened: Option<String>,
}

impl ArchiveSummary {
    /// A summary for a container that was opened and nothing was taken from.
    pub fn new(format: impl Into<String>, declared: u32) -> Self {
        Self {
            format: format.into(),
            declared,
            examined: 0,
            skipped: Vec::new(),
            expanded: 0,
            exhausted: false,
            nested_skipped: 0,
            unopened: None,
        }
    }

    /// Take in everything a nested container could not read.
    ///
    /// The skips move up whole, names and all — the name carries the chain that
    /// says which archive and which member, so nothing is lost by flattening
    /// them into one list — and they are counted separately so that the reason
    /// counts stay readable against this container's own member tally.
    ///
    /// A nested walk that stopped early makes this one incomplete too. The
    /// members it never reached were never recorded as skips, so there is
    /// nothing here to fold; the flag is the only thing that carries it.
    pub fn fold_nested(&mut self, inner: &ArchiveSummary) {
        self.nested_skipped = self.nested_skipped.saturating_add(inner.skipped_count());
        self.skipped.extend(inner.skipped.iter().cloned());
        self.exhausted |= inner.exhausted;
        self.unopened = self.unopened.take().or_else(|| inner.unopened.clone());
    }

    /// A summary for a file that is an archive this scan could not open.
    ///
    /// `declared` is zero because nothing was read of it, and that is precisely
    /// why [`ArchiveSummary::unopened`] has to carry the reason: with no members
    /// counted and none skipped, this summary is complete by every arithmetic
    /// test and would say a report is clean about a file nobody opened.
    pub fn unopened(format: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            unopened: Some(reason.into()),
            ..Self::new(format, 0)
        }
    }

    /// Record a member that was scanned.
    pub fn examined_member(&mut self, bytes: u64) {
        self.examined = self.examined.saturating_add(1);
        self.expanded = self.expanded.saturating_add(bytes);
    }

    /// Record a member that was not.
    pub fn skip(&mut self, member: impl Into<String>, reason: SkipReason) {
        self.skipped.push(ArchiveSkip::new(member, reason));
    }

    /// How many members went unexamined.
    pub fn skipped_count(&self) -> u32 {
        self.skipped.len().min(u32::MAX as usize) as u32
    }

    /// True when every member this container declares was examined.
    ///
    /// The question a caller asks before calling the file inside it clean. Note
    /// that it is about the container only: a member that was examined and is
    /// itself a container has its own summary, and completeness does not
    /// recurse. A caller that needs the whole tree wants the scan to have
    /// refused the partial answers as it went, which is what
    /// [`ArchiveSummary::exhausted`] and the skip reasons are for.
    ///
    /// Four questions, and all four are needed. *Was it opened at all?* comes
    /// first, because a container that failed to open has nothing else to say
    /// and every question below it would answer "complete". *Was it skipped?*
    /// is the ordinary one. *Did the walk stop early?* covers the case where the
    /// members it never reached were never recorded either. *Was every member
    /// accounted for?* is the backstop for the state this type's module doc
    /// calls a bug: a summary that examined four of a declared six and recorded
    /// no reason for the other two is not a summary of a complete scan, it is a
    /// summary of a scanner that lost count — and the one answer it must not
    /// give is "clean".
    pub fn is_complete(&self) -> bool {
        self.unopened.is_none()
            && !self.exhausted
            && self.skipped.is_empty()
            && self.accounted_for_every_member()
    }

    /// How many of this container's *own* members went unexamined.
    ///
    /// Not [`ArchiveSummary::skipped_count`], which includes what a nested
    /// container could not read. Those live one level down and the member they
    /// live in was examined here.
    pub fn own_skipped_count(&self) -> u32 {
        self.skipped_count().saturating_sub(self.nested_skipped)
    }

    /// True when `examined` plus this container's own skips adds up to what it
    /// declared.
    fn accounted_for_every_member(&self) -> bool {
        self.examined.saturating_add(self.own_skipped_count()) >= self.declared
    }

    /// True when something was found inside, whatever its verdict.
    pub fn examined_anything(&self) -> bool {
        self.examined > 0
    }

    /// One line for a report: `zip: 12 of 14 members examined, 1 encrypted,
    /// 1 with a method this build cannot read`.
    ///
    /// Reads as a sentence rather than a table because it is printed under a
    /// finding, where there is room for one line and no room for a legend.
    pub fn describe(&self) -> String {
        // A container that never opened has no counts worth printing: "0 of 0
        // members examined" would be the whole line, and a reader would take it
        // for an empty archive. The reason is the line.
        if let Some(reason) = &self.unopened {
            return format!(
                "{}: this is a {} archive and it could not be opened: {reason}",
                self.format, self.format
            );
        }
        let mut out = format!(
            "{}: {} of {} {} examined",
            self.format,
            self.examined,
            self.declared,
            if self.declared == 1 {
                "member"
            } else {
                "members"
            },
        );
        if !self.skipped.is_empty() {
            let mut counts: Vec<(String, u32)> = Vec::new();
            for skip in &self.skipped {
                let label = skip.reason.summary_label();
                match counts.iter_mut().find(|(l, _)| *l == label) {
                    Some((_, n)) => *n = n.saturating_add(1),
                    None => counts.push((label, 1)),
                }
            }
            let parts: Vec<String> = counts
                .into_iter()
                .map(|(label, n)| format!("{n} {label}"))
                .collect();
            out.push_str(", ");
            out.push_str(&parts.join(", "));
            if self.nested_skipped > 0 {
                // Says where the skips above live, because the reason counts
                // read against this container's member tally and the two do not
                // line up once a nested archive contributes to them.
                out.push_str(&format!(
                    " ({n} of them inside nested archives)",
                    n = self.nested_skipped
                ));
            }
        }
        if self.exhausted {
            out.push_str("; the walk stopped before the container was exhausted");
        } else if !self.accounted_for_every_member() {
            // Members that are neither examined nor skipped, with no reason
            // recorded for the gap. Not a policy — a caller that stopped a walk
            // early is supposed to set `exhausted` or record skips — so this
            // says what is true rather than inventing a benign explanation for
            // it.
            out.push_str("; not every member was accounted for");
        }
        out
    }
}

impl SkipReason {
    /// A few words naming this reason, for the counts in
    /// [`ArchiveSummary::describe`].
    fn summary_label(&self) -> String {
        match self {
            SkipReason::Encrypted => "encrypted".into(),
            SkipReason::Unsupported { .. } => "in an unsupported format".into(),
            SkipReason::Budget => "past the expansion budget".into(),
            SkipReason::Depth => "nested too deeply".into(),
            SkipReason::TooLarge { .. } => "too large to expand".into(),
            SkipReason::Corrupt { .. } => "unreadable".into(),
            SkipReason::Unnamed => "unnamed".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_with_nothing_skipped_is_complete() {
        let mut summary = ArchiveSummary::new("zip", 3);
        assert!(!summary.is_complete(), "nothing has been examined yet");
        assert!(!summary.examined_anything());

        summary.examined_member(100);
        summary.examined_member(200);
        summary.examined_member(300);
        assert!(summary.is_complete());
        assert!(summary.examined_anything());
        assert_eq!(summary.expanded, 600);
        assert_eq!(summary.skipped_count(), 0);
    }

    #[test]
    fn a_skipped_member_makes_the_archive_incomplete_however_many_were_read() {
        // The rule this whole type exists for: two hundred members read and one
        // encrypted is not a clean archive.
        let mut summary = ArchiveSummary::new("zip", 201);
        for _ in 0..200 {
            summary.examined_member(10);
        }
        summary.skip("secret.doc", SkipReason::Encrypted);
        assert!(!summary.is_complete());
        assert_eq!(summary.skipped_count(), 1);
    }

    #[test]
    fn an_exhausted_walk_is_incomplete_even_with_nothing_skipped() {
        let mut summary = ArchiveSummary::new("zip", 500);
        summary.examined_member(10);
        summary.exhausted = true;
        assert!(!summary.is_complete());
        assert!(summary.describe().contains("stopped before"));
    }

    #[test]
    fn every_skip_reason_says_the_contents_are_unknown() {
        // The invariant behind `leaves_contents_unknown`, asserted for every
        // variant so that a new one cannot be added without a decision.
        let all = [
            SkipReason::Encrypted,
            SkipReason::Unsupported {
                method: "deflate64".into(),
            },
            SkipReason::Budget,
            SkipReason::Depth,
            SkipReason::TooLarge { declared: 1 },
            SkipReason::Corrupt {
                detail: "bad crc".into(),
            },
            SkipReason::Unnamed,
        ];
        for reason in all {
            assert!(reason.leaves_contents_unknown(), "{reason:?}");
            assert!(!reason.describe().is_empty(), "{reason:?}");
            assert!(!reason.summary_label().is_empty(), "{reason:?}");
        }
    }

    #[test]
    fn the_description_counts_skips_by_reason_rather_than_listing_them() {
        // Four members, all four accounted for: one read, three skipped for two
        // different reasons. The counts are what is being checked here, so the
        // fixture has to be one where the accounting adds up — otherwise the
        // line would also carry the "not accounted for" clause and the test
        // would be measuring two things at once.
        let mut summary = ArchiveSummary::new("zip", 4);
        summary.examined_member(1);
        summary.skip("a", SkipReason::Encrypted);
        summary.skip("b", SkipReason::Encrypted);
        summary.skip("c", SkipReason::Depth);
        let text = summary.describe();
        assert!(text.starts_with("zip: 1 of 4 members examined"), "{text}");
        assert!(text.contains("2 encrypted"), "{text}");
        assert!(text.contains("1 nested too deeply"), "{text}");
        assert!(!text.contains("accounted for"), "{text}");
    }

    #[test]
    fn a_member_that_is_neither_read_nor_skipped_is_not_a_complete_scan() {
        // The backstop. Nothing was skipped and the walk did not say it stopped
        // early, so a summary that only asked those two questions would call
        // this complete — and this is a scanner that examined two of the four
        // members it declared and has no idea what happened to the others. The
        // one answer it must not give is "clean", and a report that said
        // nothing at all about the gap would be giving it.
        let mut summary = ArchiveSummary::new("zip", 4);
        summary.examined_member(10);
        summary.examined_member(10);
        assert!(!summary.is_complete());
        assert!(summary
            .describe()
            .contains("not every member was accounted for"));
        assert!(summary
            .describe()
            .starts_with("zip: 2 of 4 members examined"));
    }

    #[test]
    fn an_empty_container_is_complete_having_examined_nothing() {
        // The control for the test above: "nothing was examined" is not itself
        // the problem. A container with no members is one there was nothing to
        // miss, and calling that incomplete would put a warning on every empty
        // zip a user makes.
        let summary = ArchiveSummary::new("zip", 0);
        assert!(summary.is_complete());
        assert!(!summary.examined_anything());
    }

    #[test]
    fn a_single_member_archive_says_member_not_members() {
        let mut summary = ArchiveSummary::new("gzip", 1);
        summary.examined_member(64);
        assert!(summary.describe().contains("1 of 1 member examined"));
    }

    #[test]
    fn a_skip_describes_itself_with_its_name_first() {
        let skip = ArchiveSkip::new(
            "docs/report.pdf",
            SkipReason::TooLarge {
                declared: 9_000_000,
            },
        );
        let text = skip.describe();
        assert!(text.starts_with("docs/report.pdf: "), "{text}");
        assert!(text.contains("9000000"), "{text}");
    }
}
