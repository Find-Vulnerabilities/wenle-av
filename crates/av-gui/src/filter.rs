//! Narrowing a findings list without changing what it says.
//!
//! # Why the empty list has to be two different things
//!
//! A findings table with nothing in it is the most consequential screen in this
//! product and it is reached two entirely different ways. One is a scan that
//! found nothing, which is the answer the user wanted. The other is a scan that
//! found eleven things and a filter that is hiding all eleven, which is the
//! answer the user asked for by accident and must be told about — a user who
//! typed a file name into the search box, forgot, and then read "no findings"
//! has been told their machine is clean by a screen that never said so.
//!
//! So the result of filtering is not a list: it is a list plus the counts that
//! let a caller tell the two apart, and [`Filtered::empty_message`] is the
//! sentence to draw in each case. That is the whole reason this is a module
//! with types in it rather than a `retain` at the call site.
//!
//! # Why the sort orders match the console's
//!
//! `av-cli`'s scan command sorts findings by band (worst first), then by score
//! descending, then by path. The window's default is the same order for the
//! same reason: a person who runs a scan in the console and then opens the
//! window on the same directory should see the same three files at the top.
//! A different order would not be a bug anyone could point at — it would just
//! be two products quietly disagreeing about which finding is the worst.

use av_core::{Detection, DetectionSource, FileScanReport, Verdict};

use crate::format::{count_of, Counts};

/// The most of a search box's contents that is ever searched for.
///
/// The query comes from a paste, and a paste can be a whole log file. Matching
/// a thousand-character needle against every path is work nobody asked for, and
/// nobody means to search for the thousandth character of a pasted log. The cut
/// is by characters, not bytes, so a pasted path in a non-Latin script is not
/// truncated mid-character.
pub const MAX_QUERY_CHARS: usize = 256;

/// Which bands a list shows.
///
/// [`Verdict::Clean`] is off by default and that is not an oversight: the
/// report a scan produces holds only files that were *not* clean, so a clean
/// toggle that defaulted on would filter out nothing while looking like it was
/// doing something. It is here for a caller that assembles its own list — a
/// quarantine view, a history view — where clean entries do exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bands {
    /// Show the red band.
    pub malicious: bool,
    /// Show the amber band.
    pub suspicious: bool,
    /// Show files that could not be scanned.
    pub unknown: bool,
    /// Show files that were scanned and found clean.
    pub clean: bool,
}

impl Bands {
    /// Everything except clean, which is the default.
    pub const CONCERNING: Self = Self {
        malicious: true,
        suspicious: true,
        unknown: true,
        clean: false,
    };

    /// Everything, including clean.
    pub const ALL: Self = Self {
        malicious: true,
        suspicious: true,
        unknown: true,
        clean: true,
    };

    /// Whether a verdict's band is shown.
    pub const fn shows(self, verdict: Verdict) -> bool {
        match verdict {
            Verdict::Malicious => self.malicious,
            Verdict::Suspicious => self.suspicious,
            Verdict::Unknown => self.unknown,
            Verdict::Clean => self.clean,
        }
    }

    /// Whether every band is shown.
    pub const fn is_all(self) -> bool {
        self.malicious && self.suspicious && self.unknown && self.clean
    }
}

impl Default for Bands {
    fn default() -> Self {
        Self::CONCERNING
    }
}

/// How a findings list is ordered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Sort {
    /// Worst band first, then highest score, then path. The console's order,
    /// and the default.
    #[default]
    Severity,
    /// Highest score first, then band.
    Score,
    /// Path, A to Z. The order a user wants when they are looking for a file
    /// they already know the name of.
    Path,
    /// By the subsystem that raised the finding, grouped so that "everything
    /// the heuristics flagged" is one contiguous run.
    Source,
}

impl Sort {
    /// The name shown in the sort control.
    pub const fn label(self) -> &'static str {
        match self {
            Sort::Severity => "Worst first",
            Sort::Score => "Highest score",
            Sort::Path => "Path",
            Sort::Source => "Found by",
        }
    }

    /// Every sort order, in the order the control offers them.
    pub const ALL: [Sort; 4] = [Sort::Severity, Sort::Score, Sort::Path, Sort::Source];
}

/// What to show.
///
/// Everything here is a decision a person made, and every field has a default
/// that shows more rather than less: the filter's job is to hide things the
/// user asked to hide, and a filter that starts out hiding something is a
/// filter that makes a scan look like it found less than it did.
///
/// `Default` is derived, and the derive is the specification: no source, no
/// query, no minimum score, the console's sort order, and the band set
/// [`Bands::CONCERNING`] — every band a scan report can actually contain.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Filter {
    /// Which bands to show.
    pub bands: Bands,
    /// Show only files with a detection from this subsystem.
    pub source: Option<DetectionSource>,
    /// Show only files whose path contains this, ignoring case.
    pub path_query: String,
    /// Show only files scoring at least this much.
    pub min_score: u16,
    /// How to order what is left.
    pub sort: Sort,
}

impl Filter {
    /// A filter that hides nothing.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Whether this filter is hiding anything at all.
    ///
    /// Asked when the findings list is empty, so that the screen can offer to
    /// clear a filter the user has forgotten about instead of explaining the
    /// filter to a user who never set one.
    pub fn is_active(&self) -> bool {
        self.bands != Bands::CONCERNING
            || self.source.is_some()
            || !self.path_query.trim().is_empty()
            || self.min_score > 0
    }

    /// Whether one file passes.
    ///
    /// The four tests are independent and all must pass, which is what makes
    /// the controls compose: narrowing by band and then by path gives the
    /// intersection, and there is no order in which two controls undo each
    /// other.
    pub fn matches(&self, file: &FileScanReport) -> bool {
        if !self.bands.shows(file.verdict()) {
            return false;
        }
        if file.assessment.score < self.min_score {
            return false;
        }
        if let Some(source) = self.source {
            if !file
                .assessment
                .detections
                .iter()
                .any(|detection| detection.source == source)
            {
                return false;
            }
        }
        if !path_matches(&file.path.to_string_lossy(), &self.path_query) {
            return false;
        }
        true
    }

    /// Apply this filter to a list of files.
    pub fn apply<'a>(&self, files: &'a [FileScanReport]) -> Filtered<'a> {
        let mut shown: Vec<&FileScanReport> =
            files.iter().filter(|file| self.matches(file)).collect();
        let hidden = files.len() - shown.len();
        sort_files(&mut shown, self.sort);
        let counts = shown.iter().map(|file| file.verdict()).collect();
        Filtered {
            files: shown,
            hidden,
            total: files.len(),
            counts,
        }
    }

    /// How many of `files` this filter shows, without ordering them.
    ///
    /// # Why this is not `apply(...).files.len()`
    ///
    /// Because the filter bar says "12 of 340 shown" and does not need the
    /// twelve in order, while `apply` sorts them: an O(n log n) pass, on the
    /// filter bar's own frame, over a list that grows while a scan is running.
    /// The bar was paying that for a number, and paying it a second time —
    /// the findings list below it calls `apply` for real on the same frame.
    ///
    /// Ordering is [`Filter::apply`]'s business and counting is this one's, so
    /// this one is O(n) and allocates nothing.
    pub fn count(&self, files: &[FileScanReport]) -> usize {
        files.iter().filter(|file| self.matches(file)).count()
    }
}

/// Whether a path contains a query, ignoring case.
///
/// Case-insensitive because the paths are Windows paths and Windows is
/// case-insensitive: a user who types `downloads` and is shown nothing while
/// `Downloads` sits on the disk has been told the file is not there. This is
/// also the reason the query is matched against the whole path rather than the
/// file name — half of what a person searches for is a directory.
///
/// A query that is empty or only whitespace matches everything: a search box
/// that has been focused and then emptied must not hide the list.
pub fn path_matches(path: &str, query: &str) -> bool {
    let query = query.trim();
    if query.is_empty() {
        return true;
    }
    let query: String = query.chars().take(MAX_QUERY_CHARS).collect();
    path.to_lowercase().contains(&query.to_lowercase())
}

/// The detection that most explains a file's verdict.
///
/// The highest-scoring one, with ties broken by rule identifier so that the
/// choice is the same on every run and on every machine. `None` for a file with
/// no detections at all, which is every clean file and every file that could
/// not be read.
///
/// This is what a one-line row shows when it has space for one detection, and
/// what the "found by" sort and the per-file source are derived from — one
/// definition, so a row cannot show one detection while being sorted by
/// another.
pub fn primary_detection(file: &FileScanReport) -> Option<&Detection> {
    file.assessment.detections.iter().min_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    })
}

/// The subsystem that raised a file's most significant finding.
pub fn primary_source(file: &FileScanReport) -> Option<DetectionSource> {
    primary_detection(file).map(|detection| detection.source)
}

/// How bad a band is, for sorting. The console's ranking, so the two front ends
/// put the same file at the top.
const fn rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Unknown => 1,
        Verdict::Clean => 0,
    }
}

/// Order a list in place.
///
/// Every order ends in the path, so that two files that tie on everything the
/// user chose to sort by still come out in a fixed order. A list that reshuffles
/// itself between two identical scans is a list a person cannot compare with
/// the one they took a screenshot of.
fn sort_files(files: &mut [&FileScanReport], sort: Sort) {
    files.sort_by(|a, b| {
        let by_rank = || rank(b.verdict()).cmp(&rank(a.verdict()));
        let by_score = || b.assessment.score.cmp(&a.assessment.score);
        let by_path = || a.path.cmp(&b.path);
        let by_source = || source_key(a).cmp(source_key(b));
        match sort {
            Sort::Severity => by_rank().then_with(by_score).then_with(by_path),
            Sort::Score => by_score().then_with(by_rank).then_with(by_path),
            Sort::Path => by_path(),
            Sort::Source => by_source().then_with(by_rank).then_with(by_path),
        }
    });
}

/// The sort key for [`Sort::Source`].
///
/// A file with no detections sorts on an empty key, which puts the files that
/// could not be read at the top of a "found by" listing — where they belong,
/// because nothing found them and that is the thing to notice about them.
fn source_key(file: &FileScanReport) -> &'static str {
    primary_source(file).map_or("", DetectionSource::as_str)
}

/// A filtered list, and what it left out.
///
/// Borrows the caller's reports rather than copying them: a findings list is
/// re-filtered on every keystroke in the search box, and cloning a report per
/// keystroke is work that shows up on a scan of a large tree. Not `PartialEq`,
/// because the things it points at are not comparable — a test compares the
/// paths, which is what a reader would compare too.
#[derive(Debug, Clone)]
pub struct Filtered<'a> {
    /// The files to show, in order.
    pub files: Vec<&'a FileScanReport>,
    /// How many files the filter hid.
    pub hidden: usize,
    /// How many files there were to begin with.
    pub total: usize,
    /// What the shown files are, by band.
    pub counts: Counts,
}

/// Why a list has nothing in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emptiness {
    /// The scan found nothing. The good answer.
    NothingFound,
    /// The scan found things and the filter is hiding all of them.
    AllHidden,
    /// There is something to show.
    Some,
}

impl Filtered<'_> {
    /// How many rows to draw.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether there is nothing to draw.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Row `row` of the list, or `None` past the end.
    ///
    /// The list is drawn a viewport at a time — see the `show_rows` call in
    /// `GuiApp::draw_findings` — so the drawing code addresses rows by number
    /// and this is the one place that turns a row number into a file. Doing it
    /// here rather than indexing `files` at each use is what keeps the
    /// virtualised list from being a place a row number can mean two things.
    pub fn get(&self, row: usize) -> Option<&FileScanReport> {
        self.files.get(row).copied()
    }

    /// Which of the three empty states this is.
    pub fn emptiness(&self) -> Emptiness {
        if !self.is_empty() {
            Emptiness::Some
        } else if self.total == 0 {
            Emptiness::NothingFound
        } else {
            Emptiness::AllHidden
        }
    }

    /// The sentence to draw when there is nothing to show.
    ///
    /// `None` when there is something to show. The two sentences are different
    /// claims and the second one counts: "all 11 findings are hidden" tells the
    /// user their scan did find something, which is the fact the first sentence
    /// would have denied.
    pub fn empty_message(&self, filter_is_active: bool) -> Option<String> {
        match self.emptiness() {
            Emptiness::Some => None,
            Emptiness::NothingFound => {
                Some("Nothing was found in the files that were scanned.".to_owned())
            }
            Emptiness::AllHidden => Some(if filter_is_active {
                format!(
                    "All {} hidden by the current filter. The scan did find them — clear the \
                     filter to see them.",
                    count_of(self.total as u64, "finding")
                )
            } else {
                // Reachable when a caller hands in a list that is entirely
                // clean files, which the findings view never does but a
                // history view can.
                format!(
                    "Nothing to show here, out of {}.",
                    count_of(self.total as u64, "file")
                )
            }),
        }
    }

    /// How many of how many are shown, as a label for the filter bar.
    pub fn count_label(&self) -> String {
        if self.hidden == 0 {
            count_of(self.total as u64, "finding")
        } else {
            format!(
                "{} of {} shown",
                self.files.len(),
                count_of(self.total as u64, "finding")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{
        Assessment, Detection as CoreDetection, DetectionSource, FileKind, Severity, Verdict,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn detection(
        rule: &str,
        severity: Severity,
        source: DetectionSource,
        score: u16,
    ) -> CoreDetection {
        CoreDetection::new(rule, "a thing was found", severity, source).with_score(score)
    }

    /// A file report with one detection, so that band, score and source can all
    /// be set independently.
    fn file(path: &str, verdict: Verdict, source: DetectionSource, score: u16) -> FileScanReport {
        let mut assessment = Assessment::clean();
        assessment.push(detection("test/rule", Severity::High, source, score));
        assessment.score = score;
        assessment.verdict = verdict;
        FileScanReport {
            path: PathBuf::from(path),
            kind: FileKind::Other,
            size: 1,
            digests: av_core::Digests::default(),
            assessment,
            duration: Duration::ZERO,
            scanned_bytes: 1,
            from_cache: false,
            error: None,
            archive: None,
        }
    }

    /// The default fixture: three bands, three sources, three scores.
    fn sample() -> Vec<FileScanReport> {
        vec![
            file(
                r"C:\Users\me\Downloads\invoice.exe",
                Verdict::Malicious,
                DetectionSource::Signature,
                250,
            ),
            file(
                r"C:\Users\me\Downloads\setup.exe",
                Verdict::Suspicious,
                DetectionSource::Heuristic,
                60,
            ),
            file(
                r"C:\Windows\Temp\locked.dll",
                Verdict::Unknown,
                DetectionSource::Heuristic,
                0,
            ),
            file(
                r"C:\Users\me\projects\build\tool.exe",
                Verdict::Suspicious,
                DetectionSource::Signature,
                45,
            ),
            file(
                r"C:\Users\me\Downloads\notes.txt",
                Verdict::Clean,
                DetectionSource::User,
                0,
            ),
        ]
    }

    fn paths(filtered: &Filtered<'_>) -> Vec<String> {
        filtered
            .files
            .iter()
            .map(|f| f.path.display().to_string())
            .collect()
    }

    // -- the empty list means two things -------------------------------------

    #[test]
    fn a_scan_that_found_nothing_and_a_filter_that_hides_everything_are_different() {
        // The reason this module exists. Same table, same lack of rows, two
        // different sentences, and only one of them is good news.
        let files = sample();
        let filter = Filter::default();
        assert_eq!(filter.apply(&[]).emptiness(), Emptiness::NothingFound);
        assert_eq!(filter.apply(&files[..4]).emptiness(), Emptiness::Some);

        let filter = Filter {
            path_query: "nothing-matches-this".into(),
            ..Filter::default()
        };
        let hidden = filter.apply(&files);
        assert_eq!(hidden.emptiness(), Emptiness::AllHidden);
        assert_eq!(hidden.files.len(), 0);
        assert_eq!(hidden.hidden, 5);
        assert_eq!(hidden.total, 5);

        let nothing = Filter::default().apply(&[]);
        assert_eq!(nothing.emptiness(), Emptiness::NothingFound);
        assert!(nothing.empty_message(false).is_some());
        assert!(hidden.empty_message(true).is_some());
        assert_ne!(nothing.empty_message(false), hidden.empty_message(true));
    }

    #[test]
    fn the_message_for_a_hidden_list_says_something_was_found() {
        // The one fact the wrong message would deny.
        let files = sample();
        let filter = Filter {
            path_query: "zzz".into(),
            ..Filter::default()
        };
        let message = filter.apply(&files).empty_message(true).unwrap_or_default();
        assert!(message.contains("did find them"), "{message}");
        assert!(message.contains("5 findings"), "{message}");
    }

    #[test]
    fn a_list_with_something_in_it_has_no_message() {
        let filter = Filter::default();
        assert!(filter.apply(&sample()).empty_message(false).is_none());
        assert_eq!(filter.apply(&sample()).emptiness(), Emptiness::Some);
    }

    #[test]
    fn a_non_empty_list_reports_the_counts_of_what_it_shows_not_what_it_hid() {
        let filter = Filter {
            bands: Bands {
                malicious: false,
                ..Bands::CONCERNING
            },
            ..Filter::default()
        };
        let files = sample();
        let filtered = filter.apply(&files);
        assert_eq!(filtered.files.len(), 3);
        assert_eq!(filtered.hidden, 2);
        assert_eq!(filtered.counts.suspicious, 2);
        assert_eq!(filtered.counts.malicious, 0);
        assert_eq!(filtered.counts.unknown, 1);
        assert_eq!(filtered.counts.clean, 0);
    }

    // -- the individual tests ------------------------------------------------

    #[test]
    fn a_band_can_be_switched_off() {
        let filter = Filter {
            bands: Bands {
                suspicious: false,
                ..Bands::CONCERNING
            },
            ..Filter::default()
        };
        let shown = paths(&filter.apply(&sample()));
        assert_eq!(
            shown,
            vec![
                r"C:\Users\me\Downloads\invoice.exe",
                r"C:\Windows\Temp\locked.dll",
            ]
        );
    }

    #[test]
    fn clean_files_are_hidden_by_default_and_can_be_shown() {
        // The default has to match what a report contains, or the toggle reads
        // as broken. A report holds no clean files; this fixture does, so the
        // default hides it and `ALL` reveals it.
        assert!(!Bands::default().shows(Verdict::Clean));
        assert_eq!(Filter::default().apply(&sample()).files.len(), 4);
        let all = Filter {
            bands: Bands::ALL,
            ..Filter::default()
        };
        assert_eq!(all.apply(&sample()).files.len(), 5);
        assert!(Bands::ALL.is_all());
        assert!(!Bands::default().is_all());
    }

    #[test]
    fn a_source_filter_keeps_the_files_that_source_flagged() {
        let filter = Filter {
            source: Some(DetectionSource::Heuristic),
            ..Filter::default()
        };
        let shown = paths(&filter.apply(&sample()));
        assert_eq!(
            shown,
            vec![
                r"C:\Users\me\Downloads\setup.exe",
                r"C:\Windows\Temp\locked.dll",
            ]
        );
    }

    #[test]
    fn a_source_filter_keeps_a_file_flagged_by_two_sources() {
        // The test is "any detection came from this source", not "the primary
        // one did" — a file the heuristics also flagged is a file the
        // heuristics flagged.
        let mut both = file(
            r"C:\a.exe",
            Verdict::Malicious,
            DetectionSource::Signature,
            300,
        );
        both.assessment.push(detection(
            "test/heuristic",
            Severity::Low,
            DetectionSource::Heuristic,
            30,
        ));
        let filter = Filter {
            source: Some(DetectionSource::Heuristic),
            ..Filter::default()
        };
        assert!(filter.matches(&both));
        assert_eq!(
            primary_source(&both),
            Some(DetectionSource::Signature),
            "the primary source is still the highest-scoring one"
        );
    }

    #[test]
    fn a_path_query_matches_anywhere_in_the_path_and_ignores_case() {
        // `Bands::ALL` so that the clean file in the fixture is in the running:
        // the point of this test is the query, and a band filter quietly
        // removing one of the three matches would make it a test of two things.
        let filter = Filter {
            bands: Bands::ALL,
            path_query: "downloads".into(),
            ..Filter::default()
        };
        let shown = paths(&filter.apply(&sample()));
        assert_eq!(shown.len(), 3, "{shown:?}");
        assert!(shown.iter().all(|p| p.contains("Downloads")), "{shown:?}");

        // A directory is half of what a person searches for.
        let filter = Filter {
            path_query: "PROJECTS".into(),
            ..Filter::default()
        };
        assert_eq!(
            paths(&filter.apply(&sample())),
            vec![r"C:\Users\me\projects\build\tool.exe"]
        );
    }

    #[test]
    fn an_empty_query_matches_everything() {
        // A search box that has been focused and emptied must not hide the
        // list, and a box holding a space is an emptied box.
        for query in ["", "   ", "\t"] {
            assert!(path_matches(r"C:\a.exe", query), "{query:?}");
            let filter = Filter {
                path_query: query.into(),
                ..Filter::default()
            };
            assert_eq!(filter.apply(&sample()).files.len(), 4, "{query:?}");
            assert!(!filter.is_active(), "{query:?}");
        }
    }

    #[test]
    fn the_fixture_is_what_the_other_tests_think_it_is() {
        // Every expectation above is written against this list, so it is
        // checked once here rather than re-derived by reading it.
        let files = sample();
        assert_eq!(files.len(), 5);
        assert_eq!(files.len() - Filter::default().apply(&files).files.len(), 1);
        assert_eq!(
            Filter::default().apply(&files).counts,
            Counts {
                malicious: 1,
                suspicious: 2,
                unknown: 1,
                clean: 0,
            }
        );
    }

    #[test]
    fn an_absurd_query_is_cut_rather_than_searched_for_whole() {
        // The query comes from a paste and a paste can be a log file. What is
        // searched for is its first `MAX_QUERY_CHARS` characters and no more.
        let pasted = format!("C:\\Users\\me\\{}", "n".repeat(MAX_QUERY_CHARS * 4));
        let path = format!(r"C:\Users\me\{}.exe", "n".repeat(4_000));
        assert!(path_matches(&path, &pasted));

        // A needle longer than the cut is cut, and the part beyond the cut is
        // not searched for — which is what makes the bound a bound.
        let mut over = "C:\\Users\\me\\".to_owned();
        over.push_str(&"n".repeat(MAX_QUERY_CHARS * 4));
        over.push_str("no-such-thing");
        assert!(!path_matches(r"C:\Users\me\a.exe", &over));

        // The cut is by characters, so a query in a non-Latin script is not cut
        // mid-character, which would panic a byte slice and mis-render a string.
        assert!(!path_matches(r"C:\a.exe", &"я".repeat(MAX_QUERY_CHARS * 2)));
        assert!(!path_matches(r"C:\a.exe", &"é".repeat(5_000)));
    }

    #[test]
    fn a_minimum_score_hides_the_weak_findings() {
        let filter = Filter {
            min_score: 60,
            ..Filter::default()
        };
        let shown = paths(&filter.apply(&sample()));
        assert_eq!(
            shown,
            vec![
                r"C:\Users\me\Downloads\invoice.exe",
                r"C:\Users\me\Downloads\setup.exe",
            ]
        );
    }

    #[test]
    fn the_four_controls_compose_rather_than_undo_each_other() {
        let filter = Filter {
            source: Some(DetectionSource::Signature),
            path_query: "downloads".into(),
            min_score: 50,
            bands: Bands::CONCERNING,
            sort: Sort::Severity,
        };
        assert_eq!(
            paths(&filter.apply(&sample())),
            vec![r"C:\Users\me\Downloads\invoice.exe"]
        );
    }

    // -- the orders ----------------------------------------------------------

    #[test]
    fn the_default_order_is_the_consoles_order() {
        // Worst band first, then highest score, then path. The same three files
        // come out at the top in the window as in the console.
        let filter = Filter::default();
        assert_eq!(Sort::default(), Sort::Severity);
        assert_eq!(
            paths(&filter.apply(&sample())),
            vec![
                r"C:\Users\me\Downloads\invoice.exe",
                r"C:\Users\me\Downloads\setup.exe",
                r"C:\Users\me\projects\build\tool.exe",
                r"C:\Windows\Temp\locked.dll",
            ]
        );
    }

    #[test]
    fn the_path_order_is_the_path_order() {
        let filter = Filter {
            sort: Sort::Path,
            ..Filter::default()
        };
        let shown = paths(&filter.apply(&sample()));
        let mut expected = shown.clone();
        expected.sort();
        assert_eq!(shown, expected);
    }

    #[test]
    fn the_score_order_puts_the_highest_score_first_whatever_its_band() {
        let files = vec![
            file(r"C:\a", Verdict::Suspicious, DetectionSource::Signature, 90),
            file(r"C:\b", Verdict::Malicious, DetectionSource::Signature, 100),
            file(r"C:\c", Verdict::Unknown, DetectionSource::Signature, 0),
        ];
        let filter = Filter {
            sort: Sort::Score,
            ..Filter::default()
        };
        assert_eq!(
            paths(&filter.apply(&files)),
            vec![r"C:\b", r"C:\a", r"C:\c"]
        );
    }

    #[test]
    fn the_source_order_groups_the_files_a_source_found() {
        let files = vec![
            file(r"C:\a", Verdict::Suspicious, DetectionSource::Signature, 40),
            file(r"C:\b", Verdict::Malicious, DetectionSource::Heuristic, 200),
            file(r"C:\c", Verdict::Suspicious, DetectionSource::Heuristic, 50),
            file(r"C:\d", Verdict::Unknown, DetectionSource::Signature, 0),
        ];
        let filter = Filter {
            sort: Sort::Source,
            ..Filter::default()
        };
        let shown = paths(&filter.apply(&files));
        // `heuristic` before `signature`, alphabetically, and within a source
        // by band.
        assert_eq!(shown, vec![r"C:\b", r"C:\c", r"C:\a", r"C:\d"], "{shown:?}");
    }

    #[test]
    fn every_order_is_stable_across_runs() {
        // A list that reshuffles between two identical scans is a list a person
        // cannot compare with the screenshot they took of the first one. Each
        // order ends in the path, so ties are broken by something that does not
        // move.
        let files = vec![
            file(r"C:\z", Verdict::Malicious, DetectionSource::Signature, 100),
            file(r"C:\y", Verdict::Malicious, DetectionSource::Signature, 100),
            file(r"C:\x", Verdict::Malicious, DetectionSource::Signature, 100),
        ];
        for sort in Sort::ALL {
            let filter = Filter {
                sort,
                ..Filter::default()
            };
            let first = paths(&filter.apply(&files));
            let second = paths(&filter.apply(&files));
            assert_eq!(first, second, "{sort:?}");
            assert_eq!(first, vec![r"C:\x", r"C:\y", r"C:\z"], "{sort:?}");
        }
    }

    #[test]
    fn every_order_offers_a_label_and_a_fixed_set() {
        assert_eq!(Sort::ALL.len(), 4);
        for sort in Sort::ALL {
            assert!(!sort.label().is_empty());
            assert!(sort.label().len() < 20, "{}", sort.label());
        }
    }

    #[test]
    fn sorting_does_not_reorder_the_callers_list() {
        // The filter borrows; it must not mutate what it was handed.
        let files = sample();
        let before: Vec<_> = files.iter().map(|f| f.path.clone()).collect();
        let _ = Filter {
            sort: Sort::Path,
            ..Filter::default()
        }
        .apply(&files);
        let after: Vec<_> = files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(before, after);
    }

    // -- activity ------------------------------------------------------------

    #[test]
    fn the_default_filter_hides_nothing_and_says_so() {
        let filter = Filter::default();
        assert!(!filter.is_active());
        assert_eq!(filter.apply(&sample()).hidden, 1, "only the clean file");
    }

    #[test]
    fn every_control_makes_the_filter_active() {
        let filter = Filter {
            bands: Bands {
                malicious: false,
                ..Bands::ALL
            },
            ..Filter::default()
        };
        assert!(filter.is_active(), "a band turned off");

        let filter = Filter {
            source: Some(DetectionSource::User),
            ..Filter::default()
        };
        assert!(filter.is_active(), "a source chosen");

        let filter = Filter {
            path_query: "a".into(),
            ..Filter::default()
        };
        assert!(filter.is_active(), "a path typed");

        let filter = Filter {
            min_score: 1,
            ..Filter::default()
        };
        assert!(filter.is_active(), "a floor set");

        // Sorting is not a filter: it hides nothing.
        let filter = Filter {
            sort: Sort::Path,
            ..Filter::default()
        };
        assert!(!filter.is_active());
    }

    #[test]
    fn clearing_puts_every_control_back() {
        let mut filter = Filter {
            bands: Bands::ALL,
            source: Some(DetectionSource::Memory),
            path_query: "x".into(),
            min_score: 500,
            sort: Sort::Path,
        };
        filter.clear();
        assert_eq!(filter, Filter::default());
        assert!(!filter.is_active());
    }

    // -- the primary detection -----------------------------------------------

    #[test]
    fn the_primary_detection_is_the_highest_scoring_one_deterministically() {
        let mut report = file(
            r"C:\a.exe",
            Verdict::Malicious,
            DetectionSource::Signature,
            0,
        );
        report.assessment.detections.clear();
        report.assessment.push(detection(
            "b/rule",
            Severity::Low,
            DetectionSource::Signature,
            30,
        ));
        report.assessment.push(detection(
            "a/rule",
            Severity::High,
            DetectionSource::Heuristic,
            100,
        ));
        report.assessment.push(detection(
            "c/rule",
            Severity::High,
            DetectionSource::Reputation,
            100,
        ));
        let primary = primary_detection(&report).expect("there are detections");
        // Ties broken by rule identifier, so the answer is the same everywhere.
        assert_eq!(primary.rule_id, "a/rule");
        assert_eq!(primary_source(&report), Some(DetectionSource::Heuristic));

        let mut bare = file(r"C:\b.exe", Verdict::Unknown, DetectionSource::User, 0);
        bare.assessment.detections.clear();
        assert!(primary_detection(&bare).is_none());
        assert_eq!(primary_source(&bare), None);
    }

    // -- the label -----------------------------------------------------------

    #[test]
    fn the_count_label_distinguishes_all_from_some() {
        let filter = Filter {
            bands: Bands::ALL,
            ..Filter::default()
        };
        assert_eq!(filter.apply(&sample()).count_label(), "5 findings");
        let filter = Filter {
            bands: Bands {
                malicious: false,
                ..Bands::CONCERNING
            },
            ..Filter::default()
        };
        assert_eq!(
            filter.apply(&sample()).count_label(),
            "3 of 5 findings shown"
        );
    }
}
