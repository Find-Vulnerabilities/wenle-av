//! Turning engine values into the strings a person reads.
//!
//! # Why the console's formatting is repeated here rather than shared
//!
//! `av-cli` is a binary. Its formatting helpers are `pub` inside a `pub(crate)`
//! module of a crate nothing can depend on, so the window cannot import
//! `human_bytes` or `where_in` — only re-implement them. Re-implementing is
//! therefore not a choice, but the *risk* it creates is: two front ends that
//! disagree about what a size or a location looks like, in a product whose
//! whole claim is that they agree about the verdict.
//!
//! So the tests below are the console's tests, retyped against the same
//! expected strings, down to `"999.9 KB"` and `"payload.exe:0x1400 (32 bytes)"`.
//! A change to either side that is not made to both turns one of them red. The
//! duplication is deliberate and this is what keeps it honest.
//!
//! # Why every conversion is a function and not a `format!` at the call site
//!
//! Because the call sites are in the one file that cannot be tested. A
//! `format!` inside a `ui.label(...)` is a string no test can see; the same
//! `format!` in here has its boundary cases pinned — zero, one, the unit
//! boundary, the count that is exactly one file — which are precisely the cases
//! a person notices and a developer does not.

use std::path::Path;
use std::time::Duration;

use av_core::{Detection, FileScanReport, ScanReport, ScanTarget, Verdict};

/// A count with thousands separators.
///
/// The console's, transcribed. Grouping is by three from the right, which is
/// what every Western locale does and what a user reading `1234567` in a
/// findings list expects to be able to parse at a glance.
pub fn human_count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// A byte count in the largest decimal unit that leaves it above one.
///
/// Decimal, not binary, and matching `--max-size` in the console: a user who
/// types `100MB` and then reads `95.4 MB` for the same file has been told two
/// different things about one number.
pub fn human_bytes(value: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TB", 1_000_000_000_000),
        ("GB", 1_000_000_000),
        ("MB", 1_000_000),
        ("KB", 1_000),
    ];
    for (unit, scale) in UNITS {
        if value >= scale {
            // One decimal place: enough to tell 1.4 MB from 1.9 MB, which is
            // the resolution a person reading a size actually uses.
            let whole = value / scale;
            let tenths = (value % scale) * 10 / scale;
            return format!("{whole}.{tenths} {unit}");
        }
    }
    format!("{value} B")
}

/// A duration, at the resolution a person reads it at.
///
/// Three bands, because the useful precision changes with the size: a scan
/// measured in seconds is read to a tenth, one measured in minutes is read to
/// the second, and one measured in hours is read to the minute.
///
/// The rounding is done *before* the band is chosen, not after. `59.96s`
/// rounded inside the seconds band would print `60.0s`, and a timer that reads
/// `60.0s` is a timer that has not rolled over — so a duration on the edge of a
/// minute is promoted to `1m 00s` instead, which is the same instant said
/// correctly.
pub fn human_duration(duration: Duration) -> String {
    let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    let tenths = millis.saturating_add(50) / 100;
    if tenths < 600 {
        return format!("{}.{}s", tenths / 10, tenths % 10);
    }
    let seconds = millis.saturating_add(500) / 1000;
    if seconds < 3_600 {
        return format!("{}m {:02}s", seconds / 60, seconds % 60);
    }
    format!("{}h {:02}m", seconds / 3_600, (seconds % 3_600) / 60)
}

/// How far through a scan is, in `0.0..=1.0`.
///
/// `None` when the total is not known, which is not the same as zero and must
/// not be drawn as zero: a bar sitting at 0% while a scan runs looks stalled,
/// and a bar that jumps to 100% the moment a total arrives looks broken. The
/// caller draws an indeterminate bar for `None` and a determinate one for
/// `Some`.
///
/// A `done` past `total` is clamped rather than followed: it happens for real
/// when a directory is enumerated and files are created while the scan runs,
/// and a bar drawn past its own end is a drawing bug the user sees.
pub fn fraction(done: u64, total: u64) -> Option<f32> {
    if total == 0 {
        return None;
    }
    let ratio = done as f64 / total as f64;
    Some(ratio.clamp(0.0, 1.0) as f32)
}

/// A whole-number percentage, or `None` when the total is unknown.
///
/// Rounded down, and capped at 99 until the work is actually done. A progress
/// readout that says 100% while files are still being scanned is the single
/// most common way a progress bar lies, and it is worse than useless: the user
/// waits for a scan that has already told them it finished. `100` therefore
/// means done, and nothing else does.
/// The arithmetic is integer arithmetic, not a percentage of a float. `9.0 /
/// 10.0 * 100.0` is `89.99999999999999` in binary floating point, and flooring
/// that gives 89 — a progress readout that is wrong by one for no reason a
/// reader could ever guess. Widening to `u128` keeps the multiplication exact
/// for any count a scan can reach.
pub fn percentage(done: u64, total: u64) -> Option<u8> {
    if total == 0 {
        return None;
    }
    if done >= total {
        return Some(100);
    }
    let whole = (u128::from(done) * 100 / u128::from(total)).min(99);
    Some(whole as u8)
}

/// `1 file`, `2 files`, `0 files`.
///
/// The rule is worth stating because it is the one that gets written wrong: the
/// singular is chosen by the count, not by whether the string looks nicer, and
/// zero takes the plural. "0 file" reads as a bug in a way "0 files" does not.
pub fn count_of(count: u64, singular: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{} {singular}s", human_count(count))
    }
}

/// The same, for a word whose plural is not its singular plus `s`.
pub fn count_of_pair(count: u64, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{} {plural}", human_count(count))
    }
}

/// A path cut from the front, which is where the redundant part is.
///
/// Cut from the front rather than the back because every path a user has two of
/// shares its prefix: when scanning `C:\Users\me\Projects\thing`, the file name
/// is the whole of the information and `C:\Users\me` is the whole of the noise.
/// The ellipsis is a real character so that a cut path is visibly cut.
pub fn shorten_path(text: &str, limit: usize) -> String {
    let length = text.chars().count();
    if length <= limit {
        return text.to_owned();
    }
    if limit == 0 {
        return String::new();
    }
    let tail: String = text.chars().skip(length - (limit - 1)).collect();
    format!("…{tail}")
}

/// A timestamp in the reader's own time zone.
///
/// The engine records UTC, because a report has to be comparable across
/// machines; a person reads the clock on the wall in front of them. Converting
/// at the point of display and nowhere else is what keeps the two from being
/// confused for each other — a log line printed in UTC with no marker is a log
/// line that will be read as local.
pub fn local_time(when: &chrono::DateTime<chrono::Utc>) -> String {
    when.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

/// Where a detection was found, as the prefix of its line.
///
/// The console's `where_in`, and it has to be: the same finding shows an offset
/// here and an offset there, and two different renderings of one offset is how
/// a user concludes the two front ends scanned different things.
///
/// The member name comes first when there is one, because `0x1400` on its own
/// is an offset into the outer file and a member's offset is not one — a reader
/// who went looking for that byte in the zip would find a compressed stream and
/// conclude the scanner was making things up. Naming the member is what makes
/// the number true.
///
/// Both halves are optional and often absent: a rule that matched on a
/// file-level property has no offset, and a member found by such a rule has a
/// name but no offset. The trailing two spaces are part of a non-empty return
/// so a caller can concatenate unconditionally.
pub fn where_in(detection: &Detection) -> String {
    let offset = detection
        .locations
        .first()
        .map(|loc| format!("0x{:x} ({} bytes)", loc.offset, loc.length));
    match (detection.container.as_deref(), offset) {
        (Some(member), Some(offset)) => format!("{member}:{offset}  "),
        (Some(member), None) => format!("{member}  "),
        (None, Some(offset)) => format!("{offset}  "),
        (None, None) => String::new(),
    }
}

/// A detection as one line, the way a list row shows it.
///
/// The name a user would search for comes first — the threat family when the
/// rule attributed one, the rule identifier otherwise — then how bad the engine
/// thinks it is and which part of the engine said so. The description is
/// deliberately *not* here: it is a sentence, it belongs in the detail pane,
/// and a list of two hundred sentences is not scannable.
pub fn detection_summary(detection: &Detection) -> String {
    format!(
        "{} — {}, {}",
        detection.display_name(),
        detection.severity.as_str(),
        detection.source.as_str()
    )
}

/// The label/value rows of a detection's detail pane.
///
/// Returned as data rather than drawn, so that which rows exist and what they
/// say is a thing a test can check. The order is fixed and is the order of the
/// questions a user asks: what is it, how bad, where, and what did it match.
///
/// The "Where" row repeats [`where_in`] with its trailing padding removed,
/// because padding exists for concatenation and a value rendered on its own
/// with two trailing spaces in it looks like a typo.
pub fn detection_detail(detection: &Detection) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("Rule", detection.rule_id.clone()),
        ("What it means", detection.description.clone()),
        ("Severity", detection.severity.as_str().to_owned()),
        ("Found by", detection.source.as_str().to_owned()),
        (
            "Score",
            format!(
                "{} ({})",
                detection.score,
                if detection.incontestable {
                    // The author's own rating, or a known hash. Nothing can
                    // argue with it.
                    "decisive on its own"
                } else if detection.decisive {
                    // Decisive because this product read the rule as one that
                    // names an instance or demands an indicator nothing
                    // ordinary carries — a weaker claim than an author's
                    // rating, and the one a proven publisher can answer. See
                    // `Detection::incontestable`. Saying so here is what
                    // explains a signed file this rule condemned and the
                    // product did not act on.
                    "decisive on a reading of the rule"
                } else {
                    "added to the total"
                }
            ),
        ),
    ];

    let where_text = where_in(detection);
    if !where_text.is_empty() {
        rows.push(("Where", where_text.trim_end().to_owned()));
    }
    // The matched bytes, when the rule reported any, and capped by the engine
    // at `MatchLocation::MAX_PREVIEW` — the preview is rendered for display by
    // `av-core` with control characters replaced, so a rule matching binary
    // cannot put escape sequences into a label here.
    if let Some(location) = detection.locations.first() {
        if !location.preview.is_empty() {
            rows.push((
                "Matched",
                format!("{} — \"{}\"", location.identifier, location.preview),
            ));
        }
    }
    rows
}

/// The console's score line, for the summary under a file's path.
///
/// `score 250 — 3 detections (1 decisive)`. A finding that was reached by one
/// decisive rule and one that was reached by eight weak ones are different
/// findings, and the count of decisive rules is the part that says which.
pub fn score_line(score: u16, detections: &[Detection]) -> String {
    let plural = if detections.len() == 1 { "" } else { "s" };
    let decisive = detections.iter().filter(|d| d.decisive).count();
    let tail = if decisive > 0 {
        format!(" ({decisive} decisive)")
    } else {
        String::new()
    };
    format!(
        "score {score} — {} detection{plural}{tail}",
        detections.len()
    )
}

/// How many files ended in each band.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Files in the red band.
    pub malicious: usize,
    /// Files in the amber band.
    pub suspicious: usize,
    /// Files that could not be scanned.
    pub unknown: usize,
    /// Files that were scanned and found clean.
    ///
    /// Always zero for a report's own list, which holds only non-clean files.
    /// Present because the filtering in [`crate::filter`] works over a list a
    /// caller assembled, and a caller that assembled all of them should not get
    /// a count that silently omits the majority.
    pub clean: usize,
}

impl Counts {
    /// Count a list of file reports by band.
    pub fn of(files: &[FileScanReport]) -> Self {
        files.iter().map(FileScanReport::verdict).collect()
    }

    /// Add one verdict to the tally.
    ///
    /// The single place a verdict becomes one of the four counters, so that a
    /// caller counting a filtered list and a caller counting a whole report
    /// cannot disagree about which band a verdict belongs in.
    pub fn add(&mut self, verdict: Verdict) {
        match verdict {
            Verdict::Malicious => self.malicious += 1,
            Verdict::Suspicious => self.suspicious += 1,
            Verdict::Unknown => self.unknown += 1,
            Verdict::Clean => self.clean += 1,
        }
    }

    /// Everything that is not clean.
    pub const fn concerning(&self) -> usize {
        self.malicious + self.suspicious + self.unknown
    }

    /// The bands as a sentence fragment: `2 malicious, 3 suspicious`.
    ///
    /// A band with nothing in it is left out rather than printed as zero —
    /// `0 malicious, 0 suspicious, 0 unknown` is three times the reading for
    /// none of the information — and a list with nothing in it at all says so
    /// in words instead of being empty. The unknown band is kept separate from
    /// the other two, because it is neither an accusation nor an acquittal and
    /// a reader who saw it folded into either would be misled.
    ///
    /// The band words are adjectives rather than nouns, which is why this uses
    /// [`count_of_pair`] with the same word twice: the console prints `3
    /// detections` and `2 malicious`, and `2 maliciouss` is not a word. The
    /// number is still an ordinary count, so `1 malicious` reads correctly.
    pub fn band_line(&self) -> String {
        let mut parts = Vec::new();
        for (count, word) in [
            (self.malicious, "malicious"),
            (self.suspicious, "suspicious"),
            (self.unknown, "unknown"),
        ] {
            if count > 0 {
                parts.push(count_of_pair(count as u64, word, word));
            }
        }
        if parts.is_empty() {
            return "nothing was found".to_owned();
        }
        parts.join(", ")
    }
}

impl std::iter::FromIterator<Verdict> for Counts {
    fn from_iter<T: IntoIterator<Item = Verdict>>(iter: T) -> Self {
        let mut counts = Self::default();
        for verdict in iter {
            counts.add(verdict);
        }
        counts
    }
}

/// The line drawn under a finished scan.
///
/// Four things, in the order a user asks them: how much was looked at, how long
/// it took, what was found, and what could not be looked at. The last is not
/// optional — a scan that reported nothing and a scan that could not read half
/// the disk are the same screen without it, and only one of them is good news.
///
/// A cancelled scan says so in the first sentence rather than the last, because
/// everything after it has to be read as a partial answer and a reader who
/// takes the totals as final has been misled by the layout rather than by the
/// numbers.
///
/// A scan that opened no file at all is the third case and gets its own
/// opening. Written the ordinary way it would come out as `Scanned 0 files
/// (0 B) in 0.00s. nothing was found.` — which is a clean bill of health over a
/// tree that was never entered, and the one sentence this whole product exists
/// not to print. A run that opened no file has not found nothing; it has not
/// *looked*, and those two must not be the same sentence, because only one of
/// them is good news. See [`never_looked`] for the condition and what it does
/// and does not cover.
pub fn scan_summary(report: &ScanReport) -> String {
    let counts = Counts::of(&report.detections);
    let unlooked = never_looked(report);
    let declined_only = declined_everything(report);

    let mut out = if report.cancelled {
        format!(
            "Stopped early: {} and {} were looked at before you stopped it, in {}.",
            count_of(report.stats.files_scanned, "file"),
            human_bytes(report.stats.bytes_scanned),
            human_duration(report.duration)
        )
    } else if unlooked {
        match &report.target {
            // A file target that was not opened is a different sentence from a
            // directory with nothing in it, and the failure list below names
            // the reason. "Nothing was scanned in C:\x\a.exe" would be the
            // wrong preposition for a file.
            ScanTarget::File(path) => {
                format!("Nothing was scanned: {} was never opened.", path.display())
            }
            target => format!(
                "Nothing was scanned in {} — no files were left to look at.",
                target.label()
            ),
        }
    } else if declined_only {
        // Every file the walk found was one the engine recognised and did not
        // run a rule against, which is what scanning a folder of rule sets
        // produces. `Nothing was scanned in …` is false here — files were found
        // and opened — and `Scanned 0 files (0 B)` is true and useless. This
        // says which it was, and `append_shortfalls` adds the counts.
        format!(
            "Nothing was examined in {}: the files here are this product's own data or rule \
             sources, and a rule source is not run against itself.",
            report.target.label()
        )
    } else {
        format!(
            "Scanned {} ({}) in {}.",
            count_of(report.stats.files_scanned, "file"),
            human_bytes(report.stats.bytes_scanned),
            human_duration(report.duration)
        )
    };

    if unlooked || declined_only {
        // `Counts::band_line` would say "nothing was found" here, which is the
        // exact sentence being avoided: it is true of the scan and false as a
        // statement about the files. What replaces it has to be the opposite
        // claim, not a quieter version of the same one. The second case is the
        // same falsehood arriving by a different road — the files were found
        // and read, and then declined rather than examined — so it gets the
        // same replacement.
        out.push_str(" Nothing has been checked, so nothing here is known to be clean.");
    } else {
        out.push(' ');
        out.push_str(&counts.band_line());
        out.push('.');
        if counts.malicious > 0 {
            out.push_str(" Malicious files are safe to quarantine.");
        } else if counts.suspicious > 0 {
            out.push_str(" Suspicious files were reported and not acted on.");
        }
    }

    append_shortfalls(&mut out, report);
    out
}

/// Whether the scan finished without opening a single file it was pointed at.
///
/// The target has to be a path for this to mean anything. A process scan
/// reports zero files *by design* — it reads memory, and there is no file for
/// it to have opened — so calling that "nothing was scanned" would be a
/// different falsehood for every non-path target rather than a fix for this
/// one. Only `File`, `Directory` and `Drive` targets are judged here.
///
/// A cancelled run is excluded because it says so in its own first sentence,
/// and two openings would be one too many.
fn never_looked(report: &ScanReport) -> bool {
    !report.cancelled
        && report.target.path().is_some()
        && report.stats.files_scanned == 0
        && report.stats.files_declined == 0
}

/// Whether every file the walk found was one the engine declined to examine.
///
/// The middle case between [`never_looked`] and an ordinary scan, and it needed
/// its own sentence for the same reason the first one did: the files were found,
/// so `Nothing was scanned in …` is false, and none of them was examined, so
/// `Scanned 0 files (0 B)` is a clean bill of health over files no rule was run
/// against. That is what scanning a directory of downloaded rule sets produces,
/// which is a thing users do.
///
/// The target has to be a path for the same reason as above: a process scan
/// reports zero files by design, and a process is never declined.
fn declined_everything(report: &ScanReport) -> bool {
    !report.cancelled
        && report.target.path().is_some()
        && report.stats.files_scanned == 0
        && report.stats.files_declined > 0
}

/// What the scan could not do, appended to any of the openings above.
///
/// Both sentences are about shortfall rather than about findings, so they
/// belong on a report that found nothing quite as much as on one that found
/// something — more, if anything: "nothing was scanned" and "nothing was
/// scanned because 4,000 files were excluded" are not the same news, and only
/// the second tells the user where to look.
fn append_shortfalls(out: &mut String, report: &ScanReport) {
    if !report.failures.is_empty() {
        out.push(' ');
        out.push_str(&count_of(report.failures.len() as u64, "file"));
        out.push_str(" could not be read.");
    }
    // Named here rather than folded into the opening sentence, because it is a
    // shortfall rather than a finding and belongs on a report that found
    // something quite as much as on one that did not: a file the engine
    // recognised is a file no rule was run against, and a user comparing the
    // count against the files they chose needs to know where the rest went.
    if report.stats.files_declined > 0 {
        let declined = report.stats.files_declined;
        out.push(' ');
        out.push_str(&count_of(declined, "file"));
        out.push_str(if declined == 1 { " was" } else { " were" });
        out.push_str(
            " recognised as this product's own data or as a rule source, and not examined.",
        );
    }
    // And the part of a file that was examined which no rule was run against.
    // No byte figure, because a member's length is not a fact about the file's;
    // "inside" is what says so.
    if report.stats.declined_members > 0 {
        let members = report.stats.declined_members;
        out.push(' ');
        out.push_str(&count_of(members, "rule source"));
        out.push_str(if members == 1 {
            " inside an archive was"
        } else {
            " inside archives were"
        });
        out.push_str(" not examined.");
    }
    if report.stats.files_skipped > 0 {
        let skipped = report.stats.files_skipped;
        out.push(' ');
        out.push_str(&count_of(skipped, "file"));
        // `1 file were skipped` is what a bare `were` produces, and a scan of a
        // single excluded file is exactly the case that reaches this line.
        out.push_str(if skipped == 1 {
            " was skipped as too large or excluded."
        } else {
            " were skipped as too large or excluded."
        });
    }
}

/// The reason a single file could not be scanned, as one line.
pub fn read_failure(path: &Path, reason: &str) -> String {
    format!("{} — {reason}", path.display())
}

/// The run's third outcome, or `None` when nothing was cleared.
///
/// A file the rules matched and trust then cleared is not a finding, so it is
/// not in the list; it did not fail, so it is not in the failure count. Left
/// unsaid it makes "Nothing found" a sentence about a run that threw matches
/// away — and the user who asks "then why was this not detected" is asking
/// exactly about these files. The console says the same thing in
/// `av-cli`'s `cleared_line`, and the two have to keep saying it: a front end
/// that reports clean and a front end that reports the count would be the same
/// product giving two answers.
///
/// `None` rather than an empty string at zero, so that a caller draws nothing
/// and a run that cleared nothing says nothing about clearing.
pub fn cleared_line(cleared: usize) -> Option<String> {
    if cleared == 0 {
        return None;
    }
    // The pronoun agrees with the count, and it is spelled out rather than
    // reached for through `count_of_pair`, which puts the count in front of the
    // word and would render this one as `1 it`.
    let pronoun = if cleared == 1 { "it" } else { "them" };
    Some(format!(
        "{} cleared rather than passed: the rules matched, the bytes are the ones a signed \
         catalogue lists, and everything found describes how the file was built rather than \
         what it is. Nothing was done about {pronoun}.",
        if cleared == 1 {
            "1 file was".to_owned()
        } else {
            format!("{} files were", human_count(cleared as u64))
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{
        Assessment, DetectionSource, MatchLocation, ScanStats, ScanTarget, Severity, ThreatName,
        VerdictThresholds,
    };
    use std::path::PathBuf;

    fn detection() -> Detection {
        Detection::new(
            "trojan/dropper",
            "the file drops a second executable",
            Severity::High,
            DetectionSource::Signature,
        )
    }

    fn location() -> MatchLocation {
        MatchLocation::new(0x1400, 32, "marker", b"MZ")
    }

    fn file(path: &str, verdict: Verdict) -> FileScanReport {
        let mut assessment = Assessment::clean();
        if verdict != Verdict::Clean {
            assessment.push(detection());
            assessment.verdict = verdict;
        }
        FileScanReport {
            path: PathBuf::from(path),
            kind: av_core::FileKind::Unknown,
            size: 100,
            digests: av_core::Digests::default(),
            assessment,
            duration: Duration::from_millis(1),
            scanned_bytes: 100,
            from_cache: false,
            error: None,
            archive: None,
        }
    }

    fn report(files: Vec<FileScanReport>) -> ScanReport {
        let mut report = ScanReport::new(ScanTarget::Directory(PathBuf::from(r"C:\scan")));
        report.duration = Duration::from_millis(12_340);
        report.stats = ScanStats {
            files_scanned: 1_204,
            bytes_scanned: 3_400_000_000,
            ..ScanStats::default()
        };
        report.detections = files;
        report
    }

    // -- counts --------------------------------------------------------------

    #[test]
    fn a_count_is_grouped_in_threes() {
        assert_eq!(human_count(0), "0");
        assert_eq!(human_count(999), "999");
        assert_eq!(human_count(1000), "1,000");
        assert_eq!(human_count(1234567), "1,234,567");
    }

    #[test]
    fn a_size_is_in_the_largest_unit_that_leaves_one() {
        // The same expectations the console asserts, so the two front ends
        // cannot drift apart about a size.
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1000), "1.0 KB");
        assert_eq!(human_bytes(1500), "1.5 KB");
        assert_eq!(human_bytes(1_000_000), "1.0 MB");
        assert_eq!(human_bytes(2_500_000_000), "2.5 GB");
        assert_eq!(human_bytes(999_999), "999.9 KB");
    }

    #[test]
    fn a_size_straddles_its_boundary_where_the_boundary_actually_is() {
        // The brief's case — 1023, 1024 and 1025 — and the surprise in it. These
        // are *decimal* units, so the boundary is at 1000 and not at 1024: all
        // three of those values render as `1.0 KB`, and 999 is the last value
        // that renders as bytes. That is the same answer `--max-size 1000`
        // gives, and a binary-unit implementation would give a different one for
        // all three — which is exactly why this is pinned rather than assumed.
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1000), "1.0 KB");
        assert_eq!(human_bytes(1023), "1.0 KB");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1025), "1.0 KB");
        // One decimal of resolution, so 1.0 KB covers 1000..1099 and nothing
        // more. A reader who wants to tell two files apart in the same tenth
        // needs the byte count, which is what the detail pane is for.
        assert_eq!(human_bytes(1099), "1.0 KB");
        assert_eq!(human_bytes(1100), "1.1 KB");
        assert_eq!(human_bytes(1_048_576), "1.0 MB");
        assert_eq!(human_bytes(1_000_000_000), "1.0 GB");
        assert_eq!(human_bytes(1_000_000_000_000), "1.0 TB");
        // The extreme, which nothing produces and every formatter still has to
        // render: the arithmetic narrows to the top unit rather than wrapping.
        assert!(
            human_bytes(u64::MAX).ends_with(" TB"),
            "{}",
            human_bytes(u64::MAX)
        );
    }

    #[test]
    fn a_size_never_reports_a_unit_it_has_not_reached() {
        // 999 bytes is not 1.0 KB, and a file of exactly one megabyte is not
        // 1000 KB. The unit is chosen by the value, not by rounding it up.
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1_000_000), "1.0 MB");
        assert!(!human_bytes(999).contains("KB"));
    }

    // -- durations -----------------------------------------------------------

    #[test]
    fn a_zero_duration_is_a_duration() {
        // Not an empty string and not "0s": a scan that took no measurable time
        // still has to print something in the place a duration goes.
        assert_eq!(human_duration(Duration::ZERO), "0.0s");
        assert_eq!(human_duration(Duration::from_millis(1)), "0.0s");
        assert_eq!(human_duration(Duration::from_millis(49)), "0.0s");
        assert_eq!(human_duration(Duration::from_millis(50)), "0.1s");
    }

    #[test]
    fn seconds_are_read_to_a_tenth() {
        assert_eq!(human_duration(Duration::from_millis(12_340)), "12.3s");
        assert_eq!(human_duration(Duration::from_secs(1)), "1.0s");
        assert_eq!(human_duration(Duration::from_millis(999)), "1.0s");
    }

    #[test]
    fn a_duration_on_the_edge_of_a_minute_rolls_over_rather_than_reading_sixty() {
        // `59.96s` rounded inside the seconds band prints `60.0s`, which is not
        // a time. The band is chosen after the rounding for exactly this case.
        assert_eq!(human_duration(Duration::from_millis(59_960)), "1m 00s");
        assert_eq!(human_duration(Duration::from_millis(59_940)), "59.9s");
        assert_eq!(human_duration(Duration::from_secs(60)), "1m 00s");
    }

    #[test]
    fn minutes_and_hours_are_padded_so_the_column_does_not_jump() {
        assert_eq!(human_duration(Duration::from_secs(125)), "2m 05s");
        assert_eq!(human_duration(Duration::from_secs(3_599)), "59m 59s");
        assert_eq!(human_duration(Duration::from_secs(3_600)), "1h 00m");
        assert_eq!(human_duration(Duration::from_secs(7_325)), "2h 02m");
    }

    #[test]
    fn a_duration_beyond_anything_a_scan_takes_does_not_panic() {
        // The value comes from a clock difference, and a clock that jumps can
        // produce any of them. A formatting function that panicked on a large
        // duration would take the window down with it.
        let _ = human_duration(Duration::from_secs(u64::MAX / 2));
        let _ = human_duration(Duration::MAX);
        assert!(human_duration(Duration::MAX).ends_with('m'));
    }

    // -- progress arithmetic -------------------------------------------------

    #[test]
    fn no_files_means_no_percentage_rather_than_a_division() {
        // The brief's case. Zero files scanned is the normal state of a scan
        // that has just started, and it must not divide by zero, print NaN, or
        // print 0% as though a total of zero were a total.
        assert_eq!(fraction(0, 0), None);
        assert_eq!(percentage(0, 0), None);
        assert_eq!(fraction(5, 0), None);
        assert_eq!(percentage(5, 0), None);
    }

    #[test]
    fn a_percentage_only_reaches_one_hundred_when_the_work_is_done() {
        assert_eq!(percentage(0, 10), Some(0));
        assert_eq!(percentage(5, 10), Some(50));
        // The one that a float implementation gets wrong: 0.9 * 100 is
        // 89.99999999999999 in binary floating point.
        assert_eq!(percentage(9, 10), Some(90));
        assert_eq!(percentage(1, 3), Some(33));
        assert_eq!(percentage(2, 3), Some(66));
        assert_eq!(percentage(10, 10), Some(100));
        // 999 of 1000 is 99.9%, which rounds to 100 and must not be shown as
        // finished.
        assert_eq!(percentage(999, 1000), Some(99));
        assert_eq!(percentage(1, 1000), Some(0));
        assert_eq!(percentage(u64::MAX - 1, u64::MAX), Some(99));
        assert_eq!(percentage(u64::MAX, u64::MAX), Some(100));
    }

    #[test]
    fn progress_past_the_end_is_clamped_to_the_end() {
        // Files can appear while a directory is being scanned, so `done` can
        // pass `total` legitimately. A bar drawn past its own end is a visible
        // bug; a bar pinned at full is merely early.
        assert_eq!(fraction(12, 10), Some(1.0));
        assert_eq!(percentage(12, 10), Some(100));
        assert_eq!(fraction(5, 10), Some(0.5));
    }

    // -- words ---------------------------------------------------------------

    #[test]
    fn one_file_is_not_one_files() {
        // The brief's case, and the one that actually gets shipped wrong.
        assert_eq!(count_of(1, "file"), "1 file");
        assert_eq!(count_of(2, "file"), "2 files");
        assert_eq!(count_of(0, "file"), "0 files");
        assert_eq!(count_of(1_204, "file"), "1,204 files");
    }

    #[test]
    fn an_irregular_plural_is_the_callers_to_give() {
        assert_eq!(count_of_pair(1, "entry", "entries"), "1 entry");
        assert_eq!(count_of_pair(3, "entry", "entries"), "3 entries");
        assert_eq!(count_of_pair(0, "entry", "entries"), "0 entries");
    }

    // -- paths ---------------------------------------------------------------

    #[test]
    fn a_long_path_is_shortened_from_the_front() {
        assert_eq!(shorten_path("short", 48), "short");
        let long = "C:/Users/someone/Downloads/a/very/deep/path/that/goes/on/file.exe";
        let cut = shorten_path(long, 20);
        assert!(cut.starts_with('…'), "{cut}");
        assert!(cut.ends_with("file.exe"), "{cut}");
        assert_eq!(cut.chars().count(), 20);
    }

    #[test]
    fn a_path_is_cut_by_characters_not_bytes() {
        // The name comes from the file system and the limit is a number of
        // columns. Cutting a multi-byte character in half would panic on a
        // slice and produce a replacement glyph on a string.
        let unicode = "C:/данные/файлы/очень/длинный/путь/файл.exe";
        let cut = shorten_path(unicode, 12);
        assert_eq!(cut.chars().count(), 12);
        assert!(cut.starts_with('…'));
    }

    #[test]
    fn an_absurd_limit_does_not_panic() {
        assert_eq!(shorten_path("", 0), "");
        assert_eq!(shorten_path("abc", 0), "");
        assert_eq!(shorten_path("abc", 1), "…");
    }

    // -- where a finding was -------------------------------------------------

    #[test]
    fn a_plain_finding_leads_with_its_offset() {
        let detection = detection().with_location(location());
        assert_eq!(where_in(&detection), "0x1400 (32 bytes)  ");
    }

    #[test]
    fn a_member_finding_names_the_member_before_the_offset() {
        let detection = detection().with_location(location()).within("payload.exe");
        assert_eq!(where_in(&detection), "payload.exe:0x1400 (32 bytes)  ");
    }

    #[test]
    fn a_member_finding_with_no_offset_still_names_the_member() {
        let detection = detection().within("C:\\a.zip\\deep\\payload.exe");
        assert_eq!(where_in(&detection), "C:\\a.zip\\deep\\payload.exe  ");
    }

    #[test]
    fn a_finding_with_neither_is_an_empty_prefix() {
        assert_eq!(where_in(&detection()), "");
    }

    #[test]
    fn a_nested_members_chain_is_shown_whole() {
        let detection = detection()
            .with_location(location())
            .within("bundle.zip/tools/payload.exe");
        assert_eq!(
            where_in(&detection),
            "bundle.zip/tools/payload.exe:0x1400 (32 bytes)  "
        );
    }

    // -- detections ----------------------------------------------------------

    #[test]
    fn a_detection_summary_leads_with_the_name_a_user_would_search_for() {
        let plain = detection();
        assert_eq!(
            detection_summary(&plain),
            "trojan/dropper — high, signature"
        );
        let named = plain.with_threat(
            ThreatName::new(
                av_core::Platform::Win32,
                av_core::ThreatCategory::Ransomware,
            )
            .with_family("LockBit"),
        );
        assert_eq!(
            detection_summary(&named),
            "Win32.Ransomware.LockBit — high, signature"
        );
    }

    #[test]
    fn a_detection_detail_answers_the_questions_in_order() {
        let detection = detection()
            .with_location(location())
            .with_score(150)
            .incontestable();
        let rows = detection_detail(&detection);
        let labels: Vec<&str> = rows.iter().map(|(label, _)| *label).collect();
        assert_eq!(
            labels,
            vec![
                "Rule",
                "What it means",
                "Severity",
                "Found by",
                "Score",
                "Where",
                "Matched"
            ]
        );
        let value = |label: &str| {
            rows.iter()
                .find(|(l, _)| *l == label)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(value("Severity"), "high");
        assert_eq!(value("Found by"), "signature");
        assert_eq!(value("Score"), "150 (decisive on its own)");
        // Padding is for concatenation; a value on its own must not carry it.
        assert_eq!(value("Where"), "0x1400 (32 bytes)");
    }

    #[test]
    fn a_detection_with_nothing_to_say_about_where_has_no_where_row() {
        // A structural rule reports a property of the file, not an offset into
        // it. A "Where" row reading "—" would suggest the engine knew and lost
        // it.
        let rows = detection_detail(&detection());
        assert!(!rows.iter().any(|(label, _)| *label == "Where"));
        assert!(!rows.iter().any(|(label, _)| *label == "Matched"));
    }

    /// The two kinds of conviction read differently in the detail pane,
    /// because they *are* different: one is a rule its author rated decisive,
    /// and the other is this product reading the rule itself — its title, or a
    /// condition nothing ordinary satisfies. A user looking at a file this
    /// product declined to act on is owed the difference.
    #[test]
    fn the_score_row_names_which_kind_of_conviction_this_is() {
        let rows = detection_detail(&detection().with_score(100).incontestable());
        assert_eq!(
            rows.iter()
                .find(|(l, _)| *l == "Score")
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            "100 (decisive on its own)"
        );
        let rows = detection_detail(&detection().with_score(100).decisive());
        assert_eq!(
            rows.iter()
                .find(|(l, _)| *l == "Score")
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            "100 (decisive on a reading of the rule)"
        );
    }

    #[test]
    fn a_scored_detection_says_it_was_added_to_the_total() {
        let rows = detection_detail(&detection().with_score(30));
        let score = rows
            .iter()
            .find(|(label, _)| *label == "Score")
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        assert_eq!(score, "30 (added to the total)");
    }

    #[test]
    fn a_score_line_counts_both_kinds_of_rule() {
        assert_eq!(score_line(250, &[detection(), detection(), detection()]), {
            "score 250 — 3 detections"
        });
        assert_eq!(score_line(100, &[detection().decisive()]), {
            "score 100 — 1 detection (1 decisive)"
        });
        assert_eq!(
            score_line(200, &[detection(), detection().decisive()]),
            "score 200 — 2 detections (1 decisive)"
        );
        // No detections at all still has to render: it is the state of a clean
        // file that a user opened the detail pane for.
        assert_eq!(score_line(0, &[]), "score 0 — 0 detections");
    }

    // -- bands ---------------------------------------------------------------

    #[test]
    fn a_band_line_leaves_out_the_bands_that_are_empty() {
        let counts = Counts {
            malicious: 2,
            suspicious: 3,
            unknown: 0,
            clean: 100,
        };
        assert_eq!(counts.band_line(), "2 malicious, 3 suspicious");
        assert_eq!(counts.concerning(), 5);
    }

    #[test]
    fn a_band_line_with_nothing_in_it_says_so() {
        let counts = Counts {
            clean: 500,
            ..Counts::default()
        };
        assert_eq!(counts.band_line(), "nothing was found");
        assert_eq!(counts.concerning(), 0);
    }

    #[test]
    fn an_unknown_file_is_counted_and_never_folded_into_another_band() {
        // The distinction the whole model exists for: unknown is not clean.
        let counts = Counts {
            unknown: 1,
            ..Counts::default()
        };
        assert_eq!(counts.band_line(), "1 unknown");
        assert_eq!(counts.concerning(), 1);
    }

    #[test]
    fn the_counts_come_from_the_reports_own_verdicts() {
        let files = vec![
            file("a.exe", Verdict::Malicious),
            file("b.exe", Verdict::Malicious),
            file("c.exe", Verdict::Suspicious),
            file("d.exe", Verdict::Unknown),
            file("e.exe", Verdict::Clean),
        ];
        let counts = Counts::of(&files);
        assert_eq!(counts.malicious, 2);
        assert_eq!(counts.suspicious, 1);
        assert_eq!(counts.unknown, 1);
        assert_eq!(counts.clean, 1);
    }

    // -- the summary line ----------------------------------------------------

    #[test]
    fn a_summary_reports_what_was_looked_at_and_what_was_found() {
        let report = report(vec![
            file("a.exe", Verdict::Malicious),
            file("b.exe", Verdict::Suspicious),
        ]);
        let line = scan_summary(&report);
        assert_eq!(
            line,
            "Scanned 1,204 files (3.4 GB) in 12.3s. 1 malicious, 1 suspicious. \
             Malicious files are safe to quarantine."
        );
    }

    #[test]
    fn a_summary_of_a_clean_scan_says_nothing_was_found() {
        let line = scan_summary(&report(Vec::new()));
        assert!(line.contains("nothing was found"), "{line}");
        assert!(!line.contains("quarantine"), "{line}");
    }

    #[test]
    fn a_summary_says_when_suspicious_files_were_not_acted_on() {
        // The product rule, carried into the report line: the middle band is a
        // notification, and the summary is where a user who read nothing else
        // learns that.
        let line = scan_summary(&report(vec![
            file("a.exe", Verdict::Suspicious),
            file("b.exe", Verdict::Suspicious),
        ]));
        assert!(line.contains("reported and not acted on"), "{line}");
        assert!(!line.contains("quarantine"), "{line}");
    }

    #[test]
    fn a_cancelled_scan_says_so_before_it_says_anything_else() {
        let mut report = report(vec![file("a.exe", Verdict::Malicious)]);
        report.cancelled = true;
        let line = scan_summary(&report);
        assert!(line.starts_with("Stopped early:"), "{line}");
        assert!(line.contains("1 malicious"), "{line}");
    }

    #[test]
    fn a_summary_admits_the_files_it_could_not_read() {
        // A scan that found nothing and a scan that could not open half the
        // disk are the same screen without this sentence.
        let mut report = report(Vec::new());
        report.failures = vec![(PathBuf::from("a"), "locked".into())];
        report.stats.files_skipped = 2;
        let line = scan_summary(&report);
        assert!(line.contains("1 file could not be read."), "{line}");
        assert!(line.contains("2 files were skipped"), "{line}");
    }

    #[test]
    fn a_scan_that_opened_no_file_does_not_report_a_clean_bill_of_health() {
        // A folder with nothing in it, or one where every file was filtered
        // out. This used to print `Scanned 0 files (0 B) in 0.0s. nothing was
        // found.` — a clean bill of health over a tree that was never entered,
        // and the one sentence this product exists not to print. A user read it
        // off the window and reported it, correctly, as a scan that had not
        // happened. It must still be a sentence; it must not be that one.
        let mut report = ScanReport::new(ScanTarget::Directory(PathBuf::from(r"C:\empty")));
        report.stats = ScanStats::default();
        let line = scan_summary(&report);
        assert!(
            line.starts_with(r"Nothing was scanned in C:\empty"),
            "{line}"
        );
        assert!(line.contains("nothing here is known to be clean"), "{line}");
        assert!(!line.contains("nothing was found"), "{line}");
        assert!(!line.contains("Scanned 0 files"), "{line}");
    }

    #[test]
    fn a_scan_whose_files_were_all_declined_says_that_and_not_that_it_found_nothing() {
        // The middle case, and the one a user reaches by pointing the window at
        // a folder of rule sets. `Nothing was scanned in …` is false — files
        // were found and read — and `Scanned 0 files (0 B)` is a clean bill of
        // health over files no rule was run against. The shortfall sentence is
        // what makes the count add up for a reader comparing it against what
        // they chose.
        let mut report = ScanReport::new(ScanTarget::Directory(PathBuf::from(r"C:\rules")));
        report.stats = ScanStats {
            files_declined: 3,
            bytes_declined: 17_500_000,
            ..ScanStats::default()
        };
        let line = scan_summary(&report);
        assert!(line.contains("Nothing was examined in C:\\rules"), "{line}");
        assert!(line.contains("3 files were recognised"), "{line}");
        assert!(!line.contains("Nothing was found"), "{line}");
        assert!(!line.contains("no files were left to look at"), "{line}");
        assert!(line.contains("nothing here is known to be clean"), "{line}");
    }

    #[test]
    fn one_declined_file_is_counted_in_the_singular_and_reads_as_english() {
        // `1 file were recognised` and `1 rule source inside archives were not
        // examined` are both what a bare plural produces, and one declined file
        // is exactly the case that reaches this line.
        let mut report = ScanReport::new(ScanTarget::Directory(PathBuf::from(r"C:\rules")));
        report.stats = ScanStats {
            files_declined: 1,
            declined_members: 1,
            files_scanned: 4,
            bytes_scanned: 900,
            ..ScanStats::default()
        };
        let line = scan_summary(&report);
        assert!(line.contains("1 file was recognised"), "{line}");
        assert!(line.contains("1 rule source inside an archive was not examined"), "{line}");

        report.stats.declined_members = 4;
        report.stats.files_declined = 2;
        let line = scan_summary(&report);
        assert!(line.contains("2 files were recognised"), "{line}");
        assert!(line.contains("4 rule sources inside archives were not examined"), "{line}");
        // And the opening sentence still reports the scan that did happen.
        assert!(line.contains("Scanned 4 files"), "{line}");
    }

    #[test]
    fn a_declined_file_does_not_make_an_ordinary_scan_look_like_it_examined_nothing() {
        // The control for the two sentences above: a run that examined files
        // and declined one beside them is an ordinary scan, and the declined
        // file is a shortfall line rather than the subject of the summary.
        let mut report = report(vec![file("a.exe", Verdict::Suspicious)]);
        report.stats.files_declined = 1;
        let line = scan_summary(&report);
        assert!(line.starts_with("Scanned 1,204 files"), "{line}");
        assert!(line.contains("1 file was recognised"), "{line}");
        assert!(line.contains("1 suspicious"), "{line}");
    }

    #[test]
    fn a_scan_that_opened_no_file_says_why_when_there_is_a_why() {
        // "Nothing was scanned" and "nothing was scanned because the one file
        // there is was excluded" are not the same news, and only the second
        // tells the user where to look.
        let mut report = ScanReport::new(ScanTarget::Directory(PathBuf::from(r"C:\empty")));
        report.stats = ScanStats {
            files_skipped: 1,
            ..ScanStats::default()
        };
        let line = scan_summary(&report);
        assert!(line.contains("1 file was skipped"), "{line}");
        assert!(!line.contains("1 file were skipped"), "{line}");
    }

    #[test]
    fn a_file_that_was_never_opened_is_not_described_as_a_directory() {
        // A single-file scan whose file could not be read reaches the same
        // branch, and `Nothing was scanned in C:\x\a.exe` would be the wrong
        // preposition for a file.
        let mut report = ScanReport::new(ScanTarget::File(PathBuf::from(r"C:\x\a.exe")));
        report.stats = ScanStats::default();
        report.failures = vec![(PathBuf::from(r"C:\x\a.exe"), "locked".into())];
        let line = scan_summary(&report);
        assert!(line.starts_with(r"Nothing was scanned: C:\x\a.exe"), "{line}");
        assert!(line.contains("1 file could not be read"), "{line}");
    }

    #[test]
    fn a_target_that_is_not_a_path_is_not_judged_by_the_file_rule() {
        // A process scan reads memory and opens no file, so `files_scanned` is
        // zero for a run that worked perfectly. Calling that "nothing was
        // scanned" would be a different falsehood for every non-path target —
        // a fix for one sentence that breaks four. Nothing in the window
        // produces one of these; the guard is here because this function does
        // not know that.
        let mut report = ScanReport::new(ScanTarget::AllProcesses);
        report.stats = ScanStats::default();
        let line = scan_summary(&report);
        assert!(!line.contains("Nothing was scanned"), "{line}");
        assert!(!line.is_empty(), "{line}");
    }

    #[test]
    fn a_read_failure_names_the_file_and_the_reason() {
        let line = read_failure(Path::new(r"C:\locked.exe"), "the file is in use");
        assert!(line.contains("locked.exe"), "{line}");
        assert!(line.contains("in use"), "{line}");
    }

    // -- clearing ------------------------------------------------------------

    #[test]
    fn a_run_that_cleared_nothing_says_nothing_about_clearing() {
        // `None` and not an empty string, so the caller draws no row at all: a
        // sentence about clearing over a run that cleared nothing is a sentence
        // about a decision nobody made.
        assert_eq!(cleared_line(0), None);
    }

    #[test]
    fn a_run_that_cleared_files_says_how_many_and_what_it_means() {
        let line = cleared_line(3).expect("three cleared files are worth a line");
        assert!(line.contains("3 files were cleared"), "{line}");
        assert!(line.contains("Nothing was done about them"), "{line}");
        // The claim the sentence exists to make, and the one that has to be
        // true: the rules matched, so this is not an acquittal.
        assert!(line.contains("the rules matched"), "{line}");
        assert!(line.contains("catalogue"), "{line}");
        // And the count is the group-of-threes one, because a whole-disk scan
        // clears four figures and `1204 files` reads as a bug.
        assert!(cleared_line(1_204)
            .expect("a four-figure count is still a line")
            .contains("1,204 files were cleared"));
    }

    #[test]
    fn one_cleared_file_takes_a_singular_verb_and_a_singular_pronoun() {
        // The count is one, which reaches the two traps in this sentence at
        // once: `1 files were` and `about them`.
        let line = cleared_line(1).expect("one cleared file is still worth a line");
        assert!(line.contains("1 file was cleared"), "{line}");
        assert!(line.contains("Nothing was done about it."), "{line}");
        assert!(!line.contains("about them"), "{line}");
    }

    // -- timestamps ----------------------------------------------------------

    #[test]
    fn a_timestamp_is_rendered_the_way_the_console_renders_it() {
        // The console's `local_time` uses this exact format. Two front ends
        // showing one scan's start time differently would be noticed by exactly
        // the user who ran both.
        let when = chrono::DateTime::parse_from_rfc3339("2026-03-04T05:06:07Z")
            .map(|t| t.with_timezone(&chrono::Utc))
            .expect("a fixed timestamp parses");
        let rendered = local_time(&when);
        assert_eq!(rendered.len(), 16, "{rendered}");
        assert_eq!(rendered.chars().nth(4), Some('-'));
        assert_eq!(rendered.chars().nth(10), Some(' '));
        assert_eq!(rendered.chars().nth(13), Some(':'));
        let expected = when
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M")
            .to_string();
        assert_eq!(rendered, expected);
    }

    #[test]
    fn the_thresholds_the_window_shows_are_the_engines() {
        // Not a formatting concern, but this is where a UI could quietly invent
        // its own band boundaries. The defaults are the console's.
        let thresholds = VerdictThresholds::default();
        assert_eq!(thresholds.suspicious, 30);
        assert_eq!(thresholds.malicious, 100);
        assert_eq!(thresholds.classify(29), Verdict::Clean);
        assert_eq!(thresholds.classify(30), Verdict::Suspicious);
        assert_eq!(thresholds.classify(99), Verdict::Suspicious);
        assert_eq!(thresholds.classify(100), Verdict::Malicious);
    }
}
