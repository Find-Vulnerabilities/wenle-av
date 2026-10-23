//! The scan pipeline: a database, a buffer, and a verdict.
//!
//! # The order of the stages is the cost model, and the verdict model
//!
//! ```text
//!   file bytes
//!       │  digests            three passes at memory speed
//!       ▼
//!   blocklist           exact match, decisive          a hash lookup
//!       │
//!       ▼
//!   PE parse            headers, sections, tables      one parse
//!       │
//!       ▼
//!   rules               prefilter -> matchers -> VM    the expensive one
//!       │
//!       ▼
//!   heuristics          entropy, sections, imports     a pass plus a table walk
//!       │
//!       ▼
//!   trust                signature, path               microseconds
//!       │
//!       ▼
//!   thresholds          score -> verdict
//! ```
//!
//! The order is not arbitrary. The blocklist runs first because it is the
//! cheapest stage and the only one whose answer is final: a file whose digest
//! is known is a file that does not need its import table read. The heuristics
//! run after the rules because a rule is evidence and a heuristic is a
//! suggestion, and a report reads better with the strongest claim first. Trust
//! runs last because it is the only stage that *subtracts*.
//!
//! # Nothing here acts
//!
//! The engine produces an [`Assessment`] and stops. It does not quarantine,
//! delete, block or notify. Those are decisions with consequences for a user's
//! files and they belong to the layer that knows what the user asked for — a
//! real-time interceptor blocks, a scheduled scan quarantines, a manual scan
//! reports and waits. An engine that acted would have to guess which one it was
//! running as, and it would guess wrong on the one occasion that mattered.
//!
//! # The three bands, and where they are decided
//!
//! Not here. This module accumulates detections and calls
//! [`Assessment::finalize`], which applies [`VerdictThresholds`]. What happens
//! above the threshold is a caller's decision: the yellow band exists so that a
//! caller can notify without acting, and this module deliberately offers no way
//! to tell the two apart except by reading the verdict.
//!
//! # One scanner per thread
//!
//! [`ScanEngine::scanner`] builds a [`Scanner`] that owns the rule engine's
//! working state: the prefilter's stamps, the operand stack, the candidate
//! list. Building one allocates; using one does not. A caller scanning a
//! directory should build one per thread and hand it to
//! [`ScanEngine::scan_with`] for every file, which is why that method exists
//! separately from the convenience [`ScanEngine::scan_bytes`].

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use av_core::{
    Assessment, Detection, DetectionSource, Digests, FileScanReport, HashKind, Hasher, ScanFailure,
    ScanOptions, Severity, VerdictThresholds,
};
use av_rules::database::RuleDatabase;
use av_rules::scanner::{ScanOutcome, Scanner};
use av_rules::vm::{Input, PeInput};
use av_signatures::catalog::CatalogIndex;

use crate::blocklist::Blocklist;
use crate::heuristics::{self, HeuristicConfig};
use crate::kind;
use crate::own::OwnFiles;
use crate::rules;
use crate::trust::{TrustAssessment, TrustPolicy};

/// Which digests a scan computes.
///
/// A knob rather than a constant because the passes cost real time on a
/// full-disk scan, and because the answer depends on what the loaded rule set
/// can do with them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestPolicy {
    /// Compute none. The blocklist cannot fire and the report has no file
    /// identity in it. For a caller that already has the digest — a real-time
    /// interceptor the kernel handed one to — or for a first sweep whose hits
    /// will be re-scanned.
    None,
    /// SHA-256, plus whichever of MD5 and SHA-1 the blocklist actually holds.
    ///
    /// The default. SHA-256 is always computed because it is the file's
    /// identity and every report, cache key and log line wants it; the other
    /// two are computed only when some rule names a digest of that width, so a
    /// corpus that names none costs no pass over the data.
    Needed,
    /// All three, whatever the blocklist holds. For a scan whose report is the
    /// deliverable — a full scan a user will read, or a support case where the
    /// MD5 is what the other party asked for.
    All,
}

impl DigestPolicy {
    /// Compute the digests this policy asks for, in one pass over `data`.
    fn compute(self, data: &[u8], blocklist: &Blocklist) -> Digests {
        let mut hashers = self.hashers(blocklist);
        for (_, hasher) in &mut hashers {
            hasher.update(data);
        }
        finish_digests(hashers)
    }

    /// The hashers this policy asks for, before any bytes are fed.
    ///
    /// The scan of a file larger than its size cap reads the head and hands the
    /// rest to these as it goes past, so the digest covers the whole file while
    /// only the head is held. See [`av_fs::Reader::read_head`]. One list, used
    /// by both the whole-buffer and the streaming path, so the two cannot
    /// disagree about which digests a policy produces.
    fn hashers(self, blocklist: &Blocklist) -> Vec<(HashKind, Hasher)> {
        let mut kinds = Vec::with_capacity(3);
        match self {
            DigestPolicy::None => {}
            DigestPolicy::All => kinds.extend([HashKind::Md5, HashKind::Sha1, HashKind::Sha256]),
            DigestPolicy::Needed => {
                kinds.push(HashKind::Sha256);
                if blocklist.needs(HashKind::Sha1) {
                    kinds.push(HashKind::Sha1);
                }
                if blocklist.needs(HashKind::Md5) {
                    kinds.push(HashKind::Md5);
                }
            }
        }
        kinds.into_iter().map(|kind| (kind, kind.hasher())).collect()
    }
}

/// Turn finished hashers into the report's digests.
fn finish_digests(hashers: Vec<(HashKind, Hasher)>) -> Digests {
    let mut digests = Digests::default();
    for (kind, hasher) in hashers {
        let value = Some(hasher.finish());
        match kind {
            HashKind::Md5 => digests.md5 = value,
            HashKind::Sha1 => digests.sha1 = value,
            HashKind::Sha256 => digests.sha256 = value,
        }
    }
    digests
}

/// Everything a scan needs that is not the file.
///
/// Owns the rule set, so a scan borrows the engine and nothing else. The
/// alternative — a database passed per call — would let two scans of one file
/// disagree because the callers handed over different rule sets, and that is
/// the kind of difference a report cannot show.
#[derive(Debug)]
pub struct ScanEngine {
    database: RuleDatabase,
    blocklist: Blocklist,
    thresholds: VerdictThresholds,
    heuristics: HeuristicConfig,
    trust: TrustPolicy,
    digests: DigestPolicy,
    /// The catalog store's digests, when a caller supplied them.
    ///
    /// Evidence rather than policy, which is why it lives here and not in
    /// [`TrustPolicy`]: it is 6.5 MB read off this machine's disk, the same kind
    /// of thing as the rule database, and a policy that carried one could not be
    /// compared or written to a configuration file.
    ///
    /// An [`Arc`] because a scan walks tens of thousands of files and every one
    /// of them consults it; cloning the index per file would be a copy of a
    /// 6.5 MB structure per file.
    catalog: Option<Arc<CatalogIndex>>,
    /// The files this product wrote, by digest. Built from the database, which
    /// is the only part of a scan with evidence about provenance — see
    /// [`mod@crate::own`] for the measurement that put it here.
    own: OwnFiles,
}

impl ScanEngine {
    /// An engine over a compiled rule set, with the default policy everywhere.
    ///
    /// The blocklist is built here, from the rule set, because the hashes in a
    /// rule's metadata *are* the blocklist: there is no second corpus and no
    /// import step that could fall behind.
    pub fn new(database: RuleDatabase) -> Self {
        let blocklist = Blocklist::build(&database);
        // Taken before the database is moved, and taken here rather than by a
        // caller because a caller who forgot would produce an engine that
        // reports the product's own corpus as malware — a mistake nobody would
        // notice until it happened, in a report, to a user.
        let own = OwnFiles::from_database(&database);
        log::debug!(
            "scan engine: {} rules, {} blocklisted digests (md5 {}, sha1 {}, sha256 {}), \
             {} unreadable literal(s)",
            database.len(),
            blocklist.len(),
            blocklist.count_of(HashKind::Md5),
            blocklist.count_of(HashKind::Sha1),
            blocklist.count_of(HashKind::Sha256),
            blocklist.rejected().len(),
        );
        Self {
            database,
            blocklist,
            thresholds: VerdictThresholds::default(),
            heuristics: HeuristicConfig::default(),
            trust: TrustPolicy::default(),
            digests: DigestPolicy::Needed,
            catalog: None,
            own,
        }
    }

    /// The files this product's own data consists of, as far as this engine
    /// knows.
    pub fn own_files(&self) -> &OwnFiles {
        &self.own
    }

    /// Record one more file this product wrote.
    ///
    /// For a front end that loaded an artefact of its own the database cannot
    /// know about — a catalog index, say. See [`OwnFiles::insert`].
    pub fn add_own_file(&mut self, sha256: impl Into<String>, what: impl Into<String>) {
        self.own.insert(sha256, what);
    }

    /// Where the yellow and red lines sit. See [`VerdictThresholds`].
    pub fn with_thresholds(mut self, thresholds: VerdictThresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Which structural heuristics run, and at what thresholds.
    pub fn with_heuristics(mut self, heuristics: HeuristicConfig) -> Self {
        self.heuristics = heuristics;
        self
    }

    /// How much a file's trust signals are worth, and whether they count.
    pub fn with_trust(mut self, trust: TrustPolicy) -> Self {
        self.trust = trust;
        self
    }

    /// Which digests a scan computes. Defaults to [`DigestPolicy::Needed`].
    pub fn with_digests(mut self, digests: DigestPolicy) -> Self {
        self.digests = digests;
        self
    }

    /// The catalog store's digests, for the trust layer to match against.
    ///
    /// Absent by default, and its absence is not neutral: without it the trust
    /// layer can only see *claims* — an embedded certificate — and not the one
    /// piece of evidence on this machine that cannot be forged, which is that
    /// some catalog published by Microsoft lists these exact bytes. A scan run
    /// without it will report Microsoft's own binaries as suspicious, and the
    /// measured size of that problem is 742 files in one `System32`.
    ///
    /// The caller owns the decision to build one because building it reads
    /// 1.1 GB off disk in about a second, and a scan of three files should not
    /// pay for that. [`CatalogIndex::from_store`] is the usual source.
    pub fn with_catalog(mut self, catalog: Option<Arc<CatalogIndex>>) -> Self {
        self.catalog = catalog;
        self
    }

    /// The catalog index a scan consults, if one was supplied.
    pub fn catalog(&self) -> Option<&CatalogIndex> {
        self.catalog.as_deref()
    }

    /// The rule set being scanned with.
    pub fn database(&self) -> &RuleDatabase {
        &self.database
    }

    /// The exact-match list harvested from that rule set.
    pub fn blocklist(&self) -> &Blocklist {
        &self.blocklist
    }

    /// The thresholds a verdict is read off.
    pub fn thresholds(&self) -> &VerdictThresholds {
        &self.thresholds
    }

    /// The structural heuristics a scan runs, and at what thresholds.
    ///
    /// Public because the archive stage runs the same heuristics over archive
    /// members, and a member judged by a different configuration than the file
    /// containing it would make a scan's answer depend on where the bytes
    /// happened to be sitting.
    pub fn heuristics(&self) -> &HeuristicConfig {
        &self.heuristics
    }

    /// A rule-engine scanner, for a caller that will scan more than one file.
    ///
    /// Build one per thread and keep it. See the module documentation.
    pub fn scanner(&self) -> Scanner<'_> {
        Scanner::new(&self.database)
    }

    /// Scan a buffer with a scanner the caller already has.
    pub fn scan_with(
        &self,
        scanner: &mut Scanner<'_>,
        path: &Path,
        data: &[u8],
        options: &ScanOptions,
    ) -> FileScanReport {
        let started = Instant::now();
        // Digests are taken over the whole file, before any size cap applies. A
        // blocklist hash names a file, and a digest of the first 256 MiB of a
        // 300 MiB file is a digest of nothing.
        let digests = self.digests.compute(data, &self.blocklist);
        self.scan_prepared(scanner, path, data, data.len() as u64, digests, options, started)
    }

    /// The body of a scan, once the bytes and their digests are in hand.
    ///
    /// `size` is the file's real size, which is not `data.len()` when only the
    /// head of a file larger than `max_file_size` was kept: the truncation
    /// note, the per-file time budget and the report's `size` all speak about
    /// the file, not about the part of it this scan could see. `started` is
    /// passed in because the reading path computes the digest as it reads, and
    /// that time belongs to the file.
    fn scan_prepared(
        &self,
        scanner: &mut Scanner<'_>,
        path: &Path,
        data: &[u8],
        size: u64,
        digests: Digests,
        options: &ScanOptions,
        started: Instant,
    ) -> FileScanReport {

        // -- the product's own data ------------------------------------------
        //
        // Before anything is examined, and this is the one place it can be
        // done: the digest is computed anyway for the blocklist, so the
        // question costs a hash-table lookup, while asking it any later would
        // mean running ten thousand rules against a file that is made of the
        // patterns they search for. Reported rather than dropped so that a user
        // asking "why was this not detected?" gets the answer — see
        // [`mod@crate::own`] for the measurement that put this here.
        if let Some(what) = self.own_hit(&digests, data) {
            return self.own_file_report(path, data, digests, what, started);
        }

        // What actually gets examined. Every stage below reads this and not
        // `data`, so that no stage can examine more than the cap while another
        // examines less.
        let examined = match options.max_file_size {
            Some(cap) => &data[..data.len().min(usize::try_from(cap).unwrap_or(usize::MAX))],
            None => data,
        };
        let truncated = (examined.len() as u64) < size;

        // Parsed once and shared. `PeInput` reads every table the `pe` module
        // exposes, so the rules, the heuristics and the trust layer all ask the
        // same parse rather than each doing their own.
        let image = match PeInput::parse(examined) {
            Ok(image) => Some(image),
            Err(e) => {
                // A buffer that is not a PE is the ordinary case, not a
                // problem: most files are not. Anything else is worth a line,
                // because it means a file that claimed to be one was not.
                if !e.is_absence() {
                    log::trace!("{}: not a readable PE: {e}", path.display());
                }
                None
            }
        };

        let kind = match &image {
            Some(image) => kind::refine(kind::classify(Some(path), examined), image),
            None => kind::classify(Some(path), examined),
        };

        // -- exact match -----------------------------------------------------
        let blocked = self.blocklist.lookup(&digests).map(|hit| {
            let mut detection = Detection::new(
                format!("blocklist/{}", hit.kind.as_str()),
                format!(
                    "The file's {} digest is one this product's rule set names as a known \
                     sample: {}.",
                    hit.kind.as_str(),
                    hit.hash,
                ),
                Severity::Critical,
                DetectionSource::Reputation,
            )
            // Incontestable as well as decisive, and this is the one route to a
            // verdict where that is not a judgement call: these bytes are the
            // bytes the rule set names, and no certificate answers a hash.
            .incontestable();
            // Named after the family the carrying rule attributes it to, when
            // it attributes one. A report that says `blocklist/sha256` where it
            // could say `Win32.Ransomware.LockBit` has thrown away the only
            // part a user can act on.
            if let Some(rule) = self.database.rule(hit.rule) {
                if let Some(threat) = rule.metadata.threat() {
                    detection = detection.with_threat(threat);
                }
            }
            detection
        });

        // -- a rule source this product did not write -------------------------
        //
        // After the blocklist and before the rules, which is the only position
        // that works: a file whose digest is a known sample must be convicted
        // rather than explained, and every rule below this line would match a
        // file that is made of the strings rules search for. Placed here rather
        // than beside the digest check at the top because the kind it gates on is
        // only known once the file has been classified. See
        // [`crate::own::foreign_rule_source`] for why the digest whitelist does
        // not cover this case — measured, the near-copy of our own corpus that
        // the whitelist misses scans to 1,126 detections.
        if blocked.is_none() {
            if let Some(source) = crate::own::foreign_rule_source(&kind, examined) {
                return self.rule_source_report(path, data, digests, source, started);
            }
        }

        // -- rules -----------------------------------------------------------
        let outcome = match &image {
            Some(image) => scanner.scan_with(examined, &Input::with_pe(examined, image)),
            None => scanner.scan_with(examined, &Input::new(examined)),
        };
        let mut rule_detections = self.rule_detections(&outcome, examined);
        // Strongest first, and by name within a severity, so that two runs over
        // one file produce the same report in the same order.
        rule_detections.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        // -- heuristics ------------------------------------------------------
        let heuristic_detections = match options.heuristics {
            true => heuristics::evaluate(examined, image.as_ref(), &self.heuristics),
            false => Vec::new(),
        };

        // -- archives --------------------------------------------------------
        // Runs over the whole file and not over `examined`. A size cap is about
        // how much of a file this scan will look at directly; it is not a
        // statement that the rest of the file is uninteresting, and a container
        // whose last member sits past the cap is exactly the case where the cap
        // would hide something. The expansion budget is the ceiling that applies
        // in here, and it is a separate number for exactly this reason.
        let archive = crate::archive::walk(self, scanner, data, options);

        // -- trust -----------------------------------------------------------
        let trust = match options.trust {
            true => self
                .trust
                .assess(path, image.as_ref(), self.catalog.as_deref()),
            false => TrustAssessment::default(),
        };

        let mut assessment = Assessment::clean();
        if let Some(blocked) = blocked {
            assessment.push(blocked);
        }
        for detection in rule_detections {
            assessment.push(detection);
        }
        for detection in heuristic_detections {
            assessment.push(detection);
        }
        // After the file's own stages and before trust. A member's finding is a
        // term in the same sum as everything else, which is what makes a zip
        // holding a packed executable come out as red: neither the packing nor
        // the container alone is decisive, and together they are.
        if let Some(walk) = &archive {
            for detection in &walk.detections {
                assessment.push(detection.clone());
            }
        }

        // The discount runs before the notes are recorded. A note scores
        // nothing so the order cannot change the arithmetic, but the discount
        // reads the detection list and it is clearer to take it while the list
        // is exactly the detections.
        self.trust.discount(&mut assessment, &trust);

        // -- notes -----------------------------------------------------------
        // Observations that are not detections. Every one is [`Severity::Info`],
        // which scores zero, so none of them can colour a verdict. They exist so
        // that a report can answer "why was nothing found" and "was this file
        // really looked at" — the two questions a clean verdict invites and that
        // a scanner answering neither is asking to be distrusted over.
        if outcome.global_gate_failed {
            assessment.push(info(
                "scan/rule-gate",
                "The rule set's global rule did not match, so no other rule was evaluated \
                 against this file. This is the ordinary outcome for a file that is not the \
                 kind of file the rule set is written for.",
            ));
        }
        if truncated {
            assessment.push(info(
                "scan/truncated",
                format!(
                    "Only the first {} of {} bytes were examined; the configured size limit \
                     stopped the scan part way through this file.",
                    examined.len(),
                    size,
                ),
            ));
        }
        if let Some(sentence) = trust_sentence(&trust) {
            assessment.push(info("scan/trust", sentence));
        }
        if let Some(walk) = &archive {
            // What was inside, in one line. Always recorded, including for a
            // container that held nothing: "the zip was opened and every member
            // was examined" and "the zip was never opened" are different answers
            // to a user asking why nothing was found, and the report is the only
            // place that distinction can be made.
            if walk.summary.examined_anything() || !walk.summary.is_complete() {
                assessment.push(info("scan/archive", walk.summary.describe()));
            }
            for skip in &walk.summary.skipped {
                // Every skip, by name. The summary above counts them by reason;
                // this says which member each one was, because "2 encrypted" is
                // actionable only if the user can see which two.
                assessment.push(info("scan/archive-skipped", skip.describe()));
            }
        }

        // -- verdict ---------------------------------------------------------
        let elapsed = started.elapsed();
        // The budget for *this* file, which is the configured slack plus the
        // time this file's own size justifies. A flat budget here made every
        // file above about thirty megabytes `Unknown` however well the scan had
        // gone; see `ScanOptions::per_file_timeout`.
        let budget = options.per_file_budget_for(size);
        let over_budget = budget.is_some_and(|budget| elapsed > budget);
        // Whether the scan found anything that *scores*. Not
        // `assessment.is_detection()`, which reads the verdict — and the verdict
        // is still `Clean` here, because `finalize` has not run. Asking it would
        // answer "no" for every file and turn every over-budget scan into
        // `Unknown`, discarding findings that were already in hand.
        let found_something = assessment
            .detections
            .iter()
            .any(|d| d.decisive || d.severity > Severity::Info);
        let error = if over_budget && !found_something {
            // A file that took longer than its budget and produced nothing is a
            // file this scan cannot vouch for. Calling it clean would be
            // claiming to have looked, when the evidence is that the look did
            // not finish — so it is `Unknown`, the one verdict that says so.
            let mut unknown = Assessment::unknown(format!(
                "the scan exceeded its {:.3}s budget before reaching a conclusion",
                budget.map(|d| d.as_secs_f64()).unwrap_or_default(),
            ));
            // Whatever was seen on the way is kept. An incomplete scan that
            // noticed something is more useful than one that noticed nothing,
            // and the verdict is `Unknown` either way.
            for detection in assessment.detections.drain(..) {
                unknown.push(detection);
            }
            // `Assessment::unknown` opens with the reason it is unknown, which
            // belongs at the end of a list that reads strongest-first.
            if unknown.detections.len() > 1 {
                unknown.detections.rotate_left(1);
            }
            assessment = unknown;
            Some(format!("per-file time budget of {budget:?} exceeded"))
        } else {
            if over_budget {
                assessment.push(info(
                    "scan/over-budget",
                    format!(
                        "The scan took {elapsed:?}, longer than the budget of {budget:?} \
                         this file's size allows."
                    ),
                ));
            }
            assessment.finalize(&self.thresholds);
            // After `finalize`, and only here: the cap edits the verdict rather
            // than the score, so it needs the verdict to exist. The `Unknown`
            // arm above is deliberately not capped — a scan that could not
            // finish has no evidence either way, and trust is evidence.
            self.trust.cap_verdict(&mut assessment, &trust);
            // And then, for the narrower case, cleared outright. The order
            // matters: `cap_verdict` moves a verdict down one band, and
            // `clear_generic` moves it to `Clean` — running them the other way
            // round would leave a capped `Suspicious` sitting where a proven
            // identity had already answered the question. See
            // [`TrustPolicy::clear_generic`] for why the two are entitled to
            // different amounts of confidence.
            self.trust.clear_generic(&mut assessment, &trust);
            None
        };

        FileScanReport {
            path: path.to_path_buf(),
            kind,
            size,
            digests,
            assessment,
            duration: elapsed,
            scanned_bytes: examined.len() as u64,
            from_cache: false,
            error,
            archive: archive.map(|walk| walk.summary),
        }
    }

    /// Scan a buffer, building a scanner for the occasion.
    ///
    /// Convenient for one file and wasteful for many. See
    /// [`ScanEngine::scan_with`].
    pub fn scan_bytes(&self, path: &Path, data: &[u8], options: &ScanOptions) -> FileScanReport {
        let mut scanner = self.scanner();
        self.scan_with(&mut scanner, path, data, options)
    }

    /// Read a file and scan it.
    ///
    /// A file that cannot be read is [`av_core::Verdict::Unknown`] with the reason
    /// attached, never a clean verdict. That distinction is the whole reason
    /// the verdict enum has an `Unknown`: a scanner that reports every file it
    /// could not open as clean is a scanner that misses whatever made the file
    /// unopenable.
    ///
    /// # Reading through the backup privilege
    ///
    /// The read goes through [`mod@av_fs::read`], which enables `SeBackupPrivilege`
    /// in this process's token on first use so that a file whose permissions
    /// exclude the scanning account is read rather than refused. On a machine
    /// where the privilege is not held — a console run by a standard user — the
    /// read still works for every file that account can already open, and the
    /// ones it cannot are reported as unreadable with the reason attached
    /// rather than being skipped in silence.
    ///
    /// That is a change to the *process*, not to this call: see
    /// [`av_fs::default_reader`] for what it costs and why it is not done per
    /// file. What it is deliberately not is a change to the *verdict*. A file
    /// read through the backup privilege is scored by exactly the same rules,
    /// thresholds and trust policy as one read without it, because which
    /// account is asking must never be part of what a file *is*.
    pub fn scan_file(&self, path: &Path, options: &ScanOptions) -> FileScanReport {
        let mut scanner = self.scanner();
        self.scan_file_with(&mut scanner, path, options)
    }

    /// What this product knows the file to be, when it recognises it.
    ///
    /// `None` for every file a scan will examine, which is nearly all of them.
    ///
    /// A [`DigestPolicy::None`] caller is asking for speed, not asking to be
    /// exempt from recognising its own corpus, so the digest is computed here
    /// for the one question that needs it. The cost lands only on a policy that
    /// asked for no hashing at all and a database that knows its own sources,
    /// and it buys an answer that does not depend on how the scan was
    /// configured.
    fn own_hit<'a>(&'a self, digests: &Digests, data: &[u8]) -> Option<&'a str> {
        if self.own.is_empty() {
            return None;
        }
        match digests.sha256.as_deref() {
            Some(sha) => self.own.describes(sha),
            None => self.own.describes(&HashKind::Sha256.digest(data)),
        }
    }

    /// The report for a file this product recognises as its own.
    ///
    /// See [`Self::declined_report`] for the shape, which this and
    /// [`Self::rule_source_report`] share. The sentence is the one that matters:
    /// a rule source contains the very strings its rules search for, so a scan
    /// of one produces detections that are true of the corpus and false of the
    /// file.
    fn own_file_report(
        &self,
        path: &Path,
        data: &[u8],
        digests: Digests,
        what: &str,
        started: Instant,
    ) -> FileScanReport {
        let sentence = format!(
            "This file is {what} — {}. It was not examined: a rule source contains the \
             very strings its rules search for, so scanning one reports the corpus as \
             the malware it describes.",
            digests.sha256.as_deref().unwrap_or("no digest taken"),
        );
        self.declined_report(
            path,
            data,
            digests,
            super::own::PRODUCT_FILE_RULE,
            sentence,
            started,
        )
    }

    /// The report for a rule source this product did not write.
    ///
    /// The same shape as [`Self::own_file_report`] and a different claim, which
    /// is why a front end keeps them apart: the digest whitelist says these bytes
    /// are ours, and this says only that the file is made of rule syntax.
    fn rule_source_report(
        &self,
        path: &Path,
        data: &[u8],
        digests: Digests,
        source: av_rules::source::RuleSource,
        started: Instant,
    ) -> FileScanReport {
        let digest = digests.sha256.as_deref().unwrap_or("not taken");
        let sentence = if source.compiled {
            // The same decline with a different reason to give. A compiled
            // container is not something a reader can open and check, so
            // printing a count of rules and conditions for it would be
            // inventing two numbers — it states neither.
            format!(
                "This file is a compiled rule set — the form this product's own rule \
                 database is built from — and it is not one this product compiled. It was \
                 not examined: a compiled rule set contains the very strings its rules \
                 search for, so scanning one reports the corpus as the malware it \
                 describes. If this file is not yours, its {digest} digest is what to look \
                 up."
            )
        } else {
            format!(
                "This file is written in this product's rule language — {} rules, {} \
                 conditions — and it is not one this product compiled. It was not examined: \
                 a rule source contains the very strings its rules search for, so scanning \
                 one reports the corpus as the malware it describes. If this file is not \
                 yours, its {digest} digest is what to look up.",
                source.rules, source.conditions,
            )
        };
        self.declined_report(
            path,
            data,
            digests,
            super::own::RULE_SOURCE_RULE,
            sentence,
            started,
        )
    }

    /// A `Clean` report for a file the engine declined to examine, with the
    /// reason attached.
    ///
    /// `Clean`, with the reason as an informational detection rather than as a
    /// finding. `Severity::Info` scores nothing, so the file stays out of the
    /// band that acts and out of the list a reader takes as detections, and the
    /// sentence is still there for the question [`Assessment::suppressed`]
    /// exists to answer: "why was this not detected?". `Unknown` would be wrong
    /// in the other direction — that is the verdict for a file the scan could not
    /// judge, and this is a file the scan judged and had no reason to examine.
    ///
    /// `scanned_bytes` is zero. The file was read, because that is how it was
    /// recognised, but reading a file to identify it is not examining it, and a
    /// total that counted these bytes would be claiming work that was not done.
    /// A front end that wants to say how much it examined asks
    /// [`crate::own::is_product_file`] and
    /// [`crate::own::is_foreign_rule_source`] rather than reading this number.
    fn declined_report(
        &self,
        path: &Path,
        data: &[u8],
        digests: Digests,
        rule_id: &str,
        sentence: String,
        started: Instant,
    ) -> FileScanReport {
        let mut assessment = Assessment::clean();
        assessment.push(info(rule_id, sentence));
        assessment.finalize(&self.thresholds);
        FileScanReport {
            path: path.to_path_buf(),
            kind: kind::classify(Some(path), data),
            size: data.len() as u64,
            digests,
            assessment,
            duration: started.elapsed(),
            scanned_bytes: 0,
            from_cache: false,
            error: None,
            archive: None,
        }
    }

    /// Read a file and scan it with a scanner the caller already has.
    pub fn scan_file_with(
        &self,
        scanner: &mut Scanner<'_>,
        path: &Path,
        options: &ScanOptions,
    ) -> FileScanReport {
        // `av_fs::read`, not `std::fs::read`. The difference is that the
        // former tries the backup privilege and, when that is not available,
        // refuses with a reason that names why — `access denied … this process
        // does not hold SeBackupPrivilege` rather than a bare `os error 5`.
        // Both end up as the same `Unknown` verdict below; only the sentence a
        // user reads is different, and the sentence is the whole point, because
        // it is the difference between "your scanner is broken" and "run this
        // elevated".
        let started = Instant::now();
        // A scan that examines at most `max_file_size` bytes reads at most that
        // many. The digest still covers the whole file — `read_head` feeds
        // every byte past the cap to these hashers as it goes past — so a
        // 1.5 GB installer this product will look at 256 MiB of costs 256 MiB
        // of memory rather than 1.5 GB. Before this, the whole file was read
        // and then truncated to the cap. See [`av_fs::Reader::read_head`].
        let read = match options.max_file_size {
            Some(limit) => {
                let mut hashers = self.digests.hashers(&self.blocklist);
                let head = {
                    let mut feed = |chunk: &[u8]| {
                        for (_, hasher) in &mut hashers {
                            hasher.update(chunk);
                        }
                    };
                    av_fs::read_head(path, limit, &mut feed)
                };
                head.map(|head| (head.data, head.size, finish_digests(hashers)))
            }
            None => av_fs::read(path).map(|data| {
                let size = data.len() as u64;
                let digests = self.digests.compute(&data, &self.blocklist);
                (data, size, digests)
            }),
        };

        match read {
            Ok((data, size, digests)) => {
                self.scan_prepared(scanner, path, &data, size, digests, options, started)
            }
            Err(e) => {
                let failure = ScanFailure::from_error(path, &av_core::AvError::io_at(path, e));
                log::debug!("{}: {failure:?}", path.display());
                let digests = self.digests.compute(&[], &self.blocklist);
                let mut report =
                    self.scan_prepared(scanner, path, &[], 0, digests, options, started);
                report.assessment = Assessment::unknown(failure.reason.clone());
                report.error = Some(failure.reason);
                report.size = 0;
                report.scanned_bytes = 0;
                report
            }
        }
    }

    /// Convert every reportable rule match into a detection.
    fn rule_detections(&self, outcome: &ScanOutcome, data: &[u8]) -> Vec<Detection> {
        outcome
            .reportable()
            .filter_map(|matched| {
                // A match names its rule by index, and the index came from this
                // database. `None` would mean the scanner and the engine
                // disagree about which rule set they are running, which cannot
                // happen — but dropping the detection is the right response to
                // a state that cannot happen and would otherwise be a panic.
                let rule = self.database.rule(matched.rule)?;
                Some(rules::detection(rule, matched, data))
            })
            .collect()
    }
}

/// A note recorded in the report. Scores nothing by construction.
fn info(id: &str, description: impl Into<String>) -> Detection {
    Detection::new(id, description, Severity::Info, DetectionSource::Heuristic)
}

/// One sentence describing what trust concluded, when it concluded anything.
///
/// `None` when the reasons came to nothing, so that a scan of an unsigned file
/// in an ordinary directory does not carry a line saying so. The absence of the
/// line is the statement.
fn trust_sentence(trust: &TrustAssessment) -> Option<String> {
    if !trust.is_trusted() {
        return None;
    }
    let reasons: Vec<String> = trust.reportable().map(|r| r.describe()).collect();
    Some(format!(
        "Trust signals for this file allow up to {} points to be discounted: {}",
        trust.magnitude,
        reasons.join(" ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{FileKind, ScanTarget, Verdict};
    use av_rules::database::RuleSource;
    use std::path::PathBuf;
    use std::time::Duration;

    /// A rule set shaped like the real corpus: one rule that names a family,
    /// one weak indicator that names nothing, and one rule whose only job is to
    /// carry a sample's digest.
    ///
    /// The digest-carrying rule's own condition matches nothing here — its
    /// string is in no fixture. That is deliberate: it isolates the blocklist
    /// stage, so a test meaning to exercise the digest path cannot pass because
    /// a rule fired instead.
    const RULES: &str = r#"
rule evil_marker {
    meta:
        description = "The file carries the marker this rule is written for."
        severity = "high"
        category = "trojan"
        family = "TestFamily"
    strings:
        $marker = "WENLE-TEST-EVIL-MARKER"
    condition:
        $marker
}

rule weak_indicator {
    meta:
        description = "The file carries the weak indicator this rule is written for."
        severity = "medium"
    strings:
        $weak = "WENLE-TEST-WEAK-INDICATOR"
    condition:
        $weak
}

rule known_sample {
    meta:
        description = "A sample this rule set already knows by content."
        severity = "critical"
        category = "ransomware"
        family = "TestRansom"
        hash = "4d11186aed035cc624d553e10db358492c84a7cd6b9670d92123c144930450aa"
        decisive = true
    strings:
        $body = "WENLE-TEST-KNOWN-SAMPLE-BODY"
    condition:
        $body
}
"#;

    /// The buffer whose SHA-256 the `known_sample` rule carries. Seven bytes,
    /// not a PE, containing no rule's string — so the digest is the only thing
    /// that can fire on it.
    const KNOWN_BAD: &[u8] = b"hash-me";

    /// A rule set with a global gate, used only to exercise the gate note.
    const GATED: &str = r#"
global rule must_be_an_image {
    meta:
        description = "The rule set is written for executable images."
    strings:
        $mz = { 4D 5A }
    condition:
        $mz
}

rule needs_the_gate {
    meta:
        severity = "high"
    strings:
        $marker = "WENLE-TEST-EVIL-MARKER"
    condition:
        $marker
}
"#;

    const MARKER: &[u8] = b"MZ....WENLE-TEST-EVIL-MARKER....";
    const WEAK: &[u8] = b"WENLE-TEST-WEAK-INDICATOR";

    fn engine_over(source: &str) -> ScanEngine {
        let (database, report) = RuleDatabase::compile(source);
        assert_eq!(report.refusals.len(), 0, "{:?}", report.refusals);
        ScanEngine::new(database)
    }

    fn engine() -> ScanEngine {
        let engine = engine_over(RULES);
        assert_eq!(engine.database().len(), 3);
        engine
    }

    /// Structural heuristics off, trust off: the fixture for a test about
    /// rules, so that nothing else can contribute to the score it asserts.
    fn rules_only() -> ScanOptions {
        ScanOptions {
            heuristics: false,
            trust: false,
            ..ScanOptions::default()
        }
    }

    fn path() -> PathBuf {
        PathBuf::from("C:\\Users\\test\\Downloads\\sample.bin")
    }

    #[test]
    fn the_fixture_digest_is_the_one_the_rule_carries() {
        // Everything below depends on this, so it is checked rather than
        // trusted. A typo here would make the blocklist tests pass by never
        // firing at all — which is the failure mode a test for a detector
        // should be least willing to accept.
        assert_eq!(
            HashKind::Sha256.digest(KNOWN_BAD),
            "4d11186aed035cc624d553e10db358492c84a7cd6b9670d92123c144930450aa"
        );
    }

    #[test]
    fn an_unknown_clean_file_is_clean_and_says_so() {
        let report = engine().scan_bytes(&path(), b"nothing interesting here", &rules_only());
        assert_eq!(report.verdict(), Verdict::Clean);
        assert!(!report.is_detection());
        assert_eq!(report.kind, FileKind::Other);
        assert!(report.error.is_none());
        assert_eq!(report.size, 24);
        assert_eq!(report.scanned_bytes, 24);
        assert!(!report.from_cache);
        assert!(report.archive.is_none());
    }

    #[test]
    fn a_file_matching_a_rule_is_malicious_and_carries_the_rule_metadata() {
        let report = engine().scan_bytes(&path(), MARKER, &rules_only());
        assert_eq!(report.verdict(), Verdict::Malicious);
        let detection = report
            .assessment
            .detections
            .iter()
            .find(|d| d.rule_id == "evil_marker")
            .expect("the marker rule fired");
        assert_eq!(detection.severity, Severity::High);
        assert_eq!(detection.score, 100);
        assert_eq!(detection.source, DetectionSource::Signature);
        assert_eq!(
            detection.threat.as_ref().and_then(|t| t.family.as_deref()),
            Some("TestFamily")
        );
        assert_eq!(detection.display_name(), "Win32.Trojan.TestFamily");
        // `MZ` at 0, four filler bytes, and the marker at 6.
        assert_eq!(detection.locations.first().map(|l| l.offset), Some(6));
    }

    #[test]
    fn a_known_sample_is_decisive_whatever_else_is_found() {
        let report = engine().scan_bytes(&path(), KNOWN_BAD, &rules_only());
        assert_eq!(report.verdict(), Verdict::Malicious);
        let blocked = report
            .assessment
            .detections
            .iter()
            .find(|d| d.rule_id.starts_with("blocklist/"))
            .expect("the digest is blocklisted");
        assert!(blocked.decisive);
        assert_eq!(blocked.source, DetectionSource::Reputation);
        assert_eq!(blocked.severity, Severity::Critical);
        // The name comes from the rule that carried the digest, not from the
        // digest itself: `blocklist/sha256` tells a user nothing.
        assert_eq!(blocked.display_name(), "Win32.Ransomware.TestRansom");
        assert!(
            blocked
                .description
                .contains(&HashKind::Sha256.digest(KNOWN_BAD)),
            "{}",
            blocked.description
        );
        // A digest is not located anywhere, so there is nothing to point at.
        assert!(blocked.locations.is_empty());
    }

    #[test]
    fn a_clean_file_is_not_named_after_a_blocklisted_one() {
        // The control. A different buffer of the same length must not hit.
        let report = engine().scan_bytes(&path(), b"hash-me-not", &rules_only());
        assert_eq!(report.verdict(), Verdict::Clean);
    }

    #[test]
    fn the_report_carries_the_digests_that_were_asked_for() {
        let policy = |p| engine().with_digests(p);
        let all = policy(DigestPolicy::All).scan_bytes(&path(), b"x", &rules_only());
        assert!(all.digests.md5.is_some() && all.digests.sha1.is_some());
        assert!(all.digests.sha256.is_some());

        // `Needed` skips what the blocklist cannot use. The fixture carries one
        // SHA-256 and no MD5 or SHA-1, so neither of those passes runs.
        let needed = policy(DigestPolicy::Needed).scan_bytes(&path(), b"x", &rules_only());
        assert!(needed.digests.sha256.is_some());
        assert!(needed.digests.md5.is_none());
        assert!(needed.digests.sha1.is_none());

        let none = policy(DigestPolicy::None).scan_bytes(&path(), b"x", &rules_only());
        assert!(none.digests.is_empty());

        // And with no digests there is nothing to compare, so the blocklist
        // cannot fire. That is the trade `None` makes, and the reason it is not
        // the default. The fixture's digest rule cannot cover for it: its own
        // condition matches nothing here.
        let report = policy(DigestPolicy::None).scan_bytes(&path(), KNOWN_BAD, &rules_only());
        assert_eq!(report.verdict(), Verdict::Clean);
    }

    #[test]
    fn nothing_is_read_past_the_size_cap_but_the_digest_is_of_the_whole_file() {
        let data = b"MZ....WENLE-TEST-EVIL-MARKER....trailing";
        let capped = ScanOptions {
            max_file_size: Some(10),
            ..rules_only()
        };
        let report = engine().scan_bytes(&path(), data, &capped);
        assert_eq!(report.size, data.len() as u64);
        assert_eq!(report.scanned_bytes, 10);
        // The marker is past the cap, so the rule cannot have seen it.
        assert!(!report.is_detection(), "{:?}", report.assessment.detections);
        assert!(
            report
                .assessment
                .detections
                .iter()
                .any(|d| d.rule_id == "scan/truncated"),
            "the report has to say the file was not fully examined"
        );
        // And the digest is still of the whole buffer, which is the only thing
        // that makes a blocklist hit on a large file possible.
        assert_eq!(
            report.digests.sha256.as_deref(),
            Some(HashKind::Sha256.digest(data).as_str())
        );
    }

    #[test]
    fn an_unsigned_file_in_an_ordinary_directory_has_nothing_to_report() {
        // Trust is on and finds nothing worth saying, so it says nothing. A note
        // reading "this file has no signature" beside every file on a disk is
        // noise, and `TrustAssessment::reportable` exists to filter it.
        let report = engine().scan_bytes(&path(), MARKER, &ScanOptions::default());
        assert_eq!(report.verdict(), Verdict::Malicious);
        assert!(!report
            .assessment
            .detections
            .iter()
            .any(|d| d.rule_id == "scan/trust"));
    }

    #[test]
    fn a_trusted_directory_discounts_a_generic_detection_and_says_so() {
        // `weak_indicator` names no family and claims no more than Medium, so
        // it is generic and trust has standing to argue with it. 60 points is
        // the suspicious band; the discount is capped by the reason's own
        // magnitude of 10, leaving 50 — still suspicious, and visibly less.
        let engine = engine().with_trust(TrustPolicy {
            trusted_paths: vec![PathBuf::from("C:\\Trusted")],
            ..TrustPolicy::default()
        });
        let options = ScanOptions {
            heuristics: false,
            trust: true,
            ..ScanOptions::default()
        };

        let plain = engine.scan_bytes(&path(), WEAK, &options);
        let trusted = engine.scan_bytes(&PathBuf::from("C:\\Trusted\\weak.bin"), WEAK, &options);

        assert_eq!(plain.assessment.score, 60);
        assert_eq!(plain.verdict(), Verdict::Suspicious);
        assert_eq!(trusted.assessment.score, 50);
        assert_eq!(trusted.verdict(), Verdict::Suspicious);
        assert!(trusted
            .assessment
            .detections
            .iter()
            .any(|d| d.rule_id == "scan/trust"));
    }

    #[test]
    fn trust_cannot_discount_a_rule_that_names_a_family() {
        // The same trusted directory, and a detection trust has no standing to
        // argue with: `evil_marker` names a family, so it is not generic, and
        // `discount` finds nothing discountable. The score is untouched.
        let engine = engine().with_trust(TrustPolicy {
            trusted_paths: vec![PathBuf::from("C:\\Trusted")],
            ..TrustPolicy::default()
        });
        let options = ScanOptions {
            heuristics: false,
            trust: true,
            ..ScanOptions::default()
        };
        let report = engine.scan_bytes(&PathBuf::from("C:\\Trusted\\evil.bin"), MARKER, &options);
        assert_eq!(report.assessment.score, 100);
        assert_eq!(report.verdict(), Verdict::Malicious);
    }

    /// A rule set shaped like the corpus this product ships: every rule states
    /// the `score`/`quality` pair the whole corpus carries and no `severity`,
    /// no `weight` and no `family`, so nothing in the metadata separates a
    /// signature from a hunting rule.
    ///
    /// Three rules, and the two questions the engine answers about each are
    /// deliberately crossed rather than aligned, so neither one can be read off
    /// the other:
    ///
    /// | rule | name claims | condition needs |
    /// |---|---|---|
    /// | `…_MAL_ROOTKIT_Wenleprobe_1` | a rootkit, by name | one long marker |
    /// | `SIGNATURE_BASE_WEBSHELL` | a family, nothing narrower | any of three, one ordinary |
    /// | `SIGNATURE_BASE_KEYLOGGER` | a family, nothing narrower | one marker over the line |
    ///
    /// The first and third convict and the second does not, which is the whole
    /// shape of the rule engine's two conviction routes: a name that writes
    /// down an instance, or a condition that cannot be satisfied by anything
    /// ordinary. Only the second row is a hunting rule, and it is the only one
    /// that stays in the report-only band.
    ///
    /// The third rule's marker is deliberately longer than
    /// [`av_rules::content::MIN_SPECIFIC`] and has to stay that way: a marker
    /// under the line is a marker ordinary software could contain, and the rule
    /// would drop back into the hunting band and take this test with it.
    ///
    /// The strings are this product's own test markers. They are not malware
    /// idioms and deliberately so — a fixture that reproduced a real rootkit's
    /// bytes would be a file Defender quarantines mid-suite, which takes every
    /// test after it down with it.
    const CORPUS_SHAPED: &str = r#"
rule SIGNATURE_BASE_MAL_ROOTKIT_Wenleprobe_1 {
    meta:
        description = "The rootkit probe this rule set is written for."
        score = 75
        quality = 85
    strings:
        $probe = "WENLE-TEST-ROOTKIT-PROBE"
    condition:
        $probe
}

rule SIGNATURE_BASE_WEBSHELL {
    meta:
        description = "A shape of webshell rather than one."
        score = 75
        quality = 85
    strings:
        $ordinary = "shell_exec"
        $common = "base64_decode"
        $probe = "WENLE-TEST-WEBSHELL-PROBE"
    condition:
        any of them
}

rule SIGNATURE_BASE_KEYLOGGER {
    meta:
        description = "A family caught by the one marker its build writes down."
        score = 75
        quality = 85
    strings:
        $marker = "WENLE-TEST-KEYLOGGER-BUILD-MARKER-9f3c1a7e5b2d8046"
    condition:
        $marker
}
"#;

    const ROOTKIT_PROBE: &[u8] = b"....WENLE-TEST-ROOTKIT-PROBE....";
    const WEBSHELL_PROBE: &[u8] = b"....WENLE-TEST-WEBSHELL-PROBE....";
    const KEYLOGGER_PROBE: &[u8] =
        b"....WENLE-TEST-KEYLOGGER-BUILD-MARKER-9f3c1a7e5b2d8046....";

    /// What the names claim, asserted rather than assumed: the tests below are
    /// about what the engine does with a claim, and a later edit to
    /// [`crate::family`]'s word lists that changed the claim would otherwise
    /// turn them into tests of something else.
    #[test]
    fn the_corpus_shaped_fixture_claims_what_the_tests_below_rest_on() {
        assert_eq!(
            av_rules::family::claim("SIGNATURE_BASE_MAL_ROOTKIT_Wenleprobe_1"),
            av_rules::family::Claim::Signature
        );
        assert_eq!(
            av_rules::family::claim("SIGNATURE_BASE_WEBSHELL"),
            av_rules::family::Claim::Family
        );
        assert_eq!(
            av_rules::family::claim("SIGNATURE_BASE_KEYLOGGER"),
            av_rules::family::Claim::Family
        );
    }

    /// The reported defect, end to end.
    ///
    /// A file that matches one named-rootkit rule and nothing else was reported
    /// `Suspicious` — a band that never acts — so the one match that identified
    /// the malware was the one match nothing could be done about. It is
    /// `Malicious` now, on that match alone.
    #[test]
    fn one_match_by_a_named_rootkit_rule_convicts_on_its_own() {
        let engine = engine_over(CORPUS_SHAPED);
        assert_eq!(engine.database().len(), 3);
        let report = engine.scan_bytes(&path(), ROOTKIT_PROBE, &rules_only());

        assert_eq!(report.verdict(), Verdict::Malicious);
        let detection = report
            .assessment
            .detections
            .iter()
            .find(|d| d.rule_id == "SIGNATURE_BASE_MAL_ROOTKIT_Wenleprobe_1")
            .expect("the rootkit rule fired");
        // Decisive on its own, and its weight is the rung that makes the report
        // agree with the verdict rather than merely producing it.
        assert!(detection.decisive);
        assert_eq!(detection.score, Severity::High.default_score());
        assert_eq!(report.assessment.score, Severity::High.default_score());
        // But not beyond argument: a title is not a rating, so evidence about
        // who published the file may still answer it.
        assert!(!detection.incontestable);
        assert_eq!(
            report.assessment.detections.len(),
            1,
            "one rule matched this buffer, and the conviction is that rule's"
        );
    }

    /// The control, and the half of the distinction that keeps the fix from
    /// being "everything convicts now".
    ///
    /// A rule that names a family and no instance of it, and whose condition
    /// can be satisfied by an ordinary string, is a family-wide indicator:
    /// worth a look, never acted on. If this test ever reports `Malicious`, the
    /// read has stopped separating signatures from hunts and every one of the
    /// corpus's hunting rules convicts alone.
    ///
    /// The condition matters as much as the name, and the fixture is built so
    /// that both are load-bearing: `any of them` over three strings, the
    /// shortest of which (`shell_exec`) is ordinary on its own. Change the
    /// condition to name `$probe` alone and this rule convicts — which is the
    /// next test, and is deliberate.
    #[test]
    fn one_match_by_a_family_only_rule_is_suspicious_and_never_acts() {
        let report = engine_over(CORPUS_SHAPED).scan_bytes(&path(), WEBSHELL_PROBE, &rules_only());

        assert_eq!(report.verdict(), Verdict::Suspicious);
        let detection = report
            .assessment
            .detections
            .iter()
            .find(|d| d.rule_id == "SIGNATURE_BASE_WEBSHELL")
            .expect("the webshell rule fired");
        assert!(!detection.decisive);
        // The corpus's ordinary band, which is one rung under the line a single
        // detection needs.
        assert_eq!(detection.score, 60);
        assert_eq!(report.assessment.score, 60);
    }

    /// The other half of the control, and the reason the one above is about a
    /// *condition* and not only a name.
    ///
    /// `SIGNATURE_BASE_KEYLOGGER` names a family and no instance of it, exactly
    /// as `SIGNATURE_BASE_WEBSHELL` does — the name read alone leaves both in
    /// the report-only band. What separates them is what each condition can be
    /// satisfied by: one long marker that a program does not contain by
    /// accident, against `any of three, one of which is ordinary`. The first
    /// convicts on its own.
    ///
    /// This is the route that catches the corpus's rules whose authors wrote a
    /// signature and titled it as a family — `CAPE_Azorult` is the measured
    /// example, and it is why the two rules below differ only in their strings.
    #[test]
    fn a_family_only_rule_whose_condition_needs_a_specific_string_convicts() {
        let report = engine_over(CORPUS_SHAPED).scan_bytes(&path(), KEYLOGGER_PROBE, &rules_only());

        assert_eq!(report.verdict(), Verdict::Malicious);
        let detection = report
            .assessment
            .detections
            .iter()
            .find(|d| d.rule_id == "SIGNATURE_BASE_KEYLOGGER")
            .expect("the keylogger rule fired");
        assert!(detection.decisive);
        assert_eq!(detection.score, Severity::High.default_score());
        assert_eq!(report.assessment.score, Severity::High.default_score());
        // A conviction read out of a condition is an argument about the rule's
        // shape, so evidence about who published the file still answers it —
        // the same standing the name read leaves, and less than the rating read
        // takes away.
        assert!(!detection.incontestable);
        assert_eq!(report.assessment.detections.len(), 1);
    }

    #[test]
    fn trust_is_not_consulted_when_the_options_say_so() {
        let engine = engine().with_trust(TrustPolicy {
            trusted_paths: vec![PathBuf::from("C:\\Trusted")],
            ..TrustPolicy::default()
        });
        let options = ScanOptions {
            heuristics: false,
            trust: false,
            ..ScanOptions::default()
        };
        let report = engine.scan_bytes(&PathBuf::from("C:\\Trusted\\weak.bin"), WEAK, &options);
        assert_eq!(report.assessment.score, 60);
        assert!(!report
            .assessment
            .detections
            .iter()
            .any(|d| d.rule_id == "scan/trust"));
    }

    #[test]
    fn a_buffer_that_is_not_a_pe_still_reaches_the_rules() {
        // Scripts, documents and plain text are most of what a disk holds, and
        // the rules written for them have to run. The engine must not treat
        // "not a PE" as "nothing to do".
        let report = engine().scan_bytes(&path(), b"WENLE-TEST-EVIL-MARKER", &rules_only());
        assert!(report.is_detection());
        assert_eq!(report.kind, FileKind::Other);
    }

    #[test]
    fn a_file_the_rule_set_is_not_written_for_says_the_gate_closed() {
        let engine = engine_over(GATED);
        let report = engine.scan_bytes(&path(), b"plain text", &rules_only());
        assert_eq!(report.verdict(), Verdict::Clean);
        assert!(
            report
                .assessment
                .detections
                .iter()
                .any(|d| d.rule_id == "scan/rule-gate"),
            "why nothing was found is worth recording: {:?}",
            report.assessment.detections
        );

        // The control: when the gate holds, the rule behind it is evaluated and
        // the note is absent.
        let report = engine.scan_bytes(&path(), MARKER, &rules_only());
        assert!(report.is_detection());
        assert!(!report
            .assessment
            .detections
            .iter()
            .any(|d| d.rule_id == "scan/rule-gate"));
    }

    #[test]
    fn an_unreadable_file_is_unknown_and_never_clean() {
        let missing = Path::new("C:\\definitely\\not\\here\\nope.bin");
        let report = engine().scan_file(missing, &rules_only());
        assert_eq!(report.verdict(), Verdict::Unknown);
        assert!(!report.is_detection());
        assert!(report.error.is_some());
        assert_eq!(report.scanned_bytes, 0);
        assert_eq!(report.size, 0);
    }

    #[test]
    fn a_file_read_from_disk_is_scanned_the_same_way_as_a_buffer() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("sample.bin");
        std::fs::write(&file, MARKER).expect("writing the fixture");

        let engine = engine();
        let from_disk = engine.scan_file(&file, &rules_only());
        let from_memory = engine.scan_bytes(&file, MARKER, &rules_only());
        assert_eq!(from_disk.verdict(), from_memory.verdict());
        assert_eq!(from_disk.kind, from_memory.kind);
        assert_eq!(from_disk.digests, from_memory.digests);
        assert_eq!(
            from_disk.assessment.detections.len(),
            from_memory.assessment.detections.len()
        );
    }

    #[test]
    fn a_file_over_the_size_cap_keeps_its_head_and_the_digest_of_the_whole_file() {
        // The read used to hold the whole file and then examine the first
        // `max_file_size` bytes of it; a 1.5 GB installer cost 1.5 GB of
        // memory to scan 256 MiB. Now the head is kept and the rest is fed
        // past the hashers, so the three facts a report carries about a
        // truncated file have to stay true: the size is the file's, the
        // digest is the file's, and the examined part is the cap.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("large.bin");
        let mut data = MARKER.to_vec();
        data.resize(64 * 1024, 0x90);
        std::fs::write(&file, &data).expect("writing the fixture");

        let mut options = rules_only();
        options.max_file_size = Some(MARKER.len() as u64);

        let report = engine().scan_file(&file, &options);
        assert_eq!(
            report.size,
            data.len() as u64,
            "the report must name the file, not the head it kept"
        );
        assert_eq!(report.scanned_bytes, MARKER.len() as u64);
        assert!(
            report.is_detection(),
            "the head is still the part the rules examine: {:?}",
            report.assessment.detections
        );
        assert_eq!(
            report.digests.sha256,
            Some(HashKind::Sha256.digest(&data)),
            "a digest of the head is a digest of nothing"
        );
        assert!(report
            .assessment
            .detections
            .iter()
            .any(|d| d.rule_id == "scan/truncated"));
    }

    #[test]
    fn one_scanner_scanning_many_files_gives_the_same_answers_as_many_scanners() {
        // The reuse contract. A `Scanner` carries state between files — the
        // prefilter's stamps, the operand stack, the match table — and a scan
        // that leaked any of it would show up here as a later file inheriting
        // an earlier file's verdict.
        let engine = engine();
        let mut scanner = engine.scanner();
        let files: [&[u8]; 4] = [MARKER, KNOWN_BAD, b"plain text", MARKER];
        for data in files {
            let reused = engine.scan_with(&mut scanner, &path(), data, &rules_only());
            let fresh = engine.scan_bytes(&path(), data, &rules_only());
            assert_eq!(reused.verdict(), fresh.verdict());
            assert_eq!(
                reused.assessment.detections.len(),
                fresh.assessment.detections.len(),
                "state leaked between files"
            );
        }
    }

    #[test]
    fn the_result_is_stable_across_runs() {
        // Non-determinism in a verdict is a bug report nobody can reproduce.
        let first = engine().scan_bytes(&path(), MARKER, &rules_only());
        let second = engine().scan_bytes(&path(), MARKER, &rules_only());
        let ids = |r: &FileScanReport| -> Vec<String> {
            r.assessment
                .detections
                .iter()
                .map(|d| d.rule_id.clone())
                .collect()
        };
        assert_eq!(ids(&first), ids(&second));
        assert_eq!(first.assessment.score, second.assessment.score);
    }

    #[test]
    fn detections_are_ordered_strongest_first() {
        let data = b"MZ....WENLE-TEST-EVIL-MARKER..WENLE-TEST-WEAK-INDICATOR..";
        let report = engine().scan_bytes(&path(), data, &rules_only());
        let severities: Vec<Severity> = report
            .assessment
            .detections
            .iter()
            .map(|d| d.severity)
            .collect();
        let mut sorted = severities.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(severities, sorted, "{severities:?}");
        assert_eq!(report.assessment.score, 160);
        assert_eq!(report.verdict(), Verdict::Malicious);
    }

    #[test]
    fn two_observations_reach_the_malicious_band_and_one_does_not() {
        // The accumulation rule the thresholds exist for, stated as a test: one
        // Medium is yellow, a Medium plus a High is red. If a later change made
        // a single Medium convict, this fails.
        let engine = engine();
        let one = engine.scan_bytes(&path(), WEAK, &rules_only());
        assert_eq!(one.verdict(), Verdict::Suspicious);
        assert!(!one.assessment.detections.is_empty());
        let two = engine.scan_bytes(
            &path(),
            b"WENLE-TEST-WEAK-INDICATOR..WENLE-TEST-EVIL-MARKER",
            &rules_only(),
        );
        assert_eq!(two.verdict(), Verdict::Malicious);
    }

    #[test]
    fn a_report_names_a_target_a_user_can_recognise() {
        // Not part of the engine, but the report is what a caller hands to a
        // user, and an engine whose reports cannot be traced to a file is an
        // engine whose findings cannot be acted on.
        let target = ScanTarget::File(path());
        assert!(target.label().contains("sample.bin"));
    }

    #[test]
    fn the_engine_reports_the_rule_set_it_is_running() {
        let engine = engine();
        assert_eq!(engine.database().len(), 3);
        assert_eq!(engine.blocklist().len(), 1);
        assert_eq!(engine.blocklist().count_of(HashKind::Sha256), 1);
        assert_eq!(engine.blocklist().count_of(HashKind::Md5), 0);
        assert_eq!(engine.blocklist().rejected().len(), 0);
        assert_eq!(*engine.thresholds(), VerdictThresholds::default());
    }

    #[test]
    fn a_scan_that_overran_its_budget_without_finding_anything_is_unknown() {
        // The budget is zero, so any work at all exceeds it. The point is that
        // the verdict says `Unknown` rather than claiming a clean file: an
        // unfinished look is not a clean bill of health.
        let instant = ScanOptions {
            per_file_timeout: Some(Duration::ZERO),
            ..rules_only()
        };
        let report = engine().scan_bytes(&path(), b"plain text", &instant);
        assert_eq!(report.verdict(), Verdict::Unknown);
        assert!(report.error.is_some());
    }

    #[test]
    fn a_scan_that_overran_its_budget_having_found_something_keeps_the_finding() {
        // The converse, and the reason the budget does not simply discard the
        // work: throwing away a detection because the scan was slow would be
        // losing the one thing the scan was for.
        let instant = ScanOptions {
            per_file_timeout: Some(Duration::ZERO),
            ..rules_only()
        };
        let report = engine().scan_bytes(&path(), MARKER, &instant);
        assert_eq!(report.verdict(), Verdict::Malicious);
        assert!(
            report
                .assessment
                .detections
                .iter()
                .any(|d| d.rule_id == "scan/over-budget"),
            "{:?}",
            report.assessment.detections
        );
        // And the finding is the first thing in the list, because the list
        // reads strongest first and the note is an Info.
        assert_eq!(
            report
                .assessment
                .detections
                .first()
                .map(|d| d.rule_id.as_str()),
            Some("evil_marker")
        );
    }

    #[test]
    fn the_fixture_rule_set_refuses_nothing() {
        // The fixture asserts an empty refusal list in `engine_over`. This
        // states why that matters: every test above reads a verdict that a
        // silently dropped rule would have changed.
        let (_, report) = RuleDatabase::compile(RULES);
        assert!(
            report.string_refusals.is_empty(),
            "{:?}",
            report.string_refusals
        );
        assert_eq!(report.rules_seen, 3);
    }

    // -- the archive stage, through the engine rather than in isolation ------
    //
    // `crate::archive`'s own tests cover what the walk does. These two cover
    // the thing those cannot: that `ScanEngine::scan` actually consumes it, so
    // that a verdict reached here is the verdict a caller gets. Both are
    // written against the real `ScanOptions::default()` rather than
    // `rules_only()`, because whether archives are on by default is itself part
    // of the claim.

    /// A zip whose single member carries the marker rule. The member is
    /// *deflated*, which is what makes the test mean something: a stored member
    /// sits verbatim in the container, so the outer file's own scan would find
    /// the marker anyway and the test would pass without the archive stage
    /// existing. Compressed, the only way to this verdict is through the walk.
    #[test]
    fn a_zip_holding_a_matching_member_is_malicious_and_names_what_was_inside() {
        let container = av_archive::testing::zip_deflate(&[("payload.exe", MARKER)]);
        // The guard on the paragraph above, asserted rather than assumed: if
        // the compressed form ever did contain the marker, this test would be
        // measuring the outer scan and would have to be rewritten.
        assert!(
            !container.windows(MARKER.len()).any(|w| w == MARKER),
            "the fixture no longer isolates the member scan"
        );

        let report = engine().scan_bytes(&path(), &container, &ScanOptions::default());
        assert_eq!(report.verdict(), Verdict::Malicious);

        let detection = report
            .assessment
            .detections
            .iter()
            .find(|d| d.rule_id == "evil_marker")
            .expect("the marker rule fired on the member");
        assert_eq!(detection.container.as_deref(), Some("payload.exe"));
        // The score is the rule's own, unchanged by having been found one level
        // down. A member's finding is a term in the same sum as everything
        // else, not a discounted one.
        assert_eq!(detection.score, 100);
        assert_eq!(detection.severity, Severity::High);

        let archive = report.archive.expect("the container was walked");
        assert_eq!(archive.format, "zip");
        assert_eq!(archive.declared, 1);
        assert_eq!(archive.examined, 1);
        assert!(archive.is_complete(), "{}", archive.describe());
    }

    /// The false-positive guard. A zip of ordinary files must come out clean,
    /// and must still record that it was opened — a scanner that reached a
    /// clean verdict by declining to look inside has not earned it.
    #[test]
    fn a_zip_of_ordinary_files_is_clean_and_still_says_it_was_opened() {
        let container = av_archive::testing::zip_deflate(&[
            ("notes.txt", b"a text file with nothing in it"),
            ("data.bin", b"\x00\x01\x02\x03 ordinary bytes"),
        ]);
        let report = engine().scan_bytes(&path(), &container, &ScanOptions::default());
        assert_eq!(report.verdict(), Verdict::Clean);
        assert!(!report.is_detection());

        let archive = report.archive.expect("the container was walked");
        assert_eq!(archive.declared, 2);
        assert_eq!(archive.examined, 2);
        assert!(archive.is_complete(), "{}", archive.describe());
        assert!(
            report
                .assessment
                .detections
                .iter()
                .any(|d| d.rule_id == "scan/archive"),
            "a container that was opened says so: {:?}",
            report.assessment.detections
        );
    }

    // -- the product's own files ---------------------------------------------

    /// A rule set that is *about the text it is written in*.
    ///
    /// `RULES` above cannot be used for this: none of its three markers appears
    /// in its own source, so it does not reproduce the failure. This one does,
    /// and the shape is not contrived — a rule is a description of bytes to
    /// look for, written down in a file that contains those bytes. Every
    /// literal rule is like this one.
    const SELF_MATCHING: &str = r#"
rule self_matching {
    meta:
        description = "A marker that is also in this file."
        severity = "high"
    strings:
        $marker = "WENLE-TEST-CORPUS-MARKER"
    condition:
        $marker
}
"#;

    /// The marker above, in a file that is not the corpus.
    const NOT_THE_CORPUS: &[u8] = b"a downloaded file that mentions WENLE-TEST-CORPUS-MARKER once";

    /// An engine whose database knows the source it was compiled from, which is
    /// what `wenle build` produces and what every front end loads.
    fn engine_that_knows_its_corpus() -> ScanEngine {
        let bytes = SELF_MATCHING.as_bytes();
        let (database, _) = RuleDatabase::compile(SELF_MATCHING);
        ScanEngine::new(database.with_sources(vec![RuleSource::of("corpus.yar", bytes)]))
    }

    #[test]
    fn the_marker_rule_fires_on_a_file_that_is_not_the_corpus() {
        // The control for the two tests below. Without it they would pass on an
        // engine whose rule set matches nothing, which is not the claim being
        // made: the claim is that the corpus is recognised, not that the rule
        // was broken to make it so.
        let report =
            engine_that_knows_its_corpus().scan_bytes(&path(), NOT_THE_CORPUS, &rules_only());
        assert_eq!(
            report.verdict(),
            Verdict::Malicious,
            "{:?}",
            report.assessment
        );
    }

    #[test]
    fn a_rule_source_is_not_reported_as_the_malware_its_own_rules_describe() {
        // The measured failure, in miniature: scanning the corpus this product
        // ships produced 43 detections and a `malicious` verdict on the
        // product's own signature data.
        let bytes = SELF_MATCHING.as_bytes();
        let report = engine_that_knows_its_corpus().scan_bytes(&path(), bytes, &rules_only());

        assert_eq!(report.verdict(), Verdict::Clean, "{:?}", report.assessment);
        assert!(
            report
                .assessment
                .detections
                .iter()
                .all(|d| d.severity == Severity::Info),
            "nothing above an informational note: {:?}",
            report.assessment.detections
        );
        assert_eq!(
            report.scanned_bytes, 0,
            "reading a file to identify it is not examining it"
        );
        assert_eq!(
            report.size,
            bytes.len() as u64,
            "the file's size is still reported"
        );
    }

    #[test]
    fn the_recognition_is_of_content_and_not_of_a_path() {
        // The reason this is a digest and not a path: the same corpus sits in a
        // build tree, in an installation, in a backup and in whatever directory
        // somebody copied it into, and every one of those is the same file.
        let bytes = SELF_MATCHING.as_bytes();
        let elsewhere = PathBuf::from(r"D:\backups\somebody-elses-copy\corpus.yar");
        let report = engine_that_knows_its_corpus().scan_bytes(&elsewhere, bytes, &rules_only());
        assert_eq!(report.verdict(), Verdict::Clean, "{:?}", report.assessment);
    }

    #[test]
    fn the_note_says_which_of_the_products_files_it_was() {
        // "Why was this not detected?" is the question the note exists to
        // answer, and it is unanswerable without a name in it.
        let bytes = SELF_MATCHING.as_bytes();
        let report = engine_that_knows_its_corpus().scan_bytes(&path(), bytes, &rules_only());
        let note = report
            .assessment
            .detections
            .iter()
            .find(|d| d.rule_id == crate::own::PRODUCT_FILE_RULE)
            .expect("the file was recognised and the report says so");
        assert!(
            note.description.contains("corpus.yar"),
            "{}",
            note.description
        );
    }

    #[test]
    fn an_engine_whose_database_recorded_no_sources_still_judges_the_file() {
        // The other side of the boundary, and the one that must not regress: an
        // engine with nothing to go on examines the file rather than vouching
        // for it. A database compiled in memory from a string nobody kept has
        // no sources, and this is what that costs.
        let report = engine().scan_bytes(&path(), SELF_MATCHING.as_bytes(), &rules_only());
        assert_eq!(
            report.verdict(),
            Verdict::Clean,
            "no rule in `RULES` matches this text, so the answer is an honest clean"
        );
        assert!(!crate::own::is_product_file(&report));
    }

    // -- a rule source that is not ours --------------------------------------

    /// A rule set whose literal appears in the foreign corpus below.
    ///
    /// One literal, and it is the whole point: this rule is not broken, not
    /// weakened and not disabled. It fires on any file that holds the marker,
    /// and the test below is about a file that does.
    const FOREIGN_RULES: &str = r#"
rule foreign_marker {
    meta:
        description = "A literal that is also in the corpus below."
        severity = "high"
    strings:
        $marker = "WENLE-FOREIGN-MARKER"
    condition:
        $marker
}
"#;

    /// A rule source this product did not compile, holding the marker above.
    ///
    /// Sixteen rules rather than one, because that is the shape a real corpus
    /// has and the shape the thresholds are set for: a single rule with the
    /// marker in it is a file, and sixteen is a rule source. The literal in each
    /// rule carries a suffix so that no two are the same string, which is what
    /// keeps this from being a file that merely repeats itself.
    fn foreign_corpus() -> String {
        let mut text = String::new();
        for i in 0..16 {
            text.push_str(&format!(
                "rule foreign_{i} {{\n  strings:\n    $a = \"WENLE-FOREIGN-MARKER-{i}\"\n  \
                 condition:\n    $a\n}}\n"
            ));
        }
        text
    }

    /// The engine that owns the rule above, with no sources recorded — so the
    /// digest whitelist has nothing to say and cannot be what answers.
    fn engine_with_foreign_rules() -> ScanEngine {
        ScanEngine::new(RuleDatabase::compile(FOREIGN_RULES).0)
    }

    #[test]
    fn the_marker_in_an_ordinary_file_is_still_a_detection() {
        // The control. Every claim below is that a rule source is not convicted;
        // this is what makes them a claim about recognition rather than about a
        // rule that stopped working.
        let report = engine_with_foreign_rules().scan_bytes(
            &path(),
            b"a downloaded file that says WENLE-FOREIGN-MARKER once",
            &rules_only(),
        );
        assert!(
            report.is_detection(),
            "the rule above did not fire on the literal it names: {:?}",
            report.assessment
        );
    }

    #[test]
    fn a_rule_source_this_product_did_not_write_is_recognised_and_not_convicted() {
        // The measurement this module was written for, reproduced end to end:
        // the same literal, sixteen times, inside a file that is made of rule
        // syntax. The digest whitelist cannot answer for it — this engine's
        // database recorded no sources, and the file is nobody's but a stranger's
        // — so the answer comes from the recognition alone.
        let corpus = foreign_corpus();
        let report =
            engine_with_foreign_rules().scan_bytes(&path(), corpus.as_bytes(), &rules_only());

        assert_eq!(report.verdict(), Verdict::Clean, "{:?}", report.assessment);
        assert!(crate::own::is_foreign_rule_source(&report));
        assert!(
            !crate::own::is_product_file(&report),
            "a stranger's corpus is not this product's own data"
        );
        assert_eq!(report.scanned_bytes, 0, "nothing was examined");
    }

    #[test]
    fn the_note_for_a_foreign_corpus_counts_the_rules_it_found() {
        // The number is the evidence for the decision. A report that said "this
        // looks like a rule file" and nothing else would be asking the user to
        // take the recognition on faith.
        let corpus = foreign_corpus();
        let report =
            engine_with_foreign_rules().scan_bytes(&path(), corpus.as_bytes(), &rules_only());
        let note = report
            .assessment
            .detections
            .iter()
            .find(|d| d.rule_id == crate::own::RULE_SOURCE_RULE)
            .expect("the file was recognised and the report says so");
        assert!(
            note.description.contains("16 rules"),
            "{}",
            note.description
        );
    }

    #[test]
    fn a_program_holding_a_rule_corpus_is_still_scanned() {
        // The gate, end to end. The same corpus, in a file with an `MZ` header
        // and an executable's name: the kind is `Pe`, the recognition refuses to
        // look, and the marker rule fires. A rule set carried inside a dropper is
        // not a licence to skip the dropper.
        let mut carrier = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
        carrier.extend_from_slice(foreign_corpus().as_bytes());

        let report = engine_with_foreign_rules().scan_bytes(
            &PathBuf::from("dropper.exe"),
            &carrier,
            &rules_only(),
        );
        assert!(
            report.is_detection(),
            "an executable carrying rule text was excused: {:?}",
            report.assessment
        );
        assert!(!crate::own::is_foreign_rule_source(&report));
    }

    #[test]
    fn the_compiled_database_recognises_its_own_file() {
        // The same hazard in a different container: a `.avdb` is a compiled
        // rule set, so it holds the literals too, and one copied to a desktop
        // would be reported as the malware its own rules describe.
        let (database, _) = RuleDatabase::compile(SELF_MATCHING);
        let image = database.to_bytes().expect("the image serialises");
        let loaded = RuleDatabase::from_bytes(&image).expect("it loads");
        let engine = ScanEngine::new(loaded);

        let report = engine.scan_bytes(&path(), &image, &rules_only());
        assert_eq!(report.verdict(), Verdict::Clean, "{:?}", report.assessment);
        assert!(
            crate::own::is_product_file(&report),
            "{:?}",
            report.assessment.detections
        );
    }
}
