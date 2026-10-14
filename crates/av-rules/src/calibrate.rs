//! Turning a rule author's own confidence into this engine's score.
//!
//! # Why this module exists
//!
//! A rule set larger than a few hundred rules carries a calibration the engine
//! cannot invent: its authors wrote, for every rule, how much a match is worth
//! and how well they think they wrote it. The corpus this engine is built
//! against states both on every one of its 10,764 rules (`score`, an integer
//! in `50..=100`, and `quality`, an integer in `0..=90`), and a rule set of that
//! size does not use one value for all of them: it uses ten distinct scores and
//! sixty distinct qualities.
//!
//! An engine that ignores both has to answer "what is a match worth?" with a
//! constant, and the constant is wrong for every rule. Worse, it is wrong in
//! the direction that is hard to see: the author's most confident rules and
//! their least confident ones contribute the same number of points, so
//! precision the corpus already recorded is thrown away and a rule its author
//! rated 50 can carry a file over the line as easily as one rated 100.
//!
//! # What is read, and what it becomes
//!
//! | In the rule | Becomes | Because |
//! |---|---|---|
//! | `weight = 90` | a `weight` of 90 | this product's own point value, used as written |
//! | `score = 75` | a `weight` of 60 | the corpus's own band for an ordinary rule, never the number itself. See [`weight_for`] |
//! | `score = 75` | [`Severity::Medium`], declared or not | so the report cannot print a severity the score beside it contradicts |
//! | `severity = "high"`, no score | kept as declared | that is this engine's own ladder, and the author is speaking it |
//! | `quality = 85` | *(nothing, above the floor)* | a rule its author wrote well is taken at its word |
//! | `quality = 20` | the weight, halved | a rule its author rated badly is worth half as much |
//! | tag `info` or `category = "INFO"` | [`Severity::Info`], weight 0 | the author is saying "this is an observation, not a detection" |
//! | tag `ransomware`, `rat`, … | the rule's `category` | so the report can name a family instead of a rule id |
//! | tag `windows`, `script`, … | the rule's `platform` | ditto |
//! | a name that identifies a family *and* one of its instances | `decisive`, weight at least 100 | the name of a signature is the one field in the corpus that separates it from a hunting rule; see [`crate::family`] |
//! | a condition nothing ordinary satisfies | `decisive`, weight at least 100 | the rule demands something only the sample it names contains; see [`crate::content`] |
//! | `score >= 90` and `quality >= 80` | `decisive` **and** `incontestable` | the author's own "this match is the answer" |
//!
//! # The three routes to `decisive`, and why only one is beyond argument
//!
//! A rule can convict on its own in three ways, and they are not the same
//! claim. The rating route is the rule's author saying "if this matches, stop
//! looking", in the two fields the corpus keeps for exactly that. The other two
//! are *this product* reading the rule: its title, where the author rated the
//! rule at an ordinary 75 and said nothing about how much a match should be
//! trusted (the corpus has 9,213 rules at that score, so the title is the only
//! thing that separates a signature from a hunting rule), and its condition,
//! where the strings the rule demands are specific enough that nothing ordinary
//! satisfies them.
//!
//! All three convict. Only the rating is beyond argument
//! ([`RuleMetadata::incontestable`]), because evidence about who published a file
//! is an answer to a title and to a shape and not to a rating: signing real
//! malware with a stolen certificate is a thing that happens, and a rule its
//! author rated 90/100 matching a signed file is worth acting on. What the two
//! readings cost is measured rather than argued, and it is stated where the
//! decision is made: [`av_core::Detection::incontestable`].
//!
//! # What the tags are worth, measured rather than assumed
//!
//! The tag mapping is the smallest of these and it would be easy to describe it
//! as larger than it is, so here is the count. The corpus's `tags` lists hold
//! 11,368 words in 226 distinct spellings. Of those occurrences, **754 name a
//! category** and **39 name a platform**, and 623 of the 754 are `malware` or
//! `malicious`, which name no category in particular. So the mapping changes
//! what the report says about roughly one rule in a hundred, and the reason to
//! keep it is that the alternative is a report that says nothing at all about a
//! rule whose only label is `ransomware`: a match the user cannot act on
//! because the engine did not pass on the one word the author wrote.
//!
//! What it must *not* do is guess. The same vocabulary contains actor names
//! (`platinum`, `stormbamboo`, `charmingkitten`), ATT&CK technique ids, CVE
//! numbers, and `highvol`, which says where the sample came from. Every one of
//! those is a real label and none of them is a threat category, and a mapper
//! that reached for one would produce the specific-looking wrong answer,
//! `Win32.APT`, which is worse for the user than the general right one.
//!
//! # Two axes, one spelling
//!
//! The corpus writes both a `score` and, on 82 of its 10,764 rules, a
//! `severity`. It is tempting to read the second as this engine's
//! [`Severity`] (same word, same idea), and that is wrong, which the numbers
//! settle rather than the intuition: **every one of those 82 rules carries an
//! author score of 65 or 75**, and 67 of them declare themselves `critical`
//! while doing it. A `critical` that is worth 75 points is not a rung on this
//! engine's ladder, where `Critical` *means* 150, so the corpus's `severity` is
//! not this engine's severity. It is some other scale (an importance or a threat
//! class) that happens to be spelled the same way.
//!
//! Where the two collide, the `score` wins, and the rule above assigns the
//! severity from it rather than deferring to the declaration. The reason is not
//! that one author field outranks another: it is that `score` covers every rule
//! and drives the arithmetic while `severity` covers 82 rules and, in this
//! corpus, does not drive anything. Honouring both would produce a rule set
//! reporting `critical` next to `75`, and a reader has no way to tell which
//! half of that to believe.
//!
//! A rule that states a severity and no score is a different case and keeps
//! what it stated. That is the shape of a rule written by hand in this
//! product's own language, and there the declaration is a statement about this
//! engine's ladder rather than a word borrowed from somebody else's.
//!
//! # Every rule here is conditional on the metadata being there
//!
//! A rule written by hand in this product's own language states what it means
//! and nothing else, and calibration must not touch it: a `.avrule` that states
//! no `score` keeps the severity it declared, and a `.avrule` that states no
//! `quality` is not second-guessed for the absence. The whole module is a
//! *reading* of somebody else's metadata, so where the metadata stops, the
//! module stops.
//!
//! The single exception is the severity of a rule that states a score, which is
//! derived from that score whether or not a severity was also declared. It is
//! the one place this module overrules an author's own field, it is argued
//! above under "two axes, one spelling", and it exists so that no rule can be
//! printed with a severity its own score contradicts, which is a report
//! disagreeing with itself, and the reader has no way to tell which half to
//! believe.
//!
//! # The floor, and why it is where it is
//!
//! [`QUALITY_FLOOR`] is 60 and the corpus's own median quality is 85, so the
//! floor is well below the middle: it is not a judgement about quality, it is a
//! line below which the author is describing a rule as unreliable. The corpus
//! crosses it 288 times out of 10,715, and those are exactly the rules a
//! scanner wants to be sceptical of.

use av_core::{Platform, Severity, ThreatCategory};

use crate::content::Demand;
use crate::database::RuleMetadata;
use crate::family::{self, Claim};

/// Quality below which a rule's contribution is halved.
pub const QUALITY_FLOOR: u8 = 60;

/// The `score` at or above which, combined with [`DECISIVE_QUALITY`], a single
/// match is the whole answer.
pub const DECISIVE_SCORE: u16 = 90;

/// The `quality` at or above which, combined with [`DECISIVE_SCORE`], a single
/// match is the whole answer.
pub const DECISIVE_QUALITY: u8 = 80;

/// How much a rule rated below the floor is worth, in percent.
///
/// Half, and not nothing: `quality` is the author's opinion of the rule's
/// construction, not evidence about the file in front of us. A badly written
/// rule that matches is still a fact about the file, and dropping it to zero
/// would be the engine overruling the author's `score` on the strength of a
/// different field.
const BELOW_FLOOR_PERCENT: u16 = 50;

/// Apply the calibration to one rule's metadata, in place.
///
/// `tags` is the rule's full tag list: both the ones on the `rule` line and the
/// ones in its `tags` metadata string, which the corpus uses and the rule
/// syntax does not. Merging them is the caller's job because only the caller
/// has both; see `crate::database::CompiledRule::new`.
///
/// `name` is the rule's name, read by [`crate::family`] for the claim it makes.
/// It is passed rather than looked up because a [`RuleMetadata`] does not carry
/// one — the name belongs to the rule, not to its metadata — and the caller is
/// the only one that has both.
///
/// `demand` is what the rule's condition demands, read by [`crate::content`].
/// Passed for the same reason as the name and with the same caveat: it is a
/// reading of the rule, not a field of its metadata. [`RuleMetadata::calibrated`]
/// is the entry point that computes both, and it is the one callers should use —
/// this function takes them as arguments so that each route can be tested on its
/// own.
pub fn apply(meta: &mut RuleMetadata, tags: &[String], name: &str, demand: Demand) {
    // Order matters. The author's own `category` and `platform` win over
    // anything inferred from a tag, because a tag is a label the author applied
    // to the rule and `category` is a statement about what it detects.
    if meta.category.is_none() {
        if let Some(category) = tags.iter().find_map(|tag| ThreatCategory::from_tag(tag)) {
            meta.category = Some(category);
        }
    }
    if meta.platform.is_none() {
        if let Some(platform) = tags.iter().find_map(|tag| Platform::from_tag(tag)) {
            meta.platform = Some(platform);
        }
    }

    if is_observational(meta, tags) {
        // The author's own word for it. An `info` rule is one that says "this
        // file is a .NET assembly" or "this file is packed", and those are
        // observations: real, worth recording, and never a reason to tell a
        // user their file is malware. Scoring zero keeps them in the report and
        // out of the verdict, which is the only arrangement in which a scanner
        // can afford to look at a thousand of them.
        meta.severity = Some(Severity::Info);
        meta.weight = Some(0);
        meta.decisive = false;
        // Cleared with it, because nothing may be beyond argument and still
        // short of deciding the verdict.
        meta.incontestable = false;
        return;
    }

    // A `weight` is this product's own point value, written by hand in this
    // product's own language, and it is used as written. It is the field a
    // `.avrule` author writes when they mean "this match is worth 90 points",
    // and re-banding it would be the engine overruling the one field that
    // already speaks its units. Only the severity is derived, so that the report
    // cannot print a label its own score contradicts — the same reason as below.
    if let Some(weight) = meta.weight {
        meta.severity = Some(severity_of(weight));
        return;
    }

    // Everything below is conditional on a third-party set having stated a
    // score. A rule that states neither has told us nothing about what a match
    // is worth, and the engine's own default stands.
    let Some(score) = meta.score else {
        return;
    };

    if meta.quality.is_some_and(|q| q >= DECISIVE_QUALITY) && score >= DECISIVE_SCORE {
        // Both fields have to agree, which is what makes this safe to
        // short-circuit on. The corpus has 45 such rules out of 10,764 —
        // named samples and exploit documents, the rules whose authors are
        // saying "if this matches, stop looking".
        meta.decisive = true;
        // And beyond argument, which is the difference between this route and
        // the name route below. The author rated this rule at 90 or above out
        // of 100 *and* at 80 or above for construction: that is a claim about
        // the sample, and a certificate does not answer a claim about a sample
        // — a stolen one is a known way to sign real malware.
        meta.incontestable = true;
    }

    let mut weight = weight_for(score, meta.quality);

    // A signature is not an ordinary rule, and the corpus says which is which
    // in the rule's name rather than in any field: `score` is 75 on 86% of the
    // corpus, so the bands cannot separate `SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver`
    // from a hunting rule, and both land at 60 points — one rung below the line
    // a single detection needs to convict. That was the defect: a file matching
    // a named rootkit's signature was reported `Suspicious`, which is a band
    // that never acts, so the one match that identified the malware was also the
    // one match that could not be acted on.
    //
    // The weight is raised to the convicting rung rather than left where the
    // bands put it, because a rule that is decisive *and* scores 60 contradicts
    // itself in the report — the same reason the severity is derived from the
    // weight below. `max` rather than assignment, so a signature the corpus
    // already rates at 150 keeps its rating.
    //
    // This route deliberately does not set `incontestable`, and the difference
    // between it and the rating above is the whole reason that field exists. The
    // rating is the author's own; this one is a reading of the rule's *title*,
    // and the author rated the rule at an ordinary 75. A title is a claim that
    // evidence about who published a file has standing on — see
    // [`av_core::Detection::incontestable`] for the measurement that settled it.
    if meta
        .quality
        .is_some_and(|quality| quality >= DECISIVE_QUALITY)
        && family::claim(name) == Claim::Signature
    {
        meta.decisive = true;
        weight = weight.max(Severity::High.default_score());
    }

    // And the third route, which is the same argument made about a different
    // part of the rule. A name is a title; a condition is the thing itself. When
    // every path through a rule's condition passes through an indicator long
    // enough that ordinary software does not contain it, the rule cannot fire by
    // accident, and a file it matches carries that indicator — whatever the
    // rule's author thought to call it and however they rated it.
    //
    // The measurement that asked for this is `CAPE_Azorult`: a hundred and ten
    // bytes of the malware's own machine code and a seventy-four byte SQL
    // statement, under `all of them`, and a name that says only which family the
    // rule is about. Its score is 75 and its quality is 70, so the rating route
    // passes it by and the name route passes it by, and it was reported
    // `Suspicious` — a band that never acts — while its condition said a file
    // cannot satisfy it without carrying a hundred and ten bytes of Azorult.
    //
    // Deliberately without a `quality` requirement, and that is not an
    // oversight: `quality` is the author's opinion of the rule's *construction*,
    // and the shape of the condition is the better evidence of exactly that.
    // Requiring the author to also have said so would leave the rules whose
    // construction is fine and whose self-rating is modest precisely where the
    // defect left them.
    //
    // Not `incontestable`, for the same reason as the route above: this is an
    // argument about the rule's shape rather than a statement about the sample,
    // so evidence about who published the file still has standing on it. That is
    // the safety valve on this route — the check that a promoted rule cannot
    // convict a file that is provably an unmodified signed original.
    if demand == Demand::Specific {
        meta.decisive = true;
        weight = weight.max(Severity::High.default_score());
    }

    meta.weight = Some(weight);

    // Assigned rather than filled in when absent, which is the one place this
    // module overrules a rule's own metadata. The reason is in the module
    // documentation under "two axes, one spelling", and it is measured rather
    // than argued: of the 10,764 rules in this corpus, 82 declare a `severity`
    // and **every one of those 82 carries an author score of 65 or 75** — 67 of
    // them while calling themselves `critical`. A `critical` worth 75 points is
    // not a severity this engine's ladder can express, so the field the corpus
    // calls `severity` is not the field this engine calls `severity`, and
    // honouring it would print a label the arithmetic beside it contradicts.
    //
    // The score is what decides because it is the field that covers every rule
    // and the field the verdict is computed from. A rule that declares a
    // severity and no score is a different case and keeps its declaration: it
    // returned above.
    meta.severity = Some(severity_of(weight));
}

/// The severity a weight corresponds to.
///
/// The rungs are [`Severity::default_score`]'s own ladder, read downwards: the
/// severity is the highest rung the weight reaches, so a weight of 60 is
/// `Medium` and one of 100 is `High`. Deriving it this way is what keeps a
/// rule's severity and its score from describing different rules — a report that
/// prints `medium` beside a score of 150 is a report contradicting itself, and
/// the reader has no way to tell which half to believe.
///
/// The one rung a weight cannot fall to is [`Severity::Info`]. `Info` means
/// something specific here — recorded and never actionable, which is why it is
/// also the only severity that scores nothing — so a weight of 25 is `Low` and
/// not `Info`, even though 25 is numerically nearer 0 than 30. A rule that has
/// been halved for poor quality still contributes its points and can still, in
/// company, carry a file over the suspicious line; `Info` is the one label that
/// promises it cannot.
fn severity_of(weight: u16) -> Severity {
    match weight {
        0 => Severity::Info,
        s if s < Severity::Medium.default_score() => Severity::Low,
        s if s < Severity::High.default_score() => Severity::Medium,
        s if s < Severity::Critical.default_score() => Severity::High,
        _ => Severity::Critical,
    }
}

/// Whether the rule's author described it as an observation rather than a
/// detection.
///
/// Two spellings, because the corpus uses both and they agree on every rule
/// that has either: a `tags` list containing `info`, and a `category` whose
/// value is `INFO`. The second reaches us through [`RuleMetadata::extra`],
/// which is where the parser puts a `category` it does not recognise — and
/// `INFO` is the one unrecognised value that means something, since it is the
/// author saying "not a threat category".
fn is_observational(meta: &RuleMetadata, tags: &[String]) -> bool {
    if tags.iter().any(|tag| tag.eq_ignore_ascii_case("info")) {
        return true;
    }
    meta.extra
        .get("category")
        .is_some_and(|value| value.to_string().trim().eq_ignore_ascii_case("info"))
}

/// What one of the corpus's rules is worth on this engine's ladder.
///
/// Two steps, and the first is the one that matters: the corpus's `score` is
/// **not** a number of points on this engine's scale, and reading it as one was
/// the largest single source of false positives this engine has had.
///
/// # The measurement that forces the distinction
///
/// The corpus states a `score` in `50..=100` on all 10,764 of its rules, and the
/// values do not spread across that band — they pile at one of them:
///
/// | score | rules |
/// |---|---|
/// | 50 | 7 |
/// | 55 | 1 |
/// | 60 | 252 |
/// | 65 | 147 |
/// | 70 | 735 |
/// | **75** | **9,236** |
/// | 80 | 224 |
/// | 85 | 116 |
/// | 90 | 36 |
/// | 100 | 10 |
///
/// 86% of the corpus is a 75, so that is what the field means to its authors:
/// not "three quarters of the way to a conviction" but "an ordinary rule of
/// this set". Read as points against this engine's ladder — where
/// [`av_core::VerdictThresholds::default`] convicts at 100 — an ordinary rule
/// was worth 75, so **any two of them matching one file reached `Malicious`**,
/// which is the band that quarantines. Two ordinary rules are not evidence: a
/// file holding two patterns out of 10,764 is a file holding two patterns.
///
/// # What replaces it
///
/// The corpus's own distribution, read as its authors wrote it. They reserved
/// the top of the band for the rules they meant it about — 46 rules at 90 and
/// above, 10 of those at 100 — and left everything under 90 as degrees of
/// ordinary. So the pile lands in the *middle* of this engine's ladder instead
/// of near the top of it, and the top of the band keeps the power to convict on
/// its own:
///
/// | corpus `score` | weight | severity | rules |
/// |---|---|---|---|
/// | under 60 | 30 | `Low` | 8 |
/// | 60–69 | 40 | `Low` | 399 |
/// | 70–79 | 60 | `Medium` | 9,971 |
/// | 80–89 | 80 | `Medium` | 340 |
/// | 90–99 | 100 | `High` | 36 |
/// | 100 | 150 | `Critical` | 10 |
///
/// A weight need not be a rung of the ladder — `severity_of` places a weight
/// on the highest rung it reaches, which is why 80 reads as `Medium` — and the
/// halving below produces values off the ladder too. That was already true of
/// the halving before this mapping existed.
///
/// # The second step
///
/// Halve the weight of a rule its author rated below the floor. Kept here
/// rather than inside [`apply`] because the halving happens after the score is
/// known and before the severity is derived, and holding the two steps apart is
/// what lets each be tested on its own.
pub fn weight_for(score: u16, quality: Option<u8>) -> u16 {
    let banded = ordinary(score);
    match quality {
        Some(quality) if quality < QUALITY_FLOOR => {
            banded.saturating_mul(BELOW_FLOOR_PERCENT) / 100
        }
        _ => banded,
    }
}

/// Where one of the corpus's `score` values sits on this engine's ladder.
///
/// The bands are the corpus's own distribution and not an even division of its
/// range — see [`weight_for`] for the counts each band covers and for why the
/// pile at 75 belongs in the middle of the ladder rather than near its top. The
/// one band that is not read off the counts is `80..90`, which is placed at 80
/// so that it stays below the rung a single detection needs to convict alone
/// (see [`av_core::Assessment::finalize`]); the corpus's own line for "this one
/// is the answer" is 90, and this mapping does not move it.
fn ordinary(score: u16) -> u16 {
    match score {
        s if s < 60 => Severity::Low.default_score(),
        s if s < 70 => 40,
        s if s < 80 => Severity::Medium.default_score(),
        s if s < 90 => 80,
        s if s < 100 => Severity::High.default_score(),
        _ => Severity::Critical.default_score(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::MetaValue;

    fn meta() -> RuleMetadata {
        RuleMetadata::default()
    }

    fn tags(list: &[&str]) -> Vec<String> {
        list.iter().map(|t| (*t).to_string()).collect()
    }

    #[test]
    fn a_corpus_score_becomes_a_weight_on_this_engines_ladder() {
        // 75 is the corpus's ordinary rule — 9,236 of its 10,764 carry it — and
        // it lands in the middle of this engine's ladder rather than near the
        // top of it. See `weight_for` for the distribution this reads.
        let mut m = meta();
        m.score = Some(75);
        apply(&mut m, &[], "", Demand::None);
        assert_eq!(m.weight, Some(60));
        assert_eq!(m.severity, Some(Severity::Medium));
    }

    #[test]
    fn a_hand_written_weight_is_used_as_written() {
        // The other half of the split, and the reason it exists: our own
        // language writes `weight` and means points. A rule that says 100 gets
        // 100 — the rung a single detection needs to convict alone — and no band
        // is applied to it. Before the two fields were separated, a hand-written
        // `weight = 100` and a corpus `score = 100` were indistinguishable, so
        // any mapping that made the corpus's 75 harmless would also have made
        // this one harmless.
        let mut m = meta();
        m.weight = Some(Severity::High.default_score());
        apply(&mut m, &[], "", Demand::None);
        assert_eq!(m.weight, Some(Severity::High.default_score()), "as written");
        assert_eq!(m.severity, Some(Severity::High));

        // A weight need not be a rung: 90 is used as written and described as
        // the highest rung it reaches, which is `Medium`. It is also short of
        // the rung a conviction needs, which is the ladder's own arithmetic and
        // not this module's opinion — a hand-written rule at 90 is corroborated
        // like any other.
        let mut m = meta();
        m.weight = Some(90);
        apply(&mut m, &[], "", Demand::None);
        assert_eq!(m.weight, Some(90), "still as written");
        assert_eq!(m.severity, Some(Severity::Medium));
        assert!(m.weight.unwrap() < Severity::High.default_score());

        // And `quality` — the corpus's field — does not halve it either. The two
        // vocabularies do not mix: a rule that speaks this engine's units is not
        // second-guessed by a rating from somebody else's.
        let mut m = meta();
        m.weight = Some(Severity::High.default_score());
        m.quality = Some(20);
        apply(&mut m, &[], "", Demand::None);
        assert_eq!(m.weight, Some(Severity::High.default_score()));
    }

    #[test]
    fn no_ordinary_rule_reaches_the_convicting_rung_on_its_own() {
        // The property that makes the pile at 75 safe to keep. A conviction
        // needs one detection that reaches `Severity::High`'s rung by itself —
        // `Assessment::finalize` is where that is enforced — so the highest an
        // ordinary rule may weigh is bounded by that rung, no matter how many of
        // them match. This is the arithmetic half of the defect that put two
        // ordinary patterns out of 10,764 over the line.
        for score in 50..90 {
            assert!(
                weight_for(score, Some(85)) < Severity::High.default_score(),
                "a corpus score of {score} reaches the convicting rung on its own"
            );
        }
        // And the corpus's own confident band still does, which is the half that
        // must not be traded away.
        assert_eq!(weight_for(90, Some(85)), Severity::High.default_score());
        assert_eq!(
            weight_for(100, Some(85)),
            Severity::Critical.default_score()
        );
    }

    #[test]
    fn the_severity_ladder_is_monotonic() {
        // The property that makes the derivation safe: a rule its author scored
        // higher is never described as less severe than one scored lower. The
        // report sorts and colours by severity, so a non-monotonic mapping
        // would put the more confident rule below the less confident one.
        let mut previous = Severity::Info;
        for score in 0..=Severity::Critical.default_score() + 50 {
            let severity = severity_of(score);
            assert!(
                severity >= previous,
                "score {score} went backwards: {previous:?} then {severity:?}"
            );
            previous = severity;
        }
    }

    #[test]
    fn the_severity_bands_break_exactly_on_the_ladders_own_rungs() {
        assert_eq!(severity_of(0), Severity::Info);
        assert_eq!(severity_of(Severity::Low.default_score()), Severity::Low);
        assert_eq!(
            severity_of(Severity::Low.default_score() - 1),
            Severity::Low,
            "a score just under a rung stays on the rung below it"
        );
        assert_eq!(
            severity_of(Severity::Medium.default_score()),
            Severity::Medium
        );
        assert_eq!(
            severity_of(Severity::Medium.default_score() - 1),
            Severity::Low
        );
        assert_eq!(severity_of(Severity::High.default_score()), Severity::High);
        assert_eq!(
            severity_of(Severity::Critical.default_score()),
            Severity::Critical
        );
    }

    #[test]
    fn only_a_zero_score_is_an_observation() {
        // `Info` is not the bottom of the scale, it is off the scale: it is the
        // severity that scores nothing and is never acted on. A rule halved for
        // poor quality contributes points and therefore cannot be `Info`, or
        // the report would promise the user something the verdict contradicts.
        for score in 1..Severity::Low.default_score() {
            assert_ne!(severity_of(score), Severity::Info, "score {score}");
            assert_eq!(severity_of(score), Severity::Low, "score {score}");
        }
    }

    #[test]
    fn a_declared_severity_stands_when_the_rule_states_no_score() {
        // The case this module must not touch: a rule written by hand in this
        // product's own language, stating this engine's own ladder.
        let mut m = meta();
        m.severity = Some(Severity::Critical);
        apply(&mut m, &[], "", Demand::None);
        assert_eq!(m.severity, Some(Severity::Critical));
        assert_eq!(m.weight, None, "and no score is invented for it");
        assert_eq!(m.score(), Severity::Critical.default_score());
    }

    #[test]
    fn a_declared_severity_gives_way_to_the_score_beside_it() {
        // The case it must touch, and the reason is in the module docs: the
        // corpus's `severity` is a different scale from this engine's, and a
        // rule that says `critical` while being worth 50 points is a rule whose
        // two halves describe different rules. Keeping both would print
        // `critical` next to `score 50` and leave the reader to guess which one
        // the scan will act on. The score is the one it acts on.
        let mut m = meta();
        m.severity = Some(Severity::Critical);
        m.score = Some(50);
        apply(&mut m, &[], "", Demand::None);
        assert_eq!(m.severity, Some(Severity::Low));
        assert_eq!(
            m.score(),
            30,
            "the corpus's 50 bands to this engine's bottom rung"
        );
    }

    #[test]
    fn a_score_the_ladder_cannot_express_is_still_described_by_it() {
        // 82 of the corpus's rules declare a severity and every one of them
        // carries a score of 65 or 75 — 67 of them while calling themselves
        // `critical`. This is that rule: the declaration gives way, and the
        // severity becomes the rung the score bands to.
        let mut m = meta();
        m.severity = Some(Severity::Critical);
        m.score = Some(75);
        m.quality = Some(80);
        apply(&mut m, &[], "", Demand::None);
        assert_eq!(m.severity, Some(Severity::Medium));
        assert_eq!(m.score(), 60);
    }

    #[test]
    fn a_rule_its_author_rated_badly_is_worth_half() {
        assert_eq!(weight_for(80, Some(85)), 80);
        assert_eq!(weight_for(80, Some(60)), 80);
        assert_eq!(weight_for(80, Some(59)), 40);
        // Absent quality is not a bad quality: a hand-written rule that says
        // nothing about its own quality is taken at its word.
        assert_eq!(weight_for(80, None), 80);
    }

    #[test]
    fn the_floor_is_the_line_and_not_a_band() {
        assert_eq!(weight_for(100, Some(QUALITY_FLOOR)), 150);
        assert_eq!(weight_for(100, Some(QUALITY_FLOOR - 1)), 75);
    }

    #[test]
    fn a_rule_tagged_info_is_an_observation_and_scores_nothing() {
        let mut m = meta();
        m.score = Some(90);
        m.quality = Some(85);
        m.decisive = true;
        apply(&mut m, &tags(&["file", "info"]), "", Demand::None);
        assert_eq!(m.severity, Some(Severity::Info));
        assert_eq!(m.weight, Some(0));
        assert!(!m.decisive, "an observation is never decisive");
        assert_eq!(m.score(), 0);
    }

    #[test]
    fn a_category_of_info_in_the_unmodelled_metadata_is_read_the_same_way() {
        // The corpus writes `category = "INFO"`, which is not a threat category
        // and therefore lands in `extra`. It is the one value there that means
        // something.
        let mut m = meta();
        m.score = Some(90);
        m.extra
            .insert("category".to_owned(), MetaValue::Text("INFO".to_owned()));
        apply(&mut m, &tags(&["file"]), "", Demand::None);
        assert_eq!(m.severity, Some(Severity::Info));
        assert_eq!(m.weight, Some(0));
    }

    #[test]
    fn a_tag_names_the_category_and_the_platform_when_the_author_did_not() {
        let mut m = meta();
        m.score = Some(75);
        apply(
            &mut m,
            &tags(&["FILE", "WINDOWS", "RANSOMWARE"]),
            "",
            Demand::None,
        );
        assert_eq!(m.category, Some(ThreatCategory::Ransomware));
        assert_eq!(m.platform, Some(Platform::Win));
        assert!(m.threat().is_some(), "so the report can name a family");
    }

    #[test]
    fn the_authors_own_category_beats_a_tag() {
        let mut m = meta();
        m.category = Some(ThreatCategory::Miner);
        apply(&mut m, &tags(&["ransomware"]), "", Demand::None);
        assert_eq!(m.category, Some(ThreatCategory::Miner));
    }

    #[test]
    fn a_tag_that_is_not_a_category_is_simply_not_one() {
        // The bulk of this corpus's tag vocabulary is not threat categories:
        // `file` and `memory` say what was examined, `highvol` where it came
        // from, `tc_detection` who wrote the rule, `cve-…` what it exploits,
        // and the bamboo/storm/kitten words who is believed to be behind it.
        // Nothing here may become a category, because the value of a category
        // is that it is specific, and one guessed from an intrusion set's name
        // is the wrong kind of specific: a report that calls a file `APT`
        // because its rule was tagged with an actor has named a fact about the
        // rule, not about the file.
        let mut m = meta();
        apply(
            &mut m,
            &tags(&[
                "FILE",
                "MEMORY",
                "HIGHVOL",
                "TC_DETECTION",
                "PLATINUM",
                "STORMBAMBOO",
                "CVE-2022-30190",
                "T1027",
            ]),
            "",
            Demand::None,
        );
        assert_eq!(m.category, None);
        assert_eq!(m.platform, None);
    }

    #[test]
    fn a_tag_that_says_only_malicious_names_no_family() {
        // The corpus's two most common category-ish tags both mean "something
        // bad, unspecified", and they map to `Unknown` — which renders as
        // `Malware`. That is true and deliberately no more specific than true.
        // These two tags alone carry 623 of the 754 tag occurrences that name
        // any category at all, which is the honest measure of how much this
        // mapping refines: where the corpus knows the family it says so in the
        // rule's `category`, and where it does not, a tag cannot supply it.
        let mut m = meta();
        apply(&mut m, &tags(&["MALICIOUS", "MALWARE"]), "", Demand::None);
        assert_eq!(m.category, Some(ThreatCategory::Unknown));
        assert_eq!(ThreatCategory::Unknown.as_str(), "Malware");
    }

    #[test]
    fn only_a_high_score_and_a_high_quality_together_are_decisive() {
        let decisive = |score, quality| {
            let mut m = meta();
            m.score = Some(score);
            m.quality = Some(quality);
            apply(&mut m, &[], "", Demand::None);
            m.decisive
        };
        assert!(decisive(DECISIVE_SCORE, DECISIVE_QUALITY));
        assert!(decisive(100, 90));
        // One without the other is a rule its author trusts but wrote badly, or
        // wrote well but does not trust. Neither is a reason to skip the
        // threshold comparison.
        assert!(!decisive(89, 90));
        assert!(!decisive(100, 79));
        assert!(!decisive(75, 85));
    }

    /// The rating route is beyond trust's reach and the two reading routes are
    /// not, and the difference is what the tests below pin down.
    ///
    /// A rule the author rated 90/80 is a claim about the sample: the author is
    /// saying "this matches, stop looking", and a certificate cannot answer it,
    /// because signing real malware with a stolen certificate is a thing that
    /// happens. A rule that convicts on its *title* was rated ordinary by that
    /// same author, and an ordinary rating is a claim about the rule.
    #[test]
    fn only_the_rating_route_is_beyond_argument() {
        let mut rated = meta();
        rated.score = Some(95);
        rated.quality = Some(90);
        apply(
            &mut rated,
            &[],
            "SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1",
            Demand::None,
        );
        assert!(rated.decisive && rated.incontestable);

        let mut named = meta();
        named.score = Some(75);
        named.quality = Some(85);
        apply(&mut named, &[], "HARFANGLAB_Wingtb_Rootkit", Demand::None);
        assert!(named.decisive, "it still convicts alone");
        assert!(!named.incontestable, "but a proven publisher answers it");
    }

    /// A rule in this product's own language that writes `decisive` is its
    /// author staking the strongest claim the language can make, which is the
    /// same kind of statement as the corpus's own decisive rating.
    ///
    /// Asserted through [`crate::database::RuleMetadata::calibrated`] because
    /// that is where the flag is carried from the rule's own metadata into the
    /// engine, and the assertion is about the pair surviving calibration
    /// together — a `decisive` that arrived without `incontestable` would be a
    /// rule its own author marked beyond argument and trust could still
    /// discount.
    #[test]
    fn a_rule_that_states_its_own_decisiveness_is_beyond_argument() {
        use crate::ast::{Rule, RuleMeta};

        let own = crate::database::RuleMetadata::calibrated(
            &Rule {
                name: "own/ransom/lockbit_note".to_owned(),
                private: false,
                global: false,
                tags: Vec::new(),
                meta: RuleMeta {
                    decisive: true,
                    weight: Some(120),
                    ..RuleMeta::default()
                },
                strings: Vec::new(),
                condition: crate::ast::Expr::Bool(true),
                span: crate::ast::Span::default(),
            },
            &[],
        );
        assert!(own.decisive && own.incontestable);
        assert_eq!(
            own.weight,
            Some(120),
            "an author's own weight is used as written"
        );
    }

    #[test]
    fn a_signature_is_decisive_on_its_name_at_an_ordinary_score() {
        // The rule this was reported with, and the whole reason the name is
        // read: score 75 and quality 80 put it at 60 points through the bands,
        // one rung short of the line a single detection needs, so a match by a
        // named rootkit's signature was reported `Suspicious` — a band that
        // never acts — and the one match that identified the malware was the
        // one match nothing could be done about.
        let mut m = meta();
        m.score = Some(75);
        m.quality = Some(80);
        apply(
            &mut m,
            &[],
            "SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver",
            Demand::None,
        );
        assert!(m.decisive, "a named rootkit signature convicts alone");
        assert_eq!(m.weight, Some(Severity::High.default_score()));
        assert_eq!(m.severity, Some(Severity::High));
    }

    #[test]
    fn a_family_wide_rule_is_left_where_the_bands_put_it() {
        // The other half of the distinction, and the reason it is drawn at all:
        // `Webshell_Php_Up` names a family and no instance, so a single match is
        // an indicator and not an identification. Convicting on it is how a
        // scanner starts quarantining the web server's own scripts.
        for name in [
            "SIGNATURE_BASE_Webshell_Php_Up",
            "SIGNATURE_BASE_IMPLANT_1_V1",
        ] {
            let mut m = meta();
            m.score = Some(75);
            m.quality = Some(85);
            apply(&mut m, &[], name, Demand::None);
            assert!(!m.decisive, "{name}");
            assert_eq!(m.weight, Some(60), "{name}");
        }
    }

    #[test]
    fn a_signature_its_author_rated_below_the_quality_bar_does_not_convict() {
        // The name says a signature; the author says the rule was written
        // badly. Both have to agree, exactly as they do in
        // `only_a_high_score_and_a_high_quality_together_are_decisive`.
        let mut m = meta();
        m.score = Some(75);
        m.quality = Some(DECISIVE_QUALITY - 1);
        apply(&mut m, &[], "HARFANGLAB_Wingtb_Rootkit", Demand::None);
        assert!(!m.decisive);
        assert_eq!(m.weight, Some(60));
    }

    #[test]
    fn a_signature_keeps_a_rating_higher_than_the_convicting_rung() {
        // Raised, not assigned: a rule the corpus already rates at 150 is not
        // brought down to 100 by being recognised in its name.
        let mut m = meta();
        m.score = Some(100);
        m.quality = Some(90);
        apply(
            &mut m,
            &[],
            "REVERSINGLABS_Win32_Ransomware_Blackbasta",
            Demand::None,
        );
        assert!(m.decisive);
        assert_eq!(m.weight, Some(Severity::Critical.default_score()));
        assert_eq!(m.severity, Some(Severity::Critical));
    }

    /// The rule the content route was added for, at the metadata it actually
    /// carries.
    ///
    /// `CAPE_Azorult` is a hundred and ten bytes of the malware's own code and a
    /// seventy-four byte SQL statement under `all of them`. Its name says
    /// `Azorult` and no instance of it, and its quality is 70 — below
    /// [`DECISIVE_QUALITY`] — so both routes that existed before passed it by and
    /// it was reported `Suspicious`, a band that never acts, while its condition
    /// said a file cannot satisfy it without carrying the code.
    ///
    /// The quality is deliberately left below the bar: the shape of a condition
    /// is evidence about how the rule was built, and requiring the author to
    /// have also *said* the rule was well built would leave exactly the rules
    /// this route exists for where the defect left them.
    #[test]
    fn a_condition_that_needs_a_specific_indicator_convicts_at_an_ordinary_score() {
        let mut m = meta();
        m.score = Some(75);
        m.quality = Some(70);
        apply(&mut m, &[], "CAPE_Azorult", Demand::Specific);
        assert!(m.decisive, "the condition identified the file");
        assert_eq!(m.weight, Some(Severity::High.default_score()));
        assert_eq!(m.severity, Some(Severity::High));
    }

    /// And the safety valve, asserted rather than assumed: the content route is
    /// an argument about the rule's *shape*, not a statement about the sample,
    /// so evidence about who published the file still has standing on it. A
    /// promoted rule that could not be argued down would be a route to
    /// quarantining an unmodified signed original.
    #[test]
    fn a_conviction_read_out_of_a_condition_is_still_open_to_argument() {
        let mut m = meta();
        m.score = Some(75);
        m.quality = Some(70);
        apply(&mut m, &[], "CAPE_Azorult", Demand::Specific);
        assert!(m.decisive && !m.incontestable);
    }

    /// The control, and the half that keeps this route from being "everything
    /// convicts now": a condition some path can satisfy without a specific
    /// indicator is a hunting rule, whatever its strings look like.
    #[test]
    fn a_condition_satisfiable_by_a_short_string_stays_where_the_bands_put_it() {
        // The same metadata as the case above, so that the only thing that
        // differs between the two tests is the reading — neither the rating
        // route nor the name route can fire here, and a conviction would be the
        // content route's alone.
        for demand in [Demand::Loose, Demand::None] {
            let mut m = meta();
            m.score = Some(75);
            m.quality = Some(70);
            apply(&mut m, &[], "CAPE_Azorult", demand);
            assert!(!m.decisive, "{demand:?}");
            assert_eq!(m.weight, Some(60), "{demand:?}");
        }
    }

    /// A rule in this product's own language that states a `weight` returns
    /// before any of the three routes, exactly as it does for the name route:
    /// the field speaks this engine's units and is used as written.
    #[test]
    fn a_rule_that_states_its_own_weight_is_not_read_by_its_condition() {
        let mut m = meta();
        m.weight = Some(40);
        m.score = Some(75);
        m.quality = Some(70);
        apply(&mut m, &[], "", Demand::Specific);
        assert!(!m.decisive);
        assert_eq!(m.weight, Some(40));
    }

    #[test]
    fn a_rule_that_states_its_own_weight_is_not_read_by_its_name() {
        // This product's own language states its own worth, and the whole
        // module returns before the bands for such a rule — the name read is
        // part of reading somebody else's metadata and stops where that stops.
        let mut m = meta();
        m.weight = Some(40);
        m.score = Some(75);
        m.quality = Some(90);
        apply(
            &mut m,
            &[],
            "SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver",
            Demand::None,
        );
        assert!(!m.decisive);
        assert_eq!(m.weight, Some(40));
        assert_eq!(m.severity, Some(Severity::Low));
    }

    #[test]
    fn a_rule_with_no_author_metadata_is_left_exactly_as_it_was() {
        // The property that keeps this module from being a policy imposed on
        // hand-written rules: nothing here fires without the metadata.
        let mut m = meta();
        m.severity = Some(Severity::High);
        m.family = Some("Emotet".to_owned());
        let before = m.clone();
        apply(&mut m, &[], "", Demand::None);
        assert_eq!(m, before);
    }
}
