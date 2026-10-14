//! Writing findings for a person to read.
//!
//! # Why this is a module and not `println!` at the call sites
//!
//! Because the same finding has to be legible in three places at once — a
//! terminal, a redirected log file, and a bug report pasted into a ticket — and
//! the decisions that make it legible are the same decisions every time. Which
//! of the three bands a verdict is in decides the colour, the word, and
//! whether there is anything to say at all; a call site that decided those for
//! itself would get one of them wrong and the wrong one would be the colour.
//!
//! # Colour is not decoration here
//!
//! A scan of a large tree prints hundreds of lines and the two that matter are
//! the ones saying a file is malicious. Colour is how those two are found
//! without reading, and it is applied through the `console` crate so that it
//! switches itself off when the output is a pipe, when `NO_COLOR` is set, or
//! when the user asked for `--no-color`.

use std::io::{self, Write};

use av_core::{Assessment, Detection, Verdict};
use console::{style, Style};

/// The word printed for each band of the verdict model.
///
/// The same three words the graphical front end uses, and for the reason the
/// bands exist: `suspicious` and `malicious` are different instructions to the
/// user, not two shades of the same one.
pub fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Clean => "clean",
        Verdict::Suspicious => "suspicious",
        Verdict::Malicious => "malicious",
        Verdict::Unknown => "unknown",
    }
}

/// The style a verdict's own word is printed in.
pub fn verdict_style(verdict: Verdict) -> Style {
    match verdict {
        Verdict::Clean => Style::new().green(),
        Verdict::Suspicious => Style::new().yellow().bold(),
        Verdict::Malicious => Style::new().red().bold(),
        // Neither good news nor an accusation: the engine did not manage to
        // look, and a user who assumes a colour means what the other two mean
        // would be wrong either way.
        Verdict::Unknown => Style::new().magenta(),
    }
}

/// Print an error to standard error.
pub fn error(message: &str) {
    let _ = writeln!(io::stderr(), "{} {message}", style("error:").red().bold());
}

/// Print a warning to standard error.
pub fn warn(message: &str) {
    let _ = writeln!(
        io::stderr(),
        "{} {message}",
        style("warning:").yellow().bold()
    );
}

/// A line of a section, printed to standard output.
///
/// Used for the headings of a report, so that every one of them is laid out
/// the same way without a table implementation: a scanner that draws boxes in
/// one command and prints bare words in another reads as two tools.
pub fn heading(text: &str) {
    println!("{}", heading_line(text));
}

/// The text of a heading, styled, leading blank line included.
///
/// Split from [`heading`] for the same reason [`finding_lines`] is split from
/// [`finding`]: a section built as a list of lines has to get its heading from
/// somewhere, and it should be this, so that every heading in the product is
/// still laid out in exactly one place.
pub fn heading_line(text: &str) -> String {
    format!("\n{}", style(text).bold().underlined())
}

/// One finding, as a person reads it.
///
/// The layout is the one a user has seen from every other scanner:
///
/// ```text
///   malicious  C:\Users\me\Downloads\invoice.exe
///              Win32.Ransomware.LockBit
///              score 250 — 3 detections
///              0x1400 (32 bytes)  ransomware/lockbit_note
/// ```
///
/// The indent under the path is deliberate: a tree of a thousand clean files
/// produces no output at all, so every line printed is one the user asked to
/// see, and they should be able to read the path first and the explanation
/// second.
///
/// A detection found inside a container carries the name of the member it was
/// found in, printed in front of the offset:
///
/// ```text
///              invoice.zip/payload.exe:0x1400 (32 bytes)  trojan/dropper
/// ```
///
/// The name is not decoration. `0x1400` on its own is an offset into the outer
/// file, and a member's offset is not one — a user who went looking for that
/// byte in the zip would find a compressed byte stream and conclude the scanner
/// was making things up. Naming the member makes the number true.
pub fn finding(path: &str, verdict: Verdict, score: u16, detections: &[Detection]) {
    for line in finding_lines(path, verdict, score, detections, None) {
        println!("{line}");
    }
}

/// One finding, as lines rather than as calls to `println!`.
///
/// Split out for two reasons. The layout can be asserted as the text a user
/// reads, which a function that prints cannot be tested for from inside the
/// process that printed it; and a caller that knows one more fact about its
/// target can put that fact where it belongs instead of after everything else.
///
/// `note` is that fact: the second line of a memory finding, saying what kind of
/// region the match was read out of — `unbacked-executable`, `image`, private,
/// how big. It goes between the score and the offsets because that is the order
/// the questions are asked: what is this, how sure are you, and where in it. A
/// file finding has no such line and passes `None`.
pub fn finding_lines(
    path: &str,
    verdict: Verdict,
    score: u16,
    detections: &[Detection],
    note: Option<&str>,
) -> Vec<String> {
    let mut lines = Vec::new();
    let word = verdict_style(verdict)
        .apply_to(verdict_word(verdict))
        .to_string();
    lines.push(format!("  {word}  {path}"));
    if detections.is_empty() {
        return lines;
    }

    // The threat name when there is one, because that is the name a user
    // searches for; the rule that produced it otherwise.
    let named = detections
        .iter()
        .filter_map(|d| d.threat.as_ref().map(|t| t.to_string()))
        .next();
    if let Some(name) = named {
        lines.push(format!("             {name}"));
    }

    let plural = if detections.len() == 1 { "" } else { "s" };
    let confidence = detections.iter().filter(|d| d.decisive).count();
    let decisive = if confidence > 0 {
        format!(" ({confidence} decisive)")
    } else {
        String::new()
    };
    lines.push(format!(
        "             score {score} — {} detection{plural}{decisive}",
        detections.len()
    ));

    if let Some(note) = note {
        lines.push(format!("             {}", style(note).dim()));
    }

    for detection in detections {
        let at = where_in(detection);
        lines.push(format!(
            "             {}{}  {}",
            style(at).dim(),
            style(&detection.rule_id).cyan(),
            style(&detection.description).dim()
        ));
    }
    lines
}

/// The two things trust can do to an assessment, as the lines that explain it.
///
/// Both of trust's verdict moves set [`Assessment::remediation_withheld`], and
/// both answer the same question — "why was this not acted on?" — which a user
/// asks about a scan far more often than they ask its opposite. The verdict
/// tells the two apart: `Clean` is the move that cleared the file, and anything
/// else is the move that capped it. [`Assessment::suppressed`] is filled only by
/// the first, and it is printed as the rule ids whose matches were thrown away,
/// because "which rule fired" is the next question after "why is this clean".
///
/// Nothing here is printed for an assessment trust did not touch, which is
/// almost all of them.
pub fn trust_lines(assessment: &Assessment) -> Vec<String> {
    if !assessment.remediation_withheld {
        return Vec::new();
    }
    let cleared = assessment.verdict == Verdict::Clean;
    let lead = if cleared {
        "why this is clean: its bytes are the ones a signed catalogue lists"
    } else {
        "why nothing was done: the file carries a certificate that was read and not verified"
    };
    let detail = if cleared {
        "The detections above were suppressed rather than acted on — they describe how the file \
         was built, and a catalogue entry listing these exact bytes is a complete answer to that. \
         The score stays as it was found."
    } else {
        "Every detection above describes how the file was built rather than what it is, and an \
         unverified certificate is not proof of who wrote it. The score is reported and the file \
         is left alone."
    };
    let mut lines = vec![
        format!("             {}", style(lead).yellow().bold()),
        format!("             {}", style(detail).dim()),
    ];
    if !assessment.suppressed.is_empty() {
        lines.push(format!(
            "             {}",
            style(format!("suppressed: {}", assessment.suppressed.join(", "))).dim()
        ));
    }
    lines
}

/// Where a detection was found, as the prefix of its line: the member name when
/// it was found inside a container, then the offset when there is one.
///
/// Both halves are optional and both are absent often — a rule that matched on
/// a file-level property has no offset, and a member found by such a rule has
/// no offset but still has a name. The trailing two spaces are part of the
/// non-empty return so that the caller can concatenate unconditionally.
fn where_in(detection: &Detection) -> String {
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

/// A summary line, printed after a scan.
pub fn summary(line: &str) {
    println!("\n{line}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{DetectionSource, MatchLocation, Severity};

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

    #[test]
    fn a_plain_finding_leads_with_its_offset() {
        let detection = detection().with_location(location());
        assert_eq!(where_in(&detection), "0x1400 (32 bytes)  ");
    }

    #[test]
    fn a_member_finding_names_the_member_before_the_offset() {
        // The whole point: `0x1400` is an offset into `payload.exe`, not into
        // the zip a user would otherwise go looking in.
        let detection = detection().with_location(location()).within("payload.exe");
        assert_eq!(where_in(&detection), "payload.exe:0x1400 (32 bytes)  ");
    }

    #[test]
    fn a_member_finding_with_no_offset_still_names_the_member() {
        // A rule that matched on a structural property has no offset to show,
        // and dropping the member name with it would leave the line saying
        // nothing about where the finding was.
        let detection = detection().within("C:\\a.zip\\deep\\payload.exe");
        assert_eq!(where_in(&detection), "C:\\a.zip\\deep\\payload.exe  ");
    }

    #[test]
    fn a_finding_with_neither_is_an_empty_prefix() {
        // Not `"  "`: the caller concatenates unconditionally, and a
        // structural detection of the outer file would otherwise be indented
        // two spaces further than its neighbours for no reason.
        assert_eq!(where_in(&detection()), "");
    }

    /// An assessment trust capped: the verdict was moved down a band, the score
    /// was left alone, and nothing was suppressed because nothing was thrown
    /// away. This is the shape a signed file with an unknown generic detection
    /// in it produces, and the one a user is most likely to ask about.
    fn capped() -> Assessment {
        let mut assessment = Assessment {
            verdict: Verdict::Suspicious,
            score: 100,
            ..Assessment::default()
        };
        assessment.withhold_remediation();
        assessment
    }

    /// An assessment trust cleared: the verdict is `Clean`, the detections are
    /// still in the list, and their ids are recorded as suppressed.
    fn cleared() -> Assessment {
        let mut assessment = Assessment {
            verdict: Verdict::Clean,
            score: 60,
            ..Assessment::default()
        };
        assessment.suppress("SIGNATURE_BASE_WEBSHELL");
        assessment.suppress("SIGNATURE_BASE_MAL_ROOTKIT_Driver");
        assessment.withhold_remediation();
        assessment
    }

    #[test]
    fn an_assessment_trust_did_not_touch_gets_no_lines() {
        // The common case by a wide margin: 700 lines of a System32 scan say
        // nothing here, and a report that grew three lines per file would bury
        // the findings it is about.
        assert!(trust_lines(&Assessment::default()).is_empty());
        let mut ordinary = Assessment::clean();
        ordinary.push(detection());
        assert!(trust_lines(&ordinary).is_empty());
    }

    #[test]
    fn a_capped_verdict_says_why_nothing_was_done() {
        let text = trust_lines(&capped()).join("\n");
        assert!(text.contains("why nothing was done"), "{text}");
        // The one fact that makes the sentence true rather than reassuring: the
        // certificate was read and not verified. A file left alone because it
        // is *signed* is a different claim from one left alone because its
        // signature was checked, and only the first is what happened.
        assert!(text.contains("read and not verified"), "{text}");
        // Nothing was thrown away, so there is no list to print. A "suppressed:"
        // line with nothing after it would say the opposite of what happened.
        assert!(!text.contains("suppressed:"), "{text}");
    }

    #[test]
    fn a_cleared_file_says_so_and_names_the_rules_it_threw_away() {
        let text = trust_lines(&cleared()).join("\n");
        assert!(text.contains("why this is clean"), "{text}");
        assert!(
            text.contains("suppressed: SIGNATURE_BASE_WEBSHELL, SIGNATURE_BASE_MAL_ROOTKIT_Driver"),
            "{text}"
        );
        // The catalogue is what settles it, not the certificate — the two are
        // different evidence and only one of them is a proof.
        assert!(text.contains("signed catalogue"), "{text}");
        assert!(!text.contains("certificate"), "{text}");
    }

    #[test]
    fn a_nested_members_chain_is_shown_whole() {
        // `Detection::within` takes the chain as the archive stage built it,
        // `outer/inner`. This pins that the printer shows it as one name rather
        // than picking it apart, because only the archive knows where the
        // separators are.
        let detection = detection()
            .with_location(location())
            .within("bundle.zip/tools/payload.exe");
        assert_eq!(
            where_in(&detection),
            "bundle.zip/tools/payload.exe:0x1400 (32 bytes)  "
        );
    }
}
