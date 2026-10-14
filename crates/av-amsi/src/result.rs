//! The one thing AMSI asks for, and the one answer that must never be given.
//!
//! # The ladder
//!
//! `AMSI_RESULT` is a number, and Windows reads it as a band rather than as a
//! boolean:
//!
//! | Value     | Constant                       | What the host does                |
//! |-----------|--------------------------------|-----------------------------------|
//! | `0`       | `AMSI_RESULT_CLEAN`            | runs it                           |
//! | `1`       | `AMSI_RESULT_NOT_DETECTED`     | runs it                           |
//! | `16384`…`20479` | `AMSI_RESULT_BLOCKED_BY_ADMIN_*` | refuses it, administrator's doing |
//! | `32768`   | `AMSI_RESULT_DETECTED`         | refuses it, and says who said so  |
//!
//! Two of those look alike from the outside and are not alike at all, and the
//! difference is the entire reason this module exists.
//!
//! # Why `CLEAN` is never returned
//!
//! `CLEAN` is a claim: *this content is not malicious*. A static scanner cannot
//! honestly make it. It sees bytes; it does not see what they will do, and the
//! content it is being asked about is by construction the content somebody
//! thought worth obfuscating. `NOT_DETECTED` says the true thing — *I have no
//! evidence against this* — and hosts treat the two identically, so returning
//! `CLEAN` buys nothing and costs the truth.
//!
//! The rule is therefore: **`DETECTED` or `NOT_DETECTED`, and nothing else.**
//! Every failure path in this crate — no service, a timeout, a panic, a
//! malformed reply — ends at [`no_opinion`], which is `NOT_DETECTED`. None of
//! them ends at `CLEAN`, and a test below holds that line for the whole ladder.
//!
//! # Why the middle band does not block
//!
//! [`Verdict::blocks`] is the policy and this module is its only caller on this
//! side of the pipe. A `Suspicious` script is one where something fired and not
//! enough fired, and this product's answer to that band is to *tell the user*
//! and not to act. Answering `DETECTED` for it would make a host refuse to run
//! content this product's own policy says it must not refuse — which is a
//! product acting outside its rules, and the failure mode a user experiences as
//! "it blocked my script and would not say why".

use av_core::Verdict;
use windows::Win32::System::Antimalware::{
    AMSI_RESULT, AMSI_RESULT_DETECTED, AMSI_RESULT_NOT_DETECTED,
};

/// The answer for a scan that reached a verdict.
///
/// See [`Verdict::blocks`]: only the red band is refused.
pub const fn for_verdict(verdict: Verdict) -> AMSI_RESULT {
    if verdict.blocks() {
        AMSI_RESULT_DETECTED
    } else {
        AMSI_RESULT_NOT_DETECTED
    }
}

/// The answer when there is no verdict to give.
///
/// Takes no argument on purpose. A function that took one — an error, a
/// duration, a reason — would invite a caller to pass something and get a
/// different result out, and there is exactly one honest answer when this crate
/// could not examine the content, which is that it has nothing to say.
///
/// It is a constant function rather than a constant so that call sites read as
/// a decision rather than as a literal.
pub const fn no_opinion() -> AMSI_RESULT {
    AMSI_RESULT_NOT_DETECTED
}

/// True when `result` would make a host refuse to run the content.
///
/// The inverse of [`for_verdict`], for tests and for the log line that says
/// what this provider told the host. Deliberately not `result == DETECTED`:
/// the administrator band also refuses, and a helper that quietly ignored it
/// would be wrong about a host that is configured differently from this one.
pub const fn blocks(result: AMSI_RESULT) -> bool {
    result.0 >= AMSI_RESULT_BLOCKED_BY_ADMIN_START_VALUE
}

/// The lower bound of the administrator band, as a plain `i32`.
///
/// Spelled as a number rather than read from the generated constant so that
/// this comparison — which is a range test and not an equality — states what
/// it is comparing against. The test below pins the two together.
const AMSI_RESULT_BLOCKED_BY_ADMIN_START_VALUE: i32 = 16_384;

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Antimalware::{
        AMSI_RESULT_BLOCKED_BY_ADMIN_END, AMSI_RESULT_BLOCKED_BY_ADMIN_START, AMSI_RESULT_CLEAN,
    };

    #[test]
    fn only_the_red_band_is_refused_and_the_yellow_band_is_waved_through() {
        assert_eq!(for_verdict(Verdict::Malicious), AMSI_RESULT_DETECTED);
        assert_eq!(for_verdict(Verdict::Suspicious), AMSI_RESULT_NOT_DETECTED);
        assert_eq!(for_verdict(Verdict::Clean), AMSI_RESULT_NOT_DETECTED);
        // Not examined is not clean, and it is also not blocked. The host runs
        // content this provider failed to look at, which is the correct and
        // uncomfortable trade: the alternative is an unavailable scanner
        // breaking every script on the machine.
        assert_eq!(for_verdict(Verdict::Unknown), AMSI_RESULT_NOT_DETECTED);
    }

    #[test]
    fn the_answer_this_crate_gives_is_never_clean() {
        // The line this whole module is written to hold. Every verdict, and the
        // no-opinion path, and not one of them is `AMSI_RESULT_CLEAN`.
        for verdict in [
            Verdict::Clean,
            Verdict::Suspicious,
            Verdict::Malicious,
            Verdict::Unknown,
        ] {
            assert_ne!(for_verdict(verdict), AMSI_RESULT_CLEAN, "{verdict:?}");
        }
        assert_ne!(no_opinion(), AMSI_RESULT_CLEAN);
        assert_eq!(no_opinion(), AMSI_RESULT_NOT_DETECTED);
    }

    #[test]
    fn the_two_answers_are_exactly_the_two_a_host_acts_on_differently() {
        // `DETECTED` is above the administrator band and everything else this
        // crate returns is below it, so a host reading the value as a band —
        // which is what a host does — gets exactly the two outcomes this
        // module documents and nothing in between.
        assert!(blocks(for_verdict(Verdict::Malicious)));
        for verdict in [Verdict::Clean, Verdict::Suspicious, Verdict::Unknown] {
            assert!(!blocks(for_verdict(verdict)), "{verdict:?}");
        }
        assert!(!blocks(no_opinion()));
        assert!(!blocks(AMSI_RESULT_CLEAN));
        // And the band predicate agrees with the generated constants rather
        // than with the number written down in this file.
        assert!(blocks(AMSI_RESULT_BLOCKED_BY_ADMIN_START));
        assert!(blocks(AMSI_RESULT_BLOCKED_BY_ADMIN_END));
        assert!(!blocks(AMSI_RESULT(
            AMSI_RESULT_BLOCKED_BY_ADMIN_START.0 - 1
        )));
        assert_eq!(
            AMSI_RESULT_BLOCKED_BY_ADMIN_START_VALUE,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START.0
        );
    }

    #[test]
    fn the_predicate_this_crate_answers_with_is_the_one_the_service_acts_on() {
        // `av-service` decides whether to move a file into the vault with
        // `should_take`, which is `Verdict::blocks`, which is what this module
        // calls. This test is the reason that method exists rather than a
        // second match here: if the two ever disagree, a user is told a script
        // was stopped while the host runs it, or the reverse.
        for verdict in [
            Verdict::Clean,
            Verdict::Suspicious,
            Verdict::Malicious,
            Verdict::Unknown,
        ] {
            assert_eq!(
                blocks(for_verdict(verdict)),
                verdict.blocks(),
                "{verdict:?}"
            );
        }
    }
}
