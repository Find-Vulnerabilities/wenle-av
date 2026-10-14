//! The process exit codes, as a type.
//!
//! An enum rather than four `std::process::exit(1)` calls scattered through the
//! command implementations, because the codes are a contract with whatever
//! script is calling this binary and a contract that is written down in four
//! places is a contract that will be broken in one of them.

use av_core::Verdict;

/// What the process exits with.
///
/// See the crate documentation for the table; the discrimination between
/// [`Exit::Suspicious`] and [`Exit::Malicious`] is the whole reason this is an
/// enum rather than a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    /// Nothing to act on.
    Clean = 0,
    /// At least one target is malicious.
    Malicious = 1,
    /// The scan could not be completed.
    Failure = 2,
    /// Nothing malicious, but something suspicious.
    Suspicious = 3,
}

impl Exit {
    /// The code for a set of verdicts, with the caller's strictness applied.
    ///
    /// A failure anywhere outranks a detection: `--fail-on-suspicious` can turn
    /// a suspicious file into a code 1, but it cannot turn an unreadable
    /// directory into one, because the caller needs to be able to tell "there
    /// was malware" from "there might have been and I could not look".
    pub fn from_verdicts(
        verdicts: impl IntoIterator<Item = Verdict>,
        fail_on_suspicious: bool,
    ) -> Self {
        let mut seen = Exit::Clean;
        for verdict in verdicts {
            match verdict {
                Verdict::Malicious => return Exit::Malicious,
                Verdict::Unknown => seen = Exit::Failure,
                Verdict::Suspicious if fail_on_suspicious && seen == Exit::Clean => {
                    seen = Exit::Suspicious;
                }
                // A suspicious verdict without the flag is not an outcome a
                // script can act on: the engine looked, found something worth
                // mentioning, and deliberately did nothing about it.
                _ => {}
            }
        }
        seen
    }
}
