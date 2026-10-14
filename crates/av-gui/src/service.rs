//! Asking the service to do something, from the window.
//!
//! # Why the window does not simply do it
//!
//! The vault holds one index, and that index is rewritten whole on every
//! change. Its own documentation says what follows from that: one writer. The
//! service is that writer — every detection it acts on goes through
//! `Host::quarantine` — and until this module existed the window was a second
//! one, restoring and deleting entries behind the service's back. A user who
//! pressed *Delete* at the moment the service took a file would, on a bad
//! enough interleaving, leave the index describing neither machine state.
//!
//! So the window asks. The answer — [`av_ipc::QuarantineChange`] — is the
//! service's own account of what it did, and the window reports that rather
//! than a story of its own.
//!
//! # What the window still does itself
//!
//! It quarantines the findings of a scan *it* ran, into the vault it has open.
//! That is a second writer and it is named rather than hidden: routing it
//! would mean sending a whole [`av_core::scan::FileScanReport`] over the wire
//! and rebuilding the batch's own bookkeeping — the ticked set, the clean files
//! skipped, the removals deferred — on top of it. The two operations here are
//! the ones a user performs *about* an item that is already in the vault, and
//! they are the ones the service can answer for exactly; the scan's is the
//! window's own work, about files the service has not seen.
//!
//! # The service may not be running
//!
//! Then there is no answer, and the caller falls back to the vault it has open
//! — which is exactly one writer again, because the other one is not there. The
//! distinction is visible to the user: the status line says which of the two
//! performed the change. [`Unreachable`] is what tells the caller apart from a
//! refusal, and the two are not the same thing: a refusal is the service
//! saying no, and hiding it behind a local retry would be the window overruling
//! the process that owns the vault.

use std::time::{Duration, Instant};

use av_ipc::{Client, Incoming, QuarantineChange, Reply, Request, PIPE_NAME};
use av_quarantine::QuarantineId;
use av_service::pipe::PipeConnection;

/// How long the window waits for an answer before deciding the service is not
/// going to give one.
///
/// Generous for what the service does — a restore or a delete is one index
/// write — and short enough that a stuck service does not freeze the frame that
/// asked. The window draws at 60 Hz and this runs on the drawing thread, so the
/// cost of the timeout is paid only when something is already wrong.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to sleep between reads while waiting.
///
/// The pipe is synchronous here: the answer is usually already in the buffer by
/// the time the first read returns, so this is a backoff for the rare case and
/// not a poll interval. Small, because the whole of a healthy exchange is a few
/// hundred microseconds and a coarser sleep would be most of the measured time.
const POLL: Duration = Duration::from_millis(2);

/// Why the window could not ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreachable {
    /// Nothing is listening on the control pipe named, or the service would not
    /// take the connection.
    ///
    /// Carries the name it tried, so that a line about a service that is not
    /// there says *which* pipe was quiet. The window asks on one name and a test
    /// on another, and a message that named a constant instead of the pipe
    /// actually used would be a message about a different machine.
    NoService(String),
    /// The service took the connection and said nothing before the deadline.
    Silent,
    /// The exchange failed after it started.
    Transport(String),
    /// The service read the request and would not do it, and said why.
    ///
    /// A variant of its own rather than `Transport` because it is the one
    /// outcome here in which the service is working exactly as it should: the
    /// connection was made, the request was read, and the answer is no. Folded
    /// into "the service could not be reached" it would send somebody looking
    /// for a service that is running perfectly — and the sentence the service
    /// sent is the whole of the explanation, so it is carried rather than
    /// summarised.
    ///
    /// What produces it: `av_service::peer` refuses the requests that change
    /// the product's state when the account on the connection is not the one
    /// signed in at this machine's console and is not an administrator. A
    /// second user signed in by fast user switching pressing *Put back* in this
    /// window is the case it exists for.
    Refused(String),
}

impl Unreachable {
    /// One line for a person, phrased as the state of the machine.
    ///
    /// Written as a fact about the service rather than about the window, which
    /// is the same rule the rest of the window's wording follows: what the user
    /// needs is to know whether their protection is running.
    pub fn describe(&self) -> String {
        match self {
            Self::NoService(name) => format!("no service is listening on {name}"),
            Self::Silent => "the service accepted the connection and did not answer".to_string(),
            Self::Transport(detail) => format!("the service could not be reached: {detail}"),
            // Passed through rather than prefixed: the service's sentence names
            // the account, the session and what would have worked instead, and
            // anything this window put in front of it would only be in the way.
            Self::Refused(reason) => reason.clone(),
        }
    }
}

/// The name the installed product serves its control pipe on.
///
/// The window's own [`GuiApp::service_pipe`](crate::app::GuiApp) starts as this
/// and is a field rather than a constant here so that a test can point a window
/// at a name nothing is listening on. A test that asked [`PIPE_NAME`] would be a
/// test whose result depends on whether the machine running it has the product
/// installed — passing on one machine and driving the real service's vault on
/// another.
pub const DEFAULT_PIPE: &str = PIPE_NAME;

/// Put one request on `pipe` and wait for its reply.
///
/// One request per connection, and the connection is closed when this returns.
/// That is the shape `wenle service status` uses and it is the right one here
/// for a reason of its own: the control pipe serves one client at a time, so a
/// window that held a connection open would be the reason a console command
/// timed out.
pub fn ask(pipe: &str, request: Request) -> Result<Reply, Unreachable> {
    let connection = PipeConnection::connect_to(pipe).map_err(|error| {
        // The one error that is not a failure of the exchange: nothing was
        // listening. `connect_to` waits for the pipe first, so a service that
        // is starting up reports the same thing as one that is not installed —
        // which is honest, because from here the two look identical.
        log::debug!("the service is not listening on {pipe}: {error}");
        Unreachable::NoService(pipe.to_owned())
    })?;
    let mut client = Client::new(connection);
    let id = client
        .send(request)
        .map_err(|error| Unreachable::Transport(error.to_string()))?;
    let deadline = Instant::now() + REPLY_TIMEOUT;
    loop {
        let incoming = client
            .recv()
            .map_err(|error| Unreachable::Transport(error.to_string()))?;
        for item in incoming {
            match item {
                Incoming::Reply { id: got, reply } if got == id => return Ok(reply),
                // An answer to a question this connection did not ask, which
                // cannot happen on a fresh connection, and an event, which is
                // this service talking to whoever else is listening. Both are
                // dropped rather than treated as the answer: a reply matched by
                // position rather than by identifier is the bug the session's
                // correlation rules exist to prevent.
                _ => {}
            }
        }
        if Instant::now() >= deadline {
            return Err(Unreachable::Silent);
        }
        std::thread::sleep(POLL);
    }
}

/// Put a quarantined file back where it came from.
pub fn restore(pipe: &str, id: QuarantineId) -> Result<QuarantineChange, Unreachable> {
    quarantine_change(pipe, Request::QuarantineRestore { id })
}

/// Destroy a quarantined file's bytes, keeping the record.
pub fn delete(pipe: &str, id: QuarantineId) -> Result<QuarantineChange, Unreachable> {
    quarantine_change(pipe, Request::QuarantineDelete { id })
}

/// Put a quarantined file back and stop the product taking it again.
pub fn allow(pipe: &str, id: QuarantineId, permanent: bool) -> Result<QuarantineChange, Unreachable> {
    quarantine_change(pipe, Request::QuarantineAllow { id, permanent })
}

/// The three requests above, and the check that the answer is the one they
/// asked for.
///
/// The check is not ceremony: the protocol correlates replies by identifier,
/// and a service that answered a restore with a scan listing would be a
/// version mismatch the wire's own version field is supposed to catch. Saying
/// so here keeps the mismatch from arriving as a silently ignored outcome.
fn quarantine_change(pipe: &str, request: Request) -> Result<QuarantineChange, Unreachable> {
    match ask(pipe, request)? {
        Reply::QuarantineChange(change) => Ok(change),
        // The one reply that can answer any request, and the one this window has
        // to pass on rather than paraphrase: the service is telling a user that
        // *their account* may not do this, and the sentence says which account
        // it is and what would work. Reaching this arm is not a bug — unlike the
        // arm below — so it is not reported as one.
        Reply::Refused { reason } => Err(Unreachable::Refused(reason)),
        other => Err(Unreachable::Transport(format!(
            "the service answered with a {} reply",
            other.kind().as_str()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wording rule the rest of the window follows: a sentence about the
    /// machine, not about the program, and one that names what is missing.
    #[test]
    fn an_unreachable_reason_reads_as_a_statement_about_the_machine() {
        let named = Unreachable::NoService(DEFAULT_PIPE.to_owned()).describe();
        assert!(named.contains(PIPE_NAME), "{named}");
        assert!(
            !named.contains("error") && !named.contains("failed"),
            "a user is told what is not there, not that something failed: {named}"
        );
        assert!(!Unreachable::Silent.describe().is_empty());
        let transport = Unreachable::Transport("the pipe was closed".to_string());
        assert!(transport.describe().contains("the pipe was closed"));
    }

    /// A refusal is the service's own sentence, shown as it was sent.
    ///
    /// The one outcome here in which the service is working correctly. A window
    /// that wrapped it — "the service could not be reached: S-1-5-… is in
    /// session 2" — would contradict itself and send a user to look for a
    /// service that is running perfectly, and one that dropped the sentence
    /// would leave a *Put back* button that does nothing and says nothing.
    #[test]
    fn a_refusal_is_shown_as_the_sentence_the_service_sent() {
        let reason = "S-1-5-21-1-2-3-1002 is in session 2, and the account signed in at this \
                      machine's console is in session 1"
            .to_string();
        let refused = Unreachable::Refused(reason.clone());
        assert_eq!(refused.describe(), reason);
        assert!(
            !refused.describe().contains("could not be reached"),
            "a refusal is not a service that has gone: {}",
            refused.describe()
        );
    }

    /// The name in the message is the pipe that was asked, not the product's.
    #[test]
    fn a_missing_service_names_the_pipe_that_was_actually_asked() {
        let elsewhere = av_service::pipe::unique_name("gui-named-elsewhere");
        let Err(Unreachable::NoService(named)) = ask(&elsewhere, Request::Status) else {
            panic!("nothing is listening on {elsewhere}");
        };
        assert_eq!(named, elsewhere);
    }

    /// With no service running, every entry point reports the same thing rather
    /// than hanging or panicking. This is the state of a machine where the
    /// window was started by hand and the service was never installed, which is
    /// how the window is developed.
    #[test]
    fn asking_with_no_service_answers_instead_of_waiting() {
        // The name is unique per process and per call, so nothing can be
        // listening on it — see `av_service::pipe::unique_name`, which is the
        // same trick the service's own tests use to get a pipe of their own.
        let name = av_service::pipe::unique_name("gui-service-test");
        let started = Instant::now();
        let outcome = ask(&name, Request::Status);
        assert!(
            matches!(outcome, Err(Unreachable::NoService(_))),
            "{outcome:?}"
        );
        assert!(
            started.elapsed() < REPLY_TIMEOUT,
            "a missing service is answered by the connect, not by the timeout"
        );
    }
}
