//! The control loop: one client, one pipe, one thread of decisions.
//!
//! # Why this is a loop and not a thread per client
//!
//! [`crate::host::Host`] owns the vault, and `av_quarantine::QuarantineVault`
//! rewrites its whole index on every change. Two threads answering two clients
//! would be two writers, and the second write wins — including the write that
//! removes the first client's entry from the list while leaving its blob on
//! disk. The same argument covers the scan: one at a time, by construction.
//!
//! # Why the loop polls rather than blocks
//!
//! The transport was built for this: [`av_ipc::Connection::read_chunk`]
//! asks `PeekNamedPipe` whether anything is there and returns "nothing" rather
//! than blocking, so [`av_ipc::Server::recv`] is a question and not a wait.
//! That matters because the same thread has to keep the scan pump and the
//! watcher's event channel moving while nobody is typing: a scan started by a
//! client that has since closed its window still has to finish, be summarised,
//! and — if the configuration says so — put its findings in the vault.
//!
//! So each pass drains the machine, then takes whatever requests have arrived,
//! and sleeps [`crate::pipe::POLL_INTERVAL`] only when there were none. The
//! sleep is what stops a healthy service from burning a core while it waits.
//!
//! # What happens to events nobody is there to hear
//!
//! They are dropped. The protocol has no replay and this deliberately does not
//! invent one: a service that replayed the last few events to a client on
//! connect would be claiming that client had seen something it had not, and a
//! notification that is redrawn three minutes late is worse than one that was
//! never drawn. A client that connects asks [`av_ipc::Request::Status`] and is
//! told the truth about now, which is what it actually needs.
//!
//! What is *not* lost when a client goes away is anything that matters: the
//! vault write happens in [`crate::host::Host::drain`] on this thread and does
//! not depend on a client being attached, and a scan's findings are all
//! repeated in the [`av_ipc::ScanSummary`] that its `ScanFinished` carries.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use av_ipc::{Event, IpcError, Reply, Request, Server, PIPE_NAME};

use crate::error::ServiceError;
use crate::host::Host;
use crate::pipe::{PipeConnection, PipeListener, POLL_INTERVAL};

/// How long to wait for a client before looking at the stop flag again.
///
/// The number is a compromise the service cannot avoid: `ConnectNamedPipe` has
/// no timeout, so waiting for a client means either blocking forever — and
/// never noticing a stop — or waking up periodically to check. A tenth of a
/// second makes a stop take at most that long to be noticed and costs an idle
/// service ten wake-ups a second.
pub const ACCEPT_POLL: Duration = Duration::from_millis(100);

/// How many times in a row a failed connect is retried before giving up.
///
/// `ConnectNamedPipe` failing is usually transient — a client that vanished
/// between `WaitNamedPipeW` and the call — and retrying is right. Failing
/// forever in a tight loop is not: it would spin a core and fill the event log
/// while the service appeared to be running and served nobody. Bounded, so the
/// service fails loudly instead.
pub const MAX_CONNECT_FAILURES: u32 = 16;

/// Whether a failed connect should be retried.
pub const fn should_retry_connect(consecutive_failures: u32) -> bool {
    consecutive_failures < MAX_CONNECT_FAILURES
}

/// Whether an error means the client is gone rather than that it misbehaved.
///
/// The distinction is only about how loudly to complain. Every error ends the
/// client in `serve_client` — a service that kept reading a stream it could
/// not decode would be reading whatever the next frame's bytes happen to look
/// like — but "the user closed the window" is not worth an error line and
/// "this front end sent a frame with a bad magic" is.
pub fn is_peer_gone(error: &IpcError) -> bool {
    matches!(error, IpcError::PeerClosed)
}

/// Serve the control pipe until `stop` is set, then give the host back.
///
/// The name is [`av_ipc::PIPE_NAME`], which is the one name this product has;
/// see [`serve_on`] for the reason it is a parameter underneath.
///
/// One client at a time: [`av_ipc::Server`] speaks for one connection, and a
/// second client waits in `ConnectNamedPipe` until the first is done. That is
/// the correct shape for a control plane whose every mutation is guarded by a
/// single writer, and it is stated in the protocol documentation rather than
/// discovered by a front end that connects second and appears to hang.
///
/// The host comes back rather than being shut down here, so that the caller
/// owns the last two status transitions: a service that has finished serving
/// reports `STOP_PENDING`, shuts the machine down, and reports `STOPPED`. Those
/// three steps in that order are what [`crate::scm`] exists to get right, and
/// doing the middle one in here would leave the first one with nowhere to go.
/// A caller that drops the host instead of shutting it down is still safe —
/// [`Host`]'s own `Drop` does it — but it is the caller's job to say so first.
pub fn serve(mut host: Host, stop: &AtomicBool) -> Result<Host, ServiceError> {
    // The one line that arms real-time protection, and it is here rather than in
    // `Host::open` or `serve_on` for a reason each.
    //
    // `Host::open` cannot hold it. That function is also what the test in
    // `tests/control_pipe.rs` builds, and the default watch plan is this
    // machine's own Desktop, Downloads, Documents, temporary directory and
    // removable drives — so arming there would have `cargo test` watching a
    // developer's home directory. The split is the one `Host::open` already
    // makes for the driver port against `Host::open_with`.
    //
    // `serve_on` must not hold it, for exactly the same reason: it is what that
    // test calls, and it is a parameterised copy of this function so that a test
    // can use a pipe of its own. `serve` is the product's entry to both — the
    // service through `crate::scm` and `--console` through `crate::main` — and
    // it is the only caller that passes `PIPE_NAME`.
    //
    // This runs a moment before `serve_on` creates the pipe, which `Host::open`'s
    // documentation used to give as the reason not to start it. That reasoning
    // was wrong and the order is deliberate: the vault write is
    // `Host::drain_realtime`'s and not a client's, so a file detected with nobody
    // attached is still quarantined, and the events queue in an unbounded channel
    // until the loop's first pass. What a client can miss is the notification,
    // never the protection.
    //
    // `start_realtime` honours the configuration rather than overriding it, and
    // leaves the host's watcher absent when the plan has no roots — so a machine
    // whose configuration turns realtime off, or off for the kernel filter to
    // take over, reaches the loop below in the state its user asked for, with the
    // reason reported rather than implied.
    host.start_realtime();
    serve_on(host, stop, PIPE_NAME)
}

/// [`serve`], on a pipe this caller names.
///
/// The name is a parameter so that the end-to-end test can run the whole
/// machine — host, control loop, protocol, and a real named pipe — without
/// taking [`av_ipc::PIPE_NAME`]. It cannot take that name: a test listening on
/// the product's own pipe either collides with an installed service, which is
/// two answers to one question, or it collides with a second run of itself,
/// which is the same failure with nobody watching. Neither presents as a
/// failure, because `CreateNamedPipeW` on an existing name succeeds and
/// `PIPE_UNLIMITED_INSTANCES` makes a second listener look healthy.
///
/// Nothing else may pass a name: [`serve`] is the only caller, and it passes
/// the protocol's constant.
///
/// This does **not** arm the filesystem watcher; [`serve`] does, for the reason
/// its own documentation gives. The driver port is not started here either, and
/// for the same class of reason one level up: that is [`Host::open`]'s job and
/// deliberately not [`Host::open_with`]'s, which is what a test builds. A test
/// that reached this function with `config::load`'s defaults has
/// `realtime.enabled` true and a watch plan built from the account's own Desktop,
/// Downloads and Documents, so arming a watcher here would have `cargo test`
/// reading a developer's home directory — and the test would pass either way.
pub fn serve_on(host: Host, stop: &AtomicBool, name: &str) -> Result<Host, ServiceError> {
    let mut host = host;
    host.set_state(av_ipc::ServiceState::Running);
    let mut listener = PipeListener::create(name)?;
    log::info!("listening on {}", listener.name());

    let mut failures = 0u32;
    while !stop.load(Ordering::SeqCst) {
        // The machine keeps moving with nobody attached. See this module's
        // documentation for what that does and does not preserve.
        drop(host.drain());
        if !listener.wait_for_client(ACCEPT_POLL) {
            // Nobody is attached — and that answer covers two states, only one
            // of which can be waited on. An instance a client reached and left
            // before it was accepted accepts no one ever again, and polling
            // cannot tell it from a fresh one. Replacing the instance is what
            // turns "nobody yet" into a state the next client can actually
            // arrive in; see `PipeListener::refresh`, which is also where the
            // measurement that ruled out repairing it in place is recorded.
            // Without this the loop waits for ever on a service the SCM is told
            // is `RUNNING`.
            listener.refresh()?;
            continue;
        }
        match listener.connect() {
            Ok(connection) => {
                failures = 0;
                serve_client(&mut host, connection, stop);
            }
            Err(error) => {
                failures += 1;
                if !should_retry_connect(failures) {
                    return Err(error);
                }
                log::warn!("a client could not be connected ({failures} in a row): {error}");
                // A connect that failed can be the abandoned state itself —
                // `ERROR_NO_DATA` is precisely "the client arrived and left
                // before `ConnectNamedPipe` was called" — and the instance is
                // then one nothing will ever accept. Replacing it makes the
                // next pass a retry rather than the second of sixteen
                // identical failures.
                listener.refresh()?;
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }

    log::info!("the control pipe is closed");
    Ok(host)
}

/// Serve one client until it goes away, the service stops, or it misbehaves.
///
/// Never returns an error: everything that can go wrong here is about *this*
/// client, and a bug in a front end must not stop the antivirus. The caller
/// goes back to waiting for the next one.
fn serve_client(host: &mut Host, connection: PipeConnection, stop: &AtomicBool) {
    let peer = connection.name().to_string();
    log::info!("a client connected on {peer}");
    let mut server = Server::new(connection);
    // What this client may do, filled in at the first request rather than here.
    // `None` until then, and re-asked only while the answer is `Unknown`; see
    // [`identify_at_the_first_request`] for why the question cannot be put to
    // the operating system any earlier than that.
    let mut identity: Option<crate::peer::Peer> = None;

    loop {
        // The machine first, so a scan started ten passes ago keeps reporting
        // while the client sits idle.
        let events = host.drain();
        for event in &events {
            if !publish(&mut server, event) {
                log::info!("the client on {peer} went away");
                return;
            }
        }

        if stop.load(Ordering::SeqCst) {
            // Told, not just disconnected. A client that sees the socket drop
            // cannot tell "the service stopped" from "the service crashed", and
            // that is exactly the difference a user interface has to show.
            host.set_state(av_ipc::ServiceState::Stopping);
            publish(&mut server, &Event::StatusChanged(host.status()));
            log::info!("stopping; the client on {peer} has been told");
            return;
        }

        let requests = match server.recv() {
            Ok(requests) => requests,
            Err(error) if is_peer_gone(&error) => {
                log::info!("the client on {peer} disconnected");
                return;
            }
            Err(error) => {
                // The stream cannot be trusted from here: a frame that would not
                // decode leaves the decoder at an unknown offset.
                log::warn!("dropping the client on {peer}: {error}");
                return;
            }
        };

        if requests.is_empty() {
            // `recv` is a question, not a wait — see this module's
            // documentation — so an idle pass has to sleep or it spins.
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }

        // The client has written something and this thread has read it, which is
        // the earliest moment its account can be established at all.
        identify_at_the_first_request(&mut identity, server.connection(), &peer);
        let identity = identity.as_ref().expect("set immediately above");

        for (id, request) in requests {
            log::debug!("{peer} asked for {}", describe(&request));
            // A request that changes the product's state from an account that
            // may not change it is answered with a refusal and *not* passed to
            // the host at all — the ordering matters more than the answer does.
            // Handing it over and declining to send the result would have
            // already restored the file, written the setting and switched
            // protection off, which is the whole of what this is for.
            let (reply, events) = match refusal(&request, identity) {
                Some(refusal) => {
                    log::warn!(
                        "refusing {peer}'s {}: {}",
                        describe(&request),
                        identity.reason()
                    );
                    (refusal, Vec::new())
                }
                None => host.handle(&request),
            };
            if let Err(error) = server.reply(id, reply) {
                if !is_peer_gone(&error) {
                    log::warn!("a reply to {peer} could not be sent: {error}");
                }
                return;
            }
            // The events a request produced go out after its reply, so a client
            // that is correlating sees the answer before the consequences of it.
            for event in events {
                if !publish(&mut server, &event) {
                    return;
                }
            }
        }
    }
}

/// Establish what the client may do, the first time it has said anything.
///
/// # Why this cannot be decided when the client connects
///
/// Because the operating system will not say who the client is until then.
/// `ImpersonateNamedPipeClient` fails with `ERROR_CANNOT_IMPERSONATE` —
/// *"Unable to impersonate using a named pipe until data has been read from that
/// pipe"* — until at least one read has completed on the connection. That is a
/// rule about when the kernel captures the client's token, not about permission,
/// and there is no earlier call that would answer the question. The first
/// version of this asked at connect time, and every client came back
/// unidentified: measured on this machine, not read out of a document.
///
/// So the question is put on the first batch of requests to arrive, which is the
/// earliest moment an answer exists. The cost is that a connection which sends
/// nothing is never identified — and never needs to be, because a client that
/// sends nothing asks for nothing.
///
/// # Why `Unknown` is not remembered
///
/// Every other answer is: an identity cannot change while a connection stays
/// open, and re-asking per request would impersonate the client on every
/// keystroke a front end sends. `Unknown` is the exception because the one
/// failure this code knows to be a matter of timing is the one above, and a
/// connection refused for the rest of its life over a race would be a bug that
/// looks exactly like a permissions problem. Re-asking costs one impersonation
/// per batch, and only while the answer is still "could not tell".
fn identify_at_the_first_request(
    identity: &mut Option<crate::peer::Peer>,
    connection: &PipeConnection,
    peer: &str,
) {
    if identity
        .as_ref()
        .is_some_and(|known| !matches!(known, crate::peer::Peer::Unknown { .. }))
    {
        return;
    }
    let decided = crate::peer::identify_connection(connection);
    if identity.is_none() {
        log::info!("the client on {peer} has asked for something: {}", decided.describe());
    } else if !matches!(decided, crate::peer::Peer::Unknown { .. }) {
        log::info!("the client on {peer} can be identified after all: {}", decided.describe());
    }
    *identity = Some(decided);
}

/// Send one event. `false` means the peer has gone.
fn publish(server: &mut Server<PipeConnection>, event: &Event) -> bool {
    match server.publish(event) {
        Ok(()) => true,
        Err(error) => {
            if !is_peer_gone(&error) {
                log::warn!("an event could not be sent: {error}");
            }
            false
        }
    }
}

/// The reply to send instead of acting, or `None` to do what was asked.
///
/// A function rather than a condition inside the request loop, so that the rule
/// can be tested as a table over the whole vocabulary — every request against
/// both answers to "may this client change things" — instead of only being
/// reachable through a live service that connects as whoever is running the
/// tests.
///
/// `None` is the answer that does what was asked, and it is deliberately the
/// awkward one to write: a caller has to say `None => host.handle(…)` to reach
/// the effect, so a request cannot be acted on by forgetting to consult this.
fn refusal(request: &Request, peer: &crate::peer::Peer) -> Option<Reply> {
    if changes_state(request) && !peer.may_change() {
        Some(Reply::Refused {
            reason: peer.reason().to_string(),
        })
    } else {
        None
    }
}

/// Whether a request can change the product's state, and so needs an account
/// that may change it.
///
/// # What is on the list, and what is deliberately not
///
/// The five requests that leave the machine different afterwards: a file out of
/// the vault and back on disk, a file destroyed, an exclusion written, protection
/// switched on or off, a setting stored. Each is irreversible or close to it —
/// `QuarantineDelete` certainly is — and each is something the person at the
/// keyboard asked for by name.
///
/// **Scanning is not on the list**, and that is a decision rather than an
/// oversight. [`Request::ScanPath`] does not change what this product *does*; it
/// asks a question, and the answer is a report. It can put a file in the vault,
/// but that is the configuration's standing instruction to the scanner rather
/// than an instruction from the client, and it happens the same way when the
/// watcher finds the same file with no client anywhere near. Treating a scan as a
/// privileged request would mean a second signed-in user could not check their
/// own downloads — a real loss for nothing gained, since the second user cannot
/// release anything afterwards.
///
/// [`Request::ScanProcess`] is here to be counted: it reads another process's
/// memory, which is a serious thing to let anyone on the machine do, and it is
/// *not* refused. The account that may not release a file may still ask for a
/// memory scan. That is defensible — the answer is a report of what is in a
/// process, the scanner runs as the service rather than as the asker, and the
/// person at the console has the same reach and the same audit line — but it is
/// a choice, so it is written here rather than left to be inferred from the
/// absence of a name.
///
/// The match is exhaustive on purpose: a request added to the vocabulary without
/// a decision here is a compile error rather than a request that quietly lands
/// on one side of the rule. That is the same reason [`describe`] is a match.
fn changes_state(request: &Request) -> bool {
    match request {
        // Leaves the machine different.
        Request::QuarantineRestore { .. }
        | Request::QuarantineDelete { .. }
        | Request::QuarantineAllow { .. }
        | Request::ConfigSet { .. }
        | Request::RealtimeSet { .. } => true,
        // Asks a question.
        Request::Status
        | Request::ScanPath { .. }
        | Request::CancelScan { .. }
        | Request::ScanProcess { .. }
        | Request::ScanBuffer { .. }
        | Request::QuarantineList { .. }
        | Request::ConfigGet => false,
    }
}

/// The request's name, for a log line.
///
/// [`av_ipc::RequestKind`] has no `Display`, and giving it one in `av-ipc` would
/// put a log's wording in the protocol crate. Written as an exhaustive match
/// over the request instead of over its kind, so a new request is a compile
/// error here as well as in [`Host::handle`](crate::host::Host::handle).
fn describe(request: &Request) -> &'static str {
    match request {
        Request::Status => "Status",
        Request::ScanPath { .. } => "ScanPath",
        Request::CancelScan { .. } => "CancelScan",
        Request::ScanProcess { .. } => "ScanProcess",
        Request::ScanBuffer { .. } => "ScanBuffer",
        Request::QuarantineList { .. } => "QuarantineList",
        Request::QuarantineRestore { .. } => "QuarantineRestore",
        Request::QuarantineDelete { .. } => "QuarantineDelete",
        Request::QuarantineAllow { .. } => "QuarantineAllow",
        Request::ConfigGet => "ConfigGet",
        Request::ConfigSet { .. } => "ConfigSet",
        Request::RealtimeSet { .. } => "RealtimeSet",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disconnected_peer_is_not_a_protocol_violation() {
        // The two are handled the same way — the client goes — but only one of
        // them is worth an error line, and telling them apart is this
        // function's whole job.
        assert!(is_peer_gone(&IpcError::PeerClosed));
        assert!(!is_peer_gone(&IpcError::BadMagic));
        assert!(!is_peer_gone(&IpcError::Transport("the pipe broke".into())));
        assert!(!is_peer_gone(&IpcError::RequestIdNotIncreasing {
            id: av_ipc::RequestId::new(1),
            last: av_ipc::RequestId::new(9),
        }));
    }

    #[test]
    fn connect_retries_are_bounded() {
        // The failure this prevents: a service that appears to be running,
        // serves nobody, spins a core and logs forever.
        assert!(should_retry_connect(0));
        assert!(should_retry_connect(MAX_CONNECT_FAILURES - 1));
        assert!(!should_retry_connect(MAX_CONNECT_FAILURES));
        assert!(!should_retry_connect(u32::MAX));
    }

    #[test]
    fn the_poll_interval_is_short_enough_to_notice_a_stop() {
        // A stop that took a second to notice would hold the SCM's
        // `STOP_PENDING` for a second, and the SCM kills a service that takes
        // too long to answer. The assertion is a bound and not a value, so the
        // number can be tuned without rewriting the test.
        assert!(ACCEPT_POLL <= Duration::from_millis(500));
        assert!(POLL_INTERVAL <= ACCEPT_POLL);
    }

    #[test]
    fn every_request_has_a_name_in_the_log() {
        // Exhaustive, so a request added to the protocol is a compile error
        // here rather than an anonymous line in the log.
        let requests = every_request();
        for request in &requests {
            let name = describe(request);
            assert!(!name.is_empty());
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric()),
                "{name} is not a request name"
            );
        }
        // And the list covers every kind there is, so this test cannot pass by
        // describing a subset. The count is the vocabulary's size today rather
        // than a promise: it is here so that adding a variant and forgetting the
        // list is a failure in one place instead of a quiet gap in two.
        let described: Vec<&str> = requests.iter().map(describe).collect();
        assert_eq!(described.len(), 12);
        assert!(described.contains(&"Status"));
        assert!(described.contains(&"RealtimeSet"));
        // The list itself is what claims to be complete, and the only other
        // place a request can be added is `Request` in `av-ipc`, which this
        // crate cannot see the end of. What makes the claim hold is that
        // `refusal`'s table below consults this same list against a hand-written
        // pair of sides: a request added to `Request` and left out of here is a
        // request that no test in this file refuses or allows, which is exactly
        // the state the pair of sides exists to make impossible to reach
        // quietly.
    }

    /// Every request there is, for the two tables below.
    ///
    /// The same list `every_request_has_a_name_in_the_log` uses. Kept as one
    /// function so a request added to the protocol has to be added once and is
    /// then covered by both.
    fn every_request() -> Vec<Request> {
        vec![
            Request::Status,
            Request::ScanPath {
                path: std::path::PathBuf::from("C:\\"),
                options: av_core::scan::ScanOptions::default(),
            },
            Request::CancelScan {
                id: av_ipc::ScanId::new(1),
            },
            Request::ScanProcess { pid: 4 },
            Request::ScanBuffer {
                name: "a script".to_string(),
                data: vec![1, 2, 3],
            },
            Request::QuarantineList { limit: None },
            Request::QuarantineRestore {
                id: av_quarantine::QuarantineId::new(),
            },
            Request::QuarantineDelete {
                id: av_quarantine::QuarantineId::new(),
            },
            Request::QuarantineAllow {
                id: av_quarantine::QuarantineId::new(),
                permanent: false,
            },
            Request::ConfigGet,
            Request::ConfigSet {
                config: Box::new(av_core::config::AvConfig::default()),
            },
            Request::RealtimeSet { enabled: true },
        ]
    }

    #[test]
    fn a_client_that_may_not_change_things_is_refused_exactly_where_it_changes_them() {
        // The whole rule, as a table over the whole vocabulary: every request,
        // against the two possible answers to "may this client change things".
        // Written as an explicit list of what is refused rather than as a second
        // copy of `changes_state`'s match, because a test that recomputed the
        // same expression would pass whatever the expression said.
        let refused = [
            "QuarantineRestore",
            "QuarantineDelete",
            "QuarantineAllow",
            "ConfigSet",
            "RealtimeSet",
        ];
        let allowed = [
            "Status",
            "ScanPath",
            "CancelScan",
            "ScanProcess",
            "ScanBuffer",
            "QuarantineList",
            "ConfigGet",
        ];

        let may_not_change = crate::peer::Peer::ReadOnly {
            reason: "S-1-5-21-1-2-3-1002 is not the account at this machine's console".to_string(),
        };
        for request in every_request() {
            let name = describe(&request);
            let answer = refusal(&request, &may_not_change);
            if refused.contains(&name) {
                match answer {
                    Some(Reply::Refused { reason }) => assert!(
                        reason.contains("S-1-5-21-1-2-3-1002"),
                        "the refusal has to say who was refused: {reason}"
                    ),
                    other => panic!("{name} must be refused for a read-only client, got {other:?}"),
                }
            } else {
                assert!(
                    allowed.contains(&name),
                    "{name} is in neither list: a request added to the protocol has to be put on \
                     one side of this rule deliberately"
                );
                assert!(
                    answer.is_none(),
                    "{name} changes nothing and must not be refused, got {answer:?}"
                );
            }
        }

        // And the same requests from a client that may change things are all
        // handed over. Without this half, a `refusal` that refused everything
        // would pass the loop above.
        let may_change = crate::peer::Peer::MayChange {
            reason: "the account at this machine's console".to_string(),
        };
        for request in every_request() {
            assert!(
                refusal(&request, &may_change).is_none(),
                "{} was refused a client that may change things",
                describe(&request)
            );
        }

        // An identity that could not be read is not an identity that was
        // allowed: same answer as the read-only client, and the reason differs
        // so a support log says which happened.
        let unknown = crate::peer::Peer::Unknown {
            reason: "the client could not be impersonated".to_string(),
        };
        for request in every_request() {
            let refused_by_name = refused.contains(&describe(&request));
            assert_eq!(
                refusal(&request, &unknown).is_some(),
                refused_by_name,
                "{} answered differently for an unknown identity",
                describe(&request)
            );
        }
    }

    /// The wiring, which no test in this file can reach by calling it.
    ///
    /// `serve` is the only function that arms real-time protection, and it is
    /// the one function here that cannot be called from a test: it names
    /// `PIPE_NAME`, the product's own pipe, and a test listening there either
    /// collides with an installed service — two answers to one question — or
    /// with a second run of itself, which is the same collision with nobody
    /// watching. That is why `serve_on` exists and why this test exists.
    ///
    /// So the question is asked of the source, and it is deliberately the
    /// smallest question that catches the defect this was written for: a
    /// watcher that was wired into no entry point at all, so that a default
    /// install reported `watching: false` with the reason "the filesystem
    /// watcher has not been started" for the life of the service. `av-gui`'s
    /// `glyphs` module asks its own unanswerable question the same way.
    ///
    /// What it cannot catch: a call placed correctly that `Host::start_realtime`
    /// then ignores, which the tests in `host.rs` cover; and a call added to
    /// `serve_on` as well, which the second assertion catches only while the
    /// first copy is the earlier one — so the order of the two functions in
    /// this file is part of what this test is asserting.
    #[test]
    fn the_product_path_arms_the_watcher_and_the_test_path_does_not() {
        const ARM: &str = "host.start_realtime();";
        let source = include_str!("control.rs");
        // The search stops at the test module, because this test's own fixture
        // below contains the string it is looking for — and a search that could
        // match its own fixture would report success on a build where the call
        // had been deleted, which is the one failure it exists to catch.
        let code = source
            .split("\nmod tests")
            .next()
            .expect("the split always yields at least the whole file");
        let product = code
            .find("pub fn serve(")
            .expect("`serve` must exist: it is the product's entry point");
        let test_path = code
            .find("pub fn serve_on(")
            .expect("`serve_on` must exist: it is what the pipe test calls");
        let armed = code.find(ARM).unwrap_or_else(|| {
            panic!(
                "nothing in this file's product code calls `{ARM}`. Real-time protection is armed \
                 in exactly one place, and without it a default installation watches nothing — \
                 see this test's doc comment"
            )
        });
        assert!(
            product < armed,
            "`{ARM}` must be inside `serve`, which is the path both real entry points take"
        );
        assert!(
            armed < test_path,
            "`{ARM}` must not be inside `serve_on`: that is what the end-to-end test calls, and \
             the default watch plan is this machine's own Desktop, Downloads and Documents"
        );
    }
}
