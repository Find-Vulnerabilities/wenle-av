//! The user-mode half of the driver's decision port.
//!
//! # The failure this module ends
//!
//! The driver creates a filter communication port, registers its callbacks, and
//! asks the service for a verdict on every program that is about to start. If
//! nothing in user mode connects to that port, every one of those questions is
//! answered by the driver itself with "there is nobody to ask", and the answer
//! it gives is yes. The product then runs with the filter attached and blocking
//! nothing: no error, no log line, no symptom at all except a machine that is
//! not protected while every status report says the driver is loaded.
//! `av_driver_proto::port`'s documentation is where that failure is spelled out
//! from the other end. This module is the client that ends it.
//!
//! # Never fail closed
//!
//! Every path out of `Dispatcher::decide` answers [`Decision::Allow`]: a file
//! that cannot be read, a path that cannot be decoded, a message that cannot be
//! parsed, an engine with no rules. That is not laziness: it is the same choice
//! the driver makes for itself when the service does not answer in time, since
//! `DecisionPolicy::DEFAULT.on_timeout` is `Allow`. The asymmetry matters.
//! A file that should have been stopped and was not is a detection that arrives
//! late, from the next execution or from an ordinary scan, and the machine is
//! still usable in the meantime. A file that *cannot be opened* because the
//! component that was supposed to check it is not answering is a machine that has
//! stopped, and a user who cannot open their own documents turns the protection
//! off altogether, which protects nothing. The two failures are not the same
//! size, so they do not get the same answer.
//!
//! The same reasoning is why the client is *started* rather than offered. A
//! feature behind an opt-in is a feature that is off on every machine whose
//! owner never found the switch, and this is the switch whose being off is
//! invisible. [`crate::host::Host::open`] starts it on every service start.
//!
//! # Two correlations, not one
//!
//! A decision crosses two identity schemes, and confusing them answers nothing
//! while looking like it worked.
//!
//! The product's own is [`DecisionRequestMessage::request_id`], paired with the
//! `path_tag` that pins the path the driver is asking about. The driver discards
//! any reply whose two values do not match the request it is waiting on (that
//! check is in its `ask_service`), so a reply built field by field is a reply
//! that has to get both right. [`DecisionReplyMessage::answering`] is the
//! protocol's constructor for exactly this, and [`reply_for`] uses it for that
//! reason rather than restating the fields.
//!
//! The filter manager's own is the `MessageId` in the port headers. It is a
//! different number with a different owner, `FilterReplyMessage` pairs a reply
//! with the `FilterGetMessage` it answers by it, and (this is the trap)
//! `answering` leaves it at zero because the port's header is not the product's
//! business. A reply whose `MessageId` matches no outstanding message is not
//! delivered: the driver sits in `FltSendMessage` until its timeout, is told
//! nothing, and allows the file, which is indistinguishable from the whole
//! feature being unwired. [`reply_for`] copies it across from the request, and
//! `the_reply_carries_the_filter_managers_own_message_id` is the test that says
//! so.
//!
//! # The thread, and why it never gives up
//!
//! The port is opened at service start and the driver may be loaded long after
//! that, or reloaded after a crash, or installed while the service is running.
//! So the connection is not a step that can fail: it is a loop that keeps
//! trying, with a delay that starts at a tenth of a second, doubles to a
//! ceiling of fifteen seconds, and never stops until the process does. A service
//! that gave up after N attempts would be a service whose real-time protection
//! depends on boot order, and boot order is not something a user can fix.
//!
//! Nothing here is on the startup path: the thread is spawned and the service
//! carries on, because a service that refused to start when the driver was not
//! there would be a service that stops being a scanner too.
//!
//! # What cannot be interrupted, said plainly
//!
//! A stop is noticed between messages, not during one. `FilterGetMessage` is a
//! synchronous wait inside the filter manager and there is nothing in user mode
//! to signal it with, so a thread blocked in a receive stays blocked until the
//! driver sends something or the port goes away. The window is bounded in
//! practice (the driver sends a heartbeat status periodically, and a machine
//! that is opening files sends messages constantly), and it does not hold up a
//! shutdown: [`Client::stop`] asks and returns without joining, so the wait
//! happens on a detached thread while the process is on its way out. The
//! alternative considered was an `OVERLAPPED` receive plus a cancellation
//! event, which `FilterGetMessage`'s own documentation reserves for the system
//! and does not support; the honest answer is that this thread may outlive the
//! shutdown by one message.
//!
//! # What the scan is, and what it is not
//!
//! The decision is `Dispatcher::decide`, and it is an ordinary
//! [`av_scan::ScanEngine`] scan of the one path with [`ScanOptions::realtime`]:
//! not recursive, no heuristics, no archives, and a per-file budget of five
//! seconds plus a second per megabyte. It is deliberately *not*
//! [`crate::engine::options_from`] of the scanning configuration, which is
//! recursive and opens archives and works to a thirty-second budget: those are
//! the right options for a scan a user asked for and the wrong ones for a
//! question the driver is holding an image load open to ask. The reduction is
//! the same profile [`av_realtime`] uses for the watcher, and it is reused
//! rather than re-spelled here.
//!
//! **That budget is not what bounds the wait.** It is a label the engine puts
//! on a scan it has already finished, not a stop condition, so a file of a
//! megabyte or more may be scanned for longer than the driver waits. This
//! paragraph used to say the budget *was* the same five seconds the driver
//! waits, which was false in the code and is the defect `ScanPool` corrects.
//! What bounds the wait is `DECISION_DEADLINE`: the port thread waits that
//! long for a scan, answers the driver itself if the scan has not come back, and
//! the scan goes on to be *reported* rather than answered late.
//!
//! Two things this thread does *not* do, both on purpose:
//!
//! * **It does not quarantine.** [`crate::host::Host`] owns the vault, and
//!   `av_quarantine::QuarantineVault` rewrites its whole index on every change,
//!   so a second writer is a writer that discards the first one's entries. The
//!   block is the driver's job and the record of it arrives as an event; taking
//!   the file is the host's job, on the thread that owns it. The conviction that
//!   arrives after the deadline is the same case and goes the same way: this
//!   side publishes a detection and the host decides what to do about it.
//! * **It does not decide the driver's exclusions, and it does consult the
//!   user's.** These are two questions, and this paragraph used to run them
//!   together. The driver applies [`av_driver_proto::exclusions::BUILT_IN`]
//!   before it asks anything, so a path that reaches this module has already
//!   been judged in scope by the layer that owns that table, and nothing here
//!   re-judges it. What the driver cannot own is an exclusion the *user* typed:
//!   that table is `const`, `ExclusionBuffer` has no producer and the driver has
//!   no control device to send one through. So the user's allow set is consulted
//!   here instead, and [`crate::allow`] is where the split is argued. The
//!   disagreement this used to worry about cannot happen in the direction that
//!   matters: an entry here can only let a file run, and a file the driver
//!   refuses is never asked about in the first place.
//!
//! # What is tested, and what is not
//!
//! Everything that decides anything is in [`Received`], [`Dispatcher`] and
//! [`reply_for`], which touch no Windows API and are tested here by feeding them
//! messages: the dispatch, the reply construction, the verdict mapping, the
//! backoff, the deadline, and every fail-open path. What is left in the
//! `#[cfg(windows)]` block is the connect, the receive, the reply call and the
//! close, and those are exercised only by a driver and an installed service.
//! This module does not claim they work; the separation is what makes the claim
//! about the rest worth something.
//!
//! `ScanPool` is tested through the dispatcher that owns it (a scan past the
//! deadline, the conviction that follows one, and the clean file that produces
//! nothing), and one of its paths is not tested at all: the queue that is full
//! enough to refuse a job. Reaching it needs `SCAN_BACKLOG` files waiting
//! behind scans that do not finish, which no fixture in a unit test can
//! produce. It is a log line and a [`Decision::Allow`] on a machine that has
//! already stopped keeping up, and it is named here rather than left for a
//! reader to find.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use av_core::paths::AvPaths;
use av_core::scan::{FileScanReport, ScanOptions};
use av_core::Verdict;
use av_driver_proto::decision::{Decision, DecisionPolicy};
use av_driver_proto::event::SubjectKind;
use av_driver_proto::wire::{
    ConfigMessage, DecisionReplyMessage, DecisionRequestMessage, DriverStatus, EventMessage,
    MessageKind, MessagePrefix, StatusMessage,
};
use av_ipc::{Detection, DetectionAction, DriverEvent, DriverEventAction, DriverSubject, Event};
use av_quarantine::EntrySource;
use av_scan::ScanEngine;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError};

use crate::allow::AllowList;
use crate::driver;

/// The receive buffer: the largest message the protocol defines.
///
/// `FilterGetMessage` reports no length, so the size has to be decided in
/// advance, and it has to be the largest thing the driver can send rather than
/// the commonest. A buffer sized for a decision request — 2104 bytes — would
/// make every [`EventMessage`] fail with `ERROR_INSUFFICIENT_BUFFER` and hand
/// nothing back, so the first heartbeat or blocked-execution the driver reported
/// would end the connection and the driver would go back to blocking nothing.
/// The two assertions below are on this constant, so shrinking it is a compile
/// error rather than a fault that shows up as a quiet machine.
pub const RECEIVE_BYTES: usize = EventMessage::SIZE;

/// The request is the second-largest message, and must still fit.
const _: () = assert!(RECEIVE_BYTES >= DecisionRequestMessage::SIZE);
/// So must the status, for the same reason.
const _: () = assert!(RECEIVE_BYTES >= StatusMessage::SIZE);

/// The delays between connection attempts, in milliseconds.
///
/// Two facts shape this table. The ordinary case is a race and not a fault: the
/// service is started by the SCM and the minifilter is loaded by the filter
/// manager, and whichever finishes second finds the other already there — a
/// first retry after a tenth of a second closes that race inside the same
/// second. The case that actually has to be survived is the driver arriving
/// *later*, either installed while the service runs or reloaded after a crash,
/// and for that the only question is how long the machine goes unprotected. So
/// the schedule climbs to fifteen seconds and stops there: at worst a quarter of
/// a minute before a newly loaded driver is picked up, four attempts a minute in
/// the steady state, and no spin.
pub const RETRY_SCHEDULE_MS: [u64; 8] = [100, 250, 500, 1_000, 2_000, 4_000, 8_000, 15_000];

/// How long to wait before connection attempt `attempt`, counting from zero.
///
/// Saturating at the end of the table rather than growing without bound: what
/// the wait trades against is how long a newly loaded driver goes unnoticed, and
/// past fifteen seconds that trade stops being worth making.
pub fn retry_delay(attempt: u32) -> Duration {
    let last = RETRY_SCHEDULE_MS.len() - 1;
    Duration::from_millis(RETRY_SCHEDULE_MS[(attempt as usize).min(last)])
}

/// How long to wait after a connection that worked and then ended.
///
/// Short, and not [`retry_delay`]: the commonest reason a live connection ends
/// is that the driver was reloaded, and a reload takes a moment rather than a
/// minute. The escalation in the schedule is for the case where nothing has ever
/// connected, where the growing wait is the only thing preventing a spin.
pub const RECONNECT_PAUSE_MS: u64 = 250;

/// How long a sleep may run before the stop flag is looked at again.
///
/// Every wait in this module is taken in chunks of this, which is what bounds
/// how long a stop takes to be noticed. The number is small because the thing it
/// delays is the SCM's `STOP_PENDING`, and the SCM kills a service that takes
/// too long to answer it.
pub const STOP_POLL_MS: u64 = 100;

/// `ERROR_ACCESS_DENIED`, which is what a connect gets when the port exists and
/// this process is not permitted to open it.
const ERROR_ACCESS_DENIED: u32 = 5;

/// `ERROR_INVALID_HANDLE`, which is what an outstanding receive returns when the
/// driver unloads and its port goes with it.
const ERROR_INVALID_HANDLE: u32 = 6;

/// `ERROR_INSUFFICIENT_BUFFER`, which is what a receive returns when the message
/// is larger than the buffer it was given.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// `ERROR_OPERATION_ABORTED`, which is what a blocked receive returns when the
/// port is closed underneath it.
const ERROR_OPERATION_ABORTED: u32 = 995;

/// Sleep for `total`, looking at `stop` every [`STOP_POLL_MS`].
///
/// The chunking is the whole content of this function: a fifteen-second wait
/// taken in one call would make a stop take up to fifteen seconds to be noticed,
/// and the point of the schedule is to be patient without becoming unresponsive.
fn sleep_unless_stopped(total: Duration, stop: &AtomicBool) {
    let chunk = Duration::from_millis(STOP_POLL_MS);
    let mut slept = Duration::ZERO;
    while slept < total {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let this = chunk.min(total - slept);
        std::thread::sleep(this);
        slept += this;
    }
}

/// One message, once the bytes have been read as a structure.
///
/// Reading and acting are separated so that the reading — the only part that
/// touches an untyped buffer — is a function with no engine, no channel and no
/// port behind it, and so that what it refused can be named rather than
/// silently dropped.
pub enum Received {
    /// A verdict is wanted. The driver is inside `FltSendMessage` waiting for
    /// it, against its own timeout.
    DecisionRequest(DecisionRequestMessage),
    /// Something the driver did, to be reported.
    Event(EventMessage),
    /// The driver's own account of itself.
    Status(StatusMessage),
    /// The receive returned success without writing a message.
    ///
    /// Not a driver message and not a refusal: `FilterGetMessage` does this when
    /// more than one thread waits on the same port handle (measured 2026-10-18,
    /// thousands a second) and at the edges of a connection. The buffer is
    /// exactly as this process cleared it, so its prefix is
    /// `MessagePrefix::default` -- kind `KIND_RESERVED` 0, version 0 -- which no
    /// sender ever writes.
    ///
    /// It is a variant rather than a reason string because there is nothing to
    /// decide and nothing to report: a message that was never written must not
    /// reach a decision procedure, and calling it "a message this build cannot
    /// read" sent a reader looking for a protocol bug that does not exist.
    Empty,
    /// Something this build will not read, and why. Nothing is done with it
    /// beyond the log: the one thing a message like this must not do is reach a
    /// decision procedure that would be guessing at the layout of bytes it has
    /// just said it does not understand.
    Unreadable {
        /// One sentence for the log.
        reason: String,
        /// The two versions, when the reason is that they disagree.
        ///
        /// Carried as data and not parsed back out of `reason` because the
        /// caller acts on it: a mismatch is the one refusal that means the
        /// product is running blind, and it is raised to a warning rather than
        /// left at debug. None for every other refusal.
        mismatch: Option<(u32, u32)>,
    },
}

/// Why this is hand-written rather than derived.
///
/// `av_driver_proto::wire`'s structures are bare `repr(C)` aggregates with no
/// `Debug` of their own, and one that printed a message would print its whole
/// `[u16; 1024]` path buffer. What a log line or a failed assertion needs is
/// which message arrived and what it said.
impl core::fmt::Debug for Received {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Received::DecisionRequest(request) => f
                .debug_struct("DecisionRequest")
                .field("request_id", &request.request_id)
                .field("path_units", &request.path_units)
                .finish(),
            Received::Event(event) => f
                .debug_struct("Event")
                .field("sequence", &event.sequence)
                .field("action", &event.action)
                .finish(),
            Received::Status(status) => f
                .debug_struct("Status")
                .field("state", &status.status.state)
                .field("mode", &status.status.mode)
                .finish(),
            Received::Empty => f.write_str("Empty"),
            Received::Unreadable { reason, mismatch } => f
                .debug_struct("Unreadable")
                .field("reason", reason)
                .field("mismatch", mismatch)
                .finish(),
        }
    }
}

/// Read one received buffer as a message.
///
/// This is the only place bytes become a structure, and it is deliberately
/// narrow, because `FilterGetMessage` hands back a buffer and **no length**: the
/// only thing that says how much of the buffer is a message is the kind in its
/// prefix. A build that read the buffer as the structure it happened to be
/// expecting — rather than as the structure the prefix says the sender wrote —
/// would answer a question that was never asked, and the driver would discard
/// the answer as uncorrelated and time out. Refusing is therefore the whole job
/// here, and the caller's answer to a refusal is to drop the message and say so.
///
/// The version check comes *before* anything below the prefix is read, and the
/// order is not stylistic: a body is not self-describing, so a build that
/// decoded first and compared versions afterwards would already have read one
/// build's bytes as another build's. `MessagePrefix::is_readable` is the
/// protocol's own predicate for exactly this, and it is used rather than
/// re-derived so that the two ends cannot disagree about what readable means.
pub fn received(buffer: &[u8]) -> Received {
    let Some(prefix) = read_struct::<MessagePrefix>(buffer) else {
        return Received::Unreadable {
            reason: format!(
                "a {}-byte message, shorter than the protocol's {}-byte prefix",
                buffer.len(),
                MessagePrefix::SIZE
            ),
            mismatch: None,
        };
    };
    // The empty-success case, told apart before anything else:
    // `MessagePrefix::default` is what a buffer nobody wrote to holds, and no
    // sender produces it.
    if prefix.kind == 0 && prefix.version == 0 {
        return Received::Empty;
    }
    if !prefix.is_readable() {
        return Received::Unreadable {
            reason: format!(
                "a message this build cannot read: kind {}, version {} (this build speaks version \
                 {})",
                prefix.kind,
                prefix.version,
                av_driver_proto::PROTOCOL_VERSION
            ),
            // `is_readable` refuses an unknown *kind* as well as a wrong version,
            // so the two are told apart here rather than assumed. A *known* kind
            // that fails the check can only have failed on the version, and that
            // is the silent-blindness case the event thread warns about.
            //
            // The distinction is not academic: the driver's port hands up a
            // zero-filled prefix now and then -- `KIND_RESERVED` 0, version 0,
            // which is exactly `MessagePrefix::default` -- and treating that as
            // a version mismatch made the new warning fire on a healthy pairing
            // the first time it ran (test VM, 2026-10-23 18:24).
            mismatch: if av_driver_proto::wire::MessageKind::is_known(prefix.kind) {
                Some((prefix.version, av_driver_proto::PROTOCOL_VERSION))
            } else {
                None
            },
        };
    }
    // `is_readable` has already established that the kind is one of these, so
    // the `None` arm is unreachable from here. It is written as a match rather
    // than an `unwrap` because this thread must not panic: a panic here would
    // end the client silently, and the driver would go back to blocking nothing
    // with the service still reporting itself as running.
    match MessageKind::from_wire(prefix.kind) {
        Some(MessageKind::DecisionRequest) => match read_struct::<DecisionRequestMessage>(buffer) {
            Some(message) => Received::DecisionRequest(message),
            None => Received::Unreadable {
                reason: "a decision request truncated below its own size".to_string(),
                mismatch: None,
            },
        },
        Some(MessageKind::Event) => match read_struct::<EventMessage>(buffer) {
            Some(message) => Received::Event(message),
            None => Received::Unreadable {
                reason: "an event truncated below its own size".to_string(),
                mismatch: None,
            },
        },
        Some(MessageKind::Status) => match read_struct::<StatusMessage>(buffer) {
            Some(message) => Received::Status(message),
            None => Received::Unreadable {
                reason: "a status message truncated below its own size".to_string(),
                mismatch: None,
            },
        },
        Some(MessageKind::Config) => Received::Unreadable {
            // A configuration travels the other way. The service is the only
            // sender of one — see `configure` above — so a configuration
            // *arriving* here is a driver this build does not understand, or a
            // message that was echoed. It is refused rather than decoded for the
            // same reason every other unreadable message is: nothing good comes
            // of reading bytes whose layout has just been called into question.
            // It gets its own sentence rather than the `None` arm's, because
            // "this build does not define that kind" would be false: it defines
            // it, and it is the kind it sends.
            reason: "a configuration message, which is a kind only this service sends to the \
                     driver; one arriving here means the driver and this build disagree about the \
                     protocol"
                .to_string(),
            mismatch: None,
        },
        None => Received::Unreadable {
            reason: format!("a message kind this build does not define: {}", prefix.kind),
            mismatch: None,
        },
    }
}

/// Read one protocol structure out of a received buffer.
///
/// `None` only when the buffer is shorter than the structure, which is the one
/// thing that can go wrong: every structure in this protocol is a `repr(C)`
/// aggregate of integers and fixed arrays — no enums, no references, no niche —
/// so every bit pattern is a valid value of the type, including the zeroed one.
/// `read_unaligned` is used because a byte slice carries no alignment promise;
/// the buffer this module actually passes is over-aligned for the kernel's
/// probe, and this does not depend on that.
fn read_struct<T: Copy>(buffer: &[u8]) -> Option<T> {
    if buffer.len() < core::mem::size_of::<T>() {
        return None;
    }
    // SAFETY: the length check above guarantees the read stays inside the
    // slice, and any bit pattern is a valid `T` for the reason in the
    // documentation above.
    Some(unsafe { core::ptr::read_unaligned(buffer.as_ptr().cast::<T>()) })
}

/// What the receive loop should do with one message.
pub enum Action {
    /// Answer the driver. The reply is complete — it carries both the filter
    /// manager's message identifier and the product's request identifier — so
    /// the caller passes it straight to `FilterReplyMessage` with its own size
    /// as the length.
    Reply(DecisionReplyMessage),
    /// Answer the driver, and tell the service what the answer was about.
    ///
    /// The driver is waiting inside its own timeout, so the answer cannot be
    /// deferred until the service has finished with the file; but the file has
    /// to be reported, because a conviction nobody is ever told about is
    /// indistinguishable, from the user's side, from one that did not happen.
    ///
    /// **Two answers travel this way, and they are not the same news.** A
    /// [`Decision::Block`] is a refusal: the program did not run. A
    /// [`Decision::Allow`] carrying a detection is a gate that reports and does
    /// not refuse — the program did run, and the file is still worth taking.
    /// The [`Detection`] carries which one it was, through
    /// [`Detection::claims_a_block`], and the loop at the bottom of this module
    /// replies before it reports for the first of those reasons only.
    ///
    /// The detection is built on this side rather than by the service because
    /// the [`FileScanReport`] it is taken from does not outlive this call: its
    /// numbers are the ones the decision was reached on, and re-deriving them
    /// from the path on the far side would be a second answer to a question
    /// that has already been answered.
    ///
    /// [`FileScanReport`]: av_core::scan::FileScanReport
    ReplyAndReport(DecisionReplyMessage, Box<Detection>),
    /// Report something the driver did. The caller wraps this in
    /// [`Event::Driver`] and sends it to the service's event channel.
    Publish(DriverEvent),
    /// Nothing to send. The sentence is what the log says about it, and it is
    /// built where the facts are rather than in the loop.
    Ignored(String),
}

/// [`Action`], for a failed assertion or a log line.
impl core::fmt::Debug for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Action::Reply(reply) => f
                .debug_struct("Reply")
                .field("request_id", &reply.request_id)
                .field("decision", &reply.decision)
                .field("path_tag", &reply.path_tag)
                .field("message_id", &reply.reply.message_id)
                .finish(),
            Action::ReplyAndReport(reply, detection) => f
                .debug_struct("ReplyAndReport")
                .field("request_id", &reply.request_id)
                .field("decision", &reply.decision)
                .field("path_tag", &reply.path_tag)
                .field("message_id", &reply.reply.message_id)
                .field("detection", detection)
                .finish(),
            Action::Publish(event) => f.debug_tuple("Publish").field(event).finish(),
            Action::Ignored(reason) => f.debug_tuple("Ignored").field(reason).finish(),
        }
    }
}

/// The driver's answer for a verdict.
///
/// Not a policy of its own, and deliberately not able to become one:
/// [`Verdict::blocks`] is the product's single predicate for "this is acted on",
/// the same one `av-amsi` answers through and the same one
/// [`crate::host`]'s `should_take` is named for. Only the red band blocks; the
/// yellow band warns and never acts, which is a product rule and not a
/// threshold anybody here gets to tune.
pub const fn verdict_to_decision(verdict: Verdict) -> Decision {
    if verdict.blocks() {
        Decision::Block
    } else {
        Decision::Allow
    }
}

/// Which of the driver's two gates asked about a path.
///
/// The driver sends no field that names its callback. What it does send is
/// [`DecisionRequestMessage::subject`], and the two callers of its `decide` —
/// the only two places a decision request is built — have passed a different
/// kind: `IRP_MJ_CREATE`'s pre-operation passed `SubjectKind::Process` (the
/// operation is the process's, before the image exists), and the
/// acquire-for-section pre-operation passes `SubjectKind::Image`. So the field
/// is a gate name by construction, and the construction is in the driver's
/// source rather than in anything on the wire. That is worth stating in a log
/// rather than relying on: "which gate refused this" is the first question a
/// refusal raises, and the answer decides whether a program was about to run or
/// something was reading the file.
///
/// **No longer a live pair as of 2026-10-15.** `av-driver`'s create
/// pre-operation stopped asking, because [`refusing_gate`] made its answer a
/// constant the driver could not act on, so `SubjectKind::Process` no longer
/// arrives from this build. The arm stays for two reasons: a driver that does
/// send it — an older install, or a future one that asks again — must be
/// answered and logged correctly rather than reported as "an undefined
/// subject"; and the name is the only thing that would let a reader tell the
/// two apart in a log.
///
/// Anything else — a subject this build does not define, or one of the kinds no
/// decision request carries — is reported as itself rather than guessed at.
fn asking_gate(subject: u32) -> &'static str {
    match SubjectKind::from_wire(subject) {
        Some(SubjectKind::Process) => "create gate, an open asking FILE_EXECUTE",
        Some(SubjectKind::Image) => "section gate, an executable section being created",
        Some(other) => other.as_str(),
        None => "an undefined subject",
    }
}

/// Whether the gate that asked is allowed to refuse.
///
/// Only the acquire-for-section pre-operation may. It fires when a section is
/// being created with execute access, which is how a program's own image is
/// mapped — refusing there is the only refusal in the product that is meant to
/// stop something from running.
///
/// **What it is not, measured in the guest on 2026-10-13.** The same gate fires
/// for a **data** file mapped `PAGE_EXECUTE_READWRITE`, which is the loader shape
/// and not an image, and there the refusal was logged while the mapping
/// succeeded: the fixture printed the view's address
/// (`pid 1384 maps C:\Samples\plant2.bin executable and writable at 0x259a02f0000`).
/// So a refusal from this gate is *believed* to stop an image section (the
/// 2026-10-02 `block-test.exe` run logged the refusal; nothing on record
/// measures that the process then failed to start) and is **measured** not to
/// stop a data section mapped executable. What stops that shape is the process
/// walk and the termination behind it, and no surface may claim more — see the
/// info line below, which says which of the two happened.
///
/// **The status, after three readings and two measurements.** The reference
/// page for this operation's `FLT_PARAMETERS` names exactly one failure a
/// minifilter may return for a created section: `STATUS_INSUFFICIENT_RESOURCES`.
/// That was this product's reading on 2026-10-13, was queried on 2026-10-16 —
/// the pattern the community prescribes for blocking module loading through
/// this callback is `Data->IoStatus.Status = STATUS_ACCESS_DENIED` plus
/// `FLT_PREOP_COMPLETE`, which is what Don Burn answers with on OSR — and is
/// the reading this product acts on again from 2026-10-18.
///
/// What settles it is not the argument but the two runs that went the other
/// way. On 2026-10-13 a data file mapped `PAGE_EXECUTE_READWRITE` was mapped
/// after the refusal was logged, and on 2026-10-17 two convicted WannaCry
/// binaries started while both refusal lines were being written. Either the
/// filter manager ignored `STATUS_ACCESS_DENIED` — the document's reading — or
/// the acquire that was refused was not the one about to run. The driver now
/// uses the documented status **and** reports the asking pid, so the next run
/// separates the two: a refusal that names the shell and a program that still
/// starts means the ask was the wrong one; a refusal that names the missing
/// program's own creator and no start means the status was the problem.
///
/// The create pre-operation asks about an open carrying
/// `FILE_EXECUTE`, and that mask is not what it looks like — measured in the
/// test VM on 2026-10-01:
///
/// * `FILE_EXECUTE` is `0x0020` and so is `FILE_TRAVERSE` (both in `wdm.h`,
///   7270 and 7271), so a *directory* open reaches this gate as an execution
///   question;
/// * a copy of `notepad.exe` that nobody ran, merely displayed in a folder, is
///   asked about here — Explorer reads an icon and a manifest through the image
///   loader, which needs a `FILE_EXECUTE` open, and maps it read-only, which is
///   exactly why the section gate stays quiet about it;
/// * `ActivationStore.dat`, `settings.dat`, `machine.pckgdep` and
///   `ConsoleHost_history.txt` are asked about here too. None is executable.
///
/// So the create gate's question is a good hint and a poor accusation, and the
/// cost of acting on it is real: the same log shows a sample's mere *copy*
/// convicted, refused twice, and quarantined before anything ran it. Refusing
/// from this gate is therefore given up, and the section gate — which fires
/// only when a file is genuinely about to become an executable image — carries
/// every refusal.
///
/// **What a create-gate conviction does now, since 2026-10-15.** It is
/// reported: the driver is answered `Allow`, and a [`Detection`] goes to the
/// service so the file is taken. Before that it was a log line and nothing
/// else. In the 2026-10-14 WannaCry run this gate produced about sixty of those
/// lines, every one of them a file the engine had convicted, and not one of
/// them did anything at all — which is the half of that failure that is fixed
/// on this side. The other half is fixed in the driver: it stopped asking here
/// entirely, because an answer that can only ever be `Allow` is not worth the
/// port thread's time, and occupying that thread is what let a WannaCry
/// process run.
///
/// When the create gate stops over-firing this can be reconsidered; the mask
/// test that makes it noisy is the first thing to fix.
fn refusing_gate(subject: u32) -> bool {
    matches!(SubjectKind::from_wire(subject), Some(SubjectKind::Image))
}

/// The reply to one decision request.
///
/// See this module's documentation for the two correlations a reply has to
/// carry. The one line that is not [`DecisionReplyMessage::answering`]'s is the
/// filter manager's own `MessageId`, which `answering` leaves at zero because
/// the port header is not the product's protocol — and a reply whose `MessageId`
/// matches no outstanding receive is discarded, which is the difference between
/// a blocked program and a driver that waited five seconds and allowed it.
pub fn reply_for(request: &DecisionRequestMessage, decision: Decision) -> DecisionReplyMessage {
    let mut reply = DecisionReplyMessage::answering(request, decision);
    reply.reply.message_id = request.prefix.header.message_id;
    reply
}

/// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`, and the path spelling of it.
const HR_FILE_NOT_FOUND: u32 = 0x8007_0000 | crate::win32::ERROR_FILE_NOT_FOUND;
const HR_PATH_NOT_FOUND: u32 = 0x8007_0000 | crate::win32::ERROR_PATH_NOT_FOUND;

/// `HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)`.
const HR_ACCESS_DENIED: u32 = 0x8007_0000 | ERROR_ACCESS_DENIED;

/// `STATUS_ACCESS_DENIED`: the filter manager refusing on its own authority.
///
/// It is a kernel component, so its answer is an `NTSTATUS` rather than a Win32
/// error behind an `HRESULT` prefix. The two are not one number with two
/// spellings, and the difference is the whole reason [`connect_failure_reason`]
/// reads the shape before it reads the code.
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// `STATUS_OBJECT_NAME_NOT_FOUND` and `STATUS_OBJECT_PATH_NOT_FOUND`.
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;

/// Why a connect failed, in a sentence.
///
/// The three codes worth distinguishing are the three states a user is in: the
/// driver is not loaded or has not created its port yet, the port is there and
/// this process may not open it, or something else went wrong. A log line that
/// said only "could not connect" would send whoever reads it to the wrong one of
/// those.
///
/// # Why this reads the whole `HRESULT`
///
/// Everywhere else in this crate the code inside an `HRESULT` is
/// [`crate::win32::code`]'s low sixteen bits, which is exact for the
/// Win32-shaped values `HRESULT_FROM_WIN32` produces. Here it is not, and both
/// ways it goes wrong produce a confident wrong answer, which is worse than no
/// answer at all:
///
/// * A value that is not Win32-shaped has no Win32 code inside it. `E_FAIL` is
///   `0x8000_4005`, whose low bits are `5` — the same `5` as
///   `ERROR_ACCESS_DENIED`. Masking alone would report a generic failure as a
///   permissions problem and send the reader to look at a DACL.
/// * The filter manager may answer with an `NTSTATUS` instead.
///   `STATUS_ACCESS_DENIED` is `0xC000_0022`, whose low bits are `34`, so
///   masking alone would report a port that is in fact refusing this process as
///   an unknown failure.
///
/// So the shape is decided first and the Win32 code is read only out of a value
/// that has one. The caller logs the raw `HRESULT` beside this sentence, because
/// the sentence is a diagnosis and the number is the evidence for it.
///
/// A free function of the value rather than of the `windows::core::Error`,
/// because this is a decision about a number and it is worth being able to test
/// it.
pub const fn connect_failure_reason(hr: u32) -> &'static str {
    match hr {
        HR_FILE_NOT_FOUND | HR_PATH_NOT_FOUND => "the driver has not created its filter port",
        HR_ACCESS_DENIED | STATUS_ACCESS_DENIED => {
            "the filter port exists and this process may not connect to it"
        }
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => {
            "the driver has not created its filter port"
        }
        _ => "the filter port could not be opened",
    }
}

/// True when a receive ending is the connection ending rather than a fault.
///
/// A driver that unloads closes its port, and the filter manager fails the
/// outstanding receive with `ERROR_INVALID_HANDLE`; a port closed under a
/// blocked receive gives `ERROR_OPERATION_ABORTED`; a pipe-shaped failure gives
/// one of the three codes `crate::win32::is_peer_gone` knows. All of them are
/// ordinary — a driver being reloaded is a thing that happens — and all of them
/// are followed by a reconnect, which is the whole point of retrying. Only the
/// codes that are neither are worth a warning.
const fn is_connection_over(code: u32) -> bool {
    code == ERROR_INVALID_HANDLE
        || code == ERROR_OPERATION_ABORTED
        || crate::win32::is_peer_gone(code)
}

/// How many decision scans may run at once.
///
/// More than one, because the point of moving the scan off the port thread is
/// that a slow file must not hold up the file behind it, and one worker cannot
/// show that. No more than this, because a worker is a thread scanning with the
/// machine's processor, competing with the real-time watcher, with a scan a user
/// asked for and with whatever else the machine is doing.
const SCAN_WORKERS: usize = 2;

/// How many files may be waiting for a worker.
///
/// The queue holds the files whose driver has already given up waiting, so a
/// queue that is filling is a backlog rather than a fault — but a queue with no
/// ceiling is not a queue. Sixty-four entries is thirty-two scans per worker,
/// which is minutes rather than seconds of backlog for any scan slower than a
/// second; past that the machine has stopped keeping up, and the honest answer
/// is to say so rather than to grow a job, a waiting thread and a path per file
/// until there is no memory left. See [`ScanPool::scan_within`] for what happens
/// to the files that do not fit.
const SCAN_BACKLOG: usize = 64;

/// How many skipped decisions go between two log lines about skipping.
///
/// The event arrives in thousands at a time and the number that matters to a
/// reader is how many, not which ones.
const SKIP_REPORT_INTERVAL: u64 = 1_000;

/// What the port thread gives up the last part of the driver's wait for.
///
/// The wait being spent is not the scan alone: the driver's clock starts before
/// its message is written to the port, this thread has to read it, and the
/// answer has to travel back and be taken out of the port before the driver
/// stops looking for it.
const REPLY_HEADROOM: Duration = Duration::from_millis(1_500);

/// How long the port thread waits for one decision scan.
///
/// Derived from the protocol rather than chosen, so that the two sides of this
/// cannot drift apart without that being a decision: the driver's wait is
/// [`DecisionPolicy::DEFAULT`]'s, taken at its own `FltSendMessage` call, and
/// this is that minus [`REPLY_HEADROOM`]. A reply that arrives after the driver
/// has stopped waiting is not a late reply — it is an error: `FilterReplyMessage`
/// answers `ERROR_FLT_NO_WAITER_FOR_REPLY` (`0x801F0020`), which is the warning
/// the field logs carried once per large file.
///
/// The driver's wait is not configurable through anything the service can reach,
/// and [`DriverStatus`] has no field for it — so this is a fact about that call
/// site and not about anything the driver tells the service. If the driver is
/// ever built to wait longer than [`DecisionPolicy::DEFAULT`], the way that
/// shows up here is a rising `decisions_unanswered`, which is the counter the
/// service already prints beside every status.
const DECISION_DEADLINE: Duration =
    Duration::from_millis(DecisionPolicy::DEFAULT_TIMEOUT_MS as u64).saturating_sub(REPLY_HEADROOM);

/// One decision scan, handed to a worker.
struct ScanJob {
    /// The file, already decoded and checked.
    path: PathBuf,
    /// The options every decision scan uses.
    options: ScanOptions,
    /// Where the worker puts its answer.
    ///
    /// Nobody shares this: the port thread holds the receiving end while it is
    /// waiting, and the wait is handed to a thread of its own when the deadline
    /// passes. Dropping it instead would be a race against the worker's send,
    /// and the report that lost would be a conviction found and thrown away.
    reply: Sender<FileScanReport>,
}

/// The decision scans, off the port thread.
///
/// The scan used to run inside the receive loop: `serve` called
/// [`Dispatcher::handle`], which called [`ScanEngine::scan_file`], and the loop
/// was inside that call for as long as the file took. Two consequences, and both
/// were in the field logs of 2026-10-01 and 2026-10-02:
///
/// * **A file could be answered after the driver had given up.** The driver
///   waits [`DecisionPolicy::DEFAULT_TIMEOUT_MS`]; the budget
///   [`ScanOptions::realtime`] sets is five seconds *plus a second per
///   megabyte*, and it is a label the engine puts on a scan it has already
///   finished rather than a stop condition — so every file of a megabyte or more
///   could be scanned for longer than the driver's patience. The reply then came
///   back `ERROR_FLT_NO_WAITER_FOR_REPLY` and the file had already been allowed.
/// * **One slow file delayed every other decision**, because the port thread was
///   inside the scan and could not read the next message. A small binary behind
///   a large one inherited the large one's scan time and timed out too, which is
///   what the `0x801F0020` on `OneDriveStandaloneUpdater.exe` — not a large file
///   — is.
///
/// So the scan lives here now. Workers take jobs off a queue; the port thread
/// waits [`DECISION_DEADLINE`] for an answer and answers the driver itself if it
/// has none; and a scan that outlives that wait is not abandoned. It finishes,
/// and a conviction it reaches afterwards is *reported* — see [`report_late`] —
/// rather than sent as a reply the driver is no longer waiting for.
///
/// The threads are detached on purpose. Dropping the queue's sender ends every
/// worker as soon as it has finished the file it is holding, and joining them
/// here would make a service stop wait for a scan of a file the driver gave up
/// on minutes ago.
struct ScanPool {
    /// The queue. One sender, so dropping this is what stops the workers.
    jobs: Sender<ScanJob>,
    /// Where a late conviction goes. Cloned into the waiting thread of every
    /// scan that outlives its deadline.
    events: Sender<Event>,
    /// How long the port thread waits for one scan.
    deadline: Duration,
    /// Decisions answered without a scan because the queue was full.
    skipped: AtomicU64,
}

impl ScanPool {
    /// Start the workers over one engine.
    ///
    /// The engine is shared with the host and with every worker, and that is
    /// sound because a scan reads the rule database and never writes it:
    /// [`ScanEngine::scan_file`] takes `&self` and builds a scanner per call.
    fn new(engine: Arc<ScanEngine>, events: Sender<Event>, deadline: Duration) -> Self {
        let (jobs, queue) = crossbeam_channel::bounded::<ScanJob>(SCAN_BACKLOG);
        for index in 0..SCAN_WORKERS {
            let engine = Arc::clone(&engine);
            let queue = queue.clone();
            let spawned = std::thread::Builder::new()
                .name(format!("wenle-av-gate-scan-{index}"))
                .spawn(move || scan_jobs(engine, queue));
            if let Err(error) = spawned {
                // Worth a line at the top of the log: with no worker at all,
                // every decision is answered without the file being examined,
                // and nothing else in the product says so. The service still
                // starts — the driver allows what it cannot get an answer for.
                log::error!("a decision-scan thread could not be started: {error}");
            }
        }
        Self {
            jobs,
            events,
            deadline,
            skipped: AtomicU64::new(0),
        }
    }

    /// Scan one path, waiting no longer than this pool's deadline.
    ///
    /// `None` means the scan did not answer in time, and the caller answers the
    /// driver anyway: the driver's own clock is the reason this one exists, and
    /// a late reply is worse than an early [`Decision::Allow`] because the
    /// driver logs it as an error and discards it. What the deadline costs is
    /// the *blocking*, not the detection — the scan carries on, and if it
    /// convicts, [`report_late`] says so.
    fn scan_within(&self, path: &Path, options: &ScanOptions) -> Option<FileScanReport> {
        let (reply, answer) = crossbeam_channel::bounded(1);
        let job = ScanJob {
            path: path.to_path_buf(),
            options: options.clone(),
            reply,
        };
        match self.jobs.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // The one decision in this file made without looking at the
                // file, and it is about the queue rather than about the path:
                // sixty-four files are already waiting and every one of them
                // has a driver that has stopped waiting. Reported as a rate
                // rather than once per file — see [`SKIP_REPORT_INTERVAL`] —
                // because a full queue arrives as thousands at a time, and
                // because a reader needs the count far more than the names.
                let skipped = self.skipped.fetch_add(1, Ordering::Relaxed) + 1;
                if skipped == 1 || skipped % SKIP_REPORT_INTERVAL == 0 {
                    log::warn!(
                        "{skipped} decisions have been answered without a scan: {SCAN_BACKLOG} \
                         files are already waiting for the {SCAN_WORKERS} decision-scan threads"
                    );
                }
                return None;
            }
            Err(TrySendError::Disconnected(_)) => {
                // Every worker is gone. There is nobody to scan the file and
                // nobody who will ever report it, so this is the only case
                // where a file is not examined and nothing is said about it
                // later.
                log::error!(
                    "no decision-scan thread is running; {} was not examined",
                    path.display()
                );
                return None;
            }
        }
        match answer.recv_timeout(self.deadline) {
            Ok(report) => Some(report),
            Err(RecvTimeoutError::Timeout) => {
                // The handover, and the reason there is no flag for the worker
                // to read: `answer` is *moved* into a thread whose only job is
                // to wait for this one report, so exactly one thread owns the
                // receiving end at every instant. A worker's send therefore
                // either reaches the port thread or reaches this one, and there
                // is no interleaving in which a report is written into a
                // channel nobody holds.
                let events = self.events.clone();
                let noted = path.to_path_buf();
                let spawned = std::thread::Builder::new()
                    .name("wenle-av-late-decision".to_string())
                    .spawn(move || match answer.recv() {
                        Ok(report) => report_late(&events, report),
                        // The worker died between taking the job and sending
                        // an answer, or the process is on its way out. There is
                        // nothing to report.
                        Err(_) => log::debug!(
                            "the scan of {} ended without an answer",
                            noted.display()
                        ),
                    });
                if let Err(error) = spawned {
                    log::warn!(
                        "the scan of {} is still running and no thread could be made to report \
                         what it finds: {error}",
                        path.display()
                    );
                }
                log::info!(
                    "{} was allowed with no answer: the scan is still running after {} ms, and \
                     the driver does not wait longer (a conviction will be reported when the scan \
                     ends)",
                    path.display(),
                    self.deadline.as_millis()
                );
                None
            }
            Err(RecvTimeoutError::Disconnected) => {
                // The worker holding this job dropped its answer without
                // sending one, which is a panic. The deadline path above is
                // *not* this: an abandoned job's receiving end lives on in the
                // waiting thread, so a late report finds a reader.
                log::warn!("the scan of {} ended without an answer", path.display());
                None
            }
        }
    }
}

/// Take jobs off the queue until it is dropped.
fn scan_jobs(engine: Arc<ScanEngine>, queue: Receiver<ScanJob>) {
    while let Ok(job) = queue.recv() {
        let report = engine.scan_file(&job.path, &job.options);
        if let Err(crossbeam_channel::SendError(report)) = job.reply.send(report) {
            // Nobody is left to read this: the port thread's deadline passed
            // and no waiting thread could be made, or the process is stopping.
            // Deliberately not the ordinary "the decision was already made"
            // case, which is the waiting thread receiving it a moment later.
            log::debug!(
                "the answer for {} arrived when no decision was waiting for it",
                report.path.display()
            );
        }
    }
    log::debug!("a decision-scan thread has stopped: the queue is closed");
}

/// Report a conviction the driver was never told about.
///
/// This is the half of a decision that cannot be a reply. By the time it runs
/// the driver has answered for itself — `DecisionPolicy::DEFAULT.on_timeout` is
/// [`Decision::Allow`] — so whatever this says, the file was not stopped, and
/// the detection is built with `blocked = false` for exactly that reason:
/// [`av_ipc::Phase::describe`] then reads "was found after it appeared", and
/// nothing downstream can turn it into a claim that a program was blocked. It is
/// not a weaker finding — [`crate::host`] acts on a confirmed driver detection
/// whether or not it claims a block, so the file goes into the vault exactly as
/// a refused one does — and it is not a second answer: the driver's request was
/// answered before this was built.
///
/// Reported from *both* gates — the create gate, which [`refusing_gate`]
/// excludes and which therefore may not refuse at all, and the section gate. The
/// report-only decision for the create gate is about
/// refusing — an open carrying `FILE_EXECUTE` is asked about everything, so a
/// conviction there does not stop the open and says nothing about a program
/// about to run — and it is not a decision to keep quiet about a file the engine
/// has convicted. This detection makes no claim the gate cannot support: it says
/// the file was found and was not blocked, which is true of both gates.
fn report_late(events: &Sender<Event>, report: FileScanReport) {
    if verdict_to_decision(report.verdict()) != Decision::Block {
        // A scan that took longer than the driver's patience and found nothing
        // is a slow file. Reporting every one of those would be a notification
        // per large binary on the machine.
        return;
    }
    log::info!(
        "{} was convicted after the driver had stopped waiting for the answer: the engine scored \
         it {}; reporting it now",
        report.path.display(),
        report.verdict().as_str()
    );
    publish(
        events,
        Event::Detection(Detection::from_report(
            &report,
            EntrySource::Driver,
            false,
            DetectionAction::Reported,
        )),
    );
}

/// The decisions, separated from the port.
///
/// Everything here runs on any platform and is tested on this one; the port is
/// what cannot be tested, so the port does nothing but move bytes. It is the
/// same split `av-ipc` makes between its protocol and `av-service`'s pipes, and
/// for the same reason: a decision procedure that can only be exercised by
/// running the installed product is a decision procedure that is never
/// exercised.
pub struct Dispatcher {
    /// The scans, on their own threads. Holds the engine; see [`ScanPool::new`]
    /// for why sharing it is sound.
    pool: ScanPool,
    /// What one decision scan is allowed to do. See this module's documentation
    /// for why it is [`ScanOptions::realtime`] and not the scanning
    /// configuration's options.
    options: ScanOptions,
    /// What the driver last said about itself.
    status: Option<DriverStatus>,
    /// The paths the user has allowed. Shared, not owned: the control thread
    /// adds to it while this thread reads it, which is the entire mechanism by
    /// which pressing "allow" stops the next launch from being taken. See
    /// [`crate::allow`].
    allow: AllowList,
    /// Where this product keeps its own files.
    ///
    /// Held so that [`Self::decide`] can answer a question about a path inside
    /// our own tree without scanning it. See [`crate::engine::is_own_tree`] for
    /// the policy, which is [`crate::process_watch`]'s and not a new one.
    own_tree: AvPaths,
}

impl Dispatcher {
    /// A dispatcher over an engine, with no status heard yet.
    ///
    /// `events` is the service's event channel, and the dispatcher keeps a
    /// clone of it: a scan that outlives `DECISION_DEADLINE` is reported on
    /// the waiting thread rather than answered, and that thread has no port to
    /// reply through and no business holding one.
    pub fn new(
        engine: Arc<ScanEngine>,
        events: Sender<Event>,
        allow: AllowList,
        own_tree: AvPaths,
    ) -> Self {
        Self::on_a_deadline(engine, events, DECISION_DEADLINE, allow, own_tree)
    }

    /// The same, with the wait chosen rather than derived.
    ///
    /// Only the tests call this, and they are the reason it exists: a deadline
    /// of [`Duration::ZERO`] is how a test gets a scan that has certainly not
    /// finished yet, which is the only way to see the late path without a
    /// fixture large enough to take three and a half seconds.
    fn on_a_deadline(
        engine: Arc<ScanEngine>,
        events: Sender<Event>,
        deadline: Duration,
        allow: AllowList,
        own_tree: AvPaths,
    ) -> Self {
        Self {
            pool: ScanPool::new(engine, events, deadline),
            options: ScanOptions::realtime(),
            status: None,
            allow,
            own_tree,
        }
    }

    /// What the driver last reported about itself, if it has reported.
    ///
    /// Kept rather than logged and forgotten because it is the only evidence in
    /// the product about what the *driver* thinks it is doing — how many
    /// decisions it asked, how many it never got an answer for, how many events
    /// it dropped. The status this service reports through
    /// [`crate::driver::check`] answers a different question, which is whether
    /// the driver is loaded at all.
    pub const fn reported_status(&self) -> Option<DriverStatus> {
        self.status
    }

    /// Take one message and say what to do about it.
    ///
    /// Exhaustive over [`Received`] with no wildcard arm: a message kind added
    /// to the protocol stops this build rather than being answered by a guess,
    /// which is the failure `av_driver_proto::wire`'s own documentation names.
    pub fn handle(&mut self, message: Received) -> Action {
        match message {
            Received::DecisionRequest(request) => {
                let (decision, detection) = self.decide(&request);
                let reply = reply_for(&request, decision);
                match detection {
                    Some(detection) => Action::ReplyAndReport(reply, Box::new(detection)),
                    None => Action::Reply(reply),
                }
            }
            // Translated by the same function the rest of the service would use,
            // and not by a copy: the mapping from the driver's codes to the
            // protocol's vocabulary is exhaustive there, and a second one here
            // would be a second place for a new driver action to be dropped.
            Received::Event(event) => Action::Publish(driver::translate(&event)),
            Received::Status(message) => {
                self.status = Some(message.status);
                Action::Ignored(describe_status(&message.status))
            }
            Received::Empty => {
                Action::Ignored("the filter manager returned success without a message".to_string())
            }
            Received::Unreadable { reason, .. } => Action::Ignored(reason),
        }
    }

    /// The answer to one decision request, and what to report about it.
    ///
    /// Every way out of this function ends in [`Decision::Allow`] except a scan
    /// that confirms a detection from a gate that may refuse. See this module's
    /// documentation for why the asymmetry with blocking is deliberate rather
    /// than an oversight.
    ///
    /// **The detection is `Some` for two different reasons, and the caller must
    /// not conflate them.** One is a refusal, where the driver is told to stop
    /// the operation. The other is a conviction from a gate that only reports,
    /// where the driver is told to let it continue and the file is worth taking
    /// anyway. Both are `Some` since 2026-10-15; the second used to be `None`,
    /// which is what made about sixty convictions in the 2026-10-14 WannaCry
    /// log into nothing but log lines.
    ///
    /// `blocked` is `decision == Decision::Block` rather than a constant, for
    /// exactly that reason. [`EntrySource::is_pre_execution`] and
    /// `av_ipc::Phase::describe` read it, and a finding claiming a file was
    /// stopped when the driver was told `Allow` is precisely the kind of
    /// surface this product keeps catching itself lying on.
    fn decide(&self, request: &DecisionRequestMessage) -> (Decision, Option<Detection>) {
        let units = request.path();
        if units.is_empty() {
            // The driver asked about no path at all. There is nothing to look
            // at, so there is nothing to refuse, and inventing a path here would
            // be deciding about a file nobody named.
            log::debug!("the driver asked for a decision about no path; allowing it");
            return (Decision::Allow, None);
        }
        // Strictly, unlike `crate::driver::path_of`, which decodes the same
        // field lossily. The difference is what the text is for: there it names
        // an event that has already happened, and a replacement character in a
        // log is better than dropping the report. Here the text is the thing
        // that gets opened, so a path this process cannot reproduce exactly is a
        // path it must not decide about — and the answer for "I cannot name
        // this" is the same as for every other failure.
        let Ok(text) = String::from_utf16(units) else {
            log::warn!("the driver asked about a path that is not valid UTF-16; allowing it");
            return (Decision::Allow, None);
        };
        let path = PathBuf::from(text);
        // A path the user has allowed, checked *before* the scan rather than
        // after it. After would be enough to keep the file out of the vault and
        // not enough for two reasons: the scan is the expensive part of every
        // program launch, and a file the user has said is fine must not spend
        // the machine's time being convicted and then excused. Allow is the
        // correct answer here whether the engine would have convicted it or not
        // — that is what the user said — so nothing is lost by not asking.
        //
        // This is the branch that makes the "Allow" button mean something in
        // real time. Without it the exclusion would only be read by the GUI's
        // and the CLI's directory walkers, and a file restored to its place
        // would be convicted again on its next launch, forever. See
        // [`crate::allow`] for why the owner of a *user's* exclusion is here and
        // not in the driver.
        if self.allow.allows(&path) {
            // Debug, not info: this is one line per launch of a file the user
            // allowed, which is the same volume as the ordinary clean-file case
            // and would drown a log the moment somebody allowed a game folder.
            log::debug!("{} is on the allow list; not scanned", path.display());
            return (Decision::Allow, None);
        }
        // Our own files, for the same reason and with more force.
        //
        // The engine convicts this product's own binaries: the rules that catch
        // a packed or obfuscated dropper have no way to know that the packed
        // binary in front of them is ours, and the executable that is scanned
        // here is the one that is about to run. The answer for our own tree is
        // therefore not "scan it and hope" but "it is ours, let it run", which
        // is a policy the product already applies in two places --
        // [`crate::process_watch`]'s `skipped_own`, and the driver's own
        // exclusion table, which names `C:\ProgramData\WenleAV` -- and which
        // simply had no reader on this path until 2026-10-10.
        //
        // What that cost, measured: the product's own binaries were scanned in
        // full on every open. `C:\WenleAV\wenle.exe` was asked about nine times
        // in one session (`an open asking FILE_EXECUTE`), each scan taking about
        // two seconds, and two of those arrived from the section gate -- which
        // is not a place that can afford to wait. A machine running this
        // product from a directory its driver does not exclude was therefore
        // spending seconds of every launch scanning the scanner. See
        // [`Self::own_tree`].
        //
        // Debug, not info, and for a sharper reason than the allow list above:
        // this is every launch of every one of our binaries, which includes each
        // launch of the GUI.
        if crate::engine::is_own_tree(&self.own_tree, &path) {
            log::debug!(
                "{} is one of our own files; not scanned",
                path.display()
            );
            return (Decision::Allow, None);
        }
        // The one way out of this function that neither looks at the file nor
        // says anything about it later: the scan did not finish inside the
        // deadline the driver's own wait leaves room for. Everything below is
        // the ordinary case, and the late conviction is [`report_late`]'s.
        let Some(report) = self.pool.scan_within(&path, &self.options) else {
            return (Decision::Allow, None);
        };
        // What the engine said, and what this gate may do about it, are two
        // questions. Only one of the driver's gates may refuse -- see
        // [`refusing_gate`] for which and why -- so a conviction arriving from
        // the other is reported and not acted on.
        let convicted = verdict_to_decision(report.verdict()) == Decision::Block;
        // Which of the driver's two gates asked. Appended to both lines rather
        // than logged as a line of its own, because the two are read together
        // and a separate line would double the volume of a path every program
        // launch goes through.
        let gate = asking_gate(request.subject);
        // Which process issued the operation. **Not the program that is about
        // to run**: the image section of a process being created is created on
        // the thread that called `CreateProcess`, so this names the shell or
        // launcher. Nothing acts on it — the pid is here because it settles a
        // question the driver could not answer before 2026-10-18 (was a
        // refusal the complainant's own acquire, or a bystander's?) and because
        // a crash report that says "this file" is worth more with "opened by
        // this process" beside it. Terminating it would kill the wrong program.
        let asker = match request.process_id {
            0 => "an unidentified process".to_string(),
            pid => format!("process {pid}"),
        };
        let decision = if convicted && refusing_gate(request.subject) {
            Decision::Block
        } else {
            Decision::Allow
        };
        let detection = if decision == Decision::Block {
            // Info, not debug: a block is the whole point of the feature and it
            // happens to a handful of files, not to every file opened.
            //
            // `refusing_gate` is what puts a verdict on this branch, so this line
            // is always the acquire-for-section gate answering a section.
            //
            // The claim is about what this product *did* — it answered the
            // driver's question with a refusal — and, since 2026-10-18, about
            // what the filter manager does with that answer.
            //
            // **The status is the whole history of this feature.** Until
            // 2026-10-18 the driver completed the section with
            // `STATUS_ACCESS_DENIED`, which the filter manager does not honour
            // for a created section — the only failure it accepts there is
            // `STATUS_INSUFFICIENT_RESOURCES`. So this line printed, the
            // conviction was real, and the program ran anyway: measured on
            // 2026-10-13 (a data file mapped executable was mapped, and the
            // process walk stopped the process 1–2 s later) and again on
            // 2026-10-17, when two convicted WannaCry binaries started while
            // both lines were being written.
            //
            // What is *not* claimed here is that the program was stopped: this
            // thread does not see the caller's result. A refusal that fails
            // section creation makes `CreateProcess` fail, which is the
            // mechanism; confirming it is the next run's job, and the criterion
            // is that no process starts, not that this line appears.
            log::info!(
                "{} was refused: the engine scored it {} (asked by the {gate}, {asker}; the \
                 section was failed with STATUS_INSUFFICIENT_RESOURCES, which is the only \
                 refusal the filter manager honours for a created section)",
                path.display(),
                report.verdict().as_str()
            );
            // `Reported` rather than `Quarantined`: nothing has been done to
            // the file yet, and this function cannot do anything to it. The
            // vault belongs to the service, which is the only thing that writes
            // to it — the reply travels back to the driver first, and the
            // service acts on this detection when it drains its channel. A
            // detection that guessed at the action would be a notification
            // promising a file had been taken before anyone had tried.
            Some(Detection::from_report(
                &report,
                EntrySource::Driver,
                true,
                DetectionAction::Reported,
            ))
        } else if convicted {
            // A conviction from a gate that cannot refuse. It is reported and
            // not answered with a block, and **until 2026-10-15 the reporting
            // was a log line and nothing else**: this arm returned `None`, so
            // no detection was built, nothing reached the vault, and the file
            // stayed where it was. The 2026-10-14 WannaCry log carries about
            // sixty of these lines, every one of them a file the engine had
            // convicted, and not one of them did anything.
            //
            // `blocked = false` and not `true`, whatever `EntrySource::Driver`
            // means elsewhere: this gate's `Allow` is what the driver was told,
            // so `av_ipc::Phase::describe` must not read "was stopped" out of
            // it. What the detection does carry is the verdict, the score and
            // the rule identifiers, which is everything `crate::host`'s
            // `should_take` needs to take the file.
            log::info!(
                "{} was convicted and allowed: the engine scored it {} (asked by the {gate}, \
                 which reports and does not refuse; reporting it so the file is taken)",
                path.display(),
                report.verdict().as_str()
            );
            Some(Detection::from_report(
                &report,
                EntrySource::Driver,
                false,
                DetectionAction::Reported,
            ))
        } else {
            // Debug, not info: this is every program that starts on the
            // machine, which is a volume a log has no business carrying at its
            // default level.
            log::debug!(
                "{} was allowed: the engine scored it {} (asked by the {gate}, {asker})",
                path.display(),
                report.verdict().as_str()
            );
            None
        };
        if let Some(error) = &report.error {
            // The verdict for a file that could not be read is `Unknown`, which
            // is not a block — so a file the engine could not open is allowed,
            // and this line is the only evidence that a decision was made
            // without looking. The alternative, refusing what cannot be
            // examined, is the fail-closed shape this module exists not to have.
            log::debug!("{} could not be examined: {error}", path.display());
        }
        (decision, detection)
    }
}

/// [`Dispatcher`], for a log line or a failed assertion.
///
/// The status is summarised rather than printed: it has no `Debug` of its own —
/// it is a bare `repr(C)` wire structure — and the field that matters here is
/// whether the driver has said anything at all.
impl core::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("options", &self.options)
            .field("has_reported_status", &self.status.is_some())
            .field("allowed_paths", &self.allow.len())
            .finish()
    }
}

/// What a status message says, in a sentence.
///
/// The counters are the interesting part and are carried in full: they are how
/// a service notices that it is answering badly — decisions asked that were
/// never answered, events the driver dropped — without needing a debugger on
/// the kernel side.
fn describe_status(status: &DriverStatus) -> String {
    use av_driver_proto::event::DriverState;
    let state = match DriverState::from_wire(status.state) {
        Some(state) => format!("{state:?}"),
        None => format!("in a state this build does not define ({})", status.state),
    };
    format!(
        "the driver reports itself {state} at protocol version {}: {} decisions asked, {} \
         answered, {} unanswered, {} events dropped, {} queued",
        status.protocol_version,
        status.decisions_asked,
        status.decisions_answered,
        status.decisions_unanswered,
        status.events_dropped,
        status.queued_events
    )
}

/// The event published when the connection to the driver's port comes or goes.
///
/// `av_ipc`'s vocabulary already has the slot — `DriverEventAction::StateChanged`
/// is documented as "the driver's state changed, or the service connected or
/// disconnected" — and this is what the product emits through it. A user
/// interface that shows whether real-time protection is actually attached needs
/// exactly this and cannot derive it from anything else the service says: the
/// driver's presence check answers "is the driver loaded", and a loaded driver
/// whose port nobody is connected to blocks nothing.
///
/// `connected` is passed rather than two constructors being written, so that the
/// two events cannot disagree about everything except the word.
///
/// `pub(crate)` for one reader: `crate::host`'s tests, which check that an event
/// this module produces reaches a client through the host's drain rather than
/// being built twice — a hand-rolled copy in a test would agree with this
/// function only by being edited alongside it.
pub(crate) fn connection_event(connected: bool, port_name: &str) -> DriverEvent {
    use av_ipc::{DriverPresence, DriverStatus as Presence};
    DriverEvent {
        // The driver's sequence numbers count its own events, and this one is
        // the service's; zero says it belongs to no run of the driver's.
        sequence: 0,
        timestamp_100ns: now_100ns(),
        action: DriverEventAction::StateChanged,
        subject: DriverSubject::Driver,
        // Nothing was done to a file, so there is no path.
        path: None,
        process_id: std::process::id(),
        // The service's own connection report has no creator worth naming.
        parent_process_id: 0,
        thread_id: 0,
        detail: u32::from(connected),
        value: None,
        // The service's own note about the port; nothing was started.
        command_line: None,
        driver_state: Some(if connected {
            Presence {
                // Connecting to the port is proof that the driver created it,
                // which is proof the driver is loaded and running. It is the
                // strongest evidence this product ever gets, and the only
                // evidence that says the driver is *doing* something rather
                // than merely present.
                presence: DriverPresence::Loaded,
                detail: format!("the service is connected to the driver's filter port {port_name}"),
                device: None,
            }
        } else {
            Presence {
                // Not `Absent`: the port going away says the driver stopped
                // answering, and whether it is still loaded is a question
                // `crate::driver::check` answers by opening the control device.
                // Claiming either way here would be a guess about something
                // this thread does not know.
                presence: DriverPresence::Unknown,
                detail: format!(
                    "the connection to the driver's filter port {port_name} has ended; the \
                     service is deciding nothing until it is reconnected"
                ),
                device: None,
            }
        }),
    }
}

/// The current time in the units [`DriverEvent`] reports.
///
/// 100-nanosecond units since 1601-01-01, which is `FILETIME` — the unit the
/// driver has without converting, and therefore the unit the field is in. The
/// conversion lives here rather than in `av-ipc` because every other producer of
/// a `DriverEvent` gets the value from the driver and only this one has to make
/// its own; a helper in the protocol crate would be a helper for one caller.
fn now_100ns() -> u64 {
    /// 1601-01-01 to 1970-01-01 in 100-nanosecond units. Exact and fixed: the
    /// span is 369 Gregorian years, 89 of whose days are leap days.
    const EPOCHS_IN_100NS: i64 = 116_444_736_000_000_000;
    let since_1970 = chrono::Utc::now().timestamp_micros().saturating_mul(10);
    since_1970.saturating_add(EPOCHS_IN_100NS) as u64
}

/// A running filter-port client.
///
/// Dropping one asks its thread to stop, which is what makes the field safe to
/// hold in [`crate::host::Host`] without a shutdown path of its own.
pub struct Client {
    /// Set to ask the thread to stop.
    stop: Arc<AtomicBool>,
    /// True while the thread is alive — retrying, connecting, or serving.
    running: Arc<AtomicBool>,
    /// The thread, or `None` when it could not be started.
    worker: Option<std::thread::JoinHandle<()>>,
}

/// [`Client`], for a log line or a failed assertion.
impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("running", &self.is_running())
            .field("has_thread", &self.worker.is_some())
            .finish()
    }
}

impl Client {
    /// Whether the thread is alive.
    ///
    /// This is *not* "the driver is connected", and the two must not be
    /// confused: a client whose port does not exist is running and connected to
    /// nothing, which is exactly the state this module exists to make visible
    /// rather than hide. What it does answer is whether the retrying is still
    /// happening.
    pub fn is_running(&self) -> bool {
        self.worker.is_some() && self.running.load(Ordering::SeqCst)
    }

    /// Ask the thread to stop, without waiting for it.
    ///
    /// Not joined, and the reason is in this module's documentation: a thread
    /// inside a receive is inside a kernel wait that nothing in user mode can
    /// interrupt, so a join would block the caller — and the caller is
    /// [`crate::host::Host::shut_down`], on the path that answers the SCM's stop
    /// request. A detached thread that outlives the call by one message is the
    /// smaller of the two problems.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start the client, on a port this caller names.
///
/// The name is a parameter for the reason [`crate::control::serve_on`]'s is: a
/// test must not reach the real endpoint. There it was two listeners on one pipe
/// answering one question; here it is worse, because a filter communication port
/// has a connection limit and the second client is a client the installed
/// service cannot be. A test run on a machine where the product is installed
/// would take the driver's client slot and leave the real service deciding
/// nothing — silently, which is the failure this whole module is about.
///
/// There was a `start` beside this that passed
/// [`av_driver_proto::PORT_NAME`] and nothing else, with a comment saying it was
/// the only caller a name was allowed to come from. It was deleted on 2026-10-09:
/// the one production caller is [`crate::host::Host::start_driver_port`], which
/// has always called this directly, so the wrapper had no callers and its
/// comment described an invariant nothing was keeping. The name reaches here
/// from [`crate::host::Host::open`], which passes the protocol's constant.
pub fn start_on(
    engine: Arc<ScanEngine>,
    events: Sender<Event>,
    port_name: &str,
    allow: AllowList,
    own_tree: AvPaths,
    configuration: ConfigMessage,
) -> Client {
    #[cfg(windows)]
    {
        let dispatcher = Dispatcher::new(engine, events.clone(), allow, own_tree);
        let stop = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        let spawned = {
            let stop = Arc::clone(&stop);
            let running = Arc::clone(&running);
            let port_name = port_name.to_string();
            std::thread::Builder::new()
                .name("wenle-av-filter-port".to_string())
                .spawn(move || {
                    run(dispatcher, events, &port_name, &stop, &running, configuration)
                })
        };
        match spawned {
            Ok(worker) => Client {
                stop,
                running,
                worker: Some(worker),
            },
            Err(error) => {
                // A thread that cannot be created is a machine out of memory or
                // out of handles. It is not a reason to fail the service's
                // startup — the driver allows whatever it cannot get an answer
                // for, so the product keeps working with the real-time path off
                // — but it is a reason to say so at the top of the log.
                log::error!("the filter-port thread could not be started: {error}");
                running.store(false, Ordering::SeqCst);
                Client {
                    stop,
                    running,
                    worker: None,
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        // No filter manager, so no port to connect to and no decisions to make.
        // Said once, in a sentence, rather than left to be inferred from silence:
        // a build with no driver behind it is not a build that is protecting the
        // machine, whatever its status report says about the engine. Same shape
        // as [`crate::driver::check`]'s non-Windows arm, and for the same
        // reason — a build that cannot look must say "I cannot look" rather than
        // answer "nothing there".
        // `allow` and `configuration` are dropped with the rest: with no port
        // there is no decision path for the first to be consulted on and no
        // driver to arm the second on, and something nobody can read is not an
        // error to report — the warning below is the whole story.
        let _ = (engine, events, port_name, allow, own_tree, configuration);
        log::warn!(
            "this build has no filter manager: the driver's decision port cannot be connected \
             and nothing is being blocked in real time"
        );
        Client {
            stop: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
            worker: None,
        }
    }
}

/// The thread: connect, serve, reconnect, until asked to stop.
///
/// The connection is deliberately not `?`-able. Every failure here has the same
/// handling — wait, then try again — because the state this loop is in when it
/// cannot connect is a supported state of the product rather than a fault, and
/// the only thing that can improve it is time.
#[cfg(windows)]
fn run(
    mut dispatcher: Dispatcher,
    events: Sender<Event>,
    port_name: &str,
    stop: &AtomicBool,
    running: &AtomicBool,
    configuration: ConfigMessage,
) {
    let mut attempt = 0u32;
    while !stop.load(Ordering::SeqCst) {
        let port = match connect(port_name) {
            Ok(port) => port,
            Err(error) => {
                let delay = retry_delay(attempt);
                // The whole `HRESULT`, not `win32::code`'s low sixteen bits:
                // see `connect_failure_reason` for the two shapes masking gets
                // wrong. It is also printed, because the sentence beside it is a
                // diagnosis and this is the evidence for it.
                let hr = error.code().0 as u32;
                let why = connect_failure_reason(hr);
                if attempt == 0 {
                    // The first failure is worth a line at the default level:
                    // a service that started before the driver did is normal,
                    // and a reader of the log should see that the retrying
                    // began rather than only that it eventually stopped.
                    log::info!("{why} (0x{hr:08X}); retrying in {} ms", delay.as_millis());
                } else {
                    // After that it is one fact repeated, and a service that
                    // retried every fifteen seconds for a week must not fill
                    // the event log with it.
                    log::debug!(
                        "{why} (0x{hr:08X}, attempt {}); retrying in {} ms",
                        attempt + 1,
                        delay.as_millis()
                    );
                }
                attempt = attempt.saturating_add(1);
                sleep_unless_stopped(delay, stop);
                continue;
            }
        };
        attempt = 0;
        log::info!("connected to the driver's filter port {port_name}");
        // Before the connection is announced, and deliberately in that order:
        // what the driver does for this product depends on the configuration
        // that arrives with the connection, and a window told "the driver is
        // connected" before it was told to arm itself would be showing a state
        // that is about to change. It is also the order the driver needs — its
        // own two registration reports are queued from *its* connect callback,
        // which has already run by the time this returns.
        configure(&port, &configuration, &events);
        publish(&events, Event::Driver(connection_event(true, port_name)));
        serve(&port, &mut dispatcher, &events, stop);
        // SAFETY: `port` came from `FilterConnectCommunicationPort` and is the
        // only handle to it; nothing else closes it, and nothing uses it after
        // this point.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(port);
        }
        log::info!("the connection to the driver's filter port has ended");
        publish(&events, Event::Driver(connection_event(false, port_name)));
        if stop.load(Ordering::SeqCst) {
            break;
        }
        sleep_unless_stopped(Duration::from_millis(RECONNECT_PAUSE_MS), stop);
    }
    running.store(false, Ordering::SeqCst);
    log::debug!("the filter-port thread has stopped");
}

/// Send one event to the service, or say why not.
///
/// A failed send means the host has gone, which happens on the way out. The
/// event is dropped rather than queued: the protocol has no replay, and
/// reporting a connection state change three minutes late would be worse than
/// not reporting it.
///
/// Takes the [`Event`] rather than a [`DriverEvent`] because a block reports
/// itself as a detection, and a detection is the same shape whether the
/// filesystem watcher found the file or the driver stopped it. The service
/// reads both through one channel and tells them apart by
/// [`Detection::source`]; wrapping here would mean the block arrived by a
/// second route that everything downstream had to know about.
///
/// Not behind `#[cfg(windows)]`: the late half of a decision is reported from a
/// waiting thread rather than from the port loop, and that thread is the same
/// on every platform — the port is the only part of this module that is not.
fn publish(events: &Sender<Event>, event: Event) {
    if events.send(event).is_err() {
        log::debug!("no host is listening for driver events; one was dropped");
    }
}

/// Answer the driver's decision request.
///
/// Split out of the receive loop so that the two things a block does — answer,
/// then report — are two calls in one arm rather than a duplicated block of
/// `unsafe` that has to stay in step with itself.
#[cfg(windows)]
fn reply_to_driver(
    port: windows::Win32::Foundation::HANDLE,
    reply: DecisionReplyMessage,
) {
    use windows::Win32::Storage::InstallableFileSystems::FilterReplyMessage;

    // The length is the whole structure, header included: the reply header is
    // the first field of it, and the filter manager reads its status and message
    // identifier from there.
    // SAFETY: `reply` is alive for the call and is exactly
    // `DecisionReplyMessage::SIZE` bytes, which is the length passed; `reply.reply`
    // is its first field, so the structure's address is the header's address.
    let sent = unsafe {
        FilterReplyMessage(
            port,
            core::ptr::addr_of!(reply).cast::<
                windows::Win32::Storage::InstallableFileSystems::FILTER_REPLY_HEADER,
            >(),
            DecisionReplyMessage::SIZE as u32,
        )
    };
    if let Err(error) = sent {
        // The driver has given up waiting and allowed the file. That is a missed
        // decision and not a broken machine, and the connection is about to be
        // rebuilt by the receive that follows — so this is a warning about a
        // lost decision rather than an error about the service.
        log::warn!("a decision could not be delivered: {error}");
    }
}

/// Tell the driver what to do for this product, and report its answer.
///
/// # Why the service sends this at all
///
/// Two of the driver's defences are *this service's decisions*, not the
/// driver's: whether another process may terminate this product, and whether a
/// write to the product's own files is refused. Neither can be a compile-time
/// constant in a kernel driver, because the answer is a configuration the user
/// owns and can change while the driver is loaded. So they arrive as a
/// [`ConfigMessage`] over the same port the decisions come back on, and they
/// arrive on every connection rather than once — the driver keeps no state
/// across a disconnect, and a service that sent this only on its first connect
/// would leave a driver restarted underneath it armed with nothing.
///
/// # Why the reply is read and published
///
/// This call is synchronous and its answer is the only place the service ever
/// learns whether the driver *applied* the configuration. `STATUS_SUCCESS` means
/// it did; anything else means a defence the user asked for is not in place, and
/// the two ways that happens — a driver build that cannot parse the message, and
/// a write gate pointed at a directory it will not take — are both worth a
/// sentence a user can read rather than a silence indistinguishable from
/// working protection. The number travels as a
/// [`DriverSubject::Configuration`] event so that `Host::status` can report it
/// beside the driver's own two registration reports, which are the same kind of
/// fact about the same kind of mechanism.
///
/// # Failure to send is not a failure of the connection
///
/// A send that fails at the API level leaves the connection usable — the port is
/// still open and decisions still arrive on it — so this reports the failure and
/// returns. Dropping the connection would take the decision path down over a
/// configuration message, which would make an unreachable defence worse than
/// absent.
#[cfg(windows)]
fn configure(
    port: &windows::Win32::Foundation::HANDLE,
    configuration: &ConfigMessage,
    events: &Sender<Event>,
) {
    use windows::Win32::Storage::InstallableFileSystems::FilterSendMessage;

    // The driver answers with one `NTSTATUS`, four bytes, through the output
    // buffer — see `av-driver`'s `port_message`. Zeroed first so that a driver
    // which somehow reported nothing at all cannot have a previous call's value
    // read as its answer.
    let mut answer: i32 = 0;
    let mut returned: u32 = 0;
    // SAFETY: `configuration` is a live `ConfigMessage` and
    // `ConfigMessage::SIZE` is exactly its size, which is the length passed.
    // `answer` is a live `i32` and four is its size. `returned` is a live `u32`
    // that the call writes the count into; the filter manager requires it to be
    // non-null, which it is.
    let sent = unsafe {
        FilterSendMessage(
            *port,
            core::ptr::from_ref(configuration).cast::<core::ffi::c_void>(),
            ConfigMessage::SIZE as u32,
            Some(core::ptr::from_mut(&mut answer).cast::<core::ffi::c_void>()),
            core::mem::size_of::<i32>() as u32,
            &mut returned,
        )
    };
    let detail = match sent {
        Err(error) => {
            // Not a `Configuration` event: nothing was answered, and a status
            // code invented here would be this service's guess at what a driver
            // that never saw the message would have said.
            log::warn!(
                "the driver could not be sent this product's configuration: {error}. The \
                 connection is still usable, so decisions will go on being answered; what is not \
                 in place is the driver's own defence of this product"
            );
            return;
        }
        // A driver that answered without writing four bytes is a driver this
        // build does not understand. Reported as such rather than read as zero
        // — zero is `STATUS_SUCCESS`, which is the one value that must never be
        // reached by accident.
        Ok(()) if returned != core::mem::size_of::<i32>() as u32 => {
            log::warn!(
                "the driver answered the configuration message with {returned} bytes rather than \
                 the four an NTSTATUS occupies, so whether it applied the configuration is not \
                 known"
            );
            return;
        }
        Ok(()) => answer,
    };
    if detail == 0 {
        log::info!(
            "the driver applied this product's configuration: protect_handles={}, \
             write_gate={}",
            configuration.protect_handles(),
            configuration.gate_writes()
        );
    } else {
        log::warn!(
            "the driver refused this product's configuration with 0x{:08X}; the protections the \
             configuration asked for are not in place",
            detail as u32
        );
    }
    publish(
        events,
        Event::Driver(DriverEvent {
            sequence: 0,
            timestamp_100ns: now_100ns(),
            action: DriverEventAction::StateChanged,
            subject: DriverSubject::Configuration,
            path: None,
            process_id: std::process::id(),
            parent_process_id: 0,
            thread_id: 0,
            detail: detail as u32,
            value: None,
            command_line: None,
            driver_state: None,
        }),
    );
}

/// Open the driver's filter communication port.
#[cfg(windows)]
fn connect(port_name: &str) -> windows::core::Result<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::Storage::InstallableFileSystems::FilterConnectCommunicationPort;
    let name = crate::win32::to_wide_str(port_name);
    // SAFETY: `name` is NUL-terminated and outlives the call. There is no
    // context to carry to the driver and no security attributes to apply, so
    // both are null/zero, which the API documents as "none" — whether this
    // process may connect at all is decided by the port's own DACL, created by
    // the driver.
    unsafe {
        FilterConnectCommunicationPort(windows::core::PCWSTR(name.as_ptr()), 0, None, 0, None)
    }
}

/// The receive buffer, over-aligned for the kernel's probe.
///
/// `FilterGetMessage` writes a `FILTER_MESSAGE_HEADER` at the front of the
/// buffer, and the filter manager probes that address for write access before it
/// copies anything into it. A misaligned buffer fails that probe, so the
/// alignment is part of the call's contract rather than a performance hint — and
/// a `Vec<u8>`, whose type promises nothing beyond byte alignment, would be
/// relying on the allocator's size classes to happen to be right.
#[cfg(windows)]
#[repr(C, align(8))]
struct ReceiveBuffer([u8; RECEIVE_BYTES]);

#[cfg(windows)]
impl ReceiveBuffer {
    /// A zeroed buffer.
    fn zeroed() -> Self {
        Self([0u8; RECEIVE_BYTES])
    }

    /// Clear it, ready for the next message.
    fn clear(&mut self) {
        self.0.fill(0);
    }

    /// The buffer as the header the filter manager writes.
    fn header(&mut self) -> *mut windows::Win32::Storage::InstallableFileSystems::FILTER_MESSAGE_HEADER {
        self.0.as_mut_ptr().cast()
    }

    /// The whole buffer as bytes, for [`received`].
    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// How many messages the receive thread may hand either of the two lanes.
///
/// Large enough that an ordinary burst — a build writing a thousand files, a
/// registry sweep — never makes the receive thread wait, and bounded because
/// the alternative is a queue that grows with whatever the machine is doing.
/// When it does fill, the receive thread blocks on the hand-off and the driver
/// is back to losing ordinary events; that is a machine asking more of the
/// decision path than it can answer, and a bigger queue would only move it.
const INBOX_MESSAGES: usize = 1024;

/// Which of the two lanes a received message belongs on.
///
/// Two, and the split is 2026-10-18's answer to a measured loss. [`serve`] ran
/// one dispatcher thread over one queue, and a decision on that thread blocks
/// for as long as its scan takes — up to [`DECISION_DEADLINE`]. The test VM
/// showed what that costs the other messages: forty registry keys deleted in a
/// tight loop right after boot delivered too few delete events for a
/// thirty-count rule to fire, while the same forty on a warmed-up machine
/// delivered all forty. At boot the machine is asking for decisions on
/// `mpengine.dll` and five OneDrive DLLs, each scan outliving the deadline, so
/// the dispatch thread was inside a scan for most of that minute, the queue
/// filled behind it, and the receive thread stopped receiving.
///
/// So decisions keep the serialised lane they had — one at a time, the design
/// this module documents — and everything else is reported on a thread that
/// never scans and therefore never stops reading.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    /// Work the driver is waiting for an answer to.
    Decide,
    /// A report about something that already happened.
    Events,
}

/// The lane `message` belongs on.
///
/// Exhaustive with no wildcard: a message kind added to [`Received`] stops this
/// build rather than being reported by a guess on the wrong thread.
pub fn lane(message: &Received) -> Lane {
    match message {
        Received::DecisionRequest(_) => Lane::Decide,
        // Cheap and rare, and it is the dispatcher's own state: the same lane
        // as the decisions so that `Dispatcher::reported_status` keeps meaning
        // what it says.
        Received::Status(_) => Lane::Decide,
        Received::Event(_) => Lane::Events,
        Received::Unreadable { .. } => Lane::Events,
        Received::Empty => Lane::Events,
    }
}

/// How often the decision thread looks up from an empty inbox, so that a stop
/// with nothing arriving is still noticed.
const INBOX_POLL: Duration = Duration::from_millis(50);

/// How many threads wait in `FilterGetMessage` at once.
///
/// **One, and a second one is not merely unhelpful — it breaks the port.**
/// Measured in the test VM on 2026-10-18: with two threads waiting on the same
/// port handle, `FilterGetMessage` began returning *success* without writing a
/// message, thousands of times a second. Each empty success is a message this
/// service reads as `kind 0, version 0` and refuses, and the log said so —
/// `service.log` grew from 10.9 MB in seventeen minutes to 6.3 MB in
/// twenty-four seconds the moment that build started. Whatever pairing the
/// filter manager does between a send and a waiting receive is per connection
/// rather than per waiting thread, and a second waiter is answered with
/// nothing.
///
/// Two threads *were* tried because one measured badly: forty registry keys
/// deleted in one tight loop delivered twenty-nine `deleted key` events rather
/// than forty, while the same forty deleted 150 ms apart delivered all forty.
/// That deficit was real and was **not** answered here. It had two causes, both
/// fixed elsewhere on 2026-10-18: the driver sent an ordinary event with a zero
/// timeout, so it was delivered only if a receive was outstanding at that
/// instant (`send_event` in `av-driver/src/lib.rs` now waits a hundred
/// milliseconds), and the one dispatch thread blocked inside decision scans,
/// which is what [`Lane`] splits apart. Forty for forty was measured after
/// both changes.
const RECEIVE_THREADS: usize = 1;

/// Serve one connection until it ends or the service stops.
///
/// # Why receiving and deciding are two threads
///
/// The driver sends every ordinary event — a process start, a registry change,
/// a rename — with a **zero** timeout, and `FltSendMessage` with a zero timeout
/// fails immediately when no receive is outstanding (`av-driver/src/lib.rs`,
/// `send_event`). The failure is the event: it is not queued, not retried and
/// not counted. So an event is delivered only if this process is inside
/// `FilterGetMessage` at the instant the driver sends it, which makes the
/// receive path's occupancy a correctness property rather than a performance
/// one.
///
/// Until 2026-10-18 both halves ran on one thread, and the decision half blocks
/// for as long as the scan it waits for takes — up to `DECISION_DEADLINE`.
/// Measured in the test VM that evening: forty registry keys deleted in one
/// tight loop delivered forty `created key` events and **seventeen**
/// `deleted key` events, because the port thread was scanning for most of the
/// loop. A second run of the same loop delivered twenty-seven. The behaviour
/// engine saw too few deletions for a thirty-count rule to fire, and no amount
/// of rule tuning would have changed that.
///
/// So this thread does nothing but receive and hand over, and what it hands
/// over goes to one of two lanes ([`lane`]): [`serve_messages`] decides, and
/// [`report_events`] reports. The two are separate threads because the same VM
/// measured the same loss again with only the receive half split off — forty
/// deletes in a tight loop one minute after boot still did not reach the
/// thirty-count rule, while the same forty on a warmed-up machine delivered all
/// forty. At boot the decisions in flight are scans of `mpengine.dll` and five
/// OneDrive DLLs, each outliving the deadline, and the single dispatch thread
/// was inside one of them for most of that minute. Decisions still serialise
/// on exactly one thread; what changed is that no other message waits behind
/// them.
///
/// The receive thread ends when the port ends or when both lanes have gone.
/// Its own exit is not waited for: `run` closes the port after this function
/// returns, and the filter manager then completes the receive with an
/// error — the same policy [`crate::host`] applies to this whole client.
#[cfg(windows)]
fn serve(port: &windows::Win32::Foundation::HANDLE, dispatcher: &mut Dispatcher, events: &Sender<Event>, stop: &AtomicBool) {
    let (decisions, deciding) = crossbeam_channel::bounded::<Received>(INBOX_MESSAGES);
    let (notices, reporting) = crossbeam_channel::bounded::<Received>(INBOX_MESSAGES);
    // The reporter first, so that its failure can be answered by sending
    // everything down the decision lane instead — the single-threaded behaviour
    // this split replaces, which loses events under load but never loses a
    // decision. `None` is that fallback.
    let reporter = events.clone();
    let notices = match std::thread::Builder::new()
        .name("wenle-av-filter-events".to_string())
        .spawn(move || report_events(&reporting, &reporter))
    {
        Ok(_) => Some(notices),
        Err(error) => {
            log::error!(
                "the filter port event thread could not be started ({error}); driver events will \
                 be reported behind decisions, which is where they stopped arriving on 10-18"
            );
            None
        }
    };
    // The handle as a number: `HANDLE` is not `Send` and the receive threads
    // need a copy rather than the borrow. Nothing closes it while they can
    // still use it — `run` closes it only after this returns.
    let raw = port.0 as isize;
    let mut waiting = 0;
    for index in 0..RECEIVE_THREADS {
        let inbox = decisions.clone();
        let notices = notices.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("wenle-av-filter-receive-{index}"))
            .spawn(move || receive_until_the_port_ends(raw, inbox, notices.as_ref()));
        match spawned {
            Ok(_) => waiting += 1,
            // The same failure `start_on` handles the same way: the driver
            // allows what it cannot get an answer for, so one fewer waiting
            // thread is a narrower window rather than a reason to give the
            // connection up. The send below drops the extra sender clone.
            Err(error) => log::error!(
                "filter port receive thread {index} of {RECEIVE_THREADS} could not be started: \
                 {error}"
            ),
        }
    }
    if waiting == 0 {
        // Not one could be created: the connection is up and nobody is
        // listening, so end it and let `run` try again rather than hold a port
        // that will never answer.
        log::error!(
            "no filter port receive thread could be started; closing the connection to the \
             driver"
        );
        return;
    }
    drop(decisions);
    drop(notices);
    serve_messages(port, &deciding, dispatcher, events, stop);
}

/// Receive until the connection ends, handing every message to its lane.
///
/// This thread never scans, never replies, and logs nothing between receives:
/// every microsecond it spends doing anything else is a microsecond in which
/// the driver's send finds no receive outstanding. See [`serve`].
///
/// `notices` is `None` when the reporting thread could not be started; every
/// message then goes down the decision lane, which is the pre-split behaviour.
#[cfg(windows)]
fn receive_until_the_port_ends(
    port: isize,
    decisions: Sender<Received>,
    notices: Option<&Sender<Received>>,
) {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::InstallableFileSystems::FilterGetMessage;
    let port = HANDLE(port as *mut core::ffi::c_void);
    let mut buffer = ReceiveBuffer::zeroed();
    loop {
        // Cleared before every receive rather than after: the filter manager
        // does not report how long the message it wrote is, so a byte it did
        // *not* write has to read as zero rather than as the tail of the
        // previous message. Without this, a stale `path_units` would be read as
        // the length of this message's path — a decision about a file named by
        // a mixture of two messages.
        buffer.clear();
        // SAFETY: `buffer` is alive for the call, is exactly `RECEIVE_BYTES`
        // long and 8-aligned as the filter manager's write probe requires, and
        // no `OVERLAPPED` is passed, so the call is synchronous and the buffer
        // is not touched after it returns.
        let outcome = unsafe {
            FilterGetMessage(port, buffer.header(), RECEIVE_BYTES as u32, None)
        };
        if let Err(error) = outcome {
            let code = crate::win32::code(&error);
            if is_connection_over(code) {
                log::info!("receiving from the filter port ended ({code})");
            } else if code == ERROR_INSUFFICIENT_BUFFER {
                // Unreachable while `RECEIVE_BYTES` is the largest message the
                // protocol defines. It has its own sentence because the cause
                // would be a constant in this file rather than anything the
                // driver did, and "the receive buffer is too small" is a
                // different search from "the driver failed".
                log::error!(
                    "a message was larger than the {RECEIVE_BYTES}-byte receive buffer; the buffer \
                     is too small for this protocol"
                );
            } else {
                log::warn!("receiving from the filter port failed: {error}");
            }
            return;
        }
        let message = received(buffer.bytes());
        let routed = match (lane(&message), notices) {
            (Lane::Events, Some(notices)) => notices.send(message),
            _ => decisions.send(message),
        };
        if routed.is_err() {
            // The thread that lane belongs to has gone, so there is nothing
            // left to decide or report, and no one to answer.
            return;
        }
    }
}

/// Report the messages that are not decisions, on their own thread.
///
/// Nothing here can block: `driver::translate` copies fields and [`publish`]
/// hands the event to a channel. That is the point of the lane — see [`serve`]
/// for the measurement that made events stop arriving behind a scan.
#[cfg(windows)]
fn report_events(messages: &Receiver<Received>, events: &Sender<Event>) {
    // One warning per connection: the driver reconnects when the service does,
    // so a mismatch that is still there is said once each time rather than on
    // every event -- which on a busy machine would be thousands a second.
    let mut warned_about_mismatch = false;
    // Counted, not logged per message: see the Received::Empty arm.
    let mut empty_receives: u64 = 0;
    loop {
        // No stop flag: this thread ends when the receive thread drops the last
        // sender, which happens when the port ends or the service stops, and
        // the two are the same event from here.
        let message = match messages.recv() {
            Ok(message) => message,
            Err(_) => return,
        };
        match message {
            Received::Event(event) => publish(events, Event::Driver(driver::translate(&event))),
            // A version mismatch is the one refusal that means this product is
            // running blind: the driver's events are all being dropped, so the
            // behaviour rules see nothing and the driver's own status is never
            // recorded. Measured on 2026-10-23 -- a service one protocol version
            // ahead of the driver in the test VM dropped every event for two
            // rounds of testing, and nothing but a debug line said so.
            Received::Unreadable { reason, mismatch } => match mismatch {
                Some((driver, build)) if !warned_about_mismatch => {
                    warned_about_mismatch = true;
                    log::warn!(
                        "the driver speaks protocol version {driver} and this build speaks {build}: \
                         every event the driver sends is being dropped, so behaviour protection is \
                         not running and the driver's status is not being recorded. Install the \
                         service and the driver from the same build. Further messages of this kind \
                         are logged at debug."
                    );
                }
                _ => log::debug!("a driver message was ignored: {reason}"),
            },
            // [`lane`] puts these on the decision lane. A message here is a
            // defect in that function, and it is said rather than decided on a
            // thread that holds no engine.
            // A receive that returned success without writing a message. Known,
            // and harmless: the buffer is what this process cleared, so nothing
            // was overwritten and no decision can be about it. Said once per
            // connection, because a port answering with empty successes
            // thousands of times a second is the shape of the two-waiter defect
            // `RECEIVE_THREADS` records.
            Received::Empty => {
                empty_receives += 1;
                if empty_receives == 1 {
                    log::debug!(
                        "the filter manager returned success without a message; this is the \
                         empty-success case and not a driver message. Further ones are counted \
                         silently."
                    );
                }
            }
            Received::DecisionRequest(_) | Received::Status(_) => {
                log::error!("a decision message reached the event thread; it was not answered")
            }
        }
    }
}

/// Decide the messages the receive thread hands over on the decision lane, and
/// answer the driver.
///
/// Only [`Lane::Decide`] messages arrive here; the rest are reported by
/// [`report_events`]. What this loop blocks on — one scan at a time, up to
/// `DECISION_DEADLINE` — is therefore no longer in front of anything else.
///
/// `stop` is checked between messages and not during one; see this module's
/// documentation for why that window cannot be closed.
#[cfg(windows)]
fn serve_messages(
    port: &windows::Win32::Foundation::HANDLE,
    messages: &Receiver<Received>,
    dispatcher: &mut Dispatcher,
    events: &Sender<Event>,
    stop: &AtomicBool,
) {
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let message = match messages.recv_timeout(INBOX_POLL) {
            Ok(message) => message,
            Err(RecvTimeoutError::Timeout) => continue,
            // The receive thread has ended: the connection is over.
            Err(RecvTimeoutError::Disconnected) => return,
        };
        match dispatcher.handle(message) {
            Action::Reply(reply) => reply_to_driver(*port, reply),
            Action::ReplyAndReport(reply, detection) => {
                // The order matters, and it is not the obvious one. The driver
                // is sitting inside its own timeout, so the earlier the answer
                // goes back the less of that timeout is spent — and, when the
                // answer is a refusal, the file is held open by the kernel for
                // exactly as long as this reply is outstanding. Reporting first
                // would put a vault write between the scan and the answer, on a
                // path every program launch passes through.
                //
                // The answer goes back first whether or not it is a refusal.
                // The allow-and-report case below has no file held open, but the
                // driver is still waiting, and a reply that arrives while the
                // service is writing a vault record is a reply that arrives
                // late.
                let request_id = reply.request_id;
                let path_tag = reply.path_tag;
                let stopped = detection.claims_a_block();
                reply_to_driver(*port, reply);
                log::info!(
                    "the driver's {} on request {request_id} (path tag {path_tag}) is being \
                     reported to the service",
                    if stopped { "block" } else { "conviction" }
                );
                publish(events, Event::Detection(*detection));
            }
            Action::Publish(event) => publish(events, Event::Driver(event)),
            Action::Ignored(reason) => log::debug!("a driver message was ignored: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_driver_proto::event::{EventAction, SubjectKind};
    use av_rules::database::RuleDatabase;
    use std::time::Instant;

    /// A dispatcher over an engine with no rules.
    fn dispatcher() -> Dispatcher {
        dispatcher_over(RuleDatabase::compile("").0, DECISION_DEADLINE)
    }

    /// A dispatcher over an engine with one rule that matches `needle`.
    ///
    /// `severity = "high"` on purpose: one High indicator reaches
    /// [`Verdict::Malicious`], and only a confirmed verdict is blocked. A rule
    /// with no severity lands in the yellow band, where the product warns and
    /// never acts — which is what
    /// `only_the_red_band_blocks_and_the_yellow_band_never_does` is about, so
    /// the severity here has to be the one that *would* be blocked for the
    /// blocking tests to mean anything.
    fn dispatcher_matching(needle: &str) -> Dispatcher {
        dispatcher_over(rules_matching(needle), DECISION_DEADLINE)
    }

    /// The database [`dispatcher_matching`] describes, for the tests that need
    /// the event channel as well as the dispatcher.
    fn rules_matching(needle: &str) -> RuleDatabase {
        let source = format!(
            "rule Test_Finds_Marker {{\n  meta:\n    severity = \"high\"\n  strings:\n    \
             $a = \"{needle}\"\n  condition:\n    $a\n}}\n"
        );
        let database = RuleDatabase::compile(&source).0;
        assert_eq!(database.len(), 1, "the rule must compile");
        database
    }

    /// A dispatcher over `database` whose scans are allowed `deadline`.
    fn dispatcher_over(database: RuleDatabase, deadline: Duration) -> Dispatcher {
        dispatcher_watching(database, deadline).0
    }

    /// The same, with the channel its detections arrive on kept.
    ///
    /// Dropping the receiving end is what the callers above do, and it is not a
    /// loss: a detection sent to a channel nobody holds is a send that fails,
    /// which is a debug line, and those tests are about the reply. It is here
    /// because the *late* half of a decision has no reply — the detection is
    /// the whole of what it produces — so a test of it has to watch.
    fn dispatcher_watching(
        database: RuleDatabase,
        deadline: Duration,
    ) -> (Dispatcher, Receiver<Event>) {
        dispatcher_allowing(database, deadline, AllowList::new())
    }

    /// The same, over a dispatcher that has been told to allow something.
    ///
    /// The set is taken by value and a clone is a handle to the *same* set, so a
    /// caller that keeps one can insert into it while the dispatcher is live.
    /// That is the interesting test — not that a seeded path is skipped, which
    /// would pass even if nothing could ever be added at run time, but that
    /// adding one changes what the dispatcher does. It is the path the user's
    /// button takes.
    fn dispatcher_allowing(
        database: RuleDatabase,
        deadline: Duration,
        allow: AllowList,
    ) -> (Dispatcher, Receiver<Event>) {
        dispatcher_allowing_in(
            database,
            deadline,
            allow,
            elsewhere(),
        )
    }

    /// A layout that is nowhere near anything the tests use.
    ///
    /// [`Dispatcher::decide`] answers a path inside the product's own tree
    /// without scanning it, and every fixture in this module writes to a
    /// temporary directory. A real [`AvPaths`] here would therefore be a
    /// dispatcher whose own-tree check is *true* for exactly the paths under
    /// test, and each blocking test would pass while testing the new branch
    /// instead of the one it names. Two paths that cannot exist keep that
    /// impossible. The check itself is exercised by
    /// `a_file_of_ours_is_allowed_without_being_scanned`, which supplies a real
    /// one.
    fn elsewhere() -> AvPaths {
        AvPaths::with_data_dir(
            PathBuf::from(r"C:\wenle-no-such-install-dir"),
            PathBuf::from(r"C:\wenle-no-such-data-dir"),
        )
    }

    /// The same, over a layout chosen by the caller.
    fn dispatcher_allowing_in(
        database: RuleDatabase,
        deadline: Duration,
        allow: AllowList,
        own_tree: AvPaths,
    ) -> (Dispatcher, Receiver<Event>) {
        let (events, published) = crossbeam_channel::unbounded::<Event>();
        let engine = Arc::new(ScanEngine::new(database));
        (
            Dispatcher::on_a_deadline(engine, events, deadline, allow, own_tree),
            published,
        )
    }

    /// Every message kind reaches the lane that serves it.
    ///
    /// The routing is the whole of the 2026-10-18 split: a decision arriving on
    /// the reporting lane is dropped with an error, and an event that reached
    /// the decision lane is behind a scan again. [`lane`] is exhaustive, so
    /// what this test pins is the four answers rather than a default.
    #[test]
    fn every_message_kind_takes_the_lane_that_serves_it() {
        use av_driver_proto::wire::{EventMessage, StatusMessage};

        let request = request_for(r"C:\Windows\notepad.exe");
        assert_eq!(lane(&Received::DecisionRequest(request)), Lane::Decide);
        assert_eq!(
            lane(&Received::Status(StatusMessage::new(DriverStatus::default()))),
            Lane::Decide
        );
        let event = EventMessage::new(1, 0, SubjectKind::Process, EventAction::ProcessStarted);
        assert_eq!(lane(&Received::Event(event)), Lane::Events);
        assert_eq!(
            lane(&Received::Unreadable {
                reason: "a message this build cannot read".to_string(),
                mismatch: None,
            }),
            Lane::Events
        );
    }

    /// The bytes of a protocol structure, for feeding the reader under test.
    ///
    /// Every structure this protocol defines is a `repr(C)` aggregate of
    /// integers and fixed arrays whose constructors zero the whole of it, so
    /// every byte here is initialised and the size is the structure's own.
    fn bytes_of<T: Copy>(value: &T) -> Vec<u8> {
        // SAFETY: the slice is exactly one `T` starting at the value's address,
        // and `T` is a plain aggregate whose bytes are all initialised by the
        // constructors in `av_driver_proto::wire`.
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!(*value).cast::<u8>(),
                core::mem::size_of::<T>(),
            )
        }
        .to_vec()
    }

    /// A path as the driver puts one on the wire: UTF-16, with no terminator.
    ///
    /// Deliberately not `crate::win32::to_wide_str`, which appends the NUL a
    /// `PCWSTR` needs. The protocol's path field is a *used length* with no
    /// terminator — `av_driver_proto::path::device_to_dos_path`, which is where
    /// the driver's path comes from, refuses an embedded NUL and writes nothing
    /// past the end — so a test built with the NUL-terminated form would be
    /// feeding itself a message the driver never sends, and would be asserting
    /// about a path with a trailing NUL in it that Windows happens to truncate.
    fn wire_path(path: &str) -> Vec<u16> {
        path.encode_utf16().collect()
    }

    /// A request for `path`, as the driver would send it.
    ///
    /// The subject is the create gate's — an open asking `FILE_EXECUTE`. That is
    /// the gate most of these tests want, because it is the one that asks about
    /// everything; the tests that care which gate asked say so with
    /// [`section_request_for`].
    fn request_for(path: &str) -> DecisionRequestMessage {
        let mut request = DecisionRequestMessage::new(7, SubjectKind::Process);
        request
            .set_path(&wire_path(path))
            .expect("the test path fits the protocol's path field");
        request
    }

    /// The same, from the acquire-for-section pre-operation — the only gate
    /// allowed to refuse.
    fn section_request_for(path: &str) -> DecisionRequestMessage {
        let mut request = DecisionRequestMessage::new(7, SubjectKind::Image);
        request
            .set_path(&wire_path(path))
            .expect("the test path fits the protocol's path field");
        request
    }

    #[test]
    fn the_receive_buffer_holds_the_largest_message_the_protocol_defines() {
        // The fault this guards is silent and total: a buffer sized for a
        // decision request makes every event the driver sends fail with
        // ERROR_INSUFFICIENT_BUFFER, so the first heartbeat ends the connection
        // and the driver goes back to blocking nothing while the service reports
        // itself healthy. Written as "the widest of them" rather than as three
        // separate comparisons so that a message added to the protocol later is
        // one more entry here rather than a fourth assertion somebody has to
        // remember to write.
        let widest = [
            EventMessage::SIZE,
            DecisionRequestMessage::SIZE,
            StatusMessage::SIZE,
        ]
        .into_iter()
        .max()
        .expect("the protocol defines at least one message");
        assert_eq!(RECEIVE_BYTES, widest);
    }

    #[test]
    fn a_receive_that_wrote_nothing_is_its_own_answer_and_not_a_refusal() {
        // The zeroed buffer is what a receive that wrote nothing looks like.
        // `MessagePrefix::default` is kind 0, version 0, and no sender produces
        // it -- so this is the filter manager's empty success, not a message
        // this build failed to understand. Telling them apart matters: the
        // first is a documented Windows behaviour that needs no investigation,
        // and the second was read as "a message this build cannot read" for a
        // day, which sent the search toward a protocol bug that did not exist
        // (test VM, 2026-10-23 20:56).
        assert!(matches!(received(&[0u8; 64]), Received::Empty));
        // A buffer too short to hold a prefix is still a refusal: there is not
        // enough there to tell the two apart.
        assert!(matches!(received(&[]), Received::Unreadable { .. }));
        assert!(matches!(
            received(&[0u8; 8]),
            Received::Unreadable { .. }
        ));
    }

    #[test]
    fn a_message_shorter_than_its_own_structure_is_refused() {
        // A prefix that says "decision request" followed by nothing is a
        // truncated write or a protocol change; reading the structure anyway
        // would decide about a path built out of whatever followed in memory.
        let mut bytes = bytes_of(&request_for(r"C:\Windows\System32\cmd.exe"));
        bytes.truncate(MessagePrefix::SIZE + 4);
        match received(&bytes) {
            Received::Unreadable { reason, mismatch } => {
                assert!(reason.contains("truncated"), "{reason}");
                assert_eq!(mismatch, None, "a truncation is not a version mismatch");
            }
            other => panic!("a truncated request was not refused: {other:?}"),
        }
    }

    #[test]
    fn a_known_kind_at_another_builds_version_is_not_decoded() {
        // The version check has to happen before the body is read: a build that
        // decoded first would already have read one build's bytes as another's.
        let mut request = request_for(r"C:\Windows\System32\cmd.exe");
        request.prefix.version = av_driver_proto::PROTOCOL_VERSION + 1;
        match received(&bytes_of(&request)) {
            Received::Unreadable { reason, mismatch } => {
                assert!(reason.contains("version"), "{reason}");
                // And the versions are carried, because a mismatch is what the
                // event thread raises to a warning: dropping every event of a
                // peer is not a debug-level fact.
                assert_eq!(
                    mismatch,
                    Some((av_driver_proto::PROTOCOL_VERSION + 1, av_driver_proto::PROTOCOL_VERSION))
                );
            }
            other => panic!("a message from another build was decoded: {other:?}"),
        }
    }

    #[test]
    fn an_unknown_kind_is_dropped_with_a_reason_and_never_guessed() {
        // A driver built against a later protocol sends a kind this build has
        // never heard of. The failure to avoid is reading it as the nearest one.
        let mut request = request_for(r"C:\Windows\System32\cmd.exe");
        request.prefix.kind = 9_999;
        match received(&bytes_of(&request)) {
            Received::Unreadable { reason, mismatch } => {
                assert!(reason.contains("9999"), "{reason}");
                assert_eq!(mismatch, None, "an unknown kind is not a version mismatch");
            }
            other => panic!("an unknown kind was read as a message: {other:?}"),
        }
    }

    #[test]
    fn a_decision_request_survives_the_byte_path() {
        // The reader is the only place bytes become a structure, so the round
        // trip is the one property everything else here rests on.
        let request = request_for(r"C:\Windows\System32\cmd.exe");
        match received(&bytes_of(&request)) {
            Received::DecisionRequest(read) => {
                assert_eq!(read.request_id, request.request_id);
                assert_eq!(read.path(), request.path());
                assert_eq!(read.path_tag(), request.path_tag());
            }
            other => panic!("a decision request did not survive: {other:?}"),
        }
    }

    #[test]
    fn an_event_survives_the_byte_path_and_reaches_the_products_vocabulary() {
        let mut event = EventMessage::new(
            11,
            133_000_000_000_000_000,
            SubjectKind::Process,
            EventAction::ExecutionBlocked,
        );
        event
            .set_path(&wire_path(r"C:\Users\me\payload.exe"))
            .expect("the test path fits the protocol's path field");
        let mut dispatcher = dispatcher();
        match dispatcher.handle(received(&bytes_of(&event))) {
            Action::Publish(translated) => {
                assert_eq!(translated.sequence, 11);
                assert_eq!(translated.action, DriverEventAction::ExecutionBlocked);
                assert_eq!(translated.subject, DriverSubject::Process);
                assert_eq!(
                    translated.path,
                    Some(PathBuf::from(r"C:\Users\me\payload.exe"))
                );
            }
            other => panic!("an event was not published: {other:?}"),
        }
    }

    #[test]
    fn a_status_message_is_recorded_rather_than_answered() {
        // A status is the driver talking about itself. Answering it would be a
        // reply to a message that asked nothing, and dropping it would lose the
        // only account the product has of how the driver is doing.
        let driver = DriverStatus {
            state: av_driver_proto::event::DriverState::Running.as_wire(),
            decisions_asked: 40,
            decisions_answered: 39,
            decisions_unanswered: 1,
            ..DriverStatus::default()
        };
        let status = StatusMessage::new(driver);
        let mut dispatcher = dispatcher();
        let action = dispatcher.handle(received(&bytes_of(&status)));
        match action {
            Action::Ignored(reason) => {
                assert!(reason.contains("40"), "{reason}");
                assert!(reason.contains("Running"), "{reason}");
            }
            other => panic!("a status message was answered: {other:?}"),
        }
        let recorded = dispatcher
            .reported_status()
            .expect("the status was recorded");
        assert_eq!(recorded.decisions_asked, 40);
        assert_eq!(recorded.decisions_unanswered, 1);
    }

    #[test]
    fn the_reply_echoes_the_identifiers_the_driver_discards_on() {
        // The driver drops any reply whose `request_id` or `path_tag` does not
        // match the request it is waiting on, so a reply that gets either wrong
        // is a reply that is thrown away and a program that runs.
        let request = request_for(r"C:\Windows\System32\cmd.exe");
        let reply = reply_for(&request, Decision::Block);
        assert_eq!(reply.request_id, request.request_id);
        assert_eq!(reply.subject, request.subject);
        assert_eq!(reply.path_tag, request.path_tag());
        assert_eq!(reply.decision, Decision::Block.as_wire());
        assert_eq!(reply.reply.status, av_driver_proto::wire::PortReplyHeader::STATUS_SUCCESS);
    }

    #[test]
    fn the_reply_carries_the_filter_managers_own_message_id() {
        // The trap this guards: `answering` fills in the product's identifiers
        // and leaves the port header's `MessageId` at zero, because the port's
        // header is not the product's protocol. A reply whose `MessageId` matches
        // no outstanding receive is not delivered at all — the driver waits out
        // its timeout and allows the file — which looks exactly like the whole
        // feature being unwired, and would be found only by watching a malicious
        // program run.
        let mut request = request_for(r"C:\Windows\System32\cmd.exe");
        request.prefix.header.message_id = 0x2A;
        assert_eq!(
            DecisionReplyMessage::answering(&request, Decision::Allow)
                .reply
                .message_id,
            0,
            "if the protocol crate ever fills this in, the copy below is redundant rather than wrong"
        );
        assert_eq!(reply_for(&request, Decision::Block).reply.message_id, 0x2A);
    }

    #[test]
    fn only_the_red_band_blocks_and_the_yellow_band_never_does() {
        // The product rule, exhaustively: `Verdict::blocks` is the single
        // predicate, the yellow band warns and never acts, and an unknown
        // verdict is not evidence. A second opinion here — "suspicious is
        // suspicious, better safe" — would be a second policy, and it would
        // block files on a heuristic.
        assert_eq!(verdict_to_decision(Verdict::Malicious), Decision::Block);
        for verdict in [Verdict::Clean, Verdict::Suspicious, Verdict::Unknown] {
            assert_eq!(
                verdict_to_decision(verdict),
                Decision::Allow,
                "{verdict:?} is not a reason to stop a program"
            );
        }
    }

    #[test]
    fn the_section_gate_blocks_a_detection_and_allows_a_clean_file() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let bad = dir.path().join("bad.bin");
        std::fs::write(&bad, b"MALWARE_MARKER_FOR_THE_TEST").expect("the fixture is written");
        let good = dir.path().join("good.bin");
        std::fs::write(&good, b"nothing to see here").expect("the fixture is written");

        let mut dispatcher = dispatcher_matching("MALWARE_MARKER_FOR_THE_TEST");
        let blocked = dispatcher.handle(received(&bytes_of(&section_request_for(
            bad.to_str().expect("the fixture path is UTF-8"),
        ))));
        match blocked {
            // `ReplyAndReport`, not `Reply`: a refusal is the one answer that
            // carries a detection, because a file the driver would not let run
            // is the only thing here worth telling the user about.
            Action::ReplyAndReport(reply, detection) => {
                assert_eq!(reply.decision, Decision::Block.as_wire());
                // The three things the notification will be built from, and the
                // ones a mistake here would make a lie rather than a
                // disappointment: the file it is about, that the driver stopped
                // it, and that whatever happens to the file next has not
                // happened yet.
                assert_eq!(detection.path, bad);
                assert_eq!(detection.source, EntrySource::Driver);
                assert_eq!(detection.action, DetectionAction::Reported);
                assert!(
                    detection.claims_a_block(),
                    "a refusal has to read as one, or the toast says the program ran"
                );
            }
            other => panic!("a detection was not answered and reported: {other:?}"),
        }

        let allowed = dispatcher.handle(received(&bytes_of(&section_request_for(
            good.to_str().expect("the fixture path is UTF-8"),
        ))));
        match allowed {
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("a clean file was not answered: {other:?}"),
        }
    }

    #[test]
    fn the_create_gate_reports_a_detection_without_refusing_it() {
        // The create gate asks about an open carrying `FILE_EXECUTE`, and that
        // mask also answers to `FILE_TRAVERSE` and to the read-only image maps
        // Explorer makes to draw an icon — so it asks about a great deal that is
        // not about to run. Refusing on that evidence quarantines a file for
        // having been *copied* (measured 2026-10-01), which is why it no longer
        // does. See [`refusing_gate`].
        //
        // **Our driver stopped sending this subject entirely on 2026-10-15**,
        // because an answer it can never act on is not worth the port thread's
        // time. The dispatcher still has to answer it correctly: a driver that
        // does send it must get a `Decision` it can use *and* a detection that
        // reaches the vault. That is the whole of the 2026-10-15 fix — before
        // it, this arm returned `None`, so about sixty convictions in the
        // 2026-10-14 WannaCry log were log lines and nothing else.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let bad = dir.path().join("bad.bin");
        std::fs::write(&bad, b"MALWARE_MARKER_FOR_THE_TEST").expect("the fixture is written");

        let mut dispatcher = dispatcher_matching("MALWARE_MARKER_FOR_THE_TEST");
        let answered = dispatcher.handle(received(&bytes_of(&request_for(
            bad.to_str().expect("the fixture path is UTF-8"),
        ))));
        match answered {
            // `ReplyAndReport` since 2026-10-15, and the two halves pull in
            // opposite directions on purpose: `Allow` because this gate cannot
            // refuse, and a detection because the file is a conviction and has
            // to be taken. The assertions below are the ones that keep those
            // two from being confused for each other on the way out.
            Action::ReplyAndReport(reply, detection) => {
                assert_eq!(
                    reply.decision,
                    Decision::Allow.as_wire(),
                    "a conviction from the create gate must not stop the open"
                );
                assert_eq!(detection.path, bad);
                assert_eq!(detection.source, EntrySource::Driver);
                assert_eq!(detection.action, DetectionAction::Reported);
                assert!(
                    !detection.claims_a_block(),
                    "the driver was told `Allow`, so a finding claiming a block would put a \
                     \"was stopped\" sentence on a program that was not stopped"
                );
            }
            other => panic!("a conviction from the create gate was not reported: {other:?}"),
        }
    }

    #[test]
    fn the_deadline_leaves_the_driver_room_to_hear_the_answer() {
        // The deadline is the whole reason the scan left this thread, so the
        // relationship it is derived from is asserted rather than described:
        // lowering the driver's wait, or widening the headroom, would otherwise
        // be a silent way to make every decision in the product late — and the
        // symptom of that is the driver's own `decisions_unanswered`, which no
        // test here can see.
        assert_eq!(
            DECISION_DEADLINE + REPLY_HEADROOM,
            Duration::from_millis(u64::from(DecisionPolicy::DEFAULT_TIMEOUT_MS)),
            "the deadline has to be the driver's own wait less the headroom, not a second number \
             chosen beside it"
        );
        assert!(
            DECISION_DEADLINE >= Duration::from_secs(1),
            "a deadline this short would answer every file without scanning it"
        );
    }

    #[test]
    fn a_scan_that_outlives_the_deadline_is_allowed_now_and_convicted_afterwards() {
        // The defect, measured rather than imagined: the scan is allowed
        // `5 s + size / 1 MiB` and the driver waits five, so a file of a
        // megabyte or more could be answered after the driver had stopped
        // waiting — `ERROR_FLT_NO_WAITER_FOR_REPLY`, `0x801F0020`, once per
        // large file in the field logs. A deadline of zero is how a test says
        // "this scan has certainly not finished": the port thread can only time
        // out, and it has to answer anyway.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let bad = dir.path().join("bad.bin");
        std::fs::write(&bad, b"MALWARE_MARKER_FOR_THE_TEST").expect("the fixture is written");
        let path = bad.to_str().expect("the fixture path is UTF-8").to_string();

        let (mut dispatcher, published) =
            dispatcher_watching(rules_matching("MALWARE_MARKER_FOR_THE_TEST"), Duration::ZERO);

        match dispatcher.handle(received(&bytes_of(&section_request_for(&path)))) {
            // Answered, and allowed: only a scan that finished inside the
            // driver's patience can refuse.
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("a scan past the deadline was not answered at once: {other:?}"),
        }

        // And the conviction is not thrown away with the reply. It arrives as a
        // detection, and it says what happened rather than what was intended:
        // the driver had already allowed the file, so nothing blocked it.
        match published.recv_timeout(Duration::from_secs(5)) {
            Ok(Event::Detection(detection)) => {
                assert_eq!(detection.path, bad);
                assert_eq!(detection.source, EntrySource::Driver);
                assert_eq!(detection.action, DetectionAction::Reported);
                assert_eq!(detection.verdict, Verdict::Malicious);
                assert!(
                    !detection.claims_a_block(),
                    "the driver had already allowed this file, so a detection claiming a block \
                     would be a notification about a program that ran"
                );
            }
            Ok(other) => panic!("something other than a detection was published: {other:?}"),
            Err(error) => panic!("the late conviction was never reported: {error}"),
        }
    }

    #[test]
    fn a_second_decision_does_not_wait_for_the_first_files_scan() {
        // The second consequence of scanning inside the receive loop, and the
        // one that made a *small* file time out: `OneDriveStandaloneUpdater.exe`
        // came back `0x801F0020` in the field, behind whatever large file the
        // service was scanning at the time. Two requests with a deadline of zero
        // are both answered at once, which is the property — the second is not
        // made to wait for the first file's scan.
        //
        // What this does *not* show is two workers scanning at the same instant:
        // that is what [`SCAN_WORKERS`] is for and it is not observable from
        // here without a fixture that takes seconds to scan.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let first = dir.path().join("first.bin");
        std::fs::write(&first, b"MALWARE_MARKER_FOR_THE_TEST").expect("the fixture is written");
        let second = dir.path().join("second.bin");
        std::fs::write(&second, b"MALWARE_MARKER_FOR_THE_TEST").expect("the fixture is written");

        let (mut dispatcher, published) =
            dispatcher_watching(rules_matching("MALWARE_MARKER_FOR_THE_TEST"), Duration::ZERO);

        for path in [&first, &second] {
            let request = section_request_for(path.to_str().expect("the fixture path is UTF-8"));
            match dispatcher.handle(received(&bytes_of(&request))) {
                Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
                other => panic!("a scan past the deadline was not answered at once: {other:?}"),
            }
        }

        // Both files are convicted, each by its own scan: one detection per
        // request, naming its own file, and neither claiming a block.
        let mut convicted = Vec::new();
        for _ in 0..2 {
            match published.recv_timeout(Duration::from_secs(5)) {
                Ok(Event::Detection(detection)) => convicted.push(detection),
                Ok(other) => panic!("something other than a detection was published: {other:?}"),
                Err(error) => panic!("one of the two late convictions was never reported: {error}"),
            }
        }
        convicted.sort_by(|left, right| left.path.cmp(&right.path));
        assert_eq!(convicted[0].path, first);
        assert_eq!(convicted[1].path, second);
        assert!(convicted.iter().all(|detection| !detection.claims_a_block()));
    }

    #[test]
    fn a_clean_file_scanned_past_the_deadline_is_reported_as_nothing() {
        // The late path reports convictions and only convictions. A file slow
        // enough to miss the deadline is a large file, not a finding, and a
        // detection per large binary on the machine would be the notification
        // spam this path exists to avoid.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let good = dir.path().join("good.bin");
        std::fs::write(&good, b"nothing to see here").expect("the fixture is written");
        let path = good.to_str().expect("the fixture path is UTF-8").to_string();

        let (mut dispatcher, published) =
            dispatcher_watching(rules_matching("MALWARE_MARKER_FOR_THE_TEST"), Duration::ZERO);
        match dispatcher.handle(received(&bytes_of(&section_request_for(&path)))) {
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("a scan past the deadline was not answered at once: {other:?}"),
        }

        // The wait below is only evidence if it outlasts the scan it is about,
        // so the same file is scanned once more — with a dispatcher whose
        // deadline is the real one — and that round trip is timed. The
        // abandoned scan got the same work and started earlier; the window is
        // several times what a complete scan and reply take.
        let (mut prompt, _unused) = dispatcher_watching(
            rules_matching("MALWARE_MARKER_FOR_THE_TEST"),
            DECISION_DEADLINE,
        );
        let started = Instant::now();
        match prompt.handle(received(&bytes_of(&section_request_for(&path)))) {
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("a clean file was not answered: {other:?}"),
        }
        let round_trip = started.elapsed();
        assert!(
            round_trip < Duration::from_millis(500),
            "the fixture took {round_trip:?} to scan and answer, which makes the wait below \
             meaningless"
        );
        assert!(
            matches!(
                published.recv_timeout(round_trip * 4 + Duration::from_millis(500)),
                Err(RecvTimeoutError::Timeout)
            ),
            "a clean scan past the deadline was reported as a detection"
        );
    }

    #[test]
    fn a_file_that_cannot_be_examined_is_allowed_rather_than_blocked() {
        // The fail-open rule, on the path where it costs something: a file the
        // engine cannot open is a file nothing is known about, and the answer is
        // still yes. A machine where the antivirus refuses what it cannot read is
        // a machine whose user turns it off.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let missing = dir.path().join("not-there.bin");
        let mut dispatcher = dispatcher_matching("MALWARE_MARKER_FOR_THE_TEST");
        match dispatcher.handle(received(&bytes_of(&request_for(
            missing.to_str().expect("the fixture path is UTF-8"),
        )))) {
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("an unreadable file was not answered: {other:?}"),
        }
    }

    /// A file the user has allowed is not scanned, so it is never convicted,
    /// never refused and never reported.
    ///
    /// The first half is a positive control, and it is the half that makes the
    /// second mean anything: the *same* dispatcher over the *same* file refuses
    /// it while the allow set is empty. Without that, this test would pass
    /// against a dispatcher whose engine had simply failed to compile a rule.
    #[test]
    fn an_allowed_path_is_not_scanned_and_not_reported() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let bad = dir.path().join("bad.bin");
        std::fs::write(&bad, b"MALWARE_MARKER_FOR_THE_TEST").expect("the fixture is written");
        let text = bad.to_str().expect("the fixture path is UTF-8");

        let allow = AllowList::new();
        let (mut dispatcher, _published) = dispatcher_allowing(
            rules_matching("MALWARE_MARKER_FOR_THE_TEST"),
            DECISION_DEADLINE,
            allow.clone(),
        );

        // The control: convicted and refused, with nothing allowed yet.
        match dispatcher.handle(received(&bytes_of(&section_request_for(text)))) {
            Action::ReplyAndReport(reply, _) => {
                assert_eq!(reply.decision, Decision::Block.as_wire())
            }
            other => panic!("the fixture was not convicted, so this proves nothing: {other:?}"),
        }

        // What the window's "Allow" does: add the path to a set the dispatcher
        // is already holding a handle to. Nothing is restarted in between, so
        // if the two threads were not sharing one set this would still block.
        assert!(allow.insert(&bad));

        match dispatcher.handle(received(&bytes_of(&section_request_for(text)))) {
            // `Reply` and not `ReplyAndReport`. That the file is no longer
            // refused is the smaller half of the claim; the larger half is that
            // no detection was built at all, so nothing will be quarantined and
            // no toast will be posted about a file the user vouched for.
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("an allowed path was still acted on: {other:?}"),
        }
    }

    /// A file of the product's own is let run, whatever it contains.
    ///
    /// The defect behind this test was measured on 2026-10-10, and it is not a
    /// false positive in the ordinary sense: `Dispatcher::decide` scanned
    /// `C:\WenleAV\wenle.exe` on every open — nine times in one session, about
    /// two seconds each — because the driver's built-in exclusion table names
    /// `C:\Program Files` and `C:\ProgramData\WenleAV` and this install was in
    /// neither. A real installation is under `Program Files` and is excluded by
    /// the driver before it ever asks, so the branch this test covers is what a
    /// portable or a development layout was missing. Two of those nine arrived
    /// from the section gate, which is inside the image-mapping path and cannot
    /// afford to wait for a scan.
    ///
    /// The control arm is not decoration. Without it, a fixture that the rule
    /// does not actually convict would pass this test while proving nothing —
    /// and the tree check would be indistinguishable from a rule that never
    /// matched.
    #[test]
    fn a_file_of_ours_is_allowed_without_being_scanned() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let ours_on_disk = dir.path().join("wenle.exe");
        std::fs::write(&ours_on_disk, b"MALWARE_MARKER_FOR_THE_TEST")
            .expect("the fixture is written");
        let text = ours_on_disk.to_str().expect("the fixture path is UTF-8");

        // The control: the same bytes under a directory nobody claims, asked by
        // the gate that may refuse. This is also what says the default layout
        // the other helpers use, [`elsewhere`], does not quietly cover the
        // fixture.
        let mut stranger = dispatcher_over(rules_matching("MALWARE_MARKER_FOR_THE_TEST"), DECISION_DEADLINE);
        match stranger.handle(received(&bytes_of(&section_request_for(text)))) {
            Action::ReplyAndReport(reply, detection) => {
                assert_eq!(reply.decision, Decision::Block.as_wire());
                assert!(detection.claims_a_block());
            }
            other => panic!("the fixture was not convicted, so this proves nothing: {other:?}"),
        }

        // The same file, with the directory holding it named as the install
        // tree — which is what the failing machine's layout was.
        let own = AvPaths::with_data_dir(dir.path(), dir.path().join("data"));
        let (mut ours, _published) = dispatcher_allowing_in(
            rules_matching("MALWARE_MARKER_FOR_THE_TEST"),
            DECISION_DEADLINE,
            AllowList::new(),
            own,
        );
        match ours.handle(received(&bytes_of(&section_request_for(text)))) {
            // `Reply` and not `ReplyAndReport`: nothing is refused *and* nothing
            // is convicted, so no detection is built and no toast is raised
            // about our own executable. A block would be worse than the cost
            // this fix removes — it would be the product refusing to start.
            Action::Reply(reply) => assert_eq!(
                reply.decision,
                Decision::Allow.as_wire(),
                "a file of ours must not be refused, whatever it contains"
            ),
            other => panic!("a file of ours was acted on: {other:?}"),
        }
    }

    /// The same for an entry that came from the configuration instead of from a
    /// button — the other half of "allow permanently", and the one that has to
    /// still be in force after a restart.
    #[test]
    fn a_path_the_configuration_excludes_is_not_scanned() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let bad = dir.path().join("bad.bin");
        std::fs::write(&bad, b"MALWARE_MARKER_FOR_THE_TEST").expect("the fixture is written");
        let text = bad.to_str().expect("the fixture path is UTF-8");

        // Seeded the way the service seeds it at startup. No control arm here:
        // the previous test is the control, over the identical fixture.
        let allow = AllowList::from_paths(std::slice::from_ref(&bad));
        let (mut dispatcher, _published) = dispatcher_allowing(
            rules_matching("MALWARE_MARKER_FOR_THE_TEST"),
            DECISION_DEADLINE,
            allow,
        );

        match dispatcher.handle(received(&bytes_of(&section_request_for(text)))) {
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("an excluded path was still acted on: {other:?}"),
        }
    }

    #[test]
    fn a_request_with_no_path_is_allowed_rather_than_decided_about() {
        // Nothing to look at means nothing to refuse, and inventing a path here
        // would be deciding about a file nobody named.
        let mut dispatcher = dispatcher_matching("MALWARE_MARKER_FOR_THE_TEST");
        let request = DecisionRequestMessage::new(3, SubjectKind::File);
        assert_eq!(request.path_units, 0);
        match dispatcher.handle(received(&bytes_of(&request))) {
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("a request with no path was not answered: {other:?}"),
        }
    }

    #[test]
    fn a_path_that_cannot_be_decoded_exactly_is_allowed_rather_than_guessed_at() {
        // The text decoded here is the text that gets opened. A lossy decode
        // would turn an undecodable path into some *other* file's name, and
        // deciding about that file is deciding about the wrong one — so an
        // undecodable path is a failure like any other, and the answer is yes.
        let mut request = DecisionRequestMessage::new(5, SubjectKind::File);
        // An unpaired high surrogate: legal in a `[u16; 1024]`, illegal in a
        // `String`, and exactly what a driver sending a malformed path produces.
        request
            .set_path(&[0xD800, 0x0041])
            .expect("two units fit the path field");
        let mut dispatcher = dispatcher_matching("MALWARE_MARKER_FOR_THE_TEST");
        match dispatcher.handle(received(&bytes_of(&request))) {
            Action::Reply(reply) => assert_eq!(reply.decision, Decision::Allow.as_wire()),
            other => panic!("an undecodable path was not answered: {other:?}"),
        }
    }

    #[test]
    fn the_backoff_starts_short_rises_and_stops_growing() {
        // Two faults, one test. A first delay that is long makes the ordinary
        // race — the service started a moment before the driver finished
        // loading — cost seconds of unprotected time. A schedule that never
        // stops growing makes a driver that arrives an hour later wait an hour
        // for the service to notice.
        let mut previous = Duration::ZERO;
        for attempt in 0..RETRY_SCHEDULE_MS.len() as u32 {
            let delay = retry_delay(attempt);
            assert!(
                delay >= previous,
                "attempt {attempt} waits less than the one before it"
            );
            previous = delay;
        }
        assert!(retry_delay(0) <= Duration::from_millis(100));
        assert_eq!(retry_delay(u32::MAX), retry_delay(RETRY_SCHEDULE_MS.len() as u32));
        assert!(retry_delay(u32::MAX) <= Duration::from_secs(15));
    }

    #[test]
    fn a_stop_is_noticed_within_a_chunk_of_the_longest_wait() {
        // The fault this guards is a shutdown that hangs: the SCM's
        // `STOP_PENDING` is on a clock, and a service that slept the whole
        // fifteen-second backoff in one call would be killed rather than
        // stopped. The margin here is a hundredfold, so the test is about the
        // chunking and not about how fast this machine is.
        let stop = AtomicBool::new(true);
        let started = std::time::Instant::now();
        sleep_unless_stopped(Duration::from_secs(15), &stop);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_sleep_that_is_not_interrupted_lasts_its_whole_time() {
        // The other half: the chunking must not turn a wait into a no-op, or the
        // retry loop becomes a spin that fills the log.
        let stop = AtomicBool::new(false);
        let started = std::time::Instant::now();
        sleep_unless_stopped(Duration::from_millis(250), &stop);
        assert!(started.elapsed() >= Duration::from_millis(250));
    }

    #[test]
    fn a_connect_failure_names_which_of_the_three_states_the_machine_is_in() {
        // A log line that said only "could not connect" would send whoever reads
        // it to the wrong one of "the driver is not loaded", "the driver is
        // loaded and this process may not talk to it" and "something else".
        assert!(connect_failure_reason(HR_FILE_NOT_FOUND).contains("not created"));
        assert!(connect_failure_reason(HR_PATH_NOT_FOUND).contains("not created"));
        assert!(connect_failure_reason(HR_ACCESS_DENIED).contains("may not"));
        assert!(connect_failure_reason(0x8007_0057).contains("could not be opened"));
    }

    #[test]
    fn a_connect_failure_reads_the_shape_before_it_reads_the_code() {
        // The two values that a low-sixteen-bit mask gets wrong in opposite
        // directions. Both were reached with the masked form: `0x8000_4005`
        // masked to `5` and was reported as an access denial, and `0xC000_0022`
        // masked to `34` and was reported as an unknown failure. The assertions
        // are the opposite of each other, so a revert to masking fails one of
        // them whichever way the code is written.
        assert!(
            connect_failure_reason(0x8000_4005).contains("could not be opened"),
            "E_FAIL is not a permissions problem"
        );
        assert!(
            connect_failure_reason(STATUS_ACCESS_DENIED).contains("may not"),
            "the filter manager refusing a connection is an access denial whatever shape \
             it arrives in"
        );
        // The status spellings of "there is no such port", which the masked form
        // read as `0x34` and `0x3A`.
        assert!(connect_failure_reason(STATUS_OBJECT_NAME_NOT_FOUND).contains("not created"));
        assert!(connect_failure_reason(STATUS_OBJECT_PATH_NOT_FOUND).contains("not created"));
        // And the mapping the shapes share, so that the two spellings of one
        // state cannot drift apart.
        assert_eq!(
            connect_failure_reason(HR_ACCESS_DENIED),
            connect_failure_reason(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            connect_failure_reason(HR_FILE_NOT_FOUND),
            connect_failure_reason(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn the_connection_events_say_which_side_of_the_connection_they_describe() {
        // What a user interface reads to answer "am I actually protected": a
        // driver that is loaded with nobody connected to its port blocks
        // nothing, and these two events are the only place that difference is
        // visible.
        let connected = connection_event(true, av_driver_proto::PORT_NAME);
        assert_eq!(connected.action, DriverEventAction::StateChanged);
        assert_eq!(connected.subject, DriverSubject::Driver);
        assert_eq!(connected.path, None);
        assert!(connected.driver_state.is_some());
        assert_eq!(
            connected
                .driver_state
                .as_ref()
                .map(|status| status.presence),
            Some(av_ipc::DriverPresence::Loaded)
        );
        assert_eq!(connected.detail, 1);
        // A time, not zero: 1601 is what a zero means here, and reporting a
        // connection as three centuries old is worse than not reporting one. The
        // bound is the 1970 epoch rather than a recent date, so the assertion is
        // about the conversion happening at all and not about this machine's
        // clock.
        assert!(connected.timestamp_100ns > 116_444_736_000_000_000);

        let ended = connection_event(false, av_driver_proto::PORT_NAME);
        assert_eq!(ended.detail, 0);
        assert_eq!(
            ended.driver_state.as_ref().map(|status| status.presence),
            Some(av_ipc::DriverPresence::Unknown)
        );
    }

    #[test]
    fn a_client_over_a_port_that_is_not_there_keeps_trying_and_stops_when_asked() {
        // Two faults at once, and neither can be reached without a thread. A
        // client that gave up after the first failed connect would leave a
        // machine unprotected from the moment the driver was reloaded until the
        // service was restarted by hand; a client that could not be stopped would
        // hold the shutdown open. The port name is not the product's, so this
        // test cannot take a connection an installed service needs.
        let (events, _held) = crossbeam_channel::unbounded::<Event>();
        let engine = Arc::new(ScanEngine::new(RuleDatabase::compile("").0));
        let mut client = start_on(
            engine,
            events,
            r"\WenleAvPortThatDoesNotExistForATest",
            AllowList::new(),
            // The layout is along for the ride here and never consulted: this
            // client never reaches a driver, so it is never asked for a
            // decision. [`elsewhere`] rather than a real one, for the reason
            // recorded there.
            elsewhere(),
            // Nothing armed, which is `ConfigMessage::default`'s own value and
            // the honest one here: this test is about a client that never
            // reaches a driver, so no configuration is ever sent.
            ConfigMessage::default(),
        );
        assert!(client.is_running(), "the retrying thread must be alive");

        client.stop();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while client.is_running() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !client.is_running(),
            "the thread did not stop within ten seconds of being asked"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_platform_without_the_filter_manager_says_so_and_does_not_pretend() {
        // The honest stub: no filter manager means no port and no decisions, and
        // a client that reported itself as running would be claiming a protection
        // this build does not have.
        let (events, _held) = crossbeam_channel::unbounded::<Event>();
        let engine = Arc::new(ScanEngine::new(RuleDatabase::compile("").0));
        let client = start_on(engine, events, r"\WenleAvFilterPort");
        assert!(!client.is_running());
    }

    #[test]
    fn the_two_subjects_the_driver_sends_name_two_different_gates() {
        // `asking_gate` turns the one field that identifies the asker into a
        // name, and the guest console is read for that name. What can go wrong
        // here is not the wording but the pairing: if the wire numbers moved,
        // the service would confidently name the wrong gate, which is worse than
        // saying nothing. So the pinning is on the numbers the driver sends, and
        // on the two names not being interchangeable.
        let create = asking_gate(SubjectKind::WIRE_PROCESS);
        let section = asking_gate(SubjectKind::WIRE_IMAGE);
        assert_ne!(
            create, section,
            "the two gates have to read differently or the line says nothing"
        );
        assert!(
            create.contains("create"),
            "the process subject is the create pre-operation: {create}"
        );
        assert!(
            section.contains("section"),
            "the image subject is the acquire-for-section pre-operation: {section}"
        );

        // And a value this build does not define is reported as itself rather
        // than folded into one of the two above.
        assert_eq!(asking_gate(0), "an undefined subject");
        assert_eq!(asking_gate(u32::MAX), "an undefined subject");
        // The two subjects no decision request carries are named as themselves,
        // not as a gate.
        assert_eq!(asking_gate(SubjectKind::WIRE_FILE), "file");
        assert_eq!(asking_gate(SubjectKind::WIRE_DRIVER), "driver");
    }

    #[test]
    fn only_the_section_gate_may_refuse() {
        // The single predicate every refusal in this module goes through. It is
        // asserted against the wire numbers rather than against `SubjectKind`
        // values alone so that a renumbered protocol fails here rather than
        // quietly moving the power to refuse to the gate that asks about
        // everything.
        assert!(
            refusing_gate(SubjectKind::WIRE_IMAGE),
            "the acquire-for-section pre-operation is the gate that stops a program"
        );
        assert!(
            !refusing_gate(SubjectKind::WIRE_PROCESS),
            "the create gate asks about ordinary opens and must not refuse"
        );
        // Neither of the kinds no decision request carries may refuse: a request
        // arriving with one is not a request this build understands, and the
        // answer for that is the fail-open one.
        assert!(!refusing_gate(SubjectKind::WIRE_FILE));
        assert!(!refusing_gate(SubjectKind::WIRE_DRIVER));
        assert!(!refusing_gate(0));
        assert!(!refusing_gate(u32::MAX));
    }
}