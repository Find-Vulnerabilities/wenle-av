//! The one thread this DLL owns, and the budget it works to.
//!
//! # Why a thread at all
//!
//! `IAntimalwareProvider::Scan` runs on the host's thread, synchronously, in
//! front of the host's decision to run the script. Anything it does is time the
//! host does not have. Two things it must do are unbounded in the worst case —
//! connecting to a service, and waiting for that service to answer — and the
//! only way to make them bounded is to not do them on the caller's thread.
//!
//! So: a worker thread owns the connection, jobs go to it over a channel, and
//! the caller waits on a second channel with a timeout. When the timeout
//! expires the caller returns [`result::no_opinion`](crate::result::no_opinion)
//! and the host runs its script. That is a real reduction in protection for the
//! duration of one outage, and it is the right trade against a `powershell.exe`
//! that stops responding: an antivirus that hangs the machine is uninstalled,
//! and an uninstalled antivirus protects nothing at all.
//!
//! # Why exactly one, for ever
//!
//! The thread is started on the first scan and never stopped. It exists to hold
//! one connection open, so that the second script block a host runs does not pay
//! for a connect, and it is idle in `recv` the rest of the time — a parked
//! thread, no timer, no polling. A second thread would be a second connection
//! and a second copy of the correlation state in [`av_ipc::Client`], for no
//! gain: one host asks one question at a time on this path.
//!
//! Because it exists, **this DLL never unloads**. A thread whose code lives in
//! an unloaded module is a crash the moment it next runs, so
//! [`DllCanUnloadNow`](crate::DllCanUnloadNow) stops answering "yes" from the
//! moment the worker starts. That is a small, permanent cost in a host process
//! and it is the only correct answer.
//!
//! # Why the thread is not started until the first scan
//!
//! [`Scanner::start`] does not create it; the first [`Scanner::scan`] does. The
//! alternative is starting it from `DllGetClassObject`, and `CoCreateInstance`
//! is reached from `CoGetClassObject` in a process that is still loading this
//! DLL. `CreateThread` is not something to do while a loader lock is held, and a
//! thread created there would also be created for every host that instantiates
//! a provider and then never runs a script — which is most of them, since AMSI
//! creates the provider when the host starts, not when it runs something.
//!
//! # The budget, and where the numbers come from
//!
//! [`BUDGET`] is what the host can be made to wait. [`IO_TIMEOUT`] is what one
//! pipe operation may take, and is smaller so that a connect, a write and a read
//! can all fit inside one budget in the ordinary case where each is fast.
//! [`CONNECT_TIMEOUT_MS`](crate::connection) bounds the wait for a free pipe
//! instance. The three are chosen so that the worst case is the budget.
//!
//! A machine with no service installed pays none of this: `WaitNamedPipeW`
//! returns immediately when there is no instance of the name at all, so the
//! first failure is a connect that failed in microseconds rather than a wait.
//! What it does pay is one connect attempt per scan, because a failed connect
//! leaves nothing to reuse.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use av_ipc::{BufferScan, Client, Connection, Incoming, Request, Reply};

use crate::connection::DeadlineConnection;

/// How long a host is made to wait for an answer before it is told nothing.
///
/// Long enough that a loaded machine answers — measured on this one, a script
/// block is a few milliseconds of rule matching plus a pipe round trip. Short
/// enough that a service in trouble costs a person a flicker rather than a
/// freeze: the number a user experiences as "the machine hiccuped" is a few
/// hundred milliseconds, and the number they experience as "it hung" is a
/// second and a half.
pub const BUDGET: Duration = Duration::from_millis(800);

/// How long one pipe operation may take.
///
/// Smaller than [`BUDGET`] so that a connect, a write and a read fit inside one.
/// An operation that takes longer than this is not slow, it is stuck, and the
/// connection is abandoned rather than waited on.
pub const IO_TIMEOUT: Duration = Duration::from_millis(250);

/// How many jobs may be waiting for the worker.
///
/// A bound, and the peer does not choose it — the *host* does, by asking for
/// more script blocks than one thread can answer, which on a runaway script is
/// exactly what happens. Beyond this the caller is told there is no opinion
/// rather than queued: a queue that grows during an incident is a queue that
/// grows until the process dies, and the fourth script block in a burst is no
/// more scannable than the first.
const QUEUE_DEPTH: usize = 8;

/// True once the worker thread exists, which is from then on permanent.
static WORKER_STARTED: AtomicBool = AtomicBool::new(false);

/// Whether the worker thread has been started.
///
/// Read by [`DllCanUnloadNow`](crate::DllCanUnloadNow): a module with a live
/// thread in it can never be safely unloaded.
pub fn worker_started() -> bool {
    WORKER_STARTED.load(Ordering::Acquire)
}

/// What one scan produced.
#[derive(Debug, Clone)]
pub enum Scan {
    /// The service examined the content and said something about it.
    Reported(Box<BufferScan>),
    /// Nothing examined it, and this is why.
    ///
    /// The reason is for the log and for the notification, never for the
    /// answer: every one of these ends at
    /// [`no_opinion`](crate::result::no_opinion), because "I could not look" is
    /// not "it is clean" and not "refuse it".
    Unavailable(String),
}

impl Scan {
    /// The verdict, or [`Verdict::Unknown`](av_core::Verdict::Unknown) when
    /// nothing was examined.
    ///
    /// The service's own refusal path already stores `Unknown` with the reason
    /// attached, so this does not have to invent one — it only has to cover the
    /// case where no reply arrived at all.
    pub fn verdict(&self) -> av_core::Verdict {
        match self {
            Scan::Reported(scan) => scan.verdict,
            Scan::Unavailable(_) => av_core::Verdict::Unknown,
        }
    }

    /// One line for the log.
    pub fn summary(&self) -> String {
        match self {
            Scan::Reported(scan) => scan.summary.clone(),
            Scan::Unavailable(reason) => format!("not examined: {reason}"),
        }
    }
}

/// A job handed to the worker.
struct Job {
    name: String,
    data: Vec<u8>,
    reply: SyncSender<Result<Box<BufferScan>, String>>,
}

/// What every clone of a [`Scanner`] shares.
#[derive(Debug)]
struct Inner {
    budget: Duration,
    /// The control pipe the worker connects to.
    ///
    /// A field rather than [`av_ipc::PIPE_NAME`] read where the connection is
    /// made, so that a scanner can be pointed at a service somebody else
    /// started. Every production constructor supplies the installed service's
    /// pipe; [`Scanner::with_pipe`] is the one that does not.
    pipe: String,
    /// The job queue, created — with the thread behind it — on first use.
    jobs: OnceLock<SyncSender<Job>>,
}

/// The scanning half of this crate, as the provider sees it.
///
/// Cheap to hold, cheap to clone and safe to share: everything it owns is an
/// `Arc` around a channel and a duration. Cloning shares one worker, which is
/// what the class factory relies on when it hands one to each provider.
#[derive(Debug, Clone)]
pub struct Scanner {
    inner: Arc<Inner>,
}

impl Scanner {
    /// A scanner with the default budget.
    ///
    /// Creates nothing. The worker thread appears the first time [`Scanner::scan`]
    /// is called — see this module's documentation for why that is not merely
    /// lazy but required.
    pub fn start() -> Self {
        Self::with_budget(BUDGET)
    }

    /// A scanner with a stated budget, against the installed service's pipe.
    ///
    /// Exists so that a test can drive the whole path — provider, worker, pipe,
    /// session — against a service that answers too slowly without any of it
    /// waiting [`BUDGET`] to find that out.
    pub fn with_budget(budget: Duration) -> Self {
        Self::with_pipe(av_ipc::PIPE_NAME, budget)
    }

    /// A scanner with a stated budget, against a pipe of the caller's naming.
    ///
    /// The pipe is otherwise [`av_ipc::PIPE_NAME`], the installed service's, and
    /// every other constructor here uses it. This one is what lets a test start
    /// a service of its own on a pipe of its own — the service crate's
    /// `unique_name` builds one, and `tests/control_pipe.rs` explains why a
    /// shared name cannot be used — and then drive the real provider, the real
    /// worker and the real protocol against it.
    ///
    /// That matters more here than in most crates. Every other test in this one
    /// runs against a machine with *no* service, which is the case where the
    /// answer is `Unavailable`; without this constructor the case where the
    /// service is there and has an opinion could only be reached by installing
    /// the product on the machine running the tests.
    ///
    /// The lifetime of the pipe is the worker's: it is read once when the worker
    /// is created, which is on the first [`Scanner::scan`], so a scanner built
    /// before its service exists is ordinary rather than a mistake.
    pub fn with_pipe(pipe: &str, budget: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                budget,
                pipe: pipe.to_string(),
                jobs: OnceLock::new(),
            }),
        }
    }

    /// Ask the service about bytes a host is about to run.
    ///
    /// Returns within [`Scanner::budget`], always.
    pub fn scan(&self, name: &str, data: &[u8]) -> Scan {
        let jobs = self
            .inner
            .jobs
            .get_or_init(|| start_worker(&self.inner.pipe, self.inner.budget));
        let (reply, answers) = sync_channel(1);
        let job = Job {
            name: name.to_string(),
            data: data.to_vec(),
            reply,
        };
        match jobs.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Scan::Unavailable(format!(
                    "the scanner is already {QUEUE_DEPTH} script blocks behind"
                ))
            }
            Err(TrySendError::Disconnected(_)) => {
                return Scan::Unavailable("the scanner thread is gone".to_string())
            }
        }
        match answers.recv_timeout(self.inner.budget) {
            Ok(Ok(scan)) => Scan::Reported(scan),
            Ok(Err(reason)) => Scan::Unavailable(reason),
            Err(RecvTimeoutError::Timeout) => Scan::Unavailable(format!(
                "the service did not answer within {} ms",
                self.inner.budget.as_millis()
            )),
            // The worker dropped the sender, which happens when it panicked.
            // `catch_unwind` around the worker body turns that into an ordinary
            // exit instead, and this arm covers the case where even that failed.
            Err(RecvTimeoutError::Disconnected) => {
                Scan::Unavailable("the scanner thread stopped".to_string())
            }
        }
    }

    /// How long a caller is prepared to wait.
    pub fn budget(&self) -> Duration {
        self.inner.budget
    }
}

/// Create the queue and the thread that drains it.
///
/// A thread that could not be created leaves a sender whose receiver is already
/// gone, so every [`Scanner::scan`] reports `Unavailable` rather than blocking —
/// the correct degradation, and one that needs no branch at any call site.
fn start_worker(pipe: &str, budget: Duration) -> SyncSender<Job> {
    let (jobs, receiver) = sync_channel(QUEUE_DEPTH);
    // Owned by the thread: the scanner may be dropped the moment the job is
    // queued, and a worker reading a pipe name out of a `Scanner` that no longer
    // exists would be a use-after-free with a thread's lifetime between them.
    let pipe = pipe.to_string();
    // Detached: nothing joins it, and it exits when the process does.
    // `Builder` rather than `spawn` so it gets a name, which is what a person
    // reading a thread list in Process Explorer needs in order to tell this
    // thread apart from the host's own.
    let spawned = std::thread::Builder::new()
        .name("wenle-amsi".to_string())
        .spawn(move || worker(&receiver, &pipe, budget));
    match spawned {
        Ok(_) => WORKER_STARTED.store(true, Ordering::Release),
        Err(error) => {
            log::error!("the AMSI worker thread could not be started ({error}); content will not be scanned");
        }
    }
    jobs
}

/// The worker: one connection, reused, for as long as the process lives.
///
/// A panic here would unwind out of a thread this crate started inside somebody
/// else's process, so the loop is guarded. `panic = "unwind"` in the workspace's
/// release profile is what makes the guard possible; see the crate manifest.
fn worker(jobs: &Receiver<Job>, pipe: &str, budget: Duration) {
    let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut client: Option<Client<DeadlineConnection>> = None;
        while let Ok(job) = jobs.recv() {
            let result = attempt(&mut client, &job, pipe, budget);
            // A failed send means the caller gave up and dropped its receiver,
            // which is the ordinary case for a scan that timed out. Not an
            // error, and deliberately not logged.
            let _ = job.reply.send(result);
        }
    }));
    if guarded.is_err() {
        log::error!("the AMSI worker thread panicked; script content will not be scanned");
    }
}

/// Answer one job, reconnecting if the connection is not usable.
///
/// A connection that failed is dropped rather than reused: it may have an
/// unanswered request on it, and the next reply to arrive on it would be read as
/// the answer to the next question. That is the desynchronisation
/// [`av_ipc::session`] exists to refuse, and the cheapest way to make it
/// impossible is to throw the pipe away.
fn attempt(
    client: &mut Option<Client<DeadlineConnection>>,
    job: &Job,
    pipe: &str,
    budget: Duration,
) -> Result<Box<BufferScan>, String> {
    // A caller with a budget shorter than the default per-operation timeout
    // gets the shorter one. `IO_TIMEOUT` is tuned for the ordinary case; a test
    // that asks for a 100 ms budget should not wait 250 ms to be told the
    // service is not there.
    let io = IO_TIMEOUT.min(budget);
    if let Some(existing) = client.as_mut() {
        match exchange(existing, job) {
            Ok(scan) => return Ok(scan),
            Err(reason) => {
                log::debug!("the AMSI connection was dropped: {reason}");
                *client = None;
            }
        }
    }
    let connection = DeadlineConnection::connect(pipe, io).map_err(|error| error.to_string())?;
    let mut fresh = Client::new(connection);
    let scan = exchange(&mut fresh, job)?;
    *client = Some(fresh);
    Ok(scan)
}

/// Send one request and read its answer, ignoring anything else that arrives.
fn exchange<C: Connection>(
    client: &mut Client<C>,
    job: &Job,
) -> Result<Box<BufferScan>, String> {
    let id = client
        .send(Request::ScanBuffer {
            name: job.name.clone(),
            data: job.data.clone(),
        })
        .map_err(|error| error.to_string())?;
    loop {
        let incoming = client.recv().map_err(|error| error.to_string())?;
        for message in incoming {
            match message {
                // Events are not answers. A service publishing a detection on
                // this connection would otherwise be read as the reply and the
                // session would be off by one for the rest of its life — which
                // is the correlation rule `av_ipc::Client` already enforces and
                // this arm is the caller half of.
                Incoming::Event(event) => {
                    log::debug!("the service published {event:?} during a buffer scan");
                }
                Incoming::Reply { id: got, reply } => {
                    // Unreachable: `Client::recv` refuses a reply this client is
                    // not waiting for and this client is waiting for exactly
                    // one. Written anyway, because "unreachable" is a claim
                    // about another crate's code and a silent `continue` here
                    // would turn a desynchronised session into a scan that
                    // never returns.
                    if got != id {
                        return Err(format!("a reply for request {got:?} arrived while {id:?} was outstanding"));
                    }
                    return match reply {
                        Reply::BufferScan(scan) => Ok(scan),
                        // Likewise unreachable: the session checks the kind
                        // before the caller sees it.
                        other => Err(format!(
                            "a buffer scan was answered with {} instead",
                            other.kind().as_str()
                        )),
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::Verdict;

    /// A scanner with no service behind it, which is what a machine without
    /// this product installed actually has. `PIPE_NAME` is the installed
    /// service's name and no test creates it, so a connect here fails — but not
    /// by hanging, which is the property under test.
    #[test]
    fn a_scan_with_no_service_answers_quickly_and_with_no_opinion() {
        let scanner = Scanner::with_budget(Duration::from_millis(300));
        let started = std::time::Instant::now();
        let scan = scanner.scan("Script Block", b"Get-ChildItem");
        let elapsed = started.elapsed();

        assert_eq!(scan.verdict(), Verdict::Unknown);
        assert!(matches!(scan, Scan::Unavailable(_)), "{scan:?}");
        // Not "fast" in the abstract: fast against the budget it was given. The
        // failure this guards against is a connect that waits out its timeout
        // when there is nothing to connect to, which would make every script
        // block on a machine without the service cost the full budget.
        assert!(elapsed < scanner.budget(), "{elapsed:?}");
        assert!(!scan.summary().is_empty());
    }

    #[test]
    fn an_unavailable_scan_is_never_reported_as_clean_or_as_confirmed() {
        // The two verdicts that would be wrong in opposite directions. `Clean`
        // would tell a caller the content was examined; `Malicious` would tell
        // it to refuse content nothing looked at.
        let scanner = Scanner::with_budget(Duration::from_millis(300));
        let scan = scanner.scan("Script Block", b"Get-ChildItem");
        assert_eq!(scan.verdict(), Verdict::Unknown);
        assert_ne!(scan.verdict(), Verdict::Clean);
        assert_ne!(scan.verdict(), Verdict::Malicious);
        assert!(!scan.verdict().blocks());
    }

    #[test]
    fn the_queue_is_bounded_and_refuses_rather_than_grows() {
        // The worker is started with the default budget and no service, so it
        // spends its time failing to connect. Whatever the timing, the
        // invariant is that this never blocks for longer than one budget per
        // call and never grows a backing queue — both of which follow from
        // `try_send` on a bounded channel and `recv_timeout`.
        let scanner = Scanner::start();
        let started = std::time::Instant::now();
        for _ in 0..(QUEUE_DEPTH * 4) {
            let _ = scanner.scan("Script Block", b"Get-ChildItem");
        }
        let elapsed = started.elapsed();
        let ceiling = BUDGET * (QUEUE_DEPTH as u32 * 4) + Duration::from_secs(1);
        assert!(elapsed < ceiling, "{elapsed:?} for {} scans", QUEUE_DEPTH * 4);
    }

    #[test]
    fn the_budget_is_smaller_than_a_person_notices_as_a_hang() {
        // A number rather than a constant nobody can check. Under a tenth of a
        // second would fail honest scans on a loaded machine; over a second and
        // a half is the point at which a user calls it a freeze.
        assert!(BUDGET >= Duration::from_millis(100));
        assert!(BUDGET <= Duration::from_millis(1500));
        // And the per-operation timeout has to be smaller, or the three
        // operations one scan needs could not fit inside one budget.
        assert!(IO_TIMEOUT < BUDGET);
    }
}
