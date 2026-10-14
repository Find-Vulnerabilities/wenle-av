//! Tamper resistance: the half of it that can be checked, and the half that
//! cannot be checked often.
//!
//! # What this is for
//!
//! `crate::selfprotect` hardens the machine once, at start-up: this process's
//! own access list and the product's directories. (It also *reads* the SCM's
//! recovery policy, which it may not write — see that module — and the cheap
//! pass here does not re-read it, because nothing the service can do would
//! change it.) Every one of those lives on an object that something else can
//! change while the service runs. A directory recreated by an installer inherits
//! its parent's permissions rather than ours; a script running as an
//! administrator can put a permissive entry back on this process in one call;
//! and none of it announces itself. Without this module the service would go on
//! reporting the hardening it applied at start-up for the rest of its life,
//! which is exactly the failure `av_guard`'s whole design is built to avoid —
//! *applied* and *in place* are
//! different facts.
//!
//! # Why it is two passes and not one
//!
//! Because the two checks cost four orders of magnitude apart, and a design that
//! ran one of them on the other's schedule would either be useless or be a
//! permanent scan.
//!
//! * **The cheap pass** re-reads this process's access list and each product
//!   directory's, and puts back anything it finds undone. That is a handful of
//!   `GetNamedSecurityInfo` calls and, when something has been undone, one
//!   `SetSecurityInfo` per object. It runs every few minutes, and it is what
//!   `protection.tamper_resistance` actually turns on.
//! * **The expensive pass** hashes every file the manifest names and verifies
//!   the Authenticode signature of the five programs among them. `Manifest::verify`
//!   documents that cost itself — "tens of megabytes of I/O and a chain build
//!   per binary" — and draws the conclusion this module keeps: it is not
//!   something that happens on a timer. It runs once when the worker starts and
//!   then at a long interval, and it **repairs nothing**.
//!
//! # Why the expensive pass never re-records the manifest
//!
//! `tamper::Manifest::capture` will happily hash a tampered `wenle.exe` and write
//! it out as the new baseline. A service that re-captured on finding a difference
//! would therefore destroy the evidence of the tampering it had just detected, on
//! its own, silently, and every later check would call the machine clean. That is
//! strictly worse than not checking at all, because it converts a detection into
//! a permanent false negative. **Nothing in this module writes the manifest**,
//! and `nothing_here_writes_the_manifest` is the test that says so.
//!
//! Taking a manifest is `wenle protect manifest`, a command an administrator
//! runs, and the report this module publishes names it when there is none.
//!
//! # Why the state is a shared cell and not an event channel
//!
//! `crate::process_watch` publishes through a channel, and the difference is
//! worth stating because the two look alike. A finished process walk is an
//! *action*: the control loop has to take a file into the vault, and only the
//! host may write the vault. A tamper finding is a *fact about the machine*.
//! There is nothing to do about it — the honest responses are "protection was
//! undone and has been re-applied" and "these files no longer match", and the
//! second is one a user has to decide about. So the worker keeps the last answer
//! in a cell that a status request reads, the same way `RealtimeState` is kept,
//! and a client that was not connected when the check ran still gets it.
//!
//! # What this does not do
//!
//! It does not stop an attacker; it notices one. `av_guard`'s own documentation
//! names the limits — an administrator, a kernel-mode attacker, somebody who
//! boots another operating system — and this module adds none of its own and
//! claims none that are not there. What it will not do is stay quiet.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use av_core::paths::AvPaths;
use av_guard::tamper::{self, ManifestState};
use av_guard::{files, process};
use av_ipc::{ManifestVerdict, TamperState};

/// How often the cheap pass runs.
///
/// Five minutes, chosen against what it costs and what it is defending against.
/// The cost is a few security-descriptor reads and no writes at all on a machine
/// nobody has touched, which is nothing spread over five minutes; the threat is
/// somebody with an administrator's token re-permitting writes to this product,
/// and the window this leaves them is the time it takes the user to notice that
/// the product stopped working. A tighter interval buys a shorter window and
/// spends the machine on a check that has never yet found anything on a clean
/// install.
pub const CHEAP_INTERVAL: Duration = Duration::from_secs(300);

/// How often the expensive pass runs.
///
/// Six hours. There is no shorter honest answer: the check is tens of megabytes
/// of hashing and a signature chain per program, and what it detects — a
/// replaced binary or a modified rule database — is not something that has to be
/// caught within the minute to be acted on, because the files it covers are the
/// product's own and the response is a person's decision rather than an
/// automatic repair. `wenle protect verify` runs the same check on demand, which
/// is the answer for somebody who wants it now.
pub const EXPENSIVE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// How long the worker sleeps at a time while waiting for the next cheap pass.
///
/// The stop flag is checked between sleeps, so this is the longest a shutdown
/// waits for the worker — and it is also the granularity at which an on-demand
/// check is noticed. Small enough that neither is noticeable, large enough that
/// the thread is not spinning.
const POLL: Duration = Duration::from_millis(250);

/// How many manifest differences are carried in the published state.
///
/// A report and not a listing: a machine where every file was replaced would
/// otherwise put one sentence per file into every status answer for the life of
/// the service. The count is in [`ManifestVerdict::Changed`], and the rest are in
/// the log — which is where a history belongs.
const MAX_CHANGES: usize = 16;

/// How many unresolved sentences are carried in the published state.
///
/// Capped for the same reason as [`MAX_CHANGES`], and the residue is counted in
/// the sentence that replaces it, so a truncated list cannot be read as a
/// complete one.
const MAX_UNRESOLVED: usize = 8;

/// This process's own access list, as something that can be read and rewritten.
///
/// # Why this is a seam
///
/// The real implementation rewrites the access list of **whatever process is
/// running**, and there is no way to aim it at another one — that is deliberate,
/// and `crate::selfprotect::protect_process` documents why. The consequence here
/// is that a test of the real thing would harden the process running `cargo
/// test`, which is a side effect on a machine that did not ask for one. So the
/// policy — read, put back, read again, count — is tested against this trait, and
/// the three lines that call `av_guard` are the only part that needs a machine.
pub(crate) trait OwnProcess: Send + Sync + 'static {
    /// The dangerous rights an ordinary account still holds, by name.
    fn exposed(&self) -> Result<Vec<String>, String>;
    /// Close them again.
    fn protect(&self) -> Result<(), String>;
}

/// The real one: this process, through `av-guard`.
struct ThisProcess;

impl OwnProcess for ThisProcess {
    fn exposed(&self) -> Result<Vec<String>, String> {
        let protection = process::verify(process::current_pid())?;
        Ok(protection
            .exposed
            .iter()
            .map(|right| right.name().to_string())
            .collect())
    }

    fn protect(&self) -> Result<(), String> {
        process::protect_current_process().map(|_| ())
    }
}

/// What one read-back says is not the way this module left it.
#[derive(Debug, Default, PartialEq, Eq)]
struct ReadBack {
    /// The dangerous rights an ordinary account still holds on this process.
    process: Vec<String>,
    /// Directories an ordinary account can write, described in a sentence.
    directories: Vec<String>,
    /// Things that could not be read at all, in a sentence each.
    ///
    /// Separate from the other two because "I read it and it is wrong" and "I
    /// could not read it" are different facts with different fixes, and a check
    /// that counted an unreadable object as intact would be reporting protection
    /// it never established — the direction `av_guard::process::verify` also
    /// refuses to guess in.
    unreadable: Vec<String>,
}

impl ReadBack {
    /// Whether everything could be read and everything was in place.
    fn is_intact(&self) -> bool {
        self.process.is_empty() && self.directories.is_empty() && self.unreadable.is_empty()
    }
}

/// What the worker needs that does not change.
struct Context {
    paths: AvPaths,
    /// The name the manifest check asks the SCM about. Passed rather than
    /// imported, for the reason `av_guard::service` gives: a second copy of a
    /// name in a second crate goes stale silently.
    service_name: &'static str,
    own: Arc<dyn OwnProcess>,
    cheap: Duration,
    expensive: Duration,
}

/// A running tamper checker.
#[derive(Debug)]
pub struct Tamper {
    state: Arc<Mutex<TamperState>>,
    stop: Arc<AtomicBool>,
    /// Set by [`Tamper::check_now`], read and cleared by the worker.
    due: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Tamper {
    /// Stop the thread without waiting for it.
    ///
    /// The flag is what the worker's sleep tests, so this is also what keeps a
    /// dropped handle from leaving a thread rewriting access lists for the life
    /// of the process. The pass in flight is not interruptible — it is a
    /// sequence of kernel calls and file reads — so an exit can be delayed by up
    /// to one cheap pass, which is the reason the expensive pass runs on the
    /// worker rather than on the thread that owns the state.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Tamper {
    /// Start checking, with the intervals the product uses.
    pub fn start(paths: AvPaths, service_name: &'static str) -> Result<Self, TamperError> {
        Self::run_over(Context {
            paths,
            service_name,
            own: Arc::new(ThisProcess),
            cheap: CHEAP_INTERVAL,
            expensive: EXPENSIVE_INTERVAL,
        })
    }

    /// Start over a subject and intervals a test supplies.
    ///
    /// The one entry point, so that the thread, the loop and the state cell are
    /// the same in a test as in a service — the only things a test changes are
    /// which process's access list is read and how long it waits between passes.
    #[cfg(test)]
    fn start_with(
        paths: AvPaths,
        service_name: &'static str,
        own: Arc<dyn OwnProcess>,
        cheap: Duration,
        expensive: Duration,
    ) -> Result<Self, TamperError> {
        Self::run_over(Context {
            paths,
            service_name,
            own,
            cheap,
            expensive,
        })
    }

    fn run_over(context: Context) -> Result<Self, TamperError> {
        let state = Arc::new(Mutex::new(TamperState {
            enabled: true,
            checking: true,
            disabled_by: None,
            ..TamperState::off(false, "the checker has not reported yet")
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let due = Arc::new(AtomicBool::new(false));

        let worker = std::thread::Builder::new()
            .name("av-tamper".to_string())
            .spawn({
                let stop = Arc::clone(&stop);
                let due = Arc::clone(&due);
                let state = Arc::clone(&state);
                move || run(&context, &stop, &due, &state)
            })
            .map_err(|source| TamperError::WorkerSpawn { source })?;

        Ok(Self {
            state,
            stop,
            due,
            worker: Some(worker),
        })
    }

    /// What the checks have found, as of the moment this is called.
    pub fn state(&self) -> TamperState {
        read(&self.state)
    }

    /// Ask the worker to run an expensive pass as soon as it next wakes.
    ///
    /// The third occasion for the expensive check, alongside start-up and the
    /// interval, and the only one a caller chooses. It returns immediately: the
    /// pass runs on the worker, and [`Tamper::state`] reports it when it is done
    /// — `manifest_checks` and `manifest`. Waking the worker rather than running
    /// the pass on the caller's thread is deliberate, because the pass hashes
    /// every product file and the caller here is a status query.
    ///
    /// No product path calls it yet, and the on-demand check a person asks for is
    /// `wenle protect verify`, which runs the same comparison in that person's
    /// own process and prints all of it rather than the summary this state
    /// carries. It is public because "on demand" is a claim this module makes and
    /// a claim nothing can exercise is a claim nobody has checked.
    pub fn check_now(&self) {
        self.due.store(true, Ordering::SeqCst);
    }

    /// Stop the worker and wait for it.
    ///
    /// Returns false when the thread did not end cleanly, which in practice
    /// means it panicked. The state is readable either way, and is read before
    /// this is called.
    pub fn stop(mut self) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        match self.worker.take() {
            Some(worker) => worker.join().is_ok(),
            None => true,
        }
    }
}

/// A checker that could not be started.
#[derive(Debug, thiserror::Error)]
pub enum TamperError {
    /// The operating system would not create the thread.
    #[error("the tamper checker's thread could not be started: {source}")]
    WorkerSpawn {
        /// What the operating system said.
        source: std::io::Error,
    },
}

/// The worker's loop.
///
/// The expensive pass comes first, which is how the plan's "once at start-up"
/// happens without delaying start-up: this runs on a thread `Host::open` spawned
/// and did not wait for, so the tens of megabytes of hashing overlap with the
/// service finishing its own start-up and answering its first clients. Doing it
/// here rather than in `Host::open` is the risk the plan names, and it is a real
/// one — the service's start would otherwise be seconds longer on every boot.
fn run(context: &Context, stop: &AtomicBool, due: &AtomicBool, state: &Mutex<TamperState>) {
    let mut next_manifest = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        if due.swap(false, Ordering::SeqCst) {
            // Forced forward, and never backward: an on-demand check that ran
            // early must not also delay the interval's own pass past its
            // schedule, or a client asking for one now would quietly push the
            // next one six hours out.
            next_manifest = next_manifest.min(Instant::now());
        }
        if Instant::now() >= next_manifest {
            let (verdict, changes) = expensive_pass(context);
            next_manifest = Instant::now() + context.expensive;
            edit(state, |state| {
                state.manifest_checks += 1;
                state.manifest = verdict;
                state.changes = changes;
            });
        }

        let (reapplied, unresolved) = cheap_pass(context);
        edit(state, |state| {
            state.passes += 1;
            state.reapplied += reapplied;
            state.unresolved = unresolved;
        });

        sleep(context.cheap, stop, due);
    }
}

/// Sleep, in slices, until the interval is up or somebody asks for something.
fn sleep(interval: Duration, stop: &AtomicBool, due: &AtomicBool) {
    let wake = Instant::now() + interval;
    loop {
        if stop.load(Ordering::SeqCst) || due.load(Ordering::SeqCst) {
            return;
        }
        let left = wake.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        std::thread::sleep(POLL.min(left));
    }
}

/// One cheap pass: read, put back what is undone, read again.
///
/// Returns how many objects were re-applied and the sentences about whatever is
/// still not right. The second read-back is not ceremony — it is the whole reason
/// `av_guard` has an audit beside its apply. A call that returned `Ok` and a
/// permission list that says what it was meant to say are different facts, and
/// the second is the one this reports.
fn cheap_pass(context: &Context) -> (u64, Vec<String>) {
    let before = read_back(context);
    let mut unresolved = before.unreadable.clone();
    let mut reapplied = 0u64;
    let mut retried_process = false;
    let mut retried_directories = false;

    if !before.process.is_empty() {
        reapplied += 1;
        retried_process = true;
        if let Err(detail) = context.own.protect() {
            // Two sentences about one object, and deliberately: this one is the
            // call's own answer and the one the second read-back contributes is
            // the object's, and a reader who saw only the second could not tell
            // whether anything had been attempted.
            unresolved.push(format!(
                "this process's protection was found undone and could not be put back: {detail}"
            ));
        }
    }
    if !before.directories.is_empty() {
        reapplied += 1;
        retried_directories = true;
        match files::protect_product_dirs(&context.paths) {
            Ok(dirs) => {
                // `DirProtection::describe` rather than its `detail` field, for
                // the reason `av_guard` gives it one: the sentence has to be
                // readable when `detail` is `None`, which is the case for a
                // directory that was simply not there.
                for dir in dirs.iter().filter(|dir| dir.present && !dir.applied) {
                    unresolved.push(format!(
                        "found undone, and putting it back did not take: {}",
                        dir.describe()
                    ));
                }
            }
            Err(detail) => unresolved.push(format!(
                "the product's directories were found undone and could not be put back: {detail}"
            )),
        }
    }

    if retried_process || retried_directories {
        let after = read_back(context);
        if retried_process {
            unresolved.extend(after.process.iter().map(|right| {
                format!("this process is still reachable by an ordinary account: {right}")
            }));
        }
        if retried_directories {
            unresolved.extend(after.directories.iter().map(|dir| {
                format!("still writable by an ordinary user: {dir}")
            }));
        }
        log::warn!(
            "self-protection had been undone on {reapplied} of this product's objects and has \
             been re-applied; {} problem(s) remain",
            unresolved.len()
        );
    } else if !before.is_intact() {
        // Reachable when every read failed: nothing was re-applied because
        // nothing could be read, and the sentences say so.
        log::debug!("the tamper check could not read part of the machine: {unresolved:?}");
    }

    truncate(&mut unresolved, MAX_UNRESOLVED);
    (reapplied, unresolved)
}

/// One read-back: this process, and every product directory, as they are now.
///
/// # What is deliberately not a finding
///
/// The log directory. [`files::DirRole::users_may_write`] is `true` for it —
/// granting an ordinary user write access there is the design, argued in
/// `av_guard::files` — so a writable log directory is a machine working
/// correctly and re-applying its DACL on every pass would be a service fighting
/// its own configuration.
///
/// Ownership is also not a finding. `DirAudit::owner_can_rewrite_permissions` is
/// true whenever the directory's owner is an ordinary user, and on a layout under
/// a user's own profile — which is what `C:\Users\…\Downloads\WenleAV` is, the
/// layout this product is developed against — it is true however many times the
/// DACL is rewritten, because it is a fact about ownership and no permission list
/// can change it. Re-applying on that condition would be a pass that runs every
/// five minutes for the life of the service, logs a warning every time, and never
/// once improves anything. It is reported where it belongs instead:
/// `wenle protect status` reads it back and `DirAudit::describe` explains it in
/// the same breath as the permissions.
fn read_back(context: &Context) -> ReadBack {
    let mut read = ReadBack::default();

    match context.own.exposed() {
        Ok(rights) => read.process = rights,
        Err(reason) => read
            .unreadable
            .push(format!("this process's access list could not be read: {reason}")),
    }

    for role in files::DirRole::ALL {
        if role.users_may_write() {
            continue;
        }
        let Some(path) = role.path_in(&context.paths) else {
            continue;
        };
        match files::audit(&path) {
            // A directory this installation does not have is not a fault. The
            // roles are a fixed list and a portable layout may have no cache
            // directory at all.
            Ok(audit) if !audit.present => {}
            Ok(audit) if audit.writeable_by_ordinary_user() => read.directories.push(format!(
                "{} ({}) — writable by {}",
                path.display(),
                role.describe(),
                audit.writeable_by.join(", ")
            )),
            Ok(_) => {}
            Err(reason) => read
                .unreadable
                .push(format!("{} could not be read back: {reason}", path.display())),
        }
    }

    read
}

/// One expensive pass: compare the product's files against the manifest.
///
/// Reads and reports; writes nothing. See this module's documentation for why
/// re-recording the manifest on finding a difference would be worse than not
/// checking at all.
fn expensive_pass(context: &Context) -> (ManifestVerdict, Vec<String>) {
    let check = match tamper::self_check(&context.paths, context.service_name) {
        Ok(check) => check,
        // The one error `self_check` returns rather than reports: the manifest
        // exists and was taken against a different installation. There is
        // nothing to compare, and the sentence says what to do about it.
        Err(reason) => return (ManifestVerdict::Unavailable(reason), Vec::new()),
    };

    let alarming = check.changes.iter().filter(|change| change.is_alarming()).count();
    let verdict = verdict_of(&check.manifest, alarming, check.changes.len() - alarming);
    let mut changes: Vec<String> = check.changes.iter().map(|change| change.describe()).collect();

    match &verdict {
        ManifestVerdict::Changed { differences } => {
            // The notification. Logged at `warn` because this is the one thing
            // this module can find that a person has to decide about.
            log::warn!(
                "the product's own files no longer match the manifest taken for this installation: \
                 {differences} of them differ or appeared where the manifest records that nothing \
                 is; nothing has been repaired and the manifest has not been rewritten — run \
                 `wenle protect verify` for the comparison in full"
            );
        }
        // Logged at `info`, not `warn`: nothing the manifest names is different,
        // and the files this names are the ones an installation also holds by
        // accident. It is said because a file that appeared is a question, and
        // said quietly because answering it is not urgent.
        ManifestVerdict::Unexpected { appeared } => {
            log::info!(
                "every file the manifest names is unchanged, and {appeared} file(s) that are not \
                 the product's are in the directories they live in; `wenle protect verify` names \
                 them"
            );
        }
        ManifestVerdict::Unavailable(reason) => {
            log::debug!("the manifest check could not compare anything: {reason}");
        }
        ManifestVerdict::Absent => {
            log::debug!(
                "there is no manifest for this installation, so the product's own files are not \
                 being compared against anything; `wenle protect manifest` records one"
            );
        }
        ManifestVerdict::Clean { files } => log::debug!("{files} product file(s) are unchanged"),
        ManifestVerdict::NotChecked => {}
    }

    truncate(&mut changes, MAX_CHANGES);
    (verdict, changes)
}

/// What a manifest's state and its differences say, as one verdict.
///
/// A pure function over `av-guard`'s own types, so that the mapping can be
/// tested for every state without a manifest on disk — the same split
/// `crate::process_watch` makes between deciding and walking.
///
/// The two counts are separate arguments rather than one total because the
/// verdicts are separate: `alarming` is the files the manifest names that no
/// longer match it, or that appeared where an entry records that nothing is —
/// the kind [`tamper::Change::is_alarming`] answers for — and `appeared` is
/// everything else, which is a file the manifest does not name at all. Passing
/// the total, which this function did until 2026-10-10, made a directory
/// holding a readme report itself as twenty of the product's own files having
/// changed.
fn verdict_of(state: &ManifestState, alarming: usize, appeared: usize) -> ManifestVerdict {
    match state {
        ManifestState::Absent => ManifestVerdict::Absent,
        ManifestState::Unreadable(reason) => ManifestVerdict::Unavailable(reason.clone()),
        ManifestState::Loaded(manifest) if alarming > 0 => {
            ManifestVerdict::Changed { differences: alarming }
        }
        // The manifest's own files are all intact and something is in their
        // directories that it does not name. Reported, and as itself.
        ManifestState::Loaded(_) if appeared > 0 => ManifestVerdict::Unexpected { appeared },
        ManifestState::Loaded(manifest) => ManifestVerdict::Clean {
            files: manifest.entries.len(),
        },
    }
}

/// Cut a list to `limit`, saying so in the last entry rather than in silence.
fn truncate(list: &mut Vec<String>, limit: usize) {
    if list.len() <= limit {
        return;
    }
    let extra = list.len() - limit;
    list.truncate(limit);
    list.push(format!("and {extra} more"));
}

/// Read the state, surviving a worker that panicked while holding it.
///
/// A poisoned lock means a previous pass panicked mid-write. The state is still
/// there — a `Mutex` poisons on unwinding, it does not empty — and refusing to
/// read it would take the service down for a fact about tamper checking, which is
/// the least important thing in it.
fn read(state: &Mutex<TamperState>) -> TamperState {
    match state.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Change the state, for the same reason [`read`] tolerates a poisoned lock.
fn edit(state: &Mutex<TamperState>, change: impl FnOnce(&mut TamperState)) {
    match state.lock() {
        Ok(mut guard) => change(&mut guard),
        Err(poisoned) => change(&mut poisoned.into_inner()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;

    /// How long a test waits for the worker to publish something.
    const DEADLINE: Duration = Duration::from_secs(10);

    /// A layout with every directory the product uses, hardened for real.
    fn hardened_layout() -> (tempfile::TempDir, AvPaths) {
        let (dir, paths) = loose_layout();
        files::protect_product_dirs(&paths).expect("the layout is not the vault");
        (dir, paths)
    }

    /// The same layout, with the directories as a fresh install leaves them.
    ///
    /// # Why the manifest tests need this one
    ///
    /// Because `protect_product_dirs` closes the tree to an ordinary account and
    /// the account running `cargo test` is one, so a test that hardened first and
    /// wrote its fixture afterwards would fail with `Access is denied` — which is
    /// the hardening working, and is what these tests did first. The manifest is
    /// a question about file *contents*; the access control is a different half
    /// of this module and has its own tests. A tree the checker has to repair on
    /// its first pass would also put sentences into the report that these
    /// assertions are not about.
    fn loose_layout() -> (tempfile::TempDir, AvPaths) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let install = dir.path().join("WenleAV");
        std::fs::create_dir_all(&install).expect("creates");
        let paths = AvPaths::with_data_dir(&install, &dir.path().join("data"));
        paths.ensure_dirs().expect("the layout is created");
        (dir, paths)
    }

    /// A process whose access list a test decides, and which counts the repairs.
    #[derive(Default)]
    struct FakeProcess {
        /// Whether the rights are currently closed.
        closed: AtomicBool,
        /// How many times [`OwnProcess::protect`] was called.
        repairs: AtomicU64,
        /// What [`OwnProcess::protect`] answers.
        refuse: AtomicBool,
        /// What [`OwnProcess::exposed`] answers.
        unreadable: AtomicBool,
    }

    impl FakeProcess {
        fn closed() -> Arc<Self> {
            let fake = Arc::new(Self::default());
            fake.closed.store(true, Ordering::SeqCst);
            fake
        }

        fn open() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn repairs(&self) -> u64 {
            self.repairs.load(Ordering::SeqCst)
        }
    }

    impl OwnProcess for FakeProcess {
        fn exposed(&self) -> Result<Vec<String>, String> {
            if self.unreadable.load(Ordering::SeqCst) {
                return Err("access was denied".to_string());
            }
            Ok(if self.closed.load(Ordering::SeqCst) {
                Vec::new()
            } else {
                vec!["Terminate".to_string(), "VmWrite".to_string()]
            })
        }

        fn protect(&self) -> Result<(), String> {
            self.repairs.fetch_add(1, Ordering::SeqCst);
            if self.refuse.load(Ordering::SeqCst) {
                return Err("access was denied".to_string());
            }
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Wait until `done` says so, or fail saying what the state was.
    fn wait_for(
        checker: &Tamper,
        what: &str,
        done: impl Fn(&TamperState) -> bool,
    ) -> TamperState {
        let deadline = Instant::now() + DEADLINE;
        loop {
            let state = checker.state();
            if done(&state) {
                return state;
            }
            assert!(
                Instant::now() < deadline,
                "the checker never {what}: {state:#?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn checking(
        paths: AvPaths,
        own: Arc<dyn OwnProcess>,
    ) -> Tamper {
        // A cheap interval short enough for a test and a long one for the
        // expensive pass, so that the two can be told apart: a test that forced
        // the manifest pass is asking about it and about nothing else.
        Tamper::start_with(
            paths,
            "WenleAvServiceThatThisTestInvented",
            own,
            Duration::from_millis(20),
            Duration::from_secs(3600),
        )
        .expect("the thread can be started")
    }

    #[test]
    fn a_hardened_machine_is_read_and_left_alone() {
        // The pass on a machine nobody has touched. It has to be quiet — no
        // re-apply, nothing unresolved — because a check that repairs something
        // every five minutes on a clean install is a check that is wrong about
        // what "clean" is, and a log nobody can read.
        let (_dir, paths) = hardened_layout();
        let own = FakeProcess::closed();
        let checker = checking(paths, own.clone());

        let state = wait_for(&checker, "ran a pass", |state| state.passes >= 1);
        assert_eq!(state.reapplied, 0, "{state:#?}");
        assert!(state.unresolved.is_empty(), "{state:#?}");
        assert!(state.checking);
        assert!(state.enabled);
        assert_eq!(state.disabled_by, None);
        assert_eq!(own.repairs(), 0, "a clean machine was re-applied to");
        assert!(checker.stop());
    }

    #[test]
    fn protection_that_was_undone_is_put_back_and_counted() {
        // The case the module exists for. The rights were closed and something
        // reopened them; the pass has to notice, close them again, and say so in
        // a number rather than only in a log line.
        let (_dir, paths) = hardened_layout();
        let own = FakeProcess::open();
        let checker = checking(paths, own.clone());

        let state = wait_for(&checker, "put the process's protection back", |state| {
            state.reapplied >= 1
        });
        assert!(own.repairs() >= 1);
        assert!(
            state.unresolved.is_empty(),
            "the repair was reported as having failed: {state:#?}"
        );
        assert!(checker.stop());
    }

    #[test]
    fn protection_that_cannot_be_put_back_is_reported_rather_than_retried_silently() {
        // The unhappy half: the rights are open and the call that would close
        // them is refused. Both sentences have to be there — what the call
        // returned and what the object still says — because a report with only
        // the second would not say whether anything had been attempted.
        let (_dir, paths) = hardened_layout();
        let own = FakeProcess::open();
        own.refuse.store(true, Ordering::SeqCst);
        let checker = checking(paths, own.clone());

        let state = wait_for(&checker, "reported what it could not put back", |state| {
            !state.unresolved.is_empty()
        });
        let joined = state.unresolved.join("\n");
        assert!(
            joined.contains("could not be put back"),
            "the call's own answer is missing: {joined}"
        );
        assert!(
            joined.contains("still reachable by an ordinary account"),
            "the read-back's answer is missing: {joined}"
        );
        assert!(
            joined.contains("Terminate"),
            "the sentence does not name the right that is still open: {joined}"
        );
        assert!(state.has_findings());
        assert!(checker.stop());
    }

    #[test]
    fn an_unreadable_process_is_reported_and_never_counted_as_intact() {
        // The direction the whole crate refuses to guess in: a check that could
        // not read an object must not report it as protected.
        let (_dir, paths) = hardened_layout();
        let own = FakeProcess::closed();
        own.unreadable.store(true, Ordering::SeqCst);
        let checker = checking(paths, own);

        let state = wait_for(&checker, "reported the unreadable object", |state| {
            !state.unresolved.is_empty()
        });
        assert!(
            state.unresolved[0].contains("could not be read"),
            "{state:#?}"
        );
        assert_eq!(state.reapplied, 0);
        assert!(checker.stop());
    }

    #[test]
    fn a_manifest_that_has_changed_is_reported_and_never_re_recorded() {
        // The plan's item 9, and the invariant this module is built around.
        // `Manifest::capture` would write the tampered file out as the new
        // baseline; a service that did that on finding a difference would
        // destroy the evidence of the tampering it had just detected.
        let (_dir, paths) = loose_layout();
        let database = paths.db_dir.join("rules.avdb");
        std::fs::write(&database, b"the rules as they were").expect("writes");

        let manifest_path = tamper::manifest_path(&paths);
        tamper::Manifest::capture(&paths)
            .expect("the layout can be hashed")
            .save(&manifest_path)
            .expect("the manifest can be written");
        let before = std::fs::read(&manifest_path).expect("reads");

        // Now change the file the manifest recorded.
        std::fs::write(&database, b"the rules as something else left them").expect("writes");

        let own = FakeProcess::closed();
        let checker = checking(paths.clone(), own);
        checker.check_now();
        let state = wait_for(&checker, "compared the files", |state| {
            state.manifest_checks >= 1
        });

        match &state.manifest {
            ManifestVerdict::Changed { differences } => assert_eq!(*differences, 1, "{state:#?}"),
            other => panic!("the changed file was not reported: {other:?}"),
        }
        assert!(
            state.changes.iter().any(|line| line.contains("rules.avdb")),
            "the report does not name the file that changed: {state:#?}"
        );

        // The invariant. Both halves: the manifest's bytes are the ones that
        // were there before the check, and no temporary file was left behind —
        // `Manifest::save` writes `integrity.manifest.new` and renames, so a
        // re-capture in flight would show up as one.
        assert_eq!(
            std::fs::read(&manifest_path).expect("reads"),
            before,
            "the manifest was rewritten by the check that found it out of date"
        );
        let stray: Vec<PathBuf> = std::fs::read_dir(
            manifest_path.parent().expect("the manifest has a parent"),
        )
        .expect("the data directory can be listed")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "new"))
        .collect();
        assert!(stray.is_empty(), "a manifest was left half-written: {stray:?}");
    }

    #[test]
    fn a_clean_manifest_is_reported_as_clean_and_not_as_absent() {
        // The other direction of the same check, so that the test above is not
        // passing because the comparison never happens: the same layout, with
        // nothing changed, has to come back `Clean` with a file count.
        let (_dir, paths) = loose_layout();
        std::fs::write(paths.db_dir.join("rules.avdb"), b"the rules").expect("writes");
        tamper::Manifest::capture(&paths)
            .expect("the layout can be hashed")
            .save(&tamper::manifest_path(&paths))
            .expect("the manifest can be written");

        let checker = checking(paths, FakeProcess::closed());
        checker.check_now();
        let state = wait_for(&checker, "compared the files", |state| {
            state.manifest_checks >= 1
        });
        match &state.manifest {
            ManifestVerdict::Clean { files } => assert!(*files >= 1, "{state:#?}"),
            other => panic!("an unchanged installation was not reported as clean: {other:?}"),
        }
        assert!(state.changes.is_empty(), "{state:#?}");
        assert!(!state.has_findings());
        assert!(checker.stop());
    }

    #[test]
    fn an_installation_with_no_manifest_is_not_reported_as_clean() {
        // A fresh install has no manifest, and this is the state a client must
        // not read as "checked and fine". It is also not an alarm: taking one is
        // a command an administrator runs.
        let (_dir, paths) = hardened_layout();
        let checker = checking(paths, FakeProcess::closed());
        checker.check_now();
        let state = wait_for(&checker, "reported the missing manifest", |state| {
            state.manifest_checks >= 1
        });
        assert_eq!(state.manifest, ManifestVerdict::Absent);
        assert!(!state.has_findings());
        assert!(checker.stop());
    }

    /// One entry of a manifest this process never touched.
    ///
    /// Built by hand rather than captured, so that the mapping test has no
    /// filesystem in it: the question under test is what a state *means*, and a
    /// test that had to write a manifest to ask it could only run where writing
    /// one works.
    fn absent_entry() -> tamper::Entry {
        tamper::Entry {
            role: tamper::Role::Cli,
            path: PathBuf::from(r"C:\WenleAV\wenle.exe"),
            present: false,
            size: 0,
            sha256: [0u8; 32],
            signature: tamper::Signature::NotAProgram,
        }
    }

    #[test]
    fn every_manifest_state_maps_to_its_own_verdict() {
        // The mapping, without a filesystem. Every state `av-guard` produces has
        // to reach a distinct verdict, because two of them folded together would
        // read a machine nobody has checked as a machine with nothing wrong.
        let manifest = tamper::Manifest {
            version: tamper::MANIFEST_VERSION,
            roots: tamper::Roots {
                install_dir: PathBuf::from(r"C:\WenleAV"),
                data_dir: PathBuf::from(r"C:\WenleAV\data"),
            },
            captured_at: 0,
            entries: vec![absent_entry(), absent_entry()],
        };
        let loaded = ManifestState::Loaded(Box::new(manifest));

        assert_eq!(verdict_of(&ManifestState::Absent, 0, 0), ManifestVerdict::Absent);
        assert!(matches!(
            verdict_of(&ManifestState::Unreadable("truncated".to_string()), 0, 0),
            ManifestVerdict::Unavailable(reason) if reason == "truncated"
        ));
        assert_eq!(
            verdict_of(&loaded, 0, 0),
            ManifestVerdict::Clean { files: 2 }
        );
        assert_eq!(
            verdict_of(&loaded, 3, 0),
            ManifestVerdict::Changed { differences: 3 }
        );
        // The state the VM was in on 2026-10-10: every file the manifest names
        // matches, and twenty files that are not the product's sit beside them.
        // `Clean` would be the product not saying what it saw and `Changed`
        // would be it saying something false.
        assert_eq!(
            verdict_of(&loaded, 0, 20),
            ManifestVerdict::Unexpected { appeared: 20 }
        );
        // Both at once is `Changed`, which leads the report; the appeared files
        // are still in `changes` beside it.
        assert_eq!(
            verdict_of(&loaded, 1, 20),
            ManifestVerdict::Changed { differences: 1 }
        );

        // And the words are all different, so a user interface cannot print two
        // states the same way.
        let words = [
            ManifestVerdict::NotChecked.as_str(),
            ManifestVerdict::Absent.as_str(),
            ManifestVerdict::Clean { files: 0 }.as_str(),
            ManifestVerdict::Changed { differences: 0 }.as_str(),
            ManifestVerdict::Unexpected { appeared: 0 }.as_str(),
            ManifestVerdict::Unavailable(String::new()).as_str(),
        ];
        let mut sorted = words.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), words.len(), "two verdicts read the same");
    }

    #[test]
    fn a_long_list_is_cut_and_says_how_much_was_cut() {
        // A machine where everything was replaced would otherwise put a sentence
        // per file into every status answer for the rest of the service's life,
        // and a silently truncated list reads as a complete one.
        let mut list: Vec<String> = (0..20).map(|n| format!("difference {n}")).collect();
        truncate(&mut list, 4);
        assert_eq!(list.len(), 5);
        assert_eq!(list[4], "and 16 more");
        assert!(list[0].contains("difference 0"));

        // A list at or under the limit is untouched, and no note is added.
        let mut short = vec!["one".to_string()];
        truncate(&mut short, 4);
        assert_eq!(short, vec!["one".to_string()]);
    }

    #[test]
    fn the_log_directory_is_never_a_finding() {
        // The one role an ordinary user may write, by design. A pass that
        // re-applied to it would be a service fighting its own configuration
        // every five minutes.
        assert!(files::DirRole::Log.users_may_write());
        let (_dir, paths) = hardened_layout();
        // Taken from the role's own answer rather than from a list written here,
        // so that a new writable role cannot be added without this test noticing.
        let writable: Vec<PathBuf> = files::DirRole::ALL
            .iter()
            .filter(|role| role.users_may_write())
            .filter_map(|role| role.path_in(&paths))
            .collect();
        assert_eq!(writable, vec![paths.log_dir.clone()]);

        let own = FakeProcess::closed();
        let context = Context {
            paths,
            service_name: "WenleAvServiceThatThisTestInvented",
            own,
            cheap: CHEAP_INTERVAL,
            expensive: EXPENSIVE_INTERVAL,
        };
        let read = read_back(&context);
        assert!(read.is_intact(), "{read:#?}");
    }

    #[test]
    fn a_directory_that_lost_its_permissions_is_put_back() {
        // The directory half, for real and against a temporary layout. The
        // permissions are taken away the way they actually go away — by putting
        // back what was there before the product hardened them — using
        // `av_guard`'s own record-and-restore pair rather than a hand-written
        // DACL, so that the tampering this test simulates is the tampering
        // `wenle protect restore` performs and not an invented one.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let install = dir.path().join("WenleAV");
        std::fs::create_dir_all(&install).expect("creates");
        let paths = AvPaths::with_data_dir(&install, &dir.path().join("data"));
        paths.ensure_dirs().expect("the layout is created");

        // Recorded *before* hardening, which is the only moment the loose
        // permissions exist — `DaclRecord::capture` says so itself.
        let loose = files::DaclRecord::capture(&paths).expect("the layout can be recorded");
        files::protect_product_dirs(&paths).expect("the layout is not the vault");

        let own = FakeProcess::closed();
        let context = Context {
            paths: paths.clone(),
            service_name: "WenleAvServiceThatThisTestInvented",
            own,
            cheap: CHEAP_INTERVAL,
            expensive: EXPENSIVE_INTERVAL,
        };
        assert!(read_back(&context).is_intact(), "the hardened layout is not intact");

        // Undo the hardening, and check that it really was undone before asking
        // the pass to notice: a setup that silently did nothing would make this
        // test pass for the wrong reason.
        for restoration in files::restore_dacls(&loose) {
            assert!(
                restoration.outcome.is_applied(),
                "the setup could not undo {}: {}",
                restoration.path.display(),
                restoration.outcome.describe()
            );
        }
        let target = paths.db_dir.clone();
        let loosened = files::audit(&target).expect("readable");
        assert!(
            loosened.writeable_by_ordinary_user(),
            "the setup did not open {}: {}",
            target.display(),
            loosened.summary
        );

        let before = read_back(&context);
        assert!(!before.directories.is_empty(), "{before:#?}");

        let (reapplied, unresolved) = cheap_pass(&context);
        assert_eq!(reapplied, 1, "the directory was not counted as repaired");
        assert!(unresolved.is_empty(), "{unresolved:#?}");
        assert!(
            read_back(&context).is_intact(),
            "the pass reported a repair the read-back does not agree with"
        );
        assert!(
            !files::audit(&target)
                .expect("readable")
                .writeable_by_ordinary_user(),
            "the pass reported a repair it did not make"
        );
    }

    #[test]
    fn a_checker_that_cannot_start_its_thread_says_so() {
        // The same shape `crate::process_watch` reports, and for the same
        // reason: a service that cannot create a thread must say so rather than
        // report a protection it is not running.
        let error = TamperError::WorkerSpawn {
            source: std::io::Error::other("no more threads"),
        };
        let text = error.to_string();
        assert!(text.contains("thread"), "{text}");
        assert!(text.contains("no more threads"), "{text}");
    }

    #[test]
    fn the_default_state_is_not_a_machine_that_was_checked() {
        // What a report from a build without this field is read as. The one
        // answer that must not be the default is "clean".
        let default = TamperState::default();
        assert!(!default.checking);
        assert!(!default.enabled);
        assert_eq!(default.manifest, ManifestVerdict::NotChecked);
        assert!(default.disabled_by.is_some());
        assert!(!default.has_findings());
    }

    #[test]
    fn the_intervals_are_the_ones_the_module_documents() {
        // Two constants that decide how often the machine is read, asserted so
        // that a change to either is a change to this test as well.
        assert_eq!(CHEAP_INTERVAL, Duration::from_secs(300));
        assert_eq!(EXPENSIVE_INTERVAL, Duration::from_secs(6 * 60 * 60));
        assert!(CHEAP_INTERVAL < EXPENSIVE_INTERVAL);
        assert!(POLL <= CHEAP_INTERVAL);
    }
}
