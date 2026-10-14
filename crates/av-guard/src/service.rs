//! The installed service: how it starts, and what happens when it stops.
//!
//! # The threat, and why it is not the one people expect
//!
//! The obvious attack on an antivirus service is to stop it, and the obvious
//! defence is to make stopping it need administrator rights. The defence is
//! already there and this module did not put it there: the Service Control
//! Manager gives every service a security descriptor of its own on creation, and
//! the default one grants `NT AUTHORITY\INTERACTIVE` and `SERVICE` the query
//! rights (`CC` (`SERVICE_QUERY_CONFIG`), `LC` (`SERVICE_QUERY_STATUS`), `SW`
//! (`SERVICE_ENUMERATE_DEPENDENTS`), `LO` (`SERVICE_INTERROGATE`), `CR`
//! (`SERVICE_USER_DEFINED_CONTROL`) and `RC` (`READ_CONTROL`)) and **not**
//! `RP` (`SERVICE_START`) or `WP` (`SERVICE_STOP`). Measured on this machine:
//! opening a running service with `SERVICE_STOP` from an ordinary account is
//! refused with `ERROR_ACCESS_DENIED`, and the same account can open it with
//! `SERVICE_QUERY_STATUS`. See `the_scm_already_denies_stop_to_an_ordinary_user`.
//!
//! So an ordinary user cannot stop the service through the SCM, and the attack
//! that remains is the one an ordinary user *can* mount: make the service stop
//! itself. Crash it through a malformed input, exhaust its memory, or take the
//! process out with `TerminateProcess` (the last of which is
//! [`crate::process`]'s job), and the first two are the reason a security product
//! parses untrusted input behind a verdict threshold and a size ceiling.
//!
//! Which leaves this module with two jobs, and neither is "stop people stopping
//! it":
//!
//! * **Make a crash recoverable.** [`configure_recovery`] tells the SCM what to
//!   do when the service dies, and the answer is: restart it, three times,
//!   quickly at first and then more slowly, with the count reset after a day.
//!   A service that comes back is worth more than a service that cannot be
//!   stopped, because the attacks that actually work make it stop. The other
//!   write in this module is the same remedy for a quieter failure:
//!   [`ensure_starts_by_itself`] puts the start type back to one that starts at
//!   boot, for a service somebody has set to manual or disabled.
//! * **Check what is true rather than what was configured.** [`integrity`]
//!   reads the start type, the recovery policy, the account and the running
//!   state back off the machine. Every one of those is something an
//!   administrator, an installer or a previous version of this product may have
//!   changed, and a hardening pass that reported its own intentions would report
//!   them again on a machine where they no longer hold.
//!
//! # Why delayed automatic start, and when it is wrong
//!
//! [`configure_start`] takes a [`StartKind`], and the two that are a real choice
//! are [`StartKind::AutomaticDelayed`] and [`StartKind::Manual`]. The default
//! the rest of this crate assumes is delayed automatic, for the reason Windows
//! has the category at all: a service started `SERVICE_AUTO_START` is started
//! during boot, and an antivirus that scans a database on the way up is a
//! machine that boots slowly, which is what makes people uninstall antivirus
//! software.
//!
//! [`DEFAULT_START`] is that choice as a value, and [`ensure_starts_by_itself`]
//! is the repair built on it: it writes [`DEFAULT_START`] over a service that
//! does not start by itself and writes nothing to one that already does. Delayed
//! automatic is *not* imposed on a service that is already plain
//! automatic: see that function for why a machine that is protected does not
//! get its configuration rewritten.
//!
//! The honest cost of that choice is a window. A delayed service starts roughly
//! two minutes after boot, and for those two minutes the machine's *policy* half
//! is not running: real-time decisions come from the kernel driver and the
//! minifilter, which are loaded early and are not this module's business. If a
//! future version puts a decision in the service that nothing else can make, the
//! start kind has to change to [`StartKind::Automatic`] and this paragraph is
//! the reason. [`StartKind::Manual`] is not a policy for a security product at
//! all: it is here because a portable or diagnostic installation needs it, and
//! because `query_start` has to be able to report it.
//!
//! # The trap in the delayed flag
//!
//! `QueryServiceConfig` cannot tell you whether a service is delayed. It reports
//! `SERVICE_AUTO_START`, and the delay lives in a *second* structure reached
//! through `SERVICE_CONFIG_DELAYED_AUTO_START_INFO`, so a check that read the
//! start type and stopped would call a delayed service and a boot-start service
//! the same thing. [`query_start`] asks both questions and reports
//! [`StartKind::AutomaticDelayed`] only when the second one says so.
//!
//! The same shape causes a bug in the other direction:
//! `SERVICE_CONFIG_DELAYED_AUTO_START_INFO` has no effect on a service that is
//! not `SERVICE_AUTO_START`, and setting the *start type* back to automatic does
//! not clear a delay that is already set. [`configure_start`] therefore writes
//! both, always, including the `false`, so that asking for
//! [`StartKind::Automatic`] on a service that was delayed actually removes the
//! delay instead of leaving a setting nobody asked for pointing the other way.
//!
//! # Why the third action is thirty seconds and not another restart
//!
//! The action list is finite by design: `SC_ACTION` entries are spent in order
//! and there is no fourth, so the product stops trying when the list runs out.
//!
//! Three attempts at 5, 10 and 30 seconds is the policy here, and the widening
//! gaps are what tell a transient from a real failure. A service that fails once
//! is usually a transient: a dependency that was not up yet, a file that was
//! briefly locked. A service
//! that fails three times in a row is failing for a reason a faster retry will
//! not fix, and restarting it every five seconds forever is a machine that never
//! settles, with a log nobody can read and a support case that says "it keeps
//! restarting". The thirty-second third attempt keeps the recovery attempt alive
//! long enough for a slow dependency without the retry loop being the thing that
//! keeps the machine busy, and after it the service is **stopped**: visible in
//! the services console, with an error code and a log file, which is a state
//! somebody can diagnose.
//!
//! `dwResetPeriod` is a day: a service that crashed once on Monday and once on
//! Tuesday has crashed twice, not twice in a row, and should get the fast retry
//! again. Without a reset period the three actions are spent for the lifetime of
//! the boot.
//!
//! # What is deliberately not done here
//!
//! * **`SC_ACTION_REBOOT` and `SC_ACTION_RUN_COMMAND` are not used.** The first
//!   would restart a user's machine because a service failed, which is a
//!   hostile thing for an antivirus to do and needs `SeShutdownPrivilege`; the
//!   second would run an arbitrary command as `LocalSystem` on a failure path,
//!   which is a privilege escalation waiting for a writable path. Only
//!   `SC_ACTION_RESTART` is used.
//! * **No service security descriptor is written.** The default one already
//!   denies an ordinary user `SERVICE_STOP`, and narrowing it further would lock
//!   out the recovery tools an administrator needs at exactly the moment they
//!   are needed. The measurement is in the module documentation above.
//! * **This module cannot make a service that is already broken start.** If the
//!   binary is gone or the account cannot log on, recovery restarts it three
//!   times and stops. [`ServiceIntegrity`] reports that state rather than
//!   looping.
//!
//! # Every error names the next step
//!
//! A Win32 code on its own is not something a person can act on, so every
//! function here returns a sentence naming the service and the operation, and
//! and, for `ERROR_ACCESS_DENIED`, the step that fixes it. Which step depends on
//! whether this process is already elevated, and that is checked rather than
//! assumed: [`elevation_advice`] says "run this from an elevated prompt" only
//! when this process is not elevated, because a message that repeats that advice
//! to an administrator is a message that wastes the one minute they were willing
//! to spend on it.

use std::time::Duration;

/// The start type the SCM will use, including the delayed flag that
/// `QueryServiceConfig` cannot see on its own.
///
/// The four real variants are the SCM's four start types plus the delayed
/// distinction, and [`StartKind::Unrecognised`] exists so that this mapping is
/// total: the SCM can legally report a start type this crate has never heard of
/// — `SERVICE_BOOT_START` and `SERVICE_SYSTEM_START` are real values that driver
/// services use — and a `query_start` that panicked or lied about them would be
/// worse than one that says what it saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartKind {
    /// `SERVICE_AUTO_START` with the delayed flag set: starts shortly after
    /// boot rather than during it.
    AutomaticDelayed,
    /// `SERVICE_AUTO_START`: the SCM starts it as part of boot.
    Automatic,
    /// `SERVICE_DEMAND_START`: only starts when something asks it to.
    Manual,
    /// `SERVICE_DISABLED`: the SCM will refuse to start it.
    ///
    /// A disabled antivirus service is a *finding*, not a configuration: see
    /// [`ServiceIntegrity::describe`], which says so rather than printing it as
    /// one more state.
    Disabled,
    /// A start type this crate does not know, reported rather than rounded.
    Unrecognised(u32),
}

impl StartKind {
    /// The SCM's `dwStartType`, as a [`StartKind`].
    ///
    /// `delayed` is the separate answer from
    /// `SERVICE_CONFIG_DELAYED_AUTO_START_INFO`, and it can only turn
    /// `SERVICE_AUTO_START` into [`StartKind::AutomaticDelayed`]: the delay has
    /// no meaning on any other start type, so a machine that reported it on one
    /// is reported as the start type it actually has.
    pub const fn from_raw(raw: u32, delayed: bool) -> Self {
        match raw {
            SERVICE_AUTO_START if delayed => StartKind::AutomaticDelayed,
            SERVICE_AUTO_START => StartKind::Automatic,
            SERVICE_DEMAND_START => StartKind::Manual,
            SERVICE_DISABLED => StartKind::Disabled,
            other => StartKind::Unrecognised(other),
        }
    }

    /// Whether the SCM starts this service by itself.
    pub const fn is_automatic(self) -> bool {
        matches!(self, StartKind::Automatic | StartKind::AutomaticDelayed)
    }

    /// One phrase for a report.
    pub const fn describe(self) -> &'static str {
        match self {
            StartKind::AutomaticDelayed => "starts automatically, shortly after boot",
            StartKind::Automatic => "starts automatically, during boot",
            StartKind::Manual => "starts only when something asks it to",
            StartKind::Disabled => "is disabled and will not start at all",
            StartKind::Unrecognised(_) => "has a start type this build does not recognise",
        }
    }
}

/// The recovery policy [`configure_recovery`] applies, and the shape
/// [`integrity`] reads back.
///
/// Delays are in seconds because that is the unit the answers are reasoned about
/// in; the SCM's own unit is milliseconds and the conversion happens in one place
/// in `to_actions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    /// How long to wait before each restart attempt, in seconds, in order.
    pub delays: [Duration; 3],
    /// How long a service must run before its failure count is forgotten.
    pub reset_after: Duration,
    /// Whether a failure that is not a crash also triggers the actions.
    pub on_non_crash_failure: bool,
}

/// Restart after 5, 10 and 30 seconds; forget failures after a day; count
/// failures that are not crashes.
///
/// The reasoning for each of these is in the module documentation — in short,
/// widening gaps so that a transient is retried quickly and a real fault is not
/// retried forever, a day so that a service that failed yesterday gets the fast
/// retry today, and the non-crash flag because a service that exits with a
/// non-zero code without crashing is a service that failed, which is the whole
/// point of the flag.
pub const DEFAULT_RECOVERY: Recovery = Recovery {
    delays: [
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(30),
    ],
    reset_after: Duration::from_secs(24 * 60 * 60),
    on_non_crash_failure: true,
};

/// The start type this product repairs a service to: automatic, shortly after
/// boot.
///
/// Delayed rather than plain automatic because the delay is free and the boot is
/// not: nothing on the machine needs the scanner before the desktop is up, and a
/// service that starts with the boot-time drivers makes every start slower for
/// no protection it does not have thirty seconds later. `SERVICE_AUTO_START` is
/// what `av_service::install` creates the service with, and this is what
/// [`ensure_starts_by_itself`] writes over a service that is not starting at all.
pub const DEFAULT_START: StartKind = StartKind::AutomaticDelayed;

/// What [`ensure_starts_by_itself`] found, and whether it had to write.
///
/// `Already` rather than an `Option`, because "the service was already starting
/// by itself and this product left it alone" is a fact a report has to be able to
/// state — the alternative is a command that says nothing where the user is
/// wondering whether it did something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOutcome {
    /// It already starts by itself. Nothing was written; the variant carries what
    /// the SCM reports.
    Already(StartKind),
    /// It did not, and both of these are what the SCM reported: `before` as it was
    /// read, `after` as the read-back following the write. Both, because which
    /// state was repaired is a finding of its own — a service that was `Disabled`
    /// is a different fact about the machine from one that was merely `Manual`,
    /// and a report that printed only the new value would lose it.
    Set {
        /// The start type before the write.
        before: StartKind,
        /// The start type the SCM reported after it, read back rather than
        /// assumed to be what was asked for.
        after: StartKind,
    },
}

impl Recovery {
    /// The three delays, in seconds, as a report prints them.
    pub fn delays_in_seconds(&self) -> [u64; 3] {
        [
            self.delays[0].as_secs(),
            self.delays[1].as_secs(),
            self.delays[2].as_secs(),
        ]
    }

    /// Whether this policy would actually recover a service.
    ///
    /// Every delay must be non-zero — a zero delay is a tight restart loop, not
    /// a recovery policy — and the reset period must be non-zero, because with a
    /// zero reset period the SCM resets the failure count on every failure and
    /// the three actions are never spent, which is the "restart forever"
    /// behaviour this module deliberately does not configure.
    pub fn is_recoverable(&self) -> bool {
        self.delays.iter().all(|delay| !delay.is_zero()) && !self.reset_after.is_zero()
    }

    /// One sentence for a report.
    ///
    /// The last clause is written from the flag rather than appended
    /// unconditionally, because a report that claimed the non-crash behaviour on
    /// a service configured without it would be describing a policy the machine
    /// does not have — and the whole point of [`ServiceIntegrity`] is that it
    /// reports the machine.
    pub fn describe(&self) -> String {
        let [first, second, third] = self.delays_in_seconds();
        let mut text = format!(
            "restarts after {first}s, {second}s and {third}s and forgets a failure after {}s",
            self.reset_after.as_secs()
        );
        if self.on_non_crash_failure {
            text.push_str(", and treats a failure that is not a crash as a failure");
        } else {
            text.push_str(", and counts only a crash as a failure");
        }
        text
    }
}

/// What the machine says about the service, as opposed to what was configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIntegrity {
    /// The service's name, as it was asked about.
    pub name: String,
    /// Its start type, with the delayed flag resolved.
    pub start: StartKind,
    /// Its recovery policy, or `None` when the SCM has none configured.
    pub recovery: Option<Recovery>,
    /// The account it runs as, as the SCM reports it.
    pub account: String,
    /// Whether the SCM says it is running right now.
    pub running: bool,
    /// Its description, when it has one.
    pub description: Option<String>,
}

impl ServiceIntegrity {
    /// Whether this service is configured the way a security product's service
    /// should be.
    ///
    /// Four things, and each is a way a product can be quietly off: the service
    /// must start by itself (otherwise it is not running after the next boot),
    /// it must not be disabled (`is_automatic` covers that), it must have a
    /// recovery policy that would really attempt a restart, and it must be
    /// running now.
    ///
    /// It is deliberately *not* a check on the account. Running as `LocalSystem`
    /// is what this product does and what it needs, and a service running as
    /// `NetworkService` is a decision somebody made — reported by
    /// [`ServiceIntegrity::describe`] rather than failed here, because a
    /// hardening report that refuses to say "yes" until the account matches one
    /// string is a report nobody runs twice.
    pub fn is_hardened(&self) -> bool {
        self.start.is_automatic()
            && self.running
            && self
                .recovery
                .is_some_and(|recovery| recovery.is_recoverable())
    }

    /// One line for a person, leading with the thing that is wrong when
    /// something is.
    ///
    /// A disabled service and a stopped service are the two states that mean the
    /// machine is unprotected, so they are named first and in those words. A
    /// missing recovery policy is next, because it is the difference between a
    /// crash the product survives and one that leaves the machine unguarded until
    /// somebody reboots it.
    ///
    /// No full stop and no trailing space: this is a fragment, and the two
    /// callers that print it — [`crate::tamper::SelfCheck::lines`] as
    /// `Service: …`, and `av_service::selfprotect` as a line of its own — each
    /// decide how the line ends. It carried its own `". "` until 2026-10-11,
    /// which the first of them turned into `… after a reboot. .` in
    /// `wenle protect status`, on every machine whose service is not automatic.
    pub fn describe(&self) -> String {
        let mut parts = vec![format!("{} {}", self.name, self.start.describe())];
        if self.running {
            parts.push(format!("is running now, as {}", self.account));
        } else {
            parts.push(format!(
                "is NOT running right now (the SCM reports it stopped); it would run as {}",
                self.account
            ));
        }
        match &self.recovery {
            Some(recovery) if recovery.is_recoverable() => {
                parts.push(format!("and {}", recovery.describe()));
            }
            Some(_) => parts.push(
                "and has a recovery policy that would not actually restart it: every delay is \
                 zero, or the failure count resets on every failure"
                    .to_string(),
            ),
            None => parts.push(
                "and has NO recovery configured, so a crash would leave it stopped until \
                 something starts it by hand"
                    .to_string(),
            ),
        }
        if let Some(description) = &self.description {
            parts.push(format!("It describes itself as \"{description}\""));
        }
        let mut line = parts.join(", ").replace(", and has", " and has");
        if !self.start.is_automatic() {
            line = format!(
                "{} — this is not a service that starts by itself, so the machine is not \
                 protected after a reboot",
                line
            );
        }
        line
    }
}

/// Configure the recovery policy to [`DEFAULT_RECOVERY`].
///
/// Two calls, because the SCM keeps them in two places and neither is optional:
/// `SERVICE_CONFIG_FAILURE_ACTIONS` for the actions and the reset period, and
/// `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG` for whether a failure that is not a
/// crash counts. Without the flag the actions apply only when the service
/// *crashes*, which sounds like the same thing and is not: a service that calls
/// `ExitProcess(1)`, or that the SCM stops because it failed to report its
/// status in time, is not a crash, and a policy that ignored it would leave the
/// product down after the failure mode it is most likely to hit.
///
/// Needs two rights on the service and not one — `SERVICE_CHANGE_CONFIG` for the
/// write and `SERVICE_START` for the restart action inside it; see
/// `SET_RECOVERY_ACCESS`, which is where that was measured. The default security
/// descriptor gives an administrator both; an ordinary user has neither, and the
/// service's own `LocalSystem` account has the second and not the first. A
/// refusal comes back as a sentence naming the service and the step that fixes
/// it.
pub fn configure_recovery(name: &str) -> Result<Recovery, String> {
    scm::set_recovery(name, DEFAULT_RECOVERY)?;
    // Read back rather than returning what was asked for: the whole point of
    // this crate is that a call that returned success is not the same fact as a
    // machine that is configured.
    let recovery = query_recovery(name)?;
    Ok(recovery.unwrap_or(DEFAULT_RECOVERY))
}

/// Read the recovery policy back.
///
/// `Ok(None)` when the SCM has no failure actions for this service, which is the
/// state every freshly installed service is in and is a finding rather than an
/// error — see [`ServiceIntegrity::describe`].
pub fn query_recovery(name: &str) -> Result<Option<Recovery>, String> {
    scm::query_recovery(name)
}

/// Set the start type.
///
/// Returns what the SCM reports *after* the change, not what was asked for. The
/// difference matters for [`StartKind::AutomaticDelayed`], which is two settings
/// in two places: a caller that asked for a delayed start and got an immediate
/// one has a machine that boots more slowly than they think, and a caller that
/// asked to remove a delay and did not has a machine that is unprotected for two
/// minutes longer than they think.
///
/// # Errors
///
/// A refusal names the service and the next step. `SERVICE_DISABLED` on a
/// running service is accepted by the SCM and stops it at the next boot rather
/// than immediately, which is the SCM's behaviour and worth knowing before
/// reading a report that says the service is still running.
pub fn configure_start(name: &str, kind: StartKind) -> Result<StartKind, String> {
    scm::set_start(name, kind)?;
    query_start(name)
}

/// Read the start type, including the delayed flag.
///
/// Asks two questions, because the SCM keeps the answer in two places — see the
/// module documentation for why a single `QueryServiceConfig` cannot distinguish
/// a delayed service from a boot-start one.
pub fn query_start(name: &str) -> Result<StartKind, String> {
    scm::query_start(name)
}

/// Make the service start by itself, unless it already does.
///
/// # Why this is a command and not something the service does to itself
///
/// The same split [`configure_recovery`] documents at length: a service running
/// as `LocalSystem` has `SERVICE_QUERY_CONFIG` on its own service and not
/// `SERVICE_CHANGE_CONFIG`, so no service can change its own start type and a
/// command with an administrator's token has to. `wenle protect status` fails on
/// a service that does not start by itself, and until 2026-10-11 the only remedy
/// it named was `sc config … start= delayed-auto` — a step outside the product
/// for a fact the product can repair.
///
/// # Why a service that already starts by itself is left alone
///
/// A plain automatic service is not a machine that is unprotected: it starts
/// during boot, which is the question [`ServiceIntegrity::is_hardened`] asks
/// through [`StartKind::is_automatic`]. Rewriting it to a delayed start would be
/// this command changing a decision somebody made about their own machine, so
/// what is repaired is the state `protect status` actually fails on — a service
/// that only starts when something asks it to, one that is disabled, or one whose
/// start type this build does not recognise.
///
/// # Errors
///
/// Fails when the service does not exist, when this account may not read or write
/// its configuration, and when the write is accepted but the read-back disagrees
/// — the last of which is what [`configure_start`] exists to catch.
pub fn ensure_starts_by_itself(name: &str) -> Result<StartOutcome, String> {
    let before = query_start(name)?;
    match start_type_repair(before) {
        None => Ok(StartOutcome::Already(before)),
        Some(wanted) => Ok(StartOutcome::Set {
            before,
            after: configure_start(name, wanted)?,
        }),
    }
}

/// What to ask the SCM for, given the start type the machine reports now.
///
/// The whole of [`ensure_starts_by_itself`]'s rule, split out because the calls
/// around it cannot be exercised without a service this machine owns: a test
/// that wanted to check the write half would have to pick a real service to
/// write to, and a test that changes the machine it runs on is worse than no
/// test. `None` means write nothing.
const fn start_type_repair(before: StartKind) -> Option<StartKind> {
    if before.is_automatic() {
        None
    } else {
        Some(DEFAULT_START)
    }
}

/// Set the description the services console shows.
///
/// Worth doing and not worth much: it is the line an administrator reads when
/// they are trying to work out what a service on a machine is, and the
/// alternative on a machine with a stopped service and no description is somebody
/// deciding to disable it rather than to look at it.
///
/// An empty `text` is accepted by the SCM and clears the description.
pub fn configure_description(name: &str, text: &str) -> Result<(), String> {
    scm::set_description(name, text)
}

/// Read the recovery policy, start type, account and running state together.
///
/// One call rather than four so that a report is a snapshot: four separate reads
/// can straddle a change and produce a state that never existed, which on a
/// hardening report is worse than a slightly stale one.
///
/// # Errors
///
/// Fails when the service does not exist, or when this account may not read its
/// configuration. Both come back as a sentence naming the service rather than as
/// a Win32 code, because the caller here is usually a command a person typed.
pub fn integrity(name: &str) -> Result<ServiceIntegrity, String> {
    scm::integrity(name)
}

/// Whether this process is running with an elevated token.
///
/// Used by [`elevation_advice`], and measured rather than assumed for a reason
/// that shows up in practice: an administrator who has already elevated is told
/// to elevate by every tool that hard-codes the advice, and the advice stops
/// being read. A process on a standard user's desktop is not elevated, and
/// `SeDebugPrivilege`-free or not is a separate question this does not answer.
pub fn is_elevated() -> bool {
    scm::is_elevated()
}

/// The sentence to append to an access-denied failure.
///
/// Two sentences, chosen by [`is_elevated`], because the step that fixes a
/// refusal is different in the two cases: an unelevated process needs to be run
/// again from an elevated prompt, and an elevated one that is still refused is
/// looking at a service object whose permissions do not grant this account the
/// right — which is a thing an administrator has to look at, not a thing
/// re-running will fix.
pub fn elevation_advice() -> &'static str {
    if is_elevated() {
        "This process is already running elevated, so the account itself does not have permission \
         on that service. Check the service's permissions with `sc sdshow <name>`, and note that \
         a service created by another product may grant its configuration only to that product's \
         account."
    } else {
        "Changing a service needs administrator rights. Run this from an elevated prompt — \
         right-click the terminal, then \"Run as administrator\"."
    }
}

/// `SERVICE_AUTO_START`, `SERVICE_DEMAND_START` and `SERVICE_DISABLED`, for the
/// half of this module that is not behind `cfg(windows)`.
///
/// Mirrored here rather than imported because the `windows` crate is a Windows
/// target dependency — see the crate documentation — and because the mapping in
/// [`StartKind::from_raw`] is the part of this module a test on any machine can
/// check. The values are the ones in `winsvc.h` and they are not negotiable.
const SERVICE_AUTO_START: u32 = 2;
const SERVICE_DEMAND_START: u32 = 3;
const SERVICE_DISABLED: u32 = 4;

/// The access a write to the service's failure actions needs, as one mask:
/// `SERVICE_CHANGE_CONFIG` (`0x0002`) for the write itself and `SERVICE_START`
/// (`0x0010`) for the restart action it installs.
///
/// **`SERVICE_CHANGE_CONFIG` alone is not enough, and the refusal it earns looks
/// like a permissions problem that is not there.** Microsoft's reference for
/// `ChangeServiceConfig2W` says it in the `SERVICE_CONFIG_FAILURE_ACTIONS`
/// paragraphs: *"If the service controller handles the `SC_ACTION_RESTART`
/// action, the caller must have the `SERVICE_START` access right in addition to
/// `SERVICE_CHANGE_CONFIG`."* It is not mentioned anywhere an implementer
/// usually looks, so it is the kind of requirement that has to be measured.
///
/// **Measured in the VM, 2026-10-10.** `OpenServiceW(SERVICE_CHANGE_CONFIG)`
/// *succeeded* and the `ChangeServiceConfig2W` that followed came back
/// `ERROR_ACCESS_DENIED`, so `wenle protect apply` reported that the
/// administrator running it had no permission on a service whose security
/// descriptor grants that administrator both rights and more. The distinction
/// that matters: this is a right the *handle* was opened without, not a right the
/// *account* lacks — which is why the sentence that was printed was wrong about
/// the machine.
///
/// The service's own account is refused for the other reason and stays refused:
/// `LocalSystem` has `SERVICE_START` on its own service and not
/// `SERVICE_CHANGE_CONFIG`, so the service can read the policy back and cannot
/// write it — see `av_service::selfprotect`.
const SET_RECOVERY_ACCESS: u32 = 0x0002 | 0x0010;

#[cfg(windows)]
mod scm {
    //! The calls, and the handles that have to be closed exactly once.
    //!
    //! Split out for the same reason [`crate::files`] splits its platform half
    //! out in `av-quarantine`: the values, the mapping and the sentences are
    //! ordinary logic that any machine can check, and the calls are the part that
    //! needs a Windows SCM to say anything at all.

    use core::ffi::c_void;
    use std::time::Duration;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_DOES_NOT_EXIST,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, OpenSCManagerW,
        OpenServiceW, QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatusEx,
        ENUM_SERVICE_TYPE, SC_ACTION_RESTART, SC_HANDLE, SC_STATUS_PROCESS_INFO, SERVICE_AUTO_START,
        SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
        SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW,
        SERVICE_DISABLED, SERVICE_ERROR, SERVICE_FAILURE_ACTIONSW, SERVICE_FAILURE_ACTIONS_FLAG,
        SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_STATUS_PROCESS, QUERY_SERVICE_CONFIGW,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{elevation_advice, Recovery, StartKind};

    /// The value `SERVICE_NO_CHANGE` carries, in the type each parameter of
    /// `ChangeServiceConfigW` wants.
    ///
    /// The `windows` crate exports `SERVICE_NO_CHANGE` as a bare `u32` while the
    /// parameters are newtypes, so it does not fit any of the three slots it is
    /// meant for and has to be wrapped once per type. Three named constants
    /// rather than a cast at the call site, because the three are the same
    /// integer meaning the same thing and a reader should not have to work out
    /// which newtype each one is.
    const SERVICE_TYPE_UNCHANGED: ENUM_SERVICE_TYPE = ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE);
    const SERVICE_ERROR_UNCHANGED: SERVICE_ERROR = SERVICE_ERROR(SERVICE_NO_CHANGE);

    /// A scratch buffer the SCM can write a struct with pointers into.
    ///
    /// `Vec<u64>` rather than `Vec<u8>` for the alignment: `QUERY_SERVICE_CONFIGW`
    /// and `SERVICE_FAILURE_ACTIONSW` hold pointers, the SCM fills them with
    /// offsets into the buffer it was handed, and a `Vec<u8>` whose allocator
    /// happened to return an odd address would make every one of those a
    /// misaligned read. Eight bytes is the strictest alignment any of these
    /// structs needs on the platforms this product runs on, and `Vec<u64>` costs
    /// nothing to get it.
    fn scratch(needed: u32) -> Vec<u64> {
        let words = (needed as usize).div_ceil(size_of::<u64>());
        vec![0u64; words.max(1)]
    }

    /// `buffer`, as the `&mut [u8]` of `needed` bytes the `windows` crate's
    /// safer wrappers want.
    ///
    /// The length is clamped to the buffer's real size and floored at one byte,
    /// because `needed` is zero on the failure paths that continue anyway — and
    /// an empty slice would be a null pointer with a zero size, which is the
    /// "tell me how big it should be" call and not the one that reads anything.
    fn scratch_bytes(buffer: &mut [u64], needed: u32) -> &mut [u8] {
        let capacity = size_of_val(buffer);
        let length = (needed as usize).max(1).min(capacity);
        // SAFETY: `length` is within `buffer`, and `buffer` is `u64`-aligned,
        // which is at least as strict as any struct the SCM writes here.
        unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), length) }
    }

    use core::mem::size_of;

    /// An `SC_HANDLE` closed exactly once, on every path out.
    ///
    /// The same guard as `av-service`'s, and it has to exist in both places for
    /// the reason the two crates are separate at all: `av-service` installs and
    /// controls a service, this crate hardens one, and a hardening crate that
    /// depended on the service crate could not harden a service that failed to
    /// start. The cost is one twenty-line guard in each.
    struct Handle(SC_HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from `OpenSCManagerW` or `OpenServiceW`
            // and has not been closed; it is owned by this guard and by nothing
            // else. The result is dropped because a close that fails has already
            // had whatever effect it was going to have.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }

    /// A NUL-terminated UTF-16 buffer.
    fn to_wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A `PWSTR` from the SCM, as a `String`.
    ///
    /// # Safety
    ///
    /// `pointer` must be null or point at a NUL-terminated UTF-16 string that
    /// stays alive for the call. The SCM's `QUERY_SERVICE_CONFIGW` fills its
    /// pointers with offsets into the buffer the caller passed, so a string read
    /// here is only valid while that buffer is.
    unsafe fn read_wide(pointer: PWSTR) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0usize;
        // SAFETY: the caller guarantees a NUL-terminated string, and this stops
        // at the first NUL.
        unsafe {
            while *pointer.0.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(pointer.0, length))
        }
    }

    /// The Win32 code inside a `windows` error, masked out of the `HRESULT`.
    ///
    /// `Error::code()` is an `HRESULT`, and a Win32 failure arrives as
    /// `HRESULT_FROM_WIN32(code)` — `0x8007_0000 | code`. Comparing the whole
    /// value against `5` for `ERROR_ACCESS_DENIED` never matches, so every
    /// access-denied path in this module would report a generic failure while
    /// looking entirely correct. `av-service` has the same mask and the same
    /// comment, and it cannot be shared for the reason the guard cannot.
    fn code(error: &windows::core::Error) -> u32 {
        (error.code().0 as u32) & 0xFFFF
    }

    /// A failed call, as a sentence naming the operation and the next step.
    fn failed(what: &str, error: &windows::core::Error) -> String {
        if code(error) == ERROR_ACCESS_DENIED.0 {
            return format!("{what} was refused: access is denied. {}", elevation_advice());
        }
        format!("{what} failed (Win32 error {}): {}", code(error), error.message())
    }

    /// Open the SCM's database.
    fn manager() -> Result<Handle, String> {
        // SAFETY: a null machine name means this machine and a null database
        // name means the active database, which is what the SCM documents `NULL`
        // to mean for both. The call takes no buffer and retains nothing.
        let handle = unsafe {
            OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
        };
        handle
            .map(Handle)
            .map_err(|error| failed("opening the service database", &error))
    }

    /// `SC_MANAGER_CONNECT`, which the `windows` crate does not export as a
    /// constant in this feature set.
    const SC_MANAGER_CONNECT: u32 = 0x0001;

    /// Open the service with `access`.
    fn service(name: &str, access: u32) -> Result<Handle, String> {
        let manager = manager()?;
        let wide = to_wide(name);
        // SAFETY: `wide` is NUL-terminated and outlives the call; `manager`
        // owns a live SCM handle for the duration.
        let opened = unsafe { OpenServiceW(manager.0, PCWSTR(wide.as_ptr()), access) };
        match opened {
            Ok(handle) => Ok(Handle(handle)),
            Err(error) if code(&error) == ERROR_SERVICE_DOES_NOT_EXIST.0 => Err(format!(
                "there is no service called `{name}` on this machine, so it cannot be read or \
                 changed. Install it first, or check the name — `sc query state= all` lists what \
                 is installed."
            )),
            Err(error) => Err(failed(
                &format!("opening the `{name}` service"),
                &error,
            )),
        }
    }

    /// A buffer size query: the first call fails with
    /// `ERROR_INSUFFICIENT_BUFFER` and tells you the size, which is the
    /// documented two-call shape rather than an error.
    fn size_needed(error: &windows::core::Error, needed: u32) -> Option<u32> {
        if code(error) == ERROR_INSUFFICIENT_BUFFER.0 && needed > 0 {
            Some(needed)
        } else {
            None
        }
    }

    /// Read the start type, asking the delayed question separately.
    pub(super) fn query_start(name: &str) -> Result<StartKind, String> {
        let handle = service(name, SERVICE_QUERY_CONFIG)?;
        let config = read_config(&handle, name)?;
        // `SERVICE_CONFIG_DELAYED_AUTO_START_INFO` on a service that is not
        // auto-start is legal and meaningless, so the answer is only believed
        // when the start type makes it meaningful — see
        // `StartKind::from_raw`.
        let delayed = read_delayed(&handle).unwrap_or(false);
        Ok(StartKind::from_raw(config, delayed))
    }

    /// `QueryServiceConfigW`'s `dwStartType`, through the two-call size idiom.
    fn read_config(handle: &Handle, name: &str) -> Result<u32, String> {
        let mut needed = 0u32;
        // SAFETY: a null buffer with a zero size is the documented way to ask
        // for the size; `needed` is a live out-parameter. The expected failure
        // carries the size and is handled below.
        let first = unsafe { QueryServiceConfigW(handle.0, None, 0, &mut needed) };
        if let Err(error) = first {
            if size_needed(&error, needed).is_none() {
                return Err(failed(
                    &format!("reading the configuration of `{name}`"),
                    &error,
                ));
            }
        }
        // `scratch` is aligned and at least `needed` bytes, and its string
        // fields point back into it, which is why the buffer outlives every read
        // taken from the struct below.
        let mut buffer = scratch(needed);
        let bytes = (buffer.len() * size_of::<u64>()) as u32;
        let mut needed_again = 0u32;
        // SAFETY: `buffer` is at least `needed` bytes and aligned for the
        // struct; the API writes a `QUERY_SERVICE_CONFIGW` into it.
        let config = unsafe {
            QueryServiceConfigW(
                handle.0,
                Some(buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
                bytes,
                &mut needed_again,
            )
        };
        config.map_err(|error| {
            failed(
                &format!("reading the configuration of `{name}`"),
                &error,
            )
        })?;
        // SAFETY: the call succeeded, so the buffer holds an initialised
        // `QUERY_SERVICE_CONFIGW`.
        let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
        Ok(config.dwStartType.0)
    }

    /// The `SERVICE_CONFIG_DELAYED_AUTO_START_INFO` flag.
    ///
    /// A failure to read it is reported as `None` rather than as an error,
    /// because the flag is the *second* question and a service that refuses to
    /// answer it still has a start type worth reporting. A `None` is treated as
    /// "not delayed", which reports a delayed service as a boot-start one — a
    /// wrong answer, and the one that is wrong in the direction of the product
    /// looking *better* than it is, which is why it is logged.
    fn read_delayed(handle: &Handle) -> Option<bool> {
        let mut info = SERVICE_DELAYED_AUTO_START_INFO::default();
        let mut needed = 0u32;
        // SAFETY: `info` is a live local and the slice covers exactly its bytes;
        // the API writes at most one `SERVICE_DELAYED_AUTO_START_INFO`.
        let slice = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut info as *mut SERVICE_DELAYED_AUTO_START_INFO).cast::<u8>(),
                size_of::<SERVICE_DELAYED_AUTO_START_INFO>(),
            )
        };
        let read = unsafe {
            QueryServiceConfig2W(
                handle.0,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                Some(slice),
                &mut needed,
            )
        };
        match read {
            Ok(()) => Some(info.fDelayedAutostart.as_bool()),
            Err(error) => {
                log::debug!(
                    "the delayed start flag could not be read (Win32 error {}), so this service \
                     is reported as starting during boot rather than shortly after it",
                    code(&error)
                );
                None
            }
        }
    }

    /// `SERVICE_CONFIG_FAILURE_ACTIONS` plus `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`.
    pub(super) fn set_recovery(name: &str, recovery: Recovery) -> Result<(), String> {
        // Two rights and not one: `SERVICE_CHANGE_CONFIG` names the write, and
        // `SERVICE_START` is what the restart action in it is checked against.
        // Asking for only the first is what made this call fail in the VM while
        // the handle it held was refused for a right nobody names — see
        // `SET_RECOVERY_ACCESS`.
        let handle = service(name, super::SET_RECOVERY_ACCESS)?;
        let actions = super::to_actions(recovery);
        let info = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: recovery.reset_after.as_secs() as u32,
            // No reboot message and no command: this module restarts the service
            // and does nothing else, and an empty message is how that is said.
            lpRebootMsg: PWSTR::null(),
            lpCommand: PWSTR::null(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_ptr().cast_mut(),
        };
        // SAFETY: `info` is a live struct whose `lpsaActions` points at
        // `actions`, which is alive for the call; the API copies both and
        // retains neither.
        let set = unsafe {
            ChangeServiceConfig2W(
                handle.0,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                Some((&info as *const SERVICE_FAILURE_ACTIONSW).cast::<c_void>()),
            )
        };
        set.map_err(|error| {
            failed(
                &format!("setting the recovery options for `{name}`"),
                &error,
            )
        })?;

        let flag = SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: recovery.on_non_crash_failure.into(),
        };
        // SAFETY: as above — a live struct, read by the API and not retained.
        let flagged = unsafe {
            ChangeServiceConfig2W(
                handle.0,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                Some((&flag as *const SERVICE_FAILURE_ACTIONS_FLAG).cast::<c_void>()),
            )
        };
        flagged.map_err(|error| {
            failed(
                &format!(
                    "the recovery actions for `{name}` were set but the flag that makes them \
                     apply to a failure that is not a crash was not"
                ),
                &error,
            )
        })
    }

    /// Read the recovery policy back, both halves of it.
    pub(super) fn query_recovery(name: &str) -> Result<Option<Recovery>, String> {
        let handle = service(name, SERVICE_QUERY_CONFIG)?;
        let mut needed = 0u32;
        // SAFETY: a null buffer with a zero size asks for the size; the expected
        // failure carries it.
        let first = unsafe {
            QueryServiceConfig2W(handle.0, SERVICE_CONFIG_FAILURE_ACTIONS, None, &mut needed)
        };
        if let Err(error) = first {
            if size_needed(&error, needed).is_none() {
                // No failure actions configured is reported by the SCM as an
                // empty structure rather than as a failure on some versions and
                // as `ERROR_INVALID_PARAMETER` on others; both mean the same
                // thing to a caller, and neither is worth failing a report over.
                log::debug!(
                    "the recovery options of `{name}` could not be read (Win32 error {}), which \
                     is reported as no recovery configured",
                    code(&error)
                );
                return Ok(None);
            }
        }
        let mut buffer = scratch(needed);
        let mut needed_again = 0u32;
        // SAFETY: `buffer` is at least `needed` bytes and aligned; the API
        // writes a `SERVICE_FAILURE_ACTIONSW` into it whose `lpsaActions`
        // points into the same buffer, which is why it outlives the reads
        // below.
        let read = unsafe {
            QueryServiceConfig2W(
                handle.0,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                Some(scratch_bytes(&mut buffer, needed)),
                &mut needed_again,
            )
        };
        if let Err(error) = read {
            log::debug!(
                "the recovery options of `{name}` could not be read (Win32 error {})",
                code(&error)
            );
            return Ok(None);
        }
        // SAFETY: the call succeeded, so the buffer holds an initialised
        // `SERVICE_FAILURE_ACTIONSW` and an array of `cActions` `SC_ACTION`s.
        let (reset_after, actions) = unsafe {
            let info = &*buffer.as_ptr().cast::<SERVICE_FAILURE_ACTIONSW>();
            let count = info.cActions as usize;
            let slice = if info.lpsaActions.is_null() || count == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(info.lpsaActions, count)
            };
            (info.dwResetPeriod, slice)
        };
        if actions.is_empty() {
            return Ok(None);
        }
        // The first three restart actions, in order. Anything that is not an
        // `SC_ACTION_RESTART` — this product never sets one — is reported as a
        // zero delay so that `is_recoverable` calls the policy what it is.
        let mut delays = DEFAULT_DELAYS;
        for (slot, action) in delays.iter_mut().zip(actions.iter()) {
            if action.Type == SC_ACTION_RESTART {
                *slot = Duration::from_millis(u64::from(action.Delay));
            }
        }
        let on_non_crash_failure = read_non_crash_flag(&handle).unwrap_or(false);
        Ok(Some(Recovery {
            delays,
            reset_after: Duration::from_secs(u64::from(reset_after)),
            on_non_crash_failure,
        }))
    }

    /// The three delays a report starts from before the SCM's actions overwrite
    /// them.
    const DEFAULT_DELAYS: [Duration; 3] = [
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(30),
    ];

    /// Whether a failure that is not a crash triggers the recovery actions.
    fn read_non_crash_flag(handle: &Handle) -> Option<bool> {
        let mut flag = SERVICE_FAILURE_ACTIONS_FLAG::default();
        let mut needed = 0u32;
        // SAFETY: `flag` is a live local and the slice covers exactly its bytes;
        // the API writes at most one `SERVICE_FAILURE_ACTIONS_FLAG`.
        let slice = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut flag as *mut SERVICE_FAILURE_ACTIONS_FLAG).cast::<u8>(),
                size_of::<SERVICE_FAILURE_ACTIONS_FLAG>(),
            )
        };
        let read = unsafe {
            QueryServiceConfig2W(
                handle.0,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                Some(slice),
                &mut needed,
            )
        };
        read.ok().map(|()| flag.fFailureActionsOnNonCrashFailures.as_bool())
    }

    /// Set the start type, and the delayed flag with it.
    pub(super) fn set_start(name: &str, kind: StartKind) -> Result<(), String> {
        // The value is checked *before* the service is opened, so that a caller
        // who passed a variant this build cannot write is told about the
        // argument and not about the machine. A refusal that depended on the
        // service existing would be a guard that opens a handle on the way to
        // saying no.
        let (raw, delayed) = match kind {
            StartKind::AutomaticDelayed => (SERVICE_AUTO_START, true),
            StartKind::Automatic => (SERVICE_AUTO_START, false),
            StartKind::Manual => (SERVICE_DEMAND_START, false),
            StartKind::Disabled => (SERVICE_DISABLED, false),
            StartKind::Unrecognised(raw) => {
                // Refused rather than written. An unrecognised start type came
                // from a report of this machine, and writing it back would be
                // this crate setting a value it does not understand — which is
                // how a driver service's `SERVICE_BOOT_START` would end up on
                // the antivirus service.
                return Err(format!(
                    "`{}` is not a start type this build can set, so `{name}` was left alone. \
                     Use automatic, delayed automatic, manual or disabled.",
                    raw
                ));
            }
        };
        let handle = service(name, SERVICE_CHANGE_CONFIG)?;
        // SAFETY: every string argument is `SERVICE_NO_CHANGE`'s null, which the
        // API documents as "leave this alone", and the start type is a plain
        // integer. The handle is live for the call.
        let changed = unsafe {
            ChangeServiceConfigW(
                handle.0,
                SERVICE_TYPE_UNCHANGED,
                raw,
                SERVICE_ERROR_UNCHANGED,
                PCWSTR::null(),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
        };
        changed.map_err(|error| {
            failed(&format!("setting the start type of `{name}`"), &error)
        })?;

        // Always written, including the `false`, and this is the trap the module
        // documentation describes: setting the start type back to plain
        // automatic does not clear a delay that is already set, so a caller that
        // asked for a boot-start service and did not write this would get a
        // delayed one and a report that said otherwise.
        let info = SERVICE_DELAYED_AUTO_START_INFO {
            fDelayedAutostart: delayed.into(),
        };
        // SAFETY: a live struct, read by the API and not retained.
        let flag = unsafe {
            ChangeServiceConfig2W(
                handle.0,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                Some((&info as *const SERVICE_DELAYED_AUTO_START_INFO).cast::<c_void>()),
            )
        };
        flag.map_err(|error| {
            failed(
                &format!("setting the delayed start flag of `{name}`"),
                &error,
            )
        })
    }

    /// Set the description.
    pub(super) fn set_description(name: &str, text: &str) -> Result<(), String> {
        let handle = service(name, SERVICE_CHANGE_CONFIG)?;
        let mut wide = to_wide(text);
        let description = SERVICE_DESCRIPTIONW {
            lpDescription: PWSTR(wide.as_mut_ptr()),
        };
        // SAFETY: `wide` is NUL-terminated and outlives the call; the API reads
        // the string during the call and retains nothing.
        let set = unsafe {
            ChangeServiceConfig2W(
                handle.0,
                SERVICE_CONFIG_DESCRIPTION,
                Some((&description as *const SERVICE_DESCRIPTIONW).cast::<c_void>()),
            )
        };
        set.map_err(|error| {
            failed(
                &format!("setting the description of `{name}`"),
                &error,
            )
        })
    }

    /// Everything [`super::integrity`] reports, read in one pass.
    pub(super) fn integrity(name: &str) -> Result<super::ServiceIntegrity, String> {
        // One handle for the config half, so that the start type and the account
        // cannot disagree about which service they are describing.
        let handle = service(
            name,
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )?;
        let raw_start = read_config(&handle, name)?;
        let delayed = read_delayed(&handle).unwrap_or(false);
        let start = StartKind::from_raw(raw_start, delayed);
        let account = read_account(&handle)?;
        let description = read_description(&handle);
        // Dropped before the recovery read, which opens its own handle: the SCM
        // serialises configuration reads against a lock, and holding two handles
        // for one service across two calls is a way to wait on yourself.
        drop(handle);
        let recovery = query_recovery(name)?;
        let running = is_running(name)?;
        Ok(super::ServiceIntegrity {
            name: name.to_string(),
            start,
            recovery,
            account,
            running,
            description,
        })
    }

    /// The account the service runs as, as the SCM reports it.
    fn read_account(handle: &Handle) -> Result<String, String> {
        // The buffer from `read_config` is not kept, so this reads the
        // configuration a second time rather than restructuring that function to
        // return a buffer and a struct that points into it. The cost is one call
        // on a path a person runs by hand.
        let mut needed = 0u32;
        // SAFETY: a null buffer with a zero size asks for the size; the expected
        // failure carries it.
        let first = unsafe { QueryServiceConfigW(handle.0, None, 0, &mut needed) };
        if let Err(error) = first {
            if size_needed(&error, needed).is_none() {
                return Err(failed(
                    "reading the account a service runs as",
                    &error,
                ));
            }
        }
        let mut buffer = scratch(needed);
        let bytes = (buffer.len() * size_of::<u64>()) as u32;
        let mut needed_again = 0u32;
        // SAFETY: as in `read_config` — an aligned buffer of at least the size
        // the SCM asked for.
        let read = unsafe {
            QueryServiceConfigW(
                handle.0,
                Some(buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
                bytes,
                &mut needed_again,
            )
        };
        read.map_err(|error| failed("reading the account a service runs as", &error))?;
        // SAFETY: the call succeeded, so the buffer holds an initialised struct
        // whose pointers are offsets into the same buffer, which is alive here.
        let account = unsafe {
            let config = &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>();
            read_wide(config.lpServiceStartName)
        };
        // An empty `lpServiceStartName` means `LocalSystem` — the SCM leaves it
        // blank rather than writing the name out, and a report that showed
        // nothing would read as "this service runs as nobody".
        Ok(if account.is_empty() {
            "LocalSystem".to_string()
        } else {
            account
        })
    }

    /// The description, or `None` when there is none.
    fn read_description(handle: &Handle) -> Option<String> {
        let mut needed = 0u32;
        // SAFETY: as above.
        let first = unsafe {
            QueryServiceConfig2W(handle.0, SERVICE_CONFIG_DESCRIPTION, None, &mut needed)
        };
        if let Err(error) = first {
            // `None` from `size_needed` means the failure was not the documented
            // "here is the size" one, so there is nothing to read.
            size_needed(&error, needed)?;
        }
        let mut buffer = scratch(needed);
        let mut needed_again = 0u32;
        // SAFETY: as in `read_config`.
        let read = unsafe {
            QueryServiceConfig2W(
                handle.0,
                SERVICE_CONFIG_DESCRIPTION,
                Some(scratch_bytes(&mut buffer, needed)),
                &mut needed_again,
            )
        };
        read.ok()?;
        // SAFETY: the call succeeded, so the buffer holds an initialised
        // `SERVICE_DESCRIPTIONW` whose string points into the same buffer.
        let text = unsafe {
            let info = &*buffer.as_ptr().cast::<SERVICE_DESCRIPTIONW>();
            read_wide(info.lpDescription)
        };
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Whether the SCM says the service is running.
    ///
    /// A separate handle with `SERVICE_QUERY_STATUS`, because the state is the
    /// one thing here that changes while a report is being assembled and reading
    /// it last is the closest thing to reading it fresh.
    fn is_running(name: &str) -> Result<bool, String> {
        let handle = service(name, SERVICE_QUERY_STATUS)?;
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        // SAFETY: `status` is a live local and the slice covers exactly its
        // bytes; the API writes at most one `SERVICE_STATUS_PROCESS`.
        let slice = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast::<u8>(),
                size_of::<SERVICE_STATUS_PROCESS>(),
            )
        };
        let read = unsafe {
            QueryServiceStatusEx(handle.0, SC_STATUS_PROCESS_INFO, Some(slice), &mut needed)
        };
        read.map_err(|error| {
            failed(
                &format!("reading the running state of `{name}`"),
                &error,
            )
        })?;
        Ok(status.dwCurrentState == SERVICE_RUNNING)
    }

    /// Whether this process has an elevated token.
    ///
    /// `TokenElevation` rather than a group check: membership of
    /// `BUILTIN\Administrators` says what the account *can* do and the token says
    /// what it *is* doing, and the advice in [`elevation_advice`] is about the
    /// second one. A failure to read the token is reported as "not elevated",
    /// which gives the *more* cautious advice.
    pub(super) fn is_elevated() -> bool {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
        // closing, and `token` is a live out-parameter that `OpenProcessToken`
        // fills with a handle this function closes below.
        let opened =
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened.is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        // SAFETY: `token` is a live token handle with `TOKEN_QUERY`, and
        // `elevation` is a live, correctly typed out-parameter whose size is
        // passed.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        };
        // SAFETY: the handle came from `OpenProcessToken` and is closed exactly
        // once, here, on both paths.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(token);
        }
        read.is_ok() && elevation.TokenIsElevated != 0
    }

    /// Open a service with `access` and throw the handle away, reporting only
    /// whether the SCM allowed it.
    ///
    /// The measurement the tests need and the module documentation quotes: an
    /// access check on a service is a fact about this machine's SCM permissions,
    /// and the only way to have it is to ask. The handle is closed by the guard
    /// as this returns, so nothing is held and nothing is changed.
    #[cfg(test)]
    pub(super) fn open_with(name: &str, access: u32) -> Result<(), String> {
        service(name, access).map(|_opened| ())
    }

    /// The delayed-start flag for `name`, or `None` when the SCM would not
    /// answer.
    ///
    /// Exposed so that the tests can measure the second query on a real service
    /// without reaching into the private handles. A `None` here is the silent
    /// failure the module documentation warns about: it is reported as "not
    /// delayed", so a machine where this always fails reports every delayed
    /// service as a boot-start one.
    #[cfg(test)]
    pub(super) fn delayed_flag(name: &str) -> Result<Option<bool>, String> {
        let handle = service(name, SERVICE_QUERY_CONFIG)?;
        Ok(read_delayed(&handle))
    }
}

#[cfg(not(windows))]
mod scm {
    //! The refusals a build without a Service Control Manager gets.
    //!
    //! Named errors rather than `unreachable!`: this is ordinary library code
    //! that a second platform would compile, and the honest thing is a refusal
    //! that says why.

    use super::{Recovery, ServiceIntegrity, StartKind};

    fn no_scm() -> String {
        "this build has no Service Control Manager, so it cannot read or configure a service"
            .to_string()
    }

    pub(super) fn query_start(_name: &str) -> Result<StartKind, String> {
        Err(no_scm())
    }
    pub(super) fn set_start(_name: &str, _kind: StartKind) -> Result<(), String> {
        Err(no_scm())
    }
    pub(super) fn set_recovery(_name: &str, _recovery: Recovery) -> Result<(), String> {
        Err(no_scm())
    }
    pub(super) fn query_recovery(_name: &str) -> Result<Option<Recovery>, String> {
        Err(no_scm())
    }
    pub(super) fn set_description(_name: &str, _text: &str) -> Result<(), String> {
        Err(no_scm())
    }
    pub(super) fn integrity(_name: &str) -> Result<ServiceIntegrity, String> {
        Err(no_scm())
    }
    pub(super) fn is_elevated() -> bool {
        false
    }
    #[cfg(test)]
    pub(super) fn open_with(_name: &str, _access: u32) -> Result<(), String> {
        Err(no_scm())
    }
    #[cfg(test)]
    pub(super) fn delayed_flag(_name: &str) -> Result<Option<bool>, String> {
        Err(no_scm())
    }
}

/// The `SC_ACTION` array for a [`Recovery`].
///
/// In seconds-to-milliseconds one place, because `SC_ACTION.Delay` is in
/// milliseconds while every other duration in this module is in seconds, and a
/// mix-up there is a service that restarts after five milliseconds instead of
/// five seconds — a tight loop rather than a recovery, and one that looks
/// completely correct in the code that configured it.
///
/// `SC_ACTION_RESTART` and never `SC_ACTION_REBOOT` or `SC_ACTION_RUN_COMMAND`:
/// see the module documentation.
#[cfg(windows)]
fn to_actions(recovery: Recovery) -> [windows::Win32::System::Services::SC_ACTION; 3] {
    use windows::Win32::System::Services::{SC_ACTION, SC_ACTION_RESTART};

    let millis = |delay: Duration| -> u32 {
        // Saturating rather than truncating: a delay too large for the field is
        // reported as the largest it can be rather than wrapping to a small one.
        u32::try_from(delay.as_millis()).unwrap_or(u32::MAX)
    };
    [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: millis(recovery.delays[0]),
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: millis(recovery.delays[1]),
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: millis(recovery.delays[2]),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A service name that must not exist, for the tests that check the
    /// *refusal* paths.
    ///
    /// Deliberately not the product's own service name: the write paths in this
    /// module change a machine, and a test that used the real name would change
    /// the real service on any machine where one is installed — including a
    /// developer's. The tests in here must be safe to run on a machine with the
    /// product installed, and the only way to be sure of that is to name
    /// something that cannot be there.
    const ABSENT: &str = "WenleAvServiceGuardTestDoesNotExist";

    /// A service that is present on every Windows installation this product
    /// runs on, for the read-only measurements.
    ///
    /// The Event Log service: it is a Windows component, it is present on
    /// client and server SKUs alike, and it is not something a test can damage
    /// by reading its configuration. Every test that uses it is read-only and
    /// says so.
    const PRESENT: &str = "EventLog";

    #[test]
    fn the_start_types_are_the_scms_four_and_the_delayed_flag_is_separate() {
        assert_eq!(StartKind::from_raw(2, false), StartKind::Automatic);
        assert_eq!(StartKind::from_raw(2, true), StartKind::AutomaticDelayed);
        assert_eq!(StartKind::from_raw(3, false), StartKind::Manual);
        assert_eq!(StartKind::from_raw(4, false), StartKind::Disabled);
        // The delay has no meaning on anything but auto-start, so a machine that
        // reports it there is reported as the start type it really has.
        assert_eq!(StartKind::from_raw(3, true), StartKind::Manual);
        assert_eq!(StartKind::from_raw(4, true), StartKind::Disabled);
        // `SERVICE_BOOT_START` and `SERVICE_SYSTEM_START` are real values that
        // driver services use, and a total mapping has to report them rather
        // than round them to something plausible.
        assert_eq!(StartKind::from_raw(0, false), StartKind::Unrecognised(0));
        assert_eq!(StartKind::from_raw(1, false), StartKind::Unrecognised(1));
        assert_eq!(
            StartKind::from_raw(u32::MAX, false),
            StartKind::Unrecognised(u32::MAX)
        );
        // Automatic in both spellings, and nothing else, is a service that
        // starts by itself.
        assert!(StartKind::Automatic.is_automatic());
        assert!(StartKind::AutomaticDelayed.is_automatic());
        assert!(!StartKind::Manual.is_automatic());
        assert!(!StartKind::Disabled.is_automatic());
        assert!(!StartKind::Unrecognised(0).is_automatic());
        // Every variant has a sentence, including the one that carries a value.
        for kind in [
            StartKind::AutomaticDelayed,
            StartKind::Automatic,
            StartKind::Manual,
            StartKind::Disabled,
            StartKind::Unrecognised(7),
        ] {
            assert!(!kind.describe().is_empty(), "{kind:?}");
        }
    }

    #[test]
    fn the_default_recovery_is_the_three_widening_delays_the_module_documents() {
        assert_eq!(
            DEFAULT_RECOVERY.delays_in_seconds(),
            [5, 10, 30],
            "the policy is 5, 10 and 30 seconds — see the module documentation for why the gaps \
             widen and why there is no fourth action"
        );
        assert_eq!(
            DEFAULT_RECOVERY.reset_after,
            Duration::from_secs(86_400),
            "a failure count that never resets spends the three actions for the life of the boot"
        );
        // A `const` block because the value is a constant: this is a property of
        // the policy that a future edit must not lose, so it is checked when the
        // crate is compiled rather than when a test is run. Without the non-crash
        // flag the actions apply only to a crash, which is not how a service
        // usually dies.
        const {
            assert!(
                DEFAULT_RECOVERY.on_non_crash_failure,
                "the default recovery policy must count a failure that is not a crash"
            )
        }
        assert!(DEFAULT_RECOVERY.is_recoverable());
        // A zero delay or a zero reset period is a tight restart loop rather
        // than a policy, and `is_recoverable` has to say so — the reset period
        // especially, because a zero one means the SCM forgets each failure
        // immediately and the three actions are never spent.
        assert!(!Recovery {
            delays: [Duration::ZERO, Duration::from_secs(1), Duration::from_secs(1)],
            ..DEFAULT_RECOVERY
        }
        .is_recoverable());
        assert!(!Recovery {
            reset_after: Duration::ZERO,
            ..DEFAULT_RECOVERY
        }
        .is_recoverable());
        // And the sentence a person reads carries the numbers.
        let described = DEFAULT_RECOVERY.describe();
        assert!(described.contains('5') && described.contains("30"), "{described}");
        assert!(described.contains("86400"), "{described}");
        let quiet = Recovery {
            on_non_crash_failure: false,
            ..DEFAULT_RECOVERY
        }
        .describe();
        assert!(!quiet.contains("not a crash"), "{quiet}");
    }

    #[test]
    fn the_recovery_write_asks_for_service_start_as_well_as_change_config() {
        // Both bits, and the second is the whole of the bug this pins. A
        // `SERVICE_CHANGE_CONFIG`-only handle is refused by the SCM on a service
        // whose failure actions are restarts — and refused in a way that reads as
        // the account lacking a permission it actually has. See
        // `SET_RECOVERY_ACCESS` for the measurement and the documentation quote.
        assert_eq!(
            SET_RECOVERY_ACCESS & 0x0002,
            0x0002,
            "`SERVICE_CHANGE_CONFIG` is what the write itself is checked against"
        );
        assert_eq!(
            SET_RECOVERY_ACCESS & 0x0010,
            0x0010,
            "`SERVICE_START` is what the `SC_ACTION_RESTART` actions need on top of it; without \
             it every `apply` on an elevated prompt reports an access-denied that the security \
             descriptor does not explain"
        );
    }

    #[test]
    fn the_elevation_advice_matches_whether_this_process_is_elevated() {
        // The sentence is chosen by measurement, not hard-coded, because advice
        // that tells an administrator to elevate is advice they stop reading.
        let advice = elevation_advice();
        if is_elevated() {
            assert!(advice.contains("already running elevated"), "{advice}");
            assert!(!advice.contains("right-click"), "{advice}");
        } else {
            assert!(advice.contains("Run as administrator"), "{advice}");
            assert!(!advice.contains("already running elevated"), "{advice}");
        }
        // Either way it names the next step rather than a Win32 code.
        assert!(!advice.contains("0x"), "{advice}");
    }

    #[test]
    fn a_service_that_is_not_installed_is_named_rather_than_reported_as_a_code() {
        // A real SCM call, and the failure path every write function shares. The
        // name cannot exist, so nothing on the machine is changed by this test
        // whether or not it is elevated.
        let error = query_start(ABSENT).expect_err("there is no such service");
        assert!(error.contains(ABSENT), "{error}");
        assert!(
            error.contains("no service called") || error.contains("access is denied"),
            "the message has to say what is wrong in words: {error}"
        );
        // Not a bare code: a caller has to be able to print this to a person.
        assert!(!error.starts_with("Win32"), "{error}");

        for error in [
            configure_start(ABSENT, StartKind::AutomaticDelayed).expect_err("no such service"),
            configure_recovery(ABSENT).expect_err("no such service"),
            configure_description(ABSENT, "test").expect_err("no such service"),
            integrity(ABSENT).expect_err("no such service"),
        ] {
            assert!(error.contains(ABSENT), "{error}");
            assert!(error.len() > 40, "a refusal has to be a sentence: {error}");
        }
    }

    #[test]
    fn repairing_a_service_that_is_not_there_is_a_refusal_and_not_a_silence() {
        // `ensure_starts_by_itself` asks the machine a question first, so on a
        // service that is not installed the refusal has to come from that
        // question — not from a write that happened anyway, and not from
        // `StartOutcome::Already` guessed out of a failed read. This is the
        // difference between a command that reports "already fine" on a machine
        // with no service at all and one that says so.
        let error = ensure_starts_by_itself(ABSENT).expect_err("there is no such service");
        assert!(error.contains(ABSENT), "{error}");
        assert!(
            error.contains("no service called") || error.contains("access is denied"),
            "the message has to say what is wrong in words: {error}"
        );
        assert!(!error.starts_with("Win32"), "{error}");
    }

    #[test]
    fn a_service_that_already_starts_by_itself_is_left_alone() {
        // The rule, over every start type the SCM can hand back: the two
        // automatic spellings are what `protect status` calls hardened, and they
        // must produce no write — a plain automatic service is a machine that is
        // protected, and rewriting somebody's own choice to a delayed start is
        // this product changing a decision it was not asked to change.
        assert_eq!(start_type_repair(StartKind::Automatic), None);
        assert_eq!(start_type_repair(StartKind::AutomaticDelayed), None);
        // The three that `protect status` fails on. `Unrecognised` is included
        // on purpose: a start type this build cannot name is a service this
        // build cannot claim starts by itself, and the repair is the same
        // automatic start it applies to a manual service.
        for before in [
            StartKind::Manual,
            StartKind::Disabled,
            StartKind::Unrecognised(0),
            StartKind::Unrecognised(u32::MAX),
        ] {
            assert_eq!(
                start_type_repair(before),
                Some(DEFAULT_START),
                "{before:?} does not start by itself, so it is the state that gets repaired"
            );
            assert!(!before.is_automatic(), "{before:?}");
        }
        // And what it writes is a start type `protect status` accepts, which is
        // the only reason for the write: a repair to something that is not
        // automatic would leave the command failing on the same clause.
        assert!(DEFAULT_START.is_automatic(), "{DEFAULT_START:?}");
        // Delayed and not plain automatic: the delay is what this product
        // chooses for its own service, because nothing needs the scanner before
        // the desktop is up. `install` creates a plain automatic service, so a
        // repaired one differs from a freshly installed one by this flag and
        // nothing else.
        assert_eq!(DEFAULT_START, StartKind::AutomaticDelayed);
        assert_ne!(DEFAULT_START, StartKind::Automatic);
    }

    #[test]
    fn writing_an_unrecognised_start_type_is_refused_before_any_call() {
        // The one variant that must never reach the SCM: it came from a report of
        // this machine, and writing it back would be this crate setting a value
        // it does not understand. Refused with the name of the value.
        let error = configure_start(ABSENT, StartKind::Unrecognised(0))
            .expect_err("a start type this build does not understand");
        assert!(error.contains("not a start type"), "{error}");
        assert!(error.contains('0'), "{error}");
        // And the refusal happens before the service is looked at, which is what
        // makes it a guard rather than a nicer error message.
        assert!(
            !error.contains("no service called"),
            "the value was rejected before the service was opened: {error}"
        );
    }

    #[test]
    fn the_integrity_of_a_real_service_can_be_read_without_being_changed() {
        // The read-only measurement, against a Windows component. This is the
        // half of the module that a person actually runs, and it is the half a
        // machine without administrator rights can still exercise — the SCM's
        // default security descriptor gives every interactive logon the query
        // rights and nothing else.
        let report = match integrity(PRESENT) {
            Ok(report) => report,
            Err(error) => panic!(
                "reading the configuration of `{PRESENT}` failed: {error}. This test is \
                 read-only and needs no elevation, so a failure here means the machine is not one \
                 this product runs on, or the SCM's default permissions have been narrowed."
            ),
        };
        assert_eq!(report.name, PRESENT);
        // The values are the machine's, so this asserts the shape and not the
        // number: the account must be named rather than blank, because an empty
        // account is what the SCM reports for `LocalSystem` and a report that
        // printed nothing would read as "runs as nobody".
        assert!(!report.account.is_empty(), "{report:?}");
        assert!(
            !matches!(report.start, StartKind::Unrecognised(_)),
            "`{PRESENT}` has a start type this build cannot name: {report:?}"
        );
        let described = report.describe();
        assert!(described.contains(PRESENT), "{described}");
        assert!(described.contains(&report.account), "{described}");
        // A Windows component is auto-start, so this is the ordinary case and the
        // sentence must not be carrying a warning that is not there.
        assert!(report.start.is_automatic(), "{report:?}");
        assert!(report.is_hardened() || !report.running || report.recovery.is_none());
    }

    #[test]
    fn the_delayed_start_flag_can_actually_be_read_on_this_machine() {
        // The second question, and the one whose silent failure would be worst:
        // `read_delayed` reports `None` as "not delayed", so a machine where
        // `SERVICE_CONFIG_DELAYED_AUTO_START_INFO` cannot be read would have
        // every delayed service reported as a boot-start one — a wrong answer in
        // the direction of the product looking *better* than it is, in a report
        // whose whole purpose is to say what the machine really does.
        //
        // Measured rather than assumed, because "the query is documented to work"
        // and "the query works here" are different claims and only the second
        // one makes `query_start` trustworthy.
        let delayed = scm::delayed_flag(PRESENT)
            .expect("a Windows component has to be openable for its configuration");
        assert!(
            delayed.is_some(),
            "`QueryServiceConfig2W(SERVICE_CONFIG_DELAYED_AUTO_START_INFO)` failed for \
             `{PRESENT}`, so this build cannot tell a delayed service from a boot-start one and \
             would report both as automatic. Check the debug log for the Win32 code."
        );
    }

    #[test]
    fn a_service_that_has_no_recovery_says_so_rather_than_printing_an_empty_policy() {
        // `query_recovery` on an absent service is an error and on a present one
        // is usually `None`, which is the state every freshly installed service
        // is in. Both are answered rather than defaulted to a policy that would
        // be a lie about the machine.
        assert!(query_recovery(ABSENT).is_err());
        // Whatever the machine says about the Event Log service, `integrity`
        // reports it in the same shape, and a `None` is described as the finding
        // it is.
        if let Ok(report) = integrity(PRESENT) {
            if report.recovery.is_none() {
                assert!(
                    report.describe().contains("NO recovery"),
                    "{}",
                    report.describe()
                );
                assert!(
                    !report.is_hardened(),
                    "a service with no recovery is not hardened: {report:?}"
                );
            }
        }
    }

    #[test]
    fn the_service_description_is_a_fragment_with_no_full_stop_of_its_own() {
        // Both callers add the terminator: `av_guard::tamper::SelfCheck::lines`
        // prints `Service: {describe()}.` and `av_service::selfprotect` prints
        // it as a line of its own. The manual-start branch used to end with
        // `". "`, which the first of them rendered as
        //
        //     … so the machine is not protected after a reboot. .
        //
        // in `wenle protect status` on 2026-10-11, and left a trailing space in
        // the other. A fragment that ends with its own punctuation is a defect
        // in whichever caller does not happen to be the one it was written for,
        // which is why the rule is asserted here rather than at either caller.
        let described = ServiceIntegrity {
            name: "WenleAvService".to_string(),
            start: StartKind::Manual,
            recovery: Some(DEFAULT_RECOVERY),
            account: "LocalSystem".to_string(),
            running: true,
            description: None,
        };
        let line = described.describe();
        assert!(
            line.contains("not a service that starts by itself"),
            "the manual branch is the one that carried the full stop: {line}"
        );
        assert!(
            !line.ends_with('.'),
            "the caller appends the full stop, so `Service: {{describe()}}.` would print two: \
             {line:?}"
        );
        assert!(!line.ends_with(' '), "no trailing space: {line:?}");
        // And with the full stop the caller adds, the line reads as one
        // sentence — which is the shape `wenle protect status` shows.
        assert!(format!("Service: {line}.").ends_with("after a reboot."));
    }

    #[test]
    fn a_stopped_service_is_described_as_a_finding_and_not_as_a_state() {
        // The sentence is the whole point of the report, so the two states that
        // mean "this machine is unprotected" are built here from a report that
        // was never taken off the machine — and asserted to say the alarming
        // thing in both cases.
        let stopped = ServiceIntegrity {
            name: "WenleAvService".to_string(),
            start: StartKind::AutomaticDelayed,
            recovery: Some(DEFAULT_RECOVERY),
            account: "LocalSystem".to_string(),
            running: false,
            description: Some("Wenle AV Service".to_string()),
        };
        let line = stopped.describe();
        assert!(line.contains("NOT running"), "{line}");
        assert!(!stopped.is_hardened(), "a stopped service is not hardened");

        let disabled = ServiceIntegrity {
            start: StartKind::Disabled,
            running: false,
            ..stopped.clone()
        };
        let line = disabled.describe();
        assert!(line.contains("not a service that starts by itself"), "{line}");
        assert!(line.contains("will not start at all"), "{line}");

        let manual = ServiceIntegrity {
            start: StartKind::Manual,
            ..stopped.clone()
        };
        assert!(manual.describe().contains("not a service that starts by itself"));

        // And the healthy case has to read as healthy, or the report is one
        // nobody reads a second time.
        let healthy = ServiceIntegrity {
            running: true,
            ..stopped.clone()
        };
        let line = healthy.describe();
        assert!(line.contains("is running now"), "{line}");
        assert!(!line.contains("NOT running"), "{line}");
        assert!(healthy.is_hardened(), "{healthy:?}");
        assert!(line.contains("restarts after 5s"), "{line}");

        // A policy whose delays are zero would attempt nothing; the report says
        // that rather than that recovery is configured.
        let hollow = ServiceIntegrity {
            running: true,
            recovery: Some(Recovery {
                delays: [Duration::ZERO; 3],
                ..DEFAULT_RECOVERY
            }),
            ..stopped.clone()
        };
        assert!(hollow.describe().contains("would not actually restart it"));
        assert!(!hollow.is_hardened());
    }

    #[test]
    fn the_scm_already_denies_stop_to_an_ordinary_user() {
        // The measurement the module documentation leads with, and the one that
        // says what this module is *not* for. Opening a Windows component with
        // `SERVICE_STOP` is the cheap version of the attack: it does not stop
        // anything, and the answer says whether an ordinary account could.
        //
        // From an elevated token the answer is yes, which is the correct answer
        // and not the one this asserts — so the assertion depends on which token
        // this process holds, and which one it holds is measured rather than
        // assumed.
        const SERVICE_STOP: u32 = 0x0020;
        let outcome = scm::open_with(PRESENT, SERVICE_STOP);
        if is_elevated() {
            assert!(
                outcome.is_ok(),
                "an elevated token was refused `SERVICE_STOP` on `{PRESENT}`: {outcome:?}. That \
                 is a machine whose service permissions are narrower than the default, which is \
                 not what this test expects"
            );
            log::debug!(
                "this process is elevated, so the `SERVICE_STOP` measurement says nothing about \
                 an ordinary user"
            );
        } else {
            let error = outcome
                .err()
                .unwrap_or_else(|| {
                    panic!(
                        "an ordinary account was allowed to open `{PRESENT}` for `SERVICE_STOP`, \
                         so the SCM's default service permissions are not denying it on this \
                         machine and the module documentation's central measurement is wrong"
                    )
                });
            assert!(
                error.contains("denied") || error.contains("refused"),
                "and the refusal is a sentence: {error}"
            );
        }
        // The query rights, by contrast, are granted to every interactive logon,
        // which is why the read-only half of this module works unelevated.
        const SERVICE_QUERY_STATUS: u32 = 0x0004;
        assert!(
            scm::open_with(PRESENT, SERVICE_QUERY_STATUS).is_ok(),
            "an ordinary account has to be able to read a service's status, or the report half of \
             this module is unusable without elevation"
        );
    }
}
