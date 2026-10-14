//! What the service does to itself, and to its own files, when it starts.
//!
//! # The three calls, and why the wiring lives here
//!
//! `av-guard` is the crate that knows how to protect a process, a directory and
//! a service, and before 2026-10-09 every one of its functions was reached only
//! by `wenle protect …` — a command a person types. The product therefore had a
//! self-protection module that ran when somebody remembered to run it, and a
//! machine that was unhardened again after the next reboot, the next upgrade and
//! the next installer that recreated a directory. This module is the half that
//! was missing: the service applies it to itself, on every start.
//!
//! The three, and what each is for:
//!
//! * [`protect_process`] closes the seven rights that let another process
//!   terminate, suspend or write into *this* process. It lives on the process
//!   object, so it is redone on every start and cannot be made to survive one.
//! * [`protect_directories`] rewrites the DACL of the product's own directories
//!   so that an ordinary user cannot write the rule database, the binaries or
//!   the configuration. It lives on the objects themselves, so it survives a
//!   reboot — and is undone by an installer that recreates a directory, which is
//!   why it is applied on every start rather than once at installation.
//! * [`read_recovery`] reads the SCM's recovery policy — restart after 5, 10 and
//!   30 seconds — and reports it. It is not prevention and does not pretend to
//!   be; it is the difference between a crash the product survives and one that
//!   leaves the machine unguarded until somebody notices.
//!
//! # Why the third one is read here and written somewhere else
//!
//! It was written here until 2026-10-10, and the write could never succeed. A
//! service running as `LocalSystem` cannot change its own configuration: the
//! default service permissions give SYSTEM `CCLCSWRPWPDTLOCRRC`, which is
//! `SERVICE_QUERY_CONFIG` and **not** `SERVICE_CHANGE_CONFIG`, and the only entry
//! that holds the latter is `BUILTIN\Administrators` — read off
//! `sc.exe sdshow WenleAvService` on the machine this was found on, after eight
//! start-ups in which this module called `configure_recovery` and every one of
//! them was refused with access denied. The service therefore applies two of the
//! three and only reads the third, and the one it cannot write is the one whose
//! absence is invisible: a machine with no recovery policy looks exactly like a
//! machine with one until the service crashes.
//!
//! So the write moved to the elevated half — `wenle protect apply`, and
//! `wenle service install` at the moment it creates the service — which is the
//! same split the directory permissions already have: the service applies what
//! belongs to the service, and the SCM's record of the service belongs to
//! whoever installed it. What is left here is the reading, which an unelevated
//! account can do, and the report's job is to say what the machine holds and to
//! name the one command that puts it there.
//!
//! # The one layout nothing is applied to
//!
//! A cargo build tree. See [`skip_reason`]: on a build tree `install_dir` is the
//! directory cargo writes into, protecting it with an installation's
//! permissions makes every later build fail with access denied, and the account
//! running the build is an ordinary user for this purpose. `wenle protect apply`
//! refuses the same layout for the same reason, through the same
//! [`av_core::paths::cargo_build_tree`] — one check, in one place, so that the
//! command and the service cannot disagree about which trees are safe.
//!
//! # What this is not
//!
//! Not a defence against an administrator, a kernel-mode attacker, or somebody
//! who boots another operating system. `av_guard`'s own documentation names each
//! of those limits and this module does not widen them by a word; a service that
//! reported "self-protection applied" without them would be read as promising
//! more than it delivers. The report this module produces is deliberately about
//! *what was applied*, and [`measure`] is the one that answers *what is true
//! now* — the distinction the whole crate is built around.

use av_core::paths::AvPaths;
use av_guard::{files, process, service};

use crate::scm::SERVICE_NAME;

/// What start-up self-protection did.
///
/// Three outcomes rather than a boolean, because the three parts fail
/// independently and a report that collapsed them would have to pick which one
/// to be wrong about: a service whose process DACL was refused can still have
/// hardened every directory, and saying "self-protection failed" about it would
/// hide the half that worked.
#[derive(Debug)]
pub enum SelfProtection {
    /// Nothing was attempted, and the sentence says why. The one state this
    /// occurs in is a service started out of a cargo build tree.
    Skipped {
        /// What the machine is, and why nothing was applied to it.
        reason: String,
    },
    /// All three were attempted. Each carries its own answer.
    Applied {
        /// The result of protecting this process, or the sentence saying why it
        /// could not be.
        ///
        /// Boxed, and for a reason that is about the type rather than about this
        /// value: `Protection` carries a DACL reading per protected object, so it
        /// is several times the size of everything else here put together, and an
        /// enum whose largest variant is that much larger than its smallest makes
        /// every `SelfProtection` — including the [`SelfProtection::Skipped`] one
        /// a build tree produces — carry the whole of it. This value is built
        /// once at start-up, so the allocation is free in any sense that matters;
        /// the size is not, because it is paid by every value of the type.
        process: Box<Result<process::Protection, String>>,
        /// The result of hardening the product's directories.
        directories: Result<Vec<files::DirProtection>, String>,
        /// What the machine says about the service's recovery policy.
        ///
        /// Read, not written — see [`read_recovery`] and the module
        /// documentation. `Err` covers both "the SCM holds none" and "the SCM
        /// holds one that would not restart the service", because both are the
        /// same fact for a caller: this machine is not configured to come back
        /// by itself, and the sentence says which of the two it is.
        recovery: Result<service::Recovery, String>,
    },
}

impl SelfProtection {
    /// Whether every part of the attempt took.
    ///
    /// `false` for [`SelfProtection::Skipped`], and deliberately: a skipped
    /// attempt is not a machine that is protected, and a caller that wants one
    /// bit has to be told that. The reason it was skipped is one sentence away
    /// in [`SelfProtection::lines`].
    pub fn is_wholly_applied(&self) -> bool {
        match self {
            SelfProtection::Skipped { .. } => false,
            SelfProtection::Applied {
                process,
                directories,
                recovery,
            } => {
                process.is_ok()
                    && directories
                        .as_ref()
                        .is_ok_and(|dirs| dirs.iter().all(|dir| !dir.present || dir.applied))
                    && recovery.is_ok()
            }
        }
    }

    /// One line per part, phrased as what is now true of the machine.
    ///
    /// Every line is a sentence rather than a tick, and the unhappy ones lead
    /// with what is wrong — the same rule the rest of this product's reports
    /// follow, and the reason [`av_guard::files::DirProtection::describe`] is
    /// reused rather than re-worded here: the sentence a user reads in
    /// `wenle protect apply` and the sentence they read in the service log are
    /// the same sentence, so they cannot disagree.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match self {
            SelfProtection::Skipped { reason } => {
                lines.push(format!("self-protection was not applied: {reason}"));
            }
            SelfProtection::Applied {
                process,
                directories,
                recovery,
            } => {
                lines.push(match process.as_ref() {
                    Ok(protection) => protection.describe(),
                    Err(detail) => format!("this process could not be protected: {detail}"),
                });
                match directories {
                    // An `Err` here is a refusal of the whole layout rather than
                    // a directory that would not take, and the two are different
                    // facts: see `protect_product_dirs`'s own documentation.
                    Err(detail) => lines.push(format!(
                        "the product's directories were not protected: {detail}"
                    )),
                    Ok(dirs) => lines.extend(dirs.iter().map(files::DirProtection::describe)),
                }
                // The detail is already a whole sentence about the service —
                // [`read_recovery`] builds one, and the tests build one by hand —
                // so it is printed as it stands rather than behind a prefix that
                // would say the same thing twice.
                lines.push(match recovery {
                    Ok(recovery) => format!(
                        "the service will be restarted if it fails: {}",
                        recovery.describe()
                    ),
                    Err(detail) => detail.clone(),
                });
            }
        }
        lines
    }
}

/// Why nothing is applied to this layout, when the service is running out of a
/// cargo build tree.
///
/// `None` means the layout is one this module will harden.
///
/// # Why a build tree is refused, in the same words the command uses
///
/// Found by running it: on a build tree `install_dir` is the directory cargo
/// writes into, and the permissions [`protect_directories`] applies are an
/// installation's, which give ordinary users read and execute and nothing else.
/// The account running a build is an ordinary user for this purpose, so every
/// later build would fail with access denied until somebody put the permissions
/// back by hand — which the owner can always do, because Windows grants an owner
/// `WRITE_DAC` outside the DACL, and that is the only reason this is a refusal
/// rather than a catastrophe.
///
/// The recovery policy is skipped along with the rest, and the reason is now
/// only that the report is all-or-nothing rather than that reading it would do
/// any harm: it is read and never written (see [`read_recovery`]), so on a build
/// tree it would be a sentence about the installed service printed under a
/// heading about a build — a report about one machine's service on another
/// machine's layout, which is the confusion this refusal exists to avoid.
pub fn skip_reason(paths: &AvPaths) -> Option<String> {
    let root = av_core::paths::cargo_build_tree(&paths.install_dir)?;
    Some(format!(
        "the install directory is {}, which is inside the cargo build tree at {}. The \
         permissions applied here are an installation's, and the account running a build is an \
         ordinary user for this purpose, so every later build would fail with access denied; and \
         the service this would configure is the installed one, which a build tree is not",
        paths.install_dir.display(),
        root.display()
    ))
}

/// Apply everything that can be applied from here, and read back the one that
/// cannot.
///
/// All-or-nothing is [`skip_reason`]'s business and not a transaction: when the
/// layout is refused, nothing is called at all, so there is no half-applied
/// state to reason about. When it is not refused, the two writes are made and
/// the third is read, and each reports what it found — including the failures,
/// which is the case the report exists for.
pub fn apply(paths: &AvPaths) -> SelfProtection {
    if let Some(reason) = skip_reason(paths) {
        log::info!("{reason}");
        return SelfProtection::Skipped { reason };
    }
    let outcome = SelfProtection::Applied {
        process: Box::new(protect_process()),
        directories: protect_directories(paths),
        recovery: read_recovery(),
    };
    for line in outcome.lines() {
        if outcome.is_wholly_applied() {
            log::info!("{line}");
        } else {
            log::warn!("{line}");
        }
    }
    outcome
}

/// Close the seven rights on **this** process.
///
/// The pid is this process's own, and it is not a parameter: a service that
/// could be asked to protect another process would be a service an attacker
/// could use to lock a file out of its owner's hands. `wenle protect apply` is
/// where an operator aims this at something else, and it is a command a person
/// runs rather than something a client can ask the service for.
pub fn protect_process() -> Result<process::Protection, String> {
    process::protect_current_process()
}

/// Rewrite the DACL of every directory the product owns.
///
/// Forwards to [`av_guard::files::protect_product_dirs`], which skips the
/// quarantine vault deliberately — its permissions belong to
/// `av-quarantine::hardening`, and a second writer of that DACL is the same
/// defect as a second writer of its index.
pub fn protect_directories(paths: &AvPaths) -> Result<Vec<files::DirProtection>, String> {
    files::protect_product_dirs(paths)
}

/// What the machine says about the installed service's recovery policy.
///
/// The name is [`crate::scm::SERVICE_NAME`] — the same constant the SCM host
/// registers the service under — so there is one spelling of it in this crate.
/// `av-guard` takes it as a parameter rather than owning it, for the reason its
/// own documentation gives: a second copy of a name in a second crate is a thing
/// that goes stale silently.
///
/// # Why this reads and does not write
///
/// Because the write cannot be made from here and pretending otherwise cost the
/// product eight start-ups of a warning that named no fix. The module
/// documentation has the measurement; in one sentence, the service runs as
/// `LocalSystem` and `LocalSystem` has `SERVICE_QUERY_CONFIG` on its own service
/// without `SERVICE_CHANGE_CONFIG`. The failure sentence therefore names the
/// command that *can*, which is the only thing a reader of the log can act on.
///
/// `Err` covers three states, and they are three different facts about a
/// machine: the SCM holds no failure actions at all, it holds a policy that
/// would not actually restart the service, or the service is not installed under
/// this name. The last one is `av-guard`'s own sentence, which already names the
/// name it could not find.
pub fn read_recovery() -> Result<service::Recovery, String> {
    read_recovery_named(service_name())
}

/// [`read_recovery`] against a name this caller supplies.
///
/// Public so that the tests can point the SCM calls at a name that is not
/// installed — which is the only way to exercise them without reading the
/// recovery policy of the copy of this product that happens to be on the machine
/// running `cargo test`. Nothing in the product calls this with anything but
/// [`SERVICE_NAME`].
pub fn read_recovery_named(name: &str) -> Result<service::Recovery, String> {
    recovery_finding(name, service::query_recovery(name)?)
}

/// The sentence for what the SCM answered, as a function of the answer.
///
/// Split out from [`read_recovery_named`] so that all three sentences can be
/// tested. Two of the three states cannot be built on a machine that has this
/// product installed under the name it is asked about — a service with no
/// failure actions, and a service with a useless policy — and a report line
/// nothing can exercise is a report line that is wrong the first time somebody
/// reads it in a log.
fn recovery_finding(
    name: &str,
    answer: Option<service::Recovery>,
) -> Result<service::Recovery, String> {
    match answer {
        Some(policy) if policy.is_recoverable() => Ok(policy),
        // Configured and useless, which is a worse state than none at all: a
        // person who has seen a recovery policy in the services console has no
        // reason to look again.
        Some(policy) => Err(format!(
            "the recovery policy the SCM holds for `{name}` would not restart it: {}. `wenle \
             protect apply`, from an elevated prompt, is what replaces it",
            policy.describe()
        )),
        None => Err(format!(
            "the SCM holds no failure actions for `{name}`, so a crash would leave this machine \
             unguarded until something started the service by hand. `wenle protect apply`, from an \
             elevated prompt, is what sets them — the service cannot, because it runs as \
             `LocalSystem` and the default service permissions give that account \
             `SERVICE_QUERY_CONFIG` without `SERVICE_CHANGE_CONFIG`"
        )),
    }
}

/// What the machine says about the service's self-protection, read back.
///
/// # Why this exists next to [`apply`]
///
/// Because "I applied it" and "it is there" are different facts, and the whole
/// of `av-guard` is built on not confusing them. [`apply`] reports what the calls
/// returned; this reads the process's DACL, every directory's DACL and the SCM's
/// record back off the machine and reports those. A report that applied the
/// protection and then reported its own intentions would report them again on a
/// machine where they no longer hold — a directory recreated by an installer
/// inherits its parent's permissions, not ours, and nothing about the service's
/// own start-up would notice.
///
/// # Why it is read-only
///
/// Because a diagnostic must not harden the machine as a side effect: a report
/// that changed something could not be run to find out what a machine looks
/// like. This applies nothing; [`apply`] is the one that writes.
///
/// # Who calls it, and who must not
///
/// **Nothing in this build**, and the honest reason it is not a command is worth
/// stating rather than leaving a reader to find: the first line is
/// `process::verify(process::current_pid())`, so the process DACL this reports
/// is the *calling* process's. Run from `wenle` that would describe the
/// command-line tool's own access list and label it the service's — a report
/// about one process printed under the name of another is worse than no report.
/// A reader of this function has to be the service, or has to be told whose
/// rights it is holding; there is no third option, and the front ends do not
/// have one. `wenle protect status` answers the machine-shaped half of the same
/// question from outside, through `av_guard::files::audit` and
/// `av_guard::service::integrity`.
///
/// The service does read its own three back while it runs —
/// [`crate::tamper`]'s cheap pass — but it reads them into *findings* rather
/// than into sentences, because what it does with them is act on the ones that
/// are wrong rather than print them.
///
/// Nothing here fails as a whole. A part that cannot be read contributes a
/// sentence saying so, which is a different and more useful thing than an error
/// that would hide the parts that could.
pub fn measure(paths: &AvPaths) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(match process::verify(process::current_pid()) {
        Ok(protection) => protection.describe(),
        Err(detail) => format!("this process could not be read back: {detail}"),
    });

    for role in files::DirRole::ALL {
        let Some(path) = role.path_in(paths) else {
            continue;
        };
        lines.push(match files::audit(&path) {
            Ok(audit) => audit.describe(),
            Err(detail) => format!("{} could not be read back: {detail}", path.display()),
        });
    }

    // The fragment ends without a full stop, so this line adds one: the other
    // caller, `av_guard::tamper::SelfCheck::lines`, prints the same text as
    // `Service: …`.
    lines.push(match service::integrity(SERVICE_NAME) {
        Ok(integrity) => format!("{}.", integrity.describe()),
        Err(detail) => format!("the service could not be read back: {detail}"),
    });

    lines
}

/// The name this module configures, for the tests that check it is the SCM's.
///
/// A function rather than a re-export, so that the constant stays where it is
/// declared and this module cannot become a second home for it.
pub fn service_name() -> &'static str {
    SERVICE_NAME
}

/// True when `path` is a directory this module would harden.
///
/// Used by the tests and by nothing in the product. Present so that a test can
/// ask the question without duplicating [`skip_reason`]'s logic — a duplicated
/// check is a second answer that can disagree with the first.
pub fn would_harden(paths: &AvPaths) -> bool {
    skip_reason(paths).is_none() && paths.install_dir.is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A parent directory, so that the layout can be a `target` inside it.
    ///
    /// The two cases this module turns on are "is the install directory named
    /// `target` under a directory with a `Cargo.toml`" and "is it not", and the
    /// first cannot be built without a parent.
    fn build_tree() -> tempfile::TempDir {
        let parent = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(parent.path().join("Cargo.toml"), "[workspace]\n").expect("writes");
        std::fs::create_dir_all(parent.path().join("target/release")).expect("creates");
        parent
    }

    fn layout_under(install: &Path, data: &Path) -> AvPaths {
        AvPaths::with_data_dir(install, data)
    }

    #[test]
    fn a_build_tree_is_refused_with_a_reason_that_names_it() {
        // The guard the plan calls out: a developer running `--console` out of
        // `target/release` must not lock the build tree, and must be told why
        // rather than left to discover it when the next `cargo build` fails.
        let parent = build_tree();
        let data = tempfile::tempdir().expect("a temporary directory");
        let paths = layout_under(&parent.path().join("target/release"), data.path());

        let reason = skip_reason(&paths).expect("a build tree is refused");
        assert!(reason.contains("cargo build tree"), "{reason}");
        assert!(
            reason.contains(&parent.path().display().to_string()),
            "the reason does not name the tree it found: {reason}"
        );
        assert!(!would_harden(&paths));

        // And `apply` does nothing at all, rather than doing the two parts that
        // do not name a service. A partial application is the state this
        // all-or-nothing shape exists to make impossible.
        match apply(&paths) {
            SelfProtection::Skipped { reason: why } => assert_eq!(why, reason),
            other => panic!("a build tree must not be hardened: {other:?}"),
        }
    }

    #[test]
    fn an_installed_layout_is_not_refused() {
        // The other direction, and it is the one that would make the whole
        // module dead code if it were wrong: a directory that is not a cargo
        // `target` is a layout this module hardens.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let install = dir.path().join("WenleAV");
        std::fs::create_dir_all(&install).expect("creates");
        let paths = layout_under(&install, &dir.path().join("data"));
        assert_eq!(skip_reason(&paths), None);
        assert!(would_harden(&paths));
    }

    #[test]
    fn a_directory_named_target_with_no_manifest_is_not_a_build_tree() {
        // The check is "a directory named `target` whose parent has a
        // `Cargo.toml`", not "a directory named `target`". A product installed
        // into `C:\Program Files\target` — absurd, and a test can build the same
        // shape in a temporary directory — must be protected like any other.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let install = dir.path().join("target");
        std::fs::create_dir_all(&install).expect("creates");
        let paths = layout_under(&install, &dir.path().join("data"));
        assert_eq!(skip_reason(&paths), None);
    }

    #[test]
    fn the_name_configured_is_the_one_the_scm_registers() {
        // A second spelling of the service's name in a second place is a thing
        // that goes stale silently, and this one would go stale into a service
        // that is never restarted after it crashes.
        assert_eq!(service_name(), crate::scm::SERVICE_NAME);
        assert_eq!(service_name(), "WenleAvService");
    }

    #[test]
    fn hardening_a_real_layout_reports_every_directory_it_touched() {
        // The end-to-end half that can be run without touching the machine's
        // installed service: the directories are hardened for real, against a
        // temporary layout, and the audit is asked whether it worked.
        //
        // The recovery half is deliberately not part of this: `read_recovery`
        // names the installed service, so running it here would report the
        // recovery policy of whatever copy of this product happens to be
        // installed on the machine running `cargo test`.
        // `the_recovery_read_names_the_service_it_could_not_find` covers that
        // half against a name that is not installed, which exercises the same
        // SCM call without depending on the machine.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let install = dir.path().join("WenleAV");
        std::fs::create_dir_all(&install).expect("creates");
        let paths = layout_under(&install, &dir.path().join("data"));
        paths.ensure_dirs().expect("the layout is created");

        let done = protect_directories(&paths).expect("the layout is not the vault");
        assert!(!done.is_empty());
        for protection in &done {
            assert!(
                protection.present,
                "{} was reported as absent after `ensure_dirs`",
                protection.path.display()
            );
            assert!(
                protection.applied,
                "{} was not hardened: {:?}",
                protection.path.display(),
                protection.detail
            );
        }

        // Read back with the independent check rather than trusting `applied`.
        for role in files::DirRole::ALL {
            let Some(path) = role.path_in(&paths) else {
                continue;
            };
            let audit = files::audit(&path).expect("the audit can read what it just wrote");
            assert!(audit.present);
            if !role.users_may_write() {
                assert!(
                    !audit.writeable_by_ordinary_user(),
                    "{} is still writable by an ordinary user: {}",
                    path.display(),
                    audit.writeable_by.join(", ")
                );
            }
        }
    }

    #[test]
    fn the_recovery_read_names_the_service_it_could_not_find() {
        // The SCM half of the wiring, against a name that cannot be installed.
        // `OpenServiceW` reports `ERROR_SERVICE_DOES_NOT_EXIST`, and the refusal
        // has to name the service so that a person reading the log knows which
        // one was meant — a bare Win32 code would send them looking for a
        // permissions problem.
        let name = "WenleAvServiceThatThisTestInvented";
        let error = read_recovery_named(name).expect_err("no such service is installed");
        assert!(error.contains(name), "the refusal does not name it: {error}");
    }

    #[test]
    fn every_recovery_finding_names_the_command_that_fixes_it() {
        // The service cannot write its own recovery policy, so the only thing it
        // can do about one that is missing — or one that is there and useless —
        // is to say so in a way the reader can act on. A line that said only "no
        // recovery policy" would leave them with nothing to do, which is what
        // this module did for eight start-ups.
        //
        // A useless policy, in the shape `Recovery::is_recoverable` refuses: every
        // delay zero, which is a tight restart loop rather than a recovery.
        let useless = service::Recovery {
            delays: [std::time::Duration::ZERO; 3],
            reset_after: std::time::Duration::from_secs(60),
            on_non_crash_failure: true,
        };

        for finding in [
            recovery_finding(SERVICE_NAME, None),
            recovery_finding(SERVICE_NAME, Some(useless)),
        ] {
            let detail = finding.expect_err("neither answer is a policy that recovers");
            assert!(
                detail.contains("wenle protect apply"),
                "a finding a reader cannot act on is not worth printing: {detail}"
            );
            assert!(
                detail.contains(SERVICE_NAME),
                "the finding does not name the service it is about: {detail}"
            );
        }

        // And a policy that would recover is not a finding at all.
        let good = recovery_finding(SERVICE_NAME, Some(av_guard::service::DEFAULT_RECOVERY))
            .expect("the policy this product configures is a recovery policy");
        assert!(good.is_recoverable());

        // The finding reaches the log as the sentence it is, rather than behind
        // a prefix that would bury the command in it.
        let detail = recovery_finding(SERVICE_NAME, None).expect_err("no policy");
        let applied = SelfProtection::Applied {
            process: Box::new(Err("a sentence about the process".to_string())),
            directories: Ok(Vec::new()),
            recovery: Err(detail.clone()),
        };
        assert_eq!(
            applied.lines().last().expect("one line per part"),
            &detail,
            "the recovery finding has to survive to the log unchanged"
        );
        assert!(!applied.is_wholly_applied());
    }

    #[test]
    fn the_report_has_a_line_for_every_part() {
        // A report with a missing line is a report about a part nobody checked.
        // Built by hand rather than by running, because the three lines are the
        // shape under test and running them would harden this machine.
        let applied = SelfProtection::Applied {
            process: Box::new(Err("a sentence about the process".to_string())),
            directories: Err("a sentence about the directories".to_string()),
            recovery: Err("a sentence about the service".to_string()),
        };
        let lines = applied.lines();
        assert_eq!(lines.len(), 3);
        for (line, what) in lines.iter().zip(["process", "directories", "service"]) {
            assert!(line.contains(what), "no line is about the {what}: {line}");
            // Prose and not a code: a report line a person has to decode is the
            // failure this product's reports exist to avoid. The bound is on
            // shape rather than on the final character, because a refusal that
            // ended in a Win32 code or a file name is still a sentence — the
            // check is that it says more than the name of the thing it is about.
            assert!(
                line.len() > 20 && line.contains(' '),
                "a report line is a sentence, not a label: {line}"
            );
        }
        assert!(!applied.is_wholly_applied());

        // And the skipped case is one line that says so, with the reason in it.
        let skipped = SelfProtection::Skipped {
            reason: "the install directory is somewhere".to_string(),
        };
        let lines = skipped.lines();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("not applied"), "{}", lines[0]);
        assert!(lines[0].contains("somewhere"), "{}", lines[0]);
        assert!(!skipped.is_wholly_applied());
    }

    #[test]
    fn measure_reads_back_without_changing_anything() {
        // `--check` runs this, and a `--check` that changed the machine would be
        // one nobody could run to find out what the machine looks like. The
        // assertion that it changed nothing is that the layout's permissions are
        // the same before and after — which on a fresh temporary directory means
        // it is still writable by whoever created it.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let install = dir.path().join("WenleAV");
        std::fs::create_dir_all(&install).expect("creates");
        let paths = layout_under(&install, &dir.path().join("data"));
        paths.ensure_dirs().expect("the layout is created");

        let before = files::audit(&paths.install_dir).expect("readable");
        let lines = measure(&paths);
        let after = files::audit(&paths.install_dir).expect("still readable");

        assert!(!lines.is_empty());
        // One line for the process, one per directory role, one for the service.
        assert!(
            lines.len() >= files::DirRole::ALL.len() + 2,
            "the measurement skipped a part: {lines:#?}"
        );
        assert_eq!(
            before.summary, after.summary,
            "`measure` changed the directory it was asked to describe"
        );
        assert!(!before.summary.is_empty());
    }
}
