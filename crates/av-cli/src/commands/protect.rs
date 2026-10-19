//! `wenle protect` — the product's protection of itself.
//!
//! # What `av-guard` does and what this module does
//!
//! All of the security is in `av-guard`, and all of the output is here. That
//! split is the same one `service` uses and for the same reason: what a DACL
//! should contain, what a service's recovery policy should be and what a tamper
//! check should compare are facts about Windows and about this product, and they
//! belong beside the tests that can check them without a command line in the way.
//! This module decides what to print and what to exit with.
//!
//! # Why `status` reports three things and not one
//!
//! The three answers fail independently, and a report that collapsed them into
//! one word would be wrong in the case that matters most: a machine whose
//! directories are locked down, whose manifest is clean, and whose service is
//! disabled looks perfectly protected to a check that only read permissions. The
//! service's start type is the field that catches it, and it is the field nobody
//! thinks to look at.
//!
//! So `status` prints the directory audits, the manifest comparison and the
//! service's integrity, each under its own heading, and exits non-zero when any
//! of them says the product is not protected — which is a different question from
//! whether anything has been tampered with, and is why `verify` and `status` exit
//! differently for the same findings.
//!
//! # The one thing this module adds to `av-guard`'s answers
//!
//! The permission check is run twice on `apply`: once by
//! [`av_guard::files::protect_product_dirs`] as it writes, and once by
//! [`av_guard::files::audit`] afterwards. The second is not decoration. Every
//! write to a security descriptor in this product is a call that returns success
//! or failure, and a call that returned success is not the same fact as a
//! directory that is now restricted — so the command that changes the machine is
//! the command that reads it back and says what it found.

use anyhow::Result;
use std::path::Path;

use av_guard::files::{self, DirAudit, DirProtection, DirRole};
use av_guard::service;
use av_guard::tamper::{self, SelfCheck};
use av_service::install::SERVICE_NAME;

use crate::cli::{Globals, ProtectCommand};
use crate::commands::Context;
use crate::exit::Exit;
use crate::output;

/// Run a `protect` subcommand.
pub fn run(command: &ProtectCommand, globals: &Globals, context: &Context) -> Result<Exit> {
    match command {
        ProtectCommand::Status => status(globals, context),
        ProtectCommand::Audit { path } => audit(path.as_deref(), globals, context),
        ProtectCommand::Apply => apply(globals, context),
        ProtectCommand::Manifest => manifest(globals, context),
        ProtectCommand::Verify => verify(globals, context),
        ProtectCommand::Restore => restore(globals, context),
    }
}

/// The service's name, from the crate that owns it.
///
/// Read from `av-service` rather than written here, because a second copy of a
/// name is a thing that goes stale silently — and because `av-guard` deliberately
/// has no constant for it at all, which is why every function there takes it as a
/// parameter. This is the one place in the product where the name is turned into
/// an argument.
fn service_name() -> &'static str {
    SERVICE_NAME
}

/// `wenle protect status`.
fn status(globals: &Globals, context: &Context) -> Result<Exit> {
    output::heading("Directories");
    let audits = audit_product_dirs(context)?;
    let mut unprotected = Vec::new();
    for (kind, audit) in &audits {
        print_audit(*kind, audit, globals);
        if is_open(*kind, audit) {
            unprotected.push(audit.path.display().to_string());
        }
    }

    output::heading("The control pipe");
    // Read off the machine's own object rather than asked of the service, for
    // the reason `av_guard::files::audit` re-reads a directory it just wrote:
    // an answer about itself is not the same thing as the machine's state, and
    // the service is not always running to be asked. Opening the pipe connects
    // to it — see `av_service::pipe::audit` — so this is also a check that a
    // client can reach the service at all, which is why the sentence says so
    // when there is no pipe rather than treating it as a permission failure.
    let pipe = av_service::pipe::audit(av_ipc::PIPE_NAME);
    print_pipe(&pipe, globals);
    let pipe_holds = pipe.holds();

    output::heading("The product's own files");
    let check = tamper::self_check(&context.paths, service_name()).map_err(|reason| {
        anyhow::anyhow!(
            "{reason}\n       Run `wenle protect manifest` from an elevated prompt to record the \
             current files as the ones to compare against."
        )
    })?;
    print_self_check(&check);

    // Two different questions, and the exit code has to answer the one the
    // command is named for. `status` asks "is this machine protected", which is
    // false when a directory is open, when the control pipe's permissions are
    // not the ones this build writes, when there is no manifest to check
    // against, when the files have changed, or when the service is not the one a
    // security product needs — running, starting by itself, and configured to be
    // restarted if it fails, which is `ServiceIntegrity::is_hardened` and is
    // what `SelfCheck::is_clean` asks. `verify` asks the narrower "have the
    // files been touched".
    //
    // A pipe that could not be *reached* is not a permission failure. This
    // check is about what the object holds, and an object that is not there
    // holds nothing; whether the service is running is the next section's
    // question and is already one of the things `status` fails on. Counting it
    // here as well would make a stopped service report the same problem twice.
    let pipe_wrong = pipe.observed.is_ok() && !pipe_holds;
    let protected = unprotected.is_empty() && !pipe_wrong && check.is_clean();
    if !protected {
        // The clauses, joined so that the sentence says which of them is a
        // permissions problem, which is the control channel, and which is a
        // report that has not been taken yet. Each is dropped rather than
        // printed empty when it does not apply.
        let mut clauses = Vec::new();
        if !unprotected.is_empty() {
            let count = unprotected.len();
            clauses.push(format!(
                "{count} of the product's directories {} writable by an ordinary user",
                if count == 1 { "is" } else { "are" }
            ));
        }
        if pipe_wrong {
            clauses.push(
                "the control pipe's permissions are not the ones this build writes".to_string(),
            );
        }
        if !check.is_clean() {
            clauses.push(describe_why_not_protected(&check));
        }
        output::summary(&format!(
            "This machine is not fully protected: {}.",
            clauses.join(", and ")
        ));
        return Ok(Exit::Failure);
    }
    // The files that are not the product's are named as such rather than left
    // to be found in the section above, because the sentence that begins "its
    // files match the recorded manifest" and ends "the service is running" is
    // read as a summary of the whole report — and twenty `UNEXPECTED` lines
    // above it are not nothing. They are also not a hole: every file the
    // manifest names matches, which is the fact the sentence is about.
    let strays = check
        .changes
        .iter()
        .filter(|change| !change.is_alarming())
        .count();
    output::summary(&format!(
        "The product's directories are restricted, the control pipe is closed to everyone but an \
         interactive user, its files match the recorded manifest, and the service is running, set \
         to start by itself and set to be restarted if it fails.{strays_note}",
        strays_note = if strays == 0 {
            String::new()
        } else {
            format!(
                " {strays} file{} in those directories {} not the product's and {} listed above.",
                if strays == 1 { "" } else { "s" },
                if strays == 1 { "is" } else { "are" },
                if strays == 1 { "is" } else { "are" },
            )
        },
    ));
    Ok(Exit::Clean)
}

/// One line for the control pipe, in the shape the directory lines take.
///
/// `absent` rather than `OPEN` or `ok` when nothing answered, because the three
/// states a person has to tell apart are "there is no control channel on this
/// machine", "there is one and it is closed", and "there is one and it is open
/// to accounts that should not be on it".
fn print_pipe(permissions: &av_service::pipe::PipePermissions, globals: &Globals) {
    let mark = match (&permissions.observed, permissions.holds()) {
        (Err(_), _) => "absent",
        (Ok(_), true) => "ok",
        (Ok(_), false) => "OPEN",
    };
    println!(
        "  {mark:<7} {} permissions, and the object holds {}",
        permissions.requested, permissions.observed.as_ref().map_or_else(
            |reason| format!("nothing that could be read ({reason})"),
            |observed| observed.clone()
        )
    );
    if globals.verbose > 0 {
        println!("    {}", permissions.describe());
    }
}

/// The reason `status` is not satisfied, in the order a person should fix them.
///
/// Ordered by what makes the others meaningless: a machine with no manifest
/// cannot be said to be tampered with *or* clean, so "no manifest" is named
/// before "the files changed", which cannot even be known without one.
///
/// The file half asks [`SelfCheck::has_alarming_changes`] and not "are there
/// differences", which it did until 2026-10-10 — see that method and
/// [`why_the_files_fail`] for what counting every difference cost.
fn describe_why_not_protected(check: &SelfCheck) -> String {
    match &check.manifest {
        tamper::ManifestState::Absent => {
            "no manifest has been recorded, so nothing has been checked".to_string()
        }
        tamper::ManifestState::Unreadable(_) => {
            "the manifest could not be read, so nothing has been checked".to_string()
        }
        tamper::ManifestState::Loaded(_) => {
            if check.has_alarming_changes() {
                why_the_files_fail(&check.changes)
            } else {
                // One clause, because the summary is one sentence, and the order
                // is what makes the others meaningless: a service that is not
                // running is not protecting anything now, whatever its
                // configuration says. The last three are the three ways
                // `ServiceIntegrity::is_hardened` can be false, in the order a
                // person should fix them — and the recovery policy is one of
                // them, which it was not before 2026-10-10: a running automatic
                // service with no policy matched the first arm and was reported
                // as fine, then the summary said the machine was fully
                // protected. `av_service::selfprotect` has the measurement that
                // says why the fix for that one is a command rather than
                // something the service does to itself.
                match &check.service {
                    Ok(integrity) if !integrity.running => "the service is not running".to_string(),
                    // The remedy is this product's own command, which has set
                    // the start type since 2026-10-11. It used to name `sc
                    // config`, which worked but was a step outside the product
                    // for a fact `wenle protect apply` repairs — and the clause
                    // directly below it already named the command for the
                    // recovery policy, so the two clauses disagreed about how a
                    // person fixes a service.
                    Ok(integrity) if !integrity.start.is_automatic() => format!(
                        "the service {}. `wenle protect apply`, from an elevated prompt, is what \
                         sets it to start by itself",
                        integrity.start.describe()
                    ),
                    Ok(integrity)
                        if !integrity
                            .recovery
                            .is_some_and(|policy| policy.is_recoverable()) =>
                    {
                        "the service has no recovery policy that would restart it, so a crash \
                         would leave this machine unguarded until something started it by hand. \
                         `wenle protect apply`, from an elevated prompt, is what sets one"
                            .to_string()
                    }
                    Ok(_) => {
                        "the manifest is clean and the service is fine, which should not have \
                         reached this message"
                            .to_string()
                    }
                    Err(reason) => format!("the service could not be read ({reason})"),
                }
            }
        }
    }
}

/// Why the files on disk fail the check, in the words of what was found.
///
/// # Why this is a function of the changes alone
///
/// Because the sentence has to be built from the *kind* of each change, and
/// because a machine is not needed to test that. It is the same split
/// `av_service::tamper`'s `verdict_of` makes, for the same reason.
///
/// # The two kinds, and why one sentence could not cover both
///
/// [`tamper::Change::is_alarming`] answers which is which. A file the manifest
/// names that is gone, resized or rewritten is the product's own file having
/// changed. A file that appeared where an entry records that nothing is — the
/// second place `Role::Database` looks, for instance — is a claim the manifest
/// made and that is now false. Either is a reason `status` is not satisfied.
///
/// What neither of them is: a file that appeared in a directory the product owns
/// and that no entry names at all. Those do not reach this function — `status`
/// prints them in the section above and does not fail on them — and on
/// 2026-10-10 they were what it failed on, under this sentence, on a machine
/// where nothing had happened. The VM's own output was "20 of the product's own
/// files have changed" over twenty files that were never the product's.
fn why_the_files_fail(changes: &[tamper::Change]) -> String {
    let alarming: Vec<&tamper::Change> = changes.iter().filter(|c| c.is_alarming()).collect();
    let appeared = alarming
        .iter()
        .filter(|change| matches!(change, tamper::Change::Added { .. }))
        .count();
    let changed = alarming.len() - appeared;

    let mut clauses = Vec::new();
    if changed > 0 {
        clauses.push(if changed == 1 {
            "one of the product's own files has changed".to_string()
        } else {
            format!("{changed} of the product's own files have changed")
        });
    }
    if appeared > 0 {
        clauses.push(if appeared == 1 {
            "a file has appeared where the manifest records that nothing is".to_string()
        } else {
            format!("{appeared} files have appeared where the manifest records that nothing is")
        });
    }
    if clauses.is_empty() {
        // Unreachable from `status`, which asks `has_alarming_changes` first —
        // and written out rather than left empty because the caller joins what
        // comes back into a sentence, and an empty answer would print "This
        // machine is not fully protected: ." A caller that reaches this has
        // asked the question the wrong way round, and the sentence says what is
        // actually there rather than nothing.
        return format!(
            "{} file(s) that are not the product's are in the directories its files live in, and \
             no file the manifest names is different",
            changes.len()
        );
    }
    clauses.join(", and ")
}

/// `wenle protect audit [PATH]`.
fn audit(path: Option<&Path>, globals: &Globals, context: &Context) -> Result<Exit> {
    let audits = match path {
        // One path named by the caller. Audited on its own — a user who names a
        // path is asking about that path, and a command that second-guessed them
        // would answer a question they did not ask. What the path is is resolved
        // only so that the *mark* can tell a directory that is open by design
        // from one that is open by accident; see `kind_of`.
        Some(path) => vec![(
            kind_of(path, context),
            files::audit(path).map_err(|reason| anyhow::anyhow!("{reason}"))?,
        )],
        None => audit_product_dirs(context)?,
    };
    let mut open = 0usize;
    for (kind, audit) in &audits {
        print_audit(*kind, audit, globals);
        if is_open(*kind, audit) {
            open += 1;
        }
    }
    // The absent ones are excluded from the verdict and named in it, because
    // "audited" is not a word that should describe a directory that is not
    // there: a report that counted them would say "7 of 7 paths are open" on a
    // machine where six of them could not have been read at all.
    let absent = audits.iter().filter(|(_, audit)| !audit.present).count();
    let note = |absent: usize| {
        if absent == 0 {
            String::new()
        } else {
            format!(
                " {} {} not there, so {} not audited.",
                absent,
                if absent == 1 { "is" } else { "are" },
                if absent == 1 { "it was" } else { "they were" }
            )
        }
    };
    let plural = |n: usize| if n == 1 { "path is" } else { "paths are" };
    if open > 0 {
        output::summary(&format!(
            "{open} of {} {} open. `wenle protect apply`, from an elevated prompt, is what closes \
             them.{}",
            audits.len(),
            plural(audits.len()),
            note(absent),
        ));
        return Ok(Exit::Failure);
    }
    output::summary(&format!(
        "All {} {} restricted: no ordinary user can write to them.{}",
        audits.len() - absent,
        plural(audits.len() - absent),
        note(absent),
    ));
    Ok(Exit::Clean)
}

// The cargo workspace root this build is running out of, when it is one. It
// lives in `av-core` rather than here, and moved there on 2026-10-09: the
// service asks the same question about the same directory before it arms the
// driver's write gate over it, and two copies of a refusal are two answers that
// can disagree. The function's own documentation says what the check is and why
// it is narrow enough to be believed.
use av_core::paths::cargo_build_tree;

/// `wenle protect apply`.
fn apply(globals: &Globals, context: &Context) -> Result<Exit> {
    // The one layout this command refuses, and it is not a security decision —
    // it is a decision not to break the machine it is run on. It was found by
    // running it: on a build tree, `install_dir` is the directory cargo writes
    // into, and the permissions `apply` writes are an installation's, which give
    // ordinary users read and execute and nothing else. The account running a
    // build is an ordinary user for this purpose — measured on the machine this
    // was written on, whose token contains no `Administrators` SID at all, so
    // the "administrators have full control" entry does not rescue it. Every
    // later build would then fail with access denied until somebody put the
    // permissions back by hand; the owner can always do that, because Windows
    // grants an owner `WRITE_DAC` outside the DACL, and that is the only reason
    // this is a refusal rather than a warning.
    if let Some(root) = cargo_build_tree(&context.paths.install_dir) {
        output::error(&format!(
            "the install directory is {}, which is inside the cargo build tree at {}. `apply` \
             writes the permissions of an installation, and afterwards this account would have \
             read and execute on the directory cargo writes into, so every later build would fail \
             with access denied. Nothing has been changed. Run this against an installed copy of \
             the product; `wenle protect audit` is the read-only verb and will tell you what this \
             tree's permissions currently are.",
            context.paths.install_dir.display(),
            root.display()
        ));
        return Ok(Exit::Failure);
    }

    // The undo, taken before there is anything to undo. This is the whole of
    // what makes `restore` possible, and it has to happen *here* — a record taken
    // after `protect_product_dirs` would faithfully describe the hardened
    // directories and putting it back would be a no-op that reported success.
    record_before_change(context);
    if globals.verbose > 0 {
        println!("  (the record is at {})", files::dacl_record_path(&context.paths).display());
    }

    let protections = files::protect_product_dirs(&context.paths)
        .map_err(|reason| anyhow::anyhow!("{reason}"))?;
    output::heading("Applied");
    for protection in &protections {
        print_protection(protection, globals);
    }

    // Read it back. A security-descriptor write that returned success is not the
    // same fact as a directory that is now restricted, and this is the command
    // that changed the machine — so it is the command that has to say what the
    // machine looks like afterwards.
    output::heading("Read back");
    let audits = audit_product_dirs(context)?;
    let mut still_open = Vec::new();
    for (kind, audit) in &audits {
        print_audit(*kind, audit, globals);
        if is_open(*kind, audit) {
            still_open.push(audit.path.display().to_string());
        }
    }
    // Only the present ones. A directory that is not there yet is reported by
    // `applied: false` as well as by `present: false`, and counting both made
    // the summary name the same five directories twice — "6 are not there yet"
    // and "5 could not be changed" for one problem.
    let failed = protections
        .iter()
        .filter(|protection| protection.present && !protection.applied)
        .count();
    // The SCM's record of the service, which the service itself cannot write:
    // a service running as `LocalSystem` has `SERVICE_QUERY_CONFIG` on its own
    // service and not `SERVICE_CHANGE_CONFIG`, which is why
    // `av_service::selfprotect` reads the policy back and can only report what
    // it finds. This is the same split the directories have — applied by the
    // service on every start, and repaired here — and it is the only thing on
    // the machine that can put a policy back.
    //
    // **It is written before either verdict is read, and that is deliberate.**
    // This command's whole job is to leave the machine protected; a verdict is
    // only how it reports on that, and a verdict that can return early can stop
    // the job. It did: the still-open check sat here, above this section, and on
    // 2026-10-10 it fired on the log directory (which is open by design — see
    // [`is_open`]) and returned before the policy was ever written. `apply`
    // exited 1 having fixed the permissions and having left the service exactly
    // as unprotected as it found it, and the sentence it printed said "This is a
    // bug in `av-guard`" — which was true, and about the wrong thing. So the
    // rule for this function is: make every write, then judge.
    output::heading("The service");
    let recovery = service::configure_recovery(service_name());
    // The start type, for the same reason the recovery policy is written here:
    // `status` fails a service that does not start by itself, and until
    // 2026-10-11 the only remedy it named was `sc config … start= delayed-auto`
    // — a step outside the product for a fact this command repairs. A service
    // that already starts by itself is left exactly as it is, which is the
    // common case on a machine where `service install` ran: it creates a plain
    // automatic service, and plain automatic is a machine that is protected.
    //
    // Both writes happen before either is reported, for the reason above.
    let start = service::ensure_starts_by_itself(service_name());
    match (&recovery, &start) {
        // One sentence where both failed with it. That case is a machine with
        // no service installed — a layout this command can still harden, and
        // one the README's own order produces, `protect apply` before `service
        // install` — so both calls fail with the SCM's "there is no service
        // called ... Install it first", and printing it twice reads as two
        // problems instead of one.
        (Err(policy), Err(repair)) if policy == repair => output::warn(policy),
        (recovery, start) => {
            match recovery {
                Ok(policy) => println!(
                    "  the service will be restarted if it fails: {}",
                    policy.describe()
                ),
                Err(detail) => output::warn(detail),
            }
            match start {
                Ok(service::StartOutcome::Already(kind)) => println!(
                    "  the service {} — nothing was written, because that is how it already \
                     starts",
                    kind.describe()
                ),
                Ok(service::StartOutcome::Set { before, after }) => println!(
                    "  the service {} — its start type was changed so that it now {}",
                    before.describe(),
                    after.describe()
                ),
                Err(detail) => output::warn(detail),
            }
        }
    }
    // A machine with no service installed is a layout this command can still
    // harden — the directories are protected either way — so that is reported
    // and not failed on. A machine that *has* a service and would not take the
    // policy is a different fact about a different machine, and this is the
    // command that exists to repair it. Both writes are judged the same way.
    let installed = service::query_start(service_name()).is_ok();
    let recovery_failed = recovery.is_err() && installed;
    let start_failed = start.is_err() && installed;

    if !still_open.is_empty() {
        output::error(&format!(
            "the permissions were written and {} still open: {}. This is a bug in `av-guard` \
             rather than a permissions problem — the write reported success and the directory did \
             not change.",
            if still_open.len() == 1 {
                "one directory is".to_string()
            } else {
                format!("{} directories are", still_open.len())
            },
            still_open.join(", ")
        ));
        return Ok(Exit::Failure);
    }

    let absent = audits.iter().filter(|(_, audit)| !audit.present).count();
    // The directories whose write access is the design, and which therefore are
    // not among those that "grant ordinary users read and execute and nothing
    // else". Two numbers and not one, because the sentence below would otherwise
    // be false about the log directory on every correctly protected machine.
    let by_design: Vec<String> = audits
        .iter()
        .filter(|(kind, audit)| audit.present && is_by_design(*kind))
        .map(|(_, audit)| audit.path.display().to_string())
        .collect();
    output::summary(&format!(
        "{} of {} directories now grant ordinary users read and execute and nothing else{}{}{}. \
         `wenle protect restore` puts the permissions from before this command back; take a \
         manifest with `wenle protect manifest` if the product has been upgraded since the last \
         one.",
        audits.len() - absent - by_design.len(),
        audits.len() - by_design.len(),
        if absent == 0 {
            String::new()
        } else {
            format!(
                "; {absent} {} not there yet and so could not be protected",
                if absent == 1 { "is" } else { "are" }
            )
        },
        if failed == 0 {
            String::new()
        } else {
            format!("; {failed} could not be changed, and the reason is printed above")
        },
        if by_design.is_empty() {
            String::new()
        } else {
            format!(
                "; {} {} open to ordinary users on purpose rather than by accident — the log \
                 directory is where this product asks its own GUI to write, and the vault's \
                 permissions are `av-quarantine`'s, which grants the account that created it",
                by_design.join(", "),
                if by_design.len() == 1 { "is" } else { "are" }
            )
        },
    ));
    // One verdict for each write and one exit, because the two are independent:
    // returning inside the first check would leave a machine whose recovery
    // policy was set but whose start type was not with a failure that never said
    // so. Both reasons are printed as warnings above, so these sentences say what
    // staying broken costs rather than repeating the Win32 detail.
    if recovery_failed {
        output::error(&format!(
            "the {} recovery policy was not set, and the reason is printed above. Until it is, a \
             crash leaves this machine unguarded until somebody starts the service by hand — so \
             this command has not finished the job it was run for.",
            service_name()
        ));
    }
    if start_failed {
        output::error(&format!(
            "the {} start type was not changed, and the reason is printed above. Until it is, the \
             service does not start by itself, so this machine is unprotected after the next \
             reboot — which is why `wenle protect status` fails on it and why this command has \
             not finished the job it was run for.",
            service_name()
        ));
    }
    if recovery_failed || start_failed {
        return Ok(Exit::Failure);
    }
    Ok(Exit::Clean)
}

/// Record the permissions that are about to be replaced, and say what happened
/// if they could not be.
///
/// # Why a failure here does not stop `apply`
///
/// `apply` is the repair verb: it is what somebody runs when the product's
/// directories are open, and the state it is most needed in is a machine
/// somebody has already broken. The realistic way this read fails is a directory
/// with a *null* DACL — which grants every right to every account, and is
/// precisely the state `apply` exists to fix — so refusing to repair a machine
/// because the permissions could not first be described would be refusing in the
/// one case where the command is worth most.
///
/// The cost is that there is then no undo, and that cost is real, so it is said
/// in the voice this product uses for things the user has to know rather than in
/// a line that scrolls past. A record already being there is the same warning for
/// a milder reason: it is the record of an earlier `apply` that has not been
/// undone, and it is kept rather than replaced because replacing it would capture
/// the *hardened* permissions and destroy the only copy of the originals — see
/// [`av_guard::files::DaclRecord::save`].
fn record_before_change(context: &Context) {
    let path = files::dacl_record_path(&context.paths);
    let record = match files::DaclRecord::capture(&context.paths) {
        Ok(record) => record,
        Err(reason) => {
            output::warn(&format!(
                "the permissions of the product's directories could not be read, so no record of \
                 them has been kept: {reason}. The permissions are about to be replaced anyway — a \
                 directory with no DACL grants every right to every account, and that is a state \
                 this command exists to repair — but there is now nothing for `wenle protect \
                 restore` to put back, and it will say so rather than guess."
            ));
            return;
        }
    };
    match record.save(&path) {
        Ok(()) => println!("  Recorded {}", record.describe()),
        Err(reason) => output::warn(&reason),
    }
}

/// `wenle protect restore`.
///
/// The undo for `apply`, and the reason [`files::DaclRecord`] exists.
///
/// # Why it consumes the record
///
/// A record is a claim about a *transition*: these were the permissions before
/// `apply` replaced them. Once they are back, the transition has been undone and
/// the claim is stale — so the record is removed, and the invariant is exact and
/// statable: **a record exists if and only if an `apply` has been done and not
/// yet undone.** Keeping it would leave a file claiming to describe the state
/// before the last `apply` when what it actually describes is the state before
/// some earlier one, and the next `apply` would keep it, silently, forever.
///
/// A record is kept when any directory it names was refused, so that the fix for
/// a half-applied restore is to run the same command again. Restoring the same
/// permissions twice is the same as restoring them once.
fn restore(globals: &Globals, context: &Context) -> Result<Exit> {
    let path = files::dacl_record_path(&context.paths);
    let record = match files::DaclRecord::load(&path) {
        Ok(record) => record,
        Err(reason) => {
            output::error(&reason);
            return Ok(Exit::Failure);
        }
    };
    // The same guard `verify` makes on the manifest, and for the same reason
    // written in `Roots`: a record taken for one installation must not be applied
    // to another's directories. Here it is worse than a wrong report — it would
    // *write* another machine's permissions onto these directories.
    if !record.roots.matches(&context.paths) {
        output::error(&format!(
            "the record at {} was taken against a different installation: {}. Applying it would \
             put another installation's permissions onto this machine's directories, so nothing \
             has been changed and the record is still there.",
            path.display(),
            record.roots.describe_mismatch(&context.paths)
        ));
        return Ok(Exit::Failure);
    }
    if globals.verbose > 0 {
        println!("{}", record.describe());
    }

    output::heading("Put back");
    let restorations = files::restore_dacls(&record);
    for restoration in &restorations {
        println!(
            "  {:<7} {} {}",
            if restoration.outcome.is_applied() {
                "ok"
            } else {
                "skipped"
            },
            restoration.role.describe(),
            restoration.path.display()
        );
        println!("      {}", restoration.outcome.describe());
    }

    // A directory that did not take is a different and worse thing than one that
    // was refused, and it is the case this product's own documents call a bug in
    // `av-guard` rather than a permissions problem — the write returned success.
    let broken: Vec<String> = restorations
        .iter()
        .filter(|restoration| {
            matches!(restoration.outcome, files::RestoreOutcome::DidNotTake { .. })
        })
        .map(|restoration| restoration.path.display().to_string())
        .collect();
    let refused = restorations
        .iter()
        .filter(|restoration| matches!(restoration.outcome, files::RestoreOutcome::Refused(_)))
        .count();

    // Only when every directory that had something to put back got it. See the
    // function's documentation for why the record is removed at all.
    if refused == 0 && broken.is_empty() {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            // The permissions are back and the record is still on disk, which is
            // the safe direction to fail in: a second `restore` would put the same
            // permissions back again, and `apply` would keep this record rather
            // than overwrite it. Said out loud because the file's presence is what
            // a later command reads.
            Err(error) => output::warn(&format!(
                "the permissions were put back and the record at {} could not be removed \
                 ({error}). It is now a record of permissions the machine already has; removing \
                 it by hand is safe, and `apply` will keep it rather than replace it.",
                path.display()
            )),
        }
    }

    if !broken.is_empty() {
        output::error(&format!(
            "{}: the permissions were written and the directory does not have them. This is a bug \
             in `av-guard` rather than a permissions problem. The record has been kept, so running \
             this command again retries only what is left.",
            broken.join(", ")
        ));
        return Ok(Exit::Failure);
    }
    if refused > 0 {
        output::error(&format!(
            "{refused} of the recorded directories could not be put back, and the reason is printed \
             above. The record has been kept: run this command again once the reason is dealt with, \
             and it will retry only what is left."
        ));
        return Ok(Exit::Failure);
    }

    let applied = restorations
        .iter()
        .filter(|restoration| restoration.outcome.is_applied())
        .count();
    let skipped = restorations.len() - applied;
    output::summary(&format!(
        "{applied} of {} directories have the permissions they had before `wenle protect apply` \
         ran{}. The record has been removed, so an `apply` from here on takes a fresh one.",
        restorations.len(),
        // Not spelled out here, because the two reasons are different sentences
        // and both are printed above one directory at a time: a directory that
        // was absent when the record was taken and one that is absent now are not
        // the same fact, and a summary that ran them together would be the one
        // line a reader takes away.
        if skipped == 0 {
            String::new()
        } else {
            format!("; {skipped} had nothing to put back, for the reason printed above each")
        },
    ));
    Ok(Exit::Clean)
}

/// `wenle protect manifest`.
fn manifest(globals: &Globals, context: &Context) -> Result<Exit> {
    // The same layout `apply` refuses, and refused here for a different reason
    // that is worse. `apply` would break the build tree it was run from; this
    // would silently disarm the *installation's* tamper check, on a machine
    // where nothing was wrong.
    //
    // The reason is that the manifest's location is a fact about the machine and
    // not about where this executable is. `manifest_path` is under the data
    // directory, so a run from `target\debug` writes to the same
    // `C:\ProgramData\WenleAV\integrity.manifest` that an installed copy reads —
    // and the manifest records the roots it was taken against, which here would
    // be the build tree. `verify` and `status` both refuse to compare against a
    // manifest taken elsewhere rather than reporting every named file as missing
    // (see `Manifest::matches_roots`), so the installation's answer becomes
    // "this manifest was taken against a different installation" for as long as
    // it stands, and neither command can tell the user their files are unchanged.
    //
    // Found by running it: from `target\debug`, `manifest` succeeded unelevated
    // and wrote a baseline naming `target\debug\rules.avdb` and
    // `target\debug\WenleAvFilter.sys`, neither of which an installation has, so
    // 0 of 6 entries recorded a file that was present. That warning was printed,
    // which is what made the run look like it had said everything there was to
    // say about it; nothing in the output named the installation whose baseline
    // had just been replaced.
    if let Some(root) = cargo_build_tree(&context.paths.install_dir) {
        let path = tamper::manifest_path(&context.paths);
        output::error(&format!(
            "the install directory is {}, which is inside the cargo build tree at {}. This command \
             would record the build tree as the installation and write that baseline to {}, which \
             is where an *installed* copy keeps the manifest it compares itself against — the \
             data directory is a fact about this machine and not about where this executable is. \
             An installation reading that manifest would see roots that are not its own and would \
             refuse to compare against it at all, so its tamper check would report that no \
             comparison has been taken rather than that its files are unchanged. Nothing has been \
             written. Run this against an installed copy of the product.",
            context.paths.install_dir.display(),
            root.display(),
            path.display()
        ));
        return Ok(Exit::Failure);
    }

    let manifest = tamper::Manifest::capture(&context.paths)
        .map_err(|reason| anyhow::anyhow!("{reason}"))?;
    let path = tamper::manifest_path(&context.paths);
    manifest
        .save(&path)
        .map_err(|reason| anyhow::anyhow!("{reason}"))?;

    output::heading("Recorded");
    for entry in &manifest.entries {
        println!("  {}", entry.describe());
    }
    let present = manifest.entries.iter().filter(|entry| entry.present).count();
    if present == 0 {
        output::warn(
            "not one of the product's files was found, so the manifest records only what is \
             missing. Check that the install directory is the one this build was installed to — \
             `status` would otherwise report every file as missing and every file as unexpected.",
        );
    }
    if globals.verbose > 0 {
        println!("  ({})", manifest.describe());
    }
    output::summary(&format!(
        "Wrote {present} of {} expected files to {}. `wenle protect verify` compares against it; \
         take a new one after every upgrade.",
        manifest.entries.len(),
        path.display()
    ));
    Ok(Exit::Clean)
}

/// `wenle protect verify`.
fn verify(globals: &Globals, context: &Context) -> Result<Exit> {
    let path = tamper::manifest_path(&context.paths);
    let manifest = match tamper::Manifest::load(&path) {
        Ok(manifest) => manifest,
        Err(reason) => {
            // A manifest that was never taken is a report and not a failure:
            // `verify` was asked whether anything has changed, and on a machine
            // where nothing was ever recorded the honest answer is that the
            // question has not been asked yet. `status` is the verb that treats
            // it as the problem it will become.
            output::warn(&reason);
            return Ok(Exit::Clean);
        }
    };
    if !manifest.matches_roots(&context.paths) {
        output::error(&format!(
            "the manifest at {} was taken against a different installation: {}. Comparing these \
             files against it would report every one of them as missing and every file here as \
             unexpected, so nothing was compared. Take a new one with `wenle protect manifest`.",
            path.display(),
            manifest.roots.describe_mismatch(&context.paths)
        ));
        return Ok(Exit::Failure);
    }
    if globals.verbose > 0 {
        println!("{}", manifest.describe());
    }
    let mut changes = manifest.verify().map_err(|reason| anyhow::anyhow!("{reason}"))?;

    // The unexpected-file half of the check rests on a premise, and on a build
    // tree the premise is false. `av-guard` scans the directory each of the
    // product's files lives in and reports anything the manifest does not name,
    // which is right for an installation — `C:\Program Files\WenleAV` holds the
    // product and nothing else, so a file that appeared there is a finding — and
    // wrong for `target\debug`, which holds cargo's artifacts and always will.
    //
    // Measured on the machine this was written on: `manifest` followed
    // immediately by `verify` out of `target\debug` reported 34 unexpected files
    // and exited 3. A check that fires on a machine where nothing has happened
    // is a check that gets ignored on the machine where something has, so the
    // two halves are separated here rather than the premise being trusted.
    //
    // That sequence is no longer one a user can run — `manifest` now refuses
    // outright when the install directory is inside a build tree, for the
    // stronger reason given there — but the filter stays, because refusing to
    // *write* such a manifest does not remove the ones already written by the
    // builds that allowed it. On a machine carrying one, `matches_roots` above
    // passes (both roots are the build tree's) and this branch is the difference
    // between a report of 34 files nobody planted and a report that can be read.
    //
    // Nothing is hidden: the count and the reason are printed, and the named
    // files — the half that catches a replaced binary — are checked either way.
    // Only the install directory's own files, and only when that directory is
    // the build's output. The data directories are scanned either way: they hold
    // the rule database and the cache and nothing else, so an unexpected file in
    // one of them is a finding on a build tree exactly as it is on an
    // installation. Getting this wrong is not hypothetical — the first version of
    // this filter dropped every unexpected file, and a file planted in the
    // database directory was silently swallowed along with cargo's artifacts.
    let build_tree = cargo_build_tree(&context.paths.install_dir);
    let mut skipped = 0usize;
    if build_tree.is_some() {
        let install_dir = context.paths.install_dir.clone();
        let before = changes.len();
        changes.retain(|change| {
            !matches!(change, tamper::Change::Added { path, .. } if path.starts_with(&install_dir))
        });
        skipped = before - changes.len();
    }

    if changes.is_empty() {
        output::summary(&format!(
            "Every file the manifest names is unchanged{}.{skipped_note}",
            if build_tree.is_some() {
                ""
            } else {
                ", and nothing unexpected is in the directories they live in"
            },
            skipped_note = if skipped == 0 {
                String::new()
            } else {
                format!(
                    " The install directory is inside a cargo build tree, so {skipped} unexpected \
                     {} there {} not reported: that directory holds the build's own artifacts and \
                     is not an installation. Every other directory was scanned, and the named \
                     files were checked.",
                    if skipped == 1 { "file" } else { "files" },
                    if skipped == 1 { "was" } else { "were" },
                )
            },
        ));
        return Ok(Exit::Clean);
    }
    output::heading(&format!("{} change(s)", changes.len()));
    for change in &changes {
        println!("  {}", change.describe());
    }
    if skipped > 0 {
        output::warn(&format!(
            "{skipped} further unexpected {} in the install directory {} not reported, because it \
             is inside the cargo build tree at {} and holds the build's own artifacts rather than \
             an installation's files.",
            if skipped == 1 { "file" } else { "files" },
            if skipped == 1 { "was" } else { "were" },
            build_tree
                .as_ref()
                .map(|root| root.display().to_string())
                .unwrap_or_default(),
        ));
    }
    // Both counts, because the two kinds of change are not the same finding and
    // the sentence used to describe one of them with the words of the other: an
    // `APPEARED` line — a file where an entry records that nothing is — is
    // interference, and it used to be counted among "files that appeared".
    let alarming = changes.iter().filter(|change| change.is_alarming()).count();
    let appeared = changes.len() - alarming;
    output::summary(&format!(
        "{alarming} of {} change(s) are to files the manifest accounts for — gone, resized, \
         rewritten, or appeared where it records that nothing is — and {appeared} are files that \
         appeared in a directory the product owns and that no entry names. Nothing has been \
         changed by this command — `wenle protect manifest` records the current files as the ones \
         to compare against from now on, and should only be run once this report has been \
         explained.",
        changes.len()
    ));
    Ok(Exit::Suspicious)
}

/// Audit every directory the product owns, with the role each one belongs to.
///
/// # Why the role comes back with the audit
///
/// Because "can an ordinary user write here" is not the whole question. One role
/// — [`DirRole::Log`] — grants an ordinary user write **on purpose**, so for that
/// directory the answer to the audit's question is `yes` and the machine is
/// working exactly as designed. Without the role a caller can only see the `yes`,
/// which is how this command came to call a correct machine broken and refuse to
/// finish (see [`is_open`]). The role is what tells the two `yes`es apart.
///
/// The vault is included and is [`DirKind::Vault`] rather than a role, because it
/// is the one entry here that is not this crate's to change: `av-guard`'s file
/// module refuses it by name, since restricting a quarantine vault is
/// `av-quarantine`'s job and grants a different set of accounts. It is audited
/// here because "can an ordinary user write the quarantine vault" is precisely
/// the question a user of this command has, and a report that left it out would
/// look complete and not be. It is not judged here, and the correction that took
/// is [`is_open`]: the vault used to be answered as `None`, which is also what
/// [`kind_of`] answers for a path it cannot place, so a directory this command
/// never writes to was judged as one whose write had failed.
fn audit_product_dirs(context: &Context) -> Result<Vec<(DirKind, DirAudit)>> {
    // `av-guard` answers with sentences rather than with error types — see that
    // crate's documentation for why — so these are `map_err` and not
    // `with_context`: a `String` is not a `std::error::Error` and cannot carry
    // the caller's context. Nothing is lost, because the sentence already names
    // the path it is about.
    let mut audits: Vec<(DirKind, DirAudit)> = Vec::new();
    for role in DirRole::ALL {
        if let Some(path) = role.path_in(&context.paths) {
            audits.push((
                DirKind::Role(role),
                files::audit(&path).map_err(|reason| anyhow::anyhow!("{reason}"))?,
            ));
        }
    }
    audits.push((
        DirKind::Vault,
        files::audit(&context.paths.quarantine_dir)
            .map_err(|reason| anyhow::anyhow!("{reason}"))?,
    ));
    Ok(audits)
}

/// What one audit is about, as the verdicts need to know it.
///
/// Nearly a role and not quite, which is the whole of why it exists: two of
/// these are not roles, and a verdict that cannot tell them apart is a verdict
/// that calls a correct machine broken. [`is_by_design`] is the one question they
/// answer differently, and [`is_open`] is built on it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DirKind {
    /// A directory this command protects, in the role it plays in the layout.
    Role(DirRole),
    /// The quarantine vault: `av-quarantine`'s permissions rather than this
    /// crate's, and a directory this command never writes to.
    Vault,
    /// A path that plays no role in this layout — the one `wenle protect audit`
    /// can be given, when it is neither a directory of the layout nor the vault.
    /// Judged the conservative way, because nothing is known about it.
    Unrelated,
}

/// What a path plays in this layout.
///
/// Only [`audit`] with a named path needs this, and only so that the mark it
/// prints can tell a directory that is open **by design** from one that is open
/// by accident, and the vault from either. The question the command was asked is
/// still about the path the user named; nothing here changes which path that is.
///
/// Both sides are resolved before they are compared, because two spellings of
/// one directory are the same directory and only the filesystem can say so — the
/// user's argument may be in any case, or reached through a link, or the short
/// name of a directory whose real name is longer. A path that cannot be resolved
/// plays no role, and its mark falls back to the audit's own answer, which is the
/// conservative direction: the fallback is `OPEN`, not `ok`.
///
/// The vault is looked for by path and not by role because it has no role — see
/// [`DirKind`] — and a user who names it is asking the one question whose answer
/// is not the audit's.
fn kind_of(path: &Path, context: &Context) -> DirKind {
    let Ok(named) = std::fs::canonicalize(path) else {
        return DirKind::Unrelated;
    };
    if let Some(role) = DirRole::ALL.into_iter().find(|role| {
        role.path_in(&context.paths)
            .and_then(|known| std::fs::canonicalize(known).ok())
            .is_some_and(|known| known == named)
    }) {
        return DirKind::Role(role);
    }
    if std::fs::canonicalize(&context.paths.quarantine_dir).is_ok_and(|vault| vault == named) {
        return DirKind::Vault;
    }
    DirKind::Unrelated
}

/// Whether an ordinary user can write here, which is the question the verdicts
/// below are about.
///
/// **Not** [`DirAudit::is_restricted`], and the difference is not academic — it
/// was a bug in this command. `is_restricted` is the conjunction of three
/// facts: the directory exists, no ordinary user can write it, and its owner is
/// not an ordinary user. The third one is a real caveat and is printed as one
/// (see [`print_audit`]), but it is not a failure of the permissions: on a
/// machine where the product was installed by an administrator the owner is
/// `Administrators` and it never fires, and on a developer's machine where the
/// directories were created by the user running the command it always fires.
/// Judging by it made `apply` read a directory it had just successfully locked
/// down as "still open" and accuse `av-guard` of a bug it did not have.
///
/// A missing directory is likewise not open. `protect` reports it rather than
/// creating it — see [`av_guard::files::DirProtection::present`] — and the
/// product makes its own directories at startup, so on a machine where the
/// service has never run, every data directory is absent. Counting those as
/// findings made the first `protect apply` on a fresh machine report six
/// failures and lock down nothing wrong.
///
/// # The third thing that is not open, and the bug it caused
///
/// A directory whose *role* grants an ordinary user write. [`DirRole::Log`] is
/// the only one — `av_guard::files` argues the case and
/// [`DirRole::users_may_write`] is the one-bit form of it — and its DACL is
/// applied with `Modify` for `BUILTIN\Users` deliberately, because a log an
/// ordinary user cannot write is a log this product cannot ask its own GUI to
/// write. So the audit's answer for it is `writeable_by_ordinary_user() == true`
/// on a machine that is exactly as hardened as it is supposed to be, and a
/// verdict built on the audit alone called that a failure. Measured
/// 2026-10-10 on the VM, once the owner-trap fix left the log directory as the
/// only `OPEN` line: `wenle protect apply` printed
/// "This is a bug in `av-guard`" about a directory it had just written
/// correctly, exited 1, and — because that verdict sat before the service
/// section — never wrote the SCM recovery policy it had been run for.
/// `sc.exe qfailure WenleAvService` showed `RESET_PERIOD : 0` and no actions.
///
/// This is the third reader of [`DirRole::users_may_write`], after
/// `files::protect_product_dirs` and the service's own tamper read-back, and it
/// is the one that was missing. The role is threaded back from
/// [`audit_product_dirs`] for it.
///
/// # The fourth thing that is not open: the vault
///
/// [`DirKind::Vault`] is never a finding, and it is the one verdict here that
/// does not come from the audit at all. The vault's permissions are
/// `av-quarantine`'s policy, and that module grants the account that created the
/// directory full control **deliberately**: it documents the choice, with its own
/// measurement, as the honest limit of what an ACL can do in that position — the
/// account holding the vault open is the account that does the quarantining — and
/// it re-applies the policy every time the vault is opened, so a vault whose
/// permissions were widened is put back by the module that owns it, without this
/// command. Judging it here made `apply` print "the write reported success and
/// the directory did not change" about the one directory it had not written to:
/// measured on the VM on 2026-10-12, where the read-back said
/// `OPEN  C:\ProgramData\WenleAV\quarantine: an ordinary user CAN write here —
/// S-1-5-21-…-1001` and `apply` exited 1 having done everything it was run for.
/// The vault is still audited and still printed — its line names the accounts
/// that can write it, which is the fact a reader of this report wants — and it is
/// no longer a failure on any of the three surfaces that read this.
fn is_open(kind: DirKind, audit: &DirAudit) -> bool {
    if is_by_design(kind) {
        return false;
    }
    audit.present && audit.writeable_by_ordinary_user()
}

/// Whether a directory's write access is the design rather than a finding.
///
/// Two of them, for two different reasons: the log directory, which the layout
/// applies with `Modify` for `BUILTIN\Users` on purpose, and the vault, whose
/// permissions belong to `av-quarantine` and grant the account that created it.
/// Both are `writeable_by_ordinary_user() == true` on a machine that is exactly
/// as hardened as it is supposed to be, which is why the mark and the verdict ask
/// this once instead of each deciding it.
fn is_by_design(kind: DirKind) -> bool {
    match kind {
        DirKind::Role(role) => role.users_may_write(),
        DirKind::Vault => true,
        DirKind::Unrelated => false,
    }
}

/// One directory audit, as a person reads it.
///
/// The mark leads because the question the command is run to answer is "is this
/// one open", and a reader scanning ten directories should be able to answer it
/// without reading ten sentences. The sentence follows because the mark is a
/// conclusion and the sentence is its evidence.
///
/// The sentence is [`DirAudit::describe`], which begins with the path. That is
/// not decoration: `audit` with no argument reports seven directories, and a
/// listing that gave the permissions without the path would leave a reader
/// unable to tell which of them is the rule database. The raw DACL
/// ([`DirAudit::summary`], in the shape `icacls` prints) is behind `-v` because
/// it is evidence for the sentence rather than the sentence itself, and because
/// seven of them in a row is a wall no one reads.
fn print_audit(kind: DirKind, audit: &DirAudit, globals: &Globals) {
    // Four marks rather than three, because there are four states and the fourth
    // is the one this command spent a day getting wrong: a directory an ordinary
    // user may write **because that is what it is for**. Printing it as `OPEN`
    // said the machine was broken; printing it as `ok` would hide the write
    // access from a reader who is scanning the marks and not the sentences. See
    // [`is_open`].
    //
    // `by design` is reached two ways and the sentences behind it are what tell
    // them apart — the log directory, and the vault, whose permissions belong to
    // `av-quarantine`. The vault's line is the one that says, in the account list
    // the audit prints, who can write a directory this command does not govern.
    let mark = if !audit.present {
        "absent"
    } else if is_by_design(kind) {
        "by design"
    } else if is_open(kind, audit) {
        "OPEN"
    } else {
        "ok"
    };
    // The vault is the one line whose mark needs its reason: `by design` beside
    // the account that can write it is this report asserting something the audit
    // cannot show, and a reader who is not told why would take it for the bug it
    // used to be. The sentence the audit prints is the evidence; this is the rule.
    println!(
        "  {mark:<10} {}{}",
        audit.describe(),
        if kind == DirKind::Vault {
            " — the vault's permissions are `av-quarantine`'s, which puts them back every time \
             it opens"
        } else {
            ""
        }
    );
    if globals.verbose > 0 {
        for trustee in &audit.trustees {
            println!(
                "    {:<28} {}",
                trustee.who(),
                describe_rights(trustee.can_read, trustee.can_write, trustee.can_execute)
            );
        }
        println!("    {}", audit.summary);
    }
}

/// What a set of rights means in words.
fn describe_rights(read: bool, write: bool, execute: bool) -> String {
    if write {
        // Named first because it is the answer the whole command is for.
        return if read && execute {
            "can read, write and execute".to_string()
        } else {
            "CAN WRITE".to_string()
        };
    }
    match (read, execute) {
        (true, true) => "can read and execute".to_string(),
        (true, false) => "can read".to_string(),
        (false, true) => "can execute".to_string(),
        (false, false) => "can do nothing".to_string(),
    }
}

/// One protection, as a person reads it.
fn print_protection(protection: &DirProtection, globals: &Globals) {
    println!("  {}", protection.describe());
    if let Some(detail) = &protection.detail {
        println!("      {detail}");
    }
    if globals.verbose > 0 {
        println!("      {}", protection.sddl);
    }
}

/// The self-check's own report, indented under its heading.
fn print_self_check(check: &SelfCheck) {
    for line in check.lines() {
        println!("  {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::{cargo_build_tree, is_by_design, is_open, why_the_files_fail, DirAudit, DirKind, DirRole};
    use av_guard::tamper::{Change, Role, SignatureChange};
    use std::path::{Path, PathBuf};

    /// One audit of a directory an ordinary user can write, of the shape the log
    /// directory really produced on 2026-10-10.
    fn a_writable_directory(path: &str) -> DirAudit {
        DirAudit {
            path: PathBuf::from(path),
            present: true,
            protected: true,
            trustees: Vec::new(),
            owner: Some("BUILTIN\\Administrators".to_string()),
            owner_can_rewrite_permissions: false,
            writeable_by: vec![
                "NT AUTHORITY\\Authenticated Users".to_string(),
                "BUILTIN\\Users".to_string(),
                "NT AUTHORITY\\INTERACTIVE".to_string(),
            ],
            readable_by: Vec::new(),
            summary: String::new(),
        }
    }

    /// The role is the whole of what tells an open directory that is a finding
    /// from an open directory that is the design.
    ///
    /// Written from the machine's own output: `wenle protect apply` on the VM,
    /// 2026-10-10, printed `OPEN C:\ProgramData\WenleAV\logs: an ordinary user
    /// CAN write here — NT AUTHORITY\Authenticated Users, BUILTIN\Users, NT
    /// AUTHORITY\INTERACTIVE` and then refused to finish. The DACL was correct —
    /// [`DirRole::Log`] is applied with `Modify` for `BUILTIN\Users` on purpose —
    /// and the audit could not tell that from a directory that had been left
    /// open by accident.
    ///
    /// Sabotage: make the body `audit.present && audit.writeable_by_ordinary_user()`
    /// again and the first assertion fails with the log directory named; the
    /// signature no longer distinguishes the two cases, which is the point.
    #[test]
    fn a_directory_that_is_writable_by_design_is_not_a_finding() {
        let audit = a_writable_directory(r"C:\ProgramData\WenleAV\logs");

        assert!(
            !is_open(DirKind::Role(DirRole::Log), &audit),
            "the log directory is writable by an ordinary user because that is what it is for, \
             and it was reported as a finding"
        );

        // The same audit under every other role is a finding, so what the test
        // above shows is the role's doing rather than the audit's.
        for role in DirRole::ALL.into_iter().filter(|role| !role.users_may_write()) {
            assert!(is_open(DirKind::Role(role), &audit), "{role:?} was excused");
        }

        // And a directory that plays no role in this layout — which is any path
        // `wenle protect audit` can be given — has nothing to excuse it either.
        assert!(is_open(DirKind::Unrelated, &audit));
    }

    /// The vault is reported and never judged, and this is the machine's own
    /// output that said so.
    ///
    /// `wenle protect apply` on the VM, 2026-10-12, read the vault back as
    /// `OPEN  C:\ProgramData\WenleAV\quarantine: an ordinary user CAN write here
    /// — S-1-5-21-1-2-3-1001` and then failed with
    /// "the write reported success and the directory did not change" — about the
    /// one directory in the report it had not written to. The account named is
    /// the one that created the vault, which is the third access-control entry
    /// `av_quarantine::hardening` writes on purpose (see that module's own
    /// documentation of the limit), and the vault is the one entry in
    /// [`audit_product_dirs`] that `av-guard` refuses to protect by name.
    ///
    /// Sabotage: change `is_by_design`'s `DirKind::Vault` arm to `false` — which
    /// is what the code did before this test existed, with the vault answered as
    /// a path that plays no role — and this fails with the message below.
    /// Measured, not asserted.
    #[test]
    fn the_vault_is_reported_and_never_judged() {
        let audit = DirAudit {
            path: PathBuf::from(r"C:\ProgramData\WenleAV\quarantine"),
            writeable_by: vec!["S-1-5-21-1-2-3-1001".to_string()],
            ..a_writable_directory(r"C:\ProgramData\WenleAV\quarantine")
        };

        assert!(
            !is_open(DirKind::Vault, &audit),
            "the vault's permissions are av-quarantine's policy and this command must not fail \
             the machine for them"
        );
        assert!(
            is_by_design(DirKind::Vault),
            "the vault is printed as `by design`; if the mark and the verdict disagree the \
             report contradicts itself"
        );

        // Not because the audit says nothing: the same audit under a role, or at
        // a path that plays none, is a finding. What excuses the vault is which
        // directory it is.
        assert!(is_open(DirKind::Unrelated, &audit));
        for role in DirRole::ALL.into_iter().filter(|role| !role.users_may_write()) {
            assert!(is_open(DirKind::Role(role), &audit), "{role:?} was excused");
        }
    }

    /// A directory that is not there is not a finding, whatever its role.
    ///
    /// The `present` test is inside `is_open` and is checked after the role's,
    /// which is why this asserts the pair rather than only the absent case: an
    /// absent directory with no role must still be quiet, or the first `protect
    /// apply` on a fresh machine reports every data directory it has not made
    /// yet.
    #[test]
    fn a_directory_that_is_not_there_is_never_a_finding() {
        let absent = DirAudit {
            present: false,
            ..a_writable_directory(r"C:\ProgramData\WenleAV\db")
        };
        assert!(!is_open(DirKind::Role(DirRole::Data), &absent));
        assert!(!is_open(DirKind::Role(DirRole::Log), &absent));
        assert!(!is_open(DirKind::Vault, &absent));
        assert!(!is_open(DirKind::Unrelated, &absent));
    }


    /// The case the check exists for, asserted against the tree the test itself
    /// was built in rather than against a fixture.
    ///
    /// A temporary directory marked up to look like a workspace would test
    /// [`cargo_build_tree`] and not the thing that matters, which is whether the
    /// real build tree this binary came out of is recognised. The test
    /// executable is at `target/<profile>/deps/<name>-<hash>.exe` — three
    /// directories below the target directory, which the first version of this
    /// test got wrong by counting two, and the assertion below is what said so —
    /// so the answer is not in doubt when the check works. And if the layout
    /// ever changes, this fails rather than the check silently ceasing to fire,
    /// which is the failure mode that would matter: a refusal that stopped
    /// refusing would leave every other test in this crate passing.
    #[test]
    fn the_tree_this_test_was_built_in_is_recognised() {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let target = exe
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .expect("target/<profile>/deps/ has three parents above the binary");
        assert_eq!(
            target.file_name().and_then(|name| name.to_str()),
            Some("target"),
            "the test binary moved out of target/<profile>/deps, so this test can no longer \
             reach the build tree it means to check: {}",
            exe.display()
        );
        let root = cargo_build_tree(target).expect("target/ is inside a cargo workspace");
        assert!(
            root.join("Cargo.toml").is_file(),
            "{} was named as the workspace root and holds no Cargo.toml",
            root.display()
        );
    }

    /// The narrowness that makes the refusal believable: a directory called
    /// `target` is refused only when the directory above it is a workspace.
    ///
    /// An installation under `D:\target\` is unusual and possible, and refusing
    /// it would be this check reaching past its reason. The `Cargo.toml` test is
    /// the whole of what keeps it in bounds.
    #[test]
    fn a_directory_named_target_under_no_workspace_is_not_a_build_tree() {
        let parent = tempfile::tempdir().expect("a temporary directory");
        let target = parent.path().join("target");
        std::fs::create_dir(&target).expect("creating the directory named target");
        assert_eq!(cargo_build_tree(&target), None);

        std::fs::write(parent.path().join("Cargo.toml"), b"[workspace]\n")
            .expect("writing a workspace manifest");
        assert_eq!(cargo_build_tree(&target), Some(parent.path().to_path_buf()));
    }

    /// A nested path is refused by the same walk, which is what makes the check
    /// work for an install directory that is several levels below the artifact
    /// directory rather than the artifact directory itself.
    #[test]
    fn a_directory_below_the_build_tree_is_still_inside_it() {
        let parent = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(parent.path().join("Cargo.toml"), b"[workspace]\n")
            .expect("writing a workspace manifest");
        let deep = parent.path().join("target").join("debug").join("assets");
        std::fs::create_dir_all(&deep).expect("creating a directory below the target directory");
        assert_eq!(cargo_build_tree(&deep), Some(parent.path().to_path_buf()));
    }

    /// One of the product's own files, rewritten in place.
    fn rewritten() -> Change {
        Change::Modified {
            role: Role::Cli,
            path: PathBuf::from(r"C:\WenleAV\wenle.exe"),
            from: "00".repeat(32),
            to: "ff".repeat(32),
            signature: SignatureChange::Unchanged,
        }
    }

    /// A file that is not the product's, in a directory the product owns.
    fn stray() -> Change {
        Change::Added {
            path: PathBuf::from(r"C:\WenleAV\README.md"),
            recorded_absent: false,
        }
    }

    /// A file that appeared where an entry records that nothing is.
    fn appeared() -> Change {
        Change::Added {
            path: PathBuf::from(r"C:\ProgramData\WenleAV\db\rules.avdb"),
            recorded_absent: true,
        }
    }

    /// The sentence `status` fails with says what was found, in the words of
    /// what was found.
    ///
    /// Written from the VM's own output on 2026-10-10, which said "20 of the
    /// product's own files have changed" over twenty files that were never the
    /// product's — a readme, a test certificate, and copies of earlier binaries
    /// the user had kept. The count was of differences and the words were of
    /// something else.
    ///
    /// Sabotage: count `changes` instead of the alarming ones, or drop the
    /// appeared-file clause, and the assertions below fail on the case that
    /// matters — a file where the manifest records that nothing is must not be
    /// described as one of the product's own having changed.
    #[test]
    fn the_sentence_for_a_failed_status_names_the_kind_of_each_change() {
        assert_eq!(
            why_the_files_fail(&[rewritten()]),
            "one of the product's own files has changed"
        );
        assert_eq!(
            why_the_files_fail(&[rewritten(), rewritten()]),
            "2 of the product's own files have changed"
        );
        assert_eq!(
            why_the_files_fail(&[appeared()]),
            "a file has appeared where the manifest records that nothing is",
            "a file that appeared where an entry records that nothing is was not the product's \
             and did not change, so it is not described as one that did"
        );
        assert_eq!(
            why_the_files_fail(&[rewritten(), appeared(), appeared()]),
            "one of the product's own files has changed, and 2 files have appeared where the \
             manifest records that nothing is"
        );

        // The case `status` does not call this for, asserted so that a caller
        // which reached it the wrong way round would get a true sentence rather
        // than an empty one joined into the summary.
        assert_eq!(
            why_the_files_fail(&[stray(), stray()]),
            "2 file(s) that are not the product's are in the directories its files live in, and no \
             file the manifest names is different"
        );
    }
}
