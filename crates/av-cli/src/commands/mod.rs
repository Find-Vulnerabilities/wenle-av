//! The nine things `wenle` does.
//!
//! Each command is one file and each owns its own output. What they share is
//! here: where the product keeps its files, where its rule database is, and the
//! one place a database is loaded from disk — because "which rule database am I
//! actually running" is the question a user asks when a scan does not detect
//! something, and it has to have one answer.
//!
//! [`service`] is the odd one out and is deliberately so: the other four work
//! on files this process can open, and it works on a *machine* — a name in the
//! Service Control Manager and a service on the far end of a pipe. It is also
//! the only one that changes the machine it is run on, which is why every verb
//! that does says so in its own help text.
//!
//! [`config`] is odd in the other direction: it is the only command that does
//! not take a [`Context`], because the configuration is its subject rather than
//! its premise. See [`Context::paths`] for the half of the layout it does take.

pub mod build;
pub mod config;
pub mod db;
pub mod integrate;
pub mod memory;
pub mod protect;
pub mod quarantine;
pub mod scan;
pub mod service;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _, Result};
use av_core::{AvConfig, AvPaths};
use av_quarantine::{QuarantinePolicy, QuarantineVault};
use av_rules::database::RuleDatabase;

use crate::output;

/// The name of the compiled rule database inside the data directory.
pub const DATABASE_FILE: &str = "rules.avdb";

/// Where everything lives, and what the configuration says.
#[derive(Debug)]
pub struct Context {
    pub paths: AvPaths,
    pub config: AvConfig,
}

impl Context {
    /// Resolve the layout and read the configuration.
    ///
    /// `data_dir` is `--data-dir`; `None` means the installed location.
    ///
    /// A missing configuration is not an error: a freshly installed product has
    /// none, and the defaults are the configuration a user who has not written
    /// one has agreed to. A configuration that exists and cannot be parsed *is*
    /// an error, because it means the product's behaviour would silently differ
    /// from what the file says.
    pub fn resolve(data_dir: Option<&Path>) -> Result<Self> {
        let paths = Self::paths(data_dir)?;
        let config = AvConfig::load_or_default(&paths.config_file)
            .with_context(|| format!("reading {}", paths.config_file.display()))?;
        Ok(Self { paths, config })
    }

    /// Where everything lives, without reading the configuration.
    ///
    /// Split out of [`Self::resolve`] for one caller: [`config`], whose subject
    /// is the configuration file and which therefore has to run
    /// when that file cannot be read. Resolving the layout never depends on the
    /// document, so the two steps were only ever together because every other
    /// command needs both.
    pub fn paths(data_dir: Option<&Path>) -> Result<AvPaths> {
        let derived = AvPaths::for_current_exe()
            .context("cannot determine where the product is installed")?;
        // Only the data root is overridable. Where the executable lives is a
        // fact about the running process; where its state lives is a choice,
        // and it is the choice that makes a portable install and a support
        // engineer's examination of someone else's state possible.
        Ok(match data_dir {
            Some(dir) => AvPaths::with_data_dir(derived.install_dir, dir),
            None => derived,
        })
    }

    /// The rule database to use, and where that was decided.
    ///
    /// The search order is deliberate, and the second entry is why this returns
    /// the path rather than just loading it: a developer running the binary out
    /// of `target/debug` wants the database beside the binary they just built,
    /// not the one the installed product is using, and nothing about the two is
    /// visible in a scan report unless it is printed.
    pub fn database_path(&self, override_path: Option<&Path>) -> Result<PathBuf> {
        if let Some(path) = override_path {
            return Ok(path.to_path_buf());
        }
        let mut looked = Vec::new();
        for candidate in [
            self.paths.db_dir.join(DATABASE_FILE),
            self.paths.install_dir.join(DATABASE_FILE),
        ] {
            if candidate.is_file() {
                return Ok(candidate);
            }
            looked.push(candidate);
        }
        Err(anyhow!(
            "no rule database found. Looked in {}.\n       \
             Build one with `wenle build <rules>`, or point at one with `--db`.",
            looked
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    /// Check that the rule database can be read, without reading it.
    ///
    /// # Why this is separate from [`Self::load_database`]
    ///
    /// Because of when a scan finds out. The command asks this *before* it walks
    /// the tree and loads the database *after* it, and both orderings were wrong
    /// on their own. Loading first made a mistyped path wait for ten thousand
    /// rules to be parsed before saying the path was wrong; walking first made an
    /// unreadable database wait for the whole tree, which is the failure a user
    /// hit and reported — a folder scan that ran for a while and then failed with
    /// a message about `%ProgramData%`, so that the obvious reading was that
    /// something in their folder was at fault.
    ///
    /// Twenty bytes of header answer the second question without costing the
    /// first. What this does not claim is that the scan will succeed: see
    /// [`RuleDatabase::check_file`] for the difference between a header that can
    /// be read and a rule set that can be used.
    pub fn check_database(&self, override_path: Option<&Path>) -> Result<()> {
        let path = self.database_path(override_path)?;
        RuleDatabase::check_file(&path).with_context(|| {
            format!(
                "the rule database at {} cannot be used by this build",
                path.display()
            )
        })?;
        Ok(())
    }

    /// Load a rule database from disk, and say where it came from.
    ///
    /// The path comes back with the database rather than being left for the
    /// caller to look up again, and that is the whole point of the signature.
    /// [`Self::database_path`] searches two directories — one the user built
    /// beside the binary, one the installed product is using — and no output
    /// distinguishes them unless the answer is printed. A caller that has to ask
    /// a second time can forget to; a caller handed a tuple has to do something
    /// visible with the path to lose it.
    pub fn load_database(&self, override_path: Option<&Path>) -> Result<(RuleDatabase, PathBuf)> {
        let path = self.database_path(override_path)?;
        let database = RuleDatabase::load(&path)
            .with_context(|| format!("loading the rule database at {}", path.display()))?;
        log::info!("loaded {} rules from {}", database.len(), path.display());
        Ok((database, path))
    }

    /// Where the vault is, if the caller named a directory.
    pub fn vault_path(&self, override_path: Option<&Path>) -> PathBuf {
        override_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.paths.quarantine_dir.clone())
    }

    /// Open the quarantine vault.
    ///
    /// The policy comes from the configuration, so a vault opened by the
    /// command line enforces exactly what the service enforces: the retention
    /// and size ceiling a user set are not something a maintenance pass run by
    /// hand should be able to ignore by accident.
    ///
    /// Opening through [`QuarantineVault::open_recovering`] rather than `open`
    /// is the deliberate choice here. `open` refuses a vault whose index will
    /// not decode, which is the right answer for the service — better to fail
    /// loudly than to start an empty vault beside a directory full of
    /// unexplained payloads. On the command line the same refusal leaves an
    /// operator with no tool at all to look at the vault they are worried
    /// about, and the recovery path is the one that renames the bad index
    /// rather than deleting it, so nothing is lost by taking it.
    pub fn open_vault(&self, override_path: Option<&Path>) -> Result<QuarantineVault> {
        let root = self.vault_path(override_path);
        let policy = QuarantinePolicy::from(&self.config.quarantine);
        let mut vault = QuarantineVault::open_recovering(&root, policy)
            .with_context(|| format!("opening the quarantine vault at {}", root.display()))?;
        vault.subscribe(av_quarantine::logging_listener());
        log::info!(
            "opened the quarantine vault at {} with {} items",
            root.display(),
            vault.entries().len()
        );
        Ok(vault)
    }

    /// Say out loud which requested behaviours this build does not have.
    ///
    /// A configuration that asks for something the engine cannot do is the one
    /// failure mode a user cannot detect by reading a report: a scan that does
    /// not look inside archives finds nothing inside archives, and looks
    /// exactly like a scan that looked and found nothing. Saying so costs one
    /// line per run and is the difference between a report that means something
    /// and one that means less than it appears to.
    ///
    /// Archive scanning used to be listed here, and so did memory scanning. Both
    /// are now done: the engine examines archive members, and `wenle scan` reads
    /// the memory of running processes — see [`crate::memory`]. What is left is
    /// the part of memory scanning that is still missing, and it is missing by
    /// design rather than by omission, so it is said precisely rather than
    /// waved at.
    ///
    /// The two halves of the sentence are the two things a user might reasonably
    /// expect from "memory scanning" and does not get. What a finding is *about*
    /// is the file its bytes came from, and with `--quarantine` that file is
    /// taken when it is malicious in its own right; but bytes that came from no
    /// file — injected code, which is the case memory scanning exists for — have
    /// nowhere to go, and the process holding them is left running. `--quarantine`
    /// moves a *file* into the vault and there is nothing equivalent for an
    /// address space. And the sweep is a snapshot taken while the scan runs, not
    /// the continuous watching that the words "memory scanning" suggest to anyone
    /// who has used a product that does it in a driver — the difference between
    /// "nothing was found at 14:02" and "nothing has been found", which is the
    /// difference a user would act on wrongly.
    ///
    /// `memory` is what the run is *going to do*, which is not the same question
    /// as what the configuration says: `--memory` turns the sweep on for a run
    /// on a machine whose configuration is quiet, and `--no-memory` turns it off
    /// for one whose configuration asks for it. Reading `self.config` here would
    /// get both of those backwards, and the warning would be printed for a run
    /// that will not sweep and withheld from the one that will — which is exactly
    /// the failure this whole method exists to prevent, in reverse.
    pub fn warn_about_gaps(&self, memory: bool) {
        if memory {
            output::warn(
                "this configuration asks for memory scanning, and this run will do it: \
                 running processes are read and examined. Two things about that are worth \
                 knowing before you read the result. A finding's file is quarantined when \
                 `--quarantine` is given and that file is malicious in its own right, but \
                 bytes that came from no file at all — injected code, which is the case this \
                 exists for — have nothing to put in a vault, and the process holding them is \
                 left running. And this examines what is in memory while the scan runs, so it \
                 says nothing about what happens after it finishes.",
            );
        }
    }
}

/// Write a file, creating the parent directory, with a useful error.
pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
