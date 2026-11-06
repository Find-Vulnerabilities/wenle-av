//! `wenle update` -- install a checked package over this installation.
//!
//! # Why this exists
//!
//! Self-protection refuses writes, deletes and renames of the product's own
//! files from every image but the product's own. That is the right rule, and it
//! made the product impossible to update: on 2026-11-04 the only way in was to
//! stop the filter, copy the file and reboot, and the attempt left the service
//! binary **deleted**; on 2026-11-06 the same dance left it **truncated to
//! nothing**, and `sc start` answered `1392`, "the file or directory is
//! corrupted and unreadable". Both are worse than a refused write, and both came
//! from doing by hand what this command does with the manifest in front of it.
//!
//! # The protocol, in four steps
//!
//! 1. A release is a directory of files plus `manifest.txt`.
//! 2. `verify` hashes every file the manifest names and compares. It changes
//!    nothing, so it is safe to run on a package nobody trusts yet.
//! 3. `apply` verifies first and refuses the whole package on one mismatch. A
//!    half-installed product is not a state this command can leave behind.
//! 4. `apply` then stops the service, replaces the files, and starts it again.
//!
//! # The manifest
//!
//! One line per file: sixty-four hexadecimal characters, whitespace, the file's
//! name. That is `sha256sum`'s output, so a release can be assembled with tools
//! already on the machine and checked by a person with one they already trust.
//! Blank lines and `#` comments are ignored. Names are compared case-insensitively
//! because Windows does.
//!
//! # What this does not do yet
//!
//! It does not verify a signature over the manifest itself, and it does not
//! fetch a package from anywhere: both are the next step, and the reason the
//! manifest is a separate file rather than embedded is so that a signature can
//! be added beside it without changing the format.

use std::path::Path;

use anyhow::{anyhow, Context as _, Result};
use av_core::HashKind;

use crate::cli::{Globals, UpdateCommand};
use crate::commands::Context;
use crate::exit::Exit;
use crate::output;

mod sandbox;

/// The file a package's digests are read from.
const MANIFEST_FILE: &str = "manifest.txt";

/// One line of a package manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Lower-case hexadecimal SHA-256 of the file's contents.
    pub sha256: String,
    /// The file's name inside the package, and the name it takes beside the
    /// installed product.
    pub name: String,
}

/// Parse a manifest, returning what it names and what it does not parse.
///
/// A line that does not parse is an error rather than a skip: a release whose
/// manifest half-parses is a release that would install half of itself.
pub fn parse_manifest(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(digest), Some(name)) = (parts.next(), parts.next()) else {
            return Err(format!(
                "line {}: expected a digest and a name, found {:?}",
                number + 1,
                line
            ));
        };
        if parts.next().is_some() {
            return Err(format!(
                "line {}: more than one name after the digest; a name with a space in it \
                 cannot be expressed by this format",
                number + 1
            ));
        }
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "line {}: {:?} is not a SHA-256 digest",
                number + 1,
                digest
            ));
        }
        if name.contains('\\') || name.contains('/') || name == ".." || name == "." {
            return Err(format!(
                "line {}: {:?} is a path, not a file name; a package may not write into \
                 a directory",
                number + 1,
                name
            ));
        }
        entries.push(Entry {
            sha256: digest.to_ascii_lowercase(),
            name: name.to_string(),
        });
    }
    if entries.is_empty() {
        return Err("the manifest names no files".to_string());
    }
    Ok(entries)
}

/// Hash a file the way the manifest says to.
///
/// `pub(super)` because the sandbox hashes again at the moment of the copy: the
/// gap between verifying a package and installing from it is however long the
/// script runs, and a file that changed in that gap must not be installed.
pub(super) fn hash_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(HashKind::Sha256.digest(&bytes))
}

/// What `verify` found.
#[derive(Debug, Default)]
pub struct Verdict {
    /// Files present and matching.
    pub matching: Vec<String>,
    /// Files the manifest names whose digest differs, with what was found.
    pub differing: Vec<(String, String)>,
    /// Files the manifest names that are not in the package.
    pub missing: Vec<String>,
}

impl Verdict {
    /// Whether the package may be installed.
    pub fn is_installable(&self) -> bool {
        self.differing.is_empty() && self.missing.is_empty()
    }
}

/// Check a package directory against its manifest.
pub fn verify(dir: &Path) -> Result<Verdict> {
    let manifest_path = dir.join(MANIFEST_FILE);
    let text = std::fs::read_to_string(&manifest_path).with_context(|| {
        format!(
            "reading {}; a package is a directory of files and a {} beside them",
            manifest_path.display(),
            MANIFEST_FILE
        )
    })?;
    let entries = parse_manifest(&text).map_err(|error| anyhow!("{}: {error}", manifest_path.display()))?;

    let mut verdict = Verdict::default();
    for entry in entries {
        let path = dir.join(&entry.name);
        if !path.exists() {
            verdict.missing.push(entry.name);
            continue;
        }
        let found = hash_file(&path)?;
        if found == entry.sha256 {
            verdict.matching.push(entry.name);
        } else {
            verdict.differing.push((entry.name, found));
        }
    }
    Ok(verdict)
}

/// Run the command.
pub fn run(command: &UpdateCommand, _globals: &Globals, context: &Context) -> Result<Exit> {
    match command {
        UpdateCommand::Verify { dir } => verify_command(dir),
        UpdateCommand::Apply { dir, script } => apply_command(dir, script.as_deref(), context),
    }
}

/// `wenle update verify <dir>`.
fn verify_command(dir: &Path) -> Result<Exit> {
    let verdict = verify(dir)?;
    output::heading("Package");
    for name in &verdict.matching {
        println!("  {name} -- matches");
    }
    for name in &verdict.missing {
        println!("  {name} -- MISSING from the package");
    }
    for (name, found) in &verdict.differing {
        println!("  {name} -- DIFFERS (found {found})");
    }
    if verdict.is_installable() {
        println!();
        println!(
            "{} file(s) match their manifest and nothing is missing. Nothing was changed; \
             `wenle update apply` installs this package.",
            verdict.matching.len()
        );
        return Ok(Exit::Clean);
    }
    println!();
    println!(
        "{} file(s) do not match: this is not the package the manifest describes. Nothing \
         was changed.",
        verdict.missing.len() + verdict.differing.len()
    );
    Ok(Exit::Failure)
}

/// `wenle update apply <dir>`.
///
/// Verifies first, then hands the flow to the sandbox. The flow is a Lua script
/// because the order of the steps is policy and changes more often than the
/// operations; the operations themselves stay here, where a script cannot reach
/// a path of its own choosing.
///
/// The service is started again when the script stopped it and did not start it:
/// a product left stopped turns a failed update into an unprotected machine,
/// which is the outcome this command exists to avoid.
fn apply_command(dir: &Path, script: Option<&Path>, context: &Context) -> Result<Exit> {
    let verdict = verify(dir)?;
    if !verdict.is_installable() {
        output::error("the package does not match its manifest; nothing was changed");
        for name in &verdict.missing {
            eprintln!("  missing: {name}");
        }
        for (name, found) in &verdict.differing {
            eprintln!("  differs: {name} (found {found})");
        }
        return Ok(Exit::Failure);
    }

    let install_dir = context.paths.install_dir.clone();
    output::heading("Update");
    println!("  package:      {}", dir.display());
    println!("  installation: {}", install_dir.display());
    match script {
        Some(path) => println!("  flow:         {}", path.display()),
        None => println!("  flow:         built in"),
    }

    let text = sandbox::script_from(script)?;
    let entries = verified_entries(dir)?;
    let report = sandbox::run(dir, &install_dir, &entries, &text)?;

    if report.stopped && !report.started {
        output::warn("the script stopped the service and did not start it; starting it now");
        match av_service::install::start() {
            Ok(_) => println!("  the service was started"),
            Err(error) => output::error(&format!("the service could not be started: {error}")),
        }
    }

    if report.is_clean() {
        println!();
        println!(
            "{} file(s) installed. Take the tamper manifest again with \
             `wenle protect manifest`, which is what makes the next change visible.",
            report.installed.len()
        );
        return Ok(Exit::Clean);
    }
    println!();
    println!("{} file(s) installed, and this went wrong:", report.installed.len());
    for failure in &report.failures {
        println!("  {failure}");
    }
    Ok(Exit::Failure)
}

/// The manifest's entries, read back after verification.
///
/// Verification reports names; the sandbox needs the digests too, and re-reading
/// the manifest is cheaper than threading a second structure through the report.
fn verified_entries(dir: &Path) -> Result<Vec<Entry>> {
    let manifest_path = dir.join(MANIFEST_FILE);
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    parse_manifest(&text).map_err(|error| anyhow!("{}: {error}", manifest_path.display()))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_manifest_parses() {
        let text = "\
# a release
d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26  wenle.exe
\
         ";
        let entries = parse_manifest(text).expect("parses");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "wenle.exe");
        assert_eq!(entries[0].sha256.len(), 64);
    }

    #[test]
    fn a_line_without_a_digest_is_an_error() {
        assert!(parse_manifest("wenle.exe\n").is_err());
    }

    #[test]
    fn a_digest_that_is_not_a_digest_is_an_error() {
        assert!(parse_manifest("xyz  wenle.exe\n").is_err());
    }

    #[test]
    fn a_path_in_a_manifest_is_refused() {
        // A package that could name `..\..\Windows\System32\drivers\x.sys` would
        // be an installer with the product's privileges, which is exactly what
        // the manifest is here to prevent.
        assert!(parse_manifest(&format!("{}  ..\\evil.exe\n", "a".repeat(64))).is_err());
        assert!(parse_manifest(&format!("{}  sub/evil.exe\n", "a".repeat(64))).is_err());
    }

    #[test]
    fn a_manifest_naming_nothing_is_an_error() {
        assert!(parse_manifest("# only a comment\n\n").is_err());
    }

    #[test]
    fn the_digest_is_read_case_insensitively() {
        let upper = "A".repeat(64);
        let entries = parse_manifest(&format!("{upper}  wenle.exe\n")).expect("parses");
        assert_eq!(entries[0].sha256, "a".repeat(64));
    }
}
