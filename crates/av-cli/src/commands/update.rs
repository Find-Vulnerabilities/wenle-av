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

/// One line of a *remote* manifest: the digest, the name, and where to get it.
///
/// A release published for fetching carries a third field the local manifest
/// does not: the URL of the file. Without it every file would have to be guessed
/// from the manifest's own location, which works for a flat release and not for
/// one that keeps its binaries in a subdirectory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    /// Lower-case hexadecimal SHA-256 of the file's contents.
    pub sha256: String,
    /// The file's name, written into the package under this name.
    pub name: String,
    /// Where to fetch it, or `None` to resolve it beside the manifest.
    pub url: Option<String>,
}

/// Parse a remote manifest, returning what it names and what does not parse.
///
/// Same shape as [`parse_manifest`] with an optional third field. The rules that
/// matter are the same ones, and they matter more here: a name is a file name
/// and never a path, because this writes into a directory the caller named and
/// not into one the release names.
pub fn parse_remote_manifest(text: &str) -> Result<Vec<RemoteEntry>, String> {
    let mut entries = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(digest), Some(name)) = (parts.next(), parts.next()) else {
            return Err(format!(
                "line {}: expected a digest, a name and an optional url, found {:?}",
                number + 1,
                line
            ));
        };
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "line {}: {:?} is not a SHA-256 digest",
                number + 1,
                digest
            ));
        }
        if name.contains('\\') || name.contains('/') || name == ".." || name == "." {
            return Err(format!(
                "line {}: {:?} is a path, not a file name; a release may not write into a \
                 directory",
                number + 1,
                name
            ));
        }
        let url = parts.next().map(|url| url.to_string());
        if parts.next().is_some() {
            return Err(format!(
                "line {}: more than one url after the name",
                number + 1
            ));
        }
        entries.push(RemoteEntry {
            sha256: digest.to_ascii_lowercase(),
            name: name.to_string(),
            url,
        });
    }
    if entries.is_empty() {
        return Err("the manifest names no files".to_string());
    }
    Ok(entries)
}

/// Resolve a file's URL: what the manifest says, or the name beside it.
fn resolve_url(manifest_url: &str, entry: &RemoteEntry) -> String {
    if let Some(url) = &entry.url {
        return url.clone();
    }
    match manifest_url.rfind('/') {
        Some(cut) => format!("{}/{}", &manifest_url[..cut], entry.name),
        None => entry.name.clone(),
    }
}

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
        UpdateCommand::Fetch { url, to } => fetch_command(url, to),
        UpdateCommand::Apply { dir, script } => apply_command(dir, script.as_deref(), context),
        UpdateCommand::Rollback => rollback_command(context),
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

/// `wenle update fetch <URL> --to <DIR>`.
///
/// The half of an update this product did not have: getting the files. It reads
/// a manifest over the network, writes each named file into `to`, and checks
/// every one against the digest the manifest gave. What comes out is an ordinary
/// package directory, so `verify` and `apply` need to know nothing about where
/// it came from.
///
/// # What this does and does not establish
///
/// HTTPS and the digest together say: these bytes are the ones this manifest
/// describes, and they arrived unaltered. They do **not** say the manifest came
/// from Wenle -- that is a signature over the manifest, and it is the next piece
/// of this, not this piece. So the command says where it fetched from and the
/// caller decides whether that is a place it trusts.
fn fetch_command(url: &str, to: &Path) -> Result<Exit> {
    output::heading("Fetch");
    println!("  source:  {url}");
    println!("  package: {}", to.display());
    if !url.starts_with("https://") {
        output::error(
            "only https:// is accepted: a manifest that arrives over plain http can be changed in \
             flight, and then every digest in it is a digest the attacker chose",
        );
        return Ok(Exit::Failure);
    }

    let body = match ureq::get(url).call() {
        Ok(response) => response.into_string().context("reading the manifest")?,
        Err(error) => {
            output::error(&format!("{url} could not be fetched: {error}"));
            return Ok(Exit::Failure);
        }
    };
    let entries = match parse_remote_manifest(&body) {
        Ok(entries) => entries,
        Err(error) => {
            output::error(&format!("{url}: {error}"));
            return Ok(Exit::Failure);
        }
    };

    std::fs::create_dir_all(to)
        .with_context(|| format!("creating {}", to.display()))?;

    let mut manifest = String::new();
    let mut failures = Vec::new();
    for entry in &entries {
        let target = to.join(&entry.name);
        let file_url = resolve_url(url, entry);
        let response = match ureq::get(&file_url).call() {
            Ok(response) => response,
            Err(error) => {
                failures.push(format!("{}: {error}", file_url));
                continue;
            }
        };
        let mut reader = response.into_reader();
        let mut file = match std::fs::File::create(&target) {
            Ok(file) => file,
            Err(error) => {
                failures.push(format!("{}: {error}", target.display()));
                continue;
            }
        };
        if let Err(error) = std::io::copy(&mut reader, &mut file) {
            failures.push(format!("{}: {error}", target.display()));
            continue;
        }
        drop(file);
        match hash_file(&target) {
            Ok(found) if found == entry.sha256 => {
                println!("  {} -- fetched, matches", entry.name);
                manifest.push_str(&format!("{}  {}\n", entry.sha256, entry.name));
            }
            Ok(found) => {
                // A file that does not match is not left behind: the package
                // directory is what somebody will run `apply` on next, and a
                // wrong file in it is a trap that was already sprung once.
                let _ = std::fs::remove_file(&target);
                failures.push(format!(
                    "{}: fetched {found}, the manifest says {}",
                    entry.name, entry.sha256
                ));
            }
            Err(error) => failures.push(format!("{}: {error}", entry.name)),
        }
    }

    if !failures.is_empty() {
        output::error("the package was not written, because not every file arrived intact");
        for failure in &failures {
            println!("  {failure}");
        }
        return Ok(Exit::Failure);
    }

    let manifest_path = to.join(MANIFEST_FILE);
    std::fs::write(&manifest_path, manifest)
        .with_context(|| format!("writing {}", manifest_path.display()))?;
    println!();
    println!(
        "{} file(s) fetched into {}. Check them again with `wenle update verify` before applying; \
         the next step is `wenle update apply {}`.",
        entries.len(),
        to.display(),
        to.display()
    );
    Ok(Exit::Clean)
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
    // The state being replaced, kept where `rollback` can find it. Taken before
    // anything is touched, because a backup taken afterwards is a backup of the
    // new files.
    match backup_current(&install_dir, &entries) {
        Ok(count) => println!("  {count} file(s) of the present installation kept as .old"),
        Err(error) => {
            output::error(&format!(
                "the present installation could not be recorded, so nothing was changed: {error}"
            ));
            return Ok(Exit::Failure);
        }
    }
    // Images a previous update moved aside. The one this process is running
    // from cannot be removed while it is mapped -- measured in the test VM on
    // 2026-11-06, where the update left `wenle.old` behind for exactly that
    // reason -- but everything else can, and `protect verify` should not keep
    // reporting them as files nobody explained.
    let swept = sweep_old_files(&install_dir);
    if swept > 0 {
        println!("  {swept} leftover image(s) from an earlier update removed");
    }
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

/// Remove the images an earlier update moved aside, and say how many went.
///
/// Only names this product ships are swept: a `.old` file beside the product
/// could be anything, and an updater that deletes by extension is an updater
/// that deletes somebody's backup. The image this process is running from is
/// locked and stays until the machine reboots or the next update runs from the
/// new one; that is expected, not a failure.
fn sweep_old_files(install_dir: &Path) -> usize {
    const SHIPPED: [&str; 4] = [
        "wenle-av-service.exe.old",
        "wenle.exe.old",
        "wenle-gui.exe.old",
        "av_amsi.dll.old",
    ];
    let mut removed = 0;
    for name in SHIPPED {
        let path = install_dir.join(name);
        if path.exists() && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Where the state being replaced is recorded, so `rollback` can put it back.
const STATE_FILE: &str = "update-state.txt";

/// Record the present installation before the package replaces it.
///
/// For every file the package names that is already installed, the bytes are
/// copied to `<name>.old` and their digest written to `update-state.txt`. A
/// rollback is then a copy in the other direction, and it can check that what it
/// is about to install is what was recorded rather than what happens to be on
/// disk.
///
/// A backup taken *after* the first file is replaced is a backup of a mixture of
/// two installations, so this runs before the flow does anything.
fn backup_current(install_dir: &Path, entries: &[Entry]) -> Result<usize> {
    let mut state = String::new();
    let mut count = 0;
    for entry in entries {
        let current = install_dir.join(&entry.name);
        if !current.exists() {
            continue;
        }
        let digest = hash_file(&current)?;
        let backup = backup_path(install_dir, &entry.name);
        std::fs::copy(&current, &backup)
            .with_context(|| format!("keeping {} as {}", current.display(), backup.display()))?;
        state.push_str(&format!("{digest}  {}\n", entry.name));
        count += 1;
    }
    let state_path = install_dir.join(STATE_FILE);
    std::fs::write(&state_path, state)
        .with_context(|| format!("recording the present installation in {}", state_path.display()))?;
    Ok(count)
}

/// The name a backup of `name` takes beside it.
fn backup_path(install_dir: &Path, name: &str) -> std::path::PathBuf {
    install_dir.join(format!("{name}.old"))
}

/// Put back the installation an earlier `apply` replaced.
///
/// Reads `update-state.txt`, checks each backup against the digest recorded at
/// the time, stops the service, installs the backups and starts the service
/// again. Refuses the whole rollback when one backup is missing or does not
/// match: a half-restored installation is a mixture of two versions, which is
/// worse than either.
fn rollback_command(context: &Context) -> Result<Exit> {
    let install_dir = context.paths.install_dir.clone();
    output::heading("Rollback");
    println!("  installation: {}", install_dir.display());

    let state_path = install_dir.join(STATE_FILE);
    let text = match std::fs::read_to_string(&state_path) {
        Ok(text) => text,
        Err(error) => {
            output::error(&format!(
                "nothing to roll back to: {} could not be read ({error}). It is written by \
                 `wenle update apply`, and only the most recent update keeps one.",
                state_path.display()
            ));
            return Ok(Exit::Failure);
        }
    };
    let entries = match parse_manifest(&text) {
        Ok(entries) => entries,
        Err(error) => {
            output::error(&format!("{}: {error}", state_path.display()));
            return Ok(Exit::Failure);
        }
    };

    // Check every backup before changing anything.
    let mut problems = Vec::new();
    for entry in &entries {
        let backup = backup_path(&install_dir, &entry.name);
        match hash_file(&backup) {
            Ok(found) if found == entry.sha256 => {}
            Ok(found) => problems.push(format!(
                "{} is not what was recorded (recorded {}, found {found})",
                backup.display(),
                entry.sha256
            )),
            Err(error) => problems.push(format!("{}: {error}", backup.display())),
        }
    }
    if !problems.is_empty() {
        output::error("nothing was changed, because not every backup matches what was recorded");
        for problem in &problems {
            println!("  {problem}");
        }
        return Ok(Exit::Failure);
    }

    match av_service::install::stop_and_wait(std::time::Duration::from_secs(30)) {
        Ok(_) => println!("  the service was asked to stop, and has stopped"),
        Err(error) => println!("  the service could not be stopped: {error}"),
    }

    let mut restored = 0;
    let mut failures = Vec::new();
    for entry in &entries {
        let backup = backup_path(&install_dir, &entry.name);
        let target = install_dir.join(&entry.name);
        match sandbox::install_file(&backup, &target) {
            Ok(()) => {
                println!("  {} -- restored", entry.name);
                restored += 1;
            }
            Err(error) => failures.push(format!("{}: {error}", entry.name)),
        }
    }

    match av_service::install::start() {
        Ok(_) => println!("  the service was started"),
        Err(error) => println!("  the service could not be started: {error}"),
    }

    if failures.is_empty() {
        println!();
        println!("{restored} file(s) restored. `wenle protect manifest` records the restored files.");
        return Ok(Exit::Clean);
    }
    println!();
    println!("{restored} file(s) restored, {} failed:", failures.len());
    for failure in &failures {
        println!("  {failure}");
    }
    Ok(Exit::Failure)
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

    #[test]
    fn a_remote_manifest_may_name_a_url_or_leave_it_out() {
        let digest = "a".repeat(64);
        let text = format!(
            "{digest}  wenle.exe  https://example.invalid/rel/wenle.exe\n\
             {digest}  rules.avdb\n"
        );
        let entries = parse_remote_manifest(&text).expect("parses");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].url.as_deref(),
            Some("https://example.invalid/rel/wenle.exe")
        );
        assert_eq!(entries[1].url, None);
    }

    #[test]
    fn a_url_less_remote_entry_resolves_beside_the_manifest() {
        let entry = RemoteEntry {
            sha256: "a".repeat(64),
            name: "wenle.exe".to_string(),
            url: None,
        };
        assert_eq!(
            resolve_url("https://example.invalid/rel/manifest.txt", &entry),
            "https://example.invalid/rel/wenle.exe"
        );
    }

    #[test]
    fn a_remote_manifest_cannot_name_a_path() {
        // The same rule as the local manifest, and it matters more here: this
        // writes into a directory the caller named, not one the release names.
        let digest = "a".repeat(64);
        assert!(parse_remote_manifest(&format!("{digest}  ../../evil.exe\n")).is_err());
        assert!(parse_remote_manifest(&format!("{digest}  sub/evil.exe\n")).is_err());
    }
}
