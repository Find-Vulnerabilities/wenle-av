//! The update flow as a Lua script, with the privileged half in Rust.
//!
//! # Why the split
//!
//! An updater is the most dangerous program a security product ships: it
//! writes the files that protect the machine. Written as a script with file
//! access, one compromised script is a compromised product -- and the rewrite
//! this replaces already cost two service binaries (2026-11-04 and 2026-11-06).
//!
//! So the script decides **what happens in what order** and the Rust side does
//! every operation that touches the machine. The sandbox has no `io`, no `os`,
//! no `package`, no `debug`, no `dofile`, and no way to name a path: the four
//! things it can do are
//!
//! * `update.log(message)` -- say something to the operator,
//! * `update.names()` -- the file names the verified manifest holds,
//! * `update.stop_service()` / `update.start_service()`,
//! * `update.install(name)` -- copy **that** file from the package, with its
//!   digest checked again at the moment of the copy,
//! * `update.fail(message)` -- stop, having recorded why.
//!
//! That is the whole vocabulary. A script cannot widen it: the table is built
//! here, the standard libraries are not loaded, and `update.install` ignores any
//! name the manifest does not hold.
//!
//! # The digest is checked twice on purpose
//!
//! [`super::verify`] checks the package before the script runs. `install` checks
//! the file again immediately before copying it, because the two are separated
//! by however long the script runs and a package directory that cannot be
//! trusted between those two moments is exactly the case an updater exists to
//! survive.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context as _, Result};
use mlua::{Lua, LuaOptions, StdLib};

use super::{Entry, hash_file};

/// What the script did, for the caller to report and to exit with.
#[derive(Debug, Default)]
pub struct Report {
    /// Files installed, in the order the script asked for them.
    pub installed: Vec<String>,
    /// The service was stopped at least once.
    pub stopped: bool,
    /// The service was started after the last stop.
    pub started: bool,
    /// Messages from `update.fail`, and operations that failed.
    pub failures: Vec<String>,
}

impl Report {
    /// Whether the update finished with nothing wrong.
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Copy one file by opening both ends ourselves.
///
/// `std::fs::copy` is `CopyFileEx`, which the file system is free to serve on a
/// **system worker thread**; the driver's write gate then sees `System` rather
/// than this process and refuses the write it was asked to allow. Measured in
/// the test VM on 2026-11-06 as os error 5 on the update's own service binary.
/// Opening, reading and writing here means every request arrives from this
/// process, which is the one the driver has an exception for.
fn copy_here(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut source = std::fs::File::open(from)?;
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(to)?;
    std::io::copy(&mut source, &mut target)?;
    target.flush()?;
    Ok(())
}

/// Put one file in place, working around the file that cannot be replaced.
///
/// Windows will not overwrite a running image, and the two files an update
/// exists to replace -- the service and the command-line tool running this
/// command -- are both running. Renaming a running image *is* allowed, so the
/// old one is moved aside and the new one takes its name; the old file stays as
/// `<name>.old` and is removed the next time this runs.
///
/// Measured in the test VM on 2026-11-06: the direct copy failed with os error
/// 32, "the process cannot access the file because it is being used by another
/// process", for `wenle-av-service.exe` even after the stop request had been
/// answered. The rename is what makes the update possible at all.
pub(super) fn install_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match copy_here(from, to) {
        Ok(()) => Ok(()),
        Err(first) => {
            // Appended, not `with_extension`: that *replaces* the extension, so
            // `wenle.exe` became `wenle.old` and every sweep looking for
            // `wenle.exe.old` found nothing. Measured in the test VM on
            // 2026-11-07: two images survived a service restart that was
            // supposed to remove them.
            let aside = match to.file_name() {
                Some(name) => to.with_file_name(format!("{}.old", name.to_string_lossy())),
                None => to.with_extension("old"),
            };
            let _ = std::fs::remove_file(&aside);
            match std::fs::rename(to, &aside) {
                Ok(()) => match copy_here(from, to) {
                    Ok(()) => Ok(()),
                    Err(second) => {
                        // Put the old one back rather than leave the product
                        // without a file at all.
                        let _ = std::fs::rename(&aside, to);
                        Err(second)
                    }
                },
                Err(_) => Err(first),
            }
        }
    }
}

/// The state a running script may see and change.
struct Session {
    package: PathBuf,
    install_dir: PathBuf,
    entries: Vec<Entry>,
    report: Report,
}

impl Session {
    fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(name))
    }
}

/// Run `script` against a package that has already been verified.
///
/// `entries` is the verified manifest: a script cannot install a file the
/// manifest does not name, and cannot install one whose contents have changed
/// since it was verified.
pub fn run(
    package: &Path,
    install_dir: &Path,
    entries: &[Entry],
    script: &str,
) -> Result<Report> {
    // `ALL_SAFE` is everything that computes and nothing that reaches the
    // machine: `string`, `table`, `math`, `utf8`, `coroutine` and the base
    // functions, without `io`, `os`, `package` or `debug`. Measured in the test
    // VM on 2026-11-06: `NONE` was too little -- the built-in flow itself failed
    // on `string.format`, and a package author would have failed on `ipairs`.
    // What makes the sandbox a sandbox is the absence of the four that can name
    // a file, a process or a module, not the absence of arithmetic.
    // Named one by one rather than `ALL_SAFE`, which was measured in this
    // session to load `io` and `os` as well -- a script that can open a file is
    // not a sandbox, and the test below is what found it.
    let libs = StdLib::STRING | StdLib::TABLE | StdLib::MATH | StdLib::UTF8 | StdLib::COROUTINE;
    let lua = Lua::new_with(libs, LuaOptions::default())
        .context("starting the update script's interpreter")?;
    // A script that allocates without bound must not take the updater with it.
    // Sixteen megabytes is far more than the flow needs and far less than the
    // machine would miss.
    lua.set_memory_limit(16 * 1024 * 1024)
        .context("setting the update script's memory limit")?;

    let session = Rc::new(RefCell::new(Session {
        package: package.to_path_buf(),
        install_dir: install_dir.to_path_buf(),
        entries: entries.to_vec(),
        report: Report::default(),
    }));

    let api = lua.create_table().context("building the update script's api")?;

    let s = Rc::clone(&session);
    api.set(
        "log",
        lua.create_function(move |_, message: String| {
            println!("  {message}");
            let _ = &s;
            Ok(())
        })?,
    )?;

    let s = Rc::clone(&session);
    api.set(
        "names",
        lua.create_function(move |lua, ()| {
            let session = s.borrow();
            let table = lua.create_table()?;
            for (index, entry) in session.entries.iter().enumerate() {
                table.set(index + 1, entry.name.clone())?;
            }
            Ok(table)
        })?,
    )?;

    let s = Rc::clone(&session);
    api.set(
        "install",
        lua.create_function(move |_, name: String| {
            let mut session = s.borrow_mut();
            let Some(entry) = session.entry(&name).cloned() else {
                let message = format!("{name} is not in the package's manifest");
                session.report.failures.push(message.clone());
                return Err(mlua::Error::RuntimeError(message));
            };
            let from = session.package.join(&entry.name);
            // Checked again here, not only before the script ran: see the module
            // documentation.
            match hash_file(&from) {
                Ok(found) if found == entry.sha256 => {}
                Ok(found) => {
                    let message = format!(
                        "{} changed after verification: manifest {}, found {}",
                        entry.name, entry.sha256, found
                    );
                    session.report.failures.push(message.clone());
                    return Err(mlua::Error::RuntimeError(message));
                }
                Err(error) => {
                    let message = format!("{} could not be hashed: {error}", entry.name);
                    session.report.failures.push(message.clone());
                    return Err(mlua::Error::RuntimeError(message));
                }
            }
            let to = session.install_dir.join(&entry.name);
            match install_file(&from, &to) {
                Ok(()) => {
                    println!("  {} -- installed", entry.name);
                    session.report.installed.push(entry.name.clone());
                    Ok(true)
                }
                Err(error) => {
                    let message = format!("{} could not be installed: {error}", entry.name);
                    session.report.failures.push(message.clone());
                    Err(mlua::Error::RuntimeError(message))
                }
            }
        })?,
    )?;

    let s = Rc::clone(&session);
    api.set(
        "stop_service",
        lua.create_function(move |_, ()| {
            let mut session = s.borrow_mut();
            // Nothing to stop is not a failure. The product can be installed as
            // a portable directory with no service at all, and an update run
            // there has to work; it is also what makes the whole flow testable
            // on a machine that has never had the service installed.
            if matches!(
                av_service::install::state(),
                Ok(av_service::install::ScmState::NotInstalled)
            ) {
                println!("  no service is installed here, so there is nothing to stop");
                return Ok(false);
            }
            // Wait for it: a copy that starts while the service process is
            // still alive fails with a sharing violation, which is exactly the
            // file an update exists to replace. See `install::stop_and_wait`.
            match av_service::install::stop_and_wait(std::time::Duration::from_secs(30)) {
                Ok(_) => {
                    println!("  the service was asked to stop, and has stopped");
                    session.report.stopped = true;
                    Ok(true)
                }
                Err(error) => {
                    let message = format!("the service could not be asked to stop: {error}");
                    session.report.failures.push(message.clone());
                    Err(mlua::Error::RuntimeError(message))
                }
            }
        })?,
    )?;

    let s = Rc::clone(&session);
    api.set(
        "start_service",
        lua.create_function(move |_, ()| {
            let mut session = s.borrow_mut();
            // The same rule as stopping: a portable installation has no service,
            // and an update of one must not report a failure it did not have.
            if matches!(
                av_service::install::state(),
                Ok(av_service::install::ScmState::NotInstalled)
            ) {
                println!("  no service is installed here, so there is nothing to start");
                return Ok(false);
            }
            match av_service::install::start() {
                Ok(_) => {
                    println!("  the service was started");
                    session.report.started = true;
                    Ok(true)
                }
                Err(error) => {
                    let message = format!("the service could not be started: {error}");
                    session.report.failures.push(message.clone());
                    Err(mlua::Error::RuntimeError(message))
                }
            }
        })?,
    )?;

    let s = Rc::clone(&session);
    api.set(
        "fail",
        lua.create_function(move |_, message: String| {
            s.borrow_mut().report.failures.push(message.clone());
            Err::<(), _>(mlua::Error::RuntimeError(message))
        })?,
    )?;

    lua.globals()
        .set("update", api)
        .context("installing the update script's api")?;

    let outcome = lua.load(script).set_name("update.lua").exec();
    let mut report = session.borrow().report.clone();
    match outcome {
        Ok(()) => {}
        Err(error) => {
            // The script's own `fail` and every failed operation already wrote
            // to `failures`; this keeps a syntax or runtime error from being
            // silent, which is the one way an updater can lie about finishing.
            let rendered = error.to_string();
            if !report.failures.iter().any(|failure| rendered.contains(failure)) {
                report.failures.push(rendered);
            }
        }
    }
    Ok(report)
}

impl Clone for Report {
    fn clone(&self) -> Self {
        Report {
            installed: self.installed.clone(),
            stopped: self.stopped,
            started: self.started,
            failures: self.failures.clone(),
        }
    }
}

/// A default flow, used when the package does not carry its own.
///
/// It is written as Lua rather than as Rust so that the common case exercises
/// the same path a package with a custom flow does: a default that took a
/// different code path would not tell anybody whether the scripted one works.
pub const DEFAULT_SCRIPT: &str = r#"
local names = update.names()
update.log("installing " .. #names .. " file(s)")
update.stop_service()
for _, name in ipairs(names) do
    update.install(name)
end
update.start_service()
"#;

/// Read a script from a path, or the default when none is named.
pub fn script_from(path: Option<&Path>) -> Result<String> {
    match path {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
        }
        None => Ok(DEFAULT_SCRIPT.to_string()),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// The default flow against a package of one file, with the service calls
    /// stubbed out by not being reachable: a sandbox test cannot stop a service,
    /// so this exercises `names`, `install` and the digest check, which is where
    /// the behaviour under test lives.
    #[test]
    fn install_copies_a_verified_file() {
        let package = std::env::temp_dir().join(format!("wenle-lua-{}", std::process::id()));
        let install = package.join("install");
        std::fs::create_dir_all(&install).expect("temp dirs");
        let payload = package.join("wenle.exe");
        std::fs::write(&payload, b"pretend this is a program").expect("write");
        let digest = hash_file(&payload).expect("hash");
        let entries = vec![Entry {
            sha256: digest,
            name: "wenle.exe".to_string(),
        }];

        let script = r#"
            local names = update.names()
            assert(#names == 1, "one name")
            update.install(names[1])
        "#;
        let report = run(&package, &install, &entries, script).expect("runs");
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.installed, vec!["wenle.exe".to_string()]);
        assert!(install.join("wenle.exe").exists());

        let _ = std::fs::remove_dir_all(&package);
    }

    #[test]
    fn a_name_outside_the_manifest_is_refused() {
        let package = std::env::temp_dir().join(format!("wenle-lua-deny-{}", std::process::id()));
        let install = package.join("install");
        std::fs::create_dir_all(&install).expect("temp dirs");
        std::fs::write(package.join("wenle.exe"), b"x").expect("write");
        let entries = vec![Entry {
            sha256: hash_file(&package.join("wenle.exe")).expect("hash"),
            name: "wenle.exe".to_string(),
        }];
        let report = run(&package, &install, &entries, "update.install('evil.exe')");
        let report = report.expect("the error is reported, not returned");
        assert!(!report.is_clean(), "{report:?}");
        assert!(report.installed.is_empty());
        let _ = std::fs::remove_dir_all(&package);
    }

    #[test]
    fn the_sandbox_has_no_io_library() {
        let package = std::env::temp_dir().join(format!("wenle-lua-sb-{}", std::process::id()));
        std::fs::create_dir_all(&package).expect("temp dirs");
        let report = run(&package, &package, &[], "io.open('C:/Windows/System32/drivers/x.sys','w')")
            .expect("runs");
        assert!(!report.is_clean(), "a script could open a file: {report:?}");
        assert!(
            report.failures.iter().any(|failure| failure.contains("io")),
            "{report:?}"
        );
        let _ = std::fs::remove_dir_all(&package);
    }

    #[test]
    fn the_default_script_names_the_files_it_installs() {
        assert!(DEFAULT_SCRIPT.contains("update.install"));
        assert!(DEFAULT_SCRIPT.contains("update.stop_service"));
        assert!(DEFAULT_SCRIPT.contains("update.start_service"));
    }
}
