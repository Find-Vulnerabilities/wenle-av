//! The configuration file, and what this build does not do with it.
//!
//! # The file
//!
//! `%ProgramData%\WenleAV\config.toml`, which is
//! [`av_core::paths::AvPaths::config_file`] rather than a path spelled again
//! here. The document type is [`AvConfig`], the parser is `toml` through
//! `serde`, and an absent file is not an error: a service that refused to start
//! because nobody had written a configuration yet would leave a fresh
//! installation unprotected.
//!
//! # The list that matters
//!
//! [`AvConfig`] describes the whole product, and this service is one half of
//! it. Some of its keys are honoured here, some are honoured by the graphical
//! front end, some need the kernel driver, and some are not honoured by
//! anything in this workspace yet. The failure this module exists to prevent is
//! a user editing `config.toml`, seeing no error, and believing a protection is
//! on when nothing reads the key at all.
//!
//! So [`report`] returns both lists, and
//! [`av_ipc::ConfigReport`] carries them:
//!
//! * **unhonoured** — stored, and not acted on by anything. `driver.fail_closed`
//!   is the sharpest example: it reads as a safety setting and is a no-op.
//! * **handled elsewhere** — read and acted on, but by something other than
//!   this service, with a sentence saying what.
//!
//! A key in neither list and not in [`needs_restart`] is honoured, which is the
//! ordinary case and the one that has to stay the majority. `quarantine.
//! auto_quarantine` is the example worth naming, because it is the one that
//! moved: the service reads it, and when it is on a confirmed detection is
//! taken into the vault by [`crate::host`] rather than only reported. It was in
//! the second list until that was true, and it left the list in the same change
//! that made it true — a disclosure list is only worth reading while it is
//! exact.
//!
//! `general.exclusions` is the other one that moved, and it moved out of
//! [`needs_restart`]: the service's decision path consults the exclusions on
//! every decision and `Host::apply_live` re-seeds them when the
//! setting is edited, so a `ConfigSet` that adds or removes one is in force
//! before the reply is written. Leaving it in the restart list would tell a user
//! that a restart is required when it is not, which is the same lie in the
//! opposite direction.
//!
//! The shape follows `av_realtime::plan::WatchPlan::unhonoured`, which is the
//! same idea one layer down.
//!
//! # Why `deny_unknown_fields` changes the answer for typos
//!
//! `AvConfig` is `#[serde(default, deny_unknown_fields)]`, so a misspelled key
//! is a hard parse failure rather than a key this build could list as
//! unrecognised. That is the better behaviour — a typo is caught instead of
//! stored — but it means an unknown key never reaches [`report`]; it
//! arrives as [`av_ipc::ConfigReport::load_error`], and the configuration in
//! force is then the defaults rather than what the user wrote.

use std::path::Path;

use av_core::config::AvConfig;
use av_core::paths::AvPaths;
use av_ipc::{ConfigReport, SettingDisclosure};

use crate::error::ServiceError;

/// The configuration in force, and what is worth saying about it.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The document. Defaults, when there is no file or it would not parse.
    pub config: AvConfig,
    /// Set when the file exists and could not be used.
    pub load_error: Option<String>,
    /// Where it was read from.
    pub path: std::path::PathBuf,
}

/// Read `config.toml`, falling back to defaults and saying so.
///
/// Never returns an error. A configuration file that cannot be read is a fact
/// to report, not a reason to leave the machine unprotected; see this module's
/// documentation.
pub fn load(paths: &AvPaths) -> LoadedConfig {
    let path = paths.config_file.clone();
    match AvConfig::load_or_default(&path) {
        Ok(config) => LoadedConfig {
            config,
            load_error: None,
            path,
        },
        Err(error) => LoadedConfig {
            config: AvConfig::default(),
            load_error: Some(error.to_string()),
            path,
        },
    }
}

/// Write `config` to the file, creating the directory if it is not there.
pub fn save(path: &Path, config: &AvConfig) -> Result<(), ServiceError> {
    config.save(path).map_err(|error| ServiceError::Config {
        path: path.to_path_buf(),
        message: error.to_string(),
    })
}

/// Build the report a client gets from `ConfigGet` and `ConfigSet`.
///
/// [`needs_restart`] is folded into `unhonoured` here rather than given a field
/// of its own, because the wire type in `av-ipc` has two lists and the caller's
/// question is the same for both: *is what I wrote what is running?* A third
/// list would be a third thing for a front end to remember to render, and the
/// list a front end forgets is the list that becomes a lie. The reason string
/// is where the distinction lives, and it says "restart" when a restart is what
/// fixes it.
pub fn report(loaded: &LoadedConfig) -> ConfigReport {
    let mut stored = unhonoured();
    stored.extend(needs_restart());
    ConfigReport {
        config: Box::new(loaded.config.clone()),
        load_error: loaded.load_error.clone(),
        unhonoured: stored,
        handled_elsewhere: handled_elsewhere(),
    }
}

/// Whether `setting` is one this build reads when it starts and only then.
///
/// # Why a caller needs this when [`report`] has already answered
///
/// Because [`report`] answers the question a *client* has — *is what I just
/// wrote what is running?* — and the service's own start-up asks the opposite
/// one: it is reading the file that holds these keys, and `Host::open` is the
/// next call. A key that takes effect at the next service start is not a key
/// nothing acts on at the moment the service starts; it is a key that is being
/// acted on, which is why `announce` prints these at `debug` and reserves the
/// warning for the keys nothing in the workspace reads at all.
///
/// Measured 2026-10-10: every start-up printed eleven of these as
/// "is stored and not acted on", under a warning, immediately before the scan
/// engine was built from exactly those values.
pub fn waits_for_a_restart(setting: &str) -> bool {
    needs_restart()
        .iter()
        .any(|entry| entry.setting.as_str() == setting)
}

/// [`report`]'s `unhonoured` list, split back into the two facts it folds.
///
/// Returns the keys nothing in this workspace reads, and then the keys this
/// build reads at start-up. The order is the order `announce` prints them in,
/// which is the reason it is a tuple rather than a struct: there are two, they
/// are used once, and a named type would be a third place to look.
pub fn start_up(report: &ConfigReport) -> (Vec<&SettingDisclosure>, Vec<&SettingDisclosure>) {
    report
        .unhonoured
        .iter()
        .partition(|entry| !waits_for_a_restart(&entry.setting))
}

/// Settings this build stores and does not act on.
///
/// Every entry is a key that exists in [`AvConfig`] and that nothing in this
/// workspace reads to change a behaviour. One list, built from no argument, so
/// that it cannot accidentally become a function of the configuration — a
/// disclosure that appeared only for some values of a setting would be a
/// disclosure a user could switch off.
pub fn unhonoured() -> Vec<SettingDisclosure> {
    let raw: &[(&str, &str)] = &[
        (
            "driver.enabled",
            "the service connects to the driver's decision port whenever the driver offers one, \
             and nothing reads this switch to decide whether it should",
        ),
        (
            "driver.fail_closed",
            "a decision the service cannot complete is answered with allow — the same answer the \
             driver's own timeout gives — and this switch changes neither",
        ),
        (
            "driver.scan_timeout_ms",
            "the wait belongs to the driver's decision protocol and its own five-second default, \
             and the service's per-file budget is fixed; this number reaches neither",
        ),
        (
            "driver.verbose_logging",
            "the service logs the decisions it makes at its own levels; this switch is not read",
        ),
        (
            "protection.protect_persistence",
            "watching the registry needs a registry callback in the driver, and this driver \
             registers none: it filters the file system and reports process starts, and no part of \
             it looks at `Run`, `RunOnce`, services, IFEO, Winlogon or AppInit",
        ),
        (
            "protection.persistence_alert_only",
            "nothing is watching persistence points, so there is nothing to alert on",
        ),
        (
            "protection.protect_boot",
            "nothing in this build reads or refuses writes to the boot sector or the EFI system \
             partition — not the driver, which filters no volume at that level, and not this \
             service",
        ),
        (
            "protection.protect_hosts_file",
            "the hosts file is not treated specially by anything in this build: it is scanned as \
             an ordinary file when a scan reaches it and refused nothing",
        ),
        // Moved here from `handled_elsewhere` on 2026-10-09, when the `ui.*`
        // entries there were checked against what the window actually reads.
        // Four of them were read by nothing: the window drew one theme, one row
        // height, and no confirmation at all, and the list said otherwise — so a
        // user's next move was to set one and watch it do nothing.
        (
            "ui.theme",
            "the window draws one palette and picks it itself. There is no light variant of it — \
             the colours, their contrast ratios and the tests that measure them are all the dark \
             set — so this key cannot select one, and a window that read it would show the same \
             theme for all three values",
        ),
        (
            "ui.dense_tables",
            "the threat table draws one row height, measured from the font; nothing reads this \
             key. See `av-gui`'s `RowMetrics`, which is where the row is built",
        ),
        (
            "ui.confirm_destructive",
            "the window quarantines on the click and draws no confirmation step, so there is \
             nothing for this key to turn on or off",
        ),
        (
            "ui.prevent_sleep_during_scan",
            "nothing in this build calls `SetThreadExecutionState`, so a long scan does not keep \
             the machine awake and this key does not make it",
        ),
        (
            "sandbox.enabled",
            "the sandbox is a separate component and this service does not drive it",
        ),
        (
            "sandbox.auto_on_suspicious",
            "nothing suspends a scan for a sandbox run",
        ),
        (
            "sandbox.timeout_secs",
            "no sandbox run is started",
        ),
        (
            "sandbox.max_memory_bytes",
            "no sandbox run is started",
        ),
        (
            "sandbox.max_processes",
            "no sandbox run is started",
        ),
        (
            "sandbox.block_network",
            "no sandbox run is started",
        ),
        (
            "sandbox.capture_filesystem",
            "no sandbox run is started",
        ),
        (
            "sandbox.capture_registry",
            "no sandbox run is started",
        ),
        (
            "scanning.memory",
            "this setting only reaches a file scan, and a process's memory is not part of one: \
             memory is examined when a client asks for it with a process-scan request, which is \
             not a setting any configuration file can turn on",
        ),
        (
            "scanning.scan_cache_entries",
            "there is no scan cache in this build; every file is examined afresh",
        ),
        (
            "scanning.scan_cache_ttl_secs",
            "there is no scan cache in this build",
        ),
        (
            "scanning.hash_cache_entries",
            "there is no hash cache in this build",
        ),
        (
            "scanning.max_rules_per_file",
            "the engine's own rule-candidate prefilter decides this, not a per-file cap",
        ),
        (
            "scanning.threads",
            "this service scans with one worker; parallel scanning is the command-line scanner's",
        ),
        (
            "realtime.scan_on_execute",
            "a filesystem event does not say whether a file is about to be executed",
        ),
        (
            "realtime.worker_threads",
            "the watcher runs one scanner thread; the engine's own scan is single-threaded here",
        ),
        (
            "quarantine.backup_before_quarantine",
            "the vault has one destination per item, not a copy beside the original",
        ),
        (
            "general.excluded_processes",
            "nothing here identifies a *process*; a file-scoped rule is general.exclusions",
        ),
        (
            "general.excluded_extensions",
            "the realtime watcher's exclusion set is path-based; extensions are not filtered",
        ),
        // The whole `logging.*` group, rewritten on 2026-10-10. Every one of
        // these reasons was false, and the group is worth a comment because
        // *how* they were false is the same mistake four times: the reasons
        // described a product that does not exist rather than the one that
        // does. `to_file` claimed the service writes to the Windows event log
        // — it writes a file, always, and `main.rs`'s own module doc says the
        // event log "is not taken". The two numbers claimed no log of this
        // service's own is rotated — one is, at a size fixed in the program.
        // `logging.level` was the fourth and the worst: it sat in
        // `needs_restart` promising that a restart would make it work, while
        // nothing in the workspace read the key at all. It left this list on
        // 2026-10-18, when `main.rs`'s `logging::set_level` began applying it
        // at start-up; it is now in `needs_restart`, which is the truth for a
        // level read once when the log opens.
        (
            "logging.to_file",
            "this key is not read: the service opens its log file at startup whether this is \
             true or false, and nothing in the configuration turns that file off",
        ),
        (
            "logging.max_file_size_bytes",
            "this number reaches nothing: the log is rolled over at a size fixed in the service \
             (4 MiB), not at the size set here",
        ),
        (
            "logging.max_files",
            "this number reaches nothing: exactly one previous log (service.log.old) is kept, \
             however many are asked for here",
        ),
        (
            "logging.history_days",
            "this key is not read: the service keeps no log history of its own, and how long a \
             finished quarantine record is kept is set by `wenle quarantine maintain \
             --compact-after`",
        ),
    ];
    raw.iter()
        .map(|(setting, reason)| SettingDisclosure::new(*setting, *reason))
        .collect()
}

/// Settings this service stores, and that something else acts on.
///
/// A separate list from [`unhonoured`], and the distinction is worth the second
/// list: "we do not do this" and "we do this, over there" are different
/// answers, and merging them teaches a user that the unhonoured list is noise.
pub fn handled_elsewhere() -> Vec<SettingDisclosure> {
    let raw: &[(&str, &str)] = &[
        (
            "realtime.block_on_detect",
            "nothing is refused before it is written, because refusing a write needs the \
             driver; this service takes a detected file into the vault *after* the scan that \
             found it, and the notification says so by carrying the phase it acted in",
        ),
        (
            "general.start_with_windows",
            "the service's own start type is an installation decision, not a setting the running \
             service can apply to itself",
        ),
        (
            "general.minimize_to_tray",
            "read by the graphical front end",
        ),
        (
            "general.notifications",
            "read by whichever front end draws the notification; the service emits the event \
             either way",
        ),
        (
            "general.notification_sound",
            "read by the graphical front end",
        ),
        // The two `ui.*` keys a front end really does read, checked against the
        // code rather than against the intent on 2026-10-09: `av-gui`'s
        // `main` passes `GuiApp::window_size` — which is these two through
        // `app::window_size`'s clamp — to `ViewportBuilder::with_inner_size`.
        // The other four `ui.*` keys moved to `unhonoured` the same day,
        // because nothing read them.
        (
            "ui.window_width",
            "the size the window opens at, read by the graphical front end; a window resized by \
             hand keeps its new size for that run and this file is not written back",
        ),
        (
            "ui.window_height",
            "the size the window opens at, read by the graphical front end; a window resized by \
             hand keeps its new size for that run and this file is not written back",
        ),
    ];
    raw.iter()
        .map(|(setting, reason)| SettingDisclosure::new(*setting, *reason))
        .collect()
}

/// Settings that are applied when the service starts and not when they change.
///
/// The third answer, and the one that would otherwise be a lie: a user who
/// raises a threshold and is told nothing has "saved" a setting this process
/// will not use until it restarts. Reported in the same list as
/// [`unhonoured`] because from the caller's point of view the answer is the
/// same — what you asked for is not what is running — with the reason spelling
/// out that a restart fixes it.
pub fn needs_restart() -> Vec<SettingDisclosure> {
    let raw: &[(&str, &str)] = &[
        (
            "scanning.thresholds",
            "the scan engine is built once at startup; restart the service for this to take \
             effect",
        ),
        (
            "scanning.recursive",
            "the scan engine is built once at startup; restart the service for this to take \
             effect",
        ),
        (
            "scanning.follow_links",
            "takes effect at the next service start",
        ),
        (
            "scanning.max_file_size",
            "takes effect at the next service start",
        ),
        (
            "scanning.archive_depth",
            "takes effect at the next service start",
        ),
        (
            "scanning.archive_max_expansion",
            "takes effect at the next service start",
        ),
        (
            "scanning.heuristics",
            "takes effect at the next service start",
        ),
        ("scanning.trust", "takes effect at the next service start"),
        (
            "logging.level",
            "the level is applied when the service reads the configuration at start-up, so a \
             change waits for a restart. `info` (the default) hides the `debug` lines -- the \
             control loop's per-request line and the `process <pid> started` line -- and the \
             high-volume driver telemetry (every write, rename, delete and registry change) is \
             `trace`, so a behaviour-test pass needs `trace`",
        ),
        (
            "scanning.archives",
            "takes effect at the next service start",
        ),
        (
            "scanning.stop_on_first",
            "takes effect at the next service start",
        ),
        (
            "scanning.per_file_timeout_secs",
            "takes effect at the next service start",
        ),
        (
            "realtime.watched_paths",
            "the watcher is built from the configuration when it starts; toggle realtime off and \
             on again, or restart the service",
        ),
        (
            "realtime.extra_watched_paths",
            "the watcher is built from the configuration when it starts; toggle realtime off and \
             on again, or restart the service",
        ),
        // The four self-protection switches, which until 2026-10-09 were listed
        // as unhonoured and are now read by `Host::driver_configuration`. They
        // are here rather than off the lists entirely because of *when* they are
        // read: the service turns them into one configuration message each time
        // it connects to the driver's port, and a connection is not re-made when
        // a setting changes. So a user who turns `protection.self_protection` off
        // and is told nothing goes on being protected until the service restarts,
        // which is the fact this list exists to state.
        (
            "protection.enabled",
            "read as the master switch for what this service asks the driver to arm, and sent to \
             the driver when the service connects to it; takes effect at the next service start",
        ),
        (
            "protection.self_protection",
            "sent to the driver when the service connects to it, as the request to strip the \
             access rights that would let another process terminate, suspend or write into this \
             product; takes effect at the next service start",
        ),
        (
            "protection.protect_own_files",
            "sent to the driver when the service connects to it, as the request to refuse writes \
             to this product's own files without asking user mode. It covers the install \
             directory, and not the rule database the loader reads: `wenle build` writes that one \
             in place, and a gate over it would refuse the product's own rule compilation",
        ),
        (
            "driver.kernel_self_protection",
            "the driver's own half of `protection.protect_own_files`, and required as well as it: \
             sent to the driver when the service connects to it; takes effect at the next service \
             start",
        ),
        // Left `unhonoured` on 2026-10-09, when `crate::tamper` began re-reading
        // this process's access list and the product's directories and putting
        // back what it found undone. It is here rather than off the lists
        // entirely for the same reason the four above are: the checker is
        // started once, by `Host::start_tamper`, and nothing stops it when the
        // setting goes off, so a user who turns this off and is told nothing is
        // still being checked until the service restarts.
        (
            "protection.tamper_resistance",
            "the service re-reads its own access list and the product's directories every five \
             minutes and puts back anything it finds undone, and compares the product's own files \
             against the manifest at startup and every six hours; the checker is started at \
             service start, so a change takes effect at the next service start",
        ),
    ];
    raw.iter()
        .map(|(setting, reason)| SettingDisclosure::new(*setting, *reason))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_disclosure_names_a_key_and_says_what_is_missing() {
        // The property that makes the lists worth having: an entry a user
        // cannot act on is noise. Every reason is a sentence, and every setting
        // is spelled the way it appears in `config.toml` — a dotted path with
        // no spaces, so that grepping the file for it finds something.
        for list in [unhonoured(), handled_elsewhere(), needs_restart()] {
            assert!(!list.is_empty());
            for disclosure in list {
                assert!(
                    disclosure.setting.contains('.'),
                    "{} is not a dotted key",
                    disclosure.setting
                );
                assert!(
                    !disclosure.setting.contains(' '),
                    "{} has a space in it",
                    disclosure.setting
                );
                assert!(
                    disclosure.reason.len() > 20,
                    "{} has no real reason",
                    disclosure.setting
                );
            }
        }
    }

    #[test]
    fn every_disclosed_key_exists_in_the_configuration() {
        // The failure this catches: a disclosure naming `scanning.foo` after
        // `foo` was renamed. The list would still compile and would still look
        // right, and it would be telling the user about a key that no longer
        // exists while staying silent about the one that does. Serialised and
        // grepped rather than reflected over, because the field names are the
        // wire names and that is the whole point of the check.
        let text = toml::to_string_pretty(&AvConfig::default()).expect("defaults serialise");
        for list in [unhonoured(), handled_elsewhere(), needs_restart()] {
            for disclosure in list {
                let leaf = disclosure
                    .setting
                    .split('.')
                    .next_back()
                    .expect("a key has a last component");
                assert!(
                    text.contains(leaf),
                    "`{}` names `{leaf}`, which is not in the configuration document",
                    disclosure.setting
                );
            }
        }
    }

    #[test]
    fn an_honoured_key_is_not_disclosed_by_any_list() {
        // The property that keeps the lists readable: a key that this service
        // reads and acts on must not appear in a list of things it does not.
        // `quarantine.auto_quarantine` is the one that was moved, so it is the
        // one pinned — a later refactor that quietly put it back would make the
        // vault look like it was acting on its own.
        //
        // `general.exclusions` is pinned for the same reason and in the same
        // breath: it left `needs_restart` when the decision path started
        // consulting it live, and it is reported in `unhonoured` here because
        // `report` folds the restart list into that one.
        let reported = report(&load(&AvPaths::with_data_dir(
            Path::new("C:\\install"),
            Path::new("C:\\data"),
        )));
        for setting in ["quarantine.auto_quarantine", "general.exclusions"] {
            for list in [&reported.unhonoured, &reported.handled_elsewhere] {
                assert!(
                    !list
                        .iter()
                        .any(|disclosure| disclosure.setting == setting),
                    "{setting} is honoured by the host and must not be disclosed as missing"
                );
            }
        }
    }

    #[test]
    fn the_process_side_of_realtime_is_no_longer_disclosed_as_missing() {
        // Both of these left `unhonoured` on 2026-10-09, when the service began
        // walking a process the driver reported starting and, on a file that
        // convicts on its own evidence, terminating it. Pinned as a test because
        // leaving them in the list is invisible: the product would go on doing
        // the thing while telling the user it does not, which is worse than
        // either doing it or not.
        //
        // What is *not* claimed is that they work without a driver: with no
        // driver connected there are no process-creation reports, and
        // `driver.*` is where that gap is disclosed. A setting being honoured
        // and its mechanism being present are different questions, and this list
        // answers only the first.
        let reported = report(&load(&AvPaths::with_data_dir(
            Path::new("C:\\install"),
            Path::new("C:\\data"),
        )));
        for setting in [
            "realtime.scan_on_process_start",
            "realtime.terminate_malicious_process",
        ] {
            for list in [&reported.unhonoured, &reported.handled_elsewhere] {
                assert!(
                    !list
                        .iter()
                        .any(|disclosure| disclosure.setting == setting),
                    "{setting} is acted on by the host through the driver and must not be \
                     disclosed as missing"
                );
            }
        }
        // And it is not reported as waiting for a restart either: a change to it
        // reaches the running worker, which is what `Host::apply_live` is for.
        assert!(
            !needs_restart()
                .iter()
                .any(|disclosure| disclosure.setting == "realtime.terminate_malicious_process"),
            "a change to this setting takes effect live, so it does not wait for a restart"
        );
    }

    #[test]
    fn the_ui_keys_are_split_by_who_reads_them() {
        // Found false on 2026-10-09: all six `ui.*` keys were listed as "read by
        // the graphical front end", and the window read two of them. A
        // disclosure that names a reader which does not read is worse than no
        // disclosure, because the user's next move is to set the key and watch
        // it do nothing.
        //
        // This is the list, not the code — `av-gui` is a separate binary and no
        // test in this crate can see it — so what it pins is that the split is
        // deliberate and stays put. The reading half is asserted in `av-gui`:
        // `a_window_size_from_the_configuration_is_clamped_to_something_that_is_a_window`.
        let elsewhere: Vec<String> = handled_elsewhere()
            .into_iter()
            .map(|disclosure| disclosure.setting)
            .collect();
        let stored: Vec<String> = unhonoured()
            .into_iter()
            .map(|disclosure| disclosure.setting)
            .collect();

        for read in ["ui.window_width", "ui.window_height"] {
            assert!(elsewhere.iter().any(|key| key == read), "{read} is not named as read");
            assert!(
                !stored.iter().any(|key| key == read),
                "{read} is read and cannot be unhonoured"
            );
        }
        for unread in [
            "ui.theme",
            "ui.dense_tables",
            "ui.confirm_destructive",
            "ui.prevent_sleep_during_scan",
        ] {
            assert!(
                stored.iter().any(|key| key == unread),
                "{unread} is stored and nothing acts on it, so it must be disclosed as \
                 unhonoured rather than as read by a front end"
            );
        }
    }

    #[test]
    fn the_logging_keys_are_disclosed_as_unread() {
        // Found false on 2026-10-10, four of the five. `logging.to_file`
        // claimed the service logs to the Windows event log — it has always
        // written `%ProgramData%\WenleAV\logs\service.log` and `main.rs`'s own
        // module doc says the event log "is not taken". The two numbers claimed
        // no log of this service's own is rotated — `logging::rotate` renames
        // `service.log` to `service.log.old` at 4 MiB.
        //
        // `logging.level` was the fifth and it left this list on 2026-10-18:
        // `main.rs`'s `logging::set_level` reads it after the configuration is
        // loaded, so it is now in `needs_restart` — a level read once when the
        // log opens is exactly what that list means. See the assertion below.
        //
        // No test in this crate can see whether a key is read, so what this
        // pins is that the classification is deliberate. The reading half is a
        // fact about the workspace; the way to check it is to grep for the key.
        let stored: Vec<String> = unhonoured()
            .into_iter()
            .map(|disclosure| disclosure.setting)
            .collect();

        for unread in [
            "logging.to_file",
            "logging.max_file_size_bytes",
            "logging.max_files",
            "logging.history_days",
        ] {
            assert!(
                stored.iter().any(|key| key == unread),
                "{unread} is not read by anything, so it must be disclosed as unhonoured"
            );
            assert!(
                !needs_restart()
                    .iter()
                    .any(|disclosure| disclosure.setting == unread),
                "{unread} is not read even after a restart, so it cannot be disclosed as one"
            );
        }
    }

    #[test]
    fn logging_level_is_read_and_disclosed_as_waiting_for_a_restart() {
        // The key this crate previously disclosed as unhonoured while nothing
        // read it. `main.rs` reads `loaded.config.logging.level` in both the
        // service and the console path and calls `logging::set_level`; the
        // level is then fixed for the life of the process, which is what
        // `needs_restart` describes.
        //
        // The reason names `trace` because that is the level the behaviour
        // telemetry is logged at — a reason that told a user to set `debug` and
        // look for write lines would send them after output that never comes.
        assert!(
            !unhonoured()
                .iter()
                .any(|disclosure| disclosure.setting == "logging.level"),
            "the level is read at start-up, so it must not be disclosed as unhonoured"
        );
        assert!(
            needs_restart().iter().any(|disclosure| {
                disclosure.setting == "logging.level" && disclosure.reason.contains("trace")
            }),
            "a level read once at start-up waits for a restart, and the reason must name the \
             level the telemetry actually needs"
        );
    }

    #[test]
    fn tamper_resistance_is_no_longer_disclosed_as_missing() {
        // It left `unhonoured` on 2026-10-09, when `crate::tamper` began doing
        // the thing the key names. Pinned for the same reason the process-side
        // test above is: leaving it in the list is invisible, and the product
        // would go on re-applying its own protection while telling the user it
        // does not.
        //
        // Where it *is* reported is `needs_restart`, and that is the honest
        // place: the checker is started by `Host::start_tamper` at service
        // start and nothing stops it when the setting goes off. That list is
        // folded into the report's `unhonoured` — see `report` — so the
        // assertion is against the raw lists rather than against the report.
        for list in [unhonoured(), handled_elsewhere()] {
            assert!(
                !list
                    .iter()
                    .any(|disclosure| disclosure.setting == "protection.tamper_resistance"),
                "the service re-applies its own protection and must not be disclosed as missing"
            );
        }
        assert!(
            needs_restart()
                .iter()
                .any(|disclosure| disclosure.setting == "protection.tamper_resistance"),
            "a change to this setting does not reach the running checker, so it waits for a \
             restart and must be disclosed as one"
        );
    }

    #[test]
    fn the_report_carries_the_settings_that_wait_for_a_restart() {
        // Otherwise the third answer has nowhere to go on the wire, and a user
        // who raises a threshold is told nothing at all.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path(), dir.path());
        let reported = report(&load(&paths));
        for disclosure in needs_restart() {
            assert!(
                reported
                    .unhonoured
                    .iter()
                    .any(|entry| entry.setting == disclosure.setting
                        && entry.reason == disclosure.reason),
                "{} is missing from the report",
                disclosure.setting
            );
        }
        // And the reason still says what fixes it.
        assert!(reported.unhonoured.iter().any(
            |entry| entry.setting == "scanning.thresholds" && entry.reason.contains("restart")
        ));
    }

    #[test]
    fn the_start_up_split_leaves_no_restart_key_on_the_side_that_warns() {
        // The defect this exists for, measured 2026-10-10 from `service.log`:
        // `announce` printed every entry of the folded list as "is stored and not
        // acted on", so a machine's log carried eleven warnings about keys the
        // service was about to read — `Host::open` is the call after `announce` —
        // including the thresholds the scan engine is built from. A reader who
        // believed the log would conclude the engine ignored its configuration.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path(), dir.path());
        let reported = report(&load(&paths));

        let (ignored, read_here) = start_up(&reported);
        assert_eq!(
            ignored.len() + read_here.len(),
            reported.unhonoured.len(),
            "every entry of the folded list has to land on one side of the split"
        );
        assert!(
            !read_here.is_empty() && !ignored.is_empty(),
            "both sides are populated in this build, and a split that put everything on one of \
             them would pass every assertion below vacuously: {} read at start-up, {} ignored",
            read_here.len(),
            ignored.len()
        );
        for entry in &read_here {
            assert!(
                waits_for_a_restart(&entry.setting),
                "{} was put on the read-at-start-up side and does not wait for a restart",
                entry.setting
            );
        }
        for entry in &ignored {
            assert!(
                !waits_for_a_restart(&entry.setting),
                "{} is read at start-up and is about to be announced as a key nothing acts on",
                entry.setting
            );
        }
        // The side that warns is still the side that carries this list's point,
        // and the side that does not is the one the engine is built from.
        assert!(
            ignored.iter().any(|entry| entry.setting == "driver.enabled"),
            "a key nothing in this workspace reads has to stay on the warning side"
        );
        assert!(
            read_here
                .iter()
                .any(|entry| entry.setting == "scanning.thresholds"),
            "the thresholds the scan engine is built from are read at start-up"
        );
    }

    #[test]
    fn a_missing_file_is_defaults_and_no_error() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path(), dir.path());
        let loaded = load(&paths);
        assert!(loaded.load_error.is_none());
        assert_eq!(loaded.config, AvConfig::default());
        // And the report says the same thing, with the lists attached.
        let report = report(&loaded);
        assert!(report.load_error.is_none());
        assert!(!report.unhonoured.is_empty());
        assert!(!report.handled_elsewhere.is_empty());
        assert!(!report.is_wholly_honoured());
    }

    #[test]
    fn a_file_that_will_not_parse_is_reported_rather_than_ignored() {
        // `deny_unknown_fields`, so this is a typo — the case the user most
        // needs told about, because everything else in the file is now also not
        // in force.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path(), dir.path());
        std::fs::write(&paths.config_file, "[scanning]\nrecursiv = true\n").expect("writes");
        let loaded = load(&paths);
        let error = loaded.load_error.expect("the typo is reported");
        assert!(error.contains("recursiv"), "unexpected message: {error}");
        // And the configuration in force is the defaults, because the file
        // could not be used at all.
        assert_eq!(loaded.config, AvConfig::default());
    }

    #[test]
    fn a_file_round_trips_through_save_and_load() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path(), dir.path());
        let mut config = AvConfig::default();
        config.realtime.enabled = false;
        config.scanning.thresholds.malicious = 150;
        save(&paths.config_file, &config).expect("saves");
        let loaded = load(&paths);
        assert!(loaded.load_error.is_none());
        assert_eq!(loaded.config, config);
    }
}
