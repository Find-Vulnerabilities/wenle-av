//! The scan engine, and the rule database it was built from.
//!
//! # A service with no rules has to say so
//!
//! [`av_ipc::StatusReport::database`] is an `Option`, and this module is why it
//! has to be. An installation whose rule database is missing, unreadable or
//! written by a different format version is an installation that can detect
//! nothing, and reporting that as "no detections" is reporting a broken product
//! as a clean machine. So [`load`] never fails: it returns an engine
//! with an empty database *and* the reason, and every status reply carries both.
//!
//! That is the same decision [`crate::config`] makes about `config.toml`, for
//! the same reason, and the two are the only places in this crate where a
//! failure is turned into a report rather than propagated. A service that
//! refused to start because its rules were not built yet would be a service
//! that leaves the machine with no watcher either.
//!
//! # Where the database is
//!
//! The same search order `av-cli` uses, and spelled again here rather than
//! shared: `wenle db` writes to `db_dir`, and a developer running the service
//! out of `target/debug` wants the database beside the binary they just built.
//! `av-cli` owns its own copy of this constant — a service that reached into
//! the command-line tool for a filename would be a service that cannot be built
//! without it.
//!
//! # The catalog index
//!
//! Built once, at startup, and handed to the engine as an `Arc`. It is the
//! digest set of every catalog on the machine — `av-signatures` measures the
//! build at 1.2 s and 1.2 GB of reads — so it is built once per service rather
//! than once per scan, which is the whole reason
//! [`av_signatures::catalog::CatalogIndex`] takes a caller rather than building
//! itself implicitly. A machine with no catalog store, or a store that cannot
//! be read, gets an empty index: the trust layer then has one fewer signal and
//! says so, rather than failing a scan that would otherwise be fine.
//!
//! # Read through the cache, which is what the CLI and the console already do
//!
//! Measured in the VM on 2026-10-10: `Start-Service WenleAvService` took about
//! twenty-one seconds to report Running. A service that takes that long is a
//! service the SCM's own start-up timeout is entitled to kill, and most of it
//! was here. This module called [`CatalogIndex::from_store`], the *uncached*
//! builder, while `av-cli` and `av-gui` both called
//! [`CatalogIndex::from_store_cached`] — the function whose own documentation
//! says it "is what a scan should call". The service is the one caller that
//! never got to be a second run: every boot paid the full DER parse of 1.2 GB.
//! `av-signatures` measures the two paths at 1.65 s to 6.24 s and 60 ms over the
//! same store, so this is not a tuning question but a wrong-constructor one.
//!
//! The line below is logged for the same reason `av-cli` logs it: the number is
//! the only way a person reading the service log can tell which of the two
//! happened, and without it the next start-up is exactly as unexplained as this
//! one was.
//!
//! [`CatalogIndex::from_store`]: av_signatures::catalog::CatalogIndex::from_store
//! [`CatalogIndex::from_store_cached`]: av_signatures::catalog::CatalogIndex::from_store_cached

use std::path::{Path, PathBuf};
use std::sync::Arc;

use av_core::config::ScanningConfig;
use av_core::paths::AvPaths;
use av_core::scan::ScanOptions;
use av_ipc::DatabaseStatus;
use av_rules::database::{RuleDatabase, FORMAT_VERSION};
use av_scan::engine::ScanEngine;
use av_scan::{HeuristicConfig, TrustPolicy};

/// The name of the compiled rule database inside the data directory.
///
/// `av-cli`'s `commands::DATABASE_FILE`, spelled again rather than imported —
/// see this module's documentation.
pub const DATABASE_FILE: &str = "rules.avdb";

/// The engine, and what is worth saying about where it came from.
#[derive(Debug)]
pub struct Engine {
    /// The engine, shared because it holds the compiled rule set and is
    /// read-only: a copy per scan thread would be a copy of every rule.
    pub engine: Arc<ScanEngine>,
    /// The database that loaded, or `None` when none did.
    pub database: Option<DatabaseStatus>,
    /// Why there is no database, when there is none.
    pub load_error: Option<String>,
    /// What the catalog index covered, when one was built.
    pub catalog: CatalogStatus,
}

/// What the catalog store contributed.
///
/// Three numbers rather than a boolean, because the interesting failures are
/// partial: a store with 7,300 catalogs of which twenty were refused is not an
/// empty store, and a report that said "no catalogs" about it would be wrong in
/// a way that matters when a signed system file is scored as untrusted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CatalogStatus {
    /// How many catalogs were read.
    pub read: usize,
    /// How many files in the store were refused as not a catalog.
    pub refused: usize,
    /// How many were larger than the crate's ceiling and skipped.
    pub oversized: usize,
}

impl CatalogStatus {
    /// True when nothing at all was read.
    pub const fn is_empty(&self) -> bool {
        self.read == 0
    }

    /// One sentence, for a status report or a log line.
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "no catalog store was found, so trust has no catalog evidence".to_string();
        }
        let mut text = format!("{} catalogs indexed", self.read);
        if self.refused > 0 {
            text.push_str(&format!(
                ", {} refused as unreadable or malformed",
                self.refused
            ));
        }
        if self.oversized > 0 {
            text.push_str(&format!(", {} too large to read", self.oversized));
        }
        text
    }
}

/// Where the compiled rule database is, if it is anywhere.
///
/// `db_dir` first, then the installation directory. The second is what makes a
/// developer's build usable: `target/debug/wenle-av-service.exe` beside a
/// `rules.avdb` uses that one, and nothing about which was used is visible in a
/// scan report unless it is reported — which is what [`DatabaseStatus::path`]
/// carries.
pub fn database_path(paths: &AvPaths) -> Option<PathBuf> {
    [
        paths.db_dir.join(DATABASE_FILE),
        paths.install_dir.join(DATABASE_FILE),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

/// Build the engine, catalog store and all.
pub fn load(paths: &AvPaths, scanning: &ScanningConfig) -> Engine {
    let (catalog, catalog_status) = build_catalog(&paths.cache_dir);
    load_with(paths, scanning, catalog, catalog_status)
}

/// Build the engine with an already-decided catalog.
///
/// Separated from [`load`] so that a test does not have to read this machine's
/// catalog store — 1.2 s and 1.2 GB of reads — to assert what happens when a
/// rule database is missing. The catalog is one more input to the engine, and
/// an input a caller can supply is an input a test can control.
pub fn load_with(
    paths: &AvPaths,
    scanning: &ScanningConfig,
    catalog: Option<Arc<av_signatures::catalog::CatalogIndex>>,
    catalog_status: CatalogStatus,
) -> Engine {
    let (database, status, load_error) = match database_path(paths) {
        Some(path) => match RuleDatabase::load(&path) {
            Ok(database) => {
                let status = DatabaseStatus {
                    path: path.clone(),
                    rules: database.len(),
                    format_version: FORMAT_VERSION,
                    bytes: std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0),
                };
                (database, Some(status), None)
            }
            Err(error) => (
                empty_database(),
                None,
                Some(format!("{}: {error}", path.display())),
            ),
        },
        None => (
            empty_database(),
            None,
            Some(format!(
                "no rule database was found in {}; run `wenle build` to make one",
                paths.db_dir.display()
            )),
        ),
    };
    Engine {
        engine: Arc::new(build(database, scanning, catalog)),
        database: status,
        load_error,
        catalog: catalog_status,
    }
}

/// A database with no rules in it.
///
/// `RuleDatabase::compile` on an empty source, which is the only constructor
/// this crate may use: the fields of a `RuleDatabase` are private, and a
/// database assembled by hand would not have the prefilters and automata the
/// engine's own compilation builds. An empty source produces those structures
/// over nothing, which is exactly the "no rules" state and not a special case.
fn empty_database() -> RuleDatabase {
    RuleDatabase::compile("").0
}

/// Assemble the engine from a database and the configuration.
///
/// Every setting here is applied at construction and not afterwards, which is
/// what [`crate::config::needs_restart`] tells a user about the ones they can
/// change: the engine is built once, and rebuilding it would stall every scan
/// in flight to change a number.
fn build(
    database: RuleDatabase,
    scanning: &ScanningConfig,
    catalog: Option<Arc<av_signatures::catalog::CatalogIndex>>,
) -> ScanEngine {
    ScanEngine::new(database)
        .with_thresholds(scanning.thresholds)
        .with_heuristics(HeuristicConfig {
            enabled: scanning.heuristics,
            ..HeuristicConfig::default()
        })
        .with_trust(TrustPolicy {
            enabled: scanning.trust,
            ..TrustPolicy::default()
        })
        .with_catalog(catalog)
}

/// Build the catalog index, or the empty one with its counters.
///
/// The index itself is returned rather than only its counters: the counters
/// describe the store, and the index is what the engine consults. A store that
/// could not be read at all produces counters of zero and no index, which is
/// indistinguishable from an empty store and reported as such — by the
/// sentence in [`CatalogStatus::describe`], which says the store was not found.
///
/// Public because a caller that wants an engine *without* this store's 1.2 GB
/// of reads has to be able to say so, and [`load_with`] is where it says it.
/// Every test that builds a service would otherwise read this machine's
/// catalogs, which makes the suite slow, memory-hungry and dependent on what
/// happens to be installed.
///
/// # Why the cache directory is a parameter
///
/// [`CatalogIndex::from_directory_cached`] writes the parsed index into the
/// product's own `cache_dir` and reads it back next time, which makes this
/// function's cost a property of the directory rather than of the store. See
/// the module documentation for the measurement that made this the cached
/// constructor. `cache_dir` is [`AvPaths::cache_dir`] at every call site in the
/// product; it is a parameter because [`catalog_from`] takes it, and that
/// function exists so a test can build an index over a store it wrote itself
/// rather than over the one installed on whatever machine runs the suite.
///
/// [`CatalogIndex::from_directory_cached`]: av_signatures::catalog::CatalogIndex::from_directory_cached
pub fn build_catalog(
    cache_dir: &Path,
) -> (
    Option<Arc<av_signatures::catalog::CatalogIndex>>,
    CatalogStatus,
) {
    catalog_from(av_signatures::catalog::store_directory().as_deref(), cache_dir)
}

/// [`build_catalog`] against a store directory the caller names, and the one
/// place in this crate that chooses between the cached and the uncached
/// constructor.
///
/// Private, with the tests below as its only other caller, for the reason the
/// machine makes unavoidable: `store_directory()` is `CatRoot` on whatever
/// machine runs `cargo test`, and an index over it costs about a minute here
/// (measured 2026-10-10 while adding the test that used to do exactly that).
/// A store a test writes for itself is a fixture; the store in `CatRoot` is a
/// fact about somebody's laptop, and a suite that asserts it is a suite that
/// fails on a machine with different catalogs installed.
///
/// The seam is narrow on purpose. It is the whole of the choice this module
/// makes between the two constructors, so a test that reaches it can fail when
/// the choice is reversed, and there is nothing else here for it to miss.
fn catalog_from(
    store: Option<&Path>,
    cache_dir: &Path,
) -> (
    Option<Arc<av_signatures::catalog::CatalogIndex>>,
    CatalogStatus,
) {
    let Some(store) = store else {
        return (None, CatalogStatus::default());
    };
    let started = std::time::Instant::now();
    match av_signatures::catalog::CatalogIndex::from_directory_cached(
        store,
        &av_signatures::catalog::cache_path(cache_dir),
    ) {
        Ok(index) => {
            let status = CatalogStatus {
                read: index.catalogs_read(),
                refused: index.catalogs_refused(),
                oversized: index.catalogs_oversized(),
            };
            // The same sentence `av-cli` prints, for the same reason: `, from
            // cache` against `, rebuilt` is how a reader tells a 60 ms start-up
            // from a 6 s one without a stopwatch.
            log::info!(
                "catalog store: {} catalogs read ({} refused, {} oversized), {} digests, {:?}{}",
                status.read,
                status.refused,
                status.oversized,
                index.digest_count(),
                started.elapsed(),
                if index.cache_hit() {
                    ", from cache"
                } else {
                    ", rebuilt"
                },
            );
            (Some(Arc::new(index)), status)
        }
        Err(_) => (None, CatalogStatus::default()),
    }
}

/// The scan options a client's request and the configuration together imply.
///
/// The client's `ScanOptions` wins outright when it sends one, because a caller
/// who has named one file has said more about what it wants than any setting
/// has. This function is for the case where the service supplies the options
/// itself, and it is the only place a `ScanningConfig` becomes a `ScanOptions`
/// — a second derivation would be a second answer.
pub fn options_from(scanning: &ScanningConfig) -> ScanOptions {
    ScanOptions {
        recursive: scanning.recursive,
        follow_links: scanning.follow_links,
        max_file_size: scanning.max_file_size,
        archive_depth: scanning.archive_depth,
        archive_max_expansion: scanning.archive_max_expansion,
        heuristics: scanning.heuristics,
        // Memory scanning needs the driver's process callbacks, which this
        // build does not connect. Forced off here rather than left to the
        // setting, so that the engine is never asked to do something no part of
        // this process can do — see `crate::config::unhonoured`.
        memory: false,
        trust: scanning.trust,
        archives: scanning.archives,
        stop_on_first: scanning.stop_on_first,
        per_file_timeout: scanning
            .per_file_timeout_secs
            .map(std::time::Duration::from_secs),
    }
}

/// True when `path` is inside the product's own tree.
///
/// A scan of the data directory would find the vault, whose contents are by
/// definition the files this product already decided were malicious, and report
/// them as new detections. Forwarded from [`AvPaths::is_protected`] so that a
/// caller holding only a path and the paths value does not have to remember
/// which way round the check goes.
pub fn is_own_tree(paths: &AvPaths, path: &Path) -> bool {
    paths.is_protected(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanning() -> ScanningConfig {
        ScanningConfig::default()
    }

    #[test]
    fn options_come_from_the_configuration_and_memory_is_always_off() {
        let mut config = scanning();
        config.recursive = false;
        config.follow_links = true;
        config.archive_depth = 0;
        config.stop_on_first = true;
        config.heuristics = false;
        config.trust = false;
        config.archives = false;
        config.per_file_timeout_secs = None;
        // Asked for and refused: this is the option a *file* scan carries, and a
        // file scan has no process to read. Memory is examined when a client
        // asks for a process scan — `Request::ScanProcess`, which the host
        // answers through `av-memory` — so an engine told to try here would
        // either do nothing or fail per file.
        config.memory = true;

        let options = options_from(&config);
        assert!(!options.recursive);
        assert!(options.follow_links);
        assert_eq!(options.archive_depth, 0);
        assert!(options.stop_on_first);
        assert!(!options.heuristics);
        assert!(!options.trust);
        assert!(!options.archives);
        assert!(options.per_file_timeout.is_none());
        assert!(
            !options.memory,
            "a file scan has no process to read; a process scan is its own request"
        );
    }

    #[test]
    fn the_defaults_are_the_configurations_defaults() {
        // The two defaults agreeing is a fact worth pinning: `ScanOptions` has
        // its own `Default`, and a service that used it instead of the
        // configuration would ignore every scanning setting in the file.
        let options = options_from(&scanning());
        let defaults = ScanOptions::default();
        assert_eq!(options.recursive, defaults.recursive);
        assert_eq!(options.follow_links, defaults.follow_links);
        assert_eq!(options.max_file_size, defaults.max_file_size);
        assert_eq!(options.archive_depth, defaults.archive_depth);
        assert_eq!(options.heuristics, defaults.heuristics);
        assert_eq!(options.trust, defaults.trust);
        assert_eq!(options.archives, defaults.archives);
        assert_eq!(options.stop_on_first, defaults.stop_on_first);
        // And the one deliberate difference.
        assert!(!defaults.memory);
    }

    #[test]
    fn a_missing_database_is_an_engine_that_says_so() {
        // The failure this prevents: a service that starts, scans, finds
        // nothing and reports a clean machine — when what it actually has is no
        // ability to detect anything.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path(), dir.path());
        let engine = load_with(&paths, &scanning(), None, CatalogStatus::default());
        assert!(engine.database.is_none());
        let reason = engine.load_error.expect("the absence is reported");
        // The message names the directory that was searched and the command
        // that fills it: a user reading it has to be able to act on it, and
        // "no rules" alone says nothing about where to put them.
        assert!(
            reason.contains(&paths.db_dir.display().to_string()),
            "unexpected message: {reason}"
        );
        assert!(
            reason.contains("wenle build"),
            "unexpected message: {reason}"
        );
        // And the engine is usable rather than absent: a scan runs and finds
        // nothing, which is different from a scan that cannot run.
        assert_eq!(engine.engine.database().len(), 0);
    }

    #[test]
    fn a_database_beside_the_binary_is_found_after_the_data_directory() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let install = dir.path().join("install");
        let data = dir.path().join("data");
        std::fs::create_dir_all(&install).expect("creates");
        std::fs::create_dir_all(&data).expect("creates");
        let paths = AvPaths::with_data_dir(&install, &data);

        assert!(database_path(&paths).is_none());

        // Only beside the binary.
        std::fs::write(install.join(DATABASE_FILE), b"not a database").expect("writes");
        assert_eq!(database_path(&paths), Some(install.join(DATABASE_FILE)));

        // And now also under the data root, which wins: a database the product
        // installed for itself is the one it should be running, whatever is
        // lying beside the executable.
        std::fs::create_dir_all(&paths.db_dir).expect("creates");
        std::fs::write(paths.db_dir.join(DATABASE_FILE), b"not a database").expect("writes");
        assert_eq!(
            database_path(&paths),
            Some(paths.db_dir.join(DATABASE_FILE))
        );
        assert_ne!(
            database_path(&paths),
            Some(install.join(DATABASE_FILE)),
            "the data directory is searched first"
        );
    }

    #[test]
    fn a_database_that_will_not_load_leaves_the_reason_and_no_rules() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path(), dir.path());
        std::fs::create_dir_all(&paths.db_dir).expect("creates");
        std::fs::write(
            paths.db_dir.join(DATABASE_FILE),
            b"WENLEDB\x00 not a database",
        )
        .expect("writes");
        let engine = load_with(&paths, &scanning(), None, CatalogStatus::default());
        assert!(engine.database.is_none());
        let reason = engine.load_error.expect("the failure is reported");
        assert!(
            reason.contains(DATABASE_FILE),
            "the message must name the file: {reason}"
        );
        // A service that has no rules is at least a service that runs.
        assert_eq!(engine.engine.database().len(), 0);
    }

    #[test]
    fn a_catalog_status_describes_itself_honestly() {
        // The three states a caller can be in, each with a sentence that says
        // which one it is. An empty store and a store with problems are not the
        // same fact and must not read the same.
        let empty = CatalogStatus::default();
        assert!(empty.is_empty());
        assert!(empty.describe().contains("no catalog store"));

        let partial = CatalogStatus {
            read: 7300,
            refused: 20,
            oversized: 1,
        };
        assert!(!partial.is_empty());
        let text = partial.describe();
        assert!(text.contains("7300"));
        assert!(text.contains("20"));
        assert!(text.contains("1 too large"));

        let clean = CatalogStatus {
            read: 12,
            refused: 0,
            oversized: 0,
        };
        assert_eq!(clean.describe(), "12 catalogs indexed");
    }

    #[test]
    fn the_service_reads_the_catalog_store_through_its_own_cache() {
        // The defect this is here for: this module called `from_store`, the
        // uncached builder, while `av-cli` and `av-gui` called
        // `from_store_cached` — the function whose own documentation says it
        // "is what a scan should call". Measured in the VM on 2026-10-10, that
        // was most of a twenty-one-second `Start-Service`: the DER parse of 1.2
        // GB paid again on every boot, by the one caller in the product that
        // never gets to be a second run.
        //
        // The difference between the two constructors is one file and one
        // boolean. The uncached one writes nothing anywhere; the cached one
        // leaves the index in the directory it was handed, and the next build
        // that reads it reports a hit. So: point the service at a store and a
        // cache directory that nothing has written to, build twice, and look at
        // both.
        //
        // The store is one `.cat` this test writes, not the one in `CatRoot`.
        // That is the point of `catalog_from`'s seam, and the reason is in its
        // documentation: the real store costs about a minute to parse, and a
        // suite that reads it asserts what is installed on the machine running
        // it rather than what this code does.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = dir.path().join("store");
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&store).expect("a store directory");
        std::fs::create_dir_all(&cache_dir).expect("the cache directory the layout names");
        let digest = [0x5A_u8; 20];
        std::fs::write(
            store.join("one.cat"),
            av_signatures::testing::catalog(&[&digest]),
        )
        .expect("a catalog covering one digest");

        let cache = av_signatures::catalog::cache_path(&cache_dir);
        let (first, status) = catalog_from(Some(&store), &cache_dir);
        let first = first.expect("a store with a readable catalog in it builds an index");
        assert_eq!(status.read, 1, "one catalog was written, one must be read");
        assert_eq!(first.digest_count(), 1, "the catalog covers one digest");
        assert!(!first.cache_hit(), "the first build has nothing to read");
        assert!(
            cache.exists(),
            "the index was built without leaving one at {}, which is what the uncached \
             constructor does: the service would pay the whole store's parse at start-up and \
             pay it again at the next boot",
            cache.display()
        );

        // The second build is the boot after the first, and the one the
        // measurement is about. A hit is the whole claim, so it is asserted
        // rather than timed: a duration is a number, and a number is not an
        // assertion.
        let (second, status) = catalog_from(Some(&store), &cache_dir);
        let second = second.expect("the same store still builds an index");
        assert!(
            second.cache_hit(),
            "the second build did not read the index the first one wrote"
        );
        assert_eq!(status.read, 1);
        assert_eq!(
            second.digest_count(),
            first.digest_count(),
            "the cached index must describe the same store as the one that built it"
        );

        // A platform with no catalog store. `None` is a fact about the machine
        // and not a failure, so it produces no index and no error — and the
        // counters are zero rather than absent, which is what
        // `CatalogStatus::describe` reads to say the store was not found.
        let (absent, status) = catalog_from(None, &cache_dir);
        assert!(absent.is_none());
        assert_eq!(status, CatalogStatus::default());
    }

    #[test]
    fn the_products_own_tree_is_the_one_no_scan_should_walk() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"));
        assert!(is_own_tree(&paths, &paths.quarantine_dir.join("item.bin")));
        assert!(is_own_tree(&paths, &paths.config_file));
        assert!(!is_own_tree(
            &paths,
            Path::new("C:\\Windows\\System32\\kernel32.dll")
        ));
    }
}
