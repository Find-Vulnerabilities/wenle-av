//! The paths the product has been told to leave alone.
//!
//! An *allow* is a path the decision path must not scan. The product offers the
//! user two ways to say "I know about this file": **allow for this boot**, which
//! lasts until the service restarts, and **allow permanently**, which is also
//! written to [`av_core::config::GeneralConfig::exclusions`]. Both are honoured
//! by [`AllowList::allows`] and that is the whole of what the two have in
//! common — they are kept in two lists, because what ends them differs.
//!
//! A *session* entry is ended by the process going away. A *configured* entry is
//! ended by the user editing the setting, possibly while this service is
//! running: [`AllowList::set_configured`] replaces that list whole, which is
//! what makes a path the user has just *removed* from `general.exclusions`
//! start being scanned again. One list would make that impossible — removing an
//! entry and re-seeding from the configuration are the same operation only if
//! the session's entries are somewhere else.
//!
//! # Why the service owns this, when [`crate::filter_port`] says it does not
//! decide exclusions
//!
//! That module's documentation said the driver applies its own table before it
//! asks anything, so a second filter in the service would be a second answer to
//! a question that already has one owner. The first half is true. The second
//! half stopped being true the moment the user could press a button: the
//! driver's table is [`av_driver_proto::exclusions::BUILT_IN`] — four hardcoded
//! entries, `const`, with no run-time update path at all.
//! [`av_driver_proto::wire::ExclusionBuffer`] and `IOCTL_SET_EXCLUSIONS` are
//! defined and tested, but nothing constructs the first and the driver has no
//! control device to receive the second, so a *user's* exclusion has no owner in
//! the kernel and cannot get one without a driver change.
//!
//! The ownership is therefore split along a line that can be stated exactly:
//! **the driver owns its built-in list and still applies it first; the service
//! owns everything the user has said.** Neither answers for the other's entries.
//! An entry here can only ever widen what is allowed to run — it can never make
//! the driver refuse something it would have allowed, because the driver
//! consults its own table before it asks and this one is consulted only after.
//!
//! # The matcher is the driver's, not a second one
//!
//! [`av_driver_proto::exclusions::is_excluded`] is the function the driver
//! applies to its own table, so the two cannot disagree about component
//! boundaries: whether `C:\Windows` matches `C:\WindowsApps` is decided in one
//! place, and so is whether `C:\x.txt` matches the alternate data stream
//! `C:\x.txt:evil`. A matcher written here over [`Path`] would be exactly the
//! disagreement this module exists to avoid, and it would be invisible — a file
//! the user allowed that is scanned and taken anyway.
//!
//! # Cost, because this is on the driver's decision path
//!
//! The empty case is free. With no entries [`AllowList::allows`] returns without
//! touching the path at all, which is the state of every installation whose user
//! has never pressed "allow" — and that is the common case, so it must not pay
//! for the rare one. A non-empty set costs one UTF-16 conversion per decision
//! plus one comparison per entry; the entries are stored pre-converted, so that
//! work does not grow with how long the entries are.
//!
//! The lock is `parking_lot`'s, held for the comparison only and never across a
//! scan: [`AllowList::allows`] takes a read guard, decides, and drops it before
//! the caller does anything that waits. The decision path blocks for up to
//! `crate::filter_port::DECISION_DEADLINE` and a writer must never be waiting
//! behind that.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use av_driver_proto::exclusions;
use parking_lot::RwLock;

/// The set of paths the decision path must not scan.
///
/// Cheap to clone: every clone is a handle to the same set, which is what makes
/// it possible for the control thread to add an entry while the filter-port
/// thread is checking one. See this module's documentation for why the empty
/// case is free.
#[derive(Clone, Debug, Default)]
pub struct AllowList {
    /// What `general.exclusions` last said, in the order the file lists them.
    ///
    /// Replaced whole by [`AllowList::set_configured`] and never appended to at
    /// run time, which is the property that makes an entry the user *removed*
    /// stop applying.
    configured: Arc<RwLock<Vec<Vec<u16>>>>,
    /// What the user allowed while this service has been running.
    ///
    /// Never touched by a configuration change: a user who allows a file for
    /// this boot and then edits an unrelated setting must not lose the allow,
    /// and `ConfigSet` writes the whole document, so a re-seed that rebuilt one
    /// list from it would do exactly that.
    session: Arc<RwLock<Vec<Vec<u16>>>>,
}

/// Entries in UTF-16, in the order they were added.
///
/// A `Vec` rather than a `HashSet` because every lookup is a *prefix* match and
/// so has to compare against the entries anyway; a hash set would be a second
/// structure to keep in step with this one for no saved work. Each list is one
/// entry per path the user has allowed, so the linear scan is bounded by a
/// number a person controls.
type Entries = Vec<Vec<u16>>;

/// `path` as the comparison wants it. Both producers are strings — see
/// [`AllowList::allows`] — which is why this goes through `str`.
fn units_of(path: &Path) -> Vec<u16> {
    path.to_string_lossy().encode_utf16().collect()
}

impl AllowList {
    /// An empty set: nothing is allowed, and every check is free.
    pub fn new() -> Self {
        Self::default()
    }

    /// The set a service starts with: whatever the configuration already said.
    ///
    /// This is half of "permanent": a permanent allow is written to the
    /// configuration *and* added to the session list, and the reason it must be
    /// both is that writing the file alone would leave the button doing nothing
    /// until the next restart. Reading the file here is what makes the two
    /// paths agree after one.
    pub fn from_paths(paths: &[PathBuf]) -> Self {
        let list = Self::new();
        list.set_configured(paths);
        list
    }

    /// Replace what the configuration says, keeping this run's allows.
    ///
    /// Called at startup and on every accepted `ConfigSet`, which is what makes
    /// `general.exclusions` a setting the service honours as it is edited rather
    /// than one it reads once. Replacement rather than addition is the point:
    /// the user may have taken an entry *out*.
    pub fn set_configured(&self, paths: &[PathBuf]) {
        let mut configured = self.configured.write();
        configured.clear();
        for path in paths {
            let units = units_of(path);
            if !configured.contains(&units) {
                configured.push(units);
            }
        }
    }

    /// Whether nothing is allowed, in either list.
    ///
    /// Exposed because the decision path asks it: an empty set is reported so
    /// that the cheap answer is visibly the one being taken, rather than an
    /// optimisation a reader has to reconstruct.
    pub fn is_empty(&self) -> bool {
        self.configured.read().is_empty() && self.session.read().is_empty()
    }

    /// How many entries are held, across both lists.
    pub fn len(&self) -> usize {
        self.configured.read().len() + self.session.read().len()
    }

    /// Whether `path` is allowed, and must not be scanned.
    ///
    /// `path` is expected to be normalised — no `.` or `..` components and no
    /// embedded NUL — which is [`exclusions::is_excluded`]'s precondition. Both
    /// callers satisfy it: `crate::filter_port::Dispatcher::decide` builds the
    /// path from the driver's own device-to-DOS translation, and the entries
    /// come from a configuration string.
    ///
    /// The conversion goes through `str` rather than
    /// [`std::os::windows::ffi::OsStrExt::encode_wide`], which keeps this module
    /// portable to the non-Windows build the crate still has. It is exact for
    /// every path that can reach here, because both producers are strings: the
    /// driver's path has already survived `String::from_utf16` and a TOML value
    /// is UTF-8 to begin with. A path that somehow was not would be turned into
    /// a *different* path by `to_string_lossy` — a wrong answer rather than a
    /// panic, which is why the precondition is stated rather than assumed.
    ///
    /// The two lists are checked independently and each has its own empty check,
    /// so the common case — no configured exclusions and the user has pressed
    /// nothing — returns without converting the path at all, and a session allow
    /// costs nothing while there are no configured ones. The guards are on the
    /// lists and not on the pair because an installation with exclusions
    /// configured but nothing allowed by hand scans every entry for a decision
    /// that the session list cannot answer, and that is the state a user who
    /// edits the file reaches.
    pub fn allows(&self, path: &Path) -> bool {
        let configured = self.configured.read();
        let session = self.session.read();
        if configured.is_empty() && session.is_empty() {
            return false;
        }
        let units = units_of(path);
        matches(&units, &configured) || matches(&units, &session)
    }

    /// Add an entry to this run's list, and say whether it was new.
    ///
    /// `false` means the entry was already there and nothing changed, which is
    /// what lets a permanent allow that the user asks for twice not append the
    /// same line to the configuration twice.
    ///
    /// This is the *session* list. A permanent allow also goes to
    /// [`AllowList::set_configured`] through the configuration it was written
    /// into; putting it here as well is what makes it take effect before that
    /// happens, and what keeps it in force if the file could not be written.
    ///
    /// Comparison is on the stored spelling, so `C:\Games\` and `C:\Games`
    /// are two entries naming one directory. That costs one extra comparison per
    /// check and nothing else; it is not worth a normalising pass that could
    /// itself disagree with the matcher about what a directory is.
    ///
    /// The entry is **not** held to
    /// [`av_driver_proto::exclusions::MAX_EXCLUSION_UNITS`]. A longer one could
    /// never be sent to the driver, but nothing sends anything to the driver
    /// today (see this module's documentation), and refusing it here would
    /// silently drop an exclusion the user asked for — which is the failure this
    /// whole module is shaped to prevent.
    pub fn insert(&self, path: &Path) -> bool {
        let units = units_of(path);
        let mut session = self.session.write();
        if session.contains(&units) {
            return false;
        }
        session.push(units);
        true
    }

    /// Every entry, configured ones first, for a caller that has to write them
    /// somewhere. Lossy in the same way and for the same reason as
    /// [`AllowList::allows`].
    pub fn snapshot(&self) -> Vec<PathBuf> {
        let configured = self.configured.read();
        let session = self.session.read();
        configured
            .iter()
            .chain(session.iter())
            .map(|units| PathBuf::from(String::from_utf16_lossy(units)))
            .collect()
    }
}

/// [`exclusions::is_excluded`] over one list.
fn matches(units: &[u16], entries: &Entries) -> bool {
    !entries.is_empty() && exclusions::is_excluded(units, entries.iter().map(Vec::as_slice))
}

#[cfg(test)]
mod tests {
    use super::AllowList;
    use std::path::PathBuf;

    /// The empty set allows nothing, and it is the state the product ships in.
    #[test]
    fn nothing_is_allowed_until_something_is() {
        let list = AllowList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(!list.allows(std::path::Path::new(r"C:\Users\example\games\setup.exe")));
    }

    /// An entry names a directory, and the directory itself *and* everything
    /// under it are allowed — a user who allows a folder means the folder.
    #[test]
    fn an_entry_covers_the_path_and_everything_under_it() {
        let list = AllowList::from_paths(&[PathBuf::from(r"C:\Users\example\games")]);
        assert!(!list.is_empty());
        assert!(list.allows(std::path::Path::new(r"C:\Users\example\games\setup.exe")));
        assert!(list.allows(std::path::Path::new(r"C:\Users\example\games\a\b\c.dll")));
        assert!(list.allows(std::path::Path::new(r"C:\Users\example\games")));
    }

    /// The boundary question is the driver's matcher's, and this pins that the
    /// service inherits the right answer: a shared prefix is not a match. This
    /// is the assertion that would fail if someone replaced the matcher with
    /// `starts_with` on a `Path`.
    #[test]
    fn a_shared_prefix_is_not_a_match() {
        let list = AllowList::from_paths(&[PathBuf::from(r"C:\Windows")]);
        assert!(!list.allows(std::path::Path::new(r"C:\WindowsApps\evil.exe")));
        assert!(!list.allows(std::path::Path::new(r"C:\Windows.old\evil.exe")));
        // And the file/extension boundary, which is the same question one level
        // down and the one a naive string prefix gets wrong most often.
        let file = AllowList::from_paths(&[PathBuf::from(r"C:\games\x.txt")]);
        assert!(file.allows(std::path::Path::new(r"C:\games\x.txt")));
        assert!(!file.allows(std::path::Path::new(r"C:\games\x.txt.bak")));
    }

    /// Windows paths are case-insensitive and the driver's matcher is
    /// ASCII-case-insensitive; a user who types the path in the wrong case must
    /// still be obeyed.
    #[test]
    fn case_does_not_matter() {
        let list = AllowList::from_paths(&[PathBuf::from(r"C:\Users\Example\Games")]);
        assert!(list.allows(std::path::Path::new(r"C:\users\example\games\setup.exe")));
        assert!(list.allows(std::path::Path::new(r"c:\USERS\EXAMPLE\GAMES")));
    }

    /// An entry added at run time takes effect at once, which is the whole
    /// point of the type: `allows` and `insert` are called from different
    /// threads and the next check must see it.
    #[test]
    fn an_added_entry_takes_effect_at_once() {
        let list = AllowList::new();
        let path = std::path::Path::new(r"C:\Users\example\games\setup.exe");
        assert!(!list.allows(path));
        assert!(list.insert(std::path::Path::new(r"C:\Users\example\games")));
        assert!(list.allows(path));
        assert_eq!(list.len(), 1);
    }

    /// Adding the same entry twice changes nothing and reports that it did not,
    /// which is what stops a repeated "allow permanently" from growing the
    /// configuration file.
    #[test]
    fn adding_the_same_entry_twice_is_reported_and_changes_nothing() {
        let list = AllowList::new();
        assert!(list.insert(std::path::Path::new(r"C:\Games")));
        assert!(!list.insert(std::path::Path::new(r"C:\Games")));
        assert_eq!(list.len(), 1);
    }

    /// A clone is a second handle to one set, not a copy — the control thread's
    /// `insert` is visible to the filter-port thread's clone. If `Clone` ever
    /// became a deep copy this test fails and the feature silently stops
    /// working, which is the failure mode worth a test.
    #[test]
    fn a_clone_shares_the_set_with_its_origin() {
        let list = AllowList::new();
        let other = list.clone();
        assert!(other.insert(std::path::Path::new(r"C:\Games")));
        assert!(list.allows(std::path::Path::new(r"C:\Games\setup.exe")));
        assert_eq!(list.len(), 1);
    }

    /// The snapshot round-trips what was inserted, in order.
    #[test]
    fn the_snapshot_is_what_was_inserted() {
        let list = AllowList::new();
        list.insert(std::path::Path::new(r"C:\Games"));
        list.insert(std::path::Path::new(r"C:\Tools\r.exe"));
        assert_eq!(
            list.snapshot(),
            vec![PathBuf::from(r"C:\Games"), PathBuf::from(r"C:\Tools\r.exe")]
        );
    }

    /// Taking an entry out of the configuration stops it applying, which is the
    /// whole reason the configured entries are a list of their own: a re-seed
    /// that appended would leave a path the user has just removed permanently
    /// excluded for the life of the process.
    #[test]
    fn a_configuration_change_replaces_what_the_configuration_said() {
        let list = AllowList::from_paths(&[PathBuf::from(r"C:\Games"), PathBuf::from(r"C:\Tools")]);
        assert!(list.allows(std::path::Path::new(r"C:\Games\setup.exe")));
        assert!(list.allows(std::path::Path::new(r"C:\Tools\r.exe")));

        list.set_configured(&[PathBuf::from(r"C:\Games")]);
        assert!(list.allows(std::path::Path::new(r"C:\Games\setup.exe")));
        assert!(
            !list.allows(std::path::Path::new(r"C:\Tools\r.exe")),
            "an entry the user removed must stop applying"
        );

        list.set_configured(&[]);
        assert!(list.is_empty());
        assert!(!list.allows(std::path::Path::new(r"C:\Games\setup.exe")));
    }

    /// A user who allows a file for this boot and then edits an unrelated
    /// setting must keep the allow. `ConfigSet` writes the whole document, so a
    /// re-seed that rebuilt one list from it would drop exactly this.
    #[test]
    fn a_session_allow_survives_a_configuration_change() {
        let list = AllowList::new();
        list.insert(std::path::Path::new(r"C:\Users\example\games"));
        list.set_configured(&[PathBuf::from(r"C:\Tools")]);

        assert!(list.allows(std::path::Path::new(r"C:\Users\example\games\setup.exe")));
        assert!(list.allows(std::path::Path::new(r"C:\Tools\r.exe")));
        assert_eq!(list.len(), 2, "one configured entry and one session entry");
    }

    /// A permanent allow reaches both lists, and asking twice does not grow
    /// either of them.
    #[test]
    fn a_permanent_allow_is_in_both_lists_and_does_not_double_up() {
        let list = AllowList::new();
        assert!(list.insert(std::path::Path::new(r"C:\Games")));
        list.set_configured(&[PathBuf::from(r"C:\Games")]);
        assert!(!list.insert(std::path::Path::new(r"C:\Games")));
        assert!(list.allows(std::path::Path::new(r"C:\Games\setup.exe")));
        // One entry in each list, and the snapshot says so rather than hiding
        // one of them behind the other.
        assert_eq!(list.len(), 2);
        assert_eq!(
            list.snapshot(),
            vec![PathBuf::from(r"C:\Games"), PathBuf::from(r"C:\Games")]
        );
    }
}
