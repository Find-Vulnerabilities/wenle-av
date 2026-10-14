//! Which events are worth acting on, and which trees are not ours to scan.
//!
//! # Why a delete is not a scan candidate
//!
//! The watcher's job is to scan a file that is *there*. Three of the five
//! actions report a file that is not:
//!
//! * `FILE_ACTION_REMOVED` — the file is gone.
//! * `FILE_ACTION_RENAMED_OLD_NAME` — the file is gone *from here*.
//! * `FILE_ACTION_MODIFIED` — the file is there, but whether it is worth
//!   re-scanning depends on the write. See below.
//!
//! Scanning on a delete would mean reading a path that no longer resolves, so
//! every such event would produce a [`Verdict::Unknown`](av_core::Verdict)
//! report, a line in the log, and a wasted `open` on a machine that is trying to
//! delete a directory tree. A watched `%TEMP%` sees deletes constantly; the
//! filter is what keeps that from being the busiest part of the product.
//!
//! # What a rename is actually reported as
//!
//! This is worth being exact about, because the intuitive answer is wrong and
//! the filter would be wrong with it. The kernel can pair the two halves of a
//! rename only when it watched both, which gives two cases that behave
//! differently:
//!
//! * **Moved in from outside the watched tree** — the dropper case, staged in
//!   `%TEMP%` and moved into `Downloads`. There is no old half to report,
//!   because the source was never in a tree we watch, so this arrives as a plain
//!   `FILE_ACTION_ADDED` on the destination. Measured, not assumed:
//!   `watch::tests::filesystem::a_file_moved_into_the_tree_arrives_as_a_new_name`
//!   prints `[Added]` for exactly that operation.
//! * **Renamed inside the watched tree** — arrives as the pair
//!   `[RENAMED_OLD_NAME, RENAMED_NEW_NAME]`, in *one* batch. Measured by
//!   `..._a_rename_inside_the_tree_arrives_as_both_names`, which prints both
//!   records.
//!
//! `RENAMED_NEW_NAME` is therefore not what catches the dropper — `ADDED` is.
//! What it catches is the file whose name changed under a watch that had already
//! seen the old one: the new name is a path nothing has looked at, and a filter
//! that admitted only `ADDED` would leave it unscanned for as long as it kept
//! that name. Admitting it also costs nothing, because the two halves of the one
//! rename arrive together and the old half is filtered out below.
//!
//! The pairing has a consequence for any consumer of these records: a rename is
//! two records in one batch, so a reader that looks for its path in a batch must
//! scan the whole batch rather than stopping at the first match.
//!
//! # Why a modification is conditional
//!
//! Asking for `FILE_NOTIFY_CHANGE_LAST_WRITE` is what tells the kernel to report
//! modifications, and it costs something real: a compiler writing object files,
//! a database writing its journal and a download writing chunks all produce a
//! stream of them. `scan_on_write` is the configuration switch for whether that
//! cost is paid, and when it is off the kernel is not asked for the category at
//! all — see `watch::change_filter`, which is where asking for less is turned
//! into doing less rather than into filtering harder.
//!
//! # Why an exclusion set and not a filter on the scanner
//!
//! Because the storm this prevents is caused by the *watcher*, and a check
//! further down the pipe still pays for the kernel round trip, the buffer, the
//! channel and the event. The vault directory is where this crate's own
//! quarantines land; watching it means every detection writes a file that
//! triggers a scan that writes a file. See [`ExclusionSet`] for the decision
//! and what it costs.
//!
//! # Why these functions are pure
//!
//! So that the decisions can be tested without a filesystem and without Windows.
//! `is_scan_candidate` takes the flag rather than a whole config, and
//! `ExclusionSet` takes a path and compares strings, which is what makes the
//! shared-prefix trap in `a_sibling_directory_is_not_excluded` a unit test.

use std::path::{Path, PathBuf};

use crate::notify::FileAction;

/// Should this action cause a scan?
///
/// `scan_on_write` is
/// [`RealtimeConfig::scan_on_write`](av_core::config::RealtimeConfig::scan_on_write):
/// with it off, a modification is reported by the kernel only if some other
/// category asked for it, and is never a scan candidate here.
pub fn is_scan_candidate(action: FileAction, scan_on_write: bool) -> bool {
    match action {
        FileAction::Added | FileAction::RenamedNewName => true,
        FileAction::Modified => scan_on_write,
        // A delete leaves nothing to scan, the old half of a rename names a path
        // that is now empty, and an action code this build does not recognise is
        // not evidence that a file appeared.
        FileAction::Removed | FileAction::RenamedOldName | FileAction::Unknown(_) => false,
    }
}

/// The actions worth being told about, as a predicate over [`FileAction`].
///
/// The inverse of [`is_scan_candidate`] for the actions the kernel will report
/// anyway: a delete is not scanned, but it is still worth counting, because a
/// burst of deletes in a watched tree is what an encrypting ransomware looks
/// like from the outside.
pub fn is_reportable(action: FileAction) -> bool {
    !matches!(action, FileAction::Unknown(_))
}

/// Directories whose contents are never watched and never scanned.
///
/// # The decision
///
/// The quarantine vault lives under the product's data directory. A scan of a
/// malicious file writes it there, and if that directory is inside the watched
/// set the write is an event, the event is a scan, and the scan is a write. The
/// loop is not theoretical: the vault's index is rewritten on every quarantine,
/// so one detection becomes an unbounded stream of them. Two directories are
/// therefore excluded — the vault, and the data root that contains it — together
/// with the install directory, which holds the rule database that every scan
/// reads and the executable that every scan runs inside.
///
/// # What it costs
///
/// **An attacker who can write into the product's data directory is not scanned
/// by this crate while they are there.** That is a real gap and it is stated
/// rather than implied. It is bounded by three things: `av-core`'s
/// [`AvPaths::is_protected`] marks exactly this tree as the one the product
/// defends, so writing into it is what the self-protection rules exist to
/// refuse; a file sitting in the vault is ciphertext that no rule can say
/// anything about; and an attacker who can write there has already got past
/// self-protection, which is a worse failure than a missed scan and one this
/// crate cannot see either way.
///
/// The alternative — watching the vault and dropping the events in the scanner —
/// was rejected because the kernel work, the buffer and the channel traffic are
/// paid before the drop, and because a dropped event is indistinguishable from a
/// scanned one in every log the product writes.
///
/// [`AvPaths::is_protected`]: av_core::AvPaths::is_protected
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExclusionSet {
    /// Normalized, lowercased roots with no trailing separator.
    roots: Vec<String>,
}

impl ExclusionSet {
    /// Build a set from the directories nothing under which may be watched.
    ///
    /// Duplicates and roots that normalize to nothing are dropped, so two
    /// spellings of one directory do not make the set report two.
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut normalized: Vec<String> = roots
            .into_iter()
            .map(|root| normalize(&root))
            .filter(|root| !root.is_empty())
            .collect();
        normalized.sort_unstable();
        normalized.dedup();
        Self { roots: normalized }
    }

    /// The set that keeps the watcher out of its own house.
    ///
    /// The install tree, the data root and the vault explicitly. The data root
    /// already contains the vault, but the vault is named too because a caller
    /// can be configured with a vault somewhere else — a portable install, or a
    /// test — and a guard that only works when the two agree is not a guard.
    pub fn for_paths(paths: &av_core::AvPaths) -> Self {
        Self::new([
            paths.install_dir.clone(),
            paths.data_dir.clone(),
            paths.quarantine_dir.clone(),
        ])
    }

    /// Add one more directory that must not be watched.
    #[must_use]
    pub fn with(mut self, root: impl Into<PathBuf>) -> Self {
        let root = normalize(&root.into());
        if !root.is_empty() && !self.roots.contains(&root) {
            self.roots.push(root);
            self.roots.sort_unstable();
        }
        self
    }

    /// True when `path` is one of the excluded directories or inside one.
    ///
    /// Case-insensitive and separator-insensitive at the boundaries, because
    /// Windows paths are: `C:\ProgramData\WenleAV` and `c:\programdata\wenleav\`
    /// are one directory, and a set that thought otherwise would leave the storm
    /// guard open for whichever spelling the configuration happened to use.
    pub fn excludes(&self, path: &Path) -> bool {
        let candidate = normalize(path);
        if candidate.is_empty() {
            return false;
        }
        self.roots.iter().any(|root| {
            candidate == *root
                || candidate
                    .strip_prefix(root.as_str())
                    .is_some_and(|rest| rest.starts_with('\\'))
        })
    }

    /// True when nothing is excluded.
    ///
    /// Worth asking explicitly: an empty set is the configuration in which the
    /// storm guard is not in place, and a caller that logs it is a caller that
    /// can tell a protected installation from an unprotected one.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The excluded roots, normalized and sorted.
    pub fn roots(&self) -> &[String] {
        &self.roots
    }
}

/// Lowercase, strip the Windows extended-length prefix, and drop any trailing
/// separator.
///
/// The comparison is textual and not canonicalizing on purpose:
/// `std::fs::canonicalize` needs the path to exist, and the path being tested is
/// often a file that was created a millisecond ago and may already be gone. A
/// textual comparison also cannot fail, which matters because the failure mode
/// of a canonicalizing exclusion check would be to conclude "not excluded" and
/// watch the vault.
fn normalize(path: &Path) -> String {
    let text = path.to_string_lossy().to_lowercase();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text).to_string();
    let trimmed = text.trim_end_matches('\\');
    // A root that is nothing but separators (`\`) normalizes to the empty
    // string and is refused by the callers rather than matching everything.
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> av_core::AvPaths {
        av_core::AvPaths::with_data_dir(r"C:\Program Files\WenleAV", r"C:\ProgramData\WenleAV")
    }

    #[test]
    fn a_create_and_a_rename_into_place_are_scanned_and_a_delete_is_not() {
        assert!(is_scan_candidate(FileAction::Added, true));
        assert!(is_scan_candidate(FileAction::RenamedNewName, true));
        assert!(!is_scan_candidate(FileAction::Removed, true));
        assert!(!is_scan_candidate(FileAction::RenamedOldName, true));
        assert!(!is_scan_candidate(FileAction::Unknown(7), true));
    }

    #[test]
    fn both_shapes_a_rename_arrives_in_produce_a_scan() {
        // The differential the module documentation is built on, and the reason
        // the two cases are spelled out there. The action a *file moved into the
        // tree* arrives as is `Added`, and the pair a rename *inside* the tree
        // arrives as is `[RenamedOldName, RenamedNewName]`. Both are reported by
        // the ignored filesystem tests in `crate::watch`, which print what the
        // kernel actually sent; this pins the filtering decision that follows
        // from each, so a change to either one has to argue with a test.
        //
        // A move in from outside: `Added` carries the scan.
        let moved_in = [FileAction::Added];
        assert!(moved_in.iter().any(|a| is_scan_candidate(*a, true)));
        // A rename inside the tree: exactly one of the two halves does.
        let renamed = [FileAction::RenamedOldName, FileAction::RenamedNewName];
        assert_eq!(
            renamed
                .iter()
                .filter(|action| is_scan_candidate(**action, true))
                .count(),
            1,
            "a rename inside the tree must produce exactly one scan, not two and not none"
        );
    }

    #[test]
    fn a_modification_is_only_a_candidate_when_writes_are_scanned() {
        assert!(is_scan_candidate(FileAction::Modified, true));
        assert!(!is_scan_candidate(FileAction::Modified, false));
        // And the other two do not depend on the flag at all, which is the
        // difference between a conditional action and a disabled feature.
        assert!(is_scan_candidate(FileAction::Added, false));
        assert!(is_scan_candidate(FileAction::RenamedNewName, false));
    }

    #[test]
    fn a_delete_is_still_reportable_even_though_it_is_not_a_candidate() {
        // The two questions are different, and a filter that answered both with
        // one function would either scan deletes or stop counting them.
        assert!(is_reportable(FileAction::Removed));
        assert!(!is_scan_candidate(FileAction::Removed, true));
        assert!(!is_reportable(FileAction::Unknown(7)));
    }

    #[test]
    fn the_vault_and_the_install_and_the_data_root_are_all_excluded() {
        let set = ExclusionSet::for_paths(&paths());
        assert!(set.excludes(Path::new(r"C:\ProgramData\WenleAV\quarantine\ab.qtn")));
        assert!(set.excludes(Path::new(r"C:\ProgramData\WenleAV\logs\wenle.log")));
        assert!(set.excludes(Path::new(r"C:\Program Files\WenleAV\wenle-av.exe")));
        // The directories themselves, not only their contents: an event for the
        // directory is still an event.
        assert!(set.excludes(Path::new(r"C:\ProgramData\WenleAV")));
        assert!(set.excludes(Path::new(r"C:\ProgramData\WenleAV\quarantine")));
    }

    #[test]
    fn a_user_directory_is_not_excluded() {
        let set = ExclusionSet::for_paths(&paths());
        assert!(!set.excludes(Path::new(r"C:\Users\me\Downloads\invoice.exe")));
        assert!(!set.excludes(Path::new(r"C:\Temp")));
    }

    #[test]
    fn a_sibling_directory_sharing_a_textual_prefix_is_not_excluded() {
        // The bug a plain `starts_with` on a string produces: `WenleAV-backup`
        // begins with `WenleAV` and is a different directory. A restore that
        // wrote a quarantine backup next to the vault would then be silently
        // unwatched.
        let set = ExclusionSet::for_paths(&paths());
        assert!(!set.excludes(Path::new(r"C:\ProgramData\WenleAV-backup\x.txt")));
        assert!(!set.excludes(Path::new(r"C:\Program Files\WenleAV-old\wenle-av.exe")));
    }

    #[test]
    fn the_comparison_ignores_case_and_the_extended_length_prefix() {
        let set = ExclusionSet::for_paths(&paths());
        assert!(set.excludes(Path::new(r"c:\programdata\wenleav\quarantine\AB.QTN")));
        assert!(set.excludes(Path::new(r"\\?\C:\ProgramData\WenleAV\cache\a.bin")));
        // And a trailing separator on either side is not a difference.
        assert!(set.excludes(Path::new(r"C:\ProgramData\WenleAV\")));
    }

    #[test]
    fn a_root_that_is_only_a_separator_excludes_nothing() {
        // Normalizing `\` yields the empty string, and an empty prefix matches
        // every path — which would disable the watcher entirely rather than
        // over-watch.
        let set = ExclusionSet::new([PathBuf::from(r"\"), PathBuf::from("")]);
        assert!(set.is_empty());
        assert!(!set.excludes(Path::new(r"C:\Users\me\a.exe")));
    }

    #[test]
    fn duplicates_and_trailing_separators_do_not_make_two_roots() {
        let set = ExclusionSet::new([
            PathBuf::from(r"C:\Vault"),
            PathBuf::from(r"c:\vault\"),
            PathBuf::from(r"C:\Vault"),
        ]);
        assert_eq!(set.roots().len(), 1);
        assert_eq!(set.roots()[0], r"c:\vault");
    }

    #[test]
    fn a_root_can_be_added_after_the_fact() {
        let set = ExclusionSet::for_paths(&paths()).with(r"D:\Vault");
        assert!(set.excludes(Path::new(r"d:\vault\items\a.qtn")));
        assert!(set.excludes(Path::new(r"C:\ProgramData\WenleAV\quarantine\a.qtn")));
        // Adding the same root twice changes nothing.
        let again = set.clone().with(r"D:\VAULT\");
        assert_eq!(again, set);
    }
}
