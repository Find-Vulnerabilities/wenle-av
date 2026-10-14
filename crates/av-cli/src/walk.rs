//! Deciding which files a scan is even going to look at.
//!
//! # The cheapest large win available to a scanner
//!
//! Not scanning. A directory of ten thousand files usually contains a few
//! hundred that can carry code and several thousand that cannot, and every
//! filter here removes work rather than doing it faster. That makes this module
//! worth its own file and its own care: a filter that removes a file it should
//! not have is a missed detection, and no later stage can notice.
//!
//! # What is skipped, and why each is safe
//!
//! * **Its own directories.** Scanning the quarantine vault would be a scanner
//!   that re-detects everything it has already dealt with, and scanning the
//!   rule database would be a scanner that matches its own rules against
//!   themselves.
//! * **Links, unless asked.** A junction pointing at its parent is an infinite
//!   directory tree. `--follow-links` is the user saying they know.
//! * **Files above the size limit.** The limit is the user's; without one there
//!   is no default, because a scanner that refuses to scan a large file by
//!   default is a scanner that misses large malware.
//! * **Whatever `--exclude` names.** The one filter that is not a heuristic:
//!   the user said so.
//!
//! # What this walk can see that `std::fs::read_dir` cannot
//!
//! The descent is [`av_fs::descend`], which lists a directory with
//! `FILE_FLAG_BACKUP_SEMANTICS` and whatever state the process's
//! `SeBackupPrivilege` is in. That is not an optimisation. `std::fs::read_dir`
//! reaches `FindFirstFileW`, which is DACL-subject, so `C:\System Volume
//! Information`, the Defender platform directory and every profile but one's own
//! are not merely unreadable — they are never *offered*, and the files inside
//! them never enter the list of things to scan. A scanner that enumerates that
//! way cannot report what it missed, because it does not know it missed
//! anything.
//!
//! Without the privilege the answer is still not silence. A directory that
//! refuses to be listed becomes a line in [`WalkOutcome::unreadable`] naming the
//! directory and the reason, and an unelevated run prints those lines rather
//! than issuing a clean bill of health over a tree it never entered. Elevating
//! the process is what turns those lines into files.
//!
//! Nothing here looks at *content*. The kind of a file is decided later, from
//! its bytes ([`av_scan::kind`]), because a name is a claim and the bytes are
//! evidence.

use std::path::{Path, PathBuf};

use av_core::AvPaths;

use crate::glob;

/// What the caller wants walked.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    pub recursive: bool,
    pub follow_links: bool,
    pub max_file_size: Option<u64>,
    pub exclude: Vec<String>,
    /// The product's own tree, which is never scanned. `None` in a test or in a
    /// portable run, where there is no installation to defend.
    pub protected: Option<AvPaths>,
}

/// What the walk found.
#[derive(Debug, Default)]
pub struct WalkOutcome {
    pub files: Vec<PathBuf>,
    /// Total size of `files`, from the walk's own metadata. Used for the
    /// summary line, so a scan of a directory with no readable files still
    /// reports what it looked at.
    pub bytes: u64,
    /// Entries skipped by a filter, counted so that the summary can say so: an
    /// excluded directory or file, a file above the size limit, a target that is
    /// not a file or a directory, and a link not followed because
    /// `--follow-links` was not given. A user who excluded something and sees no
    /// mention of it will assume the scan looked at it.
    pub skipped: u64,
    /// What could not be looked at, with the reason: a missing target, a
    /// directory that refused to be listed, a file the metadata call refused.
    /// Reported rather than counted silently, because a scan that could not
    /// descend into a directory has not proven anything about what was in it —
    /// and on an unelevated run these lines are the difference between "nothing
    /// found" and "nothing found where I was allowed to look".
    pub unreadable: Vec<String>,
}

/// Collect the files to scan.
///
/// One walk, sequential, over the directory metadata. The scanning itself is
/// what runs in parallel: enumeration is dominated by the filesystem's latency
/// rather than by the CPU, and a parallel walk over one spindle is slower than
/// a sequential one.
pub fn collect(paths: &[PathBuf], options: &WalkOptions) -> WalkOutcome {
    let mut outcome = WalkOutcome::default();
    for path in paths {
        collect_one(path, options, &mut outcome);
    }
    outcome
}

fn collect_one(root: &Path, options: &WalkOptions, outcome: &mut WalkOutcome) {
    if options
        .protected
        .as_ref()
        .is_some_and(|p| p.is_protected(root))
    {
        outcome.skipped += 1;
        return;
    }
    if excluded(root, options) {
        outcome.skipped += 1;
        return;
    }

    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(e) => {
            outcome.unreadable.push(format!("{}: {e}", root.display()));
            return;
        }
    };

    if metadata.is_file() {
        push_file(root, metadata.len(), options, outcome);
        return;
    }
    if !metadata.is_dir() {
        // A device, a socket, a fifo: opening one can block forever, and
        // reading one is not scanning a file.
        outcome.skipped += 1;
        return;
    }

    // `max_depth(1)` is the non-recursive case: the root's own entries and
    // nothing below them.
    let descend = av_fs::DescendOptions {
        max_depth: if options.recursive { usize::MAX } else { 1 },
        follow_links: options.follow_links,
    };

    // Counted inside the filter rather than after it, because pruning is what
    // applies the exclusion and it drops the entry before anything else can see
    // it. A counter that missed them would make `--exclude` invisible in the
    // summary, which is the one place the user could notice it had not been
    // applied where they meant. A `Cell` because `av_fs` takes the filter by
    // shared reference — it is asked a question about each entry and has no
    // business holding a mutable borrow of the caller's state while it walks.
    let pruned = std::cell::Cell::new(0u64);
    let found = av_fs::descend(root, &descend, |path, _entry| {
        let drop = excluded(path, options)
            || options
                .protected
                .as_ref()
                .is_some_and(|p| p.is_protected(path));
        if drop {
            // An excluded *directory* counts once and is not descended into,
            // which is what makes `--exclude "**/node_modules"` cost nothing
            // rather than costing a walk of everything inside it.
            pruned.set(pruned.get() + 1);
        }
        drop
    });

    // A directory that refused to be listed. Reported with its reason rather
    // than as a count, because the user needs to know *which* directory was
    // closed to them — that is where to look by hand, and on an unelevated run
    // the answer is usually "elevate".
    for refused in &found.unreadable {
        outcome.unreadable.push(refused.to_string());
    }
    for file in found.files() {
        push_file(&file.path, file.size, options, outcome);
    }
    // Links that were not followed. Counted as skipped rather than as
    // unreadable: `--follow-links` is the user's switch and its default is a
    // deliberate choice, so a run that honoured it has not failed at anything.
    outcome.skipped += found.not_followed.len() as u64 + pruned.get();
}

/// Add one file to the outcome, if the size filter lets it through.
///
/// Takes the size rather than a `Metadata`, because the listing that produced
/// it already carried one and a second `stat` per file is a second chance for
/// the file to change between the two answers.
fn push_file(path: &Path, size: u64, options: &WalkOptions, outcome: &mut WalkOutcome) {
    if options
        .protected
        .as_ref()
        .is_some_and(|p| p.is_protected(path))
    {
        outcome.skipped += 1;
        return;
    }
    if let Some(limit) = options.max_file_size {
        if size > limit {
            outcome.skipped += 1;
            return;
        }
    }
    outcome.bytes = outcome.bytes.saturating_add(size);
    outcome.files.push(path.to_path_buf());
}

/// Whether a path matches any `--exclude` pattern.
fn excluded(path: &Path, options: &WalkOptions) -> bool {
    options
        .exclude
        .iter()
        .any(|pattern| glob::matches_path(pattern, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> WalkOptions {
        WalkOptions {
            recursive: false,
            follow_links: false,
            max_file_size: None,
            exclude: Vec::new(),
            protected: None,
        }
    }

    /// A directory tree with `files` written into it, removed when dropped.
    struct Tree {
        dir: PathBuf,
    }

    impl Tree {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("wenle-walk-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("a temp directory");
            Self { dir }
        }

        fn file(&self, relative: &str, contents: &[u8]) -> PathBuf {
            let path = self.dir.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("a temp directory");
            }
            std::fs::write(&path, contents).expect("a temp file");
            path
        }

        fn names(&self, outcome: &WalkOutcome) -> Vec<String> {
            let mut names: Vec<String> = outcome
                .files
                .iter()
                .map(|p| {
                    p.strip_prefix(&self.dir)
                        .unwrap_or(p)
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_single_file_is_its_own_target() {
        let tree = Tree::new("single");
        let file = tree.file("a.txt", b"hello");
        let outcome = collect(&[file], &options());
        assert_eq!(tree.names(&outcome), vec!["a.txt"]);
        assert_eq!(outcome.bytes, 5);
    }

    #[test]
    fn a_directory_without_recursion_stops_at_its_own_entries() {
        let tree = Tree::new("flat");
        tree.file("top.txt", b"x");
        tree.file("sub/deep.txt", b"y");
        let outcome = collect(std::slice::from_ref(&tree.dir), &options());
        assert_eq!(tree.names(&outcome), vec!["top.txt"]);
    }

    #[test]
    fn recursion_reaches_every_file() {
        let tree = Tree::new("deep");
        tree.file("top.txt", b"x");
        tree.file("sub/deep.txt", b"y");
        tree.file("sub/sub2/deeper.txt", b"z");
        let mut walk = options();
        walk.recursive = true;
        let outcome = collect(std::slice::from_ref(&tree.dir), &walk);
        assert_eq!(
            tree.names(&outcome),
            vec!["sub/deep.txt", "sub/sub2/deeper.txt", "top.txt"]
        );
    }

    #[test]
    fn an_excluded_path_is_not_collected() {
        let tree = Tree::new("exclude");
        tree.file("keep.txt", b"x");
        tree.file("skip.tmp", b"y");
        tree.file("sub/skip.tmp", b"z");
        let mut walk = options();
        walk.recursive = true;
        walk.exclude = vec!["*.tmp".to_owned()];
        let outcome = collect(std::slice::from_ref(&tree.dir), &walk);
        assert_eq!(tree.names(&outcome), vec!["keep.txt"]);
        assert_eq!(outcome.skipped, 2);
    }

    #[test]
    fn an_excluded_directory_is_not_descended_into() {
        // The filter is applied to directories as well as files, which is what
        // makes `--exclude "**/node_modules"` cost nothing rather than costing
        // a walk of every file in it.
        let tree = Tree::new("exclude-dir");
        tree.file("keep.txt", b"x");
        tree.file("node_modules/a/b.js", b"y");
        let mut walk = options();
        walk.recursive = true;
        walk.exclude = vec!["**/node_modules".to_owned()];
        let outcome = collect(std::slice::from_ref(&tree.dir), &walk);
        assert_eq!(tree.names(&outcome), vec!["keep.txt"]);
    }

    #[test]
    fn a_file_above_the_size_limit_is_skipped_and_counted() {
        let tree = Tree::new("size");
        tree.file("small.txt", b"abcd");
        tree.file("large.txt", &vec![0u8; 4096]);
        let mut walk = options();
        walk.max_file_size = Some(1024);
        let outcome = collect(std::slice::from_ref(&tree.dir), &walk);
        assert_eq!(tree.names(&outcome), vec!["small.txt"]);
        assert_eq!(outcome.skipped, 1);
    }

    #[test]
    fn a_product_directory_is_never_scanned() {
        // The vault and the rule database are the two places where scanning
        // would be actively harmful rather than merely wasteful.
        let tree = Tree::new("protected");
        let rule = tree.file("db/rules.avdb", b"not really a database");
        tree.file("elsewhere/a.txt", b"x");
        let mut walk = options();
        walk.recursive = true;
        walk.protected = Some(AvPaths::with_data_dir(
            tree.dir.join("install"),
            tree.dir.join("db"),
        ));
        let outcome = collect(std::slice::from_ref(&tree.dir), &walk);
        assert!(!outcome.files.contains(&rule), "{:?}", outcome.files);
        assert_eq!(tree.names(&outcome), vec!["elsewhere/a.txt"]);
    }

    #[test]
    fn a_target_that_does_not_exist_is_reported_rather_than_dropped() {
        let missing = std::env::temp_dir().join("wenle-walk-does-not-exist");
        let outcome = collect(&[missing], &options());
        assert!(outcome.files.is_empty());
        assert_eq!(outcome.unreadable.len(), 1);
    }
}
