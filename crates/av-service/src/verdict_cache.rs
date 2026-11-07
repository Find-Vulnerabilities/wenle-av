//! What the gate already knows about a path, so it does not have to ask again.
//!
//! # Why this exists
//!
//! A program launch is many opens of the same images, and the same DLL is
//! opened again by the next launch a minute later. Measured on the host on
//! 2026-11-07 with the driver loaded: `MpOAV.dll` and `ProtonDrive.exe` were
//! asked about repeatedly, each scan of a large image outlived the driver's
//! 3.5 s wait, and the service spent about two cores of CPU doing it. The file
//! had not changed between those questions, and the answer was the same every
//! time.
//!
//! # What is remembered, and what is not
//!
//! **Only a clean result.** Anything the engine convicted is scanned again next
//! time: a conviction is a statement worth re-earning, and the cost of being
//! wrong about a cached conviction is that a file stays refused after it was
//! fixed.
//!
//! The key is the path, its length and its last-write time. A file that is
//! rewritten, replaced or truncated has a different key and is scanned again.
//! A file whose timestamps were forged to avoid a scan is a file that arrives
//! with the same size and timestamp as one that was clean -- which is a
//! deliberate act, and the product's other layers (the behaviour rules, the
//! hash blocklist at every scan that is not a cache hit) are what cover it.
//! This is a performance cache and it is described here as one.
//!
//! # Bounded
//!
//! [`DEFAULT_CAPACITY`] entries, least-recently-used first out. The keys are
//! paths chosen by the machine, and a table that grows with uptime is a leak
//! with a nicer name.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// How many paths are remembered. An installation with more executables than
/// this that are launched in rotation will thrash, which costs a scan and
/// nothing else.
pub const DEFAULT_CAPACITY: usize = 65_536;

/// What a path looked like when it was last found clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    modified: Option<SystemTime>,
}

impl Fingerprint {
    /// The fingerprint of the file at `path`, or `None` when it cannot be read.
    ///
    /// A path this cannot stat is a path nothing should be remembered about:
    /// the next decision will try again, and if the file is gone the scan
    /// reports that rather than the cache reporting a stale clean.
    fn of(path: &Path) -> Option<Fingerprint> {
        let metadata = std::fs::metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        Some(Fingerprint {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

/// Paths found clean, and what they looked like.
#[derive(Debug)]
pub struct VerdictCache {
    entries: HashMap<PathBuf, Fingerprint>,
    /// Least recently used first. A path is moved to the back on every hit.
    order: VecDeque<PathBuf>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

impl VerdictCache {
    /// An empty cache.
    #[must_use]
    pub fn new(capacity: usize) -> VerdictCache {
        VerdictCache {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            hits: 0,
            misses: 0,
        }
    }

    /// Whether this path was found clean and has not changed since.
    ///
    /// Takes `&mut self` because asking is what keeps an entry alive in the LRU
    /// order, and because a miss evicts the stale fingerprint it found.
    pub fn is_known_clean(&mut self, path: &Path) -> bool {
        let Some(held) = self.entries.get(path).copied() else {
            self.misses += 1;
            return false;
        };
        let Some(now) = Fingerprint::of(path) else {
            self.entries.remove(path);
            self.misses += 1;
            return false;
        };
        if now != held {
            self.entries.remove(path);
            self.misses += 1;
            return false;
        }
        if let Some(index) = self.order.iter().position(|entry| entry == path) {
            self.order.remove(index);
        }
        self.order.push_back(path.to_path_buf());
        self.hits += 1;
        true
    }

    /// Remember that `path` was scanned and found clean.
    pub fn remember_clean(&mut self, path: &Path) {
        let Some(fingerprint) = Fingerprint::of(path) else {
            return;
        };
        if self.entries.contains_key(path) {
            if let Some(index) = self.order.iter().position(|entry| entry == path) {
                self.order.remove(index);
            }
        } else {
            while self.entries.len() >= self.capacity {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(path.to_path_buf(), fingerprint);
        self.order.push_back(path.to_path_buf());
    }

    /// How many paths are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Hits and misses since the service started, for the status report.
    #[must_use]
    pub fn counters(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::File::create(path).expect("create");
        file.write_all(bytes).expect("write");
        file.sync_all().expect("sync");
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wenle-cache-{}-{name}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("file.bin")
    }

    #[test]
    fn a_file_found_clean_is_remembered() {
        let path = temp("remember");
        write(&path, b"clean contents");
        let mut cache = VerdictCache::new(8);
        assert!(!cache.is_known_clean(&path));
        cache.remember_clean(&path);
        assert!(cache.is_known_clean(&path));
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn a_file_that_changed_is_scanned_again() {
        let path = temp("changed");
        write(&path, b"one");
        let mut cache = VerdictCache::new(8);
        cache.remember_clean(&path);
        assert!(cache.is_known_clean(&path));
        std::thread::sleep(std::time::Duration::from_millis(20));
        write(&path, b"two, and longer");
        assert!(!cache.is_known_clean(&path), "a rewritten file was still cached");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn a_file_that_is_gone_is_not_remembered() {
        let path = temp("gone");
        write(&path, b"x");
        let mut cache = VerdictCache::new(8);
        cache.remember_clean(&path);
        std::fs::remove_file(&path).expect("remove");
        assert!(!cache.is_known_clean(&path));
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn the_oldest_entry_is_evicted_first() {
        let dir = std::env::temp_dir().join(format!("wenle-cache-evict-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let mut cache = VerdictCache::new(2);
        let first = dir.join("first");
        let second = dir.join("second");
        let third = dir.join("third");
        for path in [&first, &second, &third] {
            write(path, b"x");
        }
        cache.remember_clean(&first);
        cache.remember_clean(&second);
        assert!(cache.is_known_clean(&first));
        cache.remember_clean(&third);
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_known_clean(&second), "the least recently used entry survived");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
