//! The vault's index: every entry, plus the list of originals still waiting to
//! be deleted.
//!
//! # One file, replaced whole
//!
//! The index is a single structure written to a single file with
//! [`crate::fsutil::write_atomic`], not an append-only log and not a directory
//! of per-item metadata. A quarantine list is read far more often than it is
//! written — the GUI polls it, the service consults it before every real-time
//! decision, retention sweeps it hourly — and it is written a handful of times
//! a day. Loading a few thousand entries from one file is microseconds;
//! reconciling a log or stat-ing a directory of metadata files is not.
//!
//! The cost is that a write rewrites the whole index. At the sizes this vault
//! reaches — an entry is a few hundred bytes and a machine that quarantines ten
//! thousand files has a serious problem — that is tens of kilobytes, which is
//! not worth a more complex scheme.
//!
//! # The pending-removal list
//!
//! A file that is open in another process cannot be deleted, and on Windows
//! that is the normal case for exactly the files worth quarantining: something
//! the user just double-clicked is running. The bytes are in the vault either
//! way, so the threat is already neutralized; what is left is a file on disk
//! that will come back to life after the next reboot. This list records the
//! path so a later pass can finish the job, and it survives a restart because
//! the reboot is precisely when the retry is most likely to succeed.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entry::{EntryStatus, QuarantineEntry};
use crate::error::{QuarantineError, Result};
use crate::id::QuarantineId;

/// Index format version. Bumped when the structure changes in a way an older
/// build could not read; an index written by a newer version is refused by name
/// rather than partially parsed.
pub const INDEX_VERSION: u32 = 1;

/// An original file that has been quarantined but not yet deleted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingRemoval {
    /// The file still on disk.
    pub path: PathBuf,
    /// The vault entry holding its bytes.
    pub id: QuarantineId,
    /// How many times deletion has been attempted. Used to stop a file that can
    /// never be deleted — a running system component, a path on a disconnected
    /// network share — from being retried forever.
    pub attempts: u32,
    /// When the first attempt failed.
    pub first_seen: DateTime<Utc>,
    /// Why the last attempt failed, for the log line and the user's benefit.
    pub last_error: Option<String>,
}

impl PendingRemoval {
    /// Record a first failed attempt.
    pub fn new(path: impl Into<PathBuf>, id: QuarantineId, error: String) -> Self {
        Self {
            path: path.into(),
            id,
            attempts: 1,
            first_seen: Utc::now(),
            last_error: Some(error),
        }
    }

    /// Record another failed attempt.
    pub fn retried(&mut self, error: String) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_error = Some(error);
    }
}

/// Every entry in the vault and everything waiting to be deleted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineIndex {
    /// Format version of this structure.
    version: u32,
    /// Every entry, in the order it was added.
    entries: Vec<QuarantineEntry>,
    /// Originals whose deletion is still outstanding.
    pending: Vec<PendingRemoval>,
}

impl Default for QuarantineIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl QuarantineIndex {
    /// An empty index at the current format version.
    pub fn new() -> Self {
        Self {
            version: INDEX_VERSION,
            entries: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// Serialize for sealing and storage.
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| QuarantineError::Serialize {
            what: "the quarantine index",
            detail: e.to_string(),
        })
    }

    /// Parse what [`QuarantineIndex::encode`] wrote.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let index: Self = bincode::deserialize(bytes)
            .map_err(|e| QuarantineError::Index(format!("could not be decoded: {e}")))?;
        if index.version != INDEX_VERSION {
            return Err(QuarantineError::Index(format!(
                "it is format version {} and this build reads version {INDEX_VERSION}",
                index.version
            )));
        }
        Ok(index)
    }

    // -- entries -----------------------------------------------------------

    /// Every entry, oldest first.
    pub fn entries(&self) -> &[QuarantineEntry] {
        &self.entries
    }

    /// Every entry, newest first — the order a quarantine list is shown in.
    pub fn entries_newest_first(&self) -> Vec<&QuarantineEntry> {
        let mut out: Vec<&QuarantineEntry> = self.entries.iter().collect();
        out.sort_by(|a, b| {
            b.quarantined_at
                .cmp(&a.quarantined_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        out
    }

    /// How many entries there are, of any status.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing has ever been quarantined.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look one up.
    pub fn get(&self, id: QuarantineId) -> Option<&QuarantineEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Look one up for modification.
    pub fn get_mut(&mut self, id: QuarantineId) -> Option<&mut QuarantineEntry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    /// Add an entry.
    ///
    /// Returns the previous entry with the same identifier if there was one,
    /// which can only happen if the random source produced a collision or a
    /// caller reused an identifier. Neither is an error worth failing on — the
    /// new entry is the one that describes the file actually taken — but the
    /// caller is told so it can log it.
    pub fn insert(&mut self, entry: QuarantineEntry) -> Option<QuarantineEntry> {
        match self.entries.iter().position(|e| e.id == entry.id) {
            Some(index) => Some(std::mem::replace(&mut self.entries[index], entry)),
            None => {
                self.entries.push(entry);
                None
            }
        }
    }

    /// Entries that still hold vault space.
    pub fn live(&self) -> impl Iterator<Item = &QuarantineEntry> {
        self.entries.iter().filter(|e| e.status.is_live())
    }

    /// Entries in a given state.
    pub fn with_status(&self, status: EntryStatus) -> impl Iterator<Item = &QuarantineEntry> {
        self.entries.iter().filter(move |e| e.status == status)
    }

    /// Total size of the live entries, which is what the vault's size limit
    /// applies to.
    pub fn live_bytes(&self) -> u64 {
        self.live().map(|e| e.size).sum()
    }

    /// Entries whose original path is `path`.
    ///
    /// More than one is possible and not an error: a user can be infected
    /// twice, restore, and be infected again.
    pub fn from_path<'a>(&'a self, path: &'a Path) -> impl Iterator<Item = &'a QuarantineEntry> {
        self.entries.iter().filter(move |e| e.is_from(path))
    }

    /// Take an entry out of the index entirely.
    ///
    /// Only for history pruning. Everywhere else an entry changes status rather
    /// than disappearing, because a file that vanishes from the list with no
    /// trace is indistinguishable from the product having lost it.
    pub fn remove(&mut self, id: QuarantineId) -> Option<QuarantineEntry> {
        let position = self.entries.iter().position(|e| e.id == id)?;
        Some(self.entries.remove(position))
    }

    /// Drop every entry for which `keep` returns false, and report how many
    /// went. Used by retention.
    pub fn retain(&mut self, mut keep: impl FnMut(&QuarantineEntry) -> bool) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| keep(e));
        before - self.entries.len()
    }

    // -- pending removals --------------------------------------------------

    /// Originals still on disk.
    pub fn pending(&self) -> &[PendingRemoval] {
        &self.pending
    }

    /// True when this path is already queued, so that a second quarantine of
    /// the same file does not queue it twice.
    pub fn is_pending(&self, path: &Path) -> bool {
        let wanted = path.to_string_lossy().to_lowercase();
        self.pending
            .iter()
            .any(|p| p.path.to_string_lossy().to_lowercase() == wanted)
    }

    /// Record a failed deletion. Replaces an existing record for the same path
    /// rather than adding a second one.
    pub fn queue_removal(&mut self, path: impl Into<PathBuf>, id: QuarantineId, error: String) {
        let path = path.into();
        let wanted = path.to_string_lossy().to_lowercase();
        match self
            .pending
            .iter_mut()
            .find(|p| p.path.to_string_lossy().to_lowercase() == wanted)
        {
            Some(existing) => {
                existing.id = id;
                existing.retried(error);
            }
            None => self.pending.push(PendingRemoval::new(path, id, error)),
        }
    }

    /// Stop tracking a path, because it is gone or because the caller gave up.
    pub fn clear_removal(&mut self, path: &Path) -> Option<PendingRemoval> {
        let wanted = path.to_string_lossy().to_lowercase();
        let position = self
            .pending
            .iter()
            .position(|p| p.path.to_string_lossy().to_lowercase() == wanted)?;
        Some(self.pending.remove(position))
    }

    /// Mark an entry's original as confirmed gone.
    pub fn mark_original_removed(&mut self, id: QuarantineId) {
        if let Some(entry) = self.get_mut(id) {
            entry.original_removed = true;
        }
    }

    /// How many originals are still on disk.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::QuarantineContext;
    use av_core::{Digests, Severity, Verdict};

    fn id(n: u8) -> QuarantineId {
        QuarantineId::from_bytes([n; 16])
    }

    fn entry(n: u8, path: &str, size: u64) -> QuarantineEntry {
        let mut e = QuarantineEntry::new(
            id(n),
            path,
            size,
            Digests::default(),
            &QuarantineContext {
                severity: Severity::High,
                verdict: Verdict::Malicious,
                ..QuarantineContext::default()
            },
        );
        // Spread the timestamps so ordering is deterministic in tests.
        e.quarantined_at = DateTime::from_timestamp(i64::from(n), 0).unwrap_or_default();
        e
    }

    #[test]
    fn an_empty_index_round_trips() {
        let index = QuarantineIndex::new();
        let bytes = index.encode().unwrap();
        assert_eq!(QuarantineIndex::decode(&bytes).unwrap(), index);
    }

    #[test]
    fn a_populated_index_round_trips() {
        let mut index = QuarantineIndex::new();
        index.insert(entry(1, r"C:\a.exe", 100));
        index.insert(entry(2, r"C:\b.exe", 200));
        index.queue_removal(r"C:\a.exe", id(1), "in use".into());

        let bytes = index.encode().unwrap();
        let back = QuarantineIndex::decode(&bytes).unwrap();
        assert_eq!(back, index);
        assert_eq!(back.entries().len(), 2);
        assert_eq!(back.pending().len(), 1);
    }

    #[test]
    fn inserting_the_same_id_twice_replaces_and_reports() {
        let mut index = QuarantineIndex::new();
        assert!(index.insert(entry(1, r"C:\a.exe", 100)).is_none());
        let replaced = index.insert(entry(1, r"C:\a.exe", 999));
        assert!(replaced.is_some());
        assert_eq!(index.len(), 1);
        assert_eq!(index.get(id(1)).unwrap().size, 999);
    }

    #[test]
    fn the_newest_entry_comes_first() {
        let mut index = QuarantineIndex::new();
        index.insert(entry(1, r"C:\old.exe", 1));
        index.insert(entry(3, r"C:\new.exe", 1));
        index.insert(entry(2, r"C:\middle.exe", 1));
        let order: Vec<u8> = index
            .entries_newest_first()
            .iter()
            .map(|e| e.id.as_bytes()[0])
            .collect();
        assert_eq!(order, vec![3, 2, 1]);
    }

    #[test]
    fn only_live_entries_count_towards_the_vault_size() {
        let mut index = QuarantineIndex::new();
        index.insert(entry(1, r"C:\a.exe", 100));
        index.insert(entry(2, r"C:\b.exe", 200));
        assert_eq!(index.live_bytes(), 300);
        index.get_mut(id(2)).unwrap().status = EntryStatus::Deleted;
        assert_eq!(index.live_bytes(), 100);
        assert_eq!(index.live().count(), 1);
        assert_eq!(index.with_status(EntryStatus::Deleted).count(), 1);
    }

    #[test]
    fn an_entry_is_found_by_the_path_it_came_from() {
        let mut index = QuarantineIndex::new();
        index.insert(entry(1, r"C:\Users\Me\bad.exe", 1));
        let found: Vec<QuarantineId> = index
            .from_path(Path::new(r"c:\users\me\BAD.exe"))
            .map(|e| e.id)
            .collect();
        assert_eq!(found, vec![id(1)]);
        assert_eq!(index.from_path(Path::new(r"C:\other.exe")).count(), 0);
    }

    #[test]
    fn a_failed_removal_is_recorded_once_and_counts_retries() {
        let mut index = QuarantineIndex::new();
        index.queue_removal(r"C:\a.exe", id(1), "in use".into());
        assert!(index.is_pending(Path::new(r"c:\A.EXE")));
        assert_eq!(index.pending_len(), 1);
        assert_eq!(index.pending()[0].attempts, 1);

        index.queue_removal(r"C:\A.EXE", id(1), "still in use".into());
        assert_eq!(index.pending_len(), 1, "a second record was added");
        assert_eq!(index.pending()[0].attempts, 2);
        assert_eq!(
            index.pending()[0].last_error.as_deref(),
            Some("still in use")
        );
    }

    #[test]
    fn clearing_a_removal_forgets_it() {
        let mut index = QuarantineIndex::new();
        index.queue_removal(r"C:\a.exe", id(1), "in use".into());
        assert!(index.clear_removal(Path::new(r"C:\A.EXE")).is_some());
        assert_eq!(index.pending_len(), 0);
        assert!(index.clear_removal(Path::new(r"C:\a.exe")).is_none());
    }

    #[test]
    fn marking_the_original_gone_updates_the_entry() {
        let mut index = QuarantineIndex::new();
        index.insert(entry(1, r"C:\a.exe", 1));
        assert!(!index.get(id(1)).unwrap().original_removed);
        index.mark_original_removed(id(1));
        assert!(index.get(id(1)).unwrap().original_removed);
        // An unknown identifier is a no-op, not a panic.
        index.mark_original_removed(id(9));
    }

    #[test]
    fn retention_reports_how_many_it_dropped() {
        let mut index = QuarantineIndex::new();
        for n in 1..=5 {
            index.insert(entry(n, &format!(r"C:\f{n}.exe"), 1));
        }
        let dropped = index.retain(|e| e.id.as_bytes()[0] <= 3);
        assert_eq!(dropped, 2);
        assert_eq!(index.len(), 3);
    }

    #[test]
    fn an_entry_can_be_taken_out_by_id() {
        let mut index = QuarantineIndex::new();
        index.insert(entry(1, r"C:\a.exe", 1));
        assert!(index.remove(id(1)).is_some());
        assert!(index.remove(id(1)).is_none());
        assert!(index.is_empty());
    }

    #[test]
    fn an_index_from_a_future_version_is_refused_by_name() {
        let mut index = QuarantineIndex::new();
        index.version = INDEX_VERSION + 1;
        let bytes = bincode::serialize(&index).unwrap();
        let err = QuarantineIndex::decode(&bytes).unwrap_err().to_string();
        assert!(err.contains("format version"), "{err}");
    }

    #[test]
    fn rubbish_bytes_are_refused_rather_than_panicking() {
        for bytes in [
            &b""[..],
            &b"\xff\xff\xff\xff"[..],
            &b"not an index at all"[..],
        ] {
            assert!(QuarantineIndex::decode(bytes).is_err());
        }
    }

    #[test]
    fn decoding_a_truncated_index_is_an_error_and_not_a_panic() {
        let mut index = QuarantineIndex::new();
        for n in 1..=4 {
            index.insert(entry(n, &format!(r"C:\f{n}.exe"), 10));
        }
        let bytes = index.encode().unwrap();
        for cut in [1usize, 8, bytes.len() / 2, bytes.len() - 1] {
            assert!(QuarantineIndex::decode(&bytes[..cut]).is_err(), "cut {cut}");
        }
    }
}
