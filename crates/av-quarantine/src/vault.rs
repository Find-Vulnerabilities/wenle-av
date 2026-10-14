//! The vault itself: the operations, in the order they must happen.
//!
//! # The one invariant
//!
//! **A file is never deleted before its bytes are sealed and on disk.**
//!
//! Everything else in this module is bookkeeping around that sentence. It is
//! what makes quarantine recoverable from a power loss at any instant: at every
//! point there is either the original file, or a sealed copy of it, or both.
//! The state that is not reachable is "neither", and that is the only state that
//! loses a user's file.
//!
//! The order a quarantine follows, and why:
//!
//! 1. Read the bytes and refuse if the file is too large. Nothing has been
//!    written yet, so a refusal is free.
//! 2. Seal them, and write the blob under a name derived from a fresh random
//!    identifier. Sealing before writing means a blob on disk is never a
//!    partially sealed one.
//! 3. Insert the entry into the index and **save the index**. The record is now
//!    durable and the original is still on disk — the state with both copies.
//! 4. Delete the original. If that fails the bytes are already safe, so the
//!    failure costs a stale file and not a lost one.
//! 5. Save the index again if step 4 changed anything.
//!
//! A crash between 3 and 4 leaves an entry marked `original_removed: false` for
//! a file that still exists — accurate. A crash between 4 and 5 leaves an entry
//! claiming the original is still there when it is not — stale, and harmless,
//! because a later sweep that finds the file gone treats that as success.
//!
//! # Restore is the direction that matters
//!
//! Writing a file *into* the filesystem based on a path stored in the vault is
//! the most dangerous thing this crate does. A false positive on a system file
//! is the expensive failure of an antivirus, and the restore path is the only
//! way a user gets out of one. So a restore validates its destination, verifies
//! the payload's digest before writing a byte, and never overwrites anything
//! without being told to.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use zeroize::Zeroize;

use av_core::{Digests, HashKind};

use crate::attributes;
use crate::crypto::{self, aad};
use crate::entry::{EntryStatus, QuarantineContext, QuarantineEntry};
use crate::error::{QuarantineError, Result};
use crate::events::{Listeners, QuarantineEvent, QuarantineListener};
use crate::fsutil;
use crate::hardening::Hardening;
use crate::id::QuarantineId;
use crate::index::{PendingRemoval, QuarantineIndex};
use crate::key::MasterKey;
use crate::policy::QuarantinePolicy;

/// Subdirectory holding the sealed payloads.
const ITEMS_DIR: &str = "items";
/// File holding the sealed index.
const INDEX_FILE: &str = "index.enc";
/// File holding the wrapped master key.
const KEY_FILE: &str = "master.key";
/// Extension of a sealed payload.
const BLOB_EXTENSION: &str = "qtn";

/// How an item is put back.
///
/// The default is the safe combination: the path it came from, no replacement,
/// and the sealed copy consumed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreOptions {
    /// Where to write it. `None` means the path it was taken from.
    pub target: Option<PathBuf>,
    /// Replace a file that is already at the destination.
    pub overwrite: bool,
    /// Keep the sealed copy in the vault after restoring, so the item can be
    /// taken again without a rescan.
    pub keep_copy: bool,
}

impl RestoreOptions {
    /// Put it back where it came from.
    pub fn to_original() -> Self {
        Self::default()
    }

    /// Put it somewhere else.
    pub fn to(path: impl Into<PathBuf>) -> Self {
        Self {
            target: Some(path.into()),
            ..Self::default()
        }
    }

    /// Replace whatever is at the destination.
    pub fn overwriting(mut self) -> Self {
        self.overwrite = true;
        self
    }

    /// Leave the sealed copy in the vault.
    pub fn keeping_copy(mut self) -> Self {
        self.keep_copy = true;
        self
    }
}

/// What a size or retention sweep removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Eviction {
    /// The items that went.
    pub removed: Vec<QuarantineId>,
    /// How many bytes that freed.
    pub freed_bytes: u64,
}

impl Eviction {
    /// How many items went.
    pub fn count(&self) -> usize {
        self.removed.len()
    }

    /// True when nothing needed removing.
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty()
    }
}

/// What a sweep of the pending-removal list did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemovalSweep {
    /// Originals that are now gone.
    pub removed: usize,
    /// Originals that failed again and are still queued.
    pub deferred: usize,
    /// Originals that were given up on after too many attempts.
    pub abandoned: usize,
}

/// A count of what is in the vault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultStats {
    /// Every entry, of any status.
    pub total: usize,
    /// Entries whose bytes are still held.
    pub quarantined: usize,
    /// Entries that were written back.
    pub restored: usize,
    /// Entries the user destroyed.
    pub deleted: usize,
    /// Bytes held by live entries.
    pub live_bytes: u64,
    /// Originals still on disk.
    pub pending_removals: usize,
    /// Sealed payloads in the vault directory that no entry refers to.
    pub orphans: usize,
    /// When the oldest item was taken.
    pub oldest: Option<DateTime<Utc>>,
    /// When the newest was.
    pub newest: Option<DateTime<Utc>>,
}

/// What another writer did to a vault, as seen by [`QuarantineVault::reconcile`].
///
/// Three lists rather than a count, because the three are acted on differently:
/// an addition is a file that was taken and a user may need telling, a change is
/// an entry whose state moved — a deferred removal that completed, most often —
/// and a removal is a row a list should stop showing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reconciliation {
    /// Entries that were not in this process's index and are on disk now.
    pub added: Vec<QuarantineEntry>,
    /// Entries that are in both, with a different record.
    pub changed: Vec<QuarantineEntry>,
    /// Identifiers this process had that the index no longer names.
    pub removed: Vec<QuarantineId>,
}

impl Reconciliation {
    /// Whether anything moved at all.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.removed.is_empty()
    }

    /// How many entries moved, counting each once.
    pub fn len(&self) -> usize {
        self.added.len() + self.changed.len() + self.removed.len()
    }
}

/// The quarantine vault.
///
/// One instance owns the directory it was opened on. Nothing here is
/// synchronised: the service wraps it in a lock, because every operation
/// mutates the index and two threads rewriting one index file is how a
/// quarantine list loses entries.
#[derive(Debug)]
pub struct QuarantineVault {
    root: PathBuf,
    items_dir: PathBuf,
    index_path: PathBuf,
    key: MasterKey,
    index: QuarantineIndex,
    policy: QuarantinePolicy,
    listeners: Listeners,
    /// What the operating system was persuaded to do about the directory's
    /// permissions. Kept because it is a fact about this vault a user may need
    /// told: the vault whose permissions could not be restricted contains
    /// exactly the same encrypted payloads as one whose could, and the
    /// difference is invisible from the outside.
    hardening: Hardening,
}

impl QuarantineVault {
    /// Open the vault at `root`, creating it if it is not there.
    ///
    /// Fails if an existing index cannot be read. That is the honest outcome —
    /// a vault whose index does not decode has lost the mapping from
    /// identifiers to files, and quietly starting from an empty one would leave
    /// the sealed payloads behind with nothing to explain them. Use
    /// [`QuarantineVault::open_recovering`] when the priority is to keep
    /// quarantining rather than to keep the history.
    pub fn open(root: impl Into<PathBuf>, policy: QuarantinePolicy) -> Result<Self> {
        let root = root.into();
        let items_dir = root.join(ITEMS_DIR);
        std::fs::create_dir_all(&items_dir)
            .map_err(|e| QuarantineError::io("create", &items_dir, e))?;

        // Before anything is written into the directory, so that the key, the
        // index and every payload are created under the restricted permissions
        // rather than granted them afterwards — and so that a vault left by an
        // earlier version, whose key and payloads were made under the inherited
        // ones, has them propagated over by this call.
        //
        // It cannot fail the open: see [`crate::hardening`] for why a vault with
        // looser permissions is still a vault that should open.
        let hardening = crate::hardening::restrict(&root);

        // The key is loaded before the index, because opening the index needs
        // it. Creating the key first also means the vault directory is never
        // left holding a sealed index whose key was never written.
        let key = MasterKey::load_or_create(&root.join(KEY_FILE))?;
        let index_path = root.join(INDEX_FILE);
        let index = Self::load_index(&key, &index_path)?;

        log::debug!(
            "opened the quarantine vault at {}: {} entries, {} bytes held",
            root.display(),
            index.len(),
            index.live_bytes()
        );

        Ok(Self {
            root,
            items_dir,
            index_path,
            key,
            index,
            policy,
            listeners: Listeners::default(),
            hardening,
        })
    }

    /// Open the vault, moving a damaged index aside rather than refusing.
    ///
    /// The damaged file is kept, renamed with a timestamp, because it is the
    /// only record of what the orphaned payloads were and somebody may need to
    /// recover it by hand. This is the mode the service uses: a product that
    /// stops protecting the machine because its own bookkeeping is damaged has
    /// its priorities backwards.
    pub fn open_recovering(root: impl Into<PathBuf>, policy: QuarantinePolicy) -> Result<Self> {
        let root = root.into();
        match Self::open(root.clone(), policy.clone()) {
            Ok(vault) => Ok(vault),
            Err(e) if e.is_corruption() => {
                let index_path = root.join(INDEX_FILE);
                let aside = root.join(format!(
                    "index.corrupt-{}.enc",
                    Utc::now().format("%Y%m%dT%H%M%SZ")
                ));
                match std::fs::rename(&index_path, &aside) {
                    Ok(()) => log::error!(
                        "the quarantine index at {} could not be read ({e}); it has been moved to \
                         {} and a new one started. Any payload in {} is now an orphan and can only \
                         be recovered by hand.",
                        index_path.display(),
                        aside.display(),
                        root.join(ITEMS_DIR).display()
                    ),
                    Err(rename_error) => {
                        return Err(QuarantineError::io(
                            "move the damaged index aside",
                            &index_path,
                            rename_error,
                        ))
                    }
                }
                Self::open(root, policy)
            }
            Err(e) => Err(e),
        }
    }

    fn load_index(key: &MasterKey, path: &Path) -> Result<QuarantineIndex> {
        match fsutil::read_optional(path)? {
            Some(stored) => {
                let plain = crypto::open(key, aad::INDEX, &stored)?;
                QuarantineIndex::decode(&plain)
            }
            None => Ok(QuarantineIndex::new()),
        }
    }

    fn save_index(&mut self) -> Result<()> {
        let plain = self.index.encode()?;
        let sealed = crypto::seal(&self.key, true, aad::INDEX, &plain)?;
        fsutil::write_atomic(&self.index_path, &sealed)
    }

    // -- accessors ---------------------------------------------------------

    /// The directory the vault lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory the sealed payloads live in.
    pub fn items_dir(&self) -> &Path {
        &self.items_dir
    }

    /// The sealed index file, which is what another writer rewrites and what a
    /// caller watching for that rewrite has to stat.
    ///
    /// Exposed because a front end has to be able to tell whether the file moved
    /// *without* opening the vault: opening one applies the directory's
    /// permissions and loads the key, which is not something to do once a
    /// second. See `av_gui::vault_poll`.
    pub fn index_path(&self) -> &Path {
        &self.index_path
    }

    /// The policy in force.
    pub fn policy(&self) -> &QuarantinePolicy {
        &self.policy
    }

    /// What the operating system did about this vault's permissions.
    ///
    /// Read by a front end that wants to tell a user how well protected their
    /// quarantined files are, and by the log. The answer is not a constant: it
    /// depends on which account created the directory, and on whether that
    /// account was allowed to set a DACL at all.
    pub fn hardening(&self) -> &Hardening {
        &self.hardening
    }

    /// Replace the policy. Takes effect on the next operation; nothing already
    /// stored is re-examined, which is why this does not itself evict.
    pub fn set_policy(&mut self, policy: QuarantinePolicy) {
        self.policy = policy;
    }

    /// Subscribe to vault events.
    ///
    /// See [`crate::events`] for why listeners run inline and must be quick.
    pub fn subscribe(&mut self, listener: QuarantineListener) {
        self.listeners.push(listener);
    }

    /// How many subscribers are attached.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Every entry, oldest first.
    pub fn entries(&self) -> &[QuarantineEntry] {
        self.index.entries()
    }

    /// Every entry, newest first, which is the order a list is shown in.
    pub fn list(&self) -> Vec<&QuarantineEntry> {
        self.index.entries_newest_first()
    }

    /// One entry, or an error naming the identifier.
    pub fn get(&self, id: QuarantineId) -> Result<&QuarantineEntry> {
        self.index.get(id).ok_or(QuarantineError::NotFound(id))
    }

    /// Originals still on disk.
    pub fn pending_removals(&self) -> &[PendingRemoval] {
        self.index.pending()
    }

    /// A count of everything in the vault.
    pub fn stats(&self) -> VaultStats {
        let mut stats = VaultStats {
            total: self.index.len(),
            live_bytes: self.index.live_bytes(),
            pending_removals: self.index.pending_len(),
            ..VaultStats::default()
        };
        for entry in self.index.entries() {
            match entry.status {
                EntryStatus::Quarantined => stats.quarantined += 1,
                EntryStatus::Restored => stats.restored += 1,
                EntryStatus::Deleted => stats.deleted += 1,
            }
            let when = entry.quarantined_at;
            stats.oldest = Some(stats.oldest.map_or(when, |o| o.min(when)));
            stats.newest = Some(stats.newest.map_or(when, |n| n.max(when)));
        }
        stats.orphans = self.orphans().len();
        stats
    }

    /// Sealed payloads that no entry refers to.
    ///
    /// Non-empty after an index was rebuilt, or after a crash between writing a
    /// blob and saving the index. They are reported rather than deleted on
    /// sight: the bytes might be the only copy of something a user needs, and
    /// a product that silently tidies away a payload it cannot name is not one
    /// to trust with a false positive.
    pub fn orphans(&self) -> Vec<PathBuf> {
        let known: std::collections::HashSet<QuarantineId> =
            self.index.entries().iter().map(|e| e.id).collect();
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.items_dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(BLOB_EXTENSION) {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            match QuarantineId::parse(stem) {
                Some(id) if known.contains(&id) => {}
                _ => out.push(path),
            }
        }
        out.sort();
        out
    }

    // -- reading it back from another writer --------------------------------

    /// Re-read the index from disk and adopt whatever another writer put there.
    ///
    /// # The problem this exists for
    ///
    /// The vault is one directory and one index file, and more than one process
    /// opens it: the service quarantines what realtime protection catches while
    /// the window holds its own vault over the same files, showing the same list.
    /// Each keeps the index in memory and rewrites the whole file on every
    /// change, so the copy in the process that is not writing is as old as its
    /// last read — and a window that never re-reads shows a list missing
    /// everything the service took since it opened, with nothing on screen to
    /// say so.
    ///
    /// This is the re-read. It replaces the in-memory index with what is on disk
    /// and reports what moved, which is what lets a front end announce a
    /// quarantine it did not perform.
    ///
    /// # Three decisions
    ///
    /// **A file that is not there is not an empty vault.** An index that cannot
    /// be read at all leaves the in-memory index alone and reports nothing.
    /// Adopting an empty index because the file blinked would drop every entry
    /// this process knows about, and the next write would make that permanent —
    /// the one direction this must never fail in.
    ///
    /// **A file that does not decode is an error, not an empty vault.** The same
    /// reasoning, and the same answer [`QuarantineVault::open`] gives.
    ///
    /// **No listener is called.** A reconciliation is not something that happened
    /// *here*: the quarantine it reveals happened in another process, and a
    /// listener that fired for it would announce the vault's whole contents the
    /// first time a front end re-read it. What moved is the return value, and it
    /// is the caller's to announce.
    ///
    /// # What this cannot tell you
    ///
    /// It cannot see a write that was *lost*. If two processes write the index at
    /// the same moment, the later write is built on the earlier one's entry only
    /// if it happened to have re-read first; otherwise it erases that entry, and
    /// the payload it named becomes an orphan. Nothing in the file records which
    /// of two indexes is newer, so this method adopts what it finds and cannot
    /// warn about it — and the entry it drops is reported as `removed`, which is
    /// the honest word for "absent from the index" and not a claim about who
    /// removed it. [`QuarantineVault::orphans`] is where the consequence shows
    /// up, and it reports rather than deletes, so nothing is destroyed by it.
    /// Serialising the writers is the fix and there is no lock.
    pub fn reconcile(&mut self) -> Result<Reconciliation> {
        let Some(stored) = fsutil::read_optional(&self.index_path)? else {
            log::debug!(
                "the index at {} is not there; the {} entries in memory are left alone",
                self.index_path.display(),
                self.index.len()
            );
            return Ok(Reconciliation::default());
        };
        let plain = crypto::open(&self.key, aad::INDEX, &stored)?;
        let fresh = QuarantineIndex::decode(&plain)?;

        let mut out = Reconciliation::default();
        for entry in fresh.entries() {
            match self.index.get(entry.id) {
                // Compared rather than assumed equal: a deferred removal that
                // completed in the other process changes an entry without
                // adding one, and a list that showed the old record would keep
                // offering to delete an original that is already gone.
                Some(known) if known == entry => {}
                Some(_) => out.changed.push(entry.clone()),
                None => out.added.push(entry.clone()),
            }
        }
        for entry in self.index.entries() {
            if fresh.get(entry.id).is_none() {
                out.removed.push(entry.id);
            }
        }

        // Adopted wholesale, which is the whole point: one file, one truth, and
        // the file is it. A merge would leave memory and disk disagreeing about
        // what the vault holds, and every later write would carry the
        // disagreement forward.
        if !out.is_empty() {
            log::debug!(
                "reconciled the vault at {}: {} added, {} changed, {} removed",
                self.root.display(),
                out.added.len(),
                out.changed.len(),
                out.removed.len()
            );
        }
        self.index = fresh;
        Ok(out)
    }

    // -- quarantining ------------------------------------------------------

    /// Take a file from disk into the vault.
    ///
    /// The original is deleted unless the context says otherwise; see the
    /// module documentation for the order this happens in and why.
    pub fn quarantine_file(
        &mut self,
        path: &Path,
        context: &QuarantineContext,
    ) -> Result<QuarantineEntry> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| QuarantineError::io("read the size of", path, e))?;
        if !metadata.is_file() {
            return Err(QuarantineError::Other(format!(
                "{} is not a regular file and cannot be quarantined",
                path.display()
            )));
        }
        let size = metadata.len();
        if !self.policy.accepts_size(size) {
            return Err(QuarantineError::TooLarge {
                size,
                limit: self.policy.max_item_size,
            });
        }

        let mut bytes = std::fs::read(path).map_err(|e| QuarantineError::io("read", path, e))?;
        // The read is wrapped so that the plaintext is cleared from this
        // process's heap whether the store succeeds or fails. The bytes exist
        // in cleartext in memory either way; the point is not to leave a second
        // copy lying in freed memory for the rest of the session.
        let outcome = self.store(path, &bytes, context);
        bytes.zeroize();
        outcome
    }

    /// Take bytes that are already in memory into the vault.
    ///
    /// Used for content that has no file of its own yet: a payload carved out
    /// of a running process, a script delivered inside a document, a sample the
    /// sandbox produced. `original` is still recorded, because it is what the
    /// user will recognise in the list.
    pub fn quarantine_bytes(
        &mut self,
        original: &Path,
        bytes: &[u8],
        context: &QuarantineContext,
    ) -> Result<QuarantineEntry> {
        if !self.policy.accepts_size(bytes.len() as u64) {
            return Err(QuarantineError::TooLarge {
                size: bytes.len() as u64,
                limit: self.policy.max_item_size,
            });
        }
        self.store(original, bytes, context)
    }

    /// The shared body of every quarantine. See the module documentation.
    fn store(
        &mut self,
        original: &Path,
        bytes: &[u8],
        context: &QuarantineContext,
    ) -> Result<QuarantineEntry> {
        let digests = Digests {
            md5: Some(HashKind::Md5.digest(bytes)),
            sha1: Some(HashKind::Sha1.digest(bytes)),
            sha256: Some(HashKind::Sha256.digest(bytes)),
        };

        let id = QuarantineId::new();
        let entry = QuarantineEntry::new(id, original, bytes.len() as u64, digests, context);

        // Steps 2 and 3: seal, then write the blob. The blob is in place before
        // anything can refer to it, so the index never names a file that is not
        // there.
        let sealed = crypto::seal(&self.key, self.policy.encrypt, &aad::item(id), bytes)?;
        let blob = self.blob_path(id);
        fsutil::write_atomic(&blob, &sealed)?;

        let mut entry = entry;
        if self.index.insert(entry.clone()).is_some() {
            // Only reachable if the random source repeated, which it will not.
            // Logged rather than ignored, because the alternative explanation
            // is a caller reusing an identifier and that would be a bug.
            log::warn!("quarantine identifier {id} was already in the index and has been replaced");
        }
        // The record is durable and the original still exists: the state with
        // both copies.
        self.save_index()?;

        let mut deferred: Option<String> = None;
        // Only a path that is actually a file is worth deleting. `original` is
        // whatever the caller said this content came from, and for bytes carved
        // out of a running process that is a synthesised path that has never
        // existed — asking for its removal would have `remove_original` report
        // success on the strength of it not being there, and the entry would
        // claim an original was deleted when there was never one to delete.
        if context.remove_original && original.is_file() {
            match remove_original(original) {
                Ok(()) => {
                    entry.original_removed = true;
                    self.index.mark_original_removed(id);
                }
                Err(e) => {
                    let message = e.to_string();
                    log::warn!(
                        "quarantined {} but could not delete it yet: {message}",
                        original.display()
                    );
                    self.index.queue_removal(original, id, message.clone());
                    deferred = Some(message);
                }
            }
            self.save_index()?;
        }

        // Re-read rather than reasoning about the copy held here: the removal
        // step above may have updated the entry, and returning a record that
        // disagrees with the index is exactly the kind of drift that shows up
        // later as a quarantine list that does not match the disk.
        let stored = self
            .index
            .get(id)
            .cloned()
            .ok_or(QuarantineError::NotFound(id))?;

        self.listeners
            .emit(&QuarantineEvent::Quarantined(Box::new(stored.clone())));
        if let Some(error) = deferred {
            self.listeners.emit(&QuarantineEvent::RemovalDeferred {
                path: original.to_path_buf(),
                id,
                error,
            });
        }
        Ok(stored)
    }

    // -- reading back ------------------------------------------------------

    /// The path a payload is stored at.
    fn blob_path(&self, id: QuarantineId) -> PathBuf {
        self.items_dir.join(id.blob_name())
    }

    /// Open a payload.
    fn read_payload(&self, id: QuarantineId) -> Result<Vec<u8>> {
        let path = self.blob_path(id);
        let stored = fsutil::read_optional(&path)?.ok_or_else(|| {
            QuarantineError::Other(format!(
                "the sealed payload for {id} is missing from {}",
                path.display()
            ))
        })?;
        crypto::open(&self.key, &aad::item(id), &stored)
    }

    /// Check that a payload still hashes to what was recorded when it was
    /// taken.
    ///
    /// SHA-256, falling back to MD5 only for entries old enough to predate the
    /// field being filled in. A missing digest on both is not a pass and not a
    /// failure: there is nothing to compare, which is reported as such.
    fn check_digest(&self, entry: &QuarantineEntry, bytes: &[u8]) -> Result<()> {
        let (kind, expected) = match (&entry.digests.sha256, &entry.digests.md5) {
            (Some(expected), _) => (HashKind::Sha256, expected),
            (None, Some(expected)) => (HashKind::Md5, expected),
            (None, None) => {
                return Err(QuarantineError::Verify {
                    id: entry.id,
                    detail: "no digest was recorded, so the payload cannot be checked".into(),
                })
            }
        };
        let actual = kind.digest(bytes);
        if actual.eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            Err(QuarantineError::Verify {
                id: entry.id,
                detail: format!(
                    "the {} of the stored bytes is {actual}, and {} was recorded when it was \
                     quarantined",
                    kind.as_str(),
                    expected
                ),
            })
        }
    }

    /// Verify one item end to end: it opens, and it hashes to what was
    /// recorded.
    pub fn verify(&self, id: QuarantineId) -> Result<()> {
        let entry = self.get(id)?;
        let bytes = self.read_payload(id)?;
        self.check_digest(entry, &bytes)
    }

    /// Verify every live item, returning the ones that failed.
    ///
    /// Returns failures rather than stopping at the first, because the useful
    /// answer to "is my vault intact" is the list, not the first problem.
    pub fn verify_all(&self) -> Vec<(QuarantineId, QuarantineError)> {
        let mut failures = Vec::new();
        for entry in self.index.live() {
            let outcome = self
                .read_payload(entry.id)
                .and_then(|bytes| self.check_digest(entry, &bytes));
            if let Err(e) = outcome {
                log::error!("quarantine integrity check failed for {}: {e}", entry.id);
                failures.push((entry.id, e));
            }
        }
        failures
    }

    /// Write a copy of a quarantined payload to `destination`.
    ///
    /// This hands live malware back to whoever asked for it, which is why it is
    /// a separate, explicitly named operation rather than a flag on `restore`:
    /// its purposes are submitting a sample to a lab and examining one by hand,
    /// and both should look deliberate in a call site.
    pub fn export(&self, id: QuarantineId, destination: &Path, overwrite: bool) -> Result<()> {
        let entry = self.get(id)?;
        let bytes = self.read_payload(id)?;
        self.check_digest(entry, &bytes)?;
        write_destination(destination, &bytes, overwrite)
    }

    // -- restore and delete ------------------------------------------------

    /// Put an item back on disk.
    pub fn restore(&mut self, id: QuarantineId, options: &RestoreOptions) -> Result<PathBuf> {
        let entry = self.get(id).cloned()?;
        if !entry.status.is_live() {
            return Err(QuarantineError::WrongState {
                id,
                status: entry.status.as_str(),
                action: "restore",
            });
        }

        let target = options
            .target
            .clone()
            .unwrap_or_else(|| entry.original_path.clone());
        validate_destination(&target, &self.root).map_err(|reason| {
            QuarantineError::UnsafeRestore {
                id,
                path: target.clone(),
                reason,
            }
        })?;

        let bytes = self.read_payload(id)?;
        if self.policy.verify_on_restore {
            self.check_digest(&entry, &bytes)?;
        }
        write_destination(&target, &bytes, options.overwrite)?;

        if !options.keep_copy {
            self.remove_blob(id);
        }
        let changed = self
            .index
            .get_mut(id)
            .ok_or(QuarantineError::NotFound(id))?;
        changed.status = EntryStatus::Restored;
        changed.changed_at = Utc::now();
        self.save_index()?;

        let entry = self.get(id)?.clone();
        self.listeners.emit(&QuarantineEvent::Restored {
            entry: Box::new(entry),
            path: target.clone(),
        });
        Ok(target)
    }

    /// Destroy an item's payload, keeping the record of what it was.
    pub fn delete(&mut self, id: QuarantineId) -> Result<QuarantineEntry> {
        let entry = self.get(id).cloned()?;
        if entry.status == EntryStatus::Deleted {
            return Err(QuarantineError::WrongState {
                id,
                status: entry.status.as_str(),
                action: "delete",
            });
        }
        self.remove_blob(id);
        let changed = self
            .index
            .get_mut(id)
            .ok_or(QuarantineError::NotFound(id))?;
        changed.status = EntryStatus::Deleted;
        changed.changed_at = Utc::now();
        self.save_index()?;

        let entry = self.get(id)?.clone();
        self.listeners
            .emit(&QuarantineEvent::Deleted(Box::new(entry.clone())));
        Ok(entry)
    }

    /// Delete a payload file, reporting but not failing on a missing one.
    fn remove_blob(&self, id: QuarantineId) {
        let path = self.blob_path(id);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => log::warn!(
                "could not delete the sealed payload {}: {e}",
                path.display()
            ),
        }
    }

    // -- maintenance -------------------------------------------------------

    /// Remove live items older than the policy's retention.
    pub fn purge_expired(&mut self) -> Result<usize> {
        let Some(retention) = self.policy.retention else {
            return Ok(0);
        };
        let Ok(retention) = chrono::Duration::from_std(retention) else {
            return Ok(0);
        };
        let cutoff = Utc::now() - retention;

        let expired: Vec<QuarantineId> = self
            .index
            .live()
            .filter(|e| e.quarantined_at < cutoff)
            .map(|e| e.id)
            .collect();
        if expired.is_empty() {
            return Ok(0);
        }

        let mut freed = 0u64;
        for id in &expired {
            if let Some(entry) = self.index.get(*id) {
                freed = freed.saturating_add(entry.size);
            }
            self.remove_blob(*id);
            if let Some(entry) = self.index.get_mut(*id) {
                entry.status = EntryStatus::Deleted;
                entry.changed_at = Utc::now();
                entry.note = Some(match entry.note.take() {
                    Some(existing) => format!("{existing}; removed by retention"),
                    None => "removed by retention".into(),
                });
            }
        }
        self.save_index()?;
        log::info!(
            "quarantine retention removed {} items older than {} days",
            expired.len(),
            retention.num_days()
        );
        self.listeners.emit(&QuarantineEvent::Evicted {
            count: expired.len(),
            freed_bytes: freed,
        });
        Ok(expired.len())
    }

    /// Evict the oldest live items until the vault is under its size ceiling.
    pub fn enforce_size_limit(&mut self) -> Result<Eviction> {
        let mut eviction = Eviction::default();
        let limit = self.policy.max_vault_size;
        if self.index.live_bytes() <= limit {
            return Ok(eviction);
        }

        // Oldest first: the item taken longest ago is the one the user is least
        // likely to still be thinking about, and a quarantine list that drops
        // the thing you just watched disappear is the one that gets complained
        // about.
        let mut candidates: Vec<(DateTime<Utc>, QuarantineId, u64)> = self
            .index
            .live()
            .map(|e| (e.quarantined_at, e.id, e.size))
            .collect();
        candidates.sort_by_key(|(when, id, _)| (*when, *id));

        let mut held = self.index.live_bytes();
        for (_, id, size) in candidates {
            if held <= limit {
                break;
            }
            self.remove_blob(id);
            if let Some(entry) = self.index.get_mut(id) {
                entry.status = EntryStatus::Deleted;
                entry.changed_at = Utc::now();
                entry.note = Some(match entry.note.take() {
                    Some(existing) => format!("{existing}; evicted to stay under the size limit"),
                    None => "evicted to stay under the size limit".into(),
                });
            }
            held = held.saturating_sub(size);
            eviction.freed_bytes = eviction.freed_bytes.saturating_add(size);
            eviction.removed.push(id);
        }

        if !eviction.is_empty() {
            self.save_index()?;
            log::warn!(
                "the quarantine vault was over its {} byte limit; evicted {} items",
                limit,
                eviction.count()
            );
            self.listeners.emit(&QuarantineEvent::Evicted {
                count: eviction.count(),
                freed_bytes: eviction.freed_bytes,
            });
        }
        Ok(eviction)
    }

    /// Forget entries that are no longer live and are older than `age`.
    ///
    /// A restored or deleted entry is history: useful for a while, pure size
    /// after that. `age` is measured from when the item changed state, not from
    /// when it was taken, so an item a user restored today stays visible today.
    pub fn compact_history(&mut self, age: Duration) -> Result<usize> {
        let Ok(age) = chrono::Duration::from_std(age) else {
            return Ok(0);
        };
        let cutoff = Utc::now() - age;
        let dropped = self
            .index
            .retain(|e| e.status.is_live() || e.changed_at >= cutoff);
        if dropped > 0 {
            self.save_index()?;
            log::debug!("compacted {dropped} finished quarantine records");
        }
        Ok(dropped)
    }

    /// Try again to delete the originals that would not go.
    ///
    /// Two callers: the service, immediately after a quarantine whose delete
    /// lost a race with the handle of the process that opened the file
    /// (`av_service::host::Host::win_the_removal_race`), and `wenle quarantine
    /// maintain`, which is what a file held open for longer than that wait
    /// needs — a reboot is the best chance of getting one of those. Nothing in
    /// the service sweeps this queue on a timer, so an entry left here stays
    /// here until one of those two runs.
    pub fn retry_pending_removals(&mut self) -> Result<RemovalSweep> {
        if self.index.pending().is_empty() {
            return Ok(RemovalSweep::default());
        }

        let queued = self.index.pending().to_vec();
        let mut sweep = RemovalSweep::default();
        let mut completed = Vec::new();

        for pending in queued {
            match remove_original(&pending.path) {
                Ok(()) => {
                    self.index.clear_removal(&pending.path);
                    self.index.mark_original_removed(pending.id);
                    completed.push((pending.path.clone(), pending.id));
                    sweep.removed += 1;
                }
                Err(e) => {
                    if pending.attempts >= self.policy.max_removal_attempts {
                        self.index.clear_removal(&pending.path);
                        log::warn!(
                            "giving up on deleting {} after {} attempts: {e}",
                            pending.path.display(),
                            pending.attempts
                        );
                        sweep.abandoned += 1;
                    } else {
                        log::debug!(
                            "{} is still held open (attempt {}): {e}",
                            pending.path.display(),
                            pending.attempts
                        );
                        self.index
                            .queue_removal(&pending.path, pending.id, e.to_string());
                        sweep.deferred += 1;
                    }
                }
            }
        }

        self.save_index()?;
        for (path, id) in completed {
            self.listeners
                .emit(&QuarantineEvent::RemovalCompleted { path, id });
        }
        Ok(sweep)
    }

    /// Everything maintenance does, in one call: retention, the size ceiling,
    /// a sweep of the pending deletions, and compaction of finished records.
    pub fn maintain(&mut self, history_age: Duration) -> Result<MaintenanceOutcome> {
        let expired = self.purge_expired()?;
        let evicted = self.enforce_size_limit()?;
        let sweep = self.retry_pending_removals()?;
        let compacted = self.compact_history(history_age)?;
        Ok(MaintenanceOutcome {
            expired,
            evicted,
            sweep,
            compacted,
        })
    }
}

/// What a full maintenance pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintenanceOutcome {
    /// Live items dropped by retention.
    pub expired: usize,
    /// Live items dropped to stay under the size ceiling.
    pub evicted: Eviction,
    /// What the deletion sweep managed.
    pub sweep: RemovalSweep,
    /// Finished records forgotten.
    pub compacted: usize,
}

/// Delete a file, clearing the read-only attribute once if that is what stands
/// in the way.
///
/// A file that is already gone is success: something else removed it, which is
/// the outcome that was wanted. The alternative — treating it as a failure and
/// queueing a deletion that can never succeed — fills the pending list with
/// paths that will be retried ten times and then reported to the user as a
/// problem.
fn remove_original(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(first) if first.kind() == std::io::ErrorKind::PermissionDenied => {
            match attributes::clear_readonly(path) {
                Ok(true) => std::fs::remove_file(path).map_err(|second| {
                    log::debug!(
                        "{} stayed undeletable after clearing the read-only attribute: {second}",
                        path.display()
                    );
                    second
                }),
                // Nothing was changed, so the first failure is the real one.
                Ok(false) => Err(first),
                Err(attribute_error) => {
                    log::debug!(
                        "could not read the attributes of {}: {attribute_error}",
                        path.display()
                    );
                    Err(first)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// Reject a restore destination before anything is written to it.
///
/// Three checks, each for a distinct way this could go wrong:
///
/// * **Absolute.** A relative path would be resolved against whatever directory
///   the service happens to have been started in, which for a service is
///   `System32`. That is not a bug that announces itself.
/// * **No parent-directory components.** `C:\Windows\System32\..\..\..\evil`
///   reads like it is going somewhere inside `System32`.
/// * **Not inside the vault.** Restoring into the vault would put a plaintext
///   executable inside the directory the vault's ACLs are meant to protect, and
///   the next scan would quarantine it again, forever.
fn validate_destination(target: &Path, root: &Path) -> std::result::Result<(), &'static str> {
    if !target.is_absolute() {
        return Err("the destination is not an absolute path");
    }
    if target
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("the destination contains a `..` component");
    }
    let mut normalized = String::new();
    for component in target.components() {
        normalized.push_str(&component.as_os_str().to_string_lossy());
        normalized.push('\\');
    }
    let root_text = {
        let mut text = String::new();
        for component in root.components() {
            text.push_str(&component.as_os_str().to_string_lossy());
            text.push('\\');
        }
        text
    };
    if normalized
        .to_lowercase()
        .starts_with(&root_text.to_lowercase())
    {
        return Err("the destination is inside the quarantine vault");
    }
    if target.file_name().is_none() {
        return Err("the destination names a directory rather than a file");
    }
    Ok(())
}

/// Write bytes to a destination, refusing to replace an existing file unless
/// asked.
fn write_destination(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        return Err(QuarantineError::TargetExists(path.to_path_buf()));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| QuarantineError::io("create", parent, e))?;
        }
    }
    fsutil::write_atomic(path, bytes)
}

/// Convenience: a listener that logs every event at `info`.
pub fn logging_listener() -> QuarantineListener {
    Arc::new(|event: &QuarantineEvent| {
        log::info!("quarantine: {}", event.summary());
    })
}

#[cfg(test)]
mod tests;
