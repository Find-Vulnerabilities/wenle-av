//! Behaviour tests for the vault, driven through its public interface.
//!
//! These live in a sibling file rather than in `vault.rs` because the module
//! they test is the largest in the crate and the tests are longer than it is.
//! Everything here uses only what a caller outside the crate could use, with
//! three exceptions where reaching into the index is the only way to construct
//! a state — backdating an entry, and queueing a deletion for a path that never
//! existed — and each of those is marked where it happens.

use super::*;
use crate::entry::EntrySource;
use av_core::{Severity, Verdict};

/// A vault in its own temporary directory. The directory is returned so it
/// outlives the vault: dropping it deletes the vault's files underneath it.
fn vault() -> (tempfile::TempDir, QuarantineVault) {
    vault_with(QuarantinePolicy::unlimited())
}

fn vault_with(policy: QuarantinePolicy) -> (tempfile::TempDir, QuarantineVault) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let vault =
        QuarantineVault::open(dir.path().join("vault"), policy).expect("the vault must open");
    (dir, vault)
}

fn write_file(dir: &std::path::Path, name: &str, contents: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write the sample");
    path
}

fn context() -> QuarantineContext {
    QuarantineContext {
        severity: Severity::Critical,
        verdict: Verdict::Malicious,
        detection: Some("TEST_Rule".into()),
        source: EntrySource::Realtime,
        ..QuarantineContext::default()
    }
}

fn take(vault: &mut QuarantineVault, path: &Path) -> QuarantineEntry {
    vault
        .quarantine_file(path, &context())
        .expect("the file must be quarantined")
}

// -- quarantining ----------------------------------------------------------

#[test]
fn quarantining_takes_the_original_and_keeps_the_bytes() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"MZ\x90\x00payload");

    let entry = take(&mut v, &sample);

    assert!(!sample.exists(), "the original must be gone");
    assert!(entry.original_removed);
    assert_eq!(entry.status, EntryStatus::Quarantined);
    assert_eq!(entry.size, 11);
    assert_eq!(entry.file_name, "bad.exe");
    assert_eq!(entry.source, EntrySource::Realtime);
    assert_eq!(entry.detection.as_deref(), Some("TEST_Rule"));
    assert!(v.items_dir().join(entry.id.blob_name()).exists());
}

#[test]
fn the_recorded_digests_are_the_digests_of_the_file() {
    let (dir, mut v) = vault();
    let contents = b"the sample bytes";
    let sample = write_file(dir.path(), "bad.exe", contents);
    let entry = take(&mut v, &sample);

    assert_eq!(
        entry.digests.sha256.as_deref(),
        Some(HashKind::Sha256.digest(contents).as_str())
    );
    assert_eq!(
        entry.digests.md5.as_deref(),
        Some(HashKind::Md5.digest(contents).as_str())
    );
    assert_eq!(
        entry.digests.sha1.as_deref(),
        Some(HashKind::Sha1.digest(contents).as_str())
    );
}

#[test]
fn the_index_survives_closing_and_reopening_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let sample = write_file(dir.path(), "bad.exe", b"payload");

    let id = {
        let mut v = QuarantineVault::open(&root, QuarantinePolicy::unlimited()).unwrap();
        take(&mut v, &sample).id
    };

    let v = QuarantineVault::open(&root, QuarantinePolicy::unlimited()).unwrap();
    let entry = v.get(id).expect("the entry must have been persisted");
    assert_eq!(entry.file_name, "bad.exe");
    assert!(v.items_dir().join(id.blob_name()).exists());
    v.verify(id).expect("the payload must still open");
}

#[test]
fn bytes_quarantined_with_no_file_of_their_own_are_accepted() {
    let (_dir, mut v) = vault();
    let original = PathBuf::from(r"C:\Users\me\Downloads\invoice.pdf");
    let entry = v
        .quarantine_bytes(&original, b"carved payload", &context())
        .expect("bytes must be accepted");

    assert_eq!(entry.size, 14);
    // Nothing was deleted, because there was never a file at that path. The
    // entry must not claim otherwise.
    assert!(!entry.original_removed);
    assert!(v.pending_removals().is_empty());
    assert_eq!(entry.file_name, "invoice.pdf");
    v.verify(entry.id).unwrap();
}

#[test]
fn a_file_over_the_item_limit_is_refused_before_anything_is_written() {
    let (dir, mut v) = vault_with(QuarantinePolicy {
        max_item_size: 4,
        ..QuarantinePolicy::unlimited()
    });
    let sample = write_file(dir.path(), "big.bin", b"more than four bytes");

    let err = v.quarantine_file(&sample, &context()).unwrap_err();
    assert!(matches!(err, QuarantineError::TooLarge { .. }), "{err:?}");
    assert!(sample.exists(), "a refused file must be left alone");
    assert!(v.entries().is_empty());
    assert_eq!(std::fs::read_dir(v.items_dir()).unwrap().count(), 0);
}

#[test]
fn a_missing_file_is_an_error_and_not_an_empty_entry() {
    let (_dir, mut v) = vault();
    let err = v
        .quarantine_file(Path::new(r"C:\definitely\not\here.exe"), &context())
        .unwrap_err();
    assert!(matches!(err, QuarantineError::Io { .. }), "{err:?}");
    assert!(v.entries().is_empty());
}

#[test]
fn a_directory_is_refused_rather_than_taken() {
    let (dir, mut v) = vault();
    let err = v.quarantine_file(dir.path(), &context()).unwrap_err();
    assert!(err.to_string().contains("not a regular file"), "{err}");
}

#[test]
fn keeping_the_original_is_honoured_for_content_that_must_stay() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "evidence.bin", b"do not delete me");
    let keeping = context().keeping_original();

    let entry = v.quarantine_file(&sample, &keeping).unwrap();

    assert!(sample.exists(), "the original was deleted anyway");
    assert!(!entry.original_removed);
    v.verify(entry.id).unwrap();
}

// -- restoring -------------------------------------------------------------

#[test]
fn restoring_writes_the_bytes_back_unchanged() {
    let (dir, mut v) = vault();
    let contents = b"MZ\x90\x00the original bytes, exactly";
    let sample = write_file(dir.path(), "bad.exe", contents);
    let entry = take(&mut v, &sample);

    let restored = v
        .restore(entry.id, &RestoreOptions::to_original())
        .expect("the restore must succeed");

    assert_eq!(restored, sample);
    assert_eq!(std::fs::read(&sample).unwrap(), contents);
    assert_eq!(v.get(entry.id).unwrap().status, EntryStatus::Restored);
    assert!(
        !v.items_dir().join(entry.id.blob_name()).exists(),
        "the sealed copy should be gone after a restore"
    );
}

#[test]
fn a_restore_can_leave_the_sealed_copy_behind() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);

    v.restore(entry.id, &RestoreOptions::to_original().keeping_copy())
        .unwrap();
    assert!(v.items_dir().join(entry.id.blob_name()).exists());
}

#[test]
fn restoring_somewhere_else_is_allowed() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);
    let elsewhere = dir.path().join("restored").join("copy.exe");

    let written = v
        .restore(entry.id, &RestoreOptions::to(&elsewhere))
        .unwrap();

    assert_eq!(written, elsewhere);
    assert_eq!(std::fs::read(&elsewhere).unwrap(), b"payload");
}

#[test]
fn restoring_creates_missing_parent_directories() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);
    let deep = dir.path().join("a").join("b").join("c").join("out.exe");

    v.restore(entry.id, &RestoreOptions::to(&deep)).unwrap();
    assert!(deep.exists());
}

#[test]
fn an_existing_file_is_not_replaced_unless_asked() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"quarantined");
    let entry = take(&mut v, &sample);
    std::fs::write(&sample, b"something the user made").unwrap();

    let err = v
        .restore(entry.id, &RestoreOptions::to_original())
        .unwrap_err();
    assert!(matches!(err, QuarantineError::TargetExists(_)), "{err:?}");
    assert_eq!(std::fs::read(&sample).unwrap(), b"something the user made");

    v.restore(entry.id, &RestoreOptions::to_original().overwriting())
        .unwrap();
    assert_eq!(std::fs::read(&sample).unwrap(), b"quarantined");
}

#[test]
fn a_relative_destination_is_refused() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);

    let err = v
        .restore(entry.id, &RestoreOptions::to("relative.exe"))
        .unwrap_err();
    assert!(
        matches!(err, QuarantineError::UnsafeRestore { .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("absolute"), "{err}");
    // The item is untouched and can still be restored somewhere valid.
    assert_eq!(v.get(entry.id).unwrap().status, EntryStatus::Quarantined);
}

#[test]
fn a_destination_climbing_out_with_dot_dot_is_refused() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);

    let sneaky = dir
        .path()
        .join("a")
        .join("..")
        .join("..")
        .join("escaped.exe");
    let err = v
        .restore(entry.id, &RestoreOptions::to(&sneaky))
        .unwrap_err();
    assert!(err.to_string().contains(".."), "{err}");
    assert!(!dir.path().join("escaped.exe").exists());
}

#[test]
fn a_destination_inside_the_vault_is_refused() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);
    let inside = v.items_dir().join("planted.exe");

    let err = v
        .restore(entry.id, &RestoreOptions::to(&inside))
        .unwrap_err();
    assert!(
        err.to_string().contains("inside the quarantine vault"),
        "{err}"
    );
    assert!(!inside.exists());
}

#[test]
fn an_item_that_is_not_quarantined_cannot_be_restored_again() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);
    v.restore(entry.id, &RestoreOptions::to_original()).unwrap();

    let err = v
        .restore(entry.id, &RestoreOptions::to_original())
        .unwrap_err();
    assert!(matches!(err, QuarantineError::WrongState { .. }), "{err:?}");
    assert!(err.to_string().contains("restored"), "{err}");
}

#[test]
fn restoring_something_that_was_never_there_names_the_identifier() {
    let (_dir, mut v) = vault();
    let unknown = QuarantineId::from_bytes([9u8; 16]);
    let err = v
        .restore(unknown, &RestoreOptions::to_original())
        .unwrap_err();
    assert!(matches!(err, QuarantineError::NotFound(_)), "{err:?}");
}

#[test]
fn a_payload_that_was_tampered_with_is_not_written_back() {
    // In plaintext mode there is no authentication tag, so the only thing
    // standing between a modified blob and the filesystem is the recorded
    // digest. This is the case that check exists for.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut v =
        QuarantineVault::open(&root, QuarantinePolicy::unlimited().without_encryption()).unwrap();
    let sample = write_file(dir.path(), "bad.exe", b"the real payload");
    let entry = take(&mut v, &sample);
    let target = dir.path().join("restored.exe");

    let blob = v.items_dir().join(entry.id.blob_name());
    let mut stored = std::fs::read(&blob).unwrap();
    let last = stored.len() - 1;
    stored[last] ^= 0xff;
    std::fs::write(&blob, &stored).unwrap();

    let err = v
        .restore(entry.id, &RestoreOptions::to(&target))
        .unwrap_err();
    assert!(matches!(err, QuarantineError::Verify { .. }), "{err:?}");
    assert!(!target.exists(), "a failed check must not write a file");
    assert_eq!(v.get(entry.id).unwrap().status, EntryStatus::Quarantined);
}

#[test]
fn exporting_writes_a_plaintext_copy_and_leaves_the_item_alone() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload for the lab");
    let entry = take(&mut v, &sample);
    let out = dir.path().join("sample.bin");

    v.export(entry.id, &out, false).unwrap();

    assert_eq!(std::fs::read(&out).unwrap(), b"payload for the lab");
    assert_eq!(v.get(entry.id).unwrap().status, EntryStatus::Quarantined);
    // And it refuses to clobber an existing file unless told to.
    assert!(matches!(
        v.export(entry.id, &out, false).unwrap_err(),
        QuarantineError::TargetExists(_)
    ));
}

// -- deleting and maintenance ----------------------------------------------

#[test]
fn deleting_destroys_the_payload_and_keeps_the_record() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);

    let deleted = v.delete(entry.id).unwrap();

    assert_eq!(deleted.status, EntryStatus::Deleted);
    assert!(!v.items_dir().join(entry.id.blob_name()).exists());
    assert!(v.get(entry.id).is_ok(), "the record must survive");
    assert!(matches!(
        v.delete(entry.id).unwrap_err(),
        QuarantineError::WrongState { .. }
    ));
}

#[test]
fn retention_removes_what_is_old_enough_and_nothing_else() {
    let (dir, mut v) = vault_with(QuarantinePolicy {
        retention: Some(Duration::from_secs(3600)),
        ..QuarantinePolicy::unlimited()
    });
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let old = take(&mut v, &sample);
    let fresh = take(&mut v, &write_file(dir.path(), "newer.exe", b"payload"));

    // Backdate one entry. Reaching into the index is the only way to build this
    // state, since nothing in the public interface moves an item's clock.
    v.index.get_mut(old.id).unwrap().quarantined_at = Utc::now() - chrono::Duration::hours(2);

    let removed = v.purge_expired().unwrap();

    assert_eq!(removed, 1);
    assert_eq!(v.get(old.id).unwrap().status, EntryStatus::Deleted);
    assert_eq!(v.get(fresh.id).unwrap().status, EntryStatus::Quarantined);
    assert!(v.items_dir().join(fresh.id.blob_name()).exists());
    assert!(!v.items_dir().join(old.id.blob_name()).exists());
}

#[test]
fn a_policy_that_keeps_everything_purges_nothing() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);
    v.index.get_mut(entry.id).unwrap().quarantined_at = Utc::now() - chrono::Duration::days(3650);

    assert_eq!(v.purge_expired().unwrap(), 0);
    assert_eq!(v.get(entry.id).unwrap().status, EntryStatus::Quarantined);
}

#[test]
fn the_size_ceiling_evicts_the_oldest_first() {
    let (dir, mut v) = vault_with(QuarantinePolicy {
        // Room for two of the three 100-byte samples.
        max_vault_size: 250,
        ..QuarantinePolicy::unlimited()
    });
    let payload = vec![0u8; 100];
    let first = take(&mut v, &write_file(dir.path(), "one.bin", &payload));
    v.index.get_mut(first.id).unwrap().quarantined_at = Utc::now() - chrono::Duration::hours(3);
    let second = take(&mut v, &write_file(dir.path(), "two.bin", &payload));
    v.index.get_mut(second.id).unwrap().quarantined_at = Utc::now() - chrono::Duration::hours(2);
    let third = take(&mut v, &write_file(dir.path(), "three.bin", &payload));

    let eviction = v.enforce_size_limit().unwrap();

    assert_eq!(eviction.count(), 1, "exactly one item had to go");
    assert_eq!(eviction.removed, vec![first.id]);
    assert_eq!(eviction.freed_bytes, 100);
    assert_eq!(v.get(first.id).unwrap().status, EntryStatus::Deleted);
    assert_eq!(v.get(second.id).unwrap().status, EntryStatus::Quarantined);
    assert_eq!(v.get(third.id).unwrap().status, EntryStatus::Quarantined);
    assert!(
        v.get(first.id).unwrap().note.is_some(),
        "the note must say why"
    );
}

#[test]
fn a_vault_under_its_ceiling_evicts_nothing() {
    let (dir, mut v) = vault_with(QuarantinePolicy {
        max_vault_size: 1024 * 1024,
        ..QuarantinePolicy::unlimited()
    });
    take(&mut v, &write_file(dir.path(), "small.bin", b"tiny"));
    assert!(v.enforce_size_limit().unwrap().is_empty());
}

#[test]
fn compaction_forgets_finished_records_and_keeps_live_ones() {
    let (dir, mut v) = vault();
    let live = take(&mut v, &write_file(dir.path(), "kept.exe", b"payload"));
    let gone = take(&mut v, &write_file(dir.path(), "finished.exe", b"payload"));
    v.delete(gone.id).unwrap();
    v.index.get_mut(gone.id).unwrap().changed_at = Utc::now() - chrono::Duration::days(40);

    let dropped = v
        .compact_history(Duration::from_secs(30 * 24 * 3600))
        .unwrap();

    assert_eq!(dropped, 1);
    assert!(v.get(gone.id).is_err());
    assert!(v.get(live.id).is_ok());
}

#[test]
fn the_stats_add_up() {
    let (dir, mut v) = vault();
    take(&mut v, &write_file(dir.path(), "a.exe", b"12345"));
    let restored = take(&mut v, &write_file(dir.path(), "b.exe", b"1234567890"));
    let deleted = take(&mut v, &write_file(dir.path(), "c.exe", b"123"));
    v.restore(restored.id, &RestoreOptions::to_original())
        .unwrap();
    v.delete(deleted.id).unwrap();

    let stats = v.stats();

    assert_eq!(stats.total, 3);
    assert_eq!(stats.quarantined, 1);
    assert_eq!(stats.restored, 1);
    assert_eq!(stats.deleted, 1);
    assert_eq!(stats.live_bytes, 5);
    assert_eq!(stats.orphans, 0);
    assert_eq!(stats.pending_removals, 0);
    assert!(stats.oldest.is_some() && stats.newest.is_some());
}

#[test]
fn a_payload_with_no_entry_is_reported_as_an_orphan() {
    let (_dir, v) = vault();
    assert!(v.orphans().is_empty());
    let stray = v
        .items_dir()
        .join(QuarantineId::from_bytes([0xee; 16]).blob_name());
    std::fs::write(&stray, b"nobody knows what this was").unwrap();

    let orphans = v.orphans();

    assert_eq!(orphans, vec![stray]);
    assert_eq!(v.stats().orphans, 1);
    // A file in the vault directory that is not a payload is not an orphan.
    std::fs::write(v.items_dir().join("notes.txt"), b"ignore me").unwrap();
    assert_eq!(v.orphans().len(), 1);
}

#[test]
fn a_damaged_index_can_be_moved_aside_rather_than_blocking_the_product() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    {
        let mut v = QuarantineVault::open(&root, QuarantinePolicy::unlimited()).unwrap();
        take(&mut v, &write_file(dir.path(), "bad.exe", b"payload"));
    }
    // Corrupt the index the way a bad sector or an editor would.
    let index_path = root.join(INDEX_FILE);
    let mut bytes = std::fs::read(&index_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&index_path, &bytes).unwrap();

    // Strict open refuses.
    assert!(QuarantineVault::open(&root, QuarantinePolicy::unlimited()).is_err());

    // Recovering open moves it aside and starts clean.
    let v = QuarantineVault::open_recovering(&root, QuarantinePolicy::unlimited()).unwrap();
    assert!(v.entries().is_empty());
    let moved_aside: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("index.corrupt-")
        })
        .collect();
    assert_eq!(moved_aside.len(), 1, "the damaged index must be kept");
    // And the payload it described is now visible as an orphan.
    assert_eq!(v.orphans().len(), 1);
}

// -- verification ----------------------------------------------------------

#[test]
fn verifying_a_healthy_item_passes_and_a_tampered_one_fails() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);
    v.verify(entry.id).expect("a fresh item must verify");

    // Flipping a byte of a sealed payload makes it fail to open, which the
    // verification reports rather than swallowing.
    let blob = v.items_dir().join(entry.id.blob_name());
    let mut stored = std::fs::read(&blob).unwrap();
    let last = stored.len() - 1;
    stored[last] ^= 0xff;
    std::fs::write(&blob, &stored).unwrap();

    let err = v.verify(entry.id).unwrap_err();
    assert!(err.is_corruption(), "{err:?}");
}

#[test]
fn verifying_everything_lists_only_the_problems() {
    let (dir, mut v) = vault();
    let good = take(&mut v, &write_file(dir.path(), "good.exe", b"payload"));
    let bad = take(&mut v, &write_file(dir.path(), "bad.exe", b"payload"));

    let blob = v.items_dir().join(bad.id.blob_name());
    let mut stored = std::fs::read(&blob).unwrap();
    let last = stored.len() - 1;
    stored[last] ^= 0xff;
    std::fs::write(&blob, &stored).unwrap();

    let failures = v.verify_all();

    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, bad.id);
    v.verify(good.id)
        .expect("the healthy item must still verify");
}

#[test]
fn a_payload_that_has_gone_missing_is_reported_by_name() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "bad.exe", b"payload");
    let entry = take(&mut v, &sample);
    std::fs::remove_file(v.items_dir().join(entry.id.blob_name())).unwrap();

    let err = v.verify(entry.id).unwrap_err();
    assert!(err.to_string().contains("missing"), "{err}");
}

// -- events ----------------------------------------------------------------

#[test]
fn every_operation_announces_itself() {
    let (dir, mut v) = vault();
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let seen = Arc::clone(&seen);
        v.subscribe(Arc::new(move |event: &QuarantineEvent| {
            seen.lock().unwrap().push(event.summary());
        }));
    }
    assert_eq!(v.listener_count(), 1);

    let entry = take(&mut v, &write_file(dir.path(), "bad.exe", b"payload"));
    v.restore(entry.id, &RestoreOptions::to_original()).unwrap();
    v.delete(entry.id).unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert!(seen[0].contains("quarantined"), "{}", seen[0]);
    assert!(seen[1].contains("restored"), "{}", seen[1]);
    assert!(seen[2].contains("deleted"), "{}", seen[2]);
}

#[test]
fn a_listener_that_panics_does_not_stop_the_quarantine() {
    let (dir, mut v) = vault();
    v.subscribe(Arc::new(|_: &QuarantineEvent| panic!("a bug in the toast")));
    let sample = write_file(dir.path(), "bad.exe", b"payload");

    let entry = take(&mut v, &sample);

    assert!(!sample.exists());
    v.verify(entry.id).expect("the payload must be intact");
}

// -- the pending-removal list ----------------------------------------------

#[cfg(windows)]
#[test]
fn a_file_held_open_is_still_quarantined_and_queued_for_deletion() {
    use std::os::windows::fs::OpenOptionsExt;
    /// `FILE_SHARE_READ`: other processes may read the file, but not delete it.
    /// This is what an installer or a running image does.
    const FILE_SHARE_READ: u32 = 1;

    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "locked.exe", b"payload");
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&sample)
        .expect("the sample must open");

    let entry = take(&mut v, &sample);

    // The bytes are safe even though the file is still there.
    v.verify(entry.id).expect("the payload must be intact");
    assert!(!entry.original_removed);
    assert!(sample.exists(), "the held file cannot have been deleted");
    assert_eq!(v.pending_removals().len(), 1);
    assert_eq!(v.pending_removals()[0].id, entry.id);

    // Once the holder lets go, a sweep finishes the job.
    drop(holder);
    let sweep = v.retry_pending_removals().unwrap();

    assert_eq!(sweep.removed, 1);
    assert_eq!(sweep.deferred, 0);
    assert!(!sample.exists());
    assert!(v.pending_removals().is_empty());
    assert!(v.get(entry.id).unwrap().original_removed);
}

#[cfg(windows)]
#[test]
fn a_queued_deletion_is_given_up_on_after_the_attempt_limit() {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;

    let (dir, mut v) = vault_with(QuarantinePolicy {
        max_removal_attempts: 2,
        ..QuarantinePolicy::unlimited()
    });
    let sample = write_file(dir.path(), "locked.exe", b"payload");
    let _holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&sample)
        .unwrap();

    let entry = take(&mut v, &sample);
    assert_eq!(v.pending_removals()[0].attempts, 1);

    // First sweep: still held, so it is retried and the count rises.
    assert_eq!(v.retry_pending_removals().unwrap().deferred, 1);
    assert_eq!(v.pending_removals()[0].attempts, 2);

    // The limit is two, so the next sweep gives up rather than retrying forever
    // on a file that is never going to move.
    let sweep = v.retry_pending_removals().unwrap();
    assert_eq!(sweep.abandoned, 1);
    assert!(v.pending_removals().is_empty());
    assert!(sample.exists());
    // The bytes are still safe, which is the point.
    v.verify(entry.id).unwrap();
}

#[test]
fn a_queued_deletion_of_a_file_that_has_already_gone_succeeds() {
    let (dir, mut v) = vault();
    let sample = write_file(dir.path(), "gone.exe", b"payload");
    let entry = take(&mut v, &sample);
    // Queue an entry for a path that does not exist, which is what a race with
    // another tool's cleanup looks like.
    v.index.queue_removal(
        dir.path().join("never-existed.exe"),
        entry.id,
        "gone".into(),
    );

    let sweep = v.retry_pending_removals().unwrap();

    assert_eq!(sweep.removed, 1);
    assert_eq!(sweep.deferred, 0);
    assert!(v.pending_removals().is_empty());
}

#[test]
fn a_sweep_with_nothing_queued_does_nothing() {
    let (_dir, mut v) = vault();
    let sweep = v.retry_pending_removals().unwrap();
    assert_eq!(sweep, RemovalSweep::default());
}

// -- policy ----------------------------------------------------------------

#[test]
fn a_vault_that_does_not_encrypt_still_keeps_the_index_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut v =
        QuarantineVault::open(&root, QuarantinePolicy::unlimited().without_encryption()).unwrap();
    let sample = write_file(dir.path(), "bad.exe", b"distinctive payload text");
    let entry = take(&mut v, &sample);

    // The payload is readable, as the policy asked.
    let blob = std::fs::read(v.items_dir().join(entry.id.blob_name())).unwrap();
    assert_eq!(blob[0], crypto::FORMAT_PLAIN);
    assert!(blob.windows(15).any(|w| w == b"distinctive pay"));

    // The index is not.
    let index = std::fs::read(root.join(INDEX_FILE)).unwrap();
    assert_eq!(index[0], crypto::FORMAT_SEALED);
    assert!(!index.windows(6).any(|w| w == b"bad.ex"));
}

#[test]
fn the_policy_can_be_changed_after_the_vault_is_open() {
    let (_dir, mut v) = vault();
    assert!(v.policy().encrypt);
    let mut policy = v.policy().clone();
    policy.encrypt = false;
    v.set_policy(policy);
    assert!(!v.policy().encrypt);
}

#[test]
fn a_maintenance_pass_does_everything_at_once() {
    let (dir, mut v) = vault_with(QuarantinePolicy {
        retention: Some(Duration::from_secs(1)),
        ..QuarantinePolicy::unlimited()
    });
    let stale = take(&mut v, &write_file(dir.path(), "stale.exe", b"payload"));
    v.index.get_mut(stale.id).unwrap().quarantined_at = Utc::now() - chrono::Duration::days(400);
    let finished = take(&mut v, &write_file(dir.path(), "done.exe", b"payload"));
    v.delete(finished.id).unwrap();
    v.index.get_mut(finished.id).unwrap().changed_at = Utc::now() - chrono::Duration::days(400);

    let outcome = v.maintain(Duration::from_secs(30 * 24 * 3600)).unwrap();

    assert_eq!(outcome.expired, 1, "the 400-day-old live item must expire");
    assert_eq!(
        outcome.compacted, 1,
        "only the record finished 400 days ago is old enough to forget"
    );
    assert!(outcome.evicted.is_empty());
    // The expired item became history *now*, so it is still listed — a user who
    // had something purged by retention this morning must still be able to see
    // that it happened.
    assert!(v.get(finished.id).is_err());
    assert_eq!(v.get(stale.id).unwrap().status, EntryStatus::Deleted);
    assert_eq!(v.entries().len(), 1);
}

// -- a second writer ------------------------------------------------------

/// Another process over the same files, which is what the pair `open` calls
/// below stands for.
///
/// Two vaults in one test process are not two processes, but they are two
/// instances with two in-memory indexes over one index file, and that is the
/// only thing this behaviour depends on: the writer that is not writing is as
/// stale as its last read.
fn rejoin(dir: &std::path::Path) -> QuarantineVault {
    QuarantineVault::open(dir.join("vault"), QuarantinePolicy::unlimited())
        .expect("the same vault must open again")
}

#[test]
fn a_second_writers_entry_appears_in_the_first_vaults_next_read() {
    let (dir, mut first) = vault();
    let mine = take(&mut first, &write_file(dir.path(), "mine.exe", b"one"));

    // A second instance, opened after that entry was written, takes another.
    let mut second = rejoin(dir.path());
    assert_eq!(second.entries().len(), 1, "it opens on what is on disk");
    let theirs = take(&mut second, &write_file(dir.path(), "theirs.exe", b"two"));

    assert_eq!(
        first.entries().len(),
        1,
        "the first vault cannot have seen it before it re-reads"
    );

    let moved = first.reconcile().unwrap();

    assert_eq!(moved.added.len(), 1, "one entry arrived: {moved:?}");
    assert_eq!(moved.added[0].id, theirs.id);
    assert_eq!(moved.added[0].file_name, "theirs.exe");
    assert!(moved.changed.is_empty(), "{moved:?}");
    assert!(moved.removed.is_empty(), "{moved:?}");
    // And the in-memory index is now the disk's, not a merge of the two.
    assert_eq!(first.entries().len(), 2);
    assert!(first.get(mine.id).is_ok(), "its own entry survives the read");
    assert!(first.get(theirs.id).is_ok());
}

#[test]
fn reading_a_vault_nobody_else_touched_reports_nothing() {
    let (dir, mut v) = vault();
    take(&mut v, &write_file(dir.path(), "mine.exe", b"one"));

    let moved = v.reconcile().unwrap();

    assert!(moved.is_empty(), "nothing moved: {moved:?}");
    assert_eq!(moved.len(), 0);
}

#[test]
fn an_entry_the_other_writer_deleted_is_reported_as_changed() {
    // A delete is not a disappearance, and that is exactly why the index keeps a
    // record instead of dropping the row: the quarantine list still has to be
    // able to say what happened to that file. So it arrives here as a change of
    // status, and `removed` — which is for a row that is no longer in the index
    // at all — stays empty.
    let (dir, mut first) = vault();
    let gone = take(&mut first, &write_file(dir.path(), "gone.exe", b"one"));
    let kept = take(&mut first, &write_file(dir.path(), "kept.exe", b"two"));

    let mut second = rejoin(dir.path());
    second.delete(gone.id).unwrap();

    let moved = first.reconcile().unwrap();

    assert!(
        moved.removed.is_empty(),
        "the record is kept, so nothing left the index: {moved:?}"
    );
    assert_eq!(moved.changed.len(), 1, "{moved:?}");
    assert_eq!(moved.changed[0].id, gone.id);
    assert_eq!(moved.changed[0].status, EntryStatus::Deleted);
    assert!(moved.added.is_empty(), "{moved:?}");
    // And the stale copy has caught up: it says the file was deleted, which is
    // the sentence the list draws for it.
    assert_eq!(first.get(gone.id).unwrap().status, EntryStatus::Deleted);
    assert!(first.get(kept.id).is_ok());
}

#[test]
fn an_entry_the_other_writer_forgot_is_reported_as_removed() {
    // The only thing that takes a row out of the index altogether is the
    // maintenance pass forgetting a finished record, so that is what this has to
    // reach for — and it is the case `removed` exists for: an entry the stale
    // copy is still listing and the index no longer holds.
    let (dir, mut first) = vault();
    let stale = take(&mut first, &write_file(dir.path(), "stale.exe", b"one"));
    let kept = take(&mut first, &write_file(dir.path(), "kept.exe", b"two"));

    let mut second = rejoin(dir.path());
    second.delete(stale.id).unwrap();
    // Finished long enough ago that a pass with no history window forgets the
    // record entirely.
    second.index.get_mut(stale.id).unwrap().changed_at = Utc::now() - chrono::Duration::days(400);
    let outcome = second.maintain(Duration::ZERO).unwrap();
    assert_eq!(
        outcome.compacted, 1,
        "the record was forgotten: {outcome:?}"
    );

    let moved = first.reconcile().unwrap();

    assert_eq!(moved.removed, vec![stale.id], "{moved:?}");
    assert!(moved.added.is_empty(), "{moved:?}");
    assert!(moved.changed.is_empty(), "{moved:?}");
    assert!(first.get(stale.id).is_err(), "the row is gone from the list");
    assert!(first.get(kept.id).is_ok());
}

#[test]
fn an_entry_the_other_writer_changed_is_reported_as_changed() {
    let (dir, mut first) = vault();
    let sample = write_file(dir.path(), "restored.exe", b"payload");
    let entry = take(&mut first, &sample);
    assert_eq!(first.get(entry.id).unwrap().status, EntryStatus::Quarantined);

    // A user restores it from the command line while the window is open. The
    // identifier does not change, so this is a change and not an addition —
    // and a list that missed it would keep offering to restore a file that is
    // already back.
    let mut second = rejoin(dir.path());
    second
        .restore(entry.id, &RestoreOptions::to_original())
        .unwrap();

    let moved = first.reconcile().unwrap();

    assert_eq!(moved.changed.len(), 1, "{moved:?}");
    assert_eq!(moved.changed[0].id, entry.id);
    assert_eq!(moved.changed[0].status, EntryStatus::Restored);
    assert!(moved.added.is_empty(), "{moved:?}");
    assert!(moved.removed.is_empty(), "{moved:?}");
    assert_eq!(first.get(entry.id).unwrap().status, EntryStatus::Restored);
}

#[test]
fn an_index_that_is_not_there_leaves_the_entries_in_memory_alone() {
    let (dir, mut v) = vault();
    let entry = take(&mut v, &write_file(dir.path(), "mine.exe", b"one"));
    // Whatever removes it — an operator, a cleaner, a second writer with a bug —
    // the vault that is holding entries must not read "no file" as "no items".
    // Adopting an empty index here would drop every entry, and the next write
    // would make that permanent.
    std::fs::remove_file(&v.index_path).expect("the index file");

    let moved = v.reconcile().unwrap();

    assert!(moved.is_empty(), "{moved:?}");
    assert_eq!(v.entries().len(), 1, "the entry is still known");
    assert!(v.get(entry.id).is_ok());
}

#[test]
fn reconciling_does_not_call_a_listener() {
    let (dir, mut first) = vault();
    // Taken before anything is subscribed, so that the subscription is the only
    // thing that can put a line in here.
    let mine = take(&mut first, &write_file(dir.path(), "mine.exe", b"one"));
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let seen = Arc::clone(&seen);
        first.subscribe(Arc::new(move |event: &QuarantineEvent| {
            seen.lock().unwrap().push(event.summary());
        }));
    }

    let mut second = rejoin(dir.path());
    take(&mut second, &write_file(dir.path(), "theirs.exe", b"two"));
    let moved = first.reconcile().unwrap();

    assert_eq!(moved.added.len(), 1, "the re-read did find the new entry");
    // The quarantine happened in the other instance. A listener fired here
    // would announce the whole vault the first time a front end re-read it, and
    // the window would then have two paths to the corner for one file.
    let seen = seen.lock().unwrap();
    assert!(seen.is_empty(), "a reconciliation is not an event: {seen:?}");
    // And the entry it did not announce is the one it adopted.
    assert!(first.get(mine.id).is_ok());
    assert_eq!(first.get(moved.added[0].id).unwrap().file_name, "theirs.exe");
}

