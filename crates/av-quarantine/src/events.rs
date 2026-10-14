//! Telling the rest of the product what the vault just did.
//!
//! The vault does not know what a notification is and must not: it is linked
//! into the service, the command-line tool and the tests, and only one of those
//! has a screen. What it does know is that several components need to react to
//! a quarantine the moment it happens — the service raises the block
//! notification, the history log records it, the tray icon updates its count —
//! and that the quarantine usually happens on a scanning worker thread that has
//! no idea any of those exist.
//!
//! So operations report through a subscription rather than a return value. The
//! entry is still returned to the caller as well; the event is for the
//! components that are not the caller.
//!
//! # Why the listener is called while the vault is still locked
//!
//! Listeners run synchronously, from inside the operation, before it returns.
//! That means a listener that blocks blocks the vault, and one that panics
//! takes the operation with it. The trade is deliberate: a listener that fires
//! *after* the lock is released can be overtaken by a second quarantine, and
//! the block notification for the second file can reach the screen before the
//! first — which for a user watching two popups arrive out of order looks like
//! the product has lost track of what it is doing. Listeners are therefore
//! expected to be short: push onto a channel and return. Anything that needs to
//! take time — a toast that animates, a log file that is flushed — belongs on
//! the far side of that channel.

use std::path::PathBuf;
use std::sync::Arc;

use crate::entry::QuarantineEntry;
use crate::id::QuarantineId;

/// Something the vault did.
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineEvent {
    /// A file was taken. This is the one the block notification is raised for.
    Quarantined(Box<QuarantineEntry>),
    /// An item was written back to disk.
    Restored {
        /// The entry, after its state change.
        entry: Box<QuarantineEntry>,
        /// Where it was written.
        path: PathBuf,
    },
    /// An item was destroyed at the user's request.
    Deleted(Box<QuarantineEntry>),
    /// Retention or the size ceiling removed items without anyone asking.
    Evicted {
        /// How many went.
        count: usize,
        /// How many bytes that freed.
        freed_bytes: u64,
    },
    /// An original file could not be deleted and is now queued for a retry.
    ///
    /// The threat is already neutralized — its bytes are in the vault — but the
    /// file is still on disk, and a user who is told "blocked" and then finds
    /// the file still there has been told something untrue. This event is what
    /// lets the interface say the accurate thing.
    RemovalDeferred {
        /// The file still on disk.
        path: PathBuf,
        /// The entry holding its bytes.
        id: QuarantineId,
        /// Why the attempt failed.
        error: String,
    },
    /// A queued deletion finally succeeded.
    RemovalCompleted {
        /// The file that is now gone.
        path: PathBuf,
        /// The entry it belonged to.
        id: QuarantineId,
    },
    /// A queued deletion was given up on, after
    /// [`crate::QuarantinePolicy::max_removal_attempts`].
    RemovalAbandoned {
        /// The file that is still there.
        path: PathBuf,
        /// The entry it belonged to.
        id: QuarantineId,
    },
    /// A payload failed an integrity check.
    CorruptionDetected {
        /// The entry.
        id: QuarantineId,
        /// What did not match.
        detail: String,
    },
}

impl QuarantineEvent {
    /// The entry this event is about, when it is about one.
    pub fn entry(&self) -> Option<&QuarantineEntry> {
        match self {
            QuarantineEvent::Quarantined(e)
            | QuarantineEvent::Deleted(e)
            | QuarantineEvent::Restored { entry: e, .. } => Some(e),
            _ => None,
        }
    }

    /// A one-line description for the log.
    pub fn summary(&self) -> String {
        match self {
            QuarantineEvent::Quarantined(e) => format!(
                "quarantined {} ({}) as {}",
                e.original_path.display(),
                e.file_name,
                e.id.short()
            ),
            QuarantineEvent::Restored { path, .. } => {
                format!("restored {}", path.display())
            }
            QuarantineEvent::Deleted(e) => {
                format!("deleted {} from the vault", e.file_name)
            }
            QuarantineEvent::Evicted { count, freed_bytes } => {
                format!("evicted {count} items, freeing {freed_bytes} bytes")
            }
            QuarantineEvent::RemovalDeferred { path, error, .. } => {
                format!("could not delete {} yet: {error}", path.display())
            }
            QuarantineEvent::RemovalCompleted { path, .. } => {
                format!("deleted the original {}", path.display())
            }
            QuarantineEvent::RemovalAbandoned { path, .. } => {
                format!("gave up deleting {}", path.display())
            }
            QuarantineEvent::CorruptionDetected { id, detail } => {
                format!("vault corruption in {}: {detail}", id.short())
            }
        }
    }
}

/// A subscriber. Called on the thread performing the operation.
pub type QuarantineListener = Arc<dyn Fn(&QuarantineEvent) + Send + Sync>;

/// The set of subscribers attached to one vault.
///
/// Not `Debug`: a boxed closure has nothing useful to print, and deriving it
/// would put an opaque pointer in every `Debug` dump of the vault.
#[derive(Default, Clone)]
pub(crate) struct Listeners(Vec<QuarantineListener>);

impl Listeners {
    /// Add a subscriber.
    pub(crate) fn push(&mut self, listener: QuarantineListener) {
        self.0.push(listener);
    }

    /// How many are attached. Used by tests to confirm a subscription took.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Hand the event to every subscriber.
    ///
    /// A panicking listener is contained: `catch_unwind` around each call means
    /// a bug in a notification handler cannot abort a quarantine that has
    /// already succeeded. The entry is on disk and in the index by the time any
    /// listener runs, so swallowing the panic loses a notification and nothing
    /// else.
    pub(crate) fn emit(&self, event: &QuarantineEvent) {
        for listener in &self.0 {
            // SAFETY-equivalent reasoning, without `unsafe`: `AssertUnwindSafe`
            // is needed because a `&QuarantineEvent` is not `UnwindSafe` — a
            // listener could in principle stash the reference. It cannot outlive
            // the call, because the borrow checker will not let it, so the
            // assertion holds.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                listener(event);
            }));
            if outcome.is_err() {
                log::error!(
                    "a quarantine listener panicked handling {:?}; the operation itself completed",
                    event
                );
            }
        }
    }
}

impl std::fmt::Debug for Listeners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Listeners({})", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{QuarantineContext, QuarantineEntry};
    use av_core::Digests;

    fn entry() -> QuarantineEntry {
        QuarantineEntry::new(
            QuarantineId::from_bytes([1u8; 16]),
            r"C:\Users\me\Downloads\bad.exe",
            42,
            Digests::default(),
            &QuarantineContext::default(),
        )
    }

    #[test]
    fn every_subscriber_hears_the_event() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut listeners = Listeners::default();
        for _ in 0..3 {
            let seen = Arc::clone(&seen);
            listeners.push(Arc::new(move |event: &QuarantineEvent| {
                seen.lock().unwrap().push(event.summary());
            }));
        }
        assert_eq!(listeners.len(), 3);
        listeners.emit(&QuarantineEvent::Quarantined(Box::new(entry())));
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[test]
    fn a_panicking_listener_does_not_stop_the_others() {
        let seen = Arc::new(std::sync::Mutex::new(0usize));
        let mut listeners = Listeners::default();
        listeners.push(Arc::new(|_: &QuarantineEvent| panic!("a bug in a handler")));
        {
            let seen = Arc::clone(&seen);
            listeners.push(Arc::new(move |_: &QuarantineEvent| {
                *seen.lock().unwrap() += 1;
            }));
        }
        // Must not propagate.
        listeners.emit(&QuarantineEvent::Deleted(Box::new(entry())));
        assert_eq!(*seen.lock().unwrap(), 1);
    }

    #[test]
    fn an_event_that_is_about_an_entry_says_so() {
        let e = entry();
        assert!(QuarantineEvent::Quarantined(Box::new(e.clone()))
            .entry()
            .is_some());
        assert!(QuarantineEvent::Deleted(Box::new(e.clone()))
            .entry()
            .is_some());
        assert!(QuarantineEvent::Restored {
            entry: Box::new(e),
            path: PathBuf::from(r"C:\a.exe"),
        }
        .entry()
        .is_some());
        assert!(QuarantineEvent::Evicted {
            count: 1,
            freed_bytes: 1
        }
        .entry()
        .is_none());
    }

    #[test]
    fn every_summary_is_a_sentence_with_something_in_it() {
        let e = entry();
        let events = vec![
            QuarantineEvent::Quarantined(Box::new(e.clone())),
            QuarantineEvent::Restored {
                entry: Box::new(e.clone()),
                path: PathBuf::from(r"C:\a.exe"),
            },
            QuarantineEvent::Deleted(Box::new(e.clone())),
            QuarantineEvent::Evicted {
                count: 2,
                freed_bytes: 4096,
            },
            QuarantineEvent::RemovalDeferred {
                path: PathBuf::from(r"C:\a.exe"),
                id: e.id,
                error: "in use".into(),
            },
            QuarantineEvent::RemovalCompleted {
                path: PathBuf::from(r"C:\a.exe"),
                id: e.id,
            },
            QuarantineEvent::RemovalAbandoned {
                path: PathBuf::from(r"C:\a.exe"),
                id: e.id,
            },
            QuarantineEvent::CorruptionDetected {
                id: e.id,
                detail: "digest mismatch".into(),
            },
        ];
        for event in events {
            let summary = event.summary();
            assert!(summary.len() > 10, "too short: {summary}");
            assert!(!summary.contains("  "), "double space: {summary}");
        }
    }

    #[test]
    fn a_quarantine_summary_names_the_path_the_name_and_the_id() {
        let summary = QuarantineEvent::Quarantined(Box::new(entry())).summary();
        assert!(summary.contains("bad.exe"), "{summary}");
        assert!(summary.contains(r"C:\Users\me\Downloads"), "{summary}");
        assert!(summary.contains("01010101"), "{summary}");
    }
}
