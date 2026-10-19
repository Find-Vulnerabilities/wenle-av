//! The engine's own view of an event.
//!
//! A [`Record`] is what the rules are written against, and it is deliberately
//! smaller than [`av_ipc::DriverEvent`]: sequence numbers, thread identifiers
//! and the driver's status picture are for logging, not for deciding, and a
//! rule that could name them would be a rule about the driver rather than about
//! the machine.
//!
//! It is also **whole**: the `path` is a `String` rather than a `PathBuf` and
//! the case-folded copy the matchers use is computed once here rather than once
//! per rule. A million events times forty rules is forty million case folds if
//! this file does not do its job.

use crate::{Action, Subject};

/// One event, as the engine sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// When it happened, in 100-nanosecond units since 1601-01-01 — the driver's
    /// own unit, unconverted, because every comparison the engine makes is
    /// between two of these and converting would only introduce a rounding.
    pub timestamp: u64,
    /// What it happened to.
    pub subject: Subject,
    /// What happened.
    pub action: Action,
    /// The action-specific detail, as the driver sent it. Rules match it through
    /// [`crate::Detail`], which pins the numbers to the protocol's constants.
    pub detail: u32,
    /// The path as the driver reported it — the DOS form for a file, and
    /// `\REGISTRY\MACHINE\...` for a key. Kept in its original case because it
    /// is what a finding shows a person.
    pub path: Option<String>,
    /// The path up to ASCII case, which is what every matcher compares against.
    ///
    /// Windows compares file names case-insensitively using an invariant
    /// uppercase table, so ASCII-only folding is the right approximation for
    /// the paths that matter here; a non-ASCII name is folded only where it is
    /// ASCII, which can make a match miss but never makes one appear.
    pub folded_path: Option<String>,
    /// The process responsible.
    pub process_id: u32,
    /// The process that created it, for a process start.
    pub parent_process_id: u32,
}

impl Record {
    /// Convert a driver event, or `None` if no rule may speak about it.
    ///
    /// `None` is the answer for the driver's own subjects (`Driver`,
    /// `Protection`, `Configuration`), for `Image` (this build's image-load
    /// events name the process, not the DLL that was mapped, so there is nothing
    /// for a path rule to match), and for anything either enum has no name for.
    pub fn from_driver(event: &av_ipc::DriverEvent) -> Option<Record> {
        let subject = Subject::from_driver(event.subject)?;
        let action = Action::from_driver(event.action)?;
        let path = event
            .path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned());
        Some(Record {
            timestamp: event.timestamp_100ns,
            subject,
            action,
            detail: event.detail,
            folded_path: path.as_deref().map(fold),
            path,
            process_id: event.process_id,
            parent_process_id: event.parent_process_id,
        })
    }

    /// The path folded for matching.
    pub fn folded(&self) -> Option<&str> {
        self.folded_path.as_deref()
    }

    /// The file name of a path, folded. `None` when there is no path or it ends
    /// in a separator.
    ///
    /// Splits on both separators rather than using [`std::path::Path`] because
    /// this is also used for registry paths, which are not file paths and on
    /// which `Path` would still silently do the wrong thing.
    pub fn image_name(&self) -> Option<String> {
        self.path
            .as_deref()
            .and_then(|path| file_name(path).map(fold))
    }
}

/// ASCII-fold a string.
pub(crate) fn fold(value: &str) -> String {
    value.to_ascii_lowercase()
}

/// The trailing component of a path, either separator.
pub(crate) fn file_name(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_ipc::{DriverEvent, DriverEventAction, DriverSubject};

    fn event(action: DriverEventAction, subject: DriverSubject, path: Option<&str>) -> DriverEvent {
        DriverEvent {
            sequence: 1,
            timestamp_100ns: 128,
            action,
            subject,
            path: path.map(std::path::PathBuf::from),
            process_id: 1234,
            parent_process_id: 5678,
            thread_id: 0,
            detail: 0,
            driver_state: None,
        }
    }

    #[test]
    fn a_file_event_becomes_a_record_with_both_cases_of_the_path() {
        let record = Record::from_driver(&event(
            DriverEventAction::FileRenamed,
            DriverSubject::File,
            Some(r"C:\Users\Someone\Documents\Report.DOCX"),
        ))
        .expect("a file rename is something a rule can speak about");
        assert_eq!(record.subject, Subject::File);
        assert_eq!(record.action, Action::FileRenamed);
        assert_eq!(
            record.path.as_deref(),
            Some(r"C:\Users\Someone\Documents\Report.DOCX"),
            "the original case is what a finding shows"
        );
        assert_eq!(
            record.folded(),
            Some(r"c:\users\someone\documents\report.docx")
        );
        assert_eq!(record.image_name().as_deref(), Some("report.docx"));
    }

    #[test]
    fn the_drivers_own_subjects_and_the_unusable_actions_are_skipped() {
        for (action, subject) in [
            (DriverEventAction::StateChanged, DriverSubject::Driver),
            (DriverEventAction::StateChanged, DriverSubject::Protection),
            (
                DriverEventAction::StateChanged,
                DriverSubject::Configuration,
            ),
            (DriverEventAction::ImageLoaded, DriverSubject::Image),
            (
                DriverEventAction::Unrecognised { code: 99 },
                DriverSubject::File,
            ),
            (
                DriverEventAction::FileRenamed,
                DriverSubject::Unrecognised { code: 99 },
            ),
        ] {
            assert!(
                Record::from_driver(&event(action, subject, None)).is_none(),
                "{subject:?}/{action:?} was offered to the engine, which has no rule language for it"
            );
        }
    }

    #[test]
    fn a_driver_state_event_still_becomes_a_record_when_it_is_about_the_machine() {
        // The same action under a subject rules can name: this one is not
        // filtered out, because a driver that reports a file-under-the-driver's-
        // protection state is reporting about a file.
        let record = Record::from_driver(&event(
            DriverEventAction::StateChanged,
            DriverSubject::File,
            None,
        ))
        .expect("a state change about a file is a record");
        assert_eq!(record.action, Action::StateChanged);
    }

    #[test]
    fn a_file_name_splits_on_both_separators() {
        assert_eq!(file_name(r"C:\Windows\System32\cmd.exe"), Some("cmd.exe"));
        assert_eq!(file_name("C:/Windows/System32/cmd.exe"), Some("cmd.exe"));
        assert_eq!(file_name(r"C:\Windows\System32\\"), None);
        assert_eq!(file_name(""), None);
    }
}
