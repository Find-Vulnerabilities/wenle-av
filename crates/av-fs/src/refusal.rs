//! Why a file could not be read, in terms a user can act on.
//!
//! # Why this is a type rather than an `io::Error`
//!
//! `io::Error` from `std::fs::read` says `Access is denied. (os error 5)`, and
//! that sentence is the same for three situations with three different answers:
//!
//! * the file's own DACL excludes this account, and this process is not
//!   elevated, so the fix is to elevate;
//! * the file's own DACL excludes this account and this process *is* elevated
//!   with the backup privilege enabled, so the fix is to look at the file,
//!   because something unusual is going on;
//! * another process holds the file open without sharing it, so the fix is to
//!   wait, and the answer will be different in a moment.
//!
//! A scanner that reports all three as "unreadable" has told the user nothing,
//! and the user's reasonable conclusion is that the product is broken. So the
//! reasons are enumerated, each one carries the sentence it needs, and
//! [`Refused`] converts into an `io::Error` whose *message* is that sentence —
//! which is how the existing scan engine's error path gets the better wording
//! without its shape changing.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::privilege::Privilege;

/// A file that could not be read, and why.
///
/// The path is carried rather than passed alongside because every caller that
/// wants the reason also wants to say *which* file, and a caller that has to
/// remember to attach the path is a caller that will forget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The path that was asked for.
    pub path: PathBuf,
    /// What went wrong.
    pub why: Why,
}

/// The reason a read did not happen.
///
/// Every variant is a state a caller can act on differently. Nothing here is a
/// catch-all that other failures are swept into: an unrecognised operating
/// system error is [`Why::Os`] and keeps its code, which is the one case where
/// the raw number really is the most useful thing to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// Nothing is at that path.
    ///
    /// Distinguished from a refusal because the two mean different things: a
    /// file that was deleted between being listed and being read is a race with
    /// the user and is worth no comment, while a path that never existed is a
    /// caller's mistake and is worth a word.
    Gone,
    /// The access check refused the open.
    ///
    /// `backup_enabled` is what separates "this process cannot read that file"
    /// from "this process may read any file on the machine and was still
    /// refused", and the two want different sentences.
    Denied {
        /// Whether `SeBackupPrivilege` was enabled in this process's token at
        /// the moment of the open.
        backup_enabled: bool,
        /// The operating system's own error code, kept so that the sentence can
        /// be checked against it rather than replacing it.
        code: u32,
    },
    /// The token does not hold the privilege that would have granted the open.
    ///
    /// This is the one refusal that a user can fix, and it is the reason
    /// [`Why::Denied`] cannot simply be reported on its own: without this
    /// variant, "you need to run this elevated" and "this file is genuinely
    /// unreadable" would be the same message.
    NotHeld {
        /// Which privilege was missing.
        needed: Privilege,
    },
    /// Another process holds the file open, and does not share it.
    ///
    /// The read was attempted more than once; `attempts` is how many times,
    /// because a file that is locked for a moment and one that is locked for
    /// the lifetime of a process look identical from a single attempt.
    InUse {
        /// How many opens were attempted before giving up.
        attempts: u32,
    },
    /// The path is larger than this crate will read into memory.
    ///
    /// A ceiling and not a truncation. Truncating would make the scan engine
    /// report the wrong file length in the same structure as the file's real
    /// length, and a scanner that is wrong about how long a file is, is wrong
    /// about what is in it. Refusing is a smaller lie.
    TooLarge {
        /// The file's size.
        size: u64,
        /// The ceiling that was applied.
        ceiling: u64,
    },
    /// The file is larger than the limit its *caller* set, having been measured
    /// as smaller when the directory was walked.
    ///
    /// A separate reason from [`Why::TooLarge`] because it says something
    /// different: not "this product will not read a file this big" but "this
    /// file was not this big a moment ago". The first is a policy, the second
    /// is a race, and a file that grew between being listed and being read is
    /// sometimes worth looking at rather than merely skipping.
    Grew {
        /// The limit the caller set, which the file has passed.
        limit: u64,
    },
    /// The machine had too little memory left to hold this file's bytes.
    ///
    /// # Why a scan refuses here rather than trying anyway
    ///
    /// Because the alternative is not a failed read, it is a dead process. Rust
    /// allocates infallibly by default: a `Vec` that cannot get its pages calls
    /// `handle_alloc_error`, which writes one line and calls `abort`. An abort
    /// cannot be caught, so it takes the whole front end with it — the window
    /// closes, the results are gone — and the record it leaves is a line in
    /// `logs/crash.log` that no user reads.
    ///
    /// That is not hypothetical. Measured on this machine: a scan that had
    /// enumerated its files and was partway through them vanished, and
    /// `crash.log` held three lines and a 4,193,376-byte request with 11,193,360
    /// bytes of commit left on the machine. From the user's seat the scan had
    /// counted the files and then exited by itself.
    ///
    /// A scan already has a better answer for a file it cannot examine — report
    /// it as a file that could not be read, with a reason, and go on to the next
    /// one — and running out of memory is a refusal like any other. This variant
    /// is what makes it one.
    ///
    /// # Why the fields are integers and the second one is an `Option`
    ///
    /// The integers, because this value is constructed on the path where
    /// allocation has just failed: a `String` would have to be allocated to
    /// report that allocation is impossible, and that second failure would
    /// happen inside the report of the first. [`Why::TooLarge`] is integers for
    /// the same reason.
    ///
    /// The `Option`, because "the machine said it has 11 MB left" and "the
    /// machine would not say" are different facts, and only the first one means
    /// closing something will help.
    OutOfMemory {
        /// How many bytes the read needed, which is the file's own length.
        size: u64,
        /// What the machine had left to commit when the read was refused.
        available: Option<u64>,
    },
    /// The path names something that is not a file: a directory, a device, a
    /// pipe.
    ///
    /// `CreateFileW` with `FILE_FLAG_BACKUP_SEMANTICS` opens directories
    /// happily, so this is not hypothetical — without the check, a directory
    /// would be read as a stream of bytes and hashed.
    NotAFile {
        /// The attributes Windows reported, which is what makes this
        /// diagnosable rather than a bare "not a file".
        attributes: u32,
    },
    /// The path could not be converted into the form the API needs.
    ///
    /// A path longer than `MAX_PATH` that is not absolute cannot be given a
    /// `\\?\` prefix, and one containing a `.` or `..` component cannot either,
    /// because the prefix turns off the normalisation that would have resolved
    /// it. Both are reported here rather than being attempted and failing with
    /// a confusing `ERROR_PATH_NOT_FOUND`.
    Unrepresentable {
        /// What was wrong with it.
        reason: &'static str,
    },
    /// The operating system said something none of the above covers.
    Os {
        /// The `GetLastError` value.
        code: u32,
        /// The operating system's own formatting of it.
        message: String,
    },
}

impl Why {
    /// Whether trying the same read again later could plausibly succeed.
    ///
    /// [`Why::InUse`] is the only one, and the retry has already happened by
    /// the time a caller sees this — so this is for a *caller's* retry policy,
    /// such as a realtime scanner that will see the file again on the next
    /// write notification.
    pub const fn is_transient(&self) -> bool {
        matches!(self, Why::InUse { .. })
    }

    /// Whether running the same read with more privilege could succeed.
    ///
    /// True for exactly the one reason a user can do something about, which is
    /// what a caller needs to decide whether to suggest elevation.
    pub const fn needs_elevation(&self) -> bool {
        matches!(self, Why::NotHeld { .. })
    }

    /// One sentence, in the second person, saying what happened and — where
    /// there is one — what to do about it.
    ///
    /// [`Refused`]'s `Display` prefixes the path; this is the half that does
    /// not depend on which file it was.
    pub fn sentence(&self) -> String {
        match self {
            Why::Gone => "no such file".to_string(),
            Why::Denied {
                backup_enabled: false,
                code,
            } => format!(
                "access denied (os error {code}), and this process does not hold \
                 SeBackupPrivilege, so it cannot read files whose permissions exclude it"
            ),
            Why::Denied {
                backup_enabled: true,
                code,
            } => format!(
                "access denied (os error {code}) even with SeBackupPrivilege enabled, which \
                 means the refusal is not the file's permissions: it is a mandatory integrity \
                 label, an encrypted file, or a filter driver"
            ),
            Why::NotHeld { needed } => format!(
                "not readable by this process: {needed} is not in its token, so {}",
                needed.remedy()
            ),
            Why::InUse { attempts } => format!(
                "in use by another process, which is not sharing it (tried {attempts} \
                 {}). It may become readable when that process closes it",
                if *attempts == 1 { "time" } else { "times" }
            ),
            Why::TooLarge { size, ceiling } => format!(
                "{} bytes, which is larger than the {ceiling}-byte ceiling this reader applies; \
                 the file was not read rather than read in part, because a scan of a prefix \
                 reported as a whole file is a wrong answer",
                thousands(*size)
            ),
            Why::Grew { limit } => format!(
                "it grew past the {} limit after the directory was walked, and is not scanned \
                 rather than scanned in part",
                bytes(*limit)
            ),
            Why::NotAFile { attributes } => format!(
                "not a file (Windows attributes {attributes:#010x}); a directory opened with \
                 backup semantics succeeds and would otherwise be read as a stream of bytes"
            ),
            Why::OutOfMemory { size, available } => {
                let wanted = size / (1024 * 1024);
                match available {
                    Some(left) => format!(
                        "{wanted} MiB, and this machine has {} MiB left to commit. The file was \
                         skipped rather than read: reading it would have taken the whole process \
                         down, and a scan that stops is worse than a file that is reported as \
                         unexamined. Close something, or give the machine more page file to \
                         commit against",
                        left / (1024 * 1024)
                    ),
                    None => format!(
                        "{wanted} MiB, and the machine would not say how much it has left to \
                         commit. The file was skipped rather than read, because an allocation \
                         that fails takes the whole process down"
                    ),
                }
            }
            Why::Unrepresentable { reason } => format!(
                "the path cannot be given to the operating system: {reason}"
            ),
            Why::Os { code, message } => format!("{message} (os error {code})"),
        }
    }
}

/// Group a number into thousands, so that `4294967296` reads as
/// `4,294,967,296` in a message a person has to parse.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A byte count as an adjective phrase: `1,024-byte`.
///
/// A function because "1024 bytes" and "1024-byte" are both wanted and neither
/// reads well with the other's punctuation, and because a lone `format!` at a
/// call site is where a missing thousands separator gets introduced.
fn bytes(n: u64) -> String {
    format!("{}-byte", thousands(n))
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.why.sentence())
    }
}

impl std::error::Error for Refused {}

impl Refused {
    /// Build one.
    pub fn new(path: impl Into<PathBuf>, why: Why) -> Self {
        Self {
            path: path.into(),
            why,
        }
    }

    /// The path, for a caller that is logging it separately from the reason.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl From<Refused> for io::Error {
    /// Convert, keeping the sentence.
    ///
    /// The kind is mapped to the closest `io::ErrorKind` so that a caller which
    /// only matches on the kind still behaves sensibly, and the *message* is
    /// [`Why::sentence`] so that a caller which prints it — which is every
    /// caller in this workspace — gets the useful half. Neither of those is
    /// [`Refused`] itself, which is why the conversion is lossy and why a
    /// caller that wants the structure should use the structured API.
    fn from(refused: Refused) -> Self {
        let kind = match refused.why {
            Why::Gone => io::ErrorKind::NotFound,
            Why::Denied { .. } | Why::NotHeld { .. } => io::ErrorKind::PermissionDenied,
            Why::InUse { .. } => io::ErrorKind::WouldBlock,
            Why::TooLarge { .. } | Why::Grew { .. } => io::ErrorKind::InvalidData,
            Why::NotAFile { .. } => io::ErrorKind::InvalidInput,
            Why::OutOfMemory { .. } => io::ErrorKind::OutOfMemory,
            Why::Unrepresentable { .. } => io::ErrorKind::InvalidInput,
            Why::Os { code, .. } => io::Error::from_raw_os_error(code as i32).kind(),
        };
        io::Error::new(kind, format!("{}: {}", refused.path.display(), refused.why.sentence()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_is_grouped_so_it_can_be_read() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(4294967296), "4,294,967,296");
        assert_eq!(thousands(1234567890123), "1,234,567,890,123");
    }

    #[test]
    fn an_out_of_memory_refusal_names_the_size_and_what_was_left() {
        // The pair of numbers is the whole diagnosis: "it needed 200 MB with
        // 80 MB left" is actionable in a way that "it crashed" is not.
        let sentence = Why::OutOfMemory {
            size: 200 * 1024 * 1024,
            available: Some(80 * 1024 * 1024),
        }
        .sentence();
        assert!(sentence.contains("200 MiB"), "{sentence}");
        assert!(sentence.contains("80 MiB"), "{sentence}");
        // It must also say what happened to the file, because the alternative a
        // reader assumes is that the file was scanned and found clean.
        assert!(sentence.contains("skipped"), "{sentence}");
    }

    #[test]
    fn an_out_of_memory_refusal_does_not_invent_a_figure_the_machine_refused() {
        let sentence = Why::OutOfMemory {
            size: 4 * 1024 * 1024,
            available: None,
        }
        .sentence();
        assert!(sentence.contains("would not say"), "{sentence}");
        assert!(!sentence.contains("0 MiB"), "{sentence}");
    }

    #[test]
    fn a_denial_says_whether_the_privilege_was_in_play() {
        // The two sentences have to differ, because the user's next action
        // differs: elevate, or look at the file.
        let without = Why::Denied {
            backup_enabled: false,
            code: 5,
        };
        let with = Why::Denied {
            backup_enabled: true,
            code: 5,
        };
        assert!(without.sentence().contains("does not hold"));
        assert!(with.sentence().contains("even with"));
        assert_ne!(without.sentence(), with.sentence());
    }

    #[test]
    fn only_one_reason_tells_the_user_to_elevate() {
        assert!(Why::NotHeld {
            needed: Privilege::Backup
        }
        .needs_elevation());
        assert!(!Why::Denied {
            backup_enabled: false,
            code: 5
        }
        .needs_elevation());
        assert!(!Why::Gone.needs_elevation());
        assert!(!Why::InUse { attempts: 3 }.needs_elevation());
    }

    #[test]
    fn a_lock_is_the_only_transient_reason() {
        assert!(Why::InUse { attempts: 2 }.is_transient());
        assert!(!Why::Gone.is_transient());
        assert!(!Why::TooLarge {
            size: 10,
            ceiling: 5
        }
        .is_transient());
        assert!(!Why::Grew { limit: 5 }.is_transient());
        assert!(!Why::Grew { limit: 5 }.needs_elevation());
        assert!(!Why::Denied {
            backup_enabled: true,
            code: 5
        }
        .is_transient());
    }

    #[test]
    fn a_refusal_prints_the_path_and_the_reason() {
        let refused = Refused::new(
            PathBuf::from(r"C:\Users\alice\secrets.kdbx"),
            Why::NotHeld {
                needed: Privilege::Backup,
            },
        );
        let text = refused.to_string();
        assert!(text.contains(r"C:\Users\alice\secrets.kdbx"), "{text}");
        assert!(text.contains("SeBackupPrivilege"), "{text}");
        assert!(text.contains("elevated"), "{text}");
        assert_eq!(refused.path(), Path::new(r"C:\Users\alice\secrets.kdbx"));
    }

    #[test]
    fn the_io_error_keeps_the_sentence_and_a_sensible_kind() {
        let cases = [
            (
                Why::Gone,
                io::ErrorKind::NotFound,
                "no such file",
            ),
            (
                Why::NotHeld {
                    needed: Privilege::Backup,
                },
                io::ErrorKind::PermissionDenied,
                "SeBackupPrivilege",
            ),
            (
                Why::InUse { attempts: 3 },
                io::ErrorKind::WouldBlock,
                "in use",
            ),
            (
                Why::TooLarge {
                    size: 8_589_934_592,
                    ceiling: 4_294_967_296,
                },
                io::ErrorKind::InvalidData,
                "8,589,934,592",
            ),
            (
                Why::NotAFile { attributes: 0x10 },
                io::ErrorKind::InvalidInput,
                "not a file",
            ),
            (
                Why::Unrepresentable {
                    reason: "it is relative and longer than MAX_PATH",
                },
                io::ErrorKind::InvalidInput,
                "MAX_PATH",
            ),
            (
                // The kind for an unrecognised operating system error is
                // whatever the platform says that code means — `os error 123`
                // is a filename error on Windows and something else elsewhere
                // — so the expectation is computed the same way rather than
                // pinned to a number that is only right on one platform. What
                // the test is really asserting is that the code survives into
                // the message at all.
                Why::Os {
                    code: 123,
                    message: "The filename, directory name, or volume label syntax is incorrect"
                        .to_string(),
                },
                io::Error::from_raw_os_error(123).kind(),
                "syntax is incorrect",
            ),
        ];
        for (why, kind, needle) in cases {
            let refused = Refused::new(PathBuf::from(r"C:\x"), why.clone());
            let io: io::Error = refused.into();
            assert_eq!(io.kind(), kind, "{why:?}");
            let text = io.to_string();
            assert!(text.contains(r"C:\x"), "{why:?}: {text}");
            assert!(text.contains(needle), "{why:?}: {text}");
        }
    }

    #[test]
    fn a_lock_reads_as_a_number_of_attempts() {
        assert!(Why::InUse { attempts: 1 }.sentence().contains("1 time"));
        assert!(Why::InUse { attempts: 4 }.sentence().contains("4 times"));
    }

    #[test]
    fn an_os_error_keeps_the_code_it_was_given() {
        let reflected = Why::Os {
            code: 123,
            message: "the operating system said".to_string(),
        };
        assert!(reflected.sentence().contains("123"));
        let io: io::Error = Refused::new(PathBuf::from("x"), reflected).into();
        assert_eq!(io.raw_os_error(), None, "the code is in the message, not the raw slot");
    }
}
