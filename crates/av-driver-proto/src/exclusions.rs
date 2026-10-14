//! Matching a path against the paths the user asked us not to look at.
//!
//! # What an exclusion is
//!
//! An exclusion is a **hole in the filter**. Every match is a file this product
//! has decided not to examine, so a matcher that is too eager is a matcher that
//! makes the product useless without saying so, and a matcher that is too
//! narrow is a matcher that keeps scanning a game's install directory and
//! costs the user frame rate.
//!
//! The asymmetry is not symmetric, though, and it decides the design: a missed
//! exclusion means more scanning, which is a performance problem, and a wrong
//! exclusion means an unscanned file, which is a security problem. Every
//! ambiguous case below resolves towards *not* matching.
//!
//! # The four rules
//!
//! 1. **Case-insensitive, ASCII-only.** Windows paths are case-insensitive, so
//!    the comparison folds ASCII case. It does *not* fold non-ASCII: doing that
//!    properly needs the operating system's uppercase tables, which are not
//!    reachable from this crate and are not a table anyone should reimplement.
//!    The consequence is stated rather than hidden — `C:\Ä` and `C:\ä` are
//!    different strings to this matcher, so an exclusion written in one case
//!    will not match a path in the other. That is a missed exclusion, which is
//!    more scanning. It is never a wrong exclusion, because folding can only
//!    *widen* a match and not folding can only narrow one.
//!
//! 2. **Component boundaries, not string prefixes.** `C:\Windows` matches
//!    `C:\Windows\System32\x.dll` and does not match `C:\WindowsApps`. The
//!    character after the match must be a separator.
//!
//! 3. **A stream name is the same file.** `C:\x.txt:evil` is the file
//!    `C:\x.txt`, so excluding `C:\x.txt` excludes its streams and a `:` after
//!    the match is a boundary. Excluding a *directory* would have covered them
//!    anyway, but a file exclusion that left the streams reachable would be a
//!    bypass with a name.
//!
//! 4. **A bare drive spec is not the drive.** `C:` names the process's current
//!    directory on `C:`, not the volume root — that is `C:\`. An exclusion of
//!    `C:` therefore matches only a path that is exactly `C:`, and a user who
//!    meant the whole volume has to write `C:\`. Widening `C:` to the volume
//!    would be the one direction this matcher is not allowed to err in.
//!
//! # What is not handled, and why
//!
//! * **Short names.** An exclusion written `C:\PROGRA~1` will not match a
//!   normalised `C:\Program Files`, and neither will the reverse. Resolving
//!   requires the file system, once per comparison, on a path that is being
//!   opened — and the exclusion's own spelling is a string a user typed, which
//!   is not a file that can be resolved at all.
//! * **Trailing dots and spaces.** `C:\Windows.` and `C:\Windows ` are
//!   different strings here and the same directory to Win32. Same trade as
//!   short names, and the same direction of error.
//! * **Traversal.** A path containing `..` is *not* matched against anything,
//!   but this module does not check for it — [`crate::path::device_to_dos_path`]
//!   rejects such a path before it can reach here, and
//!   `crates/av-driver` does not have another way to produce one. The
//!   precondition is stated on [`find_exclusion`] rather than paid for on every
//!   comparison, because the check is a scan of the whole path and this
//!   function runs once per intercepted file operation on the machine.
//! * **Entries are validated at insert**, though, because the table is
//!   populated from an IOCTL a few times an hour at most and a traversal entry
//!   is meaningless in every case.

use core::fmt;

use crate::path::eq_ignore_ascii_case;

/// How many exclusion entries the wire format and the default table hold.
///
/// Sixty-four, and the number is a compromise between two real ones. Fewer
/// would make the feature useless to the people who need it most: a developer
/// with several build trees, a gamer with a library of installed games under a
/// launcher, and an administrator excluding a network share for a line-of-
/// business application can each plausibly want a few dozen. More would grow
/// [`crate::wire::ExclusionBuffer`] — already 33 KB, allocated from nonpaged
/// pool by the I/O manager for the duration of every `IOCTL_SET_EXCLUSIONS`
/// call — and would grow a linear scan that runs on every file operation.
///
/// Not configurable at runtime: the table's size is the bound on the scan, and
/// a bound that a hostile caller could raise is not a bound.
pub const MAX_EXCLUSIONS: usize = 64;

// ---------------------------------------------------------------------------
// The exclusions the driver starts with
// ---------------------------------------------------------------------------

/// Directories that are never sent to user mode for a decision.
///
/// This is not a user preference and it is not a starting point a user can
/// narrow. It is the guard against the failure mode the decision timeout exists
/// for: a driver that can refuse to open
/// `\Device\HarddiskVolume3\Windows\System32\kernel32.dll` is a driver that can
/// produce a machine which does not boot, and no detection is worth a machine
/// that does not boot. `av_driver_proto::decision`'s fail-open contract is the
/// same argument one layer down, and neither is negotiable at runtime.
///
/// # Why the product's own directories are in the list
///
/// The last two entries are the product's install directory and its data
/// directory, and they are here for the opposite reason to the first two. The
/// Windows directories are here so the machine keeps running; the product's own
/// are here so the product keeps running. Every file this product writes — its
/// rule database, its quarantine payloads, its cache, its log — is a file the
/// driver would otherwise ask the service to decide on, which is a question the
/// service would answer by scanning a file it wrote itself. That is a loop: a
/// scan writes a log line, the log line is a file operation, the file operation
/// is scanned, and the scan writes a log line. The exclusions are what stops it
/// at the first step rather than at a depth limit.
///
/// # The spelling matters
///
/// [`matches_prefix`] compares whole components, so `C:\ProgramData\Wenle` does
/// **not** match `C:\ProgramData\WenleAV\...`. An entry naming a directory this
/// product does not use is an entry that excludes nothing, and this list once
/// named `C:\ProgramData\Wenle` while the product's directory is `WenleAV` — a
/// guard that reported itself as present while covering nothing at all. The
/// check that keeps the two spellings equal is a test in `av-service` —
/// `the_products_own_directories_are_excluded_from_driver_decisions` — and it
/// lives there because that is the only crate that can see both this constant
/// and the product's real paths.
///
/// # The drive letter is a limitation, stated
///
/// The first two entries and the last two are spelled with `C:`, so on a machine
/// whose system drive is not `C:` they match nothing. The driver could learn the
/// real letter — its volume cache maps device paths to letters — but that cache
/// is filled lazily by the first operation on each volume, and this table is
/// filled before filtering starts, when the cache is empty. So the honest
/// position is that the boot-safety guard is effective on a default Windows
/// installation and inert on one where Windows is on another drive, and a
/// machine in that state should be treated as having a driver without this
/// guard rather than with it.
///
/// # What this list does not cover, and the fix for that
///
/// These are the *default* locations. A release is an unpacked tree — the
/// product has no installer, so it runs from wherever a user put it — and the
/// service can be installed from there with a data directory that is not the
/// default either. A tree unpacked into `C:\Users\me\Downloads\WenleAV` is
/// covered by none of these entries, and the loop described above applies to it
/// in full.
///
/// The remedy is not a longer constant. It is the service pushing its own
/// [`crate::ioctl`] exclusions at start-up, from the same `av_core::paths`
/// layout it is already using, at which point this list goes back to being only
/// the boot-safety guard it was meant to be. That needs the driver's control
/// device to answer `IRP_MJ_DEVICE_CONTROL`, which it does not do yet: the
/// `IOCTL_SET_EXCLUSIONS` code and its 33 KB buffer are defined and tested, and
/// nothing on the kernel side reads them.
pub const BUILT_IN: [&str; 4] = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\WenleAV",
];

/// Longest exclusion entry, in UTF-16 code units.
///
/// `MAX_PATH` is 260, and this is 260. A longer exclusion is refused rather
/// than truncated, for the same reason a longer path is refused in
/// [`crate::wire`]: half an exclusion is an exclusion that matches the wrong
/// thing, and the wrong thing here is a hole.
///
/// The consequence is stated: a directory whose path exceeds 260 characters
/// cannot be excluded. That is a real limit, and the alternative — a larger
/// per-entry bound — multiplies by [`MAX_EXCLUSIONS`] in a structure that is
/// already the largest thing in this protocol.
pub const MAX_EXCLUSION_UNITS: usize = 260;

/// Why an entry was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExclusionError {
    /// The entry was empty. An empty entry would match only an empty path, and
    /// refusing it at insert time is what makes "no entry matches the empty
    /// path" a property of the table rather than of the matcher.
    Empty,
    /// The entry was longer than [`MAX_EXCLUSION_UNITS`].
    TooLong {
        /// Units the entry needed.
        needed: usize,
    },
    /// The table was full.
    TableFull,
    /// The entry contained a `.` or `..` component.
    ///
    /// Meaningless as an exclusion and, worse, an escape: an entry of
    /// `C:\Windows\..` would match any path starting anywhere above
    /// `C:\Windows`, which is a hole the size of the volume.
    NotNormalised,
    /// The entry contained an embedded NUL.
    EmbeddedNul,
}

impl ExclusionError {
    /// A short phrase for a log line.
    pub const fn as_str(self) -> &'static str {
        match self {
            ExclusionError::Empty => "empty exclusion",
            ExclusionError::TooLong { .. } => "exclusion too long",
            ExclusionError::TableFull => "exclusion table full",
            ExclusionError::NotNormalised => "exclusion has a . or .. component",
            ExclusionError::EmbeddedNul => "exclusion contains an embedded NUL",
        }
    }
}

impl fmt::Display for ExclusionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExclusionError::TooLong { needed } => {
                write!(f, "{}: {needed} units", self.as_str())
            }
            other => f.write_str(other.as_str()),
        }
    }
}

/// Whether the *entry* is a bare drive spec — two units, a letter and a colon.
///
/// See rule 4 in the module documentation.
fn is_bare_drive(entry: &[u16]) -> bool {
    entry.len() == 2 && entry[1] == u16::from(b':')
}

/// Whether `path` matches the single exclusion `entry`.
///
/// `path` must be normalised: no `.` or `..` components and no embedded NUL.
/// See the module documentation for why that is a precondition and not a check.
pub fn matches_prefix(path: &[u16], entry: &[u16]) -> bool {
    if entry.is_empty() || path.is_empty() {
        return false;
    }

    // A trailing separator on the entry says "this entry already ends at a
    // boundary", which is exactly the root case: `C:\` is a boundary and `C:`
    // is not. Stripping it and treating the two the same is what would turn
    // `C:\` into the drive-relative `C:`.
    let ends_with_separator = entry[entry.len() - 1] == u16::from(b'\\');
    let effective = if ends_with_separator {
        &entry[..entry.len() - 1]
    } else {
        entry
    };

    // `\` on its own, or `\` repeated. There is no path this names.
    if effective.is_empty() {
        return false;
    }

    if path.len() < effective.len() || !eq_ignore_ascii_case(&path[..effective.len()], effective) {
        return false;
    }

    // The prefix matched. Everything below is the boundary question.
    let bare_drive = is_bare_drive(effective);

    if path.len() == effective.len() {
        // Exact. A trailing separator on the entry does not make it match
        // *less*: `C:\Windows\` names the same directory as `C:\Windows`.
        // A bare drive is the exception, because the two spellings name
        // different things — `C:\` is the volume root and `C:` is
        // drive-relative, so an entry of `C:\` must not match the path `C:`.
        return !bare_drive || !ends_with_separator;
    }

    if ends_with_separator {
        // The entry ended at a boundary of its own. It may only match a path
        // that continues with a separator at exactly that position, which is
        // where the entry's own separator was. Returning `true`
        // unconditionally here is the bug that lets `C:\Windows\` match
        // `C:\WindowsApps`: the trailing separator is a claim about the
        // *entry's* end, not a licence to skip the check on the path.
        return path[effective.len()] == u16::from(b'\\');
    }

    if bare_drive {
        // `C:` is drive-relative. It has already failed the exact test above,
        // so it does not match — see rule 4.
        return false;
    }

    match path[effective.len()] {
        // The ordinary component boundary.
        c if c == u16::from(b'\\') => true,
        // A stream separator: `C:\x.txt:evil` is the file `C:\x.txt`. Only
        // treated as a boundary for an entry that names a location — a bare
        // drive spec is handled above and never reaches here.
        c if c == u16::from(b':') => true,
        // Everything else, including `.` — which is what keeps `C:\x.txt` from
        // matching `C:\x.txt.bak`, and `C:\Windows` from matching
        // `C:\WindowsApps`.
        _ => false,
    }
}

/// Find the first entry that matches `path`.
///
/// Returns the entry's index rather than a bool so that a driver can log which
/// exclusion did the excluding — an operator debugging an over-broad exclusion
/// needs to know which one it was, and an index is enough for that once the
/// table can be listed.
///
/// `path` must be normalised: no `.` or `..` components and no embedded NUL.
/// [`crate::path::device_to_dos_path`] guarantees both, and it is the only
/// producer of the paths this is called with.
pub fn find_exclusion<'a, I>(path: &[u16], entries: I) -> Option<usize>
where
    I: IntoIterator<Item = &'a [u16]>,
{
    entries
        .into_iter()
        .enumerate()
        .find_map(|(index, entry)| matches_prefix(path, entry).then_some(index))
}

/// Whether any entry matches `path`. See [`find_exclusion`] for the
/// precondition.
pub fn is_excluded<'a, I>(path: &[u16], entries: I) -> bool
where
    I: IntoIterator<Item = &'a [u16]>,
{
    entries.into_iter().any(|entry| matches_prefix(path, entry))
}

/// Validate an entry without storing it.
///
/// Used by [`FixedExclusionTable::insert`] and by the driver when it loads a
/// table from [`crate::wire::ExclusionBuffer`], so that the two paths cannot
/// disagree about what a valid entry is.
pub fn validate_entry(entry: &[u16]) -> Result<(), ExclusionError> {
    if entry.is_empty() {
        return Err(ExclusionError::Empty);
    }
    if entry.len() > MAX_EXCLUSION_UNITS {
        return Err(ExclusionError::TooLong {
            needed: entry.len(),
        });
    }
    if entry.contains(&0) {
        return Err(ExclusionError::EmbeddedNul);
    }
    // Component-wise, so `C:\..config` — a directory whose name begins with
    // dots — is fine and `C:\Windows\..` is not.
    let mut start = 0;
    while start <= entry.len() {
        let end = entry[start..]
            .iter()
            .position(|&c| c == u16::from(b'\\'))
            .map(|i| i + start)
            .unwrap_or(entry.len());
        let component = &entry[start..end];
        if component == [u16::from(b'.')] || component == [u16::from(b'.'), u16::from(b'.')] {
            return Err(ExclusionError::NotNormalised);
        }
        if end == entry.len() {
            break;
        }
        start = end + 1;
    }
    Ok(())
}

/// A fixed-capacity table of exclusion entries, packed.
///
/// # Sizing and where it lives
///
/// The type is `N * M * 2 + N * 2` bytes. At the protocol's defaults —
/// [`MAX_EXCLUSIONS`] and [`MAX_EXCLUSION_UNITS`] — that is 33,408 bytes.
///
/// **A value of this type does not belong on a kernel stack.** A kernel stack
/// is 12 KB by default on x64 and this is nearly three times that, so a local
/// of this type is a bugcheck waiting for the first machine that takes an
/// interrupt at the wrong moment. [`FixedExclusionTable::new`] is `const`
/// precisely so that the intended owner can be a `static`, which costs
/// zero-initialised bss and no pool at all:
///
/// ```text
/// static EXCLUSIONS: KernelMutex<FixedExclusionTable<64, 260>> =
///     KernelMutex::new(FixedExclusionTable::new());
/// ```
///
/// A caller that must have it in pool should allocate the memory first and
/// initialise through the pointer, *not* write `Box::new(Self::new())` — the
/// latter builds the whole 33 KB value on the stack and then copies it, which
/// is the hazard this paragraph exists to prevent. `crates/av-driver` says
/// which of the two it does.
///
/// # Rows
///
/// Rows are fixed-size and each has its own used length, rather than the
/// entries being packed end to end with separators. Packing would trade 33 KB
/// for a few hundred bytes and would make every insert a memmove of everything
/// after it, on a table that is rewritten wholesale by an IOCTL anyway. Fixed
/// rows make [`FixedExclusionTable::clear`] a single store and an insert a
/// single bounds check.
pub struct FixedExclusionTable<const N: usize, const M: usize> {
    rows: [[u16; M]; N],
    units: [u16; N],
    len: usize,
}

impl<const N: usize, const M: usize> FixedExclusionTable<N, M> {
    /// An empty table. `const`, so it can be a `static`.
    pub const fn new() -> Self {
        Self {
            rows: [[0; M]; N],
            units: [0; N],
            len: 0,
        }
    }

    /// Empty the table.
    ///
    /// Writes one field. The rows are *not* cleared, because nothing reads a
    /// row past its entry in `FixedExclusionTable::units` — which is what
    /// makes this safe to call on memory that has just been allocated and has
    /// never held a table.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// How many entries are stored.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// How many fit.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Whether the table is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The entry at `index`, clamped to its used length.
    pub fn entry(&self, index: usize) -> Option<&[u16]> {
        if index >= self.len {
            return None;
        }
        // Clamped rather than trusted: `insert` writes a value no larger than
        // `M`, but a table in a `static` that someone later wrote through a
        // raw pointer is not something this can rule out, and a length field
        // that can exceed its buffer is the one bug class this whole crate is
        // arranged to make impossible.
        let units = (self.units[index] as usize).min(M);
        Some(&self.rows[index][..units])
    }

    /// Every entry, in order. The iterator [`find_exclusion`] wants.
    pub fn entries(&self) -> impl Iterator<Item = &[u16]> {
        let len = self.len;
        (0..len).map(move |i| {
            let units = (self.units[i] as usize).min(M);
            &self.rows[i][..units]
        })
    }

    /// The first entry matching `path`, or `None`. See [`find_exclusion`] for
    /// the precondition on `path`.
    pub fn find(&self, path: &[u16]) -> Option<usize> {
        let mut found = None;
        for (index, entry) in self.entries().enumerate() {
            if matches_prefix(path, entry) {
                found = Some(index);
                break;
            }
        }
        found
    }

    /// Whether any entry matches `path`.
    pub fn is_excluded(&self, path: &[u16]) -> bool {
        self.find(path).is_some()
    }

    /// Add an entry, rejecting an empty, oversized or unnormalised one.
    ///
    /// A duplicate is stored rather than detected. Duplicates cost a little
    /// scan time and nothing else, and detecting them would need a comparison
    /// against every existing entry — the same work as a lookup — for a table
    /// that is replaced wholesale rather than appended to.
    pub fn insert(&mut self, entry: &[u16]) -> Result<(), ExclusionError> {
        validate_entry(entry)?;
        if self.len >= N {
            return Err(ExclusionError::TableFull);
        }
        // `validate_entry` proved `entry.len() <= M` whenever `M` is at least
        // `MAX_EXCLUSION_UNITS`, and the bound below is what makes it true for
        // a table declared with a smaller `M` than the protocol's.
        let take = entry.len().min(M);
        self.rows[self.len][..take].copy_from_slice(&entry[..take]);
        self.units[self.len] = take as u16;
        self.len += 1;
        Ok(())
    }

    /// Replace every entry from an iterator, stopping at the first rejection.
    ///
    /// All-or-nothing in effect: the driver only calls this with a table that
    /// has already been validated entry by entry, and a rejection part way
    /// through leaves the table holding a prefix of the input rather than
    /// nothing. That is stated rather than hidden — a caller that wants
    /// all-or-nothing must validate first, and the driver does, because it is
    /// loading from a wire structure whose entries it must check anyway.
    pub fn replace_from<'a, I>(&mut self, entries: I) -> Result<usize, ExclusionError>
    where
        I: IntoIterator<Item = &'a [u16]>,
    {
        self.clear();
        let mut count = 0;
        for entry in entries {
            self.insert(entry)?;
            count += 1;
        }
        Ok(count)
    }
}

impl<const N: usize, const M: usize> Default for FixedExclusionTable<N, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const M: usize> fmt::Debug for FixedExclusionTable<N, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Written out rather than assembled from `debug_struct`/`debug_list`,
        // because a `DebugList` borrows the formatter and cannot be nested as a
        // field. Bounded, like every other `Debug` in this crate: the rows are
        // the bulky part and the interesting facts are how many are used and
        // what they say.
        write!(
            f,
            "FixedExclusionTable {{ used: {}, capacity: {}, row_units: {}, entries: [",
            self.len, N, M
        )?;
        for (index, entry) in self.entries().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", crate::path::display_u16(entry))?;
        }
        f.write_str("] }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn entry(s: &str) -> Vec<u16> {
        utf16(s)
    }

    fn matches(path: &str, exclusion: &str) -> bool {
        matches_prefix(&utf16(path), &utf16(exclusion))
    }

    // --- the near-miss cases, which are the point of the module ------------

    /// The case the module documentation leads with. A string-prefix matcher
    /// gets this wrong, and getting it wrong means an exclusion of a Windows
    /// directory silently excludes every application whose name starts with
    /// "Windows".
    #[test]
    fn a_prefix_that_is_not_a_component_does_not_match() {
        assert!(!matches(r"C:\WindowsApps\evil.exe", r"C:\Windows"));
        assert!(!matches(r"C:\Windows.old\x", r"C:\Windows"));
        assert!(!matches(r"C:\Windows7\x", r"C:\Windows"));
        assert!(!matches(r"C:\WINdowsApps", r"C:\Windows"));
    }

    /// The same hazard with a space: `C:\Program Files (x86)` is not
    /// `C:\Program Files`, and a matcher that treated a space as a boundary
    /// would exclude the 32-bit program directory for an exclusion of the
    /// 64-bit one.
    #[test]
    fn a_space_is_not_a_component_boundary() {
        assert!(!matches(
            r"C:\Program Files (x86)\app.exe",
            r"C:\Program Files"
        ));
        assert!(matches(r"C:\Program Files\app.exe", r"C:\Program Files"));
    }

    /// A file exclusion must not swallow its neighbours, and a `.` is not a
    /// boundary.
    #[test]
    fn a_dot_is_not_a_component_boundary() {
        assert!(!matches(r"C:\x.txt.bak", r"C:\x.txt"));
        assert!(!matches(r"C:\x.txt2", r"C:\x.txt"));
        assert!(matches(r"C:\x.txt", r"C:\x.txt"));
    }

    /// A colon *is* a boundary, because `name:stream` is the same file. A file
    /// exclusion that left the streams reachable would be a bypass with a name.
    #[test]
    fn a_colon_is_a_component_boundary_for_a_stream() {
        assert!(matches(r"C:\x.txt:evil", r"C:\x.txt"));
        assert!(matches(r"C:\x.txt:$DATA", r"C:\x.txt"));
        // But the colon rule must not rescue the near-misses above.
        assert!(!matches(r"C:\x.txt.bak:evil", r"C:\x.txt"));
    }

    /// A bare drive spec is drive-relative. Widening it to the volume is the
    /// one direction this matcher may not err in.
    #[test]
    fn a_bare_drive_spec_is_not_the_volume_root() {
        assert!(
            !matches(r"C:\Windows\System32\cmd.exe", "C:"),
            "`C:` is drive-relative and does not name the volume"
        );
        assert!(!matches(r"C:\", "C:"));
        // It matches itself and nothing else.
        assert!(matches("C:", "C:"));

        // And the entry that *does* name the volume.
        assert!(matches(r"C:\Windows\System32\cmd.exe", r"C:\"));
        assert!(matches(r"C:\", r"C:\"));
        assert!(matches(r"D:\anything", r"D:\"));
    }

    // --- the ordinary cases ------------------------------------------------

    /// A directory entry matches itself and everything under it.
    #[test]
    fn a_directory_entry_matches_itself_and_its_subtree() {
        let dir = r"C:\Windows";
        assert!(matches(r"C:\Windows", dir));
        assert!(matches(r"C:\Windows\System32", dir));
        assert!(matches(r"C:\Windows\System32\cmd.exe", dir));
        assert!(matches(r"C:\Windows\a\b\c\d\e\f", dir));
    }

    /// A trailing separator on the entry is equivalent to none, and both forms
    /// match the directory itself. Writing the separator is what makes `C:\`
    /// mean the volume rather than `C:`, so the two spellings must not be
    /// conflated — but for a named directory they are the same exclusion.
    #[test]
    fn a_trailing_separator_on_a_directory_entry_is_equivalent() {
        assert!(matches(r"C:\Windows\System32", r"C:\Windows\"));
        assert!(matches(r"C:\Windows", r"C:\Windows\"));
        assert!(matches(r"C:\Windows\", r"C:\Windows\"));
        assert!(!matches(r"C:\WindowsApps", r"C:\Windows\"));
        // And the entry's own trailing separator does not match itself as a
        // doubled separator.
        assert!(!matches(r"C:\\Windows", r"C:\Windows"));
    }

    /// Case folding, ASCII-only. The non-ASCII case is asserted *not* to match,
    /// which pins the limitation as behaviour rather than leaving it as a
    /// sentence in a comment.
    #[test]
    fn matching_folds_ascii_case_and_only_ascii_case() {
        assert!(matches(r"c:\windows\system32", r"C:\WINDOWS"));
        assert!(matches(r"C:\WINDOWS\System32", r"c:\windows"));
        assert!(matches(r"C:\WiNdOwS", r"c:\WINDOWS"));

        // The stated limitation.
        assert!(!matches(r"C:\Äpfel\x", r"C:\äpfel"));
        // An ASCII path still matches a non-ASCII entry's ASCII prefix only
        // when the boundary is right.
        assert!(matches(r"C:\ä\x", r"C:\ä"));
        assert!(!matches(r"C:\äx", r"C:\ä"));
    }

    /// Entries that name nothing are refused rather than matching everything.
    #[test]
    fn degenerate_entries_match_nothing() {
        assert!(!matches(r"C:\anything", ""));
        assert!(!matches("", ""));
        assert!(!matches(r"C:\anything", r"\"));
        assert!(!matches(r"C:\anything", r"\\"));
        assert!(
            !matches("", r"C:\Windows"),
            "the empty path matches nothing"
        );
    }

    /// An entry with no drive letter still works component-wise.
    #[test]
    fn an_entry_without_a_drive_still_matches_component_wise() {
        assert!(matches(r"\Windows\System32", r"\Windows"));
        assert!(!matches(r"\WindowsApps", r"\Windows"));
    }

    // --- validation --------------------------------------------------------

    /// A traversal entry is an escape the size of the volume, and it is refused
    /// at insert rather than ignored at match.
    #[test]
    fn a_traversal_entry_is_refused() {
        assert_eq!(
            validate_entry(&entry(r"C:\Windows\..")),
            Err(ExclusionError::NotNormalised)
        );
        assert_eq!(
            validate_entry(&entry(r"C:\..\Windows")),
            Err(ExclusionError::NotNormalised)
        );
        assert_eq!(
            validate_entry(&utf16(r"C:\W\.\x")),
            Err(ExclusionError::NotNormalised)
        );
        // A component that merely begins with dots is a name, not a traversal.
        assert_eq!(validate_entry(&entry(r"C:\..config")), Ok(()));
        assert_eq!(validate_entry(&entry(r"C:\...")), Ok(()));
        assert_eq!(validate_entry(&entry(r"C:\a.b.c")), Ok(()));
    }

    /// Empty, oversized and NUL-containing entries are refused, each with its
    /// own error so a service can say which entry was bad.
    #[test]
    fn invalid_entries_are_refused_with_a_specific_reason() {
        assert_eq!(validate_entry(&[]), Err(ExclusionError::Empty));

        let long = vec![u16::from(b'A'); MAX_EXCLUSION_UNITS + 1];
        assert_eq!(
            validate_entry(&long),
            Err(ExclusionError::TooLong {
                needed: MAX_EXCLUSION_UNITS + 1
            })
        );
        // Exactly at the limit is fine.
        let exact = vec![u16::from(b'A'); MAX_EXCLUSION_UNITS];
        assert_eq!(validate_entry(&exact), Ok(()));

        let mut nul = entry(r"C:\a");
        nul.push(0);
        nul.extend(utf16(r"\b"));
        assert_eq!(validate_entry(&nul), Err(ExclusionError::EmbeddedNul));
    }

    /// Every error renders, and distinguishingly.
    #[test]
    fn exclusion_errors_render_distinctly() {
        let errors = [
            ExclusionError::Empty,
            ExclusionError::TooLong { needed: 300 },
            ExclusionError::TableFull,
            ExclusionError::NotNormalised,
            ExclusionError::EmbeddedNul,
        ];
        for (i, a) in errors.iter().enumerate() {
            let rendered = a.to_string();
            assert!(!rendered.is_empty());
            for b in &errors[i + 1..] {
                assert_ne!(rendered, b.to_string());
            }
        }
    }

    // --- the table ---------------------------------------------------------

    /// A small table for the tests that are about the table rather than about
    /// matching. Its shape mirrors the real one.
    type Table = FixedExclusionTable<4, MAX_EXCLUSION_UNITS>;

    #[test]
    fn a_new_table_matches_nothing() {
        let table = Table::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.capacity(), 4);
        assert_eq!(table.entries().count(), 0);
        assert!(!table.is_excluded(&entry(r"C:\Windows")));
        assert_eq!(table.entry(0), None);
    }

    #[test]
    fn inserted_entries_are_found_by_index() {
        let mut table = Table::new();
        table.insert(&entry(r"C:\Windows")).expect("room");
        table.insert(&entry(r"C:\Program Files")).expect("room");
        table.insert(&entry(r"D:\Games")).expect("room");
        assert_eq!(table.len(), 3);

        assert_eq!(table.find(&entry(r"C:\Windows\System32\cmd.exe")), Some(0));
        assert_eq!(table.find(&entry(r"C:\Program Files (x86)\a.exe")), None);
        assert_eq!(table.find(&entry(r"D:\Games\steam\a.dll")), Some(2));
        assert_eq!(table.find(&entry(r"E:\nothing")), None);
        assert!(table.is_excluded(&entry(r"c:\windows\a")));
    }

    /// The *first* match is reported, which is what makes the index a stable
    /// answer for a log line.
    #[test]
    fn the_first_matching_entry_is_reported() {
        let mut table = Table::new();
        table.insert(&entry(r"C:\Windows")).expect("room");
        table.insert(&entry(r"C:\Windows\System32")).expect("room");
        assert_eq!(
            table.find(&entry(r"C:\Windows\System32\cmd.exe")),
            Some(0),
            "the earlier entry is the answer"
        );
    }

    #[test]
    fn a_full_table_refuses_further_entries() {
        let mut table = Table::new();
        for i in 0..4 {
            table
                .insert(&entry(&format!(r"C:\dir{i}")))
                .expect("room for four");
        }
        assert_eq!(
            table.insert(&entry(r"C:\fifth")),
            Err(ExclusionError::TableFull)
        );
        assert_eq!(table.len(), 4);
        // And the four that were there still work.
        assert_eq!(table.find(&entry(r"C:\dir3\x")), Some(3));
    }

    /// An invalid entry is refused by `insert` and does not consume a slot, so
    /// a service sending a bad table cannot fill the table with rejections.
    #[test]
    fn an_invalid_entry_does_not_consume_a_slot() {
        let mut table = Table::new();
        assert_eq!(table.insert(&[]), Err(ExclusionError::Empty));
        assert_eq!(
            table.insert(&entry(r"C:\..")),
            Err(ExclusionError::NotNormalised)
        );
        assert_eq!(table.len(), 0, "rejected entries must not be stored");
        assert_eq!(table.insert(&entry(r"C:\ok")), Ok(()));
        assert_eq!(table.len(), 1);
    }

    /// `clear` empties without touching the rows, and an entry inserted after a
    /// clear must not inherit the previous occupant's length.
    #[test]
    fn clear_empties_the_table_and_rows_do_not_leak() {
        let mut table = Table::new();
        table
            .insert(&entry(r"C:\a\very\long\path\here"))
            .expect("room");
        table.insert(&entry(r"C:\b")).expect("room");
        assert_eq!(table.len(), 2);

        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.entries().count(), 0);
        assert_eq!(table.entry(0), None);
        assert!(!table.is_excluded(&entry(r"C:\a\very\long\path\here")));

        // A shorter entry inserted into the row the long one used must have
        // its own length, not the old one.
        table.insert(&entry(r"C:\b")).expect("room");
        assert_eq!(table.entry(0), Some(&entry(r"C:\b")[..]));
        assert!(!table.is_excluded(&entry(r"C:\a\very")));
    }

    /// `replace_from` is what an `IOCTL_SET_EXCLUSIONS` load does.
    #[test]
    fn replace_from_swaps_the_whole_table() {
        let mut table = Table::new();
        table.insert(&entry(r"C:\old")).expect("room");

        let fresh = [entry(r"C:\one"), entry(r"C:\two")];
        let count = table
            .replace_from(fresh.iter().map(Vec::as_slice))
            .expect("all valid");
        assert_eq!(count, 2);
        assert_eq!(table.len(), 2);
        assert!(!table.is_excluded(&entry(r"C:\old\x")));
        assert!(table.is_excluded(&entry(r"C:\two\x")));
    }

    /// A rejected entry part way through a `replace_from` leaves a prefix. That
    /// is documented, and this pins it so the behaviour is known rather than
    /// assumed — a caller that needs all-or-nothing must validate first.
    #[test]
    fn replace_from_leaves_a_prefix_when_an_entry_is_rejected() {
        // A real traversal, not `C:\..bad`: that one is a directory whose
        // *name* begins with dots, which `validate_entry` accepts on purpose.
        // Using it here would have made the test assert the opposite of what
        // the validator does.
        let mut table = Table::new();
        assert_eq!(validate_entry(&entry(r"C:\..bad")), Ok(()));
        let mixed = [
            entry(r"C:\good"),
            entry(r"C:\a\..\b"),
            entry(r"C:\unreached"),
        ];
        assert_eq!(
            table.replace_from(mixed.iter().map(Vec::as_slice)),
            Err(ExclusionError::NotNormalised)
        );
        assert_eq!(table.len(), 1, "the good entry stayed");
        assert!(table.is_excluded(&entry(r"C:\good\x")));
        assert!(!table.is_excluded(&entry(r"C:\unreached")));
    }

    /// The table's own row bound is enforced even when the protocol's is not:
    /// a table declared with a smaller `M` must not be able to store more than
    /// `M` units.
    #[test]
    fn a_narrow_row_still_bounds_what_is_stored() {
        // Four rows of eight units, which is smaller than the protocol's limit.
        let mut table = FixedExclusionTable::<4, 8>::new();
        let long = entry(r"C:\aaaa\bbbb\cccc");
        assert!(long.len() > 8);
        // `validate_entry` passes it — it is under `MAX_EXCLUSION_UNITS` — and
        // the row bound is what truncates it. Pinned so that a table declared
        // too small is a known narrowing rather than a buffer overrun.
        table.insert(&long).expect("fits the row");
        assert_eq!(table.entry(0).map(<[u16]>::len), Some(8));
    }

    /// The iterator and the index accessor agree, which matters because
    /// [`crate::wire`]'s loader uses one and the matcher uses the other.
    #[test]
    fn entries_and_entry_agree() {
        let mut table = Table::new();
        for path in [r"C:\a", r"C:\bb", r"C:\ccc"] {
            table.insert(&entry(path)).expect("room");
        }
        for (index, slice) in table.entries().enumerate() {
            assert_eq!(Some(slice), table.entry(index));
        }
        assert_eq!(table.entry(3), None);
        assert_eq!(table.entry(usize::MAX), None);
    }

    /// `find_exclusion` over a plain slice of slices, which is what the wire
    /// loader and the tests both produce.
    #[test]
    fn the_free_function_matches_the_table() {
        let entries: Vec<Vec<u16>> = [r"C:\Windows", r"D:\Games"]
            .iter()
            .map(|s| entry(s))
            .collect();
        let slices: Vec<&[u16]> = entries.iter().map(Vec::as_slice).collect();

        assert_eq!(
            find_exclusion(&entry(r"C:\Windows\x"), slices.iter().copied()),
            Some(0)
        );
        assert_eq!(
            find_exclusion(&entry(r"D:\Games\x"), slices.iter().copied()),
            Some(1)
        );
        assert_eq!(
            find_exclusion(&entry(r"E:\x"), slices.iter().copied()),
            None
        );
        assert!(is_excluded(&entry(r"c:\windows"), slices.iter().copied()));
        assert!(!is_excluded(
            &entry(r"C:\WindowsApps"),
            slices.iter().copied()
        ));
        assert!(!is_excluded(&entry(r"C:\Windows"), std::iter::empty()));
    }

    /// The `Debug` rendering lists the entries and reports occupancy.
    #[test]
    fn table_debug_lists_entries() {
        let mut table = Table::new();
        table.insert(&entry(r"C:\Windows")).expect("room");
        let rendered = format!("{table:?}");
        assert!(rendered.contains("used: 1"), "{rendered}");
        assert!(rendered.contains("capacity: 4"), "{rendered}");
        assert!(rendered.contains(r"C:\Windows"), "{rendered}");
    }

    /// The protocol's constants must match what `crate::wire` sizes its
    /// buffers from — a mismatch would make `ExclusionBuffer::entry` clamp
    /// rows the table would have accepted, or the reverse.
    #[test]
    fn the_protocol_constants_agree_with_the_wire_sizes() {
        assert_eq!(MAX_EXCLUSIONS, 64);
        assert_eq!(MAX_EXCLUSION_UNITS, 260);
        assert_eq!(
            crate::wire::ExclusionBuffer::SIZE,
            8 + MAX_EXCLUSIONS * 2 + MAX_EXCLUSIONS * MAX_EXCLUSION_UNITS * 2
        );
    }
}
