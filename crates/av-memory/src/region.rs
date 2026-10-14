//! What a process's address space is made of, and which parts of it are worth
//! reading.
//!
//! # The one decision this crate exists to make
//!
//! A process's address space holds thousands of regions and almost none of them
//! are worth looking at. The interesting ones are the shape of injected code,
//! and the shape has three parts:
//!
//! 1. **Committed.** A reserved or free region holds no bytes, so there is
//!    nothing to read.
//! 2. **Executable.** Rules are strings and byte patterns; what matters is
//!    whether they appear in bytes the processor will *run*, because that is
//!    the code that is doing whatever it is doing. A heap full of a malware
//!    family's name in a string table is not the malware running.
//! 3. **Not backed by a file.** This is the part that makes memory scanning
//!    worth doing at all. A region that came off the disk is a file, and the
//!    file scanner has already read it — as a file, with its header, its
//!    sections and its signature, which is far more than a region of memory
//!    can show. A region that came off *nothing* is the shape of code that was
//!    written straight into a process and never existed on disk, and no file
//!    scan can ever see it.
//!
//! A fourth condition rides along because writing it as part of the predicate
//! is what keeps the read honest: the protection has to actually *permit* a
//! read. `PAGE_EXECUTE` is execute-only, and asking `ReadProcessMemory` for it
//! can only produce a refusal. Passing over it here moves that region from the
//! "we asked and were refused" column to the "we knew we could not read it"
//! column, which is the honest place for it — but the report still counts it,
//! because a region we chose not to read is still a region we did not examine.
//!
//! # Two ways in, and why writable-and-executable is the second
//!
//! The predicate accepts a region that is executable, readable, and *private*
//! to the process, and it also accepts a region that is executable and
//! genuinely writable whatever its backing. The second is not a restatement of
//! the first: a region can be writable and executable and still be backed by a
//! file, and that is interesting for a reason that has nothing to do with
//! injection. **No compiler emits a writable code section.** A linker emits
//! `.text` as read-and-execute and `.data` as read-and-write, and it separates
//! them precisely so that neither is both. A region that is both was either
//! requested that way at run time, or was re-protected after loading, and both
//! of those are things malware does to itself and legitimate software rarely
//! does at all.
//!
//! # What "not backed by a file" is measured as, and what that misses
//!
//! `MEMORY_BASIC_INFORMATION` reports a region's type, and the type is what
//! this crate reads:
//!
//! | Type | Meaning here |
//! |---|---|
//! | `MEM_PRIVATE` | Private to the process. Backed by the pagefile at most, so nothing on disk holds these bytes. **This is the injected-code case.** |
//! | `MEM_IMAGE` | A mapped image section, which is a file on disk that was loaded. Skipped, and left to the file scanner. |
//! | `MEM_MAPPED` | A mapped section object. Skipped. |
//!
//! `MEM_MAPPED` is the honest gap. A section object is *usually* a file, but a
//! section can also be backed by the pagefile, and a pagefile-backed section
//! mapped executable is exactly as invisible to a file scan as a private
//! region is. Telling the two apart needs `QueryWorkingSetEx` and a walk of the
//! mapping's backing store, which this crate does not do; so a pagefile-backed
//! section is reported here as "backed by a file" and passed over. That is a
//! false negative and it is written down as one rather than left to be
//! discovered. The measured size of the gap is in the crate documentation.
//!
//! # Why a guarded region is never read
//!
//! `PAGE_GUARD` is how Windows implements a stack that grows on demand and a
//! heap that commits lazily: the page below the one in use is marked guarded,
//! and the first touch raises a one-shot exception in the process that touched
//! it, which is the process's cue to grow. Reading such a page through
//! `ReadProcessMemory` is not a harmless peek. At best the read is refused; at
//! worst it consumes the guard in the *target* process, and a stack that can no
//! longer discover that it needs to grow does not fail cleanly — it faults. So
//! the guard bit is checked before anything else and a guarded region is passed
//! over, whatever its protection bits otherwise say. This is not a theoretical
//! concern: one explorer.exe held between 99 and 113 guarded regions across five
//! runs, out of about 4,500 committed regions, and a live process's guard count
//! moves between scans because its stacks and heaps are still growing. The
//! measurement is recorded in the crate documentation.
//!
//! # Everything here is testable without a live process
//!
//! That is deliberate. The predicate takes a [`MemoryRegion`] — a plain value —
//! and returns a plain value, so the whole of the interesting-or-not decision
//! is exercised by unit tests rather than by hoping a machine has a suitable
//! process on it. Only the Win32 calls that *produce* a [`MemoryRegion`] need a
//! machine, and they are in [`crate::source`].

use serde::{Deserialize, Serialize};

/// The state of a range of addresses.
///
/// The three documented values plus a catch-all, because the value comes from
/// the operating system and a variant that does not exist here must not become
/// a panic or a silently-wrong "committed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionState {
    /// `MEM_COMMIT`: the range is backed by physical storage and holds bytes.
    Committed,
    /// `MEM_RESERVE`: the range is claimed but holds nothing.
    Reserved,
    /// `MEM_FREE`: the range is not in use at all.
    Free,
    /// A state this crate does not know. Never treated as committed.
    Unknown,
}

impl RegionState {
    /// `MEM_COMMIT`.
    pub const MEM_COMMIT: u32 = 0x1000;
    /// `MEM_RESERVE`.
    pub const MEM_RESERVE: u32 = 0x2000;
    /// `MEM_FREE`.
    pub const MEM_FREE: u32 = 0x10000;

    /// Read the state from the value `VirtualQueryEx` reported.
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            Self::MEM_COMMIT => RegionState::Committed,
            Self::MEM_RESERVE => RegionState::Reserved,
            Self::MEM_FREE => RegionState::Free,
            _ => RegionState::Unknown,
        }
    }

    /// The word to print for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            RegionState::Committed => "committed",
            RegionState::Reserved => "reserved",
            RegionState::Free => "free",
            RegionState::Unknown => "unknown",
        }
    }
}

/// What a region is backed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// `MEM_IMAGE`: a mapped image section. A file on disk, loaded.
    Image,
    /// `MEM_MAPPED`: a mapped section object.
    Mapped,
    /// `MEM_PRIVATE`: private to this process. Nothing on disk holds it.
    Private,
    /// A type this crate does not know. Never treated as private, because
    /// treating the unknown as private is what produces a false positive on
    /// every region of a machine whose kernel reports a type we have not seen.
    Unknown,
}

impl RegionKind {
    /// `MEM_IMAGE`.
    pub const MEM_IMAGE: u32 = 0x100_0000;
    /// `MEM_MAPPED`.
    pub const MEM_MAPPED: u32 = 0x4_0000;
    /// `MEM_PRIVATE`.
    pub const MEM_PRIVATE: u32 = 0x2_0000;

    /// Read the type from the value `VirtualQueryEx` reported.
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            Self::MEM_IMAGE => RegionKind::Image,
            Self::MEM_MAPPED => RegionKind::Mapped,
            Self::MEM_PRIVATE => RegionKind::Private,
            _ => RegionKind::Unknown,
        }
    }

    /// The word to print for this kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            RegionKind::Image => "image",
            RegionKind::Mapped => "mapped",
            RegionKind::Private => "private",
            RegionKind::Unknown => "unknown",
        }
    }

    /// True when something on disk holds these bytes.
    ///
    /// `Unknown` answers `true`, which is the conservative direction: a region
    /// we cannot classify is left to the file scanner rather than read as
    /// though it were injected.
    pub const fn is_file_backed(self) -> bool {
        matches!(
            self,
            RegionKind::Image | RegionKind::Mapped | RegionKind::Unknown
        )
    }
}

/// The access a region's protection grants, with the modifier bits stripped.
///
/// Windows documents eight values for the low byte of a protection word, and
/// they are **not** a bit field: `PAGE_READONLY` is `0x02` and
/// `PAGE_READWRITE` is `0x04`, so read is not a bit that stays set as write is
/// added. A predicate written as `raw & 0x02 != 0` would call `PAGE_READWRITE`
/// unreadable. The table below is the documented mapping, and the test module
/// checks every one of the eight against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// `PAGE_NOACCESS` (`0x01`). Anything touching it faults.
    NoAccess,
    /// `PAGE_READONLY` (`0x02`).
    ReadOnly,
    /// `PAGE_READWRITE` (`0x04`).
    ReadWrite,
    /// `PAGE_WRITECOPY` (`0x08`). Writes are allowed but private to the writer.
    WriteCopy,
    /// `PAGE_EXECUTE` (`0x10`). Execute only — not readable, so a scan cannot
    /// fetch these bytes at all.
    Execute,
    /// `PAGE_EXECUTE_READ` (`0x20`).
    ExecuteRead,
    /// `PAGE_EXECUTE_READWRITE` (`0x40`).
    ExecuteReadWrite,
    /// `PAGE_EXECUTE_WRITECOPY` (`0x80`).
    ExecuteWriteCopy,
    /// A base byte Windows does not document. Treated as granting nothing,
    /// because a protection this crate cannot read is not one it may assume
    /// permits a read.
    Other(u8),
}

impl Access {
    /// Read the access from the low byte of a protection word.
    pub const fn from_raw(base: u8) -> Self {
        match base {
            0x01 => Access::NoAccess,
            0x02 => Access::ReadOnly,
            0x04 => Access::ReadWrite,
            0x08 => Access::WriteCopy,
            0x10 => Access::Execute,
            0x20 => Access::ExecuteRead,
            0x40 => Access::ExecuteReadWrite,
            0x80 => Access::ExecuteWriteCopy,
            other => Access::Other(other),
        }
    }

    /// True when the bytes can be fetched by `ReadProcessMemory`.
    ///
    /// `PAGE_EXECUTE` is the one executable protection that is not readable,
    /// and `PAGE_NOACCESS` is not readable in any sense.
    pub const fn is_readable(self) -> bool {
        matches!(
            self,
            Access::ReadOnly
                | Access::ReadWrite
                | Access::WriteCopy
                | Access::ExecuteRead
                | Access::ExecuteReadWrite
                | Access::ExecuteWriteCopy
        )
    }

    /// True when a write to the region changes the region.
    ///
    /// Copy-on-write protections are deliberately **not** writable here, and
    /// that is the single most consequential line in this module. A write to a
    /// copy-on-write page does not go to that page: it faults, the kernel
    /// allocates a fresh private page, and the write lands there. The mapping
    /// is read-only in every sense that matters to a scan — the page a reader
    /// sees never changes. Counting it as writable would make
    /// `PAGE_EXECUTE_WRITECOPY` "writable and executable", and that is the
    /// protection some linkers request for an image's code section, so the
    /// predicate would then flag every DLL's `.text` in every process: on the
    /// machine this was measured on the count of `PAGE_EXECUTE_WRITECOPY`
    /// regions in explorer.exe was zero, so tightening it changed nothing
    /// *there* — which is exactly why the rule is written from the documented
    /// meaning of the flag rather than from what that one machine happened to
    /// show.
    pub const fn is_writable(self) -> bool {
        matches!(self, Access::ReadWrite | Access::ExecuteReadWrite)
    }

    /// True when a write is allowed but lands on a private copy.
    pub const fn is_copy_on_write(self) -> bool {
        matches!(self, Access::WriteCopy | Access::ExecuteWriteCopy)
    }

    /// True when the processor may execute these bytes.
    pub const fn is_executable(self) -> bool {
        matches!(
            self,
            Access::Execute
                | Access::ExecuteRead
                | Access::ExecuteReadWrite
                | Access::ExecuteWriteCopy
        )
    }

    /// The word to print for this access.
    pub const fn as_str(self) -> &'static str {
        match self {
            Access::NoAccess => "noaccess",
            Access::ReadOnly => "readonly",
            Access::ReadWrite => "readwrite",
            Access::WriteCopy => "writecopy",
            Access::Execute => "execute",
            Access::ExecuteRead => "execute_read",
            Access::ExecuteReadWrite => "execute_readwrite",
            Access::ExecuteWriteCopy => "execute_writecopy",
            Access::Other(_) => "unrecognised",
        }
    }
}

/// A region's protection word, modifier bits and all.
///
/// Kept as the raw value the operating system reported rather than parsed down
/// to an [`Access`], because the bits above the low byte are not decoration.
/// `PAGE_GUARD` in particular changes what a read does, and a type that threw
/// away the bits it did not understand could not report the one that matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Protection(u32);

impl Protection {
    /// `PAGE_GUARD`. The first touch by the owning process raises a one-shot
    /// exception; a read by anybody may consume it.
    pub const GUARD: u32 = 0x100;
    /// `PAGE_NOCACHE`.
    pub const NO_CACHE: u32 = 0x200;
    /// `PAGE_WRITECOMBINE`.
    pub const WRITE_COMBINE: u32 = 0x400;

    /// Wrap a raw protection word.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// The raw protection word.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// The access the low byte grants.
    pub const fn access(self) -> Access {
        Access::from_raw((self.0 & 0xFF) as u8)
    }

    /// True when the region is guarded. See the module documentation for why a
    /// guarded region is never read.
    pub const fn is_guard(self) -> bool {
        self.0 & Self::GUARD != 0
    }

    /// True when the bytes can be fetched.
    ///
    /// A guarded region answers `false` however its access bits read, because
    /// "readable" for a scan means "readable without disturbing the target".
    pub const fn is_readable(self) -> bool {
        !self.is_guard() && self.access().is_readable()
    }

    /// True when a write changes what a reader sees.
    pub const fn is_writable(self) -> bool {
        self.access().is_writable()
    }

    /// True when the processor may execute the region.
    pub const fn is_executable(self) -> bool {
        self.access().is_executable()
    }

    /// The protection as three letters plus any modifier that changes what a
    /// read does: `rwx`, `r-x`, `--x`, `rw-|guard`.
    ///
    /// The middle letter is `c` for a copy-on-write protection, because "the
    /// write makes a private copy" and "the write changes the region" are
    /// different facts and a report that printed `w` for both would hide the
    /// distinction the predicate is built on.
    pub fn describe(self) -> String {
        let access = self.access();
        let mut out = String::with_capacity(12);
        out.push(if access.is_readable() { 'r' } else { '-' });
        out.push(if access.is_writable() {
            'w'
        } else if access.is_copy_on_write() {
            'c'
        } else {
            '-'
        });
        out.push(if access.is_executable() { 'x' } else { '-' });
        if let Access::Other(base) = access {
            // Keep the unknown byte in the string. A report that printed `---`
            // for an unrecognised protection would read as "no access" when
            // what is true is "no idea".
            out.push_str(&format!("|unknown({base:#04x})"));
        }
        if self.is_guard() {
            out.push_str("|guard");
        }
        if self.0 & Self::NO_CACHE != 0 {
            out.push_str("|nocache");
        }
        if self.0 & Self::WRITE_COMBINE != 0 {
            out.push_str("|writecombine");
        }
        out
    }
}

/// One region of a process's address space, as a plain value.
///
/// Everything needed to decide whether it is worth reading and to ask for its
/// bytes. Producing one needs a live process; deciding about one does not, and
/// that split is the whole testability story of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// The address the region starts at.
    pub base: usize,
    /// How many bytes it covers. Windows allocates in pages, so this is a
    /// multiple of the page size for any region the operating system reports;
    /// it is not trusted to be, and every use of it is checked.
    pub size: usize,
    /// Whether the region holds bytes.
    pub state: RegionState,
    /// What the region's protection allows.
    pub protection: Protection,
    /// What the region is backed by.
    pub kind: RegionKind,
}

impl MemoryRegion {
    /// The first address past the end of the region.
    ///
    /// Saturating: `base` and `size` both came from the operating system, and a
    /// region that ends past the top of the address space is a value that must
    /// not become a panic or a wrap to a low address that a scan would then
    /// walk backwards into.
    pub const fn end(&self) -> usize {
        self.base.saturating_add(self.size)
    }

    /// True when this region is the described shape: committed, executable,
    /// readable, and private to the process.
    ///
    /// Matching with patterns rather than `==` so that the function can stay
    /// `const`: a derived `PartialEq` is a function call, and a function call is
    /// not allowed in a `const fn`.
    pub const fn is_unbacked_code(&self) -> bool {
        matches!(self.state, RegionState::Committed)
            && matches!(self.kind, RegionKind::Private)
            && self.protection.is_executable()
            && self.protection.is_readable()
    }

    /// True when this region is committed, executable and genuinely writable.
    pub const fn is_writable_code(&self) -> bool {
        matches!(self.state, RegionState::Committed)
            && self.protection.is_executable()
            && self.protection.is_writable()
    }
}

/// Why a region is worth reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Interest {
    /// Committed, executable, readable and private to the process: nothing on
    /// disk holds these bytes. This is the shape of injected code, and it is
    /// the reason memory scanning exists.
    UnbackedCode,
    /// Committed, executable and genuinely writable, whatever it is backed by.
    /// No compiler emits this, so whatever asked for it asked deliberately.
    WritableCode,
}

impl Interest {
    /// The word to print for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Interest::UnbackedCode => "unbacked-executable",
            Interest::WritableCode => "writable-executable",
        }
    }
}

/// Why a region was passed over.
///
/// Every region the predicate declines gets one of these rather than being
/// dropped, so that a report can account for all of a process's memory and a
/// reader can see what the scan decided not to look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Skip {
    /// Reserved or free: there are no bytes there to read.
    NotCommitted,
    /// Smaller than the caller's floor. Windows allocates in pages, so this is
    /// a guard against a source reporting a nonsense size rather than a case a
    /// real machine produces.
    TooSmall,
    /// Guarded. See the module documentation.
    Guard,
    /// Committed and executable but not readable — `PAGE_EXECUTE`. Asking for
    /// these bytes could only produce a refusal.
    NotReadable,
    /// Not executable. Rules are byte patterns; a string in a heap is not the
    /// code running.
    NotExecutable,
    /// Executable and committed, but backed by a section object that is
    /// reported as a file, and not writable. The file scanner's job.
    BackedByFile,
}

impl Skip {
    /// The word to print for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Skip::NotCommitted => "not-committed",
            Skip::TooSmall => "too-small",
            Skip::Guard => "guarded",
            Skip::NotReadable => "not-readable",
            Skip::NotExecutable => "not-executable",
            Skip::BackedByFile => "backed-by-file",
        }
    }
}

/// The decision about one region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionInterest {
    /// Worth reading.
    Interesting(Interest),
    /// Not worth reading, and why not.
    PassedOver(Skip),
}

impl RegionInterest {
    /// True when the region is worth reading.
    pub const fn is_interesting(self) -> bool {
        matches!(self, RegionInterest::Interesting(_))
    }

    /// The reason, whether the region is interesting or not.
    pub const fn reason(self) -> &'static str {
        match self {
            RegionInterest::Interesting(interest) => interest.as_str(),
            RegionInterest::PassedOver(skip) => skip.as_str(),
        }
    }
}

/// Is this region worth reading?
///
/// `floor` is the smallest region worth asking for. It exists to bound a source
/// that reports a nonsensical size — a real committed region is at least one
/// page, so no region on a real machine is ever passed over as too small. The
/// default the scanner uses is
/// [`MemoryScanConfig::min_region_bytes`](crate::MemoryScanConfig::min_region_bytes).
///
/// A region of **no bytes** is passed over whatever the floor is, including a
/// floor of zero. That is not the floor's job and it is not a special case
/// bolted on: a read of zero bytes succeeds, and a region whose read succeeded
/// is a region the report counts as read. A zero-size region is therefore the
/// one region that could be counted as examined without a single byte of it
/// having been looked at, which is the failure this whole crate is arranged to
/// make impossible — so it is refused at the door, by the same check, for every
/// caller.
///
/// The order of the checks is the order the reasons matter, not the order they
/// are cheapest. Committed comes first because a free region's protection word
/// is meaningless. Guard comes before the access checks because a guarded page
/// can read as fully accessible and still be the one region that must not be
/// touched. The unbacked check comes before the writable check so that a
/// private region that is both reports the stronger reason.
pub fn classify(region: &MemoryRegion, floor: usize) -> RegionInterest {
    if region.state != RegionState::Committed {
        return RegionInterest::PassedOver(Skip::NotCommitted);
    }
    if region.size < floor.max(1) {
        return RegionInterest::PassedOver(Skip::TooSmall);
    }
    if region.protection.is_guard() {
        return RegionInterest::PassedOver(Skip::Guard);
    }
    if !region.protection.is_readable() {
        return RegionInterest::PassedOver(Skip::NotReadable);
    }
    if !region.protection.is_executable() {
        return RegionInterest::PassedOver(Skip::NotExecutable);
    }
    if region.is_unbacked_code() {
        return RegionInterest::Interesting(Interest::UnbackedCode);
    }
    if region.is_writable_code() {
        return RegionInterest::Interesting(Interest::WritableCode);
    }
    RegionInterest::PassedOver(Skip::BackedByFile)
}

/// What came of asking for a region's bytes.
///
/// The two cases are separate variants rather than an empty `Vec` for a
/// failure, because "the region held nothing that matched" and "the region
/// could not be looked at" are different answers about a process and only one
/// of them is evidence of anything. A scanner that returned an empty buffer for
/// both would report the second as the first, and the report would then say a
/// process was clean when what is true is that part of it was never seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionRead {
    /// The bytes were produced.
    Read(RegionBytes),
    /// The read was refused. The region was not examined.
    Refused(crate::error::MemoryError),
}

impl RegionRead {
    /// True when the bytes were produced, whether or not any matched.
    pub const fn is_read(&self) -> bool {
        matches!(self, RegionRead::Read(_))
    }

    /// The bytes, when there are any.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            RegionRead::Read(read) => Some(&read.bytes),
            RegionRead::Refused(_) => None,
        }
    }

    /// True when the region was larger than the cap and only its head was read.
    pub const fn is_truncated(&self) -> bool {
        match self {
            RegionRead::Read(read) => read.truncated,
            RegionRead::Refused(_) => false,
        }
    }
}

/// The bytes of a region, and how much of the region they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionBytes {
    /// The bytes that were read. Never more than the region holds.
    pub bytes: Vec<u8>,
    /// How many bytes the region actually covers.
    pub region_size: usize,
    /// True when only the head of the region was read.
    ///
    /// Carried rather than inferred from the two lengths, because a reader
    /// comparing them would have to know they are comparable. A truncated
    /// region is a region that was not fully examined, and the report says so.
    pub truncated: bool,
}

impl RegionBytes {
    /// Bytes read, as a number that fits the report's counters.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the read produced no bytes at all — a region smaller than the
    /// smallest useful pattern, which the floor should have passed over.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A committed region with the given protection and backing.
    fn region(size: usize, protection: u32, kind: RegionKind) -> MemoryRegion {
        MemoryRegion {
            base: 0x1_0000,
            size,
            state: RegionState::Committed,
            protection: Protection::from_raw(protection),
            kind,
        }
    }

    const FLOOR: usize = 16;

    #[test]
    fn the_eight_documented_protections_grant_what_windows_documents() {
        // The differential test for the whole table. A predicate written as a
        // bit test over the raw value gets `PAGE_READWRITE` (0x04) and
        // `PAGE_WRITECOPY` (0x08) wrong, and this table is what says so.
        let expected: [(u8, bool, bool, bool); 8] = [
            // base, readable, writable, executable
            (0x01, false, false, false), // PAGE_NOACCESS
            (0x02, true, false, false),  // PAGE_READONLY
            (0x04, true, true, false),   // PAGE_READWRITE
            (0x08, true, false, false),  // PAGE_WRITECOPY: readable, but writes copy
            (0x10, false, false, true),  // PAGE_EXECUTE: execute-only
            (0x20, true, false, true),   // PAGE_EXECUTE_READ
            (0x40, true, true, true),    // PAGE_EXECUTE_READWRITE
            (0x80, true, false, true),   // PAGE_EXECUTE_WRITECOPY
        ];
        for (base, readable, writable, executable) in expected {
            let access = Access::from_raw(base);
            assert_eq!(access.is_readable(), readable, "{base:#04x} readable");
            assert_eq!(access.is_writable(), writable, "{base:#04x} writable");
            assert_eq!(access.is_executable(), executable, "{base:#04x} executable");
        }
    }

    #[test]
    fn a_private_executable_region_is_the_shape_of_injected_code() {
        // The centrepiece. Read-and-execute and private to the process: nothing
        // on disk holds these bytes.
        let r = region(4096, 0x20, RegionKind::Private);
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::Interesting(Interest::UnbackedCode)
        );
    }

    #[test]
    fn an_image_executable_region_is_left_to_the_file_scan() {
        // The other half of the centrepiece, and the one that keeps the
        // predicate from flagging a process's entire code. Every loaded DLL
        // contributes several executable image regions; measured on explorer.exe
        // there were 742 of them against 22 private ones.
        let r = region(4096, 0x20, RegionKind::Image);
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::PassedOver(Skip::BackedByFile)
        );
        assert_eq!(
            classify(&region(4096, 0x20, RegionKind::Mapped), FLOOR),
            RegionInterest::PassedOver(Skip::BackedByFile)
        );
    }

    #[test]
    fn execute_writecopy_is_not_writable_however_it_is_backed() {
        // The line the predicate turns on. If copy-on-write counted as
        // writable, this region would be "executable and writable" and be read,
        // and so would every image section a linker maps that way. Explorer had
        // none of these; the rule is written from the documented meaning of the
        // flag so that a machine that does have them does not become a false
        // positive machine.
        let image = region(4096, 0x80, RegionKind::Image);
        assert_eq!(
            classify(&image, FLOOR),
            RegionInterest::PassedOver(Skip::BackedByFile)
        );
        assert!(!image.is_writable_code());

        // A private one is still interesting, but as unbacked code rather than
        // as writable code — the reason reported is the one that is true.
        let private = region(4096, 0x80, RegionKind::Private);
        assert_eq!(
            classify(&private, FLOOR),
            RegionInterest::Interesting(Interest::UnbackedCode)
        );
    }

    #[test]
    fn a_writable_executable_image_region_is_interesting_for_its_own_reason() {
        // A compiler emits `.text` read-and-execute and `.data` read-and-write.
        // Both would be fine separately; together they mean somebody asked for
        // them together.
        let r = region(4096, 0x40, RegionKind::Image);
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::Interesting(Interest::WritableCode)
        );
    }

    #[test]
    fn a_guard_page_is_passed_over_whatever_else_it_grants() {
        // Guarded read-write-execute: maximally attractive and the one region
        // that must not be touched, because the read can consume the guard in
        // the process being scanned.
        let r = region(4096, 0x40 | Protection::GUARD, RegionKind::Private);
        assert_eq!(classify(&r, FLOOR), RegionInterest::PassedOver(Skip::Guard));
        assert!(
            !r.protection.is_readable(),
            "guarded is not readable by a scan"
        );

        // The guard bit is the *only* difference from the region above, which
        // the predicate accepts.
        let unguarded = region(4096, 0x40, RegionKind::Private);
        assert!(classify(&unguarded, FLOOR).is_interesting());
    }

    #[test]
    fn a_heap_region_is_private_and_executable_is_not_enough_on_its_own() {
        // Resident memory is mostly private; that is not what is being looked
        // for, and a predicate that dropped the executable check would read all
        // of a process's heap.
        let r = region(4096, 0x04, RegionKind::Private);
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::PassedOver(Skip::NotExecutable)
        );
        assert_eq!(
            classify(&region(4096, 0x02, RegionKind::Private), FLOOR),
            RegionInterest::PassedOver(Skip::NotExecutable)
        );
    }

    #[test]
    fn execute_only_memory_is_passed_over_as_unreadable_rather_than_failed() {
        // `PAGE_EXECUTE` is executable and, if private, unbacked — the shape of
        // injected code. It is also not readable, so asking for it could only
        // produce a refusal. Reporting it as "not readable" keeps the refusal
        // counters about regions that were actually attempted.
        let r = region(4096, 0x10, RegionKind::Private);
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::PassedOver(Skip::NotReadable)
        );

        // And a guard beats it to the reason, because guard is the more
        // important fact about the region.
        let guarded = region(4096, 0x10 | Protection::GUARD, RegionKind::Private);
        assert_eq!(
            classify(&guarded, FLOOR),
            RegionInterest::PassedOver(Skip::Guard)
        );
    }

    #[test]
    fn reserved_and_free_regions_hold_nothing_to_read() {
        let mut r = region(4096, 0x04, RegionKind::Private);
        r.state = RegionState::Reserved;
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::PassedOver(Skip::NotCommitted)
        );
        r.state = RegionState::Free;
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::PassedOver(Skip::NotCommitted)
        );
        // A free region's protection word is zero, and must not be read as
        // "no access, therefore not readable" — the reason has to be that
        // there is nothing there, which is what a reader needs to know.
        r.protection = Protection::from_raw(0);
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::PassedOver(Skip::NotCommitted)
        );
        r.state = RegionState::Unknown;
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::PassedOver(Skip::NotCommitted)
        );
    }

    #[test]
    fn a_region_below_the_floor_is_passed_over() {
        let small = region(FLOOR - 1, 0x20, RegionKind::Private);
        assert_eq!(
            classify(&small, FLOOR),
            RegionInterest::PassedOver(Skip::TooSmall)
        );
        let exact = region(FLOOR, 0x20, RegionKind::Private);
        assert!(classify(&exact, FLOOR).is_interesting());
        // A floor of zero still passes over a region of no bytes: there is
        // nothing to read, and a read of zero bytes that "succeeds" would
        // otherwise be counted as a region examined.
        assert_eq!(
            classify(&region(0, 0x20, RegionKind::Private), 0),
            RegionInterest::PassedOver(Skip::TooSmall)
        );
    }

    #[test]
    fn an_unknown_region_type_is_not_treated_as_private() {
        // The conservative direction. Treating an unknown type as private would
        // read every executable read-only region on any machine whose kernel
        // reports a type this crate has not seen.
        let r = region(4096, 0x20, RegionKind::Unknown);
        assert_eq!(
            classify(&r, FLOOR),
            RegionInterest::PassedOver(Skip::BackedByFile)
        );
        assert!(!r.is_unbacked_code());
        // It is still interesting if it is genuinely writable, because that
        // reason does not depend on the backing — but the reason it is
        // interesting is the writability, not the backing.
        let writable = region(4096, 0x40, RegionKind::Unknown);
        assert_eq!(
            classify(&writable, FLOOR),
            RegionInterest::Interesting(Interest::WritableCode)
        );
        assert!(!writable.is_unbacked_code());
    }

    #[test]
    fn an_unrecognised_protection_grants_nothing() {
        // A protection byte Windows does not document. Reading it as though the
        // bits meant something would be a guess, and a guess in this direction
        // reads memory we may not touch.
        let odd = Protection::from_raw(0x33);
        assert_eq!(odd.access(), Access::Other(0x33));
        assert!(!odd.is_readable());
        assert!(!odd.is_writable());
        assert!(!odd.is_executable());
        assert_eq!(
            classify(&region(4096, 0x33, RegionKind::Private), FLOOR),
            RegionInterest::PassedOver(Skip::NotReadable)
        );
        assert!(odd.describe().contains("unknown"), "{}", odd.describe());
    }

    #[test]
    fn describe_shows_the_difference_between_a_write_and_a_copy() {
        assert_eq!(Protection::from_raw(0x40).describe(), "rwx");
        assert_eq!(Protection::from_raw(0x20).describe(), "r-x");
        assert_eq!(Protection::from_raw(0x04).describe(), "rw-");
        assert_eq!(Protection::from_raw(0x02).describe(), "r--");
        assert_eq!(Protection::from_raw(0x01).describe(), "---");
        // The distinction the predicate is built on, visible in the string.
        assert_eq!(Protection::from_raw(0x80).describe(), "rcx");
        assert_eq!(Protection::from_raw(0x08).describe(), "rc-");
        assert_eq!(
            Protection::from_raw(0x04 | Protection::GUARD).describe(),
            "rw-|guard"
        );
    }

    #[test]
    fn the_state_and_kind_tables_cover_every_documented_value() {
        assert_eq!(
            RegionState::from_raw(RegionState::MEM_COMMIT),
            RegionState::Committed
        );
        assert_eq!(
            RegionState::from_raw(RegionState::MEM_RESERVE),
            RegionState::Reserved
        );
        assert_eq!(
            RegionState::from_raw(RegionState::MEM_FREE),
            RegionState::Free
        );
        // Zero is what a free region reports for its protection *and* its type.
        assert_eq!(RegionState::from_raw(0), RegionState::Unknown);
        assert_eq!(RegionKind::from_raw(0), RegionKind::Unknown);
        assert_eq!(
            RegionKind::from_raw(RegionKind::MEM_IMAGE),
            RegionKind::Image
        );
        assert_eq!(
            RegionKind::from_raw(RegionKind::MEM_MAPPED),
            RegionKind::Mapped
        );
        assert_eq!(
            RegionKind::from_raw(RegionKind::MEM_PRIVATE),
            RegionKind::Private
        );
        assert!(RegionKind::Image.is_file_backed());
        assert!(!RegionKind::Private.is_file_backed());
        assert!(
            RegionKind::Unknown.is_file_backed(),
            "unknown leans towards the file scan"
        );
    }

    #[test]
    fn a_region_reports_the_address_past_its_end_without_wrapping() {
        let r = MemoryRegion {
            base: usize::MAX - 1,
            size: 4096,
            state: RegionState::Committed,
            protection: Protection::from_raw(0x20),
            kind: RegionKind::Private,
        };
        assert_eq!(r.end(), usize::MAX, "a length past the end must not wrap");
        let normal = region(4096, 0x20, RegionKind::Private);
        assert_eq!(normal.end(), 0x1_1000);
    }

    #[test]
    fn a_refused_read_is_not_a_read_that_found_nothing() {
        let empty = RegionRead::Read(RegionBytes {
            bytes: Vec::new(),
            region_size: 0,
            truncated: false,
        });
        let refused = RegionRead::Refused(crate::error::MemoryError::ReadRefused {
            pid: 1,
            address: 0x1_0000,
            length: 4096,
            code: crate::error::ERROR_PARTIAL_COPY,
            message: "Only part of a ReadProcessMemory request was completed.".into(),
        });
        assert!(empty.is_read());
        assert!(!refused.is_read());
        assert_eq!(empty.bytes(), Some(&[][..]));
        assert_eq!(refused.bytes(), None);
        assert!(!refused.is_truncated());
    }

    #[test]
    fn every_reason_has_a_stable_word() {
        // The words go into reports that users and support engineers read, and
        // a rename that no test noticed would change what a saved report means.
        assert_eq!(Interest::UnbackedCode.as_str(), "unbacked-executable");
        assert_eq!(Interest::WritableCode.as_str(), "writable-executable");
        assert_eq!(Skip::NotCommitted.as_str(), "not-committed");
        assert_eq!(Skip::TooSmall.as_str(), "too-small");
        assert_eq!(Skip::Guard.as_str(), "guarded");
        assert_eq!(Skip::NotReadable.as_str(), "not-readable");
        assert_eq!(Skip::NotExecutable.as_str(), "not-executable");
        assert_eq!(Skip::BackedByFile.as_str(), "backed-by-file");
        assert_eq!(
            RegionInterest::Interesting(Interest::UnbackedCode).reason(),
            "unbacked-executable"
        );
        assert_eq!(RegionInterest::PassedOver(Skip::Guard).reason(), "guarded");
    }
}
