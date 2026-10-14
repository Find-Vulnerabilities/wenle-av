//! The policy of the kernel's own self-protection layer.
//!
//! Two questions, and they are two different questions with two different
//! answers:
//!
//! * **A handle is being opened to one of this product's own processes.** Which
//!   rights are taken off it before it is granted? Answer:
//!   [`STRIPPED_FROM_PROCESS`] and [`STRIPPED_FROM_THREAD`], applied by
//!   [`strip_process`] and [`strip_thread`].
//! * **A write is being issued to one of this product's own files.** Is it
//!   refused? Answer: [`is_protected_file`], given the installation directory
//!   the service named and the path the write is on.
//!
//! Both live here rather than in `crates/av-driver` because both are arithmetic
//! over access masks and comparisons over byte strings, and this is the crate
//! `cargo test` can run. See the crate documentation for why that split exists
//! and what it does *not* buy: the code here is tested, and the code in the
//! driver that calls it is not.
//!
//! # The boundary these two share, stated once
//!
//! Neither of them stops an administrator, and neither of them stops
//! kernel-mode code. That is not a limitation discovered late — it is the
//! policy, and it is the same policy [`crate`]'s user-mode counterpart states
//! in `av-guard`: an administrator may already load a driver, and a product
//! that refused its own administrator's maintenance is a product that cannot be
//! uninstalled. What these two *do* stop is the much larger class underneath:
//! a program running as the logged-on user, including one that has just taken
//! ownership of this product's files or rewritten the discretionary ACL on its
//! process, because both of those are paths around a user-mode-only defence and
//! neither is a path around this one.

/// `PROCESS_TERMINATE`, from `um\winnt.h` line 12685: `(0x0001)`.
///
/// The right that ends one of this product's processes. The one every
/// "kill the antivirus" tool asks for first.
pub const PROCESS_TERMINATE: u32 = 0x0001;
/// `PROCESS_CREATE_THREAD`, from `um\winnt.h` line 12686: `(0x0002)`.
///
/// With [`PROCESS_VM_WRITE`] and [`PROCESS_VM_OPERATION`], one of the three
/// rights an in-process injection is built out of — `VirtualAllocEx`, write,
/// `CreateRemoteThread` — and it is the third of that trio that is easy to
/// forget, because a stripped `PROCESS_VM_WRITE` still leaves a caller able to
/// start a thread inside the process at an address it already has.
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
/// `PROCESS_VM_OPERATION`, from `um\winnt.h` line 12688: `(0x0008)`.
///
/// `VirtualProtectEx` and `VirtualAllocEx`: the right to change what a
/// process's memory *is*, which is what turns a writable page into an
/// executable one.
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
/// `PROCESS_VM_WRITE`, from `um\winnt.h` line 12690: `(0x0020)`.
pub const PROCESS_VM_WRITE: u32 = 0x0020;
/// `PROCESS_SUSPEND_RESUME`, from `um\winnt.h` line 12696: `(0x0800)`.
///
/// Not an injection right on its own, and it is here because suspending a
/// process is how a second process gets a stable target: a scan, a comparison
/// or a `VirtualProtectEx` applied to a process that keeps running is a scan of
/// something that has already changed.
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;

/// `THREAD_TERMINATE`, from `um\winnt.h` line 12710: `(0x0001)`.
pub const THREAD_TERMINATE: u32 = 0x0001;
/// `THREAD_SUSPEND_RESUME`, from `um\winnt.h` line 12711: `(0x0002)`.
pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
/// `THREAD_SET_CONTEXT`, from `um\winnt.h` line 12713: `(0x0010)`.
///
/// The right to change a thread's registers, which is the whole of what
/// `SetThreadContext` needs and therefore the whole of what a
/// "suspend, point the instruction pointer at my buffer, resume" injection
/// needs. It is the reason a thread handle is worth stripping even when every
/// process handle is already stripped: the thread is a way in that does not
/// name the process.
pub const THREAD_SET_CONTEXT: u32 = 0x0010;

/// The process rights this product takes off a handle to one of its own
/// processes.
///
/// Removal only. `ObRegisterCallbacks` makes that a hard rule and not a matter
/// of taste: the object manager applies the callback's `DesiredAccess` to the
/// access check that follows, so a callback that *added* a right would be
/// granting a caller something the object's own ACL had refused, and the
/// documented consequence of trying is that the driver's registration is
/// refused. [`strip_process`] is therefore an `&` and can only ever clear bits
/// — see the test that says so.
///
/// The five, and what each one is for:
///
/// | Right | What it stops |
/// |---|---|
/// | [`PROCESS_TERMINATE`] | `TerminateProcess`, and Task Manager's End task |
/// | [`PROCESS_VM_WRITE`] | `WriteProcessMemory` |
/// | [`PROCESS_VM_OPERATION`] | `VirtualAllocEx`, `VirtualProtectEx` |
/// | [`PROCESS_CREATE_THREAD`] | `CreateRemoteThread` |
/// | [`PROCESS_SUSPEND_RESUME`] | `NtSuspendProcess`, freezing the target |
///
/// Deliberately **not** in the set: `PROCESS_QUERY_LIMITED_INFORMATION` and
/// `PROCESS_QUERY_INFORMATION`. Asking a process what it is must stay possible,
/// because that is what every monitoring tool, every crash reporter and this
/// product's own `wenle protect status` do, and a process nobody can look at is
/// indistinguishable from a process that is hiding.
pub const STRIPPED_FROM_PROCESS: u32 = PROCESS_TERMINATE
    | PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_WRITE
    | PROCESS_SUSPEND_RESUME;

/// The thread rights this product takes off a handle to one of its own
/// threads.
///
/// `THREAD_QUERY_INFORMATION` and `THREAD_GET_CONTEXT` are deliberately absent
/// for the reason the process side gives: reading a thread's registers is
/// diagnosis, and writing them ([`THREAD_SET_CONTEXT`]) is not.
pub const STRIPPED_FROM_THREAD: u32 =
    THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT;

/// Take this product's protected rights off a process handle's desired access.
///
/// The result may be zero, and zero is a **refusal**: a caller that asked only
/// for `PROCESS_TERMINATE` ends up asking for nothing, the object manager's
/// access check grants nothing, and `OpenProcess` returns
/// `ERROR_ACCESS_DENIED`. That is the intended outcome and not a degenerate
/// case to guard against.
///
/// A `const fn`, so that the table in the driver can be a `const` and so that
/// the tests below can enumerate the masks at compile time.
pub const fn strip_process(desired_access: u32) -> u32 {
    desired_access & !STRIPPED_FROM_PROCESS
}

/// Take this product's protected rights off a thread handle's desired access.
///
/// See [`strip_process`] for why a zero result is a refusal rather than a bug.
pub const fn strip_thread(desired_access: u32) -> u32 {
    desired_access & !STRIPPED_FROM_THREAD
}

/// How many bytes of a process's image file name the kernel keeps.
///
/// `EPROCESS.ImageFileName` is `UCHAR ImageFileName[15]`, and **15 is not in
/// the WDK**: `EPROCESS` is opaque in `ntddk.h` and `wdm.h`, which declare the
/// type and none of its members, and `PsGetProcessImageFileName` — the call
/// that hands out a pointer to this field — is not declared in any header under
/// `Include\10.0.26100.0` either. Both facts were established by searching
/// those headers rather than assumed; what could not be established here is the
/// field's *size*, because the only authority for a member of an opaque
/// structure is the kernel's own type information, which is not on this
/// machine.
///
/// So this constant is the accepted public value and not a measured one, and
/// the consequence of it being wrong is bounded: this module reads at most
/// `IMAGE_NAME_BYTES` bytes from a pointer into an `EPROCESS`, and every
/// historical size of that field is at least this large, so a wrong constant
/// here shortens the comparison rather than overrunning the structure. The
/// test `the_names_this_product_matches_all_fit_the_field` pins the other half
/// — that nothing this product claims to match is longer than the field can
/// hold, which is the direction that would silently never match.
pub const IMAGE_NAME_BYTES: usize = 15;

/// This product's executable names, as the kernel will hold them.
///
/// Only the three images that *run*. `av_amsi.dll` is loaded into other
/// processes rather than being one, and [`PROTECTED_FILES`] is where the files
/// that are not processes are named.
pub const PROTECTED_IMAGES: [&str; 3] =
    ["wenle-av-service.exe", "wenle-gui.exe", "wenle.exe"];

/// Whether an `EPROCESS.ImageFileName` field names one of this product's
/// processes.
///
/// `field` is the field's bytes exactly as the kernel holds them: at most
/// [`IMAGE_NAME_BYTES`] of them, **not** a NUL-terminated string. The long
/// names in [`PROTECTED_IMAGES`] are therefore truncated to the field's width
/// before they are compared, which is the reason a name longer than
/// [`IMAGE_NAME_BYTES`] is still a name this can match: `wenle-av-service.exe`
/// is held as `wenle-av-servic`.
///
/// # What this can and cannot tell apart
///
/// It cannot tell `wenle-av-service.exe` from a file some other process named
/// `wenle-av-servic.exe`, and it does not need to: the two possible mistakes
/// are protecting a process that is not ours and failing to protect one that
/// is, and only the second is a failure. A shorter name — `wenle.exe`,
/// `wenle-gui.exe` — is shorter than the field, so the kernel's own NUL padding
/// is part of what is compared and a longer name that merely starts with it
/// (`wenle.exe.bak`) does not match.
///
/// Comparison is ASCII case-insensitive, because Windows file names are, and a
/// name assembled in the other case is still the same file.
pub fn is_our_image(field: &[u8]) -> bool {
    PROTECTED_IMAGES.iter().any(|name| holds_name(field, name.as_bytes()))
}

/// Whether `field` holds `name`, padded to the field's width with NULs.
///
/// The padding is not decoration. `ImageFileName` is a fixed 15-byte array the
/// kernel NUL-fills after a shorter name, so `wenle.exe` is held as
/// `wenle.exe\0\0\0\0\0\0` — comparing only the nine meaningful bytes would
/// also match a fifteen-character name whose head is `wenle.exe`.
fn holds_name(field: &[u8], name: &[u8]) -> bool {
    let mut i = 0;
    while i < IMAGE_NAME_BYTES {
        let wanted = if i < name.len() { name[i] } else { 0 };
        // A `field` longer than the kernel's field is not something the kernel
        // produces; reading it as NUL-padded to `IMAGE_NAME_BYTES` is the
        // honest reading of a caller that passed too much, and it makes the
        // comparison fail rather than the function panic.
        let held = if i < field.len() { field[i] } else { 0 };
        if !ascii_fold_eq(wanted, held) {
            return false;
        }
        i += 1;
    }
    true
}

/// `A` and `a` are the same letter; nothing else is folded.
const fn ascii_fold_eq(a: u8, b: u8) -> bool {
    a == b || (a | 0x20) == (b | 0x20) && (a | 0x20).is_ascii_lowercase()
}

/// The names of this product's own files, as they sit in the installation
/// directory.
///
/// The list is `av-guard`'s `Role::paths_in` seen from the other side: that
/// function is the product's own statement of which files it ships, and
/// `av-guard`'s tests check this list against it, so that adding a file to the
/// product without adding it here fails a test rather than silently leaving one
/// file unprotected.
///
/// The driver's own `.sys` is in the list and is the one entry that is not a
/// running image. It is here because the installer places it in the
/// installation directory before copying it into the driver directory, so a
/// write to that copy is a write to the file the next repair install will load.
/// The *loaded* copy is not covered and does not need to be: the image loader
/// holds it open without write sharing for as long as the driver is loaded.
pub const PROTECTED_FILES: [&str; 6] = [
    "wenle-av-service.exe",
    "wenle.exe",
    "wenle-gui.exe",
    "av_amsi.dll",
    "rules.avdb",
    crate::install::FILE_NAME,
];

/// Whether a write to `path` is a write to one of this product's own files.
///
/// `dir` is the installation directory the service named when it armed the
/// gate, in DOS form (`C:\WenleAV`), and `path` is the file the write is on,
/// also in DOS form and already normalised by the filter manager. Both are
/// UTF-16 code units without a terminating NUL.
///
/// The comparison is against the **whole path**: `dir` plus one separator plus
/// one name in [`PROTECTED_FILES`]. A file in a subdirectory of `dir` is not
/// matched, and neither is a differently named file beside the protected ones,
/// which is what keeps this narrow enough to be safe — the previous narrowing
/// mistake in this product's history was a gate that matched a *class* of
/// operation rather than a set of files, and it refused reads of the
/// machine's own files until it was fixed.
///
/// # The gaps, named
///
/// * A short (`8.3`) form of a protected name does not match, and neither does
///   a name with a trailing dot or space. Whether the filter manager's
///   normalised name can be one of those is not something this function can
///   answer or check; what it can say is that the comparison is exact, so a
///   path spelled differently is a path this does not protect.
/// * A hard link to a protected file is a different path, and is not matched.
/// * `dir` is used as it was given. A directory that is itself a link to the
///   installation directory is not resolved here.
///
/// All three are gaps in a defence that is one of several: the file's own ACL,
/// the manifest comparison and this product's own DACL on the directory all
/// cover what these miss, and none of them is defeated by a second spelling of
/// a name.
pub fn is_protected_file(dir: &[u16], path: &[u16]) -> bool {
    let dir = trim_trailing_separator(dir);
    if dir.is_empty() || path.len() <= dir.len() {
        // An empty directory names nothing. A path no longer than the directory
        // cannot be a file *inside* it, which is the same test as "there is
        // room for a separator and at least one character of name".
        return false;
    }
    if !units_eq_ci(&path[..dir.len()], dir) || !is_separator(path[dir.len()]) {
        return false;
    }
    let name = &path[dir.len() + 1..];
    PROTECTED_FILES.iter().any(|candidate| units_eq_ascii_ci(name, candidate.as_bytes()))
}

/// Whether a unit is a path separator in either spelling.
///
/// The filter manager normalises to `\`, and `/` is accepted anyway: this
/// product's own paths are compared here and a caller that built one with
/// forward slashes has built the same path, so refusing it would be a gap with
/// no argument behind it.
fn is_separator(unit: u16) -> bool {
    unit == u16::from(b'\\') || unit == u16::from(b'/')
}

/// Whether `dir` is a shape the write gate can be armed with.
///
/// The gate compares a path the filter manager produced against `dir` plus a
/// separator plus a name, so a `dir` the filter manager would never produce is
/// a gate that can never fire while looking armed. That is the failure this
/// exists to prevent, and it is the quiet kind: the service would report the
/// gate as configured and no write would ever be refused.
///
/// The shape is `<letter>:\<something>` — one ASCII letter, a colon, and a
/// separator. That is what [`crate::path::device_to_dos_path`] builds, which is
/// the only producer of the paths this compares against, and it is also what
/// the installer and the service's own `install_dir` are.
///
/// # What this deliberately does not check
///
/// Anything about the name itself, beyond it being non-empty at the third unit.
/// A directory that does not exist, a name with a trailing separator, a
/// reserved character: none of them makes the *comparison* wrong, and each of
/// them is a fact about a machine rather than about a path, which is not
/// something this crate can see. The one property that matters here is that the
/// comparison has something to match.
pub fn is_absolute_dos_directory(dir: &[u16]) -> bool {
    let dir = trim_trailing_separator(dir);
    if dir.len() < 3 {
        // `C:` is a drive with no directory on it, and `C:\` trims back to
        // `C:`. Both leave nothing for a separator-plus-name to follow, which
        // is the same test as the one below rather than a rule of its own.
        return false;
    }
    is_ascii_letter(dir[0]) && dir[1] == u16::from(b':') && is_separator(dir[2])
}

/// Whether a UTF-16 unit is one of the ASCII letters.
///
/// A free function rather than `u16::is_ascii_alphabetic`, which `core` provides
/// for `u8` and not for `u16`, and rather than a cast: a drive letter above
/// `0x7F` is not a drive letter, and truncating it to a byte to ask would answer
/// about a different character than the one in the path.
fn is_ascii_letter(unit: u16) -> bool {
    (u16::from(b'A')..=u16::from(b'Z')).contains(&unit)
        || (u16::from(b'a')..=u16::from(b'z')).contains(&unit)
}

/// How many code units the write gate's own copy of the directory holds.
///
/// The wire's own limit rather than a second number, because the only way a
/// directory reaches the gate is [`crate::wire::ConfigMessage::dir`], which is
/// clamped to that length. Two constants would be two things to change.
pub const GATE_DIR_UNITS: usize = crate::wire::MAX_PATH_UNITS;

/// What a configuration message does to the write gate.
///
/// Returned by [`gate_update`] and applied by the driver, which is the whole
/// point of the split: the driver's buffer is written through a raw pointer and
/// cannot be tested, and which of these four happens is exactly the part that
/// can be. A driver branch here would be a branch nothing checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateUpdate {
    /// Copy this many units of the incoming directory into the gate's buffer,
    /// then publish the gate as armed.
    ///
    /// Only ever returned when the gate's buffer is still empty, which is what
    /// makes the write safe without a lock: the buffer is filled at most once,
    /// and always before any length that makes a reader look at it.
    Arm {
        /// How many units to copy. Never more than [`GATE_DIR_UNITS`].
        units: usize,
    },
    /// Already armed with this same directory. Nothing to write.
    AlreadyArmed,
    /// Turn the gate off. The stored directory is left where it is, so a later
    /// message naming the same one can arm again without a write.
    Disarm,
    /// The message names a directory the gate cannot take. The gate is left
    /// exactly as it was.
    Refused,
}

/// Decide what a configuration message does to the write gate.
///
/// `stored` is the directory already in the gate's buffer — empty if the gate's
/// buffer has never been **written**, which is the same thing as "never armed"
/// only until the first disarm: [`GateUpdate::Disarm`] leaves the buffer where
/// it is, so a gate that has been armed and then turned off still answers with a
/// non-empty `stored` and re-arms without a write. `incoming` is what the
/// message named, and `enabled` is whether the message asks for the gate at all
/// ([`crate::wire::ConfigMessage::gate_writes`], which is already false when the
/// message named no directory).
///
/// # Why the buffer is written at most once
///
/// The gate's directory cannot change for the life of a driver load, and that is
/// a fact about the product rather than a simplification: the directory is the
/// installation directory, and moving it means uninstalling and reinstalling,
/// which unloads this driver. So a second arm naming a *different* directory is
/// not an update to apply — it is a message that disagrees with the one the
/// gate was built from, and [`GateUpdate::Refused`] is the honest answer.
///
/// This is what makes the driver's unsynchronised write correct. There is no
/// interleaving to lose, because there is no second write; and a reader that
/// sees a published length sees a buffer that was filled before that length was
/// published, because the one write happens-before the one arm.
///
/// # Why turning it off is always allowed
///
/// Disarming cannot be wrong: a gate that is off refuses nothing, which is the
/// state every machine starts in. So this answers [`GateUpdate::Disarm`] for any
/// message that does not ask for the gate — including one that named a directory
/// this function would otherwise have refused. Refusing to *stop* protecting
/// would be a gate that could not be turned off by the only party allowed to
/// turn it off.
///
/// # The directions, named
///
/// Every `Refused` here is a message that would have produced a gate which
/// looks armed and never fires, or which protects a tree that is not this
/// product's. Both are worse than a refusal the sender can see: the first is
/// silence, and the second is a driver refusing writes to somebody else's files.
pub fn gate_update(stored: &[u16], incoming: &[u16], enabled: bool) -> GateUpdate {
    if !enabled {
        return GateUpdate::Disarm;
    }
    if incoming.len() > GATE_DIR_UNITS || !is_absolute_dos_directory(incoming) {
        return GateUpdate::Refused;
    }
    if stored.is_empty() {
        return GateUpdate::Arm {
            units: incoming.len(),
        };
    }
    // Trailing separators first, then `units_eq_ci`, which folds ASCII case and
    // treats the two separators as one. Both halves are needed and each covers
    // what the other cannot: `units_eq_ci` is length-sensitive, and
    // `trim_trailing_separator` is what makes `C:\WenleAV` and `C:\WenleAV\` the
    // same directory.
    //
    // The tolerance is not politeness. `is_protected_file` is handed this same
    // stored directory and trims it, so the two comparisons describe one gate
    // and have to agree about what "the same directory" means -- and a refusal
    // here is not free: the service re-sends its directory on every connect,
    // including right after its own restart, so a spelling difference would
    // report a refusal on a gate that is armed and working.
    let stored = trim_trailing_separator(stored);
    let incoming = trim_trailing_separator(incoming);
    if units_eq_ci(stored, incoming) {
        GateUpdate::AlreadyArmed
    } else {
        GateUpdate::Refused
    }
}

/// `dir` without a trailing separator, so that `C:\WenleAV\` and `C:\WenleAV`
/// are the same directory.
fn trim_trailing_separator(dir: &[u16]) -> &[u16] {
    let mut end = dir.len();
    // Only the trailing one: `C:\` must keep its separator, or the comparison
    // below would look for a file whose path starts with `C:` and a separator
    // that is not there.
    if end > 1 && is_separator(dir[end - 1]) {
        end -= 1;
    }
    &dir[..end]
}

/// Whether the UTF-16 `units` spell the ASCII `ascii`, ignoring case.
fn units_eq_ascii_ci(units: &[u16], ascii: &[u8]) -> bool {
    if units.len() != ascii.len() {
        return false;
    }
    units
        .iter()
        .zip(ascii)
        .all(|(unit, byte)| *unit < 0x80 && ascii_fold_eq(*unit as u8, *byte))
}

/// Whether two UTF-16 slices are the same text, ignoring case of ASCII letters.
///
/// The path side of [`is_protected_file`], where both halves come from the
/// filter manager and neither is a literal. Non-ASCII units are compared
/// exactly, which is the conservative direction: a path whose case deserves a
/// locale-aware fold is a path this does not protect, and the failure mode of
/// the opposite choice would be protecting a path that is not the product's.
fn units_eq_ci(units: &[u16], other: &[u16]) -> bool {
    if units.len() != other.len() {
        return false;
    }
    units.iter().zip(other).all(|(a, b)| {
        let (a, b) = (*a, *b);
        // The two separators are the same separator, here as well as at the
        // boundary. A directory sent as `C:/WenleAV` and a path normalised to
        // `C:\WenleAV\...` are the same location, and a comparison that folded
        // only the last one would be a comparison that half-works.
        if is_separator(a) && is_separator(b) {
            return true;
        }
        if a < 0x80 && b < 0x80 {
            ascii_fold_eq(a as u8, b as u8)
        } else {
            a == b
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a path for the tests.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn the_five_process_rights_are_the_five_the_policy_names() {
        assert_eq!(STRIPPED_FROM_PROCESS, 0x082B);
        assert_eq!(
            STRIPPED_FROM_PROCESS,
            PROCESS_TERMINATE
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_CREATE_THREAD
                | PROCESS_SUSPEND_RESUME
        );
    }

    #[test]
    fn the_three_thread_rights_are_the_three_the_policy_names() {
        assert_eq!(STRIPPED_FROM_THREAD, 0x0013);
    }

    #[test]
    fn stripping_only_ever_removes_rights() {
        // Every bit the stripped mask could possibly set, against every subset
        // of the rights this product cares about. A `strip` that added a bit
        // would fail the object manager's own rule, so this is the property the
        // function exists to have rather than a spot check.
        let interesting = STRIPPED_FROM_PROCESS
            | PROCESS_QUERY_LIMITED_INFORMATION
            | PROCESS_DUP_HANDLE
            | 0x1_0000;
        let mut subset = 0u32;
        loop {
            let stripped = strip_process(subset);
            assert_eq!(
                stripped & !subset,
                0,
                "{subset:#x} gained a right it never asked for: {stripped:#x}"
            );
            if subset == interesting {
                break;
            }
            // Walk the subsets of `interesting` in the only order that
            // terminates: as a counter over its bits.
            subset = ((subset | !interesting).wrapping_add(1)) & interesting;
        }
    }

    #[test]
    fn a_caller_that_asked_only_to_terminate_is_left_asking_for_nothing() {
        // The refusal, and it is the refusal rather than a degenerate case: the
        // object manager's access check grants nothing for a zero desired
        // access, so `OpenProcess(PROCESS_TERMINATE)` on one of this product's
        // processes fails with ACCESS_DENIED.
        assert_eq!(strip_process(PROCESS_TERMINATE), 0);
        assert_eq!(strip_thread(THREAD_SET_CONTEXT), 0);
    }

    #[test]
    fn the_rights_a_monitoring_tool_needs_survive() {
        // The decision that makes this policy usable: looking at this product's
        // processes stays possible. `PROCESS_ALL_ACCESS` is included because it
        // is what a caller that wants everything asks for, and it still ends up
        // unable to terminate what it opened.
        let all = 0x001F_FFFF;
        let after = strip_process(all);
        assert_eq!(after & PROCESS_TERMINATE, 0);
        assert_eq!(after & PROCESS_VM_WRITE, 0);
        assert_ne!(after & PROCESS_QUERY_LIMITED_INFORMATION, 0);
        assert_ne!(after & PROCESS_QUERY_INFORMATION, 0);
        assert_ne!(after & PROCESS_DUP_HANDLE, 0);
    }

    /// Rights this module does **not** strip, quoted from the same header so
    /// that the tests below can name them: `PROCESS_DUP_HANDLE` is `(0x0040)`
    /// at `um\winnt.h` line 12691, `PROCESS_QUERY_INFORMATION` is `(0x0400)` at
    /// line 12695 and `PROCESS_QUERY_LIMITED_INFORMATION` is `(0x1000)` at line
    /// 12697. They are here rather than in the library because nothing in the
    /// library reads them; what they are for is the test that says the rights a
    /// monitoring tool needs survive.
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_DUP_HANDLE: u32 = 0x0040;

    #[test]
    fn the_three_running_images_are_the_ones_this_product_ships() {
        assert!(is_our_image(b"wenle-av-servic"));
        assert!(is_our_image(b"wenle-gui.exe\0\0\0"));
        assert!(is_our_image(b"wenle.exe\0\0\0\0\0\0"));
    }

    #[test]
    fn a_name_shorter_than_the_field_only_matches_at_its_own_length() {
        // `wenle.exe` is nine bytes; the sixth byte of the field is the
        // kernel's NUL. A fifteen-byte name that merely starts with the same
        // nine characters is a different process.
        assert!(!is_our_image(b"wenle.exe.bak\0\0"));
        assert!(!is_our_image(b"wenle.exe2\0\0\0\0\0"));
        // And a name that is `wenle.exe` and then differs inside the padding is
        // not the same file either -- there is no padding to differ *inside*,
        // so what this really checks is that the comparison does not stop at
        // the NUL and accept anything after it.
        assert!(!is_our_image(b"wenle.exe\0X\0\0\0\0"));
    }

    #[test]
    fn no_two_names_this_product_matches_are_the_same_when_truncated() {
        // The direction that fails silently, and it is not "does it fit" --
        // `wenle-av-service.exe` is nineteen characters and the kernel's field
        // is fifteen, which is why the comparison truncates. What must hold is
        // that truncation cannot make two of this product's own images
        // indistinguishable from each other, because then a handle to one of
        // them would be protected by the other's name and the two names would
        // be one policy.
        //
        // (It cannot be made to tell `wenle-av-service.exe` from some other
        // program whose first fifteen characters are the same. That is the
        // accepted failure direction stated in `is_our_image`'s documentation:
        // it protects a process that is not ours rather than missing one that
        // is.)
        for (i, left) in PROTECTED_IMAGES.iter().enumerate() {
            for right in &PROTECTED_IMAGES[i + 1..] {
                let truncate = |s: &str| s.as_bytes()[..s.len().min(IMAGE_NAME_BYTES)].to_vec();
                assert_ne!(
                    truncate(left),
                    truncate(right),
                    "{left} and {right} are the same fifteen bytes"
                );
            }
        }
    }

    #[test]
    fn case_does_not_change_which_process_this_is() {
        assert!(is_our_image(b"WENLE-AV-SERVIC"));
        assert!(is_our_image(b"Wenle-Gui.Exe\0\0"));
    }

    #[test]
    fn a_name_the_kernel_could_never_hold_still_matches_its_own_prefix() {
        // `wenle-av-service.exe` is the name this product ships; the kernel
        // holds its first fifteen bytes and no more. Passing the whole name is
        // something only a test would do, and the answer is the honest one:
        // the first fifteen bytes are what is compared, and they are the same
        // fifteen bytes the kernel would have.
        assert!(is_our_image(b"wenle-av-service.exe"));
    }

    #[test]
    fn something_that_is_not_ours_is_not_matched() {
        // Differs from `wenle-av-servic` in its fifteenth byte, which is the
        // last byte the comparison looks at.
        assert!(!is_our_image(b"wenle-av-servix"));
        assert!(!is_our_image(b"explorer.exe\0\0\0"));
        assert!(!is_our_image(b"wenle-helper.exe"));
        assert!(!is_our_image(b""));
        // A field shorter than the name is NUL-padded, which is *not* the same
        // as being rejected -- the kernel pads, so a short field is the kernel's
        // own form and `wenle.exe` padded is a match. See
        // `the_three_running_images_are_the_ones_this_product_ships`.
    }

    /// The accepted false positive, stated as a test so that it is a decision
    /// rather than a surprise.
    ///
    /// A program whose name starts with the same fifteen bytes as one of ours
    /// is protected as though it were ours. That is the direction
    /// [`is_our_image`]'s documentation chooses: a process this product did not
    /// intend to protect is protected, rather than one of its own processes
    /// being missed. If a name that collides this way ever ships on a real
    /// machine, the visible symptom is a program whose Task Manager "End task"
    /// does nothing, and this test is where the reason is.
    ///
    /// Only `wenle-av-service.exe` (nineteen bytes) can collide this way: the
    /// other two names are thirteen and nine bytes, so the kernel's own NUL
    /// padding is what their fifteenth byte holds and a longer name cannot
    /// reproduce it -- `wenle-gui.exe.bak` differs from `wenle-gui.exe` at byte
    /// fourteen, where the kernel has a NUL and the `.bak` file has a dot.
    #[test]
    fn a_longer_name_with_the_same_first_fifteen_bytes_is_treated_as_ours() {
        assert!(is_our_image(b"wenle-av-service-helper"));
        assert!(is_our_image(b"wenle-av-servic.exe"));
    }

    #[test]
    fn the_files_this_product_protects_are_the_ones_it_ships() {
        let dir = wide(r"C:\WenleAV");
        for name in PROTECTED_FILES {
            let path = wide(&format!(r"C:\WenleAV\{name}"));
            assert!(is_protected_file(&dir, &path), "{name} was not matched");
        }
    }

    #[test]
    fn a_trailing_separator_on_the_directory_changes_nothing() {
        let path = wide(r"C:\WenleAV\rules.avdb");
        assert!(is_protected_file(&wide(r"C:\WenleAV"), &path));
        assert!(is_protected_file(&wide(r"C:\WenleAV\"), &path));
    }

    #[test]
    fn the_drive_root_keeps_its_separator() {
        // `C:\` trimmed to `C:` would then be looking for a file at
        // `C:` + `\` + name, which is the same string -- but it would also make
        // `C:x` compare as inside `C:`, which it is not.
        assert!(is_protected_file(&wide(r"C:\"), &wide(r"C:\rules.avdb")));
        assert!(!is_protected_file(&wide(r"C:\"), &wide(r"C:rules.avdb")));
    }

    #[test]
    fn a_file_beside_the_protected_ones_is_not_protected() {
        let dir = wide(r"C:\WenleAV");
        assert!(!is_protected_file(&dir, &wide(r"C:\WenleAV\readme.txt")));
        assert!(!is_protected_file(&dir, &wide(r"C:\WenleAV\wenle.pdb")));
        assert!(!is_protected_file(&dir, &wide(r"C:\Other\rules.avdb")));
        assert!(!is_protected_file(&dir, &wide(r"C:\WenleAVX\rules.avdb")));
    }

    #[test]
    fn a_file_below_a_protected_one_is_not_protected() {
        // The narrowing that matters. The rule is the product's own files, not
        // the tree around them: the service writes its own configuration, its
        // logs and its vault under the data directory, and a gate that reached
        // any of them would be a product that locks itself out.
        let dir = wide(r"C:\WenleAV");
        assert!(!is_protected_file(&dir, &wide(r"C:\WenleAV\data\rules.avdb")));
        assert!(!is_protected_file(
            &dir,
            &wide(r"C:\WenleAV\logs\wenle-av-service.exe")
        ));
    }

    #[test]
    fn case_and_separator_style_do_not_change_which_file_this_is() {
        let dir = wide(r"C:\WenleAV");
        assert!(is_protected_file(&dir, &wide(r"c:\wenleav\RULES.AVDB")));
        assert!(is_protected_file(&dir, &wide(r"C:/WenleAV/rules.avdb")));
    }

    #[test]
    fn an_empty_directory_protects_nothing() {
        assert!(!is_protected_file(&[], &wide(r"C:\WenleAV\rules.avdb")));
        // And a path that is the directory itself is not a file inside it.
        assert!(!is_protected_file(&wide(r"C:\WenleAV"), &wide(r"C:\WenleAV")));
    }

    #[test]
    fn a_name_that_is_a_prefix_of_a_protected_one_does_not_match() {
        let dir = wide(r"C:\WenleAV");
        assert!(!is_protected_file(&dir, &wide(r"C:\WenleAV\rules.avdb.bak")));
        assert!(!is_protected_file(&dir, &wide(r"C:\WenleAV\wenle.exex")));
    }

    #[test]
    fn the_installation_directory_the_installer_builds_is_armable() {
        // The shape the whole gate is built around, and the one the service
        // sends: a drive letter, a colon, a separator, a name.
        assert!(is_absolute_dos_directory(&wide(r"C:\WenleAV")));
        assert!(is_absolute_dos_directory(&wide(r"c:\WenleAV")));
        assert!(is_absolute_dos_directory(&wide(r"D:\a")));
        // A trailing separator is the same directory, which is the same
        // tolerance `is_protected_file` has and for the same reason.
        assert!(is_absolute_dos_directory(&wide(r"C:\WenleAV\")));
        assert!(is_absolute_dos_directory(&wide(r"C:/WenleAV")));
    }

    #[test]
    fn a_directory_no_path_will_ever_start_with_is_refused() {
        // Each of these arms a gate that can never fire. That is the failure
        // worth a check: the service would report the gate as configured, no
        // write would ever be refused, and nothing would say so.
        assert!(!is_absolute_dos_directory(&[]));
        assert!(!is_absolute_dos_directory(&wide(r"C:")));
        assert!(!is_absolute_dos_directory(&wide(r"C:\")));
        // A relative path is the one a service started with a different working
        // directory could produce, and it is exactly the case that looks fine.
        assert!(!is_absolute_dos_directory(&wide(r"WenleAV")));
        assert!(!is_absolute_dos_directory(&wide(r"\WenleAV")));
        // A UNC path is absolute and is still not one of these: nothing in this
        // product produces one, and the comparison against a device-to-DOS path
        // would never match it.
        assert!(!is_absolute_dos_directory(&wide(r"\\server\share")));
        // Separators without a drive, and a drive without a separator.
        assert!(!is_absolute_dos_directory(&wide(r"C:WenleAV")));
        assert!(!is_absolute_dos_directory(&wide(r":\WenleAV")));
        assert!(!is_absolute_dos_directory(&wide(r"1:\WenleAV")));
    }

    #[test]
    fn a_drive_letter_outside_ascii_is_not_a_drive_letter() {
        // Truncating a unit above `0x7F` to a byte and asking `u8` would make
        // this one an `A`; asking about the unit itself does not.
        let mut dir = wide(r"C:\WenleAV");
        dir[0] = 0x1041;
        assert!(!is_absolute_dos_directory(&dir));
    }

    // ---- the write gate's own decisions -------------------------------------

    #[test]
    fn a_message_that_does_not_ask_for_the_gate_disarms_it() {
        // The service turning the gate off is always honored, and it is what
        // every machine starts with, so refusing it would be refusing to stop.
        assert_eq!(gate_update(&[], &wide(r"C:\WenleAV"), false), GateUpdate::Disarm);
        assert_eq!(
            gate_update(&wide(r"C:\WenleAV"), &wide(r"C:\WenleAV"), false),
            GateUpdate::Disarm
        );
        // Including a message that named something the gate would have refused
        // while enabled: this one is not asking to be armed, so the directory
        // is not a gate directory and is not examined as one.
        assert_eq!(gate_update(&[], &wide(r"WenleAV"), false), GateUpdate::Disarm);
        assert_eq!(gate_update(&wide(r"C:\WenleAV"), &[], false), GateUpdate::Disarm);
    }

    #[test]
    fn the_first_arm_takes_the_installation_directory() {
        let dir = wide(r"C:\WenleAV");
        let update = gate_update(&[], &dir, true);
        assert_eq!(update, GateUpdate::Arm { units: dir.len() });
        // What the driver copies, checked here rather than trusted there.
        let GateUpdate::Arm { units } = update else {
            unreachable!("just asserted")
        };
        assert!(units <= GATE_DIR_UNITS);
    }

    #[test]
    fn a_gate_is_never_armed_with_a_directory_no_path_starts_with() {
        // The failure this prevents is silent: the service reports the gate as
        // configured, no write is ever refused, and nothing says so.
        for bad in [
            &[][..],
            &wide(r"C:")[..],
            &wide(r"C:\")[..],
            &wide(r"WenleAV")[..],
            &wide(r"\WenleAV")[..],
            &wide(r"\\server\share")[..],
        ] {
            assert_eq!(
                gate_update(&[], bad, true),
                GateUpdate::Refused,
                "armed with {:?}",
                String::from_utf16_lossy(bad)
            );
        }
    }

    #[test]
    fn re_arming_with_the_same_directory_writes_nothing() {
        let stored = wide(r"C:\WenleAV");
        // The service reads the directory out of its own configuration, so the
        // spelling is stable across restarts -- but a separator or a letter
        // case that differs is the same directory, and the same comparison
        // `is_protected_file` makes has to accept it here.
        for again in [
            &wide(r"C:\WenleAV")[..],
            &wide(r"C:/WenleAV")[..],
            &wide(r"c:\wenleav")[..],
            &wide(r"C:\WenleAV\")[..],
        ] {
            assert_eq!(
                gate_update(&stored, again, true),
                GateUpdate::AlreadyArmed,
                "re-armed with {:?}",
                String::from_utf16_lossy(again)
            );
        }
    }

    #[test]
    fn a_second_different_directory_is_refused_rather_than_written() {
        // The installation directory cannot change without an uninstall, which
        // unloads this driver. So a different one is a message that disagrees
        // with the gate's own basis, and refusing it is what lets the driver
        // write its buffer unsynchronised: there is no second write to lose.
        for other in [
            &wide(r"C:\Other")[..],
            &wide(r"C:\WenleAV2")[..],
            &wide(r"D:\WenleAV")[..],
            &wide(r"C:\WenleAV\sub")[..],
        ] {
            assert_eq!(
                gate_update(&wide(r"C:\WenleAV"), other, true),
                GateUpdate::Refused,
                "re-armed with {:?}",
                String::from_utf16_lossy(other)
            );
        }
    }

    #[test]
    fn a_refusal_leaves_the_directory_the_gate_already_had() {
        // `Refused` is what the driver applies as "do nothing", so the gate is
        // left armed with whatever it was armed with -- which is the directory
        // this arm would have replaced, not the one it named.
        assert_eq!(gate_update(&[], &[], true), GateUpdate::Refused);
        assert_eq!(gate_update(&[], &wide(r"WenleAV"), true), GateUpdate::Refused);
        // And an empty gate naming a *usable* directory is not a refusal at
        // all: with nothing stored, `C:\Other` arms the gate. Wrong files, but
        // the decision this function owns is whether the directory is a
        // directory, not whether it is the right one -- the driver has no way
        // to know the right one, which is why the service is the one that says.
        assert_eq!(
            gate_update(&[], &wide(r"C:\Other"), true),
            GateUpdate::Arm { units: 8 }
        );
    }

    #[test]
    fn a_directory_too_long_for_the_buffer_is_refused() {
        // The driver copies `units` elements into a `[u16; GATE_DIR_UNITS]`.
        // The wire clamps to that length, so this cannot arrive from the
        // service -- which is exactly why the bound is checked where it can be
        // tested rather than assumed where it cannot.
        let longest = vec![u16::from(b'a'); GATE_DIR_UNITS + 1];
        assert_eq!(gate_update(&[], &longest, true), GateUpdate::Refused);

        let mut fits = wide(r"C:\");
        fits.resize(GATE_DIR_UNITS, u16::from(b'a'));
        assert_eq!(
            gate_update(&[], &fits, true),
            GateUpdate::Arm {
                units: GATE_DIR_UNITS
            }
        );
    }

    #[test]
    fn the_gate_is_only_ever_written_while_its_buffer_is_empty() {
        // The property the driver's unsynchronised write rests on, over every
        // combination of the three inputs rather than over the cases above.
        // `Arm` returned with a non-empty `stored` would be a second write, and
        // a second write is one a reader could see half of.
        let dirs: [&[u16]; 6] = [
            &[],
            &wide(r"C:\WenleAV"),
            &wide(r"C:\WenleAV\"),
            &wide(r"c:/wenleav"),
            &wide(r"C:\Other"),
            &wide(r"WenleAV"),
        ];
        for stored in dirs {
            for incoming in dirs {
                for enabled in [true, false] {
                    let update = gate_update(stored, incoming, enabled);
                    if matches!(update, GateUpdate::Arm { .. }) {
                        assert!(
                            stored.is_empty(),
                            "Arm with a stored directory {:?}",
                            String::from_utf16_lossy(stored)
                        );
                        assert!(enabled);
                    }
                }
            }
        }
    }

    #[test]
    fn disarming_never_returns_anything_but_disarm() {
        // The other half of the same property, from the side the driver reads
        // as "publish the gate as off": no stored directory, no incoming
        // directory, and no length can turn that into a write or a refusal.
        let dirs: [&[u16]; 4] = [&[], &wide(r"C:\WenleAV"), &wide(r"WenleAV"), &wide(r"C:\Other")];
        for stored in dirs {
            for incoming in dirs {
                assert_eq!(gate_update(stored, incoming, false), GateUpdate::Disarm);
            }
        }
    }
}
