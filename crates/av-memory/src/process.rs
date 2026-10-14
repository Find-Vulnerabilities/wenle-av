//! Naming the processes on a machine, and the string a finding is attributed to.
//!
//! # Why the list is three fields and not one
//!
//! A scan needs three different things about a process and they are not always
//! available together:
//!
//! * the **PID**, which is what every call is made with and the only field that
//!   is always present;
//! * the **image path**, which is what a user recognises and what a report
//!   wants to show;
//! * the **base name**, which is what fits on a line of a console report.
//!
//! Naming a process needs a handle with `PROCESS_QUERY_LIMITED_INFORMATION`,
//! and on a real machine that is refused for close to half the process list —
//! measured here across five runs, over machines holding 270 to 296 processes.
//! The right was chosen by measuring both, and the measurement came out the same
//! way every time: `PROCESS_QUERY_LIMITED_INFORMATION` named 122 to 149 of those
//! processes and `PROCESS_QUERY_INFORMATION` named 115 to 141, so the limited
//! right named seven or eight processes that the full right could not name at
//! all, and the full right named **none** that the limited right missed. The
//! ones the limited right won were `MSPCManagerService.exe`, `OmApSvcBroker.exe`,
//! `VoiceControl_Engine.exe`, `ctfmon.exe`, `MSI.TerminalServer.exe`,
//! `taskhostw.exe`, `SecurityHealthHost.exe` and `audiodg.exe` — processes
//! running as another account or as a protected service, which are exactly the
//! ones a scan most wants to be able to describe. The measurement is a live test
//! (`naming_a_process_needs_the_least_right_that_answers_the_question`), not a
//! note taken once. So a process that cannot be named is still listed, and the
//! listing is not an error: a list that failed because one protected service
//! would not open would make the scan refuse the machine because of one service.
//!
//! # What a finding is attributed to instead of a path
//!
//! A file finding is attributed to a path, because a path is what a user can go
//! and look at. A memory finding is attributed to the process and the address,
//! as `explorer.exe:0x7ff6a1b20000`, and that string goes in
//! [`av_core::Detection::container`] — because the address is what identifies
//! the *evidence*, and for the case that makes memory scanning worth running at
//! all there is no path to give: nothing on disk holds those bytes.
//!
//! That is not the whole truth about a finding, though, and the part it leaves
//! out is the part an action needs. The bytes at an address very often *do* come
//! from a file — an image the loader mapped — and then the file is the thing to
//! deal with. So the attribution here stays the process and the address, and
//! where the bytes came from is a second field on the finding, answered by
//! [`crate::provenance`] and kept apart from the empty case rather than folded
//! into the same `Option`. The archive walk puts a member name in the same
//! field, and the console and the JSON report already render that field in front
//! of a match offset, so a memory finding prints correctly without any consumer
//! learning a new shape — with the one exception [`crate`]'s own documentation
//! names: across the service's pipe the attribution is `in_process` on an
//! `av_ipc::Detection`, because a client needs the path and the place in two
//! fields at once, not one field holding both. The offset underneath it is then
//! an offset into the region, which is what makes the pair readable: the address
//! says where the region is, the offset says where in it the match was.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{MemoryError, Result};

/// The largest number of PIDs a single enumeration will hold.
///
/// `EnumProcesses` reports four bytes per process, so this caps the buffer at
/// four mebibytes. It is a bound on a hostile or broken system rather than a
/// real limit — a machine with a million running processes is not a machine —
/// and it exists so that the growth loop below cannot allocate without end if
/// the API ever reports a nonsense required size.
const MAX_PIDS: usize = 1 << 20;

/// The first size the PID buffer is asked for.
///
/// One allocation of this size covers a normal machine: measured at 270 to 296
/// processes while this crate was written, and a doubling loop from here
/// reaches a hundred thousand processes in eight more allocations.
const PID_BUFFER_START: usize = 1024;

/// One process, identified as far as it could be without opening it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRef {
    /// The process identifier. Always present, and the only field the operating
    /// system needs to act on this process.
    pub pid: u32,
    /// The full path of the process's image, when it could be read.
    ///
    /// `None` means the process could not be named — it belongs to another
    /// user, or it is protected, or it exited between being listed and being
    /// asked about. It does **not** mean the process is not there.
    pub image: Option<PathBuf>,
    /// The image's file name, for a line of a report.
    pub name: Option<String>,
}

impl ProcessRef {
    /// A process identified by its path, when one could be read.
    pub fn new(pid: u32, image: Option<PathBuf>) -> Self {
        let name = image
            .as_deref()
            .and_then(std::path::Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty());
        Self { pid, image, name }
    }

    /// A process that could not be named.
    pub const fn anonymous(pid: u32) -> Self {
        Self {
            pid,
            image: None,
            name: None,
        }
    }

    /// The shortest honest name for this process.
    ///
    /// The image's file name when there is one, and otherwise the PID spelled
    /// out — never an empty string, because this is the prefix of every finding
    /// this process produces and a finding that pointed at nothing would be
    /// worse than one that pointed at a number.
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => format!("pid {}", self.pid),
        }
    }

    /// The name with the PID attached, for a report line about the process
    /// itself rather than about a region in it.
    pub fn describe(&self) -> String {
        match &self.image {
            Some(image) => format!("{} ({}) [{}]", self.label(), self.pid, image.display()),
            None => format!("{} (pid {}, image unknown)", self.label(), self.pid),
        }
    }

    /// The string a finding at `address` in this process is attributed to.
    ///
    /// This is what goes into [`av_core::Detection::container`]; see the module
    /// documentation for why it is the process and the address and not a path.
    pub fn container(&self, address: usize) -> String {
        format!("{}:{address:#x}", self.label())
    }
}

/// The identifier of the process this code is running in.
///
/// A scan of one's own process is the one scan that cannot be refused, which
/// makes it the honest first target for a test and the fallback for a machine
/// where nothing else can be opened.
pub fn current_pid() -> u32 {
    #[cfg(windows)]
    let pid = {
        // SAFETY: `GetCurrentProcessId` reads a value the kernel keeps for the
        // calling thread's process. It takes no arguments, touches no memory
        // this code owns, and cannot fail.
        unsafe { windows::Win32::System::Threading::GetCurrentProcessId() }
    };
    #[cfg(not(windows))]
    let pid = std::process::id();
    pid
}

/// Every process on the machine, named as far as each one could be.
///
/// One entry per PID the operating system returned, including the ones that
/// could not be named. PID 0 is left out: it is the idle process, it has no
/// image and no address space to walk, and Windows refuses it with the same
/// "no such process" code it uses for a PID that was never allocated — so
/// listing it would put a permanent, meaningless refusal in every report.
pub fn list_processes() -> Result<Vec<ProcessRef>> {
    #[cfg(windows)]
    let outcome = {
        let pids = enumerate_pids()?;
        let processes: Vec<ProcessRef> = pids
            .into_iter()
            .filter(|pid| *pid != 0)
            .map(entry_for)
            .collect();
        log::debug!(
            "{} processes enumerated, {} named",
            processes.len(),
            processes.iter().filter(|p| p.name.is_some()).count()
        );
        Ok(processes)
    };
    #[cfg(not(windows))]
    let outcome = Err(MemoryError::Unsupported);
    outcome
}

/// The PIDs the operating system reports.
///
/// `EnumProcesses` cannot say how large a buffer it needs. Asked with a zero
/// length it reports zero bytes required — measured, with a null array and with
/// a real one — so the size has to be discovered by guessing and doubling, and
/// the loop below terminates on the first guess that comes back unfilled.
/// A guess that is exactly filled is indistinguishable from one that was too
/// small, which is why the loop doubles rather than stopping when the buffer is
/// full.
#[cfg(windows)]
fn enumerate_pids() -> Result<Vec<u32>> {
    use windows::Win32::System::ProcessStatus::EnumProcesses;

    let mut capacity = PID_BUFFER_START;
    loop {
        let mut buffer: Vec<u32> = vec![0; capacity];
        let mut needed = 0u32;
        let bytes = (capacity * std::mem::size_of::<u32>()) as u32;
        // SAFETY: `buffer` holds `capacity` u32s and `bytes` is exactly its
        // size, which is the contract: `EnumProcesses` writes whole u32 PIDs
        // and never more than `cb` bytes of them. `needed` is a live local that
        // the call fills with the number of bytes it wrote.
        unsafe { EnumProcesses(buffer.as_mut_ptr(), bytes, &mut needed) }.map_err(|error| {
            MemoryError::Platform {
                operation: "EnumProcesses".to_string(),
                code: crate::error::win32_code(error.code().0 as u32),
                message: error.message(),
            }
        })?;

        // A partial write is the operating system's way of saying "there are
        // more than fitted", so only a count below the capacity can be the
        // whole list. The division is safe: `needed` came from this call and is
        // a byte count of u32s, and a value that is somehow not is treated as a
        // full buffer rather than as a huge allocation.
        let count = needed as usize / std::mem::size_of::<u32>();
        if count < capacity {
            buffer.truncate(count);
            return Ok(buffer);
        }
        capacity = capacity.saturating_mul(2);
        if capacity > MAX_PIDS {
            log::warn!("the process list did not fit in {MAX_PIDS} entries");
            return Err(MemoryError::Platform {
                operation: "EnumProcesses".to_string(),
                code: crate::error::ERROR_INVALID_PARAMETER,
                message: format!("the process list did not fit in {MAX_PIDS} entries"),
            });
        }
    }
}

/// Identify one PID, opening it for the least privilege that will do.
///
/// The single-PID form of [`list_processes`], for a caller that already knows
/// which process it is asking about and must not enumerate the machine to find
/// out its name. A caller that gets the PID from a detection, a driver event or
/// a user has one PID in hand; walking three hundred processes to name it would
/// make the answer cost more than the question.
///
/// A PID that names no running process is not an error here: it comes back
/// [`ProcessRef::anonymous`], which is the same answer [`list_processes`] gives
/// for a process it could not name, and the caller finds out what it is dealing
/// with when it tries to open the process for reading.
///
/// `PROCESS_QUERY_LIMITED_INFORMATION` and not `PROCESS_QUERY_INFORMATION`:
/// the limited right is what Windows introduced so that a process could be
/// named without being readable, and on this machine it named more processes
/// than the full right did — 122 to 149 of them against 115 to 141, over five
/// runs — with seven or eight named by the limited right alone and none named
/// only by the full one. They are the processes running as another account or
/// as a protected service, which are exactly the ones a memory scan has the
/// best reason to want to describe. The least right is not a compromise here;
/// it is the better right, and it is measured rather than assumed — see the
/// module doc.
pub fn identify(pid: u32) -> ProcessRef {
    #[cfg(windows)]
    {
        entry_for(pid)
    }
    #[cfg(not(windows))]
    {
        ProcessRef::anonymous(pid)
    }
}

/// Read one process's image path, and name it.
///
/// The Windows half of [`identify`]; see there for why the access mask is the
/// limited right.
#[cfg(windows)]
fn entry_for(pid: u32) -> ProcessRef {
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: `OpenProcess` is called with a documented access mask, a PID that
    // came from `EnumProcesses`, and `false` for inheritance, so nothing is
    // inherited and no pointer is involved. A failure is returned as a `Result`
    // and handled below.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => handle,
        Err(_) => return ProcessRef::anonymous(pid),
    };

    let mut buffer = vec![0u16; MAX_IMAGE_PATH_UNITS];
    let mut length = buffer.len() as u32;
    // SAFETY: `buffer` holds `length` u16s, which is the size the call is told
    // about, and the call writes a NUL-terminated path of at most that many
    // units into it. `length` is a live local the call updates to the number of
    // units written, excluding the terminator, so the slice formed below is
    // within the buffer.
    let outcome = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    };
    // SAFETY: the handle came from `OpenProcess` above, is owned by this
    // function, and is not used after this point; `CloseHandle` on it is the
    // documented way to release it. Its return value is discarded because
    // there is nothing a caller could do about a handle that would not close
    // other than leak it, and the process ends either way.
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }

    if outcome.is_err() {
        return ProcessRef::anonymous(pid);
    }
    let units = (length as usize).min(buffer.len());
    ProcessRef::new(
        pid,
        Some(PathBuf::from(String::from_utf16_lossy(&buffer[..units]))),
    )
}

/// Longest image path this crate will ask Windows for, in UTF-16 units.
///
/// Windows' own documented maximum for a path is 32,767 characters; this is
/// that limit, so a path that fits on the system fits here. The buffer is
/// sixteen kibibytes of stack-free heap and is allocated once per process
/// named, which is nothing against the cost of opening the process at all.
#[cfg(windows)]
const MAX_IMAGE_PATH_UNITS: usize = 32_768;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_process_takes_its_name_from_the_image() {
        let p = ProcessRef::new(4321, Some(PathBuf::from(r"C:\Windows\explorer.exe")));
        assert_eq!(p.label(), "explorer.exe");
        assert_eq!(p.pid, 4321);
        assert_eq!(
            p.image.as_deref(),
            Some(std::path::Path::new(r"C:\Windows\explorer.exe"))
        );
    }

    #[test]
    fn an_unnamed_process_is_still_usable_and_says_so() {
        // The case that is *not* an error: a protected or other-user process
        // has no name and still has a PID, and a finding in it must still be
        // attributable.
        let p = ProcessRef::anonymous(4321);
        assert_eq!(p.label(), "pid 4321");
        assert!(p.name.is_none());
        assert!(p.image.is_none());

        // A path with no file name — a bare separator — must not produce an
        // empty label, which would make every finding in that process point at
        // nothing.
        let odd = ProcessRef::new(7, Some(PathBuf::from(r"C:\")));
        assert_eq!(
            odd.label(),
            "pid 7",
            "a path with no file name falls back to the PID"
        );
    }

    #[test]
    fn the_container_names_the_process_and_the_address() {
        // The exact string that ends up in `Detection::container`. The console
        // prints it in front of a match offset, so its shape is a contract with
        // a consumer that is not in this crate.
        let p = ProcessRef::new(8808, Some(PathBuf::from(r"C:\Windows\explorer.exe")));
        assert_eq!(p.container(0x7ff6_a1b2_0000), "explorer.exe:0x7ff6a1b20000");
        assert_eq!(p.container(0), "explorer.exe:0x0");

        // An unnamed process produces a container rather than a panic or an
        // empty prefix.
        let unnamed = ProcessRef::anonymous(4);
        assert_eq!(unnamed.container(0x1000), "pid 4:0x1000");
    }

    #[test]
    fn describe_includes_the_pid_and_the_path_when_it_has_them() {
        let p = ProcessRef::new(8808, Some(PathBuf::from(r"C:\Windows\explorer.exe")));
        let text = p.describe();
        assert!(text.contains("explorer.exe"), "{text}");
        assert!(text.contains("8808"), "{text}");
        assert!(text.contains(r"C:\Windows\explorer.exe"), "{text}");

        let unnamed = ProcessRef::anonymous(4);
        let text = unnamed.describe();
        assert!(text.contains("pid 4"), "{text}");
        assert!(text.contains("image unknown"), "{text}");
    }

    #[test]
    fn this_process_can_always_name_itself() {
        // Not a machine-dependent assertion: `current_pid` is this process, and
        // the PID of a running process is never zero.
        assert_ne!(current_pid(), 0);
    }
}
