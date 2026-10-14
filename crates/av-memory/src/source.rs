//! Where a scan's regions and bytes come from.
//!
//! # Why this is a trait
//!
//! Everything interesting about a memory scan happens *between* two calls to
//! Windows: which regions the walk produced, which of them the predicate kept,
//! what came back when they were read, and what the counts say afterwards. The
//! two calls themselves — `VirtualQueryEx` and `ReadProcessMemory` — are two
//! lines each and are the least interesting code in the crate.
//!
//! So the two calls sit behind [`MemorySource`], and everything else is written
//! against that trait. The consequence is that the whole of a scan's logic is
//! tested by handing it a scripted process rather than by hoping the machine
//! running the tests happens to hold an injected region at a known address. The
//! tests that need a real machine are marked as such and are the minority.
//!
//! # The contract a source must keep
//!
//! * [`MemorySource::regions`] returns regions in ascending address order and
//!   says whether the walk reached the end of the address space. A short list
//!   is not a short address space, and the flag is the only thing that tells
//!   the two apart.
//! * [`MemorySource::read`] either returns exactly the number of bytes asked
//!   for or returns an error. It never returns fewer bytes with a success, and
//!   the scanner does not trust it to: a short buffer handed to the engine
//!   would be a *different buffer* than the region holds, and the engine's
//!   verdict would be about bytes that are not there.
//! * A read that fails is an error and never an empty buffer. That is the whole
//!   reason the trait has a `Result` here.
//!
//! # What the Windows implementation asks for
//!
//! `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, in one handle, and
//! nothing else. The measured reason: `PROCESS_QUERY_LIMITED_INFORMATION` is
//! enough for `VirtualQueryEx` — checked against a live process, where the
//! 48-byte query succeeded with the limited right alone — and as a naming right
//! it opens more processes than `PROCESS_QUERY_INFORMATION` does (122 to 149 of
//! them against 115 to 141, measured across every process on the machine, five
//! runs). `PROCESS_VM_READ` is the right the walk itself needs, and it is the
//! expensive one: with it added, 115 to 136 of those processes could be opened
//! at all, which is the census recorded in the crate documentation. Asking for a
//! stronger right where the weaker one will do is how a scanner ends up unable
//! to look at the processes it most wants to, so the mask is the two rights that
//! are used and no more.

use crate::error::{MemoryError, Result};
use crate::process::ProcessRef;
use crate::provenance::Origin;
use crate::region::MemoryRegion;

/// A process's regions, and the bytes inside them.
///
/// Implemented by [`Win32Source`] against a live process and by a scripted
/// source in the tests.
pub trait MemorySource {
    /// Which process this is. Used to attribute findings.
    fn process(&self) -> &ProcessRef;

    /// Every region of the address space, in ascending address order, up to
    /// `limit` of them.
    ///
    /// `limit` is a bound on the walk rather than a filter: a walk that stops
    /// because it reached the limit reports itself as incomplete, so a caller
    /// can never mistake a truncated list for a small address space.
    fn regions(&mut self, limit: usize) -> Result<RegionWalk>;

    /// The bytes at `base`, exactly `length` of them.
    ///
    /// `length` is the caller's to bound. The scanner caps it at
    /// [`MemoryScanConfig::max_region_bytes`](crate::MemoryScanConfig::max_region_bytes)
    /// and at what the region is reported to hold — a read that crosses the end
    /// of a region fails wholesale rather than returning a short buffer.
    fn read(&mut self, base: usize, length: usize) -> Result<Vec<u8>>;

    /// The file on disk that backs `base`, as far as this source can tell.
    ///
    /// The default is [`Origin::Unknown`], and the default is the point: a
    /// source that cannot answer must not answer [`Origin::Nothing`], which
    /// says the bytes were written into memory that no file holds. That is the
    /// injected-code shape, it is the reason a memory scan is worth running at
    /// all, and a source that produced it because it had no way to ask would be
    /// reporting an injection that is not there. See [`crate::provenance`].
    ///
    /// Takes `&self` rather than `&mut self` because the answer is a property of
    /// the process at the moment it is asked, not a step in the scan: nothing
    /// about asking changes what a later read would return.
    fn backing_file(&self, _base: usize) -> Origin {
        Origin::Unknown
    }
}

/// The regions a walk produced, and whether the walk finished.
///
/// The flag is separate from the list because the two facts are independent: a
/// list of one region can be a complete picture of a tiny address space or the
/// first region of a huge one, and a report that read the length of the list as
/// the size of the answer would claim coverage it does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionWalk {
    /// The regions, in ascending address order.
    pub regions: Vec<MemoryRegion>,
    /// True when the walk reached the end of the address space rather than
    /// stopping at the caller's limit or at an error.
    pub complete: bool,
}

impl RegionWalk {
    /// A complete walk of the given regions.
    pub fn complete(regions: Vec<MemoryRegion>) -> Self {
        Self {
            regions,
            complete: true,
        }
    }

    /// A walk that stopped at the caller's limit.
    pub fn truncated(regions: Vec<MemoryRegion>) -> Self {
        Self {
            regions,
            complete: false,
        }
    }
}

/// A process handle, closed when it goes out of scope.
///
/// Written here rather than taken from the binding crate, whose `Owned` wrapper
/// is not part of its published surface. The one thing this type exists for is
/// the `Drop` impl: a memory scan opens a handle per process and a scan of a
/// machine opens hundreds, so a handle that leaked on an early return would
/// exhaust the process's handle table on a scan of a busy machine rather than
/// on a test.
#[cfg(windows)]
#[derive(Debug)]
struct OwnedHandle(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl OwnedHandle {
    /// Take ownership of a handle that came from a Win32 call.
    ///
    /// # Safety
    ///
    /// The handle must be open, must be owned by no one else, and must be one
    /// `CloseHandle` is the correct way to release — which is every handle
    /// `OpenProcess` returns.
    const unsafe fn new(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self(handle)
    }

    /// The raw handle, for the calls that take one.
    const fn raw(&self) -> windows::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `OpenProcess`, is owned by this value
        // alone, and is not used after this point. `CloseHandle` is the
        // documented way to release it. Its result is discarded deliberately:
        // the only failure it can report is a handle that was already invalid,
        // and there is nothing useful to do about that inside a destructor.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

// A process handle is a reference to a kernel object, not to anything with
// thread affinity: `VirtualQueryEx`, `ReadProcessMemory` and `CloseHandle` may
// all be called on one from any thread. Saying so lets a caller scan processes
// in parallel, which is the only way a scan of a machine with two hundred
// scannable processes finishes in reasonable time.
#[cfg(windows)]
unsafe impl Send for OwnedHandle {}

/// A live process, opened for reading.
#[cfg(windows)]
#[derive(Debug)]
pub struct Win32Source {
    process: ProcessRef,
    handle: OwnedHandle,
    /// Drive letter to volume device, for translating the names the kernel
    /// reports addresses under. Built once, so that two findings from one scan
    /// cannot disagree about a path.
    devices: crate::provenance::DosDevices,
    /// Every image the loader has mapped into this process.
    ///
    /// Read once at open rather than per address: a scan asks about hundreds of
    /// addresses in the same process, and the list is the *fallback* for the
    /// question the kernel answers directly — an image loaded after this call
    /// is an image whose addresses the kernel names itself.
    ///
    /// Empty when the process could not be snapshotted, which is not an error:
    /// the module list is a fallback, and a process that cannot supply one can
    /// still be read.
    modules: Vec<crate::provenance::Module>,
}

#[cfg(windows)]
impl Win32Source {
    /// Open a process for a memory scan.
    ///
    /// The failure modes are the report's refusal reasons: [`MemoryError::Gone`]
    /// when the PID no longer names a running process, and
    /// [`MemoryError::Denied`] when Windows will not give this caller a handle.
    /// Both are ordinary on a live machine — a scan of every process on the
    /// development machine this was written on was refused 151 to 155 times out
    /// of 270 to 296, every one of them with the same code.
    pub fn open(process: ProcessRef) -> Result<Self> {
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        };

        let mask = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
        // SAFETY: `OpenProcess` takes an access mask, a PID and an inherit
        // flag. Nothing here is a pointer, `false` means no handle is
        // inherited, and a refusal comes back as a `Result` that is handled
        // rather than unwrapped.
        let handle = unsafe { OpenProcess(mask, false, process.pid) }
            .map_err(|error| crate::error::from_open_process(process.pid, &error))?;
        // SAFETY: `handle` is a valid, open process handle returned by
        // `OpenProcess` and not owned by anything else, which is what
        // `OwnedHandle::new` requires.
        let owned = unsafe { OwnedHandle::new(handle) };
        let modules = match crate::provenance::modules(process.pid) {
            Ok(modules) => modules,
            // Logged and not returned: see the field's documentation. A process
            // whose images cannot be listed is still a process whose regions can
            // be read, and refusing it here would trade a whole scan for a
            // fallback.
            Err(error) => {
                log::debug!(
                    "the images of {} could not be listed, so an address the kernel will not \
                     name a file for will be reported as unknown rather than as inside an \
                     image: {error}",
                    process.label()
                );
                Vec::new()
            }
        };
        Ok(Self {
            process,
            handle: owned,
            devices: crate::provenance::DosDevices::query(),
            modules,
        })
    }

    /// Open this process.
    ///
    /// The one target that cannot be refused, and therefore the one a caller
    /// can always fall back to.
    pub fn current() -> Result<Self> {
        let pid = crate::process::current_pid();
        Self::open(ProcessRef::new(pid, std::env::current_exe().ok()))
    }

    /// The handle, for the calls that take one.
    fn handle(&self) -> windows::Win32::Foundation::HANDLE {
        self.handle.raw()
    }
}

#[cfg(windows)]
impl MemorySource for Win32Source {
    fn process(&self) -> &ProcessRef {
        &self.process
    }

    fn regions(&mut self, limit: usize) -> Result<RegionWalk> {
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};

        let pid = self.process.pid;
        let mut address = 0usize;
        let mut regions = Vec::new();

        loop {
            if regions.len() >= limit {
                return Ok(RegionWalk::truncated(regions));
            }

            let mut info = MEMORY_BASIC_INFORMATION::default();
            let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
            // SAFETY: the handle is open and was opened with the right
            // `VirtualQueryEx` needs, checked against a live process. `info` is
            // a live local of exactly the size passed as `dwLength`, which is
            // what the call writes into. `address` is a query address, not a
            // pointer this code dereferences, and the API treats an address
            // that names no region as a query it answers or refuses rather than
            // as a fault.
            let written = unsafe {
                VirtualQueryEx(
                    self.handle(),
                    Some(address as *const core::ffi::c_void),
                    &mut info,
                    size,
                )
            };

            if written == 0 {
                // The walk's end is not reported as a success by this API: it
                // is a failure with `ERROR_INVALID_PARAMETER` at the first
                // address past the top of the user address space — measured at
                // `0x7fffffff0000` on x64, which is where a complete walk of
                // this process stopped. Any *other* code means the walk stopped
                // for a reason, and a walk that stopped for a reason must not
                // be reported as a complete picture.
                //
                // SAFETY: `GetLastError` takes no arguments, reads the calling
                // thread's last-error value, and cannot fail. It is read here,
                // immediately after the call that set it, because that is the
                // only time it is guaranteed to still describe this call.
                let last = unsafe { windows::Win32::Foundation::GetLastError() };
                if last.0 == crate::error::ERROR_INVALID_PARAMETER {
                    return Ok(RegionWalk::complete(regions));
                }
                return Err(MemoryError::RegionWalk {
                    pid,
                    address,
                    code: last.0,
                    message: windows::core::Error::from(last).message(),
                });
            }

            if written < size {
                // Fewer bytes than the structure needs. Reading the fields the
                // call did not write would be reading a zero-initialised
                // local, which would report a region of size zero at address
                // zero — a plausible-looking wrong answer, which is worse than
                // a refusal.
                return Err(MemoryError::RegionWalk {
                    pid,
                    address,
                    code: crate::error::ERROR_INVALID_PARAMETER,
                    message: format!(
                        "a region query wrote {written} of the {size} bytes a region needs"
                    ),
                });
            }

            let region = MemoryRegion {
                base: info.BaseAddress as usize,
                size: info.RegionSize,
                state: crate::region::RegionState::from_raw(info.State.0),
                protection: crate::region::Protection::from_raw(info.Protect.0),
                kind: crate::region::RegionKind::from_raw(info.Type.0),
            };

            // A region that does not advance the walk would loop for ever. It
            // cannot happen for a region Windows reports — every one covers at
            // least a byte and the next query is made past its end — but a walk
            // that cannot end is a hung scan rather than a wrong answer, and
            // the check is one comparison.
            let next = region.end();
            if next <= address {
                return Err(MemoryError::RegionWalk {
                    pid,
                    address,
                    code: crate::error::ERROR_INVALID_PARAMETER,
                    message: format!(
                        "the region at {address:#x} covers {:#x} bytes, which does not \
                         advance the walk",
                        region.size
                    ),
                });
            }
            regions.push(region);
            address = next;
        }
    }

    fn read(&mut self, base: usize, length: usize) -> Result<Vec<u8>> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let pid = self.process.pid;
        let mut buffer = vec![0u8; length];
        let mut copied = 0usize;

        // SAFETY: the handle is open and was opened with `PROCESS_VM_READ`,
        // which is the right this call needs. `buffer` is a live local with
        // exactly `length` writable bytes, and `length` is the count passed, so
        // the call cannot write past the end. `copied` is a live local the call
        // fills with how much it actually copied. `base` names the caller's
        // region and is not dereferenced by anything here.
        let outcome = unsafe {
            ReadProcessMemory(
                self.handle(),
                base as *const core::ffi::c_void,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                length,
                Some(&mut copied),
            )
        };

        match outcome {
            Ok(()) if copied == length => Ok(buffer),
            Ok(()) => Err(MemoryError::ReadRefused {
                pid,
                address: base,
                length,
                // The code Windows itself uses for this situation, so a caller
                // switching on codes does not have to know about a private one
                // invented here.
                code: crate::error::ERROR_PARTIAL_COPY,
                message: format!(
                    "the read reported success having copied {copied} of {length} bytes"
                ),
            }),
            Err(error) => Err(MemoryError::ReadRefused {
                pid,
                address: base,
                length,
                code: crate::error::win32_code(error.code().0 as u32),
                message: error.message(),
            }),
        }
    }

    fn backing_file(&self, base: usize) -> Origin {
        crate::provenance::resolve(
            crate::provenance::mapped_file_name(self.handle(), base, &self.devices),
            base,
            &self.modules,
        )
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A process that does exactly what a test tells it to.
    //!
    //! Scripted rather than random: each region carries the outcome its read
    //! should have, so a test can put a refused read next to a successful one
    //! and check that the scanner tells them apart. That pair is the whole
    //! point of the type, and no real machine can be asked to produce it on
    //! demand.

    use super::*;

    /// One region and what reading it should do.
    #[derive(Debug)]
    pub(crate) struct ScriptedRegion {
        pub region: MemoryRegion,
        pub contents: std::result::Result<Vec<u8>, MemoryError>,
    }

    /// A source that returns a fixed script.
    #[derive(Debug)]
    pub(crate) struct FakeSource {
        pub process: ProcessRef,
        pub script: Vec<ScriptedRegion>,
        /// When set, the walk fails with this instead of returning regions.
        pub walk_failure: Option<MemoryError>,
        /// How many times the walk and the reads were called.
        pub walks: u64,
        pub reads: u64,
        /// The last limit the walk was called with.
        pub last_limit: usize,
        /// What to answer when asked which file backs an address.
        ///
        /// [`Origin::Unknown`] unless a test sets it, which is what a source
        /// that cannot answer says — and the reason the scanner's tests can
        /// check that an origin a source *did* produce reaches the finding
        /// without also checking that every other source invents one.
        pub origin: Origin,
        /// How many times the backing file was asked for, so that a test can
        /// hold the scanner to asking once per read region rather than once per
        /// address in the process.
        ///
        /// A cell because the question is asked through `&self`: asking must not
        /// change what a source is, which is the real source's contract too.
        pub origins_asked: std::cell::Cell<u64>,
        /// How long each read takes, when a test needs the clock to matter.
        ///
        /// A real read is a `ReadProcessMemory` call whose cost a test cannot
        /// influence, so a test of [`MemoryScanConfig::deadline`] has no way to
        /// make a walk take measurable time. Sleeping here is what stands in
        /// for that cost.
        ///
        /// [`MemoryScanConfig::deadline`]: crate::scan::MemoryScanConfig::deadline
        pub read_delay: Option<std::time::Duration>,
    }

    impl FakeSource {
        pub fn new(process: ProcessRef, script: Vec<ScriptedRegion>) -> Self {
            Self {
                process,
                script,
                walk_failure: None,
                walks: 0,
                reads: 0,
                last_limit: 0,
                origin: Origin::Unknown,
                origins_asked: std::cell::Cell::new(0),
                read_delay: None,
            }
        }

        /// The source answers `origin` for every address it is asked about.
        pub fn with_origin(mut self, origin: Origin) -> Self {
            self.origin = origin;
            self
        }

        /// A source for a named process with the given script.
        pub fn named(name: &str, pid: u32, script: Vec<ScriptedRegion>) -> Self {
            Self::new(
                ProcessRef::new(pid, Some(std::path::PathBuf::from(name))),
                script,
            )
        }
    }

    impl MemorySource for FakeSource {
        fn process(&self) -> &ProcessRef {
            &self.process
        }

        fn backing_file(&self, _base: usize) -> Origin {
            self.origins_asked.set(self.origins_asked.get() + 1);
            self.origin.clone()
        }

        fn regions(&mut self, limit: usize) -> Result<RegionWalk> {
            self.walks += 1;
            self.last_limit = limit;
            if let Some(failure) = &self.walk_failure {
                return Err(failure.clone());
            }
            let complete = self.script.len() <= limit;
            let regions = self
                .script
                .iter()
                .take(limit)
                .map(|entry| entry.region)
                .collect();
            Ok(RegionWalk { regions, complete })
        }

        fn read(&mut self, base: usize, length: usize) -> Result<Vec<u8>> {
            self.reads += 1;
            if let Some(delay) = self.read_delay {
                std::thread::sleep(delay);
            }
            let entry = self
                .script
                .iter()
                .find(|entry| entry.region.base == base)
                .ok_or_else(|| MemoryError::ReadRefused {
                    pid: self.process.pid,
                    address: base,
                    length,
                    code: crate::error::ERROR_PARTIAL_COPY,
                    message: "the script has no region there".into(),
                })?;
            match &entry.contents {
                Ok(bytes) => Ok(bytes[..length.min(bytes.len())].to_vec()),
                Err(error) => Err(error.clone()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::region::{Protection, RegionKind, RegionState};

    fn region(base: usize, size: usize) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            state: RegionState::Committed,
            protection: Protection::from_raw(0x20),
            kind: RegionKind::Private,
        }
    }

    #[test]
    fn a_walk_that_hits_the_limit_is_not_a_small_address_space() {
        // The distinction the report is built on. The same regions, the same
        // source, two limits, two different answers about completeness.
        let script = (0..4)
            .map(|i| fake::ScriptedRegion {
                region: region(0x1000 * (i + 1), 4096),
                contents: Ok(vec![0; 4096]),
            })
            .collect();
        let mut source = fake::FakeSource::named("fake.exe", 10, script);

        let roomy = source.regions(100).expect("the walk");
        assert_eq!(roomy.regions.len(), 4);
        assert!(roomy.complete);

        let cramped = source.regions(2).expect("the walk");
        assert_eq!(cramped.regions.len(), 2);
        assert!(
            !cramped.complete,
            "a walk stopped at the limit must not claim the address space is small"
        );
    }

    #[test]
    fn a_walk_that_fails_is_an_error_and_not_an_empty_address_space() {
        // A source that could not be walked is not a source with nothing in it.
        let mut source = fake::FakeSource::named("fake.exe", 10, Vec::new());
        source.walk_failure = Some(MemoryError::RegionWalk {
            pid: 10,
            address: 0x2000,
            code: crate::error::ERROR_ACCESS_DENIED,
            message: "Access is denied.".into(),
        });
        let failure = source.regions(100).expect_err("the walk must fail");
        assert_eq!(failure.code(), Some(crate::error::ERROR_ACCESS_DENIED));
        assert!(failure.is_process_level());
    }

    #[test]
    fn the_scripted_source_hands_back_exactly_what_was_asked_for() {
        let mut source = fake::FakeSource::named(
            "fake.exe",
            10,
            vec![fake::ScriptedRegion {
                region: region(0x1000, 4096),
                contents: Ok(vec![7u8; 4096]),
            }],
        );
        assert_eq!(source.read(0x1000, 16).expect("the read"), vec![7u8; 16]);
        assert_eq!(source.reads, 1);
        // A read of a base the script does not have is a refusal rather than a
        // buffer of zeroes, which is what makes the script honest.
        assert!(source.read(0x9000, 16).is_err());
    }
}
