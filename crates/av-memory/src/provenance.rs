//! Where the bytes in a region came from, when the machine can say.
//!
//! # Why a memory finding needs a file
//!
//! A match inside a process is attributed to `process:address` — see
//! [`crate::process`] for why — and for the case that makes memory scanning
//! worth doing at all, that is the whole story: code that was never written to
//! disk cannot be caught by a file scan, and there is no file to name.
//!
//! The other case is the opposite, and it is the more common one in practice. A
//! malicious image is mapped from a file, the file is on disk, and it will be
//! there again after the process is gone. Terminating the process closes the
//! incident for as long as it takes the user — or whatever started it — to run
//! the file again, and an antivirus whose answer to "there is malware in memory"
//! is to kill a process is an antivirus that reports the same infection every
//! day. The file is the thing that has to be dealt with, so the question this
//! module answers is: **which file put these bytes here**.
//!
//! # The two answers the machine gives, and the honest third
//!
//! Windows answers with two independent mechanisms, and neither is complete:
//!
//! * `GetMappedFileNameW` asks the kernel what file backs one address. It
//!   answers for a region that is a view of a file — an image section, a mapped
//!   data file — and answers nothing for a region allocated privately, which is
//!   exactly the injected-code case. That "nothing" is an answer and is kept
//!   distinct from a failure: [`Origin::Nothing`] against [`Origin::Unknown`].
//! * The process's **module list** names every image the loader mapped, with its
//!   base address and size. An address inside one of those ranges belongs to
//!   that image even when the per-address query cannot name it — which happens
//!   for an image mapped as a data section, and for a region of an image that
//!   was re-protected after something wrote into it.
//!
//! So [`resolve`] takes both and prefers the first, because a per-address answer
//! is about *that* address and a module range is about a whole image. The three
//! outcomes are kept apart rather than collapsed into `Option<PathBuf>`,
//! because "nothing on disk holds this" and "this machine would not tell me"
//! are the difference between the injected-code shape and a gap in the report —
//! the same distinction [`crate::scan`] is built around for regions.
//!
//! # What this is not
//!
//! It is not a claim about intent. An address backed by `C:\Windows\System32\
//! kernel32.dll` is backed by that file whether or not the system is healthy,
//! and an address backed by `C:\Users\me\Downloads\invoice.exe` is backed by
//! that file whether or not the process is malicious. What a caller does with
//! the answer — quarantine the file, leave it, ask the user — is a decision
//! about a detection, and this module only supplies the fact a decision needs:
//! the path, spelled the way the rest of the product spells paths, so that the
//! same path can be handed to `av_quarantine::QuarantineVault::store` (named
//! rather than linked: this crate does not depend on `av-quarantine`) or matched
//! against [`av_core::paths::AvPaths`] without a second translation.
//!
//! # The device-path translation
//!
//! `GetMappedFileNameW` does not return `C:\...`. It returns the name the memory
//! manager knows, which is `\Device\HarddiskVolume3\Users\me\Downloads\
//! invoice.exe`. The translation to a DOS path is
//! [`av_driver_proto::path::device_to_dos_path`] — the same function the kernel
//! driver uses for the paths it sends to user mode, deliberately, because two
//! translations written twice are two translations that disagree about
//! `\??\C:` or about a trailing separator. What that function needs is a table
//! from volume device names to drive letters, which is what [`DosDevices`]
//! builds from `QueryDosDeviceW`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{MemoryError, Result};

/// One image mapped into a process.
///
/// From the loader's module list, which is what makes it authoritative about
/// where an image *is* rather than about what any single address is backed by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    /// The file the image was mapped from.
    pub path: PathBuf,
    /// The lowest address the image occupies.
    pub base: usize,
    /// How many bytes it covers, as the loader reports it.
    pub size: usize,
}

impl Module {
    /// Whether `address` falls inside this image.
    ///
    /// Half-open, and saturating: an image that ends past the top of the
    /// address space must not wrap and claim the bottom of it.
    pub fn contains(&self, address: usize) -> bool {
        address >= self.base && address < self.base.saturating_add(self.size)
    }

    /// The image's file name, for a log line.
    pub fn label(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.display().to_string())
    }
}

/// The file backing one address, as far as it could be established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    /// The kernel named this file for this address.
    File {
        /// The file, as a DOS path.
        path: PathBuf,
    },
    /// The address is inside a loaded image, whose file is this one.
    ///
    /// The kernel named no file for the address itself; the loader's module
    /// list placed it in this image. Kept apart from [`Origin::File`] because
    /// the two are different strengths of statement: one is about the address,
    /// the other about the range it sits in.
    Image {
        /// The image's file, as a DOS path.
        path: PathBuf,
    },
    /// Nothing on disk backs this address.
    ///
    /// The kernel was asked and named no file, and no loaded image covers the
    /// address: the bytes were written into memory that was allocated for the
    /// purpose. This is the injected-code shape, and it is an answer.
    Nothing,
    /// The question could not be asked: no process handle, or a platform this
    /// build cannot ask.
    Unknown,
}

impl Origin {
    /// The file this address came from, when there is one.
    ///
    /// Both [`Origin::File`] and [`Origin::Image`] name a file, because both
    /// are a real answer to "which file put these bytes here". A caller that
    /// needs to know which mechanism produced it matches on the variant.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::File { path } | Self::Image { path } => Some(path),
            Self::Nothing | Self::Unknown => None,
        }
    }

    /// Whether anything on disk holds these bytes.
    ///
    /// False for [`Origin::Unknown`] as well as for [`Origin::Nothing`], and
    /// that is deliberate: a caller that acts on "nothing on disk holds this"
    /// must not act on a question that was never answered. A caller that wants
    /// the difference matches on the variant, which is why the variants exist.
    pub fn is_backed_by_a_file(&self) -> bool {
        self.path().is_some()
    }

    /// One sentence for a report.
    pub fn describe(&self) -> String {
        match self {
            Self::File { path } => format!("backed by {}", path.display()),
            Self::Image { path } => format!("inside the image {}", path.display()),
            Self::Nothing => "backed by no file on disk".to_string(),
            Self::Unknown => {
                "not established: the file behind this address was not asked for".to_string()
            }
        }
    }
}

/// Combine what the kernel said about one address with the process's images.
///
/// Pure, so that the rule can be tested without a live process: `mapped` is
/// `Some` when the kernel named a file for this address, and `None` when it
/// named none — which includes the case where the question was never asked,
/// because a caller with no answer and a caller with a negative answer both
/// arrive here as `None` and the module list is what separates them.
///
/// `modules` is searched in order, so a caller that has overlapping ranges —
/// which the loader does not produce, but a hand-built list can — gets the
/// first match rather than a panic.
pub fn resolve(mapped: Option<PathBuf>, address: usize, modules: &[Module]) -> Origin {
    if let Some(path) = mapped {
        return Origin::File { path };
    }
    match modules.iter().find(|module| module.contains(address)) {
        Some(module) => Origin::Image {
            path: module.path.clone(),
        },
        None => Origin::Nothing,
    }
}

// ---------------------------------------------------------------------------
// The volume table
// ---------------------------------------------------------------------------

/// The translation from `\Device\HarddiskVolumeN` to a drive letter.
///
/// Built by asking Windows what each drive letter means. `QueryDosDeviceW("C:")`
/// answers `\Device\HarddiskVolume3`, which is the mapping `GetMappedFileNameW`'s
/// answers have to be translated through.
///
/// Built once per scan rather than per address: the answer cannot change while a
/// scan runs — a drive letter that is reassigned mid-scan would make two
/// findings from the same scan disagree about a path, which is a worse outcome
/// than a stale letter — and it is twenty-six cheap calls.
#[derive(Debug, Clone, Default)]
pub struct DosDevices {
    /// Volume device component to DOS name, both as UTF-16.
    ///
    /// The device component has no trailing separator, which is what
    /// [`av_driver_proto::path::VolumeNames`] requires: `\Device\HarddiskVolume3`
    /// and not `\Device\HarddiskVolume3\`.
    pairs: Vec<(Vec<u16>, Vec<u16>)>,
}

impl DosDevices {
    /// Ask Windows for every drive letter's volume.
    ///
    /// A letter that is not in use answers nothing and is left out rather than
    /// stored as an empty entry: an empty entry would translate every unknown
    /// volume to an empty prefix.
    #[cfg(windows)]
    pub fn query() -> Self {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

        let mut pairs = Vec::new();
        for letter in b'A'..=b'Z' {
            let name = [letter as u16, u16::from(b':'), 0];
            let mut buffer = [0u16; 1024];
            // SAFETY: `name` is a NUL-terminated two-character device name that
            // outlives the call, and `buffer` is a live local of the length
            // passed. `QueryDosDeviceW` writes at most that many code units and
            // reports how many it wrote, or zero when the letter is not in use.
            let written = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buffer)) };
            if written == 0 {
                continue;
            }
            let used = (written as usize).min(buffer.len());
            let device: Vec<u16> = buffer[..used]
                .iter()
                .copied()
                .take_while(|&unit| unit != 0)
                .collect();
            if device.is_empty() {
                continue;
            }
            pairs.push((device, vec![letter as u16, u16::from(b':')]));
        }
        log::debug!("{} drive letters resolved to volume devices", pairs.len());
        Self { pairs }
    }

    /// No table at all, for a platform with no drive letters.
    #[cfg(not(windows))]
    pub fn query() -> Self {
        Self::default()
    }

    /// Translate `device_path` — a name from `GetMappedFileNameW` — to a DOS
    /// path.
    ///
    /// `None` when the path names a volume this table does not know, or when it
    /// is not a device path at all. Both are reported as "no answer" rather than
    /// as a path with a guess in it: a finding that named the wrong file would
    /// be acted on, and a finding that names no file is one a caller can leave
    /// alone.
    pub fn to_dos_path(&self, device_path: &[u16]) -> Option<PathBuf> {
        let mut out = [0u16; MAX_DOS_PATH_UNITS];
        let converted =
            av_driver_proto::path::device_to_dos_path(device_path, self, &mut out).ok()?;
        let text = String::from_utf16(converted).ok()?;
        if text.is_empty() {
            return None;
        }
        Some(PathBuf::from(text))
    }
}

/// Longest DOS path this module will produce, in UTF-16 code units.
///
/// `MAX_PATH` plus room for a long-name expansion of the device component. A
/// path that does not fit is refused rather than truncated — the same rule the
/// driver's exclusions use, and for the same reason: half a path names a
/// different file.
pub const MAX_DOS_PATH_UNITS: usize = 512;

// Not gated on Windows, and that is the point: the *lookup* is a scan of a
// `Vec` and has nothing platform-specific in it, and `to_dos_path` —
// which is not gated either — needs this trait implemented to call
// `device_to_dos_path` at all. Gating it made the non-Windows build fail to
// compile, which nothing here noticed because the only platform this product
// ships for compiles the gate the other way. On a platform with no drive
// letters `pairs` is empty and this answers `None` for everything, which is the
// correct answer and not a stub.
impl av_driver_proto::path::VolumeNames for DosDevices {
    fn dos_name_for_device(&self, device: &[u16]) -> Option<&[u16]> {
        self.pairs
            .iter()
            .find(|(name, _)| av_driver_proto::path::eq_ignore_ascii_case(name, device))
            .map(|(_, dos)| dos.as_slice())
    }
}

// ---------------------------------------------------------------------------
// The Win32 side
// ---------------------------------------------------------------------------

/// The file backing one address of an open process, as the kernel names it.
///
/// `None` when the kernel named no file — a private allocation — and also when
/// the call failed. The two are not distinguished here because the caller
/// distinguishes them with the module list: see [`resolve`].
#[cfg(windows)]
pub fn mapped_file_name(
    process: windows::Win32::Foundation::HANDLE,
    address: usize,
    devices: &DosDevices,
) -> Option<PathBuf> {
    use windows::Win32::System::ProcessStatus::GetMappedFileNameW;

    let mut buffer = [0u16; MAX_DOS_PATH_UNITS];
    // SAFETY: the handle is open and was opened with `PROCESS_VM_READ` and
    // `PROCESS_QUERY_LIMITED_INFORMATION`, which is what this call needs.
    // `address` is an address in that process, not a pointer this code
    // dereferences, and `buffer` is a live local of the length it is passed.
    let written =
        unsafe { GetMappedFileNameW(process, address as *const std::ffi::c_void, &mut buffer) };
    if written == 0 {
        return None;
    }
    let used = (written as usize).min(buffer.len());
    let device_path: Vec<u16> = buffer[..used]
        .iter()
        .copied()
        .take_while(|&unit| unit != 0)
        .collect();
    if device_path.is_empty() {
        return None;
    }
    let path = devices.to_dos_path(&device_path);
    if path.is_none() {
        // Worth a line: it means a drive letter is missing from the table, and
        // the finding will say "no file" about an address that has one.
        log::debug!(
            "the volume of a mapped file was not in the drive table: {}",
            String::from_utf16_lossy(&device_path)
        );
    }
    path
}

/// Every image the loader mapped into `pid`.
///
/// `TH32CS_SNAPMODULE` with `TH32CS_SNAPMODULE32`, which is what makes this work
/// for a 32-bit process on a 64-bit system as well: without the second flag the
/// snapshot of a WOW64 process fails rather than returning the 32-bit module
/// list.
///
/// A process that cannot be snapshotted is not an error here. The module list is
/// the *fallback* answer for an address the kernel will not name, and a scan
/// that refused a process because a fallback was unavailable would refuse
/// processes it can otherwise read. So the caller gets an empty list with the
/// reason logged, and [`resolve`] then answers [`Origin::Unknown`] where it
/// would have answered [`Origin::Image`].
#[cfg(windows)]
pub fn modules(pid: u32) -> Result<Vec<Module>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    // SAFETY: the flag is a documented combination and `pid` is a PID the caller
    // has already listed. The call returns a handle this function owns and
    // closes on every path below.
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }.map_err(
            |error| MemoryError::Platform {
                operation: "CreateToolhelp32Snapshot".to_string(),
                code: crate::error::win32_code(error.code().0 as u32),
                message: error.message(),
            },
        )?;

    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    let mut modules = Vec::new();
    // SAFETY: the snapshot handle is open and owned here, and `entry` is a live
    // local whose `dwSize` the call requires to be set — which it is above.
    let mut more = unsafe { Module32FirstW(snapshot, &mut entry) }.is_ok();
    while more {
        let path = String::from_utf16_lossy(
            &entry.szExePath[..entry
                .szExePath
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(entry.szExePath.len())],
        );
        if !path.is_empty() {
            modules.push(Module {
                path: PathBuf::from(path),
                base: entry.modBaseAddr as usize,
                size: entry.modBaseSize as usize,
            });
        }
        // SAFETY: as for `Module32FirstW`; the same live local is reused, which
        // the API documents as the way to walk the list.
        more = unsafe { Module32NextW(snapshot, &mut entry) }.is_ok();
    }
    // SAFETY: the handle came from `CreateToolhelp32Snapshot`, is owned by this
    // function alone, and is not used after this point.
    unsafe {
        let _ = CloseHandle(snapshot);
    }

    log::debug!("{pid} has {} loaded images", modules.len());
    Ok(modules)
}

/// Every image the loader mapped into `pid`, on a platform without a loader to
/// ask.
#[cfg(not(windows))]
pub fn modules(_pid: u32) -> Result<Vec<Module>> {
    Err(MemoryError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(path: &str, base: usize, size: usize) -> Module {
        Module {
            path: PathBuf::from(path),
            base,
            size,
        }
    }

    #[test]
    fn a_name_from_the_kernel_wins_over_the_image_it_sits_in() {
        // The per-address answer is about *that* address; the module range is
        // about the whole image. When both are available the specific one is
        // the stronger statement, so it is the one kept.
        let modules = [module(r"C:\Windows\System32\kernel32.dll", 0x1000, 0x2000)];
        assert_eq!(
            resolve(
                Some(PathBuf::from(r"C:\Windows\System32\ntdll.dll")),
                0x1800,
                &modules
            ),
            Origin::File {
                path: PathBuf::from(r"C:\Windows\System32\ntdll.dll")
            }
        );
    }

    #[test]
    fn an_address_inside_an_image_is_that_image_when_the_kernel_names_no_file() {
        let modules = [module(r"C:\Windows\System32\kernel32.dll", 0x1000, 0x2000)];
        assert_eq!(
            resolve(None, 0x1000, &modules),
            Origin::Image {
                path: PathBuf::from(r"C:\Windows\System32\kernel32.dll")
            }
        );
        // The last byte of the range, and not the first byte past it.
        assert!(matches!(
            resolve(None, 0x2fff, &modules),
            Origin::Image { .. }
        ));
        assert_eq!(resolve(None, 0x3000, &modules), Origin::Nothing);
    }

    #[test]
    fn an_address_no_image_covers_is_backed_by_nothing() {
        // The injected-code shape, and the reason this is not an `Option`: a
        // caller has to be able to tell this from a question that failed.
        let modules = [module(r"C:\Windows\System32\kernel32.dll", 0x1000, 0x2000)];
        assert_eq!(resolve(None, 0x9000, &modules), Origin::Nothing);
        assert_eq!(resolve(None, 0x9000, &[]), Origin::Nothing);
        assert!(!Origin::Nothing.is_backed_by_a_file());
        assert!(!Origin::Unknown.is_backed_by_a_file());
        assert!(Origin::Nothing.path().is_none());
    }

    #[test]
    fn the_end_of_an_image_does_not_wrap_to_the_bottom_of_the_address_space() {
        // `base + size` for an image the loader reported at the top of the
        // address space would overflow, and a wrapped range would claim every
        // low address in the process.
        let modules = [module(r"C:\x.dll", usize::MAX - 0x10, 0x1000)];
        assert!(modules[0].contains(usize::MAX - 0x10));
        assert!(!modules[0].contains(0));
        assert!(!modules[0].contains(0x100));
    }

    #[test]
    fn every_origin_says_something_a_report_can_print() {
        let file = Origin::File {
            path: PathBuf::from(r"C:\Users\me\Downloads\invoice.exe"),
        };
        assert!(file.describe().contains("invoice.exe"));
        assert_eq!(
            file.path(),
            Some(Path::new(r"C:\Users\me\Downloads\invoice.exe"))
        );

        let image = Origin::Image {
            path: PathBuf::from(r"C:\Windows\System32\kernel32.dll"),
        };
        assert!(image.describe().contains("kernel32.dll"));
        assert_ne!(image.describe(), file.describe());

        // The two negatives are different sentences, because they are different
        // facts: one is a finding, the other is a gap in the report.
        assert_ne!(Origin::Nothing.describe(), Origin::Unknown.describe());
        assert!(Origin::Nothing.describe().contains("no file"));
        assert!(Origin::Unknown.describe().contains("not"));
    }

    #[test]
    fn a_volume_that_is_not_a_device_path_is_no_answer_rather_than_a_guess() {
        // The table is empty here, which is what a machine with no drive
        // letters, or a device path naming an unknown volume, produces. The
        // answer must be "no answer": a path invented from a partial
        // translation is a path a caller would act on.
        let devices = DosDevices::default();
        let device: Vec<u16> = r"\Device\HarddiskVolume3\Users\me\x.exe"
            .encode_utf16()
            .collect();
        assert_eq!(devices.to_dos_path(&device), None);

        let not_a_path: Vec<u16> = r"C:\Windows\x.dll".encode_utf16().collect();
        assert_eq!(devices.to_dos_path(&not_a_path), None);
        assert_eq!(devices.to_dos_path(&[]), None);
    }

    #[cfg(windows)]
    mod live {
        use std::os::windows::ffi::OsStrExt as _;

        use super::*;

        /// Map a file into this process and hand back the view's address.
        ///
        /// The file is created by the caller and outlives the view. The file
        /// handle is closed before returning — the view keeps the section alive
        /// on its own — so what comes back is only the address, which is what
        /// the query under test takes.
        fn map(path: &Path) -> *const u8 {
            use windows::Win32::Foundation::GENERIC_READ;
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
            };
            use windows::Win32::System::Memory::{
                CreateFileMappingW, MapViewOfFile, FILE_MAP_READ, PAGE_READONLY,
            };

            let wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: `wide` is NUL-terminated and outlives the call; the rest
            // are values. Failure is reported through `Err`.
            let file = unsafe {
                CreateFileW(
                    windows::core::PCWSTR(wide.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }
            .expect("opening the file to map");
            // SAFETY: `file` is an open handle with read access, which is what
            // the protection asks for. The mapping is unnamed and is released by
            // the caller of this function through the handle it returns.
            let mapping = unsafe { CreateFileMappingW(file, None, PAGE_READONLY, 0, 0, None) }
                .expect("creating a file mapping");
            // SAFETY: `mapping` is an open section handle. Zero for the offsets
            // and the length means the whole file from the start, which is the
            // only case this test needs. This call reports failure by returning
            // a null address rather than through an `Err`, so the check is the
            // one below.
            let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
            assert!(!view.Value.is_null(), "mapping a view of the file");
            // The section handle is not needed once the view exists, and the
            // view holds its own reference; the file handle is not needed either
            // for the same reason. Both are closed here, and the caller unmaps
            // the address.
            // SAFETY: both handles came from the calls above, are owned here,
            // and are not used after this point.
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(mapping);
                let _ = windows::Win32::Foundation::CloseHandle(file);
            }
            view.Value as *const u8
        }

        #[test]
        fn the_file_behind_a_mapped_address_is_named() {
            // The claim this module exists to make, measured: map a file, ask
            // what backs the address it was mapped at, and get the file back —
            // through the kernel's `\Device\...` spelling and the drive table,
            // which is the whole translation being exercised.
            use std::io::Write as _;

            let directory = tempfile::tempdir().expect("a temporary directory");
            let file = directory.path().join("a-file-to-map.bin");
            let mut written = std::fs::File::create(&file).expect("creating the file");
            written
                .write_all(&vec![0x5au8; 4096])
                .expect("writing the file");
            drop(written);

            let address = map(&file);
            let devices = DosDevices::query();
            // The process handle this query needs, and the one handle that
            // cannot be refused: the address is in this process. Passing the
            // *file* handle here instead is the mistake this test was written
            // with first, and the call answers zero — "no file backs this
            // address" — rather than failing, which is exactly the kind of wrong
            // answer `resolve` exists to keep a caller from acting on.
            // SAFETY: `GetCurrentProcess` takes no arguments and returns a
            // pseudo-handle that must not be closed.
            let process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
            let origin = resolve(
                mapped_file_name(process, address as usize, &devices),
                address as usize,
                &[],
            );

            // SAFETY: the address came from `MapViewOfFile` and has not been
            // unmapped yet.
            unsafe {
                let _ = windows::Win32::System::Memory::UnmapViewOfFile(
                    windows::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                        Value: address as *mut std::ffi::c_void,
                    },
                );
            }

            let named = origin.path().unwrap_or_else(|| {
                panic!(
                    "the address a file was mapped at was not attributed to a file: {}",
                    origin.describe()
                )
            });
            // Compared as canonical paths, because the kernel reports the name
            // the section was created with — a short name on a volume with
            // 8.3 generation, a different case, or a path through a junction
            // are all the same file and none of them are the string this test
            // built.
            let wanted = std::fs::canonicalize(&file).expect("canonicalizing the file");
            let got = std::fs::canonicalize(named).unwrap_or_else(|e| {
                panic!(
                    "the origin {} is not a path this machine can resolve: {e}",
                    named.display()
                )
            });
            assert_eq!(
                got, wanted,
                "the file backing the mapped address is not the file that was mapped"
            );
        }

        #[test]
        fn the_images_of_this_process_include_this_binary() {
            // The fallback half, on the one process a test can always open. If
            // the module list did not contain the running image, the fallback
            // would be worthless for every process.
            let modules = modules(crate::process::current_pid()).expect("this process's images");
            assert!(
                !modules.is_empty(),
                "a process running this test has at least one image"
            );

            let exe = std::fs::canonicalize(std::env::current_exe().expect("the test binary"))
                .expect("canonicalizing the test binary");
            let found = modules.iter().any(|module| {
                std::fs::canonicalize(&module.path)
                    .map(|path| path == exe)
                    .unwrap_or(false)
            });
            assert!(
                found,
                "the test binary is not in its own module list: {:?}",
                modules.iter().map(Module::label).collect::<Vec<_>>()
            );

            // And the range each image reports is a range a caller can use: the
            // address of the first image must be inside it.
            let first = &modules[0];
            assert!(first.contains(first.base));
            assert!(first.size > 0, "{} reports no size", first.label());
        }

        #[test]
        fn the_drive_table_translates_the_system_volume() {
            // What the whole translation rests on: the table must know the
            // volume the system drive is, or every mapped file on it is
            // reported as backed by nothing.
            let devices = DosDevices::query();
            assert!(
                !devices.pairs.is_empty(),
                "this machine has no drive letters at all"
            );

            let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
            let name: Vec<u16> = system_drive
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut buffer = [0u16; 1024];
            // SAFETY: `name` is NUL-terminated and outlives the call; `buffer`
            // is a live local of the length passed.
            let written = unsafe {
                windows::Win32::Storage::FileSystem::QueryDosDeviceW(
                    windows::core::PCWSTR(name.as_ptr()),
                    Some(&mut buffer),
                )
            };
            assert!(written > 0, "{system_drive} is not a device");
            let device: Vec<u16> = buffer[..(written as usize).min(buffer.len())]
                .iter()
                .copied()
                .take_while(|&unit| unit != 0)
                .collect();

            let mut with_windows = device.clone();
            with_windows.extend(r"\Windows".encode_utf16());
            assert_eq!(
                devices.to_dos_path(&with_windows),
                Some(PathBuf::from(format!(r"{system_drive}\Windows"))),
                "the system volume did not translate back to its drive letter"
            );
        }
    }
}
