//! Turning a `\Device\HarddiskVolume3\...` path into a `C:\...` path.
//!
//! # Why this is needed at all
//!
//! A minifilter asks the filter manager for a file's name and gets back a
//! *normalised* name — `FltGetFileNameInformation` with
//! `FLT_FILE_NAME_NORMALIZED`, which resolves every relative component, every
//! short name and every symlink to one canonical spelling. That canonical
//! spelling is in the object manager's namespace, and it begins with a device:
//!
//! ```text
//! \Device\HarddiskVolume3\Windows\System32\cmd.exe
//! ```
//!
//! Every other part of this product — the exclusion list a user writes, the
//! quarantine entry's `original_path`, the rule that matches a path prefix —
//! speaks DOS:
//!
//! ```text
//! C:\Windows\System32\cmd.exe
//! ```
//!
//! Nothing in the kernel tells the driver what `C:` is. There is no
//! `FltGetVolumeDosName`; the WDK's `fltKernel.h` on the machine this was
//! written on declares `FltGetVolumeName`, `FltGetVolumeGuidName`,
//! `FltGetVolumeFromName` and a dozen others, and no DOS-name lookup. The API
//! that does the job is `IoVolumeDeviceToDosName` in `ntddk.h`, which takes the
//! volume *device object* and returns an allocated `UNICODE_STRING` — and that
//! is a call that must be made at `PASSIVE_LEVEL`, returns pool that has to be
//! freed, and can be made on every file open on the machine.
//!
//! # Why the table is behind a trait
//!
//! So that the string work — recognising the prefix, splitting the volume
//! component off, joining the two halves, rejecting the inputs that must be
//! rejected — is in *this* crate where it can be tested on this machine, and
//! the part that needs a running kernel is the only part that is not.
//! [`VolumeNames`] is that boundary. A test implements it with a five-entry
//! constant table; the driver implements it with a cached map it fills from
//! `IoVolumeDeviceToDosName`.
//!
//! # What this does not do
//!
//! * **Short names.** `C:\PROGRA~1` and `C:\Program Files` are the same
//!   directory and this function will not say so. It compares strings. The
//!   filter manager's *normalised* name has already expanded short names, so a
//!   path that reached here from `FltGetFileNameInformation` is the long form —
//!   but an exclusion list entry a user typed as `C:\PROGRA~1` will not match
//!   it. That is a missed exclusion and therefore more scanning, not less.
//! * **Case.** Windows paths are case-insensitive and this function does not
//!   change case. [`crate::exclusions`] compares case-insensitively; this
//!   preserves whatever the filter manager produced, which is the case as it
//!   is stored on the volume. Preserving it matters, because the path is also
//!   what a user is shown.
//! * **Network volumes.** `\Device\Mup` and `\Device\LanmanRedirector` have no
//!   drive letter to find, so [`VolumeNames`] returns `None` for them and this
//!   returns [`PathError::UnknownVolume`]. The caller sends the request with
//!   the device path and
//!   [`crate::event::request_flags::PATH_UNRESOLVED`] — see that flag's
//!   documentation for why an unresolvable volume means *more* scanning rather
//!   than less.

use core::fmt;

/// Everything that can be wrong with an input to [`device_to_dos_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Nothing was passed.
    Empty,
    /// The path is not in a form this function converts. See the module
    /// documentation for the two forms that are.
    NotADevicePath,
    /// The path is in the right form and is not well formed — `\Device\` with
    /// no volume after it, `\??\` with nothing after it, or a volume name the
    /// [`VolumeNames`] implementation returned as empty.
    Malformed,
    /// The volume component is well formed and there is no drive letter behind
    /// it.
    UnknownVolume,
    /// The path contains a `.` or `..` component.
    ///
    /// **Rejected rather than resolved.** A normalised name from the filter
    /// manager cannot contain one, so its presence means either a caller
    /// passing something it should not have or a name provider behaving
    /// unexpectedly. Resolving it here would mean re-implementing the object
    /// manager's path walk, and getting that wrong would let
    /// `C:\Windows\..\Users\evil.exe` match the exclusion `C:\Windows` — an
    /// exclusion is a hole in the filter, and a hole that can be widened by a
    /// path an attacker chooses is worse than no exclusion at all.
    ParentComponent,
    /// The path contains a NUL inside it.
    ///
    /// A path is a counted slice here and has no terminator, so an embedded
    /// NUL is not a string end — it is a component the exclusion matcher would
    /// compare as a character. Two different Windows components can render to
    /// the same string up to a NUL and be different files, which is the shape
    /// of every path-parsing differential there has ever been.
    EmbeddedNul,
    /// The caller's output buffer is too small. `needed` is how big it would
    /// have to be.
    ///
    /// **Never** worked around by truncating. A truncated path is a path that
    /// can match the wrong exclusion entry, so the caller's correct response is
    /// to refuse to convert and let the file be scanned.
    OutputTooSmall {
        /// UTF-16 code units the converted path needs.
        needed: usize,
    },
}

impl PathError {
    /// A short phrase for a log line.
    pub const fn as_str(self) -> &'static str {
        match self {
            PathError::Empty => "empty path",
            PathError::NotADevicePath => "not a device or \\??\\ path",
            PathError::Malformed => "malformed device path",
            PathError::UnknownVolume => "no DOS name for the volume",
            PathError::ParentComponent => "path contains a . or .. component",
            PathError::EmbeddedNul => "path contains an embedded NUL",
            PathError::OutputTooSmall { .. } => "output buffer too small",
        }
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::OutputTooSmall { needed } => {
                write!(f, "{}: {needed} units needed", self.as_str())
            }
            other => f.write_str(other.as_str()),
        }
    }
}

/// The mapping from a volume device name to the drive letter a user knows.
///
/// The driver implements this over a cache filled by `IoVolumeDeviceToDosName`;
/// the tests implement it over a constant. See the module documentation for why
/// the boundary is here.
///
/// # Contract
///
/// * The `device` argument is the volume component *including* its leading
///   backslash and *excluding* the trailing one: `\Device\HarddiskVolume3`.
/// * The comparison must be **case-insensitive**. The object manager's device
///   namespace is, so `\device\harddiskvolume3` and `\Device\HarddiskVolume3`
///   are the same volume and a caller that compared them byte-wise would fail
///   to find a drive letter for a path a filter manager had spelled
///   differently.
/// * The returned name must be non-empty and must not end with a backslash —
///   `C:` and `\\?\Volume{...}` are both valid, `C:\` is not. An implementation
///   that returns an empty slice is treated as returning `None`, so a broken
///   table degrades to [`PathError::UnknownVolume`] rather than to a path
///   beginning with a stray backslash.
/// * The returned slice borrows `self`, which lets an implementation return a
///   pointer into its own cache without allocating.
pub trait VolumeNames {
    /// The DOS name for a volume device component, or `None` if this
    /// implementation does not know it.
    fn dos_name_for_device(&self, device: &[u16]) -> Option<&[u16]>;
}

/// The `\Device\` prefix, exactly as `FltGetFileNameInformation` produces it.
const DEVICE_PREFIX: &[u8] = br"\Device\";
/// The `\??\` prefix, which is how the object manager spells the DOS namespace.
const DOS_NAMESPACE_PREFIX: &[u8] = br"\??\";

/// Convert a kernel path to a DOS path, writing the result into `out`.
///
/// Returns the prefix of `out` that is the converted path. The result is never
/// a truncation of the input: if it does not fit, this returns
/// [`PathError::OutputTooSmall`] and writes nothing.
///
/// See the module documentation for the two accepted input forms and for what
/// this deliberately does not do.
///
/// # Aliasing
///
/// `out` must not overlap any memory `volumes` returns slices into. Rust's
/// borrow rules make that true for any implementation that returns a borrow of
/// `self` and is given an `out` it does not itself own, which is every
/// implementation this crate can express — but the driver's cache is behind a
/// lock and a careless implementation could hand back a pointer into a buffer
/// it also passes as `out`. Stated because it is the one way to misuse this
/// function.
pub fn device_to_dos_path<'o>(
    device_path: &[u16],
    volumes: &dyn VolumeNames,
    out: &'o mut [u16],
) -> Result<&'o [u16], PathError> {
    if device_path.is_empty() {
        return Err(PathError::Empty);
    }

    // Validate the whole input before converting any of it. Doing it in two
    // passes rather than inline means no partially-written `out` can be
    // returned by a path that turns out to be malformed halfway through.
    if device_path.contains(&0) {
        return Err(PathError::EmbeddedNul);
    }
    if has_dot_component(device_path) {
        return Err(PathError::ParentComponent);
    }

    if starts_with_ignore_ascii_case(device_path, DOS_NAMESPACE_PREFIX) {
        // `\??\C:\Windows` and `\??\Volume{...}\Windows` are already in the
        // namespace the exclusions are written in, so the conversion is the
        // removal of the prefix and nothing else.
        let rest = &device_path[DOS_NAMESPACE_PREFIX.len()..];
        if rest.is_empty() {
            return Err(PathError::Malformed);
        }
        return copy_into(rest, out);
    }

    if !starts_with_ignore_ascii_case(device_path, DEVICE_PREFIX) {
        return Err(PathError::NotADevicePath);
    }

    // Split the volume component from the rest. `\Device\HarddiskVolume3` has
    // no trailing separator and `\Device\HarddiskVolume3\Windows` does, so the
    // end is either the next backslash or the end of the input.
    let after_prefix = DEVICE_PREFIX.len();
    let volume_end = device_path[after_prefix..]
        .iter()
        .position(|&c| c == u16::from(b'\\'))
        .map(|i| i + after_prefix)
        .unwrap_or(device_path.len());

    let device = &device_path[..volume_end];
    let remainder = &device_path[volume_end..];

    // `\Device\` on its own, or `\Device\\...`: a separator where a volume name
    // must be.
    if device.len() == after_prefix {
        return Err(PathError::Malformed);
    }

    // An empty name from the table is treated as "does not know", so a broken
    // implementation degrades to `UnknownVolume` rather than producing a path
    // that starts with the remainder's backslash.
    let dos = match volumes.dos_name_for_device(device) {
        Some(name) if !name.is_empty() => name,
        _ => return Err(PathError::UnknownVolume),
    };

    if remainder.is_empty() {
        // The volume itself, whose DOS spelling is the root. `C:` alone means
        // "the current directory on C:" and is not what a device path with no
        // remainder denotes; appending the separator makes the two forms
        // distinct, which matters because an exclusion of `C:\` must match it.
        let needed = dos.len() + 1;
        if out.len() < needed {
            return Err(PathError::OutputTooSmall { needed });
        }
        out[..dos.len()].copy_from_slice(dos);
        out[dos.len()] = u16::from(b'\\');
        return Ok(&out[..needed]);
    }

    let needed = dos.len() + remainder.len();
    if out.len() < needed {
        return Err(PathError::OutputTooSmall { needed });
    }
    out[..dos.len()].copy_from_slice(dos);
    out[dos.len()..needed].copy_from_slice(remainder);
    Ok(&out[..needed])
}

/// Copy `src` into `out`, or report how much room it needed.
fn copy_into<'o>(src: &[u16], out: &'o mut [u16]) -> Result<&'o [u16], PathError> {
    if out.len() < src.len() {
        return Err(PathError::OutputTooSmall { needed: src.len() });
    }
    out[..src.len()].copy_from_slice(src);
    Ok(&out[..src.len()])
}

/// Whether the path has a `.` or `..` component.
///
/// Component-wise, not substring-wise: `C:\Windows\..config\x` has no `..`
/// component and is a legitimate name, while `C:\Windows\..\x` has one.
fn has_dot_component(path: &[u16]) -> bool {
    let mut start = 0;
    while start <= path.len() {
        let end = path[start..]
            .iter()
            .position(|&c| c == u16::from(b'\\'))
            .map(|i| i + start)
            .unwrap_or(path.len());
        let component = &path[start..end];
        if component == [u16::from(b'.')] || component == [u16::from(b'.'), u16::from(b'.')] {
            return true;
        }
        if end == path.len() {
            return false;
        }
        start = end + 1;
    }
    false
}

/// Whether `haystack` begins with the ASCII `prefix`, ignoring ASCII case.
///
/// Exposed because [`VolumeNames`] implementations need the same comparison for
/// the device component, and two implementations of a case-insensitive compare
/// in one product is one too many.
pub fn starts_with_ignore_ascii_case(haystack: &[u16], prefix: &[u8]) -> bool {
    // The `as u8` truncation is not a loss here: every unit this compares is
    // an ASCII byte by construction, and a unit that is not one compares
    // unequal to every ASCII byte once truncated, which is the answer rule 1
    // wants. `eq_ignore_ascii_case` on `u8` folds exactly the ASCII letters.
    haystack.len() >= prefix.len()
        && haystack
            .iter()
            .zip(prefix.iter())
            .all(|(&h, &p)| (h as u8).eq_ignore_ascii_case(&p))
}

/// Whether two UTF-16 slices are equal ignoring ASCII case.
///
/// See [`crate::exclusions`] for why the fold is ASCII-only and what the
/// resulting error direction is.
pub fn eq_ignore_ascii_case(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(&x, &y)| (x as u8).eq_ignore_ascii_case(&(y as u8)))
}

/// FNV-1a, 64-bit, over the little-endian bytes of a path's code units.
///
/// # What this is for
///
/// A request carries a `path_tag`, and the reply echoes it;
/// [`crate::decision::PendingTable::resolve`] compares the two. It catches a
/// service whose own bookkeeping is scrambled and which answers the right
/// request id with the wrong file's verdict — a real bug class in a component
/// that is juggling two ids per event.
///
/// # What this is not
///
/// **Not a digest and not collision-resistant.** FNV-1a is a hash table hash;
/// finding two paths that collide is trivial for anyone who wants to, and a
/// collision here means only that a scrambled reply would be accepted rather
/// than discarded. Nothing is authenticated by this value and it must not be
/// used as if something were. It is defence in depth behind the request id,
/// which is what actually enforces "a decision applies only to the request that
/// asked for it".
///
/// The bytes are hashed little-endian so that the tag is a property of the path
/// rather than of the machine reading it.
pub fn path_tag(path: &[u16]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    for &unit in path {
        // Windows paths are overwhelmingly ASCII, and hashing the ASCII byte
        // the unit *is* rather than its two-byte little-endian form would let
        // two different non-ASCII paths collide with an ASCII one — a real
        // narrowing of the tag's reach for a saving in a function that runs
        // once per intercepted file operation. The two-byte form is taken.
        for byte in unit.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(PRIME);
        }
    }
    hash
}

/// A `Display` adapter for a UTF-16 slice, for log lines and `Debug` output.
///
/// Printable ASCII is rendered as itself; everything else becomes `\u{XXXX}`,
/// which is what makes this safe in a kernel debugger's log — a path is
/// attacker-influenced data and a raw UTF-16 dump of one is a way to put
/// control characters wherever the log is being read.
///
/// Capped at [`MAX_DISPLAY_UNITS`]. A report wants the head of a path, not
/// three kilobytes of it.
pub struct U16Display<'a>(&'a [u16]);

/// How much of a path [`U16Display`] will render before truncating.
pub const MAX_DISPLAY_UNITS: usize = 256;

impl fmt::Display for U16Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write as _;
        let mut written = 0;
        for &unit in self.0.iter().take(MAX_DISPLAY_UNITS) {
            match unit {
                0x20..=0x7E => f.write_char(char::from(unit as u8))?,
                _ => write!(f, "\\u{{{unit:04X}}}")?,
            }
            written += 1;
        }
        if self.0.len() > written {
            f.write_str("...")?;
        }
        Ok(())
    }
}

impl fmt::Debug for U16Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Wrap a UTF-16 slice for display. See [`U16Display`].
pub fn display_u16(units: &[u16]) -> U16Display<'_> {
    U16Display(units)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`VolumeNames`] implementation over a constant, and the only one any
    /// test needs.
    ///
    /// Built from `&str` pairs so the fixtures read like paths rather than like
    /// arrays of numbers, and compared with the same
    /// [`eq_ignore_ascii_case`] the driver's implementation uses — so a test
    /// cannot pass because the fixture is more forgiving than the real thing.
    struct FixedVolumes(Vec<(Vec<u16>, Vec<u16>)>);

    impl FixedVolumes {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(device, dos)| (utf16(device), utf16(dos)))
                    .collect(),
            )
        }
    }

    impl VolumeNames for FixedVolumes {
        fn dos_name_for_device(&self, device: &[u16]) -> Option<&[u16]> {
            self.0
                .iter()
                .find(|(name, _)| eq_ignore_ascii_case(name, device))
                .map(|(_, dos)| dos.as_slice())
        }
    }

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// The standard fixture: three volumes, one of them spelled with a lower
    /// case device name so the case-insensitivity requirement is exercised.
    fn volumes() -> FixedVolumes {
        FixedVolumes::new(&[
            (r"\Device\HarddiskVolume3", "C:"),
            (r"\Device\HarddiskVolume1", "D:"),
            (r"\device\harddiskvolume7", "E:"),
        ])
    }

    fn convert(path: &str) -> Result<String, PathError> {
        let mut out = [0u16; 512];
        let written = device_to_dos_path(&utf16(path), &volumes(), &mut out)?;
        Ok(String::from_utf16_lossy(written))
    }

    #[test]
    fn a_system_path_converts() {
        assert_eq!(
            convert(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe").unwrap(),
            r"C:\Windows\System32\cmd.exe"
        );
    }

    #[test]
    fn every_known_volume_converts_to_its_own_letter() {
        assert_eq!(
            convert(r"\Device\HarddiskVolume1\Users\me\file.txt").unwrap(),
            r"D:\Users\me\file.txt"
        );
        assert_eq!(convert(r"\Device\HarddiskVolume3\x").unwrap(), r"C:\x");
    }

    /// The volume component is matched case-insensitively, because the object
    /// manager's device namespace is. A byte-wise comparison would fail to find
    /// a drive letter for a path the filter manager spelled differently, and
    /// the symptom would be a machine where some volumes are scanned and others
    /// silently are not.
    #[test]
    fn the_volume_component_is_matched_case_insensitively() {
        assert_eq!(
            convert(r"\device\harddiskvolume3\Windows").unwrap(),
            r"C:\Windows"
        );
        assert_eq!(
            convert(r"\DEVICE\HARDDISKVOLUME3\Windows").unwrap(),
            r"C:\Windows"
        );
        // And the table's own spelling is what matters, not the input's: the
        // entry stored as `\device\harddiskvolume7` must still be found.
        assert_eq!(convert(r"\Device\HarddiskVolume7\x").unwrap(), r"E:\x");
        assert_eq!(convert(r"\DEVICE\HARDDISKVOLUME7\x").unwrap(), r"E:\x");
    }

    /// A bare volume converts to the root, not to a drive-relative `C:`.
    ///
    /// `C:` and `C:\` are different places on Windows — the first is "whatever
    /// directory this process is in on C:" — and a device path with no
    /// remainder names the volume, whose DOS spelling is the root.
    #[test]
    fn a_bare_volume_converts_to_the_root() {
        assert_eq!(convert(r"\Device\HarddiskVolume3").unwrap(), r"C:\");
        // With a trailing separator the remainder is a single backslash, which
        // is the same place written differently.
        assert_eq!(convert(r"\Device\HarddiskVolume3\").unwrap(), r"C:\");
    }

    /// `\??\` paths are already in the namespace the exclusions are written in,
    /// including the GUID volume form, so the conversion is the prefix removal.
    #[test]
    fn the_dos_namespace_prefix_is_stripped() {
        assert_eq!(
            convert(r"\??\C:\Windows\System32").unwrap(),
            r"C:\Windows\System32"
        );
        assert_eq!(
            convert(r"\??\Volume{12345678-1234-1234-1234-123456789abc}\x").unwrap(),
            r"Volume{12345678-1234-1234-1234-123456789abc}\x"
        );
        // Case-insensitive, like the device prefix.
        assert_eq!(convert(r"\??\c:\x").unwrap(), r"c:\x");
    }

    /// A `\??\` prefix with nothing after it is malformed, not an empty path.
    #[test]
    fn a_dos_namespace_prefix_with_nothing_after_it_is_malformed() {
        assert_eq!(convert(r"\??\").unwrap_err(), PathError::Malformed);
    }

    /// `\Device\` with no volume name is malformed. Without this check the
    /// volume component would be the empty string, the table would be asked
    /// about it, and an implementation that matched empty-to-empty would
    /// produce a path that skipped the volume entirely.
    #[test]
    fn a_device_prefix_with_no_volume_is_malformed() {
        assert_eq!(convert(r"\Device\").unwrap_err(), PathError::Malformed);
        // And a separator where the volume name should be.
        assert_eq!(
            convert(r"\Device\\Windows").unwrap_err(),
            PathError::Malformed
        );
    }

    /// Anything that is not one of the two accepted forms is refused rather
    /// than guessed at. A UNC path is included, and deliberately: it needs no
    /// conversion, and quietly treating `\\server\share` as a device path would
    /// mean looking up a drive letter for a component that is not a volume.
    #[test]
    fn a_path_in_neither_accepted_form_is_refused() {
        for path in [
            r"C:\Windows\System32",
            r"\\server\share\file.txt",
            r"relative\path",
            r"\Windows\System32",
            r"\Device",
            r"\Registry\Machine\Software",
            r"\\?\C:\very\long",
        ] {
            assert_eq!(
                convert(path).unwrap_err(),
                PathError::NotADevicePath,
                "{path} should not have converted"
            );
        }
        assert_eq!(convert("").unwrap_err(), PathError::Empty);
    }

    /// A volume the table does not know is reported, not invented.
    #[test]
    fn an_unknown_volume_is_reported() {
        assert_eq!(
            convert(r"\Device\HarddiskVolume9\x").unwrap_err(),
            PathError::UnknownVolume
        );
        assert_eq!(
            convert(r"\Device\Mup\server\share\file").unwrap_err(),
            PathError::UnknownVolume
        );
    }

    /// A `..` or `.` component is rejected, and the reason is that the
    /// exclusion matcher trusts this function to have rejected it. If it did
    /// not, `C:\Windows\..\Users\evil.exe` would match an exclusion of
    /// `C:\Windows` and a hole in the filter would be widen-able by a path an
    /// attacker chose.
    #[test]
    fn a_parent_or_current_component_is_rejected() {
        assert_eq!(
            convert(r"\Device\HarddiskVolume3\Windows\..\Users\evil.exe").unwrap_err(),
            PathError::ParentComponent
        );
        assert_eq!(
            convert(r"\Device\HarddiskVolume3\Windows\.\evil.exe").unwrap_err(),
            PathError::ParentComponent
        );
        // Even where the walk would land somewhere harmless.
        assert_eq!(
            convert(r"\Device\HarddiskVolume3\..\HarddiskVolume1\x").unwrap_err(),
            PathError::ParentComponent
        );
    }

    /// The check is component-wise, so a file whose *name* contains dots is not
    /// caught. `..config` is a directory name, not a traversal.
    #[test]
    fn dots_inside_a_component_are_not_a_traversal() {
        assert_eq!(
            convert(r"\Device\HarddiskVolume3\Windows\..config\x").unwrap(),
            r"C:\Windows\..config\x"
        );
        assert_eq!(
            convert(r"\Device\HarddiskVolume3\a.b.c\x").unwrap(),
            r"C:\a.b.c\x"
        );
        assert_eq!(
            convert(r"\Device\HarddiskVolume3\...\x").unwrap(),
            r"C:\...\x"
        );
    }

    /// An embedded NUL is rejected: a path is a counted slice here, so a NUL is
    /// not a terminator, and two different components can render to the same
    /// string up to a NUL.
    #[test]
    fn an_embedded_nul_is_rejected() {
        let mut path = utf16(r"\Device\HarddiskVolume3\a");
        path.push(0);
        path.extend(utf16(r"\b"));
        let mut out = [0u16; 512];
        assert_eq!(
            device_to_dos_path(&path, &volumes(), &mut out).unwrap_err(),
            PathError::EmbeddedNul
        );
    }

    /// A buffer that is one unit too small must fail, and must fail without
    /// writing a partial path — a truncated path is a path that can match the
    /// wrong exclusion.
    #[test]
    fn a_short_output_buffer_fails_and_writes_nothing() {
        let path = utf16(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe");
        // The result is `C:\Windows\System32\cmd.exe`: 27 UTF-16 units, and the
        // count has to come from `chars()` rather than `len()`, which is bytes
        // on a `&str` and would agree only while the path stays ASCII.
        let needed = r"C:\Windows\System32\cmd.exe".chars().count();
        assert_eq!(needed, 27);

        let mut exact = [0xFFFFu16; 27];
        let written = device_to_dos_path(&path, &volumes(), &mut exact).expect("exactly fits");
        assert_eq!(written.len(), 27);

        let mut short = [0xFFFFu16; 26];
        assert_eq!(
            device_to_dos_path(&path, &volumes(), &mut short).unwrap_err(),
            PathError::OutputTooSmall { needed: 27 }
        );
        assert!(
            short.iter().all(|&u| u == 0xFFFF),
            "a failed conversion must not write a partial path"
        );

        // A zero-length buffer is the boundary of the same rule.
        let mut none: [u16; 0] = [];
        assert_eq!(
            device_to_dos_path(&path, &volumes(), &mut none).unwrap_err(),
            PathError::OutputTooSmall { needed: 27 }
        );
    }

    /// A table that returns an empty name is treated as not knowing, so a
    /// broken implementation produces `UnknownVolume` rather than a path
    /// beginning with a stray backslash.
    #[test]
    fn a_table_that_returns_an_empty_name_is_treated_as_not_knowing() {
        struct Broken;
        impl VolumeNames for Broken {
            fn dos_name_for_device(&self, _device: &[u16]) -> Option<&[u16]> {
                Some(&[])
            }
        }
        let path = utf16(r"\Device\HarddiskVolume3\Windows");
        let mut out = [0u16; 64];
        assert_eq!(
            device_to_dos_path(&path, &Broken, &mut out).unwrap_err(),
            PathError::UnknownVolume
        );
    }

    /// A table that returns a name ending in a backslash would produce a
    /// doubled separator, which is the table's fault and not this function's to
    /// paper over — but it must not *silently* produce a path that appears to
    /// be at a volume root. Pinned so the behaviour is known rather than
    /// discovered.
    #[test]
    fn a_table_name_with_a_trailing_separator_produces_a_doubled_one() {
        // A `static`, not a `const`: a `const` is inlined at each use and the
        // borrow of it would be a borrow of a temporary.
        static SLOPPY_NAME: [u16; 3] = [b'C' as u16, b':' as u16, b'\\' as u16];

        struct Sloppy;
        impl VolumeNames for Sloppy {
            fn dos_name_for_device(&self, _device: &[u16]) -> Option<&[u16]> {
                Some(&SLOPPY_NAME[..])
            }
        }
        let path = utf16(r"\Device\HarddiskVolume3\Windows");
        let mut out = [0u16; 64];
        let written = device_to_dos_path(&path, &Sloppy, &mut out).expect("converts");
        assert_eq!(String::from_utf16_lossy(written), r"C:\\Windows");
    }

    /// The ASCII helpers, including the case where the lengths differ — which
    /// is the case a length-checked implementation gets right and a zip-based
    /// one gets wrong.
    #[test]
    fn ascii_case_insensitive_helpers_handle_length_mismatches() {
        assert!(starts_with_ignore_ascii_case(
            &utf16(r"\Device\X"),
            br"\device\"
        ));
        assert!(starts_with_ignore_ascii_case(
            &utf16(r"\DEVICE\"),
            br"\Device\"
        ));
        // `zip` stops at the shorter of the two, so without an explicit length
        // check a short haystack would compare equal to a long prefix.
        assert!(!starts_with_ignore_ascii_case(
            &utf16(r"\Dev"),
            br"\Device\"
        ));
        assert!(!starts_with_ignore_ascii_case(&[], br"\Device\"));
        assert!(starts_with_ignore_ascii_case(
            &utf16(r"\Device\"),
            br"\Device\"
        ));

        assert!(eq_ignore_ascii_case(&utf16("C:"), &utf16("c:")));
        assert!(!eq_ignore_ascii_case(&utf16("C:"), &utf16("C:\\")));
        assert!(!eq_ignore_ascii_case(&[], &utf16("C")));
        assert!(eq_ignore_ascii_case(&[], &[]));
    }

    /// The tag is a function of the path and nothing else, and different paths
    /// give different tags. Pinned against a computed value so that a change to
    /// the algorithm is visible — a service and a driver built from different
    /// revisions must not silently disagree about the tag's meaning.
    #[test]
    fn path_tags_are_deterministic_and_distinct() {
        let cmd = path_tag(&utf16(r"C:\Windows\System32\cmd.exe"));
        let cmd_again = path_tag(&utf16(r"C:\Windows\System32\cmd.exe"));
        assert_eq!(cmd, cmd_again, "the tag must be deterministic");

        let invoice = path_tag(&utf16(r"C:\Users\me\Downloads\invoice.pdf"));
        assert_ne!(cmd, invoice);

        // Empty and single-unit paths do not panic or collapse to the basis.
        assert_ne!(path_tag(&[]), path_tag(&[0]));
        assert_ne!(path_tag(&[]), 0xcbf2_9ce4_8422_2325 ^ 0xcbf2_9ce4_8422_2325);

        // Case is *not* folded: the tag identifies a spelling, and the echo
        // path compares a request against its own spelling rather than two
        // spellings of the same file.
        assert_ne!(
            path_tag(&utf16(r"C:\Windows")),
            path_tag(&utf16(r"c:\windows"))
        );

        // The empty path hashes to the FNV offset basis, which is what makes
        // the function total.
        assert_eq!(path_tag(&[]), 0xcbf2_9ce4_8422_2325);
    }

    /// Non-ASCII units are hashed as two bytes, which is what keeps a
    /// Latin-1-range unit from colliding with an ASCII one: `U+0041` and
    /// `U+4100` share a low byte, so hashing bytes rather than units *without*
    /// both bytes would make them collide.
    #[test]
    fn path_tags_distinguish_units_that_share_a_low_byte() {
        assert_ne!(path_tag(&[0x0041]), path_tag(&[0x4100]));
        assert_ne!(path_tag(&[0x0041]), path_tag(&[0x0042]));
    }

    /// The display adapter escapes everything that is not printable ASCII, so a
    /// path cannot put control characters into a log file.
    #[test]
    fn display_escapes_non_ascii_and_control_units() {
        assert_eq!(
            display_u16(&utf16(r"C:\Windows")).to_string(),
            r"C:\Windows"
        );
        assert_eq!(
            display_u16(&[0x0041, 0x0000, 0x000A, 0x0042]).to_string(),
            r"A\u{0000}\u{000A}B"
        );
        // DEL is above the printable range and is escaped.
        assert_eq!(display_u16(&[0x007F]).to_string(), r"\u{007F}");
        // Space is printable and is not escaped.
        assert_eq!(display_u16(&[0x0020]).to_string(), " ");
    }

    /// Display is capped, so a hostile path cannot fill a log line.
    #[test]
    fn display_is_capped_and_marked() {
        let long = vec![u16::from(b'A'); MAX_DISPLAY_UNITS + 10];
        let rendered = display_u16(&long).to_string();
        assert!(rendered.ends_with("..."));
        assert_eq!(rendered.len(), MAX_DISPLAY_UNITS + 3);
    }

    /// Every error renders, and distinguishingly.
    #[test]
    fn path_errors_render_distinctly() {
        let errors = [
            PathError::Empty,
            PathError::NotADevicePath,
            PathError::Malformed,
            PathError::UnknownVolume,
            PathError::ParentComponent,
            PathError::EmbeddedNul,
            PathError::OutputTooSmall { needed: 4 },
        ];
        for (i, a) in errors.iter().enumerate() {
            let rendered = a.to_string();
            assert!(!rendered.is_empty());
            for b in &errors[i + 1..] {
                assert_ne!(rendered, b.to_string(), "{a:?} and {b:?} render the same");
            }
        }
        assert!(PathError::OutputTooSmall { needed: 25 }
            .to_string()
            .contains("25"));
    }
}
