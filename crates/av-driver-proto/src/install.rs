//! What the driver is called once it is installed on a machine, spelled once.
//!
//! # Why this is here and not in the installer
//!
//! [`crate::port`] exists because a name the driver and user mode both need will
//! otherwise be written twice, and two spellings of one name do not fail — they
//! *miss*. The facts below are the same kind of thing with one more party: the
//! driver does not read them at all, but the installer that puts it on a machine
//! and the checks that later ask whether it is still there both do, and they
//! live in crates that cannot see each other.
//!
//! The specific failure this prevents is quieter than a wrong port name. The
//! altitude lives in the registry under a key named after the service, and the
//! service's key names the file; an installer that wrote `WenleAvFilter` and a
//! verifier that looked for `WenleAVFilter` would have the verifier report a
//! driver that is loaded and filtering every file operation on the machine as
//! *not installed*. Nothing would be broken and the report would be wrong — the
//! worst combination, because it invites somebody to "fix" a working system.
//!
//! # What is not here
//!
//! The port name is in [`crate::port`], because the driver reads it. Nothing in
//! this module is read by the driver, so nothing here is part of the protocol
//! between them, and the driver crate does not link it. It is compiled into the
//! kernel build all the same — this crate is one crate — and that is harmless:
//! these are `&'static str`s, which is to say bytes in `.rdata` that nothing
//! references and the linker drops.

/// The name of the driver's service, as the SCM and `fltmc` know it.
///
/// One word, because it is typed at a command prompt and appears in `sc query`
/// output beside `WenleAvService`; a space in it would need quoting in every
/// place it is used and would be the first thing to be got wrong by hand.
///
/// It is not the port name, and the two are deliberately not derived from each
/// other. The port is in the filter manager's flat namespace and the service is
/// in the SCM's; they are different namespaces with different rules, and a
/// rename of one is not a rename of the other.
pub const SERVICE_NAME: &str = "WenleAvFilter";

/// What the service is called in a list a person reads.
pub const DISPLAY_NAME: &str = "Wenle AV Filter Driver";

/// The driver's file name under `%SystemRoot%\System32\drivers`.
///
/// Matches [`SERVICE_NAME`] rather than the `av_driver.dll` cargo writes, and
/// [`crate::install::DEVICE_SUBDIR`] is where it goes. A reader who has the
/// service name has the file name, which is the property worth having when the
/// question is "which of these forty `.sys` files is the one that is filtering
/// my disk".
///
/// # Why the extension is load-bearing
///
/// The linker is told `/SUBSYSTEM:NATIVE /ENTRY:FxDriverEntry`, and neither of
/// those makes the output a driver as far as the loader is concerned — the file
/// name does. The SCM installs a kernel service whose `ImagePath` must name a
/// `.sys`, which is why packaging renames cargo's `cdylib` output instead of
/// shipping it as a `.dll`. See [`crate::install::assert_loadable_file_name`].
pub const FILE_NAME: &str = "WenleAvFilter.sys";

/// The file cargo writes, before packaging renames it to [`FILE_NAME`].
///
/// # Why the installer has to know both names
///
/// The build produces `av_driver.dll` — that name is not a mistake and cannot be
/// changed, because [`FILE_NAME`]'s note explains that the linker's
/// `/SUBSYSTEM:NATIVE` only reaches the output through a `cdylib` target, and
/// cargo names a `cdylib` after its package. Packaging renames it to
/// `WenleAvFilter.sys`, which is the name the loader reads.
///
/// So there are two files a caller might be looking at: the installed one, which
/// is the only one that is ever on a machine the product has been installed on,
/// and the build output, which is what sits beside `wenle.exe` in a build tree
/// before anything has been packaged. An installer that knew only [`FILE_NAME`]
/// would refuse to install from a build tree — the one place a developer tries
/// it first — and the message would be "there is no WenleAvFilter.sys beside this
/// executable", which is true and reads as "the build is broken".
///
/// It is here and not in the installer for the reason this module exists: it is
/// the driver's name, and a second spelling of a driver's name is what this
/// module was created to prevent. The `av_driver` half is cargo's rule — a
/// package's `cdylib` is named after the package with `-` becoming `_` — and it
/// is written out rather than derived because `av-driver` and `av_driver` are
/// exactly the pair a derivation would be introduced to keep in step, and a
/// `-`/`_` substitution is not something to reimplement.
pub const BUILD_OUTPUT_NAME: &str = "av_driver.dll";

/// The subdirectory of `%SystemRoot%` the driver is installed into.
///
/// Relative rather than absolute, because the absolute path depends on where
/// Windows is installed and this crate cannot ask. The installer joins it to
/// `%SystemRoot%`; the checks do the same.
pub const DEVICE_SUBDIR: &str = r"System32\drivers";

/// The minifilter altitude, as a decimal string.
///
/// # This value is not allocated, and that is the one thing to know about it
///
/// Microsoft assigns minifilter altitudes, one per vendor per load order group.
/// The assigned integer is what guarantees two filters in the same group never
/// claim the same position, and a collision is not a slow path — the filter
/// manager refuses the load. This value is a *default for a machine that has no
/// other Wenle filter on it*, chosen inside the documented range for
/// [`LOAD_ORDER_GROUP`] and deliberately low in it, where the published
/// assignments are sparse; almost every vendor in that table sits above 327000.
///
/// A shipping product must request an integer from Microsoft and replace this
/// constant with it. Until that happens, a machine that also runs another
/// antivirus whose filter happens to sit at this exact number will report the
/// driver as failing to load, and this paragraph is the explanation.
///
/// It is a string and not an integer because that is what the registry holds:
/// the filter manager reads `Altitude` as `REG_SZ` and parses it as an
/// infinite-precision decimal, so a value with a fractional part is legal. Ours
/// has none — the fraction form is for vendors appending to an integer they
/// already hold, which is not this.
pub const ALTITUDE: &str = "321000";

/// The load order group the altitude is allocated within.
///
/// The string is Microsoft's and is matched literally; it is written here with
/// its spelling and its hyphen because "Anti-Virus" is not "Antivirus" to
/// anything that reads it.
pub const LOAD_ORDER_GROUP: &str = "FSFilter Anti-Virus";

/// The filter manager's service, which this driver must not start before.
///
/// A minifilter calls `FltRegisterFilter`, which the filter manager implements;
/// a driver loaded ahead of it would have nobody to register with. Naming the
/// dependency is what makes the SCM order the two, and it is the difference
/// between a driver that loads and one that fails on a machine where nothing
/// else has started the filter manager yet.
///
/// # The spelling is the whole of it
///
/// The filter manager's service is `FltMgr`, and Windows has no service called
/// `FltWgr` at all. This constant held that misspelling until 2026-09-26, when a
/// service created with it refused to start with `ERROR_SERVICE_DEPENDENCY_DELETED`
/// (1075) — a number that names neither the dependency nor the misspelling, so
/// the diagnostic has to come from somewhere other than the error. It came from
/// the registry: every minifilter on a stock Windows 11 already names `FltMgr`
/// here, which is `WdFilter`, `FileInfo`, `luafv`, `FileCrypt`, `bindflt`,
/// `storqosflt` and `Wof`, all read out to settle it. Case is not load-bearing,
/// as `FileInfo` writes `fltmgr` and loads, but the service's own key is spelled
/// `FltMgr` and that is what a reader will grep for.
pub const DEPENDENCY: &str = "FltMgr";

/// The name of the single instance under the service's `Instances` key.
///
/// The filter manager reads a minifilter's altitude from
/// `Instances\<name>`, and `DefaultInstance` names which one to use. This is
/// that name, and it is [`SERVICE_NAME`] followed by `" Instance"` — the
/// convention every minifilter follows.
///
/// Written out rather than derived, because building it from [`SERVICE_NAME`]
/// would need an allocation and this crate has none. The test below is what
/// keeps the two in step, and it is the reason this is a constant at all rather
/// than a string literal at the one place that writes it.
pub const INSTANCE_NAME: &str = "WenleAvFilter Instance";

/// That a file name is one the loader will accept as a driver.
///
/// Returned as a `Result` rather than asserted, so that the installer can refuse
/// before it writes anything and the caller can print why: a driver installed
/// under the wrong extension produces a service that is created successfully,
/// starts, and immediately stops with `ERROR_FILE_NOT_FOUND` — an error that
/// names neither the extension nor the file.
pub fn assert_loadable_file_name(name: &str) -> Result<(), &'static str> {
    if !name.ends_with(".sys") {
        return Err("a driver image must be named *.sys, whatever the linker wrote");
    }
    // The name is joined onto a directory, so a separator in it would place the
    // file somewhere other than the directory the caller believes it used.
    if name.contains('\\') || name.contains('/') {
        return Err("a driver's file name must not contain a path separator");
    }
    if name.is_empty() || name == ".sys" {
        return Err("a driver's file name must have a stem");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The range Microsoft documents for [`LOAD_ORDER_GROUP`].
    ///
    /// Written as numbers rather than as a citation, because this test's job is
    /// to fail when the constant is edited to something the filter manager will
    /// reject — and its job is *not* to be a second copy of the documentation.
    /// See the module note on the altitude for what an unallocated value inside
    /// this range does and does not promise.
    const ANTIVIRUS_ALTITUDE_RANGE: std::ops::RangeInclusive<u32> = 320_000..=329_999;

    #[test]
    fn the_service_name_is_typable_and_has_no_spaces() {
        assert!(!SERVICE_NAME.is_empty());
        assert!(
            !SERVICE_NAME.contains(char::is_whitespace),
            "{SERVICE_NAME} would need quoting at every command prompt it is typed at"
        );
        assert!(
            !SERVICE_NAME.contains('\\') && !SERVICE_NAME.contains('/'),
            "{SERVICE_NAME} looks like a path"
        );
        // The SCM's own limit, and a name anywhere near it would be a mistake
        // long before it was a failure.
        assert!(SERVICE_NAME.len() < 256, "{SERVICE_NAME}");
    }

    #[test]
    fn the_file_name_is_one_the_loader_will_accept() {
        assert_loadable_file_name(FILE_NAME).expect("the driver's own file name must be loadable");
        // The rejection paths, so that this test would fail if
        // `assert_loadable_file_name` stopped rejecting anything. A check that
        // cannot fail is not a check.
        assert!(assert_loadable_file_name("av_driver.dll").is_err());
        assert!(assert_loadable_file_name(r"sub\dir\x.sys").is_err());
        assert!(assert_loadable_file_name(".sys").is_err());
    }

    #[test]
    fn the_altitude_is_inside_the_antivirus_group() {
        let altitude: u32 = ALTITUDE
            .parse()
            .expect("the registry holds a decimal string and this is one");
        assert!(
            ANTIVIRUS_ALTITUDE_RANGE.contains(&altitude),
            "{altitude} is outside {ANTIVIRUS_ALTITUDE_RANGE:?}, so the filter manager would \
             refuse to load the driver in the {LOAD_ORDER_GROUP} group"
        );
    }

    #[test]
    fn the_altitude_has_no_fractional_part() {
        // The fraction form means "I already hold an integer in this group and
        // am placing a second filter relative to it". This product holds none,
        // so a fraction here would be a claim about an allocation that does not
        // exist.
        assert!(
            !ALTITUDE.contains('.'),
            "{ALTITUDE} claims an allocation this product has not been given"
        );
        assert!(
            ALTITUDE.chars().all(|c| c.is_ascii_digit()),
            "{ALTITUDE} is not a plain decimal"
        );
    }

    #[test]
    fn the_instance_is_named_the_way_the_filter_manager_expects() {
        // The convention, and the reason the constant is not derived: the
        // filter manager looks up `DefaultInstance`'s value under `Instances`,
        // and a name that does not match the key written there is a filter with
        // no altitude, which does not load.
        assert_eq!(INSTANCE_NAME, format!("{SERVICE_NAME} Instance"));
    }

    #[test]
    fn the_load_order_group_is_the_documented_spelling() {
        // Matched literally by everything that reads it. The hyphen in
        // "Anti-Virus" and the space in "FSFilter" are both load-bearing, and
        // both are the sort of thing an editor tidies.
        assert_eq!(LOAD_ORDER_GROUP, "FSFilter Anti-Virus");
        assert!(LOAD_ORDER_GROUP.contains("Anti-Virus"), "the hyphen is part of the name");
    }

    #[test]
    fn the_dependency_is_the_filter_manager() {
        // The filter manager's service, and the only spelling of it. Windows has
        // no `FltWgr` service; a driver depending on one fails to start with
        // 1075, which reports a missing dependency without naming it, so this
        // assertion is the only place the mistake can be caught cheaply.
        assert_eq!(DEPENDENCY, "FltMgr");
    }

    #[test]
    fn the_build_output_is_the_file_cargo_writes() {
        // Cargo's rule: a `cdylib` is named after its package, with `-` written
        // as `_`. If this ever failed, the installer's search beside the
        // executable would look for a file the build never produces, and the
        // only symptom would be a developer being told their build is missing a
        // driver that is sitting next to it.
        assert_eq!(BUILD_OUTPUT_NAME, "av_driver.dll");
        assert_eq!(
            BUILD_OUTPUT_NAME.replace('-', "_"),
            BUILD_OUTPUT_NAME,
            "cargo writes the package name with hyphens as underscores, so this must have no \
             hyphens in it already"
        );
    }

    #[test]
    fn the_build_output_is_not_a_name_the_loader_accepts() {
        // The pair is only worth documenting if the two names really are
        // different in the way the installer has to handle: one is the build
        // output and one is the installed image, and a check that accepted both
        // would let a `.dll` be registered as a kernel service.
        assert!(assert_loadable_file_name(BUILD_OUTPUT_NAME).is_err());
        assert_ne!(BUILD_OUTPUT_NAME, FILE_NAME);
    }

    #[test]
    fn the_device_subdirectory_is_the_one_the_loader_reads() {
        // `%SystemRoot%\System32\drivers` is where the SCM resolves a driver
        // image and where the loader looks. Spelled with backslashes because it
        // is joined to a Windows path and written into the registry, never into
        // a Rust `Path` on a machine that might not be Windows.
        assert_eq!(DEVICE_SUBDIR, r"System32\drivers");
        assert!(!DEVICE_SUBDIR.starts_with('\\'), "relative to %SystemRoot%, not to the drive");
        assert!(!DEVICE_SUBDIR.ends_with('\\'), "the caller joins with a separator");
    }
}
