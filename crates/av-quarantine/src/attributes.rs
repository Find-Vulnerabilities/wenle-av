//! Getting a file out of the way when it does not want to go.
//!
//! Windows refuses to delete a file that carries `FILE_ATTRIBUTE_READONLY`, and
//! nothing else. `HIDDEN` and `SYSTEM` are cosmetic as far as `DeleteFile` is
//! concerned — they hide the file from a user, they do not protect it from us —
//! so clearing the read-only bit is the whole of what is needed, and the whole
//! of what this module does.
//!
//! It is here because it is not an edge case. Setting the read-only attribute is
//! a standard trick, it costs the malware one API call, and without this the
//! product would report a threat it could not remove and leave the file where it
//! was. That failure is worse than it sounds: the user is told the file is
//! quarantined, the file is still there and still runs, and the report is a lie.

use std::path::Path;

/// Clear the read-only attribute, returning whether anything was changed.
///
/// A file that was already writable returns `Ok(false)` rather than an error,
/// so a caller can retry a failed deletion unconditionally and only report the
/// original failure when this made no difference.
///
/// On a platform whose permissions are a mode rather than an attribute this
/// does nothing and says so. The read-only *attribute* is a Windows idea, and
/// the nearest thing elsewhere — clearing the write bit — would mean clearing
/// one bit of a mode word this module has no business guessing at. The callers
/// treat `Ok(false)` as "this was not the obstacle", which is the right
/// conclusion on such a platform.
pub fn clear_readonly(path: &Path) -> std::io::Result<bool> {
    #[cfg(windows)]
    let outcome = clear_readonly_attribute(path);
    #[cfg(not(windows))]
    let outcome = {
        // Stat the path anyway, so that a missing file is reported the same way
        // on every platform rather than becoming a silent no-op.
        std::fs::metadata(path)?;
        Ok(false)
    };
    outcome
}

/// The Windows half: clear `FILE_ATTRIBUTE_READONLY` and report whether it was
/// set.
///
/// The lint allowed below is about Unix, where clearing the write bit makes a
/// file world writable. This function exists only on Windows, where the same
/// standard-library call sets a per-file attribute that has no owner, group or
/// other behind it.
#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly_attribute(path: &Path) -> std::io::Result<bool> {
    let metadata = std::fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    if !permissions.readonly() {
        return Ok(false);
    }
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)?;
    log::debug!(
        "cleared the read-only attribute on {} so it could be removed",
        path.display()
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn writable_file(dir: &Path, name: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(b"payload").expect("write");
        path
    }

    #[test]
    fn an_already_writable_file_reports_no_change() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = writable_file(dir.path(), "plain.bin");
        assert!(!clear_readonly(&path).unwrap());
        assert!(path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_read_only_file_becomes_deletable() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = writable_file(dir.path(), "stubborn.bin");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();

        assert!(clear_readonly(&path).unwrap());
        assert!(!std::fs::metadata(&path).unwrap().permissions().readonly());
        std::fs::remove_file(&path).expect("it must be removable now");
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn clearing_twice_is_not_an_error() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = writable_file(dir.path(), "twice.bin");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();

        assert!(clear_readonly(&path).unwrap());
        assert!(!clear_readonly(&path).unwrap());
    }

    #[test]
    fn a_missing_file_is_an_error_here_rather_than_silence() {
        // The caller distinguishes "there was nothing to do" from "the file is
        // gone"; conflating the two would hide a race in the removal path.
        let dir = tempfile::tempdir().expect("a temporary directory");
        assert!(clear_readonly(&dir.path().join("absent.bin")).is_err());
    }
}
