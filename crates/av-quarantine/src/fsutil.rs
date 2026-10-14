//! Two filesystem helpers the vault needs and `std` does not offer.
//!
//! Both exist because of the same requirement: **the vault must never be left
//! in a state a reader would mistake for valid**. A quarantine operation
//! touches three things — a blob, the index, and the original file — and a
//! power loss between any two of them must leave a vault that still opens.

use std::path::Path;

use crate::error::{QuarantineError, Result};

/// Write `bytes` to `path` so that a reader sees either the old contents or the
/// new ones, never a prefix of the new ones.
///
/// The write goes to a sibling temporary file, is flushed, and is then renamed
/// over the target. On Windows `std::fs::rename` maps to `MoveFileEx` with
/// `MOVEFILE_REPLACE_EXISTING`, which is atomic for a same-volume rename — and
/// the temporary is always a sibling, so the rename never crosses a volume.
///
/// The flush before the rename is what makes this work rather than merely look
/// like it works: without it the rename can land before the data does, and the
/// index is then a valid name pointing at a file of zeroes.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| QuarantineError::Other(format!("{} has no parent", path.display())))?;
    std::fs::create_dir_all(parent).map_err(|e| QuarantineError::io("create", parent, e))?;

    let temporary = sibling(path, ".tmp");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&temporary)
            .map_err(|e| QuarantineError::io("create", &temporary, e))?;
        file.write_all(bytes)
            .map_err(|e| QuarantineError::io("write", &temporary, e))?;
        // `sync_all` and not `flush`: `flush` only pushes the bytes out of the
        // standard library's buffer, which is not the promise being made here.
        file.sync_all()
            .map_err(|e| QuarantineError::io("flush", &temporary, e))?;
    }

    std::fs::rename(&temporary, path).map_err(|e| {
        // Leaving the temporary behind after a failed rename turns a transient
        // failure into a directory that slowly fills with junk.
        std::fs::remove_file(&temporary).ok();
        QuarantineError::io("replace", path, e)
    })
}

/// Read a file, treating absence as `None` rather than as an error.
///
/// Every load path in this crate distinguishes "not created yet" from "cannot
/// be read": the first is how a fresh installation starts, the second means
/// something is wrong with the machine or with our own storage.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(QuarantineError::io("read", path, e)),
    }
}

/// Append a suffix to a path's file name, keeping the extension in place:
/// `index.enc` becomes `index.tmp.enc`.
///
/// The suffix goes before the extension rather than after so that the
/// temporary of a `.qtn` blob still ends in `.qtn`, which keeps a directory
/// listing readable and, more usefully, keeps the vault's own file-matching
/// rules from having to know about two spellings.
fn sibling(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.file_stem().unwrap_or_default().to_os_string();
    name.push(suffix);
    if let Some(extension) = path.extension() {
        name.push(".");
        name.push(extension);
    }
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temporary directory")
    }

    #[test]
    fn a_write_is_visible_whole() {
        let d = dir();
        let path = d.path().join("index.enc");
        write_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn a_second_write_replaces_the_first_and_leaves_no_temporary() {
        let d = dir();
        let path = d.path().join("index.enc");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        let left: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["index.enc".to_string()], "a temporary survived");
    }

    #[test]
    fn a_write_creates_missing_parents() {
        let d = dir();
        let path = d.path().join("items").join("nested").join("blob.qtn");
        write_atomic(&path, b"x").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn the_temporary_keeps_the_extension_it_is_replacing() {
        let p = std::path::Path::new(r"C:\vault\items\ab.qtn");
        assert_eq!(
            sibling(p, ".tmp"),
            std::path::PathBuf::from(r"C:\vault\items\ab.tmp.qtn")
        );
        // A file with no extension still gets a usable sibling.
        let q = std::path::Path::new(r"C:\vault\index");
        assert_eq!(
            sibling(q, ".tmp"),
            std::path::PathBuf::from(r"C:\vault\index.tmp")
        );
    }

    #[test]
    fn a_missing_file_is_none_and_an_unreadable_one_is_an_error() {
        let d = dir();
        assert_eq!(read_optional(&d.path().join("nothing")).unwrap(), None);
        // A directory is not a file; reading it fails for a reason that is not
        // "not found", and must not be silently reported as absent.
        let err = read_optional(d.path()).unwrap_err();
        assert!(matches!(err, QuarantineError::Io { .. }), "{err:?}");
    }
}
