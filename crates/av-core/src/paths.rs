//! Where the product keeps its files.
//!
//! All runtime state lives under a single root so that uninstalling is a
//! directory delete and so that the self-protection rules have exactly one
//! tree to defend. The layout is resolved once at startup and passed around as
//! [`AvPaths`] rather than recomputed from the environment at each call site —
//! recomputation is how the previous generation of this code ended up with
//! quarantine directories in three different places.

use std::path::{Path, PathBuf};

use crate::error::{AvError, AvResult};

/// Directory name used under `%ProgramData%` and as the install folder name.
pub const PRODUCT_DIR: &str = "WenleAV";

/// Directory name holding rule sources, under either root.
///
/// One name for both roots on purpose: the rule compiler reads the *installed*
/// tree under the data root, and falls back to the tree that shipped beside the
/// executable, and the two are only interchangeable while they are spelled the
/// same. See [`AvPaths::shipped_rules_dir`].
const RULES_DIR: &str = "rules";

/// Resolved filesystem layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvPaths {
    /// Where the executables and the compiled rule database live.
    pub install_dir: PathBuf,
    /// Writable root for all mutable state.
    pub data_dir: PathBuf,
    pub config_file: PathBuf,
    pub quarantine_dir: PathBuf,
    pub log_dir: PathBuf,
    pub rules_dir: PathBuf,
    pub cache_dir: PathBuf,
    /// Signature/reputation databases and the compiled rule blob.
    pub db_dir: PathBuf,
}

impl AvPaths {
    /// Build the standard layout for a normal installation.
    ///
    /// `install_dir` is passed in (normally derived from the running
    /// executable) because only the caller knows where the binary lives.
    pub fn new(install_dir: impl Into<PathBuf>) -> Self {
        let install_dir = install_dir.into();
        let data_dir = default_data_dir();
        Self::with_data_dir(install_dir, data_dir)
    }

    /// Build a layout with an explicit data directory. Used by tests and by
    /// portable installs.
    pub fn with_data_dir(install_dir: impl Into<PathBuf>, data_dir: impl Into<PathBuf>) -> Self {
        let install_dir = install_dir.into();
        let data_dir = data_dir.into();
        Self {
            config_file: data_dir.join("config.toml"),
            quarantine_dir: data_dir.join("quarantine"),
            log_dir: data_dir.join("logs"),
            rules_dir: data_dir.join(RULES_DIR),
            cache_dir: data_dir.join("cache"),
            db_dir: data_dir.join("db"),
            install_dir,
            data_dir,
        }
    }

    /// Layout rooted at the directory containing the running executable.
    pub fn for_current_exe() -> AvResult<Self> {
        let exe = std::env::current_exe()
            .map_err(|e| AvError::Other(format!("cannot locate the running executable: {e}")))?;
        let dir = exe
            .parent()
            .ok_or_else(|| AvError::Other("executable path has no parent directory".into()))?;
        Ok(Self::new(dir))
    }

    /// Where the rule sources that ship *beside the executable* live.
    ///
    /// Not [`Self::rules_dir`], which is the installed tree under the data root
    /// and is where a user's own rules go. This one is what a release carries:
    /// the product has no installer, so a release is unpacked and this tree is
    /// never copied into the data root. It exists as a method rather than as a
    /// `join("rules")` at the call site so that the two spellings cannot drift
    /// apart, and so that the one place that has to know both is here.
    ///
    /// The two are the same directory in a portable layout, where the data root
    /// *is* the install directory — which is why callers compare rather than
    /// assume they differ.
    pub fn shipped_rules_dir(&self) -> PathBuf {
        self.install_dir.join(RULES_DIR)
    }

    /// Every directory that must exist for the product to run.
    pub fn all_dirs(&self) -> [&Path; 6] {
        [
            &self.data_dir,
            &self.quarantine_dir,
            &self.log_dir,
            &self.rules_dir,
            &self.cache_dir,
            &self.db_dir,
        ]
    }

    /// Create every directory in the layout if it does not exist.
    pub fn ensure_dirs(&self) -> AvResult<()> {
        for dir in self.all_dirs() {
            std::fs::create_dir_all(dir).map_err(|e| AvError::io_at(dir, e))?;
        }
        Ok(())
    }

    /// True when `path` is inside a directory the product must defend.
    ///
    /// Covers the whole of the install tree and the whole of the data root —
    /// not just the quarantine vault and the rule database. Anything under
    /// `data_dir` is product state: the configuration, the detection history,
    /// the logs and the vault. Malware that can rewrite our configuration or
    /// erase our logs has effectively disabled the product even if it never
    /// touches a rule file, so the entire tree is defended.
    ///
    /// This answers "is this path ours?", not "may this particular caller
    /// write it?" — the product's own service and GUI are of course allowed to
    /// write here. Callers pass through an allowance for their own process.
    pub fn is_protected(&self, path: &Path) -> bool {
        let candidate = normalize_for_compare(path);
        [&self.install_dir, &self.data_dir].iter().any(|root| {
            let root = normalize_for_compare(root);
            candidate == root
                || candidate
                    .strip_prefix(&root)
                    .is_some_and(|rest| rest.starts_with('\\'))
        })
    }
}

/// The default writable root: `%ProgramData%\WenleAV`, falling back to the
/// user's local data directory on systems where `ProgramData` is unavailable.
pub fn default_data_dir() -> PathBuf {
    if let Some(program_data) = std::env::var_os("ProgramData") {
        let candidate = PathBuf::from(program_data).join(PRODUCT_DIR);
        if !candidate.as_os_str().is_empty() {
            return candidate;
        }
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(PRODUCT_DIR)
}

/// The cargo workspace root a directory sits in, when it sits in one.
///
/// Returns the directory that holds the `Cargo.toml`, so a caller's refusal can
/// name it rather than making the reader work out where the tree starts.
///
/// # Why this is a question about two names and not about one
///
/// The `Cargo.toml` test is what keeps this from being a guess about the name of
/// a directory: a directory called `target` is a build tree only when the
/// directory above it is a cargo workspace. An installation that happens to live
/// under `D:\target\` is therefore not refused, which matters because the whole
/// point of the check is to be narrow enough that its refusal can be believed.
///
/// # Why it lives here rather than at either caller
///
/// Two callers ask it about the same directory for the same reason — a build
/// tree is the one layout where writing an installation's permissions, or arming
/// a kernel gate over the installation's files, locks the account doing the
/// building out of the directory cargo writes into. `av-cli`'s
/// `wenle protect apply` asks before it writes a DACL; `av-service` asks before
/// it asks the driver to refuse writes there. The answer must be the same
/// answer, so it is one function in the crate both can depend on. It was in
/// `av-cli/src/commands/protect.rs` until `av-service` needed it.
pub fn cargo_build_tree(install_dir: &Path) -> Option<PathBuf> {
    let mut dir = Some(install_dir);
    while let Some(current) = dir {
        let named_target = current
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("target"));
        if named_target {
            if let Some(parent) = current.parent() {
                if parent.join("Cargo.toml").is_file() {
                    return Some(parent.to_path_buf());
                }
            }
        }
        dir = current.parent();
    }
    None
}

/// Lowercase and strip the Windows extended-length prefix so two spellings of
/// the same path compare equal. Windows paths are case-insensitive.
fn normalize_for_compare(path: &Path) -> String {
    let s = path.to_string_lossy().to_lowercase();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_data_dir_derives_every_subdirectory() {
        let p = AvPaths::with_data_dir(r"C:\Program Files\WenleAV", r"C:\ProgramData\WenleAV");
        assert_eq!(
            p.config_file,
            PathBuf::from(r"C:\ProgramData\WenleAV\config.toml")
        );
        assert_eq!(
            p.quarantine_dir,
            PathBuf::from(r"C:\ProgramData\WenleAV\quarantine")
        );
        assert_eq!(p.log_dir, PathBuf::from(r"C:\ProgramData\WenleAV\logs"));
    }

    #[test]
    fn protected_covers_install_and_vault_but_not_user_documents() {
        let p = AvPaths::with_data_dir(r"C:\Program Files\WenleAV", r"C:\ProgramData\WenleAV");
        assert!(p.is_protected(Path::new(r"C:\Program Files\WenleAV\wenle-av.exe")));
        assert!(p.is_protected(Path::new(r"C:\ProgramData\WenleAV\quarantine\abc.bin")));
        assert!(!p.is_protected(Path::new(r"C:\Users\me\Documents\report.docx")));
    }

    #[test]
    fn protection_check_is_case_insensitive() {
        let p = AvPaths::with_data_dir(r"C:\Program Files\WenleAV", r"C:\ProgramData\WenleAV");
        assert!(p.is_protected(Path::new(r"c:\program files\wenleav\data\rules.avdb")));
    }

    #[test]
    fn sibling_directory_with_shared_prefix_is_not_protected() {
        // `WenleAV-backup` shares a textual prefix with `WenleAV` but is a
        // different directory and must not be treated as inside the install.
        let p = AvPaths::with_data_dir(r"C:\Program Files\WenleAV", r"C:\ProgramData\WenleAV");
        assert!(!p.is_protected(Path::new(r"C:\ProgramData\WenleAV-backup\x.txt")));
    }

    #[test]
    fn escaped_path_is_normalized() {
        let p = AvPaths::with_data_dir(r"C:\Program Files\WenleAV", r"C:\ProgramData\WenleAV");
        assert!(p.is_protected(Path::new(r"\\?\C:\ProgramData\WenleAV\logs\a.log")));
    }
}
