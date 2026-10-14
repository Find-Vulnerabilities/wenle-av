//! The application identifier a Windows notification is posted under.
//!
//! # What Windows reads, and what it decides
//!
//! A toast is posted with an *AppUserModelID* (a string, chosen by whoever
//! posts it), and the shell looks that string up in
//! `HKEY_CURRENT_USER\Software\Classes\AppUserModelId` to find the name and the
//! icon to attribute the notification to. One key with two string values is the
//! whole registration:
//!
//! | Value | What it decides |
//! |---|---|
//! | `DisplayName` | the name above the notification, and in Windows Settings |
//! | `IconUri` | the icon beside it, as a path to an image or to an executable |
//!
//! # Why this is cosmetic, measured rather than assumed
//!
//! **A notification does not need this key.** On a machine where nothing has
//! ever been registered, `CreateToastNotifierWithId` and `Show` both succeed,
//! the toast appears, it is recorded by `ToastNotificationManager.History`, and
//! the user reads it. That was measured on Windows 11 before `av-gui`'s
//! notification module was written; its documentation also records the one call
//! that *does* need this key, which is the trap worth knowing about.
//!
//! What is registered here decides what the notification is *called*. Without
//! it a toast still appears, attributed to the path of the executable that
//! posted it rather than to "Wenle Antivirus", with the shell's default icon.
//! That is a real difference to a user and it is not a difference to whether the
//! user is told about a block, which is why nothing in the product requires
//! this command to have been run, and nothing fails when it has not.
//!
//! # One hive, and why there is no machine half
//!
//! `HKEY_CURRENT_USER`, always. Notifications are per-user by construction: the
//! shell that draws them belongs to one signed-in account, the settings page
//! Windows lists them in is that account's, and Windows writes the per-app
//! switch it offers the user under the same hive. A machine-wide entry would
//! name a display name for accounts that cannot post under it anyway.
//!
//! So unlike [`crate::shell`] there is no `Scope` here and no `--machine` flag:
//! a command that took one would be offering a registration Windows does not
//! read. The same reasoning, and the same absence, as [`crate::amsi`]'s, which
//! has no per-user half because AMSI enumerates providers from
//! `HKEY_LOCAL_MACHINE` and nowhere else.
//!
//! # The third key, which this module reads and never writes
//!
//! Once an application has posted a notification, Windows creates
//! `...\CurrentVersion\Notifications\Settings\<AppUserModelID>` and keeps the
//! user's own switches in it: `Enabled`, and whether the notification appears
//! in the Action Center. Those belong to the user. [`status`] reads the key and
//! reports that this account has these notifications switched off, which is a
//! fact a report is worth having; nothing here writes it, because a product that
//! turned its own notifications back on after a user turned them off would be
//! overriding the decision it exists to respect.
//!
//! # What is deliberately not written
//!
//! `CustomActivator`, which is the value a notification *button* needs: it names
//! the COM class Windows activates when one is clicked. Nothing in this product
//! has such a class, so writing the value would register an activation that
//! fails. It is named here rather than omitted so that the next person to want a
//! button on a block notification finds the value that belongs there instead of
//! guessing at the key's shape.
//!
//! `IconBackgroundColor` and `ShowInSettings` are also not written: both affect
//! how the product is presented in Windows' own settings list, neither is
//! something this product has measured, and an unmeasured value in a key a
//! reviewer has to trust is worth less than its absence.

use std::path::Path;

use av_core::{APP_USER_MODEL_ID, AvError, PRODUCT_NAME};

use crate::registry::{Hive, Key, RegistryError};
use crate::shell::{self, ShellError};

/// The name the shell attributes these notifications to.
///
/// The product's own name, from the crate every process in the workspace
/// shares, so that the name in a notification, the name in the window's title
/// bar and the name in the service list cannot drift apart.
pub const DISPLAY_NAME: &str = PRODUCT_NAME;

/// The value that holds [`DISPLAY_NAME`].
pub const DISPLAY_NAME_VALUE: &str = "DisplayName";

/// The value that holds the icon's path.
pub const ICON_VALUE: &str = "IconUri";

/// The value that holds the user's own on/off switch for these notifications.
///
/// Created by Windows, not by this product, and read by [`status`] rather than
/// written. See the module documentation.
pub const ENABLED_VALUE: &str = "Enabled";

/// Where the registration lives, below `HKEY_CURRENT_USER`.
pub fn key_path() -> String {
    format!(r"Software\Classes\AppUserModelId\{APP_USER_MODEL_ID}")
}

/// Where Windows keeps this account's switches for these notifications.
///
/// Below `HKEY_CURRENT_USER`, and not written by anything here.
pub fn settings_path() -> String {
    format!(
        r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\{APP_USER_MODEL_ID}"
    )
}

/// The icon a registration should name, given the executable it stands for.
///
/// A plain filesystem path, and neither of the two things it could have been:
///
/// * **Not a `file:///` URI.** Both forms are accepted for `IconUri` and the
///   plain path is the one an installer writes when it has a path and not a
///   URL; a URI assembled here would have to percent-encode a Windows path, and
///   `C:\Program Files\...` has two characters that would need it.
/// * **Not `path,0`.** The trailing index is how an `.exe` is named in the
///   `Icon` value of a file association, and this is not that value. The path
///   alone is what the key documents.
pub fn icon_for(program: &Path) -> String {
    program.display().to_string()
}

/// The executable the registration should point at.
///
/// The graphical front end when it is installed beside this executable, the
/// console otherwise — the same choice, made by the same function, as the
/// Explorer verbs make. See [`shell::launch_program`] for why the fallback is
/// the console rather than a refusal.
fn icon_path() -> Result<std::path::PathBuf, ShellError> {
    Ok(shell::launch_program(&shell::executable_dir()?))
}

/// Register the identifier, and read back what the registry now holds.
///
/// Idempotent: the key is created if it is missing and opened if it is not, and
/// both values are written outright, so running this twice leaves the same
/// registry as running it once. That is what makes it usable as a repair for a
/// registration that was interrupted between its two values.
///
/// The icon is this executable's own directory's, taken from
/// `std::env::current_exe()`. Nothing here takes a path from the caller: a
/// registration naming a program that is not installed at that path would be a
/// notification attributed to an icon that does not exist, which is a worse
/// answer than no registration.
///
/// Returns [`status`] rather than `()`, so that a command can print what the
/// machine reads back — an install that did not take is then visible in the
/// command that performed it.
pub fn install() -> Result<NotificationStatus, NotificationError> {
    let program = icon_path()?;
    let key = Key::create(Hive::CurrentUser, &key_path())?;
    key.set_string(DISPLAY_NAME_VALUE, DISPLAY_NAME)?;
    key.set_string(ICON_VALUE, &icon_for(&program))?;

    log::info!(
        "registered the notification identifier {APP_USER_MODEL_ID} as {DISPLAY_NAME:?} with the \
         icon {}",
        program.display()
    );
    status()
}

/// Remove the registration.
///
/// Deletes the whole key below `Software\Classes\AppUserModelId`, so the display
/// name and the icon go together — there is no state this module creates that is
/// not under the key this deletes. A key that was never there is not an error,
/// which is what makes this usable as the cleanup step of a failed install as
/// well as the undo of a successful one.
///
/// The account's own switches are left alone. `...\Notifications\Settings` is
/// Windows' record of what the user asked for, and deleting it would turn a
/// user's "notifications from this app: off" back on as a side effect of
/// unregistering a name — which is the opposite of what an uninstall should do
/// to a decision somebody made.
pub fn remove() -> Result<(), NotificationError> {
    Key::delete_tree(Hive::CurrentUser, &key_path())?;
    log::info!("removed the notification identifier {APP_USER_MODEL_ID}");
    Ok(())
}

/// What is registered, read back from the registry.
///
/// Four facts and not a boolean, because the questions a user has are different
/// from each other: whether anything is registered at all, what name and icon it
/// carries — which may have been written by a different build, in a different
/// directory — and whether Windows has these notifications switched off for this
/// account. The last of those is the one nothing else can report: a product that
/// had been muted would otherwise look identical to one whose notifications were
/// being drawn and ignored.
pub fn status() -> Result<NotificationStatus, NotificationError> {
    let registration = match Key::open_read_only(Hive::CurrentUser, &key_path())? {
        Some(key) => (
            key.string(DISPLAY_NAME_VALUE)?,
            key.string(ICON_VALUE)?,
        ),
        None => (None, None),
    };

    // Absent is not off, and the difference is reported: Windows creates this
    // key the first time an application posts, so a machine where no
    // notification has ever been posted has no key, and one where the user has
    // turned them off has a key saying so.
    let (settings_present, enabled) = match Key::open_read_only(Hive::CurrentUser, &settings_path())?
    {
        Some(key) => (true, key.dword(ENABLED_VALUE)?.map(|value| value != 0)),
        None => (false, None),
    };

    Ok(NotificationStatus {
        display_name: registration.0,
        icon: registration.1,
        settings_present,
        enabled,
    })
}

/// What the registry holds about the notification identifier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NotificationStatus {
    /// The `DisplayName` value, or `None` when the value is absent.
    pub display_name: Option<String>,
    /// The `IconUri` value, or `None` when the value is absent.
    pub icon: Option<String>,
    /// Whether Windows has a settings entry for this account at all.
    pub settings_present: bool,
    /// Whether that entry says these notifications are on. `None` when there is
    /// no entry, or when the entry does not carry the value — and absent is not
    /// off, which is why this is not a `bool`.
    pub enabled: Option<bool>,
}

impl NotificationStatus {
    /// Whether the key exists with a display name in it.
    pub fn is_installed(&self) -> bool {
        self.display_name.is_some()
    }

    /// Whether the account has switched these notifications off.
    ///
    /// `false` for a machine with no settings entry, which is the honest answer
    /// to "has the user turned this off": nothing has been turned off, because
    /// nothing has been offered yet.
    pub fn is_muted(&self) -> bool {
        self.enabled == Some(false)
    }
}

/// A registration that could not be written or read.
///
/// Wraps [`RegistryError`] rather than repeating it, and adds the one failure
/// that is about the *product* rather than about a registry call: there is no
/// executable to point the icon at. [`ShellError`] carries it because the
/// question — where is this program running from — is asked and answered the
/// same way for the Explorer verbs, and an error type of its own here would be a
/// second answer that could disagree.
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    /// A registry call failed. See [`RegistryError`], which names the key.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// This executable's own directory could not be determined, so there is no
    /// icon to name.
    #[error(transparent)]
    NoExecutable(#[from] ShellError),
}

impl From<NotificationError> for AvError {
    /// The registry code survives; the rest becomes a sentence.
    ///
    /// The mirror of the conversion [`crate::shell`] makes, and for the same
    /// reason: a caller acting on the failure wants the code, and a person
    /// reading it wants the sentence.
    fn from(error: NotificationError) -> Self {
        match error {
            NotificationError::Registry(registry) => AvError::from(registry),
            other => AvError::Other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registration_is_under_the_current_users_classes_hive() {
        // The whole registration, as a string, because this is what a reviewer
        // checks against Microsoft's documentation and what a user would type
        // into a registry editor to see it for themselves.
        assert_eq!(
            key_path(),
            format!(r"Software\Classes\AppUserModelId\{APP_USER_MODEL_ID}")
        );
        assert!(key_path().starts_with(r"Software\Classes\"));
    }

    #[test]
    fn the_settings_key_is_the_one_windows_writes_and_not_the_registration() {
        // Two keys whose paths differ only in their middle, and the middle is
        // what decides which of them is ours to write. Getting them the wrong
        // way round would put a display name where the user's own switch
        // belongs.
        assert_eq!(
            settings_path(),
            format!(
                r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\{APP_USER_MODEL_ID}"
            )
        );
        assert_ne!(settings_path(), key_path());
        assert!(settings_path().contains(r"Notifications\Settings"));
    }

    #[test]
    fn the_identifier_is_the_one_the_window_posts_under() {
        // `av-gui` posts with this string and this module registers it. There
        // is one constant behind both — `av_core::APP_USER_MODEL_ID` — and this
        // asserts the property that makes it worth having: not empty, and the
        // same in both places by construction rather than by coincidence.
        assert_eq!(av_core::APP_USER_MODEL_ID, "WenleAV");
        assert_eq!(av_core::PRODUCT_NAME, DISPLAY_NAME);
    }

    #[test]
    fn the_icon_is_a_plain_path() {
        // A Windows path with a space and a colon in it, because those are the
        // two characters a `file:///` URI would have to escape — and this is
        // the assertion that says the value is not one.
        let icon = icon_for(Path::new(r"C:\Program Files\WenleAV\wenle-gui.exe"));
        assert_eq!(icon, r"C:\Program Files\WenleAV\wenle-gui.exe");
        assert!(!icon.contains("://"), "{icon}");
        assert!(!icon.ends_with(",0"), "{icon}");
    }

    #[test]
    fn an_absent_settings_entry_is_not_the_user_having_turned_it_off() {
        // The distinction the report exists for. A machine where nothing has
        // ever been posted has no settings key, and reading that as "muted"
        // would tell every such user that they had switched something off.
        let fresh = NotificationStatus::default();
        assert!(!fresh.is_installed());
        assert!(!fresh.is_muted());
        assert!(!fresh.settings_present);
        assert_eq!(fresh.enabled, None);

        let muted = NotificationStatus {
            enabled: Some(false),
            ..NotificationStatus::default()
        };
        assert!(muted.is_muted());

        let allowed = NotificationStatus {
            enabled: Some(true),
            ..NotificationStatus::default()
        };
        assert!(!allowed.is_muted());
    }

    #[test]
    fn an_installed_status_is_one_with_a_display_name_and_not_one_with_a_key() {
        // The key can be there with its values deleted, which is what a
        // half-finished install of a different build leaves behind. A status
        // that answered "installed" from the key's existence would call that
        // machine registered.
        let named = NotificationStatus {
            display_name: Some(DISPLAY_NAME.to_owned()),
            ..NotificationStatus::default()
        };
        assert!(named.is_installed());

        let empty = NotificationStatus {
            icon: Some("C:\\gone\\wenle-gui.exe".to_owned()),
            ..NotificationStatus::default()
        };
        assert!(!empty.is_installed());
    }
}
