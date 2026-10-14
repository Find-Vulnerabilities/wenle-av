//! The native file and folder pickers.
//!
//! # Why this exists at all
//!
//! A scanner with no way to browse to a folder is missing something a user
//! looks for in the first thirty seconds: they know which folder they are
//! suspicious of, and typing its path is a test of spelling rather than a way
//! to use the product. So there are two buttons beside the target field, one
//! that picks a folder and one that picks a single file, and the typed path
//! they sit next to keeps working exactly as it did.
//!
//! # Why the dependency is declared in this crate's manifest and not in the
//! workspace's
//!
//! `[workspace.dependencies]` is for dependencies that more than one crate
//! needs to agree on — `serde`, `log`, the engine crates. A file dialog is
//! needed by this crate, on one platform, and by nothing else in the product,
//! and the workspace manifest is a file every crate's change goes through. It
//! is also the case that the dialog is a Windows-only dependency: see below.
//!
//! # What happens on a platform that is not Windows
//!
//! `rfd` is declared under `[target.'cfg(windows)'.dependencies]`, so on any
//! other platform it is not compiled, [`available`] returns `false`, and the
//! window draws no picker buttons — a button that opened nothing is worse than
//! no button, because it is a product that appears broken. The typed path is
//! still there and still works, which is why it is not a removal: on those
//! platforms the target field is the only way to name a target, and the two
//! functions below return `None` rather than being absent, so the caller has
//! one shape to write rather than two.
//!
//! The cost is stated rather than hidden: on a platform that is not Windows
//! this crate has no browse button. Making one work there means compiling `rfd`
//! for it, which is a line in the manifest and no change here.
//!
//! # What can be tested, and what cannot
//!
//! Nothing in this module that opens a dialog can be tested. A native picker
//! cannot be dismissed except by a person clicking it, and a test that opened
//! one would hang the test run until the runner gave up. The seam is therefore
//! drawn on purpose, and everything on the near side of it is a pure function:
//!
//! * the drawing code asks [`available`] whether to offer a button at all;
//! * what comes back — a path, or `None` when the user cancelled — goes to
//!   `GuiApp::set_target`, which is a function of its argument alone and is
//!   tested for both answers;
//! * the single line in each function below that opens a dialog is the only
//!   code in this crate that no test reaches, and it is deliberately the only
//!   thing in the function.
//!
//! That last line was checked out of band rather than left as an assurance.
//! Driving a running window through UI Automation — find the `Browse…` button,
//! invoke it, then diff the process's top-level windows — produces a new window
//! of class `#32770` titled "Choose a folder to scan", which is the title
//! [`choose_folder`] hands to `rfd`. The dialog does open; what stays untested
//! is whether a person can *use* it, not whether the call reaches Windows.
//!
//! The diff is the part worth copying, because the obvious check is wrong. Ask
//! only "did a new top-level window appear" and the answer is yes even when no
//! dialog opened: a third-party IME injects its own top-level window into the
//! process — Sogou Pinyin was installed on the machine this was verified on,
//! appearing as a window of class `SoPY_Status`. Match the window class, or the
//! title, or the check passes for the wrong window.
//!
//! # Why the dialog is not given a parent window
//!
//! `rfd` can be handed the window to own the dialog, which would keep it above
//! this window instead of letting it be a top-level window of its own. That
//! needs the window's raw handle held for the life of the application: a
//! dependency on `raw-window-handle` of our own, a hand-written
//! `HasWindowHandle` that reconstructs a handle from raw parts, and a safety
//! argument for doing so. The dialog is shown from the frame loop and the
//! window is blocked while it is up, so the handle would always be valid — but
//! it is an unsafe block and a dependency bought for the stacking order of one
//! dialog, and this crate does not spend those on that.

use std::path::PathBuf;

/// Ask the user for a folder.
///
/// `None` means the user cancelled, which is not an error and is not a choice:
/// the caller keeps whatever the target field already said.
#[cfg(windows)]
pub fn choose_folder() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Choose a folder to scan")
        .pick_folder()
}

/// Ask the user for a single file.
///
/// `None` means the user cancelled — see [`choose_folder`].
#[cfg(windows)]
pub fn choose_file() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Choose a file to scan")
        .pick_file()
}

/// Ask the user for a folder. No picker is compiled in on this platform.
///
/// Present rather than absent so that the drawing code above has one call to
/// write and not two, with a `#[cfg]` at the call site as well as here. See the
/// module documentation for what the user gets instead.
#[cfg(not(windows))]
pub fn choose_folder() -> Option<PathBuf> {
    None
}

/// Ask the user for a single file. No picker is compiled in on this platform.
///
/// See [`choose_folder`] and the module documentation.
#[cfg(not(windows))]
pub fn choose_file() -> Option<PathBuf> {
    None
}

/// Whether a picker exists on this platform.
///
/// The one thing here a test can check without a person at the keyboard, and
/// the one thing the drawing code needs: a button that opens nothing is worse
/// than no button, so the buttons are drawn only where this is true.
pub const fn available() -> bool {
    cfg!(windows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_picker_is_offered_exactly_where_one_is_compiled_in() {
        // The pairing this test exists to keep: the manifest compiles `rfd` for
        // Windows, and the window offers the buttons when, and only when, this
        // says so. Changing one without the other is a button that does nothing
        // on one platform or a platform with no button where one would work.
        assert_eq!(available(), cfg!(windows));
    }

    // There is no test of the pickers themselves, and there is deliberately no
    // pretence of one: both functions open a native modal dialog, and a modal
    // dialog cannot be dismissed by a test. The behaviour that *is* worth
    // asserting without a person is what a caller does with the answer, and
    // that lives in `GuiApp::set_target`, where both answers are tested.

    #[test]
    #[cfg(not(windows))]
    fn a_platform_with_no_picker_answers_nothing() {
        // Compiled only where `rfd` is not, so that on Windows — where these
        // two calls would put a file dialog on the screen and block the test
        // run until a human clicked it — this test does not exist at all.
        assert_eq!(choose_folder(), None);
        assert_eq!(choose_file(), None);
    }
}
