//! The graphical front end.
//!
//! # What this binary is, and what it is not
//!
//! It is a window over the same engine the console drives (the same database,
//! the same thresholds, the same three bands), so that a file the console calls
//! `suspicious` is called suspicious here, in the same word and the same
//! colour. It is not a second implementation of anything: every decision about
//! what a file *is* belongs to [`av_scan`], and this crate's job is to show it
//! and to let a person say what to do about it.
//!
//! # Language
//!
//! English only. This was specified rather than assumed, and it is worth being
//! explicit about the consequence: there is no string table and no locale
//! detection, so every user-visible string is a literal in the source. Adding a
//! translation later means introducing that indirection, and pretending
//! otherwise now would mean a half-built one.
//!
//! # Suggested shape
//!
//! The window is drawn by `eframe` and the drawing is the part that cannot be
//! tested. Everything the drawing *reads* can be, and should be: the state a
//! scan moves through, the strings the interface puts in front of a user, the
//! filtering of a findings list, and the mapping from a verdict to a colour and
//! a word. Those belong in modules alongside this file with unit tests of their
//! own, so that `cargo test -p av-gui` is worth running even though no test can
//! click a button. The scanner runs on its own thread and the interface reads
//! what it reports; a scan takes minutes on a real disk and a window that
//! blocks while it runs is the one thing an immediate-mode interface must not
//! do.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_docs)]
// No console behind the window, in a build that is meant to be double-clicked.
//
// A console-subsystem program started from Explorer gets a console window it
// did not ask for, and a black rectangle behind the window is the first thing
// that says "not a real application". So the release is a Windows-subsystem
// program — which also means it has no console at all, and that is why
// [`report_fatal`] shows a dialog in this configuration instead of printing.
//
// Debug builds keep the console on purpose: `cargo run` should put the reason
// in the terminal it was started from, where a developer will look, rather than
// behind a modal window that has to be dismissed before the terminal is
// readable again. This is also what the `eframe` template does, for the same
// reason.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod filter;
mod format;
mod glyphs;
mod icons;
// Telling a user about a block when they are not looking at the window. Its own
// module because the shell's notification API has two behaviours that are the
// opposite of what they look like — a notification needs no registration to
// appear, and the call that asks whether it may appear fails without one — and
// a module is somewhere to write that down; see its documentation.
mod notify;
mod picker;
mod scan;
// The control pipe, as a caller. Its own module because the window is a client
// of the service and not a second service: a restore or a delete *about* an
// item in the vault is the service's to perform, and the vault's single-writer
// rule is why. See its documentation for the one write the window still does
// itself.
mod service;
// One window per machine, and what a second click does instead of opening
// another. Its own module because the mechanism — a named mutex and a pipe —
// is longer than its use, and because the alternative it replaces is a window
// the user has to close before they can see the one they meant.
mod single;
mod state;
mod theme;
// The icon in the notification area. Its own module because it is the only thing
// in this crate that creates a *second* window, on a second thread with its own
// message loop, and because the one property a reader has to be able to check is
// stated there: a window that puts itself out of the way needs that icon to
// exist, so the answer `Tray::start` gives decides whether that is allowed at
// all.
mod tray;
// Noticing that the vault's index was rewritten by another process, which is
// the only way a window learns that the service blocked a file while it was
// open. Its own module because the reasoning is longer than the code; see its
// documentation for why this is a poll rather than a subscription.
mod vault_poll;

use std::path::{Path, PathBuf};

use av_core::AvPaths;
use clap::Parser as _;
use eframe::egui;

/// The window's command line.
///
/// A window that is double-clicked has no arguments, and this is written so
/// that case is the default and the flag is the exception: `--data-dir` is the
/// only thing here, and it exists because the console has it.
#[derive(Debug, clap::Parser)]
#[command(
    name = "wenle-gui",
    version,
    about = "The Wenle AV graphical front end",
    long_about = None,
    disable_help_subcommand = true,
)]
struct Args {
    /// Keep all product state — configuration, rule database, quarantine
    /// vault, logs — under this directory instead of `%ProgramData%\WenleAV`.
    ///
    /// The same flag the console takes, and deliberately the same words: a
    /// portable install is a directory holding the executables and one `data`
    /// directory, and it only works if the two front ends agree about which
    /// one that is. A file the console quarantined has to appear in the
    /// window's list, and it will not if they disagree.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Scan this file or folder as soon as the window opens.
    ///
    /// This exists for the Explorer context menu, which runs
    ///
    /// ```text
    /// wenle-gui.exe --scan "%1"
    /// ```
    ///
    /// when a user right-clicks a file or folder and chooses **Scan with Wenle
    /// Antivirus**. The registration that puts that menu item there is in
    /// `av-integration`; this is the other half of it.
    ///
    /// The window is the right target for that verb rather than the console
    /// front end, and the reason is what a user sees: a console started from
    /// Explorer gets a console window that closes the instant the scan ends, so
    /// the findings scroll past and vanish. The window stays open, keeps the
    /// list, and can quarantine from it.
    ///
    /// A path that does not exist is not rejected here. The window opens with
    /// it in the target field and the scan reports the failure in the place
    /// results are reported, because a dialog before the window exists is a
    /// dialog with nothing behind it.
    #[arg(long, value_name = "PATH")]
    scan: Option<PathBuf>,

    /// Start with no window: the notification-area icon only.
    ///
    /// This is what the entry Windows runs at sign-in passes, and the string is
    /// written by `av-integration`'s startup module rather than here — see
    /// [`av_integration::startup::MINIMIZED_FLAG`], which is the one place the
    /// spelling lives. A sign-in that opened a window every time would be a
    /// product a user turns off within a week.
    ///
    /// It is honoured only when the icon could actually be created. A build
    /// whose tray failed has no way to be brought back into view, so the window
    /// opens instead — see [`crate::tray`], which is where that decision is
    /// made and why.
    #[arg(long)]
    minimized: bool,
}

/// Start the window.
///
/// Returns the process's exit code. Everything here that can fail is reported
/// where the user of this build can see it — a dialog in a release, the
/// terminal in a debug build, as [`report_fatal`] explains — and turned into a
/// code rather than a panic: this is the binary a user double-clicks, so a
/// panic means a window that flashes and vanishes with its reason somewhere the
/// user will not look.
/// The system allocator, with a report written when it refuses a request.
///
/// This matters more here than in the console. The release build is a
/// `windows`-subsystem program, so there is no stderr to write to at all: an
/// out-of-memory abort would leave the user with a window that vanished and
/// nothing, anywhere, recording why. See [`av_core::alloc`].
#[global_allocator]
static ALLOCATOR: av_core::alloc::Reporting = av_core::alloc::Reporting;

fn main() -> std::process::ExitCode {
    init_logging();
    let args = Args::parse();

    // Where the product's directories are is resolved from the running
    // executable, so that a copy unpacked anywhere finds its own data rather
    // than a path baked in at build time. It is the one thing here that can
    // fail before the window exists at all.
    let paths = match resolve_paths(args.data_dir.as_deref()) {
        Ok(paths) => paths,
        Err(error) => {
            report_fatal(&format!(
                "the installation directory could not be resolved: {error}"
            ));
            return std::process::ExitCode::FAILURE;
        }
    };
    // Before anything slow, because the claim and the listener are not created
    // at the same instant: this process holds the name from here on, and a
    // second launch arriving in the gap before the pipe exists is one that
    // `single`'s connect loop has to wait out. Claiming first makes that gap as
    // short as it can be, and a second click is a thing a user does quickly.
    //
    // Claimed before `ensure_dirs` on purpose: a launch that is only going to
    // hand its request to the running window should not create directories, and
    // more to the point should not be the launch that reports a directory
    // problem the running window will report better.
    let owner = match single::claim(&paths.data_dir, args.scan.as_deref()) {
        single::Claim::Only(owner) => owner,
        single::Claim::AlreadyRunning => {
            // Nothing to report and nothing to wait for. The window that owns
            // the name has been told what this launch wanted — including, if
            // there was one, the path from a right-click — and this process has
            // no further part to play in it.
            log::info!("a window is already open, and this launch was passed to it");
            return std::process::ExitCode::SUCCESS;
        }
    };

    // Created before anything else looks in them, and a failure here is fatal:
    // without the data directory there is nowhere to put a configuration, a
    // vault or a rule database, so the window would open onto an installation
    // that cannot do anything.
    if let Err(error) = paths.ensure_dirs() {
        report_fatal(&format!(
            "the data directories could not be created under {}: {error}",
            paths.data_dir.display()
        ));
        return std::process::ExitCode::FAILURE;
    }

    // After `ensure_dirs`, so the directory this opens into is known to exist.
    // Not fatal if it fails: the window still works, it just runs without the
    // one record that would explain a scan that disappeared.
    match av_core::set_crash_log(paths.log_dir.join("crash.log")) {
        Ok(()) => log::info!("allocation failures will be reported in {}", paths.log_dir.join("crash.log").display()),
        Err(error) => log::warn!("no crash log: {error}"),
    }

    match run(paths, args.scan, args.minimized, owner) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            report_fatal(&format!("the window could not be opened: {error}"));
            std::process::ExitCode::FAILURE
        }
    }
}

/// The layout this process will use.
///
/// `data_dir` is `--data-dir`, and only the data root is overridable: where the
/// executable lives is a fact about the running process, while where its state
/// lives is a choice — the choice that makes a portable install a directory
/// somebody can move. The console resolves it with the same rule, in
/// `av_cli::commands::Context::resolve`.
fn resolve_paths(data_dir: Option<&Path>) -> av_core::AvResult<AvPaths> {
    let installed = AvPaths::for_current_exe()?;
    Ok(match data_dir {
        Some(dir) => AvPaths::with_data_dir(installed.install_dir, dir),
        None => installed,
    })
}

/// Report a failure that stopped the window from opening.
///
/// Where this goes depends on whether the build has a console, and that is
/// decided by which of this function's two definitions was compiled rather than
/// at the call site. A release has none — see the `windows_subsystem` attribute
/// — so the message has to be a dialog or it is nowhere: a user who
/// double-clicked would see nothing happen at all and have no way to find out
/// why. A debug build prints to the terminal it was started from.
///
/// The message is the same one that goes to the log in both cases, because
/// these are the failures worth a log line: nothing else has been written yet.
#[cfg(all(windows, not(debug_assertions)))]
fn report_fatal(message: &str) {
    log::error!("{message}");
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title(WINDOW_TITLE)
        .set_description(message)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

/// Report a failure that stopped the window from opening.
///
/// The debug and non-Windows half of the pair; see the other definition for why
/// there are two.
#[cfg(not(all(windows, not(debug_assertions))))]
fn report_fatal(message: &str) {
    log::error!("{message}");
    eprintln!("wenle-gui: {message}");
}

/// Open the window and run until it is closed.
///
/// Separated from [`main`] so that a test — and a person reading the code — can
/// see exactly which of the two things that can go wrong is the one that did:
/// reading the configuration, which a broken file makes fail, and opening the
/// window, which a machine with no display makes fail. The first of those is
/// *not* fatal: the window opens on the defaults and says what happened, because
/// a settings screen is the only place a broken configuration can be looked at
/// and repaired without a text editor.
fn run(
    paths: AvPaths,
    scan: Option<PathBuf>,
    minimized: bool,
    owner: single::Owner,
) -> Result<(), eframe::Error> {
    let mut app = app::GuiApp::load(paths);
    // Later launches report through this, drained each frame. Handed over
    // rather than read here because the request arrives while the window is
    // running: a right-click on a file is not a thing that only happens before
    // the window opens.
    app.watch_for_later_launches(owner.receiver().clone());

    // `--scan`, from the context menu. Both calls are made before the first
    // frame is drawn rather than from a start-up hook inside the window, so
    // that the very first thing the user sees is the scan already running: a
    // window that opens idle and then starts a moment later looks like it
    // ignored the click.
    //
    // `start_scan` is not infallible and is not treated as though it were. It
    // refuses when there is no rule database, which is a machine where the
    // product has not been set up — and it says so in the window's own status
    // line, which is exactly where a user who just right-clicked will be
    // looking. There is nothing useful to do about that here beyond letting it
    // report itself.
    if let Some(path) = scan {
        app.set_target(Some(path));
        app.start_scan();
    }

    // Read off the application rather than from a constant, so that
    // `ui.window_width` and `ui.window_height` are the size the window actually
    // opens at. Clamped by `app::window_size`, whose documentation says why a
    // number from a text file cannot be taken at face value.
    let size = app.window_size();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(WINDOW_TITLE)
            .with_inner_size(size)
            // The floor, so that a window dragged narrow does not become a
            // column of clipped labels with no way back.
            .with_min_inner_size(app::MIN_WINDOW_SIZE)
            // `--minimized`, and only until the first frame. Whether the icon
            // that makes a put-away window reachable exists cannot be known here
            // — creating it needs a context, and the context is made inside the
            // closure below — so this is the one decision that has to wait for a
            // frame, and it waits in `GuiApp::settle_launch_visibility`. The
            // order matters: creating the window hidden and then showing it is
            // one frame of nothing, while creating it visible and then putting
            // it away is a window that flashes at every sign-in.
            //
            // This is not by itself what keeps a `--minimized` start off the
            // screen: `eframe` unhides the window at the end of the first frame
            // whatever it was created as. See `GuiApp::settle_launch_visibility`,
            // which minimises it again on the frame that decides the icon
            // exists.
            .with_visible(!minimized)
            // At sign-in the window goes straight into the notification area, so
            // a taskbar button for it would be a button that appears at every
            // login for a window the user did not open and cannot see. This is
            // the launch that is a *mode* rather than a state — the flag is on
            // the command line, so it is decided before the window exists, which
            // is the only moment `eframe` can pass it to the platform. The
            // ordinary launch keeps its button, and so does a window the user
            // put away with the close button: that one was opened deliberately,
            // and the button is a second way back to it.
            //
            // `ViewportBuilder::with_taskbar` reaches `winit`'s
            // `with_skip_taskbar`, which apps read as `WS_EX_TOOLWINDOW`. It is
            // a creation-time attribute; `egui` has no viewport command for it,
            // so it cannot be changed once the window is up.
            .with_taskbar(!minimized),
        ..eframe::NativeOptions::default()
    };

    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(move |cc| {
            // The palette is installed on the context before the first frame,
            // so that the first frame a user sees is already the product's
            // colours rather than one frame of egui's defaults.
            theme::apply(&cc.egui_ctx);
            // Before the first frame, so that a click during start-up has
            // somewhere to be delivered, and because the answer decides whether
            // the window may hide itself at all — see `crate::tray`. This call
            // blocks for as long as the shell takes to answer, which is
            // milliseconds when it answers at all and five seconds when it does
            // not; it is spent before the first frame is drawn.
            app.set_tray(tray::Tray::start(cc.egui_ctx.clone(), tooltip()));
            app.launched_hidden(minimized);
            Ok(Box::new(app))
        }),
    )
}

/// What hovering the notification-area icon says.
///
/// The product's name and nothing else. A tooltip is one line shown while the
/// pointer is over a 16-pixel square, and a sentence there is a sentence nobody
/// finishes reading; anything that has to be said at length belongs in the
/// window, which the icon opens.
fn tooltip() -> String {
    WINDOW_TITLE.to_owned()
}

/// What the taskbar and the title bar call this program.
pub const WINDOW_TITLE: &str = "Wenle AV";

/// Send the log to stderr.
///
/// The same policy the console uses, so that a user who runs the console to
/// diagnose the window sees the same lines from the same engine. `RUST_LOG`
/// overrides it; the default is deliberately quiet, because a window whose
/// stderr is full of per-file lines is a window that has made the log useless
/// for the one thing it is for, which is saying why something did not work.
fn init_logging() {
    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("wenle_gui=info,av_scan=warn,av_rules=warn"),
    );
    builder.format_timestamp_secs();
    // `try_init` rather than `init`: a second call in the same process — which
    // only a test harness makes — would panic, and a logger that is already
    // installed is not a reason to take the program down.
    let _ = builder.try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The argument surface, which is small and is tested anyway: it is the
    /// only part of this file a test can reach, and the flag it carries decides
    /// which vault the window is looking at.
    ///
    /// `resolve_paths` itself is not tested here. It reads the running
    /// executable's path, so a test would be asserting where the test binary
    /// happens to live; what can be tested is that the flag arrives, and that
    /// is what these do.
    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("wenle-gui").chain(args.iter().copied()))
    }

    #[test]
    fn a_window_with_no_arguments_uses_the_installed_data_directory() {
        let args = parse(&[]).unwrap();
        assert_eq!(args.data_dir, None);
    }

    #[test]
    fn the_data_directory_is_taken_exactly_as_given() {
        let args = parse(&["--data-dir", r"D:\portable\data"]).unwrap();
        assert_eq!(
            args.data_dir.as_deref(),
            Some(Path::new(r"D:\portable\data"))
        );
    }

    #[test]
    fn an_unknown_argument_is_refused_rather_than_ignored() {
        // The failure mode this prevents is a user typing `--data-dir=...`
        // misspelled, getting a window that opens on the *installed* directory,
        // and concluding the flag does not work. Clap exits non-zero and says
        // what it did not understand.
        let error = parse(&["--data-dri", "x"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn the_minimized_flag_is_off_unless_it_is_asked_for() {
        // A window a user double-clicks has no arguments and must open, so the
        // default is the one that shows something.
        assert!(!parse(&[]).unwrap().minimized);
        assert!(parse(&["--minimized"]).unwrap().minimized);
    }

    #[test]
    fn the_flag_is_spelled_the_way_the_startup_entry_writes_it() {
        // Two crates, one string. `av-integration` formats this argument into
        // the `Run` value Windows executes at sign-in and this parser is what
        // reads it; a rename on either side would be a sign-in that opens a
        // window every time, which is the opposite of what the setting is for.
        let entry = av_integration::startup::MINIMIZED_FLAG;
        assert!(
            parse(&[entry]).expect("the startup entry's own flag must parse").minimized,
            "{entry:?} is written into the Run value and is not understood here"
        );
    }

    #[test]
    fn the_version_is_the_workspace_version() {
        // `--version` is answered by clap from the crate version, and a window
        // whose version disagreed with the console's would make a bug report
        // ambiguous about which build it came from.
        let error = parse(&["--version"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
    }
}
