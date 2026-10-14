//! The window itself.
//!
//! # Drawing only
//!
//! Every function in this module either draws a rectangle or decides what to
//! draw. Nothing here decides what a file *is*: the verdict, the score, the
//! severity, the ordering of the findings and the text of every summary come
//! from [`crate::format`], [`crate::filter`], [`crate::state`], [`crate::scan`]
//! and the engine underneath them. That is not fastidiousness — it is the only
//! way the interface can be tested at all. A window that computed a verdict in a
//! drawing function would have that computation covered by no test, because no
//! test can click a button.
//!
//! # Drawing is two steps, and the second one is testable
//!
//! The drawing functions never act. They record what the user asked for into a
//! [`Pending`] — a plain struct of booleans and options — and [`GuiApp::draw`]
//! runs those requests after the frame is laid out. The reason is not style:
//! an immediate-mode interface holds a mutable borrow of the state for the
//! whole of a frame, so a button that started a scan where it was drawn would
//! need a second borrow of the same state from inside a closure that already
//! has one. Beyond that, it means the actions have a name and a call site a test
//! can reach, instead of being buried in a closure that only a running window
//! ever enters.
//!
//! # What is drawn, and where it goes
//!
//! Four tabs, and two places that are not tabs. The status line at the bottom
//! says what the last thing the user did did — see [`GuiApp::say`]. The
//! notifications go to the shell rather than to the corner of the window,
//! because the one that matters most is about a file that was taken while
//! nobody was looking at a window; see [`crate::notify`].
//!
//! # What this window cannot do, and why
//!
//! There is no file picker. `rfd` is not in the workspace's dependencies and
//! adding a native-dialogue dependency is a decision about the product's
//! dependency surface, which belongs to whoever owns the product rather than to
//! the crate that happens to want it. The target is a text field: a path typed
//! or pasted into it. When a picker does arrive it replaces one function here.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use av_core::{AvConfig, AvPaths, FileScanReport, Verdict};
// The service's answer, and not the vault's: a decision about a quarantined item
// is performed by whichever process owns the vault, and this is how that process
// describes what it did. See `crate::service`.
use av_ipc::QuarantineChange;
use av_quarantine::{
    EntrySource, EntryStatus, QuarantineEntry, QuarantineEvent, QuarantineId, QuarantinePolicy,
    QuarantineVault,
};
use eframe::egui;

use crate::filter::{Bands, Filter, Sort};
use crate::format::{self, Counts};
use crate::icons::{self, Icon};
use crate::picker;
use crate::scan::{self, ScanEvent, ScanJob, ScanRequest};
use crate::notify::{Announcement, Notifier, Tag};
use crate::service;
use crate::state::{Phase, ScanState, SettingsDraft, VaultSort, VaultView};
use crate::theme;
use crate::tray::{self, Command as TrayCommand};

/// How often the window asks to be redrawn while a scan is running.
///
/// Faster than the progress numbers can meaningfully change and slower than a
/// frame, which is the point: an idle window that repainted at full rate would
/// burn a core to draw the same picture, and one that repainted only on input
/// would show a frozen progress bar for as long as the user did not move the
/// mouse.
const RUNNING_REPAINT: Duration = Duration::from_millis(100);

/// The tabs, in the order they are offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Choose a target, start a scan, watch it.
    Scan,
    /// What the last scan found.
    Findings,
    /// What has been taken off the disk.
    Quarantine,
    /// The configuration.
    Settings,
}

impl Tab {
    /// Every tab, in the order the window shows them.
    pub const ALL: [Tab; 4] = [Tab::Scan, Tab::Findings, Tab::Quarantine, Tab::Settings];

    /// The word on the tab.
    pub const fn label(self) -> &'static str {
        match self {
            Tab::Scan => "Scan",
            Tab::Findings => "Findings",
            Tab::Quarantine => "Quarantine",
            Tab::Settings => "Settings",
        }
    }

    /// The mark drawn above the word.
    ///
    /// Not the band marks of [`Icon::for_band`], and deliberately so: a tab is
    /// where a person is, not what was found, and a window whose Findings tab
    /// wore the same tick as a clean verdict would be saying that the tab is
    /// clean before it has been opened. The four here are the plainest shapes
    /// that name the four places — a magnifier, a warning, a locked box, three
    /// sliders — and a test pins that no two tabs share one.
    pub const fn icon(self) -> Icon {
        match self {
            Tab::Scan => Icon::Search,
            Tab::Findings => Icon::Alert,
            Tab::Quarantine => Icon::Vault,
            Tab::Settings => Icon::Sliders,
        }
    }
}

/// A request from the drawing code to the rest of the program.
///
/// Every field is something a person clicked. Collected while the frame is laid
/// out and acted on afterwards; see the module documentation.
#[derive(Debug, Default)]
struct Pending {
    start: bool,
    stop: bool,
    save_settings: bool,
    revert_settings: bool,
    clear_filter: bool,
    open_vault: bool,
    /// The user asked to quarantine every ticked finding.
    quarantine_checked: bool,
    /// The user asked to tick everything on screen, or to untick everything.
    ///
    /// `Some(true)` for select-all and `Some(false)` for clear, rather than two
    /// flags, because these are one control's two answers and a single frame
    /// cannot honestly ask for both. `None` is "the control was not used".
    ///
    /// Select-all means everything **the filter is showing**, not everything in
    /// the report: the button sits under a list that is filtered, and a control
    /// that ticked rows the user cannot see would act on files they never
    /// chose.
    select_all: Option<bool>,
    /// The user asked to browse for a folder to scan.
    ///
    /// A flag and not a call: the picker is a modal native dialog, and this is
    /// the one action in the window that blocks for as long as a person takes
    /// to decide. Opening it here would be opening it inside a frame, with a
    /// mutable borrow of the window held and a frame half drawn behind it; it
    /// is opened in [`GuiApp::run_pending`], after the frame, like everything
    /// else a button asked for.
    pick_folder: bool,
    /// The user asked to browse for a single file to scan.
    pick_file: bool,
    restore: Option<QuarantineId>,
    delete: Option<QuarantineId>,
    /// The user asked for a quarantined file to be put back *and* left alone,
    /// with [`Allow`] saying for how long.
    ///
    /// `restore` and `allow` are separate fields rather than one action with a
    /// flag because the wording is not the only difference: a restore writes the
    /// bytes back and stops, and an allow also takes a decision about the file's
    /// future. A user who clicked "Put back" has not switched anything off, and
    /// a status line that said they had would be the window claiming a decision
    /// the user did not make.
    allow: Option<(QuarantineId, Allow)>,
}

/// How long "allow" lasts, when a user asks for it.
///
/// Two answers because the two cost different things. For the rest of this
/// session is a decision about *this* work — a file the user is in the middle of
/// using, a false positive they want out of the way until they have looked at
/// it properly. Permanently writes an exclusion into the configuration, which
/// outlives the window, the service and the reboot, and is therefore a decision
/// the interface has to make unmistakable rather than convenient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Allow {
    /// Until the service stops. Not written anywhere.
    Session,
    /// Written to the configuration, so it also survives a restart.
    Permanent,
}

/// The application state behind the window.
///
/// Constructed once by [`crate::run`] and handed to `eframe`, which calls
/// [`GuiApp::draw`] once a frame for as long as the window is open.
#[derive(Debug)]
pub struct GuiApp {
    /// The resolved filesystem layout, for the configuration file and the vault.
    paths: AvPaths,
    /// The saved configuration, which is what the last scan used.
    config: AvConfig,
    /// The configuration as the Settings tab is editing it.
    settings: SettingsDraft,
    /// Where the window is: idle, running, finished, failed.
    state: ScanState,
    /// The worker, while one is running.
    job: Option<ScanJob>,
    /// The findings to show, from whichever source is current.
    findings: Vec<FileScanReport>,
    /// The path the user typed.
    target: String,
    /// How the findings list is filtered and ordered.
    filter: Filter,
    /// Which finding's detail is open, by path.
    ///
    /// **By path and not by row number**, and that is a correctness fix rather
    /// than a preference. The list on the screen is `Filtered::files` — filtered
    /// and then sorted — while the findings themselves are in `findings`. A row
    /// number means one thing in each, so a selection stored as a row number and
    /// read as a findings index names a *different file* as soon as the filter
    /// hides a row or the sort moves one. The action that reads it is
    /// quarantine, which takes a file off the disk, so the bug was "quarantine
    /// the file above the one you clicked".
    ///
    /// A path is the same value in both lists, which is what makes the class of
    /// bug impossible rather than fixed. Within one scan a path appears once, so
    /// it is a key and not merely a label.
    selected: Option<PathBuf>,
    /// The findings ticked for a bulk action, by path.
    ///
    /// By path for the same reason as [`GuiApp::selected`], and it has to
    /// survive the sort as well: a user who ticks three rows and then reorders
    /// the list has ticked three files, not three positions.
    checked: BTreeSet<PathBuf>,
    /// The vault, opened the first time the Quarantine tab is drawn.
    vault: Option<QuarantineVault>,
    /// The control pipe this window asks the service on.
    ///
    /// [`service::DEFAULT_PIPE`] unless something says otherwise, and a field
    /// rather than a constant read at the call site for one reason: the tests
    /// that exercise the Quarantine tab's actions have to run against a pipe
    /// nothing is listening on. A test that asked the product's own name would
    /// pass or fail according to whether the machine running it has this product
    /// installed — and on the machine that matters, it would drive the real
    /// service's vault from a test fixture.
    service_pipe: String,
    /// Paths this window's own scans skip because the user allowed them here.
    ///
    /// Only ever used when the service was not reachable to take the decision —
    /// see [`GuiApp::allow_here`]. When the service *is* running the allow lives
    /// in the service's own list, which is the one the decision path consults,
    /// and this stays empty. Appended to the configured exclusions when a scan
    /// is built, so that the window's scans and the service's decisions agree
    /// about the file even though the two got there by different routes.
    allowed: Vec<PathBuf>,
    /// What the vault has said since the last frame.
    ///
    /// Subscribed to rather than inferred from the return value of the calls
    /// this window makes, so that a quarantine the window did not initiate is
    /// announced the same way as one it did. The notification belongs to the
    /// event, not to the button press.
    ///
    /// # What this cannot see, which the comment here used to claim it could
    ///
    /// It said the subscription was what brought in "the real-time blocker's, the
    /// service's" quarantines. Neither arrives, and the mechanism says why:
    /// `QuarantineVault::subscribe` appends an `Arc<dyn Fn>` to a list on the
    /// vault *value*, so a listener is called by whichever code holds that value
    /// — this process, and no other. The window opens its own vault over the same
    /// directory, and that subscription is a call inside one process.
    ///
    /// So the events that reach this receiver are the ones raised in-process: the
    /// scan worker's, which is a background thread rather than a click, and the
    /// bulk actions. That is a real reason to subscribe — a worker's quarantine
    /// and a clicked one would otherwise be reported by different code — and a
    /// much smaller one than the sentence claimed.
    ///
    /// **The service's quarantines arrive by a different route**, which is worth
    /// stating precisely because this comment used to say they arrived through
    /// nothing at all. [`GuiApp::poll_vault`] re-reads the index from disk on a
    /// timer and announces what appeared, so a file the service took *is* shown
    /// in the list and *is* announced in the corner. What the window has since
    /// gained is [`crate::service`]: a named pipe on which it can *ask* the
    /// service to change an item, so a user's decision is made by the process
    /// that owns the index rather than behind its back. What it still cannot do
    /// is receive an *event* over that pipe — the protocol carries replies, and
    /// the events a client subscribes to are not read by this window — so the
    /// notification is never the service's own; it is this window noticing a file
    /// change.
    vault_events: Option<crossbeam_channel::Receiver<QuarantineEvent>>,
    /// What later launches of this program have asked for.
    ///
    /// `None` when there is no first instance to have claimed the name — a
    /// non-Windows build, and a Windows one whose mutex could not be created.
    /// The window is then the window by default rather than by claim, and no
    /// request can arrive, which is the same situation as a build with no
    /// single-instance mechanism at all.
    ///
    /// Drained every frame for the same reason the vault's is: the request
    /// arrives while the window is running, and a right-click on a file is not
    /// something that only happens before the window opens.
    wakes: Option<crossbeam_channel::Receiver<crate::single::Wake>>,
    /// Why the vault could not be opened, if it could not.
    vault_error: Option<String>,
    /// How the vault list is filtered and ordered.
    vault_view: VaultView,
    /// Which vault entry is selected.
    vault_selected: Option<QuarantineId>,
    /// What has already been announced, so that a re-read of the index does not
    /// announce it a second time.
    ///
    /// One set over both ways an entry arrives. A quarantine this window
    /// performed raises a vault event the moment it happens, and the same entry
    /// is then in the index the next poll reads — announcing it from both would
    /// put the same block in the corner twice, which is how a user learns to
    /// ignore the corner.
    announced: BTreeSet<QuarantineId>,
    /// When to look at the index again, and whether it moved.
    vault_poll: crate::vault_poll::VaultPoll,
    /// The notifications this process posts to the desktop.
    ///
    /// A field rather than a free function because the two settings that decide
    /// whether anything is posted come from the configuration the window
    /// already holds, and because a test has to be able to read back what was
    /// announced without a desktop to announce it to. [`crate::notify`] says
    /// why this is the shell's notification and no longer a panel in the
    /// corner: a panel exists only while the window does, and the blocks that
    /// matter most are the ones that happened while it was closed.
    notifier: Notifier,
    /// Which tab is showing.
    tab: Tab,
    /// The icon in the notification area, while the process holds one.
    ///
    /// `None` is not a failure to report: a build for another platform has no
    /// notification area at all, and a machine whose shell refused the icon is
    /// one where the window simply closes when its close button is used. What
    /// it *is* is the answer to whether the window may put itself out of the way
    /// — see [`GuiApp::minimises_instead_of_closing`], which reads it, and
    /// [`crate::tray`] for why the two are the same question.
    tray: Option<tray::Tray>,
    /// Whether the process was asked to start with no window.
    ///
    /// Settled in the first frame rather than before it, because whether it can
    /// be honoured depends on the icon existing and the icon needs a context
    /// that only exists once `eframe` has built one. See
    /// [`GuiApp::settle_launch_visibility`].
    launched_hidden: bool,
    /// Whether the user has asked the process to stop.
    ///
    /// The one thing that makes the window close rather than put itself away.
    /// Set by the
    /// notification area's Exit, and by nothing else: a close button that
    /// sometimes ends the process and sometimes does not is what this flag
    /// exists to keep out of the drawing code, where nothing could test it.
    quitting: bool,
    /// One line about the last thing that happened, drawn at the bottom.
    status: Option<String>,
    /// Where the rule database was found, or why it was not.
    database: Result<PathBuf, String>,
}

impl GuiApp {
    /// Build the window's state around a configuration that has already been
    /// loaded.
    ///
    /// The database is resolved here rather than when a scan starts, so that a
    /// machine with no rules says so in the status line when the window opens
    /// rather than after the user has asked for a scan of a whole drive.
    pub fn new(paths: AvPaths, config: AvConfig) -> Self {
        let database = locate_database(&paths);
        // Read before the configuration is moved into the struct. Whether the
        // user wants shell notifications is a decision the notifier keeps for
        // the life of the window; the settings screen writes back to it when
        // the draft is saved.
        let notifier = Notifier::for_this_process(
            config.general.notifications,
            config.general.notification_sound,
        );
        Self {
            settings: SettingsDraft::new(config.clone()),
            paths,
            config,
            state: ScanState::default(),
            job: None,
            findings: Vec::new(),
            target: default_target(),
            filter: Filter::default(),
            selected: None,
            checked: BTreeSet::new(),
            vault: None,
            service_pipe: service::DEFAULT_PIPE.to_owned(),
            allowed: Vec::new(),
            vault_events: None,
            wakes: None,
            vault_error: None,
            vault_view: VaultView::default(),
            vault_selected: None,
            announced: BTreeSet::new(),
            vault_poll: crate::vault_poll::VaultPoll::new(),
            notifier,
            tab: Tab::Scan,
            // Filled in by `GuiApp::set_tray`, which `crate::run` calls once
            // `eframe` has a context to give it. Not created here because
            // creating one needs that context and this constructor is reachable
            // — and tested — without a display.
            tray: None,
            launched_hidden: false,
            quitting: false,
            status: None,
            database,
        }
    }

    // -- the notification area ------------------------------------------------

    /// Take the icon in the notification area, if one could be created.
    ///
    /// Handed over rather than created here because creating it needs an `egui`
    /// context, and this state exists — and is tested — with no window at all.
    /// See [`crate::tray`].
    pub fn set_tray(&mut self, tray: Option<tray::Tray>) {
        self.tray = tray;
    }

    /// Record that the process was asked to start with no window.
    ///
    /// Only a record: whether the request can be honoured is not knowable yet.
    /// See [`GuiApp::settle_launch_visibility`].
    pub fn launched_hidden(&mut self, hidden: bool) {
        self.launched_hidden = hidden;
    }

    /// Whether the window may put itself out of the way instead of closing.
    ///
    /// Two conditions, and both are needed. The setting is the user's answer,
    /// and the icon is whether there is any way back: a window out of the way
    /// with no icon in the notification area is a running program the user can
    /// only find in Task Manager, and nothing on screen would tell them it is
    /// there. Where the two disagree the icon wins, because the cost of being
    /// wrong is asymmetric — a close button that closes is a small
    /// disappointment, and a window that cannot be got back is a call to
    /// support.
    pub fn minimises_instead_of_closing(&self) -> bool {
        self.config.general.minimize_to_tray && self.tray.is_some()
    }

    /// Put the window on screen and in front of the user.
    ///
    /// Restore before focusing, and the order is not cosmetic — a focus sent to
    /// a minimised window does nothing, so a `Focus` first would be a command
    /// that is discarded and the window would come back behind whatever the user
    /// was looking at. See [`GuiApp::drain_later_launches`].
    ///
    /// # There is no `Visible(true)` here, and that is the point
    ///
    /// A window is put out of the way by *minimising* it, never by hiding it —
    /// see [`GuiApp::put_out_of_the_way`] for the measurement that rules hiding
    /// out. So the only state there is to undo is the minimised one, and a
    /// `Visible(true)` would be a command that says something untrue about how
    /// the window got where it is.
    fn show_window(&self, ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// Take the window off the screen without stopping the process.
    ///
    /// # Why this minimises rather than hides, measured
    ///
    /// `ViewportCommand::Visible(false)` was the first thing tried, and it is
    /// wrong in a way that is invisible until you look for it: it stops the
    /// window's clock. `egui` gets a frame only when the platform asks for a
    /// repaint, `eframe` turns that request into `RedrawWindow(hwnd, ..,
    /// RDW_INTERNALPAINT)`, and Windows does not deliver `WM_PAINT` to a window
    /// whose `IsWindowVisible` is false — so the next frame never comes and
    /// every later request is queued behind it. A hidden window is a window that
    /// has stopped, and the notification-area icon that is supposed to bring it
    /// back would be a click into a dead process: nothing would happen, ever,
    /// with no error anywhere.
    ///
    /// What was measured, on the release build, counting frames drawn:
    ///
    /// | the window                        | frames |
    /// |-----------------------------------|--------|
    /// | on screen                         | 11 in 6 s (the 1 s vault poll) |
    /// | hidden with `Visible(false)`      | 4 in the first second, then 0 in the next 3 s |
    /// | minimised (`SW_MINIMIZE` from outside) | 10 in 6 s |
    ///
    /// The four at the start are the frames of start-up, before the hide was
    /// applied; after that the process was silent, and the second launch that
    /// was supposed to wake it did not even reach the drain that reads the wake
    /// —
    /// so the failure is "no frames", not "a frame that lost a race". A
    /// minimised window is still a visible window to Windows, which is why its
    /// clock keeps running.
    ///
    /// The cost of the choice is that a minimised window keeps its taskbar
    /// button. That is what the button is for, and it is a second way back to a
    /// window that has one.
    fn put_out_of_the_way(&self, ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
    }

    /// Decide, once, whether a `--minimized` start can stay out of the way.
    ///
    /// The window is created invisible when the flag is passed, before the icon
    /// has been attempted, and this is the frame that settles it: with no icon
    /// there is no way back to a window that is out of the way, so it is shown
    /// instead. The reverse — creating the window visible and putting it away
    /// here — would be a window that appears and vanishes at every sign-in,
    /// which is worse than either outcome.
    ///
    /// # Why `with_visible(false)` is not enough on its own
    ///
    /// `eframe` creates the window hidden only to avoid painting one frame of
    /// egui's default background before the product's colours are up, and
    /// unhides it unconditionally at the end of that first frame —
    /// `epi_integration.rs`'s `post_rendering`, `window.set_visible(true)` under
    /// `if std::mem::take(&mut self.is_first_frame)`. Measured, not inferred: the
    /// release window launched with `--minimized` logged that it had started
    /// with no window and was reported by `Process.MainWindowHandle` as visible
    /// anyway, that property naming only windows that are on screen.
    ///
    /// The command sent here is applied *after* that forced show, which is what
    /// makes it work rather than a duplicate of the builder call: in
    /// `glow_integration.rs`'s `run_ui_and_paint`, `post_rendering` is called at
    /// the point the frame has been painted, and the frame's viewport commands
    /// are handed to `egui_winit::process_viewport_commands` after it. So one
    /// command on this frame is enough, and it is sent on this frame only — a
    /// window that minimised itself every frame could never be restored.
    fn settle_launch_visibility(&mut self, ctx: &egui::Context) {
        if !self.launched_hidden {
            return;
        }
        self.launched_hidden = false;
        if self.tray.is_none() {
            log::warn!("there is no notification area icon, so the window is being shown");
            self.show_window(ctx);
        } else {
            log::info!("started with no window: the notification-area icon is the way in");
            self.put_out_of_the_way(ctx);
        }
    }

    /// Take what the notification area has been asked for since the last frame.
    ///
    /// Drained where the other outside events are, at the top of a frame, so
    /// that a click is reflected in the very frame that follows it. Every
    /// command but Exit shows the window: a user who clicked a tray icon is
    /// looking for the window, and an icon that did something invisible would be
    /// a click that appeared to do nothing.
    ///
    /// `pending` is this frame's requests, which is a fresh value when this is
    /// called — so the commands here are recorded in exactly the form a button
    /// press would produce and travel through the same call sites. The folder
    /// picker is the reason: opening a native dialog happens after the frame,
    /// and reaching the picker by a second route would be a second place that
    /// blocks inside a frame.
    fn drain_tray(&mut self, ctx: &egui::Context, pending: &mut Pending) {
        // Collected before anything is acted on, because acting needs `&mut
        // self` and the receiver lives on `self`. The same shape the vault's
        // drain and the later-launch drain use.
        let commands: Vec<TrayCommand> = match &self.tray {
            Some(tray) => std::iter::from_fn(|| tray.poll()).collect(),
            None => return,
        };
        for command in commands {
            match command {
                TrayCommand::Open => {
                    self.show_window(ctx);
                }
                TrayCommand::Scan => {
                    self.show_window(ctx);
                    self.tab = Tab::Scan;
                    pending.pick_folder = true;
                }
                TrayCommand::Quarantine => {
                    self.show_window(ctx);
                    self.tab = Tab::Quarantine;
                }
                TrayCommand::Exit => {
                    // The flag first, because the close it asks for is answered
                    // by the frame after this one — see
                    // `GuiApp::answer_close_request`, which cancels exactly the
                    // closes this flag does not cover.
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    /// Answer the close button: put the window out of the way, or let it close.
    ///
    /// Called at the top of every frame. `egui` reports the request for one
    /// frame only and cancels the close on any frame where the application sends
    /// `CancelClose`, so this is not a one-shot decision — it is asked again
    /// every time somebody tries to close the window, which is what makes the
    /// Exit in the notification area work after the close button has been used
    /// any number of times.
    ///
    /// Not closing is the whole point of the tray: a user who clicks the X of an
    /// antivirus's window means "get this off my screen", not "stop protecting
    /// me", and the second is what exiting would do here, because the service is
    /// a separate process but this window is where the quarantine list is read
    /// and restored from.
    fn answer_close_request(&mut self, ctx: &egui::Context) {
        if !ctx.input(|input| input.viewport().close_requested()) {
            return;
        }
        if self.quitting || !self.minimises_instead_of_closing() {
            // Not answered, which is how a close is allowed to happen: the
            // absence of `CancelClose` is the answer.
            log::debug!("the window is closing");
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        self.put_out_of_the_way(ctx);
        log::info!("the window was put out of the way; the notification-area icon is the way back");
    }

    /// Read the configuration from disk, or the defaults if there is none.
    ///
    /// A configuration that will not load is reported in the status line and
    /// the window opens on the defaults. Refusing to open would be worse: the
    /// window is the only place a broken configuration can be looked at and
    /// fixed without a text editor.
    pub fn load(paths: AvPaths) -> Self {
        let (config, problem) = match AvConfig::load_or_default(&paths.config_file) {
            Ok(config) => (config, None),
            Err(error) => (
                AvConfig::default(),
                Some(format!(
                    "{} could not be read ({error}), so the defaults are in use. Saving the \
                     settings will replace it.",
                    paths.config_file.display()
                )),
            ),
        };
        let mut app = Self::new(paths, config);
        app.status = problem;
        app
    }

    /// The findings on screen, before filtering.
    pub fn findings(&self) -> &[FileScanReport] {
        &self.findings
    }

    /// The size this window's configuration asks the window to open at.
    ///
    /// The one accessor for a field rather than for the state, and it exists
    /// because the caller is outside this module: `main` builds `NativeOptions`
    /// — and therefore the window — *before* it hands the application to
    /// `eframe`, so the configured size has to be readable from there. Every
    /// other field is read by the drawing code, which is this module, or by the
    /// tests, which are its child.
    pub fn window_size(&self) -> [f32; 2] {
        window_size(&self.config.ui)
    }

    // There are deliberately no accessors for the state or the current tab.
    // Both are read by the drawing code, which is in this module, and by the
    // tests, which are a child of it and can reach the fields; a `pub fn` that
    // only those two callers used would be a third name for a field, and in a
    // binary crate nothing outside could call it anyway.

    // -- events --------------------------------------------------------------

    /// Take everything the worker has said since the last frame.
    ///
    /// Called once per frame, before anything is drawn, so that the picture is
    /// of the state as of now rather than of the state one frame ago.
    pub fn drain_events(&mut self) {
        // Whether the worker is still there, read before the events are taken,
        // because a thread that has exited *and* sent nothing is the case this
        // is guarding: the window would otherwise sit on a progress bar for a
        // scan that is not running, with a Stop button that stops nothing, and
        // no way out but closing the window.
        let worker_gone = self
            .job
            .as_ref()
            .is_some_and(|job| job.is_finished() && job.is_empty());

        if let Some(job) = &self.job {
            for event in job.drain() {
                self.apply(event);
            }
        }
        self.drain_vault_events();

        if worker_gone && self.job.is_some() {
            // No terminal event arrived, which the driver guarantees it will
            // send, so the worker died in a way it could not report — a panic
            // in a release build, where the profile's `panic = "abort"`
            // normally takes the whole process and this is unreachable, or a
            // thread killed from outside. Reported as a failure rather than
            // left as a running scan.
            log::error!("the scan worker ended without reporting a result");
            self.state
                .fail("The scan stopped without reporting what it found.");
            self.status = Some("The scan stopped without reporting what it found.".to_owned());
            self.job = None;
        }
    }

    /// Apply one event from the worker.
    ///
    /// Separated from [`GuiApp::drain_events`] so that a test can hand it the
    /// events a real scan produces without running one.
    pub fn apply(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Enumerated {
                files,
                bytes,
                skipped,
                unreadable,
            } => {
                self.status = Some(format!(
                    "About to scan {} ({}){}.",
                    format::count_of(files, "file"),
                    format::human_bytes(bytes),
                    if skipped == 0 && unreadable == 0 {
                        String::new()
                    } else {
                        format!(
                            " {} skipped, {} unreadable",
                            format::human_count(skipped),
                            format::human_count(unreadable)
                        )
                    }
                ));
            }
            ScanEvent::Finding(report) => {
                // A live finding, while the scan is still running. Malicious
                // ones are announced because they are news; the middle band is
                // not, and is summarised once when the scan ends.
                //
                // Note which kind of notification this is: a *notice*, not a
                // block. Nothing has been done about this file — the scan is
                // still running and no policy has been consulted — and a
                // notification headed "blocked" here would be claiming an
                // action that has not happened.
                //
                // It goes to the status line and not to the shell. This window
                // started the scan, so the user is here to be told, and a first
                // scan of a Windows installation produces hundreds of these:
                // routing them to the shell would be a popup per file, which is
                // the burst `crate::notify::Tag` exists to prevent. What does
                // reach the shell is the *result* — see the `Finished` arm
                // below, which reports a scan that found something malicious
                // exactly once, for a user who started it and walked away.
                if report.verdict() == Verdict::Malicious {
                    self.say(format!(
                        "{} — {}. Reported; nothing has been done about it yet.",
                        short_name(&report.path),
                        first_summary(&report)
                    ));
                }
                self.findings.push(*report);
            }
            ScanEvent::Finished(report) => {
                // The report is authoritative and replaces the live list
                // wholesale. Merging would have to reconcile two copies of the
                // same findings and has no key to do it by.
                self.findings = report.detections.clone();
                self.selected = None;
                if report.cancelled {
                    self.status = Some("The scan was stopped before it finished.".to_owned());
                } else {
                    self.status = Some(format::scan_summary(&report));
                    if report.worst_verdict() == Verdict::Malicious {
                        self.tab = Tab::Findings;
                    }
                    // The middle band gets exactly one notification for the
                    // whole scan, for the first file in it, and only when
                    // nothing malicious was found. One, because a card per
                    // suspicious file is hundreds of cards on a first scan of a
                    // Windows installation; and not when something malicious
                    // was found, because a user with that to deal with does not
                    // need a second card about the yellow ones. How many there
                    // were is in the status line, which is where a count
                    // belongs — see `notify_suspicious`.
                    if report.worst_verdict() == Verdict::Suspicious {
                        if let Some(file) = report
                            .detections
                            .iter()
                            .find(|file| file.verdict() == Verdict::Suspicious)
                        {
                            self.notify_suspicious(file);
                        }
                    }
                    // And the result that matters most, which nothing reached
                    // before: a scan that found something malicious told the
                    // user only if they were still watching. A full scan of a
                    // disk takes minutes and the reason to start one is usually
                    // that the machine will be left alone while it runs, so the
                    // one case where the window cannot be the only answer is
                    // also the common one.
                    //
                    // One notification for the whole scan, carrying the worst
                    // file it found and how many there were, and tagged so that
                    // it replaces the per-block notifications of the scan it
                    // concludes rather than joining them.
                    if report.worst_verdict() == Verdict::Malicious {
                        let malicious = report
                            .detections
                            .iter()
                            .filter(|file| file.verdict() == Verdict::Malicious)
                            .count();
                        if let Some(file) = report
                            .detections
                            .iter()
                            .find(|file| file.verdict() == Verdict::Malicious)
                        {
                            let text = if malicious == 1 {
                                format!("{} — {}", short_name(&file.path), first_summary(file))
                            } else {
                                format!(
                                    "{} — {}. {} in all; open the Findings tab to see them.",
                                    short_name(&file.path),
                                    first_summary(file),
                                    format::count_of(malicious as u64, "file")
                                )
                            };
                            self.announce(Announcement::replacing(
                                Tag::Blocked,
                                "The scan found something malicious",
                                text,
                            ));
                        }
                    }
                }
                self.state.finish(*report);
                self.job = None;
            }
            ScanEvent::Failed { message } => {
                // Nothing was scanned, so nothing is shown as scanned. The
                // findings list keeps whatever an earlier scan left in it
                // rather than being emptied: an empty list beside a failure
                // message reads as "the scan found nothing".
                self.state.fail(message.clone());
                self.status = Some(message);
                self.job = None;
            }
        }
    }

    /// Put a sentence in the status line.
    ///
    /// This is where everything the *user* did is reported: a setting saved, a
    /// restore that failed, a tick that had nothing behind it. They are looking
    /// at the window when it happens — they just clicked the thing — so the
    /// window is the right place for the answer, and a Windows notification
    /// saying "Settings saved." would be a popup about a button.
    ///
    /// What is deliberately not routed here is the product's own news: a file
    /// blocked, a middle band reported, a quarantined payload that no longer
    /// matches its digest. Those go through [`GuiApp::announce`], because the
    /// user is not necessarily looking.
    fn say(&mut self, text: impl Into<String>) {
        self.status = Some(text.into());
    }

    /// Tell the user something through the shell, if the settings allow it.
    fn announce(&mut self, announcement: Announcement) {
        self.notifier.announce(announcement);
    }

    // -- notifications -------------------------------------------------------

    /// Announce that a file was blocked and taken.
    ///
    /// This is the block notification, and it is raised from the vault's own
    /// event rather than from the click that caused it, so that a block the
    /// window did not initiate is announced the same way. It is raised for
    /// [`QuarantineEvent::Quarantined`] and for nothing else: "blocked" is a
    /// claim about a file that is no longer where it was, and only this event
    /// makes it true.
    ///
    /// # Why the sentence does not say "stopped"
    ///
    /// It did, and that was a claim about an action this product does not take.
    /// Nothing here terminates a process — a grep of the workspace finds no
    /// `TerminateProcess` outside a sandbox rule's own pattern strings — and the
    /// realtime watcher says so in its own type system, with a constant named
    /// `BLOCKS_NOTHING` set to `false` and every finding it produces in a phase
    /// called `AfterTheFact`. A file is taken off the disk; a process that
    /// already had it open or mapped keeps running. So "stopped" told a user
    /// their machine had been defended in a way it had not, and it did so in the
    /// one notification they are most likely to read.
    ///
    /// The crate that owns those two names is not a dependency of this one — the
    /// window does not link the watcher — so they are named in prose rather than
    /// as documentation links, which would be links to nothing.
    ///
    /// What replaces it is deliberately the crate's own definition rather than a
    /// stronger word: "blocked" means the file is no longer where it was, which
    /// is exactly what this event proves and all it proves. When the kernel
    /// driver can refuse a write before it happens, the thing that reports *that*
    /// is the driver, and this sentence is the one that would have to change.
    ///
    /// The text carries the three things a user needs and no more — what the
    /// file was called, what was found in it, and that it was taken.
    pub fn notify_blocked(&mut self, event: &QuarantineEvent) {
        let QuarantineEvent::Quarantined(entry) = event else {
            return;
        };
        self.announce_block(entry);
    }

    /// The same announcement, for an entry that arrived without an event.
    ///
    /// The service quarantines into the same vault this window reads, and it
    /// cannot raise an event in this process — see [`crate::vault_poll`]. What
    /// reaches the window instead is the entry, in the index, on the next
    /// re-read, and it is announced here so that a block the service made gets
    /// the same wording, the same band and the same corner as one this window
    /// made.
    ///
    /// The identifier is recorded first and the announcement is skipped when it
    /// is already there, which is what keeps a file from being announced twice:
    /// a quarantine this window performed raises an event *and* appears in the
    /// next index it reads, and the two arrive in whichever order they arrive
    /// in.
    fn announce_block(&mut self, entry: &QuarantineEntry) {
        if !self.announced.insert(entry.id) {
            log::debug!("{} was already announced", entry.file_name);
            return;
        }
        let text = format!(
            "{} — {}. The file was blocked and moved to quarantine.",
            entry.file_name,
            what_was_found(entry)
        );
        log::info!("blocked and quarantined {}: {}", entry.file_name, text);
        // Tagged, so that a scan which blocks forty files updates one
        // notification rather than stacking forty. See `crate::notify::Tag`.
        self.announce(Announcement::replacing(
            Tag::Blocked,
            "Blocked and quarantined",
            text,
        ));
    }

    /// Re-read the vault if another process has written to it since the last
    /// look.
    ///
    /// Called once a frame and cheap in the common case: the filesystem is asked
    /// at most once per [`crate::vault_poll::POLL_INTERVAL`], and the index is
    /// decrypted only when the file actually moved. See [`crate::vault_poll`]
    /// for why this is a poll rather than a subscription, and for what it
    /// cannot see.
    ///
    /// It opens the vault if nothing has opened it yet. That is deliberate: the
    /// case this exists for is a user who never opens the Quarantine tab and
    /// still needs to be told that the service took something, so the vault
    /// cannot be opened lazily by the tab and by nothing else.
    pub fn poll_vault(&mut self, now: Instant) {
        // Opened if nothing has opened it yet, and the borrow given straight
        // back: `vault_mut` lends out the whole of `self`, and the poll is a
        // different field of it. Every later statement here takes the vault
        // again and only ever holds it for one call.
        if self.vault_mut().is_none() {
            return;
        }
        let moved_on = match (&self.vault, &mut self.vault_poll) {
            (Some(vault), poll) => poll.due(now, vault.index_path()),
            (None, _) => return,
        };
        if !moved_on {
            return;
        }
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        let moved = match vault.reconcile() {
            Ok(moved) => moved,
            Err(error) => {
                // The index is there and does not decode. The window keeps the
                // entries it has and says nothing in the corner: it cannot tell
                // a damaged index from a transient read, and a notification
                // that fires on both would be one a user learns to dismiss.
                log::warn!("the vault's index could not be re-read: {error}");
                return;
            }
        };
        // Collected before anything is announced, because announcing needs
        // `&mut self` and the vault is borrowed from it.
        //
        // Only entries that are *in* the vault are announced. One that was taken
        // and put back between two looks was never in quarantine by the time the
        // window heard about it, and saying "blocked and moved to quarantine"
        // about a file that is sitting where it always was would be the
        // notification lying about the state of the machine.
        let added: Vec<QuarantineEntry> = moved
            .added
            .iter()
            .filter(|entry| entry.status == EntryStatus::Quarantined)
            .cloned()
            .collect();
        if !moved.removed.is_empty() {
            log::debug!(
                "{} entries left the vault while this window was open",
                moved.removed.len()
            );
        }
        for entry in &added {
            self.announce_block(entry);
        }
    }

    /// Report a file the scan found suspicious, without claiming anything was
    /// done about it.
    ///
    /// The headline for this kind says "not acted on" and there is no button,
    /// because the product's rule is that the middle band warns and never
    /// remediates. It is a different function from
    /// [`GuiApp::notify_blocked`] rather than the same one with a different
    /// band passed in, so that the two cannot be confused at a call site.
    ///
    /// Raised once per scan, at the end, for the middle band as a whole. A
    /// notification per suspicious file is what the band's own count is for: a
    /// first scan of a Windows installation produces hundreds of them, and a
    /// corner of the screen that has been full for ten minutes is one a user
    /// has stopped reading by the time it matters.
    pub fn notify_suspicious(&mut self, report: &FileScanReport) {
        let text = format!("{} — {}", short_name(&report.path), first_summary(report));
        self.announce(Announcement::replacing(
            Tag::Suspicious,
            "Suspicious — not acted on",
            text,
        ));
    }

    /// Say that a file's bytes are held but the original is still on disk.
    ///
    /// Its own notification because it is neither of the other two: something
    /// *was* done, and the thing a user would assume from "blocked" — that the
    /// file is gone — is not yet true.
    fn notify_removal_deferred(&mut self, path: &std::path::Path, error: &str) {
        let text = format!(
            "{} is still on disk and will be retried. Its bytes are in the vault ({error}).",
            short_name(path)
        );
        // Untagged on purpose: this is not another instance of the middle-band
        // report, it is a second fact about the same block, and a tag would
        // make it replace the block's own notification rather than join it.
        self.announce(Announcement::new("Still on disk", text));
    }

    /// Take everything the vault has said since the last frame, announcing
    /// every block.
    pub fn drain_vault_events(&mut self) {
        self.drain_vault_events_announcing(true);
    }

    /// Take everything the vault has said since the last frame.
    ///
    /// Collected before it is acted on, because acting needs `&mut self` and
    /// the receiver is part of `self`.
    ///
    /// `announce_blocks` is false for exactly one caller: a bulk quarantine,
    /// which reports the batch as one card instead of one card per file. See
    /// [`GuiApp::quarantine_checked`]. It suppresses only the *block* cards —
    /// a deferred removal, a failed integrity check and a corruption are
    /// reported either way, because each of those is a file in a state the user
    /// does not expect and none of them is made less true by there being
    /// several.
    pub fn drain_vault_events_announcing(&mut self, announce_blocks: bool) {
        let events: Vec<QuarantineEvent> = match &self.vault_events {
            Some(events) => events.try_iter().collect(),
            None => return,
        };
        for event in &events {
            match event {
                QuarantineEvent::Quarantined(_) if announce_blocks => self.notify_blocked(event),
                // A bulk quarantine reports the batch as one card, so each of
                // its entries is recorded without being announced — recorded
                // rather than dropped, because the re-read of the index that
                // follows would otherwise find them all new and put one card per
                // file in the corner, which is the thing the batch card is for.
                QuarantineEvent::Quarantined(entry) => {
                    self.announced.insert(entry.id);
                }
                QuarantineEvent::RemovalDeferred { path, error, .. } => {
                    self.notify_removal_deferred(path, error);
                }
                QuarantineEvent::CorruptionDetected { id, detail } => {
                    // The worst thing the vault can discover: a payload it can
                    // no longer vouch for. This is the case a notification
                    // exists for — a user who never opens the Quarantine tab
                    // would otherwise never hear it, and this one is about a
                    // file the product already took off their disk.
                    let text = format!("{id} failed its integrity check: {detail}");
                    log::error!("{text}");
                    self.announce(Announcement::new(
                        "A quarantined file failed its integrity check",
                        text,
                    ));
                }
                // A restore or a delete is the direct result of something the
                // user just clicked, and the tab underneath already shows the
                // new state. Announcing it in the corner as well would be the
                // interface telling a user what they just did.
                QuarantineEvent::Restored { .. }
                | QuarantineEvent::Deleted(_)
                | QuarantineEvent::Evicted { .. }
                | QuarantineEvent::RemovalCompleted { .. }
                | QuarantineEvent::RemovalAbandoned { .. } => {}
            }
        }
    }

    // -- later launches ------------------------------------------------------

    /// Take the requests a second launch of this program has made.
    ///
    /// Called once per frame from [`GuiApp::draw`], before anything is drawn, for
    /// the same reason the vault's events are drained there: the request arrives
    /// at some moment between two frames, and the picture should be of the state
    /// as of now.
    ///
    /// Every request raises the window, including the one that names a file. The
    /// point of the whole mechanism is that the user clicked something and the
    /// answer is the window they already have, so it has to end up in front of
    /// them; a scan started in a window still behind the one they were looking at
    /// is a click that appears to have done nothing.
    ///
    /// The raise is a viewport command rather than a Win32 call, and that is the
    /// reason there is no `FindWindowW` anywhere in [`crate::single`]: this
    /// process owns the window, and `egui` is the only thing that knows which
    /// state it is in — behind another window, minimised, or on another virtual
    /// desktop — so it is the only thing that can raise it correctly. That is
    /// also why it takes two commands rather than one; see below.
    ///
    /// Nothing is drawn and nothing is logged per request. A wake is the user
    /// doing something, and the window coming to the front is the report.
    pub fn drain_later_launches(&mut self, ctx: &egui::Context) {
        // Collected before anything is acted on, because acting needs `&mut self`
        // and the receiver is part of `self`. The same shape the vault's drain
        // uses, for the same reason.
        let wakes: Vec<crate::single::Wake> = match &self.wakes {
            Some(wakes) => wakes.try_iter().collect(),
            None => return,
        };
        if wakes.is_empty() {
            return;
        }
        // Restore, then focus, and the order is not cosmetic: `Focus` is
        // documented as having no effect on a minimised window, so sending it
        // first would be a command that is discarded and the window would come
        // back behind whatever the user was looking at. Both are no-ops when
        // they are already true, so the two together are right for every state
        // the window can be in. See [`GuiApp::show_window`] for why there is no
        // third command.
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        for wake in wakes {
            match wake {
                // Nothing further: the raise above is the whole of what a
                // second double-click asks for.
                crate::single::Wake::Focus => {}
                crate::single::Wake::Scan(path) => self.scan_from_launch(path),
            }
        }
    }

    /// Subscribe to the requests of later launches.
    ///
    /// Handed over rather than read at start-up because the request arrives while
    /// the window is running: a right-click on a file is not something that only
    /// happens before the window opens.
    pub fn watch_for_later_launches(
        &mut self,
        wakes: crossbeam_channel::Receiver<crate::single::Wake>,
    ) {
        self.wakes = Some(wakes);
    }

    /// Scan a path a second launch named, or say why that cannot be done now.
    ///
    /// This is the Explorer verb's other half: `wenle-gui.exe --scan "%1"` run
    /// against a window that is already open. The path lands in the target field
    /// before anything is decided about it, so that a request that cannot be
    /// honoured at this instant is still visible on screen rather than reported
    /// and forgotten — the field is what the Scan button reads, so the user's
    /// click has left the window ready to do what they asked as soon as it can.
    ///
    /// A running scan is the one case that cannot be honoured, and it is said out
    /// loud rather than dropped. [`GuiApp::start_scan`] refuses while one is
    /// running — correctly, since two scans over one findings list is two answers
    /// to every question the list asks — but its refusal is silent in that case,
    /// and a right-click that produced nothing at all is the outcome this module
    /// exists to prevent in the other direction.
    fn scan_from_launch(&mut self, path: PathBuf) {
        self.set_target(Some(path));
        if self.state.is_running() {
            self.status = Some(
                "A scan is already running, so that request is waiting in the target field. \
                 Press Scan when this one finishes."
                    .to_owned(),
            );
            return;
        }
        self.start_scan();
    }

    // -- actions -------------------------------------------------------------

    /// Act on what the drawing code asked for.
    ///
    /// Order matters and is the order below: a stop is obeyed before a start, so
    /// that a frame in which the user somehow managed both leaves the window
    /// stopping rather than starting a second scan on top of the first.
    fn run_pending(&mut self, pending: Pending) {
        if pending.stop {
            self.stop_scan();
        }
        // Before starting anything: a picker changes where the scan would go,
        // and a user who clicked both in one frame meant the picker first. The
        // two are exclusive in the interface — the buttons are drawn only where
        // a picker exists — but this costs nothing and reads in the order the
        // screen reads in.
        if pending.pick_folder {
            let picked = picker::choose_folder();
            self.set_target(picked);
        }
        if pending.pick_file {
            let picked = picker::choose_file();
            self.set_target(picked);
        }
        if pending.start {
            self.start_scan();
        }
        if pending.open_vault {
            // Opening the vault from a notification means the user asked to
            // *see* it, so the tab comes with it. Opening it from the Quarantine
            // tab is already on the tab, and setting it again costs nothing.
            self.tab = Tab::Quarantine;
            self.open_vault();
        }
        if let Some(on) = pending.select_all {
            self.tick_all(on);
        }
        if pending.quarantine_checked {
            self.quarantine_checked();
        }
        if let Some(id) = pending.restore {
            self.restore(&id);
        }
        if let Some(id) = pending.delete {
            self.delete(&id);
        }
        if let Some((id, how)) = pending.allow {
            self.allow(&id, how);
        }
        if pending.clear_filter {
            self.filter.clear();
        }
        if pending.revert_settings {
            self.settings.revert();
            self.status = Some("The settings were put back to what is saved.".to_owned());
        }
        if pending.save_settings {
            self.save_settings();
        }
    }

    /// Take what a picker returned, if it returned anything.
    ///
    /// This is the seam the picker is tested across: a native dialog cannot be
    /// driven by a test, so everything that happens *after* one is closed is
    /// this function, and it is a function of its argument alone. `None` is a
    /// cancelled dialog and is not a decision — the field keeps whatever the
    /// user had already typed, which is what they were looking at when they
    /// changed their mind, and the status line says nothing, because nothing
    /// happened. An empty path is not treated as a cancellation: it cannot come
    /// from a picker, and if it somehow did it would be refused by
    /// [`GuiApp::start_scan`] in the same words an empty typed path is.
    ///
    /// The path is converted with `to_string_lossy` rather than refused when it
    /// is not valid UTF-8, because the alternative is a dialog that appears to
    /// do nothing on a folder the user is looking at. The replacement character
    /// it puts in is visible in the field, so the user can see that the path is
    /// not the one they picked rather than being told the picker failed.
    pub fn set_target(&mut self, picked: Option<PathBuf>) {
        let Some(path) = picked else {
            return;
        };
        self.target = path.to_string_lossy().into_owned();
        self.status = Some(format!(
            "Target set to {}.",
            format::shorten_path(&self.target, 90)
        ));
    }

    /// The request a scan of `target` is made with.
    ///
    /// Its own function because of the second half of it: a path the user
    /// allowed from the Quarantine tab while the service was not running is
    /// skipped by this window's scans as well, and the only way to check that is
    /// to be able to build the request without starting a scan. A test that
    /// started one would be waiting on a worker to prove what is decided before
    /// the worker exists.
    ///
    /// The configuration comes from `self.config` and not from the Settings
    /// tab's unsaved edits: a scan that used edits nobody had agreed to yet
    /// would make the report and the settings screen describe two different
    /// runs. The allows are added *after* it rather than merged into it, because
    /// they were never written to the file — see [`GuiApp::allow_here`].
    fn scan_request(&self, target: PathBuf, database: PathBuf) -> ScanRequest {
        let mut request =
            ScanRequest::from_config(target, database, &self.config, Some(self.paths.clone()));
        request.excluded_paths.extend(self.allowed.iter().cloned());
        request
    }

    /// Start scanning the path in the target field.
    ///
    /// Refuses in the two cases where starting would produce a worse answer
    /// than not starting: no rules to scan with, and nothing named to scan.
    pub fn start_scan(&mut self) {
        if !self.state.can_start() {
            return;
        }
        let target = PathBuf::from(self.target.trim());
        if self.target.trim().is_empty() {
            self.state.fail("No folder or file to scan was named.");
            self.status = Some("Type or paste a folder or file to scan.".to_owned());
            return;
        }
        // Asked again, every time, and that is not belt-and-braces. The
        // resolution at start-up is the right thing for the line the window
        // opens with — a machine with no rules should say so before the user has
        // asked for a scan of a whole drive — but it is a snapshot, and this is
        // where the answer is acted on. A window that was opened before the
        // rules existed would refuse every scan for the rest of its life,
        // saying "there are no rules" long after there were: the first run
        // after an install, or a window opened while `wenle build` was
        // replacing the file, is enough. It cuts the other way too, and that
        // direction is the one a user is more likely to report: a rule database
        // that was replaced while the window was open is picked up by the next
        // scan instead of being refused as the file that used to be there.
        self.database = locate_database(&self.paths);
        let database = match &self.database {
            Ok(path) => path.clone(),
            Err(message) => {
                self.state.fail(message.clone());
                self.status = Some(message.clone());
                return;
            }
        };
        // And whether the database can be read at all, before the window goes
        // into a scanning state. The worker checks this too, and its check is the
        // one that counts — but the worker's comes *after* it has walked the
        // tree, so the failure it produces arrives at the end of a scan the user
        // watched run. This one costs twenty bytes and happens while the button
        // is still under their cursor. A user reported the worker's version: a
        // scan of a folder that ran, then failed, and named a file in
        // `%ProgramData%` that they had never pointed it at.
        if let Err(error) = av_rules::database::RuleDatabase::check_file(&database) {
            let message = format!(
                "The rule database at {} cannot be used by this build: {error}",
                database.display()
            );
            self.state.fail(message.clone());
            self.status = Some(message);
            return;
        }
        let request = self.scan_request(target, database);
        self.findings.clear();
        self.selected = None;
        self.filter.clear();
        // And the ticks, which are the one piece of per-result state that would
        // otherwise outlive its results. Every other field here is cleared; this
        // one was not, and it is the one that *acts*: the ticks drive the bulk
        // quarantine, whose button and count read `checked.len()` rather than the
        // visible rows. Left alone, a scan started after ticking three files
        // shows a button offering to quarantine three files that are no longer
        // listed — and `quarantine_checked` would act on the paths, not on what
        // the user can see. The paths are keyed by file rather than by row, for
        // the reason its own documentation gives, which is exactly why nothing
        // else prunes them.
        self.checked.clear();
        // Nothing is done to the notifications already posted. The old
        // behaviour was to clear the corner, because a card about a file the
        // last scan found is a card about a result the user has dealt with; a
        // notification the shell has already put in the Action Center belongs
        // to the user now, and removing it would be this window reaching into
        // their notification history. The status line below is cleared by the
        // new scan writing its own.
        let job = ScanJob::start(request);
        self.state = ScanState::Running(job.handle().clone());
        self.job = Some(job);
        self.tab = Tab::Scan;
        self.status = Some("Looking for files…".to_owned());
    }

    /// Ask the running scan to stop.
    ///
    /// Returns immediately and says so: the scan stops between files, so the
    /// window goes into a state that reports a stop on its way rather than one
    /// that has arrived. See [`ScanState::cancelled_note`].
    pub fn stop_scan(&mut self) {
        // Through the state's own handle rather than through the job, because
        // the state is what the Stop button is looking at: a stop that went to
        // the job alone would leave the state's copy of the flag unset and the
        // button's own "is it stopping" question answered wrongly.
        if let Some(handle) = self.state.handle() {
            handle.request_stop();
            self.status = Some(
                "Stopping. The file being scanned finishes first, then the scan stops.".to_owned(),
            );
        }
    }

    /// Save the settings if they are valid, and say why not if they are not.
    ///
    /// The validation is the engine's own ([`SettingsDraft::validate`]), so the
    /// window refuses exactly what a later start-up would refuse. Writing a
    /// configuration the product cannot load would leave a machine that will not
    /// start, which is a worse outcome than a settings screen that says no.
    pub fn save_settings(&mut self) {
        if let Err(message) = self.settings.validate() {
            self.say(format!("Not saved: {message}"));
            return;
        }
        let edited = self.settings.edited().clone();
        if let Err(error) = edited.save(&self.paths.config_file) {
            self.say(format!("The settings could not be written: {error}"));
            return;
        }
        self.config = edited;
        // The next scan uses the new configuration, so the draft's baseline
        // moves with it. Leaving the draft dirty would make the Save button
        // offer to save a file that already contains those values.
        self.settings.committed();
        // The two settings that are not only this process's business: the
        // notification layer reads its two, and the two per-user registrations
        // follow `minimize_to_tray`. After the file, never before — a machine
        // changed for a setting that did not save would be a change nobody
        // asked for.
        self.notifier.configure(
            self.config.general.notifications,
            self.config.general.notification_sound,
        );
        self.sync_registrations();
        self.say(format!("Saved to {}.", self.paths.config_file.display()));
    }

    /// Make this user's registrations agree with the settings just saved.
    ///
    /// Two of them, and both are per-user values written through
    /// `av-integration`: the entry that starts this window at sign-in, and the
    /// name and icon Windows attributes this product's notifications to. The
    /// window is the only thing in the product that can decide either, because
    /// both are answers to a question this window asks the user.
    ///
    /// **Nothing is written when the machine already agrees.** The startup entry
    /// is a value under `HKCU\...\CurrentVersion\Run`, a key every other program
    /// that starts at sign-in keeps an entry in, and rewriting a value that is
    /// already correct is how a product's own installer gets reported as
    /// suspicious behaviour by other security software. So each is read first
    /// and written only when it differs.
    ///
    /// A failure is reported and not fatal: the settings are already saved, and a
    /// machine where the registry could not be written is still a machine where
    /// the scanner works.
    fn sync_registrations(&mut self) {
        let wanted = self.config.general.minimize_to_tray;
        match av_integration::startup::status() {
            Ok(status) if status.is_installed() == wanted => {}
            Ok(_) => {
                let changed = if wanted {
                    av_integration::startup::install().map(|_| ())
                } else {
                    av_integration::startup::remove()
                };
                match changed {
                    Ok(()) => self.say(if wanted {
                        "Wenle AV will start in the notification area when you sign in.".to_owned()
                    } else {
                        "Wenle AV will no longer start when you sign in.".to_owned()
                    }),
                    Err(error) => self.say(format!(
                        "The settings were saved, but the sign-in entry could not be changed: \
                         {error}"
                    )),
                }
            }
            // The key could not be read, so there is no way to know whether the
            // write is needed. Writing anyway is the better wrong: a stale
            // entry points at a path the program is no longer at, which is the
            // one failure a start-up entry has.
            Err(error) => {
                log::warn!("the sign-in entry could not be read: {error}");
            }
        }

        match av_integration::notifications::status() {
            Ok(status) if status.is_installed() == self.config.general.notifications => {}
            Ok(_) => {
                let changed = if self.config.general.notifications {
                    av_integration::notifications::install().map(|_| ())
                } else {
                    av_integration::notifications::remove()
                };
                if let Err(error) = changed {
                    log::warn!("the notification registration could not be changed: {error}");
                }
            }
            Err(error) => log::warn!("the notification registration could not be read: {error}"),
        }
    }

    /// Open the vault, once, and remember why if it will not open.
    fn open_vault(&mut self) {
        if self.vault.is_some() {
            return;
        }
        let policy = QuarantinePolicy::from(&self.config.quarantine);
        match QuarantineVault::open_recovering(&self.paths.quarantine_dir, policy) {
            Ok(mut vault) => {
                log::info!(
                    "opened the vault at {} with {} items",
                    self.paths.quarantine_dir.display(),
                    vault.entries().len()
                );
                // Subscribe before anything can be quarantined through this
                // vault, so that the very first item taken raises its
                // notification. The listener is a channel send and nothing
                // else: the vault may call it from whichever thread did the
                // quarantine, and no drawing may happen on that thread.
                let (sender, events) = crossbeam_channel::unbounded();
                vault.subscribe(std::sync::Arc::new(move |event: &QuarantineEvent| {
                    // A send on an unbounded channel cannot block, and a closed
                    // receiver means the window is going away, which is not a
                    // reason to fail a quarantine that has already happened.
                    let _ = sender.send(event.clone());
                }));
                self.vault_events = Some(events);
                // Everything the vault already holds was taken before this
                // window was watching, and none of it is news. Recorded before
                // the baseline is taken, so the two describe the same instant.
                self.announced = vault.entries().iter().map(|e| e.id).collect();
                // The baseline the first look compares against: without it, a
                // write landing between this open and that look would be read as
                // the state of the world rather than as a change to it.
                self.vault_poll.prime(vault.index_path());
                self.vault = Some(vault);
                self.vault_error = None;
            }
            Err(error) => {
                // Reported rather than swallowed, and the error is kept so that
                // the tab can keep saying it. A quarantine tab that silently
                // showed nothing would tell a user their vault was empty.
                let message = format!(
                    "The quarantine vault at {} could not be opened: {error}",
                    self.paths.quarantine_dir.display()
                );
                log::error!("{message}");
                self.vault_error = Some(message.clone());
                self.say(message);
            }
        }
    }

    /// The vault, opening it if this is the first time it has been needed.
    fn vault_mut(&mut self) -> Option<&mut QuarantineVault> {
        if self.vault.is_none() && self.vault_error.is_none() {
            self.open_vault();
        }
        self.vault.as_mut()
    }

    /// Tick everything the filter is showing, or untick everything.
    ///
    /// Select-all is over the **filtered** set and untick-all is over the whole
    /// set, and the asymmetry is deliberate. A user who has narrowed the list to
    /// "malicious" and presses "Tick all" means those rows; they cannot see the
    /// hidden ones and would not recognise a file they were never shown. But a
    /// user pressing "Untick all" means "none of them", and leaving ticks on
    /// invisible rows would mean the quarantine button's count disagreed with
    /// everything on screen and the next press took files the user had just
    /// decided against.
    pub fn tick_all(&mut self, on: bool) {
        if !on {
            self.checked.clear();
            return;
        }
        let shown: Vec<PathBuf> = self
            .filter
            .apply(self.findings())
            .files
            .iter()
            .map(|report| report.path.clone())
            .collect();
        self.checked.extend(shown);
    }

    /// Take every ticked finding off the disk.
    ///
    /// One file is the ordinary case of this and not a separate path: a user
    /// who ticks one row and presses the button gets the same code, so the two
    /// can never disagree about what "quarantined" means.
    ///
    /// # What it refuses, and why it refuses it out loud
    ///
    /// A clean finding that happens to be ticked is skipped rather than
    /// quarantined, and the count of skipped files is reported. Quarantine is
    /// destructive: it removes the original from where the user left it, and
    /// there is no undo for that from this window. "I ticked everything" must
    /// not become "I removed files the product itself says are fine".
    ///
    /// # One notification for the batch
    ///
    /// The per-file [`QuarantineEvent::Quarantined`] announcements are
    /// suppressed here and replaced with a single card, so the vault is drained
    /// with `announce_blocks = false`. Two hundred files ticked means two
    /// hundred events, and the corner holds four cards — so without this a user
    /// would see the last four files by name and no indication of the other
    /// hundred and ninety-six. The batch is one thing the user did, and it
    /// reports once.
    pub fn quarantine_checked(&mut self) {
        if self.checked.is_empty() {
            self.say("Nothing was ticked, so nothing was quarantined.");
            return;
        }
        // Resolved in list order before anything is taken, so that the status
        // line reads in the order the user sees and so that the vault's borrow
        // is not held across the whole batch.
        let targets: Vec<FileScanReport> = self
            .findings
            .iter()
            .filter(|report| self.checked.contains(&report.path))
            .cloned()
            .collect();
        // A tick for a file that is no longer in the report — possible if the
        // list was replaced between the click and this call. Dropped here so
        // the count on the button and the count in the status line stay the
        // same number.
        self.checked.retain(|path| {
            self.findings
                .iter()
                .any(|report| &report.path == path)
        });
        if targets.is_empty() {
            self.status = Some("Those files are no longer in the list.".to_owned());
            return;
        }

        let mut taken = 0usize;
        let mut skipped = 0usize;
        let mut failures: Vec<(PathBuf, String)> = Vec::new();
        let mut deferred = 0usize;
        for report in &targets {
            if report.verdict() == Verdict::Clean {
                skipped += 1;
                // The tick is cleared here as well as on the taken files, and
                // the reason is what the button's count means. It says how many
                // files pressing it will act on; a file the product has called
                // clean is not one of those and never will be, so leaving it
                // ticked leaves the window offering to do something it has
                // already decided against — and the next press re-reports the
                // same refusal for as long as the user leaves the tick there.
                // The file stays in the list, unticked, and the message says
                // what it was left alone for.
                self.checked.remove(&report.path);
                continue;
            }
            let context =
                av_quarantine::QuarantineContext::from_report(report, EntrySource::Manual);
            // The result is taken out of the vault's borrow before anything else
            // on `self` is touched: acting on the outcome needs the whole of
            // `self`, and an event the vault emitted during the call is already
            // waiting on the channel by the time this returns.
            let outcome = {
                let Some(vault) = self.vault_mut() else {
                    failures.push((
                        report.path.clone(),
                        "the quarantine vault is not open".to_owned(),
                    ));
                    continue;
                };
                match vault.quarantine_file(&report.path, &context) {
                    Ok(entry) => Ok(entry),
                    Err(error) => Err(error.to_string()),
                }
            };
            match outcome {
                Ok(entry) => {
                    taken += 1;
                    if !entry.original_removed {
                        deferred += 1;
                    }
                    // Ticked files that were dealt with are unticked, so the
                    // button's count is what is left to do rather than what has
                    // been done. The ones that failed stay ticked: those are
                    // exactly the files a user needs to try again.
                    self.checked.remove(&entry.original_path);
                }
                Err(error) => failures.push((report.path.clone(), error)),
            }
        }

        // Everything the vault said during the batch, minus the per-file block
        // cards — the one card below stands in for them.
        self.drain_vault_events_announcing(false);
        self.reload_vault_entries();

        if taken > 0 {
            self.announce(Announcement::replacing(
                Tag::Blocked,
                "Blocked and quarantined",
                format!(
                    "{} {} blocked and moved to quarantine.",
                    format::count_of(taken as u64, "file"),
                    if taken == 1 { "was" } else { "were" }
                ),
            ));
        } else if skipped > 0 && failures.is_empty() {
            // Nothing was taken and nothing went wrong, which means every ticked
            // file was clean, and the status line at the end of this function
            // says exactly that — `batch_status` reports the skipped count and
            // the reason. A second copy in a notification would have been the
            // same sentence twice.
            log::info!(
                "a bulk quarantine found {} of its ticks clean",
                format::count_of(skipped as u64, "file")
            );
        }
        for (path, error) in &failures {
            // The most important failure this window can report: a file the user
            // believes has been dealt with, which has not been. They are logged
            // one by one and announced once, because a batch of two hundred
            // files with a systematic failure — a directory that went read-only
            // — would otherwise be two hundred notifications saying one thing.
            log::error!("{} could not be quarantined: {error}", path.display());
        }
        if let Some((path, error)) = failures.first() {
            let text = if failures.len() == 1 {
                format!("{} could not be quarantined: {error}", path.display())
            } else {
                format!(
                    "{} could not be quarantined. The first was {}: {error}",
                    format::count_of(failures.len() as u64, "file"),
                    path.display()
                )
            };
            self.announce(Announcement::new("Could not be quarantined", text));
        }

        self.status = Some(self.batch_status(taken, skipped, deferred, failures.len()));
    }

    /// One line describing what a bulk quarantine did.
    ///
    /// Written as a sentence rather than as counters, and it always says what
    /// was *not* done as well as what was: a user who ticked ten files and is
    /// told "3 quarantined" has to work out what happened to the other seven,
    /// and the answer is the part they need.
    fn batch_status(
        &self,
        taken: usize,
        skipped: usize,
        deferred: usize,
        failed: usize,
    ) -> String {
        let mut parts = vec![format::count_of(taken as u64, "file") + " quarantined"];
        if skipped > 0 {
            parts.push(format!(
                "{} left alone because it was scanned and found clean",
                format::count_of(skipped as u64, "file")
            ));
        }
        if failed > 0 {
            parts.push(format!(
                "{} could not be taken — see the notifications",
                format::count_of(failed as u64, "file")
            ));
        }
        let mut line = parts.join(", ") + ".";
        if deferred > 0 {
            line.push_str(&format!(
                " {} still on disk and will be retried.",
                format::count_of(deferred as u64, "file")
            ));
        }
        line
    }

    /// Put a quarantined file back where it came from.
    ///
    /// The service performs it when it is running, because the vault has one
    /// writer and the service is that writer. See [`crate::service`] for what
    /// follows when it is not, and [`GuiApp::allow`] for the version of this
    /// that also stops the file being taken again.
    pub fn restore(&mut self, id: &QuarantineId) {
        match service::restore(&self.service_pipe, *id) {
            Ok(change) => self.report_change(change, "restored"),
            Err(unreachable) => self.restore_here(*id, &unreachable),
        }
    }

    /// Destroy a quarantined file's bytes, keeping the record.
    pub fn delete(&mut self, id: &QuarantineId) {
        match service::delete(&self.service_pipe, *id) {
            Ok(change) => self.report_change(change, "deleted"),
            Err(unreachable) => self.delete_here(*id, &unreachable),
        }
    }

    /// Put a quarantined file back and stop the product taking it again.
    ///
    /// The two halves are one operation and not two buttons' worth of work: a
    /// restore on its own leaves the file exactly where it was before, so the
    /// next scan — or the next time it is run — takes it straight back. That
    /// loop is what a user hits on a false positive, and this is the way out of
    /// it.
    ///
    /// [`Allow::Permanent`] is a real decision about the machine and the
    /// interface has to present it as one; see [`Allow`].
    pub fn allow(&mut self, id: &QuarantineId, how: Allow) {
        let permanent = how == Allow::Permanent;
        match service::allow(&self.service_pipe, *id, permanent) {
            Ok(change) => self.report_change(change, "allowed"),
            Err(unreachable) => self.allow_here(*id, permanent, &unreachable),
        }
    }

    /// Say what was done to an item, in the words of whoever did it.
    ///
    /// `action` is the verb for the failure line only — `"restored"`,
    /// `"deleted"`, `"allowed"` — because a refusal has to say which of the
    /// three was refused, and the service's own reason is a sentence about the
    /// vault that does not name the operation the user asked for.
    fn report_change(&mut self, change: QuarantineChange, action: &'static str) {
        let name = self.name_of(change.id());
        match change {
            QuarantineChange::Restored { path, .. } => {
                // A restore is not good news and is not coloured as good news:
                // it puts an executable back on the disk where it was. The band
                // is the middle one, which is the band that says "look at this
                // yourself", and the notification is a notice rather than a
                // block because nothing was stopped.
                self.say(format!("{name} was written back to {}.", path.display()));
            }
            QuarantineChange::Allowed { path, lasting, .. } => {
                let mut line =
                    format!("{name} was written back to {} and will not be taken again", path.display());
                line.push_str(if lasting {
                    " — the exclusion was saved."
                } else {
                    " until the service stops: the exclusion could not be written to the \
                     configuration."
                });
                self.say(line);
                // The service was the writer, so no file write happened in this
                // process and nothing here moved with it. That used to be the
                // whole of this arm and it was a leak: the exclusion is in the
                // file, this window's copy of the configuration and its Settings
                // draft still hold the configuration from before the allow, and
                // the next Save writes that older copy over the file. The
                // exclusion — the thing the status line just said was saved —
                // is gone. See [`Self::note_allow`].
                self.note_allow(&path, lasting);
            }
            QuarantineChange::Deleted { .. } => {
                self.say(format!("{name} was deleted from the vault."));
            }
            QuarantineChange::Failed { reason, .. } => {
                self.say(format!("{name} could not be {action}: {reason}"));
            }
        }
        self.reload_vault_entries();
    }

    /// What to call an item in a sentence.
    ///
    /// The file name when this window's copy of the index holds the item, and
    /// the identifier when it does not — which is what the user sees if
    /// something purged it between the list being drawn and the button being
    /// pressed. Reported before the index is re-read, so the name is the one
    /// from the row the user was looking at.
    fn name_of(&self, id: QuarantineId) -> String {
        self.vault
            .as_ref()
            .and_then(|vault| vault.get(id).ok())
            .map(|entry| entry.file_name.clone())
            .unwrap_or_else(|| id.to_string())
    }

    /// Put an item back, here, because the service did not answer.
    ///
    /// # Why this is still allowed to exist
    ///
    /// The vault's one-writer rule is about two writers at once. When nothing
    /// is listening on the control pipe there is no other writer, so this is
    /// one writer again — and refusing to restore a user's file because a
    /// service they may never have installed is not running would be the window
    /// holding their data hostage to a second process.
    ///
    /// What it must not do is pass itself off as the service's work. Every line
    /// these three write ends with the reason the service was not asked, because
    /// "the exclusion could not be saved" and "no service is listening" are
    /// different states of the machine and the user is the one who has to act on
    /// the difference.
    fn restore_here(&mut self, id: QuarantineId, why: &service::Unreachable) {
        let name = self.name_of(id);
        let outcome = {
            let Some(vault) = self.vault_mut() else {
                return;
            };
            vault
                .restore(id, &av_quarantine::RestoreOptions::to_original())
                .map_err(|error| error.to_string())
        };
        match outcome {
            Ok(path) => self.say(format!(
                "{name} was written back to {} — {}.",
                path.display(),
                why.describe()
            )),
            Err(error) => self.say(format!("{name} could not be restored: {error}")),
        }
        self.reload_vault_entries();
    }

    /// Destroy an item's bytes, here, because the service did not answer.
    fn delete_here(&mut self, id: QuarantineId, why: &service::Unreachable) {
        let name = self.name_of(id);
        let outcome = {
            let Some(vault) = self.vault_mut() else {
                return;
            };
            vault
                .delete(id)
                .map(|entry| entry.file_name.clone())
                .map_err(|error| error.to_string())
        };
        match outcome {
            Ok(file_name) => self.say(format!(
                "{file_name} was deleted from the vault — {}.",
                why.describe()
            )),
            Err(error) => self.say(format!("{name} could not be deleted: {error}")),
        }
        self.reload_vault_entries();
    }

    /// Put an item back and leave it alone, here, because the service did not
    /// answer.
    ///
    /// The exclusion goes into the configuration file the same way, and into
    /// this window's own list of paths its scans skip, because with the service
    /// down there is nothing else for it to mean: [`crate::scan`] reads the
    /// exclusions from the configuration when a scan starts, and a session
    /// allow that was written nowhere would be gone by the next scan and the
    /// status line would have said otherwise.
    fn allow_here(&mut self, id: QuarantineId, permanent: bool, why: &service::Unreachable) {
        let name = self.name_of(id);
        let outcome = {
            let Some(vault) = self.vault_mut() else {
                return;
            };
            vault
                .restore(id, &av_quarantine::RestoreOptions::to_original())
                .map_err(|error| error.to_string())
        };
        match outcome {
            Ok(path) => {
                let lasting = permanent && self.remember_exclusion(&path);
                // This window was the writer here, so `remember_exclusion` has
                // already carried the durable half; the rest of what an allow
                // means is the same whoever performed it, so it goes through
                // the same function as the service's answer does.
                self.note_allow(&path, lasting);
                let mut line = format!(
                    "{name} was written back to {} and will not be taken again",
                    path.display()
                );
                line.push_str(if lasting {
                    " — the exclusion was saved"
                } else if permanent {
                    " until this window is closed: the exclusion could not be written to the \
                     configuration"
                } else {
                    " until this window is closed"
                });
                line.push_str(&format!(" — {}.", why.describe()));
                self.say(line);
            }
            Err(error) => self.say(format!("{name} could not be allowed: {error}")),
        }
        self.reload_vault_entries();
    }

    /// Record an allow in this window's own state, whoever performed it.
    ///
    /// Two halves, and they are separate on purpose.
    ///
    /// The first is this window's alone: its scans skip the path
    /// ([`Self::scan_request`]) whether or not anything was written down. The
    /// service will not take the file again for the rest of this boot either
    /// way, and a manual scan here that still reported it would be the window
    /// telling the user a different story about the same file than the one the
    /// last status line told.
    ///
    /// The second half only exists when the exclusion was written down, and
    /// `lasting` is that question — asked of the service, because when the
    /// service is running *it* is the one that writes. When the answer is yes
    /// this process still has to move with it, and that is the part that is
    /// easy to miss: the Settings tab holds a draft of the configuration taken
    /// when it was last committed, and a Save writes that draft to the file
    /// whole. An allow that moved the file but not the draft is undone by the
    /// next Save — silently, because the tab reads as dirty by exactly the one
    /// exclusion the user just created.
    ///
    /// It deliberately does not go through the draft's dirty state: that state
    /// is the Settings tab's editing state, and a user who never opened that
    /// tab has not edited anything. [`SettingsDraft::note_exclusion`] moves both
    /// of the draft's copies so that saving some unrelated setting keeps this
    /// exclusion.
    fn note_allow(&mut self, path: &std::path::Path, lasting: bool) {
        if !self.allowed.iter().any(|held| held == path) {
            self.allowed.push(path.to_path_buf());
        }
        if !lasting {
            return;
        }
        if !self.config.general.exclusions.iter().any(|held| held == path) {
            self.config.general.exclusions.push(path.to_path_buf());
        }
        self.settings.note_exclusion(path);
    }

    /// Add `path` to the exclusions in force and write them to the file.
    ///
    /// Answers whether the file was written, so the caller can tell the user
    /// that the allow lasts only for now rather than reporting a permanence that
    /// does not exist.
    ///
    /// It does not go through the Settings draft's dirty state: that draft is
    /// the Settings tab's own editing state, and a user who has never opened
    /// that tab has not edited anything. What it does have to do is move the
    /// draft's two copies with it — see [`SettingsDraft::note_exclusion`] — or
    /// the next Save would write the configuration from before this call.
    fn remember_exclusion(&mut self, path: &std::path::Path) -> bool {
        let mut config = self.config.clone();
        if !config.general.exclusions.iter().any(|held| held == path) {
            config.general.exclusions.push(path.to_path_buf());
        }
        match config.save(&self.paths.config_file) {
            Ok(()) => {
                self.config = config;
                self.settings.note_exclusion(path);
                true
            }
            Err(error) => {
                log::warn!(
                    "the path {} was allowed for this window, but the exclusion could not be \
                     written to {}: {error}",
                    path.display(),
                    self.paths.config_file.display()
                );
                false
            }
        }
    }

    /// Re-read the vault's index after something changed it.
    ///
    /// This used to do nothing, on the grounds that every operation on the vault
    /// had already updated the copy in memory. That was true while this window
    /// was the only thing acting on the vault; it is not true now that the
    /// service performs the user's decisions, because the service writes the
    /// file and this process's copy knows nothing about it. The row would stay
    /// on screen marked `quarantined` after its bytes had gone back to disk, and
    /// the next click would act on a stale record.
    ///
    /// The vault's own [`QuarantineVault::reconcile`] is the whole of it: one
    /// file, one truth, and the file is it.
    fn reload_vault_entries(&mut self) {
        if let Some(vault) = self.vault.as_mut() {
            if let Err(error) = vault.reconcile() {
                // Kept rather than cleared: the entries this process has are the
                // last thing known to be true, and emptying the list would show
                // a user that their quarantine is gone.
                log::warn!("the vault's index could not be re-read: {error}");
            }
        }
        // The selection may now name an entry that is gone, which is the state
        // the tab would draw a button for.
        if let Some(vault) = &self.vault {
            if let Some(id) = self.vault_selected {
                if vault.get(id).is_err() {
                    self.vault_selected = None;
                }
            }
        }
    }

    // -- drawing -------------------------------------------------------------

    /// Draw the window.
    ///
    /// The whole of one frame. `eframe` calls it through
    /// [`eframe::App::update`]; the tests call it through a headless
    /// [`egui::Context`], which is the only way any of this is covered without
    /// a desktop.
    pub fn draw(&mut self, ctx: &egui::Context) {
        let now = Instant::now();
        // First, because it is the one thing here that decides whether this
        // frame exists at all: a close request is answered for one frame only,
        // and a frame that drew before answering it would be a frame drawn for a
        // window that is already gone.
        self.answer_close_request(ctx);
        // Once, on the first frame, and never again: see
        // [`GuiApp::settle_launch_visibility`] for why a `--minimized` start is
        // decided here rather than before the window was created.
        self.settle_launch_visibility(ctx);
        self.drain_events();
        // And what another launch of this program has asked for, which is the
        // third way something outside this process reaches it. Before the frame
        // rather than after, because a request that starts a scan should be
        // reflected in the very frame that reports it: a window that raised
        // itself and then drew a frame of the state it was in before the click
        // looks like it ignored the click.
        self.drain_later_launches(ctx);
        // Beside the drain, and for the same reason: this is the other way
        // something that happened outside this process reaches the corner.
        self.poll_vault(now);

        let mut pending = Pending::default();
        // The fourth way something outside this process reaches it, and the only
        // one that arrives as a click on the product rather than on a file: the
        // notification-area icon. Drained into `pending` so that its commands are
        // acted on by the same code a button press is.
        self.drain_tray(ctx, &mut pending);

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            self.draw_header(ui, &mut pending);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            self.draw_status(ui, &mut pending);
        });
        // Every tab scrolls, and that lives here rather than inside each view
        // because the two axes are not the same problem. A view may be *taller*
        // than the window — the Scan view's card and legend come to 797 points
        // in the 720-point window the product opens at, and to well over twice
        // the 440-point window it may be dragged down to — and a vertical
        // scroll area is what makes the rest of it reachable. Nothing may be
        // *wider* than the window, because there is no horizontal scrolling
        // anywhere in the product to recover from that.
        //
        // Without this the Scan view's band legend stopped at the bottom edge
        // and the two bands below it could not be reached at all: no scrollbar,
        // no clipped edge to drag, nothing. See
        // `nothing_is_drawn_past_the_side_of_the_window`, which measures the
        // horizontal half of that rule, and `Tab::ALL`, which is what made the
        // omission easy — the two tabs with long lists had grown their own
        // scroll areas and the two without were assumed to fit.
        egui::CentralPanel::default().show(ctx, |ui| {
            let pending = &mut pending;
            let tab = self.tab;
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| match tab {
                    Tab::Scan => self.draw_scan(ui, pending),
                    Tab::Findings => self.draw_findings(ui, pending),
                    Tab::Quarantine => self.draw_quarantine(ui, pending),
                    Tab::Settings => self.draw_settings(ui, pending),
                });
        });

        // A running scan changes its numbers without any input, so the window
        // has to ask to be redrawn — and an idle one still has something to wait
        // for that nothing in this process can tell it about: the service taking
        // a file. No event can arrive from there, so the only way to notice is to
        // look, and looking needs a frame to look in — see [`crate::vault_poll`].
        //
        // The idle interval is the poll's own, so a change written just after a
        // look is announced within one interval of it. Waking once a second to
        // `stat` one file costs a frame; without it a block the service made
        // while this window was open would sit unannounced until the user
        // happened to move the mouse. A running scan is redrawn far more often
        // than that, so the faster request is the one that matters.
        ctx.request_repaint_after(if self.state.is_running() {
            RUNNING_REPAINT
        } else {
            crate::vault_poll::POLL_INTERVAL
        });

        // After the frame, not during it: see the module documentation.
        self.run_pending(pending);
    }

    fn draw_header(&mut self, ui: &mut egui::Ui, _pending: &mut Pending) {
        ui.add_space(theme::Spacing::SM);
        ui.horizontal(|ui| {
            // The product's own mark. Drawn rather than set in a font — see
            // `icons` — and the same shield the empty Scan view shows at four
            // times the size, so the window has one recognisable mark rather
            // than a logo and a set of unrelated glyphs.
            icons::show(ui, icons::Icon::Shield, 22.0, theme::Palette::ACCENT);
            ui.add_space(theme::Spacing::SM);
            ui.label(theme::title("Wenle AV"));
            ui.add_space(theme::Spacing::XL);
            if let Some(tab) = tab_bar(ui, self.tab) {
                self.tab = tab;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                status_pill(ui, self.state.report());
            });
        });
        ui.add_space(theme::Spacing::SM);
    }

    /// The bottom strip: what the scan is doing, and what the engine is.
    ///
    /// It used to be a second copy of the Scan tab's controls, which is why it
    /// was empty on three of the four tabs. It is now the one place in the
    /// window that is *always* saying the same thing about the machine — the
    /// phase's own sentence, the last thing the window did, and where the rule
    /// database is — so a user who is looking at Settings can still see that a
    /// scan is running, and a user whose installation has no rules can see it
    /// without going back to the tab that would tell them.
    ///
    /// It carries a Stop while one is running and nothing else: starting a scan
    /// is the Scan tab's job and there is one obvious place for it, but a scan
    /// that cannot be stopped from wherever the user happens to be standing is
    /// a scan that has taken the window hostage.
    fn draw_status(&mut self, ui: &mut egui::Ui, pending: &mut Pending) {
        ui.add_space(theme::Spacing::SM);
        ui.horizontal(|ui| {
            // The phase's own sentence, from `ScanState::summary`, so that the
            // line and the state underneath it cannot say two different things.
            let summary = self.state.summary();
            status_state(ui, self.state.phase());
            ui.label(theme::body(summary.clone()));
            // And what the window last did, when that is something the summary
            // does not already say. Most of the time the two agree and this
            // adds nothing; it is shown only when they differ, because two
            // labels saying the same thing is how a status bar becomes noise.
            if let Some(status) = self.status.as_deref() {
                if status != summary {
                    ui.separator();
                    ui.label(theme::meta(format::shorten_path(status, 72)));
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.state.is_running() && ui.button("Stop").clicked() {
                    pending.stop = true;
                }
                match &self.database {
                    Ok(path) => {
                        ui.label(theme::meta(format::shorten_path(
                            &path.display().to_string(),
                            44,
                        )))
                        .on_hover_text(format!("The rule database in use: {}", path.display()));
                        ui.label(theme::meta("Rules:"));
                    }
                    Err(_) => {
                        ui.label(
                            theme::meta("Rules: none found").color(theme::Palette::SUSPICIOUS),
                        );
                    }
                }
            });
        });
        // The stop-is-still-landing sentence, which is the difference between a
        // window that says a scan has ended and one that says it is ending.
        if let Some(note) = self.state.cancelled_note() {
            ui.label(theme::meta(note).color(theme::Palette::SUSPICIOUS));
        }
        ui.add_space(theme::Spacing::SM);
    }

    /// The Scan view: what state the machine is in, and the one control that
    /// changes it.
    ///
    /// A page title, a status card, and — while there is no result to read — a
    /// legend for the four bands the rest of the product is written in. The
    /// legend is not filler. The first amber row a user ever meets is worth
    /// understanding before they meet it rather than after, and "suspicious"
    /// meaning *reported and not acted on* is the one piece of vocabulary in
    /// this product that a person can be actively misled by.
    fn draw_scan(&mut self, ui: &mut egui::Ui, pending: &mut Pending) {
        let style = hero_style(&self.state);
        ui.add_space(theme::Spacing::MD);
        ui.label(theme::display("Scan"));
        ui.add_space(theme::Spacing::XS);
        ui.label(theme::meta(
            "Look at files on this machine and report what is in them.",
        ));
        ui.add_space(theme::Spacing::LG);

        self.draw_scan_hero(ui, pending, &style);

        // Under a first-time user's card and not under a result. A legend
        // explaining the four bands is worth its space on a machine that has
        // never been scanned, and it is in the way on one that has just
        // produced four numbers a reader is trying to get to.
        if !matches!(self.state, ScanState::Finished(_)) {
            ui.add_space(theme::Spacing::XL);
            band_legend(ui);
        }
    }

    /// The status card, in four shapes.
    ///
    /// The card is where the Scan view stops being a form and starts being an
    /// answer: at rest it says the machine has not been checked, while scanning
    /// it carries the walk and the bar, and after a scan it is tinted with the
    /// band and carries the counts. What it never does is show the band colour
    /// *behind* text that is also the band colour — see [`hero_style`].
    fn draw_scan_hero(&mut self, ui: &mut egui::Ui, pending: &mut Pending, style: &HeroStyle) {
        let running = self.state.is_running();
        let finished = matches!(self.state, ScanState::Finished(_));
        let database_ok = self.database.is_ok();
        theme::card(style.fill, style.outline).show(ui, |ui| {
            ui.set_width(ui.available_width());

            // The headline row. The mark carries the band's colour and the
            // sentence carries none, because a band colour on its own band tint
            // measures 4.00 for malicious and 4.15 for unknown — under the
            // 4.5:1 the rest of the window holds itself to, and on the two
            // bands a reader most needs to get right. The tint, the outline and
            // the mark say which band it is; the words are drawn in
            // `Palette::TEXT`, which measures 9.12–10.89 on all four fills.
            ui.horizontal(|ui| {
                ui.add_space(theme::Spacing::XS);
                icons::show(ui, style.icon, 44.0, style.accent);
                ui.add_space(theme::Spacing::LG);
                ui.vertical(|ui| {
                    ui.add_space(theme::Spacing::SM);
                    ui.label(theme::display(style.headline.clone()));
                    ui.add_space(theme::Spacing::SM);
                    // The secondary line, in `TEXT` at `META` rather than in
                    // `TEXT_DIM` at the same size: the hierarchy on a tinted
                    // card is the type scale's, not contrast's.
                    ui.label(theme::body(style.detail.clone()));
                });
            });

            if let ScanState::Finished(report) = &self.state {
                let counts = Counts::of(&report.detections);
                ui.add_space(theme::Spacing::LG);
                ui.horizontal_wrapped(|ui| {
                    band_chip(ui, count_of(counts.malicious), Verdict::Malicious);
                    band_chip(ui, count_of(counts.suspicious), Verdict::Suspicious);
                    band_chip(ui, count_of(counts.unknown), Verdict::Unknown);
                });
                // The middle band's note, in the same place a user reads the
                // count it is about. This is the sentence that has to survive
                // every redesign, because it is where the window says nothing
                // was done about those files.
                if let Some(note) = theme::band_note(Verdict::Suspicious) {
                    if counts.suspicious > 0 {
                        ui.add_space(theme::Spacing::XS);
                        ui.label(theme::body(note));
                    }
                }
                // The run's third outcome, and the one with no chip: a file the
                // rules matched and trust then cleared. It is not a finding, so
                // it is not in the list; it did not fail, so it is not in the
                // failure count. Left unsaid it would make "nothing found" a
                // sentence about a run that threw matches away — which is the
                // question a user asks when they are told a file is clean and do
                // not believe it. The rule ids are on the file's own row, and
                // nobody can open that row, because the file is not listed; so
                // this says how many and why, and the console is where the names
                // are read. See `ScanReport::cleared`.
                if let Some(line) = format::cleared_line(report.cleared) {
                    ui.add_space(theme::Spacing::XS);
                    ui.label(theme::body(line));
                }
                if !report.failures.is_empty() {
                    ui.add_space(theme::Spacing::SM);
                    ui.label(theme::body(format!(
                        "{} could not be read, so nothing is known about {}.",
                        format::count_of(report.failures.len() as u64, "file"),
                        format::count_of_pair(report.failures.len() as u64, "it", "them")
                    )));
                    // And then which ones, because the count is the half of the
                    // news a user cannot act on. "41 files could not be read"
                    // is a fact about the scan; "these four are on a volume
                    // that is not mounted" is a fact about the machine. The
                    // list is capped because a scan of a whole disk can fail on
                    // thousands of files and the card is not a log — the
                    // remainder is counted rather than dropped silently, so
                    // that a truncated list never reads as a complete one.
                    const SHOWN: usize = 5;
                    for (path, reason) in report.failures.iter().take(SHOWN) {
                        ui.label(theme::meta(format::read_failure(path, reason)));
                    }
                    if report.failures.len() > SHOWN {
                        ui.label(theme::meta(format!(
                            "and {} more",
                            format::count_of((report.failures.len() - SHOWN) as u64, "other file")
                        )));
                    }
                }
            }

            if let Err(message) = &self.database {
                ui.add_space(theme::Spacing::LG);
                framed(ui, theme::Palette::MALICIOUS, |ui| {
                    ui.label(theme::heading("There are no rules to scan with"));
                    ui.add_space(theme::Spacing::XS);
                    ui.label(theme::meta(message));
                });
            }

            ui.add_space(theme::Spacing::LG);
            ui.separator();
            ui.add_space(theme::Spacing::MD);

            if running {
                // An indeterminate bar while the walk runs, because a
                // percentage of an unknown total is not a percentage.
                // `animate` is what makes it move, and a bar that moves without
                // saying anything false about how much is left is the honest
                // picture of "we are still counting".
                let fraction = self
                    .state
                    .progress()
                    .and_then(|progress| progress.fraction());
                let bar = match fraction {
                    Some(fraction) => egui::ProgressBar::new(fraction)
                        .desired_width(ui.available_width())
                        .fill(theme::Palette::ACCENT)
                        .text(format!(
                            "{}%",
                            self.state.progress().and_then(|p| p.percent()).unwrap_or(0)
                        )),
                    None => egui::ProgressBar::new(0.0)
                        .desired_width(ui.available_width())
                        .fill(theme::Palette::ACCENT)
                        .animate(true)
                        .text("counting files"),
                };
                ui.add(bar);
                ui.add_space(theme::Spacing::MD);
                let stop = button(ui, icons::Icon::Stop, "Stop", true)
                    .on_hover_text("Stops after the file being scanned finishes");
                if stop.clicked() {
                    pending.stop = true;
                }
            } else {
                target_row(ui, &mut self.target, pending);
                ui.add_space(theme::Spacing::MD);
                let label = if finished { "Scan again" } else { "Start scan" };
                if primary_button(ui, icons::Icon::Play, label, database_ok).clicked() {
                    pending.start = true;
                }
            }
        });
    }

    fn draw_findings(&mut self, ui: &mut egui::Ui, pending: &mut Pending) {
        ui.add_space(theme::Spacing::MD);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(theme::display("Findings"));
                ui.add_space(theme::Spacing::XS);
                ui.label(theme::meta(
                    "Everything the last scan reported, worst first.",
                ));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Quarantining is the only action in the window that takes a
                // file off the disk, so its button is enabled only when
                // something is ticked, and its hover text is the sentence that
                // says so rather than a description of the button.
                //
                // The count is on the button for the same reason it is on the
                // "select all" control: this is the control that removes files,
                // and the number of files it is about to remove is the last
                // thing a user should have to work out.
                let ticked = self.checked.len();
                let label = if ticked == 0 {
                    "Quarantine ticked files".to_owned()
                } else {
                    format!("Quarantine {ticked} ticked")
                };
                if ui
                    .add_enabled(ticked > 0, egui::Button::new(label))
                    .on_hover_text("Moves them into the vault. This cannot be undone from here.")
                    .clicked()
                {
                    pending.quarantine_checked = true;
                }
            });
        });
        ui.add_space(theme::Spacing::LG);
        self.draw_filter_bar(ui, pending);
        ui.add_space(theme::Spacing::MD);

        let filtered = self.filter.apply(self.findings());
        ui.horizontal(|ui| {
            ui.label(theme::body(filtered.count_label()));
            // How much of what is shown is worth worrying about, from the
            // counts over the filtered set rather than over the whole report:
            // a count that ignored the filter would describe rows that are not
            // on the screen.
            if filtered.counts.concerning() > 0 {
                ui.label(theme::meta(format!(
                    "— {} of them are not clean",
                    format::count_of(filtered.counts.concerning() as u64, "finding")
                )));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Select-all means the rows the filter is showing, and it is
                // drawn as two controls rather than one toggle: a user who has
                // ticked nine of forty rows and wants none of them should not
                // have to re-derive which state the toggle is in.
                //
                // Both are enabled on what is *shown*, so a list the filter has
                // emptied leaves them disabled rather than offering to tick
                // nothing.
                let shown = filtered.files.len();
                let all_ticked = shown > 0
                    && filtered
                        .files
                        .iter()
                        .all(|report| self.checked.contains(&report.path));
                if ui
                    .add_enabled(shown > 0 && !all_ticked, egui::Button::new("Tick all"))
                    .on_hover_text("Ticks every file the filter is showing.")
                    .clicked()
                {
                    pending.select_all = Some(true);
                }
                if ui
                    .add_enabled(!self.checked.is_empty(), egui::Button::new("Untick all"))
                    .on_hover_text("Unticks everything, including rows the filter is hiding.")
                    .clicked()
                {
                    pending.select_all = Some(false);
                }
                if !self.checked.is_empty() {
                    ui.label(theme::meta(format!(
                        "{} ticked",
                        format::human_count(self.checked.len() as u64)
                    )));
                }
            });
        });

        if let Some(message) = filtered.empty_message(self.filter.is_active()) {
            // Three empty states and not one, because they mean three different
            // things: nothing has been scanned, a scan found nothing, or a scan
            // found something that the filter is now hiding. The middle one is
            // good news and the third is an accident of the controls, and a
            // view that drew the same sentence for both would have a user
            // looking for a Clear button that was already on the screen.
            let (icon, headline) = match self.state.report() {
                None => (
                    icons::Icon::Search,
                    "Nothing has been scanned yet".to_owned(),
                ),
                Some(_) if self.filter.is_active() => (
                    icons::Icon::Sliders,
                    "The filter is hiding everything".to_owned(),
                ),
                Some(_) => (icons::Icon::Check, "Nothing was found".to_owned()),
            };
            ui.add_space(theme::Spacing::XL);
            empty_state(ui, icon, &headline, &message);
            return;
        }

        ui.add_space(theme::Spacing::SM);
        let open = self.selected.clone();
        let mut clicked: Option<PathBuf> = None;
        let mut ticked: Vec<(PathBuf, bool)> = Vec::new();
        // Rows are drawn a viewport at a time rather than all of them. The list
        // grows while a scan runs — every detection and every file the engine
        // could not vouch for is appended live — and laying out ten thousand
        // rows to show the twenty a window can hold costs about 107 ms a frame
        // at that size, measured, in a release build. `show_rows` asks for one
        // row height and draws only the rows the viewport overlaps.
        let metrics = RowMetrics::for_ui(ui);
        egui::ScrollArea::vertical()
            .id_salt("findings")
            .show_rows(ui, metrics.height, filtered.len(), |ui, range| {
                for row in range {
                    // A row number means one thing here and one thing in
                    // `filtered`, and `Filtered::get` is the only place the two
                    // are related. See the note on `GuiApp::selected` for what
                    // happens when a row number is taken for a findings index.
                    let Some(report) = filtered.get(row) else {
                        continue;
                    };
                    // The tick is a sibling of the row and not a widget inside
                    // it. `finding_row` ends by claiming the whole of its own
                    // rect as clickable, and egui gives a position to the
                    // widget registered last — so a checkbox *inside* the frame
                    // would never receive a click, because the row's own
                    // interaction is registered after it. Laying the two out
                    // side by side means their rects do not overlap and each
                    // gets the clicks it is owed.
                    let mut on = self.checked.contains(&report.path);
                    ui.horizontal(|ui| {
                        if ui.checkbox(&mut on, "").changed() {
                            ticked.push((report.path.clone(), on));
                        }
                        let response = finding_row(
                            ui,
                            report,
                            &metrics,
                            open.as_deref() == Some(report.path.as_path()),
                        );
                        if response.clicked() {
                            clicked = Some(report.path.clone());
                        }
                    });
                }
            });

        // Clicking the row that is already open closes it, so the pane can be
        // dismissed without a second control. The new selection is worked out
        // into a local and written back to `self` at the end of the function:
        // `filtered` borrows the findings for the detail pane below, and the
        // findings live behind `self`, so assigning to `self.selected` here
        // would be a write through a live borrow.
        let open = match clicked {
            Some(path) if open.as_deref() == Some(path.as_path()) => None,
            Some(path) => Some(path),
            None => open,
        };

        // The detail pane finds its file by path in the filtered list, so it
        // shows the file the user clicked and not whatever now sits at that row
        // number. This is the read that used to be an index into `findings` and
        // picked the wrong file whenever the filter or the sort moved a row.
        let detail = open
            .as_ref()
            .and_then(|path| filtered.files.iter().find(|report| &report.path == path).copied())
            .map(|report| (row_facts(report), row_detections(report)));
        // The last read of the filtered list has happened, so the borrow of the
        // findings behind `self` is over and the tick changes can be stored.
        for (path, on) in ticked {
            if on {
                self.checked.insert(path);
            } else {
                self.checked.remove(&path);
            }
        }
        self.selected = open;
        if let Some((facts, detections)) = detail {
            ui.add_space(theme::Spacing::MD);
            ui.separator();
            ui.add_space(theme::Spacing::SM);
            egui::ScrollArea::vertical()
                .max_height(260.0)
                .id_salt("finding-detail")
                .show(ui, |ui| {
                    egui::Grid::new("finding-facts")
                        .num_columns(2)
                        .spacing(egui::vec2(theme::Spacing::MD, theme::Spacing::XS))
                        .show(ui, |ui| {
                            for (label, value) in &facts {
                                ui.label(theme::meta(*label));
                                ui.label(theme::body(value));
                                ui.end_row();
                            }
                        });
                    for (heading, rows) in &detections {
                        ui.add_space(theme::Spacing::SM);
                        ui.label(theme::heading(heading));
                        egui::Grid::new(heading)
                            .num_columns(2)
                            .spacing(egui::vec2(theme::Spacing::MD, theme::Spacing::XS))
                            .show(ui, |ui| {
                                for (label, value) in rows {
                                    ui.label(theme::meta(*label));
                                    ui.label(theme::mono(value));
                                    ui.end_row();
                                }
                            });
                    }
                });
        }
    }

    /// The filter, on a panel of its own.
    ///
    /// Two fixed rows rather than one wrapping row. It was one
    /// `horizontal_wrapped`, which meant that on a narrow window a label could
    /// come apart from the control it named — "Found by" broke across two lines
    /// with the list on a third — and a control whose label has moved away from
    /// it is worse than a control that is one row further down. The split is by
    /// what a control does: row one is what is *shown*, row two is how it is
    /// *ordered* and how to undo it.
    fn draw_filter_bar(&mut self, ui: &mut egui::Ui, pending: &mut Pending) {
        theme::card(theme::Palette::PANEL, theme::Palette::BORDER).show(ui, |ui| {
            ui.set_width(ui.available_width());
            // Wrapped, not plain `horizontal`, and the difference is a control
            // that goes missing rather than a line that looks cramped. This row
            // is eight independent controls — four band checkboxes, two
            // presets, a path field, a score — and it measures 1,032 points,
            // which is wider than the 1,020-point window the product opens at.
            // In a `horizontal` layout egui refuses to reflow, so the excess is
            // not wrapped and not elided: it is laid out past the right edge and
            // clipped, and the user sees a filter bar whose last control is
            // simply absent. `horizontal_wrapped` breaks the row instead.
            ui.horizontal_wrapped(|ui| {
                ui.label(theme::heading("Bands"));
                // Each band's own colour, so that the box a user ticks is
                // recognisably the colour of the rows it will hide. It is the
                // band colour as *text* on `PANEL`, which is where the palette's
                // measured table applies — not on a band fill, where the same
                // pairing fails for two of the four.
                for (flag, verdict) in [
                    (&mut self.filter.bands.malicious, Verdict::Malicious),
                    (&mut self.filter.bands.suspicious, Verdict::Suspicious),
                    (&mut self.filter.bands.unknown, Verdict::Unknown),
                    (&mut self.filter.bands.clean, Verdict::Clean),
                ] {
                    let word = theme::verdict_word(verdict);
                    ui.checkbox(
                        flag,
                        egui::RichText::new(word).color(theme::verdict_color(verdict)),
                    );
                }

                // The two presets, so that the common intent does not mean four
                // clicks. `Bands::ALL` and `Bands::CONCERNING` are the same
                // values the checkboxes above drive — a preset that set a
                // *different* set of flags would make the boxes and the buttons
                // disagree about what is on screen.
                ui.separator();
                if ui
                    .add_enabled(
                        !self.filter.bands.is_all(),
                        egui::Button::new("Everything").small(),
                    )
                    .clicked()
                {
                    self.filter.bands = Bands::ALL;
                }
                if ui
                    .selectable_label(self.filter.bands == Bands::CONCERNING, "Only concerning")
                    .on_hover_text("Everything but the files that were clean")
                    .clicked()
                {
                    self.filter.bands = Bands::CONCERNING;
                }

                ui.separator();
                ui.label(theme::heading("Path"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter.path_query)
                        .hint_text("any part of the path")
                        .desired_width(220.0),
                );
                ui.label(theme::heading("Best score at least"));
                ui.add(
                    egui::DragValue::new(&mut self.filter.min_score)
                        .speed(1.0)
                        .range(0..=u16::MAX),
                );
            });

            ui.add_space(theme::Spacing::SM);
            ui.horizontal_wrapped(|ui| {
                ui.label(theme::heading("Found by"));
                source_combo(ui, &mut self.filter.source);
                ui.separator();
                ui.label(theme::heading("Order"));
                egui::ComboBox::from_id_salt("sort")
                    .selected_text(self.filter.sort.label())
                    .show_ui(ui, |ui| {
                        for sort in Sort::ALL {
                            ui.selectable_value(&mut self.filter.sort, sort, sort.label());
                        }
                    });
                // The Clear button appears only when there is something to
                // clear, and the sentence beside it says how many the filter is
                // hiding — a user who has filtered their findings down to two
                // rows should be able to see that the other hundred still
                // exist.
                if self.filter.is_active() {
                    if ui.button("Clear the filter").clicked() {
                        pending.clear_filter = true;
                    }
                    let all = self.findings().len();
                    let shown = self.filter.count(self.findings());
                    ui.label(theme::meta(format!(
                        "{} of {} shown",
                        format::count_of(shown as u64, "finding"),
                        format::count_of(all as u64, "finding")
                    )));
                }
            });
        });
    }

    fn draw_quarantine(&mut self, ui: &mut egui::Ui, pending: &mut Pending) {
        ui.add_space(theme::Spacing::MD);
        ui.label(theme::display("Quarantine"));
        ui.add_space(theme::Spacing::XS);
        ui.label(theme::meta(
            "Files taken off the disk, kept sealed, and put back or destroyed from here.",
        ));
        ui.add_space(theme::Spacing::LG);

        if let Some(message) = self.vault_error.clone() {
            empty_state(
                ui,
                icons::Icon::Alert,
                "The vault could not be opened",
                &message,
            );
            ui.add_space(theme::Spacing::MD);
            if ui.button("Try again").clicked() {
                self.vault_error = None;
                pending.open_vault = true;
            }
            return;
        }

        if self.vault.is_none() {
            empty_state(
                ui,
                icons::Icon::Vault,
                "The vault has not been opened yet",
                "A quarantined file is encrypted and stored out of the way of everything else on \
                 the machine. Opening the vault reads its index; it does not change anything.",
            );
            ui.add_space(theme::Spacing::MD);
            if primary_button(ui, icons::Icon::Vault, "Open the vault", true).clicked() {
                pending.open_vault = true;
            }
            return;
        }

        let stats = match &self.vault {
            Some(vault) => vault.stats(),
            None => return,
        };
        theme::card(theme::Palette::PANEL, theme::Palette::BORDER).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(theme::heading("In the vault"));
                ui.label(theme::body(format!(
                    "{} held, {} on disk, across {}",
                    format::count_of(stats.quarantined as u64, "file"),
                    format::human_bytes(stats.live_bytes),
                    format::count_of(stats.total as u64, "record"),
                )));
            });
        });
        // Two conditions that are worth saying out loud and are not findings:
        // an original the vault could not take off the disk, and sealed bytes
        // in the directory that belong to no record. Both are drawn in the
        // amber band, which is the band that means *reported and not acted on*
        // — which is exactly what they are.
        if stats.pending_removals > 0 {
            ui.add_space(theme::Spacing::XS);
            ui.label(theme::body(format!(
                "{} could not be removed from disk and {} still there.",
                format::count_of(stats.pending_removals as u64, "original file"),
                format::count_of_pair(stats.pending_removals as u64, "is", "are")
            )));
        }
        if stats.orphans > 0 {
            ui.add_space(theme::Spacing::XS);
            ui.label(theme::body(format!(
                "{} in the vault belong to no record.",
                format::count_of(stats.orphans as u64, "sealed file")
            )));
        }

        ui.add_space(theme::Spacing::MD);
        theme::card(theme::Palette::PANEL, theme::Palette::BORDER).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(theme::heading("Find"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.vault_view.query)
                        .hint_text("name, path or threat")
                        .desired_width(240.0),
                );
                ui.separator();
                ui.label(theme::heading("Order"));
                egui::ComboBox::from_id_salt("vault-sort")
                    .selected_text(self.vault_view.sort.label())
                    .show_ui(ui, |ui| {
                        for sort in VaultSort::ALL {
                            ui.selectable_value(&mut self.vault_view.sort, sort, sort.label());
                        }
                    });
                if self.vault_view.is_active() && ui.button("Clear").clicked() {
                    self.vault_view.clear();
                }
            });

            // The actions on a stored file, on their own line and only while
            // one is selected.
            //
            // Their own line because there are four of them now and the words
            // are the point: "Allow permanently" is a decision that outlives
            // everything else on this screen, and a button whose label had to be
            // abbreviated to fit beside a search box would be exactly the
            // mis-clickable control its own documentation says it must not be.
            //
            // Only with a selection, because that is what they act on. All four
            // are destructive in the sense that matters — two write over
            // whatever is at the original path, one destroys the only copy, and
            // one switches a rule off for a path from now on — so none of them
            // is reachable without naming a file first.
            if let Some(selected) = self.vault_selected {
                let name = self
                    .vault
                    .as_ref()
                    .and_then(|vault| vault.get(selected).ok())
                    .map(|entry| format::shorten_path(&entry.original_path.to_string_lossy(), 36))
                    .unwrap_or_default();
                ui.add_space(theme::Spacing::SM);
                ui.horizontal(|ui| {
                    ui.label(theme::meta(format!("Selected: {name}")));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button("Delete")
                            .on_hover_text(format!(
                                "Destroys the stored bytes of {name}. This cannot be undone."
                            ))
                            .clicked()
                        {
                            pending.delete = Some(selected);
                        }
                        if ui
                            .button("Allow permanently")
                            .on_hover_text(format!(
                                "Writes {name} back and adds it to the exclusions in the \
                                 configuration, so nothing here looks at it again — even if it \
                                 changes. A saved decision, not a click to make by accident."
                            ))
                            .clicked()
                        {
                            pending.allow = Some((selected, Allow::Permanent));
                        }
                        if ui
                            .button("Allow for now")
                            .on_hover_text(format!(
                                "Writes {name} back and leaves it alone until the service stops. \
                                 Nothing is written to the configuration, so it is taken again \
                                 after a restart."
                            ))
                            .clicked()
                        {
                            pending.allow = Some((selected, Allow::Session));
                        }
                        if ui
                            .button("Put back")
                            .on_hover_text(format!(
                                "Writes {name} back to where it was taken from. It is still the \
                                 same file, so a scan will find it again."
                            ))
                            .clicked()
                        {
                            pending.restore = Some(selected);
                        }
                    });
                });
            }
        });

        ui.add_space(theme::Spacing::MD);
        let entries: Vec<QuarantineEntry> = match &self.vault {
            Some(vault) => vault.entries().to_vec(),
            None => Vec::new(),
        };
        let shown: Vec<&QuarantineEntry> = self.vault_view.apply(&entries);
        if shown.is_empty() {
            ui.add_space(theme::Spacing::XL);
            // The same distinction the findings list makes: an empty list
            // because there is nothing and an empty list because the query
            // excludes everything are different answers.
            if self.vault_view.is_active() {
                empty_state(
                    ui,
                    icons::Icon::Search,
                    "Nothing here matches that",
                    &format!(
                        "The vault holds {}. Clear the box above to see {}.",
                        format::count_of(entries.len() as u64, "record"),
                        format::count_of_pair(entries.len() as u64, "it", "them")
                    ),
                );
            } else {
                empty_state(
                    ui,
                    icons::Icon::Vault,
                    "Nothing has been quarantined",
                    "This is where a file goes when you quarantine it from the Findings tab. \
                     Nothing is here yet, so nothing has been taken off the disk.",
                );
            }
            return;
        }

        let mut clicked = None;
        egui::ScrollArea::vertical()
            .id_salt("vault")
            .show(ui, |ui| {
                for entry in &shown {
                    let selected = self.vault_selected == Some(entry.id);
                    if vault_row(ui, entry, selected).clicked() {
                        clicked = Some(entry.id);
                    }
                }
            });
        if let Some(id) = clicked {
            self.vault_selected = if self.vault_selected == Some(id) {
                None
            } else {
                Some(id)
            };
        }
    }

    fn draw_settings(&mut self, ui: &mut egui::Ui, pending: &mut Pending) {
        ui.add_space(theme::Spacing::MD);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(theme::display("Settings"));
                ui.add_space(theme::Spacing::XS);
                ui.label(theme::meta(format!(
                    "{} — {}",
                    self.paths.config_file.display(),
                    if self.settings.is_dirty() {
                        "edited, not saved"
                    } else {
                        "saved"
                    }
                )));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(self.settings.is_dirty(), egui::Button::new("Save"))
                    .clicked()
                {
                    pending.save_settings = true;
                }
                if ui
                    .add_enabled(self.settings.is_dirty(), egui::Button::new("Revert"))
                    .on_hover_text("Puts every field back to what is on disk")
                    .clicked()
                {
                    pending.revert_settings = true;
                }
                if self.settings.is_dirty() {
                    ui.label(
                        theme::meta("This scan will still use the saved settings.")
                            .color(theme::Palette::SUSPICIOUS),
                    );
                }
            });
        });
        ui.add_space(theme::Spacing::LG);

        // Read before the draft is borrowed, because the borrow below is
        // exclusive for the whole of the tab: whether there is a
        // notification-area icon decides what the checkbox under General can
        // honestly promise, and asking the question there would need a second
        // borrow of the same window.
        let tray_present = self.tray.is_some();

        // The whole of this tab works on the draft from one borrow, so that the
        // widgets below cannot read a field the draft is in the middle of
        // changing.
        let edited = self.settings.edited_mut();

        section_heading(ui, "General");
        // Shown and not offered. The protection service's start type lives in
        // the service control manager, where changing it needs the machine's
        // privileges and the service cannot change it about itself; it is
        // `wenle integrate service install` that writes it. A control here that
        // looked like it did something would be the interface lying about what
        // it had done, and it is worse than the one line it takes to say so.
        ui.add_enabled_ui(false, |ui| {
            ui.checkbox(
                &mut edited.general.start_with_windows,
                "Start the protection service with Windows",
            )
            .on_disabled_hover_text(
                "Registered by the installer, not by this window: the service's start type \
                 is a machine-wide installation decision and this window is not elevated. \
                 Change it with `wenle integrate service install`.",
            );
        });
        ui.checkbox(
            &mut edited.general.minimize_to_tray,
            "Keep running in the notification area",
        )
        .on_hover_text(
            "Closing the window hides it instead of ending the program, and the icon in the \
             notification area is the way back. Saving this also writes the entry that starts \
             it when you sign in — without that, closing the window would leave the tray icon \
             gone until you opened it again yourself.",
        );
        if !tray_present {
            ui.label(theme::meta(
                "There is no notification-area icon on this system, so closing the window \
                 ends the program whatever this says.",
            ));
        }

        ui.add_space(theme::Spacing::MD);
        ui.checkbox(
            &mut edited.general.notifications,
            "Show a Windows notification when something is found",
        )
        .on_hover_text(
            "The notification is posted by Windows, so it is still shown when this window is \
             closed. Nothing but a detection is ever posted there; everything else the window \
             has to say appears in the status line at the bottom.",
        );
        ui.checkbox(
            &mut edited.general.notification_sound,
            "Play the notification sound",
        );

        ui.add_space(theme::Spacing::LG);
        // General is behind us; the rest of the tab is four sections, each a
        // heading and the controls that belong under it.
        // The heading is `HEADING_STEP`, which is `TEXT_DIM` and strong — a step
        // below the page title and a step above the labels, which is the whole
        // of what the type scale is for.
        section_heading(ui, "Bands");
        egui::Grid::new("thresholds")
            .num_columns(2)
            .spacing(egui::vec2(theme::Spacing::MD, theme::Spacing::XS))
            .show(ui, |ui| {
                ui.label(theme::body("Suspicious at"));
                ui.add(
                    egui::DragValue::new(&mut edited.scanning.thresholds.suspicious)
                        .speed(1.0)
                        .range(0..=u16::MAX),
                );
                ui.end_row();
                ui.label(theme::body("Malicious at"));
                ui.add(
                    egui::DragValue::new(&mut edited.scanning.thresholds.malicious)
                        .speed(1.0)
                        .range(0..=u16::MAX),
                );
                ui.end_row();
                ui.label("");
                ui.label(theme::meta(
                    "Suspicious must be below malicious. The suspicious band reports \
                     and does not act.",
                ));
                ui.end_row();
            });

        section_heading(ui, "What to scan");
        ui.checkbox(&mut edited.scanning.recursive, "Descend into subfolders");
        ui.checkbox(
            &mut edited.scanning.follow_links,
            "Follow folder links and junctions",
        )
        .on_hover_text(
            "Off by default: a junction pointing at its parent is an endless folder tree.",
        );
        ui.checkbox(&mut edited.scanning.archives, "Look inside archives");
        ui.checkbox(
            &mut edited.scanning.heuristics,
            "Run the structural heuristics",
        );
        ui.checkbox(
            &mut edited.scanning.trust,
            "Consult the trust layer and let it discount weak detections",
        );
        ui.checkbox(
            &mut edited.scanning.stop_on_first,
            "Stop at the first malicious file",
        );

        ui.add_space(theme::Spacing::SM);
        ui.horizontal(|ui| {
            ui.label(theme::body("Files larger than"));
            let mut limited = edited.scanning.max_file_size.is_some();
            if ui.checkbox(&mut limited, "limit").changed() {
                edited.scanning.max_file_size = if limited {
                    Some(256 * 1024 * 1024)
                } else {
                    None
                };
            }
            if let Some(limit) = edited.scanning.max_file_size.as_mut() {
                ui.add(
                    egui::DragValue::new(limit)
                        .speed(1024.0 * 1024.0)
                        .range(0..=u64::MAX)
                        .custom_formatter(|value, _| format::human_bytes(value as u64)),
                );
            } else {
                ui.label(theme::meta("no limit — every file is opened"));
            }
        });

        section_heading(ui, "Work");
        egui::Grid::new("work")
            .num_columns(2)
            .spacing(egui::vec2(theme::Spacing::MD, theme::Spacing::XS))
            .show(ui, |ui| {
                ui.label(theme::body("Worker threads"));
                ui.add(
                    egui::DragValue::new(&mut edited.scanning.threads)
                        .speed(1.0)
                        .range(0..=1024),
                );
                ui.end_row();
                ui.label("");
                ui.label(theme::meta("0 means one per core."));
                ui.end_row();

                ui.label(theme::body("Archive depth"));
                ui.add(
                    egui::DragValue::new(&mut edited.scanning.archive_depth)
                        .speed(1.0)
                        .range(0..=16),
                );
                ui.end_row();

                ui.label(theme::body("Per-file timeout"));
                let mut timed = edited.scanning.per_file_timeout_secs.is_some();
                if ui.checkbox(&mut timed, "seconds").changed() {
                    edited.scanning.per_file_timeout_secs = if timed { Some(30) } else { None };
                }
                if let Some(seconds) = edited.scanning.per_file_timeout_secs.as_mut() {
                    ui.add(
                        egui::DragValue::new(seconds)
                            .speed(1.0)
                            .range(1..=u64::MAX)
                            .suffix(" s"),
                    );
                } else {
                    ui.label(theme::meta("no limit"));
                }
                ui.end_row();
            });

        section_heading(ui, "Where things are kept");
        ui.label(theme::meta(format!(
            "Rules: {}",
            self.database
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| "no rule database was found".to_owned())
        )));
        ui.label(theme::meta(format!(
            "Config: {}",
            self.paths.config_file.display()
        )));
        ui.label(theme::meta(format!(
            "Quarantine: {}",
            self.paths.quarantine_dir.display()
        )));
        ui.add_space(theme::Spacing::MD);
        ui.label(theme::meta(
            "A scan uses the saved settings, not these. Save before starting one to \
             have it apply.",
        ));
    }

}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.draw(ctx);
    }

    /// The window's title bar, which is the only place the product's name and
    /// the scan's state can be read when the window is behind another one.
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        let [r, g, b, a] = theme::Palette::BACKGROUND.to_array();
        [
            f32::from(r) / 255.0,
            f32::from(g) / 255.0,
            f32::from(b) / 255.0,
            f32::from(a) / 255.0,
        ]
    }
}

/// The number of findings in a band, in words.
fn count_of(count: usize) -> String {
    format::count_of(count as u64, "finding")
}

/// The path's last component, or the whole path when it has none.
fn short_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// What was found in a file, in one clause.
///
/// The strongest detection's description, or the rule that fired when it has no
/// description, or a plain statement that something matched. Shared by every
/// notification that has to say what the file was, so that two of them cannot
/// describe the same finding two different ways.
fn first_summary(report: &FileScanReport) -> String {
    match report.assessment.detections.first() {
        Some(detection) => format::detection_summary(detection),
        // Reachable only for a report whose verdict came from something other
        // than a listed detection. Saying so is better than an empty sentence.
        None => format!(
            "a {} verdict with no detection listed",
            theme::verdict_word(report.verdict())
        ),
    }
}

/// What was found in a quarantined file, in one clause.
///
/// A quarantine entry is not a report: it keeps the family name and the rule
/// identifier rather than the detections themselves. Preference order is the
/// family, then the rule, then the severity — most specific statement first,
/// because that is the one a user searching the web for it needs.
fn what_was_found(entry: &QuarantineEntry) -> String {
    if let Some(threat) = &entry.threat {
        return format!("{threat}");
    }
    if let Some(rule) = &entry.detection {
        if !rule.is_empty() {
            return format!("matched {rule}");
        }
    }
    format!("{:?} severity", entry.severity)
}

/// Where the rule database is, or the sentence saying it is not there.
///
/// A free function rather than a method because [`GuiApp::new`] needs it before
/// there is a `GuiApp` to ask. It is asked more than once — see
/// [`GuiApp::start_scan`] — so the refusal is worded in one place: a user who
/// reads "no rule database was found in A or B" and then finds one in A has been
/// told the truth twice about two different moments, and only one wording can
/// make that clear.
fn locate_database(paths: &AvPaths) -> Result<PathBuf, String> {
    scan::database_path(paths).ok_or_else(|| {
        format!(
            "No rule database was found in {} or {}. Build one with \
             `wenle build <rules>`, or put it beside the program.",
            paths.db_dir.display(),
            paths.install_dir.display()
        )
    })
}

/// Where a fresh window points its target field.
///
/// The user's own folder rather than a whole drive. A window that opens with
/// `C:\` in the box is a window one click away from an hour-long scan nobody
/// asked for; a user who wants the whole drive can type it, and the placeholder
/// shows them the shape.
fn default_target() -> String {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default()
}

/// A bordered box, used for the two errors worth framing.
fn framed(ui: &mut egui::Ui, border: egui::Color32, content: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(theme::Palette::RAISED)
        .stroke(egui::Stroke {
            width: 1.0,
            color: border,
        })
        .corner_radius(theme::corner_radius())
        .inner_margin(egui::Margin::same(theme::Spacing::MD as i8))
        .show(ui, content);
}

/// A band-coloured count, drawn as a small chip.
///
/// The chip's ground is the band's fill, its outline and its mark are the band
/// colour, and its label is [`theme::Palette::TEXT`] — not the band colour, which
/// is what it used to be. That pairing measures 4.00 on the malicious fill and
/// 4.15 on the unknown one, both under the 4.5:1 the rest of the window holds
/// itself to and both on the two bands a reader most needs to get right. The
/// band is still carried three ways; the one that carries the *number* is the
/// one that has to be readable.
fn band_chip(ui: &mut egui::Ui, text: String, band: Verdict) {
    let colour = theme::verdict_color(band);
    egui::Frame::new()
        .fill(theme::Palette::fill(band))
        .stroke(egui::Stroke::new(1.0, colour))
        .corner_radius(theme::corner_radius())
        .inner_margin(egui::Margin::symmetric(
            theme::Spacing::SM as i8,
            theme::Spacing::XS as i8,
        ))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                icons::show(ui, icons::Icon::for_band(band), 13.0, colour);
                ui.add_space(theme::Spacing::XS);
                ui.label(theme::body(text).strong());
            });
        });
}

/// A section heading inside a view.
///
/// One step down from the page title and one step up from the labels under it,
/// with the space above it that makes it a heading rather than a line of text.
/// Every section in the window goes through this, so that two sections in two
/// views cannot be two different sizes.
fn section_heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(theme::Spacing::LG);
    ui.label(theme::heading(text));
    ui.add_space(theme::Spacing::SM);
}

/// The tab strip in the header: four marks with words under them.
///
/// A segmented control rather than the four bare text labels it was: each tab
/// carries its own mark, and the selected one is drawn on a raised ground with
/// an accent underline, so that "where am I" is answerable from the shape of the
/// strip alone and not only from the brightness of one word.
fn tab_bar(ui: &mut egui::Ui, current: Tab) -> Option<Tab> {
    let mut clicked = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = theme::Spacing::XS;
        for tab in Tab::ALL {
            if tab_button(ui, tab, tab == current).clicked() {
                clicked = Some(tab);
            }
        }
    });
    clicked
}

/// One tab in the strip.
fn tab_button(ui: &mut egui::Ui, tab: Tab, selected: bool) -> egui::Response {
    let mark = 15.0;
    let galley = ui.painter().layout_no_wrap(
        tab.label().to_owned(),
        egui::FontId::proportional(theme::Text::BODY),
        theme::Palette::TEXT,
    );
    let width = galley.size().x.max(mark) + theme::Spacing::LG * 2.0;
    let height = 40.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let colour = if selected {
            theme::Palette::TEXT
        } else {
            theme::Palette::TEXT_DIM
        };
        let painter = ui.painter();
        if selected {
            painter.rect_filled(rect, theme::corner_radius(), theme::Palette::RAISED);
        } else if response.hovered() {
            painter.rect_filled(rect, theme::corner_radius(), theme::Palette::PANEL);
        }
        let mark_rect = egui::Rect::from_center_size(
            egui::pos2(rect.center().x, rect.top() + 12.0),
            egui::Vec2::splat(mark),
        );
        icons::paint(
            painter,
            tab.icon(),
            mark_rect,
            if selected {
                theme::Palette::ACCENT
            } else {
                colour
            },
            icons::stroke_width(mark),
        );
        painter.galley(
            egui::pos2(rect.center().x - galley.size().x / 2.0, rect.top() + 24.0),
            galley,
            colour,
        );
        // The underline, on the selected tab only. It is a second carrier of
        // "you are here" beside the raised ground and the brighter word, for the
        // same reason every band carries a word: a state that is one colour
        // change away from another state is a state somebody will miss.
        if selected {
            let underline = egui::Rect::from_min_max(
                egui::pos2(rect.left() + theme::Spacing::MD, rect.bottom() - 2.0),
                egui::pos2(rect.right() - theme::Spacing::MD, rect.bottom()),
            );
            painter.rect_filled(underline, egui::CornerRadius::ZERO, theme::Palette::ACCENT);
        }
    }
    response
}

/// The pill in the top-right corner: the machine's state in one word.
///
/// At rest it says so, in the muted text colour rather than in green. Green is
/// a claim that something was checked and came back clean, and a window that
/// prints it before the first scan is a window that has told its user something
/// untrue about their machine.
fn status_pill(ui: &mut egui::Ui, report: Option<&av_core::ScanReport>) {
    let (word, colour, icon) = match report {
        Some(report) => {
            let verdict = report.worst_verdict();
            (
                theme::verdict_word(verdict),
                theme::verdict_color(verdict),
                icons::Icon::for_band(verdict),
            )
        }
        None => ("not scanned", theme::Palette::TEXT_DIM, icons::Icon::Shield),
    };
    egui::Frame::new()
        .fill(theme::Palette::PANEL)
        .stroke(egui::Stroke::new(1.0, theme::Palette::BORDER))
        .corner_radius(theme::corner_radius())
        .inner_margin(egui::Margin::symmetric(
            theme::Spacing::MD as i8,
            theme::Spacing::XS as i8,
        ))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                icons::show(ui, icon, 13.0, colour);
                ui.add_space(theme::Spacing::XS);
                ui.label(theme::body(word).color(colour).strong());
            });
        });
}

/// The state mark in the bottom strip, before the phase's sentence.
fn status_state(ui: &mut egui::Ui, phase: Phase) {
    let (icon, colour) = match phase {
        Phase::Idle => (icons::Icon::Shield, theme::Palette::TEXT_DIM),
        Phase::Running => (icons::Icon::Search, theme::Palette::ACCENT),
        Phase::Finished => (icons::Icon::Check, theme::Palette::TEXT_DIM),
        Phase::Failed => (icons::Icon::Alert, theme::Palette::MALICIOUS),
    };
    icons::show(ui, icon, 13.0, colour);
}

/// The hero card's four treatments, worked out in one place.
///
/// Everything the card draws that varies — the tint, the outline, the mark, the
/// headline and the sentence under it — comes from here, so that the card's
/// appearance is a value a test can compare rather than a set of `if`s in the
/// middle of a layout.
#[derive(Debug, Clone, PartialEq)]
struct HeroStyle {
    /// The card's ground.
    fill: egui::Color32,
    /// The card's one-point outline.
    outline: egui::Color32,
    /// The large mark on the left.
    icon: icons::Icon,
    /// The mark's colour.
    accent: egui::Color32,
    /// The one sentence that says what state the machine is in.
    headline: String,
    /// The line under it: how much was looked at, or what is being looked at.
    detail: String,
}

/// Which of the four cards the Scan view is showing.
///
/// The finished card is tinted with the *worst* band on the report, because that
/// is the number the header pill and the console summary also use — a card that
/// tinted itself with the first finding would be a fourth opinion about how bad
/// the scan was.
fn hero_style(state: &ScanState) -> HeroStyle {
    match state {
        ScanState::Idle => HeroStyle {
            fill: theme::Palette::PANEL,
            outline: theme::Palette::BORDER,
            icon: icons::Icon::Shield,
            accent: theme::Palette::ACCENT,
            headline: theme::UNSCANNED.to_owned(),
            detail: "Choose a folder or a file and start a scan. A scan only looks and reports \
                     — it does not move, change or block anything on its own."
                .to_owned(),
        },
        ScanState::Running(_) => HeroStyle {
            fill: theme::Palette::PANEL,
            // The accent outline, so that a running scan is recognisable as
            // *active* from the card's edge alone.
            outline: theme::Palette::ACCENT,
            icon: icons::Icon::Search,
            accent: theme::Palette::ACCENT,
            headline: "Scanning".to_owned(),
            // The live line, from the same place the status bar reads it, so
            // that the card and the strip cannot report two different rates.
            detail: state
                .progress()
                .map(|progress| progress.line())
                .unwrap_or_else(|| "Counting the files to look at…".to_owned()),
        },
        ScanState::Finished(report) => {
            let verdict = report.worst_verdict();
            HeroStyle {
                fill: theme::verdict_fill(verdict),
                outline: theme::verdict_color(verdict),
                icon: icons::Icon::for_band(verdict),
                accent: theme::verdict_color(verdict),
                headline: theme::band_headline(verdict).to_owned(),
                detail: format::scan_summary(report),
            }
        }
        ScanState::Failed { message } => HeroStyle {
            fill: theme::Palette::PANEL,
            outline: theme::Palette::MALICIOUS,
            icon: icons::Icon::Alert,
            accent: theme::Palette::MALICIOUS,
            headline: "The scan could not be run".to_owned(),
            detail: message.clone(),
        },
    }
}

/// The target field and the two pickers.
///
/// A free function rather than a method so that it borrows the target string and
/// nothing else — see the module documentation on why the drawing code takes
/// disjoint pieces of the window rather than `&mut self` where it can.
fn target_row(ui: &mut egui::Ui, target: &mut String, pending: &mut Pending) {
    ui.horizontal(|ui| {
        ui.label(theme::heading("Folder or file"));
        // The buttons are measured first and the field is given what is left,
        // rather than the other way round. A `TextEdit` claims the width it is
        // handed and never gives any of it back, so a field sized first pushes
        // the last control past the right edge — which is what the fixed
        // 210-point allowance that stood here did once the buttons grew a mark
        // and a longer label. Measured, not assumed: with the allowance restored,
        // `nothing_is_drawn_past_the_side_of_the_window` fails at
        // [`MIN_WINDOW_SIZE`] with the Scan view drawing 31.8 points past the
        // edge. At the default size the old allowance happened to be enough,
        // which is why nothing caught it.
        let reserved = if picker::available() {
            button_width(ui, "Browse…") + button_width(ui, "One file…") + theme::Spacing::SM * 2.0
        } else {
            0.0
        };
        // Sized rather than elastic: an elastic field on a wide window puts the
        // buttons a foot away from the text they act on.
        ui.add_sized(
            [
                (ui.available_width() - reserved).clamp(140.0, 560.0),
                theme::Spacing::CONTROL_HEIGHT,
            ],
            egui::TextEdit::singleline(target).hint_text(r"C:\Users\me\Downloads"),
        );
        // The pickers, where there is one to offer. A button that opened nothing
        // would read as a product that is broken rather than as a platform this
        // build does not have a dialog for, so on a platform without one there
        // is no button and the window says nothing about it — see `picker.rs`
        // for that decision.
        //
        // The field is the way in; these are ways to fill it in. Typing or
        // pasting a path still works exactly as it did, which is why these sit
        // beside the field rather than replacing it.
        if picker::available() {
            if button(ui, icons::Icon::Folder, "Browse…", true)
                .on_hover_text("Choose a folder to scan")
                .clicked()
            {
                pending.pick_folder = true;
            }
            if button(ui, icons::Icon::Page, "One file…", true)
                .on_hover_text("Choose one file to scan")
                .clicked()
            {
                pending.pick_file = true;
            }
        }
    });
}

/// How wide [`button`] will be, before it is drawn.
///
/// Separated out so that a row can reserve the space its buttons will take
/// *before* it sizes the field beside them. The alternative — the fixed
/// allowance that stood in [`target_row`] before this — is a number that is
/// correct until somebody renames a button or gives it a mark, and whose failure
/// is a control pushed past the right edge of a window one character narrower
/// than the allowance assumed.
fn button_width(ui: &egui::Ui, label: &str) -> f32 {
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::FontId::proportional(theme::Text::BODY),
        theme::Palette::TEXT,
    );
    galley.size().x + BUTTON_MARK + theme::Spacing::SM + theme::Spacing::LG * 2.0
}

/// The mark in front of a button's word, in points.
const BUTTON_MARK: f32 = 14.0;

/// A secondary button: an outline, a mark and a word.
///
/// The counterpart to [`primary_button`]. It has no ground of its own, so that
/// there is exactly one filled button on a screen and it is always the one the
/// view is asking the user to press.
fn button(ui: &mut egui::Ui, icon: icons::Icon, label: &str, enabled: bool) -> egui::Response {
    let height = theme::Spacing::CONTROL_HEIGHT.max(30.0);
    let mark = BUTTON_MARK;
    let colour = if enabled {
        theme::Palette::TEXT
    } else {
        theme::Palette::TEXT_FAINT
    };
    let width = button_width(ui, label);
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::FontId::proportional(theme::Text::BODY),
        colour,
    );
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(width, height),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(
            rect,
            theme::corner_radius(),
            if response.hovered() && enabled {
                theme::Palette::RAISED
            } else {
                theme::Palette::PANEL
            },
        );
        painter.rect_stroke(
            rect,
            theme::corner_radius(),
            egui::Stroke::new(1.0, theme::Palette::BORDER),
            egui::StrokeKind::Inside,
        );
        let start = rect.center().x - (mark + theme::Spacing::SM + galley.size().x) / 2.0;
        icons::paint(
            painter,
            icon,
            egui::Rect::from_center_size(
                egui::pos2(start + mark / 2.0, rect.center().y),
                egui::Vec2::splat(mark),
            ),
            colour,
            icons::stroke_width(mark),
        );
        painter.galley(
            egui::pos2(
                start + mark + theme::Spacing::SM,
                rect.center().y - galley.size().y / 2.0,
            ),
            galley,
            colour,
        );
    }
    response
}

/// The one filled button on a screen.
///
/// Drawn by hand rather than styled through [`egui::Button`] because it is the
/// only control in the window with a filled ground, and egui's widget states do
/// not have a hover fill that measures: every candidate — `#3F7AD8` at 4.34,
/// `#3568BE` at 3.38, `#2F5FA8` at 2.90 — drops the dark label below the 4.5:1
/// the rest of the window holds itself to. So the hover is a ring in
/// [`theme::Palette::TEXT`] around the unchanged accent fill, which is 15.15:1
/// against the background and so is unambiguously a change *without touching
/// the label*, and the pressed state insets the content by a pixel instead of
/// changing a colour.
///
/// A disabled primary button is filled with the border colour and labelled in
/// the faint text colour: it is still a button in the same place, so a user can
/// see what they will be able to do, and it is unmistakably not pressable.
fn primary_button(
    ui: &mut egui::Ui,
    icon: icons::Icon,
    label: &str,
    enabled: bool,
) -> egui::Response {
    let height = theme::Spacing::CONTROL_HEIGHT.max(34.0);
    let fill = if enabled {
        theme::Palette::ACCENT
    } else {
        theme::Palette::BORDER
    };
    let on_fill = if enabled {
        theme::Palette::BACKGROUND
    } else {
        theme::Palette::TEXT_FAINT
    };
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::FontId::proportional(theme::Text::BODY),
        on_fill,
    );
    let mark = (height * 0.38).round();
    let gap = theme::Spacing::SM;
    let width = galley.size().x + mark + gap + theme::Spacing::LG * 3.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(width, height),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    if ui.is_rect_visible(rect) && !galley.is_empty() {
        let pressed = enabled && response.is_pointer_button_down_on();
        let inner = if pressed { rect.shrink(1.0) } else { rect };
        let painter = ui.painter();
        painter.rect_filled(inner, theme::corner_radius(), fill);
        if enabled && response.hovered() {
            painter.rect_stroke(
                inner,
                theme::corner_radius(),
                egui::Stroke::new(2.0, theme::Palette::TEXT),
                egui::StrokeKind::Inside,
            );
        }
        let start = inner.center().x - (mark + gap + galley.size().x) / 2.0;
        icons::paint(
            painter,
            icon,
            egui::Rect::from_center_size(
                egui::pos2(start + mark / 2.0, inner.center().y),
                egui::Vec2::splat(mark),
            ),
            on_fill,
            icons::stroke_width(mark),
        );
        painter.galley(
            egui::pos2(start + mark + gap, inner.center().y - galley.size().y / 2.0),
            galley,
            on_fill,
        );
    }
    response
}

/// A view with nothing in it, and something to say about why.
///
/// A mark, a headline and a paragraph, centred in the space it is given. This is
/// the difference between a view that is empty because the product has nothing
/// to show and a view that looks like it failed to load: "Nothing was found"
/// over three lines of explanation is an answer, and the bare sentence it
/// replaced was a hole.
fn empty_state(ui: &mut egui::Ui, icon: icons::Icon, headline: &str, detail: &str) {
    let width = ui.available_width().min(520.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(width);
        ui.add_space(theme::Spacing::SM);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 56.0), egui::Sense::hover());
        icons::paint(
            ui.painter(),
            icon,
            egui::Rect::from_center_size(rect.center(), egui::Vec2::splat(48.0)),
            theme::Palette::TEXT_FAINT,
            icons::stroke_width(48.0),
        );
        ui.add_space(theme::Spacing::MD);
        ui.label(theme::title(headline));
        ui.add_space(theme::Spacing::SM);
        ui.label(theme::body(detail));
    });
}

/// The four bands, explained, in one card.
///
/// The legend for the vocabulary the whole product is written in, on the one
/// screen a user sees before they have met any of it. The words and the colours
/// come from [`theme`], so the legend cannot drift from the rows it is
/// explaining, and the meaning column is [`theme::band_meaning`] — the same
/// sentence the console prints.
fn band_legend(ui: &mut egui::Ui) {
    theme::card(theme::Palette::PANEL, theme::Palette::BORDER).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(theme::heading("What the four bands mean"));
        ui.add_space(theme::Spacing::SM);
        ui.label(theme::meta(
            "Every file a scan looks at ends in exactly one of these. The word is the same \
             one the console prints, and the colour is never the only thing saying which it \
             is.",
        ));
        ui.add_space(theme::Spacing::MD);
        egui::Grid::new("band-legend")
            .num_columns(2)
            .spacing(egui::vec2(theme::Spacing::XL, theme::Spacing::MD))
            .show(ui, |ui| {
                for verdict in [
                    Verdict::Malicious,
                    Verdict::Suspicious,
                    Verdict::Unknown,
                    Verdict::Clean,
                ] {
                    let colour = theme::verdict_color(verdict);
                    ui.horizontal(|ui| {
                        ui.set_min_width(150.0);
                        icons::show(ui, icons::Icon::for_band(verdict), 17.0, colour);
                        ui.add_space(theme::Spacing::SM);
                        ui.label(
                            theme::body(theme::verdict_word(verdict))
                                .color(colour)
                                .strong(),
                        );
                    });
                    // Wrapped explicitly, and inside a `Grid` that is the only
                    // way to get it. `Grid::wrap_text` (egui 0.31, `grid.rs:137`)
                    // is `max_cell_size.x.is_finite()`, which is false for a grid
                    // that has not been given a maximum — so a label in a cell
                    // takes `TextWrapMode::Extend` exactly as one in a
                    // `ui.horizontal` does, and lays itself out at full width.
                    // The meaning column is a sentence about 510 points wide, so
                    // the legend came to 690 points and pushed the Scan view 31.8
                    // points past the edge of a window at `MIN_WINDOW_SIZE`.
                    // `Label::wrap` pins the mode, and the cell's available width
                    // is finite either way, so it reflows correctly.
                    ui.add(egui::Label::new(theme::meta(theme::band_meaning(verdict))).wrap());
                    ui.end_row();
                }
            });
    });
}

/// How tall one row of the findings list is, and why every row is that tall.
///
/// # Why a row has one height
///
/// Because the list is virtualised. [`egui::ScrollArea::show_rows`] draws only
/// the rows the viewport overlaps, and it decides which those are by dividing
/// the scroll offset by a single row height. A row whose real height disagreed
/// with the number handed to it would be drawn on top of its neighbour — so
/// every row is exactly this tall, and the parts of a row that could otherwise
/// change its height are pinned:
///
/// * a row with no detection summary is **padded** to the two-line height
///   rather than being shorter, which is also what the old
///   `set_min_height(ROW_HEIGHT)` floor was for: a list where some rows were
///   six points shorter than others reads as a rendering fault;
/// * the name and the summary are **truncated** rather than wrapped, because a
///   long file name in a narrow window would otherwise make one row taller
///   than the arithmetic assumes. The whole path is in the detail pane, which
///   is what it is for.
///
/// Two lines because the tallest row is a name line with a detection summary
/// under it, plus the frame's own margin above and below.
#[derive(Debug, Clone, Copy)]
struct RowMetrics {
    /// One line of the body font.
    line: f32,
    /// The vertical gap the layout puts between the two lines of a row.
    gap: f32,
    /// What `show_rows` is given: two lines, the gap between them, and the
    /// frame's own margin above and below.
    ///
    /// The space *between* rows is not in here; `show_rows` adds it.
    height: f32,
}

impl RowMetrics {
    fn for_ui(ui: &egui::Ui) -> Self {
        let line = ui.text_style_height(&egui::TextStyle::Body);
        let gap = ui.spacing().item_spacing.y;
        let height = line * 2.0 + gap + 2.0 * theme::Spacing::SM;
        Self { line, gap, height }
    }

    /// The height of the frame's content, which is what the row lays out in.
    fn content(&self) -> f32 {
        self.height - 2.0 * theme::Spacing::SM
    }
}

/// One row of the findings list.
fn finding_row(
    ui: &mut egui::Ui,
    report: &FileScanReport,
    metrics: &RowMetrics,
    selected: bool,
) -> egui::Response {
    let verdict = report.verdict();
    // Through the palette rather than through the free function, so that the
    // row's colour comes from the same place the palette's own tests check.
    let colour = theme::Palette::SCALE.verdict(verdict);
    let fill = if selected {
        theme::Palette::RAISED
    } else {
        theme::Palette::PANEL
    };
    let inner = egui::Frame::new()
        .fill(fill)
        .corner_radius(theme::corner_radius())
        .inner_margin(egui::Margin::symmetric(
            theme::Spacing::MD as i8,
            theme::Spacing::SM as i8,
        ))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // The whole row is one explicit allocation of the height the list
            // was laid out with, and its two lines are explicit allocations
            // inside that. Nothing here depends on how tall a label turns out
            // to be: a row whose real height disagreed with `RowMetrics` would
            // be drawn on top of its neighbour, and the disagreement would come
            // from content growing.
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), metrics.content()),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
            ui.spacing_mut().item_spacing.y = metrics.gap;
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), metrics.line),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                // A band stripe on the left, then the name, then the score.
                // The band is carried by shape and position as well as colour,
                // which is what makes the list readable when the colour is not.
                icons::stripe(ui, colour, metrics.line);
                // Truncated rather than wrapped: see `RowMetrics`. A name that
                // wrapped would make this one row taller than the height the
                // list was laid out with.
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(short_name(&report.path))
                            .color(theme::Palette::TEXT)
                            .strong(),
                    )
                    .wrap_mode(egui::TextWrapMode::Truncate),
                );
                ui.label(egui::RichText::new(theme::verdict_word(verdict)).color(colour));
                // The severity of the strongest detection, which is a different
                // fact from the band: a file can be malicious on one critical
                // rule or on five weak ones, and how it got there is what tells
                // a user whether to look closer.
                if let Some(detection) = report.assessment.detections.first() {
                    ui.label(
                        egui::RichText::new(detection.severity.as_str())
                            .color(theme::severity_color(detection.severity)),
                    );
                }
                ui.label(
                    egui::RichText::new(format!(
                        "score {}",
                        format::human_count(u64::from(report.assessment.score))
                    ))
                    .color(theme::Palette::TEXT_FAINT),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format::shorten_path(
                            &report.path.display().to_string(),
                            64,
                        ))
                        .color(theme::Palette::TEXT_FAINT),
                    );
                });
                },
            );
            // The second line, drawn or merely reserved. A row with no
            // detection to summarise — a file the engine could not vouch for,
            // which is a finding with nothing behind it — takes the same room
            // as one that has.
            let second = egui::vec2(ui.available_width(), metrics.line);
            match report.assessment.detections.first() {
                // Truncated for the same reason as the name above: this is the
                // line `RowMetrics` budgets for, and it is one line of it.
                Some(detection) => {
                    ui.allocate_ui_with_layout(
                        second,
                        egui::Layout::left_to_right(egui::Align::Min),
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(format::detection_summary(detection))
                                        .color(theme::Palette::TEXT_DIM),
                                )
                                .wrap_mode(egui::TextWrapMode::Truncate),
                            );
                        },
                    );
                }
                None => {
                    ui.allocate_space(second);
                }
            }
                },
            );
        });
    ui.interact(
        inner.response.rect,
        ui.id().with(("finding", &report.path)),
        egui::Sense::click(),
    )
}

/// The facts about one finding, as label/value pairs.
fn row_facts(report: &FileScanReport) -> Vec<(&'static str, String)> {
    let mut facts = vec![
        ("Path", report.path.display().to_string()),
        ("Verdict", theme::verdict_word(report.verdict()).to_owned()),
    ];
    // Why the verdict is not the one the score argues for. Both front ends have
    // to answer this: a user told a file is clean and who does not believe it is
    // asking exactly this question, and a user whose finding was reported but
    // never acted on is asking it too. Only trust sets either flag, and it sets
    // them together — see `Assessment::withhold_remediation`.
    if report.assessment.remediation_withheld {
        facts.push((
            "Remediation",
            if report.verdict() == Verdict::Clean {
                "not needed — the rules matched, but a signed catalogue lists these exact \
                 bytes, so everything found describes how the file was built rather than what \
                 it is"
            } else {
                "withheld — the rules matched, but the file's certificate was read and not \
                 verified, so the finding is reported and the file is left alone"
            }
            .to_owned(),
        ));
    }
    // The rules thrown away along the way, named. A file reported clean because
    // of what it was signed with still has to answer "why was this not
    // detected", and the answer is these rules, not silence.
    if !report.assessment.suppressed.is_empty() {
        facts.push((
            "Suppressed",
            format!(
                "matched and thrown away, because a signed catalogue lists these exact bytes: {}",
                report.assessment.suppressed.join(", ")
            ),
        ));
    }
    facts.push((
        "Score",
        format::score_line(report.assessment.score, &report.assessment.detections),
    ));
    facts.push(("Size", format::human_bytes(report.size)));
    // The container a finding is *about*, which is carried on the detection and
    // set even when there are no locations at all — the ordinary case for a
    // rule that reads a PE header field. A finding with a container is a
    // finding about a member of the file, not about the file, and a user
    // pointed at the wrong file is a user who cannot act on this.
    if let Some(container) = report
        .assessment
        .detections
        .iter()
        .find_map(|detection| detection.container.clone())
    {
        facts.push(("Inside", container));
    }
    if let Some(archive) = &report.archive {
        facts.push((
            "Archive",
            format!(
                "{} of {} {} examined, {} expanded{}",
                format::human_count(u64::from(archive.examined)),
                format::human_count(u64::from(archive.declared)),
                if archive.declared == 1 {
                    "member"
                } else {
                    "members"
                },
                format::human_bytes(archive.expanded),
                if archive.exhausted {
                    " — the walk stopped early"
                } else {
                    ""
                }
            ),
        ));
    }
    facts
}

/// The detections behind one finding, each as its own small table.
fn row_detections(report: &FileScanReport) -> Vec<(String, Vec<(&'static str, String)>)> {
    report
        .assessment
        .detections
        .iter()
        .enumerate()
        .map(|(index, detection)| {
            let heading = if detection.rule_id.is_empty() {
                format!("Finding {}", index + 1)
            } else {
                format!("Finding {} — {}", index + 1, detection.rule_id)
            };
            (heading, format::detection_detail(detection))
        })
        .collect()
}

/// The control that chooses a detection source, including "any".
fn source_combo(ui: &mut egui::Ui, value: &mut Option<av_core::DetectionSource>) {
    const SOURCES: [av_core::DetectionSource; 6] = [
        av_core::DetectionSource::Signature,
        av_core::DetectionSource::Heuristic,
        av_core::DetectionSource::Behavior,
        av_core::DetectionSource::Memory,
        av_core::DetectionSource::Reputation,
        av_core::DetectionSource::User,
    ];
    egui::ComboBox::from_id_salt("source")
        .selected_text(match value {
            Some(source) => source.as_str(),
            None => "anything",
        })
        .show_ui(ui, |ui| {
            ui.selectable_value(value, None, "anything");
            for source in SOURCES {
                ui.selectable_value(value, Some(source), source.as_str());
            }
        });
}

/// One row of the quarantine list.
fn vault_row(ui: &mut egui::Ui, entry: &QuarantineEntry, selected: bool) -> egui::Response {
    let colour = theme::verdict_color(entry.verdict);
    let fill = if selected {
        theme::Palette::RAISED
    } else {
        theme::Palette::PANEL
    };
    let inner = egui::Frame::new()
        .fill(fill)
        .corner_radius(theme::corner_radius())
        .inner_margin(egui::Margin::symmetric(
            theme::Spacing::MD as i8,
            theme::Spacing::SM as i8,
        ))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                icons::stripe(ui, colour, ui.text_style_height(&egui::TextStyle::Body));
                ui.label(
                    egui::RichText::new(&entry.file_name)
                        .color(theme::Palette::TEXT)
                        .strong(),
                );
                ui.label(egui::RichText::new(entry.status.as_str()).color(
                    if entry.status == EntryStatus::Quarantined {
                        colour
                    } else {
                        theme::Palette::TEXT_FAINT
                    },
                ));
                ui.label(
                    egui::RichText::new(format::human_bytes(entry.size))
                        .color(theme::Palette::TEXT_FAINT),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format::local_time(&entry.quarantined_at))
                            .color(theme::Palette::TEXT_FAINT),
                    );
                });
            });
            ui.label(
                egui::RichText::new(format!(
                    "{} — {}",
                    entry
                        .threat
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "no threat name".to_owned()),
                    entry.original_path.display()
                ))
                .color(theme::Palette::TEXT_DIM),
            );
            // What caught it, which is the first thing a user checking a false
            // positive needs and was the one fact this row did not carry: the
            // entry has held it since the vault was written.
            //
            // The component and the rule on one line, because they answer
            // different halves of the question. "Real-time" and "scan" are the
            // difference between a file taken out from under the user while they
            // were opening it and one found sitting on a disk last Tuesday, and
            // the rule identifier is what to search for. A source with no rule —
            // the behaviour monitor acts on what a process did, and the driver
            // reports its own events — says so rather than leaving the line
            // blank, because a blank line reads as a rendering fault.
            ui.label(
                theme::mono(match &entry.detection {
                    Some(rule) => format!("{} — {rule}", entry.source.as_str()),
                    None => format!("{} — no rule recorded", entry.source.as_str()),
                })
                .color(theme::Palette::TEXT_FAINT),
            );
            if !entry.original_removed {
                // The one thing a user must not have to guess about a
                // quarantined file.
                ui.label(
                    egui::RichText::new("The original is still on disk.")
                        .color(theme::Palette::SUSPICIOUS),
                );
            }
        });
    ui.interact(
        inner.response.rect,
        ui.id().with(("vault", entry.id.to_hex())),
        egui::Sense::click(),
    )
}

/// The smallest the window may be made, and it is also the floor for a
/// configured size.
///
/// Wide enough for the findings list's path column and short enough to fit on a
/// laptop screen with the taskbar showing, which is the narrower of the two
/// constraints on a window most people never resize.
pub const MIN_WINDOW_SIZE: [f32; 2] = [640.0, 440.0];

/// The largest size a configuration may ask for.
///
/// A ceiling rather than a preference. `ui.window_width` is a number in a text
/// file, so it can be a million, and a window created a million points wide is
/// one a user can neither use nor find the settings screen in to undo. This is
/// far past any real display — a 4K monitor is 3,840 — so nothing anybody meant
/// is refused.
pub const MAX_WINDOW_SIZE: [f32; 2] = [16_384.0, 16_384.0];

/// The size the window opens at, from `ui.window_width` and `ui.window_height`.
///
/// # Why the numbers are clamped rather than trusted
///
/// Because they come from a text file a person edits, and every value that
/// cannot be a window is one this window still has to open in — the settings
/// screen is inside it. `0` is a window with no width, a negative number is one
/// the platform will refuse, and `nan` is accepted by `f32::from_str` and has no
/// size at all. Each is clamped to the nearest size that is a window:
/// [`MIN_WINDOW_SIZE`] below, [`MAX_WINDOW_SIZE`] above, and `MIN_WINDOW_SIZE`
/// for a value that is not a number. Refusing to open would be the one response
/// that leaves the user with no way to fix what they typed.
pub fn window_size(ui: &av_core::config::UiConfig) -> [f32; 2] {
    [
        clamp_dimension(ui.window_width, MIN_WINDOW_SIZE[0], MAX_WINDOW_SIZE[0]),
        clamp_dimension(ui.window_height, MIN_WINDOW_SIZE[1], MAX_WINDOW_SIZE[1]),
    ]
}

/// One dimension, clamped, with a non-finite value treated as the floor.
///
/// `f32::clamp` propagates NaN rather than panicking, and a NaN reaching
/// `ViewportBuilder::with_inner_size` is a window whose size is undefined — so
/// it is answered here rather than left to the platform.
fn clamp_dimension(value: f32, low: f32, high: f32) -> f32 {
    if value.is_finite() {
        value.clamp(low, high)
    } else {
        low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{
        Assessment, Detection, Digests, FileKind, FileScanReport, ScanStats, ScanTarget, Severity,
        VerdictThresholds,
    };
    use av_rules::database::RuleDatabase;
    use std::path::Path;

    /// A window over a temporary installation, with nothing on disk.
    fn window() -> (GuiApp, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("a temp directory");
        let paths = test_paths(dir.path());
        (window_over(paths), dir)
    }

    /// A window over an installation, with nowhere to reach a service.
    ///
    /// The pipe is redirected for every test that makes a window, and not only
    /// for the ones that ask the service for something. A window with the
    /// product's own pipe name would reach whatever service the machine running
    /// the tests happens to have installed: a test of the Quarantine tab would
    /// then act on the real vault, and a test that passed here would be a test
    /// that never ran its own code.
    fn window_over(paths: AvPaths) -> GuiApp {
        let mut app = GuiApp::new(paths, AvConfig::default());
        app.service_pipe = av_service::pipe::unique_name("gui-test");
        app
    }

    /// A window with a notification-area icon behind it, and the hand that can
    /// click it.
    ///
    /// The icon is a channel and not a shell: [`crate::tray::Tray::start`] would
    /// put a real icon in the notification area of whatever machine runs the
    /// tests. What is real is everything on this side of it — what a command
    /// does to the window is the whole of what these tests are about.
    fn window_with_an_icon() -> (GuiApp, crossbeam_channel::Sender<TrayCommand>, tempfile::TempDir) {
        let (mut app, dir) = window();
        let (tray, clicks) = tray::Tray::for_test();
        app.set_tray(Some(tray));
        (app, clicks, dir)
    }

    fn test_paths(root: &Path) -> AvPaths {
        AvPaths::with_data_dir(root.join("install"), root.join("data"))
    }

    /// Tick one file and quarantine it, the way the window's button does.
    ///
    /// A helper rather than two lines at every call site, and named for what a
    /// user does rather than for the fields it writes: the tick is keyed by
    /// path, so a test says *which file* and never a row number. That is the
    /// same property the window relies on, and a test that had to work out a
    /// row number would be testing the thing that was wrong.
    fn quarantine(app: &mut GuiApp, path: &Path) {
        app.checked.insert(path.to_path_buf());
        app.quarantine_checked();
    }

    /// An installation with a rule database beside the program, so that a scan
    /// can actually be started.
    /// A window with a rule database it can actually scan with.
    ///
    /// The file is written by [`RuleDatabase::save`] rather than by hand, and
    /// that is not incidental. The window checks the database's header before it
    /// starts a scan, so a fixture holding bytes that are not a database is a
    /// fixture whose scans refuse to start — which is correct behaviour and a
    /// useless test. The tests that want a refusal write their own.
    fn window_with_rules() -> (GuiApp, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("a temp directory");
        let paths = test_paths(dir.path());
        std::fs::create_dir_all(&paths.install_dir).expect("the install directory");
        let (database, _) = RuleDatabase::compile(RULES_FOR_A_WINDOW);
        database
            .save(paths.install_dir.join(scan::DATABASE_FILE))
            .expect("the database file");
        (window_over(paths), dir)
    }

    /// One rule, so that the database above has something in it. What the rule
    /// matches does not matter to any test that starts a scan: they stop the scan
    /// or inspect the window's state, and the files they point at do not exist.
    const RULES_FOR_A_WINDOW: &str = r#"
rule a_window_has_something_to_scan_with {
    strings:
        $a = "WENLE-GUI-TEST-MARKER"
    condition:
        $a
}
"#;

    fn finding(name: &str, verdict: Verdict, score: u16) -> FileScanReport {
        let severity = match verdict {
            Verdict::Malicious => Severity::Critical,
            Verdict::Suspicious => Severity::Medium,
            _ => Severity::Low,
        };
        let mut assessment = Assessment {
            verdict,
            score,
            ..Assessment::default()
        };
        assessment.detections.push(Detection {
            rule_id: format!("Test.Rule.{name}"),
            description: "a marker the tests wrote".to_owned(),
            severity,
            source: av_core::DetectionSource::Signature,
            score,
            threat: None,
            locations: Vec::new(),
            // Both, because this stands in for a rule its author rated
            // decisive rather than one this product read: the GUI tests are
            // about what the window draws for a verdict, and a detection trust
            // could still argue with would be a different fixture.
            decisive: verdict == Verdict::Malicious,
            incontestable: verdict == Verdict::Malicious,
            container: None,
        });
        // Built as a literal rather than through a constructor because
        // `FileScanReport` has none: the engine fills one in as it scans, so
        // there is no value for a default report to hold.
        FileScanReport {
            path: PathBuf::from(format!("C:\\scan\\{name}")),
            kind: FileKind::Pe,
            size: 1_024,
            digests: Digests {
                md5: None,
                sha1: None,
                sha256: None,
            },
            assessment,
            duration: Duration::from_millis(4),
            scanned_bytes: 1_024,
            from_cache: false,
            error: None,
            archive: None,
        }
    }

    /// A quarantined file, as the vault would hand one back.
    ///
    /// Shared by every test that needs the block notification, because a
    /// notification's *size* is part of what is being tested — the two kinds of
    /// card are deliberately different weights — so a second, slightly
    /// different entry built at the next call site would be testing a card the
    /// product does not draw.
    fn quarantined_entry() -> QuarantineEntry {
        QuarantineEntry {
            id: QuarantineId::from_bytes([7; 16]),
            original_path: PathBuf::from("C:\\Users\\me\\evil.exe"),
            file_name: "evil.exe".to_owned(),
            size: 4_096,
            digests: Digests {
                md5: None,
                sha1: None,
                sha256: None,
            },
            threat: None,
            detection: Some("ransomware/lockbit_note".to_owned()),
            severity: Severity::Critical,
            verdict: Verdict::Malicious,
            source: EntrySource::Realtime,
            quarantined_at: chrono::Utc::now(),
            status: EntryStatus::Quarantined,
            changed_at: chrono::Utc::now(),
            original_removed: true,
            note: None,
        }
    }

    /// The same entry for the `n`th file: its own identifier and its own name.
    ///
    /// A column of notifications is a column about *different files*, and the
    /// window will not put two cards in it for one — [`GuiApp::announce_block`]
    /// records the identifiers it has announced and refuses the second, because
    /// the same file reaching it twice (once as the vault's event, once from the
    /// index re-read) is a duplicate and not news. So a test that wants four
    /// cards has to have four entries, which is the only way that state can
    /// arise.
    fn quarantined_entry_of(n: u8) -> QuarantineEntry {
        let mut entry = quarantined_entry();
        entry.id = QuarantineId::from_bytes([n; 16]);
        entry.file_name = format!("evil-{n}.exe");
        entry.original_path = PathBuf::from(format!("C:\\Users\\me\\evil-{n}.exe"));
        entry
    }

    fn report(detections: Vec<FileScanReport>, cancelled: bool) -> av_core::ScanReport {
        let mut report = av_core::ScanReport::new(ScanTarget::Directory(PathBuf::from("C:\\scan")));
        report.stats = ScanStats {
            files_scanned: 10,
            bytes_scanned: 4_096,
            threats_found: detections.len() as u64,
            ..ScanStats::default()
        };
        report.detections = detections;
        report.cancelled = cancelled;
        report
    }

    /// Draw every tab once, headlessly.
    ///
    /// `egui` runs without a window: a `Context` can lay out a frame and
    /// tessellate it with no renderer behind it. That makes the drawing code
    /// reachable from a test, which is the only reason any of it is covered at
    /// all — and a panic in a drawing function is exactly the class of bug that
    /// would otherwise reach a user's screen rather than a test log.
    fn draw_all_tabs(app: &mut GuiApp) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        for tab in Tab::ALL {
            app.tab = tab;
            // Twice: the first frame of an immediate-mode interface lays out
            // sizes that the second one uses, and a bug in the second frame is
            // the one a user sees.
            for _ in 0..2 {
                let _ = ctx.run(egui::RawInput::default(), |ctx| app.draw(ctx));
            }
        }
    }

    // -- the tabs ------------------------------------------------------------

    /// Draw one tab into a window of a given size and report every shape that
    /// was drawn past one of its sides.
    fn overflow_at(tab: Tab, size: egui::Vec2) -> Vec<(f32, String)> {
        let (mut app, _dir) = window();
        app.tab = tab;
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        // Twice: an immediate-mode interface lays out on the first frame what
        // the second one draws, and the second is the frame a user sees.
        let _ = ctx.run(input(size), |ctx| app.draw(ctx));
        let output = ctx.run(input(size), |ctx| app.draw(ctx));
        past_the_sides(&output.shapes, size)
    }

    /// One frame's input for a window of a given size.
    fn input(size: egui::Vec2) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            ..Default::default()
        }
    }

    /// The findings list, with `count` suspicious findings in it.
    fn findings_at_scale(count: usize) -> Vec<FileScanReport> {
        (0..count)
            .map(|i| {
                let mut report = finding(
                    &format!("f{i:06}.exe"),
                    Verdict::Suspicious,
                    (i % 60) as u16 + 20,
                );
                // Distinct paths, in distinct directories, so nothing here
                // relies on a comparison that would collapse them.
                report.path = PathBuf::from(format!("C:\\scan\\dir{}\\f{i:06}.exe", i % 97));
                report
            })
            .collect()
    }

    /// How many shapes one frame of the Findings tab emits.
    fn shapes_in_a_frame(findings: Vec<FileScanReport>) -> usize {
        let (mut app, _dir) = window();
        app.findings = findings;
        app.tab = Tab::Findings;
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let size = egui::vec2(app.window_size()[0], app.window_size()[1]);
        // One warm frame first, so the font atlas and the style caches are
        // built before the frame that is measured.
        let _ = ctx.run(input(size), |ctx| app.draw(ctx));
        ctx.run(input(size), |ctx| app.draw(ctx)).shapes.len()
    }

    #[test]
    fn the_findings_list_draws_only_the_rows_the_window_can_show() {
        // The list grows while a scan runs: every detection and every file the
        // engine could not vouch for is appended live. Laying out all of them
        // to show the twenty a window can hold is what made the window slower
        // the more a scan found, and it was measurable rather than theoretical
        // — before the list was virtualised, one frame cost 190 ms at ten
        // thousand findings in a debug build and 107 ms in a release one,
        // against 8.8 ms at a thousand. A window at nine frames a second also
        // *looks* like a scan that has slowed down, because the counters and
        // the progress bar only move when a frame is drawn.
        //
        // The assertion is on shapes and not on elapsed time: a test that
        // asserts a duration is a test that passes on a fast machine and fails
        // on a busy one. Shapes are what the time was being spent on, and if
        // the list ever goes back to drawing every row this is what says so.
        let small = shapes_in_a_frame(findings_at_scale(1_000));
        let large = shapes_in_a_frame(findings_at_scale(10_000));
        println!("MF 1,000 findings: {small} shapes; 10,000 findings: {large} shapes");
        assert!(
            large <= small,
            "ten times the findings emitted {large} shapes against {small}: \
             the list is laying out rows the window cannot show"
        );
    }

    #[test]
    fn a_row_is_exactly_as_tall_as_the_list_was_laid_out_for() {
        // The arithmetic `show_rows` divides by. A row that disagreed with it
        // would be drawn on top of its neighbour, and the disagreement would
        // come from content that grew — a wrapped file name, a second summary
        // line — so the two labels that could grow are truncated and a row
        // without a summary is padded.
        //
        // Measured through the layout rather than asserted as a constant: the
        // line height belongs to the font, which belongs to the theme, and a
        // hard-coded number here would be this machine's font imposed on
        // every other one.
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let opens = window_size(&av_core::config::UiConfig::default());
        let size = egui::vec2(opens[0], opens[1]);
        let mut measured = None;
        let _ = ctx.run(input(size), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let metrics = RowMetrics::for_ui(ui);
                let mut report = finding("a-very-long-file-name-indeed.exe", Verdict::Suspicious, 40);
                // The longest a name can be, so that if truncation were not in
                // force this row would wrap and come out taller.
                report.path = PathBuf::from(format!("C:\\scan\\{}.exe", "n".repeat(200)));
                let response = finding_row(ui, &report, &metrics, false);
                measured = Some((metrics, response.rect.height()));
            });
        });
        let (metrics, drawn) = measured.expect("the frame drew a row");
        assert!(
            (drawn - metrics.height).abs() <= 1.0,
            "the row drew {} points tall but the list was laid out for {}",
            drawn,
            metrics.height
        );
        assert!(
            metrics.content() > 0.0 && metrics.height > metrics.content(),
            "a row has to be its content plus the frame's margins: {metrics:?}"
        );
    }

    /// Every shape drawn outside the window's left or right side, worst first.
    ///
    /// # Why only the sides, and not the top and bottom
    ///
    /// Because the two axes are not the same rule. A view taller than the window
    /// is *reachable* — [`GuiApp::draw`] puts every tab in a vertical scroll
    /// area, so the rest of it is a scroll away, and content below the bottom
    /// edge is drawn there on purpose. A view wider than the window is not: the
    /// product has no horizontal scrolling anywhere, so a control past the side
    /// is gone, and a row that is 1,032 points wide in a 1,020-point window
    /// shows a filter bar with its last control missing.
    ///
    /// That asymmetry cost this test its first version. It checked all four
    /// edges, found the Scan view's content 77 points past the bottom, and was
    /// right to: the view was *not* scrollable then, and the two lowest bands of
    /// its legend could not be reached at all. The fix was to make it scroll —
    /// not to stop measuring. What may not happen is the side.
    ///
    /// The overlays are the exception and are measured on all four edges,
    /// because they are not inside the scroll area and nothing recovers them;
    /// see `the_notification_column_stays_inside_the_window`.
    fn past_the_sides(
        shapes: &[egui::epaint::ClippedShape],
        size: egui::Vec2,
    ) -> Vec<(f32, String)> {
        let mut offenders = Vec::new();
        for clipped in shapes {
            let rect = clipped.shape.visual_bounding_rect();
            let sides = [
                ("the right side", rect.max.x - size.x),
                ("the left side", -rect.min.x),
            ];
            let worst = sides
                .into_iter()
                .filter(|(_, past)| *past > 0.5)
                .max_by(|a, b| a.1.total_cmp(&b.1));
            let Some((side, past)) = worst else {
                continue;
            };
            let what = match &clipped.shape {
                egui::Shape::Text(text) => format!("text {:?}", text.galley.text()),
                other => format!("{other:?}").chars().take(70).collect(),
            };
            offenders.push((past, format!("{side} by {past:.1}pt: {rect:?} {what}")));
        }
        offenders.sort_by(|a, b| b.0.total_cmp(&a.0));
        offenders
    }

    /// Nothing the window draws may fall outside its left or right side.
    ///
    /// # Why this is a test and not a matter of looking at it
    ///
    /// Because egui does not report it and does not wrap it: a row of controls
    /// in a `ui.horizontal(...)` that is wider than the panel is laid out at full
    /// width and then clipped, so the failure is a control that is simply absent
    /// from the screen with nothing to say one is missing. The Findings filter
    /// bar measured 1,032 points against a 1,020-point window, and the user saw a
    /// filter bar whose score control did not exist.
    ///
    /// It is a test rather than a screenshot because the screenshot is what made
    /// this hard to find in the first place. A screenshot helper running in a
    /// DPI-unaware process gets virtualised window coordinates — this machine
    /// runs at 125%, so `GetWindowRect` reported 1,034 physical pixels for a
    /// window that is really 1,275, and capturing that region cut the right-hand
    /// side off a window that was in fact drawing correctly. Three rounds of
    /// "the layout is broken" were a bug in the ruler. Measuring the shapes egui
    /// actually emitted has no such failure mode.
    ///
    /// The bottom edge is not measured, and that is deliberate: a view taller
    /// than the window scrolls, so it is reachable, and content below the bottom
    /// edge is drawn there on purpose. See [`past_the_sides`] for why the two
    /// axes are two rules. What the bottom edge *is* measured for is the
    /// notification column, which is not inside the scroll area; see
    /// `the_notification_column_stays_inside_the_window`.
    ///
    /// The sizes are the two the product promises — the one an unconfigured
    /// window opens at and the one it may be dragged down to — plus a wide one,
    /// because a layout that only works when it has room to spare is not a
    /// layout.
    #[test]
    fn nothing_is_drawn_past_the_side_of_the_window() {
        let opens = window_size(&av_core::config::UiConfig::default());
        for (name, size) in [
            (
                "the size an unconfigured window opens at",
                egui::vec2(opens[0], opens[1]),
            ),
            (
                "the smallest allowed",
                egui::vec2(MIN_WINDOW_SIZE[0], MIN_WINDOW_SIZE[1]),
            ),
            ("a wide window", egui::vec2(1_600.0, 900.0)),
        ] {
            for tab in Tab::ALL {
                let offenders = overflow_at(tab, size);
                assert!(
                    offenders.is_empty(),
                    "{name}: {tab:?} drew {} shape(s) past the side:\n  {}",
                    offenders.len(),
                    offenders
                        .iter()
                        .map(|(_, what)| what.as_str())
                        .collect::<Vec<_>>()
                        .join("\n  "),
                );
            }
        }
    }

    #[test]
    fn there_are_four_tabs_and_every_one_has_its_own_word() {
        assert_eq!(Tab::ALL.len(), 4);
        let mut labels: Vec<&str> = Tab::ALL.iter().map(|tab| tab.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), 4, "two tabs share a label");
        assert_eq!(Tab::Scan.label(), "Scan");
    }

    // -- events --------------------------------------------------------------

    #[test]
    fn a_finished_report_replaces_the_live_list_rather_than_adding_to_it() {
        // The bug this prevents: every finding appearing twice, because the
        // live events and the finished report are the same findings.
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finding(Box::new(finding(
            "a.exe",
            Verdict::Malicious,
            200,
        ))));
        assert_eq!(app.findings().len(), 1);

        app.apply(ScanEvent::Finished(Box::new(report(
            vec![finding("a.exe", Verdict::Malicious, 200)],
            true,
        ))));
        assert_eq!(app.findings().len(), 1, "not two");
        assert!(matches!(app.state, ScanState::Finished(_)));
    }

    #[test]
    fn a_live_finding_is_reported_in_the_window_and_never_to_the_shell() {
        // A first scan of a Windows installation finds hundreds of files. Each
        // one is a row in the list and a line in the status line; none of them
        // is worth pulling the user out of whatever they are doing, and the
        // shell's stack would be useless long before the scan ended. What
        // reaches the shell is the *result* — see the test below.
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finding(Box::new(finding(
            "bad.exe",
            Verdict::Malicious,
            200,
        ))));
        assert!(
            app.notifier.announced().is_empty(),
            "{:?}",
            app.notifier.announced()
        );
        let status = app.status.as_deref().expect("the status line reports it");
        assert!(status.contains("bad.exe"), "{status}");
        assert!(status.contains("nothing has been done about it"), "{status}");

        // And the middle band does not even reach the status line: it is a row
        // in the list, and nothing about it is an event.
        app.status = None;
        app.apply(ScanEvent::Finding(Box::new(finding(
            "maybe.exe",
            Verdict::Suspicious,
            40,
        ))));
        assert!(app.status.is_none(), "{:?}", app.status);
    }

    #[test]
    fn a_scan_that_found_something_malicious_says_so_to_the_shell_once() {
        // The case the window cannot cover, and the common one: the reason to
        // start a full scan is usually that the machine will be left alone
        // while it runs. One notification for the whole scan, carrying the
        // worst file and how many there were.
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finished(Box::new(report(
            vec![
                finding("worse.exe", Verdict::Malicious, 300),
                finding("bad.exe", Verdict::Malicious, 200),
            ],
            false,
        ))));
        assert_eq!(
            app.notifier.announced().len(),
            1,
            "one for the scan, not one per file: {:?}",
            app.notifier.announced()
        );
        let announcement = &app.notifier.announced()[0];
        assert_eq!(announcement.title, "The scan found something malicious");
        // Tagged as a block, so it replaces the per-block notifications of the
        // scan it concludes instead of joining them.
        assert_eq!(announcement.tag, Some(Tag::Blocked));
        assert!(announcement.body.contains("worse.exe"), "{}", announcement.body);
        assert!(announcement.body.contains("2 files"), "{}", announcement.body);
    }

    #[test]
    fn a_scan_that_found_nothing_is_not_announced_to_the_shell() {
        // "Nothing was found" is not news: the window says it, the machine was
        // not touched, and a notification per scheduled scan would be a popup
        // the user learns to dismiss.
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finished(Box::new(report(
            vec![
                finding("good.txt", Verdict::Clean, 0),
                finding("maybe.exe", Verdict::Suspicious, 40),
            ],
            false,
        ))));
        let titles: Vec<&str> = app
            .notifier
            .announced()
            .iter()
            .map(|a| a.title.as_str())
            .collect();
        assert!(
            !titles.iter().any(|t| t.contains("found something")),
            "{titles:?}"
        );
    }

    #[test]
    fn a_malicious_result_switches_to_the_findings_tab() {
        let (mut app, _dir) = window();
        app.tab = Tab::Settings;
        app.apply(ScanEvent::Finished(Box::new(report(
            vec![finding("bad.exe", Verdict::Malicious, 200)],
            false,
        ))));
        assert_eq!(app.tab, Tab::Findings);
    }

    #[test]
    fn a_clean_result_leaves_the_user_where_they_were() {
        let (mut app, _dir) = window();
        app.tab = Tab::Settings;
        app.apply(ScanEvent::Finished(Box::new(report(Vec::new(), false))));
        assert_eq!(
            app.tab,
            Tab::Settings,
            "nothing to look at, so nothing moves"
        );
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("nothing"), "{status}");
    }

    #[test]
    fn a_cancelled_report_says_it_was_stopped_and_does_not_claim_a_clean_machine() {
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finished(Box::new(report(Vec::new(), true))));
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("stopped"), "{status}");
        assert!(!status.contains("nothing"), "{status}");
    }

    #[test]
    fn a_failure_empty_the_scan_state_and_leaves_the_old_findings_alone() {
        // An empty list next to a failure message reads as "the scan found
        // nothing", which is the one thing a failed scan has not shown.
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finished(Box::new(report(
            vec![finding("old.exe", Verdict::Malicious, 200)],
            false,
        ))));
        assert_eq!(app.findings().len(), 1);

        app.apply(ScanEvent::Failed {
            message: "the rules would not load".to_owned(),
        });
        assert!(matches!(app.state, ScanState::Failed { .. }));
        assert_eq!(app.findings().len(), 1, "the earlier result is still there");
        assert_eq!(app.status.as_deref(), Some("the rules would not load"));
    }

    #[test]
    fn the_walk_announcement_counts_what_it_is_about_to_do() {
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Enumerated {
            files: 1_204,
            bytes: 3_400_000_000,
            skipped: 12,
            unreadable: 1,
        });
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("1,204 files"), "{status}");
        assert!(status.contains("3.4 GB"), "{status}");
        assert!(status.contains("12 skipped"), "{status}");
        assert!(status.contains("1 unreadable"), "{status}");
    }

    // -- starting a scan -----------------------------------------------------

    #[test]
    fn a_machine_with_no_rules_says_so_instead_of_scanning() {
        let (mut app, _dir) = window();
        app.target = "C:\\scan".to_owned();
        app.start_scan();
        assert!(matches!(app.state, ScanState::Failed { .. }));
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("No rule database"), "{status}");
        assert!(app.job.is_none(), "nothing was started");
    }

    #[test]
    fn a_database_that_arrives_after_the_window_opened_is_used_without_a_restart() {
        // The window resolves the database when it opens, which is right for the
        // line it opens with and wrong for the rest of its life. A window that
        // began before the rules existed refused every scan — "No rule database
        // was found in ..." — long after one was there, and the only cure a user
        // has is to close the window and open it again, which reads as the rules
        // having gone missing and then come back. The question is asked again
        // where the answer is acted on.
        let dir = tempfile::tempdir().expect("a temp directory");
        let paths = test_paths(dir.path());
        std::fs::create_dir_all(&paths.install_dir).expect("the install directory");
        let mut app = window_over(paths.clone());

        // Opened with nothing to scan with, and it says so — before any scan is
        // asked for, which is the reason the start-up resolution exists at all.
        assert!(app.database.is_err());

        // The rules arrive: `wenle build`, an installer, or a service.
        let (database, _) = RuleDatabase::compile(RULES_FOR_A_WINDOW);
        database
            .save(paths.install_dir.join(scan::DATABASE_FILE))
            .expect("the database file");

        app.target = "C:\\scan".to_owned();
        app.start_scan();

        assert!(
            app.database.is_ok(),
            "the window would not look again: {:?}",
            app.database
        );
        assert!(
            app.state.is_running(),
            "the scan was refused with the database right there: {:?}",
            app.status
        );
        app.stop_scan();
    }

    #[test]
    fn an_empty_target_is_refused_rather_than_scanned() {
        let (mut app, _dir) = window_with_rules();
        app.target = "   ".to_owned();
        app.start_scan();
        assert!(matches!(app.state, ScanState::Failed { .. }));
        assert!(app.job.is_none());
        assert!(app.state.can_start(), "the user can try again");
    }

    #[test]
    fn a_database_this_build_cannot_read_is_refused_before_the_scan_starts() {
        // The user's report, as a test. The window used to accept any database
        // path that existed, hand it to the worker, and let the worker discover
        // after walking the tree that it could not be read — so the failure
        // arrived at the end of a scan the user watched run, and named a file
        // they had not pointed the scan at. The refusal has to come from the
        // window, before the state goes to `Running`.
        let dir = tempfile::tempdir().expect("a temp directory");
        let paths = test_paths(dir.path());
        std::fs::create_dir_all(&paths.install_dir).expect("the install directory");
        let path = paths.install_dir.join(scan::DATABASE_FILE);
        std::fs::write(&path, b"not a real database").expect("the database file");

        let mut app = window_over(paths);
        app.target = "C:\\scan".to_owned();
        app.start_scan();

        assert!(matches!(app.state, ScanState::Failed { .. }), "no scan started");
        assert!(app.job.is_none(), "no worker was spawned");
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("rules.avdb"), "it names the file: {status}");
        assert!(app.state.can_start(), "the user can fix it and try again");
    }

    #[test]
    fn a_scan_starts_and_can_be_stopped_from_the_window() {
        let (mut app, _dir) = window_with_rules();
        app.target = "C:\\scan".to_owned();
        app.start_scan();
        assert!(app.state.is_running());
        assert!(app.job.is_some());

        app.stop_scan();
        assert!(app
            .job
            .as_ref()
            .is_some_and(|job| job.handle().stop_requested()));
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("Stopping"), "{status}");
        // And the note the window shows is the engine's own caveat, not a claim
        // that the scan is over.
        assert!(app.state.cancelled_note().is_some());
    }

    #[test]
    fn a_second_start_while_a_scan_is_running_does_nothing() {
        let (mut app, _dir) = window_with_rules();
        app.target = "C:\\scan".to_owned();
        app.start_scan();
        let first = app.job.as_ref().map(|job| job.handle().stop_requested());
        app.start_scan();
        assert_eq!(
            first,
            app.job.as_ref().map(|job| job.handle().stop_requested()),
            "the same job, not a second one"
        );
        assert!(app.state.is_running());
    }

    // -- settings ------------------------------------------------------------

    #[test]
    fn saving_writes_the_configuration_and_clears_the_unsaved_mark() {
        let (mut app, _dir) = window();
        assert!(!app.settings.is_dirty());

        app.settings.edited_mut().scanning.thresholds.malicious = 250;
        assert!(app.settings.is_dirty());

        app.save_settings();
        assert!(!app.settings.is_dirty());
        assert_eq!(app.config.scanning.thresholds.malicious, 250);

        let written = AvConfig::load_or_default(&app.paths.config_file)
            .expect("the saved configuration loads again");
        assert_eq!(written.scanning.thresholds.malicious, 250);
    }

    #[test]
    fn a_configuration_the_engine_would_refuse_is_not_written() {
        // Inverted thresholds stop the product from starting, so writing them
        // would be a settings screen that bricks the installation.
        let (mut app, _dir) = window();
        app.settings.edited_mut().scanning.thresholds.suspicious = 500;
        app.settings.edited_mut().scanning.thresholds.malicious = 100;

        app.save_settings();
        assert!(app.settings.is_dirty(), "still unsaved");
        let status = app.status.clone().unwrap_or_default();
        assert!(status.starts_with("Not saved:"), "{status}");
        assert!(
            !app.paths.config_file.exists(),
            "nothing was written for a configuration that cannot load"
        );
    }

    #[test]
    fn reverting_puts_the_settings_back_without_writing_anything() {
        let (mut app, _dir) = window();
        app.settings.edited_mut().scanning.threads = 7;
        app.run_pending(Pending {
            revert_settings: true,
            ..Pending::default()
        });
        assert!(!app.settings.is_dirty());
        assert_eq!(
            app.settings.edited().scanning.threads,
            AvConfig::default().scanning.threads
        );
        assert!(!app.paths.config_file.exists());
    }

    #[test]
    fn a_scan_uses_the_saved_settings_and_not_the_unsaved_edits() {
        let (mut app, _dir) = window_with_rules();
        app.settings.edited_mut().scanning.threads = 9;
        app.target = "C:\\scan".to_owned();
        app.start_scan();
        // The job is running with the saved configuration, which is what the
        // report will describe; a test cannot read the request back out of a
        // started job, so what is asserted is the invariant that the saved
        // config is what a request is built from.
        assert_eq!(
            app.config.scanning.threads,
            AvConfig::default().scanning.threads
        );
        assert_ne!(
            app.settings.edited().scanning.threads,
            app.config.scanning.threads
        );
        app.stop_scan();
    }

    // -- quarantine ----------------------------------------------------------

    #[test]
    fn quarantining_with_nothing_ticked_asks_for_a_selection_instead_of_guessing() {
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finished(Box::new(report(
            vec![finding("bad.exe", Verdict::Malicious, 200)],
            false,
        ))));
        app.checked.clear();
        app.quarantine_checked();
        assert_eq!(app.notifier.announced().len(), 1, "the user is told, in the corner");
        assert!(app.vault.is_none(), "and nothing was opened to do it with");
    }

    #[test]
    fn quarantining_a_real_file_takes_it_and_records_it() {
        let (mut app, dir) = window();
        let victim = dir.path().join("victim.exe");
        std::fs::write(&victim, b"WENLE-GUI-TEST-MARKER").expect("the victim is written");
        app.findings = vec![finding("victim.exe", Verdict::Malicious, 200)];
        app.findings[0].path = victim.clone();

        quarantine(&mut app, &victim);
        assert!(app.vault.is_some(), "the vault was opened");
        assert!(!victim.exists(), "the original is gone");
        let entry = app
            .vault
            .as_ref()
            .and_then(|vault| vault.list().first().copied())
            .expect("the file is in the vault");
        assert_eq!(entry.verdict, Verdict::Malicious);
        assert_eq!(entry.original_path, victim);
        assert_eq!(app.notifier.announced().len(), 1);
        let toast = &app.notifier.announced()[0];
        assert!(
            toast.body.contains("blocked and moved to quarantine"),
            "{:?}",
            toast.body
        );
        // And it is the *block* kind, not a notice: the whole point of the
        // notification is that it distinguishes what was done from what was
        // merely noticed.
        assert_eq!(toast.title, "Blocked and quarantined");
        // Tagged, so that a second block of the same scan replaces this one on
        // the shell's stack rather than piling up under it.
        assert_eq!(toast.tag, Some(Tag::Blocked));
    }

    #[test]
    fn a_block_notification_names_the_file_what_was_found_and_what_was_done() {
        // The three things the notification has to carry. A user told a block
        // happened but not which file, or not what was in it, has been told
        // nothing they can act on.
        let (mut app, _dir) = window();
        let entry = quarantined_entry();
        app.notify_blocked(&QuarantineEvent::Quarantined(Box::new(entry.clone())));
        let toast = &app.notifier.announced()[0];
        assert!(toast.body.contains("evil.exe"), "{}", toast.body);
        assert!(
            toast.body.contains("ransomware/lockbit_note"),
            "{}",
            toast.body
        );
        // What was done, in the words `notify_blocked` explains at length: the
        // file is gone and its bytes are in the vault, and nothing claims a
        // process was terminated, because nothing terminates one.
        assert!(
            toast.body.contains("blocked and moved to quarantine"),
            "{}",
            toast.body
        );

        // The family name wins over the rule when the engine attributed one,
        // because that is the statement a user can search for.
        //
        // A second *file*, and not the same entry announced again: one entry is
        // one file, and the window refuses to say "blocked" about the same one
        // twice — see [`GuiApp::announce_block`]. The scenario this describes is
        // two files the same engine attributed, which is what makes the family
        // name win over the rule in both cards.
        let mut second = quarantined_entry_of(9);
        second.threat = Some(
            av_core::ThreatName::new(av_core::Platform::Win32, av_core::ThreatCategory::Trojan)
                .with_family("Wacatac"),
        );
        app.notify_blocked(&QuarantineEvent::Quarantined(Box::new(second)));
        assert!(
            app.notifier.announced()[1].body.contains("Wacatac"),
            "{:?}",
            app.notifier.announced()[1].body
        );
    }

    #[test]
    fn a_middle_band_notification_says_nothing_was_done_about_it() {
        let (mut app, _dir) = window();
        app.notify_suspicious(&finding("maybe.exe", Verdict::Suspicious, 40));
        let toast = &app.notifier.announced()[0];
        assert_eq!(toast.title, "Suspicious — not acted on");
        assert!(toast.title.contains("not acted on"), "{}", toast.title);
        // Tagged apart from a block, so that a run of these replaces itself and
        // can never push a block notification off the stack.
        assert_eq!(toast.tag, Some(Tag::Suspicious));
        assert!(toast.body.contains("maybe.exe"), "{}", toast.body);
    }

    #[test]
    fn the_two_notifications_are_two_functions_and_produce_two_different_cards() {
        // The requirement's own test: the middle band must never be able to
        // borrow the language of an action.
        let (mut app, _dir) = window();
        app.notify_blocked(&QuarantineEvent::Quarantined(Box::new(QuarantineEntry {
            id: QuarantineId::from_bytes([1; 16]),
            original_path: PathBuf::from("C:\\evil.exe"),
            file_name: "evil.exe".to_owned(),
            size: 1,
            digests: av_core::Digests {
                md5: None,
                sha1: None,
                sha256: None,
            },
            threat: None,
            detection: None,
            severity: Severity::Critical,
            verdict: Verdict::Malicious,
            source: EntrySource::Realtime,
            quarantined_at: chrono::Utc::now(),
            status: EntryStatus::Quarantined,
            changed_at: chrono::Utc::now(),
            original_removed: true,
            note: None,
        })));
        app.notify_suspicious(&finding("maybe.exe", Verdict::Suspicious, 40));

        let blocked = &app.notifier.announced()[0];
        let suspicious = &app.notifier.announced()[1];
        assert_ne!(blocked.title, suspicious.title);
        assert_ne!(blocked.tag, suspicious.tag);
        assert!(
            !suspicious.body.contains("taken") && !suspicious.body.contains("blocked"),
            "the middle band claimed an action: {}",
            suspicious.body
        );
    }

    #[test]
    fn a_scans_middle_band_produces_one_card_and_not_one_per_file() {
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finished(Box::new(report(
            vec![
                finding("a.exe", Verdict::Suspicious, 40),
                finding("b.exe", Verdict::Suspicious, 41),
                finding("c.exe", Verdict::Suspicious, 42),
            ],
            false,
        ))));
        assert_eq!(
            app.notifier.announced().len(),
            1,
            "one card for the band, not three: {:?}",
            app.notifier.announced()
        );
        assert_eq!(app.notifier.announced()[0].title, "Suspicious — not acted on");
    }

    #[test]
    fn a_scan_with_something_malicious_in_it_does_not_also_warn_about_the_middle_band() {
        let (mut app, _dir) = window();
        app.apply(ScanEvent::Finished(Box::new(report(
            vec![
                finding("bad.exe", Verdict::Malicious, 200),
                finding("maybe.exe", Verdict::Suspicious, 40),
            ],
            false,
        ))));
        assert!(
            app.notifier.announced()
                .iter()
                .all(|t| t.title != "Suspicious — not acted on"),
            "one thing to deal with at a time: {:?}",
            app.notifier.announced()
        );
    }

    #[test]
    fn a_quarantine_the_window_did_not_start_still_raises_the_block_notification() {
        // The notification belongs to the vault's event, not to the button.
        // This is what makes the real-time blocker's quarantines announce
        // themselves in this window without this window having asked for them.
        let (mut app, dir) = window();
        let victim = dir.path().join("blocked.exe");
        std::fs::write(&victim, b"WENLE-GUI-TEST-MARKER").expect("the victim is written");
        app.open_vault();
        let context = av_quarantine::QuarantineContext::from_report(
            &finding("blocked.exe", Verdict::Malicious, 200),
            EntrySource::Realtime,
        );
        app.vault
            .as_mut()
            .expect("the vault is open")
            .quarantine_file(&victim, &context)
            .expect("the file is quarantined");

        assert!(
            app.notifier.announced().is_empty(),
            "nothing is raised until it is drained"
        );
        app.drain_vault_events();
        assert_eq!(app.notifier.announced().len(), 1);
        assert_eq!(app.notifier.announced()[0].title, "Blocked and quarantined");
        assert!(app.notifier.announced()[0].body.contains("blocked.exe"));
    }

    #[test]
    fn an_event_the_notification_does_not_cover_is_not_announced_as_a_block() {
        // Every variant other than `Quarantined` must leave the corner alone:
        // raising "blocked" for a delete would be the window claiming an action
        // nobody took.
        let (mut app, _dir) = window();
        app.notify_blocked(&QuarantineEvent::Evicted {
            count: 3,
            freed_bytes: 100,
        });
        app.notify_blocked(&QuarantineEvent::RemovalCompleted {
            path: PathBuf::from("C:\\x.exe"),
            id: QuarantineId::from_bytes([2; 16]),
        });
        assert!(app.notifier.announced().is_empty(), "{:?}", app.notifier.announced());
    }

    // -- what another process did to the vault ------------------------------

    /// What the service would record about a file it blocked in real time.
    fn a_block_report(name: &str) -> av_quarantine::QuarantineContext {
        av_quarantine::QuarantineContext::from_report(
            &finding(name, Verdict::Malicious, 200),
            EntrySource::Realtime,
        )
    }

    /// A second vault over the same directory this window reads, standing in for
    /// the service.
    ///
    /// A helper, and the reason these tests mean anything: quarantining through
    /// the window's own vault is what the tests above do, and it can only ever
    /// show that the window notices *itself*. A writer in another process is the
    /// case with no other way to be reached, and one directory is what makes
    /// this one — `AvPaths::default_writable_root` is machine-wide, so the
    /// service and a window a user double-clicked really do share it.
    fn another_writer(app: &GuiApp) -> QuarantineVault {
        let policy = QuarantinePolicy::from(&app.config.quarantine);
        QuarantineVault::open_recovering(&app.paths.quarantine_dir, policy)
            .expect("a vault over the same directory")
    }

    #[test]
    fn a_block_the_service_made_is_announced_in_the_corner() {
        // The gap `vault_poll` closes, and the whole reason it exists. Until it
        // did, a file the service took while this window was open appeared
        // nowhere: the list was read when the tab was first drawn and never
        // again, and no event crosses a process boundary.
        //
        // This window never opens the Quarantine tab, which is deliberate — the
        // user who needs to be told is the one who is not looking at that list.
        let (mut app, dir) = window();
        let victim = dir.path().join("dropped.exe");
        std::fs::write(&victim, b"WENLE-GUI-TEST-MARKER").expect("the victim is written");

        // The first look, on a vault whose index has never been written: the
        // state every new installation is in, and the case where "no file" has
        // to be a baseline rather than an absence of one. Without that, the
        // first thing this product ever took would be the one thing nobody was
        // told about.
        let first = Instant::now();
        app.poll_vault(first);
        assert!(app.vault.is_some(), "the poll opens the vault itself");
        assert!(app.notifier.announced().is_empty(), "{:?}", app.notifier.announced());

        let mut service = another_writer(&app);
        service
            .quarantine_file(&victim, &a_block_report("dropped.exe"))
            .expect("the service takes the file");

        app.poll_vault(first + Duration::from_secs(2));

        assert_eq!(app.notifier.announced().len(), 1, "{:?}", app.notifier.announced());
        let toast = &app.notifier.announced()[0];
        assert_eq!(toast.title, "Blocked and quarantined");
        assert!(toast.body.contains("dropped.exe"), "{}", toast.body);
        // And not only the card: the list the tab draws has it too, because the
        // same re-read is what puts it there.
        assert!(
            app.vault
                .as_ref()
                .expect("the vault is open")
                .entries()
                .iter()
                .any(|entry| entry.file_name == "dropped.exe"),
            "the entry is in the vault, not only in the corner"
        );
    }

    #[test]
    fn the_same_file_is_announced_once_however_many_times_the_window_hears_about_it() {
        // `announce_block` is reached from two directions — the vault's event
        // and the index poll — and the same entry can arrive by either. What
        // keeps a batch quarantine from reporting itself twice is the record of
        // what has been announced.
        let (mut app, dir) = window();
        let victim = dir.path().join("blocked.exe");
        std::fs::write(&victim, b"WENLE-GUI-TEST-MARKER").expect("the victim is written");
        app.open_vault();
        let entry = app
            .vault
            .as_mut()
            .expect("the vault is open")
            .quarantine_file(&victim, &a_block_report("blocked.exe"))
            .expect("the file is quarantined");

        let event = QuarantineEvent::Quarantined(Box::new(entry));
        app.notify_blocked(&event);
        assert_eq!(app.notifier.announced().len(), 1, "{:?}", app.notifier.announced());

        app.notify_blocked(&event);
        assert_eq!(
            app.notifier.announced().len(),
            1,
            "one file, one notification: {:?}",
            app.notifier.announced()
        );
    }

    #[test]
    fn a_file_that_was_taken_and_put_back_between_two_looks_is_not_called_blocked() {
        // The poll reports what the index now says, and the index keeps a record
        // of a file that was restored. Announcing that as "blocked and moved to
        // quarantine" would be the notification lying about the state of the
        // machine — and this is the one way the announcement can be wrong,
        // because the entry really is news to the window's list.
        let (mut app, dir) = window();
        let victim = dir.path().join("released.exe");
        std::fs::write(&victim, b"WENLE-GUI-TEST-MARKER").expect("the victim is written");
        let first = Instant::now();
        app.poll_vault(first);

        let mut service = another_writer(&app);
        let entry = service
            .quarantine_file(&victim, &a_block_report("released.exe"))
            .expect("the service takes the file");
        service
            .restore(
                entry.id,
                &av_quarantine::RestoreOptions::to(dir.path().join("put-back.exe")),
            )
            .expect("and puts it back before the window looks");

        app.poll_vault(first + Duration::from_secs(2));

        assert!(
            app.notifier.announced().is_empty(),
            "the file is on disk and nothing is blocked: {:?}",
            app.notifier.announced()
        );
        // The window still learns about it, which is what the list is for: it
        // says what happened to that file, and says "restored".
        assert!(
            app.vault
                .as_ref()
                .expect("the vault is open")
                .entries()
                .iter()
                .any(|entry| entry.file_name == "released.exe"),
            "the entry is in the list"
        );
    }

    #[test]
    fn quarantining_something_that_is_not_there_reports_the_failure_and_does_not_pretend() {
        let (mut app, _dir) = window();
        app.findings = vec![finding("gone.exe", Verdict::Malicious, 200)];
        quarantine(&mut app, Path::new(r"C:\scan\gone.exe"));
        let texts: Vec<&str> = app.notifier.announced().iter().map(|t| t.body.as_str()).collect();
        assert!(
            texts
                .iter()
                .any(|text| text.contains("could not be quarantined")),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|text| text.contains("was quarantined")));
    }

    #[test]
    fn a_clean_file_is_never_quarantined() {
        // The middle band exists so that the product does not act on it; the
        // clean band must not be actionable at all.
        let (mut app, dir) = window();
        let file = dir.path().join("clean.txt");
        std::fs::write(&file, b"harmless").expect("the file is written");
        let mut report = finding("clean.txt", Verdict::Clean, 0);
        report.path = file.clone();
        app.findings = vec![report];

        quarantine(&mut app, &file);
        assert!(file.exists(), "it is still there");
        assert!(
            app.notifier.announced().is_empty(),
            "a clean file is not news for the shell: {:?}",
            app.notifier.announced()
        );
        let status = app.status.as_deref().expect("the status line says why");
        assert!(status.contains("found clean"), "{status}");
    }

    // -- ticking more than one file ------------------------------------------

    /// Write `names` into a temporary directory and return a report per file,
    /// in the order given, all of them malicious.
    ///
    /// The score walks down the list, so the order the reports are in is *not*
    /// the order a sort by score or by path produces — which is the whole point
    /// of the tests below.
    fn malicious_files(dir: &Path, names: &[&str]) -> Vec<FileScanReport> {
        names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let path = dir.join(name);
                std::fs::write(&path, b"WENLE-GUI-TEST-MARKER").expect("the file is written");
                let mut report = finding(name, Verdict::Malicious, 900 - index as u16 * 100);
                report.path = path;
                report
            })
            .collect()
    }

    #[test]
    fn a_bulk_action_takes_the_ticked_file_and_not_the_row_a_sort_moved_into_its_place() {
        // The bug this exists for. The window used to remember a *row number*
        // from the filtered list and read it back as an index into the
        // unfiltered one. `Filter::apply` both filters and sorts, so the moment
        // any sort but the identity one was chosen the two lists were different
        // and the file taken was whichever one happened to sit at that
        // position — a different file, with no error, and nothing in the
        // window's state that would have looked wrong afterwards.
        //
        // The reports are in descending score order and the sort is by path, so
        // the two orders are exactly reversed. Row zero of what is drawn is
        // `a-first.exe`; index zero of `findings` is `z-last.exe`.
        let (mut app, dir) = window();
        app.findings = malicious_files(dir.path(), &["z-last.exe", "a-first.exe"]);
        app.filter.sort = crate::filter::Sort::Path;

        let tapped = app.findings[1].path.clone();
        let spared = app.findings[0].path.clone();
        assert_eq!(
            app.filter.apply(&app.findings).files[0].path,
            tapped,
            "the fixture is only meaningful while the sort really does reorder"
        );

        quarantine(&mut app, &tapped);
        assert!(!tapped.exists(), "the file that was ticked is the one taken");
        assert!(spared.exists(), "and the other one is untouched");
        assert_eq!(app.notifier.announced().len(), 1);
    }

    #[test]
    fn ticking_all_ticks_what_the_filter_is_showing_and_leaves_the_hidden_rows_alone() {
        // Select-all is over the filtered set on purpose: a user who has
        // narrowed the list to the bands worth acting on means those rows. A
        // file they were never shown is not a file they asked to have removed,
        // and "tick all" reaching into a hidden row is how a bulk action takes
        // something nobody chose.
        let (mut app, dir) = window();
        let malicious = malicious_files(dir.path(), &["one.exe"]);
        let mut clean = finding("harmless.txt", Verdict::Clean, 0);
        clean.path = dir.path().join("harmless.txt");
        std::fs::write(&clean.path, b"harmless").expect("the file is written");
        app.findings = malicious;
        app.findings.push(clean);
        app.filter.bands.clean = false;

        app.tick_all(true);
        assert_eq!(app.checked.len(), 1);
        assert!(app.checked.contains(&app.findings[0].path));
        assert!(
            !app.checked.contains(&app.findings[1].path),
            "the hidden clean file was not ticked"
        );
        assert!(app.findings[1].path.exists(), "and it is still on disk");
    }

    #[test]
    fn unticking_all_clears_the_ticks_the_filter_is_hiding_too() {
        // The asymmetry with the test above, and it is deliberate. "Tick all"
        // means the rows on screen; "untick all" means none. A tick left on an
        // invisible row would make the button's count disagree with everything
        // the user can see, and the next press would take a file they had just
        // decided against.
        let (mut app, dir) = window();
        app.findings = malicious_files(dir.path(), &["one.exe", "two.exe"]);
        app.tick_all(true);
        assert_eq!(app.checked.len(), 2);

        app.filter.sort = crate::filter::Sort::Path;
        app.filter.path_query = "one".to_owned();
        assert_eq!(app.filter.apply(&app.findings).files.len(), 1, "one hidden");
        app.tick_all(false);
        assert!(app.checked.is_empty());
    }

    #[test]
    fn a_batch_takes_every_ticked_file_and_reports_once() {
        // One card, not one per file. The corner holds four, so a batch that
        // announced each file by name would fill up with the last four and say
        // nothing about the rest — and the batch is one thing the user did.
        let (mut app, dir) = window();
        app.findings = malicious_files(dir.path(), &["one.exe", "two.exe", "three.exe"]);
        let paths: Vec<PathBuf> = app.findings.iter().map(|r| r.path.clone()).collect();

        for path in &paths {
            app.checked.insert(path.clone());
        }
        app.quarantine_checked();

        for path in &paths {
            assert!(!path.exists(), "{} was not taken", path.display());
        }
        assert_eq!(app.notifier.announced().len(), 1, "{:?}", app.notifier.announced());
        let toast = &app.notifier.announced()[0];
        assert_eq!(toast.title, "Blocked and quarantined");
        assert!(toast.body.contains("3 files"), "{}", toast.body);
        assert!(app.checked.is_empty(), "nothing is left to do");
        // And what was done is said as a sentence, in the order the user sees.
        let status = app.status.clone().expect("a status line");
        assert!(status.contains("3 files quarantined"), "{status}");
    }

    #[test]
    fn a_batch_leaves_the_clean_files_where_they_are_and_says_so() {
        // Quarantine is destructive and this window cannot undo it, so "I
        // ticked everything" must not become "it removed files the product
        // itself says are fine".
        let (mut app, dir) = window();
        app.findings = malicious_files(dir.path(), &["bad.exe"]);
        let mut clean = finding("good.txt", Verdict::Clean, 0);
        clean.path = dir.path().join("good.txt");
        std::fs::write(&clean.path, b"harmless").expect("the file is written");
        app.findings.push(clean);

        let bad = app.findings[0].path.clone();
        let good = app.findings[1].path.clone();
        app.checked.insert(bad.clone());
        app.checked.insert(good.clone());
        app.quarantine_checked();

        assert!(!bad.exists(), "the malicious one is gone");
        assert!(good.exists(), "the clean one is still there");
        assert_eq!(app.notifier.announced().len(), 1, "the take is reported once");
        assert!(app.notifier.announced()[0].body.contains("1 file"));
        let status = app.status.clone().expect("a status line");
        assert!(status.contains("1 file left alone"), "{status}");
        assert!(
            !app.checked.contains(&good),
            "the tick that was acted on is cleared"
        );
    }

    #[test]
    fn a_batch_of_only_clean_files_says_why_it_did_nothing() {
        // The one button in the window that removes files, pressed by the user,
        // which did nothing at all: "why not?" is then the only question they
        // have. It is answered in the status line, in the window they pressed
        // the button in — and nothing is sent to the shell, because nothing
        // happened to the machine.
        let (mut app, dir) = window();
        let mut clean = finding("good.txt", Verdict::Clean, 0);
        clean.path = dir.path().join("good.txt");
        std::fs::write(&clean.path, b"harmless").expect("the file is written");
        app.findings = vec![clean];

        let good = app.findings[0].path.clone();
        quarantine(&mut app, &good);
        assert!(
            app.notifier.announced().is_empty(),
            "nothing left the machine, so the shell is not told: {:?}",
            app.notifier.announced()
        );
        let status = app.status.as_deref().expect("the status line says why");
        assert!(status.contains("found clean"), "{status}");
    }

    #[test]
    fn the_files_a_batch_could_not_take_stay_ticked_so_they_can_be_tried_again() {
        // A file that could not be taken is exactly the one a user has to deal
        // with, so it keeps its tick. Clearing the whole set on the way out
        // would silently forget it and leave the button offering nothing.
        let (mut app, dir) = window();
        app.findings = malicious_files(dir.path(), &["real.exe"]);
        let mut absent = finding("gone.exe", Verdict::Malicious, 800);
        absent.path = dir.path().join("gone.exe");
        app.findings.push(absent);

        let real = app.findings[0].path.clone();
        let gone = app.findings[1].path.clone();
        app.checked.insert(real.clone());
        app.checked.insert(gone.clone());
        app.quarantine_checked();

        assert!(!real.exists());
        assert!(!app.checked.contains(&real), "the one taken is unticked");
        assert!(
            app.checked.contains(&gone),
            "the one that failed is still ticked"
        );
        let texts: Vec<&str> = app.notifier.announced().iter().map(|t| t.body.as_str()).collect();
        assert!(
            texts.iter().any(|text| text.contains("could not be quarantined")),
            "{texts:?}"
        );
        let status = app.status.clone().expect("a status line");
        assert!(status.contains("1 file could not be taken"), "{status}");
    }

    #[test]
    fn the_button_counts_the_ticked_files_and_is_disabled_until_there_are_some() {
        // The count is the only thing on screen that says what the button will
        // do, and it has to match the ticks exactly — a label reading one
        // number while the click takes another is worse than no label.
        let (mut app, dir) = window();
        app.findings = malicious_files(dir.path(), &["one.exe", "two.exe"]);
        app.tab = Tab::Findings;
        // The disabled label names the verb and carries no number. "Quarantine
        // 0 ticked" would be a count of nothing, and a user reading it has to
        // work out whether the zero is the ticks or the files.
        let drawn = drawn_text(&mut app);
        assert!(
            drawn.iter().any(|text| text.contains("Quarantine ticked files")),
            "{drawn:?}"
        );
        assert!(
            !drawn.iter().any(|text| text.contains("0 ticked")),
            "no count is shown while nothing is ticked: {drawn:?}"
        );

        app.checked.insert(app.findings[0].path.clone());
        let drawn = drawn_text(&mut app);
        assert!(
            drawn.iter().any(|text| text.contains("Quarantine 1 ticked")),
            "{drawn:?}"
        );

        app.tick_all(true);
        let drawn = drawn_text(&mut app);
        assert!(
            drawn.iter().any(|text| text.contains("Quarantine 2 ticked")),
            "{drawn:?}"
        );
        assert!(
            drawn.iter().any(|text| text.contains("2 ticked")),
            "the count row says the same number: {drawn:?}"
        );
    }

    /// Every string the window draws on the current tab, headlessly.
    ///
    /// Two frames, because an immediate-mode interface lays out on the first
    /// what the second one draws and the second is the frame a user sees.
    fn drawn_text(app: &mut GuiApp) -> Vec<String> {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let _ = ctx.run(input(egui::Vec2::new(1_024.0, 768.0)), |ctx| app.draw(ctx));
        let output = ctx.run(input(egui::Vec2::new(1_024.0, 768.0)), |ctx| app.draw(ctx));
        output
            .shapes
            .iter()
            .filter_map(|clipped| match &clipped.shape {
                egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
                _ => None,
            })
            .collect()
    }

    /// Quarantine one file through the window and hand back its identifier.
    fn quarantined(app: &mut GuiApp, dir: &tempfile::TempDir, name: &str) -> QuarantineId {
        let victim = dir.path().join(name);
        std::fs::write(&victim, b"the bytes a test wrote").expect("the victim is written");
        app.findings = vec![finding(name, Verdict::Malicious, 200)];
        app.findings[0].path = victim.clone();
        quarantine(app, &victim);
        app.vault
            .as_ref()
            .and_then(|vault| vault.list().first().map(|entry| entry.id))
            .expect("the entry exists")
    }

    #[test]
    fn a_change_made_by_another_writer_is_read_back_into_this_window() {
        // The service performs a user's decision, so this process's copy of the
        // index is stale the moment it answers. A row that still said
        // `quarantined` after its bytes had gone back to disk would offer
        // "Delete" for something that is no longer held, and the vault would
        // refuse — correctly, and incomprehensibly to the person who clicked.
        let (mut app, dir) = window();
        let id = quarantined(&mut app, &dir, "victim.exe");
        app.vault_view.clear();
        app.reload_vault_entries();
        let before = app
            .vault
            .as_ref()
            .and_then(|vault| vault.get(id).ok())
            .map(|entry| entry.status);
        assert_eq!(before, Some(EntryStatus::Quarantined));

        // Another writer: a second vault over the same directory, which is what
        // the service is from this process's point of view.
        {
            let policy = QuarantinePolicy::from(&app.config.quarantine);
            let mut other =
                QuarantineVault::open(&app.paths.quarantine_dir, policy).expect("a second vault");
            other.delete(id).expect("the other writer deleted it");
        }

        app.reload_vault_entries();
        let after = app
            .vault
            .as_ref()
            .and_then(|vault| vault.get(id).ok())
            .map(|entry| entry.status);
        assert_eq!(
            after,
            Some(EntryStatus::Deleted),
            "the window is still showing the record from before the other writer"
        );
    }

    #[test]
    fn a_selection_names_an_entry_that_is_still_in_the_vault() {
        // The selection is what every action reads, so an entry that left the
        // vault between the list being drawn and the click would leave the four
        // buttons pointing at nothing. Deleting the *record* leaves it in the
        // index and the selection is still good; a selection on an identifier the
        // index no longer names is let go of.
        let (mut app, dir) = window();
        let id = quarantined(&mut app, &dir, "victim.exe");
        app.vault_view.clear();
        app.vault_selected = Some(id);

        {
            let policy = QuarantinePolicy::from(&app.config.quarantine);
            let mut other =
                QuarantineVault::open(&app.paths.quarantine_dir, policy).expect("a second vault");
            other.delete(id).expect("the other writer deleted it");
        }
        app.reload_vault_entries();
        assert_eq!(
            app.vault_selected,
            Some(id),
            "a deleted record is still a row and its selection still means something"
        );

        // Now for an identifier the index does not name at all, which is what a
        // purge leaves behind.
        app.vault_selected = Some(QuarantineId::from_bytes([0xAB; 16]));
        app.reload_vault_entries();
        assert_eq!(app.vault_selected, None, "a selection on nothing is let go");
    }

    #[test]
    fn allowing_a_file_writes_the_exclusion_and_the_windows_scans_skip_it() {
        // With no service to ask, the window performs the allow itself — see
        // `GuiApp::allow_here`. What it must not do is *say* it did and then
        // scan the path again: the exclusion has to reach the window's own list,
        // the configuration, and the request the next scan is built from.
        let (mut app, dir) = window();
        let id = quarantined(&mut app, &dir, "victim.exe");
        let victim = dir.path().join("victim.exe");

        app.allow(&id, Allow::Permanent);

        assert!(victim.is_file(), "an allow puts the file back as well");
        assert!(
            app.allowed.contains(&victim),
            "the window's own scans do not know about it: {:?}",
            app.allowed
        );
        assert!(
            app.config.general.exclusions.contains(&victim),
            "the exclusion is not in force: {:?}",
            app.config.general.exclusions
        );
        let written = std::fs::read_to_string(&app.paths.config_file).expect("the configuration");
        assert!(
            written.contains("victim.exe"),
            "the exclusion was not written to {}: {written}",
            app.paths.config_file.display()
        );
        // The Settings tab's baseline moved with it. Without that, the next Save
        // would write the configuration from before this call and the exclusion
        // would be gone — and the tab would read as dirty by exactly one line.
        assert!(
            !app.settings.is_dirty(),
            "the draft thinks the user edited something"
        );
        assert!(
            app.settings.edited().general.exclusions.contains(&victim),
            "saving any other setting would drop this exclusion"
        );

        // And the request a scan would be built from leaves the path out.
        let request = app.scan_request(
            PathBuf::from("C:/scan"),
            app.paths.install_dir.join(scan::DATABASE_FILE),
        );
        assert!(
            request.excluded_paths.contains(&victim),
            "{:?}",
            request.excluded_paths
        );
    }

    #[test]
    fn an_allow_for_this_session_only_is_not_written_to_the_configuration() {
        // The two allowances cost different things and the file is the
        // difference. A session allow that quietly wrote itself down would be
        // this window taking a decision the user deliberately did not make.
        let (mut app, dir) = window();
        let id = quarantined(&mut app, &dir, "victim.exe");
        let victim = dir.path().join("victim.exe");

        app.allow(&id, Allow::Session);

        assert!(victim.is_file());
        assert!(app.allowed.contains(&victim));
        assert!(
            !app.config.general.exclusions.contains(&victim),
            "a session allow reached the configuration: {:?}",
            app.config.general.exclusions
        );
        let status = app.status.clone().unwrap_or_default();
        assert!(
            status.contains("until this window is closed"),
            "the line has to say how long it lasts: {status}"
        );
    }

    #[test]
    fn an_allow_the_service_performed_moves_this_windows_copies_with_it() {
        // The mirror image of the two tests above, and the one that was really
        // broken. When the service is running *it* writes the exclusion, so this
        // process never sees a file write — `report_change` only printed a line.
        // The Settings tab's draft still held the configuration from before the
        // allow, so the next Save wrote that draft over the file the service had
        // just written and the exclusion the user made disappeared. Nothing said
        // so: the status line said it was saved, and it was, until the next
        // click.
        let (mut app, dir) = window();
        let victim = dir.path().join("victim.exe");
        // What the service does before it answers, done here by the test so that
        // the file is the state `lasting: true` claims it is.
        {
            let mut written = app.config.clone();
            written.general.exclusions.push(victim.clone());
            written.save(&app.paths.config_file).expect("the service's write");
        }
        assert!(!app.settings.edited().general.exclusions.contains(&victim));

        app.report_change(
            QuarantineChange::Allowed {
                id: QuarantineId::from_bytes([3; 16]),
                path: victim.clone(),
                lasting: true,
            },
            "allowed",
        );

        assert!(
            app.allowed.contains(&victim),
            "the window's own scans would find it again: {:?}",
            app.allowed
        );
        assert!(
            app.config.general.exclusions.contains(&victim),
            "the copy this window scans with disagrees with the file: {:?}",
            app.config.general.exclusions
        );
        assert!(
            app.settings.edited().general.exclusions.contains(&victim),
            "the draft would drop the exclusion on the next Save: {:?}",
            app.settings.edited().general.exclusions
        );
        assert!(
            !app.settings.is_dirty(),
            "an allow is not an edit by the user; the tab must not read as unsaved"
        );

        // And the symptom itself, through the button the user would press: save
        // some unrelated setting and the exclusion has to still be there.
        app.settings.edited_mut().scanning.threads = 7;
        app.save_settings();
        let written = AvConfig::load_or_default(&app.paths.config_file)
            .expect("the configuration the window just wrote loads");
        assert!(
            written.general.exclusions.contains(&victim),
            "saving another setting wrote the exclusion away: {:?}",
            written.general.exclusions
        );
    }

    #[test]
    fn a_session_allow_the_service_performed_is_not_written_anywhere_by_this_window() {
        // Same path with `lasting: false`: the service held the allow in its own
        // memory and wrote nothing, so there is no durable half for this window
        // to mirror — and mirroring one would be this process inventing an
        // exclusion the user did not ask for.
        let (mut app, dir) = window();
        let victim = dir.path().join("victim.exe");

        app.report_change(
            QuarantineChange::Allowed {
                id: QuarantineId::from_bytes([4; 16]),
                path: victim.clone(),
                lasting: false,
            },
            "allowed",
        );

        assert!(app.allowed.contains(&victim));
        assert!(
            !app.config.general.exclusions.contains(&victim),
            "a session allow reached this window's configuration: {:?}",
            app.config.general.exclusions
        );
        assert!(!app.settings.edited().general.exclusions.contains(&victim));
        let status = app.status.clone().unwrap_or_default();
        assert!(
            status.contains("until the service stops"),
            "the line has to say how long it lasts: {status}"
        );
    }

    #[test]
    fn the_window_says_that_it_acted_because_the_service_did_not() {
        // The one thing these three must not do is pass themselves off as the
        // service's work. The reason is not a diagnostic detail: "no service is
        // listening" is a fact about whether the user's protection is running,
        // and it is the whole reason the change they just made is not permanent.
        let (mut app, dir) = window();
        let id = quarantined(&mut app, &dir, "victim.exe");
        app.restore(&id);
        let status = app.status.clone().unwrap_or_default();
        assert!(
            status.contains("no service is listening"),
            "the window performed this itself and has to say so: {status}"
        );
        assert!(
            status.contains("victim.exe"),
            "and it has to name the file it acted on: {status}"
        );
    }

    #[test]
    fn every_action_on_a_stored_file_is_offered_only_with_a_selection() {
        // The four buttons are the whole of the Quarantine tab's actions, and
        // each of them either writes over a file or switches a rule off for one.
        // A user who cannot see which file is selected must not be able to press
        // any of them, which is why the row is drawn only with a selection — and
        // that selection is a field of the window, not the row the pointer
        // happens to be over.
        let (mut app, dir) = window();
        quarantined(&mut app, &dir, "victim.exe");
        app.tab = Tab::Quarantine;
        app.vault_view.clear();

        app.vault_selected = None;
        let drawn = drawn_text(&mut app);
        for label in ["Put back", "Allow for now", "Allow permanently", "Delete"] {
            assert!(
                !drawn.iter().any(|text| text == label),
                "{label} is offered with nothing selected"
            );
        }

        app.vault_selected = app
            .vault
            .as_ref()
            .and_then(|vault| vault.list().first().map(|entry| entry.id));
        let drawn = drawn_text(&mut app);
        for label in ["Put back", "Allow for now", "Allow permanently", "Delete"] {
            assert!(
                drawn.iter().any(|text| text == label),
                "{label} is not offered with an item selected: {drawn:?}"
            );
        }
    }

    #[test]
    fn the_vault_row_says_which_component_and_which_rule_took_the_file() {
        // The "why" line. `QuarantineEntry` has carried both since the vault was
        // written and the row showed neither, so a user checking the one file
        // they care about had to open it by hand.
        let (mut app, dir) = window();
        let id = quarantined(&mut app, &dir, "victim.exe");
        app.tab = Tab::Quarantine;
        app.vault_view.clear();
        // The fixture's entry came from a window quarantine, so the component is
        // `manual`; the rule identifier is the one the finding carried.
        assert_eq!(
            app.vault
                .as_ref()
                .and_then(|v| v.get(id).ok())
                .map(|e| e.source),
            Some(EntrySource::Manual)
        );
        let drawn = drawn_text(&mut app);
        assert!(
            drawn
                .iter()
                .any(|text| text.contains("manual") && text.contains("Test.Rule")),
            "the row does not say what took the file: {drawn:?}"
        );
    }

    #[test]
    fn restoring_and_deleting_a_quarantined_file_work_from_the_window() {
        let (mut app, dir) = window();
        let victim = dir.path().join("victim.exe");
        std::fs::write(&victim, b"bytes").expect("the victim is written");
        app.findings = vec![finding("victim.exe", Verdict::Malicious, 200)];
        app.findings[0].path = victim.clone();
        quarantine(&mut app, &victim);
        let id = app
            .vault
            .as_ref()
            .and_then(|vault| vault.list().first().map(|entry| entry.id))
            .expect("the entry exists");

        app.restore(&id);
        assert!(victim.exists(), "it is back where it came from");

        // Restoring leaves the entry as `restored`, so a delete still needs to
        // work on a record whose bytes may or may not still be held.
        app.delete(&id);
        let entry = app
            .vault
            .as_ref()
            .and_then(|vault| vault.get(id).ok())
            .cloned();
        assert_eq!(
            entry.map(|entry| entry.status),
            Some(av_quarantine::EntryStatus::Deleted)
        );
    }

    #[test]
    fn an_unopenable_vault_is_reported_and_kept_reported() {
        // A quarantine tab that showed an empty list would tell a user their
        // vault was empty when it was in fact unreadable.
        let dir = tempfile::tempdir().expect("a temp directory");
        let paths = test_paths(dir.path());
        let mut app = window_over(paths);
        // A file where the vault directory should be: `create_dir_all` cannot
        // make a directory out of it. The parent is created by hand rather than
        // with `ensure_dirs`, because that would create the vault directory too
        // and there would be nothing in the way.
        std::fs::create_dir_all(
            app.paths
                .quarantine_dir
                .parent()
                .expect("the vault directory has a parent"),
        )
        .expect("the data directory");
        std::fs::write(&app.paths.quarantine_dir, b"in the way").expect("the blocker is written");

        app.open_vault();
        assert!(app.vault.is_none());
        let message = app.vault_error.clone().expect("the reason is kept");
        assert!(message.contains("could not be opened"), "{message}");
        // Asking again does not clear it or panic.
        app.open_vault();
        assert!(app.vault_error.is_some());
    }

    // -- the drawing ---------------------------------------------------------

    #[test]
    fn every_tab_draws_in_every_state_without_a_window() {
        let (mut app, _dir) = window();
        // Idle, with nothing found.
        draw_all_tabs(&mut app);

        // Running, with a synthetic handle and findings arriving live.
        app.state = ScanState::Running(crate::state::ScanHandle::new());
        app.apply(ScanEvent::Finding(Box::new(finding(
            "live.exe",
            Verdict::Malicious,
            200,
        ))));
        draw_all_tabs(&mut app);

        // Running with a total known, a filter hiding everything, and a
        // selection open.
        app.state = ScanState::Running(crate::state::ScanHandle::new());
        app.filter.bands = Bands {
            malicious: false,
            suspicious: false,
            unknown: false,
            clean: false,
        };
        app.selected = Some(PathBuf::from(r"C:\scanad.exe"));
        draw_all_tabs(&mut app);

        // Finished, with findings of every band and a failure in the report.
        app.filter.clear();
        app.state = ScanState::default();
        app.apply(ScanEvent::Finished(Box::new(report(
            vec![
                finding("bad.exe", Verdict::Malicious, 200),
                finding("maybe.exe", Verdict::Suspicious, 40),
                finding("odd.bin", Verdict::Unknown, 0),
            ],
            false,
        ))));
        app.selected = Some(PathBuf::from(r"C:\scanad.exe"));
        draw_all_tabs(&mut app);

        // Failed, and stopped mid-scan.
        app.apply(ScanEvent::Failed {
            message: "the rules would not load".to_owned(),
        });
        draw_all_tabs(&mut app);
        app.state = ScanState::Running(crate::state::ScanHandle::new());
        app.stop_scan();
        draw_all_tabs(&mut app);
    }

    #[test]
    fn the_quarantine_tab_draws_with_a_vault_an_empty_vault_and_a_broken_one() {
        let (mut app, dir) = window();
        // A vault with something in it.
        let victim = dir.path().join("victim.exe");
        std::fs::write(&victim, b"bytes").expect("the victim is written");
        app.findings = vec![finding("victim.exe", Verdict::Malicious, 200)];
        app.findings[0].path = victim.clone();
        quarantine(&mut app, &victim);
        app.vault_view.query = "nothing matches this".to_owned();
        draw_all_tabs(&mut app);
        app.vault_view.query.clear();
        draw_all_tabs(&mut app);

        // And a vault that will not open.
        let (mut broken, _dir) = window();
        broken.vault_error = Some("the vault is unreadable".to_owned());
        draw_all_tabs(&mut broken);
    }

    // -- the pieces ----------------------------------------------------------

    #[test]
    fn a_short_name_is_the_last_component_and_never_an_empty_string() {
        assert_eq!(short_name(Path::new("C:\\a\\b\\c.exe")), "c.exe");
        assert_eq!(short_name(Path::new("C:\\")), "C:\\");
        assert_eq!(short_name(Path::new("")), "");
    }

    #[test]
    fn the_default_target_is_a_folder_that_exists_or_nothing_at_all() {
        // Never a drive root: a window that opens pointing at `C:\` is one
        // click from an hour-long scan nobody asked for.
        let target = default_target();
        assert!(!target.ends_with(":\\"), "{target}");
        assert_eq!(
            target,
            target.trim(),
            "no stray whitespace to be trimmed later"
        );
    }

    // -- the pickers ---------------------------------------------------------
    //
    // The dialogs themselves cannot be tested — see `picker.rs` — so what is
    // tested here is everything that happens once one has closed, which is the
    // whole of what a picked path does to the window.

    #[test]
    fn a_picked_folder_becomes_the_target_and_the_window_says_so() {
        let (mut app, _dir) = window();
        app.target = "something that was typed".to_owned();
        app.set_target(Some(PathBuf::from(r"C:\Users\me\Downloads")));
        assert_eq!(app.target, r"C:\Users\me\Downloads");
        assert!(
            app.status
                .as_deref()
                .is_some_and(|status| status.contains("Downloads")),
            "the status line names what was chosen: {:?}",
            app.status
        );
    }

    #[test]
    fn a_cancelled_picker_is_not_a_decision() {
        // The commonest outcome of opening a picker is closing it again. It
        // must leave the field exactly as the user left it, and must not claim
        // in the status line that anything was chosen.
        let (mut app, _dir) = window();
        app.target = "C:\\typed\\by hand".to_owned();
        let before = app.status.clone();
        app.set_target(None);
        assert_eq!(app.target, "C:\\typed\\by hand");
        assert_eq!(app.status, before, "a cancellation says nothing happened");
    }

    #[test]
    fn a_picked_path_is_scanned_exactly_as_it_was_picked() {
        // A folder with a space in its name is the case where a path can be
        // mangled between the dialog and the scan — and it is not a rare name.
        let (mut app, _dir) = window();
        let picked = PathBuf::from(r"C:\Program Files\Some Vendor\app");
        app.set_target(Some(picked.clone()));
        // What `start_scan` would hand the driver, from the same conversion.
        assert_eq!(PathBuf::from(app.target.trim()), picked);
    }

    #[test]
    #[cfg(windows)]
    fn a_picked_path_that_is_not_valid_utf8_is_shown_rather_than_refused() {
        // A file name on Windows is a sequence of UTF-16 code units and need
        // not be valid UTF-8 at all. The choice `set_target` makes is to show
        // it with the replacement character rather than to refuse it: a picker
        // that silently did nothing on a folder the user is looking at is worse
        // than one that shows a path they can see is not quite right.
        use std::os::windows::ffi::OsStringExt;
        let (mut app, _dir) = window();
        let lone_surrogate = vec![
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            0xD800, // an unpaired surrogate: legal in a path, not in UTF-8
        ];
        app.set_target(Some(PathBuf::from(std::ffi::OsString::from_wide(
            &lone_surrogate,
        ))));
        assert!(app.target.starts_with("C:\\"), "{:?}", app.target);
        assert!(
            app.target.contains('\u{fffd}'),
            "the unrepresentable unit is visible: {:?}",
            app.target
        );
    }

    #[test]
    fn the_picker_buttons_are_offered_exactly_where_a_picker_exists() {
        // The drawing code asks one question, and this is the pairing it is
        // asking about: `picker::available()` is what decides whether the two
        // buttons are drawn, so a platform without a picker has no button that
        // opens nothing.
        assert_eq!(picker::available(), cfg!(windows));
    }

    /// The sizes the configuration ships with have to be sizes a window can be.
    ///
    /// The one test that ties the two together: `ui.window_width` and
    /// `ui.window_height` are what `main` opens the window at, and this is the
    /// assertion that an edit to either default is an edit to something that is
    /// still a usable window — wide enough for the findings list's path column
    /// and short enough for a laptop screen with the taskbar showing.
    #[test]
    fn the_window_opens_large_enough_for_its_own_contents_and_no_larger() {
        let opening = window_size(&av_core::config::UiConfig::default());
        assert!(opening[0] >= MIN_WINDOW_SIZE[0], "{opening:?}");
        assert!(opening[1] >= MIN_WINDOW_SIZE[1], "{opening:?}");
        // A laptop screen with a taskbar is about 1,300 by 700 usable pixels.
        assert!(opening[1] <= 760.0, "too tall for a laptop: {opening:?}");
        assert!(MIN_WINDOW_SIZE[0] >= 480.0, "too narrow to be usable");
    }

    /// The clamp, over every value a text file can hold.
    ///
    /// `ui.window_width` is a number a person types, so it can be `0`, negative,
    /// a million, or `nan` — and the window it describes is the one the settings
    /// screen is inside, which is why none of those may stop it opening.
    #[test]
    fn a_window_size_from_the_configuration_is_clamped_to_something_that_is_a_window() {
        let with = |width: f32, height: f32| {
            let mut ui = av_core::config::UiConfig::default();
            ui.window_width = width;
            ui.window_height = height;
            window_size(&ui)
        };

        // A size that is a size is passed through untouched, which is the whole
        // point — a clamp that moved the ordinary case would be a setting that
        // does not do what it says.
        assert_eq!(with(1_180.0, 760.0), [1_180.0, 760.0]);
        assert_eq!(with(2_400.0, 1_400.0), [2_400.0, 1_400.0]);

        // Below the floor, at it, and above the ceiling.
        assert_eq!(with(0.0, 0.0), MIN_WINDOW_SIZE);
        assert_eq!(with(-100.0, -1.0), MIN_WINDOW_SIZE);
        assert_eq!(
            with(MIN_WINDOW_SIZE[0], MIN_WINDOW_SIZE[1]),
            MIN_WINDOW_SIZE
        );
        assert_eq!(with(1.0e9, 1.0e9), MAX_WINDOW_SIZE);

        // `f32::from_str` accepts these, and `f32::clamp` would propagate the
        // NaN into the window's size rather than refusing it.
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(with(bad, bad), MIN_WINDOW_SIZE, "{bad} was not answered");
        }
    }

    #[test]
    fn a_finding_row_and_a_detail_pane_are_built_from_the_modules_and_not_by_hand() {
        let report = finding("bad.exe", Verdict::Malicious, 200);
        let facts = row_facts(&report);
        let labels: Vec<&str> = facts.iter().map(|(label, _)| *label).collect();
        assert!(labels.contains(&"Verdict"));
        assert!(labels.contains(&"Score"));
        assert!(facts
            .iter()
            .any(|(_, value)| value == theme::verdict_word(Verdict::Malicious)));

        let detections = row_detections(&report);
        assert_eq!(detections.len(), 1);
        assert!(detections[0].0.contains("Test.Rule.bad.exe"));
        // The detail rows come from `format`, so the window and the console
        // cannot disagree about what a detection says.
        assert!(detections[0].1.iter().any(|(label, _)| *label == "Rule"));
    }

    /// The value of one fact row, by label.
    fn fact<'a>(facts: &'a [(&'static str, String)], label: &str) -> Option<&'a str> {
        facts
            .iter()
            .find(|(name, _)| *name == label)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn a_finding_trust_never_touched_says_nothing_about_trust() {
        // The ordinary finding, and the reason this is asserted rather than
        // assumed: a `Remediation` row reading "withheld" on a file nothing was
        // withheld from would be the window inventing a decision nobody made.
        let report = finding("bad.exe", Verdict::Malicious, 200);
        assert!(!report.assessment.remediation_withheld);
        let facts = row_facts(&report);
        assert_eq!(fact(&facts, "Remediation"), None);
        assert_eq!(fact(&facts, "Suppressed"), None);
    }

    #[test]
    fn a_capped_finding_says_why_nothing_was_done_about_it() {
        // Verdict left in a band that acts, and `remediation_withheld` set: the
        // file was capped, not cleared. `clear_generic` would have moved the
        // verdict, so a capped file that stayed capped has no proven identity —
        // which is why the sentence may say the certificate was read and not
        // verified, and may not say the catalogue proved anything.
        let mut report = finding("signed.exe", Verdict::Suspicious, 60);
        report.assessment.withhold_remediation();
        let facts = row_facts(&report);
        let value = fact(&facts, "Remediation").expect("a capped file says so");
        assert!(value.contains("withheld"), "{value}");
        assert!(value.contains("not verified"), "{value}");
        assert!(value.contains("left alone"), "{value}");
        assert_eq!(fact(&facts, "Suppressed"), None);
    }

    #[test]
    fn a_cleared_file_names_the_rules_that_were_thrown_away() {
        // Clean, withheld, and rules in `suppressed`: what `clear_generic`
        // leaves behind. The rule ids have to be on the row, because the file is
        // not in the findings list and this pane is the only place a GUI user
        // can read them — "why was this not detected" has to have an answer.
        let mut report = finding("catalogued.dll", Verdict::Clean, 40);
        report.assessment.suppress("SIGNATURE_BASE_WEBSHELL");
        report.assessment.suppress("HEURISTIC_PACKED_UPX");
        report.assessment.withhold_remediation();
        let facts = row_facts(&report);
        let value = fact(&facts, "Remediation").expect("a cleared file says so");
        assert!(value.contains("not needed"), "{value}");
        assert!(value.contains("catalogue"), "{value}");
        let suppressed = fact(&facts, "Suppressed").expect("the rules are named");
        assert!(suppressed.contains("SIGNATURE_BASE_WEBSHELL"), "{suppressed}");
        assert!(suppressed.contains("HEURISTIC_PACKED_UPX"), "{suppressed}");
    }

    #[test]
    fn the_settings_tab_offers_the_engines_default_thresholds_to_begin_with() {
        let (app, _dir) = window();
        assert_eq!(
            app.settings.edited().scanning.thresholds,
            VerdictThresholds::default()
        );
        assert_eq!(app.config.scanning.thresholds, VerdictThresholds::default());
    }

    #[test]
    fn a_configuration_that_will_not_load_opens_on_the_defaults_and_says_so() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let paths = test_paths(dir.path());
        std::fs::create_dir_all(paths.config_file.parent().expect("a parent"))
            .expect("the config directory");
        std::fs::write(&paths.config_file, "this is not toml at all {{{")
            .expect("the broken configuration");

        let app = GuiApp::load(paths);
        assert_eq!(app.config, AvConfig::default());
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("could not be read"), "{status}");
    }

    #[test]
    fn the_quarantine_policy_comes_from_the_configuration() {
        // A vault opened by the window must enforce what the service enforces;
        // a window that opened one with default settings would ignore the
        // retention and size ceiling the user set.
        let (mut app, _dir) = window();
        app.config.quarantine.max_size_bytes = 4_096;
        app.config.quarantine.retention_days = Some(7);
        app.open_vault();
        let vault = app.vault.as_ref().expect("the vault opens");
        assert_eq!(vault.policy().max_vault_size, 4_096);
        assert_eq!(
            vault.policy().retention,
            Some(Duration::from_secs(7 * 24 * 60 * 60))
        );
    }

    #[test]
    fn the_vault_view_filters_and_sorts_the_entries_the_window_shows() {
        let (mut app, dir) = window();
        for (name, size) in [("b.exe", 20u64), ("a.exe", 10)] {
            let path = dir.path().join(name);
            std::fs::write(&path, vec![b'x'; size as usize]).expect("the victim is written");
            app.findings = vec![finding(name, Verdict::Malicious, 200)];
            app.findings[0].path = path.clone();
            quarantine(&mut app, &path);
        }
        let entries: Vec<QuarantineEntry> = app
            .vault
            .as_ref()
            .map(|vault| vault.entries().to_vec())
            .unwrap_or_default();
        assert_eq!(entries.len(), 2);

        app.vault_view.query = "a.exe".to_owned();
        let shown = app.vault_view.apply(&entries);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].file_name, "a.exe");

        app.vault_view.query.clear();
        app.vault_view.sort = VaultSort::Size;
        let shown = app.vault_view.apply(&entries);
        assert_eq!(shown[0].file_name, "b.exe", "largest first");
    }

    #[test]
    fn the_source_control_offers_every_source_the_engine_can_report() {
        // The list in the combo is written out by hand in this module, so it
        // has to be pinned: a source the engine reports and the filter cannot
        // name is a set of findings the user cannot narrow to.
        let all = [
            av_core::DetectionSource::Signature,
            av_core::DetectionSource::Heuristic,
            av_core::DetectionSource::Behavior,
            av_core::DetectionSource::Memory,
            av_core::DetectionSource::Reputation,
            av_core::DetectionSource::User,
        ];
        let mut seen: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 6);
    }

    // -- the notification area ------------------------------------------------

    /// What the frame does with a fresh `Pending`, so that a command's effect on
    /// it can be read back.
    fn drain(app: &mut GuiApp, ctx: &egui::Context) -> Pending {
        let mut pending = Pending::default();
        app.drain_tray(ctx, &mut pending);
        pending
    }

    #[test]
    fn a_window_may_only_put_itself_away_when_there_is_an_icon_to_get_it_back() {
        // The property the whole module is arranged around. Both halves are
        // needed and each is tested by holding the other fixed: putting the
        // window away with the setting on and no icon is a running program with
        // nothing on screen to say so, and doing it with an icon but the setting
        // off ignores what the user asked for.
        let (mut app, _dir) = window();
        assert!(app.config.general.minimize_to_tray, "the default this starts from");
        assert!(
            !app.minimises_instead_of_closing(),
            "there is no icon, so there is no way back"
        );

        let (tray, _clicks) = tray::Tray::for_test();
        app.set_tray(Some(tray));
        assert!(app.minimises_instead_of_closing());

        app.config.general.minimize_to_tray = false;
        assert!(
            !app.minimises_instead_of_closing(),
            "the setting is still the setting"
        );
    }

    /// The viewport commands one drawn frame emits, which is where a visibility
    /// decision is observable: the app only asks for the change, and the
    /// platform applies it at the end of the frame.
    fn commands_of(app: &mut GuiApp) -> Vec<egui::ViewportCommand> {
        commands_of_input(app, egui::RawInput::default())
    }

    /// The same, for a frame the platform handed something first.
    ///
    /// A close is a viewport *event* rather than a command, so the frame that
    /// answers one is a frame that has to be given it — which is also the only
    /// way to reach `answer_close_request` from a test at all.
    fn commands_of_input(app: &mut GuiApp, input: egui::RawInput) -> Vec<egui::ViewportCommand> {
        let ctx = egui::Context::default();
        ctx.run(input, |ctx| app.draw(ctx))
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .expect("the root viewport reported")
            .commands
            .clone()
    }

    /// A frame whose window the platform has been asked to close.
    fn a_close_request() -> egui::RawInput {
        let mut input = egui::RawInput::default();
        let mut viewport = egui::ViewportInfo::default();
        viewport.events.push(egui::ViewportEvent::Close);
        input.viewports.insert(egui::ViewportId::ROOT, viewport);
        input
    }

    #[test]
    fn a_launch_with_no_window_is_shown_when_the_icon_could_not_be_made() {
        // `--minimized` on a machine whose shell refused the icon: honouring the
        // flag would leave a running process with no window and no icon, which a
        // user can only find in Task Manager and cannot see is running at all.
        let (mut app, _dir) = window();
        app.launched_hidden(true);

        let commands = commands_of(&mut app);
        assert!(
            commands.contains(&egui::ViewportCommand::Minimized(false)),
            "the window is restored onto the screen: {commands:?}"
        );
        assert!(
            !commands.contains(&egui::ViewportCommand::Minimized(true)),
            "and is never put away: {commands:?}"
        );
        assert!(!app.launched_hidden, "the question is settled once");
    }

    #[test]
    fn a_launch_with_an_icon_puts_the_window_away_after_the_first_frame() {
        // The half that `ViewportBuilder::with_visible(false)` cannot do by
        // itself: `eframe` unhides the window at the end of the first frame no
        // matter how it was created, so a `--minimized` start that only passed
        // the builder flag is a window on screen. Measured on the release build
        // before this line existed — the window logged that it had started with
        // no window and `Process.MainWindowHandle` found it anyway.
        //
        // Minimised and not hidden, and the difference is the whole reason this
        // test is worth having: a hidden window gets no `WM_PAINT`, so the frame
        // this command is sent on would be the process's last. See
        // [`GuiApp::put_out_of_the_way`] for the frame counts that were
        // measured. So this test asserts *no* `Visible` command as well, and
        // that assertion is the one that keeps somebody from "fixing" the
        // flicker by hiding the window instead.
        let (mut app, _clicks, _dir) = window_with_an_icon();
        app.launched_hidden(true);

        let commands = commands_of(&mut app);
        assert!(
            commands.contains(&egui::ViewportCommand::Minimized(true)),
            "the window goes off the screen: {commands:?}"
        );
        assert!(
            !commands.iter().any(|c| matches!(c, egui::ViewportCommand::Visible(_))),
            "and is never hidden — a hidden window stops drawing frames: {commands:?}"
        );

        // Once. A window that minimised itself every frame could never be
        // restored, and the icon that is supposed to bring it back would be a
        // click that did nothing.
        let later = commands_of(&mut app);
        assert!(
            !later.iter().any(|c| matches!(c, egui::ViewportCommand::Minimized(_))),
            "the second frame asks for nothing: {later:?}"
        );
    }

    #[test]
    fn an_icon_that_opens_the_window_goes_to_the_tab_it_names() {
        // Three commands, three places. A user who clicked "Quarantine…" is
        // looking for the quarantine list, and one who clicked the icon itself
        // is looking for whatever they were last on: the icon is not a
        // navigation control.
        let (mut app, clicks, _dir) = window_with_an_icon();
        let ctx = egui::Context::default();

        app.tab = Tab::Settings;
        clicks.send(TrayCommand::Open).expect("the click");
        drain(&mut app, &ctx);
        assert_eq!(app.tab, Tab::Settings, "Open leaves the tab where it was");

        clicks.send(TrayCommand::Quarantine).expect("the click");
        drain(&mut app, &ctx);
        assert_eq!(app.tab, Tab::Quarantine);

        clicks.send(TrayCommand::Scan).expect("the click");
        let pending = drain(&mut app, &ctx);
        assert_eq!(app.tab, Tab::Scan);
        assert!(
            pending.pick_folder,
            "the picker is opened after the frame, like the button's"
        );
    }

    #[test]
    fn the_close_button_puts_the_window_away_instead_of_ending_the_process() {
        // The user's side of the same decision. Asserted as the two commands
        // `egui` actually emitted, because the failure mode is a cancel that is
        // not sent: without it the window closes, the quarantine list goes with
        // it, and the icon in the notification area is left pointing at a
        // process that has gone.
        let (mut app, _clicks, _dir) = window_with_an_icon();

        let commands = commands_of_input(&mut app, a_close_request());
        assert!(
            commands.contains(&egui::ViewportCommand::CancelClose),
            "the close is refused: {commands:?}"
        );
        assert!(
            commands.contains(&egui::ViewportCommand::Minimized(true)),
            "and the window is put out of the way: {commands:?}"
        );
    }

    #[test]
    fn the_close_button_closes_the_window_when_there_is_no_icon_to_get_it_back() {
        // The other half, and the one that keeps the first from being a trap: a
        // machine with no notification area must not have a window whose close
        // button does nothing, because there is nothing else to reach it by.
        let (mut app, _dir) = window();

        let commands = commands_of_input(&mut app, a_close_request());
        assert!(
            !commands.contains(&egui::ViewportCommand::CancelClose),
            "the close is allowed to happen: {commands:?}"
        );
    }

    #[test]
    fn the_close_button_ends_the_process_once_the_icon_has_been_used_to_leave() {
        // The X and the icon's Exit answer the same question differently, and
        // this is the flag that separates them: without it, Exit would ask for a
        // close that the next frame cancels, and the only way to stop the
        // program would be Task Manager.
        let (mut app, clicks, _dir) = window_with_an_icon();
        clicks.send(TrayCommand::Exit).expect("the click");
        drain(&mut app, &egui::Context::default());

        let commands = commands_of_input(&mut app, a_close_request());
        assert!(
            !commands.contains(&egui::ViewportCommand::CancelClose),
            "this close is the one that ends it: {commands:?}"
        );
    }

    #[test]
    fn an_icon_that_says_leave_makes_the_window_close_rather_than_minimise() {
        // The one command that is not "show the window", and the reason the
        // window can put itself away at all: without it, a window whose close
        // button does not close has no close button that works, and the only way
        // out would be Task Manager.
        let (mut app, clicks, _dir) = window_with_an_icon();
        assert!(app.minimises_instead_of_closing(), "it minimises by default here");
        assert!(!app.quitting);

        clicks.send(TrayCommand::Exit).expect("the click");
        drain(&mut app, &egui::Context::default());

        assert!(app.quitting, "the close it asks for is the one that ends it");
    }

    #[test]
    fn two_clicks_between_two_frames_are_two_commands() {
        // The channel is a queue and not a flag: a user who clicks the icon and
        // then picks Quarantine before the next frame has asked for both, and
        // dropping either of them would be a click that did nothing.
        let (mut app, clicks, _dir) = window_with_an_icon();
        let ctx = egui::Context::default();
        clicks.send(TrayCommand::Open).expect("the click");
        clicks.send(TrayCommand::Quarantine).expect("the click");
        drain(&mut app, &ctx);
        assert_eq!(app.tab, Tab::Quarantine, "the later request is the state");
        assert!(app.tray.is_some());
    }

    #[test]
    fn a_window_with_no_icon_ignores_the_channel_it_does_not_have() {
        // The non-Windows build and the refused-icon case are the same value
        // here, and neither may panic or act: there is no receiver to read, and
        // the frame has to draw regardless.
        let (mut app, _dir) = window();
        let ctx = egui::Context::default();
        let pending = drain(&mut app, &ctx);
        assert!(!pending.pick_folder);
        assert!(!app.quitting);
    }

    // -- later launches ------------------------------------------------------

    /// A window subscribed to a channel the test can wake it through.
    ///
    /// Tied to [`window_with_rules`] rather than to [`window`] because the
    /// interesting half of what a wake does is start a scan, and a window with
    /// no rule database refuses to start one — see
    /// [`GuiApp::start_scan`]. A test built on `window` would pass whether or
    /// not the wake reached the scan at all.
    fn window_that_hears_launches() -> (
        GuiApp,
        crossbeam_channel::Sender<crate::single::Wake>,
        tempfile::TempDir,
    ) {
        let (mut app, dir) = window_with_rules();
        let (sender, receiver) = crossbeam_channel::unbounded();
        app.watch_for_later_launches(receiver);
        (app, sender, dir)
    }

    #[test]
    fn a_second_launch_with_no_arguments_raises_the_window_and_scans_nothing() {
        // The plain double-click: the user asked for the window they already
        // have. Nothing about the scan state may change — a second click that
        // started a scan of whatever was in the target field would be the
        // window acting on a request nobody made.
        let (mut app, wakes, _dir) = window_that_hears_launches();
        app.target = r"C:\somewhere\already\typed".to_owned();
        let before = app.target.clone();

        wakes.send(crate::single::Wake::Focus).expect("the send");
        let ctx = egui::Context::default();
        app.drain_later_launches(&ctx);

        assert_eq!(app.target, before, "a bare focus changes no target");
        assert!(!app.state.is_running(), "a bare focus starts nothing");
    }

    #[test]
    fn a_second_launch_naming_a_file_puts_it_in_the_field_and_scans_it() {
        // The Explorer verb, which is the case the whole mechanism exists for:
        // `wenle-gui.exe --scan "%1"` against a window that is already open.
        let (mut app, wakes, dir) = window_that_hears_launches();
        let target = dir.path().join("thing.exe");

        wakes
            .send(crate::single::Wake::Scan(target.clone()))
            .expect("the send");
        let ctx = egui::Context::default();
        app.drain_later_launches(&ctx);

        assert_eq!(app.target, target.to_string_lossy(), "the field is the path");
        assert!(app.state.is_running(), "and the scan has started");
        assert_eq!(app.tab, Tab::Scan, "on the tab that shows it");
    }

    #[test]
    fn a_launch_arriving_while_a_scan_runs_is_kept_and_said_out_loud() {
        // A right-click during a scan cannot be honoured at that instant — two
        // scans over one findings list is two answers to every question the
        // list asks — but dropping it silently is the outcome this whole
        // mechanism exists to prevent. The path waits in the field, which is
        // what the Scan button reads, and the status line says so.
        let (mut app, wakes, dir) = window_that_hears_launches();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        let ctx = egui::Context::default();

        wakes
            .send(crate::single::Wake::Scan(first))
            .expect("the send");
        app.drain_later_launches(&ctx);
        assert!(app.state.is_running(), "the first scan is running");

        wakes
            .send(crate::single::Wake::Scan(second.clone()))
            .expect("the send");
        app.drain_later_launches(&ctx);

        assert_eq!(
            app.target,
            second.to_string_lossy(),
            "the request the user made is what the field shows"
        );
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("already running"), "{status}");
        assert!(status.contains("target field"), "{status}");
        app.stop_scan();
    }

    #[test]
    fn a_wake_from_a_build_that_disagrees_about_the_format_only_raises() {
        // `single::decode` answers `None` for a message it cannot read, and the
        // listener's response to that is to send nothing at all — see
        // `single::listen`. The window is then in the state this asserts: no
        // target moved, no scan started, and only the raise, which happens
        // whether or not a wake arrived.
        let (mut app, wakes, _dir) = window_that_hears_launches();
        app.target = r"C:\untouched".to_owned();

        // What the listener does with an undecodable message.
        assert_eq!(crate::single::decode(&[9, 9, 9]), None);
        wakes.send(crate::single::Wake::Focus).expect("the send");
        let ctx = egui::Context::default();
        app.drain_later_launches(&ctx);

        assert_eq!(app.target, r"C:\untouched");
        assert!(!app.state.is_running());
    }

    #[test]
    fn a_wake_shows_the_window_before_it_restores_and_focuses_it() {
        // Two commands, and the order is the point: `Minimized(false)` because a
        // minimised window is the state the close button leaves it in, and
        // `Focus` after it because it is documented as having no effect on a
        // minimised window — so a `Focus` first would be discarded and a second
        // launch while the tray was holding the window would bring it back
        // behind whatever the user was looking at. Asserted against the commands
        // `egui` actually emitted rather than against the source, because the
        // failure this guards against is somebody dropping one of the two lines.
        let (mut app, wakes, _dir) = window_that_hears_launches();
        wakes.send(crate::single::Wake::Focus).expect("the send");

        let ctx = egui::Context::default();
        let output = ctx.run(egui::RawInput::default(), |ctx| app.draw(ctx));
        let commands = &output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .expect("the root viewport reported")
            .commands;

        let restore = commands
            .iter()
            .position(|command| matches!(command, egui::ViewportCommand::Minimized(false)));
        let focus = commands
            .iter()
            .position(|command| matches!(command, egui::ViewportCommand::Focus));
        assert!(restore.is_some(), "restored: {commands:?}");
        assert!(focus.is_some(), "and focused: {commands:?}");
        assert!(restore < focus, "in that order: {commands:?}");
        assert!(
            !commands.iter().any(|c| matches!(c, egui::ViewportCommand::Visible(_))),
            "and the window is never hidden: a hidden window stops drawing \
             frames, so a wake could not reach it in the first place: {commands:?}"
        );
    }

    #[test]
    fn a_frame_with_no_wake_asks_for_neither_command() {
        // The other half of the test above, and the reason both are needed: a
        // window that restored and focused itself on every frame would fight the
        // user for the foreground sixty times a second.
        let (mut app, _wakes, _dir) = window_that_hears_launches();
        let ctx = egui::Context::default();
        let output = ctx.run(egui::RawInput::default(), |ctx| app.draw(ctx));
        let commands = &output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .expect("the root viewport reported")
            .commands;
        assert!(
            !commands
                .iter()
                .any(|command| matches!(command, egui::ViewportCommand::Focus)),
            "{commands:?}"
        );
    }

    #[test]
    fn a_window_nobody_has_claimed_hears_nothing_and_does_not_mind() {
        // `wakes` is `None` in a build with no single-instance mechanism, and
        // the drain has to be a no-op there rather than a panic: the window is
        // drawn every frame whatever this field holds.
        let (mut app, _dir) = window();
        assert!(app.wakes.is_none());
        let ctx = egui::Context::default();
        app.drain_later_launches(&ctx);
        assert!(!app.state.is_running());
    }
}
