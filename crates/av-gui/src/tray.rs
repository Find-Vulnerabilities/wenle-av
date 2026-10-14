//! The icon in the notification area, and what clicking it asks for.
//!
//! # Why this process needs a second window
//!
//! `Shell_NotifyIconW` is not a drawing call. It hands the shell a *window
//! handle* and a message number, and the shell then posts messages to that
//! window when the user clicks the icon, hovers it, or picks something from the
//! menu. A process with no window of its own therefore has nowhere for those to
//! arrive, which is why there is one here: a *message-only* window
//! (`HWND_MESSAGE`), which is a real `HWND` with a real window procedure that is
//! never drawn, never appears in the taskbar, and is not found by `FindWindow`'s
//! ordinary search — the shell can post to it and nothing can see it.
//!
//! # Why a thread, and why not the drawing thread
//!
//! The window and its message loop live on a thread of their own. Two reasons,
//! and either would be enough:
//!
//! * **A menu runs a nested message loop.** `TrackPopupMenuEx` does not return
//!   until the user chooses a line or dismisses the menu, which for a
//!   right-click on a tray icon is however long a person takes to read it. Run
//!   on the drawing thread, that would freeze the window for the whole of it.
//! * **A window belongs to the thread that created it.** Win32 delivers a
//!   window's messages on that thread, and no other, so the loop has to be
//!   somewhere that can block. `egui`'s frame is not that place.
//!
//! The two threads talk over a channel. Nothing is shared and nothing is
//! locked: the tray thread sends a [`Command`] and asks `egui` to repaint, and
//! the window drains the channel once a frame.
//!
//! # Putting the window away is only safe when this exists
//!
//! [`Tray::start`] answers whether the icon is *there*, and the caller's next
//! decision depends on it: a window that puts itself out of the way with no icon
//! in the notification area has no way back, and nothing on screen says the
//! program is still running. So every uncertain answer is `None` — a shell that
//! refused the icon, a thread that could not be started, and a shell that did
//! not answer within [`START_TIMEOUT`] all mean the same thing to a caller,
//! which is "keep the window where the user can see it".
//!
//! "Out of the way" means minimised and never hidden, and that is a measurement
//! rather than a preference — see `GuiApp::put_out_of_the_way`, which carries
//! the frame counts. A hidden window stops receiving frames, so this icon's
//! commands would be sent from a working thread into a process that had stopped
//! reading them.
//!
//! # What this module does not do
//!
//! It does not decide what a command means. [`Command::Scan`] is a request to
//! put the window in front of the user with a folder to scan; where that folder
//! comes from, and what happens if the user cancels the picker, belong to the
//! window. This module's whole job is to turn a click in the notification area
//! into one of four values on a channel.

use std::time::Duration;

use crossbeam_channel::Receiver;
// Named only by the test constructor below, and an import nothing in the
// product reads is a warning this workspace does not carry.
#[cfg(test)]
use crossbeam_channel::Sender;

/// How long [`Tray::start`] waits for the shell to say whether it took the icon.
///
/// Generous, because the answer is normally immediate — creating a window and
/// adding an icon is a few milliseconds — and because the failure it guards
/// against is a window put out of the way with no way back. Time spent waiting
/// here is spent before the window opens, once.
pub const START_TIMEOUT: Duration = Duration::from_secs(5);

/// What a click in the notification area asks the window to do.
///
/// Four values and not a callback, because the thread that receives the click is
/// not the thread that owns the window: the command crosses to the drawing
/// thread over a channel and is acted on in a frame, like every other thing that
/// happens to this window from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    /// Show the window and bring it to the front.
    Open,
    /// Show the window and ask it for something to scan.
    Scan,
    /// Show the window on the Quarantine tab.
    Quarantine,
    /// Stop the process.
    ///
    /// The one command here that is not "show the window". A window that puts
    /// itself away instead of closing has no close button that works, so without
    /// this line the only way to stop the program would be Task Manager.
    Exit,
}

impl Command {
    /// Every command, in the order the menu lists them.
    ///
    /// The single list the menu and the Win32 identifiers are both derived from:
    /// a command added here is in the menu and has an identifier, and one that
    /// is not here has neither. Two hand-written lists that have to agree is
    /// exactly the drift this avoids.
    pub const ALL: [Command; 4] = [
        Command::Open,
        Command::Scan,
        Command::Quarantine,
        Command::Exit,
    ];

    /// The menu, top to bottom: three things that open the window, a rule, and
    /// the one that ends the process.
    ///
    /// `Exit` is under the rule on purpose. A tray menu is a list a user reads
    /// while aiming at one line, and the only line here that stops their
    /// protection is the one that should not be a slip away from the others.
    pub const MENU: [Entry; 5] = [
        Entry::Item(Command::Open),
        Entry::Item(Command::Scan),
        Entry::Item(Command::Quarantine),
        Entry::Separator,
        Entry::Item(Command::Exit),
    ];

    /// What the menu line says.
    pub fn label(self) -> &'static str {
        match self {
            Command::Open => "Open Wenle AV",
            Command::Scan => "Scan a folder…",
            Command::Quarantine => "Quarantine…",
            Command::Exit => "Exit",
        }
    }

    /// Every command as a sentence about what it does to the window.
    ///
    /// Used by a test rather than by the menu, because the strings have to be
    /// distinct and none of them may be empty, and the tray is the one part of
    /// this window that cannot be clicked from a test.
    #[cfg(test)]
    pub fn description(self) -> &'static str {
        match self {
            Command::Open => "show the window",
            Command::Scan => "show the window and pick something to scan",
            Command::Quarantine => "show the window on the quarantine list",
            Command::Exit => "stop the program",
        }
    }

    /// The identifier this command is filed under in the Win32 menu.
    ///
    /// Derived from [`Command::ALL`] rather than written out, so that it cannot
    /// disagree with the list the menu is built from. Zero is never returned:
    /// Win32 reads zero back from `TrackPopupMenuEx` as "the menu was dismissed
    /// without a choice", which is why the numbering starts at one.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn menu_id(self) -> usize {
        Self::ALL.iter().position(|other| *other == self).map_or(0, |at| at + 1)
    }

    /// The command a Win32 menu identifier names, if it names one.
    ///
    /// Total in both directions: an identifier that came from anywhere else — a
    /// menu dismissed with no choice, or a value this build does not know — is
    /// `None`, and the caller does nothing rather than guessing.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn from_menu_id(id: usize) -> Option<Self> {
        id.checked_sub(1).and_then(|at| Self::ALL.get(at)).copied()
    }
}

/// One line of the notification-area menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// A command the user can choose.
    Item(Command),
    /// A horizontal rule, which cannot be chosen.
    Separator,
}

/// The icon in the notification area, for as long as it is there.
///
/// Held rather than owned by the window's state so that the icon's lifetime is
/// written down in a type: dropping this closes the channel the tray thread
/// sends on, and the thread takes the icon down the next time it has something
/// to say. A process that exits does that sooner, which is the only other way
/// this ends.
#[derive(Debug)]
pub struct Tray {
    commands: Receiver<Command>,
}

impl Tray {
    /// Put an icon in the notification area and start taking what it is asked
    /// for.
    ///
    /// `None` when there is no icon to put there: a build for another platform,
    /// a thread that could not be started, a shell that refused the icon, or a
    /// shell that did not answer within [`START_TIMEOUT`]. The caller is expected
    /// to refuse to put its window away in every one of those cases — see the
    /// module documentation.
    ///
    /// `context` is a clone of the drawing thread's `egui` context, and it is
    /// what makes an idle window wake up: `egui` draws nothing until something
    /// asks it to, and the vault poll's one-second tick is otherwise the only
    /// thing that would. Asking it to repaint from here is the difference
    /// between a tray command taking effect and a tray command taking effect the
    /// next time the user happens to move the mouse over the window.
    ///
    /// It matters more than a delay, and that is worth stating because the first
    /// version of this window got it wrong: a window is put out of the way by
    /// being *minimised*, never by being hidden, because Windows does not
    /// deliver `WM_PAINT` to a window whose `IsWindowVisible` is false and
    /// `eframe` gets its frames from exactly that message. Hiding the window
    /// stops its clock, and a stopped window would never reach the drain that
    /// reads this channel however loudly the context asked to be repainted. See
    /// `GuiApp::put_out_of_the_way` for the frame counts.
    ///
    /// `tooltip` is what a user sees when they hover the icon. It is a parameter
    /// rather than a constant because the product's name is the window's to know
    /// — the same reason [`crate::notify`] takes its text rather than composing
    /// it.
    pub fn start(context: eframe::egui::Context, tooltip: String) -> Option<Self> {
        #[cfg(windows)]
        {
            area::start(context, tooltip)
        }
        #[cfg(not(windows))]
        {
            // Nothing to put an icon in, and the honest answer is that there is
            // no notification area rather than a handle to one that does
            // nothing. The caller puts no window away on this platform.
            let _ = (context, tooltip);
            None
        }
    }

    /// What the icon has been asked for since the last call, if anything.
    ///
    /// One per frame: a click is a single event, and two clicks between two
    /// frames are two events a caller acts on in turn.
    pub fn poll(&self) -> Option<Command> {
        self.commands.try_recv().ok()
    }

    /// A tray with nothing behind it, and the hand that can send to it.
    ///
    /// The window's own tests need a `Tray` value to exercise what a click does
    /// — the tab it opens, the window it raises, the exit it asks for — and
    /// [`Tray::start`] is the one thing they must not call: it would put a real
    /// icon in the notification area of whatever machine runs `cargo test`, and
    /// leave it there. This is the same value with the shell taken out, which is
    /// also why it is gated: nothing in the product can build one.
    #[cfg(test)]
    pub fn for_test() -> (Self, Sender<Command>) {
        let (sender, commands) = crossbeam_channel::unbounded();
        (Self { commands }, sender)
    }
}

#[cfg(windows)]
mod area {
    use std::cell::RefCell;
    use std::sync::mpsc;

    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::Shell::{
        ExtractIconExW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
        Shell_NotifyIconW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu,
        DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, HICON, HWND_MESSAGE,
        IDI_APPLICATION, LoadIconW, MF_SEPARATOR, MF_STRING, MSG, PostMessageW, PostQuitMessage,
        RegisterClassW, SetForegroundWindow, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenuEx,
        TranslateMessage, WM_APP, WM_CLOSE, WM_DESTROY, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP,
        WNDCLASSW, WINDOW_EX_STYLE, WINDOW_STYLE,
    };
    use windows::core::PCWSTR;

    use super::{Command, Entry, Tray, START_TIMEOUT};

    /// The message the shell posts to our window when something happens to the
    /// icon.
    ///
    /// `WM_APP` is the first number Win32 leaves to applications, and everything
    /// above it is ours to define. A `const` item rather than the expression at
    /// each use, because it is matched against and a `match` arm has to be a
    /// path.
    const CALLBACK_MESSAGE: u32 = WM_APP + 1;

    /// The identifier the shell files the icon under.
    ///
    /// An icon is keyed by the pair (window, identifier), so one window with one
    /// icon needs exactly one number, and this is it. It is also the `uID` that
    /// `NIM_DELETE` has to name, which is why it is a constant rather than a
    /// literal in the two places that write it.
    const ICON_ID: u32 = 1;

    /// The window class this module registers.
    ///
    /// Registered rather than taken from a stock class, because a stock class
    /// has its own window procedure and this one has to receive the shell's
    /// callback. The name is the product's so that a class list in a debugger
    /// says whose window it is.
    const CLASS_NAME: &str = "WenleAVNotificationAreaIcon";

    /// The tooltip's capacity, less the terminator.
    ///
    /// `NOTIFYICONDATAW::szTip` is 128 units and the shell reads it as a
    /// NUL-terminated string. Writing 128 units of text would fill the buffer
    /// with no terminator at all, so the last slot is left for it.
    const TIP_UNITS: usize = 127;

    /// What the window procedure needs and cannot be handed.
    ///
    /// A `WNDPROC` is a bare function pointer: it is called by the operating
    /// system with four arguments and has nowhere to carry a closure. A
    /// thread-local is the honest place for the rest, and it is correct for the
    /// reason it is possible — Win32 delivers a window's messages on the thread
    /// that created it, so the only thread that ever reads this is the one that
    /// wrote it.
    struct State {
        /// Where a click goes.
        commands: crossbeam_channel::Sender<Command>,
        /// What wakes the window up after one.
        context: eframe::egui::Context,
        /// The icon the shell is showing, so that it can be deleted and, when
        /// this module owns it, destroyed.
        icon: HICON,
        /// Whether `icon` came out of this executable and must be destroyed.
        ///
        /// A stock icon is shared with every other program that asked for it and
        /// destroying it would take it away from them, so the two cases are not
        /// interchangeable and this is the flag that keeps them apart.
        owns_icon: bool,
    }

    thread_local! {
        static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    }

    /// Put an icon in the notification area, and answer whether it is there.
    ///
    /// Blocks until the tray thread has either added the icon or given up. See
    /// [`Tray::start`] for why the answer has to be known rather than assumed,
    /// and [`START_TIMEOUT`] for how long it will wait for it.
    pub(super) fn start(context: eframe::egui::Context, tooltip: String) -> Option<Tray> {
        let (commands, receiver) = crossbeam_channel::unbounded();
        let (ready, answer) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("wenle-tray".to_owned())
            .spawn(move || run(&context, &tooltip, commands, &ready));
        if let Err(error) = thread {
            log::warn!("no notification-area icon: the thread was not started: {error}");
            return None;
        }
        match answer.recv_timeout(START_TIMEOUT) {
            Ok(true) => Some(Tray { commands: receiver }),
            Ok(false) => None,
            Err(_) => {
                // The thread is still there and may yet add the icon. If it
                // does, its next attempt to send a command finds the receiver
                // dropped — this function returns `None` and the caller keeps
                // its window — and takes the icon down again. A visible icon
                // that does nothing for that long is a smaller wrong than a
                // window put out of the way with no icon at all.
                log::warn!(
                    "no notification-area icon: the shell did not answer within {START_TIMEOUT:?}"
                );
                None
            }
        }
    }

    /// Create the window, add the icon, and pump messages until it goes away.
    ///
    /// Everything in here is a Win32 call on handles this thread creates and
    /// destroys, which is why the whole body is one `unsafe` block rather than
    /// a safety comment on each call.
    fn run(
        context: &eframe::egui::Context,
        tooltip: &str,
        commands: crossbeam_channel::Sender<Command>,
        ready: &mpsc::Sender<bool>,
    ) {
        // SAFETY: this thread creates every handle used below and destroys each
        // one before returning. The window procedure it installs reads a
        // thread-local this thread writes before the window exists.
        unsafe {
            let instance = match GetModuleHandleW(None) {
                Ok(instance) => instance,
                Err(error) => {
                    log::warn!("no notification-area icon: this module was not found: {error}");
                    let _ = ready.send(false);
                    return;
                }
            };
            let class = wide(CLASS_NAME);
            let definition = WNDCLASSW {
                lpfnWndProc: Some(window_procedure),
                hInstance: HINSTANCE(instance.0),
                lpszClassName: PCWSTR(class.as_ptr()),
                ..Default::default()
            };
            if RegisterClassW(&definition) == 0 {
                log::warn!(
                    "no notification-area icon: the window class was not registered: {}",
                    std::io::Error::last_os_error()
                );
                let _ = ready.send(false);
                return;
            }
            // A message-only window: no size, no style, `HWND_MESSAGE` as its
            // parent. It is never drawn and never enumerated, and it exists to
            // be posted to. See the module documentation for why one is needed
            // at all.
            let window = match CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class.as_ptr()),
                PCWSTR(class.as_ptr()),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                Some(HINSTANCE(instance.0)),
                None,
            ) {
                Ok(window) => window,
                Err(error) => {
                    log::warn!("no notification-area icon: the window was not created: {error}");
                    let _ = ready.send(false);
                    return;
                }
            };

            let (icon, owns_icon) = icon();
            STATE.with(|state| {
                *state.borrow_mut() = Some(State {
                    commands,
                    context: context.clone(),
                    icon,
                    owns_icon,
                });
            });

            let data = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: window,
                uID: ICON_ID,
                uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage: CALLBACK_MESSAGE,
                hIcon: icon,
                szTip: tip(tooltip),
                ..Default::default()
            };
            if !Shell_NotifyIconW(NIM_ADD, &data).as_bool() {
                log::warn!(
                    "no notification-area icon: the shell refused one: {}",
                    std::io::Error::last_os_error()
                );
                clear();
                let _ = DestroyWindow(window);
                let _ = ready.send(false);
                return;
            }
            // The icon is in the notification area from here on, so the caller
            // may put its window away. Said before the loop starts, because the loop
            // is what the icon is *for* and it does not end until the process
            // does.
            let _ = ready.send(true);
            log::info!("the notification-area icon is up");

            let mut message = MSG::default();
            while GetMessageW(&mut message, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }

            // Reached when the loop ends, which is `WM_QUIT`: either the window
            // was destroyed, which is where the icon is removed, or the thread
            // posted it itself because there was nobody left to tell. The icon
            // this thread extracted from the executable is freed here and not
            // before, because the shell holds it for as long as the icon is
            // there.
            if let Some(state) = STATE.with(|state| state.borrow_mut().take()) {
                if state.owns_icon {
                    let _ = DestroyIcon(state.icon);
                }
            }
        }
    }

    /// The window procedure, which is where every click arrives.
    ///
    /// # Safety
    ///
    /// Called by Win32 with the arguments of the message being dispatched. The
    /// thread-local it reaches is written by the thread that created the window,
    /// which is the only thread Win32 delivers that window's messages on.
    unsafe extern "system" fn window_procedure(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // One block for the whole body rather than one per call: every call
        // under it is a Win32 message-handling call whose required guarantees
        // are the same one — that this really is the message being dispatched to
        // a window this thread created.
        unsafe {
            match message {
                CALLBACK_MESSAGE => {
                    // The low word of `lParam` is the mouse message that caused
                    // the callback — the shell forwards the mouse's own message
                    // number rather than defining numbers of its own. Only two
                    // of them mean anything: a left click opens the window and a
                    // right click opens the menu. The rest — the pointer moving
                    // over the icon, a double click, the keyboard's context-menu
                    // key — are ignored rather than guessed at.
                    match (lparam.0 as u32) & 0xffff {
                        WM_LBUTTONUP => ask(window, Command::Open),
                        WM_RBUTTONUP => menu(window),
                        _ => {}
                    }
                    LRESULT(0)
                }
                // Asked to close, which is what this thread does to itself when
                // the window that owns the channel has gone. Destroying the
                // window runs `WM_DESTROY` below, which is where the icon comes
                // down.
                WM_CLOSE => {
                    let _ = DestroyWindow(window);
                    LRESULT(0)
                }
                WM_DESTROY => {
                    remove_icon(window);
                    PostQuitMessage(0);
                    LRESULT(0)
                }
                _ => DefWindowProcW(window, message, wparam, lparam),
            }
        }
    }

    /// Hand a command to the window and wake it up.
    ///
    /// Does nothing when there is no receiver: the window that owns this process
    /// is going away, and the right end state for that is an icon that goes with
    /// it. So the window is closed instead, which ends the message loop.
    ///
    /// Safe to call from the window procedure, which is the only thing that
    /// does: `window` is the handle that procedure was given.
    fn ask(window: HWND, command: Command) {
        let delivered = STATE.with(|state| match state.borrow().as_ref() {
            Some(state) => match state.commands.send(command) {
                Ok(()) => {
                    // An idle `egui` window draws nothing until something asks
                    // it to. This is that something: without it the command sits
                    // on the channel until the user happens to move the mouse
                    // over the window.
                    state.context.request_repaint();
                    true
                }
                Err(_) => false,
            },
            None => false,
        });
        if !delivered {
            log::debug!("a notification-area command arrived after the window had gone");
            // SAFETY: `window` is a live handle — this runs from that window's
            // own procedure, or from a function called by it.
            unsafe {
                let _ = PostMessageW(Some(window), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }
    }

    /// Show the menu at the pointer and act on whatever is chosen.
    ///
    /// Safe to call from the window procedure: `window` is the handle it was
    /// given, and the menu this creates is destroyed before returning on every
    /// path.
    fn menu(window: HWND) {
        // SAFETY: creates a menu belonging to this thread, which is destroyed
        // below whichever way this function returns; each `AppendMenuW` names a
        // string that outlives the call.
        unsafe {
            let Ok(menu) = CreatePopupMenu() else {
                log::warn!("the notification-area menu was not created");
                return;
            };
            for entry in Command::MENU {
                let added = match entry {
                    Entry::Item(command) => {
                        let label = wide(command.label());
                        AppendMenuW(menu, MF_STRING, command.menu_id(), PCWSTR(label.as_ptr()))
                    }
                    Entry::Separator => AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null()),
                };
                if let Err(error) = added {
                    log::warn!("the notification-area menu was not filled in: {error}");
                    let _ = DestroyMenu(menu);
                    return;
                }
            }

            let mut pointer = POINT::default();
            if let Err(error) = GetCursorPos(&mut pointer) {
                log::warn!("the notification-area menu was not placed: {error}");
                let _ = DestroyMenu(menu);
                return;
            }
            // The menu is a window in its own right and has to be the
            // foreground one for as long as it is up. Without this it does not
            // close when the user clicks somewhere else, which is the behaviour
            // every Windows menu has and the one a user reads as "the program
            // has hung".
            let _ = SetForegroundWindow(window);
            // `TPM_RETURNCMD` makes the return value the identifier of the line
            // that was chosen rather than a boolean, which is the only way to
            // find out which one it was. Zero means the menu was dismissed
            // without a choice, and names no command.
            let chosen = TrackPopupMenuEx(
                menu,
                (TPM_RETURNCMD | TPM_RIGHTBUTTON).0,
                pointer.x,
                pointer.y,
                window,
                None,
            )
            .0 as usize;
            let _ = DestroyMenu(menu);
            // The documented companion to the call above: a menu that was made
            // foreground by a program that then does nothing can stay on screen
            // after it has been dismissed. Posting a null message puts the
            // thread back in its own message loop, which is where the dismissal
            // is processed.
            let _ = PostMessageW(Some(window), WM_NULL, WPARAM(0), LPARAM(0));
            if let Some(command) = Command::from_menu_id(chosen) {
                ask(window, command);
            }
        }
    }

    /// Take the icon out of the notification area.
    ///
    /// The same structure that added it, with the fields the shell reads for a
    /// deletion filled in. A failure is logged and otherwise ignored: this runs
    /// on the way out, and there is nothing left to retry with.
    fn remove_icon(window: HWND) {
        let icon = STATE.with(|state| {
            state
                .borrow()
                .as_ref()
                .map_or(HICON(std::ptr::null_mut()), |state| state.icon)
        });
        let data = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: window,
            uID: ICON_ID,
            hIcon: icon,
            ..Default::default()
        };
        // SAFETY: the struct is the shell's own, filled in the way its
        // documentation requires, and describes an icon that was added under
        // this same window and identifier.
        unsafe {
            if !Shell_NotifyIconW(NIM_DELETE, &data).as_bool() {
                log::debug!(
                    "the notification-area icon was not removed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    /// Forget the window's own state, sending nothing.
    ///
    /// Used on the path where the icon was refused: the thread is about to
    /// return and a window procedure that ran before it did must not find a
    /// sender whose receiver nobody holds.
    fn clear() {
        STATE.with(|state| *state.borrow_mut() = None);
    }

    /// The icon to show: this executable's own, or the stock application icon.
    ///
    /// Answers whether the handle is one this module owns. The second field is
    /// not a detail: a stock icon belongs to the system and is shared with every
    /// other program that asked for it, so destroying one takes it away from
    /// them, and the two cases cannot be treated alike at the end of the thread.
    fn icon() -> (HICON, bool) {
        if let Ok(path) = std::env::current_exe() {
            let path = wide(&path.to_string_lossy());
            let mut small = HICON(std::ptr::null_mut());
            // Index zero is the first icon in the file's resources, whatever
            // identifier it was given — which is what makes this work for an
            // executable whose icon a build script added without telling this
            // code what it called it.
            //
            // SAFETY: `path` is a NUL-terminated wide string that outlives the
            // call, and `small` is a live local for the out-parameter.
            let extracted =
                unsafe { ExtractIconExW(PCWSTR(path.as_ptr()), 0, None, Some(&mut small), 1) };
            if extracted >= 1 && !small.0.is_null() {
                return (small, true);
            }
        }
        // SAFETY: a stock icon identifier from this module, and a null module
        // handle, which is what asks for one of the system's.
        match unsafe { LoadIconW(None, IDI_APPLICATION) } {
            Ok(icon) => (icon, false),
            Err(error) => {
                log::debug!("no icon for the notification area: {error}");
                (HICON(std::ptr::null_mut()), false)
            }
        }
    }

    /// A NUL-terminated UTF-16 copy of `text`, for as long as it lives.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The tooltip, in the fixed-size buffer the shell reads it from.
    fn tip(text: &str) -> [u16; 128] {
        let mut buffer = [0u16; 128];
        for (slot, unit) in buffer[..TIP_UNITS].iter_mut().zip(text.encode_utf16()) {
            *slot = unit;
        }
        buffer
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_tip_buffer_keeps_its_terminator() {
            // The defect this is here for: a tooltip of 128 units or more fills
            // every slot of the buffer, so the shell reads a string with no end
            // and shows whatever follows it in memory.
            let long = "x".repeat(400);
            let filled = tip(&long);
            assert_eq!(filled[127], 0, "the buffer must end in a terminator");
            assert_eq!(filled[0], u16::from(b'x'));
            assert_eq!(filled[126], u16::from(b'x'));
        }

        #[test]
        fn a_short_tip_is_copied_whole() {
            let filled = tip("Wenle AV");
            let text: Vec<u16> = "Wenle AV".encode_utf16().collect();
            assert_eq!(&filled[..text.len()], &text[..]);
            assert_eq!(filled[text.len()], 0);
        }

        #[test]
        fn a_wide_string_ends_in_a_terminator() {
            let encoded = wide("Wenle AV");
            assert_eq!(encoded.last(), Some(&0));
            assert_eq!(encoded.len(), "Wenle AV".len() + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_menu_offers_every_command_and_nothing_else() {
        // The property that matters: a command that exists but is not in the
        // menu is unreachable, and a menu line that names no command is a click
        // that does nothing. Both lists come from `ALL`, and this is the test
        // that says so.
        let offered: Vec<Command> = Command::MENU
            .iter()
            .filter_map(|entry| match entry {
                Entry::Item(command) => Some(*command),
                Entry::Separator => None,
            })
            .collect();
        assert_eq!(offered, Command::ALL.to_vec());
    }

    #[test]
    fn leaving_is_the_last_line_and_under_a_rule() {
        // Not decoration: `Exit` stops the user's protection, and it is the only
        // line in this menu that does. A rule above it and a position at the
        // bottom is what keeps it out of the way of a user aiming at "Open".
        assert_eq!(Command::MENU[Command::MENU.len() - 1], Entry::Item(Command::Exit));
        assert_eq!(Command::MENU[Command::MENU.len() - 2], Entry::Separator);
        assert_eq!(
            Command::MENU
                .iter()
                .filter(|entry| **entry == Entry::Separator)
                .count(),
            1
        );
    }

    #[test]
    fn every_command_round_trips_through_its_win32_identifier() {
        // The identifiers are what `TrackPopupMenuEx` returns, so a command
        // whose identifier did not name it again would be a menu line that
        // performs a different action from the one it read as.
        let mut seen = Vec::new();
        for command in Command::ALL {
            let id = command.menu_id();
            assert_ne!(id, 0, "zero means the menu was dismissed, not a choice");
            assert_eq!(Command::from_menu_id(id), Some(command));
            assert!(!seen.contains(&id), "{id} names two commands");
            seen.push(id);
        }
    }

    #[test]
    fn an_identifier_from_nowhere_names_nothing() {
        assert_eq!(Command::from_menu_id(0), None);
        assert_eq!(Command::from_menu_id(Command::ALL.len() + 1), None);
        assert_eq!(Command::from_menu_id(usize::MAX), None);
    }

    #[test]
    fn every_line_reads_differently_and_says_something() {
        // Two menu lines with the same text is a menu a user cannot use, and an
        // empty one is a line with nothing on it.
        let mut labels = Vec::new();
        for command in Command::ALL {
            let label = command.label();
            assert!(!label.trim().is_empty());
            assert!(!labels.contains(&label), "{label:?} is on two lines");
            labels.push(label);
            assert!(!command.description().trim().is_empty());
        }
    }

    #[test]
    fn the_menu_is_short_enough_to_read() {
        // A tray menu is read with the pointer held down. The four commands
        // here are the whole product's reach from the notification area, and a
        // fifth would be a sign that something else belongs in the window.
        assert_eq!(Command::ALL.len(), 4);
        assert_eq!(Command::MENU.len(), 5);
    }
}
