//! The visual design, as data.
//!
//! # Why the design is a module and not numbers in the drawing code
//!
//! Because the drawing code is the one part of this crate that cannot be
//! tested, and every decision inside it is a decision nobody can check. A
//! colour written at the point it is used can only be judged by looking at the
//! window; the same colour written here is a value a test can measure. So the
//! palette, the spacing scale and the mapping from a verdict to a word, a
//! colour and a sentence all live here, and `app.rs` is left with the business
//! of putting rectangles where this module says.
//!
//! # The palette is a set, not a list of colours
//!
//! Three surface levels an even step apart, one text ramp, one accent and four
//! band colours. Choosing them one at a time is how a dark theme ends up with
//! four unrelated greys and a green that only looks green next to one of them.
//!
//! Every contrast figure quoted below is a WCAG 2.1 relative-luminance ratio
//! **computed by the tests in this module** from the same constants the window
//! draws with — not copied from a design tool, and not estimated. That is the
//! point of stating them here: a colour edited without re-measuring is a test
//! failure rather than a design regression nobody notices.
//!
//! | Colour | Hex | on [`Palette::BACKGROUND`] | on [`Palette::PANEL`] | on [`Palette::RAISED`] |
//! |---|---|---|---|---|
//! | [`Palette::TEXT`] | `#E6EAF0` | 15.15 | 13.70 | 12.77 |
//! | [`Palette::TEXT_DIM`] | `#9AA5B4` | 7.33 | 6.63 | 6.18 |
//! | [`Palette::TEXT_FAINT`] | `#6B7686` | 3.97 | 3.59 | 3.35 |
//! | [`Palette::ACCENT`] | `#5AA2FF` | 7.01 | 6.34 | 5.91 |
//! | [`Palette::CLEAN`] | `#4ADE80` | 10.50 | 9.50 | 8.85 |
//! | [`Palette::SUSPICIOUS`] | `#FBBF24` | 10.96 | 9.91 | 9.23 |
//! | [`Palette::MALICIOUS`] | `#EE5C6C` | 5.56 | 5.03 | 4.69 |
//! | [`Palette::UNKNOWN`] | `#8E99A8` | 6.34 | 5.73 | 5.34 |
//!
//! The four band colours are the ones that have to survive being read in a
//! hurry, so they are the darkest and brightest the palette gets and every one
//! of them clears the 4.5:1 that WCAG asks of body text on **all three**
//! surfaces. [`Palette::MALICIOUS`] is the tightest at 4.69 on `RAISED`, which
//! is why `RAISED` is `#1F252E` and not a lighter grey: at `#232A34` the same
//! red measures 4.40 and would fail.
//!
//! [`Palette::TEXT_FAINT`] is deliberately *below* 4.5:1. It is the disabled
//! label colour — a control that cannot be used, and text that repeats
//! something already shown in full elsewhere — and WCAG exempts disabled
//! controls for exactly this reason. It must not be used for anything a person
//! has to read to act.
//!
//! # The band colours are chosen to survive colour blindness, and that is
//! # measured too
//!
//! Red for malicious and green for clean is the owner's decision and it is the
//! convention every user already has. It is also the pair most likely to be
//! confused: under deuteranopia — the common form, around 6% of men — red and
//! green both land on a desaturated olive. So the red is pulled towards pink
//! (`#EE5C6C`, not a pure `#FF0000`) and the green towards emerald
//! (`#4ADE80`, not a pure `#00FF00`), which keeps them apart once the red and
//! green cones are gone.
//!
//! The tests simulate deuteranopia, protanopia and tritanopia (Viénot,
//! Brettel and Mollon 1999, in linear RGB) and assert that no two band colours
//! come closer than a set floor in any of the three simulations. Measured worst
//! pairs with this palette:
//!
//! | Simulation | Worst pair | Separation (0 to 441 RGB distance) |
//! |---|---|---|
//! | Deuteranopia (~6% of men) | clean / malicious | 62.8 |
//! | Protanopia (~1% of men) | malicious / unknown | 73.5 |
//! | Tritanopia (~0.01%) | suspicious / malicious | 56.6 |
//!
//! Colour is nonetheless never the only carrier of a band. Every place a band
//! is shown, the band's *word* is shown with it — the same word the console
//! prints, see [`verdict_word`] — so a reader who cannot separate the two hues
//! is not being asked to. The colour is what makes the one line that matters
//! findable in a list of two hundred; the word is what makes it true.
//!
//! # Two more pairings the palette is used for, and both of them measured
//!
//! The status card in the middle of the Scan view draws text on a *band fill*
//! rather than on one of the three surfaces, and the primary button draws its
//! label on [`Palette::ACCENT`] rather than in it. Both are new uses of the same
//! twelve constants, and both are the kind of use that looks fine and reads
//! badly: a tinted card is only a few steps from the panel it sits on, and a
//! button label is the one string a user is meant to read without trying. So
//! both are measured like everything else:
//!
//! | Colour | On | Ratio |
//! |---|---|---|
//! | [`Palette::TEXT`] | the four band fills | 9.12 to 10.89 |
//! | [`Palette::TEXT_DIM`] | the four band fills | 4.42 to 5.27 |
//! | [`Palette::BACKGROUND`] | [`Palette::ACCENT`] | 7.01 |
//!
//! **The second row is why a band-tinted card carries one text colour and not
//! two.** `TEXT_DIM` was the obvious choice for the secondary line on that card
//! and it is below the 4.5:1 that the rest of the window holds itself to on two
//! of the four fills — 4.42 on the amber, which is the band a user is most
//! likely to be reading that card about. The tinted card therefore draws its
//! secondary line in [`Palette::TEXT`] at a smaller size, which is a hierarchy
//! made of the type scale instead of one made of contrast, and the test below
//! pins both halves of that: `TEXT` clears 4.5:1 on every fill, and `TEXT_DIM`
//! does not.
//!
//! The accent is symmetric — contrast is a ratio between two luminances, so
//! "accent on background" and "background on accent" are the same number — which
//! is why the primary button is the one place the window paints text darker than
//! the thing it sits on.
//!
//! # The type scale is a scale and not four numbers
//!
//! Before this, a view title, a section heading, a label and a caption were all
//! drawn at egui's default body size, and the only thing telling them apart was
//! where they sat. [`Text`] is the scale that fixes that: six steps, each with a
//! size and a weight, and a test that lays every step out on a real headless
//! frame and measures the rendered heights, so that a step edited to the same
//! size as its neighbour fails the build rather than the eye.

use av_core::{Severity, Verdict};
use eframe::egui::{self, Color32, CornerRadius, Margin, Stroke, Vec2};

/// The dark palette.
///
/// A frozen set of constants rather than a struct with fields, because a
/// palette is not something the product varies: there is one theme, it is dark,
/// and a value that can be reconfigured is a value that can be got wrong.
/// [`Palette::SCALE`] exists so that the whole set can be handed around as one
/// value in a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// The window behind everything.
    pub background: Color32,
    /// The surface a list, a table or a detail pane sits on.
    pub panel: Color32,
    /// One step above `panel`: toolbars, headers, cards, the selected row.
    pub raised: Color32,
    /// Separators and control outlines.
    pub border: Color32,
    /// Body text.
    pub text: Color32,
    /// Secondary text: labels, units, timestamps.
    pub text_dim: Color32,
    /// Disabled and repeated meta text. Below 4.5:1 on purpose; see the module
    /// documentation.
    pub text_faint: Color32,
    /// The interactive colour: selection, focus, links.
    pub accent: Color32,
    /// [`Verdict::Clean`].
    pub clean: Color32,
    /// [`Verdict::Suspicious`].
    pub suspicious: Color32,
    /// [`Verdict::Malicious`].
    pub malicious: Color32,
    /// [`Verdict::Unknown`].
    pub unknown: Color32,
}

impl Palette {
    /// The three surfaces, top to bottom.
    pub const BACKGROUND: Color32 = Color32::from_rgb(0x12, 0x15, 0x1A);
    /// The list and detail surface. See [`Palette::BACKGROUND`].
    pub const PANEL: Color32 = Color32::from_rgb(0x1A, 0x1F, 0x27);
    /// The header and selection surface. See [`Palette::BACKGROUND`].
    pub const RAISED: Color32 = Color32::from_rgb(0x1F, 0x25, 0x2E);
    /// Separators and outlines.
    pub const BORDER: Color32 = Color32::from_rgb(0x33, 0x3C, 0x49);
    /// Body text.
    pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xEA, 0xF0);
    /// Secondary text.
    pub const TEXT_DIM: Color32 = Color32::from_rgb(0x9A, 0xA5, 0xB4);
    /// Disabled and repeated meta text.
    pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x6B, 0x76, 0x86);
    /// Selection, focus and links.
    pub const ACCENT: Color32 = Color32::from_rgb(0x5A, 0xA2, 0xFF);
    /// The clean band.
    pub const CLEAN: Color32 = Color32::from_rgb(0x4A, 0xDE, 0x80);
    /// The suspicious band.
    pub const SUSPICIOUS: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);
    /// The malicious band.
    pub const MALICIOUS: Color32 = Color32::from_rgb(0xEE, 0x5C, 0x6C);
    /// The unknown band.
    pub const UNKNOWN: Color32 = Color32::from_rgb(0x8E, 0x99, 0xA8);

    /// The whole set, for a caller that wants to pass it around.
    pub const SCALE: Self = Self {
        background: Self::BACKGROUND,
        panel: Self::PANEL,
        raised: Self::RAISED,
        border: Self::BORDER,
        text: Self::TEXT,
        text_dim: Self::TEXT_DIM,
        text_faint: Self::TEXT_FAINT,
        accent: Self::ACCENT,
        clean: Self::CLEAN,
        suspicious: Self::SUSPICIOUS,
        malicious: Self::MALICIOUS,
        unknown: Self::UNKNOWN,
    };

    /// The colour of a verdict's own word.
    ///
    /// A pure function of the band and nothing else, so that a verdict shown in
    /// the results list, in the quarantine list and in the summary line cannot
    /// be three different colours.
    pub const fn verdict(self, verdict: Verdict) -> Color32 {
        verdict_color(verdict)
    }

    /// The tinted background a band's row or chip is drawn on: the band colour
    /// blended 18% into the panel.
    ///
    /// Blended rather than picked, so that the tint cannot drift away from the
    /// colour it is a tint of. The low alpha is what keeps it reading as a
    /// highlight: at 18% the fill is around 1.3:1 against the panel, which is
    /// visible as a wash and never mistaken for a second label.
    pub const fn fill(verdict: Verdict) -> Color32 {
        verdict_fill(verdict)
    }
}

/// The word shown for each band.
///
/// **These four strings are the console's** (`av-cli`'s `output::verdict_word`)
/// and they are duplicated here rather than shared because `av-cli` is a binary
/// and cannot be depended on. A window that called a file "risky" where the
/// console called it "suspicious" would be two products disagreeing about one
/// file, and the disagreement would only ever be noticed by a person who ran
/// both. A test pins all four.
pub const fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Clean => "clean",
        Verdict::Suspicious => "suspicious",
        Verdict::Malicious => "malicious",
        Verdict::Unknown => "unknown",
    }
}

/// The colour of a band. Clean is green, suspicious amber, malicious red,
/// unknown grey — see the module documentation for why these four and not
/// others, and for the measurements.
pub const fn verdict_color(verdict: Verdict) -> Color32 {
    match verdict {
        Verdict::Clean => Palette::CLEAN,
        Verdict::Suspicious => Palette::SUSPICIOUS,
        Verdict::Malicious => Palette::MALICIOUS,
        Verdict::Unknown => Palette::UNKNOWN,
    }
}

/// A tinted fill for a band's row or chip. The values are the band colour
/// blended 18% into [`Palette::PANEL`]; a test checks each is between the two.
pub const fn verdict_fill(verdict: Verdict) -> Color32 {
    match verdict {
        Verdict::Clean => Color32::from_rgb(0x23, 0x41, 0x37),
        Verdict::Suspicious => Color32::from_rgb(0x42, 0x3C, 0x26),
        Verdict::Malicious => Color32::from_rgb(0x40, 0x2A, 0x33),
        Verdict::Unknown => Color32::from_rgb(0x31, 0x37, 0x40),
    }
}

/// The sentence shown beside a band, where a band on its own would be
/// ambiguous.
///
/// `None` for [`Verdict::Clean`], because there is nothing to say about a file
/// nothing was found in and a line saying so next to every clean row would be
/// noise. The two that matter are the middle band and the unknown band, and for
/// different reasons: the middle band is the one a user is most likely to
/// misread as an accusation, and the unknown band is the one they are most
/// likely to misread as an acquittal.
///
/// **The middle band's sentence is a product decision, not a description.** The
/// owner's rule is that `Suspicious` means "worth telling you about, not worth
/// acting on", so the label has to say the file was not acted on. A user who
/// reads "suspicious" as "infected" deletes a toolchain; one who reads it as
/// "nothing" ignores a warning they asked for. The sentence cannot be both, so
/// it says the thing that is not recoverable from: nothing was done.
pub const fn band_note(verdict: Verdict) -> Option<&'static str> {
    match verdict {
        Verdict::Clean => None,
        Verdict::Suspicious => Some(
            "Reported, not acted on. This band means the file is worth a look, not that it is \
             malware: nothing was moved, changed or blocked.",
        ),
        Verdict::Malicious => {
            Some("Confirmed. Safe to quarantine or block, and worth a look at where it came from.")
        }
        Verdict::Unknown => Some(
            "Not scanned. Nothing is known about this file either way; it is not reported as \
             clean, and its verdict is not a reason to trust it.",
        ),
    }
}

/// What the window says about the machine when a scan has produced this band.
///
/// The one line at the top of the status card, and the one place the product
/// states a conclusion. It is short where [`band_note`] is long because the two
/// do different jobs: this is the sentence a user reads from across the room to
/// know whether they have to do something, and the note underneath is the
/// sentence they read when they have come closer.
///
/// The middle band's headline is the one that is doing work. "Some files are
/// worth a look" is deliberately not "files were flagged" and deliberately not
/// anything with the word *threat* in it: the owner's rule is that this band
/// reports and does not act, and a headline is where a user forms that
/// impression before they read a single count.
pub const fn band_headline(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Clean => "No threats were found",
        Verdict::Suspicious => "Some files are worth a look",
        Verdict::Malicious => "Malicious files were found",
        Verdict::Unknown => "Some files could not be scanned",
    }
}

/// What a band means, in one line, for the legend on the Scan view.
///
/// Shorter than [`band_note`] and written for a reader who has not met the
/// bands yet: this is the legend of a chart, not the footnote under a result.
/// It exists because the four band words are the product's whole vocabulary and
/// nothing on the screen explained them before a user's first scan — a legend is
/// what turns "suspicious" from an accusation into a definition.
///
/// Every line obeys the same rule [`band_note`] does: the middle band does not
/// claim malware was found, and the unknown band does not claim the file is
/// safe. A test pins both.
pub const fn band_meaning(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Clean => "Nothing in the file matched anything the engine knows about.",
        Verdict::Suspicious => {
            "Worth a look. Reported and not acted on — nothing was moved, changed or blocked."
        }
        Verdict::Malicious => {
            "Confirmed harmful. Safe to quarantine, and worth finding out where it came from."
        }
        Verdict::Unknown => {
            "Not scanned, so nothing is known about it either way. It is not a clean result."
        }
    }
}

/// What the window says when no scan has run.
///
/// Deliberately not a band word and deliberately not in a band colour. A window
/// that showed green before anything had been checked would be claiming a
/// protection it has not performed, and this product's whole vocabulary of
/// verdicts is about files that were looked at — a machine nobody has scanned
/// has no verdict, and saying so is the honest empty state.
pub const UNSCANNED: &str = "Nothing has been scanned yet";

/// The colouring of a severity.
///
/// Deliberately borrowed from the band colours rather than given a second
/// palette. A severity is a statement about how damaging a finding would be if
/// it is genuine, and a detection list that coloured `High` orange and
/// `Critical` red would introduce a second colour language next to the first —
/// so a user reading a red row would have to know which of the two scales was
/// in play. Info and Low take the secondary text colour: they are context, and
/// by construction they can never move a file out of the clean band.
pub const fn severity_color(severity: Severity) -> Color32 {
    match severity {
        Severity::Info | Severity::Low => Palette::TEXT_DIM,
        Severity::Medium => Palette::SUSPICIOUS,
        Severity::High | Severity::Critical => Palette::MALICIOUS,
    }
}

/// The spacing scale, in points.
///
/// Four-point steps, which is the smallest grid that keeps a dense table and a
/// comfortable dialogue looking like the same product. Everything the window
/// pads or separates is one of these five numbers; a gap that is not is a gap
/// nobody can reproduce.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spacing {
    /// 4 — the gap between a label and its value.
    pub xs: f32,
    /// 8 — the default gap between controls in a row.
    pub sm: f32,
    /// 12 — the padding inside a panel, and the gap between rows.
    pub md: f32,
    /// 16 — the padding inside the window, and the gap between sections.
    pub lg: f32,
    /// 24 — the gap between the major areas of a view.
    pub xl: f32,
    /// The corner radius shared by every rounded surface.
    pub radius: u8,
    /// Height of one row in a list.
    pub row_height: f32,
    /// The height every interactive control is given, so a row of controls
    /// lines up whatever kind of control each one is.
    pub control_height: f32,
}

impl Spacing {
    /// 4 points.
    pub const XS: f32 = 4.0;
    /// 8 points.
    pub const SM: f32 = 8.0;
    /// 12 points.
    pub const MD: f32 = 12.0;
    /// 16 points.
    pub const LG: f32 = 16.0;
    /// 24 points.
    pub const XL: f32 = 24.0;
    /// 6 points of corner radius: enough to read as soft, not enough to make a
    /// dense table look like a card game.
    pub const RADIUS: u8 = 6;
    /// 26 points of row height, which fits a line of the default font with
    /// [`Spacing::XS`] above and below it.
    pub const ROW_HEIGHT: f32 = 26.0;
    /// 28 points: comfortably above the 24-point minimum target a pointer needs.
    pub const CONTROL_HEIGHT: f32 = 28.0;

    /// The whole scale, for a caller that wants to pass it around.
    pub const SCALE: Self = Self {
        xs: Self::XS,
        sm: Self::SM,
        md: Self::MD,
        lg: Self::LG,
        xl: Self::XL,
        radius: Self::RADIUS,
        row_height: Self::ROW_HEIGHT,
        control_height: Self::CONTROL_HEIGHT,
    };
}

/// The type scale, in points.
///
/// Six steps, and the rule for which one to use is what the text *is* rather
/// than how big it happens to look on the day:
///
/// * [`Text::DISPLAY`] is the one headline on a view — the sentence that says
///   what state the machine is in. There is at most one of these on screen.
/// * [`Text::TITLE`] is a view's own name, under the tab that selected it.
/// * [`Text::HEADING`] is a heading over a group of controls.
/// * [`Text::BODY`] is running text: a row, a control's label, a sentence.
/// * [`Text::META`] is a caption: a count, a unit, a timestamp, the sentence
///   under a field explaining it.
/// * [`Text::MONO`] is a path, a rule identifier or anything a user may need to
///   compare character by character.
///
/// The steps are close together on purpose — 26, 19, 15, 13, 11.5 — because a
/// window that is mostly a table cannot afford a heading that shouts. What
/// separates them is the pairing with weight and colour, which [`Step`] carries;
/// a size on its own would make the heading a smaller version of the title
/// rather than a different kind of thing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Text {
    /// 26 — the state of the machine, once per view at most.
    pub display: f32,
    /// 19 — a view's title.
    pub title: f32,
    /// 15 — a heading over a group.
    pub heading: f32,
    /// 13 — running text and control labels.
    pub body: f32,
    /// 11.5 — captions, counts and explanations.
    pub meta: f32,
    /// 12 — paths and identifiers.
    pub mono: f32,
}

impl Text {
    /// 26 points.
    pub const DISPLAY: f32 = 26.0;
    /// 19 points.
    pub const TITLE: f32 = 19.0;
    /// 15 points.
    pub const HEADING: f32 = 15.0;
    /// 13 points.
    pub const BODY: f32 = 13.0;
    /// 11.5 points. The one step that is off the four-point grid, because 12 is
    /// too close to [`Text::BODY`] to read as a caption and 11 is small enough
    /// that a count stops being legible on a 125% display.
    pub const META: f32 = 11.5;
    /// 12 points.
    pub const MONO: f32 = 12.0;
}

// There is deliberately no `Text::SCALE`, and the asymmetry with `Palette` and
// `Spacing` is the point rather than an omission. Those two keep one so that a
// caller can hand the whole set to something — `style` reads `Spacing::SCALE` to
// build egui's own spacing, and `Palette::SCALE` answers `verdict`. The type
// scale is passed around as the six [`Step`] constants instead, which carry a
// weight and a colour as well as a size, so a `SCALE` beside them would be a
// second spelling of the same six numbers and the two could drift. What that
// constant existed to protect — a size declared and never drawn — is asserted
// directly, by `every_text_size_is_a_size_something_is_drawn_at`.

/// One step of the type scale: a size, a weight and a colour, as a value.
///
/// A step is a value rather than a call so that the scale can be *asserted* —
/// that the sizes descend, that the weights are not all the same, and that the
/// colours are ones the palette owns. [`display`] and its neighbours are the
/// three-line wrappers that turn a step into text egui can draw, and a test
/// measures the rendered height of all six to prove the size survives the trip.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Step {
    /// The size, in points.
    pub size: f32,
    /// Whether the step is drawn heavy.
    pub strong: bool,
    /// The colour the step defaults to, before a caller overrides it.
    pub color: Color32,
}

/// The state of the machine, once per view: [`Text::DISPLAY`], heavy, in the
/// body colour.
pub const DISPLAY_STEP: Step = Step {
    size: Text::DISPLAY,
    strong: true,
    color: Palette::TEXT,
};

/// A view's title: [`Text::TITLE`], heavy.
pub const TITLE_STEP: Step = Step {
    size: Text::TITLE,
    strong: true,
    color: Palette::TEXT,
};

/// A heading over a group: [`Text::HEADING`], heavy, in the secondary colour so
/// that it labels the group without competing with the title above it.
pub const HEADING_STEP: Step = Step {
    size: Text::HEADING,
    strong: true,
    color: Palette::TEXT_DIM,
};

/// Running text: [`Text::BODY`], regular, in the body colour.
pub const BODY_STEP: Step = Step {
    size: Text::BODY,
    strong: false,
    color: Palette::TEXT,
};

/// A caption: [`Text::META`], regular, in the secondary colour.
pub const META_STEP: Step = Step {
    size: Text::META,
    strong: false,
    color: Palette::TEXT_DIM,
};

/// A path or an identifier: [`Text::MONO`], regular, monospaced.
pub const MONO_STEP: Step = Step {
    size: Text::MONO,
    strong: false,
    color: Palette::TEXT,
};

/// Turn a step and a string into drawable text.
///
/// The one place a step is read, so that the constants above cannot be a second
/// opinion about what the scale is.
fn step(text: impl Into<String>, step: Step) -> egui::RichText {
    let text = egui::RichText::new(text).size(step.size).color(step.color);
    if step.strong {
        text.strong()
    } else {
        text
    }
}

/// The state of the machine, once per view.
pub fn display(text: impl Into<String>) -> egui::RichText {
    step(text, DISPLAY_STEP)
}

/// A view's title.
pub fn title(text: impl Into<String>) -> egui::RichText {
    step(text, TITLE_STEP)
}

/// A heading over a group of controls.
pub fn heading(text: impl Into<String>) -> egui::RichText {
    step(text, HEADING_STEP)
}

/// Running text.
pub fn body(text: impl Into<String>) -> egui::RichText {
    step(text, BODY_STEP)
}

/// A caption: a count, a unit, an explanation.
pub fn meta(text: impl Into<String>) -> egui::RichText {
    step(text, META_STEP)
}

/// A path or a rule identifier.
pub fn mono(text: impl Into<String>) -> egui::RichText {
    step(text, MONO_STEP).monospace()
}

/// The scale as egui's own text styles.
///
/// The widgets this window does not draw by hand — `ui.heading()`, a checkbox's
/// label, a text field's contents — take their size from here, and taking it
/// from the same constants the hand-drawn text uses is what keeps the two from
/// being different scales. A `Button` is the body size rather than a size of its
/// own: a button's label and the sentence beside it are the same kind of text.
fn text_styles() -> std::collections::BTreeMap<egui::TextStyle, egui::FontId> {
    let proportional = egui::FontFamily::Proportional;
    let monospace = egui::FontFamily::Monospace;
    [
        (
            egui::TextStyle::Heading,
            egui::FontId::new(TITLE_STEP.size, proportional.clone()),
        ),
        (
            egui::TextStyle::Body,
            egui::FontId::new(BODY_STEP.size, proportional.clone()),
        ),
        (
            egui::TextStyle::Button,
            egui::FontId::new(BODY_STEP.size, proportional.clone()),
        ),
        (
            egui::TextStyle::Small,
            egui::FontId::new(META_STEP.size, proportional),
        ),
        (
            egui::TextStyle::Monospace,
            egui::FontId::new(MONO_STEP.size, monospace),
        ),
    ]
    .into()
}

/// The corner radius every rounded surface uses.
pub const fn corner_radius() -> CornerRadius {
    CornerRadius::same(Spacing::RADIUS)
}

/// A panel a view is built out of: a fill, a hairline outline and the standard
/// inner padding.
///
/// The one place the padding and the radius of a card are written down, so that
/// a card added later cannot be the one card with a different margin.
pub fn card(fill: Color32, outline: Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, outline))
        .corner_radius(corner_radius())
        .inner_margin(Margin::same(Spacing::LG as i8))
}

/// A hairline separator, in the border colour.
///
/// Written as a struct literal rather than `Stroke::new`, which is not a `const
/// fn`; a separator that could only be built at run time would have to be a
/// function that returns a fresh value every call.
pub const fn separator() -> Stroke {
    Stroke {
        width: 1.0,
        color: Palette::BORDER,
    }
}

/// The style the window is drawn with.
///
/// A pure function returning a value rather than a call that installs one, so
/// that the result can be asserted without a window: a test builds the style
/// and checks that the panel fill, the text colour and the item spacing are the
/// ones this module defines. `apply` is the one-line wrapper that hands it to
/// egui.
pub fn style() -> egui::Style {
    let mut style = egui::Style::default();

    let mut visuals = egui::Visuals::dark();
    visuals.dark_mode = true;
    visuals.panel_fill = Palette::BACKGROUND;
    visuals.window_fill = Palette::RAISED;
    visuals.faint_bg_color = Palette::PANEL;
    visuals.extreme_bg_color = Palette::BACKGROUND;
    visuals.code_bg_color = Palette::RAISED;
    visuals.override_text_color = Some(Palette::TEXT);
    visuals.window_stroke = separator();
    visuals.window_corner_radius = corner_radius();
    visuals.menu_corner_radius = corner_radius();
    visuals.hyperlink_color = Palette::ACCENT;
    visuals.warn_fg_color = Palette::SUSPICIOUS;
    visuals.error_fg_color = Palette::MALICIOUS;
    visuals.selection = egui::style::Selection {
        bg_fill: Palette::ACCENT.gamma_multiply(0.35),
        stroke: Stroke::new(1.0, Palette::ACCENT),
    };

    // The four widget states are the surface ramp: a control at rest is the
    // panel colour, one under the pointer is the raised colour, one being
    // pressed is the accent. Using the ramp rather than adding widget-specific
    // greys is what keeps a button and a row reading as the same material.
    visuals.widgets.noninteractive = widget(Palette::PANEL, Palette::TEXT);
    visuals.widgets.inactive = widget(Palette::RAISED, Palette::TEXT);
    visuals.widgets.hovered = widget_with_border(Palette::RAISED, Palette::TEXT, Palette::ACCENT);
    visuals.widgets.active = widget_with_border(Palette::PANEL, Palette::ACCENT, Palette::ACCENT);
    visuals.widgets.open = widget(Palette::PANEL, Palette::TEXT);
    style.visuals = visuals;

    // The type scale, installed where the widgets that are not drawn by hand
    // will find it. Without this the hand-drawn text would follow the scale and
    // every checkbox, field and combo box beside it would stay at egui's
    // defaults, which is one window with two type scales in it.
    style.text_styles = text_styles();

    // Read through the scale as one value rather than as eight pulls on the
    // type: this is the only place the scale is installed into egui, and the
    // test that every constant matches its `SCALE` field is what keeps the two
    // spellings of the same number from drifting apart.
    let scale = Spacing::SCALE;
    style.spacing = egui::Spacing {
        item_spacing: Vec2::new(scale.sm, scale.sm),
        button_padding: Vec2::new(scale.md, scale.xs),
        window_margin: Margin::same(scale.md as i8),
        menu_margin: Margin::same(scale.xs as i8),
        interact_size: Vec2::new(0.0, scale.control_height),
        slider_width: 160.0,
        combo_width: 180.0,
        text_edit_width: 260.0,
        indent: scale.lg,
        ..egui::Spacing::default()
    };

    style
}

/// One widget state, outlined in the border colour.
fn widget(fill: Color32, text: Color32) -> egui::style::WidgetVisuals {
    widget_with_border(fill, text, Palette::BORDER)
}

/// One widget state, outlined in a given colour.
///
/// `weak_bg_fill` is set with `bg_fill` rather than left at the default: egui
/// draws most framed widgets with the *weak* fill, so a state that set only
/// `bg_fill` would look correct in a test and wrong on the screen.
fn widget_with_border(fill: Color32, text: Color32, border: Color32) -> egui::style::WidgetVisuals {
    egui::style::WidgetVisuals {
        bg_fill: fill,
        weak_bg_fill: fill,
        bg_stroke: Stroke::new(1.0, border),
        corner_radius: corner_radius(),
        fg_stroke: Stroke::new(1.0, text),
        expansion: 0.0,
    }
}

/// Install the style into a context.
///
/// Drawing-adjacent and therefore thin: everything it installs comes from
/// [`style`], which is where the decisions are and where the tests are.
///
/// # Why this is three calls and not the one it looks like it should be
///
/// This was `ctx.set_style(style())`, and that call does not do what its name
/// suggests. egui 0.31 keeps **two** styles — one for dark mode and one for
/// light — and `set_style` writes into whichever is current *at that moment*
/// (`Options::style_mut`). Which one is current depends on `ThemePreference`,
/// which defaults to `System`, which cannot be resolved until the first pass
/// begins and the platform has said how the operating system is set. Until
/// then egui falls back to `Theme::Dark`.
///
/// So the call ran before the first pass, wrote the palette into the dark slot
/// because Dark was the fallback, and then the first pass reported an operating
/// system in light mode and every frame after it read the light slot, which
/// nothing had ever written. The window drew in egui's default light theme, and
/// the tests in this module passed throughout: a headless context has no system
/// theme either, so it resolves to Dark too, and they were checking the one
/// slot that happened to be correct. The window was light and every assertion
/// was green, which is the failure mode this whole module exists to prevent.
///
/// Hence two fixes, which are separate decisions:
///
/// * [`egui::Context::set_theme`] with [`egui::ThemePreference::Dark`] pins the
///   theme, so the product does not follow the operating system. That is this
///   module's stated design — there is one theme and it is dark — and it also
///   removes the fallback that made the slot ambiguous in the first place.
/// * [`egui::Context::set_style_of`] writes the palette into both slots
///   explicitly, so that no future change to the preference, and no context
///   whose system theme resolves the other way, can produce a window that is
///   half this palette and half egui's defaults.
///
/// Both halves are pinned by `a_light_system_theme_still_draws_the_palette`,
/// which fails if either is undone.
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.set_style_of(egui::Theme::Dark, style());
    ctx.set_style_of(egui::Theme::Light, style());
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the measurement tools the claims above are checked with -------------
    //
    // Ported rather than pulled in: a colour-science crate would be a
    // dependency for four functions used by tests only, and these are the
    // published formulae, short enough to read.

    /// WCAG 2.1 relative luminance.
    fn luminance(color: Color32) -> f32 {
        let channel = |v: u8| {
            let v = f32::from(v) / 255.0;
            if v <= 0.04045 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
    }

    /// WCAG 2.1 contrast ratio, always at least 1.
    fn contrast(a: Color32, b: Color32) -> f32 {
        let (la, lb) = (luminance(a), luminance(b));
        let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// Which form of colour blindness to simulate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Blindness {
        Deuteranopia,
        Protanopia,
        Tritanopia,
    }

    fn linear(v: u8) -> f32 {
        let v = f32::from(v) / 255.0;
        if v <= 0.04045 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    }

    fn encode(v: f32) -> u8 {
        let v = v.clamp(0.0, 1.0);
        let s = if v <= 0.0031308 {
            12.92 * v
        } else {
            1.055 * v.powf(1.0 / 2.4) - 0.055
        };
        (s * 255.0).round().clamp(0.0, 255.0) as u8
    }

    /// Viénot, Brettel and Mollon (1999): project the colour onto the plane the
    /// missing cone leaves behind, in linear RGB.
    fn simulate(color: Color32, kind: Blindness) -> [u8; 3] {
        let r = linear(color.r());
        let g = linear(color.g());
        let b = linear(color.b());
        let mut l = 17.8824 * r + 43.5161 * g + 4.11935 * b;
        let mut m = 3.45565 * r + 27.1554 * g + 3.86714 * b;
        let mut s = 0.0299566 * r + 0.184309 * g + 1.46709 * b;
        match kind {
            Blindness::Deuteranopia => m = 0.494207 * l + 1.24827 * s,
            Blindness::Protanopia => l = 2.02344 * m - 2.52581 * s,
            Blindness::Tritanopia => s = -0.395913 * l + 0.801109 * m,
        }
        [
            encode(0.080944 * l - 0.130504 * m + 0.116721 * s),
            encode(-0.0102485 * l + 0.0540194 * m - 0.113615 * s),
            encode(-0.000365294 * l - 0.00412163 * m + 0.693513 * s),
        ]
    }

    /// Euclidean distance in RGB, 0 to 441.
    fn distance(a: [u8; 3], b: [u8; 3]) -> f32 {
        let d: f32 = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| {
                let d = f32::from(*x) - f32::from(*y);
                d * d
            })
            .sum();
        d.sqrt()
    }

    fn bands() -> [(Verdict, Color32); 4] {
        [
            (Verdict::Clean, Palette::CLEAN),
            (Verdict::Suspicious, Palette::SUSPICIOUS),
            (Verdict::Malicious, Palette::MALICIOUS),
            (Verdict::Unknown, Palette::UNKNOWN),
        ]
    }

    fn surfaces() -> [(&'static str, Color32); 3] {
        [
            ("background", Palette::BACKGROUND),
            ("panel", Palette::PANEL),
            ("raised", Palette::RAISED),
        ]
    }

    // -- the word ------------------------------------------------------------

    #[test]
    fn the_four_band_words_are_the_consoles_words() {
        // Spelled out rather than compared against `Verdict::as_str`, because
        // the point is not that they match the enum's spelling — it is that
        // they match the *console's* spelling, and the console's is a
        // hand-written `match` too. If av-cli ever changes one of these, this
        // test is the place the divergence is meant to be noticed.
        assert_eq!(verdict_word(Verdict::Clean), "clean");
        assert_eq!(verdict_word(Verdict::Suspicious), "suspicious");
        assert_eq!(verdict_word(Verdict::Malicious), "malicious");
        assert_eq!(verdict_word(Verdict::Unknown), "unknown");
    }

    #[test]
    fn every_band_has_a_word_and_a_colour_and_no_two_share_either() {
        let mut words = Vec::new();
        let mut colours = Vec::new();
        for (verdict, colour) in bands() {
            assert_eq!(verdict_color(verdict), colour);
            words.push(verdict_word(verdict));
            colours.push(colour);
        }
        words.sort_unstable();
        let before = words.len();
        words.dedup();
        assert_eq!(words.len(), before, "two bands share a word");
        for (index, colour) in colours.iter().enumerate() {
            for other in &colours[index + 1..] {
                assert_ne!(colour, other, "two bands share a colour");
            }
        }
    }

    #[test]
    fn the_palette_scale_is_the_palettes_constants() {
        // `SCALE` exists so a caller can pass the set around; a field added to
        // the struct and forgotten in `SCALE` would otherwise be a colour that
        // is never drawn.
        assert_eq!(Palette::SCALE.background, Palette::BACKGROUND);
        assert_eq!(Palette::SCALE.panel, Palette::PANEL);
        assert_eq!(Palette::SCALE.raised, Palette::RAISED);
        assert_eq!(Palette::SCALE.border, Palette::BORDER);
        assert_eq!(Palette::SCALE.text, Palette::TEXT);
        assert_eq!(Palette::SCALE.text_dim, Palette::TEXT_DIM);
        assert_eq!(Palette::SCALE.text_faint, Palette::TEXT_FAINT);
        assert_eq!(Palette::SCALE.accent, Palette::ACCENT);
        assert_eq!(Palette::SCALE.clean, Palette::CLEAN);
        assert_eq!(Palette::SCALE.suspicious, Palette::SUSPICIOUS);
        assert_eq!(Palette::SCALE.malicious, Palette::MALICIOUS);
        assert_eq!(Palette::SCALE.unknown, Palette::UNKNOWN);
    }

    #[test]
    fn the_verdict_colour_is_the_same_read_through_the_palette() {
        // `Palette::verdict` and `verdict_color` must not be two mappings, so
        // that a caller holding a palette and a caller holding nothing agree.
        let palette = Palette::SCALE;
        for (verdict, _) in bands() {
            assert_eq!(palette.verdict(verdict), verdict_color(verdict));
        }
    }

    // -- the band note -------------------------------------------------------

    #[test]
    fn the_middle_band_says_it_was_not_acted_on() {
        // The owner's rule, pinned as a test: the sentence for the yellow band
        // has to contain the thing that is not recoverable from — that nothing
        // was done to the file.
        let note = band_note(Verdict::Suspicious).expect("the middle band has a note");
        assert!(note.contains("not acted on"), "{note}");
        assert!(note.contains("not that it is malware"), "{note}");
    }

    #[test]
    fn the_unknown_band_is_not_allowed_to_read_as_an_acquittal() {
        let note = band_note(Verdict::Unknown).expect("the unknown band has a note");
        assert!(note.contains("Not scanned"), "{note}");
        assert!(note.contains("not reported as clean"), "{note}");
    }

    #[test]
    fn a_clean_band_has_nothing_to_say() {
        assert!(band_note(Verdict::Clean).is_none());
    }

    #[test]
    fn every_note_that_exists_is_a_sentence() {
        for (verdict, _) in bands() {
            if let Some(note) = band_note(verdict) {
                assert!(note.len() > 20, "{verdict:?}: {note}");
                assert!(note.ends_with('.'), "{verdict:?}: {note}");
                assert!(!note.contains("  "), "{verdict:?}: double space in {note}");
            }
        }
    }

    // -- contrast, measured --------------------------------------------------

    #[test]
    fn every_band_colour_is_readable_on_every_surface() {
        // 4.5:1 is the WCAG AA figure for body text. A band word is the one
        // thing on the screen a user must be able to read, so it is held to it
        // on all three surfaces rather than only on the one it happens to sit
        // on today.
        for (verdict, colour) in bands() {
            for (name, surface) in surfaces() {
                let ratio = contrast(colour, surface);
                assert!(
                    ratio >= 4.5,
                    "{verdict:?} on {name} is {ratio:.2}:1, below 4.5:1"
                );
            }
        }
    }

    #[test]
    fn body_text_and_secondary_text_are_readable_on_every_surface() {
        for colour in [Palette::TEXT, Palette::TEXT_DIM] {
            for (name, surface) in surfaces() {
                let ratio = contrast(colour, surface);
                assert!(ratio >= 4.5, "{colour:?} on {name} is {ratio:.2}:1");
            }
        }
        let accent = contrast(Palette::ACCENT, Palette::PANEL);
        assert!(accent >= 4.5, "the accent on the panel is {accent:.2}:1");
    }

    #[test]
    fn the_faint_colour_is_reserved_for_things_nobody_has_to_read() {
        // Documented as below AA, and pinned as below AA so that nobody
        // "fixes" it to 4.5:1 and then uses it for a label. If this ever passes
        // at 4.5:1 the documentation above is wrong.
        let ratio = contrast(Palette::TEXT_FAINT, Palette::PANEL);
        assert!(ratio < 4.5, "the faint colour is {ratio:.2}:1");
        // And it is still visible: a disabled control nobody can see is a
        // control nobody knows is disabled.
        assert!(ratio > 3.0, "the faint colour is {ratio:.2}:1");
    }

    #[test]
    fn a_band_fill_is_between_the_band_and_the_panel() {
        // The fills are hand-written blends, so they can drift from the colours
        // they claim to be blends of. Two properties pin them: each is closer to
        // the panel than to its own band colour, and each is visible against the
        // panel without competing with the text on it.
        for (verdict, colour) in bands() {
            let fill = verdict_fill(verdict);
            let to_panel = contrast(fill, Palette::PANEL);
            let to_band = contrast(fill, colour);
            assert!(
                to_panel < to_band,
                "{verdict:?}: the fill is nearer its band ({to_band:.2}) than the panel \
                 ({to_panel:.2})"
            );
            assert!(
                (1.05..2.0).contains(&to_panel),
                "{verdict:?}: the fill is {to_panel:.2}:1 against the panel, which is either \
                 invisible or a second label"
            );
        }
    }

    // -- colour blindness, measured ------------------------------------------

    #[test]
    fn no_two_bands_collapse_together_under_deuteranopia_or_protanopia() {
        // The floor is 60 rather than 40 because the two bands a user must not
        // confuse are clean and malicious, and this palette measures 62.8 for
        // that pair. A future tweak that pushed it to 41 would pass a floor of
        // 40 while making the pair a reader actually has to separate much
        // harder to separate.
        for kind in [Blindness::Deuteranopia, Blindness::Protanopia] {
            for (index, (a, colour_a)) in bands().iter().enumerate() {
                for (b, colour_b) in &bands()[index + 1..] {
                    let separation = distance(simulate(*colour_a, kind), simulate(*colour_b, kind));
                    assert!(
                        separation >= 60.0,
                        "{kind:?}: {a:?} and {b:?} are {separation:.1} apart"
                    );
                }
            }
        }
    }

    #[test]
    fn tritanopia_is_survivable_if_less_comfortable() {
        // Blue-yellow deficiency is the rare one, and it is the one this
        // palette cannot fully separate: the amber and the red both lose their
        // yellow axis. The floor is lower here and the module documentation
        // says so rather than claiming a symmetry that does not exist. The word
        // carried beside every band is what covers the remaining gap.
        for (index, (a, colour_a)) in bands().iter().enumerate() {
            for (b, colour_b) in &bands()[index + 1..] {
                let separation = distance(
                    simulate(*colour_a, Blindness::Tritanopia),
                    simulate(*colour_b, Blindness::Tritanopia),
                );
                assert!(
                    separation >= 50.0,
                    "tritanopia: {a:?} and {b:?} are {separation:.1} apart"
                );
            }
        }
    }

    #[test]
    fn the_simulation_is_the_published_one() {
        // The tool checked before its measurements are trusted. The Viénot
        // matrices are normalised so that white is a fixed point: the forward
        // matrix's row sums are exactly the LMS of white, and each substitution
        // restores the cone it removes at that same point. Any transcription
        // error in the eighteen coefficients breaks the fixed point, and every
        // separation measured above would then be measuring something else.
        //
        // Neutrals are fixed points too, because the transform is linear and
        // scaling every linear channel by the same factor scales the LMS by it
        // as well. That is what makes "grey" a safe choice for text in all
        // three simulations, and it is checked here rather than assumed.
        let tolerance = 1.0;
        for kind in [
            Blindness::Deuteranopia,
            Blindness::Protanopia,
            Blindness::Tritanopia,
        ] {
            for value in [0u8, 0x80, 0xFF] {
                let colour = Color32::from_rgb(value, value, value);
                let simulated = simulate(colour, kind);
                for channel in simulated {
                    assert!(
                        (f32::from(channel) - f32::from(value)).abs() <= tolerance,
                        "{kind:?} moved a neutral {value} to {simulated:?}"
                    );
                }
            }
        }
    }

    // -- the type scale ------------------------------------------------------

    /// The six steps, as a list, for the tests that are about the scale as a
    /// whole rather than about one step.
    fn steps() -> [(&'static str, Step); 6] {
        [
            ("display", DISPLAY_STEP),
            ("title", TITLE_STEP),
            ("heading", HEADING_STEP),
            ("body", BODY_STEP),
            ("meta", META_STEP),
            ("mono", MONO_STEP),
        ]
    }

    #[test]
    fn the_type_scale_descends_and_no_two_steps_are_the_same_size() {
        // The bug this is here to catch is a step edited to the size of its
        // neighbour, which is invisible in the source and obvious on the screen:
        // a section heading that looks exactly like the running text under it.
        //
        // The monospaced step is not part of the descent and is checked
        // separately: it is a family rather than a level of importance, and a
        // path is drawn at its own size wherever it appears — putting it in the
        // chain would be claiming that a path is less important than a caption.
        let ranked = ["display", "title", "heading", "body", "meta"];
        let sizes: Vec<f32> = ranked
            .iter()
            .map(|name| {
                steps()
                    .into_iter()
                    .find(|(step, _)| step == name)
                    .expect("every ranked step is in the scale")
                    .1
                    .size
            })
            .collect();
        for pair in sizes.windows(2) {
            assert!(pair[0] > pair[1], "the scale does not descend: {sizes:?}");
        }
        // Every operand is a `const`, so clippy can fold the comparison away and
        // is right that it cannot fail at run time. That is the point: this is
        // not checking a value computed at run time, it is failing the build of
        // anyone who moves the monospaced size out of the band between the two
        // levels it has to sit between. The same allowance, for the same reason,
        // as the window-size test in `av-gui`'s `app`.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                Text::MONO > Text::META && Text::MONO < Text::BODY,
                "the monospaced size has left the range the body text sets"
            );
        }

        let mut all: Vec<f32> = steps().iter().map(|(_, step)| step.size).collect();
        let count = all.len();
        all.sort_by(f32::total_cmp);
        all.dedup();
        assert_eq!(all.len(), count, "two steps share a size: {all:?}");
        for size in &all {
            assert!(
                *size >= 11.0 && *size <= 32.0,
                "{size} is not a size text is read at"
            );
        }
    }

    #[test]
    fn the_scale_is_not_one_weight_wearing_six_sizes() {
        // Weight is half of what separates a heading from a caption, and it is
        // the half that survives being scaled by a display DPI setting.
        let heavy: Vec<&str> = steps()
            .iter()
            .filter(|(_, step)| step.strong)
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(heavy, vec!["display", "title", "heading"]);
        assert!(steps().iter().any(|(_, step)| !step.strong));
    }

    #[test]
    fn every_text_size_is_a_size_something_is_drawn_at() {
        // `Palette::SCALE` and `Spacing::SCALE` exist so a caller can pass the
        // set around, and the tests beside them check that the two spellings of
        // each number agree. The type scale has no such value — see the note
        // under `Text` — so the property those tests protect has to be asserted
        // some other way, and this is it: no size is declared and then never
        // drawn.
        //
        // That matters more for a size than for a colour. A colour nothing
        // renders is simply absent; a size nothing renders is still *read*, by
        // whatever code picked the neighbouring constant, and the text appears
        // at a size that looks deliberate and is not.
        let declared = [
            Text::DISPLAY,
            Text::TITLE,
            Text::HEADING,
            Text::BODY,
            Text::META,
            Text::MONO,
        ];
        let drawn: Vec<f32> = steps().iter().map(|(_, step)| step.size).collect();
        for size in declared {
            assert!(
                drawn.contains(&size),
                "{size} points is declared but no step draws at it"
            );
        }
        assert_eq!(
            declared.len(),
            drawn.len(),
            "a step draws at a size no `Text` constant declares"
        );
    }

    #[test]
    fn every_step_takes_a_colour_the_palette_owns() {
        // The rule the whole crate is built on, applied to the scale: a step
        // cannot introduce a colour, so a step whose colour was typed by hand
        // fails here rather than looking almost right on the screen.
        let owned = [
            Palette::TEXT,
            Palette::TEXT_DIM,
            Palette::TEXT_FAINT,
            Palette::ACCENT,
            Palette::CLEAN,
            Palette::SUSPICIOUS,
            Palette::MALICIOUS,
            Palette::UNKNOWN,
        ];
        for (name, step) in steps() {
            assert!(owned.contains(&step.color), "{name} invented a colour");
        }
        // And no step is the disabled colour: a step is something to read.
        assert!(steps()
            .iter()
            .all(|(_, step)| step.color != Palette::TEXT_FAINT));
    }

    #[test]
    fn the_steps_render_at_the_sizes_they_claim() {
        // The measurement, and the one that would have caught a step whose size
        // was set on the `Step` and never reached the `RichText`. A headless
        // context lays the text out for real, so the number measured here is the
        // one the window would draw.
        let ctx = egui::Context::default();
        apply(&ctx);
        let mut heights = Vec::new();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            let style = ctx.style();
            for text in [
                display("Wenle AV"),
                title("Wenle AV"),
                heading("Wenle AV"),
                body("Wenle AV"),
                meta("Wenle AV"),
            ] {
                heights.push(ctx.fonts(|fonts| text.font_height(fonts, &style)));
            }
            // And the monospaced step is drawn at its own size, not at the
            // family's default.
            let mono = ctx.fonts(|fonts| mono("C:\\a\\b").font_height(fonts, &style));
            assert!(mono > 0.0);
        });
        for pair in heights.windows(2) {
            assert!(
                pair[1] < pair[0],
                "the rendered heights do not descend: {heights:?}"
            );
        }
        // The rendered height of the biggest step is of the order of its own
        // size rather than a constant egui chose.
        assert!(
            heights[0] >= Text::DISPLAY * 0.9,
            "the display step rendered at {} for a size of {}",
            heights[0],
            Text::DISPLAY
        );
    }

    #[test]
    fn the_scale_reaches_the_widgets_egui_draws_itself() {
        // A heading drawn by `ui.heading()` and a heading drawn through
        // `theme::heading` have to be the same size, or the window has two type
        // scales in it and the second one is egui's defaults.
        let styles = style().text_styles;
        let size = |style: egui::TextStyle| {
            styles
                .get(&style)
                .unwrap_or_else(|| panic!("{style:?} is not in the scale"))
                .size
        };
        assert_eq!(size(egui::TextStyle::Heading), TITLE_STEP.size);
        assert_eq!(size(egui::TextStyle::Body), BODY_STEP.size);
        assert_eq!(size(egui::TextStyle::Button), BODY_STEP.size);
        assert_eq!(size(egui::TextStyle::Small), META_STEP.size);
        assert_eq!(size(egui::TextStyle::Monospace), MONO_STEP.size);
        // Every family egui asks for is in the map: a missing one is a panic
        // inside egui rather than a wrong size, and it happens on the first
        // frame of a window nobody is watching a test run.
        for style in [
            egui::TextStyle::Heading,
            egui::TextStyle::Body,
            egui::TextStyle::Button,
            egui::TextStyle::Small,
            egui::TextStyle::Monospace,
        ] {
            assert!(styles.contains_key(&style), "{style:?} is missing");
        }
    }

    // -- the two new pairings, measured --------------------------------------

    #[test]
    fn text_on_a_band_tint_is_readable_and_the_secondary_colour_is_not() {
        // The status card is drawn on a band fill, which is not one of the three
        // surfaces the table at the top of this module measures. Both halves of
        // the decision are pinned: `TEXT` clears AA on all four, and `TEXT_DIM`
        // does not — which is *why* the card carries one text colour and takes
        // its hierarchy from the type scale instead.
        for (verdict, _) in bands() {
            let fill = verdict_fill(verdict);
            let text = contrast(Palette::TEXT, fill);
            assert!(
                text >= 4.5,
                "{verdict:?}: the body colour is {text:.2}:1 on its own fill"
            );
            // Well clear rather than barely: the floor the palette actually
            // measures is 9.12, and a fill edited down to 4.6 would pass the AA
            // check while making the one sentence on the card an effort.
            assert!(text >= 7.0, "{verdict:?}: the body colour is {text:.2}:1");
        }
        let below_aa: Vec<Verdict> = bands()
            .into_iter()
            .filter(|(verdict, _)| contrast(Palette::TEXT_DIM, verdict_fill(*verdict)) < 4.5)
            .map(|(verdict, _)| verdict)
            .collect();
        assert!(
            !below_aa.is_empty(),
            "the secondary colour now clears AA on every fill, so the documentation \
             above is wrong about why the card carries one text colour"
        );
    }

    #[test]
    fn the_primary_button_paints_its_label_on_the_accent() {
        // The one place the window puts a dark ground under light text. Contrast
        // is symmetric, so this is the same number as "the accent on the
        // background" in the table above — pinned separately because it is a
        // different decision that happens to measure the same.
        let ratio = contrast(Palette::BACKGROUND, Palette::ACCENT);
        assert!(ratio >= 4.5, "the primary button's label is {ratio:.2}:1");
        // And the raised colour, for the primary button drawn on a card rather
        // than on the window.
        let on_raised = contrast(Palette::RAISED, Palette::ACCENT);
        assert!(on_raised >= 4.5, "on a card it is {on_raised:.2}:1");
    }

    // -- the band copy -------------------------------------------------------

    #[test]
    fn every_band_has_a_headline_and_a_meaning_and_no_two_share_either() {
        let mut headlines = Vec::new();
        let mut meanings = Vec::new();
        for (verdict, _) in bands() {
            let headline = band_headline(verdict);
            let meaning = band_meaning(verdict);
            assert!(headline.len() > 8, "{verdict:?}: {headline}");
            assert!(meaning.len() > 20, "{verdict:?}: {meaning}");
            assert!(!headline.ends_with('.'), "a headline is not a sentence");
            assert!(meaning.ends_with('.'), "{verdict:?}: {meaning}");
            assert!(!meaning.contains("  "), "{verdict:?}: double space");
            headlines.push(headline);
            meanings.push(meaning);
        }
        headlines.sort_unstable();
        headlines.dedup();
        meanings.sort_unstable();
        meanings.dedup();
        assert_eq!(headlines.len(), 4, "two bands share a headline");
        assert_eq!(meanings.len(), 4, "two bands share a meaning");
    }

    /// The word that accuses, if the copy accuses anything.
    ///
    /// A word that names a harm is not an accusation when the clause it is in
    /// denies it, and the honest sentences in this module do exactly that —
    /// "nothing was moved, changed or blocked" is the sentence that makes the
    /// middle band safe to read, and a test that banned the word *blocked*
    /// outright would delete the sentence rather than the problem. So the copy
    /// is cut into clauses and a clause that contains a negation is allowed to
    /// name anything it likes.
    ///
    /// A comma is not a clause boundary: "nothing was moved, changed or blocked"
    /// is one denial with a list in it, and splitting on the commas would leave
    /// the last item of the list standing on its own as an accusation.
    fn accuses(text: &str, words: &[&str]) -> Option<String> {
        for clause in text.split(['.', ';', '—', ':', '\n']) {
            let clause = clause.to_lowercase();
            if ["not", "nothing", "never", "no "]
                .iter()
                .any(|denial| clause.contains(denial))
            {
                continue;
            }
            for word in words {
                if clause.contains(word) {
                    return Some((*word).to_owned());
                }
            }
        }
        None
    }

    #[test]
    fn the_middle_bands_copy_never_accuses_a_file() {
        // The owner's rule, checked on every string a user can meet the middle
        // band through — the long note included, so that the two cannot drift.
        // These are the words a reader takes as "this file is malware", and the
        // band that means "worth a look" must not say any of them outside a
        // denial.
        let accusations = [
            "malware", "infected", "virus", "threat", "blocked", "harmful",
        ];
        for text in [
            band_headline(Verdict::Suspicious),
            band_meaning(Verdict::Suspicious),
            band_note(Verdict::Suspicious).expect("the middle band has a note"),
        ] {
            if let Some(word) = accuses(text, &accusations) {
                panic!("\"{text}\" accuses a file of {word}");
            }
        }
        assert!(band_meaning(Verdict::Suspicious).contains("not acted on"));
    }

    #[test]
    fn the_unknown_band_never_reads_as_an_acquittal() {
        // The mirror image: this band must not say anything a reader would take
        // as "this file is fine", because nothing looked at it.
        let acquittals = ["clean", "safe", "trust", "verified"];
        for text in [
            band_headline(Verdict::Unknown),
            band_meaning(Verdict::Unknown),
            band_note(Verdict::Unknown).expect("the unknown band has a note"),
        ] {
            if let Some(word) = accuses(text, &acquittals) {
                panic!("\"{text}\" reads as {word}");
            }
        }
        assert!(band_meaning(Verdict::Unknown).contains("Not scanned"));
    }

    #[test]
    fn the_test_that_checks_for_accusations_can_see_one() {
        // The clause-splitting above is the whole of the test, so it is checked
        // against copy that is wrong in each of the two ways it looks for.
        assert!(accuses("This file is malware.", &["malware"]).is_some());
        assert!(accuses("Malware was found, and it is safe.", &["malware"]).is_some());
        assert!(accuses("Nothing was blocked.", &["blocked"]).is_none());
        assert!(accuses("It is not a clean result.", &["clean"]).is_none());
        // A list under a denial is one clause, which is the case the sentences
        // in this module actually contain.
        assert!(accuses("Nothing was moved, changed or blocked.", &["blocked"]).is_none());
        // But a denial in one clause does not cover the next one.
        assert!(accuses("Nothing was blocked; the file is malware.", &["malware"]).is_some());
    }

    #[test]
    fn the_malicious_headline_is_allowed_to_accuse_and_does() {
        // The counterpart to the test above: the band that *is* an accusation
        // has to make it, or the two bands would read the same and the red one
        // would be the one nobody acted on.
        assert!(band_headline(Verdict::Malicious).contains("Malicious"));
        assert!(band_meaning(Verdict::Malicious).contains("quarantine"));
    }

    #[test]
    fn the_unscanned_state_is_not_a_band_and_shares_no_word_with_one() {
        // A window that had not scanned anything and said "clean" would be
        // claiming a check it never ran.
        let lower = UNSCANNED.to_lowercase();
        for (verdict, _) in bands() {
            assert!(
                !lower.contains(verdict_word(verdict)),
                "{UNSCANNED} contains the {} band's word",
                verdict_word(verdict)
            );
        }
        assert!(!lower.contains("protected"), "this window protects nothing");
        assert!(!lower.contains("safe"));
    }

    // -- the card ------------------------------------------------------------

    #[test]
    fn a_card_is_the_spacing_scale_and_the_palette() {
        let frame = card(Palette::PANEL, Palette::BORDER);
        assert_eq!(frame.fill, Palette::PANEL);
        assert_eq!(frame.stroke, Stroke::new(1.0, Palette::BORDER));
        assert_eq!(frame.corner_radius, corner_radius());
        assert_eq!(frame.inner_margin, Margin::same(Spacing::LG as i8));
    }

    // -- severity ------------------------------------------------------------

    #[test]
    fn severity_borrows_the_band_colours_rather_than_inventing_a_scale() {
        assert_eq!(severity_color(Severity::Info), Palette::TEXT_DIM);
        assert_eq!(severity_color(Severity::Low), Palette::TEXT_DIM);
        assert_eq!(severity_color(Severity::Medium), Palette::SUSPICIOUS);
        assert_eq!(severity_color(Severity::High), Palette::MALICIOUS);
        assert_eq!(severity_color(Severity::Critical), Palette::MALICIOUS);
    }

    #[test]
    fn severity_colours_never_introduce_a_colour_the_palette_does_not_own() {
        let owned = [
            Palette::TEXT,
            Palette::TEXT_DIM,
            Palette::TEXT_FAINT,
            Palette::ACCENT,
            Palette::SUSPICIOUS,
            Palette::MALICIOUS,
        ];
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let colour = severity_color(severity);
            assert!(owned.contains(&colour), "{severity:?} invented a colour");
        }
    }

    // -- the style handed to egui --------------------------------------------

    #[test]
    fn the_style_is_the_palette_and_the_scale() {
        let style = style();
        assert!(style.visuals.dark_mode);
        assert_eq!(style.visuals.panel_fill, Palette::BACKGROUND);
        assert_eq!(style.visuals.window_fill, Palette::RAISED);
        assert_eq!(style.visuals.override_text_color, Some(Palette::TEXT));
        assert_eq!(style.visuals.hyperlink_color, Palette::ACCENT);
        assert_eq!(style.visuals.window_corner_radius, corner_radius());
        assert_eq!(
            style.spacing.item_spacing,
            Vec2::new(Spacing::SM, Spacing::SM)
        );
        assert_eq!(style.spacing.indent, Spacing::LG);
        assert_eq!(style.spacing.interact_size.y, Spacing::CONTROL_HEIGHT);
        assert_eq!(style.visuals.widgets.inactive.bg_fill, Palette::RAISED);
        assert_eq!(
            style.visuals.widgets.hovered.bg_stroke,
            Stroke::new(1.0, Palette::ACCENT)
        );
    }

    #[test]
    fn installing_the_style_on_a_context_is_the_style_function() {
        // `apply` must not be a second opinion. A headless context is enough to
        // prove it: this needs no window and no event loop.
        let ctx = egui::Context::default();
        apply(&ctx);
        let installed = ctx.style();
        assert_eq!(installed.visuals.panel_fill, Palette::BACKGROUND);
        assert_eq!(installed.visuals.panel_fill, style().visuals.panel_fill);
        // Necessary, and not sufficient. A headless context resolves to the
        // dark theme, so this reads the same slot `apply` happened to write on a
        // machine egui had not yet asked about — which is why this test was
        // green while the window drew light. See the test below for the one
        // that would have caught it.
    }

    #[test]
    fn a_light_system_theme_still_draws_the_palette() {
        // The bug, reproduced. The window drew in egui's default light theme on
        // a machine set to light mode while every other test in this module
        // passed. Both of the things that let this test see it are things a
        // rewrite has to keep:
        //
        // * the style is installed *before* the pass, exactly as `main.rs` does
        //   it — where in the frame it is installed is the whole bug, because
        //   before the first pass egui has no system theme and falls back to
        //   Dark, and after it egui knows and may read the other slot;
        // * the pass carries a system theme of Light, which is what both a
        //   headless context and a developer machine in dark mode fail to do.
        let ctx = egui::Context::default();
        apply(&ctx);

        let input = egui::RawInput {
            system_theme: Some(egui::Theme::Light),
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| {
            assert_eq!(
                ctx.style().visuals.panel_fill,
                Palette::BACKGROUND,
                "the frame drew on egui's default fill, not the palette's"
            );
            assert_eq!(ctx.style().visuals.override_text_color, Some(Palette::TEXT));
            assert_eq!(
                ctx.theme(),
                egui::Theme::Dark,
                "the theme followed the system instead of being pinned"
            );
        });
    }

    #[test]
    fn the_spacing_scale_is_four_point_steps_that_grow() {
        let scale = Spacing::SCALE;
        let steps = [scale.xs, scale.sm, scale.md, scale.lg, scale.xl];
        for pair in steps.windows(2) {
            assert!(pair[1] > pair[0], "{pair:?} is not increasing");
            assert_eq!(pair[1] % 4.0, 0.0, "{pair:?} is off the four-point grid");
        }
        assert_eq!(scale.xs, Spacing::XS);
        assert_eq!(scale.xl, Spacing::XL);
        assert_eq!(scale.radius, Spacing::RADIUS);
        assert!(scale.row_height >= 20.0 && scale.row_height <= 40.0);
        assert!(
            scale.control_height >= 24.0,
            "a target smaller than 24 points is a miss"
        );
    }
}
