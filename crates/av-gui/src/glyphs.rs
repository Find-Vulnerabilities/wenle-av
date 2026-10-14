//! The characters the window draws, and the font's promise to have them.
//!
//! # The failure this exists for
//!
//! `egui` renders text with the fonts it ships — Ubuntu-Light for proportional
//! text, Hack for monospace, and two emoji faces behind them as fallbacks. A
//! character none of them carries is not an error and not a blank: it is a
//! *tofu box*, the hollow rectangle a font draws for a glyph it does not have.
//! Nothing fails, nothing is logged, and the window shows the user a rectangle
//! where a symbol was meant to be.
//!
//! This window tried that route for two marks and both failed it. The filled dot
//! that heads the status line (`⬤`, U+2B24) and the half block that makes the
//! vertical rule beside a section (`▌`, U+258C) were written as characters first.
//! Both are outside Latin-1 and outside ASCII, and both are the sort of thing a
//! proportional text font omits on purpose — which is precisely what the test in
//! this module was written to find out, and what it found out: neither has a
//! glyph in Ubuntu-Light, the family the window draws them in, so both reached
//! the screen as the tofu box described above. Both are now drawn as geometry,
//! [`crate::icons::Icon::for_band`] and [`crate::icons::stripe`], and neither is
//! in the `DRAWN` list below any more. That list is built only for the tests — a
//! `const` behind `cfg(test)` cannot be linked to from a doc comment, which is
//! why it is named here rather than linked.
//!
//! So [`crate::icons`] is this problem's answer rather than its alternative. A
//! shape drawn as polylines cannot be missing from a font, and the two characters
//! that were meant to show a character was good enough are the evidence that it is
//! not. A character is cheaper to write and is a dependency on somebody else's
//! glyph coverage; this crate took that dependency twice and lost both times.
//!
//! # The second question, which is about drift
//!
//! A test that lists the em dash and the ellipsis only guards the two characters
//! someone remembered to list. The one that gets added later — a check mark in a
//! tooltip, an arrow in a sentence — is the one that ships as a box, and it
//! will be added by an edit that never touches this file.
//!
//! So the inventory below is checked against the crate's own source: every
//! non-ASCII character anywhere in `crates/av-gui/src` has to be one of these.
//! A new one fails the build with the character and the file it is in, which is
//! a message that says what to do. That test reads the sources with
//! `include_str!`, so it is a compile-time dependency on each file and cannot
//! silently stop covering one that is renamed.

/// Every non-ASCII character that appears anywhere in this crate's sources.
///
/// Grouped by what the character is *for*, because the groups are answered by
/// different things: [`DRAWN`] has to be in the font, and the rest only has to
/// be accounted for. A character in a comment cannot reach a user's screen and a
/// character in a test is checked by that test; both still have to be listed, so
/// that the list stays a complete account of the file's non-ASCII content.
///
/// Test-only, for the reason [`crate::icons::Icon::ALL`] gives about its own
/// list: nothing in the shipped window iterates these — the window draws text
/// and the characters in it are whatever the strings say — so the only reader is
/// the test below. Compiling the inventory into the product would be compiling a
/// test fixture into it.
#[cfg(test)]
pub const INVENTORY: &[char] = &[
    // Prose. The em dash is the one this project writes with, the en dash and
    // the ellipsis appear in ranges and in truncated text.
    '\u{2014}', // — em dash
    '\u{2013}', // – en dash
    '\u{2026}', // … ellipsis
    // Test data: a path component in a script this product does not speak, and
    // the accented letter in `Viénot`. Neither is ever drawn.
    '\u{00E9}', // é
    '\u{0430}', // а
    '\u{0434}', // д
    '\u{0435}', // е
    '\u{0438}', // и
    '\u{0439}', // й
    '\u{043B}', // л
    '\u{043D}', // н
    '\u{043E}', // о
    '\u{043F}', // п
    '\u{0442}', // т
    '\u{0443}', // у
    '\u{0444}', // ф
    '\u{0447}', // ч
    '\u{044B}', // ы
    '\u{044C}', // ь
    '\u{044F}', // я
    // Written about but never drawn, and listed for that reason alone. Both were
    // characters in an earlier version of the window and both were found to have
    // no glyph in the font that draws them, so both are geometry now — see the
    // module documentation. They stay here because the sources that name them,
    // including the ones explaining the change, still contain them.
    '\u{258C}', // ▌ left half block
    '\u{2B24}', // ⬤ black large circle
];

/// The subset of [`INVENTORY`] that reaches a user's screen as *text*.
///
/// These are the characters the font has to carry. A character here that the
/// font set does not have is a tofu box in the window, and the test below is
/// what turns that into a build failure.
///
/// What is deliberately absent is as much the point as what is here. The two
/// marks this test was written for — `▌` U+258C and `⬤` U+2B24 — are no longer
/// in the list because they are no longer characters: they were found to have no
/// glyph in the proportional family, which is the family the window draws them
/// in, and both are now drawn as geometry ([`crate::icons::stripe`] and
/// [`crate::icons::Icon::for_band`]). They remain in [`INVENTORY`] because they
/// are still written about, here and in the modules that explain the change.
///
/// Test-only, like [`INVENTORY`].
#[cfg(test)]
pub const DRAWN: &[char] = &[
    '\u{2014}', // — the em dash, which this product writes its asides with
    '\u{2026}', // … the ellipsis, at the end of a sentence that is still going
];

#[cfg(test)]
mod tests {
    use super::*;
    // Through `eframe`, which is the only way this crate names `egui`: it is not
    // a direct dependency, so `eframe` decides the version.
    use eframe::egui;

    /// The crate's own sources, so that a character added anywhere is seen.
    ///
    /// `include_str!` rather than a directory walk: a file that is renamed or
    /// deleted is then a compile error here rather than a file this test
    /// quietly stopped reading.
    const SOURCES: &[(&str, &str)] = &[
        ("app.rs", include_str!("app.rs")),
        ("filter.rs", include_str!("filter.rs")),
        ("format.rs", include_str!("format.rs")),
        ("glyphs.rs", include_str!("glyphs.rs")),
        ("icons.rs", include_str!("icons.rs")),
        ("main.rs", include_str!("main.rs")),
        ("picker.rs", include_str!("picker.rs")),
        ("scan.rs", include_str!("scan.rs")),
        ("service.rs", include_str!("service.rs")),
        ("state.rs", include_str!("state.rs")),
        ("theme.rs", include_str!("theme.rs")),
    ];

    /// Assert that the window's font set carries every drawn character.
    ///
    /// The fonts are a fresh `Context`'s own, which are `egui`'s defaults — the
    /// same set `eframe` installs, because nothing in this crate replaces the
    /// font definitions. Deliberately not built from `crate::theme`'s style: the
    /// style carries sizes and colours and no font data, so the two cannot
    /// disagree about coverage, and a test that reconstructed the style would be
    /// testing its own copy of it.
    ///
    /// `Context::fonts` lends the fonts behind a lock guard, so the question has
    /// to be asked inside the closure. The closure returns `()`, and the answers
    /// leave by way of the assertions.
    fn assert_drawn_characters_have_glyphs() {
        let context = egui::Context::default();
        // One empty frame first. `Context` builds its font atlas lazily, on the
        // first frame it is asked to draw, and `Context::fonts` panics before
        // that with "No fonts available until first call to Context::run()".
        // Running a frame here is not a workaround: a frame is what a real
        // window does before it draws any of this text, so this asks the
        // question in the state the answer will actually be given in.
        let _ = context.run(egui::RawInput::default(), |_| {});
        // Both families, because a mark is not tied to one: these two are drawn
        // through `ui.label` and so take the proportional family, but the same
        // character put through `crate::theme::mono` would ask the monospace
        // family, and a rule that held in one and not the other would be a
        // surprise waiting for whoever moved the label.
        //
        // The size is the one thing here that is arbitrary: `has_glyphs` asks
        // the *font*, and a family's coverage does not depend on the point size.
        const SIZE: f32 = 12.0;
        context.fonts(|fonts| {
            let mut missing: Vec<String> = Vec::new();
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                let font = egui::FontId::new(SIZE, family.clone());
                for character in DRAWN {
                    if !fonts.has_glyphs(&font, &character.to_string()) {
                        missing.push(format!("U+{:04X} in {family:?}", *character as u32));
                    }
                }
            }
            assert!(
                missing.is_empty(),
                "the font set has no glyph for {}, so the window would draw a hollow box where \
                 the mark was meant. Either draw it as geometry — see `crate::icons`, which is \
                 how the other twelve are done — or stop using the character",
                missing.join(", ")
            );
        });
    }

    #[test]
    fn the_drawn_characters_are_in_the_font_the_window_is_drawn_with() {
        assert_drawn_characters_have_glyphs();
    }

    #[test]
    fn every_drawn_character_is_in_the_inventory() {
        for character in DRAWN {
            assert!(
                INVENTORY.contains(character),
                "U+{:04X} is drawn but is not listed in INVENTORY",
                *character as u32
            );
        }
    }

    #[test]
    fn the_inventory_is_a_complete_account_of_the_crates_non_ascii_text() {
        // The drift guard. A character added to any file fails here, with the
        // character and the file, rather than reaching a user as a box.
        let mut unlisted: Vec<(String, char)> = Vec::new();
        for (name, source) in SOURCES {
            for character in source.chars() {
                if !character.is_ascii() && !INVENTORY.contains(&character) {
                    let entry = ((*name).to_owned(), character);
                    if !unlisted.contains(&entry) {
                        unlisted.push(entry);
                    }
                }
            }
        }
        assert!(
            unlisted.is_empty(),
            "these characters appear in this crate's sources and are not in `INVENTORY`: {}. \
             Add each one there. If it is drawn rather than written in a comment or a test, add \
             it to `DRAWN` as well — that is the list the font is checked against",
            unlisted
                .iter()
                .map(|(name, character)| format!("U+{:04X} in {name}", *character as u32))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}
