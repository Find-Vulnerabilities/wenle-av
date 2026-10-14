//! The marks the window draws itself.
//!
//! # Why these are geometry and not a font
//!
//! The obvious way to put a shield or a tick on a button is an icon font, and it
//! is the wrong way here for two reasons that are both about this product rather
//! than about taste. The first is that a font is a dependency, and this
//! workspace is deliberately thin: every crate added is build time on a machine
//! that rebuilds this binary many times a day, and attack surface in a program
//! whose job is to look at untrusted files. The second is that a glyph is
//! whatever the font's designer drew — a stroke weight, an optical size and a
//! corner treatment chosen for a different product — while the marks here have
//! to sit next to text at four sizes and share one line weight with the
//! rectangles around them.
//!
//! So an icon is a list of polylines in a unit square, and [`shapes`] scales one
//! into a rectangle. That makes the whole module testable without a window,
//! which a font would not be: the tests below check that every mark is inside the
//! square it claims, that none of them is degenerate, that no two are the same
//! drawing, and that a collapsed rectangle produces nothing rather than a panic.
//!
//! # Every mark is a stroke, and the dots are the exception
//!
//! One line weight across the whole set is what makes a column of marks look
//! drawn by one hand. The exclamation and the question mark need a filled dot to
//! read at small sizes, and those are the only filled shape in the module; a
//! filled dot at a known radius is not a second line weight, it is punctuation.
//!
//! # Colour is never the only carrier, and here that is structural
//!
//! Every mark is a different *shape* as well as a different colour where the two
//! travel together — a tick, a cross, a triangle, a question mark — so an icon is
//! never the only thing distinguishing two states. The window also always draws
//! the band's word beside the mark; see [`crate::theme::verdict_word`].

use eframe::egui::{self, Color32, Pos2, Rect, Shape, Stroke, Vec2};

/// A mark the window can draw.
///
/// The names are the shapes, not the meanings: [`Icon::Check`] is a tick, and
/// where a tick is used for "clean" is a decision [`Icon::for_band`] makes in one
/// place rather than a fact about the tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// A shield, the product's own mark and the shape of "this machine".
    Shield,
    /// A tick.
    Check,
    /// A cross.
    Cross,
    /// A triangle with a stroke under it: a warning that something is wrong.
    Alert,
    /// A question mark.
    Question,
    /// A magnifier.
    Search,
    /// A locked box with a dial.
    Vault,
    /// Three sliders.
    Sliders,
    /// A folder.
    Folder,
    /// A page with a folded corner.
    Page,
    /// A filled right-pointing triangle.
    Play,
    /// A filled square.
    Stop,
}

impl Icon {
    /// The mark that stands for a band.
    ///
    /// Four bands, four different shapes, one function — so that the mark in the
    /// header, the mark on a status card and the mark in the legend cannot be
    /// three different pictures of the same verdict. A test pins that all four
    /// are distinct.
    pub const fn for_band(verdict: av_core::Verdict) -> Self {
        use av_core::Verdict;
        match verdict {
            Verdict::Clean => Icon::Check,
            Verdict::Suspicious => Icon::Alert,
            Verdict::Malicious => Icon::Cross,
            Verdict::Unknown => Icon::Question,
        }
    }

    /// The mark's geometry, as polylines in the unit square.
    ///
    /// Each polyline is a list of points in `0..=1` on both axes; the caller
    /// scales them into whatever rectangle it has. A polyline of two points is a
    /// straight line, a longer one is an open curve, and a polyline whose last
    /// point equals its first is a closed outline. Nothing here is filled except
    /// the dot list.
    pub fn outline(self) -> Vec<Vec<Pos2>> {
        let p = |x: f32, y: f32| Pos2::new(x, y);
        match self {
            // A shield: flat across the top with two shoulders, tapering to a
            // point. Six points rather than a curve, because at 14 points a
            // curve and a chord look the same and a polyline is one shape.
            Icon::Shield => vec![vec![
                p(0.50, 0.06),
                p(0.90, 0.24),
                p(0.90, 0.52),
                p(0.50, 0.94),
                p(0.10, 0.52),
                p(0.10, 0.24),
                p(0.50, 0.06),
            ]],
            // A tick. The short arm is deliberately shorter than the long one:
            // a symmetrical tick reads as a corner.
            Icon::Check => vec![vec![p(0.20, 0.52), p(0.42, 0.74), p(0.80, 0.26)]],
            Icon::Cross => vec![
                vec![p(0.24, 0.24), p(0.76, 0.76)],
                vec![p(0.76, 0.24), p(0.24, 0.76)],
            ],
            // A warning triangle with an exclamation in it. The stroke is short
            // and the dot below it small, so the triangle stays an outline at
            // 14 points instead of filling in.
            Icon::Alert => vec![
                vec![p(0.50, 0.08), p(0.95, 0.86), p(0.05, 0.86), p(0.50, 0.08)],
                vec![p(0.50, 0.38), p(0.50, 0.62)],
            ],
            // A question mark: a hook over the top, a tail curving down to the
            // centre line, and a dot under it. The hook is 175 degrees round to
            // 370, so it opens at the bottom-left and ends pointing down-right,
            // which is where a sans-serif question mark's stem begins.
            Icon::Question => {
                let mut hook = arc(p(0.50, 0.38), 0.24, 175.0, 370.0, 14);
                hook.push(p(0.50, 0.62));
                vec![hook]
            }
            // A magnifier: the lens, and a handle at the lower right.
            Icon::Search => vec![
                arc(p(0.44, 0.42), 0.30, 0.0, 360.0, 20),
                vec![p(0.65, 0.65), p(0.90, 0.90)],
            ],
            // A box with a dial on it: the vault.
            Icon::Vault => vec![
                vec![
                    p(0.08, 0.14),
                    p(0.92, 0.14),
                    p(0.92, 0.90),
                    p(0.08, 0.90),
                    p(0.08, 0.14),
                ],
                arc(p(0.50, 0.54), 0.16, 0.0, 360.0, 14),
                vec![p(0.50, 0.30), p(0.50, 0.38)],
            ],
            // Three sliders, each a rail with a knob: the universal mark for
            // settings, and the one mark here whose meaning is a convention
            // rather than a picture of the thing.
            Icon::Sliders => vec![
                vec![p(0.08, 0.24), p(0.92, 0.24)],
                vec![p(0.08, 0.50), p(0.92, 0.50)],
                vec![p(0.08, 0.76), p(0.92, 0.76)],
                vec![p(0.34, 0.14), p(0.34, 0.34)],
                vec![p(0.66, 0.40), p(0.66, 0.60)],
                vec![p(0.42, 0.66), p(0.42, 0.86)],
            ],
            // A folder: two points across the tab, then the body.
            Icon::Folder => vec![vec![
                p(0.08, 0.80),
                p(0.08, 0.22),
                p(0.40, 0.22),
                p(0.48, 0.34),
                p(0.92, 0.34),
                p(0.92, 0.80),
                p(0.08, 0.80),
            ]],
            // A page with the top-right corner folded off.
            Icon::Page => vec![
                vec![
                    p(0.20, 0.08),
                    p(0.62, 0.08),
                    p(0.82, 0.30),
                    p(0.82, 0.92),
                    p(0.20, 0.92),
                    p(0.20, 0.08),
                ],
                vec![p(0.62, 0.08), p(0.62, 0.30), p(0.82, 0.30)],
            ],
            // A filled triangle. Returned as an outline like everything else and
            // drawn filled by `shapes`, which is the one place the module has a
            // second drawing mode — a play triangle is unreadable as an outline
            // at 14 points.
            Icon::Play => vec![vec![
                p(0.24, 0.12),
                p(0.86, 0.50),
                p(0.24, 0.88),
                p(0.24, 0.12),
            ]],
            Icon::Stop => vec![vec![
                p(0.18, 0.18),
                p(0.82, 0.18),
                p(0.82, 0.82),
                p(0.18, 0.82),
                p(0.18, 0.18),
            ]],
        }
    }

    /// The filled dots the mark needs, as `(centre, radius)` in the unit square.
    ///
    /// Only the exclamation and the question mark have them, and a test pins
    /// that: a dot added to the shield would be a stray blob nobody could
    /// explain.
    pub fn dots(self) -> Vec<(Pos2, f32)> {
        match self {
            Icon::Alert => vec![(Pos2::new(0.50, 0.74), 0.055)],
            Icon::Question => vec![(Pos2::new(0.50, 0.80), 0.055)],
            _ => Vec::new(),
        }
    }

    /// Whether the mark is drawn filled rather than stroked.
    ///
    /// True for the two transport marks, which are shapes rather than
    /// line drawings: an outlined play triangle is a triangle with a triangle
    /// inside it at any size this window draws.
    pub const fn filled(self) -> bool {
        matches!(self, Icon::Play | Icon::Stop)
    }

    /// Every mark, in the order they are declared.
    ///
    /// Test-only, and the reason is worth stating rather than leaving as a
    /// `cfg`: the product never iterates its marks — every call site names the
    /// one it wants — so the only caller this array has is the set of tests
    /// below that check the *whole* set at once: that every mark fits the
    /// square it claims, that none is degenerate, and that no two are the same
    /// drawing. Those are properties of the set, not of any one mark, and there
    /// is no way to state them without a list. Compiling the list into the
    /// shipped binary would be compiling a test fixture into the product.
    #[cfg(test)]
    pub const ALL: [Icon; 12] = [
        Icon::Shield,
        Icon::Check,
        Icon::Cross,
        Icon::Alert,
        Icon::Question,
        Icon::Search,
        Icon::Vault,
        Icon::Sliders,
        Icon::Folder,
        Icon::Page,
        Icon::Play,
        Icon::Stop,
    ];
}

/// Points along an arc, in the unit square.
///
/// `start` and `end` are degrees measured the way the screen measures them —
/// zero to the right, increasing downwards — so that 270 is straight up, which
/// is where a hook starts. The arc is always drawn in increasing angle, so an
/// end smaller than the start wraps the long way round; that is what makes a
/// closed ring one call rather than a special case.
fn arc(centre: Pos2, radius: f32, start: f32, end: f32, segments: usize) -> Vec<Pos2> {
    let segments = segments.max(2);
    let sweep = end - start;
    (0..=segments)
        .map(|step| {
            let angle = (start + sweep * step as f32 / segments as f32).to_radians();
            centre + Vec2::new(angle.cos(), angle.sin()) * radius
        })
        .collect()
}

/// A mark scaled into a rectangle, as shapes ready to be painted.
///
/// `width` is the stroke weight, and the rectangle is inset by half of it before
/// anything is scaled, so that a mark drawn in a rectangle touches the edge
/// without the stroke spilling out of it. A rectangle with no area in it — a
/// panel that has been collapsed to nothing, which a window dragged to its
/// minimum produces — gives an empty list rather than a set of degenerate
/// shapes, because a zero-sized shape is a thing egui has to tessellate and the
/// user cannot see.
pub fn shapes(icon: Icon, rect: Rect, color: Color32, width: f32) -> Vec<Shape> {
    let inset = width / 2.0;
    let inner = rect.shrink(inset);
    if inner.width() <= 0.0 || inner.height() <= 0.0 {
        return Vec::new();
    }
    let at = |point: Pos2| {
        Pos2::new(
            inner.left() + point.x * inner.width(),
            inner.top() + point.y * inner.height(),
        )
    };

    let mut shapes = Vec::new();
    for line in icon.outline() {
        if line.len() < 2 {
            continue;
        }
        let points: Vec<Pos2> = line.into_iter().map(at).collect();
        if icon.filled() {
            shapes.push(Shape::convex_polygon(points, color, Stroke::NONE));
        } else {
            shapes.push(Shape::line(points, Stroke::new(width, color)));
        }
    }
    // The dots are circles, and a circle's radius is scaled by the smaller side
    // so that a dot stays round when the rectangle is not square.
    let unit = inner.width().min(inner.height());
    for (centre, radius) in icon.dots() {
        shapes.push(Shape::circle_filled(at(centre), radius * unit, color));
    }
    shapes
}

/// Paint a mark into a rectangle.
pub fn paint(painter: &egui::Painter, icon: Icon, rect: Rect, color: Color32, width: f32) {
    let shapes = shapes(icon, rect, color, width);
    if !shapes.is_empty() {
        painter.extend(shapes);
    }
}

/// Draw a mark as its own widget, and return the space it took.
///
/// The mark is laid out as a square of `size` points and the response carries no
/// sense, so an icon is never a click target by accident: a 14-point square is
/// below the 24-point minimum a pointer target needs, and one that was clickable
/// would be a target a user misses.
pub fn show(ui: &mut egui::Ui, icon: Icon, size: f32, color: Color32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    paint(ui.painter(), icon, rect, color, stroke_width(size));
    response
}

/// The stroke weight for a mark of a given size.
///
/// One rule for the whole set: a fifth of the size, clamped, so that a 14-point
/// mark in a row and a 40-point mark on a status card are the same drawing at
/// two scales rather than two weights.
pub fn stroke_width(size: f32) -> f32 {
    (size * 0.09).clamp(1.0, 2.4)
}

/// How wide [`stripe`] draws, and the one place that number is written.
pub const STRIPE_WIDTH: f32 = 3.0;

/// The colour stripe that opens a row: a bar, and deliberately not a mark.
///
/// # Why this is not a character
///
/// It used to be `▌` — U+258C, the half block — drawn as a label beside the row
/// it belongs to. The proportional font `egui` ships does not carry that
/// character, so every row in the findings list and every row in the vault drew
/// a hollow rectangle where the stripe was meant to be. `crate::glyphs` is what
/// found it, by asking the font set instead of assuming.
///
/// The module documentation above already gives the reason this is a rectangle:
/// a shape the window draws itself cannot be missing from a font, and a stripe
/// is a rectangle. Nothing about a bar needs a designer's glyph.
///
/// # Why it takes a height rather than a size
///
/// Because it is not square and should not be. A mark is drawn in a square so
/// that it reads the same at any size; a stripe is as tall as the line it sits
/// beside and one number wide, and the caller is the only thing that knows how
/// tall the line is.
pub fn stripe(ui: &mut egui::Ui, color: Color32, height: f32) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(STRIPE_WIDTH, height), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, crate::theme::corner_radius(), color);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::Verdict;

    fn rect() -> Rect {
        Rect::from_min_size(Pos2::new(10.0, 20.0), Vec2::splat(32.0))
    }

    /// Every point of every polyline, as a flat list.
    fn points(icon: Icon) -> Vec<Pos2> {
        icon.outline().into_iter().flatten().collect()
    }

    #[test]
    fn every_mark_is_a_drawing_and_not_an_empty_list() {
        // A mark that returned nothing would draw nothing, and the one place
        // that would show is the window — which no test can see.
        for icon in Icon::ALL {
            let outline = icon.outline();
            assert!(!outline.is_empty(), "{icon:?} has no polylines");
            for (index, line) in outline.iter().enumerate() {
                assert!(
                    line.len() >= 2,
                    "{icon:?} polyline {index} has {} point(s), which is not a line",
                    line.len()
                );
            }
        }
    }

    #[test]
    fn every_mark_stays_inside_the_square_it_is_drawn_in() {
        // The unit square is the contract between this module and the drawing
        // code: a point at 1.4 would be drawn outside the rectangle the caller
        // allocated, over whatever is next to it.
        for icon in Icon::ALL {
            for point in points(icon) {
                assert!(
                    (0.0..=1.0).contains(&point.x) && (0.0..=1.0).contains(&point.y),
                    "{icon:?} has a point at {point:?}, outside the unit square"
                );
            }
            for (centre, radius) in icon.dots() {
                assert!(
                    centre.x - radius >= 0.0
                        && centre.x + radius <= 1.0
                        && centre.y - radius >= 0.0
                        && centre.y + radius <= 1.0,
                    "{icon:?} has a dot at {centre:?} r{radius} that leaves the square"
                );
            }
        }
    }

    #[test]
    fn every_mark_fills_a_usable_part_of_its_square() {
        // Two failure modes at once: a mark collapsed onto one axis (a tick that
        // is a horizontal line) and a mark drawn so small in the corner that it
        // is a speck at 14 points.
        for icon in Icon::ALL {
            let points = points(icon);
            let (mut min_x, mut max_x) = (f32::MAX, f32::MIN);
            let (mut min_y, mut max_y) = (f32::MAX, f32::MIN);
            for point in &points {
                min_x = min_x.min(point.x);
                max_x = max_x.max(point.x);
                min_y = min_y.min(point.y);
                max_y = max_y.max(point.y);
            }
            let (width, height) = (max_x - min_x, max_y - min_y);
            // The cross is the narrowest thing here at 0.52 of the square; the
            // floor is below it and well above a mark that has gone flat.
            assert!(
                width >= 0.4 && height >= 0.4,
                "{icon:?} covers {width:.2} by {height:.2} of the unit square"
            );
            assert!(
                min_x <= 0.3 && max_x >= 0.7,
                "{icon:?} is not centred: {min_x:.2}..{max_x:.2}"
            );
        }
    }

    #[test]
    fn no_two_marks_are_the_same_drawing() {
        // The failure this catches is a copy-paste: a new variant added by
        // duplicating its neighbour and forgetting to change the geometry, which
        // would draw the right shape for the wrong state.
        for (index, icon) in Icon::ALL.iter().enumerate() {
            for other in &Icon::ALL[index + 1..] {
                assert_ne!(
                    icon.outline(),
                    other.outline(),
                    "{icon:?} and {other:?} are the same drawing"
                );
            }
        }
    }

    #[test]
    fn the_four_bands_get_four_different_marks() {
        // The mark is a second carrier of the band beside the colour and the
        // word. Two bands sharing a mark would leave colour doing the work
        // alone, which is the thing the palette's own tests exist to prevent.
        let marks: Vec<Icon> = [
            Verdict::Clean,
            Verdict::Suspicious,
            Verdict::Malicious,
            Verdict::Unknown,
        ]
        .into_iter()
        .map(Icon::for_band)
        .collect();
        for (index, mark) in marks.iter().enumerate() {
            for other in &marks[index + 1..] {
                assert_ne!(mark, other, "two bands share a mark");
            }
        }
        assert_eq!(Icon::for_band(Verdict::Clean), Icon::Check);
        assert_eq!(Icon::for_band(Verdict::Malicious), Icon::Cross);
    }

    #[test]
    fn only_the_two_punctuation_marks_carry_a_dot() {
        let with_dots: Vec<Icon> = Icon::ALL
            .into_iter()
            .filter(|icon| !icon.dots().is_empty())
            .collect();
        assert_eq!(with_dots, vec![Icon::Alert, Icon::Question]);
    }

    #[test]
    fn the_filled_marks_are_the_two_transport_marks() {
        let filled: Vec<Icon> = Icon::ALL.into_iter().filter(|icon| icon.filled()).collect();
        assert_eq!(filled, vec![Icon::Play, Icon::Stop]);
    }

    #[test]
    fn a_scaled_mark_is_inside_the_rectangle_it_was_given() {
        // The contract the drawing code relies on: an icon never paints outside
        // the space it asked for.
        let bounds = rect();
        for icon in Icon::ALL {
            let shapes = shapes(icon, bounds, Color32::WHITE, 2.0);
            assert!(!shapes.is_empty(), "{icon:?} produced no shapes");
            for shape in &shapes {
                let drawn = shape.visual_bounding_rect();
                assert!(
                    drawn.min.x >= bounds.min.x - 0.5
                        && drawn.min.y >= bounds.min.y - 0.5
                        && drawn.max.x <= bounds.max.x + 0.5
                        && drawn.max.y <= bounds.max.y + 0.5,
                    "{icon:?} drew {drawn:?} outside {bounds:?}"
                );
            }
        }
    }

    #[test]
    fn a_mark_scaled_into_nothing_is_no_shapes_and_not_a_panic() {
        // A window dragged to its minimum, or a panel that laid out to zero
        // height, hands the drawing code a rectangle with no area in it.
        for icon in Icon::ALL {
            for empty in [
                Rect::from_min_size(Pos2::ZERO, Vec2::ZERO),
                Rect::from_min_size(Pos2::ZERO, Vec2::new(32.0, 0.0)),
                Rect::from_min_size(Pos2::ZERO, Vec2::new(0.0, 32.0)),
                // Narrower than the stroke is wide, which the inset turns into a
                // negative rectangle.
                Rect::from_min_size(Pos2::ZERO, Vec2::splat(0.5)),
            ] {
                assert!(
                    shapes(icon, empty, Color32::WHITE, 2.0).is_empty(),
                    "{icon:?} drew something into {empty:?}"
                );
            }
        }
    }

    #[test]
    fn a_mark_takes_the_colour_and_the_weight_it_was_given() {
        // The shapes carry their own paint, so a mark drawn in the wrong colour
        // is not a styling slip the caller can fix later — it is what is on the
        // screen. Checked through the two constructors rather than by matching
        // on every variant: a stroked mark's path stroke and a filled mark's
        // fill are the only two places this module puts a colour.
        let colour = Color32::from_rgb(1, 2, 3);
        let stroked = shapes(Icon::Check, rect(), colour, 2.0);
        let Shape::Path(path) = &stroked[0] else {
            panic!("a tick is a path");
        };
        assert_eq!(path.stroke.color, egui::epaint::ColorMode::Solid(colour));
        assert_eq!(path.stroke.width, 2.0);

        let filled = shapes(Icon::Play, rect(), colour, 2.0);
        let Shape::Path(path) = &filled[0] else {
            panic!("a play triangle is a path");
        };
        assert_eq!(path.fill, colour);

        let dotted = shapes(Icon::Alert, rect(), colour, 2.0);
        let Shape::Circle(circle) = dotted.last().expect("the exclamation's dot") else {
            panic!("an exclamation ends in a dot");
        };
        assert_eq!(circle.fill, colour);
    }

    #[test]
    fn the_stroke_weight_grows_with_the_mark_and_stays_legible() {
        // A 14-point mark in a list and a 40-point mark on a status card have to
        // be the same drawing at two scales. A weight that did not grow with the
        // size would make the big one a hairline; one that grew too fast would
        // fill the small one in.
        let small = stroke_width(14.0);
        let large = stroke_width(40.0);
        assert!((1.0..=1.5).contains(&small), "{small}");
        assert!(large > small, "{small} then {large}");
        assert!(large <= 2.4, "{large}");
        // And a size of zero, which a collapsed layout produces, is still a
        // positive weight rather than a zero one.
        assert!(stroke_width(0.0) >= 1.0);
    }

    #[test]
    fn a_closed_ring_is_one_polyline_that_ends_where_it_started() {
        // `arc` is what every curved mark is built from, and the wrap it allows
        // is what makes a ring one call. A ring that did not close would be a
        // horseshoe, which is a different mark.
        let ring = arc(Pos2::new(0.5, 0.5), 0.25, 0.0, 360.0, 16);
        assert_eq!(ring.len(), 17, "both ends of the ring are drawn");
        let (first, last) = (ring[0], ring[ring.len() - 1]);
        assert!((first - last).length() < 1e-4, "{first:?} then {last:?}");
        // Every point is on the circle.
        for point in &ring {
            let distance = (*point - Pos2::new(0.5, 0.5)).length();
            assert!(
                (distance - 0.25).abs() < 1e-4,
                "{point:?} is off the circle"
            );
        }
    }
}
