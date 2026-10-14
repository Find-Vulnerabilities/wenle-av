//! The resource directory: icons, manifests, version information and whatever
//! else an image carries for the operating system to load.
//!
//! # Why a scanner cares
//!
//! The resource directory is the one part of a PE that is *for* data rather than
//! for code, and it is the only part a loader hands to the system as an opaque
//! blob. That makes it the first place a dropper puts its payload and the first
//! place a packer looks for somewhere to hide one. The corpus asks about it in
//! the two shapes that follow from that: an embedded executable
//! (`uint16(pe.resources[i].offset) == 0x5A4D`) and an encrypted blob
//! (`math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7`).
//!
//! # The shape of the tree
//!
//! Three levels, each a directory of entries, each entry either the next level's
//! directory or a leaf:
//!
//! ```text
//! Type   ── Name ── Language ── IMAGE_RESOURCE_DATA_ENTRY
//!  │          │         │
//!  │          │         └─ usually an id: 1033 for en-US
//!  │          └─ an id, or a name such as "RC2CL"
//!  └─ usually an id: 10 for RCDATA, 16 for VERSION
//! ```
//!
//! Every level carries *either* an integer id or a name, and one bit of the
//! entry says which: the field is an offset to a name when its high bit is set,
//! and an id when it is not. The two are not interchangeable — `10` and `"10"`
//! are different resource types — so a level is reported as `None` for whichever
//! of the two it does not have, rather than as a guess.
//!
//! # Offsets, and the two meanings of one
//!
//! Both directory entries and data entries hold offsets, and they are measured
//! from **different places**:
//!
//! - A directory entry's offset is relative to the **start of the whole resource
//!   directory**, and its high bit says whether it points at a subdirectory or
//!   at a data entry. A level-3 entry nested two directories deep is still
//!   measured from the root, which is what a reader that recursed carrying "the
//!   current directory's offset" gets wrong.
//! - A data entry's `OffsetToData` is an **RVA**, so it goes through the section
//!   table like any other address. [`Resource::rva`] is that value and
//!   [`Resource::offset`] is the file offset it maps to — the one the corpus
//!   reads, in `uint16(pe.resources[i].offset) == 0x5A4D`.
//!
//! # What a hostile file can do
//!
//! Every level is a count and a set of offsets read out of the file, so a
//! three-level tree with two levels of fan-out is a structure whose size is the
//! *cube* of what the file declares: two entries per directory reaches eight
//! leaves, sixty-five thousand reaches `2.8e14`. The walk therefore counts the
//! entries it examines against a budget rather than trusting any level's count,
//! and stops when the budget is gone. The tree it walks is the tree the file
//! has; the budget is what keeps walking it from being unbounded work.

use crate::headers::directory;
use crate::pe::PeFile;

/// Size of `IMAGE_RESOURCE_DIRECTORY`.
const DIRECTORY_HEADER_LEN: usize = 16;

/// Size of one `IMAGE_RESOURCE_DIRECTORY_ENTRY`.
const ENTRY_LEN: usize = 8;

/// Size of `IMAGE_RESOURCE_DATA_ENTRY`.
const DATA_ENTRY_LEN: usize = 16;

/// Set in an entry's name field when it is an offset to a name, clear when it is
/// an id.
const NAME_IS_STRING: u32 = 0x8000_0000;

/// Set in an entry's offset field when it points at a subdirectory, clear when
/// it points at a data entry.
const OFFSET_IS_DIRECTORY: u32 = 0x8000_0000;

/// How deep the tree is allowed to be: type, name, language.
const MAX_DEPTH: usize = 3;

/// The most directory entries the walk will examine, across the whole tree.
///
/// The bound is on entries examined rather than on leaves produced, because the
/// work is in the examining: a file can declare two directories of sixty-five
/// thousand entries each and produce no leaves at all, and a bound on the output
/// would not notice. Sixty-five thousand is far past any real image — a busy one
/// has a few hundred resources, so a few thousand entries — and it caps the walk
/// at a few hundred thousand bounds-checked reads whatever the file claims.
const MAX_ENTRIES_WALKED: usize = 65_536;

/// The most leaves that will be reported.
///
/// Separate from the budget above because the corpus's loops index this array
/// and a rule writes `for any i in (0 .. pe.number_of_resources - 1)`. Eight
/// thousand resources is past any real file and still keeps the array a rule can
/// walk to a size worth walking.
const MAX_RESOURCES: usize = 8192;

/// The longest resource name that will be read, in UTF-16 code units.
///
/// Real names are a handful of characters. The bound is what stops a name offset
/// aimed into a region of large values from producing a length that is then used
/// to slice the buffer.
const MAX_NAME_CHARS: usize = 512;

/// One resource: a leaf of the tree, and the path that reached it.
///
/// Borrows the names from the file's own bytes rather than owning them, for the
/// same reason [`crate::imports::Import`] does: a scan walks this array for a
/// rule, and most rules look at none of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resource<'a> {
    /// Where the resource's bytes are, as a file offset.
    ///
    /// A file offset and not an RVA, which the corpus depends on: the rule at
    /// line 289079 reads `uint16(pe.resources[i].offset) == 0x5A4D` to find a
    /// second executable embedded in the first.
    pub offset: u64,
    /// How many bytes the data entry says the resource is.
    ///
    /// As declared, and not clamped to what is left in the buffer. A rule
    /// computing `math.entropy(offset, length)` over a length that runs past the
    /// end gets a shorter region — `av_core::region` clamps — but a rule
    /// comparing the length itself is comparing the number the file wrote.
    pub length: u64,
    /// The RVA the data entry holds, before it was mapped through the sections.
    pub rva: u32,
    /// The type id, when the type level is an id rather than a name.
    pub type_id: Option<u32>,
    /// The name id, when the name level is an id rather than a name.
    pub id: Option<u32>,
    /// The language id, when the language level is an id rather than a name.
    pub language: Option<u32>,
    /// The type level's name, as raw UTF-16LE with no terminator.
    pub type_string: Option<&'a [u8]>,
    /// The name level's name, as raw UTF-16LE with no terminator.
    pub name_string: Option<&'a [u8]>,
    /// The language level's name, as raw UTF-16LE with no terminator.
    pub language_string: Option<&'a [u8]>,
}

/// Every leaf of a file's resource tree, in the order the tree lists them.
///
/// Empty for a file with no resource directory, which is most executables that
/// are not installers or droppers. Not an error: about a file with no resources,
/// the honest answer to every resource question is "none".
#[derive(Debug, Clone, Default)]
pub struct Resources<'a> {
    leaves: Vec<Resource<'a>>,
}

impl<'a> Resources<'a> {
    /// The leaves, in the tree's own order.
    pub fn leaves(&self) -> &[Resource<'a>] {
        &self.leaves
    }

    /// How many leaves there are — what `pe.number_of_resources` answers.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

/// Read a file's resource tree.
///
/// A file with no resource directory, or with one that points nowhere, yields an
/// empty set rather than an error — the same choice [`crate::exports::read`]
/// makes, and for the same reason: for most files the empty answer is the
/// ordinary one.
pub fn read<'a>(pe: &PeFile<'a>) -> Resources<'a> {
    let mut resources = Resources::default();
    let entry = pe.data_directory(directory::RESOURCE);
    if !entry.is_present() {
        return resources;
    }
    let base = entry.virtual_address;
    // The header has to be there before the walk starts. Everything below reads
    // through the reader and would fail anyway; failing once here is what says
    // why.
    let Ok(at) = usize::try_from(pe.rva_to_offset(base)) else {
        return resources;
    };
    if pe.reader().slice(at, DIRECTORY_HEADER_LEN).is_err() {
        return resources;
    }

    let mut budget = MAX_ENTRIES_WALKED;
    let mut path: [Level; MAX_DEPTH] = [Level::default(); MAX_DEPTH];
    walk(pe, base, base, 0, &mut path, &mut budget, &mut resources);
    resources
}

/// What one level of the path resolved to.
#[derive(Debug, Clone, Copy, Default)]
struct Level {
    id: Option<u32>,
    /// Where the name's bytes are, and how many.
    name: Option<(usize, usize)>,
}

/// Walk one directory and everything below it.
///
/// `base_rva` is the root of the whole resource directory and `dir_rva` is the
/// directory being read. They differ at every level below the first, and keeping
/// both is what makes the offsets come out right: every offset in every entry is
/// measured from `base_rva`, while the entries themselves are found at
/// `dir_rva`.
fn walk<'a>(
    pe: &PeFile<'a>,
    base_rva: u32,
    dir_rva: u32,
    depth: usize,
    path: &mut [Level; MAX_DEPTH],
    budget: &mut usize,
    out: &mut Resources<'a>,
) {
    if depth >= MAX_DEPTH || out.leaves.len() >= MAX_RESOURCES {
        return;
    }
    let Some(dir_at) = file_offset(pe, dir_rva) else {
        return;
    };
    let reader = pe.reader();
    let (Ok(named), Ok(by_id)) = (reader.u16(dir_at + 12), reader.u16(dir_at + 14)) else {
        return;
    };
    let count = named as usize + by_id as usize;
    let first = dir_at + DIRECTORY_HEADER_LEN;
    // The whole entries array has to be present before it is walked, so that a
    // directory claiming an entry off the end of the file stops here rather than
    // reading whatever lies past the mapping.
    if reader.array(first, count as u64, ENTRY_LEN as u64).is_err() {
        return;
    }

    for index in 0..count {
        if *budget == 0 || out.leaves.len() >= MAX_RESOURCES {
            return;
        }
        *budget -= 1;
        let at = first + index * ENTRY_LEN;
        let (Ok(name), Ok(offset)) = (reader.u32(at), reader.u32(at + 4)) else {
            return;
        };

        path[depth] = Level::default();
        if name & NAME_IS_STRING != 0 {
            path[depth].name = name_string(pe, base_rva, name & !NAME_IS_STRING);
        } else {
            path[depth].id = Some(name);
        }

        let target = base_rva.wrapping_add(offset & !OFFSET_IS_DIRECTORY);
        if offset & OFFSET_IS_DIRECTORY == 0 {
            // A data entry, which the format puts at the third level — but a
            // file can put one at any level, and the levels it skipped are
            // reported as absent rather than invented.
            if let Some(found) = leaf(pe, &path[..=depth], target) {
                out.leaves.push(found);
            }
        } else {
            walk(pe, base_rva, target, depth + 1, path, budget, out);
        }
    }
}

/// Build the leaf a data entry at `rva` describes, with the path that reached
/// it.
///
/// `path` holds one level per directory the walk descended through, so it is
/// shorter than three when a data entry sits above the third level. The levels
/// it does not reach are absent from the leaf, which is what the file says about
/// them.
fn leaf<'a>(pe: &PeFile<'a>, path: &[Level], rva: u32) -> Option<Resource<'a>> {
    let at = file_offset(pe, rva)?;
    let reader = pe.reader();
    if reader.slice(at, DATA_ENTRY_LEN).is_err() {
        return None;
    }
    let data_rva = reader.u32(at).ok()?;
    let length = u64::from(reader.u32(at + 4).ok()?);
    let level = |index: usize| path.get(index).copied().unwrap_or_default();

    Some(Resource {
        // The file offset, not the RVA. See `Resource::offset`.
        offset: pe.rva_to_offset(data_rva),
        length,
        rva: data_rva,
        type_id: level(0).id,
        id: level(1).id,
        language: level(2).id,
        type_string: borrow(pe, level(0).name),
        name_string: borrow(pe, level(1).name),
        language_string: borrow(pe, level(2).name),
    })
}

/// The bytes of a name, as stored.
fn borrow<'a>(pe: &PeFile<'a>, span: Option<(usize, usize)>) -> Option<&'a [u8]> {
    let (at, len) = span?;
    pe.reader().slice(at, len).ok()
}

/// A name entry's string, as raw UTF-16LE with no terminator, and where it is.
///
/// The entry is a `u16` count of code units followed by that many of them, and
/// the count is the whole of the length — there is no terminator, which the
/// corpus confirms twice: a four-character name is eight bytes
/// (`string.length(pe.resources[i].name_string) == 8`) and the regex written
/// against one is `[0-9]\x00[0-9]\x00[0-9]\x00[0-9]\x00`, exactly eight.
///
/// The bytes are returned rather than a `String` because they are not text: a
/// name is a sequence of UTF-16 code units chosen by whoever built the file, and
/// a rule compares it against a literal with `\x00` escapes precisely because it
/// is not UTF-8. Converting here would make every such comparison fail.
fn name_string(pe: &PeFile<'_>, base_rva: u32, offset: u32) -> Option<(usize, usize)> {
    let at = file_offset(pe, base_rva.wrapping_add(offset))?;
    let reader = pe.reader();
    let chars = reader.u16(at).ok()? as usize;
    if chars == 0 || chars > MAX_NAME_CHARS {
        return None;
    }
    let len = chars.checked_mul(2)?;
    // The whole name has to be present. A count running past the end of the file
    // is a name that is not there, and a shortened one would compare as a
    // *different* name rather than as no name.
    reader.slice(at + 2, len).ok()?;
    Some((at + 2, len))
}

/// The file offset an RVA maps to, or `None` when it is not a usable offset.
fn file_offset(pe: &PeFile<'_>, rva: u32) -> Option<usize> {
    usize::try_from(pe.rva_to_offset(rva)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{add_resources, minimal_pe32, LevelSpec, ResourceSpec};
    use crate::PeFile;

    /// A resource name as a test writes it: UTF-16LE, as the file stores it.
    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn a_file_with_no_resource_directory_has_no_resources() {
        let image = minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        let resources = read(&pe);
        assert!(resources.is_empty());
        assert_eq!(resources.len(), 0);
        assert!(resources.leaves().is_empty());
    }

    #[test]
    fn a_leaf_carries_its_type_its_name_and_its_language() {
        let mut image = minimal_pe32();
        add_resources(
            &mut image,
            &[ResourceSpec::new(10u32, "RC2CL", &[1033u32], b"payload")],
        );
        let pe = PeFile::parse(&image).unwrap();
        let resources = read(&pe);
        assert_eq!(resources.len(), 1);
        let found = resources.leaves()[0];
        assert_eq!(found.type_id, Some(10));
        assert_eq!(found.type_string, None, "the type level is an id");
        assert_eq!(found.id, None, "and the name level is a name");
        assert_eq!(found.name_string, Some(utf16("RC2CL").as_slice()));
        assert_eq!(found.language, Some(1033));
        assert_eq!(found.length, 7);
        // The corpus's own test for where `offset` points: the bytes are there.
        assert_eq!(pe.data()[found.offset as usize..][..7], *b"payload");
    }

    #[test]
    fn a_name_is_the_raw_utf16_bytes_with_no_terminator() {
        // The two corpus readings this pins: a four-character name is eight
        // bytes, and the regex written against it is four `[0-9]\x00` pairs.
        let mut image = minimal_pe32();
        add_resources(
            &mut image,
            &[ResourceSpec::new(10u32, "1000", &[1033u32], b"x")],
        );
        let pe = PeFile::parse(&image).unwrap();
        let found = read(&pe).leaves()[0];
        let name = found.name_string.expect("the fixture names the resource");
        assert_eq!(name.len(), 8, "four code units, two bytes each");
        assert_eq!(name, b"1\x000\x000\x000\x00");
        assert!(!name.ends_with(&[0, 0]), "and no terminator");
    }

    #[test]
    fn a_named_type_and_a_named_language_are_reported_as_names_not_ids() {
        // Both shapes the format allows, in one fixture: a type that is a name
        // rather than `RT_RCDATA`'s 10, and a language that is a name rather
        // than 1033. The ids are `None` because there is no id — not zero, which
        // would be a type this file does not have.
        let mut image = minimal_pe32();
        add_resources(
            &mut image,
            &[ResourceSpec::new("BIN", "DATA", &["en-US"], b"z")],
        );
        let pe = PeFile::parse(&image).unwrap();
        let found = read(&pe).leaves()[0];
        assert_eq!(found.type_id, None);
        assert_eq!(found.type_string, Some(utf16("BIN").as_slice()));
        assert_eq!(found.id, None);
        assert_eq!(found.name_string, Some(utf16("DATA").as_slice()));
        assert_eq!(found.language, None);
        assert_eq!(found.language_string, Some(utf16("en-US").as_slice()));
    }

    #[test]
    fn an_id_and_a_name_at_the_same_level_are_different_resources() {
        // `10` and `"10"` are not the same type. A reader that decoded a name
        // into an id, or an id into a name, would report one leaf where the file
        // has two — and would answer the other one's questions with it.
        let mut image = minimal_pe32();
        add_resources(
            &mut image,
            &[
                ResourceSpec::new(10u32, "100", &[1033u32], b"aaa"),
                ResourceSpec::new(0x100u32, "100", &[1033u32], b"bbb"),
            ],
        );
        let pe = PeFile::parse(&image).unwrap();
        let resources = read(&pe);
        assert_eq!(resources.len(), 2);
        let name = utf16("100");
        assert_eq!(resources.leaves()[0].type_id, Some(10));
        assert_eq!(resources.leaves()[0].name_string, Some(name.as_slice()));
        assert_eq!(resources.leaves()[1].type_id, Some(0x100));
        assert_eq!(resources.leaves()[1].name_string, Some(name.as_slice()));
        assert_eq!(
            pe.data()[resources.leaves()[0].offset as usize..][..3],
            *b"aaa"
        );
        assert_eq!(
            pe.data()[resources.leaves()[1].offset as usize..][..3],
            *b"bbb"
        );
    }

    #[test]
    fn every_language_of_one_name_becomes_its_own_leaf() {
        // The tree's fan-out at the last level. A file with one icon in five
        // languages has five leaves, and a rule that counts resources counts
        // five.
        let mut image = minimal_pe32();
        add_resources(
            &mut image,
            &[ResourceSpec::new(
                3u32,
                "ICON",
                &[1033u32, 1031, 1036, 1041, 2052],
                b"icon",
            )],
        );
        let pe = PeFile::parse(&image).unwrap();
        let resources = read(&pe);
        assert_eq!(resources.len(), 5);
        let languages: Vec<_> = resources.leaves().iter().map(|r| r.language).collect();
        assert_eq!(
            languages,
            vec![Some(1033), Some(1031), Some(1036), Some(1041), Some(2052)]
        );
    }

    #[test]
    fn the_offset_is_a_file_offset_and_the_rva_is_the_one_the_entry_holds() {
        // The distinction the corpus turns on. The fixture keeps its resources
        // in `.data`, where the section table maps one to the other, so the two
        // readings *disagree*: a reader that reported the RVA under the name
        // `offset` fails here, and a fixture whose resources sat past the last
        // section — where an unmapped RVA is returned unchanged and the two
        // coincide — would not notice.
        let mut image = minimal_pe32();
        add_resources(
            &mut image,
            &[ResourceSpec::new(10u32, 0u32, &[0u32], b"MARKER")],
        );
        let pe = PeFile::parse(&image).unwrap();
        let found = read(&pe).leaves()[0];
        assert_eq!(pe.data()[found.offset as usize..][..6], *b"MARKER");
        assert_ne!(
            found.offset,
            u64::from(found.rva),
            "the fixture is built so that the two cannot be confused"
        );
        // And the RVA really is the one the entry holds: mapping it back gives
        // the offset again.
        assert_eq!(pe.rva_to_offset(found.rva), found.offset);
    }

    #[test]
    fn a_data_entry_whose_bytes_run_off_the_end_is_still_reported() {
        // `length` is the number the file wrote, and the reader does not clamp
        // it: a rule comparing the length is comparing the file's claim, while
        // one reading the bytes gets the part that is there through
        // `av_core::region`. Shortening the number here would answer two
        // different questions with one value.
        let mut image = minimal_pe32();
        add_resources(
            &mut image,
            &[ResourceSpec::new(10u32, 0u32, &[0u32], b"short").with_length(0x1000)],
        );
        let pe = PeFile::parse(&image).unwrap();
        let found = read(&pe).leaves()[0];
        assert_eq!(found.length, 0x1000);
        assert_eq!(pe.data()[found.offset as usize..][..5], *b"short");
    }

    #[test]
    fn a_directory_claiming_entries_past_the_end_of_the_file_stops_the_walk() {
        // The counts are `u16`s the file chose, and they index into the file. A
        // directory claiming sixty-five thousand entries in a fixture with room
        // for two must yield nothing, not read past the mapping.
        let mut image = minimal_pe32();
        let layout = add_resources(
            &mut image,
            &[
                ResourceSpec::new(10u32, 0u32, &[1033u32], b"one"),
                ResourceSpec::new(11u32, 0u32, &[1033u32], b"two"),
            ],
        );
        let pe = PeFile::parse(&image).unwrap();
        assert_eq!(read(&pe).len(), 2);

        let base = layout.directory;
        image[base + 12..base + 14].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let pe = PeFile::parse(&image).unwrap();
        assert!(
            read(&pe).is_empty(),
            "an entries array that is not all there cannot be walked"
        );
    }

    #[test]
    fn a_resource_directory_that_points_nowhere_yields_nothing() {
        // A present directory entry whose RVA is in no section. A reader that
        // treated the returned RVA as a file offset would read whatever is at
        // that offset instead of reporting nothing.
        let mut image = minimal_pe32();
        let opt = 0x80 + 4 + 20;
        let rsrc = opt + 96 + directory::RESOURCE * 8;
        image[rsrc..rsrc + 4].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        image[rsrc + 4..rsrc + 8].copy_from_slice(&0x100u32.to_le_bytes());
        let pe = PeFile::parse(&image).unwrap();
        assert!(read(&pe).is_empty());
    }

    #[test]
    fn a_subdirectory_below_the_last_level_is_not_followed() {
        // The format defines three levels. A file that points a *third*-level
        // entry at a subdirectory is asking to be walked four deep, and the
        // depth limit refuses — which is the difference between walking the tree
        // the format has and walking one the file invented.
        let mut image = minimal_pe32();
        let layout = add_resources(
            &mut image,
            &[ResourceSpec::new(10u32, 0u32, &[1033u32], b"leaf")],
        );
        let pe = PeFile::parse(&image).unwrap();
        assert_eq!(read(&pe).len(), 1);

        // Flip the third-level entry's offset from a data entry to a
        // subdirectory, so the last level is a directory pointing at whatever
        // follows. The walk has to stop rather than descend into it.
        let at = layout.language_entries[0];
        let offset = u32::from_le_bytes(image[at + 4..at + 8].try_into().unwrap());
        assert_eq!(
            offset & OFFSET_IS_DIRECTORY,
            0,
            "a data entry, to begin with"
        );
        image[at + 4..at + 8].copy_from_slice(&(offset | OFFSET_IS_DIRECTORY).to_le_bytes());

        let pe = PeFile::parse(&image).unwrap();
        assert!(read(&pe).is_empty());
        assert_eq!(MAX_DEPTH, 3, "three levels, and no more");
    }

    #[test]
    fn a_name_longer_than_any_real_one_is_refused_rather_than_read() {
        // A name offset aimed at a region of large values produces a `u16` count
        // that would slice far past the name. The bound is what stops a length
        // the file chose from being used as a length.
        let mut image = minimal_pe32();
        add_resources(
            &mut image,
            &[ResourceSpec::new(10u32, "NAME", &[1033u32], b"x")],
        );
        let pe = PeFile::parse(&image).unwrap();
        let found = read(&pe).leaves()[0];
        let name = found.name_string.unwrap();
        let name_at = name.as_ptr() as usize - pe.data().as_ptr() as usize;

        // The count sits in the two bytes before the name.
        image[name_at - 2..name_at].copy_from_slice(&(MAX_NAME_CHARS as u16 + 1).to_le_bytes());
        let pe = PeFile::parse(&image).unwrap();
        let found = read(&pe).leaves()[0];
        assert_eq!(found.name_string, None);
        assert_eq!(found.type_id, Some(10), "the rest of the leaf is read");
    }

    #[test]
    fn a_level_a_file_leaves_empty_is_absent_rather_than_zero() {
        // `LevelSpec::Id(0)` writes an id of zero, which is a real id — the
        // lowest one — and not the same as a level the file did not fill in.
        // Reporting `Some(0)` for an absent level would have a rule asking for
        // language 0 match every unnamed resource.
        let mut image = minimal_pe32();
        add_resources(&mut image, &[ResourceSpec::new(10u32, 0u32, &[0u32], b"z")]);
        let pe = PeFile::parse(&image).unwrap();
        let found = read(&pe).leaves()[0];
        assert_eq!(found.id, Some(0));
        assert_eq!(found.language, Some(0));
        assert_eq!(found.type_string, None);
        assert_eq!(found.name_string, None);
        assert_eq!(found.language_string, None);
    }

    /// The fixture's own conversion, checked because a name and an id that
    /// compared equal would merge two resources into one and no reader test
    /// could see it.
    #[test]
    fn a_name_and_an_id_are_never_equal() {
        assert_ne!(LevelSpec::Id(10), LevelSpec::Name("10"));
        assert_ne!(LevelSpec::Name("a"), LevelSpec::Name("b"));
        assert_eq!(LevelSpec::Name("a"), LevelSpec::Name("a"));
    }
}
