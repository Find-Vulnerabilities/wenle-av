//! Bounds-checked little-endian reads.
//!
//! Every byte this crate takes out of a file comes through here. That is the
//! whole reason the type exists: a PE header is a set of offsets and sizes read
//! out of a file the scanner did not write, and the classic way a parser like
//! this goes wrong is to trust one of them. `Reader` makes trusting one
//! impossible — there is no method that returns a value without saying whether
//! the bytes for it were there.
//!
//! # What is deliberately missing
//!
//! There is no `read_u32_unchecked`, no indexing operator and no conversion to
//! a slice. A caller that wants a field gets a `Result`, and the `?` that
//! follows is the audit trail for every one of them.

use crate::error::PeError;

/// A cursor over a buffer that refuses to read past the end.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// How many bytes are readable.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether there is nothing to read.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The whole buffer, for the few places that need to hash it.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// `len` bytes at `offset`, or [`PeError::Truncated`].
    ///
    /// `offset + len` is computed with `checked_add` rather than `+`: both come
    /// from the file in the resource and import paths, and a crafted pair that
    /// wraps would otherwise yield a slice of the *front* of the buffer — data
    /// the caller never asked for and the file never pointed at.
    pub fn slice(&self, offset: usize, len: usize) -> Result<&'a [u8], PeError> {
        let end = offset.checked_add(len).ok_or(PeError::Truncated {
            offset,
            wanted: len,
            available: self.data.len(),
        })?;
        self.data.get(offset..end).ok_or(PeError::Truncated {
            offset,
            wanted: len,
            available: self.data.len(),
        })
    }

    /// `count` items of `stride` bytes at `offset`, requiring all of them.
    ///
    /// The multiplication is checked, because `count` is a field out of the file
    /// and `usize::MAX / 2 * 2` is not a length any buffer has.
    pub fn array(&self, offset: usize, count: u64, stride: u64) -> Result<&'a [u8], PeError> {
        let len = count
            .checked_mul(stride)
            .ok_or(PeError::CountOverflow { count, stride })?;
        let len = usize::try_from(len).map_err(|_| PeError::CountOverflow { count, stride })?;
        self.slice(offset, len)
    }

    /// The `index`-th item of an array of `stride` bytes, requiring only it.
    ///
    /// Unlike [`Reader::array`] this does not demand that every *other* item is
    /// present. That matters for the section table, where a file with a
    /// plausible `NumberOfSections` but a short table should still yield the
    /// sections it does have rather than none — and where requiring all of them
    /// would be a way to make the scanner report nothing for a whole file.
    pub fn item(&self, offset: usize, index: u64, stride: u64) -> Result<&'a [u8], PeError> {
        let at = index.checked_mul(stride).ok_or(PeError::CountOverflow {
            count: index,
            stride,
        })?;
        let at = usize::try_from(at).map_err(|_| PeError::CountOverflow {
            count: index,
            stride,
        })?;
        let start = offset.checked_add(at).ok_or(PeError::Truncated {
            offset,
            wanted: stride as usize,
            available: self.data.len(),
        })?;
        self.slice(start, stride as usize)
    }

    /// One byte at `offset`.
    pub fn u8(&self, offset: usize) -> Result<u8, PeError> {
        Ok(self.slice(offset, 1)?[0])
    }

    /// A little-endian `u16` at `offset`.
    pub fn u16(&self, offset: usize) -> Result<u16, PeError> {
        let b = self.slice(offset, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// A little-endian `u32` at `offset`.
    pub fn u32(&self, offset: usize) -> Result<u32, PeError> {
        let b = self.slice(offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A little-endian `u64` at `offset`.
    pub fn u64(&self, offset: usize) -> Result<u64, PeError> {
        let b = self.slice(offset, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A NUL-terminated string at `offset`, read within `limit` bytes.
    ///
    /// The returned slice excludes the terminator. `limit` is a hard bound on
    /// the search as well as the read: a fixed-size field like a section name
    /// has no terminator of its own, and a file whose whole 8 bytes are
    /// non-zero must not make this scan to the end of the buffer looking for
    /// one that belongs to something else.
    pub fn cstr(&self, offset: usize, limit: usize) -> Result<&'a [u8], PeError> {
        let window = self.slice(offset, limit)?;
        Ok(match window.iter().position(|&b| b == 0) {
            Some(end) => &window[..end],
            None => window,
        })
    }

    /// A string at `offset` that must have a NUL inside `limit` bytes.
    ///
    /// For the places where the format says the string is terminated — a
    /// resource's name, a version-info key — and where running to the end of
    /// the window means the file is malformed rather than that the name filled
    /// its field.
    pub fn cstr_required(&self, offset: usize, limit: usize) -> Result<&'a [u8], PeError> {
        let window = self.slice(offset, limit)?;
        window
            .iter()
            .position(|&b| b == 0)
            .map(|end| &window[..end])
            .ok_or(PeError::UnterminatedString { offset, limit })
    }

    /// A UTF-16LE string at `offset`, terminated by a NUL code unit.
    ///
    /// Windows' own strings — the version resource, the manifest — are UTF-16,
    /// and every one of them reaches a rule as a string comparison.
    pub fn utf16(&self, offset: usize, limit_code_units: usize) -> Result<String, PeError> {
        let limit = limit_code_units
            .checked_mul(2)
            .ok_or(PeError::CountOverflow {
                count: limit_code_units as u64,
                stride: 2,
            })?;
        let window = self.slice(offset, limit)?;
        let mut units = Vec::new();
        for pair in window.chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_little_endian() {
        let r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(r.u8(0).unwrap(), 0x01);
        assert_eq!(r.u16(0).unwrap(), 0x0201);
        assert_eq!(r.u32(0).unwrap(), 0x04030201);
        assert_eq!(r.u64(0).unwrap(), 0x0807060504030201);
    }

    #[test]
    fn a_read_past_the_end_is_an_error_and_not_a_panic() {
        let r = Reader::new(&[0x01, 0x02]);
        assert!(matches!(
            r.u32(0),
            Err(PeError::Truncated {
                offset: 0,
                wanted: 4,
                available: 2
            })
        ));
        assert!(r.u32(1).is_err());
        assert!(r.u8(2).is_err());
        assert!(r.slice(0, 3).is_err());
    }

    #[test]
    fn an_offset_that_would_wrap_is_refused_rather_than_wrapped() {
        // `offset + len` overflowing would put the window at the *front* of the
        // buffer under a wrapping add — bytes the file never pointed at.
        let r = Reader::new(&[0xAA; 16]);
        assert!(matches!(
            r.slice(usize::MAX, 16),
            Err(PeError::Truncated { .. })
        ));
        assert!(matches!(
            r.slice(usize::MAX - 8, 16),
            Err(PeError::Truncated { .. })
        ));
    }

    #[test]
    fn an_array_whose_size_overflows_is_refused() {
        let r = Reader::new(&[0u8; 64]);
        assert!(matches!(
            r.array(0, u64::MAX, 4),
            Err(PeError::CountOverflow { .. })
        ));
        assert!(matches!(
            r.item(0, u64::MAX, 40),
            Err(PeError::CountOverflow { .. })
        ));
    }

    #[test]
    fn an_item_does_not_require_its_neighbours() {
        // The section table relies on this: a file claiming more sections than
        // it has must still yield the ones that are there.
        let r = Reader::new(&[0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02]);
        assert_eq!(r.item(0, 0, 2).unwrap(), &[0xAA, 0xBB]);
        assert_eq!(r.item(0, 2, 2).unwrap(), &[0x01, 0x02]);
        // The fourth is past the end even though the buffer is not empty.
        assert!(r.item(0, 3, 2).is_err());
        // Whereas `array` would have refused all of it up front.
        assert!(r.array(0, 4, 2).is_err());
    }

    #[test]
    fn a_terminated_string_stops_at_its_terminator() {
        let r = Reader::new(b".text\0\0\0.data\0\0\0");
        assert_eq!(r.cstr(0, 8).unwrap(), b".text");
        assert_eq!(r.cstr(8, 8).unwrap(), b".data");
    }

    #[test]
    fn an_unterminated_string_fills_its_whole_window() {
        // A section name is exactly eight bytes and has no terminator of its
        // own when it is full. Scanning past the window would find the NUL that
        // belongs to the *next* field and report a name that is too short.
        let r = Reader::new(b"12345678\0data\0");
        assert_eq!(r.cstr(0, 8).unwrap(), b"12345678");
        // The strict form is for the places the format promises a terminator.
        assert!(matches!(
            r.cstr_required(0, 8),
            Err(PeError::UnterminatedString { limit: 8, .. })
        ));
        assert_eq!(r.cstr_required(9, 5).unwrap(), b"data");
        // And its limit is a hard bound: the terminator one byte past the window
        // is not found, because finding it would mean the name this returns runs
        // into whatever the file put next.
        assert!(matches!(
            r.cstr_required(9, 4),
            Err(PeError::UnterminatedString {
                offset: 9,
                limit: 4
            })
        ));
    }

    #[test]
    fn utf16_stops_at_a_nul_code_unit() {
        let mut data = Vec::new();
        for unit in "Hi!".encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
        for unit in "no".encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        let r = Reader::new(&data);
        assert_eq!(
            r.utf16(0, 4).unwrap(),
            "Hi!",
            "four code units: `Hi!` and a NUL"
        );
        // The limit is a window, not a promise that the string ends inside it.
        // A window that stops short of the terminator still yields the text it
        // holds, which is the reading that cannot lose a rule's string.
        assert_eq!(r.utf16(0, 2).unwrap(), "Hi");
        assert!(
            r.utf16(0, 64).is_err(),
            "a window past the end is not a read"
        );
    }

    #[test]
    fn utf16_that_is_not_valid_text_is_still_returned() {
        // A lone surrogate becomes the replacement character rather than an
        // error: the file is malformed but the rule that reads this string
        // should still see something, and refusing would turn a bad string into
        // a missing detection for the whole rule.
        let r = Reader::new(&[0x00, 0xD8, 0x00, 0x00]);
        assert_eq!(r.utf16(0, 2).unwrap(), "\u{FFFD}");
    }
}
