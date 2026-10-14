//! Certificate validity times, as the Unix timestamps rules compare against.
//!
//! # Why the output is a number
//!
//! A rule asks whether a certificate was issued inside a window:
//!
//! ```text
//! pe.signatures[i].not_before > 1308182400
//! ```
//!
//! That comparison is only meaningful if both sides are the same kind of thing.
//! Rendering the time as text would make the rule a string comparison, which
//! would put `"1"` after `"09"` and quietly answer the wrong question: the kind
//! of wrong answer that produces a false positive on a valid file rather than a
//! refusal, which is the failure mode worth the most care.
//!
//! # The two encodings
//!
//! X.509 carries a time in one of two forms, and which one is used is decided
//! by the year, not by the issuer:
//!
//! * `UTCTime`: `YYMMDDHHMMSSZ`, with the year as two digits. RFC 5280 §4.1.2.5.1
//!   splits it at 50: `50` to `99` is 1950 to 1999 and `00` to `49` is 2000 to
//!   2049. That boundary is the standard's, not a guess, and a parser that
//!   assumed `20YY` throughout would date every certificate from the 1990s to
//!   the year 2090.
//! * `GeneralizedTime`: `YYYYMMDDHHMMSSZ`, four digits, no ambiguity. Required
//!   from 2050 on, and already used by some CAs.
//!
//! Both are required to carry seconds and a `Z`. An offset form such as
//! `+0800` is legal in some profiles and refused here: certificates in the wild
//! do not use it, and accepting it would mean a second parsing path whose only
//! exercise is by files crafted to take it.

use crate::error::SignatureError;

/// Seconds between the Unix epoch and the start of the proleptic Gregorian
/// calendar's year 1, for the day-count arithmetic below.
const EPOCH_DAY_OFFSET: i64 = 719_468;

/// A moment, as seconds since 1970-01-01T00:00:00Z.
///
/// A newtype rather than a bare `i64` so that the two accessors on a
/// certificate cannot be swapped by accident — `not_before` and `not_after` are
/// both numbers of the same type, and a caller that transposed them would
/// compile and then answer every date question backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(pub i64);

impl UnixTime {
    /// Seconds since the epoch.
    pub fn seconds(self) -> i64 {
        self.0
    }

    /// The day this falls on, as `(year, month, day)` in UTC.
    ///
    /// The inverse of the conversion in `days_from_civil`, and present because
    /// an error message or a scan report that says `1308182400` tells a human
    /// nothing.
    pub fn civil(self) -> (i64, u32, u32) {
        // `div_euclid`, not `/`: a pre-1970 timestamp is negative, and truncating
        // division would round it the wrong way and put the date one day late.
        civil_from_days(self.0.div_euclid(86_400))
    }
}

/// Parse a `UTCTime` or `GeneralizedTime` text into a Unix timestamp.
///
/// The tag decides which form is expected, because `500101000000Z` is a valid
/// instance of both and means 1950 under one and the year 5000 under the other.
/// Passing the tag in rather than guessing from the length is what keeps that
/// unambiguous.
pub fn parse_time(tag: u8, text: &str) -> Result<UnixTime, SignatureError> {
    let bad = || SignatureError::BadTime {
        value: text.to_owned(),
    };

    let digits = text.strip_suffix('Z').ok_or_else(bad)?;
    let year = match tag {
        crate::der::UTC_TIME => {
            // Two digits, then the standard's split at 50.
            if !digits.is_ascii() {
                return Err(bad());
            }
            let yy: i64 = digits
                .get(0..2)
                .ok_or_else(bad)?
                .parse()
                .map_err(|_| bad())?;
            if yy >= 50 {
                1900 + yy
            } else {
                2000 + yy
            }
        }
        crate::der::GENERALIZED_TIME => {
            let yyyy: i64 = digits
                .get(0..4)
                .ok_or_else(bad)?
                .parse()
                .map_err(|_| bad())?;
            yyyy
        }
        _ => return Err(bad()),
    };

    let width = if tag == crate::der::UTC_TIME { 2 } else { 4 };
    let rest = digits.get(width..).ok_or_else(bad)?;
    // `YYMMDDHHMMSS` is twelve digits after the year. Seconds are mandatory:
    // RFC 5280 §4.1.2.5.1 requires them, and a form without them would have to
    // be distinguished from a truncated one.
    if rest.len() != 10 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let field = |at: usize| -> Result<i64, SignatureError> {
        rest.get(at..at + 2)
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())
    };
    let month = field(0)? as u32;
    let day = field(2)? as u32;
    let hour = field(4)?;
    let minute = field(6)?;
    let second = field(8)?;

    if !(1..=12).contains(&month) {
        return Err(bad());
    }
    if day < 1 || day > days_in_month(year, month) {
        return Err(bad());
    }
    if hour > 23 || minute > 59 || second > 60 {
        return Err(bad());
    }
    // A leap second (`:60`) is legal in the format and is folded onto the
    // following second rather than refused: it names a real instant, and
    // dropping the whole certificate over it would lose a signature that
    // Windows reads.
    let second = second.min(59);

    let days = days_from_civil(year, month, day);
    Ok(UnixTime(days * 86_400 + hour * 3600 + minute * 60 + second))
}

/// Days from 1970-01-01 to `y-m-d`, by Howard Hinnant's `days_from_civil`.
///
/// Chosen because it is branch-free in the leap-year rules and correct for
/// every proleptic Gregorian date, including the pre-1970 ones a certificate
/// with a backdated `not_before` can carry. The `m <= 2` shift moves the year
/// boundary to March so that the leap day lands at the end of the year, which
/// is what removes the special case.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64; // March = 0
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - EPOCH_DAY_OFFSET
}

/// The inverse of `days_from_civil`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + EPOCH_DAY_OFFSET;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// How many days the given month has.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Whether a Gregorian year has a leap day.
fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{GENERALIZED_TIME, UTC_TIME};

    fn utc(text: &str) -> Result<UnixTime, SignatureError> {
        parse_time(UTC_TIME, text)
    }

    fn generalized(text: &str) -> Result<UnixTime, SignatureError> {
        parse_time(GENERALIZED_TIME, text)
    }

    #[test]
    fn the_epoch_is_zero() {
        assert_eq!(utc("700101000000Z").unwrap().seconds(), 0);
    }

    #[test]
    fn a_known_timestamp_round_trips() {
        // 1308182400 is 2011-06-16T00:00:00Z, a value the corpus compares
        // against directly.
        assert_eq!(utc("110616000000Z").unwrap().seconds(), 1_308_182_400);
        assert_eq!(UnixTime(1_308_182_400).civil(), (2011, 6, 16),);
    }

    #[test]
    fn the_two_digit_year_splits_at_fifty() {
        // RFC 5280 §4.1.2.5.1: 50-99 is the 1900s, 00-49 is the 2000s. A parser
        // that assumed `20YY` would date every 1990s certificate to the 2090s.
        assert_eq!(utc("500101000000Z").unwrap().civil().0, 1950);
        assert_eq!(utc("990101000000Z").unwrap().civil().0, 1999);
        assert_eq!(utc("000101000000Z").unwrap().civil().0, 2000);
        assert_eq!(utc("490101000000Z").unwrap().civil().0, 2049);
    }

    #[test]
    fn the_same_digits_mean_different_years_under_the_two_tags() {
        // The reason the tag is a parameter rather than inferred from length:
        // the two encodings are different widths, and the leading digits that
        // mean 1950 in one mean the year 5000 in the other.
        assert_eq!(utc("500101000000Z").unwrap().civil().0, 1950);
        assert_eq!(generalized("50000101000000Z").unwrap().civil().0, 5000);

        // And the encoding's own width is enforced, so a twelve-digit string
        // cannot be read as a GeneralizedTime at all rather than being read as
        // the year 5001.
        assert!(generalized("500101000000Z").is_err());
    }

    #[test]
    fn a_leap_day_is_accepted_only_in_a_leap_year() {
        assert!(generalized("20240229120000Z").is_ok());
        assert!(generalized("20230229120000Z").is_err());
        // 2000 is a leap year (divisible by 400), 1900 is not (divisible by
        // 100 but not 400).
        assert!(generalized("20000229120000Z").is_ok());
        assert!(generalized("19000229120000Z").is_err());
    }

    #[test]
    fn the_day_count_is_right_for_dates_before_the_epoch() {
        // A backdated `not_before` is something a crafted certificate carries,
        // and the arithmetic has to stay correct on the other side of 1970.
        assert_eq!(utc("691231235959Z").unwrap().seconds(), -1);
        assert_eq!(utc("700101000000Z").unwrap().seconds(), 0);
        // 1900 is outside what a two-digit year can express — `00` is 2000 —
        // so the only way to write it is a GeneralizedTime, which is also a
        // check that the four-digit path handles a year before the epoch.
        assert_eq!(
            generalized("19000101000000Z").unwrap().seconds(),
            -2_208_988_800
        );
        assert_eq!(utc("000101000000Z").unwrap().civil().0, 2000);
    }

    #[test]
    fn the_civil_conversion_inverts_the_day_count() {
        for &(y, m, d) in &[
            (1970, 1, 1),
            (2000, 2, 29),
            (1999, 12, 31),
            (2024, 7, 4),
            (1900, 3, 1),
            (2100, 1, 1),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d));
        }
    }

    #[test]
    fn a_time_without_a_z_is_refused() {
        // An offset form would need a second parsing path, exercised only by
        // files built to take it.
        assert!(utc("110616000000+0800").is_err());
        assert!(utc("110616000000").is_err());
    }

    #[test]
    fn a_time_without_seconds_is_refused() {
        assert!(utc("1106160000Z").is_err());
        assert!(generalized("201106160000Z").is_err());
    }

    #[test]
    fn a_field_out_of_range_is_refused() {
        assert!(utc("111316000000Z").is_err()); // month 13
        assert!(utc("110632000000Z").is_err()); // 32 June
        assert!(utc("110616240000Z").is_err()); // hour 24
        assert!(utc("110616006000Z").is_err()); // minute 60
    }

    #[test]
    fn a_non_digit_is_refused_rather_than_parsed_as_zero() {
        assert!(utc("11061600x000Z").is_err());
    }

    #[test]
    fn the_wrong_tag_for_the_text_is_refused() {
        assert!(parse_time(GENERALIZED_TIME, "110616000000Z").is_err());
        assert!(parse_time(0x02, "110616000000Z").is_err());
    }
}
