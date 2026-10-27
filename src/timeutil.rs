//! Minimal, dependency-free UTC time utilities.
//!
//! All timestamps in this platform are Unix seconds (UTC). Wire format is
//! strict RFC 3339 with a mandatory `Z` (or `+00:00`) suffix. Local-time
//! offsets are rejected on purpose: every boundary in this system is
//! defined in UTC, and silently accepting non-UTC offsets would make the
//! documented expiration rule (`now >= exp` in UTC) ambiguous.
//!
//! Civil-date conversion uses Howard Hinnant's public-domain
//! `days_from_civil` / `civil_from_days` algorithms, which are exact and
//! cover the whole supported range (years 1970..=9999).

/// Days from 1970-01-01 for a proleptic Gregorian date.
/// Source: Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms".
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = ((m + 9) % 12) as i64; // Mar=0..Feb=11
    let doy = (153 * mp + 2) / 5 + (d as i64) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`].
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC, RFC 3339, no fraction).
pub fn format_rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Format Unix milliseconds as RFC 3339 with millisecond precision.
pub fn format_rfc3339_utc_ms(ms: u64) -> String {
    let secs_part = format_rfc3339_utc(ms / 1000);
    format!("{}.{:03}Z", secs_part.trim_end_matches('Z'), ms % 1000)
}

/// `YYYY-MM-DD` for the UTC day of a Unix-seconds timestamp.
pub fn format_date_utc(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Strictly parse an RFC 3339 UTC timestamp into Unix seconds.
///
/// Accepted: `YYYY-MM-DDTHH:MM:SSZ`, optional 1..3 digit fraction, and the
/// equivalent `+00:00` suffix. Anything else (other offsets, missing date
/// parts, day out of range) is rejected.
pub fn parse_rfc3339_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |from: usize, len: usize| -> Option<u64> {
        let mut v: u64 = 0;
        for &c in &b[from..from + len] {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + u64::from(c - b'0');
        }
        Some(v)
    };
    let year = num(0, 4)? as i64;
    if b[4] != b'-' {
        return None;
    }
    let month = num(5, 2)? as u32;
    if b[7] != b'-' {
        return None;
    }
    let day = num(8, 2)? as u32;
    // Separator: 'T' (strict) or space (tolerated, RFC 3339 §5.6 NOTE).
    if b[10] != b'T' && b[10] != b' ' {
        return None;
    }
    let hour = num(11, 2)?;
    if b[13] != b':' {
        return None;
    }
    let minute = num(14, 2)?;
    if b[16] != b':' {
        return None;
    }
    let second = num(17, 2)?;
    // Timezone: 'Z' or '+00:00' (both are UTC). Fraction may precede it.
    let mut idx = 19;
    if b.get(19) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        // Accept up to 9 fractional digits (nanoseconds); extra digits are
        // rejected rather than silently truncated.
        if idx == start || idx - start > 9 {
            return None;
        }
    }
    let rest = &s[idx..];
    if rest != "Z" && rest != "z" && rest != "+00:00" {
        return None;
    }
    if !(1970..=9999).contains(&year) {
        return None;
    }
    if !(1..=12).contains(&month) {
        return None;
    }
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some((days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_formats() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_date_utc(0), "1970-01-01");
    }

    #[test]
    fn leap_day_roundtrip() {
        // 2000-02-29T00:00:00Z
        let secs = days_from_civil(2000, 2, 29) * 86_400;
        assert_eq!(format_rfc3339_utc(secs as u64), "2000-02-29T00:00:00Z");
        assert_eq!(parse_rfc3339_utc("2000-02-29T00:00:00Z"), Some(secs as u64));
        // 1900 is not a leap year (divisible by 100, not 400)
        assert_eq!(days_in_month(1900, 2), 28);
        assert_eq!(days_in_month(2400, 2), 29);
    }

    #[test]
    fn parse_accepts_utc_forms_only() {
        assert_eq!(
            parse_rfc3339_utc("2026-10-27T12:00:00Z"),
            parse_rfc3339_utc("2026-10-27T12:00:00+00:00")
        );
        assert!(parse_rfc3339_utc("2026-10-27T12:00:00.500Z").is_some());
        assert!(parse_rfc3339_utc("2026-10-27 12:00:00Z").is_some()); // space separator
                                                                      // Rejected: non-UTC offset, missing fields, bad values.
        assert!(parse_rfc3339_utc("2026-10-27T12:00:00+02:00").is_none());
        assert!(parse_rfc3339_utc("2026-10-27T12:00:00").is_none());
        assert!(parse_rfc3339_utc("2026-13-01T00:00:00Z").is_none());
        assert!(parse_rfc3339_utc("2026-02-30T00:00:00Z").is_none());
        assert!(parse_rfc3339_utc("2026-10-27T24:00:00Z").is_none());
        assert!(parse_rfc3339_utc("2026-10-27T12:61:00Z").is_none());
        assert!(parse_rfc3339_utc("").is_none());
        assert!(parse_rfc3339_utc("garbage").is_none());
    }

    #[test]
    fn roundtrip_over_range() {
        for secs in [0u64, 951_782_400, 1_767_225_600, 4_102_444_800] {
            let s = format_rfc3339_utc(secs);
            assert_eq!(
                parse_rfc3339_utc(&s),
                Some(secs),
                "roundtrip failed for {secs}: {s}"
            );
        }
    }

    #[test]
    fn ms_formatting() {
        assert_eq!(format_rfc3339_utc_ms(1_000), "1970-01-01T00:00:01.000Z");
        assert_eq!(format_rfc3339_utc_ms(1_234), "1970-01-01T00:00:01.234Z");
    }
}
