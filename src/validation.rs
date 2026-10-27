//! Input validation for every externally-supplied value.
//!
//! All identifiers used in routes are validated against a conservative
//! charset BEFORE any storage access, which removes path traversal,
//! glob-injection (users cannot smuggle `*` into Edge Storage scan
//! patterns through a user id), and header-injection classes. JSON
//! bodies are additionally size-capped and rejected on unknown fields.

use crate::errors::FieldError;

pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_EMAIL_LEN: usize = 253;
pub const MAX_NAME_LEN: usize = 128;

/// Route-safe identifier: `[A-Za-z0-9_-]{1,128}`. No dots, no slashes,
/// no glob metacharacters — safe to interpolate into storage keys.
pub fn is_route_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// ULID-style record id with a single lowercase-letter prefix.
pub fn is_record_id(s: &str, prefix: char) -> bool {
    let body = match s.strip_prefix(prefix) {
        Some(b) => b,
        None => return false,
    };
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    body.len() == 26 && body.bytes().all(|c| CROCKFORD.contains(&c))
}

/// Admin usernames: lowercase, conservative.
pub fn is_username(s: &str) -> bool {
    (3..=32).contains(&s.len())
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-' || c == b'.'
        })
        && s.bytes()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// RFC-lite email validation + normalization (lowercase, trim).
/// Rejects control characters and CR/LF anywhere (header/log safety).
pub fn normalize_email(raw: &str) -> Result<String, &'static str> {
    let s = raw.trim();
    if s.len() > MAX_EMAIL_LEN || s.is_empty() {
        return Err("email must be between 1 and 253 characters");
    }
    if s.bytes().any(|c| c < 0x20 || c == 0x7f) {
        return Err("email contains invalid characters");
    }
    let lower = s.to_lowercase();
    let (local, domain) = lower
        .rsplit_once('@')
        .ok_or("email must contain exactly one '@'")?;
    if lower.matches('@').count() != 1 || local.is_empty() || domain.is_empty() {
        return Err("email must contain exactly one '@'");
    }
    if local.len() > 64 {
        return Err("email local part is too long");
    }
    if !local.bytes().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || b"!#$%&'*+/=?^_`{|}~.-".contains(&c)
    }) {
        return Err("email local part contains invalid characters");
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err("email local part has invalid dot placement");
    }
    if !domain.contains('.') {
        return Err("email domain must contain at least one dot");
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("email domain has invalid labels");
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err("email domain contains invalid characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("email domain labels cannot start or end with a hyphen");
        }
    }
    Ok(lower)
}

/// Display names: printable, no control characters, no CR/LF.
pub fn is_display_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_NAME_LEN && !s.chars().any(|c| c.is_control())
}

/// Free-text admin metadata: bounded and control-character-free.
pub fn sanitize_text(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Rejects strings that could smuggle CR/LF into headers or logs.
pub fn has_crlf(s: &str) -> bool {
    s.bytes().any(|c| c == b'\r' || c == b'\n')
}

/// Validate a UTC expiration timestamp and enforce a future lower bound.
pub fn validate_future_timestamp(
    raw: &str,
    now: u64,
    min_seconds_ahead: u64,
    field: &str,
    errs: &mut Vec<FieldError>,
) -> Option<u64> {
    match crate::timeutil::parse_rfc3339_utc(raw) {
        None => {
            errs.push(FieldError::new(
                field,
                "must be an RFC 3339 UTC timestamp ending in Z (e.g. 2026-12-31T23:59:59Z)",
            ));
            None
        }
        Some(ts) if now + min_seconds_ahead >= ts => {
            errs.push(FieldError::new(field, "must be in the future"));
            None
        }
        Some(ts) => Some(ts),
    }
}

/// Query integer with default + inclusive bounds.
pub fn parse_bounded_u64(
    raw: Option<&str>,
    min: u64,
    max: u64,
    default: u64,
) -> Result<u64, &'static str> {
    match raw {
        None => Ok(default),
        Some(s) => {
            let v: u64 = s.parse().map_err(|_| "must be a non-negative integer")?;
            if v < min || v > max {
                return Err("out of allowed range");
            }
            Ok(v)
        }
    }
}

/// Application role token: [a-z0-9_-]{1,32}
pub fn is_app_role(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_ids_reject_dangerous_input() {
        assert!(is_route_id("u01ABCD"));
        assert!(is_route_id("c-123_456"));
        assert!(!is_route_id(""));
        assert!(!is_route_id("../../etc/passwd"));
        assert!(!is_route_id("users/*"));
        assert!(!is_route_id("a*b"));
        assert!(!is_route_id("with space"));
        assert!(!is_route_id(&"x".repeat(129)));
        assert!(!is_route_id("sh%23"));
    }

    #[test]
    fn emails_normalize_and_validate() {
        assert_eq!(
            normalize_email("Alice@Example.COM").unwrap(),
            "alice@example.com"
        );
        assert!(normalize_email("a@b.c").is_ok());
        assert!(normalize_email("first.last+tag@sub.domain.io").is_ok());
        assert!(normalize_email("no-at-sign").is_err());
        assert!(normalize_email("a@b").is_err());
        assert!(normalize_email("a b@c.d").is_err());
        assert!(normalize_email(".dot@c.d").is_err());
        assert!(normalize_email("a@-bad.c").is_err());
        assert!(normalize_email("a\r\n@b.c").is_err());
        assert!(normalize_email(&format!("{}@x.io", "a".repeat(300))).is_err());
        assert!(normalize_email("two@@at.com").is_err());
    }

    #[test]
    fn usernames_and_names() {
        assert!(is_username("alice"));
        assert!(is_username("ops-01.read"));
        assert!(!is_username("AL"));
        assert!(!is_username("bad space"));
        assert!(!is_username("ab"));
        assert!(is_display_name("Alice O'Neil"));
        assert!(!is_display_name("bad\nname"));
        assert!(!is_display_name(&"x".repeat(200)));
    }

    #[test]
    fn future_timestamps() {
        let now = 1_800_000_000u64;
        let mut errs = vec![];
        // now = 1_800_000_000 ≈ 2027-01-15T08:00:00Z. A timestamp 60+s in
        // the future is required, so exactly `now + 60` is rejected too.
        let good =
            validate_future_timestamp("2027-06-01T00:00:00Z", now, 60, "expires_at", &mut errs);
        assert_eq!(
            good,
            Some(crate::timeutil::parse_rfc3339_utc("2027-06-01T00:00:00Z").unwrap())
        );
        assert!(errs.is_empty());
        validate_future_timestamp("not-a-date", now, 60, "expires_at", &mut errs);
        validate_future_timestamp("2026-01-01T00:00:00Z", now, 60, "expires_at", &mut errs);
        validate_future_timestamp(
            "2027-06-01T00:00:00Z",
            now,
            180000060,
            "expires_at",
            &mut errs,
        );
        assert_eq!(errs.len(), 3);
    }

    #[test]
    fn bounded_ints() {
        assert_eq!(parse_bounded_u64(None, 1, 100, 25).unwrap(), 25);
        assert_eq!(parse_bounded_u64(Some("7"), 1, 100, 25).unwrap(), 7);
        assert!(parse_bounded_u64(Some("0"), 1, 100, 25).is_err());
        assert!(parse_bounded_u64(Some("101"), 1, 100, 25).is_err());
        assert!(parse_bounded_u64(Some("-3"), 1, 100, 25).is_err());
        assert!(parse_bounded_u64(Some("abc"), 1, 100, 25).is_err());
    }
}
