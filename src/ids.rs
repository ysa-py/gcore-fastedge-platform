//! Identifier and secret generation.
//!
// CSPRNG/identifier failures carry no diagnostic payload by design — the
// caller can only abort the operation. `clippy::result_unit_err` is
// therefore intentionally allowed here.
#![allow(clippy::result_unit_err)]

//! Randomness comes from the `getrandom` crate, which on `wasm32-wasip1`
//! delegates to the WASI `random_get` host call — the same CSPRNG the
//! runtime provides to the platform's own code. No fallback to weaker
//! sources exists: if the OS/random service refuses, the operation fails
//! loudly instead of degrading.
//!
//! Record identifiers are ULID-shaped (48-bit millisecond timestamp +
//! 80 random bits, Crockford base32): lexicographically sortable by
//! creation time, which `Store::scan`-based listings rely on.

use crate::crypto::sha256_hex;
use base64::Engine;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Raw CSPRNG bytes. Fails the operation if the source is unavailable.
pub fn random_bytes(n: usize) -> Result<Vec<u8>, ()> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|_| ())?;
    Ok(buf)
}

fn encode_crockford(value: u128, len: usize) -> String {
    let mut out = vec![b'0'; len];
    let mut v = value;
    for i in (0..len).rev() {
        out[i] = CROCKFORD[(v & 31) as usize];
        v >>= 5;
    }
    String::from_utf8(out).expect("crockford alphabet is ascii")
}

fn ulid_body(ts_ms: u64) -> Result<String, ()> {
    // 48-bit timestamp + 80 bits of randomness = 128 bits → 26 base32 chars.
    let rand: u128 = {
        let bytes = random_bytes(10)?;
        let mut v: u128 = 0;
        for b in bytes {
            v = (v << 8) | u128::from(b);
        }
        v
    };
    let combined = (u128::from(ts_ms & 0xFFFF_FFFF_FFFF) << 80) | rand;
    Ok(encode_crockford(combined, 26))
}

/// Stable, immutable user identifier: `u` + 26-char ULID body.
pub fn new_user_id(ts_ms: u64) -> Result<String, ()> {
    Ok(format!("u{}", ulid_body(ts_ms)?))
}

/// Subscription record id: `s` + ULID body.
pub fn new_subscription_id(ts_ms: u64) -> Result<String, ()> {
    Ok(format!("s{}", ulid_body(ts_ms)?))
}

/// Credential (API token) id: `c` + ULID body.
pub fn new_credential_id(ts_ms: u64) -> Result<String, ()> {
    Ok(format!("c{}", ulid_body(ts_ms)?))
}

/// Audit event id: `e` + ULID body. Sorting event keys matches event time.
pub fn new_event_id(ts_ms: u64) -> Result<String, ()> {
    Ok(format!("e{}", ulid_body(ts_ms)?))
}

/// JWT id (jti): compact random string.
pub fn new_jti() -> Result<String, ()> {
    Ok(hex(&random_bytes(8)?))
}

/// Correlation id for request tracing.
pub fn new_request_id() -> Result<String, ()> {
    let b = random_bytes(9)?;
    let mut s = String::with_capacity(18);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    Ok(s)
}

/// End-user API token, shown exactly once at issuance.
/// Format: `sk_live_` + 43 base64url chars (32 bytes = 256 bits of entropy).
pub fn new_api_token() -> Result<String, ()> {
    let bytes = random_bytes(32)?;
    let mut s = String::from("sk_live_");
    s.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
    Ok(s)
}

/// Suggested session-signing key material (for setup tooling).
pub fn new_signing_key_b64() -> Result<String, ()> {
    let bytes = random_bytes(32)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

/// SHA-256 hex of an API token — the only token-derived value ever stored.
pub fn token_fingerprint(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_stable_shape_and_unique_bodies() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..64 {
            let id = new_user_id(1_700_000_000_000 + i).unwrap();
            assert_eq!(id.len(), 27);
            assert!(id.starts_with('u'));
            assert!(id[1..].bytes().all(|c| CROCKFORD.contains(&c)));
            assert!(seen.insert(id), "unexpected duplicate id");
        }
    }

    #[test]
    fn ids_sort_by_creation_time() {
        let older = new_user_id(1_700_000_000_000).unwrap();
        let newer = new_user_id(1_700_000_000_001).unwrap();
        assert!(older < newer);
    }

    #[test]
    fn api_tokens_are_opaque_and_fingerprint_stable() {
        let t = new_api_token().unwrap();
        assert!(t.starts_with("sk_live_"));
        assert_eq!(t.len(), "sk_live_".len() + 43);
        let fp = token_fingerprint(&t);
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, token_fingerprint(&t));
        assert_ne!(fp, token_fingerprint(&new_api_token().unwrap()));
    }
}
