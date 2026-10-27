// Base64 decode failures are undiagnosed on purpose (no oracle).
#![allow(clippy::result_unit_err)]

//! Cryptographic primitives (pure-Rust, WASM-compatible crates only).
//!
//! Scope is deliberately narrow: SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256
//! password hashing, and HS256 JWTs. There is no home-grown cipher or
//! protocol anywhere in this platform; JWT verification pins the
//! algorithm to HS256 and rejects everything else (including `none`).
//!
//! PBKDF2 iteration counts: stored hashes are self-describing
//! (`pbkdf2-sha256$<iters>$<salt_b64>$<hash_b64>`), verification enforces a
//! floor of [`PBKDF2_MIN_ITERATIONS`] to prevent parameter-downgrade
//! attacks, and the iteration count is a documented operational knob
//! because edge runtimes impose CPU limits per request.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PBKDF2_MIN_ITERATIONS: u32 = 10_000;
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 100_000;
const HASH_LEN: usize = 32;
const PASSWORD_SCHEME: &str = "pbkdf2-sha256";

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time equality for secret material.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = [0u8; HASH_LEN];
    let _ = pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut out);
    out.to_vec()
}

/// Produce a self-describing password hash.
pub fn hash_password(password: &str, iterations: u32) -> String {
    let salt = crate::ids::random_bytes(16).expect("csprng unavailable");
    let hash = pbkdf2_sha256(password.as_bytes(), &salt, iterations);
    format!(
        "{}${}${}${}",
        PASSWORD_SCHEME,
        iterations,
        STANDARD.encode(salt),
        STANDARD.encode(hash)
    )
}

/// Verify a password against a stored hash string.
///
/// Errors on: unknown scheme, malformed encoding, iteration count below
/// the enforced floor (downgrade), or a non-UTF8 secret.
pub fn verify_password(password: &str, stored: &str) -> Result<bool, &'static str> {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 || parts[0] != PASSWORD_SCHEME {
        return Err("unsupported password hash scheme");
    }
    let iterations: u32 = parts[1].parse().map_err(|_| "malformed hash parameters")?;
    if iterations < PBKDF2_MIN_ITERATIONS {
        return Err("hash parameters below security floor");
    }
    let salt = STANDARD
        .decode(parts[2])
        .map_err(|_| "malformed hash salt")?;
    let expected = STANDARD
        .decode(parts[3])
        .map_err(|_| "malformed hash digest")?;
    if expected.len() != HASH_LEN {
        return Err("malformed hash digest");
    }
    let actual = pbkdf2_sha256(password.as_bytes(), &salt, iterations);
    Ok(ct_eq(&actual, &expected))
}

pub fn b64url_encode<T: AsRef<[u8]>>(data: T) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, ()> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| ())
}

/// JWT claims shared by admin sessions and application access tokens.
/// Domain separation happens via `aud` ("admin" vs "app") and `purpose`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Role for admin sessions; absent for app tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Credential version at issuance; app tokens only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cv: Option<u32>,
    /// Step-up authenticated until (unix seconds); admin sessions only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub su: Option<u64>,
    /// Session-epoch at issuance; admin sessions only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ep: Option<u64>,
    /// Not-before (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
}

/// HS256 signing. The header is pinned; callers cannot influence it.
pub fn jwt_encode(claims: &Claims, key: &[u8]) -> String {
    let header = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url_encode(serde_json::to_vec(claims).expect("claims serialize"));
    let signing_input = format!("{}.{}", header, payload);
    let sig = hmac_sha256(key, signing_input.as_bytes());
    format!("{}.{}", signing_input, b64url_encode(&sig))
}

/// Strict HS256 verification. Any deviation in header (algorithm confusion,
/// `alg: none`, extra segments, non-canonical base64) fails.
pub fn jwt_verify(
    token: &str,
    key: &[u8],
    expected_aud: &str,
    expected_iss: &str,
    now: u64,
) -> Result<Claims, &'static str> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed token");
    }
    // Header must be byte-identical to our pinned header. This prevents
    // algorithm confusion and embedded-`none` attacks outright.
    let header_bytes = b64url_decode(parts[0]).map_err(|_| "malformed header")?;
    if header_bytes != br#"{"alg":"HS256","typ":"JWT"}"# {
        return Err("unsupported token header");
    }
    let sig = b64url_decode(parts[2]).map_err(|_| "malformed signature")?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected_sig = hmac_sha256(key, signing_input.as_bytes());
    if !ct_eq(&sig, &expected_sig) {
        return Err("invalid signature");
    }
    let payload = b64url_decode(parts[1]).map_err(|_| "malformed payload")?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| "malformed claims")?;
    if claims.iss != expected_iss {
        return Err("invalid issuer");
    }
    if claims.aud != expected_aud {
        return Err("invalid audience");
    }
    if now >= claims.exp {
        return Err("expired");
    }
    if let Some(nbf) = claims.nbf {
        if now < nbf {
            return Err("not yet valid");
        }
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-signing-key-material-32-bytes-long!";

    fn sample_claims(now: u64, aud: &str) -> Claims {
        Claims {
            iss: "fap".into(),
            aud: aud.into(),
            sub: "admin".into(),
            iat: now,
            exp: now + 600,
            jti: "abc123".into(),
            purpose: Some("test".into()),
            role: Some("super_admin".into()),
            cv: None,
            su: None,
            ep: Some(1),
            nbf: None,
        }
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hmac_rfc4231_vectors() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let k = b"Jefe";
        let d = b"what do ya want for nothing?";
        let mac = hmac_sha256(k, d);
        let hexs: String = mac.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hexs,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn password_hash_roundtrip_and_floor() {
        let h = hash_password("correct horse battery staple", 10_000);
        assert!(verify_password("correct horse battery staple", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
        // Downgraded parameters are refused.
        let weak = hash_password("x", 999);
        assert!(verify_password("x", &weak).is_err());
        // Garbage hashes are refused, not silently accepted.
        assert!(verify_password("x", "bcrypt$1$2$3").is_err());
        assert!(verify_password("x", "").is_err());
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"aaa", b"aaa"));
        assert!(!ct_eq(b"aaa", b"aab"));
        assert!(!ct_eq(b"aaa", b"aa"));
    }

    #[test]
    fn jwt_roundtrip_and_expiry_boundary() {
        let now = 1_000_000;
        let t = jwt_encode(&sample_claims(now, "admin"), KEY);
        assert!(jwt_verify(&t, KEY, "admin", "fap", now).is_ok());
        // exp boundary: exp == now+600 → at now+600 token is EXPIRED (>=).
        assert!(jwt_verify(&t, KEY, "admin", "fap", now + 600).is_err());
        assert!(jwt_verify(&t, KEY, "admin", "fap", now + 599).is_ok());
    }

    #[test]
    fn jwt_rejects_attacks() {
        let now = 1_000_000;
        let t = jwt_encode(&sample_claims(now, "admin"), KEY);

        // Wrong key.
        assert!(jwt_verify(&t, b"other-key", "admin", "fap", now).is_err());
        // Wrong audience (admin token on app side).
        assert!(jwt_verify(&t, KEY, "app", "fap", now).is_err());
        // Tampered payload.
        let segs: Vec<&str> = t.split('.').collect();
        let evil = b64url_decode(segs[1]).unwrap();
        let mut claims: Claims = serde_json::from_slice(&evil).unwrap();
        claims.sub = "root".into();
        let evil_payload = b64url_encode(serde_json::to_vec(&claims).unwrap());
        let forged = format!("{}.{}.{}", segs[0], evil_payload, segs[2]);
        assert!(jwt_verify(&forged, KEY, "admin", "fap", now).is_err());

        // alg=none strip attack.
        let none_header = b64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
        let stripped = format!("{}.{}.AA", none_header, segs[1]);
        assert!(jwt_verify(&stripped, KEY, "admin", "fap", now).is_err());

        // Garbage inputs.
        assert!(jwt_verify("", KEY, "admin", "fap", now).is_err());
        assert!(jwt_verify("a.b.c.d", KEY, "admin", "fap", now).is_err());
        assert!(jwt_verify("!!!.###.$$$", KEY, "admin", "fap", now).is_err());
    }
}
