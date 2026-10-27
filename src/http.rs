//! Platform-neutral request/response types.
//!
//! The whole application (routing, auth, handlers) operates on these
//! plain structs. The wasm entrypoint converts FastEdge SDK types into
//! [`Req`] once and converts [`Resp`] back — everything else, including
//! all tests, is SDK-free.

use crate::errors::ApiError;
use serde::de::DeserializeOwned;

pub const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query_raw: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn new(method: &str, path: &str) -> Self {
        // Defensive split: a path may carry an embedded query string (test
        // helpers and hand-built requests); production always passes them
        // separately via the request target.
        let (path_part, query) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q.to_string())),
            None => (path, None),
        };
        Self {
            method: method.to_uppercase(),
            path: path_part.into(),
            query_raw: query,
            headers: vec![],
            body: vec![],
        }
    }

    pub fn get(path: &str) -> Self {
        Self::new("GET", path)
    }

    pub fn post(path: &str) -> Self {
        Self::new("POST", path)
    }

    pub fn with_query(mut self, q: &str) -> Self {
        if !q.is_empty() {
            self.query_raw = Some(q.into());
        }
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_ascii_lowercase(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Case-insensitive first header match.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == lower)
            .map(|(_, v)| v.as_str())
    }

    /// All values for a header (e.g., cookies may repeat).
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(k, _)| *k == lower)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Parsed query parameters. Takes the LAST occurrence of a key
    /// (predictable) and URL-decodes both sides.
    pub fn query(&self, name: &str) -> Option<String> {
        let raw = self.query_raw.as_deref()?;
        for pair in raw.split('&').rev() {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            if url_decode(k) == Some(name.to_string()) {
                return url_decode(v);
            }
        }
        None
    }

    pub fn query_all(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(raw) = &self.query_raw {
            for pair in raw.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = match pair.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (pair, ""),
                };
                out.push((
                    url_decode(k).unwrap_or_default(),
                    url_decode(v).unwrap_or_default(),
                ));
            }
        }
        out
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        for header in self.headers_all("cookie") {
            for part in header.split(';') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=') {
                    if k.trim() == name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
        None
    }

    pub fn bearer(&self) -> Option<String> {
        let h = self.header("authorization")?;
        let rest = h
            .strip_prefix("Bearer ")
            .or_else(|| h.strip_prefix("bearer "))?;
        Some(rest.trim().to_string())
    }

    /// Body already validated for size by the router; parse strictly.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, ApiError> {
        if self.body.is_empty() {
            return Err(ApiError::BadRequest("A JSON request body is required."));
        }
        if self.body.len() > MAX_BODY_BYTES {
            return Err(ApiError::TooLarge);
        }
        serde_json::from_slice(&self.body)
            .map_err(|_| ApiError::BadRequest("The request body is not valid JSON."))
    }

    /// Best-effort client IP for rate limiting only (never for authz).
    pub fn client_ip(&self) -> Option<&str> {
        self.header("x-real-ip")
            .or_else(|| self.header("x-forwarded-for"))
    }
}

/// Minimal percent-decoder (`%XX` + `+` → space). Returns `None` on
/// malformed input rather than silently passing it through.
pub fn url_decode(s: &str) -> Option<String> {
    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 2 >= b.len() {
                    return None;
                }
                let hi = hex_val(b[i + 1])?;
                let lo = hex_val(b[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: vec![],
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn append_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.into(), value.into()));
    }

    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| {
            br#"{"error":{"code":"INTERNAL_ERROR","message":"Serialization failed."}}"#.to_vec()
        });
        Self::new(status)
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body(body)
    }

    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self::new(status)
            .header("Content-Type", content_type)
            .with_body(body)
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Standard security headers applied to every response by the router.
    pub fn with_security_headers(mut self) -> Self {
        for (k, v) in [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            (
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=()",
            ),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("X-Robots-Tag", "noindex, nofollow"),
        ] {
            self.headers.push((k.into(), v.into()));
        }
        self
    }

    pub fn with_csp(self, csp: &str) -> Self {
        self.header("Content-Security-Policy", csp)
    }

    pub fn from_error(err: &ApiError, request_id: &str) -> Self {
        let mut v = err.to_json();
        v["request_id"] = serde_json::json!(request_id);
        let mut r = Self::json(err.status(), &v)
            .with_security_headers()
            .header("Cache-Control", "no-store");
        if let ApiError::TooManyRequests { retry_after_s } = err {
            r.append_header("Retry-After", &retry_after_s.to_string());
        }
        if let ApiError::MethodNotAllowed(allowed) = err {
            r.append_header("Allow", &allowed.join(", "));
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing_takes_last_key_occurrence() {
        let r = Req::get("/x").with_query("a=1&b=2&a=3&flag&enc=%41%42&plus=a+b");
        assert_eq!(r.query("a").unwrap(), "3");
        assert_eq!(r.query("b").unwrap(), "2");
        assert_eq!(r.query("flag").unwrap(), "");
        assert_eq!(r.query("enc").unwrap(), "AB");
        assert_eq!(r.query("plus").unwrap(), "a b");
        assert_eq!(r.query("missing"), None);
    }

    #[test]
    fn cookie_parsing() {
        let r = Req::get("/").with_header("Cookie", "a=1; fes_session=tok; b=2");
        assert_eq!(r.cookie("fes_session").unwrap(), "tok");
        assert_eq!(r.cookie("missing"), None);
        // Multiple cookie headers are also considered.
        let r2 = Req::get("/")
            .with_header("Cookie", "x=1")
            .with_header("Cookie", "fes_session=tok2");
        assert_eq!(r2.cookie("fes_session").unwrap(), "tok2");
    }

    #[test]
    fn bearer_parsing() {
        let r = Req::get("/").with_header("Authorization", "Bearer abc.def");
        assert_eq!(r.bearer().unwrap(), "abc.def");
        let r2 = Req::get("/").with_header("Authorization", "Basic xyz");
        assert_eq!(r2.bearer(), None);
        assert_eq!(Req::get("/").bearer(), None);
    }

    #[test]
    fn json_body_strict() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct P {
            a: u32,
        }
        let ok = Req::post("/").with_body(br#"{"a":1}"#.to_vec());
        assert!(ok.json::<P>().is_ok());
        let bad = Req::post("/").with_body(br#"{"a":"x"}"#.to_vec());
        assert!(matches!(bad.json::<P>(), Err(ApiError::BadRequest(_))));
        let empty = Req::post("/");
        assert!(matches!(empty.json::<P>(), Err(ApiError::BadRequest(_))));
        let malformed = Req::post("/").with_body(b"{nope".to_vec());
        assert!(matches!(
            malformed.json::<P>(),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn url_decode_rejects_bad_escapes() {
        assert_eq!(url_decode("ok").unwrap(), "ok");
        assert!(url_decode("bad%2").is_none());
        assert!(url_decode("bad%GG").is_none());
    }
}
