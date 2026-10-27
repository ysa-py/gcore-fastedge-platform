//! Embedded static assets — the admin panel is baked into the WASM binary.
//!
//! Deployment consequence (documented trade-off, accepted deliberately):
//! the entire panel ships as ONE artifact with the API, so there is no
//! separate hosting, no extra origin to harden, and no version skew
//! between panel and API. Assets are immutable per build; `index.html`
//! carries `Cache-Control: no-store` so upgrades apply on next reload.

pub struct Asset {
    pub path: &'static str,
    pub content_type: &'static str,
    pub body: &'static [u8],
}

macro_rules! asset {
    ($path:expr, $ctype:expr, $file:expr) => {
        Asset {
            path: $path,
            content_type: $ctype,
            body: include_bytes!($file),
        }
    };
}

pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub static ASSETS: &[Asset] = &[
    asset!("/", "text/html; charset=utf-8", "../frontend/index.html"),
    asset!(
        "/favicon.svg",
        "image/svg+xml",
        "../frontend/assets/favicon.svg"
    ),
    asset!(
        "/assets/logo.svg",
        "image/svg+xml",
        "../frontend/assets/logo.svg"
    ),
    asset!(
        "/assets/styles.css",
        "text/css; charset=utf-8",
        "../frontend/assets/styles.css"
    ),
    asset!(
        "/assets/js/utils.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/utils.js"
    ),
    asset!(
        "/assets/js/api.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/api.js"
    ),
    asset!(
        "/assets/js/state.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/state.js"
    ),
    asset!(
        "/assets/js/ui.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/ui.js"
    ),
    asset!(
        "/assets/js/charts.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/charts.js"
    ),
    asset!(
        "/assets/js/pages/login.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/login.js"
    ),
    asset!(
        "/assets/js/pages/dashboard.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/dashboard.js"
    ),
    asset!(
        "/assets/js/pages/users.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/users.js"
    ),
    asset!(
        "/assets/js/pages/user-detail.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/user-detail.js"
    ),
    asset!(
        "/assets/js/pages/subscriptions.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/subscriptions.js"
    ),
    asset!(
        "/assets/js/pages/credentials.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/credentials.js"
    ),
    asset!(
        "/assets/js/pages/config.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/config.js"
    ),
    asset!(
        "/assets/js/pages/storage.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/storage.js"
    ),
    asset!(
        "/assets/js/pages/audit.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/audit.js"
    ),
    asset!(
        "/assets/js/pages/analytics.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/analytics.js"
    ),
    asset!(
        "/assets/js/pages/system.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/system.js"
    ),
    asset!(
        "/assets/js/pages/roles.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/roles.js"
    ),
    asset!(
        "/assets/js/pages/backup.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/backup.js"
    ),
    asset!(
        "/assets/js/pages/help.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/pages/help.js"
    ),
    asset!(
        "/assets/js/main.js",
        "text/javascript; charset=utf-8",
        "../frontend/assets/js/main.js"
    ),
];

/// Serve an exact path with strong ETag revalidation. Only `GET`/`HEAD`
/// reach this function (enforced by the router). Unknown paths return
/// `None` (→ 404 JSON).
///
/// Caching policy (correctness first): assets are served with
/// `Cache-Control: no-cache` + a content-hash ETag. The browser revalidates
/// on every load and receives an empty 304 when nothing changed — fresh
/// after every deployment, cheap in the steady state. (`max-age` caching
/// was deliberately rejected: new binaries serve identical URLs, so
/// long-lived caches would show a stale panel after upgrades.)
pub fn serve(path: &str, if_none_match: Option<&str>) -> Option<crate::http::Resp> {
    let asset = ASSETS.iter().find(|a| a.path == path)?;
    let etag = etag_for(asset.body);
    if if_none_match == Some(etag.as_str()) || if_none_match == Some("*") {
        let mut not_modified = crate::http::Resp::new(304)
            .header("ETag", &etag)
            .header("Cache-Control", "no-cache");
        not_modified.append_header("X-Content-Type-Options", "nosniff");
        return Some(not_modified);
    }
    let mut resp = crate::http::Resp::bytes(200, asset.content_type, asset.body.to_vec())
        .with_security_headers()
        .header("ETag", &etag)
        .header("Cache-Control", "no-cache");
    if asset.content_type.starts_with("text/html") {
        resp = resp.with_csp(CSP);
    }
    Some(resp)
}

/// Content-hash ETag (first 16 hex chars of SHA-256) — changes exactly
/// when the served bytes change.
fn etag_for(body: &[u8]) -> String {
    format!("\"{}\"", &crate::crypto::sha256_hex(body)[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_serves_with_strict_csp_and_revalidation() {
        let r = serve("/", None).unwrap();
        assert_eq!(r.status, 200);
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Security-Policy" && v.contains("default-src 'self'")));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "Cache-Control" && v == "no-cache"));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "ETag" && v.starts_with("\"")));
        assert!(!r.body.is_empty());
        // Revalidation with the same ETag → 304 with no body.
        let etag = r
            .headers
            .iter()
            .find(|(k, _)| k == "ETag")
            .map(|(_, v)| v.clone())
            .unwrap();
        let cached = serve("/", Some(&etag)).unwrap();
        assert_eq!(cached.status, 304);
        assert!(cached.body.is_empty());
    }

    #[test]
    fn assets_are_revalidatable_and_bounded() {
        for a in ASSETS {
            assert!(!a.body.is_empty(), "asset {} is empty", a.path);
            assert!(
                a.body.len() < 200_000,
                "asset {} is suspiciously large: {}",
                a.path,
                a.body.len()
            );
        }
        let js = serve("/assets/js/main.js", None).unwrap();
        assert!(js
            .headers
            .iter()
            .any(|(k, v)| k == "Cache-Control" && v == "no-cache"));
        assert!(js.headers.iter().any(|(k, _)| k == "ETag"));
    }

    #[test]
    fn unknown_paths_miss() {
        assert!(serve("/etc/passwd", None).is_none());
        assert!(serve("/../../../etc/passwd", None).is_none());
        assert!(serve("/assets/../../secrets", None).is_none());
    }
}
