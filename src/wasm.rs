//! FastEdge wasm32-wasip1 entrypoint and platform providers.
//!
//! Provider mapping (all verified against the FastEdge SDK v0.4.x):
//! * `Secrets`  → `fastedge::secret::get` (encrypted Secrets Manager),
//!   falling back to deployment-time environment variables.
//! * `Cache`    → `fastedge::cache` (per-POP, atomic `incr`, TTL in ms).
//! * `Store` reads → `fastedge::key_value::Store` (Edge Storage local
//!   replica). The composed [`ReadYourWritesStore`] routes all writes to
//!   the Gcore REST control plane, matching the platform's design in
//!   which Edge Storage is application read-only.
//! * `HttpOut`  → `fastedge::send_request` (outbound HTTP).
//!
//! One `App` per instance is built lazily via `OnceLock` and reused for
//! every request. Nothing per-request is leaked.

use crate::app::{App, EnvConfig};
use crate::controlplane::GcoreControlPlane;
use crate::datastore::ReadYourWritesStore;
use crate::http::{Req, Resp};
use crate::platform::{
    Cache, CacheError, HttpError, HttpOut, HttpResponse, SecretError, Secrets, Store, StoreError,
    SystemClock,
};
use fastedge::body::Body;
use fastedge::http::{Request, Response, StatusCode};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

struct FastEdgeSecrets;

impl Secrets for FastEdgeSecrets {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, SecretError> {
        match fastedge::secret::get(name) {
            // Component path: secrets are UTF-8 strings (verified in the
            // canonical WIT: secret::get returns option<string>).
            Ok(v) => Ok(v.map(String::into_bytes)),
            Err(_) => match std::env::var(name) {
                Ok(v) if !v.is_empty() => Ok(Some(v.into_bytes())),
                _ => Ok(None),
            },
        }
    }
}

struct FastEdgeCache;

impl Cache for FastEdgeCache {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        fastedge::cache::get(key).map_err(|_| CacheError::Unavailable)
    }
    fn set(&self, key: &str, value: Vec<u8>, ttl_ms: Option<u64>) -> Result<(), CacheError> {
        fastedge::cache::set(key, &value, ttl_ms).map_err(|_| CacheError::Unavailable)
    }
    fn delete(&self, key: &str) -> Result<(), CacheError> {
        fastedge::cache::delete(key).map_err(|_| CacheError::Unavailable)
    }
    fn incr(&self, key: &str, delta: i64) -> Result<i64, CacheError> {
        fastedge::cache::incr(key, delta).map_err(|_| CacheError::Unavailable)
    }
    fn expire(&self, key: &str, ttl_ms: u64) -> Result<bool, CacheError> {
        fastedge::cache::expire(key, ttl_ms).map_err(|_| CacheError::Unavailable)
    }
}

struct FastEdgeHttp;

impl HttpOut for FastEdgeHttp {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError> {
        let method = fastedge::http::Method::from_bytes(method.as_bytes())
            .map_err(|_| HttpError::Unreachable)?;
        let mut builder = Request::builder().method(method).uri(url);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let req = builder
            .body(Body::from(body.to_vec()))
            .map_err(|_| HttpError::Unreachable)?;
        let resp = fastedge::send_request(req).map_err(|_| HttpError::Unreachable)?;
        let status = resp.status().as_u16();
        let payload = {
            let (_, b) = resp.into_parts();
            b.to_vec()
        };
        Ok(HttpResponse {
            status,
            body: payload,
        })
    }
}

/// Edge Storage READ path. Writes never come here — the composed store
/// routes `put`/`delete` to the control plane.
struct FastEdgeKvReads;

impl Store for FastEdgeKvReads {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let store = open_edge_store()?;
        store.get(key).map_err(|_| StoreError::Unavailable)
    }
    fn put(&self, _key: &str, _value: Vec<u8>) -> Result<(), StoreError> {
        // Unreachable by construction; fail loudly if ever hit.
        Err(StoreError::Unavailable)
    }
    fn delete(&self, _key: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn scan(&self, pattern: &str) -> Result<Vec<String>, StoreError> {
        let store = open_edge_store()?;
        store.scan(pattern).map_err(|_| StoreError::Unavailable)
    }
}

/// Open the Edge Storage store configured via FE_STORE_NAME (default:
/// "default"). Opening by label is the only supported access on the
/// component path; an unknown or unlinked label surfaces as
/// `NoSuchStore`, which we treat as unavailable (fail-closed).
fn open_edge_store() -> Result<fastedge::key_value::Store, StoreError> {
    let label = std::env::var("FE_STORE_NAME").unwrap_or_else(|_| "default".to_string());
    fastedge::key_value::Store::open(&label).map_err(|_| StoreError::Unavailable)
}

static SECRETS: FastEdgeSecrets = FastEdgeSecrets;
static CACHE: FastEdgeCache = FastEdgeCache;
static HTTP: FastEdgeHttp = FastEdgeHttp;
static KV: FastEdgeKvReads = FastEdgeKvReads;
static CLOCK: SystemClock = SystemClock;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn read_env_config() -> EnvConfig {
    EnvConfig {
        store_id: env_or("FE_STORE_ID", ""),
        api_base: env_or("FE_API_BASE", "https://api.gcore.com"),
        cookie_name: env_or("FE_COOKIE_NAME", ""),
        insecure_cookie: env_or("FE_COOKIE_INSECURE", "").eq_ignore_ascii_case("true"),
        public_origin: env_or("FE_PUBLIC_ORIGIN", ""),
        app_version: env!("CARGO_PKG_VERSION"),
    }
}

fn build_app() -> App<'static> {
    let env = read_env_config();
    let api_key = FastEdgeSecrets
        .get("GCORE_API_KEY")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let cp: &'static GcoreControlPlane<'static> = Box::leak(Box::new(GcoreControlPlane::new(
        &HTTP,
        &api_key,
        &env.store_id,
        &env.api_base,
    )));
    let store: &'static ReadYourWritesStore<'static> =
        Box::leak(Box::new(ReadYourWritesStore::new(&KV, cp, &CLOCK)));
    App {
        store,
        cache: &CACHE,
        secrets: &SECRETS,
        clock: &CLOCK,
        http: Some(&HTTP),
        env,
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

static APP: OnceLock<App<'static>> = OnceLock::new();

#[fastedge::http]
fn main(req: Request<Body>) -> Result<Response<Body>, fastedge::http::Error> {
    let app = APP.get_or_init(build_app);

    // FastEdge SDK → platform-neutral request.
    let (parts, body) = req.into_parts();
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_ascii_lowercase(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let platform_req = Req {
        method: parts.method.as_str().to_uppercase(),
        path: parts.uri.path().to_string(),
        query_raw: parts.uri.query().map(str::to_string),
        headers,
        body: body.to_vec(),
    };

    let method_label = platform_req.method.clone();
    let path_label = platform_req.path.clone();
    let resp = crate::router::handle(app, platform_req);

    // Sanitized per-request diagnostic (stdout; visible in platform logs).
    // Contains no inputs, no secrets.
    fastedge::utils::set_user_diag(&format!(
        "method={} path={} status={}",
        method_label,
        crate::validation::sanitize_text(&path_label, 64),
        resp.status
    ));

    to_fastedge_response(resp)
}

fn to_fastedge_response(resp: Resp) -> Result<Response<Body>, fastedge::http::Error> {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = Response::builder()
        .status(status)
        .body(Body::from(resp.body))?;
    // Append (never replace) so repeated headers survive verbatim.
    for (k, v) in &resp.headers {
        if let (Ok(name), Ok(value)) = (
            fastedge::http::HeaderName::try_from(k.as_str()),
            fastedge::http::HeaderValue::from_str(v),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    Ok(response)
}
