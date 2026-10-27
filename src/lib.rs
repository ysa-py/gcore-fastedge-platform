//! FastEdge Admin Platform — platform-independent core.
//!
//! Everything in this tree compiles on both the host (`cargo test`) and
//! `wasm32-wasip1`. The only wasm-gated module is [`wasm`], which contains
//! the FastEdge entrypoint and the platform provider implementations.

pub mod app;
pub mod assets;
pub mod audit;
pub mod auth;
pub mod authorization;
pub mod controlplane;
pub mod crypto;
pub mod datastore;
pub mod errors;
pub mod handlers;
pub mod http;
pub mod ids;
pub mod metrics;
pub mod models;
pub mod platform;
pub mod router;
pub mod timeutil;
pub mod users;
pub mod validation;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
