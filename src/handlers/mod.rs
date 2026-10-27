//! Request handlers, split by surface.
//!
//! * [`admin`] — the authenticated administration API.
//! * [`app`]   — the end-user application API (`/api/v1/*`).
//! * [`system`] — health, diagnostics, metrics, and platform proxies.

pub mod admin;
pub mod app;
pub mod system;
