//! Centralized API error taxonomy with safe, non-leaking public messages.
//!
//! Rules:
//! * Clients receive a stable machine code plus a generic, non-sensitive
//!   message. Internal details (storage errors, upstream bodies, stack info)
//!   never leave the process.
//! * Fail-closed: on protected resources, any inability to *establish*
//!   authorization is reported as 401/403, never as a 5xx that might be
//!   interpreted as "try again later" for an unauthorized caller.
//! * Field-level validation errors are collected and returned together as
//!   HTTP 422 so forms can highlight every problem in one round trip.

use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

impl FieldError {
    pub fn new(field: &str, message: &str) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub enum ApiError {
    /// 400 — syntactically fine but semantically unusable request.
    BadRequest(&'static str),
    /// 401 — no or invalid credentials.
    Unauthorized(&'static str),
    /// 403 — authenticated but not permitted (never reveals why in detail).
    Forbidden(&'static str),
    /// 403 — valid session, but destructive operation needs step-up auth.
    StepUpRequired,
    /// 404 — resource does not exist (also used to avoid existence oracles).
    NotFound(&'static str),
    /// 405 — method not supported for the route.
    MethodNotAllowed(Vec<&'static str>),
    /// 409 — state conflict (duplicate email, terminal status, stale rev).
    Conflict(&'static str),
    /// 422 — request validation failed; contains per-field errors.
    Unprocessable(Vec<FieldError>),
    /// 413 — request body exceeds the accepted size.
    TooLarge,
    /// 429 — rate limited.
    TooManyRequests { retry_after_s: u64 },
    /// 502 — the Gcore control plane (REST API) could not be reached/used.
    ControlPlane(&'static str),
    /// 503 — Edge Storage is unavailable or not linked to this app.
    StorageUnavailable,
    /// 500 — unexpected internal condition (no details exposed).
    Internal,
}

impl ApiError {
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) | Self::StepUpRequired => 403,
            Self::NotFound(_) => 404,
            Self::MethodNotAllowed(_) => 405,
            Self::Conflict(_) => 409,
            Self::Unprocessable(_) => 422,
            Self::TooLarge => 413,
            Self::TooManyRequests { .. } => 429,
            Self::ControlPlane(_) => 502,
            Self::StorageUnavailable => 503,
            Self::Internal => 500,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "INVALID_REQUEST",
            Self::Unauthorized(_) => "UNAUTHENTICATED",
            Self::Forbidden(_) => "PERMISSION_DENIED",
            Self::StepUpRequired => "STEP_UP_REQUIRED",
            Self::NotFound(_) => "NOT_FOUND",
            Self::MethodNotAllowed(_) => "METHOD_NOT_ALLOWED",
            Self::Conflict(_) => "CONFLICT",
            Self::Unprocessable(_) => "VALIDATION_FAILED",
            Self::TooLarge => "PAYLOAD_TOO_LARGE",
            Self::TooManyRequests { .. } => "RATE_LIMITED",
            Self::ControlPlane(_) => "CONTROL_PLANE_UNAVAILABLE",
            Self::StorageUnavailable => "STORAGE_UNAVAILABLE",
            Self::Internal => "INTERNAL_ERROR",
        }
    }

    /// Public message — safe to show to any caller. Never includes internal
    /// state, storage details, or upstream responses.
    pub fn public_message(&self) -> String {
        match self {
            Self::StepUpRequired => {
                "This operation requires recent re-authentication. Confirm your password and retry."
                    .into()
            }
            Self::BadRequest(m)
            | Self::Unauthorized(m)
            | Self::Forbidden(m)
            | Self::Conflict(m)
            | Self::ControlPlane(m) => (*m).to_string(),
            Self::NotFound(m) => (*m).to_string(),
            Self::Unprocessable(_) => "One or more fields failed validation.".into(),
            Self::MethodNotAllowed(_) => {
                "The HTTP method is not supported for this resource.".into()
            }
            Self::TooLarge => "The request body is too large.".into(),
            Self::TooManyRequests { retry_after_s } => {
                format!("Too many requests. Retry after {retry_after_s} seconds.")
            }
            Self::StorageUnavailable => {
                "The data plane is currently unavailable. Try again shortly.".into()
            }
            Self::Internal => "An unexpected error occurred. The incident was recorded.".into(),
        }
    }

    /// JSON body for the error envelope.
    pub fn to_json(&self) -> serde_json::Value {
        let mut err = json!({
            "code": self.code(),
            "message": self.public_message(),
        });
        if let Self::Unprocessable(fields) = self {
            err["details"] = json!(fields
                .iter()
                .map(|f| json!({"field": f.field, "message": f.message}))
                .collect::<Vec<_>>());
        }
        json!({ "error": err })
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code(), self.public_message())
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes() {
        assert_eq!(ApiError::Unauthorized("x").status(), 401);
        assert_eq!(ApiError::TooLarge.status(), 413);
        assert_eq!(ApiError::MethodNotAllowed(vec!["GET"]).status(), 405);
        assert_eq!(ApiError::StorageUnavailable.status(), 503);
    }

    #[test]
    fn unprocessable_lists_fields() {
        let e = ApiError::Unprocessable(vec![
            FieldError::new("email", "already in use"),
            FieldError::new("expires_at", "must be in the future"),
        ]);
        let v = e.to_json();
        assert_eq!(v["error"]["code"], "VALIDATION_FAILED");
        assert_eq!(v["error"]["details"][0]["field"], "email");
    }

    #[test]
    fn messages_never_leak_internals() {
        // Internal errors expose nothing beyond a generic sentence.
        assert_eq!(
            ApiError::Internal.public_message(),
            "An unexpected error occurred. The incident was recorded."
        );
    }
}
