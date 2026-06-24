//! The single error type for authentication handlers (CLAUDE.md §12).
//!
//! Only three outcomes are visible to a client: `401` for a rejected credential
//! or token (the two are deliberately indistinguishable — no enumeration), and
//! `500` for an internal fault. Internal causes (DB errors, JWT signing, integer
//! overflow) are logged here and collapsed to [`AuthError::Internal`] so a
//! caller learns nothing from the response.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use std::time::Duration;
use thiserror::Error;

/// Why an authentication operation failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum AuthError {
    /// Login failed: wrong password, unknown user, inactive account, or unknown
    /// tenant — all reported identically.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// A presented refresh/reset token was missing, malformed, expired, revoked,
    /// or replayed.
    #[error("invalid token")]
    InvalidToken,

    /// An unexpected internal failure (already logged at the source).
    #[error("internal authentication error")]
    Internal,

    /// The bounded database round-trip exceeded [`AUTH_QUERY_TIMEOUT`]
    /// (`super::limits`). An availability failure, distinct from an internal bug.
    #[error("authentication query timed out")]
    Timeout,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::InvalidCredentials | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            // A bounded-query timeout is an availability failure, not an internal
            // bug — report 504 so it is distinguishable (mirrors `SettingsError`).
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
        };
        status.into_response()
    }
}

/// Logs an unexpected failure and maps it to [`AuthError::Internal`] (CLAUDE.md
/// §2): the cause is recorded in a span event, never returned to the client.
pub(crate) fn internal<E: std::fmt::Debug>(error: E) -> AuthError {
    tracing::error!(error = ?error, event = "auth.internal_error");
    AuthError::Internal
}

/// Computes `now + ttl` as an absolute deadline, guarding against overflow.
///
/// # Errors
///
/// Returns [`AuthError::Internal`] if `ttl` does not fit a signed-seconds offset
/// or the addition overflows the representable range.
pub(crate) fn deadline(now: DateTime<Utc>, ttl: Duration) -> Result<DateTime<Utc>, AuthError> {
    let secs = i64::try_from(ttl.as_secs()).map_err(internal)?;
    now.checked_add_signed(chrono::Duration::seconds(secs))
        .ok_or(AuthError::Internal)
}
