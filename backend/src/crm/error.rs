//! CRM failure type and its single HTTP mapping (CLAUDE.md §12).
//!
//! One `IntoResponse` lives next to the variants so status-code mapping cannot
//! drift. Server-side faults are logged with detail; client errors carry a
//! short, value-free message.

use crate::db;
use crate::domain::DomainError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Why a CRM operation failed.
#[derive(Debug, Error)]
pub(crate) enum CrmError {
    /// A path identifier could not be parsed (malformed customer/contact id).
    #[error("invalid identifier")]
    InvalidId,

    /// A query parameter held an unrecognized value (e.g. `?status=bogus`).
    #[error("invalid query parameter")]
    InvalidQuery,

    /// No customer/contact with the given id is visible in this tenant's scope
    /// (also covers creating a contact under a missing/archived customer).
    #[error("not found")]
    NotFound,

    /// A `PATCH` carried no updatable fields.
    #[error("no fields to update")]
    EmptyPatch,

    /// A database failure — a query, or opening/committing the tenant
    /// transaction. Both funnel through [`db::DbError`] so there is one DB path.
    #[error(transparent)]
    Db(#[from] db::DbError),

    /// A bounded DB await exceeded its deadline (CLAUDE.md §5).
    #[error("operation timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

impl From<DomainError> for CrmError {
    fn from(_: DomainError) -> Self {
        // Collapse the parse detail; callers don't probe which ids exist.
        Self::InvalidId
    }
}

impl From<sqlx::Error> for CrmError {
    fn from(error: sqlx::Error) -> Self {
        // Raw query/decode errors (repo + commit) join the single DB path.
        Self::Db(db::DbError::from(error))
    }
}

impl IntoResponse for CrmError {
    fn into_response(self) -> Response {
        let (status, message): (StatusCode, &str) = match &self {
            Self::InvalidId => (StatusCode::BAD_REQUEST, "invalid identifier"),
            Self::InvalidQuery => (StatusCode::BAD_REQUEST, "invalid query parameter"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found"),
            Self::EmptyPatch => (StatusCode::UNPROCESSABLE_ENTITY, "no fields to update"),
            Self::Timeout(_) => (StatusCode::GATEWAY_TIMEOUT, "operation timed out"),
            Self::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };

        // Record only the failures an operator must see; client errors are
        // self-evident and value-free (mirrors `AssetError`, CLAUDE.md §2).
        match &self {
            Self::Db(_) | Self::Timeout(_) => {
                tracing::error!(error = ?self, event = "crm.operation.failed");
            }
            Self::InvalidId | Self::InvalidQuery | Self::NotFound | Self::EmptyPatch => {}
        }

        (status, message).into_response()
    }
}
