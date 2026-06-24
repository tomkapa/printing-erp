//! Asset failure type and its single HTTP mapping (CLAUDE.md §12).
//!
//! One `IntoResponse` lives next to the variants so status-code mapping cannot
//! drift. Server-side failures are logged with detail; client errors carry a
//! short, value-free message.

use crate::db;
use crate::domain::DomainError;
use crate::storage::StorageError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Why an asset operation failed.
#[derive(Debug, Error)]
pub(crate) enum AssetError {
    /// A path/identifier could not be parsed (e.g. a malformed asset id).
    #[error("invalid identifier")]
    InvalidId,

    /// No asset with the given id is visible in this tenant's scope.
    #[error("asset not found")]
    NotFound,

    /// The uploaded object's size does not match what was declared at create.
    #[error("uploaded object size {stored} does not match declared {declared}")]
    SizeMismatch { declared: i64, stored: i64 },

    /// An object-storage operation failed.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// A database failure — a query, or opening/committing the tenant
    /// transaction. Both funnel through [`db::DbError`] so there is one DB path.
    #[error(transparent)]
    Db(#[from] db::DbError),

    /// A bounded I/O await (DB or object store) exceeded its deadline.
    #[error("operation timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

impl From<DomainError> for AssetError {
    fn from(_: DomainError) -> Self {
        // Collapse the parse detail; callers don't probe which ids exist.
        Self::InvalidId
    }
}

impl From<sqlx::Error> for AssetError {
    fn from(error: sqlx::Error) -> Self {
        // Raw query errors (repo + commit) join the single DB path via DbError.
        Self::Db(db::DbError::from(error))
    }
}

impl IntoResponse for AssetError {
    fn into_response(self) -> Response {
        let (status, message): (StatusCode, &str) = match &self {
            Self::InvalidId => (StatusCode::BAD_REQUEST, "invalid identifier"),
            Self::NotFound => (StatusCode::NOT_FOUND, "asset not found"),
            Self::SizeMismatch { .. } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "uploaded object does not match the declared size",
            ),
            Self::Storage(StorageError::NotFound) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "uploaded object not found in storage",
            ),
            Self::Storage(_) => (StatusCode::BAD_GATEWAY, "object storage unavailable"),
            Self::Timeout(_) => (StatusCode::GATEWAY_TIMEOUT, "operation timed out"),
            Self::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };

        // Log the failures the operator must see; client errors are self-evident.
        match &self {
            Self::Storage(_) | Self::Db(_) | Self::Timeout(_) => {
                tracing::error!(error = ?self, event = "asset.operation.failed");
            }
            Self::InvalidId | Self::NotFound | Self::SizeMismatch { .. } => {}
        }

        (status, message).into_response()
    }
}
