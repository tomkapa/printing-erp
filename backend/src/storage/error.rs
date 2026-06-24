//! Object-storage failure type (CLAUDE.md §12: one typed error per boundary).
//!
//! The SDK's own error types never cross out of [`crate::storage`]; they are
//! collapsed into [`StorageError`] so callers depend on our vocabulary, not the
//! `aws-sdk-s3` surface.

use thiserror::Error;

/// Why an object-storage operation failed.
#[derive(Debug, Error)]
pub(crate) enum StorageError {
    /// The requested object does not exist (a 404 / `NoSuchKey` from the store).
    #[error("object not found")]
    NotFound,

    /// Misconfiguration detected at client construction (empty bucket/region).
    /// The payload names the offending field, never a credential.
    #[error("storage misconfigured: {0}")]
    Config(&'static str),

    /// Any other backend failure — presign computation, network, 5xx. The
    /// source is preserved for `error = ?e` logging without leaking the SDK
    /// type into our public signatures.
    #[error("object store backend failure")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}
