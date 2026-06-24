//! Hard limits for the asset subsystem (CLAUDE.md §5).
//!
//! Every bound is named and documented with *why this number*, never a magic
//! literal in parsing or query logic. Storage-transport bounds (presign TTLs,
//! per-operation timeouts) live in [`crate::storage::limits`] instead.

/// Largest object we accept, in bytes (512 MiB). Print artwork — layered PDFs,
/// high-resolution TIFFs, packaged AI/EPS — dwarfs ordinary uploads, but a
/// ceiling still bounds storage cost and rejects pathological declared sizes
/// before a presigned URL is ever issued.
pub(crate) const MAX_ASSET_BYTES: i64 = 512 * 1024 * 1024;

/// Largest accepted original filename, in bytes. 255 is the de-facto filename
/// limit on every mainstream filesystem; the name is display-only metadata, so
/// nothing larger is ever useful.
pub(crate) const MAX_FILENAME_BYTES: usize = 255;

/// Exact length of a hex-encoded SHA-256 digest (32 bytes → 64 hex chars).
pub(crate) const SHA256_HEX_LEN: usize = 64;

/// Largest accepted storage key, in bytes. S3 caps object keys at 1024 bytes;
/// our keys are short (`{tenant}/{asset}`), so this only guards a corrupt read.
pub(crate) const MAX_STORAGE_KEY_BYTES: usize = 1024;

/// Largest page the list endpoint will return (CLAUDE.md §5: every batch capped).
pub(crate) const MAX_ASSETS_PER_PAGE: i64 = 100;

/// Default page size when the caller does not specify one.
pub(crate) const DEFAULT_ASSETS_PER_PAGE: i64 = 50;
