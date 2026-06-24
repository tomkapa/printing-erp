//! Hard limits for the object-storage transport (CLAUDE.md §5).
//!
//! Asset *content* bounds (max size, filename length) live in
//! [`crate::assets`]; these are the transport-level knobs: how long a presigned
//! URL is valid and how long a single store round-trip may block.

use std::time::Duration;

/// Validity window of a presigned upload (PUT) URL. Long enough for a large
/// print file over a slow connection, short enough that a leaked URL is a brief
/// exposure rather than a standing capability.
pub(crate) const PRESIGN_PUT_TTL: Duration = Duration::from_secs(15 * 60);

/// Validity window of a presigned download (GET) URL. Tighter than the upload
/// window: downloads are issued on demand right before use.
pub(crate) const PRESIGN_GET_TTL: Duration = Duration::from_secs(5 * 60);

/// Upper bound on a single object-store network call (`head`/`delete`). Generous
/// for a metadata round-trip, tight enough to free the request rather than hang
/// until the global HTTP timeout (CLAUDE.md §5: every I/O await is bounded).
pub(crate) const STORAGE_OP_TIMEOUT: Duration = Duration::from_secs(10);
