//! Hard limits for the HTTP surface (CLAUDE.md §5).
//!
//! Every bound lives here, named and documented with *why this number*, rather
//! than as a magic literal in request-handling logic.

use std::time::Duration;

/// Maximum time a single request may run before the server aborts it.
/// Generous enough for report generation, short enough to free a worker slot
/// and surface upstream stalls.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum accepted request body size (2 MiB). JSON API payloads are small;
/// large design files are uploaded to object storage out of band.
pub(crate) const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Per-dependency timeout for readiness probes. Kept tight so an unhealthy
/// backing service is reported quickly rather than hanging the probe.
pub(crate) const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum accepted `Authorization` header length, in bytes (CLAUDE.md §5:
/// every string crossing a trust boundary is length-capped). An HS256 JWT for
/// our small claim set is well under 1 KiB; 4 KiB leaves headroom while bounding
/// parse work before any signature verification.
pub(crate) const MAX_AUTH_HEADER_BYTES: usize = 4 * 1024;

/// Upper bound on a tenant-scoped database round-trip from a request handler
/// (CLAUDE.md §5: every I/O await is bounded). Generous for an OLTP query, but
/// tight enough to free the pooled connection on a stalled server or lock wait
/// rather than hang until the global request timeout fires.
pub(crate) const TENANT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on a business-settings read/upsert round-trip (CLAUDE.md §5).
/// A single-row keyed access; the same rationale as [`TENANT_QUERY_TIMEOUT`].
pub(crate) const SETTINGS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on a user-management DB round-trip (CLAUDE.md §5). A tenant's
/// roster is small and every access is keyed or a short page; the same rationale
/// as [`TENANT_QUERY_TIMEOUT`].
pub(crate) const USER_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest page the user-list endpoint returns (CLAUDE.md §5: every batch is
/// capped). A tenant's user roster is small, so 100 is generous.
pub(crate) const MAX_USERS_PER_PAGE: i64 = 100;

/// Default user page size when the caller does not specify one.
pub(crate) const DEFAULT_USERS_PER_PAGE: i64 = 50;

/// Largest accepted user-list offset (CLAUDE.md §5: every scan is bounded). At
/// 100 rows/page this is 100 pages deep — far past any realistic roster — while
/// stopping a client from forcing an unbounded `OFFSET` scan.
pub(crate) const MAX_USERS_OFFSET: i64 = 100 * MAX_USERS_PER_PAGE;
