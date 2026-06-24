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

/// Maximum accepted length of the `X-Tenant-Id` header value, in bytes
/// (CLAUDE.md §5: every string crossing a trust boundary is length-capped).
/// A canonical UUID is 36 chars; 40 leaves room for brace/URN-prefixed forms
/// that `Uuid::parse_str` accepts while rejecting anything pathological before
/// it reaches the parser.
pub(crate) const MAX_TENANT_HEADER_BYTES: usize = 40;

/// Upper bound on a tenant-scoped database round-trip from a request handler
/// (CLAUDE.md §5: every I/O await is bounded). Generous for an OLTP query, but
/// tight enough to free the pooled connection on a stalled server or lock wait
/// rather than hang until the global request timeout fires.
pub(crate) const TENANT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
