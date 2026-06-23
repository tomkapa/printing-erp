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
