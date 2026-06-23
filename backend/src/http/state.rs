//! Shared application state handed to every request handler.

use crate::clock::Clock;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;

/// Cheaply-cloneable handle to process-wide resources.
///
/// Cloned per request by axum; every field is itself a cheap handle (pool,
/// multiplexed Redis connection, `Arc`) so cloning never allocates a resource.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) redis: ConnectionManager,
    clock: Arc<dyn Clock>,
    started_at: Instant,
}

impl AppState {
    /// Assembles state from already-constructed resource handles.
    pub(crate) fn new(db: PgPool, redis: ConnectionManager, clock: Arc<dyn Clock>) -> Self {
        let started_at = clock.now();
        Self {
            db,
            redis,
            clock,
            started_at,
        }
    }

    /// Whole-seconds since the server started, via the injected clock.
    pub(crate) fn uptime_secs(&self) -> u64 {
        self.clock
            .now()
            .saturating_duration_since(self.started_at)
            .as_secs()
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db", &"PgPool")
            .field("redis", &"ConnectionManager")
            .field("clock", &self.clock)
            .field("started_at", &self.started_at)
            .finish()
    }
}
