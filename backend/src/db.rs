//! PostgreSQL access.
//!
//! The pool is built once at startup from [`DatabaseSettings`] (CLAUDE.md §9)
//! and threaded through the application as `&PgPool`. Migrations live in
//! `backend/migrations` and are embedded at compile time.

use crate::config::DatabaseSettings;
use secrecy::ExposeSecret as _;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use thiserror::Error;

/// Embedded, reversible migrations applied by [`migrate`].
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Failure while connecting to PostgreSQL or running migrations.
#[derive(Debug, Error)]
pub(crate) enum DbError {
    /// A query or connection-pool operation failed.
    #[error(transparent)]
    Query(#[from] sqlx::Error),

    /// Applying embedded migrations failed.
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Builds the bounded PostgreSQL connection pool.
///
/// The pool size and acquire timeout are fixed at construction per CLAUDE.md
/// §5 / §9; no growth on demand inside request handlers.
///
/// # Errors
///
/// Returns [`DbError::Query`] if the pool cannot establish its connections
/// within the configured acquire timeout.
pub(crate) async fn connect(settings: &DatabaseSettings) -> Result<PgPool, DbError> {
    let pool = PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout())
        .connect(settings.url.expose_secret())
        .await?;
    Ok(pool)
}

/// Runs all pending migrations against the pool.
///
/// # Errors
///
/// Returns [`DbError::Migrate`] if a migration fails or the recorded migration
/// history diverges from the embedded set.
pub(crate) async fn migrate(pool: &PgPool) -> Result<(), DbError> {
    MIGRATOR.run(pool).await?;
    Ok(())
}

/// Liveness probe: confirms a connection can round-trip a trivial query.
///
/// # Errors
///
/// Returns [`DbError::Query`] if no connection is available or the query fails.
pub(crate) async fn ping(pool: &PgPool) -> Result<(), DbError> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}
