//! Application wiring: build resources, mount the router, serve until shutdown.

use crate::clock::SystemClock;
use crate::config::{RedisSettings, Settings};
use crate::http::{self, AppState};
use crate::storage::S3ObjectStore;
use redis::aio::ConnectionManager;
use secrecy::ExposeSecret as _;
use std::sync::Arc;
use thiserror::Error;

/// Failure while starting or running the HTTP server.
#[derive(Debug, Error)]
pub(crate) enum ServerError {
    /// Database pool construction or migration failed.
    #[error(transparent)]
    Db(#[from] crate::db::DbError),

    /// The Redis connection manager could not be established.
    #[error("redis connection failed")]
    Redis(#[from] redis::RedisError),

    /// The object-storage client could not be constructed (misconfiguration).
    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),

    /// Binding the TCP listener or serving the app failed.
    #[error("server I/O error")]
    Io(#[from] std::io::Error),
}

/// Starts the server and blocks until graceful shutdown completes.
///
/// # Errors
///
/// Returns [`ServerError`] if the database pool or migrations fail, Redis is
/// unreachable, or the TCP listener cannot bind / serve.
pub(crate) async fn run(settings: Settings) -> Result<(), ServerError> {
    // Migrations run as the admin role (DDL); the serving pool then connects as
    // the least-privilege role so Row-Level Security applies to every request.
    crate::db::migrate(&settings.database).await?;
    let db = crate::db::connect(&settings.database).await?;
    let redis = connect_redis(&settings.redis).await?;
    // Build the object-storage client once at startup (CLAUDE.md §9).
    let store = Arc::new(S3ObjectStore::new(&settings.storage)?);

    let state = AppState::new(db, redis, store, Arc::new(SystemClock));
    let app = http::router(state);

    let address = settings.server.bind_address();
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!(event = "server.started", address = %address);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!(event = "server.stopped");
    Ok(())
}

/// Opens a multiplexed, auto-reconnecting Redis connection.
async fn connect_redis(settings: &RedisSettings) -> Result<ConnectionManager, ServerError> {
    let client = redis::Client::open(settings.url.expose_secret())?;
    let manager = ConnectionManager::new(client).await?;
    Ok(manager)
}

/// Resolves when the process receives `Ctrl+C` or (on Unix) `SIGTERM`.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(error = ?error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => tracing::error!(error = ?error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!(event = "server.shutdown.signal_received");
}
