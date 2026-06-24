//! HTTP router assembly and global middleware.

use super::limits;
use super::routes::{health, tenant};
use super::state::AppState;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::routing::get;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Builds the application router with health routes and the middleware stack.
///
/// Middleware applies the cross-cutting limits from [`limits`]: a per-request
/// timeout, a body-size cap, and HTTP tracing that opens a root span per
/// request (CLAUDE.md §2, §5).
pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        // Pre-auth tenant echo: demonstrates the `TenantScope` extractor
        // end-to-end (see `http::tenant`). Replaced by authenticated routing
        // when auth lands.
        .route("/tenant/me", get(tenant::me))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits::REQUEST_TIMEOUT,
        ))
        .layer(DefaultBodyLimit::max(limits::MAX_BODY_BYTES))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
