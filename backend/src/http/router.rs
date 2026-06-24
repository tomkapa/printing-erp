//! HTTP router assembly and global middleware.

use super::limits;
use super::routes::{auth, health, tenant};
use super::state::AppState;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::routing::{get, post};
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
        // Authentication (unauthenticated entry points).
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/password/forgot", post(auth::password_forgot))
        .route("/auth/password/reset", post(auth::password_reset))
        // Authenticated tenant echo: resolves the tenant from a verified access
        // token (`AuthPrincipal`) and reports its RLS-visible user count.
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
