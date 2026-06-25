//! HTTP router assembly and global middleware.

use super::limits;
use super::routes::{assets, auth, health, settings, tenant, users};
use super::state::AppState;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::routing::{get, patch, post};
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
        // Asset upload/download. Bytes move out of band via presigned URLs, so
        // these endpoints carry only small JSON metadata.
        .route("/assets", post(assets::create).get(assets::list))
        .route("/assets/{id}", get(assets::get_one).delete(assets::delete))
        .route("/assets/{id}/complete", post(assets::complete))
        // Per-tenant business configuration (logo, identity, tax, currency,
        // default unit). Authenticated via the same `AuthPrincipal` extractor.
        .route(
            "/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        // User management ("role center"): list/create/modify tenant users and
        // their roles. Admin-only, enforced by the `Require<ManageUsers>` guard.
        .route("/users", post(users::create_user).get(users::list_users))
        .route("/users/{id}", patch(users::update_user))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits::REQUEST_TIMEOUT,
        ))
        .layer(DefaultBodyLimit::max(limits::MAX_BODY_BYTES))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
