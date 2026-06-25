//! HTTP router assembly and global middleware.

use super::limits;
use super::routes::{assets, auth, contacts, customers, health, settings, tenant, users};
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
/// Business routes are nested under `/api` so they share no path namespace with
/// the SPA, which is served at `/` and does its own client-side routing — a UI
/// route like `/settings` must not collide with the API. Health endpoints stay
/// at the top level for infrastructure probes (the Ingress routes only `/api`
/// and `/health` to this service).
///
/// Middleware applies the cross-cutting limits from [`limits`]: a per-request
/// timeout, a body-size cap, and HTTP tracing that opens a root span per
/// request (CLAUDE.md §2, §5). It wraps every route, `/health` included.
pub(crate) fn router(state: AppState) -> Router {
    // Business surface, mounted under `/api` below.
    let api = Router::new()
        // Authentication (unauthenticated entry points).
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/password/forgot", post(auth::password_forgot))
        .route("/auth/password/reset", post(auth::password_reset))
        // Authenticated tenant echo: resolves the tenant from a verified access
        // token (via the `Require` guard) and reports its RLS-visible user count.
        .route("/tenant/me", get(tenant::me))
        // Asset upload/download. Bytes move out of band via presigned URLs, so
        // these endpoints carry only small JSON metadata.
        .route("/assets", post(assets::create).get(assets::list))
        .route("/assets/{id}", get(assets::get_one).delete(assets::delete))
        .route("/assets/{id}/complete", post(assets::complete))
        // Per-tenant business configuration (logo, identity, tax, currency,
        // default unit). Authorized via the same `Require` guard.
        .route(
            "/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        // User management ("role center"): list/create/modify tenant users and
        // their roles. Admin-only, enforced by the `Require<ManageUsers>` guard.
        .route("/users", post(users::create_user).get(users::list_users))
        .route("/users/{id}", patch(users::update_user))
        // CRM (issue #17): customer profiles and their contacts. Codes are
        // system-assigned (`CS001`, …); removal is a soft archive. Contacts are a
        // sub-resource sharing the customer capabilities.
        .route("/customers", post(customers::create).get(customers::list))
        .route(
            "/customers/{id}",
            get(customers::get_one)
                .patch(customers::update)
                .delete(customers::delete),
        )
        .route(
            "/customers/{customer_id}/contacts",
            post(contacts::create).get(contacts::list),
        )
        .route(
            "/contacts/{id}",
            patch(contacts::update).delete(contacts::delete),
        );

    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .nest("/api", api)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits::REQUEST_TIMEOUT,
        ))
        .layer(DefaultBodyLimit::max(limits::MAX_BODY_BYTES))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
