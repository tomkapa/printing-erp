//! Tenant-context route.
//!
//! `me` reports the authenticated principal and how many users are visible under
//! Row-Level Security. The tenant now comes from a verified access-token claim
//! ([`AuthPrincipal`]) rather than a client header, so it doubles as the
//! end-to-end check that the auth → RLS path is wired correctly.

use crate::db;
use crate::domain::{Role, TenantId, UserId};
use crate::http::AuthPrincipal;
use crate::http::limits;
use crate::http::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use tokio::time::timeout;

/// Body of the `GET /tenant/me` response.
#[derive(Debug, Serialize)]
pub(crate) struct TenantMeBody {
    tenant_id: TenantId,
    user_id: UserId,
    role: Role,
    /// Users visible to this tenant under RLS — proves the scope is applied.
    user_count: i64,
}

/// `GET /tenant/me` — echoes the authenticated principal and its RLS-visible
/// user count.
pub(crate) async fn me(
    State(state): State<AppState>,
    principal: AuthPrincipal,
) -> Result<Json<TenantMeBody>, StatusCode> {
    // The whole tenant-scoped round-trip is bounded (CLAUDE.md §5): a stalled
    // server or lock wait frees the pooled connection instead of hanging until
    // the global request timeout.
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, principal.tenant_id).await?;
        let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok::<i64, db::DbError>(user_count)
    };
    let user_count = timeout(limits::TENANT_QUERY_TIMEOUT, work)
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    Ok(Json(TenantMeBody {
        tenant_id: principal.tenant_id,
        user_id: principal.user_id,
        role: principal.role,
        user_count,
    }))
}

/// Logs an unexpected failure and maps it to a 500 (CLAUDE.md §2).
fn internal_error<E: std::fmt::Debug>(error: E) -> StatusCode {
    tracing::error!(error = ?error, event = "tenant.me.failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[cfg(test)]
mod tests {
    use super::me;
    use crate::domain::{Role, TenantId, UserId};
    use crate::http::AppState;
    use crate::testsupport;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use http_body_util::BodyExt as _;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::time::Duration;
    use tower::ServiceExt as _;

    fn app(state: AppState) -> Router {
        Router::new().route("/tenant/me", get(me)).with_state(state)
    }

    /// Mints a valid access token for `user`/`tenant`/`role` at the test epoch.
    fn bearer(state: &AppState, user: UserId, tenant: TenantId, role: Role) -> String {
        let token = state
            .auth()
            .issue_access(user, tenant, role, testsupport::epoch())
            .expect("issue access token");
        format!("Bearer {token}")
    }

    async fn get_me(state: AppState, authorization: Option<String>) -> StatusCode {
        let mut builder = Request::builder().uri("/tenant/me");
        if let Some(value) = authorization {
            builder = builder.header("authorization", value);
        }
        let req = builder.body(Body::empty()).expect("build request");
        app(state)
            .oneshot(req)
            .await
            .expect("router responds")
            .status()
    }

    #[sqlx::test]
    async fn valid_bearer_resolves_principal_and_counts_users(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let pool = testsupport::app_pool(opts, conn).await;
        let tenant = testsupport::new_tenant();
        testsupport::seed_tenant(&pool, tenant, "acme").await;
        let user =
            testsupport::seed_user(&pool, tenant, "a@acme.test", Role::Admin, "x", true).await;

        let state =
            testsupport::app_state(pool, testsupport::test_clock(), testsupport::auth_context())
                .await;
        let auth = bearer(&state, user, tenant, Role::Admin);
        let req = Request::builder()
            .uri("/tenant/me")
            .header("authorization", auth)
            .body(Body::empty())
            .expect("request");

        let response = app(state).oneshot(req).await.expect("responds");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(body["user_count"], 1, "tenant sees its single user");
        assert_eq!(body["role"], "admin", "principal role is echoed");
        assert_eq!(body["tenant_id"], tenant.as_uuid().to_string());
        assert_eq!(body["user_id"], user.as_uuid().to_string());
    }

    #[sqlx::test]
    async fn missing_bearer_is_unauthorized(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let state =
            testsupport::app_state(pool, testsupport::test_clock(), testsupport::auth_context())
                .await;
        assert_eq!(get_me(state, None).await, StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test]
    async fn expired_token_is_unauthorized(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let tenant = testsupport::new_tenant();
        testsupport::seed_tenant(&pool, tenant, "acme").await;
        let user =
            testsupport::seed_user(&pool, tenant, "a@acme.test", Role::Sales, "x", true).await;

        let clock = testsupport::test_clock();
        let state = testsupport::app_state(pool, clock.clone(), testsupport::auth_context()).await;
        let auth = bearer(&state, user, tenant, Role::Sales);

        // Move past the 900s access-token lifetime; the extractor's clock-based
        // check must now reject the token.
        clock.advance(Duration::from_secs(901));
        assert_eq!(get_me(state, Some(auth)).await, StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test]
    async fn token_tenant_claim_drives_row_level_security(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let pool = testsupport::app_pool(opts, conn).await;
        let (a, b) = (testsupport::new_tenant(), testsupport::new_tenant());
        testsupport::seed_tenant(&pool, a, "tenant-a").await;
        testsupport::seed_tenant(&pool, b, "tenant-b").await;
        let user_a = testsupport::seed_user(&pool, a, "a@a.test", Role::Admin, "x", true).await;
        testsupport::seed_user(&pool, b, "b1@b.test", Role::Admin, "x", true).await;
        testsupport::seed_user(&pool, b, "b2@b.test", Role::Admin, "x", true).await;

        // A token scoped to tenant A must see only A's one user, never B's two.
        let state =
            testsupport::app_state(pool, testsupport::test_clock(), testsupport::auth_context())
                .await;
        let auth = bearer(&state, user_a, a, Role::Admin);
        let req = Request::builder()
            .uri("/tenant/me")
            .header("authorization", auth)
            .body(Body::empty())
            .expect("request");

        let response = app(state).oneshot(req).await.expect("responds");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["user_count"], 1, "tenant A's token sees only tenant A");
    }
}
