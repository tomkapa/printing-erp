//! Tenant-context routes.
//!
//! `me` resolves the request's tenant via [`TenantScope`], opens a tenant-scoped
//! transaction with [`db::begin_tenant_tx`], and reports how many users are
//! visible under Row-Level Security. It is a development aid that exercises the
//! whole isolation path end-to-end (see [`crate::http::tenant`] for the pre-auth
//! security caveat); real tenant-scoped resources arrive in later issues.

use crate::db;
use crate::domain::TenantId;
use crate::http::limits;
use crate::http::state::AppState;
use crate::http::tenant::TenantScope;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use tokio::time::timeout;

/// Body of the `GET /tenant/me` response.
#[derive(Debug, Serialize)]
pub(crate) struct TenantMeBody {
    tenant_id: TenantId,
    /// Users visible to this tenant under RLS — proves the scope is applied.
    user_count: i64,
}

/// `GET /tenant/me` — echoes the resolved tenant and its RLS-visible user count.
pub(crate) async fn me(
    State(state): State<AppState>,
    TenantScope(tenant): TenantScope,
) -> Result<Json<TenantMeBody>, StatusCode> {
    // The whole tenant-scoped round-trip is bounded (CLAUDE.md §5), like the
    // readiness probe in `health.rs`: a stalled server or lock wait frees the
    // pooled connection instead of hanging until the global request timeout.
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
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
        tenant_id: tenant,
        user_count,
    }))
}

/// Logs an unexpected failure and maps it to a 500 (CLAUDE.md §2).
fn internal_error<E: std::fmt::Debug>(error: E) -> StatusCode {
    tracing::error!(error = ?error, event = "tenant.me.failed");
    StatusCode::INTERNAL_SERVER_ERROR
}
