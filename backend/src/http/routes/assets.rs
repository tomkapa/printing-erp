//! Asset upload/download routes.
//!
//! Every handler resolves the tenant from the authenticated principal (via the
//! [`Require`] guard, which also enforces the caller's role — RBAC, issue #13),
//! runs DB work inside a [`db::begin_tenant_tx`] (so Row-Level Security applies),
//! and bounds every I/O await with a timeout (CLAUDE.md §5). Bytes never transit
//! the API: clients upload and download directly through presigned URLs.
//!
//! Flow: `POST /api/assets` records a `pending` row and returns a presigned PUT →
//! the client uploads → `POST /api/assets/{id}/complete` HEAD-verifies and marks it
//! `ready`. `GET /api/assets/{id}` returns a presigned download URL.

use crate::assets::limits as asset_limits;
use crate::assets::{
    Asset, AssetError, AssetStatus, ByteSize, ContentType, FileName, Sha256Hex, StorageKey, repo,
};
use crate::authz::{CreateAsset, DeleteAsset, ReadAsset};
use crate::db;
use crate::domain::{AssetId, TenantId};
use crate::http::Require;
use crate::http::limits as http_limits;
use crate::http::state::AppState;
use crate::storage::PresignedUrl;
use crate::storage::limits as storage_limits;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

/// `POST /api/assets` request: the client declares what it is about to upload.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateAssetRequest {
    filename: FileName,
    content_type: ContentType,
    size_bytes: ByteSize,
}

/// `POST /api/assets` response: where and for how long to upload.
#[derive(Debug, Serialize)]
pub(crate) struct CreateAssetResponse {
    asset_id: AssetId,
    upload_url: PresignedUrl,
    expires_in_secs: u64,
}

/// Public metadata view of an asset (no raw storage key).
#[derive(Debug, Serialize)]
pub(crate) struct AssetView {
    id: AssetId,
    filename: FileName,
    content_type: ContentType,
    size_bytes: ByteSize,
    status: AssetStatus,
    checksum_sha256: Option<Sha256Hex>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// `GET /api/assets/{id}` response: metadata plus a presigned download URL.
#[derive(Debug, Serialize)]
pub(crate) struct AssetDetail {
    #[serde(flatten)]
    asset: AssetView,
    download_url: PresignedUrl,
    download_expires_in_secs: u64,
}

/// `GET /api/assets` pagination parameters.
#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

/// `POST /api/assets` — record a pending asset and issue a presigned upload URL.
pub(crate) async fn create(
    State(state): State<AppState>,
    guard: Require<CreateAsset>,
    Json(request): Json<CreateAssetRequest>,
) -> Result<(StatusCode, Json<CreateAssetResponse>), AssetError> {
    let principal = guard.principal;
    let tenant = principal.tenant_id;
    let asset = AssetId::try_from(Uuid::new_v4())?;
    let key = StorageKey::new(tenant, asset);

    // Presign first, so a DB failure never leaves a usable URL for an
    // unrecorded object; then persist the pending row.
    let upload_url = timeout(
        storage_limits::STORAGE_OP_TIMEOUT,
        state
            .store
            .presign_put(&key, request.content_type, storage_limits::PRESIGN_PUT_TTL),
    )
    .await??;

    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        repo::insert_pending(
            &mut tx,
            tenant,
            asset,
            &request.filename,
            request.content_type,
            request.size_bytes,
            principal.user_id,
        )
        .await?;
        tx.commit().await?;
        Ok::<(), AssetError>(())
    };
    timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;

    Ok((
        StatusCode::CREATED,
        Json(CreateAssetResponse {
            asset_id: asset,
            upload_url,
            expires_in_secs: storage_limits::PRESIGN_PUT_TTL.as_secs(),
        }),
    ))
}

/// `POST /api/assets/{id}/complete` — verify the uploaded bytes and mark `ready`.
pub(crate) async fn complete(
    State(state): State<AppState>,
    guard: Require<CreateAsset>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetView>, AssetError> {
    let principal = guard.principal;
    let tenant = principal.tenant_id;
    let asset = AssetId::try_from(id)?;
    let existing = fetch(&state, tenant, asset).await?;
    assert!(existing.size_bytes.get() > 0, "persisted size is positive");

    let meta = timeout(
        storage_limits::STORAGE_OP_TIMEOUT,
        state.store.head(&existing.storage_key),
    )
    .await??;
    if meta.size_bytes != existing.size_bytes.get() {
        return Err(AssetError::SizeMismatch {
            declared: existing.size_bytes.get(),
            stored: meta.size_bytes,
        });
    }

    // Mark ready and read the updated row back in the same transaction, so the
    // response reflects the new state without a third round-trip. (We do not
    // hold this tx across the store HEAD above — that ran on its own.)
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        repo::mark_ready(&mut tx, asset, None).await?;
        let updated = repo::get(&mut tx, tenant, asset).await?;
        tx.commit().await?;
        Ok::<Asset, AssetError>(updated)
    };
    let updated = timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok(Json(view_of(updated)))
}

/// `GET /api/assets` — list this tenant's non-deleted assets, newest first.
pub(crate) async fn list(
    State(state): State<AppState>,
    guard: Require<ReadAsset>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<AssetView>>, AssetError> {
    let tenant = guard.principal.tenant_id;
    let limit = clamp_limit(query.limit);
    // Clamp the offset into `0..=MAX_ASSETS_OFFSET` so a client cannot force an
    // unbounded `OFFSET` scan (CLAUDE.md §5: every batch/scan is bounded).
    let offset = query
        .offset
        .unwrap_or(0)
        .clamp(0, asset_limits::MAX_ASSETS_OFFSET);

    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let assets = repo::list(&mut tx, limit, offset).await?;
        tx.commit().await?;
        Ok::<Vec<Asset>, AssetError>(assets)
    };
    let assets = timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;
    Ok(Json(assets.into_iter().map(view_of).collect()))
}

/// `GET /api/assets/{id}` — metadata plus a short-lived presigned download URL.
pub(crate) async fn get_one(
    State(state): State<AppState>,
    guard: Require<ReadAsset>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetDetail>, AssetError> {
    let tenant = guard.principal.tenant_id;
    let asset = AssetId::try_from(id)?;
    let existing = fetch(&state, tenant, asset).await?;

    let download_url = timeout(
        storage_limits::STORAGE_OP_TIMEOUT,
        state.store.presign_get(
            &existing.storage_key,
            storage_limits::PRESIGN_GET_TTL,
            &existing.original_name,
        ),
    )
    .await??;

    Ok(Json(AssetDetail {
        asset: view_of(existing),
        download_url,
        download_expires_in_secs: storage_limits::PRESIGN_GET_TTL.as_secs(),
    }))
}

/// `DELETE /api/assets/{id}` — remove the bytes and soft-delete the row.
pub(crate) async fn delete(
    State(state): State<AppState>,
    guard: Require<DeleteAsset>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AssetError> {
    let tenant = guard.principal.tenant_id;
    let asset = AssetId::try_from(id)?;
    let existing = fetch(&state, tenant, asset).await?;

    timeout(
        storage_limits::STORAGE_OP_TIMEOUT,
        state.store.delete(&existing.storage_key),
    )
    .await??;

    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        repo::soft_delete(&mut tx, asset).await?;
        tx.commit().await?;
        Ok::<(), AssetError>(())
    };
    timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await??;

    Ok(StatusCode::NO_CONTENT)
}

/// Fetches one asset inside a bounded tenant transaction.
async fn fetch(state: &AppState, tenant: TenantId, asset: AssetId) -> Result<Asset, AssetError> {
    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let asset = repo::get(&mut tx, tenant, asset).await?;
        tx.commit().await?;
        Ok::<Asset, AssetError>(asset)
    };
    timeout(http_limits::TENANT_QUERY_TIMEOUT, work).await?
}

/// Clamps a requested page size into `1..=MAX_ASSETS_PER_PAGE`, defaulting when
/// absent or non-positive — so [`repo::list`]'s entry assertions always hold.
fn clamp_limit(requested: Option<i64>) -> i64 {
    match requested {
        Some(n) if n > 0 => n.min(asset_limits::MAX_ASSETS_PER_PAGE),
        _ => asset_limits::DEFAULT_ASSETS_PER_PAGE,
    }
}

/// Projects a stored [`Asset`] into its public view (drops the raw storage key),
/// consuming it so the owned fields move rather than clone.
fn view_of(asset: Asset) -> AssetView {
    AssetView {
        id: asset.id,
        filename: asset.original_name,
        content_type: asset.content_type,
        size_bytes: asset.size_bytes,
        status: asset.status,
        checksum_sha256: asset.checksum_sha256,
        created_at: asset.created_at,
        updated_at: asset.updated_at,
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end handler tests: real router + the `Require` guard +
    //! tenant transaction against Postgres, with the in-memory object store
    //! standing in for S3. Requests carry a real Bearer access token minted from
    //! the test [`AuthContext`](crate::auth::AuthContext) (CLAUDE.md §3).

    use crate::domain::{AssetId, Role, TenantId};
    use crate::storage::InMemoryObjectStore;
    use crate::testsupport;
    use crate::{assets::ContentType, assets::StorageKey};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::Arc;
    use tower::ServiceExt as _;

    /// Builds the full router backed by a real DB pool, real Redis and the
    /// in-memory store, with a seeded tenant + user. Returns the store handle (so
    /// a test can simulate the client's direct upload), a `Bearer` header for the
    /// seeded user, and that user's tenant.
    async fn setup(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) -> (Router, InMemoryObjectStore, String, TenantId) {
        let pool = testsupport::app_pool(opts, conn).await;
        let tenant = testsupport::new_tenant();
        testsupport::seed_tenant(&pool, tenant, "acme").await;
        let user =
            testsupport::seed_user(&pool, tenant, "u@acme.test", Role::Admin, "x", true).await;

        let store = InMemoryObjectStore::default();
        let state = testsupport::app_state_with_store(
            pool,
            Arc::new(store.clone()),
            testsupport::test_clock(),
            testsupport::auth_context(),
        )
        .await;
        let token = state
            .auth()
            .issue_access(user, tenant, Role::Admin, testsupport::epoch())
            .expect("issue access token");
        (
            crate::http::router(state),
            store,
            format!("Bearer {token}"),
            tenant,
        )
    }

    fn post_json(uri: &str, bearer: &str, body: &serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", bearer)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("build request")
    }

    fn request(method: &str, uri: &str, bearer: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", bearer)
            .body(Body::empty())
            .expect("build request")
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app.oneshot(req).await.expect("router responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        // Success responses are JSON; error responses are plain text — tolerate
        // both so status-only assertions don't trip on a non-JSON body.
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn create_body() -> serde_json::Value {
        serde_json::json!({
            "filename": "business-card.pdf",
            "content_type": "application/pdf",
            "size_bytes": 2048,
        })
    }

    /// Creates an asset and returns its id (as a `Uuid` string) and key.
    async fn create_asset(app: &Router, bearer: &str, tenant: TenantId) -> (String, StorageKey) {
        let (status, body) = send(
            app.clone(),
            post_json("/api/assets", bearer, &create_body()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create returns 201");
        let id = body["asset_id"]
            .as_str()
            .expect("asset_id string")
            .to_owned();
        let asset = AssetId::try_from(id.as_str()).expect("valid asset id");
        (id, StorageKey::new(tenant, asset))
    }

    #[sqlx::test]
    async fn create_returns_upload_url_and_persists_pending(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let (app, _store, bearer, _tenant) = setup(opts, conn).await;
        let (status, body) = send(
            app.clone(),
            post_json("/api/assets", &bearer, &create_body()),
        )
        .await;

        assert_eq!(status, StatusCode::CREATED);
        assert!(
            body["upload_url"]
                .as_str()
                .is_some_and(|u| u.starts_with("memory://")),
            "a presigned upload URL is returned"
        );
        assert_eq!(body["expires_in_secs"].as_u64(), Some(900));

        // The pending asset is now listable.
        let (list_status, list_body) = send(app, request("GET", "/api/assets", &bearer)).await;
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(list_body.as_array().map(Vec::len), Some(1));
        assert_eq!(list_body[0]["status"], "pending");
    }

    #[sqlx::test]
    async fn create_rejects_unsupported_content_type(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (app, _store, bearer, _tenant) = setup(opts, conn).await;
        let body = serde_json::json!({
            "filename": "notes.txt",
            "content_type": "text/plain",
            "size_bytes": 10,
        });
        let (status, _) = send(app, post_json("/api/assets", &bearer, &body)).await;
        // The `ContentType` newtype rejects it during JSON deserialization.
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[sqlx::test]
    async fn complete_marks_ready_when_size_matches(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (app, store, bearer, tenant) = setup(opts, conn).await;
        let (id, key) = create_asset(&app, &bearer, tenant).await;
        store.put(&key, 2048, ContentType::Pdf); // simulate the client upload

        let (status, body) = send(
            app,
            request("POST", &format!("/api/assets/{id}/complete"), &bearer),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
    }

    #[sqlx::test]
    async fn complete_rejects_size_mismatch(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (app, store, bearer, tenant) = setup(opts, conn).await;
        let (id, key) = create_asset(&app, &bearer, tenant).await;
        store.put(&key, 1024, ContentType::Pdf); // declared 2048, uploaded 1024

        let (status, _) = send(
            app,
            request("POST", &format!("/api/assets/{id}/complete"), &bearer),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[sqlx::test]
    async fn get_one_returns_download_url(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (app, _store, bearer, tenant) = setup(opts, conn).await;
        let (id, _key) = create_asset(&app, &bearer, tenant).await;

        let (status, body) = send(app, request("GET", &format!("/api/assets/{id}"), &bearer)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["download_url"]
                .as_str()
                .is_some_and(|u| u.starts_with("memory://")),
            "a presigned download URL is returned"
        );
        assert_eq!(body["id"], id);
    }

    #[sqlx::test]
    async fn delete_soft_deletes_then_404(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (app, _store, bearer, tenant) = setup(opts, conn).await;
        let (id, _key) = create_asset(&app, &bearer, tenant).await;

        let (status, _) = send(
            app.clone(),
            request("DELETE", &format!("/api/assets/{id}"), &bearer),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (after, _) = send(app, request("GET", &format!("/api/assets/{id}"), &bearer)).await;
        assert_eq!(after, StatusCode::NOT_FOUND, "a deleted asset is gone");
    }

    #[sqlx::test]
    async fn missing_bearer_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (app, _store, _bearer, _tenant) = setup(opts, conn).await;
        let req = Request::builder()
            .uri("/api/assets")
            .body(Body::empty())
            .expect("build request");
        let (status, _) = send(app, req).await;
        // No token → the `Require` guard rejects with 401, not 400.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod authz_tests {
    //! RBAC matrix for `/assets` (issue #13): reads are open to every role;
    //! `CreateAsset` is admin/sales/coordinator; `DeleteAsset` is admin/coordinator.
    //! The guard reads the token's role claim, so one seeded user acts as any role.

    use crate::domain::{Role, TenantId, UserId};
    use crate::http::AppState;
    use crate::storage::InMemoryObjectStore;
    use crate::testsupport;
    use crate::testsupport::{bearer, send};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::Arc;

    async fn setup(opts: PgPoolOptions, conn: PgConnectOptions) -> (AppState, UserId, TenantId) {
        let pool = testsupport::app_pool(opts, conn).await;
        let tenant = testsupport::new_tenant();
        testsupport::seed_tenant(&pool, tenant, "acme").await;
        let user =
            testsupport::seed_user(&pool, tenant, "u@acme.test", Role::Admin, "x", true).await;
        let state = testsupport::app_state_with_store(
            pool,
            Arc::new(InMemoryObjectStore::default()),
            testsupport::test_clock(),
            testsupport::auth_context(),
        )
        .await;
        (state, user, tenant)
    }

    fn post_create(bearer: &str) -> Request<Body> {
        let body = serde_json::json!({
            "filename": "card.pdf",
            "content_type": "application/pdf",
            "size_bytes": 2048,
        });
        Request::builder()
            .method("POST")
            .uri("/api/assets")
            .header("authorization", bearer)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("build POST")
    }

    fn request(method: &str, uri: &str, bearer: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", bearer)
            .body(Body::empty())
            .expect("build request")
    }

    /// Creates a pending asset as admin and returns its id string.
    async fn create_as_admin(state: &AppState, user: UserId, tenant: TenantId) -> String {
        let admin = bearer(state, user, tenant, Role::Admin);
        let (status, body) = send(state, post_create(&admin)).await;
        assert_eq!(status, StatusCode::CREATED);
        body["asset_id"].as_str().expect("asset_id").to_owned()
    }

    #[sqlx::test]
    async fn create_asset_is_admin_sales_coordinator(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;

        for role in [Role::Admin, Role::Sales, Role::Coordinator] {
            let token = bearer(&state, user, tenant, role);
            let (status, _) = send(&state, post_create(&token)).await;
            assert_eq!(status, StatusCode::CREATED, "role {role:?} may create");
        }
        for role in [Role::Scheduler, Role::Operator] {
            let token = bearer(&state, user, tenant, role);
            let (status, _) = send(&state, post_create(&token)).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "role {role:?} may not create"
            );
        }
    }

    #[sqlx::test]
    async fn read_assets_is_allowed_for_every_role(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;
        for role in [
            Role::Admin,
            Role::Sales,
            Role::Coordinator,
            Role::Scheduler,
            Role::Operator,
        ] {
            let token = bearer(&state, user, tenant, role);
            let (status, _) = send(&state, request("GET", "/api/assets", &token)).await;
            assert_eq!(status, StatusCode::OK, "role {role:?} may list assets");
        }
    }

    #[sqlx::test]
    async fn delete_asset_is_admin_coordinator_only(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user, tenant) = setup(opts, conn).await;

        // Sales/scheduler/operator are refused before any work (403).
        for role in [Role::Sales, Role::Scheduler, Role::Operator] {
            let id = create_as_admin(&state, user, tenant).await;
            let token = bearer(&state, user, tenant, role);
            let (status, _) = send(
                &state,
                request("DELETE", &format!("/api/assets/{id}"), &token),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "role {role:?} may not delete"
            );
        }

        // Coordinator is permitted (admin too, by construction).
        let id = create_as_admin(&state, user, tenant).await;
        let coordinator = bearer(&state, user, tenant, Role::Coordinator);
        let (status, _) = send(
            &state,
            request("DELETE", &format!("/api/assets/{id}"), &coordinator),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "coordinator may delete");
    }
}
