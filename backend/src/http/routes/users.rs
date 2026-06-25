//! User-management ("role center") routes (RBAC, issue #13).
//!
//! Every handler is gated by [`Require<ManageUsers>`](crate::http::Require), so
//! only an admin may list, create, or modify users. Work runs inside a
//! [`db::begin_tenant_tx`] (Row-Level Security keys every row to the caller's
//! tenant — a target in another tenant is simply invisible, so cross-tenant
//! access surfaces as `404`, never a leak) and every I/O await is bounded
//! (CLAUDE.md §5).
//!
//! An admin sets the initial password at creation; it is hashed through the same
//! argon2id path as login ([`auth::hash_password`]). An invite-link flow (reusing
//! the reset-token machinery) is a deliberate follow-up.

use crate::auth::{PasswordError, hash_password};
use crate::authz::ManageUsers;
use crate::db;
use crate::domain::{DisplayName, Email, PlaintextPassword, Role, UserId};
use crate::http::Require;
use crate::http::limits;
use crate::http::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use thiserror::Error;
use tokio::time::timeout;
use uuid::Uuid;

/// `POST /api/users` request: an admin provisions a teammate with an initial password.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateUserRequest {
    email: Email,
    display_name: DisplayName,
    role: Role,
    password: PlaintextPassword,
}

/// `PATCH /api/users/{id}` request: change role and/or active state. Both are
/// optional, but at least one must be present (an empty patch is `422`).
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateUserRequest {
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    is_active: Option<bool>,
}

/// `GET /api/users` pagination parameters.
#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

/// Public view of a user — never includes the password hash.
#[derive(Debug, Serialize)]
pub(crate) struct UserView {
    id: UserId,
    email: Email,
    display_name: DisplayName,
    role: Role,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// A `users` row as fetched, before parsing into the typed [`UserView`] at the
/// boundary (CLAUDE.md §1). Column order matches every `SELECT`/`RETURNING` here.
type UserRow = (
    Uuid,
    String,
    String,
    Role,
    bool,
    DateTime<Utc>,
    DateTime<Utc>,
);

/// Why a user-management operation failed (CLAUDE.md §12). Client errors carry a
/// value-free body and are not logged; only server faults are recorded.
#[derive(Debug, Error)]
pub(crate) enum UsersError {
    /// No user with that id is visible to the caller's tenant.
    #[error("user not found")]
    NotFound,

    /// The `(tenant, email)` pair already exists.
    #[error("email already in use")]
    EmailTaken,

    /// A `PATCH` carried neither `role` nor `is_active`.
    #[error("no fields to update")]
    EmptyPatch,

    /// The change would leave the tenant with no active admin.
    #[error("cannot remove the last active admin")]
    LastAdmin,

    /// Hashing the initial password failed (an internal fault).
    #[error(transparent)]
    Hash(#[from] PasswordError),

    /// A database/transaction error.
    #[error(transparent)]
    Db(#[from] db::DbError),

    /// A stored row did not parse back into its domain types — corrupt data, an
    /// internal invariant violation rather than a client error.
    #[error("stored user row is malformed")]
    Corrupt,

    /// The bounded query exceeded [`limits::USER_QUERY_TIMEOUT`].
    #[error("users query timed out")]
    Timeout,
}

impl IntoResponse for UsersError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::EmailTaken | Self::LastAdmin => StatusCode::CONFLICT,
            Self::EmptyPatch => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Hash(_) | Self::Db(_) | Self::Corrupt => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
        };
        // Record only server-side faults; client errors are expected and
        // value-free (mirrors `SettingsError`/`AssetError`, CLAUDE.md §2).
        if status.is_server_error() {
            tracing::error!(error = ?self, event = "users.request.failed");
        }
        status.into_response()
    }
}

/// `GET /api/users` — list this tenant's users, newest first, paginated.
pub(crate) async fn list_users(
    State(state): State<AppState>,
    guard: Require<ManageUsers>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<UserView>>, UsersError> {
    let tenant = guard.principal.tenant_id;
    let limit = clamp_limit(query.limit);
    let offset = query.offset.unwrap_or(0).clamp(0, limits::MAX_USERS_OFFSET);
    assert!(limit > 0, "page limit is clamped positive");
    assert!(offset >= 0, "page offset is clamped non-negative");

    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let rows = sqlx::query_as::<_, UserRow>(
            "SELECT id, email, display_name, role, is_active, created_at, updated_at \
             FROM users ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await
        .map_err(db::DbError::from)?;
        tx.commit().await.map_err(db::DbError::from)?;
        Ok::<Vec<UserRow>, UsersError>(rows)
    };
    let rows = timeout(limits::USER_QUERY_TIMEOUT, work)
        .await
        .map_err(|_| UsersError::Timeout)??;
    assert!(
        i64::try_from(rows.len()).is_ok_and(|n| n <= limit),
        "LIMIT must bound the row count"
    );

    let views = rows
        .into_iter()
        .map(row_to_view)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(views))
}

/// `POST /api/users` — create a user with an admin-set initial password.
pub(crate) async fn create_user(
    State(state): State<AppState>,
    guard: Require<ManageUsers>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserView>), UsersError> {
    let tenant = guard.principal.tenant_id;
    // Hash before opening the transaction so the (CPU-bound) argon2 work does not
    // hold a pooled connection.
    let hash = hash_password(&request.password)?;
    assert!(!hash.as_str().is_empty(), "a hash is always non-empty");

    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        let row = insert_user(&mut tx, tenant, &request, hash.as_str()).await?;
        tx.commit().await.map_err(db::DbError::from)?;
        Ok::<UserRow, UsersError>(row)
    };
    let row = timeout(limits::USER_QUERY_TIMEOUT, work)
        .await
        .map_err(|_| UsersError::Timeout)??;
    // The INSERT … RETURNING must echo what we inserted (guards a column-order
    // drift between the SQL projection and `UserRow`).
    assert_eq!(
        row.1,
        request.email.as_str(),
        "inserted row echoes the requested email"
    );
    assert_eq!(
        row.3, request.role,
        "inserted row carries the requested role"
    );
    Ok((StatusCode::CREATED, Json(row_to_view(row)?)))
}

/// `PATCH /api/users/{id}` — change a user's role and/or active state.
pub(crate) async fn update_user(
    State(state): State<AppState>,
    guard: Require<ManageUsers>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserView>, UsersError> {
    let tenant = guard.principal.tenant_id;
    if request.role.is_none() && request.is_active.is_none() {
        return Err(UsersError::EmptyPatch);
    }
    // A nil/unknown id names no row; treat it as not-found rather than a 500.
    let target = UserId::try_from(id).map_err(|_| UsersError::NotFound)?;

    let work = async {
        let mut tx = db::begin_tenant_tx(&state.db, tenant).await?;
        // Enforce the last-admin invariant inside the same transaction as the
        // write, under a row lock, before patching (RBAC #13).
        assert_not_last_admin(&mut tx, target, &request).await?;
        let row = patch_user(&mut tx, target, &request).await?;
        tx.commit().await.map_err(db::DbError::from)?;
        Ok::<UserRow, UsersError>(row)
    };
    let row = timeout(limits::USER_QUERY_TIMEOUT, work)
        .await
        .map_err(|_| UsersError::Timeout)??;
    // Post-conditions: the UPDATE … RETURNING returned the targeted row and the
    // requested fields took effect (an absent field is left untouched).
    assert_eq!(row.0, target.as_uuid(), "patch returned the targeted row");
    if let Some(role) = request.role {
        assert_eq!(row.3, role, "requested role is reflected");
    }
    if let Some(active) = request.is_active {
        assert_eq!(row.4, active, "requested active state is reflected");
    }
    Ok(Json(row_to_view(row)?))
}

/// Inserts a new active user, translating a duplicate `(tenant, email)` into
/// [`UsersError::EmailTaken`] (`409`) rather than a generic `500`.
async fn insert_user(
    conn: &mut PgConnection,
    tenant: crate::domain::TenantId,
    request: &CreateUserRequest,
    password_hash: &str,
) -> Result<UserRow, UsersError> {
    let result = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (tenant_id, email, display_name, role, password_hash, is_active) \
         VALUES ($1, $2, $3, $4, $5, TRUE) \
         RETURNING id, email, display_name, role, is_active, created_at, updated_at",
    )
    .bind(tenant.as_uuid())
    .bind(request.email.as_str())
    .bind(request.display_name.as_str())
    .bind(request.role)
    .bind(password_hash)
    .fetch_one(&mut *conn)
    .await;
    match result {
        Ok(row) => Ok(row),
        Err(sqlx::Error::Database(dberr)) if dberr.is_unique_violation() => {
            Err(UsersError::EmailTaken)
        }
        Err(error) => Err(UsersError::Db(db::DbError::Query(error))),
    }
}

/// Applies a partial update with `COALESCE`, so an absent field is a no-op and
/// no part of the SQL is built from input (CLAUDE.md §10). `None` → `404`.
async fn patch_user(
    conn: &mut PgConnection,
    target: UserId,
    request: &UpdateUserRequest,
) -> Result<UserRow, UsersError> {
    let row = sqlx::query_as::<_, UserRow>(
        "UPDATE users \
         SET role = COALESCE($2, role), is_active = COALESCE($3, is_active), updated_at = now() \
         WHERE id = $1 \
         RETURNING id, email, display_name, role, is_active, created_at, updated_at",
    )
    .bind(target.as_uuid())
    .bind(request.role)
    .bind(request.is_active)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db::DbError::from)?;
    row.ok_or(UsersError::NotFound)
}

/// Refuses a `PATCH` that would leave the tenant with no active admin (CLAUDE.md
/// §6 — the invariant is guarded in app code, not a DB constraint).
///
/// Whether a change keeps the patch from touching the active-admin count is
/// decided from the request alone (an absent field leaves that dimension as-is):
/// a patch that keeps the role admin *and* keeps it active can only ever add or
/// preserve an admin, never remove one — so it needs no lock or read at all.
/// Only a demotion or a deactivation can reduce the count and must be checked.
///
/// When a check is needed, the active-admin set is locked `FOR UPDATE` in
/// canonical `id` order, then decided against that locked snapshot. The ordering
/// makes two concurrent demotions of different admins serialize without
/// deadlocking: the second transaction blocks on the first, then re-reads a set
/// that no longer includes the just-demoted admin, so it correctly sees itself
/// as the last one. Counting locked rows in Rust avoids `FOR UPDATE` on an
/// aggregate (which Postgres rejects).
async fn assert_not_last_admin(
    conn: &mut PgConnection,
    target: UserId,
    request: &UpdateUserRequest,
) -> Result<(), UsersError> {
    // Fast path, decided without any I/O: if the patch neither demotes nor
    // deactivates, it cannot drop an active admin — skip the query and the lock.
    let stays_admin = request.role.is_none_or(|role| matches!(role, Role::Admin));
    let stays_active = request.is_active.unwrap_or(true);
    if stays_admin && stays_active {
        return Ok(());
    }

    let active_admins: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users WHERE role = 'admin' AND is_active ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(db::DbError::from)?;

    // The patch removes admin capability, but only matters if the target is one
    // of the active admins today (existence / 404 is handled by the UPDATE).
    if !active_admins.contains(&target.as_uuid()) {
        return Ok(());
    }
    // The target is an active admin being demoted/deactivated — another must remain.
    assert!(
        !active_admins.is_empty(),
        "the target is among the locked active admins"
    );
    if active_admins.len() <= 1 {
        return Err(UsersError::LastAdmin);
    }
    Ok(())
}

/// Parses a stored row into its typed view at the boundary (CLAUDE.md §1). A
/// parse failure means corrupt data we wrote — an internal fault, not a client
/// error.
fn row_to_view(row: UserRow) -> Result<UserView, UsersError> {
    let (id, email, display_name, role, is_active, created_at, updated_at) = row;
    Ok(UserView {
        id: UserId::try_from(id).map_err(|_| UsersError::Corrupt)?,
        email: Email::try_from(email.as_str()).map_err(|_| UsersError::Corrupt)?,
        display_name: DisplayName::try_from(display_name).map_err(|_| UsersError::Corrupt)?,
        role,
        is_active,
        created_at,
        updated_at,
    })
}

/// Clamps a requested page size into `1..=MAX_USERS_PER_PAGE`, defaulting when
/// absent or non-positive — so the list query's entry assertions always hold.
fn clamp_limit(requested: Option<i64>) -> i64 {
    match requested {
        Some(n) if n > 0 => n.min(limits::MAX_USERS_PER_PAGE),
        _ => limits::DEFAULT_USERS_PER_PAGE,
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end `/users` tests: the full router and `Require<ManageUsers>`
    //! guard over a tenant transaction against real Postgres (CLAUDE.md §3). The
    //! seeded user is an admin; per-role tokens are minted to exercise the guard.

    use crate::domain::{Role, TenantId, UserId};
    use crate::http::AppState;
    use crate::testsupport;
    use crate::testsupport::{bearer, send};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    const PASSWORD: &str = "correct horse battery"; // ≥ 12 bytes

    async fn setup(opts: PgPoolOptions, conn: PgConnectOptions) -> (AppState, UserId, TenantId) {
        let pool = testsupport::app_pool(opts, conn).await;
        let tenant = testsupport::new_tenant();
        testsupport::seed_tenant(&pool, tenant, "acme").await;
        let admin =
            testsupport::seed_user(&pool, tenant, "admin@acme.test", Role::Admin, "x", true).await;
        let state =
            testsupport::app_state(pool, testsupport::test_clock(), testsupport::auth_context())
                .await;
        (state, admin, tenant)
    }

    fn json_request(
        method: &str,
        uri: &str,
        bearer: &str,
        body: &serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", bearer)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("build request")
    }

    fn empty_request(method: &str, uri: &str, authorization: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(value) = authorization {
            builder = builder.header("authorization", value);
        }
        builder.body(Body::empty()).expect("build request")
    }

    fn create_body(email: &str, role: &str) -> serde_json::Value {
        serde_json::json!({
            "email": email,
            "display_name": "New Teammate",
            "role": role,
            "password": PASSWORD,
        })
    }

    /// Creates a user as admin and returns its id string.
    async fn create_as_admin(state: &AppState, admin: &str, email: &str, role: &str) -> String {
        let (status, body) = send(
            state,
            json_request("POST", "/api/users", admin, &create_body(email, role)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "admin creates a user");
        body["id"].as_str().expect("id string").to_owned()
    }

    #[sqlx::test]
    async fn create_user_persists_and_is_listable(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);

        let (status, body) = send(
            &state,
            json_request(
                "POST",
                "/api/users",
                &admin,
                &create_body("sales@acme.test", "sales"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["email"], "sales@acme.test");
        assert_eq!(body["display_name"], "New Teammate");
        assert_eq!(body["role"], "sales");
        assert_eq!(body["is_active"], true);
        assert!(
            body.get("password").is_none() && body.get("password_hash").is_none(),
            "the response must never expose password material"
        );

        // The new user plus the seeded admin are both listed.
        let (list_status, list) =
            send(&state, empty_request("GET", "/api/users", Some(&admin))).await;
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(list.as_array().map(Vec::len), Some(2), "admin + new user");
    }

    #[sqlx::test]
    async fn create_user_then_login_succeeds(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        create_as_admin(&state, &admin, "operator@acme.test", "operator").await;

        // The admin-set password must authenticate through the real login path —
        // proving the hash was produced by the shared argon2id routine.
        let login = serde_json::json!({
            "tenant_slug": "acme",
            "email": "operator@acme.test",
            "password": PASSWORD,
        });
        let (status, body) = send(
            &state,
            json_request("POST", "/api/auth/login", "ignored", &login),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the created user can log in");
        assert!(
            body["access_token"].as_str().is_some(),
            "login returns an access token"
        );
    }

    #[sqlx::test]
    async fn create_duplicate_email_is_conflict(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        create_as_admin(&state, &admin, "dup@acme.test", "sales").await;

        let (status, _) = send(
            &state,
            json_request(
                "POST",
                "/api/users",
                &admin,
                &create_body("dup@acme.test", "operator"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "duplicate email is 409");
    }

    #[sqlx::test]
    async fn list_is_tenant_isolated(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_a, tenant_a) = setup(opts, conn).await;
        let admin_token_a = bearer(&state, admin_a, tenant_a, Role::Admin);
        create_as_admin(&state, &admin_token_a, "sales@acme.test", "sales").await;

        // A second tenant with its own admin must not see tenant A's users.
        let tenant_b = testsupport::new_tenant();
        testsupport::seed_tenant(&state.db, tenant_b, "beta").await;
        let admin_b = testsupport::seed_user(
            &state.db,
            tenant_b,
            "admin@beta.test",
            Role::Admin,
            "x",
            true,
        )
        .await;
        let admin_token_b = bearer(&state, admin_b, tenant_b, Role::Admin);

        let (status, list) = send(
            &state,
            empty_request("GET", "/api/users", Some(&admin_token_b)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            list.as_array().map(Vec::len),
            Some(1),
            "tenant B sees only its own admin, never tenant A's users"
        );
    }

    #[sqlx::test]
    async fn patch_changes_role(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        let id = create_as_admin(&state, &admin, "u@acme.test", "operator").await;

        let (status, body) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/users/{id}"),
                &admin,
                &serde_json::json!({"role": "coordinator"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["role"], "coordinator", "role is updated");
        assert_eq!(body["is_active"], true, "is_active is untouched");
    }

    #[sqlx::test]
    async fn patch_deactivates_user(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        let id = create_as_admin(&state, &admin, "u@acme.test", "sales").await;

        let (status, body) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/users/{id}"),
                &admin,
                &serde_json::json!({"is_active": false}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["is_active"], false, "user is deactivated");
        assert_eq!(body["role"], "sales", "role is untouched");
    }

    #[sqlx::test]
    async fn patch_unknown_user_is_404(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        let missing = uuid::Uuid::new_v4();
        let (status, _) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/users/{missing}"),
                &admin,
                &serde_json::json!({"role": "sales"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn patch_empty_body_is_422(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        let id = create_as_admin(&state, &admin, "u@acme.test", "sales").await;
        let (status, _) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/users/{id}"),
                &admin,
                &serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "empty patch is rejected"
        );
    }

    #[sqlx::test]
    async fn users_api_is_admin_only(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, user_id, tenant) = setup(opts, conn).await;
        for role in [
            Role::Sales,
            Role::Coordinator,
            Role::Scheduler,
            Role::Operator,
        ] {
            let token = bearer(&state, user_id, tenant, role);
            let (get_status, _) =
                send(&state, empty_request("GET", "/api/users", Some(&token))).await;
            assert_eq!(
                get_status,
                StatusCode::FORBIDDEN,
                "{role:?} cannot list users"
            );

            let (post_status, _) = send(
                &state,
                json_request(
                    "POST",
                    "/api/users",
                    &token,
                    &create_body("x@acme.test", "sales"),
                ),
            )
            .await;
            assert_eq!(
                post_status,
                StatusCode::FORBIDDEN,
                "{role:?} cannot create users"
            );

            let some_id = uuid::Uuid::new_v4();
            let (patch_status, _) = send(
                &state,
                json_request(
                    "PATCH",
                    &format!("/api/users/{some_id}"),
                    &token,
                    &serde_json::json!({"role": "sales"}),
                ),
            )
            .await;
            assert_eq!(
                patch_status,
                StatusCode::FORBIDDEN,
                "{role:?} cannot modify users"
            );
        }
    }

    #[sqlx::test]
    async fn missing_token_is_401_not_403(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, _admin, _tenant) = setup(opts, conn).await;
        // Authn precedes authz: no token is 401, and must not leak (via 403) that
        // the route needs ManageUsers.
        let (status, _) = send(&state, empty_request("GET", "/api/users", None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// Reads one user's `(role, is_active)` from the listing, by id.
    async fn user_state(state: &AppState, admin: &str, id: &str) -> (String, bool) {
        let (status, list) = send(state, empty_request("GET", "/api/users", Some(admin))).await;
        assert_eq!(status, StatusCode::OK);
        let entry = list
            .as_array()
            .expect("array")
            .iter()
            .find(|u| u["id"] == id)
            .expect("user present");
        (
            entry["role"].as_str().expect("role").to_owned(),
            entry["is_active"].as_bool().expect("is_active"),
        )
    }

    #[sqlx::test]
    async fn cannot_demote_the_sole_active_admin(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        let id = admin_id.as_uuid().to_string();

        // The acting admin is the only one; demoting itself must be refused.
        let (status, _) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/users/{id}"),
                &admin,
                &serde_json::json!({"role": "operator"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "last admin cannot be demoted");
        assert_eq!(
            user_state(&state, &admin, &id).await,
            ("admin".to_owned(), true),
            "the row is unchanged after the refused demotion"
        );
    }

    #[sqlx::test]
    async fn cannot_deactivate_the_sole_active_admin(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        let id = admin_id.as_uuid().to_string();

        let (status, _) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/users/{id}"),
                &admin,
                &serde_json::json!({"is_active": false}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "last admin cannot be deactivated"
        );
        assert_eq!(
            user_state(&state, &admin, &id).await,
            ("admin".to_owned(), true)
        );
    }

    #[sqlx::test]
    async fn can_demote_admin_when_another_active_admin_exists(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        // Seed a second active admin, so demoting the first is allowed.
        let second = testsupport::seed_user(
            &state.db,
            tenant,
            "admin2@acme.test",
            Role::Admin,
            "x",
            true,
        )
        .await;
        let id = second.as_uuid().to_string();

        let (status, body) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/users/{id}"),
                &admin,
                &serde_json::json!({"role": "sales"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a non-last admin may be demoted");
        assert_eq!(body["role"], "sales");
    }

    #[sqlx::test]
    async fn inactive_admin_does_not_satisfy_the_invariant(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let (state, admin_id, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_id, tenant, Role::Admin);
        // A second admin exists but is inactive — it cannot keep the tenant
        // administrable, so demoting the sole *active* admin is still refused.
        testsupport::seed_user(
            &state.db,
            tenant,
            "dormant@acme.test",
            Role::Admin,
            "x",
            false,
        )
        .await;
        let id = admin_id.as_uuid().to_string();

        let (status, _) = send(
            &state,
            json_request(
                "PATCH",
                &format!("/api/users/{id}"),
                &admin,
                &serde_json::json!({"role": "operator"}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "an inactive admin does not count"
        );
    }

    #[sqlx::test]
    async fn concurrent_demotions_keep_one_admin(opts: PgPoolOptions, conn: PgConnectOptions) {
        let (state, admin_a, tenant) = setup(opts, conn).await;
        let admin = bearer(&state, admin_a, tenant, Role::Admin);
        let admin_b = testsupport::seed_user(
            &state.db,
            tenant,
            "admin2@acme.test",
            Role::Admin,
            "x",
            true,
        )
        .await;

        // Two admins, each demoted concurrently. The `FOR UPDATE` lock serializes
        // the transactions, so exactly one succeeds and the other is refused —
        // never both, which would empty the tenant of admins.
        let demote = |id: String, token: String| {
            let state = state.clone();
            async move {
                send(
                    &state,
                    json_request(
                        "PATCH",
                        &format!("/api/users/{id}"),
                        &token,
                        &serde_json::json!({"role": "operator"}),
                    ),
                )
                .await
                .0
            }
        };
        let (first, second) = tokio::join!(
            demote(admin_a.as_uuid().to_string(), admin.clone()),
            demote(admin_b.as_uuid().to_string(), admin.clone()),
        );

        let won = usize::from(first == StatusCode::OK) + usize::from(second == StatusCode::OK);
        let refused = usize::from(first == StatusCode::CONFLICT)
            + usize::from(second == StatusCode::CONFLICT);
        assert_eq!(won, 1, "exactly one demotion wins");
        assert_eq!(refused, 1, "the other hits the last-admin guard");
    }
}
