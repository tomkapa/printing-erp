//! Tenant-scoped persistence for [`Asset`] rows.
//!
//! Every function runs on a connection already inside a tenant transaction
//! (`db::begin_tenant_tx`), so Row-Level Security scopes all reads and writes to
//! the active tenant. Queries use bound parameters only — never string
//! interpolation (CLAUDE.md §10) — and the column list is a fixed literal with
//! `status::text` so [`Asset::try_from`] can decode the enum as text.

use crate::assets::error::AssetError;
use crate::assets::limits;
use crate::assets::model::{Asset, ByteSize, ContentType, FileName, Sha256Hex, StorageKey};
use crate::domain::{AssetId, TenantId};
use sqlx::PgConnection;

/// Inserts a freshly-created asset in the `pending` state.
///
/// # Errors
///
/// [`AssetError::Db`] on query failure (e.g. a duplicate `(tenant, storage_key)`).
pub(crate) async fn insert_pending(
    conn: &mut PgConnection,
    tenant: TenantId,
    asset: AssetId,
    storage_key: &StorageKey,
    original_name: &FileName,
    content_type: ContentType,
    size: ByteSize,
) -> Result<(), AssetError> {
    assert!(size.get() > 0, "ByteSize invariant: strictly positive");
    let result = sqlx::query(
        "INSERT INTO assets \
         (id, tenant_id, storage_key, original_name, content_type, size_bytes) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(asset.as_uuid())
    .bind(tenant.as_uuid())
    .bind(storage_key.as_str())
    .bind(original_name.as_str())
    .bind(content_type.as_str())
    .bind(size.get())
    .execute(conn)
    .await?;
    assert_eq!(
        result.rows_affected(),
        1,
        "a successful insert affects exactly one row"
    );
    Ok(())
}

/// Fetches a non-deleted asset by id within the tenant scope.
///
/// # Errors
///
/// [`AssetError::NotFound`] if no visible, non-deleted asset has that id;
/// [`AssetError::Db`] on query/decode failure.
pub(crate) async fn get(
    conn: &mut PgConnection,
    tenant: TenantId,
    asset: AssetId,
) -> Result<Asset, AssetError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, storage_key, original_name, content_type, size_bytes, \
                checksum_sha256, status::text AS status, created_at, updated_at \
         FROM assets WHERE id = $1 AND status <> 'deleted'",
    )
    .bind(asset.as_uuid())
    .fetch_optional(conn)
    .await?
    .ok_or(AssetError::NotFound)?;

    let parsed = Asset::try_from(&row)?;
    assert_eq!(
        parsed.tenant_id, tenant,
        "RLS invariant: a visible row belongs to the active tenant"
    );
    Ok(parsed)
}

/// Lists non-deleted assets in the tenant scope, newest first.
///
/// `limit` is clamped by the caller to [`limits::MAX_ASSETS_PER_PAGE`]; the
/// returned vector is bounded by it (CLAUDE.md §5).
///
/// # Errors
///
/// [`AssetError::Db`] on query/decode failure.
pub(crate) async fn list(
    conn: &mut PgConnection,
    limit: i64,
    offset: i64,
) -> Result<Vec<Asset>, AssetError> {
    assert!(limit > 0, "page limit must be positive");
    assert!(
        limit <= limits::MAX_ASSETS_PER_PAGE,
        "page limit must be clamped before query"
    );
    assert!(offset >= 0, "page offset must be non-negative");

    let rows = sqlx::query(
        "SELECT id, tenant_id, storage_key, original_name, content_type, size_bytes, \
                checksum_sha256, status::text AS status, created_at, updated_at \
         FROM assets WHERE status <> 'deleted' \
         ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(conn)
    .await?;

    assert!(
        i64::try_from(rows.len()).is_ok_and(|n| n <= limit),
        "LIMIT must bound the row count"
    );
    let mut assets = Vec::with_capacity(rows.len());
    for row in &rows {
        assets.push(Asset::try_from(row)?);
    }
    Ok(assets)
}

/// Marks an asset `ready`, recording its checksum if known. Idempotent: a
/// re-confirmation of an already-ready asset succeeds.
///
/// # Errors
///
/// [`AssetError::NotFound`] if no non-deleted asset has that id;
/// [`AssetError::Db`] on query failure.
pub(crate) async fn mark_ready(
    conn: &mut PgConnection,
    asset: AssetId,
    checksum: Option<&Sha256Hex>,
) -> Result<(), AssetError> {
    let result = sqlx::query(
        "UPDATE assets SET status = 'ready', checksum_sha256 = $2, updated_at = now() \
         WHERE id = $1 AND status <> 'deleted'",
    )
    .bind(asset.as_uuid())
    .bind(checksum.map(Sha256Hex::as_str))
    .execute(conn)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AssetError::NotFound);
    }
    Ok(())
}

/// Soft-deletes an asset (status → `deleted`); the bytes are removed separately.
///
/// # Errors
///
/// [`AssetError::NotFound`] if no asset has that id; [`AssetError::Db`] on
/// query failure.
pub(crate) async fn soft_delete(conn: &mut PgConnection, asset: AssetId) -> Result<(), AssetError> {
    let result =
        sqlx::query("UPDATE assets SET status = 'deleted', updated_at = now() WHERE id = $1")
            .bind(asset.as_uuid())
            .execute(conn)
            .await?;
    if result.rows_affected() == 0 {
        return Err(AssetError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Repo CRUD and Row-Level Security, against real Postgres.
    //!
    //! Like `db::rls_tests`, we connect a pool as the least-privilege `erp_app`
    //! role so the `assets_tenant_isolation` policy is genuinely exercised — the
    //! admin pool `#[sqlx::test]` provides is a superuser and bypasses RLS.

    use super::{get, insert_pending, list, mark_ready, soft_delete};
    use crate::assets::error::AssetError;
    use crate::assets::model::{
        AssetStatus, ByteSize, ContentType, FileName, Sha256Hex, StorageKey,
    };
    use crate::db::begin_tenant_tx;
    use crate::domain::{AssetId, TenantId};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use sqlx::{Connection as _, PgConnection, PgPool};
    use uuid::Uuid;

    fn new_tenant() -> TenantId {
        TenantId::try_from(Uuid::new_v4()).expect("v4 uuid is non-nil")
    }

    fn new_asset() -> AssetId {
        AssetId::try_from(Uuid::new_v4()).expect("v4 uuid is non-nil")
    }

    fn name() -> FileName {
        FileName::try_from("artwork.pdf").expect("valid filename")
    }

    fn size() -> ByteSize {
        ByteSize::try_from(123_456).expect("in range")
    }

    async fn app_pool(opts: PgPoolOptions, conn: PgConnectOptions) -> PgPool {
        opts.connect_with(conn.username("erp_app").password("erp_app"))
            .await
            .expect("connect to test database as erp_app")
    }

    async fn seed_tenant(pool: &PgPool, tenant: TenantId, slug: &str) {
        sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind("Acme Print Co")
            .bind(slug)
            .execute(pool)
            .await
            .expect("seed tenant");
    }

    /// Inserts one pending asset inside the tenant context and commits.
    async fn seed_asset(pool: &PgPool, tenant: TenantId) -> AssetId {
        let asset = new_asset();
        let key = StorageKey::new(tenant, asset);
        let mut tx = begin_tenant_tx(pool, tenant)
            .await
            .expect("begin tenant tx");
        insert_pending(
            &mut tx,
            tenant,
            asset,
            &key,
            &name(),
            ContentType::Pdf,
            size(),
        )
        .await
        .expect("insert pending asset");
        tx.commit().await.expect("commit");
        asset
    }

    #[sqlx::test]
    async fn insert_then_get_round_trips(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        let asset = seed_asset(&pool, tenant).await;

        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        let fetched = get(&mut tx, tenant, asset).await.expect("get");
        assert_eq!(fetched.id, asset);
        assert_eq!(fetched.status, AssetStatus::Pending, "new asset is pending");
        assert_eq!(fetched.content_type, ContentType::Pdf);
        assert_eq!(fetched.size_bytes, size());
    }

    #[sqlx::test]
    async fn get_missing_is_not_found(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;

        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        let err = get(&mut tx, tenant, new_asset())
            .await
            .expect_err("absent id is not found");
        assert!(matches!(err, AssetError::NotFound));
    }

    #[sqlx::test]
    async fn mark_ready_sets_status_and_checksum(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        let asset = seed_asset(&pool, tenant).await;
        let checksum = Sha256Hex::try_from("a".repeat(64).as_str()).expect("valid digest");

        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        mark_ready(&mut tx, asset, Some(&checksum))
            .await
            .expect("mark ready");
        let fetched = get(&mut tx, tenant, asset).await.expect("get");
        assert_eq!(fetched.status, AssetStatus::Ready);
        assert_eq!(fetched.checksum_sha256, Some(checksum));
    }

    #[sqlx::test]
    async fn soft_delete_hides_from_get_and_list(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        let asset = seed_asset(&pool, tenant).await;

        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        soft_delete(&mut tx, asset).await.expect("soft delete");
        assert!(
            matches!(get(&mut tx, tenant, asset).await, Err(AssetError::NotFound)),
            "deleted asset is invisible to get"
        );
        let listed = list(&mut tx, 50, 0).await.expect("list");
        assert!(listed.is_empty(), "deleted asset is excluded from listing");
    }

    #[sqlx::test]
    async fn list_paginates_newest_first(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let tenant = new_tenant();
        seed_tenant(&pool, tenant, "tenant-a").await;
        for _ in 0..3 {
            seed_asset(&pool, tenant).await;
        }

        let mut tx = begin_tenant_tx(&pool, tenant).await.expect("begin");
        let page = list(&mut tx, 2, 0).await.expect("first page");
        assert_eq!(page.len(), 2, "limit caps the page");
        let rest = list(&mut tx, 2, 2).await.expect("second page");
        assert_eq!(rest.len(), 1, "offset reaches the remainder");
    }

    #[sqlx::test]
    async fn rls_scopes_assets_to_their_tenant(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;
        seed_asset(&pool, a).await;
        seed_asset(&pool, b).await;

        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin");
        let listed = list(&mut tx, 50, 0).await.expect("list");
        assert_eq!(listed.len(), 1, "tenant A sees only its own asset");
        assert_eq!(listed[0].tenant_id, a, "and it is A's");
    }

    #[sqlx::test]
    async fn no_tenant_context_denies_all_assets(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let a = new_tenant();
        seed_tenant(&pool, a, "tenant-a").await;
        seed_asset(&pool, a).await;

        // A plain transaction never sets app.current_tenant → default-deny.
        let mut tx = pool.begin().await.expect("begin plain tx");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM assets")
            .fetch_one(&mut *tx)
            .await
            .expect("count without context");
        assert_eq!(count, 0, "no tenant context exposes zero assets");
    }

    #[sqlx::test]
    async fn cross_tenant_insert_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;

        // In A's context, try to write a row stamped for tenant B.
        let asset = new_asset();
        let key = StorageKey::new(b, asset);
        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin");
        let result = sqlx::query(
            "INSERT INTO assets (id, tenant_id, storage_key, original_name, content_type, size_bytes) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(asset.as_uuid())
        .bind(b.as_uuid())
        .bind(key.as_str())
        .bind("intruder.pdf")
        .bind("application/pdf")
        .bind(1_i64)
        .execute(&mut *tx)
        .await;
        let err = result.expect_err("WITH CHECK must reject the cross-tenant insert");
        assert!(
            err.to_string().contains("row-level security"),
            "rejection must come from the RLS policy, got: {err}"
        );
    }

    #[sqlx::test]
    async fn assets_rls_migration_is_reversible(_opts: PgPoolOptions, conn: PgConnectOptions) {
        // Run as the admin role (DDL). The assets migration creates the table;
        // reverting it drops the table entirely (CLAUDE.md §13).
        let mut admin = PgConnection::connect_with(&conn)
            .await
            .expect("admin connection");
        let migrator = sqlx::migrate!("./migrations");

        let forced: bool = sqlx::query_scalar(FORCE_RLS_ASSETS)
            .fetch_one(&mut admin)
            .await
            .expect("read forcerowsecurity");
        assert!(forced, "migration leaves FORCE RLS enabled on assets");

        migrator
            .undo(&mut admin, USERS_RLS_MIGRATION_VERSION)
            .await
            .expect("revert the assets migration");
        let after_undo: Option<bool> = sqlx::query_scalar(FORCE_RLS_ASSETS)
            .fetch_optional(&mut admin)
            .await
            .expect("read forcerowsecurity after undo");
        assert!(
            after_undo.is_none(),
            "down migration drops the assets table"
        );

        migrator.run(&mut admin).await.expect("re-apply");
        let forced_again: bool = sqlx::query_scalar(FORCE_RLS_ASSETS)
            .fetch_one(&mut admin)
            .await
            .expect("read forcerowsecurity after re-apply");
        assert!(forced_again, "re-applied migration re-enables FORCE RLS");
    }

    /// Reverting *to* this version (the users_rls migration) undoes the assets one.
    const USERS_RLS_MIGRATION_VERSION: i64 = 20_260_623_000_002;

    /// Reads whether `assets` has `FORCE ROW LEVEL SECURITY` set.
    const FORCE_RLS_ASSETS: &str =
        "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'assets'";
}
