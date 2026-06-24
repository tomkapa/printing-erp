//! PostgreSQL access.
//!
//! The pool is built once at startup from [`DatabaseSettings`] (CLAUDE.md §9)
//! and threaded through the application as `&PgPool`. Migrations live in
//! `backend/migrations` and are embedded at compile time.

use crate::config::DatabaseSettings;
use crate::domain::TenantId;
use secrecy::ExposeSecret as _;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection as _, PgConnection, PgPool, Postgres, Transaction};
use thiserror::Error;

/// Session GUC carrying the active tenant for Row-Level Security.
///
/// Set per-transaction by [`begin_tenant_tx`]; the `users_tenant_isolation`
/// policy (migration `20260623000002_users_rls`) reads it. The name is a
/// `&'static str` constant — never interpolated from input (CLAUDE.md §10).
const TENANT_GUC: &str = "app.current_tenant";

/// Embedded, reversible migrations applied by [`migrate`].
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Shared helpers for Row-Level Security integration tests across modules.
///
/// Every tenant-scoped table's test suite needs the same scaffolding: an
/// `erp_app`-role pool (so the policy is genuinely exercised rather than bypassed
/// by the admin role), a fresh tenant id, a seeded `tenants` row, and access to
/// the embedded migration set for per-table reversibility checks. They live here
/// once, beside the DB layer they exercise. `pub(crate)` under `#[cfg(test)]`
/// widens visibility only within the test build, never the production surface
/// (CLAUDE.md §3).
#[cfg(test)]
pub(crate) mod test_support {
    use crate::domain::TenantId;
    use sqlx::PgPool;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use uuid::Uuid;

    /// The embedded migration set, for per-table reversibility checks.
    pub(crate) fn migrator() -> &'static sqlx::migrate::Migrator {
        &super::MIGRATOR
    }

    /// A fresh, valid tenant id (v4 UUIDs are never nil).
    pub(crate) fn new_tenant() -> TenantId {
        TenantId::try_from(Uuid::new_v4()).expect("v4 uuid is non-nil")
    }

    /// Connects a pool as the least-privilege `erp_app` role to the test DB. The
    /// admin pool `#[sqlx::test]` provides is a superuser and would bypass RLS,
    /// masking any regression.
    pub(crate) async fn app_pool(opts: PgPoolOptions, conn: PgConnectOptions) -> PgPool {
        opts.connect_with(conn.username("erp_app").password("erp_app"))
            .await
            .expect("connect to test database as erp_app")
    }

    /// Seeds a tenant directly (the root `tenants` table is not under RLS).
    pub(crate) async fn seed_tenant(pool: &PgPool, tenant: TenantId, slug: &str) {
        sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind("Acme Print Co")
            .bind(slug)
            .execute(pool)
            .await
            .expect("seed tenant");
    }
}

/// Failure while connecting to PostgreSQL or running migrations.
#[derive(Debug, Error)]
pub(crate) enum DbError {
    /// A query or connection-pool operation failed.
    #[error(transparent)]
    Query(#[from] sqlx::Error),

    /// Applying embedded migrations failed.
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Builds the bounded PostgreSQL connection pool.
///
/// The pool size and acquire timeout are fixed at construction per CLAUDE.md
/// §5 / §9; no growth on demand inside request handlers.
///
/// # Errors
///
/// Returns [`DbError::Query`] if the pool cannot establish its connections
/// within the configured acquire timeout.
pub(crate) async fn connect(settings: &DatabaseSettings) -> Result<PgPool, DbError> {
    let pool = PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout())
        .connect(settings.url.expose_secret())
        .await?;
    Ok(pool)
}

/// Runs all pending migrations using the **admin** role.
///
/// Migrations are DDL (and `CREATE EXTENSION`), which the least-privilege
/// serving role cannot perform; they run as the owner via
/// [`DatabaseSettings::migration_url`]. A single short-lived connection is used
/// rather than a pool — migrations run once at startup.
///
/// # Errors
///
/// Returns [`DbError::Query`] if the admin connection cannot be established, or
/// [`DbError::Migrate`] if a migration fails or the recorded history diverges
/// from the embedded set.
pub(crate) async fn migrate(settings: &DatabaseSettings) -> Result<(), DbError> {
    let mut conn = PgConnection::connect(settings.migration_url().expose_secret()).await?;
    MIGRATOR.run(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

/// Opens a transaction scoped to a single tenant for Row-Level Security.
///
/// Sets the [`TENANT_GUC`] for the lifetime of the returned transaction via
/// `set_config(.., is_local => true)`, which resets the value on commit or
/// rollback — so the setting never leaks to the next checkout of this pooled
/// connection. `SET LOCAL` cannot take a bind parameter; `set_config` can, so
/// the tenant id is bound (as text), never concatenated (CLAUDE.md §10).
///
/// The caller MUST run every tenant-scoped statement on the returned
/// transaction (the GUC is per-transaction) and `commit` it to persist writes;
/// dropping it rolls back.
///
/// # Errors
///
/// Returns [`DbError::Query`] if the transaction cannot begin or the GUC cannot
/// be set within the pool's acquire timeout.
pub(crate) async fn begin_tenant_tx(
    pool: &PgPool,
    tenant: TenantId,
) -> Result<Transaction<'_, Postgres>, DbError> {
    assert!(
        !tenant.as_uuid().is_nil(),
        "TenantId invariant: uuid is never nil"
    );
    let value = tenant.as_uuid().to_string();
    assert_eq!(value.len(), 36, "canonical uuid text is 36 characters");

    let mut tx = pool.begin().await?;
    // `set_config(name, value, is_local)` — name and value are bound text
    // params; the policy casts the value back to uuid. is_local = true ties the
    // setting to this transaction.
    sqlx::query("SELECT set_config($1, $2, true)")
        .bind(TENANT_GUC)
        .bind(value)
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Liveness probe: confirms a connection can round-trip a trivial query.
///
/// # Errors
///
/// Returns [`DbError::Query`] if no connection is available or the query fails.
pub(crate) async fn ping(pool: &PgPool) -> Result<(), DbError> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}

#[cfg(test)]
mod rls_tests {
    //! Row-Level Security enforcement, against real Postgres.
    //!
    //! `#[sqlx::test]` provisions an ephemeral database and applies the embedded
    //! migrations as the admin role. We then connect a pool as the
    //! least-privilege `erp_app` role (created at cluster init) so the policy is
    //! genuinely exercised — the admin pool `#[sqlx::test]` hands us is a
    //! superuser and would bypass RLS, masking any regression.

    use super::begin_tenant_tx;
    use super::test_support::{app_pool, migrator, new_tenant, seed_tenant};
    use crate::domain::TenantId;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use sqlx::{Connection as _, PgConnection, PgPool};

    /// Inserts a user inside the tenant's RLS context and commits.
    async fn seed_user(pool: &PgPool, tenant: TenantId, email: &str) {
        let mut tx = begin_tenant_tx(pool, tenant)
            .await
            .expect("begin tenant tx");
        sqlx::query(
            "INSERT INTO users (tenant_id, email, display_name, password_hash) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant.as_uuid())
        .bind(email)
        .bind("Test User")
        .bind("argon2-hash")
        .execute(&mut *tx)
        .await
        .expect("insert user within tenant context");
        tx.commit().await.expect("commit user");
    }

    #[sqlx::test]
    async fn tenant_context_sees_only_its_own_rows(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;
        seed_user(&pool, a, "alice@a.test").await;
        seed_user(&pool, b, "bob@b.test").await;

        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin tenant tx");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&mut *tx)
            .await
            .expect("count users");
        let email: String = sqlx::query_scalar("SELECT email FROM users")
            .fetch_one(&mut *tx)
            .await
            .expect("read the single visible user");

        assert_eq!(count, 1, "tenant A must see exactly its own one user");
        assert_eq!(
            email, "alice@a.test",
            "the visible user must be A's, not B's"
        );
    }

    #[sqlx::test]
    async fn no_tenant_context_denies_all_rows(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let a = new_tenant();
        seed_tenant(&pool, a, "tenant-a").await;
        seed_user(&pool, a, "alice@a.test").await;

        // A plain transaction never sets `app.current_tenant`, so the policy
        // predicate is NULL and every row is filtered: default-deny.
        let mut tx = pool.begin().await.expect("begin plain tx");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&mut *tx)
            .await
            .expect("count users without context");

        assert_eq!(count, 0, "no tenant context must expose zero rows");
    }

    #[sqlx::test]
    async fn cross_tenant_insert_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;

        // In tenant A's context, try to write a row stamped for tenant B.
        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin tenant tx");
        let result = sqlx::query(
            "INSERT INTO users (tenant_id, email, display_name, password_hash) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(b.as_uuid())
        .bind("intruder@b.test")
        .bind("Intruder")
        .bind("hash")
        .execute(&mut *tx)
        .await;

        let err = result.expect_err("WITH CHECK must reject a cross-tenant insert");
        assert!(
            err.to_string().contains("row-level security"),
            "rejection must come from the RLS policy, got: {err}"
        );
    }

    #[sqlx::test]
    async fn rls_migration_is_reversible(_opts: PgPoolOptions, conn: PgConnectOptions) {
        // Run as the admin role (DDL); revert the RLS migration, assert RLS is
        // off on `users`, then re-apply and assert it is back on (CLAUDE.md §13).
        let mut admin = PgConnection::connect_with(&conn)
            .await
            .expect("admin connection");

        let forced_before: bool = sqlx::query_scalar(FORCE_RLS_QUERY)
            .fetch_one(&mut admin)
            .await
            .expect("read forcerowsecurity");
        assert!(forced_before, "migration must leave FORCE RLS enabled");

        migrator()
            .undo(&mut admin, INIT_MIGRATION_VERSION)
            .await
            .expect("revert RLS migration");
        let forced_after_undo: bool = sqlx::query_scalar(FORCE_RLS_QUERY)
            .fetch_one(&mut admin)
            .await
            .expect("read forcerowsecurity after undo");
        assert!(!forced_after_undo, "down migration must disable FORCE RLS");

        migrator()
            .run(&mut admin)
            .await
            .expect("re-apply RLS migration");
        let forced_again: bool = sqlx::query_scalar(FORCE_RLS_QUERY)
            .fetch_one(&mut admin)
            .await
            .expect("read forcerowsecurity after re-apply");
        assert!(
            forced_again,
            "re-applied migration must re-enable FORCE RLS"
        );
    }

    /// Version of the initial migration; reverting *to* it undoes the RLS one.
    const INIT_MIGRATION_VERSION: i64 = 20_260_623_000_001;

    /// Reads whether `users` has `FORCE ROW LEVEL SECURITY` set.
    const FORCE_RLS_QUERY: &str =
        "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'users'";
}
