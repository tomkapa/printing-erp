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
    use std::time::Duration;
    use tokio::time::timeout;
    use uuid::Uuid;

    /// Upper bound on any single test-DB operation. Generous for a loaded CI
    /// runner, but bounded so a slow or wedged database fails the test fast
    /// instead of hanging the whole `#[sqlx::test]` cohort.
    const TEST_DB_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// masking any regression. Bounded by [`TEST_DB_TIMEOUT`].
    pub(crate) async fn app_pool(opts: PgPoolOptions, conn: PgConnectOptions) -> PgPool {
        timeout(
            TEST_DB_TIMEOUT,
            opts.connect_with(conn.username("erp_app").password("erp_app")),
        )
        .await
        .expect("connect to test database within timeout")
        .expect("connect to test database as erp_app")
    }

    /// Seeds a tenant directly (the root `tenants` table is not under RLS).
    /// Bounded by [`TEST_DB_TIMEOUT`].
    pub(crate) async fn seed_tenant(pool: &PgPool, tenant: TenantId, slug: &str) {
        let insert = sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(tenant.as_uuid())
            .bind("Acme Print Co")
            .bind(slug)
            .execute(pool);
        timeout(TEST_DB_TIMEOUT, insert)
            .await
            .expect("seed tenant within timeout")
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
    use uuid::Uuid;

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

    /// Inserts a user and a refresh token for it inside the tenant's context.
    async fn seed_refresh_token(pool: &PgPool, tenant: TenantId, email: &str) {
        let mut tx = begin_tenant_tx(pool, tenant)
            .await
            .expect("begin tenant tx");
        let user_id: Uuid = sqlx::query_scalar(
            "INSERT INTO users (tenant_id, email, display_name, password_hash) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(tenant.as_uuid())
        .bind(email)
        .bind("Test User")
        .bind("argon2-hash")
        .fetch_one(&mut *tx)
        .await
        .expect("insert user");
        sqlx::query(
            "INSERT INTO refresh_tokens \
             (tenant_id, user_id, family_id, token_hash, issued_at, expires_at) \
             VALUES ($1, $2, gen_random_uuid(), $3, now(), now() + interval '1 hour')",
        )
        .bind(tenant.as_uuid())
        .bind(user_id)
        .bind(vec![0_u8; 32])
        .execute(&mut *tx)
        .await
        .expect("insert refresh token within tenant context");
        tx.commit().await.expect("commit refresh token");
    }

    #[sqlx::test]
    async fn refresh_tokens_are_tenant_isolated(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = app_pool(opts, conn).await;
        let (a, b) = (new_tenant(), new_tenant());
        seed_tenant(&pool, a, "tenant-a").await;
        seed_tenant(&pool, b, "tenant-b").await;
        seed_refresh_token(&pool, b, "bob@b.test").await;

        // Tenant A's context must not see tenant B's refresh token.
        let mut tx = begin_tenant_tx(&pool, a).await.expect("begin tenant tx");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens")
            .fetch_one(&mut *tx)
            .await
            .expect("count refresh tokens");
        assert_eq!(count, 0, "tenant A must not see tenant B's refresh tokens");
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

    #[sqlx::test]
    async fn auth_tokens_migration_is_reversible(_opts: PgPoolOptions, conn: PgConnectOptions) {
        // Reverting *to* the business-settings version undoes only the auth_tokens
        // migration (the one applied after it). Assert the tables exist + are
        // FORCE-protected, revert, assert they are gone, re-apply, assert they are
        // back (CLAUDE.md §13).
        let mut admin = PgConnection::connect_with(&conn)
            .await
            .expect("admin connection");

        let forced_before: bool = sqlx::query_scalar(FORCE_REFRESH_TOKENS_QUERY)
            .fetch_one(&mut admin)
            .await
            .expect("read refresh_tokens forcerowsecurity");
        assert!(forced_before, "migration must leave FORCE RLS enabled");

        migrator()
            .undo(&mut admin, BUSINESS_SETTINGS_MIGRATION_VERSION)
            .await
            .expect("revert auth_tokens migration");
        let table_after_undo: Option<String> = sqlx::query_scalar(REFRESH_TOKENS_REGCLASS_QUERY)
            .fetch_one(&mut admin)
            .await
            .expect("read to_regclass after undo");
        assert!(
            table_after_undo.is_none(),
            "down migration must drop refresh_tokens"
        );

        migrator()
            .run(&mut admin)
            .await
            .expect("re-apply auth_tokens migration");
        let forced_again: bool = sqlx::query_scalar(FORCE_REFRESH_TOKENS_QUERY)
            .fetch_one(&mut admin)
            .await
            .expect("read refresh_tokens forcerowsecurity after re-apply");
        assert!(
            forced_again,
            "re-applied migration must re-enable FORCE RLS"
        );
    }

    /// Version of the initial migration; reverting *to* it undoes the RLS one.
    const INIT_MIGRATION_VERSION: i64 = 20_260_623_000_001;

    /// Version of the business-settings migration; reverting *to* it undoes the
    /// auth_tokens migration that follows it.
    const BUSINESS_SETTINGS_MIGRATION_VERSION: i64 = 20_260_624_000_003;

    /// Reads whether `users` has `FORCE ROW LEVEL SECURITY` set.
    const FORCE_RLS_QUERY: &str =
        "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'users'";

    /// Reads whether `refresh_tokens` has `FORCE ROW LEVEL SECURITY` set.
    const FORCE_REFRESH_TOKENS_QUERY: &str =
        "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'refresh_tokens'";

    /// Resolves `refresh_tokens` to its table OID name, or NULL if absent.
    const REFRESH_TOKENS_REGCLASS_QUERY: &str = "SELECT to_regclass('refresh_tokens')::text";
}
