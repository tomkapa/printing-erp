//! Shared test helpers (CLAUDE.md §3 — real Postgres via `#[sqlx::test]`).
//!
//! Integration tests connect a pool as the least-privilege `erp_app` role so
//! Row-Level Security is genuinely exercised (the admin pool `#[sqlx::test]`
//! hands us is a superuser and would bypass RLS). This module centralizes that
//! pool, tenant/user seeding, and the auth/test-clock wiring so the per-flow
//! test modules stay focused on behavior.

#![cfg(test)]

use crate::auth::{AuthContext, LoggingNotifier};
use crate::clock::test_clock::TestClock;
use crate::config::AuthSettings;
use crate::db;
use crate::domain::{Role, TenantId, UserId};
use crate::http::AppState;
use chrono::{DateTime, TimeZone as _, Utc};
use redis::aio::ConnectionManager;
use secrecy::SecretString;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

// The RLS-test primitives (erp_app pool, tenant seeding, fresh ids) live beside
// the DB layer in `db::test_support`; re-export them here so the auth and HTTP
// tests share the same bounded helpers rather than a divergent copy.
pub(crate) use crate::db::test_support::{app_pool, new_tenant, seed_tenant};

/// A fixed wall-clock anchor for deterministic token timing.
pub(crate) fn epoch() -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000, 0).single().expect("epoch")
}

/// A test clock frozen at [`epoch`] until advanced.
pub(crate) fn test_clock() -> Arc<TestClock> {
    TestClock::new(epoch())
}

/// Settings with a fixed signing secret and short, test-friendly lifetimes.
pub(crate) fn auth_settings() -> AuthSettings {
    AuthSettings {
        jwt_secret: SecretString::from("test-signing-secret-at-least-32-bytes!!".to_owned()),
        access_ttl_secs: 900,
        refresh_ttl_secs: 2_592_000,
        reset_ttl_secs: 3_600,
        issuer: "printing-erp-test".to_owned(),
    }
}

/// A shared [`AuthContext`] built from [`auth_settings`] with the logging
/// notifier (reset-token delivery is asserted via a capturing notifier in the
/// reset tests instead).
pub(crate) fn auth_context() -> Arc<AuthContext> {
    Arc::new(AuthContext::new(
        &auth_settings(),
        Arc::new(LoggingNotifier),
    ))
}

/// Connects the Redis manager (matches docker-compose; override with
/// `APP__REDIS__URL`). Only the HTTP-level state needs it; flow tests use
/// granular dependencies and skip it.
pub(crate) async fn redis_manager() -> ConnectionManager {
    let url =
        std::env::var("APP__REDIS__URL").unwrap_or_else(|_| "redis://localhost:6379".to_owned());
    let client = redis::Client::open(url).expect("redis client");
    ConnectionManager::new(client)
        .await
        .expect("redis connection (is docker-compose redis up?)")
}

/// Assembles an [`AppState`] over the given pool, clock, and auth context.
pub(crate) async fn app_state(
    pool: PgPool,
    clock: Arc<TestClock>,
    auth: Arc<AuthContext>,
) -> AppState {
    AppState::new(pool, redis_manager().await, clock, auth)
}

/// Inserts a user inside the tenant's RLS context and returns its id. The caller
/// supplies the stored `password_hash` (a real argon2 hash for login tests, or a
/// placeholder where the password is irrelevant).
pub(crate) async fn seed_user(
    pool: &PgPool,
    tenant: TenantId,
    email: &str,
    role: Role,
    password_hash: &str,
    is_active: bool,
) -> UserId {
    let mut tx = db::begin_tenant_tx(pool, tenant)
        .await
        .expect("begin tenant tx");
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (tenant_id, email, display_name, role, password_hash, is_active) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(tenant.as_uuid())
    .bind(email)
    .bind("Test User")
    .bind(role)
    .bind(password_hash)
    .bind(is_active)
    .fetch_one(&mut *tx)
    .await
    .expect("insert user");
    tx.commit().await.expect("commit user");
    UserId::try_from(id).expect("seeded user id is non-nil")
}
