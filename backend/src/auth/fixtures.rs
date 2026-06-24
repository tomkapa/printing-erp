//! Shared fixtures for the auth-flow integration tests.
//!
//! Centralizes the standard tenant/user seeding (with a real argon2 hash), the
//! login request builder, and the login fixture so the per-flow test modules
//! (`login`, `logout`, `refresh`, `reset`) do not each re-implement them. Lives
//! inside `auth` so it can reach the private `password::hash_password`.

#![cfg(test)]

use super::context::AuthContext;
use super::login::{LoginRequest, login};
use super::password::hash_password;
use crate::domain::{Email, PlaintextPassword, Role, TenantSlug};
use crate::testsupport;
use sqlx::PgPool;
use std::sync::Arc;

/// Plaintext password whose argon2 hash seeds the standard fixture user.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// A distinct replacement password for reset tests.
pub(crate) const NEW_PASSWORD: &str = "a brand new passphrase!";

/// Parses a plaintext test password.
pub(crate) fn password(text: &str) -> PlaintextPassword {
    PlaintextPassword::try_from(text.to_owned()).expect("valid test password")
}

/// Builds a [`LoginRequest`] from string parts.
pub(crate) fn login_request(slug: &str, email: &str, password_text: &str) -> LoginRequest {
    LoginRequest {
        tenant_slug: TenantSlug::try_from(slug.to_owned()).expect("valid slug"),
        email: Email::try_from(email).expect("valid email"),
        password: password(password_text),
    }
}

/// Seeds tenant `slug` plus a user `email` (active or not) whose stored hash is a
/// real argon2 hash of [`PASSWORD`].
pub(crate) async fn seed_user(pool: &PgPool, slug: &str, email: &str, active: bool) {
    let tenant = testsupport::new_tenant();
    testsupport::seed_tenant(pool, tenant, slug).await;
    let hash = hash_password(&password(PASSWORD)).expect("hash");
    testsupport::seed_user(pool, tenant, email, Role::Sales, hash.as_str(), active).await;
}

/// Seeds the standard `acme` / `user@acme.test` fixture and logs in, returning
/// the shared auth context and the issued refresh token.
pub(crate) async fn login_fixture(pool: &PgPool) -> (Arc<AuthContext>, String) {
    seed_user(pool, "acme", "user@acme.test", true).await;
    let auth = testsupport::auth_context();
    let clock = testsupport::test_clock();
    let pair = login(
        pool,
        clock.as_ref(),
        &auth,
        login_request("acme", "user@acme.test", PASSWORD),
    )
    .await
    .expect("login");
    (auth, pair.refresh_token)
}
