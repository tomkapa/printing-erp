//! The login flow.
//!
//! Every failure mode — wrong password, unknown user, inactive account, unknown
//! tenant — returns [`AuthError::InvalidCredentials`] with an identical response,
//! so a caller cannot enumerate accounts. A real argon2 verification runs even
//! when no user matched (against a fixed dummy hash) so timing does not leak
//! existence (CLAUDE.md anti-enumeration; rate-limiting is out of scope, #12).

use super::context::AuthContext;
use super::error::{AuthError, internal};
use super::limits::AUTH_QUERY_TIMEOUT;
use super::password::{PasswordHash, verify_or_dummy};
use super::session::{TokenPair, issue_pair};
use super::tenants;
use crate::clock::Clock;
use crate::db;
use crate::domain::{Email, PlaintextPassword, Role, TenantSlug, UserId};
use sqlx::{PgConnection, PgPool};
use tokio::time::timeout;
use uuid::Uuid;

/// Login request body. `email`/`password` parse through their domain newtypes on
/// deserialization; `tenant_slug` selects the workspace.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct LoginRequest {
    pub(crate) tenant_slug: TenantSlug,
    pub(crate) email: Email,
    pub(crate) password: PlaintextPassword,
}

/// A user row relevant to authentication.
struct UserRow {
    id: UserId,
    role: Role,
    hash: PasswordHash,
    is_active: bool,
}

/// Authenticates a request and, on success, issues an access + refresh pair.
///
/// # Errors
///
/// [`AuthError::InvalidCredentials`] on any authentication failure;
/// [`AuthError::Internal`] on a database or signing fault.
pub(crate) async fn login(
    pool: &PgPool,
    clock: &dyn Clock,
    auth: &AuthContext,
    request: LoginRequest,
) -> Result<TokenPair, AuthError> {
    let now = clock.now_utc();
    // Bound the whole tenant-scoped round-trip (CLAUDE.md §5), like
    // `http::routes::tenant::me`: one timeout covers every I/O await below.
    let work = async {
        let Some(tenant) = tenants::resolve_by_slug(pool, &request.tenant_slug).await? else {
            // Unknown tenant: do equivalent verification work, then fail uniformly.
            let _ignored = verify_or_dummy(&request.password, None);
            return Err(AuthError::InvalidCredentials);
        };

        let mut tx = db::begin_tenant_tx(pool, tenant).await.map_err(internal)?;
        let found = load_user(&mut tx, &request.email).await?;
        let (user, role) = authenticate(&request.password, found)?;

        let pair = issue_pair(&mut tx, auth, now, user, tenant, role, Uuid::new_v4()).await?;
        tx.commit().await.map_err(internal)?;
        Ok(pair)
    };
    let pair = timeout(AUTH_QUERY_TIMEOUT, work)
        .await
        .map_err(|_| AuthError::Timeout)??;

    // Post-conditions (CLAUDE.md §6): a successful login always yields both tokens.
    assert!(
        !pair.access_token.is_empty(),
        "issued access token is non-empty"
    );
    assert!(
        !pair.refresh_token.is_empty(),
        "issued refresh token is non-empty"
    );
    Ok(pair)
}

/// Loads the user with `email` within the current tenant transaction. The
/// caller bounds this await as part of the flow-level timeout.
async fn load_user(conn: &mut PgConnection, email: &Email) -> Result<Option<UserRow>, AuthError> {
    let row: Option<(Uuid, Role, String, bool)> =
        sqlx::query_as("SELECT id, role, password_hash, is_active FROM users WHERE email = $1")
            .bind(email.as_str())
            .fetch_optional(&mut *conn)
            .await
            .map_err(internal)?;
    match row {
        None => Ok(None),
        Some((id, role, hash, is_active)) => Ok(Some(UserRow {
            id: UserId::try_from(id).map_err(internal)?,
            role,
            hash: PasswordHash::try_from(hash).map_err(internal)?,
            is_active,
        })),
    }
}

/// Verifies the password (always, even when absent) and applies the active-state
/// gate. Returns the authenticated `(user, role)` or a uniform failure.
fn authenticate(
    password: &PlaintextPassword,
    found: Option<UserRow>,
) -> Result<(UserId, Role), AuthError> {
    let Some(user) = found else {
        let _ignored = verify_or_dummy(password, None);
        return Err(AuthError::InvalidCredentials);
    };
    let verified = verify_or_dummy(password, Some(&user.hash));
    if verified && user.is_active {
        return Ok((user.id, user.role));
    }
    Err(AuthError::InvalidCredentials)
}

#[cfg(test)]
mod tests {
    use super::login;
    use crate::auth::error::AuthError;
    use crate::auth::fixtures::{PASSWORD, login_request, seed_user};
    use crate::testsupport;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    /// Runs login against a seeded fixture and returns the result.
    async fn try_login(
        pool: &sqlx::PgPool,
        slug: &str,
        email: &str,
        password: &str,
    ) -> Result<crate::auth::TokenPair, AuthError> {
        let clock = testsupport::test_clock();
        let auth = testsupport::auth_context();
        login(
            pool,
            clock.as_ref(),
            &auth,
            login_request(slug, email, password),
        )
        .await
    }

    #[sqlx::test]
    async fn valid_credentials_issue_a_token_pair(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;

        let pair = try_login(&pool, "acme", "user@acme.test", PASSWORD)
            .await
            .expect("login succeeds");
        assert_eq!(pair.token_type, "Bearer");
        assert!(!pair.access_token.is_empty(), "an access token is returned");
        assert!(
            !pair.refresh_token.is_empty(),
            "a refresh token is returned"
        );
    }

    #[sqlx::test]
    async fn wrong_password_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;

        let err = try_login(&pool, "acme", "user@acme.test", "wrong password!!")
            .await
            .expect_err("wrong password fails");
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[sqlx::test]
    async fn unknown_user_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;

        let err = try_login(&pool, "acme", "ghost@acme.test", PASSWORD)
            .await
            .expect_err("unknown user fails");
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[sqlx::test]
    async fn inactive_user_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", false).await;

        let err = try_login(&pool, "acme", "user@acme.test", PASSWORD)
            .await
            .expect_err("inactive user fails");
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[sqlx::test]
    async fn unknown_tenant_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;

        let err = try_login(&pool, "nope", "user@acme.test", PASSWORD)
            .await
            .expect_err("unknown tenant fails");
        assert_eq!(err, AuthError::InvalidCredentials);
    }
}
