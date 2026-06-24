//! Forgot-password and reset-password flows.
//!
//! `forgot_password` always reports success (HTTP 200) whether or not the email
//! exists — no account enumeration — and emits the reset token only through the
//! [`PasswordResetNotifier`](super::notifier::PasswordResetNotifier), never in
//! the response. `reset_password` consumes a valid token exactly once, sets the
//! new hash, and revokes **all** of the user's refresh tokens so existing
//! sessions cannot outlive the credential change.

use super::context::AuthContext;
use super::error::{AuthError, deadline, internal};
use super::opaque;
use super::password::hash_password;
use super::tenants;
use crate::clock::Clock;
use crate::db;
use crate::domain::{Email, PlaintextPassword, TenantSlug, UserId};
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

/// Forgot-password request body.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ForgotRequest {
    pub(crate) tenant_slug: TenantSlug,
    pub(crate) email: Email,
}

/// Reset-password request body — the routable reset token and the new password.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ResetRequest {
    pub(crate) token: String,
    pub(crate) new_password: PlaintextPassword,
}

/// Raw column tuple read for a reset-token row:
/// `(id, user_id, expires_at, consumed_at)`.
type ResetTokenColumns = (Uuid, Uuid, DateTime<Utc>, Option<DateTime<Utc>>);

/// Issues a reset token for an active user and dispatches it via the notifier.
/// Always `Ok(())`: an unknown tenant/email is indistinguishable to the caller.
///
/// # Errors
///
/// Returns [`AuthError::Internal`] only on a database or token fault.
pub(crate) async fn forgot_password(
    pool: &sqlx::PgPool,
    clock: &dyn Clock,
    auth: &AuthContext,
    request: ForgotRequest,
) -> Result<(), AuthError> {
    let now = clock.now_utc();
    let Some(tenant) = tenants::resolve_by_slug(pool, &request.tenant_slug).await? else {
        return Ok(());
    };

    let mut tx = db::begin_tenant_tx(pool, tenant).await.map_err(internal)?;
    let user: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE email = $1 AND is_active = TRUE")
            .bind(request.email.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;

    let Some(user_id) = user else {
        // No active user: nothing issued, but the response is identical.
        return Ok(());
    };
    let user_id = UserId::try_from(user_id).map_err(internal)?;

    let minted = opaque::mint(tenant);
    let expires_at = deadline(now, auth.reset_ttl())?;
    sqlx::query(
        "INSERT INTO password_reset_tokens \
         (tenant_id, user_id, token_hash, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant.as_uuid())
    .bind(user_id.as_uuid())
    .bind(minted.hash.as_bytes())
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    // Deliver out of band only after the token is durably stored.
    auth.notifier().notify_reset(&request.email, &minted.raw);
    Ok(())
}

/// Consumes a reset token, sets the new password, and revokes every refresh
/// token for the user.
///
/// # Errors
///
/// [`AuthError::InvalidToken`] if the token is malformed, unknown, expired, or
/// already used; [`AuthError::Internal`] on a database or hashing fault.
pub(crate) async fn reset_password(
    pool: &sqlx::PgPool,
    clock: &dyn Clock,
    request: ResetRequest,
) -> Result<(), AuthError> {
    let now = clock.now_utc();
    let (tenant, hash) = opaque::parse(&request.token).map_err(|_| AuthError::InvalidToken)?;

    let mut tx = db::begin_tenant_tx(pool, tenant).await.map_err(internal)?;
    let row: Option<ResetTokenColumns> = sqlx::query_as(
        "SELECT id, user_id, expires_at, consumed_at \
         FROM password_reset_tokens WHERE token_hash = $1",
    )
    .bind(hash.as_bytes())
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;

    let (token_id, user_id, expires_at, consumed_at) = row.ok_or(AuthError::InvalidToken)?;
    if consumed_at.is_some() || expires_at <= now {
        return Err(AuthError::InvalidToken);
    }

    let new_hash = hash_password(&request.new_password).map_err(internal)?;
    apply_reset(&mut tx, user_id, token_id, &new_hash, now).await?;
    tx.commit().await.map_err(internal)?;
    Ok(())
}

/// Within the open transaction: set the new hash, consume the token, and revoke
/// the user's live refresh tokens.
async fn apply_reset(
    conn: &mut PgConnection,
    user_id: Uuid,
    token_id: Uuid,
    new_hash: &super::password::PasswordHash,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let updated = sqlx::query("UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3")
        .bind(new_hash.as_str())
        .bind(now)
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(internal)?
        .rows_affected();
    assert_eq!(updated, 1, "invariant: reset token's user row exists");

    sqlx::query("UPDATE password_reset_tokens SET consumed_at = $1 WHERE id = $2")
        .bind(now)
        .bind(token_id)
        .execute(&mut *conn)
        .await
        .map_err(internal)?;

    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(user_id)
    .execute(&mut *conn)
    .await
    .map_err(internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ForgotRequest, ResetRequest, forgot_password, reset_password};
    use crate::auth::fixtures::{NEW_PASSWORD, PASSWORD, login_request, password, seed_user};
    use crate::auth::login::login;
    use crate::auth::notifier::PasswordResetNotifier;
    use crate::auth::refresh::{RefreshRequest, refresh};
    use crate::auth::{AuthContext, AuthError};
    use crate::domain::{Email, TenantSlug};
    use crate::testsupport;
    use sqlx::PgPool;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::{Arc, Mutex};

    /// Captures dispatched reset tokens so tests can assert on delivery.
    #[derive(Debug, Default)]
    struct CapturingNotifier {
        sent: Mutex<Vec<(String, String)>>,
    }

    impl CapturingNotifier {
        fn tokens(&self) -> Vec<(String, String)> {
            self.sent.lock().expect("notifier mutex").clone()
        }
    }

    impl PasswordResetNotifier for CapturingNotifier {
        fn notify_reset(&self, email: &Email, token: &str) {
            self.sent
                .lock()
                .expect("notifier mutex")
                .push((email.as_str().to_owned(), token.to_owned()));
        }
    }

    /// An auth context wired to a capturing notifier so reset delivery can be
    /// asserted (the shared `testsupport::auth_context` uses the logging stub).
    fn context_with(notifier: Arc<CapturingNotifier>) -> Arc<AuthContext> {
        Arc::new(AuthContext::new(&testsupport::auth_settings(), notifier))
    }

    fn forgot(slug: &str, email: &str) -> ForgotRequest {
        ForgotRequest {
            tenant_slug: TenantSlug::try_from(slug.to_owned()).expect("slug"),
            email: Email::try_from(email).expect("email"),
        }
    }

    #[sqlx::test]
    async fn forgot_dispatches_a_token_for_a_real_user(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;
        let notifier = Arc::new(CapturingNotifier::default());
        let auth = context_with(notifier.clone());
        let clock = testsupport::test_clock();

        forgot_password(
            &pool,
            clock.as_ref(),
            &auth,
            forgot("acme", "user@acme.test"),
        )
        .await
        .expect("forgot always succeeds");
        let sent = notifier.tokens();
        assert_eq!(sent.len(), 1, "one reset token dispatched");
        assert_eq!(sent[0].0, "user@acme.test");
    }

    #[sqlx::test]
    async fn forgot_is_silent_for_unknown_email(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;
        let notifier = Arc::new(CapturingNotifier::default());
        let auth = context_with(notifier.clone());
        let clock = testsupport::test_clock();

        forgot_password(
            &pool,
            clock.as_ref(),
            &auth,
            forgot("acme", "ghost@acme.test"),
        )
        .await
        .expect("forgot still succeeds");
        assert!(notifier.tokens().is_empty(), "no token for an unknown user");
    }

    #[sqlx::test]
    async fn forgot_is_silent_for_unknown_tenant(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;
        let notifier = Arc::new(CapturingNotifier::default());
        let auth = context_with(notifier.clone());
        let clock = testsupport::test_clock();

        forgot_password(
            &pool,
            clock.as_ref(),
            &auth,
            forgot("nope", "user@acme.test"),
        )
        .await
        .expect("forgot still succeeds");
        assert!(
            notifier.tokens().is_empty(),
            "no token for an unknown tenant"
        );
    }

    /// Drives a full forgot → reset and returns the captured reset token.
    async fn issue_reset_token(
        pool: &PgPool,
        auth: &AuthContext,
        notifier: &CapturingNotifier,
    ) -> String {
        let clock = testsupport::test_clock();
        forgot_password(pool, clock.as_ref(), auth, forgot("acme", "user@acme.test"))
            .await
            .expect("forgot");
        notifier
            .tokens()
            .first()
            .expect("a token was sent")
            .1
            .clone()
    }

    fn reset_req(token: &str, new_password: &str) -> ResetRequest {
        ResetRequest {
            token: token.to_owned(),
            new_password: password(new_password),
        }
    }

    /// A login request for the standard fixture user with the given password.
    fn login_req(password_text: &str) -> crate::auth::LoginRequest {
        login_request("acme", "user@acme.test", password_text)
    }

    #[sqlx::test]
    async fn reset_changes_the_password(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;
        let notifier = Arc::new(CapturingNotifier::default());
        let auth = context_with(notifier.clone());
        let clock = testsupport::test_clock();
        let token = issue_reset_token(&pool, &auth, &notifier).await;

        reset_password(&pool, clock.as_ref(), reset_req(&token, NEW_PASSWORD))
            .await
            .expect("reset succeeds");

        // The new password works; the old one no longer does.
        login(&pool, clock.as_ref(), &auth, login_req(NEW_PASSWORD))
            .await
            .expect("login with new password");
        let err = login(&pool, clock.as_ref(), &auth, login_req(PASSWORD))
            .await
            .expect_err("old password rejected");
        assert_eq!(err, AuthError::InvalidCredentials);
    }

    #[sqlx::test]
    async fn reset_revokes_existing_refresh_tokens(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;
        let notifier = Arc::new(CapturingNotifier::default());
        let auth = context_with(notifier.clone());
        let clock = testsupport::test_clock();

        // An active session exists before the reset.
        let session = login(&pool, clock.as_ref(), &auth, login_req(PASSWORD))
            .await
            .expect("login");
        let token = issue_reset_token(&pool, &auth, &notifier).await;
        reset_password(&pool, clock.as_ref(), reset_req(&token, NEW_PASSWORD))
            .await
            .expect("reset");

        let err = refresh(
            &pool,
            clock.as_ref(),
            &auth,
            RefreshRequest {
                refresh_token: session.refresh_token,
            },
        )
        .await
        .expect_err("pre-reset refresh token is revoked");
        assert_eq!(err, AuthError::InvalidToken);
    }

    #[sqlx::test]
    async fn reset_token_is_single_use(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;
        let notifier = Arc::new(CapturingNotifier::default());
        let auth = context_with(notifier.clone());
        let clock = testsupport::test_clock();
        let token = issue_reset_token(&pool, &auth, &notifier).await;

        reset_password(&pool, clock.as_ref(), reset_req(&token, NEW_PASSWORD))
            .await
            .expect("first reset");
        let err = reset_password(
            &pool,
            clock.as_ref(),
            reset_req(&token, "another password here"),
        )
        .await
        .expect_err("token cannot be reused");
        assert_eq!(err, AuthError::InvalidToken);
    }

    #[sqlx::test]
    async fn expired_reset_token_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        seed_user(&pool, "acme", "user@acme.test", true).await;
        let notifier = Arc::new(CapturingNotifier::default());
        let auth = context_with(notifier.clone());
        let token = issue_reset_token(&pool, &auth, &notifier).await;

        // Past the 1-hour reset lifetime.
        let clock = testsupport::test_clock();
        clock.advance(std::time::Duration::from_secs(3_600 + 1));
        let err = reset_password(&pool, clock.as_ref(), reset_req(&token, NEW_PASSWORD))
            .await
            .expect_err("expired token rejected");
        assert_eq!(err, AuthError::InvalidToken);
    }

    #[sqlx::test]
    async fn garbage_reset_token_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let clock = testsupport::test_clock();
        let err = reset_password(
            &pool,
            clock.as_ref(),
            reset_req("not-a-token", NEW_PASSWORD),
        )
        .await
        .expect_err("garbage rejected");
        assert_eq!(err, AuthError::InvalidToken);
    }
}
