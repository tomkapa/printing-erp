//! Logout: revoke the session family of a presented refresh token.
//!
//! Idempotent by design — an unknown, malformed, or already-revoked token still
//! succeeds (the HTTP layer returns 204). Revoking the whole *family* (not just
//! the one token) ends the session even if it was mid-rotation, so the device is
//! truly logged out. Only a database fault surfaces as an error.

use super::error::{AuthError, internal};
use super::limits::AUTH_QUERY_TIMEOUT;
use super::opaque;
use crate::clock::Clock;
use crate::db;
use tokio::time::timeout;

/// Logout request body — the opaque refresh token to invalidate.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct LogoutRequest {
    pub(crate) refresh_token: String,
}

/// Revokes the presented token's family. Always `Ok(())` unless the database
/// itself fails.
///
/// # Errors
///
/// Returns [`AuthError::Internal`] only on a database fault.
pub(crate) async fn logout(
    pool: &sqlx::PgPool,
    clock: &dyn Clock,
    request: LogoutRequest,
) -> Result<(), AuthError> {
    let now = clock.now_utc();
    // A token we cannot even parse names no session: nothing to revoke.
    let Ok((tenant, hash)) = opaque::parse(&request.refresh_token) else {
        return Ok(());
    };
    assert_eq!(hash.as_bytes().len(), 32, "token hash is 32 bytes");
    assert!(!tenant.as_uuid().is_nil(), "parsed tenant id is non-nil");

    // One timeout bounds both the UPDATE and the commit (CLAUDE.md §5).
    let work = async {
        let mut tx = db::begin_tenant_tx(pool, tenant).await.map_err(internal)?;
        // Revoke the whole family of the row matching this hash. A miss revokes
        // nothing (the subquery is NULL), keeping logout idempotent.
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = $1 \
             WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $2) \
             AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(hash.as_bytes())
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(())
    };
    timeout(AUTH_QUERY_TIMEOUT, work)
        .await
        .map_err(|_| AuthError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::{LogoutRequest, logout};
    use crate::auth::AuthError;
    use crate::auth::fixtures::login_fixture;
    use crate::auth::refresh::{RefreshRequest, refresh};
    use crate::testsupport;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    fn logout_req(token: &str) -> LogoutRequest {
        LogoutRequest {
            refresh_token: token.to_owned(),
        }
    }

    #[sqlx::test]
    async fn logout_invalidates_the_refresh_token(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let (auth, token) = login_fixture(&pool).await;
        let clock = testsupport::test_clock();

        logout(&pool, clock.as_ref(), logout_req(&token))
            .await
            .expect("logout succeeds");

        let err = refresh(
            &pool,
            clock.as_ref(),
            &auth,
            RefreshRequest {
                refresh_token: token,
            },
        )
        .await
        .expect_err("revoked token cannot refresh");
        assert_eq!(err, AuthError::InvalidToken);
    }

    #[sqlx::test]
    async fn logout_is_idempotent(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let (_auth, token) = login_fixture(&pool).await;
        let clock = testsupport::test_clock();

        logout(&pool, clock.as_ref(), logout_req(&token))
            .await
            .expect("first logout");
        logout(&pool, clock.as_ref(), logout_req(&token))
            .await
            .expect("second logout is still ok");
    }

    #[sqlx::test]
    async fn logout_with_garbage_token_succeeds(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let clock = testsupport::test_clock();
        logout(&pool, clock.as_ref(), logout_req("not-a-real-token"))
            .await
            .expect("garbage token still yields a successful logout");
    }
}
