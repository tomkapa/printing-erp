//! Refresh-token rotation with reuse detection.
//!
//! Each refresh issues a new token in the same family and revokes the presented
//! one (single-use rotation). If an *already-rotated* token is presented again —
//! the hallmark of a stolen, replayed token — the entire family is revoked,
//! logging the legitimate holder out and forcing a fresh login. Natural expiry
//! is not treated as theft (no family revoke).
//!
//! The whole flow runs in one tenant transaction so the select → insert → update
//! is atomic; the unique index on `token_hash` is the final race backstop.

use super::context::AuthContext;
use super::error::{AuthError, internal};
use super::opaque::{self, TokenHash};
use super::session::{TokenPair, issue_refresh};
use crate::clock::Clock;
use crate::db;
use crate::domain::{RefreshTokenId, Role, TenantId, UserId};
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

/// Refresh request body — the opaque (routable) refresh token.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct RefreshRequest {
    pub(crate) refresh_token: String,
}

/// A refresh-token row joined with its user's role.
struct RefreshRow {
    id: RefreshTokenId,
    user_id: UserId,
    family_id: Uuid,
    replaced_by: Option<Uuid>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    role: Role,
}

/// What to do with a presented token.
enum Disposition {
    /// Current and valid — rotate it.
    Live,
    /// Already rotated and presented again — a replay; revoke the family.
    Reuse,
    /// Revoked (not via rotation) or expired — reject without family revoke.
    Dead,
}

/// Rotates a refresh token, returning a fresh access + refresh pair.
///
/// # Errors
///
/// [`AuthError::InvalidToken`] if the token is malformed, unknown, expired,
/// revoked, or replayed; [`AuthError::Internal`] on a database or signing fault.
pub(crate) async fn refresh(
    pool: &sqlx::PgPool,
    clock: &dyn Clock,
    auth: &AuthContext,
    request: RefreshRequest,
) -> Result<TokenPair, AuthError> {
    let now = clock.now_utc();
    let (tenant, hash) =
        opaque::parse(&request.refresh_token).map_err(|_| AuthError::InvalidToken)?;

    let mut tx = db::begin_tenant_tx(pool, tenant).await.map_err(internal)?;
    let Some(row) = fetch_row(&mut tx, &hash).await? else {
        return Err(AuthError::InvalidToken);
    };

    match classify(&row, now) {
        Disposition::Reuse => {
            // Persist the family revocation before reporting the failure.
            revoke_family(&mut tx, row.family_id, now).await?;
            tx.commit().await.map_err(internal)?;
            Err(AuthError::InvalidToken)
        }
        // Dropping `tx` rolls back; nothing was written.
        Disposition::Dead => Err(AuthError::InvalidToken),
        Disposition::Live => {
            let pair = rotate(&mut tx, auth, now, &row, tenant).await?;
            tx.commit().await.map_err(internal)?;
            Ok(pair)
        }
    }
}

/// Loads the row for `hash` (RLS already scopes it to the token's tenant),
/// joined with the user's current role.
/// Raw column tuple read for a refresh-token row joined with its user's role:
/// `(id, user_id, family_id, replaced_by, expires_at, revoked_at, role)`.
type RefreshTokenColumns = (
    Uuid,
    Uuid,
    Uuid,
    Option<Uuid>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Role,
);

async fn fetch_row(
    conn: &mut PgConnection,
    hash: &TokenHash,
) -> Result<Option<RefreshRow>, AuthError> {
    let row: Option<RefreshTokenColumns> = sqlx::query_as(
        "SELECT rt.id, rt.user_id, rt.family_id, rt.replaced_by, rt.expires_at, \
             rt.revoked_at, u.role \
             FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id \
             WHERE rt.token_hash = $1",
    )
    .bind(hash.as_bytes())
    .fetch_optional(&mut *conn)
    .await
    .map_err(internal)?;

    match row {
        None => Ok(None),
        Some((id, user_id, family_id, replaced_by, expires_at, revoked_at, role)) => {
            Ok(Some(RefreshRow {
                id: RefreshTokenId::try_from(id).map_err(internal)?,
                user_id: UserId::try_from(user_id).map_err(internal)?,
                family_id,
                replaced_by,
                expires_at,
                revoked_at,
                role,
            }))
        }
    }
}

/// Classifies a presented token. A revoked row that *was rotated*
/// (`replaced_by` set) means someone replayed a superseded token — reuse.
fn classify(row: &RefreshRow, now: DateTime<Utc>) -> Disposition {
    if row.revoked_at.is_some() && row.replaced_by.is_some() {
        return Disposition::Reuse;
    }
    if row.revoked_at.is_some() {
        return Disposition::Dead;
    }
    if row.expires_at <= now {
        return Disposition::Dead;
    }
    Disposition::Live
}

/// Issues a successor token in the same family and retires the presented one.
async fn rotate(
    conn: &mut PgConnection,
    auth: &AuthContext,
    now: DateTime<Utc>,
    row: &RefreshRow,
    tenant: TenantId,
) -> Result<TokenPair, AuthError> {
    let access_token = auth
        .issue_access(row.user_id, tenant, row.role, now)
        .map_err(internal)?;
    let (refresh_token, successor) = issue_refresh(
        &mut *conn,
        tenant,
        row.user_id,
        row.family_id,
        now,
        auth.refresh_ttl(),
    )
    .await?;

    let affected = sqlx::query(
        "UPDATE refresh_tokens SET replaced_by = $1, revoked_at = $2 \
         WHERE id = $3 AND revoked_at IS NULL",
    )
    .bind(successor.as_uuid())
    .bind(now)
    .bind(row.id.as_uuid())
    .execute(&mut *conn)
    .await
    .map_err(internal)?
    .rows_affected();
    // 0 ⇒ a concurrent rotation already retired this row; reject and roll back.
    if affected != 1 {
        return Err(AuthError::InvalidToken);
    }

    Ok(TokenPair::bearer(
        access_token,
        auth.access_ttl_secs(),
        refresh_token,
    ))
}

/// Revokes every live token in a family (theft response).
async fn revoke_family(
    conn: &mut PgConnection,
    family: Uuid,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    assert!(!family.is_nil(), "invariant: family id is non-nil");
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = $1 WHERE family_id = $2 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(family)
    .execute(&mut *conn)
    .await
    .map_err(internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RefreshRequest, refresh};
    use crate::auth::error::AuthError;
    use crate::auth::fixtures::login_fixture;
    use crate::testsupport;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    fn req(token: &str) -> RefreshRequest {
        RefreshRequest {
            refresh_token: token.to_owned(),
        }
    }

    #[sqlx::test]
    async fn rotation_issues_new_pair_and_retires_old(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let (auth, first) = login_fixture(&pool).await;
        let clock = testsupport::test_clock();

        let rotated = refresh(&pool, clock.as_ref(), &auth, req(&first))
            .await
            .expect("first refresh rotates");
        assert_ne!(
            rotated.refresh_token, first,
            "a new refresh token is issued"
        );

        // The original token is now retired and must not refresh again.
        let err = refresh(&pool, clock.as_ref(), &auth, req(&first))
            .await
            .expect_err("retired token rejected");
        assert_eq!(err, AuthError::InvalidToken);
    }

    #[sqlx::test]
    async fn the_rotated_successor_works(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let (auth, first) = login_fixture(&pool).await;
        let clock = testsupport::test_clock();

        let rotated = refresh(&pool, clock.as_ref(), &auth, req(&first))
            .await
            .expect("rotate once");
        let again = refresh(&pool, clock.as_ref(), &auth, req(&rotated.refresh_token))
            .await
            .expect("successor rotates");
        assert!(
            !again.access_token.is_empty(),
            "successor yields a fresh access token"
        );
    }

    #[sqlx::test]
    async fn replaying_a_rotated_token_revokes_the_whole_family(
        opts: PgPoolOptions,
        conn: PgConnectOptions,
    ) {
        let pool = testsupport::app_pool(opts, conn).await;
        let (auth, first) = login_fixture(&pool).await;
        let clock = testsupport::test_clock();

        // Rotate once: `first` is now retired, `second` is live.
        let second = refresh(&pool, clock.as_ref(), &auth, req(&first))
            .await
            .expect("rotate")
            .refresh_token;
        // Replay the retired `first`: theft detected ⇒ revoke the family.
        let err = refresh(&pool, clock.as_ref(), &auth, req(&first))
            .await
            .expect_err("replay rejected");
        assert_eq!(err, AuthError::InvalidToken);
        // The legitimate live token `second` is now dead too.
        let dead = refresh(&pool, clock.as_ref(), &auth, req(&second))
            .await
            .expect_err("family revoked");
        assert_eq!(dead, AuthError::InvalidToken);
    }

    #[sqlx::test]
    async fn expired_refresh_token_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let (auth, first) = login_fixture(&pool).await;

        // Advance a fresh clock past the 30-day refresh lifetime.
        let clock = testsupport::test_clock();
        clock.advance(std::time::Duration::from_secs(2_592_000 + 1));
        let err = refresh(&pool, clock.as_ref(), &auth, req(&first))
            .await
            .expect_err("expired token rejected");
        assert_eq!(err, AuthError::InvalidToken);
    }

    #[sqlx::test]
    async fn garbage_token_is_rejected(opts: PgPoolOptions, conn: PgConnectOptions) {
        let pool = testsupport::app_pool(opts, conn).await;
        let auth = testsupport::auth_context();
        let clock = testsupport::test_clock();
        let err = refresh(&pool, clock.as_ref(), &auth, req("not-a-token"))
            .await
            .expect_err("garbage rejected");
        assert_eq!(err, AuthError::InvalidToken);
    }
}
