//! Session issuance shared by login and refresh: minting an access + refresh
//! token pair and persisting the refresh row.
//!
//! A refresh token belongs to a *family* (`family_id`): login starts a new
//! family, refresh extends the current one. Reuse detection (in `refresh`)
//! operates on the family. Only the token's SHA-256 hash is stored.

use super::context::AuthContext;
use super::error::{AuthError, deadline, internal};
use super::opaque;
use crate::domain::{RefreshTokenId, Role, TenantId, UserId};
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use std::time::Duration;
use uuid::Uuid;

/// The credential pair returned by login and refresh. Serialized as the JSON
/// response body; `token_type` is always `"Bearer"`.
#[derive(Debug, serde::Serialize)]
pub(crate) struct TokenPair {
    pub(crate) access_token: String,
    pub(crate) token_type: &'static str,
    pub(crate) expires_in: u64,
    pub(crate) refresh_token: String,
}

impl TokenPair {
    /// Assembles a `Bearer` token pair. The single place `token_type` is set.
    pub(crate) const fn bearer(
        access_token: String,
        expires_in: u64,
        refresh_token: String,
    ) -> Self {
        Self {
            access_token,
            token_type: "Bearer",
            expires_in,
            refresh_token,
        }
    }
}

/// Mints an access token plus a fresh refresh token in `family`, persisting the
/// refresh row on `conn` (which must already be inside the tenant's RLS
/// transaction). Used by both login (new family) and refresh (rotation).
///
/// # Errors
///
/// Returns [`AuthError::Internal`] if signing or the insert fails.
pub(crate) async fn issue_pair(
    conn: &mut PgConnection,
    auth: &AuthContext,
    now: DateTime<Utc>,
    user: UserId,
    tenant: TenantId,
    role: Role,
    family: Uuid,
) -> Result<TokenPair, AuthError> {
    assert!(
        !family.is_nil(),
        "invariant: a session family id is non-nil"
    );
    let access_token = auth
        .issue_access(user, tenant, role, now)
        .map_err(internal)?;
    let (refresh_token, _id) =
        issue_refresh(conn, tenant, user, family, now, auth.refresh_ttl()).await?;
    Ok(TokenPair::bearer(
        access_token,
        auth.access_ttl_secs(),
        refresh_token,
    ))
}

/// Mints and stores a single refresh token, returning the raw wire form (the
/// only time it exists outside the client) and the new row's id (so a rotation
/// can chain `replaced_by` to it). Only the token's hash is persisted.
///
/// # Errors
///
/// Returns [`AuthError::Internal`] if the lifetime overflows or the insert fails.
pub(crate) async fn issue_refresh(
    conn: &mut PgConnection,
    tenant: TenantId,
    user: UserId,
    family: Uuid,
    now: DateTime<Utc>,
    ttl: Duration,
) -> Result<(String, RefreshTokenId), AuthError> {
    let minted = opaque::mint(tenant);
    let expires_at = deadline(now, ttl)?;
    assert!(
        expires_at > now,
        "invariant: refresh token expires in the future"
    );

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_tokens \
         (tenant_id, user_id, family_id, token_hash, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(tenant.as_uuid())
    .bind(user.as_uuid())
    .bind(family)
    .bind(minted.hash.as_bytes())
    .bind(now)
    .bind(expires_at)
    .fetch_one(conn)
    .await
    .map_err(internal)?;

    let id = RefreshTokenId::try_from(id).map_err(internal)?;
    Ok((minted.raw, id))
}
