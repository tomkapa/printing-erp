//! The authenticated request principal.
//!
//! [`AuthPrincipal`] replaces the pre-auth `X-Tenant-Id` header path: the tenant
//! now comes from a *verified* access-token claim, not a forgeable header, so a
//! caller can no longer claim another tenant. Handlers take it as an argument
//! and hand `tenant_id` to [`db::begin_tenant_tx`](crate::db::begin_tenant_tx).
//!
//! The extractor needs the decoding key and the clock, so it implements
//! `FromRequestParts<AppState>` concretely and pulls both via [`FromRef`]. Every
//! failure collapses to a generic `401` — a caller never learns whether a token
//! was missing, expired, or forged.

use crate::auth::AuthContext;
use crate::clock::Clock;
use crate::domain::{Role, TenantId, UserId};
use crate::http::limits::MAX_AUTH_HEADER_BYTES;
use crate::http::state::AppState;
use axum::extract::{FromRef as _, FromRequestParts};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use thiserror::Error;

/// The `Bearer ` scheme prefix, including its trailing space.
const BEARER_PREFIX: &str = "Bearer ";

/// The verified identity a request operates under.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthPrincipal {
    pub(crate) user_id: UserId,
    pub(crate) tenant_id: TenantId,
    pub(crate) role: Role,
}

/// Why resolving an [`AuthPrincipal`] failed (CLAUDE.md §12). All variants map to
/// `401`; the distinctions exist for internal tracing, not the client.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum AuthRejection {
    /// No `Authorization` header was present.
    #[error("missing bearer token")]
    Missing,

    /// The header was not `Bearer <token>` or not valid header text.
    #[error("malformed authorization header")]
    Malformed,

    /// The header exceeded [`MAX_AUTH_HEADER_BYTES`].
    #[error("authorization header too long")]
    TooLong,

    /// The token's signature, issuer, or lifetime did not validate.
    #[error("invalid bearer token")]
    Invalid,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        // Uniform 401: never reveal which check failed.
        StatusCode::UNAUTHORIZED.into_response()
    }
}

impl FromRequestParts<AppState> for AuthPrincipal {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = Arc::<AuthContext>::from_ref(state);
        let clock = Arc::<dyn Clock>::from_ref(state);

        let header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthRejection::Missing)?;
        // Length-cap before any parsing or verification work (CLAUDE.md §5).
        if header.as_bytes().len() > MAX_AUTH_HEADER_BYTES {
            return Err(AuthRejection::TooLong);
        }
        let raw = header.to_str().map_err(|_| AuthRejection::Malformed)?;
        let token = raw
            .strip_prefix(BEARER_PREFIX)
            .ok_or(AuthRejection::Malformed)?;

        let claims = auth
            .decode_access(token, clock.now_utc())
            .map_err(|_| AuthRejection::Invalid)?;
        Ok(Self {
            user_id: claims.sub,
            tenant_id: claims.tid,
            role: claims.role,
        })
    }
}
