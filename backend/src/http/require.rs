//! Authentication extraction + the authorization guard (RBAC, issue #13).
//!
//! This module owns both halves of access control and deliberately couples them:
//! the verified [`AuthPrincipal`] is produced *only* by the private
//! [`authenticate`] step, which is reachable *only* through the [`Require<C>`]
//! extractor. `AuthPrincipal` has no `FromRequestParts` impl, so a route cannot
//! take `principal: AuthPrincipal` directly — it would fail to compile. The only
//! way to obtain a request's identity is `Require<C>`, and `Require<C>` always
//! checks capability `C` via [`permits`]. "Authenticated but unauthorized" is
//! therefore unrepresentable at the HTTP boundary, not merely discouraged by
//! convention.
//!
//! Ordering matters: authentication runs before authorization, so a request with
//! no/invalid token is `401` (never `403`) and a caller cannot probe which
//! capability a route needs by sending an empty token.

use crate::auth::AuthContext;
use crate::authz::{Capability, permits};
use crate::clock::Clock;
use crate::domain::{Role, TenantId, UserId};
use crate::http::limits::MAX_AUTH_HEADER_BYTES;
use crate::http::state::AppState;
use axum::extract::{FromRef as _, FromRequestParts};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use std::marker::PhantomData;
use std::sync::Arc;
use thiserror::Error;

/// The `Bearer ` scheme prefix, including its trailing space.
const BEARER_PREFIX: &str = "Bearer ";

/// The verified identity a request operates under.
///
/// The tenant comes from a *verified* access-token claim, not a forgeable header,
/// so a caller cannot claim another tenant. It is produced solely by
/// [`authenticate`] (private to this module) and surfaced to handlers through
/// [`Require<C>`] as `guard.principal`; there is intentionally no
/// `FromRequestParts` impl, so it cannot be extracted without the authorization
/// check that `Require` performs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthPrincipal {
    pub(crate) user_id: UserId,
    pub(crate) tenant_id: TenantId,
    pub(crate) role: Role,
}

/// Why authentication failed (CLAUDE.md §12). All variants map to `401`; the
/// distinctions exist for internal tracing, not the client.
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

/// Verifies the request's bearer token and resolves the [`AuthPrincipal`].
///
/// Private by design: this is the single authentication entry point, callable
/// only from [`Require<C>`] in this module, so no route can authenticate without
/// the capability check (see the module docs). Every failure collapses to a
/// generic `401` — a caller never learns whether a token was missing, expired,
/// or forged.
fn authenticate(parts: &Parts, state: &AppState) -> Result<AuthPrincipal, AuthRejection> {
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
    Ok(AuthPrincipal {
        user_id: claims.sub,
        tenant_id: claims.tid,
        role: claims.role,
    })
}

/// A request principal proven to hold capability `C`.
///
/// The wrapped [`AuthPrincipal`] is the verified identity; read it as
/// `guard.principal`. The `PhantomData<C>` carries only the type-level capability
/// and adds no runtime cost.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Require<C: Capability> {
    pub(crate) principal: AuthPrincipal,
    _cap: PhantomData<C>,
}

/// Why an authorization guard refused a request (CLAUDE.md §12).
///
/// Authentication failures propagate unchanged (uniform `401`); a successfully
/// authenticated caller lacking the capability is `403`. The two are distinct so
/// a client learns "log in" vs "you may not", but neither reveals *which* check
/// or capability was involved.
#[derive(Debug, Error)]
pub(crate) enum AuthzRejection {
    /// Authentication itself failed — delegate to the `401` response.
    #[error(transparent)]
    Unauthenticated(#[from] AuthRejection),

    /// Authenticated, but the role does not hold the required permission.
    #[error("forbidden")]
    Forbidden,
}

impl IntoResponse for AuthzRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated(rejection) => rejection.into_response(),
            // Empty body: never disclose which capability was required.
            Self::Forbidden => StatusCode::FORBIDDEN.into_response(),
        }
    }
}

impl<C> FromRequestParts<AppState> for Require<C>
where
    // `Send + Sync + 'static` lets axum prove the extractor future is `Send`
    // for any capability; the zero-sized markers satisfy it trivially.
    C: Capability + Send + Sync + 'static,
{
    type Rejection = AuthzRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Authentication first (CLAUDE.md ordering invariant): a bad token is a
        // 401 before any authorization decision is made.
        let principal = authenticate(parts, state)?;
        if permits(principal.role, C::PERMISSION) {
            // Allow is the common path; log at DEBUG so it stays observable
            // without flooding INFO on every authorized request. The shape is
            // forward-compatible with an `authz.decisions{decision,permission}`
            // counter once a metrics meter exists (CLAUDE.md §2).
            tracing::debug!(
                event = "authz.decision",
                decision = "allow",
                permission = ?C::PERMISSION,
                role = ?principal.role,
                tenant_id = %principal.tenant_id.as_uuid(),
                user_id = %principal.user_id.as_uuid(),
            );
            return Ok(Self {
                principal,
                _cap: PhantomData,
            });
        }
        // Deny is operationally interesting but expected, not a fault — WARN, not
        // ERROR (CLAUDE.md §2 severity table reserves ERROR for user-visible faults).
        tracing::warn!(
            event = "authz.decision",
            decision = "deny",
            permission = ?C::PERMISSION,
            role = ?principal.role,
            tenant_id = %principal.tenant_id.as_uuid(),
            user_id = %principal.user_id.as_uuid(),
        );
        Err(AuthzRejection::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthRejection, AuthzRejection};
    use axum::http::StatusCode;
    use axum::response::IntoResponse as _;

    #[test]
    fn forbidden_maps_to_403() {
        let response = AuthzRejection::Forbidden.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn unauthenticated_maps_to_401() {
        // Any authentication failure must surface as 401, never 403, so the
        // authn-before-authz ordering is observable to the client.
        let response = AuthzRejection::from(AuthRejection::Missing).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = AuthzRejection::from(AuthRejection::Invalid).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
