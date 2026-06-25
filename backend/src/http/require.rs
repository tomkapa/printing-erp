//! The authorization guard extractor (RBAC, issue #13).
//!
//! [`Require<C>`] is the HTTP enforcement point for the [`authz`](crate::authz)
//! policy. It runs authentication first by delegating to the existing
//! [`AuthPrincipal`] extractor, then checks the verified role against the
//! capability `C` via [`permits`]. A handler that takes `Require<WriteSettings>`
//! cannot run unless the caller both authenticated *and* holds `WriteSettings`,
//! and the requirement is visible in the signature ("push ifs up", CLAUDE.md §4).
//!
//! Ordering matters: authentication is checked before authorization, so a request
//! with no/invalid token is `401` (never `403`) and a caller cannot probe which
//! capability a route needs by sending an empty token.

use crate::authz::{Capability, permits};
use crate::http::auth_principal::{AuthPrincipal, AuthRejection};
use crate::http::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use std::marker::PhantomData;
use thiserror::Error;

/// A request principal proven to hold capability `C`.
///
/// The wrapped [`AuthPrincipal`] is the same verified identity handlers used
/// before RBAC; read it as `guard.principal`. The `PhantomData<C>` carries only
/// the type-level capability and adds no runtime cost.
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
        let principal = AuthPrincipal::from_request_parts(parts, state).await?;
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
    use super::AuthzRejection;
    use crate::http::auth_principal::AuthRejection;
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
