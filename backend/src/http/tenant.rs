//! Request-scoped tenant resolution.
//!
//! [`TenantScope`] is an axum extractor that yields the [`TenantId`] a request
//! operates under. Handlers take it as an argument and hand it to
//! [`db::begin_tenant_tx`](crate::db::begin_tenant_tx) to open a tenant-scoped
//! transaction.
//!
//! SECURITY — pre-auth placeholder. The tenant is read from the client-supplied
//! `X-Tenant-Id` header, which any caller can forge. This is acceptable ONLY
//! until authentication lands: at that point the tenant must come from the
//! authenticated principal's claim, not a header. Row-Level Security is a
//! backstop against a *missing* tenant filter — it does NOT defend against a
//! caller that deliberately claims another tenant. Every resolution emits a
//! `warn!` so this path is impossible to ship to production unnoticed.

use crate::domain::{DomainError, TenantId};
use crate::http::limits;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Header carrying the (currently unauthenticated) tenant identifier.
const TENANT_HEADER: &str = "x-tenant-id";

/// Compile-time guard: the byte cap must admit a canonical UUID (36 chars),
/// otherwise every valid id would be rejected as too long.
const _: () = assert!(limits::MAX_TENANT_HEADER_BYTES >= 36);

/// The tenant a request operates under, resolved at the HTTP boundary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TenantScope(pub(crate) TenantId);

/// Why resolving a [`TenantScope`] from a request failed (CLAUDE.md §12).
///
/// Messages never echo the raw header value back to the caller.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum TenantRejection {
    /// No `X-Tenant-Id` header was present.
    #[error("missing X-Tenant-Id header")]
    Missing,

    /// More than one `X-Tenant-Id` header was sent; the intent is ambiguous.
    #[error("duplicate X-Tenant-Id header")]
    Duplicate,

    /// The header value exceeded [`limits::MAX_TENANT_HEADER_BYTES`].
    #[error("X-Tenant-Id header is too long")]
    TooLong,

    /// The header value was not valid ASCII / printable header text.
    #[error("X-Tenant-Id header is not valid text")]
    NotText,

    /// The value was well-formed text but not a valid tenant id.
    #[error("X-Tenant-Id header is not a valid tenant id")]
    Invalid,
}

impl From<DomainError> for TenantRejection {
    fn from(_: DomainError) -> Self {
        // Collapse the parse failure detail; the caller does not get to probe
        // which ids exist via differential error messages.
        Self::Invalid
    }
}

impl IntoResponse for TenantRejection {
    fn into_response(self) -> Response {
        // Every failure is a malformed request from the client's side.
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

impl<S> FromRequestParts<S> for TenantScope
where
    S: Send + Sync,
{
    type Rejection = TenantRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let mut values = parts.headers.get_all(TENANT_HEADER).iter();
        let raw = values.next().ok_or(TenantRejection::Missing)?;
        if values.next().is_some() {
            return Err(TenantRejection::Duplicate);
        }

        // Length-cap before any parsing work (CLAUDE.md §5).
        if raw.as_bytes().len() > limits::MAX_TENANT_HEADER_BYTES {
            return Err(TenantRejection::TooLong);
        }

        let text = raw.to_str().map_err(|_| TenantRejection::NotText)?;
        let tenant = TenantId::try_from(text)?;

        // SECURITY: unauthenticated tenant claim — see module docs.
        tracing::warn!(
            event = "tenant.resolved_from_header",
            patom.tenant.id = %tenant.as_uuid(),
            "tenant resolved from unauthenticated X-Tenant-Id header (pre-auth)",
        );
        Ok(Self(tenant))
    }
}

#[cfg(test)]
mod tests {
    use super::TenantScope;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    /// Minimal app whose handler echoes the resolved tenant id, so tests assert
    /// both the status and that the correct id was parsed — without needing a
    /// database-backed `AppState`.
    fn app() -> Router {
        async fn echo(TenantScope(tenant): TenantScope) -> String {
            tenant.as_uuid().to_string()
        }
        Router::new().route("/t", get(echo)).with_state(())
    }

    async fn send(req: Request<Body>) -> (StatusCode, String) {
        let response = app().oneshot(req).await.expect("router responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        (
            status,
            String::from_utf8(bytes.to_vec()).expect("utf8 body"),
        )
    }

    /// Sends a request to `/t` with an optional `X-Tenant-Id` header.
    async fn send_header(value: Option<&str>) -> (StatusCode, String) {
        let mut builder = Request::builder().uri("/t");
        if let Some(value) = value {
            builder = builder.header("x-tenant-id", value);
        }
        let req = builder.body(Body::empty()).expect("build request");
        send(req).await
    }

    #[tokio::test]
    async fn valid_header_resolves_tenant() {
        let id = Uuid::new_v4().to_string();
        let (status, body) = send_header(Some(&id)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, id, "handler must see the parsed tenant id");
    }

    #[tokio::test]
    async fn missing_header_is_rejected() {
        let (status, _) = send_header(None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn malformed_header_is_rejected() {
        let (status, _) = send_header(Some("not-a-uuid")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn nil_uuid_header_is_rejected() {
        let (status, _) = send_header(Some(&Uuid::nil().to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oversized_header_is_rejected() {
        let (status, _) = send_header(Some(&"a".repeat(64))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn duplicate_header_is_rejected() {
        let id = Uuid::new_v4().to_string();
        let req = Request::builder()
            .uri("/t")
            .header("x-tenant-id", &id)
            .header("x-tenant-id", Uuid::new_v4().to_string())
            .body(Body::empty())
            .expect("build request");
        let (status, _) = send(req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
