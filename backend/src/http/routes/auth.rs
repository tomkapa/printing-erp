//! Authentication route handlers.
//!
//! Each handler is thin glue: it parses a typed request body and delegates to an
//! `auth::*` flow, which owns the security logic. The flows take granular
//! dependencies (`&PgPool`, `&dyn Clock`, `&AuthContext`) so they are unit-tested
//! without HTTP; these handlers wire them to request/response types.

use crate::auth::{
    self, AuthError, ForgotRequest, LoginRequest, LogoutRequest, RefreshRequest, ResetRequest,
    TokenPair,
};
use crate::http::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

/// `POST /auth/login` — exchanges credentials for an access + refresh token pair.
pub(crate) async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<TokenPair>, AuthError> {
    let pair = auth::login(&state.db, state.clock().as_ref(), state.auth(), request).await?;
    Ok(Json(pair))
}

/// `POST /auth/refresh` — rotates a refresh token for a fresh token pair.
pub(crate) async fn refresh(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<TokenPair>, AuthError> {
    let pair = auth::refresh(&state.db, state.clock().as_ref(), state.auth(), request).await?;
    Ok(Json(pair))
}

/// `POST /auth/logout` — revokes the presented refresh token's session family.
pub(crate) async fn logout(
    State(state): State<AppState>,
    Json(request): Json<LogoutRequest>,
) -> Result<StatusCode, AuthError> {
    auth::logout(&state.db, state.clock().as_ref(), request).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /auth/password/forgot` — issues a reset token (always 200, no
/// enumeration); the token is delivered out of band, never in the response.
pub(crate) async fn password_forgot(
    State(state): State<AppState>,
    Json(request): Json<ForgotRequest>,
) -> Result<StatusCode, AuthError> {
    auth::forgot_password(&state.db, state.clock().as_ref(), state.auth(), request).await?;
    Ok(StatusCode::OK)
}

/// `POST /auth/password/reset` — consumes a reset token, sets the new password,
/// and revokes the user's refresh tokens.
pub(crate) async fn password_reset(
    State(state): State<AppState>,
    Json(request): Json<ResetRequest>,
) -> Result<StatusCode, AuthError> {
    auth::reset_password(&state.db, state.clock().as_ref(), request).await?;
    Ok(StatusCode::NO_CONTENT)
}
