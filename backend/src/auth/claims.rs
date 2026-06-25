//! Access-token claims and the HS256 codec.
//!
//! The codec uses `jsonwebtoken` only for signing, signature verification, claim
//! deserialization, and the `iss` check. Temporal validation is done **here**,
//! against an injected wall-clock time, because `jsonwebtoken`'s built-in `exp`
//! check reads `SystemTime::now()` internally — which would violate "tests own
//! the clock" (CLAUDE.md §11) and make expiry tests non-deterministic. The
//! algorithm is pinned to HS256 on decode, rejecting `alg` downgrade/confusion.

use super::limits::MAX_IAT_SKEW_SECS;
use crate::domain::{Role, TenantId, UserId};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use thiserror::Error;
use uuid::Uuid;

/// Why minting or verifying an access token failed (CLAUDE.md §12). Verification
/// failures are deliberately coarse so a caller cannot learn *why* a token was
/// rejected (e.g. expired vs forged) — the HTTP layer collapses them to 401.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum JwtError {
    /// The claims could not be serialized/signed.
    #[error("failed to encode access token")]
    Encode,

    /// Signature invalid, `alg` not HS256, `iss` mismatch, or claims malformed.
    #[error("invalid access token")]
    Invalid,

    /// Signature valid but the token's `exp` is at or before now.
    #[error("expired access token")]
    Expired,

    /// Signature valid but `iat` is implausibly far in the future (forged).
    #[error("access token not yet valid")]
    NotYetValid,
}

/// The signed claims of an access token. A boundary DTO: `serde` runs only here,
/// and deserializing `sub`/`tid`/`role` funnels through their `TryFrom`
/// constructors (a nil/malformed id fails decode).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct AccessClaims {
    /// Subject — the authenticated user.
    pub(crate) sub: UserId,
    /// Tenant the user is acting within; drives Row-Level Security downstream.
    pub(crate) tid: TenantId,
    /// The user's role. Carried here; authorization is enforced downstream by
    /// the [`Require`](crate::http::Require) guard against the `authz` policy (#13).
    pub(crate) role: Role,
    /// Issued-at, unix seconds.
    pub(crate) iat: i64,
    /// Expiry, unix seconds.
    pub(crate) exp: i64,
    /// Unique token id, for tracing/correlation.
    pub(crate) jti: Uuid,
    /// Issuer; checked against the configured value on decode.
    pub(crate) iss: String,
}

impl AccessClaims {
    /// Builds claims for `user`/`tenant`/`role` valid over `[iat_ts, exp_ts)`.
    pub(crate) fn new(
        user: UserId,
        tenant: TenantId,
        role: Role,
        issuer: String,
        iat_ts: i64,
        exp_ts: i64,
    ) -> Self {
        assert!(
            exp_ts > iat_ts,
            "invariant: token must expire after it is issued"
        );
        assert!(!issuer.is_empty(), "invariant: issuer is non-empty");
        Self {
            sub: user,
            tid: tenant,
            role,
            iat: iat_ts,
            exp: exp_ts,
            jti: Uuid::new_v4(),
            iss: issuer,
        }
    }
}

/// Signs `claims` into a compact HS256 JWT. Clock-free: `iat`/`exp` are already
/// computed by the caller from its [`Clock`](crate::clock::Clock).
pub(crate) fn encode_access(claims: &AccessClaims, key: &EncodingKey) -> Result<String, JwtError> {
    jsonwebtoken::encode(&Header::new(Algorithm::HS256), claims, key).map_err(|_| JwtError::Encode)
}

/// Verifies signature + issuer via `jsonwebtoken`, then validates `exp`/`iat`
/// against `now_ts` (unix seconds) here. `validation` must pin HS256 and disable
/// `jsonwebtoken`'s own temporal checks (see [`build_validation`]).
pub(crate) fn decode_access(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
    now_ts: i64,
) -> Result<AccessClaims, JwtError> {
    let data = jsonwebtoken::decode::<AccessClaims>(token, key, validation)
        .map_err(|_| JwtError::Invalid)?;
    check_temporal(&data.claims, now_ts)?;
    Ok(data.claims)
}

/// Builds the decode policy: pin HS256, require + check `iss`, and turn OFF
/// `jsonwebtoken`'s `exp`/`nbf` validation (we do it against the injected clock).
pub(crate) fn build_validation(issuer: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.algorithms = vec![Algorithm::HS256];
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation.set_issuer(&[issuer]);
    validation
}

/// Validates the token's lifetime against the current wall-clock second.
fn check_temporal(claims: &AccessClaims, now_ts: i64) -> Result<(), JwtError> {
    // Reachable only after signature verification, so these hold for our tokens.
    assert!(
        claims.exp >= claims.iat,
        "invariant: signed token exp not before iat"
    );
    assert!(now_ts >= 0, "invariant: unix time is non-negative");
    if claims.exp <= now_ts {
        return Err(JwtError::Expired);
    }
    if claims.iat > now_ts + MAX_IAT_SKEW_SECS {
        return Err(JwtError::NotYetValid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AccessClaims, JwtError, build_validation, check_temporal};
    use crate::domain::{Role, TenantId, UserId};
    use uuid::Uuid;

    fn claims(iat: i64, exp: i64) -> AccessClaims {
        AccessClaims::new(
            UserId::try_from(Uuid::from_u128(1)).expect("user id"),
            TenantId::try_from(Uuid::from_u128(2)).expect("tenant id"),
            Role::Admin,
            "printing-erp".to_owned(),
            iat,
            exp,
        )
    }

    #[test]
    fn live_token_passes_temporal_check() {
        let c = claims(1_000, 2_000);
        assert_eq!(check_temporal(&c, 1_500), Ok(()));
    }

    #[test]
    fn expired_token_is_rejected() {
        let c = claims(1_000, 2_000);
        assert_eq!(check_temporal(&c, 2_000), Err(JwtError::Expired));
        assert_eq!(check_temporal(&c, 2_001), Err(JwtError::Expired));
    }

    #[test]
    fn far_future_iat_is_rejected() {
        let c = claims(10_000, 11_000);
        assert_eq!(check_temporal(&c, 9_000), Err(JwtError::NotYetValid));
    }

    #[test]
    fn build_validation_pins_hs256_and_disables_builtin_exp() {
        let validation = build_validation("printing-erp");
        assert!(!validation.validate_exp, "we validate exp ourselves");
        assert_eq!(validation.algorithms, vec![jsonwebtoken::Algorithm::HS256]);
    }
}
