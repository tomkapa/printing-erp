//! [`AuthContext`]: the process-wide authentication keys and policy, built once
//! at startup (CLAUDE.md §9) and shared as an `Arc` through `AppState`.
//!
//! It owns the HS256 signing/verifying keys (which never leave the struct), the
//! pre-built decode [`Validation`], the issuer, and the token lifetimes. Handlers
//! and the `AuthPrincipal` extractor mint and verify access tokens through it.

use super::claims::{AccessClaims, JwtError, build_validation, decode_access, encode_access};
use super::limits::MIN_JWT_SECRET_BYTES;
use super::notifier::PasswordResetNotifier;
use crate::config::AuthSettings;
use crate::domain::{Role, TenantId, UserId};
use chrono::{DateTime, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
use secrecy::ExposeSecret as _;
use std::sync::Arc;
use std::time::Duration;

/// Authentication keys, decode policy, token lifetimes, and reset delivery.
pub(crate) struct AuthContext {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    issuer: String,
    access_ttl: Duration,
    refresh_ttl: Duration,
    reset_ttl: Duration,
    notifier: Arc<dyn PasswordResetNotifier>,
}

impl AuthContext {
    /// Builds the context from [`AuthSettings`] and a reset-token `notifier`,
    /// deriving the HS256 keys from the signing secret. Panics (a startup
    /// assertion, §6) if the secret is shorter than [`MIN_JWT_SECRET_BYTES`] — a
    /// misconfiguration the process must not run with.
    pub(crate) fn new(settings: &AuthSettings, notifier: Arc<dyn PasswordResetNotifier>) -> Self {
        let secret = settings.jwt_secret.expose_secret();
        assert!(
            secret.len() >= MIN_JWT_SECRET_BYTES,
            "invariant: JWT secret must be at least {MIN_JWT_SECRET_BYTES} bytes"
        );
        assert!(
            !settings.issuer.is_empty(),
            "invariant: issuer is configured"
        );
        let bytes = secret.as_bytes();
        Self {
            encoding_key: EncodingKey::from_secret(bytes),
            decoding_key: DecodingKey::from_secret(bytes),
            validation: build_validation(&settings.issuer),
            issuer: settings.issuer.clone(),
            access_ttl: settings.access_ttl(),
            refresh_ttl: settings.refresh_ttl(),
            reset_ttl: settings.reset_ttl(),
            notifier,
        }
    }

    /// The password-reset notifier, for dispatching a freshly issued token.
    pub(crate) fn notifier(&self) -> &dyn PasswordResetNotifier {
        self.notifier.as_ref()
    }

    /// Refresh-token lifetime, for stamping `expires_at` on new refresh rows.
    pub(crate) const fn refresh_ttl(&self) -> Duration {
        self.refresh_ttl
    }

    /// Reset-token lifetime, for stamping `expires_at` on new reset rows.
    pub(crate) const fn reset_ttl(&self) -> Duration {
        self.reset_ttl
    }

    /// Access-token lifetime in whole seconds, for the `expires_in` response.
    pub(crate) const fn access_ttl_secs(&self) -> u64 {
        self.access_ttl.as_secs()
    }

    /// Mints a signed access token for `user`/`tenant`/`role`, valid from `now`
    /// for [`access_ttl`](Self::access_ttl_secs).
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::Encode`] if the lifetime overflows the unix-second
    /// range or signing fails.
    pub(crate) fn issue_access(
        &self,
        user: UserId,
        tenant: TenantId,
        role: Role,
        now: DateTime<Utc>,
    ) -> Result<String, JwtError> {
        let iat_ts = now.timestamp();
        let ttl_secs = i64::try_from(self.access_ttl.as_secs()).map_err(|_| JwtError::Encode)?;
        let exp_ts = iat_ts.checked_add(ttl_secs).ok_or(JwtError::Encode)?;
        let claims = AccessClaims::new(user, tenant, role, self.issuer.clone(), iat_ts, exp_ts);
        encode_access(&claims, &self.encoding_key)
    }

    /// Verifies an access token and returns its claims if signature, issuer, and
    /// lifetime (against `now`) all hold.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError`] (`Invalid`/`Expired`/`NotYetValid`) on any failure.
    pub(crate) fn decode_access(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<AccessClaims, JwtError> {
        decode_access(token, &self.decoding_key, &self.validation, now.timestamp())
    }
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the signing keys.
        f.debug_struct("AuthContext")
            .field("issuer", &self.issuer)
            .field("access_ttl", &self.access_ttl)
            .field("refresh_ttl", &self.refresh_ttl)
            .field("reset_ttl", &self.reset_ttl)
            .field("notifier", &self.notifier)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::AuthContext;
    use crate::auth::claims::JwtError;
    use crate::config::AuthSettings;
    use crate::domain::{Role, TenantId, UserId};
    use chrono::{TimeZone as _, Utc};
    use secrecy::SecretString;
    use uuid::Uuid;

    fn settings(secret: &str, issuer: &str) -> AuthSettings {
        AuthSettings {
            jwt_secret: SecretString::from(secret.to_owned()),
            access_ttl_secs: 900,
            refresh_ttl_secs: 2_592_000,
            reset_ttl_secs: 3_600,
            issuer: issuer.to_owned(),
        }
    }

    fn ctx(secret: &str, issuer: &str) -> AuthContext {
        AuthContext::new(
            &settings(secret, issuer),
            std::sync::Arc::new(crate::auth::notifier::LoggingNotifier),
        )
    }

    fn ids() -> (UserId, TenantId) {
        (
            UserId::try_from(Uuid::from_u128(11)).expect("user"),
            TenantId::try_from(Uuid::from_u128(22)).expect("tenant"),
        )
    }

    fn at(secs: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).single().expect("timestamp")
    }

    #[test]
    fn round_trips_user_tenant_and_role() {
        let context = ctx("a-test-signing-secret-of-32+chars!!", "printing-erp");
        let (user, tenant) = ids();
        let token = context
            .issue_access(user, tenant, Role::Coordinator, at(1_000))
            .expect("issue");
        let claims = context.decode_access(&token, at(1_100)).expect("decode");
        assert_eq!(claims.sub, user);
        assert_eq!(claims.tid, tenant);
        assert_eq!(claims.role, Role::Coordinator);
    }

    #[test]
    fn rejects_token_after_expiry() {
        let context = ctx("a-test-signing-secret-of-32+chars!!", "printing-erp");
        let (user, tenant) = ids();
        let token = context
            .issue_access(user, tenant, Role::Admin, at(1_000))
            .expect("issue");
        // 900s ttl ⇒ exp = 1900; one second past must be rejected.
        let err = context
            .decode_access(&token, at(1_901))
            .expect_err("expired");
        assert_eq!(err, JwtError::Expired);
    }

    #[test]
    fn rejects_token_signed_with_a_different_secret() {
        let signer = ctx("first-secret-aaaaaaaaaaaaaaaaaaaaaaaa", "printing-erp");
        let other = ctx("second-secret-bbbbbbbbbbbbbbbbbbbbbbbb", "printing-erp");
        let (user, tenant) = ids();
        let token = signer
            .issue_access(user, tenant, Role::Sales, at(1_000))
            .expect("issue");
        let err = other.decode_access(&token, at(1_100)).expect_err("bad sig");
        assert_eq!(err, JwtError::Invalid);
    }

    #[test]
    fn rejects_tampered_token() {
        let context = ctx("a-test-signing-secret-of-32+chars!!", "printing-erp");
        let (user, tenant) = ids();
        let mut token = context
            .issue_access(user, tenant, Role::Operator, at(1_000))
            .expect("issue");
        token.pop();
        token.push(if token.ends_with('A') { 'B' } else { 'A' });
        let err = context
            .decode_access(&token, at(1_100))
            .expect_err("tampered");
        assert_eq!(err, JwtError::Invalid);
    }

    #[test]
    fn rejects_token_from_a_different_issuer() {
        let signer = ctx("shared-secret-cccccccccccccccccccccccc", "issuer-a");
        let verifier = ctx("shared-secret-cccccccccccccccccccccccc", "issuer-b");
        let (user, tenant) = ids();
        let token = signer
            .issue_access(user, tenant, Role::Scheduler, at(1_000))
            .expect("issue");
        let err = verifier
            .decode_access(&token, at(1_100))
            .expect_err("issuer mismatch");
        assert_eq!(err, JwtError::Invalid);
    }
}
