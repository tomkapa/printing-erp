//! Routable opaque tokens for refresh and password-reset.
//!
//! Wire form: `<tenant_uuid>.<base64url(32 random bytes)>`. The tenant prefix
//! lets the server open the correct Row-Level-Security transaction *before*
//! looking the token up — necessary because the access token may already be
//! expired, so the tenant has no other source. The token is opaque to the
//! client; the server treats the whole string as the credential.
//!
//! Only `sha256(tenant_bytes ++ secret)` is ever stored (`refresh_tokens` /
//! `password_reset_tokens`, 32-byte `BYTEA`). Binding the tenant into the hash
//! means a forged prefix cannot collide with another tenant's row, and storing
//! only the hash means a database leak does not expose usable tokens.

use super::limits::{MAX_OPAQUE_TOKEN_BYTES, OPAQUE_SECRET_BYTES};
use crate::domain::TenantId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore as _;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// SHA-256 digest of a routable token, as stored in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenHash([u8; 32]);

impl TokenHash {
    /// The 32 raw bytes, for binding to a `BYTEA` column.
    pub(crate) const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A freshly minted token: the `raw` string is returned to the client exactly
/// once; only `hash` is persisted.
#[derive(Debug)]
pub(crate) struct MintedToken {
    /// The wire form handed to the client. Never stored.
    pub(crate) raw: String,
    /// The digest to store and later match against.
    pub(crate) hash: TokenHash,
}

/// Why parsing a presented token failed (CLAUDE.md §12).
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum OpaqueError {
    /// The token exceeded [`MAX_OPAQUE_TOKEN_BYTES`].
    #[error("token too long")]
    TooLong,

    /// The token was not `<uuid>.<base64url(32 bytes)>`.
    #[error("malformed token")]
    Malformed,
}

/// Mints a new routable token for `tenant`: 32 CSPRNG bytes, base64url-encoded
/// behind the tenant prefix, plus the digest to persist.
pub(crate) fn mint(tenant: TenantId) -> MintedToken {
    let mut secret = [0_u8; OPAQUE_SECRET_BYTES];
    let mut rng = OsRng;
    rng.fill_bytes(&mut secret);
    assert_eq!(
        secret.len(),
        OPAQUE_SECRET_BYTES,
        "invariant: secret is 32 bytes"
    );

    let hash = hash_parts(tenant, &secret);
    let raw = format!("{}.{}", tenant.as_uuid(), URL_SAFE_NO_PAD.encode(secret));
    assert!(
        raw.len() <= MAX_OPAQUE_TOKEN_BYTES,
        "invariant: minted token fits the size cap"
    );
    MintedToken { raw, hash }
}

/// Parses a presented token into its tenant and the digest to look up. The
/// caller opens `tenant`'s RLS transaction, then matches `token_hash` against
/// [`TokenHash::as_bytes`].
///
/// # Errors
///
/// Returns [`OpaqueError`] if the token is oversized or not well formed.
pub(crate) fn parse(raw: &str) -> Result<(TenantId, TokenHash), OpaqueError> {
    if raw.len() > MAX_OPAQUE_TOKEN_BYTES {
        return Err(OpaqueError::TooLong);
    }
    let (tenant_part, secret_part) = raw.split_once('.').ok_or(OpaqueError::Malformed)?;
    let tenant = TenantId::try_from(tenant_part).map_err(|_| OpaqueError::Malformed)?;

    let decoded = URL_SAFE_NO_PAD
        .decode(secret_part)
        .map_err(|_| OpaqueError::Malformed)?;
    let secret: [u8; OPAQUE_SECRET_BYTES] =
        decoded.try_into().map_err(|_| OpaqueError::Malformed)?;

    Ok((tenant, hash_parts(tenant, &secret)))
}

/// Computes `sha256(tenant_uuid_bytes ++ secret)`.
fn hash_parts(tenant: TenantId, secret: &[u8; OPAQUE_SECRET_BYTES]) -> TokenHash {
    let mut hasher = Sha256::new();
    hasher.update(tenant.as_uuid().as_bytes());
    hasher.update(secret);
    let digest = hasher.finalize();

    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    TokenHash(out)
}

#[cfg(test)]
mod tests {
    use super::{OpaqueError, mint, parse};
    use crate::domain::TenantId;
    use uuid::Uuid;

    fn tenant(n: u128) -> TenantId {
        TenantId::try_from(Uuid::from_u128(n)).expect("tenant id")
    }

    #[test]
    fn mint_then_parse_recovers_tenant_and_matching_hash() {
        let t = tenant(0x1234);
        let minted = mint(t);
        let (parsed_tenant, parsed_hash) = parse(&minted.raw).expect("parse minted token");
        assert_eq!(parsed_tenant, t, "tenant prefix round-trips");
        assert_eq!(
            parsed_hash, minted.hash,
            "re-deriving the hash from the wire form matches the stored hash"
        );
    }

    #[test]
    fn each_mint_is_unique() {
        let t = tenant(1);
        let a = mint(t);
        let b = mint(t);
        assert_ne!(a.raw, b.raw, "fresh randomness per mint");
        assert_ne!(a.hash, b.hash, "distinct secrets ⇒ distinct hashes");
    }

    #[test]
    fn forged_tenant_prefix_changes_the_hash() {
        // Take a real token and swap its tenant prefix for another tenant's id,
        // keeping the same secret. The recomputed hash must differ, so a replay
        // under the wrong tenant can never match the original row.
        let minted = mint(tenant(7));
        let secret_part = minted.raw.split_once('.').expect("has a dot").1;
        let forged = format!("{}.{}", tenant(8).as_uuid(), secret_part);
        let (_, forged_hash) = parse(&forged).expect("forged token still parses");
        assert_ne!(forged_hash, minted.hash, "tenant is bound into the hash");
    }

    #[test]
    fn rejects_missing_separator() {
        assert_eq!(parse("no-dot-here").unwrap_err(), OpaqueError::Malformed);
    }

    #[test]
    fn rejects_bad_tenant_uuid() {
        assert_eq!(
            parse("not-a-uuid.AAAA").unwrap_err(),
            OpaqueError::Malformed
        );
    }

    #[test]
    fn rejects_wrong_secret_length() {
        // Valid base64url, but decodes to fewer than 32 bytes.
        let short = format!("{}.{}", tenant(3).as_uuid(), "QUJD"); // "ABC"
        assert_eq!(parse(&short).unwrap_err(), OpaqueError::Malformed);
    }

    #[test]
    fn rejects_oversized_token() {
        let huge = format!("{}.{}", tenant(4).as_uuid(), "A".repeat(200));
        assert_eq!(parse(&huge).unwrap_err(), OpaqueError::TooLong);
    }
}
