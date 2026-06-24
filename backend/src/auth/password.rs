//! argon2id password hashing and verification.
//!
//! Hashing uses the OWASP-baseline parameters from [`super::limits`]; tests use
//! a deliberately cheap cost (the algorithm is unchanged, only the work factor).
//! Verification reads the cost + salt embedded in the stored PHC string, so it
//! needs no configured parameters. [`verify_or_dummy`] always performs a real
//! verification — against a fixed dummy hash when no user matched — so login
//! timing does not reveal whether an account exists (anti-enumeration).

use super::limits::{ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM};
use crate::domain::PlaintextPassword;
use argon2::password_hash::{PasswordHash as PhcHash, PasswordHashString, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version};
use rand::rngs::OsRng;
use std::sync::LazyLock;
use thiserror::Error;

/// Failure while hashing a password (CLAUDE.md §12). Verification never errors —
/// it returns `false` — so callers cannot branch on *why* a check failed.
#[derive(Debug, Error)]
pub(crate) enum PasswordError {
    /// The configured argon2 parameters were rejected (a programming error in
    /// the [`limits`](super::limits) constants).
    #[error("invalid argon2 parameters")]
    Params,

    /// Hashing the input failed (e.g. allocation of the memory cost).
    #[error("failed to hash password")]
    Hash,

    /// A stored hash string was not a valid PHC-format argon2 hash.
    #[error("malformed password hash")]
    MalformedHash,
}

/// A stored password hash in PHC string form (`$argon2id$v=19$...`).
///
/// Constructed by [`hash_password`] or parsed from the database via [`TryFrom`]
/// at the row boundary (CLAUDE.md §1/§10). Bind it back with [`PasswordHash::as_str`].
#[derive(Clone)]
pub(crate) struct PasswordHash(PasswordHashString);

impl PasswordHash {
    /// The PHC string, for binding to SQL.
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A hash is not the password, but there is no reason to print it.
        f.write_str("PasswordHash(<redacted>)")
    }
}

impl TryFrom<String> for PasswordHash {
    type Error = PasswordError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let parsed = PhcHash::new(&raw).map_err(|_| PasswordError::MalformedHash)?;
        Ok(Self(parsed.serialize()))
    }
}

/// Builds the argon2id hasher with the production/test parameters.
fn hasher() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .map_err(|_| PasswordError::Params)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hashes a password with a fresh random salt.
///
/// # Errors
///
/// Returns [`PasswordError`] if the argon2 parameters are invalid or hashing
/// fails.
pub(crate) fn hash_password(password: &PlaintextPassword) -> Result<PasswordHash, PasswordError> {
    let exposed = password.expose();
    assert!(
        exposed.len() >= PlaintextPassword::MIN_BYTES,
        "invariant: PlaintextPassword enforces a minimum length"
    );
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = hasher()?;
    let phc = argon2
        .hash_password(exposed.as_bytes(), &salt)
        .map_err(|_| PasswordError::Hash)?;
    let owned = phc.serialize();
    assert!(
        !owned.as_str().is_empty(),
        "invariant: PHC string is non-empty"
    );
    Ok(PasswordHash(owned))
}

/// Verifies a password against a stored hash. `false` on any mismatch or
/// malformed stored hash — never an error, so callers cannot distinguish causes.
pub(crate) fn verify_password(password: &PlaintextPassword, hash: &PasswordHash) -> bool {
    let parsed = hash.0.password_hash();
    // Argon2 reads the cost + salt from the PHC string, so a default instance
    // verifies correctly regardless of our configured parameters.
    Argon2::default()
        .verify_password(password.expose().as_bytes(), &parsed)
        .is_ok()
}

/// Verifies against the user's hash when present; otherwise runs a real
/// verification against a fixed dummy hash and returns `false`. The dummy path
/// equalizes timing so a caller cannot tell a missing user from a wrong password.
pub(crate) fn verify_or_dummy(password: &PlaintextPassword, hash: Option<&PasswordHash>) -> bool {
    hash.map_or_else(
        || {
            // Burn equivalent CPU against a fixed hash, then report failure.
            let _ignored = verify_password(password, &DUMMY_HASH);
            false
        },
        |real| verify_password(password, real),
    )
}

/// A real argon2id hash of a fixed string, computed once (CLAUDE.md §9). Used
/// only to burn equivalent CPU on the missing-user login path; nothing ever
/// verifies *true* against it. The `expect`s are named startup assertions
/// (CLAUDE.md §6): the inputs are constants, so they cannot fail in practice.
#[allow(
    clippy::expect_used,
    reason = "invariant: dummy hash is built from compile-time constants"
)]
static DUMMY_HASH: LazyLock<PasswordHash> = LazyLock::new(|| {
    let filler = PlaintextPassword::try_from("argon2-dummy-password".to_owned())
        .expect("invariant: dummy password is within length bounds");
    hash_password(&filler).expect("invariant: dummy hash computes with valid parameters")
});

#[cfg(test)]
mod tests {
    use super::{PasswordHash, hash_password, verify_or_dummy, verify_password};
    use crate::domain::PlaintextPassword;

    fn pw(text: &str) -> PlaintextPassword {
        PlaintextPassword::try_from(text.to_owned()).expect("valid test password")
    }

    #[test]
    fn hash_then_verify_succeeds() {
        let password = pw("correct horse battery staple");
        let hash = hash_password(&password).expect("hash");
        assert!(
            verify_password(&password, &hash),
            "the right password verifies"
        );
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let hash = hash_password(&pw("the real password")).expect("hash");
        assert!(
            !verify_password(&pw("a wrong password!!"), &hash),
            "a different password must not verify"
        );
    }

    #[test]
    fn hash_is_salted_and_unique_per_call() {
        let password = pw("repeated password value");
        let a = hash_password(&password).expect("hash a");
        let b = hash_password(&password).expect("hash b");
        assert_ne!(
            a.as_str(),
            b.as_str(),
            "a fresh salt must make each hash distinct"
        );
    }

    #[test]
    fn stored_hash_round_trips_through_try_from() {
        let password = pw("persisted password value");
        let hash = hash_password(&password).expect("hash");
        let reloaded = PasswordHash::try_from(hash.as_str().to_owned()).expect("parse PHC string");
        assert!(
            verify_password(&password, &reloaded),
            "a hash reloaded from its string still verifies"
        );
    }

    #[test]
    fn malformed_hash_string_is_rejected() {
        let err = PasswordHash::try_from("not-a-phc-string".to_owned());
        assert!(err.is_err(), "a non-PHC string must not parse");
    }

    #[test]
    fn verify_or_dummy_returns_false_when_no_user() {
        // Exercises the constant-time dummy path; must report failure.
        assert!(
            !verify_or_dummy(&pw("any password here"), None),
            "absent user always fails verification"
        );
    }

    #[test]
    fn verify_or_dummy_delegates_when_user_present() {
        let password = pw("present user password");
        let hash = hash_password(&password).expect("hash");
        assert!(verify_or_dummy(&password, Some(&hash)));
        assert!(!verify_or_dummy(&pw("wrong wrong wrong"), Some(&hash)));
    }
}
