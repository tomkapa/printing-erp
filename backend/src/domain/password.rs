//! [`PlaintextPassword`]: a user-supplied password, bounded and zeroized.
//!
//! The plaintext exists only transiently — at login to verify, and at reset to
//! re-hash. It is wrapped in [`secrecy::SecretString`] so it is zeroized on drop
//! and never lands in `Debug` output or logs. The byte bounds are enforced once,
//! at the boundary, via [`TryFrom`] (CLAUDE.md §1).

use super::ids::DomainError;
use secrecy::{ExposeSecret as _, SecretString};

/// A validated, secret password awaiting hashing or verification.
#[derive(Debug, Clone)]
pub(crate) struct PlaintextPassword(SecretString);

impl PlaintextPassword {
    /// Minimum length, in bytes. A usability floor against trivially weak
    /// passwords without imposing a composition policy.
    pub(crate) const MIN_BYTES: usize = 12;

    /// Maximum length, in bytes. Argon2 hashes the entire input, so an unbounded
    /// password is a CPU-exhaustion vector (CLAUDE.md §5). 256 bytes is far above
    /// any genuine passphrase.
    pub(crate) const MAX_BYTES: usize = 256;

    /// The plaintext, for hashing/verification only. Never log or persist this.
    pub(crate) fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl TryFrom<String> for PlaintextPassword {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let len = raw.len();
        if len < Self::MIN_BYTES {
            return Err(DomainError::TooShort {
                field: "password",
                min: Self::MIN_BYTES,
            });
        }
        if len > Self::MAX_BYTES {
            return Err(DomainError::TooLong {
                field: "password",
                max: Self::MAX_BYTES,
            });
        }
        Ok(Self(SecretString::from(raw)))
    }
}

impl<'de> serde::Deserialize<'de> for PlaintextPassword {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainError, PlaintextPassword};

    #[test]
    fn accepts_password_within_bounds() {
        let pw = PlaintextPassword::try_from("correct horse battery".to_owned()).expect("valid");
        assert_eq!(pw.expose(), "correct horse battery");
    }

    #[test]
    fn rejects_too_short() {
        let err = PlaintextPassword::try_from("short".to_owned()).expect_err("must reject");
        assert!(matches!(
            err,
            DomainError::TooShort {
                field: "password",
                ..
            }
        ));
    }

    #[test]
    fn rejects_too_long() {
        let huge = "a".repeat(PlaintextPassword::MAX_BYTES + 1);
        let err = PlaintextPassword::try_from(huge).expect_err("must reject");
        assert!(matches!(
            err,
            DomainError::TooLong {
                field: "password",
                ..
            }
        ));
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let pw = PlaintextPassword::try_from("super secret value".to_owned()).expect("valid");
        let rendered = format!("{pw:?}");
        assert!(
            !rendered.contains("super secret"),
            "Debug must not expose the plaintext, got: {rendered}"
        );
    }
}
