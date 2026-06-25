//! Tenant- and user-facing value types: [`TenantSlug`], [`Email`], and [`Role`].
//!
//! Each parses at the boundary via the §1 smart-constructor pattern: a
//! `TenantSlug` is length-bounded and non-blank; an `Email` is trimmed,
//! shape-checked, and lowercase-normalized; a `Role` corresponds to a label of
//! the Postgres `user_role` enum.

use super::ids::DomainError;

/// A tenant's workspace handle, used to resolve the tenant at login / forgot.
///
/// Length-bounded and non-blank so the lookup key is validated once, at the
/// boundary, rather than re-checked in query logic. Stored verbatim (no
/// normalization) to match the exact `tenants.slug` value. Read it with
/// [`TenantSlug::as_str`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantSlug(String);

impl TenantSlug {
    /// Maximum accepted length, in bytes. Slugs are short handles; 64 bounds the
    /// lookup key before it reaches the database (CLAUDE.md §5).
    pub(crate) const MAX_BYTES: usize = 64;

    /// The slug, for binding to SQL.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TenantSlug {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        if raw.is_empty() {
            return Err(DomainError::Malformed("tenant_slug"));
        }
        if raw.len() > Self::MAX_BYTES {
            return Err(DomainError::TooLong {
                field: "tenant_slug",
                max: Self::MAX_BYTES,
            });
        }
        Ok(Self(raw))
    }
}

impl<'de> serde::Deserialize<'de> for TenantSlug {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// A normalized email address.
///
/// Stored lowercase with surrounding whitespace trimmed, so the `UNIQUE
/// (tenant_id, email)` constraint and login lookups are case-insensitive. The
/// inner field is private; read it with [`Email::as_str`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub(crate) struct Email(String);

impl Email {
    /// Maximum accepted length, in bytes. RFC 5321 caps a deliverable address
    /// at 254 octets; anything longer is rejected before it reaches the DB
    /// (CLAUDE.md §5).
    pub(crate) const MAX_BYTES: usize = 254;

    /// The normalized address, for binding to SQL or rendering.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Email {
    type Error = DomainError;

    /// Trims, length-caps, shape-checks (exactly one `@`, non-empty and
    /// whitespace-free local/domain parts), then lowercases.
    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let trimmed = raw.trim();
        if trimmed.len() > Self::MAX_BYTES {
            return Err(DomainError::TooLong {
                field: "email",
                max: Self::MAX_BYTES,
            });
        }

        let (local, domain) = trimmed
            .split_once('@')
            .ok_or(DomainError::Malformed("email"))?;
        // Reject a second `@`, empty parts, or any internal whitespace.
        let well_formed = !local.is_empty()
            && !domain.is_empty()
            && !domain.contains('@')
            && !trimmed.chars().any(char::is_whitespace);
        if !well_formed {
            return Err(DomainError::Malformed("email"));
        }

        Ok(Self(trimmed.to_ascii_lowercase()))
    }
}

impl<'de> serde::Deserialize<'de> for Email {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw.as_str()).map_err(serde::de::Error::custom)
    }
}

/// A user's human-facing display name, shown in the role center.
///
/// Trimmed of surrounding whitespace and required to be non-blank, with a byte
/// cap so an unbounded string never reaches the `users.display_name` column
/// (CLAUDE.md §5). The inner field is private; read it with
/// [`DisplayName::as_str`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub(crate) struct DisplayName(String);

impl DisplayName {
    /// Maximum accepted length, in bytes, measured after trimming. Display names
    /// are short labels; 128 bounds the value before it reaches the database.
    pub(crate) const MAX_BYTES: usize = 128;

    /// The trimmed name, for binding to SQL or rendering.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DisplayName {
    type Error = DomainError;

    /// Trims surrounding whitespace, rejects a blank result, then length-caps.
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DomainError::Empty("display_name"));
        }
        if trimmed.len() > Self::MAX_BYTES {
            return Err(DomainError::TooLong {
                field: "display_name",
                max: Self::MAX_BYTES,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }
}

impl<'de> serde::Deserialize<'de> for DisplayName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// A user's role within a tenant, mirroring the Postgres `user_role` enum.
///
/// `#[sqlx(rename_all = "lowercase")]` and `#[serde(rename_all = "lowercase")]`
/// keep the Rust variants in lockstep with the SQL labels (`'admin'`, …) and the
/// JWT `role` claim. What each role may *do* is the [`authz`](crate::authz)
/// policy (RBAC, #13); this type only names the roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, serde::Serialize, serde::Deserialize)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    Admin,
    Sales,
    Coordinator,
    Scheduler,
    Operator,
}

#[cfg(test)]
mod tests {
    use super::{DisplayName, DomainError, Email, Role, TenantSlug};

    #[test]
    fn tenant_slug_accepts_a_normal_handle() {
        let slug = TenantSlug::try_from("acme-print".to_owned()).expect("valid slug");
        assert_eq!(slug.as_str(), "acme-print");
    }

    #[test]
    fn tenant_slug_rejects_empty_and_oversized() {
        let empty = TenantSlug::try_from(String::new()).expect_err("empty rejected");
        assert!(matches!(empty, DomainError::Malformed("tenant_slug")));

        let huge = "a".repeat(TenantSlug::MAX_BYTES + 1);
        let err = TenantSlug::try_from(huge).expect_err("oversized rejected");
        assert!(matches!(
            err,
            DomainError::TooLong {
                field: "tenant_slug",
                ..
            }
        ));
    }

    #[test]
    fn email_normalizes_case_and_whitespace() {
        let email = Email::try_from("  Alice@Example.COM  ").expect("valid email");
        assert_eq!(email.as_str(), "alice@example.com");
    }

    #[test]
    fn email_rejects_missing_at() {
        let err = Email::try_from("no-at-sign").expect_err("must reject");
        assert!(matches!(err, DomainError::Malformed("email")));
    }

    #[test]
    fn email_rejects_double_at_and_empty_parts() {
        for bad in ["a@@b.com", "@example.com", "alice@", "a b@x.com"] {
            let err = Email::try_from(bad).expect_err("must reject malformed");
            assert!(
                matches!(err, DomainError::Malformed("email")),
                "input {bad}"
            );
        }
    }

    #[test]
    fn email_rejects_oversized() {
        let long = format!("{}@example.com", "a".repeat(Email::MAX_BYTES));
        let err = Email::try_from(long.as_str()).expect_err("must reject oversized");
        assert!(matches!(err, DomainError::TooLong { field: "email", .. }));
    }

    #[test]
    fn display_name_accepts_and_trims() {
        let name = DisplayName::try_from("  Alice Nguyễn  ".to_owned()).expect("valid name");
        assert_eq!(name.as_str(), "Alice Nguyễn");
    }

    #[test]
    fn display_name_rejects_blank() {
        for blank in ["", "   ", "\t\n"] {
            let err = DisplayName::try_from(blank.to_owned()).expect_err("blank rejected");
            assert!(
                matches!(err, DomainError::Empty("display_name")),
                "input {blank:?}"
            );
        }
    }

    #[test]
    fn display_name_rejects_oversized() {
        let long = "a".repeat(DisplayName::MAX_BYTES + 1);
        let err = DisplayName::try_from(long).expect_err("oversized rejected");
        assert!(matches!(
            err,
            DomainError::TooLong {
                field: "display_name",
                ..
            }
        ));
    }

    #[test]
    fn display_name_deserializes_through_try_from() {
        let name: DisplayName = serde_json::from_str("\"  Bob  \"").expect("valid");
        assert_eq!(name.as_str(), "Bob");
        let bad: Result<DisplayName, _> = serde_json::from_str("\"   \"");
        assert!(bad.is_err(), "blank display name must not deserialize");
    }

    #[test]
    fn display_name_serializes_transparently() {
        let name = DisplayName::try_from("Carol".to_owned()).expect("valid");
        let json = serde_json::to_string(&name).expect("serialize");
        assert_eq!(json, "\"Carol\"");
    }

    #[test]
    fn role_serde_round_trips_lowercase() {
        let json = serde_json::to_string(&Role::Coordinator).expect("serialize");
        assert_eq!(json, "\"coordinator\"");
        let role: Role = serde_json::from_str("\"admin\"").expect("deserialize");
        assert_eq!(role, Role::Admin);
    }

    #[test]
    fn email_deserializes_through_try_from() {
        let email: Email = serde_json::from_str("\" Bob@Test.IO \"").expect("valid");
        assert_eq!(email.as_str(), "bob@test.io");
        let bad: Result<Email, _> = serde_json::from_str("\"bad\"");
        assert!(bad.is_err(), "malformed email must not deserialize");
    }
}
