//! Strongly-typed entity identifiers.

use thiserror::Error;
use uuid::Uuid;

/// Failure parsing a raw value into a domain identifier (CLAUDE.md §12).
///
/// The `&'static str` payload names the identifier kind so a caller's error
/// response and logs can say *which* id was malformed without interpolating
/// the (untrusted) raw value.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum DomainError {
    /// The raw string was not a syntactically valid UUID.
    #[error("malformed identifier: {0}")]
    Malformed(&'static str),

    /// The UUID was syntactically valid but nil (all-zero), which never names
    /// a real row and almost always signals an uninitialized value.
    #[error("nil identifier: {0}")]
    Nil(&'static str),
}

/// Identifier of a [`Tenant`](crate) — the root of all tenant-scoped data.
///
/// Constructed only via [`TryFrom`], so a value of this type is always a
/// non-nil UUID. The inner field is private (CLAUDE.md §1); read it with
/// [`TenantId::as_uuid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "Uuid")]
pub(crate) struct TenantId(Uuid);

impl TenantId {
    /// The underlying UUID, for binding to SQL or rendering at the boundary.
    pub(crate) const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl TryFrom<Uuid> for TenantId {
    type Error = DomainError;

    fn try_from(raw: Uuid) -> Result<Self, Self::Error> {
        if raw.is_nil() {
            return Err(DomainError::Nil("tenant_id"));
        }
        Ok(Self(raw))
    }
}

impl TryFrom<&str> for TenantId {
    type Error = DomainError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let parsed = Uuid::parse_str(raw).map_err(|_| DomainError::Malformed("tenant_id"))?;
        Self::try_from(parsed)
    }
}

/// Identifier of an [`Asset`](crate::assets) — a tenant-scoped stored file.
///
/// Same invariants as [`TenantId`]: constructed only via [`TryFrom`], always a
/// non-nil UUID, inner field private (CLAUDE.md §1). Read it with
/// [`AssetId::as_uuid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "Uuid")]
pub(crate) struct AssetId(Uuid);

impl AssetId {
    /// The underlying UUID, for binding to SQL or rendering at the boundary.
    pub(crate) const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl TryFrom<Uuid> for AssetId {
    type Error = DomainError;

    fn try_from(raw: Uuid) -> Result<Self, Self::Error> {
        if raw.is_nil() {
            return Err(DomainError::Nil("asset_id"));
        }
        Ok(Self(raw))
    }
}

impl TryFrom<&str> for AssetId {
    type Error = DomainError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let parsed = Uuid::parse_str(raw).map_err(|_| DomainError::Malformed("asset_id"))?;
        Self::try_from(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::{AssetId, DomainError, TenantId};
    use uuid::Uuid;

    #[test]
    fn tenant_id_round_trips_through_as_uuid() {
        let raw = Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
        let id = TenantId::try_from(raw).expect("invariant: non-nil uuid is a valid tenant id");
        assert_eq!(id.as_uuid(), raw);
    }

    #[test]
    fn tenant_id_parses_canonical_string() {
        let text = "67e55044-10b1-426f-9247-bb680e5fe0c8";
        let id = TenantId::try_from(text).expect("invariant: canonical uuid string parses");
        assert_eq!(id.as_uuid().to_string(), text);
    }

    #[test]
    fn tenant_id_rejects_malformed_string() {
        let err = TenantId::try_from("not-a-uuid").expect_err("malformed input must be rejected");
        assert!(matches!(err, DomainError::Malformed("tenant_id")));
    }

    #[test]
    fn tenant_id_rejects_nil_uuid() {
        let err = TenantId::try_from(Uuid::nil()).expect_err("nil uuid must be rejected");
        assert!(matches!(err, DomainError::Nil("tenant_id")));
    }

    #[test]
    fn tenant_id_deserializes_through_try_from() {
        let raw = Uuid::from_u128(42);
        let json = format!("\"{raw}\"");
        let id: TenantId = serde_json::from_str(&json).expect("valid uuid deserializes");
        assert_eq!(id.as_uuid(), raw);
    }

    #[test]
    fn tenant_id_deserialize_rejects_nil() {
        let json = format!("\"{}\"", Uuid::nil());
        let result: Result<TenantId, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "nil uuid must not deserialize into a TenantId"
        );
    }

    #[test]
    fn asset_id_round_trips_and_parses() {
        let raw = Uuid::new_v4();
        let id = AssetId::try_from(raw).expect("non-nil uuid is a valid asset id");
        assert_eq!(id.as_uuid(), raw);

        let from_str =
            AssetId::try_from(raw.to_string().as_str()).expect("canonical string parses");
        assert_eq!(from_str, id);
    }

    #[test]
    fn asset_id_rejects_nil_and_malformed() {
        assert_eq!(
            AssetId::try_from(Uuid::nil()).expect_err("nil rejected"),
            DomainError::Nil("asset_id")
        );
        assert_eq!(
            AssetId::try_from("not-a-uuid").expect_err("malformed rejected"),
            DomainError::Malformed("asset_id")
        );
    }
}
