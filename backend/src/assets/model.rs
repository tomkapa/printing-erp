//! Asset value types and the row aggregate.
//!
//! Every field that carries an invariant is a newtype constructed through
//! `TryFrom` at the boundary (CLAUDE.md §1): a bare `String`/`i64` for a content
//! type, filename or byte count is a bug. Deserialization funnels through the
//! same constructors via `#[serde(try_from = ...)]`; serialization is explicit.

use crate::assets::limits;
use crate::domain::{AssetId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use thiserror::Error;
use uuid::Uuid;

/// Failure parsing a raw value into an asset value type (CLAUDE.md §12).
///
/// Payloads name the field, never echo the (untrusted) raw value.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// A required text field was empty (after trimming).
    #[error("{0} must not be empty")]
    Empty(&'static str),
    /// A text field exceeded its byte cap.
    #[error("{field} too long: max {max} bytes, got {got}")]
    TooLong {
        field: &'static str,
        max: usize,
        got: usize,
    },
    /// A field contained characters that are not allowed (path separators,
    /// control bytes, non-hex digits, …).
    #[error("{0} contains illegal characters")]
    Illegal(&'static str),
    /// A numeric field fell outside its permitted range.
    #[error("{0} is out of range")]
    OutOfRange(&'static str),
    /// The declared content type is not in the upload allowlist.
    #[error("unsupported content type")]
    UnsupportedContentType,
}

/// Allowlisted upload content types — the enum *is* the allowlist (CLAUDE.md §1
/// prefer sum types; §5 cap what crosses the trust boundary). Anything not named
/// here is rejected before a presigned URL is issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentType {
    Pdf,
    Png,
    Jpeg,
    Tiff,
    Svg,
    /// PostScript family — covers `.ps`/`.eps` and many packaged AI files.
    PostScript,
    Zip,
}

impl ContentType {
    /// Canonical MIME string. This exact value is bound into the presigned PUT,
    /// so the uploading client must send the same `Content-Type` header.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "application/pdf",
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Tiff => "image/tiff",
            Self::Svg => "image/svg+xml",
            Self::PostScript => "application/postscript",
            Self::Zip => "application/zip",
        }
    }
}

impl TryFrom<&str> for ContentType {
    type Error = ParseError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        // Some clients append parameters (`; charset=binary`); match the essence.
        let mime = raw.split(';').next().unwrap_or(raw).trim();
        let parsed = match mime {
            "application/pdf" => Self::Pdf,
            "image/png" => Self::Png,
            "image/jpeg" => Self::Jpeg,
            "image/tiff" => Self::Tiff,
            "image/svg+xml" => Self::Svg,
            "application/postscript" => Self::PostScript,
            "application/zip" => Self::Zip,
            _ => return Err(ParseError::UnsupportedContentType),
        };
        Ok(parsed)
    }
}

impl TryFrom<String> for ContentType {
    type Error = ParseError;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::try_from(raw.as_str())
    }
}

impl Serialize for ContentType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ContentType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// A display filename, sanitized and length-capped. Display-only metadata: the
/// storage key is opaque and never derived from this, so it carries no path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileName(String);

impl FileName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for FileName {
    type Error = ParseError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ParseError::Empty("filename"));
        }
        let got = trimmed.len();
        if got > limits::MAX_FILENAME_BYTES {
            return Err(ParseError::TooLong {
                field: "filename",
                max: limits::MAX_FILENAME_BYTES,
                got,
            });
        }
        // Reject path separators and control bytes: a name is never a path, so a
        // `/`, `\` or control byte signals traversal or a forged value.
        let illegal = trimmed
            .bytes()
            .any(|b| b == b'/' || b == b'\\' || b.is_ascii_control());
        if illegal {
            return Err(ParseError::Illegal("filename"));
        }
        Ok(Self(trimmed.to_owned()))
    }
}

impl TryFrom<String> for FileName {
    type Error = ParseError;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::try_from(raw.as_str())
    }
}

impl Serialize for FileName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for FileName {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// A positive object size in bytes, bounded by [`limits::MAX_ASSET_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ByteSize(i64);

impl ByteSize {
    pub(crate) const fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for ByteSize {
    type Error = ParseError;

    fn try_from(n: i64) -> Result<Self, Self::Error> {
        if n <= 0 {
            return Err(ParseError::OutOfRange("size_bytes"));
        }
        if n > limits::MAX_ASSET_BYTES {
            return Err(ParseError::OutOfRange("size_bytes"));
        }
        Ok(Self(n))
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = i64::deserialize(d)?;
        Self::try_from(n).map_err(serde::de::Error::custom)
    }
}

/// A lowercase hex-encoded SHA-256 digest (exactly 64 hex chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sha256Hex(String);

impl Sha256Hex {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Sha256Hex {
    type Error = ParseError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        if raw.is_empty() {
            return Err(ParseError::Empty("checksum_sha256"));
        }
        let is_canonical = raw.len() == limits::SHA256_HEX_LEN
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !is_canonical {
            return Err(ParseError::Illegal("checksum_sha256"));
        }
        Ok(Self(raw.to_owned()))
    }
}

impl TryFrom<String> for Sha256Hex {
    type Error = ParseError;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::try_from(raw.as_str())
    }
}

impl Serialize for Sha256Hex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// The opaque object-storage key for an asset: `{tenant_id}/{asset_id}`.
///
/// App-generated and tenant-prefixed, so it namespaces objects at the bucket
/// layer and never embeds a user-supplied filename. Not exposed at the API
/// boundary — clients see presigned URLs, never the raw key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StorageKey(String);

impl StorageKey {
    /// Derives the key from the owning tenant and asset ids.
    pub(crate) fn new(tenant: TenantId, asset: AssetId) -> Self {
        let key = format!("{}/{}", tenant.as_uuid(), asset.as_uuid());
        assert!(
            key.contains('/'),
            "storage key invariant: tenant/asset shape"
        );
        assert!(
            key.len() <= limits::MAX_STORAGE_KEY_BYTES,
            "storage key invariant: within S3 key cap"
        );
        Self(key)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for StorageKey {
    type Error = ParseError;

    /// Parses a key read back from the database (app-generated, so lenient:
    /// non-empty, capped, no control bytes).
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        if raw.is_empty() {
            return Err(ParseError::Empty("storage_key"));
        }
        let got = raw.len();
        if got > limits::MAX_STORAGE_KEY_BYTES {
            return Err(ParseError::TooLong {
                field: "storage_key",
                max: limits::MAX_STORAGE_KEY_BYTES,
                got,
            });
        }
        if raw.bytes().any(|b| b.is_ascii_control()) {
            return Err(ParseError::Illegal("storage_key"));
        }
        Ok(Self(raw))
    }
}

/// Lifecycle of a stored asset, mirroring the `asset_status` Postgres enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssetStatus {
    /// Row created, presigned URL issued, bytes not yet confirmed.
    Pending,
    /// Bytes confirmed present in object storage (HEAD-verified).
    Ready,
    /// Soft-deleted; bytes removed (best-effort) and hidden from listings.
    Deleted,
}

impl AssetStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Deleted => "deleted",
        }
    }
}

impl TryFrom<&str> for AssetStatus {
    type Error = ParseError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let parsed = match raw {
            "pending" => Self::Pending,
            "ready" => Self::Ready,
            "deleted" => Self::Deleted,
            _ => return Err(ParseError::Illegal("status")),
        };
        Ok(parsed)
    }
}

impl Serialize for AssetStatus {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A stored asset's metadata row. The bytes live in object storage; this is the
/// system-of-record for everything *about* the object.
#[derive(Debug, Clone)]
pub(crate) struct Asset {
    pub(crate) id: AssetId,
    pub(crate) tenant_id: TenantId,
    pub(crate) storage_key: StorageKey,
    pub(crate) original_name: FileName,
    pub(crate) content_type: ContentType,
    pub(crate) size_bytes: ByteSize,
    pub(crate) checksum_sha256: Option<Sha256Hex>,
    pub(crate) status: AssetStatus,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

impl TryFrom<&PgRow> for Asset {
    type Error = sqlx::Error;

    /// Boundary parse of a `SELECT … , status::text AS status …` row. Every
    /// column funnels through its newtype constructor; a malformed column
    /// becomes a `Decode` error (the row did not have the expected shape).
    fn try_from(row: &PgRow) -> Result<Self, Self::Error> {
        let decode = |e: ParseError| sqlx::Error::Decode(Box::new(e));
        let id = AssetId::try_from(row.try_get::<Uuid, _>("id")?)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let tenant_id = TenantId::try_from(row.try_get::<Uuid, _>("tenant_id")?)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let storage_key =
            StorageKey::try_from(row.try_get::<String, _>("storage_key")?).map_err(decode)?;
        let original_name =
            FileName::try_from(row.try_get::<String, _>("original_name")?).map_err(decode)?;
        let content_type =
            ContentType::try_from(row.try_get::<String, _>("content_type")?).map_err(decode)?;
        let size_bytes =
            ByteSize::try_from(row.try_get::<i64, _>("size_bytes")?).map_err(decode)?;
        let checksum_sha256 = row
            .try_get::<Option<String>, _>("checksum_sha256")?
            .map(Sha256Hex::try_from)
            .transpose()
            .map_err(decode)?;
        let status =
            AssetStatus::try_from(row.try_get::<String, _>("status")?.as_str()).map_err(decode)?;

        assert!(
            size_bytes.get() > 0,
            "ByteSize invariant: strictly positive"
        );
        assert!(
            !storage_key.as_str().is_empty(),
            "StorageKey invariant: non-empty"
        );
        Ok(Self {
            id,
            tenant_id,
            storage_key,
            original_name,
            content_type,
            size_bytes,
            checksum_sha256,
            status,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{AssetStatus, ByteSize, ContentType, FileName, ParseError, Sha256Hex, StorageKey};
    use crate::assets::limits;
    use crate::domain::{AssetId, TenantId};
    use uuid::Uuid;

    #[test]
    fn content_type_allows_known_and_strips_params() {
        assert_eq!(
            ContentType::try_from("application/pdf").unwrap(),
            ContentType::Pdf
        );
        assert_eq!(
            ContentType::try_from("image/png; charset=binary").unwrap(),
            ContentType::Png
        );
        assert_eq!(ContentType::Tiff.as_str(), "image/tiff");
    }

    #[test]
    fn content_type_rejects_unlisted() {
        assert_eq!(
            ContentType::try_from("text/plain").unwrap_err(),
            ParseError::UnsupportedContentType
        );
        assert_eq!(
            ContentType::try_from("application/octet-stream").unwrap_err(),
            ParseError::UnsupportedContentType
        );
    }

    #[test]
    fn filename_accepts_plain_name() {
        let name = FileName::try_from("  business-card.pdf  ").unwrap();
        assert_eq!(name.as_str(), "business-card.pdf", "trimmed, preserved");
    }

    #[test]
    fn filename_rejects_empty_separators_and_oversize() {
        assert_eq!(
            FileName::try_from("   ").unwrap_err(),
            ParseError::Empty("filename")
        );
        assert_eq!(
            FileName::try_from("a/b.pdf").unwrap_err(),
            ParseError::Illegal("filename")
        );
        assert_eq!(
            FileName::try_from("a\\b.pdf").unwrap_err(),
            ParseError::Illegal("filename")
        );
        let long = "x".repeat(limits::MAX_FILENAME_BYTES + 1);
        assert!(matches!(
            FileName::try_from(long.as_str()).unwrap_err(),
            ParseError::TooLong { .. }
        ));
    }

    #[test]
    fn byte_size_enforces_inclusive_bounds() {
        assert_eq!(ByteSize::try_from(1).unwrap().get(), 1);
        assert_eq!(
            ByteSize::try_from(limits::MAX_ASSET_BYTES).unwrap().get(),
            limits::MAX_ASSET_BYTES
        );
        assert_eq!(
            ByteSize::try_from(0).unwrap_err(),
            ParseError::OutOfRange("size_bytes")
        );
        assert_eq!(
            ByteSize::try_from(-1).unwrap_err(),
            ParseError::OutOfRange("size_bytes")
        );
        assert_eq!(
            ByteSize::try_from(limits::MAX_ASSET_BYTES + 1).unwrap_err(),
            ParseError::OutOfRange("size_bytes")
        );
    }

    #[test]
    fn sha256_requires_exactly_64_lowercase_hex() {
        let good = "a".repeat(64);
        assert_eq!(Sha256Hex::try_from(good.as_str()).unwrap().as_str(), good);
        assert!(Sha256Hex::try_from("a".repeat(63).as_str()).is_err());
        assert!(
            Sha256Hex::try_from("A".repeat(64).as_str()).is_err(),
            "uppercase rejected"
        );
        assert!(
            Sha256Hex::try_from("g".repeat(64).as_str()).is_err(),
            "non-hex rejected"
        );
    }

    #[test]
    fn storage_key_is_tenant_then_asset() {
        let tenant = TenantId::try_from(Uuid::new_v4()).unwrap();
        let asset = AssetId::try_from(Uuid::new_v4()).unwrap();
        let key = StorageKey::new(tenant, asset);
        assert_eq!(
            key.as_str(),
            format!("{}/{}", tenant.as_uuid(), asset.as_uuid())
        );
        // Round-trips through the lenient DB reader.
        let reparsed = StorageKey::try_from(key.as_str().to_owned()).unwrap();
        assert_eq!(reparsed, key);
    }

    #[test]
    fn asset_status_round_trips() {
        for status in [
            AssetStatus::Pending,
            AssetStatus::Ready,
            AssetStatus::Deleted,
        ] {
            assert_eq!(AssetStatus::try_from(status.as_str()).unwrap(), status);
        }
        assert_eq!(
            AssetStatus::try_from("bogus").unwrap_err(),
            ParseError::Illegal("status")
        );
    }

    #[test]
    fn content_type_serializes_as_mime() {
        let json = serde_json::to_string(&ContentType::Svg).unwrap();
        assert_eq!(json, "\"image/svg+xml\"");
        let parsed: ContentType = serde_json::from_str("\"application/pdf\"").unwrap();
        assert_eq!(parsed, ContentType::Pdf);
    }
}
