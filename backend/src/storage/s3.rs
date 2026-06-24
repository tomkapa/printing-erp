//! Real S3-compatible object store backed by `aws-sdk-s3`.
//!
//! One client serves AWS S3, Cloudflare R2 and MinIO; the differences are the
//! `endpoint_url`, `region` and `force_path_style` knobs in [`StorageSettings`].
//! Credentials are static (from config), so `aws-config` is not needed.

use crate::assets::{ContentType, FileName, StorageKey};
use crate::config::StorageSettings;
use crate::storage::{ObjectMeta, ObjectStore, PresignedUrl, StorageError};
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::presigning::PresigningConfig;
use secrecy::ExposeSecret as _;
use std::time::Duration;

/// Object store that talks to an S3-compatible service over SigV4.
#[derive(Debug, Clone)]
pub(crate) struct S3ObjectStore {
    client: Client,
    bucket: String,
}

impl S3ObjectStore {
    /// Builds the client once at startup from static credentials (CLAUDE.md §9).
    ///
    /// # Errors
    ///
    /// [`StorageError::Config`] if the bucket or region is empty.
    pub(crate) fn new(settings: &StorageSettings) -> Result<Self, StorageError> {
        let bucket = settings.bucket.trim();
        if bucket.is_empty() {
            return Err(StorageError::Config("bucket"));
        }
        let region = settings.region.trim();
        if region.is_empty() {
            return Err(StorageError::Config("region"));
        }

        let credentials = Credentials::new(
            settings.access_key_id.expose_secret(),
            settings.secret_access_key.expose_secret(),
            None,
            None,
            "patom-static",
        );
        let mut builder = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.to_owned()))
            .credentials_provider(credentials)
            .force_path_style(settings.force_path_style);
        if let Some(endpoint) = &settings.endpoint_url {
            builder = builder.endpoint_url(endpoint.as_str());
        }

        assert!(!bucket.is_empty(), "bucket invariant: validated non-empty");
        let client = Client::from_conf(builder.build());
        Ok(Self {
            client,
            bucket: bucket.to_owned(),
        })
    }

    /// Builds a presigning config, asserting a positive validity window.
    fn presigning(ttl: Duration) -> Result<PresigningConfig, StorageError> {
        assert!(!ttl.is_zero(), "presign ttl invariant: strictly positive");
        PresigningConfig::expires_in(ttl).map_err(|e| StorageError::Backend(Box::new(e)))
    }
}

/// Builds an RFC 6266 `Content-Disposition` value carrying `name`.
///
/// A bare `filename=` must be ASCII, so we emit an ASCII-sanitized fallback for
/// legacy agents *and* an RFC 5987 `filename*=UTF-8''…` extension that preserves
/// the exact name — print shops routinely upload Vietnamese/accented filenames,
/// and a raw multi-byte `filename` would be mangled by the client.
fn content_disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .filter(|c| c.is_ascii() && *c != '"' && *c != '\\')
        .collect();
    let encoded = rfc5987_encode(name);
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

/// Percent-encodes `value` per RFC 5987 `attr-char`: bytes outside the
/// unreserved set become `%XX`. Suitable for a `filename*` parameter value.
fn rfc5987_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(hex_upper(byte >> 4)));
            out.push(char::from(hex_upper(byte & 0x0f)));
        }
    }
    out
}

/// Maps a nibble (`0..=15`) to its uppercase ASCII hex digit.
const fn hex_upper(nibble: u8) -> u8 {
    assert!(nibble < 16, "hex_upper invariant: input is a single nibble");
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'A' + (nibble - 10)
    }
}

#[async_trait::async_trait]
impl ObjectStore for S3ObjectStore {
    async fn presign_put(
        &self,
        key: &StorageKey,
        content_type: ContentType,
        ttl: Duration,
    ) -> Result<PresignedUrl, StorageError> {
        assert!(!key.as_str().is_empty(), "storage key invariant: non-empty");
        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .content_type(content_type.as_str())
            .presigned(Self::presigning(ttl)?)
            .await
            .map_err(|e| StorageError::Backend(Box::new(e)))?;
        Ok(PresignedUrl::new(request.uri().to_owned()))
    }

    async fn presign_get(
        &self,
        key: &StorageKey,
        ttl: Duration,
        download_name: &FileName,
    ) -> Result<PresignedUrl, StorageError> {
        assert!(!key.as_str().is_empty(), "storage key invariant: non-empty");
        let disposition = content_disposition(download_name.as_str());
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .response_content_disposition(disposition)
            .presigned(Self::presigning(ttl)?)
            .await
            .map_err(|e| StorageError::Backend(Box::new(e)))?;
        Ok(PresignedUrl::new(request.uri().to_owned()))
    }

    async fn head(&self, key: &StorageKey) -> Result<ObjectMeta, StorageError> {
        let output = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .send()
            .await
            .map_err(|e| {
                let not_found = e
                    .as_service_error()
                    .is_some_and(|se: &HeadObjectError| matches!(se, HeadObjectError::NotFound(_)));
                if not_found {
                    StorageError::NotFound
                } else {
                    StorageError::Backend(Box::new(e))
                }
            })?;
        let size_bytes = output.content_length().unwrap_or_default();
        assert!(size_bytes >= 0, "object size invariant: non-negative");
        Ok(ObjectMeta { size_bytes })
    }

    async fn delete(&self, key: &StorageKey) -> Result<(), StorageError> {
        assert!(!key.as_str().is_empty(), "storage key invariant: non-empty");
        // S3 DELETE is idempotent — removing an absent key reports success.
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .send()
            .await
            .map_err(|e| StorageError::Backend(Box::new(e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod encode_tests {
    use super::content_disposition;

    #[test]
    fn ascii_name_has_quoted_filename_and_matching_extended() {
        let value = content_disposition("artwork.pdf");
        assert_eq!(
            value,
            "attachment; filename=\"artwork.pdf\"; filename*=UTF-8''artwork.pdf"
        );
    }

    #[test]
    fn non_ascii_name_is_percent_encoded_in_extended_and_stripped_in_fallback() {
        // Vietnamese filename: the ASCII fallback drops the accented bytes; the
        // RFC 5987 `filename*` carries the exact UTF-8, percent-encoded.
        let value = content_disposition("tờ-rơi.pdf");
        assert!(
            value.contains("filename*=UTF-8''t%E1%BB%9D-r%C6%A1i.pdf"),
            "extended form carries the percent-encoded UTF-8 name: {value}"
        );
        assert!(
            value.contains("filename=\"t-ri.pdf\""),
            "ascii fallback keeps only ascii bytes: {value}"
        );
    }

    #[test]
    fn quotes_and_backslashes_cannot_break_the_header() {
        let value = content_disposition("a\"b\\c.png");
        // Neither a raw quote nor a backslash survives in the ASCII fallback.
        assert!(value.contains("filename=\"abc.png\""), "{value}");
    }
}

#[cfg(test)]
mod live_tests {
    //! Live round-trip against a real S3-compatible server (the docker-compose
    //! MinIO). Reads `APP__STORAGE__*` from the environment and skips when
    //! unset — exactly as `#[sqlx::test]` relies on the compose Postgres via
    //! `DATABASE_URL`. Exercises real SigV4 presigning, PUT, HEAD, GET, DELETE.

    use super::S3ObjectStore;
    use crate::assets::{ContentType, FileName, StorageKey};
    use crate::config::StorageSettings;
    use crate::domain::{AssetId, TenantId};
    use crate::storage::{ObjectStore as _, StorageError};
    use secrecy::SecretString;
    use std::time::Duration;
    use uuid::Uuid;

    /// Builds storage settings from the environment, or `None` to skip the test.
    fn settings_from_env() -> Option<StorageSettings> {
        let endpoint = std::env::var("APP__STORAGE__ENDPOINT_URL").ok()?;
        Some(StorageSettings {
            endpoint_url: Some(endpoint),
            region: std::env::var("APP__STORAGE__REGION")
                .unwrap_or_else(|_| "us-east-1".to_owned()),
            bucket: std::env::var("APP__STORAGE__BUCKET")
                .unwrap_or_else(|_| "erp-assets".to_owned()),
            access_key_id: SecretString::from(
                std::env::var("APP__STORAGE__ACCESS_KEY_ID").unwrap_or_else(|_| "erp".to_owned()),
            ),
            secret_access_key: SecretString::from(
                std::env::var("APP__STORAGE__SECRET_ACCESS_KEY")
                    .unwrap_or_else(|_| "erp_secret_dev".to_owned()),
            ),
            force_path_style: true,
        })
    }

    #[tokio::test]
    async fn presign_put_head_get_delete_round_trip() {
        let Some(settings) = settings_from_env() else {
            // No object-storage env configured — skip (CLAUDE.md §2: instrument
            // via tracing, never println/eprintln, which clippy denies).
            tracing::warn!(
                event = "storage.live_test.skipped",
                "APP__STORAGE__ENDPOINT_URL unset"
            );
            return;
        };
        let store = S3ObjectStore::new(&settings).expect("build store");

        let tenant = TenantId::try_from(Uuid::new_v4()).expect("non-nil");
        let asset = AssetId::try_from(Uuid::new_v4()).expect("non-nil");
        let key = StorageKey::new(tenant, asset);
        let name = FileName::try_from("artwork.pdf").expect("valid name");
        let body = b"hello-print-artwork".to_vec();
        let body_len = i64::try_from(body.len()).expect("small body");
        let ttl = Duration::from_secs(120);
        let client = reqwest::Client::new();

        // 1. Presign a PUT and upload the bytes directly, as a browser would.
        //    The Content-Type header must match what was signed, or SigV4 fails.
        let put_url = store
            .presign_put(&key, ContentType::Pdf, ttl)
            .await
            .expect("presign put");
        let put = client
            .put(put_url.as_str())
            .header("content-type", ContentType::Pdf.as_str())
            .body(body.clone())
            .send()
            .await
            .expect("PUT to presigned url");
        assert!(put.status().is_success(), "upload status: {}", put.status());

        // 2. HEAD verifies the object is present with the expected size.
        let meta = store.head(&key).await.expect("head");
        assert_eq!(meta.size_bytes, body_len);

        // 3. Presign a GET and download — bytes round-trip exactly.
        let get_url = store
            .presign_get(&key, ttl, &name)
            .await
            .expect("presign get");
        let downloaded = client
            .get(get_url.as_str())
            .send()
            .await
            .expect("GET from presigned url")
            .bytes()
            .await
            .expect("read body");
        assert_eq!(downloaded.as_ref(), body.as_slice());

        // 4. Delete, then HEAD reports NotFound.
        store.delete(&key).await.expect("delete");
        assert!(
            matches!(store.head(&key).await, Err(StorageError::NotFound)),
            "object is gone after delete"
        );
    }
}
