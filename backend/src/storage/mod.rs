//! S3-compatible object storage.
//!
//! [`ObjectStore`] is the portability seam the platform requires: one async
//! trait, implemented once for real S3/R2/MinIO by [`S3ObjectStore`] and once
//! in-memory for tests. Production holds it as `Arc<dyn ObjectStore>` so handlers
//! stay free of a storage generic.
//!
//! Bytes never transit the API: callers presign a URL and the client talks to
//! the store directly. Every networked call is bounded by
//! [`limits::STORAGE_OP_TIMEOUT`] at the call site (CLAUDE.md §5).

pub(crate) mod limits;

mod error;
mod s3;

pub(crate) use error::StorageError;
pub(crate) use s3::S3ObjectStore;

use crate::assets::{ContentType, FileName, StorageKey};
use serde::{Serialize, Serializer};
use std::time::Duration;

/// A time-limited, signed URL the client uses to upload or download directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PresignedUrl(String);

impl PresignedUrl {
    /// Wraps a freshly-signed URL. Asserts it is non-empty — an empty presigned
    /// URL is a signing bug, never a valid capability.
    pub(crate) fn new(url: String) -> Self {
        assert!(!url.is_empty(), "presigned URL invariant: non-empty");
        Self(url)
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for PresignedUrl {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// Metadata read back from the store for a stored object (via `head`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjectMeta {
    /// Object size in bytes, as the store reports it.
    pub(crate) size_bytes: i64,
}

/// The object-storage boundary. `dyn`-compatible via `async-trait` so
/// [`crate::http::AppState`] can hold `Arc<dyn ObjectStore>`.
#[async_trait::async_trait]
pub(crate) trait ObjectStore: std::fmt::Debug + Send + Sync + 'static {
    /// Signs a `PUT` the client uses to upload bytes for `key`. The client must
    /// send the same `content_type` header it was signed with.
    async fn presign_put(
        &self,
        key: &StorageKey,
        content_type: ContentType,
        ttl: Duration,
    ) -> Result<PresignedUrl, StorageError>;

    /// Signs a `GET` for `key`, asking the store to serve it as an attachment
    /// named `download_name`.
    async fn presign_get(
        &self,
        key: &StorageKey,
        ttl: Duration,
        download_name: &FileName,
    ) -> Result<PresignedUrl, StorageError>;

    /// Reads an object's metadata; [`StorageError::NotFound`] if it is absent.
    async fn head(&self, key: &StorageKey) -> Result<ObjectMeta, StorageError>;

    /// Deletes an object. Idempotent: deleting an absent key succeeds.
    async fn delete(&self, key: &StorageKey) -> Result<(), StorageError>;
}

/// In-memory [`ObjectStore`] for fast, deterministic tests — no Docker, no
/// network. `presign_*` return synthetic `memory://` URLs; `put` (test-only)
/// simulates the client upload that a presigned PUT would have performed.
#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub(crate) struct InMemoryObjectStore {
    objects: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, ObjectMeta>>>,
}

#[cfg(test)]
impl InMemoryObjectStore {
    /// Simulates a completed client upload for `key` (what the real client does
    /// against a presigned PUT). Tests call this between `presign_put` and the
    /// completion step. `content_type` mirrors the real call's signature.
    pub(crate) fn put(&self, key: &StorageKey, size_bytes: i64, _content_type: ContentType) {
        self.objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.as_str().to_owned(), ObjectMeta { size_bytes });
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl ObjectStore for InMemoryObjectStore {
    async fn presign_put(
        &self,
        key: &StorageKey,
        _content_type: ContentType,
        _ttl: Duration,
    ) -> Result<PresignedUrl, StorageError> {
        Ok(PresignedUrl::new(format!(
            "memory://{}?upload",
            key.as_str()
        )))
    }

    async fn presign_get(
        &self,
        key: &StorageKey,
        _ttl: Duration,
        _download_name: &FileName,
    ) -> Result<PresignedUrl, StorageError> {
        Ok(PresignedUrl::new(format!(
            "memory://{}?download",
            key.as_str()
        )))
    }

    async fn head(&self, key: &StorageKey) -> Result<ObjectMeta, StorageError> {
        let found = {
            let guard = self
                .objects
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.get(key.as_str()).copied()
        };
        found.ok_or(StorageError::NotFound)
    }

    async fn delete(&self, key: &StorageKey) -> Result<(), StorageError> {
        self.objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key.as_str());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryObjectStore, ObjectStore, StorageError};
    use crate::assets::{ContentType, FileName, StorageKey};
    use crate::domain::{AssetId, TenantId};
    use std::time::Duration;
    use uuid::Uuid;

    fn key() -> StorageKey {
        let tenant = TenantId::try_from(Uuid::new_v4()).expect("non-nil");
        let asset = AssetId::try_from(Uuid::new_v4()).expect("non-nil");
        StorageKey::new(tenant, asset)
    }

    #[tokio::test]
    async fn head_after_put_returns_meta_then_not_found_after_delete() {
        let store = InMemoryObjectStore::default();
        let k = key();

        assert!(
            matches!(store.head(&k).await, Err(StorageError::NotFound)),
            "absent object heads as NotFound"
        );

        store.put(&k, 4096, ContentType::Pdf);
        let meta = store.head(&k).await.expect("present after put");
        assert_eq!(meta.size_bytes, 4096);

        store.delete(&k).await.expect("delete succeeds");
        assert!(
            matches!(store.head(&k).await, Err(StorageError::NotFound)),
            "object is gone after delete"
        );
    }

    #[tokio::test]
    async fn presign_returns_nonempty_urls_and_delete_is_idempotent() {
        let store = InMemoryObjectStore::default();
        let k = key();
        let name = FileName::try_from("art.pdf").expect("valid name");

        let put = store
            .presign_put(&k, ContentType::Pdf, Duration::from_secs(60))
            .await
            .expect("presign put");
        let get = store
            .presign_get(&k, Duration::from_secs(60), &name)
            .await
            .expect("presign get");
        assert!(put.as_str().contains(k.as_str()));
        assert!(get.as_str().contains(k.as_str()));

        // Deleting a never-uploaded key still succeeds (idempotent contract).
        store.delete(&k).await.expect("idempotent delete");
    }
}
