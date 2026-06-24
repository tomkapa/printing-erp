//! Tenant-scoped file/asset management.
//!
//! An asset is a file (print artwork, proofs, packaged jobs) whose bytes live in
//! S3-compatible object storage ([`crate::storage`]) and whose metadata lives in
//! the `assets` table under Row-Level Security. Clients never stream bytes
//! through the API: they upload and download directly via presigned URLs.
//!
//! - [`model`] — value newtypes ([`ContentType`], [`FileName`], [`ByteSize`], …)
//!   and the [`Asset`] row aggregate, all parsed at the boundary (CLAUDE.md §1).
//! - [`repo`] — tenant-scoped CRUD, run inside a `db::begin_tenant_tx`.
//! - [`error`] — [`AssetError`] and its single HTTP mapping.

mod error;
pub(crate) mod limits;
mod model;
pub(crate) mod repo;

pub(crate) use error::AssetError;
pub(crate) use model::{
    Asset, AssetStatus, ByteSize, ContentType, FileName, Sha256Hex, StorageKey,
};
