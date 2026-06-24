//! Tenant resolution by slug, shared by login and forgot-password.
//!
//! The `tenants` table is intentionally not under Row-Level Security (SPEC.md
//! §Tenancy): the slug → tenant mapping must be readable *before* any tenant
//! context exists. The slug is already a validated [`TenantSlug`]; a miss returns
//! `None` so callers fail uniformly (no tenant enumeration).

use super::error::{AuthError, internal};
use crate::domain::{TenantId, TenantSlug};
use uuid::Uuid;

/// Resolves a tenant by `slug` on the bare pool (outside any tenant transaction).
/// The caller bounds this await as part of its flow-level timeout (CLAUDE.md §5).
///
/// # Errors
///
/// Returns [`AuthError::Internal`] on a database fault or a corrupt stored id.
pub(crate) async fn resolve_by_slug(
    pool: &sqlx::PgPool,
    slug: &TenantSlug,
) -> Result<Option<TenantId>, AuthError> {
    let row: Option<Uuid> = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
        .bind(slug.as_str())
        .fetch_optional(pool)
        .await
        .map_err(internal)?;
    match row {
        Some(id) => Ok(Some(TenantId::try_from(id).map_err(internal)?)),
        None => Ok(None),
    }
}
