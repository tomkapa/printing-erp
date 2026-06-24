//! Domain value types shared across the application.
//!
//! Every identifier and bounded value is a newtype (CLAUDE.md §1): a bare
//! `Uuid` or `String` carrying an invariant is a bug. Values cross into the
//! typed world exactly once, at the boundary, via `TryFrom` — there is no
//! public field and no infallible free constructor.
//!
//! These types currently live in a module; once the entity set grows they are
//! the natural seed of the `erp-domain` crate referenced by `SPEC.md`.

mod ids;
mod limits;
mod password;
mod settings;
mod user;

pub(crate) use ids::{DomainError, RefreshTokenId, TenantId, UserId};
pub(crate) use password::PlaintextPassword;
pub(crate) use settings::{
    Address, BusinessSettings, BusinessSettingsRow, EmailAddress, LogoRef, Phone, TaxCode,
};
pub(crate) use user::{Email, Role, TenantSlug};
