//! Type-level capabilities: a zero-sized marker per [`Permission`], carried as
//! the generic parameter of the [`Require`](crate::http::Require) extractor.
//!
//! A route writes its requirement in the handler signature — `Require<ManageUsers>`
//! — so the gate is visible and impossible to forget (CLAUDE.md §4, "push ifs
//! up"). The [`Capability`] trait maps a marker to its [`Permission`]; the
//! authorization decision itself stays in [`permits`](super::permits).
//!
//! The markers are written out by hand rather than generated: seven near-identical
//! three-line impls are clearer than a macro (CLAUDE.md §4 — explicit repetition
//! beats a premature abstraction).

use super::Permission;

/// A compile-time capability: the [`Permission`] a guarded route requires.
///
/// Implemented only by the zero-sized markers in this module. The bound is
/// deliberately minimal — the marker carries no state, only the associated
/// [`Permission`] constant the extractor reads.
pub(crate) trait Capability {
    /// The permission a request must hold to pass the guard.
    const PERMISSION: Permission;
}

/// Guards `GET /tenant/me`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadTenant;
impl Capability for ReadTenant {
    const PERMISSION: Permission = Permission::ReadTenant;
}

/// Guards `GET /settings`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadSettings;
impl Capability for ReadSettings {
    const PERMISSION: Permission = Permission::ReadSettings;
}

/// Guards `PUT /settings`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteSettings;
impl Capability for WriteSettings {
    const PERMISSION: Permission = Permission::WriteSettings;
}

/// Guards `GET /assets` and `GET /assets/{id}`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadAsset;
impl Capability for ReadAsset {
    const PERMISSION: Permission = Permission::ReadAsset;
}

/// Guards `POST /assets` and `POST /assets/{id}/complete`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CreateAsset;
impl Capability for CreateAsset {
    const PERMISSION: Permission = Permission::CreateAsset;
}

/// Guards `DELETE /assets/{id}`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeleteAsset;
impl Capability for DeleteAsset {
    const PERMISSION: Permission = Permission::DeleteAsset;
}

/// Guards every `/users` route.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ManageUsers;
impl Capability for ManageUsers {
    const PERMISSION: Permission = Permission::ManageUsers;
}

#[cfg(test)]
mod tests {
    use super::{
        Capability, CreateAsset, DeleteAsset, ManageUsers, ReadAsset, ReadSettings, ReadTenant,
        WriteSettings,
    };
    use crate::authz::Permission;

    #[test]
    fn markers_map_to_their_permission() {
        assert_eq!(ReadTenant::PERMISSION, Permission::ReadTenant);
        assert_eq!(ReadSettings::PERMISSION, Permission::ReadSettings);
        assert_eq!(WriteSettings::PERMISSION, Permission::WriteSettings);
        assert_eq!(ReadAsset::PERMISSION, Permission::ReadAsset);
        assert_eq!(CreateAsset::PERMISSION, Permission::CreateAsset);
        assert_eq!(DeleteAsset::PERMISSION, Permission::DeleteAsset);
        assert_eq!(ManageUsers::PERMISSION, Permission::ManageUsers);
    }
}
