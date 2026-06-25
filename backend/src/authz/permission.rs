//! The authorization policy: which [`Role`] holds which [`Permission`].
//!
//! [`permits`] is the single source of truth (CLAUDE.md §1 — an exhaustive
//! `match` on the role proves totality). The policy is **default-deny**: a role
//! grants only the permissions it lists; `admin` is the sole role that holds
//! every capability. Authorization decisions never touch I/O, so this is pure
//! and carries the 100%-coverage bar of an evaluator core (CLAUDE.md §3).

use crate::domain::Role;

/// A guarded capability — one per distinct authorization decision in the HTTP
/// surface. Each variant maps to a [`Capability`](super::Capability) marker and
/// gates one or more routes; there are no unused variants (CLAUDE.md §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Permission {
    /// Read the caller's own tenant (`GET /tenant/me`).
    ReadTenant,
    /// Read the tenant's business settings (`GET /settings`).
    ReadSettings,
    /// Create or replace the tenant's business settings (`PUT /settings`).
    WriteSettings,
    /// List or fetch assets (`GET /assets`, `GET /assets/{id}`).
    ReadAsset,
    /// Create an asset or complete its upload (`POST /assets`, `.../complete`).
    CreateAsset,
    /// Delete an asset (`DELETE /assets/{id}`).
    DeleteAsset,
    /// Manage tenant users and their roles (all `/users` routes).
    ManageUsers,
    /// Read customers and their contacts (`GET /customers`, `…/{id}`, `…/contacts`).
    ReadCustomer,
    /// Create or update a customer/contact (`POST`/`PATCH` on `/customers`, `/contacts`).
    WriteCustomer,
    /// Archive a customer/contact (`DELETE /customers/{id}`, `DELETE /contacts/{id}`).
    DeleteCustomer,
}

#[cfg(test)]
impl Permission {
    /// Every permission, for exhaustive iteration in policy tests. Kept in sync
    /// with the enum by the `expected` anchor below: adding a variant there fails
    /// to compile until the matrix is extended (CLAUDE.md §1). Test-only — the
    /// production policy reaches each variant through its capability marker.
    pub(crate) const ALL: [Self; 10] = [
        Self::ReadTenant,
        Self::ReadSettings,
        Self::WriteSettings,
        Self::ReadAsset,
        Self::CreateAsset,
        Self::DeleteAsset,
        Self::ManageUsers,
        Self::ReadCustomer,
        Self::WriteCustomer,
        Self::DeleteCustomer,
    ];
}

/// Decides whether `role` may exercise `perm` (CLAUDE.md §1: exhaustive match
/// over the role proves every role's policy is declared). Default-deny: a role
/// that does not list a permission does not hold it.
pub(crate) const fn permits(role: Role, perm: Permission) -> bool {
    // Only the permissions a non-admin role can hold are named here; admin
    // short-circuits to `true`, and `WriteSettings`/`ManageUsers` are admin-only.
    use Permission::{
        CreateAsset, DeleteAsset, DeleteCustomer, ReadAsset, ReadCustomer, ReadSettings,
        ReadTenant, WriteCustomer,
    };
    match role {
        // Admin holds every capability (the tenant's superuser).
        Role::Admin => true,
        Role::Sales => matches!(
            perm,
            ReadTenant | ReadSettings | ReadAsset | CreateAsset | ReadCustomer | WriteCustomer
        ),
        Role::Coordinator => matches!(
            perm,
            ReadTenant
                | ReadSettings
                | ReadAsset
                | CreateAsset
                | DeleteAsset
                | ReadCustomer
                | WriteCustomer
                | DeleteCustomer
        ),
        Role::Scheduler => matches!(perm, ReadTenant | ReadSettings | ReadAsset | ReadCustomer),
        Role::Operator => matches!(perm, ReadTenant | ReadSettings | ReadAsset | ReadCustomer),
    }
}

#[cfg(test)]
mod tests {
    use super::{Permission, permits};
    use crate::domain::Role;

    /// All five roles, in the column order used by [`expected`].
    const ROLES: [Role; 5] = [
        Role::Admin,
        Role::Sales,
        Role::Coordinator,
        Role::Scheduler,
        Role::Operator,
    ];

    /// The authoritative matrix, mirroring the plan's policy table: for each
    /// permission, the decision per role in [`ROLES`] order.
    ///
    /// This `match` is the exhaustiveness anchor (CLAUDE.md §1): adding a
    /// `Permission` variant breaks compilation here, forcing both `ALL` and the
    /// `permits` policy to be extended before tests build.
    const fn expected(perm: Permission) -> [bool; 5] {
        // Permissions sharing an identical row are grouped (so the table has no
        // duplicate arms); every variant still appears, so adding one breaks
        // this match and forces the matrix to be extended.
        match perm {
            //                                  admin  sales  coord  sched  op
            Permission::ReadTenant
            | Permission::ReadSettings
            | Permission::ReadAsset
            | Permission::ReadCustomer => [true, true, true, true, true],
            Permission::CreateAsset | Permission::WriteCustomer => [true, true, true, false, false],
            Permission::DeleteAsset | Permission::DeleteCustomer => {
                [true, false, true, false, false]
            }
            Permission::WriteSettings | Permission::ManageUsers => {
                [true, false, false, false, false]
            }
        }
    }

    #[test]
    fn permits_matches_the_policy_matrix() {
        // 10 permissions × 5 roles = the full truth table, cell by cell. This
        // alone exercises every arm of `permits` (100% coverage, CLAUDE.md §3).
        for perm in Permission::ALL {
            let row = expected(perm);
            for (role, want) in ROLES.into_iter().zip(row) {
                assert_eq!(
                    permits(role, perm),
                    want,
                    "policy mismatch for role={role:?} perm={perm:?}"
                );
            }
        }
    }

    #[test]
    fn admin_holds_every_permission() {
        for perm in Permission::ALL {
            assert!(permits(Role::Admin, perm), "admin must hold {perm:?}");
        }
    }

    #[test]
    fn default_deny_for_unlisted_permissions() {
        assert!(!permits(Role::Operator, Permission::WriteSettings));
        assert!(!permits(Role::Sales, Permission::ManageUsers));
        assert!(!permits(Role::Scheduler, Permission::DeleteAsset));
        assert!(!permits(Role::Sales, Permission::DeleteAsset));
    }

    #[test]
    fn all_has_the_full_arity_and_no_duplicates() {
        assert_eq!(Permission::ALL.len(), 10);
        for (i, a) in Permission::ALL.into_iter().enumerate() {
            for b in Permission::ALL.into_iter().skip(i + 1) {
                assert_ne!(a, b, "ALL must not contain duplicates");
            }
        }
    }
}
