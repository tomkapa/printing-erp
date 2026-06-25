//! Authorization (RBAC, issue #13): the role→permission policy and the
//! type-level capabilities that gate routes.
//!
//! Authentication (issue #12) establishes *who* a request is — the verified
//! authenticated principal and its [`Role`](crate::domain::Role). Authorization
//! decides *what* that role may do. The policy lives in one pure,
//! exhaustively-matched function, [`permits`]; the HTTP enforcement point is the
//! [`Require`](crate::http::Require) extractor, which reads a capability's
//! [`Permission`] and calls [`permits`] before a handler body runs.

mod capability;
mod permission;

pub(crate) use capability::{
    Capability, CreateAsset, DeleteAsset, ManageUsers, ReadAsset, ReadSettings, ReadTenant,
    WriteSettings,
};
pub(crate) use permission::{Permission, permits};
