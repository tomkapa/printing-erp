//! Tenant-scoped customer & contact management (CRM, issue #17).
//!
//! A `customer` is one of a tenant's clients — the head of the order-to-delivery
//! pipeline (`SPEC.md` §Pipeline) that quotes, orders and invoices attach to. A
//! `contact` is a person at that customer. Both are tenant-scoped under
//! Row-Level Security and soft-archived rather than hard-deleted, so historical
//! pipeline references never dangle.
//!
//! - [`model`] — value newtypes ([`CustomerName`], [`CustomerCode`],
//!   [`RecordStatus`], …) and the [`Customer`] / [`Contact`] row aggregates,
//!   parsed at the boundary (CLAUDE.md §1). Contact-info fields ([`TaxCode`],
//!   [`Address`], [`Phone`], [`EmailAddress`]) are reused from [`crate::domain`].
//! - [`repo`] — tenant-scoped CRUD, run inside a `db::begin_tenant_tx`, including
//!   the atomic per-tenant `CS###` code allocator.
//! - [`error`] — [`CrmError`] and its single HTTP mapping.
//!
//! [`TaxCode`]: crate::domain::TaxCode
//! [`Address`]: crate::domain::Address
//! [`Phone`]: crate::domain::Phone
//! [`EmailAddress`]: crate::domain::EmailAddress

mod error;
pub(crate) mod limits;
mod model;
pub(crate) mod repo;

pub(crate) use error::CrmError;
pub(crate) use model::{
    Contact, ContactName, ContactTitle, Customer, CustomerCode, CustomerName, Notes, RecordStatus,
};
