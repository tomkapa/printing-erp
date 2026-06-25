//! Hard limits for the CRM subsystem (CLAUDE.md §5).
//!
//! Every bound is named and documented with *why this number*, never a magic
//! literal in parsing or query logic. Caps for the contact-info fields reused
//! from [`crate::domain`] (tax code, address, phone, email) live in
//! [`crate::domain::limits`]; only the CRM-native fields are bounded here.

/// Customer display name. Generous for a full registered company name including
/// type suffixes, matching the business-settings `MAX_LEGAL_NAME`.
pub(crate) const MAX_CUSTOMER_NAME: usize = 200;

/// Contact person name. A short label, matching the user `DisplayName` cap.
pub(crate) const MAX_CONTACT_NAME: usize = 128;

/// Contact job title / role (e.g. "Trưởng phòng mua hàng"). A short label.
pub(crate) const MAX_CONTACT_TITLE: usize = 100;

/// Free-form note on a customer. A few short paragraphs; bounds the column and
/// the request body without admitting an essay.
pub(crate) const MAX_NOTES: usize = 2_000;

/// The fixed prefix of a generated customer code ("CS001"). Making this
/// per-tenant configurable is a deliberate follow-up (see issue #17 plan).
pub(crate) const CUSTOMER_CODE_PREFIX: &str = "CS";

/// Minimum digit width of the numeric part of a customer code, zero-padded
/// ("CS001"). The number grows past this naturally ("CS1000") — the pad is a
/// floor, not a ceiling.
pub(crate) const CUSTOMER_CODE_MIN_DIGITS: usize = 3;

/// Largest accepted customer code, in bytes. `CS` + up to 19 digits covers the
/// full positive `i64` sequence range, so [`CustomerCode::from_seq`] never trips
/// its length assertion for any valid sequence; on read it only guards a corrupt
/// row.
///
/// [`CustomerCode::from_seq`]: crate::crm::CustomerCode::from_seq
pub(crate) const MAX_CUSTOMER_CODE: usize = CUSTOMER_CODE_PREFIX.len() + 19;

/// Largest page the customer list endpoint returns (CLAUDE.md §5: every batch is
/// capped). A tenant's active client list is browseable, so 100 is generous.
pub(crate) const MAX_CUSTOMERS_PER_PAGE: i64 = 100;

/// Default customer page size when the caller does not specify one.
pub(crate) const DEFAULT_CUSTOMERS_PER_PAGE: i64 = 50;

/// Largest accepted customer-list offset (CLAUDE.md §5: every scan is bounded).
/// At 100 rows/page this is 1,000 pages — far past any realistic browse — while
/// stopping a client from forcing an unbounded `OFFSET` scan.
pub(crate) const MAX_CUSTOMERS_OFFSET: i64 = 100 * MAX_CUSTOMERS_PER_PAGE;

/// Largest number of contacts returned for one customer (CLAUDE.md §5). A single
/// client's contact roster is small; 100 bounds the result without pagination.
pub(crate) const MAX_CONTACTS_PER_CUSTOMER: i64 = 100;

/// Largest accepted `?q=` name filter, in bytes. The needle is bound as a query
/// parameter (never interpolated, CLAUDE.md §10); the cap bounds the work and
/// the body before it reaches Postgres.
pub(crate) const MAX_CUSTOMER_SEARCH: usize = 100;
