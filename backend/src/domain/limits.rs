//! Bounds for domain value types (CLAUDE.md §5).
//!
//! Every string crossing the boundary into a domain newtype is length-capped,
//! and every bounded numeric has an explicit ceiling. The caps live here — named
//! and documented with *why this number* — rather than as literals scattered
//! through the `TryFrom` impls. The DB `CHECK` constraints in
//! `migrations/20260624000003_business_settings.up.sql` mirror these numbers.

/// Company legal name. Generous for a full registered entity name including
/// company-type suffixes, while bounding header/log size.
pub(crate) const MAX_LEGAL_NAME: usize = 200;

/// Tax code (mã số thuế). Vietnamese codes are 10 or 13 digits; 20 leaves room
/// for separators and other jurisdictions without admitting free-form text.
pub(crate) const MAX_TAX_CODE: usize = 20;

/// Postal address printed on documents — one line or a short multi-line block.
pub(crate) const MAX_ADDRESS: usize = 300;

/// Phone number, including country code, spaces and separators.
pub(crate) const MAX_PHONE: usize = 32;

/// Email address. 254 is the practical maximum length of an RFC 5321 address.
pub(crate) const MAX_EMAIL: usize = 254;

/// Logo reference (object-storage key or URL). Bounds a stored pointer, not the
/// asset itself — the bytes live in object storage (Issue #16).
pub(crate) const MAX_LOGO_REF: usize = 512;

/// Default unit of measure (đơn vị tính), e.g. "tờ", "kg", "m²". Short by nature.
pub(crate) const MAX_UNIT: usize = 32;

/// Maximum VAT rate, in basis points: 10_000 bps = 100%. A rate above 100% is a
/// programmer/data error, not a configuration the system should accept.
pub(crate) const MAX_TAX_RATE_BPS: u16 = 10_000;
