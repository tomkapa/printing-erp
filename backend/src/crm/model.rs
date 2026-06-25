//! CRM value types and the row aggregates.
//!
//! Every field that carries an invariant is a newtype constructed through
//! `TryFrom` at the boundary (CLAUDE.md §1): a bare `String` for a customer
//! name, code or status is a bug. Client-supplied fields funnel deserialization
//! through the same constructors via `#[serde(try_from = "String")]`. The
//! contact-info fields ([`TaxCode`], [`Address`], [`Phone`], [`EmailAddress`])
//! are reused from [`crate::domain`] rather than redefined.
//!
//! The customer **code** is special: it is system-assigned (never client input),
//! so [`CustomerCode`] has a [`CustomerCode::from_seq`] constructor and a lenient
//! `TryFrom<String>` for reading it back, but no `Deserialize`.

use crate::crm::limits;
use crate::domain::{Address, ContactId, CustomerId, EmailAddress, Phone, TaxCode, TenantId};
use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use thiserror::Error;
use uuid::Uuid;

/// Failure parsing a raw value into a CRM value type (CLAUDE.md §12).
///
/// Payloads name the field, never echo the (untrusted) raw value.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// A required text field was empty (after trimming).
    #[error("{0} must not be empty")]
    Empty(&'static str),
    /// A text field exceeded its byte cap.
    #[error("{field} too long: max {max} bytes, got {got}")]
    TooLong {
        field: &'static str,
        max: usize,
        got: usize,
    },
    /// A field did not match its required shape (e.g. a customer code that is not
    /// `CS` followed by digits, or an unknown status label).
    #[error("{0} has an invalid format")]
    Illegal(&'static str),
}

/// Validates a bounded, non-empty text field: trims surrounding whitespace,
/// rejects an empty/whitespace-only value, then enforces the byte cap.
///
/// Shared by every bounded-string newtype below (CLAUDE.md §4 — the same three
/// checks recur well past the rule-of-three, so one helper holds the rule once).
fn bounded(raw: &str, max: usize, field: &'static str) -> Result<String, ParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty(field));
    }
    let got = trimmed.len();
    if got > max {
        return Err(ParseError::TooLong { field, max, got });
    }
    Ok(trimmed.to_owned())
}

/// Wraps any boundary parse failure as a `sqlx` decode error: a stored column
/// did not have the shape our newtypes guarantee — an internal invariant
/// violation, not a client error.
fn decode<E>(error: E) -> sqlx::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    sqlx::Error::Decode(Box::new(error))
}

/// A customer's display name (company or individual). Required, trimmed, bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct CustomerName(String);

impl CustomerName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CustomerName {
    type Error = ParseError;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_CUSTOMER_NAME, "name").map(Self)
    }
}

/// A contact person's name. Required, trimmed, bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct ContactName(String);

impl ContactName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ContactName {
    type Error = ParseError;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_CONTACT_NAME, "contact_name").map(Self)
    }
}

/// A contact's job title / role. Optional, but non-empty when present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct ContactTitle(String);

impl ContactTitle {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ContactTitle {
    type Error = ParseError;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_CONTACT_TITLE, "title").map(Self)
    }
}

/// A free-form note on a customer. Optional, but non-empty when present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Notes(String);

impl Notes {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Notes {
    type Error = ParseError;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_NOTES, "notes").map(Self)
    }
}

/// A system-assigned, human-readable customer code: the [`CUSTOMER_CODE_PREFIX`]
/// followed by a per-tenant sequence, zero-padded to [`CUSTOMER_CODE_MIN_DIGITS`]
/// (`CS001`, `CS002`, … `CS1000`).
///
/// Never client input — built only from an allocated sequence via
/// [`CustomerCode::from_seq`], so there is no `Deserialize`. The lenient
/// `TryFrom<String>` parses a value read back from the database.
///
/// [`CUSTOMER_CODE_PREFIX`]: limits::CUSTOMER_CODE_PREFIX
/// [`CUSTOMER_CODE_MIN_DIGITS`]: limits::CUSTOMER_CODE_MIN_DIGITS
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct CustomerCode(String);

impl CustomerCode {
    /// Formats a customer code from an allocated 1-based sequence number. Pure
    /// and total for any positive `seq` (CLAUDE.md §3 — the generator core is
    /// 100%-covered): `1 -> "CS001"`, `1000 -> "CS1000"`.
    pub(crate) fn from_seq(seq: i64) -> Self {
        assert!(seq > 0, "customer code sequence is 1-based and positive");
        let code = format!(
            "{}{:0width$}",
            limits::CUSTOMER_CODE_PREFIX,
            seq,
            width = limits::CUSTOMER_CODE_MIN_DIGITS
        );
        assert!(
            code.len() <= limits::MAX_CUSTOMER_CODE,
            "customer code stays within its byte cap"
        );
        Self(code)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CustomerCode {
    type Error = ParseError;

    /// Parses a code read back from the database. Codes are app-generated, so the
    /// parse is strict: it must be exactly what [`CustomerCode::from_seq`] would
    /// produce for some positive sequence. A non-canonical value (`CS0`, `CS1`,
    /// `CS0010`, …) is a corrupt row, not a value we ever wrote, so it is rejected
    /// rather than silently admitted past the newtype invariant (CLAUDE.md §1).
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        if raw.len() > limits::MAX_CUSTOMER_CODE {
            return Err(ParseError::TooLong {
                field: "code",
                max: limits::MAX_CUSTOMER_CODE,
                got: raw.len(),
            });
        }
        let digits = raw
            .strip_prefix(limits::CUSTOMER_CODE_PREFIX)
            .ok_or(ParseError::Illegal("code"))?;
        // A positive sequence whose canonical rendering round-trips to the input.
        let seq = digits
            .parse::<i64>()
            .ok()
            .filter(|&seq| seq > 0)
            .ok_or(ParseError::Illegal("code"))?;
        let canonical = Self::from_seq(seq);
        if canonical.as_str() != raw {
            return Err(ParseError::Illegal("code"));
        }
        Ok(canonical)
    }
}

/// Lifecycle of a customer or contact row: visible (`active`) or soft-archived
/// (`archived`). Stored as plain `TEXT` and validated here, not by a DB enum
/// (the status set changes in code, not a migration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordStatus {
    /// Visible in default listings and resolvable by id.
    Active,
    /// Soft-deleted: hidden from default listings, preserved for history.
    Archived,
}

impl RecordStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
        }
    }
}

impl TryFrom<&str> for RecordStatus {
    type Error = ParseError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        match raw {
            "active" => Ok(Self::Active),
            "archived" => Ok(Self::Archived),
            _ => Err(ParseError::Illegal("status")),
        }
    }
}

impl Serialize for RecordStatus {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A customer profile row: a tenant's client (issue #17). The system-of-record
/// for everything the pipeline (quotes/orders/invoices) attaches a buyer to.
#[derive(Debug, Clone)]
pub(crate) struct Customer {
    pub(crate) id: CustomerId,
    pub(crate) tenant_id: TenantId,
    pub(crate) code: CustomerCode,
    pub(crate) name: CustomerName,
    pub(crate) tax_code: Option<TaxCode>,
    pub(crate) address: Option<Address>,
    pub(crate) phone: Option<Phone>,
    pub(crate) email: Option<EmailAddress>,
    pub(crate) notes: Option<Notes>,
    pub(crate) status: RecordStatus,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

impl TryFrom<&PgRow> for Customer {
    type Error = sqlx::Error;

    /// Boundary parse of a `SELECT …, status::text AS status …` row. Every column
    /// funnels through its newtype constructor; a malformed column becomes a
    /// `Decode` error (the stored row did not have the expected shape).
    fn try_from(row: &PgRow) -> Result<Self, Self::Error> {
        let id = CustomerId::try_from(row.try_get::<Uuid, _>("id")?).map_err(decode)?;
        let tenant_id = TenantId::try_from(row.try_get::<Uuid, _>("tenant_id")?).map_err(decode)?;
        let code = CustomerCode::try_from(row.try_get::<String, _>("code")?).map_err(decode)?;
        let name = CustomerName::try_from(row.try_get::<String, _>("name")?).map_err(decode)?;
        let tax_code = opt(row, "tax_code")?
            .map(TaxCode::try_from)
            .transpose()
            .map_err(decode)?;
        let address = opt(row, "address")?
            .map(Address::try_from)
            .transpose()
            .map_err(decode)?;
        let phone = opt(row, "phone")?
            .map(Phone::try_from)
            .transpose()
            .map_err(decode)?;
        let email = opt(row, "email")?
            .map(EmailAddress::try_from)
            .transpose()
            .map_err(decode)?;
        let notes = opt(row, "notes")?
            .map(Notes::try_from)
            .transpose()
            .map_err(decode)?;
        let status =
            RecordStatus::try_from(row.try_get::<String, _>("status")?.as_str()).map_err(decode)?;

        assert!(
            !code.as_str().is_empty(),
            "CustomerCode invariant: non-empty"
        );
        assert!(
            !name.as_str().is_empty(),
            "CustomerName invariant: non-empty"
        );
        Ok(Self {
            id,
            tenant_id,
            code,
            name,
            tax_code,
            address,
            phone,
            email,
            notes,
            status,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// A contact person attached to a [`Customer`].
#[derive(Debug, Clone)]
pub(crate) struct Contact {
    pub(crate) id: ContactId,
    pub(crate) tenant_id: TenantId,
    pub(crate) customer_id: CustomerId,
    pub(crate) name: ContactName,
    pub(crate) title: Option<ContactTitle>,
    pub(crate) email: Option<EmailAddress>,
    pub(crate) phone: Option<Phone>,
    pub(crate) is_primary: bool,
    pub(crate) status: RecordStatus,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

impl TryFrom<&PgRow> for Contact {
    type Error = sqlx::Error;

    fn try_from(row: &PgRow) -> Result<Self, Self::Error> {
        let id = ContactId::try_from(row.try_get::<Uuid, _>("id")?).map_err(decode)?;
        let tenant_id = TenantId::try_from(row.try_get::<Uuid, _>("tenant_id")?).map_err(decode)?;
        let customer_id =
            CustomerId::try_from(row.try_get::<Uuid, _>("customer_id")?).map_err(decode)?;
        let name = ContactName::try_from(row.try_get::<String, _>("name")?).map_err(decode)?;
        let title = opt(row, "title")?
            .map(ContactTitle::try_from)
            .transpose()
            .map_err(decode)?;
        let email = opt(row, "email")?
            .map(EmailAddress::try_from)
            .transpose()
            .map_err(decode)?;
        let phone = opt(row, "phone")?
            .map(Phone::try_from)
            .transpose()
            .map_err(decode)?;
        let status =
            RecordStatus::try_from(row.try_get::<String, _>("status")?.as_str()).map_err(decode)?;

        assert!(
            !name.as_str().is_empty(),
            "ContactName invariant: non-empty"
        );
        Ok(Self {
            id,
            tenant_id,
            customer_id,
            name,
            title,
            email,
            phone,
            is_primary: row.try_get("is_primary")?,
            status,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Reads a nullable `TEXT` column as `Option<String>` (an absent value is `None`).
fn opt(row: &PgRow, column: &str) -> Result<Option<String>, sqlx::Error> {
    row.try_get::<Option<String>, _>(column)
}

#[cfg(test)]
mod tests {
    use super::{
        ContactName, ContactTitle, CustomerCode, CustomerName, Notes, ParseError, RecordStatus,
    };
    use crate::crm::limits;

    #[test]
    fn customer_name_trims_and_caps() {
        assert_eq!(
            CustomerName::try_from("  Công ty In Ấn ABC  ".to_owned())
                .unwrap()
                .as_str(),
            "Công ty In Ấn ABC",
        );
        assert_eq!(
            CustomerName::try_from("   ".to_owned()).unwrap_err(),
            ParseError::Empty("name")
        );
        let long = "x".repeat(limits::MAX_CUSTOMER_NAME + 1);
        assert!(matches!(
            CustomerName::try_from(long).unwrap_err(),
            ParseError::TooLong { field: "name", .. }
        ));
    }

    #[test]
    fn contact_name_and_title_and_notes_are_bounded() {
        assert_eq!(
            ContactName::try_from("  Nguyễn Văn A ".to_owned())
                .unwrap()
                .as_str(),
            "Nguyễn Văn A"
        );
        assert!(ContactName::try_from(String::new()).is_err());
        assert_eq!(
            ContactTitle::try_from("Trưởng phòng mua hàng".to_owned())
                .unwrap()
                .as_str(),
            "Trưởng phòng mua hàng"
        );
        assert!(matches!(
            Notes::try_from("n".repeat(limits::MAX_NOTES + 1)).unwrap_err(),
            ParseError::TooLong { field: "notes", .. }
        ));
        assert_eq!(
            Notes::try_from("  ".to_owned()).unwrap_err(),
            ParseError::Empty("notes")
        );
    }

    #[test]
    fn customer_code_from_seq_pads_and_grows() {
        // The generator core: zero-padded to the minimum width, growing past it.
        assert_eq!(CustomerCode::from_seq(1).as_str(), "CS001");
        assert_eq!(CustomerCode::from_seq(2).as_str(), "CS002");
        assert_eq!(CustomerCode::from_seq(42).as_str(), "CS042");
        assert_eq!(CustomerCode::from_seq(999).as_str(), "CS999");
        assert_eq!(CustomerCode::from_seq(1000).as_str(), "CS1000");
        assert_eq!(CustomerCode::from_seq(123_456).as_str(), "CS123456");
    }

    #[test]
    #[should_panic(expected = "1-based and positive")]
    fn customer_code_from_seq_rejects_non_positive() {
        let _ = CustomerCode::from_seq(0);
    }

    #[test]
    fn customer_code_round_trips_through_db_reader() {
        let code = CustomerCode::from_seq(7);
        let reparsed = CustomerCode::try_from(code.as_str().to_owned()).unwrap();
        assert_eq!(reparsed, code);
    }

    #[test]
    fn customer_code_reader_rejects_bad_shapes() {
        // Wrong prefix / shape, plus non-canonical codes `from_seq` never emits
        // (too few pad digits, extra leading zeros, a sign, a non-positive seq).
        for bad in [
            "KH001", "CS", "CSabc", "001", "CS-1", "", "CS0", "CS1", "CS42", "CS0010", "CS+5",
        ] {
            assert!(
                CustomerCode::try_from(bad.to_owned()).is_err(),
                "must reject {bad:?}"
            );
        }
        let too_long = format!("CS{}", "9".repeat(limits::MAX_CUSTOMER_CODE));
        assert!(matches!(
            CustomerCode::try_from(too_long).unwrap_err(),
            ParseError::TooLong { field: "code", .. }
        ));
    }

    #[test]
    fn customer_code_serializes_as_bare_string() {
        let json = serde_json::to_string(&CustomerCode::from_seq(5)).unwrap();
        assert_eq!(json, "\"CS005\"");
    }

    #[test]
    fn record_status_round_trips_and_serializes() {
        for status in [RecordStatus::Active, RecordStatus::Archived] {
            assert_eq!(RecordStatus::try_from(status.as_str()).unwrap(), status);
        }
        assert_eq!(
            RecordStatus::try_from("bogus").unwrap_err(),
            ParseError::Illegal("status")
        );
        let json = serde_json::to_string(&RecordStatus::Archived).unwrap();
        assert_eq!(json, "\"archived\"");
    }

    #[test]
    fn customer_name_deserializes_through_constructor() {
        let name: CustomerName = serde_json::from_str("\"  Acme  \"").unwrap();
        assert_eq!(name.as_str(), "Acme");
        let bad: Result<CustomerName, _> = serde_json::from_str("\"   \"");
        assert!(bad.is_err(), "blank name must not deserialize");
    }
}
