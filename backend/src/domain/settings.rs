//! Per-tenant business configuration value types (Issue #15).
//!
//! Branding, company identity, default tax rate, currency and default unit of
//! measure. Every field carrying an invariant is a newtype (CLAUDE.md §1):
//! values cross into the typed world exactly once, via `TryFrom`, with no public
//! inner field and no infallible free constructor. The same constructors back
//! `serde` (`#[serde(try_from = ...)]`) so an HTTP body and a database row are
//! validated by identical rules. Caps live in [`limits`](crate::domain::limits).

use super::limits;
use crate::domain::DomainError;

/// Validates a bounded, non-empty text field: trims surrounding whitespace,
/// rejects an empty/whitespace-only value, and enforces the byte cap.
///
/// Shared by every bounded-string newtype below — the same three checks recur
/// well past the rule-of-three, so a single free function holds the rule once
/// without reaching for a trait or macro (CLAUDE.md §4).
fn bounded(raw: &str, max: usize, field: &'static str) -> Result<String, DomainError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DomainError::Empty(field));
    }
    if trimmed.len() > max {
        return Err(DomainError::TooLong { field, max });
    }
    Ok(trimmed.to_owned())
}

/// Company legal name printed on quotes, orders and invoices.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct LegalName(String);

impl LegalName {
    /// The validated name, for binding to SQL or rendering at the boundary.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LegalName {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_LEGAL_NAME, "legal_name").map(Self)
    }
}

/// Default unit of measure (đơn vị tính), e.g. "tờ", "kg", "m²".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct UnitOfMeasure(String);

impl UnitOfMeasure {
    /// The validated unit, for binding to SQL or rendering at the boundary.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for UnitOfMeasure {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_UNIT, "default_unit").map(Self)
    }
}

/// Tax code (mã số thuế / MST).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct TaxCode(String);

impl TaxCode {
    /// The validated tax code, for binding to SQL or rendering at the boundary.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TaxCode {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_TAX_CODE, "tax_code").map(Self)
    }
}

/// Postal address.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Address(String);

impl Address {
    /// The validated address, for binding to SQL or rendering at the boundary.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Address {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_ADDRESS, "address").map(Self)
    }
}

/// Contact phone number.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Phone(String);

impl Phone {
    /// The validated phone, for binding to SQL or rendering at the boundary.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Phone {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_PHONE, "phone").map(Self)
    }
}

/// Contact email address. Length-bounded; deeper RFC validation is deferred.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct EmailAddress(String);

impl EmailAddress {
    /// The validated email, for binding to SQL or rendering at the boundary.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EmailAddress {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_EMAIL, "email").map(Self)
    }
}

/// Logo reference — an object-storage key or URL, not the asset bytes (uploads
/// land in Issue #16).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct LogoRef(String);

impl LogoRef {
    /// The validated reference, for binding to SQL or rendering at the boundary.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LogoRef {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        bounded(&raw, limits::MAX_LOGO_REF, "logo_url").map(Self)
    }
}

/// ISO 4217 alphabetic currency code: exactly three uppercase ASCII letters.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct CurrencyCode(String);

impl CurrencyCode {
    /// The three-letter code, for binding to SQL or rendering at the boundary.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CurrencyCode {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let bytes = raw.as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_uppercase) {
            return Err(DomainError::Invalid("currency"));
        }
        Ok(Self(raw))
    }
}

/// VAT rate in basis points (1000 = 10%), capped at 100%
/// ([`limits::MAX_TAX_RATE_BPS`]). An integer so rate maths never touches
/// floating point (CLAUDE.md §7 `float_cmp`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "u16")]
pub(crate) struct TaxRateBps(u16);

impl TaxRateBps {
    /// The rate in basis points.
    pub(crate) const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for TaxRateBps {
    type Error = DomainError;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        if raw > limits::MAX_TAX_RATE_BPS {
            return Err(DomainError::OutOfRange("tax_rate_bps"));
        }
        Ok(Self(raw))
    }
}

/// A tenant's validated business configuration.
///
/// This is the `PUT /api/settings` request body (deserialized through each field's
/// smart constructor) and the core of the `GET`/`PUT` response. Optional fields
/// are absent rather than empty: an omitted JSON key and a `NULL` column both
/// map to `None`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct BusinessSettings {
    pub(crate) legal_name: LegalName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tax_code: Option<TaxCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) address: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) phone: Option<Phone>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<EmailAddress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) logo_url: Option<LogoRef>,
    pub(crate) currency: CurrencyCode,
    pub(crate) tax_rate_bps: TaxRateBps,
    pub(crate) default_unit: UnitOfMeasure,
}

/// Raw `business_settings` row as read from Postgres, before validation.
///
/// `sqlx` maps columns to primitives here; [`BusinessSettings`] is produced from
/// it via [`TryFrom`] at the boundary (CLAUDE.md §1, §10). `updated_at` is
/// carried separately so the handler can report it without it leaking into the
/// typed config.
#[derive(Debug, sqlx::FromRow)]
pub(crate) struct BusinessSettingsRow {
    pub(crate) legal_name: String,
    pub(crate) tax_code: Option<String>,
    pub(crate) address: Option<String>,
    pub(crate) phone: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) logo_url: Option<String>,
    pub(crate) currency: String,
    pub(crate) tax_rate_bps: i32,
    pub(crate) default_unit: String,
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<BusinessSettingsRow> for BusinessSettings {
    type Error = DomainError;

    fn try_from(row: BusinessSettingsRow) -> Result<Self, Self::Error> {
        // SMALLINT is signed in Postgres; the CHECK keeps it >= 0, but parse
        // defensively rather than narrow with `as` (CLAUDE.md §7).
        let bps =
            u16::try_from(row.tax_rate_bps).map_err(|_| DomainError::OutOfRange("tax_rate_bps"))?;
        Ok(Self {
            legal_name: LegalName::try_from(row.legal_name)?,
            tax_code: row.tax_code.map(TaxCode::try_from).transpose()?,
            address: row.address.map(Address::try_from).transpose()?,
            phone: row.phone.map(Phone::try_from).transpose()?,
            email: row.email.map(EmailAddress::try_from).transpose()?,
            logo_url: row.logo_url.map(LogoRef::try_from).transpose()?,
            currency: CurrencyCode::try_from(row.currency)?,
            tax_rate_bps: TaxRateBps::try_from(bps)?,
            default_unit: UnitOfMeasure::try_from(row.default_unit)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::limits;
    use super::{
        BusinessSettings, CurrencyCode, DomainError, LegalName, TaxRateBps, UnitOfMeasure,
    };

    #[test]
    fn legal_name_accepts_and_trims_valid_text() {
        let name = LegalName::try_from("  Acme Print Co  ".to_owned())
            .expect("a non-empty name within the cap is valid");
        assert_eq!(
            name.as_str(),
            "Acme Print Co",
            "surrounding whitespace is trimmed"
        );
    }

    #[test]
    fn legal_name_rejects_empty() {
        let err = LegalName::try_from("   ".to_owned()).expect_err("whitespace-only is empty");
        assert_eq!(err, DomainError::Empty("legal_name"));
    }

    #[test]
    fn legal_name_rejects_over_cap() {
        let raw = "a".repeat(limits::MAX_LEGAL_NAME + 1);
        let err = LegalName::try_from(raw).expect_err("a name past the cap is rejected");
        assert!(matches!(
            err,
            DomainError::TooLong {
                field: "legal_name",
                ..
            }
        ));
    }

    #[test]
    fn unit_of_measure_accepts_unicode() {
        let unit = UnitOfMeasure::try_from("m²".to_owned()).expect("unicode unit is valid");
        assert_eq!(unit.as_str(), "m²");
    }

    #[test]
    fn currency_accepts_three_uppercase_letters() {
        let code = CurrencyCode::try_from("VND".to_owned()).expect("VND is a valid code");
        assert_eq!(code.as_str(), "VND");
    }

    #[test]
    fn currency_rejects_lowercase() {
        let err = CurrencyCode::try_from("vnd".to_owned()).expect_err("lowercase is invalid");
        assert_eq!(err, DomainError::Invalid("currency"));
    }

    #[test]
    fn currency_rejects_wrong_length() {
        let err = CurrencyCode::try_from("US".to_owned()).expect_err("two letters is invalid");
        assert_eq!(err, DomainError::Invalid("currency"));
    }

    #[test]
    fn currency_rejects_non_letters() {
        let err = CurrencyCode::try_from("U$D".to_owned()).expect_err("a symbol is invalid");
        assert_eq!(err, DomainError::Invalid("currency"));
    }

    #[test]
    fn tax_rate_accepts_boundary() {
        let rate = TaxRateBps::try_from(limits::MAX_TAX_RATE_BPS)
            .expect("exactly 100% is the inclusive maximum");
        assert_eq!(rate.get(), limits::MAX_TAX_RATE_BPS);
    }

    #[test]
    fn tax_rate_rejects_over_cap() {
        let err = TaxRateBps::try_from(limits::MAX_TAX_RATE_BPS + 1)
            .expect_err("above 100% is out of range");
        assert_eq!(err, DomainError::OutOfRange("tax_rate_bps"));
    }

    /// A minimal valid JSON body with only the required fields set.
    const MINIMAL_JSON: &str = r#"{
        "legal_name": "Acme Print Co",
        "currency": "VND",
        "tax_rate_bps": 1000,
        "default_unit": "tờ"
    }"#;

    #[test]
    fn deserializes_minimal_body_with_optionals_absent() {
        let settings: BusinessSettings =
            serde_json::from_str(MINIMAL_JSON).expect("minimal body deserializes");
        assert_eq!(settings.legal_name.as_str(), "Acme Print Co");
        assert!(settings.tax_code.is_none(), "absent optional maps to None");
        assert_eq!(settings.tax_rate_bps.get(), 1000);
    }

    #[test]
    fn deserialize_rejects_invalid_field_through_constructor() {
        let json = r#"{
            "legal_name": "Acme",
            "currency": "vnd",
            "tax_rate_bps": 1000,
            "default_unit": "tờ"
        }"#;
        let result: Result<BusinessSettings, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "an invalid currency must fail deserialization"
        );
    }

    #[test]
    fn serialize_skips_absent_optionals() {
        let settings: BusinessSettings =
            serde_json::from_str(MINIMAL_JSON).expect("minimal body deserializes");
        let json = serde_json::to_value(&settings).expect("serializes");
        assert!(json.get("tax_code").is_none(), "None optionals are omitted");
        assert_eq!(
            json["currency"], "VND",
            "currency renders as a plain string"
        );
        assert_eq!(
            json["tax_rate_bps"], 1000,
            "rate renders as a plain integer"
        );
    }

    #[test]
    fn settings_round_trips_through_json() {
        let json = r#"{
            "legal_name": "Acme Print Co",
            "tax_code": "0312345678",
            "address": "12 Lê Lợi, Q1, HCMC",
            "currency": "VND",
            "tax_rate_bps": 800,
            "default_unit": "tờ"
        }"#;
        let settings: BusinessSettings = serde_json::from_str(json).expect("deserializes");
        let reparsed: BusinessSettings =
            serde_json::from_value(serde_json::to_value(&settings).expect("serializes"))
                .expect("re-deserializes");
        assert_eq!(settings, reparsed, "serialize/deserialize is lossless");
    }
}
