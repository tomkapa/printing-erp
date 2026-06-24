-- Per-tenant business configuration (Issue #15): branding, company identity,
-- default tax rate, currency, and default unit of measure. These values feed the
-- outward-facing documents along the pipeline (quote -> order -> job ticket).
--
-- One row per tenant: `tenant_id` is the primary key (a singleton-per-tenant
-- config), which also gives `PUT /settings` a natural `ON CONFLICT` upsert
-- target. This is a deliberate departure from the `id UUID PK + UNIQUE(tenant_id)`
-- shape used by `users`; there is never more than one settings row per tenant.
--
-- `logo_url` holds a reference (object key / URL) only — the upload pipeline and
-- object storage land in Issue #16 and will populate this column.

CREATE TABLE business_settings (
    tenant_id    UUID PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    legal_name   TEXT        NOT NULL,
    tax_code     TEXT,
    address      TEXT,
    phone        TEXT,
    email        TEXT,
    logo_url     TEXT,
    -- ISO 4217 alphabetic code; defaults to Vietnamese dong (the primary market).
    currency     CHAR(3)     NOT NULL DEFAULT 'VND',
    -- VAT rate in basis points (1000 = 10%). Stored as an integer so rate
    -- arithmetic never touches floating point (CLAUDE.md §7 `float_cmp`); INTEGER
    -- (not SMALLINT) so the `u16 -> i32` bind is the infallible `i32::from`.
    tax_rate_bps INTEGER     NOT NULL DEFAULT 1000,
    default_unit TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Defense-in-depth: these CHECKs mirror the domain newtype constructors in
    -- `backend/src/domain/settings.rs` (`bounded()`, `CurrencyCode`, `TaxRateBps`)
    -- at the storage layer, so a write that bypasses the application path still
    -- cannot persist a value the typed read would later reject (which would
    -- surface as a 500 on `GET /settings`). Text caps use `octet_length` (bytes)
    -- to match Rust's `str::len`, and `btrim(...) <> ''` rejects blank /
    -- whitespace-only values exactly as `bounded()` does. Nullable columns admit
    -- NULL (absent) but reject an empty/over-cap value when present.
    CONSTRAINT business_settings_tax_rate_bps_range
        CHECK (tax_rate_bps BETWEEN 0 AND 10000),
    CONSTRAINT business_settings_currency_format
        CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT business_settings_legal_name_valid
        CHECK (btrim(legal_name) <> '' AND octet_length(legal_name) <= 200),
    CONSTRAINT business_settings_default_unit_valid
        CHECK (btrim(default_unit) <> '' AND octet_length(default_unit) <= 32),
    CONSTRAINT business_settings_tax_code_valid
        CHECK (tax_code IS NULL OR (btrim(tax_code) <> '' AND octet_length(tax_code) <= 20)),
    CONSTRAINT business_settings_address_valid
        CHECK (address IS NULL OR (btrim(address) <> '' AND octet_length(address) <= 300)),
    CONSTRAINT business_settings_phone_valid
        CHECK (phone IS NULL OR (btrim(phone) <> '' AND octet_length(phone) <= 32)),
    CONSTRAINT business_settings_email_valid
        CHECK (email IS NULL OR (btrim(email) <> '' AND octet_length(email) <= 254)),
    CONSTRAINT business_settings_logo_url_valid
        CHECK (logo_url IS NULL OR (btrim(logo_url) <> '' AND octet_length(logo_url) <= 512))
);

-- Row-Level Security backstop, identical in shape to `users` (migration
-- 20260623000002): every tenant-scoped table repeats this block so a forgotten
-- `WHERE tenant_id` returns nothing instead of leaking across tenants
-- (SPEC.md §Tenancy, CLAUDE.md §10).
ALTER TABLE business_settings ENABLE ROW LEVEL SECURITY;
-- FORCE is load-bearing: the app connects as the table OWNER, which bypasses RLS
-- unless FORCE is set.
ALTER TABLE business_settings FORCE ROW LEVEL SECURITY;

CREATE POLICY business_settings_tenant_isolation ON business_settings
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    );

-- Grant the least-privilege runtime role table access. Grants must live in the
-- migration (not the init script) so they run inside every template-cloned
-- database that `#[sqlx::test]` spins up. The DO block keeps the migration
-- runnable on clusters where `erp_app` was not provisioned.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON business_settings TO erp_app;
    END IF;
END
$$;
