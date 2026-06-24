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
    -- Plain TEXT, not CHAR(3): the 3-uppercase-letter rule is enforced by the
    -- `CurrencyCode` newtype, and TEXT avoids blank-padding on read-back.
    currency     TEXT        NOT NULL DEFAULT 'VND',
    -- VAT rate in basis points (1000 = 10%). Stored as an integer so rate
    -- arithmetic never touches floating point (CLAUDE.md §7 `float_cmp`); INTEGER
    -- (not SMALLINT) so the `u16 -> i32` bind is the infallible `i32::from`.
    tax_rate_bps INTEGER     NOT NULL DEFAULT 1000,
    default_unit TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    -- No value CHECK constraints by design: range/length/format/blank rules live
    -- only in the domain newtype constructors (`backend/src/domain/settings.rs`),
    -- so a limit or rule change is a one-place code edit, not a schema migration.
    -- The DB keeps only structural guarantees (PK, FK, NOT NULL, RLS below).
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
