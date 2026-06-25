-- CRM: tenant-scoped customer profiles and their contacts (issue #17). A
-- `customer` is a tenant's client; a `contact` is a person at that client.
-- Customers are the head of the order-to-delivery pipeline (SPEC.md §Pipeline):
-- quotes/orders/jobs land later and FK to `customers`, so removal is a soft
-- archive (`status`), never a hard delete that would dangle history.
--
-- Tenant isolation repeats the `users_rls`/`assets` pattern (SPEC.md §Tenancy,
-- CLAUDE.md §10): ENABLE + FORCE ROW LEVEL SECURITY + a `*_tenant_isolation`
-- FOR ALL policy keyed on the `app.current_tenant` GUC, plus a grant to the
-- least-privilege `erp_app` serving role.
--
-- Value constraints (status set, field lengths, the `CS###` code shape) are NOT
-- expressed as DB ENUM/CHECK: they are enforced once, in the Rust newtype
-- `TryFrom` constructors (`crm::model`). The columns are plain `TEXT`/`BIGINT`,
-- so a limit bump or a new status variant is a code change, not a migration.
-- Only structural guarantees live here: PRIMARY KEY, FOREIGN KEY, NOT NULL,
-- UNIQUE, and the RLS policies.

CREATE TABLE customers (
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- System-assigned, human-readable, sequential per tenant ("CS001", …).
    -- Allocated from `customer_code_seq` in the same transaction as the insert.
    code       TEXT        NOT NULL,
    name       TEXT        NOT NULL,
    tax_code   TEXT,
    address    TEXT,
    phone      TEXT,
    email      TEXT,
    notes      TEXT,
    -- 'active' | 'archived' — validated by the `RecordStatus` newtype, not an enum.
    status     TEXT        NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Structural backstop for the per-tenant code generator (codes are unique by
    -- construction; a violation here is an internal invariant failure, not a 409).
    UNIQUE (tenant_id, code),
    -- Target of the contacts composite FK below. `id` alone is already unique
    -- (it is the PK); this names (tenant_id, id) as a key so a contact can be
    -- structurally pinned to a customer *in the same tenant* — a defense-in-depth
    -- backstop for the cross-tenant leak that a plain `customer_id` FK would allow
    -- (FK checks bypass RLS, so the same-tenant guarantee must be in the key).
    UNIQUE (tenant_id, id)
);

CREATE INDEX customers_tenant_id_idx ON customers (tenant_id);

-- Per-tenant monotonic counter backing the `CS###` codes. One row per tenant;
-- `next_seq` is the last allocated value. Incremented under a row lock via
-- `INSERT … ON CONFLICT DO UPDATE … RETURNING`, so concurrent customer creates
-- for one tenant serialize and never collide (CLAUDE.md §6 — the generator's
-- invariant is enforced by the lock, gap-free because it shares the insert's tx).
CREATE TABLE customer_code_seq (
    tenant_id UUID   PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    next_seq  BIGINT NOT NULL
);

CREATE TABLE contacts (
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- A contact belongs to exactly one customer. The FK is composite on
    -- (tenant_id, customer_id) → customers (tenant_id, id), so a contact can only
    -- ever reference a customer in its own tenant (FK validation bypasses RLS, so
    -- this structural key is what actually prevents a cross-tenant link). Cascade
    -- keeps the child set consistent if a customer row is hard-deleted.
    customer_id UUID        NOT NULL,
    name        TEXT        NOT NULL,
    title       TEXT,
    email       TEXT,
    phone       TEXT,
    is_primary  BOOLEAN     NOT NULL DEFAULT FALSE,
    status      TEXT        NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, customer_id)
        REFERENCES customers (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX contacts_tenant_customer_idx ON contacts (tenant_id, customer_id);

-- Row-Level Security (FORCE is load-bearing: the app connects as the table
-- OWNER, which bypasses RLS unless FORCE is set). Each policy compares the row's
-- `tenant_id` to the per-transaction GUC; an unset GUC sees no rows (default-deny).
ALTER TABLE customers         ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers         FORCE  ROW LEVEL SECURITY;
ALTER TABLE customer_code_seq ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_code_seq FORCE  ROW LEVEL SECURITY;
ALTER TABLE contacts          ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts          FORCE  ROW LEVEL SECURITY;

CREATE POLICY customers_tenant_isolation ON customers
    FOR ALL
    USING (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);

CREATE POLICY customer_code_seq_tenant_isolation ON customer_code_seq
    FOR ALL
    USING (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);

CREATE POLICY contacts_tenant_isolation ON contacts
    FOR ALL
    USING (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid);

-- Grant the runtime role table access (see db/init/00-app-role.sql and the
-- users_rls migration for why grants live in migrations, not the init script).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON customers         TO erp_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON customer_code_seq TO erp_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON contacts          TO erp_app;
    END IF;
END
$$;
