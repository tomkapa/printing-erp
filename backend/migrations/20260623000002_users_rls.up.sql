-- Row-Level Security backstop for tenant isolation (SPEC.md §Tenancy,
-- CLAUDE.md §10). The application always scopes queries by tenant; this policy
-- is the defense-in-depth layer that makes a forgotten `WHERE tenant_id` return
-- nothing instead of leaking across tenants.
--
-- How it works: each request runs inside a transaction that sets the GUC
-- `app.current_tenant` (see `db::begin_tenant_tx`). The policy compares each
-- row's `tenant_id` to that GUC. When the GUC is unset, `current_setting(.., true)`
-- yields NULL and the predicate is NULL — so the row is invisible (default-deny).
-- `nullif(.., '')` collapses an empty/reset GUC to NULL so the `::uuid` cast can
-- never raise on `''` and turn a missing-tenant case into a 500.
--
-- Convention for future tenant-scoped tables: every table carrying `tenant_id`
-- repeats this block (ENABLE + FORCE + a `*_tenant_isolation` FOR ALL policy).
-- The root `tenants` table is intentionally NOT under RLS: it is read to resolve
-- a tenant before any tenant context exists, and provisioning a new tenant is a
-- platform-admin path guarded at the application/authz layer.

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- FORCE is load-bearing: the application connects as the table OWNER, and an
-- owner bypasses RLS unless FORCE is set. Without it, isolation is silently absent.
ALTER TABLE users FORCE ROW LEVEL SECURITY;

CREATE POLICY users_tenant_isolation ON users
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    );

-- Grant the least-privilege runtime role (created at cluster init, see
-- db/init/00-app-role.sql) table access. Grants must live in the migration, not
-- the init script: ALTER DEFAULT PRIVILEGES / pg_default_acl does NOT propagate
-- to the template-cloned databases that `#[sqlx::test]` spins up, so the grant
-- has to run inside every database the migration touches. `erp_app` is subject
-- to the RLS policy above; `tenants` (the root table) is reachable but not
-- tenant-filtered. DO block keeps the migration runnable on clusters where the
-- role was not provisioned (e.g. a plain admin-only setup).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON users   TO erp_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON tenants TO erp_app;
    END IF;
END
$$;
