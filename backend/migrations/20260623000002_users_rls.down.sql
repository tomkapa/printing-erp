-- Reverse of 20260623000002_users_rls.up.sql (CLAUDE.md §13: tested reversible
-- rollback). Restores the pre-RLS state: no policy, RLS disabled.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        REVOKE SELECT, INSERT, UPDATE, DELETE ON users   FROM erp_app;
        REVOKE SELECT, INSERT, UPDATE, DELETE ON tenants FROM erp_app;
    END IF;
END
$$;

DROP POLICY IF EXISTS users_tenant_isolation ON users;
ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
