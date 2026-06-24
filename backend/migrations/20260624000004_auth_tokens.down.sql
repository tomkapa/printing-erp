-- Reverse of 20260624000003_auth_tokens.up.sql (CLAUDE.md §13: tested reversible
-- rollback). Drops grants, policies, RLS flags, and the tables — in reverse
-- order of creation so the self-referential FK on refresh_tokens unwinds cleanly.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        REVOKE SELECT, INSERT, UPDATE, DELETE ON password_reset_tokens FROM erp_app;
        REVOKE SELECT, INSERT, UPDATE, DELETE ON refresh_tokens        FROM erp_app;
    END IF;
END
$$;

DROP POLICY IF EXISTS password_reset_tokens_tenant_isolation ON password_reset_tokens;
DROP POLICY IF EXISTS refresh_tokens_tenant_isolation        ON refresh_tokens;

ALTER TABLE password_reset_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens DISABLE  ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens        NO FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens        DISABLE  ROW LEVEL SECURITY;

DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS refresh_tokens;
