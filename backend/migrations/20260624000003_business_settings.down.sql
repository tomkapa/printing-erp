-- Reverse of 20260624000003_business_settings.up.sql (CLAUDE.md §13: tested
-- reversible rollback). Drops the table; the policy and RLS flags go with it.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        REVOKE SELECT, INSERT, UPDATE, DELETE ON business_settings FROM erp_app;
    END IF;
END
$$;

DROP POLICY IF EXISTS business_settings_tenant_isolation ON business_settings;
DROP TABLE IF EXISTS business_settings;
