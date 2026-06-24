-- Cluster-init bootstrap (mounted at /docker-entrypoint-initdb.d, runs once when
-- the data directory is first created). Creates the least-privilege role the
-- application uses to serve requests.
--
-- Why a second role: the default POSTGRES_USER (`erp`) is a SUPERUSER, and
-- superusers BYPASS Row-Level Security entirely — even `FORCE ROW LEVEL SECURITY`
-- does not apply to them. For RLS (SPEC.md §Tenancy, CLAUDE.md §10) to actually
-- isolate tenants, the request-serving role must be NOSUPERUSER NOBYPASSRLS.
--
-- Split of responsibilities:
--   * `erp`     — admin/owner: runs migrations (DDL, CREATE EXTENSION), creates DBs.
--   * `erp_app` — runtime: connects to serve requests, fully subject to RLS.
--
-- Roles are cluster-global (pg_authid is shared), so this role also exists for
-- every ephemeral `#[sqlx::test]` database. Per-table privileges are granted in
-- migrations (default privileges do NOT propagate to template-cloned test DBs).

CREATE ROLE erp_app LOGIN PASSWORD 'erp_app' NOSUPERUSER NOBYPASSRLS;
