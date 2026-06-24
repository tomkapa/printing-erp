-- Assets: tenant-scoped file/asset metadata — print artwork, proofs, packaged
-- jobs (issue #16). The bytes live in S3-compatible object storage; this table
-- is the system-of-record for everything *about* each object. Clients upload and
-- download directly via presigned URLs, so no bytes ever transit the API.
--
-- Tenant isolation repeats the `users_rls` pattern (SPEC.md §Tenancy,
-- CLAUDE.md §10): ENABLE + FORCE ROW LEVEL SECURITY + a `*_tenant_isolation`
-- FOR ALL policy keyed on the `app.current_tenant` GUC, plus a grant to the
-- least-privilege `erp_app` serving role.

CREATE TYPE asset_status AS ENUM ('pending', 'ready', 'deleted');

CREATE TABLE assets (
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id       UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- App-generated, opaque, tenant-prefixed: "{tenant_id}/{asset_id}".
    storage_key     TEXT         NOT NULL,
    original_name   TEXT         NOT NULL,
    content_type    TEXT         NOT NULL,
    -- Declared at create, HEAD-verified at completion. CHECK is defense-in-depth
    -- behind the app-side `ByteSize` newtype.
    size_bytes      BIGINT       NOT NULL CHECK (size_bytes > 0),
    checksum_sha256 TEXT,
    status          asset_status NOT NULL DEFAULT 'pending',
    -- Nullable until authentication lands (then the uploading user's id).
    uploaded_by     UUID                  REFERENCES users (id),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, storage_key)
);

CREATE INDEX assets_tenant_id_idx ON assets (tenant_id);

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
-- FORCE is load-bearing: the app connects as the table OWNER, which bypasses RLS
-- unless FORCE is set. Without it, isolation is silently absent.
ALTER TABLE assets FORCE ROW LEVEL SECURITY;

CREATE POLICY assets_tenant_isolation ON assets
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    );

-- Grant the runtime role table access (see db/init/00-app-role.sql and the
-- users_rls migration for why grants live in migrations, not the init script).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON assets TO erp_app;
    END IF;
END
$$;
