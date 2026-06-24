-- Authentication token storage: rotating refresh tokens (organized into session
-- families for reuse detection) and single-use password-reset tokens. Both are
-- tenant-scoped and repeat the Row-Level Security pattern established for `users`
-- in 20260623000002_users_rls.up.sql (SPEC.md §Tenancy, CLAUDE.md §10).
--
-- Tokens are never stored in plaintext: the application stores `sha256(tenant ++
-- secret)` as a 32-byte BYTEA (the `octet_length = 32` CHECK enforces the width).
-- `issued_at` / `expires_at` are written by the app from its injected clock
-- (CLAUDE.md §11), not via a `DEFAULT now()`, so tests drive expiry deterministically.

CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users   (id) ON DELETE CASCADE,
    -- All tokens minted from one login share a family; rotation chains them and
    -- replaying a rotated token revokes the whole family (theft detection).
    family_id   UUID        NOT NULL,
    token_hash  BYTEA       NOT NULL,
    -- Set when this token is rotated; points at its successor. NULL = current.
    -- ON DELETE SET NULL avoids a self-referential cascade cycle.
    replaced_by UUID                 REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    -- NULL = live; set on rotation, logout, family revocation, or password reset.
    revoked_at  TIMESTAMPTZ,
    CONSTRAINT refresh_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32)
);

CREATE UNIQUE INDEX refresh_tokens_token_hash_key ON refresh_tokens (token_hash);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (tenant_id, family_id);
CREATE INDEX refresh_tokens_user_idx   ON refresh_tokens (tenant_id, user_id);

CREATE TABLE password_reset_tokens (
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users   (id) ON DELETE CASCADE,
    token_hash  BYTEA       NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Single-use: set the moment a reset succeeds. NULL = unused.
    consumed_at TIMESTAMPTZ,
    CONSTRAINT reset_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32)
);

CREATE UNIQUE INDEX password_reset_tokens_token_hash_key ON password_reset_tokens (token_hash);
CREATE INDEX password_reset_tokens_user_idx ON password_reset_tokens (tenant_id, user_id);

-- RLS backstop, repeated per the `users` convention: ENABLE + FORCE (the app
-- connects as the table OWNER, which bypasses RLS unless FORCE is set) + a
-- FOR ALL policy comparing `tenant_id` to the `app.current_tenant` GUC that
-- `db::begin_tenant_tx` sets. An unset GUC yields NULL → default-deny.
ALTER TABLE refresh_tokens        ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens        FORCE  ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens FORCE  ROW LEVEL SECURITY;

CREATE POLICY refresh_tokens_tenant_isolation ON refresh_tokens
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    );

CREATE POLICY password_reset_tokens_tenant_isolation ON password_reset_tokens
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.current_tenant', true), '')::uuid
    );

-- Grant the least-privilege runtime role table access. Grants live in the
-- migration (not the init script) because ALTER DEFAULT PRIVILEGES does not
-- propagate to the template-cloned databases `#[sqlx::test]` spins up. The DO
-- block keeps the migration runnable where `erp_app` was not provisioned.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens        TO erp_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON password_reset_tokens TO erp_app;
    END IF;
END
$$;
