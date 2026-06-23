-- Initial schema: multi-tenant foundation (tenants + users).
-- The full domain model (estimates, orders, jobs, …) lands in later migrations.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE tenants (
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL,
    slug       TEXT        NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE user_role AS ENUM (
    'admin',
    'sales',
    'coordinator',
    'scheduler',
    'operator'
);

CREATE TABLE users (
    id            UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email         TEXT        NOT NULL,
    display_name  TEXT        NOT NULL,
    role          user_role   NOT NULL DEFAULT 'operator',
    password_hash TEXT        NOT NULL,
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX users_tenant_id_idx ON users (tenant_id);
