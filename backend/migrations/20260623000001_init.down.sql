-- Reverse of 20260623000001_init.up.sql (CLAUDE.md §13: tested reversible rollback).

DROP INDEX IF EXISTS users_tenant_id_idx;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS user_role;
DROP TABLE IF EXISTS tenants;
