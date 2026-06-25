-- Reverse of 20260625000001_crm.up.sql (CLAUDE.md §13: tested reversible
-- rollback). Dropping each table cascades its policy, indexes and grants. Drop
-- `contacts` first (it FKs `customers`); the order of the other two is free.
-- No ENUM types to drop — the status set lives in the Rust newtype, not the DB.

DROP TABLE IF EXISTS contacts;
DROP TABLE IF EXISTS customer_code_seq;
DROP TABLE IF EXISTS customers;
