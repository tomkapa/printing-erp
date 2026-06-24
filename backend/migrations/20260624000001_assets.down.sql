-- Reverse of 20260624000001_assets.up.sql (CLAUDE.md §13: tested reversible
-- rollback). Dropping the table cascades its policy, index and grants; the enum
-- type is dropped afterwards.

DROP TABLE IF EXISTS assets;
DROP TYPE IF EXISTS asset_status;
