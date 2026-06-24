# Convenience wrappers for local development. The backend also applies
# migrations automatically on startup; `make migrate` is for running them
# standalone (requires `cargo install sqlx-cli`).

CARGO        := cargo --manifest-path backend/Cargo.toml
DATABASE_URL ?= postgres://erp:erp@localhost:5432/erp

# Object storage for the live S3 round-trip test (points at the compose MinIO).
STORAGE_ENDPOINT ?= http://localhost:9000
STORAGE_REGION   ?= us-east-1
STORAGE_BUCKET   ?= erp-assets
STORAGE_KEY      ?= erp
STORAGE_SECRET   ?= erp_secret_dev

.PHONY: up down logs migrate backend frontend frontend-install fmt lint test audit deny check clean

up: ## Start PostgreSQL + Redis
	docker compose up -d

down: ## Stop infrastructure
	docker compose down

logs: ## Tail infrastructure logs
	docker compose logs -f

migrate: ## Apply migrations (needs sqlx-cli)
	cd backend && DATABASE_URL=$(DATABASE_URL) sqlx migrate run

backend: ## Run the API server
	$(CARGO) run

frontend-install: ## Install frontend deps
	cd frontend && bun install

frontend: ## Run the Vite dev server
	cd frontend && bun run dev

fmt: ## Format Rust code
	$(CARGO) fmt --all

lint: ## Clippy with warnings denied
	$(CARGO) clippy --all-targets --all-features -- -D warnings

test: ## Run the Rust test suite (DATABASE_URL = admin role; #[sqlx::test] needs CREATEDB)
	DATABASE_URL=$(DATABASE_URL) \
	APP__STORAGE__ENDPOINT_URL=$(STORAGE_ENDPOINT) \
	APP__STORAGE__REGION=$(STORAGE_REGION) \
	APP__STORAGE__BUCKET=$(STORAGE_BUCKET) \
	APP__STORAGE__ACCESS_KEY_ID=$(STORAGE_KEY) \
	APP__STORAGE__SECRET_ACCESS_KEY=$(STORAGE_SECRET) \
	$(CARGO) test --all-features

# Run from backend/ so cargo-audit and cargo-deny read .cargo/audit.toml and
# deny.toml (the RUSTSEC-2023-0071 suppression + license/bans policy live there).
audit: ## Scan dependencies for RustSec advisories (needs `cargo install cargo-audit`)
	cd backend && cargo audit

deny: ## Check advisories, licenses, bans, sources (needs `cargo install cargo-deny`)
	cd backend && cargo deny check

check: fmt lint test ## Format, lint and test

clean: ## Remove build artifacts
	$(CARGO) clean
	rm -rf frontend/node_modules frontend/dist
