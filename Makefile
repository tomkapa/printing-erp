# Convenience wrappers for local development. The backend also applies
# migrations automatically on startup; `make migrate` is for running them
# standalone (requires `cargo install sqlx-cli`).

CARGO        := cargo --manifest-path backend/Cargo.toml
DATABASE_URL ?= postgres://erp:erp@localhost:5432/erp

.PHONY: up down logs migrate backend frontend frontend-install fmt lint test check clean

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

test: ## Run the Rust test suite
	$(CARGO) test --all-features

check: fmt lint test ## Format, lint and test

clean: ## Remove build artifacts
	$(CARGO) clean
	rm -rf frontend/node_modules frontend/dist
