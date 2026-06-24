# Printing ERP

A print-shop management system (Print MIS/ERP) for the printing industry —
purpose-built to replace spreadsheets with a single connected flow from
**quote → order → job ticket → shop-floor tracking → delivery → invoicing**.

It packages the operational workflow of a print business: estimating from
material/press norms, turning orders into production jobs with configurable
routing, tracking work across stages in real time, and managing stock,
shipping and receivables — with Vietnamese-language operation as a first-class
goal.

## What it does

- **Estimating** — price a job from paper, ink, press time, finishing and
  waste using per-shop materials, machine speed tables and BOM templates.
- **Quotes & orders** — versioned quotes, approval into orders, re-orders, and
  artwork attached to each job.
- **Job tickets & routing** — generate production jobs from orders with the
  right sequence of operations for the print method (offset / digital / flexo).
- **Shop-floor tracking** — operators start/stop operations on a tablet; time
  and material consumption are captured live over WebSockets.
- **Inventory** — track paper/ink/consumables by lot and consume stock against
  jobs.
- **Delivery & invoicing** — packing lists, shipments, invoices and payments.
- **Multi-tenant SaaS platform** — tenants, role-based access
  (admin/sales/coordinator/scheduler/operator), audit and notifications.

See [`SPEC.md`](SPEC.md) for the data model and the order-to-delivery pipeline.
The MVP targets the core flow (modules above); scheduling, BI, the customer
portal and e-invoice integration follow in later phases.

## Architecture

| Layer | Technology |
| --- | --- |
| Frontend | React 19 + TypeScript, built and run with **Bun** (Vite) |
| Backend | **Rust** — axum (HTTP) + tower, tokio runtime |
| Persistence | **PostgreSQL** via sqlx (runtime queries, embedded migrations) |
| Queue / cache | **Redis** (background jobs, caching) |
| Object storage | **S3-compatible** (AWS S3 / Cloudflare R2 / MinIO) via `aws-sdk-s3`, presigned URLs |
| Config | `config` + `secrecy` (layered file + `APP__*` env, secrets redacted) |
| Telemetry | `tracing` + OpenTelemetry (OTLP/gRPC export) |
| Errors | `thiserror` at module boundaries, `anyhow` only in the binary |

Engineering rules for the backend are codified in
[`CLAUDE.md`](CLAUDE.md) (types encode invariants, everything bounded,
tests own the clock, strict clippy).

## Repository layout

```
printing-erp/
├── backend/                 # Rust binary crate
│   ├── Cargo.toml           # dependencies + lint configuration
│   ├── src/
│   │   ├── main.rs          # entry point
│   │   ├── app.rs           # wiring: run, redis, graceful shutdown
│   │   ├── config.rs        # layered settings + secrets
│   │   ├── telemetry.rs     # tracing + OpenTelemetry bootstrap
│   │   ├── clock.rs         # time abstraction (CLAUDE.md §11)
│   │   ├── db.rs            # PgPool + migrations
│   │   └── http/            # axum router, state, routes, limits
│   └── migrations/          # reversible sqlx migrations
├── frontend/                # React + TypeScript (Bun/Vite)
├── docker-compose.yml       # PostgreSQL + Redis for local dev
├── SPEC.md                  # data model & pipeline
└── CLAUDE.md                # backend engineering rules
```

## Getting started

### Prerequisites

- Rust (stable) with `cargo`
- [Bun](https://bun.sh)
- Docker (for PostgreSQL + Redis)

### 1. Start infrastructure

```sh
docker compose up -d
```

This brings up PostgreSQL on `localhost:5432`, Redis on `localhost:6379`
(credentials `erp` / `erp`, database `erp`) and **MinIO** (S3-compatible object
storage) on `localhost:9000` with a console on `localhost:9001`. A one-shot
`minio-init` container creates the `erp-assets` bucket.

### 2. Run the backend

```sh
cp .env.example .env
set -a; source .env; set +a          # load config into the environment
cargo run --manifest-path backend/Cargo.toml
```

The server applies migrations on startup, then listens on
`http://localhost:8080`. Verify:

```sh
curl localhost:8080/health/live
curl localhost:8080/health/ready     # 200 when Postgres + Redis are reachable
```

### 3. Run the frontend

```sh
cd frontend
bun install
bun run dev
```

Open `http://localhost:5173`. The dev server proxies `/api` and `/health` to
the backend, and the home page shows live backend/database/Redis status.

## Object storage (assets)

File uploads (print artwork, proofs) never stream through the API. The backend
issues short-lived **presigned URLs** and the client transfers bytes directly to
the object store:

1. `POST /assets` — declare `{ filename, content_type, size_bytes }`; returns an
   `asset_id` and a presigned `upload_url`.
2. `PUT` the file to `upload_url` (S3 / R2 / MinIO directly, out of band).
3. `POST /assets/{id}/complete` — the backend HEAD-verifies the object and marks
   it `ready`.
4. `GET /assets/{id}` returns a presigned download URL; `DELETE /assets/{id}`
   removes the bytes and soft-deletes the record.

The provider is pure configuration (`APP__STORAGE__*`, see `.env.example`): one
code path serves AWS S3, Cloudflare R2 and MinIO via `endpoint_url`, `region`
and `force_path_style`. Asset rows are tenant-scoped under Row-Level Security,
like every other table.

## Development

Backend gates (run from `backend/`, see `CLAUDE.md §3`):

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

A `Makefile` at the repo root wraps the common commands:

```sh
make up          # start postgres + redis
make migrate     # apply migrations
make backend     # run the API server
make frontend    # run the Vite dev server
make check       # fmt + clippy + test
make down        # stop infrastructure
```

## License

MIT — see [`LICENSE`](LICENSE).
