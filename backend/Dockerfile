# syntax=docker/dockerfile:1
#
# Backend image for the printing-erp HTTP API (axum + sqlx + tokio).
# Build context is this `backend/` directory:
#   docker build -t printing-erp-backend backend/
#
# All runtime configuration is supplied via APP__* environment variables
# (config/base.toml is optional — see backend/src/config.rs), so the image ships
# no baked-in config and is identical across every environment.

# ---- builder ----------------------------------------------------------------
FROM rust:1.85-bookworm AS builder
WORKDIR /build

# Migrations are embedded into the binary at compile time via
# sqlx::migrate!("./migrations") (backend/src/db.rs), so the whole crate —
# sources and migrations alike — must be present before `cargo build`.
COPY . .

# BuildKit cache mounts keep the cargo registry and target dir warm across builds
# without the dummy-manifest trick. `--locked` pins to the committed Cargo.lock.
# The release binary is copied OUT of the cached target dir within the same layer
# so it survives once the cache mount is unmounted.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked \
 && cp target/release/printing-erp /usr/local/bin/printing-erp

# ---- runtime ----------------------------------------------------------------
# distroless `cc`: glibc + libgcc (the binary dynamically links glibc) and the CA
# root bundle (TLS to Postgres, Redis and S3/R2). `:nonroot` runs as uid 65532 —
# no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /usr/local/bin/printing-erp /usr/local/bin/printing-erp

# Server binds APP__SERVER__HOST:APP__SERVER__PORT (defaults 0.0.0.0:8080).
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/printing-erp"]
