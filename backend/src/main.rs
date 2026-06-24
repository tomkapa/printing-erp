//! Print MIS/ERP backend.
//!
//! A single binary crate organized into modules:
//! - [`config`]    — layered settings + secrets
//! - [`telemetry`] — tracing + OpenTelemetry bootstrap
//! - [`clock`]     — the time abstraction (CLAUDE.md §11)
//! - [`db`]        — PostgreSQL pool + migrations
//! - [`http`]      — axum router, state and route handlers
//! - [`app`]       — wires everything together and serves until shutdown
//!
//! `anyhow` is permitted only here at the top level (CLAUDE.md §12); every
//! module boundary returns a typed `thiserror` enum.

mod app;
mod auth;
mod clock;
mod config;
mod db;
mod domain;
mod http;
mod telemetry;
#[cfg(test)]
mod testsupport;

use anyhow::Context as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = config::load().context("loading configuration")?;
    let _telemetry = telemetry::init(&settings.telemetry).context("initializing telemetry")?;

    app::run(settings).await.context("running HTTP server")?;
    Ok(())
}
