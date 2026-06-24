//! Application configuration.
//!
//! Settings are layered: an optional `config/base.toml` provides defaults, then
//! environment variables prefixed `APP__` override them (nested keys use `__`,
//! e.g. `APP__DATABASE__URL`). Secrets are wrapped in [`secrecy::SecretString`]
//! so they never land in logs or `Debug` output.

use secrecy::SecretString;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

/// Failure while loading or deserializing application configuration.
#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    /// The underlying `config` crate failed to build or deserialize sources.
    #[error("failed to load configuration")]
    Load(#[from] config::ConfigError),
}

/// Top-level configuration aggregate.
#[derive(Debug, Deserialize)]
pub(crate) struct Settings {
    /// HTTP server binding.
    pub(crate) server: ServerSettings,
    /// PostgreSQL connection pool.
    pub(crate) database: DatabaseSettings,
    /// Redis connection.
    pub(crate) redis: RedisSettings,
    /// Tracing / OpenTelemetry export.
    #[serde(default)]
    pub(crate) telemetry: TelemetrySettings,
}

/// HTTP server binding configuration.
#[derive(Debug, Deserialize)]
pub(crate) struct ServerSettings {
    /// Interface to bind, e.g. `0.0.0.0`.
    #[serde(default = "default_host")]
    pub(crate) host: String,
    /// TCP port to listen on.
    #[serde(default = "default_port")]
    pub(crate) port: u16,
}

impl ServerSettings {
    /// Returns the `host:port` string to hand to a TCP listener.
    pub(crate) fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// PostgreSQL connection settings.
#[derive(Debug, Deserialize)]
pub(crate) struct DatabaseSettings {
    /// Request-serving connection URL (`postgres://user:pass@host:port/db`).
    ///
    /// In production this is the least-privilege `erp_app` role, so Row-Level
    /// Security applies — a superuser role would bypass it (CLAUDE.md §10).
    pub(crate) url: SecretString,
    /// Admin URL used **only** to run migrations (DDL needs the owner role).
    /// When absent, [`url`](Self::url) is reused — appropriate only when `url`
    /// is itself an admin role.
    #[serde(default)]
    pub(crate) admin_url: Option<SecretString>,
    /// Maximum size of the connection pool.
    #[serde(default = "default_max_connections")]
    pub(crate) max_connections: u32,
    /// Seconds to wait for a free connection before erroring.
    #[serde(default = "default_acquire_timeout_secs")]
    pub(crate) acquire_timeout_secs: u64,
}

impl DatabaseSettings {
    /// Pool acquire timeout as a [`Duration`].
    pub(crate) const fn acquire_timeout(&self) -> Duration {
        Duration::from_secs(self.acquire_timeout_secs)
    }

    /// URL to run migrations with: the admin role if configured, else [`url`].
    pub(crate) fn migration_url(&self) -> &SecretString {
        self.admin_url.as_ref().unwrap_or(&self.url)
    }
}

/// Redis connection settings.
#[derive(Debug, Deserialize)]
pub(crate) struct RedisSettings {
    /// Full connection URL (`redis://host:port`).
    pub(crate) url: SecretString,
}

/// Tracing / OpenTelemetry settings.
#[derive(Debug, Deserialize)]
pub(crate) struct TelemetrySettings {
    /// `service.name` reported to the collector.
    #[serde(default = "default_service_name")]
    pub(crate) service_name: String,
    /// Default log filter when `RUST_LOG` is unset (e.g. `info`).
    #[serde(default = "default_log_level")]
    pub(crate) log_level: String,
    /// OTLP/gRPC collector endpoint. When absent, only the stdout layer runs.
    #[serde(default)]
    pub(crate) otlp_endpoint: Option<String>,
}

impl Default for TelemetrySettings {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            log_level: default_log_level(),
            otlp_endpoint: None,
        }
    }
}

/// Loads configuration from the optional base file and `APP__*` environment.
///
/// # Errors
///
/// Returns [`ConfigError::Load`] if a source cannot be read or a required field
/// (such as the database or Redis URL) is missing or has the wrong type.
pub(crate) fn load() -> Result<Settings, ConfigError> {
    let settings = config::Config::builder()
        .add_source(config::File::with_name("config/base").required(false))
        .add_source(
            config::Environment::with_prefix("APP")
                .separator("__")
                .try_parsing(true),
        )
        .build()?
        .try_deserialize()?;
    Ok(settings)
}

fn default_host() -> String {
    "0.0.0.0".to_owned()
}

const fn default_port() -> u16 {
    8080
}

const fn default_max_connections() -> u32 {
    10
}

const fn default_acquire_timeout_secs() -> u64 {
    5
}

fn default_service_name() -> String {
    "erp-server".to_owned()
}

fn default_log_level() -> String {
    "info".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{DatabaseSettings, ServerSettings, default_acquire_timeout_secs, default_port};
    use secrecy::SecretString;
    use std::time::Duration;

    #[test]
    fn bind_address_joins_host_and_port() {
        let server = ServerSettings {
            host: "127.0.0.1".to_owned(),
            port: 9000,
        };
        assert_eq!(server.bind_address(), "127.0.0.1:9000");
    }

    #[test]
    fn database_acquire_timeout_uses_seconds() {
        let database = DatabaseSettings {
            url: SecretString::from("postgres://localhost/erp"),
            admin_url: None,
            max_connections: 5,
            acquire_timeout_secs: 7,
        };
        assert_eq!(database.acquire_timeout(), Duration::from_secs(7));
    }

    #[test]
    fn migration_url_prefers_admin_then_falls_back_to_url() {
        use secrecy::ExposeSecret as _;

        let with_admin = DatabaseSettings {
            url: SecretString::from("postgres://erp_app@localhost/erp"),
            admin_url: Some(SecretString::from("postgres://erp@localhost/erp")),
            max_connections: 5,
            acquire_timeout_secs: 7,
        };
        assert_eq!(
            with_admin.migration_url().expose_secret(),
            "postgres://erp@localhost/erp"
        );

        let without_admin = DatabaseSettings {
            url: SecretString::from("postgres://erp@localhost/erp"),
            admin_url: None,
            max_connections: 5,
            acquire_timeout_secs: 7,
        };
        assert_eq!(
            without_admin.migration_url().expose_secret(),
            "postgres://erp@localhost/erp"
        );
    }

    #[test]
    fn defaults_are_sane() {
        assert_eq!(default_port(), 8080);
        assert_eq!(default_acquire_timeout_secs(), 5);
    }
}
