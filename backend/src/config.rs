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
    /// S3-compatible object storage (S3 / Cloudflare R2 / MinIO).
    pub(crate) storage: StorageSettings,
    /// Authentication: JWT signing + token lifetimes.
    pub(crate) auth: AuthSettings,
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

/// S3-compatible object storage settings.
///
/// One configuration serves AWS S3, Cloudflare R2 and MinIO — they speak the
/// same SigV4 protocol, so portability is a matter of these knobs, not of a
/// per-provider code path (CLAUDE.md §4: no abstraction the data does not need).
#[derive(Debug, Deserialize)]
pub(crate) struct StorageSettings {
    /// Custom endpoint for R2/MinIO (e.g. `https://<acct>.r2.cloudflarestorage.com`
    /// or `http://localhost:9000`). Absent ⇒ the default AWS S3 endpoint.
    ///
    /// SECURITY/OPS — this host is baked into **presigned URLs**, so it must be
    /// reachable by the *client* that uploads/downloads (the browser), not just
    /// by the server. In local dev use `localhost:9000`, never the
    /// docker-internal hostname the backend would otherwise resolve.
    #[serde(default)]
    pub(crate) endpoint_url: Option<String>,
    /// SigV4 region. AWS uses real regions; R2 uses `auto`; MinIO accepts any
    /// non-empty token but it must match what the client signs with.
    pub(crate) region: String,
    /// Bucket that holds every tenant's objects (tenant-prefixed keys).
    pub(crate) bucket: String,
    /// Access key id (SigV4 credential). Secret so it never reaches logs.
    pub(crate) access_key_id: SecretString,
    /// Secret access key (SigV4 credential).
    pub(crate) secret_access_key: SecretString,
    /// Path-style addressing (`endpoint/bucket/key`) instead of virtual-hosted
    /// (`bucket.endpoint/key`). Required by MinIO; harmless for R2. Defaults to
    /// virtual-hosted, which is what real AWS S3 expects.
    #[serde(default)]
    pub(crate) force_path_style: bool,
}

/// Authentication settings: the HS256 signing secret and token lifetimes.
///
/// Lifetimes are seconds in config (TOML/env are stringly typed); the
/// `*_ttl` accessors hand back [`Duration`]s. The secret is a
/// [`SecretString`] so it never appears in logs or `Debug`.
#[derive(Debug, Deserialize)]
pub(crate) struct AuthSettings {
    /// HS256 signing/verification key. Its length is asserted (≥256 bits) when
    /// the auth context is built, so a too-short secret fails fast at startup.
    pub(crate) jwt_secret: SecretString,
    /// Access-token lifetime in seconds (default 900 = 15 min): short, since the
    /// stateless access token cannot be revoked before it expires.
    #[serde(default = "default_access_ttl_secs")]
    pub(crate) access_ttl_secs: u64,
    /// Refresh-token lifetime in seconds (default 2_592_000 = 30 days).
    #[serde(default = "default_refresh_ttl_secs")]
    pub(crate) refresh_ttl_secs: u64,
    /// Password-reset-token lifetime in seconds (default 3600 = 1 hour).
    #[serde(default = "default_reset_ttl_secs")]
    pub(crate) reset_ttl_secs: u64,
    /// `iss` claim stamped on, and required of, every access token.
    #[serde(default = "default_issuer")]
    pub(crate) issuer: String,
}

impl AuthSettings {
    /// Access-token lifetime as a [`Duration`].
    pub(crate) const fn access_ttl(&self) -> Duration {
        Duration::from_secs(self.access_ttl_secs)
    }

    /// Refresh-token lifetime as a [`Duration`].
    pub(crate) const fn refresh_ttl(&self) -> Duration {
        Duration::from_secs(self.refresh_ttl_secs)
    }

    /// Reset-token lifetime as a [`Duration`].
    pub(crate) const fn reset_ttl(&self) -> Duration {
        Duration::from_secs(self.reset_ttl_secs)
    }
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

const fn default_access_ttl_secs() -> u64 {
    900
}

const fn default_refresh_ttl_secs() -> u64 {
    2_592_000
}

const fn default_reset_ttl_secs() -> u64 {
    3_600
}

fn default_issuer() -> String {
    "printing-erp".to_owned()
}

fn default_service_name() -> String {
    "erp-server".to_owned()
}

fn default_log_level() -> String {
    "info".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseSettings, ServerSettings, StorageSettings, default_acquire_timeout_secs,
        default_port,
    };
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

    #[test]
    fn storage_optional_fields_default_off() {
        // Only the four required keys are supplied; `endpoint_url` and
        // `force_path_style` must fall back to their AWS-shaped defaults.
        let json = serde_json::json!({
            "region": "us-east-1",
            "bucket": "erp-assets",
            "access_key_id": "ak",
            "secret_access_key": "sk",
        });
        let storage: StorageSettings =
            serde_json::from_value(json).expect("required keys deserialize");
        assert!(
            storage.endpoint_url.is_none(),
            "absent endpoint_url means default AWS S3"
        );
        assert!(
            !storage.force_path_style,
            "default addressing is virtual-hosted, as AWS S3 expects"
        );
        assert_eq!(storage.bucket, "erp-assets");
    }

    #[test]
    fn auth_ttls_convert_seconds_to_durations() {
        use super::AuthSettings;
        use std::time::Duration;

        let auth = AuthSettings {
            jwt_secret: SecretString::from("x".repeat(32)),
            access_ttl_secs: 900,
            refresh_ttl_secs: 2_592_000,
            reset_ttl_secs: 3_600,
            issuer: "printing-erp".to_owned(),
        };
        assert_eq!(auth.access_ttl(), Duration::from_secs(900));
        assert_eq!(auth.refresh_ttl(), Duration::from_secs(2_592_000));
        assert_eq!(auth.reset_ttl(), Duration::from_secs(3_600));
    }
}
