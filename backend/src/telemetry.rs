//! Tracing + OpenTelemetry bootstrap.
//!
//! [`init`] installs a global [`tracing`] subscriber composed of an
//! environment-driven filter, a structured stdout layer, and — when an OTLP
//! endpoint is configured — an OpenTelemetry layer exporting spans over gRPC.
//! The returned [`TelemetryGuard`] flushes the exporter on drop.

use crate::config::TelemetrySettings;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use thiserror::Error;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Failure while installing the global tracing subscriber or OTLP exporter.
#[derive(Debug, Error)]
pub(crate) enum TelemetryError {
    /// The configured log filter directive was invalid.
    #[error("invalid log filter")]
    Filter(#[from] tracing_subscriber::filter::ParseError),

    /// The OTLP span exporter could not be built.
    #[error("failed to build OTLP exporter")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),

    /// A global subscriber was already installed.
    #[error("global tracing subscriber already set")]
    AlreadyInitialized,
}

/// Holds the OpenTelemetry provider so spans flush when the process exits.
#[derive(Debug, Default)]
pub(crate) struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Best-effort flush; nothing actionable remains if shutdown fails.
            drop(provider.shutdown());
        }
    }
}

/// Installs the global tracing subscriber and optional OTLP exporter.
///
/// Call exactly once at startup and keep the returned guard alive for the
/// lifetime of the process.
///
/// # Errors
///
/// Returns [`TelemetryError`] if the log filter is invalid, the OTLP exporter
/// cannot be built, or a global subscriber was already installed.
pub(crate) fn init(settings: &TelemetrySettings) -> Result<TelemetryGuard, TelemetryError> {
    let filter =
        EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(&settings.log_level))?;

    let fmt_layer = tracing_subscriber::fmt::layer().with_target(true);
    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);

    let Some(endpoint) = settings.otlp_endpoint.as_deref() else {
        registry
            .try_init()
            .map_err(|_| TelemetryError::AlreadyInitialized)?;
        return Ok(TelemetryGuard::default());
    };

    let provider = build_provider(&settings.service_name, endpoint)?;
    let tracer = provider.tracer(settings.service_name.clone());
    opentelemetry::global::set_tracer_provider(provider.clone());

    registry
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()
        .map_err(|_| TelemetryError::AlreadyInitialized)?;

    Ok(TelemetryGuard {
        provider: Some(provider),
    })
}

/// Builds a batching OTLP/gRPC tracer provider tagged with the service name.
fn build_provider(service_name: &str, endpoint: &str) -> Result<SdkTracerProvider, TelemetryError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let resource = Resource::builder()
        .with_service_name(service_name.to_owned())
        .build();

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    Ok(provider)
}
