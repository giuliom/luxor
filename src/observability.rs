//! Logging, tracing, and error reporting.
//!
//! Logs are always on: compact in development and test, JSON in production.
//! With the `otel` feature the tracer is on too — finished spans feed a bounded
//! in-process `TraceStore` and, when an OTLP endpoint is configured, are
//! batch-exported over OTLP/gRPC. With the `sentry` feature, server errors are
//! reported to Sentry when a DSN is configured.

use crate::config::{Config, ConfigError, Env, Environment};
use anyhow::{Context, Result};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[cfg(feature = "otel")]
pub use trace_store::{StoredSpan, TraceStore};

/// The `RUST_LOG` filter used when none is set: this crate at `info`, the
/// dependencies at the level that keeps their noise out of a normal run.
const DEFAULT_LOG_FILTER: &str = concat!(
    env!("CARGO_CRATE_NAME"),
    "=info,tower_http=info,sqlx=warn,redis=warn,librdkafka=warn"
);

#[derive(Clone, Debug, Default)]
pub struct TelemetrySettings {
    /// OTLP/gRPC collector address; `None` keeps spans in-process only.
    #[cfg(feature = "otel")]
    pub otlp_endpoint: Option<String>,
    /// The `service.name` resource attribute; `APP_NAME` unless
    /// `OTEL_SERVICE_NAME` says otherwise.
    #[cfg(feature = "otel")]
    pub service_name: String,
    #[cfg(feature = "sentry")]
    pub sentry_dsn: Option<secrecy::SecretString>,
}

impl TelemetrySettings {
    #[cfg_attr(
        not(any(feature = "otel", feature = "sentry")),
        allow(unused_variables)
    )]
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        #[cfg(feature = "otel")]
        let otlp_endpoint = env.optional("OTEL_EXPORTER_OTLP_ENDPOINT");
        #[cfg(feature = "otel")]
        if let Some(endpoint) = &otlp_endpoint {
            crate::config::parse_url("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint, &["http", "https"])?;
        }
        #[cfg(feature = "sentry")]
        let sentry_dsn = env.optional("SENTRY_DSN");
        #[cfg(feature = "sentry")]
        if let Some(dsn) = &sentry_dsn {
            dsn.parse::<sentry::types::Dsn>()
                .map_err(|error| ConfigError::Invalid("SENTRY_DSN", error.to_string()))?;
        }
        Ok(Self {
            #[cfg(feature = "otel")]
            otlp_endpoint,
            #[cfg(feature = "otel")]
            service_name: env
                .optional("OTEL_SERVICE_NAME")
                .unwrap_or_else(|| env.app_name().to_owned()),
            #[cfg(feature = "sentry")]
            sentry_dsn: sentry_dsn.map(secrecy::SecretString::from),
        })
    }
}

/// Keeps the exporters alive; [`Observability::shutdown`] flushes them.
pub struct Observability {
    #[cfg(feature = "otel")]
    trace_store: TraceStore,
    #[cfg(feature = "sentry")]
    sentry: Option<sentry::ClientInitGuard>,
}

impl Observability {
    /// The in-process store finished spans are recorded into.
    #[cfg(feature = "otel")]
    pub fn trace_store(&self) -> TraceStore {
        self.trace_store.clone()
    }

    pub fn shutdown(self) {
        #[cfg(feature = "otel")]
        opentelemetry::global::shutdown_tracer_provider();
        #[cfg(feature = "sentry")]
        drop(self.sentry);
    }
}

pub fn init(config: &Config) -> Result<Observability> {
    #[cfg(feature = "sentry")]
    let sentry = init_sentry(config);
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));

    let registry = tracing_subscriber::registry().with(filter);
    #[cfg(feature = "otel")]
    let trace_store = TraceStore::default();
    #[cfg(feature = "otel")]
    let registry = registry.with(
        tracing_opentelemetry::layer().with_tracer(tracer::build(&config.telemetry, &trace_store)?),
    );

    match &config.environment {
        Environment::Production => registry
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()
            .context("global tracing subscriber was already initialized")?,
        _ => registry
            .with(tracing_subscriber::fmt::layer().compact())
            .try_init()
            .context("global tracing subscriber was already initialized")?,
    }

    Ok(Observability {
        #[cfg(feature = "otel")]
        trace_store,
        #[cfg(feature = "sentry")]
        sentry,
    })
}

#[cfg(feature = "sentry")]
fn init_sentry(config: &Config) -> Option<sentry::ClientInitGuard> {
    use secrecy::ExposeSecret;

    config.telemetry.sentry_dsn.as_ref().map(|dsn| {
        // Configuration parsing already rejected invalid DSNs.
        let dsn = dsn
            .expose_secret()
            .parse::<sentry::types::Dsn>()
            .expect("SENTRY_DSN is validated when the configuration is loaded");
        sentry::init((
            dsn,
            sentry::ClientOptions {
                release: sentry::release_name!(),
                environment: Some(config.environment.as_str().into()),
                ..Default::default()
            },
        ))
    })
}

#[cfg(feature = "otel")]
mod tracer {
    use super::{TelemetrySettings, TraceStore};
    use anyhow::{Context, Result};
    use opentelemetry::{
        global, propagation::TextMapCompositePropagator, trace::TracerProvider as _, KeyValue,
    };
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{
        export::trace::{ExportResult, SpanData},
        propagation::{BaggagePropagator, TraceContextPropagator},
        Resource,
    };
    use std::{future::Future, pin::Pin};

    /// Builds the tracer pipeline. Finished spans always feed the in-process
    /// trace store; when an OTLP endpoint is configured they are additionally
    /// batch-exported over OTLP/gRPC.
    pub(super) fn build(
        settings: &TelemetrySettings,
        trace_store: &TraceStore,
    ) -> Result<opentelemetry_sdk::trace::Tracer> {
        global::set_text_map_propagator(TextMapCompositePropagator::new(vec![
            Box::new(TraceContextPropagator::new()),
            Box::new(BaggagePropagator::new()),
        ]));
        let resource = Resource::default().merge(&Resource::new(vec![KeyValue::new(
            "service.name",
            settings.service_name.clone(),
        )]));
        let mut builder = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_config(opentelemetry_sdk::trace::Config::default().with_resource(resource))
            .with_simple_exporter(TraceStoreExporter {
                store: trace_store.clone(),
            });
        if let Some(endpoint) = settings.otlp_endpoint.as_deref() {
            let exporter = opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint)
                .build_span_exporter()
                .context("failed to initialize OTLP tracing")?;
            builder = builder.with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio);
        }
        let provider = builder.build();
        let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
        global::set_tracer_provider(provider);
        Ok(tracer)
    }

    #[derive(Debug)]
    struct TraceStoreExporter {
        store: TraceStore,
    }

    impl opentelemetry_sdk::export::trace::SpanExporter for TraceStoreExporter {
        fn export(
            &mut self,
            batch: Vec<SpanData>,
        ) -> Pin<Box<dyn Future<Output = ExportResult> + Send + 'static>> {
            for span in &batch {
                self.store.record(super::StoredSpan::from(span));
            }
            Box::pin(std::future::ready(Ok(())))
        }
    }
}

#[cfg(feature = "otel")]
mod trace_store {
    use opentelemetry::trace::{SpanKind, Status};
    use opentelemetry_sdk::export::trace::SpanData;
    use serde::Serialize;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex, PoisonError},
        time::{SystemTime, UNIX_EPOCH},
    };

    /// Upper bound on retained spans; the oldest spans are dropped first.
    const TRACE_STORE_CAPACITY: usize = 512;

    /// Compact summary of a finished span, kept for the browser console's
    /// trace visualizer. Attribute values are deliberately not retained.
    #[derive(Clone, Debug, Serialize)]
    pub struct StoredSpan {
        pub trace_id: String,
        pub span_id: String,
        pub parent_span_id: Option<String>,
        pub name: String,
        pub kind: &'static str,
        pub status: &'static str,
        pub start_unix_ms: f64,
        pub duration_ms: f64,
    }

    impl From<&SpanData> for StoredSpan {
        fn from(span: &SpanData) -> Self {
            Self {
                trace_id: span.span_context.trace_id().to_string(),
                span_id: span.span_context.span_id().to_string(),
                parent_span_id: (span.parent_span_id != opentelemetry::trace::SpanId::INVALID)
                    .then(|| span.parent_span_id.to_string()),
                name: span.name.to_string(),
                kind: match span.span_kind {
                    SpanKind::Client => "client",
                    SpanKind::Server => "server",
                    SpanKind::Producer => "producer",
                    SpanKind::Consumer => "consumer",
                    SpanKind::Internal => "internal",
                },
                status: match span.status {
                    Status::Unset => "unset",
                    Status::Ok => "ok",
                    Status::Error { .. } => "error",
                },
                start_unix_ms: unix_ms(span.start_time),
                duration_ms: span
                    .end_time
                    .duration_since(span.start_time)
                    .unwrap_or_default()
                    .as_secs_f64()
                    * 1000.0,
            }
        }
    }

    fn unix_ms(time: SystemTime) -> f64 {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
            * 1000.0
    }

    /// Bounded in-process store of finished spans, which the browser console
    /// renders as a waterfall without an external collector.
    #[derive(Clone, Debug, Default)]
    pub struct TraceStore {
        spans: Arc<Mutex<VecDeque<StoredSpan>>>,
    }

    impl TraceStore {
        pub fn record(&self, span: StoredSpan) {
            let mut spans = self.spans.lock().unwrap_or_else(PoisonError::into_inner);
            if spans.len() == TRACE_STORE_CAPACITY {
                spans.pop_front();
            }
            spans.push_back(span);
        }

        /// Returns the trace's retained spans ordered by start time.
        pub fn trace(&self, trace_id: &str) -> Vec<StoredSpan> {
            let spans = self.spans.lock().unwrap_or_else(PoisonError::into_inner);
            let mut spans = spans
                .iter()
                .filter(|span| span.trace_id == trace_id)
                .cloned()
                .collect::<Vec<_>>();
            spans.sort_by(|a, b| a.start_unix_ms.total_cmp(&b.start_unix_ms));
            spans
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "otel", feature = "sentry"))]
    use crate::testing::values;

    #[test]
    fn the_default_log_filter_names_this_crate() {
        assert!(DEFAULT_LOG_FILTER.starts_with(concat!(env!("CARGO_CRATE_NAME"), "=info,")));
        assert!(EnvFilter::try_new(DEFAULT_LOG_FILTER).is_ok());
    }

    #[cfg(feature = "otel")]
    #[test]
    fn the_service_name_defaults_to_the_application_name() {
        let default = TelemetrySettings::from_env(&Env::new(values(&[])).unwrap()).unwrap();
        assert_eq!(default.service_name, env!("CARGO_PKG_NAME"));
        assert!(default.otlp_endpoint.is_none());

        let named =
            TelemetrySettings::from_env(&Env::new(values(&[("APP_NAME", "orders-api")])).unwrap())
                .unwrap();
        assert_eq!(named.service_name, "orders-api");

        let explicit = TelemetrySettings::from_env(
            &Env::new(values(&[("OTEL_SERVICE_NAME", "checkout-api")])).unwrap(),
        )
        .unwrap();
        assert_eq!(explicit.service_name, "checkout-api");
    }

    #[cfg(feature = "otel")]
    #[test]
    fn otlp_endpoints_must_be_http_urls() {
        let outcome = TelemetrySettings::from_env(
            &Env::new(values(&[(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "grpc://collector:4317",
            )]))
            .unwrap(),
        );
        assert!(matches!(
            outcome,
            Err(ConfigError::Invalid("OTEL_EXPORTER_OTLP_ENDPOINT", _))
        ));
    }

    #[cfg(feature = "sentry")]
    #[test]
    fn sentry_dsns_are_validated() {
        let outcome =
            TelemetrySettings::from_env(&Env::new(values(&[("SENTRY_DSN", "not a dsn")])).unwrap());
        assert!(matches!(
            outcome,
            Err(ConfigError::Invalid("SENTRY_DSN", _))
        ));
    }
}
