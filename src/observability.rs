use crate::config::{Config, Environment};
use anyhow::{Context, Result};
use opentelemetry::global;
use opentelemetry::propagation::TextMapCompositePropagator;
use opentelemetry::trace::{SpanKind, Status, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::export::trace::{ExportResult, SpanData};
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use opentelemetry_sdk::Resource;
use secrecy::ExposeSecret;
use sentry::ClientInitGuard;
use serde::Serialize;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Upper bound on retained spans; the oldest spans are dropped first.
const TRACE_STORE_CAPACITY: usize = 512;

/// Compact summary of a finished span, kept for the browser console's trace
/// visualizer. Attribute values are deliberately not retained.
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

/// Bounded in-process store of finished spans, consumed by the browser
/// console's `/api/telemetry/traces/{trace_id}` endpoint.
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
            self.store.record(StoredSpan::from(span));
        }
        Box::pin(std::future::ready(Ok(())))
    }
}

pub struct ObservabilityGuard {
    sentry: Option<ClientInitGuard>,
}

impl ObservabilityGuard {
    pub fn shutdown(self) {
        global::shutdown_tracer_provider();
        drop(self.sentry);
    }
}

pub fn init(config: &Config) -> Result<(ObservabilityGuard, TraceStore)> {
    let sentry = init_sentry(config)?;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("luxor=info,tower_http=info,sqlx=warn,redis=warn"));
    let trace_store = TraceStore::default();
    let tracer = build_tracer(config, &trace_store)?;

    match &config.environment {
        Environment::Production => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .context("global tracing subscriber was already initialized")?,
        _ => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().compact())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .context("global tracing subscriber was already initialized")?,
    }

    Ok((ObservabilityGuard { sentry }, trace_store))
}

fn init_sentry(config: &Config) -> Result<Option<ClientInitGuard>> {
    config
        .sentry_dsn
        .as_ref()
        .map(|dsn| {
            let dsn = dsn
                .expose_secret()
                .parse::<sentry::types::Dsn>()
                .context("invalid SENTRY_DSN")?;
            Ok(sentry::init((
                dsn,
                sentry::ClientOptions {
                    release: sentry::release_name!(),
                    environment: Some(match config.environment {
                        Environment::Development => "development".into(),
                        Environment::Test => "test".into(),
                        Environment::Production => "production".into(),
                    }),
                    ..Default::default()
                },
            )))
        })
        .transpose()
}

/// Builds the tracer pipeline. Finished spans always feed the in-process
/// trace store consumed by the browser console; when an OTLP endpoint is
/// configured they are additionally batch-exported over OTLP/gRPC.
fn build_tracer(
    config: &Config,
    trace_store: &TraceStore,
) -> Result<opentelemetry_sdk::trace::Tracer> {
    global::set_text_map_propagator(TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ]));
    let resource = Resource::default().merge(&Resource::new(vec![KeyValue::new(
        "service.name",
        config.otel_service_name.clone(),
    )]));
    let mut builder = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_config(opentelemetry_sdk::trace::Config::default().with_resource(resource))
        .with_simple_exporter(TraceStoreExporter {
            store: trace_store.clone(),
        });
    if let Some(endpoint) = config.otlp_endpoint.as_deref() {
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint)
            .build_span_exporter()
            .context("failed to initialize OTLP tracing")?;
        builder = builder.with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio);
    }
    let provider = builder.build();
    let tracer = provider.tracer("luxor");
    global::set_tracer_provider(provider);
    Ok(tracer)
}
