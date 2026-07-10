use crate::config::{Config, Environment};
use anyhow::{Context, Result};
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use secrecy::ExposeSecret;
use sentry::ClientInitGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub struct ObservabilityGuard {
    sentry: Option<ClientInitGuard>,
    otel_enabled: bool,
}

impl ObservabilityGuard {
    pub fn shutdown(self) {
        if self.otel_enabled {
            global::shutdown_tracer_provider();
        }
        drop(self.sentry);
    }
}

pub fn init(config: &Config) -> Result<ObservabilityGuard> {
    let sentry = init_sentry(config)?;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("luxor=info,tower_http=info,sqlx=warn,redis=warn"));
    let otel_tracer = config
        .otlp_endpoint
        .as_deref()
        .map(build_otlp_tracer)
        .transpose()?;
    let otel_enabled = otel_tracer.is_some();

    match (&config.environment, otel_tracer) {
        (Environment::Production, Some(tracer)) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .context("global tracing subscriber was already initialized")?,
        (Environment::Production, None) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()
            .context("global tracing subscriber was already initialized")?,
        (_, Some(tracer)) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().compact())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .context("global tracing subscriber was already initialized")?,
        (_, None) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().compact())
            .try_init()
            .context("global tracing subscriber was already initialized")?,
    }

    Ok(ObservabilityGuard {
        sentry,
        otel_enabled,
    })
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

fn build_otlp_tracer(endpoint: &str) -> Result<opentelemetry_sdk::trace::Tracer> {
    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .context("failed to initialize OTLP tracing")?;
    let tracer = provider.tracer("luxor");
    global::set_tracer_provider(provider);
    Ok(tracer)
}
