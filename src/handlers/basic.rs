use crate::{error::AppError, observability::StoredSpan, state::AppState};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::{SecondsFormat, Utc};
use opentelemetry::trace::TraceContextExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "luxor",
    })
}

#[derive(Serialize)]
pub struct RuntimeResponse {
    database: &'static str,
    cache: &'static str,
    queue: &'static str,
}

pub async fn runtime(State(state): State<AppState>) -> Json<RuntimeResponse> {
    let database = if state.config.database_url.is_some() {
        "postgresql"
    } else {
        "embedded-postgresql"
    };
    let (cache, queue) = if state.config.redis_url.is_some() {
        ("redis", "redis")
    } else {
        ("memory", "memory")
    };
    Json(RuntimeResponse {
        database,
        cache,
        queue,
    })
}

#[derive(Deserialize)]
pub struct HelloParams {
    name: Option<String>,
}

#[derive(Serialize)]
pub struct HelloResponse {
    message: String,
}

pub async fn hello(Query(params): Query<HelloParams>) -> Json<HelloResponse> {
    let name = params
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("world");
    Json(HelloResponse {
        message: format!("Hello, {name}!"),
    })
}

#[derive(Serialize)]
pub struct TimeResponse {
    server_time: String,
}

pub async fn time() -> Json<TimeResponse> {
    Json(TimeResponse {
        server_time: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

#[derive(Serialize)]
pub struct TelemetryDemoResponse {
    otlp_enabled: bool,
    service_name: String,
    request_id: Option<String>,
    trace_id: Option<String>,
    span_id: Option<String>,
    sampled: Option<bool>,
}

#[tracing::instrument(
    name = "telemetry_demo",
    skip(state, headers),
    fields(otel.kind = "internal", demo.source = "browser_console")
)]
pub async fn telemetry_demo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<TelemetryDemoResponse> {
    let prepare = async {
        tokio::time::sleep(Duration::from_millis(12)).await;
        tracing::info!(demo.step = "prepare", "telemetry demo step completed");
    }
    .instrument(tracing::info_span!(
        "telemetry_demo.prepare",
        otel.kind = "internal"
    ));
    let render = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tracing::info!(demo.step = "render", "telemetry demo step completed");
    }
    .instrument(tracing::info_span!(
        "telemetry_demo.render",
        otel.kind = "internal"
    ));
    tokio::join!(prepare, render);

    let (trace_id, span_id, sampled) = current_trace_context();
    Json(TelemetryDemoResponse {
        otlp_enabled: state.config.otlp_endpoint.is_some(),
        service_name: state.config.otel_service_name.clone(),
        request_id: headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
        trace_id,
        span_id,
        sampled,
    })
}

#[derive(Serialize)]
pub struct TraceResponse {
    trace_id: String,
    spans: Vec<StoredSpan>,
}

/// Serves the spans captured in-process for one trace, so the browser console
/// can render a waterfall without an external collector.
pub async fn trace(
    State(state): State<AppState>,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceResponse>, AppError> {
    let trace_id = trace_id.to_ascii_lowercase();
    if trace_id.len() != 32 || !trace_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "trace id must be 32 hexadecimal characters".into(),
        ));
    }
    let spans = state.trace_store.trace(&trace_id);
    if spans.is_empty() {
        return Err(AppError::NotFound("trace"));
    }
    Ok(Json(TraceResponse { trace_id, spans }))
}

fn current_trace_context() -> (Option<String>, Option<String>, Option<bool>) {
    let context = tracing::Span::current().context();
    let span = context.span();
    let span_context = span.span_context();
    if span_context.is_valid() {
        (
            Some(span_context.trace_id().to_string()),
            Some(span_context.span_id().to_string()),
            Some(span_context.is_sampled()),
        )
    } else {
        (None, None, None)
    }
}
