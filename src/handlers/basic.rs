use crate::state::AppState;
use axum::{extract::Query, extract::State, http::HeaderMap, Json};
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
    mode: &'static str,
    authentication: &'static str,
    cache: &'static str,
    queue: &'static str,
}

pub async fn runtime(State(state): State<AppState>) -> Json<RuntimeResponse> {
    let response = if state.config.standalone {
        RuntimeResponse {
            mode: "standalone",
            authentication: "disabled",
            cache: "memory",
            queue: "memory",
        }
    } else {
        RuntimeResponse {
            mode: "full",
            authentication: "postgresql",
            cache: "redis",
            queue: "redis",
        }
    };
    Json(response)
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
    enabled: bool,
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
        enabled: state.config.otlp_endpoint.is_some(),
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
