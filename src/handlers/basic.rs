use axum::{extract::Query, Json};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

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
