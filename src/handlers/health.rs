use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    service: String,
}

/// Liveness: the process is up and serving requests. It deliberately checks
/// no dependency, so a database blip does not get healthy instances killed.
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: state.config.app_name.clone(),
    })
}
