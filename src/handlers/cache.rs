use crate::{
    auth::AuthUser,
    error::{ApiJson, AppError},
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const DEMO_KEY: &str = "demo:value";

#[derive(Deserialize)]
pub struct CachePutRequest {
    value: Value,
    #[serde(default = "default_ttl")]
    ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    300
}

#[derive(Serialize)]
pub struct CacheResponse {
    hit: bool,
    value: Option<Value>,
}

pub async fn get_demo(
    State(state): State<AppState>,
    _auth: AuthUser,
) -> Result<Json<CacheResponse>, AppError> {
    let value = state.cache.get_json(DEMO_KEY).await?;
    Ok(Json(CacheResponse {
        hit: value.is_some(),
        value,
    }))
}

pub async fn put_demo(
    State(state): State<AppState>,
    _auth: AuthUser,
    ApiJson(request): ApiJson<CachePutRequest>,
) -> Result<Json<CacheResponse>, AppError> {
    if !(1..=86_400).contains(&request.ttl_seconds) {
        return Err(AppError::BadRequest(
            "ttl_seconds must be between 1 and 86400".into(),
        ));
    }
    state
        .cache
        .put_json(
            DEMO_KEY,
            &request.value,
            Duration::from_secs(request.ttl_seconds),
        )
        .await?;
    Ok(Json(CacheResponse {
        hit: true,
        value: Some(request.value),
    }))
}

pub async fn delete_demo(
    State(state): State<AppState>,
    _auth: AuthUser,
) -> Result<StatusCode, AppError> {
    state.cache.invalidate(DEMO_KEY).await?;
    Ok(StatusCode::NO_CONTENT)
}
