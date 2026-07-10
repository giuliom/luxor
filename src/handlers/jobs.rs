use crate::{
    auth::AuthUser,
    error::{ApiJson, AppError},
    queue::Job,
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnqueueRequest {
    SendEmail { to: String, template: String },
    AuditEvent { action: String },
}

#[derive(Serialize)]
pub struct EnqueueResponse {
    id: Uuid,
    kind: String,
    status: &'static str,
}

pub async fn enqueue(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(request): ApiJson<EnqueueRequest>,
) -> Result<(StatusCode, Json<EnqueueResponse>), AppError> {
    let job = match request {
        EnqueueRequest::SendEmail { to, template } => {
            if !to.contains('@') || template.trim().is_empty() {
                return Err(AppError::BadRequest(
                    "a recipient and template are required".into(),
                ));
            }
            Job::SendEmail { to, template }
        }
        EnqueueRequest::AuditEvent { action } => {
            if action.trim().is_empty() || action.len() > 200 {
                return Err(AppError::BadRequest(
                    "action must contain 1-200 characters".into(),
                ));
            }
            Job::AuditEvent {
                actor_id: auth.id,
                action,
            }
        }
    };
    let envelope = state.queue.enqueue(job).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(EnqueueResponse {
            id: envelope.id,
            kind: envelope.kind,
            status: "queued",
        }),
    ))
}
