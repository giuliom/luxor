use crate::{
    auth::AuthUser,
    error::{ApiJson, AppError},
    events::{self, DomainEvent},
    queue::Job,
    state::AppState,
    validation,
};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Long enough for any descriptive template name, short enough that the value
/// cannot become a payload in its own right.
const TEMPLATE_MAX_LENGTH: usize = 64;

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
        // Both fields are validated before the job is queued rather than in
        // the worker that will one day drain it: a queue is a trust boundary
        // in only one direction, and a payload already on it is read back as
        // trusted input.
        EnqueueRequest::SendEmail { to, template } => {
            let to = to.trim().to_owned();
            validation::email(&to)?;
            validate_template(&template)?;
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
    // The queue moves work to a worker; the event tells everyone else that the
    // work exists. Losing the announcement must not un-queue the job, so it is
    // published on the best-effort path.
    events::publish_or_log(
        state.events.as_ref(),
        DomainEvent::JobEnqueued {
            job_id: envelope.id,
            job_kind: envelope.kind.clone(),
        },
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(EnqueueResponse {
            id: envelope.id,
            kind: envelope.kind,
            status: "queued",
        }),
    ))
}

/// Holds a template to a bare identifier.
///
/// A worker resolving one into a path (`templates/{template}.html`) or a
/// lookup key must not be steerable by the caller, so separators, dots, and
/// anything non-ASCII are refused rather than stripped — a filter invites the
/// question of what it missed, and no legitimate template name needs them.
fn validate_template(template: &str) -> Result<(), AppError> {
    let named = (1..=TEMPLATE_MAX_LENGTH).contains(&template.len())
        && template
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'));
    named.then_some(()).ok_or_else(|| {
        AppError::BadRequest(format!(
            "template must be 1-{TEMPLATE_MAX_LENGTH} characters of letters, digits, underscores, or hyphens"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_template_identifiers() {
        for template in ["welcome", "password_reset", "invoice-2026", "a"] {
            assert!(
                validate_template(template).is_ok(),
                "{template:?} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_templates_that_could_steer_a_worker() {
        for template in [
            "",
            "   ",
            "../../etc/passwd",
            "welcome.html",
            "templates/welcome",
            "welcome\r\nX-Injected: 1",
            "welcome email",
            &"a".repeat(TEMPLATE_MAX_LENGTH + 1),
        ] {
            assert!(
                validate_template(template).is_err(),
                "{template:?} should be rejected"
            );
        }
    }
}
