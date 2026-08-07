//! The event stream's two endpoints: publishing an event, and reading back
//! what this instance has consumed from the topic.
//!
//! They are deliberately not two views of the same buffer. A publish returns
//! the broker's receipt — the partition and offset the record occupies — while
//! the listing is filled by the consumer task, so an event appears there only
//! once it has genuinely travelled through the stream and come back.

use crate::{
    auth::AuthUser,
    error::{ApiJson, AppError},
    events::{ConsumedEvent, DomainEvent, PublishReceipt},
    state::AppState,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

/// Long enough for a legible note, short enough that the topic does not become
/// a place to store documents.
const NOTE_MAX_CHARACTERS: usize = 280;

/// The default and the ceiling for one page of the consumed tail.
const DEFAULT_EVENT_LIMIT: usize = 20;
const MAX_EVENT_LIMIT: usize = 100;

#[derive(Deserialize)]
pub struct PublishRequest {
    text: String,
}

#[derive(Serialize)]
pub struct PublishResponse {
    status: &'static str,
    #[serde(flatten)]
    receipt: PublishReceipt,
}

/// Publishes one note to the topic on behalf of the caller.
///
/// This is the only event a client can produce directly, and it is validated
/// here rather than in the consumer: a topic is a trust boundary in one
/// direction only, and everything read back off it — by this application or by
/// anyone else subscribed — arrives as input that has already been accepted.
pub async fn publish(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(request): ApiJson<PublishRequest>,
) -> Result<(StatusCode, Json<PublishResponse>), AppError> {
    let receipt = state
        .events
        .publish(DomainEvent::Note {
            author_id: auth.id,
            text: validate_note(&request.text)?,
        })
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(PublishResponse {
            status: "published",
            receipt,
        }),
    ))
}

#[derive(Deserialize)]
pub struct StreamQuery {
    limit: Option<usize>,
}

#[derive(Serialize)]
pub struct StreamResponse {
    backend: &'static str,
    topic: Option<String>,
    consumer_group: Option<String>,
    /// Everything this instance has consumed since it started, which exceeds
    /// `events` once the retained window has slid.
    consumed: u64,
    events: Vec<ConsumedEvent>,
}

/// Serves the tail of the stream as this instance has consumed it.
pub async fn stream(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(query): Query<StreamQuery>,
) -> Result<Json<StreamResponse>, AppError> {
    let limit = query.limit.unwrap_or(DEFAULT_EVENT_LIMIT);
    if !(1..=MAX_EVENT_LIMIT).contains(&limit) {
        return Err(AppError::BadRequest(format!(
            "limit must be between 1 and {MAX_EVENT_LIMIT}"
        )));
    }
    let kafka = state.config.kafka.as_ref();
    Ok(Json(StreamResponse {
        backend: state.events.backend(),
        topic: kafka.map(|settings| settings.topic.clone()),
        consumer_group: kafka.map(|settings| settings.consumer_group.clone()),
        consumed: state.event_log.consumed(),
        events: state.event_log.recent(limit),
    }))
}

/// Normalizes and bounds a note. Control characters are refused rather than
/// stripped: they corrupt every consumer that renders the topic into a log, a
/// terminal, or a spreadsheet, and nothing legitimate publishes them.
fn validate_note(text: &str) -> Result<String, AppError> {
    let text = text.trim();
    if text.is_empty() || text.chars().count() > NOTE_MAX_CHARACTERS {
        return Err(AppError::BadRequest(format!(
            "text must contain 1-{NOTE_MAX_CHARACTERS} characters"
        )));
    }
    if text.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "text must not contain control characters".into(),
        ));
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_are_trimmed_bounded_and_free_of_control_characters() {
        assert_eq!(validate_note("  shipped  ").unwrap(), "shipped");
        assert_eq!(
            validate_note(&"é".repeat(NOTE_MAX_CHARACTERS))
                .unwrap()
                .chars()
                .count(),
            NOTE_MAX_CHARACTERS
        );

        for rejected in [
            "",
            "   ",
            "two\nlines",
            "carriage\rreturn",
            &"a".repeat(NOTE_MAX_CHARACTERS + 1),
        ] {
            assert!(
                validate_note(rejected).is_err(),
                "{rejected:?} should be refused"
            );
        }
    }
}
