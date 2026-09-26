//! The events the application announces on the stream.
//!
//! The foundation publishes [`UserRegistered`] when an account is created, so
//! [`DomainEvent`] must be able to carry it; every other variant is the
//! application's to define. The serialized names are a contract with every
//! consumer of the stream, so a variant is renamed only by adding a new one.

use crate::{
    access::Role,
    events::{Event, UserRegistered},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Serialized with a `kind` discriminator that reads as an event name rather
/// than a Rust variant, because the stream is a contract with consumers that
/// are not this codebase.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", content = "payload")]
pub enum DomainEvent {
    #[serde(rename = "user.registered")]
    UserRegistered { user_id: Uuid, role: Role },
    #[serde(rename = "job.enqueued")]
    JobEnqueued { job_id: Uuid, job_kind: String },
    /// Published by the console, so the demo has an event a person can send on
    /// purpose and watch come back off the topic.
    #[cfg(feature = "demo")]
    #[serde(rename = "note.published")]
    Note { author_id: Uuid, text: String },
}

impl Event for DomainEvent {
    fn kind(&self) -> &'static str {
        match self {
            Self::UserRegistered { .. } => "user.registered",
            Self::JobEnqueued { .. } => "job.enqueued",
            #[cfg(feature = "demo")]
            Self::Note { .. } => "note.published",
        }
    }

    fn key(&self) -> String {
        match self {
            Self::UserRegistered { user_id, .. } => user_id.to_string(),
            Self::JobEnqueued { job_id, .. } => job_id.to_string(),
            #[cfg(feature = "demo")]
            Self::Note { author_id, .. } => author_id.to_string(),
        }
    }
}

impl From<UserRegistered> for DomainEvent {
    fn from(event: UserRegistered) -> Self {
        Self::UserRegistered {
            user_id: event.user_id,
            role: event.role,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventEnvelope;

    #[test]
    fn events_are_self_describing_on_the_wire() {
        let user_id = Uuid::new_v4();
        let envelope = EventEnvelope::new(DomainEvent::from(UserRegistered {
            user_id,
            role: Role::Admin,
        }));
        let value = serde_json::to_value(&envelope).unwrap();

        // The name on the topic is an event name, not a Rust variant, and the
        // payload is nested under it so a consumer can switch on `kind` alone.
        assert_eq!(value["kind"], "user.registered");
        assert_eq!(value["key"], user_id.to_string());
        assert_eq!(value["payload"]["user_id"], user_id.to_string());
        assert_eq!(value["payload"]["role"], "admin");

        // What is published is what a consumer reads back.
        let decoded: EventEnvelope<DomainEvent> = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, envelope);
    }

    /// The key decides the partition, and a partition is the only place Kafka
    /// orders anything, so every event about one entity has to key on that
    /// entity's identifier.
    #[test]
    fn events_are_keyed_by_what_they_are_about() {
        let user_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();

        let cases = vec![
            (
                DomainEvent::UserRegistered {
                    user_id,
                    role: Role::User,
                },
                user_id,
            ),
            (
                DomainEvent::JobEnqueued {
                    job_id,
                    job_kind: "send_email".into(),
                },
                job_id,
            ),
        ];
        #[cfg(feature = "demo")]
        let cases = {
            let author_id = Uuid::new_v4();
            let mut cases = cases;
            cases.push((
                DomainEvent::Note {
                    author_id,
                    text: "hello".into(),
                },
                author_id,
            ));
            cases
        };
        for (event, expected) in cases {
            assert_eq!(event.key(), expected.to_string(), "{}", event.kind());
            // The kind a consumer switches on is the serialized name.
            assert_eq!(serde_json::to_value(&event).unwrap()["kind"], event.kind());
        }
    }
}
