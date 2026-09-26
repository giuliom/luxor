//! The jobs the application hands to a worker.
//!
//! Each variant is a contract with the worker that drains the queue, which
//! reads the payload back as trusted input — so everything a job carries is
//! validated before it is enqueued. The two jobs here are provider-neutral
//! examples; nothing in this repository sends email.

use crate::queue::JobPayload;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum Job {
    SendEmail { to: String, template: String },
    AuditEvent { actor_id: Uuid, action: String },
}

impl JobPayload for Job {
    fn kind(&self) -> &'static str {
        match self {
            Self::SendEmail { .. } => "send_email",
            Self::AuditEvent { .. } => "audit_event",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::JobEnvelope;

    #[test]
    fn envelope_has_a_stable_serialized_contract() {
        let envelope = JobEnvelope::new(Job::SendEmail {
            to: "person@example.com".into(),
            template: "welcome".into(),
        });
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(value["kind"], "send_email");
        assert_eq!(value["attempt"], 0);
        assert_eq!(value["max_attempts"], 3);
        assert_eq!(value["payload"]["kind"], "send_email");
    }

    #[test]
    fn kinds_match_the_serialized_names() {
        for job in [
            Job::SendEmail {
                to: "person@example.com".into(),
                template: "welcome".into(),
            },
            Job::AuditEvent {
                actor_id: Uuid::new_v4(),
                action: "signed_in".into(),
            },
        ] {
            assert_eq!(serde_json::to_value(&job).unwrap()["kind"], job.kind());
        }
    }
}
