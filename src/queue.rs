use crate::error::AppError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum Job {
    SendEmail { to: String, template: String },
    AuditEvent { actor_id: Uuid, action: String },
}

impl Job {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SendEmail { .. } => "send_email",
            Self::AuditEvent { .. } => "audit_event",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct JobEnvelope {
    pub id: Uuid,
    pub kind: String,
    pub payload: Job,
    pub attempt: u16,
    pub max_attempts: u16,
    pub enqueued_at: DateTime<Utc>,
}

impl JobEnvelope {
    pub fn new(job: Job) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind: job.kind().to_owned(),
            payload: job,
            attempt: 0,
            max_attempts: 3,
            enqueued_at: Utc::now(),
        }
    }
}

#[async_trait]
pub trait Queue: Send + Sync {
    async fn enqueue(&self, job: Job) -> Result<JobEnvelope, AppError>;
}

#[derive(Clone)]
pub struct RedisQueue {
    manager: ConnectionManager,
    key: String,
}

impl RedisQueue {
    pub fn new(manager: ConnectionManager, key: String) -> Self {
        Self { manager, key }
    }
}

#[async_trait]
impl Queue for RedisQueue {
    async fn enqueue(&self, job: Job) -> Result<JobEnvelope, AppError> {
        let envelope = JobEnvelope::new(job);
        let serialized = serde_json::to_string(&envelope)?;
        let mut manager = self.manager.clone();
        // LPUSH + a worker-side BRPOP provides FIFO delivery with a minimal,
        // inspectable message contract. A worker owns retries and dead-lettering.
        let _: usize = manager.lpush(&self.key, serialized).await?;
        Ok(envelope)
    }
}

#[derive(Clone, Default)]
pub struct MemoryQueue {
    jobs: Arc<RwLock<Vec<JobEnvelope>>>,
}

impl MemoryQueue {
    pub async fn jobs(&self) -> Vec<JobEnvelope> {
        self.jobs.read().await.clone()
    }
}

#[async_trait]
impl Queue for MemoryQueue {
    async fn enqueue(&self, job: Job) -> Result<JobEnvelope, AppError> {
        let envelope = JobEnvelope::new(job);
        self.jobs.write().await.push(envelope.clone());
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
