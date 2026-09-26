//! The job queue: an enqueue-only boundary to a worker that runs elsewhere.
//!
//! Jobs are the application's own type ([`crate::app::jobs::Job`]); this
//! module only requires it to be a [`JobPayload`] and wraps each one in a
//! [`JobEnvelope`], the version-stable record a worker reads.

use crate::{config::Env, error::AppError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
#[cfg(feature = "redis")]
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt::Debug, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct QueueSettings {
    /// The Redis list jobs are pushed to; `<APP_NAME>:queue:jobs` unless
    /// `QUEUE_KEY` says otherwise.
    pub key: String,
}

impl QueueSettings {
    pub fn from_env(env: &Env) -> Self {
        Self {
            key: env
                .optional("QUEUE_KEY")
                .unwrap_or_else(|| format!("{}:queue:jobs", env.app_name())),
        }
    }
}

/// What a job type must provide to travel through the queue.
///
/// The worker that drains the queue reads the payload back as trusted input,
/// so everything a job carries is validated before it is enqueued.
pub trait JobPayload: Clone + Debug + Serialize + DeserializeOwned + Send + Sync + 'static {
    /// The job's stable name, repeated in the envelope so a worker can route
    /// on it without decoding the payload.
    fn kind(&self) -> &'static str;
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct JobEnvelope<J> {
    pub id: Uuid,
    pub kind: String,
    pub payload: J,
    pub attempt: u16,
    pub max_attempts: u16,
    pub enqueued_at: DateTime<Utc>,
}

impl<J: JobPayload> JobEnvelope<J> {
    pub fn new(job: J) -> Self {
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
pub trait Queue<J: JobPayload>: Send + Sync {
    async fn enqueue(&self, job: J) -> Result<JobEnvelope<J>, AppError>;
}

#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisQueue {
    manager: ConnectionManager,
    key: String,
}

#[cfg(feature = "redis")]
impl RedisQueue {
    pub fn new(manager: ConnectionManager, key: String) -> Self {
        Self { manager, key }
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl<J: JobPayload> Queue<J> for RedisQueue {
    async fn enqueue(&self, job: J) -> Result<JobEnvelope<J>, AppError> {
        let envelope = JobEnvelope::new(job);
        let serialized = serde_json::to_string(&envelope)?;
        let mut manager = self.manager.clone();
        // LPUSH + a worker-side BRPOP provides FIFO delivery with a minimal,
        // inspectable message contract. A worker owns retries and dead-lettering.
        let _: usize = manager.lpush(&self.key, serialized).await?;
        Ok(envelope)
    }
}

/// Keeps enqueued jobs in memory, for development runs and tests. Nothing
/// drains it: it is a stand-in for the contract, not a worker.
#[derive(Clone)]
pub struct MemoryQueue<J> {
    jobs: Arc<RwLock<Vec<JobEnvelope<J>>>>,
}

impl<J> Default for MemoryQueue<J> {
    fn default() -> Self {
        Self {
            jobs: Arc::default(),
        }
    }
}

impl<J: Clone> MemoryQueue<J> {
    pub async fn jobs(&self) -> Vec<JobEnvelope<J>> {
        self.jobs.read().await.clone()
    }
}

#[async_trait]
impl<J: JobPayload> Queue<J> for MemoryQueue<J> {
    async fn enqueue(&self, job: J) -> Result<JobEnvelope<J>, AppError> {
        let envelope = JobEnvelope::new(job);
        self.jobs.write().await.push(envelope.clone());
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
    enum TestJob {
        Reindex { shard: u16 },
    }

    impl JobPayload for TestJob {
        fn kind(&self) -> &'static str {
            match self {
                Self::Reindex { .. } => "reindex",
            }
        }
    }

    #[test]
    fn envelope_has_a_stable_serialized_contract() {
        let envelope = JobEnvelope::new(TestJob::Reindex { shard: 3 });
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(value["kind"], "reindex");
        assert_eq!(value["attempt"], 0);
        assert_eq!(value["max_attempts"], 3);
        assert_eq!(value["payload"]["kind"], "reindex");
        assert_eq!(value["payload"]["payload"]["shard"], 3);

        let decoded: JobEnvelope<TestJob> = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[tokio::test]
    async fn the_memory_queue_keeps_what_was_enqueued() {
        let queue = MemoryQueue::default();
        let envelope = queue.enqueue(TestJob::Reindex { shard: 1 }).await.unwrap();
        assert_eq!(queue.jobs().await, vec![envelope]);
    }
}
