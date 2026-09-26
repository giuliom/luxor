//! Domain events on a stream.
//!
//! One stream carries everything the application announces about itself. The
//! events are the application's own type ([`crate::app::events::DomainEvent`]);
//! this module is the transport, and requires only that the type is an
//! [`Event`]. A publisher turns an event into an [`EventEnvelope`] — a
//! versioned, self-describing JSON record — and a consumer reads the stream
//! back and hands each event to the application's [`EventHandler`].
//!
//! Three decisions shape the contract:
//!
//! * **Every event carries a key**, and the key is the identifier the event is
//!   about. Kafka orders records within a partition and derives the partition
//!   from the key, so all events about one user or one job stay in order
//!   relative to each other no matter how many partitions the topic has or how
//!   many instances publish to it.
//! * **The producer is idempotent** (`enable.idempotence`), which pins
//!   `acks=all` and lets librdkafka retry a publish without risking a duplicate
//!   or a reordering on the partition.
//! * **Offsets are committed by this application, after the handler has
//!   returned**, never by librdkafka's auto-commit timer. That makes delivery
//!   at-least-once: a crash between handling and committing replays the event,
//!   which is the failure mode a consumer can actually defend against, unlike
//!   the silent loss auto-commit produces.
//!
//! Publishing is a network call to another system, so it can fail while the
//! request that triggered it succeeds. [`publish_or_log`] is the deliberate
//! at-most-once path for that case: the event is dropped and recorded, rather
//! than failing a registration because a broker was briefly unreachable. A
//! system that cannot tolerate a lost event needs the transactional outbox
//! pattern — write the event to the database inside the same transaction as the
//! state change, and relay it from there — which is a larger commitment than
//! this boundary makes.
//!
//! Without `KAFKA_BROKERS`, or in a build without the `kafka` feature, the same
//! publish and consume paths run over an in-process [`MemoryEventBus`], so the
//! whole flow works with nothing installed. It is a stand-in, not a broker: no
//! persistence, no partitions, no delivery to any other instance.

use crate::{
    access::Role,
    error::AppError,
    tasks::{Shutdown, ShutdownTrigger},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fmt::Debug,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::Duration,
};
use tokio::{sync::broadcast, task::JoinHandle};
use uuid::Uuid;

#[cfg(feature = "kafka")]
pub mod kafka;

/// Version of the envelope shape. Consumers keep working when a payload gains
/// a field; they can refuse a version they were not written for.
pub const EVENT_SCHEMA_VERSION: u16 = 1;

/// Upper bound on the events an [`EventLog`] keeps. The stream is the record;
/// the log is a window onto its tail, and the oldest entry is dropped first.
const EVENT_LOG_CAPACITY: usize = 100;

/// Events buffered per subscriber of the in-process bus.
const MEMORY_BUS_CAPACITY: usize = 256;

/// How long [`ConsumerTask::stop`] gives a consumer to finish its current
/// event and commit before it stops waiting for it.
const CONSUMER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// What an event type must provide to travel on the stream.
///
/// Serialize it with a `kind` discriminator that reads as an event name rather
/// than a Rust variant (`#[serde(tag = "kind", content = "payload")]` with
/// renamed variants), because the stream is a contract with consumers that are
/// not this codebase.
pub trait Event: Clone + Debug + Serialize + DeserializeOwned + Send + Sync + 'static {
    /// The event's name on the stream, such as `user.registered`.
    fn kind(&self) -> &'static str;

    /// The identifier this event is about, which is also its partition key.
    fn key(&self) -> String;
}

/// Announced by the foundation when an account is created. The application's
/// event type carries it through `From<UserRegistered>`. It deliberately has
/// no email: a stream is read by more consumers than the account holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserRegistered {
    pub user_id: Uuid,
    pub role: Role,
}

/// One event as it sits on the stream: `{id, schema_version, key, occurred_at,
/// kind, payload}`, where `kind` and `payload` come from the flattened event
/// itself, so a consumer switches on one field and reads the rest under it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct EventEnvelope<E> {
    pub id: Uuid,
    pub schema_version: u16,
    /// The partition key, repeated inside the record so an event read from a
    /// dump or a dead-letter topic still says what it is about.
    pub key: String,
    pub occurred_at: DateTime<Utc>,
    #[serde(flatten)]
    pub payload: E,
}

impl<E: Event> EventEnvelope<E> {
    pub fn new(payload: E) -> Self {
        Self {
            id: Uuid::new_v4(),
            schema_version: EVENT_SCHEMA_VERSION,
            key: payload.key(),
            occurred_at: Utc::now(),
            payload,
        }
    }

    pub fn kind(&self) -> &'static str {
        self.payload.kind()
    }
}

/// Where a published event landed. The partition and offset are the broker's
/// receipt: they name the exact position the record occupies.
#[derive(Clone, Debug, Serialize)]
pub struct PublishReceipt<E> {
    pub partition: i32,
    pub offset: i64,
    #[serde(flatten)]
    pub envelope: EventEnvelope<E>,
}

/// An event as it came back off the stream, with the coordinates the broker
/// assigned it.
#[derive(Clone, Debug, Serialize)]
pub struct ConsumedEvent<E> {
    pub partition: i32,
    pub offset: i64,
    pub consumed_at: DateTime<Utc>,
    #[serde(flatten)]
    pub envelope: EventEnvelope<E>,
}

#[async_trait]
pub trait EventPublisher<E: Event>: Send + Sync {
    async fn publish(&self, event: E) -> Result<PublishReceipt<E>, AppError>;

    /// Which backend is carrying events: `kafka` or `memory`.
    fn backend(&self) -> &'static str;
}

/// Publishes an event that must not be able to fail its caller.
///
/// The state change has already happened — the account exists, the job is
/// queued — so a broker that is unreachable must not turn a successful request
/// into an error. The event is lost and said to be lost; see the module
/// documentation for what closing that gap costs.
pub async fn publish_or_log<E: Event>(publisher: &dyn EventPublisher<E>, event: E) {
    let kind = event.kind();
    if let Err(error) = publisher.publish(event).await {
        tracing::warn!(
            event.kind = kind,
            ?error,
            "a domain event was not published"
        );
    }
}

/// Receives every event the consumer reads.
///
/// The event's offset is committed once `handle` returns, so a crash while
/// handling replays it (at-least-once delivery) and a handler must tolerate
/// seeing an event twice. Returning acknowledges the event: a handler that
/// cannot process one retries, dead-letters, or logs it before it returns.
#[async_trait]
pub trait EventHandler<E: Event>: Send + Sync + 'static {
    async fn handle(&self, event: ConsumedEvent<E>);
}

#[async_trait]
impl<E, H> EventHandler<E> for Arc<H>
where
    E: Event,
    H: EventHandler<E> + ?Sized,
{
    async fn handle(&self, event: ConsumedEvent<E>) {
        self.as_ref().handle(event).await;
    }
}

/// The in-process stand-in used when no brokers are configured.
///
/// It preserves the shape of the contract — every event is published, keyed,
/// numbered, and consumed by the same handler — and none of the guarantees:
/// nothing is persisted, there is one partition because there is one process,
/// and an event reaches no other instance.
#[derive(Clone)]
pub struct MemoryEventBus<E> {
    events: broadcast::Sender<ConsumedEvent<E>>,
    next_offset: Arc<AtomicI64>,
}

impl<E: Event> Default for MemoryEventBus<E> {
    fn default() -> Self {
        let (events, _receiver) = broadcast::channel(MEMORY_BUS_CAPACITY);
        Self {
            events,
            next_offset: Arc::new(AtomicI64::new(0)),
        }
    }
}

impl<E: Event> MemoryEventBus<E> {
    /// The consumer side of this bus. Only events published after this call
    /// reach it.
    pub fn source(&self) -> EventSource<E> {
        EventSource(Source::Memory(self.events.subscribe()))
    }
}

#[async_trait]
impl<E: Event> EventPublisher<E> for MemoryEventBus<E> {
    async fn publish(&self, event: E) -> Result<PublishReceipt<E>, AppError> {
        let envelope = EventEnvelope::new(event);
        let offset = self.next_offset.fetch_add(1, Ordering::SeqCst);
        // Delivery is what a broker would do next, so the receipt is complete
        // before any subscriber has run.
        let _ = self.events.send(ConsumedEvent {
            partition: 0,
            offset,
            consumed_at: Utc::now(),
            envelope: envelope.clone(),
        });
        Ok(PublishReceipt {
            partition: 0,
            offset,
            envelope,
        })
    }

    fn backend(&self) -> &'static str {
        "memory"
    }
}

/// A bounded in-process view of the tail of the stream: an [`EventHandler`]
/// that keeps the most recent events.
#[derive(Clone, Debug)]
pub struct EventLog<E> {
    inner: Arc<Mutex<EventLogInner<E>>>,
}

#[derive(Debug)]
struct EventLogInner<E> {
    events: VecDeque<ConsumedEvent<E>>,
    /// Every event this process has consumed, including those already dropped
    /// from the window.
    consumed: u64,
}

impl<E> Default for EventLog<E> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventLogInner {
                events: VecDeque::new(),
                consumed: 0,
            })),
        }
    }
}

impl<E: Clone> EventLog<E> {
    pub fn record(&self, event: ConsumedEvent<E>) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.events.len() == EVENT_LOG_CAPACITY {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
        inner.consumed += 1;
    }

    /// The most recent events, newest first.
    pub fn recent(&self, limit: usize) -> Vec<ConsumedEvent<E>> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.events.iter().rev().take(limit).cloned().collect()
    }

    /// How many events this process has consumed since it started.
    pub fn consumed(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .consumed
    }
}

#[async_trait]
impl<E: Event> EventHandler<E> for EventLog<E> {
    async fn handle(&self, event: ConsumedEvent<E>) {
        self.record(event);
    }
}

/// The stream a consumer reads, whichever backend is carrying it.
pub struct EventSource<E>(Source<E>);

enum Source<E> {
    // Boxed because a StreamConsumer is an order of magnitude larger than a
    // channel receiver, and this value is moved into the consumer task.
    #[cfg(feature = "kafka")]
    Kafka(Box<rdkafka::consumer::StreamConsumer<kafka::KafkaContext>>),
    Memory(broadcast::Receiver<ConsumedEvent<E>>),
}

/// Reads `source` until `shutdown` fires, handing every event to `handler`.
pub async fn consume<E, H>(source: EventSource<E>, handler: H, mut shutdown: Shutdown)
where
    E: Event,
    H: EventHandler<E>,
{
    match source.0 {
        #[cfg(feature = "kafka")]
        Source::Kafka(consumer) => kafka::consume(&consumer, &handler, shutdown).await,
        Source::Memory(mut events) => loop {
            tokio::select! {
                biased;
                _ = shutdown.requested() => break,
                received = events.recv() => match received {
                    Ok(event) => handler.handle(event).await,
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "the in-process event bus dropped events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
        },
    }
}

/// A consumer running on its own, which stops when its handle is stopped.
pub struct ConsumerTask {
    trigger: ShutdownTrigger,
    task: JoinHandle<()>,
}

impl ConsumerTask {
    /// Asks the consumer to finish the event in flight, commit it, and stop.
    ///
    /// Waiting is bounded: a consumer blocked on an unreachable broker must not
    /// hold up the shutdown of the process, and an uncommitted offset is
    /// replayed on the next start, which is exactly what at-least-once
    /// delivery promises.
    pub async fn stop(self) {
        self.trigger.fire();
        match tokio::time::timeout(CONSUMER_SHUTDOWN_TIMEOUT, self.task).await {
            Ok(_) => tracing::info!("event consumer stopped"),
            Err(_) => tracing::warn!("event consumer did not stop within its shutdown timeout"),
        }
    }
}

/// Starts consuming `source` into `handler` on a task of its own.
pub fn spawn_consumer<E, H>(source: EventSource<E>, handler: H) -> ConsumerTask
where
    E: Event,
    H: EventHandler<E>,
{
    let (trigger, shutdown) = Shutdown::channel();
    let task = tokio::spawn(consume(source, handler, shutdown));
    ConsumerTask { trigger, task }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An event type local to these tests, so the transport is exercised
    /// independently of the application's own events.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(tag = "kind", content = "payload")]
    pub(crate) enum TestEvent {
        #[serde(rename = "test.noted")]
        Noted { subject: Uuid, text: String },
    }

    impl Event for TestEvent {
        fn kind(&self) -> &'static str {
            match self {
                Self::Noted { .. } => "test.noted",
            }
        }

        fn key(&self) -> String {
            match self {
                Self::Noted { subject, .. } => subject.to_string(),
            }
        }
    }

    pub(crate) fn note(text: &str) -> TestEvent {
        TestEvent::Noted {
            subject: Uuid::new_v4(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn envelopes_are_self_describing_on_the_wire() {
        let subject = Uuid::new_v4();
        let envelope = EventEnvelope::new(TestEvent::Noted {
            subject,
            text: "hello".into(),
        });
        let value = serde_json::to_value(&envelope).unwrap();

        // The payload is nested under the event name, so a consumer can
        // switch on `kind` alone, and the key names what the event is about.
        assert_eq!(value["kind"], "test.noted");
        assert_eq!(value["schema_version"], EVENT_SCHEMA_VERSION);
        assert_eq!(value["key"], subject.to_string());
        assert_eq!(value["payload"]["text"], "hello");

        // What is published is what a consumer reads back.
        let decoded: EventEnvelope<TestEvent> = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[tokio::test]
    async fn the_memory_bus_numbers_events_and_delivers_them_to_its_consumer() {
        let bus = MemoryEventBus::default();
        let log = EventLog::default();
        let consumer = spawn_consumer(bus.source(), log.clone());

        let first = bus.publish(note("first")).await.unwrap();
        let second = bus.publish(note("second")).await.unwrap();
        assert_eq!((first.partition, first.offset), (0, 0));
        assert_eq!((second.partition, second.offset), (0, 1));

        // The consumer runs in its own task, so the log fills shortly after
        // the publish returns rather than during it.
        let recorded = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if log.consumed() == 2 {
                    return log.recent(10);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both events reach the consumer");

        // Newest first, and each carries the coordinates it was published at.
        assert_eq!(recorded[0].envelope.id, second.envelope.id);
        assert_eq!(recorded[0].offset, 1);
        assert_eq!(recorded[1].envelope.id, first.envelope.id);
        assert_eq!(recorded[1].offset, 0);

        consumer.stop().await;
    }

    /// Handlers are shared through `Arc`, including as trait objects, which is
    /// how the application hands one to the consumer.
    #[tokio::test]
    async fn a_shared_handler_receives_the_events() {
        let bus = MemoryEventBus::default();
        let log = EventLog::default();
        let handler: Arc<dyn EventHandler<TestEvent>> = Arc::new(log.clone());
        let consumer = spawn_consumer(bus.source(), handler);

        bus.publish(note("shared")).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while log.consumed() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the event reaches the shared handler");
        consumer.stop().await;
    }

    #[test]
    fn the_event_log_keeps_the_newest_events_and_counts_all_of_them() {
        let log = EventLog::default();
        for offset in 0..(EVENT_LOG_CAPACITY as i64 + 10) {
            log.record(ConsumedEvent {
                partition: 0,
                offset,
                consumed_at: Utc::now(),
                envelope: EventEnvelope::new(note("filler")),
            });
        }

        let recent = log.recent(EVENT_LOG_CAPACITY * 2);
        assert_eq!(recent.len(), EVENT_LOG_CAPACITY);
        // The window slid: the newest event is present and the first ones are
        // gone, while the total still counts them.
        assert_eq!(recent[0].offset, EVENT_LOG_CAPACITY as i64 + 9);
        assert_eq!(recent[EVENT_LOG_CAPACITY - 1].offset, 10);
        assert_eq!(log.consumed(), EVENT_LOG_CAPACITY as u64 + 10);
    }

    #[tokio::test]
    async fn a_failed_publish_never_fails_its_caller() {
        struct BrokenPublisher;

        #[async_trait]
        impl EventPublisher<TestEvent> for BrokenPublisher {
            async fn publish(
                &self,
                _event: TestEvent,
            ) -> Result<PublishReceipt<TestEvent>, AppError> {
                Err(AppError::Internal)
            }

            fn backend(&self) -> &'static str {
                "broken"
            }
        }

        // The state change this event describes has already happened; losing
        // the event must not undo it.
        publish_or_log(&BrokenPublisher, note("dropped")).await;
    }
}
