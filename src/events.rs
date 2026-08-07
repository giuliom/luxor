//! Domain events on a Kafka topic.
//!
//! One topic carries everything the application announces about itself. A
//! publisher turns a [`DomainEvent`] into an [`EventEnvelope`] — a versioned,
//! self-describing JSON record — and a consumer in the same process reads the
//! topic back into a bounded [`EventLog`] that the browser console renders. The
//! round trip is the point: what the console shows has genuinely been through
//! the broker, partition and offset included.
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
//! * **Offsets are committed by this application, after the event has been
//!   handled**, never by librdkafka's auto-commit timer. That makes delivery
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
//! Without `KAFKA_BROKERS` the same publish and consume paths run over an
//! in-process [`MemoryEventBus`], so the whole flow works with nothing
//! installed. It is a stand-in, not a broker: no persistence, no partitions, no
//! delivery to any other instance.

use crate::{config::KafkaSettings, error::AppError, models::Role};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opentelemetry::{
    global,
    propagation::{Extractor, Injector},
};
use rdkafka::{
    consumer::{CommitMode, Consumer, ConsumerContext, StreamConsumer},
    error::{KafkaError, RDKafkaErrorCode},
    message::{BorrowedMessage, Header, Headers, OwnedHeaders},
    producer::{FutureProducer, FutureRecord},
    util::Timeout,
    ClientConfig, ClientContext, Message,
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::Duration,
};
use tokio::{
    sync::{broadcast, oneshot},
    task::JoinHandle,
};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

/// Version of the envelope shape. Consumers keep working when a payload gains
/// a field; they can refuse a version they were not written for.
pub const EVENT_SCHEMA_VERSION: u16 = 1;

/// Upper bound on the events the console can show. The topic is the record;
/// this is a window onto its tail, and the oldest entry is dropped first.
const EVENT_LOG_CAPACITY: usize = 100;

/// Events buffered per subscriber of the in-process bus.
const MEMORY_BUS_CAPACITY: usize = 256;

/// How long the consumer waits after a broker error before trying again, so a
/// broker that is down produces a slow retry rather than a hot loop.
const CONSUMER_RETRY_DELAY: Duration = Duration::from_secs(1);

/// How long a consumer is given to finish its current event and commit at
/// shutdown before the process stops waiting for it.
const CONSUMER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// What the application announces about itself.
///
/// Serialized with a `kind` discriminator that reads as an event name rather
/// than a Rust variant, because the topic is a contract with consumers that
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
    #[serde(rename = "note.published")]
    Note { author_id: Uuid, text: String },
}

impl DomainEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::UserRegistered { .. } => "user.registered",
            Self::JobEnqueued { .. } => "job.enqueued",
            Self::Note { .. } => "note.published",
        }
    }

    /// The identifier this event is about, which is also its partition key.
    fn key(&self) -> Uuid {
        match self {
            Self::UserRegistered { user_id, .. } => *user_id,
            Self::JobEnqueued { job_id, .. } => *job_id,
            Self::Note { author_id, .. } => *author_id,
        }
    }
}

/// One event as it sits on the topic: `{id, schema_version, key, occurred_at,
/// kind, payload}`, where `kind` and `payload` come from the flattened event
/// itself, so a consumer switches on one field and reads the rest under it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct EventEnvelope {
    pub id: Uuid,
    pub schema_version: u16,
    /// The partition key, repeated inside the record so an event read from a
    /// dump or a dead-letter topic still says what it is about.
    pub key: String,
    pub occurred_at: DateTime<Utc>,
    #[serde(flatten)]
    pub payload: DomainEvent,
}

impl EventEnvelope {
    pub fn new(payload: DomainEvent) -> Self {
        Self {
            id: Uuid::new_v4(),
            schema_version: EVENT_SCHEMA_VERSION,
            key: payload.key().to_string(),
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
pub struct PublishReceipt {
    pub partition: i32,
    pub offset: i64,
    #[serde(flatten)]
    pub envelope: EventEnvelope,
}

/// An event as it came back off the stream, with the coordinates the broker
/// assigned it.
#[derive(Clone, Debug, Serialize)]
pub struct ConsumedEvent {
    pub partition: i32,
    pub offset: i64,
    pub consumed_at: DateTime<Utc>,
    #[serde(flatten)]
    pub envelope: EventEnvelope,
}

#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: DomainEvent) -> Result<PublishReceipt, AppError>;

    /// Which backend is carrying events, as `/api/runtime` reports it.
    fn backend(&self) -> &'static str;
}

/// Publishes an event that must not be able to fail its caller.
///
/// The state change has already happened — the account exists, the job is
/// queued — so a broker that is unreachable must not turn a successful request
/// into an error. The event is lost and said to be lost; see the module
/// documentation for what closing that gap costs.
pub async fn publish_or_log(publisher: &dyn EventPublisher, event: DomainEvent) {
    let kind = event.kind();
    if let Err(error) = publisher.publish(event).await {
        tracing::warn!(
            event.kind = kind,
            ?error,
            "a domain event was not published"
        );
    }
}

/// Routes librdkafka's own diagnostics through this application's subscriber.
///
/// One case is worth handling rather than forwarding: a subscription to a topic
/// that does not exist yet. On a fresh broker that is ordinary — the topic
/// appears when the first record is published, or when an operator creates it —
/// but librdkafka reports it as a client error on every retry until then, which
/// would fill a first run with errors describing something that is about to fix
/// itself. It is recorded as a fact; every other error keeps its severity.
#[derive(Clone, Default)]
pub struct KafkaContext;

impl ClientContext for KafkaContext {
    fn error(&self, error: KafkaError, reason: &str) {
        if is_missing_topic(&error) {
            tracing::debug!(%reason, "the event topic does not exist yet");
        } else {
            tracing::error!(?error, %reason, "the Kafka client reported an error");
        }
    }
}

impl ConsumerContext for KafkaContext {}

fn is_missing_topic(error: &KafkaError) -> bool {
    matches!(
        error,
        KafkaError::MessageConsumption(RDKafkaErrorCode::UnknownTopicOrPartition)
            | KafkaError::Global(RDKafkaErrorCode::UnknownTopicOrPartition)
    )
}

/// Publishes to a Kafka topic.
#[derive(Clone)]
pub struct KafkaPublisher {
    producer: FutureProducer<KafkaContext>,
    topic: String,
    /// Bounds one publish end to end: enqueueing, any retry librdkafka makes,
    /// and the acknowledgement from every in-sync replica.
    delivery_timeout: Duration,
}

impl KafkaPublisher {
    pub fn connect(settings: &KafkaSettings) -> Result<Self, KafkaError> {
        Ok(Self {
            producer: producer_config(settings).create_with_context(KafkaContext)?,
            topic: settings.topic.clone(),
            delivery_timeout: Duration::from_secs(settings.delivery_timeout_seconds),
        })
    }
}

/// The producer's delivery guarantees, built separately from the client so the
/// settings that carry them can be asserted without a broker to connect to.
fn producer_config(settings: &KafkaSettings) -> ClientConfig {
    let mut config = client_config(settings);
    config
        // Deduplicates and orders retries at the broker, which also pins
        // acks=all: a receipt means every in-sync replica has the record.
        .set("enable.idempotence", "true")
        // The one deadline that matters to a caller, so it is the one the
        // configuration exposes. It covers retries, not just the first attempt.
        .set(
            "message.timeout.ms",
            (settings.delivery_timeout_seconds * 1_000).to_string(),
        )
        // A short batching window: publishes that arrive together travel
        // together, at a latency cost far below the delivery timeout.
        .set("linger.ms", "5")
        .set("compression.type", "lz4");
    config
}

/// The consumer's delivery guarantees, likewise separated from the client.
fn consumer_config(settings: &KafkaSettings) -> ClientConfig {
    let mut config = client_config(settings);
    config
        .set("group.id", &settings.consumer_group)
        // Offsets are committed by this application once an event has been
        // handled; the auto-commit timer would acknowledge events that were
        // read and never processed.
        .set("enable.auto.commit", "false")
        // A group that has never committed starts at the beginning of the
        // topic, so a fresh deployment sees the history it is a projection of
        // rather than only what happens next.
        .set("auto.offset.reset", "earliest");
    config
}

#[async_trait]
impl EventPublisher for KafkaPublisher {
    async fn publish(&self, event: DomainEvent) -> Result<PublishReceipt, AppError> {
        let envelope = EventEnvelope::new(event);
        let payload = serde_json::to_vec(&envelope)?;
        let span = tracing::info_span!(
            "kafka_publish",
            otel.name = %format!("{} publish", self.topic),
            otel.kind = "producer",
            messaging.system = "kafka",
            messaging.destination.name = %self.topic,
            messaging.message.id = %envelope.id,
            event.kind = envelope.kind(),
        );
        // The trace context travels in the record's headers, so the consumer —
        // in this process or in someone else's — continues this trace rather
        // than starting an unrelated one.
        let headers = record_headers(&envelope, &span);

        let delivery = self
            .producer
            .send(
                FutureRecord::to(&self.topic)
                    .key(&envelope.key)
                    .payload(&payload)
                    .headers(headers),
                Timeout::After(self.delivery_timeout),
            )
            .instrument(span)
            .await
            .map_err(|(error, _message)| error)?;

        Ok(PublishReceipt {
            partition: delivery.partition,
            offset: delivery.offset,
            envelope,
        })
    }

    fn backend(&self) -> &'static str {
        "kafka"
    }
}

/// The in-process stand-in used when no brokers are configured.
///
/// It preserves the shape of the contract — every event is published, keyed,
/// numbered, and consumed by the same handler — and none of the guarantees:
/// nothing is persisted, there is one partition because there is one process,
/// and an event reaches no other instance.
#[derive(Clone)]
pub struct MemoryEventBus {
    events: broadcast::Sender<ConsumedEvent>,
    next_offset: Arc<AtomicI64>,
}

impl Default for MemoryEventBus {
    fn default() -> Self {
        let (events, _receiver) = broadcast::channel(MEMORY_BUS_CAPACITY);
        Self {
            events,
            next_offset: Arc::new(AtomicI64::new(0)),
        }
    }
}

impl MemoryEventBus {
    /// The consumer side of this bus, to be handed to [`spawn_consumer`].
    pub fn source(&self) -> EventSource {
        EventSource::Memory(self.events.subscribe())
    }
}

#[async_trait]
impl EventPublisher for MemoryEventBus {
    async fn publish(&self, event: DomainEvent) -> Result<PublishReceipt, AppError> {
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

/// Bounded in-process view of the tail of the stream, filled by the consumer
/// and served by `/api/events`.
#[derive(Clone, Debug, Default)]
pub struct EventLog {
    inner: Arc<Mutex<EventLogInner>>,
}

#[derive(Debug, Default)]
struct EventLogInner {
    events: VecDeque<ConsumedEvent>,
    /// Every event this process has consumed, including those already dropped
    /// from the window.
    consumed: u64,
}

impl EventLog {
    pub fn record(&self, event: ConsumedEvent) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.events.len() == EVENT_LOG_CAPACITY {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
        inner.consumed += 1;
    }

    /// The most recent events, newest first.
    pub fn recent(&self, limit: usize) -> Vec<ConsumedEvent> {
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

/// The stream a consumer reads, whichever backend is carrying it.
pub enum EventSource {
    // Boxed because a StreamConsumer is an order of magnitude larger than a
    // channel receiver, and this enum is moved into the task.
    Kafka(Box<StreamConsumer<KafkaContext>>),
    Memory(broadcast::Receiver<ConsumedEvent>),
}

impl EventSource {
    /// Subscribes to the configured topic. The subscription itself is
    /// asynchronous — librdkafka joins the group in the background — so this
    /// returns before any partition has been assigned.
    pub fn kafka(settings: &KafkaSettings) -> Result<Self, KafkaError> {
        let consumer: StreamConsumer<KafkaContext> =
            consumer_config(settings).create_with_context(KafkaContext)?;
        consumer.subscribe(&[settings.topic.as_str()])?;
        Ok(Self::Kafka(Box::new(consumer)))
    }
}

/// A running consumer, which stops when its handle is stopped.
pub struct ConsumerTask {
    shutdown: oneshot::Sender<()>,
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
        // A closed receiver means the task has already ended, which is not a
        // failure to shut it down.
        let _ = self.shutdown.send(());
        match tokio::time::timeout(CONSUMER_SHUTDOWN_TIMEOUT, self.task).await {
            Ok(_) => tracing::info!("event consumer stopped"),
            Err(_) => tracing::warn!("event consumer did not stop within its shutdown timeout"),
        }
    }
}

/// Starts consuming, feeding every event into `log`.
pub fn spawn_consumer(source: EventSource, log: EventLog) -> ConsumerTask {
    let (shutdown, mut shutdown_signal) = oneshot::channel();
    let task = tokio::spawn(async move {
        match source {
            EventSource::Kafka(consumer) => {
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut shutdown_signal => break,
                        received = consumer.recv() => match received {
                            Ok(message) => consume_kafka_message(consumer.as_ref(), &message, &log),
                        // librdkafka reconnects and re-subscribes on its own,
                        // so this is a report rather than a recovery step: the
                        // delay only keeps a broker that is down or a topic
                        // that does not exist yet from becoming a hot loop.
                        Err(error) => {
                            if is_missing_topic(&error) {
                                tracing::debug!("waiting for the event topic to appear");
                            } else {
                                tracing::warn!(?error, "reading from the event stream failed");
                            }
                            tokio::time::sleep(CONSUMER_RETRY_DELAY).await;
                            }
                        },
                    }
                }
                commit_on_shutdown(consumer.as_ref());
            }
            EventSource::Memory(mut events) => loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_signal => break,
                    received = events.recv() => match received {
                        Ok(event) => log.record(event),
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            tracing::warn!(missed, "the in-process event bus dropped events");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                }
            },
        }
    });
    ConsumerTask { shutdown, task }
}

/// Acknowledges everything this consumer handled, and waits for the broker to
/// say so.
///
/// The per-event commits are asynchronous, so some of them may still be in
/// flight when the process is asked to stop. This one is synchronous: a restart
/// then resumes where this instance left off instead of replaying events it had
/// already projected. Replaying them would be correct — delivery is
/// at-least-once — but it is work nobody needs done twice.
fn commit_on_shutdown(consumer: &StreamConsumer<KafkaContext>) {
    match consumer.commit_consumer_state(CommitMode::Sync) {
        Ok(()) => {}
        // Nothing was ever handled: a consumer that stops before it is assigned
        // a partition has no position to record.
        Err(KafkaError::ConsumerCommit(RDKafkaErrorCode::NoOffset)) => {}
        Err(error) => tracing::warn!(?error, "committing event offsets at shutdown failed"),
    }
}

/// Handles one record and acknowledges it.
///
/// A record that cannot be decoded is committed anyway. It will never decode on
/// a later attempt, so the alternative is a consumer that stops on it forever
/// and a projection that silently stops advancing; a deployment that must keep
/// such records sends them to a dead-letter topic here.
fn consume_kafka_message(
    consumer: &StreamConsumer<KafkaContext>,
    message: &BorrowedMessage<'_>,
    log: &EventLog,
) {
    let span = tracing::info_span!(
        "kafka_consume",
        otel.name = %format!("{} receive", message.topic()),
        otel.kind = "consumer",
        messaging.system = "kafka",
        messaging.destination.name = %message.topic(),
        messaging.kafka.partition = message.partition(),
        messaging.kafka.offset = message.offset(),
        event.kind = tracing::field::Empty,
    );
    // Continues the trace of whoever published the record.
    if let Some(headers) = message.headers() {
        span.set_parent(global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(headers))
        }));
    }
    let _entered = span.enter();

    match message
        .payload()
        .ok_or_else(|| "the record has no payload".to_owned())
        .and_then(|payload| {
            serde_json::from_slice::<EventEnvelope>(payload).map_err(|error| error.to_string())
        }) {
        Ok(envelope) => {
            span.record("event.kind", envelope.kind());
            log.record(ConsumedEvent {
                partition: message.partition(),
                offset: message.offset(),
                consumed_at: Utc::now(),
                envelope,
            });
        }
        Err(reason) => tracing::warn!(
            partition = message.partition(),
            offset = message.offset(),
            %reason,
            "skipping a record that is not a luxor event",
        ),
    }

    // Asynchronous: the offset is queued for the next commit interval rather
    // than costing a broker round trip per event. At-least-once delivery is
    // what makes that safe.
    if let Err(error) = consumer.commit_message(message, CommitMode::Async) {
        tracing::warn!(?error, "committing an event offset failed");
    }
}

/// The settings both clients share. Everything specific to producing or
/// consuming is set by its own constructor.
fn client_config(settings: &KafkaSettings) -> ClientConfig {
    let mut config = ClientConfig::new();
    config
        .set("bootstrap.servers", &settings.brokers)
        .set("client.id", &settings.client_id)
        .set("security.protocol", settings.security_protocol.as_str());
    if let Some(sasl) = &settings.sasl {
        config
            .set("sasl.mechanism", sasl.mechanism.as_str())
            .set("sasl.username", &sasl.username)
            .set("sasl.password", sasl.password.expose_secret());
    }
    config
}

/// The headers a published record carries: what the payload is, what it is
/// about, and which trace produced it.
fn record_headers(envelope: &EventEnvelope, span: &tracing::Span) -> OwnedHeaders {
    let mut trace_context = HeaderInjector::default();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&span.context(), &mut trace_context);
    });

    let mut headers = OwnedHeaders::new()
        .insert(Header {
            key: "content-type",
            value: Some("application/json"),
        })
        .insert(Header {
            key: "event-id",
            value: Some(&envelope.id.to_string()),
        })
        .insert(Header {
            key: "event-kind",
            value: Some(envelope.kind()),
        })
        .insert(Header {
            key: "schema-version",
            value: Some(&envelope.schema_version.to_string()),
        });
    for (key, value) in &trace_context.0 {
        headers = headers.insert(Header {
            key,
            value: Some(value),
        });
    }
    headers
}

/// Collects the propagator's output, because `OwnedHeaders` is built by
/// consuming and returning itself rather than by mutation.
#[derive(Default)]
struct HeaderInjector(Vec<(String, String)>);

impl Injector for HeaderInjector {
    fn set(&mut self, key: &str, value: String) {
        self.0.push((key.to_owned(), value));
    }
}

/// Reads the trace context back out of a record's headers. Generic over the
/// headers trait rather than tied to a borrowed message, so the round trip with
/// [`record_headers`] can be tested without a broker.
struct HeaderExtractor<'a, H: Headers>(&'a H);

impl<H: Headers> Extractor for HeaderExtractor<'_, H> {
    fn get(&self, key: &str) -> Option<&str> {
        (0..self.0.count())
            .map(|index| self.0.get(index))
            .find(|header| header.key.eq_ignore_ascii_case(key))
            .and_then(|header| header.value)
            .and_then(|value| std::str::from_utf8(value).ok())
    }

    fn keys(&self) -> Vec<&str> {
        (0..self.0.count())
            .map(|index| self.0.get(index).key)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(text: &str) -> DomainEvent {
        DomainEvent::Note {
            author_id: Uuid::new_v4(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn envelopes_are_self_describing_on_the_wire() {
        let user_id = Uuid::new_v4();
        let envelope = EventEnvelope::new(DomainEvent::UserRegistered {
            user_id,
            role: Role::Admin,
        });
        let value = serde_json::to_value(&envelope).unwrap();

        // The name on the topic is an event name, not a Rust variant, and the
        // payload is nested under it so a consumer can switch on `kind` alone.
        assert_eq!(value["kind"], "user.registered");
        assert_eq!(value["schema_version"], EVENT_SCHEMA_VERSION);
        assert_eq!(value["key"], user_id.to_string());
        assert_eq!(value["payload"]["user_id"], user_id.to_string());
        assert_eq!(value["payload"]["role"], "admin");

        // What is published is what a consumer reads back.
        let decoded: EventEnvelope = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, envelope);
    }

    /// The key decides the partition, and a partition is the only place Kafka
    /// orders anything, so every event about one entity has to key on that
    /// entity's identifier.
    #[test]
    fn events_are_keyed_by_what_they_are_about() {
        let user_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let author_id = Uuid::new_v4();

        for (event, expected) in [
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
            (
                DomainEvent::Note {
                    author_id,
                    text: "hello".into(),
                },
                author_id,
            ),
        ] {
            assert_eq!(event.key(), expected, "{}", event.kind());
        }
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
        impl EventPublisher for BrokenPublisher {
            async fn publish(&self, _event: DomainEvent) -> Result<PublishReceipt, AppError> {
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

    #[test]
    fn kafka_clients_carry_the_configured_credentials() {
        use crate::config::{Config, KafkaSaslMechanism};
        use std::collections::HashMap;

        let config = Config::from_map(HashMap::from([
            ("KAFKA_BROKERS".into(), "broker.example.com:9093".into()),
            ("KAFKA_SECURITY_PROTOCOL".into(), "sasl_ssl".into()),
            ("KAFKA_SASL_MECHANISM".into(), "scram-sha-256".into()),
            ("KAFKA_SASL_USERNAME".into(), "luxor".into()),
            ("KAFKA_SASL_PASSWORD".into(), "streaming-secret".into()),
        ]))
        .unwrap();
        let settings = config.kafka.unwrap();
        assert_eq!(
            settings.sasl.as_ref().unwrap().mechanism,
            KafkaSaslMechanism::ScramSha256
        );

        let client = client_config(&settings);
        assert_eq!(client.get("security.protocol"), Some("sasl_ssl"));
        assert_eq!(client.get("sasl.mechanism"), Some("SCRAM-SHA-256"));
        assert_eq!(client.get("sasl.password"), Some("streaming-secret"));
    }

    #[test]
    fn published_records_carry_their_trace_context() {
        let envelope = EventEnvelope::new(note("traced"));
        let span = tracing::info_span!("kafka_publish");
        let headers = record_headers(&envelope, &span);

        let named = |name: &str| {
            (0..headers.count())
                .map(|index| headers.get(index))
                .find(|header| header.key == name)
                .and_then(|header| {
                    header
                        .value
                        .map(|value| String::from_utf8_lossy(value).into_owned())
                })
        };
        assert_eq!(named("content-type").as_deref(), Some("application/json"));
        assert_eq!(named("event-kind").as_deref(), Some("note.published"));
        assert_eq!(
            named("event-id").as_deref(),
            Some(envelope.id.to_string().as_str())
        );
        assert_eq!(named("schema-version").as_deref(), Some("1"));
    }

    /// The publishing trace has to survive the trip through the broker, which
    /// means what the injector writes is what the extractor reads. Both halves
    /// are exercised here, because a consumer that silently starts its own
    /// trace looks exactly like one that continued the right one.
    #[test]
    fn a_trace_context_written_into_headers_is_read_back_from_them() {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::TracerProvider};
        use tracing_subscriber::prelude::*;

        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        let provider = TracerProvider::builder().build();
        let subscriber =
            tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(
                opentelemetry::trace::TracerProvider::tracer(&provider, "luxor-test"),
            ));

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("kafka_publish");
            let published_trace_id = span.context().span().span_context().trace_id();
            assert!(
                published_trace_id != opentelemetry::trace::TraceId::INVALID,
                "the publishing span must be recorded for its context to travel"
            );

            let headers = record_headers(&EventEnvelope::new(note("traced")), &span);
            let extracted = opentelemetry::global::get_text_map_propagator(|propagator| {
                propagator.extract(&HeaderExtractor(&headers))
            });

            // A consumer setting this as its parent lands in the publisher's
            // trace, which is what the console's waterfall renders.
            let consumed = extracted.span().span_context().clone();
            assert_eq!(consumed.trace_id(), published_trace_id);
            assert!(consumed.is_remote());
            assert!(consumed.is_sampled());
        });
    }

    /// The three delivery decisions the module documents live in configuration
    /// keys, which is exactly the kind of thing a later edit silently reverses.
    #[test]
    fn the_clients_carry_the_documented_delivery_guarantees() {
        use crate::config::Config;
        use std::collections::HashMap;

        let settings = Config::from_map(HashMap::from([
            ("KAFKA_BROKERS".into(), "localhost:9092".into()),
            ("KAFKA_CONSUMER_GROUP".into(), "orders-projection".into()),
            ("KAFKA_DELIVERY_TIMEOUT_SECONDS".into(), "7".into()),
        ]))
        .unwrap()
        .kafka
        .unwrap();

        // Idempotence is what makes a retry safe, and the delivery timeout is
        // the deadline a waiting request is bounded by — in milliseconds, which
        // is the unit librdkafka reads it in.
        let producer = producer_config(&settings);
        assert_eq!(producer.get("enable.idempotence"), Some("true"));
        assert_eq!(producer.get("message.timeout.ms"), Some("7000"));

        // Auto-commit would acknowledge events that were read and never
        // handled, which is the difference between at-least-once and silent
        // loss.
        let consumer = consumer_config(&settings);
        assert_eq!(consumer.get("enable.auto.commit"), Some("false"));
        assert_eq!(consumer.get("auto.offset.reset"), Some("earliest"));
        assert_eq!(consumer.get("group.id"), Some("orders-projection"));
    }
}
