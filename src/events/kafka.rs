//! The Kafka transport for domain events: settings, the idempotent producer,
//! and the consumer that commits after handling.

use super::{
    ConsumedEvent, Event, EventEnvelope, EventHandler, EventPublisher, EventSource, PublishReceipt,
    Source,
};
use crate::{
    config::{ConfigError, Env, KAFKA_SETTINGS},
    error::AppError,
    tasks::Shutdown,
};
use async_trait::async_trait;
use chrono::Utc;
use rdkafka::{
    consumer::{CommitMode, Consumer, ConsumerContext, StreamConsumer},
    error::{KafkaError, RDKafkaErrorCode},
    message::{BorrowedMessage, Header, OwnedHeaders},
    producer::{FutureProducer, FutureRecord},
    util::Timeout,
    ClientConfig, ClientContext, Message,
};
use secrecy::{ExposeSecret, SecretString};
use std::{str::FromStr, time::Duration};
use tracing::Instrument;

/// How long the consumer waits after a broker error before trying again, so a
/// broker that is down produces a slow retry rather than a hot loop.
const CONSUMER_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Kafka's own limit on a topic name.
const KAFKA_TOPIC_MAX_LENGTH: usize = 249;

/// How a Kafka client authenticates and encrypts its connection, named exactly
/// as librdkafka's `security.protocol` spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KafkaSecurityProtocol {
    Plaintext,
    Ssl,
    SaslPlaintext,
    SaslSsl,
}

impl KafkaSecurityProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Ssl => "ssl",
            Self::SaslPlaintext => "sasl_plaintext",
            Self::SaslSsl => "sasl_ssl",
        }
    }

    fn is_sasl(self) -> bool {
        matches!(self, Self::SaslPlaintext | Self::SaslSsl)
    }
}

impl FromStr for KafkaSecurityProtocol {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "plaintext" => Ok(Self::Plaintext),
            "ssl" => Ok(Self::Ssl),
            "sasl_plaintext" => Ok(Self::SaslPlaintext),
            "sasl_ssl" => Ok(Self::SaslSsl),
            _ => Err(ConfigError::Invalid(
                "KAFKA_SECURITY_PROTOCOL",
                value.to_owned(),
            )),
        }
    }
}

/// The SASL mechanisms librdkafka implements itself. Kerberos (`GSSAPI`) is
/// deliberately absent: it needs the Cyrus SASL library, which this build does
/// not link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KafkaSaslMechanism {
    Plain,
    ScramSha256,
    ScramSha512,
}

impl KafkaSaslMechanism {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

impl FromStr for KafkaSaslMechanism {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_uppercase().as_str() {
            "PLAIN" => Ok(Self::Plain),
            "SCRAM-SHA-256" => Ok(Self::ScramSha256),
            "SCRAM-SHA-512" => Ok(Self::ScramSha512),
            "GSSAPI" => Err(ConfigError::Invalid(
                "KAFKA_SASL_MECHANISM",
                "GSSAPI needs the Cyrus SASL library, which this build does not link".to_owned(),
            )),
            _ => Err(ConfigError::Invalid(
                "KAFKA_SASL_MECHANISM",
                value.to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KafkaSasl {
    pub mechanism: KafkaSaslMechanism,
    pub username: String,
    pub password: SecretString,
}

/// Connection and topic settings for the event stream. `None` selects the
/// in-process event bus; a configuration that names brokers always carries a
/// complete, validated set.
#[derive(Clone, Debug)]
pub struct KafkaSettings {
    /// `host:port[,host:port…]`, as librdkafka's `bootstrap.servers` takes it,
    /// normalized so the library never sees stray whitespace.
    pub brokers: String,
    /// `<APP_NAME>.events` unless `KAFKA_TOPIC` says otherwise.
    pub topic: String,
    /// The consumer group this instance joins; `<APP_NAME>` by default.
    /// Instances sharing a group share the topic's partitions between them;
    /// instances given different groups each receive every event.
    pub consumer_group: String,
    /// Identifies this application to the broker, in its logs and metrics;
    /// `<APP_NAME>` by default.
    pub client_id: String,
    pub security_protocol: KafkaSecurityProtocol,
    /// Present exactly when `security_protocol` names a SASL one.
    pub sasl: Option<KafkaSasl>,
    /// How long a publish may take — including the broker acknowledging it —
    /// before it is reported as failed. It bounds a request that publishes an
    /// event, so it belongs well inside `REQUEST_TIMEOUT_SECONDS`.
    pub delivery_timeout_seconds: u64,
}

impl KafkaSettings {
    pub fn from_env(env: &Env) -> Result<Option<Self>, ConfigError> {
        let Some(brokers) = env.get("KAFKA_BROKERS") else {
            // A configured broker credential that would never be sent anywhere
            // is a mistake worth naming, not a value to quietly discard.
            if let Some(key) = KAFKA_SETTINGS[1..]
                .iter()
                .find(|key| env.get(key).is_some())
            {
                return Err(ConfigError::Validation(format!(
                    "{key} has no effect unless KAFKA_BROKERS is set"
                )));
            }
            return Ok(None);
        };

        let security_protocol = match env.get("KAFKA_SECURITY_PROTOCOL") {
            Some(value) => value.parse()?,
            None => KafkaSecurityProtocol::Plaintext,
        };
        let credentials = [
            env.get("KAFKA_SASL_MECHANISM"),
            env.get("KAFKA_SASL_USERNAME"),
            env.get("KAFKA_SASL_PASSWORD"),
        ];
        let sasl = match (security_protocol.is_sasl(), credentials) {
            (true, [Some(mechanism), Some(username), Some(password)]) => Some(KafkaSasl {
                mechanism: mechanism.parse()?,
                username: username.to_owned(),
                password: SecretString::from(password.to_owned()),
            }),
            (true, _) => {
                return Err(ConfigError::Validation(format!(
                    "KAFKA_SECURITY_PROTOCOL={} requires KAFKA_SASL_MECHANISM, KAFKA_SASL_USERNAME, and KAFKA_SASL_PASSWORD",
                    security_protocol.as_str()
                )))
            }
            // Credentials under a non-SASL protocol would never be sent, so the
            // deployment believes it is authenticating when it is not.
            (false, [None, None, None]) => None,
            (false, _) => {
                return Err(ConfigError::Validation(format!(
                    "the KAFKA_SASL_* settings need a SASL KAFKA_SECURITY_PROTOCOL, not {}",
                    security_protocol.as_str()
                )))
            }
        };

        let delivery_timeout_seconds = env.parse("KAFKA_DELIVERY_TIMEOUT_SECONDS", 10_u64)?;
        if !(1..=300).contains(&delivery_timeout_seconds) {
            return Err(ConfigError::Validation(
                "KAFKA_DELIVERY_TIMEOUT_SECONDS must be between 1 and 300 seconds".into(),
            ));
        }

        let app_name = env.app_name();
        Ok(Some(Self {
            brokers: parse_broker_list(brokers)?,
            topic: parse_topic(
                &env.optional("KAFKA_TOPIC")
                    .unwrap_or_else(|| format!("{app_name}.events")),
            )?,
            consumer_group: parse_kafka_identifier(
                "KAFKA_CONSUMER_GROUP",
                env.get("KAFKA_CONSUMER_GROUP").unwrap_or(app_name),
            )?,
            client_id: parse_kafka_identifier(
                "KAFKA_CLIENT_ID",
                env.get("KAFKA_CLIENT_ID").unwrap_or(app_name),
            )?,
            security_protocol,
            sasl,
            delivery_timeout_seconds,
        }))
    }
}

/// Normalizes `host:port[,host:port…]`. librdkafka reports an unusable entry
/// only once a connection is attempted, in a background thread, so the shape is
/// checked here instead — a typo should fail startup, not surface as events
/// that silently never arrive.
fn parse_broker_list(brokers: &str) -> Result<String, ConfigError> {
    let mut normalized = Vec::new();
    for entry in brokers.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // rsplit keeps a bracketed IPv6 literal (`[::1]:9092`) intact.
        let valid = entry.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port > 0)
        });
        if !valid {
            return Err(ConfigError::Invalid(
                "KAFKA_BROKERS",
                format!("{entry} is not a host:port address"),
            ));
        }
        normalized.push(entry);
    }
    if normalized.is_empty() {
        return Err(ConfigError::Invalid(
            "KAFKA_BROKERS",
            "expected at least one host:port address".to_owned(),
        ));
    }
    Ok(normalized.join(","))
}

/// Applies Kafka's own topic-name rule. A name the broker would refuse is
/// better refused here, where the message says which setting is wrong.
fn parse_topic(topic: &str) -> Result<String, ConfigError> {
    let named = (1..=KAFKA_TOPIC_MAX_LENGTH).contains(&topic.len())
        && topic != "."
        && topic != ".."
        && topic.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        });
    named.then(|| topic.to_owned()).ok_or_else(|| {
        ConfigError::Invalid(
            "KAFKA_TOPIC",
            format!(
                "expected 1-{KAFKA_TOPIC_MAX_LENGTH} characters of letters, digits, dots, underscores, or hyphens"
            ),
        )
    })
}

/// A group or client identifier. Both are echoed into broker logs and metric
/// names, so they stay printable ASCII without whitespace.
fn parse_kafka_identifier(key: &'static str, value: &str) -> Result<String, ConfigError> {
    let named = (1..=255).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_graphic() && character != ',');
    named.then(|| value.to_owned()).ok_or_else(|| {
        ConfigError::Invalid(
            key,
            "expected 1-255 printable ASCII characters without whitespace or commas".to_owned(),
        )
    })
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

/// Publishes to a Kafka topic. One publisher carries any [`Event`] type.
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
impl<E: Event> EventPublisher<E> for KafkaPublisher {
    async fn publish(&self, event: E) -> Result<PublishReceipt<E>, AppError> {
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

impl<E: Event> EventSource<E> {
    /// Subscribes to the configured topic. The subscription itself is
    /// asynchronous — librdkafka joins the group in the background — so this
    /// returns before any partition has been assigned.
    pub fn kafka(settings: &KafkaSettings) -> Result<Self, KafkaError> {
        let consumer: StreamConsumer<KafkaContext> =
            consumer_config(settings).create_with_context(KafkaContext)?;
        consumer.subscribe(&[settings.topic.as_str()])?;
        Ok(Self(Source::Kafka(Box::new(consumer))))
    }
}

/// Reads the topic until `shutdown` fires, then commits what was handled.
pub(super) async fn consume<E, H>(
    consumer: &StreamConsumer<KafkaContext>,
    handler: &H,
    mut shutdown: Shutdown,
) where
    E: Event,
    H: EventHandler<E>,
{
    loop {
        tokio::select! {
            biased;
            _ = shutdown.requested() => break,
            received = consumer.recv() => match received {
                Ok(message) => consume_message(consumer, &message, handler).await,
                // librdkafka reconnects and re-subscribes on its own, so this
                // is a report rather than a recovery step: the delay only keeps
                // a broker that is down or a topic that does not exist yet
                // from becoming a hot loop.
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
    commit_on_shutdown(consumer);
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

/// Hands one record to the handler and acknowledges it.
///
/// A record that cannot be decoded is committed anyway. It will never decode on
/// a later attempt, so the alternative is a consumer that stops on it forever
/// and a projection that silently stops advancing; a deployment that must keep
/// such records sends them to a dead-letter topic here.
async fn consume_message<E, H>(
    consumer: &StreamConsumer<KafkaContext>,
    message: &BorrowedMessage<'_>,
    handler: &H,
) where
    E: Event,
    H: EventHandler<E>,
{
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
    #[cfg(feature = "otel")]
    if let Some(headers) = message.headers() {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        span.set_parent(opentelemetry::global::get_text_map_propagator(
            |propagator| propagator.extract(&trace_context::HeaderExtractor(headers)),
        ));
    }

    let decoded = message
        .payload()
        .ok_or_else(|| "the record has no payload".to_owned())
        .and_then(|payload| {
            serde_json::from_slice::<EventEnvelope<E>>(payload).map_err(|error| error.to_string())
        });
    match decoded {
        Ok(envelope) => {
            span.record("event.kind", envelope.kind());
            let event = ConsumedEvent {
                partition: message.partition(),
                offset: message.offset(),
                consumed_at: Utc::now(),
                envelope,
            };
            handler.handle(event).instrument(span.clone()).await;
        }
        Err(reason) => span.in_scope(|| {
            tracing::warn!(
                partition = message.partition(),
                offset = message.offset(),
                %reason,
                "skipping a record that is not an event of this application",
            );
        }),
    }

    // Asynchronous: the offset is queued for the next commit interval rather
    // than costing a broker round trip per event. At-least-once delivery is
    // what makes that safe.
    span.in_scope(|| {
        if let Err(error) = consumer.commit_message(message, CommitMode::Async) {
            tracing::warn!(?error, "committing an event offset failed");
        }
    });
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
/// about, and — when the build includes OpenTelemetry — which trace produced
/// it.
fn record_headers<E: Event>(envelope: &EventEnvelope<E>, span: &tracing::Span) -> OwnedHeaders {
    let headers = OwnedHeaders::new()
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
    #[cfg(feature = "otel")]
    let headers = trace_context::inject(span)
        .into_iter()
        .fold(headers, |headers, (key, value)| {
            headers.insert(Header {
                key: &key,
                value: Some(&value),
            })
        });
    #[cfg(not(feature = "otel"))]
    let _ = span;
    headers
}

/// W3C trace-context propagation through record headers.
#[cfg(feature = "otel")]
mod trace_context {
    use opentelemetry::{
        global,
        propagation::{Extractor, Injector},
    };
    use rdkafka::message::Headers;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    /// The propagator's output for `span`, as header name-value pairs.
    pub(super) fn inject(span: &tracing::Span) -> Vec<(String, String)> {
        let mut injector = HeaderInjector::default();
        global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&span.context(), &mut injector);
        });
        injector.0
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

    /// Reads the trace context back out of a record's headers. Generic over
    /// the headers trait rather than tied to a borrowed message, so the round
    /// trip with [`super::record_headers`] can be tested without a broker.
    pub(super) struct HeaderExtractor<'a, H: Headers>(pub(super) &'a H);

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::tests::note;
    use crate::testing::values;
    use rdkafka::message::Headers;

    fn settings(pairs: &[(&str, &str)]) -> Result<Option<KafkaSettings>, ConfigError> {
        KafkaSettings::from_env(&Env::new(values(pairs))?)
    }

    #[test]
    fn kafka_is_off_until_brokers_are_named() {
        assert!(settings(&[]).unwrap().is_none());

        // Settings that would silently never be used are reported rather than
        // discarded: this is the deployment that believes it configured Kafka.
        assert!(matches!(
            settings(&[("KAFKA_TOPIC", "orders.events")]),
            Err(ConfigError::Validation(message)) if message.contains("KAFKA_BROKERS")
        ));
    }

    #[test]
    fn kafka_defaults_apply_once_brokers_are_named() {
        let kafka = settings(&[("KAFKA_BROKERS", " localhost:9092 , [::1]:9093 ")])
            .unwrap()
            .expect("naming brokers enables Kafka");

        // The normalized list is what librdkafka receives, whitespace included
        // in neither entry.
        assert_eq!(kafka.brokers, "localhost:9092,[::1]:9093");
        assert_eq!(kafka.topic, format!("{}.events", env!("CARGO_PKG_NAME")));
        assert_eq!(kafka.consumer_group, env!("CARGO_PKG_NAME"));
        assert_eq!(kafka.client_id, env!("CARGO_PKG_NAME"));
        assert_eq!(kafka.security_protocol, KafkaSecurityProtocol::Plaintext);
        assert!(kafka.sasl.is_none());
        assert_eq!(kafka.delivery_timeout_seconds, 10);
    }

    #[test]
    fn kafka_names_follow_the_application_name() {
        let kafka = settings(&[
            ("APP_NAME", "orders-api"),
            ("KAFKA_BROKERS", "localhost:9092"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(kafka.topic, "orders-api.events");
        assert_eq!(kafka.consumer_group, "orders-api");
        assert_eq!(kafka.client_id, "orders-api");
    }

    #[test]
    fn kafka_broker_addresses_and_topics_are_validated() {
        for brokers in ["localhost", "localhost:0", "localhost:not-a-port", ":9092"] {
            assert!(
                matches!(
                    settings(&[("KAFKA_BROKERS", brokers)]),
                    Err(ConfigError::Invalid("KAFKA_BROKERS", _))
                ),
                "{brokers:?} should be refused"
            );
        }

        for topic in ["", "..", "orders events", "orders/events", &"a".repeat(250)] {
            // An empty value reads as unset, which leaves the default in place.
            let outcome = settings(&[("KAFKA_BROKERS", "localhost:9092"), ("KAFKA_TOPIC", topic)]);
            if topic.is_empty() {
                assert_eq!(
                    outcome.unwrap().unwrap().topic,
                    format!("{}.events", env!("CARGO_PKG_NAME"))
                );
            } else {
                assert!(
                    matches!(outcome, Err(ConfigError::Invalid("KAFKA_TOPIC", _))),
                    "{topic:?} should be refused"
                );
            }
        }
    }

    #[test]
    fn kafka_sasl_credentials_and_protocol_must_agree() {
        let mut pairs = vec![
            ("KAFKA_BROKERS", "broker.example.com:9093"),
            ("KAFKA_SECURITY_PROTOCOL", "sasl_ssl"),
        ];
        // A SASL protocol without credentials authenticates with nothing.
        assert!(matches!(
            settings(&pairs),
            Err(ConfigError::Validation(message)) if message.contains("KAFKA_SASL_MECHANISM")
        ));

        pairs.extend([
            ("KAFKA_SASL_MECHANISM", "scram-sha-512"),
            ("KAFKA_SASL_USERNAME", "streaming-user"),
            ("KAFKA_SASL_PASSWORD", "streaming-secret"),
        ]);
        let sasl = settings(&pairs)
            .unwrap()
            .unwrap()
            .sasl
            .expect("a SASL protocol carries credentials");
        assert_eq!(sasl.mechanism.as_str(), "SCRAM-SHA-512");
        assert_eq!(sasl.username, "streaming-user");

        // The mirror image: credentials that would never leave the process,
        // because the protocol does not authenticate at all.
        pairs[1] = ("KAFKA_SECURITY_PROTOCOL", "ssl");
        assert!(matches!(
            settings(&pairs),
            Err(ConfigError::Validation(message)) if message.contains("SASL")
        ));

        // Kerberos needs a library this build does not link, so it is refused
        // with the reason rather than passed to librdkafka to fail on.
        pairs[1] = ("KAFKA_SECURITY_PROTOCOL", "sasl_ssl");
        pairs[2] = ("KAFKA_SASL_MECHANISM", "GSSAPI");
        assert!(matches!(
            settings(&pairs),
            Err(ConfigError::Invalid("KAFKA_SASL_MECHANISM", message))
                if message.contains("Cyrus SASL")
        ));
    }

    /// A publish happens inside a request, so its deadline has to stay well
    /// inside the request timeout rather than outlive it.
    #[test]
    fn kafka_delivery_timeout_is_bounded() {
        assert!(matches!(
            settings(&[
                ("KAFKA_BROKERS", "localhost:9092"),
                ("KAFKA_DELIVERY_TIMEOUT_SECONDS", "600"),
            ]),
            Err(ConfigError::Validation(message))
                if message.contains("KAFKA_DELIVERY_TIMEOUT_SECONDS")
        ));
    }

    #[test]
    fn kafka_clients_carry_the_configured_credentials() {
        let settings = settings(&[
            ("KAFKA_BROKERS", "broker.example.com:9093"),
            ("KAFKA_SECURITY_PROTOCOL", "sasl_ssl"),
            ("KAFKA_SASL_MECHANISM", "scram-sha-256"),
            ("KAFKA_SASL_USERNAME", "streaming-user"),
            ("KAFKA_SASL_PASSWORD", "streaming-secret"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            settings.sasl.as_ref().unwrap().mechanism,
            KafkaSaslMechanism::ScramSha256
        );

        let client = client_config(&settings);
        assert_eq!(client.get("security.protocol"), Some("sasl_ssl"));
        assert_eq!(client.get("sasl.mechanism"), Some("SCRAM-SHA-256"));
        assert_eq!(client.get("sasl.password"), Some("streaming-secret"));
    }

    /// The three delivery decisions the module documents live in configuration
    /// keys, which is exactly the kind of thing a later edit silently reverses.
    #[test]
    fn the_clients_carry_the_documented_delivery_guarantees() {
        let settings = settings(&[
            ("KAFKA_BROKERS", "localhost:9092"),
            ("KAFKA_CONSUMER_GROUP", "orders-projection"),
            ("KAFKA_DELIVERY_TIMEOUT_SECONDS", "7"),
        ])
        .unwrap()
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

    #[test]
    fn published_records_describe_their_payload() {
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
        assert_eq!(named("event-kind").as_deref(), Some("test.noted"));
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
    #[cfg(feature = "otel")]
    #[test]
    fn a_trace_context_written_into_headers_is_read_back_from_them() {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::TracerProvider};
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        use tracing_subscriber::prelude::*;

        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        let provider = TracerProvider::builder().build();
        let subscriber =
            tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(
                opentelemetry::trace::TracerProvider::tracer(&provider, "test"),
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
                propagator.extract(&trace_context::HeaderExtractor(&headers))
            });

            // A consumer setting this as its parent lands in the publisher's
            // trace, which is what the console's waterfall renders.
            let consumed = extracted.span().span_context().clone();
            assert_eq!(consumed.trace_id(), published_trace_id);
            assert!(consumed.is_remote());
            assert!(consumed.is_sampled());
        });
    }
}
