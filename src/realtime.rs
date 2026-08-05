//! Realtime WebSocket fan-out.
//!
//! A [`RealtimeHub`] is a broadcast channel plus a connection counter: every
//! socket subscribes to it, and anything published reaches all of them. The
//! event contract is versionable JSON — a tagged [`EventPayload`] inside an
//! envelope carrying the server timestamp and the live connection count — so
//! clients switch on `type` and ignore payloads they do not know yet.
//!
//! Two properties of browser WebSockets shape the connection setup:
//!
//! * The handshake cannot carry an `Authorization` header, so the access JWT
//!   cannot authenticate it directly. Putting the JWT in the query string
//!   instead would write a live credential into access logs and proxy traces,
//!   which is why connections are opened with a short-lived, single-use ticket
//!   ([`issue_ticket`], [`consume_ticket`]) that is worthless once redeemed.
//! * CORS does not apply to WebSockets: a page on any origin may open a socket
//!   to this server, and the browser will send it. [`origin_allowed`] is what
//!   keeps a hostile page out, not the CORS layer.
//!
//! The fan-out is in-process. One instance serves its own connections, so a
//! multi-instance deployment needs a shared bus (Redis pub/sub, or a dedicated
//! realtime service) between the instances before broadcasts reach every
//! client. That boundary is deliberate: this module demonstrates the socket
//! lifecycle, not a distributed message broker.

use crate::{
    cache::{self, Cache},
    error::AppError,
    models::Role,
};
use axum::{
    body::Bytes,
    extract::ws::{close_code, CloseFrame, Message, WebSocket},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::broadcast, time::Instant};
use uuid::Uuid;

/// Largest WebSocket message the server will assemble. Well above any valid
/// command, and small enough that a hostile client cannot make the server
/// buffer megabytes per connection.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// Maximum characters in one broadcast, counted in `char`s rather than bytes
/// so the limit does not depend on the alphabet a client writes in.
pub const MAX_TEXT_CHARACTERS: usize = 280;

/// Per-connection publish budget: at most `MESSAGE_QUOTA` broadcasts per
/// `MESSAGE_WINDOW`. The HTTP rate limiter meters the upgrade request but sees
/// nothing afterwards, so an established socket carries its own budget.
const MESSAGE_QUOTA: u32 = 5;
const MESSAGE_WINDOW: Duration = Duration::from_secs(5);

/// How often the server pushes a tick and pings the peer.
const TICK_INTERVAL: Duration = Duration::from_secs(5);

/// A connection that has sent nothing — not even the automatic Pong answering
/// our Ping — for this long is treated as gone. Half-open TCP connections do
/// not surface as errors, so without this check they would hold a slot until
/// the process restarts.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Events buffered per subscriber before it is considered too slow. A client
/// that falls this far behind is told what it missed rather than silently
/// served an incomplete stream.
const BROADCAST_CAPACITY: usize = 256;

const TICKET_KEY_PREFIX: &str = "realtime:ticket";

/// Who a connection belongs to. The same shape is stored in the connection
/// ticket and echoed in events, and it deliberately carries no email: the
/// event stream is fanned out to every connected client.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Participant {
    pub user_id: Uuid,
    pub role: Role,
}

/// The server-enforced limits, published in the welcome event so a client can
/// render them instead of hardcoding a copy.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Limits {
    pub max_connections: usize,
    pub max_text_characters: usize,
    pub messages_per_window: u32,
    pub message_window_seconds: u64,
    pub tick_interval_seconds: u64,
    pub idle_timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceChange {
    Joined,
    Left,
}

/// What happened. Serialized with a `type` discriminator alongside the
/// envelope fields.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    /// First frame of every connection, sent only to that connection.
    Welcome {
        connection_id: Uuid,
        you: Participant,
        limits: Limits,
    },
    /// A connection arrived or went away.
    Presence {
        change: PresenceChange,
        connection_id: Uuid,
        participant: Participant,
    },
    /// A client broadcast, fanned out to everyone including its sender.
    Message {
        sequence: u64,
        from: Participant,
        text: String,
    },
    /// Server-driven push, so the stream is visibly alive with one client.
    Tick { sequence: u64 },
    /// Something the connection should know about itself: a rejected command,
    /// a dropped backlog. Sent only to the affected connection.
    Notice { code: &'static str, detail: String },
}

/// One event as it goes on the wire: the payload plus the facts every client
/// wants for all of them.
#[derive(Clone, Debug, Serialize)]
pub struct ServerEvent {
    pub at: DateTime<Utc>,
    /// Connections attached to this instance when the event was produced.
    pub connections: usize,
    #[serde(flatten)]
    pub payload: EventPayload,
}

/// What a client may send. Unknown types are answered with a notice rather
/// than a disconnect, so a newer client talking to an older server degrades
/// instead of flapping.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientCommand {
    Broadcast { text: String },
}

#[derive(Clone)]
pub struct RealtimeHub {
    inner: Arc<HubInner>,
}

struct HubInner {
    events: broadcast::Sender<ServerEvent>,
    connections: AtomicUsize,
    max_connections: usize,
    sequence: AtomicU64,
}

impl RealtimeHub {
    pub fn new(max_connections: usize) -> Self {
        let (events, _receiver) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(HubInner {
                events,
                connections: AtomicUsize::new(0),
                max_connections,
                sequence: AtomicU64::new(0),
            }),
        }
    }

    pub fn connections(&self) -> usize {
        self.inner.connections.load(Ordering::Relaxed)
    }

    pub fn max_connections(&self) -> usize {
        self.inner.max_connections
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ServerEvent> {
        self.inner.events.subscribe()
    }

    /// Takes a connection slot, or returns `None` when the instance is already
    /// at capacity. The slot releases itself on drop, so every early return on
    /// the connection path stays balanced.
    pub fn try_admit(&self) -> Option<ConnectionSlot> {
        self.inner
            .connections
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (current < self.inner.max_connections).then_some(current + 1)
            })
            .ok()?;
        Some(ConnectionSlot {
            hub: self.clone(),
            released: false,
        })
    }

    /// Wraps a payload in the envelope every client sees.
    pub fn envelope(&self, payload: EventPayload) -> ServerEvent {
        ServerEvent {
            at: Utc::now(),
            connections: self.connections(),
            payload,
        }
    }

    /// Fans an event out to every subscriber. A send with no subscribers left
    /// is not an error: the last connection closing is ordinary.
    pub fn publish(&self, payload: EventPayload) -> ServerEvent {
        let event = self.envelope(payload);
        let _ = self.inner.events.send(event.clone());
        event
    }

    /// Monotonic per-instance ordering for broadcast messages, so a client can
    /// tell a reordered render from a genuinely missed event.
    fn next_sequence(&self) -> u64 {
        self.inner.sequence.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn limits(&self) -> Limits {
        Limits {
            max_connections: self.max_connections(),
            max_text_characters: MAX_TEXT_CHARACTERS,
            messages_per_window: MESSAGE_QUOTA,
            message_window_seconds: MESSAGE_WINDOW.as_secs(),
            tick_interval_seconds: TICK_INTERVAL.as_secs(),
            idle_timeout_seconds: IDLE_TIMEOUT.as_secs(),
        }
    }
}

/// A held connection slot. Dropping it frees capacity, including on the paths
/// that fail after admission but before the socket is established.
pub struct ConnectionSlot {
    hub: RealtimeHub,
    released: bool,
}

impl ConnectionSlot {
    /// Releases the slot early so that events published afterwards (the
    /// departure notice) already report the lower count.
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            self.hub.inner.connections.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.release();
    }
}

/// Serves one accepted WebSocket until it closes.
///
/// The whole connection is one task driving one `select!`: broadcasts out,
/// commands in, and a timer that pushes ticks, pings the peer, and enforces
/// the idle deadline. Nothing here can outlive the socket, and the slot is
/// released on every exit path.
pub async fn run_connection(
    mut socket: WebSocket,
    hub: RealtimeHub,
    mut slot: ConnectionSlot,
    participant: Participant,
) {
    let connection_id = Uuid::new_v4();
    // Subscribing before announcing the arrival means this connection also
    // receives its own presence event, so a client can confirm the round trip.
    let mut events = hub.subscribe();

    let welcome = hub.envelope(EventPayload::Welcome {
        connection_id,
        you: participant,
        limits: hub.limits(),
    });
    if send_event(&mut socket, &welcome).await.is_err() {
        return;
    }
    hub.publish(EventPayload::Presence {
        change: PresenceChange::Joined,
        connection_id,
        participant,
    });
    tracing::debug!(%connection_id, user_id = %participant.user_id, "realtime connection opened");

    let mut ticks = tokio::time::interval(TICK_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticks.tick().await; // The first tick of an interval completes immediately.
    let mut quota = SendQuota::new(Instant::now());
    let mut last_seen = Instant::now();
    let mut tick_sequence = 0_u64;

    loop {
        tokio::select! {
            event = events.recv() => {
                if forward_event(&mut socket, &hub, event).await.is_err() {
                    break;
                }
            },
            incoming = socket.recv() => {
                let Some(Ok(message)) = incoming else { break };
                last_seen = Instant::now();
                match message {
                    Message::Text(text) => {
                        let Some(payload) = handle_command(&hub, participant, &text, &mut quota) else {
                            continue;
                        };
                        // Notices concern one connection, so they are answered
                        // directly; accepted commands go through the hub.
                        match payload {
                            Outcome::Broadcast(payload) => { hub.publish(payload); }
                            Outcome::Notice(payload) => {
                                if send_directly(&mut socket, &hub, &mut events, payload).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Message::Close(_) => break,
                    Message::Binary(_) => {
                        let notice = EventPayload::Notice {
                            code: "unsupported_frame",
                            detail: "this endpoint speaks JSON text frames".into(),
                        };
                        if send_directly(&mut socket, &hub, &mut events, notice).await.is_err() {
                            break;
                        }
                    }
                    // axum answers Ping automatically; Pong is the liveness
                    // signal we asked for and needs no reply.
                    Message::Ping(_) | Message::Pong(_) => {}
                }
            },
            _ = ticks.tick() => {
                if last_seen.elapsed() >= IDLE_TIMEOUT {
                    tracing::debug!(%connection_id, "closing an idle realtime connection");
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: close_code::POLICY,
                            reason: "idle timeout".into(),
                        })))
                        .await;
                    break;
                }
                tick_sequence += 1;
                let tick = EventPayload::Tick { sequence: tick_sequence };
                if send_directly(&mut socket, &hub, &mut events, tick).await.is_err() {
                    break;
                }
                if socket.send(Message::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Free the slot first so the departure event reports the count that
    // remains, then let the socket go.
    slot.release();
    hub.publish(EventPayload::Presence {
        change: PresenceChange::Left,
        connection_id,
        participant,
    });
    tracing::debug!(%connection_id, "realtime connection closed");
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: close_code::NORMAL,
            reason: "connection closed".into(),
        })))
        .await;
}

/// Writes one event from this connection's subscription, or reports that the
/// connection is finished.
async fn forward_event(
    socket: &mut WebSocket,
    hub: &RealtimeHub,
    received: Result<ServerEvent, broadcast::error::RecvError>,
) -> Result<(), ()> {
    match received {
        Ok(event) => send_event(socket, &event).await,
        // The client is slower than the stream. Telling it how much it missed
        // is more useful than a silently truncated history.
        Err(broadcast::error::RecvError::Lagged(missed)) => {
            let notice = hub.envelope(EventPayload::Notice {
                code: "lagged",
                detail: format!("{missed} events were dropped because this connection fell behind"),
            });
            send_event(socket, &notice).await
        }
        Err(broadcast::error::RecvError::Closed) => Err(()),
    }
}

/// Sends an event to this connection alone, behind everything already fanned
/// out to it.
///
/// Publishing is synchronous, so a broadcast this connection has just accepted
/// is already sitting in its own subscription — but that subscription is
/// drained by another branch of the loop. Writing the socket straight from
/// here would let a notice arrive ahead of the very messages it is a verdict
/// on, so the pending fan-out goes out first.
async fn send_directly(
    socket: &mut WebSocket,
    hub: &RealtimeHub,
    events: &mut broadcast::Receiver<ServerEvent>,
    payload: EventPayload,
) -> Result<(), ()> {
    loop {
        let received = match events.try_recv() {
            Ok(event) => Ok(event),
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Lagged(missed)) => {
                Err(broadcast::error::RecvError::Lagged(missed))
            }
            Err(broadcast::error::TryRecvError::Closed) => Err(broadcast::error::RecvError::Closed),
        };
        forward_event(socket, hub, received).await?;
    }
    let event = hub.envelope(payload);
    send_event(socket, &event).await
}

/// Where an accepted command goes: to everyone, or back to its sender.
enum Outcome {
    Broadcast(EventPayload),
    Notice(EventPayload),
}

fn handle_command(
    hub: &RealtimeHub,
    participant: Participant,
    raw: &str,
    quota: &mut SendQuota,
) -> Option<Outcome> {
    let command = match serde_json::from_str::<ClientCommand>(raw) {
        Ok(command) => command,
        Err(_) => {
            return Some(Outcome::Notice(EventPayload::Notice {
                code: "invalid_command",
                detail: format!(
                    "expected a JSON object such as {{\"type\":\"broadcast\",\"text\":\"hello\"}}, \
                     with at most {MAX_TEXT_CHARACTERS} characters of text"
                ),
            }))
        }
    };

    match command {
        ClientCommand::Broadcast { text } => {
            let text = match validate_text(&text) {
                Ok(text) => text,
                Err(detail) => {
                    return Some(Outcome::Notice(EventPayload::Notice {
                        code: "invalid_message",
                        detail: detail.to_owned(),
                    }))
                }
            };
            if !quota.allow(Instant::now()) {
                return Some(Outcome::Notice(EventPayload::Notice {
                    code: "rate_limited",
                    detail: format!(
                        "at most {MESSAGE_QUOTA} messages every {} seconds per connection",
                        MESSAGE_WINDOW.as_secs()
                    ),
                }));
            }
            Some(Outcome::Broadcast(EventPayload::Message {
                sequence: hub.next_sequence(),
                from: participant,
                text,
            }))
        }
    }
}

/// Normalizes and bounds a broadcast. Control characters are refused because
/// nothing legitimate sends them and they corrupt any log or terminal the
/// event is later rendered into.
fn validate_text(text: &str) -> Result<String, &'static str> {
    let text = text.trim();
    if text.is_empty() {
        return Err("a broadcast needs some text");
    }
    if text.chars().count() > MAX_TEXT_CHARACTERS {
        return Err("the text is longer than the published limit");
    }
    if text.chars().any(char::is_control) {
        return Err("the text contains control characters");
    }
    Ok(text.to_owned())
}

async fn send_event(socket: &mut WebSocket, event: &ServerEvent) -> Result<(), ()> {
    // Every event is a plain serializable struct, so a failure here would be a
    // programming error rather than a runtime condition.
    let encoded = serde_json::to_string(event).map_err(|error| {
        tracing::error!(?error, "failed to encode a realtime event");
    })?;
    socket
        .send(Message::Text(encoded.into()))
        .await
        .map_err(|_| ())
}

/// A per-connection fixed-window publish budget.
struct SendQuota {
    window_started: Instant,
    used: u32,
}

impl SendQuota {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            used: 0,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_started) >= MESSAGE_WINDOW {
            self.window_started = now;
            self.used = 0;
        }
        if self.used >= MESSAGE_QUOTA {
            return false;
        }
        self.used += 1;
        true
    }
}

/// Mints a connection ticket for `participant`, valid for `ttl`.
///
/// Only the ticket's hash is stored, exactly as refresh tokens are handled: a
/// dump of the cache yields no usable connection credential. The ticket itself
/// exists only in the response and in the client's memory.
pub async fn issue_ticket(
    cache: &dyn Cache,
    participant: Participant,
    ttl: Duration,
) -> Result<String, AppError> {
    let ticket = random_ticket();
    cache::put_typed(cache, &ticket_key(&ticket), &participant, ttl).await?;
    Ok(ticket)
}

/// Redeems a connection ticket, which invalidates it in the same step.
///
/// The read and the delete are one atomic operation ([`Cache::take_json`]), so
/// two connections racing on a stolen ticket cannot both win.
pub async fn consume_ticket(cache: &dyn Cache, ticket: &str) -> Result<Participant, AppError> {
    // Anything that cannot be a ticket is rejected before it becomes a lookup.
    if ticket.is_empty() || ticket.len() > 128 {
        return Err(AppError::Unauthorized);
    }
    let stored = cache
        .take_json(&ticket_key(ticket))
        .await?
        .ok_or(AppError::Unauthorized)?;
    serde_json::from_value(stored).map_err(|error| {
        tracing::error!(?error, "stored realtime ticket could not be decoded");
        AppError::Unauthorized
    })
}

fn ticket_key(ticket: &str) -> String {
    let digest = Sha256::digest(ticket.as_bytes());
    let fingerprint: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{TICKET_KEY_PREFIX}:{fingerprint}")
}

fn random_ticket() -> String {
    let mut bytes = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decides whether a WebSocket handshake may proceed.
///
/// CORS never runs for a WebSocket: the browser opens the connection and hands
/// the response to the page regardless of origin, which is what makes
/// cross-site WebSocket hijacking possible. This is the check that stands in
/// for it.
///
/// A handshake without an `Origin` is allowed: browsers always send one, so
/// its absence marks a non-browser client (a service, `curl`, the test suite),
/// and such a client cannot be tricked into connecting on a user's behalf.
/// What authenticates a connection is the single-use ticket, not this check.
pub fn origin_allowed(origin: Option<&str>, host: Option<&str>, allowed: &[String]) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    if allowed
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(origin))
    {
        return true;
    }
    // The console is served by this app, so a page whose origin matches the
    // host it is connecting to is same-origin and allowed even when the
    // deployment's CORS list names a different public origin (as the local
    // default does).
    match (origin_authority(origin), host) {
        (Some(authority), Some(host)) => authority.eq_ignore_ascii_case(host),
        _ => false,
    }
}

/// The `host[:port]` of an HTTP(S) origin, or `None` for anything that is not
/// one (`null`, a file origin, a value carrying a path).
fn origin_authority(origin: &str) -> Option<&str> {
    let (scheme, authority) = origin.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    (!authority.is_empty() && !authority.contains('/')).then_some(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::MemoryCache;

    fn participant() -> Participant {
        Participant {
            user_id: Uuid::new_v4(),
            role: Role::User,
        }
    }

    #[test]
    fn admission_is_bounded_and_slots_are_returned_on_drop() {
        let hub = RealtimeHub::new(2);
        let first = hub.try_admit().expect("capacity is free");
        let second = hub.try_admit().expect("capacity is free");
        assert_eq!(hub.connections(), 2);
        assert!(hub.try_admit().is_none());

        drop(second);
        assert_eq!(hub.connections(), 1);
        // An early return between admission and the socket must not leak a
        // slot, which is what the drop guard is for.
        drop(first);
        assert_eq!(hub.connections(), 0);
        assert!(hub.try_admit().is_some());
    }

    #[tokio::test]
    async fn published_events_reach_every_subscriber() {
        let hub = RealtimeHub::new(4);
        let mut first = hub.subscribe();
        let mut second = hub.subscribe();
        let sender = participant();

        hub.publish(EventPayload::Message {
            sequence: hub.next_sequence(),
            from: sender,
            text: "hello".into(),
        });

        for receiver in [&mut first, &mut second] {
            let event = receiver.recv().await.unwrap();
            let EventPayload::Message {
                sequence,
                from,
                text,
            } = event.payload
            else {
                panic!("expected a message event");
            };
            assert_eq!(sequence, 1);
            assert_eq!(from, sender);
            assert_eq!(text, "hello");
        }
    }

    #[test]
    fn events_carry_a_type_discriminator_and_the_envelope_fields() {
        let hub = RealtimeHub::new(1);
        let _slot = hub.try_admit().unwrap();
        let event = hub.envelope(EventPayload::Tick { sequence: 7 });
        let encoded = serde_json::to_value(&event).unwrap();

        assert_eq!(encoded["type"], "tick");
        assert_eq!(encoded["sequence"], 7);
        assert_eq!(encoded["connections"], 1);
        assert!(encoded["at"].is_string());
    }

    #[test]
    fn presence_events_name_the_role_but_never_an_email() {
        let hub = RealtimeHub::new(1);
        let participant = participant();
        let event = hub.envelope(EventPayload::Presence {
            change: PresenceChange::Joined,
            connection_id: Uuid::new_v4(),
            participant,
        });
        let encoded = serde_json::to_string(&event).unwrap();

        assert!(encoded.contains(r#""type":"presence""#));
        assert!(encoded.contains(r#""change":"joined""#));
        assert!(encoded.contains(&participant.user_id.to_string()));
        assert!(!encoded.contains("email"));
    }

    #[test]
    fn broadcasts_are_trimmed_bounded_and_free_of_control_characters() {
        assert_eq!(validate_text("  hello  ").unwrap(), "hello");
        assert_eq!(
            validate_text(&"é".repeat(MAX_TEXT_CHARACTERS))
                .unwrap()
                .chars()
                .count(),
            MAX_TEXT_CHARACTERS
        );
        assert!(validate_text("   ").is_err());
        assert!(validate_text(&"a".repeat(MAX_TEXT_CHARACTERS + 1)).is_err());
        assert!(validate_text("two\nlines").is_err());
    }

    #[test]
    fn unknown_commands_answer_with_a_notice_rather_than_a_disconnect() {
        let hub = RealtimeHub::new(1);
        let mut quota = SendQuota::new(Instant::now());

        for raw in [
            r#"{"type":"reboot_world"}"#,
            r#"{"type":"broadcast"}"#,
            "not json at all",
        ] {
            let outcome = handle_command(&hub, participant(), raw, &mut quota);
            assert!(
                matches!(
                    outcome,
                    Some(Outcome::Notice(EventPayload::Notice {
                        code: "invalid_command",
                        ..
                    }))
                ),
                "{raw}"
            );
        }
    }

    #[test]
    fn empty_broadcasts_are_refused_without_consuming_the_publish_budget() {
        let hub = RealtimeHub::new(1);
        let mut quota = SendQuota::new(Instant::now());

        let outcome = handle_command(
            &hub,
            participant(),
            r#"{"type":"broadcast","text":" "}"#,
            &mut quota,
        );
        assert!(matches!(
            outcome,
            Some(Outcome::Notice(EventPayload::Notice {
                code: "invalid_message",
                ..
            }))
        ));
        assert_eq!(quota.used, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_publish_budget_refills_once_its_window_passes() {
        let start = Instant::now();
        let mut quota = SendQuota::new(start);
        for _ in 0..MESSAGE_QUOTA {
            assert!(quota.allow(start));
        }
        assert!(!quota.allow(start));

        // Still inside the window.
        assert!(!quota.allow(start + MESSAGE_WINDOW - Duration::from_millis(1)));
        assert!(quota.allow(start + MESSAGE_WINDOW));
    }

    #[tokio::test]
    async fn tickets_are_single_use() {
        let cache = MemoryCache::default();
        let participant = participant();
        let ticket = issue_ticket(&cache, participant, Duration::from_secs(30))
            .await
            .unwrap();

        assert_eq!(
            consume_ticket(&cache, &ticket).await.unwrap(),
            participant,
            "the first redemption returns the ticket's owner"
        );
        assert!(matches!(
            consume_ticket(&cache, &ticket).await,
            Err(AppError::Unauthorized)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn tickets_expire() {
        let cache = MemoryCache::default();
        let ticket = issue_ticket(&cache, participant(), Duration::from_secs(30))
            .await
            .unwrap();

        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(matches!(
            consume_ticket(&cache, &ticket).await,
            Err(AppError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn a_stored_ticket_never_contains_the_ticket_itself() {
        let cache = MemoryCache::default();
        let ticket = issue_ticket(&cache, participant(), Duration::from_secs(30))
            .await
            .unwrap();

        // Only the fingerprint is stored, so the ticket as issued is not a key
        // that finds anything.
        assert!(cache.get_json(&ticket).await.unwrap().is_none());
        assert!(!ticket_key(&ticket).contains(&ticket));
        assert!(cache
            .get_json(&ticket_key(&ticket))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn malformed_tickets_are_rejected_before_a_lookup() {
        let cache = MemoryCache::default();
        assert!(matches!(
            consume_ticket(&cache, "").await,
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            consume_ticket(&cache, &"a".repeat(129)).await,
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn origin_checks_admit_the_console_and_the_configured_origins() {
        let allowed = vec!["https://app.example.com".to_owned()];

        // Same-origin: the console served by this deployment.
        assert!(origin_allowed(
            Some("http://127.0.0.1:8080"),
            Some("127.0.0.1:8080"),
            &allowed
        ));
        // A configured cross-origin client.
        assert!(origin_allowed(
            Some("https://app.example.com"),
            Some("api.example.com"),
            &allowed
        ));
        // Non-browser clients send no Origin.
        assert!(origin_allowed(None, Some("127.0.0.1:8080"), &allowed));
    }

    #[test]
    fn origin_checks_turn_away_cross_site_connections() {
        let allowed = vec!["https://app.example.com".to_owned()];

        // The case this check exists for: a hostile page opening a socket to
        // this server. CORS would never see it.
        assert!(!origin_allowed(
            Some("https://evil.test"),
            Some("app.example.com"),
            &allowed
        ));
        // A near-miss host, and an origin that is not an HTTP(S) origin.
        assert!(!origin_allowed(
            Some("https://app.example.com.evil.test"),
            Some("app.example.com"),
            &allowed
        ));
        assert!(!origin_allowed(
            Some("null"),
            Some("app.example.com"),
            &allowed
        ));
        assert!(!origin_allowed(
            Some("file://app.example.com"),
            Some("app.example.com"),
            &allowed
        ));
    }
}
