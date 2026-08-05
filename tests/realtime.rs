//! End-to-end tests for the realtime WebSocket demo.
//!
//! These run a real listener and a real WebSocket client, because the parts
//! worth testing here — the handshake, the fan-out between two connections,
//! the per-connection limits — only exist once a socket is established.
//! Nothing external is required: the cache, queue, and rate limiter are the
//! in-memory backends, and the database handle is never used.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use futures_util::{SinkExt, StreamExt};
use luxor::{
    auth::JwtService, cache::MemoryCache, config::Config, db, models::Role,
    observability::TraceStore, queue::MemoryQueue, rate_limit::MemoryRateLimiter, server,
    state::AppState,
};
use serde_json::Value;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Error as WsError, Message},
    MaybeTlsStream, WebSocketStream,
};
use tower::ServiceExt;
use uuid::Uuid;

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Long enough that a loaded CI machine does not fail a correct
/// implementation, short enough that a wrong one fails the test instead of
/// hanging the suite.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

struct TestServer {
    address: SocketAddr,
    /// The same router the listener serves, kept for the plain HTTP calls
    /// (minting a ticket) so the tests need no HTTP client.
    app: Router,
    config: Arc<Config>,
}

impl TestServer {
    async fn start(overrides: &[(&str, &str)]) -> Self {
        let values = overrides
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<HashMap<_, _>>();
        let config = Arc::new(Config::from_map(values).unwrap());
        let state = AppState::new(
            config.clone(),
            db::connect_lazy("postgres://luxor:luxor@localhost/luxor").unwrap(),
            Arc::new(MemoryCache::default()),
            Arc::new(MemoryQueue::default()),
            Arc::new(MemoryRateLimiter::default()),
            TraceStore::default(),
        );
        let app = server::app(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let served = app.clone();
        tokio::spawn(async move {
            axum::serve(
                listener,
                served.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        Self {
            address,
            app,
            config,
        }
    }

    /// Signs an access token for a user that does not need to exist: the
    /// realtime endpoints authorize from the token's claims alone.
    fn bearer(&self, user_id: Uuid) -> String {
        let token = JwtService::from_config(&self.config)
            .issue(user_id, Role::User)
            .unwrap();
        format!("Bearer {token}")
    }

    async fn mint_ticket(&self, user_id: Uuid) -> String {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/realtime/ticket")
                    .header(header::AUTHORIZATION, self.bearer(user_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        body["ticket"].as_str().unwrap().to_owned()
    }

    async fn connect_with(&self, ticket: &str) -> Result<Client, WsError> {
        let mut request = format!("ws://{}/api/realtime/ws?ticket={ticket}", self.address)
            .into_client_request()
            .unwrap();
        // The console is served by this app, so its connections are
        // same-origin; the endpoint refuses anything else.
        request.headers_mut().insert(
            header::ORIGIN,
            format!("http://{}", self.address).parse().unwrap(),
        );
        tokio_tungstenite::connect_async(request)
            .await
            .map(|(client, _response)| client)
    }

    /// Mints a ticket and redeems it, which is the whole client-side sequence.
    async fn connect(&self, user_id: Uuid) -> Client {
        let ticket = self.mint_ticket(user_id).await;
        self.connect_with(&ticket).await.expect("the handshake")
    }
}

/// Reads events until one satisfies `wanted`, so a test never depends on
/// events it does not care about (a tick, another connection's presence)
/// arriving in a particular order.
async fn next_matching(client: &mut Client, wanted: impl Fn(&Value) -> bool) -> Value {
    let event = tokio::time::timeout(RECEIVE_TIMEOUT, async {
        while let Some(message) = client.next().await {
            match message.expect("a websocket frame") {
                Message::Text(text) => {
                    let event: Value = serde_json::from_str(&text).expect("a JSON event");
                    if wanted(&event) {
                        return Some(event);
                    }
                }
                Message::Close(_) => return None,
                _ => {}
            }
        }
        None
    })
    .await;
    event
        .expect("an event arrived before the timeout")
        .expect("the connection stayed open")
}

async fn next_of_type(client: &mut Client, kind: &str) -> Value {
    next_matching(client, |event| event["type"] == kind).await
}

/// Every event up to and including the first one of `kind`, so a test can
/// assert on what did — and did not — arrive before it.
async fn collect_until(client: &mut Client, kind: &str) -> Vec<Value> {
    let mut seen = Vec::new();
    loop {
        let event = next_matching(client, |_| true).await;
        let matched = event["type"] == kind;
        seen.push(event);
        if matched {
            return seen;
        }
    }
}

async fn broadcast(client: &mut Client, text: &str) {
    client
        .send(Message::text(
            serde_json::json!({"type": "broadcast", "text": text}).to_string(),
        ))
        .await
        .unwrap();
}

fn handshake_status(error: WsError) -> StatusCode {
    match error {
        WsError::Http(response) => response.status(),
        other => panic!("expected an HTTP handshake rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn realtime_connections_exchange_presence_and_broadcasts() {
    let server = TestServer::start(&[]).await;
    let alice_id = Uuid::new_v4();
    let bob_id = Uuid::new_v4();

    let mut alice = server.connect(alice_id).await;

    // The welcome frame carries the connection's own identity and the limits
    // the server enforces, so a client renders them instead of assuming them.
    let welcome = next_of_type(&mut alice, "welcome").await;
    assert_eq!(welcome["you"]["user_id"], alice_id.to_string());
    assert_eq!(welcome["you"]["role"], "user");
    assert_eq!(welcome["connections"], 1);
    assert!(welcome["limits"]["max_text_characters"].as_u64().unwrap() > 0);
    assert!(welcome["at"].is_string());

    // A connection also sees its own arrival, which is how a client confirms
    // the round trip through the hub.
    let own_arrival = next_of_type(&mut alice, "presence").await;
    assert_eq!(own_arrival["participant"]["user_id"], alice_id.to_string());
    assert_eq!(own_arrival["change"], "joined");

    // A second connection is announced to the first one.
    let mut bob = server.connect(bob_id).await;
    let joined = next_matching(&mut alice, |event| {
        event["type"] == "presence" && event["participant"]["user_id"] == bob_id.to_string()
    })
    .await;
    assert_eq!(joined["change"], "joined");
    assert_eq!(joined["connections"], 2);

    // A broadcast reaches every connection, its sender included.
    broadcast(&mut alice, "  hello everyone  ").await;
    for client in [&mut alice, &mut bob] {
        let message = next_of_type(client, "message").await;
        assert_eq!(message["text"], "hello everyone", "text is trimmed");
        assert_eq!(message["from"]["user_id"], alice_id.to_string());
        assert_eq!(message["sequence"], 1);
        // The fan-out never carries anything the sender did not publish.
        assert!(!message.to_string().contains("email"));
    }

    // Departures are announced too, with the count that remains.
    bob.close(None).await.unwrap();
    let left = next_matching(&mut alice, |event| {
        event["type"] == "presence" && event["change"] == "left"
    })
    .await;
    assert_eq!(left["participant"]["user_id"], bob_id.to_string());
    assert_eq!(left["connections"], 1);
}

/// The frame size cap is a protocol-level limit: tungstenite fails the
/// connection rather than handing over a partial message, which is what keeps
/// one client from making the server buffer without bound.
#[tokio::test]
async fn realtime_drops_connections_that_exceed_the_frame_cap() {
    let server = TestServer::start(&[]).await;
    let mut client = server.connect(Uuid::new_v4()).await;
    let welcome = next_of_type(&mut client, "welcome").await;
    assert_eq!(welcome["connections"], 1);

    broadcast(&mut client, &"a".repeat(64 * 1024)).await;

    let ended = tokio::time::timeout(RECEIVE_TIMEOUT, async {
        while let Some(message) = client.next().await {
            match message {
                Ok(Message::Close(_)) | Err(_) => return true,
                Ok(_) => {}
            }
        }
        true
    })
    .await;
    assert!(ended.unwrap(), "the connection was torn down");
}

#[tokio::test]
async fn realtime_answers_bad_commands_with_a_notice_and_meters_publishing() {
    let server = TestServer::start(&[]).await;
    let mut client = server.connect(Uuid::new_v4()).await;
    let welcome = next_of_type(&mut client, "welcome").await;
    let quota = welcome["limits"]["messages_per_window"].as_u64().unwrap();

    // An unusable command is answered, not punished with a disconnect.
    client
        .send(Message::text(r#"{"type":"reboot_world"}"#))
        .await
        .unwrap();
    let notice = next_of_type(&mut client, "notice").await;
    assert_eq!(notice["code"], "invalid_command");

    let too_long = welcome["limits"]["max_text_characters"].as_u64().unwrap() + 1;
    broadcast(&mut client, &"a".repeat(too_long as usize)).await;
    let notice = next_of_type(&mut client, "notice").await;
    assert_eq!(notice["code"], "invalid_message");

    // The HTTP rate limiter cannot see an established socket, so publishing
    // carries its own per-connection budget: the first `quota` broadcasts go
    // out and the next one is refused.
    for index in 0..=quota {
        broadcast(&mut client, &format!("message {index}")).await;
    }
    let events = collect_until(&mut client, "notice").await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "message")
            .count() as u64,
        quota
    );
    assert_eq!(events.last().unwrap()["code"], "rate_limited");

    // The connection survives every rejection.
    client
        .send(Message::text(r#"{"type":"reboot_world"}"#))
        .await
        .unwrap();
    assert_eq!(
        next_of_type(&mut client, "notice").await["code"],
        "invalid_command"
    );
}

#[tokio::test]
async fn realtime_tickets_authorize_exactly_one_connection() {
    let server = TestServer::start(&[]).await;
    let ticket = server.mint_ticket(Uuid::new_v4()).await;

    let mut first = server.connect_with(&ticket).await.expect("the handshake");
    assert_eq!(next_of_type(&mut first, "welcome").await["connections"], 1);

    // Redeeming a ticket destroys it, so a replayed one is worthless.
    let replayed = server.connect_with(&ticket).await.expect_err("a rejection");
    assert_eq!(handshake_status(replayed), StatusCode::UNAUTHORIZED);

    for rejected in ["", "not-a-ticket"] {
        let error = server
            .connect_with(rejected)
            .await
            .expect_err("a rejection");
        assert_eq!(handshake_status(error), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn realtime_connections_are_capped_per_instance() {
    let server = TestServer::start(&[("REALTIME_MAX_CONNECTIONS", "1")]).await;

    let mut held = server.connect(Uuid::new_v4()).await;
    assert_eq!(next_of_type(&mut held, "welcome").await["connections"], 1);

    let refused = server
        .connect_with(&server.mint_ticket(Uuid::new_v4()).await)
        .await
        .expect_err("a rejection");
    assert_eq!(handshake_status(refused), StatusCode::SERVICE_UNAVAILABLE);

    // Closing a connection returns its slot to the pool.
    held.close(None).await.unwrap();
    while held.next().await.is_some() {}
    let mut replacement = server.connect(Uuid::new_v4()).await;
    assert_eq!(
        next_of_type(&mut replacement, "welcome").await["connections"],
        1
    );
}

#[tokio::test]
async fn realtime_upgrades_from_a_foreign_origin_are_refused() {
    let server = TestServer::start(&[]).await;
    let ticket = server.mint_ticket(Uuid::new_v4()).await;

    let mut request = format!("ws://{}/api/realtime/ws?ticket={ticket}", server.address)
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert(header::ORIGIN, "https://evil.test".parse().unwrap());

    let error = tokio_tungstenite::connect_async(request)
        .await
        .expect_err("a rejection");
    assert_eq!(handshake_status(error), StatusCode::FORBIDDEN);
}
