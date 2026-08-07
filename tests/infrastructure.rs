use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use chrono::{Duration as ChronoDuration, Utc};
use luxor::{
    auth::hash_refresh_token,
    cache::{Cache, MemoryCache, RedisCache},
    config::{Config, RateLimitQuota},
    db,
    events::{
        spawn_consumer, DomainEvent, EventLog, EventPublisher, EventSource, KafkaPublisher,
        MemoryEventBus,
    },
    observability::TraceStore,
    queue::{Job, MemoryQueue, Queue, RedisQueue},
    rate_limit::{MemoryRateLimiter, RateLimiter, RedisRateLimiter},
    server,
    state::AppState,
};
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    util::Timeout,
    ClientConfig,
};
use redis::AsyncCommands;
use secrecy::SecretString;
use serde_json::{json, Value};
use std::{collections::HashMap, env, sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

/// Scores 4/4 with the account email as context, so the fixture does not sit
/// one zxcvbn dictionary update away from failing registration.
const INTEGRATION_PASSWORD: &str = "integration-tsunami-cobalt-4417";

#[tokio::test]
async fn migrations_and_authentication_flow_work_against_postgres() {
    let Some(database_url) = env::var("DATABASE_URL").ok() else {
        eprintln!("skipping PostgreSQL integration test: DATABASE_URL is not set");
        return;
    };
    let pool = db::connect(&SecretString::from(database_url.clone()))
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();

    let config = Arc::new(
        Config::from_map(HashMap::from([
            ("APP_ENV".into(), "test".into()),
            ("DATABASE_URL".into(), database_url),
            (
                "JWT_SECRET".into(),
                "integration-test-secret-at-least-32-characters".into(),
            ),
            // This test issues many credential requests from one client;
            // rate limiting has its own dedicated tests.
            ("RATE_LIMIT_AUTH_MAX_REQUESTS".into(), "1000".into()),
            ("RATE_LIMIT_API_MAX_REQUESTS".into(), "1000".into()),
        ]))
        .unwrap(),
    );
    let app = server::app(AppState::new(
        config,
        pool.clone(),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryQueue::default()),
        Arc::new(MemoryEventBus::default()),
        Arc::new(MemoryRateLimiter::default()),
        TraceStore::default(),
    ));
    let email = format!("integration-{}@example.com", Uuid::new_v4());
    // Registration enforces a zxcvbn strength floor, so the fixture has to be
    // a password a real account could use.
    let credentials = json!({"email": email, "password": INTEGRATION_PASSWORD});

    let registration = request_json(&app, "/api/auth/register", &credentials, None).await;
    assert_eq!(registration.status(), StatusCode::CREATED);
    let first_cookie = response_cookie(&registration);
    let registration_body = response_json(registration).await;
    let access_token = registration_body["access_token"].as_str().unwrap();
    assert_eq!(registration_body["user"]["role"], "user");

    let profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    let profile_body = response_json(profile).await;
    assert_eq!(profile_body["email"], email);
    assert_eq!(profile_body["role"], "user");

    // Roles persist through PostgreSQL, travel in the access token, and gate
    // the permission-demo endpoints: the default user role cannot purge
    // records while an admin can.
    let admin_email = format!("integration-admin-{}@example.com", Uuid::new_v4());
    let admin_credentials =
        json!({"email": admin_email, "password": INTEGRATION_PASSWORD, "role": "admin"});
    let admin_registration =
        request_json(&app, "/api/auth/register", &admin_credentials, None).await;
    assert_eq!(admin_registration.status(), StatusCode::CREATED);
    let admin_body = response_json(admin_registration).await;
    assert_eq!(admin_body["user"]["role"], "admin");
    let admin_token = admin_body["access_token"].as_str().unwrap();

    let purge_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/demo/records")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(purge_denied.status(), StatusCode::FORBIDDEN);

    let purge_allowed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/demo/records")
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(purge_allowed.status(), StatusCode::OK);
    assert_eq!(response_json(purge_allowed).await["simulated"], true);

    // Roles are fixed at registration; the write surfaces do not exist.
    let role_switch = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/me/role")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"role":"admin"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(role_switch.status(), StatusCode::NOT_FOUND);

    // Pruning removes sessions whose whole rotation family has expired and
    // leaves live ones alone (the refresh flow below still works).
    let user_id: Uuid = profile_body["id"].as_str().unwrap().parse().unwrap();
    let expired_hash = hash_refresh_token(&format!("expired-family-{}", Uuid::new_v4()));
    db::insert_session(
        &pool,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        &expired_hash,
        Utc::now() - ChronoDuration::hours(2),
        Utc::now() - ChronoDuration::hours(1),
    )
    .await
    .unwrap();
    let pruned = db::delete_expired_session_families(&pool).await.unwrap();
    assert!(pruned >= 1, "the expired family must be deleted");

    let refresh = app
        .clone()
        .oneshot(
            Request::post("/api/auth/refresh")
                .header(header::COOKIE, &first_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::OK);
    let rotated_cookie = response_cookie(&refresh);
    assert_ne!(first_cookie, rotated_cookie);

    // Reusing a rotated token is detected and revokes the whole refresh family.
    let replay = app
        .clone()
        .oneshot(
            Request::post("/api/auth/refresh")
                .header(header::COOKIE, &first_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    let revoked_family = app
        .clone()
        .oneshot(
            Request::post("/api/auth/refresh")
                .header(header::COOKIE, &rotated_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked_family.status(), StatusCode::UNAUTHORIZED);

    // A fresh login creates a new family that logout can revoke.
    let login = request_json(&app, "/api/auth/login", &credentials, None).await;
    assert_eq!(login.status(), StatusCode::OK);
    let login_cookie = response_cookie(&login);
    let logout = app
        .clone()
        .oneshot(
            Request::post("/api/auth/logout")
                .header(header::COOKIE, &login_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert!(logout
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));

    sqlx::query("DELETE FROM users WHERE email = ANY($1)")
        .bind(vec![email, admin_email])
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn cache_and_queue_contracts_work_against_redis() {
    let Some(redis_url) = env::var("REDIS_URL").ok() else {
        eprintln!("skipping Redis integration test: REDIS_URL is not set");
        return;
    };
    let client = redis::Client::open(redis_url).unwrap();
    let manager = redis::aio::ConnectionManager::new(client.clone())
        .await
        .unwrap();
    let suffix = Uuid::new_v4();
    let namespace = format!("luxor:test:cache:{suffix}");
    let queue_key = format!("luxor:test:queue:{suffix}");
    let limiter_namespace = format!("luxor:test:ratelimit:{suffix}");
    let cache = RedisCache::new(manager.clone(), namespace.clone());
    let queue = RedisQueue::new(manager.clone(), queue_key.clone());
    let limiter = RedisRateLimiter::new(manager, limiter_namespace.clone());

    cache
        .put_json("sample", &json!({"value": 42}), Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(
        cache.get_json("sample").await.unwrap(),
        Some(json!({"value": 42}))
    );
    cache.invalidate("sample").await.unwrap();
    assert!(cache.get_json("sample").await.unwrap().is_none());

    // Sub-second TTLs survive the trip to Redis (PSETEX, not SETEX).
    cache
        .put_json("sample", &json!({"value": 7}), Duration::from_millis(750))
        .await
        .unwrap();
    assert_eq!(
        cache.get_json("sample").await.unwrap(),
        Some(json!({"value": 7}))
    );

    let envelope = queue
        .enqueue(Job::SendEmail {
            to: "integration@example.com".into(),
            template: "welcome".into(),
        })
        .await
        .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let serialized: String = connection.rpop(&queue_key, None).await.unwrap();
    let queued: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(queued["id"], envelope.id.to_string());
    assert_eq!(queued["kind"], "send_email");

    // The distributed limiter counts atomically and reports when the fixed
    // window resets.
    let quota = RateLimitQuota {
        max_requests: 2,
        window_seconds: 60,
    };
    let limiter_key = "api:198.51.100.7";
    let first = limiter.hit(limiter_key, quota).await.unwrap();
    assert!(first.allowed);
    assert_eq!(first.remaining, 1);
    let second = limiter.hit(limiter_key, quota).await.unwrap();
    assert!(second.allowed);
    assert_eq!(second.remaining, 0);
    let third = limiter.hit(limiter_key, quota).await.unwrap();
    assert!(!third.allowed);
    assert_eq!(third.remaining, 0);
    assert!((1..=60).contains(&third.retry_after_seconds));

    let keys = [
        format!("{namespace}:sample"),
        queue_key,
        format!("{limiter_namespace}:{limiter_key}"),
    ];
    let _: usize = connection.del(&keys).await.unwrap();
}

/// The full round trip against a real broker: an event published through the
/// producer comes back through a consumer group, decoded, with the coordinates
/// the broker assigned it. Nothing here is simulated, which is why it is the
/// one test that needs Kafka running.
#[tokio::test]
async fn events_round_trip_through_kafka() {
    let Some(brokers) = env::var("KAFKA_BROKERS").ok() else {
        eprintln!("skipping Kafka integration test: KAFKA_BROKERS is not set");
        return;
    };
    // A topic and a group per run, so a rerun is never served another run's
    // offsets and the assertions can count exactly.
    let suffix = Uuid::new_v4();
    let config = Config::from_map(HashMap::from([
        ("KAFKA_BROKERS".into(), brokers),
        ("KAFKA_TOPIC".into(), format!("luxor.test.{suffix}")),
        (
            "KAFKA_CONSUMER_GROUP".into(),
            format!("luxor-test-{suffix}"),
        ),
    ]))
    .unwrap();
    let settings = config.kafka.as_ref().unwrap();

    let publisher = KafkaPublisher::connect(settings).unwrap();
    let log = EventLog::default();
    let consumer = spawn_consumer(EventSource::kafka(settings).unwrap(), log.clone());

    let author_id = Uuid::new_v4();
    let receipt = publisher
        .publish(DomainEvent::Note {
            author_id,
            text: "integration".into(),
        })
        .await
        .expect("the broker acknowledges the publish");
    // A receipt names the position the record occupies, not merely that it was
    // sent: the topic was created on demand, so this is its first record.
    assert_eq!(receipt.offset, 0);
    assert_eq!(receipt.envelope.key, author_id.to_string());

    // Joining a consumer group takes a rebalance, so the event arrives shortly
    // after it was published rather than immediately.
    let consumed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(event) = log.recent(1).into_iter().next() {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the published event comes back off the topic");

    assert_eq!(consumed.envelope, receipt.envelope);
    assert_eq!(consumed.partition, receipt.partition);
    assert_eq!(consumed.offset, receipt.offset);
    assert_eq!(consumed.envelope.kind(), "note.published");

    // Stopping commits what was handled, so the same consumer group started
    // again resumes rather than replaying. The proof has two halves, because
    // "received nothing" is also what a consumer that never joined looks like:
    // a new event published afterwards must arrive, and it must be the only
    // thing that does.
    consumer.stop().await;
    let after_restart = EventLog::default();
    let restarted = spawn_consumer(EventSource::kafka(settings).unwrap(), after_restart.clone());
    let published_after_restart = publisher
        .publish(DomainEvent::Note {
            author_id,
            text: "published after the restart".into(),
        })
        .await
        .unwrap();
    assert_eq!(published_after_restart.offset, 1);

    let resumed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(event) = after_restart.recent(1).into_iter().next() {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the restarted consumer receives events published after it");

    assert_eq!(resumed.envelope.id, published_after_restart.envelope.id);
    assert_eq!(
        after_restart.consumed(),
        1,
        "the event consumed before the restart was replayed"
    );

    restarted.stop().await;
}

/// A record the application could never have written must not wedge the
/// projection. It is skipped and acknowledged, so everything published behind
/// it still arrives; the alternative is one malformed record stopping the
/// stream at that offset forever.
#[tokio::test]
async fn a_record_that_is_not_an_event_is_skipped_rather_than_retried_forever() {
    let Some(brokers) = env::var("KAFKA_BROKERS").ok() else {
        eprintln!("skipping Kafka integration test: KAFKA_BROKERS is not set");
        return;
    };
    let suffix = Uuid::new_v4();
    let topic = format!("luxor.test.poison.{suffix}");
    let config = Config::from_map(HashMap::from([
        ("KAFKA_BROKERS".into(), brokers.clone()),
        ("KAFKA_TOPIC".into(), topic.clone()),
        (
            "KAFKA_CONSUMER_GROUP".into(),
            format!("luxor-test-{suffix}"),
        ),
    ]))
    .unwrap();
    let settings = config.kafka.as_ref().unwrap();

    // Written with a bare producer, because this application's publisher is
    // incapable of producing the record this test needs.
    let raw: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .create()
        .unwrap();
    raw.send(
        FutureRecord::to(&topic)
            .key("not-an-event")
            .payload(r#"{"totally":"unexpected"}"#),
        Timeout::After(Duration::from_secs(10)),
    )
    .await
    .expect("the broker accepts the record regardless of its shape");

    let log = EventLog::default();
    let consumer = spawn_consumer(EventSource::kafka(settings).unwrap(), log.clone());
    let receipt = KafkaPublisher::connect(settings)
        .unwrap()
        .publish(DomainEvent::Note {
            author_id: Uuid::new_v4(),
            text: "published behind a poison record".into(),
        })
        .await
        .unwrap();
    // The undecodable record holds the offset before it.
    assert_eq!(receipt.offset, 1);

    let consumed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(event) = log.recent(1).into_iter().next() {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the consumer moves past the record it cannot decode");

    assert_eq!(consumed.envelope.id, receipt.envelope.id);
    assert_eq!(consumed.offset, 1);
    // Skipped, not projected: only the record that decoded is in the log.
    assert_eq!(log.consumed(), 1);

    consumer.stop().await;
}

async fn request_json(
    app: &axum::Router,
    uri: &str,
    body: &Value,
    cookie: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

fn response_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}
