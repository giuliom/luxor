use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use luxor::{
    cache::{Cache, MemoryCache, RedisCache},
    config::Config,
    db,
    observability::TraceStore,
    queue::{Job, MemoryQueue, Queue, RedisQueue},
    server,
    state::AppState,
};
use redis::AsyncCommands;
use secrecy::SecretString;
use serde_json::{json, Value};
use std::{collections::HashMap, env, sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

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
        ]))
        .unwrap(),
    );
    let app = server::app(AppState::new(
        config,
        pool.clone(),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryQueue::default()),
        TraceStore::default(),
    ));
    let email = format!("integration-{}@example.com", Uuid::new_v4());
    let credentials = json!({"email": email, "password": "integration-password"});

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
        json!({"email": admin_email, "password": "integration-password", "role": "admin"});
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

    // Self-service role switch: the user promotes themselves to admin and
    // receives a fresh access token carrying the new role claim.
    let promoted = app
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
    assert_eq!(promoted.status(), StatusCode::OK);
    let promoted_body = response_json(promoted).await;
    assert_eq!(promoted_body["user"]["role"], "admin");
    let promoted_token = promoted_body["access_token"].as_str().unwrap();

    let purge_after_promotion = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/demo/records")
                .header(header::AUTHORIZATION, format!("Bearer {promoted_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(purge_after_promotion.status(), StatusCode::OK);

    // The pre-switch token still carries the old role claim until it expires.
    let stale_token_purge = app
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
    assert_eq!(stale_token_purge.status(), StatusCode::FORBIDDEN);

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
    let cache = RedisCache::new(manager.clone(), namespace.clone());
    let queue = RedisQueue::new(manager, queue_key.clone());

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

    let keys = [format!("{namespace}:sample"), queue_key];
    let _: usize = connection.del(&keys).await.unwrap();
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
