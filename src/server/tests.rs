//! The server's contract, exercised through the foundation's own routes: the
//! middleware stack, the API fallbacks and rate limits, authentication, and the
//! extension points an application builds on. The console and the demo
//! endpoints are tested in [`crate::demo`].

use super::*;
use crate::{
    access::{AccessRole, Role},
    auth::AuthUser,
    config::Config,
    routes,
    testing::{body_json, body_text, production_values, send, send_with, TestApp},
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use tower::ServiceExt;

/// The foundation's routes with nothing else mounted: what an application
/// that drops the demo starts from.
fn core_router() -> Router {
    let core = TestApp::new().state();
    app(core.clone(), Routes::new().api(routes::api(&core)))
}

#[tokio::test]
async fn returns_health_json_with_a_request_id() {
    let response = send(&TestApp::new().router(), "GET", "/api/health", None, None).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-request-id"));
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store, max-age=0"
    );
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    assert!(response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    assert_eq!(
        body_text(response).await,
        format!(
            r#"{{"status":"ok","service":"{}"}}"#,
            env!("CARGO_PKG_NAME")
        )
    );
}

#[tokio::test]
async fn the_health_check_names_the_configured_application() {
    let router = TestApp::new().env("APP_NAME", "orders-api").router();
    let body = body_json(send(&router, "GET", "/api/health", None, None).await).await;
    assert_eq!(body["service"], "orders-api");
}

#[tokio::test]
async fn enables_hsts_only_in_production() {
    let development = send(&TestApp::new().router(), "GET", "/api/health", None, None).await;
    assert!(!development
        .headers()
        .contains_key("strict-transport-security"));

    let production = send(
        &TestApp::production().router(),
        "GET",
        "/api/health",
        None,
        None,
    )
    .await;
    assert_eq!(
        production
            .headers()
            .get("strict-transport-security")
            .unwrap(),
        "max-age=31536000; includeSubDomains"
    );
}

#[tokio::test]
async fn hsts_directives_follow_configuration() {
    let preloaded = TestApp::production()
        .env("HSTS_MAX_AGE_SECONDS", "63072000")
        .env("HSTS_PRELOAD", "true")
        .router();
    let response = send(&preloaded, "GET", "/api/health", None, None).await;
    assert_eq!(
        response.headers().get("strict-transport-security").unwrap(),
        "max-age=63072000; includeSubDomains; preload"
    );

    // Turning the header off is what lets an operator release browsers
    // that already cached a policy (paired with max-age=0 beforehand).
    let disabled = TestApp::production().env("HSTS_ENABLED", "false").router();
    let response = send(&disabled, "GET", "/api/health", None, None).await;
    assert!(!response.headers().contains_key("strict-transport-security"));
}

#[tokio::test]
async fn https_enforcement_turns_away_proxied_plaintext() {
    let app = TestApp::production().router();

    // A safe method is redirected to the same target over https.
    let redirected = send_with(
        &app,
        "GET",
        "/api/health?probe=1",
        &[
            (HeaderName::from_static("x-forwarded-proto"), "http"),
            (header::HOST, "app.example.com"),
        ],
    )
    .await;
    assert_eq!(redirected.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        redirected.headers().get(header::LOCATION).unwrap(),
        "https://app.example.com/api/health?probe=1"
    );

    // A credential-bearing method is refused outright rather than
    // redirected: the body has already crossed the wire in the clear.
    let refused = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("x-forwarded-proto", "http")
                .header(header::HOST, "app.example.com")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"a@b.com","password":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(body_text(refused)
        .await
        .contains(r#""code":"https_required""#));

    // A Host that could retarget the redirect is refused instead.
    let hostile_host = send_with(
        &app,
        "GET",
        "/api/health",
        &[
            (HeaderName::from_static("x-forwarded-proto"), "http"),
            (header::HOST, "app.example.com/@evil.test"),
        ],
    )
    .await;
    assert_eq!(hostile_host.status(), StatusCode::FORBIDDEN);
    assert!(!hostile_host.headers().contains_key(header::LOCATION));
}

#[tokio::test]
async fn https_enforcement_admits_tls_and_unproxied_requests() {
    let app = TestApp::production().router();

    for proto in ["https", "https,http"] {
        let response = send_with(
            &app,
            "GET",
            "/api/health",
            &[(HeaderName::from_static("x-forwarded-proto"), proto)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "proto {proto:?}");
    }

    // No proxy spoke for this request, so there is nothing to enforce
    // against; failing closed here would break platform health checks
    // that bypass the proxy without buying any protection.
    let unproxied = send(&app, "GET", "/api/health", None, None).await;
    assert_eq!(unproxied.status(), StatusCode::OK);
}

#[tokio::test]
async fn https_enforcement_is_off_outside_production() {
    let response = send_with(
        &TestApp::new().router(),
        "GET",
        "/api/health",
        &[(HeaderName::from_static("x-forwarded-proto"), "http")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn preserves_or_assigns_the_request_id() {
    let response = send_with(
        &TestApp::new().router(),
        "GET",
        "/api/health",
        &[(
            HeaderName::from_static("x-request-id"),
            "test-correlation-id",
        )],
    )
    .await;
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "test-correlation-id"
    );
}

#[tokio::test]
async fn unknown_api_routes_and_methods_follow_the_error_contract() {
    let app = TestApp::new().router();

    let missing = send(&app, "GET", "/api/no-such-route", None, None).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert!(body_text(missing).await.contains(r#""code":"not_found""#));

    let wrong_method = send(&app, "DELETE", "/api/health", None, None).await;
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(body_text(wrong_method)
        .await
        .contains(r#""code":"method_not_allowed""#));
}

#[tokio::test]
async fn rejects_protected_routes_without_a_bearer_token() {
    let mut protected = vec![("GET", "/api/me")];
    if cfg!(feature = "realtime") {
        protected.push(("POST", "/api/realtime/ticket"));
    }
    let app = TestApp::new().router();
    for (method, uri) in protected {
        let response = send(&app, method, uri, None, None).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
        assert!(body_text(response)
            .await
            .contains(r#""code":"unauthorized""#));
    }
}

/// A probe route that answers with the caller's identity, so the bearer
/// extractor can be exercised without a database.
fn whoami() -> Router<crate::app::State> {
    Router::new().route(
        "/whoami",
        get(|user: AuthUser| async move { user.role.name() }),
    )
}

#[tokio::test]
async fn accepts_a_case_insensitive_bearer_scheme() {
    let test_app = TestApp::new().api(whoami());
    let authorization = test_app.bearer(Role::Admin).replace("Bearer", "bearer");
    let app = test_app.router();
    let response = send(&app, "GET", "/api/whoami", Some(&authorization), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, "admin");

    for malformed in ["Basic abc", "Bearer", "Bearer ", "token-without-scheme"] {
        let response = send(&app, "GET", "/api/whoami", Some(malformed), None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{malformed:?}");
    }
}

/// A token signed for another application (here, another `APP_NAME` with the
/// same secret) is not accepted, because the issuer is checked.
#[tokio::test]
async fn tokens_issued_under_another_application_name_are_refused() {
    let other = TestApp::new().env("APP_NAME", "another-application");
    let foreign = other.bearer(Role::User);
    let app = TestApp::new().api(whoami()).router();
    let response = send(&app, "GET", "/api/whoami", Some(&foreign), None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn permission_matrix_is_public_and_reports_the_declared_grants() {
    let response = send(
        &TestApp::new().router(),
        "GET",
        "/api/permissions",
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    for &role in Role::ALL {
        let expected = role
            .permissions()
            .iter()
            .map(|permission| serde_json::to_value(permission).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            body["roles"][role.name()],
            serde_json::Value::from(expected)
        );
    }
    assert_eq!(
        body["catalog"].as_array().unwrap().len(),
        <crate::access::Permission as crate::access::AccessPermission>::ALL.len()
    );
}

// The grants are part of the authorization contract; the write surface
// must not exist at all, and the role stored at registration must not be
// editable afterwards.
#[tokio::test]
async fn matrix_and_role_write_endpoints_do_not_exist() {
    let test_app = TestApp::new();
    let admin = test_app.bearer(Role::Admin);
    let app = test_app.router();

    let matrix_edit = send(
        &app,
        "PUT",
        "/api/permissions/user",
        Some(&admin),
        Some(r#"{"permissions":[]}"#),
    )
    .await;
    assert_eq!(matrix_edit.status(), StatusCode::NOT_FOUND);

    let role_switch = send(
        &app,
        "PUT",
        "/api/me/role",
        Some(&admin),
        Some(r#"{"role":"admin"}"#),
    )
    .await;
    assert_eq!(role_switch.status(), StatusCode::NOT_FOUND);
}

#[cfg(feature = "realtime")]
#[tokio::test]
async fn realtime_tickets_are_short_lived_and_name_their_endpoint() {
    let test_app = TestApp::new();
    let user = test_app.bearer(Role::User);
    let response = send(
        &test_app.router(),
        "POST",
        "/api/realtime/ticket",
        Some(&user),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["expires_in"], 30);
    assert_eq!(body["websocket_path"], "/api/realtime/ws");
    // Long enough to be a 256-bit random value, and not the access token.
    assert!(body["ticket"].as_str().unwrap().len() >= 40);
}

/// CORS never runs for a WebSocket handshake, so the endpoint checks the
/// origin itself; this is the cross-site WebSocket hijacking case.
#[cfg(feature = "realtime")]
#[tokio::test]
async fn realtime_upgrades_are_refused_from_a_foreign_origin() {
    let response = send_with(
        &TestApp::production().router(),
        "GET",
        "/api/realtime/ws?ticket=stolen",
        &[
            (header::ORIGIN, "https://evil.test"),
            (header::HOST, "app.example.com"),
        ],
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(body_text(response).await.contains(r#""code":"forbidden""#));
}

/// A same-origin request gets past the origin check and is then turned
/// away by the upgrade extractor — in the JSON shape the rest of the API
/// uses, rather than axum's plain-text rejection.
#[cfg(feature = "realtime")]
#[tokio::test]
async fn realtime_upgrades_without_websocket_headers_follow_the_error_contract() {
    let response = send_with(
        &TestApp::new().router(),
        "GET",
        "/api/realtime/ws",
        &[
            (header::ORIGIN, "http://127.0.0.1:8080"),
            (header::HOST, "127.0.0.1:8080"),
        ],
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(response)
        .await
        .contains(r#""code":"bad_request""#));
}

#[tokio::test]
async fn maps_json_body_rejections_to_the_error_contract() {
    let app = TestApp::new().router();

    // A JSON body without the JSON content type is 415, not a generic 400.
    let missing_content_type = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .body(Body::from(r#"{"email":"a@b.com","password":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        missing_content_type.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert!(body_text(missing_content_type)
        .await
        .contains(r#""code":"unsupported_media_type""#));

    // A body that parses but does not match the target type is a 400 that
    // names the class of problem — and never quotes the caller's own input
    // back at it, which is what would make the response a reflection.
    let mismatched = send(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(r#"{"reboot_world":true}"#),
    )
    .await;
    assert_eq!(mismatched.status(), StatusCode::BAD_REQUEST);
    let body = body_text(mismatched).await;
    assert!(body.contains(r#""code":"bad_request""#));
    assert!(body.contains("does not match the schema"));
    assert!(!body.contains("reboot_world"), "the body was echoed back");

    // Malformed JSON is reported as such, and is likewise not echoed.
    let malformed = send(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(r#"{"email":"leaked@example.com","#),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let body = body_text(malformed).await;
    assert!(body.contains("not valid JSON"));
    assert!(
        !body.contains("leaked@example.com"),
        "the body was echoed back"
    );
}

/// API responses carry credentials next to request-influenced content, so
/// they are never compressed (the BREACH precondition).
#[tokio::test]
async fn api_responses_are_not_compressed() {
    let response = send_with(
        &TestApp::new().router(),
        "GET",
        "/api/permissions",
        &[(header::ACCEPT_ENCODING, "gzip")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
}

#[tokio::test]
async fn auth_rate_limit_rejects_excess_attempts_with_retry_headers() {
    let app = TestApp::new()
        .env("RATE_LIMIT_AUTH_MAX_REQUESTS", "2")
        .router();

    // Refresh without a cookie fails authentication before touching the
    // database, so the first two attempts get 401 and the third trips
    // the auth quota.
    for _ in 0..2 {
        let response = send(&app, "POST", "/api/auth/refresh", None, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let limited = send(&app, "POST", "/api/auth/refresh", None, None).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers().get("ratelimit-limit").unwrap(), "2");
    assert_eq!(limited.headers().get("ratelimit-remaining").unwrap(), "0");
    assert!(limited.headers().contains_key("ratelimit-reset"));
    assert!(limited.headers().contains_key(header::RETRY_AFTER));
    assert!(body_text(limited)
        .await
        .contains(r#""code":"rate_limited""#));
}

#[tokio::test]
async fn api_rate_limit_meters_api_routes_but_not_site_routes() {
    let app = TestApp::new()
        .env("RATE_LIMIT_API_MAX_REQUESTS", "2")
        .site(Router::new().route("/page", get(|| async { "page" })))
        .router();

    for _ in 0..2 {
        let response = send(&app, "GET", "/api/health", None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let limited = send(&app, "GET", "/api/health", None, None).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

    // Routes outside /api stay reachable.
    let page = send(&app, "GET", "/page", None, None).await;
    assert_eq!(page.status(), StatusCode::OK);
}

#[tokio::test]
async fn rate_limiting_can_be_disabled_outside_production() {
    let app = TestApp::new()
        .env("RATE_LIMIT_ENABLED", "false")
        .env("RATE_LIMIT_API_MAX_REQUESTS", "1")
        .router();
    for _ in 0..3 {
        let response = send(&app, "GET", "/api/health", None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

async fn get_health_forwarded_for(app: &Router, forwarded_for: &str) -> Response {
    send_with(
        app,
        "GET",
        "/api/health",
        &[(HeaderName::from_static("x-forwarded-for"), forwarded_for)],
    )
    .await
}

#[tokio::test]
async fn forwarded_clients_are_limited_independently() {
    let app = TestApp::new()
        .env("CLIENT_IP_SOURCE", "x-forwarded-for")
        .env("RATE_LIMIT_API_MAX_REQUESTS", "1")
        .router();

    let first = get_health_forwarded_for(&app, "198.51.100.7").await;
    assert_eq!(first.status(), StatusCode::OK);
    let repeat = get_health_forwarded_for(&app, "198.51.100.7").await;
    assert_eq!(repeat.status(), StatusCode::TOO_MANY_REQUESTS);

    // A different client has its own budget.
    let other = get_health_forwarded_for(&app, "198.51.100.8").await;
    assert_eq!(other.status(), StatusCode::OK);

    // Prepending spoofed entries does not mint a fresh identity: only
    // the rightmost, proxy-appended address counts.
    let spoofed = get_health_forwarded_for(&app, "203.0.113.99, 198.51.100.8").await;
    assert_eq!(spoofed.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(start_paused = true)]
async fn requests_exceeding_the_deadline_return_the_timeout_contract() {
    let app = Router::new()
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "done"
            }),
        )
        .layer(middleware::from_fn_with_state(
            Duration::from_secs(1),
            enforce_request_timeout,
        ));

    let response = send(&app, "GET", "/slow", None, None).await;
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(body_text(response)
        .await
        .contains(r#""code":"request_timeout""#));
}

/// The server without the demo: exactly the foundation's routes.
#[tokio::test]
async fn the_foundation_serves_its_routes_without_an_application_layer() {
    let app = core_router();
    let health = send(&app, "GET", "/api/health", None, None).await;
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(
        health.headers().get("content-security-policy").unwrap(),
        DEFAULT_CONTENT_SECURITY_POLICY
    );
    // Nothing outside /api is served.
    let root = send(&app, "GET", "/", None, None).await;
    assert_eq!(root.status(), StatusCode::NOT_FOUND);
}

/// An application serves its own state type. The built-in routes and
/// extractors read the foundation's state out of it; its own handlers read
/// their part, and its routes sit under /api with the same rate limit.
#[tokio::test]
async fn applications_extend_the_server_with_their_own_state_and_routes() {
    #[derive(Clone)]
    struct Custom {
        core: AppState,
        greeting: &'static str,
    }
    impl FromRef<Custom> for AppState {
        fn from_ref(state: &Custom) -> Self {
            state.core.clone()
        }
    }

    let test_app = TestApp::new().env("RATE_LIMIT_API_MAX_REQUESTS", "3");
    let user = test_app.bearer(Role::User);
    let core = test_app.state();
    let routes = Routes::new()
        .api(routes::api(&core))
        .api(Router::new().route(
            "/greeting",
            get(|State(custom): State<Custom>, _user: AuthUser| async move { custom.greeting }),
        ))
        .content_security_policy("default-src 'none'");
    let app = app(
        Custom {
            core,
            greeting: "hello",
        },
        routes,
    );

    let greeting = send(&app, "GET", "/api/greeting", Some(&user), None).await;
    assert_eq!(greeting.status(), StatusCode::OK);
    assert_eq!(
        greeting.headers().get("content-security-policy").unwrap(),
        "default-src 'none'"
    );
    assert_eq!(body_text(greeting).await, "hello");

    let unauthenticated = send(&app, "GET", "/api/greeting", None, None).await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let health = send(&app, "GET", "/api/health", None, None).await;
    assert_eq!(health.status(), StatusCode::OK);
    // Three requests so far: the fourth trips the shared API budget.
    let limited = send(&app, "GET", "/api/greeting", Some(&user), None).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn production_fixture_is_a_valid_configuration() {
    assert!(Config::from_map(production_values()).is_ok());
}

#[cfg(feature = "otel")]
#[test]
fn header_extractor_accepts_w3c_trace_context() {
    use opentelemetry::{
        propagation::TextMapPropagator,
        trace::{TraceContextExt, TracerProvider as _},
    };
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::prelude::*;

    let mut headers = HeaderMap::new();
    headers.insert(
        "traceparent",
        HeaderValue::from_static("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
    );
    let context = TraceContextPropagator::new().extract(&HeaderExtractor(&headers));
    let span = context.span();
    let span_context = span.span_context();

    assert_eq!(
        span_context.trace_id().to_string(),
        "0af7651916cd43dd8448eb211c80319c"
    );
    assert!(span_context.is_remote());
    assert!(span_context.is_sampled());

    let provider = opentelemetry_sdk::trace::TracerProvider::builder().build();
    let tracer = provider.tracer("test");
    let subscriber =
        tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));
    tracing::subscriber::with_default(subscriber, || {
        let server_span = tracing::info_span!("http_request");
        server_span.set_parent(context);
        let server_context = server_span.context();
        let server_otel_span = server_context.span();
        assert_eq!(
            server_otel_span.span_context().trace_id().to_string(),
            "0af7651916cd43dd8448eb211c80319c"
        );
    });
}
