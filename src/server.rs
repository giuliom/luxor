use crate::{
    config::HttpsEnforcement,
    error::AppError,
    handlers::{auth, basic, cache, demo, jobs, permissions},
    rate_limit::{self, RateLimitPolicy},
    state::AppState,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{
        header::{self, HeaderName},
        HeaderMap, HeaderValue, Method, Request, StatusCode,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use opentelemetry::{global, propagation::Extractor};
use std::time::Duration;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{field, Level};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Clone)]
struct SecurityHeaders {
    /// Prebuilt `Strict-Transport-Security` value, or `None` when the header
    /// is switched off. Built once at startup so the per-response path stays
    /// a header clone rather than a format.
    hsts: Option<HeaderValue>,
}

pub fn app(state: AppState) -> Router {
    let request_id_header = HeaderName::from_static("x-request-id");
    let cors = cors_layer(&state);
    let body_limit = state.config.body_limit_bytes;
    let request_timeout = Duration::from_secs(state.config.request_timeout_seconds);
    let hsts = &state.config.hsts;
    let security_headers = SecurityHeaders {
        hsts: hsts.enabled.then(|| {
            HeaderValue::try_from(hsts.header_value())
                .expect("HSTS directives are built from digits and ASCII keywords")
        }),
    };
    let https_enforcement = state.config.https_enforcement;
    let auth_rate_limit = RateLimitPolicy::new(&state, "auth", state.config.rate_limit.auth);
    let api_rate_limit = RateLimitPolicy::new(&state, "api", state.config.rate_limit.api);

    // The credential endpoints are the brute-force surface, so they carry
    // their own, much stricter budget on top of the API-wide one.
    let auth_routes = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route_layer(middleware::from_fn_with_state(
            auth_rate_limit,
            rate_limit::enforce,
        ));

    let api = Router::new()
        .route("/health", get(basic::health))
        .route("/runtime", get(basic::runtime))
        .route("/hello", get(basic::hello))
        .route("/time", get(basic::time))
        .route("/telemetry/demo", get(basic::telemetry_demo))
        .route("/telemetry/traces/{trace_id}", get(basic::trace))
        .route("/me", get(auth::me))
        .route("/permissions", get(permissions::matrix))
        .route("/demo/reports", get(demo::reports))
        .route("/demo/records", delete(demo::purge_records))
        .route(
            "/cache/demo",
            get(cache::get_demo)
                .put(cache::put_demo)
                .delete(cache::delete_demo),
        )
        .route("/jobs", post(jobs::enqueue))
        .merge(auth_routes)
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed)
        .layer(middleware::from_fn_with_state(
            api_rate_limit,
            rate_limit::enforce,
        ));

    Router::new()
        .route("/", get(index))
        .route("/favicon.svg", get(favicon))
        .route("/styles.css", get(styles))
        .route("/script.js", get(script))
        .route("/demo.wasm", get(wasm_demo))
        .nest("/api", api)
        .with_state(state)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(middleware::from_fn_with_state(
            request_timeout,
            enforce_request_timeout,
        ))
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("unknown");
                    let span = tracing::span!(
                        Level::INFO,
                        "http_request",
                        otel.name = %format!("{} {}", request.method(), request.uri().path()),
                        otel.kind = "server",
                        method = %request.method(),
                        uri = %request.uri(),
                        http.request.method = %request.method(),
                        url.path = %request.uri().path(),
                        http.response.status_code = field::Empty,
                        otel.status_code = field::Empty,
                        request_id = %request_id,
                    );
                    global::get_text_map_propagator(|propagator| {
                        span.set_parent(propagator.extract(&HeaderExtractor(request.headers())));
                    });
                    span
                })
                .on_response(
                    |response: &Response, _latency: std::time::Duration, span: &tracing::Span| {
                        span.record("http.response.status_code", response.status().as_u16());
                        if response.status().is_server_error() {
                            span.record("otel.status_code", "ERROR");
                        }
                    },
                ),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(middleware::from_fn_with_state(
            security_headers,
            apply_security_headers,
        ))
        // Outermost: a plaintext request is turned away before it reaches
        // routing, rate limiting, or body reading.
        .layer(middleware::from_fn_with_state(
            https_enforcement,
            enforce_https,
        ))
}

/// Bounds end-to-end request processing. Axum reads the body inside handler
/// extractors, so the deadline also covers clients that send a body slowly,
/// not just slow handlers.
async fn enforce_request_timeout(
    State(timeout): State<Duration>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let uri = request.uri().clone();
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_elapsed) => {
            tracing::warn!(%uri, timeout_seconds = timeout.as_secs(), "request timed out");
            AppError::RequestTimeout.into_response()
        }
    }
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

async fn apply_security_headers(
    State(settings): State<SecurityHeaders>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    insert_header(
        headers,
        "content-security-policy",
        // 'wasm-unsafe-eval' (CSP3) permits WebAssembly compilation while
        // still forbidding JavaScript eval.
        "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'",
    );
    insert_header(headers, "x-content-type-options", "nosniff");
    insert_header(headers, "x-frame-options", "DENY");
    insert_header(
        headers,
        "referrer-policy",
        "strict-origin-when-cross-origin",
    );
    insert_header(
        headers,
        "permissions-policy",
        "camera=(), geolocation=(), microphone=()",
    );
    if is_api {
        insert_header(headers, "cache-control", "no-store, max-age=0");
        insert_header(headers, "pragma", "no-cache");
    }
    if let Some(hsts) = &settings.hsts {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            hsts.clone(),
        );
    }

    response
}

/// Turns away requests the proxy in front of the app marked as plaintext.
///
/// This closes the case where a browser is talking to the deployment over
/// http — credentials in a request body, a refresh cookie replayed without
/// `Secure` taking effect. It does not, and cannot, defend against an attacker
/// who reaches the container directly: such a request either omits
/// `x-forwarded-proto` or forges it, which is why the deployment contract puts
/// a trusted proxy in front. That proxy must overwrite the header on every
/// request rather than pass a client-supplied one through.
async fn enforce_https(
    State(enforcement): State<HttpsEnforcement>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if enforcement == HttpsEnforcement::Off {
        return next.run(request).await;
    }
    let forwarded_proto = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        // A proxy may forward a comma-separated chain; the first entry is the
        // scheme the original client used.
        .and_then(|value| value.split(',').next())
        .map(str::trim);

    match forwarded_proto {
        Some(proto) if proto.eq_ignore_ascii_case("https") => next.run(request).await,
        // No proxy spoke for this request, so there is nothing to enforce
        // against. Failing closed here would take the deployment down the
        // moment a platform health check bypassed the proxy, and would buy
        // nothing: a request that reaches the app directly can set the header
        // to whatever it likes.
        None => next.run(request).await,
        Some(_) => plaintext_response(&request),
    }
}

fn plaintext_response(request: &Request<Body>) -> Response {
    // Safe methods are redirected so a person who typed the http URL lands on
    // the right page. Everything else is refused outright: replaying a POST at
    // a new location would resend a body that has already been exposed.
    if request.method() == Method::GET || request.method() == Method::HEAD {
        if let Some(redirect) = https_redirect(request) {
            return redirect;
        }
    }
    AppError::HttpsRequired.into_response()
}

fn https_redirect(request: &Request<Body>) -> Option<Response> {
    let host = request.headers().get(header::HOST)?.to_str().ok()?;
    // The Host header is client-controlled. Anything that could add a second
    // URL component (and so retarget the redirect) disqualifies it; a caller
    // that forges its own Host only ever redirects itself, but the value must
    // not be able to smuggle a path or userinfo into `Location`.
    if host.is_empty() || !host.is_ascii() || host.contains(['/', '\\', '@', '?', '#']) {
        return None;
    }
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |target| target.as_str());
    let location = HeaderValue::try_from(format!("https://{host}{path_and_query}")).ok()?;
    Some(
        (
            StatusCode::PERMANENT_REDIRECT,
            [(header::LOCATION, location)],
        )
            .into_response(),
    )
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let origins = state
        .config
        .cors_origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect::<Vec<_>>();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("traceparent"),
            HeaderName::from_static("tracestate"),
            HeaderName::from_static("baggage"),
        ])
        .allow_credentials(true)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../public/index.html"))
}

async fn favicon() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("image/svg+xml; charset=utf-8"),
        )],
        include_str!("../public/favicon.svg"),
    )
}

async fn styles() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/css"))],
        include_str!("../public/styles.css"),
    )
}

async fn script() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../public/script.js"),
    )
}

// The application/wasm content type is required for
// WebAssembly.instantiateStreaming.
async fn wasm_demo() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/wasm"),
        )],
        include_bytes!("../public/demo.wasm").as_slice(),
    )
}

async fn api_not_found() -> AppError {
    AppError::NotFound("route")
}

async fn api_method_not_allowed() -> AppError {
    AppError::MethodNotAllowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::JwtService,
        cache::MemoryCache,
        config::Config,
        db,
        models::Role,
        observability::{StoredSpan, TraceStore},
        queue::MemoryQueue,
        rate_limit::MemoryRateLimiter,
        state::AppState,
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use opentelemetry::{
        propagation::TextMapPropagator,
        trace::{TraceContextExt, TracerProvider as _},
    };
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use std::{collections::HashMap, sync::Arc};
    use tower::ServiceExt;
    use tracing_subscriber::prelude::*;
    use uuid::Uuid;

    fn test_app() -> Router {
        test_app_with_config(Config::from_map(HashMap::new()).unwrap())
    }

    fn test_app_with_config(config: Config) -> Router {
        test_app_with_trace_store(config, TraceStore::default())
    }

    /// A minimal valid production environment. Production refuses plaintext
    /// CORS origins, so the https one is part of what makes it valid.
    fn production_values() -> HashMap<String, String> {
        HashMap::from([
            ("APP_ENV".into(), "production".into()),
            (
                "DATABASE_URL".into(),
                "postgres://luxor:luxor@localhost/luxor".into(),
            ),
            ("REDIS_URL".into(), "redis://localhost:6379/".into()),
            (
                "JWT_SECRET".into(),
                "production-test-secret-at-least-32-characters".into(),
            ),
            ("CORS_ORIGINS".into(), "https://app.example.com".into()),
        ])
    }

    fn production_config() -> Config {
        Config::from_map(production_values()).unwrap()
    }

    fn test_app_with_trace_store(config: Config, trace_store: TraceStore) -> Router {
        let config = Arc::new(config);
        let pool = db::connect_lazy("postgres://luxor:luxor@localhost/luxor").unwrap();
        app(AppState::new(
            config,
            pool,
            Arc::new(MemoryCache::default()),
            Arc::new(MemoryQueue::default()),
            Arc::new(MemoryRateLimiter::default()),
            trace_store,
        ))
    }

    #[tokio::test]
    async fn serves_index_html() {
        let response = test_app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_header_starts_with(&response, header::CONTENT_TYPE.as_str(), "text/html");
        let body = body_text(response).await;
        assert!(body.contains("Luxor backend console"));
        assert!(body.contains(r#"rel="icon" href="/favicon.svg""#));
    }

    #[tokio::test]
    async fn serves_svg_favicon() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/favicon.svg")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_header_starts_with(&response, header::CONTENT_TYPE.as_str(), "image/svg+xml");
        assert!(body_text(response).await.contains("<svg"));
    }

    #[tokio::test]
    async fn returns_health_json_with_a_request_id() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

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
        assert_header_starts_with(&response, header::CONTENT_TYPE.as_str(), "application/json");
        assert_eq!(
            body_text(response).await,
            r#"{"status":"ok","service":"luxor"}"#
        );
    }

    #[tokio::test]
    async fn enables_hsts_only_in_production() {
        let development = test_app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(!development
            .headers()
            .contains_key("strict-transport-security"));

        let production = test_app_with_config(production_config())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
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
        let mut values = production_values();
        values.insert("HSTS_MAX_AGE_SECONDS".into(), "63072000".into());
        values.insert("HSTS_PRELOAD".into(), "true".into());
        let response = test_app_with_config(Config::from_map(values).unwrap())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("strict-transport-security").unwrap(),
            "max-age=63072000; includeSubDomains; preload"
        );

        // Turning the header off is what lets an operator release browsers
        // that already cached a policy (paired with max-age=0 beforehand).
        let mut disabled = production_values();
        disabled.insert("HSTS_ENABLED".into(), "false".into());
        let response = test_app_with_config(Config::from_map(disabled).unwrap())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(!response.headers().contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn https_enforcement_turns_away_proxied_plaintext() {
        let app = test_app_with_config(production_config());

        // A safe method is redirected to the same target over https.
        let redirected = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health?probe=1")
                    .header("x-forwarded-proto", "http")
                    .header(header::HOST, "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
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
        let hostile_host = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header("x-forwarded-proto", "http")
                    .header(header::HOST, "app.example.com/@evil.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(hostile_host.status(), StatusCode::FORBIDDEN);
        assert!(!hostile_host.headers().contains_key(header::LOCATION));
    }

    #[tokio::test]
    async fn https_enforcement_admits_tls_and_unproxied_requests() {
        let app = test_app_with_config(production_config());

        for proto in ["https", "https,http"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/health")
                        .header("x-forwarded-proto", proto)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "proto {proto:?}");
        }

        // No proxy spoke for this request, so there is nothing to enforce
        // against; failing closed here would break platform health checks
        // that bypass the proxy without buying any protection.
        let unproxied = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unproxied.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn https_enforcement_is_off_outside_production() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header("x-forwarded-proto", "http")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn preserves_or_assigns_the_request_id() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/time")
                    .header("x-request-id", "test-correlation-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("x-request-id").unwrap(),
            "test-correlation-id"
        );
    }

    #[tokio::test]
    async fn rejects_protected_routes_without_a_bearer_token() {
        for (method, uri) in [
            ("GET", "/api/me"),
            ("GET", "/api/demo/reports"),
            ("DELETE", "/api/demo/records"),
            ("GET", "/api/cache/demo"),
            ("POST", "/api/jobs"),
        ] {
            let response = test_app()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
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

    /// Mints a bearer token compatible with `test_app`, which signs with the
    /// development JWT secret. The demo endpoints check permissions against
    /// the role claim alone, so the user does not need to exist.
    fn bearer(role: Role) -> String {
        let config = Config::from_map(HashMap::new()).unwrap();
        let token = JwtService::from_config(&config)
            .issue(Uuid::new_v4(), role)
            .unwrap();
        format!("Bearer {token}")
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        authorization: Option<&str>,
        body: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(authorization) = authorization {
            builder = builder.header(header::AUTHORIZATION, authorization);
        }
        let body = match body {
            Some(json) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(json.to_owned())
            }
            None => Body::empty(),
        };
        app.clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn permission_matrix_is_public_and_reports_the_fixed_grants() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/permissions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(body.contains(
            r#""roles":{"admin":["reports.view","records.purge"],"user":["reports.view"]}"#
        ));
        assert!(body.contains(r#""name":"reports.view""#));
        assert!(body.contains(r#""name":"records.purge""#));
    }

    // The grants are part of the authorization contract; the write surface
    // must not exist at all, and the role stored at registration must not be
    // editable afterwards.
    #[tokio::test]
    async fn matrix_and_role_write_endpoints_do_not_exist() {
        let app = test_app();
        let admin = bearer(Role::Admin);

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

    #[tokio::test]
    async fn permission_grants_control_the_demo_endpoints() {
        let app = test_app();
        let admin = bearer(Role::Admin);
        let user = bearer(Role::User);

        // The user role reads reports but cannot purge.
        let reports = send(&app, "GET", "/api/demo/reports", Some(&user), None).await;
        assert_eq!(reports.status(), StatusCode::OK);
        assert!(body_text(reports)
            .await
            .contains(r#""required_permission":"reports.view""#));

        let denied = send(&app, "DELETE", "/api/demo/records", Some(&user), None).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let denied_body = body_text(denied).await;
        assert!(denied_body.contains(r#""code":"forbidden""#));
        assert!(denied_body.contains("records.purge"));

        let allowed = send(&app, "DELETE", "/api/demo/records", Some(&admin), None).await;
        assert_eq!(allowed.status(), StatusCode::OK);
        assert!(body_text(allowed).await.contains(r#""simulated":true"#));
    }

    #[tokio::test]
    async fn accepts_a_case_insensitive_bearer_scheme() {
        let app = test_app();
        let authorization = bearer(Role::User).replace("Bearer", "bearer");
        let response = send(&app, "GET", "/api/demo/reports", Some(&authorization), None).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn maps_json_body_rejections_to_the_error_contract() {
        let app = test_app();
        let user = bearer(Role::User);

        // A JSON body without the JSON content type is 415, not a generic 400.
        let missing_content_type = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/jobs")
                    .header(header::AUTHORIZATION, &user)
                    .body(Body::from(r#"{"kind":"audit_event","action":"x"}"#))
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

        // Deserialization failures name the problem instead of a generic
        // "invalid JSON" message.
        let unknown_variant = send(
            &app,
            "POST",
            "/api/jobs",
            Some(&user),
            Some(r#"{"kind":"reboot_world"}"#),
        )
        .await;
        assert_eq!(unknown_variant.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(unknown_variant).await.contains("reboot_world"));
    }

    #[tokio::test]
    async fn auth_rate_limit_rejects_excess_attempts_with_retry_headers() {
        let config = Config::from_map(HashMap::from([(
            "RATE_LIMIT_AUTH_MAX_REQUESTS".into(),
            "2".into(),
        )]))
        .unwrap();
        let app = test_app_with_config(config);

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
    async fn api_rate_limit_meters_api_routes_but_not_static_assets() {
        let config = Config::from_map(HashMap::from([(
            "RATE_LIMIT_API_MAX_REQUESTS".into(),
            "2".into(),
        )]))
        .unwrap();
        let app = test_app_with_config(config);

        for _ in 0..2 {
            let response = send(&app, "GET", "/api/time", None, None).await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        let limited = send(&app, "GET", "/api/time", None, None).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        // The embedded frontend assets stay reachable.
        let index = send(&app, "GET", "/", None, None).await;
        assert_eq!(index.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rate_limiting_can_be_disabled_outside_production() {
        let config = Config::from_map(HashMap::from([
            ("RATE_LIMIT_ENABLED".into(), "false".into()),
            ("RATE_LIMIT_API_MAX_REQUESTS".into(), "1".into()),
        ]))
        .unwrap();
        let app = test_app_with_config(config);
        for _ in 0..3 {
            let response = send(&app, "GET", "/api/time", None, None).await;
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    async fn get_time_forwarded_for(app: &Router, forwarded_for: &str) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/api/time")
                    .header("x-forwarded-for", forwarded_for)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn forwarded_clients_are_limited_independently() {
        let config = Config::from_map(HashMap::from([
            ("CLIENT_IP_SOURCE".into(), "x-forwarded-for".into()),
            ("RATE_LIMIT_API_MAX_REQUESTS".into(), "1".into()),
        ]))
        .unwrap();
        let app = test_app_with_config(config);

        let first = get_time_forwarded_for(&app, "198.51.100.7").await;
        assert_eq!(first.status(), StatusCode::OK);
        let repeat = get_time_forwarded_for(&app, "198.51.100.7").await;
        assert_eq!(repeat.status(), StatusCode::TOO_MANY_REQUESTS);

        // A different client has its own budget.
        let other = get_time_forwarded_for(&app, "198.51.100.8").await;
        assert_eq!(other.status(), StatusCode::OK);

        // Prepending spoofed entries does not mint a fresh identity: only
        // the rightmost, proxy-appended address counts.
        let spoofed = get_time_forwarded_for(&app, "203.0.113.99, 198.51.100.8").await;
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

        let response = app
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(body_text(response)
            .await
            .contains(r#""code":"request_timeout""#));
    }

    #[tokio::test]
    async fn returns_named_and_default_hello_json() {
        for (uri, expected) in [
            ("/api/hello?name=Ada", r#"{"message":"Hello, Ada!"}"#),
            ("/api/hello", r#"{"message":"Hello, world!"}"#),
        ] {
            let response = test_app()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body_text(response).await, expected);
        }
    }

    #[tokio::test]
    async fn serves_the_wasm_demo_module_for_streaming_compilation() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/demo.wasm")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        // WebAssembly.instantiateStreaming requires this exact content type.
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/wasm"
        );
        // The page compiles the module under the site CSP, which must allow
        // WebAssembly compilation without allowing JavaScript eval.
        assert!(response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("script-src 'self' 'wasm-unsafe-eval'"));
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(bytes.starts_with(b"\0asm"));
    }

    #[tokio::test]
    async fn telemetry_demo_reports_disabled_export_without_a_tracer() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/telemetry/demo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(body.contains(r#""otlp_enabled":false"#));
        assert!(body.contains(r#""service_name":"luxor""#));
        assert!(body.contains(r#""request_id":""#));
        assert!(body.contains(r#""trace_id":null"#));
    }

    #[tokio::test]
    async fn trace_endpoint_validates_ids_and_serves_stored_spans() {
        let trace_id = "0af7651916cd43dd8448eb211c80319c";
        let trace_store = TraceStore::default();
        trace_store.record(StoredSpan {
            trace_id: trace_id.to_owned(),
            span_id: "b7ad6b7169203331".to_owned(),
            parent_span_id: None,
            name: "GET /api/telemetry/demo".to_owned(),
            kind: "server",
            status: "unset",
            start_unix_ms: 1_700_000_000_000.0,
            duration_ms: 32.5,
        });
        let app = test_app_with_trace_store(Config::from_map(HashMap::new()).unwrap(), trace_store);

        let invalid = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/telemetry/traces/not-a-trace-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

        let unknown = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/telemetry/traces/ffffffffffffffffffffffffffffffff")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        let found = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/telemetry/traces/{trace_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(found.status(), StatusCode::OK);
        let body = body_text(found).await;
        assert!(body.contains(r#""trace_id":"0af7651916cd43dd8448eb211c80319c""#));
        assert!(body.contains(r#""name":"GET /api/telemetry/demo""#));
        assert!(body.contains(r#""kind":"server""#));
    }

    #[tokio::test]
    async fn runtime_reports_the_active_backends() {
        let development = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/runtime")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(development.status(), StatusCode::OK);
        assert_eq!(
            body_text(development).await,
            r#"{"database":"embedded-postgresql","cache":"memory","queue":"memory"}"#
        );

        let production = test_app_with_config(production_config())
            .oneshot(
                Request::builder()
                    .uri("/api/runtime")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(production.status(), StatusCode::OK);
        assert_eq!(
            body_text(production).await,
            r#"{"database":"postgresql","cache":"redis","queue":"redis"}"#
        );
    }

    #[test]
    fn header_extractor_accepts_w3c_trace_context() {
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
        let tracer = provider.tracer("luxor-test");
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

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn assert_header_starts_with(
        response: &axum::response::Response,
        header_name: &str,
        expected_prefix: &str,
    ) {
        let value = response
            .headers()
            .get(header_name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(value.starts_with(expected_prefix));
    }
}
