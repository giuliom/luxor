use crate::{
    error::AppError,
    handlers::{auth, basic, cache, jobs},
    state::AppState,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{
        header::{self, HeaderName},
        HeaderMap, HeaderValue, Method, Request,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use opentelemetry::{global, propagation::Extractor};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{field, Level};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Clone)]
struct SecurityHeaders {
    hsts: bool,
}

pub fn app(state: AppState) -> Router {
    let request_id_header = HeaderName::from_static("x-request-id");
    let cors = cors_layer(&state);
    let body_limit = state.config.body_limit_bytes;
    let security_headers = SecurityHeaders {
        hsts: state.config.environment.is_production(),
    };

    let api = Router::new()
        .route("/health", get(basic::health))
        .route("/runtime", get(basic::runtime))
        .route("/hello", get(basic::hello))
        .route("/time", get(basic::time))
        .route("/telemetry/demo", get(basic::telemetry_demo))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/me", get(auth::me))
        .route(
            "/cache/demo",
            get(cache::get_demo)
                .put(cache::put_demo)
                .delete(cache::delete_demo),
        )
        .route("/jobs", post(jobs::enqueue))
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed);

    Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/script.js", get(script))
        .nest("/api", api)
        .with_state(state)
        .layer(DefaultBodyLimit::max(body_limit))
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
        "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'",
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
    if settings.hsts {
        insert_header(headers, "strict-transport-security", "max-age=31536000");
    }

    response
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

async fn api_not_found() -> AppError {
    AppError::NotFound("route")
}

async fn api_method_not_allowed() -> AppError {
    AppError::MethodNotAllowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cache::MemoryCache, config::Config, db, queue::MemoryQueue, state::AppState};
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

    fn test_app() -> Router {
        test_app_with_config(Config::from_map(HashMap::new()).unwrap())
    }

    fn test_app_with_config(config: Config) -> Router {
        let config = Arc::new(config);
        let pool = db::connect_lazy("postgres://luxor:luxor@localhost/luxor").unwrap();
        app(AppState::new(
            config,
            pool,
            Arc::new(MemoryCache::default()),
            Arc::new(MemoryQueue::default()),
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
        assert!(body_text(response).await.contains("Luxor backend console"));
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

        let production_config = Config::from_map(HashMap::from([
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
        ]))
        .unwrap();
        let production = test_app_with_config(production_config)
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            production
                .headers()
                .get("strict-transport-security")
                .unwrap(),
            "max-age=31536000"
        );
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
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(body_text(response)
            .await
            .contains(r#""code":"unauthorized""#));
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
        assert!(body.contains(r#""enabled":false"#));
        assert!(body.contains(r#""service_name":"luxor""#));
        assert!(body.contains(r#""request_id":""#));
        assert!(body.contains(r#""trace_id":null"#));
    }

    #[tokio::test]
    async fn standalone_mode_uses_memory_backends_without_authentication() {
        let config =
            Config::from_map(HashMap::from([("APP_STANDALONE".into(), "true".into())])).unwrap();
        let app = test_app_with_config(config);

        let runtime = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/runtime")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(runtime.status(), StatusCode::OK);
        let runtime_body = body_text(runtime).await;
        assert!(runtime_body.contains(r#""mode":"standalone""#));
        assert!(runtime_body.contains(r#""cache":"memory""#));

        let cache_write = app
            .clone()
            .oneshot(
                Request::put("/api/cache/demo")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":{"source":"memory"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cache_write.status(), StatusCode::OK);

        let register = app
            .oneshot(
                Request::post("/api/auth/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"email":"demo@example.com","password":"long-enough-password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(register.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(body_text(register)
            .await
            .contains(r#""code":"service_unavailable""#));
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
