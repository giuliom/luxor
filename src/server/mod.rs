//! The HTTP server: the middleware stack every response passes through, and
//! the assembly of an application's [`Routes`] into one router.
//!
//! [`app`] is generic over the router state, so an application serves its own
//! state type; the only requirement is that the foundation's [`AppState`] can
//! be read from it (`AppState: FromRef<S>`), which is what the built-in routes
//! and extractors use.

mod settings;
#[cfg(test)]
mod tests;

pub use settings::{HstsSettings, HttpSettings, HttpsEnforcement};

use crate::{
    config::Config,
    error::AppError,
    rate_limit::{self, RateLimitPolicy},
    state::AppState,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, FromRef, State},
    http::{
        header::{self, HeaderName},
        HeaderMap, HeaderValue, Method, Request, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use std::time::Duration;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{field, Level};

/// The Content-Security-Policy sent unless the application sets its own
/// through [`Routes::content_security_policy`]: everything same-origin, no
/// inline script, no `eval`, no framing.
pub const DEFAULT_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'";

/// Everything an application serves, as it hands it to [`app`].
pub struct Routes<S> {
    api: Router<S>,
    site: Router<S>,
    content_security_policy: HeaderValue,
}

impl<S> Default for Routes<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            api: Router::new(),
            site: Router::new(),
            content_security_policy: HeaderValue::from_static(DEFAULT_CONTENT_SECURITY_POLICY),
        }
    }
}

impl<S> Routes<S>
where
    S: Clone + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds routes under `/api`, with paths relative to it: `/orders` serves
    /// `/api/orders`. They share the API-wide rate limit, the JSON 404 and 405
    /// fallbacks, and `Cache-Control: no-store`, so they must not set a
    /// fallback of their own.
    pub fn api(mut self, routes: Router<S>) -> Self {
        self.api = self.api.merge(routes);
        self
    }

    /// Adds routes outside `/api`: pages, static files, anything a browser
    /// loads directly. They are not rate limited.
    pub fn site(mut self, routes: Router<S>) -> Self {
        self.site = self.site.merge(routes);
        self
    }

    /// Replaces the Content-Security-Policy every response carries. Panics on
    /// a value that is not a valid header value, which a startup test catches.
    pub fn content_security_policy(mut self, policy: &'static str) -> Self {
        self.content_security_policy = HeaderValue::from_static(policy);
        self
    }
}

/// Assembles the router the server runs: the application's routes, under the
/// API-wide rate limit and fallbacks, inside the [`middleware()`] stack.
pub fn app<S>(state: S, routes: Routes<S>) -> Router
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    let core = AppState::from_ref(&state);
    let api_rate_limit = RateLimitPolicy::new(&core, "api", core.config.rate_limit.api);
    let api = routes
        .api
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed)
        .layer(middleware::from_fn_with_state(
            api_rate_limit,
            rate_limit::enforce,
        ));
    let router = routes.site.nest("/api", api).with_state(state);
    self::middleware(router, &core.config, routes.content_security_policy)
}

/// The stack every response passes through, outermost first: HTTPS
/// enforcement, security headers, request IDs, tracing, CORS, the request
/// deadline, and the body limit.
pub fn middleware(router: Router, config: &Config, content_security_policy: HeaderValue) -> Router {
    let http = &config.http;
    let request_id_header = HeaderName::from_static("x-request-id");
    let security_headers = SecurityHeaders {
        content_security_policy,
        hsts: http.hsts.enabled.then(|| {
            HeaderValue::try_from(http.hsts.header_value())
                .expect("HSTS directives are built from digits and ASCII keywords")
        }),
    };

    router
        .layer(DefaultBodyLimit::max(http.body_limit_bytes))
        .layer(middleware::from_fn_with_state(
            Duration::from_secs(http.request_timeout_seconds),
            enforce_request_timeout,
        ))
        .layer(cors_layer(&http.cors_origins))
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
                    // Continue the caller's distributed trace, if it sent one.
                    #[cfg(feature = "otel")]
                    {
                        use tracing_opentelemetry::OpenTelemetrySpanExt;
                        span.set_parent(opentelemetry::global::get_text_map_propagator(
                            |propagator| propagator.extract(&HeaderExtractor(request.headers())),
                        ));
                    }
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
            http.https_enforcement,
            enforce_https,
        ))
}

#[derive(Clone)]
struct SecurityHeaders {
    content_security_policy: HeaderValue,
    /// Prebuilt `Strict-Transport-Security` value, or `None` when the header
    /// is switched off. Built once at startup so the per-response path stays
    /// a header clone rather than a format.
    hsts: Option<HeaderValue>,
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

#[cfg(feature = "otel")]
struct HeaderExtractor<'a>(&'a HeaderMap);

#[cfg(feature = "otel")]
impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
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

    headers.insert(
        HeaderName::from_static("content-security-policy"),
        settings.content_security_policy,
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
    if let Some(hsts) = settings.hsts {
        headers.insert(HeaderName::from_static("strict-transport-security"), hsts);
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

fn cors_layer(cors_origins: &[String]) -> CorsLayer {
    let origins = cors_origins
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

async fn api_not_found() -> AppError {
    AppError::NotFound("route")
}

async fn api_method_not_allowed() -> AppError {
    AppError::MethodNotAllowed
}
