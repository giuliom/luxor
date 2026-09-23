use crate::{
    assets::{self, Asset, CachePolicy},
    config::HttpsEnforcement,
    error::AppError,
    handlers::{auth, basic, cache, demo, events, jobs, permissions, realtime},
    i18n,
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
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
    Router,
};
use opentelemetry::{global, propagation::Extractor};
use std::{sync::Arc, time::Duration};
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
        // Publishing goes to the broker; the listing comes back from it, by
        // way of the consumer that feeds this instance's event log.
        .route("/events", get(events::stream).post(events::publish))
        // The ticket exchange is an ordinary authenticated POST; the upgrade
        // that redeems it authenticates itself with that ticket, because a
        // browser handshake cannot carry an Authorization header.
        .route("/realtime/ticket", post(realtime::ticket))
        .route("/realtime/ws", get(realtime::connect))
        .merge(auth_routes)
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed)
        .layer(middleware::from_fn_with_state(
            api_rate_limit,
            rate_limit::enforce,
        ));

    // The console is rendered once per language at startup: every localized
    // page has its own stable URL and is complete — translated, with the
    // permission matrix and runtime badge filled in — before the first byte
    // is sent, so the browser neither translates nor fetches anything to
    // finish it. `/` never serves content, only a negotiated redirect. Pages,
    // sitemap, and robots.txt are revalidated on every use: their content
    // changes with a deployment, and the ETag makes an unchanged one a 304.
    let base_url = state.config.public_base_url();
    let files = assets::embedded();
    let context = i18n::PageContext {
        base_url: &base_url,
        embedded_database: state.config.database_url.is_none(),
        grants: state.permissions.grants(),
        styles_url: &files.styles.fingerprinted_path,
        script_url: &files.script.fingerprinted_path,
        favicon_url: &files.favicon.fingerprinted_path,
        wasm_url: &files.wasm.fingerprinted_path,
    };
    let mut site = Router::new().route("/", get(localized_root));
    for locale in i18n::SUPPORTED_LOCALES {
        let page = Asset::new(
            "text/html; charset=utf-8",
            i18n::render_page(locale, &context),
        )
        .with_content_language(locale.as_str());
        site = site
            .route(
                locale.path(),
                assets::serve(Arc::new(page), CachePolicy::Revalidate),
            )
            // One canonical URL per language: the slashed variant redirects
            // rather than serving a duplicate.
            .route(
                &format!("{}/", locale.path()),
                get(move || async move { Redirect::permanent(locale.path()) }),
            );
    }
    let sitemap = Asset::new(
        "application/xml; charset=utf-8",
        i18n::render_sitemap(&base_url),
    );
    let robots = Asset::new("text/plain; charset=utf-8", render_robots(&base_url));
    site = site
        .route(
            "/sitemap.xml",
            assets::serve(Arc::new(sitemap), CachePolicy::Revalidate),
        )
        .route(
            "/robots.txt",
            assets::serve(Arc::new(robots), CachePolicy::Revalidate),
        );

    // Every embedded file answers at its content-addressed URL, which is all
    // the pages reference and is cached for a year, and at its stable name,
    // revalidated, for whatever addresses it directly. An outdated
    // fingerprint is a 404 rather than today's bytes under yesterday's
    // immutable URL.
    for file in files.all() {
        site = site
            .route(
                &file.fingerprinted_path,
                assets::serve(file.asset.clone(), CachePolicy::Immutable),
            )
            .route(
                file.path,
                assets::serve(file.asset.clone(), CachePolicy::Revalidate),
            );
    }

    site.nest("/api", api)
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

/// Sends `/` to the negotiated language version: the explicit cookie
/// preference first, then `Accept-Language`, then the default. The redirect
/// varies on what it read and is never cached, so a shared cache can never
/// pin every visitor to one visitor's language; the language-prefixed URLs
/// it points at are what caches and crawlers index.
async fn localized_root(headers: HeaderMap) -> Response {
    let locale = i18n::negotiate(
        headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok()),
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|value| value.to_str().ok()),
    );
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, HeaderValue::from_static(locale.path())),
            (
                header::VARY,
                HeaderValue::from_static("Cookie, Accept-Language"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response()
}

/// Points crawlers at the sitemap, whose URL robots.txt requires to be
/// absolute, and keeps them off the API: its JSON is not content, and crawler
/// traffic would spend the per-IP rate-limit budgets. Nothing the pages show
/// depends on it, because they arrive fully rendered.
fn render_robots(base_url: &str) -> String {
    format!("User-agent: *\nDisallow: /api/\n\nSitemap: {base_url}/sitemap.xml\n")
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
        events::MemoryEventBus,
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
    use std::{collections::HashMap, io::Read, sync::Arc};
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
            Arc::new(MemoryEventBus::default()),
            Arc::new(MemoryRateLimiter::default()),
            trace_store,
        ))
    }

    #[tokio::test]
    async fn serves_a_complete_console_page_per_language() {
        let dev_base = "http://127.0.0.1:8080";
        for (path, lang, title) in [
            ("/en", "en", "<title>Luxor backend console</title>"),
            ("/it", "it", "<title>Console backend Luxor</title>"),
        ] {
            let response = test_app()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            assert_header_starts_with(&response, header::CONTENT_TYPE.as_str(), "text/html");
            assert_eq!(
                response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
                lang
            );
            let body = body_text(response).await;
            assert!(body.contains(&format!(r#"<html lang="{lang}" dir="ltr">"#)));
            assert!(body.contains(title));
            assert!(body.contains(&format!(
                r#"rel="icon" href="{}""#,
                assets::embedded().favicon.fingerprinted_path
            )));
            assert!(!body.contains("{{"), "unresolved template placeholder");
            // Self-referencing canonical plus reciprocal hreflang alternates,
            // including x-default; visible, crawlable selector links.
            assert!(body.contains(&format!(
                r#"<link rel="canonical" href="{dev_base}{path}">"#
            )));
            assert!(body.contains(&format!(
                r#"<link rel="alternate" hreflang="en" href="{dev_base}/en">"#
            )));
            assert!(body.contains(&format!(
                r#"<link rel="alternate" hreflang="it" href="{dev_base}/it">"#
            )));
            assert!(body.contains(&format!(
                r#"<link rel="alternate" hreflang="x-default" href="{dev_base}/en">"#
            )));
            assert!(body.contains(r#"<a href="/it" hreflang="it" lang="it""#));
        }
    }

    #[tokio::test]
    async fn root_negotiates_a_language_and_redirects() {
        let app = test_app();

        // No signal at all falls back to the default language. The redirect
        // names what it varies on and must never be cached.
        let default = send(&app, "GET", "/", None, None).await;
        assert_eq!(default.status(), StatusCode::FOUND);
        assert_eq!(default.headers().get(header::LOCATION).unwrap(), "/en");
        assert_eq!(
            default.headers().get(header::VARY).unwrap(),
            "Cookie, Accept-Language"
        );
        assert_eq!(
            default.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        // The browser's weighted preference is honored…
        let from_header = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT_LANGUAGE, "it-IT,it;q=0.9,en;q=0.8")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(from_header.status(), StatusCode::FOUND);
        assert_eq!(from_header.headers().get(header::LOCATION).unwrap(), "/it");

        // …but an explicitly stored choice outranks it.
        let from_cookie = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, "lang=en")
                    .header(header::ACCEPT_LANGUAGE, "it")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(from_cookie.status(), StatusCode::FOUND);
        assert_eq!(from_cookie.headers().get(header::LOCATION).unwrap(), "/en");
    }

    /// A language named in the URL is the strongest signal there is: browser
    /// settings and stored preferences must never redirect away from it.
    #[tokio::test]
    async fn explicit_language_urls_are_never_overridden() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/en")
                    .header(header::COOKIE, "lang=it")
                    .header(header::ACCEPT_LANGUAGE, "it-IT,it;q=0.9")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response)
            .await
            .contains(r#"<html lang="en" dir="ltr">"#));
    }

    #[tokio::test]
    async fn slashed_language_urls_redirect_to_the_canonical_form() {
        for (slashed, canonical) in [("/en/", "/en"), ("/it/", "/it")] {
            let response = test_app()
                .oneshot(Request::builder().uri(slashed).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
            assert_eq!(response.headers().get(header::LOCATION).unwrap(), canonical);
        }
    }

    #[tokio::test]
    async fn sitemap_lists_every_language_version() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/sitemap.xml")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_header_starts_with(&response, header::CONTENT_TYPE.as_str(), "application/xml");
        let body = body_text(response).await;
        assert!(body.contains("<loc>http://127.0.0.1:8080/en</loc>"));
        assert!(body.contains("<loc>http://127.0.0.1:8080/it</loc>"));
        assert!(body.contains(r#"hreflang="x-default""#));
    }

    /// In production the SEO URLs must name the public origin, which the
    /// deployment already provides as the first CORS origin unless an
    /// explicit PUBLIC_BASE_URL is set.
    #[tokio::test]
    async fn production_seo_urls_use_the_public_origin() {
        let response = test_app_with_config(production_config())
            .oneshot(Request::builder().uri("/it").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_text(response).await;
        assert!(body.contains(r#"<link rel="canonical" href="https://app.example.com/it">"#));
        assert!(body
            .contains(r#"<link rel="alternate" hreflang="en" href="https://app.example.com/en">"#));
    }

    /// The content a script used to fetch after load — the runtime badge and
    /// the permission matrix — is in the first response, drawn from this
    /// instance's configuration and the grants it enforces.
    #[tokio::test]
    async fn pages_arrive_with_runtime_and_permissions_rendered() {
        let development = body_text(send(&test_app(), "GET", "/en", None, None).await).await;
        assert!(development
            .contains(r#"<span id="runtime-badge" class="badge ok">Embedded database</span>"#));
        assert!(
            development.contains(r#"<th scope="col" class="grant" data-role="admin">Admin</th>"#)
        );
        assert!(development
            .contains(r#"aria-label="User may not: Run the simulated record purge">—</span>"#));

        let production = body_text(
            send(
                &test_app_with_config(production_config()),
                "GET",
                "/it",
                None,
                None,
            )
            .await,
        )
        .await;
        assert!(production
            .contains(r#"<span id="runtime-badge" class="badge ok">Stack completo</span>"#));
        assert!(production.contains(
            r#"<span class="permission-hint">Leggere il report operativo dimostrativo</span>"#
        ));
    }

    #[tokio::test]
    async fn robots_txt_points_crawlers_at_the_sitemap_and_off_the_api() {
        let response = send(&test_app(), "GET", "/robots.txt", None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            body_text(response).await,
            "User-agent: *\nDisallow: /api/\n\nSitemap: http://127.0.0.1:8080/sitemap.xml\n"
        );

        let production = send(
            &test_app_with_config(production_config()),
            "GET",
            "/robots.txt",
            None,
            None,
        )
        .await;
        assert!(body_text(production)
            .await
            .contains("Sitemap: https://app.example.com/sitemap.xml\n"));
    }

    /// The pages reference only content-addressed asset URLs, which may be
    /// cached for a year because new content means a new URL; the stable
    /// names still answer, revalidated, with the same bytes.
    #[tokio::test]
    async fn pages_load_content_addressed_assets_cached_for_a_year() {
        let app = test_app();
        let page = body_text(send(&app, "GET", "/en", None, None).await).await;

        let files = assets::embedded();
        for (file, content_type, bytes) in [
            (
                &files.styles,
                "text/css; charset=utf-8",
                include_bytes!("../public/styles.css").as_slice(),
            ),
            (
                &files.script,
                "text/javascript; charset=utf-8",
                include_bytes!("../public/script.js").as_slice(),
            ),
            (
                &files.favicon,
                "image/svg+xml; charset=utf-8",
                include_bytes!("../public/favicon.svg").as_slice(),
            ),
            (
                &files.wasm,
                "application/wasm",
                include_bytes!("../public/demo.wasm").as_slice(),
            ),
        ] {
            assert!(
                page.contains(&format!(r#""{}""#, file.fingerprinted_path)),
                "the page does not reference {}",
                file.fingerprinted_path
            );
            assert!(
                !page.contains(&format!(r#""{}""#, file.path)),
                "the page references the revalidated name {}",
                file.path
            );

            let fingerprinted = send(&app, "GET", &file.fingerprinted_path, None, None).await;
            assert_eq!(fingerprinted.status(), StatusCode::OK);
            assert_eq!(
                fingerprinted.headers().get(header::CACHE_CONTROL).unwrap(),
                "public, max-age=31536000, immutable"
            );
            assert_eq!(
                fingerprinted.headers().get(header::CONTENT_TYPE).unwrap(),
                content_type
            );
            let etag = fingerprinted.headers().get(header::ETAG).unwrap().clone();
            let body = to_bytes(fingerprinted.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(body.as_ref(), bytes);

            let stable = send(&app, "GET", file.path, None, None).await;
            assert_eq!(stable.status(), StatusCode::OK);
            assert_eq!(
                stable.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-cache"
            );
            assert_eq!(stable.headers().get(header::ETAG).unwrap(), &etag);
        }
    }

    #[tokio::test]
    async fn outdated_asset_fingerprints_are_not_found() {
        let response = send(
            &test_app(),
            "GET",
            "/assets/styles.0000000000000000.css",
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn pages_and_assets_answer_revalidation_with_not_modified() {
        let app = test_app();
        let styles = assets::embedded().styles.fingerprinted_path.as_str();
        for path in [
            "/en",
            "/it",
            "/sitemap.xml",
            "/robots.txt",
            "/demo.wasm",
            styles,
        ] {
            let first = send(&app, "GET", path, None, None).await;
            assert_eq!(first.status(), StatusCode::OK, "{path}");
            let etag = first
                .headers()
                .get(header::ETAG)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            assert!(
                etag.starts_with('"') && etag.ends_with('"'),
                "{path}: {etag}"
            );

            for condition in [
                etag.clone(),
                format!("W/{etag}"),
                format!("\"stale\", {etag}"),
                "*".to_owned(),
            ] {
                let response =
                    send_with(&app, "GET", path, &[(header::IF_NONE_MATCH, &condition)]).await;
                assert_eq!(
                    response.status(),
                    StatusCode::NOT_MODIFIED,
                    "{path} with If-None-Match: {condition}"
                );
                assert_eq!(response.headers().get(header::ETAG).unwrap(), etag.as_str());
                assert!(response.headers().contains_key(header::CACHE_CONTROL));
                assert!(!response.headers().contains_key(header::CONTENT_LANGUAGE));
                assert!(body_text(response).await.is_empty());
            }

            let changed =
                send_with(&app, "GET", path, &[(header::IF_NONE_MATCH, "\"stale\"")]).await;
            assert_eq!(changed.status(), StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn text_and_wasm_are_served_gzip_to_clients_that_accept_it() {
        let app = test_app();
        let script = assets::embedded().script.fingerprinted_path.as_str();
        for path in ["/en", "/it", "/sitemap.xml", "/demo.wasm", script] {
            let plain = send(&app, "GET", path, None, None).await;
            assert!(!plain.headers().contains_key(header::CONTENT_ENCODING));
            assert!(varies_on_accept_encoding(&plain), "{path}");
            let plain_etag = plain.headers().get(header::ETAG).unwrap().clone();
            let plain_type = plain.headers().get(header::CONTENT_TYPE).unwrap().clone();
            let plain_body = to_bytes(plain.into_body(), usize::MAX).await.unwrap();

            let compressed = send_with(
                &app,
                "GET",
                path,
                &[(header::ACCEPT_ENCODING, "gzip, deflate, br, zstd")],
            )
            .await;
            assert_eq!(compressed.status(), StatusCode::OK);
            assert_eq!(
                compressed.headers().get(header::CONTENT_ENCODING).unwrap(),
                "gzip",
                "{path}"
            );
            assert!(varies_on_accept_encoding(&compressed), "{path}");
            assert_eq!(
                compressed.headers().get(header::CONTENT_TYPE).unwrap(),
                &plain_type
            );
            assert_ne!(compressed.headers().get(header::ETAG).unwrap(), &plain_etag);
            let compressed_body = to_bytes(compressed.into_body(), usize::MAX).await.unwrap();
            assert!(compressed_body.len() < plain_body.len(), "{path}");

            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(compressed_body.as_ref())
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, plain_body.as_ref(), "{path}");

            let refused =
                send_with(&app, "GET", path, &[(header::ACCEPT_ENCODING, "gzip;q=0")]).await;
            assert!(!refused.headers().contains_key(header::CONTENT_ENCODING));
        }
    }

    /// API responses carry credentials next to request-influenced content, so
    /// they are never compressed (the BREACH precondition).
    #[tokio::test]
    async fn api_responses_are_not_compressed() {
        let response = send_with(
            &test_app(),
            "GET",
            "/api/permissions",
            &[(header::ACCEPT_ENCODING, "gzip")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
    }

    #[tokio::test]
    async fn head_requests_describe_the_page_without_sending_it() {
        let app = test_app();
        let get = send(&app, "GET", "/en", None, None).await;
        let etag = get.headers().get(header::ETAG).unwrap().clone();
        let length = body_text(get).await.len();

        let head = send(&app, "HEAD", "/en", None, None).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers().get(header::ETAG).unwrap(), &etag);
        assert_eq!(
            head.headers().get(header::CONTENT_LENGTH).unwrap(),
            length.to_string().as_str()
        );
        assert!(body_text(head).await.is_empty());
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
            ("GET", "/api/events"),
            ("POST", "/api/events"),
            ("POST", "/api/realtime/ticket"),
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
    async fn realtime_tickets_are_short_lived_and_name_their_endpoint() {
        let app = test_app();
        let response = send(
            &app,
            "POST",
            "/api/realtime/ticket",
            Some(&bearer(Role::User)),
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_text(response).await).expect("a JSON ticket");
        assert_eq!(body["expires_in"], 30);
        assert_eq!(body["websocket_path"], "/api/realtime/ws");
        // Long enough to be a 256-bit random value, and not the access token.
        assert!(body["ticket"].as_str().unwrap().len() >= 40);
    }

    /// CORS never runs for a WebSocket handshake, so the endpoint checks the
    /// origin itself; this is the cross-site WebSocket hijacking case.
    #[tokio::test]
    async fn realtime_upgrades_are_refused_from_a_foreign_origin() {
        let response = test_app_with_config(production_config())
            .oneshot(
                Request::builder()
                    .uri("/api/realtime/ws?ticket=stolen")
                    .header(header::ORIGIN, "https://evil.test")
                    .header(header::HOST, "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(body_text(response).await.contains(r#""code":"forbidden""#));
    }

    /// A same-origin request gets past the origin check and is then turned
    /// away by the upgrade extractor — in the JSON shape the rest of the API
    /// uses, rather than axum's plain-text rejection.
    #[tokio::test]
    async fn realtime_upgrades_without_websocket_headers_follow_the_error_contract() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/realtime/ws")
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header(header::HOST, "127.0.0.1:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(response)
            .await
            .contains(r#""code":"bad_request""#));
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

        // A body that parses but does not match the target type is a 400 that
        // names the class of problem — and never quotes the caller's own input
        // back at it, which is what would make the response a reflection.
        let unknown_variant = send(
            &app,
            "POST",
            "/api/jobs",
            Some(&user),
            Some(r#"{"kind":"reboot_world"}"#),
        )
        .await;
        assert_eq!(unknown_variant.status(), StatusCode::BAD_REQUEST);
        let body = body_text(unknown_variant).await;
        assert!(body.contains(r#""code":"bad_request""#));
        assert!(body.contains("does not match the schema"));
        assert!(!body.contains("reboot_world"), "the body was echoed back");

        // Malformed JSON is reported as such, and is likewise not echoed.
        let malformed = send(
            &app,
            "POST",
            "/api/jobs",
            Some(&user),
            Some(r#"{"kind":"audit_event","#),
        )
        .await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let body = body_text(malformed).await;
        assert!(body.contains("not valid JSON"));
        assert!(!body.contains("audit_event"), "the body was echoed back");
    }

    /// The queue is validated on the way in, because the worker that drains it
    /// reads its payload back as trusted input. Each rejected body here is one
    /// a worker would otherwise render into an SMTP header or a template path.
    #[tokio::test]
    async fn enqueueing_validates_the_job_payload() {
        let app = test_app();
        let user = bearer(Role::User);

        let accepted = send(
            &app,
            "POST",
            "/api/jobs",
            Some(&user),
            Some(r#"{"kind":"send_email","to":"person@example.com","template":"welcome"}"#),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        assert!(body_text(accepted).await.contains(r#""kind":"send_email""#));

        for rejected in [
            // A recipient smuggling a header past the address.
            r#"{"kind":"send_email","to":"person\r\nBcc: attacker@example.com","template":"welcome"}"#,
            r#"{"kind":"send_email","to":"not-an-address","template":"welcome"}"#,
            // A template steering whatever resolves it.
            r#"{"kind":"send_email","to":"person@example.com","template":"../../etc/passwd"}"#,
            r#"{"kind":"send_email","to":"person@example.com","template":""}"#,
        ] {
            let response = send(&app, "POST", "/api/jobs", Some(&user), Some(rejected)).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{rejected} should be refused"
            );
            assert!(body_text(response)
                .await
                .contains(r#""code":"bad_request""#));
        }
    }

    /// A publish answers with the broker's receipt, and the payload is
    /// validated on the way in — the topic is read back by this application
    /// and by anyone else subscribed to it.
    #[tokio::test]
    async fn publishing_an_event_returns_its_position_on_the_stream() {
        let app = test_app();
        let user = bearer(Role::User);

        for expected_offset in 0..2 {
            let response = send(
                &app,
                "POST",
                "/api/events",
                Some(&user),
                Some(r#"{"text":"deployed to staging"}"#),
            )
            .await;
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let body: serde_json::Value =
                serde_json::from_str(&body_text(response).await).expect("a JSON receipt");
            assert_eq!(body["status"], "published");
            assert_eq!(body["kind"], "note.published");
            assert_eq!(body["schema_version"], 1);
            assert_eq!(body["offset"], expected_offset);
            assert_eq!(body["payload"]["text"], "deployed to staging");
        }

        for rejected in [
            r#"{"text":""}"#,
            r#"{"text":"   "}"#,
            r#"{"text":"two\nlines"}"#,
        ] {
            let response = send(&app, "POST", "/api/events", Some(&user), Some(rejected)).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{rejected} should be refused"
            );
        }
    }

    /// The listing is filled by the consumer task, which the binary starts and
    /// these tests do not, so it reports the stream's identity and an empty
    /// window rather than echoing what was just published.
    #[tokio::test]
    async fn the_event_listing_describes_the_stream_and_bounds_its_window() {
        let app = test_app();
        let user = bearer(Role::User);

        let response = send(&app, "GET", "/api/events", Some(&user), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_text(response).await).expect("a JSON listing");
        assert_eq!(body["backend"], "memory");
        assert_eq!(body["topic"], serde_json::Value::Null);
        assert_eq!(body["consumed"], 0);
        assert!(body["events"].as_array().unwrap().is_empty());

        let oversized = send(&app, "GET", "/api/events?limit=500", Some(&user), None).await;
        assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
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
        let index = send(&app, "GET", "/en", None, None).await;
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
            r#"{"database":"embedded-postgresql","cache":"memory","queue":"memory","events":"memory"}"#
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
        // The event backend is reported by the publisher this instance was
        // built with, not inferred from configuration, and these fixtures name
        // no brokers.
        assert_eq!(
            body_text(production).await,
            r#"{"database":"postgresql","cache":"redis","queue":"redis","events":"memory"}"#
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

    async fn send_with(
        app: &Router,
        method: &str,
        uri: &str,
        headers: &[(header::HeaderName, &str)],
    ) -> axum::response::Response {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(name, *value);
        }
        app.clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// Other layers (CORS) add their own `Vary` lines, so look through all.
    fn varies_on_accept_encoding(response: &axum::response::Response) -> bool {
        response
            .headers()
            .get_all(header::VARY)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|name| name.trim().eq_ignore_ascii_case("accept-encoding"))
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
