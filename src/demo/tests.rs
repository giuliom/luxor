//! The console and the demo endpoints, exercised through the full router.

use crate::{
    access::Role,
    testing::{body_json, body_text, send, send_with, TestApp},
};
use axum::{
    body::to_bytes,
    http::{header, StatusCode},
    response::Response,
};
use std::io::Read;

fn assert_header_starts_with(response: &Response, name: header::HeaderName, prefix: &str) {
    let value = response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        value.starts_with(prefix),
        "{value:?} does not start with {prefix:?}"
    );
}

/// Other layers (CORS) add their own `Vary` lines, so look through all.
fn varies_on_accept_encoding(response: &Response) -> bool {
    response
        .headers()
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|name| name.trim().eq_ignore_ascii_case("accept-encoding"))
}

#[tokio::test]
async fn serves_a_complete_console_page_per_language() {
    let dev_base = "http://127.0.0.1:8080";
    let app = TestApp::new().router();
    for (path, locale) in [
        ("/en", crate::i18n::Locale::En),
        ("/it", crate::i18n::Locale::It),
    ] {
        let lang = locale.as_str();
        let response = send(&app, "GET", path, None, None).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_header_starts_with(&response, header::CONTENT_TYPE, "text/html");
        assert_eq!(
            response.headers().get(header::CONTENT_LANGUAGE).unwrap(),
            lang
        );
        let body = body_text(response).await;
        assert!(body.contains(&format!(r#"<html lang="{lang}" dir="ltr">"#)));
        assert!(body.contains(&format!(
            "<title>{}</title>",
            crate::i18n::escape_html(crate::i18n::message(locale, "meta.title"))
        )));
        assert!(body.contains(&format!(
            r#"rel="icon" href="{}""#,
            console_file_url(&body, "favicon")
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

/// The content-addressed URL a rendered page gives the named console file.
fn console_file_url(page: &str, stem: &str) -> String {
    let marker = format!("/assets/{stem}.");
    let start = page.find(&marker).expect("the page references the file");
    let end = start + page[start..].find('"').unwrap();
    page[start..end].to_owned()
}

#[tokio::test]
async fn root_negotiates_a_language_and_redirects() {
    let app = TestApp::new().router();

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
    let from_header = send_with(
        &app,
        "GET",
        "/",
        &[(header::ACCEPT_LANGUAGE, "it-IT,it;q=0.9,en;q=0.8")],
    )
    .await;
    assert_eq!(from_header.status(), StatusCode::FOUND);
    assert_eq!(from_header.headers().get(header::LOCATION).unwrap(), "/it");

    // …but an explicitly stored choice outranks it.
    let from_cookie = send_with(
        &app,
        "GET",
        "/",
        &[(header::COOKIE, "lang=en"), (header::ACCEPT_LANGUAGE, "it")],
    )
    .await;
    assert_eq!(from_cookie.status(), StatusCode::FOUND);
    assert_eq!(from_cookie.headers().get(header::LOCATION).unwrap(), "/en");
}

/// A language named in the URL is the strongest signal there is: browser
/// settings and stored preferences must never redirect away from it.
#[tokio::test]
async fn explicit_language_urls_are_never_overridden() {
    let response = send_with(
        &TestApp::new().router(),
        "GET",
        "/en",
        &[
            (header::COOKIE, "lang=it"),
            (header::ACCEPT_LANGUAGE, "it-IT,it;q=0.9"),
        ],
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_text(response)
        .await
        .contains(r#"<html lang="en" dir="ltr">"#));
}

#[tokio::test]
async fn slashed_language_urls_redirect_to_the_canonical_form() {
    let app = TestApp::new().router();
    for (slashed, canonical) in [("/en/", "/en"), ("/it/", "/it")] {
        let response = send(&app, "GET", slashed, None, None).await;
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), canonical);
    }
}

#[tokio::test]
async fn sitemap_lists_every_language_version() {
    let response = send(&TestApp::new().router(), "GET", "/sitemap.xml", None, None).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_header_starts_with(&response, header::CONTENT_TYPE, "application/xml");
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
    let response = send(&TestApp::production().router(), "GET", "/it", None, None).await;
    let body = body_text(response).await;
    assert!(body.contains(r#"<link rel="canonical" href="https://app.example.com/it">"#));
    assert!(
        body.contains(r#"<link rel="alternate" hreflang="en" href="https://app.example.com/en">"#)
    );
}

/// The content a script used to fetch after load — the runtime badge and
/// the permission matrix — is in the first response, drawn from this
/// instance's configuration and the grants it enforces.
#[tokio::test]
async fn pages_arrive_with_runtime_and_permissions_rendered() {
    let development =
        body_text(send(&TestApp::new().router(), "GET", "/en", None, None).await).await;
    assert!(development
        .contains(r#"<span id="runtime-badge" class="badge ok">Embedded database</span>"#));
    assert!(development.contains(r#"<th scope="col" class="grant" data-role="admin">Admin</th>"#));
    assert!(development
        .contains(r#"aria-label="User may not: Run the simulated record purge">—</span>"#));

    let production =
        body_text(send(&TestApp::production().router(), "GET", "/it", None, None).await).await;
    assert!(
        production.contains(r#"<span id="runtime-badge" class="badge ok">Stack completo</span>"#)
    );
    assert!(production.contains(
        r#"<span class="permission-hint">Leggere il report operativo dimostrativo</span>"#
    ));
}

#[tokio::test]
async fn robots_txt_points_crawlers_at_the_sitemap_and_off_the_api() {
    let response = send(&TestApp::new().router(), "GET", "/robots.txt", None, None).await;
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
        &TestApp::production().router(),
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
    let app = TestApp::new().router();
    let page = body_text(send(&app, "GET", "/en", None, None).await).await;

    for (path, stem, content_type, bytes) in [
        (
            "/styles.css",
            "styles",
            "text/css; charset=utf-8",
            include_bytes!("../../public/styles.css").as_slice(),
        ),
        (
            "/script.js",
            "script",
            "text/javascript; charset=utf-8",
            include_bytes!("../../public/script.js").as_slice(),
        ),
        (
            "/favicon.svg",
            "favicon",
            "image/svg+xml; charset=utf-8",
            include_bytes!("../../public/favicon.svg").as_slice(),
        ),
        (
            "/demo.wasm",
            "demo",
            "application/wasm",
            include_bytes!("../../public/demo.wasm").as_slice(),
        ),
    ] {
        let fingerprinted_path = console_file_url(&page, stem);
        assert!(
            !page.contains(&format!(r#""{path}""#)),
            "the page references the revalidated name {path}"
        );

        let fingerprinted = send(&app, "GET", &fingerprinted_path, None, None).await;
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

        let stable = send(&app, "GET", path, None, None).await;
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
        &TestApp::new().router(),
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
    let app = TestApp::new().router();
    let page = body_text(send(&app, "GET", "/en", None, None).await).await;
    let styles = console_file_url(&page, "styles");
    for path in [
        "/en",
        "/it",
        "/sitemap.xml",
        "/robots.txt",
        "/demo.wasm",
        styles.as_str(),
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

        let changed = send_with(&app, "GET", path, &[(header::IF_NONE_MATCH, "\"stale\"")]).await;
        assert_eq!(changed.status(), StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn text_and_wasm_are_served_gzip_to_clients_that_accept_it() {
    let app = TestApp::new().router();
    let page = body_text(send(&app, "GET", "/en", None, None).await).await;
    let script = console_file_url(&page, "script");
    for path in ["/en", "/it", "/sitemap.xml", "/demo.wasm", script.as_str()] {
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

        let refused = send_with(&app, "GET", path, &[(header::ACCEPT_ENCODING, "gzip;q=0")]).await;
        assert!(!refused.headers().contains_key(header::CONTENT_ENCODING));
    }
}

#[tokio::test]
async fn head_requests_describe_the_page_without_sending_it() {
    let app = TestApp::new().router();
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
    let response = send(&TestApp::new().router(), "GET", "/favicon.svg", None, None).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_header_starts_with(&response, header::CONTENT_TYPE, "image/svg+xml");
    assert!(body_text(response).await.contains("<svg"));
}

/// The console compiles WebAssembly, so its policy allows that — and still
/// forbids JavaScript eval.
#[tokio::test]
async fn serves_the_wasm_demo_module_for_streaming_compilation() {
    let response = send(&TestApp::new().router(), "GET", "/demo.wasm", None, None).await;

    assert_eq!(response.status(), StatusCode::OK);
    // WebAssembly.instantiateStreaming requires this exact content type.
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/wasm"
    );
    assert_eq!(
        response.headers().get("content-security-policy").unwrap(),
        super::CONTENT_SECURITY_POLICY
    );
    assert!(super::CONTENT_SECURITY_POLICY.contains("script-src 'self' 'wasm-unsafe-eval'"));
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(bytes.starts_with(b"\0asm"));
}

#[tokio::test]
async fn the_console_is_not_metered_by_the_api_rate_limit() {
    let app = TestApp::new()
        .env("RATE_LIMIT_API_MAX_REQUESTS", "2")
        .router();
    for _ in 0..2 {
        let response = send(&app, "GET", "/api/time", None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let limited = send(&app, "GET", "/api/time", None, None).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

    let index = send(&app, "GET", "/en", None, None).await;
    assert_eq!(index.status(), StatusCode::OK);
}

#[tokio::test]
async fn rejects_demo_routes_without_a_bearer_token() {
    let app = TestApp::new().router();
    for (method, uri) in [
        ("GET", "/api/demo/reports"),
        ("DELETE", "/api/demo/records"),
        ("GET", "/api/cache/demo"),
        ("POST", "/api/jobs"),
        ("GET", "/api/events"),
        ("POST", "/api/events"),
    ] {
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

#[tokio::test]
async fn permission_matrix_reports_the_demo_grants() {
    let response = send(
        &TestApp::new().router(),
        "GET",
        "/api/permissions",
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body
        .contains(r#""roles":{"admin":["reports.view","records.purge"],"user":["reports.view"]}"#));
    assert!(body.contains(r#""name":"reports.view""#));
    assert!(body.contains(r#""name":"records.purge""#));
}

#[tokio::test]
async fn permission_grants_control_the_demo_endpoints() {
    let test_app = TestApp::new();
    let admin = test_app.bearer(Role::Admin);
    let user = test_app.bearer(Role::User);
    let app = test_app.router();

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
async fn maps_job_body_rejections_to_the_error_contract() {
    let test_app = TestApp::new();
    let user = test_app.bearer(Role::User);
    let app = test_app.router();

    // A body that parses but does not match the target type is a 400 that
    // names the class of problem, without quoting the caller's input back.
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
    assert!(body.contains("does not match the schema"));
    assert!(!body.contains("reboot_world"), "the body was echoed back");

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
    let test_app = TestApp::new();
    let user = test_app.bearer(Role::User);
    let app = test_app.router();

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
    let test_app = TestApp::new();
    let user = test_app.bearer(Role::User);
    let app = test_app.router();

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
        let body = body_json(response).await;
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
    let test_app = TestApp::new();
    let user = test_app.bearer(Role::User);
    let app = test_app.router();

    let response = send(&app, "GET", "/api/events", Some(&user), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["backend"], "memory");
    assert_eq!(body["topic"], serde_json::Value::Null);
    assert_eq!(body["consumed"], 0);
    assert!(body["events"].as_array().unwrap().is_empty());

    let oversized = send(&app, "GET", "/api/events?limit=500", Some(&user), None).await;
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn returns_named_and_default_hello_json() {
    let app = TestApp::new().router();
    for (uri, expected) in [
        ("/api/hello?name=Ada", r#"{"message":"Hello, Ada!"}"#),
        ("/api/hello", r#"{"message":"Hello, world!"}"#),
    ] {
        let response = send(&app, "GET", uri, None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, expected);
    }
}

#[tokio::test]
async fn telemetry_demo_reports_disabled_export_without_a_tracer() {
    let response = send(
        &TestApp::new().router(),
        "GET",
        "/api/telemetry/demo",
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["otlp_enabled"], false);
    assert_eq!(body["service_name"], env!("CARGO_PKG_NAME"));
    assert!(body["request_id"].is_string());
    assert_eq!(body["trace_id"], serde_json::Value::Null);
}

#[tokio::test]
async fn trace_endpoint_validates_ids_and_serves_stored_spans() {
    use crate::observability::{StoredSpan, TraceStore};

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
    let app = TestApp::new().trace_store(trace_store).router();

    let invalid = send(
        &app,
        "GET",
        "/api/telemetry/traces/not-a-trace-id",
        None,
        None,
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let unknown = send(
        &app,
        "GET",
        "/api/telemetry/traces/ffffffffffffffffffffffffffffffff",
        None,
        None,
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let found = send(
        &app,
        "GET",
        &format!("/api/telemetry/traces/{trace_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(found.status(), StatusCode::OK);
    let body = body_text(found).await;
    assert!(body.contains(r#""trace_id":"0af7651916cd43dd8448eb211c80319c""#));
    assert!(body.contains(r#""name":"GET /api/telemetry/demo""#));
    assert!(body.contains(r#""kind":"server""#));
}

#[tokio::test]
async fn runtime_reports_the_active_backends() {
    let development = send(&TestApp::new().router(), "GET", "/api/runtime", None, None).await;
    assert_eq!(development.status(), StatusCode::OK);
    assert_eq!(
        body_text(development).await,
        r#"{"database":"embedded-postgresql","cache":"memory","queue":"memory","events":"memory"}"#
    );

    let production = send(
        &TestApp::production().router(),
        "GET",
        "/api/runtime",
        None,
        None,
    )
    .await;
    assert_eq!(production.status(), StatusCode::OK);
    // The event backend is reported by the publisher this instance was
    // built with, not inferred from configuration, and these fixtures name
    // no brokers. Production names Redis whenever the build includes it.
    let shared = if cfg!(feature = "redis") {
        "redis"
    } else {
        "memory"
    };
    assert_eq!(
        body_text(production).await,
        format!(
            r#"{{"database":"postgresql","cache":"{shared}","queue":"{shared}","events":"memory"}}"#
        )
    );
}
