//! Helpers for testing the application's HTTP surface without infrastructure.
//!
//! [`TestApp`] builds the same router the binary serves — the application's
//! routes, state, and middleware — on the in-memory cache, queue, event bus,
//! and rate limiter, with a database pool that never connects unless a test
//! reaches the database (and then fails fast, or uses the pool the test
//! provides). Compiled for this crate's own tests and for anything that
//! enables the `test-util` feature.

#[cfg(feature = "otel")]
use crate::observability::TraceStore;
use crate::{
    access::Role,
    app::{App, State},
    auth::JwtService,
    bootstrap::Application,
    cache::MemoryCache,
    config::Config,
    events::MemoryEventBus,
    queue::MemoryQueue,
    rate_limit::MemoryRateLimiter,
    server,
    state::{AppState, Services},
};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderName, Request},
    response::Response,
    Router,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

/// Nothing listens on port 1, so a test that unexpectedly reaches the
/// database fails at once instead of waiting out a connection timeout.
const UNREACHABLE_DATABASE_URL: &str = "postgres://test@127.0.0.1:1/unused";

/// Settings from `(key, value)` pairs, as [`Config::from_map`] takes them.
pub fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

/// A minimal valid production configuration. Production requires external
/// infrastructure and https origins, so the fixture names both; nothing here
/// is ever connected to.
pub fn production_values() -> HashMap<String, String> {
    let mut values = values(&[
        ("APP_ENV", "production"),
        ("DATABASE_URL", "postgres://test@localhost/production"),
        (
            "JWT_SECRET",
            "production-test-secret-at-least-32-characters",
        ),
        ("CORS_ORIGINS", "https://app.example.com"),
    ]);
    if cfg!(feature = "redis") {
        values.insert("REDIS_URL".into(), "redis://localhost:6379/".into());
    }
    values
}

/// Builds the application router for a test.
pub struct TestApp {
    values: HashMap<String, String>,
    database: Option<PgPool>,
    #[cfg(feature = "otel")]
    trace_store: TraceStore,
    api: Router<State>,
    site: Router<State>,
}

impl Default for TestApp {
    fn default() -> Self {
        Self::with_values(HashMap::new())
    }
}

impl TestApp {
    /// The development configuration: every default, nothing external.
    pub fn new() -> Self {
        Self::default()
    }

    /// A valid production configuration; see [`production_values`].
    pub fn production() -> Self {
        Self::with_values(production_values())
    }

    fn with_values(values: HashMap<String, String>) -> Self {
        Self {
            values,
            database: None,
            #[cfg(feature = "otel")]
            trace_store: TraceStore::default(),
            api: Router::new(),
            site: Router::new(),
        }
    }

    /// Sets one setting, exactly as an environment variable would.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.values.insert(key.to_owned(), value.to_owned());
        self
    }

    /// Serves the application on a real database instead of the unreachable
    /// placeholder.
    pub fn database(mut self, pool: PgPool) -> Self {
        self.database = Some(pool);
        self
    }

    #[cfg(feature = "otel")]
    pub fn trace_store(mut self, trace_store: TraceStore) -> Self {
        self.trace_store = trace_store;
        self
    }

    /// Adds routes under `/api` next to the application's own, such as a
    /// probe that exercises an extractor.
    pub fn api(mut self, routes: Router<State>) -> Self {
        self.api = self.api.merge(routes);
        self
    }

    /// Adds routes outside `/api` next to the application's own.
    pub fn site(mut self, routes: Router<State>) -> Self {
        self.site = self.site.merge(routes);
        self
    }

    /// The configuration the router is built with. Panics on an invalid one,
    /// which is a mistake in the test.
    pub fn config(&self) -> Config {
        Config::from_map(self.values.clone()).expect("the test configuration is valid")
    }

    /// The foundation's state on the in-memory backends.
    pub fn state(&self) -> AppState {
        AppState::new(
            Arc::new(self.config()),
            Services {
                db: self.database.clone().unwrap_or_else(unreachable_database),
                cache: Arc::new(MemoryCache::default()),
                queue: Arc::new(MemoryQueue::default()),
                events: Arc::new(MemoryEventBus::default()),
                rate_limiter: Arc::new(MemoryRateLimiter::default()),
                #[cfg(feature = "otel")]
                trace_store: self.trace_store.clone(),
            },
        )
    }

    /// A bearer `Authorization` value for a new, random user in `role`. The
    /// user does not exist in any database; endpoints that authorize from the
    /// token's claims alone accept it.
    pub fn bearer(&self, role: Role) -> String {
        bearer(&self.config(), Uuid::new_v4(), role)
    }

    /// The router the binary would serve with this configuration.
    pub fn router(self) -> Router {
        let app = App;
        let state = app
            .state(self.state())
            .expect("the application state builds");
        let routes = app.routes(&state).api(self.api).site(self.site);
        server::app(state, routes)
    }
}

/// A pool that never connects on its own. A request that does not touch the
/// database never notices it; one that does fails fast.
fn unreachable_database() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(1))
        .connect_lazy(UNREACHABLE_DATABASE_URL)
        .expect("the placeholder database URL is well formed")
}

/// A bearer `Authorization` value for `user_id` in `role`, signed with the
/// configuration's secret.
pub fn bearer(config: &Config, user_id: Uuid, role: Role) -> String {
    let token = JwtService::from_config(config)
        .issue(user_id, role)
        .expect("signing a test token succeeds");
    format!("Bearer {token}")
}

/// Sends one request through `router`, with an optional `Authorization` value
/// and an optional JSON body.
pub async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    authorization: Option<&str>,
    json: Option<&str>,
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(authorization) = authorization {
        builder = builder.header(header::AUTHORIZATION, authorization);
    }
    let body = match json {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(json.to_owned())
        }
        None => Body::empty(),
    };
    router
        .clone()
        .oneshot(builder.body(body).expect("a valid test request"))
        .await
        .expect("the router is infallible")
}

/// Sends one bodiless request through `router` with the given headers.
pub async fn send_with(
    router: &Router,
    method: &str,
    uri: &str,
    headers: &[(HeaderName, &str)],
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(name, *value);
    }
    router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("a valid test request"))
        .await
        .expect("the router is infallible")
}

pub async fn body_text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body is readable");
    String::from_utf8(bytes.to_vec()).expect("the body is UTF-8")
}

pub async fn body_json(response: Response) -> serde_json::Value {
    serde_json::from_str(&body_text(response).await).expect("the body is JSON")
}
