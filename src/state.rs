//! The foundation's services, shared by every request.
//!
//! An application serves its own state type (see [`crate::app::State`]); the
//! built-in routes and extractors read this one out of it through
//! `AppState: FromRef<YourState>`.

#[cfg(feature = "otel")]
use crate::observability::TraceStore;
#[cfg(feature = "realtime")]
use crate::realtime::RealtimeHub;
use crate::{
    access::PermissionStore,
    app::{events::DomainEvent, jobs::Job},
    auth::JwtService,
    cache::Cache,
    config::Config,
    events::EventPublisher,
    queue::Queue,
    rate_limit::RateLimiter,
};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub cache: Arc<dyn Cache>,
    pub queue: Arc<dyn Queue<Job>>,
    pub events: Arc<dyn EventPublisher<DomainEvent>>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub jwt: JwtService,
    pub permissions: PermissionStore,
    /// Spans this instance recorded, for the in-process trace viewer.
    #[cfg(feature = "otel")]
    pub trace_store: TraceStore,
    /// In-process fan-out for realtime connections. Its connections belong to
    /// this instance only.
    #[cfg(feature = "realtime")]
    pub realtime: RealtimeHub,
}

/// The backends an [`AppState`] is built on. [`crate::bootstrap`] connects
/// them from configuration; tests use the in-memory ones.
pub struct Services {
    pub db: PgPool,
    pub cache: Arc<dyn Cache>,
    pub queue: Arc<dyn Queue<Job>>,
    pub events: Arc<dyn EventPublisher<DomainEvent>>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    #[cfg(feature = "otel")]
    pub trace_store: TraceStore,
}

impl AppState {
    pub fn new(config: Arc<Config>, services: Services) -> Self {
        let jwt = JwtService::from_config(&config);
        #[cfg(feature = "realtime")]
        let realtime = RealtimeHub::new(config.realtime.max_connections);
        Self {
            config,
            db: services.db,
            cache: services.cache,
            queue: services.queue,
            events: services.events,
            rate_limiter: services.rate_limiter,
            jwt,
            permissions: PermissionStore,
            #[cfg(feature = "otel")]
            trace_store: services.trace_store,
            #[cfg(feature = "realtime")]
            realtime,
        }
    }
}
