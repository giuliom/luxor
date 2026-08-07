use crate::{
    auth::JwtService,
    cache::Cache,
    config::Config,
    events::{EventLog, EventPublisher},
    observability::TraceStore,
    permissions::PermissionStore,
    queue::Queue,
    rate_limit::RateLimiter,
    realtime::RealtimeHub,
};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub cache: Arc<dyn Cache>,
    pub queue: Arc<dyn Queue>,
    pub events: Arc<dyn EventPublisher>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub jwt: JwtService,
    pub permissions: PermissionStore,
    pub trace_store: TraceStore,
    /// In-process fan-out for the realtime WebSocket demo. Its connections
    /// belong to this instance only.
    pub realtime: RealtimeHub,
    /// The tail of the event stream as this instance has consumed it. The
    /// consumer that fills it is started by the binary, against the same
    /// backend `events` publishes to.
    pub event_log: EventLog,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        db: PgPool,
        cache: Arc<dyn Cache>,
        queue: Arc<dyn Queue>,
        events: Arc<dyn EventPublisher>,
        rate_limiter: Arc<dyn RateLimiter>,
        trace_store: TraceStore,
    ) -> Self {
        let jwt = JwtService::from_config(&config);
        let realtime = RealtimeHub::new(config.realtime.max_connections);
        Self {
            config,
            db,
            cache,
            queue,
            events,
            rate_limiter,
            jwt,
            permissions: PermissionStore,
            trace_store,
            realtime,
            event_log: EventLog::default(),
        }
    }
}
