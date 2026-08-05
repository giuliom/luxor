use crate::{
    auth::JwtService, cache::Cache, config::Config, observability::TraceStore,
    permissions::PermissionStore, queue::Queue, rate_limit::RateLimiter, realtime::RealtimeHub,
};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub cache: Arc<dyn Cache>,
    pub queue: Arc<dyn Queue>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub jwt: JwtService,
    pub permissions: PermissionStore,
    pub trace_store: TraceStore,
    /// In-process fan-out for the realtime WebSocket demo. Its connections
    /// belong to this instance only.
    pub realtime: RealtimeHub,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        db: PgPool,
        cache: Arc<dyn Cache>,
        queue: Arc<dyn Queue>,
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
            rate_limiter,
            jwt,
            permissions: PermissionStore,
            trace_store,
            realtime,
        }
    }
}
