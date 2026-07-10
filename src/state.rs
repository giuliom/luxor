use crate::{auth::JwtService, cache::Cache, config::Config, queue::Queue};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub cache: Arc<dyn Cache>,
    pub queue: Arc<dyn Queue>,
    pub jwt: JwtService,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        db: PgPool,
        cache: Arc<dyn Cache>,
        queue: Arc<dyn Queue>,
    ) -> Self {
        let jwt = JwtService::from_config(&config);
        Self {
            config,
            db,
            cache,
            queue,
            jwt,
        }
    }
}
