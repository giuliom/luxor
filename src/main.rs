use anyhow::{bail, Context, Result};
use luxor::{
    cache::RedisCache, config::Config, db, observability, queue::RedisQueue, server,
    state::AppState,
};
use secrecy::{ExposeSecret, SecretString};
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    if let Some(command) = std::env::args().nth(1) {
        return match command.as_str() {
            "migrate" => migrate().await,
            other => bail!("unknown command {other:?}; supported commands: migrate"),
        };
    }

    serve().await
}

/// Applies the embedded migrations and exits. Deployment platforms run this as
/// a release step (for example Railway's pre-deploy command) so that
/// production never migrates during application startup.
async fn migrate() -> Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .map(SecretString::from)
        .context("DATABASE_URL must be set to run migrations")?;
    let db = db::connect(&database_url).await?;
    db::migrate(&db).await.context("migration failed")?;
    println!("database migrations applied");
    Ok(())
}

async fn serve() -> Result<()> {
    let config = Arc::new(Config::from_env().context("invalid application configuration")?);
    let telemetry = observability::init(&config).context("failed to initialize observability")?;

    let db = db::connect(&config.database_url)
        .await
        .context("database startup failed")?;
    if config.auto_migrate {
        db::migrate(&db).await?;
    }

    let redis =
        redis::Client::open(config.redis_url.expose_secret()).context("invalid REDIS_URL")?;
    let redis_manager = redis::aio::ConnectionManager::new(redis)
        .await
        .context("could not connect to Redis")?;
    let cache = Arc::new(RedisCache::new(
        redis_manager.clone(),
        config.cache_namespace.clone(),
    ));
    let queue = Arc::new(RedisQueue::new(redis_manager, config.queue_key.clone()));
    let state = AppState::new(config.clone(), db, cache, queue);
    let app = server::app(state);

    let listener = tokio::net::TcpListener::bind(config.bind_address())
        .await
        .with_context(|| format!("failed to bind {}", config.bind_address()))?;
    tracing::info!(address = %listener.local_addr()?, "server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;

    // Give exporters a short opportunity to drain before their guards are dropped.
    tokio::time::sleep(Duration::from_millis(50)).await;
    telemetry.shutdown();
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
