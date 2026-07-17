use anyhow::{bail, Context, Result};
use luxor::{
    cache::{Cache, MemoryCache, RedisCache},
    config::Config,
    db,
    dev_postgres::DevPostgres,
    observability,
    queue::{MemoryQueue, Queue, RedisQueue},
    server,
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
    let (telemetry, trace_store) =
        observability::init(&config).context("failed to initialize observability")?;

    // Bind before any infrastructure starts so that a second instance fails
    // fast on the port conflict instead of first spinning up (or attaching
    // to) the embedded development database.
    let listener = tokio::net::TcpListener::bind(config.bind_address())
        .await
        .with_context(|| format!("failed to bind {}", config.bind_address()))?;

    let (db, dev_postgres) = match &config.database_url {
        Some(database_url) => {
            let db = db::connect(database_url)
                .await
                .context("database startup failed")?;
            if config.auto_migrate {
                db::migrate(&db).await?;
            }
            (db, None)
        }
        None => {
            tracing::info!(
                "DATABASE_URL is not set; starting the embedded development PostgreSQL server"
            );
            let server = DevPostgres::start().await?;
            let db = db::connect(&server.database_url())
                .await
                .context("embedded database startup failed")?;
            // The embedded cluster exists only for the application, so it
            // always migrates itself regardless of AUTO_MIGRATE.
            db::migrate(&db).await?;
            (db, Some(server))
        }
    };

    let (cache, queue): (Arc<dyn Cache>, Arc<dyn Queue>) = match &config.redis_url {
        Some(redis_url) => {
            let redis =
                redis::Client::open(redis_url.expose_secret()).context("invalid REDIS_URL")?;
            let redis_manager = redis::aio::ConnectionManager::new(redis)
                .await
                .context("could not connect to Redis")?;
            (
                Arc::new(RedisCache::new(
                    redis_manager.clone(),
                    config.cache_namespace.clone(),
                )),
                Arc::new(RedisQueue::new(redis_manager, config.queue_key.clone())),
            )
        }
        None => {
            tracing::info!("REDIS_URL is not set; using the in-memory cache and queue");
            (
                Arc::new(MemoryCache::default()),
                Arc::new(MemoryQueue::default()),
            )
        }
    };
    let state = AppState::new(config.clone(), db, cache, queue, trace_store);
    let app = server::app(state);

    let address = listener.local_addr()?;
    tracing::info!(%address, "server listening");
    if config.open_browser {
        let url = format!("http://{address}/");
        match open_frontend(&url) {
            Ok(()) => tracing::info!(%url, "opened frontend in system browser"),
            Err(error) => tracing::warn!(%url, ?error, "could not open frontend automatically"),
        }
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;

    if let Some(server) = dev_postgres {
        server.stop().await;
    }

    // Give exporters a short opportunity to drain before their guards are dropped.
    tokio::time::sleep(Duration::from_millis(50)).await;
    telemetry.shutdown();
    Ok(())
}

#[cfg(target_os = "macos")]
fn open_frontend(url: &str) -> Result<()> {
    run_browser_command(std::process::Command::new("open").arg(url))
}

#[cfg(target_os = "windows")]
fn open_frontend(url: &str) -> Result<()> {
    run_browser_command(std::process::Command::new("cmd").args(["/C", "start", "", url]))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_frontend(url: &str) -> Result<()> {
    run_browser_command(std::process::Command::new("xdg-open").arg(url))
}

fn run_browser_command(command: &mut std::process::Command) -> Result<()> {
    let status = command.status().context("system browser command failed")?;
    if status.success() {
        Ok(())
    } else {
        bail!("system browser command exited with {status}")
    }
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
