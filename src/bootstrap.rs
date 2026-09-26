//! Starting and stopping the server.
//!
//! `main.rs` hands [`run`] an [`Application`]; everything else happens here:
//! configuration, telemetry, the database and the other backends, background
//! tasks, the router, and a graceful shutdown in the right order. An
//! application extends the server through the trait's hooks instead of
//! editing this file.

use crate::{
    app::{events::DomainEvent, jobs::Job},
    cache::{Cache, MemoryCache},
    config::Config,
    db,
    dev_postgres::DevPostgres,
    events::{self, EventHandler, EventPublisher, EventSource, MemoryEventBus},
    observability,
    queue::{MemoryQueue, Queue},
    rate_limit::{MemoryRateLimiter, RateLimiter},
    server::{self, Routes},
    state::{AppState, Services},
    tasks::{BackgroundTasks, Shutdown},
};
use anyhow::{anyhow, bail, Context, Result};
use axum::extract::FromRef;
use secrecy::SecretString;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc, time::Duration};

/// What an application contributes to the server. Only [`state`] and
/// [`routes`] are required; see [`crate::app::App`] for the template's own.
///
/// [`state`]: Application::state
/// [`routes`]: Application::routes
pub trait Application: Send + Sync + 'static {
    /// The state every route is served with: [`AppState`] itself, or an
    /// application type that carries it and exposes it through
    /// `impl FromRef<Self::State> for AppState`, which the built-in routes and
    /// extractors rely on.
    type State: Clone + Send + Sync + 'static;

    /// Builds the router state from the foundation's services.
    fn state(&self, core: AppState) -> Result<Self::State>;

    /// Everything the server serves. [`crate::routes::api`] provides the
    /// foundation's endpoints for `Routes::api`.
    fn routes(&self, state: &Self::State) -> Routes<Self::State>;

    /// The handler the event consumer feeds, if this application reads the
    /// event stream. With `None` no consumer is started, and a Kafka
    /// deployment joins no consumer group.
    fn event_handler(&self, _state: &Self::State) -> Option<Arc<dyn EventHandler<DomainEvent>>> {
        None
    }

    /// Starts the application's own long-running tasks. Each receives a
    /// shutdown signal and is awaited, within a grace period, after the
    /// server stops taking requests.
    fn tasks(&self, _state: &Self::State, _tasks: &mut BackgroundTasks) {}
}

/// Runs the process: the `migrate` command when it is given, the server
/// otherwise.
pub async fn run<A>(app: A) -> Result<()>
where
    A: Application,
    AppState: FromRef<A::State>,
{
    dotenvy::dotenv().ok();
    install_crypto_provider()?;

    if let Some(command) = std::env::args().nth(1) {
        return match command.as_str() {
            "migrate" => migrate().await,
            other => bail!("unknown command {other:?}; supported commands: migrate"),
        };
    }

    serve(app).await
}

/// Settles which rustls crypto provider the process uses, before any TLS
/// configuration can be built for the database, Sentry, or the archive
/// download.
///
/// The two build profiles do not enable the same set: the production image
/// (built without `embedded-postgres`) compiles ring alone, while a
/// development build also pulls in aws-lc-rs through postgresql_embedded.
/// rustls panics rather than pick between two enabled providers, so leaving
/// the choice implicit would mean code that works in the image and fails
/// under `cargo run`.
fn install_crypto_provider() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("a rustls crypto provider was installed before startup"))
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

/// How long background tasks get to finish once the server has stopped.
const TASK_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

async fn serve<A>(app: A) -> Result<()>
where
    A: Application,
    AppState: FromRef<A::State>,
{
    let config = Arc::new(Config::from_env().context("invalid application configuration")?);
    let observability =
        observability::init(&config).context("failed to initialize observability")?;

    // Bind before any infrastructure starts so that a second instance fails
    // fast on the port conflict instead of first spinning up (or attaching
    // to) the embedded development database.
    let listener = tokio::net::TcpListener::bind(config.http.bind_address())
        .await
        .with_context(|| format!("failed to bind {}", config.http.bind_address()))?;

    let (db, dev_postgres) = connect_database(&config).await?;
    let (cache, queue, rate_limiter) = connect_shared_state(&config).await?;
    // The publisher and the consumer are built from the same settings, so the
    // events this instance emits are the events it reads back.
    let memory_bus = MemoryEventBus::default();
    let events = event_publisher(&config, &memory_bus)?;

    // Compute the login timing-equalizer hash before traffic arrives so the
    // first unknown-email login is not measurably slower than later ones.
    tokio::task::spawn_blocking(crate::auth::prewarm_login_timing_equalizer);

    let core = AppState::new(
        config.clone(),
        Services {
            db: db.clone(),
            cache,
            queue,
            events,
            rate_limiter,
            #[cfg(feature = "otel")]
            trace_store: observability.trace_store(),
        },
    );
    let state = app.state(core).context("application state setup failed")?;

    let mut tasks = BackgroundTasks::default();
    tasks.spawn("session pruner", move |shutdown| {
        prune_sessions(db, shutdown)
    });
    if let Some(handler) = app.event_handler(&state) {
        let source = event_source(&config, &memory_bus)?;
        tasks.spawn("event consumer", move |shutdown| {
            events::consume(source, handler, shutdown)
        });
    }
    app.tasks(&state, &mut tasks);

    let router = server::app(state.clone(), app.routes(&state));

    let address = listener.local_addr()?;
    tracing::info!(%address, "server listening");
    if config.http.open_browser {
        let url = format!("http://{address}/");
        match open_frontend(&url) {
            Ok(()) => tracing::info!(%url, "opened frontend in system browser"),
            Err(error) => tracing::warn!(%url, ?error, "could not open frontend automatically"),
        }
    }

    // Connect info exposes the peer address, which the rate limiter uses to
    // identify clients when CLIENT_IP_SOURCE is "socket".
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("HTTP server failed")?;

    // Once no request can publish anything, the tasks — the event consumer
    // among them — are given their chance to drain and commit what they hold.
    tasks.shutdown(TASK_SHUTDOWN_GRACE).await;

    if let Some(server) = dev_postgres {
        server.stop().await;
    }

    // Give exporters a short opportunity to drain before their guards are dropped.
    tokio::time::sleep(Duration::from_millis(50)).await;
    observability.shutdown();
    Ok(())
}

/// Connects to `DATABASE_URL`, or starts the embedded development server when
/// it is unset.
async fn connect_database(config: &Config) -> Result<(PgPool, Option<DevPostgres>)> {
    match &config.database.url {
        Some(database_url) => {
            let db = db::connect(database_url)
                .await
                .context("database startup failed")?;
            if config.database.auto_migrate {
                db::migrate(&db).await?;
            }
            Ok((db, None))
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
            Ok((db, Some(server)))
        }
    }
}

type SharedState = (Arc<dyn Cache>, Arc<dyn Queue<Job>>, Arc<dyn RateLimiter>);

/// The cache, queue, and rate limiter: on Redis when it is configured, in
/// memory otherwise.
async fn connect_shared_state(config: &Config) -> Result<SharedState> {
    #[cfg(feature = "redis")]
    if let Some(redis_url) = &config.redis_url {
        use crate::{cache::RedisCache, queue::RedisQueue, rate_limit::RedisRateLimiter};
        use secrecy::ExposeSecret;

        let redis = redis::Client::open(redis_url.expose_secret()).context("invalid REDIS_URL")?;
        let redis_manager = redis::aio::ConnectionManager::new(redis)
            .await
            .context("could not connect to Redis")?;
        return Ok((
            Arc::new(RedisCache::new(
                redis_manager.clone(),
                config.cache.namespace.clone(),
            )),
            Arc::new(RedisQueue::new(
                redis_manager.clone(),
                config.queue.key.clone(),
            )),
            Arc::new(RedisRateLimiter::new(
                redis_manager,
                config.rate_limit.namespace.clone(),
            )),
        ));
    }

    if cfg!(feature = "redis") {
        tracing::info!("REDIS_URL is not set; using the in-memory cache, queue, and rate limiter");
    } else if config.environment.is_production() {
        tracing::warn!(
            "this build excludes the redis feature; the cache, queue, and rate limiter are \
             in-memory and per instance, which suits a single instance only"
        );
    } else {
        tracing::info!(
            "this build excludes the redis feature; using the in-memory cache, queue, and rate limiter"
        );
    }
    Ok((
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryQueue::default()),
        Arc::new(MemoryRateLimiter::default()),
    ))
}

#[cfg_attr(not(feature = "kafka"), allow(unused_variables))]
fn event_publisher(
    config: &Config,
    memory_bus: &MemoryEventBus<DomainEvent>,
) -> Result<Arc<dyn EventPublisher<DomainEvent>>> {
    #[cfg(feature = "kafka")]
    if let Some(settings) = &config.kafka {
        let publisher = crate::events::kafka::KafkaPublisher::connect(settings)
            .context("Kafka producer setup failed")?;
        tracing::info!(topic = %settings.topic, "publishing domain events to Kafka");
        return Ok(Arc::new(publisher));
    }
    if cfg!(feature = "kafka") {
        tracing::info!("KAFKA_BROKERS is not set; using the in-process event bus");
    } else {
        tracing::info!("this build excludes the kafka feature; using the in-process event bus");
    }
    Ok(Arc::new(memory_bus.clone()))
}

/// The consumer side of [`event_publisher`]'s stream. Created only when the
/// application reads the stream: a Kafka consumer that joins a group it never
/// reads for would hold partitions other instances should be consuming.
#[cfg_attr(not(feature = "kafka"), allow(unused_variables))]
fn event_source(
    config: &Config,
    memory_bus: &MemoryEventBus<DomainEvent>,
) -> Result<EventSource<DomainEvent>> {
    #[cfg(feature = "kafka")]
    if let Some(settings) = &config.kafka {
        let source = EventSource::kafka(settings).context("Kafka consumer setup failed")?;
        tracing::info!(
            topic = %settings.topic,
            consumer_group = %settings.consumer_group,
            "consuming domain events from Kafka"
        );
        return Ok(source);
    }
    Ok(memory_bus.source())
}

const SESSION_PRUNE_INTERVAL: Duration = Duration::from_secs(3600);

/// Periodically deletes auth sessions whose whole rotation family has
/// expired (see `db::delete_expired_session_families`). Runs once at startup
/// and then hourly; concurrent instances pruning the same database is
/// harmless because the delete is idempotent.
async fn prune_sessions(pool: PgPool, mut shutdown: Shutdown) {
    let mut interval = tokio::time::interval(SESSION_PRUNE_INTERVAL);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.requested() => break,
            _ = interval.tick() => match db::delete_expired_session_families(&pool).await {
                Ok(0) => {}
                Ok(deleted) => tracing::info!(deleted, "pruned expired auth session families"),
                Err(error) => tracing::warn!(?error, "failed to prune expired auth sessions"),
            },
        }
    }
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
