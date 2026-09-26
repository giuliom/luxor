//! The foundation's routes, in groups an application mounts under `/api`
//! through [`crate::server::Routes::api`]. [`api`] is all of them; the
//! individual groups let an application leave one out.
//!
//! Every group works with any router state that exposes the foundation's
//! [`AppState`] (`AppState: FromRef<S>`).

use crate::{
    handlers,
    rate_limit::{self, RateLimitPolicy},
    state::AppState,
};
use axum::{
    extract::FromRef,
    middleware,
    routing::{get, post},
    Router,
};

/// Every foundation route: [`health`], [`auth`], [`permissions`], and, with the
/// `realtime` feature, `realtime`.
pub fn api<S>(core: &AppState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    let router = Router::new()
        .merge(health())
        .merge(auth(core))
        .merge(permissions());
    #[cfg(feature = "realtime")]
    let router = router.merge(realtime());
    router
}

/// `GET /health`.
pub fn health<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    Router::new().route("/health", get(handlers::health::health))
}

/// Registration, login, refresh, and logout under `/auth`, and `GET /me`.
pub fn auth<S>(core: &AppState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    // The credential endpoints are the brute-force surface, so they carry
    // their own, much stricter budget on top of the API-wide one.
    let auth_rate_limit = RateLimitPolicy::new(core, "auth", core.config.rate_limit.auth);
    Router::new()
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .route("/auth/refresh", post(handlers::auth::refresh))
        .route("/auth/logout", post(handlers::auth::logout))
        .route_layer(middleware::from_fn_with_state(
            auth_rate_limit,
            rate_limit::enforce,
        ))
        .route("/me", get(handlers::auth::me))
}

/// `GET /permissions`: the public, read-only role-permission matrix.
pub fn permissions<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    Router::new().route("/permissions", get(handlers::permissions::matrix))
}

/// The ticket exchange and the WebSocket upgrade under `/realtime`.
#[cfg(feature = "realtime")]
pub fn realtime<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    // The ticket exchange is an ordinary authenticated POST; the upgrade that
    // redeems it authenticates itself with that ticket, because a browser
    // handshake cannot carry an Authorization header.
    Router::new()
        .route("/realtime/ticket", post(handlers::realtime::ticket))
        .route("/realtime/ws", get(handlers::realtime::connect))
}
