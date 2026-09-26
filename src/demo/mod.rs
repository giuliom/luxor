//! The reference console and the demo endpoints it exercises.
//!
//! Everything here exists to show the foundation working end to end: a
//! localized browser console served at `/en` and `/it`, and endpoints that
//! demonstrate permissions, the cache, the queue, the event stream, tracing,
//! and WebAssembly. None of it is needed by an application built from this
//! template, which drops the `demo` feature and deletes this module together
//! with the code marked `feature = "demo"`.

mod console;
mod handlers;
#[cfg(test)]
mod tests;

use crate::{app::events::DomainEvent, events::EventLog, server::Routes, state::AppState};
use axum::{
    extract::FromRef,
    routing::{delete, get, post},
    Router,
};

/// The demo's own state.
#[derive(Clone, Default)]
pub struct DemoState {
    /// The tail of the event stream as this instance has consumed it, which
    /// `GET /api/events` serves. The application hands it to the event
    /// consumer ([`crate::app::App`]'s `event_handler`).
    pub event_log: EventLog<DomainEvent>,
}

/// The default policy plus `'wasm-unsafe-eval'` (CSP3), which permits the
/// console's WebAssembly compilation while still forbidding JavaScript `eval`.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'";

/// Adds the console pages, the demo endpoints, and the console's
/// Content-Security-Policy to `routes`.
pub fn routes<S>(routes: Routes<S>, core: &AppState) -> Routes<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
    DemoState: FromRef<S>,
{
    let api = Router::new()
        .route("/runtime", get(handlers::basic::runtime))
        .route("/hello", get(handlers::basic::hello))
        .route("/time", get(handlers::basic::time))
        .route("/telemetry/demo", get(handlers::basic::telemetry_demo))
        .route("/telemetry/traces/{trace_id}", get(handlers::basic::trace))
        .route("/demo/reports", get(handlers::permissions::reports))
        .route(
            "/demo/records",
            delete(handlers::permissions::purge_records),
        )
        .route(
            "/cache/demo",
            get(handlers::cache::get_demo)
                .put(handlers::cache::put_demo)
                .delete(handlers::cache::delete_demo),
        )
        .route("/jobs", post(handlers::jobs::enqueue))
        // Publishing goes to the broker; the listing comes back from it, by
        // way of the consumer that feeds this instance's event log.
        .route(
            "/events",
            get(handlers::events::stream).post(handlers::events::publish),
        );
    routes
        .api(api)
        .site(console::site(core))
        .content_security_policy(CONTENT_SECURITY_POLICY)
}
