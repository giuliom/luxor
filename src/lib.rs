//! A production-oriented Axum backend template.
//!
//! [`app`] is the application: its routes, state, domain types, and
//! settings. Everything else is the foundation it runs on — configuration,
//! the HTTP server and its middleware, authentication, persistence, the cache,
//! queue, event stream, and rate limiter, observability — which an application
//! extends through [`bootstrap::Application`] rather than by editing it.
//! `demo` is the reference console and its demo endpoints, compiled only
//! with the `demo` feature.

pub mod access;
pub mod app;
pub mod assets;
pub mod auth;
pub mod bootstrap;
pub mod cache;
pub mod config;
pub mod db;
#[cfg(feature = "demo")]
pub mod demo;
pub mod dev_postgres;
pub mod error;
pub mod events;
pub mod handlers;
pub mod i18n;
pub mod models;
pub mod observability;
pub mod queue;
pub mod rate_limit;
#[cfg(feature = "realtime")]
pub mod realtime;
pub mod routes;
pub mod server;
pub mod services;
pub mod state;
pub mod tasks;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub mod validation;
