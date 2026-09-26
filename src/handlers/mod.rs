//! The foundation's endpoints. [`crate::routes`] groups them into routers an
//! application mounts.

pub mod auth;
pub mod health;
pub mod permissions;
#[cfg(feature = "realtime")]
pub mod realtime;
