//! The application's own configuration section, parsed with the rest of
//! [`crate::config::Config`] and available to handlers as
//! `state.config.app`.
//!
//! A setting is added as a field here and parsed in [`Settings::from_env`]
//! through the same helpers every other section uses, which gives it the same
//! empty-means-unset rule and the same error messages:
//!
//! ```ignore
//! pub struct Settings {
//!     pub invoice_prefix: String,
//! }
//!
//! impl Settings {
//!     pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
//!         Ok(Self {
//!             invoice_prefix: env.get("INVOICE_PREFIX").unwrap_or("INV").to_owned(),
//!         })
//!     }
//! }
//! ```

use crate::config::{ConfigError, Env};

#[derive(Clone, Debug, Default)]
pub struct Settings {}

impl Settings {
    pub fn from_env(_env: &Env) -> Result<Self, ConfigError> {
        Ok(Self {})
    }
}
