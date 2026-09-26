//! The application: everything a project built from this template makes its
//! own. The rest of the crate is the foundation it runs on, and is extended
//! from here rather than edited.
//!
//! * [`App`] tells [`crate::bootstrap`] what to serve: the router [`State`],
//!   the [`Routes`], the handler for the event stream, and any background
//!   tasks.
//! * [`access`] defines the roles and permissions, [`events`] the domain events,
//!   [`jobs`] the queued jobs, and [`Settings`] the application's own
//!   configuration.
//!
//! Code marked `feature = "demo"` wires in the reference console and its demo
//! endpoints (`crate::demo`); a real project deletes it along with that
//! module.

pub mod access;
pub mod events;
pub mod jobs;
mod settings;

pub use settings::Settings;

use crate::{bootstrap::Application, routes, server::Routes, state::AppState};
use axum::extract::FromRef;

/// The state every route is served with: the foundation's services, plus
/// whatever the application's own handlers need. A handler extracts any part
/// that has a `FromRef` impl below, such as `State<AppState>`.
#[derive(Clone)]
pub struct State {
    pub core: AppState,
    #[cfg(feature = "demo")]
    pub demo: crate::demo::DemoState,
}

impl FromRef<State> for AppState {
    fn from_ref(state: &State) -> Self {
        state.core.clone()
    }
}

#[cfg(feature = "demo")]
impl FromRef<State> for crate::demo::DemoState {
    fn from_ref(state: &State) -> Self {
        state.demo.clone()
    }
}

pub struct App;

impl Application for App {
    type State = State;

    fn state(&self, core: AppState) -> anyhow::Result<State> {
        Ok(State {
            core,
            #[cfg(feature = "demo")]
            demo: crate::demo::DemoState::default(),
        })
    }

    fn routes(&self, state: &State) -> Routes<State> {
        let routes = Routes::new().api(routes::api(&state.core));
        #[cfg(feature = "demo")]
        let routes = crate::demo::routes(routes, &state.core);
        routes
    }

    /// The console's event card lists what the consumer has read back.
    #[cfg(feature = "demo")]
    fn event_handler(
        &self,
        state: &State,
    ) -> Option<std::sync::Arc<dyn crate::events::EventHandler<events::DomainEvent>>> {
        Some(std::sync::Arc::new(state.demo.event_log.clone()))
    }
}
