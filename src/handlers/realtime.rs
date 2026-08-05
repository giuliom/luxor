//! The realtime demo's two endpoints: the ticket exchange that authorizes one
//! handshake, and the WebSocket upgrade that redeems it.
//!
//! Both live under `/api`, so the per-client rate limiter meters them. It sees
//! the handshake and nothing after it; what happens on an established socket
//! is bounded by [`crate::realtime`] instead.

use crate::{
    auth::AuthUser,
    error::AppError,
    realtime::{self, Participant},
    state::AppState,
};
use axum::{
    extract::{
        ws::{rejection::WebSocketUpgradeRejection, WebSocketUpgrade},
        Query, State,
    },
    http::{header, HeaderMap},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize)]
pub struct TicketResponse {
    ticket: String,
    expires_in: u64,
    /// Where to redeem it, so the client does not hardcode the route.
    websocket_path: &'static str,
}

/// Issues a single-use ticket for one WebSocket handshake.
///
/// This is the authenticated half of the connection: it is an ordinary bearer
/// JWT request, and the ticket it returns is what the browser can actually
/// send on a handshake that cannot carry an `Authorization` header.
pub async fn ticket(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<TicketResponse>, AppError> {
    let ttl_seconds = state.config.realtime.ticket_ttl_seconds;
    let ticket = realtime::issue_ticket(
        state.cache.as_ref(),
        Participant {
            user_id: auth.id,
            role: auth.role,
        },
        Duration::from_secs(ttl_seconds),
    )
    .await?;
    Ok(Json(TicketResponse {
        ticket,
        expires_in: ttl_seconds,
        websocket_path: "/api/realtime/ws",
    }))
}

#[derive(Deserialize)]
pub struct ConnectParams {
    ticket: Option<String>,
}

/// Upgrades a handshake into a realtime connection.
///
/// The checks run in the order that wastes the least: the origin decides
/// whether the caller may talk to this endpoint at all, the upgrade headers
/// decide whether a socket is even on the table, and only then is the ticket
/// redeemed — a ticket burned by a botched handshake would force the client
/// through the whole exchange again.
pub async fn connect(
    State(state): State<AppState>,
    Query(params): Query<ConnectParams>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, AppError> {
    if !realtime::origin_allowed(
        header_str(&headers, header::ORIGIN),
        header_str(&headers, header::HOST),
        &state.config.cors_origins,
    ) {
        return Err(AppError::Forbidden);
    }
    let upgrade = upgrade.map_err(|rejection| AppError::BadRequest(rejection.body_text()))?;

    // Held from here on: if the ticket turns out to be invalid, dropping the
    // slot on the error path frees the capacity again.
    let slot = state
        .realtime
        .try_admit()
        .ok_or(AppError::AtCapacity("the realtime demo"))?;
    let participant = realtime::consume_ticket(
        state.cache.as_ref(),
        params.ticket.as_deref().unwrap_or_default(),
    )
    .await?;

    let hub = state.realtime.clone();
    Ok(upgrade
        // Caps what one connection can make the server buffer. tungstenite
        // fails the connection rather than truncating, which is why the limit
        // sits well above any valid command.
        .max_message_size(realtime::MAX_MESSAGE_BYTES)
        .max_frame_size(realtime::MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| realtime::run_connection(socket, hub, slot, participant)))
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}
