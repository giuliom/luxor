//! Permission-gated demo endpoints. They serve fixed sample payloads; their
//! purpose is to show the permission checks succeeding or failing as the
//! role-permission matrix changes.

use crate::{
    auth::AuthUser, error::AppError, models::Role, permissions::Permission, state::AppState,
};
use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Serialize)]
pub struct ReportResponse {
    required_permission: &'static str,
    role: Role,
    generated_at: DateTime<Utc>,
    rows: [ReportRow; 3],
    note: &'static str,
}

#[derive(Serialize)]
pub struct ReportRow {
    metric: &'static str,
    value: u64,
}

pub async fn reports(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ReportResponse>, AppError> {
    state
        .permissions
        .require(auth.role, Permission::ReportsView)?;
    Ok(Json(ReportResponse {
        required_permission: Permission::ReportsView.name(),
        role: auth.role,
        generated_at: Utc::now(),
        rows: [
            ReportRow {
                metric: "active_sessions",
                value: 12,
            },
            ReportRow {
                metric: "queued_jobs",
                value: 3,
            },
            ReportRow {
                metric: "cache_entries",
                value: 42,
            },
        ],
        note: "Sample data demonstrating a permission-gated read.",
    }))
}

#[derive(Serialize)]
pub struct PurgeReceipt {
    required_permission: &'static str,
    role: Role,
    purged_records: u32,
    simulated: bool,
    note: &'static str,
}

pub async fn purge_records(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<PurgeReceipt>, AppError> {
    state
        .permissions
        .require(auth.role, Permission::RecordsPurge)?;
    Ok(Json(PurgeReceipt {
        required_permission: Permission::RecordsPurge.name(),
        role: auth.role,
        purged_records: 128,
        simulated: true,
        note:
            "Nothing was deleted; this endpoint demonstrates a permission-gated destructive action.",
    }))
}
