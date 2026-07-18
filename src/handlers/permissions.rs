use crate::{models::Role, permissions::Permission, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize)]
pub struct PermissionMatrixResponse {
    /// Every permission the endpoints enforce, for clients that render the
    /// matrix dynamically.
    catalog: Vec<PermissionDescriptor>,
    /// The fixed grants per role.
    roles: BTreeMap<Role, BTreeSet<Permission>>,
}

#[derive(Serialize)]
pub struct PermissionDescriptor {
    name: &'static str,
    description: &'static str,
}

/// Public, read-only view of the role-permission matrix. The grants are
/// fixed; there is deliberately no endpoint that edits them.
pub async fn matrix(State(state): State<AppState>) -> Json<PermissionMatrixResponse> {
    Json(PermissionMatrixResponse {
        catalog: Permission::ALL
            .into_iter()
            .map(|permission| PermissionDescriptor {
                name: permission.name(),
                description: permission.description(),
            })
            .collect(),
        roles: state.permissions.grants(),
    })
}
