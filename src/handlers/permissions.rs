use crate::{
    auth::AuthUser,
    error::{ApiJson, AppError},
    models::Role,
    permissions::Permission,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize)]
pub struct PermissionMatrixResponse {
    /// Every permission the demo endpoints enforce, for clients that render
    /// the matrix dynamically.
    catalog: Vec<PermissionDescriptor>,
    /// The current grants per role.
    roles: BTreeMap<Role, BTreeSet<Permission>>,
}

#[derive(Serialize)]
pub struct PermissionDescriptor {
    name: &'static str,
    description: &'static str,
}

#[derive(Deserialize)]
pub struct UpdateRolePermissionsRequest {
    permissions: BTreeSet<Permission>,
}

/// Public, read-only view of the role-permission matrix.
pub async fn matrix(State(state): State<AppState>) -> Json<PermissionMatrixResponse> {
    Json(matrix_response(&state))
}

/// Replaces one role's grants. Any signed-in user may edit the matrix so that
/// both demo roles can experiment with authorization outcomes; a production
/// system would gate this behind a dedicated management permission.
pub async fn update_role(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(role): Path<String>,
    ApiJson(request): ApiJson<UpdateRolePermissionsRequest>,
) -> Result<Json<PermissionMatrixResponse>, AppError> {
    let role = Role::from_name(&role).ok_or(AppError::NotFound("role"))?;
    state.permissions.set(role, request.permissions);
    Ok(Json(matrix_response(&state)))
}

fn matrix_response(state: &AppState) -> PermissionMatrixResponse {
    PermissionMatrixResponse {
        catalog: Permission::ALL
            .into_iter()
            .map(|permission| PermissionDescriptor {
                name: permission.name(),
                description: permission.description(),
            })
            .collect(),
        roles: state.permissions.grants(),
    }
}
