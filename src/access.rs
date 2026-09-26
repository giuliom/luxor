//! Role-based access control.
//!
//! The vocabulary — which roles exist, which permissions exist, and which role
//! holds which — belongs to the application and lives in
//! [`crate::app::access`]. This module is the contract that vocabulary fulfils
//! ([`AccessRole`], [`AccessPermission`]) and the single enforcement seam every
//! endpoint goes through ([`PermissionStore`]).

use crate::error::AppError;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};

pub use crate::app::access::{Permission, Role};

/// What the foundation needs from the application's role type.
///
/// A role is chosen at registration, stored in the `users.role` column by its
/// [`name`](AccessRole::name), and carried in every access token, so its
/// serde representation must be that same name.
pub trait AccessRole:
    Copy + Eq + Ord + Debug + Default + Serialize + DeserializeOwned + Send + Sync + 'static
{
    type Permission: AccessPermission;

    /// Every role, in the order the permission matrix lists them.
    const ALL: &'static [Self];

    /// The wire name used in JSON, in the database, and in access tokens.
    fn name(self) -> &'static str;

    /// The permissions this role holds. The mapping is part of the
    /// application's authorization contract: fixed at compile time, identical
    /// across restarts and instances, and changed only by a deployment.
    fn permissions(self) -> &'static [Self::Permission];

    /// Parses the wire name used in JSON bodies and URL paths.
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|role| role.name() == name)
    }
}

/// What the foundation needs from the application's permission type.
pub trait AccessPermission:
    Copy + Eq + Ord + Debug + Serialize + DeserializeOwned + Send + Sync + 'static
{
    /// Every permission, in the order the permission matrix lists them.
    const ALL: &'static [Self];

    /// The wire name, which must match the serde representation.
    fn name(self) -> &'static str;

    /// A one-line English description for the API's permission catalog.
    fn description(self) -> &'static str;
}

/// Read-only view over the fixed role-to-permission grants.
///
/// The store is a stateless handle so that call sites keep a single
/// enforcement seam; a future system that loads grants from storage can grow
/// behind the same methods.
#[derive(Clone, Copy, Default)]
pub struct PermissionStore;

impl PermissionStore {
    /// The full matrix, in the shape the `/api/permissions` endpoint serves.
    pub fn grants(&self) -> BTreeMap<Role, BTreeSet<Permission>> {
        Role::ALL
            .iter()
            .map(|&role| (role, role.permissions().iter().copied().collect()))
            .collect()
    }

    pub fn allows(&self, role: Role, permission: Permission) -> bool {
        role.permissions().contains(&permission)
    }

    pub fn require(&self, role: Role, permission: Permission) -> Result<(), AppError> {
        if self.allows(role, permission) {
            Ok(())
        } else {
            Err(AppError::MissingPermission(permission.name()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_matrix_is_exactly_the_declared_grants() {
        let store = PermissionStore;
        let grants = store.grants();
        assert_eq!(grants.len(), Role::ALL.len());
        for &role in Role::ALL {
            for &permission in Permission::ALL {
                let granted = role.permissions().contains(&permission);
                assert_eq!(grants[&role].contains(&permission), granted);
                assert_eq!(store.allows(role, permission), granted);
                assert_eq!(store.require(role, permission).is_ok(), granted);
            }
        }
    }

    #[test]
    fn a_missing_permission_is_named_in_the_error() {
        let store = PermissionStore;
        for &role in Role::ALL {
            for &permission in Permission::ALL {
                if let Err(error) = store.require(role, permission) {
                    assert!(matches!(
                        error,
                        AppError::MissingPermission(name) if name == permission.name()
                    ));
                }
            }
        }
    }

    #[test]
    fn wire_names_match_the_serde_representation() {
        for &role in Role::ALL {
            assert_eq!(Role::from_name(role.name()), Some(role));
            assert_eq!(
                serde_json::to_string(&role).unwrap(),
                format!("\"{}\"", role.name())
            );
        }
        assert_eq!(Role::from_name("not-a-role"), None);
        for &permission in Permission::ALL {
            let encoded = serde_json::to_string(&permission).unwrap();
            assert_eq!(encoded, format!("\"{}\"", permission.name()));
            // Compared as `Option`s: without the demo the permission type has
            // no values, and a call returning one directly is unreachable code.
            assert_eq!(
                serde_json::from_str::<Permission>(&encoded).ok(),
                Some(permission)
            );
        }
    }
}
