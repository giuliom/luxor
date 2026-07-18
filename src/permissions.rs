use crate::{error::AppError, models::Role};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The fixed catalog of permissions enforced by the endpoints under
/// `/api/demo`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    #[serde(rename = "reports.view")]
    ReportsView,
    #[serde(rename = "records.purge")]
    RecordsPurge,
}

impl Permission {
    pub const ALL: [Permission; 2] = [Permission::ReportsView, Permission::RecordsPurge];

    pub fn name(self) -> &'static str {
        match self {
            Self::ReportsView => "reports.view",
            Self::RecordsPurge => "records.purge",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::ReportsView => "Read the operational demo report",
            Self::RecordsPurge => "Run the simulated record purge",
        }
    }
}

/// The permissions each role carries. This mapping is part of the
/// application's authorization contract: it is fixed at compile time,
/// identical across restarts and instances, and changes only through a code
/// change and deployment.
fn role_permissions(role: Role) -> &'static [Permission] {
    match role {
        Role::Admin => &Permission::ALL,
        Role::User => &[Permission::ReportsView],
    }
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
            .into_iter()
            .map(|role| (role, role_permissions(role).iter().copied().collect()))
            .collect()
    }

    pub fn allows(&self, role: Role, permission: Permission) -> bool {
        role_permissions(role).contains(&permission)
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
    fn grants_follow_least_privilege() {
        let store = PermissionStore;
        for permission in Permission::ALL {
            assert!(store.allows(Role::Admin, permission));
        }
        assert!(store.allows(Role::User, Permission::ReportsView));
        assert!(!store.allows(Role::User, Permission::RecordsPurge));
        assert!(matches!(
            store.require(Role::User, Permission::RecordsPurge),
            Err(AppError::MissingPermission("records.purge"))
        ));
    }

    #[test]
    fn matrix_covers_every_role() {
        let grants = PermissionStore.grants();
        assert_eq!(grants.len(), Role::ALL.len());
        assert!(grants[&Role::Admin].contains(&Permission::RecordsPurge));
        assert_eq!(
            grants[&Role::User],
            BTreeSet::from([Permission::ReportsView])
        );
    }

    #[test]
    fn permission_wire_names_round_trip() {
        for permission in Permission::ALL {
            let encoded = serde_json::to_string(&permission).unwrap();
            assert_eq!(encoded, format!("\"{}\"", permission.name()));
            assert_eq!(
                serde_json::from_str::<Permission>(&encoded).unwrap(),
                permission
            );
        }
        assert!(serde_json::from_str::<Permission>("\"reports.destroy\"").is_err());
    }
}
