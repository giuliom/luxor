use crate::{error::AppError, models::Role};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

/// The fixed catalog of permissions enforced by the demo endpoints under
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

/// Runtime-editable role-to-permission grants.
///
/// The store is deliberately in-memory: the browser console edits it to
/// demonstrate authorization outcomes without a redeploy, and a restart
/// restores the defaults. A production system would persist grants and gate
/// changes behind a dedicated management permission.
#[derive(Clone)]
pub struct PermissionStore {
    grants: Arc<RwLock<BTreeMap<Role, BTreeSet<Permission>>>>,
}

impl Default for PermissionStore {
    fn default() -> Self {
        Self {
            grants: Arc::new(RwLock::new(BTreeMap::from([
                (Role::Admin, BTreeSet::from(Permission::ALL)),
                (Role::User, BTreeSet::from([Permission::ReportsView])),
            ]))),
        }
    }
}

impl PermissionStore {
    pub fn grants(&self) -> BTreeMap<Role, BTreeSet<Permission>> {
        self.read().clone()
    }

    /// Replaces one role's grants with the presented set.
    pub fn set(&self, role: Role, permissions: BTreeSet<Permission>) {
        self.grants
            .write()
            .expect("permission store lock poisoned")
            .insert(role, permissions);
    }

    pub fn allows(&self, role: Role, permission: Permission) -> bool {
        self.read()
            .get(&role)
            .is_some_and(|granted| granted.contains(&permission))
    }

    pub fn require(&self, role: Role, permission: Permission) -> Result<(), AppError> {
        if self.allows(role, permission) {
            Ok(())
        } else {
            Err(AppError::MissingPermission(permission.name()))
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<Role, BTreeSet<Permission>>> {
        self.grants.read().expect("permission store lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_grants_follow_least_privilege() {
        let store = PermissionStore::default();
        for permission in Permission::ALL {
            assert!(store.allows(Role::Admin, permission));
        }
        assert!(store.allows(Role::User, Permission::ReportsView));
        assert!(!store.allows(Role::User, Permission::RecordsPurge));
    }

    #[test]
    fn replacing_grants_changes_enforcement() {
        let store = PermissionStore::default();
        assert!(store.require(Role::User, Permission::RecordsPurge).is_err());

        store.set(Role::User, BTreeSet::from(Permission::ALL));
        assert!(store.require(Role::User, Permission::RecordsPurge).is_ok());

        store.set(Role::User, BTreeSet::new());
        assert!(matches!(
            store.require(Role::User, Permission::ReportsView),
            Err(AppError::MissingPermission("reports.view"))
        ));
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
