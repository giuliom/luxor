//! The application's roles and permissions.
//!
//! This file is the authorization vocabulary: which roles an account can hold,
//! which permissions exist, and which role holds which. The foundation relies
//! only on the [`AccessRole`] and [`AccessPermission`] contracts, so roles and
//! permissions are changed here and nowhere else. The endpoints enforce them
//! through [`crate::access::PermissionStore`].
//!
//! A role is stored by its wire name, so renaming or removing one needs a
//! migration for the accounts that hold it: an unknown stored role fails the
//! read rather than falling back to another role.

use crate::access::{AccessPermission, AccessRole};
use serde::{Deserialize, Serialize};

/// The authorization role, chosen once at registration and immutable
/// afterwards.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    #[default]
    User,
}

impl AccessRole for Role {
    type Permission = Permission;

    const ALL: &'static [Self] = &[Self::Admin, Self::User];

    fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    fn permissions(self) -> &'static [Permission] {
        match self {
            Self::Admin => Permission::ALL,
            Self::User => &[
                #[cfg(feature = "demo")]
                Permission::ReportsView,
            ],
        }
    }
}

/// Everything a role can be granted. The two permissions here are the demo's;
/// a project replaces them with its own.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    #[cfg(feature = "demo")]
    #[serde(rename = "reports.view")]
    ReportsView,
    #[cfg(feature = "demo")]
    #[serde(rename = "records.purge")]
    RecordsPurge,
}

impl AccessPermission for Permission {
    const ALL: &'static [Self] = &[
        #[cfg(feature = "demo")]
        Self::ReportsView,
        #[cfg(feature = "demo")]
        Self::RecordsPurge,
    ];

    fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "demo")]
            Self::ReportsView => "reports.view",
            #[cfg(feature = "demo")]
            Self::RecordsPurge => "records.purge",
        }
    }

    fn description(self) -> &'static str {
        match self {
            #[cfg(feature = "demo")]
            Self::ReportsView => "Read the operational demo report",
            #[cfg(feature = "demo")]
            Self::RecordsPurge => "Run the simulated record purge",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_is_the_default_role() {
        assert_eq!(Role::default(), Role::User);
        assert_eq!(Role::from_name("superuser"), None);
    }

    #[test]
    fn admins_hold_every_permission() {
        assert_eq!(Role::Admin.permissions(), Permission::ALL);
    }

    #[cfg(feature = "demo")]
    #[test]
    fn grants_follow_least_privilege() {
        use crate::{access::PermissionStore, error::AppError};
        use std::collections::BTreeSet;

        let store = PermissionStore;
        assert!(store.allows(Role::User, Permission::ReportsView));
        assert!(!store.allows(Role::User, Permission::RecordsPurge));
        assert!(matches!(
            store.require(Role::User, Permission::RecordsPurge),
            Err(AppError::MissingPermission("records.purge"))
        ));
        assert_eq!(
            store.grants()[&Role::User],
            BTreeSet::from([Permission::ReportsView])
        );
        assert!(serde_json::from_str::<Permission>("\"reports.destroy\"").is_err());
    }
}
