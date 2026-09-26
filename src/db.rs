use crate::{
    access::{AccessRole, Role},
    config::{ConfigError, Env},
    error::AppError,
    models::UserRecord,
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

/// Where the application's PostgreSQL lives, and whether startup migrates it.
#[derive(Clone, Debug)]
pub struct DatabaseSettings {
    /// `None` selects the embedded development PostgreSQL server; production
    /// configuration always carries a URL.
    pub url: Option<SecretString>,
    /// Migrate an external database at startup. The embedded development
    /// server always migrates itself; production migrates as a release step.
    pub auto_migrate: bool,
}

impl DatabaseSettings {
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let url = env.infrastructure_url("DATABASE_URL", &["postgres", "postgresql"])?;
        let auto_migrate = env.parse("AUTO_MIGRATE", !env.is_production())?;
        if env.is_production() && auto_migrate {
            return Err(ConfigError::Validation(
                "AUTO_MIGRATE cannot be enabled in production".into(),
            ));
        }
        Ok(Self { url, auto_migrate })
    }
}

const DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn connect(database_url: &SecretString) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        // PostgreSQL containers can accept TCP connections before they are
        // ready to authenticate. Keep retrying during that short startup
        // window instead of failing the application immediately.
        .acquire_timeout(DATABASE_CONNECT_TIMEOUT)
        .idle_timeout(Duration::from_secs(600))
        .connect(database_url.expose_secret())
        .await
        .context(
            "could not connect to PostgreSQL; verify that it is running and that DATABASE_URL is reachable",
        )
}

pub fn connect_lazy(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy(database_url)
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!()
        .run(pool)
        .await
        .map_err(anyhow::Error::from)
}

pub async fn create_user(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    role: Role,
) -> Result<UserRecord, AppError> {
    sqlx::query_as::<_, UserRow>(
        r#"
        INSERT INTO users (email, password_hash, role)
        VALUES ($1, $2, $3)
        RETURNING id, email, password_hash, role, created_at, updated_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .bind(role.name())
    .fetch_one(pool)
    .await
    .map_err(map_user_write_error)?
    .try_into()
    .map_err(AppError::from)
}

pub async fn user_by_email(pool: &PgPool, email: &str) -> Result<Option<UserRecord>, AppError> {
    sqlx::query_as::<_, UserRow>(
        r#"
        SELECT id, email, password_hash, role, created_at, updated_at
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await?
    .map(UserRecord::try_from)
    .transpose()
    .map_err(AppError::from)
}

/// Replaces a stored password hash in place. Used to re-hash an account at
/// the current argon2 cost after its owner logs in, so raising the pinned
/// parameters upgrades existing users instead of only new ones.
pub async fn update_password_hash(
    pool: &PgPool,
    id: Uuid,
    password_hash: &str,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE users
        SET password_hash = $2, updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(password_hash)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(AppError::from)
}

pub async fn user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRecord>, AppError> {
    sqlx::query_as::<_, UserRow>(
        r#"
        SELECT id, email, password_hash, role, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(UserRecord::try_from)
    .transpose()
    .map_err(AppError::from)
}

pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    family_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
    family_expires_at: DateTime<Utc>,
) -> Result<Uuid, AppError> {
    let id = Uuid::new_v4();
    insert_session(
        pool,
        id,
        user_id,
        family_id,
        token_hash,
        expires_at,
        family_expires_at,
    )
    .await?;
    Ok(id)
}

pub async fn insert_session<'e, E>(
    executor: E,
    id: Uuid,
    user_id: Uuid,
    family_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
    family_expires_at: DateTime<Utc>,
) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO auth_sessions (id, user_id, family_id, token_hash, expires_at, family_expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(family_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(family_expires_at)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn revoke_session(pool: &PgPool, token_hash: &str) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE auth_sessions
        SET revoked_at = COALESCE(revoked_at, now())
        WHERE token_hash = $1
        "#,
    )
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn revoke_family(
    transaction: &mut Transaction<'_, Postgres>,
    family_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE auth_sessions
        SET revoked_at = COALESCE(revoked_at, now())
        WHERE family_id = $1
        "#,
    )
    .bind(family_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Deletes sessions whose whole rotation family has expired. Every token in
/// such a family already fails rotation on the expiry check, so removing the
/// rows changes no behavior — it only stops the table from growing without
/// bound. Rows are deliberately kept until then: a revoked row is what lets
/// rotation detect the replay of a stolen token and revoke its family.
pub async fn delete_expired_session_families(pool: &PgPool) -> Result<u64, AppError> {
    let result = sqlx::query("DELETE FROM auth_sessions WHERE family_expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
}

/// A `users` row as PostgreSQL returns it. The role column is plain TEXT
/// holding the role's wire name, so the application's role type needs no
/// database mapping of its own.
#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    password_hash: String,
    role: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<UserRow> for UserRecord {
    type Error = sqlx::Error;

    /// A role the application no longer defines fails the read, exactly as an
    /// undecodable column would, rather than being coerced into another role.
    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        let role = Role::from_name(&row.role).ok_or_else(|| {
            sqlx::Error::Decode(format!("unknown role {:?} in database", row.role).into())
        })?;
        Ok(Self {
            id: row.id,
            email: row.email,
            password_hash: row.password_hash,
            role,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

fn map_user_write_error(error: sqlx::Error) -> AppError {
    if is_unique_violation(&error) {
        AppError::Conflict("user")
    } else {
        AppError::Database(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::values;

    fn settings(pairs: &[(&str, &str)]) -> Result<DatabaseSettings, ConfigError> {
        DatabaseSettings::from_env(&Env::new(values(pairs))?)
    }

    #[test]
    fn development_selects_the_embedded_server_and_migrates() {
        let database = settings(&[]).unwrap();
        assert!(database.url.is_none());
        assert!(database.auto_migrate);
    }

    #[test]
    fn explicit_urls_are_kept_and_validated() {
        let database =
            settings(&[("DATABASE_URL", "postgres://test@localhost:5432/test")]).unwrap();
        assert!(database.url.is_some());

        assert!(matches!(
            settings(&[("DATABASE_URL", "mysql://nope")]),
            Err(ConfigError::Invalid("DATABASE_URL", _))
        ));
    }

    #[test]
    fn production_requires_a_url_and_never_migrates_at_startup() {
        assert_eq!(
            settings(&[("APP_ENV", "production")]).unwrap_err(),
            ConfigError::Missing("DATABASE_URL")
        );

        let production = [
            ("APP_ENV", "production"),
            ("DATABASE_URL", "postgres://test@localhost:5432/test"),
        ];
        assert!(!settings(&production).unwrap().auto_migrate);
        assert!(matches!(
            settings(&[production[0], production[1], ("AUTO_MIGRATE", "true")]),
            Err(ConfigError::Validation(message)) if message.contains("AUTO_MIGRATE")
        ));
    }

    #[test]
    fn stored_roles_decode_by_wire_name_and_unknown_ones_fail() {
        let row = |role: &str| UserRow {
            id: Uuid::new_v4(),
            email: "person@example.com".into(),
            password_hash: "hash".into(),
            role: role.into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        for role in Role::ALL {
            assert_eq!(UserRecord::try_from(row(role.name())).unwrap().role, *role);
        }
        assert!(matches!(
            UserRecord::try_from(row("superuser")),
            Err(sqlx::Error::Decode(_))
        ));
    }
}
