use crate::{
    error::AppError,
    models::{Role, UserRecord},
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

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
    sqlx::query_as::<_, UserRecord>(
        r#"
        INSERT INTO users (email, password_hash, role)
        VALUES ($1, $2, $3)
        RETURNING id, email, password_hash, role, created_at, updated_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .bind(role)
    .fetch_one(pool)
    .await
    .map_err(map_user_write_error)
}

pub async fn user_by_email(pool: &PgPool, email: &str) -> Result<Option<UserRecord>, AppError> {
    sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT id, email, password_hash, role, created_at, updated_at
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)
}

pub async fn user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRecord>, AppError> {
    sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT id, email, password_hash, role, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)
}

pub async fn update_user_role(
    pool: &PgPool,
    id: Uuid,
    role: Role,
) -> Result<Option<UserRecord>, AppError> {
    sqlx::query_as::<_, UserRecord>(
        r#"
        UPDATE users
        SET role = $2, updated_at = now()
        WHERE id = $1
        RETURNING id, email, password_hash, role, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(role)
    .fetch_optional(pool)
    .await
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

pub fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database_error| database_error.is_unique_violation())
}

fn map_user_write_error(error: sqlx::Error) -> AppError {
    if is_unique_violation(&error) {
        AppError::Conflict("user")
    } else {
        AppError::Database(error)
    }
}
