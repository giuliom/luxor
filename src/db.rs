use crate::{error::AppError, models::UserRecord};
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

pub async fn connect(database_url: &SecretString) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(600))
        .connect(database_url.expose_secret())
        .await
        .map_err(Into::into)
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
) -> Result<UserRecord, AppError> {
    sqlx::query_as::<_, UserRecord>(
        r#"
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id, email, password_hash, created_at, updated_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await
    .map_err(map_user_write_error)
}

pub async fn user_by_email(pool: &PgPool, email: &str) -> Result<Option<UserRecord>, AppError> {
    sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT id, email, password_hash, created_at, updated_at
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
        SELECT id, email, password_hash, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
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
) -> Result<Uuid, AppError> {
    let id = Uuid::new_v4();
    insert_session(pool, id, user_id, family_id, token_hash, expires_at).await?;
    Ok(id)
}

pub async fn insert_session<'e, E>(
    executor: E,
    id: Uuid,
    user_id: Uuid,
    family_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO auth_sessions (id, user_id, family_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(family_id)
    .bind(token_hash)
    .bind(expires_at)
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
