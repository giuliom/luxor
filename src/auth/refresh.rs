use crate::{db, error::AppError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

pub struct RefreshGrant {
    pub token: String,
    pub user_id: Uuid,
}

pub async fn issue_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    lifetime_seconds: i64,
) -> Result<RefreshGrant, AppError> {
    let token = random_token();
    db::create_session(
        pool,
        user_id,
        Uuid::new_v4(),
        &hash_refresh_token(&token),
        Utc::now() + Duration::seconds(lifetime_seconds),
    )
    .await?;
    Ok(RefreshGrant { token, user_id })
}

pub async fn rotate_refresh_token(
    pool: &PgPool,
    presented_token: &str,
    lifetime_seconds: i64,
) -> Result<RefreshGrant, AppError> {
    let presented_hash = hash_refresh_token(presented_token);
    let mut transaction = pool.begin().await?;
    let session = sqlx::query_as::<_, crate::models::SessionRecord>(
        r#"
        SELECT id, user_id, family_id, token_hash, expires_at, revoked_at, replaced_by, created_at
        FROM auth_sessions
        WHERE token_hash = $1
        FOR UPDATE
        "#,
    )
    .bind(&presented_hash)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if session.revoked_at.is_some() {
        db::revoke_family(&mut transaction, session.family_id).await?;
        transaction.commit().await?;
        return Err(AppError::Unauthorized);
    }
    if session.expires_at <= Utc::now() {
        transaction.rollback().await?;
        return Err(AppError::Unauthorized);
    }

    let token = random_token();
    let next_id = Uuid::new_v4();
    db::insert_session(
        &mut *transaction,
        next_id,
        session.user_id,
        session.family_id,
        &hash_refresh_token(&token),
        Utc::now() + Duration::seconds(lifetime_seconds),
    )
    .await?;
    sqlx::query(
        r#"
        UPDATE auth_sessions
        SET revoked_at = now(), replaced_by = $2
        WHERE id = $1
        "#,
    )
    .bind(session.id)
    .bind(next_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(RefreshGrant {
        token,
        user_id: session.user_id,
    })
}

pub fn hash_refresh_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hashes_are_deterministic_without_storing_the_secret() {
        let token = random_token();
        let hash = hash_refresh_token(&token);
        assert_eq!(hash, hash_refresh_token(&token));
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains(&token));
    }
}
