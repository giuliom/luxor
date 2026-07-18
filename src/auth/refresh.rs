use crate::{config::Config, db, error::AppError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Lifetimes governing refresh tokens. Each rotation issues a token with a
/// fresh `token_ttl_seconds`, but a rotation family as a whole never outlives
/// `family_ttl_seconds` from the login that created it, so a stolen cookie
/// cannot be renewed forever.
#[derive(Clone, Copy, Debug)]
pub struct RefreshPolicy {
    pub token_ttl_seconds: i64,
    pub family_ttl_seconds: i64,
}

impl RefreshPolicy {
    pub fn from_config(config: &Config) -> Self {
        Self {
            token_ttl_seconds: config.refresh_token_ttl_seconds,
            family_ttl_seconds: config.refresh_family_ttl_seconds,
        }
    }
}

pub struct RefreshGrant {
    pub token: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

pub async fn issue_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    policy: RefreshPolicy,
) -> Result<RefreshGrant, AppError> {
    let token = random_token();
    let now = Utc::now();
    let expires_at = now + Duration::seconds(policy.token_ttl_seconds);
    db::create_session(
        pool,
        user_id,
        Uuid::new_v4(),
        &hash_refresh_token(&token),
        expires_at,
        now + Duration::seconds(policy.family_ttl_seconds),
    )
    .await?;
    Ok(RefreshGrant {
        token,
        user_id,
        expires_at,
    })
}

pub async fn rotate_refresh_token(
    pool: &PgPool,
    presented_token: &str,
    policy: RefreshPolicy,
) -> Result<RefreshGrant, AppError> {
    let presented_hash = hash_refresh_token(presented_token);
    let mut transaction = pool.begin().await?;
    let session = sqlx::query_as::<_, crate::models::SessionRecord>(
        r#"
        SELECT id, user_id, family_id, token_hash, expires_at, family_expires_at,
               revoked_at, replaced_by, created_at
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
    let now = Utc::now();
    if session.expires_at <= now || session.family_expires_at <= now {
        transaction.rollback().await?;
        return Err(AppError::Unauthorized);
    }

    let token = random_token();
    let next_id = Uuid::new_v4();
    let expires_at = rotated_expiry(now, policy.token_ttl_seconds, session.family_expires_at);
    db::insert_session(
        &mut *transaction,
        next_id,
        session.user_id,
        session.family_id,
        &hash_refresh_token(&token),
        expires_at,
        session.family_expires_at,
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
        expires_at,
    })
}

/// Rotated tokens get a full lifetime, but never one that outlives the
/// family's absolute expiry.
fn rotated_expiry(
    now: DateTime<Utc>,
    token_ttl_seconds: i64,
    family_expires_at: DateTime<Utc>,
) -> DateTime<Utc> {
    (now + Duration::seconds(token_ttl_seconds)).min(family_expires_at)
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

    #[test]
    fn rotation_never_extends_past_the_family_expiry() {
        let now = Utc::now();

        let distant_family_expiry = now + Duration::seconds(1_000);
        assert_eq!(
            rotated_expiry(now, 60, distant_family_expiry),
            now + Duration::seconds(60)
        );

        let imminent_family_expiry = now + Duration::seconds(30);
        assert_eq!(
            rotated_expiry(now, 60, imminent_family_expiry),
            imminent_family_expiry
        );
    }
}
