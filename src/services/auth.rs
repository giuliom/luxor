use crate::{
    auth::{hash_password, issue_refresh_token, verify_password, RefreshGrant},
    db,
    error::AppError,
    models::{Role, UserRecord},
};
use sqlx::PgPool;

pub async fn register(
    pool: &PgPool,
    email: &str,
    password: String,
    role: Role,
    refresh_lifetime_seconds: i64,
) -> Result<(UserRecord, RefreshGrant), AppError> {
    validate_credentials(email, &password)?;
    let password_hash = hash_password(password).await?;
    let user = db::create_user(pool, &normalize_email(email), &password_hash, role).await?;
    let grant = issue_refresh_token(pool, user.id, refresh_lifetime_seconds).await?;
    Ok((user, grant))
}

pub async fn login(
    pool: &PgPool,
    email: &str,
    password: String,
    refresh_lifetime_seconds: i64,
) -> Result<(UserRecord, RefreshGrant), AppError> {
    let user = db::user_by_email(pool, &normalize_email(email))
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !verify_password(password, user.password_hash.clone()).await? {
        return Err(AppError::Unauthorized);
    }
    let grant = issue_refresh_token(pool, user.id, refresh_lifetime_seconds).await?;
    Ok((user, grant))
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn validate_credentials(email: &str, password: &str) -> Result<(), AppError> {
    let email = email.trim();
    let looks_like_email = email.len() <= 320
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    if !looks_like_email {
        return Err(AppError::BadRequest("a valid email is required".into()));
    }
    if !(12..=1024).contains(&password.len()) {
        return Err(AppError::BadRequest(
            "password must contain between 12 and 1024 characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_registration_credentials() {
        assert!(validate_credentials("person@example.com", "long-enough-password").is_ok());
        assert!(validate_credentials("not-email", "long-enough-password").is_err());
        assert!(validate_credentials("person@example.com", "short").is_err());
    }
}
