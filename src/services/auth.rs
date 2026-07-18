use crate::{
    auth::{
        equalize_login_timing, hash_password, issue_refresh_token, verify_password, RefreshGrant,
        RefreshPolicy,
    },
    db,
    error::AppError,
    models::{Role, UserRecord},
};
use sqlx::PgPool;

const PASSWORD_MIN_LENGTH: usize = 12;
const PASSWORD_MAX_LENGTH: usize = 1024;

pub async fn register(
    pool: &PgPool,
    email: &str,
    password: String,
    role: Role,
    refresh_policy: RefreshPolicy,
) -> Result<(UserRecord, RefreshGrant), AppError> {
    validate_credentials(email, &password)?;
    let password_hash = hash_password(password).await?;
    let user = db::create_user(pool, &normalize_email(email), &password_hash, role).await?;
    let grant = issue_refresh_token(pool, user.id, refresh_policy).await?;
    Ok((user, grant))
}

pub async fn login(
    pool: &PgPool,
    email: &str,
    password: String,
    refresh_policy: RefreshPolicy,
) -> Result<(UserRecord, RefreshGrant), AppError> {
    // Registration bounds password length, so nothing longer can match a
    // stored credential; rejecting outsized input up front keeps login from
    // feeding attacker-controlled megabytes into argon2.
    if password.len() > PASSWORD_MAX_LENGTH {
        return Err(AppError::Unauthorized);
    }
    let Some(user) = db::user_by_email(pool, &normalize_email(email)).await? else {
        // An unknown email still burns one argon2 verification so that
        // response timing does not reveal which emails are registered.
        equalize_login_timing(password).await?;
        return Err(AppError::Unauthorized);
    };
    if !verify_password(password, user.password_hash.clone()).await? {
        return Err(AppError::Unauthorized);
    }
    let grant = issue_refresh_token(pool, user.id, refresh_policy).await?;
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
    if !(PASSWORD_MIN_LENGTH..=PASSWORD_MAX_LENGTH).contains(&password.len()) {
        return Err(AppError::BadRequest(format!(
            "password must contain between {PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH} characters"
        )));
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
        assert!(validate_credentials("person@example.com", &"x".repeat(1025)).is_err());
    }
}
