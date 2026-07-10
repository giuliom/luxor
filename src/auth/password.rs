use crate::error::AppError;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub async fn hash_password(password: String) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AppError::Authentication)
    })
    .await
    .map_err(|_| AppError::Authentication)?
}

pub async fn verify_password(password: String, encoded_hash: String) -> Result<bool, AppError> {
    tokio::task::spawn_blocking(move || {
        let hash = PasswordHash::new(&encoded_hash).map_err(|_| AppError::Authentication)?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok())
    })
    .await
    .map_err(|_| AppError::Authentication)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_and_verifies_passwords() {
        let hash = hash_password("correct horse battery staple".into())
            .await
            .unwrap();
        assert!(
            verify_password("correct horse battery staple".into(), hash.clone())
                .await
                .unwrap()
        );
        assert!(!verify_password("wrong".into(), hash).await.unwrap());
    }
}
