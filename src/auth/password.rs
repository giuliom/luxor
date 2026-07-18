use crate::error::AppError;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::sync::LazyLock;

/// PHC hash of a fixed throwaway password, computed once with the same
/// default parameters as real hashes. Verifying a submitted password against
/// it costs exactly one argon2 verification; the outcome is always discarded,
/// so the password's value is irrelevant.
static TIMING_EQUALIZER_HASH: LazyLock<String> = LazyLock::new(|| {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(b"luxor-timing-equalizer", &salt)
        .expect("hashing a fixed password with default parameters cannot fail")
        .to_string()
});

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

/// Computes the timing-equalizer hash ahead of the first login, so even the
/// first unknown-email attempt after startup is indistinguishable. Called
/// from a blocking context at startup; safe to skip (the hash would simply
/// be computed on first use).
pub fn prewarm_login_timing_equalizer() {
    LazyLock::force(&TIMING_EQUALIZER_HASH);
}

/// Burns the same work as [`verify_password`] without a real account, so a
/// login naming an unknown email takes as long as one with a wrong password
/// and response timing does not reveal which emails are registered. Never
/// authenticates anything.
pub async fn equalize_login_timing(password: String) -> Result<(), AppError> {
    tokio::task::spawn_blocking(move || {
        let hash = PasswordHash::new(&TIMING_EQUALIZER_HASH)
            .expect("the timing-equalizer hash is a valid PHC string");
        let _ = Argon2::default().verify_password(password.as_bytes(), &hash);
    })
    .await
    .map_err(|_| AppError::Authentication)
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

    // Timing itself is not asserted (that would be flaky); the equalizer's
    // cost equivalence comes from sharing verify_password's argon2 parameters.
    #[tokio::test]
    async fn timing_equalizer_never_authenticates() {
        equalize_login_timing("any password at all".into())
            .await
            .unwrap();
        equalize_login_timing("luxor-timing-equalizer".into())
            .await
            .unwrap();
    }
}
