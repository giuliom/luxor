use crate::error::AppError;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use secrecy::{ExposeSecret, SecretString};
use std::sync::LazyLock;

/// The Argon2id cost is pinned here rather than taken from `Argon2::default()`
/// so that a crate upgrade cannot move it in either direction unnoticed. These
/// values are OWASP's second recommended configuration and happen to match the
/// argon2 0.5 defaults, so pinning changes nothing today; raising them becomes
/// a deliberate edit to this file, after which [`verify_password`] upgrades
/// stored hashes as their owners log in.
const ALGORITHM: Algorithm = Algorithm::Argon2id;
const VERSION: Version = Version::V0x13;
const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

static HASHER: LazyLock<Argon2<'static>> = LazyLock::new(|| {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .expect("the pinned argon2 parameters are within the crate's accepted range");
    Argon2::new(ALGORITHM, VERSION, params)
});

/// PHC hash of a fixed throwaway password, computed once with the same pinned
/// parameters as real hashes. Verifying a submitted password against it costs
/// exactly one argon2 verification; the outcome is always discarded, so the
/// password's value is irrelevant.
static TIMING_EQUALIZER_HASH: LazyLock<String> = LazyLock::new(|| {
    let salt = SaltString::generate(&mut OsRng);
    HASHER
        .hash_password(b"luxor-timing-equalizer", &salt)
        .expect("hashing a fixed password with the pinned parameters cannot fail")
        .to_string()
});

/// The outcome of checking a submitted password against a stored hash.
pub struct Verification {
    pub matched: bool,
    /// A replacement hash, present only when the password matched and the
    /// stored hash was produced with weaker parameters than the pinned ones.
    /// Persisting it upgrades the account without involving its owner;
    /// dropping it costs nothing but leaves the account on the old cost.
    pub upgraded_hash: Option<String>,
}

pub async fn hash_password(password: SecretString) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || hash_with_pinned_parameters(&password))
        .await
        .map_err(|_| AppError::Authentication)?
}

pub async fn verify_password(
    password: SecretString,
    encoded_hash: String,
) -> Result<Verification, AppError> {
    tokio::task::spawn_blocking(move || {
        let hash = PasswordHash::new(&encoded_hash).map_err(|_| AppError::Authentication)?;
        // The verifier takes algorithm, version, and cost from the stored PHC
        // string rather than from `HASHER`, so hashes written under earlier
        // parameters keep verifying after the pinned values move.
        if HASHER
            .verify_password(password.expose_secret().as_bytes(), &hash)
            .is_err()
        {
            return Ok(Verification {
                matched: false,
                upgraded_hash: None,
            });
        }
        // Only a correct password can reach this point, which is what makes
        // the rehash safe: the plaintext needed to produce it is in hand, and
        // the extra argon2 pass lands on a request that already paid for one.
        let upgraded_hash = is_below_pinned_cost(&hash)
            .then(|| hash_with_pinned_parameters(&password).ok())
            .flatten();
        Ok(Verification {
            matched: true,
            upgraded_hash,
        })
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
pub async fn equalize_login_timing(password: SecretString) -> Result<(), AppError> {
    tokio::task::spawn_blocking(move || {
        let hash = PasswordHash::new(&TIMING_EQUALIZER_HASH)
            .expect("the timing-equalizer hash is a valid PHC string");
        let _ = HASHER.verify_password(password.expose_secret().as_bytes(), &hash);
    })
    .await
    .map_err(|_| AppError::Authentication)
}

fn hash_with_pinned_parameters(password: &SecretString) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    HASHER
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AppError::Authentication)
    // The PHC string returned here is not secret: it carries the salt and
    // cost parameters in the clear and is safe to store and log.
}

/// Whether a stored hash is weaker than what this module now produces. Each
/// cost is compared with `>=` so a hash written under *stronger* parameters
/// (a deployment mid-rollout, or one that has since been lowered) is left
/// alone instead of being downgraded.
fn is_below_pinned_cost(hash: &PasswordHash<'_>) -> bool {
    // Argon2i and Argon2d are not comparable to Argon2id by cost, so anything
    // other than the pinned variant counts as stale outright.
    if Algorithm::try_from(hash.algorithm) != Ok(ALGORITHM) {
        return true;
    }
    if !hash
        .version
        .is_some_and(|version| version >= VERSION as u32)
    {
        return true;
    }
    let Ok(params) = Params::try_from(hash) else {
        return true;
    };
    params.m_cost() < MEMORY_KIB || params.t_cost() < ITERATIONS || params.p_cost() < PARALLELISM
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    #[tokio::test]
    async fn hashes_and_verifies_passwords() {
        let hash = hash_password(secret("correct horse battery staple"))
            .await
            .unwrap();
        assert!(
            verify_password(secret("correct horse battery staple"), hash.clone())
                .await
                .unwrap()
                .matched
        );
        assert!(
            !verify_password(secret("wrong"), hash)
                .await
                .unwrap()
                .matched
        );
    }

    #[tokio::test]
    async fn hashes_carry_the_pinned_parameters() {
        let encoded = hash_password(secret("correct horse battery staple"))
            .await
            .unwrap();
        let hash = PasswordHash::new(&encoded).unwrap();
        let params = Params::try_from(&hash).unwrap();
        assert_eq!(hash.algorithm.as_str(), "argon2id");
        assert_eq!(hash.version, Some(VERSION as u32));
        assert_eq!(params.m_cost(), MEMORY_KIB);
        assert_eq!(params.t_cost(), ITERATIONS);
        assert_eq!(params.p_cost(), PARALLELISM);
        assert!(!is_below_pinned_cost(&hash));
    }

    // The point of pinning: a hash written under weaker parameters still
    // verifies (its own cost is read from the PHC string) and is reported as
    // due for an upgrade, while one written under stronger parameters is not.
    #[tokio::test]
    async fn weaker_hashes_verify_and_are_upgraded_in_place() {
        let weaker = Argon2::new(
            ALGORITHM,
            VERSION,
            Params::new(MEMORY_KIB / 2, 1, PARALLELISM, None).unwrap(),
        );
        let salt = SaltString::generate(&mut OsRng);
        let legacy = weaker
            .hash_password(b"correct horse battery staple", &salt)
            .unwrap()
            .to_string();

        let verification = verify_password(secret("correct horse battery staple"), legacy.clone())
            .await
            .unwrap();
        assert!(verification.matched);

        let upgraded = verification
            .upgraded_hash
            .expect("a weaker stored hash must be upgraded");
        assert_ne!(upgraded, legacy);
        let params = Params::try_from(&PasswordHash::new(&upgraded).unwrap()).unwrap();
        assert_eq!(params.m_cost(), MEMORY_KIB);
        assert_eq!(params.t_cost(), ITERATIONS);

        // The upgraded hash still accepts the same password, and a wrong
        // password against the legacy hash is not handed an upgrade.
        assert!(
            verify_password(secret("correct horse battery staple"), upgraded)
                .await
                .unwrap()
                .matched
        );
        let rejected = verify_password(secret("wrong"), legacy).await.unwrap();
        assert!(!rejected.matched);
        assert!(rejected.upgraded_hash.is_none());
    }

    #[tokio::test]
    async fn hashes_at_the_pinned_cost_are_left_alone() {
        let hash = hash_password(secret("correct horse battery staple"))
            .await
            .unwrap();
        let verification = verify_password(secret("correct horse battery staple"), hash)
            .await
            .unwrap();
        assert!(verification.matched);
        assert!(verification.upgraded_hash.is_none());
    }

    #[test]
    fn stronger_hashes_are_never_downgraded() {
        let stronger = Argon2::new(
            ALGORITHM,
            VERSION,
            Params::new(MEMORY_KIB * 2, ITERATIONS + 1, PARALLELISM, None).unwrap(),
        );
        let salt = SaltString::generate(&mut OsRng);
        let encoded = stronger
            .hash_password(b"correct horse battery staple", &salt)
            .unwrap()
            .to_string();
        assert!(!is_below_pinned_cost(&PasswordHash::new(&encoded).unwrap()));
    }

    // Timing itself is not asserted (that would be flaky); the equalizer's
    // cost equivalence comes from sharing the pinned argon2 parameters.
    #[tokio::test]
    async fn timing_equalizer_never_authenticates() {
        equalize_login_timing(secret("any password at all"))
            .await
            .unwrap();
        equalize_login_timing(secret("luxor-timing-equalizer"))
            .await
            .unwrap();
    }
}
