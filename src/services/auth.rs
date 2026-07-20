use crate::{
    auth::{
        equalize_login_timing, hash_password, issue_refresh_token, verify_password, RefreshGrant,
        RefreshPolicy,
    },
    db,
    error::AppError,
    models::{Role, UserRecord},
};
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use zxcvbn::{feedback::Feedback, zxcvbn, Score};

const PASSWORD_MIN_LENGTH: usize = 12;
const PASSWORD_MAX_LENGTH: usize = 1024;

/// zxcvbn's guessability score, 0 to 4. Three means "safely unguessable:
/// moderate protection from an offline slow-hash scenario", the weakest score
/// that still resists a targeted offline attack on an argon2 hash. A length
/// floor alone accepts `passwordpassword`; this rejects it.
const PASSWORD_MIN_SCORE: Score = Score::Three;

/// zxcvbn's matchers are superlinear in the input length, so a caller-supplied
/// 1 KiB password could otherwise occupy a blocking worker far longer than the
/// argon2 hash that follows it. Only this many bytes are scored. A password
/// whose first 128 bytes are weak is rejected even if later bytes are strong;
/// that false rejection is rare, visible to the person choosing the password,
/// and cheaper than leaving the pathological input unbounded.
const STRENGTH_SAMPLE_BYTES: usize = 128;

pub async fn register(
    pool: &PgPool,
    email: &str,
    password: SecretString,
    role: Role,
    refresh_policy: RefreshPolicy,
) -> Result<(UserRecord, RefreshGrant), AppError> {
    let email = normalize_email(email);
    validate_email(&email)?;
    validate_password_length(&password)?;
    validate_password_strength(&email, &password).await?;
    let password_hash = hash_password(password).await?;
    let user = db::create_user(pool, &email, &password_hash, role).await?;
    let grant = issue_refresh_token(pool, user.id, refresh_policy).await?;
    Ok((user, grant))
}

pub async fn login(
    pool: &PgPool,
    email: &str,
    password: SecretString,
    refresh_policy: RefreshPolicy,
) -> Result<(UserRecord, RefreshGrant), AppError> {
    // Registration bounds password length, so nothing longer can match a
    // stored credential; rejecting outsized input up front keeps login from
    // feeding attacker-controlled megabytes into argon2. Strength is not
    // re-checked here: an account that predates a stricter policy must still
    // be able to log in, and the check would cost time on every attempt.
    if password.expose_secret().len() > PASSWORD_MAX_LENGTH {
        return Err(AppError::Unauthorized);
    }
    let Some(user) = db::user_by_email(pool, &normalize_email(email)).await? else {
        // An unknown email still burns one argon2 verification so that
        // response timing does not reveal which emails are registered.
        equalize_login_timing(password).await?;
        return Err(AppError::Unauthorized);
    };
    let verification = verify_password(password, user.password_hash.clone()).await?;
    if !verification.matched {
        return Err(AppError::Unauthorized);
    }
    if let Some(upgraded_hash) = verification.upgraded_hash {
        // The account was hashed under weaker parameters than the current
        // pinned cost. Rewriting it here is best-effort: the credential was
        // already proven correct, so a failed upgrade must not fail the login.
        if let Err(error) = db::update_password_hash(pool, user.id, &upgraded_hash).await {
            tracing::warn!(
                user_id = %user.id,
                error = %error,
                "could not upgrade a stored password hash to the current argon2 cost"
            );
        }
    }
    let grant = issue_refresh_token(pool, user.id, refresh_policy).await?;
    Ok((user, grant))
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn validate_email(email: &str) -> Result<(), AppError> {
    let looks_like_email = email.len() <= 320
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    if looks_like_email {
        Ok(())
    } else {
        Err(AppError::BadRequest("a valid email is required".into()))
    }
}

fn validate_password_length(password: &SecretString) -> Result<(), AppError> {
    if (PASSWORD_MIN_LENGTH..=PASSWORD_MAX_LENGTH).contains(&password.expose_secret().len()) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "password must contain between {PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH} characters"
        )))
    }
}

/// Rejects passwords a guessing attack would reach quickly. The account's own
/// email is supplied as context, which is what catches the case a generic
/// checker misses: `mike@northwind.com` choosing `Northwind2026!` scores top
/// marks on shape alone, because "northwind" appears in no dictionary — yet it
/// is the first thing an attacker targeting that account would try. With the
/// email as context the same password drops two scores and is refused.
async fn validate_password_strength(email: &str, password: &SecretString) -> Result<(), AppError> {
    // Both the sample and the analysis are moved onto a blocking worker: the
    // sample stays a `SecretString` so it is zeroized there rather than left
    // in a plain `String` for the allocator to recycle.
    let sample = SecretString::from(strength_sample(password.expose_secret()));
    let user_inputs = strength_user_inputs(email);
    tokio::task::spawn_blocking(move || {
        let user_inputs = user_inputs.iter().map(String::as_str).collect::<Vec<_>>();
        let estimate = zxcvbn(sample.expose_secret(), &user_inputs);
        if estimate.score() >= PASSWORD_MIN_SCORE {
            return Ok(());
        }
        // zxcvbn's warnings are a fixed set of English phrases describing the
        // *shape* of the guess ("this is a common password"), never the
        // password itself, so they are safe to return to the client.
        let reason = estimate
            .feedback()
            .and_then(Feedback::warning)
            .map(|warning| format!(": {warning}"))
            .unwrap_or_default();
        Err(AppError::BadRequest(format!(
            "password is too easily guessed{reason}"
        )))
    })
    .await
    .map_err(|_| AppError::Authentication)?
}

/// Truncates to [`STRENGTH_SAMPLE_BYTES`] on a character boundary, so a
/// multi-byte character straddling the cap cannot panic the slice.
fn strength_sample(password: &str) -> String {
    let end = (0..=STRENGTH_SAMPLE_BYTES.min(password.len()))
        .rev()
        .find(|index| password.is_char_boundary(*index))
        .unwrap_or(0);
    password[..end].to_owned()
}

/// The email, plus the pieces of it someone is most likely to build a password
/// from: the local part and each label of the domain.
fn strength_user_inputs(email: &str) -> Vec<String> {
    let mut inputs = vec![email.to_owned()];
    if let Some((local, domain)) = email.split_once('@') {
        inputs.push(local.to_owned());
        inputs.extend(
            domain
                .split('.')
                .filter(|label| label.len() > 2)
                .map(ToOwned::to_owned),
        );
    }
    inputs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    #[test]
    fn validates_email_shape() {
        assert!(validate_email("person@example.com").is_ok());
        assert!(validate_email("not-email").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("person@localhost").is_err());
    }

    #[test]
    fn validates_password_length() {
        assert!(validate_password_length(&secret("long-enough-password")).is_ok());
        assert!(validate_password_length(&secret("short")).is_err());
        assert!(validate_password_length(&secret(&"x".repeat(1025))).is_err());
    }

    #[tokio::test]
    async fn rejects_guessable_passwords_that_clear_the_length_floor() {
        // Every one of these is at least twelve characters, so length alone
        // would have accepted it.
        for weak in [
            "passwordpassword",
            "qwertyuiopasdf",
            "aaaaaaaaaaaaaaa",
            "letmein123456",
            "abcdefghijklmnop",
        ] {
            assert!(
                validate_password_strength("person@example.com", &secret(weak))
                    .await
                    .is_err(),
                "{weak:?} should be rejected as guessable"
            );
        }
    }

    // A differential test: the same password is refused for the account whose
    // email it is built from and accepted for an unrelated one. That gap is
    // the whole contribution of passing user inputs to zxcvbn — without them
    // "Northwind2026!" scores the maximum, since "northwind" is in no
    // dictionary and the shape looks strong.
    #[tokio::test]
    async fn rejects_passwords_built_from_the_account_email() {
        assert!(
            validate_password_strength("mike@northwind.com", &secret("Northwind2026!"))
                .await
                .is_err()
        );
        assert!(
            validate_password_strength("mike@example.com", &secret("Northwind2026!"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn accepts_strong_passwords() {
        for strong in [
            "correct horse battery staple",
            "7Xk!mQz2*Lp9wVn4",
            "unravel-cobalt-thimble-9821",
        ] {
            assert!(
                validate_password_strength("person@example.com", &secret(strong))
                    .await
                    .is_ok(),
                "{strong:?} should be accepted"
            );
        }
    }

    #[test]
    fn strength_sample_truncates_on_a_character_boundary() {
        let multibyte = "é".repeat(200);
        let sample = strength_sample(&multibyte);
        assert!(sample.len() <= STRENGTH_SAMPLE_BYTES);
        // Truncating mid-character would have produced invalid UTF-8 and
        // panicked before returning; reaching here proves the boundary walk.
        assert!(multibyte.starts_with(&sample));

        let short = "correct horse";
        assert_eq!(strength_sample(short), short);
    }

    #[test]
    fn strength_user_inputs_cover_the_email_pieces() {
        let inputs = strength_user_inputs("giulio@example.co.uk");
        assert!(inputs.contains(&"giulio@example.co.uk".to_owned()));
        assert!(inputs.contains(&"giulio".to_owned()));
        assert!(inputs.contains(&"example".to_owned()));
        // Two-letter labels are noise as password material.
        assert!(!inputs.contains(&"co".to_owned()));
        assert!(!inputs.contains(&"uk".to_owned()));
    }
}
