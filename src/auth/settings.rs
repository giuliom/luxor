//! Credentials and their lifetimes.

use crate::config::{parse_url, ConfigError, Env};
use secrecy::SecretString;
use std::fmt;
use url::Url;

const DEV_JWT_SECRET: &str = "development-only-secret-change-me";

#[derive(Clone, Debug)]
pub struct AuthSettings {
    pub jwt_secret: SecretString,
    /// The `iss` claim every access token carries and verification requires:
    /// the application's name.
    pub jwt_issuer: String,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    /// Absolute cap on a refresh-token rotation family: rotations renew the
    /// session, but never past this many seconds after the first login.
    pub refresh_family_ttl_seconds: i64,
    pub refresh_cookie_secure: bool,
    /// `<APP_NAME>_refresh`, so two applications on one host keep separate
    /// sessions.
    pub refresh_cookie_name: String,
    pub oauth: Option<OAuthConfig>,
}

impl AuthSettings {
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let production = env.is_production();
        let jwt_secret = env.required_or_dev("JWT_SECRET", DEV_JWT_SECRET)?;
        if jwt_secret.len() < 32 {
            return Err(ConfigError::Validation(
                "JWT_SECRET must contain at least 32 characters".into(),
            ));
        }
        if production && jwt_secret == DEV_JWT_SECRET {
            return Err(ConfigError::Validation(
                "the development JWT_SECRET cannot be used in production".into(),
            ));
        }

        let access_token_ttl_seconds = env.parse("ACCESS_TOKEN_TTL_SECONDS", 900_i64)?;
        let refresh_token_ttl_seconds = env.parse("REFRESH_TOKEN_TTL_SECONDS", 2_592_000_i64)?;
        if access_token_ttl_seconds <= 0 || refresh_token_ttl_seconds <= 0 {
            return Err(ConfigError::Validation(
                "token lifetimes must be greater than zero".into(),
            ));
        }
        if refresh_token_ttl_seconds <= access_token_ttl_seconds {
            return Err(ConfigError::Validation(
                "refresh token lifetime must exceed access token lifetime".into(),
            ));
        }
        let refresh_family_ttl_seconds = env.parse("REFRESH_FAMILY_TTL_SECONDS", 7_776_000_i64)?;
        if refresh_family_ttl_seconds < refresh_token_ttl_seconds {
            return Err(ConfigError::Validation(
                "refresh family lifetime must be at least the refresh token lifetime".into(),
            ));
        }

        let oauth = parse_oauth(env)?;
        let refresh_cookie_secure = env.parse("REFRESH_COOKIE_SECURE", production)?;
        if production && !refresh_cookie_secure {
            return Err(ConfigError::Validation(
                "REFRESH_COOKIE_SECURE cannot be disabled in production".into(),
            ));
        }

        Ok(Self {
            jwt_secret: SecretString::from(jwt_secret),
            jwt_issuer: env.app_name().to_owned(),
            access_token_ttl_seconds,
            refresh_token_ttl_seconds,
            refresh_family_ttl_seconds,
            refresh_cookie_secure,
            refresh_cookie_name: format!("{}_refresh", env.app_name()),
            oauth,
        })
    }
}

#[derive(Clone)]
pub struct OAuthConfig {
    pub authorization_url: Url,
    pub token_url: Url,
    pub client_id: String,
    pub client_secret: SecretString,
    pub redirect_url: Url,
}

impl fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthConfig")
            .field("authorization_url", &self.authorization_url)
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
}

fn parse_oauth(env: &Env) -> Result<Option<OAuthConfig>, ConfigError> {
    const KEYS: [&str; 5] = [
        "OAUTH_AUTHORIZATION_URL",
        "OAUTH_TOKEN_URL",
        "OAUTH_CLIENT_ID",
        "OAUTH_CLIENT_SECRET",
        "OAUTH_REDIRECT_URL",
    ];
    let present = KEYS.iter().filter(|key| env.get(key).is_some()).count();
    if present == 0 {
        return Ok(None);
    }
    if present != KEYS.len() {
        return Err(ConfigError::Validation(format!(
            "OAuth configuration is all-or-nothing; set {}",
            KEYS.join(", ")
        )));
    }

    Ok(Some(OAuthConfig {
        authorization_url: parse_url(
            "OAUTH_AUTHORIZATION_URL",
            env.get(KEYS[0]).unwrap(),
            &["http", "https"],
        )?,
        token_url: parse_url(
            "OAUTH_TOKEN_URL",
            env.get(KEYS[1]).unwrap(),
            &["http", "https"],
        )?,
        client_id: env.get(KEYS[2]).unwrap().to_owned(),
        client_secret: SecretString::from(env.get(KEYS[3]).unwrap().to_owned()),
        redirect_url: parse_url(
            "OAUTH_REDIRECT_URL",
            env.get(KEYS[4]).unwrap(),
            &["http", "https"],
        )?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::values;
    use secrecy::ExposeSecret;

    fn settings(pairs: &[(&str, &str)]) -> Result<AuthSettings, ConfigError> {
        AuthSettings::from_env(&Env::new(values(pairs))?)
    }

    const PRODUCTION_SECRET: (&str, &str) = (
        "JWT_SECRET",
        "production-test-secret-at-least-32-characters",
    );

    #[test]
    fn development_defaults_are_valid() {
        let auth = settings(&[]).unwrap();
        assert_eq!(auth.jwt_secret.expose_secret(), DEV_JWT_SECRET);
        assert_eq!(auth.access_token_ttl_seconds, 900);
        assert_eq!(auth.refresh_family_ttl_seconds, 7_776_000);
        assert!(!auth.refresh_cookie_secure);
        assert!(auth.oauth.is_none());
    }

    #[test]
    fn the_issuer_and_cookie_are_named_after_the_application() {
        let auth = settings(&[]).unwrap();
        assert_eq!(auth.jwt_issuer, env!("CARGO_PKG_NAME"));
        assert_eq!(
            auth.refresh_cookie_name,
            format!("{}_refresh", env!("CARGO_PKG_NAME"))
        );
    }

    #[test]
    fn production_requires_a_unique_long_secret() {
        assert_eq!(
            settings(&[("APP_ENV", "production")]).unwrap_err(),
            ConfigError::Missing("JWT_SECRET")
        );
        assert!(matches!(
            settings(&[("APP_ENV", "production"), ("JWT_SECRET", DEV_JWT_SECRET)]),
            Err(ConfigError::Validation(message)) if message.contains("development JWT_SECRET")
        ));
        assert!(matches!(
            settings(&[("JWT_SECRET", "too-short")]),
            Err(ConfigError::Validation(message)) if message.contains("32 characters")
        ));

        let production = settings(&[("APP_ENV", "production"), PRODUCTION_SECRET]).unwrap();
        assert!(production.refresh_cookie_secure);
    }

    #[test]
    fn refresh_family_lifetime_covers_the_token_lifetime() {
        assert!(matches!(
            settings(&[("REFRESH_FAMILY_TTL_SECONDS", "3600")]),
            Err(ConfigError::Validation(message)) if message.contains("family")
        ));
        let equal = settings(&[
            ("REFRESH_TOKEN_TTL_SECONDS", "86400"),
            ("REFRESH_FAMILY_TTL_SECONDS", "86400"),
        ])
        .unwrap();
        assert_eq!(equal.refresh_family_ttl_seconds, 86_400);
    }

    #[test]
    fn partial_oauth_configuration_is_rejected() {
        assert!(matches!(
            settings(&[("OAUTH_CLIENT_ID", "configured-without-other-fields")]),
            Err(ConfigError::Validation(message)) if message.contains("all-or-nothing")
        ));
    }

    #[test]
    fn secure_refresh_cookies_cannot_be_disabled_in_production() {
        assert!(matches!(
            settings(&[
                ("APP_ENV", "production"),
                PRODUCTION_SECRET,
                ("REFRESH_COOKIE_SECURE", "false"),
            ]),
            Err(ConfigError::Validation(message)) if message.contains("REFRESH_COOKIE_SECURE")
        ));
    }
}
