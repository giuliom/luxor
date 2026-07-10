use secrecy::SecretString;
use std::{
    collections::HashMap,
    env, fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use thiserror::Error;
use url::Url;

const DEV_DATABASE_URL: &str = "postgres://luxor:luxor@localhost:5432/luxor";
const DEV_REDIS_URL: &str = "redis://127.0.0.1:6379/";
const DEV_JWT_SECRET: &str = "development-only-secret-change-me";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Environment {
    Development,
    Test,
    Production,
}

impl Environment {
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

impl FromStr for Environment {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "production" | "prod" => Ok(Self::Production),
            _ => Err(ConfigError::Invalid("APP_ENV", value.to_owned())),
        }
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

#[derive(Clone, Debug)]
pub struct Config {
    pub environment: Environment,
    pub app_host: String,
    pub app_port: u16,
    pub database_url: SecretString,
    pub redis_url: SecretString,
    pub jwt_secret: SecretString,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub refresh_cookie_secure: bool,
    pub cors_origins: Vec<String>,
    pub body_limit_bytes: usize,
    pub auto_migrate: bool,
    pub otlp_endpoint: Option<String>,
    pub sentry_dsn: Option<SecretString>,
    pub oauth: Option<OAuthConfig>,
    pub cache_namespace: String,
    pub queue_key: String,
    bind_address: SocketAddr,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_map(env::vars().collect())
    }

    pub fn from_map(values: HashMap<String, String>) -> Result<Self, ConfigError> {
        let environment = get(&values, "APP_ENV")
            .unwrap_or("development")
            .parse::<Environment>()?;
        let production = environment.is_production();

        // Deployed containers sit behind a platform proxy and must accept
        // traffic on all interfaces; local development stays loopback-only.
        let default_host = if production { "0.0.0.0" } else { "127.0.0.1" };
        let app_host = get(&values, "APP_HOST").unwrap_or(default_host).to_owned();
        let app_ip = app_host
            .parse::<IpAddr>()
            .map_err(|error| ConfigError::Invalid("APP_HOST", error.to_string()))?;
        // Platforms such as Railway and Heroku inject PORT and route traffic
        // to it, so it must win over the locally documented APP_PORT.
        let app_port = parse(&values, "PORT", parse(&values, "APP_PORT", 8080_u16)?)?;
        if app_port == 0 {
            return Err(ConfigError::Validation(
                "APP_PORT must be greater than zero".into(),
            ));
        }

        let database_url = required_or_dev(&values, "DATABASE_URL", production, DEV_DATABASE_URL)?;
        parse_url("DATABASE_URL", &database_url, &["postgres", "postgresql"])?;

        let redis_url = required_or_dev(&values, "REDIS_URL", production, DEV_REDIS_URL)?;
        parse_url("REDIS_URL", &redis_url, &["redis", "rediss"])?;

        let jwt_secret = required_or_dev(&values, "JWT_SECRET", production, DEV_JWT_SECRET)?;
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

        let access_token_ttl_seconds = parse(&values, "ACCESS_TOKEN_TTL_SECONDS", 900_i64)?;
        let refresh_token_ttl_seconds = parse(&values, "REFRESH_TOKEN_TTL_SECONDS", 2_592_000_i64)?;
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

        let oauth = parse_oauth(&values)?;
        let cors_origins = get(&values, "CORS_ORIGINS")
            .unwrap_or("http://localhost:8080")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if cors_origins.is_empty() {
            return Err(ConfigError::Validation(
                "CORS_ORIGINS must contain at least one origin".into(),
            ));
        }
        for origin in &cors_origins {
            validate_origin(origin)?;
        }

        let body_limit_bytes = parse(&values, "BODY_LIMIT_BYTES", 1_048_576_usize)?;
        if body_limit_bytes == 0 {
            return Err(ConfigError::Validation(
                "BODY_LIMIT_BYTES must be greater than zero".into(),
            ));
        }
        let refresh_cookie_secure = parse(&values, "REFRESH_COOKIE_SECURE", production)?;
        if production && !refresh_cookie_secure {
            return Err(ConfigError::Validation(
                "REFRESH_COOKIE_SECURE cannot be disabled in production".into(),
            ));
        }
        let auto_migrate = parse(&values, "AUTO_MIGRATE", !production)?;
        if production && auto_migrate {
            return Err(ConfigError::Validation(
                "AUTO_MIGRATE cannot be enabled in production".into(),
            ));
        }

        let otlp_endpoint = optional(&values, "OTEL_EXPORTER_OTLP_ENDPOINT");
        if let Some(endpoint) = &otlp_endpoint {
            parse_url("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint, &["http", "https"])?;
        }
        let sentry_dsn = optional(&values, "SENTRY_DSN");
        if let Some(dsn) = &sentry_dsn {
            dsn.parse::<sentry::types::Dsn>()
                .map_err(|error| ConfigError::Invalid("SENTRY_DSN", error.to_string()))?;
        }

        let cache_namespace = get(&values, "CACHE_NAMESPACE")
            .unwrap_or("luxor:cache")
            .to_owned();
        let queue_key = get(&values, "QUEUE_KEY")
            .unwrap_or("luxor:queue:jobs")
            .to_owned();

        Ok(Self {
            environment,
            app_host,
            app_port,
            database_url: SecretString::from(database_url),
            redis_url: SecretString::from(redis_url),
            jwt_secret: SecretString::from(jwt_secret),
            access_token_ttl_seconds,
            refresh_token_ttl_seconds,
            refresh_cookie_secure,
            cors_origins,
            body_limit_bytes,
            auto_migrate,
            otlp_endpoint,
            sentry_dsn: sentry_dsn.map(SecretString::from),
            oauth,
            cache_namespace,
            queue_key,
            bind_address: SocketAddr::new(app_ip, app_port),
        })
    }

    pub fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
    #[error("configuration validation failed: {0}")]
    Validation(String),
}

fn get<'a>(values: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    values
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
}

fn optional(values: &HashMap<String, String>, key: &str) -> Option<String> {
    get(values, key).map(ToOwned::to_owned)
}

fn required_or_dev(
    values: &HashMap<String, String>,
    key: &'static str,
    production: bool,
    development_default: &str,
) -> Result<String, ConfigError> {
    get(values, key)
        .map(ToOwned::to_owned)
        .or_else(|| (!production).then(|| development_default.to_owned()))
        .ok_or(ConfigError::Missing(key))
}

fn parse<T>(
    values: &HashMap<String, String>,
    key: &'static str,
    default: T,
) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match get(values, key) {
        Some(value) => value
            .parse::<T>()
            .map_err(|error| ConfigError::Invalid(key, error.to_string())),
        None => Ok(default),
    }
}

fn parse_url(key: &'static str, value: &str, schemes: &[&str]) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|error| ConfigError::Invalid(key, error.to_string()))?;
    if schemes.contains(&url.scheme()) {
        Ok(url)
    } else {
        Err(ConfigError::Invalid(
            key,
            format!("expected one of these URL schemes: {}", schemes.join(", ")),
        ))
    }
}

fn validate_origin(origin: &str) -> Result<(), ConfigError> {
    let url = parse_url("CORS_ORIGINS", origin, &["http", "https"])?;
    let is_origin_only = url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    if is_origin_only {
        Ok(())
    } else {
        Err(ConfigError::Invalid(
            "CORS_ORIGINS",
            format!("{origin} is not an HTTP(S) origin"),
        ))
    }
}

fn parse_oauth(values: &HashMap<String, String>) -> Result<Option<OAuthConfig>, ConfigError> {
    const KEYS: [&str; 5] = [
        "OAUTH_AUTHORIZATION_URL",
        "OAUTH_TOKEN_URL",
        "OAUTH_CLIENT_ID",
        "OAUTH_CLIENT_SECRET",
        "OAUTH_REDIRECT_URL",
    ];
    let present = KEYS.iter().filter(|key| get(values, key).is_some()).count();
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
            get(values, KEYS[0]).unwrap(),
            &["http", "https"],
        )?,
        token_url: parse_url(
            "OAUTH_TOKEN_URL",
            get(values, KEYS[1]).unwrap(),
            &["http", "https"],
        )?,
        client_id: get(values, KEYS[2]).unwrap().to_owned(),
        client_secret: SecretString::from(get(values, KEYS[3]).unwrap().to_owned()),
        redirect_url: parse_url(
            "OAUTH_REDIRECT_URL",
            get(values, KEYS[4]).unwrap(),
            &["http", "https"],
        )?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_defaults_are_valid() {
        let config = Config::from_map(HashMap::new()).unwrap();
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.app_port, 8080);
        assert_eq!(config.cors_origins, vec!["http://localhost:8080"]);
        assert!(config.auto_migrate);
        assert!(!config.refresh_cookie_secure);
    }

    #[test]
    fn injected_platform_port_wins_over_app_port() {
        let values = HashMap::from([
            ("APP_PORT".into(), "3000".into()),
            ("PORT".into(), "8080".into()),
        ]);
        let config = Config::from_map(values).unwrap();
        assert_eq!(config.app_port, 8080);
        assert_eq!(config.bind_address().port(), 8080);
    }

    #[test]
    fn production_binds_all_interfaces_by_default() {
        let values = HashMap::from([
            ("APP_ENV".into(), "production".into()),
            ("DATABASE_URL".into(), DEV_DATABASE_URL.into()),
            ("REDIS_URL".into(), DEV_REDIS_URL.into()),
            (
                "JWT_SECRET".into(),
                "production-test-secret-at-least-32-characters".into(),
            ),
        ]);
        let config = Config::from_map(values).unwrap();
        assert_eq!(config.app_host, "0.0.0.0");

        let development = Config::from_map(HashMap::new()).unwrap();
        assert_eq!(development.app_host, "127.0.0.1");
    }

    #[test]
    fn production_requires_secrets() {
        let values = HashMap::from([("APP_ENV".into(), "production".into())]);
        assert_eq!(
            Config::from_map(values).unwrap_err(),
            ConfigError::Missing("DATABASE_URL")
        );
    }

    #[test]
    fn partial_oauth_configuration_is_rejected() {
        let values = HashMap::from([(
            "OAUTH_CLIENT_ID".into(),
            "configured-without-other-fields".into(),
        )]);
        assert!(matches!(
            Config::from_map(values),
            Err(ConfigError::Validation(message)) if message.contains("all-or-nothing")
        ));
    }

    #[test]
    fn invalid_listener_and_cors_values_are_rejected() {
        let bad_host = HashMap::from([("APP_HOST".into(), "localhost".into())]);
        assert!(matches!(
            Config::from_map(bad_host),
            Err(ConfigError::Invalid("APP_HOST", _))
        ));

        let bad_origin =
            HashMap::from([("CORS_ORIGINS".into(), "https://example.com/a-path".into())]);
        assert!(matches!(
            Config::from_map(bad_origin),
            Err(ConfigError::Invalid("CORS_ORIGINS", _))
        ));
    }

    #[test]
    fn production_security_controls_cannot_be_disabled() {
        let base = HashMap::from([
            ("APP_ENV".into(), "production".into()),
            ("DATABASE_URL".into(), DEV_DATABASE_URL.into()),
            ("REDIS_URL".into(), DEV_REDIS_URL.into()),
            (
                "JWT_SECRET".into(),
                "production-test-secret-at-least-32-characters".into(),
            ),
        ]);

        let mut insecure_cookie = base.clone();
        insecure_cookie.insert("REFRESH_COOKIE_SECURE".into(), "false".into());
        assert!(matches!(
            Config::from_map(insecure_cookie),
            Err(ConfigError::Validation(message)) if message.contains("REFRESH_COOKIE_SECURE")
        ));

        let mut automatic_migrations = base;
        automatic_migrations.insert("AUTO_MIGRATE".into(), "true".into());
        assert!(matches!(
            Config::from_map(automatic_migrations),
            Err(ConfigError::Validation(message)) if message.contains("AUTO_MIGRATE")
        ));
    }
}
