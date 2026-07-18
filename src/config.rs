use secrecy::SecretString;
use std::{
    collections::HashMap,
    env, fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use thiserror::Error;
use url::Url;

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

/// Where the client address used for per-client policies (rate limiting)
/// comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientIpSource {
    /// The peer address of the TCP connection. Correct when clients connect
    /// directly, as in local development.
    Socket,
    /// The rightmost `X-Forwarded-For` entry, appended by the platform proxy
    /// in front of the app. Correct on Railway, Heroku, and similar
    /// platforms; unsafe without a trusted proxy, because clients can send
    /// the header themselves.
    XForwardedFor,
}

impl FromStr for ClientIpSource {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "socket" => Ok(Self::Socket),
            "x-forwarded-for" => Ok(Self::XForwardedFor),
            _ => Err(ConfigError::Invalid("CLIENT_IP_SOURCE", value.to_owned())),
        }
    }
}

/// A fixed-window request budget: at most `max_requests` per client per
/// `window_seconds`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitQuota {
    pub max_requests: u32,
    pub window_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct RateLimitSettings {
    /// Cannot be disabled in production.
    pub enabled: bool,
    pub client_ip_source: ClientIpSource,
    /// Prefix for the Redis keys of the distributed limiter.
    pub namespace: String,
    /// Budget for the credential endpoints under `/api/auth`, the
    /// brute-force surface. Applies on top of `api`.
    pub auth: RateLimitQuota,
    /// Budget for everything under `/api`.
    pub api: RateLimitQuota,
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
    /// `None` selects the embedded development PostgreSQL server; production
    /// configuration always carries a URL.
    pub database_url: Option<SecretString>,
    /// `None` selects the in-memory cache and queue; production configuration
    /// always carries a URL.
    pub redis_url: Option<SecretString>,
    pub jwt_secret: SecretString,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    /// Absolute cap on a refresh-token rotation family: rotations renew the
    /// session, but never past this many seconds after the first login.
    pub refresh_family_ttl_seconds: i64,
    pub refresh_cookie_secure: bool,
    pub cors_origins: Vec<String>,
    pub body_limit_bytes: usize,
    pub request_timeout_seconds: u64,
    pub rate_limit: RateLimitSettings,
    pub auto_migrate: bool,
    pub open_browser: bool,
    pub otlp_endpoint: Option<String>,
    pub otel_service_name: String,
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

        let database_url = infrastructure_url(
            &values,
            "DATABASE_URL",
            production,
            &["postgres", "postgresql"],
        )?;
        let redis_url = infrastructure_url(&values, "REDIS_URL", production, &["redis", "rediss"])?;

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
        let refresh_family_ttl_seconds =
            parse(&values, "REFRESH_FAMILY_TTL_SECONDS", 7_776_000_i64)?;
        if refresh_family_ttl_seconds < refresh_token_ttl_seconds {
            return Err(ConfigError::Validation(
                "refresh family lifetime must be at least the refresh token lifetime".into(),
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
        let request_timeout_seconds = parse(&values, "REQUEST_TIMEOUT_SECONDS", 30_u64)?;
        if request_timeout_seconds == 0 {
            return Err(ConfigError::Validation(
                "REQUEST_TIMEOUT_SECONDS must be greater than zero".into(),
            ));
        }
        let rate_limit = parse_rate_limit(&values, production)?;
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
        let open_browser = parse(&values, "APP_OPEN_BROWSER", false)?;
        if production && open_browser {
            return Err(ConfigError::Validation(
                "APP_OPEN_BROWSER cannot be enabled in production".into(),
            ));
        }

        let otlp_endpoint = optional(&values, "OTEL_EXPORTER_OTLP_ENDPOINT");
        if let Some(endpoint) = &otlp_endpoint {
            parse_url("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint, &["http", "https"])?;
        }
        let otel_service_name = get(&values, "OTEL_SERVICE_NAME")
            .unwrap_or("luxor")
            .to_owned();
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
            database_url,
            redis_url,
            jwt_secret: SecretString::from(jwt_secret),
            access_token_ttl_seconds,
            refresh_token_ttl_seconds,
            refresh_family_ttl_seconds,
            refresh_cookie_secure,
            cors_origins,
            body_limit_bytes,
            request_timeout_seconds,
            rate_limit,
            auto_migrate,
            open_browser,
            otlp_endpoint,
            otel_service_name,
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

/// Production must point at real infrastructure; outside production a missing
/// URL selects the built-in development fallback (the embedded PostgreSQL
/// server, or the in-memory cache and queue).
fn infrastructure_url(
    values: &HashMap<String, String>,
    key: &'static str,
    production: bool,
    schemes: &[&str],
) -> Result<Option<SecretString>, ConfigError> {
    match get(values, key) {
        Some(value) => {
            parse_url(key, value, schemes)?;
            Ok(Some(SecretString::from(value.to_owned())))
        }
        None if production => Err(ConfigError::Missing(key)),
        None => Ok(None),
    }
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

fn parse_rate_limit(
    values: &HashMap<String, String>,
    production: bool,
) -> Result<RateLimitSettings, ConfigError> {
    let enabled = parse(values, "RATE_LIMIT_ENABLED", true)?;
    if production && !enabled {
        return Err(ConfigError::Validation(
            "RATE_LIMIT_ENABLED cannot be disabled in production".into(),
        ));
    }
    // Deployed containers sit behind the platform proxy, so the peer address
    // would be the proxy itself; local development connects directly.
    let default_source = if production {
        ClientIpSource::XForwardedFor
    } else {
        ClientIpSource::Socket
    };
    let client_ip_source = match get(values, "CLIENT_IP_SOURCE") {
        Some(value) => value.parse()?,
        None => default_source,
    };
    let namespace = get(values, "RATE_LIMIT_NAMESPACE")
        .unwrap_or("luxor:ratelimit")
        .to_owned();
    let auth = parse_quota(
        values,
        ("RATE_LIMIT_AUTH_MAX_REQUESTS", 10),
        ("RATE_LIMIT_AUTH_WINDOW_SECONDS", 60),
    )?;
    let api = parse_quota(
        values,
        ("RATE_LIMIT_API_MAX_REQUESTS", 120),
        ("RATE_LIMIT_API_WINDOW_SECONDS", 60),
    )?;
    Ok(RateLimitSettings {
        enabled,
        client_ip_source,
        namespace,
        auth,
        api,
    })
}

fn parse_quota(
    values: &HashMap<String, String>,
    (max_key, default_max): (&'static str, u32),
    (window_key, default_window): (&'static str, u64),
) -> Result<RateLimitQuota, ConfigError> {
    let max_requests = parse(values, max_key, default_max)?;
    if max_requests == 0 {
        return Err(ConfigError::Validation(format!(
            "{max_key} must be greater than zero"
        )));
    }
    let window_seconds = parse(values, window_key, default_window)?;
    if !(1..=86_400).contains(&window_seconds) {
        return Err(ConfigError::Validation(format!(
            "{window_key} must be between 1 and 86400 seconds"
        )));
    }
    Ok(RateLimitQuota {
        max_requests,
        window_seconds,
    })
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

    const TEST_DATABASE_URL: &str = "postgres://luxor:luxor@localhost:5432/luxor";
    const TEST_REDIS_URL: &str = "redis://127.0.0.1:6379/";

    #[test]
    fn development_defaults_are_valid() {
        let config = Config::from_map(HashMap::new()).unwrap();
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.app_port, 8080);
        assert_eq!(config.cors_origins, vec!["http://localhost:8080"]);
        assert!(config.auto_migrate);
        assert!(config.database_url.is_none());
        assert!(config.redis_url.is_none());
        assert!(!config.open_browser);
        assert!(!config.refresh_cookie_secure);
        assert_eq!(config.otel_service_name, "luxor");
        assert_eq!(config.refresh_family_ttl_seconds, 7_776_000);
        assert_eq!(config.request_timeout_seconds, 30);
        assert!(config.rate_limit.enabled);
        assert_eq!(config.rate_limit.client_ip_source, ClientIpSource::Socket);
        assert_eq!(config.rate_limit.namespace, "luxor:ratelimit");
        assert_eq!(
            config.rate_limit.auth,
            RateLimitQuota {
                max_requests: 10,
                window_seconds: 60
            }
        );
        assert_eq!(
            config.rate_limit.api,
            RateLimitQuota {
                max_requests: 120,
                window_seconds: 60
            }
        );
    }

    fn production_base() -> HashMap<String, String> {
        HashMap::from([
            ("APP_ENV".into(), "production".into()),
            ("DATABASE_URL".into(), TEST_DATABASE_URL.into()),
            ("REDIS_URL".into(), TEST_REDIS_URL.into()),
            (
                "JWT_SECRET".into(),
                "production-test-secret-at-least-32-characters".into(),
            ),
        ])
    }

    #[test]
    fn rate_limiting_cannot_be_disabled_in_production() {
        let mut values = production_base();
        values.insert("RATE_LIMIT_ENABLED".into(), "false".into());
        assert!(matches!(
            Config::from_map(values),
            Err(ConfigError::Validation(message)) if message.contains("RATE_LIMIT_ENABLED")
        ));

        let development = Config::from_map(HashMap::from([(
            "RATE_LIMIT_ENABLED".into(),
            "false".into(),
        )]))
        .unwrap();
        assert!(!development.rate_limit.enabled);
    }

    #[test]
    fn client_ip_source_follows_the_deployment_shape() {
        let production = Config::from_map(production_base()).unwrap();
        assert_eq!(
            production.rate_limit.client_ip_source,
            ClientIpSource::XForwardedFor
        );

        let mut direct_production = production_base();
        direct_production.insert("CLIENT_IP_SOURCE".into(), "socket".into());
        assert_eq!(
            Config::from_map(direct_production)
                .unwrap()
                .rate_limit
                .client_ip_source,
            ClientIpSource::Socket
        );

        let invalid = HashMap::from([("CLIENT_IP_SOURCE".into(), "guess".into())]);
        assert!(matches!(
            Config::from_map(invalid),
            Err(ConfigError::Invalid("CLIENT_IP_SOURCE", _))
        ));
    }

    #[test]
    fn rate_limit_quotas_are_validated() {
        let zero_budget = HashMap::from([("RATE_LIMIT_AUTH_MAX_REQUESTS".into(), "0".into())]);
        assert!(matches!(
            Config::from_map(zero_budget),
            Err(ConfigError::Validation(message))
                if message.contains("RATE_LIMIT_AUTH_MAX_REQUESTS")
        ));

        let oversized_window =
            HashMap::from([("RATE_LIMIT_API_WINDOW_SECONDS".into(), "86401".into())]);
        assert!(matches!(
            Config::from_map(oversized_window),
            Err(ConfigError::Validation(message))
                if message.contains("RATE_LIMIT_API_WINDOW_SECONDS")
        ));
    }

    #[test]
    fn refresh_family_lifetime_covers_the_token_lifetime() {
        let too_short = HashMap::from([("REFRESH_FAMILY_TTL_SECONDS".into(), "3600".into())]);
        assert!(matches!(
            Config::from_map(too_short),
            Err(ConfigError::Validation(message)) if message.contains("family")
        ));

        let equal = HashMap::from([
            ("REFRESH_TOKEN_TTL_SECONDS".into(), "86400".into()),
            ("REFRESH_FAMILY_TTL_SECONDS".into(), "86400".into()),
        ]);
        assert_eq!(
            Config::from_map(equal).unwrap().refresh_family_ttl_seconds,
            86_400
        );
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let values = HashMap::from([("REQUEST_TIMEOUT_SECONDS".into(), "0".into())]);
        assert!(matches!(
            Config::from_map(values),
            Err(ConfigError::Validation(message)) if message.contains("REQUEST_TIMEOUT_SECONDS")
        ));
    }

    #[test]
    fn accepts_standard_opentelemetry_service_name() {
        let values = HashMap::from([("OTEL_SERVICE_NAME".into(), "checkout-api".into())]);
        let config = Config::from_map(values).unwrap();
        assert_eq!(config.otel_service_name, "checkout-api");
    }

    #[test]
    fn explicit_infrastructure_urls_are_kept() {
        let values = HashMap::from([
            ("DATABASE_URL".into(), TEST_DATABASE_URL.into()),
            ("REDIS_URL".into(), TEST_REDIS_URL.into()),
        ]);
        let config = Config::from_map(values).unwrap();
        assert!(config.database_url.is_some());
        assert!(config.redis_url.is_some());

        let invalid = HashMap::from([("DATABASE_URL".into(), "mysql://nope".into())]);
        assert!(matches!(
            Config::from_map(invalid),
            Err(ConfigError::Invalid("DATABASE_URL", _))
        ));
    }

    #[test]
    fn browser_launch_is_development_only() {
        let development =
            Config::from_map(HashMap::from([("APP_OPEN_BROWSER".into(), "true".into())])).unwrap();
        assert!(development.open_browser);

        let production = HashMap::from([
            ("APP_ENV".into(), "production".into()),
            ("DATABASE_URL".into(), TEST_DATABASE_URL.into()),
            ("REDIS_URL".into(), TEST_REDIS_URL.into()),
            (
                "JWT_SECRET".into(),
                "production-test-secret-at-least-32-characters".into(),
            ),
            ("APP_OPEN_BROWSER".into(), "true".into()),
        ]);
        assert!(matches!(
            Config::from_map(production),
            Err(ConfigError::Validation(message)) if message.contains("APP_OPEN_BROWSER")
        ));
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
            ("DATABASE_URL".into(), TEST_DATABASE_URL.into()),
            ("REDIS_URL".into(), TEST_REDIS_URL.into()),
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

        let values = HashMap::from([
            ("APP_ENV".into(), "production".into()),
            ("DATABASE_URL".into(), TEST_DATABASE_URL.into()),
        ]);
        assert_eq!(
            Config::from_map(values).unwrap_err(),
            ConfigError::Missing("REDIS_URL")
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
            ("DATABASE_URL".into(), TEST_DATABASE_URL.into()),
            ("REDIS_URL".into(), TEST_REDIS_URL.into()),
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
