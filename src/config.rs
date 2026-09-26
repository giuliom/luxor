//! Environment-backed configuration.
//!
//! [`Config`] is assembled from sections, and each section parses itself next
//! to the module that uses it: the listener and HTTP policy in
//! [`crate::server`], credentials in [`crate::auth`], the database in
//! [`crate::db`], rate limiting in [`crate::rate_limit`], and so on. The
//! application's own settings are one more section,
//! [`crate::app::Settings`], so a project adds configuration without touching
//! this file.
//!
//! Every section reads through an [`Env`], which carries the raw values along
//! with the two facts most defaults depend on: the environment, and the
//! application's name.

use secrecy::SecretString;
use std::{collections::HashMap, env, fmt, str::FromStr};
use thiserror::Error;
use url::Url;

#[cfg(feature = "kafka")]
use crate::events::kafka::KafkaSettings;
#[cfg(feature = "realtime")]
use crate::realtime::RealtimeSettings;
use crate::{
    auth::AuthSettings, cache::CacheSettings, db::DatabaseSettings,
    observability::TelemetrySettings, queue::QueueSettings, rate_limit::RateLimitSettings,
    server::HttpSettings,
};

/// What the application calls itself unless `APP_NAME` says otherwise: the
/// package name, so renaming the package renames every derived default.
pub const DEFAULT_APP_NAME: &str = env!("CARGO_PKG_NAME");

/// Longest accepted `APP_NAME`. The name is embedded in Redis keys, a cookie
/// name, and a Kafka topic, so it stays short.
const APP_NAME_MAX_LENGTH: usize = 64;

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

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
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

#[derive(Clone, Debug)]
pub struct Config {
    /// Names this deployment wherever the application identifies itself: the
    /// health check, the JWT issuer, the refresh cookie, and the defaults for
    /// Redis key namespaces, Kafka names, and the OpenTelemetry service name.
    pub app_name: String,
    pub environment: Environment,
    pub http: HttpSettings,
    pub database: DatabaseSettings,
    /// `None` selects the in-memory cache, queue, and rate limiter. Production
    /// configuration always carries a URL when the build includes the `redis`
    /// feature; a build without it runs the in-memory backends everywhere.
    pub redis_url: Option<SecretString>,
    pub auth: AuthSettings,
    pub cache: CacheSettings,
    pub queue: QueueSettings,
    pub rate_limit: RateLimitSettings,
    #[cfg(feature = "realtime")]
    pub realtime: RealtimeSettings,
    /// `None` selects the in-process event bus; see [`KafkaSettings`].
    #[cfg(feature = "kafka")]
    pub kafka: Option<KafkaSettings>,
    pub telemetry: TelemetrySettings,
    /// The application's own section.
    pub app: crate::app::Settings,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_map(env::vars().collect())
    }

    pub fn from_map(values: HashMap<String, String>) -> Result<Self, ConfigError> {
        let env = Env::new(values)?;
        env.refuse_excluded_features()?;

        let http = HttpSettings::from_env(&env)?;
        let database = DatabaseSettings::from_env(&env)?;
        #[cfg(feature = "redis")]
        let redis_url = env.infrastructure_url("REDIS_URL", &["redis", "rediss"])?;
        // Refused above when set, so a build without Redis never carries one.
        #[cfg(not(feature = "redis"))]
        let redis_url = None;

        Ok(Self {
            http,
            database,
            redis_url,
            auth: AuthSettings::from_env(&env)?,
            cache: CacheSettings::from_env(&env),
            queue: QueueSettings::from_env(&env),
            rate_limit: RateLimitSettings::from_env(&env)?,
            #[cfg(feature = "realtime")]
            realtime: RealtimeSettings::from_env(&env)?,
            #[cfg(feature = "kafka")]
            kafka: KafkaSettings::from_env(&env)?,
            telemetry: TelemetrySettings::from_env(&env)?,
            app: crate::app::Settings::from_env(&env)?,
            app_name: env.app_name,
            environment: env.environment,
        })
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

/// The raw settings a [`Config`] is parsed from, with the environment and the
/// application name already resolved so that every section can derive its
/// defaults from them.
///
/// An empty value reads as unset, which is how `.env` files and deployment
/// platforms spell "not configured".
pub struct Env {
    values: HashMap<String, String>,
    environment: Environment,
    app_name: String,
}

impl Env {
    pub fn new(values: HashMap<String, String>) -> Result<Self, ConfigError> {
        let environment = get(&values, "APP_ENV")
            .unwrap_or("development")
            .parse::<Environment>()?;
        let app_name = parse_app_name(get(&values, "APP_NAME").unwrap_or(DEFAULT_APP_NAME))?;
        Ok(Self {
            values,
            environment,
            app_name,
        })
    }

    pub fn environment(&self) -> &Environment {
        &self.environment
    }

    pub fn is_production(&self) -> bool {
        self.environment.is_production()
    }

    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        get(&self.values, key)
    }

    pub fn optional(&self, key: &str) -> Option<String> {
        self.get(key).map(ToOwned::to_owned)
    }

    /// Parses `key`, or returns `default` when it is unset.
    pub fn parse<T>(&self, key: &'static str, default: T) -> Result<T, ConfigError>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        match self.get(key) {
            Some(value) => value
                .parse::<T>()
                .map_err(|error| ConfigError::Invalid(key, error.to_string())),
            None => Ok(default),
        }
    }

    /// A value production must supply, with a fixed stand-in elsewhere.
    pub fn required_or_dev(
        &self,
        key: &'static str,
        development_default: &str,
    ) -> Result<String, ConfigError> {
        self.get(key)
            .map(ToOwned::to_owned)
            .or_else(|| (!self.is_production()).then(|| development_default.to_owned()))
            .ok_or(ConfigError::Missing(key))
    }

    /// Production must point at real infrastructure; outside production a
    /// missing URL selects the built-in development fallback (the embedded
    /// PostgreSQL server, or the in-memory cache and queue).
    pub fn infrastructure_url(
        &self,
        key: &'static str,
        schemes: &[&str],
    ) -> Result<Option<SecretString>, ConfigError> {
        match self.get(key) {
            Some(value) => {
                parse_url(key, value, schemes)?;
                Ok(Some(SecretString::from(value.to_owned())))
            }
            None if self.is_production() => Err(ConfigError::Missing(key)),
            None => Ok(None),
        }
    }

    /// Fails on any setting that belongs to a feature this build excludes.
    ///
    /// A deployment that sets `REDIS_URL` on a build without Redis believes it
    /// shares state across instances when it does not, so the value is a
    /// mistake worth naming rather than one to quietly ignore.
    fn refuse_excluded_features(&self) -> Result<(), ConfigError> {
        for (feature, included, keys) in FEATURE_SETTINGS {
            if included {
                continue;
            }
            if let Some(key) = keys.iter().find(|key| self.get(key).is_some()) {
                return Err(ConfigError::Validation(format!(
                    "{key} is set, but this build excludes the `{feature}` feature"
                )));
            }
        }
        Ok(())
    }
}

/// Every Kafka setting. `KAFKA_BROKERS` enables the event stream; the others
/// configure it and mean nothing without it.
pub(crate) const KAFKA_SETTINGS: [&str; 9] = [
    "KAFKA_BROKERS",
    "KAFKA_TOPIC",
    "KAFKA_CONSUMER_GROUP",
    "KAFKA_CLIENT_ID",
    "KAFKA_SECURITY_PROTOCOL",
    "KAFKA_SASL_MECHANISM",
    "KAFKA_SASL_USERNAME",
    "KAFKA_SASL_PASSWORD",
    "KAFKA_DELIVERY_TIMEOUT_SECONDS",
];

/// The settings owned by each optional feature, and whether this build
/// includes it.
const FEATURE_SETTINGS: [(&str, bool, &[&str]); 5] = [
    (
        "redis",
        cfg!(feature = "redis"),
        &[
            "REDIS_URL",
            "CACHE_NAMESPACE",
            "QUEUE_KEY",
            "RATE_LIMIT_NAMESPACE",
        ],
    ),
    ("kafka", cfg!(feature = "kafka"), &KAFKA_SETTINGS),
    (
        "otel",
        cfg!(feature = "otel"),
        &["OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_SERVICE_NAME"],
    ),
    ("sentry", cfg!(feature = "sentry"), &["SENTRY_DSN"]),
    (
        "realtime",
        cfg!(feature = "realtime"),
        &["REALTIME_MAX_CONNECTIONS", "REALTIME_TICKET_TTL_SECONDS"],
    ),
];

fn get<'a>(values: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    values
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
}

/// The name is embedded in Redis keys, a cookie name, and a Kafka topic, so it
/// is held to the characters all three accept — which are also the characters
/// a Cargo package name may contain, so the default always passes.
fn parse_app_name(value: &str) -> Result<String, ConfigError> {
    let valid = (1..=APP_NAME_MAX_LENGTH).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    valid.then(|| value.to_owned()).ok_or_else(|| {
        ConfigError::Invalid(
            "APP_NAME",
            format!(
                "expected 1-{APP_NAME_MAX_LENGTH} characters of letters, digits, hyphens, or underscores"
            ),
        )
    })
}

pub fn parse_url(key: &'static str, value: &str, schemes: &[&str]) -> Result<Url, ConfigError> {
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

pub fn validate_origin(
    key: &'static str,
    origin: &str,
    production: bool,
) -> Result<(), ConfigError> {
    let url = parse_url(key, origin, &["http", "https"])?;
    // A plaintext origin in production means credentialed requests are
    // expected over a channel that cannot carry a `Secure` cookie, which is
    // a deployment mistake rather than a preference.
    if production && url.scheme() != "https" {
        return Err(ConfigError::Invalid(
            key,
            format!("{origin} must use https in production"),
        ));
    }
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
            key,
            format!("{origin} is not an HTTP(S) origin"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATABASE_URL: &str = "postgres://test@localhost:5432/test";

    fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn development_defaults_are_valid() {
        let config = Config::from_map(HashMap::new()).unwrap();
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.app_name, DEFAULT_APP_NAME);
        assert!(config.redis_url.is_none());
    }

    #[test]
    fn the_app_name_defaults_to_the_package_and_names_derived_settings() {
        let default = Config::from_map(HashMap::new()).unwrap();
        assert_eq!(default.app_name, env!("CARGO_PKG_NAME"));
        assert_eq!(
            default.cache.namespace,
            format!("{}:cache", env!("CARGO_PKG_NAME"))
        );

        let named = Config::from_map(values(&[("APP_NAME", "orders-api")])).unwrap();
        assert_eq!(named.app_name, "orders-api");
        assert_eq!(named.auth.jwt_issuer, "orders-api");
        assert_eq!(named.auth.refresh_cookie_name, "orders-api_refresh");
        assert_eq!(named.cache.namespace, "orders-api:cache");
        assert_eq!(named.queue.key, "orders-api:queue:jobs");
        assert_eq!(named.rate_limit.namespace, "orders-api:ratelimit");
    }

    #[test]
    fn the_app_name_is_held_to_identifier_characters() {
        for invalid in ["orders api", "orders/api", "orders:api", &"a".repeat(65)] {
            assert!(
                matches!(
                    Config::from_map(values(&[("APP_NAME", invalid)])),
                    Err(ConfigError::Invalid("APP_NAME", _))
                ),
                "{invalid:?} should be refused"
            );
        }
        assert!(Config::from_map(values(&[("APP_NAME", "Orders_API-2")])).is_ok());
    }

    #[test]
    fn the_environment_is_validated() {
        assert!(matches!(
            Config::from_map(values(&[("APP_ENV", "staging")])),
            Err(ConfigError::Invalid("APP_ENV", _))
        ));
        assert_eq!(
            Config::from_map(values(&[("APP_ENV", "test")]))
                .unwrap()
                .environment,
            Environment::Test
        );
    }

    #[test]
    fn production_requires_infrastructure_and_secrets() {
        assert_eq!(
            Config::from_map(values(&[("APP_ENV", "production")])).unwrap_err(),
            ConfigError::Missing("DATABASE_URL")
        );

        let with_database = values(&[
            ("APP_ENV", "production"),
            ("DATABASE_URL", TEST_DATABASE_URL),
        ]);
        // Redis is required exactly when the build can use it.
        let expected = if cfg!(feature = "redis") {
            ConfigError::Missing("REDIS_URL")
        } else {
            ConfigError::Missing("JWT_SECRET")
        };
        assert_eq!(Config::from_map(with_database).unwrap_err(), expected);
    }

    #[cfg(feature = "redis")]
    #[test]
    fn explicit_redis_urls_are_kept_and_validated() {
        let config = Config::from_map(values(&[("REDIS_URL", "redis://127.0.0.1:6379/")])).unwrap();
        assert!(config.redis_url.is_some());

        assert!(matches!(
            Config::from_map(values(&[("REDIS_URL", "http://127.0.0.1:6379/")])),
            Err(ConfigError::Invalid("REDIS_URL", _))
        ));
    }

    /// Each setting of an excluded feature is refused with the feature's name;
    /// in a build that includes the feature, the same setting is accepted.
    #[test]
    fn settings_of_excluded_features_are_refused() {
        for (feature, included, keys) in FEATURE_SETTINGS {
            for key in keys {
                let outcome = Config::from_map(values(&[(key, "configured")]));
                if included {
                    assert!(
                        !matches!(
                            &outcome,
                            Err(ConfigError::Validation(message)) if message.contains("this build excludes")
                        ),
                        "{key} is refused although `{feature}` is included"
                    );
                } else {
                    assert_eq!(
                        outcome.unwrap_err(),
                        ConfigError::Validation(format!(
                            "{key} is set, but this build excludes the `{feature}` feature"
                        ))
                    );
                }
            }
        }
    }

    #[test]
    fn empty_values_read_as_unset() {
        let env = Env::new(values(&[("APP_NAME", ""), ("APP_PORT", "")])).unwrap();
        assert_eq!(env.app_name(), DEFAULT_APP_NAME);
        assert_eq!(env.get("APP_PORT"), None);
        assert_eq!(env.parse("APP_PORT", 8080_u16).unwrap(), 8080);
    }
}
