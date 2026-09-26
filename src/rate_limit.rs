//! General-purpose request rate limiting.
//!
//! A [`RateLimiter`] counts hits against arbitrary string keys inside a fixed
//! window, so one backend can meter clients by IP today and by account, API
//! key, or route tomorrow. The HTTP middleware ([`enforce`]) applies a named
//! [`RateLimitPolicy`] per router group, keyed by client IP; the policies and
//! their quotas come from [`RateLimitSettings`].
//!
//! Two backends mirror the cache and queue pattern: an in-memory limiter for
//! single-process development runs, and a Redis-backed one that keeps counts
//! consistent across instances. Production configuration carries a
//! `REDIS_URL` whenever the build includes the `redis` feature, so deployed
//! instances of such a build always share the Redis backend.

use crate::{
    config::{ConfigError, Env},
    error::AppError,
    state::AppState,
};
use async_trait::async_trait;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};
#[cfg(feature = "redis")]
use redis::{aio::ConnectionManager, Script};
use std::{
    collections::{hash_map::Entry, HashMap},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;

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
    /// Prefix for the Redis keys of the distributed limiter;
    /// `<APP_NAME>:ratelimit` unless `RATE_LIMIT_NAMESPACE` says otherwise.
    pub namespace: String,
    /// Budget for the credential endpoints under `/api/auth`, the
    /// brute-force surface. Applies on top of `api`.
    pub auth: RateLimitQuota,
    /// Budget for everything under `/api`.
    pub api: RateLimitQuota,
}

impl RateLimitSettings {
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let production = env.is_production();
        let enabled = env.parse("RATE_LIMIT_ENABLED", true)?;
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
        let client_ip_source = match env.get("CLIENT_IP_SOURCE") {
            Some(value) => value.parse()?,
            None => default_source,
        };
        let namespace = env
            .optional("RATE_LIMIT_NAMESPACE")
            .unwrap_or_else(|| format!("{}:ratelimit", env.app_name()));
        let auth = parse_quota(
            env,
            ("RATE_LIMIT_AUTH_MAX_REQUESTS", 10),
            ("RATE_LIMIT_AUTH_WINDOW_SECONDS", 60),
        )?;
        let api = parse_quota(
            env,
            ("RATE_LIMIT_API_MAX_REQUESTS", 120),
            ("RATE_LIMIT_API_WINDOW_SECONDS", 60),
        )?;
        Ok(Self {
            enabled,
            client_ip_source,
            namespace,
            auth,
            api,
        })
    }
}

fn parse_quota(
    env: &Env,
    (max_key, default_max): (&'static str, u32),
    (window_key, default_window): (&'static str, u64),
) -> Result<RateLimitQuota, ConfigError> {
    let max_requests = env.parse(max_key, default_max)?;
    if max_requests == 0 {
        return Err(ConfigError::Validation(format!(
            "{max_key} must be greater than zero"
        )));
    }
    let window_seconds = env.parse(window_key, default_window)?;
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

/// The verdict for one recorded hit.
#[derive(Clone, Copy, Debug)]
pub struct RateLimitDecision {
    pub allowed: bool,
    /// The quota's request budget, echoed in the `RateLimit-Limit` header.
    pub limit: u32,
    /// Requests left in the current window.
    pub remaining: u32,
    /// Seconds (rounded up) until the current window resets.
    pub retry_after_seconds: u64,
}

#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Records one hit against `key` and reports whether it fits within the
    /// quota's window. Denied hits still count, so hammering a limited key
    /// never reopens the window early. Keys are arbitrary; callers namespace
    /// them (the middleware uses `{policy}:{client-ip}`).
    async fn hit(&self, key: &str, quota: RateLimitQuota) -> Result<RateLimitDecision, AppError>;
}

fn decision(count: u32, quota: RateLimitQuota, reset_in: Duration) -> RateLimitDecision {
    RateLimitDecision {
        allowed: count <= quota.max_requests,
        limit: quota.max_requests,
        remaining: quota.max_requests.saturating_sub(count),
        retry_after_seconds: ceil_seconds(reset_in),
    }
}

/// Rounds up so that a client honoring `Retry-After` never comes back inside
/// the same window.
fn ceil_seconds(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

/// Upper bound on concurrently tracked windows; expired windows are swept
/// once the bound is reached.
const MAX_TRACKED_WINDOWS: usize = 100_000;

struct MemoryWindow {
    count: u32,
    resets_at: tokio::time::Instant,
}

/// Fixed-window limiter for development runs, and for deployments built
/// without the `redis` feature, whose counts are then per instance.
#[derive(Clone, Default)]
pub struct MemoryRateLimiter {
    windows: Arc<RwLock<HashMap<String, MemoryWindow>>>,
}

#[async_trait]
impl RateLimiter for MemoryRateLimiter {
    async fn hit(&self, key: &str, quota: RateLimitQuota) -> Result<RateLimitDecision, AppError> {
        let now = tokio::time::Instant::now();
        let mut windows = self.windows.write().await;
        if windows.len() >= MAX_TRACKED_WINDOWS && !windows.contains_key(key) {
            windows.retain(|_, window| window.resets_at > now);
            if windows.len() >= MAX_TRACKED_WINDOWS {
                // Every tracked window is still live. Admitting the request
                // untracked keeps memory bounded at the cost of not metering
                // brand-new clients until windows expire.
                tracing::warn!(
                    "in-memory rate limiter reached its window capacity; \
                     allowing the request untracked"
                );
                return Ok(decision(
                    1,
                    quota,
                    Duration::from_secs(quota.window_seconds),
                ));
            }
        }

        let resets_at = now + Duration::from_secs(quota.window_seconds);
        let window = match windows.entry(key.to_owned()) {
            Entry::Occupied(entry) => {
                let window = entry.into_mut();
                if window.resets_at > now {
                    window.count = window.count.saturating_add(1);
                } else {
                    *window = MemoryWindow {
                        count: 1,
                        resets_at,
                    };
                }
                window
            }
            Entry::Vacant(entry) => entry.insert(MemoryWindow {
                count: 1,
                resets_at,
            }),
        };
        Ok(decision(window.count, quota, window.resets_at - now))
    }
}

/// Counts a hit and returns `{count, remaining window in milliseconds}` in
/// one atomic step. The second PEXPIRE is defensive: it re-arms the expiry if
/// a pre-existing key somehow lacks one, so no counter can persist forever.
#[cfg(feature = "redis")]
const FIXED_WINDOW_SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
    ttl = tonumber(ARGV[1])
end
return {count, ttl}
"#;

/// Fixed-window limiter with counters shared by every instance pointed at
/// the same Redis and namespace.
#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisRateLimiter {
    manager: ConnectionManager,
    namespace: String,
    script: Script,
}

#[cfg(feature = "redis")]
impl RedisRateLimiter {
    pub fn new(manager: ConnectionManager, namespace: String) -> Self {
        Self {
            manager,
            namespace,
            script: Script::new(FIXED_WINDOW_SCRIPT),
        }
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn hit(&self, key: &str, quota: RateLimitQuota) -> Result<RateLimitDecision, AppError> {
        let mut manager = self.manager.clone();
        // The configured window is at most a day, so the conversion cannot
        // overflow.
        let window_millis = quota.window_seconds * 1000;
        let (count, ttl_millis): (i64, i64) = self
            .script
            .key(format!("{}:{key}", self.namespace))
            .arg(window_millis)
            .invoke_async(&mut manager)
            .await?;
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        let reset_in = Duration::from_millis(u64::try_from(ttl_millis).unwrap_or(0));
        Ok(decision(count, quota, reset_in))
    }
}

/// One named budget, ready to be attached to a router group through
/// [`enforce`].
#[derive(Clone)]
pub struct RateLimitPolicy {
    name: &'static str,
    quota: RateLimitQuota,
    limiter: Arc<dyn RateLimiter>,
    client_ip_source: ClientIpSource,
    enabled: bool,
}

impl RateLimitPolicy {
    pub fn new(state: &AppState, name: &'static str, quota: RateLimitQuota) -> Self {
        let settings = &state.config.rate_limit;
        Self {
            name,
            quota,
            limiter: state.rate_limiter.clone(),
            client_ip_source: settings.client_ip_source,
            enabled: settings.enabled,
        }
    }
}

/// Middleware enforcing one [`RateLimitPolicy`], attached with
/// `middleware::from_fn_with_state(policy, rate_limit::enforce)`.
pub async fn enforce(
    State(policy): State<RateLimitPolicy>,
    request: Request,
    next: Next,
) -> Response {
    if !policy.enabled {
        return next.run(request).await;
    }
    // Requests without an attributable address (no connect info, or a
    // malformed forwarded header) share one "unknown" bucket rather than
    // bypassing the limit.
    let client = client_ip(policy.client_ip_source, &request)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let key = format!("{}:{client}", policy.name);
    match policy.limiter.hit(&key, policy.quota).await {
        Ok(decision) if decision.allowed => next.run(request).await,
        Ok(decision) => {
            tracing::info!(
                policy = policy.name,
                client = %client,
                retry_after_seconds = decision.retry_after_seconds,
                "rate limit exceeded"
            );
            limited_response(&decision)
        }
        Err(error) => {
            // Fail open: refusing every request while the limiter backend is
            // unreachable would escalate a Redis outage into an API outage.
            tracing::error!(
                error = ?error,
                policy = policy.name,
                "rate limiter unavailable; allowing the request"
            );
            next.run(request).await
        }
    }
}

fn limited_response(decision: &RateLimitDecision) -> Response {
    let mut response = AppError::RateLimited {
        retry_after_seconds: decision.retry_after_seconds,
    }
    .into_response();
    let headers = response.headers_mut();
    for (name, value) in [
        ("ratelimit-limit", u64::from(decision.limit)),
        ("ratelimit-remaining", u64::from(decision.remaining)),
        ("ratelimit-reset", decision.retry_after_seconds),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value.to_string())
                .expect("decimal digits are a valid header value"),
        );
    }
    response
}

fn client_ip(source: ClientIpSource, request: &Request) -> Option<IpAddr> {
    match source {
        ClientIpSource::Socket => request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(address)| address.ip()),
        // Only the rightmost entry of the last X-Forwarded-For header is
        // trusted: the platform proxy in front of the app appended it, while
        // everything left of it arrived client-controlled.
        ClientIpSource::XForwardedFor => request
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit(',').next())
            .and_then(|value| value.trim().parse::<IpAddr>().ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    const QUOTA: RateLimitQuota = RateLimitQuota {
        max_requests: 2,
        window_seconds: 60,
    };

    #[tokio::test(start_paused = true)]
    async fn memory_limiter_enforces_and_resets_the_window() {
        let limiter = MemoryRateLimiter::default();

        let first = limiter.hit("api:203.0.113.1", QUOTA).await.unwrap();
        assert!(first.allowed);
        assert_eq!(first.remaining, 1);

        let second = limiter.hit("api:203.0.113.1", QUOTA).await.unwrap();
        assert!(second.allowed);
        assert_eq!(second.remaining, 0);

        let third = limiter.hit("api:203.0.113.1", QUOTA).await.unwrap();
        assert!(!third.allowed);
        assert_eq!(third.remaining, 0);
        assert!((1..=60).contains(&third.retry_after_seconds));

        tokio::time::advance(Duration::from_secs(61)).await;
        let after_reset = limiter.hit("api:203.0.113.1", QUOTA).await.unwrap();
        assert!(after_reset.allowed);
        assert_eq!(after_reset.remaining, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn memory_limiter_tracks_keys_independently() {
        let limiter = MemoryRateLimiter::default();
        for _ in 0..3 {
            limiter.hit("api:203.0.113.1", QUOTA).await.unwrap();
        }
        assert!(!limiter.hit("api:203.0.113.1", QUOTA).await.unwrap().allowed);
        assert!(limiter.hit("api:203.0.113.2", QUOTA).await.unwrap().allowed);
        assert!(
            limiter
                .hit("auth:203.0.113.1", QUOTA)
                .await
                .unwrap()
                .allowed
        );
    }

    fn settings(pairs: &[(&str, &str)]) -> Result<RateLimitSettings, ConfigError> {
        RateLimitSettings::from_env(&Env::new(crate::testing::values(pairs))?)
    }

    #[test]
    fn development_defaults_are_valid() {
        let settings = settings(&[]).unwrap();
        assert!(settings.enabled);
        assert_eq!(settings.client_ip_source, ClientIpSource::Socket);
        assert_eq!(
            settings.namespace,
            format!("{}:ratelimit", env!("CARGO_PKG_NAME"))
        );
        assert_eq!(
            settings.auth,
            RateLimitQuota {
                max_requests: 10,
                window_seconds: 60
            }
        );
        assert_eq!(
            settings.api,
            RateLimitQuota {
                max_requests: 120,
                window_seconds: 60
            }
        );
    }

    #[test]
    fn rate_limiting_cannot_be_disabled_in_production() {
        assert!(matches!(
            settings(&[("APP_ENV", "production"), ("RATE_LIMIT_ENABLED", "false")]),
            Err(ConfigError::Validation(message)) if message.contains("RATE_LIMIT_ENABLED")
        ));
        assert!(
            !settings(&[("RATE_LIMIT_ENABLED", "false")])
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn client_ip_source_follows_the_deployment_shape() {
        assert_eq!(
            settings(&[("APP_ENV", "production")])
                .unwrap()
                .client_ip_source,
            ClientIpSource::XForwardedFor
        );
        assert_eq!(
            settings(&[("APP_ENV", "production"), ("CLIENT_IP_SOURCE", "socket")])
                .unwrap()
                .client_ip_source,
            ClientIpSource::Socket
        );
        assert!(matches!(
            settings(&[("CLIENT_IP_SOURCE", "guess")]),
            Err(ConfigError::Invalid("CLIENT_IP_SOURCE", _))
        ));
    }

    #[test]
    fn rate_limit_quotas_are_validated() {
        assert!(matches!(
            settings(&[("RATE_LIMIT_AUTH_MAX_REQUESTS", "0")]),
            Err(ConfigError::Validation(message))
                if message.contains("RATE_LIMIT_AUTH_MAX_REQUESTS")
        ));
        assert!(matches!(
            settings(&[("RATE_LIMIT_API_WINDOW_SECONDS", "86401")]),
            Err(ConfigError::Validation(message))
                if message.contains("RATE_LIMIT_API_WINDOW_SECONDS")
        ));
    }

    fn request_with_forwarded_for(values: &[&str]) -> Request {
        let mut builder = Request::builder().uri("/");
        for value in values {
            builder = builder.header("x-forwarded-for", *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn client_ip_uses_the_socket_peer_address() {
        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        assert_eq!(client_ip(ClientIpSource::Socket, &request), None);

        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 40_000))));
        assert_eq!(
            client_ip(ClientIpSource::Socket, &request),
            Some(IpAddr::from([203, 0, 113, 7]))
        );
    }

    #[test]
    fn client_ip_trusts_only_the_proxy_appended_forwarded_entry() {
        let single = request_with_forwarded_for(&["203.0.113.7"]);
        assert_eq!(
            client_ip(ClientIpSource::XForwardedFor, &single),
            Some(IpAddr::from([203, 0, 113, 7]))
        );

        // Entries the client sent itself sit to the left and are ignored.
        let spoofed = request_with_forwarded_for(&["198.51.100.1, 203.0.113.7"]);
        assert_eq!(
            client_ip(ClientIpSource::XForwardedFor, &spoofed),
            Some(IpAddr::from([203, 0, 113, 7]))
        );

        // With repeated headers, the last one is the proxy's.
        let repeated = request_with_forwarded_for(&["198.51.100.1", "2001:db8::17"]);
        assert_eq!(
            client_ip(ClientIpSource::XForwardedFor, &repeated),
            Some("2001:db8::17".parse::<IpAddr>().unwrap())
        );

        let garbage = request_with_forwarded_for(&["not-an-address"]);
        assert_eq!(client_ip(ClientIpSource::XForwardedFor, &garbage), None);

        let missing = Request::builder().uri("/").body(Body::empty()).unwrap();
        assert_eq!(client_ip(ClientIpSource::XForwardedFor, &missing), None);
    }

    #[test]
    fn retry_after_rounds_up() {
        assert_eq!(ceil_seconds(Duration::from_secs(3)), 3);
        assert_eq!(ceil_seconds(Duration::from_millis(3_400)), 4);
        assert_eq!(ceil_seconds(Duration::ZERO), 0);
    }
}
