//! General-purpose request rate limiting.
//!
//! A [`RateLimiter`] counts hits against arbitrary string keys inside a fixed
//! window, so one backend can meter clients by IP today and by account, API
//! key, or route tomorrow. The HTTP middleware ([`enforce`]) applies a named
//! [`RateLimitPolicy`] per router group, keyed by client IP; the policies and
//! their quotas come from [`crate::config::RateLimitSettings`].
//!
//! Two backends mirror the cache and queue pattern: an in-memory limiter for
//! single-process development runs, and a Redis-backed one that keeps counts
//! consistent across instances. Production configuration always carries a
//! `REDIS_URL`, so deployed instances always share the Redis backend.

use crate::{
    config::{ClientIpSource, RateLimitQuota},
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
use redis::{aio::ConnectionManager, Script};
use std::{
    collections::{hash_map::Entry, HashMap},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;

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

/// Fixed-window limiter for development runs; production always uses
/// [`RedisRateLimiter`], because its configuration requires Redis.
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
#[derive(Clone)]
pub struct RedisRateLimiter {
    manager: ConnectionManager,
    namespace: String,
    script: Script,
}

impl RedisRateLimiter {
    pub fn new(manager: ConnectionManager, namespace: String) -> Self {
        Self {
            manager,
            namespace,
            script: Script::new(FIXED_WINDOW_SCRIPT),
        }
    }
}

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
