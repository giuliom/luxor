use crate::error::AppError;
use async_trait::async_trait;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn get_json(&self, key: &str) -> Result<Option<serde_json::Value>, AppError>;
    async fn put_json(
        &self,
        key: &str,
        value: &serde_json::Value,
        ttl: Duration,
    ) -> Result<(), AppError>;
    async fn invalidate(&self, key: &str) -> Result<(), AppError>;
    /// Reads a key and deletes it in one atomic step, so that at most one
    /// caller ever observes the value. Separate `get` and `invalidate` calls
    /// cannot promise that: two callers can both read before either deletes.
    /// Single-use credentials — the realtime connection ticket — depend on it.
    async fn take_json(&self, key: &str) -> Result<Option<serde_json::Value>, AppError>;
}

pub async fn get_typed<T: DeserializeOwned>(
    cache: &dyn Cache,
    key: &str,
) -> Result<Option<T>, AppError> {
    cache
        .get_json(key)
        .await?
        .map(serde_json::from_value)
        .transpose()
        .map_err(AppError::from)
}

pub async fn put_typed<T: Serialize + Sync>(
    cache: &dyn Cache,
    key: &str,
    value: &T,
    ttl: Duration,
) -> Result<(), AppError> {
    cache
        .put_json(key, &serde_json::to_value(value)?, ttl)
        .await
}

#[derive(Clone)]
pub struct RedisCache {
    manager: ConnectionManager,
    namespace: String,
}

impl RedisCache {
    pub fn new(manager: ConnectionManager, namespace: String) -> Self {
        Self { manager, namespace }
    }

    pub fn namespaced_key(&self, key: &str) -> Result<String, AppError> {
        validate_key(key)?;
        Ok(format!("{}:{key}", self.namespace))
    }
}

#[async_trait]
impl Cache for RedisCache {
    async fn get_json(&self, key: &str) -> Result<Option<serde_json::Value>, AppError> {
        let mut manager = self.manager.clone();
        let value: Option<String> = manager.get(self.namespaced_key(key)?).await?;
        value
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(AppError::from)
    }

    async fn put_json(
        &self,
        key: &str,
        value: &serde_json::Value,
        ttl: Duration,
    ) -> Result<(), AppError> {
        validate_ttl(ttl)?;
        let mut manager = self.manager.clone();
        let serialized = serde_json::to_string(value)?;
        // Millisecond precision (PSETEX) keeps sub-second TTLs meaningful;
        // SETEX would truncate them to zero seconds, which Redis rejects.
        let ttl_millis = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let _: () = manager
            .pset_ex(self.namespaced_key(key)?, serialized, ttl_millis)
            .await?;
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), AppError> {
        let mut manager = self.manager.clone();
        let _: usize = manager.del(self.namespaced_key(key)?).await?;
        Ok(())
    }

    // GETDEL is a single command, so the read and the delete cannot interleave
    // with another instance's. It requires Redis 6.2 or newer.
    async fn take_json(&self, key: &str) -> Result<Option<serde_json::Value>, AppError> {
        let mut manager = self.manager.clone();
        let value: Option<String> = manager.get_del(self.namespaced_key(key)?).await?;
        value
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(AppError::from)
    }
}

type MemoryEntry = (serde_json::Value, tokio::time::Instant);

#[derive(Clone, Default)]
pub struct MemoryCache {
    values: Arc<RwLock<HashMap<String, MemoryEntry>>>,
}

#[async_trait]
impl Cache for MemoryCache {
    async fn get_json(&self, key: &str) -> Result<Option<serde_json::Value>, AppError> {
        validate_key(key)?;
        let mut values = self.values.write().await;
        match values.get(key) {
            Some((value, expires_at)) if *expires_at > tokio::time::Instant::now() => {
                Ok(Some(value.clone()))
            }
            Some(_) => {
                values.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn put_json(
        &self,
        key: &str,
        value: &serde_json::Value,
        ttl: Duration,
    ) -> Result<(), AppError> {
        validate_key(key)?;
        validate_ttl(ttl)?;
        self.values.write().await.insert(
            key.to_owned(),
            (value.clone(), tokio::time::Instant::now() + ttl),
        );
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), AppError> {
        validate_key(key)?;
        self.values.write().await.remove(key);
        Ok(())
    }

    // The write lock is held across the read and the removal, which is this
    // backend's equivalent of Redis GETDEL.
    async fn take_json(&self, key: &str) -> Result<Option<serde_json::Value>, AppError> {
        validate_key(key)?;
        let mut values = self.values.write().await;
        Ok(values
            .remove(key)
            .filter(|(_, expires_at)| *expires_at > tokio::time::Instant::now())
            .map(|(value, _)| value))
    }
}

/// Both backends store with millisecond precision, so anything below one
/// millisecond is effectively no TTL at all.
fn validate_ttl(ttl: Duration) -> Result<(), AppError> {
    if ttl.as_millis() == 0 {
        return Err(AppError::BadRequest(
            "cache TTL must be at least one millisecond".into(),
        ));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), AppError> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
    {
        return Err(AppError::BadRequest(
            "cache key must be 1-128 URL-safe characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn memory_cache_honors_ttl_and_invalidation() {
        let cache = MemoryCache::default();
        put_typed(&cache, "profile:1", &42_u32, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            get_typed::<u32>(&cache, "profile:1").await.unwrap(),
            Some(42)
        );

        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(get_typed::<u32>(&cache, "profile:1").await.unwrap(), None);

        put_typed(&cache, "profile:1", &42_u32, Duration::from_secs(10))
            .await
            .unwrap();
        cache.invalidate("profile:1").await.unwrap();
        assert!(cache.get_json("profile:1").await.unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn memory_cache_take_returns_a_value_once() {
        let cache = MemoryCache::default();
        put_typed(&cache, "ticket:1", &"grant", Duration::from_secs(30))
            .await
            .unwrap();

        assert_eq!(
            cache.take_json("ticket:1").await.unwrap(),
            Some(serde_json::json!("grant"))
        );
        assert_eq!(cache.take_json("ticket:1").await.unwrap(), None);

        // An expired entry is a miss, and taking it still clears the row.
        put_typed(&cache, "ticket:2", &"grant", Duration::from_secs(30))
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(cache.take_json("ticket:2").await.unwrap(), None);
    }

    #[test]
    fn validates_cache_keys() {
        assert!(validate_key("user:123_profile").is_ok());
        assert!(validate_key("spaces are unsafe").is_err());
    }

    #[test]
    fn validates_cache_ttls_with_millisecond_precision() {
        assert!(validate_ttl(Duration::from_millis(500)).is_ok());
        assert!(validate_ttl(Duration::from_secs(300)).is_ok());
        assert!(validate_ttl(Duration::ZERO).is_err());
        assert!(validate_ttl(Duration::from_micros(900)).is_err());
    }
}
