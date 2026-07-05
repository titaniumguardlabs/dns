#![cfg_attr(not(feature = "recursion"), allow(dead_code))]

pub mod base;
pub mod moka;
#[cfg(feature = "redis-cache")]
pub mod redis;

use serde::Deserialize;
use std::sync::Arc;

type CacheError = Box<dyn std::error::Error + Send + Sync>;
type CacheResult<T> = Result<T, CacheError>;
type SharedDnsCache = Arc<dyn base::DnsRecordCache>;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CachingConfig {
    Memory {
        #[serde(default = "default_cache_memory_max_entries")]
        max_entries: u64,
    },
    #[cfg_attr(not(feature = "redis-cache"), allow(dead_code))]
    Redis {
        url: String,
        #[serde(default = "default_cache_redis_key_prefix")]
        key_prefix: String,
        #[serde(default)]
        required: bool,
        #[serde(default = "default_cache_redis_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_cache_redis_failure_threshold")]
        failure_threshold: u32,
    },
}

impl Default for CachingConfig {
    fn default() -> Self {
        Self::Memory {
            max_entries: default_cache_memory_max_entries(),
        }
    }
}

pub fn build_dns_record_cache(config: &CachingConfig) -> CacheResult<SharedDnsCache> {
    match config {
        CachingConfig::Memory { max_entries } => {
            Ok(Arc::new(moka::MokaDnsRecordCache::new(*max_entries)) as SharedDnsCache)
        }
        #[cfg(feature = "redis-cache")]
        CachingConfig::Redis {
            url,
            key_prefix,
            required,
            timeout_ms,
            failure_threshold,
        } => Ok(Arc::new(redis::RedisDnsRecordCache::new(
            url,
            key_prefix,
            *required,
            *timeout_ms,
            *failure_threshold,
        )?) as SharedDnsCache),
        #[cfg(not(feature = "redis-cache"))]
        CachingConfig::Redis { .. } => Err(
            "Redis cache configured but binary was built without the `redis-cache` feature".into(),
        ),
    }
}

fn default_cache_memory_max_entries() -> u64 {
    100_000
}

fn default_cache_redis_key_prefix() -> String {
    "dns:cache:".to_string()
}

fn default_cache_redis_timeout_ms() -> u64 {
    250
}

fn default_cache_redis_failure_threshold() -> u32 {
    3
}

pub use base::DnsRecordCache;
#[cfg(test)]
pub use moka::MokaDnsRecordCache;
