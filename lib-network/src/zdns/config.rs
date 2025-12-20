//! ZDNS configuration

use std::time::Duration;

/// Default cache size (number of records)
pub const DEFAULT_CACHE_SIZE: usize = 10_000;

/// Default TTL for cached records (5 minutes)
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Default negative cache TTL (1 minute for not-found results)
pub const DEFAULT_NEGATIVE_TTL_SECS: u64 = 60;

/// ZDNS resolver configuration
#[derive(Debug, Clone)]
pub struct ZdnsConfig {
    /// Maximum number of cached records
    pub cache_size: usize,
    /// Default TTL for cached records (if not specified by domain)
    pub default_ttl: Duration,
    /// TTL for negative cache entries (domain not found)
    pub negative_ttl: Duration,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable debug logging for cache operations
    pub debug_cache: bool,
}

impl Default for ZdnsConfig {
    fn default() -> Self {
        Self {
            cache_size: DEFAULT_CACHE_SIZE,
            default_ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            negative_ttl: Duration::from_secs(DEFAULT_NEGATIVE_TTL_SECS),
            enable_metrics: true,
            debug_cache: false,
        }
    }
}

impl ZdnsConfig {
    /// Create config for testing with smaller cache and shorter TTLs
    pub fn for_testing() -> Self {
        Self {
            cache_size: 100,
            default_ttl: Duration::from_secs(10),
            negative_ttl: Duration::from_secs(5),
            enable_metrics: false,
            debug_cache: true,
        }
    }

    /// Create config optimized for high-traffic scenarios
    pub fn high_traffic() -> Self {
        Self {
            cache_size: 100_000,
            default_ttl: Duration::from_secs(600), // 10 minutes
            negative_ttl: Duration::from_secs(120), // 2 minutes
            enable_metrics: true,
            debug_cache: false,
        }
    }
}
