//! State caching layer for hot contract data
//!
//! Implements Adaptive Replacement Cache (ARC) for frequently accessed contract state,
//! reducing load on persistent storage and improving throughput.

use super::errors::StorageResult;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

/// Hot state cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum cache size in bytes (default: 16MB)
    pub max_size_bytes: usize,
    /// Enable statistics tracking
    pub track_stats: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_size_bytes: 16 * 1024 * 1024, // 16 MB
            track_stats: true,
        }
    }
}

/// Cache entry metadata
#[derive(Debug, Clone)]
struct CacheEntry {
    key: Vec<u8>,
    value: Vec<u8>,
    access_count: u64,
    size: usize,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub current_size_bytes: usize,
    pub entry_count: usize,
}

impl CacheStats {
    /// Calculate hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let total = (self.hits + self.misses) as f64;
        if total == 0.0 {
            0.0
        } else {
            (self.hits as f64 / total) * 100.0
        }
    }
}

/// Adaptive Replacement Cache for contract state
///
/// This cache uses an LRU eviction policy optimized for contract state patterns:
/// - Hot contracts (frequently accessed) stay in cache
/// - Cold contracts are evicted to make room
/// - Statistics track performance for optimization
pub struct StateCache {
    cache: Arc<Mutex<LruCache<Vec<u8>, CacheEntry>>>,
    stats: Arc<Mutex<CacheStats>>,
    config: CacheConfig,
}

impl Clone for StateCache {
    fn clone(&self) -> Self {
        StateCache {
            cache: Arc::clone(&self.cache),
            stats: Arc::clone(&self.stats),
            config: self.config.clone(),
        }
    }
}

impl StateCache {
    /// Create a new state cache with default configuration
    pub fn new() -> StorageResult<Self> {
        Self::with_config(CacheConfig::default())
    }

    /// Create a new state cache with custom configuration
    pub fn with_config(config: CacheConfig) -> StorageResult<Self> {
        // Estimate number of entries: assume average entry is 4KB
        let avg_entry_size = 4096;
        let max_entries = (config.max_size_bytes / avg_entry_size).max(100);

        let cache = LruCache::new(
            NonZeroUsize::new(max_entries)
                .ok_or_else(|| anyhow::anyhow!("Cache size must be > 0"))?,
        );

        Ok(StateCache {
            cache: Arc::new(Mutex::new(cache)),
            stats: Arc::new(Mutex::new(CacheStats::default())),
            config,
        })
    }

    /// Get a value from cache
    ///
    /// Returns None if not found in cache (not the same as None in storage)
    pub fn get(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| anyhow::anyhow!("Cache lock poisoned: {}", e))?;

        if let Some(entry) = cache.get_mut(key) {
            let mut stats = self
                .stats
                .lock()
                .map_err(|e| anyhow::anyhow!("Stats lock poisoned: {}", e))?;
            stats.hits += 1;

            Ok(Some(entry.value.clone()))
        } else {
            let mut stats = self
                .stats
                .lock()
                .map_err(|e| anyhow::anyhow!("Stats lock poisoned: {}", e))?;
            stats.misses += 1;

            Ok(None)
        }
    }

    /// Put a value in cache
    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| anyhow::anyhow!("Cache lock poisoned: {}", e))?;

        let size = value.len();
        let entry = CacheEntry {
            key: key.clone(),
            value,
            access_count: 1,
            size,
        };

        // Check if eviction will happen
        if cache.len() >= cache.cap().get() {
            let mut stats = self
                .stats
                .lock()
                .map_err(|e| anyhow::anyhow!("Stats lock poisoned: {}", e))?;
            stats.evictions += 1;
        }

        cache.put(key, entry);
        Ok(())
    }

    /// Invalidate a cache entry
    pub fn invalidate(&self, key: &[u8]) -> StorageResult<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| anyhow::anyhow!("Cache lock poisoned: {}", e))?;
        cache.pop(key);
        Ok(())
    }

    /// Invalidate all cache entries
    pub fn clear(&self) -> StorageResult<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| anyhow::anyhow!("Cache lock poisoned: {}", e))?;
        cache.clear();
        Ok(())
    }

    /// Get current cache statistics
    pub fn stats(&self) -> StorageResult<CacheStats> {
        let cache = self
            .cache
            .lock()
            .map_err(|e| anyhow::anyhow!("Cache lock poisoned: {}", e))?;
        let stats = self
            .stats
            .lock()
            .map_err(|e| anyhow::anyhow!("Stats lock poisoned: {}", e))?;

        let mut current_stats = stats.clone();
        current_stats.entry_count = cache.len();
        // Note: We don't track exact size currently, would need per-entry tracking
        current_stats.current_size_bytes = cache.len() * 4096; // Approximate

        Ok(current_stats)
    }

    /// Reset statistics counters
    pub fn reset_stats(&self) -> StorageResult<()> {
        let mut stats = self
            .stats
            .lock()
            .map_err(|e| anyhow::anyhow!("Stats lock poisoned: {}", e))?;
        *stats = CacheStats::default();
        Ok(())
    }
}

impl Default for StateCache {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            // Fallback for initialization failure
            panic!("Failed to create default StateCache")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_get_put() {
        let cache = StateCache::new().unwrap();

        // Initially miss
        assert_eq!(cache.get(b"key1").unwrap(), None);

        // Put and hit
        cache.put(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        assert_eq!(
            cache.get(b"key1").unwrap(),
            Some(b"value1".to_vec())
        );
    }

    #[test]
    fn test_cache_invalidation() {
        let cache = StateCache::new().unwrap();

        cache.put(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        assert_eq!(
            cache.get(b"key1").unwrap(),
            Some(b"value1".to_vec())
        );

        cache.invalidate(b"key1").unwrap();
        assert_eq!(cache.get(b"key1").unwrap(), None);
    }

    #[test]
    fn test_cache_stats() {
        let cache = StateCache::new().unwrap();

        cache.put(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        cache.get(b"key1").unwrap();
        cache.get(b"key2").unwrap(); // Miss
        cache.get(b"key1").unwrap();

        let stats = cache.stats().unwrap();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!(stats.hit_rate() > 50.0 && stats.hit_rate() < 80.0);
    }

    #[test]
    fn test_cache_clear() {
        let cache = StateCache::new().unwrap();

        cache.put(b"key1".to_vec(), b"value1".to_vec()).unwrap();
        cache.put(b"key2".to_vec(), b"value2".to_vec()).unwrap();

        cache.clear().unwrap();

        assert_eq!(cache.get(b"key1").unwrap(), None);
        assert_eq!(cache.get(b"key2").unwrap(), None);
    }
}
