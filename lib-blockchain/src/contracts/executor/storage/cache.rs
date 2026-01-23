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
/// - Byte-based size limit enforcement prevents memory bloat
pub struct StateCache {
    cache: Arc<Mutex<LruCache<Vec<u8>, CacheEntry>>>,
    stats: Arc<Mutex<CacheStats>>,
    config: CacheConfig,
    current_size_bytes: Arc<Mutex<usize>>,
}

impl Clone for StateCache {
    fn clone(&self) -> Self {
        StateCache {
            cache: Arc::clone(&self.cache),
            stats: Arc::clone(&self.stats),
            config: self.config.clone(),
            current_size_bytes: Arc::clone(&self.current_size_bytes),
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
        // Use a large initial capacity for the LRU cache.
        // The actual limit is enforced by byte-based eviction in put().
        // We start with enough slots to handle the max_size_bytes case where
        // all entries are small (e.g., 100 byte entries).
        let initial_capacity = (config.max_size_bytes / 100).max(100);

        let cache = LruCache::new(
            NonZeroUsize::new(initial_capacity)
                .ok_or_else(|| anyhow::anyhow!("Cache size must be > 0"))?,
        );

        Ok(StateCache {
            cache: Arc::new(Mutex::new(cache)),
            stats: Arc::new(Mutex::new(CacheStats::default())),
            config,
            current_size_bytes: Arc::new(Mutex::new(0)),
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
    ///
    /// Enforces byte-based size limits by evicting LRU entries until there's
    /// enough space for the new entry. If the new entry alone exceeds max_size_bytes,
    /// it will not be cached.
    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        // Calculate entry size: heap data (key + value) + stack struct overhead
        // CacheEntry stack size: 2 * 24 bytes (Vec metadata) + 8 (u64) + 8 (usize) = 64 bytes
        let entry_size = key.len() + value.len() + 64;
        
        // Don't cache entries that exceed the max size by themselves
        if entry_size > self.config.max_size_bytes {
            return Ok(());
        }

        let mut cache = self
            .cache
            .lock()
            .map_err(|e| anyhow::anyhow!("Cache lock poisoned: {}", e))?;
        
        let mut current_size = self
            .current_size_bytes
            .lock()
            .map_err(|e| anyhow::anyhow!("Size tracking lock poisoned: {}", e))?;

        // If key already exists, subtract its old size
        if let Some(old_entry) = cache.peek(&key) {
            *current_size = current_size.saturating_sub(old_entry.size);
        }

        // Evict LRU entries until we have enough space
        let mut stats = self
            .stats
            .lock()
            .map_err(|e| anyhow::anyhow!("Stats lock poisoned: {}", e))?;
        
        while *current_size + entry_size > self.config.max_size_bytes {
            if let Some((_evicted_key, evicted_entry)) = cache.pop_lru() {
                *current_size = current_size.saturating_sub(evicted_entry.size);
                stats.evictions += 1;
            } else {
                // Cache is empty but we still don't have space (shouldn't happen)
                break;
            }
        }

        let entry = CacheEntry {
            key: key.clone(),
            value,
            access_count: 1,
            size: entry_size,
        };

        cache.put(key, entry);
        *current_size += entry_size;
        
        Ok(())
    }

    /// Invalidate a cache entry
    pub fn invalidate(&self, key: &[u8]) -> StorageResult<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| anyhow::anyhow!("Cache lock poisoned: {}", e))?;
        
        if let Some(entry) = cache.pop(key) {
            let mut current_size = self
                .current_size_bytes
                .lock()
                .map_err(|e| anyhow::anyhow!("Size tracking lock poisoned: {}", e))?;
            *current_size = current_size.saturating_sub(entry.size);
        }
        
        Ok(())
    }

    /// Invalidate all cache entries
    pub fn clear(&self) -> StorageResult<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| anyhow::anyhow!("Cache lock poisoned: {}", e))?;
        cache.clear();
        
        let mut current_size = self
            .current_size_bytes
            .lock()
            .map_err(|e| anyhow::anyhow!("Size tracking lock poisoned: {}", e))?;
        *current_size = 0;
        
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
        let current_size = self
            .current_size_bytes
            .lock()
            .map_err(|e| anyhow::anyhow!("Size tracking lock poisoned: {}", e))?;

        let mut current_stats = stats.clone();
        current_stats.entry_count = cache.len();
        current_stats.current_size_bytes = *current_size;

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

// Note: Default is not implemented for StateCache because initialization
// can fail and Default is expected to be infallible. Use StateCache::new()
// or StateCache::with_config() explicitly instead.

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
        
        // Verify size tracking is reset
        let stats = cache.stats().unwrap();
        assert_eq!(stats.current_size_bytes, 0);
    }

    #[test]
    fn test_byte_based_eviction() {
        // Create a cache with a small byte limit (1KB)
        let config = CacheConfig {
            max_size_bytes: 1024,
            track_stats: true,
        };
        let cache = StateCache::with_config(config).unwrap();

        // Add entries that will exceed the limit
        // Each entry: key (4 bytes) + value (100 bytes) + CacheEntry overhead (~40 bytes) ≈ 144 bytes
        for i in 0..10 {
            let key = format!("key{}", i).into_bytes();
            let value = vec![i as u8; 100];
            cache.put(key, value).unwrap();
        }

        let stats = cache.stats().unwrap();
        
        // Verify the cache stayed within byte limits
        assert!(stats.current_size_bytes <= 1024, 
            "Cache size {} exceeds limit 1024", stats.current_size_bytes);
        
        // Verify some evictions occurred (we tried to add ~1440 bytes)
        assert!(stats.evictions > 0, "Expected evictions but got 0");
        
        // Verify we don't have all 10 entries
        assert!(stats.entry_count < 10, 
            "Expected fewer than 10 entries due to eviction, got {}", stats.entry_count);
    }

    #[test]
    fn test_oversized_entry_rejected() {
        // Create a cache with a small byte limit (100 bytes)
        let config = CacheConfig {
            max_size_bytes: 100,
            track_stats: true,
        };
        let cache = StateCache::with_config(config).unwrap();

        // Try to add an entry larger than the limit
        let key = b"key1".to_vec();
        let value = vec![1u8; 200]; // 200 bytes, exceeds 100 byte limit
        
        cache.put(key.clone(), value).unwrap();
        
        // Verify the entry was not cached
        assert_eq!(cache.get(&key).unwrap(), None);
        
        let stats = cache.stats().unwrap();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.current_size_bytes, 0);
    }

    #[test]
    fn test_size_tracking_accuracy() {
        let cache = StateCache::new().unwrap();

        let key1 = b"key1".to_vec();
        let value1 = vec![1u8; 50];
        cache.put(key1.clone(), value1).unwrap();

        let stats1 = cache.stats().unwrap();
        let size1 = stats1.current_size_bytes;
        assert!(size1 > 0);

        // Add another entry
        let key2 = b"key2".to_vec();
        let value2 = vec![2u8; 75];
        cache.put(key2.clone(), value2).unwrap();

        let stats2 = cache.stats().unwrap();
        assert!(stats2.current_size_bytes > size1);

        // Invalidate first entry
        cache.invalidate(&key1).unwrap();

        let stats3 = cache.stats().unwrap();
        assert!(stats3.current_size_bytes < stats2.current_size_bytes);
        assert_eq!(stats3.entry_count, 1);
    }
}
