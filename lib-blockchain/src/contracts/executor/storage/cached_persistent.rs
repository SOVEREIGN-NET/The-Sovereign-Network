//! Cached persistent storage combining PersistentStorage with StateCache
//!
//! Provides a high-performance storage backend that combines persistent durability
//! with hot-path caching for frequently accessed contract state.

use super::cache::StateCache;
use super::errors::StorageResult;
use super::persistent::PersistentStorage;
use crate::contracts::executor::ContractStorage;

/// Persistent storage with integrated caching layer
///
/// Combines PersistentStorage durability with StateCache performance optimization.
/// Implements transparent cache invalidation on writes and hit rate tracking.
#[derive(Clone)]
pub struct CachedPersistentStorage {
    storage: PersistentStorage,
    cache: StateCache,
}

impl CachedPersistentStorage {
    /// Create a new cached persistent storage instance
    pub fn new(storage: PersistentStorage) -> StorageResult<Self> {
        let cache = StateCache::new()?;

        Ok(CachedPersistentStorage { storage, cache })
    }

    /// Create with custom cache configuration
    pub fn with_cache_config(
        storage: PersistentStorage,
        cache_config: super::cache::CacheConfig,
    ) -> StorageResult<Self> {
        let cache = StateCache::with_config(cache_config)?;

        Ok(CachedPersistentStorage { storage, cache })
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> StorageResult<super::cache::CacheStats> {
        self.cache.stats()
    }

    /// Clear all cached entries
    pub fn clear_cache(&self) -> StorageResult<()> {
        self.cache.clear()
    }

    /// Get underlying storage reference (for admin operations)
    pub fn underlying_storage(&self) -> &PersistentStorage {
        &self.storage
    }
}

impl ContractStorage for CachedPersistentStorage {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        // Try cache first
        if let Some(cached_value) = self.cache.get(key)? {
            return Ok(Some(cached_value));
        }

        // Cache miss - fetch from persistent storage
        if let Some(value) = self.storage.get(key)? {
            // Populate cache
            self.cache.put(key.to_vec(), value.clone())?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    fn set(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        // Write to persistent storage first (durability)
        self.storage.set(key, value)?;

        // Update cache
        self.cache.put(key.to_vec(), value.to_vec())?;

        Ok(())
    }

    fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
        // Remove from persistent storage
        self.storage.delete(key)?;

        // Invalidate cache entry
        self.cache.invalidate(key)?;

        Ok(())
    }

    fn exists(&self, key: &[u8]) -> anyhow::Result<bool> {
        // Check storage directly (cache doesn't track non-existence)
        self.storage.exists(key)
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cached_storage_hit_rate() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let cached_storage = CachedPersistentStorage::new(storage).unwrap();

        // Set a value
        let key = b"test_key";
        let value = b"test_value";

        // First access is a cache miss
        let _ = cached_storage.get(key).unwrap();

        // Set value
        cached_storage.set(key, value).unwrap();

        // Subsequent accesses should be cache hits
        for _ in 0..10 {
            let result = cached_storage.get(key).unwrap();
            assert_eq!(result, Some(value.to_vec()));
        }

        // Check cache stats
        let stats = cached_storage.cache_stats().unwrap();
        assert!(stats.hits > 0);
    }

    #[test]
    fn test_cache_invalidation_on_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let cached_storage = CachedPersistentStorage::new(storage).unwrap();

        let key = b"key_to_delete";
        let value = b"value";

        // Set and cache
        cached_storage.set(key, value).unwrap();
        assert_eq!(
            cached_storage.get(key).unwrap(),
            Some(value.to_vec())
        );

        // Delete should invalidate cache
        cached_storage.delete(key).unwrap();

        // After deletion, should return None
        assert_eq!(cached_storage.get(key).unwrap(), None);
    }

    #[test]
    fn test_cache_invalidation_on_update() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let cached_storage = CachedPersistentStorage::new(storage).unwrap();

        let key = b"key";
        let value1 = b"value1";
        let value2 = b"value2";

        // Set initial value
        cached_storage.set(key, value1).unwrap();
        assert_eq!(
            cached_storage.get(key).unwrap(),
            Some(value1.to_vec())
        );

        // Update value
        cached_storage.set(key, value2).unwrap();

        // Should return updated value
        assert_eq!(
            cached_storage.get(key).unwrap(),
            Some(value2.to_vec())
        );
    }

    #[test]
    fn test_clear_cache() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let cached_storage = CachedPersistentStorage::new(storage).unwrap();

        // Add some entries to cache
        for i in 0..5 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            cached_storage.set(key.as_bytes(), value.as_bytes()).unwrap();
        }

        // Verify cache has entries
        let stats_before = cached_storage.cache_stats().unwrap();
        assert!(stats_before.entry_count > 0);

        // Clear cache
        cached_storage.clear_cache().unwrap();

        // Cache should be empty
        let stats_after = cached_storage.cache_stats().unwrap();
        assert_eq!(stats_after.entry_count, 0);
    }
}
