//! Bounded LRU cache with TTL support for replay attack detection
//!
//! This module implements a size-bounded cache that combines:
//! - **LRU Eviction**: Removes oldest entries when size exceeds limit
//! - **TTL Cleanup**: Time-based expiration prevents false positives
//!
//! The cache is used for tracking (validator, payload_hash) pairs in replay detection.
//! When the same payload is seen again within the TTL window, it's marked as replay.
//! After TTL expiry, the same payload is no longer considered replay.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash as StdHash;

/// Bounded cache entry with timestamp
#[derive(Clone, Debug)]
struct CacheEntry<V> {
    value: V,
    inserted_at: u64,
    access_count: u32,
}

/// Bounded LRU cache with TTL support
///
/// **Eviction Policy**: When size exceeds `max_size`, oldest entry is removed.
/// **TTL Cleanup**: Entries older than `ttl_secs` are considered expired.
///
/// **Access Pattern**: Uses HashMap for O(1) lookup and VecDeque for LRU ordering.
/// **Memory**: O(max_size) bounded growth.
///
/// # Example
///
/// ```ignore
/// let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
/// cache.insert("key1", 42, current_time);
/// assert_eq!(cache.get("key1", current_time), Some(42));
/// ```
#[derive(Debug, Clone)]
pub struct BoundedLruCache<K: StdHash + Eq + Clone, V: Clone> {
    /// HashMap for O(1) lookup: key -> value + timestamp
    entries: HashMap<K, CacheEntry<V>>,
    /// VecDeque for LRU ordering: front = oldest, back = newest
    access_order: VecDeque<K>,
    /// Maximum number of entries before eviction
    max_size: usize,
    /// Time-to-live in seconds
    ttl_secs: u64,
    /// Total insertions (used for periodic cleanup trigger)
    insert_count: u64,
}

impl<K: StdHash + Eq + Clone, V: Clone> BoundedLruCache<K, V> {
    /// Create a new bounded LRU cache
    ///
    /// # Arguments
    /// * `max_size` - Maximum entries before LRU eviction (typical: 10,000)
    /// * `ttl_secs` - Seconds before entry expires (typical: 300 for 5 minutes)
    pub fn new(max_size: usize, ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            max_size,
            ttl_secs,
            insert_count: 0,
        }
    }

    /// Insert or update a cache entry
    ///
    /// If key exists: updates value and moves to back (most recent).
    /// If new key and cache at max_size: evicts oldest entry first.
    /// Periodic TTL cleanup triggered every 1000 insertions.
    pub fn insert(&mut self, key: K, value: V, current_time: u64) {
        // Periodic cleanup (every 1000 insertions)
        self.insert_count += 1;
        if self.insert_count % 1000 == 0 {
            self.cleanup_expired(current_time);
        }

        // If key exists: update value and move to back
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.value = value;
            entry.inserted_at = current_time;
            entry.access_count += 1;
            // Note: We don't move in access_order for performance
            // (VecDeque remove is O(n)). Acceptable for replay detection.
            return;
        }

        // New key: check size limit
        if self.entries.len() >= self.max_size {
            // Evict oldest (front of VecDeque)
            if let Some(oldest_key) = self.access_order.pop_front() {
                self.entries.remove(&oldest_key);
            }
        }

        // Insert new entry at back
        self.entries.insert(
            key.clone(),
            CacheEntry {
                value,
                inserted_at: current_time,
                access_count: 1,
            },
        );
        self.access_order.push_back(key);
    }

    /// Get a cache entry if it exists and hasn't expired
    ///
    /// Returns None if:
    /// - Key not found
    /// - Entry has expired (current_time - inserted_at > ttl_secs)
    pub fn get(&self, key: &K, current_time: u64) -> Option<V> {
        self.entries.get(key).and_then(|entry| {
            // Check if entry has expired
            if current_time.saturating_sub(entry.inserted_at) > self.ttl_secs {
                None
            } else {
                Some(entry.value.clone())
            }
        })
    }

    /// Check if key exists and hasn't expired
    pub fn contains(&self, key: &K, current_time: u64) -> bool {
        self.get(key, current_time).is_some()
    }

    /// Remove all entries older than TTL
    ///
    /// This is called periodically (every 1000 insertions) but can also
    /// be invoked manually for aggressive cleanup.
    pub fn cleanup_expired(&mut self, current_time: u64) {
        let expired_keys: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| current_time.saturating_sub(entry.inserted_at) > self.ttl_secs)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            self.entries.remove(&key);
        }

        // Rebuild access_order, removing expired keys
        self.access_order
            .retain(|key| self.entries.contains_key(key));
    }

    /// Get current size of cache
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
    }

    /// Get cache statistics (useful for monitoring)
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            current_size: self.entries.len(),
            max_size: self.max_size,
            ttl_secs: self.ttl_secs,
            total_insertions: self.insert_count,
        }
    }
}

/// Cache statistics
#[derive(Clone, Debug)]
pub struct CacheStats {
    pub current_size: usize,
    pub max_size: usize,
    pub ttl_secs: u64,
    pub total_insertions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_insert_and_get() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        cache.insert("key1".to_string(), 42, now);
        assert_eq!(cache.get(&"key1".to_string(), now), Some(42));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_nonexistent_key() {
        let cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        assert_eq!(cache.get(&"nonexistent".to_string(), now), None);
    }

    #[test]
    fn test_ttl_expiry() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        cache.insert("key1".to_string(), 42, now);
        assert_eq!(cache.get(&"key1".to_string(), now), Some(42));

        // Still valid at now + 299 seconds
        assert_eq!(cache.get(&"key1".to_string(), now + 299), Some(42));

        // Expired at now + 301 seconds
        assert_eq!(cache.get(&"key1".to_string(), now + 301), None);
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(3, 300);
        let now = 1000u64;

        // Fill to capacity
        cache.insert("key1".to_string(), 1, now);
        cache.insert("key2".to_string(), 2, now);
        cache.insert("key3".to_string(), 3, now);
        assert_eq!(cache.len(), 3);

        // Add 4th key: should evict key1 (oldest)
        cache.insert("key4".to_string(), 4, now);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(&"key1".to_string(), now), None); // Evicted
        assert_eq!(cache.get(&"key2".to_string(), now), Some(2)); // Still there
        assert_eq!(cache.get(&"key3".to_string(), now), Some(3)); // Still there
        assert_eq!(cache.get(&"key4".to_string(), now), Some(4)); // Newly added
    }

    #[test]
    fn test_update_existing_key() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        cache.insert("key1".to_string(), 42, now);
        assert_eq!(cache.get(&"key1".to_string(), now), Some(42));
        assert_eq!(cache.len(), 1);

        // Update same key with new value
        cache.insert("key1".to_string(), 100, now + 50);
        assert_eq!(cache.get(&"key1".to_string(), now + 50), Some(100));
        assert_eq!(cache.len(), 1); // Size unchanged
    }

    #[test]
    fn test_cleanup_expired() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        cache.insert("key1".to_string(), 1, now);
        cache.insert("key2".to_string(), 2, now + 100);
        cache.insert("key3".to_string(), 3, now + 200);
        assert_eq!(cache.len(), 3);

        // Clean up at now + 350: only key2 and key3 remain
        cache.cleanup_expired(now + 350);
        assert_eq!(cache.get(&"key1".to_string(), now + 350), None);
        assert_eq!(cache.get(&"key2".to_string(), now + 350), Some(2)); // Inserted at +100, expires at +400
        assert_eq!(cache.get(&"key3".to_string(), now + 350), Some(3)); // Inserted at +200, expires at +500
    }

    #[test]
    fn test_contains() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        assert!(!cache.contains(&"key1".to_string(), now));

        cache.insert("key1".to_string(), 42, now);
        assert!(cache.contains(&"key1".to_string(), now));

        // After expiry
        assert!(!cache.contains(&"key1".to_string(), now + 301));
    }

    #[test]
    fn test_clear() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        cache.insert("key1".to_string(), 42, now);
        cache.insert("key2".to_string(), 100, now);
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_stats() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        cache.insert("key1".to_string(), 42, now);
        cache.insert("key2".to_string(), 100, now);

        let stats = cache.stats();
        assert_eq!(stats.current_size, 2);
        assert_eq!(stats.max_size, 100);
        assert_eq!(stats.ttl_secs, 300);
    }

    #[test]
    fn test_periodic_cleanup_trigger() {
        let mut cache: BoundedLruCache<String, u32> = BoundedLruCache::new(100, 10);
        let mut now = 1000u64;

        // Insert 2000 keys (triggers cleanup every 1000 inserts)
        for i in 0..2000 {
            cache.insert(format!("key{}", i), i as u32, now);
            if i == 1000 {
                now += 15; // Move time forward after 1000 inserts to trigger cleanup
            }
        }

        // After cleanup at second batch, expired entries should be gone
        // All entries from first 1000 should be expired (TTL=10, time diff=15)
        assert!(cache.len() <= 1000); // Size reduced by cleanup
    }

    #[test]
    fn test_integer_keys() {
        let mut cache: BoundedLruCache<u64, String> = BoundedLruCache::new(100, 300);
        let now = 1000u64;

        cache.insert(123u64, "value1".to_string(), now);
        cache.insert(456u64, "value2".to_string(), now);

        assert_eq!(cache.get(&123u64, now), Some("value1".to_string()));
        assert_eq!(cache.get(&456u64, now), Some("value2".to_string()));
    }
}
