//! Multi-level Caching System
//!
//! Implements a multi-level cache with LRU/LFU eviction policies,
//! cache coherency, and tiered storage (hot/warm/cold).

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod lru;
pub mod lfu;
pub mod tiered;
pub mod coherency;

// Re-export key types
pub use lru::LruCache;
pub use lfu::LfuCache;
pub use tiered::{TieredCache, CacheTier};
pub use coherency::{CacheCoherencyManager, CoherencyProtocol};

/// Cache entry with metadata
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached data
    pub data: Vec<u8>,
    /// Content key/identifier
    pub key: String,
    /// Size in bytes
    pub size: usize,
    /// Access count
    pub access_count: u64,
    /// Last access timestamp
    pub last_access: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Time-to-live in seconds (0 = no expiration)
    pub ttl: u64,
    /// Cache tier (hot/warm/cold)
    pub tier: CacheTier,
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(key: String, data: Vec<u8>, ttl: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            size: data.len(),
            data,
            key,
            access_count: 0,
            last_access: now,
            created_at: now,
            ttl,
            tier: CacheTier::Hot,
        }
    }

    /// Record an access
    pub fn record_access(&mut self) {
        self.access_count += 1;
        self.last_access = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        if self.ttl == 0 {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.created_at + self.ttl
    }

    /// Get age in seconds
    pub fn age(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.created_at)
    }

    /// Calculate entry score for eviction (higher = keep longer)
    pub fn eviction_score(&self) -> f64 {
        let recency_factor = 1.0 / (self.age() as f64 + 1.0);
        let frequency_factor = self.access_count as f64;
        recency_factor * frequency_factor
    }
}

/// Cache eviction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvictionPolicy {
    /// Least Recently Used
    LRU,
    /// Least Frequently Used
    LFU,
    /// Adaptive Replacement Cache (balance between LRU and LFU)
    ARC,
    /// First In First Out
    FIFO,
}

/// Unified cache manager
pub struct CacheManager {
    /// Cache entries
    entries: HashMap<String, CacheEntry>,
    /// Eviction policy
    eviction_policy: EvictionPolicy,
    /// Maximum cache size in bytes
    max_size: usize,
    /// Current cache size in bytes
    current_size: usize,
    /// LRU access order queue
    lru_queue: VecDeque<String>,
    /// Access frequency map for LFU
    frequency_map: HashMap<String, u64>,
    /// Cache statistics
    stats: CacheStats,
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new(max_size: usize, eviction_policy: EvictionPolicy) -> Self {
        Self {
            entries: HashMap::new(),
            eviction_policy,
            max_size,
            current_size: 0,
            lru_queue: VecDeque::new(),
            frequency_map: HashMap::new(),
            stats: CacheStats::new(),
        }
    }

    /// Insert data into cache
    pub fn insert(&mut self, key: String, data: Vec<u8>, ttl: u64) -> Result<()> {
        let entry_size = data.len();

        // Check if we need to evict
        while self.current_size + entry_size > self.max_size && !self.entries.is_empty() {
            self.evict_one()?;
        }

        // Check if still doesn't fit
        if entry_size > self.max_size {
            return Err(anyhow!("Entry too large for cache"));
        }

        // Create entry
        let mut entry = CacheEntry::new(key.clone(), data, ttl);
        entry.record_access();

        // Update tracking structures
        self.update_access_tracking(&key);

        // Insert entry
        if let Some(old_entry) = self.entries.insert(key.clone(), entry) {
            self.current_size = self.current_size.saturating_sub(old_entry.size);
            self.stats.replacements += 1;
        } else {
            self.stats.insertions += 1;
        }

        self.current_size += entry_size;

        Ok(())
    }

    /// Get data from cache
    pub fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        // Check expiration and get data in separate scope
        let (is_expired, data_result) = if let Some(entry) = self.entries.get(key) {
            (entry.is_expired(), Some(entry.data.clone()))
        } else {
            (false, None)
        };

        if is_expired {
            let key_owned = key.to_string();
            self.remove(&key_owned);
            self.stats.expirations += 1;
            self.stats.misses += 1;
            return None;
        }

        if let Some(data) = data_result {
            // Record access after we've released the borrow
            if let Some(entry) = self.entries.get_mut(key) {
                entry.record_access();
            }
            self.update_access_tracking(key);
            self.stats.hits += 1;
            Some(data)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Check if key exists in cache
    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Remove entry from cache
    pub fn remove(&mut self, key: &str) -> Option<CacheEntry> {
        if let Some(entry) = self.entries.remove(key) {
            self.current_size = self.current_size.saturating_sub(entry.size);
            self.lru_queue.retain(|k| k != key);
            self.frequency_map.remove(key);
            self.stats.evictions += 1;
            Some(entry)
        } else {
            None
        }
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        let count = self.entries.len();
        self.entries.clear();
        self.lru_queue.clear();
        self.frequency_map.clear();
        self.current_size = 0;
        self.stats.evictions += count as u64;
    }

    /// Evict one entry based on policy
    fn evict_one(&mut self) -> Result<()> {
        let key_to_evict = match self.eviction_policy {
            EvictionPolicy::LRU => self.find_lru_victim(),
            EvictionPolicy::LFU => self.find_lfu_victim(),
            EvictionPolicy::ARC => self.find_arc_victim(),
            EvictionPolicy::FIFO => self.find_fifo_victim(),
        };

        if let Some(key) = key_to_evict {
            self.remove(&key);
            Ok(())
        } else {
            Err(anyhow!("No entry to evict"))
        }
    }

    /// Find LRU victim
    fn find_lru_victim(&self) -> Option<String> {
        self.lru_queue.front().cloned()
    }

    /// Find LFU victim
    fn find_lfu_victim(&self) -> Option<String> {
        self.frequency_map
            .iter()
            .min_by_key(|(_, &freq)| freq)
            .map(|(key, _)| key.clone())
    }

    /// Find ARC victim (hybrid approach)
    fn find_arc_victim(&self) -> Option<String> {
        self.entries
            .iter()
            .min_by(|(_, a), (_, b)| {
                a.eviction_score().partial_cmp(&b.eviction_score()).unwrap()
            })
            .map(|(key, _)| key.clone())
    }

    /// Find FIFO victim
    fn find_fifo_victim(&self) -> Option<String> {
        self.entries
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(key, _)| key.clone())
    }

    /// Update access tracking structures
    fn update_access_tracking(&mut self, key: &str) {
        // Update LRU queue
        self.lru_queue.retain(|k| k != key);
        self.lru_queue.push_back(key.to_string());

        // Update frequency map
        *self.frequency_map.entry(key.to_string()).or_insert(0) += 1;
    }

    /// Remove expired entries
    pub fn cleanup_expired(&mut self) -> usize {
        let expired_keys: Vec<String> = self.entries
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        let count = expired_keys.len();
        for key in expired_keys {
            self.remove(&key);
        }

        self.stats.expirations += count as u64;
        count
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get cache utilization (0.0 to 1.0)
    pub fn utilization(&self) -> f64 {
        if self.max_size == 0 {
            0.0
        } else {
            self.current_size as f64 / self.max_size as f64
        }
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get current size in bytes
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Get maximum size in bytes
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub expirations: u64,
    pub replacements: u64,
}

impl CacheStats {
    pub fn new() -> Self {
        Self {
            hits: 0,
            misses: 0,
            insertions: 0,
            evictions: 0,
            expirations: 0,
            replacements: 0,
        }
    }

    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }

    pub fn miss_rate(&self) -> f64 {
        100.0 - self.hit_rate()
    }
}

impl Default for CacheStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_creation() {
        let entry = CacheEntry::new("key1".to_string(), vec![1, 2, 3], 3600);
        assert_eq!(entry.size, 3);
        assert_eq!(entry.access_count, 0);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_manager_insert_get() {
        let mut cache = CacheManager::new(1024, EvictionPolicy::LRU);
        
        cache.insert("key1".to_string(), vec![1, 2, 3], 3600).unwrap();
        
        let data = cache.get("key1");
        assert!(data.is_some());
        assert_eq!(data.unwrap(), vec![1, 2, 3]);
        
        assert_eq!(cache.get_stats().hits, 1);
        assert_eq!(cache.get_stats().insertions, 1);
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = CacheManager::new(10, EvictionPolicy::LRU);
        
        // Fill cache
        cache.insert("key1".to_string(), vec![1, 2, 3, 4, 5], 3600).unwrap();
        cache.insert("key2".to_string(), vec![6, 7, 8, 9, 10], 3600).unwrap();
        
        // This should trigger eviction
        cache.insert("key3".to_string(), vec![11, 12], 3600).unwrap();
        
        // key1 should have been evicted (LRU)
        assert!(cache.get("key1").is_none());
        assert!(cache.get("key2").is_some());
        assert!(cache.get("key3").is_some());
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = CacheManager::new(1024, EvictionPolicy::LRU);
        
        cache.insert("key1".to_string(), vec![1, 2, 3], 3600).unwrap();
        cache.get("key1");
        cache.get("key2");
        
        let stats = cache.get_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 50.0);
    }

    #[test]
    fn test_cache_utilization() {
        let mut cache = CacheManager::new(100, EvictionPolicy::LRU);
        
        cache.insert("key1".to_string(), vec![0; 50], 3600).unwrap();
        assert_eq!(cache.utilization(), 0.5);
        
        cache.insert("key2".to_string(), vec![0; 25], 3600).unwrap();
        assert_eq!(cache.utilization(), 0.75);
    }
}
