//! Optimized DHT Cache with LRU and TTL support
//! 
//! High-performance caching layer for DHT content resolution

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};

/// Cache entry with metadata
#[derive(Debug, Clone)]
struct CacheEntry {
    value: String,
    created_at: SystemTime,
    last_accessed: SystemTime,
    access_count: u64,
    ttl: Duration,
}

/// DHT cache statistics  
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub size: usize,
    pub max_size: usize,
    pub hit_rate: f64,
}

/// High-performance DHT cache with LRU eviction and TTL
#[derive(Debug)]
pub struct OptimizedDHTCache {
    entries: HashMap<String, CacheEntry>,
    access_order: Vec<String>, // LRU tracking (most recent at end)
    max_size: usize,
    default_ttl: Duration,
    stats: CacheStats,
}

impl OptimizedDHTCache {
    /// Create new optimized cache
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            access_order: Vec::with_capacity(max_size),
            max_size,
            default_ttl,
            stats: CacheStats {
                max_size,
                ..Default::default()
            },
        }
    }

    /// Get value from cache
    pub fn get(&mut self, key: &str) -> Option<String> {
        // Check if entry exists and is valid
        let (is_valid, value) = if let Some(entry) = self.entries.get(key) {
            // Check TTL
            if entry.created_at.elapsed().unwrap_or(Duration::MAX) <= entry.ttl {
                (true, Some(entry.value.clone()))
            } else {
                (false, None)
            }
        } else {
            (false, None)
        };

        if is_valid {
            // Update access metadata (separate borrow)
            if let Some(entry) = self.entries.get_mut(key) {
                entry.last_accessed = SystemTime::now();
                entry.access_count += 1;
            }
            
            // Update LRU order
            self.update_access_order(key);
            
            // Update stats
            self.stats.hits += 1;
            self.update_hit_rate();
            
            value
        } else {
            // Entry expired or doesn't exist, remove if expired
            if self.entries.contains_key(key) {
                self.remove_entry(key);
            }
            self.stats.misses += 1;
            self.update_hit_rate();
            None
        }
    }

    /// Insert value into cache
    pub fn insert(&mut self, key: String, value: String) {
        self.insert_with_ttl(key, value, self.default_ttl);
    }

    /// Insert value with custom TTL
    pub fn insert_with_ttl(&mut self, key: String, value: String, ttl: Duration) {
        let now = SystemTime::now();
        
        let entry = CacheEntry {
            value,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            ttl,
        };

        // If key already exists, just update it
        if self.entries.contains_key(&key) {
            self.entries.insert(key.clone(), entry);
            self.update_access_order(&key);
            return;
        }

        // Check if we need to evict
        if self.entries.len() >= self.max_size {
            self.evict_lru();
        }

        // Insert new entry
        self.entries.insert(key.clone(), entry);
        self.access_order.push(key);
        
        self.stats.size = self.entries.len();
    }

    /// Remove entry from cache
    pub fn remove(&mut self, key: &str) -> Option<String> {
        if let Some(entry) = self.remove_entry(key) {
            Some(entry.value)
        } else {
            None
        }
    }

    /// Clear all cache entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
        self.stats.size = 0;
        self.stats.evictions = 0; // Reset evictions on manual clear
    }

    /// Get cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Clean expired entries
    pub fn cleanup_expired(&mut self) -> usize {
        let mut expired_keys = Vec::new();
        
        for (key, entry) in &self.entries {
            if entry.created_at.elapsed().unwrap_or(Duration::MAX) > entry.ttl {
                expired_keys.push(key.clone());
            }
        }
        
        let expired_count = expired_keys.len();
        for key in expired_keys {
            self.remove_entry(&key);
        }
        
        expired_count
    }

    /// Resize cache capacity
    pub fn resize(&mut self, new_max_size: usize) {
        self.max_size = new_max_size;
        self.stats.max_size = new_max_size;
        
        // Evict excess entries if needed
        while self.entries.len() > new_max_size {
            self.evict_lru();
        }
    }

    // Internal helper methods
    
    fn remove_entry(&mut self, key: &str) -> Option<CacheEntry> {
        // Remove from entries
        let entry = self.entries.remove(key)?;
        
        // Remove from access order
        if let Some(pos) = self.access_order.iter().position(|k| k == key) {
            self.access_order.remove(pos);
        }
        
        self.stats.size = self.entries.len();
        Some(entry)
    }

    fn evict_lru(&mut self) {
        if let Some(lru_key) = self.access_order.first().cloned() {
            self.remove_entry(&lru_key);
            self.stats.evictions += 1;
        }
    }

    fn update_access_order(&mut self, key: &str) {
        // Remove from current position
        if let Some(pos) = self.access_order.iter().position(|k| k == key) {
            self.access_order.remove(pos);
        }
        
        // Add to end (most recently used)
        self.access_order.push(key.to_string());
    }

    fn update_hit_rate(&mut self) {
        let total = self.stats.hits + self.stats.misses;
        if total > 0 {
            self.stats.hit_rate = self.stats.hits as f64 / total as f64;
        }
    }
}

/// Thread-safe wrapper for the optimized cache
#[derive(Debug)]
pub struct ThreadSafeDHTCache {
    cache: Arc<Mutex<OptimizedDHTCache>>,
}

impl ThreadSafeDHTCache {
    /// Create new thread-safe cache
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        Self {
            cache: Arc::new(Mutex::new(OptimizedDHTCache::new(max_size, default_ttl))),
        }
    }

    /// Get value from cache (async)
    pub async fn get(&self, key: &str) -> Option<String> {
        self.cache.lock().await.get(key)
    }

    /// Insert value into cache (async)
    pub async fn insert(&self, key: String, value: String) {
        self.cache.lock().await.insert(key, value);
    }

    /// Insert with custom TTL (async)
    pub async fn insert_with_ttl(&self, key: String, value: String, ttl: Duration) {
        self.cache.lock().await.insert_with_ttl(key, value, ttl);
    }

    /// Remove from cache (async)
    pub async fn remove(&self, key: &str) -> Option<String> {
        self.cache.lock().await.remove(key)
    }

    /// Clear cache (async)
    pub async fn clear(&self) {
        self.cache.lock().await.clear();
    }

    /// Get statistics (async)
    pub async fn stats(&self) -> CacheStats {
        self.cache.lock().await.stats().clone()
    }

    /// Cleanup expired entries (async)
    pub async fn cleanup_expired(&self) -> usize {
        self.cache.lock().await.cleanup_expired()
    }

    /// Resize cache (async)
    pub async fn resize(&self, new_max_size: usize) {
        self.cache.lock().await.resize(new_max_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[test]
    fn test_basic_cache_operations() {
        let mut cache = OptimizedDHTCache::new(3, Duration::from_secs(10));
        
        // Test insert and get
        cache.insert("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get("key1"), Some("value1".to_string()));
        
        // Test miss
        assert_eq!(cache.get("nonexistent"), None);
        
        // Test stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.size, 1);
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = OptimizedDHTCache::new(2, Duration::from_secs(10));
        
        // Fill cache to capacity
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());
        
        // Access key1 to make it most recent
        cache.get("key1");
        
        // Insert key3, should evict key2 (least recent)
        cache.insert("key3".to_string(), "value3".to_string());
        
        assert_eq!(cache.get("key1"), Some("value1".to_string()));
        assert_eq!(cache.get("key2"), None); // Evicted
        assert_eq!(cache.get("key3"), Some("value3".to_string()));
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let mut cache = OptimizedDHTCache::new(10, Duration::from_millis(50));
        
        // Insert with short TTL
        cache.insert_with_ttl("key1".to_string(), "value1".to_string(), Duration::from_millis(10));
        
        // Should be available immediately
        assert_eq!(cache.get("key1"), Some("value1".to_string()));
        
        // Wait for expiration
        sleep(Duration::from_millis(20)).await;
        
        // Should be expired
        assert_eq!(cache.get("key1"), None);
    }
}