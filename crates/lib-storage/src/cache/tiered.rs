//! Tiered cache system (hot/warm/cold)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cache tier levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheTier {
    /// Hot tier - frequently accessed, in-memory
    Hot,
    /// Warm tier - moderately accessed, fast storage
    Warm,
    /// Cold tier - rarely accessed, slower storage
    Cold,
}

/// Tiered cache manager
pub struct TieredCache {
    /// Hot tier (in-memory)
    hot_cache: HashMap<String, Vec<u8>>,
    /// Warm tier
    warm_cache: HashMap<String, Vec<u8>>,
    /// Cold tier
    cold_cache: HashMap<String, Vec<u8>>,
    /// Maximum size per tier in bytes
    hot_max_size: usize,
    warm_max_size: usize,
    cold_max_size: usize,
    /// Current sizes
    hot_size: usize,
    warm_size: usize,
    cold_size: usize,
    /// Access tracking
    access_counts: HashMap<String, u64>,
    /// Promotion/demotion thresholds
    hot_threshold: u64,
    warm_threshold: u64,
}

impl TieredCache {
    pub fn new(hot_max: usize, warm_max: usize, cold_max: usize) -> Self {
        Self {
            hot_cache: HashMap::new(),
            warm_cache: HashMap::new(),
            cold_cache: HashMap::new(),
            hot_max_size: hot_max,
            warm_max_size: warm_max,
            cold_max_size: cold_max,
            hot_size: 0,
            warm_size: 0,
            cold_size: 0,
            access_counts: HashMap::new(),
            hot_threshold: 10,   // Promote to hot after 10 accesses
            warm_threshold: 3,   // Promote to warm after 3 accesses
        }
    }

    /// Insert data into appropriate tier
    pub fn insert(&mut self, key: String, data: Vec<u8>) {
        let _size = data.len();
        let access_count = *self.access_counts.get(&key).unwrap_or(&0);

        // Determine tier based on access count
        if access_count >= self.hot_threshold {
            self.insert_hot(key, data);
        } else if access_count >= self.warm_threshold {
            self.insert_warm(key, data);
        } else {
            self.insert_cold(key, data);
        }
    }

    /// Get data and potentially promote tier
    pub fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        // Increment access count
        *self.access_counts.entry(key.to_string()).or_insert(0) += 1;
        let access_count = *self.access_counts.get(key).unwrap();

        // Check hot tier first
        if let Some(data) = self.hot_cache.get(key) {
            return Some(data.clone());
        }

        // Check warm tier
        if let Some(data) = self.warm_cache.remove(key) {
            let data_clone = data.clone();
            self.warm_size -= data.len();

            // Promote to hot if threshold met
            if access_count >= self.hot_threshold {
                self.insert_hot(key.to_string(), data);
            } else {
                self.warm_cache.insert(key.to_string(), data);
            }
            return Some(data_clone);
        }

        // Check cold tier
        if let Some(data) = self.cold_cache.remove(key) {
            let data_clone = data.clone();
            self.cold_size -= data.len();

            // Promote to appropriate tier
            if access_count >= self.hot_threshold {
                self.insert_hot(key.to_string(), data);
            } else if access_count >= self.warm_threshold {
                self.insert_warm(key.to_string(), data);
            } else {
                self.cold_cache.insert(key.to_string(), data);
            }
            return Some(data_clone);
        }

        None
    }

    fn insert_hot(&mut self, key: String, data: Vec<u8>) {
        // Remove from other tiers
        self.remove_from_tier(&key);

        let size = data.len();
        if self.hot_size + size > self.hot_max_size {
            // Demote some hot entries to warm
            self.demote_from_hot();
        }

        self.hot_cache.insert(key, data);
        self.hot_size += size;
    }

    fn insert_warm(&mut self, key: String, data: Vec<u8>) {
        self.remove_from_tier(&key);

        let size = data.len();
        if self.warm_size + size > self.warm_max_size {
            self.demote_from_warm();
        }

        self.warm_cache.insert(key, data);
        self.warm_size += size;
    }

    fn insert_cold(&mut self, key: String, data: Vec<u8>) {
        self.remove_from_tier(&key);

        let size = data.len();
        if self.cold_size + size > self.cold_max_size {
            self.evict_from_cold();
        }

        self.cold_cache.insert(key, data);
        self.cold_size += size;
    }

    fn remove_from_tier(&mut self, key: &str) {
        if let Some(data) = self.hot_cache.remove(key) {
            self.hot_size -= data.len();
        }
        if let Some(data) = self.warm_cache.remove(key) {
            self.warm_size -= data.len();
        }
        if let Some(data) = self.cold_cache.remove(key) {
            self.cold_size -= data.len();
        }
    }

    fn demote_from_hot(&mut self) {
        if let Some((key, data)) = self.hot_cache.iter().next() {
            let key = key.clone();
            let data = data.clone();
            self.hot_cache.remove(&key);
            self.hot_size -= data.len();
            self.insert_warm(key, data);
        }
    }

    fn demote_from_warm(&mut self) {
        if let Some((key, data)) = self.warm_cache.iter().next() {
            let key = key.clone();
            let data = data.clone();
            self.warm_cache.remove(&key);
            self.warm_size -= data.len();
            self.insert_cold(key, data);
        }
    }

    fn evict_from_cold(&mut self) {
        if let Some((key, data)) = self.cold_cache.iter().next() {
            let key = key.clone();
            self.cold_size -= data.len();
            self.cold_cache.remove(&key);
            self.access_counts.remove(&key);
        }
    }

    pub fn get_tier_stats(&self) -> TierStats {
        TierStats {
            hot_entries: self.hot_cache.len(),
            warm_entries: self.warm_cache.len(),
            cold_entries: self.cold_cache.len(),
            hot_size: self.hot_size,
            warm_size: self.warm_size,
            cold_size: self.cold_size,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TierStats {
    pub hot_entries: usize,
    pub warm_entries: usize,
    pub cold_entries: usize,
    pub hot_size: usize,
    pub warm_size: usize,
    pub cold_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tiered_cache() {
        let mut cache = TieredCache::new(100, 200, 300);
        
        cache.insert("key1".to_string(), vec![1, 2, 3]);
        
        // Access multiple times to promote
        for _ in 0..15 {
            cache.get("key1");
        }
        
        let stats = cache.get_tier_stats();
        assert_eq!(stats.hot_entries, 1);
    }
}
