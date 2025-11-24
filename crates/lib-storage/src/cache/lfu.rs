//! LFU (Least Frequently Used) Cache implementation

use std::collections::HashMap;

/// LFU Cache
pub struct LfuCache<K: Clone + Eq + std::hash::Hash, V> {
    capacity: usize,
    cache: HashMap<K, V>,
    frequency: HashMap<K, usize>,
}

impl<K: Clone + Eq + std::hash::Hash, V> LfuCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            cache: HashMap::new(),
            frequency: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.cache.contains_key(key) {
            // Increment frequency
            *self.frequency.entry(key.clone()).or_insert(0) += 1;
            self.cache.get(key)
        } else {
            None
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.cache.len() >= self.capacity && !self.cache.contains_key(&key) {
            // Find and evict least frequently used
            if let Some((lfu_key, _)) = self.frequency.iter().min_by_key(|(_, &freq)| freq) {
                let lfu_key = lfu_key.clone();
                self.cache.remove(&lfu_key);
                self.frequency.remove(&lfu_key);
            }
        }

        // Set initial frequency
        self.frequency.insert(key.clone(), 1);

        self.cache.insert(key, value)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.frequency.remove(key);
        self.cache.remove(key)
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn clear(&mut self) {
        self.cache.clear();
        self.frequency.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lfu_cache() {
        let mut cache = LfuCache::new(2);
        
        cache.insert("a", 1);
        cache.insert("b", 2);
        
        // Access "a" multiple times
        cache.get(&"a");
        cache.get(&"a");
        cache.get(&"b");
        
        cache.insert("c", 3); // Should evict "b" (lower frequency)
        
        assert_eq!(cache.get(&"b"), None);
        assert_eq!(cache.get(&"a"), Some(&1));
        assert_eq!(cache.get(&"c"), Some(&3));
    }
}
