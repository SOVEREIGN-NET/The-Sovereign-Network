//! Cache coherency management for distributed caching

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache coherency protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoherencyProtocol {
    /// Write-through: writes go to cache and storage immediately
    WriteThrough,
    /// Write-back: writes go to cache, storage updated later
    WriteBack,
    /// Write-around: writes bypass cache, go directly to storage
    WriteAround,
}

/// Cache entry state for coherency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheEntryState {
    /// Clean - matches backing store
    Clean,
    /// Dirty - modified, needs writeback
    Dirty,
    /// Invalid - needs refresh from backing store
    Invalid,
}

/// Cache coherency manager
pub struct CacheCoherencyManager {
    /// Entry states
    entry_states: HashMap<String, CacheEntryState>,
    /// Last modification times
    modification_times: HashMap<String, u64>,
    /// Protocol to use
    protocol: CoherencyProtocol,
    /// Writeback queue for write-back protocol
    writeback_queue: Vec<String>,
}

impl CacheCoherencyManager {
    pub fn new(protocol: CoherencyProtocol) -> Self {
        Self {
            entry_states: HashMap::new(),
            modification_times: HashMap::new(),
            protocol,
            writeback_queue: Vec::new(),
        }
    }

    /// Mark entry as accessed
    pub fn on_read(&mut self, key: &str) {
        // For read, just ensure entry is not invalid
        if let Some(state) = self.entry_states.get(key) {
            if *state == CacheEntryState::Invalid {
                // Entry needs refresh
                // In practice, this would trigger a reload
            }
        }
    }

    /// Mark entry as written
    pub fn on_write(&mut self, key: String) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match self.protocol {
            CoherencyProtocol::WriteThrough => {
                // Mark as clean since write goes through to storage
                self.entry_states.insert(key.clone(), CacheEntryState::Clean);
            }
            CoherencyProtocol::WriteBack => {
                // Mark as dirty and add to writeback queue
                self.entry_states.insert(key.clone(), CacheEntryState::Dirty);
                if !self.writeback_queue.contains(&key) {
                    self.writeback_queue.push(key.clone());
                }
            }
            CoherencyProtocol::WriteAround => {
                // Invalidate cache entry since write bypasses cache
                self.entry_states.insert(key.clone(), CacheEntryState::Invalid);
            }
        }

        self.modification_times.insert(key, now);
    }

    /// Invalidate an entry
    pub fn invalidate(&mut self, key: &str) {
        self.entry_states.insert(key.to_string(), CacheEntryState::Invalid);
    }

    /// Get entries needing writeback
    pub fn get_writeback_queue(&self) -> &[String] {
        &self.writeback_queue
    }

    /// Mark entry as written back
    pub fn mark_written_back(&mut self, key: &str) {
        self.entry_states.insert(key.to_string(), CacheEntryState::Clean);
        self.writeback_queue.retain(|k| k != key);
    }

    /// Get entry state
    pub fn get_state(&self, key: &str) -> CacheEntryState {
        self.entry_states
            .get(key)
            .copied()
            .unwrap_or(CacheEntryState::Clean)
    }

    /// Check if entry is dirty
    pub fn is_dirty(&self, key: &str) -> bool {
        matches!(self.get_state(key), CacheEntryState::Dirty)
    }

    /// Get all dirty entries
    pub fn get_dirty_entries(&self) -> Vec<String> {
        self.entry_states
            .iter()
            .filter(|(_, &state)| state == CacheEntryState::Dirty)
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Flush all dirty entries
    pub fn flush_all(&mut self) -> Vec<String> {
        let dirty = self.get_dirty_entries();
        for key in &dirty {
            self.mark_written_back(key);
        }
        dirty
    }
}

impl Default for CacheCoherencyManager {
    fn default() -> Self {
        Self::new(CoherencyProtocol::WriteThrough)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_through() {
        let mut manager = CacheCoherencyManager::new(CoherencyProtocol::WriteThrough);
        
        manager.on_write("key1".to_string());
        
        assert_eq!(manager.get_state("key1"), CacheEntryState::Clean);
        assert!(!manager.is_dirty("key1"));
    }

    #[test]
    fn test_write_back() {
        let mut manager = CacheCoherencyManager::new(CoherencyProtocol::WriteBack);
        
        manager.on_write("key1".to_string());
        
        assert_eq!(manager.get_state("key1"), CacheEntryState::Dirty);
        assert!(manager.is_dirty("key1"));
        assert_eq!(manager.get_writeback_queue().len(), 1);
    }

    #[test]
    fn test_flush_all() {
        let mut manager = CacheCoherencyManager::new(CoherencyProtocol::WriteBack);
        
        manager.on_write("key1".to_string());
        manager.on_write("key2".to_string());
        
        let dirty = manager.flush_all();
        assert_eq!(dirty.len(), 2);
        assert!(!manager.is_dirty("key1"));
        assert!(!manager.is_dirty("key2"));
    }
}
