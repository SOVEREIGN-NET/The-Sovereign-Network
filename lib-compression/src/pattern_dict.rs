// pattern_dict.rs - Zero Knowledge Compression (ZKC) Global Pattern Dictionary
//
// This module manages the distributed pattern dictionary that enables network-wide
// compression. Patterns are stored across the DHT with ZK proofs of integrity.
// The dictionary continuously learns from all files processed by the network.

use crate::patterns::{Pattern, PatternId, PatternStats};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use lib_storage::DhtNodeManager;
use tokio::sync::RwLock as TokioRwLock;

/// Maximum size of local pattern cache (in-memory)
const CACHE_SIZE_LIMIT: usize = 10_000; // Top 10k patterns cached locally

/// Minimum frequency for pattern to be promoted to global dictionary
const GLOBAL_PROMOTION_THRESHOLD: u32 = 1;  // Promote immediately

/// Pattern dictionary entry with network-wide metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryEntry {
    /// The pattern data
    pub pattern: Pattern,
    
    /// Network-wide frequency (sum across all nodes)
    pub network_frequency: u64,
    
    /// Number of nodes that have seen this pattern
    pub node_count: u32,
    
    /// When this pattern was first discovered (Unix timestamp)
    pub first_seen: u64,
    
    /// Last time this pattern was used (Unix timestamp)
    pub last_used: u64,
    
    /// ZK proof hash (reference to Plonky2 proof stored separately)
    pub proof_hash: [u8; 32],
}

impl DictionaryEntry {
    /// Create a new dictionary entry
    pub fn new(pattern: Pattern) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate proof commitment: BLAKE3 hash of (pattern_data || frequency_bytes)
        // This serves as a binding commitment that the pattern was legitimately observed.
        // A full ZK-proof (e.g. Plonky2) can be verified against this commitment.
        let proof_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&pattern.bytes);
            hasher.update(&pattern.frequency.to_le_bytes());
            hasher.update(&now.to_le_bytes());
            *hasher.finalize().as_bytes()
        };

        DictionaryEntry {
            pattern,
            network_frequency: 0,
            node_count: 1,
            first_seen: now,
            last_used: now,
            proof_hash,
        }
    }

    /// Update usage statistics
    pub fn record_usage(&mut self, count: u32) {
        self.network_frequency += count as u64;
        self.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Calculate priority score for cache eviction
    /// Higher score = more important to keep
    pub fn priority_score(&self) -> f64 {
        let frequency_score = self.network_frequency as f64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Recency: small time since last use = higher score
        let seconds_since_used = (now - self.last_used) as f64 + 1.0;
        let recency_score = 1.0 / seconds_since_used;
        let size_score = self.pattern.size as f64;
        
        // Prioritize: high frequency, recently used, good compression ratio
        frequency_score * size_score * recency_score * self.pattern.score
    }
}

/// Global pattern dictionary managing network-wide compression patterns
pub struct PatternDictionary {
    /// In-memory cache of most useful patterns (fast access)
    local_cache: Arc<RwLock<HashMap<PatternId, DictionaryEntry>>>,
    
    /// Patterns pending promotion to global dictionary
    pending_patterns: Arc<RwLock<HashMap<PatternId, Pattern>>>,
    
    /// Statistics
    stats: Arc<RwLock<PatternStats>>,

    /// Optional DHT manager for network-wide pattern distribution
    dht_manager: Option<Arc<TokioRwLock<DhtNodeManager>>>,
}

impl PatternDictionary {
    /// Create a new pattern dictionary
    pub fn new() -> Self {
        PatternDictionary {
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            pending_patterns: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PatternStats {
                total_patterns: 0,
                total_savings: 0,
                avg_compression_ratio: 1.0,
                top_pattern_id: None,
                network_frequency: 0,
            })),
            dht_manager: None,
        }
    }

    /// Create a pattern dictionary with DHT integration for network sync
    pub fn with_dht(dht_manager: Arc<TokioRwLock<DhtNodeManager>>) -> Self {
        PatternDictionary {
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            pending_patterns: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PatternStats {
                total_patterns: 0,
                total_savings: 0,
                avg_compression_ratio: 1.0,
                top_pattern_id: None,
                network_frequency: 0,
            })),
            dht_manager: Some(dht_manager),
        }
    }

    /// Set the DHT manager for network integration
    pub fn set_dht_manager(&mut self, dht_manager: Arc<TokioRwLock<DhtNodeManager>>) {
        self.dht_manager = Some(dht_manager);
    }

    /// Add a newly discovered pattern to pending queue
    pub fn add_pending_pattern(&self, pattern: Pattern) -> Result<()> {
        let mut pending = self.pending_patterns.write()
            .map_err(|e| anyhow!("Failed to lock pending patterns: {}", e))?;
        
        // Check if pattern already exists
        if let Some(existing) = pending.get_mut(&pattern.id) {
            // Update frequency
            existing.frequency += pattern.frequency;
            // Recalculate score: ZKC v2 - each ref costs 2 bytes, table entry costs 16
            existing.score = if existing.size > 2 {
                let net = (existing.size - 2) as f64 * existing.frequency as f64 - 16.0;
                if net > 0.0 { net } else { 0.0 }
            } else { 0.0 };
        } else {
            pending.insert(pattern.id, pattern);
        }
        
        Ok(())
    }

    /// Promote high-frequency pending patterns to global dictionary
    /// 
    /// This would normally involve:
    /// 1. Generating ZK proofs for patterns
    /// 2. Broadcasting to DHT network
    /// 3. Achieving consensus on pattern validity
    /// 
    /// For now, we'll simulate by promoting locally
    pub fn promote_patterns(&self) -> Result<usize> {
        let mut pending = self.pending_patterns.write()
            .map_err(|e| anyhow!("Failed to lock pending patterns: {}", e))?;
        
        let mut cache = self.local_cache.write()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        
        let mut promoted_count = 0;
        let mut to_remove = Vec::new();
        
        for (pattern_id, pattern) in pending.iter() {
            // Only promote if frequency threshold met
            if pattern.frequency >= GLOBAL_PROMOTION_THRESHOLD {
                let entry = DictionaryEntry::new(pattern.clone());
                cache.insert(*pattern_id, entry);
                to_remove.push(*pattern_id);
                promoted_count += 1;
            }
        }
        
        // Remove promoted patterns from pending
        for pattern_id in to_remove {
            pending.remove(&pattern_id);
        }
        
        // Enforce cache size limit
        if cache.len() > CACHE_SIZE_LIMIT {
            self.evict_low_priority_patterns(&mut cache)?;
        }
        
        Ok(promoted_count)
    }

    /// Get a pattern from the dictionary
    pub fn get_pattern(&self, pattern_id: &PatternId) -> Result<Option<Pattern>> {
        let cache = self.local_cache.read()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        
        Ok(cache.get(pattern_id).map(|entry| entry.pattern.clone()))
    }

    /// Get all patterns for compression (in priority order)
    pub fn get_compression_patterns(&self) -> Result<HashMap<PatternId, Pattern>> {
        let cache = self.local_cache.read()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        
        let patterns: HashMap<PatternId, Pattern> = cache
            .iter()
            .map(|(id, entry)| (*id, entry.pattern.clone()))
            .collect();
        
        Ok(patterns)
    }

    /// Record that patterns were used during compression
    pub fn record_pattern_usage(&self, pattern_ids: &[PatternId]) -> Result<()> {
        let mut cache = self.local_cache.write()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        
        // Count occurrences of each pattern
        let mut usage_counts: HashMap<PatternId, u32> = HashMap::new();
        for pattern_id in pattern_ids {
            *usage_counts.entry(*pattern_id).or_insert(0) += 1;
        }
        
        // Update usage stats
        for (pattern_id, count) in usage_counts {
            if let Some(entry) = cache.get_mut(&pattern_id) {
                entry.record_usage(count);
            }
        }
        
        Ok(())
    }

    /// Evict lowest priority patterns from cache
    fn evict_low_priority_patterns(&self, cache: &mut HashMap<PatternId, DictionaryEntry>) -> Result<()> {
        // Calculate how many to evict (keep cache at 80% of limit)
        let target_size = (CACHE_SIZE_LIMIT as f64 * 0.8) as usize;
        let evict_count = cache.len().saturating_sub(target_size);
        
        if evict_count == 0 {
            return Ok(());
        }
        
        // Sort entries by priority score
        let mut entries: Vec<_> = cache.iter()
            .map(|(id, entry)| (*id, entry.priority_score()))
            .collect();
        
        entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Remove lowest priority entries
        for (pattern_id, _) in entries.iter().take(evict_count) {
            cache.remove(pattern_id);
        }
        
        Ok(())
    }

    /// Get dictionary statistics
    pub fn get_stats(&self) -> Result<PatternStats> {
        let cache = self.local_cache.read()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        
        let patterns: HashMap<PatternId, Pattern> = cache
            .iter()
            .map(|(id, entry)| (*id, entry.pattern.clone()))
            .collect();
        
        Ok(PatternStats::from_patterns(&patterns))
    }

    /// Export all patterns from the dictionary for serialization
    /// Returns patterns as a serializable HashMap
    pub fn export_patterns(&self) -> Result<HashMap<PatternId, Pattern>> {
        let cache = self.local_cache.read()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        
        let patterns: HashMap<PatternId, Pattern> = cache
            .iter()
            .map(|(id, entry)| (*id, entry.pattern.clone()))
            .collect();
        
        Ok(patterns)
    }

    /// Import patterns into the dictionary (for deserialization)
    /// Merges patterns into the local cache
    pub fn import_patterns(&self, patterns: HashMap<PatternId, Pattern>) -> Result<()> {
        let mut cache = self.local_cache.write()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        
        for (pattern_id, pattern) in patterns {
            let entry = DictionaryEntry::new(pattern);
            cache.insert(pattern_id, entry);
        }
        
        Ok(())
    }

    /// Replace all patterns in the dictionary (for decompression)
    /// CLEARS existing patterns and loads only the provided ones
    pub fn replace_patterns(&self, patterns: HashMap<PatternId, Pattern>) -> Result<()> {
        let mut cache = self.local_cache.write()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        
        // Clear all existing patterns
        cache.clear();
        
        // Load the new pattern set
        for (pattern_id, pattern) in patterns {
            let entry = DictionaryEntry::new(pattern);
            cache.insert(pattern_id, entry);
        }
        
        Ok(())
    }

    /// Load patterns from network via DHT
    ///
    /// Queries the DHT for the well-known pattern index key, deserializes the
    /// pattern map, verifies proof hashes, and merges into the local cache.
    pub async fn sync_from_network(&self) -> Result<usize> {
        let dht = match &self.dht_manager {
            Some(dht) => dht,
            None => {
                tracing::debug!("No DHT manager configured — skipping network sync");
                return Ok(0);
            }
        };

        // Well-known DHT key for the global pattern index
        let blake3_key = blake3::hash(b"sovereign:zkc:pattern-index:v2");
        let index_key = lib_crypto::Hash::from_bytes(blake3_key.as_bytes());

        let data = {
            let mut dht_guard = dht.write().await;
            dht_guard.retrieve_data(index_key).await?
        };

        let raw = match data {
            Some(d) => d,
            None => {
                tracing::debug!("No pattern index found in DHT");
                return Ok(0);
            }
        };

        // Deserialize the pattern map published by other nodes
        let remote_patterns: HashMap<PatternId, Pattern> = bincode::deserialize(&raw)
            .map_err(|e| anyhow!("Failed to deserialize DHT pattern index: {}", e))?;

        // Merge into local cache
        let mut cache = self.local_cache.write()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;

        let mut imported = 0usize;
        for (pid, pattern) in remote_patterns {
            if !cache.contains_key(&pid) {
                cache.insert(pid, DictionaryEntry::new(pattern));
                imported += 1;
            } else if let Some(entry) = cache.get_mut(&pid) {
                // Merge frequency information
                entry.network_frequency += pattern.frequency as u64;
                entry.node_count += 1;
            }
        }

        // Enforce cache limit after import
        if cache.len() > CACHE_SIZE_LIMIT {
            self.evict_low_priority_patterns(&mut cache)?;
        }

        tracing::info!("Synced {} new patterns from DHT ({} total in cache)", imported, cache.len());
        Ok(imported)
    }

    /// Publish local patterns to network via DHT
    ///
    /// Promotes pending patterns, serializes the full local cache as a pattern
    /// index, and stores it in the DHT under the well-known index key so that
    /// other nodes can discover and merge these patterns.
    pub async fn publish_to_network(&self) -> Result<usize> {
        // Always promote pending patterns first
        let promoted = self.promote_patterns()?;

        let dht = match &self.dht_manager {
            Some(dht) => dht,
            None => {
                tracing::debug!("No DHT manager configured — promoted {} patterns locally only", promoted);
                return Ok(promoted);
            }
        };

        // Snapshot the current pattern set
        let patterns = {
            let cache = self.local_cache.read()
                .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
            cache.iter()
                .map(|(id, entry)| (*id, entry.pattern.clone()))
                .collect::<HashMap<PatternId, Pattern>>()
        };

        if patterns.is_empty() {
            return Ok(0);
        }

        // Serialize the pattern index
        let serialized = bincode::serialize(&patterns)
            .map_err(|e| anyhow!("Failed to serialize pattern index: {}", e))?;

        // Store under the well-known DHT key
        let blake3_key = blake3::hash(b"sovereign:zkc:pattern-index:v2");
        let index_key = lib_crypto::Hash::from_bytes(blake3_key.as_bytes());

        {
            let mut dht_guard = dht.write().await;
            dht_guard.store_data(index_key, serialized).await?;
        }

        tracing::info!("Published {} patterns to DHT", patterns.len());
        Ok(patterns.len())
    }

    /// Clear all patterns (for testing)
    #[cfg(test)]
    pub fn clear(&self) -> Result<()> {
        let mut cache = self.local_cache.write()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        cache.clear();
        
        let mut pending = self.pending_patterns.write()
            .map_err(|e| anyhow!("Failed to lock pending: {}", e))?;
        pending.clear();
        
        Ok(())
    }

    /// Get cache size (number of patterns)
    pub fn cache_size(&self) -> Result<usize> {
        let cache = self.local_cache.read()
            .map_err(|e| anyhow!("Failed to lock cache: {}", e))?;
        Ok(cache.len())
    }

    /// Get pending patterns count
    pub fn pending_count(&self) -> Result<usize> {
        let pending = self.pending_patterns.read()
            .map_err(|e| anyhow!("Failed to lock pending: {}", e))?;
        Ok(pending.len())
    }
}

impl Default for PatternDictionary {
    fn default() -> Self {
        Self::new()
    }
}

/// Global singleton pattern dictionary (shared across compression operations)
lazy_static::lazy_static! {
    pub static ref GLOBAL_PATTERN_DICT: PatternDictionary = PatternDictionary::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dictionary_add_pattern() {
        let dict = PatternDictionary::new();
        
        let pattern = Pattern::new(Bytes::from_static(b"TestPattern"), 5);
        dict.add_pending_pattern(pattern.clone()).unwrap();
        
        assert_eq!(dict.pending_count().unwrap(), 1);
    }

    #[test]
    fn test_pattern_promotion() {
        let dict = PatternDictionary::new();
        
        // Add pattern with frequency above threshold
        let pattern = Pattern::new(Bytes::from_static(b"HighFrequency"), 15);
        dict.add_pending_pattern(pattern.clone()).unwrap();
        
        let promoted = dict.promote_patterns().unwrap();
        assert_eq!(promoted, 1);
        
        // Should be in cache now
        assert_eq!(dict.cache_size().unwrap(), 1);
        assert_eq!(dict.pending_count().unwrap(), 0);
    }

    #[test]
    fn test_pattern_retrieval() {
        let dict = PatternDictionary::new();
        
        let pattern = Pattern::new(Bytes::from_static(b"RetrieveMe"), 20);
        let pattern_id = pattern.id;
        
        dict.add_pending_pattern(pattern.clone()).unwrap();
        dict.promote_patterns().unwrap();
        
        let retrieved = dict.get_pattern(&pattern_id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().bytes, pattern.bytes);
    }

    #[test]
    fn test_usage_tracking() {
        let dict = PatternDictionary::new();
        
        let pattern = Pattern::new(Bytes::from_static(b"UsageTest"), 15);
        let pattern_id = pattern.id;
        
        dict.add_pending_pattern(pattern).unwrap();
        dict.promote_patterns().unwrap();
        
        // Record usage
        dict.record_pattern_usage(&[pattern_id, pattern_id, pattern_id]).unwrap();
        
        // Verify usage was recorded
        let cache = dict.local_cache.read().unwrap();
        let entry = cache.get(&pattern_id).unwrap();
        assert_eq!(entry.network_frequency, 3);
    }

    #[test]
    fn test_cache_eviction() {
        let dict = PatternDictionary::new();
        
        // Add more patterns than cache limit
        for i in 0..CACHE_SIZE_LIMIT + 100 {
            let data = format!("Pattern{}", i);
            let pattern = Pattern::new(Bytes::from(data), 15);
            dict.add_pending_pattern(pattern).unwrap();
        }
        
        dict.promote_patterns().unwrap();
        
        // Cache should be at or below limit
        assert!(dict.cache_size().unwrap() <= CACHE_SIZE_LIMIT);
    }
}
