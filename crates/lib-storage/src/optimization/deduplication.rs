//! Content deduplication

use anyhow::Result;
use lib_crypto::hashing::hash_blake3;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Content-based deduplicator
pub struct Deduplicator {
    /// Map from chunk hash to chunk data
    chunk_store: HashMap<[u8; 32], Vec<u8>>,
    /// Statistics
    stats: DedupStats,
}

impl Deduplicator {
    pub fn new() -> Self {
        Self {
            chunk_store: HashMap::new(),
            stats: DedupStats::default(),
        }
    }

    /// Deduplicate chunks, returns block references
    pub fn deduplicate_chunks(&mut self, chunks: Vec<Vec<u8>>) -> Result<Vec<BlockReference>> {
        let mut references = Vec::new();

        for chunk in chunks {
            let hash = hash_blake3(&chunk);
            
            // Check if chunk exists
            if self.chunk_store.contains_key(&hash) {
                // Duplicate found
                self.stats.duplicate_chunks += 1;
                self.stats.bytes_saved += chunk.len();
            } else {
                // New chunk
                self.stats.unique_chunks += 1;
                self.stats.bytes_stored += chunk.len();
                self.chunk_store.insert(hash, chunk.clone());
            }

            self.stats.total_chunks += 1;

            references.push(BlockReference {
                hash,
                size: chunk.len(),
            });
        }

        Ok(references)
    }

    /// Reconstruct content from block references
    pub fn reconstruct(&self, references: &[BlockReference]) -> Result<Vec<Vec<u8>>> {
        let mut chunks = Vec::new();

        for reference in references {
            if let Some(chunk) = self.chunk_store.get(&reference.hash) {
                chunks.push(chunk.clone());
            } else {
                return Err(anyhow::anyhow!("Chunk not found: {:?}", reference.hash));
            }
        }

        Ok(chunks)
    }

    /// Get stored chunk by hash
    pub fn get_chunk(&self, hash: &[u8; 32]) -> Option<&Vec<u8>> {
        self.chunk_store.get(hash)
    }

    /// Check if chunk exists
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.chunk_store.contains_key(hash)
    }

    /// Remove a chunk
    pub fn remove_chunk(&mut self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.chunk_store.remove(hash)
    }

    /// Get number of stored chunks
    pub fn chunk_count(&self) -> usize {
        self.chunk_store.len()
    }

    /// Get deduplication statistics
    pub fn get_stats(&self) -> &DedupStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = DedupStats::default();
    }

    /// Clear all stored chunks
    pub fn clear(&mut self) {
        self.chunk_store.clear();
    }

    /// Calculate deduplication ratio
    pub fn dedup_ratio(&self) -> f64 {
        if self.stats.total_chunks == 0 {
            0.0
        } else {
            self.stats.duplicate_chunks as f64 / self.stats.total_chunks as f64
        }
    }

    /// Calculate space savings percentage
    pub fn space_savings_percentage(&self) -> f64 {
        self.dedup_ratio() * 100.0
    }
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self::new()
    }
}

/// Reference to a deduplicated block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockReference {
    pub hash: [u8; 32],
    pub size: usize,
}

/// Deduplication statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DedupStats {
    pub total_chunks: u64,
    pub unique_chunks: u64,
    pub duplicate_chunks: u64,
    pub bytes_stored: usize,
    pub bytes_saved: usize,
}

impl DedupStats {
    pub fn dedup_ratio(&self) -> f64 {
        if self.total_chunks == 0 {
            0.0
        } else {
            self.duplicate_chunks as f64 / self.total_chunks as f64
        }
    }

    pub fn space_savings(&self) -> f64 {
        self.dedup_ratio() * 100.0
    }

    pub fn effective_storage_ratio(&self) -> f64 {
        if self.bytes_stored + self.bytes_saved == 0 {
            1.0
        } else {
            self.bytes_stored as f64 / (self.bytes_stored + self.bytes_saved) as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplication() {
        let mut dedup = Deduplicator::new();

        let chunk1 = b"test chunk 1".to_vec();
        let chunk2 = b"test chunk 2".to_vec();
        let chunk3 = b"test chunk 1".to_vec(); // Duplicate of chunk1

        let chunks = vec![chunk1.clone(), chunk2.clone(), chunk3.clone()];
        let refs = dedup.deduplicate_chunks(chunks).unwrap();

        assert_eq!(refs.len(), 3);
        assert_eq!(dedup.chunk_count(), 2); // Only 2 unique chunks
        assert_eq!(refs[0].hash, refs[2].hash); // Same hash for duplicates
    }

    #[test]
    fn test_reconstruct() {
        let mut dedup = Deduplicator::new();

        let chunks = vec![
            b"chunk1".to_vec(),
            b"chunk2".to_vec(),
            b"chunk1".to_vec(),
        ];

        let refs = dedup.deduplicate_chunks(chunks.clone()).unwrap();
        let reconstructed = dedup.reconstruct(&refs).unwrap();

        assert_eq!(reconstructed.len(), 3);
        assert_eq!(reconstructed[0], b"chunk1");
        assert_eq!(reconstructed[1], b"chunk2");
        assert_eq!(reconstructed[2], b"chunk1");
    }

    #[test]
    fn test_dedup_stats() {
        let mut dedup = Deduplicator::new();

        let chunks = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"a".to_vec(),
            b"c".to_vec(),
        ];

        dedup.deduplicate_chunks(chunks).unwrap();

        let stats = dedup.get_stats();
        assert_eq!(stats.total_chunks, 4);
        assert_eq!(stats.unique_chunks, 3);
        assert_eq!(stats.duplicate_chunks, 1);
    }
}
