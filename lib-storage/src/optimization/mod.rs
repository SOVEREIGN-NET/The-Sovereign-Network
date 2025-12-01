//! Storage Optimization Module
//!
//! Provides compression, deduplication, and content-defined chunking
//! to optimize storage efficiency.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

pub mod compression;
pub mod deduplication;
pub mod chunking;

// Re-export key types
pub use compression::{CompressionAlgorithm, Compressor, CompressionStats};
pub use deduplication::{Deduplicator, DedupStats, BlockReference};
pub use chunking::{ContentChunker, ChunkingAlgorithm, Chunk};

/// Optimization manager coordinating compression and deduplication
pub struct OptimizationManager {
    /// Compressor
    compressor: Compressor,
    /// Deduplicator
    deduplicator: Deduplicator,
    /// Content chunker
    chunker: ContentChunker,
    /// Overall statistics
    stats: OptimizationStats,
}

impl OptimizationManager {
    /// Create a new optimization manager
    pub fn new(
        compression_algorithm: CompressionAlgorithm,
        chunking_algorithm: ChunkingAlgorithm,
    ) -> Self {
        Self {
            compressor: Compressor::new(compression_algorithm),
            deduplicator: Deduplicator::new(),
            chunker: ContentChunker::new(chunking_algorithm),
            stats: OptimizationStats::default(),
        }
    }

    /// Optimize data for storage (chunk, deduplicate, compress)
    pub fn optimize(&mut self, data: &[u8]) -> Result<OptimizedData> {
        let original_size = data.len();

        // Step 1: Chunk the data
        let chunks = self.chunker.chunk(data)?;
        
        // Step 2: Deduplicate chunks - extract data from Chunk structs
        let chunk_data: Vec<Vec<u8>> = chunks.iter().map(|c| c.data.clone()).collect();
        let dedup_refs = self.deduplicator.deduplicate_chunks(chunk_data)?;

        // Step 3: Reconstruct unique chunks for compression
        let unique_chunks = self.deduplicator.reconstruct(&dedup_refs)?;

        // Step 4: Compress unique chunks
        let mut compressed_chunks = Vec::new();
        for chunk_data in &unique_chunks {
            let compressed = self.compressor.compress(chunk_data)?;
            compressed_chunks.push(compressed);
        }

        // Calculate final size
        let final_size = compressed_chunks.iter().map(|c| c.len()).sum();

        // Update statistics
        self.stats.total_operations += 1;
        self.stats.original_bytes += original_size;
        self.stats.final_bytes += final_size;
        self.stats.chunks_processed += chunks.len();
        self.stats.unique_chunks += unique_chunks.len();
        self.stats.duplicate_chunks += dedup_refs.len() - unique_chunks.len();

        Ok(OptimizedData {
            original_size,
            final_size,
            chunks: compressed_chunks,
            chunk_map: dedup_refs,
            compression_algorithm: self.compressor.algorithm(),
            chunking_algorithm: self.chunker.algorithm().clone(),
        })
    }

    /// Reconstruct data from optimized form
    pub fn reconstruct(&self, optimized: &OptimizedData) -> Result<Vec<u8>> {
        // Step 1: Decompress chunks
        let mut decompressed_chunks = Vec::new();
        for compressed_chunk in &optimized.chunks {
            let decompressed = self.compressor.decompress(compressed_chunk)?;
            decompressed_chunks.push(decompressed);
        }

        // Step 2: Reconstruct from block references
        let mut result = Vec::new();
        for block_ref in &optimized.chunk_map {
            // Look up chunk by hash in deduplicator
            if let Some(chunk_data) = self.deduplicator.get_chunk(&block_ref.hash) {
                result.extend_from_slice(chunk_data);
            } else {
                return Err(anyhow!("Chunk not found during reconstruction: {:?}", block_ref.hash));
            }
        }

        Ok(result)
    }

    /// Get optimization statistics
    pub fn get_stats(&self) -> &OptimizationStats {
        &self.stats
    }

    /// Get compression statistics
    pub fn get_compression_stats(&self) -> &CompressionStats {
        self.compressor.get_stats()
    }

    /// Get deduplication statistics
    pub fn get_dedup_stats(&self) -> &DedupStats {
        self.deduplicator.get_stats()
    }

    /// Calculate space savings percentage
    pub fn space_savings(&self) -> f64 {
        if self.stats.original_bytes == 0 {
            0.0
        } else {
            let saved = self.stats.original_bytes.saturating_sub(self.stats.final_bytes);
            (saved as f64 / self.stats.original_bytes as f64) * 100.0
        }
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = OptimizationStats::default();
        self.compressor.reset_stats();
        self.deduplicator.reset_stats();
    }
}

impl Default for OptimizationManager {
    fn default() -> Self {
        Self::new(
            CompressionAlgorithm::Lz4,
            ChunkingAlgorithm::Fixed { size: 4096 },
        )
    }
}

/// Optimized data representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedData {
    /// Original data size
    pub original_size: usize,
    /// Final compressed and deduplicated size
    pub final_size: usize,
    /// Compressed unique chunks
    pub chunks: Vec<Vec<u8>>,
    /// Map of block references for reconstruction
    pub chunk_map: Vec<BlockReference>,
    /// Compression algorithm used
    pub compression_algorithm: CompressionAlgorithm,
    /// Chunking algorithm used
    pub chunking_algorithm: ChunkingAlgorithm,
}

impl OptimizedData {
    /// Calculate compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            1.0
        } else {
            self.final_size as f64 / self.original_size as f64
        }
    }

    /// Calculate space savings percentage
    pub fn space_savings(&self) -> f64 {
        (1.0 - self.compression_ratio()) * 100.0
    }
}

/// Overall optimization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationStats {
    /// Total optimization operations
    pub total_operations: u64,
    /// Total original bytes processed
    pub original_bytes: usize,
    /// Total final bytes after optimization
    pub final_bytes: usize,
    /// Total chunks processed
    pub chunks_processed: usize,
    /// Total unique chunks
    pub unique_chunks: usize,
    /// Total duplicate chunks found
    pub duplicate_chunks: usize,
}

impl Default for OptimizationStats {
    fn default() -> Self {
        Self {
            total_operations: 0,
            original_bytes: 0,
            final_bytes: 0,
            chunks_processed: 0,
            unique_chunks: 0,
            duplicate_chunks: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimization_manager_creation() {
        let manager = OptimizationManager::default();
        assert_eq!(manager.get_stats().total_operations, 0);
    }

    #[test]
    fn test_optimize_and_reconstruct() {
        let mut manager = OptimizationManager::default();
        let data = b"Hello, World! This is test data. Hello, World!".to_vec();

        let optimized = manager.optimize(&data).unwrap();
        assert!(optimized.final_size > 0);

        let reconstructed = manager.reconstruct(&optimized).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_space_savings() {
        let mut manager = OptimizationManager::default();
        let data = vec![0u8; 1000]; // Highly compressible data

        manager.optimize(&data).unwrap();
        let savings = manager.space_savings();
        assert!(savings > 0.0);
    }

    #[test]
    fn test_optimized_data_metrics() {
        let optimized = OptimizedData {
            original_size: 1000,
            final_size: 500,
            chunks: vec![],
            chunk_map: vec![],
            compression_algorithm: CompressionAlgorithm::Lz4,
            chunking_algorithm: ChunkingAlgorithm::Fixed { size: 4096 },
        };

        assert_eq!(optimized.compression_ratio(), 0.5);
        assert_eq!(optimized.space_savings(), 50.0);
    }
}
