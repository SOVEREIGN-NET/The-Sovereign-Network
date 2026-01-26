//! Blockchain chunk buffer for reassembly with duplicate detection

use std::collections::{HashMap, HashSet};
use std::time::Instant;
use lib_crypto::PublicKey;

/// Buffer for reassembling blockchain chunks with security tracking
#[derive(Debug)]
pub(crate) struct BlockchainChunkBuffer {
    pub(crate) chunks: HashMap<u32, Vec<u8>>,
    pub(crate) total_chunks: u32,
    /// Hash used for verification after reassembly (Blake3)
    pub(crate) complete_data_hash: [u8; 32],
    /// Original requester for validation during chunk receipt
    pub(crate) requester: PublicKey,
    pub(crate) created_at: Instant,
    pub(crate) total_bytes: usize,
    /// Track received chunk indices to detect duplicates
    received_indices: HashSet<u32>,
}

impl BlockchainChunkBuffer {
    pub(crate) fn new(
        total_chunks: u32,
        complete_data_hash: [u8; 32],
        requester: PublicKey,
    ) -> Self {
        Self {
            chunks: HashMap::new(),
            total_chunks,
            complete_data_hash,
            requester,
            created_at: Instant::now(),
            total_bytes: 0,
            received_indices: HashSet::new(),
        }
    }

    /// Check if a chunk has already been received (duplicate detection)
    pub(crate) fn has_chunk(&self, chunk_index: u32) -> bool {
        self.received_indices.contains(&chunk_index)
    }

    /// Add a chunk and track it for duplicate detection
    pub(crate) fn add_chunk(&mut self, chunk_index: u32, data: Vec<u8>) {
        self.chunks.insert(chunk_index, data);
        self.received_indices.insert(chunk_index);
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.chunks.len() as u32 == self.total_chunks
    }

    pub(crate) fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Get missing chunk indices (for recovery/resume)
    #[allow(dead_code)]
    pub(crate) fn get_missing_chunks(&self) -> Vec<u32> {
        (0..self.total_chunks)
            .filter(|i| !self.received_indices.contains(i))
            .collect()
    }

    /// Get progress percentage
    #[allow(dead_code)]
    pub(crate) fn progress_percent(&self) -> f64 {
        if self.total_chunks == 0 {
            0.0
        } else {
            (self.chunks.len() as f64 / self.total_chunks as f64) * 100.0
        }
    }
}
