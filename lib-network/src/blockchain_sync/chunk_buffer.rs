//! Blockchain chunk buffer for reassembly

use std::collections::HashMap;
use std::time::Instant;
use lib_crypto::PublicKey;

/// Buffer for reassembling blockchain chunks
#[derive(Debug)]
pub(crate) struct BlockchainChunkBuffer {
    pub(crate) chunks: HashMap<u32, Vec<u8>>,
    pub(crate) total_chunks: u32,
    /// Hash used for verification after reassembly (sync_manager.rs:239)
    pub(crate) complete_data_hash: [u8; 32],
    /// Original requester for validation during chunk receipt
    pub(crate) requester: PublicKey,
    pub(crate) created_at: Instant,
    pub(crate) total_bytes: usize,
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
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.chunks.len() as u32 == self.total_chunks
    }

    pub(crate) fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}
