//! Blockchain chunk buffer for reassembly
//!
//! Buffers received chunks until complete, with timeout and size tracking.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use lib_crypto::PublicKey;

/// Buffer for reassembling blockchain chunks
#[derive(Debug)]
pub struct BlockchainChunkBuffer {
    /// Received chunks indexed by chunk_index
    pub chunks: HashMap<u32, Vec<u8>>,
    /// Total expected chunks
    pub total_chunks: u32,
    /// Hash of complete data for verification
    pub complete_data_hash: [u8; 32],
    /// Original requester for sender validation
    pub requester: PublicKey,
    /// When buffer was created (for timeout)
    pub created_at: Instant,
    /// Total bytes received so far
    pub total_bytes: usize,
}

impl BlockchainChunkBuffer {
    pub fn new(
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

    /// Check if all chunks received
    pub fn is_complete(&self) -> bool {
        self.chunks.len() as u32 == self.total_chunks
    }

    /// Get age of buffer
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Add a chunk to the buffer
    pub fn add_chunk(&mut self, chunk_index: u32, data: Vec<u8>) {
        self.total_bytes += data.len();
        self.chunks.insert(chunk_index, data);
    }

    /// Reassemble chunks in order
    pub fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let mut complete_data = Vec::with_capacity(self.total_bytes);
        for i in 0..self.total_chunks {
            if let Some(chunk) = self.chunks.get(&i) {
                complete_data.extend_from_slice(chunk);
            } else {
                return None;
            }
        }

        Some(complete_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_buffer_creation() {
        let buffer = BlockchainChunkBuffer::new(
            3,
            [0u8; 32],
            PublicKey::new(vec![1, 2, 3]),
        );

        assert_eq!(buffer.total_chunks, 3);
        assert!(!buffer.is_complete());
        assert_eq!(buffer.total_bytes, 0);
    }

    #[test]
    fn test_chunk_buffer_add_and_complete() {
        let mut buffer = BlockchainChunkBuffer::new(
            3,
            [0u8; 32],
            PublicKey::new(vec![1, 2, 3]),
        );

        buffer.add_chunk(0, vec![1, 2, 3]);
        assert!(!buffer.is_complete());

        buffer.add_chunk(1, vec![4, 5, 6]);
        assert!(!buffer.is_complete());

        buffer.add_chunk(2, vec![7, 8, 9]);
        assert!(buffer.is_complete());
        assert_eq!(buffer.total_bytes, 9);
    }

    #[test]
    fn test_chunk_buffer_reassemble() {
        let mut buffer = BlockchainChunkBuffer::new(
            3,
            [0u8; 32],
            PublicKey::new(vec![1, 2, 3]),
        );

        buffer.add_chunk(0, vec![1, 2, 3]);
        buffer.add_chunk(1, vec![4, 5, 6]);
        buffer.add_chunk(2, vec![7, 8, 9]);

        let data = buffer.reassemble().unwrap();
        assert_eq!(data, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_chunk_buffer_reassemble_incomplete() {
        let mut buffer = BlockchainChunkBuffer::new(
            3,
            [0u8; 32],
            PublicKey::new(vec![1, 2, 3]),
        );

        buffer.add_chunk(0, vec![1, 2, 3]);
        buffer.add_chunk(2, vec![7, 8, 9]);
        // Missing chunk 1

        assert!(buffer.reassemble().is_none());
    }
}
