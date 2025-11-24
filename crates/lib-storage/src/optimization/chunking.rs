//! Content-defined chunking algorithms

use anyhow::Result;
use lib_crypto::hashing::hash_blake3;
use serde::{Deserialize, Serialize};

/// Chunking algorithm types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkingAlgorithm {
    /// Fixed-size chunks
    Fixed { size: usize },
    /// Content-defined chunking using Rabin fingerprinting
    ContentDefined {
        min_size: usize,
        avg_size: usize,
        max_size: usize,
    },
}

impl Default for ChunkingAlgorithm {
    fn default() -> Self {
        Self::ContentDefined {
            min_size: 4096,
            avg_size: 8192,
            max_size: 16384,
        }
    }
}

/// Content chunker
pub struct ContentChunker {
    algorithm: ChunkingAlgorithm,
}

impl ContentChunker {
    pub fn new(algorithm: ChunkingAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Chunk data into smaller pieces
    pub fn chunk(&self, data: &[u8]) -> Result<Vec<Chunk>> {
        match &self.algorithm {
            ChunkingAlgorithm::Fixed { size } => self.chunk_fixed(data, *size),
            ChunkingAlgorithm::ContentDefined {
                min_size,
                avg_size,
                max_size,
            } => self.chunk_content_defined(data, *min_size, *avg_size, *max_size),
        }
    }

    /// Fixed-size chunking
    fn chunk_fixed(&self, data: &[u8], size: usize) -> Result<Vec<Chunk>> {
        let mut chunks = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = std::cmp::min(offset + size, data.len());
            let chunk_data = data[offset..end].to_vec();
            let hash = hash_blake3(&chunk_data);

            chunks.push(Chunk {
                hash,
                data: chunk_data,
                offset,
            });

            offset = end;
        }

        Ok(chunks)
    }

    /// Content-defined chunking using rolling hash
    fn chunk_content_defined(
        &self,
        data: &[u8],
        min_size: usize,
        avg_size: usize,
        max_size: usize,
    ) -> Result<Vec<Chunk>> {
        let mut chunks = Vec::new();
        let mut offset = 0;

        // Target mask for average chunk size
        let mask = (1u64 << (avg_size.trailing_zeros())) - 1;

        while offset < data.len() {
            let mut chunk_end = offset + min_size;
            
            // Ensure we don't exceed data length
            if chunk_end >= data.len() {
                // Last chunk
                let chunk_data = data[offset..].to_vec();
                let hash = hash_blake3(&chunk_data);
                chunks.push(Chunk {
                    hash,
                    data: chunk_data,
                    offset,
                });
                break;
            }

            // Use rolling hash to find chunk boundary
            let search_end = std::cmp::min(offset + max_size, data.len());
            let mut found_boundary = false;

            for pos in chunk_end..search_end {
                let hash = self.rolling_hash(&data[pos.saturating_sub(32)..=pos]);
                if hash & mask == 0 {
                    chunk_end = pos + 1;
                    found_boundary = true;
                    break;
                }
            }

            // If no boundary found, use max_size
            if !found_boundary {
                chunk_end = search_end;
            }

            let chunk_data = data[offset..chunk_end].to_vec();
            let hash = hash_blake3(&chunk_data);

            chunks.push(Chunk {
                hash,
                data: chunk_data,
                offset,
            });

            offset = chunk_end;
        }

        Ok(chunks)
    }

    /// Simple rolling hash (Rabin-inspired)
    fn rolling_hash(&self, window: &[u8]) -> u64 {
        let mut hash = 0u64;
        for (i, &byte) in window.iter().enumerate() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
            hash = hash.wrapping_add(i as u64);
        }
        hash
    }

    /// Get algorithm being used
    pub fn algorithm(&self) -> &ChunkingAlgorithm {
        &self.algorithm
    }
}

impl Default for ContentChunker {
    fn default() -> Self {
        Self::new(ChunkingAlgorithm::default())
    }
}

/// A chunk of data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub hash: [u8; 32],
    pub data: Vec<u8>,
    pub offset: usize,
}

impl Chunk {
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Verify chunk integrity
    pub fn verify(&self) -> bool {
        hash_blake3(&self.data) == self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_chunking() {
        let chunker = ContentChunker::new(ChunkingAlgorithm::Fixed { size: 10 });
        let data = b"0123456789abcdefghij";

        let chunks = chunker.chunk(data).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].data.len(), 10);
        assert_eq!(chunks[1].data.len(), 10);
    }

    #[test]
    fn test_content_defined_chunking() {
        let chunker = ContentChunker::new(ChunkingAlgorithm::ContentDefined {
            min_size: 4,
            avg_size: 8,
            max_size: 16,
        });
        
        let data = b"This is a test of content-defined chunking algorithm";
        let chunks = chunker.chunk(data).unwrap();

        // Should produce multiple chunks
        assert!(chunks.len() > 1);
        
        // All chunks should be within size bounds
        for chunk in &chunks {
            assert!(chunk.size() >= 4 || chunks.last().unwrap().offset == chunk.offset);
            assert!(chunk.size() <= 16);
        }
    }

    #[test]
    fn test_chunk_verification() {
        let chunker = ContentChunker::new(ChunkingAlgorithm::Fixed { size: 10 });
        let data = b"test data here";

        let chunks = chunker.chunk(data).unwrap();
        
        for chunk in chunks {
            assert!(chunk.verify());
        }
    }

    #[test]
    fn test_small_data() {
        let chunker = ContentChunker::new(ChunkingAlgorithm::ContentDefined {
            min_size: 100,
            avg_size: 200,
            max_size: 400,
        });
        
        let data = b"small";
        let chunks = chunker.chunk(data).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data, data);
    }
}
