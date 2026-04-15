//! Content-defined chunking using FastCDC algorithm
//! OPTIMIZED VERSION with parallel processing

use crate::error::{CompressionError, Result};
use crate::shard::Shard;
use crate::{AVG_SHARD_SIZE, MAX_SHARD_SIZE, MIN_SHARD_SIZE};
use fastcdc::ronomon::FastCDC;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tracing::{debug, info};
use rayon::prelude::*;
use dashmap::DashMap;

pub struct ContentChunker {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
}

impl ContentChunker {
    pub fn new() -> Self {
        Self {
            min_size: MIN_SHARD_SIZE,
            avg_size: AVG_SHARD_SIZE,
            max_size: MAX_SHARD_SIZE,
        }
    }

    pub fn with_sizes(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        Self {
            min_size,
            avg_size,
            max_size,
        }
    }

    pub fn chunk(&self, data: &[u8]) -> Result<Vec<Shard>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        info!(
            "Chunking {} bytes (min: {}, avg: {}, max: {})",
            data.len(),
            self.min_size,
            self.avg_size,
            self.max_size
        );

        let chunker = FastCDC::new(data, self.min_size, self.avg_size, self.max_size);
        let chunk_boundaries: Vec<_> = chunker.collect();
        
        info!("Found {} chunk boundaries", chunk_boundaries.len());
        
        let shards: Vec<Shard> = chunk_boundaries
            .par_iter()
            .map(|entry| {
                let chunk_data = &data[entry.offset..entry.offset + entry.length];
                let shard = Shard::new(chunk_data.to_vec());
                
                debug!(
                    "Created shard {} at offset {} (size: {})",
                    shard.id, entry.offset, shard.size
                );
                
                shard
            })
            .collect();

        info!("Chunked into {} shards", shards.len());
        
        Ok(shards)
    }

    pub async fn chunk_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Shard>> {
        let path = path.as_ref();
        
        info!("Reading file: {}", path.display());
        
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|e| CompressionError::Io(e))?;
        
        let file_size = metadata.len() as usize;
        const STREAMING_THRESHOLD: usize = 100 * 1024 * 1024;
        
        if file_size > STREAMING_THRESHOLD {
            info!("File size {} bytes - using streaming chunking", file_size);
            self.chunk_file_streaming(path).await
        } else {
            let mut file = File::open(path)
                .await
                .map_err(|e| CompressionError::Io(e))?;
            
            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .await
                .map_err(|e| CompressionError::Io(e))?;
            
            info!("Read {} bytes from {}", data.len(), path.display());
            
            self.chunk(&data)
        }
    }

    pub async fn chunk_file_streaming<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Shard>> {
        let path = path.as_ref();
        
        let mut file = File::open(path)
            .await
            .map_err(|e| CompressionError::Io(e))?;
        
        const BUFFER_SIZE: usize = 10 * 1024 * 1024;
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut accumulated_data = Vec::new();
        let mut shards = Vec::new();
        let mut total_bytes_read = 0;
        
        loop {
            let bytes_read = file.read(&mut buffer)
                .await
                .map_err(|e| CompressionError::Io(e))?;
            
            if bytes_read == 0 {
                if !accumulated_data.is_empty() {
                    let final_shards = self.chunk(&accumulated_data)?;
                    shards.extend(final_shards);
                }
                break;
            }
            
            total_bytes_read += bytes_read;
            accumulated_data.extend_from_slice(&buffer[..bytes_read]);
            
            if accumulated_data.len() >= 2 * self.max_size {
                let split_point = accumulated_data.len() - self.max_size;
                let to_chunk = accumulated_data[..split_point].to_vec();
                accumulated_data = accumulated_data[split_point..].to_vec();
                
                let chunk_shards = self.chunk(&to_chunk)?;
                shards.extend(chunk_shards);
                
                debug!(
                    "Streaming chunk processed {} bytes, {} total shards so far",
                    to_chunk.len(),
                    shards.len()
                );
            }
        }
        
        info!(
            "Streaming chunking complete: {} bytes, {} shards",
            total_bytes_read,
            shards.len()
        );
        
        Ok(shards)
    }

    pub fn chunk_with_dedup(&self, data: &[u8]) -> Result<ChunkResult> {
        let shards = self.chunk(data)?;
        
        use std::sync::{Arc, Mutex};
        let unique_shards = Arc::new(Mutex::new(Vec::new()));
        let shard_indices = Arc::new(Mutex::new(Vec::new()));
        let seen_ids = Arc::new(DashMap::new());
        
        shards.par_iter().for_each(|shard| {
            if let Some(index) = seen_ids.get(&shard.id) {
                shard_indices.lock().unwrap().push(*index);
            } else {
                let mut unique = unique_shards.lock().unwrap();
                let index = unique.len();
                seen_ids.insert(shard.id, index);
                shard_indices.lock().unwrap().push(index);
                unique.push(shard.clone());
            }
        });
        
        let unique_shards = Arc::try_unwrap(unique_shards).unwrap().into_inner().unwrap();
        let shard_indices = Arc::try_unwrap(shard_indices).unwrap().into_inner().unwrap();
        
        let total_bytes = data.len();
        let unique_bytes: usize = unique_shards.iter().map(|s| s.size).sum();
        
        info!(
            "Deduplication: {} total shards, {} unique",
            shard_indices.len(),
            unique_shards.len()
        );
        
        Ok(ChunkResult {
            unique_shards,
            shard_indices,
            total_bytes,
            unique_bytes,
        })
    }

    pub fn estimate_shard_count(&self, data_size: usize) -> usize {
        (data_size + self.avg_size - 1) / self.avg_size
    }
}

impl Default for ContentChunker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ChunkResult {
    pub unique_shards: Vec<Shard>,
    pub shard_indices: Vec<usize>,
    pub total_bytes: usize,
    pub unique_bytes: usize,
}

impl ChunkResult {
    pub fn dedup_ratio(&self) -> f64 {
        if self.unique_bytes > 0 {
            self.total_bytes as f64 / self.unique_bytes as f64
        } else {
            1.0
        }
    }

    pub fn space_savings(&self) -> f64 {
        if self.total_bytes > 0 {
            (1.0 - (self.unique_bytes as f64 / self.total_bytes as f64)) * 100.0
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_empty() {
        let chunker = ContentChunker::new();
        let shards = chunker.chunk(b"").unwrap();
        assert_eq!(shards.len(), 0);
    }

    #[test]
    fn test_chunk_small_data() {
        let chunker = ContentChunker::new();
        let data = b"Hello World";
        let shards = chunker.chunk(data).unwrap();
        
        assert!(shards.len() >= 1);
        
        for shard in &shards {
            assert!(shard.verify());
        }
    }

    #[test]
    fn test_chunk_deterministic() {
        let chunker = ContentChunker::new();
        let data = vec![0u8; 100_000];
        
        let shards1 = chunker.chunk(&data).unwrap();
        let shards2 = chunker.chunk(&data).unwrap();
        
        assert_eq!(shards1.len(), shards2.len());
        
        for (s1, s2) in shards1.iter().zip(shards2.iter()) {
            assert_eq!(s1.id, s2.id);
            assert_eq!(s1.size, s2.size);
        }
    }

    #[test]
    fn test_chunk_with_dedup() {
        let chunker = ContentChunker::new();
        
        let mut data = Vec::new();
        let block = vec![42u8; 16 * 1024];
        
        for _ in 0..10 {
            data.extend_from_slice(&block);
        }
        
        let result = chunker.chunk_with_dedup(&data).unwrap();
        assert!(result.shard_indices.len() >= result.unique_shards.len());
    }

    #[test]
    fn test_estimate_shard_count() {
        let chunker = ContentChunker::new();
        let estimate = chunker.estimate_shard_count(1_000_000);
        // With 1MB avg shards: 1MB / 1MB ≈ 1 shard
        assert!(estimate >= 1 && estimate < 5);
    }
}
