//! JIT (Just-In-Time) assembler for parallel shard reconstruction

use crate::error::{CompressionError, Result};
use crate::shard::{Shard, ShardId};
use crate::witness::ZkWitness;
use bitvec::prelude::*;
use futures::Stream;
use memmap2::MmapMut;
use std::fs::OpenOptions;
use std::path::Path;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Assembles file from streamed shards with verification
pub struct JitAssembler {
    /// Memory-mapped output buffer
    buffer: Mutex<Option<MmapMut>>,
    
    /// Bitmap tracking received shards
    received: Mutex<BitVec>,
    
    /// Expected shard order from witness
    witness: ZkWitness,
    
    /// Current offset for writing
    offset: Mutex<usize>,
}

impl JitAssembler {
    /// Create new assembler for a file
    pub async fn new<P: AsRef<Path>>(
        output_path: P,
        witness: ZkWitness,
    ) -> Result<Self> {
        let file_size = witness.metadata.size as usize;
        let shard_count = witness.shard_ids.len();
        
        info!(
            "Creating assembler for {} ({} bytes, {} shards)",
            output_path.as_ref().display(),
            file_size,
            shard_count
        );
        
        // Create output file with correct size
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(output_path.as_ref())
            .map_err(|e| CompressionError::Io(e))?;
        
        file.set_len(file_size as u64)
            .map_err(|e| CompressionError::Io(e))?;
        
        // Memory-map the file
        let mmap = unsafe {
            MmapMut::map_mut(&file)
                .map_err(|e| CompressionError::Io(e))?
        };
        
        // Initialize bitmap
        let received = bitvec![0; shard_count];
        
        Ok(Self {
            buffer: Mutex::new(Some(mmap)),
            received: Mutex::new(received),
            witness,
            offset: Mutex::new(0),
        })
    }

    /// Assemble file from streaming shards
    pub async fn assemble_streaming<S>(&self, mut shard_stream: S) -> Result<()>
    where
        S: Stream<Item = Result<Shard>> + Unpin,
    {
        use futures::StreamExt;
        
        info!("Starting streaming assembly");
        
        let mut received_count = 0;
        let total_shards = self.witness.shard_ids.len();
        
        while let Some(result) = shard_stream.next().await {
            let shard = result?;
            
            self.process_shard(shard).await?;
            
            received_count += 1;
            
            if received_count % 100 == 0 {
                info!("Progress: {}/{} shards", received_count, total_shards);
            }
        }
        
        // Verify completion
        self.verify_complete().await?;
        
        info!("Assembly complete: {}/{} shards", received_count, total_shards);
        
        Ok(())
    }

    /// Process a single shard
    async fn process_shard(&self, shard: Shard) -> Result<()> {
        // Find shard index in witness
        let shard_index = self.witness.shard_ids
            .iter()
            .position(|id| *id == shard.id)
            .ok_or_else(|| {
                CompressionError::InvalidShard(
                    format!("Shard {} not in witness", shard.id)
                )
            })?;
        
        // Check if already received
        {
            let received = self.received.lock().await;
            if received[shard_index] {
                debug!("Duplicate shard {}, skipping", shard.id);
                return Ok(());
            }
        }
        
        // Verify shard integrity
        if !shard.verify() {
            return Err(CompressionError::InvalidShard(
                format!("Shard {} failed verification", shard.id)
            ));
        }
        
        // Calculate write position
        let offset = self.calculate_offset(shard_index)?;
        
        // Write to memory-mapped buffer
        {
            let mut buffer = self.buffer.lock().await;
            if let Some(ref mut mmap) = *buffer {
                let end = offset + shard.size;
                
                if end > mmap.len() {
                    return Err(CompressionError::ReassemblyFailed(
                        format!("Shard exceeds file bounds: {} > {}", end, mmap.len())
                    ));
                }
                
                mmap[offset..end].copy_from_slice(shard.as_slice());
                
                debug!(
                    "Wrote shard {} at offset {} ({} bytes)",
                    shard.id, offset, shard.size
                );
            } else {
                return Err(CompressionError::ReassemblyFailed(
                    "Buffer not initialized".to_string()
                ));
            }
        }
        
        // Mark as received
        {
            let mut received = self.received.lock().await;
            received.set(shard_index, true);
        }
        
        Ok(())
    }

    /// Calculate file offset for a shard index
    fn calculate_offset(&self, shard_index: usize) -> Result<usize> {
        if shard_index >= self.witness.shard_ids.len() {
            return Err(CompressionError::ReassemblyFailed(
                format!("Invalid shard index: {}", shard_index)
            ));
        }
        
        // Use stored offsets if available
        if let Some(ref offsets) = self.witness.metadata.shard_offsets {
            return Ok(offsets[shard_index]);
        }
        
        // Fallback to average size calculation for legacy witnesses
        let avg_size = self.witness.metadata.avg_shard_size;
        Ok(shard_index * avg_size)
    }

    /// Verify all shards received
    async fn verify_complete(&self) -> Result<()> {
        let received = self.received.lock().await;
        
        let missing: Vec<usize> = received.iter()
            .enumerate()
            .filter_map(|(i, bit)| if !*bit { Some(i) } else { None })
            .collect();
        
        if !missing.is_empty() {
            warn!("Missing {} shards: {:?}", missing.len(), &missing[..10.min(missing.len())]);
            return Err(CompressionError::ReassemblyFailed(
                format!("Missing {} shards", missing.len())
            ));
        }
        
        // Verify final hash matches witness
        let buffer = self.buffer.lock().await;
        if let Some(ref mmap) = *buffer {
            let computed_hash = *blake3::hash(&mmap[..]).as_bytes();
            
            if computed_hash != self.witness.root_hash {
                return Err(CompressionError::ReassemblyFailed(
                    "Final hash mismatch".to_string()
                ));
            }
            
            info!("✓ Hash verification passed");
        }
        
        Ok(())
    }

    /// Get assembly progress (0.0 to 1.0)
    pub async fn progress(&self) -> f64 {
        let received = self.received.lock().await;
        let count = received.count_ones();
        count as f64 / received.len() as f64
    }

    /// Get list of missing shard IDs
    pub async fn missing_shards(&self) -> Vec<ShardId> {
        let received = self.received.lock().await;
        
        received.iter()
            .enumerate()
            .filter_map(|(i, bit)| {
                if !*bit {
                    Some(self.witness.shard_ids[i])
                } else {
                    None
                }
            })
            .collect()
    }

    /// Flush buffer to disk
    pub async fn flush(&self) -> Result<()> {
        let buffer = self.buffer.lock().await;
        if let Some(ref mmap) = *buffer {
            mmap.flush()
                .map_err(|e| CompressionError::Io(e))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunker::ContentChunker;
    use crate::witness::FileMetadata;
    use futures::stream;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_assembler_basic() {
        // Create test data
        let data = b"Hello, World!".repeat(100);
        
        // Chunk it
        let chunker = ContentChunker::new();
        let shards = chunker.chunk(&data).unwrap();
        
        // Generate witness
        let metadata = FileMetadata {
            name: "test.txt".to_string(),
            size: data.len() as u64,
            shard_count: shards.len(),
            avg_shard_size: data.len() / shards.len(),
            created_at: 0,
            mime_type: None,
            shard_offsets: None,
        };
        let witness = ZkWitness::generate(&shards, metadata).unwrap();
        
        // Create assembler
        let output = NamedTempFile::new().unwrap();
        let assembler = JitAssembler::new(output.path(), witness).await.unwrap();
        
        // Stream shards
        let shard_stream = stream::iter(shards.into_iter().map(Ok));
        assembler.assemble_streaming(shard_stream).await.unwrap();
        
        // Verify
        let progress = assembler.progress().await;
        assert_eq!(progress, 1.0);
        
        let missing = assembler.missing_shards().await;
        assert_eq!(missing.len(), 0);
    }
}
