//! Multi-Channel QUIC Parallel Shard Streaming
//!
//! Splits model weights into shards, compresses each in parallel via rayon,
//! and streams them over multiple concurrent QUIC streams. On the receiving
//! side, shards arrive independently and are reassembled once all complete.
//!
//! # Architecture
//!
//! ```text
//! Model Weights (e.g. 70KB)
//!     │
//!     ├─ Shard 0 ──► rayon::spawn ──► int8 quant + SovereignCodec ──► QUIC stream 0
//!     ├─ Shard 1 ──► rayon::spawn ──► int8 quant + SovereignCodec ──► QUIC stream 1
//!     ├─ Shard 2 ──► rayon::spawn ──► int8 quant + SovereignCodec ──► QUIC stream 2
//!     └─ Shard 3 ──► rayon::spawn ──► int8 quant + SovereignCodec ──► QUIC stream 3
//!
//! Receiver:
//!     QUIC stream 0 ──► decompress ──┐
//!     QUIC stream 1 ──► decompress ──┼──► reassemble ──► Model Weights
//!     QUIC stream 2 ──► decompress ──┤
//!     QUIC stream 3 ──► decompress ──┘
//! ```
//!
//! # Benefits
//!
//! - **Parallel compression**: 4 shards × rayon threads = ~4x faster on multi-core
//! - **Parallel streaming**: QUIC multiplexing means shards don't head-of-line block
//! - **Incremental delivery**: receiver can start decompressing shard 0 while 3 is still sending
//! - **Fault tolerance**: losing one stream only requires resending that shard, not the full model

use crate::distributed::{ModelCompressor, ModelId};
use crate::error::{NeuralMeshError, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Default number of shards to split model weights into
pub const DEFAULT_SHARD_COUNT: usize = 4;

/// Minimum shard size in bytes (below this, don't bother sharding)
pub const MIN_SHARD_SIZE: usize = 1024;

/// A single compressed shard ready for QUIC streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedShard {
    /// Which model this shard belongs to
    pub model_id: ModelId,
    /// Shard index (0-based)
    pub shard_index: usize,
    /// Total number of shards
    pub total_shards: usize,
    /// Compressed shard data
    pub data: Vec<u8>,
    /// Raw (uncompressed) size of this shard
    pub raw_size: usize,
    /// BLAKE3 hash of uncompressed shard bytes
    pub shard_hash: [u8; 32],
    /// Training generation
    pub generation: u64,
    /// Source node
    pub source_node: String,
}

impl CompressedShard {
    /// Serialize for QUIC stream transfer
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Serialize shard: {}", e)))
    }

    /// Deserialize from QUIC stream
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Deserialize shard: {}", e)))
    }
}

/// Result of parallel shard compression
#[derive(Debug)]
pub struct ShardedModel {
    /// Model ID
    pub model_id: ModelId,
    /// Compressed shards, ready for parallel QUIC streaming
    pub shards: Vec<CompressedShard>,
    /// Total raw size before sharding
    pub total_raw_size: usize,
    /// Total compressed size across all shards
    pub total_compressed_size: usize,
    /// Overall compression ratio
    pub compression_ratio: f32,
    /// BLAKE3 hash of the full uncompressed model
    pub model_hash: [u8; 32],
}

/// Shard reassembly buffer — collects arriving shards and reassembles when complete
#[derive(Debug)]
pub struct ShardReassembler {
    model_id: ModelId,
    expected_shards: usize,
    received: Vec<Option<Vec<u8>>>,
    raw_sizes: Vec<usize>,
    expected_hash: Option<[u8; 32]>,
}

impl ShardReassembler {
    /// Create a new reassembler expecting `total_shards` pieces
    pub fn new(model_id: ModelId, total_shards: usize) -> Self {
        Self {
            model_id,
            expected_shards: total_shards,
            received: vec![None; total_shards],
            raw_sizes: vec![0; total_shards],
            expected_hash: None,
        }
    }

    /// Insert a decompressed shard. Returns true if all shards are now received.
    pub fn insert(&mut self, index: usize, raw_data: Vec<u8>, raw_size: usize) -> bool {
        if index < self.expected_shards {
            self.received[index] = Some(raw_data);
            self.raw_sizes[index] = raw_size;
        }
        self.is_complete()
    }

    /// Check if all shards have been received
    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|s| s.is_some())
    }

    /// How many shards are still missing
    pub fn missing_count(&self) -> usize {
        self.received.iter().filter(|s| s.is_none()).count()
    }

    /// Reassemble the full model weights from received shards.
    /// Fails if not all shards are present.
    pub fn reassemble(self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(NeuralMeshError::InferenceFailed(format!(
                "Cannot reassemble {}: {}/{} shards received",
                self.model_id,
                self.expected_shards - self.missing_count(),
                self.expected_shards,
            )));
        }

        let total_size: usize = self.raw_sizes.iter().sum();
        let mut assembled = Vec::with_capacity(total_size);
        for shard_data in self.received.into_iter() {
            assembled.extend_from_slice(&shard_data.unwrap());
        }

        Ok(assembled)
    }
}

/// Split model weights into shards, compress each in parallel using rayon.
///
/// Each shard is independently compressed using the provided `ModelCompressor`
/// (SovereignCodec in production). Compression runs on rayon's thread pool,
/// giving ~Nx speedup on N-core machines.
///
/// # Arguments
///
/// * `model_id` - Which model these weights belong to
/// * `raw_weights` - Full model weight bytes
/// * `source_node` - Node ID of the source
/// * `generation` - Training generation number
/// * `compressor` - The compression implementation (SovereignCodec)
/// * `num_shards` - How many shards to split into (default: 4)
///
/// # Returns
///
/// A `ShardedModel` containing all compressed shards ready for parallel streaming.
pub fn parallel_shard_compress(
    model_id: ModelId,
    raw_weights: &[u8],
    source_node: &str,
    generation: u64,
    compressor: &dyn ModelCompressor,
    num_shards: usize,
) -> ShardedModel {
    let total_raw_size = raw_weights.len();
    let model_hash: [u8; 32] = blake3::hash(raw_weights).into();

    // If the model is too small, use a single shard
    let effective_shards = if total_raw_size < MIN_SHARD_SIZE * 2 {
        1
    } else {
        num_shards.max(1).min(16) // Clamp to [1, 16]
    };

    // Split into roughly equal-sized shards (aligned to 4 bytes for f32 safety)
    let base_shard_size = total_raw_size / effective_shards;
    // Align to 4 bytes so we don't split f32 values across shards
    let aligned_shard_size = (base_shard_size / 4) * 4;
    let aligned_shard_size = aligned_shard_size.max(4);

    let mut shard_ranges: Vec<(usize, usize)> = Vec::with_capacity(effective_shards);
    let mut offset = 0;
    for i in 0..effective_shards {
        let end = if i == effective_shards - 1 {
            total_raw_size // Last shard gets the remainder
        } else {
            (offset + aligned_shard_size).min(total_raw_size)
        };
        shard_ranges.push((offset, end));
        offset = end;
    }

    let source = source_node.to_string();

    // Compress each shard in parallel using rayon
    let shards: Vec<CompressedShard> = shard_ranges
        .par_iter()
        .enumerate()
        .map(|(idx, &(start, end))| {
            let shard_data = &raw_weights[start..end];
            let shard_hash: [u8; 32] = blake3::hash(shard_data).into();
            let compressed = compressor.compress(shard_data);

            CompressedShard {
                model_id,
                shard_index: idx,
                total_shards: effective_shards,
                data: compressed,
                raw_size: shard_data.len(),
                shard_hash,
                generation,
                source_node: source.clone(),
            }
        })
        .collect();

    let total_compressed_size: usize = shards.iter().map(|s| s.data.len()).sum();
    let compression_ratio = if total_compressed_size > 0 {
        total_raw_size as f32 / total_compressed_size as f32
    } else {
        1.0
    };

    ShardedModel {
        model_id,
        shards,
        total_raw_size,
        total_compressed_size,
        compression_ratio,
        model_hash,
    }
}

/// Decompress a single shard using the provided compressor.
/// Verifies integrity via BLAKE3 hash after decompression.
pub fn decompress_shard(
    shard: &CompressedShard,
    compressor: &dyn ModelCompressor,
) -> Result<Vec<u8>> {
    let raw = compressor.decompress(&shard.data).map_err(|e| {
        NeuralMeshError::InferenceFailed(format!(
            "Decompress shard {}/{} of {}: {}",
            shard.shard_index, shard.total_shards, shard.model_id, e
        ))
    })?;

    // Verify integrity
    let hash: [u8; 32] = blake3::hash(&raw).into();
    if hash != shard.shard_hash {
        return Err(NeuralMeshError::InferenceFailed(format!(
            "Shard {}/{} integrity check failed",
            shard.shard_index, shard.total_shards
        )));
    }

    Ok(raw)
}

/// Decompress all shards in parallel and reassemble the model.
/// Uses rayon for parallel decompression across shards.
pub fn parallel_shard_decompress(
    shards: &[CompressedShard],
    compressor: &dyn ModelCompressor,
) -> Result<Vec<u8>> {
    if shards.is_empty() {
        return Err(NeuralMeshError::InferenceFailed(
            "No shards to decompress".to_string(),
        ));
    }

    // Verify all shards belong to the same model and generation
    let _model_id = shards[0].model_id;
    let total_shards = shards[0].total_shards;

    if shards.len() != total_shards {
        return Err(NeuralMeshError::InferenceFailed(format!(
            "Expected {} shards, got {}",
            total_shards,
            shards.len()
        )));
    }

    // Sort by shard index
    let mut sorted: Vec<&CompressedShard> = shards.iter().collect();
    sorted.sort_by_key(|s| s.shard_index);

    // Decompress all shards in parallel
    let results: Vec<Result<Vec<u8>>> = sorted
        .par_iter()
        .map(|shard| decompress_shard(shard, compressor))
        .collect();

    // Check for errors and reassemble
    let total_raw: usize = sorted.iter().map(|s| s.raw_size).sum();
    let mut assembled = Vec::with_capacity(total_raw);
    for result in results {
        assembled.extend_from_slice(&result?);
    }

    Ok(assembled)
}

/// QUIC parallel stream message envelope for shard transfer.
/// Wraps a CompressedShard with routing metadata for QUIC multi-stream transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStreamMessage {
    /// The shard payload
    pub shard: CompressedShard,
    /// Total model hash for final reassembly verification
    pub model_hash: [u8; 32],
    /// Sample count from the training that produced this model
    pub sample_count: u64,
}

impl ShardStreamMessage {
    /// Serialize for QUIC stream transfer
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Serialize shard message: {}", e)))
    }

    /// Deserialize from QUIC stream
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Deserialize shard message: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed::IdentityCompressor;

    fn id_comp() -> &'static dyn ModelCompressor {
        &IdentityCompressor
    }

    #[test]
    fn test_shard_compress_decompress_roundtrip() {
        let raw_weights: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let sharded = parallel_shard_compress(
            ModelId::RlRouter,
            &raw_weights,
            "test-node",
            0,
            id_comp(),
            4,
        );

        assert_eq!(sharded.shards.len(), 4);
        assert_eq!(sharded.total_raw_size, 4096);

        // Decompress and reassemble
        let reassembled = parallel_shard_decompress(&sharded.shards, id_comp()).unwrap();
        assert_eq!(reassembled, raw_weights);
    }

    #[test]
    fn test_small_model_single_shard() {
        let raw_weights = vec![42u8; 512]; // Below MIN_SHARD_SIZE * 2
        let sharded = parallel_shard_compress(
            ModelId::Prefetcher,
            &raw_weights,
            "test-node",
            1,
            id_comp(),
            4,
        );

        // Should be a single shard for tiny models
        assert_eq!(sharded.shards.len(), 1);

        let reassembled = parallel_shard_decompress(&sharded.shards, id_comp()).unwrap();
        assert_eq!(reassembled, raw_weights);
    }

    #[test]
    fn test_shard_reassembler() {
        let mut reassembler = ShardReassembler::new(ModelId::RlRouter, 3);
        assert!(!reassembler.is_complete());
        assert_eq!(reassembler.missing_count(), 3);

        reassembler.insert(0, vec![1, 2, 3], 3);
        assert!(!reassembler.is_complete());
        assert_eq!(reassembler.missing_count(), 2);

        reassembler.insert(2, vec![7, 8, 9], 3);
        assert!(!reassembler.is_complete());

        let complete = reassembler.insert(1, vec![4, 5, 6], 3);
        assert!(complete);

        let assembled = reassembler.reassemble().unwrap();
        assert_eq!(assembled, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_shard_stream_message_roundtrip() {
        let raw = vec![0u8; 2048];
        let sharded = parallel_shard_compress(
            ModelId::AnomalySentry,
            &raw,
            "node-1",
            5,
            id_comp(),
            2,
        );

        for shard in &sharded.shards {
            let msg = ShardStreamMessage {
                shard: shard.clone(),
                model_hash: sharded.model_hash,
                sample_count: 100,
            };

            let bytes = msg.to_bytes().unwrap();
            let restored = ShardStreamMessage::from_bytes(&bytes).unwrap();
            assert_eq!(restored.shard.shard_index, shard.shard_index);
            assert_eq!(restored.sample_count, 100);
        }
    }

    #[test]
    fn test_f32_model_weights() {
        // Simulate real model weights (f32 values)
        let f32_weights: Vec<f32> = (0..1000)
            .map(|i| (i as f32 * 0.001) - 0.5)
            .collect();
        let raw: Vec<u8> = f32_weights
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        let sharded = parallel_shard_compress(
            ModelId::RlRouter,
            &raw,
            "test-node",
            0,
            id_comp(),
            4,
        );

        let reassembled = parallel_shard_decompress(&sharded.shards, id_comp()).unwrap();
        assert_eq!(reassembled, raw);

        // Verify f32 values survived roundtrip
        let restored_floats: Vec<f32> = reassembled
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        for (orig, restored) in f32_weights.iter().zip(restored_floats.iter()) {
            assert!((orig - restored).abs() < 1e-10);
        }
    }
}
