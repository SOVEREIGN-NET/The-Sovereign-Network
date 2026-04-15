// zkc_decompressor.rs - Zero Knowledge Compression (ZKC) Decompressor
//
// Implements ZKC decompression by replacing pattern references with
// actual pattern bytes from the global dictionary. Verifies integrity
// using ShardID hash verification.

use crate::patterns::{Pattern, PatternId};
use crate::pattern_dict::{PatternDictionary, GLOBAL_PATTERN_DICT};
use crate::sovereign_codec::SovereignCodec;
use crate::zkc_compressor::CompressedShard;
use crate::shard::{Shard, ShardId};
use bytes::{Bytes, BytesMut, BufMut};
use anyhow::{Result, anyhow};

/// Pattern marker byte (must match compressor)
const PATTERN_MARKER: u8 = 0xFF;

/// Maximum decompressed output size (256 MB) — prevents decompression bombs
const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

/// ZKC Decompression engine
pub struct ZkcDecompressor {
    /// Reference to global pattern dictionary
    dictionary: &'static PatternDictionary,
    
    /// Enable integrity verification
    verify_integrity: bool,
}

impl ZkcDecompressor {
    /// Create a new ZKC decompressor
    pub fn new() -> Self {
        ZkcDecompressor {
            dictionary: &GLOBAL_PATTERN_DICT,
            verify_integrity: true,
        }
    }

    /// Disable integrity verification (faster but less safe)
    pub fn disable_verification(mut self) -> Self {
        self.verify_integrity = false;
        self
    }

    /// Decompress a .zkc compressed shard
    /// 
    /// Process:
    /// 1. Check if shard is actually compressed
    /// 2. Parse compressed data format (if compressed)
    /// 3. Fetch pattern definitions from dictionary
    /// 4. Replace pattern references with actual bytes
    /// 5. Verify ShardID hash matches original
    /// 6. Return reconstructed shard
    pub fn decompress_shard(&self, compressed: &CompressedShard) -> Result<Shard> {
        // Phase 0: Check if actually compressed
        let decompressed_data = if compressed.is_compressed {
            // ZKC v2: decode Local Pattern Table format directly
            self.decode_compressed_data(&compressed.compressed_data)?
        } else {
            // Shard was stored uncompressed - use data as-is
            compressed.compressed_data.clone()
        };
        
        // Phase 2: Verify integrity (if enabled)
        if self.verify_integrity {
            self.verify_shard_integrity(&decompressed_data, &compressed.original_id)?;
        }
        
        // Phase 3: Create reconstructed shard
        let shard = Shard {
            id: compressed.original_id.clone(),
            data: decompressed_data,
            size: compressed.original_size,
            encrypted: false,
        };
        
        Ok(shard)
    }

    /// Decompress from raw .zkc bytes (without metadata)
    pub fn decompress_bytes(&self, compressed_data: &[u8], expected_id: &ShardId) -> Result<Shard> {
        // ZKC v2: decode directly (no inflate step)
        let decompressed_data = self.decode_compressed_data(compressed_data)?;
        
        if self.verify_integrity {
            self.verify_shard_integrity(&decompressed_data, expected_id)?;
        }
        
        let shard = Shard {
            id: expected_id.clone(),
            data: decompressed_data.clone(),
            size: decompressed_data.len(),
            encrypted: false,
        };
        
        Ok(shard)
    }

    /// Decode Sovereign ZKC v2 compressed data with Local Pattern Table
    /// 
    /// The data may be wrapped in SFC (Sovereign Frequency Coder) encoding.
    /// If so, decode SFC first to get the raw ZKC stream, then decode ZKC.
    /// 
    /// ZKC Format:
    ///   HEADER: [num_patterns: u8][PatternId(16 bytes) × N]
    ///   BODY:   literal bytes / [0xFF][index] pattern refs / [0xFF][0xFF] escaped 0xFF
    fn decode_compressed_data(&self, compressed: &[u8]) -> Result<Bytes> {
        if compressed.is_empty() {
            return Ok(Bytes::new());
        }
        
        // Check if this is pure SFC-encoded data (bypassed ZKC entirely).
        // Pure SFC starts with SFC magic bytes (e.g., "SFC0"-"SFC7").
        // ZKC header starts with num_patterns byte (0x00-0xFF) which would
        // only collide if num_patterns=0x53='S' AND the next 3 PatternId
        // bytes spell "FC0"-"FC7" — astronomically unlikely.
        if SovereignCodec::is_sfc_encoded(compressed) {
            let decoded = SovereignCodec::decode(compressed)
                .map_err(|e| anyhow!("Pure SFC decode failed: {}", e))?;
            return Ok(Bytes::from(decoded));
        }
        
        // Step 0: Read the ZKC header (NOT SFC-encoded)
        // Header format: [num_patterns: u8][PatternId(16 bytes) × N]
        // SFC is only applied to the BODY after the header.
        let num_patterns = compressed[0] as usize;
        let header_len = 1 + num_patterns * 16;
        
        if compressed.len() < header_len {
            return Err(anyhow!("ZKC data too short for header: need {} bytes, have {}", 
                header_len, compressed.len()));
        }
        
        // Read local pattern table from header
        let mut local_table: Vec<PatternId> = Vec::with_capacity(num_patterns);
        for i in 0..num_patterns {
            let start = 1 + i * 16;
            let mut id_bytes = [0u8; 16];
            id_bytes.copy_from_slice(&compressed[start..start + 16]);
            local_table.push(PatternId(id_bytes));
        }
        
        // Step 1: Decode the body (may be SFC-encoded or raw)
        let raw_body = &compressed[header_len..];
        let body_data = if SovereignCodec::is_sfc_encoded(raw_body) {
            SovereignCodec::decode(raw_body)
                .map_err(|e| anyhow!("SFC decode failed: {}", e))?
        } else {
            raw_body.to_vec()
        };
        
        // Step 2: Decode ZKC body (pattern references → actual bytes)
        let mut output = BytesMut::with_capacity(body_data.len() * 2);
        let mut i = 0;
        
        while i < body_data.len() {
            // Decompression bomb protection
            if output.len() > MAX_DECOMPRESSED_SIZE {
                return Err(anyhow!(
                    "Decompression bomb detected: output ({} bytes) exceeds {} MB limit",
                    output.len(), MAX_DECOMPRESSED_SIZE / (1024 * 1024)
                ));
            }
            
            let byte = body_data[i];
            i += 1;
            
            if byte == PATTERN_MARKER {
                if i >= body_data.len() {
                    return Err(anyhow!("Unexpected end of data after pattern marker"));
                }
                
                let index = body_data[i];
                i += 1;
                
                if index == PATTERN_MARKER {
                    // Escaped literal 0xFF
                    output.put_u8(PATTERN_MARKER);
                } else {
                    // Pattern reference
                    let idx = index as usize;
                    if idx >= local_table.len() {
                        return Err(anyhow!(
                            "Invalid pattern table index {} (table has {} entries)",
                            idx, local_table.len()
                        ));
                    }
                    
                    let pattern_id = &local_table[idx];
                    let pattern = self.dictionary.get_pattern(pattern_id)?
                        .ok_or_else(|| {
                            let dict_size = self.dictionary.cache_size().unwrap_or(0);
                            eprintln!("❌ Pattern lookup failed!");
                            eprintln!("   Table index: {} → PatternId {:?}", idx, pattern_id);
                            eprintln!("   Dictionary has: {} patterns", dict_size);
                            anyhow!(
                                "Pattern {:?} (table index {}) not found in dictionary (has {} patterns)",
                                pattern_id, idx, dict_size
                            )
                        })?;
                    
                    output.put_slice(&pattern.bytes);
                }
            } else {
                output.put_u8(byte);
            }
        }
        
        Ok(output.freeze())
    }

    /// Verify decompressed data matches expected ShardID
    fn verify_shard_integrity(&self, data: &[u8], expected_id: &ShardId) -> Result<()> {
        let computed_id = ShardId::from_hash(blake3::hash(data));
        
        if computed_id != *expected_id {
            return Err(anyhow!(
                "Shard integrity check failed: computed ID {:?} doesn't match expected {:?}",
                computed_id,
                expected_id
            ));
        }
        
        Ok(())
    }

    /// Decompress multiple shards (batch operation)
    pub fn decompress_shards(&self, compressed_shards: &[CompressedShard]) -> Result<Vec<Shard>> {
        let mut shards = Vec::with_capacity(compressed_shards.len());
        
        for compressed in compressed_shards {
            let shard = self.decompress_shard(compressed)?;
            shards.push(shard);
        }
        
        Ok(shards)
    }

    /// Get decompression statistics
    pub fn get_decompression_stats(&self, decompressed_shards: &[Shard]) -> DecompressionStats {
        let total_shards = decompressed_shards.len();
        let total_size: usize = decompressed_shards
            .iter()
            .map(|s| s.size)
            .sum();
        
        DecompressionStats {
            total_shards,
            total_size,
            shards_verified: total_shards, // All verified if verify_integrity=true
        }
    }
}

impl Default for ZkcDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Decompression statistics
#[derive(Debug, Clone)]
pub struct DecompressionStats {
    /// Total number of shards decompressed
    pub total_shards: usize,
    
    /// Total decompressed size
    pub total_size: usize,
    
    /// Number of shards that passed integrity verification
    pub shards_verified: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkc_compressor::{ZkcCompressor, CompressedShard};
    use crate::shard::Shard;

    #[test]
    fn test_compress_decompress_roundtrip() {
        // Create compressor and decompressor
        let compressor = ZkcCompressor::new();
        let decompressor = ZkcDecompressor::new();
        
        // Original data with long repeated pattern (> 17 bytes per occurrence)
        let repeated = "HELLO_WORLD_REPEATING_PATTERN!!";
        let mut data_str = String::new();
        for _ in 0..20 {
            data_str.push_str(repeated);
        }
        let original_data = Bytes::from(data_str);
        let original_shard = Shard {
            id: ShardId::from_hash(blake3::hash(&original_data)),
            data: original_data.clone(),
            size: original_data.len(),
            encrypted: false,
        };
        
        // Compress
        let compressed = compressor.compress_shard(&original_shard).unwrap();
        
        // Decompress
        let decompressed = decompressor.decompress_shard(&compressed).unwrap();
        
        // Verify roundtrip
        assert_eq!(original_shard.data, decompressed.data);
        assert_eq!(original_shard.id, decompressed.id);
    }

    #[test]
    fn test_decompress_with_escaped_markers() {
        let decompressor = ZkcDecompressor::new();
        
        // ZKC v2 format: [num_patterns=0][body with escaped 0xFF]
        let mut compressed_data = Vec::new();
        compressed_data.push(0x00); // num_patterns = 0 (no pattern table)
        compressed_data.push(0x48); // 'H'
        compressed_data.push(PATTERN_MARKER);
        compressed_data.push(PATTERN_MARKER); // Escaped literal 0xFF
        compressed_data.push(0x49); // 'I'
        
        let expected_id = ShardId::from_hash(blake3::hash(b"H\xFFI"));
        let result = decompressor.decompress_bytes(&compressed_data, &expected_id);
        
        assert!(result.is_ok());
        let shard = result.unwrap();
        assert_eq!(shard.data.as_ref(), b"H\xFFI");
    }

    #[test]
    fn test_integrity_verification() {
        let decompressor = ZkcDecompressor::new();
        
        let data = b"Test data for integrity";
        let correct_id = ShardId::from_hash(blake3::hash(data));
        let wrong_id = ShardId([0xFF; 32]);
        
        // Should succeed with correct ID
        let result = decompressor.verify_shard_integrity(data, &correct_id);
        assert!(result.is_ok());
        
        // Should fail with wrong ID
        let result = decompressor.verify_shard_integrity(data, &wrong_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_stats() {
        let decompressor = ZkcDecompressor::new();
        
        let shards = vec![
            Shard {
                id: ShardId([0u8; 32]),
                data: Bytes::from_static(b"shard1"),
                size: 6,
                encrypted: false,
            },
            Shard {
                id: ShardId([1u8; 32]),
                data: Bytes::from_static(b"shard2"),
                size: 6,
                encrypted: false,
            },
        ];
        
        let stats = decompressor.get_decompression_stats(&shards);
        
        assert_eq!(stats.total_shards, 2);
        assert_eq!(stats.total_size, 12);
        assert_eq!(stats.shards_verified, 2);
    }

    #[test]
    fn test_batch_decompress() {
        let compressor = ZkcCompressor::new();
        let decompressor = ZkcDecompressor::new();
        
        // Create multiple shards with long repeated patterns (> 17 bytes)
        let pat1 = "REPEAT_THIS_LONG_DATA_PLZ!";
        let mut data1 = String::new();
        for _ in 0..10 { data1.push_str(pat1); }
        let data1_bytes = Bytes::from(data1.clone());
        
        let pat2 = "ANOTHER_LONG_REPEATING_SEQ!";
        let mut data2 = String::new();
        for _ in 0..10 { data2.push_str(pat2); }
        let data2_bytes = Bytes::from(data2.clone());
        
        let shards = vec![
            Shard {
                id: ShardId::from_hash(blake3::hash(&data1_bytes)),
                data: data1_bytes.clone(),
                size: data1_bytes.len(),
                encrypted: false,
            },
            Shard {
                id: ShardId::from_hash(blake3::hash(&data2_bytes)),
                data: data2_bytes.clone(),
                size: data2_bytes.len(),
                encrypted: false,
            },
        ];
        
        // Compress all
        let compressed = compressor.compress_shards(&shards).unwrap();
        
        // Decompress all
        let decompressed = decompressor.decompress_shards(&compressed).unwrap();
        
        // Verify all match
        assert_eq!(shards.len(), decompressed.len());
        for (original, decompressed) in shards.iter().zip(decompressed.iter()) {
            assert_eq!(original.data, decompressed.data);
            assert_eq!(original.id, decompressed.id);
        }
    }
}
