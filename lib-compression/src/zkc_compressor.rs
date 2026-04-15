// zkc_compressor.rs - Zero Knowledge Compression (ZKC) Compressor
//
// Implements the ZKC compression algorithm that replaces repeating byte sequences
// with pattern references from the global dictionary. Produces .zkc compressed shards.
//
// OPTIMIZED VERSION with parallel processing and performance improvements

use crate::patterns::{Pattern, PatternId, PatternMiner, PatternMinerConfig};
use crate::pattern_dict::{PatternDictionary, GLOBAL_PATTERN_DICT};
use crate::sovereign_codec::SovereignCodec;
use crate::shard::{Shard, ShardId};
use bytes::{Bytes, BytesMut, BufMut};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use rayon::prelude::*; // Parallel processing

/// Size of pattern reference in body (1 marker + 1 table index = 2 bytes)
const PATTERN_REF_SIZE: usize = 2;

/// Maximum patterns per shard local table (indices 0-253, 0xFF=escape)
const MAX_LOCAL_PATTERNS: usize = 254;

/// Marker byte for pattern references in compressed data
const PATTERN_MARKER: u8 = 0xFF;

/// Minimum savings required to use compression (bytes)
const MIN_COMPRESSION_SAVINGS: i64 = 1;  // Compress even tiny savings

/// Compressed shard data format
#[derive(Debug, Clone)]
pub struct CompressedShard {
    /// Original shard ID (for verification)
    pub original_id: ShardId,
    
    /// Compressed data (.zkc format) OR original data if uncompressed
    pub compressed_data: Bytes,
    
    /// Original size (before compression)
    pub original_size: usize,
    
    /// Compressed size (after compression)
    pub compressed_size: usize,
    
    /// Compression ratio (original / compressed)
    pub compression_ratio: f64,
    
    /// Pattern IDs used in compression (for usage tracking)
    pub pattern_ids_used: Vec<PatternId>,
    
    /// Whether this shard is actually compressed (false = stored uncompressed)
    pub is_compressed: bool,
}

impl CompressedShard {
    /// Calculate compression savings in bytes
    pub fn savings(&self) -> i64 {
        self.original_size as i64 - self.compressed_size as i64
    }

    /// Convert to a regular Shard for storage
    pub fn to_shard(&self) -> Shard {
        Shard {
            id: self.original_id.clone(),
            data: self.compressed_data.clone(),
            size: self.compressed_size,
            encrypted: false,
        }
    }
}

/// ZKC Compression engine
pub struct ZkcCompressor {
    /// Pattern miner for discovering new patterns
    pattern_miner: PatternMiner,
    
    /// Reference to global pattern dictionary
    dictionary: &'static PatternDictionary,
    
    /// Enable pattern discovery (mine new patterns from data)
    enable_mining: bool,
}

impl ZkcCompressor {
    /// Create a new ZKC compressor
    pub fn new() -> Self {
        // Sovereign ZKC v2: Local Pattern Table means refs cost only 2 bytes
        // Sovereign ZKC v2: refs cost 2 bytes + 16 byte table entry per unique pattern.
        // min_pattern_size=4 is optimal: 3-byte patterns' 1-byte-per-ref savings
        // are already captured well by BWT+MTF+RLE+Huffman entropy coding.
        let config = PatternMinerConfig {
            min_pattern_size: 4,        // ZKC v2: 4+ bytes saves more than BWT handles alone
            max_pattern_size: 512,      // Larger patterns for better compression
            min_frequency: 2,           // Must appear at least twice
            max_patterns: 20000,        // Top 20k — proven optimal, more causes header bloat
            window_size: 16384,         // 16 KB window for pattern discovery
        };
        
        ZkcCompressor {
            pattern_miner: PatternMiner::new(config),
            dictionary: &GLOBAL_PATTERN_DICT,
            enable_mining: true,
        }
    }

    /// Create compressor with custom configuration
    pub fn with_config(config: PatternMinerConfig) -> Self {
        ZkcCompressor {
            pattern_miner: PatternMiner::new(config),
            dictionary: &GLOBAL_PATTERN_DICT,
            enable_mining: true,
        }
    }

    /// Disable pattern mining (only use existing dictionary)
    pub fn disable_mining(mut self) -> Self {
        self.enable_mining = false;
        self
    }

    /// Compress a shard using ZKC algorithm
    /// 
    /// Process:
    /// 1. Load known patterns from global dictionary
    /// 2. Find pattern matches in shard data
    /// 3. Replace patterns with references
    /// 4. Optionally mine new patterns and add to dictionary
    /// 5. Return compressed shard with metadata
    pub fn compress_shard(&self, shard: &Shard) -> Result<CompressedShard> {
        let original_size = shard.data.len();
        
        // Phase 1: Get compression patterns from dictionary
        let known_patterns = self.dictionary.get_compression_patterns()?;
        
        // Phase 1.5: Mine new patterns FIRST if enabled
        // OPTIMIZED: Increased threshold for mining to be more aggressive
        const MAX_MINING_SIZE: usize = 512 * 1024; // Increased from 256 KB to 512 KB
        if self.enable_mining && shard.data.len() <= MAX_MINING_SIZE {
            self.mine_and_contribute_patterns(&shard.data)?;
        } else if self.enable_mining && shard.data.len() > MAX_MINING_SIZE {
            // For large shards, mine from a larger sample
            let sample_size = 128 * 1024; // Increased from 64 KB to 128 KB
            let sample = &shard.data[..sample_size.min(shard.data.len())];
            self.mine_and_contribute_patterns(sample)?;
        }
        
        // Refresh pattern list after mining
        let known_patterns = self.dictionary.get_compression_patterns()?;
        
        if known_patterns.is_empty() {
            // No patterns available - return uncompressed
            return Ok(CompressedShard {
                original_id: shard.id.clone(),
                compressed_data: shard.data.clone(),
                original_size,
                compressed_size: original_size,
                compression_ratio: 1.0,
                pattern_ids_used: Vec::new(),
                is_compressed: false,  // No compression applied
            });
        }
        
        // Phase 2: Find pattern matches in data
        let matches = self.pattern_miner.find_patterns_in_data(
            &shard.data,
            &known_patterns,
        );
        
        // Phase 3: Encode compressed data (ZKC v2 with Local Pattern Table)
        let (compressed_data, pattern_ids_used) = self.encode_compressed_data(
            &shard.data,
            &matches,
            &known_patterns,
        )?;
        
        let compressed_size = compressed_data.len();
        
        // Check if compression actually helped
        if (original_size as i64 - compressed_size as i64) < MIN_COMPRESSION_SAVINGS {
            // Compression didn't save enough - return uncompressed
            return Ok(CompressedShard {
                original_id: shard.id.clone(),
                compressed_data: shard.data.clone(),
                original_size,
                compressed_size: original_size,
                compression_ratio: 1.0,
                pattern_ids_used: Vec::new(),
                is_compressed: false,  // CRITICAL: Mark as uncompressed
            });
        }
        
        let compression_ratio = original_size as f64 / compressed_size as f64;
        
        // Phase 5: Record pattern usage
        self.dictionary.record_pattern_usage(&pattern_ids_used)?;
        
        Ok(CompressedShard {
            original_id: shard.id.clone(),
            compressed_data,
            original_size,
            compressed_size,
            compression_ratio,
            pattern_ids_used,
            is_compressed: true,  // This shard is actually compressed
        })
    }

    /// Encode Sovereign ZKC v2 compressed data format with Local Pattern Table:
    /// 
    /// HEADER:
    ///   [num_patterns: u8] (0-254)
    ///   [PatternId (16 bytes)] × num_patterns  (the local lookup table)
    /// 
    /// BODY:
    ///   Regular byte (0x00-0xFE): literal — just that byte
    ///   [0xFF][index: u8]:         if index < num_patterns → expand pattern_table[index]
    ///   [0xFF][0xFF]:              literal 0xFF byte (escaped)
    /// 
    /// This format reduces per-reference cost from 17 bytes to 2 bytes (8.5× improvement)
    /// by storing each unique PatternId once in a header table and referencing by index.
    fn encode_compressed_data(
        &self,
        original_data: &[u8],
        matches: &[(usize, PatternId, usize)],
        _patterns: &HashMap<PatternId, Pattern>,
    ) -> Result<(Bytes, Vec<PatternId>)> {
        // Step 1: Count per-shard frequency & size for each pattern
        // CRITICAL: Must verify each pattern's IN-THIS-SHARD savings justifies
        // the 16-byte local table entry cost. Global mining frequency != shard frequency.
        let mut pattern_shard_stats: HashMap<PatternId, (u32, usize)> = HashMap::new();
        for &(_, pattern_id, size) in matches {
            let entry = pattern_shard_stats.entry(pattern_id).or_insert((0, size));
            entry.0 += 1;
        }
        
        // Step 2: Filter patterns by per-shard cost-benefit, sort by net savings
        let mut viable_patterns: Vec<(PatternId, f64)> = pattern_shard_stats.iter()
            .filter_map(|(&pid, &(count, size))| {
                let body_savings = count as f64 * (size as f64 - PATTERN_REF_SIZE as f64);
                let table_cost = 16.0; // 16 bytes per unique pattern in header
                let net = body_savings - table_cost;
                if net > 0.0 { Some((pid, net)) } else { None }
            })
            .collect();
        viable_patterns.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Step 3: Build local pattern table from ONLY profitable patterns
        let mut unique_patterns: Vec<PatternId> = Vec::new();
        let mut pattern_to_index: HashMap<PatternId, u8> = HashMap::new();
        for (pid, _net_savings) in viable_patterns {
            if unique_patterns.len() >= MAX_LOCAL_PATTERNS {
                break;
            }
            let idx = unique_patterns.len() as u8;
            pattern_to_index.insert(pid, idx);
            unique_patterns.push(pid);
        }
        
        let num_patterns = unique_patterns.len();
        
        // Step 2: Calculate output capacity
        // Header: 1 byte (count) + 16 bytes per pattern
        let header_size = 1 + num_patterns * 16;
        let mut output = BytesMut::with_capacity(header_size + original_data.len());
        
        // Step 3: Write header
        output.put_u8(num_patterns as u8);
        for pid in &unique_patterns {
            output.put_slice(&pid.0); // 16 bytes each
        }
        
        // Step 4: Write body with pattern references
        let mut pattern_ids_used = Vec::new();
        let mut offset = 0;
        let mut match_idx = 0;
        
        while offset < original_data.len() {
            if match_idx < matches.len() && matches[match_idx].0 == offset {
                let (_, pattern_id, pattern_size) = matches[match_idx];
                
                if let Some(&table_idx) = pattern_to_index.get(&pattern_id) {
                    // Encode as [0xFF][table_index] — only 2 bytes!
                    output.put_u8(PATTERN_MARKER);
                    output.put_u8(table_idx);
                    pattern_ids_used.push(pattern_id);
                    offset += pattern_size;
                } else {
                    // Pattern didn't fit in table — write raw bytes
                    let byte = original_data[offset];
                    if byte == PATTERN_MARKER {
                        output.put_u8(PATTERN_MARKER);
                        output.put_u8(PATTERN_MARKER);
                    } else {
                        output.put_u8(byte);
                    }
                    offset += 1;
                }
                match_idx += 1;
            } else {
                let byte = original_data[offset];
                if byte == PATTERN_MARKER {
                    output.put_u8(PATTERN_MARKER);
                    output.put_u8(PATTERN_MARKER); // Escaped literal 0xFF
                } else {
                    output.put_u8(byte);
                }
                offset += 1;
            }
        }
        
        // Apply Sovereign Frequency Coder (SFC) ONLY to the body, not the header.
        // The header contains PatternId hashes (near-random bytes) that destroy
        // BWT context modeling. The body contains structured literals + markers.
        let full_zkc = output.freeze();
        let header_len = 1 + num_patterns * 16;
        
        // Strategy 1: ZKC header + SFC(ZKC body)
        // Only try this when ZKC actually replaced patterns AND the body
        // is significantly smaller than original (pattern replacements saved >15%).
        // If pattern savings are modest, the ZKC header overhead + BWT disruption
        // from 0xFF markers makes this path lose to pure SFC almost always.
        let body_bytes_len = full_zkc.len().saturating_sub(header_len);
        let significant_zkc_savings = body_bytes_len < original_data.len() * 85 / 100;
        let zkc_sfc_result = if num_patterns > 0 && full_zkc.len() > header_len && significant_zkc_savings {
            let header_bytes = &full_zkc[..header_len];
            let body_bytes = &full_zkc[header_len..];
            let sfc_body = SovereignCodec::encode(body_bytes);
            
            if sfc_body.len() < body_bytes.len() {
                let mut combined = Vec::with_capacity(header_len + sfc_body.len());
                combined.extend_from_slice(header_bytes);
                combined.extend_from_slice(&sfc_body);
                Some(Bytes::from(combined))
            } else {
                None
            }
        } else {
            None
        };
        
        // Strategy 2: Pure SFC on original data (bypasses ZKC entirely)
        // This often wins when ZKC pattern markers disrupt BWT context modeling.
        let pure_sfc = SovereignCodec::encode(original_data);
        let pure_sfc_result = if pure_sfc.len() < original_data.len() {
            Some(Bytes::from(pure_sfc))
        } else {
            None
        };
        
        // Pick the smallest result
        let best = match (zkc_sfc_result, pure_sfc_result) {
            (Some(zkc), Some(pure)) => {
                if zkc.len() <= pure.len() {
                    zkc
                } else {
                    pure
                }
            }
            (Some(zkc), None) => zkc,
            (None, Some(pure)) => pure,
            (None, None) => full_zkc,
        };
        
        Ok((best, pattern_ids_used))
    }

    /// Mine new patterns from data and contribute to global dictionary
    fn mine_and_contribute_patterns(&self, data: &[u8]) -> Result<()> {
        // Mine patterns from this data
        let discovered_patterns = self.pattern_miner.mine_patterns(data);
        
        // Add to dictionary and promote IMMEDIATELY (not pending)
        for pattern in discovered_patterns {
            self.dictionary.add_pending_pattern(pattern)?;
        }
        
        // Force immediate promotion so patterns are available for decompression
        self.dictionary.promote_patterns()?;
        
        Ok(())
    }

    /// Compress multiple shards (batch operation)
    /// 
    /// Uses Rayon to compress shards in parallel across all CPU cores
    pub fn compress_shards(&self, shards: &[Shard]) -> Result<Vec<CompressedShard>> {
        let total_shards = shards.len();
        
        if total_shards == 0 {
            return Ok(Vec::new());
        }
        
        // Show progress for large batches
        let show_progress = total_shards > 10;
        
        if show_progress {
            println!("   🚀 Compressing {} shards in parallel...", total_shards);
        }
        
        // PARALLEL COMPRESSION - Use all CPU cores
        let compressed_shards: Result<Vec<CompressedShard>> = shards
            .par_iter()
            .enumerate()
            .map(|(idx, shard)| {
                let result = self.compress_shard(shard);
                
                // Log progress every 100 shards for very large files
                if show_progress && (idx + 1) % 100 == 0 {
                    let progress = ((idx + 1) as f64 / total_shards as f64) * 100.0;
                    println!("   ⚙️  Progress: {}/{} shards ({:.0}%)", idx + 1, total_shards, progress);
                }
                
                result
            })
            .collect();
        
        if show_progress {
            println!("   ✅ Compressed all {} shards", total_shards);
        }
        
        compressed_shards
    }
    
    /// Compress shards sequentially with optimized single-pass mining
    /// 
    /// Mines patterns ONCE from a combined data sample, then compresses all
    /// shards using those patterns. This is dramatically faster than mining
    /// per-shard (seconds instead of minutes).
    pub fn compress_shards_sequential(&self, shards: &[Shard]) -> Result<Vec<CompressedShard>> {
        // PERFORMANCE: Mine patterns ONCE from ALL data (for files ≤ 2MB)
        // or a large sample (for bigger files). Full-data mining catches all
        // patterns, not just those in a random sample.
        if self.enable_mining && !shards.is_empty() {
            println!("   ⛏️  Mining patterns from data...");
            let mining_start = std::time::Instant::now();
            let mut sample = Vec::new();
            let max_sample = 2 * 1024 * 1024; // 2 MB — use full data for typical files
            for shard in shards {
                if sample.len() >= max_sample { break; }
                sample.extend_from_slice(&shard.data);
            }
            sample.truncate(max_sample);
            self.mine_and_contribute_patterns(&sample)?;
            println!("   ✅ Pattern mining complete in {:.1}s ({} patterns, from {} KB sample)", 
                     mining_start.elapsed().as_secs_f64(),
                     self.dictionary.cache_size().unwrap_or(0),
                     sample.len() / 1024);
        }
        
        // Compress all shards using discovered patterns (NO per-shard mining)
        let mut compressed_shards = Vec::with_capacity(shards.len());
        let total_shards = shards.len();
        let show_progress = total_shards > 10;
        
        for (idx, shard) in shards.iter().enumerate() {
            let compressed = self.compress_shard_no_mining(shard)?;
            compressed_shards.push(compressed);
            
            if show_progress && (idx + 1) % 10 == 0 {
                let progress = ((idx + 1) as f64 / total_shards as f64) * 100.0;
                println!("   ⚙️  Compressing... {}/{} shards ({:.0}%)", idx + 1, total_shards, progress);
            }
        }
        
        if show_progress {
            println!("   ✅ Compressed all {} shards", total_shards);
        }
        
        Ok(compressed_shards)
    }

    /// Compress a single shard using only existing dictionary patterns (no mining).
    /// Used by compress_shards_sequential to avoid redundant per-shard mining.
    fn compress_shard_no_mining(&self, shard: &Shard) -> Result<CompressedShard> {
        let original_size = shard.data.len();
        
        let known_patterns = self.dictionary.get_compression_patterns()?;
        
        // Find pattern matches (even if empty, we still ZKC-encode + deflate)
        let matches = if known_patterns.is_empty() {
            Vec::new()
        } else {
            self.pattern_miner.find_patterns_in_data(
                &shard.data,
                &known_patterns,
            )
        };
        
        // ZKC v2 encode with local pattern table (no mining, no deflate)
        let (compressed_data, pattern_ids_used) = self.encode_compressed_data(
            &shard.data,
            &matches,
            &known_patterns,
        )?;
        
        let compressed_size = compressed_data.len();
        
        if (original_size as i64 - compressed_size as i64) < MIN_COMPRESSION_SAVINGS {
            return Ok(CompressedShard {
                original_id: shard.id.clone(),
                compressed_data: shard.data.clone(),
                original_size,
                compressed_size: original_size,
                compression_ratio: 1.0,
                pattern_ids_used: Vec::new(),
                is_compressed: false,
            });
        }
        
        let compression_ratio = original_size as f64 / compressed_size as f64;
        
        if !pattern_ids_used.is_empty() {
            self.dictionary.record_pattern_usage(&pattern_ids_used)?;
        }
        
        Ok(CompressedShard {
            original_id: shard.id.clone(),
            compressed_data,
            original_size,
            compressed_size,
            compression_ratio,
            pattern_ids_used,
            is_compressed: true,
        })
    }

    /// Get compression statistics for a set of shards
    pub fn get_compression_stats(&self, compressed_shards: &[CompressedShard]) -> CompressionStats {
        let total_original_size: usize = compressed_shards
            .iter()
            .map(|s| s.original_size)
            .sum();
        
        let total_compressed_size: usize = compressed_shards
            .iter()
            .map(|s| s.compressed_size)
            .sum();
        
        let total_savings = total_original_size as i64 - total_compressed_size as i64;
        
        let avg_compression_ratio = if total_compressed_size > 0 {
            total_original_size as f64 / total_compressed_size as f64
        } else {
            1.0
        };
        
        let shards_compressed = compressed_shards
            .iter()
            .filter(|s| s.compression_ratio > 1.0)
            .count();
        
        CompressionStats {
            total_shards: compressed_shards.len(),
            shards_compressed,
            total_original_size,
            total_compressed_size,
            total_savings,
            avg_compression_ratio,
        }
    }
}

impl Default for ZkcCompressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Compression statistics
#[derive(Debug, Clone)]
pub struct CompressionStats {
    /// Total number of shards
    pub total_shards: usize,
    
    /// Number of shards actually compressed (others returned uncompressed)
    pub shards_compressed: usize,
    
    /// Total original size
    pub total_original_size: usize,
    
    /// Total compressed size
    pub total_compressed_size: usize,
    
    /// Total bytes saved
    pub total_savings: i64,
    
    /// Average compression ratio
    pub avg_compression_ratio: f64,
}

impl CompressionStats {
    /// Calculate percentage compressed
    pub fn compression_percentage(&self) -> f64 {
        if self.total_original_size == 0 {
            return 0.0;
        }
        (self.total_savings as f64 / self.total_original_size as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::Shard;

    #[test]
    fn test_compress_shard_no_patterns() {
        let compressor = ZkcCompressor::new().disable_mining();
        
        let data = Bytes::from_static(b"UniqueDataWithNoRepeatingPatterns12345");
        let shard = Shard {
            id: ShardId::from_hash(blake3::hash(&data)),
            data: data.clone(),
            size: data.len(),
            encrypted: false,
        };
        
        let compressed = compressor.compress_shard(&shard).unwrap();
        
        // Should return uncompressed (no patterns available)
        assert_eq!(compressed.compression_ratio, 1.0);
        assert_eq!(compressed.compressed_data, data);
    }

    #[test]
    fn test_compress_with_patterns() {
        let compressor = ZkcCompressor::new();
        
        // Data with long repeated pattern (> 17 bytes) to actually compress
        let repeated = "This_is_a_long_repeating_pattern!";
        let mut data_str = String::new();
        for _ in 0..20 {
            data_str.push_str(repeated);
        }
        let data = Bytes::from(data_str);
        let shard = Shard {
            id: ShardId::from_hash(blake3::hash(&data)),
            data: data.clone(),
            size: data.len(),
            encrypted: false,
        };
        
        // First compression should discover and mine patterns
        let compressed = compressor.compress_shard(&shard).unwrap();
        
        // Check that patterns were discovered
        assert!(compressor.dictionary.cache_size().unwrap() > 0 || 
                compressor.dictionary.pending_count().unwrap() > 0);
    }

    #[test]
    fn test_compression_stats() {
        let compressor = ZkcCompressor::new();
        
        let shard1 = CompressedShard {
            original_id: ShardId([0u8; 32]),
            compressed_data: Bytes::from_static(b"compressed1"),
            original_size: 100,
            compressed_size: 50,
            compression_ratio: 2.0,
            pattern_ids_used: Vec::new(),
            is_compressed: true,
        };
        
        let shard2 = CompressedShard {
            original_id: ShardId([1u8; 32]),
            compressed_data: Bytes::from_static(b"compressed2"),
            original_size: 200,
            compressed_size: 100,
            compression_ratio: 2.0,
            pattern_ids_used: Vec::new(),
            is_compressed: true,
        };
        
        let stats = compressor.get_compression_stats(&[shard1, shard2]);
        
        assert_eq!(stats.total_shards, 2);
        assert_eq!(stats.total_original_size, 300);
        assert_eq!(stats.total_compressed_size, 150);
        assert_eq!(stats.total_savings, 150);
        assert_eq!(stats.avg_compression_ratio, 2.0);
        assert_eq!(stats.compression_percentage(), 50.0);
    }
}
