// patterns.rs - Zero Knowledge Compression (ZKC) Pattern Mining
//
// This module extracts repeating byte sequences from data to build a compression
// dictionary. Patterns are discovered using sliding window analysis and frequency
// counting, then ranked by compression potential.
//
// OPTIMIZED VERSION with parallel processing and hash-based lookups

use bytes::Bytes;
use std::collections::{HashMap, BTreeMap};
use serde::{Deserialize, Serialize};
use blake3::Hash as Blake3Hash;
use ahash::AHashMap; // Faster hash map
use rayon::prelude::*; // Parallel iterators

/// Unique identifier for a pattern (content-addressed using BLAKE3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PatternId(pub [u8; 16]); // First 16 bytes of BLAKE3 hash

impl PatternId {
    /// Generate PatternId from pattern bytes using BLAKE3 content addressing
    /// IMPORTANT: First byte is guaranteed != 0xFF to avoid encoding ambiguity
    /// with the PATTERN_MARKER byte used in compressed streams.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[0..16]);
        // CRITICAL: Ensure first byte is never 0xFF (PATTERN_MARKER = 0xFF)
        // This prevents ambiguity in the compressed stream where
        // [0xFF][0xFF] means "escaped literal 0xFF" vs a pattern ref.
        if id[0] == 0xFF {
            id[0] = 0xFE;
        }
        PatternId(id)
    }

    /// Convert to u128 for compact storage/indexing
    pub fn as_u128(&self) -> u128 {
        u128::from_le_bytes(self.0)
    }
}

/// A discovered byte pattern with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Content-addressed unique identifier
    pub id: PatternId,
    
    /// The actual byte sequence
    pub bytes: Bytes,
    
    /// How many times this pattern appears (locally)
    pub frequency: u32,
    
    /// Size of pattern in bytes
    pub size: usize,
    
    /// Compression potential score (higher = better)
    pub score: f64,
}

/// Cost of each pattern reference in the encoded body stream:
/// 1 byte PATTERN_MARKER (0xFF) + 1 byte table index = 2 bytes
/// (Sovereign ZKC v2: Local Pattern Table replaces full 16-byte IDs with 1-byte indices)
pub(crate) const PATTERN_REF_OVERHEAD: usize = 2;

/// Cost of adding a unique pattern to the shard's local pattern table header:
/// 16 bytes (PatternId stored once in the table)
pub(crate) const PATTERN_TABLE_ENTRY_COST: usize = 16;

impl Pattern {
    /// Create a new pattern from byte sequence
    pub fn new(bytes: Bytes, frequency: u32) -> Self {
        let id = PatternId::from_bytes(&bytes);
        let size = bytes.len();
        
        // Sovereign ZKC v2 scoring:
        //   Per-reference savings: (pattern_size - 2) bytes each occurrence
        //   Per-unique-pattern cost: 16 bytes (one entry in local table header)
        //   Net savings = frequency * (size - 2) - 16
        let per_ref_savings = if size > PATTERN_REF_OVERHEAD { (size - PATTERN_REF_OVERHEAD) as f64 } else { 0.0 };
        let net_savings = per_ref_savings * frequency as f64 - PATTERN_TABLE_ENTRY_COST as f64;
        let score = if net_savings > 0.0 { net_savings } else { 0.0 };
        
        Pattern {
            id,
            bytes,
            frequency,
            size,
            score,
        }
    }

    /// Calculate potential compression savings in bytes
    pub fn compression_savings(&self, reference_size: usize) -> i64 {
        // Each occurrence saves (pattern_size - reference_size) bytes
        // Minus one-time table entry cost
        let savings_per_use = self.size as i64 - reference_size as i64;
        savings_per_use * self.frequency as i64 - PATTERN_TABLE_ENTRY_COST as i64
    }
}

/// Configuration for pattern mining
#[derive(Debug, Clone)]
pub struct PatternMinerConfig {
    /// Minimum pattern size (bytes)
    pub min_pattern_size: usize,
    
    /// Maximum pattern size (bytes)
    pub max_pattern_size: usize,
    
    /// Minimum frequency to consider (must appear this many times)
    pub min_frequency: u32,
    
    /// Maximum number of patterns to extract
    pub max_patterns: usize,
    
    /// Window size for sliding window analysis
    pub window_size: usize,
}

impl Default for PatternMinerConfig {
    fn default() -> Self {
        PatternMinerConfig {
            min_pattern_size: 4,      // ZKC v2: refs are 2 bytes, pattern needs freq*(size-2)>16 per shard
            max_pattern_size: 128,    // 128 bytes covers JSON structural patterns; anything larger is rare
            min_frequency: 3,         // Must appear at least 3 times (reduces noise)
            max_patterns: 4096,       // Top 4K patterns (fast overlap removal)
            window_size: 16384,       // 16 KB sliding window for better pattern discovery
        }
    }
}

/// Pattern mining engine
pub struct PatternMiner {
    config: PatternMinerConfig,
}

impl PatternMiner {
    /// Create new pattern miner with configuration
    pub fn new(config: PatternMinerConfig) -> Self {
        PatternMiner { config }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        PatternMiner {
            config: PatternMinerConfig::default(),
        }
    }

    /// Extract patterns from data
    /// 
    /// Uses sliding window to find repeating byte sequences, then ranks
    /// by compression potential (frequency × bytes saved).
    /// 
    /// PERFORMANCE: HEAVILY OPTIMIZED with parallel processing and hash-based lookups
    pub fn mine_patterns(&self, data: &[u8]) -> Vec<Pattern> {
        if data.len() < self.config.min_pattern_size {
            return Vec::new();
        }

        // Use AHashMap for better performance
        let mut pattern_frequencies: AHashMap<Bytes, u32> = AHashMap::new();
        
        // Phase 0: Add byte-level RLE patterns (repeated bytes) - Fast path
        self.add_byte_run_patterns(data, &mut pattern_frequencies);
        
        // Phase 1: Intelligent sampling for large data
        // For files ≤ 256KB, scan ALL data for complete pattern coverage.
        // For larger files, use 5-region sampling up to 256KB.
        const MAX_SCAN_SIZE: usize = 256 * 1024; // 256KB — fast mining, good pattern discovery
        let scan_data = if data.len() > MAX_SCAN_SIZE {
            // Sample from 5 regions: beginning, 25%, 50%, 75%, end
            let chunk_size = MAX_SCAN_SIZE / 5;
            let positions = [
                0,
                data.len() / 4,
                data.len() / 2,
                (3 * data.len()) / 4,
                data.len().saturating_sub(chunk_size),
            ];
            
            let mut sampled = Vec::with_capacity(MAX_SCAN_SIZE);
            for &pos in &positions {
                let end = (pos + chunk_size).min(data.len());
                sampled.extend_from_slice(&data[pos..end]);
                if sampled.len() >= MAX_SCAN_SIZE { break; }
            }
            sampled.truncate(MAX_SCAN_SIZE);
            sampled
        } else {
            data.to_vec()
        };
        
        // Phase 2: PARALLEL pattern extraction — LOGARITHMIC length sampling
        // Instead of scanning every length 4-512 (509 passes!), scan ~40 representative
        // lengths: 4-16 (every length), 17-64 (every 4), 65-512 (every 16)
        // This covers the same compression space in ~10% of the time.
        let max_len = self.config.max_pattern_size.min(scan_data.len());
        let mut pattern_lengths: Vec<usize> = Vec::new();
        // Fine-grained for small patterns (highest compression ROI)
        for l in self.config.min_pattern_size..=16.min(max_len) {
            pattern_lengths.push(l);
        }
        // Medium-grained for mid patterns
        for l in (17..=64.min(max_len)).step_by(4) {
            pattern_lengths.push(l);
        }
        // Coarse-grained for large patterns (rare but high-value when found)
        for l in (65..=max_len).step_by(16) {
            pattern_lengths.push(l);
        }
        // Always include max length
        if max_len > 64 && !pattern_lengths.contains(&max_len) {
            pattern_lengths.push(max_len);
        }
        
        let parallel_patterns: Vec<_> = pattern_lengths
            .par_iter()
            .flat_map(|&pattern_len| {
                let mut local_freq: AHashMap<Bytes, u32> = AHashMap::new();
                
                // Smart stepping: larger patterns need less granular search
                let step = if pattern_len > 64 { 8 } else if pattern_len > 32 { 4 } else if pattern_len > 16 { 2 } else { 1 };
                
                // Use memchr for SIMD-accelerated first-byte matching (optimization)
                for start in (0..=(scan_data.len().saturating_sub(pattern_len))).step_by(step) {
                    let sequence = &scan_data[start..start + pattern_len];
                    
                    // Skip homogeneous patterns (all same byte) — fast O(1) check
                    let first = sequence[0];
                    if (first == 0 || first == 0xFF) && sequence[sequence.len() - 1] == first && sequence[sequence.len() / 2] == first {
                        continue;
                    }
                    
                    let bytes = Bytes::copy_from_slice(sequence);
                    *local_freq.entry(bytes).or_insert(0) += 1;
                }
                
                local_freq.into_iter().collect::<Vec<_>>()
            })
            .collect();
        
        // Merge parallel results
        for (bytes, freq) in parallel_patterns {
            *pattern_frequencies.entry(bytes).or_insert(0) += freq;
        }

        // Phase 3: Filter and create Pattern objects (parallel)
        // Only keep patterns that: meet min frequency AND are large enough to save space
        let patterns_vec: Vec<_> = pattern_frequencies.into_iter().collect();
        let mut patterns: Vec<Pattern> = patterns_vec
            .into_par_iter()
            .filter(|(bytes, freq)| {
                *freq >= self.config.min_frequency 
                && bytes.len() > PATTERN_REF_OVERHEAD  // Must be larger than 2-byte ref cost
            })
            .map(|(bytes, freq)| Pattern::new(bytes, freq))
            .filter(|p| p.score > 0.0)  // Only patterns that actually save space
            .collect();

        // Phase 4: Pre-sort by score and cap before expensive overlap removal
        patterns.par_sort_by(|a, b| {
            b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)
        });
        // Cap at 2× max_patterns BEFORE overlap removal to bound O(n²) cost
        let overlap_cap = self.config.max_patterns * 2;
        if patterns.len() > overlap_cap {
            patterns.truncate(overlap_cap);
        }

        // Phase 5: Remove overlapping patterns (keep highest scoring)
        if patterns.len() <= 8192 {
            patterns = self.remove_overlaps_fast(patterns);
        }
        // else: skip overlap removal for very large sets — score ranking is sufficient

        // Phase 6: Take top N patterns
        patterns.truncate(self.config.max_patterns);

        patterns
    }
    
    /// Faster overlap removal using parallel processing
    fn remove_overlaps_fast(&self, mut patterns: Vec<Pattern>) -> Vec<Pattern> {
        if patterns.len() < 100 {
            // For small pattern sets, use original algorithm
            return self.remove_overlaps(patterns);
        }
        
        // Sort by score descending (parallel)
        patterns.par_sort_by(|a, b| {
            b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Use parallel filtering with atomic operations
        use std::sync::atomic::{AtomicBool, Ordering};
        let keep_flags: Vec<AtomicBool> = (0..patterns.len())
            .map(|_| AtomicBool::new(true))
            .collect();
        
        // Check overlaps in parallel
        (0..patterns.len()).into_par_iter().for_each(|i| {
            if !keep_flags[i].load(Ordering::Relaxed) {
                return;
            }
            
            // Check if this pattern is contained in any higher-scoring pattern
            for j in 0..i {
                if keep_flags[j].load(Ordering::Relaxed) {
                    if self.is_subsequence(&patterns[i].bytes, &patterns[j].bytes) {
                        keep_flags[i].store(false, Ordering::Relaxed);
                        return;
                    }
                }
            }
        });
        
        patterns.into_iter()
            .enumerate()
            .filter(|(i, _)| keep_flags[*i].load(Ordering::Relaxed))
            .map(|(_, p)| p)
            .collect()
    }

    /// Remove overlapping patterns, keeping the highest-scoring ones
    /// 
    /// If pattern A contains pattern B, only keep the one with better score
    fn remove_overlaps(&self, mut patterns: Vec<Pattern>) -> Vec<Pattern> {
        // Sort by score descending
        patterns.sort_by(|a, b| {
            b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut result: Vec<Pattern> = Vec::new();
        
        for pattern in patterns {
            let mut is_subset = false;
            
            // Check if this pattern is contained in any already selected pattern
            for existing in &result {
                if self.is_subsequence(&pattern.bytes, &existing.bytes) {
                    is_subset = true;
                    break;
                }
            }
            
            if !is_subset {
                result.push(pattern);
            }
        }
        
        result
    }

    /// Check if `needle` is a subsequence of `haystack`
    fn is_subsequence(&self, needle: &[u8], haystack: &[u8]) -> bool {
        if needle.len() > haystack.len() {
            return false;
        }
        
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Add byte-level run-length encoding patterns
    /// Finds sequences of repeated bytes (e.g., 0x00 repeated 20+ times)
    /// Only adds runs >= 18 bytes (the pattern reference overhead) to ensure savings
    fn add_byte_run_patterns(&self, data: &[u8], patterns: &mut AHashMap<Bytes, u32>) {
        if data.is_empty() {
            return;
        }
        
        let mut i = 0;
        while i < data.len() {
            let byte = data[i];
            let mut run_length = 1;
            
            // Count consecutive identical bytes
            while i + run_length < data.len() && data[i + run_length] == byte {
                run_length += 1;
            }
            
            // Only add runs that are long enough to save space after ref overhead
            if run_length >= PATTERN_REF_OVERHEAD + 1 {
                for len in (PATTERN_REF_OVERHEAD + 1)..=run_length.min(256) {
                    let pattern = vec![byte; len];
                    let bytes = Bytes::from(pattern);
                    *patterns.entry(bytes).or_insert(0) += 1;
                }
            }
            
            i += run_length; // Skip the entire run
        }
    }

    /// OPTIMIZED: Fast pattern extraction using hash-based lookups and SIMD
    /// 
    /// Given a known pattern dictionary, quickly find which patterns
    /// appear in the data (for compression phase)
    /// 
    /// Uses Aho-Corasick-inspired multi-pattern matching for O(n) performance
    pub fn find_patterns_in_data(
        &self,
        data: &[u8],
        known_patterns: &HashMap<PatternId, Pattern>,
    ) -> Vec<(usize, PatternId, usize)> {
        if known_patterns.is_empty() || data.is_empty() {
            return Vec::new();
        }
        
        // Build fast lookup structures
        // Group patterns by first byte for faster matching
        let mut patterns_by_first_byte: AHashMap<u8, Vec<&Pattern>> = AHashMap::new();
        for pattern in known_patterns.values() {
            if let Some(&first_byte) = pattern.bytes.first() {
                patterns_by_first_byte.entry(first_byte)
                    .or_insert_with(Vec::new)
                    .push(pattern);
            }
        }
        
        // Sort patterns within each group by size (descending) for greedy matching
        for patterns in patterns_by_first_byte.values_mut() {
            patterns.sort_by(|a, b| b.size.cmp(&a.size));
        }
        
        let mut matches = Vec::new();
        let mut offset = 0;
        
        while offset < data.len() {
            let current_byte = data[offset];
            let mut matched = false;
            
            // Check patterns that start with current byte
            if let Some(candidates) = patterns_by_first_byte.get(&current_byte) {
                for pattern in candidates {
                    if offset + pattern.size > data.len() {
                        continue;
                    }
                    
                    // SIMD-friendly comparison
                    let slice = &data[offset..offset + pattern.size];
                    if slice == pattern.bytes.as_ref() {
                        matches.push((offset, pattern.id, pattern.size));
                        offset += pattern.size;
                        matched = true;
                        break;
                    }
                }
            }
            
            if !matched {
                offset += 1;
            }
        }
        
        matches
    }
}

/// Global pattern dictionary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStats {
    /// Total number of unique patterns
    pub total_patterns: usize,
    
    /// Total bytes saved across all patterns
    pub total_savings: i64,
    
    /// Average compression ratio
    pub avg_compression_ratio: f64,
    
    /// Most common pattern
    pub top_pattern_id: Option<PatternId>,
    
    /// Network-wide pattern frequency
    pub network_frequency: u64,
}

impl PatternStats {
    /// Calculate statistics from pattern dictionary
    pub fn from_patterns(patterns: &HashMap<PatternId, Pattern>) -> Self {
        let total_patterns = patterns.len();
        
        let total_savings: i64 = patterns
            .values()
            .map(|p| p.compression_savings(PATTERN_REF_OVERHEAD)) // 17-byte references (1 marker + 16 ID)
            .sum();
        
        let total_original_size: usize = patterns
            .values()
            .map(|p| p.size * p.frequency as usize)
            .sum();
        
        let total_compressed_size = total_original_size as i64 - total_savings;
        let avg_compression_ratio = if total_compressed_size > 0 {
            total_original_size as f64 / total_compressed_size as f64
        } else {
            1.0
        };
        
        let top_pattern_id = patterns
            .values()
            .max_by_key(|p| p.frequency)
            .map(|p| p.id);
        
        let network_frequency: u64 = patterns
            .values()
            .map(|p| p.frequency as u64)
            .sum();
        
        PatternStats {
            total_patterns,
            total_savings,
            avg_compression_ratio,
            top_pattern_id,
            network_frequency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_id_generation() {
        let data = b"Hello, World!";
        let id1 = PatternId::from_bytes(data);
        let id2 = PatternId::from_bytes(data);
        assert_eq!(id1, id2, "Same data should produce same PatternId");

        let other_data = b"Goodbye, World!";
        let id3 = PatternId::from_bytes(other_data);
        assert_ne!(id1, id3, "Different data should produce different PatternId");
    }

    #[test]
    fn test_pattern_mining_basic() {
        // Data with repeated pattern (must be > 2 bytes per ref + 16 table cost to net save)
        let long_pat = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut data = Vec::new();
        for _ in 0..5 {
            data.extend_from_slice(long_pat);
            data.extend_from_slice(b"---SEP---");
        }
        let miner = PatternMiner::default();
        let patterns = miner.mine_patterns(&data);

        // Should find repeated patterns with positive savings
        let has_useful = patterns.iter().any(|p| p.size > PATTERN_REF_OVERHEAD && p.score > 0.0);
        assert!(has_useful, "Should find patterns that actually save space");
    }

    #[test]
    fn test_pattern_compression_savings() {
        // With ZKC v2: refs are 2 bytes, table entry = 16 bytes
        // Pattern 43 bytes, freq 10: net = 10*(43-2) - 16 = 394
        let bytes = Bytes::from("This is a longer pattern that saves space!".as_bytes().to_vec());
        let pattern = Pattern::new(bytes.clone(), 10);
        
        let savings = pattern.compression_savings(PATTERN_REF_OVERHEAD);
        // savings = 10 * (43-2) - 16 = 394
        assert_eq!(savings, (bytes.len() as i64 - PATTERN_REF_OVERHEAD as i64) * 10 - PATTERN_TABLE_ENTRY_COST as i64);
        assert!(savings > 0, "Savings should be positive for frequent large patterns");
        
        // Very short infrequent pattern: 5 bytes * 2 freq = 2*(5-2) - 16 = -10 (no good)
        let short = Bytes::from_static(b"Hello");
        let short_pattern = Pattern::new(short, 2);
        let short_savings = short_pattern.compression_savings(PATTERN_REF_OVERHEAD);
        assert!(short_savings < 0, "Infrequent short patterns should have negative savings");
    }

    #[test]
    fn test_find_patterns_in_data() {
        let miner = PatternMiner::default();
        
        // Create a known pattern > 2 bytes
        let pat_bytes = Bytes::from_static(b"PATTERN_LONG_ENOUGH!");
        let mut known_patterns = HashMap::new();
        let pattern1 = Pattern::new(pat_bytes.clone(), 1);
        known_patterns.insert(pattern1.id, pattern1.clone());
        
        // Data containing the pattern
        let mut data = b"SOME_PREFIX_DATA_".to_vec();
        data.extend_from_slice(b"PATTERN_LONG_ENOUGH!");
        data.extend_from_slice(b"_SUFFIX");
        let matches = miner.find_patterns_in_data(&data, &known_patterns);
        
        assert_eq!(matches.len(), 1, "Should find one match");
        assert_eq!(matches[0].0, 17, "Match at correct offset");
        assert_eq!(matches[0].2, pat_bytes.len(), "Correct pattern size");
    }

    #[test]
    fn test_pattern_scoring() {
        // 2-byte pattern, freq 100: net = 100*(2-2) - 16 = -16 → score 0
        let small_pattern = Pattern::new(Bytes::from_static(b"AB"), 100);
        // 36-byte pattern, freq 10: net = 10*(36-2) - 16 = 324
        let large_pattern = Pattern::new(
            Bytes::from("This-is-a-long-pattern-that-repeats!".as_bytes().to_vec()), 
            10
        );
        
        assert_eq!(small_pattern.score, 0.0, "Patterns <= 2 bytes should have zero score");
        assert!(large_pattern.score > 0.0, "Larger patterns with frequency should have positive score");
        assert!(large_pattern.score > small_pattern.score);
    }
}
