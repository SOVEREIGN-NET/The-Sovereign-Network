//! Content analysis, classification, and compression feedback
//!
//! This module provides:
//! - Fast O(n) content-type detection (JSON, text, binary, compressed, etc.)
//! - `ContentProfile`: learned statistical signature of data
//! - `CompressionFeedback`: post-compression metrics fed back into the neural mesh
//!   for RL Router training and anomaly baseline improvement.
//!
//! The RL Router uses content profiles as its state vector and compression
//! ratios as reward signals, learning which content types compress well and
//! predicting outcomes for network resource allocation.

use crate::compressor::{Embedding, NeuroCompressor};
use crate::semantic_channeling::{ContentTagBinding, SemanticTag, TagId};
use serde::{Deserialize, Serialize};

/// Detected content type — fast O(n) classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    /// JSON / NDJSON (structured, high compressibility)
    Json,
    /// Plain text / logs / CSV (moderate compressibility)
    Text,
    /// HTML / XML / SVG (structured markup)
    Markup,
    /// Already-compressed (zip, gzip, zstd, png, jpg, mp4, etc.)
    Compressed,
    /// Executable / binary (variable compressibility)
    Binary,
    /// Unknown / mixed content
    Unknown,
}

impl ContentType {
    /// Classify content type from raw bytes.
    ///
    /// Runs a fast heuristic scan: checks magic bytes, then samples the
    /// first 4 KB for byte distribution and structure.  O(n) with n capped
    /// at 4096 — effectively O(1).
    pub fn detect(data: &[u8]) -> Self {
        if data.is_empty() {
            return ContentType::Unknown;
        }

        // ── Magic-byte detection (O(1)) ──────────────────────────────
        if data.len() >= 4 {
            let magic4 = &data[..4];
            // ZIP / PKZIP
            if magic4[..2] == [0x50, 0x4B] { return ContentType::Compressed; }
            // Gzip
            if magic4[..2] == [0x1F, 0x8B] { return ContentType::Compressed; }
            // Zstd
            if magic4 == [0x28, 0xB5, 0x2F, 0xFD] { return ContentType::Compressed; }
            // PNG
            if data.len() >= 8 && data[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
                return ContentType::Compressed;
            }
            // JPEG
            if magic4[..3] == [0xFF, 0xD8, 0xFF] { return ContentType::Compressed; }
            // MP4 / MOV (ftyp box)
            if data.len() >= 8 && &data[4..8] == b"ftyp" { return ContentType::Compressed; }
            // RIFF (AVI, WebP, WAV)
            if magic4 == *b"RIFF" { return ContentType::Compressed; }
            // BMP — uncompressed raster image (magic: "BM")
            if magic4[..2] == [0x42, 0x4D] { return ContentType::Binary; }
            // TIFF — uncompressed raster image (II or MM byte order)
            if magic4[..2] == [0x49, 0x49] || magic4[..2] == [0x4D, 0x4D] { return ContentType::Binary; }
            // XZ
            if data.len() >= 6 && data[..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
                return ContentType::Compressed;
            }
            // Bzip2
            if magic4[..3] == [0x42, 0x5A, 0x68] { return ContentType::Compressed; }
            // ELF binary
            if magic4 == [0x7F, 0x45, 0x4C, 0x46] { return ContentType::Binary; }
            // PE binary (MZ)
            if magic4[..2] == [0x4D, 0x5A] { return ContentType::Binary; }
            // Wasm
            if magic4 == [0x00, 0x61, 0x73, 0x6D] { return ContentType::Binary; }
        }

        // ── Content scan: sample first 4 KB ──────────────────────────
        let scan = &data[..data.len().min(4096)];
        let len = scan.len();

        // Count printable-ASCII, whitespace, control bytes
        let mut printable = 0u32;
        let mut whitespace = 0u32;
        let mut control = 0u32;
        let mut high = 0u32; // bytes >= 0x80
        let mut braces = 0u32; // { } [ ]
        let mut angles = 0u32; // < >
        for &b in scan {
            match b {
                0x20..=0x7E => printable += 1,
                b'\t' | b'\n' | b'\r' => whitespace += 1,
                0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F => control += 1,
                0x80..=0xFF => high += 1,
                _ => {}
            }
            if b == b'{' || b == b'}' || b == b'[' || b == b']' { braces += 1; }
            if b == b'<' || b == b'>' { angles += 1; }
        }

        let text_ratio = (printable + whitespace) as f64 / len as f64;
        let control_ratio = control as f64 / len as f64;
        let high_ratio = high as f64 / len as f64;

        // Already-compressed data has near-uniform byte distribution
        // (high entropy, many bytes >= 0x80, low text ratio)
        if high_ratio > 0.30 && text_ratio < 0.50 {
            return ContentType::Compressed;
        }

        // High control byte content → binary
        if control_ratio > 0.10 {
            return ContentType::Binary;
        }

        // Text-like content (>85% printable + whitespace)
        if text_ratio > 0.85 {
            // Check for JSON: starts with { or [ after optional whitespace
            let trimmed = scan.iter().skip_while(|&&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r');
            if let Some(&first) = trimmed.clone().next() {
                if (first == b'{' || first == b'[') && braces >= 2 {
                    return ContentType::Json;
                }
            }
            // Check for HTML/XML
            if angles >= 4 {
                let has_tag = scan.windows(2).any(|w| w[0] == b'<' && w[1].is_ascii_alphabetic());
                if has_tag { return ContentType::Markup; }
            }
            return ContentType::Text;
        }

        // Mixed but mostly text
        if text_ratio > 0.60 {
            return ContentType::Text;
        }

        ContentType::Binary
    }

    /// Human-readable label
    pub fn label(&self) -> &'static str {
        match self {
            ContentType::Json => "JSON",
            ContentType::Text => "Text",
            ContentType::Markup => "Markup (HTML/XML)",
            ContentType::Compressed => "Already Compressed",
            ContentType::Binary => "Binary",
            ContentType::Unknown => "Unknown",
        }
    }

    /// Whether lossless compression is expected to be effective
    pub fn is_compressible(&self) -> bool {
        matches!(self, ContentType::Json | ContentType::Text | ContentType::Markup | ContentType::Binary)
    }
}

/// Statistical content profile — the RL Router's state vector
///
/// Captures the data's structure in a compact feature vector so the
/// neural mesh can learn content-type → compression-outcome mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentProfile {
    /// Detected content type
    pub content_type: ContentType,
    /// Shannon entropy (0.0 – 8.0 bits/byte)
    pub entropy: f32,
    /// Size in bytes
    pub size: usize,
    /// Fraction of bytes that are printable ASCII
    pub text_ratio: f32,
    /// Number of unique byte values (0-256)
    pub unique_bytes: u16,
    /// Average byte-to-byte delta (smoothness indicator)
    pub avg_delta: f32,
}

impl ContentProfile {
    /// Build a content profile from raw data.  O(n) single pass.
    pub fn analyze(data: &[u8]) -> Self {
        let content_type = ContentType::detect(data);

        if data.is_empty() {
            return Self {
                content_type,
                entropy: 0.0,
                size: 0,
                text_ratio: 0.0,
                unique_bytes: 0,
                avg_delta: 0.0,
            };
        }

        // Single-pass stats: histogram + printable count + delta sum
        let mut counts = [0u32; 256];
        let mut printable = 0u32;
        let mut delta_sum = 0u64;
        let mut prev = data[0];
        counts[data[0] as usize] += 1;
        if data[0].is_ascii_graphic() || data[0] == b' ' { printable += 1; }

        for &b in &data[1..] {
            counts[b as usize] += 1;
            if b.is_ascii_graphic() || b == b' ' { printable += 1; }
            delta_sum += (b as i16 - prev as i16).unsigned_abs() as u64;
            prev = b;
        }

        let len = data.len() as f64;
        let entropy = {
            let mut h = 0.0f64;
            for &c in &counts {
                if c > 0 {
                    let p = c as f64 / len;
                    h -= p * p.log2();
                }
            }
            h as f32
        };
        let unique_bytes = counts.iter().filter(|&&c| c > 0).count() as u16;

        Self {
            content_type,
            entropy,
            size: data.len(),
            text_ratio: printable as f32 / data.len() as f32,
            unique_bytes,
            avg_delta: delta_sum as f32 / (data.len() - 1).max(1) as f32,
        }
    }

    /// Convert to a fixed-size feature vector for the RL Router.
    ///
    /// The 8-dimensional vector is:
    /// `[content_type_onehot(5), entropy/8, text_ratio, log2(size)/30]`
    pub fn to_state_vector(&self) -> Vec<f32> {
        let mut v = vec![0.0f32; 8];
        // One-hot content type (5 dims)
        let idx = match self.content_type {
            ContentType::Json => 0,
            ContentType::Text => 1,
            ContentType::Markup => 2,
            ContentType::Compressed => 3,
            ContentType::Binary | ContentType::Unknown => 4,
        };
        v[idx] = 1.0;
        v[5] = self.entropy / 8.0;            // normalised entropy
        v[6] = self.text_ratio;                // already [0,1]
        v[7] = (self.size as f32).ln() / 30.0; // log-scaled size
        v
    }
}

// ─── Semantic Tag Generation ─────────────────────────────────────────

/// Configuration for semantic tag generation from content profiles.
#[derive(Debug, Clone)]
pub struct TagGenerationConfig {
    /// Number of sub-tags to generate per content item via k-means clustering
    /// of the embedding dimensions. Default: 3
    pub num_sub_tags: usize,
    /// Minimum cosine similarity for two sub-tags to be considered distinct.
    /// Below this, sub-tags are merged. Default: 0.85
    pub dedup_threshold: f32,
}

impl Default for TagGenerationConfig {
    fn default() -> Self {
        Self {
            num_sub_tags: 3,
            dedup_threshold: 0.85,
        }
    }
}

impl ContentProfile {
    /// Generate semantic tags from this content profile using a NeuroCompressor
    /// to produce embeddings, then clustering the embedding into discrete
    /// topic-level and sub-topic-level tags.
    ///
    /// Returns:
    /// - A primary tag capturing the full embedding
    /// - N sub-tags capturing different facets of the content
    ///
    /// The NeuroCompressor must be enabled. Raw data is needed for embedding
    /// generation — the profile alone doesn't hold the raw bytes.
    pub fn generate_semantic_tags(
        &self,
        compressor: &NeuroCompressor,
        data: &[u8],
        config: &TagGenerationConfig,
    ) -> crate::error::Result<Vec<SemanticTag>> {
        // Generate full embedding from the raw data
        let embedding = compressor.embed(data)?;
        let mut tags = Vec::with_capacity(1 + config.num_sub_tags);

        // Primary tag: the full embedding reduced to 32-D via SemanticTag::from_embedding
        let primary_label = format!("{}:{:.2}e", self.content_type.label(), self.entropy);
        let primary = SemanticTag::from_embedding(&embedding, Some(primary_label));
        tags.push(primary);

        // Sub-tags: partition the embedding into facets via stride-based clustering.
        // Each sub-tag captures a different "slice" of the semantic space.
        if config.num_sub_tags > 0 && embedding.len() >= config.num_sub_tags {
            let sub_embeddings = partition_embedding(&embedding, config.num_sub_tags);

            for (i, sub_emb) in sub_embeddings.iter().enumerate() {
                let sub_label = format!("facet-{}", i);
                let sub_tag = SemanticTag::from_embedding(sub_emb, Some(sub_label));

                // Dedup: only add if sufficiently different from existing tags
                let dominated = tags.iter().any(|existing| {
                    existing.similarity(&sub_tag) > config.dedup_threshold
                });
                if !dominated {
                    tags.push(sub_tag);
                }
            }
        }

        Ok(tags)
    }

    /// Generate a complete ContentTagBinding for a piece of data.
    ///
    /// This is the full pipeline: content → embedding → semantic tags → binding
    /// with ZK-style commitment. The binding maps the content's BLAKE3 hash to
    /// its semantic tags and DHT shard locations.
    pub fn generate_tag_binding(
        &self,
        compressor: &NeuroCompressor,
        data: &[u8],
        shard_ids: Vec<[u8; 32]>,
        config: &TagGenerationConfig,
    ) -> crate::error::Result<ContentTagBinding> {
        let tags = self.generate_semantic_tags(compressor, data, config)?;
        let content_id: [u8; 32] = *blake3::hash(data).as_bytes();
        let tag_ids: Vec<TagId> = tags.iter().map(|t| t.tag_id).collect();

        Ok(ContentTagBinding::new(content_id, tag_ids, shard_ids))
    }

    /// Convenience: generate tags with default config.
    pub fn generate_semantic_tags_default(
        &self,
        compressor: &NeuroCompressor,
        data: &[u8],
    ) -> crate::error::Result<Vec<SemanticTag>> {
        self.generate_semantic_tags(compressor, data, &TagGenerationConfig::default())
    }
}

/// Partition a high-dimensional embedding into N sub-embeddings.
/// Each sub-embedding captures a different "facet" of the content by
/// taking interleaved elements (round-robin partition), preserving
/// cross-dimensional relationships while reducing dimensionality.
fn partition_embedding(embedding: &Embedding, n: usize) -> Vec<Embedding> {
    let mut partitions: Vec<Vec<f32>> = vec![Vec::new(); n];

    for (i, &val) in embedding.iter().enumerate() {
        partitions[i % n].push(val);
    }

    // Pad each partition to the full embedding dimension (zero-padded)
    // so SemanticTag::from_embedding's reduce_embedding works correctly
    let target_len = embedding.len();
    for part in &mut partitions {
        let orig_len = part.len();
        part.resize(target_len, 0.0);
        // Scale up non-zero values to compensate for the sparsity
        let scale = (target_len as f32 / orig_len as f32).sqrt();
        for v in part.iter_mut().take(orig_len) {
            *v *= scale;
        }
    }

    partitions
}

/// Post-compression feedback fed back into the neural mesh.
///
/// The RL Router observes these results as *rewards* so it learns which
/// content types yield good compression, enabling accurate network-wide
/// ratio prediction and resource planning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionFeedback {
    /// Content profile of the input
    pub profile: ContentProfile,
    /// Compression ratio achieved (original / compressed)
    pub ratio: f64,
    /// Total storage including witness
    pub total_ratio: f64,
    /// Compression wall-clock time in seconds
    pub time_secs: f64,
    /// Throughput in MB/s
    pub throughput_mbps: f64,
    /// Whether integrity roundtrip passed
    pub integrity_ok: bool,
    /// Number of shards
    pub shard_count: usize,
    /// How many shards actually compressed (ratio > 1)
    pub shards_compressed: usize,
}

impl CompressionFeedback {
    /// Compute RL reward signal from this feedback.
    ///
    /// Higher reward = better compression ratio + fast speed.
    /// Negative reward if integrity failed (catastrophic).
    pub fn rl_reward(&self) -> f32 {
        if !self.integrity_ok {
            return -10.0; // severe penalty
        }
        // reward = log2(ratio) + speed_bonus
        //   log2(8:1) = 3.0, log2(1:1) = 0.0
        //   speed_bonus = min(throughput / 100, 1.0)
        let ratio_reward = (self.ratio.max(1.0)).log2() as f32;
        let speed_bonus = (self.throughput_mbps as f32 / 100.0).min(1.0);
        ratio_reward + speed_bonus
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_json() {
        let json = br#"{"name": "Alice", "age": 30, "items": [1,2,3]}"#;
        assert_eq!(ContentType::detect(json), ContentType::Json);
    }

    #[test]
    fn test_detect_text() {
        let text = b"The quick brown fox jumps over the lazy dog. This is plain text content.";
        assert_eq!(ContentType::detect(text), ContentType::Text);
    }

    #[test]
    fn test_detect_compressed() {
        let gz = &[0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]; // gzip magic
        assert_eq!(ContentType::detect(gz), ContentType::Compressed);
    }

    #[test]
    fn test_detect_binary() {
        // ELF magic
        let elf = &[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        assert_eq!(ContentType::detect(elf), ContentType::Binary);
    }

    #[test]
    fn test_content_profile_json() {
        let json = br#"{"transactions":[{"id":"tx001","amount":42.5},{"id":"tx002","amount":99.9}]}"#;
        let profile = ContentProfile::analyze(json);
        assert_eq!(profile.content_type, ContentType::Json);
        assert!(profile.entropy > 0.0);
        assert!(profile.text_ratio > 0.9);
    }

    #[test]
    fn test_state_vector_dimensions() {
        let data = b"test data";
        let profile = ContentProfile::analyze(data);
        let sv = profile.to_state_vector();
        assert_eq!(sv.len(), 8);
        // All values should be in a reasonable range
        for &v in &sv {
            assert!(v >= 0.0 && v <= 2.0, "state value {} out of range", v);
        }
    }

    #[test]
    fn test_compression_feedback_reward() {
        let profile = ContentProfile::analyze(b"test");
        let fb = CompressionFeedback {
            profile,
            ratio: 8.0,
            total_ratio: 7.5,
            time_secs: 0.5,
            throughput_mbps: 50.0,
            integrity_ok: true,
            shard_count: 1,
            shards_compressed: 1,
        };
        let reward = fb.rl_reward();
        assert!(reward > 0.0, "reward should be positive for good compression");
    }

    #[test]
    fn test_integrity_failure_penalty() {
        let profile = ContentProfile::analyze(b"test");
        let fb = CompressionFeedback {
            profile,
            ratio: 8.0,
            total_ratio: 7.5,
            time_secs: 0.5,
            throughput_mbps: 50.0,
            integrity_ok: false,
            shard_count: 1,
            shards_compressed: 1,
        };
        assert!(fb.rl_reward() < 0.0, "integrity failure should give negative reward");
    }

    // ── Semantic Tag Generation Tests ──

    #[test]
    fn test_generate_semantic_tags() {
        let mut compressor = crate::compressor::NeuroCompressor::new();
        compressor.enable();

        let data = b"The quick brown fox is a JSON payload with transactions";
        let profile = ContentProfile::analyze(data);
        let tags = profile.generate_semantic_tags_default(&compressor, data).unwrap();

        // Should have at least 1 primary tag
        assert!(!tags.is_empty(), "should generate at least one tag");
        // Primary tag should have a label containing content type
        assert!(tags[0].label.is_some());
        // All tags should have 32-D semantic vectors
        for tag in &tags {
            assert_eq!(tag.semantic_vector.len(), 32);
        }
    }

    #[test]
    fn test_generate_tag_binding() {
        let mut compressor = crate::compressor::NeuroCompressor::new();
        compressor.enable();

        let data = b"Test content for tag binding generation";
        let profile = ContentProfile::analyze(data);
        let shard_ids = vec![[0x42; 32], [0x43; 32]];

        let binding = profile.generate_tag_binding(
            &compressor, data, shard_ids, &TagGenerationConfig::default()
        ).unwrap();

        // Binding should reference the correct content hash
        let expected_hash: [u8; 32] = *blake3::hash(data).as_bytes();
        assert_eq!(binding.content_id, expected_hash);
        // Should have at least one tag
        assert!(!binding.tag_ids.is_empty());
        // Should have the shard IDs we provided
        assert_eq!(binding.shard_ids.len(), 2);
        // Commitment should verify
        assert!(binding.verify_commitment());
    }

    #[test]
    fn test_different_content_produces_different_tags() {
        let mut compressor = crate::compressor::NeuroCompressor::new();
        compressor.enable();

        let data_a = b"Compression algorithms use BWT and MTF for better entropy";
        let data_b = b"Routing protocols optimize latency across mesh networks";

        let profile_a = ContentProfile::analyze(data_a);
        let profile_b = ContentProfile::analyze(data_b);

        let tags_a = profile_a.generate_semantic_tags_default(&compressor, data_a).unwrap();
        let tags_b = profile_b.generate_semantic_tags_default(&compressor, data_b).unwrap();

        // Primary tags should have different tag IDs
        assert_ne!(tags_a[0].tag_id, tags_b[0].tag_id,
            "different content should produce different primary tags");
    }

    #[test]
    fn test_tag_generation_config_custom() {
        let mut compressor = crate::compressor::NeuroCompressor::new();
        compressor.enable();

        let data = b"Custom configuration test data with enough bytes to analyze";
        let profile = ContentProfile::analyze(data);

        let config = TagGenerationConfig {
            num_sub_tags: 5,
            dedup_threshold: 0.95, // very strict dedup
        };
        let tags = profile.generate_semantic_tags(&compressor, data, &config).unwrap();

        // Should have primary + potentially more sub-tags (some may be deduped)
        assert!(!tags.is_empty());
        // With strict dedup, we might get fewer sub-tags
        assert!(tags.len() <= 6, "1 primary + at most 5 sub-tags");
    }

    #[test]
    fn test_partition_embedding() {
        let embedding: Vec<f32> = (0..512).map(|i| i as f32).collect();
        let parts = partition_embedding(&embedding, 3);

        assert_eq!(parts.len(), 3);
        // Each partition should be padded to 512
        for part in &parts {
            assert_eq!(part.len(), 512);
        }
    }
}
