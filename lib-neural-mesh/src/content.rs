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
}
