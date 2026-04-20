//! # SovereignCodec ↔ ModelCompressor Bridge
//!
//! Provides production implementations of `lib_neural_mesh::distributed::ModelCompressor`
//! using SovereignCodec (BWT→MTF→RLE→Range). This is the **self-referential** core of
//! the Sovereign Network: the AI's own model weights are compressed by the same codec
//! the AI helps optimize.
//!
//! ## Why it lives here
//!
//! `lib-neural-mesh` defines the `ModelCompressor` trait but cannot depend on
//! `lib-compression` (that would be circular). `lib-compression` already depends
//! on `lib-neural-mesh`, so it can implement the trait here. The `zhtp` runtime
//! layer injects these implementations at boot: see `NeuralMeshComponent::start()`.
//!
//! ## Implementations
//!
//! | Struct | Codec | Notes |
//! |--------|-------|-------|
//! | [`SovereignCodecCompressor`] | SFC7 | Standard BWT→MTF→RLE→O(1)Range, lossless |
//! | [`AdaptiveCodecCompressor`]  | SFC9 | SFC7 + neural-mesh learned params, lossless |

use lib_neural_mesh::distributed::ModelCompressor;
use crate::sovereign_codec::SovereignCodec;
use crate::CodecParams;

// ─── Standard SFC7 Compressor ────────────────────────────────────────

/// Lossless model weight compression using SovereignCodec SFC7.
///
/// Pipeline: BWT → MTF → RLE → Adaptive Order-1 Range Coder.
/// Completely lossless — `decompress(compress(x)) == x` for all inputs.
pub struct SovereignCodecCompressor;

impl ModelCompressor for SovereignCodecCompressor {
    fn compress(&self, data: &[u8]) -> Vec<u8> {
        SovereignCodec::encode(data)
    }

    fn decompress(&self, data: &[u8]) -> std::result::Result<Vec<u8>, String> {
        SovereignCodec::decode(data)
    }

    fn name(&self) -> &str {
        "SovereignCodec-SFC7"
    }
}

// ─── Adaptive SFC9 Compressor ────────────────────────────────────────

/// Content-adaptive lossless compression using SovereignCodec SFC9.
///
/// Uses neural-mesh learned parameters (rescale_limit, freq_step, init_freq_zero)
/// for the range coder to achieve better compression on model weight distributions.
/// Falls back to SFC7 behaviour when parameters are at their defaults.
pub struct AdaptiveCodecCompressor {
    params: CodecParams,
}

impl AdaptiveCodecCompressor {
    /// Create with explicit codec parameters.
    pub fn with_params(params: CodecParams) -> Self {
        Self { params }
    }

    /// Create from neural-mesh learned parameters (rescale_limit, freq_step, init_freq_zero).
    pub fn from_learned(rescale_limit: u32, freq_step: u8, init_freq_zero: u8) -> Self {
        Self {
            params: CodecParams {
                rescale_limit,
                freq_step,
                init_freq_zero,
            },
        }
    }
}

impl ModelCompressor for AdaptiveCodecCompressor {
    fn compress(&self, data: &[u8]) -> Vec<u8> {
        SovereignCodec::encode_with_params(data, &self.params)
    }

    fn decompress(&self, data: &[u8]) -> std::result::Result<Vec<u8>, String> {
        // decode() handles both SFC7 and SFC9 transparently
        SovereignCodec::decode(data)
    }

    fn name(&self) -> &str {
        "SovereignCodec-SFC9-Adaptive"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sovereign_codec_compressor_roundtrip() {
        let compressor = SovereignCodecCompressor;
        // Use larger data — BWT needs sufficient context for compression gains
        let data: Vec<u8> = b"The Sovereign Network compresses its own AI model weights \
                     using the same BWT-MTF-RLE-Range codec the AI helps optimize. \
                     This is repeated to give the codec enough context for compression. \
                     The Sovereign Network compresses its own AI model weights \
                     using the same BWT-MTF-RLE-Range codec the AI helps optimize."
            .to_vec();

        let compressed = compressor.compress(&data);
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data, "SovereignCodecCompressor must be perfectly lossless");
        // With enough repetition, BWT-based compression should shrink the data
        assert!(compressed.len() < data.len(), "Should compress repeated text data");
    }

    #[test]
    fn sovereign_codec_compressor_lossless_binary() {
        let compressor = SovereignCodecCompressor;
        // Simulate model weight bytes (f32 values as bytes)
        let weights: Vec<u8> = (0..256u32)
            .flat_map(|i| (i as f32 * 0.001).to_le_bytes())
            .collect();

        let compressed = compressor.compress(&weights);
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, weights, "Must be bit-perfect lossless for model weights");
    }

    #[test]
    fn adaptive_codec_compressor_roundtrip() {
        let compressor = AdaptiveCodecCompressor::from_learned(4096, 4u8, 1u8);
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();

        let compressed = compressor.compress(&data);
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data, "AdaptiveCodecCompressor must be perfectly lossless");
    }

    #[test]
    fn compressor_names() {
        assert_eq!(SovereignCodecCompressor.name(), "SovereignCodec-SFC7");
        assert_eq!(
            AdaptiveCodecCompressor::from_learned(4096, 4u8, 1u8).name(),
            "SovereignCodec-SFC9-Adaptive"
        );
    }
}
