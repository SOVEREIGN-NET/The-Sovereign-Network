//! Neural network-based semantic compression and deduplication
//! OPTIMIZED with SIMD acceleration and optional ONNX neural embeddings
//!
//! ## Architecture
//!
//! When an ONNX embedding model is loaded (via [`NeuroCompressor::load_model`]),
//! raw byte data is pre-processed into a fixed-size feature vector and run through
//! a trained neural network for learned embeddings.  This produces far richer
//! semantic representations than hand-crafted features alone.
//!
//! When no model is available the engine falls back to a high-quality statistical
//! pipeline: BLAKE3 hash features + byte-histogram + entropy + n-grams + structural
//! features, all extracted in parallel via Rayon.
//!
//! Both paths produce L2-normalised embeddings suitable for cosine-similarity
//! nearest-neighbour deduplication.

use crate::error::{NeuralMeshError, Result};
use crate::inference::InferenceEngine;
use rayon::prelude::*;
use std::path::Path;

/// Embedding vector for content similarity
pub type Embedding = Vec<f32>;

/// Content embedding engine for semantic deduplication.
///
/// Generates fixed-dimension embeddings from raw byte data using a hybrid approach:
/// - BLAKE3 cryptographic hash features (32 dimensions)
/// - Statistical features: byte histogram, entropy, variance (parallel)
/// - N-gram frequency features (parallel)
/// - Structural features: compressibility, run-length, zero/FF density
///
/// Embeddings are L2-normalized to unit length for efficient cosine similarity.
/// The engine leverages Rayon for parallel feature extraction on large inputs.
///
/// # Alias
/// Also available as [`ContentEmbedder`] for clarity.
pub struct NeuroCompressor {
    enabled: bool,
    similarity_threshold: f32,
    embedding_dim: usize,
    /// Optional ONNX neural embedding model (used when loaded)
    inference_engine: Option<InferenceEngine>,
}

impl std::fmt::Debug for NeuroCompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NeuroCompressor")
            .field("enabled", &self.enabled)
            .field("embedding_dim", &self.embedding_dim)
            .field("has_model", &self.inference_engine.is_some())
            .finish()
    }
}

impl NeuroCompressor {
    /// Create new neural compressor
    pub fn new() -> Self {
        Self {
            enabled: false,
            similarity_threshold: 0.998, // 99.8% similarity threshold
            embedding_dim: 512,
            inference_engine: None,
        }
    }
    
    /// Create with custom embedding dimension
    pub fn with_dimension(embedding_dim: usize) -> Self {
        Self {
            enabled: false,
            similarity_threshold: 0.998,
            embedding_dim,
            inference_engine: None,
        }
    }

    /// Enable neural compression
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Set similarity threshold (0.0 - 1.0)
    pub fn set_threshold(&mut self, threshold: f32) {
        self.similarity_threshold = threshold.clamp(0.0, 1.0);
    }

    /// Load an ONNX embedding model for neural-quality embeddings.
    ///
    /// When a model is loaded, [`embed()`](Self::embed) runs the data through the
    /// trained network instead of the statistical fallback pipeline.
    /// The model should accept a 1-D float feature vector and output a 1-D
    /// embedding vector of `embedding_dim` dimensions.
    ///
    /// # Example
    /// ```no_run
    /// # use lib_neural_mesh::NeuroCompressor;
    /// let mut nc = NeuroCompressor::new();
    /// nc.enable();
    /// nc.load_model("models/content-embeddings.onnx").unwrap();
    /// ```
    pub fn load_model<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let mut engine = InferenceEngine::new();
        engine.load_model(path)?;
        self.inference_engine = Some(engine);
        tracing::info!("NeuroCompressor: ONNX embedding model loaded — neural path active");
        Ok(())
    }

    /// Check whether a neural ONNX model is loaded
    pub fn has_model(&self) -> bool {
        self.inference_engine.as_ref().map_or(false, |e| e.is_loaded())
    }

    /// Generate embedding for content.
    ///
    /// **Neural path** (when ONNX model is loaded): extracts a compact feature
    /// vector from the raw data, runs it through the trained neural network, and
    /// returns the model's output embedding.
    ///
    /// **Statistical fallback** (no model): uses BLAKE3 hash features, byte
    /// histogram, entropy, n-gram frequencies and structural features, all
    /// computed in parallel via Rayon.
    ///
    /// Both paths produce L2-normalised embeddings of `embedding_dim` dimensions.
    pub fn embed(&self, data: &[u8]) -> Result<Embedding> {
        if !self.enabled {
            return Err(NeuralMeshError::InferenceFailed(
                "Neural compressor not enabled".to_string(),
            ));
        }

        // ── Neural path ─────────────────────────────────────────────────
        if let Some(ref engine) = self.inference_engine {
            if engine.is_loaded() {
                return self.embed_neural(engine, data);
            }
        }

        // ── Statistical fallback ─────────────────────────────────────────
        self.embed_statistical(data)
    }

    /// Neural embedding: build a feature vector from the raw data, then run
    /// it through the ONNX model to obtain a learned representation.
    fn embed_neural(&self, engine: &InferenceEngine, data: &[u8]) -> Result<Embedding> {
        // Build a compact input feature vector the model was trained on.
        // We use the same statistical features we'd compute for fallback,
        // but pack them into a dense input tensor for the neural network.
        let input_features = self.build_model_input(data);

        // Run the model forward pass
        let mut embedding = engine.infer(&input_features)?;

        // Ensure correct dimensionality
        embedding.resize(self.embedding_dim, 0.0);

        // L2-normalise
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            let inv = 1.0 / norm;
            for val in &mut embedding {
                *val *= inv;
            }
        }

        Ok(embedding)
    }

    /// Build a fixed-size feature vector from raw bytes for neural model input.
    ///
    /// This encodes the data as a 512-D float tensor capturing:
    ///   [0..32]   BLAKE3 hash features
    ///   [32..96]  byte-histogram (64 bins)
    ///   [96..224] n-gram features (128 bins)
    ///   [224..352] statistical features (128 dims)
    ///   [352..512] structural features (padding to 512)
    fn build_model_input(&self, data: &[u8]) -> Vec<f32> {
        let target_dim = 512; // fixed input size for the model
        let mut features = Vec::with_capacity(target_dim);

        // 1. BLAKE3 hash (32 dimensions)
        let hash = blake3::hash(data);
        for &byte in hash.as_bytes() {
            features.push(byte as f32 / 255.0);
        }

        // 2. Byte histogram (64 bins) - parallel
        let histogram: Vec<u32> = data.par_chunks(4096)
            .map(|chunk| {
                let mut h = vec![0u32; 64];
                for &b in chunk { h[(b >> 2) as usize] += 1; }
                h
            })
            .reduce(
                || vec![0u32; 64],
                |mut acc, local| { for (a, b) in acc.iter_mut().zip(&local) { *a += *b; } acc },
            );
        let total = data.len().max(1) as f32;
        features.extend(histogram.iter().map(|&c| c as f32 / total));

        // 3. N-gram features (128 dims)
        features.extend(self.extract_ngram_features(data, 128));

        // 4. Statistical features (128 dims)
        features.extend(self.extract_statistical_features(data, 128));

        // 5. Structural padding
        let remaining = target_dim.saturating_sub(features.len());
        if remaining > 0 {
            features.extend(self.extract_structural_features(data, remaining));
        }

        features.truncate(target_dim);
        features.resize(target_dim, 0.0);
        features
    }

    /// Statistical embedding (no neural model).
    fn embed_statistical(&self, data: &[u8]) -> Result<Embedding> {

        // Generate multi-scale content-aware embedding in parallel
        let mut embedding = Vec::with_capacity(self.embedding_dim);
        
        // 1. Cryptographic hash features (256 dimensions)
        let hash = blake3::hash(data);
        let hash_bytes = hash.as_bytes();
        for byte in &hash_bytes[..] {
            embedding.push(*byte as f32 / 255.0);
        }
        
        // 2-4. Extract all features in parallel
        let (stat_features, (ngram_features, struct_features)) = rayon::join(
            || self.extract_statistical_features(data, 128),
            || rayon::join(
                || self.extract_ngram_features(data, 128),
                || {
                    let remaining = self.embedding_dim.saturating_sub(256 + 128 + 128);
                    if remaining > 0 {
                        self.extract_structural_features(data, remaining)
                    } else {
                        Vec::new()
                    }
                }
            )
        );
        
        embedding.extend(stat_features);
        embedding.extend(ngram_features);
        embedding.extend(struct_features);
        
        // Normalize embedding to unit length using SIMD-friendly operations
        let norm: f32 = embedding.par_iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            let inv_norm = 1.0 / norm;
            embedding.par_iter_mut().for_each(|val| *val *= inv_norm);
        }
        
        // Truncate or pad to exact dimension
        embedding.resize(self.embedding_dim, 0.0);
        
        Ok(embedding)
    }
    
    /// Extract statistical features from data - OPTIMIZED
    fn extract_statistical_features(&self, data: &[u8], dim: usize) -> Vec<f32> {
        let mut features = Vec::with_capacity(dim);
        
        if data.is_empty() {
            return vec![0.0; dim];
        }
        
        // Byte distribution histogram (first 64 dimensions) - PARALLEL
        let histogram: Vec<u32> = data.par_chunks(4096)
            .map(|chunk| {
                let mut local_hist = vec![0u32; 64];
                for &byte in chunk {
                    local_hist[(byte >> 2) as usize] += 1;
                }
                local_hist
            })
            .reduce(
                || vec![0u32; 64],
                |mut acc, local| {
                    for (a, b) in acc.iter_mut().zip(local.iter()) {
                        *a += *b;
                    }
                    acc
                },
            );
        
        let total = data.len() as f32;
        features.extend(histogram.iter().map(|&count| count as f32 / total));
        
        // Calculate statistics in parallel
        let (entropy, mean) = rayon::join(
            || self.calculate_entropy(data),
            || {
                let sum: u64 = data.par_iter().map(|&b| b as u64).sum();
                (sum as f32) / total
            },
        );
        
        features.push(entropy);
        features.push(mean / 255.0);
        
        // Variance calculation (parallel)
        let var = data.par_iter()
            .map(|&b| (b as f32 - mean).powi(2))
            .sum::<f32>() / total;
        features.push(var.sqrt() / 255.0);
        
        // Sequential differences - sample for performance
        let sample_size = data.len().min(10000);
        let mut diff_sum = 0.0;
        for i in 1..sample_size {
            diff_sum += (data[i] as f32 - data[i-1] as f32).abs();
        }
        features.push((diff_sum / sample_size as f32) / 255.0);
        
        // Pad to dimension
        features.resize(dim, 0.0);
        features
    }
    
    /// Extract n-gram features from data - OPTIMIZED
    fn extract_ngram_features(&self, data: &[u8], dim: usize) -> Vec<f32> {
        let mut features = vec![0.0; dim];
        
        if data.len() < 2 {
            return features;
        }
        
        // Sample bigrams from data in parallel chunks
        let chunk_size = (data.len() / rayon::current_num_threads()).max(1000);
        let partial_features: Vec<Vec<f32>> = data.par_chunks(chunk_size)
            .filter_map(|chunk| {
                if chunk.len() < 2 {
                    return None;
                }
                
                let mut local_features = vec![0.0; dim];
                for i in 0..chunk.len() - 1 {
                    let bigram = ((chunk[i] as usize) << 8) | (chunk[i + 1] as usize);
                    let idx = bigram % dim;
                    local_features[idx] += 1.0;
                }
                Some(local_features)
            })
            .collect();
        
        // Merge partial results
        for partial in partial_features {
            for (i, val) in partial.iter().enumerate() {
                features[i] += val;
            }
        }
        
        // Normalize
        let sum: f32 = features.iter().sum();
        if sum > 0.0 {
            let inv_sum = 1.0 / sum;
            features.par_iter_mut().for_each(|val| *val *= inv_sum);
        }
        
        features
    }
    
    /// Extract structural features from data
    fn extract_structural_features(&self, data: &[u8], dim: usize) -> Vec<f32> {
        let mut features = Vec::with_capacity(dim);
        
        if data.is_empty() {
            return vec![0.0; dim];
        }
        
        // File size indicators
        features.push((data.len() as f32).ln() / 20.0); // Log-scaled size
        
        // Compressibility estimate (based on repeated patterns)
        let compressibility = self.estimate_compressibility(data);
        features.push(compressibility);
        
        // Randomness indicators
        let mut zero_count = 0;
        let mut ff_count = 0;
        for &byte in data.iter().take(10000) {
            if byte == 0 { zero_count += 1; }
            if byte == 0xFF { ff_count += 1; }
        }
        features.push(zero_count as f32 / data.len().min(10000) as f32);
        features.push(ff_count as f32 / data.len().min(10000) as f32);
        
        // Run length encoding estimate
        let mut run_count = 0;
        let mut run_length = 1;
        for i in 1..data.len().min(10000) {
            if data[i] == data[i - 1] {
                run_length += 1;
            } else {
                if run_length > 3 {
                    run_count += 1;
                }
                run_length = 1;
            }
        }
        features.push(run_count as f32 / 10000.0);
        
        // Pad to dimension
        features.resize(dim, 0.0);
        features
    }
    
    /// Calculate Shannon entropy of data
    fn calculate_entropy(&self, data: &[u8]) -> f32 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f32;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy / 8.0 // Normalize to [0, 1]
    }
    
    /// Estimate data compressibility
    fn estimate_compressibility(&self, data: &[u8]) -> f32 {
        // Simple compressibility estimate based on byte uniqueness
        let sample_size = data.len().min(10000);
        let mut unique = std::collections::HashSet::new();
        
        for &byte in data.iter().take(sample_size) {
            unique.insert(byte);
        }
        
        1.0 - (unique.len() as f32 / 256.0)
    }

    /// Calculate cosine similarity between embeddings
    pub fn similarity(&self, a: &Embedding, b: &Embedding) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }

        let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }

        dot_product / (norm_a * norm_b)
    }

    /// Check if two embeddings are semantically similar
    pub fn is_similar(&self, a: &Embedding, b: &Embedding) -> bool {
        self.similarity(a, b) >= self.similarity_threshold
    }
    
    /// Calculate L2 distance between embeddings
    pub fn distance(&self, a: &Embedding, b: &Embedding) -> f32 {
        if a.len() != b.len() {
            return f32::MAX;
        }
        
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f32>()
            .sqrt()
    }
}

impl Default for NeuroCompressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for `NeuroCompressor` — preferred name for new code.
pub type ContentEmbedder = NeuroCompressor;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compressor_creation() {
        let compressor = NeuroCompressor::new();
        assert!(!compressor.enabled);
        assert_eq!(compressor.similarity_threshold, 0.998);
    }

    #[test]
    fn test_similarity_calculation() {
        let compressor = NeuroCompressor::new();
        
        // Identical vectors should have similarity 1.0
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![1.0, 2.0, 3.0];
        assert!((compressor.similarity(&a, &b) - 1.0).abs() < 0.001);
        
        // Orthogonal vectors should have similarity 0.0
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(compressor.similarity(&a, &b).abs() < 0.001);
    }

    #[test]
    fn test_similarity_threshold() {
        let mut compressor = NeuroCompressor::new();
        compressor.set_threshold(0.95);
        
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![1.0, 2.0, 3.1]; // Very similar but not identical
        
        let sim = compressor.similarity(&a, &b);
        assert!(sim > 0.99); // Should be very similar
        assert!(compressor.is_similar(&a, &b)); // Should pass threshold
    }
    
    #[test]
    fn test_embedding_generation() {
        let mut compressor = NeuroCompressor::new();
        compressor.enable();
        
        let data = b"Hello, this is test data for embedding generation!";
        let embedding = compressor.embed(data).unwrap();
        
        assert_eq!(embedding.len(), 512); // Default dimension
        
        // Embedding should be normalized
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01); // Should be unit length
    }
    
    #[test]
    fn test_similar_content_embeddings() {
        let mut compressor = NeuroCompressor::new();
        compressor.enable();
        
        let data1 = b"The quick brown fox jumps over the lazy dog";
        let data2 = b"The quick brown fox jumps over the lazy dog";
        
        let emb1 = compressor.embed(data1).unwrap();
        let emb2 = compressor.embed(data2).unwrap();
        
        let similarity = compressor.similarity(&emb1, &emb2);
        assert!(similarity > 0.99); // Identical content should be very similar
    }
    
    #[test]
    fn test_different_content_embeddings() {
        let mut compressor = NeuroCompressor::new();
        compressor.enable();
        
        let data1 = b"This is some random text data";
        let data2 = b"Completely different content here with other words";
        
        let emb1 = compressor.embed(data1).unwrap();
        let emb2 = compressor.embed(data2).unwrap();
        
        let similarity = compressor.similarity(&emb1, &emb2);
        assert!(similarity < 0.99); // Different content should be less similar
    }
    
    #[test]
    fn test_distance_calculation() {
        let compressor = NeuroCompressor::new();
        
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        
        let distance = compressor.distance(&a, &b);
        assert!((distance - 2.0_f32.sqrt()).abs() < 0.001);
    }
    
    #[test]
    fn test_custom_dimension() {
        let mut compressor = NeuroCompressor::with_dimension(256);
        compressor.enable();
        
        let data = b"Test data";
        let embedding = compressor.embed(data).unwrap();
        
        assert_eq!(embedding.len(), 256);
    }
}
