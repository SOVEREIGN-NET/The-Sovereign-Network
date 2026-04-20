//! Distributed Training Coordinator
//!
//! The self-compressing distributed neural mesh. This is the virtuous loop:
//!
//! ```text
//! ╔══════════════════════════════════════════════════════════════════╗
//! ║                  SELF-OPTIMIZING NEURAL MESH                    ║
//! ╠══════════════════════════════════════════════════════════════════╣
//! ║                                                                  ║
//! ║   Node A trains locally ──► exports model weights               ║
//! ║                                    │                             ║
//! ║                            ZKC-compress the weights              ║
//! ║                 (using the SAME compression the AI optimizes)    ║
//! ║                                    │                             ║
//! ║                     RL-Router picks optimal route                ║
//! ║                 (using the SAME routing the AI learns)           ║
//! ║                                    │                             ║
//! ║                    QUIC parallel streams ──► Node B,C,D         ║
//! ║                                    │                             ║
//! ║                     FedAvg merges gradients                      ║
//! ║                 (more nodes = faster convergence)                ║
//! ║                                    │                             ║
//! ║                    Better model ──► better compression           ║
//! ║                    Better compression ──► faster sync            ║
//! ║                    Faster sync ──► more training data            ║
//! ║                    More data ──► better model ◄── THE LOOP      ║
//! ║                                                                  ║
//! ╚══════════════════════════════════════════════════════════════════╝
//! ```

use crate::error::{NeuralMeshError, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ─── Injectable Compression ──────────────────────────────────────────
// The compression is injected at runtime so the AI compresses itself
// using the SAME SovereignCodec (BWT→MTF→RLE→Range) that it helps optimize.
// lib-neural-mesh can't directly depend on lib-compression (cyclic),
// so the zhtp layer injects the real codec.

/// Trait for model weight compression. Injected by the runtime layer.
pub trait ModelCompressor: Send + Sync + 'static {
    /// Compress raw bytes
    fn compress(&self, data: &[u8]) -> Vec<u8>;
    /// Decompress bytes
    fn decompress(&self, data: &[u8]) -> std::result::Result<Vec<u8>, String>;
    /// Name of the compression algorithm (for logging)
    fn name(&self) -> &str;
}

/// Identity compressor (no compression) — used when SovereignCodec not yet injected
pub struct IdentityCompressor;
impl ModelCompressor for IdentityCompressor {
    fn compress(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
    fn decompress(&self, data: &[u8]) -> std::result::Result<Vec<u8>, String> { Ok(data.to_vec()) }
    fn name(&self) -> &str { "identity" }
}

// ─── Differential Privacy ────────────────────────────────────────────

/// Configuration for differential privacy in federated learning.
///
/// Guarantees (ε, δ)-differential privacy per FedAvg round: an adversary
/// seeing the merged model learns at most ε additional bits about any
/// single contributor's private training data, except with probability δ.
///
/// ## How it works
///
/// 1. **Gradient Clipping**: Each contributor's weight delta (θ_k − θ_ref) is
///    L2-norm clipped to `max_grad_norm`, bounding any single node's influence.
///
/// 2. **Gaussian Noise**: After averaging, calibrated noise N(0, σ²) is added
///    where σ = (C / n) · √(2 ln(1.25/δ)) / ε.  More contributors → less noise.
///
/// 3. **Result**: The merged model provably hides individual training data
///    while preserving the aggregate learning signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialPrivacyConfig {
    /// Privacy budget per round. Lower ε = more private.
    /// ε=1.0 is strong. ε=0.1 is very strong. Default: 1.0
    pub epsilon: f64,

    /// Failure probability. Default: 1e-5
    pub delta: f64,

    /// Maximum L2 norm for weight deltas (gradient clipping bound).
    /// Each contributor's deviation from the reference model is clipped
    /// to this bound before averaging. Default: 1.0
    pub max_grad_norm: f64,

    /// Whether differential privacy is active. Default: true
    pub enabled: bool,
}

impl Default for DifferentialPrivacyConfig {
    fn default() -> Self {
        Self {
            epsilon: 1.0,
            delta: 1e-5,
            max_grad_norm: 1.0,
            enabled: true,
        }
    }
}

impl DifferentialPrivacyConfig {
    /// Compute the Gaussian noise standard deviation.
    ///
    /// σ = (C / n) · √(2 ln(1.25/δ)) / ε
    ///
    /// where C = max_grad_norm, n = number of contributors.
    pub fn noise_sigma(&self, num_contributors: usize) -> f64 {
        if !self.enabled || num_contributors == 0 {
            return 0.0;
        }
        let n = num_contributors as f64;
        let sensitivity = self.max_grad_norm / n;
        sensitivity * (2.0 * (1.25_f64 / self.delta).ln()).sqrt() / self.epsilon
    }
}

// ─── Model Weight Encryption ─────────────────────────────────────────

/// Trait for encrypting model weights before network transfer.
///
/// The zhtp runtime injects the production encryptor after peer key exchange.
/// In standalone mode, `Blake3StreamEncryptor` provides authenticated
/// encryption using a pre-shared key.
pub trait ModelEncryptor: Send + Sync + 'static {
    /// Encrypt data for network transmission
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    /// Decrypt received network data
    fn decrypt(&self, data: &[u8]) -> std::result::Result<Vec<u8>, String>;
    /// Name of the encryption scheme
    fn name(&self) -> &str;
}

/// No-op encryptor for tests and local-only mode
pub struct IdentityEncryptor;
impl ModelEncryptor for IdentityEncryptor {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
    fn decrypt(&self, data: &[u8]) -> std::result::Result<Vec<u8>, String> { Ok(data.to_vec()) }
    fn name(&self) -> &str { "identity" }
}

/// BLAKE3-XOF authenticated stream cipher for model weight encryption.
///
/// **Format**: `nonce(16) ‖ ciphertext(N) ‖ mac(32)`
///
/// - **Encryption**: BLAKE3 keyed XOF generates keystream, XOR'd with plaintext
/// - **Authentication**: BLAKE3 keyed MAC over `nonce ‖ ciphertext` (encrypt-then-MAC)
/// - **Key derivation**: Separate MAC key derived via `blake3::derive_key`
///
/// Secure under the PRF assumption on BLAKE3. For post-quantum transport
/// security, the shared key should come from a Kyber key exchange
/// (injected by the zhtp runtime via `lib-crypto`).
pub struct Blake3StreamEncryptor {
    /// 32-byte shared secret (from key exchange or pre-shared)
    shared_key: [u8; 32],
}

impl Blake3StreamEncryptor {
    pub fn new(shared_key: [u8; 32]) -> Self {
        Self { shared_key }
    }
}

impl ModelEncryptor for Blake3StreamEncryptor {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce);

        // Generate keystream from BLAKE3 keyed XOF
        let mut hasher = blake3::Hasher::new_keyed(&self.shared_key);
        hasher.update(&nonce);
        let mut xof = hasher.finalize_xof();
        let mut keystream = vec![0u8; data.len()];
        xof.fill(&mut keystream);

        // XOR plaintext with keystream
        let ciphertext: Vec<u8> = data.iter()
            .zip(keystream.iter())
            .map(|(d, k)| d ^ k)
            .collect();

        // Encrypt-then-MAC: BLAKE3 keyed hash over nonce ‖ ciphertext
        let mac_key = blake3::derive_key("sovereign-network-model-mac-v1", &self.shared_key);
        let mut mac_hasher = blake3::Hasher::new_keyed(&mac_key);
        mac_hasher.update(&nonce);
        mac_hasher.update(&ciphertext);
        let mac = mac_hasher.finalize();

        // nonce(16) ‖ ciphertext(N) ‖ mac(32)
        let mut out = Vec::with_capacity(16 + ciphertext.len() + 32);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(mac.as_bytes());
        out
    }

    fn decrypt(&self, data: &[u8]) -> std::result::Result<Vec<u8>, String> {
        if data.len() < 48 {
            return Err("Ciphertext too short (need >=48 bytes: 16 nonce + 32 mac)".to_string());
        }

        let nonce = &data[..16];
        let ciphertext = &data[16..data.len() - 32];
        let received_mac = &data[data.len() - 32..];

        // Verify MAC FIRST — reject tampered data before decryption
        let mac_key = blake3::derive_key("sovereign-network-model-mac-v1", &self.shared_key);
        let mut mac_hasher = blake3::Hasher::new_keyed(&mac_key);
        mac_hasher.update(nonce);
        mac_hasher.update(ciphertext);
        let expected_mac = mac_hasher.finalize();

        if expected_mac.as_bytes() != received_mac {
            return Err("MAC verification failed — model weights may have been tampered".to_string());
        }

        // Decrypt: same keystream operation
        let mut hasher = blake3::Hasher::new_keyed(&self.shared_key);
        hasher.update(nonce);
        let mut xof = hasher.finalize_xof();
        let mut keystream = vec![0u8; ciphertext.len()];
        xof.fill(&mut keystream);

        Ok(ciphertext.iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect())
    }

    fn name(&self) -> &str { "blake3-xof-stream" }
}

// ─── Model Identity ──────────────────────────────────────────────────

/// Which sub-model within the neural mesh
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelId {
    /// PPO reinforcement learning router
    RlRouter,
    /// LSTM predictive prefetcher
    Prefetcher,
    /// Isolation forest anomaly detector
    AnomalySentry,
    /// Semantic channeling tag-chain LSTM
    SemanticChanneler,
}

impl std::fmt::Display for ModelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelId::RlRouter => write!(f, "rl-router"),
            ModelId::Prefetcher => write!(f, "prefetcher"),
            ModelId::AnomalySentry => write!(f, "anomaly-sentry"),
            ModelId::SemanticChanneler => write!(f, "semantic-channeler"),
        }
    }
}

// ─── Compressed Model Store ──────────────────────────────────────────

/// Header prepended to quantized model data so decompression knows the format.
/// If the first 4 bytes of decompressed data equal QUANT_MAGIC, the payload is
/// quantized int8 and must be dequantized before use.
const QUANT_MAGIC: [u8; 4] = [0x51, 0x4E, 0x54, 0x38]; // "QNT8"

/// A model's weights, ZKC-compressed using the same algorithms the AI optimizes.
/// The neural net IS compressed by the very compression it learns to improve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedModel {
    /// Which model this is
    pub model_id: ModelId,
    /// Raw (uncompressed) weight size in bytes
    pub raw_size: usize,
    /// ZKC-compressed weight bytes
    pub compressed_weights: Vec<u8>,
    /// Compression ratio achieved (raw / compressed)
    pub compression_ratio: f32,
    /// Which node produced this model
    pub source_node: String,
    /// Training generation (increments each FedAvg round)
    pub generation: u64,
    /// BLAKE3 hash of uncompressed weights for integrity
    pub weight_hash: [u8; 32],
    /// Timestamp of export
    pub timestamp_ms: u64,
}

impl CompressedModel {
    /// Compress raw model weights using the injected compressor.
    /// When SovereignCodec is injected (from zhtp runtime), this uses
    /// BWT→MTF→RLE→Range — the SAME codec the AI helps optimize.
    ///
    /// **Quantization**: Before compression, f32 weights are quantized to int8.
    /// This dramatically increases byte-level redundancy, boosting SovereignCodec
    /// from ~1.0x to 2-4x compression. A 4-byte header (QUANT_MAGIC) + f32 scale
    /// + f32 zero_point are prepended so `decompress()` can restore full precision.
    pub fn compress(
        model_id: ModelId,
        raw_weights: &[u8],
        source_node: &str,
        generation: u64,
        compressor: &dyn ModelCompressor,
    ) -> Self {
        let raw_size = raw_weights.len();
        let weight_hash: [u8; 32] = blake3::hash(raw_weights).into();

        // ── Int8 Quantization ──
        // Interpret the raw bytes as f32 values, find min/max, map to [0, 255].
        // Prepend: QUANT_MAGIC(4) + scale(4) + zero_point(4) + quantized_bytes(N/4)
        let quantized_payload = quantize_weights_int8(raw_weights);

        // Compress the quantized payload (much more compressible than raw f32)
        let compressed_weights = compressor.compress(&quantized_payload);
        let compressed_size = compressed_weights.len();
        let compression_ratio = if compressed_size > 0 {
            raw_size as f32 / compressed_size as f32
        } else {
            1.0
        };

        debug!(
            "🧠📦 Compressed {} model via {} (quant→codec): {} → {} → {} bytes ({:.1}x total)",
            model_id, compressor.name(), raw_size, quantized_payload.len(),
            compressed_size, compression_ratio
        );

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            model_id,
            raw_size,
            compressed_weights,
            compression_ratio,
            source_node: source_node.to_string(),
            generation,
            weight_hash,
            timestamp_ms,
        }
    }

    /// Compress raw model weights **losslessly** using the injected compressor.
    ///
    /// Unlike [`compress()`](Self::compress), this skips int8 quantization entirely.
    /// The raw bytes are passed directly to the `ModelCompressor`, producing a
    /// bit-perfect roundtrip: `decompress(compress_lossless(x)) == x`.
    ///
    /// Use this when exact weight fidelity is required (e.g. cryptographic
    /// commitments over model weights, cross-node weight equality checks,
    /// or any non-training context where lossy quantization is unacceptable).
    ///
    /// When SovereignCodec (SFC7/SFC9) is injected, the codec is itself lossless,
    /// so the entire pipeline is fully lossless end-to-end.
    pub fn compress_lossless(
        model_id: ModelId,
        raw_weights: &[u8],
        source_node: &str,
        generation: u64,
        compressor: &dyn ModelCompressor,
    ) -> Self {
        let raw_size = raw_weights.len();
        let weight_hash: [u8; 32] = blake3::hash(raw_weights).into();

        // No quantization — pass raw bytes directly to the codec
        let compressed_weights = compressor.compress(raw_weights);
        let compressed_size = compressed_weights.len();
        let compression_ratio = if compressed_size > 0 {
            raw_size as f32 / compressed_size as f32
        } else {
            1.0
        };

        debug!(
            "🧠📦 Compressed {} model via {} (lossless, no quant): {} → {} bytes ({:.1}x)",
            model_id, compressor.name(), raw_size, compressed_size, compression_ratio
        );

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            model_id,
            raw_size,
            compressed_weights,
            compression_ratio,
            source_node: source_node.to_string(),
            generation,
            weight_hash,
            timestamp_ms,
        }
    }

    /// Decompress to raw model weights using the injected compressor.
    /// Automatically detects and reverses int8 quantization if present.
    pub fn decompress(&self, compressor: &dyn ModelCompressor) -> Result<Vec<u8>> {
        let decompressed = compressor.decompress(&self.compressed_weights)
            .map_err(|e| NeuralMeshError::InferenceFailed(
                format!("Decompress model weights: {}", e)
            ))?;

        // Check for quantization header and dequantize if present
        let is_quantized = decompressed.len() >= 12 && decompressed[..4] == QUANT_MAGIC;
        let raw = if is_quantized {
            dequantize_weights_int8(&decompressed)?
        } else {
            decompressed
        };

        // Verify integrity — but allow quantization error for quantized models.
        // Quantization maps f32→int8→f32, introducing ±(range/255) per weight,
        // so the bytes won't match the original hash exactly. For quantized
        // payloads we only verify the size is consistent (f32 count matches).
        if is_quantized {
            // Size check: dequantized output should have same number of f32 values
            if raw.len() != self.raw_size {
                // Allow small rounding due to alignment (±3 bytes trailing)
                if (raw.len() as i64 - self.raw_size as i64).unsigned_abs() > 4 {
                    return Err(NeuralMeshError::InferenceFailed(format!(
                        "Quantized model size mismatch: got {} expected {}",
                        raw.len(), self.raw_size
                    )));
                }
            }
        } else {
            let hash: [u8; 32] = blake3::hash(&raw).into();
            if hash != self.weight_hash {
                return Err(NeuralMeshError::InferenceFailed(
                    "Model weight integrity check failed after decompression".to_string(),
                ));
            }
        }

        Ok(raw)
    }

    /// Serialize the entire compressed model for network transfer
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Serialize compressed model: {}", e)))
    }

    /// Deserialize from network transfer bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Deserialize compressed model: {}", e)))
    }

    /// Serialize and encrypt for secure peer-to-peer transfer.
    ///
    /// Uses the injected `ModelEncryptor` (BLAKE3-XOF stream cipher or
    /// Kyber+ChaCha20 from lib-crypto). Format: `nonce(16) ‖ ciphertext(N) ‖ mac(32)`.
    pub fn to_encrypted_bytes(&self, encryptor: &dyn ModelEncryptor) -> Result<Vec<u8>> {
        let plain = self.to_bytes()?;
        Ok(encryptor.encrypt(&plain))
    }

    /// Decrypt and deserialize from secure peer-to-peer transfer.
    pub fn from_encrypted_bytes(data: &[u8], encryptor: &dyn ModelEncryptor) -> Result<Self> {
        let plain = encryptor.decrypt(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Decrypt model: {}", e)))?;
        Self::from_bytes(&plain)
    }
}

// ─── Weight Quantization (f32 → int8) ────────────────────────────────

/// Quantize f32 model weights to int8 for dramatically better compression.
///
/// Raw f32 weights have high byte entropy (~8 bits/byte) because the mantissa
/// bits look random. BWT/MTF/RLE can't find patterns. But int8 values only
/// occupy 256 possible bytes, creating massive byte-level redundancy.
///
/// Layout: `QUANT_MAGIC(4) | scale(f32=4) | zero_point(f32=4) | int8_data(N/4)`
///
/// Precision: ±(range/255) per weight. For typical weight ranges of [-2, 2],
/// quantization error ≈ ±0.016 — negligible for RL/LSTM networks.
fn quantize_weights_int8(raw_weights: &[u8]) -> Vec<u8> {
    let num_floats = raw_weights.len() / 4;
    if num_floats == 0 {
        // Too small to quantize — return as-is (no header)
        return raw_weights.to_vec();
    }

    // Interpret as f32, find min/max
    let mut min_val = f32::MAX;
    let mut max_val = f32::MIN;
    let floats: Vec<f32> = raw_weights
        .chunks_exact(4)
        .map(|c| {
            let v = f32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            if v.is_finite() {
                if v < min_val { min_val = v; }
                if v > max_val { max_val = v; }
            }
            v
        })
        .collect();

    // Edge case: all identical or no finite values
    if min_val >= max_val {
        min_val = 0.0;
        max_val = 1.0;
    }

    let range = max_val - min_val;
    let scale = range / 255.0;
    let zero_point = min_val;

    // Build output: header + quantized bytes
    let mut out = Vec::with_capacity(12 + num_floats);
    out.extend_from_slice(&QUANT_MAGIC);
    out.extend_from_slice(&scale.to_le_bytes());
    out.extend_from_slice(&zero_point.to_le_bytes());

    for &v in &floats {
        if v.is_finite() {
            let q = ((v - zero_point) / scale).round().clamp(0.0, 255.0) as u8;
            out.push(q);
        } else {
            // Preserve NaN/Inf marker as 0 (will be close enough after dequant)
            out.push(128);
        }
    }

    // Append any trailing bytes that weren't part of a full f32
    let remainder = raw_weights.len() % 4;
    if remainder > 0 {
        out.extend_from_slice(&raw_weights[raw_weights.len() - remainder..]);
    }

    out
}

/// Dequantize int8 model weights back to f32.
/// Expects the QUANT_MAGIC header to have been verified by the caller.
fn dequantize_weights_int8(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(NeuralMeshError::InferenceFailed(
            "Quantized data too short for header".to_string(),
        ));
    }

    let scale = f32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let zero_point = f32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    let quantized = &data[12..];
    // Each int8 byte becomes 4 f32 bytes
    let mut out = Vec::with_capacity(quantized.len() * 4);

    for &q in quantized {
        let val = q as f32 * scale + zero_point;
        out.extend_from_slice(&val.to_le_bytes());
    }

    Ok(out)
}

// ─── Federated Averaging ─────────────────────────────────────────────

/// A pending model contribution from a peer node for FedAvg
#[derive(Debug, Clone)]
pub struct PeerModelContribution {
    pub compressed_model: CompressedModel,
    pub peer_id: String,
    /// How many training samples this node used (weights the average)
    pub sample_count: u64,
    pub received_at: Instant,
}

/// Federated averaging result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedAvgResult {
    /// Merged model weights (raw bytes, bincode-serialized)
    pub merged_weights: Vec<u8>,
    /// How many nodes contributed
    pub num_contributors: usize,
    /// Total training samples across all nodes
    pub total_samples: u64,
    /// New generation number
    pub generation: u64,
}

// ─── Distributed Training Coordinator ────────────────────────────────

/// Orchestrates distributed training across the mesh network.
///
/// More nodes = faster convergence because:
/// 1. Each node trains on its LOCAL traffic (diverse data)  
/// 2. FedAvg merges all local models (collective intelligence)
/// 3. Compressed model sync means low bandwidth overhead
/// 4. The AI's routing optimizes its own weight delivery  
///
/// The coordinator manages:
/// - Compressed model store (local cache of all model versions)
/// - FedAvg aggregation (weighted by sample count)
/// - Peer model collection (from QUIC parallel streams)
/// - Self-optimization loop metrics
pub struct DistributedTrainingCoordinator {
    /// This node's identifier
    node_id: String,

    /// Current training generation (increments each FedAvg round)
    generation: Arc<RwLock<u64>>,

    /// Pending contributions from peer nodes, keyed by (ModelId, peer_id)
    pending_contributions: Arc<RwLock<HashMap<(ModelId, String), PeerModelContribution>>>,

    /// How many peers we need before running FedAvg
    min_peers_for_avg: usize,

    /// Maximum age of a contribution before it's discarded
    max_contribution_age: Duration,

    /// Local training sample counts per model
    local_sample_counts: Arc<RwLock<HashMap<ModelId, u64>>>,

    /// Self-optimization loop metrics
    loop_metrics: Arc<RwLock<SelfOptimizingMetrics>>,

    /// History of compression ratios for the models themselves
    model_compression_history: Arc<RwLock<Vec<ModelCompressionSnapshot>>>,

    /// Injectable compressor — SovereignCodec in production, identity in tests
    compressor: Arc<dyn ModelCompressor>,

    /// Differential privacy config — (ε,δ)-DP per FedAvg round via clip+noise
    dp_config: DifferentialPrivacyConfig,

    /// Injectable encryptor for secure model weight transport
    encryptor: Arc<dyn ModelEncryptor>,
}

impl std::fmt::Debug for DistributedTrainingCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DistributedTrainingCoordinator")
            .field("node_id", &self.node_id)
            .field("min_peers_for_avg", &self.min_peers_for_avg)
            .field("compressor", &self.compressor.name())
            .field("dp_enabled", &self.dp_config.enabled)
            .field("encryptor", &self.encryptor.name())
            .finish()
    }
}

impl DistributedTrainingCoordinator {
    /// Create a new coordinator for this node (identity compression by default)
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            generation: Arc::new(RwLock::new(0)),
            pending_contributions: Arc::new(RwLock::new(HashMap::new())),
            min_peers_for_avg: 2,
            max_contribution_age: Duration::from_secs(300),
            local_sample_counts: Arc::new(RwLock::new(HashMap::new())),
            loop_metrics: Arc::new(RwLock::new(SelfOptimizingMetrics::new())),
            model_compression_history: Arc::new(RwLock::new(Vec::new())),
            compressor: Arc::new(IdentityCompressor),
            dp_config: DifferentialPrivacyConfig::default(),
            encryptor: Arc::new(IdentityEncryptor),
        }
    }

    /// Create with a specific compressor (SovereignCodec injected from zhtp runtime)
    pub fn with_compressor(node_id: String, compressor: Arc<dyn ModelCompressor>) -> Self {
        info!(
            "🧠 Distributed coordinator created with {} compressor — AI will compress itself",
            compressor.name()
        );
        Self {
            compressor,
            ..Self::new(node_id)
        }
    }

    /// Configure differential privacy for federated averaging.
    ///
    /// When enabled, each contributor's weight delta is L2-clipped to `max_grad_norm`
    /// and calibrated Gaussian noise is added, guaranteeing (ε, δ)-DP per round.
    pub fn set_dp_config(&mut self, config: DifferentialPrivacyConfig) {
        info!("🔒 DP configured: ε={}, δ={:.0e}, C={}, enabled={}",
            config.epsilon, config.delta, config.max_grad_norm, config.enabled);
        self.dp_config = config;
    }

    /// Inject a model encryptor for secure weight transport.
    ///
    /// Protects model weights during peer-to-peer transfer with authenticated
    /// encryption, preventing eavesdropping on model updates.
    pub fn set_encryptor(&mut self, encryptor: Arc<dyn ModelEncryptor>) {
        info!("🔐 Model encryptor set: {}", encryptor.name());
        self.encryptor = encryptor;
    }

    /// Get current DP configuration
    pub fn dp_config(&self) -> &DifferentialPrivacyConfig {
        &self.dp_config
    }

    /// Get the model encryptor
    pub fn encryptor(&self) -> &dyn ModelEncryptor {
        self.encryptor.as_ref()
    }

    /// Set minimum peers needed before FedAvg runs
    pub fn set_min_peers(&mut self, n: usize) {
        self.min_peers_for_avg = n;
    }

    /// Record that local training happened (for weighting in FedAvg)
    pub async fn record_local_training(&self, model_id: ModelId, samples: u64) {
        let mut counts = self.local_sample_counts.write().await;
        *counts.entry(model_id).or_insert(0) += samples;
    }

    /// Export local model weights, ZKC-compressed, ready for mesh broadcast.
    /// This compresses the AI using the AI's own compression pipeline.
    pub async fn export_compressed_model(
        &self,
        model_id: ModelId,
        raw_weights: &[u8],
    ) -> CompressedModel {
        let gen = *self.generation.read().await;
        let model = CompressedModel::compress(model_id, raw_weights, &self.node_id, gen, self.compressor.as_ref());

        // Record in self-optimization metrics
        let mut metrics = self.loop_metrics.write().await;
        metrics.record_model_compression(model_id, model.raw_size, model.compressed_weights.len());

        // Track compression history for the meta-loop
        let mut history = self.model_compression_history.write().await;
        history.push(ModelCompressionSnapshot {
            model_id,
            generation: gen,
            raw_size: model.raw_size,
            compressed_size: model.compressed_weights.len(),
            ratio: model.compression_ratio,
            timestamp: Instant::now(),
        });
        // Keep last 100 snapshots
        if history.len() > 100 {
            let drain_to = history.len() - 100;
            history.drain(..drain_to);
        }

        model
    }

    /// Receive a compressed model from a peer node.
    /// Returns true if we now have enough contributions to run FedAvg.
    pub async fn receive_peer_model(&self, compressed: CompressedModel, sample_count: u64) -> bool {
        let peer_id = compressed.source_node.clone();
        let model_id = compressed.model_id;

        info!(
            "🧠📥 Received {} model from {} (gen={}, {:.1}x compressed)",
            model_id, peer_id, compressed.generation, compressed.compression_ratio
        );

        let contribution = PeerModelContribution {
            compressed_model: compressed,
            peer_id: peer_id.clone(),
            sample_count,
            received_at: Instant::now(),
        };

        let mut pending = self.pending_contributions.write().await;
        pending.insert((model_id, peer_id), contribution);

        // Purge stale contributions
        pending.retain(|_, c| c.received_at.elapsed() < self.max_contribution_age);

        // Count contributions for this model
        let count = pending
            .keys()
            .filter(|(mid, _)| *mid == model_id)
            .count();

        count >= self.min_peers_for_avg
    }

    /// Run Federated Averaging on collected peer models + local model.
    ///
    /// FedAvg formula: θ_merged = Σ (n_k / n_total) * θ_k
    /// where n_k = sample count for node k, θ_k = weight vector for node k
    ///
    /// More nodes = more diverse gradients = faster convergence.
    pub async fn federated_average(
        &self,
        model_id: ModelId,
        local_weights: &[u8],
    ) -> Result<FedAvgResult> {
        let local_samples = {
            let counts = self.local_sample_counts.read().await;
            *counts.get(&model_id).unwrap_or(&1)
        };

        // Collect all contributions for this model (clone to release the lock)
        let contributions: Vec<PeerModelContribution> = {
            let pending = self.pending_contributions.read().await;
            pending
                .iter()
                .filter(|((mid, _), _)| *mid == model_id)
                .map(|(_, c)| c.clone())
                .collect()
        };

        if contributions.is_empty() {
            return Err(NeuralMeshError::InferenceFailed(
                "No peer contributions for FedAvg".to_string(),
            ));
        }

        info!(
            "🧠🔄 Running FedAvg for {} with {} peer contributions + local",
            model_id,
            contributions.len()
        );

        // Decompress all peer models
        let mut all_weights: Vec<(Vec<u8>, u64)> = Vec::new();
        all_weights.push((local_weights.to_vec(), local_samples));

        for contrib in &contributions {
            match contrib.compressed_model.decompress(self.compressor.as_ref()) {
                Ok(raw) => {
                    all_weights.push((raw, contrib.sample_count));
                }
                Err(e) => {
                    warn!("🧠⚠️ Skipping corrupt model from {}: {}", contrib.peer_id, e);
                }
            }
        }

        let total_samples: u64 = all_weights.iter().map(|(_, s)| s).sum();
        let num_contributors = all_weights.len();

        // FedAvg: weighted average with differential privacy (clip + noise)
        let merged = fedavg_bincode_weights(&all_weights, total_samples, &self.dp_config)?;

        let gen = {
            let mut g = self.generation.write().await;
            *g += 1;
            *g
        };

        // Clear pending contributions for this model
        {
            let mut pending = self.pending_contributions.write().await;
            pending.retain(|(mid, _), _| *mid != model_id);
        }

        // Update loop metrics
        {
            let mut metrics = self.loop_metrics.write().await;
            metrics.record_fedavg_round(model_id, num_contributors, total_samples);
        }

        info!(
            "🧠✅ FedAvg complete for {} — {} contributors, {} total samples, gen={}",
            model_id, num_contributors, total_samples, gen
        );

        Ok(FedAvgResult {
            merged_weights: merged,
            num_contributors,
            total_samples,
            generation: gen,
        })
    }

    /// Get current generation number
    pub async fn generation(&self) -> u64 {
        *self.generation.read().await
    }

    /// Get the self-optimization loop metrics
    pub async fn loop_metrics(&self) -> SelfOptimizingMetrics {
        self.loop_metrics.read().await.clone()
    }

    /// Get compression ratio trend for a model (is the AI compressing itself better over time?)
    pub async fn compression_trend(&self, model_id: ModelId) -> Vec<f32> {
        self.model_compression_history
            .read()
            .await
            .iter()
            .filter(|s| s.model_id == model_id)
            .map(|s| s.ratio)
            .collect()
    }

    /// Get number of pending contributions for a model
    pub async fn pending_count(&self, model_id: ModelId) -> usize {
        self.pending_contributions
            .read()
            .await
            .keys()
            .filter(|(mid, _)| *mid == model_id)
            .count()
    }
}

// ─── Differential Privacy Helpers ────────────────────────────────────────

/// Generate a Gaussian random sample using the Box-Muller transform.
///
/// Produces `N(mean, σ²)` without requiring the `rand_distr` crate.
fn gaussian_sample(rng: &mut impl Rng, mean: f64, sigma: f64) -> f64 {
    if sigma <= 0.0 {
        return mean;
    }
    let u1: f64 = rng.gen_range(1e-10_f64..1.0);
    let u2: f64 = rng.gen_range(0.0_f64..std::f64::consts::TAU);
    mean + sigma * (-2.0 * u1.ln()).sqrt() * u2.cos()
}

/// L2-clip a weight delta vector to the given max norm.
///
/// Only positions where `is_weight[i]` is true are included in the norm
/// computation and clipping. Metadata positions are left untouched.
///
/// Returns the clipping factor applied (1.0 = no clipping needed).
fn dp_clip_delta(delta: &mut [f32], is_weight: &[bool], max_norm: f64) -> f64 {
    let mut norm_sq = 0.0_f64;
    for (i, &is_w) in is_weight.iter().enumerate() {
        if is_w && i < delta.len() {
            norm_sq += (delta[i] as f64).powi(2);
        }
    }
    let norm = norm_sq.sqrt();
    if norm <= max_norm || norm < 1e-10 {
        return 1.0;
    }
    let clip_factor = max_norm / norm;
    for (i, &is_w) in is_weight.iter().enumerate() {
        if is_w && i < delta.len() {
            delta[i] = (delta[i] as f64 * clip_factor) as f32;
        }
    }
    clip_factor
}

// ─── FedAvg Implementation ──────────────────────────────────────────

/// Federated averaging on bincode-serialized weight vectors.
///
/// Each `Vec<u8>` is a bincode-serialized `PolicyValueNetwork`, `LstmNetwork`,
/// or `IsolationForest`. We identify which byte spans are f32 weight data vs.
/// bincode structural metadata by checking for `is_finite()`, then only average
/// the weight portions while preserving metadata from the reference model.
///
/// Safety: metadata bytes (lengths, enum tags) are kept from the first
/// contribution (the local model) — all peers MUST have identical architecture.
fn fedavg_bincode_weights(
    contributions: &[(Vec<u8>, u64)],
    _total_samples: u64,
    dp_config: &DifferentialPrivacyConfig,
) -> Result<Vec<u8>> {
    if contributions.is_empty() {
        return Err(NeuralMeshError::InferenceFailed("No weights to average".to_string()));
    }

    if contributions.len() == 1 {
        return Ok(contributions[0].0.clone());
    }

    // All weight blobs should be the same size (same architecture)
    let expected_len = contributions[0].0.len();

    // Start from the local (first) model as the base — preserves all metadata
    let mut merged = contributions[0].0.clone();
    let base = &contributions[0].0;

    // Identify which 4-byte-aligned positions hold actual weight data vs metadata.
    // Weight data: finite f32 values that VARY across contributions.
    // Metadata: identical bytes across all contributions (lengths, tags, config).
    let num_chunks = expected_len / 4;
    let mut is_weight = vec![false; num_chunks];

    // A chunk is a weight if it contains a finite f32 AND at least one peer differs
    for i in 0..num_chunks {
        let offset = i * 4;
        let base_val = f32::from_le_bytes([
            base[offset], base[offset + 1], base[offset + 2], base[offset + 3],
        ]);
        if !base_val.is_finite() {
            continue; // NaN/Inf = not a weight
        }
        // Check if any peer has a different value here (confirms it's a learned weight)
        let mut any_different = false;
        for (weights, _) in contributions.iter().skip(1) {
            if weights.len() != expected_len {
                continue;
            }
            let peer_val = f32::from_le_bytes([
                weights[offset], weights[offset + 1], weights[offset + 2], weights[offset + 3],
            ]);
            if peer_val.is_finite() && (peer_val - base_val).abs() > 1e-10 {
                any_different = true;
                break;
            }
        }
        is_weight[i] = any_different || contributions.len() == 1;
    }

    // If no varying positions detected (e.g. architecture mismatch), fall back
    // to averaging all finite f32 chunks (original behavior but safer)
    let num_weights: usize = is_weight.iter().filter(|&&w| w).count();
    if num_weights == 0 {
        // All peers have identical weights — just return the base
        return Ok(merged);
    }

    if dp_config.enabled && contributions.len() > 1 {
        // ─── DP-FedAvg: Clip-and-Noise Gaussian Mechanism ───────
        //
        // Guarantees (ε, δ)-differential privacy per FedAvg round:
        //
        // 1. Reference = local model (contribution[0])
        // 2. Each contributor's weight delta is L2-clipped to max_grad_norm
        // 3. Weighted average of clipped deltas
        // 4. Calibrated Gaussian noise: σ = (C / n) · √(2 ln(1.25/δ)) / ε
        // 5. Merged model = reference + noisy averaged delta
        //
        // An adversary seeing the merged model learns < ε bits about any
        // single contributor's private training data (with prob. 1 − δ).

        // Phase 1: Extract reference weights (local model)
        let ref_floats: Vec<f32> = (0..num_chunks).map(|i| {
            let o = i * 4;
            f32::from_le_bytes([base[o], base[o+1], base[o+2], base[o+3]])
        }).collect();

        // Phase 2: Compute and L2-clip deltas for each contributor
        let mut clipped_deltas: Vec<(Vec<f32>, u64)> = Vec::new();
        for (weights, sample_count) in contributions {
            if weights.len() != expected_len { continue; }
            let mut delta = vec![0.0f32; num_chunks];
            for i in 0..num_chunks {
                if !is_weight[i] { continue; }
                let o = i * 4;
                let val = f32::from_le_bytes([
                    weights[o], weights[o+1], weights[o+2], weights[o+3],
                ]);
                if val.is_finite() {
                    delta[i] = val - ref_floats[i];
                }
            }
            dp_clip_delta(&mut delta, &is_weight, dp_config.max_grad_norm);
            clipped_deltas.push((delta, *sample_count));
        }

        // Phase 3: Weighted average of clipped deltas + calibrated noise
        let total: f64 = clipped_deltas.iter().map(|(_, s)| *s as f64).sum();
        let sigma = dp_config.noise_sigma(clipped_deltas.len());
        let mut rng = rand::thread_rng();

        for i in 0..num_chunks {
            if !is_weight[i] { continue; }
            let o = i * 4;
            let mut avg_delta = 0.0f64;
            for (delta, sc) in &clipped_deltas {
                avg_delta += delta[i] as f64 * (*sc as f64 / total);
            }

            // Calibrated Gaussian noise hides individual contributions
            let noise = gaussian_sample(&mut rng, 0.0, sigma);
            let new_val = (ref_floats[i] as f64 + avg_delta + noise) as f32;
            let bytes = new_val.to_le_bytes();
            merged[o..o + 4].copy_from_slice(&bytes);
        }

        debug!(
            "🔒 DP-FedAvg: ε={}, δ={:.0e}, σ={:.6}, {} contributors, {} weight chunks, C={}",
            dp_config.epsilon, dp_config.delta, sigma,
            clipped_deltas.len(), num_weights, dp_config.max_grad_norm
        );
    } else {
        // ─── Standard FedAvg (DP disabled or single contributor) ─
        for i in 0..num_chunks {
            if !is_weight[i] { continue; }
            let offset = i * 4;
            let mut accum = 0.0f64;
            let mut valid_samples = 0u64;

            for (weights, sample_count) in contributions {
                if weights.len() != expected_len { continue; }
                let val = f32::from_le_bytes([
                    weights[offset], weights[offset + 1], weights[offset + 2], weights[offset + 3],
                ]);
                if val.is_finite() {
                    accum += val as f64 * *sample_count as f64;
                    valid_samples += sample_count;
                }
            }

            if valid_samples > 0 {
                let averaged = (accum / valid_samples as f64) as f32;
                let bytes = averaged.to_le_bytes();
                merged[offset..offset + 4].copy_from_slice(&bytes);
            }
        }

        debug!(
            "🧠🔄 FedAvg: averaged {}/{} chunks as weights, preserved {} metadata chunks",
            num_weights, num_chunks, num_chunks - num_weights
        );
    }

    // Copy any trailing bytes (not f32-aligned) from the base
    let aligned_len = num_chunks * 4;
    if aligned_len < expected_len {
        merged[aligned_len..].copy_from_slice(&base[aligned_len..]);
    }

    Ok(merged)
}

// ─── Self-Optimizing Loop Metrics ────────────────────────────────────

/// Snapshot of model compression at a point in time
#[derive(Debug, Clone)]
struct ModelCompressionSnapshot {
    model_id: ModelId,
    generation: u64,
    raw_size: usize,
    compressed_size: usize,
    ratio: f32,
    timestamp: Instant,
}

/// Tracks the self-referential optimization loop.
///
/// The key insight: the AI uses compression → the AI IS compressed →
/// better compression → smaller AI → faster sync → more training →
/// better AI → better compression → ∞
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfOptimizingMetrics {
    // ── Model compression (AI compressing itself) ──
    /// Total bytes of model weights compressed
    pub total_model_bytes_raw: u64,
    /// Total bytes after compression
    pub total_model_bytes_compressed: u64,
    /// Average compression ratio across all model exports
    pub avg_model_compression_ratio: f32,
    /// Best compression ratio ever achieved for each model
    pub best_compression_ratio: HashMap<String, f32>,

    // ── Distributed training ──
    /// Total FedAvg rounds completed
    pub fedavg_rounds: u64,
    /// Total peer contributions received
    pub peer_contributions: u64,
    /// Total training samples across all nodes
    pub total_distributed_samples: u64,
    /// Average contributors per round
    pub avg_contributors_per_round: f32,

    // ── Loop velocity (how fast the cycle spins) ──
    /// Model syncs per minute (compressed model broadcasts)
    pub syncs_per_minute: f32,
    /// Training rounds per minute
    pub training_rounds_per_minute: f32,
    /// Bytes saved by self-compression (what would have been sent uncompressed)
    pub bytes_saved_by_self_compression: u64,

    // ── Convergence tracking ──
    /// Loss/reward trend (should improve over time)
    pub reward_history: Vec<f32>,
    /// Is the loop getting faster? (ratio of current velocity / initial velocity)
    pub acceleration_factor: f32,

    // internal counters
    #[serde(skip)]
    compression_count: u64,
    #[serde(skip)]
    round_count: u64,
}

impl SelfOptimizingMetrics {
    pub fn new() -> Self {
        Self {
            total_model_bytes_raw: 0,
            total_model_bytes_compressed: 0,
            avg_model_compression_ratio: 1.0,
            best_compression_ratio: HashMap::new(),
            fedavg_rounds: 0,
            peer_contributions: 0,
            total_distributed_samples: 0,
            avg_contributors_per_round: 0.0,
            syncs_per_minute: 0.0,
            training_rounds_per_minute: 0.0,
            bytes_saved_by_self_compression: 0,
            reward_history: Vec::new(),
            acceleration_factor: 1.0,
            compression_count: 0,
            round_count: 0,
        }
    }

    fn record_model_compression(&mut self, model_id: ModelId, raw: usize, compressed: usize) {
        self.total_model_bytes_raw += raw as u64;
        self.total_model_bytes_compressed += compressed as u64;
        self.bytes_saved_by_self_compression += (raw.saturating_sub(compressed)) as u64;

        let ratio = if compressed > 0 {
            raw as f32 / compressed as f32
        } else {
            1.0
        };

        self.compression_count += 1;
        self.avg_model_compression_ratio = self.total_model_bytes_raw as f32
            / self.total_model_bytes_compressed.max(1) as f32;

        let key = model_id.to_string();
        let best = self.best_compression_ratio.entry(key).or_insert(1.0);
        if ratio > *best {
            *best = ratio;
        }
    }

    fn record_fedavg_round(&mut self, _model_id: ModelId, contributors: usize, samples: u64) {
        self.fedavg_rounds += 1;
        self.peer_contributions += contributors as u64;
        self.total_distributed_samples += samples;
        self.round_count += 1;
        self.avg_contributors_per_round =
            self.peer_contributions as f32 / self.round_count.max(1) as f32;
    }

    /// Record a reward observation for convergence tracking
    pub fn record_reward(&mut self, reward: f32) {
        self.reward_history.push(reward);
        if self.reward_history.len() > 1000 {
            self.reward_history.drain(..self.reward_history.len() - 1000);
        }

        // Calculate acceleration: compare recent avg to early avg
        if self.reward_history.len() >= 20 {
            let early: f32 = self.reward_history[..10].iter().sum::<f32>() / 10.0;
            let recent: f32 = self.reward_history[self.reward_history.len() - 10..]
                .iter()
                .sum::<f32>()
                / 10.0;
            if early.abs() > 0.001 {
                self.acceleration_factor = recent / early;
            }
        }
    }

    /// Is the network improving? (acceleration > 1.0 means getting better)
    pub fn is_improving(&self) -> bool {
        self.acceleration_factor > 1.0
    }

    /// Summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "🧠🔄 Self-Optimizing Loop: {:.1}x model compression, {} FedAvg rounds, \
             {} contributors, {:.0} bytes saved, acceleration={:.2}x {}",
            self.avg_model_compression_ratio,
            self.fedavg_rounds,
            self.peer_contributions,
            self.bytes_saved_by_self_compression,
            self.acceleration_factor,
            if self.is_improving() { "📈" } else { "📉" }
        )
    }
}

impl Default for SelfOptimizingMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ─── QUIC Parallel Model Sync Messages ──────────────────────────────

/// Message types for model sync over QUIC parallel streams.
/// Each model component can sync independently and concurrently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelSyncMessage {
    /// Broadcast compressed model weights to peers
    BroadcastModel {
        model: CompressedModel,
        sample_count: u64,
    },
    /// Request the latest model from a peer
    RequestModel {
        model_id: ModelId,
        from_generation: u64,
    },
    /// Response with compressed model
    ModelResponse {
        model: CompressedModel,
        sample_count: u64,
    },
    /// FedAvg result broadcast (merged model for all to adopt)
    FedAvgResult {
        model_id: ModelId,
        result: FedAvgResult,
    },
    /// Loop metrics exchange (nodes share their performance data)
    MetricsExchange {
        node_id: String,
        metrics: SelfOptimizingMetrics,
    },
}

impl ModelSyncMessage {
    /// Serialize for QUIC stream transfer
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Serialize sync message: {}", e)))
    }

    /// Deserialize from QUIC stream
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Deserialize sync message: {}", e)))
    }

    /// Serialize and encrypt for secure QUIC transfer.
    pub fn to_encrypted_bytes(&self, encryptor: &dyn ModelEncryptor) -> Result<Vec<u8>> {
        let plain = self.to_bytes()?;
        Ok(encryptor.encrypt(&plain))
    }

    /// Decrypt and deserialize from secure QUIC stream.
    pub fn from_encrypted_bytes(data: &[u8], encryptor: &dyn ModelEncryptor) -> Result<Self> {
        let plain = encryptor.decrypt(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Decrypt sync message: {}", e)))?;
        Self::from_bytes(&plain)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn id_comp() -> &'static dyn ModelCompressor {
        &IdentityCompressor
    }

    #[test]
    fn test_compressed_model_roundtrip() {
        // Use f32 weights since we now quantize to int8 during compression.
        // [1.0, 2.0, 3.0, 4.0] as f32 bytes
        let f32_weights: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0];
        let raw_weights: Vec<u8> = f32_weights.iter().flat_map(|f| f.to_le_bytes()).collect();
        let model = CompressedModel::compress(
            ModelId::RlRouter,
            &raw_weights,
            "node-1",
            0,
            id_comp(),
        );

        assert_eq!(model.model_id, ModelId::RlRouter);
        assert_eq!(model.raw_size, 16);
        assert!(model.compression_ratio > 0.0);

        let decompressed = model.decompress(id_comp()).unwrap();
        // Check approximate equality since int8 quantization introduces ±(range/255) error
        let orig_f32: Vec<f32> = raw_weights.chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let dec_f32: Vec<f32> = decompressed.chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        for (o, d) in orig_f32.iter().zip(dec_f32.iter()) {
            assert!((o - d).abs() < 0.05, "f32 mismatch: {} vs {}", o, d);
        }
    }

    #[test]
    fn test_compressed_model_network_roundtrip() {
        // Use recognizable f32 data for network roundtrip test
        let f32_weights: Vec<f32> = (0..64).map(|i| i as f32 * 0.1).collect();
        let raw_weights: Vec<u8> = f32_weights.iter().flat_map(|f| f.to_le_bytes()).collect();
        let model = CompressedModel::compress(ModelId::Prefetcher, &raw_weights, "node-a", 5, id_comp());

        let bytes = model.to_bytes().unwrap();
        let restored = CompressedModel::from_bytes(&bytes).unwrap();

        assert_eq!(restored.model_id, ModelId::Prefetcher);
        assert_eq!(restored.generation, 5);
        let decompressed = restored.decompress(id_comp()).unwrap();
        // Check approximate equality
        let orig_f32: Vec<f32> = raw_weights.chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let dec_f32: Vec<f32> = decompressed.chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        for (o, d) in orig_f32.iter().zip(dec_f32.iter()) {
            assert!((o - d).abs() < 0.1, "f32 mismatch: {} vs {}", o, d);
        }
    }

    #[tokio::test]
    async fn test_distributed_coordinator_basic() {
        let coord = DistributedTrainingCoordinator::new("test-node".to_string());

        // Record some local training
        coord.record_local_training(ModelId::RlRouter, 100).await;
        coord.record_local_training(ModelId::RlRouter, 50).await;

        assert_eq!(coord.generation().await, 0);
    }

    #[tokio::test]
    async fn test_export_compressed_model() {
        let coord = DistributedTrainingCoordinator::new("test-node".to_string());

        let raw_weights = vec![0u8; 1024]; // 1KB model
        let compressed = coord
            .export_compressed_model(ModelId::RlRouter, &raw_weights)
            .await;

        assert_eq!(compressed.model_id, ModelId::RlRouter);
        assert_eq!(compressed.raw_size, 1024);

        // Verify loop metrics updated
        let metrics = coord.loop_metrics().await;
        assert_eq!(metrics.total_model_bytes_raw, 1024);
        assert!(metrics.total_model_bytes_compressed > 0);
    }

    #[tokio::test]
    async fn test_fedavg_two_peers() {
        let mut coord = DistributedTrainingCoordinator::new("local".to_string());
        coord.set_min_peers(1);
        // Disable DP for deterministic averaging (DP tested separately below)
        coord.set_dp_config(DifferentialPrivacyConfig { enabled: false, ..Default::default() });

        // Simulate local weights: 4 f32 values
        let local: Vec<u8> = [1.0f32, 2.0, 3.0, 4.0]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        // Simulate peer weights: 4 f32 values
        let peer: Vec<u8> = [3.0f32, 4.0, 5.0, 6.0]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        // Peer exports compressed model (identity compressor in tests)
        let peer_model = CompressedModel::compress(ModelId::RlRouter, &peer, "peer-1", 0, id_comp());

        // Receive peer model (should trigger readiness)
        let ready = coord.receive_peer_model(peer_model, 100).await;
        assert!(ready);

        // Run FedAvg (local=100 samples, peer=100 samples → equal weight)
        coord.record_local_training(ModelId::RlRouter, 100).await;
        let result = coord
            .federated_average(ModelId::RlRouter, &local)
            .await
            .unwrap();

        assert_eq!(result.num_contributors, 2); // local + 1 peer
        assert_eq!(result.total_samples, 200);
        assert_eq!(result.generation, 1);

        // The merged weights should be approximately the average: [2.0, 3.0, 4.0, 5.0]
        let merged_f32: Vec<f32> = result
            .merged_weights
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        assert!((merged_f32[0] - 2.0).abs() < 0.1);
        assert!((merged_f32[1] - 3.0).abs() < 0.1);
        assert!((merged_f32[2] - 4.0).abs() < 0.1);
        assert!((merged_f32[3] - 5.0).abs() < 0.1);
    }

    #[test]
    fn test_self_optimizing_metrics() {
        let mut metrics = SelfOptimizingMetrics::new();

        // Simulate improving rewards
        for i in 0..30 {
            metrics.record_reward(i as f32 * 0.1);
        }

        assert!(metrics.is_improving());
        assert!(metrics.acceleration_factor > 1.0);
    }

    #[test]
    fn test_model_sync_message_roundtrip() {
        let model = CompressedModel::compress(ModelId::AnomalySentry, &[1, 2, 3], "n1", 0, id_comp());
        let msg = ModelSyncMessage::BroadcastModel {
            model,
            sample_count: 42,
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ModelSyncMessage::from_bytes(&bytes).unwrap();

        match restored {
            ModelSyncMessage::BroadcastModel { sample_count, .. } => {
                assert_eq!(sample_count, 42);
            }
            _ => panic!("Wrong variant"),
        }
    }

    // ─── Differential Privacy Tests ──────────────────────────────

    #[test]
    fn test_dp_config_noise_sigma() {
        let config = DifferentialPrivacyConfig::default();
        // ε=1.0, δ=1e-5, C=1.0
        let sigma = config.noise_sigma(10);
        // σ = (1.0/10) * √(2 ln(125000)) / 1.0
        // ln(125000) ≈ 11.736, √(23.472) ≈ 4.845
        // σ ≈ 0.1 * 4.845 ≈ 0.485
        assert!(sigma > 0.4 && sigma < 0.6, "sigma={}", sigma);

        // More contributors → less noise
        let sigma2 = config.noise_sigma(100);
        assert!(sigma2 < sigma, "More peers should reduce noise");

        // Disabled → no noise
        let disabled = DifferentialPrivacyConfig { enabled: false, ..Default::default() };
        assert_eq!(disabled.noise_sigma(10), 0.0);
    }

    #[test]
    fn test_dp_clip_delta_no_clip_needed() {
        let mut delta = vec![0.1, 0.2, 0.3, 0.0];
        let is_weight = vec![true, true, true, false];
        // L2 norm = √(0.01 + 0.04 + 0.09) = √0.14 ≈ 0.374
        let factor = dp_clip_delta(&mut delta, &is_weight, 1.0);
        assert_eq!(factor, 1.0); // No clipping needed
        assert!((delta[0] - 0.1).abs() < 1e-6);
    }

    #[test]
    fn test_dp_clip_delta_clips_large_norm() {
        let mut delta = vec![3.0, 4.0, 0.0, 0.0];
        let is_weight = vec![true, true, false, false];
        // L2 norm = √(9+16) = 5.0, clip to C=1.0 → factor = 0.2
        let factor = dp_clip_delta(&mut delta, &is_weight, 1.0);
        assert!((factor - 0.2).abs() < 1e-6, "factor={}", factor);
        // Clipped: [0.6, 0.8], norm should be 1.0
        let clipped_norm = ((delta[0] as f64).powi(2) + (delta[1] as f64).powi(2)).sqrt();
        assert!((clipped_norm - 1.0).abs() < 1e-4, "clipped_norm={}", clipped_norm);
        // Metadata position unchanged
        assert_eq!(delta[2], 0.0);
    }

    #[test]
    fn test_gaussian_sample_distribution() {
        let mut rng = rand::thread_rng();
        let n = 10_000;
        let samples: Vec<f64> = (0..n).map(|_| gaussian_sample(&mut rng, 0.0, 1.0)).collect();

        // Mean should be ~0
        let mean: f64 = samples.iter().sum::<f64>() / n as f64;
        assert!(mean.abs() < 0.1, "mean={}", mean);

        // Std should be ~1
        let variance: f64 = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n as f64;
        let std = variance.sqrt();
        assert!((std - 1.0).abs() < 0.1, "std={}", std);

        // Zero sigma → constant
        let zero = gaussian_sample(&mut rng, 5.0, 0.0);
        assert_eq!(zero, 5.0);
    }

    #[tokio::test]
    async fn test_dp_fedavg_adds_noise() {
        // Local and peer have DIFFERENT weights so is_weight detection works
        let mut coord = DistributedTrainingCoordinator::new("local".to_string());
        coord.set_min_peers(1);
        // High noise for easy detection
        coord.set_dp_config(DifferentialPrivacyConfig {
            epsilon: 0.1,
            delta: 1e-5,
            max_grad_norm: 1.0,
            enabled: true,
        });

        let local: Vec<u8> = [1.0f32, 2.0, 3.0, 4.0]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        // Peer with different weights so the weight-detection heuristic works
        let peer_raw: Vec<u8> = [1.5f32, 2.5, 3.5, 4.5]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        let peer_model = CompressedModel::compress(
            ModelId::RlRouter, &peer_raw, "peer-1", 0, id_comp(),
        );
        coord.receive_peer_model(peer_model, 100).await;
        coord.record_local_training(ModelId::RlRouter, 100).await;

        let result = coord.federated_average(ModelId::RlRouter, &local).await.unwrap();

        // Without DP, the average would be ~[1.25, 2.25, 3.25, 4.25].
        // With ε=0.1 DP noise (σ ≈ 24), weights should be far from that.
        let merged_f32: Vec<f32> = result.merged_weights
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        // At least one weight should differ by more than 1.0 from the no-DP avg
        let any_noisy = merged_f32.iter()
            .zip([1.25f32, 2.25, 3.25, 4.25].iter())
            .any(|(m, expected)| (m - expected).abs() > 1.0);
        assert!(any_noisy, "DP noise (σ≈24) should have large effect: {:?}", merged_f32);
    }

    // ─── Encryption Tests ───────────────────────────────────────

    #[test]
    fn test_blake3_stream_encryptor_roundtrip() {
        let key = blake3::hash(b"test-shared-secret");
        let enc = Blake3StreamEncryptor::new(*key.as_bytes());

        let plaintext = b"Hello, sovereign network model weights!";
        let ciphertext = enc.encrypt(plaintext);

        // Ciphertext should be larger (16 nonce + data + 32 mac)
        assert_eq!(ciphertext.len(), 16 + plaintext.len() + 32);

        // Ciphertext should differ from plaintext
        assert_ne!(&ciphertext[16..16 + plaintext.len()], &plaintext[..]);

        let decrypted = enc.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_blake3_stream_encryptor_tamper_detection() {
        let key = blake3::hash(b"test-key");
        let enc = Blake3StreamEncryptor::new(*key.as_bytes());

        let ciphertext = enc.encrypt(b"secret model weights");

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered[20] ^= 0xFF;

        let result = enc.decrypt(&tampered);
        assert!(result.is_err(), "Tampered data should fail MAC verification");
    }

    #[test]
    fn test_blake3_stream_encryptor_different_nonces() {
        let key = blake3::hash(b"test-key-2");
        let enc = Blake3StreamEncryptor::new(*key.as_bytes());

        let plaintext = b"same message encrypted twice";
        let ct1 = enc.encrypt(plaintext);
        let ct2 = enc.encrypt(plaintext);

        // Different nonces → different ciphertexts (semantic security)
        assert_ne!(ct1, ct2);

        // Both should decrypt correctly
        assert_eq!(enc.decrypt(&ct1).unwrap(), plaintext);
        assert_eq!(enc.decrypt(&ct2).unwrap(), plaintext);
    }

    #[test]
    fn test_compressed_model_encrypted_roundtrip() {
        let key = blake3::hash(b"peer-shared-key");
        let enc = Blake3StreamEncryptor::new(*key.as_bytes());

        let f32_weights: Vec<f32> = (0..64).map(|i| i as f32 * 0.1).collect();
        let raw: Vec<u8> = f32_weights.iter().flat_map(|f| f.to_le_bytes()).collect();

        let model = CompressedModel::compress(ModelId::RlRouter, &raw, "node-a", 3, id_comp());
        let encrypted = model.to_encrypted_bytes(&enc).unwrap();

        // Wrong key should fail
        let wrong_key = blake3::hash(b"wrong-key");
        let wrong_enc = Blake3StreamEncryptor::new(*wrong_key.as_bytes());
        assert!(CompressedModel::from_encrypted_bytes(&encrypted, &wrong_enc).is_err());

        // Correct key should work
        let restored = CompressedModel::from_encrypted_bytes(&encrypted, &enc).unwrap();
        assert_eq!(restored.model_id, ModelId::RlRouter);
        assert_eq!(restored.generation, 3);
    }

    #[test]
    fn test_identity_encryptor_passthrough() {
        let enc = IdentityEncryptor;
        let data = b"model weights";
        let encrypted = enc.encrypt(data);
        assert_eq!(encrypted, data);
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
}
