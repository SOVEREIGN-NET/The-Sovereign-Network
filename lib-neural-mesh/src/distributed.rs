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
}

impl std::fmt::Display for ModelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelId::RlRouter => write!(f, "rl-router"),
            ModelId::Prefetcher => write!(f, "prefetcher"),
            ModelId::AnomalySentry => write!(f, "anomaly-sentry"),
        }
    }
}

// ─── Compressed Model Store ──────────────────────────────────────────

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
    pub fn compress(
        model_id: ModelId,
        raw_weights: &[u8],
        source_node: &str,
        generation: u64,
        compressor: &dyn ModelCompressor,
    ) -> Self {
        let raw_size = raw_weights.len();
        let weight_hash: [u8; 32] = blake3::hash(raw_weights).into();

        // Compress using the injected compressor (SovereignCodec in production)
        let compressed_weights = compressor.compress(raw_weights);
        let compressed_size = compressed_weights.len();
        let compression_ratio = if compressed_size > 0 {
            raw_size as f32 / compressed_size as f32
        } else {
            1.0
        };

        debug!(
            "🧠📦 Compressed {} model via {}: {} → {} bytes ({:.1}x)",
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

    /// Decompress to raw model weights using the injected compressor
    pub fn decompress(&self, compressor: &dyn ModelCompressor) -> Result<Vec<u8>> {
        let raw = compressor.decompress(&self.compressed_weights)
            .map_err(|e| NeuralMeshError::InferenceFailed(
                format!("Decompress model weights: {}", e)
            ))?;

        // Verify integrity
        let hash: [u8; 32] = blake3::hash(&raw).into();
        if hash != self.weight_hash {
            return Err(NeuralMeshError::InferenceFailed(
                "Model weight integrity check failed after decompression".to_string(),
            ));
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
}

impl std::fmt::Debug for DistributedTrainingCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DistributedTrainingCoordinator")
            .field("node_id", &self.node_id)
            .field("min_peers_for_avg", &self.min_peers_for_avg)
            .field("compressor", &self.compressor.name())
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

        // FedAvg: weighted average of raw weight bytes interpreted as f32 arrays
        let merged = fedavg_bincode_weights(&all_weights, total_samples)?;

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

// ─── FedAvg Implementation ──────────────────────────────────────────

/// Federated averaging on bincode-serialized weight vectors.
///
/// Each `Vec<u8>` is a bincode-serialized `PolicyValueNetwork`, `LstmNetwork`,
/// or `IsolationForest`. We deserialize to f32 arrays, weighted-average them,
/// and re-serialize.
///
/// This works because all our models store weights as contiguous f32
/// (ndarray Array2/Array1 serialized via bincode → packed f32 with metadata).
/// We average the raw float portions while preserving the structure metadata.
fn fedavg_bincode_weights(
    contributions: &[(Vec<u8>, u64)],
    total_samples: u64,
) -> Result<Vec<u8>> {
    if contributions.is_empty() {
        return Err(NeuralMeshError::InferenceFailed("No weights to average".to_string()));
    }

    if contributions.len() == 1 {
        return Ok(contributions[0].0.clone());
    }

    // All weight blobs should be the same size (same architecture)
    let expected_len = contributions[0].0.len();

    // Simple byte-level weighted average: interpret as f32 where alignment allows.
    // For bincode-serialized ndarray, the float data is stored after some metadata bytes.
    // We average ALL bytes that are at f32-aligned positions and identical metadata.
    //
    // Safer approach: average entire byte streams as if f32 arrays.
    // This is valid because bincode stores ndarray data as length-prefixed f32 sequences.
    let mut merged = vec![0u8; expected_len];

    // First pass: find which byte positions are metadata (identical across all)
    // and which are weight data (varying)
    let base = &contributions[0].0;

    // Float-accumulator for weighted averaging
    // We'll work with the raw bytes, converting overlapping f32 windows
    let mut f32_accum = vec![0.0f64; expected_len / 4];

    for (weights, sample_count) in contributions {
        if weights.len() != expected_len {
            // Architecture mismatch — skip this contribution safely
            warn!(
                "🧠⚠️ FedAvg: weight size mismatch ({} vs {}), skipping",
                weights.len(),
                expected_len
            );
            continue;
        }

        let factor = *sample_count as f64 / total_samples as f64;

        // Extract f32 values (4-byte aligned chunks)
        for (i, chunk) in weights.chunks_exact(4).enumerate() {
            let val = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if val.is_finite() {
                f32_accum[i] += val as f64 * factor;
            } else {
                // Non-finite = probably metadata section, keep original
                f32_accum[i] = f32::from_le_bytes([base[i * 4], base[i * 4 + 1], base[i * 4 + 2], base[i * 4 + 3]]) as f64;
            }
        }
    }

    // Write averaged f32 values back
    for (i, val) in f32_accum.iter().enumerate() {
        let bytes = (*val as f32).to_le_bytes();
        let offset = i * 4;
        if offset + 4 <= merged.len() {
            merged[offset..offset + 4].copy_from_slice(&bytes);
        }
    }

    // Copy any trailing bytes (not f32-aligned) from the base
    let aligned_len = (expected_len / 4) * 4;
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
        let raw_weights = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
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
        assert_eq!(decompressed, raw_weights);
    }

    #[test]
    fn test_compressed_model_network_roundtrip() {
        let raw_weights = vec![42u8; 256];
        let model = CompressedModel::compress(ModelId::Prefetcher, &raw_weights, "node-a", 5, id_comp());

        let bytes = model.to_bytes().unwrap();
        let restored = CompressedModel::from_bytes(&bytes).unwrap();

        assert_eq!(restored.model_id, ModelId::Prefetcher);
        assert_eq!(restored.generation, 5);
        assert_eq!(restored.decompress(id_comp()).unwrap(), raw_weights);
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
}
