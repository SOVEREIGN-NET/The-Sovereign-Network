//! Neural Mesh Component — ML/AI intelligence layer for the Sovereign Network
//!
//! Integrates lib-neural-mesh into the RuntimeOrchestrator:
//! - **RlRouter** (PPO): intelligent routing decisions based on network state  
//! - **AnomalySentry** (Isolation Forest): Byzantine fault detection
//! - **PredictivePrefetcher** (LSTM): negative-latency shard prefetching
//! - **NeuroCompressor** (embeddings): semantic deduplication across the network
//!
//! Training loop:
//!   Network events → update models → better routing/compression → compress model weights → replicate
//!
//! This component subscribes to network events (peer connects, latency changes,
//! shard fetches) and feeds them into the ML models. Model decisions are exposed
//! via the ComponentMessage::Custom interface so other components (Protocols,
//! Consensus, Storage) can query for optimal routes, anomaly scores, and
//! prefetch hints.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::runtime::{Component, ComponentHealth, ComponentId, ComponentMessage, ComponentStatus};
use lib_neural_mesh::{
    AnomalyReport, AnomalySentry, NetworkState, NeuroCompressor, NodeMetrics,
    PredictivePrefetcher, RlRouter, RoutingAction,
    distributed::{
        CompressedModel, DistributedTrainingCoordinator, ModelCompressor, ModelId,
        ModelSyncMessage, SelfOptimizingMetrics,
    },
};

// ─── SovereignCodec Compressor ──────────────────────────────────────
// Implements the ModelCompressor trait using SovereignCodec.
// This is the SELF-REFERENTIAL part: the AI's own model weights are
// compressed by the same BWT→MTF→RLE→Range codec that the AI helps optimize.

/// Production compressor that wraps SovereignCodec for model weight compression
pub struct SovereignCodecCompressor;

impl ModelCompressor for SovereignCodecCompressor {
    fn compress(&self, data: &[u8]) -> Vec<u8> {
        lib_compression::SovereignCodec::encode(data)
    }

    fn decompress(&self, data: &[u8]) -> std::result::Result<Vec<u8>, String> {
        lib_compression::SovereignCodec::decode(data)
    }

    fn name(&self) -> &str {
        "SovereignCodec-SFC7"
    }
}

/// Statistics tracked during operation
#[derive(Debug, Default, Clone)]
pub struct NeuralMeshStats {
    pub routing_decisions: u64,
    pub anomalies_detected: u64,
    pub prefetch_predictions: u64,
    pub embeddings_computed: u64,
    pub training_episodes: u64,
    pub total_reward: f64,
    pub avg_routing_confidence: f64,
    pub distributed_syncs: u64,
    pub fedavg_rounds: u64,
    pub model_bytes_saved: u64,
}

/// Neural Mesh runtime component
#[derive(Debug)]
pub struct NeuralMeshComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,

    // ML sub-components
    router: Arc<RwLock<RlRouter>>,
    anomaly: Arc<RwLock<AnomalySentry>>,
    prefetcher: Arc<RwLock<PredictivePrefetcher>>,
    compressor: Arc<RwLock<NeuroCompressor>>,

    // Distributed training — self-compressing neural mesh
    // More nodes = faster training because FedAvg merges gradients from all peers
    // The AI's own model weights are ZKC-compressed by SovereignCodec
    distributed: Arc<RwLock<DistributedTrainingCoordinator>>,

    // Operational stats
    stats: Arc<RwLock<NeuralMeshStats>>,

    // Baseline training data for anomaly detection
    baseline_metrics: Arc<RwLock<Vec<NodeMetrics>>>,
}

impl NeuralMeshComponent {
    pub fn new() -> Self {
        let node_id = uuid::Uuid::new_v4().to_string();

        // Create distributed coordinator with SovereignCodec compressor
        // This is the self-referential part: the AI compresses itself
        let coordinator = DistributedTrainingCoordinator::with_compressor(
            node_id,
            Arc::new(SovereignCodecCompressor),
        );

        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            router: Arc::new(RwLock::new(RlRouter::new())),
            anomaly: Arc::new(RwLock::new(AnomalySentry::new())),
            prefetcher: Arc::new(RwLock::new(PredictivePrefetcher::new())),
            compressor: Arc::new(RwLock::new(NeuroCompressor::new())),
            distributed: Arc::new(RwLock::new(coordinator)),
            stats: Arc::new(RwLock::new(NeuralMeshStats::default())),
            baseline_metrics: Arc::new(RwLock::new(Vec::new())),
        }
    }

    // ── Public accessors (for inter-component queries) ──

    /// Select optimal route for the given network state
    pub async fn select_route(&self, state: &NetworkState) -> Result<RoutingAction> {
        let mut router = self.router.write().await;
        let action = router.select_action(state)?;
        let mut stats = self.stats.write().await;
        stats.routing_decisions += 1;
        stats.avg_routing_confidence = (stats.avg_routing_confidence
            * (stats.routing_decisions - 1) as f64
            + action.confidence as f64)
            / stats.routing_decisions as f64;
        Ok(action)
    }

    /// Provide reward signal to the RL router after a routing decision
    pub async fn provide_routing_reward(
        &self,
        reward: f32,
        next_state: &NetworkState,
        done: bool,
    ) -> Result<()> {
        let mut router = self.router.write().await;
        router.provide_reward(reward, next_state, done)?;
        let mut stats = self.stats.write().await;
        stats.total_reward += reward as f64;
        Ok(())
    }

    /// Run a policy update step on the RL router (batch training)
    pub async fn update_routing_policy(&self) -> Result<f32> {
        let mut router = self.router.write().await;
        let loss = router.update_policy()?;
        let mut stats = self.stats.write().await;
        stats.training_episodes += 1;
        info!(
            "RL Router policy update: loss={:.4}, episodes={}",
            loss, stats.training_episodes
        );
        Ok(loss)
    }

    /// Detect anomaly for a given node's metrics
    pub async fn detect_anomaly(&self, metrics: &NodeMetrics) -> Result<AnomalyReport> {
        let sentry = self.anomaly.read().await;
        let report = sentry.detect_anomaly(metrics)?;
        if report.severity != lib_neural_mesh::AnomalySeverity::Low {
            let mut stats = self.stats.write().await;
            stats.anomalies_detected += 1;
        }
        Ok(report)
    }

    /// Record a shard access pattern for the prefetcher
    pub async fn record_shard_access(&self, shard_id: String, context: String) {
        let mut prefetcher = self.prefetcher.write().await;
        let pattern = lib_neural_mesh::AccessPattern {
            shard_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            context,
        };
        prefetcher.record_access(pattern);
    }

    /// Get prefetch predictions for a given context
    pub async fn predict_prefetch(
        &self,
        context: &str,
        num_predictions: usize,
    ) -> Result<Vec<lib_neural_mesh::PredictionResult>> {
        let mut prefetcher = self.prefetcher.write().await;
        let predictions = prefetcher.predict_next(context, num_predictions)?;
        let mut stats = self.stats.write().await;
        stats.prefetch_predictions += 1;
        Ok(predictions)
    }

    /// Compute content embedding for semantic deduplication
    pub async fn embed_content(&self, data: &[u8]) -> Result<lib_neural_mesh::Embedding> {
        let compressor = self.compressor.read().await;
        let embedding = compressor.embed(data)?;
        let mut stats = self.stats.write().await;
        stats.embeddings_computed += 1;
        Ok(embedding)
    }

    /// Add baseline metrics for anomaly detection training
    pub async fn add_baseline_metrics(&self, metrics: NodeMetrics) {
        self.baseline_metrics.write().await.push(metrics);
    }

    /// Train the anomaly detector on collected baseline metrics
    pub async fn train_anomaly_baseline(&self) -> Result<usize> {
        let metrics = self.baseline_metrics.read().await.clone();
        let count = metrics.len();
        if count >= 10 {
            let mut sentry = self.anomaly.write().await;
            sentry.train_baseline(metrics)?;
            info!("Anomaly Sentry trained on {} baseline metric samples", count);
        } else {
            warn!(
                "Only {} baseline samples collected, need at least 10 to train",
                count
            );
        }
        Ok(count)
    }

    /// Export all model weights as compressed bytes (for network replication)
    pub async fn export_model_weights(&self) -> Result<Vec<u8>> {
        let router = self.router.read().await;
        let weights = router.save_model()?;
        info!("Exported RL Router model: {} bytes", weights.len());
        Ok(weights)
    }

    /// Import model weights from a peer (federated learning)
    pub async fn import_model_weights(&self, data: &[u8]) -> Result<()> {
        let mut router = self.router.write().await;
        // RL Router: 5 = state_dim (congestion, latency, bandwidth, packet_loss, energy)
        // 3 = action_dim (3 possible route choices)
        router.load_model(data, 5, 3)?;
        info!("Imported RL Router model from peer: {} bytes", data.len());
        Ok(())
    }

    /// Get a snapshot of current operational stats
    pub async fn get_stats(&self) -> NeuralMeshStats {
        self.stats.read().await.clone()
    }

    // ── Distributed Training (self-compressing neural mesh) ──

    /// Export ALL model weights as compressed bundles ready for mesh broadcast.
    /// Each model (RL Router, Prefetcher, Anomaly Sentry) is independently
    /// ZKC-compressed using SovereignCodec — the same codec the AI optimizes.
    pub async fn export_all_compressed_models(&self) -> Vec<CompressedModel> {
        let mut models = Vec::new();
        let dist = self.distributed.read().await;

        // RL Router weights
        if let Ok(raw) = self.router.read().await.save_model() {
            let compressed = dist.export_compressed_model(ModelId::RlRouter, &raw).await;
            info!("🧠📦 RL Router: {} → {} bytes ({:.1}x)",
                compressed.raw_size, compressed.compressed_weights.len(), compressed.compression_ratio);
            models.push(compressed);
        }

        // Prefetcher LSTM weights
        if let Ok(raw) = self.prefetcher.read().await.save_model() {
            let compressed = dist.export_compressed_model(ModelId::Prefetcher, &raw).await;
            info!("🧠📦 Prefetcher: {} → {} bytes ({:.1}x)",
                compressed.raw_size, compressed.compressed_weights.len(), compressed.compression_ratio);
            models.push(compressed);
        }

        // Anomaly Sentry weights
        if let Ok(raw) = self.anomaly.read().await.save_model() {
            let compressed = dist.export_compressed_model(ModelId::AnomalySentry, &raw).await;
            info!("🧠📦 Anomaly Sentry: {} → {} bytes ({:.1}x)",
                compressed.raw_size, compressed.compressed_weights.len(), compressed.compression_ratio);
            models.push(compressed);
        }

        models
    }

    /// Receive a compressed model from a peer and check if FedAvg should run.
    /// Returns true if enough peers have contributed for FedAvg.
    pub async fn receive_peer_model(&self, compressed: CompressedModel, sample_count: u64) -> bool {
        let dist = self.distributed.read().await;
        dist.receive_peer_model(compressed, sample_count).await
    }

    /// Run Federated Averaging for a specific model, merging local + peer weights.
    /// More nodes = more diverse gradients = faster convergence.
    pub async fn run_federated_average(&self, model_id: ModelId) -> Result<()> {
        let local_weights = match model_id {
            ModelId::RlRouter => self.router.read().await.save_model()?,
            ModelId::Prefetcher => self.prefetcher.read().await.save_model()?,
            ModelId::AnomalySentry => self.anomaly.read().await.save_model()?,
        };

        let dist = self.distributed.read().await;
        let result = dist.federated_average(model_id, &local_weights).await?;

        // Apply merged weights back to the local model
        match model_id {
            ModelId::RlRouter => {
                let mut router = self.router.write().await;
                router.load_model(&result.merged_weights, 5, 3)?;
                info!("🧠🔄 FedAvg: RL Router updated (gen={}, {} contributors)",
                    result.generation, result.num_contributors);
            }
            ModelId::Prefetcher => {
                let mut prefetcher = self.prefetcher.write().await;
                prefetcher.load_model(&result.merged_weights)?;
                info!("🧠🔄 FedAvg: Prefetcher updated (gen={}, {} contributors)",
                    result.generation, result.num_contributors);
            }
            ModelId::AnomalySentry => {
                let mut sentry = self.anomaly.write().await;
                sentry.load_model(&result.merged_weights)?;
                info!("🧠🔄 FedAvg: Anomaly Sentry updated (gen={}, {} contributors)",
                    result.generation, result.num_contributors);
            }
        }

        Ok(())
    }

    /// Get the self-optimization loop metrics (how well is the AI compressing and training itself?)
    pub async fn get_loop_metrics(&self) -> SelfOptimizingMetrics {
        self.distributed.read().await.loop_metrics().await
    }

    /// Record local training activity for FedAvg weighting
    pub async fn record_distributed_training(&self, model_id: ModelId, samples: u64) {
        self.distributed.read().await.record_local_training(model_id, samples).await;
    }
}

#[async_trait::async_trait]
impl Component for NeuralMeshComponent {
    fn id(&self) -> ComponentId {
        ComponentId::NeuralMesh
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("🧠 Starting Neural Mesh component...");
        *self.status.write().await = ComponentStatus::Starting;

        // Enable the RL Router with network state dimensions
        // State: [congestion, avg_latency, avg_bandwidth, avg_packet_loss, avg_energy] = 5
        // Actions: [route_choice_0, route_choice_1, route_choice_2] = 3
        {
            let mut router = self.router.write().await;
            router.enable(5, 3);
            info!("  RL Router enabled (PPO, state_dim=5, action_dim=3)");
        }

        // Enable the Anomaly Sentry
        {
            let mut sentry = self.anomaly.write().await;
            sentry.enable();
            sentry.set_threshold(0.7);
            info!("  Anomaly Sentry enabled (Isolation Forest, threshold=0.7)");
        }

        // Enable the Predictive Prefetcher
        {
            let mut prefetcher = self.prefetcher.write().await;
            prefetcher.enable_default();
            prefetcher.set_threshold(0.8);
            info!("  Predictive Prefetcher enabled (LSTM, threshold=0.8)");
        }

        // Enable the Neuro-Compressor (statistical embeddings — no ONNX model needed)
        {
            let mut compressor = self.compressor.write().await;
            compressor.enable();
            info!("  Neuro-Compressor enabled (512-dim statistical embeddings)");
        }

        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;

        // Spawn background training loop — periodically trains anomaly baseline,
        // updates routing policy, and exports compressed models for distributed sync.
        // This is the self-optimizing loop:
        //   train locally → compress weights → broadcast → FedAvg → better model → repeat
        let status_clone = self.status.clone();
        let anomaly_clone = self.anomaly.clone();
        let router_clone = self.router.clone();
        let baseline_clone = self.baseline_metrics.clone();
        let stats_clone = self.stats.clone();
        let distributed_clone = self.distributed.clone();
        let prefetcher_clone = self.prefetcher.clone();
        let anomaly_export_clone = self.anomaly.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            let mut cycle_count: u64 = 0;
            loop {
                interval.tick().await;
                cycle_count += 1;

                // Check if still running
                if !matches!(*status_clone.read().await, ComponentStatus::Running) {
                    break;
                }

                // Train anomaly baseline if we have enough samples
                let baseline_count = baseline_clone.read().await.len();
                if baseline_count >= 10 {
                    let baselines = baseline_clone.read().await.clone();
                    let mut sentry = anomaly_clone.write().await;
                    match sentry.train_baseline(baselines) {
                        Ok(()) => {
                            info!(
                                "🧠 Auto-trained anomaly baseline on {} samples",
                                baseline_count
                            );
                        }
                        Err(e) => {
                            debug!("Auto anomaly training: {}", e);
                        }
                    }
                }

                // Update routing policy if experiences accumulated
                {
                    let mut router = router_clone.write().await;
                    match router.update_policy() {
                        Ok(loss) => {
                            if !loss.is_nan() {
                                let mut stats = stats_clone.write().await;
                                stats.training_episodes += 1;
                                info!(
                                    "🧠 Auto-updated routing policy: loss={:.4}, episodes={}",
                                    loss, stats.training_episodes
                                );
                            }
                        }
                        Err(_) => {
                            // Not enough experiences yet — this is normal early on
                        }
                    }
                }

                // ── Self-Compressing Distributed Sync (every 2nd cycle = ~60s) ──
                // Export compressed model weights for peer distribution.
                // The AI compresses ITSELF using SovereignCodec, the same codec
                // it optimizes through its routing decisions.
                if cycle_count % 2 == 0 {
                    let dist = distributed_clone.read().await;

                    // Export RL Router (most important — drives routing)
                    if let Ok(raw) = router_clone.read().await.save_model() {
                        let compressed = dist.export_compressed_model(
                            lib_neural_mesh::distributed::ModelId::RlRouter, &raw
                        ).await;
                        info!(
                            "🧠📦 Self-compressed RL Router: {} → {} bytes ({:.1}x) — cycle {}",
                            compressed.raw_size, compressed.compressed_weights.len(),
                            compressed.compression_ratio, cycle_count
                        );
                        dist.record_local_training(
                            lib_neural_mesh::distributed::ModelId::RlRouter,
                            stats_clone.read().await.routing_decisions
                        ).await;
                    }

                    // Export LSTM Prefetcher (every 4th cycle = ~120s)
                    if cycle_count % 4 == 0 {
                        if let Ok(raw) = prefetcher_clone.read().await.save_model() {
                            let compressed = dist.export_compressed_model(
                                lib_neural_mesh::distributed::ModelId::Prefetcher, &raw
                            ).await;
                            info!(
                                "🧠📦 Self-compressed Prefetcher: {} → {} bytes ({:.1}x)",
                                compressed.raw_size, compressed.compressed_weights.len(),
                                compressed.compression_ratio
                            );
                        }
                    }

                    // Export Anomaly Sentry (every 6th cycle = ~180s)
                    if cycle_count % 6 == 0 {
                        if let Ok(raw) = anomaly_export_clone.read().await.save_model() {
                            let compressed = dist.export_compressed_model(
                                lib_neural_mesh::distributed::ModelId::AnomalySentry, &raw
                            ).await;
                            info!(
                                "🧠📦 Self-compressed Anomaly Sentry: {} → {} bytes ({:.1}x)",
                                compressed.raw_size, compressed.compressed_weights.len(),
                                compressed.compression_ratio
                            );
                        }
                    }

                    // Log self-optimization loop metrics
                    let metrics = dist.loop_metrics().await;
                    if metrics.fedavg_rounds > 0 || metrics.total_model_bytes_raw > 0 {
                        info!("{}", metrics.summary());
                    }
                }
            }
            debug!("Neural mesh background training loop exited");
        });

        info!("🧠 Neural Mesh component running — all 4 sub-components active + background training");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping Neural Mesh component...");
        *self.status.write().await = ComponentStatus::Stopping;

        // Export model weights before shutdown (so they can be persisted)
        match self.export_model_weights().await {
            Ok(weights) => {
                info!(
                    "Neural mesh model weights exported: {} bytes (for persistence)",
                    weights.len()
                );
            }
            Err(e) => {
                warn!("Failed to export model weights on shutdown: {}", e);
            }
        }

        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Neural Mesh component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        let stats = self.stats.read().await;

        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: (stats.routing_decisions + stats.embeddings_computed) * 64, // rough estimate
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            // ── Peer lifecycle events → Anomaly Sentry baseline + RL Router training ──
            ComponentMessage::PeerConnected(peer_id) => {
                info!("Neural mesh: peer connected — {}", peer_id);
                // Seed baseline metrics for the new peer
                self.add_baseline_metrics(NodeMetrics {
                    node_id: peer_id.clone(),
                    response_time: 100.0,   // default 100ms
                    success_rate: 1.0,       // assume healthy
                    corruption_rate: 0.0,
                    participation_rate: 1.0,
                    reputation: 0.5,         // neutral starting reputation
                })
                .await;

                // Generate a routing experience from the peer connection event
                // This feeds the RL router with real network topology changes
                {
                    let state = NetworkState {
                        latencies: std::collections::HashMap::from([
                            (peer_id.clone(), 100.0),
                        ]),
                        bandwidth: std::collections::HashMap::from([
                            (peer_id.clone(), 1000.0),
                        ]),
                        packet_loss: std::collections::HashMap::new(),
                        energy_scores: std::collections::HashMap::new(),
                        congestion: 0.3,
                    };
                    let mut router = self.router.write().await;
                    if let Ok(action) = router.select_action(&state) {
                        // Reward for accepting a new peer (expanding the network)
                        let reward = 0.5;
                        let next_state = NetworkState {
                            congestion: 0.25,
                            ..state
                        };
                        let _ = router.provide_reward(reward, &next_state, false);
                        let mut stats = self.stats.write().await;
                        stats.routing_decisions += 1;
                        stats.total_reward += reward as f64;
                        debug!(
                            "Neural mesh: RL episode from peer connect — action={}, reward={}",
                            action.action_id, reward
                        );
                    }
                }
                Ok(())
            }

            ComponentMessage::PeerDisconnected(peer_id) => {
                info!("Neural mesh: peer disconnected — {}", peer_id);
                // Negative reward — losing a peer is penalized
                {
                    let state = NetworkState {
                        latencies: std::collections::HashMap::new(),
                        bandwidth: std::collections::HashMap::new(),
                        packet_loss: std::collections::HashMap::new(),
                        energy_scores: std::collections::HashMap::new(),
                        congestion: 0.6,
                    };
                    let mut router = self.router.write().await;
                    if let Ok(_action) = router.select_action(&state) {
                        let next_state = NetworkState {
                            congestion: 0.7,
                            ..state
                        };
                        let _ = router.provide_reward(-0.3, &next_state, false);
                        let mut stats = self.stats.write().await;
                        stats.total_reward -= 0.3;
                    }
                }
                Ok(())
            }

            // ── Network state update → RL Router training ──
            ComponentMessage::NetworkUpdate(state_json) => {
                debug!("Neural mesh: network state update");
                // Parse the network state and provide to the router
                if let Ok(state) = serde_json::from_str::<NetworkState>(&state_json) {
                    match self.select_route(&state).await {
                        Ok(action) => {
                            debug!(
                                "Neural mesh route decision: {:?} (confidence: {:.2})",
                                action.nodes, action.confidence
                            );
                        }
                        Err(e) => {
                            debug!("Neural mesh routing fallback: {}", e);
                        }
                    }
                }
                Ok(())
            }

            // ── Shard access events → Predictive Prefetcher ──
            ComponentMessage::FileRequested(shard_id) => {
                debug!("Neural mesh: shard access recorded — {}", shard_id);
                self.record_shard_access(shard_id, "fetch".to_string())
                    .await;
                Ok(())
            }

            ComponentMessage::FileStored(shard_id) => {
                debug!("Neural mesh: shard stored — {}", shard_id);
                self.record_shard_access(shard_id, "store".to_string())
                    .await;
                Ok(())
            }

            // ── Custom messages for explicit queries ──
            ComponentMessage::Custom(op, data) => {
                match op.as_str() {
                    "select_route" => {
                        if let Ok(state) = serde_json::from_slice::<NetworkState>(&data) {
                            match self.select_route(&state).await {
                                Ok(action) => {
                                    info!("Route selected: {:?}", action);
                                }
                                Err(e) => warn!("Route selection failed: {}", e),
                            }
                        }
                    }
                    "detect_anomaly" => {
                        if let Ok(metrics) = serde_json::from_slice::<NodeMetrics>(&data) {
                            match self.detect_anomaly(&metrics).await {
                                Ok(report) => {
                                    if report.severity != lib_neural_mesh::AnomalySeverity::Low {
                                        warn!(
                                            "Anomaly detected: node={}, severity={:?}, type={:?}",
                                            report.node_id, report.severity, report.threat_type
                                        );
                                    }
                                }
                                Err(e) => warn!("Anomaly detection failed: {}", e),
                            }
                        }
                    }
                    "predict_prefetch" => {
                        let context = String::from_utf8_lossy(&data);
                        match self.predict_prefetch(&context, 5).await {
                            Ok(predictions) => {
                                let high_conf: Vec<_> = predictions
                                    .iter()
                                    .filter(|p| p.confidence > 0.8)
                                    .collect();
                                if !high_conf.is_empty() {
                                    info!(
                                        "Prefetch predictions: {} high-confidence shards",
                                        high_conf.len()
                                    );
                                }
                            }
                            Err(e) => debug!("Prefetch prediction: {}", e),
                        }
                    }
                    "train_anomaly_baseline" => {
                        match self.train_anomaly_baseline().await {
                            Ok(n) => info!("Trained anomaly baseline on {} samples", n),
                            Err(e) => warn!("Anomaly baseline training failed: {}", e),
                        }
                    }
                    "update_routing_policy" => {
                        match self.update_routing_policy().await {
                            Ok(loss) => info!("Routing policy updated: loss={:.4}", loss),
                            Err(e) => warn!("Routing policy update failed: {}", e),
                        }
                    }
                    "export_model" => {
                        match self.export_model_weights().await {
                            Ok(weights) => {
                                info!("Model exported: {} bytes", weights.len());
                            }
                            Err(e) => warn!("Model export failed: {}", e),
                        }
                    }
                    "import_model" => {
                        match self.import_model_weights(&data).await {
                            Ok(()) => info!("Model imported successfully"),
                            Err(e) => warn!("Model import failed: {}", e),
                        }
                    }
                    // ── Distributed Training Operations ──
                    "receive_peer_model" => {
                        // Receive compressed model from a peer for FedAvg
                        if let Ok(msg) = ModelSyncMessage::from_bytes(&data) {
                            match msg {
                                ModelSyncMessage::BroadcastModel { model, sample_count } => {
                                    let model_id = model.model_id;
                                    let ready = self.receive_peer_model(model, sample_count).await;
                                    if ready {
                                        info!("🧠🔄 FedAvg threshold reached for {} — merging", model_id);
                                        if let Err(e) = self.run_federated_average(model_id).await {
                                            warn!("FedAvg failed for {}: {}", model_id, e);
                                        }
                                    }
                                }
                                ModelSyncMessage::FedAvgResult { model_id, result } => {
                                    // Apply FedAvg result from a coordinator node
                                    match model_id {
                                        ModelId::RlRouter => {
                                            let mut router = self.router.write().await;
                                            let _ = router.load_model(&result.merged_weights, 5, 3);
                                        }
                                        ModelId::Prefetcher => {
                                            let mut pf = self.prefetcher.write().await;
                                            let _ = pf.load_model(&result.merged_weights);
                                        }
                                        ModelId::AnomalySentry => {
                                            let mut s = self.anomaly.write().await;
                                            let _ = s.load_model(&result.merged_weights);
                                        }
                                    }
                                    info!("🧠✅ Applied FedAvg result for {} (gen={})", model_id, result.generation);
                                }
                                _ => {}
                            }
                        }
                    }
                    "export_compressed_models" => {
                        let models = self.export_all_compressed_models().await;
                        info!("🧠📤 Exported {} compressed model bundles for mesh broadcast", models.len());
                    }
                    "loop_metrics" => {
                        let metrics = self.get_loop_metrics().await;
                        info!("{}", metrics.summary());
                    }
                    _ => {
                        debug!("Neural mesh: unknown custom operation: {}", op);
                    }
                }
                Ok(())
            }

            ComponentMessage::HealthCheck => {
                debug!("Neural mesh health check");
                Ok(())
            }

            _ => {
                debug!("Neural mesh: unhandled message {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time
            .map(|t| t.elapsed().as_secs() as f64)
            .unwrap_or(0.0);
        let stats = self.stats.read().await;

        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert(
            "is_running".to_string(),
            if matches!(*self.status.read().await, ComponentStatus::Running) {
                1.0
            } else {
                0.0
            },
        );
        metrics.insert(
            "routing_decisions".to_string(),
            stats.routing_decisions as f64,
        );
        metrics.insert(
            "anomalies_detected".to_string(),
            stats.anomalies_detected as f64,
        );
        metrics.insert(
            "prefetch_predictions".to_string(),
            stats.prefetch_predictions as f64,
        );
        metrics.insert(
            "embeddings_computed".to_string(),
            stats.embeddings_computed as f64,
        );
        metrics.insert(
            "training_episodes".to_string(),
            stats.training_episodes as f64,
        );
        metrics.insert("total_reward".to_string(), stats.total_reward);
        metrics.insert(
            "avg_routing_confidence".to_string(),
            stats.avg_routing_confidence,
        );
        metrics.insert(
            "distributed_syncs".to_string(),
            stats.distributed_syncs as f64,
        );
        metrics.insert(
            "fedavg_rounds".to_string(),
            stats.fedavg_rounds as f64,
        );
        metrics.insert(
            "model_bytes_saved".to_string(),
            stats.model_bytes_saved as f64,
        );

        // Add self-optimization loop metrics
        let loop_metrics = self.distributed.read().await.loop_metrics().await;
        metrics.insert(
            "model_compression_ratio".to_string(),
            loop_metrics.avg_model_compression_ratio as f64,
        );
        metrics.insert(
            "acceleration_factor".to_string(),
            loop_metrics.acceleration_factor as f64,
        );

        Ok(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_neural_mesh_lifecycle() {
        let component = NeuralMeshComponent::new();
        assert!(matches!(
            *component.status.read().await,
            ComponentStatus::Stopped
        ));

        component.start().await.unwrap();
        assert!(matches!(
            *component.status.read().await,
            ComponentStatus::Running
        ));

        // Test routing
        let state = NetworkState {
            latencies: HashMap::from([("peer1".into(), 50.0), ("peer2".into(), 100.0)]),
            bandwidth: HashMap::from([("peer1".into(), 1000.0), ("peer2".into(), 500.0)]),
            packet_loss: HashMap::from([("peer1".into(), 0.01), ("peer2".into(), 0.05)]),
            energy_scores: HashMap::from([("peer1".into(), 0.8), ("peer2".into(), 0.6)]),
            congestion: 0.3,
        };
        let action = component.select_route(&state).await.unwrap();
        assert!(action.confidence >= 0.0);

        // Test anomaly detection
        let metrics = NodeMetrics {
            node_id: "peer1".to_string(),
            response_time: 50.0,
            success_rate: 0.99,
            corruption_rate: 0.0,
            participation_rate: 0.95,
            reputation: 0.8,
        };
        let report = component.detect_anomaly(&metrics).await.unwrap();
        assert!(!report.node_id.is_empty());

        // Test prefetch
        component
            .record_shard_access("shard-001".to_string(), "fetch".to_string())
            .await;

        // Test embedding
        let embedding = component.embed_content(b"hello world").await.unwrap();
        assert_eq!(embedding.len(), 512);

        // Test stats
        let stats = component.get_stats().await;
        assert_eq!(stats.routing_decisions, 1);
        assert_eq!(stats.embeddings_computed, 1);

        component.stop().await.unwrap();
        assert!(matches!(
            *component.status.read().await,
            ComponentStatus::Stopped
        ));
    }

    #[tokio::test]
    async fn test_model_export_import() {
        let component = NeuralMeshComponent::new();
        component.start().await.unwrap();

        // Export model
        let weights = component.export_model_weights().await.unwrap();
        assert!(!weights.is_empty());

        // Import into a new component (federated learning simulation)
        let component2 = NeuralMeshComponent::new();
        component2.start().await.unwrap();
        component2.import_model_weights(&weights).await.unwrap();
    }

    #[tokio::test]
    async fn test_anomaly_baseline_training() {
        let component = NeuralMeshComponent::new();
        component.start().await.unwrap();

        // Add enough baseline samples
        for i in 0..20 {
            component
                .add_baseline_metrics(NodeMetrics {
                    node_id: format!("node-{}", i),
                    response_time: 100.0 + (i as f32 * 5.0),
                    success_rate: 0.95 + (i as f32 * 0.002),
                    corruption_rate: 0.001,
                    participation_rate: 0.9,
                    reputation: 0.7,
                })
                .await;
        }

        let count = component.train_anomaly_baseline().await.unwrap();
        assert_eq!(count, 20);

        // Now detect an anomalous node
        let report = component
            .detect_anomaly(&NodeMetrics {
                node_id: "malicious-node".to_string(),
                response_time: 5000.0, // Very slow
                success_rate: 0.1,     // Very unreliable
                corruption_rate: 0.5,  // Lots of corruption
                participation_rate: 0.1,
                reputation: 0.1,
            })
            .await
            .unwrap();

        assert_eq!(report.node_id, "malicious-node");
        // After training, extreme outlier should get a non-trivial score
        info!(
            "Anomaly score for malicious node: {}, severity: {:?}",
            report.score, report.severity
        );
    }
}
