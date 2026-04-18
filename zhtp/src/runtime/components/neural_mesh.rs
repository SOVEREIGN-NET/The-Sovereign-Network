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
};

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

    // Operational stats
    stats: Arc<RwLock<NeuralMeshStats>>,

    // Baseline training data for anomaly detection
    baseline_metrics: Arc<RwLock<Vec<NodeMetrics>>>,
}

impl NeuralMeshComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            router: Arc::new(RwLock::new(RlRouter::new())),
            anomaly: Arc::new(RwLock::new(AnomalySentry::new())),
            prefetcher: Arc::new(RwLock::new(PredictivePrefetcher::new())),
            compressor: Arc::new(RwLock::new(NeuroCompressor::new())),
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

        info!("🧠 Neural Mesh component running — all 4 sub-components active");
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
            // ── Peer lifecycle events → Anomaly Sentry baseline ──
            ComponentMessage::PeerConnected(peer_id) => {
                info!("Neural mesh: peer connected — {}", peer_id);
                // Seed baseline metrics for the new peer
                self.add_baseline_metrics(NodeMetrics {
                    node_id: peer_id,
                    response_time: 100.0,   // default 100ms
                    success_rate: 1.0,       // assume healthy
                    corruption_rate: 0.0,
                    participation_rate: 1.0,
                    reputation: 0.5,         // neutral starting reputation
                })
                .await;
                Ok(())
            }

            ComponentMessage::PeerDisconnected(peer_id) => {
                info!("Neural mesh: peer disconnected — {}", peer_id);
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
