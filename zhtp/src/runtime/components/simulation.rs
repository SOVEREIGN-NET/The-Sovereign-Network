//! Multi-Node Simulation — Dev/Demo harness for the Neural Mesh
//!
//! When `ZHTP_MULTI_NODE_SIM=1` is set, this module spawns 4 virtual peer nodes
//! that independently train RL routers, compress + broadcast model weights,
//! trigger FedAvg, generate diverse compression workloads, inject anomalous
//! metrics, and feed prefetcher access patterns.
//!
//! This is development-only code — it exercises the full distributed pipeline
//! on a single machine so you can observe the self-optimizing loop in action.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::runtime::ComponentStatus;
use lib_neural_mesh::{
    AnomalySentry, NetworkState, NodeMetrics,
    PredictivePrefetcher, RlRouter,
    AdaptiveCodecLearner,
    content::{ContentProfile, CompressionFeedback},
    distributed::{
        CompressedModel, DistributedTrainingCoordinator, ModelId,
    },
};

use super::neural_mesh::{NeuralMeshStats, SovereignCodecCompressor};

/// Spawns a background task that simulates 4 virtual peer nodes, each with
/// different workload profiles. These simulated nodes:
/// 1. Train their own local RL routers on distinct network conditions
/// 2. Compress their model weights using SovereignCodec (SFC7/SFC9)
/// 3. Send compressed models to this node via receive_peer_model()
/// 4. Trigger real Federated Averaging when enough peers contribute
/// 5. Generate diverse compression workloads for the Adaptive Codec Learner
/// 6. Inject anomalous node metrics to test the Anomaly Sentry
/// 7. Generate access patterns for the Predictive Prefetcher
///
/// This lets you see the entire distributed system working on a single machine.
pub fn spawn_multi_node_simulation(
    distributed: Arc<RwLock<DistributedTrainingCoordinator>>,
    router: Arc<RwLock<RlRouter>>,
    anomaly: Arc<RwLock<AnomalySentry>>,
    prefetcher: Arc<RwLock<PredictivePrefetcher>>,
    codec_learner: Arc<RwLock<AdaptiveCodecLearner>>,
    baseline_metrics: Arc<RwLock<Vec<NodeMetrics>>>,
    stats: Arc<RwLock<NeuralMeshStats>>,
    status: Arc<RwLock<ComponentStatus>>,
) {
    let sim_handle = tokio::spawn(async move {
        info!("🌐🧪 Multi-Node Simulation starting — 4 virtual peer nodes");
        info!("🌐🧪   sim-node-alpha  (JSON/API workload)");
        info!("🌐🧪   sim-node-beta   (Binary/model weights)");
        info!("🌐🧪   sim-node-gamma  (Mixed text + markup)");
        info!("🌐🧪   sim-node-delta  (High-entropy adversarial)");

        // Give the main training loop time to initialize
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Each sim node has its own RL router that trains on different conditions
        let node_names = ["sim-node-alpha", "sim-node-beta", "sim-node-gamma", "sim-node-delta"];
        let mut sim_routers: Vec<RlRouter> = (0..4).map(|_| {
            let mut r = RlRouter::new();
            r.enable(5, 3);
            r
        }).collect();

        // Warm up each sim router with different network profiles
        warm_up_sim_routers(&mut sim_routers, &node_names);

        let compressor = SovereignCodecCompressor;
        let mut sim_cycle: u64 = 0;

        loop {
            // 15-second interval (offset from the main 30s loop)
            tokio::time::sleep(Duration::from_secs(15)).await;
            sim_cycle += 1;

            if !matches!(*status.read().await, ComponentStatus::Running) {
                info!("🌐🧪 Multi-node simulation stopping (component no longer running)");
                break;
            }

            info!("🌐🧪 ═══ Simulation cycle {} ═══", sim_cycle);

            // Phase 1: Each sim node trains on its workload
            train_sim_routers(&mut sim_routers, &node_names, sim_cycle);

            // Phase 2: Sim nodes export + compress models, send to local node
            exchange_models(
                &sim_routers, &node_names, sim_cycle,
                &compressor, &distributed, &router, &stats,
            ).await;

            // Phase 3: Feed the local RL router with multi-hop routing
            feed_routing_decisions(&router, &node_names, sim_cycle, &stats).await;

            // Phase 4: Generate diverse compression workloads
            generate_compression_workloads(&codec_learner, sim_cycle, &stats).await;

            // Phase 5: Anomaly detection — inject one bad node per cycle
            run_anomaly_detection(
                &baseline_metrics, &anomaly, &node_names, sim_cycle, &stats,
            ).await;

            // Phase 6: Prefetcher access patterns
            feed_prefetcher(&prefetcher, &node_names, sim_cycle, &stats).await;

            // Summary every 4 cycles
            if sim_cycle % 4 == 0 {
                log_simulation_summary(&stats, &distributed, sim_cycle).await;
            }
        }
    });

    // Watch the sim task's JoinHandle so panics are logged instead of silently swallowed
    tokio::spawn(async move {
        match sim_handle.await {
            Ok(()) => info!("🌐🧪 Multi-node simulation task completed normally"),
            Err(e) => {
                if e.is_panic() {
                    let panic_info = e.into_panic();
                    let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        format!("{:?}", panic_info)
                    };
                    error!("🌐🧪 ❌ MULTI-NODE SIMULATION PANICKED: {}", msg);
                    error!("🌐🧪 ❌ Set RUST_BACKTRACE=1 for full backtrace");
                } else {
                    error!("🌐🧪 ❌ Multi-node simulation task was cancelled");
                }
            }
        }
    });
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn warm_up_sim_routers(sim_routers: &mut [RlRouter], node_names: &[&str; 4]) {
    for (idx, sim_router) in sim_routers.iter_mut().enumerate() {
        let base_congestion = [0.1, 0.4, 0.25, 0.6][idx];
        let base_latency = [15.0_f32, 80.0, 40.0, 150.0][idx];
        let base_bw = [2000.0_f32, 500.0, 1200.0, 300.0][idx];
        for i in 0..30u32 {
            let jitter = (i as f32) * 0.01;
            let state = NetworkState {
                latencies: HashMap::from([
                    (node_names[idx].into(), base_latency + jitter * 20.0),
                    ("local-node".into(), 5.0 + jitter * 10.0),
                ]),
                bandwidth: HashMap::from([
                    (node_names[idx].into(), base_bw - jitter * 50.0),
                    ("local-node".into(), 1500.0),
                ]),
                packet_loss: HashMap::from([
                    (node_names[idx].into(), 0.005 + jitter * 0.01),
                ]),
                energy_scores: HashMap::from([
                    (node_names[idx].into(), 0.7 - jitter * 0.1),
                ]),
                congestion: base_congestion + jitter,
            };
            if sim_router.select_action(&state).is_ok() {
                let reward = if base_congestion < 0.3 { 0.5 } else { -0.2 };
                let next = NetworkState { congestion: base_congestion, ..state };
                let _ = sim_router.provide_reward(reward, &next, i == 29);
            }
        }
        let _ = sim_router.update_policy();
    }
}

fn train_sim_routers(sim_routers: &mut [RlRouter], node_names: &[&str; 4], sim_cycle: u64) {
    for (idx, sim_router) in sim_routers.iter_mut().enumerate() {
        let profiles: Vec<(f32, f32, f32)> = match idx {
            0 => vec![(0.1, 12.0, 2200.0), (0.15, 18.0, 2000.0), (0.08, 10.0, 2500.0)],
            1 => vec![(0.5, 90.0, 400.0), (0.55, 100.0, 350.0), (0.45, 85.0, 450.0)],
            2 => vec![(0.25, 35.0, 1100.0), (0.3, 45.0, 1000.0), (0.2, 30.0, 1300.0)],
            _ => vec![(0.7, 180.0, 200.0), (0.75, 200.0, 150.0), (0.65, 160.0, 250.0)],
        };
        for (cong, lat, bw) in &profiles {
            let state = NetworkState {
                latencies: HashMap::from([
                    (node_names[idx].into(), *lat),
                    ("local-node".into(), 5.0),
                ]),
                bandwidth: HashMap::from([
                    (node_names[idx].into(), *bw),
                    ("local-node".into(), 1500.0),
                ]),
                packet_loss: HashMap::from([(node_names[idx].into(), cong * 0.05)]),
                energy_scores: HashMap::from([(node_names[idx].into(), 1.0 - cong)]),
                congestion: *cong,
            };
            if sim_router.select_action(&state).is_ok() {
                let reward = 1.0 - cong * 2.0;
                let next = NetworkState { congestion: cong * 0.95, ..state };
                let _ = sim_router.provide_reward(reward, &next, false);
            }
        }
        let _ = sim_router.update_policy();
    }
}

#[allow(clippy::too_many_arguments)]
async fn exchange_models(
    sim_routers: &[RlRouter],
    node_names: &[&str; 4],
    sim_cycle: u64,
    compressor: &SovereignCodecCompressor,
    distributed: &Arc<RwLock<DistributedTrainingCoordinator>>,
    router: &Arc<RwLock<RlRouter>>,
    stats: &Arc<RwLock<NeuralMeshStats>>,
) {
    for (idx, sim_router) in sim_routers.iter().enumerate() {
        if let Ok(raw_weights) = sim_router.save_model() {
            let compressed = CompressedModel::compress(
                ModelId::RlRouter,
                &raw_weights,
                node_names[idx],
                sim_cycle,
                compressor,
            );
            let sample_count = 30 + sim_cycle * 3;
            info!(
                "🌐🧪 {} sent RL Router: {} → {} bytes ({:.1}x)",
                node_names[idx],
                compressed.raw_size,
                compressed.compressed_weights.len(),
                compressed.compression_ratio,
            );
            let ready = distributed.read().await
                .receive_peer_model(compressed, sample_count).await;
            if ready {
                info!("🌐🧪 🔄 FedAvg threshold reached! Merging {} peer models...", idx + 1);
                let local_weights = router.read().await.save_model();
                if let Ok(local_weights) = local_weights {
                    let result = distributed.read().await
                        .federated_average(ModelId::RlRouter, &local_weights).await;
                    match result {
                        Ok(result) => {
                            if router.write().await.load_model(&result.merged_weights, 5, 3).is_ok() {
                                stats.write().await.fedavg_rounds += 1;
                                info!(
                                    "🌐🧪 ✅ FedAvg complete: gen={}, {} contributors, {} total samples",
                                    result.generation, result.num_contributors, result.total_samples
                                );
                            }
                        }
                        Err(e) => warn!("🌐🧪 FedAvg failed: {}", e),
                    }
                }
            }
        }
    }
}

async fn feed_routing_decisions(
    router: &Arc<RwLock<RlRouter>>,
    node_names: &[&str; 4],
    sim_cycle: u64,
    stats: &Arc<RwLock<NeuralMeshStats>>,
) {
    let mut routing_count = 0u64;
    let mut r = router.write().await;
    for (idx, name) in node_names.iter().enumerate() {
        let hop_latency = [15.0_f32, 80.0, 40.0, 150.0][idx];
        let hop_bw = [2000.0_f32, 500.0, 1200.0, 300.0][idx];
        let jitter = ((sim_cycle * (idx as u64 + 1)) % 20) as f32;
        let state = NetworkState {
            latencies: HashMap::from([
                (name.to_string(), hop_latency + jitter),
                ("local".into(), 2.0),
            ]),
            bandwidth: HashMap::from([
                (name.to_string(), hop_bw - jitter * 5.0),
                ("local".into(), 2000.0),
            ]),
            packet_loss: HashMap::from([(name.to_string(), 0.01 * (idx as f32 + 1.0))]),
            energy_scores: HashMap::from([(name.to_string(), 0.9 - (idx as f32) * 0.1)]),
            congestion: 0.1 + (idx as f32) * 0.15 + jitter * 0.005,
        };
        if let Ok(action) = r.select_action(&state) {
            let reward = if action.confidence > 0.5 { 0.8 } else { 0.2 };
            let next_state = NetworkState { congestion: state.congestion * 0.9, ..state };
            let _ = r.provide_reward(reward, &next_state, false);
            routing_count += 1;
        }
    }
    let _ = r.update_policy();
    drop(r);
    if routing_count > 0 {
        stats.write().await.routing_decisions += routing_count;
    }
}

async fn generate_compression_workloads(
    codec_learner: &Arc<RwLock<AdaptiveCodecLearner>>,
    sim_cycle: u64,
    stats: &Arc<RwLock<NeuralMeshStats>>,
) {
    let mut learner = codec_learner.write().await;
    let workloads: Vec<(lib_neural_mesh::ContentType, f32, f32, usize)> = vec![
        (lib_neural_mesh::ContentType::Json, 3.8 + (sim_cycle % 10) as f32 * 0.1, 0.94, 60_000),
        (lib_neural_mesh::ContentType::Binary, 6.8 + (sim_cycle % 5) as f32 * 0.2, 0.12, 500_000),
        (lib_neural_mesh::ContentType::Text, 4.2 + (sim_cycle % 8) as f32 * 0.15, 0.90, 120_000),
        (lib_neural_mesh::ContentType::Markup, 4.0 + (sim_cycle % 6) as f32 * 0.1, 0.85, 80_000),
    ];
    for (ct, entropy, text_ratio, size) in &workloads {
        let profile = ContentProfile {
            content_type: *ct,
            entropy: *entropy,
            size: *size,
            text_ratio: *text_ratio,
            unique_bytes: ((*entropy * 30.0) as u16).min(256),
            avg_delta: entropy * 10.0,
        };
        let params = learner.predict_params(&profile);

        // Actually compress synthetic data to get real feedback
        let synthetic_data: Vec<u8> = (0..*size).map(|i| {
            match ct {
                lib_neural_mesh::ContentType::Json => {
                    let json_bytes = b"{{\"key\":\"value\",\"num\":12345,\"arr\":[1,2,3]}}";
                    json_bytes[i % json_bytes.len()]
                }
                lib_neural_mesh::ContentType::Text => {
                    let text = b"The quick brown fox jumps over the lazy dog. ";
                    text[i % text.len()]
                }
                lib_neural_mesh::ContentType::Markup => {
                    let html = b"<div class=\"container\"><p>Hello World</p></div>";
                    html[i % html.len()]
                }
                _ => ((i * 7 + 13) % 256) as u8,
            }
        }).collect();

        let codec_params = lib_compression::CodecParams {
            rescale_limit: params.rescale_limit,
            freq_step: params.freq_step,
            init_freq_zero: params.init_freq_zero,
        };
        let start = std::time::Instant::now();
        let compressed = lib_compression::SovereignCodec::encode_with_params(
            &synthetic_data, &codec_params,
        );
        let elapsed = start.elapsed().as_secs_f64();
        let ratio = synthetic_data.len() as f64 / compressed.len().max(1) as f64;
        let throughput = (synthetic_data.len() as f64 / 1_048_576.0) / elapsed.max(0.0001);

        let integrity_ok = lib_compression::SovereignCodec::decode(&compressed)
            .map(|d| d == synthetic_data)
            .unwrap_or(false);

        learner.observe_result(&CompressionFeedback {
            profile,
            ratio,
            total_ratio: ratio * 0.95,
            time_secs: elapsed,
            throughput_mbps: throughput,
            integrity_ok,
            shard_count: 1,
            shards_compressed: 1,
        });
    }

    let train_result = learner.train();
    let (epsilon, steps) = (learner.exploration_rate(), learner.training_steps());
    drop(learner);
    stats.write().await.codec_adaptations += 4;
    if let Some(loss) = train_result {
        info!(
            "🌐🧪 🎯 Codec Learner updated: loss={:.4}, ε={:.3}, step={}",
            loss, epsilon, steps
        );
    }
}

async fn run_anomaly_detection(
    baseline_metrics: &Arc<RwLock<Vec<NodeMetrics>>>,
    anomaly: &Arc<RwLock<AnomalySentry>>,
    node_names: &[&str; 4],
    sim_cycle: u64,
    stats: &Arc<RwLock<NeuralMeshStats>>,
) {
    let mut baselines = baseline_metrics.write().await;
    for name in &node_names[..3] {
        baselines.push(NodeMetrics {
            node_id: name.to_string(),
            response_time: 30.0 + (sim_cycle % 10) as f32 * 5.0,
            success_rate: 0.97,
            corruption_rate: 0.001,
            participation_rate: 0.92,
            reputation: 0.85,
        });
    }
    let anomaly_type = sim_cycle % 4;
    baselines.push(NodeMetrics {
        node_id: "sim-node-delta".into(),
        response_time: if anomaly_type == 0 { 800.0 } else { 50.0 },
        success_rate: if anomaly_type == 1 { 0.40 } else { 0.95 },
        corruption_rate: if anomaly_type == 2 { 0.15 } else { 0.002 },
        participation_rate: if anomaly_type == 3 { 0.20 } else { 0.90 },
        reputation: 0.3,
    });
    drop(baselines);

    let sentry = anomaly.read().await;
    let report = sentry.detect_anomaly(&NodeMetrics {
        node_id: "sim-node-delta".into(),
        response_time: if anomaly_type == 0 { 800.0 } else { 50.0 },
        success_rate: if anomaly_type == 1 { 0.40 } else { 0.95 },
        corruption_rate: if anomaly_type == 2 { 0.15 } else { 0.002 },
        participation_rate: if anomaly_type == 3 { 0.20 } else { 0.90 },
        reputation: 0.3,
    });
    if let Ok(report) = report {
        if report.score > 0.5 {
            let mut s = stats.write().await;
            s.anomalies_detected += 1;
            info!(
                "🌐🧪 🛡️  Anomaly detected: {} — score={:.2}, threat={:?}, severity={:?}",
                report.node_id, report.score, report.threat_type, report.severity
            );
        } else {
            info!(
                "🌐🧪 ✅ {} passed anomaly check (score={:.2})",
                report.node_id, report.score
            );
        }
    }
}

async fn feed_prefetcher(
    prefetcher: &Arc<RwLock<PredictivePrefetcher>>,
    node_names: &[&str; 4],
    sim_cycle: u64,
    stats: &Arc<RwLock<NeuralMeshStats>>,
) {
    let mut pf = prefetcher.write().await;
    let shard_names = ["shard-blockchain-001", "shard-identity-002", "shard-model-003", "shard-storage-004"];
    for (idx, _name) in node_names.iter().enumerate() {
        let shard = shard_names[idx];
        pf.record_access(lib_neural_mesh::AccessPattern {
            shard_id: shard.into(),
            timestamp: sim_cycle * 15_000 + (idx as u64) * 1000,
            context: format!("{}-workload", node_names[idx]),
        });
    }
    if let Ok(predictions) = pf.predict_next("sim-node-alpha-workload", 3) {
        for pred in &predictions {
            if pf.should_prefetch(pred) {
                let mut s = stats.write().await;
                s.prefetch_predictions += 1;
                info!(
                    "🌐🧪 📡 Prefetch: {} (confidence={:.2})",
                    pred.shard_id, pred.confidence
                );
            }
        }
    }
}

async fn log_simulation_summary(
    stats: &Arc<RwLock<NeuralMeshStats>>,
    distributed: &Arc<RwLock<DistributedTrainingCoordinator>>,
    sim_cycle: u64,
) {
    let s = stats.read().await;
    let metrics = distributed.read().await.loop_metrics().await;
    info!("🌐🧪 ═══════════════════════════════════════════════════════");
    info!("🌐🧪 MULTI-NODE SIMULATION STATUS (cycle {})", sim_cycle);
    info!("🌐🧪   Routing decisions:   {}", s.routing_decisions);
    info!("🌐🧪   FedAvg rounds:       {}", s.fedavg_rounds);
    info!("🌐🧪   Anomalies detected:  {}", s.anomalies_detected);
    info!("🌐🧪   Prefetch predictions: {}", s.prefetch_predictions);
    info!("🌐🧪   Codec adaptations:   {}", s.codec_adaptations);
    info!("🌐🧪   Distributed syncs:   {}", s.distributed_syncs);
    if metrics.total_model_bytes_raw > 0 {
        info!("🌐🧪   Model compression:   {:.1}x avg", metrics.avg_model_compression_ratio);
        info!("🌐🧪   Bytes saved:         {}", metrics.total_model_bytes_raw - metrics.total_model_bytes_compressed);
    }
    let wire = &crate::compression::WIRE_STATS;
    let wire_ops = wire.total_ops.load(std::sync::atomic::Ordering::Relaxed);
    if wire_ops > 0 {
        info!("🌐🧪   Wire compression:    {} ops, {:.1}x avg, {} bytes saved",
            wire_ops, wire.avg_ratio(), wire.total_bytes_saved());
        info!("🌐🧪   Blocks: {} | Txs: {} | DHT: {} | ZHTP: {}",
            wire.blocks_compressed.load(std::sync::atomic::Ordering::Relaxed),
            wire.txs_compressed.load(std::sync::atomic::Ordering::Relaxed),
            wire.dht_compressed.load(std::sync::atomic::Ordering::Relaxed),
            wire.zhtp_compressed.load(std::sync::atomic::Ordering::Relaxed));
    }
    info!("🌐🧪 ═══════════════════════════════════════════════════════");
}
