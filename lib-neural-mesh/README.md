# lib-neural-mesh — Neural Intelligence Layer

On-device AI subsystems that make the Sovereign Network self-optimizing. Every component is pure Rust (no Python, no libtorch), runs inference in < 50 ms, and trains incrementally without centralized coordination.

## Components

| Module | Model | Purpose |
|--------|-------|---------|
| `RlRouter` | PPO (actor-critic) | Routes packets to the lowest-latency, highest-bandwidth path |
| `AnomalySentry` | Isolation Forest | Detects malicious, selfish, or degraded nodes |
| `PredictivePrefetcher` | LSTM | Predicts which shards a node will request next |
| `NeuroCompressor` | Embedding + cosine similarity | Semantic deduplication across the network |
| `AdaptiveCodecLearner` | REINFORCE (actor-critic) | Learns optimal compression parameters per content type |
| `DistributedTrainingCoordinator` | Federated Averaging | Synchronizes model weights across peers with DP |

## RlRouter — Intelligent Packet Routing

PPO reinforcement-learning agent that observes network state and selects the best forwarding path.

```rust
use lib_neural_mesh::{RlRouter, NetworkState};

let mut router = RlRouter::new();
router.enable(5, 3); // 5-D state, 3 candidate nodes

let state = NetworkState {
    latencies: [("node-a", 10.0), ("node-b", 50.0)].into(),
    bandwidth: [("node-a", 100.0), ("node-b", 20.0)].into(),
    congestion: 0.3,
    ..Default::default()
};

let action = router.select_action(&state)?;
// action.nodes = ["node-a"], action.confidence = 0.87

router.provide_reward(1.0, &next_state, false)?;
let loss = router.update_policy()?;
```

**State vector** (5-D): congestion, avg latency, avg bandwidth, avg packet loss, avg energy.

**Key methods**: `select_action`, `provide_reward`, `update_policy`, `save_model` / `load_model`.

## AnomalySentry — Byzantine Node Detection

Isolation Forest that scores each node's behavior against a trained baseline.

```rust
use lib_neural_mesh::{AnomalySentry, NodeMetrics};

let mut sentry = AnomalySentry::new();
sentry.enable(); // 100 trees, subsample 256, max_depth 10

// Train on known-good behavior
sentry.train_baseline(good_metrics)?;

// Score a suspicious node
let report = sentry.detect_anomaly(&suspect_metrics)?;
// report.score = 0.92, report.threat_type = ThreatType::Malicious
```

**Scoring**: 70% ML anomaly score + 30% rule-based heuristics. Threshold default `0.7`.

**Threat types**: `Normal`, `SlowNode`, `DataCorruption`, `Selfish`, `Malicious`.

**Severity levels**: `Low`, `Medium`, `High`, `Critical`.

## PredictivePrefetcher — Shard Pre-fetching

LSTM that learns access patterns and predicts which shards a node will request next.

```rust
use lib_neural_mesh::{PredictivePrefetcher, AccessPattern};

let mut prefetcher = PredictivePrefetcher::new();
prefetcher.enable_default(); // input=3, hidden=64, output=3, seq_len=10

// Record access history
prefetcher.record_access(AccessPattern {
    shard_id: "abc123".into(),
    timestamp: 1000,
    context: "block-sync".into(),
});

// Predict next accesses
let predictions = prefetcher.predict_next("block-sync", 5)?;
for p in &predictions {
    if prefetcher.should_prefetch(p) {
        fetch_shard(&p.shard_id);
    }
}

// Train on accumulated history
let (loss, num_sequences) = prefetcher.train_from_history()?;
```

**Prediction**: LSTM inference when enough history, heuristic fallback otherwise. Confidence threshold default `0.8`.

## NeuroCompressor — Semantic Deduplication

Generates content embeddings and identifies near-duplicate data across the network.

```rust
use lib_neural_mesh::NeuroCompressor;

let compressor = NeuroCompressor::with_dimension(512);
let emb_a = compressor.embed(&data_a)?;
let emb_b = compressor.embed(&data_b)?;

let sim = compressor.similarity(&emb_a, &emb_b); // 0.0–1.0
if compressor.is_similar(&emb_a, &emb_b) {        // threshold 0.998
    // data_b is a near-duplicate — store a reference instead
}
```

**Embedding**: Statistical fallback (byte histogram + bigram features) when no ONNX model loaded. ONNX model support via `load_model()`. SIMD-accelerated cosine similarity for vectors > 128 elements.

Also exported as `ContentEmbedder` (type alias).

## AdaptiveCodecLearner — Neural Compression Tuning

Actor-critic RL agent that learns optimal `CodecParams` for each content type by observing compression results.

```rust
use lib_neural_mesh::{AdaptiveCodecLearner, CodecLearnerConfig};
use lib_neural_mesh::ContentProfile;

let mut learner = AdaptiveCodecLearner::new(CodecLearnerConfig::default());

// Profile the data → 8-D state vector
let profile = ContentProfile::analyze(&data);

// Agent predicts codec parameters (epsilon-greedy exploration)
let params = learner.predict_params(&profile);
// params.rescale_limit, params.freq_step, params.init_freq_zero

// Compress with predicted params, then feed back results
learner.observe_result(&feedback);

// Train when enough experience accumulated
if let Some(loss) = learner.train() {
    println!("REINFORCE loss: {loss:.4}");
}
```

**Architecture**: 8 → 64 → 3 actor (sigmoid), 8 → 64 → 1 critic. Exploration: ε-greedy with Gaussian noise, decaying from 0.3 to 0.05.

**Content types**: `Json`, `Text`, `Markup`, `Compressed`, `Binary`, `Unknown` — each tracked independently with per-type best-known params.

### ContentProfile

8-dimensional state vector that characterizes input data:

| Field | Type | Description |
|-------|------|-------------|
| `content_type` | `ContentType` | Auto-detected from magic bytes / heuristics |
| `entropy` | `f32` | Shannon entropy (0–8 bits) |
| `size` | `usize` | Input byte count |
| `text_ratio` | `f32` | Fraction of printable ASCII |
| `unique_bytes` | `u16` | Distinct byte values (0–256) |
| `avg_delta` | `f32` | Mean absolute byte-to-byte difference |

### CompressionFeedback

| Field | Type | Description |
|-------|------|-------------|
| `ratio` | `f64` | Compression ratio (original / compressed) |
| `throughput_mbps` | `f64` | Speed |
| `integrity_ok` | `bool` | Round-trip verified |
| `shard_count` | `usize` | Total shards |
| `shards_compressed` | `usize` | Shards that actually compressed |

**Reward**: `log2(ratio) + min(throughput/100, 1.0)`, or `-10.0` if integrity fails.

## DistributedTrainingCoordinator — Federated Learning

Coordinates model weight synchronization across peers. Each node trains locally, then broadcasts compressed + encrypted model updates for federated averaging.

```rust
use lib_neural_mesh::{
    DistributedTrainingCoordinator, CompressedModel, ModelId,
    DifferentialPrivacyConfig, Blake3StreamEncryptor,
};
use std::sync::Arc;

let mut coord = DistributedTrainingCoordinator::new("node-1".into());

// Configure security
coord.set_dp_config(DifferentialPrivacyConfig {
    epsilon: 1.0,
    delta: 1e-5,
    max_grad_norm: 1.0,
    enabled: true,
});
coord.set_encryptor(Arc::new(Blake3StreamEncryptor::new(shared_key)));

// Export local model (int8-quantized + compressed)
let compressed = coord.export_compressed_model(ModelId::RlRouter, &weights).await;

// Receive a peer's model
let ready = coord.receive_peer_model(peer_model, 1000).await;
if ready {
    let result = coord.federated_average(ModelId::RlRouter, &local_weights).await?;
    // result.merged_weights — DP-noised weighted average
}
```

### Security

**Differential Privacy** (`DifferentialPrivacyConfig`): (ε,δ)-DP noise injection during federated averaging. Noise σ scales with `max_grad_norm / (n · ε)` using the Gaussian mechanism.

**BLAKE3 Stream Encryption** (`Blake3StreamEncryptor`): Authenticated stream cipher using BLAKE3-XOF as the keystream generator. Wire format: `nonce(16) ‖ ciphertext ‖ mac(32)`. Encrypt-then-MAC with integrity verification before decryption.

**Int8 Quantization** (`CompressedModel`): Model weights quantized to 8-bit integers before compression. Magic header `QNT8`. Typical 4× size reduction before any codec compression.

### ModelSyncMessage

Protocol messages for peer-to-peer model exchange:

| Variant | Purpose |
|---------|---------|
| `BroadcastModel` | Push local model to peers |
| `RequestModel` | Pull a specific model by ID and generation |
| `ModelResponse` | Reply to a request |
| `FedAvgResult` | Broadcast merged weights after averaging |
| `MetricsExchange` | Share optimization metrics |

All variants support `to_bytes` / `from_bytes` and `to_encrypted_bytes` / `from_encrypted_bytes`.

## Parallel Shard Streaming

High-throughput parallel compression/decompression for model weight shards:

```rust
use lib_neural_mesh::{parallel_shard_compress, parallel_shard_decompress};

let compressed_shards = parallel_shard_compress(&large_model_weights);
let restored = parallel_shard_decompress(&compressed_shards)?;
```

Exported types: `CompressedShard`, `ShardedModel`, `ShardReassembler`, `ShardStreamMessage`.

## Constants

| Name | Value | Description |
|------|-------|-------------|
| `PROTOCOL_VERSION` | `1` | Wire protocol version |
| `DEFAULT_INFERENCE_TIMEOUT_MS` | `50` | Max inference latency target |
| `MAX_MODEL_SIZE` | `100 MB` | Largest model accepted for sync |

## Tests

```bash
cargo test -p lib-neural-mesh --lib     # 76 unit tests
cargo test -p lib-neural-mesh --test '*' # Integration tests
```

## See Also

- `lib-compression` — SovereignCodec that the AdaptiveCodecLearner tunes
- `lib-proofs` — ZK proof generation for transaction/identity/storage verification
- [docs/NEURAL-COMPRESSION-ARCHITECTURE.md](../docs/NEURAL-COMPRESSION-ARCHITECTURE.md) — System-level architecture
