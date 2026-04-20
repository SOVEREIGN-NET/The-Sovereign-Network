//! # lib-neural-mesh: ML/AI Optimization Layer
//!
//! Cognitive intelligence for the Sovereign Network that learns and adapts:
//!
//! ## Components
//!
//! - **RL-Router**: Reinforcement learning for intelligent routing decisions
//! - **Neuro-Compressor**: Neural network semantic deduplication
//! - **Predictive Prefetcher**: LSTM-based negative latency system
//! - **Anomaly Sentry**: Byzantine fault detection using ML
//! - **Semantic Channeler**: Parallel flow-state inference over ZKP-tagged data
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │  Network State  │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐      ┌──────────────────┐
//! │   RL-Router     │◄────►│  RewardSystem    │
//! └────────┬────────┘      └──────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐      ┌──────────────────┐
//! │  Neuro-Compress │◄────►│  lib-compression │
//! └────────┬────────┘      └──────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐      ┌──────────────────┐
//! │ Anomaly Sentry  │◄────►│  lib-consensus   │
//! └─────────────────┘      └──────────────────┘
//! ```
//!
//! ## Status: Phase 2 Implementation
//!
//! Core infrastructure is being built. Full ML capabilities will be added
//! progressively as dependencies are integrated.

pub mod router;
pub mod compressor;
pub mod prefetch;
pub mod anomaly;
pub mod inference;
pub mod error;
pub mod ml; // ML implementations
pub mod content; // Content analysis and compression feedback
pub mod codec_learner; // Adaptive codec parameter learning (content-adaptive SFC9)
pub mod distributed; // Distributed training + self-compressing neural mesh
pub mod parallel_shard_stream; // Multi-channel QUIC parallel shard compression + streaming
pub mod semantic_channeling; // Parallel flow-state semantic inference (the "channeling" layer)

// Re-export all public types
pub use router::{RlRouter, NetworkState, RoutingAction};
pub use compressor::{NeuroCompressor, ContentEmbedder, Embedding};
pub use prefetch::{
    PredictivePrefetcher, AccessPattern, PredictionResult,
    SemanticPrefetcher, TagAccessEvent, TagChainPrediction,
};
pub use anomaly::{AnomalySentry, NodeMetrics, AnomalyReport, AnomalySeverity, ThreatType};
pub use inference::InferenceEngine;
pub use error::{NeuralMeshError, Result};
pub use content::{ContentType, ContentProfile, CompressionFeedback, TagGenerationConfig};
pub use codec_learner::{AdaptiveCodecLearner, CodecLearnerConfig, LearnedCodecParams};
pub use distributed::{
    DistributedTrainingCoordinator, CompressedModel, ModelId,
    FedAvgResult, ModelSyncMessage, SelfOptimizingMetrics,
    DifferentialPrivacyConfig, ModelCompressor, ModelEncryptor,
    Blake3StreamEncryptor, IdentityEncryptor, IdentityCompressor,
};
pub use parallel_shard_stream::{
    parallel_shard_compress, parallel_shard_decompress,
    CompressedShard, ShardedModel, ShardReassembler, ShardStreamMessage,
};
pub use semantic_channeling::{
    parallel_semantic_channel, channel_query,
    SemanticTag, TagId, TagGraph, ContentTagBinding,
    SemanticChannel, ChannelStrategy, ChannelingResult,
    ConvergencePoint, ThoughtStep, ChannelStreamMessage,
    ChannelingMetrics, DEFAULT_CHANNEL_STRATEGIES,
};

/// Neural mesh protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Default inference timeout (milliseconds)
pub const DEFAULT_INFERENCE_TIMEOUT_MS: u64 = 50;

/// Maximum model size (100 MB)
pub const MAX_MODEL_SIZE: usize = 100 * 1024 * 1024;
