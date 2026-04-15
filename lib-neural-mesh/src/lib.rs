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

// Re-export all public types
pub use router::{RlRouter, NetworkState, RoutingAction};
pub use compressor::{NeuroCompressor, ContentEmbedder, Embedding};
pub use prefetch::{PredictivePrefetcher, AccessPattern, PredictionResult};
pub use anomaly::{AnomalySentry, NodeMetrics, AnomalyReport, AnomalySeverity, ThreatType};
pub use inference::InferenceEngine;
pub use error::{NeuralMeshError, Result};

/// Neural mesh protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Default inference timeout (milliseconds)
pub const DEFAULT_INFERENCE_TIMEOUT_MS: u64 = 50;

/// Maximum model size (100 MB)
pub const MAX_MODEL_SIZE: usize = 100 * 1024 * 1024;
