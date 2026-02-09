//! Ren AI Service Node Module
//!
//! This module implements the Ren LLM inference service for the Sovereign Network.
//! A Ren AI node accepts signed prompts from clients, runs inference through
//! the local Ren model, and returns completions. Payment is handled via SOV
//! micro-transactions anchored to on-chain inference receipts.
//!
//! # Architecture
//!
//! ```text
//! Client (DID-signed prompt)
//!     |
//!     v
//! [Rate Limiter] --> reject if over quota
//!     |
//!     v
//! [Prompt Validator] --> verify DID signature, check payment escrow
//!     |
//!     v
//! [Inference Engine] --> run Ren model, stream tokens
//!     |
//!     v
//! [Receipt Generator] --> create signed inference receipt
//!     |
//!     v
//! [Reward Tracker] --> log work metrics for epoch rewards
//! ```
//!
//! # Modules
//!
//! - `config`   - Ren AI node configuration parsing and validation
//! - `engine`   - Model loading, inference execution, token streaming
//! - `types`    - Request/response types, inference receipts, errors
//! - `routes`   - HTTP/ZHTP API endpoint handlers
//! - `rewards`  - AI inference reward calculation (SOV per token)
//! - `metrics`  - Prometheus counters and histograms for inference
//! - `guardrails` - Content filtering, prompt safety, abuse prevention

pub mod config;
pub mod engine;
pub mod types;
pub mod routes;
pub mod rewards;
pub mod metrics;
pub mod guardrails;

pub use config::RenAiConfig;
pub use engine::RenInferenceEngine;
pub use types::*;
pub use routes::ren_ai_routes;
pub use rewards::InferenceRewardCalculator;
pub use metrics::RenAiMetrics;
pub use guardrails::ContentGuardrails;
