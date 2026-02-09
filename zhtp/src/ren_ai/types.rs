//! Ren AI Type Definitions
//!
//! Request/response types, inference receipts, and error codes for the
//! Ren AI service node.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Inference Request / Response
// ---------------------------------------------------------------------------

/// A signed inference request from a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Unique request identifier (UUID v7 -- time-sortable).
    pub request_id: String,
    /// DID of the requesting client.
    pub client_did: String,
    /// The task to perform.
    pub task: InferenceTaskRequest,
    /// Sampling parameters (optional overrides).
    #[serde(default)]
    pub sampling: SamplingParams,
    /// Ed25519 or Dilithium signature over the canonical request bytes.
    pub signature: Vec<u8>,
    /// Timestamp (Unix epoch seconds).
    pub timestamp: u64,
    /// Optional: pre-paid escrow transaction hash on-chain.
    pub payment_tx: Option<String>,
}

/// Task-specific payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InferenceTaskRequest {
    /// Text completion.
    Completion {
        prompt: String,
        max_tokens: Option<u32>,
    },
    /// Multi-turn chat.
    Chat {
        messages: Vec<ChatMessage>,
        max_tokens: Option<u32>,
    },
    /// Embedding generation.
    Embedding {
        input: Vec<String>,
    },
    /// Summarization.
    Summarization {
        text: String,
        max_length: Option<u32>,
    },
}

/// A single chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

/// Chat roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

/// Sampling parameter overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingParams {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    pub repetition_penalty: Option<f32>,
    pub stop_sequences: Vec<String>,
}

impl Default for SamplingParams {
    fn default() -> Self {
        Self {
            temperature: None,
            top_p: None,
            top_k: None,
            repetition_penalty: None,
            stop_sequences: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Inference Response
// ---------------------------------------------------------------------------

/// Response returned to the client after inference completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    /// Mirrors the request_id.
    pub request_id: String,
    /// DID of the serving node.
    pub node_did: String,
    /// Model identifier that produced the result.
    pub model_id: String,
    /// The generated output.
    pub output: InferenceOutput,
    /// Usage statistics.
    pub usage: TokenUsage,
    /// Signed inference receipt (proof-of-work for rewards).
    pub receipt: InferenceReceipt,
    /// Unix epoch seconds when inference completed.
    pub completed_at: u64,
}

/// Task-specific output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InferenceOutput {
    Completion {
        text: String,
        finish_reason: FinishReason,
    },
    Chat {
        message: ChatMessage,
        finish_reason: FinishReason,
    },
    Embedding {
        vectors: Vec<Vec<f32>>,
        dimensions: u32,
    },
    Summarization {
        summary: String,
        finish_reason: FinishReason,
    },
}

/// Why the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    MaxTokens,
    ContentFilter,
}

/// Token usage accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    /// Wall-clock inference time in milliseconds.
    pub inference_time_ms: u64,
    /// Tokens per second throughput.
    pub tokens_per_second: f32,
}

// ---------------------------------------------------------------------------
// Inference Receipt  (on-chain proof that work was done)
// ---------------------------------------------------------------------------

/// Cryptographically signed receipt proving inference was performed.
/// Submitted to the reward pipeline so the node earns SOV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceReceipt {
    /// Unique receipt ID (derived from request_id + node_did).
    pub receipt_id: String,
    /// DID of the node that performed inference.
    pub node_did: String,
    /// DID of the client that requested inference.
    pub client_did: String,
    /// Model identifier.
    pub model_id: String,
    /// Number of input tokens processed.
    pub input_tokens: u32,
    /// Number of output tokens generated.
    pub output_tokens: u32,
    /// Task type performed.
    pub task_type: String,
    /// SOV charged for this request.
    pub sov_charged: u64,
    /// Blake3 hash of the prompt (privacy -- not the prompt itself).
    pub prompt_hash: String,
    /// Blake3 hash of the completion.
    pub output_hash: String,
    /// Inference latency in milliseconds.
    pub latency_ms: u64,
    /// Unix epoch seconds.
    pub timestamp: u64,
    /// Ed25519 / Dilithium signature by the node over the receipt fields.
    pub node_signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Model Registry (on-chain advertisement)
// ---------------------------------------------------------------------------

/// Entry in the on-chain AI model registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRegistryEntry {
    /// DID of the node hosting this model.
    pub node_did: String,
    /// Human-readable model name.
    pub model_id: String,
    /// Supported task types.
    pub supported_tasks: Vec<String>,
    /// Pricing: SOV per 1K input tokens.
    pub price_input_1k: u64,
    /// Pricing: SOV per 1K output tokens.
    pub price_output_1k: u64,
    /// Context window size.
    pub context_window: u32,
    /// Quantization level.
    pub quantization: String,
    /// Average tokens/second throughput (self-reported, auditable).
    pub avg_throughput_tps: f32,
    /// Current availability: true if accepting requests.
    pub available: bool,
    /// Reputation score (0-100, from on-chain history).
    pub reputation_score: u32,
    /// Block height at registration.
    pub registered_at_block: u64,
}

// ---------------------------------------------------------------------------
// Streaming token event (for SSE / WebSocket streaming)
// ---------------------------------------------------------------------------

/// A single token event sent during streaming inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStreamEvent {
    pub request_id: String,
    pub index: u32,
    pub token: String,
    pub finish_reason: Option<FinishReason>,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during Ren AI inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceError {
    pub code: InferenceErrorCode,
    pub message: String,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InferenceErrorCode {
    /// Model is not loaded or unavailable.
    ModelUnavailable,
    /// Prompt exceeds maximum length.
    PromptTooLong,
    /// Client has exceeded rate limit.
    RateLimited,
    /// DID signature on the prompt is invalid.
    InvalidSignature,
    /// Payment escrow is missing or insufficient.
    PaymentRequired,
    /// Content filter blocked the prompt or output.
    ContentFiltered,
    /// Internal engine error (OOM, GPU fault, etc.).
    EngineError,
    /// Request timed out.
    Timeout,
    /// Batch queue is full.
    QueueFull,
}

impl std::fmt::Display for InferenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}", self.code, self.message)
    }
}

impl std::error::Error for InferenceError {}
