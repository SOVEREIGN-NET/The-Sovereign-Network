//! Ren AI Node Configuration
//!
//! Parses and validates the `[ren_ai_config]` section from the node TOML.

use serde::{Deserialize, Serialize};

/// Top-level Ren AI configuration block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenAiConfig {
    /// Whether the Ren AI engine is enabled on this node.
    pub enabled: bool,

    // -- Model identity --
    /// Model identifier advertised on the network (e.g. "ren-v1").
    pub model_id: String,
    /// Local filesystem path to model weights.
    pub model_path: String,
    /// Weight file format: `safetensors`, `gguf`, `onnx`.
    pub model_format: ModelFormat,
    /// Quantization level applied to weights.
    pub quantization: Quantization,

    // -- Inference parameters --
    /// Maximum context window in tokens.
    pub context_window: u32,
    /// Maximum concurrent inference requests.
    pub max_batch_size: u32,
    /// Hard cap on output tokens per request.
    pub max_tokens_per_request: u32,
    /// Default sampling temperature.
    pub temperature_default: f32,
    /// Default nucleus sampling probability.
    pub top_p_default: f32,
    /// Default top-k sampling.
    pub top_k_default: u32,

    // -- GPU / Accelerator --
    /// Whether to use GPU acceleration.
    pub gpu_enabled: bool,
    /// Number of transformer layers offloaded to GPU.
    pub gpu_layers: i32,
    /// Fraction of VRAM the engine may use (0.0 - 1.0).
    pub gpu_memory_fraction: f32,
    /// Number of GPUs for tensor parallelism.
    pub tensor_parallel: u32,

    // -- Safety --
    /// Enable built-in content filter.
    pub content_filter_enabled: bool,
    /// Maximum input prompt length in tokens.
    pub max_prompt_length: u32,
    /// Per-DID rate limit (prompts per minute).
    pub rate_limit_prompts_per_min: u32,
    /// Require prompts to carry a valid DID signature.
    pub require_signed_prompts: bool,
    /// Write an audit log entry for every inference request.
    pub audit_log_enabled: bool,

    // -- On-chain advertisement --
    /// Whether to register this model in the on-chain AI service registry.
    pub advertise_on_chain: bool,
    /// Task types this model supports.
    pub supported_tasks: Vec<InferenceTask>,
    /// Price in SOV per 1 000 input tokens.
    pub pricing_sov_per_1k_input_tokens: u64,
    /// Price in SOV per 1 000 output tokens.
    pub pricing_sov_per_1k_output_tokens: u64,
}

impl Default for RenAiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_id: "ren-v1".into(),
            model_path: "./models/ren-v1".into(),
            model_format: ModelFormat::Safetensors,
            quantization: Quantization::Q4KM,
            context_window: 8192,
            max_batch_size: 8,
            max_tokens_per_request: 4096,
            temperature_default: 0.7,
            top_p_default: 0.9,
            top_k_default: 40,
            gpu_enabled: true,
            gpu_layers: 99,
            gpu_memory_fraction: 0.90,
            tensor_parallel: 1,
            content_filter_enabled: true,
            max_prompt_length: 32768,
            rate_limit_prompts_per_min: 60,
            require_signed_prompts: true,
            audit_log_enabled: true,
            advertise_on_chain: true,
            supported_tasks: vec![
                InferenceTask::Completion,
                InferenceTask::Chat,
                InferenceTask::Embedding,
                InferenceTask::Summarization,
            ],
            pricing_sov_per_1k_input_tokens: 1,
            pricing_sov_per_1k_output_tokens: 3,
        }
    }
}

impl RenAiConfig {
    /// Validate the configuration at startup.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.model_id.is_empty() {
            errors.push("model_id must not be empty".into());
        }
        if self.model_path.is_empty() {
            errors.push("model_path must not be empty".into());
        }
        if self.context_window == 0 {
            errors.push("context_window must be > 0".into());
        }
        if self.max_batch_size == 0 {
            errors.push("max_batch_size must be > 0".into());
        }
        if self.max_tokens_per_request == 0 {
            errors.push("max_tokens_per_request must be > 0".into());
        }
        if self.gpu_memory_fraction <= 0.0 || self.gpu_memory_fraction > 1.0 {
            errors.push("gpu_memory_fraction must be in (0.0, 1.0]".into());
        }
        if self.pricing_sov_per_1k_output_tokens == 0 {
            errors.push("pricing_sov_per_1k_output_tokens must be > 0".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ---- Supporting enums ----

/// Model weight format on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFormat {
    Safetensors,
    Gguf,
    Onnx,
}

/// Quantization level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Quantization {
    #[serde(rename = "Q4_K_M")]
    Q4KM,
    #[serde(rename = "Q8_0")]
    Q80,
    #[serde(rename = "F16")]
    F16,
    #[serde(rename = "F32")]
    F32,
}

/// Inference task types the model can serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InferenceTask {
    Completion,
    Chat,
    Embedding,
    Summarization,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = RenAiConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn empty_model_id_rejected() {
        let mut cfg = RenAiConfig::default();
        cfg.model_id = String::new();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("model_id")));
    }
}
