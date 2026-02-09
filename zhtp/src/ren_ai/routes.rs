//! Ren AI API Route Handlers
//!
//! HTTP/ZHTP endpoints for the Ren AI inference service:
//!
//! - `POST /ren/v1/completions`  -- text completion
//! - `POST /ren/v1/chat`         -- multi-turn chat
//! - `POST /ren/v1/embeddings`   -- embedding generation
//! - `POST /ren/v1/summarize`    -- text summarization
//! - `GET  /ren/v1/models`       -- list available models
//! - `GET  /ren/v1/health`       -- engine health check
//! - `GET  /ren/v1/metrics`      -- Prometheus metrics

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use super::engine::RenInferenceEngine;
use super::metrics::RenAiMetrics;
use super::types::*;

// ---------------------------------------------------------------------------
// Route table (framework-agnostic scaffold)
// ---------------------------------------------------------------------------

/// Register all Ren AI routes. Returns a list of (method, path, description)
/// tuples for documentation / framework wiring.
pub fn ren_ai_routes() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("POST", "/ren/v1/completions", "Run text completion"),
        ("POST", "/ren/v1/chat",        "Multi-turn chat inference"),
        ("POST", "/ren/v1/embeddings",  "Generate embeddings"),
        ("POST", "/ren/v1/summarize",   "Summarize text"),
        ("GET",  "/ren/v1/models",      "List available models"),
        ("GET",  "/ren/v1/health",      "Engine health check"),
        ("GET",  "/ren/v1/metrics",     "Prometheus metrics"),
    ]
}

// ---------------------------------------------------------------------------
// Handler functions (to be wired into the HTTP framework)
// ---------------------------------------------------------------------------

/// Handle `POST /ren/v1/completions`
pub async fn handle_completion(
    engine: Arc<RenInferenceEngine>,
    request: InferenceRequest,
) -> Result<InferenceResponse, InferenceError> {
    // Validate task type
    match &request.task {
        InferenceTaskRequest::Completion { .. } => {}
        _ => {
            return Err(InferenceError {
                code: InferenceErrorCode::EngineError,
                message: "Expected completion task type".into(),
                request_id: Some(request.request_id.clone()),
            });
        }
    }

    engine.infer(&request).await.map_err(|e| InferenceError {
        code: InferenceErrorCode::EngineError,
        message: e.to_string(),
        request_id: Some(request.request_id.clone()),
    })
}

/// Handle `POST /ren/v1/chat`
pub async fn handle_chat(
    engine: Arc<RenInferenceEngine>,
    request: InferenceRequest,
) -> Result<InferenceResponse, InferenceError> {
    match &request.task {
        InferenceTaskRequest::Chat { .. } => {}
        _ => {
            return Err(InferenceError {
                code: InferenceErrorCode::EngineError,
                message: "Expected chat task type".into(),
                request_id: Some(request.request_id.clone()),
            });
        }
    }

    engine.infer(&request).await.map_err(|e| InferenceError {
        code: InferenceErrorCode::EngineError,
        message: e.to_string(),
        request_id: Some(request.request_id.clone()),
    })
}

/// Handle `POST /ren/v1/embeddings`
pub async fn handle_embeddings(
    engine: Arc<RenInferenceEngine>,
    request: InferenceRequest,
) -> Result<InferenceResponse, InferenceError> {
    match &request.task {
        InferenceTaskRequest::Embedding { .. } => {}
        _ => {
            return Err(InferenceError {
                code: InferenceErrorCode::EngineError,
                message: "Expected embedding task type".into(),
                request_id: Some(request.request_id.clone()),
            });
        }
    }

    engine.infer(&request).await.map_err(|e| InferenceError {
        code: InferenceErrorCode::EngineError,
        message: e.to_string(),
        request_id: Some(request.request_id.clone()),
    })
}

/// Handle `POST /ren/v1/summarize`
pub async fn handle_summarize(
    engine: Arc<RenInferenceEngine>,
    request: InferenceRequest,
) -> Result<InferenceResponse, InferenceError> {
    match &request.task {
        InferenceTaskRequest::Summarization { .. } => {}
        _ => {
            return Err(InferenceError {
                code: InferenceErrorCode::EngineError,
                message: "Expected summarization task type".into(),
                request_id: Some(request.request_id.clone()),
            });
        }
    }

    engine.infer(&request).await.map_err(|e| InferenceError {
        code: InferenceErrorCode::EngineError,
        message: e.to_string(),
        request_id: Some(request.request_id.clone()),
    })
}

/// Handle `GET /ren/v1/models`
pub async fn handle_list_models(
    engine: Arc<RenInferenceEngine>,
) -> ModelListResponse {
    let health = engine.health().await;
    ModelListResponse {
        models: vec![ModelInfo {
            model_id: health.model_id,
            state: health.state,
            supported_tasks: vec![
                "completion".into(),
                "chat".into(),
                "embedding".into(),
                "summarization".into(),
            ],
            context_window: 8192, // From config
            max_batch_size: health.max_batch_size,
        }],
    }
}

/// Handle `GET /ren/v1/health`
pub async fn handle_health(
    engine: Arc<RenInferenceEngine>,
) -> super::engine::EngineHealthStatus {
    engine.health().await
}

/// Handle `GET /ren/v1/metrics`
pub async fn handle_metrics(
    metrics: Arc<RenAiMetrics>,
) -> String {
    metrics.to_prometheus()
}

// ---------------------------------------------------------------------------
// Auxiliary response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelListResponse {
    pub models: Vec<ModelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub model_id: String,
    pub state: String,
    pub supported_tasks: Vec<String>,
    pub context_window: u32,
    pub max_batch_size: u32,
}
