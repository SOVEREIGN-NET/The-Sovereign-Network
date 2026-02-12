// ! Ollama HTTP Client
//!
//! Minimal client for interacting with Ollama's REST API.
//! See: https://github.com/ollama/ollama/blob/main/docs/api.md

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

/// Ollama HTTP client.
pub struct OllamaClient {
    base_url: String,
    client: reqwest::Client,
}

/// Request for `/api/generate` endpoint (completion).
#[derive(Debug, Serialize)]
pub struct OllamaGenerateRequest {
    pub model: String,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<OllamaOptions>,
}

/// Request for `/api/chat` endpoint (chat completion).
#[derive(Debug, Serialize)]
pub struct OllamaChatRequest {
    pub model: String,
    pub messages: Vec<OllamaChatMessage>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<OllamaOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaChatMessage {
    pub role: String,    // "system" | "user" | "assistant"
    pub content: String,
}

/// Request for `/api/embeddings` endpoint.
#[derive(Debug, Serialize)]
pub struct OllamaEmbeddingRequest {
    pub model: String,
    pub prompt: String,
}

/// Ollama runtime options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_predict: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_ctx: Option<u32>,
}

/// Response from `/api/generate` (non-streaming).
#[derive(Debug, Deserialize)]
pub struct OllamaGenerateResponse {
    pub model: String,
    pub response: String,
    pub done: bool,
    #[serde(default)]
    pub context: Vec<i32>,
    #[serde(default)]
    pub total_duration: u64,
    #[serde(default)]
    pub load_duration: u64,
    #[serde(default)]
    pub prompt_eval_count: u32,
    #[serde(default)]
    pub prompt_eval_duration: u64,
    #[serde(default)]
    pub eval_count: u32,
    #[serde(default)]
    pub eval_duration: u64,
}

/// Response from `/api/chat` (non-streaming).
#[derive(Debug, Deserialize)]
pub struct OllamaChatResponse {
    pub model: String,
    pub message: OllamaChatMessage,
    pub done: bool,
    #[serde(default)]
    pub total_duration: u64,
    #[serde(default)]
    pub load_duration: u64,
    #[serde(default)]
    pub prompt_eval_count: u32,
    #[serde(default)]
    pub prompt_eval_duration: u64,
    #[serde(default)]
    pub eval_count: u32,
    #[serde(default)]
    pub eval_duration: u64,
}

/// Response from `/api/embeddings`.
#[derive(Debug, Deserialize)]
pub struct OllamaEmbeddingResponse {
    pub embedding: Vec<f32>,
}

/// Response from `/api/tags` (list models).
#[derive(Debug, Deserialize)]
pub struct OllamaListResponse {
    pub models: Vec<OllamaModelInfo>,
}

#[derive(Debug, Deserialize)]
pub struct OllamaModelInfo {
    pub name: String,
    pub modified_at: String,
    pub size: u64,
}

impl OllamaClient {
    /// Create a new Ollama client pointing to the given base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Check if the Ollama server is reachable.
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/api/tags", self.base_url);
        match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => Ok(true),
            Ok(resp) => {
                error!("Ollama health check failed: HTTP {}", resp.status());
                Ok(false)
            }
            Err(e) => {
                error!("Ollama health check error: {}", e);
                Ok(false)
            }
        }
    }

    /// List available models on the Ollama server.
    pub async fn list_models(&self) -> Result<Vec<OllamaModelInfo>> {
        let url = format!("{}/api/tags", self.base_url);
        let resp: OllamaListResponse = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch model list")?
            .json()
            .await
            .context("Failed to parse model list")?;
        Ok(resp.models)
    }

    /// Run a completion (generate) request (non-streaming).
    pub async fn generate(&self, req: OllamaGenerateRequest) -> Result<OllamaGenerateResponse> {
        let url = format!("{}/api/generate", self.base_url);
        debug!("Ollama generate: model={}, prompt_len={}", req.model, req.prompt.len());
        
        let resp = self.client
            .post(&url)
            .json(&req)
            .send()
            .await
            .context("Failed to send generate request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ollama generate failed: HTTP {} - {}", status, body);
        }

        let result: OllamaGenerateResponse = resp.json().await
            .context("Failed to parse generate response")?;
        Ok(result)
    }

    /// Run a chat completion request (non-streaming).
    pub async fn chat(&self, req: OllamaChatRequest) -> Result<OllamaChatResponse> {
        let url = format!("{}/api/chat", self.base_url);
        debug!("Ollama chat: model={}, messages_count={}", req.model, req.messages.len());
        
        let resp = self.client
            .post(&url)
            .json(&req)
            .send()
            .await
            .context("Failed to send chat request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ollama chat failed: HTTP {} - {}", status, body);
        }

        let result: OllamaChatResponse = resp.json().await
            .context("Failed to parse chat response")?;
        Ok(result)
    }

    /// Generate embeddings for a given prompt.
    pub async fn embeddings(&self, req: OllamaEmbeddingRequest) -> Result<OllamaEmbeddingResponse> {
        let url = format!("{}/api/embeddings", self.base_url);
        debug!("Ollama embeddings: model={}, prompt_len={}", req.model, req.prompt.len());
        
        let resp = self.client
            .post(&url)
            .json(&req)
            .send()
            .await
            .context("Failed to send embeddings request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ollama embeddings failed: HTTP {} - {}", status, body);
        }

        let result: OllamaEmbeddingResponse = resp.json().await
            .context("Failed to parse embeddings response")?;
        Ok(result)
    }
}
