use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use crate::ren_ai::engine::RenInferenceEngine;
use crate::ren_ai::ollama::OllamaClient;
use crate::ren_ai::config::{RenAiConfig, ModelFormat, Quantization, InferenceTask};
use crate::ren_ai::metrics::RenAiMetrics;

/// Ren AI Service Component
/// 
/// Provides monetized LLM inference services on the Sovereign Network
pub struct RenAIComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    engine: Arc<RwLock<Option<Arc<RenInferenceEngine>>>>,
    ollama_url: String,
}

impl std::fmt::Debug for RenAIComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenAIComponent")
            .field("ollama_url", &self.ollama_url)
            .finish()
    }
}

impl RenAIComponent {
    /// Create a new Ren AI component with Ollama backend URL
    pub fn new(ollama_url: String) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            engine: Arc::new(RwLock::new(None)),
            ollama_url,
        }
    }

    /// Get the initialized inference engine (if started)
    pub async fn get_engine(&self) -> Option<Arc<RenInferenceEngine>> {
        self.engine.read().await.clone()
    }
}

#[async_trait::async_trait]
impl Component for RenAIComponent {
    fn id(&self) -> ComponentId {
        ComponentId::RenAI
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting Ren AI Service Component...");
        info!("  Ollama URL: {}", self.ollama_url);
        
        *self.status.write().await = ComponentStatus::Starting;

        // Initialize Ollama client
        let ollama_client = OllamaClient::new(&self.ollama_url);
        
        // Test Ollama connectivity
        match ollama_client.health_check().await {
            Ok(healthy) => {
                if healthy {
                    info!("✅ Ollama backend connected at {}", self.ollama_url);
                } else {
                    warn!("⚠️  Ollama health check returned false");
                }
            }
            Err(e) => {
                warn!("⚠️  Ollama health check failed: {}", e);
                warn!("  Inference requests will fail until Ollama is available");
                warn!("  Continuing startup - Ollama may start later");
            }
        }

        // List available models
        match ollama_client.list_models().await {
            Ok(models) => {
                let model_names: Vec<String> = models.iter().map(|m| m.name.clone()).collect();
                info!("📚 Available models: {}", model_names.join(", "));
            }
            Err(e) => {
                warn!("⚠️  Could not list models: {}", e);
            }
        }

        // Create configuration with default values
        let config = RenAiConfig {
            enabled: true,
            model_id: "ren-v1".to_string(),
            model_path: "./models/ren-v1".to_string(),
            model_format: ModelFormat::Gguf,
            quantization: Quantization::Q4KM,
            ollama_url: self.ollama_url.clone(),
            context_window: 8192,
            max_batch_size: 8,
            max_tokens_per_request: 4096,
            temperature_default: 0.7,
            top_p_default: 0.9,
            top_k_default: 40,
            gpu_enabled: true,
            gpu_layers: 99,
            gpu_memory_fraction: 0.9,
            tensor_parallel: 1,
            content_filter_enabled: true,
            max_prompt_length: 32768,
            rate_limit_prompts_per_min: 60,
            require_signed_prompts: false,
            audit_log_enabled: true,
            advertise_on_chain: false,
            supported_tasks: vec![
                InferenceTask::Completion,
                InferenceTask::Chat,
                InferenceTask::Embedding,
                InferenceTask::Summarization,
            ],
            pricing_sov_per_1k_input_tokens: 1,
            pricing_sov_per_1k_output_tokens: 3,
        };

        // Create metrics
        let metrics = Arc::new(RenAiMetrics::new());

        // Create inference engine
        let engine = Arc::new(RenInferenceEngine::new(config, metrics));
        
        // Try to load the model (non-fatal if it fails)
        match engine.load_model().await {
            Ok(_) => {
                info!("✅ Ren AI model loaded successfully");
            }
            Err(e) => {
                warn!("⚠️  Could not load model: {}", e);
                warn!("  Engine will retry when first inference request arrives");
            }
        }
        
        *self.engine.write().await = Some(engine.clone());

        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("✅ Ren AI Service Component started");
        info!("  Inference endpoints ready:");
        info!("    - /ren/v1/completions (text completion)");
        info!("    - /ren/v1/chat (conversational AI)");
        info!("    - /ren/v1/embeddings (vector embeddings)");
        info!("    - /ren/v1/summarize (text summarization)");
        
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping Ren AI Service Component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Drop engine reference (model will be unloaded when Arc drops)
        *self.engine.write().await = None;
        
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        
        info!("Ren AI Service Component stopped");
        Ok(())
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        
        // Basic metrics
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        
        // Engine availability
        let engine_available = self.engine.read().await.is_some();
        metrics.insert("engine_available".to_string(), if engine_available { 1.0 } else { 0.0 });
        
        Ok(metrics)
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);

        // Check if engine is still available
        let engine_available = self.engine.read().await.is_some();
        
        let final_status = if matches!(status, ComponentStatus::Running) && !engine_available {
            ComponentStatus::Error("Inference engine unavailable".to_string())
        } else {
            status
        };

        Ok(ComponentHealth {
            status: final_status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::Start => self.start().await,
            ComponentMessage::Stop => self.stop().await,
            ComponentMessage::Restart => {
                self.stop().await?;
                self.start().await
            }
            _ => {
                warn!("Ren AI component received unhandled message: {:?}", message);
                Ok(())
            }
        }
    }
}
