use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, debug};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use lib_crypto::{KeyPair, generate_keypair, sign_message};

/// Crypto component implementation using lib-crypto package
#[derive(Debug)]
pub struct CryptoComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    keypair: Arc<RwLock<Option<KeyPair>>>,
    last_signature: Arc<RwLock<Option<Vec<u8>>>>,
}

impl CryptoComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            keypair: Arc::new(RwLock::new(None)),
            last_signature: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for CryptoComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Crypto
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting crypto component with lib-crypto implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Generate cryptographic keypair
        let keypair = generate_keypair()?;
        info!("Generated post-quantum keypair");
        
        *self.keypair.write().await = Some(keypair);
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Crypto component started with post-quantum cryptography");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping crypto component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.keypair.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Crypto component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
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
            ComponentMessage::Custom(msg, data) if msg == "sign_data" => {
                if let Some(ref keypair) = *self.keypair.read().await {
                    let signature = sign_message(keypair, &data)?;
                    *self.last_signature.write().await = Some(signature.signature.clone());
                    info!("Signed data with post-quantum signature, length: {} bytes", signature.signature.len());
                }
                Ok(())
            }
            ComponentMessage::HealthCheck => {
                debug!("Crypto component health check");
                Ok(())
            }
            _ => {
                debug!("Crypto component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        metrics.insert("has_keypair".to_string(), if self.keypair.read().await.is_some() { 1.0 } else { 0.0 });
        
        Ok(metrics)
    }
}
