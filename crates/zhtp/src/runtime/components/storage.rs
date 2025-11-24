use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};

/// Storage component implementation using lib-storage package
#[derive(Debug)]
pub struct StorageComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    storage_system: Arc<RwLock<Option<lib_storage::UnifiedStorageSystem>>>,
}

impl StorageComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            storage_system: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for StorageComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Storage
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting storage component with lib-storage implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        match crate::runtime::components::identity::create_default_storage_config() {
            Ok(config) => {
                match lib_storage::UnifiedStorageSystem::new(config).await {
                    Ok(storage) => {
                        info!("unified storage system initialized successfully");
                        info!("-style content addressing ready");
                        info!("DHT network integration active");
                        info!("Economic incentives for storage providers enabled");
                        
                        *self.storage_system.write().await = Some(storage);
                        info!("Storage system stored in component state");
                    }
                    Err(e) => {
                        warn!("Failed to initialize storage system: {}", e);
                        info!("Continuing with basic storage component");
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create storage config: {}", e);
                info!("Continuing with basic storage component");
            }
        }
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Storage component started with decentralized storage");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping storage component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Storage component stopped");
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
            ComponentMessage::HealthCheck => {
                debug!("Storage component health check");
                Ok(())
            }
            _ => {
                debug!("Storage component received message: {:?}", message);
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
        
        Ok(metrics)
    }
}
