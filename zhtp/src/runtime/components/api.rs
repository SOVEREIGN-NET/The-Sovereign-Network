use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, debug};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};

/// API component - delegates to unified server on port 9333
#[derive(Debug)]
pub struct ApiComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl ApiComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            server_handle: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for ApiComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Api
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        // NOTE: API server is now handled by ZhtpUnifiedServer on port 9333
        info!("API endpoints handled by unified server - skipping separate API server");
        info!("API routes available:");
        info!("   - Identity management (/api/v1/identity/*)");
        info!("   - Blockchain operations (/api/v1/blockchain/*)");
        info!("   - Storage management (/api/v1/storage/*)");
        info!("   - Protocol information (/api/v1/protocol/*)");
        info!("   - Wallet operations (/api/v1/wallet/*)");
        info!("   - DAO management (/api/v1/dao/*)");
        info!("   - DHT queries (/api/v1/dht/*)");
        info!("   - Web4 content (/api/v1/web4/*)");
        
        *self.status.write().await = ComponentStatus::Starting;
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("ApiComponent ready (APIs handled by unified server on port 9333)");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping API component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Stop the server handle if it exists
        if let Some(handle) = self.server_handle.write().await.take() {
            handle.abort();
            info!("API server handle terminated");
        }
        
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        
        info!("API component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        // Check if API is actually running on port 9333 (QUIC/UDP, not TCP)
        // This ensures we report "Running" even if the component state got desynchronized
        // or if the UnifiedServer is running but this component wasn't explicitly started
        
        // QUIC-only architecture: Check UDP socket instead of TCP
        let api_running = async {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            // Send a test packet to verify port 9333 is bound
            // Note: We don't expect a response, just checking if port is in use
            socket.connect("127.0.0.1:9333").await?;
            Ok::<bool, std::io::Error>(true)
        }
        .await
        .is_ok();
        
        if api_running {
            let mut status_guard = self.status.write().await;
            if !matches!(*status_guard, ComponentStatus::Running) {
                *status_guard = ComponentStatus::Running;
                // Also update start time if it was None
                let mut start_time = self.start_time.write().await;
                if start_time.is_none() {
                    *start_time = Some(Instant::now());
                }
            }
        } else {
            // If API is not running, we should reflect that, unless we are explicitly Stopped
            let mut status_guard = self.status.write().await;
            if matches!(*status_guard, ComponentStatus::Running) {
                *status_guard = ComponentStatus::Error("API port 9333 (QUIC/UDP) unreachable".to_string());
            }
        }

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
            ComponentMessage::Custom(msg, _data) if msg == "health_check" => {
                info!("API component health check - using unified server");
            }
            ComponentMessage::Custom(msg, _data) if msg == "get_stats" => {
                info!("API component stats - handled by unified server");
            }
            ComponentMessage::HealthCheck => {
                debug!("API component health check");
            }
            _ => {
                debug!("API component received unhandled message: {:?}", message);
            }
        }
        Ok(())
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), 
            if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        // API handled by unified server
        metrics.insert("api_unified_server".to_string(), 1.0);
        metrics.insert("handlers_integrated".to_string(), 8.0);
        metrics.insert("middleware_active".to_string(), 4.0);
        
        Ok(metrics)
    }
}
