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
        // API is handled by the unified QUIC server (ProtocolsComponent)
        // We trust the component status since there's no reliable way to probe QUIC
        // without a full TLS handshake. The ProtocolsComponent manages the actual server.
        //
        // Previous approach of UDP connect() was flawed because:
        // 1. UDP is connectionless - connect() always succeeds even if nothing is listening
        // 2. QUIC requires TLS handshake which is expensive for health checks
        //
        // The ApiComponent delegates to the unified server, so we report Running
        // if we've been started (status is Running/Starting), otherwise report current status.

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
