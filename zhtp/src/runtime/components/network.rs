use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use lib_network::ZhtpMeshServer;

/// Statistics for routing reward processing
#[derive(Debug, Clone, Default)]
pub struct RoutingRewardStats {
    pub theoretical_tokens_earned: u64,
    pub bytes_routed: u64,
    pub messages_routed: u64,
}

/// Storage reward statistics for reward calculation
#[derive(Debug, Clone, Default)]
pub struct StorageRewardStats {
    pub theoretical_tokens_earned: u64,
    pub items_stored: u64,
    pub bytes_stored: u64,
    pub retrievals_served: u64,
    pub storage_duration_hours: u64,
}

/// Network component implementation using lib-network package
#[derive(Clone)]
pub struct NetworkComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    mesh_server: Arc<RwLock<Option<ZhtpMeshServer>>>,
}

impl std::fmt::Debug for NetworkComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkComponent")
            .field("status", &"<RwLock<ComponentStatus>>")
            .field("start_time", &"<RwLock<Option<Instant>>>")
            .field("mesh_server", &"<RwLock<Option<ZhtpMeshServer>>>")
            .finish()
    }
}

impl NetworkComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            mesh_server: Arc::new(RwLock::new(None)),
        }
    }
    
    pub async fn get_routing_stats(&self) -> RoutingRewardStats {
        if let Some(ref server) = *self.mesh_server.read().await {
            RoutingRewardStats {
                theoretical_tokens_earned: server.get_theoretical_tokens_earned().await,
                bytes_routed: server.get_total_bytes_routed().await,
                messages_routed: server.get_total_messages_routed().await,
            }
        } else {
            debug!("Mesh statistics not yet available (unified_server starting), returning defaults");
            RoutingRewardStats::default()
        }
    }
    
    pub async fn reset_routing_rewards(&self) -> Result<()> {
        if let Some(ref server) = *self.mesh_server.read().await {
            server.reset_reward_counter().await;
            info!(" Routing rewards reset after successful claim");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Cannot reset rewards: mesh server not initialized"))
        }
    }
    
    pub async fn get_node_id(&self) -> Option<[u8; 32]> {
        if let Some(ref server) = *self.mesh_server.read().await {
            Some(server.get_node_id())
        } else {
            debug!("Node ID not yet available (unified_server starting)");
            None
        }
    }
    
    pub fn get_mesh_server_arc(&self) -> Arc<RwLock<Option<ZhtpMeshServer>>> {
        self.mesh_server.clone()
    }
    
    pub async fn get_storage_stats(&self) -> StorageRewardStats {
        if let Some(ref server) = *self.mesh_server.read().await {
            let stats = server.get_storage_stats_snapshot().await;
            StorageRewardStats {
                theoretical_tokens_earned: stats.theoretical_tokens_earned,
                items_stored: stats.items_stored,
                bytes_stored: stats.bytes_stored,
                retrievals_served: stats.retrievals_served,
                storage_duration_hours: stats.storage_duration_hours,
            }
        } else {
            debug!("Mesh statistics not yet available (unified_server starting), returning defaults");
            StorageRewardStats::default()
        }
    }
    
    pub async fn reset_storage_rewards(&self) -> Result<()> {
        if let Some(ref server) = *self.mesh_server.read().await {
            server.reset_storage_reward_counter().await;
            info!(" Storage rewards reset after successful claim");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Cannot reset storage rewards: mesh server not initialized"))
        }
    }
}

#[async_trait::async_trait]
impl Component for NetworkComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Network
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting network component with lib-network mesh protocol...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        info!("Mesh networking handled by unified server - skipping separate mesh server");
        info!("NetworkComponent ready (mesh handled by unified server on port 9333)");
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Network component started with mesh networking ready");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping network component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        {
            let mut mesh_server_guard = self.mesh_server.write().await;
            if let Some(_server) = mesh_server_guard.as_mut() {
                // ZhtpMeshServer will be dropped when set to None below
                // Internal cleanup happens in Drop implementation
                info!("Mesh server will be cleaned up on drop");
            }
        }
        
        *self.mesh_server.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Network component stopped");
        Ok(())
    }

    async fn force_stop(&self) -> Result<()> {
        warn!(" Force stopping network component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        if let Some(_server) = self.mesh_server.write().await.take() {
            info!("Mesh server forcefully terminated");
        }
        
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Network component force stopped");
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
            ComponentMessage::Custom(msg, _data) if msg == "discover_peers" => {
                if let Some(ref server) = *self.mesh_server.read().await {
                    info!("Starting peer discovery...");
                    let stats = server.get_network_stats().await;
                    info!("Network stats - Active connections: {}, Coverage: {:.2} km²", 
                          stats.active_connections, stats.coverage_area_km2);
                } else {
                    warn!("Cannot discover peers: mesh server not initialized");
                }
                Ok(())
            }
            ComponentMessage::HealthCheck => {
                debug!("Network component health check");
                Ok(())
            }
            _ => {
                debug!("Network component received message: {:?}", message);
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
        
        if let Some(ref server) = *self.mesh_server.read().await {
            let stats = server.get_network_stats().await;
            metrics.insert("active_connections".to_string(), stats.active_connections as f64);
            metrics.insert("total_data_routed".to_string(), stats.total_data_routed as f64);
            metrics.insert("long_range_relays".to_string(), stats.long_range_relays as f64);
            metrics.insert("average_latency_ms".to_string(), stats.average_latency_ms as f64);
            metrics.insert("coverage_area_km2".to_string(), stats.coverage_area_km2);
            metrics.insert("people_with_free_internet".to_string(), stats.people_with_free_internet as f64);
        } else {
            metrics.insert("active_connections".to_string(), 0.0);
            metrics.insert("total_data_routed".to_string(), 0.0);
            metrics.insert("long_range_relays".to_string(), 0.0);
            metrics.insert("average_latency_ms".to_string(), 0.0);
            metrics.insert("coverage_area_km2".to_string(), 0.0);
            metrics.insert("people_with_free_internet".to_string(), 0.0);
        }
        
        Ok(metrics)
    }
}
