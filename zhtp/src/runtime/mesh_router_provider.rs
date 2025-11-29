use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use anyhow::Result;
use tracing::{info, warn};

use crate::unified_server::{MeshRouter, BroadcastMetrics};

/// Global mesh router provider for shared access across components
/// This allows API handlers to access mesh router metrics and state
/// without directly coupling to the protocols component or unified server
#[derive(Clone)]
pub struct MeshRouterProvider {
    mesh_router: Arc<RwLock<Option<Arc<MeshRouter>>>>,
}

impl MeshRouterProvider {
    /// Create a new empty mesh router provider
    pub fn new() -> Self {
        Self {
            mesh_router: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the mesh router instance
    pub async fn set_mesh_router(&self, mesh_router: Arc<MeshRouter>) -> Result<()> {
        *self.mesh_router.write().await = Some(mesh_router);
        info!("Global mesh router instance set");
        Ok(())
    }

    /// Get the mesh router instance
    pub async fn get_mesh_router(&self) -> Result<Arc<MeshRouter>> {
        self.mesh_router.read().await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Mesh router not available"))
    }

    /// Check if mesh router is available
    pub async fn is_available(&self) -> bool {
        self.mesh_router.read().await.is_some()
    }
}

/// Global mesh router provider instance
static GLOBAL_MESH_ROUTER_PROVIDER: OnceLock<MeshRouterProvider> = OnceLock::new();

/// Initialize the global mesh router provider
pub fn initialize_global_mesh_router_provider() -> &'static MeshRouterProvider {
    GLOBAL_MESH_ROUTER_PROVIDER.get_or_init(|| {
        info!("Initializing global mesh router provider");
        MeshRouterProvider::new()
    })
}

/// Get the global mesh router provider
pub fn get_global_mesh_router_provider() -> Option<&'static MeshRouterProvider> {
    GLOBAL_MESH_ROUTER_PROVIDER.get()
}

/// Set the global mesh router instance
pub async fn set_global_mesh_router(mesh_router: Arc<MeshRouter>) -> Result<()> {
    let provider = initialize_global_mesh_router_provider();
    provider.set_mesh_router(mesh_router).await
}

/// Get the global mesh router instance
pub async fn get_global_mesh_router() -> Result<Arc<MeshRouter>> {
    let provider = get_global_mesh_router_provider()
        .ok_or_else(|| anyhow::anyhow!("Global mesh router provider not initialized"))?;
    provider.get_mesh_router().await
}

/// Check if global mesh router is available
pub async fn is_global_mesh_router_available() -> bool {
    if let Some(provider) = get_global_mesh_router_provider() {
        provider.is_available().await
    } else {
        false
    }
}

/// Get broadcast metrics from the global mesh router
pub async fn get_broadcast_metrics() -> Result<BroadcastMetrics> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.get_broadcast_metrics().await)
}

/// Get peer reputation from the global mesh router
pub async fn get_peer_reputation(peer_id: &str) -> Result<Option<crate::unified_server::PeerReputation>> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.get_peer_reputation(peer_id).await)
}

/// List all peer reputations from the global mesh router
pub async fn list_peer_reputations() -> Result<Vec<crate::unified_server::PeerReputation>> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.list_peer_reputations().await)
}

// Phase 4: Advanced monitoring & analytics helper functions

/// Get performance metrics from the global mesh router
pub async fn get_performance_metrics() -> Result<crate::unified_server::SyncPerformanceMetrics> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.get_performance_metrics().await)
}

/// Get active alerts from the global mesh router
pub async fn get_active_alerts() -> Result<Vec<crate::unified_server::SyncAlert>> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.get_active_alerts().await)
}

/// Acknowledge an alert by ID
pub async fn acknowledge_alert(alert_id: &str) -> Result<bool> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.acknowledge_alert(alert_id).await)
}

/// Clear acknowledged alerts
pub async fn clear_acknowledged_alerts() -> Result<()> {
    let mesh_router = get_global_mesh_router().await?;
    mesh_router.clear_acknowledged_alerts().await;
    Ok(())
}

/// Get alert thresholds
pub async fn get_alert_thresholds() -> Result<crate::unified_server::AlertThresholds> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.get_alert_thresholds().await)
}

/// Update alert thresholds
pub async fn update_alert_thresholds(thresholds: crate::unified_server::AlertThresholds) -> Result<()> {
    let mesh_router = get_global_mesh_router().await?;
    mesh_router.update_alert_thresholds(thresholds).await;
    Ok(())
}

/// Get metrics history
pub async fn get_metrics_history(last_n: Option<usize>) -> Result<Vec<crate::unified_server::MetricsSnapshot>> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.get_metrics_history(last_n).await)
}

/// Get peer-specific performance metrics
pub async fn get_peer_performance(peer_id: &str) -> Result<Option<crate::unified_server::PeerPerformanceStats>> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.get_peer_performance(peer_id).await)
}

/// List all peers with performance stats
pub async fn list_peer_performance() -> Result<Vec<crate::unified_server::PeerPerformanceStats>> {
    let mesh_router = get_global_mesh_router().await?;
    Ok(mesh_router.list_peer_performance().await)
}
