//! WiFi Direct Protocol Orchestrator
//!
//! Coordinates all WiFi Direct managers and provides the unified Protocol interface.
//! This is a thin orchestrator pattern that delegates to specialized managers.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use crate::protocols::wifi_direct::discovery::DiscoveryManager;
use crate::protocols::wifi_direct::group::GroupManager;
use crate::protocols::wifi_direct::wps::WpsManager;
use crate::protocols::wifi_direct::invitation::InvitationManager;
use crate::protocols::wifi_direct::mesh::MeshManager;
use crate::protocols::wifi_direct::connection::ConnectionManager;

/// WiFi Direct Protocol Orchestrator
///
/// Coordinates all WiFi Direct managers and delegates operations to them.
/// This pattern keeps the main WiFiDirectMeshProtocol focused on state and public API,
/// while complex operations are delegated to specialized managers.
pub struct WiFiDirectOrchestrator {
    /// Node ID
    pub node_id: [u8; 32],

    /// Manager instances
    pub discovery: Arc<DiscoveryManager>,
    pub group: Arc<GroupManager>,
    pub wps: Arc<WpsManager>,
    pub invitation: Arc<InvitationManager>,
    pub mesh: Arc<MeshManager>,
    pub connection: Arc<ConnectionManager>,
}

impl WiFiDirectOrchestrator {
    /// Create a new orchestrator with all managers
    pub async fn new(node_id: [u8; 32]) -> Result<Self> {
        debug!("Initializing WiFi Direct Protocol Orchestrator");

        // Create shared state
        let connected_devices = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let discovered_peers = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let advertised_services = Arc::new(RwLock::new(Vec::new()));
        let sent_invitations = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let received_invitations = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let persistent_groups = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Create discovery manager
        let discovery = Arc::new(DiscoveryManager::new(
            connected_devices.clone(),
            discovered_peers.clone(),
            advertised_services.clone(),
            node_id,
        )?);

        // Create group manager
        let group = Arc::new(GroupManager::new(node_id, persistent_groups.clone())?);

        // Create WPS manager
        let wps = Arc::new(WpsManager::new()?);

        // Create invitation manager
        let invitation = Arc::new(InvitationManager::new(
            sent_invitations,
            received_invitations,
            persistent_groups,
        )?);

        // Create mesh manager
        let mesh = Arc::new(MeshManager::new(connected_devices.clone(), false)?);

        // Create connection manager
        let connection = Arc::new(ConnectionManager::new(connected_devices)?);

        Ok(Self {
            node_id,
            discovery,
            group,
            wps,
            invitation,
            mesh,
            connection,
        })
    }

    /// Start all discovery mechanisms
    pub async fn start_discovery(&self) -> Result<()> {
        debug!("Starting WiFi Direct discovery mechanisms");

        // Start both P2P discovery and mDNS discovery in parallel
        tokio::try_join!(
            self.discovery.start_p2p_discovery(),
            self.discovery.start_mdns_discovery(),
            self.connection.start_monitoring()
        )?;

        Ok(())
    }

    /// Stop all operations
    pub async fn stop(&self) -> Result<()> {
        debug!("Stopping WiFi Direct orchestrator");

        self.discovery.stop().await?;
        self.connection.cleanup_inactive_peers().await?;

        Ok(())
    }

    /// Get discovered services
    pub async fn get_discovered_services(&self) -> Vec<(String, std::collections::HashMap<String, String>)> {
        self.discovery.get_discovered_services().await
    }

    /// Get discovered peer addresses
    pub async fn get_discovered_peer_addresses(&self) -> Vec<String> {
        self.discovery.get_discovered_peer_addresses().await
    }

    /// Get mesh status
    pub async fn get_mesh_status(&self, group_owner: bool, discovery_active: bool) -> crate::protocols::wifi_direct::wifi_direct::WiFiDirectMeshStatus {
        self.connection.get_mesh_status(group_owner, discovery_active).await
    }

    /// Get connected devices
    pub async fn get_connected_devices(&self) -> Vec<crate::protocols::wifi_direct::wifi_direct::WiFiDirectConnection> {
        self.connection.get_connected_devices().await
    }
}
