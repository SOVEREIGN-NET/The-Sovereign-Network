//! WiFi Direct Discovery Manager
//!
//! Handles:
//! - P2P device scanning (platform-specific)
//! - mDNS service discovery and registration
//! - Service browsing and publication
//! - Discovered peer and service queries

pub mod scanner;
pub mod mdns;

pub use scanner::DiscoveryScanner;
pub use mdns::MdnsDiscovery;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::protocols::wifi_direct::wifi_direct::{
    WiFiDirectConnection, P2PGoNegotiation, WiFiDirectService,
};

/// Discovery manager coordinating P2P and mDNS discovery
pub struct DiscoveryManager {
    scanner: Arc<DiscoveryScanner>,
    mdns: Arc<MdnsDiscovery>,
    connected_devices: Arc<RwLock<HashMap<String, WiFiDirectConnection>>>,
    discovered_peers: Arc<RwLock<HashMap<String, P2PGoNegotiation>>>,
    advertised_services: Arc<RwLock<Vec<WiFiDirectService>>>,
}

impl DiscoveryManager {
    /// Create a new discovery manager
    pub fn new(
        connected_devices: Arc<RwLock<HashMap<String, WiFiDirectConnection>>>,
        discovered_peers: Arc<RwLock<HashMap<String, P2PGoNegotiation>>>,
        advertised_services: Arc<RwLock<Vec<WiFiDirectService>>>,
        node_id: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            scanner: Arc::new(DiscoveryScanner::new()?),
            mdns: Arc::new(MdnsDiscovery::new(node_id)?),
            connected_devices,
            discovered_peers,
            advertised_services,
        })
    }

    /// Start P2P device discovery
    pub async fn start_p2p_discovery(&self) -> Result<()> {
        self.scanner.start_discovery(self.connected_devices.clone()).await
    }

    /// Start mDNS service discovery
    pub async fn start_mdns_discovery(&self) -> Result<()> {
        self.mdns.start_discovery().await
    }

    /// Register ZHTP service with mDNS
    pub async fn register_service(&self) -> Result<()> {
        self.mdns.register_service(self.advertised_services.clone()).await
    }

    /// Get list of discovered services
    pub async fn get_discovered_services(&self) -> Vec<(String, HashMap<String, String>)> {
        let peers = self.discovered_peers.read().await;
        let devices = self.connected_devices.read().await;

        let mut services = Vec::new();

        // Add services from P2P peers
        for (node_id, negotiation) in peers.iter() {
            let mut service_info = HashMap::new();
            service_info.insert("node_id".to_string(), node_id.clone());
            service_info.insert(
                "group_owner".to_string(),
                negotiation.group_capability.p2p_group_owner.to_string(),
            );
            service_info.insert(
                "channel".to_string(),
                negotiation.channel_list.first().unwrap_or(&6).to_string(),
            );
            service_info.insert("go_intent".to_string(), negotiation.go_intent.to_string());
            service_info.insert(
                "concurrent_op".to_string(),
                negotiation.device_capability.concurrent_operation.to_string(),
            );

            services.push((format!("ZHTP-{}", &node_id[..8]), service_info));
        }

        // Add services from active connections
        for (mac_addr, connection) in devices.iter() {
            if !peers.contains_key(mac_addr) {
                let mut service_info = HashMap::new();
                service_info.insert("mac_address".to_string(), mac_addr.clone());
                service_info.insert("device_name".to_string(), connection.device_name.clone());
                service_info.insert("signal_strength".to_string(), connection.signal_strength.to_string());
                service_info.insert(
                    "data_rate".to_string(),
                    format!("{} Mbps", connection.data_rate),
                );
                service_info.insert("connection_type".to_string(), "Active".to_string());

                services.push((format!("Active-{}", &connection.device_name), service_info));
            }
        }

        services
    }

    /// Get discovered peer addresses for bootstrap
    pub async fn get_discovered_peer_addresses(&self) -> Vec<String> {
        let peers = self.discovered_peers.read().await;
        peers
            .keys()
            .map(|addr| format!("zhtp://{}", addr))
            .collect()
    }

    /// Update mDNS service registration
    pub async fn update_service(&self) -> Result<()> {
        self.mdns.update_service().await
    }

    /// Stop discovery and cleanup
    pub async fn stop(&self) -> Result<()> {
        self.scanner.stop().await?;
        self.mdns.stop().await?;
        Ok(())
    }
}
