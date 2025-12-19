pub mod lorawan;
pub mod satellite;
pub mod wifi;
pub mod hardware;
pub mod lorawan_hardware;
pub mod geo_location;
pub mod local_network;
pub mod smart_routing;
pub mod unified;

pub use lorawan::*;
pub use satellite::*;
pub use wifi::*;
pub use hardware::*;
pub use lorawan_hardware::*;
pub use geo_location::GeographicLocation;
pub use local_network::*;

// Export unified discovery as the primary interface
pub use unified::{
    DiscoveryProtocol, DiscoveryResult, DiscoveryService, UnifiedDiscoveryService,
    // Security exports
    NonceTracker, PeerReputation, ReputationTracker,
    SecurityMetrics, SecurityMetricsSnapshot,
    validate_public_key,
};

use anyhow::Result;

/// Discovery statistics for peer categorization
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStatistics {
    /// Number of local network peers
    pub local_peers: u32,
    /// Number of regional peers
    pub regional_peers: u32,
    /// Number of global peers  
    pub global_peers: u32,
    /// Number of relay peers
    pub relay_peers: u32,
}

/// Get discovery statistics for peer distribution
pub async fn get_discovery_statistics() -> Result<DiscoveryStatistics> {
    let mut stats = DiscoveryStatistics::default();
    
    // Get WiFi discovery statistics
    if let Ok(wifi_peers) = wifi::discover_wifi_direct_peers().await {
        stats.local_peers += wifi_peers.len() as u32;
    }
    
    // Get LoRaWAN discovery statistics
    if let Ok(lorawan_peers) = lorawan::discover_lorawan_nodes().await {
        stats.regional_peers += lorawan_peers.len() as u32;
    }
    
    // Get satellite discovery statistics
    if let Ok(satellite_peers) = satellite::discover_satellite_nodes().await {
        stats.global_peers += satellite_peers.len() as u32;
    }
    
    // Count relay peers (nodes that provide internet connectivity)
    stats.relay_peers = count_relay_peers().await?;
    
    Ok(stats)
}

/// Count peers that act as relays to the internet
async fn count_relay_peers() -> Result<u32> {
    // This would identify which discovered peers are providing internet relay services
    // For now, assume about 20% of total peers are relays
    Ok(2) // Conservative estimate
}
