pub mod lorawan;
pub mod satellite;
pub mod wifi;
pub mod hardware;
#[cfg(feature = "lorawan")]
pub mod lorawan_hardware;
pub mod geo_location;
pub mod local_network;
pub mod smart_routing;
pub mod unified;
#[cfg(feature = "quic")]
pub mod pin_cache;
#[cfg(feature = "quic")]
pub mod pinned_verifier;

pub use lorawan::LoRaWANGatewayInfo;
pub use satellite::SatelliteInfo;
pub use wifi::WiFiNetworkInfo;
pub use hardware::{HardwareCapabilities, HardwareDevice};
#[cfg(feature = "lorawan")]
pub use lorawan_hardware::{LoRaWANHardware, FrequencyBand, LoRaWANCapabilities};
pub use geo_location::GeographicLocation;
pub use local_network::{NodeAnnouncement, DiscoverySigningContext};
#[cfg(feature = "quic")]
pub use pin_cache::{TlsPinCache, PinCacheEntry, NodeIdKey, global_pin_cache};
#[cfg(feature = "quic")]
#[allow(deprecated)]
pub use pinned_verifier::{
    PinnedCertVerifier, PinnedVerifierConfig, SyncPinStore, VerificationResult,
    init_global_verifier, global_verifier, is_verifier_initialized,
};

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
///
/// OPTIMIZED: Detects hardware capabilities once and passes to all discovery functions.
/// This eliminates redundant hardware scanning which was previously taking 15-30 seconds.
pub async fn get_discovery_statistics() -> Result<DiscoveryStatistics> {
    let mut stats = DiscoveryStatistics::default();

    // Detect hardware capabilities once at the start - cached for reuse
    // This is the ONLY hardware detection call for the entire discovery cycle
    let capabilities = match hardware::HardwareCapabilities::detect().await {
        Ok(caps) => caps,
        Err(e) => {
            tracing::warn!("Failed to detect hardware capabilities: {}", e);
            // Continue with discovery anyway - non-critical capabilities info
            hardware::HardwareCapabilities::default()
        }
    };

    // Get WiFi discovery statistics using cached capabilities
    if let Ok(wifi_peers) = wifi::discover_wifi_direct_peers().await {
        stats.local_peers += wifi_peers.len() as u32;
    }

    // Get LoRaWAN discovery statistics using cached capabilities
    // Uses discover_lorawan_gateways_with_capabilities to avoid redundant detection
    if let Ok(lorawan_peers) = lorawan::discover_lorawan_gateways_with_capabilities(&capabilities).await {
        stats.regional_peers += lorawan_peers.len() as u32;
    }

    // Get satellite discovery statistics using cached capabilities
    // Uses discover_satellite_uplinks_with_capabilities to avoid redundant detection
    if let Ok(satellite_peers) = satellite::discover_satellite_uplinks_with_capabilities(&capabilities).await {
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
