//! Network types needed for economic c#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BandwidthStatistics {
    pub bytes_transferred: u64,
    pub peak_bandwidth: f64,
    pub average_bandwidth: f64,
    pub congestion_level: CongestionLevel,
    pub quality_score: f64,
    // Legacy fields for compatibility
    pub upload_utilization: f64,
    pub download_utilization: f64,
    pub efficiency: f64,
}

//! Network types for economics calculations
//! 
//! These types are defined here to avoid circular dependencies with lib-network

use serde::{Deserialize, Serialize};
use anyhow::Result;

/// Mesh network status information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshStatus {
    pub active_nodes: u32,
    pub total_bandwidth: f64,
    pub network_coverage: f64,
    pub connection_quality: f64,
    pub uptime_percentage: f64,
    pub routing_efficiency: f64,
    // Legacy fields for compatibility
    pub connectivity_percentage: f64,
    pub active_peers: u32,
    pub stability: f64,
    pub redundancy: f64,
    pub mesh_connectivity: bool,
    pub coverage: f64,
}

impl Default for MeshStatus {
    fn default() -> Self {
        Self {
            active_nodes: 0,
            total_bandwidth: 0,
            network_coverage: 0.0,
            connection_quality: 0.0,
            uptime_percentage: 0.0,
            routing_efficiency: 0.0,
        }
    }
}

/// Bandwidth usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthStatistics {
    pub bytes_transferred: u64,
    pub peak_bandwidth: u64,
    pub average_bandwidth: u64,
    pub congestion_level: CongestionLevel,
    pub quality_score: f64,
    // Legacy fields for compatibility
    pub upload_utilization: f64,
    pub download_utilization: f64,
    pub efficiency: f64,
}

impl Default for BandwidthStatistics {
    fn default() -> Self {
        Self {
            bytes_transferred: 0,
            peak_bandwidth: 0,
            average_bandwidth: 0,
            congestion_level: CongestionLevel::Low,
            quality_score: 1.0,
            upload_utilization: 0.0,
            download_utilization: 0.0,
            efficiency: 1.0,
        }
    }
}

/// Network congestion levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CongestionLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Peer discovery statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryStatistics {
    pub peers_discovered: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub discovery_time_ms: u64,
    pub network_diameter: u32,
    // Legacy fields for compatibility
    pub total_peers_discovered_per_hour: u32,
    pub average_discovery_success_rate: f64,
    pub regions_with_peers: u32,
    pub geographic_diversity_index: f64,
    pub long_distance_connections: u32,
    pub rural_connectivity_index: f64,
    pub average_response_time_ms: f64,
    pub discovery_variance: f64,
}

impl Default for DiscoveryStatistics {
    fn default() -> Self {
        Self {
            peers_discovered: 0,
            successful_connections: 0,
            failed_connections: 0,
            discovery_time_ms: 0,
            network_diameter: 0,
            total_peers_discovered_per_hour: 0,
            average_discovery_success_rate: 0.0,
            regions_with_peers: 0,
            geographic_diversity_index: 0.0,
            long_distance_connections: 0,
            rural_connectivity_index: 0.0,
            average_response_time_ms: 0.0,
            discovery_variance: 0.0,
        }
    }
}

/// Network statistics for economic calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatistics {
    pub mesh_status: MeshStatus,
    pub bandwidth_stats: BandwidthStatistics,
    pub discovery_stats: DiscoveryStatistics,
    pub timestamp: u64,
}

impl Default for NetworkStatistics {
    fn default() -> Self {
        Self {
            mesh_status: MeshStatus::default(),
            bandwidth_stats: BandwidthStatistics::default(),
            discovery_stats: DiscoveryStatistics::default(),
            timestamp: 0,
        }
    }
}

/// Get mesh status for economic calculations
/// This is a simplified version that doesn't depend on lib-network
pub async fn get_mesh_status() -> Result<MeshStatus> {
    // Return a default status to avoid dependency on lib-network
    // In the implementation, this would be provided by the caller
    Ok(MeshStatus::default())
}

/// Get network statistics for economic calculations
/// This is a simplified version that doesn't depend on lib-network
pub async fn get_network_statistics() -> Result<NetworkStatistics> {
    // Return default statistics to avoid dependency on lib-network
    // In the implementation, this would be provided by the caller
    Ok(NetworkStatistics::default())
}

/// Get bandwidth statistics for economic calculations
pub async fn get_bandwidth_statistics() -> Result<BandwidthStatistics> {
    Ok(BandwidthStatistics::default())
}

/// Get discovery statistics for economic calculations
pub async fn get_discovery_statistics() -> Result<DiscoveryStatistics> {
    Ok(DiscoveryStatistics::default())
}

/// Get active peer count for economic calculations
pub async fn get_active_peer_count() -> Result<u32> {
    Ok(10) // Default peer count
}
