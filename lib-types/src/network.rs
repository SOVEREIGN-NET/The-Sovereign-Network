use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum CongestionLevel {
    #[default]
    Low,
    Moderate,
    High,
    Critical,
}

impl From<CongestionLevel> for u8 {
    fn from(level: CongestionLevel) -> u8 {
        match level {
            CongestionLevel::Low => 0,
            CongestionLevel::Moderate => 85,
            CongestionLevel::High => 170,
            CongestionLevel::Critical => 255,
        }
    }
}

impl From<u8> for CongestionLevel {
    fn from(value: u8) -> Self {
        match value {
            0..=85 => CongestionLevel::Low,
            86..=170 => CongestionLevel::Moderate,
            171..=254 => CongestionLevel::High,
            _ => CongestionLevel::Critical,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BandwidthStatistics {
    pub upload_utilization: f64,
    pub download_utilization: f64,
    pub efficiency: f64,
    pub bytes_transferred: u64,
    pub peak_bandwidth: f64,
    pub average_bandwidth: f64,
    pub congestion_level: CongestionLevel,
    pub quality_score: f64,
}

impl Default for BandwidthStatistics {
    fn default() -> Self {
        Self {
            upload_utilization: 0.0,
            download_utilization: 0.0,
            efficiency: 0.0,
            bytes_transferred: 0,
            peak_bandwidth: 0.0,
            average_bandwidth: 0.0,
            congestion_level: CongestionLevel::Low,
            quality_score: 0.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MeshStatus {
    pub internet_connected: bool,
    pub mesh_connected: bool,
    pub connectivity_percentage: f64,
    pub active_peers: u32,
    pub local_peers: u32,
    pub regional_peers: u32,
    pub global_peers: u32,
    pub relay_peers: u32,
    pub network_coverage: f64,
    pub connection_quality: f64,
    pub uptime_percentage: f64,
    pub routing_efficiency: f64,
    pub stability: f64,
    pub redundancy: f64,
    pub total_bandwidth: f64,
    pub active_nodes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DiscoveryStatistics {
    pub local_peers: u32,
    pub regional_peers: u32,
    pub global_peers: u32,
    pub relay_peers: u32,
    pub peers_discovered: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub discovery_time_ms: u64,
    pub network_diameter: u32,
    pub total_peers_discovered_per_hour: u32,
    pub average_discovery_success_rate: f64,
    pub regions_with_peers: u32,
    pub geographic_diversity_index: f64,
    pub long_distance_connections: u32,
    pub rural_connectivity_index: f64,
    pub average_response_time_ms: f64,
    pub discovery_variance: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NetworkStatistics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub peer_count: usize,
    pub connection_count: usize,
    pub mesh_status: Option<MeshStatus>,
    pub bandwidth_stats: Option<BandwidthStatistics>,
    pub discovery_stats: Option<DiscoveryStatistics>,
    pub timestamp: u64,
}
