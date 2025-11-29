//! Network statistics and status types for the ZHTP mesh network

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Network statistics from the mesh network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatistics {
    /// Total bytes sent through the network
    pub bytes_sent: u64,
    /// Total bytes received from the network
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Current number of connected peers
    pub peer_count: usize,
    /// Current number of active connections
    pub connection_count: usize,
}

impl Default for NetworkStatistics {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            peer_count: 0,
            connection_count: 0,
        }
    }
}

/// Mesh network status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshStatus {
    /// Whether connection to traditional internet is available
    pub internet_connected: bool,
    /// Whether mesh network is operational
    pub mesh_connected: bool,
    /// Overall connectivity percentage (0.0 to 100.0)
    pub connectivity_percentage: f64,
    /// Relay node connectivity percentage
    pub relay_connectivity: f64,
    /// Number of currently active peers
    pub active_peers: u32,
    /// Number of local (same network) peers
    pub local_peers: u32,
    /// Number of regional (nearby networks) peers
    pub regional_peers: u32,
    /// Number of global (distant networks) peers
    pub global_peers: u32,
    /// Number of relay peers
    pub relay_peers: u32,
    /// Rate of peer churn (peers leaving/joining)
    pub churn_rate: f64,
    /// Mesh coverage percentage
    pub coverage: f64,
    /// Mesh redundancy factor
    pub redundancy: f64,
    /// Mesh stability score
    pub stability: f64,
    /// Protocol-specific health information
    pub protocol_health: HashMap<String, f64>,
}

impl Default for MeshStatus {
    fn default() -> Self {
        Self {
            internet_connected: false,
            mesh_connected: false,
            connectivity_percentage: 0.0,
            relay_connectivity: 0.0,
            active_peers: 0,
            local_peers: 0,
            regional_peers: 0,
            global_peers: 0,
            relay_peers: 0,
            churn_rate: 0.0,
            coverage: 0.0,
            redundancy: 0.0,
            stability: 0.0,
            protocol_health: HashMap::new(),
        }
    }
}

/// Bandwidth utilization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthStatistics {
    /// Upload bandwidth utilization (0.0 to 1.0)
    pub upload_utilization: f64,
    /// Download bandwidth utilization (0.0 to 1.0)
    pub download_utilization: f64,
    /// Overall bandwidth efficiency
    pub efficiency: f64,
    /// Current congestion level
    pub congestion_level: CongestionLevel,
}

impl Default for BandwidthStatistics {
    fn default() -> Self {
        Self {
            upload_utilization: 0.0,
            download_utilization: 0.0,
            efficiency: 1.0,
            congestion_level: CongestionLevel::Low,
        }
    }
}

/// Network congestion levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CongestionLevel {
    /// Low congestion - optimal performance
    Low,
    /// Moderate congestion - slight delays
    Moderate,
    /// High congestion - noticeable delays
    High,
    /// Critical congestion - severe performance impact
    Critical,
}

impl Default for CongestionLevel {
    fn default() -> Self {
        CongestionLevel::Low
    }
}

/// Network latency statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStatistics {
    /// Average latency in milliseconds
    pub average_latency: f64,
    /// Latency variance in milliseconds
    pub variance: f64,
    /// Timeout rate (0.0 to 1.0)
    pub timeout_rate: f64,
    /// Network jitter in milliseconds
    pub jitter: f64,
}

impl Default for LatencyStatistics {
    fn default() -> Self {
        Self {
            average_latency: 0.0,
            variance: 0.0,
            timeout_rate: 0.0,
            jitter: 0.0,
        }
    }
}
