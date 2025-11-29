use serde::{Deserialize, Serialize};

/// Connection establishment details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDetails {
    /// Network address/identifier
    pub address: String,
    /// Authentication token
    pub auth_token: Vec<u8>,
    /// Session duration in seconds
    pub session_duration_sec: u32,
    /// QoS parameters
    pub qos_parameters: QoSParameters,
}

/// Quality of Service parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QoSParameters {
    /// Guaranteed minimum bandwidth (kbps)
    pub min_bandwidth_kbps: u32,
    /// Maximum allowed latency (ms)
    pub max_latency_ms: u32,
    /// Priority level (0-255)
    pub priority: u8,
    /// Reliability requirement (0.0 to 1.0)
    pub reliability_requirement: f64,
}
