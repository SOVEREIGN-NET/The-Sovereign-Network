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
    // Utilization metrics (0.0-1.0)
    pub upload_utilization: f64,
    pub download_utilization: f64,
    pub efficiency: f64,

    // Throughput metrics
    pub bytes_transferred: u64,
    pub peak_bandwidth: f64,
    pub average_bandwidth: f64,

    // Quality metrics
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
