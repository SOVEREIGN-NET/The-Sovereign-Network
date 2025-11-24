//! Alert System
//! 
//! Generates and manages system alerts based on metrics thresholds

use std::time::{SystemTime, UNIX_EPOCH};

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

/// Sync alert notification
#[derive(Debug, Clone)]
pub struct SyncAlert {
    pub id: String,
    pub level: AlertLevel,
    pub category: String,
    pub message: String,
    pub timestamp: u64,
    pub acknowledged: bool,
    pub peer_id: Option<String>,
    pub metric_value: Option<f64>,
    pub threshold_value: Option<f64>,
}

impl SyncAlert {
    pub fn new(level: AlertLevel, category: String, message: String) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            id: format!("alert_{}", now),
            level,
            category,
            message,
            timestamp: now,
            acknowledged: false,
            peer_id: None,
            metric_value: None,
            threshold_value: None,
        }
    }
    
    pub fn with_peer(mut self, peer_id: String) -> Self {
        self.peer_id = Some(peer_id);
        self
    }
    
    pub fn with_metric(mut self, value: f64, threshold: f64) -> Self {
        self.metric_value = Some(value);
        self.threshold_value = Some(threshold);
        self
    }
}

/// Alert thresholds configuration
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub max_block_latency_ms: u64,
    pub max_tx_latency_ms: u64,
    pub max_bandwidth_mbps: f64,
    pub min_validation_success_rate: f64,
    pub max_duplicate_ratio: f64,
    pub min_peer_score: i32,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            max_block_latency_ms: 5000,      // 5 seconds
            max_tx_latency_ms: 3000,         // 3 seconds
            max_bandwidth_mbps: 10.0,        // 10 MB/s
            min_validation_success_rate: 95.0, // 95%
            max_duplicate_ratio: 20.0,       // 20%
            min_peer_score: -25,             // Warning before ban threshold
        }
    }
}
