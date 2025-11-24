//! Performance Metrics Tracking
//! 
//! Monitors blockchain synchronization performance

use std::time::{SystemTime, UNIX_EPOCH};

/// Performance metrics for blockchain sync
#[derive(Debug, Clone)]
pub struct SyncPerformanceMetrics {
    // Latency tracking (milliseconds)
    pub avg_block_propagation_ms: f64,
    pub avg_tx_propagation_ms: f64,
    pub p95_block_latency_ms: u64,
    pub p95_tx_latency_ms: u64,
    pub min_block_latency_ms: u64,
    pub max_block_latency_ms: u64,
    pub min_tx_latency_ms: u64,
    pub max_tx_latency_ms: u64,
    
    // Bandwidth tracking (bytes)
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub bytes_sent_per_sec: f64,
    pub bytes_received_per_sec: f64,
    pub peak_bandwidth_usage_bps: u64,
    
    // Efficiency metrics
    pub duplicate_block_ratio: f64,
    pub duplicate_tx_ratio: f64,
    pub validation_success_rate: f64,
    pub relay_efficiency: f64,
    
    // Time window for rate calculations
    pub measurement_start: u64,
    pub measurement_duration_secs: u64,
}

impl SyncPerformanceMetrics {
    pub fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            avg_block_propagation_ms: 0.0,
            avg_tx_propagation_ms: 0.0,
            p95_block_latency_ms: 0,
            p95_tx_latency_ms: 0,
            min_block_latency_ms: u64::MAX,
            max_block_latency_ms: 0,
            min_tx_latency_ms: u64::MAX,
            max_tx_latency_ms: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            bytes_sent_per_sec: 0.0,
            bytes_received_per_sec: 0.0,
            peak_bandwidth_usage_bps: 0,
            duplicate_block_ratio: 0.0,
            duplicate_tx_ratio: 0.0,
            validation_success_rate: 100.0,
            relay_efficiency: 100.0,
            measurement_start: now,
            measurement_duration_secs: 0,
        }
    }
}

/// Broadcast metrics
#[derive(Debug, Clone)]
pub struct BroadcastMetrics {
    pub blocks_sent: u64,
    pub blocks_received: u64,
    pub transactions_sent: u64,
    pub transactions_received: u64,
    pub blocks_relayed: u64,
    pub transactions_relayed: u64,
    pub blocks_rejected: u64,
    pub transactions_rejected: u64,
}

impl BroadcastMetrics {
    pub fn new() -> Self {
        Self {
            blocks_sent: 0,
            blocks_received: 0,
            transactions_sent: 0,
            transactions_received: 0,
            blocks_relayed: 0,
            transactions_relayed: 0,
            blocks_rejected: 0,
            transactions_rejected: 0,
        }
    }
}

/// Historical data point for time-series tracking
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub blocks_received: u64,
    pub txs_received: u64,
    pub blocks_rejected: u64,
    pub txs_rejected: u64,
    pub avg_latency_ms: f64,
    pub bandwidth_bps: u64,
    pub active_peers: usize,
    pub banned_peers: usize,
}

/// Time-series metrics storage with rolling window
#[derive(Debug, Clone)]
pub struct MetricsHistory {
    pub snapshots: Vec<MetricsSnapshot>,
    pub max_snapshots: usize,
    pub interval_secs: u64,
    pub last_snapshot: u64,
}

impl MetricsHistory {
    pub fn new(max_snapshots: usize, interval_secs: u64) -> Self {
        Self {
            snapshots: Vec::new(),
            max_snapshots,
            interval_secs,
            last_snapshot: 0,
        }
    }
    
    pub fn add_snapshot(&mut self, snapshot: MetricsSnapshot) {
        self.last_snapshot = snapshot.timestamp;
        self.snapshots.push(snapshot);
        if self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }
    }
    
    pub fn should_take_snapshot(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        now - self.last_snapshot >= self.interval_secs
    }
}
