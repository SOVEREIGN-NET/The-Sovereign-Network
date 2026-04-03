use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolStorageStats {
    pub total_content: u64,
    pub total_size_bytes: u64,
    pub active_contracts: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub total_uploads: u64,
    pub total_downloads: u64,
    pub retrievals_served: u64,
    pub cache_size: u64,
    pub dht_entries: u64,
    pub routing_table_size: u64,
    pub known_storage_nodes: u64,
    pub total_fees_paid: u64,
    pub theoretical_tokens_earned: u64,
    pub avg_replication: f64,
    pub reliability_percentage: f64,
    pub storage_duration_hours: u64,
}

impl Default for ProtocolStorageStats {
    fn default() -> Self {
        Self {
            total_content: 0,
            total_size_bytes: 0,
            active_contracts: 0,
            successful_operations: 0,
            failed_operations: 0,
            total_uploads: 0,
            total_downloads: 0,
            retrievals_served: 0,
            cache_size: 0,
            dht_entries: 0,
            routing_table_size: 0,
            known_storage_nodes: 0,
            total_fees_paid: 0,
            theoretical_tokens_earned: 0,
            avg_replication: 0.0,
            reliability_percentage: 100.0,
            storage_duration_hours: 0,
        }
    }
}

/// Deprecated alias for backward compatibility
/// Use `ProtocolStorageStats` instead
#[deprecated(since = "0.1.0", note = "Use ProtocolStorageStats instead")]
pub type StorageStats = ProtocolStorageStats;
