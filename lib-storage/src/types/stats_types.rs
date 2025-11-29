//! Statistics and monitoring type definitions
//! 
//! Contains all types related to storage system monitoring, health checks,
//! and statistical reporting.

use serde::{Deserialize, Serialize};

/// Storage system health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHealth {
    /// Storage utilization percentage
    pub utilization: f64,
    /// Number of chunks currently stored
    pub chunk_count: usize,
    /// Average replication factor
    pub avg_replication: f64,
    /// Overall system health status
    pub healthy: bool,
}

/// DHT network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStats {
    /// Total number of DHT nodes
    pub total_nodes: usize,
    /// Total active connections
    pub total_connections: usize,
    /// Total messages sent
    pub total_messages_sent: u64,
    /// Total messages received
    pub total_messages_received: u64,
    /// Size of routing table
    pub routing_table_size: usize,
    /// Storage utilization percentage
    pub storage_utilization: f64,
    /// Network health score (0.0 to 1.0)
    pub network_health: f64,
}

/// Contract manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractStats {
    /// Total number of contracts
    pub total_contracts: u64,
    /// Total storage under contract (bytes)
    pub total_storage_under_contract: u64,
    /// Total contract value (tokens)
    pub total_contract_value: u64,
    /// Number of active contracts
    pub active_contracts: u64,
    /// Number of expired contracts
    pub expired_contracts: u64,
    /// Number of breached contracts
    pub breached_contracts: u64,
}

/// Contract performance evaluation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractPerformanceReport {
    /// Contract identifier
    pub contract_id: String,
    /// Overall performance score (0.0-1.0)
    pub performance_score: f64,
    /// Performance category (Excellent, Good, etc.)
    pub performance_category: String,
    /// SLA compliance percentage
    pub sla_compliance: f64,
    /// Uptime percentage
    pub uptime_percentage: f64,
    /// Average response time in milliseconds
    pub avg_response_time: u64,
    /// Data integrity score
    pub data_integrity_score: f64,
    /// Performance improvement recommendations
    pub recommendations: Vec<String>,
    /// When this evaluation was performed
    pub evaluation_timestamp: u64,
}

/// Storage system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total number of stored content items
    pub total_content: usize,
    /// Total size of all stored content (bytes)
    pub total_size: u64,
    /// Size of local cache (bytes)
    pub cache_size: u64,
    /// Number of active storage contracts
    pub active_contracts: usize,
    /// Number of known storage nodes
    pub known_storage_nodes: usize,
    /// Number of DHT entries
    pub dht_entries: usize,
    /// Size of routing table
    pub routing_table_size: usize,
}
