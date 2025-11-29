//! Configuration type definitions
//! 
//! Contains all configuration-related types for the storage system including
//! storage configuration, erasure coding configuration, and system parameters.

use std::path::PathBuf;

/// Storage system configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Local storage path
    pub storage_path: PathBuf,
    /// Total storage capacity
    pub capacity: u64,
    /// Replication factor for content
    pub replication_factor: u8,
    /// Node identifier bytes
    pub node_id: [u8; 32],
    /// Network addresses for this node
    pub addresses: Vec<String>,
    /// K-bucket size for Kademlia routing
    pub k_bucket_size: usize,
    /// DHT replication factor
    pub dht_replication: usize,
    /// Number of erasure coding data chunks
    pub erasure_data_chunks: usize,
    /// Number of erasure coding parity chunks
    pub erasure_parity_chunks: usize,
    /// Chunk size for erasure coding
    pub chunk_size: usize,
}

/// Erasure coding configuration
#[derive(Debug, Clone)]
pub struct ErasureConfig {
    /// Number of data chunks
    pub data_chunks: u8,
    /// Number of parity chunks
    pub parity_chunks: u8,
    /// Chunk size in bytes
    pub chunk_size: u32,
}
