//! Storage layer type definitions
//! 
//! Contains all types related to the economic storage layer built on top of the DHT,
//! including content metadata, chunks, tiers, and access patterns.

use crate::types::{ContentHash, NodeId};
use crate::types::dht_types::{StorageTier, AccessLevel};
use lib_crypto::Hash;
use lib_identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};

/// Storage access patterns for optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessPattern {
    /// Frequently accessed data
    Frequent,
    /// Occasionally accessed data
    Occasional,
    /// Rarely accessed data
    Rare,
    /// Write-once, read-never (backup)
    WriteOnce,
}

/// Storage encryption level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionLevel {
    /// No encryption (public data)
    None,
    /// Standard encryption
    Standard,
    /// High-security encryption
    HighSecurity,
    /// Quantum-resistant encryption
    QuantumResistant,
}

/// Content metadata for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Content hash (unique identifier)
    pub hash: ContentHash,
    /// Content size in bytes
    pub size: u64,
    /// Content type/MIME type
    pub content_type: String,
    /// Owner identity
    pub owner: ZhtpIdentity,
    /// Storage tier
    pub tier: StorageTier,
    /// Encryption level
    pub encryption: EncryptionLevel,
    /// Access pattern hint
    pub access_pattern: AccessPattern,
    /// Replication factor
    pub replication_factor: u8,
    /// Creation timestamp
    pub created_at: u64,
    /// Last access timestamp
    pub last_accessed: u64,
    /// Access count for tracking usage
    pub access_count: u64,
    /// Expiration timestamp (if any)
    pub expires_at: Option<u64>,
    /// Storage cost per day
    pub cost_per_day: u64,
    /// Content tags for discovery
    pub tags: Vec<String>,
    /// Access control settings
    pub access_control: Vec<AccessLevel>,
    /// Total number of chunks
    pub total_chunks: u32,
    /// Content checksum for integrity
    pub checksum: Hash,
    /// Content hash (duplicate for compatibility)
    pub content_hash: ContentHash,
    /// Original filename
    pub filename: String,
    /// Content description
    pub description: String,
    /// Encryption status
    pub is_encrypted: bool,
    /// Compression status
    pub is_compressed: bool,
}

/// Storage chunk for erasure coding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChunk {
    /// Chunk identifier
    pub id: Hash,
    /// Parent content hash
    pub content_hash: ContentHash,
    /// Chunk index in the content
    pub chunk_index: u32,
    /// Chunk data (encrypted)
    pub data: Vec<u8>,
    /// Erasure coding parity data
    pub parity_data: Option<Vec<u8>>,
    /// Chunk size
    pub size: u32,
    /// Checksum for integrity
    pub checksum: Hash,
}

/// Metadata for individual storage chunks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMetadata {
    /// Chunk identifier
    pub chunk_id: String,
    /// Chunk size in bytes
    pub size: u64,
    /// Checksum for integrity verification
    pub checksum: Vec<u8>,
    /// Storage tier level
    pub tier: StorageTier,
    /// Nodes storing this chunk
    pub location: Vec<NodeId>,
    /// Access count
    pub access_count: u64,
    /// Last access timestamp
    pub last_access: u64,
    /// Compression algorithm used (if any)
    pub compression_algorithm: Option<String>,
    /// Compression ratio achieved
    pub compression_ratio: f64,
}
