<<<<<<< HEAD
# Type System Documentation

The ZHTP Unified Storage System employs a comprehensive type system that provides strong typing, clear interfaces, and consistent data structures across all components. This documentation covers all core types, enums, and data structures used throughout the system.

## ðŸ“ Type Module Structure

- **[Core Types](types_core.md)** (`types/mod.rs`) - Primary type aliases and constants
- **[DHT Types](types_dht.md)** (`types/dht_types.rs`) - Distributed hash table data structures
- **[Storage Types](types_storage.md)** (`types/storage_types.rs`) - Storage layer data structures
- **[Economic Types](types_economic.md)** (`types/economic_types.rs`) - Economic system types
- **[Configuration Types](types_config.md)** (`types/config_types.rs`) - System configuration structures
- **[Statistics Types](types_stats.md)** (`types/stats_types.rs`) - Metrics and statistics types
- **[Node Address Types](types_node_address.md)** (`types/node_address.rs`) - Network addressing types

## ðŸ—ï¸ Type System Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                        Type System Hierarchy                    â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                     Core Type Aliases                           â”‚
â”‚         NodeId â”‚ ContentHash â”‚ DhtKey = Hash                   â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  DHT Types    â”‚  Storage Types â”‚  Economic Types â”‚ Config Types â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚         Statistics Types â”‚ Network Address Types               â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

##  Core Type Aliases

### Primary Identifiers

```rust
/// Node identifier for DHT routing (deterministic, derived from identity)
pub use lib_identity::NodeId;

/// Content hash for addressing  
pub type ContentHash = Hash;

/// DHT key type
pub type DhtKey = Hash;
```

**Usage:**
- **NodeId**: Uniquely identifies nodes in the DHT network
- **ContentHash**: Content-addressable storage keys
- **DhtKey**: Generic DHT key type for storage operations

### System Constants

```rust
/// Storage pricing per GB per day (in SOV tokens)
pub const STORAGE_PRICE_PER_GB_DAY: u64 = 100;

/// Minimum replication factor
pub const MIN_REPLICATION: u8 = 3;

/// Maximum replication factor  
pub const MAX_REPLICATION: u8 = 12;
```

##  Enumeration Types

### Storage Tiers

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageTier {
    /// High performance, frequently accessed data
    Hot,
    /// Balanced performance and cost
    Warm, 
    /// Cost optimized, infrequently accessed
    Cold,
    /// Long-term storage, lowest cost
    Archive,
}
```

**Characteristics:**
- **Hot**: SSD storage, <100ms access, highest cost
- **Warm**: Hybrid storage, <1s access, balanced cost
- **Cold**: HDD storage, <10s access, lower cost  
- **Archive**: Tape/offline storage, >1min access, lowest cost

### Access Levels

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessLevel {
    /// Anyone can access without restrictions
    Public,
    /// Only owner can access
    Private,
    /// Specific permissions required
    Restricted,
}
```

### Encryption Levels

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncryptionLevel {
    /// No encryption (public data only)
    None,
    /// Standard AES-256 encryption
    Standard,
    /// Enhanced encryption with additional security
    HighSecurity,
    /// Post-quantum cryptographic algorithms
    QuantumResistant,
}
```

### Access Patterns

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessPattern {
    /// Frequently accessed data (daily access)
    Frequent,
    /// Occasionally accessed data (weekly/monthly)
    Occasional,
    /// Rarely accessed data (yearly or less)
    Rare,
    /// Write-once, read-never (backup/archive)
    WriteOnce,
}
```

##  Core Data Structures

### Content Metadata

```rust
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
    /// Access count for usage tracking
    pub access_count: u64,
    /// Expiration timestamp (optional)
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
    /// Original filename
    pub filename: String,
    /// Content description
    pub description: String,
    /// Encryption status
    pub is_encrypted: bool,
    /// Compression status
    pub is_compressed: bool,
}
```

### Storage Chunk

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChunk {
    /// Chunk identifier
    pub id: Hash,
    /// Parent content hash
    pub content_hash: ContentHash,
    /// Chunk index in the content
    pub chunk_index: u32,
    /// Chunk data (potentially encrypted)
    pub data: Vec<u8>,
    /// Erasure coding parity data
    pub parity_data: Option<Vec<u8>>,
    /// Chunk size
    pub size: u32,
    /// Checksum for integrity
    pub checksum: Hash,
}
```

### Chunk Metadata

```rust
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
```

##  DHT-Specific Types

### DHT Node

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNode {
    /// Node identifier (cryptographic hash)
    pub id: NodeId,
    /// Network addresses (IP:Port combinations)
    pub addresses: Vec<String>,
    /// Post-quantum cryptographic signature
    pub public_key: PostQuantumSignature,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Reputation score (0-âˆž)
    pub reputation: u32,
    /// Storage capabilities (optional)
    pub storage_info: Option<StorageCapabilities>,
}
```

### Storage Capabilities

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapabilities {
    /// Available storage space in bytes
    pub available_space: u64,
    /// Total storage capacity in bytes
    pub total_capacity: u64,
    /// Pricing per GB per day in SOV tokens
    pub price_per_gb_day: u64,
    /// Supported storage tiers
    pub supported_tiers: Vec<StorageTier>,
    /// Geographic region
    pub region: String,
    /// Historical uptime percentage
    pub uptime: f64,
}
```

### DHT Message Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessageType {
    Ping,                    // Node liveness check
    Pong,                    // Ping response
    Store,                   // Store data request
    FindNode,                // Find closest nodes
    FindValue,               // Find stored value
    ContractDeploy,          // Deploy smart contract
    ContractQuery,           // Query smart contract
    ContractExecute,         // Execute smart contract
    ContractFind,            // Find smart contracts
}
```

### Zero-Knowledge DHT Value

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkDhtValue {
    /// Encrypted data payload
    pub encrypted_data: Vec<u8>,
    /// Zero-knowledge validity proof
    pub validity_proof: ZeroKnowledgeProof,
    /// Access level for the data
    pub access_level: AccessLevel,
    /// Cryptographic nonce
    pub nonce: Vec<u8>,
}
```

##  Economic Types

### Economic Storage Request

```rust
#[derive(Debug, Clone)]
pub struct EconomicStorageRequest {
    /// Content to be stored
    pub content: Vec<u8>,
    /// Original filename
    pub filename: String,
    /// Content MIME type
    pub content_type: String,
    /// Content description
    pub description: String,
    /// Preferred storage tier
    pub preferred_tier: StorageTier,
    /// Storage requirements and constraints
    pub requirements: StorageRequirements,
    /// Payment preferences
    pub payment_preferences: PaymentPreferences,
    /// Identity of the requester
    pub requester: ZhtpIdentity,
}
```

### Storage Requirements

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRequirements {
    /// Storage duration in days
    pub duration_days: u32,
    /// Quality requirements
    pub quality_requirements: QualityRequirements,
    /// Budget constraints
    pub budget_constraints: BudgetConstraints,
    /// Geographic preferences
    pub geographic_preferences: Vec<String>,
    /// Replication factor
    pub replication_factor: u8,
}
```

### Quality Requirements

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityRequirements {
    /// Minimum uptime percentage (0.0-1.0)
    pub min_uptime: f64,
    /// Maximum response time in milliseconds
    pub max_response_time: u64,
    /// Minimum replication factor
    pub min_replication: u8,
    /// Data integrity level (0.0-1.0)
    pub data_integrity_level: f64,
}
```

### Budget Constraints

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConstraints {
    /// Maximum total cost in SOV tokens
    pub max_total_cost: u64,
    /// Maximum cost per GB per day
    pub max_cost_per_gb_day: u64,
    /// Preferred payment schedule
    pub preferred_payment_schedule: PaymentSchedule,
}
```

### Economic Quote

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicQuote {
    /// Unique quote identifier
    pub quote_id: String,
    /// Total cost in SOV tokens
    pub total_cost: u64,
    /// Cost per GB per day
    pub cost_per_gb_day: u64,
    /// Storage duration in days
    pub duration_days: u32,
    /// Recommended storage provider nodes
    pub recommended_nodes: Vec<Hash>,
    /// Estimated quality metrics
    pub estimated_quality: QualityMetrics,
    /// Quote validity timestamp
    pub valid_until: u64,
    /// Contract terms and conditions
    pub terms: Vec<String>,
}
```

##  Statistics Types

### DHT Statistics

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStats {
    /// Total number of nodes in network
    pub total_nodes: usize,
    /// Total active connections
    pub total_connections: usize,
    /// Messages sent counter
    pub total_messages_sent: u64,
    /// Messages received counter
    pub total_messages_received: u64,
    /// Routing table size
    pub routing_table_size: usize,
    /// Storage utilization percentage
    pub storage_utilization: f64,
    /// Overall network health score
    pub network_health: f64,
}
```

### Economic Statistics

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicStats {
    /// Total number of contracts
    pub total_contracts: u64,
    /// Total storage under contract
    pub total_storage: u64,
    /// Total value locked in contracts
    pub total_value_locked: u64,
    /// Average contract value
    pub average_contract_value: u64,
    /// Total penalties enforced
    pub total_penalties: u64,
    /// Total rewards distributed
    pub total_rewards: u64,
}
```

### Storage Statistics

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total content items stored
    pub total_content_count: u64,
    /// Total storage space used
    pub total_storage_used: u64,
    /// Total upload operations
    pub total_uploads: u64,
    /// Total download operations
    pub total_downloads: u64,
}
```

##  Configuration Types

### Unified Storage Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedStorageConfig {
    /// Node identifier
    pub node_id: NodeId,
    /// Network addresses to bind
    pub addresses: Vec<String>,
    /// Economic system configuration
    pub economic_config: EconomicManagerConfig,
    /// Storage system configuration
    pub storage_config: StorageConfig,
    /// Erasure coding configuration
    pub erasure_config: ErasureConfig,
}
```

### Storage Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum storage size in bytes
    pub max_storage_size: u64,
    /// Default storage tier
    pub default_tier: StorageTier,
    /// Enable compression
    pub enable_compression: bool,
    /// Enable encryption
    pub enable_encryption: bool,
}
```

### Erasure Coding Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureConfig {
    /// Number of data shards
    pub data_shards: usize,
    /// Number of parity shards
    pub parity_shards: usize,
}
```

##  Type Usage Examples

### Creating Content Metadata

```rust
let metadata = ContentMetadata {
    hash: content_hash,
    size: data.len() as u64,
    content_type: "application/pdf".to_string(),
    owner: user_identity,
    tier: StorageTier::Warm,
    encryption: EncryptionLevel::Standard,
    access_pattern: AccessPattern::Occasional,
    replication_factor: 3,
    created_at: current_timestamp(),
    last_accessed: current_timestamp(),
    access_count: 0,
    expires_at: Some(expiry_timestamp),
    cost_per_day: 150, // 150 SOV tokens per day
    tags: vec!["legal".to_string(), "contract".to_string()],
    access_control: vec![AccessLevel::Private],
    total_chunks: 1,
    checksum: calculate_checksum(&data),
    filename: "contract.pdf".to_string(),
    description: "Legal contract document".to_string(),
    is_encrypted: true,
    is_compressed: false,
};
```

### Setting Up Storage Requirements

```rust
let requirements = StorageRequirements {
    duration_days: 365, // Store for 1 year
    quality_requirements: QualityRequirements {
        min_uptime: 0.99,           // 99% uptime
        max_response_time: 5000,    // 5 seconds max
        min_replication: 5,         // 5 replicas
        data_integrity_level: 0.999, // 99.9% integrity
    },
    budget_constraints: BudgetConstraints {
        max_total_cost: 100000,     // 100,000 SOV tokens
        max_cost_per_gb_day: 200,   // 200 tokens per GB/day
        preferred_payment_schedule: PaymentSchedule::Monthly,
    },
    geographic_preferences: vec!["US".to_string(), "EU".to_string()],
    replication_factor: 5,
};
```

##  Type Testing

### Type Validation Tests

```rust
#[test]
fn test_storage_tier_serialization() {
    let tier = StorageTier::Hot;
    let serialized = serde_json::to_string(&tier).unwrap();
    let deserialized: StorageTier = serde_json::from_str(&serialized).unwrap();
    assert_eq!(tier, deserialized);
}

#[test]
fn test_content_metadata_creation() {
    let metadata = ContentMetadata {
        hash: Hash::from_bytes(&[1u8; 32]),
        size: 1024,
        content_type: "text/plain".to_string(),
        // ... other fields
    };
    
    assert_eq!(metadata.size, 1024);
    assert_eq!(metadata.content_type, "text/plain");
}
```

### Type Compatibility Tests

```rust
#[test]
fn test_type_constants() {
    assert_eq!(STORAGE_PRICE_PER_GB_DAY, 100);
    assert_eq!(MIN_REPLICATION, 3);
    assert_eq!(MAX_REPLICATION, 12);
}

#[test]
fn test_hash_type_aliases() {
    let node_id: NodeId = lib_identity::NodeId::from_bytes(&[1u8; 32]);
    let content_hash: ContentHash = Hash::from_bytes(&[2u8; 32]);
    let dht_key: DhtKey = Hash::from_bytes(&[3u8; 32]);
    
    // All should be the same underlying type
    assert_eq!(std::mem::size_of::<NodeId>(), std::mem::size_of::<Hash>());
    assert_eq!(std::mem::size_of::<ContentHash>(), std::mem::size_of::<Hash>());
    assert_eq!(std::mem::size_of::<DhtKey>(), std::mem::size_of::<Hash>());
}
```

---

=======
# Type System Documentation

The ZHTP Unified Storage System employs a comprehensive type system that provides strong typing, clear interfaces, and consistent data structures across all components. This documentation covers all core types, enums, and data structures used throughout the system.

## ðŸ“ Type Module Structure

- **[Core Types](types_core.md)** (`types/mod.rs`) - Primary type aliases and constants
- **[DHT Types](types_dht.md)** (`types/dht_types.rs`) - Distributed hash table data structures
- **[Storage Types](types_storage.md)** (`types/storage_types.rs`) - Storage layer data structures
- **[Economic Types](types_economic.md)** (`types/economic_types.rs`) - Economic system types
- **[Configuration Types](types_config.md)** (`types/config_types.rs`) - System configuration structures
- **[Statistics Types](types_stats.md)** (`types/stats_types.rs`) - Metrics and statistics types
- **[Node Address Types](types_node_address.md)** (`types/node_address.rs`) - Network addressing types

## ðŸ—ï¸ Type System Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                        Type System Hierarchy                    â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                     Core Type Aliases                           â”‚
â”‚         NodeId â”‚ ContentHash â”‚ DhtKey = Hash                   â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  DHT Types    â”‚  Storage Types â”‚  Economic Types â”‚ Config Types â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚         Statistics Types â”‚ Network Address Types               â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

##  Core Type Aliases

### Primary Identifiers

```rust
/// Node identifier for DHT routing
pub use lib_identity::NodeId;

/// Content hash for addressing  
pub type ContentHash = Hash;

/// DHT key type
pub type DhtKey = Hash;
```

**Usage:**
- **NodeId**: Uniquely identifies nodes in the DHT network
- **ContentHash**: Content-addressable storage keys
- **DhtKey**: Generic DHT key type for storage operations

### System Constants

```rust
/// Storage pricing per GB per day (in SOV tokens)
pub const STORAGE_PRICE_PER_GB_DAY: u64 = 100;

/// Minimum replication factor
pub const MIN_REPLICATION: u8 = 3;

/// Maximum replication factor  
pub const MAX_REPLICATION: u8 = 12;
```

##  Enumeration Types

### Storage Tiers

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageTier {
    /// High performance, frequently accessed data
    Hot,
    /// Balanced performance and cost
    Warm, 
    /// Cost optimized, infrequently accessed
    Cold,
    /// Long-term storage, lowest cost
    Archive,
}
```

**Characteristics:**
- **Hot**: SSD storage, <100ms access, highest cost
- **Warm**: Hybrid storage, <1s access, balanced cost
- **Cold**: HDD storage, <10s access, lower cost  
- **Archive**: Tape/offline storage, >1min access, lowest cost

### Access Levels

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessLevel {
    /// Anyone can access without restrictions
    Public,
    /// Only owner can access
    Private,
    /// Specific permissions required
    Restricted,
}
```

### Encryption Levels

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncryptionLevel {
    /// No encryption (public data only)
    None,
    /// Standard AES-256 encryption
    Standard,
    /// Enhanced encryption with additional security
    HighSecurity,
    /// Post-quantum cryptographic algorithms
    QuantumResistant,
}
```

### Access Patterns

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessPattern {
    /// Frequently accessed data (daily access)
    Frequent,
    /// Occasionally accessed data (weekly/monthly)
    Occasional,
    /// Rarely accessed data (yearly or less)
    Rare,
    /// Write-once, read-never (backup/archive)
    WriteOnce,
}
```

##  Core Data Structures

### Content Metadata

```rust
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
    /// Access count for usage tracking
    pub access_count: u64,
    /// Expiration timestamp (optional)
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
    /// Original filename
    pub filename: String,
    /// Content description
    pub description: String,
    /// Encryption status
    pub is_encrypted: bool,
    /// Compression status
    pub is_compressed: bool,
}
```

### Storage Chunk

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChunk {
    /// Chunk identifier
    pub id: Hash,
    /// Parent content hash
    pub content_hash: ContentHash,
    /// Chunk index in the content
    pub chunk_index: u32,
    /// Chunk data (potentially encrypted)
    pub data: Vec<u8>,
    /// Erasure coding parity data
    pub parity_data: Option<Vec<u8>>,
    /// Chunk size
    pub size: u32,
    /// Checksum for integrity
    pub checksum: Hash,
}
```

### Chunk Metadata

```rust
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
```

##  DHT-Specific Types

### DHT Node

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNode {
    /// Node identifier (cryptographic hash)
    pub id: NodeId,
    /// Network addresses (IP:Port combinations)
    pub addresses: Vec<String>,
    /// Post-quantum cryptographic signature
    pub public_key: PostQuantumSignature,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Reputation score (0-âˆž)
    pub reputation: u32,
    /// Storage capabilities (optional)
    pub storage_info: Option<StorageCapabilities>,
}
```

### Storage Capabilities

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapabilities {
    /// Available storage space in bytes
    pub available_space: u64,
    /// Total storage capacity in bytes
    pub total_capacity: u64,
    /// Pricing per GB per day in SOV tokens
    pub price_per_gb_day: u64,
    /// Supported storage tiers
    pub supported_tiers: Vec<StorageTier>,
    /// Geographic region
    pub region: String,
    /// Historical uptime percentage
    pub uptime: f64,
}
```

### DHT Message Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessageType {
    Ping,                    // Node liveness check
    Pong,                    // Ping response
    Store,                   // Store data request
    FindNode,                // Find closest nodes
    FindValue,               // Find stored value
    ContractDeploy,          // Deploy smart contract
    ContractQuery,           // Query smart contract
    ContractExecute,         // Execute smart contract
    ContractFind,            // Find smart contracts
}
```

### Zero-Knowledge DHT Value

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkDhtValue {
    /// Encrypted data payload
    pub encrypted_data: Vec<u8>,
    /// Zero-knowledge validity proof
    pub validity_proof: ZeroKnowledgeProof,
    /// Access level for the data
    pub access_level: AccessLevel,
    /// Cryptographic nonce
    pub nonce: Vec<u8>,
}
```

##  Economic Types

### Economic Storage Request

```rust
#[derive(Debug, Clone)]
pub struct EconomicStorageRequest {
    /// Content to be stored
    pub content: Vec<u8>,
    /// Original filename
    pub filename: String,
    /// Content MIME type
    pub content_type: String,
    /// Content description
    pub description: String,
    /// Preferred storage tier
    pub preferred_tier: StorageTier,
    /// Storage requirements and constraints
    pub requirements: StorageRequirements,
    /// Payment preferences
    pub payment_preferences: PaymentPreferences,
    /// Identity of the requester
    pub requester: ZhtpIdentity,
}
```

### Storage Requirements

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRequirements {
    /// Storage duration in days
    pub duration_days: u32,
    /// Quality requirements
    pub quality_requirements: QualityRequirements,
    /// Budget constraints
    pub budget_constraints: BudgetConstraints,
    /// Geographic preferences
    pub geographic_preferences: Vec<String>,
    /// Replication factor
    pub replication_factor: u8,
}
```

### Quality Requirements

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityRequirements {
    /// Minimum uptime percentage (0.0-1.0)
    pub min_uptime: f64,
    /// Maximum response time in milliseconds
    pub max_response_time: u64,
    /// Minimum replication factor
    pub min_replication: u8,
    /// Data integrity level (0.0-1.0)
    pub data_integrity_level: f64,
}
```

### Budget Constraints

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConstraints {
    /// Maximum total cost in SOV tokens
    pub max_total_cost: u64,
    /// Maximum cost per GB per day
    pub max_cost_per_gb_day: u64,
    /// Preferred payment schedule
    pub preferred_payment_schedule: PaymentSchedule,
}
```

### Economic Quote

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicQuote {
    /// Unique quote identifier
    pub quote_id: String,
    /// Total cost in SOV tokens
    pub total_cost: u64,
    /// Cost per GB per day
    pub cost_per_gb_day: u64,
    /// Storage duration in days
    pub duration_days: u32,
    /// Recommended storage provider nodes
    pub recommended_nodes: Vec<Hash>,
    /// Estimated quality metrics
    pub estimated_quality: QualityMetrics,
    /// Quote validity timestamp
    pub valid_until: u64,
    /// Contract terms and conditions
    pub terms: Vec<String>,
}
```

##  Statistics Types

### DHT Statistics

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStats {
    /// Total number of nodes in network
    pub total_nodes: usize,
    /// Total active connections
    pub total_connections: usize,
    /// Messages sent counter
    pub total_messages_sent: u64,
    /// Messages received counter
    pub total_messages_received: u64,
    /// Routing table size
    pub routing_table_size: usize,
    /// Storage utilization percentage
    pub storage_utilization: f64,
    /// Overall network health score
    pub network_health: f64,
}
```

### Economic Statistics

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicStats {
    /// Total number of contracts
    pub total_contracts: u64,
    /// Total storage under contract
    pub total_storage: u64,
    /// Total value locked in contracts
    pub total_value_locked: u64,
    /// Average contract value
    pub average_contract_value: u64,
    /// Total penalties enforced
    pub total_penalties: u64,
    /// Total rewards distributed
    pub total_rewards: u64,
}
```

### Storage Statistics

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total content items stored
    pub total_content_count: u64,
    /// Total storage space used
    pub total_storage_used: u64,
    /// Total upload operations
    pub total_uploads: u64,
    /// Total download operations
    pub total_downloads: u64,
}
```

##  Configuration Types

### Unified Storage Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedStorageConfig {
    /// Node identifier
    pub node_id: NodeId,
    /// Network addresses to bind
    pub addresses: Vec<String>,
    /// Economic system configuration
    pub economic_config: EconomicManagerConfig,
    /// Storage system configuration
    pub storage_config: StorageConfig,
    /// Erasure coding configuration
    pub erasure_config: ErasureConfig,
}
```

### Storage Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum storage size in bytes
    pub max_storage_size: u64,
    /// Default storage tier
    pub default_tier: StorageTier,
    /// Enable compression
    pub enable_compression: bool,
    /// Enable encryption
    pub enable_encryption: bool,
}
```

### Erasure Coding Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureConfig {
    /// Number of data shards
    pub data_shards: usize,
    /// Number of parity shards
    pub parity_shards: usize,
}
```

##  Type Usage Examples

### Creating Content Metadata

```rust
let metadata = ContentMetadata {
    hash: content_hash,
    size: data.len() as u64,
    content_type: "application/pdf".to_string(),
    owner: user_identity,
    tier: StorageTier::Warm,
    encryption: EncryptionLevel::Standard,
    access_pattern: AccessPattern::Occasional,
    replication_factor: 3,
    created_at: current_timestamp(),
    last_accessed: current_timestamp(),
    access_count: 0,
    expires_at: Some(expiry_timestamp),
    cost_per_day: 150, // 150 SOV tokens per day
    tags: vec!["legal".to_string(), "contract".to_string()],
    access_control: vec![AccessLevel::Private],
    total_chunks: 1,
    checksum: calculate_checksum(&data),
    filename: "contract.pdf".to_string(),
    description: "Legal contract document".to_string(),
    is_encrypted: true,
    is_compressed: false,
};
```

### Setting Up Storage Requirements

```rust
let requirements = StorageRequirements {
    duration_days: 365, // Store for 1 year
    quality_requirements: QualityRequirements {
        min_uptime: 0.99,           // 99% uptime
        max_response_time: 5000,    // 5 seconds max
        min_replication: 5,         // 5 replicas
        data_integrity_level: 0.999, // 99.9% integrity
    },
    budget_constraints: BudgetConstraints {
        max_total_cost: 100000,     // 100,000 SOV tokens
        max_cost_per_gb_day: 200,   // 200 tokens per GB/day
        preferred_payment_schedule: PaymentSchedule::Monthly,
    },
    geographic_preferences: vec!["US".to_string(), "EU".to_string()],
    replication_factor: 5,
};
```

##  Type Testing

### Type Validation Tests

```rust
#[test]
fn test_storage_tier_serialization() {
    let tier = StorageTier::Hot;
    let serialized = serde_json::to_string(&tier).unwrap();
    let deserialized: StorageTier = serde_json::from_str(&serialized).unwrap();
    assert_eq!(tier, deserialized);
}

#[test]
fn test_content_metadata_creation() {
    let metadata = ContentMetadata {
        hash: Hash::from_bytes(&[1u8; 32]),
        size: 1024,
        content_type: "text/plain".to_string(),
        // ... other fields
    };
    
    assert_eq!(metadata.size, 1024);
    assert_eq!(metadata.content_type, "text/plain");
}
```

### Type Compatibility Tests

```rust
#[test]
fn test_type_constants() {
    assert_eq!(STORAGE_PRICE_PER_GB_DAY, 100);
    assert_eq!(MIN_REPLICATION, 3);
    assert_eq!(MAX_REPLICATION, 12);
}

#[test]
fn test_hash_type_aliases() {
    let node_id: NodeId = lib_identity::NodeId::from_bytes(&[1u8; 32]);
    let content_hash: ContentHash = Hash::from_bytes(&[2u8; 32]);
    let dht_key: DhtKey = Hash::from_bytes(&[3u8; 32]);
    
    // All should be the same underlying type
    assert_eq!(std::mem::size_of::<NodeId>(), std::mem::size_of::<Hash>());
    assert_eq!(std::mem::size_of::<ContentHash>(), std::mem::size_of::<Hash>());
    assert_eq!(std::mem::size_of::<DhtKey>(), std::mem::size_of::<Hash>());
}
```

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
The type system provides a robust foundation that ensures type safety, clear interfaces, and consistent data handling across all components of the ZHTP Unified Storage System.
