<<<<<<< HEAD
# lib-storage API Reference

Complete API documentation for the ZHTP Unified Storage System.

##  Table of Contents

- [UnifiedStorageSystem](#unifiedstoragesystem) - Main system interface
- [Configuration](#configuration) - System configuration types
- [Storage Operations](#storage-operations) - Core storage functionality
- [Economic Features](#economic-features) - Contracts and payments
- [Identity Integration](#identity-integration) - Identity management
- [DHT Operations](#dht-operations) - Low-level DHT access
- [Types Reference](#types-reference) - Core data types

## UnifiedStorageSystem

The main entry point for all storage operations.

### Constructor

```rust
impl UnifiedStorageSystem {
    /// Create new unified storage system
    pub async fn new(config: UnifiedStorageConfig) -> Result<Self>
}
```

**Example:**
```rust
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};

let config = UnifiedStorageConfig::default();
let mut system = UnifiedStorageSystem::new(config).await?;
```

### Content Operations

#### upload_content
```rust
pub async fn upload_content(
    &mut self,
    request: UploadRequest,
    uploader: ZhtpIdentity,
) -> Result<ContentHash>
```

Upload content to the storage system with full economic integration.

**Parameters:**
- `request: UploadRequest` - Upload configuration and content
- `uploader: ZhtpIdentity` - Identity of the user uploading content

**Returns:** `ContentHash` - Unique identifier for the stored content

**Example:**
```rust
let upload_request = UploadRequest {
    content: b"Hello, ZHTP Storage!".to_vec(),
    filename: "hello.txt".to_string(),
    mime_type: "text/plain".to_string(),
    description: "Test file".to_string(),
    tags: vec!["test".to_string()],
    encrypt: true,
    compress: false,
    access_control: AccessControlSettings {
        public_read: false,
        read_permissions: vec![],
        write_permissions: vec![],
        expires_at: None,
    },
    storage_requirements: ContentStorageRequirements {
        duration_days: 30,
        quality_requirements: QualityRequirements::default(),
        budget_constraints: BudgetConstraints::default(),
    },
};

let content_hash = system.upload_content(upload_request, uploader_identity).await?;
```

#### download_content
```rust
pub async fn download_content(
    &mut self,
    request: DownloadRequest,
) -> Result<Vec<u8>>
```

Download content with access control verification.

**Parameters:**
- `request: DownloadRequest` - Download request with access credentials

**Returns:** `Vec<u8>` - The downloaded content data

**Example:**
```rust
let download_request = DownloadRequest {
    content_hash,
    requester: requester_identity,
    access_proof: None, // Optional for public content
};

let content = system.download_content(download_request).await?;
```

#### search_content
```rust
pub async fn search_content(
    &self,
    query: SearchQuery,
    requester: ZhtpIdentity,
) -> Result<Vec<ContentMetadata>>
```

Search for content across the storage system.

**Example:**
```rust
let search_query = SearchQuery {
    keywords: vec!["test".to_string()],
    content_type: Some("text/plain".to_string()),
    tags: vec!["test".to_string()],
    owner: None,
    date_range: None,
    size_range: None,
    limit: 10,
};

let results = system.search_content(search_query, requester_identity).await?;
```

### Erasure Coding Operations

#### store_with_erasure_coding
```rust
pub async fn store_with_erasure_coding(
    &mut self,
    data: Vec<u8>,
    storage_requirements: StorageRequirements,
    uploader: ZhtpIdentity,
) -> Result<ContentHash>
```

Store data with Reed-Solomon erasure coding for enhanced reliability.

**Example:**
```rust
let data = b"Important data requiring high reliability".to_vec();
let requirements = StorageRequirements {
    duration_days: 365,
    quality_requirements: QualityRequirements {
        min_uptime: 0.99,
        max_response_time: 2000,
        min_replication: 6,
        data_integrity_level: 0.999,
    },
    budget_constraints: BudgetConstraints::default(),
    // ... other fields
};

let content_hash = system.store_with_erasure_coding(
    data, 
    requirements, 
    uploader_identity
).await?;
```

## Configuration

### UnifiedStorageConfig

Main configuration structure for the storage system.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedStorageConfig {
    pub node_id: NodeId,
    pub addresses: Vec<String>,
    pub economic_config: EconomicManagerConfig,
    pub storage_config: StorageConfig,
    pub erasure_config: ErasureConfig,
}
```

**Default Configuration:**
```rust
let config = UnifiedStorageConfig {
    node_id: Hash::from_bytes(&rand::random::<[u8; 32]>()),
    addresses: vec!["127.0.0.1:33445".to_string()],
    economic_config: EconomicManagerConfig::default(),
    storage_config: StorageConfig {
        max_storage_size: 100_000_000_000, // 100GB
        default_tier: StorageTier::Hot,
        enable_compression: true,
        enable_encryption: true,
    },
    erasure_config: ErasureConfig {
        data_shards: 4,
        parity_shards: 2,
    },
};
```

### EconomicManagerConfig

Configuration for the economic incentive system.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicManagerConfig {
    pub default_duration_days: u32,
    pub base_price_per_gb_day: u64,
    pub enable_escrow: bool,
    pub quality_premium_rate: f64,
    pub network_fee_rate: f64,
    pub escrow_fee_rate: f64,
}
```

## Economic Features

### get_storage_quote
```rust
pub async fn get_storage_quote(
    &mut self, 
    request: EconomicStorageRequest
) -> Result<EconomicQuote>
```

Get a pricing quote for storage services.

**Example:**
```rust
let request = EconomicStorageRequest {
    content: data.clone(),
    filename: "important_file.pdf".to_string(),
    content_type: "application/pdf".to_string(),
    description: "Important document".to_string(),
    preferred_tier: StorageTier::Warm,
    requirements: StorageRequirements {
        duration_days: 90,
        quality_requirements: QualityRequirements {
            min_uptime: 0.95,
            max_response_time: 5000,
            min_replication: 3,
            data_integrity_level: 0.99,
        },
        budget_constraints: BudgetConstraints {
            max_total_cost: 10000, // 10,000 SOV tokens
            max_cost_per_gb_day: 150,
            preferred_payment_schedule: PaymentSchedule::Upfront,
        },
        geographic_preferences: vec!["US".to_string(), "EU".to_string()],
        replication_factor: 3,
    },
    payment_preferences: PaymentPreferences::default(),
    requester: requester_identity,
};

let quote = system.get_storage_quote(request).await?;
println!("Total cost: {} SOV tokens", quote.total_cost);
```

### EconomicQuote Structure

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicQuote {
    pub quote_id: String,
    pub total_cost: u64,
    pub cost_per_gb_day: u64,
    pub duration_days: u32,
    pub recommended_nodes: Vec<Hash>,
    pub estimated_quality: QualityMetrics,
    pub valid_until: u64,
    pub terms: Vec<String>,
}
```

## Identity Integration

### store_identity_credentials
```rust
pub async fn store_identity_credentials(
    &mut self,
    identity_id: &lib_identity::IdentityId,
    credentials: &lib_identity::ZhtpIdentity,
    passphrase: &str,
) -> Result<()>
```

Store identity credentials securely in the unified storage system.

**Example:**
```rust
let identity_id = IdentityId::from_bytes(&[1u8; 32]);
let passphrase = "secure_passphrase_123";

system.store_identity_credentials(
    &identity_id, 
    &user_identity, 
    passphrase
).await?;
```

### retrieve_identity_credentials
```rust
pub async fn retrieve_identity_credentials(
    &mut self,
    identity_id: &lib_identity::IdentityId,
    passphrase: &str,
) -> Result<lib_identity::ZhtpIdentity>
```

Retrieve previously stored identity credentials.

**Example:**
```rust
let retrieved_identity = system.retrieve_identity_credentials(
    &identity_id, 
    passphrase
).await?;

println!("Retrieved identity: {}", retrieved_identity.id);
```

## DHT Operations

### add_peer
```rust
pub async fn add_peer(&mut self, peer_address: String) -> Result<()>
```

Add a peer to the DHT network with their identity-derived NodeId.

**Example:**
```rust
let peer_node_id = lib_storage::NodeId::from_bytes(rand::random::<[u8; 32]>());
system.add_peer("192.168.1.100:33445".to_string(), peer_node_id).await?;
```

### perform_maintenance
```rust
pub async fn perform_maintenance(&mut self) -> Result<()>
```

Perform system maintenance including contract monitoring and cleanup.

**Example:**
```rust
// Run maintenance periodically
tokio::spawn(async move {
    loop {
        if let Err(e) = system.perform_maintenance().await {
            eprintln!("Maintenance error: {}", e);
        }
        tokio::time::sleep(Duration::from_secs(300)).await; // Every 5 minutes
    }
});
```

## Statistics and Monitoring

### get_statistics
```rust
pub async fn get_statistics(&mut self) -> Result<UnifiedStorageStats>
```

Get comprehensive system statistics.

**Example:**
```rust
let stats = system.get_statistics().await?;

println!("DHT Stats:");
println!("  Total nodes: {}", stats.dht_stats.total_nodes);
println!("  Network health: {:.2}", stats.dht_stats.network_health);

println!("Economic Stats:");
println!("  Total contracts: {}", stats.economic_stats.total_contracts);
println!("  Total value locked: {}", stats.economic_stats.total_value_locked);

println!("Storage Stats:");
println!("  Total uploads: {}", stats.storage_stats.total_uploads);
println!("  Storage used: {} bytes", stats.storage_stats.total_storage_used);
```

## Types Reference

### Core Types

```rust
// Primary identifiers
pub use lib_identity::NodeId;
pub type ContentHash = Hash;
pub type DhtKey = Hash;

// Storage tiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageTier {
    Hot,     // High performance, frequently accessed
    Warm,    // Balanced performance and cost
    Cold,    // Cost optimized, infrequently accessed
    Archive, // Long-term storage, lowest cost
}

// Access levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessLevel {
    Public,     // Anyone can access
    Private,    // Only owner can access
    Restricted, // Specific permissions required
}

// Encryption levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionLevel {
    None,               // No encryption
    Standard,           // AES-256
    HighSecurity,       // Enhanced encryption
    QuantumResistant,   // Post-quantum algorithms
}
```

### Request Types

#### UploadRequest
```rust
#[derive(Debug, Clone)]
pub struct UploadRequest {
    pub content: Vec<u8>,
    pub filename: String,
    pub mime_type: String,
    pub description: String,
    pub tags: Vec<String>,
    pub encrypt: bool,
    pub compress: bool,
    pub access_control: AccessControlSettings,
    pub storage_requirements: ContentStorageRequirements,
}
```

#### DownloadRequest
```rust
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    pub content_hash: ContentHash,
    pub requester: ZhtpIdentity,
    pub access_proof: Option<ZeroKnowledgeProof>,
}
```

## Error Handling

All API methods return `Result<T, anyhow::Error>`. Common error scenarios:

- **Storage Capacity Exceeded**: When trying to store more data than node capacity
- **Invalid Identity**: When identity verification fails
- **Budget Constraints**: When quote exceeds specified budget limits
- **Network Errors**: When DHT network operations fail
- **Proof Verification**: When zero-knowledge proofs are invalid
- **Contract Violations**: When storage contracts are breached

**Example Error Handling:**
```rust
match system.upload_content(request, identity).await {
    Ok(content_hash) => {
        println!("Upload successful: {}", hex::encode(content_hash.as_bytes()));
    }
    Err(e) => {
        eprintln!("Upload failed: {}", e);
        // Handle specific error types
        if e.to_string().contains("Storage capacity exceeded") {
            // Handle capacity issues
        } else if e.to_string().contains("Budget constraints") {
            // Handle budget issues
        }
    }
}
```

---

=======
# lib-storage API Reference

Complete API documentation for the ZHTP Unified Storage System.

##  Table of Contents

- [UnifiedStorageSystem](#unifiedstoragesystem) - Main system interface
- [Configuration](#configuration) - System configuration types
- [Storage Operations](#storage-operations) - Core storage functionality
- [Economic Features](#economic-features) - Contracts and payments
- [Identity Integration](#identity-integration) - Identity management
- [DHT Operations](#dht-operations) - Low-level DHT access
- [Types Reference](#types-reference) - Core data types

## UnifiedStorageSystem

The main entry point for all storage operations.

### Constructor

```rust
impl UnifiedStorageSystem {
    /// Create new unified storage system
    pub async fn new(config: UnifiedStorageConfig) -> Result<Self>
}
```

**Example:**
```rust
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};

let config = UnifiedStorageConfig::default();
let mut system = UnifiedStorageSystem::new(config).await?;
```

### Content Operations

#### upload_content
```rust
pub async fn upload_content(
    &mut self,
    request: UploadRequest,
    uploader: ZhtpIdentity,
) -> Result<ContentHash>
```

Upload content to the storage system with full economic integration.

**Parameters:**
- `request: UploadRequest` - Upload configuration and content
- `uploader: ZhtpIdentity` - Identity of the user uploading content

**Returns:** `ContentHash` - Unique identifier for the stored content

**Example:**
```rust
let upload_request = UploadRequest {
    content: b"Hello, ZHTP Storage!".to_vec(),
    filename: "hello.txt".to_string(),
    mime_type: "text/plain".to_string(),
    description: "Test file".to_string(),
    tags: vec!["test".to_string()],
    encrypt: true,
    compress: false,
    access_control: AccessControlSettings {
        public_read: false,
        read_permissions: vec![],
        write_permissions: vec![],
        expires_at: None,
    },
    storage_requirements: ContentStorageRequirements {
        duration_days: 30,
        quality_requirements: QualityRequirements::default(),
        budget_constraints: BudgetConstraints::default(),
    },
};

let content_hash = system.upload_content(upload_request, uploader_identity).await?;
```

#### download_content
```rust
pub async fn download_content(
    &mut self,
    request: DownloadRequest,
) -> Result<Vec<u8>>
```

Download content with access control verification.

**Parameters:**
- `request: DownloadRequest` - Download request with access credentials

**Returns:** `Vec<u8>` - The downloaded content data

**Example:**
```rust
let download_request = DownloadRequest {
    content_hash,
    requester: requester_identity,
    access_proof: None, // Optional for public content
};

let content = system.download_content(download_request).await?;
```

#### search_content
```rust
pub async fn search_content(
    &self,
    query: SearchQuery,
    requester: ZhtpIdentity,
) -> Result<Vec<ContentMetadata>>
```

Search for content across the storage system.

**Example:**
```rust
let search_query = SearchQuery {
    keywords: vec!["test".to_string()],
    content_type: Some("text/plain".to_string()),
    tags: vec!["test".to_string()],
    owner: None,
    date_range: None,
    size_range: None,
    limit: 10,
};

let results = system.search_content(search_query, requester_identity).await?;
```

### Erasure Coding Operations

#### store_with_erasure_coding
```rust
pub async fn store_with_erasure_coding(
    &mut self,
    data: Vec<u8>,
    storage_requirements: StorageRequirements,
    uploader: ZhtpIdentity,
) -> Result<ContentHash>
```

Store data with Reed-Solomon erasure coding for enhanced reliability.

**Example:**
```rust
let data = b"Important data requiring high reliability".to_vec();
let requirements = StorageRequirements {
    duration_days: 365,
    quality_requirements: QualityRequirements {
        min_uptime: 0.99,
        max_response_time: 2000,
        min_replication: 6,
        data_integrity_level: 0.999,
    },
    budget_constraints: BudgetConstraints::default(),
    // ... other fields
};

let content_hash = system.store_with_erasure_coding(
    data, 
    requirements, 
    uploader_identity
).await?;
```

## Configuration

### UnifiedStorageConfig

Main configuration structure for the storage system.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedStorageConfig {
    pub node_id: NodeId,
    pub addresses: Vec<String>,
    pub economic_config: EconomicManagerConfig,
    pub storage_config: StorageConfig,
    pub erasure_config: ErasureConfig,
}
```

**Default Configuration:**
```rust
let config = UnifiedStorageConfig {
    node_id: Hash::from_bytes(&rand::random::<[u8; 32]>()),
    addresses: vec!["127.0.0.1:33445".to_string()],
    economic_config: EconomicManagerConfig::default(),
    storage_config: StorageConfig {
        max_storage_size: 100_000_000_000, // 100GB
        default_tier: StorageTier::Hot,
        enable_compression: true,
        enable_encryption: true,
    },
    erasure_config: ErasureConfig {
        data_shards: 4,
        parity_shards: 2,
    },
};
```

### EconomicManagerConfig

Configuration for the economic incentive system.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicManagerConfig {
    pub default_duration_days: u32,
    pub base_price_per_gb_day: u64,
    pub enable_escrow: bool,
    pub quality_premium_rate: f64,
    pub network_fee_rate: f64,
    pub escrow_fee_rate: f64,
}
```

## Economic Features

### get_storage_quote
```rust
pub async fn get_storage_quote(
    &mut self, 
    request: EconomicStorageRequest
) -> Result<EconomicQuote>
```

Get a pricing quote for storage services.

**Example:**
```rust
let request = EconomicStorageRequest {
    content: data.clone(),
    filename: "important_file.pdf".to_string(),
    content_type: "application/pdf".to_string(),
    description: "Important document".to_string(),
    preferred_tier: StorageTier::Warm,
    requirements: StorageRequirements {
        duration_days: 90,
        quality_requirements: QualityRequirements {
            min_uptime: 0.95,
            max_response_time: 5000,
            min_replication: 3,
            data_integrity_level: 0.99,
        },
        budget_constraints: BudgetConstraints {
            max_total_cost: 10000, // 10,000 SOV tokens
            max_cost_per_gb_day: 150,
            preferred_payment_schedule: PaymentSchedule::Upfront,
        },
        geographic_preferences: vec!["US".to_string(), "EU".to_string()],
        replication_factor: 3,
    },
    payment_preferences: PaymentPreferences::default(),
    requester: requester_identity,
};

let quote = system.get_storage_quote(request).await?;
println!("Total cost: {} SOV tokens", quote.total_cost);
```

### EconomicQuote Structure

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicQuote {
    pub quote_id: String,
    pub total_cost: u64,
    pub cost_per_gb_day: u64,
    pub duration_days: u32,
    pub recommended_nodes: Vec<Hash>,
    pub estimated_quality: QualityMetrics,
    pub valid_until: u64,
    pub terms: Vec<String>,
}
```

## Identity Integration

### store_identity_credentials
```rust
pub async fn store_identity_credentials(
    &mut self,
    identity_id: &lib_identity::IdentityId,
    credentials: &lib_identity::ZhtpIdentity,
    passphrase: &str,
) -> Result<()>
```

Store identity credentials securely in the unified storage system.

**Example:**
```rust
let identity_id = IdentityId::from_bytes(&[1u8; 32]);
let passphrase = "secure_passphrase_123";

system.store_identity_credentials(
    &identity_id, 
    &user_identity, 
    passphrase
).await?;
```

### retrieve_identity_credentials
```rust
pub async fn retrieve_identity_credentials(
    &mut self,
    identity_id: &lib_identity::IdentityId,
    passphrase: &str,
) -> Result<lib_identity::ZhtpIdentity>
```

Retrieve previously stored identity credentials.

**Example:**
```rust
let retrieved_identity = system.retrieve_identity_credentials(
    &identity_id, 
    passphrase
).await?;

println!("Retrieved identity: {}", retrieved_identity.id);
```

## DHT Operations

### add_peer
```rust
pub async fn add_peer(&mut self, peer_address: String) -> Result<()>
```

Add a peer to the DHT network with their identity-derived NodeId.

**Example:**
```rust
let peer_node_id = lib_storage::NodeId::from_bytes(rand::random::<[u8; 32]>());
system.add_peer("192.168.1.100:33445".to_string(), peer_node_id).await?;
```

### perform_maintenance
```rust
pub async fn perform_maintenance(&mut self) -> Result<()>
```

Perform system maintenance including contract monitoring and cleanup.

**Example:**
```rust
// Run maintenance periodically
tokio::spawn(async move {
    loop {
        if let Err(e) = system.perform_maintenance().await {
            eprintln!("Maintenance error: {}", e);
        }
        tokio::time::sleep(Duration::from_secs(300)).await; // Every 5 minutes
    }
});
```

## Statistics and Monitoring

### get_statistics
```rust
pub async fn get_statistics(&mut self) -> Result<UnifiedStorageStats>
```

Get comprehensive system statistics.

**Example:**
```rust
let stats = system.get_statistics().await?;

println!("DHT Stats:");
println!("  Total nodes: {}", stats.dht_stats.total_nodes);
println!("  Network health: {:.2}", stats.dht_stats.network_health);

println!("Economic Stats:");
println!("  Total contracts: {}", stats.economic_stats.total_contracts);
println!("  Total value locked: {}", stats.economic_stats.total_value_locked);

println!("Storage Stats:");
println!("  Total uploads: {}", stats.storage_stats.total_uploads);
println!("  Storage used: {} bytes", stats.storage_stats.total_storage_used);
```

## Types Reference

### Core Types

```rust
// Primary identifiers
pub use lib_identity::NodeId;
pub type ContentHash = Hash;
pub type DhtKey = Hash;

// Storage tiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageTier {
    Hot,     // High performance, frequently accessed
    Warm,    // Balanced performance and cost
    Cold,    // Cost optimized, infrequently accessed
    Archive, // Long-term storage, lowest cost
}

// Access levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessLevel {
    Public,     // Anyone can access
    Private,    // Only owner can access
    Restricted, // Specific permissions required
}

// Encryption levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionLevel {
    None,               // No encryption
    Standard,           // AES-256
    HighSecurity,       // Enhanced encryption
    QuantumResistant,   // Post-quantum algorithms
}
```

### Request Types

#### UploadRequest
```rust
#[derive(Debug, Clone)]
pub struct UploadRequest {
    pub content: Vec<u8>,
    pub filename: String,
    pub mime_type: String,
    pub description: String,
    pub tags: Vec<String>,
    pub encrypt: bool,
    pub compress: bool,
    pub access_control: AccessControlSettings,
    pub storage_requirements: ContentStorageRequirements,
}
```

#### DownloadRequest
```rust
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    pub content_hash: ContentHash,
    pub requester: ZhtpIdentity,
    pub access_proof: Option<ZeroKnowledgeProof>,
}
```

## Error Handling

All API methods return `Result<T, anyhow::Error>`. Common error scenarios:

- **Storage Capacity Exceeded**: When trying to store more data than node capacity
- **Invalid Identity**: When identity verification fails
- **Budget Constraints**: When quote exceeds specified budget limits
- **Network Errors**: When DHT network operations fail
- **Proof Verification**: When zero-knowledge proofs are invalid
- **Contract Violations**: When storage contracts are breached

**Example Error Handling:**
```rust
match system.upload_content(request, identity).await {
    Ok(content_hash) => {
        println!("Upload successful: {}", hex::encode(content_hash.as_bytes()));
    }
    Err(e) => {
        eprintln!("Upload failed: {}", e);
        // Handle specific error types
        if e.to_string().contains("Storage capacity exceeded") {
            // Handle capacity issues
        } else if e.to_string().contains("Budget constraints") {
            // Handle budget issues
        }
    }
}
```

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
For more detailed examples and use cases, see the [Examples](../examples/) directory.
