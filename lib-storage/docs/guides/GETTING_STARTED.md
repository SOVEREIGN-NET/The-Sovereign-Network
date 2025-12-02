<<<<<<< HEAD
# Getting Started with ZHTP Unified Storage System

This guide will help you get started with the ZHTP Unified Storage System, from basic setup to advanced features. Whether you're storing simple files or building complex distributed applications, this guide covers everything you need to know.

##  Quick Start

### Prerequisites

- **Rust**: Version 1.70+ with 2021 edition support
- **Tokio**: For async runtime (included in dependencies)
- **ZHTP Libraries**: `lib-crypto`, `lib-proofs`, `lib-identity` (included as path dependencies)

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-storage = { path = "path/to/lib-storage" }
tokio = { version = "1.0", features = ["full"] }
```

### Basic Setup

```rust
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create default configuration
    let config = UnifiedStorageConfig::default();
    
    // Initialize storage system
    let mut storage = UnifiedStorageSystem::new(config).await?;
    
    println!("ZHTP Storage System initialized successfully!");
    Ok(())
}
```

##  Basic Storage Operations

### Storing Content

```rust
use lib_storage::{UploadRequest, AccessControlSettings, ContentStorageRequirements, 
                  QualityRequirements, BudgetConstraints};

async fn store_document(
    storage: &mut UnifiedStorageSystem,
    data: Vec<u8>,
    uploader: ZhtpIdentity
) -> Result<ContentHash, Box<dyn std::error::Error>> {
    
    let upload_request = UploadRequest {
        content: data,
        filename: "my_document.pdf".to_string(),
        mime_type: "application/pdf".to_string(),
        description: "Important document".to_string(),
        tags: vec!["important".to_string(), "document".to_string()],
        encrypt: true,  // Enable encryption
        compress: true, // Enable compression
        access_control: AccessControlSettings {
            public_read: false,
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 365, // Store for 1 year
            quality_requirements: QualityRequirements {
                min_uptime: 0.95,
                max_response_time: 5000,
                min_replication: 3,
                data_integrity_level: 0.99,
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 50000, // 50,000 ZHTP tokens
                max_cost_per_gb_day: 200,
                preferred_payment_schedule: PaymentSchedule::Upfront,
            },
        },
    };

    let content_hash = storage.upload_content(upload_request, uploader).await?;
    println!("Content stored with hash: {}", hex::encode(content_hash.as_bytes()));
    
    Ok(content_hash)
}
```

### Retrieving Content

```rust
use lib_storage::DownloadRequest;

async fn retrieve_document(
    storage: &mut UnifiedStorageSystem,
    content_hash: ContentHash,
    requester: ZhtpIdentity
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    
    let download_request = DownloadRequest {
        content_hash,
        requester,
        access_proof: None, // Not needed for content you own
    };

    let content = storage.download_content(download_request).await?;
    println!("Retrieved {} bytes", content.len());
    
    Ok(content)
}
```

### Searching Content

```rust
use lib_storage::SearchQuery;

async fn search_documents(
    storage: &UnifiedStorageSystem,
    requester: ZhtpIdentity
) -> Result<Vec<ContentMetadata>, Box<dyn std::error::Error>> {
    
    let search_query = SearchQuery {
        keywords: vec!["important".to_string()],
        content_type: Some("application/pdf".to_string()),
        tags: vec!["document".to_string()],
        owner: None,
        date_range: None,
        size_range: None,
        limit: 10,
    };

    let results = storage.search_content(search_query, requester).await?;
    
    for result in &results {
        println!("Found: {} ({} bytes)", result.filename, result.size);
    }
    
    Ok(results)
}
```

##  Economic Storage Features

### Getting Storage Quotes

```rust
use lib_storage::{EconomicStorageRequest, StorageRequirements, PaymentPreferences};

async fn get_storage_quote(
    storage: &mut UnifiedStorageSystem,
    data: Vec<u8>,
    requester: ZhtpIdentity
) -> Result<EconomicQuote, Box<dyn std::error::Error>> {
    
    let request = EconomicStorageRequest {
        content: data,
        filename: "enterprise_data.zip".to_string(),
        content_type: "application/zip".to_string(),
        description: "Enterprise backup data".to_string(),
        preferred_tier: StorageTier::Cold, // Cost-optimized tier
        requirements: StorageRequirements {
            duration_days: 2555, // ~7 years
            quality_requirements: QualityRequirements {
                min_uptime: 0.99,
                max_response_time: 30000, // 30 seconds OK for cold storage
                min_replication: 5,
                data_integrity_level: 0.999,
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 1000000, // 1M ZHTP tokens
                max_cost_per_gb_day: 50,  // Lower cost for cold storage
                preferred_payment_schedule: PaymentSchedule::Annual,
            },
            geographic_preferences: vec!["US".to_string(), "EU".to_string()],
            replication_factor: 5,
        },
        payment_preferences: PaymentPreferences {
            escrow_preferences: EscrowPreferences {
                use_escrow: true,
                release_schedule: ReleaseSchedule::Milestone,
                dispute_resolution: DisputeResolution::Arbitration,
            },
            payment_method: PaymentMethod::ZhtpTokens,
            auto_renewal: true,
        },
        requester,
    };

    let quote = storage.get_storage_quote(request).await?;
    
    println!("Storage Quote:");
    println!("  Total cost: {} ZHTP tokens", quote.total_cost);
    println!("  Cost per GB/day: {} tokens", quote.cost_per_gb_day);
    println!("  Duration: {} days", quote.duration_days);
    println!("  Recommended nodes: {}", quote.recommended_nodes.len());
    println!("  Expected quality score: {:.2}", quote.estimated_quality.overall_score);
    
    Ok(quote)
}
```

### High-Reliability Storage with Erasure Coding

```rust
async fn store_critical_data(
    storage: &mut UnifiedStorageSystem,
    critical_data: Vec<u8>,
    uploader: ZhtpIdentity
) -> Result<ContentHash, Box<dyn std::error::Error>> {
    
    // High-reliability requirements for critical data
    let requirements = StorageRequirements {
        duration_days: 3650, // 10 years
        quality_requirements: QualityRequirements {
            min_uptime: 0.999,     // 99.9% uptime
            max_response_time: 2000, // 2 seconds max
            min_replication: 8,     // 8 replicas
            data_integrity_level: 0.9999, // 99.99% integrity
        },
        budget_constraints: BudgetConstraints {
            max_total_cost: 5000000, // 5M ZHTP tokens
            max_cost_per_gb_day: 500, // Premium pricing acceptable
            preferred_payment_schedule: PaymentSchedule::Monthly,
        },
        geographic_preferences: vec![
            "US".to_string(), 
            "EU".to_string(), 
            "Asia".to_string()
        ],
        replication_factor: 8,
    };

    // Store with Reed-Solomon erasure coding for maximum reliability
    let content_hash = storage.store_with_erasure_coding(
        critical_data, 
        requirements, 
        uploader
    ).await?;
    
    println!("Critical data stored with erasure coding: {}", 
             hex::encode(content_hash.as_bytes()));
    
    Ok(content_hash)
}
```

##  Identity Integration

### Storing Identity Credentials

```rust
use lib_identity::{IdentityId, ZhtpIdentity};

async fn store_identity(
    storage: &mut UnifiedStorageSystem,
    identity: ZhtpIdentity,
    passphrase: &str
) -> Result<(), Box<dyn std::error::Error>> {
    
    let identity_id = identity.id.clone();
    
    // Store identity credentials securely
    storage.store_identity_credentials(
        &identity_id,
        &identity,
        passphrase
    ).await?;
    
    println!("Identity stored securely");
    
    // Verify storage
    let exists = storage.identity_exists(&identity_id).await?;
    println!("Identity exists in storage: {}", exists);
    
    Ok(())
}
```

### Retrieving Identity Credentials

```rust
async fn retrieve_identity(
    storage: &mut UnifiedStorageSystem,
    identity_id: &IdentityId,
    passphrase: &str
) -> Result<ZhtpIdentity, Box<dyn std::error::Error>> {
    
    let identity = storage.retrieve_identity_credentials(
        identity_id,
        passphrase
    ).await?;
    
    println!("Retrieved identity: {}", identity.id);
    
    Ok(identity)
}
```

##  Network Operations

### Adding Network Peers

```rust
async fn setup_network(
    storage: &mut UnifiedStorageSystem
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Add known peers to the network
    let peers = vec![
        "192.168.1.100:33445".to_string(),
        "10.0.0.50:33445".to_string(),
        "peer.example.com:33445".to_string(),
    ];
    
    for peer in peers {
        // In real code, derive NodeId from peer's identity
        let peer_node_id = lib_storage::NodeId::from_bytes(rand::random::<[u8; 32]>());
        match storage.add_peer(peer.clone(), peer_node_id).await {
            Ok(_) => println!("Added peer: {}", peer),
            Err(e) => eprintln!("Failed to add peer {}: {}", peer, e),
        }
    }
    
    Ok(())
}
```

### System Monitoring

```rust
async fn monitor_system(
    storage: &mut UnifiedStorageSystem
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Get comprehensive system statistics
    let stats = storage.get_statistics().await?;
    
    println!("System Statistics:");
    println!("=================");
    
    println!("DHT Network:");
    println!("  Total nodes: {}", stats.dht_stats.total_nodes);
    println!("  Active connections: {}", stats.dht_stats.total_connections);
    println!("  Messages sent: {}", stats.dht_stats.total_messages_sent);
    println!("  Messages received: {}", stats.dht_stats.total_messages_received);
    println!("  Network health: {:.2}%", stats.dht_stats.network_health * 100.0);
    
    println!("\\nEconomic Activity:");
    println!("  Total contracts: {}", stats.economic_stats.total_contracts);
    println!("  Value locked: {} ZHTP", stats.economic_stats.total_value_locked);
    println!("  Average contract value: {} ZHTP", stats.economic_stats.average_contract_value);
    println!("  Total penalties: {} ZHTP", stats.economic_stats.total_penalties);
    println!("  Total rewards: {} ZHTP", stats.economic_stats.total_rewards);
    
    println!("\\nStorage Usage:");
    println!("  Total content items: {}", stats.storage_stats.total_content_count);
    println!("  Storage used: {} bytes", stats.storage_stats.total_storage_used);
    println!("  Total uploads: {}", stats.storage_stats.total_uploads);
    println!("  Total downloads: {}", stats.storage_stats.total_downloads);
    
    Ok(())
}
```

### Maintenance Operations

```rust
async fn run_maintenance(
    storage: &mut UnifiedStorageSystem
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("Starting system maintenance...");
    
    // Perform comprehensive maintenance
    storage.perform_maintenance().await?;
    
    println!("Maintenance completed successfully");
    
    Ok(())
}

// Run maintenance periodically
async fn start_maintenance_loop(mut storage: UnifiedStorageSystem) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
    
    loop {
        interval.tick().await;
        
        if let Err(e) = run_maintenance(&mut storage).await {
            eprintln!("Maintenance error: {}", e);
        }
    }
}
```

##  Complete Example Application

Here's a complete example that demonstrates the main features:

```rust
use lib_storage::*;
use lib_identity::*;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage system
    let config = UnifiedStorageConfig::default();
    let mut storage = UnifiedStorageSystem::new(config).await?;
    
    // Create test identity
    let identity = create_test_identity();
    
    // Store identity credentials
    let passphrase = "secure_passphrase_123";
    storage.store_identity_credentials(
        &identity.id,
        &identity,
        passphrase
    ).await?;
    
    // Add network peers (with their identity-derived NodeIds)
    let peer_node_id = lib_storage::NodeId::from_bytes(rand::random::<[u8; 32]>());
    storage.add_peer("127.0.0.1:33446".to_string(), peer_node_id).await?;
    
    // Store some test content
    let test_data = b"Hello, ZHTP Storage System!".to_vec();
    let upload_request = create_upload_request(test_data.clone());
    let content_hash = storage.upload_content(upload_request, identity.clone()).await?;
    
    println!("Content stored with hash: {}", hex::encode(content_hash.as_bytes()));
    
    // Retrieve the content
    let download_request = DownloadRequest {
        content_hash,
        requester: identity.clone(),
        access_proof: None,
    };
    
    let retrieved_data = storage.download_content(download_request).await?;
    assert_eq!(test_data, retrieved_data);
    
    println!("Content retrieved successfully!");
    
    // Get storage quote for economic features
    let economic_request = create_economic_request(test_data, identity.clone());
    let quote = storage.get_storage_quote(economic_request).await?;
    
    println!("Storage quote received:");
    println!("  Total cost: {} ZHTP tokens", quote.total_cost);
    println!("  Quality score: {:.2}", quote.estimated_quality.overall_score);
    
    // Start maintenance loop in background
    let storage_clone = storage.clone();
    tokio::spawn(async move {
        start_maintenance_loop(storage_clone).await;
    });
    
    // Monitor system statistics
    let stats = storage.get_statistics().await?;
    println!("\\nSystem initialized with {} DHT nodes", stats.dht_stats.total_nodes);
    
    Ok(())
}

fn create_test_identity() -> ZhtpIdentity {
    // Implementation would create a proper ZHTP identity
    // This is simplified for the example
    unimplemented!("Create proper ZHTP identity using lib-identity")
}

fn create_upload_request(data: Vec<u8>) -> UploadRequest {
    UploadRequest {
        content: data,
        filename: "test.txt".to_string(),
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
    }
}

fn create_economic_request(data: Vec<u8>, requester: ZhtpIdentity) -> EconomicStorageRequest {
    EconomicStorageRequest {
        content: data,
        filename: "economic_test.txt".to_string(),
        content_type: "text/plain".to_string(),
        description: "Economic storage test".to_string(),
        preferred_tier: StorageTier::Hot,
        requirements: StorageRequirements::default(),
        payment_preferences: PaymentPreferences::default(),
        requester,
    }
}
```

##  Configuration Best Practices

### Production Configuration

```rust
let config = UnifiedStorageConfig {
    node_id: Hash::from_bytes(&your_node_key),
    addresses: vec!["0.0.0.0:33445".to_string()], // Bind to all interfaces
    economic_config: EconomicManagerConfig {
        default_duration_days: 30,
        base_price_per_gb_day: 100,
        enable_escrow: true,
        quality_premium_rate: 0.15, // 15% quality premium
        network_fee_rate: 0.05,     // 5% network fees
        escrow_fee_rate: 0.02,      // 2% escrow fees
    },
    storage_config: StorageConfig {
        max_storage_size: 1_000_000_000_000, // 1TB
        default_tier: StorageTier::Warm,
        enable_compression: true,
        enable_encryption: true,
    },
    erasure_config: ErasureConfig {
        data_shards: 6,   // More shards for production
        parity_shards: 3, // Higher redundancy
    },
};
```

### Development Configuration

```rust
let config = UnifiedStorageConfig {
    node_id: Hash::from_bytes(&test_key),
    addresses: vec!["127.0.0.1:33445".to_string()], // Localhost only
    economic_config: EconomicManagerConfig {
        base_price_per_gb_day: 1, // Very low cost for testing
        enable_escrow: false,     // Simplified for development
        quality_premium_rate: 0.0,
        network_fee_rate: 0.0,
        escrow_fee_rate: 0.0,
    },
    storage_config: StorageConfig {
        max_storage_size: 100_000_000, // 100MB for testing
        default_tier: StorageTier::Hot,
        enable_compression: false,      // Disabled for easier debugging
        enable_encryption: false,       // Disabled for easier debugging
    },
    erasure_config: ErasureConfig {
        data_shards: 2,   // Minimal for testing
        parity_shards: 1,
    },
};
```

##  Error Handling

### Common Error Patterns

```rust
use anyhow::Result;

async fn robust_storage_operation(
    storage: &mut UnifiedStorageSystem,
    data: Vec<u8>,
    identity: ZhtpIdentity
) -> Result<ContentHash> {
    
    let upload_request = create_upload_request(data.clone());
    
    match storage.upload_content(upload_request, identity).await {
        Ok(content_hash) => {
            println!("Upload successful: {}", hex::encode(content_hash.as_bytes()));
            Ok(content_hash)
        }
        Err(e) => {
            eprintln!("Upload failed: {}", e);
            
            // Handle specific error types
            let error_msg = e.to_string();
            if error_msg.contains("Storage capacity exceeded") {
                eprintln!("Storage full - consider using different tier or cleaning up");
            } else if error_msg.contains("Budget constraints") {
                eprintln!("Cost too high - adjust budget or requirements");
            } else if error_msg.contains("Network") {
                eprintln!("Network error - check connectivity and try again");
            }
            
            Err(e)
        }
    }
}
```

## 📚 Next Steps

Now that you have the basics working, explore these advanced topics:

1. **[Economic Features Guide](ECONOMIC_FEATURES.md)** - Deep dive into storage contracts and payments
2. **[Zero-Knowledge Features](ZERO_KNOWLEDGE.md)** - Privacy-preserving storage operations
3. **[Identity Integration](IDENTITY_INTEGRATION.md)** - Advanced identity management
4. **[Smart Contracts](../examples/smart_contracts.md)** - DHT-based smart contract deployment

For production deployments, see:
- **[Performance Tuning](PERFORMANCE_TUNING.md)** - Optimize for your use case
- **[Security Best Practices](SECURITY.md)** - Secure deployment guidelines
- **[Monitoring and Alerting](MONITORING.md)** - Production monitoring setup

---

=======
# Getting Started with ZHTP Unified Storage System

This guide will help you get started with the ZHTP Unified Storage System, from basic setup to advanced features. Whether you're storing simple files or building complex distributed applications, this guide covers everything you need to know.

##  Quick Start

### Prerequisites

- **Rust**: Version 1.70+ with 2021 edition support
- **Tokio**: For async runtime (included in dependencies)
- **ZHTP Libraries**: `lib-crypto`, `lib-proofs`, `lib-identity` (included as path dependencies)

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-storage = { path = "path/to/lib-storage" }
tokio = { version = "1.0", features = ["full"] }
```

### Basic Setup

```rust
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create default configuration
    let config = UnifiedStorageConfig::default();
    
    // Initialize storage system
    let mut storage = UnifiedStorageSystem::new(config).await?;
    
    println!("ZHTP Storage System initialized successfully!");
    Ok(())
}
```

##  Basic Storage Operations

### Storing Content

```rust
use lib_storage::{UploadRequest, AccessControlSettings, ContentStorageRequirements, 
                  QualityRequirements, BudgetConstraints};

async fn store_document(
    storage: &mut UnifiedStorageSystem,
    data: Vec<u8>,
    uploader: ZhtpIdentity
) -> Result<ContentHash, Box<dyn std::error::Error>> {
    
    let upload_request = UploadRequest {
        content: data,
        filename: "my_document.pdf".to_string(),
        mime_type: "application/pdf".to_string(),
        description: "Important document".to_string(),
        tags: vec!["important".to_string(), "document".to_string()],
        encrypt: true,  // Enable encryption
        compress: true, // Enable compression
        access_control: AccessControlSettings {
            public_read: false,
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 365, // Store for 1 year
            quality_requirements: QualityRequirements {
                min_uptime: 0.95,
                max_response_time: 5000,
                min_replication: 3,
                data_integrity_level: 0.99,
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 50000, // 50,000 ZHTP tokens
                max_cost_per_gb_day: 200,
                preferred_payment_schedule: PaymentSchedule::Upfront,
            },
        },
    };

    let content_hash = storage.upload_content(upload_request, uploader).await?;
    println!("Content stored with hash: {}", hex::encode(content_hash.as_bytes()));
    
    Ok(content_hash)
}
```

### Retrieving Content

```rust
use lib_storage::DownloadRequest;

async fn retrieve_document(
    storage: &mut UnifiedStorageSystem,
    content_hash: ContentHash,
    requester: ZhtpIdentity
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    
    let download_request = DownloadRequest {
        content_hash,
        requester,
        access_proof: None, // Not needed for content you own
    };

    let content = storage.download_content(download_request).await?;
    println!("Retrieved {} bytes", content.len());
    
    Ok(content)
}
```

### Searching Content

```rust
use lib_storage::SearchQuery;

async fn search_documents(
    storage: &UnifiedStorageSystem,
    requester: ZhtpIdentity
) -> Result<Vec<ContentMetadata>, Box<dyn std::error::Error>> {
    
    let search_query = SearchQuery {
        keywords: vec!["important".to_string()],
        content_type: Some("application/pdf".to_string()),
        tags: vec!["document".to_string()],
        owner: None,
        date_range: None,
        size_range: None,
        limit: 10,
    };

    let results = storage.search_content(search_query, requester).await?;
    
    for result in &results {
        println!("Found: {} ({} bytes)", result.filename, result.size);
    }
    
    Ok(results)
}
```

##  Economic Storage Features

### Getting Storage Quotes

```rust
use lib_storage::{EconomicStorageRequest, StorageRequirements, PaymentPreferences};

async fn get_storage_quote(
    storage: &mut UnifiedStorageSystem,
    data: Vec<u8>,
    requester: ZhtpIdentity
) -> Result<EconomicQuote, Box<dyn std::error::Error>> {
    
    let request = EconomicStorageRequest {
        content: data,
        filename: "enterprise_data.zip".to_string(),
        content_type: "application/zip".to_string(),
        description: "Enterprise backup data".to_string(),
        preferred_tier: StorageTier::Cold, // Cost-optimized tier
        requirements: StorageRequirements {
            duration_days: 2555, // ~7 years
            quality_requirements: QualityRequirements {
                min_uptime: 0.99,
                max_response_time: 30000, // 30 seconds OK for cold storage
                min_replication: 5,
                data_integrity_level: 0.999,
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 1000000, // 1M ZHTP tokens
                max_cost_per_gb_day: 50,  // Lower cost for cold storage
                preferred_payment_schedule: PaymentSchedule::Annual,
            },
            geographic_preferences: vec!["US".to_string(), "EU".to_string()],
            replication_factor: 5,
        },
        payment_preferences: PaymentPreferences {
            escrow_preferences: EscrowPreferences {
                use_escrow: true,
                release_schedule: ReleaseSchedule::Milestone,
                dispute_resolution: DisputeResolution::Arbitration,
            },
            payment_method: PaymentMethod::ZhtpTokens,
            auto_renewal: true,
        },
        requester,
    };

    let quote = storage.get_storage_quote(request).await?;
    
    println!("Storage Quote:");
    println!("  Total cost: {} ZHTP tokens", quote.total_cost);
    println!("  Cost per GB/day: {} tokens", quote.cost_per_gb_day);
    println!("  Duration: {} days", quote.duration_days);
    println!("  Recommended nodes: {}", quote.recommended_nodes.len());
    println!("  Expected quality score: {:.2}", quote.estimated_quality.overall_score);
    
    Ok(quote)
}
```

### High-Reliability Storage with Erasure Coding

```rust
async fn store_critical_data(
    storage: &mut UnifiedStorageSystem,
    critical_data: Vec<u8>,
    uploader: ZhtpIdentity
) -> Result<ContentHash, Box<dyn std::error::Error>> {
    
    // High-reliability requirements for critical data
    let requirements = StorageRequirements {
        duration_days: 3650, // 10 years
        quality_requirements: QualityRequirements {
            min_uptime: 0.999,     // 99.9% uptime
            max_response_time: 2000, // 2 seconds max
            min_replication: 8,     // 8 replicas
            data_integrity_level: 0.9999, // 99.99% integrity
        },
        budget_constraints: BudgetConstraints {
            max_total_cost: 5000000, // 5M ZHTP tokens
            max_cost_per_gb_day: 500, // Premium pricing acceptable
            preferred_payment_schedule: PaymentSchedule::Monthly,
        },
        geographic_preferences: vec![
            "US".to_string(), 
            "EU".to_string(), 
            "Asia".to_string()
        ],
        replication_factor: 8,
    };

    // Store with Reed-Solomon erasure coding for maximum reliability
    let content_hash = storage.store_with_erasure_coding(
        critical_data, 
        requirements, 
        uploader
    ).await?;
    
    println!("Critical data stored with erasure coding: {}", 
             hex::encode(content_hash.as_bytes()));
    
    Ok(content_hash)
}
```

##  Identity Integration

### Storing Identity Credentials

```rust
use lib_identity::{IdentityId, ZhtpIdentity};

async fn store_identity(
    storage: &mut UnifiedStorageSystem,
    identity: ZhtpIdentity,
    passphrase: &str
) -> Result<(), Box<dyn std::error::Error>> {
    
    let identity_id = identity.id.clone();
    
    // Store identity credentials securely
    storage.store_identity_credentials(
        &identity_id,
        &identity,
        passphrase
    ).await?;
    
    println!("Identity stored securely");
    
    // Verify storage
    let exists = storage.identity_exists(&identity_id).await?;
    println!("Identity exists in storage: {}", exists);
    
    Ok(())
}
```

### Retrieving Identity Credentials

```rust
async fn retrieve_identity(
    storage: &mut UnifiedStorageSystem,
    identity_id: &IdentityId,
    passphrase: &str
) -> Result<ZhtpIdentity, Box<dyn std::error::Error>> {
    
    let identity = storage.retrieve_identity_credentials(
        identity_id,
        passphrase
    ).await?;
    
    println!("Retrieved identity: {}", identity.id);
    
    Ok(identity)
}
```

##  Network Operations

### Adding Network Peers

```rust
async fn setup_network(
    storage: &mut UnifiedStorageSystem
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Add known peers to the network
    let peers = vec![
        "192.168.1.100:33445".to_string(),
        "10.0.0.50:33445".to_string(),
        "peer.example.com:33445".to_string(),
    ];
    
    for peer in peers {
        // In real code, derive NodeId from peer's identity
        let peer_node_id = lib_storage::NodeId::from_bytes(rand::random::<[u8; 32]>());
        match storage.add_peer(peer.clone(), peer_node_id).await {
            Ok(_) => println!("Added peer: {}", peer),
            Err(e) => eprintln!("Failed to add peer {}: {}", peer, e),
        }
    }
    
    Ok(())
}
```

### System Monitoring

```rust
async fn monitor_system(
    storage: &mut UnifiedStorageSystem
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Get comprehensive system statistics
    let stats = storage.get_statistics().await?;
    
    println!("System Statistics:");
    println!("=================");
    
    println!("DHT Network:");
    println!("  Total nodes: {}", stats.dht_stats.total_nodes);
    println!("  Active connections: {}", stats.dht_stats.total_connections);
    println!("  Messages sent: {}", stats.dht_stats.total_messages_sent);
    println!("  Messages received: {}", stats.dht_stats.total_messages_received);
    println!("  Network health: {:.2}%", stats.dht_stats.network_health * 100.0);
    
    println!("\\nEconomic Activity:");
    println!("  Total contracts: {}", stats.economic_stats.total_contracts);
    println!("  Value locked: {} ZHTP", stats.economic_stats.total_value_locked);
    println!("  Average contract value: {} ZHTP", stats.economic_stats.average_contract_value);
    println!("  Total penalties: {} ZHTP", stats.economic_stats.total_penalties);
    println!("  Total rewards: {} ZHTP", stats.economic_stats.total_rewards);
    
    println!("\\nStorage Usage:");
    println!("  Total content items: {}", stats.storage_stats.total_content_count);
    println!("  Storage used: {} bytes", stats.storage_stats.total_storage_used);
    println!("  Total uploads: {}", stats.storage_stats.total_uploads);
    println!("  Total downloads: {}", stats.storage_stats.total_downloads);
    
    Ok(())
}
```

### Maintenance Operations

```rust
async fn run_maintenance(
    storage: &mut UnifiedStorageSystem
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("Starting system maintenance...");
    
    // Perform comprehensive maintenance
    storage.perform_maintenance().await?;
    
    println!("Maintenance completed successfully");
    
    Ok(())
}

// Run maintenance periodically
async fn start_maintenance_loop(mut storage: UnifiedStorageSystem) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
    
    loop {
        interval.tick().await;
        
        if let Err(e) = run_maintenance(&mut storage).await {
            eprintln!("Maintenance error: {}", e);
        }
    }
}
```

##  Complete Example Application

Here's a complete example that demonstrates the main features:

```rust
use lib_storage::*;
use lib_identity::*;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage system
    let config = UnifiedStorageConfig::default();
    let mut storage = UnifiedStorageSystem::new(config).await?;
    
    // Create test identity
    let identity = create_test_identity();
    
    // Store identity credentials
    let passphrase = "secure_passphrase_123";
    storage.store_identity_credentials(
        &identity.id,
        &identity,
        passphrase
    ).await?;
    
    // Add network peers (with their identity-derived NodeIds)
    let peer_node_id = lib_storage::NodeId::from_bytes(rand::random::<[u8; 32]>());
    storage.add_peer("127.0.0.1:33446".to_string(), peer_node_id).await?;
    
    // Store some test content
    let test_data = b"Hello, ZHTP Storage System!".to_vec();
    let upload_request = create_upload_request(test_data.clone());
    let content_hash = storage.upload_content(upload_request, identity.clone()).await?;
    
    println!("Content stored with hash: {}", hex::encode(content_hash.as_bytes()));
    
    // Retrieve the content
    let download_request = DownloadRequest {
        content_hash,
        requester: identity.clone(),
        access_proof: None,
    };
    
    let retrieved_data = storage.download_content(download_request).await?;
    assert_eq!(test_data, retrieved_data);
    
    println!("Content retrieved successfully!");
    
    // Get storage quote for economic features
    let economic_request = create_economic_request(test_data, identity.clone());
    let quote = storage.get_storage_quote(economic_request).await?;
    
    println!("Storage quote received:");
    println!("  Total cost: {} ZHTP tokens", quote.total_cost);
    println!("  Quality score: {:.2}", quote.estimated_quality.overall_score);
    
    // Start maintenance loop in background
    let storage_clone = storage.clone();
    tokio::spawn(async move {
        start_maintenance_loop(storage_clone).await;
    });
    
    // Monitor system statistics
    let stats = storage.get_statistics().await?;
    println!("\\nSystem initialized with {} DHT nodes", stats.dht_stats.total_nodes);
    
    Ok(())
}

fn create_test_identity() -> ZhtpIdentity {
    // Implementation would create a proper ZHTP identity
    // This is simplified for the example
    unimplemented!("Create proper ZHTP identity using lib-identity")
}

fn create_upload_request(data: Vec<u8>) -> UploadRequest {
    UploadRequest {
        content: data,
        filename: "test.txt".to_string(),
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
    }
}

fn create_economic_request(data: Vec<u8>, requester: ZhtpIdentity) -> EconomicStorageRequest {
    EconomicStorageRequest {
        content: data,
        filename: "economic_test.txt".to_string(),
        content_type: "text/plain".to_string(),
        description: "Economic storage test".to_string(),
        preferred_tier: StorageTier::Hot,
        requirements: StorageRequirements::default(),
        payment_preferences: PaymentPreferences::default(),
        requester,
    }
}
```

##  Configuration Best Practices

### Production Configuration

```rust
let config = UnifiedStorageConfig {
    node_id: Hash::from_bytes(&your_node_key),
    addresses: vec!["0.0.0.0:33445".to_string()], // Bind to all interfaces
    economic_config: EconomicManagerConfig {
        default_duration_days: 30,
        base_price_per_gb_day: 100,
        enable_escrow: true,
        quality_premium_rate: 0.15, // 15% quality premium
        network_fee_rate: 0.05,     // 5% network fees
        escrow_fee_rate: 0.02,      // 2% escrow fees
    },
    storage_config: StorageConfig {
        max_storage_size: 1_000_000_000_000, // 1TB
        default_tier: StorageTier::Warm,
        enable_compression: true,
        enable_encryption: true,
    },
    erasure_config: ErasureConfig {
        data_shards: 6,   // More shards for production
        parity_shards: 3, // Higher redundancy
    },
};
```

### Development Configuration

```rust
let config = UnifiedStorageConfig {
    node_id: Hash::from_bytes(&test_key),
    addresses: vec!["127.0.0.1:33445".to_string()], // Localhost only
    economic_config: EconomicManagerConfig {
        base_price_per_gb_day: 1, // Very low cost for testing
        enable_escrow: false,     // Simplified for development
        quality_premium_rate: 0.0,
        network_fee_rate: 0.0,
        escrow_fee_rate: 0.0,
    },
    storage_config: StorageConfig {
        max_storage_size: 100_000_000, // 100MB for testing
        default_tier: StorageTier::Hot,
        enable_compression: false,      // Disabled for easier debugging
        enable_encryption: false,       // Disabled for easier debugging
    },
    erasure_config: ErasureConfig {
        data_shards: 2,   // Minimal for testing
        parity_shards: 1,
    },
};
```

##  Error Handling

### Common Error Patterns

```rust
use anyhow::Result;

async fn robust_storage_operation(
    storage: &mut UnifiedStorageSystem,
    data: Vec<u8>,
    identity: ZhtpIdentity
) -> Result<ContentHash> {
    
    let upload_request = create_upload_request(data.clone());
    
    match storage.upload_content(upload_request, identity).await {
        Ok(content_hash) => {
            println!("Upload successful: {}", hex::encode(content_hash.as_bytes()));
            Ok(content_hash)
        }
        Err(e) => {
            eprintln!("Upload failed: {}", e);
            
            // Handle specific error types
            let error_msg = e.to_string();
            if error_msg.contains("Storage capacity exceeded") {
                eprintln!("Storage full - consider using different tier or cleaning up");
            } else if error_msg.contains("Budget constraints") {
                eprintln!("Cost too high - adjust budget or requirements");
            } else if error_msg.contains("Network") {
                eprintln!("Network error - check connectivity and try again");
            }
            
            Err(e)
        }
    }
}
```

## 📚 Next Steps

Now that you have the basics working, explore these advanced topics:

1. **[Economic Features Guide](ECONOMIC_FEATURES.md)** - Deep dive into storage contracts and payments
2. **[Zero-Knowledge Features](ZERO_KNOWLEDGE.md)** - Privacy-preserving storage operations
3. **[Identity Integration](IDENTITY_INTEGRATION.md)** - Advanced identity management
4. **[Smart Contracts](../examples/smart_contracts.md)** - DHT-based smart contract deployment

For production deployments, see:
- **[Performance Tuning](PERFORMANCE_TUNING.md)** - Optimize for your use case
- **[Security Best Practices](SECURITY.md)** - Secure deployment guidelines
- **[Monitoring and Alerting](MONITORING.md)** - Production monitoring setup

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
You now have everything you need to start building applications with the ZHTP Unified Storage System!