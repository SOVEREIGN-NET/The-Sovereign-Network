<<<<<<< HEAD
# Basic Usage Examples

This document provides practical examples of using the ZHTP Unified Storage System for common storage operations. These examples demonstrate the core functionality without complex economic features.

##  Simple File Storage

### Store and Retrieve a Text File

```rust
use lib_storage::*;
use lib_identity::ZhtpIdentity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage system
    let config = UnifiedStorageConfig::default();
    let mut storage = UnifiedStorageSystem::new(config).await?;
    
    // Create a simple text file
    let content = "Hello, ZHTP Storage System!\\nThis is a test file.".as_bytes().to_vec();
    let identity = create_user_identity()?;
    
    // Create upload request
    let upload_request = UploadRequest {
        content: content.clone(),
        filename: "hello.txt".to_string(),
        mime_type: "text/plain".to_string(),
        description: "Simple test file".to_string(),
        tags: vec!["test".to_string(), "hello".to_string()],
        encrypt: false,  // No encryption for this example
        compress: false, // No compression for this example
        access_control: AccessControlSettings {
            public_read: true, // Make it publicly readable
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 7, // Store for 1 week
            quality_requirements: QualityRequirements {
                min_uptime: 0.9,
                max_response_time: 10000, // 10 seconds
                min_replication: 3,
                data_integrity_level: 0.95,
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 1000, // 1000 ZHTP tokens
                max_cost_per_gb_day: 100,
                preferred_payment_schedule: PaymentSchedule::Upfront,
            },
        },
    };
    
    // Store the file
    let content_hash = storage.upload_content(upload_request, identity.clone()).await?;
    println!("File stored successfully!");
    println!("Content hash: {}", hex::encode(content_hash.as_bytes()));
    
    // Retrieve the file
    let download_request = DownloadRequest {
        content_hash,
        requester: identity,
        access_proof: None, // Not needed for public content
    };
    
    let retrieved_content = storage.download_content(download_request).await?;
    let retrieved_text = String::from_utf8(retrieved_content)?;
    
    println!("Retrieved content:");
    println!("{}", retrieved_text);
    
    // Verify content matches
    assert_eq!(content, retrieved_text.as_bytes());
    println!(" Content verification successful!");
    
    Ok(())
}
```

### Store Multiple Files with Different Configurations

```rust
async fn store_multiple_files(
    storage: &mut UnifiedStorageSystem,
    identity: ZhtpIdentity
) -> Result<Vec<ContentHash>, Box<dyn std::error::Error>> {
    
    let mut content_hashes = Vec::new();
    
    // Store a small text file
    let text_content = "Small text content".as_bytes().to_vec();
    let text_hash = store_file(
        storage,
        text_content,
        "small.txt",
        "text/plain",
        false, // No encryption
        false, // No compression
        identity.clone()
    ).await?;
    content_hashes.push(text_hash);
    
    // Store a larger binary file with compression
    let binary_content = vec![0u8; 10_000]; // 10KB of zeros (compresses well)
    let binary_hash = store_file(
        storage,
        binary_content,
        "data.bin",
        "application/octet-stream",
        false, // No encryption
        true,  // Enable compression
        identity.clone()
    ).await?;
    content_hashes.push(binary_hash);
    
    // Store an encrypted document
    let document_content = "Confidential document content".as_bytes().to_vec();
    let document_hash = store_file(
        storage,
        document_content,
        "confidential.doc",
        "application/msword",
        true,  // Enable encryption
        false, // No compression (encrypted data doesn't compress well)
        identity.clone()
    ).await?;
    content_hashes.push(document_hash);
    
    println!("Stored {} files successfully", content_hashes.len());
    
    Ok(content_hashes)
}

async fn store_file(
    storage: &mut UnifiedStorageSystem,
    content: Vec<u8>,
    filename: &str,
    mime_type: &str,
    encrypt: bool,
    compress: bool,
    identity: ZhtpIdentity
) -> Result<ContentHash, Box<dyn std::error::Error>> {
    
    let upload_request = UploadRequest {
        content,
        filename: filename.to_string(),
        mime_type: mime_type.to_string(),
        description: format!("File: {}", filename),
        tags: vec!["example".to_string()],
        encrypt,
        compress,
        access_control: AccessControlSettings {
            public_read: !encrypt, // Private if encrypted, public otherwise
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
    
    let content_hash = storage.upload_content(upload_request, identity).await?;
    println!("Stored {}: {}", filename, hex::encode(content_hash.as_bytes()));
    
    Ok(content_hash)
}
```

##  Content Search and Discovery

### Search for Files by Tags

```rust
async fn search_files_example(
    storage: &UnifiedStorageSystem,
    identity: ZhtpIdentity
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Search for all text files
    let text_query = SearchQuery {
        keywords: vec![],
        content_type: Some("text/plain".to_string()),
        tags: vec![],
        owner: None,
        date_range: None,
        size_range: None,
        limit: 10,
    };
    
    let text_results = storage.search_content(text_query, identity.clone()).await?;
    println!("Found {} text files", text_results.len());
    
    for result in &text_results {
        println!("   {} ({} bytes) - {}", 
                 result.filename, 
                 result.size, 
                 result.description);
    }
    
    // Search for files with specific tags
    let tagged_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec!["example".to_string()],
        owner: None,
        date_range: None,
        size_range: None,
        limit: 20,
    };
    
    let tagged_results = storage.search_content(tagged_query, identity.clone()).await?;
    println!("\\nFound {} files with 'example' tag", tagged_results.len());
    
    for result in &tagged_results {
        println!("  🏷️  {} - Tags: {:?}", result.filename, result.tags);
    }
    
    // Search by keyword in filename or description
    let keyword_query = SearchQuery {
        keywords: vec!["confidential".to_string()],
        content_type: None,
        tags: vec![],
        owner: None,
        date_range: None,
        size_range: None,
        limit: 5,
    };
    
    let keyword_results = storage.search_content(keyword_query, identity).await?;
    println!("\\nFound {} files matching 'confidential'", keyword_results.len());
    
    for result in &keyword_results {
        println!("   {} - {}", result.filename, result.description);
    }
    
    Ok(())
}
```

### Search with Size and Date Filters

```rust
use chrono::{DateTime, Utc, Duration};

async fn advanced_search_example(
    storage: &UnifiedStorageSystem,
    identity: ZhtpIdentity
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Search for large files (> 1MB)
    let large_files_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec![],
        owner: None,
        date_range: None,
        size_range: Some((1_000_000, u64::MAX)), // 1MB to unlimited
        limit: 10,
    };
    
    let large_results = storage.search_content(large_files_query, identity.clone()).await?;
    println!("Large files (>1MB): {}", large_results.len());
    
    // Search for recent files (last 7 days)
    let now = Utc::now().timestamp() as u64;
    let week_ago = (Utc::now() - Duration::days(7)).timestamp() as u64;
    
    let recent_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec![],
        owner: None,
        date_range: Some((week_ago, now)),
        size_range: None,
        limit: 20,
    };
    
    let recent_results = storage.search_content(recent_query, identity.clone()).await?;
    println!("Recent files (last 7 days): {}", recent_results.len());
    
    for result in &recent_results {
        let created_date = DateTime::from_timestamp(result.created_at as i64, 0)
            .unwrap_or_default();
        println!("  📅 {} - Created: {}", 
                 result.filename, 
                 created_date.format("%Y-%m-%d %H:%M:%S"));
    }
    
    // Search for files by specific owner
    let owner_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec![],
        owner: Some(identity.clone()),
        date_range: None,
        size_range: None,
        limit: 50,
    };
    
    let owned_results = storage.search_content(owner_query, identity).await?;
    println!("\\nFiles owned by user: {}", owned_results.len());
    
    Ok(())
}
```

##  Batch Operations

### Upload Multiple Files at Once

```rust
use std::collections::HashMap;

async fn batch_upload_example(
    storage: &mut UnifiedStorageSystem,
    identity: ZhtpIdentity
) -> Result<HashMap<String, ContentHash>, Box<dyn std::error::Error>> {
    
    // Prepare multiple files for upload
    let files = vec![
        ("file1.txt", "Content of file 1".as_bytes().to_vec(), "text/plain"),
        ("file2.txt", "Content of file 2".as_bytes().to_vec(), "text/plain"),
        ("data.json", r#"{"key": "value", "number": 42}"#.as_bytes().to_vec(), "application/json"),
        ("image.txt", "This would be image data".as_bytes().to_vec(), "image/png"),
    ];
    
    let mut upload_results = HashMap::new();
    let mut upload_tasks = Vec::new();
    
    // Create upload requests for all files
    for (filename, content, mime_type) in files {
        let upload_request = UploadRequest {
            content,
            filename: filename.to_string(),
            mime_type: mime_type.to_string(),
            description: format!("Batch upload: {}", filename),
            tags: vec!["batch".to_string(), "upload".to_string()],
            encrypt: false,
            compress: true, // Enable compression for all files
            access_control: AccessControlSettings {
                public_read: true,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 14, // 2 weeks
                quality_requirements: QualityRequirements::default(),
                budget_constraints: BudgetConstraints::default(),
            },
        };
        
        // Store the upload task for concurrent execution
        upload_tasks.push((filename.to_string(), upload_request));
    }
    
    // Execute uploads concurrently (in a scenario)
    // For this example, we'll do them sequentially
    for (filename, upload_request) in upload_tasks {
        match storage.upload_content(upload_request, identity.clone()).await {
            Ok(content_hash) => {
                println!(" Uploaded {}: {}", filename, hex::encode(content_hash.as_bytes()));
                upload_results.insert(filename, content_hash);
            }
            Err(e) => {
                eprintln!(" Failed to upload {}: {}", filename, e);
            }
        }
    }
    
    println!("Batch upload completed: {}/{} files successful", 
             upload_results.len(), 4);
    
    Ok(upload_results)
}
```

### Download Multiple Files

```rust
async fn batch_download_example(
    storage: &mut UnifiedStorageSystem,
    content_hashes: HashMap<String, ContentHash>,
    identity: ZhtpIdentity
) -> Result<HashMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    
    let mut download_results = HashMap::new();
    
    for (filename, content_hash) in content_hashes {
        let download_request = DownloadRequest {
            content_hash,
            requester: identity.clone(),
            access_proof: None,
        };
        
        match storage.download_content(download_request).await {
            Ok(content) => {
                println!(" Downloaded {}: {} bytes", filename, content.len());
                download_results.insert(filename, content);
            }
            Err(e) => {
                eprintln!(" Failed to download {}: {}", filename, e);
            }
        }
    }
    
    println!("Batch download completed: {}/{} files successful", 
             download_results.len(), 4);
    
    Ok(download_results)
}
```

##  Configuration Examples

### Custom Storage Configuration

```rust
fn create_custom_config() -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id: Hash::from_bytes(&generate_random_key()),
        addresses: vec!["0.0.0.0:33445".to_string()],
        economic_config: EconomicManagerConfig {
            default_duration_days: 14, // 2 weeks default
            base_price_per_gb_day: 50, // Lower base price
            enable_escrow: false,      // Disable escrow for simplicity
            quality_premium_rate: 0.0, // No quality premium
            network_fee_rate: 0.0,     // No network fees
            escrow_fee_rate: 0.0,      // No escrow fees
        },
        storage_config: StorageConfig {
            max_storage_size: 10_000_000_000, // 10GB
            default_tier: StorageTier::Warm,   // Balanced tier
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,   // 4 data shards
            parity_shards: 2, // 2 parity shards (6 total)
        },
    }
}
```

### Development vs Production Settings

```rust
fn create_development_config() -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id: Hash::from_bytes(&[1u8; 32]), // Fixed test key
        addresses: vec!["127.0.0.1:33445".to_string()], // Localhost only
        economic_config: EconomicManagerConfig {
            base_price_per_gb_day: 1, // Very low cost
            enable_escrow: false,
            quality_premium_rate: 0.0,
            network_fee_rate: 0.0,
            escrow_fee_rate: 0.0,
        },
        storage_config: StorageConfig {
            max_storage_size: 100_000_000, // 100MB for testing
            default_tier: StorageTier::Hot,
            enable_compression: false, // Easier debugging
            enable_encryption: false,  // Easier debugging
        },
        erasure_config: ErasureConfig {
            data_shards: 2,
            parity_shards: 1,
        },
    }
}

fn create_production_config() -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id: Hash::from_bytes(&load_production_key()),
        addresses: vec!["0.0.0.0:33445".to_string()], // All interfaces
        economic_config: EconomicManagerConfig {
            base_price_per_gb_day: 100, // Production pricing
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
            data_shards: 6,   // Higher redundancy
            parity_shards: 3,
        },
    }
}
```

##  Monitoring and Statistics

### Basic System Monitoring

```rust
async fn monitor_storage_system(
    storage: &mut UnifiedStorageSystem
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Get current system statistics
    let stats = storage.get_statistics().await?;
    
    // Display basic information
    println!("=== ZHTP Storage System Status ===");
    
    // Network status
    println!("\\n Network Status:");
    println!("  Connected nodes: {}", stats.dht_stats.total_nodes);
    println!("  Active connections: {}", stats.dht_stats.total_connections);
    println!("  Network health: {:.1}%", stats.dht_stats.network_health * 100.0);
    
    // Storage usage
    println!("\\n Storage Usage:");
    println!("  Total content items: {}", stats.storage_stats.total_content_count);
    println!("  Storage used: {:.2} MB", 
             stats.storage_stats.total_storage_used as f64 / 1_000_000.0);
    println!("  Total uploads: {}", stats.storage_stats.total_uploads);
    println!("  Total downloads: {}", stats.storage_stats.total_downloads);
    
    // Economic activity (if enabled)
    if stats.economic_stats.total_contracts > 0 {
        println!("\\n Economic Activity:");
        println!("  Active contracts: {}", stats.economic_stats.total_contracts);
        println!("  Value locked: {} ZHTP", stats.economic_stats.total_value_locked);
        println!("  Total rewards: {} ZHTP", stats.economic_stats.total_rewards);
    }
    
    // Performance metrics
    println!("\\n Performance:");
    println!("  Messages sent: {}", stats.dht_stats.total_messages_sent);
    println!("  Messages received: {}", stats.dht_stats.total_messages_received);
    println!("  Storage utilization: {:.1}%", stats.dht_stats.storage_utilization);
    
    Ok(())
}
```

### Periodic Health Checks

```rust
async fn start_health_monitoring(mut storage: UnifiedStorageSystem) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // Every minute
    
    loop {
        interval.tick().await;
        
        match monitor_storage_system(&mut storage).await {
            Ok(_) => {
                // Health check passed
            }
            Err(e) => {
                eprintln!("Health check failed: {}", e);
            }
        }
        
        // Perform maintenance if needed
        if let Err(e) = storage.perform_maintenance().await {
            eprintln!("Maintenance failed: {}", e);
        }
    }
}
```

##  Testing Utilities

### Create Test Data

```rust
fn generate_test_files() -> Vec<(String, Vec<u8>, String)> {
    vec![
        // Small text file
        (
            "readme.txt".to_string(),
            "This is a README file\\nWith multiple lines\\nFor testing purposes".as_bytes().to_vec(),
            "text/plain".to_string()
        ),
        
        // JSON data
        (
            "config.json".to_string(),
            serde_json::to_vec(&serde_json::json!({
                "version": "1.0",
                "settings": {
                    "debug": true,
                    "timeout": 30
                }
            })).unwrap(),
            "application/json".to_string()
        ),
        
        // Binary data
        (
            "data.bin".to_string(),
            (0..1000).map(|i| (i % 256) as u8).collect(),
            "application/octet-stream".to_string()
        ),
        
        // Large text file
        (
            "large.txt".to_string(),
            "Lorem ipsum ".repeat(1000).as_bytes().to_vec(),
            "text/plain".to_string()
        ),
    ]
}
```

### Verification Utilities

```rust
async fn verify_upload_download_cycle(
    storage: &mut UnifiedStorageSystem,
    test_data: Vec<u8>,
    identity: ZhtpIdentity
) -> Result<bool, Box<dyn std::error::Error>> {
    
    // Create upload request
    let upload_request = UploadRequest {
        content: test_data.clone(),
        filename: "test_verification.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
        description: "Verification test file".to_string(),
        tags: vec!["verification".to_string()],
        encrypt: false,
        compress: false,
        access_control: AccessControlSettings {
            public_read: true,
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 1, // Short duration for testing
            quality_requirements: QualityRequirements::default(),
            budget_constraints: BudgetConstraints::default(),
        },
    };
    
    // Upload
    let content_hash = storage.upload_content(upload_request, identity.clone()).await?;
    
    // Download
    let download_request = DownloadRequest {
        content_hash,
        requester: identity,
        access_proof: None,
    };
    
    let retrieved_data = storage.download_content(download_request).await?;
    
    // Verify
    let matches = test_data == retrieved_data;
    
    if matches {
        println!(" Upload/download cycle verification passed");
    } else {
        println!(" Upload/download cycle verification failed");
        println!("  Original size: {} bytes", test_data.len());
        println!("  Retrieved size: {} bytes", retrieved_data.len());
    }
    
    Ok(matches)
}
```

##  Complete Working Example

Here's a complete example that demonstrates all basic features:

```rust
use lib_storage::*;
use lib_identity::*;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(" Starting ZHTP Storage Basic Usage Example");
    
    // Initialize storage system
    let config = create_development_config();
    let mut storage = UnifiedStorageSystem::new(config).await?;
    
    // Create test identity
    let identity = create_test_identity()?;
    
    println!(" Storage system initialized");
    
    // Upload test files
    println!("\\n Uploading test files...");
    let content_hashes = batch_upload_example(&mut storage, identity.clone()).await?;
    
    // Search for uploaded files
    println!("\\n Searching for uploaded files...");
    search_files_example(&storage, identity.clone()).await?;
    
    // Download files
    println!("\\n Downloading files...");
    let downloaded_content = batch_download_example(&mut storage, content_hashes, identity.clone()).await?;
    
    // Verify content
    println!("\\n Verifying downloaded content...");
    for (filename, content) in downloaded_content {
        println!("  {} - {} bytes", filename, content.len());
    }
    
    // Monitor system
    println!("\\n System status:");
    monitor_storage_system(&mut storage).await?;
    
    // Perform verification test
    println!("\\n Running verification test...");
    let test_data = b"Verification test data".to_vec();
    let verification_passed = verify_upload_download_cycle(&mut storage, test_data, identity).await?;
    
    if verification_passed {
        println!("\\n All tests passed! ZHTP Storage is working correctly.");
    } else {
        println!("\\n Verification failed!");
    }
    
    Ok(())
}

// Helper functions would be implemented here...
fn create_test_identity() -> Result<ZhtpIdentity, Box<dyn std::error::Error>> {
    // Implementation depends on lib-identity
    unimplemented!("Implement using lib-identity")
}

fn generate_random_key() -> [u8; 32] {
    rand::random()
}

fn load_production_key() -> [u8; 32] {
    // In production, load from secure storage
    [0u8; 32] // Placeholder
}
```

---

=======
# Basic Usage Examples

This document provides practical examples of using the ZHTP Unified Storage System for common storage operations. These examples demonstrate the core functionality without complex economic features.

##  Simple File Storage

### Store and Retrieve a Text File

```rust
use lib_storage::*;
use lib_identity::ZhtpIdentity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage system
    let config = UnifiedStorageConfig::default();
    let mut storage = UnifiedStorageSystem::new(config).await?;
    
    // Create a simple text file
    let content = "Hello, ZHTP Storage System!\\nThis is a test file.".as_bytes().to_vec();
    let identity = create_user_identity()?;
    
    // Create upload request
    let upload_request = UploadRequest {
        content: content.clone(),
        filename: "hello.txt".to_string(),
        mime_type: "text/plain".to_string(),
        description: "Simple test file".to_string(),
        tags: vec!["test".to_string(), "hello".to_string()],
        encrypt: false,  // No encryption for this example
        compress: false, // No compression for this example
        access_control: AccessControlSettings {
            public_read: true, // Make it publicly readable
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 7, // Store for 1 week
            quality_requirements: QualityRequirements {
                min_uptime: 0.9,
                max_response_time: 10000, // 10 seconds
                min_replication: 3,
                data_integrity_level: 0.95,
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 1000, // 1000 ZHTP tokens
                max_cost_per_gb_day: 100,
                preferred_payment_schedule: PaymentSchedule::Upfront,
            },
        },
    };
    
    // Store the file
    let content_hash = storage.upload_content(upload_request, identity.clone()).await?;
    println!("File stored successfully!");
    println!("Content hash: {}", hex::encode(content_hash.as_bytes()));
    
    // Retrieve the file
    let download_request = DownloadRequest {
        content_hash,
        requester: identity,
        access_proof: None, // Not needed for public content
    };
    
    let retrieved_content = storage.download_content(download_request).await?;
    let retrieved_text = String::from_utf8(retrieved_content)?;
    
    println!("Retrieved content:");
    println!("{}", retrieved_text);
    
    // Verify content matches
    assert_eq!(content, retrieved_text.as_bytes());
    println!(" Content verification successful!");
    
    Ok(())
}
```

### Store Multiple Files with Different Configurations

```rust
async fn store_multiple_files(
    storage: &mut UnifiedStorageSystem,
    identity: ZhtpIdentity
) -> Result<Vec<ContentHash>, Box<dyn std::error::Error>> {
    
    let mut content_hashes = Vec::new();
    
    // Store a small text file
    let text_content = "Small text content".as_bytes().to_vec();
    let text_hash = store_file(
        storage,
        text_content,
        "small.txt",
        "text/plain",
        false, // No encryption
        false, // No compression
        identity.clone()
    ).await?;
    content_hashes.push(text_hash);
    
    // Store a larger binary file with compression
    let binary_content = vec![0u8; 10_000]; // 10KB of zeros (compresses well)
    let binary_hash = store_file(
        storage,
        binary_content,
        "data.bin",
        "application/octet-stream",
        false, // No encryption
        true,  // Enable compression
        identity.clone()
    ).await?;
    content_hashes.push(binary_hash);
    
    // Store an encrypted document
    let document_content = "Confidential document content".as_bytes().to_vec();
    let document_hash = store_file(
        storage,
        document_content,
        "confidential.doc",
        "application/msword",
        true,  // Enable encryption
        false, // No compression (encrypted data doesn't compress well)
        identity.clone()
    ).await?;
    content_hashes.push(document_hash);
    
    println!("Stored {} files successfully", content_hashes.len());
    
    Ok(content_hashes)
}

async fn store_file(
    storage: &mut UnifiedStorageSystem,
    content: Vec<u8>,
    filename: &str,
    mime_type: &str,
    encrypt: bool,
    compress: bool,
    identity: ZhtpIdentity
) -> Result<ContentHash, Box<dyn std::error::Error>> {
    
    let upload_request = UploadRequest {
        content,
        filename: filename.to_string(),
        mime_type: mime_type.to_string(),
        description: format!("File: {}", filename),
        tags: vec!["example".to_string()],
        encrypt,
        compress,
        access_control: AccessControlSettings {
            public_read: !encrypt, // Private if encrypted, public otherwise
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
    
    let content_hash = storage.upload_content(upload_request, identity).await?;
    println!("Stored {}: {}", filename, hex::encode(content_hash.as_bytes()));
    
    Ok(content_hash)
}
```

##  Content Search and Discovery

### Search for Files by Tags

```rust
async fn search_files_example(
    storage: &UnifiedStorageSystem,
    identity: ZhtpIdentity
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Search for all text files
    let text_query = SearchQuery {
        keywords: vec![],
        content_type: Some("text/plain".to_string()),
        tags: vec![],
        owner: None,
        date_range: None,
        size_range: None,
        limit: 10,
    };
    
    let text_results = storage.search_content(text_query, identity.clone()).await?;
    println!("Found {} text files", text_results.len());
    
    for result in &text_results {
        println!("   {} ({} bytes) - {}", 
                 result.filename, 
                 result.size, 
                 result.description);
    }
    
    // Search for files with specific tags
    let tagged_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec!["example".to_string()],
        owner: None,
        date_range: None,
        size_range: None,
        limit: 20,
    };
    
    let tagged_results = storage.search_content(tagged_query, identity.clone()).await?;
    println!("\\nFound {} files with 'example' tag", tagged_results.len());
    
    for result in &tagged_results {
        println!("  🏷️  {} - Tags: {:?}", result.filename, result.tags);
    }
    
    // Search by keyword in filename or description
    let keyword_query = SearchQuery {
        keywords: vec!["confidential".to_string()],
        content_type: None,
        tags: vec![],
        owner: None,
        date_range: None,
        size_range: None,
        limit: 5,
    };
    
    let keyword_results = storage.search_content(keyword_query, identity).await?;
    println!("\\nFound {} files matching 'confidential'", keyword_results.len());
    
    for result in &keyword_results {
        println!("   {} - {}", result.filename, result.description);
    }
    
    Ok(())
}
```

### Search with Size and Date Filters

```rust
use chrono::{DateTime, Utc, Duration};

async fn advanced_search_example(
    storage: &UnifiedStorageSystem,
    identity: ZhtpIdentity
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Search for large files (> 1MB)
    let large_files_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec![],
        owner: None,
        date_range: None,
        size_range: Some((1_000_000, u64::MAX)), // 1MB to unlimited
        limit: 10,
    };
    
    let large_results = storage.search_content(large_files_query, identity.clone()).await?;
    println!("Large files (>1MB): {}", large_results.len());
    
    // Search for recent files (last 7 days)
    let now = Utc::now().timestamp() as u64;
    let week_ago = (Utc::now() - Duration::days(7)).timestamp() as u64;
    
    let recent_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec![],
        owner: None,
        date_range: Some((week_ago, now)),
        size_range: None,
        limit: 20,
    };
    
    let recent_results = storage.search_content(recent_query, identity.clone()).await?;
    println!("Recent files (last 7 days): {}", recent_results.len());
    
    for result in &recent_results {
        let created_date = DateTime::from_timestamp(result.created_at as i64, 0)
            .unwrap_or_default();
        println!("  📅 {} - Created: {}", 
                 result.filename, 
                 created_date.format("%Y-%m-%d %H:%M:%S"));
    }
    
    // Search for files by specific owner
    let owner_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec![],
        owner: Some(identity.clone()),
        date_range: None,
        size_range: None,
        limit: 50,
    };
    
    let owned_results = storage.search_content(owner_query, identity).await?;
    println!("\\nFiles owned by user: {}", owned_results.len());
    
    Ok(())
}
```

##  Batch Operations

### Upload Multiple Files at Once

```rust
use std::collections::HashMap;

async fn batch_upload_example(
    storage: &mut UnifiedStorageSystem,
    identity: ZhtpIdentity
) -> Result<HashMap<String, ContentHash>, Box<dyn std::error::Error>> {
    
    // Prepare multiple files for upload
    let files = vec![
        ("file1.txt", "Content of file 1".as_bytes().to_vec(), "text/plain"),
        ("file2.txt", "Content of file 2".as_bytes().to_vec(), "text/plain"),
        ("data.json", r#"{"key": "value", "number": 42}"#.as_bytes().to_vec(), "application/json"),
        ("image.txt", "This would be image data".as_bytes().to_vec(), "image/png"),
    ];
    
    let mut upload_results = HashMap::new();
    let mut upload_tasks = Vec::new();
    
    // Create upload requests for all files
    for (filename, content, mime_type) in files {
        let upload_request = UploadRequest {
            content,
            filename: filename.to_string(),
            mime_type: mime_type.to_string(),
            description: format!("Batch upload: {}", filename),
            tags: vec!["batch".to_string(), "upload".to_string()],
            encrypt: false,
            compress: true, // Enable compression for all files
            access_control: AccessControlSettings {
                public_read: true,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 14, // 2 weeks
                quality_requirements: QualityRequirements::default(),
                budget_constraints: BudgetConstraints::default(),
            },
        };
        
        // Store the upload task for concurrent execution
        upload_tasks.push((filename.to_string(), upload_request));
    }
    
    // Execute uploads concurrently (in a scenario)
    // For this example, we'll do them sequentially
    for (filename, upload_request) in upload_tasks {
        match storage.upload_content(upload_request, identity.clone()).await {
            Ok(content_hash) => {
                println!(" Uploaded {}: {}", filename, hex::encode(content_hash.as_bytes()));
                upload_results.insert(filename, content_hash);
            }
            Err(e) => {
                eprintln!(" Failed to upload {}: {}", filename, e);
            }
        }
    }
    
    println!("Batch upload completed: {}/{} files successful", 
             upload_results.len(), 4);
    
    Ok(upload_results)
}
```

### Download Multiple Files

```rust
async fn batch_download_example(
    storage: &mut UnifiedStorageSystem,
    content_hashes: HashMap<String, ContentHash>,
    identity: ZhtpIdentity
) -> Result<HashMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    
    let mut download_results = HashMap::new();
    
    for (filename, content_hash) in content_hashes {
        let download_request = DownloadRequest {
            content_hash,
            requester: identity.clone(),
            access_proof: None,
        };
        
        match storage.download_content(download_request).await {
            Ok(content) => {
                println!(" Downloaded {}: {} bytes", filename, content.len());
                download_results.insert(filename, content);
            }
            Err(e) => {
                eprintln!(" Failed to download {}: {}", filename, e);
            }
        }
    }
    
    println!("Batch download completed: {}/{} files successful", 
             download_results.len(), 4);
    
    Ok(download_results)
}
```

##  Configuration Examples

### Custom Storage Configuration

```rust
fn create_custom_config() -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id: Hash::from_bytes(&generate_random_key()),
        addresses: vec!["0.0.0.0:33445".to_string()],
        economic_config: EconomicManagerConfig {
            default_duration_days: 14, // 2 weeks default
            base_price_per_gb_day: 50, // Lower base price
            enable_escrow: false,      // Disable escrow for simplicity
            quality_premium_rate: 0.0, // No quality premium
            network_fee_rate: 0.0,     // No network fees
            escrow_fee_rate: 0.0,      // No escrow fees
        },
        storage_config: StorageConfig {
            max_storage_size: 10_000_000_000, // 10GB
            default_tier: StorageTier::Warm,   // Balanced tier
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,   // 4 data shards
            parity_shards: 2, // 2 parity shards (6 total)
        },
    }
}
```

### Development vs Production Settings

```rust
fn create_development_config() -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id: Hash::from_bytes(&[1u8; 32]), // Fixed test key
        addresses: vec!["127.0.0.1:33445".to_string()], // Localhost only
        economic_config: EconomicManagerConfig {
            base_price_per_gb_day: 1, // Very low cost
            enable_escrow: false,
            quality_premium_rate: 0.0,
            network_fee_rate: 0.0,
            escrow_fee_rate: 0.0,
        },
        storage_config: StorageConfig {
            max_storage_size: 100_000_000, // 100MB for testing
            default_tier: StorageTier::Hot,
            enable_compression: false, // Easier debugging
            enable_encryption: false,  // Easier debugging
        },
        erasure_config: ErasureConfig {
            data_shards: 2,
            parity_shards: 1,
        },
    }
}

fn create_production_config() -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id: Hash::from_bytes(&load_production_key()),
        addresses: vec!["0.0.0.0:33445".to_string()], // All interfaces
        economic_config: EconomicManagerConfig {
            base_price_per_gb_day: 100, // Production pricing
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
            data_shards: 6,   // Higher redundancy
            parity_shards: 3,
        },
    }
}
```

##  Monitoring and Statistics

### Basic System Monitoring

```rust
async fn monitor_storage_system(
    storage: &mut UnifiedStorageSystem
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Get current system statistics
    let stats = storage.get_statistics().await?;
    
    // Display basic information
    println!("=== ZHTP Storage System Status ===");
    
    // Network status
    println!("\\n Network Status:");
    println!("  Connected nodes: {}", stats.dht_stats.total_nodes);
    println!("  Active connections: {}", stats.dht_stats.total_connections);
    println!("  Network health: {:.1}%", stats.dht_stats.network_health * 100.0);
    
    // Storage usage
    println!("\\n Storage Usage:");
    println!("  Total content items: {}", stats.storage_stats.total_content_count);
    println!("  Storage used: {:.2} MB", 
             stats.storage_stats.total_storage_used as f64 / 1_000_000.0);
    println!("  Total uploads: {}", stats.storage_stats.total_uploads);
    println!("  Total downloads: {}", stats.storage_stats.total_downloads);
    
    // Economic activity (if enabled)
    if stats.economic_stats.total_contracts > 0 {
        println!("\\n Economic Activity:");
        println!("  Active contracts: {}", stats.economic_stats.total_contracts);
        println!("  Value locked: {} ZHTP", stats.economic_stats.total_value_locked);
        println!("  Total rewards: {} ZHTP", stats.economic_stats.total_rewards);
    }
    
    // Performance metrics
    println!("\\n Performance:");
    println!("  Messages sent: {}", stats.dht_stats.total_messages_sent);
    println!("  Messages received: {}", stats.dht_stats.total_messages_received);
    println!("  Storage utilization: {:.1}%", stats.dht_stats.storage_utilization);
    
    Ok(())
}
```

### Periodic Health Checks

```rust
async fn start_health_monitoring(mut storage: UnifiedStorageSystem) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // Every minute
    
    loop {
        interval.tick().await;
        
        match monitor_storage_system(&mut storage).await {
            Ok(_) => {
                // Health check passed
            }
            Err(e) => {
                eprintln!("Health check failed: {}", e);
            }
        }
        
        // Perform maintenance if needed
        if let Err(e) = storage.perform_maintenance().await {
            eprintln!("Maintenance failed: {}", e);
        }
    }
}
```

##  Testing Utilities

### Create Test Data

```rust
fn generate_test_files() -> Vec<(String, Vec<u8>, String)> {
    vec![
        // Small text file
        (
            "readme.txt".to_string(),
            "This is a README file\\nWith multiple lines\\nFor testing purposes".as_bytes().to_vec(),
            "text/plain".to_string()
        ),
        
        // JSON data
        (
            "config.json".to_string(),
            serde_json::to_vec(&serde_json::json!({
                "version": "1.0",
                "settings": {
                    "debug": true,
                    "timeout": 30
                }
            })).unwrap(),
            "application/json".to_string()
        ),
        
        // Binary data
        (
            "data.bin".to_string(),
            (0..1000).map(|i| (i % 256) as u8).collect(),
            "application/octet-stream".to_string()
        ),
        
        // Large text file
        (
            "large.txt".to_string(),
            "Lorem ipsum ".repeat(1000).as_bytes().to_vec(),
            "text/plain".to_string()
        ),
    ]
}
```

### Verification Utilities

```rust
async fn verify_upload_download_cycle(
    storage: &mut UnifiedStorageSystem,
    test_data: Vec<u8>,
    identity: ZhtpIdentity
) -> Result<bool, Box<dyn std::error::Error>> {
    
    // Create upload request
    let upload_request = UploadRequest {
        content: test_data.clone(),
        filename: "test_verification.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
        description: "Verification test file".to_string(),
        tags: vec!["verification".to_string()],
        encrypt: false,
        compress: false,
        access_control: AccessControlSettings {
            public_read: true,
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 1, // Short duration for testing
            quality_requirements: QualityRequirements::default(),
            budget_constraints: BudgetConstraints::default(),
        },
    };
    
    // Upload
    let content_hash = storage.upload_content(upload_request, identity.clone()).await?;
    
    // Download
    let download_request = DownloadRequest {
        content_hash,
        requester: identity,
        access_proof: None,
    };
    
    let retrieved_data = storage.download_content(download_request).await?;
    
    // Verify
    let matches = test_data == retrieved_data;
    
    if matches {
        println!(" Upload/download cycle verification passed");
    } else {
        println!(" Upload/download cycle verification failed");
        println!("  Original size: {} bytes", test_data.len());
        println!("  Retrieved size: {} bytes", retrieved_data.len());
    }
    
    Ok(matches)
}
```

##  Complete Working Example

Here's a complete example that demonstrates all basic features:

```rust
use lib_storage::*;
use lib_identity::*;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(" Starting ZHTP Storage Basic Usage Example");
    
    // Initialize storage system
    let config = create_development_config();
    let mut storage = UnifiedStorageSystem::new(config).await?;
    
    // Create test identity
    let identity = create_test_identity()?;
    
    println!(" Storage system initialized");
    
    // Upload test files
    println!("\\n Uploading test files...");
    let content_hashes = batch_upload_example(&mut storage, identity.clone()).await?;
    
    // Search for uploaded files
    println!("\\n Searching for uploaded files...");
    search_files_example(&storage, identity.clone()).await?;
    
    // Download files
    println!("\\n Downloading files...");
    let downloaded_content = batch_download_example(&mut storage, content_hashes, identity.clone()).await?;
    
    // Verify content
    println!("\\n Verifying downloaded content...");
    for (filename, content) in downloaded_content {
        println!("  {} - {} bytes", filename, content.len());
    }
    
    // Monitor system
    println!("\\n System status:");
    monitor_storage_system(&mut storage).await?;
    
    // Perform verification test
    println!("\\n Running verification test...");
    let test_data = b"Verification test data".to_vec();
    let verification_passed = verify_upload_download_cycle(&mut storage, test_data, identity).await?;
    
    if verification_passed {
        println!("\\n All tests passed! ZHTP Storage is working correctly.");
    } else {
        println!("\\n Verification failed!");
    }
    
    Ok(())
}

// Helper functions would be implemented here...
fn create_test_identity() -> Result<ZhtpIdentity, Box<dyn std::error::Error>> {
    // Implementation depends on lib-identity
    unimplemented!("Implement using lib-identity")
}

fn generate_random_key() -> [u8; 32] {
    rand::random()
}

fn load_production_key() -> [u8; 32] {
    // In production, load from secure storage
    [0u8; 32] // Placeholder
}
```

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
These examples provide a solid foundation for using the ZHTP Unified Storage System in your applications. Start with the simple examples and gradually explore more advanced features as needed.