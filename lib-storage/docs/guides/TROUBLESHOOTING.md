<<<<<<< HEAD
# ZHTP Storage Troubleshooting Guide

This guide helps diagnose and resolve common issues when working with the ZHTP Unified Storage System.

##  Common Issues and Solutions

### Network Connection Issues

#### Problem: "Failed to bootstrap DHT network"

**Symptoms:**
- Node cannot join the network
- Bootstrap node connection failures
- Network health shows 0% or very low percentages

**Diagnosis:**
```rust
// Check network connectivity
let mut storage = UnifiedStorageSystem::new(config).await?;
let stats = storage.get_statistics().await?;

println!("Network health: {:.1}%", stats.dht_stats.network_health * 100.0);
println!("Connected nodes: {}", stats.dht_stats.total_nodes);
println!("Messages sent: {}", stats.dht_stats.total_messages_sent);
println!("Messages received: {}", stats.dht_stats.total_messages_received);
```

**Solutions:**

1. **Check Bootstrap Nodes:**
```rust
let config = UnifiedStorageConfig {
    // Add multiple bootstrap nodes
    bootstrap_nodes: vec![
        "bootstrap1.zhtp.network:33445".to_string(),
        "bootstrap2.zhtp.network:33445".to_string(),
        "127.0.0.1:33445".to_string(), // Local for testing
    ],
    ..Default::default()
};
```

2. **Firewall Configuration:**
```bash
# Allow ZHTP default port
sudo ufw allow 33445

# Or use custom port
sudo ufw allow 12345
```

3. **NAT/Router Configuration:**
- Forward port 33445 (or your custom port) to your machine
- Enable UPnP if available
- Use STUN servers for NAT traversal

4. **Network Interface Binding:**
```rust
let config = UnifiedStorageConfig {
    addresses: vec![
        "0.0.0.0:33445".to_string(), // Bind to all interfaces
        // Or specific interface:
        // "192.168.1.100:33445".to_string(),
    ],
    ..Default::default()
};
```

#### Problem: "Connection timeout to peers"

**Symptoms:**
- Nodes visible but cannot communicate
- Upload/download operations timeout
- High network latency

**Solutions:**

1. **Increase Timeout Values:**
```rust
let config = UnifiedStorageConfig {
    network_config: NetworkConfig {
        connection_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_secs(15),
        max_concurrent_connections: 50,
        ..Default::default()
    },
    ..Default::default()
};
```

2. **Enable Keep-Alive:**
```rust
let config = UnifiedStorageConfig {
    network_config: NetworkConfig {
        enable_keepalive: true,
        keepalive_interval: Duration::from_secs(30),
        keepalive_timeout: Duration::from_secs(10),
        ..Default::default()
    },
    ..Default::default()
};
```

### Storage Operation Failures

#### Problem: "Upload failed with insufficient storage"

**Symptoms:**
- Uploads are rejected
- Error: "No nodes with sufficient capacity"
- Network has storage but nodes refuse content

**Diagnosis:**
```rust
async fn diagnose_storage_capacity(storage: &mut UnifiedStorageSystem) -> Result<()> {
    let stats = storage.get_statistics().await?;
    
    println!("Total network storage: {} bytes", stats.storage_stats.total_storage_capacity);
    println!("Used storage: {} bytes", stats.storage_stats.total_storage_used);
    println!("Available: {} bytes", 
             stats.storage_stats.total_storage_capacity - stats.storage_stats.total_storage_used);
    
    // Check individual node capacities
    let network_info = storage.get_network_info().await?;
    for node in network_info.nodes {
        println!("Node {}: {}/{} bytes used", 
                 node.id, node.storage_used, node.storage_capacity);
    }
    
    Ok(())
}
```

**Solutions:**

1. **Increase Storage Budget:**
```rust
let upload_req = UploadRequest {
    // ... other fields
    storage_requirements: ContentStorageRequirements {
        duration_days: 30,
        quality_requirements: QualityRequirements::default(),
        budget_constraints: BudgetConstraints {
            max_total_cost: 50000, // Increase budget
            max_cost_per_gb_day: 500, // Higher price tolerance
            preferred_payment_schedule: PaymentSchedule::Upfront,
        },
    },
};
```

2. **Adjust Quality Requirements:**
```rust
let upload_req = UploadRequest {
    // ... other fields
    storage_requirements: ContentStorageRequirements {
        quality_requirements: QualityRequirements {
            min_uptime: 0.90,        // Reduce from 0.95
            max_response_time: 10000, // Increase from 5000
            min_replication: 2,       // Reduce from 3
            data_integrity_level: 0.95, // Reduce from 0.99
        },
        // ... other fields
    },
};
```

3. **Use Compression and Deduplication:**
```rust
let upload_req = UploadRequest {
    compress: true,  // Enable compression
    // Enable deduplication (if content exists)
    // ... other fields
};
```

#### Problem: "Download failed with content not found"

**Symptoms:**
- Content hash exists but download fails
- Error: "Content not reachable"
- Partial download failures

**Diagnosis:**
```rust
async fn diagnose_content_availability(
    storage: &mut UnifiedStorageSystem, 
    content_hash: &ContentHash
) -> Result<()> {
    // Check content metadata
    let metadata = storage.get_content_metadata(content_hash.clone()).await?;
    println!("Content metadata: {:?}", metadata);
    
    // Check replication status
    let replication_info = storage.get_replication_status(content_hash.clone()).await?;
    println!("Replicas available: {}/{}", 
             replication_info.available_replicas, 
             replication_info.total_replicas);
    
    // Check node availability
    for replica in replication_info.replica_locations {
        let node_status = storage.check_node_status(&replica.node_id).await?;
        println!("Node {} status: {:?}", replica.node_id, node_status);
    }
    
    Ok(())
}
```

**Solutions:**

1. **Retry with Different Strategy:**
```rust
async fn download_with_fallback(
    storage: &mut UnifiedStorageSystem,
    content_hash: ContentHash,
    requester: ZhtpIdentity
) -> Result<Vec<u8>> {
    let download_req = DownloadRequest {
        content_hash: content_hash.clone(),
        requester: requester.clone(),
        access_proof: None,
    };
    
    // Try normal download first
    match storage.download_content(download_req.clone()).await {
        Ok(content) => return Ok(content),
        Err(e) => println!("Direct download failed: {}", e),
    }
    
    // Try reconstruction from erasure coding
    match storage.reconstruct_content(content_hash.clone()).await {
        Ok(content) => return Ok(content),
        Err(e) => println!("Reconstruction failed: {}", e),
    }
    
    // Try downloading from specific high-reputation nodes
    let network_info = storage.get_network_info().await?;
    let high_rep_nodes: Vec<_> = network_info.nodes.into_iter()
        .filter(|n| n.reputation > 0.8)
        .collect();
    
    for node in high_rep_nodes {
        match storage.download_from_node(content_hash.clone(), node.id).await {
            Ok(content) => return Ok(content),
            Err(e) => println!("Download from node {} failed: {}", node.id, e),
        }
    }
    
    Err(anyhow::anyhow!("All download strategies failed"))
}
```

### Economic/Payment Issues

#### Problem: "Insufficient funds for storage operation"

**Symptoms:**
- Uploads rejected due to payment
- Error: "Payment authorization failed"
- Economic contracts not created

**Diagnosis:**
```rust
async fn check_wallet_status(storage: &mut UnifiedStorageSystem, identity: &ZhtpIdentity) -> Result<()> {
    let wallet_info = storage.get_wallet_info(identity).await?;
    
    println!("Wallet balance: {} SOV", wallet_info.balance);
    println!("Locked funds: {} SOV", wallet_info.locked_balance);
    println!("Available: {} SOV", wallet_info.balance - wallet_info.locked_balance);
    
    // Check recent transactions
    let transactions = storage.get_transaction_history(identity, 10).await?;
    for tx in transactions {
        println!("Transaction: {} SOV, Status: {:?}", tx.amount, tx.status);
    }
    
    Ok(())
}
```

**Solutions:**

1. **Top Up Wallet:**
```rust
// In a implementation, integrate with SOV token system
async fn fund_wallet(storage: &mut UnifiedStorageSystem, identity: &ZhtpIdentity, amount: u64) -> Result<()> {
    // This would connect to the ZHTP blockchain/token system
    let funding_tx = storage.fund_wallet(identity.clone(), amount).await?;
    println!("Wallet funded with {} SOV, tx: {}", amount, funding_tx);
    Ok(())
}
```

2. **Adjust Payment Schedule:**
```rust
let upload_req = UploadRequest {
    storage_requirements: ContentStorageRequirements {
        budget_constraints: BudgetConstraints {
            max_total_cost: 1000, // Lower cost
            max_cost_per_gb_day: 50, // Lower daily rate
            preferred_payment_schedule: PaymentSchedule::Monthly, // Spread payments
        },
        // ... other fields
    },
    // ... other fields
};
```

3. **Use Free/Demo Storage:**
```rust
let config = UnifiedStorageConfig {
    economic_config: EconomicManagerConfig {
        enable_free_tier: true,
        free_tier_limit_gb: 1, // 1GB free
        free_tier_duration_days: 7, // 7 days free
        // ... other settings
    },
    // ... other settings
};
```

### Performance Issues

#### Problem: "Slow upload/download speeds"

**Symptoms:**
- Operations take much longer than expected
- Network appears healthy but transfers are slow
- High CPU/memory usage during transfers

**Diagnosis:**
```rust
use std::time::Instant;

async fn benchmark_operations(storage: &mut UnifiedStorageSystem) -> Result<()> {
    let test_data = vec![0u8; 1024 * 1024]; // 1MB test data
    let identity = create_test_identity();
    
    // Benchmark upload
    let upload_start = Instant::now();
    let upload_req = create_test_upload_request(test_data.clone());
    let content_hash = storage.upload_content(upload_req, identity.clone()).await?;
    let upload_duration = upload_start.elapsed();
    
    println!("Upload: {} MB/s", 
             (test_data.len() as f64 / 1024.0 / 1024.0) / upload_duration.as_secs_f64());
    
    // Benchmark download
    let download_start = Instant::now();
    let download_req = DownloadRequest {
        content_hash,
        requester: identity,
        access_proof: None,
    };
    let downloaded_data = storage.download_content(download_req).await?;
    let download_duration = download_start.elapsed();
    
    println!("Download: {} MB/s", 
             (downloaded_data.len() as f64 / 1024.0 / 1024.0) / download_duration.as_secs_f64());
    
    Ok(())
}
```

**Solutions:**

1. **Increase Parallelism:**
```rust
let config = UnifiedStorageConfig {
    performance_config: PerformanceConfig {
        max_concurrent_uploads: 10,
        max_concurrent_downloads: 20,
        chunk_size: 1024 * 1024, // 1MB chunks
        enable_parallel_erasure: true,
        ..Default::default()
    },
    ..Default::default()
};
```

2. **Optimize Erasure Coding:**
```rust
let config = UnifiedStorageConfig {
    erasure_config: ErasureConfig {
        data_shards: 4,   // Reduce for faster encoding
        parity_shards: 2, // Reduce redundancy for speed
        enable_sse: true, // Use SIMD optimizations
    },
    ..Default::default()
};
```

3. **Tune Compression:**
```rust
let upload_req = UploadRequest {
    compress: true,
    compression_level: 3, // Fast compression (1-9 scale)
    // ... other fields
};
```

### Identity and Access Issues

#### Problem: "Access denied" or "Authentication failed"

**Symptoms:**
- Cannot access uploaded content
- Permission errors
- Identity verification failures

**Diagnosis:**
```rust
async fn diagnose_access_issues(
    storage: &mut UnifiedStorageSystem,
    content_hash: &ContentHash,
    identity: &ZhtpIdentity
) -> Result<()> {
    // Check content permissions
    let metadata = storage.get_content_metadata(content_hash.clone()).await?;
    println!("Content owner: {:?}", metadata.owner);
    println!("Public read: {}", metadata.access_control.public_read);
    println!("Read permissions: {:?}", metadata.access_control.read_permissions);
    
    // Check identity
    let identity_info = storage.get_identity_info(identity).await?;
    println!("Identity valid: {}", identity_info.is_valid);
    println!("Identity reputation: {}", identity_info.reputation);
    
    // Check access permissions
    let has_access = storage.check_access_permission(content_hash.clone(), identity.clone()).await?;
    println!("Has access: {}", has_access);
    
    Ok(())
}
```

**Solutions:**

1. **Update Access Permissions:**
```rust
async fn grant_access(
    storage: &mut UnifiedStorageSystem,
    content_hash: ContentHash,
    owner_identity: ZhtpIdentity,
    target_identity: ZhtpIdentity
) -> Result<()> {
    let access_update = AccessControlUpdate {
        content_hash,
        add_read_permissions: vec![target_identity],
        remove_read_permissions: vec![],
        make_public: false,
    };
    
    storage.update_access_control(access_update, owner_identity).await?;
    println!("Access granted successfully");
    Ok(())
}
```

2. **Verify Identity:**
```rust
async fn refresh_identity(identity: &mut ZhtpIdentity) -> Result<()> {
    // Refresh identity certificates/proofs
    identity.refresh_credentials().await?;
    
    // Re-sign identity
    identity.sign_with_current_key().await?;
    
    println!("Identity refreshed");
    Ok(())
}
```

##  Debugging Tools

### Enable Debug Logging

```rust
use tracing::{info, debug, warn, error};
use tracing_subscriber::{fmt, EnvFilter};

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("lib_storage=debug".parse().unwrap())
            .add_directive("lib_dht=debug".parse().unwrap())
            .add_directive("lib_network=info".parse().unwrap()))
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();
}

// Set environment variable for detailed logging
// RUST_LOG=lib_storage=debug,lib_dht=debug
```

### Network Diagnostic Tool

```rust
use std::time::Duration;
use tokio::time::timeout;

pub struct NetworkDiagnostic {
    storage: UnifiedStorageSystem,
}

impl NetworkDiagnostic {
    pub async fn run_full_diagnostic(&mut self) -> Result<DiagnosticReport> {
        let mut report = DiagnosticReport::new();
        
        // Test 1: Network connectivity
        report.network_test = self.test_network_connectivity().await?;
        
        // Test 2: DHT functionality
        report.dht_test = self.test_dht_operations().await?;
        
        // Test 3: Storage operations
        report.storage_test = self.test_storage_operations().await?;
        
        // Test 4: Economic operations
        report.economic_test = self.test_economic_operations().await?;
        
        // Test 5: Performance benchmarks
        report.performance_test = self.test_performance().await?;
        
        Ok(report)
    }
    
    async fn test_network_connectivity(&mut self) -> Result<NetworkTestResult> {
        let start = std::time::Instant::now();
        
        // Test basic connectivity
        let stats = timeout(Duration::from_secs(10), self.storage.get_statistics()).await??;
        
        let connectivity_score = if stats.dht_stats.total_nodes > 0 {
            stats.dht_stats.network_health
        } else {
            0.0
        };
        
        Ok(NetworkTestResult {
            success: connectivity_score > 0.5,
            latency: start.elapsed(),
            connected_nodes: stats.dht_stats.total_nodes,
            network_health: connectivity_score,
            message: if connectivity_score > 0.8 {
                "Network connectivity excellent".to_string()
            } else if connectivity_score > 0.5 {
                "Network connectivity acceptable".to_string()
            } else {
                "Network connectivity poor".to_string()
            },
        })
    }
    
    async fn test_storage_operations(&mut self) -> Result<StorageTestResult> {
        let test_data = b"diagnostic test data";
        let identity = create_test_identity();
        
        // Test upload
        let upload_start = std::time::Instant::now();
        let upload_req = UploadRequest {
            content: test_data.to_vec(),
            filename: "diagnostic_test.txt".to_string(),
            mime_type: "text/plain".to_string(),
            description: "Diagnostic test file".to_string(),
            tags: vec!["diagnostic".to_string()],
            encrypt: false,
            compress: false,
            access_control: AccessControlSettings {
                public_read: true,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 1,
                quality_requirements: QualityRequirements::default(),
                budget_constraints: BudgetConstraints {
                    max_total_cost: 1000,
                    max_cost_per_gb_day: 100,
                    preferred_payment_schedule: PaymentSchedule::Upfront,
                },
            },
        };
        
        let content_hash = match timeout(Duration::from_secs(30), 
                                       self.storage.upload_content(upload_req, identity.clone())).await {
            Ok(Ok(hash)) => hash,
            Ok(Err(e)) => return Ok(StorageTestResult {
                success: false,
                upload_time: upload_start.elapsed(),
                download_time: Duration::default(),
                message: format!("Upload failed: {}", e),
            }),
            Err(_) => return Ok(StorageTestResult {
                success: false,
                upload_time: upload_start.elapsed(),
                download_time: Duration::default(),
                message: "Upload timed out".to_string(),
            }),
        };
        
        let upload_time = upload_start.elapsed();
        
        // Test download
        let download_start = std::time::Instant::now();
        let download_req = DownloadRequest {
            content_hash,
            requester: identity,
            access_proof: None,
        };
        
        let downloaded_data = match timeout(Duration::from_secs(30), 
                                          self.storage.download_content(download_req)).await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Ok(StorageTestResult {
                success: false,
                upload_time,
                download_time: download_start.elapsed(),
                message: format!("Download failed: {}", e),
            }),
            Err(_) => return Ok(StorageTestResult {
                success: false,
                upload_time,
                download_time: download_start.elapsed(),
                message: "Download timed out".to_string(),
            }),
        };
        
        let download_time = download_start.elapsed();
        
        let success = downloaded_data == test_data;
        
        Ok(StorageTestResult {
            success,
            upload_time,
            download_time,
            message: if success {
                format!("Storage operations successful (up: {:?}, down: {:?})", upload_time, download_time)
            } else {
                "Data integrity check failed".to_string()
            },
        })
    }
}

#[derive(Debug)]
pub struct DiagnosticReport {
    pub network_test: NetworkTestResult,
    pub dht_test: DhtTestResult,
    pub storage_test: StorageTestResult,
    pub economic_test: EconomicTestResult,
    pub performance_test: PerformanceTestResult,
}

#[derive(Debug)]
pub struct NetworkTestResult {
    pub success: bool,
    pub latency: Duration,
    pub connected_nodes: usize,
    pub network_health: f64,
    pub message: String,
}

#[derive(Debug)]
pub struct StorageTestResult {
    pub success: bool,
    pub upload_time: Duration,
    pub download_time: Duration,
    pub message: String,
}
```

### Configuration Validator

```rust
pub fn validate_config(config: &UnifiedStorageConfig) -> Result<Vec<ConfigWarning>> {
    let mut warnings = Vec::new();
    
    // Check network configuration
    if config.addresses.is_empty() {
        warnings.push(ConfigWarning::Error("No network addresses specified".to_string()));
    }
    
    if config.bootstrap_nodes.is_empty() {
        warnings.push(ConfigWarning::Warning("No bootstrap nodes configured - may have trouble joining network".to_string()));
    }
    
    // Check storage limits
    if config.storage_config.max_storage_size < 1024 * 1024 * 100 { // 100MB
        warnings.push(ConfigWarning::Warning("Very low storage limit may affect network participation".to_string()));
    }
    
    // Check economic settings
    if config.economic_config.base_price_per_gb_day == 0 {
        warnings.push(ConfigWarning::Warning("Zero pricing may lead to resource abuse".to_string()));
    }
    
    // Check erasure coding
    let total_shards = config.erasure_config.data_shards + config.erasure_config.parity_shards;
    if total_shards > 16 {
        warnings.push(ConfigWarning::Warning("High shard count may impact performance".to_string()));
    }
    
    if config.erasure_config.parity_shards > config.erasure_config.data_shards {
        warnings.push(ConfigWarning::Warning("More parity than data shards is usually inefficient".to_string()));
    }
    
    Ok(warnings)
}

#[derive(Debug)]
pub enum ConfigWarning {
    Error(String),
    Warning(String),
    Info(String),
}
```

## 📚 Getting Help

### Enable Comprehensive Logging

```bash
# Set environment variables for maximum debugging
export RUST_LOG=lib_storage=trace,lib_dht=debug,lib_network=debug,lib_economy=debug
export RUST_BACKTRACE=full

# Run with verbose output
cargo run --bin your_app 2>&1 | tee debug.log
```

### Collect System Information

```rust
pub async fn collect_system_info(storage: &mut UnifiedStorageSystem) -> Result<SystemInfo> {
    Ok(SystemInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        node_id: storage.get_node_id().await?,
        network_stats: storage.get_statistics().await?.dht_stats,
        storage_stats: storage.get_statistics().await?.storage_stats,
        config_summary: ConfigSummary {
            max_storage: storage.get_config().storage_config.max_storage_size,
            network_ports: storage.get_config().addresses.clone(),
            erasure_config: storage.get_config().erasure_config.clone(),
        },
        runtime_info: RuntimeInfo {
            uptime: storage.get_uptime().await?,
            memory_usage: get_memory_usage(),
            cpu_usage: get_cpu_usage(),
        },
    })
}
```

### Report Issues

When reporting issues, please include:

1. **System Information:**
   - Operating system and version
   - Rust version (`rustc --version`)
   - lib-storage version
   - Hardware specifications

2. **Configuration:**
   - Sanitized configuration file (remove private keys!)
   - Network topology
   - Storage allocation

3. **Logs:**
   - Full debug logs with timestamps
   - Network diagnostic results
   - Error messages and stack traces

4. **Reproduction Steps:**
   - Minimal code example
   - Specific operations that fail
   - Expected vs actual behavior

5. **Environment:**
   - Network conditions (bandwidth, latency)
   - Firewall/NAT configuration
   - Other running applications

---

=======
# ZHTP Storage Troubleshooting Guide

This guide helps diagnose and resolve common issues when working with the ZHTP Unified Storage System.

##  Common Issues and Solutions

### Network Connection Issues

#### Problem: "Failed to bootstrap DHT network"

**Symptoms:**
- Node cannot join the network
- Bootstrap node connection failures
- Network health shows 0% or very low percentages

**Diagnosis:**
```rust
// Check network connectivity
let mut storage = UnifiedStorageSystem::new(config).await?;
let stats = storage.get_statistics().await?;

println!("Network health: {:.1}%", stats.dht_stats.network_health * 100.0);
println!("Connected nodes: {}", stats.dht_stats.total_nodes);
println!("Messages sent: {}", stats.dht_stats.total_messages_sent);
println!("Messages received: {}", stats.dht_stats.total_messages_received);
```

**Solutions:**

1. **Check Bootstrap Nodes:**
```rust
let config = UnifiedStorageConfig {
    // Add multiple bootstrap nodes
    bootstrap_nodes: vec![
        "bootstrap1.zhtp.network:33445".to_string(),
        "bootstrap2.zhtp.network:33445".to_string(),
        "127.0.0.1:33445".to_string(), // Local for testing
    ],
    ..Default::default()
};
```

2. **Firewall Configuration:**
```bash
# Allow ZHTP default port
sudo ufw allow 33445

# Or use custom port
sudo ufw allow 12345
```

3. **NAT/Router Configuration:**
- Forward port 33445 (or your custom port) to your machine
- Enable UPnP if available
- Use STUN servers for NAT traversal

4. **Network Interface Binding:**
```rust
let config = UnifiedStorageConfig {
    addresses: vec![
        "0.0.0.0:33445".to_string(), // Bind to all interfaces
        // Or specific interface:
        // "192.168.1.100:33445".to_string(),
    ],
    ..Default::default()
};
```

#### Problem: "Connection timeout to peers"

**Symptoms:**
- Nodes visible but cannot communicate
- Upload/download operations timeout
- High network latency

**Solutions:**

1. **Increase Timeout Values:**
```rust
let config = UnifiedStorageConfig {
    network_config: NetworkConfig {
        connection_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_secs(15),
        max_concurrent_connections: 50,
        ..Default::default()
    },
    ..Default::default()
};
```

2. **Enable Keep-Alive:**
```rust
let config = UnifiedStorageConfig {
    network_config: NetworkConfig {
        enable_keepalive: true,
        keepalive_interval: Duration::from_secs(30),
        keepalive_timeout: Duration::from_secs(10),
        ..Default::default()
    },
    ..Default::default()
};
```

### Storage Operation Failures

#### Problem: "Upload failed with insufficient storage"

**Symptoms:**
- Uploads are rejected
- Error: "No nodes with sufficient capacity"
- Network has storage but nodes refuse content

**Diagnosis:**
```rust
async fn diagnose_storage_capacity(storage: &mut UnifiedStorageSystem) -> Result<()> {
    let stats = storage.get_statistics().await?;
    
    println!("Total network storage: {} bytes", stats.storage_stats.total_storage_capacity);
    println!("Used storage: {} bytes", stats.storage_stats.total_storage_used);
    println!("Available: {} bytes", 
             stats.storage_stats.total_storage_capacity - stats.storage_stats.total_storage_used);
    
    // Check individual node capacities
    let network_info = storage.get_network_info().await?;
    for node in network_info.nodes {
        println!("Node {}: {}/{} bytes used", 
                 node.id, node.storage_used, node.storage_capacity);
    }
    
    Ok(())
}
```

**Solutions:**

1. **Increase Storage Budget:**
```rust
let upload_req = UploadRequest {
    // ... other fields
    storage_requirements: ContentStorageRequirements {
        duration_days: 30,
        quality_requirements: QualityRequirements::default(),
        budget_constraints: BudgetConstraints {
            max_total_cost: 50000, // Increase budget
            max_cost_per_gb_day: 500, // Higher price tolerance
            preferred_payment_schedule: PaymentSchedule::Upfront,
        },
    },
};
```

2. **Adjust Quality Requirements:**
```rust
let upload_req = UploadRequest {
    // ... other fields
    storage_requirements: ContentStorageRequirements {
        quality_requirements: QualityRequirements {
            min_uptime: 0.90,        // Reduce from 0.95
            max_response_time: 10000, // Increase from 5000
            min_replication: 2,       // Reduce from 3
            data_integrity_level: 0.95, // Reduce from 0.99
        },
        // ... other fields
    },
};
```

3. **Use Compression and Deduplication:**
```rust
let upload_req = UploadRequest {
    compress: true,  // Enable compression
    // Enable deduplication (if content exists)
    // ... other fields
};
```

#### Problem: "Download failed with content not found"

**Symptoms:**
- Content hash exists but download fails
- Error: "Content not reachable"
- Partial download failures

**Diagnosis:**
```rust
async fn diagnose_content_availability(
    storage: &mut UnifiedStorageSystem, 
    content_hash: &ContentHash
) -> Result<()> {
    // Check content metadata
    let metadata = storage.get_content_metadata(content_hash.clone()).await?;
    println!("Content metadata: {:?}", metadata);
    
    // Check replication status
    let replication_info = storage.get_replication_status(content_hash.clone()).await?;
    println!("Replicas available: {}/{}", 
             replication_info.available_replicas, 
             replication_info.total_replicas);
    
    // Check node availability
    for replica in replication_info.replica_locations {
        let node_status = storage.check_node_status(&replica.node_id).await?;
        println!("Node {} status: {:?}", replica.node_id, node_status);
    }
    
    Ok(())
}
```

**Solutions:**

1. **Retry with Different Strategy:**
```rust
async fn download_with_fallback(
    storage: &mut UnifiedStorageSystem,
    content_hash: ContentHash,
    requester: ZhtpIdentity
) -> Result<Vec<u8>> {
    let download_req = DownloadRequest {
        content_hash: content_hash.clone(),
        requester: requester.clone(),
        access_proof: None,
    };
    
    // Try normal download first
    match storage.download_content(download_req.clone()).await {
        Ok(content) => return Ok(content),
        Err(e) => println!("Direct download failed: {}", e),
    }
    
    // Try reconstruction from erasure coding
    match storage.reconstruct_content(content_hash.clone()).await {
        Ok(content) => return Ok(content),
        Err(e) => println!("Reconstruction failed: {}", e),
    }
    
    // Try downloading from specific high-reputation nodes
    let network_info = storage.get_network_info().await?;
    let high_rep_nodes: Vec<_> = network_info.nodes.into_iter()
        .filter(|n| n.reputation > 0.8)
        .collect();
    
    for node in high_rep_nodes {
        match storage.download_from_node(content_hash.clone(), node.id).await {
            Ok(content) => return Ok(content),
            Err(e) => println!("Download from node {} failed: {}", node.id, e),
        }
    }
    
    Err(anyhow::anyhow!("All download strategies failed"))
}
```

### Economic/Payment Issues

#### Problem: "Insufficient funds for storage operation"

**Symptoms:**
- Uploads rejected due to payment
- Error: "Payment authorization failed"
- Economic contracts not created

**Diagnosis:**
```rust
async fn check_wallet_status(storage: &mut UnifiedStorageSystem, identity: &ZhtpIdentity) -> Result<()> {
    let wallet_info = storage.get_wallet_info(identity).await?;
    
    println!("Wallet balance: {} SOV", wallet_info.balance);
    println!("Locked funds: {} SOV", wallet_info.locked_balance);
    println!("Available: {} SOV", wallet_info.balance - wallet_info.locked_balance);
    
    // Check recent transactions
    let transactions = storage.get_transaction_history(identity, 10).await?;
    for tx in transactions {
        println!("Transaction: {} SOV, Status: {:?}", tx.amount, tx.status);
    }
    
    Ok(())
}
```

**Solutions:**

1. **Top Up Wallet:**
```rust
// In a implementation, integrate with SOV token system
async fn fund_wallet(storage: &mut UnifiedStorageSystem, identity: &ZhtpIdentity, amount: u64) -> Result<()> {
    // This would connect to the ZHTP blockchain/token system
    let funding_tx = storage.fund_wallet(identity.clone(), amount).await?;
    println!("Wallet funded with {} SOV, tx: {}", amount, funding_tx);
    Ok(())
}
```

2. **Adjust Payment Schedule:**
```rust
let upload_req = UploadRequest {
    storage_requirements: ContentStorageRequirements {
        budget_constraints: BudgetConstraints {
            max_total_cost: 1000, // Lower cost
            max_cost_per_gb_day: 50, // Lower daily rate
            preferred_payment_schedule: PaymentSchedule::Monthly, // Spread payments
        },
        // ... other fields
    },
    // ... other fields
};
```

3. **Use Free/Demo Storage:**
```rust
let config = UnifiedStorageConfig {
    economic_config: EconomicManagerConfig {
        enable_free_tier: true,
        free_tier_limit_gb: 1, // 1GB free
        free_tier_duration_days: 7, // 7 days free
        // ... other settings
    },
    // ... other settings
};
```

### Performance Issues

#### Problem: "Slow upload/download speeds"

**Symptoms:**
- Operations take much longer than expected
- Network appears healthy but transfers are slow
- High CPU/memory usage during transfers

**Diagnosis:**
```rust
use std::time::Instant;

async fn benchmark_operations(storage: &mut UnifiedStorageSystem) -> Result<()> {
    let test_data = vec![0u8; 1024 * 1024]; // 1MB test data
    let identity = create_test_identity();
    
    // Benchmark upload
    let upload_start = Instant::now();
    let upload_req = create_test_upload_request(test_data.clone());
    let content_hash = storage.upload_content(upload_req, identity.clone()).await?;
    let upload_duration = upload_start.elapsed();
    
    println!("Upload: {} MB/s", 
             (test_data.len() as f64 / 1024.0 / 1024.0) / upload_duration.as_secs_f64());
    
    // Benchmark download
    let download_start = Instant::now();
    let download_req = DownloadRequest {
        content_hash,
        requester: identity,
        access_proof: None,
    };
    let downloaded_data = storage.download_content(download_req).await?;
    let download_duration = download_start.elapsed();
    
    println!("Download: {} MB/s", 
             (downloaded_data.len() as f64 / 1024.0 / 1024.0) / download_duration.as_secs_f64());
    
    Ok(())
}
```

**Solutions:**

1. **Increase Parallelism:**
```rust
let config = UnifiedStorageConfig {
    performance_config: PerformanceConfig {
        max_concurrent_uploads: 10,
        max_concurrent_downloads: 20,
        chunk_size: 1024 * 1024, // 1MB chunks
        enable_parallel_erasure: true,
        ..Default::default()
    },
    ..Default::default()
};
```

2. **Optimize Erasure Coding:**
```rust
let config = UnifiedStorageConfig {
    erasure_config: ErasureConfig {
        data_shards: 4,   // Reduce for faster encoding
        parity_shards: 2, // Reduce redundancy for speed
        enable_sse: true, // Use SIMD optimizations
    },
    ..Default::default()
};
```

3. **Tune Compression:**
```rust
let upload_req = UploadRequest {
    compress: true,
    compression_level: 3, // Fast compression (1-9 scale)
    // ... other fields
};
```

### Identity and Access Issues

#### Problem: "Access denied" or "Authentication failed"

**Symptoms:**
- Cannot access uploaded content
- Permission errors
- Identity verification failures

**Diagnosis:**
```rust
async fn diagnose_access_issues(
    storage: &mut UnifiedStorageSystem,
    content_hash: &ContentHash,
    identity: &ZhtpIdentity
) -> Result<()> {
    // Check content permissions
    let metadata = storage.get_content_metadata(content_hash.clone()).await?;
    println!("Content owner: {:?}", metadata.owner);
    println!("Public read: {}", metadata.access_control.public_read);
    println!("Read permissions: {:?}", metadata.access_control.read_permissions);
    
    // Check identity
    let identity_info = storage.get_identity_info(identity).await?;
    println!("Identity valid: {}", identity_info.is_valid);
    println!("Identity reputation: {}", identity_info.reputation);
    
    // Check access permissions
    let has_access = storage.check_access_permission(content_hash.clone(), identity.clone()).await?;
    println!("Has access: {}", has_access);
    
    Ok(())
}
```

**Solutions:**

1. **Update Access Permissions:**
```rust
async fn grant_access(
    storage: &mut UnifiedStorageSystem,
    content_hash: ContentHash,
    owner_identity: ZhtpIdentity,
    target_identity: ZhtpIdentity
) -> Result<()> {
    let access_update = AccessControlUpdate {
        content_hash,
        add_read_permissions: vec![target_identity],
        remove_read_permissions: vec![],
        make_public: false,
    };
    
    storage.update_access_control(access_update, owner_identity).await?;
    println!("Access granted successfully");
    Ok(())
}
```

2. **Verify Identity:**
```rust
async fn refresh_identity(identity: &mut ZhtpIdentity) -> Result<()> {
    // Refresh identity certificates/proofs
    identity.refresh_credentials().await?;
    
    // Re-sign identity
    identity.sign_with_current_key().await?;
    
    println!("Identity refreshed");
    Ok(())
}
```

##  Debugging Tools

### Enable Debug Logging

```rust
use tracing::{info, debug, warn, error};
use tracing_subscriber::{fmt, EnvFilter};

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("lib_storage=debug".parse().unwrap())
            .add_directive("lib_dht=debug".parse().unwrap())
            .add_directive("lib_network=info".parse().unwrap()))
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();
}

// Set environment variable for detailed logging
// RUST_LOG=lib_storage=debug,lib_dht=debug
```

### Network Diagnostic Tool

```rust
use std::time::Duration;
use tokio::time::timeout;

pub struct NetworkDiagnostic {
    storage: UnifiedStorageSystem,
}

impl NetworkDiagnostic {
    pub async fn run_full_diagnostic(&mut self) -> Result<DiagnosticReport> {
        let mut report = DiagnosticReport::new();
        
        // Test 1: Network connectivity
        report.network_test = self.test_network_connectivity().await?;
        
        // Test 2: DHT functionality
        report.dht_test = self.test_dht_operations().await?;
        
        // Test 3: Storage operations
        report.storage_test = self.test_storage_operations().await?;
        
        // Test 4: Economic operations
        report.economic_test = self.test_economic_operations().await?;
        
        // Test 5: Performance benchmarks
        report.performance_test = self.test_performance().await?;
        
        Ok(report)
    }
    
    async fn test_network_connectivity(&mut self) -> Result<NetworkTestResult> {
        let start = std::time::Instant::now();
        
        // Test basic connectivity
        let stats = timeout(Duration::from_secs(10), self.storage.get_statistics()).await??;
        
        let connectivity_score = if stats.dht_stats.total_nodes > 0 {
            stats.dht_stats.network_health
        } else {
            0.0
        };
        
        Ok(NetworkTestResult {
            success: connectivity_score > 0.5,
            latency: start.elapsed(),
            connected_nodes: stats.dht_stats.total_nodes,
            network_health: connectivity_score,
            message: if connectivity_score > 0.8 {
                "Network connectivity excellent".to_string()
            } else if connectivity_score > 0.5 {
                "Network connectivity acceptable".to_string()
            } else {
                "Network connectivity poor".to_string()
            },
        })
    }
    
    async fn test_storage_operations(&mut self) -> Result<StorageTestResult> {
        let test_data = b"diagnostic test data";
        let identity = create_test_identity();
        
        // Test upload
        let upload_start = std::time::Instant::now();
        let upload_req = UploadRequest {
            content: test_data.to_vec(),
            filename: "diagnostic_test.txt".to_string(),
            mime_type: "text/plain".to_string(),
            description: "Diagnostic test file".to_string(),
            tags: vec!["diagnostic".to_string()],
            encrypt: false,
            compress: false,
            access_control: AccessControlSettings {
                public_read: true,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 1,
                quality_requirements: QualityRequirements::default(),
                budget_constraints: BudgetConstraints {
                    max_total_cost: 1000,
                    max_cost_per_gb_day: 100,
                    preferred_payment_schedule: PaymentSchedule::Upfront,
                },
            },
        };
        
        let content_hash = match timeout(Duration::from_secs(30), 
                                       self.storage.upload_content(upload_req, identity.clone())).await {
            Ok(Ok(hash)) => hash,
            Ok(Err(e)) => return Ok(StorageTestResult {
                success: false,
                upload_time: upload_start.elapsed(),
                download_time: Duration::default(),
                message: format!("Upload failed: {}", e),
            }),
            Err(_) => return Ok(StorageTestResult {
                success: false,
                upload_time: upload_start.elapsed(),
                download_time: Duration::default(),
                message: "Upload timed out".to_string(),
            }),
        };
        
        let upload_time = upload_start.elapsed();
        
        // Test download
        let download_start = std::time::Instant::now();
        let download_req = DownloadRequest {
            content_hash,
            requester: identity,
            access_proof: None,
        };
        
        let downloaded_data = match timeout(Duration::from_secs(30), 
                                          self.storage.download_content(download_req)).await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Ok(StorageTestResult {
                success: false,
                upload_time,
                download_time: download_start.elapsed(),
                message: format!("Download failed: {}", e),
            }),
            Err(_) => return Ok(StorageTestResult {
                success: false,
                upload_time,
                download_time: download_start.elapsed(),
                message: "Download timed out".to_string(),
            }),
        };
        
        let download_time = download_start.elapsed();
        
        let success = downloaded_data == test_data;
        
        Ok(StorageTestResult {
            success,
            upload_time,
            download_time,
            message: if success {
                format!("Storage operations successful (up: {:?}, down: {:?})", upload_time, download_time)
            } else {
                "Data integrity check failed".to_string()
            },
        })
    }
}

#[derive(Debug)]
pub struct DiagnosticReport {
    pub network_test: NetworkTestResult,
    pub dht_test: DhtTestResult,
    pub storage_test: StorageTestResult,
    pub economic_test: EconomicTestResult,
    pub performance_test: PerformanceTestResult,
}

#[derive(Debug)]
pub struct NetworkTestResult {
    pub success: bool,
    pub latency: Duration,
    pub connected_nodes: usize,
    pub network_health: f64,
    pub message: String,
}

#[derive(Debug)]
pub struct StorageTestResult {
    pub success: bool,
    pub upload_time: Duration,
    pub download_time: Duration,
    pub message: String,
}
```

### Configuration Validator

```rust
pub fn validate_config(config: &UnifiedStorageConfig) -> Result<Vec<ConfigWarning>> {
    let mut warnings = Vec::new();
    
    // Check network configuration
    if config.addresses.is_empty() {
        warnings.push(ConfigWarning::Error("No network addresses specified".to_string()));
    }
    
    if config.bootstrap_nodes.is_empty() {
        warnings.push(ConfigWarning::Warning("No bootstrap nodes configured - may have trouble joining network".to_string()));
    }
    
    // Check storage limits
    if config.storage_config.max_storage_size < 1024 * 1024 * 100 { // 100MB
        warnings.push(ConfigWarning::Warning("Very low storage limit may affect network participation".to_string()));
    }
    
    // Check economic settings
    if config.economic_config.base_price_per_gb_day == 0 {
        warnings.push(ConfigWarning::Warning("Zero pricing may lead to resource abuse".to_string()));
    }
    
    // Check erasure coding
    let total_shards = config.erasure_config.data_shards + config.erasure_config.parity_shards;
    if total_shards > 16 {
        warnings.push(ConfigWarning::Warning("High shard count may impact performance".to_string()));
    }
    
    if config.erasure_config.parity_shards > config.erasure_config.data_shards {
        warnings.push(ConfigWarning::Warning("More parity than data shards is usually inefficient".to_string()));
    }
    
    Ok(warnings)
}

#[derive(Debug)]
pub enum ConfigWarning {
    Error(String),
    Warning(String),
    Info(String),
}
```

## 📚 Getting Help

### Enable Comprehensive Logging

```bash
# Set environment variables for maximum debugging
export RUST_LOG=lib_storage=trace,lib_dht=debug,lib_network=debug,lib_economy=debug
export RUST_BACKTRACE=full

# Run with verbose output
cargo run --bin your_app 2>&1 | tee debug.log
```

### Collect System Information

```rust
pub async fn collect_system_info(storage: &mut UnifiedStorageSystem) -> Result<SystemInfo> {
    Ok(SystemInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        node_id: storage.get_node_id().await?,
        network_stats: storage.get_statistics().await?.dht_stats,
        storage_stats: storage.get_statistics().await?.storage_stats,
        config_summary: ConfigSummary {
            max_storage: storage.get_config().storage_config.max_storage_size,
            network_ports: storage.get_config().addresses.clone(),
            erasure_config: storage.get_config().erasure_config.clone(),
        },
        runtime_info: RuntimeInfo {
            uptime: storage.get_uptime().await?,
            memory_usage: get_memory_usage(),
            cpu_usage: get_cpu_usage(),
        },
    })
}
```

### Report Issues

When reporting issues, please include:

1. **System Information:**
   - Operating system and version
   - Rust version (`rustc --version`)
   - lib-storage version
   - Hardware specifications

2. **Configuration:**
   - Sanitized configuration file (remove private keys!)
   - Network topology
   - Storage allocation

3. **Logs:**
   - Full debug logs with timestamps
   - Network diagnostic results
   - Error messages and stack traces

4. **Reproduction Steps:**
   - Minimal code example
   - Specific operations that fail
   - Expected vs actual behavior

5. **Environment:**
   - Network conditions (bandwidth, latency)
   - Firewall/NAT configuration
   - Other running applications

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
This troubleshooting guide covers the most common issues encountered when working with ZHTP Storage. For additional support, consult the documentation or reach out to the development community.