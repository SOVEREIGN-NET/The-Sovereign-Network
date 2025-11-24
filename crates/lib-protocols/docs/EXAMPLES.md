# Examples

This document provides practical examples for common use cases with `lib-protocols`.

## Table of Contents

1. [Basic ZHTP Server](#basic-zhtp-server)
2. [Custom Request Handler](#custom-request-handler)
3. [ZDNS Domain Registration](#zdns-domain-registration)
4. [Secure Wallet Transfer](#secure-wallet-transfer)
5. [Content Storage and Retrieval](#content-storage-and-retrieval)
6. [Zero-Knowledge Authentication](#zero-knowledge-authentication)
7. [Economic Fee Calculation](#economic-fee-calculation)
8. [Full Integration Example](#full-integration-example)

---

## Basic ZHTP Server

Create and start a basic ZHTP server:

```rust
use lib_protocols::{ZhtpServer, ServerConfig};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure the server
    let config = ServerConfig {
        host: "0.0.0.0".to_string(),
        port: 9333,
        max_connections: 1000,
        request_timeout: 30,
        enable_tls: true,
        enable_compression: true,
        worker_threads: 4,
    };

    // Create and start the server
    let server = ZhtpServer::new(config);
    println!("Starting ZHTP server on port 9333...");
    
    server.start().await?;
    
    Ok(())
}
```

---

## Custom Request Handler

Implement a custom request handler:

```rust
use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpHeaders};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use async_trait::async_trait;

pub struct CustomHandler;

#[async_trait]
impl ZhtpRequestHandler for CustomHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Process the request
        let response_body = format!("Received {} request to {}", 
                                   request.method, request.uri);
        
        // Create response
        let mut headers = ZhtpHeaders::new();
        headers.set("Content-Type", "text/plain".to_string());
        
        Ok(ZhtpResponse {
            version: "1.0".to_string(),
            status: ZhtpStatus::Ok,
            status_message: "OK".to_string(),
            headers,
            body: response_body.into_bytes(),
            timestamp: request.timestamp,
            server: Some("Custom ZHTP Server".to_string()),
            validity_proof: None,
        })
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/custom")
    }
    
    fn priority(&self) -> u32 {
        200 // Higher priority than default
    }
}

// Usage
#[tokio::main]
async fn main() -> Result<()> {
    let mut server = ZhtpServer::new(ServerConfig::default());
    server.register_handler(CustomHandler);
    server.start().await?;
    Ok(())
}
```

---

## ZDNS Domain Registration

Register a new Web4 domain:

```rust
use lib_protocols::zdns::{ZdnsServer, ZdnsConfig, ZdnsRecord, ZdnsRecordType};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create ZDNS server
    let mut server = ZdnsServer::new(ZdnsConfig::default());
    
    // Create domain record
    let record = ZdnsRecord {
        name: "myapp.zhtp".to_string(),
        record_type: ZdnsRecordType::A,
        value: "192.168.1.100".to_string(),
        ttl: 3600,
        ownership_proof: "zk_proof_data_here".to_string(),
        pq_signature: "post_quantum_signature".to_string(),
        dao_fee_proof: "dao_fee_payment_proof".to_string(),
        priority: None,
        weight: None,
        port: None,
        target: None,
        metadata: Default::default(),
    };
    
    // Register the record
    server.register_record(record).await?;
    println!("Domain myapp.zhtp registered successfully!");
    
    Ok(())
}
```

---

## Secure Wallet Transfer

Perform a secure wallet transfer with signature verification:

```rust
use lib_protocols::secure_transfer::{SecureWalletTransferHandler, SecureTransferRequest};
use lib_protocols::{ZhtpRequest, ZhtpMethod, ZhtpHeaders};
use base64::{Engine as _, engine::general_purpose};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create transfer handler
    let handler = SecureWalletTransferHandler::new();
    
    // Prepare transfer request (normally this comes from client)
    let transfer = SecureTransferRequest {
        from: "alice.zhtp".to_string(),
        to: "bob.zhtp".to_string(),
        amount: 100.0,
        signature: general_purpose::STANDARD.encode(b"client_signature"),
        public_key: general_purpose::STANDARD.encode(b"client_public_key"),
        signed_transaction: general_purpose::STANDARD.encode(b"signed_tx_data"),
    };
    
    // Serialize transfer request
    let body = serde_json::to_vec(&transfer)?;
    
    // Create ZHTP request
    let mut headers = ZhtpHeaders::new();
    headers.set("Content-Type", "application/json".to_string());
    
    let request = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/wallet/transfer".to_string(),
        version: "1.0".to_string(),
        headers,
        body,
        timestamp: 1234567890,
        requester: None,
        auth_proof: None,
    };
    
    // Process transfer
    let response = handler.handle_request(request).await?;
    println!("Transfer status: {:?}", response.status);
    
    Ok(())
}
```

---

## Content Storage and Retrieval

Store and retrieve content using the storage integration:

```rust
use lib_protocols::storage::{StorageIntegration, StorageConfig};
use lib_protocols::types::ContentMetadata;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize storage
    let storage = StorageIntegration::new(StorageConfig::default()).await?;
    
    // Prepare content
    let content = b"Hello, Web4! This is my content.";
    let metadata = ContentMetadata {
        filename: Some("greeting.txt".to_string()),
        size: content.len(),
        mime_type: "text/plain".to_string(),
        encoding: None,
        language: Some("en".to_string()),
        tags: vec!["greeting".to_string(), "test".to_string()],
        description: Some("A simple greeting".to_string()),
        version: 1,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        author: Some("alice.zhtp".to_string()),
    };
    
    // Store content
    let content_id = storage.store_content(content, metadata).await?;
    println!("Content stored with ID: {}", content_id);
    
    // Retrieve content
    let retrieved = storage.retrieve_content(&content_id).await?;
    println!("Retrieved: {}", String::from_utf8_lossy(&retrieved.data));
    
    Ok(())
}
```

---

## Zero-Knowledge Authentication

Authenticate using zero-knowledge proofs:

```rust
use lib_protocols::identity::{ProtocolIdentityService, IdentityServiceConfig};
use lib_protocols::crypto::ZhtpCrypto;
use lib_identity::IdentityManager;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize identity service
    let identity_manager = IdentityManager::new();
    let identity_service = ProtocolIdentityService::new(
        identity_manager,
        IdentityServiceConfig::default(),
    );
    
    // Initialize crypto
    let crypto = ZhtpCrypto::new()?;
    
    // Generate identity proof (simplified)
    let identity_id = "alice.zhtp".to_string();
    let proof_data = b"zk_identity_proof_data";
    
    // Verify the proof
    let valid = crypto.verify_zk_proof(proof_data, b"public_inputs")?;
    
    if valid {
        println!("Identity verified for {}", identity_id);
        // Create session, grant access, etc.
    } else {
        println!("Identity verification failed");
    }
    
    Ok(())
}
```

---

## Economic Fee Calculation

Calculate fees for various operations:

```rust
use lib_protocols::economics::{ZhtpEconomics, EconomicConfig};
use lib_economy::Priority;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize economics
    let econ = ZhtpEconomics::new(EconomicConfig::default())?;
    
    // Calculate fees for different operations
    let operations = vec![
        ("GET", 1024, Priority::Normal),
        ("POST", 4096, Priority::High),
        ("PUT", 8192, Priority::Urgent),
        ("DELETE", 0, Priority::Low),
    ];
    
    for (op, size, priority) in operations {
        let assessment = econ.calculate_operation_fees(op, size, priority)?;
        
        println!("\n{} operation ({} bytes, {:?} priority):", op, size, priority);
        println!("  Base fee: {} ZHTP", assessment.base_fee);
        println!("  DAO fee: {} ZHTP", assessment.dao_fee);
        println!("  Network fee: {} ZHTP", assessment.network_fee);
        println!("  Total: {} ZHTP", assessment.total_fee);
    }
    
    Ok(())
}
```

---

## Full Integration Example

Complete example with all components:

```rust
use lib_protocols::integration::{ZhtpIntegration, IntegrationConfig};
use lib_protocols::{ZhtpRequest, ZhtpMethod, ZhtpHeaders};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize integrated system
    let mut integration = ZhtpIntegration::new(IntegrationConfig {
        node_id: None,
        blockchain_enabled: true,
        identity_enabled: true,
        consensus_enabled: true,
        mesh_enabled: true,
        monitoring_enabled: true,
        timeout_seconds: 30,
    }).await?;
    
    println!(" Integration initialized");
    
    // Create a sample request
    let mut headers = ZhtpHeaders::new();
    headers.set("Content-Type", "application/json".to_string());
    headers.set("X-Priority", "high".to_string());
    
    let request = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/data/store".to_string(),
        version: "1.0".to_string(),
        headers,
        body: b"Sample data to store".to_vec(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        requester: None,
        auth_proof: None,
    };
    
    println!("→ Sending request: {} {}", request.method, request.uri);
    
    // Process through integrated system
    let response = integration.process_integrated_request(request).await?;
    
    println!("← Response status: {:?}", response.status);
    println!("← Response body: {}", String::from_utf8_lossy(&response.body));
    
    // Get statistics
    let stats = integration.get_stats();
    println!("\nIntegration Statistics:");
    println!("  Total requests: {}", stats.total_requests);
    println!("  Successful: {}", stats.successful_requests);
    println!("  Failed: {}", stats.failed_requests);
    
    Ok(())
}
```

---

## Testing Example

Using the testing utilities:

```rust
#[cfg(feature = "testing")]
use lib_protocols::testing::{MockZhtpServer, TestConfig};
use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpStatus, ZhtpHeaders};
use anyhow::Result;

#[cfg(feature = "testing")]
#[tokio::test]
async fn test_request_handling() -> Result<()> {
    // Create mock server
    let mut mock = MockZhtpServer::new(TestConfig::default());
    
    // Add predefined response
    let mut headers = ZhtpHeaders::new();
    headers.set("Content-Type", "application/json".to_string());
    
    let mock_response = ZhtpResponse {
        version: "1.0".to_string(),
        status: ZhtpStatus::Ok,
        status_message: "OK".to_string(),
        headers,
        body: b"{\"success\": true}".to_vec(),
        timestamp: 1234567890,
        server: Some("Mock".to_string()),
        validity_proof: None,
    };
    
    mock.add_response("GET /test", mock_response);
    
    // Create test request
    let request = ZhtpRequest {
        method: ZhtpMethod::Get,
        uri: "/test".to_string(),
        version: "1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: vec![],
        timestamp: 1234567890,
        requester: None,
        auth_proof: None,
    };
    
    // Process request
    let response = mock.process_request(request).await?;
    
    // Assert response
    assert_eq!(response.status, ZhtpStatus::Ok);
    assert_eq!(response.body, b"{\"success\": true}");
    
    // Check recorded requests
    assert_eq!(mock.get_recorded_requests().len(), 1);
    
    Ok(())
}
```

---

## Best Practices

### 1. Always Validate Requests

```rust
let validator = ZhtpValidator::new(ValidationConfig::default());
let validation = validator.validate_request(&request).await?;
if !validation.valid {
    return Err(anyhow::anyhow!("Invalid request"));
}
```

### 2. Handle Economic Fees

```rust
let econ = ZhtpEconomics::new(EconomicConfig::default())?;
let fees = econ.calculate_operation_fees(...)?;
// Ensure fees are paid before processing
```

### 3. Use Proper Error Handling

```rust
match integration.process_integrated_request(request).await {
    Ok(response) => {
        // Handle success
    },
    Err(e) => {
        eprintln!("Error: {}", e);
        // Return error response
    }
}
```

### 4. Implement Proper Logging

```rust
use tracing::{info, warn, error};

info!("Processing request: {} {}", request.method, request.uri);
warn!("High load detected");
error!("Request processing failed: {}", err);
```

---

For more examples, see the tests in the source code and the API reference documentation.
