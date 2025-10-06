//! Blockchain API Integration Tests
//!
//! Tests the blockchain API endpoints in the proper order:
//! 1. Foundation layer (core blockchain)  
//! 2. Read-only APIs (safe operations)
//! 3. State-changing APIs (write operations)
//! 4. Advanced integration APIs

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde_json::{json, Value};

// ZHTP imports
use zhtp::api::handlers::blockchain::BlockchainHandler;
use zhtp::api::server::ApiServer;
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpHeaders};

// Blockchain imports
use lib_blockchain::{Blockchain, Transaction, Block, BlockHeader, Hash, Difficulty};

/// Test helper to create a blockchain with some test data
async fn create_test_blockchain() -> Result<Arc<RwLock<Blockchain>>> {
    let mut blockchain = Blockchain::new()?;
    
    // Add a few test blocks
    for i in 1..=3 {
        let header = BlockHeader::new(
            1, // version
            blockchain.latest_block().unwrap().hash(),
            Hash::default(), // merkle_root
            blockchain.latest_block().unwrap().timestamp() + (i * 10),
            Difficulty::from_bits(0x1fffffff), // easy difficulty
            blockchain.height + 1,
            0, // tx_count
            0, // total_size
            Difficulty::from_bits(0x1fffffff),
        );
        
        let block = Block::new(header, Vec::new());
        blockchain.add_block(block)?;
    }
    
    Ok(Arc::new(RwLock::new(blockchain)))
}

/// Helper to create test HTTP request
fn create_test_request(method: ZhtpMethod, uri: &str, body: Vec<u8>) -> ZhtpRequest {
    let mut headers = ZhtpHeaders::new();
    headers.set("Content-Type", "application/json".to_string());
    
    ZhtpRequest {
        method,
        uri: uri.to_string(),
        headers,
        body,
    }
}

// =============================================================================
// PHASE 1: Foundation Layer Tests (Already covered in blockchain_tests.rs)
// =============================================================================

#[tokio::test]
async fn test_blockchain_foundation_ready() -> Result<()> {
    // Verify that the core blockchain functionality is working
    let blockchain = create_test_blockchain().await?;
    let blockchain_lock = blockchain.read().await;
    
    // Basic sanity checks
    assert_eq!(blockchain_lock.height, 3); // Genesis + 3 test blocks
    assert_eq!(blockchain_lock.blocks.len(), 4);
    assert!(blockchain_lock.latest_block().is_some());
    
    println!("Foundation layer is ready for API testing");
    Ok(())
}

// =============================================================================
// PHASE 2: Read-Only API Tests (Safe Operations)
// =============================================================================

#[tokio::test]
async fn test_blockchain_status_api() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    let request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/status",
        Vec::new(),
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_success());
    
    // Parse response body
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["status"], "active");
    assert_eq!(body["height"], 3);
    assert!(body["latest_block_hash"].is_string());
    assert!(body["total_transactions"].is_number());
    
    println!("Blockchain status API working");
    Ok(())
}

#[tokio::test]
async fn test_latest_block_api() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    let request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/latest",
        Vec::new(),
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_success());
    
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["status"], "block_found");
    assert_eq!(body["height"], 3);
    assert!(body["hash"].is_string());
    assert!(body["previous_hash"].is_string());
    
    println!("Latest block API working");
    Ok(())
}

#[tokio::test]
async fn test_get_block_by_height_api() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    // Test getting block at height 1
    let request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/block/1",
        Vec::new(),
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_success());
    
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["status"], "block_found");
    assert_eq!(body["height"], 1);
    
    println!("Get block by height API working");
    Ok(())
}

#[tokio::test]
async fn test_get_block_not_found() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    // Test getting non-existent block
    let request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/block/999",
        Vec::new(),
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_error());
    
    println!("Block not found handling working");
    Ok(())
}

#[tokio::test]
async fn test_balance_api() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    // Test with a valid hex address
    let test_address = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let request = create_test_request(
        ZhtpMethod::Get,
        &format!("/api/v1/blockchain/balance/{}", test_address),
        Vec::new(),
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_success());
    
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["status"], "balance_found");
    assert_eq!(body["address"], test_address);
    assert!(body["balance"].is_number());
    
    println!("Balance API working");
    Ok(())
}

#[tokio::test]
async fn test_validators_api() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    let request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/validators",
        Vec::new(),
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_success());
    
    let body: Value = serde_json::from_slice(&response.body)?;
    assert!(body["status"].is_string());
    assert!(body["total_validators"].is_number());
    assert!(body["validators"].is_array());
    
    println!("Validators API working");
    Ok(())
}

// =============================================================================
// PHASE 3: State-Changing API Tests (Write Operations)
// =============================================================================

#[tokio::test]
async fn test_submit_transaction_api() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    let transaction_data = json!({
        "from": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "to": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "amount": 1000,
        "fee": 10,
        "signature": "test_signature"
    });
    
    let request = create_test_request(
        ZhtpMethod::Post,
        "/api/v1/blockchain/transaction",
        serde_json::to_vec(&transaction_data)?,
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_success());
    
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["status"], "transaction_submitted");
    assert!(body["transaction_hash"].is_string());
    
    println!("Submit transaction API working");
    Ok(())
}

#[tokio::test]
async fn test_submit_invalid_transaction() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    // Invalid transaction with zero amount
    let transaction_data = json!({
        "from": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "to": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "amount": 0, // Invalid: zero amount
        "fee": 10,
        "signature": "test_signature"
    });
    
    let request = create_test_request(
        ZhtpMethod::Post,
        "/api/v1/blockchain/transaction",
        serde_json::to_vec(&transaction_data)?,
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_error());
    
    println!("Invalid transaction rejection working");
    Ok(())
}

// =============================================================================
// PHASE 4: Advanced Integration API Tests (Complex Operations)
// =============================================================================

#[tokio::test]
async fn test_api_error_handling() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    // Test unsupported endpoint
    let request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/nonexistent",
        Vec::new(),
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_error());
    
    println!("API error handling working");
    Ok(())
}

#[tokio::test]
async fn test_api_headers() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    let request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/status",
        Vec::new(),
    );
    
    let response = handler.handle_request(request).await?;
    assert!(response.status.is_success());
    
    // Check that proper headers are set
    assert_eq!(response.headers.get("X-Handler"), Some("Blockchain"));
    assert_eq!(response.headers.get("X-Protocol"), Some("ZHTP/1.0"));
    
    println!("API headers working");
    Ok(())
}

// =============================================================================
// Integration Test: Complete API Flow
// =============================================================================

#[tokio::test]
async fn test_complete_api_flow() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    // 1. Check initial status
    let status_request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/status",
        Vec::new(),
    );
    let status_response = handler.handle_request(status_request).await?;
    assert!(status_response.status.is_success());
    
    // 2. Get latest block
    let latest_request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/latest",
        Vec::new(),
    );
    let latest_response = handler.handle_request(latest_request).await?;
    assert!(latest_response.status.is_success());
    
    // 3. Submit a transaction
    let transaction_data = json!({
        "from": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "to": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "amount": 1000,
        "fee": 10,
        "signature": "test_signature"
    });
    
    let tx_request = create_test_request(
        ZhtpMethod::Post,
        "/api/v1/blockchain/transaction",
        serde_json::to_vec(&transaction_data)?,
    );
    let tx_response = handler.handle_request(tx_request).await?;
    assert!(tx_response.status.is_success());
    
    // 4. Check validators
    let validators_request = create_test_request(
        ZhtpMethod::Get,
        "/api/v1/blockchain/validators",
        Vec::new(),
    );
    let validators_response = handler.handle_request(validators_request).await?;
    assert!(validators_response.status.is_success());
    
    println!("Complete API flow working");
    Ok(())
}

// =============================================================================
// Performance and Stress Tests
// =============================================================================

#[tokio::test]
async fn test_concurrent_api_requests() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = Arc::new(BlockchainHandler::new(blockchain));
    
    // Create multiple concurrent requests
    let mut tasks = Vec::new();
    
    for i in 0..10 {
        let handler_clone = handler.clone();
        let task = tokio::spawn(async move {
            let request = create_test_request(
                ZhtpMethod::Get,
                "/api/v1/blockchain/status",
                Vec::new(),
            );
            handler_clone.handle_request(request).await
        });
        tasks.push(task);
    }
    
    // Wait for all tasks to complete
    let results = futures::future::join_all(tasks).await;
    
    // All requests should succeed
    for result in results {
        let response = result??;
        assert!(response.status.is_success());
    }
    
    println!("Concurrent API requests working");
    Ok(())
}

#[tokio::test]
async fn test_api_performance() -> Result<()> {
    let blockchain = create_test_blockchain().await?;
    let handler = BlockchainHandler::new(blockchain);
    
    let start = std::time::Instant::now();
    
    // Perform 100 status requests
    for _ in 0..100 {
        let request = create_test_request(
            ZhtpMethod::Get,
            "/api/v1/blockchain/status",
            Vec::new(),
        );
        let response = handler.handle_request(request).await?;
        assert!(response.status.is_success());
    }
    
    let duration = start.elapsed();
    println!("100 status requests took: {:?}", duration);
    
    // Should complete reasonably quickly (adjust threshold as needed)
    assert!(duration.as_millis() < 5000, "API performance too slow");
    
    println!("API performance acceptable");
    Ok(())
}