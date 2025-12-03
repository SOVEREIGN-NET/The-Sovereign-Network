//! Testing Utilities for ZHTP Protocols
//! 
//! Comprehensive testing framework for ZHTP protocol components,
//! including mock implementations, test fixtures, and integration test helpers.

#![cfg(feature = "testing")]

use crate::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpStatus, ZhtpHeaders};
use crate::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Test configuration for ZHTP protocol testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    /// Enable mock blockchain
    pub mock_blockchain: bool,
    /// Enable mock economics
    pub mock_economics: bool,
    /// Enable mock storage
    pub mock_storage: bool,
    /// Enable mock mesh networking
    pub mock_mesh: bool,
    /// Test timeout in seconds
    pub timeout_seconds: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            mock_blockchain: true,
            mock_economics: true,
            mock_storage: true,
            mock_mesh: true,
            timeout_seconds: 30,
        }
    }
}

/// Mock ZHTP server for testing
#[derive(Debug)]
pub struct MockZhtpServer {
    /// Test configuration
    config: TestConfig,
    /// Recorded requests
    recorded_requests: Vec<ZhtpRequest>,
    /// Predefined responses
    responses: HashMap<String, ZhtpResponse>,
    /// Test statistics
    stats: TestStats,
}

impl MockZhtpServer {
    /// Create new mock server
    pub fn new(config: TestConfig) -> Self {
        Self {
            config,
            recorded_requests: Vec::new(),
            responses: HashMap::new(),
            stats: TestStats::default(),
        }
    }

    /// Add predefined response for a request pattern
    pub fn add_response(&mut self, pattern: &str, response: ZhtpResponse) {
        self.responses.insert(pattern.to_string(), response);
    }

    /// Process mock request
    pub async fn process_request(&mut self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Record the request
        self.recorded_requests.push(request.clone());
        self.stats.total_requests += 1;

        // Find matching response
        let pattern = format!("{} {}", request.method, request.uri);
        if let Some(response) = self.responses.get(&pattern) {
            return Ok(response.clone());
        }

        // Default response
        Ok(ZhtpResponse {
            version: "1.0".to_string(),
            status: ZhtpStatus::Ok,
            status_message: "Mock response".to_string(),
            headers: ZhtpHeaders::new(),
            body: b"Mock response".to_vec(),
            timestamp: request.timestamp,
            server: None,
            validity_proof: None,
        })
    }

    /// Get recorded requests
    pub fn get_recorded_requests(&self) -> &[ZhtpRequest] {
        &self.recorded_requests
    }

    /// Clear recorded requests
    pub fn clear_requests(&mut self) {
        self.recorded_requests.clear();
    }

    /// Get test statistics
    pub fn get_stats(&self) -> &TestStats {
        &self.stats
    }
}

/// Test statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestStats {
    /// Total requests processed
    pub total_requests: u64,
    /// Successful responses
    pub successful_responses: u64,
    /// Failed responses
    pub failed_responses: u64,
    /// Average response time (ms)
    pub avg_response_time_ms: u64,
}

/// Request builder for testing
#[derive(Debug, Clone)]
pub struct TestRequestBuilder {
    method: ZhtpMethod,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    timestamp: Option<u64>,
}

impl TestRequestBuilder {
    /// Create new request builder
    pub fn new(method: ZhtpMethod, path: &str) -> Self {
        Self {
            method,
            path: path.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
            timestamp: None,
        }
    }

    /// Add header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Set body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Set JSON body
    pub fn json_body<T: Serialize>(mut self, data: &T) -> Result<Self> {
        self.body = serde_json::to_vec(data)
            .map_err(|e| ProtocolError::InvalidRequest(format!("JSON serialization failed: {}", e)))?;
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        Ok(self)
    }

    /// Set timestamp
    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Build the request
    pub fn build(self) -> ZhtpRequest {
        let mut lib_headers = ZhtpHeaders::new();
        for (key, value) in self.headers {
            lib_headers.set(&key, value);
        }
        
        ZhtpRequest {
            method: self.method,
            uri: self.path,
            version: "1.0".to_string(),
            headers: lib_headers,
            body: self.body,
            timestamp: self.timestamp.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            }),
            requester: None,
            auth_proof: None,
        }
    }
}

/// Response builder for testing
#[derive(Debug, Clone)]
pub struct TestResponseBuilder {
    status: ZhtpStatus,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl TestResponseBuilder {
    /// Create new response builder
    pub fn new(status: ZhtpStatus) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Add header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Set body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Set JSON body
    pub fn json_body<T: Serialize>(mut self, data: &T) -> Result<Self> {
        self.body = serde_json::to_vec(data)
            .map_err(|e| ProtocolError::InvalidRequest(format!("JSON serialization failed: {}", e)))?;
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        Ok(self)
    }

    /// Build the response
    pub fn build(self) -> ZhtpResponse {
        let mut lib_headers = ZhtpHeaders::new();
        for (key, value) in self.headers {
            lib_headers.set(&key, value);
        }
        
        ZhtpResponse {
            version: "1.0".to_string(),
            status: self.status,
            status_message: "Test response".to_string(),
            headers: lib_headers,
            body: self.body,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            server: None,
            validity_proof: None,
        }
    }
}

/// Test fixtures for common scenarios
pub mod fixtures {
    use super::*;

    /// Create a test GET request
    pub fn test_get_request() -> ZhtpRequest {
        TestRequestBuilder::new(ZhtpMethod::Get, "/api/test")
            .header("User-Agent", "ZHTP-Test/1.0")
            .build()
    }

    /// Create a test POST request with JSON body
    pub fn test_post_request() -> ZhtpRequest {
        let data = serde_json::json!({
            "test": true,
            "message": "Hello ZHTP"
        });
        
        TestRequestBuilder::new(ZhtpMethod::Post, "/api/data")
            .json_body(&data)
            .unwrap()
            .build()
    }

    /// Create a test successful response
    pub fn test_success_response() -> ZhtpResponse {
        TestResponseBuilder::new(ZhtpStatus::Ok)
            .header("Content-Type", "application/json")
            .json_body(&serde_json::json!({
                "success": true,
                "message": "Test successful"
            }))
            .unwrap()
            .build()
    }

    /// Create a test error response
    pub fn test_error_response() -> ZhtpResponse {
        TestResponseBuilder::new(ZhtpStatus::BadRequest)
            .header("Content-Type", "application/json")
            .json_body(&serde_json::json!({
                "error": "Test error",
                "code": 400
            }))
            .unwrap()
            .build()
    }

    /// Create wallet operation test request
    pub fn test_wallet_request() -> ZhtpRequest {
        let mut parameters = std::collections::HashMap::new();
        parameters.insert("token_type".to_string(), "SOV".to_string());
        parameters.insert("network".to_string(), "mainnet".to_string());
        
        // Create a simple test wallet operation (API types moved to zhtp)
        let wallet_op = serde_json::json!({
            "operation": "GetBalance",
            "wallet_address": "0x1234567890abcdef",
            "amount": null,
            "recipient": null,
            "parameters": parameters,
        });

        TestRequestBuilder::new(ZhtpMethod::Post, "/api/wallet/operation")
            .json_body(&wallet_op)
            .unwrap()
            .build()
    }

    /// Create DAO operation test request
    pub fn test_dao_request() -> ZhtpRequest {
        let mut parameters = std::collections::HashMap::new();
        parameters.insert("stake_amount".to_string(), "1000".to_string());
        
        // Create a simple test DAO operation (API types moved to zhtp)
        let dao_op = serde_json::json!({
            "operation": "Vote",
            "dao_id": "dao_123",
            "proposal_id": "prop_123",
            "vote": "Yes",
            "parameters": parameters,
        });

        TestRequestBuilder::new(ZhtpMethod::Post, "/api/dao/operation")
            .json_body(&dao_op)
            .unwrap()
            .build()
    }
}

/// Mock implementations for testing
pub mod mocks {
    use super::*;

    /// Mock crypto implementation
    pub struct MockCrypto;

    impl MockCrypto {
        pub fn verify_signature(&self, _data: &[u8], _signature: &[u8]) -> bool {
            true // Always valid in tests
        }

        pub fn generate_proof(&self, _data: &[u8]) -> Vec<u8> {
            b"mock_proof".to_vec()
        }
    }

    /// Mock economics implementation
    pub struct MockEconomics;

    impl MockEconomics {
        pub fn calculate_fee(&self, _size: usize) -> u64 {
            100 // Fixed fee for tests
        }

        pub fn validate_dao_fee(&self, _amount: u64) -> bool {
            true // Always valid in tests
        }
    }

    /// Mock storage implementation
    pub struct MockStorage {
        storage: HashMap<String, Vec<u8>>,
    }

    impl MockStorage {
        pub fn new() -> Self {
            Self {
                storage: HashMap::new(),
            }
        }

        pub fn store(&mut self, _key: &str, data: Vec<u8>) -> String {
            let id = Uuid::new_v4().to_string();
            self.storage.insert(id.clone(), data);
            id
        }

        pub fn retrieve(&self, id: &str) -> Option<Vec<u8>> {
            self.storage.get(id).cloned()
        }

        pub fn delete(&mut self, id: &str) -> bool {
            self.storage.remove(id).is_some()
        }
    }

    impl Default for MockStorage {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Test utilities
pub mod utils {
    use super::*;

    /// Generate test data of specified size
    pub fn generate_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    /// Generate random test string
    pub fn generate_test_string(length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        
        let mut rng = rand::rngs::OsRng;
        
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Create test timestamp
    pub fn test_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Create test timestamp in the past
    pub fn test_timestamp_past(seconds_ago: u64) -> u64 {
        test_timestamp().saturating_sub(seconds_ago)
    }

    /// Create test timestamp in the future
    pub fn test_timestamp_future(seconds_ahead: u64) -> u64 {
        test_timestamp() + seconds_ahead
    }

    /// Assert request matches pattern
    pub fn assert_request_matches(request: &ZhtpRequest, method: ZhtpMethod, path: &str) {
        assert_eq!(request.method, method);
        assert_eq!(request.uri, path);
    }

    /// Assert response has status
    pub fn assert_response_status(response: &ZhtpResponse, status: ZhtpStatus) {
        assert_eq!(response.status, status);
    }

    /// Assert response contains header
    pub fn assert_response_header(response: &ZhtpResponse, key: &str, value: &str) {
        assert_eq!(response.headers.get(key), Some(value.to_string()));
    }
}

/// Integration test helpers
pub mod integration {
    use super::*;

    /// Test scenario runner
    pub struct TestScenario {
        name: String,
        requests: Vec<ZhtpRequest>,
        expected_responses: Vec<ZhtpStatus>,
    }

    impl TestScenario {
        pub fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                requests: Vec::new(),
                expected_responses: Vec::new(),
            }
        }

        pub fn add_request(mut self, request: ZhtpRequest, expected_status: ZhtpStatus) -> Self {
            self.requests.push(request);
            self.expected_responses.push(expected_status);
            self
        }

        pub async fn run(&self, server: &mut MockZhtpServer) -> Result<()> {
            println!("Running test scenario: {}", self.name);
            
            for (i, request) in self.requests.iter().enumerate() {
                let response = server.process_request(request.clone()).await?;
                let expected_status = &self.expected_responses[i];
                
                if response.status != *expected_status {
                    return Err(ProtocolError::InternalError(
                        format!("Step {}: Expected {:?}, got {:?}", i + 1, expected_status, response.status)
                    ));
                }
            }
            
            println!("Test scenario '{}' completed successfully", self.name);
            Ok(())
        }
    }

    /// Create comprehensive test scenarios
    pub fn create_wallet_test_scenario() -> TestScenario {
        TestScenario::new("Wallet Operations")
            .add_request(fixtures::test_wallet_request(), ZhtpStatus::Ok)
            .add_request(fixtures::test_get_request(), ZhtpStatus::Ok)
    }

    pub fn create_dao_test_scenario() -> TestScenario {
        TestScenario::new("DAO Operations")
            .add_request(fixtures::test_dao_request(), ZhtpStatus::Ok)
            .add_request(fixtures::test_get_request(), ZhtpStatus::Ok)
    }

    pub fn create_storage_test_scenario() -> TestScenario {
        TestScenario::new("Storage Operations")
            .add_request(fixtures::test_post_request(), ZhtpStatus::Ok)
            .add_request(fixtures::test_get_request(), ZhtpStatus::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server() {
        let config = TestConfig::default();
        let mut server = MockZhtpServer::new(config);
        
        let request = fixtures::test_get_request();
        let response = server.process_request(request).await.unwrap();
        
        assert_eq!(response.status, ZhtpStatus::Ok);
        assert_eq!(server.get_recorded_requests().len(), 1);
    }

    #[test]
    fn test_request_builder() {
        let request = TestRequestBuilder::new(ZhtpMethod::Get, "/test")
            .header("Test", "Value")
            .body(b"test body".to_vec())
            .build();
        
        assert_eq!(request.method, ZhtpMethod::Get);
        assert_eq!(request.uri, "/test");
        assert_eq!(request.headers.get("Test"), Some("Value".to_string()));
        assert_eq!(request.body, b"test body");
    }

    #[test]
    fn test_response_builder() {
        let response = TestResponseBuilder::new(ZhtpStatus::Ok)
            .header("Content-Type", "text/plain")
            .body(b"test response".to_vec())
            .build();
        
        assert_eq!(response.status, ZhtpStatus::Ok);
        assert_eq!(response.headers.get("Content-Type"), Some("text/plain".to_string()));
        assert_eq!(response.body, b"test response");
    }

    #[tokio::test]
    async fn test_integration_scenario() {
        let config = TestConfig::default();
        let mut server = MockZhtpServer::new(config);
        
        let scenario = integration::create_wallet_test_scenario();
        let result = scenario.run(&mut server).await;
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_storage() {
        let mut storage = mocks::MockStorage::new();
        
        let id = storage.store("test", b"test data".to_vec());
        assert!(!id.is_empty());
        
        let retrieved = storage.retrieve(&id);
        assert_eq!(retrieved, Some(b"test data".to_vec()));
        
        let deleted = storage.delete(&id);
        assert!(deleted);
        
        let not_found = storage.retrieve(&id);
        assert_eq!(not_found, None);
    }
}
