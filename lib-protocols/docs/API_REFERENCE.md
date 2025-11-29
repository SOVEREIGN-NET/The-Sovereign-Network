# API Reference

This document provides a detailed API reference for the most commonly used functions and types in `lib-protocols`.

## Table of Contents

1. [ZHTP Request/Response API](#zhtp-requestresponse-api)
2. [ZHTP Server API](#zhtp-server-api)
3. [ZDNS API](#zdns-api)
4. [Validation API](#validation-api)
5. [Integration API](#integration-api)
6. [Economic API](#economic-api)
7. [Cryptographic API](#cryptographic-api)

---

## ZHTP Request/Response API

### ZhtpRequest

```rust
pub struct ZhtpRequest {
    pub method: ZhtpMethod,
    pub uri: String,
    pub version: String,
    pub headers: ZhtpHeaders,
    pub body: Vec<u8>,
    pub timestamp: u64,
    pub requester: Option<IdentityId>,
    pub auth_proof: Option<ZkProof>,
}
```

**Methods:**
- `new(method, uri, version, headers, body)` - Create a new request
- `with_auth(identity, proof)` - Add authentication proof
- `add_header(key, value)` - Add a header
- `validate()` - Validate request structure

### ZhtpResponse

```rust
pub struct ZhtpResponse {
    pub version: String,
    pub status: ZhtpStatus,
    pub status_message: String,
    pub headers: ZhtpHeaders,
    pub body: Vec<u8>,
    pub timestamp: u64,
    pub server: Option<String>,
    pub validity_proof: Option<ZkProof>,
}
```

**Methods:**
- `new(status, body)` - Create a new response
- `with_status(status)` - Set status code
- `add_header(key, value)` - Add a header
- `with_proof(proof)` - Add validity proof

### ZhtpMethod

```rust
pub enum ZhtpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Verify,
    Query,
    Subscribe,
}
```

### ZhtpStatus

```rust
pub enum ZhtpStatus {
    Ok,                    // 200
    Created,               // 201
    Accepted,              // 202
    NoContent,             // 204
    BadRequest,            // 400
    Unauthorized,          // 401
    Forbidden,             // 403
    NotFound,              // 404
    MethodNotAllowed,      // 405
    InternalServerError,   // 500
    NotImplemented,        // 501
    ServiceUnavailable,    // 503
}
```

---

## ZHTP Server API

### ZhtpServer

```rust
pub struct ZhtpServer {
    // Internal fields
}
```

**Methods:**

```rust
impl ZhtpServer {
    /// Create a new ZHTP server
    pub fn new(config: ServerConfig) -> Self;
    
    /// Start the server
    pub async fn start(&self) -> ZhtpResult<()>;
    
    /// Stop the server
    pub async fn stop(&self) -> ZhtpResult<()>;
    
    /// Register a request handler
    pub fn register_handler<H: ZhtpRequestHandler>(&mut self, handler: H);
    
    /// Register middleware
    pub fn register_middleware<M: ZhtpMiddleware>(&mut self, middleware: M);
    
    /// Get server statistics
    pub fn get_stats(&self) -> ServerStats;
}
```

### ServerConfig

```rust
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub request_timeout: u64,
    pub enable_tls: bool,
    pub enable_compression: bool,
    pub worker_threads: usize,
}
```

**Example:**

```rust
let config = ServerConfig {
    host: "0.0.0.0".to_string(),
    port: 9333,
    max_connections: 1000,
    request_timeout: 30,
    enable_tls: true,
    enable_compression: true,
    worker_threads: 4,
};

let server = ZhtpServer::new(config);
```

---

## ZDNS API

### ZdnsServer

```rust
impl ZdnsServer {
    /// Create a new ZDNS server
    pub fn new(config: ZdnsConfig) -> Self;
    
    /// Resolve a domain query
    pub async fn resolve(&self, query: ZdnsQuery) -> ZhtpResult<ZdnsResponse>;
    
    /// Register a new domain record
    pub async fn register_record(&mut self, record: ZdnsRecord) -> ZhtpResult<()>;
    
    /// Update an existing record
    pub async fn update_record(&mut self, record: ZdnsRecord) -> ZhtpResult<()>;
    
    /// Delete a record
    pub async fn delete_record(&mut self, name: &str, record_type: ZdnsRecordType) -> ZhtpResult<()>;
}
```

### ZdnsQuery

```rust
pub struct ZdnsQuery {
    pub name: String,
    pub record_type: ZdnsRecordType,
    pub recursive: bool,
}
```

**Example:**

```rust
use lib_protocols::zdns::{ZdnsServer, ZdnsQuery, ZdnsRecordType};

let server = ZdnsServer::new(ZdnsConfig::default());
let query = ZdnsQuery {
    name: "example.zhtp".to_string(),
    record_type: ZdnsRecordType::A,
    recursive: true,
};

let response = server.resolve(query).await?;
```

---

## Validation API

### ZhtpValidator

```rust
impl ZhtpValidator {
    /// Create a new validator
    pub fn new(config: ValidationConfig) -> Self;
    
    /// Validate a request
    pub async fn validate_request(&self, request: &ZhtpRequest) -> ZhtpResult<ValidationResult>;
    
    /// Validate a response
    pub async fn validate_response(&self, response: &ZhtpResponse) -> ZhtpResult<ValidationResult>;
    
    /// Validate ZK proof
    pub fn validate_zk_proof(&self, proof: &ZkProof, public_inputs: &[u8]) -> ZhtpResult<bool>;
    
    /// Validate DAO fee
    pub fn validate_dao_fee(&self, fee: u64, operation: &str) -> ZhtpResult<bool>;
    
    /// Check rate limit
    pub fn check_rate_limit(&self, identity: &IdentityId) -> ZhtpResult<bool>;
}
```

**Example:**

```rust
let validator = ZhtpValidator::new(ValidationConfig::default());
let result = validator.validate_request(&request).await?;

if !result.valid {
    for error in result.errors {
        eprintln!("Validation error: {:?}", error);
    }
}
```

---

## Integration API

### ZhtpIntegration

```rust
impl ZhtpIntegration {
    /// Create new integrated system
    pub async fn new(config: IntegrationConfig) -> Result<Self>;
    
    /// Process a complete ZHTP request through all systems
    pub async fn process_integrated_request(&mut self, request: ZhtpRequest) -> Result<ZhtpResponse>;
    
    /// Get integration statistics
    pub fn get_stats(&self) -> IntegrationStats;
}
```

**Example:**

```rust
let integration = ZhtpIntegration::new(IntegrationConfig::default()).await?;
let response = integration.process_integrated_request(request).await?;
```

---

## Economic API

### ZhtpEconomics

```rust
impl ZhtpEconomics {
    /// Create a new economics context
    pub fn new(config: EconomicConfig) -> Result<Self>;
    
    /// Calculate fees for an operation
    pub fn calculate_operation_fees(
        &self,
        operation_type: &str,
        data_size: usize,
        priority: Priority,
    ) -> Result<EconomicAssessment>;
    
    /// Validate economic requirements
    pub fn validate_payment(&self, assessment: &EconomicAssessment) -> Result<bool>;
}
```

**Example:**

```rust
use lib_economy::Priority;

let econ = ZhtpEconomics::new(EconomicConfig::default())?;
let assessment = econ.calculate_operation_fees("POST", 2048, Priority::Normal)?;

println!("Total fee: {}", assessment.total_fee);
println!("DAO fee: {}", assessment.dao_fee);
```

---

## Cryptographic API

### ZhtpCrypto

```rust
impl ZhtpCrypto {
    /// Create a new crypto context
    pub fn new() -> Result<Self>;
    
    /// Generate a keypair
    pub fn generate_keypair() -> Result<KeyPair>;
    
    /// Hash content
    pub fn hash_content(&self, data: &[u8]) -> Hash;
    
    /// Verify signature
    pub fn verify_protocol_signature(
        &self,
        data: &[u8],
        signature: &PostQuantumSignature,
        public_key: &[u8],
    ) -> Result<bool>;
    
    /// Verify ZK proof
    pub fn verify_zk_proof(&self, proof_data: &[u8], public_inputs: &[u8]) -> Result<bool>;
}
```

**Example:**

```rust
let crypto = ZhtpCrypto::new()?;
let hash = crypto.hash_content(b"Hello, Web4!");
let valid = crypto.verify_protocol_signature(&data, &sig, &pubkey)?;
```

---

## Common Patterns

### Request-Response Pattern

```rust
async fn handle_request(request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
    // 1. Validate request
    let validator = ZhtpValidator::new(ValidationConfig::default());
    let validation = validator.validate_request(&request).await?;
    
    if !validation.valid {
        return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, "Invalid request"));
    }
    
    // 2. Calculate fees
    let econ = ZhtpEconomics::new(EconomicConfig::default())?;
    let fees = econ.calculate_operation_fees(
        request.method.as_str(),
        request.body.len(),
        Priority::Normal,
    )?;
    
    // 3. Process request
    let result = process_business_logic(&request).await?;
    
    // 4. Create response
    Ok(ZhtpResponse::success(result))
}
```

### Full Integration Pattern

```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize integrated system
    let integration = ZhtpIntegration::new(IntegrationConfig::default()).await?;
    
    // Create and process request
    let request = ZhtpRequest::new(...);
    let response = integration.process_integrated_request(request).await?;
    
    // Check response
    if response.status == ZhtpStatus::Ok {
        println!("Success!");
    }
    
    Ok(())
}
```

---

## Error Handling

All API functions return `Result` types:

```rust
pub type Result<T> = std::result::Result<T, ProtocolError>;
pub type ZhtpResult<T> = anyhow::Result<T>;

pub enum ProtocolError {
    InvalidRequest(String),
    ValidationError(String),
    CryptoError(String),
    EconomicError(String),
    StorageError(String),
    NetworkError(String),
    // ... more variants
}
```

**Error handling example:**

```rust
match integration.process_integrated_request(request).await {
    Ok(response) => println!("Success: {:?}", response),
    Err(e) => eprintln!("Error: {}", e),
}
```

---

For more detailed information, see the individual module documentation files.
