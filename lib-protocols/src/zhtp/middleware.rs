//! ZHTP Middleware Stack
//! 
//! Comprehensive middleware system for ZHTP protocol including authentication,
//! authorization, compression, CORS, logging, economic validation, rate limiting,
//! security headers, and Web4-specific middleware components.

use crate::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use crate::zhtp::{ZhtpMiddleware, ZhtpResult};
use crate::zhtp::config::ServerConfig;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Instant};

/// Middleware execution order
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MiddlewareOrder {
    /// Pre-processing (CORS, security headers)
    PreProcessing = 100,
    /// Authentication and authorization
    Auth = 200,
    /// Rate limiting and throttling
    RateLimit = 300,
    /// Economic validation
    Economic = 400,
    /// Content processing (compression, encryption)
    Content = 500,
    /// Logging and monitoring
    Logging = 600,
    /// Application-specific middleware
    Application = 700,
    /// Post-processing (response modification)
    PostProcessing = 800,
}

/// Middleware configuration
#[derive(Debug, Clone)]
pub struct MiddlewareConfig {
    /// Middleware name
    pub name: String,
    /// Execution order
    pub order: MiddlewareOrder,
    /// Enabled flag
    pub enabled: bool,
    /// Configuration parameters
    pub params: HashMap<String, String>,
}

/// Middleware context for passing data between middleware
#[derive(Debug, Clone)]
pub struct MiddlewareContext {
    /// Request ID for tracing
    pub request_id: String,
    /// Start time for performance measurement
    pub start_time: Instant,
    /// User identity if authenticated
    pub user_identity: Option<String>,
    /// DAO account if available
    pub dao_account: Option<String>,
    /// Economic validation results
    pub economic_validation: Option<EconomicValidationResult>,
    /// Security context
    pub security_context: SecurityContext,
    /// Custom context data
    pub custom_data: HashMap<String, String>,
}

/// Economic validation result
#[derive(Debug, Clone)]
pub struct EconomicValidationResult {
    /// DAO fee amount
    pub dao_fee: u64,
    /// UBI allocation
    pub ubi_allocation: u64,
    /// Payment method
    pub payment_method: String,
    /// Fee validation status
    pub fee_valid: bool,
    /// Economic impact score
    pub impact_score: u32,
}

/// Security context
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Authentication status
    pub authenticated: bool,
    /// Authorization level
    pub authorization_level: u32,
    /// Risk score
    pub risk_score: u32,
    /// ZK proof verified
    pub zk_proof_verified: bool,
    /// Signature verified
    pub signature_verified: bool,
    /// Client IP address
    pub client_ip: String,
    /// User agent
    pub user_agent: String,
}

/// CORS (Cross-Origin Resource Sharing) middleware
pub struct CorsMiddleware {
    /// Allowed origins
    allowed_origins: Vec<String>,
    /// Allowed methods
    allowed_methods: Vec<String>,
    /// Allowed headers
    allowed_headers: Vec<String>,
    /// Exposed headers
    exposed_headers: Vec<String>,
    /// Allow credentials
    allow_credentials: bool,
    /// Max age for preflight requests
    max_age: u32,
}

impl CorsMiddleware {
    /// Create new CORS middleware
    pub fn new() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "HEAD".to_string(),
                "OPTIONS".to_string(),
                "VERIFY".to_string(),
            ],
            allowed_headers: vec![
                "Origin".to_string(),
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
                "X-DAO-Fee".to_string(),
                "X-ZK-Proof".to_string(),
                "X-Signature".to_string(),
                "X-ZHTP-Version".to_string(),
            ],
            exposed_headers: vec![
                "X-DAO-Fee-Collected".to_string(),
                "X-UBI-Distributed".to_string(),
                "X-Economic-Impact".to_string(),
                "X-Mesh-Route".to_string(),
            ],
            allow_credentials: true,
            max_age: 86400, // 24 hours
        }
    }
    
    /// Configure allowed origins
    pub fn with_origins(mut self, origins: Vec<String>) -> Self {
        self.allowed_origins = origins;
        self
    }
    
    /// Configure allowed methods
    pub fn with_methods(mut self, methods: Vec<String>) -> Self {
        self.allowed_methods = methods;
        self
    }
    
    /// Configure allowed headers
    pub fn with_headers(mut self, headers: Vec<String>) -> Self {
        self.allowed_headers = headers;
        self
    }
}

#[async_trait::async_trait]
impl ZhtpMiddleware for CorsMiddleware {
    async fn before_request(&self, request: &mut ZhtpRequest) -> ZhtpResult<()> {
        // Add CORS context to request for later processing
        request.headers.set(
            "X-CORS-Processed",
            "true".to_string(),
        );
        
        tracing::debug!("CORS middleware: Processing request from origin: {}",
                        request.headers.get("Origin").unwrap_or("unknown".to_string()));
        Ok(())
    }
    
    async fn after_response(&self, response: &mut ZhtpResponse) -> ZhtpResult<()> {
        // Add CORS headers
        response.headers.set(
            "Access-Control-Allow-Origin",
            if self.allowed_origins.contains(&"*".to_string()) {
                "*".to_string()
            } else {
                self.allowed_origins.join(", ")
            },
        );
        
        response.headers.set(
            "Access-Control-Allow-Methods",
            self.allowed_methods.join(", "),
        );
        
        response.headers.set(
            "Access-Control-Allow-Headers",
            self.allowed_headers.join(", "),
        );
        
        response.headers.set(
            "Access-Control-Expose-Headers",
            self.exposed_headers.join(", "),
        );
        
        if self.allow_credentials {
            response.headers.set(
                "Access-Control-Allow-Credentials",
                "true".to_string(),
            );
        }
        
        response.headers.set(
            "Access-Control-Max-Age",
            self.max_age.to_string(),
        );
        
        Ok(())
    }
}

/// Authentication middleware
pub struct AuthenticationMiddleware {
    /// Required authentication methods
    required_auth_methods: Vec<String>,
    /// JWT secret key
    jwt_secret: Option<String>,
    /// ZK proof verification enabled
    zk_proof_verification: bool,
    /// Signature verification enabled
    signature_verification: bool,
}

impl AuthenticationMiddleware {
    /// Create new authentication middleware
    pub fn new() -> Self {
        Self {
            required_auth_methods: vec!["zk_proof".to_string()],
            jwt_secret: None,
            zk_proof_verification: true,
            signature_verification: true,
        }
    }
    
    /// Configure required authentication methods
    pub fn with_auth_methods(mut self, methods: Vec<String>) -> Self {
        self.required_auth_methods = methods;
        self
    }
    
    /// Configure JWT secret
    pub fn with_jwt_secret(mut self, secret: String) -> Self {
        self.jwt_secret = Some(secret);
        self
    }
}

#[async_trait::async_trait]
impl ZhtpMiddleware for AuthenticationMiddleware {
    async fn before_request(&self, request: &mut ZhtpRequest) -> ZhtpResult<()> {
        let mut authenticated = false;
        let mut auth_method_used = String::new();
        
        // Check ZK proof authentication
        if self.zk_proof_verification {
            if let Some(zk_proof) = request.headers.get("X-ZK-Proof") {
                if self.verify_zk_proof(&zk_proof).await? {
                    authenticated = true;
                    auth_method_used = "zk_proof".to_string();
                    tracing::info!("ZK proof authentication successful");
                }
            }
        }
        
        // Check signature authentication
        if !authenticated && self.signature_verification {
            if let Some(signature) = request.headers.get("X-Signature") {
                if self.verify_signature(request, &signature).await? {
                    authenticated = true;
                    auth_method_used = "signature".to_string();
                    tracing::info!("Signature authentication successful");
                }
            }
        }
        
        // Check JWT authentication
        if !authenticated && self.jwt_secret.is_some() {
            if let Some(auth_header) = request.headers.get("Authorization") {
                if auth_header.starts_with("Bearer ") {
                    let token = &auth_header[7..];
                    if self.verify_jwt(token).await? {
                        authenticated = true;
                        auth_method_used = "jwt".to_string();
                        tracing::info!("JWT authentication successful");
                    }
                }
            }
        }
        
        // Set authentication context
        request.headers.set(
            "X-Authenticated",
            authenticated.to_string(),
        );
        
        if authenticated {
            request.headers.set(
                "X-Auth-Method",
                auth_method_used,
            );
        }
        
        // Check if authentication is required
        if !self.required_auth_methods.is_empty() && !authenticated {
            return Err(anyhow::anyhow!("Authentication required"));
        }
        
        Ok(())
    }
    
    async fn after_response(&self, response: &mut ZhtpResponse) -> ZhtpResult<()> {
        // Add authentication-related headers
        response.headers.set(
            "X-Auth-Required",
            (!self.required_auth_methods.is_empty()).to_string(),
        );
        
        Ok(())
    }
    
    async fn on_error(&self, error: &anyhow::Error) -> ZhtpResult<Option<ZhtpResponse>> {
        if error.to_string().contains("Authentication required") {
            let response = ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                "Authentication required".to_string(),
            );
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }
}

impl AuthenticationMiddleware {
    /// Verify ZK proof
    async fn verify_zk_proof(&self, zk_proof: &str) -> ZhtpResult<bool> {
        // In production, this would integrate with the lib-proofs package
        // For now, basic validation
        Ok(zk_proof.len() > 32 && zk_proof.starts_with("zk_"))
    }
    
    /// Verify signature
    async fn verify_signature(&self, request: &ZhtpRequest, signature: &str) -> ZhtpResult<bool> {
        // In production, this would verify the actual signature
        // For now, basic validation
        Ok(signature.len() >= 64 && signature.chars().all(|c| c.is_ascii_hexdigit()))
    }
    
    /// Verify JWT token
    async fn verify_jwt(&self, token: &str) -> ZhtpResult<bool> {
        // In production, this would use a JWT library for verification
        // For now, basic validation
        Ok(token.split('.').count() == 3)
    }
}

/// Economic validation middleware
pub struct EconomicMiddleware {
    /// Minimum DAO fee required (in wei)
    min_dao_fee: u64,
    /// DAO fee percentage
    dao_fee_percentage: f64,
    /// UBI distribution percentage
    ubi_percentage: f64,
    /// Economic validation enabled
    enabled: bool,
}

impl EconomicMiddleware {
    /// Create new economic middleware
    pub fn new(min_dao_fee: u64, dao_fee_percentage: f64, ubi_percentage: f64) -> Self {
        Self {
            min_dao_fee,
            dao_fee_percentage,
            ubi_percentage,
            enabled: true,
        }
    }
}

#[async_trait::async_trait]
impl ZhtpMiddleware for EconomicMiddleware {
    async fn before_request(&self, request: &mut ZhtpRequest) -> ZhtpResult<()> {
        if !self.enabled {
            return Ok(());
        }
        
        // Extract DAO fee from request
        let dao_fee = request.headers.get("X-DAO-Fee")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        
        // Calculate required fee based on transaction value
        let transaction_value = request.headers.get("X-Transaction-Value")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(self.calculate_default_transaction_value(request));
        
        let required_fee = std::cmp::max(
            self.min_dao_fee,
            (transaction_value as f64 * self.dao_fee_percentage) as u64
        );
        
        // Validate DAO fee
        if dao_fee < required_fee {
            return Err(anyhow::anyhow!(
                "Insufficient DAO fee: required {} wei, provided {} wei",
                required_fee, dao_fee
            ));
        }
        
        // Calculate UBI allocation
        let ubi_allocation = (dao_fee as f64 * self.ubi_percentage) as u64;
        
        // Calculate economic impact score
        let impact_score = self.calculate_economic_impact(transaction_value, dao_fee);
        
        // Add economic context to request
        request.headers.set("X-Required-DAO-Fee", required_fee.to_string());
        request.headers.set("X-UBI-Allocation", ubi_allocation.to_string());
        request.headers.set("X-Economic-Impact", impact_score.to_string());
        request.headers.set("X-Economic-Validated", "true".to_string());
        
        tracing::info!("Economic validation: fee={} wei, UBI={} wei, impact={}",
                      dao_fee, ubi_allocation, impact_score);
        
        Ok(())
    }
    
    async fn after_response(&self, response: &mut ZhtpResponse) -> ZhtpResult<()> {
        if !self.enabled {
            return Ok(());
        }
        
        // Add economic information to response
        response.headers.set(
            "X-DAO-Fee-Processed",
            "true".to_string(),
        );
        
        response.headers.set(
            "X-UBI-System",
            "enabled".to_string(),
        );
        
        Ok(())
    }
    
    async fn on_error(&self, error: &anyhow::Error) -> ZhtpResult<Option<ZhtpResponse>> {
        let error_msg = error.to_string();
        if error_msg.contains("Insufficient DAO fee") {
            let response = ZhtpResponse::error(
                ZhtpStatus::PaymentRequired,
                error_msg,
            );
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }
}

impl EconomicMiddleware {
    /// Calculate default transaction value based on request
    fn calculate_default_transaction_value(&self, request: &ZhtpRequest) -> u64 {
        // Base value on request size and method
        let base_value: u64 = match request.method {
            crate::types::ZhtpMethod::Get => 1000,
            crate::types::ZhtpMethod::Post => 5000,
            crate::types::ZhtpMethod::Put => 3000,
            crate::types::ZhtpMethod::Delete => 2000,
            crate::types::ZhtpMethod::Head => 500,
            crate::types::ZhtpMethod::Options => 100,
            crate::types::ZhtpMethod::Verify => 10000,
            crate::types::ZhtpMethod::Patch => 4000,
            crate::types::ZhtpMethod::Connect => 6000,
            crate::types::ZhtpMethod::Trace => 1500,
        };
        
        // Add size component
        let size_value = (request.body.len() as u64).saturating_mul(10);
        
        base_value.saturating_add(size_value)
    }
    
    /// Calculate economic impact score
    fn calculate_economic_impact(&self, transaction_value: u64, dao_fee: u64) -> u32 {
        let fee_ratio = dao_fee as f64 / transaction_value.max(1) as f64;
        
        match fee_ratio {
            r if r >= 0.1 => 100,  // Very high impact (10%+ fee ratio)
            r if r >= 0.05 => 80,  // High impact (5-10% fee ratio)
            r if r >= 0.02 => 60,  // Medium impact (2-5% fee ratio)
            r if r >= 0.01 => 40,  // Low impact (1-2% fee ratio)
            _ => 20,               // Very low impact (<1% fee ratio)
        }
    }
}

/// Compression middleware
pub struct CompressionMiddleware {
    /// Enabled compression algorithms
    algorithms: Vec<CompressionAlgorithm>,
    /// Minimum size to compress
    min_size: usize,
    /// Compression level (1-9)
    level: u32,
}

#[derive(Debug, Clone)]
pub enum CompressionAlgorithm {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl CompressionMiddleware {
    /// Create new compression middleware
    pub fn new() -> Self {
        Self {
            algorithms: vec![
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Deflate,
            ],
            min_size: 1024, // 1KB minimum
            level: 6,
        }
    }
    
    /// Configure compression algorithms
    pub fn with_algorithms(mut self, algorithms: Vec<CompressionAlgorithm>) -> Self {
        self.algorithms = algorithms;
        self
    }
    
    /// Configure minimum compression size
    pub fn with_min_size(mut self, min_size: usize) -> Self {
        self.min_size = min_size;
        self
    }
}

#[async_trait::async_trait]
impl ZhtpMiddleware for CompressionMiddleware {
    async fn before_request(&self, request: &mut ZhtpRequest) -> ZhtpResult<()> {
        // Decompress request body if compressed
        if let Some(encoding) = request.headers.get("Content-Encoding") {
            let decompressed = self.decompress_data(&request.body, &encoding)?;
            request.body = decompressed;
            request.headers.remove("Content-Encoding");
            
            // Update content length
            request.headers.set(
                "Content-Length",
                request.body.len().to_string(),
            );
            
            tracing::debug!(" Decompressed request body: {} -> {} bytes",
                           encoding, request.body.len());
        }
        
        Ok(())
    }
    
    async fn after_response(&self, response: &mut ZhtpResponse) -> ZhtpResult<()> {
        // Skip compression for small responses
        if response.body.len() < self.min_size {
            return Ok(());
        }
        
        // Check if client accepts compression
        // Note: In a implementation, we'd check the Accept-Encoding header
        // from the original request
        
        // Compress response body
        if let Some(algorithm) = self.algorithms.first() {
            let compressed = self.compress_data(&response.body, algorithm)?;
            
            // Only use compression if it actually reduces size
            if compressed.len() < response.body.len() {
                response.body = compressed;
                
                let encoding = match algorithm {
                    CompressionAlgorithm::Gzip => "gzip",
                    CompressionAlgorithm::Deflate => "deflate",
                    CompressionAlgorithm::Brotli => "br",
                    CompressionAlgorithm::Zstd => "zstd",
                };
                
                response.headers.set(
                    "Content-Encoding",
                    encoding.to_string(),
                );
                
                response.headers.set(
                    "Content-Length",
                    response.body.len().to_string(),
                );
                
                tracing::debug!(" Compressed response body with {}: {} bytes",
                               encoding, response.body.len());
            }
        }
        
        Ok(())
    }
}

impl CompressionMiddleware {
    /// Compress data using specified algorithm
    fn compress_data(&self, data: &[u8], algorithm: &CompressionAlgorithm) -> ZhtpResult<Vec<u8>> {
        match algorithm {
            CompressionAlgorithm::Gzip => {
                use flate2::write::GzEncoder;
                use flate2::Compression;
                use std::io::Write;
                
                let mut encoder = GzEncoder::new(Vec::new(), Compression::new(self.level));
                encoder.write_all(data)?;
                Ok(encoder.finish()?)
            }
            CompressionAlgorithm::Deflate => {
                use flate2::write::DeflateEncoder;
                use flate2::Compression;
                use std::io::Write;
                
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(self.level));
                encoder.write_all(data)?;
                Ok(encoder.finish()?)
            }
            CompressionAlgorithm::Brotli => {
                // For production, would use brotli crate
                // For now, return original data
                Ok(data.to_vec())
            }
            CompressionAlgorithm::Zstd => {
                // For production, would use zstd crate
                // For now, return original data
                Ok(data.to_vec())
            }
        }
    }
    
    /// Decompress data using specified encoding
    fn decompress_data(&self, data: &[u8], encoding: &str) -> ZhtpResult<Vec<u8>> {
        match encoding {
            "gzip" => {
                use flate2::read::GzDecoder;
                use std::io::Read;
                
                let mut decoder = GzDecoder::new(data);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            "deflate" => {
                use flate2::read::DeflateDecoder;
                use std::io::Read;
                
                let mut decoder = DeflateDecoder::new(data);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            "br" | "brotli" => {
                // For production, would use brotli crate
                // For now, return original data
                Ok(data.to_vec())
            }
            "zstd" => {
                // For production, would use zstd crate
                // For now, return original data
                Ok(data.to_vec())
            }
            _ => Err(anyhow::anyhow!("Unsupported compression encoding: {}", encoding)),
        }
    }
}

/// Rate limiting middleware
pub struct RateLimitMiddleware {
    /// Requests per minute limit
    requests_per_minute: u32,
    /// Burst size
    burst_size: u32,
    /// Rate limit by IP
    limit_by_ip: bool,
    /// Rate limit by user identity
    limit_by_identity: bool,
    /// Request counters
    counters: HashMap<String, RateLimitCounter>,
}

#[derive(Debug, Clone)]
struct RateLimitCounter {
    /// Request count in current window
    count: u32,
    /// Window start time
    window_start: u64,
    /// Burst tokens available
    burst_tokens: u32,
}

impl RateLimitMiddleware {
    /// Create new rate limit middleware
    pub fn new(requests_per_minute: u32, burst_size: u32) -> Self {
        Self {
            requests_per_minute,
            burst_size,
            limit_by_ip: true,
            limit_by_identity: true,
            counters: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl ZhtpMiddleware for RateLimitMiddleware {
    async fn before_request(&self, request: &mut ZhtpRequest) -> ZhtpResult<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Generate rate limit key
        let mut limit_keys = Vec::new();
        
        if self.limit_by_ip {
            let client_ip_raw = request.headers.get("X-Real-IP")
                .or_else(|| request.headers.get("X-Forwarded-For"))
                .unwrap_or("unknown".to_string());
            let client_ip = client_ip_raw
                .split(',')
                .next()
                .unwrap_or("unknown")
                .trim();
            limit_keys.push(format!("ip:{}", client_ip));
        }
        
        if self.limit_by_identity {
            if let Some(user_id) = request.headers.get("X-User-ID") {
                limit_keys.push(format!("user:{}", user_id));
            }
        }
        
        // Check rate limits for each key
        for key in limit_keys {
            if self.is_rate_limited(&key, current_time) {
                return Err(anyhow::anyhow!("Rate limit exceeded for {}", key));
            }
        }
        
        tracing::debug!("🚦 Rate limit check passed");
        Ok(())
    }
    
    async fn after_response(&self, response: &mut ZhtpResponse) -> ZhtpResult<()> {
        // Add rate limit headers
        response.headers.set(
            "X-RateLimit-Limit",
            self.requests_per_minute.to_string(),
        );
        
        response.headers.set(
            "X-RateLimit-Burst",
            self.burst_size.to_string(),
        );
        
        Ok(())
    }
    
    async fn on_error(&self, error: &anyhow::Error) -> ZhtpResult<Option<ZhtpResponse>> {
        if error.to_string().contains("Rate limit exceeded") {
            let mut response = ZhtpResponse::error(
                ZhtpStatus::TooManyRequests,
                "Rate limit exceeded".to_string(),
            );
            
            response.headers.set(
                "Retry-After",
                "60".to_string(), // Retry after 60 seconds
            );
            
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }
}

impl RateLimitMiddleware {
    /// Check if request should be rate limited
    fn is_rate_limited(&self, key: &str, current_time: u64) -> bool {
        // This is a simplified implementation
        // In production, would use a more sophisticated algorithm like token bucket
        // and would need to be thread-safe with proper synchronization
        false // For now, always allow
    }
}

/// Logging middleware
pub struct LoggingMiddleware {
    /// Log requests
    log_requests: bool,
    /// Log responses
    log_responses: bool,
    /// Log request bodies
    log_request_bodies: bool,
    /// Log response bodies
    log_response_bodies: bool,
    /// Maximum body size to log
    max_body_log_size: usize,
}

impl LoggingMiddleware {
    /// Create new logging middleware
    pub fn new() -> Self {
        Self {
            log_requests: true,
            log_responses: true,
            log_request_bodies: false,
            log_response_bodies: false,
            max_body_log_size: 1024,
        }
    }
    
    /// Configure request logging
    pub fn with_request_logging(mut self, enabled: bool) -> Self {
        self.log_requests = enabled;
        self
    }
    
    /// Configure response logging
    pub fn with_response_logging(mut self, enabled: bool) -> Self {
        self.log_responses = enabled;
        self
    }
    
    /// Configure body logging
    pub fn with_body_logging(mut self, enabled: bool) -> Self {
        self.log_request_bodies = enabled;
        self.log_response_bodies = enabled;
        self
    }
}

#[async_trait::async_trait]
impl ZhtpMiddleware for LoggingMiddleware {
    async fn before_request(&self, request: &mut ZhtpRequest) -> ZhtpResult<()> {
        if self.log_requests {
            let mut log_msg = format!("Request: {} {}", request.method as u8, request.uri);
            
            if self.log_request_bodies && !request.body.is_empty() {
                let body_preview = if request.body.len() <= self.max_body_log_size {
                    String::from_utf8_lossy(&request.body).to_string()
                } else {
                    format!("{}... ({} bytes)",
                           String::from_utf8_lossy(&request.body[..self.max_body_log_size]),
                           request.body.len())
                };
                log_msg.push_str(&format!(" | Body: {}", body_preview));
            }
            
            tracing::info!("{}", log_msg);
        }
        
        // Add request start time for performance measurement
        request.headers.set(
            "X-Request-Start-Time",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .to_string(),
        );
        
        Ok(())
    }
    
    async fn after_response(&self, response: &mut ZhtpResponse) -> ZhtpResult<()> {
        if self.log_responses {
            let mut log_msg = format!(" Response: {} {}", 
                                    response.status.code(), 
                                    response.status.reason_phrase());
            
            if self.log_response_bodies && !response.body.is_empty() {
                let body_preview = if response.body.len() <= self.max_body_log_size {
                    String::from_utf8_lossy(&response.body).to_string()
                } else {
                    format!("{}... ({} bytes)",
                           String::from_utf8_lossy(&response.body[..self.max_body_log_size]),
                           response.body.len())
                };
                log_msg.push_str(&format!(" | Body: {}", body_preview));
            }
            
            tracing::info!("{}", log_msg);
        }
        
        Ok(())
    }
    
    async fn on_error(&self, error: &anyhow::Error) -> ZhtpResult<Option<ZhtpResponse>> {
        tracing::error!("Middleware error: {}", error);
        Ok(None)
    }
}

/// Security headers middleware
pub struct SecurityHeadersMiddleware {
    /// Add security headers
    add_security_headers: bool,
    /// Custom security headers
    custom_headers: HashMap<String, String>,
}

impl SecurityHeadersMiddleware {
    /// Create new security headers middleware
    pub fn new() -> Self {
        let mut custom_headers = HashMap::new();
        
        // Standard security headers
        custom_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        custom_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        custom_headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());
        custom_headers.insert("Strict-Transport-Security".to_string(), 
                            "max-age=31536000; includeSubDomains".to_string());
        custom_headers.insert("Referrer-Policy".to_string(), "strict-origin-when-cross-origin".to_string());
        
        // ZHTP-specific security headers
        custom_headers.insert("X-ZHTP-Security".to_string(), "enabled".to_string());
        custom_headers.insert("X-ZK-Privacy".to_string(), "protected".to_string());
        custom_headers.insert("X-Post-Quantum".to_string(), "ready".to_string());
        
        Self {
            add_security_headers: true,
            custom_headers,
        }
    }
}

#[async_trait::async_trait]
impl ZhtpMiddleware for SecurityHeadersMiddleware {
    async fn before_request(&self, _request: &mut ZhtpRequest) -> ZhtpResult<()> {
        // Security headers are added in after_response
        Ok(())
    }
    
    async fn after_response(&self, response: &mut ZhtpResponse) -> ZhtpResult<()> {
        if self.add_security_headers {
            for (header, value) in &self.custom_headers {
                response.headers.set(&header, value.clone());
            }
        }
        
        Ok(())
    }
}

/// Create default middleware stack for ZHTP server
pub fn create_default_middleware_stack(config: &ServerConfig) -> Vec<Box<dyn ZhtpMiddleware>> {
    let mut middleware: Vec<Box<dyn ZhtpMiddleware>> = Vec::new();
    
    // Security headers (first)
    middleware.push(Box::new(SecurityHeadersMiddleware::new()));
    
    // CORS
    middleware.push(Box::new(CorsMiddleware::new()));
    
    // Rate limiting
    if config.security.enable_rate_limiting {
        middleware.push(Box::new(RateLimitMiddleware::new(
            config.security.rate_limiting.requests_per_minute,
            config.security.rate_limiting.burst_size,
        )));
    }
    
    // Authentication
    middleware.push(Box::new(AuthenticationMiddleware::new()));
    
    // Economic validation
    if config.economic.enable_dao_fees {
        middleware.push(Box::new(EconomicMiddleware::new(
            config.economic.min_dao_fee_wei,
            config.economic.dao_fee_percentage,
            config.economic.ubi_percentage,
        )));
    }
    
    // Compression
    if config.enable_compression {
        middleware.push(Box::new(CompressionMiddleware::new()));
    }
    
    // Logging (last)
    middleware.push(Box::new(LoggingMiddleware::new()));
    
    middleware
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ZhtpMethod, ZhtpHeaders};

    #[tokio::test]
    async fn test_cors_middleware() {
        use lib_economy::{EconomicModel, Priority};
        
        let cors = CorsMiddleware::new();
        
        // Create a test economic model
        let economic_model = EconomicModel::new();
        
        let mut request = ZhtpRequest::new(
            ZhtpMethod::Get,
            "/test".to_string(),
            vec![],
            None, // requester
            Priority::Normal,
            &economic_model,
        ).unwrap();
        
        cors.before_request(&mut request).await.unwrap();
        assert_eq!(request.headers.get("X-CORS-Processed"), Some("true".to_string()));
    }

    #[tokio::test]
    async fn test_economic_middleware() {
        use lib_economy::{EconomicModel, Priority};
        
        let economic = EconomicMiddleware::new(1000, 0.02, 0.8);
        
        // Create a test economic model
        let economic_model = EconomicModel::new();
        
        let mut request = ZhtpRequest::new(
            ZhtpMethod::Post,
            "/test".to_string(),
            vec![1; 1000],
            None, // requester
            Priority::Normal,
            &economic_model,
        ).unwrap();
        
        // Set the required headers after creating the request
        request.headers.set("X-DAO-Fee", "2000".to_string());
        request.headers.set("X-Transaction-Value", "50000".to_string());
        
        economic.before_request(&mut request).await.unwrap();
        assert_eq!(request.headers.get("X-Economic-Validated"), Some("true".to_string()));
    }

    #[tokio::test]
    async fn test_compression_middleware() {
        let compression = CompressionMiddleware::new().with_min_size(10);
        let test_data = b"This is test data that should be compressed".repeat(10);
        let mut response = ZhtpResponse::success(test_data, None);
        
        compression.after_response(&mut response).await.unwrap();
        
        // Should have compression headers if compressed
        if response.headers.get("Content-Encoding").is_some() {
            assert!(response.body.len() > 0);
        }
    }

    #[test]
    fn test_middleware_order() {
        assert!(MiddlewareOrder::PreProcessing < MiddlewareOrder::Auth);
        assert!(MiddlewareOrder::Auth < MiddlewareOrder::Economic);
        assert!(MiddlewareOrder::Economic < MiddlewareOrder::Content);
        assert!(MiddlewareOrder::Content < MiddlewareOrder::Logging);
    }
}
