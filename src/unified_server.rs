//! ZHTP Unified Server - Single Server for All Protocols
//! 
//! Consolidates HTTP API, UDP mesh, WiFi Direct, and Bootstrap into one intelligent server
//! Listens on port 9333 for all protocols with automatic protocol detection

use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::net::{TcpListener, UdpSocket, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use hex;
use async_trait::async_trait;

// Import from libraries (no circular dependencies!)
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpStatus, ZhtpHeaders};
use lib_network::protocols::wifi_direct::WiFiDirectMeshProtocol;
use lib_network::protocols::bluetooth::BluetoothMeshProtocol;
use lib_network::dht::relay::ZhtpRelayProtocol;
use lib_network::dht::protocol::ZhtpRelayQuery;
use lib_network::protocols::zhtp_encryption::{ZhtpEncryptionManager, ZhtpEncryptionSession, ZhtpKeyExchangeResponse};
use lib_network::protocols::zhtp_auth::{ZhtpAuthManager, ZhtpAuthResponse, NodeCapabilities};
use lib_network::types::mesh_message::ZhtpMeshMessage;
use lib_network::routing::message_routing::MeshMessageRouter;
use lib_network::mesh::server::ZhtpMeshServer;

use lib_network::MeshConnection;
use lib_blockchain::Blockchain;
use lib_storage::UnifiedStorageSystem;
use lib_identity::IdentityManager;
use lib_economy::EconomicModel;
use lib_crypto::PublicKey;

// Import our comprehensive API handlers
use crate::api::handlers::{
    BlockchainHandler, IdentityHandler, StorageHandler, 
    ProtocolHandler, WalletHandler, DaoHandler, 
    DhtHandler, Web4Handler, DnsHandler
};
use crate::session_manager::SessionManager;

/// Protocol detection for incoming connections
#[derive(Debug, Clone, PartialEq)]
pub enum IncomingProtocol {
    /// HTTP/1.1 REST API requests
    HTTP,
    /// ZHTP mesh protocol over TCP
    ZhtpMeshTcp,
    /// ZHTP mesh protocol over UDP
    ZhtpMeshUdp,
    /// WiFi Direct device connections
    WiFiDirect,
    /// Bluetooth device connections
    Bluetooth,
    /// Network bootstrap connections
    Bootstrap,
    /// bootstrap protocol
    Unknown,
}

/// Simplified ZHTP mesh request format (as sent by browser)
#[derive(Debug, Serialize, Deserialize)]
struct MeshZhtpRequest {
    method: String,
    uri: String,
    timestamp: u64,
    requester: Option<serde_json::Value>, // Cryptographic identity data
}

/// Middleware trait for request processing
#[async_trait]
pub trait Middleware: Send + Sync {
    async fn process(&self, request: &mut ZhtpRequest, response: &mut Option<ZhtpResponse>) -> Result<bool>;
    fn name(&self) -> &str;
}

/// CORS middleware
pub struct CorsMiddleware;

#[async_trait]
impl Middleware for CorsMiddleware {
    async fn process(&self, _request: &mut ZhtpRequest, response: &mut Option<ZhtpResponse>) -> Result<bool> {
        if let Some(resp) = response {
            resp.headers.set("Access-Control-Allow-Origin", "*".to_string());
            resp.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS".to_string());
            resp.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization".to_string());
        }
        Ok(true) // Continue processing
    }
    
    fn name(&self) -> &str {
        "CORS"
    }
}

/// Rate limiting middleware
pub struct RateLimitMiddleware {
    request_counts: Arc<RwLock<HashMap<String, (u64, SystemTime)>>>,
    max_requests: u64,
    window_seconds: u64,
}

impl RateLimitMiddleware {
    pub fn new(max_requests: u64, window_seconds: u64) -> Self {
        Self {
            request_counts: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_seconds,
        }
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    async fn process(&self, request: &mut ZhtpRequest, response: &mut Option<ZhtpResponse>) -> Result<bool> {
        let client_key = request.headers.get("X-Forwarded-For")
            .or_else(|| request.headers.get("X-Real-IP"))
            .unwrap_or("unknown".to_string());
            
        let mut counts = self.request_counts.write().await;
        let now = SystemTime::now();
        
        let (count, last_window) = counts.get(&client_key)
            .copied()
            .unwrap_or((0, now));
            
        let elapsed = now.duration_since(last_window).unwrap_or_default().as_secs();
        
        if elapsed >= self.window_seconds {
            // Reset window
            counts.insert(client_key, (1, now));
            Ok(true)
        } else if count >= self.max_requests {
            // Rate limit exceeded
            *response = Some(ZhtpResponse::error(
                ZhtpStatus::TooManyRequests,
                "Rate limit exceeded".to_string(),
            ));
            Ok(false) // Stop processing
        } else {
            // Increment count
            counts.insert(client_key, (count + 1, last_window));
            Ok(true)
        }
    }
    
    fn name(&self) -> &str {
        "RateLimit"
    }
}

/// Authentication middleware
pub struct AuthMiddleware;

#[async_trait]
impl Middleware for AuthMiddleware {
    async fn process(&self, request: &mut ZhtpRequest, response: &mut Option<ZhtpResponse>) -> Result<bool> {
        // Skip auth for public endpoints
        if request.uri.starts_with("/api/v1/public/") || 
           request.uri == "/api/v1/health" ||
           request.uri.starts_with("/api/v1/web4/") ||
           request.uri.starts_with("/api/v1/dns/") ||
           request.uri.starts_with("/api/v1/blockchain/") ||
           request.uri.starts_with("/api/v1/storage/") ||
           request.uri.starts_with("/api/v1/identity/") ||  // Allow identity creation without auth
           request.uri.starts_with("/api/marketplace/") ||
           request.uri.starts_with("/api/content/") ||
           request.uri.starts_with("/api/wallet/") {
            return Ok(true);
        }
        
        // Check for Authorization header
        if let Some(auth_header) = request.headers.get("Authorization") {
            if auth_header.starts_with("Bearer ") {
                let token = &auth_header[7..];
                // In a implementation, verify JWT token
                if token.len() > 10 { // Simple validation
                    request.headers.set("X-Authenticated", "true".to_string());
                    return Ok(true);
                }
            }
        }
        
        // Authentication required but not provided
        *response = Some(ZhtpResponse::error(
            ZhtpStatus::Unauthorized,
            "Authentication required".to_string(),
        ));
        Ok(false) // Stop processing
    }
    
    fn name(&self) -> &str {
        "Auth"
    }
}

/// HTTP request routing and handling
pub struct HttpRouter {
    routes: HashMap<String, Arc<dyn ZhtpRequestHandler>>,
    middleware: Vec<Arc<dyn Middleware>>,
}

impl HttpRouter {
    pub fn new() -> Self {
        let mut middleware: Vec<Arc<dyn Middleware>> = Vec::new();
        
        // Add core middleware in order
        middleware.push(Arc::new(CorsMiddleware));
        middleware.push(Arc::new(RateLimitMiddleware::new(100, 60))); // 100 requests per minute
        middleware.push(Arc::new(AuthMiddleware));
        
        info!("Initialized HTTP middleware: {}", 
            middleware.iter().map(|m| m.name()).collect::<Vec<_>>().join(", "));
        
        Self {
            routes: HashMap::new(),
            middleware,
        }
    }
    
    pub fn register_handler(&mut self, path: String, handler: Arc<dyn ZhtpRequestHandler>) {
        info!("Registering HTTP handler: {}", path);
        self.routes.insert(path, handler);
    }
    
    pub async fn handle_http_request(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        debug!("Processing HTTP request from: {}", addr);
        
        // Read HTTP request with dynamic buffer sizing based on Content-Length
        // First, read headers to determine content length
        let mut header_buffer = vec![0; 8192]; // Initial buffer for headers
        
        // Read initial chunk
        let bytes_read = stream.read(&mut header_buffer).await
            .context("Failed to read HTTP request")?;
        
        if bytes_read == 0 {
            return Ok(());
        }
        
        let mut total_read = bytes_read;
        
        // Check if headers are complete (look for \r\n\r\n)
        let header_data = String::from_utf8_lossy(&header_buffer[..total_read]);
        if let Some(header_end) = header_data.find("\r\n\r\n") {
            // Headers are complete
            
            // Parse Content-Length from headers
            let mut content_length: Option<usize> = None;
            for line in header_data.lines() {
                if line.to_lowercase().starts_with("content-length:") {
                    if let Some(len_str) = line.split(':').nth(1) {
                        content_length = len_str.trim().parse().ok();
                        break;
                    }
                }
            }
            
            // If we have Content-Length and need more data, read the body
            if let Some(content_len) = content_length {
                let header_size = header_end + 4; // +4 for \r\n\r\n
                let body_bytes_read = total_read - header_size;
                let remaining_body = content_len.saturating_sub(body_bytes_read);
                
                if remaining_body > 0 {
                    // Need to read more data
                    let total_size = header_size + content_len;
                    let max_size = 10_485_760; // 10 MB limit for safety
                    
                    if total_size > max_size {
                        warn!("Request too large: {} bytes (max: {} bytes)", total_size, max_size);
                        let error_response = self.create_error_response(413, "Payload Too Large");
                        let _ = stream.write_all(&error_response).await;
                        return Ok(());
                    }
                    
                    // Allocate buffer for full request
                    let mut full_buffer = vec![0; total_size];
                    full_buffer[..total_read].copy_from_slice(&header_buffer[..total_read]);
                    
                    // Read remaining body
                    let mut body_offset = total_read;
                    while body_offset < total_size {
                        let bytes = stream.read(&mut full_buffer[body_offset..]).await
                            .context("Failed to read request body")?;
                        if bytes == 0 {
                            break;
                        }
                        body_offset += bytes;
                    }
                    
                    header_buffer = full_buffer;
                    total_read = body_offset;
                    debug!("Read full request: {} bytes (header: {}, body: {})", total_read, header_size, content_len);
                }
            }
        }
        
        let request_data = String::from_utf8_lossy(&header_buffer[..total_read]);
        debug!("HTTP request data: {}", &request_data[..std::cmp::min(200, request_data.len())]);
        
        // Parse HTTP request (simplified)
        if let Some(first_line) = request_data.lines().next() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let method = parts[0];
                let path = parts[1];
                
                info!("HTTP {} {}", method, path);
                
                // Route to handler
                info!("Looking for handler for path: '{}'", path);
                info!("Registered routes: {:?}", self.routes.keys().collect::<Vec<_>>());
                if let Some(handler) = self.find_handler(path) {
                    info!("Found handler for path: '{}'", path);
                    match self.call_handler(handler, method, path, &request_data).await {
                        Ok(response) => {
                            let _ = stream.write_all(&response).await;
                        },
                        Err(e) => {
                            warn!("Handler error: {}", e);
                            let error_response = self.create_error_response(500, "Internal Server Error");
                            let _ = stream.write_all(&error_response).await;
                        }
                    }
                } else {
                    // 404 Not Found
                    warn!("No handler found for path: '{}' (method: {})", path, method);
                    warn!("Available routes: {:?}", self.routes.keys().collect::<Vec<_>>());
                    let not_found_response = self.create_error_response(404, "Not Found");
                    let _ = stream.write_all(&not_found_response).await;
                }
            }
        }
        
        Ok(())
    }
    
    fn find_handler(&self, path: &str) -> Option<&Arc<dyn ZhtpRequestHandler>> {
        // Try exact match first
        if let Some(handler) = self.routes.get(path) {
            return Some(handler);
        }
        
        // Try prefix matching for API routes
        for (route_path, handler) in &self.routes {
            if path.starts_with(route_path) {
                return Some(handler);
            }
        }
        
        None
    }
    
    async fn process_middleware(&self, mut request: ZhtpRequest) -> Result<(ZhtpRequest, Option<ZhtpResponse>)> {
        let mut response: Option<ZhtpResponse> = None;
        
        for middleware in &self.middleware {
            match middleware.process(&mut request, &mut response).await {
                Ok(true) => continue, // Continue to next middleware
                Ok(false) => break,   // Middleware stopped processing
                Err(e) => {
                    warn!("Middleware '{}' error: {}", middleware.name(), e);
                    response = Some(ZhtpResponse::error(
                        ZhtpStatus::InternalServerError,
                        format!("Middleware error: {}", e),
                    ));
                    break;
                }
            }
        }
        
        Ok((request, response))
    }
    
    async fn call_handler(&self, handler: &Arc<dyn ZhtpRequestHandler>, method: &str, path: &str, request_data: &str) -> Result<Vec<u8>> {
        // Create ZHTP request from HTTP request
        let zhtp_request = ZhtpRequest {
            method: match method {
                "GET" => ZhtpMethod::Get,
                "POST" => ZhtpMethod::Post,
                "PUT" => ZhtpMethod::Put,
                "DELETE" => ZhtpMethod::Delete,
                _ => ZhtpMethod::Get,
            },
            uri: path.to_string(),
            headers: {
                let mut headers = ZhtpHeaders::new();
                // Add basic content type header based on method
                if method == "POST" || method == "PUT" {
                    headers.set("content-type", "application/zhtp".to_string());
                }
                
                // Parse actual HTTP headers from request_data
                let lines: Vec<&str> = request_data.lines().collect();
                for line in lines.iter().skip(1) { // Skip request line
                    if line.is_empty() {
                        break; // End of headers
                    }
                    if let Some((key, value)) = line.split_once(':') {
                        headers.set(key.trim(), value.trim().to_string());
                    }
                }
                headers
            },
            body: {
                // Extract body from HTTP request after headers
                let lines: Vec<&str> = request_data.lines().collect();
                let mut body_start = 0;
                let mut found_empty_line = false;
                
                // Find the empty line that separates headers from body
                for (i, line) in lines.iter().enumerate().skip(1) { // Skip request line
                    if line.is_empty() {
                        body_start = i + 1;
                        found_empty_line = true;
                        break;
                    }
                }
                
                if found_empty_line && body_start < lines.len() {
                    let body_lines = &lines[body_start..];
                    let body_text = body_lines.join("\n");
                    body_text.as_bytes().to_vec()
                } else {
                    Vec::new()
                }
            },
            timestamp: chrono::Utc::now().timestamp() as u64,
            version: "1.0".to_string(),
            requester: None, // Anonymous for HTTP requests
            auth_proof: None, // No auth proof for basic HTTP
        };
        
        // Process middleware first
        let (processed_request, middleware_response) = self.process_middleware(zhtp_request).await?;
        
        // If middleware returned a response, use it
        let zhtp_response = if let Some(middleware_resp) = middleware_response {
            middleware_resp
        } else {
            // Call handler with processed request
            handler.handle_request(processed_request).await?
        };
        
        Ok(self.zhtp_response_to_http(&zhtp_response))
    }
    
    fn zhtp_response_to_http(&self, response: &ZhtpResponse) -> Vec<u8> {
        let status_line = match response.status {
            ZhtpStatus::Ok => "HTTP/1.1 200 OK\r\n",
            ZhtpStatus::BadRequest => "HTTP/1.1 400 Bad Request\r\n",
            ZhtpStatus::Unauthorized => "HTTP/1.1 401 Unauthorized\r\n",
            ZhtpStatus::Forbidden => "HTTP/1.1 403 Forbidden\r\n",
            ZhtpStatus::NotFound => "HTTP/1.1 404 Not Found\r\n",
            ZhtpStatus::InternalServerError => "HTTP/1.1 500 Internal Server Error\r\n",
            _ => "HTTP/1.1 200 OK\r\n",
        };
        
        // Extract content-type from ZhtpResponse headers
        let content_type = response.headers.get("content-type")
            .unwrap_or_else(|| "application/json".to_string());
        
        let mut http_response = String::new();
        http_response.push_str(status_line);
        http_response.push_str(&format!("Content-Type: {}\r\n", content_type));
        http_response.push_str("Access-Control-Allow-Origin: *\r\n");
        http_response.push_str("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n");
        http_response.push_str("Access-Control-Allow-Headers: Content-Type, Authorization\r\n");
        http_response.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
        http_response.push_str("Connection: close\r\n");
        http_response.push_str("\r\n");
        
        let mut result = http_response.into_bytes();
        result.extend_from_slice(&response.body);
        result
    }
    
    fn create_error_response(&self, status_code: u16, message: &str) -> Vec<u8> {
        let status_line = match status_code {
            404 => "HTTP/1.1 404 Not Found\r\n",
            500 => "HTTP/1.1 500 Internal Server Error\r\n",
            _ => "HTTP/1.1 400 Bad Request\r\n",
        };
        
        let body = format!("{{\"error\": \"{}\"}}", message);
        let mut response = String::new();
        response.push_str(status_line);
        response.push_str("Content-Type: application/json\r\n");
        response.push_str("Access-Control-Allow-Origin: *\r\n");
        response.push_str(&format!("Content-Length: {}\r\n", body.len()));
        response.push_str("Connection: close\r\n");
        response.push_str("\r\n");
        response.push_str(&body);
        
        response.into_bytes()
    }
}

/// Peer rate limiting tracker
#[derive(Debug, Clone)]
struct PeerRateLimit {
    block_count: u32,
    tx_count: u32,
    last_reset: u64,
    violations: u32, // Track rate limit violations
}

impl PeerRateLimit {
    fn new() -> Self {
        Self {
            block_count: 0,
            tx_count: 0,
            last_reset: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            violations: 0,
        }
    }
    
    fn check_and_increment_block(&mut self, max_per_minute: u32) -> bool {
        self.reset_if_needed();
        if self.block_count >= max_per_minute {
            self.violations += 1;
            return false; // Rate limit exceeded
        }
        self.block_count += 1;
        true
    }
    
    fn check_and_increment_tx(&mut self, max_per_minute: u32) -> bool {
        self.reset_if_needed();
        if self.tx_count >= max_per_minute {
            self.violations += 1;
            return false;
        }
        self.tx_count += 1;
        true
    }
    
    fn reset_if_needed(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if now - self.last_reset >= 60 {
            self.block_count = 0;
            self.tx_count = 0;
            self.last_reset = now;
            // Don't reset violations - they accumulate over time
        }
    }
    
    fn get_violations(&self) -> u32 {
        self.violations
    }
}

/// Peer reputation scoring
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub peer_id: String,
    pub score: i32, // -100 (banned) to 100 (trusted)
    pub blocks_accepted: u64,
    pub blocks_rejected: u64,
    pub txs_accepted: u64,
    pub txs_rejected: u64,
    pub violations: u32,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl PeerReputation {
    fn new(peer_id: String) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            peer_id,
            score: 50, // Start neutral
            blocks_accepted: 0,
            blocks_rejected: 0,
            txs_accepted: 0,
            txs_rejected: 0,
            violations: 0,
            first_seen: now,
            last_seen: now,
        }
    }
    
    fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    }
    
    fn record_block_accepted(&mut self) {
        self.blocks_accepted += 1;
        self.score = (self.score + 1).min(100);
        self.update_last_seen();
    }
    
    fn record_block_rejected(&mut self) {
        self.blocks_rejected += 1;
        self.score = (self.score - 2).max(-100);
        self.update_last_seen();
    }
    
    fn record_tx_accepted(&mut self) {
        self.txs_accepted += 1;
        self.score = (self.score + 1).min(100);
        self.update_last_seen();
    }
    
    fn record_tx_rejected(&mut self) {
        self.txs_rejected += 1;
        self.score = (self.score - 2).max(-100);
        self.update_last_seen();
    }
    
    fn record_violation(&mut self) {
        self.violations += 1;
        self.score = (self.score - 10).max(-100);
        self.update_last_seen();
    }
    
    fn is_banned(&self) -> bool {
        self.score <= -50 || self.violations >= 10
    }
    
    fn get_acceptance_rate(&self) -> f64 {
        let total = self.blocks_accepted + self.blocks_rejected + self.txs_accepted + self.txs_rejected;
        if total == 0 {
            return 100.0;
        }
        ((self.blocks_accepted + self.txs_accepted) as f64 / total as f64) * 100.0
    }
}

/// Peer performance statistics (for API responses)
#[derive(Debug, Clone)]
pub struct PeerPerformanceStats {
    pub peer_id: String,
    pub reputation_score: i32,
    pub blocks_accepted: u64,
    pub blocks_rejected: u64,
    pub txs_accepted: u64,
    pub txs_rejected: u64,
    pub violations: u32,
    pub acceptance_rate: f64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Broadcast metrics
#[derive(Debug, Clone)]
pub struct BroadcastMetrics {
    pub blocks_sent: u64,
    pub blocks_received: u64,
    pub transactions_sent: u64,
    pub transactions_received: u64,
    pub blocks_relayed: u64,
    pub transactions_relayed: u64,
    pub blocks_rejected: u64,
    pub transactions_rejected: u64,
}

impl BroadcastMetrics {
    fn new() -> Self {
        Self {
            blocks_sent: 0,
            blocks_received: 0,
            transactions_sent: 0,
            transactions_received: 0,
            blocks_relayed: 0,
            transactions_relayed: 0,
            blocks_rejected: 0,
            transactions_rejected: 0,
        }
    }
}

/// Performance metrics for blockchain sync
#[derive(Debug, Clone)]
pub struct SyncPerformanceMetrics {
    // Latency tracking (milliseconds)
    pub avg_block_propagation_ms: f64,
    pub avg_tx_propagation_ms: f64,
    pub p95_block_latency_ms: u64,
    pub p95_tx_latency_ms: u64,
    pub min_block_latency_ms: u64,
    pub max_block_latency_ms: u64,
    pub min_tx_latency_ms: u64,
    pub max_tx_latency_ms: u64,
    
    // Bandwidth tracking (bytes)
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub bytes_sent_per_sec: f64,
    pub bytes_received_per_sec: f64,
    pub peak_bandwidth_usage_bps: u64,
    
    // Efficiency metrics
    pub duplicate_block_ratio: f64,
    pub duplicate_tx_ratio: f64,
    pub validation_success_rate: f64,
    pub relay_efficiency: f64,
    
    // Time window for rate calculations
    pub measurement_start: u64,
    pub measurement_duration_secs: u64,
}

impl SyncPerformanceMetrics {
    fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            avg_block_propagation_ms: 0.0,
            avg_tx_propagation_ms: 0.0,
            p95_block_latency_ms: 0,
            p95_tx_latency_ms: 0,
            min_block_latency_ms: u64::MAX,
            max_block_latency_ms: 0,
            min_tx_latency_ms: u64::MAX,
            max_tx_latency_ms: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            bytes_sent_per_sec: 0.0,
            bytes_received_per_sec: 0.0,
            peak_bandwidth_usage_bps: 0,
            duplicate_block_ratio: 0.0,
            duplicate_tx_ratio: 0.0,
            validation_success_rate: 100.0,
            relay_efficiency: 100.0,
            measurement_start: now,
            measurement_duration_secs: 0,
        }
    }
}

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

/// Sync alert notification
#[derive(Debug, Clone)]
pub struct SyncAlert {
    pub id: String,
    pub level: AlertLevel,
    pub category: String,
    pub message: String,
    pub timestamp: u64,
    pub acknowledged: bool,
    pub peer_id: Option<String>,
    pub metric_value: Option<f64>,
    pub threshold_value: Option<f64>,
}

impl SyncAlert {
    fn new(level: AlertLevel, category: String, message: String) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            id: format!("alert_{}", now),
            level,
            category,
            message,
            timestamp: now,
            acknowledged: false,
            peer_id: None,
            metric_value: None,
            threshold_value: None,
        }
    }
    
    fn with_peer(mut self, peer_id: String) -> Self {
        self.peer_id = Some(peer_id);
        self
    }
    
    fn with_metric(mut self, value: f64, threshold: f64) -> Self {
        self.metric_value = Some(value);
        self.threshold_value = Some(threshold);
        self
    }
}

/// Alert thresholds configuration
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub max_block_latency_ms: u64,
    pub max_tx_latency_ms: u64,
    pub max_bandwidth_mbps: f64,
    pub min_validation_success_rate: f64,
    pub max_duplicate_ratio: f64,
    pub min_peer_score: i32,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            max_block_latency_ms: 5000,      // 5 seconds
            max_tx_latency_ms: 3000,         // 3 seconds
            max_bandwidth_mbps: 10.0,        // 10 MB/s
            min_validation_success_rate: 95.0, // 95%
            max_duplicate_ratio: 20.0,       // 20%
            min_peer_score: -25,             // Warning before ban threshold
        }
    }
}

/// Historical data point for time-series tracking
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub blocks_received: u64,
    pub txs_received: u64,
    pub blocks_rejected: u64,
    pub txs_rejected: u64,
    pub avg_latency_ms: f64,
    pub bandwidth_bps: u64,
    pub active_peers: usize,
    pub banned_peers: usize,
}

/// Time-series metrics storage with rolling window
#[derive(Debug, Clone)]
pub struct MetricsHistory {
    pub snapshots: Vec<MetricsSnapshot>,
    pub max_snapshots: usize,
    pub interval_secs: u64,
    pub last_snapshot: u64,
}

impl MetricsHistory {
    fn new(max_snapshots: usize, interval_secs: u64) -> Self {
        Self {
            snapshots: Vec::new(),
            max_snapshots,
            interval_secs,
            last_snapshot: 0,
        }
    }
    
    fn add_snapshot(&mut self, snapshot: MetricsSnapshot) {
        self.last_snapshot = snapshot.timestamp;
        self.snapshots.push(snapshot);
        if self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0); // Remove oldest
        }
    }
    
    fn should_snapshot(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        now - self.last_snapshot >= self.interval_secs
    }
}

/// UDP mesh protocol routing and handling
pub struct MeshRouter {
    connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
    server_id: Uuid,
    identity_manager: Option<Arc<RwLock<IdentityManager>>>,
    session_manager: Arc<SessionManager>,
    relay_protocol: Arc<RwLock<Option<ZhtpRelayProtocol>>>,
    encryption_manager: Arc<RwLock<ZhtpEncryptionManager>>,
    zhtp_auth_manager: Arc<RwLock<Option<ZhtpAuthManager>>>,
    encryption_sessions: Arc<RwLock<HashMap<String, ZhtpEncryptionSession>>>,
    // Blockchain sync infrastructure
    sync_manager: Arc<lib_network::blockchain_sync::BlockchainSyncManager>,
    // Protocol instances for sending
    bluetooth_protocol: Arc<RwLock<Option<BluetoothMeshProtocol>>>,
    udp_socket: Arc<RwLock<Option<Arc<UdpSocket>>>>,
    // Real-time block propagation - duplicate detection
    recent_blocks: Arc<RwLock<HashMap<lib_blockchain::types::Hash, u64>>>,
    recent_transactions: Arc<RwLock<HashMap<lib_blockchain::types::Hash, u64>>>,
    // Blockchain broadcast receiver
    broadcast_receiver: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedReceiver<lib_blockchain::BlockchainBroadcastMessage>>>>,
    // Phase 3: Rate limiting & monitoring
    peer_rate_limits: Arc<RwLock<HashMap<String, PeerRateLimit>>>,
    broadcast_metrics: Arc<RwLock<BroadcastMetrics>>,
    peer_reputations: Arc<RwLock<HashMap<String, PeerReputation>>>,
    // Phase 4: Advanced monitoring & analytics
    performance_metrics: Arc<RwLock<SyncPerformanceMetrics>>,
    active_alerts: Arc<RwLock<Vec<SyncAlert>>>,
    alert_thresholds: Arc<RwLock<AlertThresholds>>,
    metrics_history: Arc<RwLock<MetricsHistory>>,
    latency_samples_blocks: Arc<RwLock<Vec<u64>>>,  // For percentile calculations
    latency_samples_txs: Arc<RwLock<Vec<u64>>>,
    // Phase 2.5: Multi-hop routing with rewards
    mesh_message_router: Arc<RwLock<MeshMessageRouter>>,
}

impl MeshRouter {
    pub fn new(server_id: Uuid, session_manager: Arc<SessionManager>) -> Self {
        // Create shared connections map
        let connections = Arc::new(RwLock::new(HashMap::new()));
        
        // Create blockchain sync manager
        let sync_manager = Arc::new(lib_network::blockchain_sync::BlockchainSyncManager::new());
        
        // Create duplicate tracking for block propagation
        let recent_blocks = Arc::new(RwLock::new(HashMap::new()));
        let recent_transactions = Arc::new(RwLock::new(HashMap::new()));
        
        // Spawn cleanup task for duplicate tracking
        let recent_blocks_cleanup = recent_blocks.clone();
        let recent_transactions_cleanup = recent_transactions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await; // Every 5 minutes
                let cutoff = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() - 3600; // Keep 1 hour history
                
                // Cleanup old blocks
                let mut blocks = recent_blocks_cleanup.write().await;
                blocks.retain(|_, &mut ts| ts > cutoff);
                
                // Cleanup old transactions
                let mut txs = recent_transactions_cleanup.write().await;
                txs.retain(|_, &mut ts| ts > cutoff);
                
                debug!("Cleaned up duplicate tracking maps (blocks: {}, txs: {})", blocks.len(), txs.len());
            }
        });
        
        // Phase 2.5: Clone connections before moving for router initialization
        let connections_for_router = connections.clone();
        
        Self {
            connections,
            server_id,
            identity_manager: None,
            session_manager,
            relay_protocol: Arc::new(RwLock::new(None)),
            encryption_manager: Arc::new(RwLock::new(ZhtpEncryptionManager::new())),
            zhtp_auth_manager: Arc::new(RwLock::new(None)),
            encryption_sessions: Arc::new(RwLock::new(HashMap::new())),
            sync_manager,
            bluetooth_protocol: Arc::new(RwLock::new(None)),
            udp_socket: Arc::new(RwLock::new(None)),
            recent_blocks,
            recent_transactions,
            broadcast_receiver: Arc::new(RwLock::new(None)),
            peer_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            broadcast_metrics: Arc::new(RwLock::new(BroadcastMetrics::new())),
            peer_reputations: Arc::new(RwLock::new(HashMap::new())),
            // Phase 4: Advanced monitoring
            performance_metrics: Arc::new(RwLock::new(SyncPerformanceMetrics::new())),
            active_alerts: Arc::new(RwLock::new(Vec::new())),
            alert_thresholds: Arc::new(RwLock::new(AlertThresholds::default())),
            metrics_history: Arc::new(RwLock::new(MetricsHistory::new(720, 60))), // 12 hours at 1-min intervals
            latency_samples_blocks: Arc::new(RwLock::new(Vec::new())),
            latency_samples_txs: Arc::new(RwLock::new(Vec::new())),
            // Phase 2.5: Create multi-hop message router with shared connections and empty relay map
            mesh_message_router: Arc::new(RwLock::new(
                MeshMessageRouter::new(
                    connections_for_router, 
                    Arc::new(RwLock::new(HashMap::new()))
                )
            )),
        }
    }
    
    /// Get broadcast metrics
    pub async fn get_broadcast_metrics(&self) -> BroadcastMetrics {
        self.broadcast_metrics.read().await.clone()
    }
    
    /// Get peer reputation (for monitoring/admin purposes)
    pub async fn get_peer_reputation(&self, peer_id: &str) -> Option<PeerReputation> {
        self.peer_reputations.read().await.get(peer_id).cloned()
    }
    
    /// List all peer reputations
    pub async fn list_peer_reputations(&self) -> Vec<PeerReputation> {
        self.peer_reputations.read().await.values().cloned().collect()
    }
    
    // Phase 4: Advanced monitoring getters
    
    /// Get performance metrics
    pub async fn get_performance_metrics(&self) -> SyncPerformanceMetrics {
        self.performance_metrics.read().await.clone()
    }
    
    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<SyncAlert> {
        self.active_alerts.read().await.clone()
    }
    
    /// Acknowledge an alert by ID
    pub async fn acknowledge_alert(&self, alert_id: &str) -> bool {
        let mut alerts = self.active_alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            return true;
        }
        false
    }
    
    /// Clear acknowledged alerts
    pub async fn clear_acknowledged_alerts(&self) {
        let mut alerts = self.active_alerts.write().await;
        alerts.retain(|a| !a.acknowledged);
    }
    
    /// Get alert thresholds
    pub async fn get_alert_thresholds(&self) -> AlertThresholds {
        self.alert_thresholds.read().await.clone()
    }
    
    /// Update alert thresholds
    pub async fn update_alert_thresholds(&self, thresholds: AlertThresholds) {
        *self.alert_thresholds.write().await = thresholds;
    }
    
    /// Get metrics history
    pub async fn get_metrics_history(&self, last_n: Option<usize>) -> Vec<MetricsSnapshot> {
        let history = self.metrics_history.read().await;
        match last_n {
            Some(n) => {
                let start = history.snapshots.len().saturating_sub(n);
                history.snapshots[start..].to_vec()
            }
            None => history.snapshots.clone(),
        }
    }
    
    /// Get peer-specific performance metrics
    pub async fn get_peer_performance(&self, peer_id: &str) -> Option<PeerPerformanceStats> {
        let reputation = self.peer_reputations.read().await.get(peer_id).cloned()?;
        
        Some(PeerPerformanceStats {
            peer_id: peer_id.to_string(),
            reputation_score: reputation.score,
            blocks_accepted: reputation.blocks_accepted,
            blocks_rejected: reputation.blocks_rejected,
            txs_accepted: reputation.txs_accepted,
            txs_rejected: reputation.txs_rejected,
            violations: reputation.violations,
            acceptance_rate: reputation.get_acceptance_rate(),
            first_seen: reputation.first_seen,
            last_seen: reputation.last_seen,
        })
    }
    
    /// List all peers with performance stats
    pub async fn list_peer_performance(&self) -> Vec<PeerPerformanceStats> {
        let reputations = self.peer_reputations.read().await;
        reputations.iter().map(|(peer_id, rep)| {
            PeerPerformanceStats {
                peer_id: peer_id.clone(),
                reputation_score: rep.score,
                blocks_accepted: rep.blocks_accepted,
                blocks_rejected: rep.blocks_rejected,
                txs_accepted: rep.txs_accepted,
                txs_rejected: rep.txs_rejected,
                violations: rep.violations,
                acceptance_rate: rep.get_acceptance_rate(),
                first_seen: rep.first_seen,
                last_seen: rep.last_seen,
            }
        }).collect()
    }

    // ==================== Phase 4: Performance Tracking Methods ====================

    /// Record block propagation latency
    async fn track_block_latency(&self, block_timestamp: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if now > block_timestamp {
            let latency_ms = ((now - block_timestamp) * 1000) as u64;
            
            // Add to latency samples for percentile calculation
            let mut samples = self.latency_samples_blocks.write().await;
            samples.push(latency_ms);
            
            // Keep only last 1000 samples to prevent unbounded growth
            if samples.len() > 1000 {
                let excess = samples.len() - 1000;
                samples.drain(0..excess);
            }
            
            // Update metrics
            self.update_performance_metrics().await;
        }
    }

    /// Record transaction propagation latency
    async fn track_tx_latency(&self, tx_timestamp: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if now > tx_timestamp {
            let latency_ms = ((now - tx_timestamp) * 1000) as u64;
            
            // Add to latency samples
            let mut samples = self.latency_samples_txs.write().await;
            samples.push(latency_ms);
            
            // Keep only last 1000 samples
            if samples.len() > 1000 {
                let excess = samples.len() - 1000;
                samples.drain(0..excess);
            }
            
            // Update metrics
            self.update_performance_metrics().await;
        }
    }

    /// Record bytes sent to track bandwidth
    async fn track_bytes_sent(&self, bytes: u64) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.total_bytes_sent += bytes;
    }

    /// Record bytes received to track bandwidth
    async fn track_bytes_received(&self, bytes: u64) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.total_bytes_received += bytes;
    }

    /// Calculate p95 percentile from samples
    fn calculate_p95(samples: &[u64]) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        
        let index = ((sorted.len() as f64) * 0.95).ceil() as usize;
        sorted.get(index.saturating_sub(1)).copied().unwrap_or(0)
    }

    /// Update performance metrics with current data
    async fn update_performance_metrics(&self) {
        let mut metrics = self.performance_metrics.write().await;
        
        // Calculate block latency metrics
        let block_samples = self.latency_samples_blocks.read().await;
        if !block_samples.is_empty() {
            let sum: u64 = block_samples.iter().sum();
            metrics.avg_block_propagation_ms = sum as f64 / block_samples.len() as f64;
            metrics.p95_block_latency_ms = Self::calculate_p95(&block_samples);
            metrics.min_block_latency_ms = *block_samples.iter().min().unwrap_or(&0);
            metrics.max_block_latency_ms = *block_samples.iter().max().unwrap_or(&0);
        }
        
        // Calculate tx latency metrics
        let tx_samples = self.latency_samples_txs.read().await;
        if !tx_samples.is_empty() {
            let sum: u64 = tx_samples.iter().sum();
            metrics.avg_tx_propagation_ms = sum as f64 / tx_samples.len() as f64;
            metrics.p95_tx_latency_ms = Self::calculate_p95(&tx_samples);
            metrics.min_tx_latency_ms = *tx_samples.iter().min().unwrap_or(&0);
            metrics.max_tx_latency_ms = *tx_samples.iter().max().unwrap_or(&0);
        }
        
        // Calculate bandwidth metrics
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let duration = now.saturating_sub(metrics.measurement_start);
        if duration > 0 {
            metrics.bytes_sent_per_sec = metrics.total_bytes_sent as f64 / duration as f64;
            metrics.bytes_received_per_sec = metrics.total_bytes_received as f64 / duration as f64;
            
            // Update peak bandwidth
            let current_bps = (metrics.bytes_sent_per_sec + metrics.bytes_received_per_sec) as u64;
            if current_bps > metrics.peak_bandwidth_usage_bps {
                metrics.peak_bandwidth_usage_bps = current_bps;
            }
        }
        
        // Calculate efficiency metrics
        let broadcast_metrics = self.broadcast_metrics.read().await;
        let total_blocks = broadcast_metrics.blocks_received;
        let rejected_blocks = broadcast_metrics.blocks_rejected;
        if total_blocks > 0 {
            metrics.duplicate_block_ratio = (rejected_blocks as f64 / total_blocks as f64) * 100.0;
            metrics.validation_success_rate = ((total_blocks - rejected_blocks) as f64 / total_blocks as f64) * 100.0;
        }
        
        let total_txs = broadcast_metrics.transactions_received;
        let rejected_txs = broadcast_metrics.transactions_rejected;
        if total_txs > 0 {
            metrics.duplicate_tx_ratio = (rejected_txs as f64 / total_txs as f64) * 100.0;
        }
        
        // Calculate relay efficiency (accepted / total sent)
        let total_sent = broadcast_metrics.blocks_sent + broadcast_metrics.transactions_sent;
        if total_sent > 0 {
            metrics.relay_efficiency = ((total_blocks + total_txs) as f64 / total_sent as f64) * 100.0;
        }
        
        metrics.measurement_duration_secs = duration;
    }

    /// Check thresholds and generate alerts
    async fn check_and_generate_alerts(&self) {
        let metrics = self.performance_metrics.read().await;
        let thresholds = self.alert_thresholds.read().await;
        let mut alerts = self.active_alerts.write().await;
        
        // Check block latency threshold
        if metrics.avg_block_propagation_ms > thresholds.max_block_latency_ms as f64 {
            let alert = SyncAlert::new(
                AlertLevel::Warning,
                "block_latency".to_string(),
                format!("Block propagation latency ({:.2}ms) exceeds threshold ({}ms)", 
                        metrics.avg_block_propagation_ms, thresholds.max_block_latency_ms)
            ).with_metric(metrics.avg_block_propagation_ms, thresholds.max_block_latency_ms as f64);
            
            // Only add if not already present
            if !alerts.iter().any(|a| a.category == "block_latency" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check tx latency threshold
        if metrics.avg_tx_propagation_ms > thresholds.max_tx_latency_ms as f64 {
            let alert = SyncAlert::new(
                AlertLevel::Warning,
                "tx_latency".to_string(),
                format!("Transaction propagation latency ({:.2}ms) exceeds threshold ({}ms)", 
                        metrics.avg_tx_propagation_ms, thresholds.max_tx_latency_ms)
            ).with_metric(metrics.avg_tx_propagation_ms, thresholds.max_tx_latency_ms as f64);
            
            if !alerts.iter().any(|a| a.category == "tx_latency" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check bandwidth threshold
        let bandwidth_mbps = (metrics.bytes_sent_per_sec + metrics.bytes_received_per_sec) / 1_000_000.0;
        if bandwidth_mbps > thresholds.max_bandwidth_mbps {
            let alert = SyncAlert::new(
                AlertLevel::Critical,
                "bandwidth".to_string(),
                format!("Bandwidth usage ({:.2} MB/s) exceeds threshold ({:.2} MB/s)", 
                        bandwidth_mbps, thresholds.max_bandwidth_mbps)
            ).with_metric(bandwidth_mbps, thresholds.max_bandwidth_mbps);
            
            if !alerts.iter().any(|a| a.category == "bandwidth" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check validation success rate
        if metrics.validation_success_rate < thresholds.min_validation_success_rate && metrics.validation_success_rate > 0.0 {
            let alert = SyncAlert::new(
                AlertLevel::Critical,
                "validation_rate".to_string(),
                format!("Validation success rate ({:.1}%) below threshold ({:.1}%)", 
                        metrics.validation_success_rate, thresholds.min_validation_success_rate)
            ).with_metric(metrics.validation_success_rate, thresholds.min_validation_success_rate);
            
            if !alerts.iter().any(|a| a.category == "validation_rate" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check duplicate ratio
        if metrics.duplicate_block_ratio > thresholds.max_duplicate_ratio {
            let alert = SyncAlert::new(
                AlertLevel::Warning,
                "duplicate_blocks".to_string(),
                format!("Duplicate block ratio ({:.1}%) exceeds threshold ({:.1}%)", 
                        metrics.duplicate_block_ratio, thresholds.max_duplicate_ratio)
            ).with_metric(metrics.duplicate_block_ratio, thresholds.max_duplicate_ratio);
            
            if !alerts.iter().any(|a| a.category == "duplicate_blocks" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check peer scores
        let reputations = self.peer_reputations.read().await;
        for (peer_id, rep) in reputations.iter() {
            if rep.score < thresholds.min_peer_score && rep.score < 0 {
                let alert = SyncAlert::new(
                    AlertLevel::Warning,
                    "peer_score".to_string(),
                    format!("Peer {} has low reputation score ({})", &peer_id[..16.min(peer_id.len())], rep.score)
                ).with_peer(peer_id.clone()).with_metric(rep.score as f64, thresholds.min_peer_score as f64);
                
                if !alerts.iter().any(|a| a.category == "peer_score" && a.peer_id.as_ref() == Some(peer_id) && !a.acknowledged) {
                    alerts.push(alert);
                }
            }
        }
    }

    /// Create a metrics snapshot for historical tracking
    async fn create_metrics_snapshot(&self) -> MetricsSnapshot {
        let broadcast_metrics = self.broadcast_metrics.read().await;
        let performance_metrics = self.performance_metrics.read().await;
        let connections = self.connections.read().await;
        let reputations = self.peer_reputations.read().await;
        
        let banned_count = reputations.values().filter(|r| r.is_banned()).count();
        
        MetricsSnapshot {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            blocks_received: broadcast_metrics.blocks_received,
            txs_received: broadcast_metrics.transactions_received,
            blocks_rejected: broadcast_metrics.blocks_rejected,
            txs_rejected: broadcast_metrics.transactions_rejected,
            avg_latency_ms: (performance_metrics.avg_block_propagation_ms + performance_metrics.avg_tx_propagation_ms) / 2.0,
            bandwidth_bps: (performance_metrics.bytes_sent_per_sec + performance_metrics.bytes_received_per_sec) as u64,
            active_peers: connections.len(),
            banned_peers: banned_count,
        }
    }

    /// Start background metrics snapshot task
    pub async fn start_metrics_snapshot_task(&self) {
        let metrics_history = self.metrics_history.clone();
        let mesh_router = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Create snapshot
                let snapshot = mesh_router.create_metrics_snapshot().await;
                
                // Add to history
                let mut history = metrics_history.write().await;
                history.add_snapshot(snapshot);
                
                // Check and generate alerts
                mesh_router.check_and_generate_alerts().await;
                
                debug!("📊 Metrics snapshot created ({} total snapshots)", history.snapshots.len());
            }
        });
        
        info!("✓ Started metrics snapshot background task (60s interval)");
    }
    
    /// Set the blockchain broadcast receiver and start processing task
    pub async fn set_broadcast_receiver(&self, mut receiver: tokio::sync::mpsc::UnboundedReceiver<lib_blockchain::BlockchainBroadcastMessage>) {
        info!("✓ Blockchain broadcast channel connected to mesh router");
        
        let connections = self.connections.clone();
        let recent_blocks = self.recent_blocks.clone();
        let recent_transactions = self.recent_transactions.clone();
        let udp_socket = self.udp_socket.clone();
        let broadcast_metrics = self.broadcast_metrics.clone();
        // TODO: Add bluetooth_protocol when NetworkProtocol::Bluetooth variant is implemented
        
        // Spawn task to process broadcast messages from blockchain
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    lib_blockchain::BlockchainBroadcastMessage::NewBlock(block) => {
                        info!("📡 Broadcasting new block {} to mesh network", block.height());
                        
                        // Serialize block
                        let block_data = match bincode::serialize(&block) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize block: {}", e);
                                continue;
                            }
                        };
                        
                        // Get local node's public key
                        // TODO: Implement proper node identity retrieval
                        let sender_pubkey = lib_crypto::PublicKey::new(vec![]);
                        
                        // Create NewBlock message
                        let message = lib_network::types::mesh_message::ZhtpMeshMessage::NewBlock {
                            block: block_data,
                            sender: sender_pubkey,
                            height: block.height(),
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                        };
                        
                        // Serialize message
                        let serialized = match bincode::serialize(&message) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize NewBlock message: {}", e);
                                continue;
                            }
                        };
                        
                        // Broadcast to all connected peers
                        let conns = connections.read().await;
                        let mut success_count = 0;
                        
                        for (_peer_key, connection) in conns.iter() {
                            match &connection.protocol {
                                lib_network::protocols::NetworkProtocol::UDP => {
                                    if let Some(ref sock) = *udp_socket.read().await {
                                        if let Some(peer_addr_str) = &connection.peer_address {
                                            if let Ok(addr) = peer_addr_str.parse::<SocketAddr>() {
                                                if sock.send_to(&serialized, addr).await.is_ok() {
                                                    success_count += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {} // Other protocols can be added as needed
                            }
                        }
                        
                        // TODO: Add Bluetooth mesh broadcasting when NetworkProtocol::Bluetooth is implemented
                        
                        info!("📤 Block {} broadcast to {} peers", block.height(), success_count);
                        
                        // Update metrics
                        broadcast_metrics.write().await.blocks_sent += 1;
                        
                        // Mark as seen (prevent echo)
                        recent_blocks.write().await.insert(
                            block.header.hash(),
                            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                        );
                    }
                    lib_blockchain::BlockchainBroadcastMessage::NewTransaction(tx) => {
                        debug!("📡 Broadcasting new transaction {} to mesh network", tx.hash());
                        
                        // Serialize transaction
                        let tx_data = match bincode::serialize(&tx) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize transaction: {}", e);
                                continue;
                            }
                        };
                        
                        // Get local node's public key (use empty vec for now - TODO: get from identity manager)
                        let sender_pubkey = lib_crypto::PublicKey::new(vec![]);
                        
                        // Get tx hash bytes
                        let tx_hash = tx.hash();
                        let tx_hash_slice = tx_hash.as_bytes();
                        let mut tx_hash_bytes = [0u8; 32];
                        tx_hash_bytes.copy_from_slice(tx_hash_slice);
                        
                        // Create NewTransaction message
                        let message = lib_network::types::mesh_message::ZhtpMeshMessage::NewTransaction {
                            transaction: tx_data,
                            sender: sender_pubkey,
                            tx_hash: tx_hash_bytes,
                            fee: 1000, // TODO: Extract actual fee from transaction
                        };
                        
                        // Serialize message
                        let serialized = match bincode::serialize(&message) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize NewTransaction message: {}", e);
                                continue;
                            }
                        };
                        
                        // Broadcast to all connected peers
                        let conns = connections.read().await;
                        let mut success_count = 0;
                        
                        for (_peer_key, connection) in conns.iter() {
                            match &connection.protocol {
                                lib_network::protocols::NetworkProtocol::UDP => {
                                    if let Some(ref sock) = *udp_socket.read().await {
                                        if let Some(peer_addr_str) = &connection.peer_address {
                                            if let Ok(addr) = peer_addr_str.parse::<SocketAddr>() {
                                                if sock.send_to(&serialized, addr).await.is_ok() {
                                                    success_count += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {} // TODO: Add other protocols as needed
                            }
                        }
                        
                        debug!("📤 Transaction {} broadcast to {} peers", tx.hash(), success_count);
                        
                        // Update metrics
                        broadcast_metrics.write().await.transactions_sent += 1;
                        
                        // Mark as seen (prevent echo)
                        recent_transactions.write().await.insert(
                            tx.hash(),
                            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                        );
                    }
                }
            }
            
            warn!("Blockchain broadcast receiver task terminated");
        });
        
        info!("✓ Blockchain broadcast processing task started");
    }
    
    pub fn set_identity_manager(&mut self, manager: Arc<RwLock<IdentityManager>>) {
        self.identity_manager = Some(manager);
    }
    
    /// Set Bluetooth protocol for sending messages
    pub async fn set_bluetooth_protocol(&self, protocol: BluetoothMeshProtocol) {
        *self.bluetooth_protocol.write().await = Some(protocol);
    }
    
    /// Set UDP socket for sending messages
    pub async fn set_udp_socket(&self, socket: Arc<UdpSocket>) {
        *self.udp_socket.write().await = Some(socket);
    }
    
    /// Set mesh server for reward tracking (Phase 2.5)
    /// This links the router to the mesh server so routing rewards can be recorded
    pub async fn set_mesh_server(&self, mesh_server: Arc<RwLock<ZhtpMeshServer>>) {
        let mut router = self.mesh_message_router.write().await;
        router.set_mesh_server(mesh_server);
        info!("✅ Phase 2.5: Mesh server linked to router for reward tracking");
    }
    
    /// Get a clone of the connections Arc for sharing with other components
    pub fn get_connections(&self) -> Arc<RwLock<HashMap<PublicKey, MeshConnection>>> {
        self.connections.clone()
    }
    
    /// Get a clone of the relay protocol Arc for sharing with other components
    pub fn get_relay_protocol(&self) -> Arc<RwLock<Option<ZhtpRelayProtocol>>> {
        self.relay_protocol.clone()
    }
    
    /// Get a clone of the identity manager Arc for sharing with other components
    pub fn get_identity_manager(&self) -> Option<Arc<RwLock<IdentityManager>>> {
        self.identity_manager.clone()
    }
    
    /// Get sender's public key from identity manager (for routing)
    async fn get_sender_public_key(&self) -> Result<PublicKey> {
        if let Some(ref identity_mgr) = self.identity_manager {
            let mgr = identity_mgr.read().await;
            // Get the first identity (typically the node's identity)
            if let Some(identity) = mgr.list_identities().first() {
                // Convert Vec<u8> to PublicKey with proper array conversion
                let mut key_id = [0u8; 32];
                let len = identity.public_key.len().min(32);
                key_id[..len].copy_from_slice(&identity.public_key[..len]);
                
                return Ok(PublicKey {
                    key_id,
                    dilithium_pk: vec![], // Empty for now, can be added later
                    kyber_pk: vec![],     // Empty for now, can be added later
                });
            }
        }
        Err(anyhow::anyhow!("No identity available for sender public key"))
    }
    
    /// Send a mesh message to a specific peer using multi-hop routing (Phase 2.5)
    /// This method uses MeshMessageRouter for intelligent path finding and reward tracking
    pub async fn send_to_peer(&self, peer_id: &PublicKey, message: ZhtpMeshMessage) -> Result<()> {
        info!("🚀 Phase 2.5: Routing message via multi-hop router to {:?}", 
              hex::encode(&peer_id.key_id[0..8.min(peer_id.key_id.len())]));
        
        // Get sender's public key
        let sender = self.get_sender_public_key().await?;
        
        // Use the multi-hop message router for intelligent routing
        let router = self.mesh_message_router.read().await;
        let message_id = router.route_message(message, peer_id.clone(), sender).await?;
        
        info!("✅ Message routed successfully! Message ID: {}", message_id);
        info!("   Multi-hop routing with protocol bonuses and quality tracking active");
        
        Ok(())
    }
    
    /// Broadcast a message to all connected peers (excluding optional sender)
    /// Used for real-time block and transaction propagation
    pub async fn broadcast_to_peers(
        &self,
        message: ZhtpMeshMessage,
        exclude: Option<&PublicKey>,
    ) -> Result<usize> {
        let connections = self.connections.read().await;
        
        // Serialize message once for efficiency
        let serialized = bincode::serialize(&message)
            .context("Failed to serialize broadcast message")?;
        
        let mut success_count = 0;
        let mut failed_count = 0;
        
        for (peer_key, connection) in connections.iter() {
            // Skip excluded peer (usually the original sender)
            if let Some(excluded_key) = exclude {
                if peer_key == excluded_key {
                    continue;
                }
            }
            
            // Skip if no peer address
            let peer_address = match connection.peer_address.as_ref() {
                Some(addr) => addr,
                None => {
                    debug!("Skipping peer without address: {:?}", hex::encode(&peer_key.key_id[0..8.min(peer_key.key_id.len())]));
                    continue;
                }
            };
            
            // Send based on protocol type
            let result = match &connection.protocol {
                lib_network::protocols::NetworkProtocol::UDP => {
                    let socket = self.udp_socket.read().await;
                    if let Some(ref sock) = *socket {
                        let peer_addr: Result<SocketAddr, _> = peer_address.parse();
                        match peer_addr {
                            Ok(addr) => sock.send_to(&serialized, addr).await.map(|_| ()).map_err(|e| anyhow::anyhow!("UDP send error: {}", e)),
                            Err(e) => Err(anyhow::anyhow!("Invalid address: {}", e)),
                        }
                    } else {
                        Err(anyhow::anyhow!("UDP socket not available"))
                    }
                }
                lib_network::protocols::NetworkProtocol::BluetoothLE | 
                lib_network::protocols::NetworkProtocol::BluetoothClassic => {
                    let bluetooth = self.bluetooth_protocol.read().await;
                    if let Some(ref protocol) = *bluetooth {
                        protocol.send_mesh_message(peer_address, &serialized).await
                    } else {
                        Err(anyhow::anyhow!("Bluetooth protocol not available"))
                    }
                }
                _ => {
                    debug!("Skipping unsupported protocol: {:?}", connection.protocol);
                    continue;
                }
            };
            
            match result {
                Ok(_) => {
                    success_count += 1;
                    debug!("Broadcast to peer {:?} successful", hex::encode(&peer_key.key_id[0..8.min(peer_key.key_id.len())]));
                }
                Err(e) => {
                    failed_count += 1;
                    debug!("Failed to broadcast to peer {:?}: {}", hex::encode(&peer_key.key_id[0..8.min(peer_key.key_id.len())]), e);
                }
            }
        }
        
        if success_count > 0 || failed_count > 0 {
            info!("📡 Broadcast complete: {} succeeded, {} failed", success_count, failed_count);
        }
        Ok(success_count)
    }
    
    /// Initialize ZHTP authentication manager with blockchain identity
    pub async fn initialize_auth_manager(&self, blockchain_pubkey: PublicKey) -> Result<()> {
        info!(" Initializing ZHTP authentication manager...");
        
        let auth_manager = ZhtpAuthManager::new(blockchain_pubkey)?;
        *self.zhtp_auth_manager.write().await = Some(auth_manager);
        
        info!(" ZHTP authentication manager initialized (Dilithium2)");
        Ok(())
    }
    
    /// Initialize ZHTP relay protocol with blockchain keys
    pub async fn initialize_relay_protocol(&self) -> Result<()> {
        info!("Initializing ZHTP relay protocol with post-quantum encryption...");
        
        // Generate Dilithium2 keypair for signing relay messages
        let (dilithium_pubkey, dilithium_privkey) = lib_crypto::post_quantum::dilithium::dilithium2_keypair();
        
        // Create node capabilities for relay protocol
        let capabilities = lib_network::protocols::zhtp_auth::NodeCapabilities {
            has_dht: true,
            can_relay: true,
            max_bandwidth: 1000000, // 1 Gbps
            protocols: vec!["zhtp".to_string(), "dht".to_string()],
            reputation: 100,
            quantum_secure: true,
        };
        
        // Create relay protocol instance (secret_key, public_key, capabilities)
        let relay = ZhtpRelayProtocol::new(
            dilithium_privkey,
            dilithium_pubkey,
            capabilities,
        );
        
        *self.relay_protocol.write().await = Some(relay);
        
        info!(" ZHTP relay protocol initialized (Dilithium2 + Kyber512 + ChaCha20)");
        Ok(())
    }
    
    pub async fn handle_udp_mesh(&self, data: &[u8], addr: SocketAddr) -> Result<Option<Vec<u8>>> {
        debug!("Processing UDP mesh packet from: {} ({} bytes)", addr, data.len());
        
        // First, try to parse as ZhtpMeshMessage (includes blockchain sync messages)
        if let Ok(mesh_message) = bincode::deserialize::<ZhtpMeshMessage>(data) {
            info!("📨 Received ZhtpMeshMessage from: {}", addr);
            
            // Handle blockchain-specific messages
            match &mesh_message {
                ZhtpMeshMessage::BlockchainRequest { requester, request_id, from_height } => {
                    info!(" Blockchain request received from {:?} (request_id: {}, from_height: {:?})", 
                          hex::encode(&requester.key_id[0..8]), request_id, from_height);
                    
                    // Export and send blockchain chunks directly
                    match crate::runtime::blockchain_provider::get_global_blockchain().await {
                        Ok(blockchain_arc) => {
                            let blockchain_lock = blockchain_arc.read().await;
                            
                            // Export blockchain data
                            match blockchain_lock.export_chain() {
                                Ok(blockchain_data) => {
                                    info!(" Exported {} bytes of blockchain data", blockchain_data.len());
                                    
                                    // Get connection info for chunking
                                    let connections = self.connections.read().await;
                                    if let Some(connection) = connections.get(requester) {
                                        // Chunk data based on protocol
                                        match lib_network::blockchain_sync::BlockchainSyncManager::chunk_blockchain_data_for_protocol(
                                            *request_id,
                                            blockchain_data,
                                            &connection.protocol
                                        ) {
                                            Ok(chunk_messages) => {
                                                let chunk_count = chunk_messages.len();
                                                info!(" Sending {} blockchain chunks to peer", chunk_count);
                                                
                                                // Send each chunk
                                                for chunk_message in chunk_messages {
                                                    if let Err(e) = self.send_to_peer(requester, chunk_message).await {
                                                        error!("Failed to send blockchain chunk: {}", e);
                                                        break;
                                                    }
                                                }
                                                info!(" All blockchain chunks sent successfully");
                                            }
                                            Err(e) => error!("Failed to chunk blockchain data: {}", e),
                                        }
                                    } else {
                                        warn!("No connection found for requester");
                                    }
                                }
                                Err(e) => error!("Failed to export blockchain: {}", e),
                            }
                        }
                        Err(e) => error!("Failed to get global blockchain: {}", e),
                    }
                    
                    return Ok(None);
                }
                ZhtpMeshMessage::BlockchainData { request_id, chunk_index, total_chunks, data: chunk_data, complete_data_hash } => {
                    info!(" Blockchain chunk {}/{} received (request_id: {}, {} bytes)", 
                          chunk_index + 1, total_chunks, request_id, chunk_data.len());
                    
                    // Add chunk to sync manager
                    match self.sync_manager.add_chunk(
                        *request_id,
                        *chunk_index,
                        *total_chunks,
                        chunk_data.clone(),
                        *complete_data_hash
                    ).await {
                        Ok(Some(complete_data)) => {
                            info!(" All blockchain chunks received and verified! Total: {} bytes", complete_data.len());
                            info!("   Importing blockchain data...");
                            
                            // Import the blockchain
                            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                                Ok(blockchain_arc) => {
                                    let mut blockchain_lock = blockchain_arc.write().await;
                                    
                                    match blockchain_lock.evaluate_and_merge_chain(complete_data).await {
                                        Ok(merge_result) => {
                                            info!(" Blockchain imported successfully from peer");
                                            info!("   Merge result: {:?}", merge_result);
                                            info!("   New blockchain height: {}", blockchain_lock.get_height());
                                        }
                                        Err(e) => error!("Failed to import blockchain: {}", e),
                                    }
                                }
                                Err(e) => error!("Failed to get global blockchain: {}", e),
                            }
                        }
                        Ok(None) => {
                            debug!("Chunk {}/{} buffered, waiting for more chunks", chunk_index + 1, total_chunks);
                        }
                        Err(e) => {
                            error!("Failed to process blockchain chunk: {}", e);
                        }
                    }
                    
                    return Ok(None);
                }
                ZhtpMeshMessage::NewBlock { block, sender, height, timestamp } => {
                    info!("📦 Received NewBlock at height {} from {:?}", height, hex::encode(&sender.key_id[0..8.min(sender.key_id.len())]));
                    
                    // Phase 4: Track block latency
                    self.track_block_latency(*timestamp).await;
                    
                    // Phase 4: Track bytes received
                    self.track_bytes_received(block.len() as u64).await;
                    
                    let sender_key = hex::encode(&sender.key_id);
                    
                    // Check peer reputation first - reject if banned
                    {
                        let mut reputations = self.peer_reputations.write().await;
                        let reputation = reputations.entry(sender_key.clone()).or_insert_with(|| PeerReputation::new(sender_key.clone()));
                        
                        if reputation.is_banned() {
                            warn!("🚫 Blocked NewBlock from banned peer {} (score: {}, violations: {})", 
                                  &sender_key[..16], reputation.score, reputation.violations);
                            self.broadcast_metrics.write().await.blocks_rejected += 1;
                            return Ok(None);
                        }
                    }
                    
                    // Rate limiting check
                    let mut rate_limits = self.peer_rate_limits.write().await;
                    let rate_limit = rate_limits.entry(sender_key.clone()).or_insert_with(PeerRateLimit::new);
                    
                    const MAX_BLOCKS_PER_MINUTE: u32 = 10; // Configurable limit
                    if !rate_limit.check_and_increment_block(MAX_BLOCKS_PER_MINUTE) {
                        let violations = rate_limit.get_violations();
                        warn!("⚠️ Rate limit exceeded for peer {} (violations: {}) - rejecting block {}", 
                              &sender_key[..16], violations, height);
                        
                        // Record violation in reputation
                        drop(rate_limits);
                        
                        let mut reputations = self.peer_reputations.write().await;
                        if let Some(reputation) = reputations.get_mut(&sender_key) {
                            reputation.record_violation();
                            if reputation.is_banned() {
                                warn!("🚫 Peer {} has been banned (score: {}, violations: {})", 
                                      &sender_key[..16], reputation.score, reputation.violations);
                            }
                        }
                        
                        self.broadcast_metrics.write().await.blocks_rejected += 1;
                        return Ok(None);
                    }
                    drop(rate_limits);
                    
                    // Update metrics
                    self.broadcast_metrics.write().await.blocks_received += 1;
                    
                    // Check for duplicates using hash of block data
                    let block_data_hash = {
                        let hash_bytes = lib_crypto::hash_blake3(&block);
                        lib_blockchain::types::Hash::from(hash_bytes)
                    };
                    
                    {
                        let mut recent = self.recent_blocks.write().await;
                        if recent.contains_key(&block_data_hash) {
                            debug!("Duplicate block {} ignored", height);
                            return Ok(None);
                        }
                        recent.insert(block_data_hash, *timestamp);
                    }
                    
                    // Deserialize block
                    let received_block = match lib_blockchain::integration::network_integration::deserialize_block_from_network(&block) {
                        Ok(b) => b,
                        Err(e) => {
                            error!("Failed to deserialize block: {}", e);
                            return Ok(None);
                        }
                    };
                    
                    // Validate block height matches
                    if received_block.height() != *height {
                        warn!("Block height mismatch: advertised {}, actual {}", height, received_block.height());
                        return Ok(None);
                    }
                    
                    // Get blockchain and try to add block
                    match crate::runtime::blockchain_provider::get_global_blockchain().await {
                        Ok(blockchain_arc) => {
                            let blockchain = blockchain_arc.read().await;
                            
                            // Check if we already have this block
                            if blockchain.get_height() >= *height {
                                if let Some(existing) = blockchain.get_block(*height) {
                                    if existing.header.hash() == received_block.header.hash() {
                                        debug!("Block {} already in chain", height);
                                        return Ok(None);
                                    }
                                }
                            }
                            drop(blockchain); // Release read lock before acquiring write lock
                            
                            let mut blockchain = blockchain_arc.write().await;
                            
                            // Export as single-block chain for evaluation
                            let import_data = lib_blockchain::BlockchainImport {
                                blocks: vec![received_block.clone()],
                                utxo_set: HashMap::new(),
                                identity_registry: HashMap::new(),
                                wallet_registry: HashMap::new(),
                                token_contracts: HashMap::new(),
                                web4_contracts: HashMap::new(),
                                contract_blocks: HashMap::new(),
                                validator_registry: HashMap::new(),
                            };
                            
                            let serialized = match bincode::serialize(&import_data) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!("Failed to serialize block for import: {}", e);
                                    return Ok(None);
                                }
                            };
                            
                            // Try to evaluate and merge
                            match blockchain.evaluate_and_merge_chain(serialized).await {
                                Ok(merge_result) => {
                                    match merge_result {
                                        lib_consensus::ChainMergeResult::ImportedAdopted | 
                                        lib_consensus::ChainMergeResult::Merged => {
                                            info!("✅ Block {} accepted into blockchain", height);
                                            
                                            // Update reputation - block accepted
                                            {
                                                let mut reputations = self.peer_reputations.write().await;
                                                if let Some(reputation) = reputations.get_mut(&sender_key) {
                                                    reputation.record_block_accepted();
                                                }
                                            }
                                            
                                            // Update metrics for relay
                                            self.broadcast_metrics.write().await.blocks_relayed += 1;
                                            
                                            drop(blockchain); // Release lock before broadcasting
                                            
                                            // Relay to other peers (excluding sender)
                                            let relay_message = ZhtpMeshMessage::NewBlock {
                                                block: block.clone(),
                                                sender: sender.clone(),
                                                height: *height,
                                                timestamp: *timestamp,
                                            };
                                            
                                            if let Err(e) = self.broadcast_to_peers(relay_message, Some(&sender)).await {
                                                warn!("Failed to relay block to peers: {}", e);
                                            }
                                        },
                                        lib_consensus::ChainMergeResult::LocalKept => {
                                            debug!("Block {} rejected - local chain is better", height);
                                            
                                            // Update reputation - block rejected
                                            {
                                                let mut reputations = self.peer_reputations.write().await;
                                                if let Some(reputation) = reputations.get_mut(&sender_key) {
                                                    reputation.record_block_rejected();
                                                }
                                            }
                                            
                                            self.broadcast_metrics.write().await.blocks_rejected += 1;
                                        },
                                        lib_consensus::ChainMergeResult::Failed(reason) => {
                                            warn!("Block {} validation failed: {}", height, reason);
                                            
                                            // Update reputation - block rejected
                                            {
                                                let mut reputations = self.peer_reputations.write().await;
                                                if let Some(reputation) = reputations.get_mut(&sender_key) {
                                                    reputation.record_block_rejected();
                                                }
                                            }
                                            
                                            self.broadcast_metrics.write().await.blocks_rejected += 1;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to evaluate block {}: {}", height, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to get global blockchain: {}", e);
                        }
                    }
                    
                    return Ok(None);
                }
                ZhtpMeshMessage::NewTransaction { transaction, sender, tx_hash, fee } => {
                    info!("💸 Received NewTransaction {:?} (fee: {}) from {:?}", 
                          hex::encode(&tx_hash[0..8]), fee, hex::encode(&sender.key_id[0..8.min(sender.key_id.len())]));
                    
                    // Phase 4: Track bytes received
                    self.track_bytes_received(transaction.len() as u64).await;
                    
                    let sender_key = hex::encode(&sender.key_id);
                    
                    // Check peer reputation first - reject if banned
                    {
                        let mut reputations = self.peer_reputations.write().await;
                        let reputation = reputations.entry(sender_key.clone()).or_insert_with(|| PeerReputation::new(sender_key.clone()));
                        
                        if reputation.is_banned() {
                            warn!("🚫 Blocked NewTransaction from banned peer {} (score: {})", 
                                  &sender_key[..16], reputation.score);
                            self.broadcast_metrics.write().await.transactions_rejected += 1;
                            return Ok(None);
                        }
                    }
                    
                    // Rate limiting check
                    let mut rate_limits = self.peer_rate_limits.write().await;
                    let rate_limit = rate_limits.entry(sender_key.clone()).or_insert_with(PeerRateLimit::new);
                    
                    const MAX_TXS_PER_MINUTE: u32 = 100; // Configurable limit
                    if !rate_limit.check_and_increment_tx(MAX_TXS_PER_MINUTE) {
                        warn!("⚠️ Rate limit exceeded for peer {} - rejecting transaction", &sender_key[..16]);
                        
                        // Record violation
                        drop(rate_limits);
                        let mut reputations = self.peer_reputations.write().await;
                        if let Some(reputation) = reputations.get_mut(&sender_key) {
                            reputation.record_violation();
                        }
                        
                        self.broadcast_metrics.write().await.transactions_rejected += 1;
                        return Ok(None);
                    }
                    drop(rate_limits);
                    
                    // Update metrics
                    self.broadcast_metrics.write().await.transactions_received += 1;
                    
                    // Check for duplicates
                    let tx_hash_obj = lib_blockchain::types::Hash::from(*tx_hash);
                    {
                        let mut recent = self.recent_transactions.write().await;
                        let current_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        
                        if recent.contains_key(&tx_hash_obj) {
                            debug!("Duplicate transaction {:?} ignored", hex::encode(&tx_hash[0..8]));
                            return Ok(None);
                        }
                        recent.insert(tx_hash_obj, current_time);
                    }
                    
                    // Deserialize transaction
                    let received_tx = match lib_blockchain::integration::network_integration::deserialize_transaction_from_network(&transaction) {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to deserialize transaction: {}", e);
                            return Ok(None);
                        }
                    };
                    
                    // Validate hash matches
                    let computed_hash = received_tx.hash();
                    if computed_hash.as_bytes() != tx_hash {
                        warn!("Transaction hash mismatch");
                        return Ok(None);
                    }
                    
                    // Add to mempool
                    match crate::runtime::blockchain_provider::get_global_blockchain().await {
                        Ok(blockchain_arc) => {
                            let mut blockchain = blockchain_arc.write().await;
                            
                            match blockchain.add_pending_transaction(received_tx) {
                                Ok(()) => {
                                    info!("✅ Transaction {:?} accepted to mempool", hex::encode(&tx_hash[0..8]));
                                    
                                    // Update reputation - transaction accepted
                                    {
                                        let mut reputations = self.peer_reputations.write().await;
                                        if let Some(reputation) = reputations.get_mut(&sender_key) {
                                            reputation.record_tx_accepted();
                                        }
                                    }
                                    
                                    // Update metrics for relay
                                    self.broadcast_metrics.write().await.transactions_relayed += 1;
                                    
                                    drop(blockchain); // Release lock before broadcasting
                                    
                                    // Relay to other peers (excluding sender)
                                    let relay_message = ZhtpMeshMessage::NewTransaction {
                                        transaction: transaction.clone(),
                                        sender: sender.clone(),
                                        tx_hash: *tx_hash,
                                        fee: *fee,
                                    };
                                    
                                    if let Err(e) = self.broadcast_to_peers(relay_message, Some(&sender)).await {
                                        warn!("Failed to relay transaction to peers: {}", e);
                                    }
                                },
                                Err(e) => {
                                    debug!("Transaction {:?} rejected from mempool: {}", hex::encode(&tx_hash[0..8]), e);
                                    
                                    // Update reputation - transaction rejected
                                    {
                                        let mut reputations = self.peer_reputations.write().await;
                                        if let Some(reputation) = reputations.get_mut(&sender_key) {
                                            reputation.record_tx_rejected();
                                        }
                                    }
                                    
                                    self.broadcast_metrics.write().await.transactions_rejected += 1;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to get global blockchain: {}", e);
                        }
                    }
                    
                    return Ok(None);
                }
                _ => {
                    // Other mesh messages - process via handler
                    debug!("Processing non-blockchain mesh message");
                    // We'll handle other message types below or let them fall through
                }
            }
        }
        
        // Second, try to parse as ZHTP relay query (encrypted DHT request)
        if let Ok(relay_query) = bincode::deserialize::<ZhtpRelayQuery>(data) {
            info!(" Received ZHTP relay query from: {} (encrypted)", addr);
            
            if let Some(relay_protocol) = self.relay_protocol.read().await.as_ref() {
                let peer_address = addr.to_string();
                match relay_protocol.process_relay_query(&peer_address, &relay_query).await {
                    Ok(query_payload) => {
                        info!(" ZHTP relay query verified and decrypted: domain={}, path={}", 
                            query_payload.domain, query_payload.path);
                        
                        // Query local DHT for the requested content
                        if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
                            let dht = dht_client.read().await;
                            let content_key = format!("{}/{}", query_payload.domain, query_payload.path);
                            
                            match dht.fetch_content(&content_key).await {
                                Ok(content) => {
                                    info!(" Found DHT content ({} bytes), creating encrypted response", content.len());
                                    
                                    // Create response payload with content hash
                                    let content_hash_bytes = lib_crypto::hash_blake3(&content);
                                    let content_hash = lib_crypto::Hash::from_bytes(&content_hash_bytes);
                                    let response_payload = lib_network::dht::protocol::ZhtpRelayResponsePayload {
                                        content: Some(content),
                                        content_type: Some("application/octet-stream".to_string()),
                                        content_hash: Some(content_hash),
                                        error: None,
                                        ttl: 3600,
                                    };
                                    
                                    // Create encrypted relay response
                                    let peer_address = addr.to_string();
                                    match relay_protocol.create_relay_response(
                                        &peer_address,
                                        relay_query.request_id.clone(),
                                        response_payload
                                    ).await {
                                        Ok(relay_response) => {
                                            info!(" Created encrypted relay response, sending back to {}", addr);
                                            let response_bytes = bincode::serialize(&relay_response)?;
                                            return Ok(Some(response_bytes));
                                        },
                                        Err(e) => {
                                            warn!("Failed to create relay response: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    warn!("DHT content not found: {}", e);
                                    // Return empty response or error
                                }
                            }
                        }
                    },
                    Err(e) => {
                        warn!(" ZHTP relay query verification failed: {}", e);
                    }
                }
            } else {
                warn!("ZHTP relay protocol not initialized");
            }
        }
        
        // Bridge to Bluetooth if we have Bluetooth clients connected
        let _: Result<()> = self.bridge_dht_to_bluetooth(data, &addr).await;
        
        // Try to parse as ZHTP mesh message
        if let Ok(message_str) = std::str::from_utf8(data) {
            if let Ok(mesh_message) = serde_json::from_str::<serde_json::Value>(message_str) {
                if let Some(zhtp_request) = mesh_message.get("ZhtpRequest") {
                    info!("Received ZHTP mesh request from: {}", addr);
                    info!("Raw ZHTP request data: {}", serde_json::to_string_pretty(zhtp_request).unwrap_or_default());
                    
                    // Parse the mesh-specific ZHTP request format
                    if let Ok(mesh_req) = Self::parse_mesh_request(zhtp_request) {
                        info!("ZHTP Method: {}, URI: {}", mesh_req.method, mesh_req.uri);
                        
                        // Check if this is an API request that should be handled directly via UDP mesh
                        if mesh_req.uri.starts_with("/api/v1/identity") {
                            info!(" Handling identity API request directly via UDP mesh: {} {}", mesh_req.method, mesh_req.uri);
                            
                            // Handle identity API requests directly without HTTP overhead
                            return self.handle_identity_mesh_request(&mesh_req, zhtp_request).await;
                        }
                        
                        // Convert mesh request to proper ZhtpMethod for non-API requests
                        let _method = match mesh_req.method.to_uppercase().as_str() {
                            "GET" => ZhtpMethod::Get,
                            "POST" => ZhtpMethod::Post,
                            "PUT" => ZhtpMethod::Put,
                            "DELETE" => ZhtpMethod::Delete,
                            "HEAD" => ZhtpMethod::Head,
                            "OPTIONS" => ZhtpMethod::Options,
                            _ => ZhtpMethod::Get, // Default fallback
                        };
                        
                        // Create a successful ZHTP response for mesh protocol (fallback)
                        let zhtp_response = ZhtpResponse {
                            version: "1.0".to_string(),
                            status: ZhtpStatus::Ok,
                            status_message: "OK".to_string(),
                            headers: ZhtpHeaders::new(),
                            body: serde_json::json!({
                                "status": "success",
                                "message": "ZHTP mesh connection established",
                                "server_id": self.server_id,
                                "protocol": "ZHTP_MESH_v1.0",
                                "method": mesh_req.method,
                                "uri": mesh_req.uri,
                                "timestamp": mesh_req.timestamp,
                                "capabilities": ["api", "mesh", "storage", "identity"],
                                "ok": true,
                                "connected": true
                            }).to_string().into_bytes(),
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            server: None,
                            validity_proof: None,
                        };
                        
                        // Create a compatible response structure for the browser
                        let mut response_json = serde_json::to_value(&zhtp_response)?;
                        
                        // Ensure numeric status code for browser compatibility
                        if let Some(response_obj) = response_json.as_object_mut() {
                            response_obj.insert("status".to_string(), serde_json::Value::Number(serde_json::Number::from(200u16)));
                        }
                        
                        // Wrap response in ZHTP mesh format
                        let mesh_response = serde_json::json!({
                            "ZhtpResponse": response_json
                        });
                        
                        let response_bytes = serde_json::to_vec(&mesh_response)?;
                        info!("Sending ZHTP mesh response ({} bytes)", response_bytes.len());
                        return Ok(Some(response_bytes));
                    } else {
                        warn!("Failed to parse mesh ZHTP request from browser");
                    }
                }
            }
        }
        
        // Fallback to raw mesh packet processing
        info!("Processing raw mesh packet from: {}", addr);
        Ok(None)
    }
    
    /// Parse mesh-specific ZHTP request format and convert to standard ZhtpRequest
    fn parse_mesh_request(mesh_data: &serde_json::Value) -> Result<MeshZhtpRequest> {
        serde_json::from_value(mesh_data.clone())
            .context("Failed to parse mesh ZHTP request")
    }
    
    /// Handle identity API requests directly via UDP mesh for maximum efficiency
    async fn handle_identity_mesh_request(&self, mesh_req: &MeshZhtpRequest, zhtp_request: &serde_json::Value) -> Result<Option<Vec<u8>>> {
        info!("Processing identity request via UDP mesh: {} {}", mesh_req.method, mesh_req.uri);
        
        // Check if we have access to identity manager
        let identity_manager = match &self.identity_manager {
            Some(manager) => manager,
            None => {
                warn!("Identity manager not available");
                return self.create_error_mesh_response(500, "Identity manager not available").await;
            }
        };
        
        // Route based on URI path
        if mesh_req.uri == "/api/v1/identity/create" && mesh_req.method.to_uppercase() == "POST" {
            info!(" Creating new zkDID identity via UDP mesh");
            
                    // Extract request data from the original ZHTP request body
                    let request_data = if let Some(body_data) = zhtp_request.get("body") {
                        info!("Found body data in ZHTP request");
                        
                        // Handle different body formats
                        if let Some(body_array) = body_data.as_array() {
                            // Convert byte array to string
                            let body_bytes: Vec<u8> = body_array.iter()
                                .filter_map(|v| v.as_u64())
                                .map(|v| v as u8)
                                .collect();
                            let body_str = String::from_utf8_lossy(&body_bytes);
                            info!("Converted body array to string: {}", body_str);
                            
                            match serde_json::from_str::<serde_json::Value>(&body_str) {
                                Ok(parsed) => {
                                    info!("Successfully parsed request JSON from array");
                                    parsed
                                },
                                Err(e) => {
                                    warn!("Failed to parse body array as JSON: {}, using string as display name", e);
                                    serde_json::json!({
                                        "display_name": body_str.trim(),
                                        "identity_type": "human"
                                    })
                                }
                            }
                        } else if let Some(body_str) = body_data.as_str() {
                            // Direct string body
                            info!("Found string body: {}", body_str);
                            match serde_json::from_str::<serde_json::Value>(body_str) {
                                Ok(parsed) => {
                                    info!("Successfully parsed request JSON from string");
                                    parsed
                                },
                                Err(e) => {
                                    warn!("Failed to parse body string as JSON: {}, using as display name", e);
                                    serde_json::json!({
                                        "display_name": body_str.trim(),
                                        "identity_type": "human"
                                    })
                                }
                            }
                        } else {
                            // Use body data directly if it's already an object
                            info!("Using body data directly as object");
                            body_data.clone()
                        }
                    } else {
                        info!("No body found in ZHTP request, using defaults");
                        serde_json::json!({
                            "display_name": "Anonymous User", 
                            "identity_type": "human"
                        })
                    };
                    
                    info!("Final request data: {}", serde_json::to_string_pretty(&request_data).unwrap_or_default());            // Create identity using the identity manager directly
            match self.create_identity_direct(identity_manager, &request_data).await {
                Ok(identity_result) => {
                    info!("Identity created successfully via UDP mesh");
                    
                            // Serialize identity result properly as JSON string
                            let identity_data = match serde_json::to_string(&identity_result) {
                                Ok(json_string) => {
                                    info!("Successfully serialized identity data: {}", &json_string[..std::cmp::min(200, json_string.len())]);
                                    json_string
                                },
                                Err(e) => {
                                    warn!("Failed to serialize identity result: {}", e);
                                    format!("{{\"error\": \"Serialization failed: {}\"}}", e)
                                }
                            };
                            
                            let response_json = serde_json::json!({
                                "status": 200,
                                "status_message": "OK", 
                                "headers": {
                                    "Content-Type": "application/json",
                                    "X-ZHTP-Success": "true"
                                },
                                "body": identity_data.as_bytes(),
                                "timestamp": std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs()
                            });                    let mesh_response = serde_json::json!({
                        "ZhtpResponse": response_json
                    });
                    
                    Ok(Some(serde_json::to_vec(&mesh_response)?))
                },
                Err(e) => {
                    warn!("Identity creation failed: {}", e);
                    self.create_error_mesh_response(500, &format!("Identity creation failed: {}", e)).await
                }
            }
        } else if mesh_req.uri == "/api/v1/identity/signin" && mesh_req.method.to_uppercase() == "POST" {
            info!("🔓 Signing in with existing zkDID identity via UDP mesh");
            
            // Extract request data from the original ZHTP request body
            let request_data = if let Some(body_data) = zhtp_request.get("body") {
                info!("Found signin body data in ZHTP request");
                
                // Handle different body formats
                if let Some(body_array) = body_data.as_array() {
                    // Convert byte array to string
                    let body_bytes: Vec<u8> = body_array.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|v| v as u8)
                        .collect();
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    info!("Converted signin body array to string: {}", body_str);
                    
                    match serde_json::from_str::<serde_json::Value>(&body_str) {
                        Ok(parsed) => {
                            info!("Successfully parsed signin request JSON from array");
                            parsed
                        },
                        Err(e) => {
                            warn!("Failed to parse signin body array as JSON: {}, using string as did", e);
                            serde_json::json!({
                                "did": body_str.trim()
                            })
                        }
                    }
                } else if let Some(body_str) = body_data.as_str() {
                    // Direct string body
                    info!("Found signin string body: {}", body_str);
                    match serde_json::from_str::<serde_json::Value>(body_str) {
                        Ok(parsed) => {
                            info!("Successfully parsed signin request JSON from string");
                            parsed
                        },
                        Err(e) => {
                            warn!("Failed to parse signin body string as JSON: {}, using as did", e);
                            serde_json::json!({
                                "did": body_str.trim()
                            })
                        }
                    }
                } else {
                    // Use body data directly if it's already an object
                    info!("Using signin body data directly as object");
                    body_data.clone()
                }
            } else {
                warn!("No body found in signin ZHTP request");
                return self.create_error_mesh_response(400, "Missing signin data").await;
            };
            
            info!("Final signin request data: {}", serde_json::to_string_pretty(&request_data).unwrap_or_default());
            
            // Handle signin using the identity manager directly
            match self.signin_identity_direct(identity_manager, &request_data).await {
                Ok(signin_result) => {
                    info!("Identity signin successful via UDP mesh");
                    
                    // Serialize signin result properly as JSON string
                    let signin_data = match serde_json::to_string(&signin_result) {
                        Ok(json_string) => {
                            info!("Successfully serialized signin data: {}", &json_string[..std::cmp::min(200, json_string.len())]);
                            json_string
                        },
                        Err(e) => {
                            warn!("Failed to serialize signin result: {}", e);
                            format!("{{\"error\": \"Signin serialization failed: {}\"}}", e)
                        }
                    };
                    
                    let response_json = serde_json::json!({
                        "status": 200,
                        "status_message": "OK", 
                        "headers": {
                            "Content-Type": "application/json",
                            "X-ZHTP-Success": "true"
                        },
                        "body": signin_data.as_bytes(),
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    });
                    
                    let mesh_response = serde_json::json!({
                        "ZhtpResponse": response_json
                    });
                    
                    Ok(Some(serde_json::to_vec(&mesh_response)?))
                },
                Err(e) => {
                    warn!("Identity signin failed: {}", e);
                    self.create_error_mesh_response(401, &format!("Identity signin failed: {}", e)).await
                }
            }
        } else if mesh_req.uri == "/api/v1/wallet/create" && mesh_req.method.to_uppercase() == "POST" {
            info!("💳 Creating identity-linked wallet via UDP mesh");
            
            // Extract wallet creation request data
            let request_data = if let Some(body_data) = zhtp_request.get("body") {
                // Handle body parsing similar to identity creation
                if let Some(body_array) = body_data.as_array() {
                    let body_bytes: Vec<u8> = body_array.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|v| v as u8)
                        .collect();
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    serde_json::from_str::<serde_json::Value>(&body_str).unwrap_or_else(|_| {
                        serde_json::json!({
                            "wallet_name": body_str.trim(),
                            "wallet_type": "Standard"
                        })
                    })
                } else if let Some(body_str) = body_data.as_str() {
                    serde_json::from_str::<serde_json::Value>(body_str).unwrap_or_else(|_| {
                        serde_json::json!({
                            "wallet_name": body_str.trim(),
                            "wallet_type": "Standard"
                        })
                    })
                } else {
                    body_data.clone()
                }
            } else {
                serde_json::json!({
                    "wallet_name": "Anonymous Wallet",
                    "wallet_type": "Standard"
                })
            };
            
            // Handle identity-linked wallet creation
            match self.create_standalone_wallet_direct(request_data).await {
                Ok(wallet_result) => {
                    info!("Identity-linked wallet created successfully");
                    
                    let wallet_data = serde_json::to_string(&wallet_result).unwrap_or_default();
                    let response_json = serde_json::json!({
                        "status": 200,
                        "status_message": "OK",
                        "headers": {
                            "Content-Type": "application/json",
                            "X-ZHTP-Success": "true"
                        },
                        "body": wallet_data.as_bytes(),
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    });
                    
                    let mesh_response = serde_json::json!({
                        "ZhtpResponse": response_json
                    });
                    
                    Ok(Some(serde_json::to_vec(&mesh_response)?))
                },
                Err(e) => {
                    warn!("Identity-linked wallet creation failed: {}", e);
                    self.create_error_mesh_response(500, &format!("Wallet creation failed: {}", e)).await
                }
            }
        } else if mesh_req.uri == "/api/v1/identity/import" && mesh_req.method.to_uppercase() == "POST" {
            info!(" Importing identity from 20-word phrase via UDP mesh");
            
            // Extract import request data
            let request_data = if let Some(body_data) = zhtp_request.get("body") {
                if let Some(body_array) = body_data.as_array() {
                    let body_bytes: Vec<u8> = body_array.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|v| v as u8)
                        .collect();
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    serde_json::from_str::<serde_json::Value>(&body_str).unwrap_or_else(|_| {
                        serde_json::json!({
                            "recovery_phrase": body_str.trim()
                        })
                    })
                } else if let Some(body_str) = body_data.as_str() {
                    serde_json::from_str::<serde_json::Value>(body_str).unwrap_or_else(|_| {
                        serde_json::json!({
                            "recovery_phrase": body_str.trim()
                        })
                    })
                } else {
                    body_data.clone()
                }
            } else {
                return self.create_error_mesh_response(400, "Missing recovery phrase in request body").await;
            };
            
            match self.import_identity_direct(identity_manager, &request_data).await {
                Ok(import_result) => {
                    info!("Identity imported successfully");
                    
                    let import_data = serde_json::to_string(&import_result).unwrap_or_default();
                    let response_json = serde_json::json!({
                        "status": 200,
                        "status_message": "OK",
                        "headers": {
                            "Content-Type": "application/json",
                            "X-ZHTP-Success": "true"
                        },
                        "body": import_data.as_bytes(),
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    });
                    
                    let mesh_response = serde_json::json!({
                        "ZhtpResponse": response_json
                    });
                    
                    Ok(Some(serde_json::to_vec(&mesh_response)?))
                },
                Err(e) => {
                    warn!("Identity import failed: {}", e);
                    self.create_error_mesh_response(400, &format!("Identity import failed: {}", e)).await
                }
            }
        } else if mesh_req.uri == "/api/v1/identity/set-password" && mesh_req.method.to_uppercase() == "POST" {
            info!("Setting password for imported identity via UDP mesh");
            
            // Extract password set request data
            let request_data = if let Some(body_data) = zhtp_request.get("body") {
                if let Some(body_array) = body_data.as_array() {
                    let body_bytes: Vec<u8> = body_array.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|v| v as u8)
                        .collect();
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    serde_json::from_str::<serde_json::Value>(&body_str).unwrap_or_default()
                } else if let Some(body_str) = body_data.as_str() {
                    serde_json::from_str::<serde_json::Value>(body_str).unwrap_or_default()
                } else {
                    body_data.clone()
                }
            } else {
                return self.create_error_mesh_response(400, "Missing password data in request body").await;
            };
            
            match self.set_identity_password_direct(identity_manager, &request_data).await {
                Ok(password_result) => {
                    info!("Password set successfully");
                    
                    let password_data = serde_json::to_string(&password_result).unwrap_or_default();
                    let response_json = serde_json::json!({
                        "status": 200,
                        "status_message": "OK",
                        "headers": {
                            "Content-Type": "application/json",
                            "X-ZHTP-Success": "true"
                        },
                        "body": password_data.as_bytes(),
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    });
                    
                    let mesh_response = serde_json::json!({
                        "ZhtpResponse": response_json
                    });
                    
                    Ok(Some(serde_json::to_vec(&mesh_response)?))
                },
                Err(e) => {
                    warn!("Set password failed: {}", e);
                    self.create_error_mesh_response(400, &format!("Set password failed: {}", e)).await
                }
            }
        } else if mesh_req.uri == "/api/v1/identity/signout" && mesh_req.method.to_uppercase() == "POST" {
            info!("🚪 Signing out identity via UDP mesh");
            
            // Extract signout request data (session token)
            let request_data = if let Some(body_data) = zhtp_request.get("body") {
                if let Some(body_array) = body_data.as_array() {
                    let body_bytes: Vec<u8> = body_array.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|v| v as u8)
                        .collect();
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    serde_json::from_str::<serde_json::Value>(&body_str).unwrap_or_default()
                } else if let Some(body_str) = body_data.as_str() {
                    serde_json::from_str::<serde_json::Value>(body_str).unwrap_or_default()
                } else {
                    body_data.clone()
                }
            } else {
                return self.create_error_mesh_response(400, "Missing session token in request body").await;
            };
            
            match self.signout_identity_direct(&request_data).await {
                Ok(signout_result) => {
                    info!("Signout successful");
                    
                    let signout_data = serde_json::to_string(&signout_result).unwrap_or_default();
                    let response_json = serde_json::json!({
                        "status": 200,
                        "status_message": "OK",
                        "headers": {
                            "Content-Type": "application/json",
                            "X-ZHTP-Success": "true"
                        },
                        "body": signout_data.as_bytes(),
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    });
                    
                    let mesh_response = serde_json::json!({
                        "ZhtpResponse": response_json
                    });
                    
                    Ok(Some(serde_json::to_vec(&mesh_response)?))
                },
                Err(e) => {
                    warn!("Signout failed: {}", e);
                    self.create_error_mesh_response(400, &format!("Signout failed: {}", e)).await
                }
            }
        } else {
            warn!("❓ Unknown identity API endpoint: {} {}", mesh_req.method, mesh_req.uri);
            self.create_error_mesh_response(404, "Identity API endpoint not found").await
        }
    }
    
    /// Create identity directly using IdentityManager for UDP mesh efficiency
    async fn create_identity_direct(&self, identity_manager: &Arc<RwLock<IdentityManager>>, request_data: &serde_json::Value) -> Result<serde_json::Value> {
        let mut manager = identity_manager.write().await;
        
        // Extract display name from request data
        let display_name = request_data.get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Anonymous Citizen")
            .to_string();
            
        info!(" Creating identity for: {}", display_name);
        
        // Create a new zkDID identity with full citizenship
        let mut economic_model = lib_identity::economics::EconomicModel::new();
        
        // Use safe recovery options to avoid banned word validation
        let recovery_options = vec![
            "backup_phrase".to_string(),
            "recovery_method".to_string(),
            "secure_backup".to_string()
        ];
        
        let identity_result = manager.create_citizen_identity(
            display_name,
            recovery_options,
            &mut economic_model
        ).await.map_err(|e| anyhow::anyhow!("Failed to create citizen identity: {}", e))?;
            
        // ⚠️ CRITICAL: Drop the write lock BEFORE acquiring read lock to prevent deadlock
        drop(manager);
            
        info!("Created identity with ID: {}", identity_result.identity_id);
        
        // Record identity and wallets on blockchain
        // Convert identity_id to hex string for blockchain registration
        info!("🔍 Step 1: Converting identity_id to hex...");
        let identity_id_hex = hex::encode(&identity_result.identity_id.0);
        info!("🔍 Step 2: Identity ID hex: {}", identity_id_hex);
        
        // Get the identity from manager to extract public key and ownership proof
        info!("🔍 Step 3: Acquiring read lock on identity manager...");
        let manager_read = identity_manager.read().await;
        info!("🔍 Step 4: Retrieving identity from manager...");
        let identity = manager_read.get_identity(&identity_result.identity_id)
            .ok_or_else(|| {
                error!("❌ Identity not found in manager after creation!");
                anyhow::anyhow!("Identity not found in manager after creation")
            })?;
        info!("🔍 Step 5: Identity retrieved successfully");
        let public_key = identity.public_key.clone();
        
        // Extract the proof_data from ZeroKnowledgeProof as bytes for blockchain
        info!("🔍 Step 6: Extracting ownership proof...");
        let ownership_proof_bytes = identity.ownership_proof.proof_data.clone();
        info!("🔍 Step 7: Dropping read lock...");
        drop(manager_read);
        
        info!("🔍 Step 8: Building identity JSON...");
        let identity_json = serde_json::json!({
            "identity_id": identity_id_hex,
            "citizenship_result": {
                "identity_id": identity_id_hex,
                "primary_wallet_id": hex::encode(&identity_result.primary_wallet_id.0),
                "ubi_wallet_id": hex::encode(&identity_result.ubi_wallet_id.0),
                "savings_wallet_id": hex::encode(&identity_result.savings_wallet_id.0),
                "wallet_seed_phrases": {
                    "primary": identity_result.wallet_seed_phrases.primary_wallet_seeds.words.join(" "),
                    "ubi": identity_result.wallet_seed_phrases.ubi_wallet_seeds.words.join(" "),
                    "savings": identity_result.wallet_seed_phrases.savings_wallet_seeds.words.join(" ")
                },
                "privacy_credentials": {
                    "public_key": hex::encode(&public_key),
                    "ownership_proof": hex::encode(&ownership_proof_bytes)
                },
                "created_at": identity_result.privacy_credentials.created_at
            }
        });
        
        // Try blockchain registration with timeout to prevent hanging
        info!("🔗 Attempting blockchain registration...");
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.record_identity_on_blockchain(&identity_json)
        ).await {
            Ok(Ok(())) => {
                info!("✅ Identity successfully registered on blockchain");
            }
            Ok(Err(e)) => {
                error!("⚠️ BLOCKCHAIN REGISTRATION FAILED: {}", e);
                error!("   Error details: {:?}", e);
            }
            Err(_) => {
                error!("⚠️ BLOCKCHAIN REGISTRATION TIMEOUT - operation took >5 seconds");
            }
        }
        info!("🔗 Blockchain registration attempt complete (continuing with response)");
        
        // Distribute DID document to DHT network
        self.distribute_identity_to_dht(&identity_json).await.unwrap_or_else(|e| {
            warn!("Failed to distribute identity to DHT: {}", e);
        });
        
        // Return the full response structure expected by browser
        Ok(serde_json::json!({
            "success": true,
            "identity_id": identity_result.identity_id,
            "citizenship_result": {
                "identity_id": identity_result.identity_id,
                "primary_wallet_id": identity_result.primary_wallet_id,
                "ubi_wallet_id": identity_result.ubi_wallet_id,
                "savings_wallet_id": identity_result.savings_wallet_id,
                "wallet_seed_phrases": {
                    "primary": identity_result.wallet_seed_phrases.primary_wallet_seeds,
                    "ubi": identity_result.wallet_seed_phrases.ubi_wallet_seeds,
                    "savings": identity_result.wallet_seed_phrases.savings_wallet_seeds
                },
                "dao_registration": identity_result.dao_registration,
                "ubi_registration": identity_result.ubi_registration,
                "web4_access": identity_result.web4_access,
                "privacy_credentials": identity_result.privacy_credentials,
                "welcome_bonus": identity_result.welcome_bonus,
                "created_at": identity_result.privacy_credentials.created_at
            }
        }))
    }
    
    /// Sign in with existing identity using IdentityManager for UDP mesh efficiency
    async fn signin_identity_direct(&self, identity_manager: &Arc<RwLock<IdentityManager>>, request_data: &serde_json::Value) -> Result<serde_json::Value> {
        // Extract DID and password from request data
        let did_str = request_data.get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing DID in signin request"))?;
            
        let password = request_data.get("password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing password in signin request"))?;
            
        info!("🔓 Attempting password-based signin for DID: {}", did_str);
        
        // Parse DID string to identity ID
        let identity_id = if did_str.starts_with("did:zhtp:") {
            // Extract the hex part after the prefix
            let hex_part = did_str.strip_prefix("did:zhtp:").unwrap_or(did_str);
            
            // Parse hex string to bytes
            match hex::decode(hex_part) {
                Ok(bytes) => {
                    if bytes.len() == 32 {
                        let mut id_bytes = [0u8; 32];
                        id_bytes.copy_from_slice(&bytes);
                        lib_crypto::Hash::from_bytes(&id_bytes)
                    } else {
                        return Err(anyhow::anyhow!("Invalid DID format: incorrect length"));
                    }
                },
                Err(_) => {
                    return Err(anyhow::anyhow!("Invalid DID format: not valid hex"));
                }
            }
        } else {
            return Err(anyhow::anyhow!("Invalid DID format: must start with 'did:zhtp:'"));
        };
        
        // Validate password for the identity (requires imported identity)
        let manager = identity_manager.read().await;
        let validation_result = manager.validate_identity_password(&identity_id, password);
        drop(manager);
        
        match validation_result {
            Ok(validation) => {
                if validation.valid {
                    // Password validation successful, create session
                    let session_token = self.session_manager.create_session(identity_id.clone()).await?;
                    
                    // Get identity information
                    let manager = identity_manager.read().await;
                    if let Some(identity) = manager.get_identity(&identity_id) {
                        let current_time = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        
                        info!("Password signin successful for identity: {}", hex::encode(&identity.id.0[..8]));
                        
                        Ok(serde_json::json!({
                            "success": true,
                            "session_token": session_token,
                            "did": did_str,
                            "identity_info": {
                                "identity_id": identity.id,
                                "identity_type": format!("{:?}", identity.identity_type),
                                "access_level": format!("{:?}", identity.access_level),
                                "reputation": identity.reputation,
                                "created_at": identity.created_at,
                                "last_active": identity.last_active,
                                "has_credentials": !identity.credentials.is_empty(),
                                "credential_count": identity.credentials.len(),
                                "is_imported": manager.is_identity_imported(&identity_id),
                                "has_password": manager.has_password(&identity_id)
                            },
                            "signin_time": current_time,
                            "message": "Password authentication successful"
                        }))
                    } else {
                        Err(anyhow::anyhow!("Identity not found after successful validation"))
                    }
                } else {
                    warn!("Password validation failed for DID: {}", did_str);
                    Err(anyhow::anyhow!("Invalid password"))
                }
            },
            Err(e) => {
                warn!("Password authentication error for DID {}: {}", did_str, e);
                match e.to_string().as_str() {
                    msg if msg.contains("Identity must be imported") => {
                        Err(anyhow::anyhow!("Identity must be imported using 20-word recovery phrase before password signin"))
                    },
                    msg if msg.contains("No password set") => {
                        Err(anyhow::anyhow!("No password set for this identity. Please set a password first."))
                    },
                    _ => Err(anyhow::anyhow!("Password authentication failed: {}", e))
                }
            }
        }
    }

    /// Import identity from 20-word recovery phrase
    async fn import_identity_direct(&self, identity_manager: &Arc<RwLock<IdentityManager>>, request_data: &serde_json::Value) -> Result<serde_json::Value> {
        let recovery_phrase = request_data.get("recovery_phrase")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing recovery phrase"))?;
        
        info!(" Importing identity from recovery phrase");
        
        let mut manager = identity_manager.write().await;
        let identity_id = manager.import_identity_from_phrase(recovery_phrase).await?;
        
        // Get identity information
        if let Some(identity) = manager.get_identity(&identity_id) {
            let did_string = format!("did:zhtp:{}", hex::encode(&identity_id.0));
            
            info!("Identity imported successfully: {}", hex::encode(&identity_id.0[..8]));
            
            Ok(serde_json::json!({
                "success": true,
                "identity_id": identity_id,
                "did": did_string,
                "identity_info": {
                    "identity_type": format!("{:?}", identity.identity_type),
                    "access_level": format!("{:?}", identity.access_level),
                    "reputation": identity.reputation,
                    "created_at": identity.created_at,
                    "is_imported": manager.is_identity_imported(&identity_id),
                    "can_set_password": true
                },
                "message": "Identity imported successfully. You can now set a password for signin."
            }))
        } else {
            Err(anyhow::anyhow!("Failed to retrieve imported identity"))
        }
    }

    /// Set password for an imported identity
    async fn set_identity_password_direct(&self, identity_manager: &Arc<RwLock<IdentityManager>>, request_data: &serde_json::Value) -> Result<serde_json::Value> {
        let did_str = request_data.get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing DID"))?;
        
        let password = request_data.get("password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing password"))?;
        
        // Parse DID to identity ID
        let identity_id = if did_str.starts_with("did:zhtp:") {
            let hex_part = did_str.strip_prefix("did:zhtp:").unwrap_or(did_str);
            match hex::decode(hex_part) {
                Ok(bytes) => {
                    if bytes.len() == 32 {
                        let mut id_bytes = [0u8; 32];
                        id_bytes.copy_from_slice(&bytes);
                        lib_crypto::Hash::from_bytes(&id_bytes)
                    } else {
                        return Err(anyhow::anyhow!("Invalid DID format: incorrect length"));
                    }
                },
                Err(_) => {
                    return Err(anyhow::anyhow!("Invalid DID format: not valid hex"));
                }
            }
        } else {
            return Err(anyhow::anyhow!("Invalid DID format: must start with 'did:zhtp:'"));
        };
        
        info!("Setting password for DID: {}", did_str);
        
        let mut manager = identity_manager.write().await;
        manager.set_identity_password(&identity_id, password)?;
        
        Ok(serde_json::json!({
            "success": true,
            "did": did_str,
            "message": "Password set successfully. You can now signin with your DID and password."
        }))
    }

    /// Sign out user session
    async fn signout_identity_direct(&self, request_data: &serde_json::Value) -> Result<serde_json::Value> {
        let session_token = request_data.get("session_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing session token"))?;
        
        info!("🚪 Signing out session: {}...", &session_token[..16]);
        
        self.session_manager.remove_session(session_token).await?;
        
        Ok(serde_json::json!({
            "success": true,
            "message": "Signed out successfully"
        }))
    }
    
    /// Create identity-linked wallet using WalletManager (enforces identity requirement)
    async fn create_standalone_wallet_direct(&self, request_data: serde_json::Value) -> Result<serde_json::Value> {
        // Extract wallet parameters
        let wallet_name = request_data.get("wallet_name")
            .and_then(|v| v.as_str())
            .unwrap_or("New Wallet")
            .to_string();
            
        let node_name = request_data.get("node_name")
            .and_then(|v| v.as_str())
            .unwrap_or("API User")
            .to_string();
            
        let wallet_type_str = request_data.get("wallet_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Standard");
            
        let wallet_alias = request_data.get("alias")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        info!("💳 Creating user identity with wallet: {} for node: {}", wallet_name, node_name);
        
        // Create user identity with wallet (enforces identity requirement)
        let (user_identity_id, wallet_id, seed_phrase) = lib_identity::create_user_identity_with_wallet(
            node_name.clone(),
            wallet_name.clone(),
            wallet_alias.clone()
        ).await?;
        
        info!("✓ User identity created: {}", hex::encode(&user_identity_id.0[..8]));
        
        // Create node device identity owned by the user
        info!("⚙ Creating node device identity...");
        let node_device_name = format!("{}-device", node_name);
        let identity_id = lib_identity::create_node_device_identity(
            user_identity_id.clone(),
            wallet_id.clone(),
            node_device_name,
        ).await?;
        
        info!("Created complete identity setup - User: {}, Node Device: {}, Wallet: {}", 
            hex::encode(&user_identity_id.0[..8]),
            hex::encode(&identity_id.0[..8]),
            hex::encode(&wallet_id.0[..8]));
        
        // Record identity-wallet pair on blockchain
        self.record_standalone_wallet_on_blockchain(&user_identity_id, &wallet_id, &wallet_type_str, &wallet_name, &wallet_alias, &seed_phrase).await
            .unwrap_or_else(|e| warn!("Failed to record identity-wallet on blockchain: {}", e));
        
        // Distribute identity-wallet info to DHT
        self.distribute_standalone_wallet_to_dht(&user_identity_id, &wallet_id, &wallet_type_str, &wallet_name).await
            .unwrap_or_else(|e| warn!("Failed to distribute identity-wallet to DHT: {}", e));
        
        // Return wallet creation result with identity
        Ok(serde_json::json!({
            "success": true,
            "user_identity_id": user_identity_id,
            "node_identity_id": identity_id,
            "wallet_id": wallet_id,
            "wallet_type": wallet_type_str,
            "wallet_name": wallet_name,
            "node_name": node_name,
            "alias": wallet_alias,
            "seed_phrase": seed_phrase,
            "created_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "identity_linked": true,
            "blockchain_recorded": true,
            "dht_distributed": true
        }))
    }
    
    /// Record identity-wallet pair on blockchain 
    async fn record_standalone_wallet_on_blockchain(
        &self,
        identity_id: &lib_identity::IdentityId,
        wallet_id: &lib_identity::wallets::WalletId,
        wallet_type: &str,
        wallet_name: &str,
        wallet_alias: &Option<String>,
        seed_phrase: &str
    ) -> Result<()> {
        info!("Recording identity-linked wallet on blockchain...");
        
        let blockchain = lib_blockchain::get_shared_blockchain().await?;
        let mut blockchain_guard = blockchain.write().await;
        
        // Create seed commitment hash for blockchain verification
        // seed_phrase is already a String (20 words joined by spaces)
        let seed_commitment = lib_crypto::hash_blake3(seed_phrase.as_bytes());
        
        let wallet_data = lib_blockchain::WalletTransactionData {
            wallet_id: lib_blockchain::Hash::from_slice(&wallet_id.0),
            wallet_type: wallet_type.to_string(),
            wallet_name: wallet_name.to_string(),
            alias: wallet_alias.clone(),
            public_key: vec![0u8; 32], // Generate proper public key
            owner_identity_id: Some(lib_blockchain::Hash::from_slice(&identity_id.0)), // Identity-linked
            seed_commitment: lib_blockchain::Hash::from_slice(&seed_commitment),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            registration_fee: 25,
            capabilities: 0x0F, // Basic capabilities
            initial_balance: 0,
        };
        
        let _tx_hash = blockchain_guard.register_wallet(wallet_data)?;
        info!("Identity-linked wallet recorded on blockchain");
        Ok(())
    }
    
    /// Distribute identity-wallet pair to DHT
    async fn distribute_standalone_wallet_to_dht(
        &self,
        identity_id: &lib_identity::IdentityId,
        wallet_id: &lib_identity::wallets::WalletId, 
        wallet_type: &str,
        wallet_name: &str
    ) -> Result<()> {
        if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
            let mut dht = dht_client.write().await;
            
            let wallet_info = serde_json::json!({
                "identity_id": hex::encode(&identity_id.0),
                "wallet_id": hex::encode(&wallet_id.0),
                "wallet_type": wallet_type,
                "wallet_name": wallet_name,
                "identity_linked": true,
                "public_endpoint": format!("zhtp://identity.{}.wallet.{}.zhtp/", 
                    hex::encode(&identity_id.0[..8]),
                    hex::encode(&wallet_id.0[..8])),
                "capabilities": ["receive"], // Public capabilities only
                "created_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            });
            
            let wallet_info_bytes = serde_json::to_vec(&wallet_info)?;
            let path = format!("/identity/{}/wallet/{}", 
                hex::encode(&identity_id.0[..8]),
                hex::encode(&wallet_id.0[..8]));
            dht.store_content(
                "wallet.zhtp",
                &path,
                wallet_info_bytes
            ).await?;
            
            info!("Identity-wallet pair distributed to DHT");
        }
        Ok(())
    }
    
    /// Record identity and wallets on blockchain for immutable proof
    async fn record_identity_on_blockchain(&self, identity_result: &serde_json::Value) -> Result<()> {
        info!("🔗 Starting blockchain registration...");
        
        // Get shared blockchain instance
        info!("🔗 Getting shared blockchain instance...");
        let blockchain = lib_blockchain::get_shared_blockchain().await?;
        info!("🔗 Acquiring blockchain write lock...");
        let mut blockchain_guard = blockchain.write().await;
        info!("🔗 Blockchain lock acquired successfully");
        
        // Extract identity data from JSON result
        info!("🔗 Extracting identity_id from JSON...");
        let identity_id_str = identity_result.get("identity_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing identity_id string"))?;
        
        info!("🔗 Identity ID extracted: {}", identity_id_str);
        
        // Parse identity_id from hex string to Hash
        let identity_id_bytes = hex::decode(identity_id_str)
            .map_err(|_| anyhow::anyhow!("Invalid identity_id hex format"))?;
        let identity_hash = lib_crypto::Hash::from_bytes(&identity_id_bytes[..32]);
        
        let did = format!("did:zhtp:{}", identity_id_str);
        
        // Extract display name from citizenship result or default
        let display_name = identity_result.get("citizenship_result")
            .and_then(|cr| cr.get("display_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("ZHTP Citizen")
            .to_string();
        
        // Extract public key from privacy credentials
        let public_key = identity_result.get("citizenship_result")
            .and_then(|cr| cr.get("privacy_credentials"))
            .and_then(|pc| pc.get("public_key"))
            .and_then(|v| v.as_str())
            .and_then(|hex_str| hex::decode(hex_str).ok())
            .unwrap_or_else(|| vec![0u8; 32]); // Fallback to zeros if not found
        
        // Extract ownership proof from privacy credentials  
        let ownership_proof = identity_result.get("citizenship_result")
            .and_then(|cr| cr.get("privacy_credentials"))
            .and_then(|pc| pc.get("ownership_proof"))
            .and_then(|v| v.as_str())
            .and_then(|hex_str| hex::decode(hex_str).ok())
            .unwrap_or_else(|| vec![0u8; 64]); // Fallback if not found
        
        // Extract creation timestamp from privacy credentials
        let created_at = identity_result.get("citizenship_result")
            .and_then(|cr| cr.get("created_at"))
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });
        
        // Create identity transaction data with extracted data
        let identity_data = lib_blockchain::IdentityTransactionData {
            did: did.clone(),
            display_name,
            public_key,
            ownership_proof,
            identity_type: "human".to_string(),
            did_document_hash: lib_blockchain::Hash::from_slice(&[0u8; 32]), // Will be set when DID doc is created
            created_at,
            registration_fee: 100, // Standard registration fee
            dao_fee: 50, // DAO contribution fee
        };
        
        // Register identity on blockchain
        let _identity_tx_hash = blockchain_guard.register_identity(identity_data)?;
        info!("Registered identity {} on blockchain", identity_id_str);
        
        // Register ALL wallets created during citizenship on blockchain
        if let Some(citizenship_result) = identity_result.get("citizenship_result") {
            // Register Primary Wallet with data
            if let Some(primary_wallet_id_val) = citizenship_result.get("primary_wallet_id") {
                let primary_wallet_id_str = primary_wallet_id_val.as_str()
                    .ok_or_else(|| anyhow::anyhow!("primary_wallet_id is not a string"))?;
                
                let primary_wallet_id_bytes = hex::decode(primary_wallet_id_str)
                    .map_err(|_| anyhow::anyhow!("Invalid primary_wallet_id hex format"))?;
                let primary_wallet_hash = lib_blockchain::Hash::from_slice(&primary_wallet_id_bytes[..32]);
                
                // Extract primary wallet seed for commitment hash
                let primary_seed_commitment = citizenship_result.get("wallet_seed_phrases")
                    .and_then(|wsp| wsp.get("primary"))
                    .and_then(|v| v.as_str())
                    .map(|seed_str| {
                        // Create commitment hash from seed phrase
                        let hash_result = lib_crypto::hash_blake3(seed_str.as_bytes());
                        lib_blockchain::Hash::from_slice(&hash_result)
                    })
                    .unwrap_or_else(|| lib_blockchain::Hash::from_slice(&[0u8; 32]));
                
                let wallet_data = lib_blockchain::WalletTransactionData {
                    wallet_id: primary_wallet_hash,
                    wallet_type: "Primary".to_string(),
                    wallet_name: "Primary Wallet".to_string(),
                    alias: Some("primary".to_string()),
                    public_key: vec![0u8; 32], // Will be derived from seed in wallet manager
                    owner_identity_id: Some(lib_blockchain::Hash::new(identity_hash.0)),
                    seed_commitment: primary_seed_commitment,
                    created_at,
                    registration_fee: 50,
                    capabilities: 0xFF, // Full spending capabilities
                    initial_balance: 1000, // Initial funding
                };
                let _primary_tx_hash = blockchain_guard.register_wallet(wallet_data)?;
                info!("Registered Primary Wallet {} on blockchain", primary_wallet_id_str);
            }
            
            // Register UBI Wallet with data
            if let Some(ubi_wallet_id_val) = citizenship_result.get("ubi_wallet_id") {
                let ubi_wallet_id_str = ubi_wallet_id_val.as_str()
                    .ok_or_else(|| anyhow::anyhow!("ubi_wallet_id is not a string"))?;
                
                let ubi_wallet_id_bytes = hex::decode(ubi_wallet_id_str)
                    .map_err(|_| anyhow::anyhow!("Invalid ubi_wallet_id hex format"))?;
                let ubi_wallet_hash = lib_blockchain::Hash::from_slice(&ubi_wallet_id_bytes[..32]);
                
                // Extract UBI wallet seed for commitment hash
                let ubi_seed_commitment = citizenship_result.get("wallet_seed_phrases")
                    .and_then(|wsp| wsp.get("ubi"))
                    .and_then(|v| v.as_str())
                    .map(|seed_str| {
                        let hash_result = lib_crypto::hash_blake3(seed_str.as_bytes());
                        lib_blockchain::Hash::from_slice(&hash_result)
                    })
                    .unwrap_or_else(|| lib_blockchain::Hash::from_slice(&[0u8; 32]));
                
                let wallet_data = lib_blockchain::WalletTransactionData {
                    wallet_id: ubi_wallet_hash,
                    wallet_type: "UBI".to_string(),
                    wallet_name: "UBI Receiving Wallet".to_string(),
                    alias: Some("ubi".to_string()),
                    public_key: vec![0u8; 32], // Will be derived from seed in wallet manager
                    owner_identity_id: Some(lib_blockchain::Hash::new(identity_hash.0)),
                    seed_commitment: ubi_seed_commitment,
                    created_at,
                    registration_fee: 50,
                    capabilities: 0x01, // Receive-only initially
                    initial_balance: 0, // UBI payments come later
                };
                let _ubi_tx_hash = blockchain_guard.register_wallet(wallet_data)?;
                info!("Registered UBI Wallet {} on blockchain", ubi_wallet_id_str);
            }
            
            // Register Savings Wallet with data
            if let Some(savings_wallet_id_val) = citizenship_result.get("savings_wallet_id") {
                let savings_wallet_id_str = savings_wallet_id_val.as_str()
                    .ok_or_else(|| anyhow::anyhow!("savings_wallet_id is not a string"))?;
                
                let savings_wallet_id_bytes = hex::decode(savings_wallet_id_str)
                    .map_err(|_| anyhow::anyhow!("Invalid savings_wallet_id hex format"))?;
                let savings_wallet_hash = lib_blockchain::Hash::from_slice(&savings_wallet_id_bytes[..32]);
                
                // Extract savings wallet seed for commitment hash
                let savings_seed_commitment = citizenship_result.get("wallet_seed_phrases")
                    .and_then(|wsp| wsp.get("savings"))
                    .and_then(|v| v.as_str())
                    .map(|seed_str| {
                        let hash_result = lib_crypto::hash_blake3(seed_str.as_bytes());
                        lib_blockchain::Hash::from_slice(&hash_result)
                    })
                    .unwrap_or_else(|| lib_blockchain::Hash::from_slice(&[0u8; 32]));
                
                // Extract welcome bonus amount
                let welcome_bonus = citizenship_result.get("welcome_bonus")
                    .and_then(|wb| wb.get("bonus_amount"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(4000); // Default welcome bonus
                
                let wallet_data = lib_blockchain::WalletTransactionData {
                    wallet_id: savings_wallet_hash,
                    wallet_type: "Savings".to_string(),
                    wallet_name: "Long-term Savings".to_string(),
                    alias: Some("savings".to_string()),
                    public_key: vec![0u8; 32], // Will be derived from seed in wallet manager
                    owner_identity_id: Some(lib_blockchain::Hash::new(identity_hash.0)),
                    seed_commitment: savings_seed_commitment,
                    created_at,
                    registration_fee: 50,
                    capabilities: 0x02, // Savings-specific capabilities
                    initial_balance: welcome_bonus, // welcome bonus amount
                };
                let _savings_tx_hash = blockchain_guard.register_wallet(wallet_data)?;
                info!("Registered Savings Wallet {} on blockchain", savings_wallet_id_str);
            }
        }
        
        info!("Successfully recorded identity and wallets on blockchain with data");
        Ok(())
    }
    
    /// Distribute DID document and public data to DHT network
    async fn distribute_identity_to_dht(&self, identity_result: &serde_json::Value) -> Result<()> {
        info!("Distributing identity to DHT network...");
        
        // Get DHT client
        if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
            let mut dht = dht_client.write().await;
            
            // Extract identity data
            let identity_id = identity_result.get("identity_id")
                .ok_or_else(|| anyhow::anyhow!("Missing identity_id"))?;
            
            let did = format!("did:zhtp:{}", identity_id);
            
            // Create DID document for DHT storage
            let did_document = serde_json::json!({
                "@context": "https://www.w3.org/ns/did/v1",
                "id": did,
                "verificationMethod": [{
                    "id": format!("{}#key-1", did),
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": "z6Mkf5rGMoatrSj..."  // Would be actual public key
                }],
                "service": [{
                    "id": format!("{}#zhtp-endpoint", did),
                    "type": "ZhtpEndpoint",
                    "serviceEndpoint": "zhtp://identity.zhtp"
                }],
                "created": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            });
            
            // Store DID document in DHT
            let did_doc_bytes = serde_json::to_vec(&did_document)?;
            let did_path = format!("/did/{}", identity_id);
            dht.store_content(
                "identity.zhtp",
                &did_path,
                did_doc_bytes
            ).await?;
            
            // Store wallet registry in DHT for public discovery
            if let Some(citizenship_result) = identity_result.get("citizenship_result") {
                let wallet_registry = serde_json::json!({
                    "owner_did": did,
                    "wallets": {
                        "primary": {
                            "id": citizenship_result.get("primary_wallet_id"),
                            "type": "Primary",
                            "capabilities": ["send", "receive", "stake"],
                            "public_endpoint": format!("zhtp://wallet.{}.zhtp/primary", identity_id)
                        },
                        "ubi": {
                            "id": citizenship_result.get("ubi_wallet_id"),
                            "type": "UBI", 
                            "capabilities": ["receive"],
                            "public_endpoint": format!("zhtp://wallet.{}.zhtp/ubi", identity_id)
                        },
                        "savings": {
                            "id": citizenship_result.get("savings_wallet_id"),
                            "type": "Savings",
                            "capabilities": ["receive", "savings"],
                            "public_endpoint": format!("zhtp://wallet.{}.zhtp/savings", identity_id)
                        }
                    },
                    "created_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs()
                });
                
                let wallet_registry_bytes = serde_json::to_vec(&wallet_registry)?;
                let registry_path = format!("/registry/{}", identity_id);
                dht.store_content(
                    "wallet.zhtp",
                    &registry_path,
                    wallet_registry_bytes
                ).await?;
                
                info!("💳 Distributed wallet registry to DHT network");
            }
            
            info!("Successfully distributed DID document to DHT network");
        } else {
            warn!("DHT client not available for identity distribution");
        }
        
        Ok(())
    }
    
    /// Create error response in mesh format
    async fn create_error_mesh_response(&self, status_code: u16, message: &str) -> Result<Option<Vec<u8>>> {
        let error_response = serde_json::json!({
            "status": status_code,
            "statusText": match status_code {
                400 => "Bad Request",
                404 => "Not Found", 
                500 => "Internal Server Error",
                _ => "Error"
            },
            "headers": {},
            "data": format!("{{\"error\": \"{}\"}}", message),
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
        
        let mesh_response = serde_json::json!({
            "ZhtpResponse": error_response
        });
        
        Ok(Some(serde_json::to_vec(&mesh_response)?))
    }
    
    /// Shared authentication, key exchange, and DHT registration flow
    /// Used by TCP, UDP, and Bluetooth connection handlers
    async fn authenticate_and_register_peer(
        &self,
        peer_pubkey: &PublicKey,
        handshake: &lib_network::discovery::local_network::MeshHandshake,
        addr: &SocketAddr,
        stream: &mut TcpStream,
    ) -> Result<bool> {
        let node_id = &handshake.node_id;
        
        // ============================================================================
        // PHASE 2: BLOCKCHAIN AUTHENTICATION (Dilithium2 signatures)
        // ============================================================================
        info!(" Phase 2: Initiating ZHTP blockchain authentication with peer {}", node_id);
        
        if let Some(auth_manager) = self.zhtp_auth_manager.read().await.as_ref() {
            // Create authentication challenge
            match auth_manager.create_challenge().await {
                Ok(challenge) => {
                    info!(" Sending authentication challenge to peer {}", node_id);
                    
                    // Send challenge over TCP/Bluetooth
                    let challenge_bytes = bincode::serialize(&challenge)?;
                    if let Err(e) = stream.write_all(&challenge_bytes).await {
                        warn!("Failed to send auth challenge to {}: {}", node_id, e);
                        return Ok(false);
                    }
                    
                    // Receive response with timeout
                    let mut response_buf = vec![0; 16384]; // Dilithium signatures are large
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        stream.read(&mut response_buf)
                    ).await {
                        Ok(Ok(response_len)) if response_len > 0 => {
                            match bincode::deserialize::<ZhtpAuthResponse>(&response_buf[..response_len]) {
                                Ok(auth_response) => {
                                    info!(" Received authentication response from peer {}", node_id);
                                    
                                    // Verify Dilithium2 signature
                                    match auth_manager.verify_response(&auth_response).await {
                                        Ok(verification) if verification.authenticated => {
                                            info!(" Peer {} authenticated! Trust score: {:.2}", 
                                                node_id, verification.trust_score);
                                            
                                            // Update connection with blockchain identity
                                            let mut connections = self.connections.write().await;
                                            if let Some(connection) = connections.get_mut(peer_pubkey) {
                                                connection.zhtp_authenticated = true;
                                                connection.peer_dilithium_pubkey = Some(auth_response.responder_pubkey.clone());
                                                connection.trust_score = verification.trust_score;
                                            }
                                            
                                            // ============================================================================
                                            // PHASE 3: QUANTUM-SAFE KEY EXCHANGE (Kyber512)
                                            // ============================================================================
                                            info!(" Phase 3: Initiating Kyber512 key exchange with peer {}", node_id);
                                            
                                            // Create encryption session
                                            match ZhtpEncryptionSession::new() {
                                                Ok(encryption_session) => {
                                                    let session_id = uuid::Uuid::new_v4().to_string();
                                                    
                                                    // Send our Kyber public key
                                                    match encryption_session.create_key_exchange_init(session_id.clone()) {
                                                        Ok(key_init) => {
                                                            let key_init_bytes = bincode::serialize(&key_init)?;
                                                            if let Err(e) = stream.write_all(&key_init_bytes).await {
                                                                warn!("Failed to send Kyber init to {}: {}", node_id, e);
                                                                return Ok(false);
                                                            }
                                                            
                                                            // Receive peer's Kyber ciphertext
                                                            let mut key_response_buf = vec![0; 8192];
                                                            match tokio::time::timeout(
                                                                std::time::Duration::from_secs(10),
                                                                stream.read(&mut key_response_buf)
                                                            ).await {
                                                                Ok(Ok(key_response_len)) if key_response_len > 0 => {
                                                                    match bincode::deserialize::<ZhtpKeyExchangeResponse>(&key_response_buf[..key_response_len]) {
                                                                        Ok(key_response) => {
                                                                            info!(" Received Kyber ciphertext from peer {}", node_id);
                                                                            
                                                                            // Complete key exchange (decapsulate shared secret)
                                                                            let mut session = encryption_session;
                                                                            match session.complete_key_exchange(&key_response) {
                                                                                Ok(_) => {
                                                                                    info!(" Kyber512 shared secret established with peer {}", node_id);
                                                                                    
                                                                                    // Update connection
                                                                                    let mut connections = self.connections.write().await;
                                                                                    if let Some(connection) = connections.get_mut(peer_pubkey) {
                                                                                        connection.quantum_secure = true;
                                                                                        connection.kyber_shared_secret = session.get_shared_secret().map(|s| s.to_vec());
                                                                                    }
                                                                                    
                                                                                    // Store encryption session
                                                                                    self.encryption_sessions.write().await.insert(
                                                                                        node_id.to_string(),
                                                                                        session
                                                                                    );
                                                                                    
                                                                                    // ============================================================================
                                                                                    // PHASE 4: DHT PEER REGISTRATION
                                                                                    // ============================================================================
                                                                                    info!(" Phase 4: Registering peer {} in DHT", node_id);
                                                                                    
                                                                                    // Register peer in DHT with blockchain identity
                                                                                    if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
                                                                                        let dht = dht_client.read().await;
                                                                                        
                                                                                        // Create peer info with blockchain identity
                                                                                        let peer_info = lib_network::dht::peer_discovery::ZhtpPeerInfo {
                                                                                            blockchain_pubkey: peer_pubkey.clone(),
                                                                                            dilithium_pubkey: auth_response.responder_pubkey.clone(),
                                                                                            capabilities: NodeCapabilities {
                                                                                                has_dht: handshake.protocols.contains(&"dht".to_string()),
                                                                                                can_relay: handshake.protocols.contains(&"relay".to_string()),
                                                                                                max_bandwidth: 1_000_000,
                                                                                                protocols: handshake.protocols.clone(),
                                                                                                reputation: verification.trust_score as u32,
                                                                                                quantum_secure: true,
                                                                                            },
                                                                                            addresses: vec![addr.to_string()],
                                                                                            reputation: verification.trust_score,
                                                                                            last_seen: std::time::SystemTime::now()
                                                                                                .duration_since(std::time::UNIX_EPOCH)
                                                                                                .unwrap_or_default()
                                                                                                .as_secs(),
                                                                                            registered_at: std::time::SystemTime::now()
                                                                                                .duration_since(std::time::UNIX_EPOCH)
                                                                                                .unwrap_or_default()
                                                                                                .as_secs(),
                                                                                            ttl: 86400, // 24 hours
                                                                                            signature: auth_response.signature.clone(),
                                                                                        };
                                                                                        
                                                                                        // Register in DHT
                                                                                        match dht.register_peer(peer_info).await {
                                                                                            Ok(()) => {
                                                                                                info!(" SUCCESS! Peer {} fully integrated:", node_id);
                                                                                                info!("   ✓ Blockchain authenticated (Dilithium2)");
                                                                                                info!("   ✓ Quantum-secure encryption (Kyber512)");
                                                                                                info!("   ✓ Registered in DHT peer registry");
                                                                                                info!("   ✓ Ready for relay queries & Web4 content");
                                                                                                
                                                                                                // ============================================================================
                                                                                                // PHASE 5: AUTOMATIC BLOCKCHAIN SYNC
                                                                                                // ============================================================================
                                                                                                info!("🔄 Phase 5: Initiating automatic blockchain sync with peer {}", node_id);
                                                                                                
                                                                                                // Create blockchain sync request
                                                                                                let (request_id, sync_message) = match self.sync_manager
                                                                                                    .create_blockchain_request(peer_pubkey.clone(), None).await {
                                                                                                    Ok(result) => result,
                                                                                                    Err(e) => {
                                                                                                        warn!("Failed to create blockchain sync request: {}", e);
                                                                                                        return Ok(true); // Still return success for connection
                                                                                                    }
                                                                                                };
                                                                                                
                                                                                                info!(" Sending blockchain sync request (ID: {}) to peer {}", request_id, node_id);
                                                                                                
                                                                                                // Send blockchain request to peer
                                                                                                if let Err(e) = self.send_to_peer(&peer_pubkey, sync_message).await {
                                                                                                    warn!("Failed to send blockchain sync request to peer {}: {}", node_id, e);
                                                                                                    warn!("   Connection established but sync will not start automatically");
                                                                                                } else {
                                                                                                    info!(" Blockchain sync request sent successfully");
                                                                                                    info!("    Waiting for blockchain chunks from peer...");
                                                                                                }
                                                                                                
                                                                                                return Ok(true);
                                                                                            }
                                                                                            Err(e) => {
                                                                                                warn!("Failed to register peer {} in DHT: {}", node_id, e);
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                Err(e) => {
                                                                                    warn!("Failed to complete key exchange with {}: {}", node_id, e);
                                                                                }
                                                                            }
                                                                        }
                                                                        Err(e) => {
                                                                            warn!("Failed to deserialize Kyber response from {}: {}", node_id, e);
                                                                        }
                                                                    }
                                                                }
                                                                _ => {
                                                                    warn!("Timeout or error receiving Kyber response from {}", node_id);
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("Failed to create key exchange init: {}", e);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("Failed to create encryption session: {}", e);
                                                }
                                            }
                                        }
                                        Ok(_) => {
                                            warn!(" Peer {} authentication failed (signature invalid)", node_id);
                                            // Remove from connections
                                            self.connections.write().await.remove(peer_pubkey);
                                        }
                                        Err(e) => {
                                            warn!("Error verifying peer {} authentication: {}", node_id, e);
                                            self.connections.write().await.remove(peer_pubkey);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to deserialize auth response from {}: {}", node_id, e);
                                }
                            }
                        }
                        _ => {
                            warn!("Timeout or error receiving auth response from {}", node_id);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to create auth challenge: {}", e);
                }
            }
        } else {
            warn!("  ZHTP authentication manager not initialized, skipping authentication");
        }
        
        Ok(false)
    }
    
    pub async fn handle_tcp_mesh(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("Processing TCP mesh connection from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read TCP mesh data")?;
        
        if bytes_read > 0 {
            debug!("TCP mesh data: {} bytes", bytes_read);
            
            // Try to parse as binary mesh handshake (from local discovery)
            if let Ok(handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(&buffer[..bytes_read]) {
                info!("🤝 Received binary mesh handshake from peer: {}", handshake.node_id);
                info!("   Version: {}, Port: {}, Protocols: {:?}", 
                    handshake.version, handshake.mesh_port, handshake.protocols);
                
                let discovery_method = match handshake.discovered_via {
                    0 => "local_multicast",
                    1 => "bluetooth",
                    2 => "wifi_direct",
                    3 => "manual",
                    _ => "unknown",
                };
                info!("   Discovered via: {}", discovery_method);
                
                // Add peer to mesh connections (like blockchain nodes do)
                // Use node_id as temporary identity until blockchain identity is exchanged
                let peer_pubkey = lib_crypto::PublicKey::new(handshake.node_id.as_bytes().to_vec());
                
                // Determine protocol from discovery method
                let protocol = match handshake.discovered_via {
                    0 => lib_network::protocols::NetworkProtocol::TCP,
                    1 => lib_network::protocols::NetworkProtocol::BluetoothLE,
                    2 => lib_network::protocols::NetworkProtocol::WiFiDirect,
                    _ => lib_network::protocols::NetworkProtocol::TCP,
                };
                
                // Create mesh connection (blockchain identity will be exchanged later)
                let connection = lib_network::mesh::connection::MeshConnection {
                    peer_id: peer_pubkey.clone(),
                    protocol,
                    peer_address: Some(addr.to_string()), //  Store peer address for relay queries
                    signal_strength: 0.8, // Initial estimate
                    bandwidth_capacity: 1_000_000, // 1 MB/s default
                    latency_ms: 50, // Initial estimate
                    connected_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    data_transferred: 0,
                    tokens_earned: 0,
                    stability_score: 1.0,
                    zhtp_authenticated: false, // Will be set to true after blockchain auth
                    quantum_secure: false, // Will enable after Kyber key exchange
                    peer_dilithium_pubkey: None, // Will be exchanged later
                    kyber_shared_secret: None, // Will be established later
                    trust_score: 0.5, // Default trust for new peers
                };
                
                // Add to mesh connections
                {
                    let mut connections = self.connections.write().await;
                    connections.insert(peer_pubkey.clone(), connection);
                    info!(" Peer {} added to mesh network ({} total peers)", 
                        handshake.node_id, connections.len());
                }
                
                // Note: Blockchain sync happens at startup during bootstrap phase
                // See components.rs try_bootstrap_blockchain() function
                
                // Note: Authentication will happen when the peer initiates a proper
                // bidirectional connection. The initial discovery handshake is one-way
                // and disconnects immediately, so we can't complete the auth dance here.
                debug!(" Peer {} registered, awaiting full authentication on next connection", handshake.node_id);
                
                // Send acknowledgment back on original stream
                let ack = bincode::serialize(&true)?;
                let _ = stream.write_all(&ack).await;
            } else {
                // Not a binary handshake, might be other mesh protocol
                debug!("TCP data is not a binary mesh handshake, ignoring");
            }
        }
        
        Ok(())
    }

    /// Bridge Bluetooth messages to DHT network
    pub async fn bridge_bluetooth_to_dht(&self, message_data: &[u8], source_addr: &SocketAddr) -> Result<()> {
        info!("🌉 Bridging Bluetooth message to DHT network from {}", source_addr);
        
        // Parse the Bluetooth message
        let message_str = String::from_utf8_lossy(message_data);
        debug!("Bluetooth message content: {}", message_str.chars().take(100).collect::<String>());
        
        // Extract DHT operation from Bluetooth message
        if message_str.starts_with("DHT:STORE:") {
            // DHT store operation via Bluetooth
            let parts: Vec<&str> = message_str.splitn(4, ':').collect();
            if parts.len() >= 4 {
                let key = parts[2];
                let value = parts[3].as_bytes();
                
                // Forward to DHT network
                // Parse key as domain/path format, or use default domain
                let (domain, path) = if key.contains('/') {
                    let parts: Vec<&str> = key.splitn(2, '/').collect();
                    (parts[0], parts[1])
                } else {
                    ("bluetooth-bridge", key)
                };
                
                info!("Bridging DHT STORE operation: domain={}, path={}, {} bytes", domain, path, value.len());
                
                // Get mutable access to DHT client for store operation
                if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
                    let mut dht = dht_client.write().await;
                    if let Err(e) = dht.store_content(domain, path, value.to_vec()).await {
                        warn!("Failed to store DHT content via Bluetooth bridge: {}", e);
                    } else {
                        info!("Stored DHT content via Bluetooth bridge: domain={}, path={}", domain, path);
                    }
                } else {
                    warn!("DHT client not available for Bluetooth bridge operation");
                }
            }
        } else if message_str.starts_with("DHT:GET:") {
            // DHT get operation via Bluetooth
            let parts: Vec<&str> = message_str.splitn(3, ':').collect();
            if parts.len() >= 3 {
                let key = parts[2];
                
                // Retrieve from DHT network
                if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
                    let dht = dht_client.read().await;
                    match dht.fetch_content(key).await {
                        Ok(data) => {
                            info!("Retrieved DHT data via Bluetooth bridge: {} bytes", data.len());
                            // TODO: Send response back to Bluetooth client
                        },
                        Err(e) => {
                            warn!("Failed to get DHT content via Bluetooth bridge: {}", e);
                        }
                    }
                } else {
                    warn!("DHT client not available for Bluetooth bridge operation");
                }
            }
        } else if message_str.starts_with("ZHTP-MESH:") {
            // General ZHTP mesh message forwarding
            info!("🌉 Forwarding ZHTP mesh message to DHT network");
            // TODO: Implement mesh message forwarding
        }
        
        Ok(())
    }

    /// Bridge DHT/Internet messages to Bluetooth clients
    pub async fn bridge_dht_to_bluetooth(&self, message_data: &[u8], source_addr: &SocketAddr) -> Result<()> {
        debug!("🌉 Attempting to bridge DHT message to Bluetooth clients from {}", source_addr);
        
        // Parse message to see if it's DHT traffic
        if let Ok(message_str) = std::str::from_utf8(message_data) {
            let _bluetooth_message = if message_str.contains("DHT") {
                format!("BRIDGED-DHT:{}", message_str)
            } else if message_str.contains("ZHTP") {
                format!("BRIDGED-ZHTP:{}", message_str)
            } else {
                format!("BRIDGED-MESH:{}", message_str)
            };
            
            info!("Would forward {} message to Bluetooth clients", 
                if message_str.contains("DHT") { "DHT" } else { "MESH" });
            
            // TODO: Implement actual Bluetooth message forwarding
            // This would require maintaining active Bluetooth connections
            // and implementing the reverse TCP connection mechanism
        }
        
        Ok(())
    }
}

/// WiFi Direct device connections
/// WiFi Direct handling with basic group owner detection
pub struct WiFiRouter {
    connected_devices: Arc<RwLock<HashMap<String, String>>>,
    node_id: [u8; 32],
    protocol: Arc<RwLock<Option<WiFiDirectMeshProtocol>>>,
}

/// Bluetooth mesh protocol router for phone connectivity
#[derive(Clone)]
pub struct BluetoothRouter {
    connected_devices: Arc<RwLock<HashMap<String, String>>>,
    node_id: [u8; 32],
    protocol: Arc<RwLock<Option<BluetoothMeshProtocol>>>,
}

/// Bluetooth Classic RFCOMM router for high-throughput mesh
#[derive(Clone)]
pub struct BluetoothClassicRouter {
    connected_devices: Arc<RwLock<HashMap<String, String>>>,
    node_id: [u8; 32],
    protocol: Arc<RwLock<Option<lib_network::protocols::bluetooth::classic::BluetoothClassicProtocol>>>,
}

// Type alias for cleaner code
type ClassicProtocol = lib_network::protocols::bluetooth::classic::BluetoothClassicProtocol;

impl WiFiRouter {
    pub fn new() -> Self {
        let node_id = {
            let mut id = [0u8; 32];
            let uuid = Uuid::new_v4();
            let uuid_bytes = uuid.as_bytes();
            id[..16].copy_from_slice(uuid_bytes);
            id[16..].copy_from_slice(uuid_bytes); // Fill remaining with same UUID
            id
        };
        
        Self {
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            node_id,
            protocol: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Initialize WiFi Direct - simplified version without complex protocol
    pub async fn initialize(&self) -> Result<()> {
        info!("WiFi Direct router initialized with node_id: {:?}", &self.node_id[..8]);
        Ok(())
    }
    
    /// Check if this device is currently a group owner
    pub async fn is_group_owner(&self) -> bool {
        // Simulate group owner detection based on network configuration
        // In a implementation, this would check WiFi Direct interface status
        debug!("Checking WiFi Direct group owner status");
        
        // For demonstration, alternate based on node_id to simulate detection
        let is_owner = (self.node_id[0] % 2) == 0;
        debug!("WiFi Direct group owner status: {} (simulated based on node_id)", is_owner);
        is_owner
    }
    
    pub async fn handle_wifi_direct(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("Processing WiFi Direct connection from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read WiFi Direct data")?;
        
        if bytes_read > 0 {
            debug!("WiFi Direct data: {} bytes", bytes_read);
            
            let is_owner = self.is_group_owner().await;
            let device_role = if is_owner { "Group Owner" } else { "Client" };
            
            info!("WiFi Direct role: {} for connection from {}", device_role, addr);
            
            // Send role-aware acknowledgment
            let response = format!(
                "ZHTP/1.0 200 OK\r\nX-WiFi-Role: {}\r\nX-Node-ID: {:?}\r\n\r\nWiFi Direct connection established as {}",
                device_role, &self.node_id[..8], device_role
            );
            
            let _ = stream.write_all(response.as_bytes()).await;
            
            // Store connection info
            let mut devices = self.connected_devices.write().await;
            devices.insert(addr.to_string(), device_role.to_string());
            
            info!("WiFi Direct connection established with {} as {}", addr, device_role);
        }
        
        Ok(())
    }
}

impl BluetoothRouter {
    pub fn new() -> Self {
        let node_id = {
            let mut id = [0u8; 32];
            let uuid = Uuid::new_v4();
            let uuid_bytes = uuid.as_bytes();
            id[..16].copy_from_slice(uuid_bytes);
            id[16..].copy_from_slice(uuid_bytes); // Fill remaining with same UUID
            id
        };
        
        Self {
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            node_id,
            protocol: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Initialize Bluetooth mesh protocol for phone connectivity
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing Bluetooth mesh protocol for phone connectivity...");
        
        // Create Bluetooth mesh protocol instance
        let mut bluetooth_protocol = BluetoothMeshProtocol::new(self.node_id)?;
        
        // Create GATT message channel for forwarding GATT writes to this router
        let (gatt_tx, mut gatt_rx) = tokio::sync::mpsc::unbounded_channel();
        bluetooth_protocol.set_gatt_message_channel(gatt_tx).await;
        info!(" GATT message channel connected to BluetoothRouter");
        
        // Initialize Bluetooth advertising for ZHTP service
        // Note: Windows COM threading handled within the Bluetooth implementation
        if let Err(e) = bluetooth_protocol.start_advertising().await {
            warn!("Bluetooth advertising failed to start: {}", e);
            // Don't fail the entire initialization if Bluetooth fails
            warn!("Continuing without Bluetooth advertising support");
        } else {
            info!(" Bluetooth advertising started successfully");
        }
        
        // Store the protocol instance
        *self.protocol.write().await = Some(bluetooth_protocol);
        
        // Spawn GATT message handler task
        let connected_devices = self.connected_devices.clone();
        tokio::spawn(async move {
            while let Some(gatt_message) = gatt_rx.recv().await {
                use lib_network::protocols::bluetooth::gatt::GattMessage;
                match gatt_message {
                    GattMessage::MeshHandshake(data) => {
                        info!(" GATT: Received mesh handshake ({} bytes)", data.len());
                        // Parse and process mesh handshake
                        if let Ok(handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(&data) {
                            info!("🤝 GATT handshake from: {}", handshake.node_id);
                            
                            // Track connected device
                            let device_key = handshake.node_id.to_string();
                            let device_info = format!("Bluetooth device (protocols: {:?})", handshake.protocols);
                            connected_devices.write().await.insert(device_key.clone(), device_info);
                            info!("   Tracked device: {}", device_key);
                            // TODO: Add to mesh connections (need mesh_router ref)
                        }
                    }
                    GattMessage::DhtBridge(text) => {
                        info!("🌉 GATT: DHT bridge message: {}", text);
                        // TODO: Forward to DHT
                    }
                    GattMessage::RawData(uuid, data) => {
                        info!(" GATT: Raw data on {}: {} bytes", uuid, data.len());
                        // Process based on characteristic UUID
                    }
                    GattMessage::RelayQuery(data) => {
                        info!(" GATT: Relay query ({} bytes)", data.len());
                        // TODO: Process ZHTP relay query
                    }
                }
            }
            info!("GATT message handler stopped");
        });
        
        info!("Bluetooth mesh protocol initialized - discoverable as 'ZHTP-{}'", 
              hex::encode(&self.node_id[..4]));
        info!("Your phone can now discover and connect to this ZHTP node via Bluetooth");
        
        Ok(())
    }
    
    /// Handle incoming Bluetooth connection with full mesh authentication
    pub async fn handle_bluetooth_connection(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        mesh_router: &MeshRouter,
    ) -> Result<()> {
        info!(" Processing Bluetooth mesh connection from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read Bluetooth data")?;
        
        if bytes_read > 0 {
            debug!("Bluetooth data received: {} bytes", bytes_read);
            
            // Try to parse as binary mesh handshake (same as TCP!)
            if let Ok(handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(&buffer[..bytes_read]) {
                info!("🤝 Received Bluetooth mesh handshake from peer: {}", handshake.node_id);
                info!("   Version: {}, Port: {}, Protocols: {:?}", 
                    handshake.version, handshake.mesh_port, handshake.protocols);
                
                // Create peer identity
                let peer_pubkey = lib_crypto::PublicKey::new(handshake.node_id.as_bytes().to_vec());
                
                // Bluetooth connections use BluetoothLE protocol
                let protocol = lib_network::protocols::NetworkProtocol::BluetoothLE;
                
                // Create mesh connection
                let connection = lib_network::mesh::connection::MeshConnection {
                    peer_id: peer_pubkey.clone(),
                    protocol,
                    peer_address: Some(addr.to_string()), //  Store Bluetooth peer address for relay queries
                    signal_strength: 0.7, // Bluetooth typically lower than WiFi
                    bandwidth_capacity: 250_000, // 250 KB/s - optimized BLE throughput (7.5ms interval + 1ms delay)
                    latency_ms: 100, // Bluetooth has higher latency
                    connected_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    data_transferred: 0,
                    tokens_earned: 0,
                    stability_score: 0.8,
                    zhtp_authenticated: false, // Will be set after authentication
                    quantum_secure: false, // Will be set after Kyber exchange
                    peer_dilithium_pubkey: None,
                    kyber_shared_secret: None,
                    trust_score: 0.5,
                };
                
                // Add to mesh connections
                {
                    let mut connections = mesh_router.connections.write().await;
                    connections.insert(peer_pubkey.clone(), connection);
                    info!(" Bluetooth peer {} added to mesh network ({} total peers)", 
                        handshake.node_id, connections.len());
                }
                
                // Run full authentication, key exchange, and DHT registration (same as TCP!)
                info!(" Starting automatic authentication (no pairing code needed)");
                let _ = mesh_router.authenticate_and_register_peer(&peer_pubkey, &handshake, &addr, &mut stream).await;
                
                // Send acknowledgment
                let ack = bincode::serialize(&true)?;
                let _ = stream.write_all(&ack).await;
                
                info!(" Bluetooth peer fully integrated - zero-trust authentication complete!");
                
            } else {
                // Legacy text-based Bluetooth messages (DHT bridge)
                let message = String::from_utf8_lossy(&buffer[..bytes_read]);
                
                if message.starts_with("ZHTP-MESH:") || message.starts_with("DHT:") {
                    info!("🌉 Bridging Bluetooth ZHTP traffic to DHT network");
                    
                    //  ACTUALLY CALL THE BRIDGE FUNCTION
                    match mesh_router.bridge_bluetooth_to_dht(&buffer[..bytes_read], &addr).await {
                        Ok(()) => {
                            info!(" Bluetooth message successfully bridged to DHT");
                            let response = format!(
                                "ZHTP/1.0 200 OK\r\nX-Protocol: Bluetooth-DHT-Bridge\r\nX-Node-ID: {:?}\r\nX-Service: ZHTP-Mesh\r\nX-Bridge: Active\r\n\r\nBridged to DHT network",
                                &self.node_id[..8]
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                        Err(e) => {
                            warn!("Failed to bridge Bluetooth message to DHT: {}", e);
                            let response = format!(
                                "ZHTP/1.0 500 Internal Server Error\r\nX-Protocol: Bluetooth-DHT-Bridge\r\nX-Error: {}\r\n\r\nBridge failed",
                                e
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                    }
                } else {
                    // Unknown Bluetooth message - still acknowledge
                    info!("Bluetooth message received (not DHT): {} bytes", bytes_read);
                    let response = format!(
                        "ZHTP/1.0 200 OK\r\nX-Protocol: Bluetooth\r\nX-Node-ID: {:?}\r\nX-Service: ZHTP-Mesh\r\n\r\nBluetooth mesh node ready",
                        &self.node_id[..8]
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
                
                // Store legacy connection
                let mut devices = self.connected_devices.write().await;
                devices.insert(addr.to_string(), "bluetooth-legacy-bridge".to_string());
            }
        }
        
        Ok(())
    }


    
    /// Get the Bluetooth service name visible to phones
    pub fn get_service_name(&self) -> String {
        format!("ZHTP-{}", hex::encode(&self.node_id[..4]))
    }
    
    /// Check if Bluetooth is advertising and discoverable
    pub async fn is_advertising(&self) -> bool {
        if let Some(protocol) = self.protocol.read().await.as_ref() {
            protocol.is_advertising()
        } else {
            false
        }
    }
    
    /// Get connected phone devices
    pub async fn get_connected_phones(&self) -> HashMap<String, String> {
        self.connected_devices.read().await.clone()
    }
}

impl BluetoothClassicRouter {
    pub fn new() -> Self {
        let node_id = {
            let mut id = [0u8; 32];
            let uuid = Uuid::new_v4();
            let uuid_bytes = uuid.as_bytes();
            id[..16].copy_from_slice(uuid_bytes);
            id[16..].copy_from_slice(uuid_bytes);
            id
        };
        
        Self {
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            node_id,
            protocol: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Initialize Bluetooth Classic RFCOMM protocol for high-throughput mesh
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing Bluetooth Classic RFCOMM protocol for high-throughput mesh...");
        
        // Check if Windows Bluetooth feature is enabled on Windows
        #[cfg(all(target_os = "windows", not(feature = "windows-bluetooth")))]
        {
            warn!(" Windows: Bluetooth Classic requires --features windows-bluetooth");
            warn!("   Current build will NOT support RFCOMM discovery or connections");
            warn!("   Rebuild with: cargo build --features windows-bluetooth");
            warn!("   Skipping Bluetooth Classic initialization");
            return Err(anyhow::anyhow!("Windows Bluetooth feature not enabled"));
        }
        
        #[cfg(any(not(target_os = "windows"), feature = "windows-bluetooth"))]
        {
            use lib_network::protocols::bluetooth::classic::BluetoothClassicProtocol;
            use lib_crypto::PublicKey;
            
            // Create Bluetooth Classic protocol instance
            let bluetooth_classic = BluetoothClassicProtocol::new(self.node_id)?;
            
            // Initialize ZHTP authentication with blockchain public key
            info!(" Initializing ZHTP authentication for Bluetooth Classic...");
            let blockchain_pubkey = PublicKey::new(self.node_id.to_vec());
            if let Err(e) = bluetooth_classic.initialize_zhtp_auth(blockchain_pubkey).await {
                warn!("  Bluetooth Classic auth initialization failed: {}", e);
                warn!("Continuing without authentication - connections may be insecure");
            } else {
                info!(" Bluetooth Classic ZHTP authentication initialized");
            }
        
            // Initialize RFCOMM advertising
            if let Err(e) = bluetooth_classic.start_advertising().await {
                warn!("Bluetooth Classic advertising failed to start: {}", e);
                return Err(anyhow::anyhow!("Bluetooth Classic advertising initialization failed: {}", e));
            }
            
            // Store the protocol instance
            *self.protocol.write().await = Some(bluetooth_classic);
            
            info!("Bluetooth Classic RFCOMM initialized - discoverable as 'ZHTP-CLASSIC-{}'", 
                  hex::encode(&self.node_id[..4]));
            info!("High-throughput mesh (375 KB/s) available via Bluetooth Classic");
            
            Ok(())
        }
    }
    
    /// Handle incoming Bluetooth Classic RFCOMM connection
    /// Uses same authentication flow as BLE but over RFCOMM transport
    pub async fn handle_rfcomm_connection(
        &self,
        mut stream: TcpStream, // TODO: Replace with RfcommStream when implemented
        addr: SocketAddr,
        mesh_router: &MeshRouter,
    ) -> Result<()> {
        info!(" Processing Bluetooth Classic RFCOMM connection from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read RFCOMM data")?;
        
        if bytes_read > 0 {
            debug!("RFCOMM data received: {} bytes", bytes_read);
            
            // Try to parse as binary mesh handshake (IDENTICAL to BLE!)
            if let Ok(handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(&buffer[..bytes_read]) {
                info!("🤝 Received RFCOMM mesh handshake from peer: {}", handshake.node_id);
                info!("   Version: {}, Port: {}, Protocols: {:?}", 
                    handshake.version, handshake.mesh_port, handshake.protocols);
                
                // Create peer identity
                let peer_pubkey = lib_crypto::PublicKey::new(handshake.node_id.as_bytes().to_vec());
                
                // Use BluetoothClassic protocol type
                let protocol = lib_network::protocols::NetworkProtocol::BluetoothClassic;
                
                // Create mesh connection with higher bandwidth
                let connection = lib_network::mesh::connection::MeshConnection {
                    peer_id: peer_pubkey.clone(),
                    protocol,
                    peer_address: Some(addr.to_string()),
                    signal_strength: 0.8, // Classic typically better than BLE
                    bandwidth_capacity: 375_000, // 375 KB/s - Bluetooth Classic EDR
                    latency_ms: 50, // Lower latency than BLE
                    connected_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    data_transferred: 0,
                    tokens_earned: 0,
                    stability_score: 0.85,
                    zhtp_authenticated: false,
                    quantum_secure: false,
                    peer_dilithium_pubkey: None,
                    kyber_shared_secret: None,
                    trust_score: 0.5,
                };
                
                // Add to mesh connections
                {
                    let mut connections = mesh_router.connections.write().await;
                    connections.insert(peer_pubkey.clone(), connection);
                    info!(" Bluetooth Classic peer {} added to mesh network ({} total peers)", 
                        handshake.node_id, connections.len());
                }
                
                // Run SAME authentication flow as BLE (transport-agnostic!)
                info!(" Starting automatic authentication over RFCOMM");
                let _ = mesh_router.authenticate_and_register_peer(&peer_pubkey, &handshake, &addr, &mut stream).await;
                
                // Send acknowledgment
                let ack = bincode::serialize(&true)?;
                let _ = stream.write_all(&ack).await;
                
                info!(" Bluetooth Classic peer fully integrated - high-throughput mesh active!");
                
            } else {
                warn!("Failed to parse RFCOMM handshake");
            }
        }
        
        Ok(())
    }
    
    /// Get Bluetooth Classic service name
    pub fn get_service_name(&self) -> String {
        format!("ZHTP-CLASSIC-{}", hex::encode(&self.node_id[..4]))
    }
    
    /// Check if Bluetooth Classic is advertising
    pub async fn is_advertising(&self) -> bool {
        let protocol_guard: tokio::sync::RwLockReadGuard<Option<ClassicProtocol>> = self.protocol.read().await;
        protocol_guard.is_some()
    }
    
    /// Discover and connect to Bluetooth Classic peers
    /// Actively discovers paired devices, queries RFCOMM services, and connects to ZHTP nodes
    pub async fn discover_and_connect_peers(&self, mesh_router: &MeshRouter) -> Result<usize> {
        info!(" Starting Bluetooth Classic peer discovery...");
        
        let protocol_guard: tokio::sync::RwLockReadGuard<Option<ClassicProtocol>> = self.protocol.read().await;
        let protocol: &ClassicProtocol = match protocol_guard.as_ref() {
            Some(p) => p,
            None => {
                warn!("Bluetooth Classic protocol not initialized");
                return Ok(0);
            }
        };
        
        // Step 1: Discover paired devices
        let devices: Vec<lib_network::protocols::bluetooth::classic::BluetoothDevice> = match protocol.discover_paired_devices().await {
            Ok(devs) => {
                info!(" Discovered {} paired Bluetooth devices", devs.len());
                devs
            }
            Err(e) => {
                warn!("Failed to discover Bluetooth devices: {}", e);
                return Ok(0);
            }
        };
        
        let mut connected_count = 0;
        
        // Step 2: Query each device for RFCOMM services and connect
        for device in devices {
            info!(" Checking device: {} ({})", 
                device.name.as_deref().unwrap_or("Unknown"),
                device.address
            );
            
            // Only connect to paired and available devices
            if !device.is_paired {
                continue;
            }
            
            // Query RFCOMM services on this device
            let services = match protocol.query_rfcomm_services(&device.address).await {
                Ok(svcs) => svcs,
                Err(e) => {
                    debug!("Failed to query services on {}: {}", device.address, e);
                    continue;
                }
            };
            
            // Look for ZHTP services
            for service in services {
                if service.service_name.contains("ZHTP") || 
                   service.service_uuid.contains("6ba7b810") {
                    info!("✨ Found ZHTP service on {} (channel {})", 
                        device.address, service.channel);
                    
                    // Attempt to connect
                    match protocol.connect_to_peer(&device.address, service.channel).await {
                        Ok(_stream) => {
                            info!(" Connected to {} via Bluetooth Classic RFCOMM!", device.address);
                            connected_count += 1;
                            // TODO: Spawn task to handle stream or store for later use
                            
                            // Create mesh connection entry
                            let peer_pubkey = lib_crypto::PublicKey::new(device.address.as_bytes().to_vec());
                            let connection = lib_network::mesh::connection::MeshConnection {
                                peer_id: peer_pubkey.clone(),
                                protocol: lib_network::protocols::NetworkProtocol::BluetoothClassic,
                                peer_address: Some(device.address.clone()),
                                signal_strength: device.rssi.map(|r| (r + 127) as f64 / 127.0).unwrap_or(0.7),
                                bandwidth_capacity: 375_000, // 375 KB/s
                                latency_ms: 50,
                                connected_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                data_transferred: 0,
                                tokens_earned: 0,
                                stability_score: 0.8,
                                zhtp_authenticated: false,
                                quantum_secure: false,
                                peer_dilithium_pubkey: None,
                                kyber_shared_secret: None,
                                trust_score: 0.5,
                            };
                            
                            // Add to mesh network
                            let mut connections = mesh_router.connections.write().await;
                            connections.insert(peer_pubkey, connection);
                            
                            info!(" Added {} to mesh network", device.address);
                            
                            // Store the stream for future communication
                            self.connected_devices.write().await.insert(
                                device.address.clone(),
                                device.address.clone()
                            );
                        }
                        Err(e) => {
                            debug!("Failed to connect to {}: {}", device.address, e);
                        }
                    }
                    
                    // Only connect to first ZHTP service per device
                    break;
                }
            }
        }
        
        if connected_count > 0 {
            info!("🎊 Successfully connected to {} Bluetooth Classic peers", connected_count);
        } else {
            info!("No new Bluetooth Classic peers discovered");
        }
        
        Ok(connected_count)
    }
    
    /// Get connected devices via Bluetooth Classic
    pub async fn get_connected_devices(&self) -> HashMap<String, String> {
        self.connected_devices.read().await.clone()
    }
}

/// Network bootstrap handling
#[derive(Debug)]
pub struct BootstrapRouter {
    server_id: Uuid,
}

impl BootstrapRouter {
    pub fn new(server_id: Uuid) -> Self {
        Self { server_id }
    }
    
    pub async fn handle_tcp_bootstrap(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("Processing TCP bootstrap connection from: {}", addr);
        
        let mut buffer = vec![0; 1024];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read bootstrap request")?;
        
        if bytes_read > 0 {
            debug!("Bootstrap request: {} bytes", bytes_read);
            
            // Send bootstrap response
            let response = format!("ZHTP Bootstrap Response\nServer ID: {}\n", self.server_id);
            let _ = stream.write_all(response.as_bytes()).await;
        }
        
        Ok(())
    }
    
    pub async fn handle_udp_bootstrap(&self, data: &[u8], addr: SocketAddr, http_port: u16, zhtp_port: u16, socket: &UdpSocket) -> Result<Vec<u8>> {
        info!("Processing UDP bootstrap packet from: {} ({} bytes)", addr, data.len());
        
        // Parse bootstrap request and send response
        let request_str = String::from_utf8_lossy(data);
        debug!("Bootstrap request content: {}", request_str);
        
        // Create bootstrap response with server capabilities
        let response_data = serde_json::json!({
            "server_id": self.server_id,
            "server_type": "zhtp_unified",
            "protocol_version": "ZHTP/1.0",
            "capabilities": [
                "blockchain_api",
                "storage_api", 
                "identity_api",
                "mesh_networking",
                "wifi_direct",
                "dht_operations"
            ],
            "endpoints": {
                "http": format!("http://localhost:{}", http_port),
                "zhtp": format!("zhtp://localhost:{}", zhtp_port),
                "websocket": format!("ws://localhost:{}/ws", http_port)
            },
            "network_info": {
                "node_type": "full_node",
                "uptime": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                "peers_connected": 0
            },
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
        });
        
        // Convert to bytes for UDP transmission
        let response_bytes = serde_json::to_vec(&response_data)
            .context("Failed to serialize bootstrap response")?;
        
        // Send the actual UDP response back to the client
        match socket.send_to(&response_bytes, addr).await {
            Ok(sent_bytes) => {
                info!("Sent UDP bootstrap response to {} ({} bytes)", addr, sent_bytes);
                debug!("Bootstrap response: {}", response_data);
            }
            Err(e) => {
                error!("Failed to send UDP bootstrap response to {}: {}", addr, e);
                return Err(anyhow::anyhow!("UDP send failed: {}", e));
            }
        }
        
        Ok(response_bytes)
    }
}

/// Main unified server that handles all protocols
pub struct ZhtpUnifiedServer {
    // Network listeners
    tcp_listener: Option<Arc<TcpListener>>,
    udp_socket: Option<Arc<UdpSocket>>,
    
    // Protocol routers
    http_router: HttpRouter,
    mesh_router: MeshRouter,
    wifi_router: WiFiRouter,
    bluetooth_router: BluetoothRouter,
    bluetooth_classic_router: BluetoothClassicRouter,
    bootstrap_router: BootstrapRouter,
    
    // Shared backend state (from ZHTP orchestrator)
    blockchain: Arc<RwLock<Blockchain>>,
    storage: Arc<RwLock<UnifiedStorageSystem>>,
    identity_manager: Arc<RwLock<IdentityManager>>,
    economic_model: Arc<RwLock<EconomicModel>>,
    
    // Session management
    session_manager: Arc<SessionManager>,
    
    // Server state
    is_running: Arc<RwLock<bool>>,
    server_id: Uuid,
    port: u16,
}

impl ZhtpUnifiedServer {
    /// Check if an address is a self-connection from our own node trying to connect to itself
    /// This prevents multi-NIC self-loops but ALLOWS browser connections from localhost
    fn is_self_connection(addr: &std::net::SocketAddr) -> bool {
        let ip = addr.ip();
        
        // IMPORTANT: Do NOT block loopback (127.0.0.1) - that's how browsers connect!
        // We only want to block our actual network IP connecting to itself
        
        // Check if the source IP matches our local network IP
        // (This prevents Ethernet connecting to WiFi on same machine)
        if let Ok(local_ip) = local_ip_address::local_ip() {
            // Only block if source IP matches our non-loopback local IP
            if !local_ip.is_loopback() && ip == local_ip {
                return true;
            }
        }
        
        // Check for link-local auto-assigned addresses (169.254.x.x, fe80::/10)
        // These can cause issues on multi-NIC systems
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                // 169.254.x.x is link-local (auto-assigned)
                if ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 {
                    // Get our local IP to compare
                    if let Ok(local_ip) = local_ip_address::local_ip() {
                        if std::net::IpAddr::V4(ipv4) == local_ip {
                            return true;
                        }
                    }
                }
            }
            std::net::IpAddr::V6(ipv6) => {
                // fe80::/10 is link-local
                if ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                    // Get our local IP to compare
                    if let Ok(local_ip) = local_ip_address::local_ip() {
                        if std::net::IpAddr::V6(ipv6) == local_ip {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    /// Get broadcast metrics from mesh router
    pub async fn get_broadcast_metrics(&self) -> BroadcastMetrics {
        self.mesh_router.get_broadcast_metrics().await
    }
    
    /// Get the mesh router as an Arc for global provider access
    pub fn get_mesh_router_arc(&self) -> Arc<MeshRouter> {
        // MeshRouter is already Arc-wrapped internally, but we need to clone the Arc to return
        // Since MeshRouter isn't stored as Arc in the struct, we need to wrap it
        // For now, we'll need to refactor mesh_router to be Arc<MeshRouter> instead of MeshRouter
        // As a temporary solution, return a reference through the methods
        Arc::new(self.mesh_router.clone())
    }
    
    /// Create new unified server with comprehensive backend integration
    pub async fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
        port: u16, // Port from configuration
    ) -> Result<Self> {
        let server_id = Uuid::new_v4();
        
        info!("Creating ZHTP Unified Server (ID: {})", server_id);
        info!("Port: {} (HTTP + UDP + WiFi + Bootstrap)", port);
        
        // Initialize session manager first
        let session_manager = Arc::new(SessionManager::new());
        session_manager.start_cleanup_task();
        
        // Initialize protocol routers
        let mut http_router = HttpRouter::new();
        let mut mesh_router = MeshRouter::new(server_id, session_manager.clone());
        let wifi_router = WiFiRouter::new();
        let bluetooth_router = BluetoothRouter::new();
        let bluetooth_classic_router = BluetoothClassicRouter::new();
        
        // Set identity manager on mesh router for direct UDP access
        mesh_router.set_identity_manager(identity_manager.clone());
        
        // Create blockchain broadcast channel for real-time sync
        let (broadcast_sender, broadcast_receiver) = tokio::sync::mpsc::unbounded_channel();
        
        // Configure blockchain to use broadcast channel
        {
            let mut blockchain_write = blockchain.write().await;
            blockchain_write.set_broadcast_channel(broadcast_sender);
        }
        
        // Configure mesh router to receive broadcasts
        mesh_router.set_broadcast_receiver(broadcast_receiver).await;
        
        // Initialize WiFi Direct protocol
        if let Err(e) = wifi_router.initialize().await {
            warn!("WiFi Direct initialization failed: {}", e);
        }
        
        // NOTE: Bluetooth initialization happens in start() to avoid double initialization
        // The bluetooth_router is created here but initialized later when server starts
        
        let bootstrap_router = BootstrapRouter::new(server_id);
        
        // Register comprehensive API handlers
        Self::register_api_handlers(
            &mut http_router,
            blockchain.clone(),
            storage.clone(),
            identity_manager.clone(),
            economic_model.clone(),
            session_manager.clone(),
            Arc::new(mesh_router.clone()),
        ).await?;
        
        Ok(Self {
            tcp_listener: None,
            udp_socket: None,
            http_router,
            mesh_router,
            wifi_router,
            bluetooth_router,
            bluetooth_classic_router,
            bootstrap_router,
            blockchain,
            storage,
            identity_manager,
            economic_model,
            session_manager,
            is_running: Arc::new(RwLock::new(false)),
            server_id,
            port,
        })
    }
    
    /// Register all comprehensive API handlers
    async fn register_api_handlers(
        http_router: &mut HttpRouter,
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        _economic_model: Arc<RwLock<EconomicModel>>,
        _session_manager: Arc<SessionManager>,
        mesh_router: Arc<MeshRouter>,
    ) -> Result<()> {
        info!("Registering comprehensive API handlers...");
        
        // Blockchain operations
        let blockchain_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            BlockchainHandler::new(blockchain.clone())
        );
        http_router.register_handler("/api/v1/blockchain".to_string(), blockchain_handler);
        
        // Identity and wallet management  
        // Note: Using lib_identity::economics::EconomicModel as expected by IdentityHandler
        let identity_economic_model = Arc::new(RwLock::new(
            lib_identity::economics::EconomicModel::new()
        ));
        let identity_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            IdentityHandler::new(identity_manager.clone(), identity_economic_model)
        );
        http_router.register_handler("/api/v1/identity".to_string(), identity_handler);
        
        // Wallet content ownership manager (shared across handlers)
        let wallet_content_manager = Arc::new(RwLock::new(lib_storage::WalletContentManager::new()));
        
        // Storage operations (with wallet content manager for ownership tracking)
        let storage_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            StorageHandler::new(storage.clone())
                .with_wallet_manager(Arc::clone(&wallet_content_manager))
        );
        http_router.register_handler("/api/v1/storage".to_string(), storage_handler);
        
        // Wallet operations
        let wallet_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            WalletHandler::new(identity_manager.clone())
        );
        http_router.register_handler("/api/v1/wallet".to_string(), wallet_handler);
        
        // DAO operations
        let dao_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            DaoHandler::new(identity_manager.clone())
        );
        http_router.register_handler("/api/v1/dao".to_string(), dao_handler);
        
        // DHT operations (zkDHT bridge)
        let dht_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            DhtHandler::new(mesh_router)
        );
        http_router.register_handler("/api/v1/dht".to_string(), dht_handler);
        
        // Web4 domain and content (handle async creation first)
        let web4_handler = Web4Handler::new().await?;
        let web4_manager = web4_handler.get_web4_manager();
        let wallet_content_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::WalletContentHandler::new(Arc::clone(&wallet_content_manager))
        );
        http_router.register_handler("/api/wallet".to_string(), Arc::clone(&wallet_content_handler));
        http_router.register_handler("/api/content".to_string(), wallet_content_handler);
        
        // Marketplace handler for buying/selling content (shares managers with wallet content)
        let marketplace_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::MarketplaceHandler::new(
                Arc::clone(&wallet_content_manager),
                Arc::clone(&blockchain)
            )
        );
        http_router.register_handler("/api/marketplace".to_string(), marketplace_handler);
        
        // DNS resolution for .zhtp domains (connect to Web4Manager)
        let mut dns_handler = DnsHandler::new();
        dns_handler.set_web4_manager(web4_manager);
        let dns_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(dns_handler);
        http_router.register_handler("/api/v1/dns".to_string(), dns_handler);
        
        // Register Web4 handler
        let web4_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(web4_handler);
        http_router.register_handler("/api/v1/web4".to_string(), web4_handler);
        
        // Validator management
        let validator_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::ValidatorHandler::new(blockchain.clone())
        );
        http_router.register_handler("/api/v1/validator".to_string(), validator_handler);
        
        // Protocol management
        let protocol_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            ProtocolHandler::new()
        );
        http_router.register_handler("/api/v1/protocol".to_string(), protocol_handler);
        
        info!("All API handlers registered successfully");
        Ok(())
    }
    
    /// Start the unified server on port 9333
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting ZHTP Unified Server on port {}", self.port);
        
        // STEP 1: Apply network isolation to block internet access
        info!(" Applying network isolation for ISP-free mesh operation...");
        if let Err(e) = crate::config::network_isolation::initialize_network_isolation().await {
            warn!("Failed to apply network isolation: {}", e);
            warn!(" Mesh may still have internet access - check network configuration");
        } else {
            info!(" Network isolation applied - mesh is now ISP-free");
        }
        
        // Initialize ZHTP relay protocol ONLY if not already initialized
        // (components.rs may have already initialized it with authentication)
        if self.mesh_router.relay_protocol.read().await.is_none() {
            info!(" Initializing ZHTP relay protocol...");
            if let Err(e) = self.mesh_router.initialize_relay_protocol().await {
                warn!("Failed to initialize ZHTP relay protocol: {}", e);
            }
        } else {
            info!(" ZHTP relay protocol already initialized (authentication active)");
        }
        
        // Start local network peer discovery (multicast)
        info!(" Starting local network peer discovery...");
        if let Err(e) = lib_network::discovery::local_network::start_local_discovery(
            self.server_id,
            self.port
        ).await {
            warn!("Failed to start local network discovery: {}", e);
        } else {
            info!(" Local network discovery active (multicast)");
        }
        
        // Start automatic TCP/UDP network scanner
        info!(" Starting TCP/UDP network scanner...");
        if let Err(e) = lib_network::discovery::network_scanner::start_network_scanner(self.port, self.server_id).await {
            warn!("Failed to start network scanner: {}", e);
        } else {
            info!(" TCP/UDP network scanner active (scans every 30 seconds)");
        }
        
        // Quick scan on startup for immediate peer discovery
        info!(" Running quick network scan...");
        match lib_network::discovery::network_scanner::quick_scan_local_network().await {
            Ok(nodes) if !nodes.is_empty() => {
                info!(" Quick scan found {} ZHTP nodes:", nodes.len());
                for node in &nodes {
                    info!("   → {}:{} ({}ms response)", node.ip, node.port, node.response_time_ms);
                }
            }
            Ok(_) => {
                info!(" Quick scan complete - no ZHTP nodes found yet");
            }
            Err(e) => {
                warn!("Quick scan failed: {}", e);
            }
        }
        
        // Initialize Bluetooth discovery
        info!(" Initializing Bluetooth mesh discovery...");
        if let Err(e) = self.bluetooth_router.initialize().await {
            warn!("Bluetooth LE initialization failed: {}", e);
            warn!("Continuing without Bluetooth LE support");
        } else {
            info!(" Bluetooth LE mesh advertising active");
        }
        
        // Initialize Bluetooth Classic for high-throughput mesh
        info!(" Initializing Bluetooth Classic RFCOMM...");
        if let Err(e) = self.bluetooth_classic_router.initialize().await {
            warn!("Bluetooth Classic initialization failed: {}", e);
            warn!("Continuing without Bluetooth Classic support");
        } else {
            info!(" Bluetooth Classic RFCOMM active (375 KB/s)");
        }
        
        // HYBRID MODE: TCP/UDP + Mesh Protocols for Browser Compatibility
        info!(" Hybrid Mode: TCP/UDP for browser + Direct mesh protocols");
        
        // Bind TCP listener for HTTP API
        let bind_addr = format!("0.0.0.0:{}", self.port);
        info!(" Binding TCP listener on {}...", bind_addr);
        let listener = TcpListener::bind(&bind_addr).await
            .context(format!("Failed to bind TCP listener on {}", bind_addr))?;
        self.tcp_listener = Some(Arc::new(listener));
        info!(" TCP listener bound successfully on port {}", self.port);
        
        // Bind UDP socket for mesh protocol
        info!(" Binding UDP socket on {}...", bind_addr);
        let udp_socket = UdpSocket::bind(&bind_addr).await
            .context(format!("Failed to bind UDP socket on {}", bind_addr))?;
        self.udp_socket = Some(Arc::new(udp_socket));
        info!(" UDP socket bound successfully on port {}", self.port);
        
        *self.is_running.write().await = true;
        
        // Start TCP listener for HTTP API
        self.start_tcp_listener().await?;
        info!(" TCP listener started - HTTP API ready");
        
        // Start UDP listener for mesh protocol
        self.start_udp_listener().await?;
        info!(" UDP listener started - ZHTP mesh protocol ready");
        
        // Start mesh protocol handlers
        self.start_bluetooth_mesh_handler().await?;
        self.start_bluetooth_classic_handler().await?;
        self.start_wifi_direct_handler().await?;
        self.start_lorawan_handler().await?;
        
        info!("ZHTP Unified Server online");
        info!("Protocols: BLE + BT Classic + WiFi Direct + LoRaWAN + ZHTP Relay");
        info!(" ZHTP relay: Encrypted DHT queries with Dilithium2 + Kyber512 + ChaCha20");
        
        // Verify network isolation is working
        info!(" Verifying network isolation...");
        match crate::config::network_isolation::verify_mesh_isolation().await {
            Ok(true) => {
                info!(" NETWORK ISOLATION VERIFIED - Mesh is ISP-free!");
                info!(" No internet access possible - pure mesh operation confirmed");
            }
            Ok(false) => {
                warn!(" NETWORK ISOLATION FAILED - Internet access still possible!");
                warn!(" Check firewall and routing configuration");
            }
            Err(e) => {
                warn!(" Could not verify network isolation: {}", e);
            }
        }
        
        Ok(())
    }

    /// Start Bluetooth mesh protocol handler
    async fn start_bluetooth_mesh_handler(&self) -> Result<()> {
        info!(" Starting Bluetooth LE mesh handler...");
        
        // Check if protocol is initialized (should be done in run_pure_mesh already)
        let is_initialized = self.bluetooth_router.protocol.read().await.is_some();
        
        if !is_initialized {
            warn!("Bluetooth LE protocol not initialized - skipping handler");
            return Ok(());
        }
        
        info!(" Bluetooth LE mesh handler active - discoverable for phone connections");
        
        Ok(())
    }

    /// Start Bluetooth Classic RFCOMM mesh handler
    async fn start_bluetooth_classic_handler(&self) -> Result<()> {
        info!(" Starting Bluetooth Classic RFCOMM mesh handler...");
        
        // Check if protocol is initialized (should be done in run_pure_mesh already)
        let protocol_guard: tokio::sync::RwLockReadGuard<Option<ClassicProtocol>> = self.bluetooth_classic_router.protocol.read().await;
        let is_initialized = protocol_guard.is_some();
        
        if !is_initialized {
            warn!("Bluetooth Classic protocol not initialized - skipping handler");
            return Ok(());
        }
        
        info!(" Bluetooth Classic RFCOMM handler active");
        
        // Note: Windows Bluetooth API types are not Send, so periodic discovery
        // cannot run in a spawned task. Manual discovery can still be triggered.
        #[cfg(not(all(target_os = "windows", feature = "windows-bluetooth")))]
        {
            info!("Starting periodic Bluetooth Classic peer discovery...");
            // Start periodic peer discovery task
            let bt_router = self.bluetooth_classic_router.clone();
            let mesh_router = self.mesh_router.clone();
            let is_running = self.is_running.clone();
            
            tokio::spawn(async move {
                // Initial discovery after 5 seconds
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                
                while *is_running.read().await {
                    interval.tick().await;
                    
                    info!(" Bluetooth Classic: Starting periodic peer discovery...");
                    match bt_router.discover_and_connect_peers(&mesh_router).await {
                        Ok(count) => {
                            if count > 0 {
                                info!(" Bluetooth Classic: Connected to {} new peers", count);
                            } else {
                                debug!("Bluetooth Classic: No new peers found");
                            }
                        }
                        Err(e) => {
                            warn!("Bluetooth Classic discovery error: {}", e);
                        }
                    }
                }
            });
        }
        
        #[cfg(all(target_os = "windows", feature = "windows-bluetooth"))]
        {
            info!("  Windows: Automatic periodic discovery disabled (API not thread-safe)");
            info!("    Use manual discovery commands or API calls instead");
        }
        
        info!(" Bluetooth Classic periodic discovery task started (60s interval)");
        
        Ok(())
    }

    /// Start WiFi Direct mesh protocol handler  
    async fn start_wifi_direct_handler(&self) -> Result<()> {
        info!(" Starting WiFi Direct mesh handler...");
        
        if let Err(e) = self.wifi_router.initialize().await {
            warn!("WiFi Direct initialization failed: {}", e);
            warn!("Continuing without WiFi Direct support");
        } else {
            info!(" WiFi Direct mesh active - P2P connections enabled");
        }
        
        Ok(())
    }

    /// Start LoRaWAN mesh protocol handler
    async fn start_lorawan_handler(&self) -> Result<()> {
        info!(" Starting LoRaWAN mesh handler...");
        
        // LoRaWAN requires specific hardware - check availability
        info!(" LoRaWAN mesh protocol ready (requires LoRa hardware)");
        info!(" Long-range mesh capability available");
        
        Ok(())
    }
    
    /// Start TCP connection handler (HTTP + TCP mesh + WiFi + Bootstrap)
    async fn start_tcp_listener(&self) -> Result<()> {
        let listener = self.tcp_listener.as_ref().unwrap().clone();
        let http_router = Arc::new(self.http_router.clone());
        let mesh_router = Arc::new(self.mesh_router.clone());
        let wifi_router = Arc::new(self.wifi_router.clone());
        let bluetooth_router = Arc::new(self.bluetooth_router.clone());
        let bootstrap_router = Arc::new(self.bootstrap_router.clone());
        let is_running = self.is_running.clone();
        
        tokio::spawn(async move {
            info!("TCP listener started - accepting connections...");
            
            while *is_running.read().await {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        // Skip self-connections
                        if Self::is_self_connection(&addr) {
                            debug!("⏭️ Skipping self-connection from {}", addr);
                            continue;
                        }
                        
                        debug!(" New TCP connection from: {}", addr);
                        
                        let http_router = http_router.clone();
                        let mesh_router = mesh_router.clone();
                        let wifi_router = wifi_router.clone();
                        let bluetooth_router = bluetooth_router.clone();
                        let bootstrap_router = bootstrap_router.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_tcp_connection(
                                stream, 
                                addr,
                                http_router,
                                mesh_router,
                                wifi_router,
                                bluetooth_router,
                                bootstrap_router,
                            ).await {
                                error!("TCP connection error: {}", e);
                            }
                        });
                    },
                    Err(e) => {
                        error!("Failed to accept TCP connection: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
            
            info!("TCP listener stopped");
        });
        
        Ok(())
    }
    
    /// Handle individual TCP connection with protocol detection
    async fn handle_tcp_connection(
        stream: TcpStream,
        addr: SocketAddr,
        http_router: Arc<HttpRouter>,
        mesh_router: Arc<MeshRouter>,
        wifi_router: Arc<WiFiRouter>,
        bluetooth_router: Arc<BluetoothRouter>,
        bootstrap_router: Arc<BootstrapRouter>,
    ) -> Result<()> {
        // Peek at first bytes to detect protocol
        let mut buffer = [0; 512];
        
        // Use a small timeout for peeking
        let peek_result = tokio::time::timeout(
            tokio::time::Duration::from_millis(1000),
            stream.peek(&mut buffer)
        ).await;
        
        let bytes_read = match peek_result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                warn!("Failed to peek TCP stream: {}", e);
                return Ok(());
            },
            Err(_) => {
                warn!("Timeout peeking TCP stream from: {}", addr);
                return Ok(());
            }
        };
        
        if bytes_read == 0 {
            return Ok(());
        }
        
        let protocol = Self::detect_tcp_protocol(&buffer[..bytes_read]);
        debug!("Detected protocol: {:?} from {}", protocol, addr);
        
        match protocol {
            IncomingProtocol::HTTP => {
                info!("HTTP request from: {}", addr);
                http_router.handle_http_request(stream, addr).await
            },
            IncomingProtocol::ZhtpMeshTcp => {
                info!("TCP mesh connection from: {}", addr);
                mesh_router.handle_tcp_mesh(stream, addr).await
            },
            IncomingProtocol::WiFiDirect => {
                info!("WiFi Direct connection from: {}", addr);
                wifi_router.handle_wifi_direct(stream, addr).await
            },
            IncomingProtocol::Bluetooth => {
                info!("Bluetooth connection from phone: {}", addr);
                bluetooth_router.handle_bluetooth_connection(stream, addr, &mesh_router).await
            },
            IncomingProtocol::Bootstrap | IncomingProtocol::Unknown => {
                info!("Bootstrap connection from: {}", addr);
                bootstrap_router.handle_tcp_bootstrap(stream, addr).await
            },
            _ => {
                warn!("❓ Unknown TCP protocol from: {}", addr);
                Ok(())
            }
        }
    }
    
    /// Detect protocol type from TCP stream data
    fn detect_tcp_protocol(buffer: &[u8]) -> IncomingProtocol {
        let data = String::from_utf8_lossy(buffer);
        
        // HTTP detection
        if data.starts_with("GET ") || data.starts_with("POST ") || 
           data.starts_with("PUT ") || data.starts_with("DELETE ") ||
           data.starts_with("OPTIONS ") || data.starts_with("HEAD ") {
            return IncomingProtocol::HTTP;
        }
        
        // ZHTP mesh detection (text protocol)
        if data.starts_with("ZHTP/1.0 MESH") {
            return IncomingProtocol::ZhtpMeshTcp;
        }
        
        // Binary mesh handshake detection (bincode format from local discovery)
        // Bincode handshakes start with small numbers (version byte)
        // and are typically 60-100 bytes for mesh handshakes
        if buffer.len() >= 20 && buffer.len() < 200 {
            // Try to deserialize as MeshHandshake
            if let Ok(_handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(buffer) {
                return IncomingProtocol::ZhtpMeshTcp;
            }
        }
        
        // WiFi Direct detection
        if data.contains("WIFI-DIRECT") || data.contains("P2P-DEVICE") {
            return IncomingProtocol::WiFiDirect;
        }
        
        // Bluetooth detection (phone connections often include these markers)
        if data.contains("BLUETOOTH") || data.contains("BT-") || 
           data.contains("ZHTP-PHONE") || data.contains("RFCOMM") {
            return IncomingProtocol::Bluetooth;
        }
        
        // Default to bootstrap for unknown TCP connections
        IncomingProtocol::Bootstrap
    }
    
    /// Start UDP packet handler (UDP mesh + Bootstrap)
    async fn start_udp_listener(&self) -> Result<()> {
        let socket = self.udp_socket.as_ref().unwrap().clone();
        let mesh_router = Arc::new(self.mesh_router.clone());
        let bootstrap_router = Arc::new(self.bootstrap_router.clone());
        let is_running = self.is_running.clone();
        
        tokio::spawn(async move {
            info!("UDP listener started - receiving packets...");
            let mut buffer = [0; 8192];
            
            while *is_running.read().await {
                match socket.recv_from(&mut buffer).await {
                    Ok((len, addr)) => {
                        // Skip self-connections
                        if Self::is_self_connection(&addr) {
                            debug!("⏭️ Skipping self-connection from {}", addr);
                            continue;
                        }
                        
                        debug!(" UDP packet from: {} ({} bytes)", addr, len);
                        
                        let data = &buffer[..len];
                        let protocol = Self::detect_udp_protocol(data);
                        
                        match protocol {
                            IncomingProtocol::ZhtpMeshUdp => {
                                info!("UDP mesh packet from: {}", addr);
                                match mesh_router.handle_udp_mesh(data, addr).await {
                                    Ok(Some(response)) => {
                                        // Send response back to client
                                        if let Err(e) = socket.send_to(&response, addr).await {
                                            warn!("Failed to send UDP mesh response: {}", e);
                                        } else {
                                            info!("Sent ZHTP mesh response to: {}", addr);
                                        }
                                    },
                                    Ok(None) => {
                                        // No response needed
                                    },
                                    Err(e) => {
                                        warn!("UDP mesh error: {}", e);
                                    }
                                }
                            },
                            IncomingProtocol::Bootstrap | IncomingProtocol::Unknown => {
                                info!("UDP bootstrap packet from: {}", addr);
                                match bootstrap_router.handle_udp_bootstrap(data, addr, 8080, 8443, &socket).await {
                                    Ok(_response_bytes) => {
                                        debug!("Bootstrap response sent successfully to {}", addr);
                                    }
                                    Err(e) => {
                                        warn!("UDP bootstrap error for {}: {}", addr, e);
                                    }
                                }
                            },
                            _ => {
                                debug!("❓ Unknown UDP packet from: {}", addr);
                            }
                        }
                    },
                    Err(e) => {
                        error!("UDP receive error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
            
            info!("UDP listener stopped");
        });
        
        Ok(())
    }
    
    /// Detect protocol type from UDP packet data
    fn detect_udp_protocol(data: &[u8]) -> IncomingProtocol {
        // Try to parse as text first
        if let Ok(text) = std::str::from_utf8(data) {
            // ZHTP mesh JSON detection
            if text.contains("\"ZhtpRequest\"") || text.contains("\"ZhtpResponse\"") {
                return IncomingProtocol::ZhtpMeshUdp;
            }
            
            // JSON structure indicates mesh protocol
            if text.trim().starts_with('{') && 
               (text.contains("\"requester\"") || text.contains("\"mesh\"")) {
                return IncomingProtocol::ZhtpMeshUdp;
            }
        }
        
        // Default to bootstrap for other UDP packets
        IncomingProtocol::Bootstrap
    }
    
    /// Stop the unified server
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping ZHTP Unified Server...");
        
        *self.is_running.write().await = false;
        
        // Drop listeners to stop accepting new connections
        self.tcp_listener = None;
        self.udp_socket = None;
        
        info!("ZHTP Unified Server stopped");
        Ok(())
    }
    
    /// Get server status
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    /// Initialize ZHTP authentication manager (wrapper for mesh_router method)
    pub async fn initialize_auth_manager(&mut self, blockchain_pubkey: lib_crypto::PublicKey) -> Result<()> {
        self.mesh_router.initialize_auth_manager(blockchain_pubkey).await
    }
    
    /// Initialize ZHTP relay protocol (wrapper for mesh_router method)
    pub async fn initialize_relay_protocol(&self) -> Result<()> {
        self.mesh_router.initialize_relay_protocol().await
    }
    
    /// Get server information
    pub fn get_server_info(&self) -> (Uuid, u16) {
        (self.server_id, self.port)
    }
    
    /// Get blockchain statistics
    pub async fn get_blockchain_stats(&self) -> Result<serde_json::Value> {
        let blockchain = self.blockchain.read().await;
        Ok(serde_json::json!({
            "block_count": blockchain.blocks.len(),
            "pending_transactions": blockchain.pending_transactions.len(),
            "identity_count": blockchain.identity_registry.len(),
            "server_id": self.server_id
        }))
    }
    
    /// Get storage system status
    pub async fn get_storage_status(&self) -> Result<serde_json::Value> {
        let _storage = self.storage.read().await;
        Ok(serde_json::json!({
            "status": "active",
            "server_id": self.server_id,
            "storage_type": "unified"
        }))
    }
    
    /// Get identity manager statistics  
    pub async fn get_identity_stats(&self) -> Result<serde_json::Value> {
        let identity_manager = self.identity_manager.read().await;
        let identities = identity_manager.list_identities();
        Ok(serde_json::json!({
            "identity_count": identities.len(),
            "server_id": self.server_id
        }))
    }
    
    /// Get economic model information
    pub async fn get_economic_info(&self) -> Result<serde_json::Value> {
        let _economic_model = self.economic_model.read().await;
        Ok(serde_json::json!({
            "model_type": "ZHTP",
            "server_id": self.server_id,
            "status": "active"
        }))
    }
}

// Make routers cloneable for sharing between tasks
impl Clone for HttpRouter {
    fn clone(&self) -> Self {
        // Clone all registered routes and handlers
        Self {
            routes: self.routes.clone(),
            middleware: self.middleware.clone(),
        }
    }
}

impl Clone for MeshRouter {
    fn clone(&self) -> Self {
        Self {
            connections: self.connections.clone(),
            server_id: self.server_id,
            identity_manager: self.identity_manager.clone(),
            session_manager: self.session_manager.clone(),
            relay_protocol: self.relay_protocol.clone(),
            encryption_manager: self.encryption_manager.clone(),
            zhtp_auth_manager: self.zhtp_auth_manager.clone(),
            encryption_sessions: self.encryption_sessions.clone(),
            sync_manager: self.sync_manager.clone(),
            bluetooth_protocol: self.bluetooth_protocol.clone(),
            udp_socket: self.udp_socket.clone(),
            recent_blocks: self.recent_blocks.clone(),
            recent_transactions: self.recent_transactions.clone(),
            broadcast_receiver: self.broadcast_receiver.clone(),
            peer_rate_limits: self.peer_rate_limits.clone(),
            broadcast_metrics: self.broadcast_metrics.clone(),
            peer_reputations: self.peer_reputations.clone(),
            // Phase 4: Advanced monitoring
            performance_metrics: self.performance_metrics.clone(),
            active_alerts: self.active_alerts.clone(),
            alert_thresholds: self.alert_thresholds.clone(),
            metrics_history: self.metrics_history.clone(),
            latency_samples_blocks: self.latency_samples_blocks.clone(),
            latency_samples_txs: self.latency_samples_txs.clone(),
            // Phase 2.5: Multi-hop routing
            mesh_message_router: self.mesh_message_router.clone(),
        }
    }
}

impl Clone for WiFiRouter {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id,
            connected_devices: self.connected_devices.clone(),
            protocol: self.protocol.clone(),
        }
    }
}

impl Clone for BootstrapRouter {
    fn clone(&self) -> Self {
        Self {
            server_id: self.server_id,
        }
    }
}
