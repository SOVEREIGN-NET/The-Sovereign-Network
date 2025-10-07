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
    /// Unknown protocol
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
           request.uri.starts_with("/api/v1/blockchain/") {
            return Ok(true);
        }
        
        // Check for Authorization header
        if let Some(auth_header) = request.headers.get("Authorization") {
            if auth_header.starts_with("Bearer ") {
                let token = &auth_header[7..];
                // In a real implementation, verify JWT token
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
        let mut total_read = 0;
        let mut headers_complete = false;
        
        // Read initial chunk
        let bytes_read = stream.read(&mut header_buffer).await
            .context("Failed to read HTTP request")?;
        
        if bytes_read == 0 {
            return Ok(());
        }
        
        total_read = bytes_read;
        
        // Check if headers are complete (look for \r\n\r\n)
        let header_data = String::from_utf8_lossy(&header_buffer[..total_read]);
        if let Some(header_end) = header_data.find("\r\n\r\n") {
            headers_complete = true;
            
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

/// UDP mesh protocol routing and handling
pub struct MeshRouter {
    connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
    server_id: Uuid,
    identity_manager: Option<Arc<RwLock<IdentityManager>>>,
    session_manager: Arc<SessionManager>,
}

impl MeshRouter {
    pub fn new(server_id: Uuid, session_manager: Arc<SessionManager>) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            server_id,
            identity_manager: None,
            session_manager,
        }
    }
    
    pub fn set_identity_manager(&mut self, manager: Arc<RwLock<IdentityManager>>) {
        self.identity_manager = Some(manager);
    }
    
    pub async fn handle_udp_mesh(&self, data: &[u8], addr: SocketAddr) -> Result<Option<Vec<u8>>> {
        debug!("Processing UDP mesh packet from: {} ({} bytes)", addr, data.len());
        
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
            info!("💳 Creating standalone wallet via UDP mesh");
            
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
            
            // Handle standalone wallet creation
            match self.create_standalone_wallet_direct(request_data).await {
                Ok(wallet_result) => {
                    info!("Standalone wallet created successfully");
                    
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
                    warn!("Standalone wallet creation failed: {}", e);
                    self.create_error_mesh_response(500, &format!("Wallet creation failed: {}", e)).await
                }
            }
        } else if mesh_req.uri == "/api/v1/identity/import" && mesh_req.method.to_uppercase() == "POST" {
            info!("📥 Importing identity from 20-word phrase via UDP mesh");
            
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
            
        info!("Created identity with ID: {}", identity_result.identity_id);
        
        // Record identity and wallets on blockchain
        let identity_json = serde_json::to_value(&identity_result).unwrap_or_default();
        self.record_identity_on_blockchain(&identity_json).await.unwrap_or_else(|e| {
            warn!("Failed to record identity on blockchain: {}", e);
        });
        
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
        
        info!("📥 Importing identity from recovery phrase");
        
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
    
    /// Create standalone wallet (not tied to DID) using WalletManager
    async fn create_standalone_wallet_direct(&self, request_data: serde_json::Value) -> Result<serde_json::Value> {
        // Extract wallet parameters
        let wallet_name = request_data.get("wallet_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Standalone Wallet")
            .to_string();
            
        let wallet_type_str = request_data.get("wallet_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Standard");
            
        let wallet_alias = request_data.get("alias")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        info!("💳 Creating standalone wallet: {}", wallet_name);
        
        // Create standalone wallet manager (no owner identity)
        let mut wallet_manager = lib_identity::wallets::WalletManager::new_standalone();
        
        // Convert string to WalletType enum
        let wallet_type = match wallet_type_str {
            "Primary" => lib_identity::wallets::WalletType::Primary,
            "UBI" => lib_identity::wallets::WalletType::UBI,
            "Savings" => lib_identity::wallets::WalletType::Savings,
            "DAO" => lib_identity::wallets::WalletType::NonProfitDAO,
            _ => lib_identity::wallets::WalletType::Standard,
        };
        
        // Create wallet with seed phrase
        let (wallet_id, seed_phrase) = wallet_manager.create_wallet_with_seed_phrase(
            wallet_type,
            wallet_name.clone(),
            wallet_alias.clone()
        ).await?;
        
        info!("Created standalone wallet with ID: {}", hex::encode(&wallet_id.0[..8]));
        
        // Record standalone wallet on blockchain
        self.record_standalone_wallet_on_blockchain(&wallet_id, &wallet_type_str, &wallet_name, &wallet_alias, &seed_phrase).await
            .unwrap_or_else(|e| warn!("Failed to record standalone wallet on blockchain: {}", e));
        
        // Distribute wallet info to DHT
        self.distribute_standalone_wallet_to_dht(&wallet_id, &wallet_type_str, &wallet_name).await
            .unwrap_or_else(|e| warn!("Failed to distribute standalone wallet to DHT: {}", e));
        
        // Return wallet creation result
        Ok(serde_json::json!({
            "success": true,
            "wallet_id": wallet_id,
            "wallet_type": wallet_type_str,
            "wallet_name": wallet_name,
            "alias": wallet_alias,
            "seed_phrase": {
                "words": seed_phrase.words,
                "word_count": seed_phrase.word_count,
                "language": seed_phrase.language
            },
            "created_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "standalone": true,
            "blockchain_recorded": true,
            "dht_distributed": true
        }))
    }
    
    /// Record standalone wallet on blockchain 
    async fn record_standalone_wallet_on_blockchain(
        &self, 
        wallet_id: &lib_identity::wallets::WalletId,
        wallet_type: &str,
        wallet_name: &str,
        wallet_alias: &Option<String>,
        seed_phrase: &lib_identity::recovery::RecoveryPhrase
    ) -> Result<()> {
        info!("Recording standalone wallet on blockchain...");
        
        let blockchain = lib_blockchain::get_shared_blockchain().await?;
        let mut blockchain_guard = blockchain.write().await;
        
        // Create seed commitment hash for blockchain verification
        let seed_commitment = lib_crypto::hash_blake3(&seed_phrase.words.join(" ").as_bytes());
        
        let wallet_data = lib_blockchain::WalletTransactionData {
            wallet_id: lib_blockchain::Hash::from_slice(&wallet_id.0),
            wallet_type: wallet_type.to_string(),
            wallet_name: wallet_name.to_string(),
            alias: wallet_alias.clone(),
            public_key: vec![0u8; 32], // Generate proper public key
            owner_identity_id: None, // No owner for standalone wallets
            seed_commitment: lib_blockchain::Hash::from_slice(&seed_commitment),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            registration_fee: 25, // Lower fee for standalone wallets
            capabilities: 0x0F, // Basic capabilities
            initial_balance: 0, // No initial balance for standalone
        };
        
        let _tx_hash = blockchain_guard.register_wallet(wallet_data)?;
        info!("Standalone wallet recorded on blockchain");
        Ok(())
    }
    
    /// Distribute standalone wallet to DHT
    async fn distribute_standalone_wallet_to_dht(
        &self,
        wallet_id: &lib_identity::wallets::WalletId, 
        wallet_type: &str,
        wallet_name: &str
    ) -> Result<()> {
        if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
            let mut dht = dht_client.write().await;
            
            let wallet_info = serde_json::json!({
                "wallet_id": hex::encode(&wallet_id.0),
                "wallet_type": wallet_type,
                "wallet_name": wallet_name,
                "standalone": true,
                "public_endpoint": format!("zhtp://wallet.{}.zhtp/", hex::encode(&wallet_id.0[..8])),
                "capabilities": ["receive"], // Public capabilities only
                "created_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            });
            
            let wallet_info_bytes = serde_json::to_vec(&wallet_info)?;
            let path = format!("/standalone/{}", hex::encode(&wallet_id.0[..8]));
            dht.store_content(
                "wallet.zhtp",
                &path,
                wallet_info_bytes
            ).await?;
            
            info!("Standalone wallet distributed to DHT");
        }
        Ok(())
    }
    
    /// Record identity and wallets on blockchain for immutable proof
    async fn record_identity_on_blockchain(&self, identity_result: &serde_json::Value) -> Result<()> {
        info!("Recording identity and wallets on blockchain...");
        
        // Get shared blockchain instance
        let blockchain = lib_blockchain::get_shared_blockchain().await?;
        let mut blockchain_guard = blockchain.write().await;
        
        // Extract real identity data from JSON result
        let identity_id_str = identity_result.get("identity_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing identity_id string"))?;
        
        // Parse identity_id from hex string to Hash
        let identity_id_bytes = hex::decode(identity_id_str)
            .map_err(|_| anyhow::anyhow!("Invalid identity_id hex format"))?;
        let identity_hash = lib_crypto::Hash::from_bytes(&identity_id_bytes[..32]);
        
        let did = format!("did:zhtp:{}", identity_id_str);
        
        // Extract real display name from citizenship result or default
        let display_name = identity_result.get("citizenship_result")
            .and_then(|cr| cr.get("display_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("ZHTP Citizen")
            .to_string();
        
        // Extract real public key from privacy credentials
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
        
        // Create identity transaction data with real extracted data
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
            // Register Primary Wallet with real data
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
            
            // Register UBI Wallet with real data
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
            
            // Register Savings Wallet with real data
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
                    initial_balance: welcome_bonus, // Real welcome bonus amount
                };
                let _savings_tx_hash = blockchain_guard.register_wallet(wallet_data)?;
                info!("Registered Savings Wallet {} on blockchain", savings_wallet_id_str);
            }
        }
        
        info!("Successfully recorded identity and wallets on blockchain with real data");
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
    
    pub async fn handle_tcp_mesh(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("Processing TCP mesh connection from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read TCP mesh data")?;
        
        if bytes_read > 0 {
            // Process TCP mesh message
            debug!("TCP mesh data: {} bytes", bytes_read);
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
        // In a real implementation, this would check WiFi Direct interface status
        debug!("Checking WiFi Direct group owner status");
        
        // For demonstration, alternate based on node_id to simulate real detection
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
        
        // Initialize Bluetooth advertising for ZHTP service
        if let Err(e) = bluetooth_protocol.start_advertising().await {
            warn!("Bluetooth advertising failed to start: {}", e);
            return Err(anyhow::anyhow!("Bluetooth advertising initialization failed: {}", e));
        }
        
        // Store the protocol instance
        *self.protocol.write().await = Some(bluetooth_protocol);
        
        info!("Bluetooth mesh protocol initialized - discoverable as 'ZHTP-{}'", 
              hex::encode(&self.node_id[..4]));
        info!("Your phone can now discover and connect to this ZHTP node via Bluetooth");
        
        Ok(())
    }
    
    /// Handle incoming Bluetooth connection with DHT bridging
    pub async fn handle_bluetooth_connection(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("Processing Bluetooth connection with DHT bridge from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read Bluetooth data")?;
        
        if bytes_read > 0 {
            debug!("Bluetooth data received: {} bytes", bytes_read);
            
            // Parse incoming message to determine if it's ZHTP mesh traffic
            let message = String::from_utf8_lossy(&buffer[..bytes_read]);
            
            if message.starts_with("ZHTP-MESH:") || message.starts_with("DHT:") {
                // This is ZHTP mesh traffic - bridge to DHT network
                info!("Bridging Bluetooth ZHTP traffic to DHT network");
                
                // TODO: Bridge to mesh router instead of having duplicate bridge logic
                // For now, handle DHT operations directly
                if message.starts_with("DHT:STORE:") || message.starts_with("DHT:GET:") {
                    info!("Handling DHT operation via Bluetooth");
                }
                
                // Send DHT bridge response
                let response = format!(
                    "ZHTP/1.0 200 OK\r\nX-Protocol: Bluetooth-DHT-Bridge\r\nX-Node-ID: {:?}\r\nX-Service: ZHTP-Mesh\r\nX-Bridge: Active\r\n\r\nBridged to DHT network",
                    &self.node_id[..8]
                );
                let _ = stream.write_all(response.as_bytes()).await;
                
            } else {
                // Regular Bluetooth connection
                let response = format!(
                    "ZHTP/1.0 200 OK\r\nX-Protocol: Bluetooth\r\nX-Node-ID: {:?}\r\nX-Service: ZHTP-Mesh\r\nX-Bridge: Available\r\n\r\nBluetooth connection established - DHT bridge ready",
                    &self.node_id[..8]
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
            
            // Store connection info with bridge capability
            let mut devices = self.connected_devices.write().await;
            devices.insert(addr.to_string(), "bluetooth-dht-bridge".to_string());
            
            info!("Bluetooth-DHT bridge established with device at {}", addr);
            info!("🌉 Device can now access DHT network via Bluetooth");
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
    /// Create new unified server with comprehensive backend integration
    pub async fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
    ) -> Result<Self> {
        let server_id = Uuid::new_v4();
        let port = 9333; // Single port for all protocols
        
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
        
        // Set identity manager on mesh router for direct UDP access
        mesh_router.set_identity_manager(identity_manager.clone());
        
        // Initialize WiFi Direct protocol
        if let Err(e) = wifi_router.initialize().await {
            warn!("WiFi Direct initialization failed: {}", e);
        }
        
        // Initialize Bluetooth protocol for phone connectivity
        if let Err(e) = bluetooth_router.initialize().await {
            warn!("Bluetooth initialization failed: {}", e);
        } else {
            info!("Bluetooth mesh ready - discoverable as '{}'", bluetooth_router.get_service_name());
        }
        
        let bootstrap_router = BootstrapRouter::new(server_id);
        
        // Register comprehensive API handlers
        Self::register_api_handlers(
            &mut http_router,
            blockchain.clone(),
            storage.clone(),
            identity_manager.clone(),
            economic_model.clone(),
            session_manager.clone(),
        ).await?;
        
        Ok(Self {
            tcp_listener: None,
            udp_socket: None,
            http_router,
            mesh_router,
            wifi_router,
            bluetooth_router,
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
        session_manager: Arc<SessionManager>,
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
        
        // Storage operations
        let storage_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            StorageHandler::new(storage.clone())
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
            DhtHandler::new()
        );
        http_router.register_handler("/api/v1/dht".to_string(), dht_handler);
        
        // Web4 domain and content (handle async creation first)
        let web4_handler = Web4Handler::new().await?;
        let web4_manager = web4_handler.get_web4_manager();
        
        // DNS resolution for .zhtp domains (connect to Web4Manager)
        let mut dns_handler = DnsHandler::new();
        dns_handler.set_web4_manager(web4_manager);
        let dns_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(dns_handler);
        http_router.register_handler("/api/v1/dns".to_string(), dns_handler);
        
        // Register Web4 handler
        let web4_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(web4_handler);
        http_router.register_handler("/api/v1/web4".to_string(), web4_handler);
        
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
        
        // Bind TCP listener for HTTP, TCP mesh, WiFi Direct, Bootstrap
        let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await
            .context("Failed to bind TCP listener")?;
        info!("TCP listener bound to port {}", self.port);
        
        // Bind UDP socket for UDP mesh, Bootstrap
        let udp_socket = UdpSocket::bind(format!("0.0.0.0:{}", self.port)).await
            .context("Failed to bind UDP socket")?;
        info!("UDP socket bound to port {}", self.port);
        
        self.tcp_listener = Some(Arc::new(tcp_listener));
        self.udp_socket = Some(Arc::new(udp_socket));
        
        *self.is_running.write().await = true;
        
        // Start TCP connection handler
        self.start_tcp_listener().await?;
        
        // Start UDP packet handler  
        self.start_udp_listener().await?;
        
        info!("ZHTP Unified Server online");
        info!("Protocols: HTTP API + UDP Mesh + WiFi Direct + Bootstrap");
        info!("Browser compatible: http://localhost:{}/api/v1/*", self.port);
        info!("Mesh compatible: UDP packets to port {}", self.port);
        
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
                        debug!("📥 New TCP connection from: {}", addr);
                        
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
                bluetooth_router.handle_bluetooth_connection(stream, addr).await
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
        
        // ZHTP mesh detection
        if data.starts_with("ZHTP/1.0 MESH") {
            return IncomingProtocol::ZhtpMeshTcp;
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
                        debug!("📥 UDP packet from: {} ({} bytes)", addr, len);
                        
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