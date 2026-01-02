//! ZHTP Server Core Implementation
//! 
//! Complete ZHTP server implementation with request processing,
//! economic validation, zero-knowledge proof verification, and
//! comprehensive content serving capabilities.

use crate::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod, ZhtpHeaders};
use crate::zhtp::config::ServerConfig;
use crate::zhtp::{ZhtpRequestHandler, ZhtpMiddleware, ZhtpServerEvents, ServerCapabilities, ZhtpResult};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum concurrent connections
const MAX_CONCURRENT_CONNECTIONS: usize = 1000;

/// Default keep-alive timeout
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// Request buffer size
const REQUEST_BUFFER_SIZE: usize = 8192;

/// Response buffer size
const RESPONSE_BUFFER_SIZE: usize = 8192;

/// ZHTP Server state
#[derive(Debug, Clone)]
pub struct ServerState {
    /// Server configuration
    pub config: ServerConfig,
    /// Server capabilities
    pub capabilities: ServerCapabilities,
    /// Active connections count
    pub active_connections: Arc<RwLock<usize>>,
    /// Request statistics
    pub stats: Arc<RwLock<ServerStats>>,
    /// Server start time
    pub start_time: Instant,
    /// Server unique ID
    pub server_id: String,
    /// Custom state storage
    pub custom_state: Arc<RwLock<HashMap<String, String>>>,
}

/// Server statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerStats {
    /// Total requests processed
    pub total_requests: u64,
    /// Total responses sent
    pub total_responses: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total DAO fees collected
    pub dao_fees_collected: u64,
    /// Total UBI distributed
    pub ubi_distributed: u64,
    /// Error count by type
    pub errors: HashMap<String, u64>,
    /// Request count by method
    pub requests_by_method: HashMap<String, u64>,
    /// Response count by status
    pub responses_by_status: HashMap<u16, u64>,
    /// ZK proof verification count
    pub zk_proofs_verified: u64,
    /// Post-quantum operations
    pub post_quantum_operations: u64,
    /// Mesh routing operations
    pub mesh_operations: u64,
    ///  operations
    pub isp_bypass_operations: u64,
}

impl ServerStats {
    /// Update request statistics
    pub fn record_request(&mut self, method: &ZhtpMethod, size: usize) {
        self.total_requests += 1;
        self.bytes_received += size as u64;
        let method_str = format!("{:?}", method);
        *self.requests_by_method.entry(method_str).or_insert(0) += 1;
    }
    
    /// Update response statistics
    pub fn record_response(&mut self, status: &ZhtpStatus, size: usize) {
        self.total_responses += 1;
        self.bytes_sent += size as u64;
        let status_code = status.code();
        *self.responses_by_status.entry(status_code).or_insert(0) += 1;
    }
    
    /// Record error
    pub fn record_error(&mut self, error_type: &str) {
        *self.errors.entry(error_type.to_string()).or_insert(0) += 1;
    }
    
    /// Record economic activity
    pub fn record_dao_fee(&mut self, amount: u64) {
        self.dao_fees_collected += amount;
    }
    
    /// Record UBI distribution
    pub fn record_ubi_distribution(&mut self, amount: u64) {
        self.ubi_distributed += amount;
    }
    
    /// Record zero-knowledge proof verification
    pub fn record_zk_proof_verification(&mut self) {
        self.zk_proofs_verified += 1;
    }
    
    /// Record post-quantum cryptography operation
    pub fn record_post_quantum_operation(&mut self) {
        self.post_quantum_operations += 1;
    }
    
    /// Record mesh networking operation
    pub fn record_mesh_operation(&mut self) {
        self.mesh_operations += 1;
    }
    
    /// Record  operation
    pub fn record_isp_bypass_operation(&mut self) {
        self.isp_bypass_operations += 1;
    }
}

/// ZHTP Server implementation
pub struct ZhtpServer {
    /// Server state
    state: ServerState,
    /// Request handlers
    handlers: Vec<Arc<dyn ZhtpRequestHandler>>,
    /// Middleware stack
    middleware: Vec<Arc<dyn ZhtpMiddleware>>,
    /// Event handlers
    event_handlers: Vec<Arc<dyn ZhtpServerEvents>>,
    /// Connection semaphore
    connection_semaphore: Arc<Semaphore>,
    /// TCP listener
    listener: Option<TcpListener>,
    /// Server running flag
    is_running: Arc<RwLock<bool>>,
}

impl ZhtpServer {
    /// Create new ZHTP server
    pub fn new(config: ServerConfig) -> Self {
        let server_id = Uuid::new_v4().to_string();
        let capabilities = ServerCapabilities::default();
        
        let state = ServerState {
            config,
            capabilities,
            active_connections: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(ServerStats::default())),
            start_time: Instant::now(),
            server_id,
            custom_state: Arc::new(RwLock::new(HashMap::new())),
        };
        
        Self {
            state,
            handlers: Vec::new(),
            middleware: Vec::new(),
            event_handlers: Vec::new(),
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            listener: None,
            is_running: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Add request handler
    pub fn add_handler(&mut self, handler: Arc<dyn ZhtpRequestHandler>) {
        self.handlers.push(handler);
        // Sort handlers by priority (highest first)
        self.handlers.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }
    
    /// Add middleware
    pub fn add_middleware(&mut self, middleware: Arc<dyn ZhtpMiddleware>) {
        self.middleware.push(middleware);
    }
    
    /// Add event handler
    pub fn add_event_handler(&mut self, handler: Arc<dyn ZhtpServerEvents>) {
        self.event_handlers.push(handler);
    }
    
    /// Get server state
    pub fn state(&self) -> &ServerState {
        &self.state
    }
    
    /// Get server statistics
    pub fn stats(&self) -> ServerStats {
        self.state.stats.read().unwrap().clone()
    }
    
    /// Check if server is running
    pub fn is_running(&self) -> bool {
        *self.is_running.read().unwrap()
    }
    
    /// Start the ZHTP server
    pub async fn start(&mut self) -> ZhtpResult<()> {
        if self.is_running() {
            return Err(anyhow::anyhow!("Server is already running"));
        }
        
        tracing::info!(" Starting ZHTP Server v{}", crate::zhtp::ZHTP_VERSION);
        tracing::info!("Server ID: {}", self.state.server_id);
        tracing::info!("Binding to port {}", self.state.config.port);
        
        // Bind to address
        let addr = format!("{}:{}", self.state.config.host, self.state.config.port);
        let listener = TcpListener::bind(&addr).await
            .with_context(|| format!("Failed to bind to address {}", addr))?;
        
        tracing::info!("ZHTP Server listening on {}", addr);
        
        // Notify event handlers
        for handler in &self.event_handlers {
            if let Err(e) = handler.on_start().await {
                tracing::error!("Event handler start error: {}", e);
            }
        }
        
        self.listener = Some(listener);
        *self.is_running.write().unwrap() = true;
        
        // Start accepting connections
        self.accept_connections().await?;
        
        Ok(())
    }
    
    /// Stop the ZHTP server
    pub async fn stop(&mut self) -> ZhtpResult<()> {
        if !self.is_running() {
            return Ok(());
        }
        
        tracing::info!("Stopping ZHTP Server");
        
        *self.is_running.write().unwrap() = false;
        
        // Notify event handlers
        for handler in &self.event_handlers {
            if let Err(e) = handler.on_stop().await {
                tracing::error!("Event handler stop error: {}", e);
            }
        }
        
        // Wait for active connections to finish
        let mut wait_count = 0;
        while *self.state.active_connections.read().unwrap() > 0 && wait_count < 30 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            wait_count += 1;
        }
        
        if *self.state.active_connections.read().unwrap() > 0 {
            tracing::warn!("{} connections still active after shutdown", 
                         *self.state.active_connections.read().unwrap());
        }
        
        tracing::info!("ZHTP Server stopped");
        Ok(())
    }
    
    /// Accept incoming connections
    async fn accept_connections(&mut self) -> ZhtpResult<()> {
        let listener = self.listener.take()
            .ok_or_else(|| anyhow::anyhow!("No listener available"))?;
        
        while self.is_running() {
            // Acquire connection permit
            let _permit = self.connection_semaphore.acquire().await
                .context("Failed to acquire connection permit")?;
            
            match listener.accept().await {
                Ok((stream, addr)) => {
                    tracing::debug!("New connection from {}", addr);
                    
                    // Increment active connections
                    *self.state.active_connections.write().unwrap() += 1;
                    
                    // Handle connection in background
                    let server_state = self.state.clone();
                    let handlers = self.handlers.clone();
                    let middleware = self.middleware.clone();
                    let event_handlers = self.event_handlers.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            server_state,
                            handlers,
                            middleware,
                            event_handlers,
                        ).await {
                            tracing::error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                    // Continue accepting connections despite errors
                }
            }
        }
        
        Ok(())
    }
}

/// Handle individual connection
async fn handle_connection(
    mut stream: TcpStream,
    state: ServerState,
    handlers: Vec<Arc<dyn ZhtpRequestHandler>>,
    middleware: Vec<Arc<dyn ZhtpMiddleware>>,
    event_handlers: Vec<Arc<dyn ZhtpServerEvents>>,
) -> ZhtpResult<()> {
    let connection_start = Instant::now();
    
    // Set keep-alive timeout
    let timeout_duration = Duration::from_secs(state.config.request_timeout_seconds);
    
    loop {
        // Read request with timeout
        let request_result = timeout(timeout_duration, read_request(&mut stream)).await;
        
        let mut request = match request_result {
            Ok(Ok(Some(req))) => req,
            Ok(Ok(None)) => break, // Connection closed gracefully
            Ok(Err(e)) => {
                tracing::error!("Request parsing error: {}", e);
                let error_response = ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Request parsing error: {}", e),
                );
                let _ = send_response(&mut stream, &error_response, &state).await;
                break;
            }
            Err(_) => {
                tracing::warn!("⏰ Request timeout");
                let timeout_response = ZhtpResponse::error(
                    ZhtpStatus::RequestTimeout,
                    "Request timeout".to_string(),
                );
                let _ = send_response(&mut stream, &timeout_response, &state).await;
                break;
            }
        };
        
        // Record request statistics
        {
            let mut stats = state.stats.write().unwrap();
            stats.record_request(&request.method, request.body.len());
        }
        
        // Notify event handlers
        for handler in &event_handlers {
            if let Err(e) = handler.on_request(&request).await {
                tracing::error!("Event handler request error: {}", e);
            }
        }
        
        // Process middleware (before request)
        for mw in &middleware {
            if let Err(e) = mw.before_request(&mut request).await {
                tracing::error!("Middleware before_request error: {}", e);
                let error_response = ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Middleware error".to_string(),
                );
                let _ = send_response(&mut stream, &error_response, &state).await;
                continue;
            }
        }
        
        // Handle CORS preflight OPTIONS requests
        let mut response = None;
        if request.method == ZhtpMethod::Options {
            let mut cors_headers = ZhtpHeaders::new();
            cors_headers.set("Access-Control-Allow-Origin", "*".to_string());
            cors_headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS".to_string());
            cors_headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Peer-Address".to_string());
            cors_headers.set("Access-Control-Max-Age", "86400".to_string());
            cors_headers.set("Content-Length", "0".to_string());
            
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            response = Some(ZhtpResponse {
                version: crate::types::ZHTP_VERSION.to_string(),
                status: ZhtpStatus::Ok,
                status_message: "OK".to_string(),
                headers: cors_headers,
                body: Vec::new(),
                timestamp,
                server: None,
                validity_proof: None,
            });
        }
        
        // Find appropriate handler if not OPTIONS
        if response.is_none() {
            for handler in &handlers {
                if handler.can_handle(&request) {
                    match handler.handle_request(request.clone()).await {
                        Ok(resp) => {
                            response = Some(resp);
                            break;
                        }
                        Err(e) => {
                            tracing::error!("Handler error: {}", e);
                            
                            // Try middleware error handlers
                            for mw in &middleware {
                                if let Ok(Some(error_resp)) = mw.on_error(&e).await {
                                    response = Some(error_resp);
                                    break;
                                }
                            }
                            
                            if response.is_none() {
                                response = Some(ZhtpResponse::error(
                                    ZhtpStatus::InternalServerError,
                                    format!("Handler error: {}", e),
                                ));
                            }
                            break;
                        }
                    }
                }
            }
        }
        
        // Default response if no handler found
        let mut final_response = response.unwrap_or_else(|| {
            ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "No handler found for request".to_string(),
            )
        });
        
        // Process middleware (after response)
        for mw in &middleware {
            if let Err(e) = mw.after_response(&mut final_response).await {
                tracing::error!("Middleware after_response error: {}", e);
            }
        }
        
        // Send response
        if let Err(e) = send_response(&mut stream, &final_response, &state).await {
            tracing::error!("Failed to send response: {}", e);
            break;
        }
        
        // Record response statistics
        {
            let mut stats = state.stats.write().unwrap();
            stats.record_response(&final_response.status, final_response.body.len());
        }
        
        // Notify event handlers
        for handler in &event_handlers {
            if let Err(e) = handler.on_response(&final_response).await {
                tracing::error!("Event handler response error: {}", e);
            }
        }
        
        // Check if connection should be kept alive
        if !should_keep_alive(&request, &final_response) {
            break;
        }
        
        // Check keep-alive timeout
        if connection_start.elapsed() > KEEP_ALIVE_TIMEOUT {
            tracing::debug!("⏰ Keep-alive timeout reached");
            break;
        }
    }
    
    // Decrement active connections
    *state.active_connections.write().unwrap() -= 1;
    
    Ok(())
}

/// Read ZHTP request from stream
async fn read_request(stream: &mut TcpStream) -> ZhtpResult<Option<ZhtpRequest>> {
    let mut buffer = vec![0u8; REQUEST_BUFFER_SIZE];
    let mut total_read = 0;
    let mut headers_complete = false;
    let mut content_length = 0;
    
    // Read headers first
    while !headers_complete && total_read < buffer.len() {
        let bytes_read = stream.read(&mut buffer[total_read..]).await?;
        if bytes_read == 0 {
            return Ok(None); // Connection closed
        }
        
        total_read += bytes_read;
        
        // Check for end of headers (double CRLF)
        if let Some(headers_end) = find_headers_end(&buffer[..total_read]) {
            headers_complete = true;
            
            // Parse headers to get content length
            let headers_str = String::from_utf8_lossy(&buffer[..headers_end]);
            content_length = parse_content_length(&headers_str);
            
            // If we have more data than headers, it's part of the body
            let body_start = headers_end + 4; // +4 for double CRLF
            if total_read > body_start {
                // We already have some body data
                let body_data_read = total_read - body_start;
                if body_data_read >= content_length {
                    // We have all the data we need
                    break;
                }
            }
        }
    }
    
    // Read remaining body if needed
    if content_length > 0 {
        let headers_end = find_headers_end(&buffer[..total_read]).unwrap_or(total_read);
        let body_start = headers_end + 4;
        let body_data_read = if total_read > body_start { total_read - body_start } else { 0 };
        let remaining_body = content_length.saturating_sub(body_data_read);
        
        if remaining_body > 0 {
            // Resize buffer if needed
            let total_needed = total_read + remaining_body;
            if total_needed > buffer.len() {
                buffer.resize(total_needed, 0);
            }
            
            // Read remaining body data
            let mut body_read = 0;
            while body_read < remaining_body {
                let bytes_read = stream.read(&mut buffer[total_read + body_read..total_needed]).await?;
                if bytes_read == 0 {
                    break; // Connection closed unexpectedly
                }
                body_read += bytes_read;
            }
            total_read += body_read;
        }
    }
    
    // Parse the complete request
    let request_data = &buffer[..total_read];
    parse_lib_request(request_data)
}

/// Find end of headers (double CRLF)
fn find_headers_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r' && data[i + 1] == b'\n' && 
           data[i + 2] == b'\r' && data[i + 3] == b'\n' {
            return Some(i);
        }
    }
    None
}

/// Parse content length from headers
fn parse_content_length(headers: &str) -> usize {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            if let Some(value) = line.split(':').nth(1) {
                if let Ok(length) = value.trim().parse::<usize>() {
                    return length;
                }
            }
        }
    }
    0
}

/// Parse ZHTP request from raw data
fn parse_lib_request(data: &[u8]) -> ZhtpResult<Option<ZhtpRequest>> {
    if data.is_empty() {
        return Ok(None);
    }
    
    let request_str = String::from_utf8_lossy(data);
    let lines: Vec<&str> = request_str.lines().collect();
    
    if lines.is_empty() {
        return Err(anyhow::anyhow!("Empty request"));
    }
    
    // Parse request line
    let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
    if request_line_parts.len() < 3 {
        return Err(anyhow::anyhow!("Invalid request line"));
    }
    
    let method = request_line_parts[0].parse::<ZhtpMethod>()
        .map_err(|e| anyhow::anyhow!("Invalid method: {}", e))?;
    let uri = request_line_parts[1].to_string();
    let _version = request_line_parts[2].to_string();
    
    // Parse headers
    let mut headers = ZhtpHeaders::new();
    let mut header_end = 1;
    
    for (i, line) in lines[1..].iter().enumerate() {
        if line.is_empty() {
            header_end = i + 2; // +1 for skipping first line, +1 for current empty line
            break;
        }
        
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.set(&key, value);
        }
    }
    
    // Parse body
    let body_lines = &lines[header_end..];
    let body = body_lines.join("\n").into_bytes();
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let request = ZhtpRequest {
        method,
        uri,
        version: "1.0".to_string(),
        headers,
        body,
        timestamp,
        requester: None,
        auth_proof: None,
    };
    
    Ok(Some(request))
}

/// Send ZHTP response
async fn send_response(
    stream: &mut TcpStream,
    response: &ZhtpResponse,
    state: &ServerState,
) -> ZhtpResult<()> {
    let response_data = format_lib_response(response)?;
    stream.write_all(&response_data).await?;
    stream.flush().await?;
    
    // Update statistics
    {
        let mut stats = state.stats.write().unwrap();
        stats.record_response(&response.status, response_data.len());
    }
    
    Ok(())
}

/// Format ZHTP response as bytes
fn format_lib_response(response: &ZhtpResponse) -> ZhtpResult<Vec<u8>> {
    let mut result = Vec::new();
    
    // Status line - Use HTTP/1.1 for compatibility with standard HTTP clients
    let status_line = format!("HTTP/1.1 {} {}\r\n", 
        response.status.code(), 
        response.status.reason_phrase()
    );
    result.extend_from_slice(status_line.as_bytes());
    
    // Headers
    for (key, value) in response.headers.iter() {
        let header_line = format!("{}: {}\r\n", key, value);
        result.extend_from_slice(header_line.as_bytes());
    }
    
    // Content length if not present
    if !response.headers.contains_key("Content-Length") {
        let content_length = format!("Content-Length: {}\r\n", response.body.len());
        result.extend_from_slice(content_length.as_bytes());
    }
    
    // Server header
    if !response.headers.contains_key("Server") {
        let server_header = format!("Server: ZHTP/1.0 (HTTP/1.1 Compatible)\r\n");
        result.extend_from_slice(server_header.as_bytes());
    }
    
    // Add standard HTTP headers for compatibility
    if !response.headers.contains_key("Connection") {
        result.extend_from_slice(b"Connection: close\r\n");
    }
    if !response.headers.contains_key("Content-Type") {
        result.extend_from_slice(b"Content-Type: application/json\r\n");
    }
    
    // Add CORS headers for browser integration
    if !response.headers.contains_key("Access-Control-Allow-Origin") {
        result.extend_from_slice(b"Access-Control-Allow-Origin: *\r\n");
    }
    if !response.headers.contains_key("Access-Control-Allow-Methods") {
        result.extend_from_slice(b"Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n");
    }
    if !response.headers.contains_key("Access-Control-Allow-Headers") {
        result.extend_from_slice(b"Access-Control-Allow-Headers: Content-Type, Authorization, X-Peer-Address\r\n");
    }
    if !response.headers.contains_key("Access-Control-Max-Age") {
        result.extend_from_slice(b"Access-Control-Max-Age: 86400\r\n");
    }
    
    // Date header
    if !response.headers.contains_key("Date") {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let date_header = format!("Date: {}\r\n", now);
        result.extend_from_slice(date_header.as_bytes());
    }
    
    // End of headers
    result.extend_from_slice(b"\r\n");
    
    // Body
    result.extend_from_slice(&response.body);
    
    Ok(result)
}

/// Check if connection should be kept alive
fn should_keep_alive(request: &ZhtpRequest, response: &ZhtpResponse) -> bool {
    // Check Connection header in request
    if let Some(connection) = request.headers.get("Connection") {
        if connection.to_lowercase() == "close" {
            return false;
        }
    }
    
    // Check Connection header in response
    if let Some(connection) = response.headers.get("Connection") {
        if connection.to_lowercase() == "close" {
            return false;
        }
    }
    
    // Default to keep-alive for ZHTP/1.0
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zhtp::config::ServerConfig;

    #[test]
    fn test_server_creation() {
        let config = ServerConfig::default();
        let server = ZhtpServer::new(config);
        assert!(!server.is_running());
        assert_eq!(server.handlers.len(), 0);
        assert_eq!(server.middleware.len(), 0);
    }

    #[test]
    fn test_server_stats() {
        let mut stats = ServerStats::default();
        stats.record_request(&ZhtpMethod::Get, 1024);
        stats.record_response(&ZhtpStatus::Ok, 2048);
        stats.record_dao_fee(100);
        stats.record_zk_proof_verification();
        
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.total_responses, 1);
        assert_eq!(stats.bytes_received, 1024);
        assert_eq!(stats.bytes_sent, 2048);
        assert_eq!(stats.dao_fees_collected, 100);
        assert_eq!(stats.zk_proofs_verified, 1);
    }

    #[test]
    fn test_find_headers_end() {
        let data = b"GET / ZHTP/1.0\r\nHost: example.com\r\n\r\nBody data";
        
        // Let's debug the exact positions
        println!("Data length: {}", data.len());
        for (i, &byte) in data.iter().enumerate() {
            if byte == b'\r' || byte == b'\n' {
                println!("Position {}: {:?} ({})", i, byte as char, byte);
            }
        }
        
        let end = find_headers_end(data);
        // The double CRLF (\r\n\r\n) should start at position 33
        assert_eq!(end, Some(33));
    }

    #[test]
    fn test_parse_content_length() {
        let headers = "GET / ZHTP/1.0\r\nHost: example.com\r\nContent-Length: 1024\r\n";
        let length = parse_content_length(headers);
        assert_eq!(length, 1024);
    }

    #[test]
    fn test_should_keep_alive() {
        let request = ZhtpRequest::get("/test".to_string(), None).unwrap();
        let response = ZhtpResponse::success(vec![], None);
        assert!(should_keep_alive(&request, &response));
        
        let mut close_request = ZhtpRequest::get("/test".to_string(), None).unwrap();
        close_request.headers.set("Connection", "close".to_string());
        assert!(!should_keep_alive(&close_request, &response));
    }
}
