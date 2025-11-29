//! HTTP Request Router
//! 
//! Routes incoming HTTP requests to appropriate handlers

use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Result, Context};
use tracing::{info, warn, debug};
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpStatus, ZhtpHeaders};

use super::middleware::Middleware;

/// HTTP request routing and handling
pub struct HttpRouter {
    routes: HashMap<String, Arc<dyn ZhtpRequestHandler>>,
    middleware: Vec<Arc<dyn Middleware>>,
}

impl HttpRouter {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            middleware: Vec::new(),
        }
    }
    
    pub fn register_handler(&mut self, path: String, handler: Arc<dyn ZhtpRequestHandler>) {
        info!("Registering HTTP handler: {}", path);
        self.routes.insert(path, handler);
    }
    
    pub fn add_middleware(&mut self, middleware: Arc<dyn Middleware>) {
        info!("Adding middleware: {}", middleware.name());
        self.middleware.push(middleware);
    }
    
    pub async fn handle_http_request(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        debug!("Processing HTTP request from: {}", addr);
        
        // Read HTTP request with dynamic buffer sizing based on Content-Length
        let mut header_buffer = vec![0; 8192]; // Initial buffer for headers
        
        let bytes_read = stream.read(&mut header_buffer).await
            .context("Failed to read HTTP request")?;
        
        if bytes_read == 0 {
            return Ok(());
        }
        
        let mut total_read = bytes_read;
        
        // Check if headers are complete (look for \r\n\r\n)
        let header_data = String::from_utf8_lossy(&header_buffer[..total_read]);
        if let Some(header_end) = header_data.find("\r\n\r\n") {
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
                    let total_size = header_size + content_len;
                    let max_size = 10_485_760; // 10 MB limit
                    
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
                    debug!("Read full request: {} bytes (header: {}, body: {})", 
                           total_read, header_size, content_len);
                }
            }
        }
        
        let request_data = String::from_utf8_lossy(&header_buffer[..total_read]);
        debug!("HTTP request data: {}", &request_data[..std::cmp::min(200, request_data.len())]);
        
        // Parse HTTP request
        if let Some(first_line) = request_data.lines().next() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let method = parts[0];
                let path = parts[1];
                
                info!("HTTP {} {}", method, path);
                
                // Route to handler
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
                    warn!("No handler found for path: '{}' (method: {})", path, method);
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
    
    async fn call_handler(&self, handler: &Arc<dyn ZhtpRequestHandler>, 
                          method: &str, path: &str, request_data: &str) -> Result<Vec<u8>> {
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
            headers: self.parse_headers(request_data),
            body: self.parse_body(request_data),
            timestamp: chrono::Utc::now().timestamp() as u64,
            version: "1.0".to_string(),
            requester: None,
            auth_proof: None,
        };
        
        // Process middleware first
        let (processed_request, middleware_response) = self.process_middleware(zhtp_request).await?;
        
        // If middleware returned a response, use it
        let zhtp_response = if let Some(middleware_resp) = middleware_response {
            middleware_resp
        } else {
            handler.handle_request(processed_request).await?
        };
        
        Ok(self.zhtp_response_to_http(&zhtp_response))
    }
    
    fn parse_headers(&self, request_data: &str) -> ZhtpHeaders {
        let mut headers = ZhtpHeaders::new();
        
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
    }
    
    fn parse_body(&self, request_data: &str) -> Vec<u8> {
        let lines: Vec<&str> = request_data.lines().collect();
        let mut body_start = 0;
        let mut found_empty_line = false;
        
        // Find the empty line that separates headers from body
        for (i, line) in lines.iter().enumerate().skip(1) {
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
    }
    
    fn zhtp_response_to_http(&self, response: &ZhtpResponse) -> Vec<u8> {
        let status_line = match response.status {
            ZhtpStatus::Ok => "HTTP/1.1 200 OK\r\n",
            ZhtpStatus::BadRequest => "HTTP/1.1 400 Bad Request\r\n",
            ZhtpStatus::Unauthorized => "HTTP/1.1 401 Unauthorized\r\n",
            ZhtpStatus::Forbidden => "HTTP/1.1 403 Forbidden\r\n",
            ZhtpStatus::NotFound => "HTTP/1.1 404 Not Found\r\n",
            ZhtpStatus::InternalServerError => "HTTP/1.1 500 Internal Server Error\r\n",
            ZhtpStatus::TooManyRequests => "HTTP/1.1 429 Too Many Requests\r\n",
            _ => "HTTP/1.1 200 OK\r\n",
        };
        
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
    
    pub fn create_error_response(&self, status_code: u16, message: &str) -> Vec<u8> {
        let status_line = match status_code {
            404 => "HTTP/1.1 404 Not Found\r\n",
            413 => "HTTP/1.1 413 Payload Too Large\r\n",
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

impl Clone for HttpRouter {
    fn clone(&self) -> Self {
        // Clone all registered routes and handlers
        Self {
            routes: self.routes.clone(),
            middleware: self.middleware.clone(),
        }
    }
}
