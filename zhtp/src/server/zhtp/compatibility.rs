//! HTTP Compatibility Layer (Temporary)
//!
//! Provides HTTP/1.1 and HTTP/3 compatibility for legacy browsers
//! that don't yet support native ZHTP protocol. This layer will be
//! deprecated once native ZHTP clients are widely available.

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use tracing::{info, warn, debug};
use quinn::{RecvStream, SendStream};

use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpHeaders, ZhtpStatus};
use super::router::ZhtpRouter;

/// HTTP compatibility layer for legacy clients
pub struct HttpCompatibilityLayer {
    router: Arc<RwLock<ZhtpRouter>>,
}

impl HttpCompatibilityLayer {
    pub fn new(router: Arc<RwLock<ZhtpRouter>>) -> Self {
        info!("🔄 HTTP compatibility layer initialized (deprecated - use native ZHTP)");
        Self { router }
    }
    
    /// Handle HTTP request over QUIC stream and convert to ZHTP
    pub async fn handle_http_over_quic(
        &self,
        mut recv: RecvStream,
        send: SendStream,
    ) -> Result<()> {
        debug!("🔄 Processing legacy HTTP request (compatibility mode)");

        // Read HTTP request
        let buffer = recv.read_to_end(10 * 1024 * 1024).await
            .map_err(|e| anyhow::anyhow!("Failed to read HTTP request: {}", e))?;

        self.handle_http_request_data(buffer, send).await
    }

    /// Handle HTTP request with already-read prefix data
    pub async fn handle_http_over_quic_with_prefix(
        &self,
        prefix: Vec<u8>,
        mut recv: RecvStream,
        send: SendStream,
    ) -> Result<()> {
        debug!("🔄 Processing legacy HTTP request with {} byte prefix", prefix.len());

        // Read remaining data
        let remaining = recv.read_to_end(10 * 1024 * 1024).await
            .map_err(|e| anyhow::anyhow!("Failed to read remaining HTTP data: {}", e))?;

        // Combine prefix with remaining data
        let mut buffer = prefix;
        buffer.extend(remaining);

        self.handle_http_request_data(buffer, send).await
    }

    /// Internal: process HTTP request data and send response
    async fn handle_http_request_data(
        &self,
        buffer: Vec<u8>,
        mut send: SendStream,
    ) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }

        // Parse HTTP request
        let http_data = String::from_utf8_lossy(&buffer);
        let request = match self.parse_http_request(&http_data) {
            Ok(req) => req,
            Err(e) => {
                warn!("❌ Failed to parse HTTP request: {}", e);
                let error_response = self.create_http_error_response(400, "Bad Request");
                send.write_all(&error_response).await
                    .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
                send.finish()
                    .map_err(|e| anyhow::anyhow!("Finish error: {}", e))?;
                return Ok(());
            }
        };
        
        info!("🔄 HTTP {} {} → ZHTP", 
            match request.method {
                ZhtpMethod::Get => "GET",
                ZhtpMethod::Post => "POST",
                ZhtpMethod::Put => "PUT",
                ZhtpMethod::Delete => "DELETE",
                _ => "UNKNOWN",
            },
            request.uri
        );
        
        // Route through ZHTP router
        let router = self.router.read().await;
        let response = router.route_request(request).await
            .unwrap_or_else(|e| {
                warn!("Handler error: {}", e);
                ZhtpResponse::error(ZhtpStatus::InternalServerError, e.to_string())
            });
        
        // Convert ZHTP response back to HTTP
        let http_response = self.zhtp_to_http_response(&response);
        
        send.write_all(&http_response).await
            .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("Finish error: {}", e))?;
        
        debug!("✅ HTTP compatibility response sent");
        Ok(())
    }

    /// Handle HTTP request over QUIC with BufferedStream (for protocol detection compatibility)
    pub async fn handle_http_over_quic_buffered(
        &self,
        buffered: &mut crate::server::quic_handler::BufferedStream,
        mut send: SendStream,
    ) -> Result<()> {
        debug!("🔄 Processing legacy HTTP request (compatibility mode, buffered)");

        // Read HTTP request from buffered stream
        let buffer = buffered.read_to_end(10 * 1024 * 1024).await
            .map_err(|e| anyhow::anyhow!("Failed to read HTTP request from buffered stream: {}", e))?;

        if buffer.is_empty() {
            return Ok(());
        }

        // Parse HTTP request
        let http_data = String::from_utf8_lossy(&buffer);
        let request = match self.parse_http_request(&http_data) {
            Ok(req) => req,
            Err(e) => {
                warn!("❌ Failed to parse HTTP request: {}", e);
                let error_response = self.create_http_error_response(400, "Bad Request");
                send.write_all(&error_response).await
                    .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
                send.finish()
                    .map_err(|e| anyhow::anyhow!("Finish error: {}", e))?;
                return Ok(());
            }
        };

        info!("🔄 HTTP {} {} → ZHTP",
            match request.method {
                ZhtpMethod::Get => "GET",
                ZhtpMethod::Post => "POST",
                ZhtpMethod::Put => "PUT",
                ZhtpMethod::Delete => "DELETE",
                _ => "UNKNOWN",
            },
            request.uri
        );

        // Route through ZHTP router
        let router = self.router.read().await;
        let response = router.route_request(request).await
            .unwrap_or_else(|e| {
                warn!("Handler error: {}", e);
                ZhtpResponse::error(ZhtpStatus::InternalServerError, e.to_string())
            });

        // Convert ZHTP response back to HTTP
        let http_response = self.zhtp_to_http_response(&response);

        send.write_all(&http_response).await
            .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("Finish error: {}", e))?;

        debug!("✅ HTTP compatibility response sent (buffered)");
        Ok(())
    }

    /// Parse HTTP/1.1 request into ZHTP request
    fn parse_http_request(&self, http_data: &str) -> Result<ZhtpRequest> {
        let lines: Vec<&str> = http_data.lines().collect();
        
        if lines.is_empty() {
            return Err(anyhow::anyhow!("Empty HTTP request"));
        }
        
        // Parse request line
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return Err(anyhow::anyhow!("Invalid HTTP request line"));
        }
        
        let method = match parts[0] {
            "GET" => ZhtpMethod::Get,
            "POST" => ZhtpMethod::Post,
            "PUT" => ZhtpMethod::Put,
            "DELETE" => ZhtpMethod::Delete,
            "HEAD" => ZhtpMethod::Head,
            "OPTIONS" => ZhtpMethod::Options,
            _ => ZhtpMethod::Get,
        };
        
        let uri = parts[1].to_string();
        
        // Parse headers
        let mut headers = ZhtpHeaders::new();
        let mut body_start = 0;
        
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i + 1;
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.set(key.trim(), value.trim().to_string());
            }
        }
        
        // Parse body
        let body = if body_start < lines.len() {
            lines[body_start..].join("\n").into_bytes()
        } else {
            Vec::new()
        };
        
        Ok(ZhtpRequest {
            method,
            uri,
            headers,
            body,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            version: "1.0".to_string(),
            requester: None,
            auth_proof: None,
        })
    }
    
    /// Convert ZHTP response to HTTP/1.1 response
    fn zhtp_to_http_response(&self, response: &ZhtpResponse) -> Vec<u8> {
        let status_line = match response.status {
            ZhtpStatus::Ok => "HTTP/1.1 200 OK\r\n",
            ZhtpStatus::Created => "HTTP/1.1 201 Created\r\n",
            ZhtpStatus::Accepted => "HTTP/1.1 202 Accepted\r\n",
            ZhtpStatus::BadRequest => "HTTP/1.1 400 Bad Request\r\n",
            ZhtpStatus::Unauthorized => "HTTP/1.1 401 Unauthorized\r\n",
            ZhtpStatus::Forbidden => "HTTP/1.1 403 Forbidden\r\n",
            ZhtpStatus::NotFound => "HTTP/1.1 404 Not Found\r\n",
            ZhtpStatus::TooManyRequests => "HTTP/1.1 429 Too Many Requests\r\n",
            ZhtpStatus::InternalServerError => "HTTP/1.1 500 Internal Server Error\r\n",
            _ => "HTTP/1.1 500 Internal Server Error\r\n",
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
        http_response.push_str("X-ZHTP-Compatibility: HTTP-Legacy\r\n");
        http_response.push_str("Connection: close\r\n");
        http_response.push_str("\r\n");
        
        let mut result = http_response.into_bytes();
        result.extend_from_slice(&response.body);
        result
    }
    
    /// Create HTTP error response
    fn create_http_error_response(&self, status_code: u16, message: &str) -> Vec<u8> {
        let status_line = match status_code {
            400 => "HTTP/1.1 400 Bad Request\r\n",
            404 => "HTTP/1.1 404 Not Found\r\n",
            500 => "HTTP/1.1 500 Internal Server Error\r\n",
            _ => "HTTP/1.1 500 Internal Server Error\r\n",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    #[test]
    fn test_parse_http_get() {
        let layer = HttpCompatibilityLayer::new(Arc::new(RwLock::new(ZhtpRouter::new())));
        
        let http_request = "GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = layer.parse_http_request(http_request).unwrap();
        
        assert_eq!(result.method, ZhtpMethod::Get);
        assert_eq!(result.uri, "/api/test");
    }
    
    #[test]
    fn test_parse_http_post_with_body() {
        let layer = HttpCompatibilityLayer::new(Arc::new(RwLock::new(ZhtpRouter::new())));
        
        let http_request = "POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\ntest data";
        let result = layer.parse_http_request(http_request).unwrap();
        
        assert_eq!(result.method, ZhtpMethod::Post);
        assert_eq!(result.uri, "/api/data");
        assert_eq!(result.body, b"test data");
    }
    
    #[test]
    fn test_zhtp_to_http_response() {
        let layer = HttpCompatibilityLayer::new(Arc::new(RwLock::new(ZhtpRouter::new())));
        
        let zhtp_response = ZhtpResponse {
            version: "1.0".to_string(),
            status: ZhtpStatus::Ok,
            status_message: "OK".to_string(),
            headers: ZhtpHeaders::new(),
            body: b"success".to_vec(),
            timestamp: 0,
            server: None,
            validity_proof: None,
        };
        
        let http_response = layer.zhtp_to_http_response(&zhtp_response);
        let response_str = String::from_utf8_lossy(&http_response);
        
        assert!(response_str.contains("HTTP/1.1 200 OK"));
        assert!(response_str.contains("Content-Length: 7"));
        assert!(response_str.contains("success"));
    }
}
