//! ZHTP Router - Native Request Routing Over QUIC
//!
//! Routes ZHTP requests directly from QUIC streams to registered handlers.
//! No HTTP parsing or conversion - pure ZHTP protocol.

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn, debug};

use quinn::{RecvStream, SendStream};
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};

use super::serialization::{deserialize_request, serialize_response};
use super::super::http::middleware::Middleware;

/// Native ZHTP router for QUIC streams
pub struct ZhtpRouter {
    /// Registered route handlers
    routes: HashMap<String, Arc<dyn ZhtpRequestHandler>>,
    
    /// Request middleware
    middleware: Vec<Arc<dyn Middleware>>,
}

impl ZhtpRouter {
    /// Create a new ZHTP router
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            middleware: Vec::new(),
        }
    }
    
    /// Register a handler for a specific path
    pub fn register_handler(&mut self, path: String, handler: Arc<dyn ZhtpRequestHandler>) {
        info!("📝 Registering ZHTP handler: {}", path);
        self.routes.insert(path, handler);
    }
    
    /// Add middleware to the processing chain
    pub fn add_middleware(&mut self, middleware: Arc<dyn Middleware>) {
        info!("🔧 Adding ZHTP middleware: {}", middleware.name());
        self.middleware.push(middleware);
    }
    
    /// Handle a native ZHTP request over QUIC stream
    pub async fn handle_zhtp_stream(
        &self,
        mut recv: RecvStream,
        mut send: SendStream,
    ) -> Result<()> {
        debug!("📨 Processing native ZHTP request over QUIC");

        // Read request data from QUIC stream
        let request_data = recv.read_to_end(super::serialization::MAX_MESSAGE_SIZE)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read ZHTP request from QUIC stream: {}", e))?;

        self.handle_zhtp_request_data(request_data, send).await
    }

    /// Handle ZHTP request with already-read prefix data
    pub async fn handle_zhtp_stream_with_prefix(
        &self,
        prefix: Vec<u8>,
        mut recv: RecvStream,
        send: SendStream,
    ) -> Result<()> {
        debug!("📨 Processing native ZHTP request with {} byte prefix", prefix.len());

        // Read remaining data
        let remaining = recv.read_to_end(super::serialization::MAX_MESSAGE_SIZE)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read remaining ZHTP data: {}", e))?;

        // Combine prefix with remaining data
        let mut request_data = prefix;
        request_data.extend(remaining);

        self.handle_zhtp_request_data(request_data, send).await
    }

    /// Internal: process ZHTP request data and send response
    async fn handle_zhtp_request_data(
        &self,
        request_data: Vec<u8>,
        mut send: SendStream,
    ) -> Result<()> {
        if request_data.is_empty() {
            warn!("⚠️ Empty ZHTP request received");
            return Ok(());
        }

        debug!("📦 Received {} bytes of ZHTP request data", request_data.len());
        
        // Deserialize ZHTP request
        let request = match deserialize_request(&request_data) {
            Ok(req) => req,
            Err(e) => {
                warn!("❌ Failed to deserialize ZHTP request: {}", e);
                let error_response = ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid ZHTP request: {}", e),
                );
                let response_data = serialize_response(&error_response)?;
                send.write_all(&response_data).await
                    .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
                send.finish()
                    .map_err(|e| anyhow::anyhow!("Finish error: {}", e))?;
                return Ok(());
            }
        };
        
        info!("✅ ZHTP {} {}", request.method, request.uri);
        
        // Process middleware
        let (processed_request, middleware_response) = self.process_middleware(request).await?;
        
        // If middleware returned a response, use it
        let response = if let Some(middleware_resp) = middleware_response {
            middleware_resp
        } else {
            // Route to handler
            match self.route_request(processed_request).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("❌ Handler error: {}", e);
                    ZhtpResponse::error(
                        ZhtpStatus::InternalServerError,
                        format!("Handler error: {}", e),
                    )
                }
            }
        };
        
        debug!("📤 Sending ZHTP response: {:?}", response.status);
        
        // Serialize response
        let response_data = serialize_response(&response)
            .map_err(|e| anyhow::anyhow!("Failed to serialize ZHTP response: {}", e))?;
        
        // Send response over QUIC stream
        send.write_all(&response_data).await
            .map_err(|e| anyhow::anyhow!("Failed to write ZHTP response to QUIC stream: {}", e))?;
        
        send.finish()
            .map_err(|e| anyhow::anyhow!("Failed to finish QUIC stream: {}", e))?;
        
        info!("✅ ZHTP response sent successfully");
        Ok(())
    }
    
    /// Route a ZHTP request to the appropriate handler
    pub async fn route_request(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let path = &request.uri;
        
        // Try exact match first
        if let Some(handler) = self.routes.get(path) {
            debug!("🎯 Exact route match: {}", path);
            return handler.handle_request(request).await;
        }
        
        // Try prefix matching for API routes
        for (route_path, handler) in &self.routes {
            if path.starts_with(route_path) {
                debug!("🎯 Prefix route match: {} → {}", path, route_path);
                return handler.handle_request(request).await;
            }
        }
        
        // No handler found
        warn!("❓ No handler found for path: {}", path);
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotFound,
            format!("No handler registered for path: {}", path),
        ))
    }
    
    /// Process middleware chain
    async fn process_middleware(
        &self,
        mut request: ZhtpRequest,
    ) -> Result<(ZhtpRequest, Option<ZhtpResponse>)> {
        let mut response: Option<ZhtpResponse> = None;
        
        for middleware in &self.middleware {
            match middleware.process(&mut request, &mut response).await {
                Ok(true) => continue, // Continue to next middleware
                Ok(false) => break,   // Middleware stopped processing
                Err(e) => {
                    warn!("⚠️ Middleware '{}' error: {}", middleware.name(), e);
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
    
    /// Get list of registered routes
    pub fn get_routes(&self) -> Vec<String> {
        self.routes.keys().cloned().collect()
    }
}

impl Clone for ZhtpRouter {
    fn clone(&self) -> Self {
        Self {
            routes: self.routes.clone(),
            middleware: self.middleware.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_protocols::types::{ZhtpMethod, ZhtpHeaders};
    
    // Mock handler for testing
    struct MockHandler;
    
    #[async_trait::async_trait]
    impl ZhtpRequestHandler for MockHandler {
        async fn handle_request(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
            Ok(ZhtpResponse::success(b"test response".to_vec(), None))
        }

        fn can_handle(&self, request: &ZhtpRequest) -> bool {
            request.uri.starts_with("/test")
        }

        fn priority(&self) -> u32 {
            100
        }
    }
    
    #[tokio::test]
    async fn test_route_registration() {
        let mut router = ZhtpRouter::new();
        router.register_handler("/test".to_string(), Arc::new(MockHandler));
        
        let routes = router.get_routes();
        assert_eq!(routes.len(), 1);
        assert!(routes.contains(&"/test".to_string()));
    }
    
    #[tokio::test]
    async fn test_exact_route_match() {
        let mut router = ZhtpRouter::new();
        router.register_handler("/api/test".to_string(), Arc::new(MockHandler));
        
        let request = ZhtpRequest {
            method: ZhtpMethod::Get,
            uri: "/api/test".to_string(),
            headers: ZhtpHeaders::new(),
            body: vec![],
            timestamp: 0,
            version: "1.0".to_string(),
            requester: None,
            auth_proof: None,
        };
        
        let response = router.route_request(request).await.unwrap();
        assert_eq!(response.status, ZhtpStatus::Ok);
    }
    
    #[tokio::test]
    async fn test_prefix_route_match() {
        let mut router = ZhtpRouter::new();
        router.register_handler("/api".to_string(), Arc::new(MockHandler));
        
        let request = ZhtpRequest {
            method: ZhtpMethod::Get,
            uri: "/api/v1/test".to_string(),
            headers: ZhtpHeaders::new(),
            body: vec![],
            timestamp: 0,
            version: "1.0".to_string(),
            requester: None,
            auth_proof: None,
        };
        
        let response = router.route_request(request).await.unwrap();
        assert_eq!(response.status, ZhtpStatus::Ok);
    }
    
    #[tokio::test]
    async fn test_no_route_match() {
        let router = ZhtpRouter::new();
        
        let request = ZhtpRequest {
            method: ZhtpMethod::Get,
            uri: "/nonexistent".to_string(),
            headers: ZhtpHeaders::new(),
            body: vec![],
            timestamp: 0,
            version: "1.0".to_string(),
            requester: None,
            auth_proof: None,
        };
        
        let response = router.route_request(request).await.unwrap();
        assert_eq!(response.status, ZhtpStatus::NotFound);
    }
}
