//! ZHTP Router - Native Request Routing Over QUIC
//!
//! Routes ZHTP requests directly from QUIC streams to registered handlers.
//! No HTTP parsing or conversion - pure ZHTP protocol.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;
use quinn::{RecvStream, SendStream};

use super::super::http::middleware::Middleware;
use super::serialization::{
    deserialize_request_with_format, serialize_response_with_format, PayloadFormat,
};

/// Strip trailing slash(es) from a request URI's path component in place.
///
/// `/api/v1/wallet/list/abc/`  → `/api/v1/wallet/list/abc`
/// `/api/v1/foo/?x=1`          → `/api/v1/foo?x=1`
/// `/`                         → `/`   (root is left intact)
///
/// Idempotent and query-string aware. Collapses multiple trailing slashes.
fn normalize_request_uri(uri: &mut String) {
    // Split off the query string so it is never touched.
    let (path, query) = match uri.find('?') {
        Some(i) => (uri[..i].to_string(), uri[i..].to_string()),
        None => (uri.clone(), String::new()),
    };
    // Never strip the lone root "/".
    let trimmed = path.trim_end_matches('/');
    let trimmed = if trimmed.is_empty() { "/" } else { trimmed };
    if trimmed.len() != path.len() {
        *uri = format!("{}{}", trimmed, query);
    }
}

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
    pub async fn handle_zhtp_stream(&self, mut recv: RecvStream, send: SendStream) -> Result<()> {
        debug!("📨 Processing native ZHTP request over QUIC");

        // Read request data from QUIC stream
        let request_data = recv
            .read_to_end(super::serialization::MAX_MESSAGE_SIZE)
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
        debug!(
            "📨 Processing native ZHTP request with {} byte prefix",
            prefix.len()
        );

        // Read remaining data
        let remaining = recv
            .read_to_end(super::serialization::MAX_MESSAGE_SIZE)
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

        debug!(
            "📦 Received {} bytes of ZHTP request data",
            request_data.len()
        );

        // Deserialize ZHTP request with format detection
        let (request, request_format) = match deserialize_request_with_format(&request_data) {
            Ok((req, fmt)) => {
                debug!("📦 Request format detected: {:?}", fmt);
                (req, fmt)
            }
            Err(e) => {
                warn!("❌ Failed to deserialize ZHTP request: {}", e);
                let error_response = ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid ZHTP request: {}", e),
                );
                // Default to CBOR for error responses when we can't detect format
                let response_data =
                    serialize_response_with_format(&error_response, PayloadFormat::Cbor)?;
                send.write_all(&response_data)
                    .await
                    .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
                send.finish()
                    .map_err(|e| anyhow::anyhow!("Finish error: {}", e))?;
                return Ok(());
            }
        };

        info!(
            "✅ ZHTP {} {} (format: {:?})",
            request.method, request.uri, request_format
        );

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

        debug!(
            "📤 Sending ZHTP response: {:?} (format: {:?})",
            response.status, request_format
        );

        // Serialize response in the same format as the request
        let response_data = serialize_response_with_format(&response, request_format)
            .map_err(|e| anyhow::anyhow!("Failed to serialize ZHTP response: {}", e))?;

        // Send response over QUIC stream
        send.write_all(&response_data)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to write ZHTP response to QUIC stream: {}", e))?;

        send.finish()
            .map_err(|e| anyhow::anyhow!("Failed to finish QUIC stream: {}", e))?;

        info!(
            "✅ ZHTP response sent successfully (format: {:?})",
            request_format
        );
        Ok(())
    }

    /// Handle ZHTP stream with BufferedStream (for protocol detection compatibility)
    pub async fn handle_zhtp_stream_buffered(
        &self,
        buffered: &mut crate::server::quic_handler::BufferedStream,
        mut send: SendStream,
    ) -> Result<()> {
        debug!("📨 Processing native ZHTP request over QUIC (buffered stream)");

        // Read request data from buffered stream
        let request_data = buffered
            .read_to_end(super::serialization::MAX_MESSAGE_SIZE)
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to read ZHTP request from buffered stream: {}", e)
            })?;

        if request_data.is_empty() {
            warn!("⚠️ Empty ZHTP request received");
            return Ok(());
        }

        debug!(
            "📦 Received {} bytes of ZHTP request data",
            request_data.len()
        );

        // Deserialize ZHTP request with format detection
        let (request, request_format) = match deserialize_request_with_format(&request_data) {
            Ok((req, fmt)) => {
                debug!("📦 Request format detected: {:?}", fmt);
                (req, fmt)
            }
            Err(e) => {
                warn!("❌ Failed to deserialize ZHTP request: {}", e);
                let error_response = ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid ZHTP request: {}", e),
                );
                let response_data =
                    serialize_response_with_format(&error_response, PayloadFormat::Cbor)?;
                send.write_all(&response_data)
                    .await
                    .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
                send.finish()
                    .map_err(|e| anyhow::anyhow!("Finish error: {}", e))?;
                return Ok(());
            }
        };

        info!(
            "✅ ZHTP {} {} (format: {:?})",
            request.method, request.uri, request_format
        );

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

        debug!(
            "📤 Sending ZHTP response: {:?} (format: {:?})",
            response.status, request_format
        );

        // Serialize response in the same format as the request
        let response_data = serialize_response_with_format(&response, request_format)
            .map_err(|e| anyhow::anyhow!("Failed to serialize ZHTP response: {}", e))?;

        // Send response over QUIC stream
        send.write_all(&response_data)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to write ZHTP response to QUIC stream: {}", e))?;

        send.finish()
            .map_err(|e| anyhow::anyhow!("Failed to finish QUIC stream: {}", e))?;

        info!(
            "✅ ZHTP response sent successfully (format: {:?})",
            request_format
        );
        Ok(())
    }

    /// Handle authenticated ZHTP stream from control plane connection
    /// The session contains authentication context from UHP+Kyber handshake
    pub async fn handle_authenticated_zhtp_stream(
        &self,
        buffered: &mut crate::server::quic_handler::BufferedStream,
        mut send: SendStream,
        session: &lib_network::protocols::types::session::V2Session,
    ) -> Result<()> {
        debug!(
            "📨 Processing authenticated ZHTP request from {}",
            session.peer_did()
        );

        // Read request data from buffered stream
        let request_data = buffered
            .read_to_end(super::serialization::MAX_MESSAGE_SIZE)
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to read ZHTP request from buffered stream: {}", e)
            })?;

        if request_data.is_empty() {
            warn!("⚠️ Empty ZHTP request received from authenticated session");
            return Ok(());
        }

        debug!(
            "📦 Received {} bytes of authenticated ZHTP request data",
            request_data.len()
        );

        // Deserialize ZHTP request with format detection
        let (mut request, request_format) = match deserialize_request_with_format(&request_data) {
            Ok((req, fmt)) => {
                debug!("📦 Request format detected: {:?}", fmt);
                (req, fmt)
            }
            Err(e) => {
                warn!(
                    "❌ Failed to deserialize ZHTP request from {}: {}",
                    session.peer_did(),
                    e
                );
                let error_response = ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid ZHTP request: {}", e),
                );
                let response_data =
                    serialize_response_with_format(&error_response, PayloadFormat::Cbor)?;
                send.write_all(&response_data)
                    .await
                    .map_err(|e| anyhow::anyhow!("Write error: {}", e))?;
                send.finish()
                    .map_err(|e| anyhow::anyhow!("Finish error: {}", e))?;
                return Ok(());
            }
        };

        // Add authenticated requester identity to request context
        // IdentityId is a Hash of the DID
        request.requester = Some(lib_crypto::Hash(lib_crypto::hash_blake3(
            session.peer_did().as_bytes(),
        )));

        info!(
            "✅ Authenticated ZHTP {} {} from {} (format: {:?})",
            request.method,
            request.uri,
            session.peer_did(),
            request_format
        );

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
                    warn!("❌ Handler error for authenticated request: {}", e);
                    ZhtpResponse::error(
                        ZhtpStatus::InternalServerError,
                        format!("Handler error: {}", e),
                    )
                }
            }
        };

        debug!(
            "📤 Sending authenticated ZHTP response: {:?} (format: {:?})",
            response.status, request_format
        );

        // Serialize response in the same format as the request
        let response_data = serialize_response_with_format(&response, request_format)
            .map_err(|e| anyhow::anyhow!("Failed to serialize ZHTP response: {}", e))?;

        // Send response over QUIC stream
        send.write_all(&response_data)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to write ZHTP response to QUIC stream: {}", e))?;

        send.finish()
            .map_err(|e| anyhow::anyhow!("Failed to finish QUIC stream: {}", e))?;

        info!(
            "✅ Authenticated ZHTP response sent to {} (format: {:?})",
            session.peer_did(),
            request_format
        );
        Ok(())
    }

    /// Route a ZHTP request to the appropriate handler
    pub async fn route_request(&self, mut request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Canonicalize the URI: strip trailing slash(es) from the path.
        // Path-parameter routes (e.g. /api/v1/wallet/list/<hex-id>) must not
        // depend on a trailing slash — a client that appends one would feed
        // the '/' straight into hex::decode and trigger a 500
        // ("Odd number of digits"). Normalize ONCE here, at the single
        // dispatch funnel, so every handler — and every handler's own
        // internal uri match — sees the canonical form. The query string,
        // if any, is preserved.
        normalize_request_uri(&mut request.uri);

        // S5 #2559 — default-deny for Password (OPAQUE lobby) sessions.
        // Key (Dilithium) sessions and unauthenticated requests bypass this
        // gate; only Password sessions are constrained to the allowlist.
        if crate::session_manager::is_request_password_session(&request).await
            && !super::lobby_acl::is_lobby_allowed(&request.method, &request.uri)
        {
            warn!(
                "🔒 lobby session blocked from {} {} (not in allowlist)",
                request.method.as_str(),
                request.uri
            );
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Forbidden,
                "Forbidden — lobby session".to_string(),
            ));
        }

        let path = &request.uri;

        // Try exact match first
        if let Some(handler) = self.routes.get(path) {
            debug!("🎯 Exact route match: {}", path);
            return handler.handle_request(request).await;
        }

        // Try prefix matching for API routes - LONGEST PREFIX FIRST
        // This ensures /api/v1/blockchain/sync matches before /api/v1/blockchain
        let mut matching_routes: Vec<(&String, &Arc<dyn ZhtpRequestHandler>)> = self
            .routes
            .iter()
            .filter(|(route_path, _)| path.starts_with(route_path.as_str()))
            .collect();

        // Sort by route path length descending (longest first)
        matching_routes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        if let Some((route_path, handler)) = matching_routes.first() {
            debug!("🎯 Prefix route match: {} → {}", path, route_path);
            return handler.handle_request(request).await;
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
    use lib_protocols::types::{ZhtpHeaders, ZhtpMethod};

    fn norm(s: &str) -> String {
        let mut u = s.to_string();
        normalize_request_uri(&mut u);
        u
    }

    #[test]
    fn normalize_strips_single_trailing_slash() {
        assert_eq!(
            norm("/api/v1/wallet/list/abc123"),
            "/api/v1/wallet/list/abc123"
        );
        assert_eq!(
            norm("/api/v1/wallet/list/abc123/"),
            "/api/v1/wallet/list/abc123"
        );
    }

    #[test]
    fn normalize_collapses_multiple_trailing_slashes() {
        assert_eq!(norm("/api/v1/foo///"), "/api/v1/foo");
    }

    #[test]
    fn normalize_leaves_root_intact() {
        assert_eq!(norm("/"), "/");
        assert_eq!(norm("//"), "/");
    }

    #[test]
    fn normalize_preserves_query_string() {
        assert_eq!(norm("/api/v1/foo/?x=1"), "/api/v1/foo?x=1");
        assert_eq!(norm("/api/v1/foo?x=1"), "/api/v1/foo?x=1");
        // A slash inside the query value must NOT be touched.
        assert_eq!(norm("/api/v1/foo/?path=a/b/"), "/api/v1/foo?path=a/b/");
    }

    #[test]
    fn normalize_is_idempotent() {
        let once = norm("/api/v1/wallet/list/abc/");
        assert_eq!(norm(&once), once);
    }

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
