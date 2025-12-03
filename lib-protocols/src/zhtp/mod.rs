//! ZHTP v1.0 Protocol Core - HTTP Replacement
//! 
//! Complete implementation of the Zero Knowledge Hypertext Transfer Protocol,
//! designed as a replacement for HTTP with built-in economic
//! incentives, zero-knowledge privacy, and post-quantum security.

pub mod server;
pub mod config;
pub mod access_control;
pub mod routing;
pub mod content;
pub mod middleware;
pub mod session;

// Re-export commonly used types
pub use server::{ZhtpServer, ServerState};
pub use config::ServerConfig;
pub use access_control::AccessController;
pub use routing::{Router, Route, RouteHandler};
pub use content::{ZhtpContentManager, ContentConfig, StorageBackend, CompressionType, EncryptionType};
pub use session::{ZhtpSessionManager, SessionConfig, SessionInfo, AuthMethod, SecurityLevel};

use crate::types::{ZhtpRequest, ZhtpResponse};

/// ZHTP protocol version
pub const ZHTP_VERSION: &str = "1.0";

/// Default ZHTP port
pub const DEFAULT_ZHTP_PORT: u16 = 9333;

/// Maximum request size (16MB)
pub const MAX_REQUEST_SIZE: usize = 16 * 1024 * 1024;

/// Default request timeout (30 seconds)
pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;

/// ZHTP protocol result type
pub type ZhtpResult<T> = anyhow::Result<T>;

/// ZHTP request handler trait
#[async_trait::async_trait]
pub trait ZhtpRequestHandler: Send + Sync {
    /// Handle ZHTP request
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse>;
    
    /// Check if handler can process the request
    fn can_handle(&self, request: &ZhtpRequest) -> bool;
    
    /// Get handler priority (higher priority handlers are checked first)
    fn priority(&self) -> u32 {
        100
    }
}

/// ZHTP middleware trait
#[async_trait::async_trait]
pub trait ZhtpMiddleware: Send + Sync {
    /// Process request before handling
    async fn before_request(&self, request: &mut ZhtpRequest) -> ZhtpResult<()>;
    
    /// Process response after handling
    async fn after_response(&self, response: &mut ZhtpResponse) -> ZhtpResult<()>;
    
    /// Handle errors
    async fn on_error(&self, error: &anyhow::Error) -> ZhtpResult<Option<ZhtpResponse>> {
        Ok(None)
    }
}

/// ZHTP server lifecycle events
#[async_trait::async_trait]
pub trait ZhtpServerEvents: Send + Sync {
    /// Called when server starts
    async fn on_start(&self) -> ZhtpResult<()> {
        Ok(())
    }
    
    /// Called when server stops
    async fn on_stop(&self) -> ZhtpResult<()> {
        Ok(())
    }
    
    /// Called when request is received
    async fn on_request(&self, request: &ZhtpRequest) -> ZhtpResult<()> {
        Ok(())
    }
    
    /// Called when response is sent
    async fn on_response(&self, response: &ZhtpResponse) -> ZhtpResult<()> {
        Ok(())
    }
    
    /// Called when error occurs
    async fn on_error(&self, error: &anyhow::Error) -> ZhtpResult<()> {
        Ok(())
    }
}

/// ZHTP server capabilities
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerCapabilities {
    /// Supported ZHTP version
    pub lib_version: String,
    /// Maximum request size
    pub max_request_size: usize,
    /// Supported content types
    pub supported_content_types: Vec<String>,
    /// Supported encodings
    pub supported_encodings: Vec<String>,
    /// Zero-knowledge proof support
    pub zk_proof_support: bool,
    /// Post-quantum cryptography support
    pub post_quantum_support: bool,
    /// Mesh networking support
    pub mesh_support: bool,
    ///  capability
    pub isp_bypass_support: bool,
    /// DAO fee processing
    pub dao_fee_support: bool,
    /// UBI integration
    pub ubi_support: bool,
    /// Economic incentive processing
    pub economic_support: bool,
    /// Identity management integration
    pub identity_support: bool,
    /// Storage system integration
    pub storage_support: bool,
    /// Custom capabilities
    pub custom_capabilities: std::collections::HashMap<String, String>,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            lib_version: ZHTP_VERSION.to_string(),
            max_request_size: MAX_REQUEST_SIZE,
            supported_content_types: vec![
                "text/plain".to_string(),
                "text/html".to_string(),
                "application/json".to_string(),
                "application/octet-stream".to_string(),
                "application/x-zhtp".to_string(),
            ],
            supported_encodings: vec![
                "identity".to_string(),
                "gzip".to_string(),
                "deflate".to_string(),
                "br".to_string(),
            ],
            zk_proof_support: true,
            post_quantum_support: true,
            mesh_support: true,
            isp_bypass_support: true,
            dao_fee_support: true,
            ubi_support: true,
            economic_support: true,
            identity_support: true,
            storage_support: true,
            custom_capabilities: std::collections::HashMap::new(),
        }
    }
}

impl ServerCapabilities {
    /// Check if server supports given content type
    pub fn supports_content_type(&self, content_type: &str) -> bool {
        self.supported_content_types.iter().any(|ct| ct == content_type)
    }
    
    /// Check if server supports given encoding
    pub fn supports_encoding(&self, encoding: &str) -> bool {
        self.supported_encodings.iter().any(|enc| enc == encoding)
    }
    
    /// Add custom capability
    pub fn add_capability(&mut self, name: String, value: String) {
        self.custom_capabilities.insert(name, value);
    }
    
    /// Get capabilities as ZHTP response
    pub fn to_response(&self) -> ZhtpResult<ZhtpResponse> {
        let capabilities_json = serde_json::to_vec(self)?;
        Ok(ZhtpResponse::success_with_content_type(
            capabilities_json,
            "application/json".to_string(),
            None,
        ))
    }
}

/// Initialize ZHTP protocol subsystem
pub async fn initialize() -> ZhtpResult<()> {
    tracing::info!(" Initializing ZHTP v{} Protocol", ZHTP_VERSION);
    tracing::info!("Zero Knowledge Hypertext Transfer Protocol Ready");
    tracing::info!("Post-quantum cryptography enabled");
    tracing::info!("DAO fee system active");
    tracing::info!(" capabilities ready");
    Ok(())
}

/// Get default ZHTP server configuration
pub fn default_config() -> ServerConfig {
    ServerConfig::default()
}

/// Create a simple ZHTP response for testing
pub fn create_test_response(body: &str) -> ZhtpResponse {
    ZhtpResponse::text(body.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_capabilities() {
        let mut caps = ServerCapabilities::default();
        assert!(caps.supports_content_type("application/json"));
        assert!(caps.supports_encoding("gzip"));
        assert!(caps.zk_proof_support);
        assert!(caps.post_quantum_support);
        
        caps.add_capability("custom".to_string(), "value".to_string());
        assert_eq!(caps.custom_capabilities.get("custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_constants() {
        assert_eq!(ZHTP_VERSION, "1.0");
        assert_eq!(DEFAULT_ZHTP_PORT, 9333);
        assert_eq!(MAX_REQUEST_SIZE, 16 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_initialization() {
        let result = initialize().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_config() {
        let config = default_config();
        assert_eq!(config.port, DEFAULT_ZHTP_PORT);
    }

    #[test]
    fn test_create_test_response() {
        let response = create_test_response("Hello, ZHTP!");
        assert_eq!(response.status, ZhtpStatus::Ok);
        assert_eq!(response.body_as_string().unwrap(), "Hello, ZHTP!");
    }
}
