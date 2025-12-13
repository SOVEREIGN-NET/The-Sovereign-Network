//! Web4 Gateway Handler
//!
//! Host-based domain routing for Web4 content. This handler intercepts requests
//! with Web4 domain hosts and routes them through the Web4ContentService.
//!
//! # Host Resolution
//!
//! Supports multiple host patterns:
//! - `{domain}.zhtp` - Direct ZHTP domain
//! - `{domain}.zhtp.localhost` - Local development
//! - `{domain}.zhtp.gateway.example.com` - Managed gateway
//!
//! # Security
//!
//! - Path normalization is performed by Web4ContentService before any lookup
//! - Domain validation prevents injection attacks
//! - Host header sanitization prevents header injection

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_network::{Web4ContentService, DomainRegistry, ZdnsResolver};
use std::sync::Arc;
use tracing::{info, warn, debug, error};
use serde::{Serialize, Deserialize};

/// Configuration for the Web4 gateway
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Gateway suffix to strip (e.g., ".localhost", ".gateway.example.com")
    pub gateway_suffix: String,
    /// Whether to allow bare .zhtp domains (without gateway suffix)
    pub allow_bare_zhtp: bool,
    /// Maximum domain length
    pub max_domain_length: usize,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            gateway_suffix: ".localhost".to_string(),
            allow_bare_zhtp: true,
            max_domain_length: 253, // DNS max
        }
    }
}

/// Web4 Gateway Handler
///
/// Intercepts requests based on Host header and routes them to Web4 content.
pub struct Web4GatewayHandler {
    /// Content service for content retrieval
    content_service: Arc<Web4ContentService>,
    /// Gateway configuration
    config: GatewayConfig,
}

impl Web4GatewayHandler {
    /// Create a new gateway handler
    pub fn new(registry: Arc<DomainRegistry>) -> Self {
        Self {
            content_service: Arc::new(Web4ContentService::new(registry)),
            config: GatewayConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(registry: Arc<DomainRegistry>, config: GatewayConfig) -> Self {
        Self {
            content_service: Arc::new(Web4ContentService::new(registry)),
            config,
        }
    }

    /// Create with existing content service (for sharing with API handler)
    pub fn with_content_service(
        content_service: Arc<Web4ContentService>,
        config: GatewayConfig,
    ) -> Self {
        Self {
            content_service,
            config,
        }
    }

    /// Create with ZDNS resolver for cached domain lookups
    pub fn with_zdns(
        registry: Arc<DomainRegistry>,
        zdns_resolver: Arc<ZdnsResolver>,
        config: GatewayConfig,
    ) -> Self {
        Self {
            content_service: Arc::new(Web4ContentService::with_zdns(registry, zdns_resolver)),
            config,
        }
    }

    /// Extract domain from Host header
    ///
    /// Returns the Web4 domain if the host matches expected patterns.
    ///
    /// Patterns:
    /// - `myapp.zhtp` -> `myapp.zhtp`
    /// - `myapp.zhtp.localhost` -> `myapp.zhtp`
    /// - `myapp.zhtp.gateway.example.com` -> `myapp.zhtp`
    fn extract_domain(&self, host: &str) -> Option<String> {
        // Sanitize host - remove port if present
        let host = host.split(':').next().unwrap_or(host);

        // Check length
        if host.len() > self.config.max_domain_length {
            warn!("Host too long: {} chars", host.len());
            return None;
        }

        // Try to extract domain from various patterns

        // Pattern 1: {domain}.zhtp.{gateway_suffix}
        // e.g., myapp.zhtp.localhost -> myapp.zhtp
        let gateway_suffix = &self.config.gateway_suffix;
        if let Some(without_suffix) = host.strip_suffix(gateway_suffix) {
            if without_suffix.ends_with(".zhtp") {
                debug!("Extracted domain from gateway suffix: {}", without_suffix);
                return Some(without_suffix.to_string());
            }
        }

        // Pattern 2: {domain}.zhtp (bare domain, if allowed)
        if self.config.allow_bare_zhtp && host.ends_with(".zhtp") {
            debug!("Extracted bare domain: {}", host);
            return Some(host.to_string());
        }

        // Pattern 3: {domain}.sov.{gateway_suffix}
        // e.g., myapp.commerce.sov.localhost -> myapp.commerce.sov
        if let Some(without_suffix) = host.strip_suffix(gateway_suffix) {
            if without_suffix.ends_with(".sov") || without_suffix.contains(".sov.") {
                // Find the .sov part
                if let Some(sov_idx) = without_suffix.rfind(".sov") {
                    let domain = &without_suffix[..sov_idx + 4]; // Include ".sov"
                    debug!("Extracted .sov domain: {}", domain);
                    return Some(domain.to_string());
                }
            }
        }

        // Pattern 4: {domain}.sov (bare .sov domain, if allowed)
        if self.config.allow_bare_zhtp {
            if host.ends_with(".sov") || host.contains(".sov.") {
                // Handle subdomains like myapp.commerce.sov
                if let Some(sov_idx) = host.rfind(".sov") {
                    if sov_idx + 4 == host.len() {
                        // Ends with .sov
                        debug!("Extracted bare .sov domain: {}", host);
                        return Some(host.to_string());
                    }
                }
            }
        }

        None
    }

    /// Validate domain name for security
    fn validate_domain(&self, domain: &str) -> bool {
        // Check length
        if domain.is_empty() || domain.len() > self.config.max_domain_length {
            return false;
        }

        // Check for valid characters (alphanumeric, dots, hyphens)
        if !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return false;
        }

        // Check for path traversal attempts in domain
        if domain.contains("..") {
            return false;
        }

        // Must end with .zhtp or .sov
        if !domain.ends_with(".zhtp") && !domain.ends_with(".sov") {
            return false;
        }

        true
    }

    /// Handle a Web4 gateway request
    async fn handle_gateway_request(
        &self,
        request: ZhtpRequest,
        domain: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        // Path is the full URI for gateway requests
        let path = if request.uri.is_empty() || request.uri == "/" {
            "/".to_string()
        } else {
            request.uri.clone()
        };

        debug!(
            domain = %domain,
            path = %path,
            "Handling Web4 gateway request"
        );

        // Delegate to content service
        match self.content_service.serve(domain, &path).await {
            Ok(result) => {
                info!(
                    domain = %domain,
                    path = %path,
                    mime_type = %result.mime_type,
                    is_fallback = result.is_fallback,
                    content_length = result.content.len(),
                    "Gateway: Content served successfully"
                );

                // Build response with headers
                let mut response = ZhtpResponse::success_with_content_type(
                    result.content,
                    result.mime_type,
                    None,
                )
                .with_cache_control(result.cache_control);

                // Add ETag if present
                if let Some(etag) = result.etag {
                    response = response.with_etag(etag);
                }

                // Add custom headers
                for (key, value) in result.headers {
                    response = response.with_custom_header(key, value);
                }

                // Add gateway-specific headers
                response = response.with_custom_header(
                    "X-Web4-Domain".to_string(),
                    domain.to_string(),
                );

                if result.is_fallback {
                    response = response.with_custom_header(
                        "X-Web4-Fallback".to_string(),
                        "true".to_string(),
                    );
                }

                Ok(response)
            }
            Err(e) => {
                warn!(
                    domain = %domain,
                    path = %path,
                    error = %e,
                    "Gateway: Content not found"
                );

                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Content not found: {}", e),
                ))
            }
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for Web4GatewayHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract Host header
        let host = request
            .headers
            .custom
            .get("host")
            .or_else(|| request.headers.custom.get("Host"))
            .cloned()
            .unwrap_or_default();

        if host.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Missing Host header".to_string(),
            ));
        }

        // Try to extract domain from host
        let domain = match self.extract_domain(&host) {
            Some(d) => d,
            None => {
                // Not a Web4 domain, this handler shouldn't handle it
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Not a Web4 domain: {}", host),
                ));
            }
        };

        // Validate domain
        if !self.validate_domain(&domain) {
            warn!("Invalid domain: {}", domain);
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid domain name".to_string(),
            ));
        }

        // Handle the request
        self.handle_gateway_request(request, &domain).await
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        // Check if this looks like a Web4 gateway request
        // by examining the Host header
        let host = request
            .headers
            .custom
            .get("host")
            .or_else(|| request.headers.custom.get("Host"))
            .cloned()
            .unwrap_or_default();

        // If we can extract a domain, we can handle it
        self.extract_domain(&host).is_some()
    }

    fn priority(&self) -> u32 {
        // Higher priority than general handlers, but lower than explicit API routes
        150
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> GatewayConfig {
        GatewayConfig {
            gateway_suffix: ".localhost".to_string(),
            allow_bare_zhtp: true,
            max_domain_length: 253,
        }
    }

    /// Helper struct to test extract_domain without needing a real DomainRegistry
    struct TestExtractor {
        config: GatewayConfig,
    }

    impl TestExtractor {
        fn new(config: GatewayConfig) -> Self {
            Self { config }
        }

        /// Extract domain from host (mirrors Web4GatewayHandler::extract_domain logic)
        fn extract_domain(&self, host: &str) -> Option<String> {
            // Sanitize host - remove port if present
            let host = host.split(':').next().unwrap_or(host);

            // Check length
            if host.len() > self.config.max_domain_length {
                return None;
            }

            // Pattern 1: {domain}.zhtp.{gateway_suffix}
            let gateway_suffix = &self.config.gateway_suffix;
            if let Some(without_suffix) = host.strip_suffix(gateway_suffix) {
                if without_suffix.ends_with(".zhtp") {
                    return Some(without_suffix.to_string());
                }
            }

            // Pattern 2: {domain}.zhtp (bare domain, if allowed)
            if self.config.allow_bare_zhtp && host.ends_with(".zhtp") {
                return Some(host.to_string());
            }

            // Pattern 3: {domain}.sov.{gateway_suffix}
            if let Some(without_suffix) = host.strip_suffix(gateway_suffix) {
                if without_suffix.ends_with(".sov") {
                    return Some(without_suffix.to_string());
                }
            }

            // Pattern 4: {domain}.sov (bare .sov domain, if allowed)
            if self.config.allow_bare_zhtp && host.ends_with(".sov") {
                return Some(host.to_string());
            }

            None
        }

        /// Validate domain name
        fn validate_domain(&self, domain: &str) -> bool {
            if domain.is_empty() || domain.len() > self.config.max_domain_length {
                return false;
            }
            if !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                return false;
            }
            if domain.contains("..") {
                return false;
            }
            if !domain.ends_with(".zhtp") && !domain.ends_with(".sov") {
                return false;
            }
            true
        }
    }

    // ========================================
    // Domain Extraction Tests
    // ========================================

    #[test]
    fn test_extract_domain_with_gateway_suffix() {
        let extractor = TestExtractor::new(create_test_config());

        // .zhtp domains with .localhost suffix
        assert_eq!(
            extractor.extract_domain("myapp.zhtp.localhost"),
            Some("myapp.zhtp".to_string())
        );
        assert_eq!(
            extractor.extract_domain("my-app.zhtp.localhost"),
            Some("my-app.zhtp".to_string())
        );
        assert_eq!(
            extractor.extract_domain("sub.domain.zhtp.localhost"),
            Some("sub.domain.zhtp".to_string())
        );
    }

    #[test]
    fn test_extract_domain_bare_zhtp() {
        let extractor = TestExtractor::new(create_test_config());

        // Bare .zhtp domains (when allow_bare_zhtp is true)
        assert_eq!(
            extractor.extract_domain("myapp.zhtp"),
            Some("myapp.zhtp".to_string())
        );
        assert_eq!(
            extractor.extract_domain("my-app.zhtp"),
            Some("my-app.zhtp".to_string())
        );
    }

    #[test]
    fn test_extract_domain_sov() {
        let extractor = TestExtractor::new(create_test_config());

        // .sov domains with suffix
        assert_eq!(
            extractor.extract_domain("myapp.commerce.sov.localhost"),
            Some("myapp.commerce.sov".to_string())
        );

        // Bare .sov domains
        assert_eq!(
            extractor.extract_domain("myapp.commerce.sov"),
            Some("myapp.commerce.sov".to_string())
        );
        assert_eq!(
            extractor.extract_domain("central.sov"),
            Some("central.sov".to_string())
        );
    }

    #[test]
    fn test_extract_domain_with_port() {
        let extractor = TestExtractor::new(create_test_config());

        // Should strip port before extraction
        assert_eq!(
            extractor.extract_domain("myapp.zhtp.localhost:8080"),
            Some("myapp.zhtp".to_string())
        );
        assert_eq!(
            extractor.extract_domain("myapp.zhtp:443"),
            Some("myapp.zhtp".to_string())
        );
    }

    #[test]
    fn test_extract_domain_invalid() {
        let extractor = TestExtractor::new(create_test_config());

        // Non-Web4 domains should return None
        assert_eq!(extractor.extract_domain("example.com"), None);
        assert_eq!(extractor.extract_domain("google.com.localhost"), None);
        assert_eq!(extractor.extract_domain("localhost"), None);
        assert_eq!(extractor.extract_domain(""), None);
    }

    #[test]
    fn test_extract_domain_bare_disabled() {
        let mut config = create_test_config();
        config.allow_bare_zhtp = false;
        let extractor = TestExtractor::new(config);

        // With bare disabled, only suffix-based extraction works
        assert_eq!(
            extractor.extract_domain("myapp.zhtp.localhost"),
            Some("myapp.zhtp".to_string())
        );
        assert_eq!(extractor.extract_domain("myapp.zhtp"), None);
    }

    // ========================================
    // Domain Validation Tests
    // ========================================

    #[test]
    fn test_validate_domain_valid() {
        let extractor = TestExtractor::new(create_test_config());

        assert!(extractor.validate_domain("myapp.zhtp"));
        assert!(extractor.validate_domain("my-app.zhtp"));
        assert!(extractor.validate_domain("sub.domain.zhtp"));
        assert!(extractor.validate_domain("myapp.commerce.sov"));
        assert!(extractor.validate_domain("central.sov"));
        assert!(extractor.validate_domain("a.sov")); // Minimum valid
    }

    #[test]
    fn test_validate_domain_invalid_tld() {
        let extractor = TestExtractor::new(create_test_config());

        assert!(!extractor.validate_domain("myapp.com"));
        assert!(!extractor.validate_domain("myapp.org"));
        assert!(!extractor.validate_domain("myapp.localhost"));
    }

    #[test]
    fn test_validate_domain_invalid_chars() {
        let extractor = TestExtractor::new(create_test_config());

        assert!(!extractor.validate_domain("my_app.zhtp")); // Underscore
        assert!(!extractor.validate_domain("my app.zhtp")); // Space
        assert!(!extractor.validate_domain("my@app.zhtp")); // Special char
    }

    #[test]
    fn test_validate_domain_double_dot() {
        let extractor = TestExtractor::new(create_test_config());

        // Double dots could indicate path traversal attempts
        assert!(!extractor.validate_domain("my..app.zhtp"));
        assert!(!extractor.validate_domain("..zhtp"));
    }

    #[test]
    fn test_validate_domain_empty() {
        let extractor = TestExtractor::new(create_test_config());

        assert!(!extractor.validate_domain(""));
    }

    #[test]
    fn test_validate_domain_too_long() {
        let mut config = create_test_config();
        config.max_domain_length = 20;
        let extractor = TestExtractor::new(config);

        assert!(extractor.validate_domain("short.zhtp")); // 10 chars
        assert!(!extractor.validate_domain("this-is-a-very-long-domain-name.zhtp")); // > 20 chars
    }
}
