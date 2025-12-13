//! HTTP Request Handlers for HTTPS Gateway
//!
//! Routes incoming HTTP requests to Web4 content via Web4ContentService.
//!
//! Note: HSTS headers are added via middleware in server.rs to ensure ALL
//! responses include Strict-Transport-Security, including /health endpoint.

use axum::{
    body::Body,
    extract::{Host, State},
    http::{header, Request, Response, StatusCode, Uri},
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{debug, info, warn};

use lib_network::{Web4ContentService, Web4Capability, ContentResult};

use super::config::GatewayTlsConfig;

/// Shared state for gateway handlers
#[derive(Clone)]
pub struct GatewayState {
    pub content_service: Arc<Web4ContentService>,
    pub config: Arc<GatewayTlsConfig>,
}

/// Extract domain from Host header based on gateway configuration
fn extract_domain(host: &str, config: &GatewayTlsConfig) -> Option<String> {
    // Remove port if present
    let host = host.split(':').next().unwrap_or(host);

    // Check length
    if host.len() > 253 {
        warn!("Host too long: {} chars", host.len());
        return None;
    }

    // Pattern 1: {domain}.zhtp.{gateway_suffix}
    // e.g., myapp.zhtp.gateway.example.com -> myapp.zhtp
    if !config.gateway_suffix.is_empty() {
        if let Some(without_suffix) = host.strip_suffix(&config.gateway_suffix) {
            if without_suffix.ends_with(".zhtp") {
                debug!("Extracted .zhtp domain from gateway suffix: {}", without_suffix);
                return Some(without_suffix.to_string());
            }
            if without_suffix.ends_with(".sov") || without_suffix.contains(".sov.") {
                if let Some(sov_idx) = without_suffix.rfind(".sov") {
                    if sov_idx + 4 == without_suffix.len() {
                        debug!("Extracted .sov domain from gateway suffix: {}", without_suffix);
                        return Some(without_suffix.to_string());
                    }
                }
            }
        }
    }

    // Pattern 2: Bare .zhtp/.sov domains (if allowed and DNS resolves to gateway)
    if config.allow_bare_sovereign_domains {
        if host.ends_with(".zhtp") {
            debug!("Extracted bare .zhtp domain: {}", host);
            return Some(host.to_string());
        }
        if host.ends_with(".sov") {
            debug!("Extracted bare .sov domain: {}", host);
            return Some(host.to_string());
        }
    }

    None
}

/// Validate domain name for security
fn validate_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // Only allow alphanumeric, dots, and hyphens
    if !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return false;
    }

    // No path traversal
    if domain.contains("..") {
        return false;
    }

    // Must be sovereign TLD
    if !domain.ends_with(".zhtp") && !domain.ends_with(".sov") {
        return false;
    }

    true
}

/// Main gateway handler for all Web4 content requests
/// Note: HSTS header is added by middleware in server.rs
pub async fn gateway_handler(
    State(state): State<GatewayState>,
    Host(host): Host,
    request: Request<Body>,
) -> impl IntoResponse {
    // Extract domain from host
    let domain = match extract_domain(&host, &state.config) {
        Some(d) => d,
        None => {
            // Not a Web4 domain - return landing page or 404
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                format!(
                    r#"<!DOCTYPE html>
<html>
<head><title>Web4 Gateway</title></head>
<body>
<h1>Web4 Gateway</h1>
<p>This is a Web4 HTTPS gateway. To access Web4 content, use a .zhtp or .sov domain.</p>
<p>Example: <code>https://myapp.zhtp{}</code></p>
</body>
</html>"#,
                    state.config.gateway_suffix
                ),
            ).into_response();
        }
    };

    // Validate domain
    if !validate_domain(&domain) {
        warn!("Invalid domain: {}", domain);
        return (
            StatusCode::BAD_REQUEST,
            "Invalid domain name",
        ).into_response();
    }

    // Get path from URI
    let path = request.uri().path().to_string();
    let path = if path.is_empty() { "/" } else { &path };

    debug!(domain = %domain, path = %path, "Handling Web4 gateway request");

    // Serve content via Web4ContentService
    match state.content_service.serve(&domain, path).await {
        Ok(result) => {
            info!(
                domain = %domain,
                path = %path,
                mime_type = %result.mime_type,
                is_fallback = result.is_fallback,
                content_length = result.content.len(),
                "Gateway: Content served successfully"
            );

            // Build response
            let mut response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, &result.mime_type)
                .header(header::CACHE_CONTROL, &result.cache_control)
                .header("X-Web4-Domain", &domain);

            // Add ETag if present
            if let Some(etag) = &result.etag {
                response = response.header(header::ETAG, etag);
            }

            // Add custom headers
            for (key, value) in &result.headers {
                response = response.header(key.as_str(), value.as_str());
            }

            // Add fallback indicator
            if result.is_fallback {
                response = response.header("X-Web4-Fallback", "true");
            }

            response
                .body(Body::from(result.content))
                .unwrap()
                .into_response()
        }
        Err(e) => {
            warn!(domain = %domain, path = %path, error = %e, "Gateway: Content not found");

            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                format!(
                    r#"<!DOCTYPE html>
<html>
<head><title>404 - Not Found</title></head>
<body>
<h1>404 - Content Not Found</h1>
<p>The requested path <code>{}</code> was not found on domain <code>{}</code>.</p>
<p>Error: {}</p>
</body>
</html>"#,
                    path, domain, e
                ),
            ).into_response()
        }
    }
}

/// HTTP to HTTPS redirect handler
pub async fn redirect_handler(
    Host(host): Host,
    uri: Uri,
    State(state): State<GatewayState>,
) -> impl IntoResponse {
    let https_port = state.config.https_port;

    // Build redirect URL
    let redirect_url = if https_port == 443 {
        format!("https://{}{}", host.split(':').next().unwrap_or(&host), uri.path())
    } else {
        format!("https://{}:{}{}", host.split(':').next().unwrap_or(&host), https_port, uri.path())
    };

    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, redirect_url)],
        "",
    )
}

/// Health check endpoint
pub async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Gateway info endpoint (returns JSON)
/// Note: HSTS header is added by middleware in server.rs
pub async fn info_handler(
    State(state): State<GatewayState>,
) -> impl IntoResponse {
    let info = serde_json::json!({
        "service": "web4-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "tls_mode": format!("{:?}", state.config.mode),
        "gateway_suffix": state.config.gateway_suffix,
        "allow_bare_domains": state.config.allow_bare_sovereign_domains,
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&info).unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> GatewayTlsConfig {
        GatewayTlsConfig {
            gateway_suffix: ".localhost".to_string(),
            allow_bare_sovereign_domains: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_extract_domain_with_suffix() {
        let config = default_config();

        assert_eq!(
            extract_domain("myapp.zhtp.localhost", &config),
            Some("myapp.zhtp".to_string())
        );
        assert_eq!(
            extract_domain("my-app.zhtp.localhost", &config),
            Some("my-app.zhtp".to_string())
        );
        assert_eq!(
            extract_domain("sub.domain.zhtp.localhost", &config),
            Some("sub.domain.zhtp".to_string())
        );
    }

    #[test]
    fn test_extract_domain_bare() {
        let config = default_config();

        assert_eq!(
            extract_domain("myapp.zhtp", &config),
            Some("myapp.zhtp".to_string())
        );
        assert_eq!(
            extract_domain("myapp.commerce.sov", &config),
            Some("myapp.commerce.sov".to_string())
        );
    }

    #[test]
    fn test_extract_domain_with_port() {
        let config = default_config();

        assert_eq!(
            extract_domain("myapp.zhtp.localhost:8443", &config),
            Some("myapp.zhtp".to_string())
        );
        assert_eq!(
            extract_domain("myapp.zhtp:443", &config),
            Some("myapp.zhtp".to_string())
        );
    }

    #[test]
    fn test_extract_domain_invalid() {
        let config = default_config();

        assert_eq!(extract_domain("example.com", &config), None);
        assert_eq!(extract_domain("google.com.localhost", &config), None);
        assert_eq!(extract_domain("localhost", &config), None);
    }

    #[test]
    fn test_extract_domain_bare_disabled() {
        let config = GatewayTlsConfig {
            gateway_suffix: ".localhost".to_string(),
            allow_bare_sovereign_domains: false,
            ..Default::default()
        };

        // With bare disabled, only suffix-based extraction works
        assert_eq!(
            extract_domain("myapp.zhtp.localhost", &config),
            Some("myapp.zhtp".to_string())
        );
        assert_eq!(extract_domain("myapp.zhtp", &config), None);
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("myapp.zhtp"));
        assert!(validate_domain("my-app.zhtp"));
        assert!(validate_domain("sub.domain.zhtp"));
        assert!(validate_domain("myapp.commerce.sov"));
        assert!(validate_domain("central.sov"));
    }

    #[test]
    fn test_validate_domain_invalid() {
        assert!(!validate_domain("myapp.com")); // Wrong TLD
        assert!(!validate_domain("my_app.zhtp")); // Underscore
        assert!(!validate_domain("my app.zhtp")); // Space
        assert!(!validate_domain("my..app.zhtp")); // Double dot
        assert!(!validate_domain("")); // Empty
    }

    #[test]
    fn test_validate_domain_too_long() {
        let long_domain = format!("{}.zhtp", "a".repeat(250));
        assert!(!validate_domain(&long_domain));
    }

    // Note: HSTS tests are now in server.rs since HSTS is handled via middleware
}
