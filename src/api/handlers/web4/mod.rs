//! Web4 API Handlers
//! 
//! Web4 domain registration and content publishing endpoints that integrate
//! with the existing ZHTP server infrastructure

pub mod domains;
pub mod content;

pub use domains::*;
pub use content::*;

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::zhtp::ZhtpRequestHandler;
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_network::Web4Manager;
use tracing::{info, error};

/// Web4 API handler that integrates with existing ZHTP server
pub struct Web4Handler {
    /// Web4 system manager
    web4_manager: Arc<RwLock<Web4Manager>>,
}

impl Web4Handler {
    /// Create new Web4 API handler
    pub async fn new() -> ZhtpResult<Self> {
        info!("Initializing Web4 API handler");
        
        let web4_manager = lib_network::initialize_web4_system().await
            .map_err(|e| anyhow::anyhow!("Failed to initialize Web4 system: {}", e))?;
        
        info!(" Web4 API handler initialized successfully");
        
        Ok(Self {
            web4_manager: Arc::new(RwLock::new(web4_manager)),
        })
    }

    /// Get reference to the Web4Manager for sharing with other handlers
    pub fn get_web4_manager(&self) -> Arc<RwLock<Web4Manager>> {
        Arc::clone(&self.web4_manager)
    }

    /// Get Web4 system statistics
    async fn get_web4_statistics(&self) -> ZhtpResult<ZhtpResponse> {
        let manager = self.web4_manager.read().await;
        
        match manager.registry.get_statistics().await {
            Ok(stats) => {
                let stats_json = serde_json::to_vec(&stats)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize statistics: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    stats_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to get Web4 statistics: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to retrieve Web4 statistics".to_string(),
                ))
            }
        }
    }

    /// Serve domain content
    async fn serve_domain_content(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract domain and path from: /api/v1/web4/serve/{domain}{path}
        // Example: /api/v1/web4/serve/hello-world.zhtp/style.css
        let uri = &request.uri;
        let prefix = "/api/v1/web4/serve/";
        
        if !uri.starts_with(prefix) {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid serve path".to_string(),
            ));
        }

        let remainder = &uri[prefix.len()..];
        let parts: Vec<&str> = remainder.splitn(2, '/').collect();
        
        let domain = parts[0];
        let path = if parts.len() > 1 {
            format!("/{}", parts[1])
        } else {
            "/".to_string()
        };

        info!("🌐 Serving content for domain: {} path: {}", domain, path);

        let manager = self.web4_manager.read().await;
        
        match manager.registry.get_domain_content(domain, &path).await {
            Ok(content) => {
                // Determine content type from path
                let content_type = if path.ends_with(".css") {
                    "text/css"
                } else if path.ends_with(".js") {
                    "application/javascript"
                } else if path.ends_with(".json") {
                    "application/json"
                } else if path.ends_with(".png") {
                    "image/png"
                } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
                    "image/jpeg"
                } else if path.ends_with(".gif") {
                    "image/gif"
                } else if path.ends_with(".svg") {
                    "image/svg+xml"
                } else if path.ends_with(".webp") {
                    "image/webp"
                } else if path.ends_with(".mp4") {
                    "video/mp4"
                } else if path.ends_with(".webm") {
                    "video/webm"
                } else if path.ends_with(".mp3") {
                    "audio/mpeg"
                } else if path.ends_with(".wav") {
                    "audio/wav"
                } else if path.ends_with(".ogg") {
                    "audio/ogg"
                } else {
                    "text/html"
                };

                // For HTML content, inject base tag to fix relative URLs
                let final_content = if content_type == "text/html" {
                    match String::from_utf8(content.clone()) {
                        Ok(mut html) => {
                            // Escape domain name for HTML (defense-in-depth, domain is already validated)
                            let escaped_domain = domain
                                .replace('&', "&amp;")
                                .replace('<', "&lt;")
                                .replace('>', "&gt;")
                                .replace('"', "&quot;")
                                .replace('\'', "&#39;");
                            
                            let base_url = format!("http://localhost:9333/api/v1/web4/serve/{}/", escaped_domain);
                            let base_tag = format!("<base href=\"{}\">", base_url);
                            
                            // Insert base tag after <head> tag
                            if let Some(head_pos) = html.find("<head>") {
                                let insert_pos = head_pos + "<head>".len();
                                html.insert_str(insert_pos, &format!("\n    {}", base_tag));
                                html.into_bytes()
                            } else {
                                // If no <head> tag, return original content
                                content
                            }
                        }
                        Err(_) => content, // Not valid UTF-8, return as-is
                    }
                } else {
                    content
                };

                info!("✅ Serving {} bytes of {}", final_content.len(), content_type);

                Ok(ZhtpResponse::success_with_content_type(
                    final_content,
                    content_type.to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to serve content for {}{}: {}", domain, path, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Content not found: {}", e),
                ))
            }
        }
    }
}

/// Implement ZHTP request handler trait to integrate with existing server
#[async_trait::async_trait]
impl ZhtpRequestHandler for Web4Handler {
    /// Handle ZHTP requests for Web4 endpoints
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path = &request.uri;
        info!("Handling Web4 request: {} {}", request.method as u8, path);
        
        match path.as_str() {
            // Domain management endpoints
            path if path.starts_with("/api/v1/web4/domains/register") => {
                self.register_domain_simple(request.body).await
            }
            path if path.starts_with("/api/v1/web4/domains/") && request.method == lib_protocols::ZhtpMethod::Get => {
                self.get_domain(request).await
            }
            path if path.starts_with("/api/v1/web4/domains/") && path.ends_with("/transfer") => {
                self.transfer_domain(request).await
            }
            path if path.starts_with("/api/v1/web4/domains/") && path.ends_with("/release") => {
                self.release_domain(request).await
            }
            
            // Content publishing endpoints
            path if path == "/api/v1/web4/content/publish" => {
                self.publish_content(request.body).await
            }
            path if path.starts_with("/api/v1/web4/content/") && request.method == lib_protocols::ZhtpMethod::Put => {
                self.update_content(request).await
            }
            path if path.starts_with("/api/v1/web4/content/") && path.ends_with("/metadata") => {
                self.get_content_metadata(request).await
            }
            path if path.starts_with("/api/v1/web4/content/") && request.method == lib_protocols::ZhtpMethod::Delete => {
                self.delete_content(request).await
            }
            
            // Statistics endpoint
            "/api/v1/web4/statistics" => {
                self.get_web4_statistics().await
            }
            
            // Serve domain content
            path if path.starts_with("/api/v1/web4/serve/") => {
                self.serve_domain_content(request).await
            }
            
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Web4 endpoint not found: {}", path),
            )),
        }
    }

    /// Check if this handler can process the request
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/web4/")
    }

    /// Get handler priority (higher than default)
    fn priority(&self) -> u32 {
        200 // Higher priority for Web4 endpoints
    }
}