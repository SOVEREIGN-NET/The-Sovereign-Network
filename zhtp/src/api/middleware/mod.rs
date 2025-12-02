//! Middleware Module
//!
//! Clean, minimal middleware for ZHTP requests

pub mod rate_limiter;
pub mod csrf;

use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn};

// ZHTP protocol imports
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};

// Re-export middleware components
pub use rate_limiter::{RateLimiter, RateLimitConfig, RateLimiterStats};
pub use csrf::CsrfProtection;

/// Simple request logging middleware
pub struct LoggingMiddleware;

impl LoggingMiddleware {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn process_request(&self, request: &ZhtpRequest) -> Result<()> {
        let client_id = request.headers.get("X-Client-ID")
            .unwrap_or_else(|| "unknown".to_string());
        info!(
            "Request: {} {} from {}",
            request.method,
            request.uri,
            client_id
        );
        Ok(())
    }
    
    pub async fn process_response(&self, request: &ZhtpRequest, response: &ZhtpResponse) -> Result<()> {
        info!(
            " Response: {} {} -> {} ({} bytes)",
            request.method,
            request.uri,
            response.status,
            response.body.len()
        );
        Ok(())
    }
}

/// Simple CORS middleware
pub struct CorsMiddleware {
    allowed_origins: Vec<String>,
}

impl CorsMiddleware {
    pub fn new() -> Self {
        Self {
            allowed_origins: vec![
                "*".to_string(), // Allow all origins for development
            ],
        }
    }
    
    pub fn with_origins(origins: Vec<String>) -> Self {
        Self {
            allowed_origins: origins,
        }
    }
    
    pub async fn process_request(&self, request: &ZhtpRequest) -> Result<()> {
        // CORS preflight handling
        if let Some(origin) = request.headers.get("Origin") {
            if !self.is_origin_allowed(&origin) {
                warn!(" CORS: Origin not allowed: {}", origin);
            }
        }
        Ok(())
    }
    
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.contains(&"*".to_string()) || self.allowed_origins.contains(&origin.to_string())
    }
    
    pub fn add_cors_headers(&self, response: &mut ZhtpResponse, request_origin: Option<&str>) -> Result<()> {
        // Check if the request origin is allowed
        let allowed_origin = if let Some(origin) = request_origin {
            if self.allowed_origins.contains(&"*".to_string()) || self.allowed_origins.contains(&origin.to_string()) {
                origin.to_string()
            } else {
                "null".to_string() // Deny origin
            }
        } else {
            self.allowed_origins.first().cloned().unwrap_or_else(|| "*".to_string())
        };
        
        response.headers.set("Access-Control-Allow-Origin", allowed_origin);
        response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS".to_string());
        response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Client-ID".to_string());
        Ok(())
    }
}

/// Simple rate limiting middleware
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub struct RateLimitMiddleware {
    max_requests_per_minute: u32,
    request_counts: Arc<RwLock<HashMap<String, (u64, u32)>>>, // (timestamp, count)
}

impl RateLimitMiddleware {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            max_requests_per_minute,
            request_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub fn get_max_requests(&self) -> u32 {
        self.max_requests_per_minute
    }
    
    pub async fn check_rate_limit(&self, client_id: &str) -> Result<bool> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let current_minute = current_time / 60; // Get current minute
        
        let mut counts = self.request_counts.write().await;
        
        let (last_minute, count) = counts.get(client_id).copied().unwrap_or((0, 0));
        
        if last_minute == current_minute {
            // Same minute, check if limit exceeded
            if count >= self.max_requests_per_minute {
                warn!(" Rate limit exceeded for client: {} ({}/{})", client_id, count, self.max_requests_per_minute);
                return Ok(false);
            }
            // Increment counter
            counts.insert(client_id.to_string(), (current_minute, count + 1));
        } else {
            // New minute, reset counter
            counts.insert(client_id.to_string(), (current_minute, 1));
        }
        
        info!("🚦 Rate limit check for client: {} ({}/{})", client_id, 
              counts.get(client_id).map(|(_, c)| *c).unwrap_or(0), self.max_requests_per_minute);
        Ok(true)
    }
    
    pub fn create_rate_limit_response(&self) -> ZhtpResponse {
        ZhtpResponse::error(
            ZhtpStatus::TooManyRequests,
            "Rate limit exceeded. Please try again later.".to_string(),
        )
    }
}

/// Authentication middleware
pub struct AuthMiddleware;

impl AuthMiddleware {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn authenticate_request(&self, request: &ZhtpRequest) -> Result<Option<String>> {
        // Check for authentication header
        if let Some(auth_header) = request.headers.get("Authorization") {
            if auth_header.starts_with("Bearer ") {
                let token = &auth_header[7..];
                // Simplified token validation - would need proper JWT validation
                info!("Authenticating token: {}...", &token[..8.min(token.len())]);
                return Ok(Some("authenticated_user".to_string()));
            }
        }
        
        // Check if endpoint requires authentication
        if self.requires_auth(&request.uri) {
            warn!(" Authentication required for: {}", request.uri);
            return Ok(None);
        }
        
        Ok(Some("anonymous".to_string()))
    }
    
    pub fn create_auth_required_response(&self) -> ZhtpResponse {
        ZhtpResponse::error(
            ZhtpStatus::Unauthorized,
            "Authentication required".to_string(),
        )
    }
    
    fn requires_auth(&self, uri: &str) -> bool {
        // Define which endpoints require authentication
        // NOTE: Identity creation does NOT require auth (you're creating your first identity!)
        uri.starts_with("/api/v1/blockchain/transaction") ||
        uri.starts_with("/api/v1/storage/put") ||
        uri.starts_with("/api/v1/storage/delete") ||
        uri.starts_with("/api/v1/wallet/") || // Wallet operations need auth
        uri.starts_with("/api/v1/identity/update") // Updates need auth, but not create
    }
}

/// Middleware stack for combining multiple middleware
pub struct MiddlewareStack {
    pub logging: LoggingMiddleware,
    pub cors: CorsMiddleware,
    pub rate_limit: RateLimitMiddleware,
    pub auth: AuthMiddleware,
}

impl MiddlewareStack {
    pub fn new() -> Self {
        Self {
            logging: LoggingMiddleware::new(),
            cors: CorsMiddleware::new(),
            rate_limit: RateLimitMiddleware::new(100), // 100 requests per minute
            auth: AuthMiddleware::new(),
        }
    }
    
    /// Process request through all middleware
    pub async fn process_request(&self, request: &ZhtpRequest) -> Result<Option<ZhtpResponse>> {
        // 1. Logging
        self.logging.process_request(request).await?;
        
        // 2. CORS preflight
        self.cors.process_request(request).await?;
        
        // 3. Rate limiting
        let client_id = request.headers.get("X-Client-ID")
            .unwrap_or_else(|| "anonymous".to_string());
        if !self.rate_limit.check_rate_limit(&client_id).await? {
            return Ok(Some(self.rate_limit.create_rate_limit_response()));
        }
        
        // 4. Authentication
        if let Some(_user) = self.auth.authenticate_request(request).await? {
            // Authentication successful, continue to handlers
            Ok(None)
        } else {
            // Authentication failed
            Ok(Some(self.auth.create_auth_required_response()))
        }
    }
    
    /// Process response through all middleware
    pub async fn process_response(&self, request: &ZhtpRequest, mut response: ZhtpResponse) -> Result<ZhtpResponse> {
        // 1. Add CORS headers with origin checking
        let request_origin = request.headers.get("Origin");
        self.cors.add_cors_headers(&mut response, request_origin.as_deref())?;
        
        // 2. Response logging
        self.logging.process_response(request, &response).await?;
        
        Ok(response)
    }
}