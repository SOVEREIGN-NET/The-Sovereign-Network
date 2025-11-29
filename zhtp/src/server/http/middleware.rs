//! HTTP Middleware Components
//! 
//! Provides CORS, rate limiting, and authentication middleware for HTTP requests

use std::sync::Arc;
use std::collections::HashMap;
use std::time::SystemTime;
use tokio::sync::RwLock;
use anyhow::Result;
use async_trait::async_trait;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};

/// Middleware trait for request processing
#[async_trait]
pub trait Middleware: Send + Sync {
    async fn process(&self, request: &mut ZhtpRequest, response: &mut Option<ZhtpResponse>) -> Result<bool>;
    fn name(&self) -> &str;
}

/// CORS middleware
pub struct CorsMiddleware;

#[async_trait]
impl Middleware for CorsMiddleware {
    async fn process(&self, _request: &mut ZhtpRequest, response: &mut Option<ZhtpResponse>) -> Result<bool> {
        if let Some(resp) = response {
            resp.headers.set("Access-Control-Allow-Origin", "*".to_string());
            resp.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS".to_string());
            resp.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization".to_string());
        }
        Ok(true) // Continue processing
    }
    
    fn name(&self) -> &str {
        "CORS"
    }
}

/// Rate limiting middleware
pub struct RateLimitMiddleware {
    request_counts: Arc<RwLock<HashMap<String, (u64, SystemTime)>>>,
    max_requests: u64,
    window_seconds: u64,
}

impl RateLimitMiddleware {
    pub fn new(max_requests: u64, window_seconds: u64) -> Self {
        Self {
            request_counts: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_seconds,
        }
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    async fn process(&self, request: &mut ZhtpRequest, response: &mut Option<ZhtpResponse>) -> Result<bool> {
        let client_key = request.headers.get("X-Forwarded-For")
            .or_else(|| request.headers.get("X-Real-IP"))
            .unwrap_or("unknown".to_string());
            
        let mut counts = self.request_counts.write().await;
        let now = SystemTime::now();
        
        let (count, last_window) = counts.get(&client_key)
            .copied()
            .unwrap_or((0, now));
            
        let elapsed = now.duration_since(last_window).unwrap_or_default().as_secs();
        
        if elapsed >= self.window_seconds {
            // Reset window
            counts.insert(client_key, (1, now));
            Ok(true)
        } else if count >= self.max_requests {
            // Rate limit exceeded
            *response = Some(ZhtpResponse::error(
                ZhtpStatus::TooManyRequests,
                "Rate limit exceeded".to_string(),
            ));
            Ok(false) // Stop processing
        } else {
            // Increment count
            counts.insert(client_key, (count + 1, last_window));
            Ok(true)
        }
    }
    
    fn name(&self) -> &str {
        "RateLimit"
    }
}

/// Authentication middleware
pub struct AuthMiddleware;

#[async_trait]
impl Middleware for AuthMiddleware {
    async fn process(&self, request: &mut ZhtpRequest, response: &mut Option<ZhtpResponse>) -> Result<bool> {
        // Skip auth for public endpoints
        if request.uri.starts_with("/api/v1/public/") || 
           request.uri == "/api/v1/health" ||
           request.uri.starts_with("/api/v1/web4/") ||
           request.uri.starts_with("/api/v1/dns/") ||
           request.uri.starts_with("/api/v1/dht/") ||  // Allow DHT content access without auth
           request.uri.starts_with("/api/v1/blockchain/") ||
           request.uri.starts_with("/api/v1/storage/") ||
           request.uri.starts_with("/api/v1/identity/") ||  // Allow identity creation without auth
           request.uri.starts_with("/api/marketplace/") ||
           request.uri.starts_with("/api/content/") ||
           request.uri.starts_with("/api/wallet/") {
            return Ok(true);
        }
        
        // Check for Authorization header
        if let Some(auth_header) = request.headers.get("Authorization") {
            if auth_header.starts_with("Bearer ") {
                let token = &auth_header[7..];
                // In a real implementation, verify JWT token
                if token.len() > 10 { // Simple validation
                    request.headers.set("X-Authenticated", "true".to_string());
                    return Ok(true);
                }
            }
        }
        
        // Authentication required but not provided
        *response = Some(ZhtpResponse::error(
            ZhtpStatus::Unauthorized,
            "Authentication required".to_string(),
        ));
        Ok(false) // Stop processing
    }
    
    fn name(&self) -> &str {
        "Auth"
    }
}
