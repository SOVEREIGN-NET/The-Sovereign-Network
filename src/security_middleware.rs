use anyhow::Result;
use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode, Method},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;
use log::{warn, debug};
use base64::{Engine as _, engine::general_purpose};

use crate::auth::{AuthSystem, Claims};
use crate::security_monitor::{ZhtpSecurityMonitor, SecurityEventType, SecuritySeverity};

/// Security middleware configuration
#[derive(Debug, Clone)]
pub struct SecurityMiddlewareConfig {
    pub enable_csrf_protection: bool,
    pub enable_xss_protection: bool,
    pub enable_content_security_policy: bool,
    pub enable_hsts: bool,
    pub enable_frame_options: bool,
    pub enable_content_type_options: bool,
    pub enable_referrer_policy: bool,
    pub enable_permissions_policy: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_requests_per_minute: u32,
    pub rate_limit_burst_size: u32,
    pub session_timeout_minutes: u64,
    pub require_authentication: bool,
    pub allowed_origins: Vec<String>,
    pub blocked_user_agents: Vec<String>,
    pub max_request_size: usize,
}

impl Default for SecurityMiddlewareConfig {
    fn default() -> Self {
        Self {
            enable_csrf_protection: true,
            enable_xss_protection: true,
            enable_content_security_policy: true,
            enable_hsts: true,
            enable_frame_options: true,
            enable_content_type_options: true,
            enable_referrer_policy: true,
            enable_permissions_policy: true,
            rate_limit_enabled: true,
            rate_limit_requests_per_minute: 100,
            rate_limit_burst_size: 20,
            session_timeout_minutes: 30,
            require_authentication: true,
            allowed_origins: vec!["https://localhost".to_string()],
            blocked_user_agents: vec![
                "curl".to_string(),
                "wget".to_string(),
                "python-requests".to_string(),
                // Add known malicious user agents
            ],
            max_request_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// CSRF token store
#[derive(Debug, Clone)]
pub struct CsrfToken {
    pub token: String,
    pub created_at: u64,
    pub used: bool,
    pub session_id: String,
}

/// Rate limiting bucket for token bucket algorithm
#[derive(Debug, Clone)]
pub struct RateLimitBucket {
    pub tokens: u32,
    pub last_refill: u64,
    pub requests_this_minute: u32,
    pub minute_start: u64,
}

/// Security context for requests
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub request_id: String,
    pub client_ip: String,
    pub user_agent: String,
    pub authenticated: bool,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub claims: Option<Claims>,
    pub csrf_token: Option<String>,
    pub rate_limited: bool,
    pub threat_score: f64,
}

/// Security middleware state
#[derive(Debug)]
pub struct SecurityMiddlewareState {
    pub config: SecurityMiddlewareConfig,
    pub auth_system: Arc<AuthSystem>,
    pub security_monitor: Arc<ZhtpSecurityMonitor>,
    pub csrf_tokens: Arc<RwLock<HashMap<String, CsrfToken>>>,
    pub rate_limits: Arc<RwLock<HashMap<String, RateLimitBucket>>>,
    pub nonces: Arc<RwLock<HashMap<String, String>>>, // CSP nonces
}

impl SecurityMiddlewareState {
    pub fn new(
        config: SecurityMiddlewareConfig,
        auth_system: Arc<AuthSystem>,
        security_monitor: Arc<ZhtpSecurityMonitor>,
    ) -> Self {
        Self {
            config,
            auth_system,
            security_monitor,
            csrf_tokens: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate CSRF token
    pub async fn generate_csrf_token(&self, session_id: &str) -> String {
        let token = format!("csrf_{}", Uuid::new_v4().to_string().replace('-', ""));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let csrf_token = CsrfToken {
            token: token.clone(),
            created_at: now,
            used: false,
            session_id: session_id.to_string(),
        };

        self.csrf_tokens.write().await.insert(token.clone(), csrf_token);
        token
    }

    /// Validate CSRF token
    pub async fn validate_csrf_token(&self, token: &str, session_id: &str) -> bool {
        let mut tokens = self.csrf_tokens.write().await;
        
        if let Some(csrf_token) = tokens.get_mut(token) {
            if csrf_token.session_id == session_id && !csrf_token.used {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let age = now - csrf_token.created_at;
                
                // Tokens expire after 1 hour
                if age < 3600 {
                    csrf_token.used = true;
                    return true;
                }
            }
        }
        
        false
    }

    /// Check rate limit
    pub async fn check_rate_limit(&self, client_ip: &str) -> bool {
        if !self.config.rate_limit_enabled {
            return true;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let minute_start = (now / 60) * 60;
        
        let mut rate_limits = self.rate_limits.write().await;
        let bucket = rate_limits.entry(client_ip.to_string())
            .or_insert_with(|| RateLimitBucket {
                tokens: self.config.rate_limit_burst_size,
                last_refill: now,
                requests_this_minute: 0,
                minute_start,
            });

        // Reset minute counter if new minute
        if bucket.minute_start != minute_start {
            bucket.requests_this_minute = 0;
            bucket.minute_start = minute_start;
        }

        // Check per-minute limit
        if bucket.requests_this_minute >= self.config.rate_limit_requests_per_minute {
            return false;
        }

        // Refill tokens (token bucket algorithm)
        let time_passed = now - bucket.last_refill;
        let tokens_to_add = (time_passed * self.config.rate_limit_requests_per_minute as u64) / 60;
        
        bucket.tokens = (bucket.tokens + tokens_to_add as u32)
            .min(self.config.rate_limit_burst_size);
        bucket.last_refill = now;

        // Check if tokens available
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            bucket.requests_this_minute += 1;
            true
        } else {
            false
        }
    }

    /// Calculate threat score based on request characteristics
    pub fn calculate_threat_score(
        &self,
        _client_ip: &str,
        user_agent: &str,
        method: &Method,
        path: &str,
    ) -> f64 {
        let mut score: f64 = 0.0;

        // Check user agent
        for blocked_agent in &self.config.blocked_user_agents {
            if user_agent.to_lowercase().contains(&blocked_agent.to_lowercase()) {
                score += 0.8;
            }
        }

        // Check for suspicious patterns
        if user_agent.is_empty() {
            score += 0.5;
        }

        if path.contains("..") || path.contains("etc/passwd") || path.contains("cmd=") {
            score += 0.9;
        }

        // Check for SQL injection patterns
        let sql_patterns = ["union", "select", "drop", "insert", "update", "delete", "'", "\"", ";"];
        for pattern in &sql_patterns {
            if path.to_lowercase().contains(pattern) {
                score += 0.3;
            }
        }

        // Check for XSS patterns
        let xss_patterns = ["<script", "javascript:", "onload=", "onerror="];
        for pattern in &xss_patterns {
            if path.to_lowercase().contains(pattern) {
                score += 0.4;
            }
        }

        // Penalize non-standard methods on sensitive paths
        if !matches!(method, &Method::GET | &Method::POST | &Method::PUT | &Method::DELETE) {
            score += 0.2;
        }

        score.min(1.0)
    }

    /// Generate CSP nonce
    pub async fn generate_csp_nonce(&self) -> String {
        let nonce = general_purpose::STANDARD.encode(&rand::random::<[u8; 16]>());
        let request_id = Uuid::new_v4().to_string();
        
        self.nonces.write().await.insert(request_id.clone(), nonce.clone());
        nonce
    }

    /// Clean up expired tokens and nonces
    pub async fn cleanup_expired(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Clean CSRF tokens (expire after 1 hour)
        {
            let mut tokens = self.csrf_tokens.write().await;
            tokens.retain(|_, token| now - token.created_at < 3600);
        }

        // Clean rate limit buckets (expire after 1 hour of inactivity)
        {
            let mut rate_limits = self.rate_limits.write().await;
            rate_limits.retain(|_, bucket| now - bucket.last_refill < 3600);
        }

        // Clean nonces (expire after 1 hour)
        {
            let mut nonces = self.nonces.write().await;
            // For simplicity, clear all nonces - in production you'd track timestamps
            if nonces.len() > 10000 {
                nonces.clear();
            }
        }
    }
}

/// Main security middleware function
pub async fn security_middleware(
    State(state): State<Arc<SecurityMiddlewareState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let request_id = Uuid::new_v4().to_string();
    let start_time = SystemTime::now();

    // Extract request information
    let client_ip = extract_client_ip(&request);
    let user_agent = extract_user_agent(&request);
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    debug!("Processing request {} from {} to {}", request_id, client_ip, path);

    // Check rate limiting
    if !state.check_rate_limit(&client_ip).await {
        warn!("Rate limit exceeded for IP: {}", client_ip);
        
        // Log security event
        state.security_monitor.log_security_event(
            SecurityEventType::RateLimitExceeded,
            &client_ip,
            format!("Rate limit exceeded for path: {}", path),
            SecuritySeverity::Medium,
        ).await;
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Calculate threat score
    let threat_score = state.calculate_threat_score(&client_ip, &user_agent, &method, &path);
    
    if threat_score > 0.7 {
        warn!("High threat score {} for request from {}", threat_score, client_ip);
        
        state.security_monitor.log_security_event(
            SecurityEventType::SuspiciousActivity,
            &client_ip,
            format!("High threat score: {} for path: {}", threat_score, path),
            SecuritySeverity::High,
        ).await;
        
        if threat_score > 0.9 {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Authentication check
    let mut security_context = SecurityContext {
        request_id: request_id.clone(),
        client_ip: client_ip.clone(),
        user_agent: user_agent.clone(),
        authenticated: false,
        user_id: None,
        session_id: None,
        claims: None,
        csrf_token: None,
        rate_limited: false,
        threat_score,
    };

    // Extract and validate authentication
    if let Some(claims) = extract_and_validate_auth(&state, &request).await {
        security_context.authenticated = true;
        security_context.user_id = Some(claims.user_id.clone());
        security_context.session_id = Some(claims.session_id.clone());
        security_context.claims = Some(claims);
    } else if state.config.require_authentication {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // CSRF protection for state-changing requests
    if state.config.enable_csrf_protection && 
       matches!(method, Method::POST | Method::PUT | Method::DELETE | Method::PATCH) {
        
        if let Some(session_id) = &security_context.session_id {
            let csrf_token = extract_csrf_token(&request);
            
            if csrf_token.is_none() || 
               !state.validate_csrf_token(&csrf_token.unwrap(), session_id).await {
                
                warn!("CSRF token validation failed for request {}", request_id);
                
                state.security_monitor.log_security_event(
                    SecurityEventType::InvalidAuthentication,
                    &client_ip,
                    "CSRF token validation failed".to_string(),
                    SecuritySeverity::Medium,
                ).await;
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    // Add security context to request extensions
    request.extensions_mut().insert(security_context);

    // Process request
    let mut response = next.run(request).await;

    // Add security headers
    add_security_headers(&state, &mut response).await;

    // Log successful request
    let duration = start_time.elapsed().unwrap_or_default();
    debug!("Request {} completed in {:?}", request_id, duration);

    Ok(response)
}

/// Extract client IP from request
fn extract_client_ip(request: &Request) -> String {
    // Check X-Forwarded-For header first
    if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip) = forwarded_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // Fallback to connection info (would need to be added to extensions)
    "unknown".to_string()
}

/// Extract user agent from request
fn extract_user_agent(request: &Request) -> String {
    request.headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Extract and validate authentication from request
async fn extract_and_validate_auth(
    state: &SecurityMiddlewareState,
    request: &Request,
) -> Option<Claims> {
    // Try Bearer token first
    if let Some(auth_header) = request.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Ok(claims) = state.auth_system.validate_token(token).await {
                    return Some(claims);
                }
            } else if auth_str.starts_with("ApiKey ") {
                let api_key = &auth_str[7..];
                if let Ok(claims) = state.auth_system.authenticate_api_key(api_key).await {
                    return Some(claims);
                }
            }
        }
    }

    // Try cookie-based session
    if let Some(cookie_header) = request.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if cookie.starts_with("zhtp_session=") {
                    let session_token = &cookie[13..]; // "zhtp_session=".len()
                    if let Ok(claims) = state.auth_system.validate_token(session_token).await {
                        return Some(claims);
                    }
                }
            }
        }
    }

    None
}

/// Extract CSRF token from request
fn extract_csrf_token(request: &Request) -> Option<String> {
    // Try header first
    if let Some(csrf_header) = request.headers().get("x-csrf-token") {
        if let Ok(token) = csrf_header.to_str() {
            return Some(token.to_string());
        }
    }

    // Try form data (would need to parse body)
    // This is simplified - in production you'd parse the request body
    None
}

/// Add security headers to response
async fn add_security_headers(
    state: &SecurityMiddlewareState,
    response: &mut Response,
) {
    let headers = response.headers_mut();

    if state.config.enable_xss_protection {
        headers.insert(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        );
    }

    if state.config.enable_content_type_options {
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
    }

    if state.config.enable_frame_options {
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
    }

    if state.config.enable_referrer_policy {
        headers.insert(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
    }

    if state.config.enable_hsts {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }

    if state.config.enable_permissions_policy {
        headers.insert(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        );
    }

    if state.config.enable_content_security_policy {
        let nonce = state.generate_csp_nonce().await;
        let csp = format!(
            "default-src 'self'; script-src 'self' 'nonce-{}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
            nonce
        );
        
        if let Ok(csp_value) = HeaderValue::from_str(&csp) {
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                csp_value,
            );
        }
    }

    // Add request ID for tracing
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_static("placeholder"), // Would use actual request ID
    );
}

/// Start cleanup task for expired tokens
pub fn start_security_cleanup_task(state: Arc<SecurityMiddlewareState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
        
        loop {
            interval.tick().await;
            state.cleanup_expired().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_score_calculation() {
        let config = SecurityMiddlewareConfig::default();
        let state = SecurityMiddlewareState {
            config,
            auth_system: Arc::new(crate::auth::AuthSystem::new(Default::default()).unwrap()),
            security_monitor: Arc::new(crate::security_monitor::ZhtpSecurityMonitor::new(Default::default())),
            csrf_tokens: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            nonces: Arc::new(RwLock::new(HashMap::new())),
        };

        // Normal request
        let score = state.calculate_threat_score(
            "192.168.1.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            &Method::GET,
            "/api/status"
        );
        assert!(score < 0.1);

        // Suspicious request
        let score = state.calculate_threat_score(
            "192.168.1.1",
            "curl/7.68.0",
            &Method::GET,
            "/api/users?id=1' OR '1'='1"
        );
        assert!(score > 0.5);
    }
}
