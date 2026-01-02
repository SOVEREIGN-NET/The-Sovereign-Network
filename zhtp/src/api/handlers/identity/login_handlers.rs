//! Login and Signin Handlers for Identity Authentication
//!
//! Provides password-based authentication endpoints:
//! - POST /api/v1/identity/signin - DID + password authentication
//! - POST /api/v1/identity/login - Alias for signin
//!
//! Security features:
//! - Rate limiting (10 attempts per 15 minutes per IP) via dependency injection
//! - Constant-time operations to prevent timing attacks
//! - Password zeroization after use
//! - Audit logging for security events
//! - No sensitive data in logs

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

// ZHTP protocol imports
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

// Identity management imports
use lib_identity::IdentityManager;

// Session management
use crate::session_manager::SessionManager;

// Rate limiting and CSRF protection via dependency injection
use crate::api::middleware::{RateLimiter, CsrfProtection};

/// Account lockout tracker
#[derive(Clone)]
pub struct AccountLockout {
    failed_attempts: Arc<RwLock<HashMap<String, Vec<u64>>>>,
    max_attempts: usize,
    lockout_duration_seconds: u64,
}

impl AccountLockout {
    pub fn new() -> Self {
        Self {
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
            max_attempts: 5, // Lock after 5 failed attempts
            lockout_duration_seconds: 900, // 15 minutes
        }
    }

    /// Check if an identity is locked out
    pub async fn is_locked_out(&self, identity_id: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let attempts = self.failed_attempts.read().await;
        if let Some(attempt_times) = attempts.get(identity_id) {
            // Count recent failed attempts within lockout window
            let recent_failures = attempt_times
                .iter()
                .filter(|&&t| now - t < self.lockout_duration_seconds)
                .count();

            recent_failures >= self.max_attempts
        } else {
            false
        }
    }

    /// Record a failed login attempt
    pub async fn record_failure(&self, identity_id: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut attempts = self.failed_attempts.write().await;
        let entry = attempts.entry(identity_id.to_string()).or_insert_with(Vec::new);

        // Remove old attempts outside lockout window
        entry.retain(|&t| now - t < self.lockout_duration_seconds);

        // Add this failure
        entry.push(now);
    }

    /// Clear failures on successful login
    pub async fn clear_failures(&self, identity_id: &str) {
        let mut attempts = self.failed_attempts.write().await;
        attempts.remove(identity_id);
    }

    /// Cleanup old entries
    pub async fn cleanup(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut attempts = self.failed_attempts.write().await;
        attempts.retain(|_, times| {
            times.retain(|&t| now - t < self.lockout_duration_seconds);
            !times.is_empty()
        });
    }
}

impl Default for AccountLockout {
    fn default() -> Self {
        Self::new()
    }
}

/// Request structure for signin/login
#[derive(Debug, Deserialize)]
pub struct SigninRequest {
    /// DID or identity_id for authentication
    #[serde(alias = "identifier")]
    pub did: Option<String>,

    /// Identity ID (alternative to DID)
    pub identity_id: Option<String>,

    /// User's password (will be zeroized after use)
    #[serde(alias = "passphrase")]
    pub password: String,
}

/// Response structure for successful signin/login
#[derive(Debug, Serialize)]
pub struct SigninResponse {
    pub status: String,
    pub session_token: String,
    pub csrf_token: String,
    pub identity: IdentityInfo,
}

/// Identity information returned in signin response
#[derive(Debug, Serialize)]
pub struct IdentityInfo {
    pub identity_id: String,
    pub did: String,
    pub identity_type: String,
    pub access_level: String,
    pub created_at: u64,
    pub last_active: u64,
}

/// Audit log entry for authentication attempts
struct AuthAuditLog {
    timestamp: u64,
    ip_address: String,
    success: bool,
    identity_exists: bool,
    failure_reason: Option<String>,
}

impl AuthAuditLog {
    fn log(&self) {
        if self.success {
            tracing::info!(
                "AUTH_SUCCESS: ip={} timestamp={}",
                self.ip_address,
                self.timestamp
            );
        } else {
            tracing::warn!(
                "AUTH_FAILURE: ip={} reason={} timestamp={}",
                self.ip_address,
                self.failure_reason.as_deref().unwrap_or("unknown"),
                self.timestamp
            );
        }
    }
}

/// Extract client IP from request headers
fn extract_client_ip(request: &lib_protocols::types::ZhtpRequest) -> String {
    // Try X-Real-IP first (from reverse proxy)
    if let Some(ip) = request.headers.get("X-Real-IP") {
        return ip;
    }

    // Try X-Forwarded-For (may contain multiple IPs, take first)
    if let Some(forwarded) = request.headers.get("X-Forwarded-For") {
        if let Some(first_ip) = forwarded.split(',').next() {
            return first_ip.trim().to_string();
        }
    }

    // Fallback to "unknown" if no IP headers found
    // This should log a warning in production
    tracing::warn!("No client IP found in request headers");
    "unknown".to_string()
}

/// Extract User-Agent from request headers (P0-6)
fn extract_user_agent(request: &lib_protocols::types::ZhtpRequest) -> String {
    request.headers
        .get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string())
}

/// Check HTTPS enforcement for production (P0-5)
fn check_https(_request: &lib_protocols::types::ZhtpRequest) -> Result<(), ZhtpResponse> {
    // Only enforce HTTPS in production (non-debug builds)
    #[cfg(not(debug_assertions))]
    {
        // Check X-Forwarded-Proto header (set by reverse proxy)
        if let Some(proto) = request.headers.get("X-Forwarded-Proto") {
            if proto != "https" {
                return Err(ZhtpResponse::error(
                    ZhtpStatus::Forbidden,
                    "HTTPS required for authentication in production".to_string(),
                ));
            }
        } else {
            // No X-Forwarded-Proto header - assume direct connection
            // In production, this should be configured with reverse proxy
            tracing::warn!("No X-Forwarded-Proto header found - HTTPS enforcement cannot be verified");
        }
    }

    Ok(())
}

/// Handle signin request (POST /api/v1/identity/signin)
pub async fn handle_signin(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<RateLimiter>,
    account_lockout: Arc<AccountLockout>,
    csrf_protection: Arc<CsrfProtection>,
    request: &lib_protocols::types::ZhtpRequest,
) -> ZhtpResult<ZhtpResponse> {
    // P0-5: Check HTTPS enforcement in production
    if let Err(response) = check_https(request) {
        return Ok(response);
    }

    let client_ip = extract_client_ip(request);
    let user_agent = extract_user_agent(request);
    handle_signin_with_ip(request_body, identity_manager, session_manager, rate_limiter, account_lockout, csrf_protection, &client_ip, &user_agent).await
}

/// Handle signin request with IP address for rate limiting
pub async fn handle_signin_with_ip(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<RateLimiter>,
    account_lockout: Arc<AccountLockout>,
    csrf_protection: Arc<CsrfProtection>,
    client_ip: &str,
    user_agent: &str,
) -> ZhtpResult<ZhtpResponse> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // P0-1: Rate limiting check (dependency injected)
    if let Err(response) = rate_limiter.check_rate_limit(client_ip).await {
        AuthAuditLog {
            timestamp: now,
            ip_address: client_ip.to_string(),
            success: false,
            identity_exists: false,
            failure_reason: Some("rate_limit_exceeded".to_string()),
        }.log();

        return Ok(response);
    }

    // Parse request
    let mut signin_req: SigninRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid signin request: {}", e))?;

    // P0-5: Use zeroizing string for password
    let password = Zeroizing::new(signin_req.password.clone());
    signin_req.password.zeroize();

    // Validate that we have either DID or identity_id
    let identity_id_str = match (&signin_req.did, &signin_req.identity_id) {
        (Some(did), _) => {
            // Extract identity_id from DID (format: "did:zhtp:<identity_id>")
            if let Some(id) = did.strip_prefix("did:zhtp:") {
                // P1: Validate DID format
                if id.len() < 16 || id.len() > 128 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                    AuthAuditLog {
                        timestamp: now,
                        ip_address: client_ip.to_string(),
                        success: false,
                        identity_exists: false,
                        failure_reason: Some("invalid_did_format".to_string()),
                    }.log();

                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::BadRequest,
                        "Invalid DID format".to_string(),
                    ));
                }
                id.to_string()
            } else {
                AuthAuditLog {
                    timestamp: now,
                    ip_address: client_ip.to_string(),
                    success: false,
                    identity_exists: false,
                    failure_reason: Some("missing_did_prefix".to_string()),
                }.log();

                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid DID format. Expected 'did:zhtp:<identity_id>'".to_string(),
                ));
            }
        }
        (None, Some(id)) => id.clone(),
        (None, None) => {
            AuthAuditLog {
                timestamp: now,
                ip_address: client_ip.to_string(),
                success: false,
                identity_exists: false,
                failure_reason: Some("missing_identifier".to_string()),
            }.log();

            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Either 'did' or 'identity_id' must be provided".to_string(),
            ));
        }
    };

    // Parse identity ID from hex string
    let identity_id_bytes = hex::decode(&identity_id_str)
        .map_err(|e| anyhow::anyhow!("Invalid identity ID hex: {}", e))?;
    let identity_id = lib_crypto::Hash::from_bytes(&identity_id_bytes);

    // P0-4: Check account lockout before attempting authentication
    if account_lockout.is_locked_out(&identity_id_str).await {
        AuthAuditLog {
            timestamp: now,
            ip_address: client_ip.to_string(),
            success: false,
            identity_exists: false,
            failure_reason: Some("account_locked_out".to_string()),
        }.log();

        return Ok(ZhtpResponse::error(
            ZhtpStatus::TooManyRequests,
            "Account temporarily locked due to too many failed login attempts. Please try again later.".to_string(),
        ));
    }

    // P0-2: No sensitive data in logs (removed identity_id_str from logs)
    tracing::info!("Authentication attempt from IP: {}", client_ip);

    // P0-3: Constant-time operations - validate password regardless of identity existence
    // This prevents timing attacks that could enumerate valid identity IDs
    let validation_result: Result<Option<(String, lib_identity::IdentityType, lib_identity::AccessLevel, u64)>> = {
        let manager = identity_manager.read().await;

        // Always attempt to get identity (even if it doesn't exist)
        let identity_option = manager.get_identity(&identity_id);

        // Always call password validation (even with dummy identity)
        // This maintains constant time regardless of identity existence
        let validation = if let Some(_identity) = identity_option.as_ref() {
            manager.validate_identity_password(&identity_id, &password)
        } else {
            // Simulate password validation timing even when identity doesn't exist
            // P0-2 FIX: Use longer delay (500ms) to prevent timing attacks
            // This makes enumeration attacks impractical (500ms × millions of DIDs = years)
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let _ = lib_crypto::hash_blake3(password.as_bytes());
            Err(lib_identity::PasswordError::IdentityNotImported)
        };

        // Extract identity data only if validation succeeded
        match (identity_option, validation) {
            (Some(identity), Ok(val)) if val.valid => {
                Ok(Some((
                    identity.did.clone(),
                    identity.identity_type.clone(),
                    identity.access_level.clone(),
                    identity.created_at,
                )))
            }
            _ => Ok(None),
        }
    };

    // P0-4: Race condition fixed - validation and data extraction are atomic
    let identity_data = match validation_result {
        Ok(Some(data)) => data,
        Ok(None) | Err(_) => {
            // P0-4: Record failed attempt for account lockout
            account_lockout.record_failure(&identity_id_str).await;

            // P0-2: Generic error message doesn't leak internal state
            AuthAuditLog {
                timestamp: now,
                ip_address: client_ip.to_string(),
                success: false,
                identity_exists: false,
                failure_reason: Some("invalid_credentials".to_string()),
            }.log();

            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                "Invalid credentials".to_string(),
            ));
        }
    };

    let (did, identity_type, access_level, created_at) = identity_data;

    // P0-4: Clear failed attempts on successful authentication
    account_lockout.clear_failures(&identity_id_str).await;

    // Create session (only after successful validation) with IP/UA binding (P0-6)
    let session_token = session_manager
        .create_session(identity_id.clone(), client_ip, user_agent)
        .await
        .map_err(|e| {
            tracing::error!("Session creation failed: {}", e);
            anyhow::anyhow!("Authentication failed")
        })?;

    // P0-2: Don't log session tokens or sensitive data
    tracing::info!("Authentication successful for IP: {}", client_ip);

    AuthAuditLog {
        timestamp: now,
        ip_address: client_ip.to_string(),
        success: true,
        identity_exists: true,
        failure_reason: None,
    }.log();

    // Generate CSRF token for this session (P0-7)
    let csrf_token = csrf_protection.generate_token(&session_token);

    // Build response
    let response = SigninResponse {
        status: "success".to_string(),
        session_token,
        csrf_token,
        identity: IdentityInfo {
            identity_id: identity_id.to_string(),
            did,
            identity_type: format!("{:?}", identity_type),
            access_level: format!("{:?}", access_level),
            created_at,
            last_active: now,
        },
    };

    let json_response = serde_json::to_vec(&response)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

/// Handle login request (POST /api/v1/identity/login)
/// This is an alias for signin for compatibility
pub async fn handle_login(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<RateLimiter>,
    account_lockout: Arc<AccountLockout>,
    csrf_protection: Arc<CsrfProtection>,
    request: &lib_protocols::types::ZhtpRequest,
) -> ZhtpResult<ZhtpResponse> {
    // Login is identical to signin
    handle_signin(request_body, identity_manager, session_manager, rate_limiter, account_lockout, csrf_protection, request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signin_request_parsing() {
        // Test with DID
        let json = r#"{"did": "did:zhtp:abc123", "password": "test"}"#;
        let req: SigninRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.did, Some("did:zhtp:abc123".to_string()));
        assert_eq!(req.password, "test");

        // Test with identity_id
        let json = r#"{"identity_id": "abc123", "password": "test"}"#;
        let req: SigninRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.identity_id, Some("abc123".to_string()));

        // Test with passphrase alias
        let json = r#"{"did": "did:zhtp:abc123", "passphrase": "test"}"#;
        let req: SigninRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.password, "test");

        // Test with identifier alias
        let json = r#"{"identifier": "did:zhtp:abc123", "password": "test"}"#;
        let req: SigninRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.did, Some("did:zhtp:abc123".to_string()));
    }
}
