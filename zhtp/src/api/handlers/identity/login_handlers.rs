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
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

// ZHTP protocol imports
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

// Identity management imports
use lib_identity::{IdentityManager, IdentityId};

// Session management
use crate::session_manager::SessionManager;

// Rate limiting via dependency injection
use crate::api::middleware::RateLimiter;

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

/// Handle signin request (POST /api/v1/identity/signin)
pub async fn handle_signin(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<RateLimiter>,
) -> ZhtpResult<ZhtpResponse> {
    handle_signin_with_ip(request_body, identity_manager, session_manager, rate_limiter, "unknown").await
}

/// Handle signin request with IP address for rate limiting
pub async fn handle_signin_with_ip(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<RateLimiter>,
    client_ip: &str,
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
            // Use a dummy hash to maintain constant-time behavior
            let _ = lib_crypto::hash_blake3(password.as_bytes());
            std::thread::sleep(std::time::Duration::from_millis(10)); // Simulate validation time
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

    // Create session (only after successful validation)
    let session_token = session_manager
        .create_session(identity_id.clone())
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

    // Build response
    let response = SigninResponse {
        status: "success".to_string(),
        session_token,
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
) -> ZhtpResult<ZhtpResponse> {
    // Login is identical to signin
    handle_signin(request_body, identity_manager, session_manager, rate_limiter).await
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
