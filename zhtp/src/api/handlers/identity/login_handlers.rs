//! Login and Signin Handlers for Identity Authentication
//!
//! Provides password-based authentication endpoints:
//! - POST /api/v1/identity/signin - DID + password authentication
//! - POST /api/v1/identity/login - Alias for signin

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};

// ZHTP protocol imports
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

// Identity management imports
use lib_identity::{IdentityManager, IdentityId};

// Session management
use crate::session_manager::SessionManager;

/// Request structure for signin/login
#[derive(Debug, Deserialize)]
pub struct SigninRequest {
    /// DID or identity_id for authentication
    #[serde(alias = "identifier")]
    pub did: Option<String>,

    /// Identity ID (alternative to DID)
    pub identity_id: Option<String>,

    /// User's password
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

/// Handle signin request (POST /api/v1/identity/signin)
pub async fn handle_signin(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
) -> ZhtpResult<ZhtpResponse> {
    // Parse request
    let signin_req: SigninRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid signin request: {}", e))?;

    // Validate that we have either DID or identity_id
    let identity_id_str = match (&signin_req.did, &signin_req.identity_id) {
        (Some(did), _) => {
            // Extract identity_id from DID (format: "did:zhtp:<identity_id>")
            if let Some(id) = did.strip_prefix("did:zhtp:") {
                id.to_string()
            } else {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid DID format. Expected 'did:zhtp:<identity_id>'".to_string(),
                ));
            }
        }
        (None, Some(id)) => id.clone(),
        (None, None) => {
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

    tracing::info!(
        "Signin attempt for identity: {}",
        &identity_id_str[..16.min(identity_id_str.len())]
    );

    // Validate password and get identity data
    let (did, identity_type, access_level, created_at) = {
        let manager = identity_manager.read().await;

        // Check if identity exists
        let identity = manager.get_identity(&identity_id)
            .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;

        // Validate password
        let validation = manager
            .validate_identity_password(&identity_id, &signin_req.password)
            .map_err(|e| {
                tracing::warn!("Password validation failed: {}", e);
                anyhow::anyhow!("Invalid credentials")
            })?;

        if !validation.valid {
            tracing::warn!("Invalid password for identity {}", &identity_id_str[..16]);
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                "Invalid credentials".to_string(),
            ));
        }

        tracing::info!("Password validated for identity {}", &identity_id_str[..16]);

        // Extract needed data before dropping the lock
        (
            identity.did.clone(),
            identity.identity_type.clone(),
            identity.access_level.clone(),
            identity.created_at,
        )
    }; // Manager lock is dropped here

    // Create session
    let session_token = session_manager
        .create_session(identity_id.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to create session: {}", e);
            anyhow::anyhow!("Failed to create session")
        })?;

    tracing::info!(
        "Session created for identity {}: {}",
        &identity_id_str[..16],
        &session_token[..16]
    );

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
            last_active: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
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
) -> ZhtpResult<ZhtpResponse> {
    // Login is identical to signin
    handle_signin(request_body, identity_manager, session_manager).await
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
