//! Password Reset and Recovery Handlers (P0-8)
//!
//! Provides recovery phrase-based password reset functionality

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

// ZHTP protocol imports
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

// Identity management imports
use lib_identity::IdentityManager;
use lib_identity::recovery::RecoveryPhraseManager;

// Session management
use crate::session_manager::SessionManager;

/// Request structure for password recovery
#[derive(Debug, Deserialize)]
pub struct PasswordRecoveryRequest {
    /// Identity ID or DID
    #[serde(alias = "did")]
    pub identity_id: Option<String>,

    /// Recovery phrase (will be zeroized after use)
    pub recovery_phrase: String,

    /// New password (will be zeroized after use)
    pub new_password: String,
}

/// Response structure for password recovery
#[derive(Debug, Serialize)]
pub struct PasswordRecoveryResponse {
    pub status: String,
    pub message: String,
}

/// Handle password recovery request (POST /api/v1/identity/password/recover)
pub async fn handle_password_recovery(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
) -> ZhtpResult<ZhtpResponse> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Parse request
    let mut recovery_req: PasswordRecoveryRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid recovery request: {}", e))?;

    // Use zeroizing for sensitive data
    let _recovery_phrase = Zeroizing::new(recovery_req.recovery_phrase.clone());
    let new_password = Zeroizing::new(recovery_req.new_password.clone());
    recovery_req.recovery_phrase.zeroize();
    recovery_req.new_password.zeroize();

    // Validate identity_id provided
    let identity_id_str = match &recovery_req.identity_id {
        Some(id) => {
            // Handle DID format
            if let Some(id_part) = id.strip_prefix("did:zhtp:") {
                id_part.to_string()
            } else {
                id.clone()
            }
        }
        None => {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "identity_id or did required".to_string(),
            ));
        }
    };

    // Parse identity ID
    let identity_id_bytes = hex::decode(&identity_id_str)
        .map_err(|e| anyhow::anyhow!("Invalid identity ID hex: {}", e))?;
    let identity_id = lib_crypto::Hash::from_bytes(&identity_id_bytes);

    // Validate recovery phrase BEFORE leaking whether the identity exists.
    // This endpoint is intended for "imported" identities, where the server can
    // deterministically derive the IdentityId from the phrase.
    let phrase_words: Vec<String> = _recovery_phrase
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Accept both 20-word custom and 24-word BIP39 standard (matches lib-identity behavior).
    if phrase_words.len() != 20 && phrase_words.len() != 24 {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            format!(
                "Recovery phrase must be 20 or 24 words, got {}",
                phrase_words.len()
            ),
        ));
    }

    let recovery_manager = RecoveryPhraseManager::new();
    let (derived_identity_id, _derived_sk, _derived_pk, _derived_seed) = recovery_manager
        .restore_from_phrase(&phrase_words)
        .await
        .map_err(|e| anyhow::anyhow!("Invalid recovery phrase: {}", e))?;

    if derived_identity_id.0 != identity_id.0 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        return Ok(ZhtpResponse::error(
            ZhtpStatus::Unauthorized,
            "Invalid recovery phrase or identity not found".to_string(),
        ));
    }

    // Validate recovery phrase and reset password
    let mut manager = identity_manager.write().await;

    // Check if identity exists
    if manager.get_identity(&identity_id).is_none() {
        // Constant-time delay to prevent enumeration
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        return Ok(ZhtpResponse::error(
            ZhtpStatus::Unauthorized,
            "Invalid recovery phrase or identity not found".to_string(),
        ));
    }

    // Set new password
    match manager.set_identity_password(&identity_id, &new_password) {
        Ok(_) => {
            // Invalidate all existing sessions for this identity
            drop(manager);
            let removed_count = session_manager.remove_all_sessions(&identity_id).await?;

            tracing::info!(
                "Password reset successful for identity {}: {} sessions invalidated",
                &identity_id_str[..16],
                removed_count
            );

            // Audit log
            tracing::warn!(
                "PASSWORD_RESET: identity={} timestamp={} sessions_invalidated={}",
                &identity_id_str[..16],
                now,
                removed_count
            );

            let response = PasswordRecoveryResponse {
                status: "success".to_string(),
                message: "Password reset successful. All sessions have been invalidated.".to_string(),
            };

            let json_response = serde_json::to_vec(&response)?;
            Ok(ZhtpResponse::success_with_content_type(
                json_response,
                "application/json".to_string(),
                None,
            ))
        }
        Err(e) => {
            // Password validation / eligibility errors are client-visible.
            tracing::warn!("Password reset rejected: {}", e);
            Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Password reset rejected: {}", e),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_recovery_request_parsing() {
        let json = r#"{"identity_id": "abc123", "recovery_phrase": "word1 word2 ... word20", "new_password": "newpass123"}"#;
        let req: PasswordRecoveryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.identity_id, Some("abc123".to_string()));
        assert_eq!(req.recovery_phrase, "word1 word2 ... word20");
        assert_eq!(req.new_password, "newpass123");

        // Test with DID
        let json = r#"{"did": "did:zhtp:abc123", "recovery_phrase": "words", "new_password": "newpass"}"#;
        let req: PasswordRecoveryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.identity_id, Some("did:zhtp:abc123".to_string()));
    }
}
