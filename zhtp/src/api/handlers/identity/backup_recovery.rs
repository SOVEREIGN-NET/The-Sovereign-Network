//! Backup and Recovery Handlers (Issue #100)
//!
//! Provides endpoints for identity backup and recovery using recovery phrases:
//! - POST /api/v1/identity/backup/generate - Generate recovery phrase
//! - POST /api/v1/identity/backup/verify - Verify recovery phrase
//! - POST /api/v1/identity/recover - Recover identity from phrase
//! - GET /api/v1/identity/backup/status - Check backup status

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ZHTP protocol imports
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

// Identity management imports
use lib_identity::{IdentityManager, RecoveryPhraseManager, PhraseGenerationOptions, EntropySource, RecoveryPhrase};

// Session management
use crate::session_manager::SessionManager;

/// Request for generating recovery phrase
#[derive(Debug, Deserialize)]
pub struct GenerateRecoveryPhraseRequest {
    pub identity_id: String,
    pub session_token: String,
}

/// Response with recovery phrase
#[derive(Debug, Serialize)]
pub struct GenerateRecoveryPhraseResponse {
    pub status: String,
    pub phrase_hash: String,
    /// SECURITY: Phrase is returned ONCE for client-side display only
    /// Client MUST display securely and NEVER store in logs/cache
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_phrase: Option<String>,
    pub instructions: String,
}

/// Request for verifying recovery phrase
#[derive(Debug, Deserialize)]
pub struct VerifyRecoveryPhraseRequest {
    pub identity_id: String,
    pub recovery_phrase: String,
}

/// Response for verification
#[derive(Debug, Serialize)]
pub struct VerifyRecoveryPhraseResponse {
    pub status: String,
    pub verified: bool,
}

/// Request for recovering identity
#[derive(Debug, Deserialize)]
pub struct RecoverIdentityRequest {
    pub recovery_phrase: String,
}

/// Response for identity recovery
#[derive(Debug, Serialize)]
pub struct RecoverIdentityResponse {
    pub status: String,
    pub identity: IdentityInfo,
    pub session_token: String,
}

/// Identity information in recovery response
#[derive(Debug, Serialize)]
pub struct IdentityInfo {
    pub identity_id: String,
    pub did: String,
}

/// Response for backup status
#[derive(Debug, Serialize)]
pub struct BackupStatusResponse {
    pub has_recovery_phrase: bool,
    pub backup_date: Option<u64>,
    pub verified: bool,
}

/// Handle POST /api/v1/identity/backup/generate
pub async fn handle_generate_recovery_phrase(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    recovery_phrase_manager: Arc<RwLock<RecoveryPhraseManager>>,
    request: &lib_protocols::types::ZhtpRequest,
) -> ZhtpResult<ZhtpResponse> {
    // Parse request
    let req: GenerateRecoveryPhraseRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

    // Extract client IP and User-Agent for session binding validation
    let client_ip = request.headers.get("X-Real-IP")
        .or_else(|| request.headers.get("X-Forwarded-For").and_then(|f| {
            f.split(',').next().map(|s| s.trim().to_string())
        }))
        .unwrap_or_else(|| "unknown".to_string());

    let user_agent = request.headers.get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string());

    // Validate session token with IP and User-Agent binding
    let session = session_manager
        .validate_session(&req.session_token, &client_ip, &user_agent)
        .await
        .map_err(|e| anyhow::anyhow!("Invalid session: {}", e))?;

    // Verify session belongs to this identity
    let identity_id_bytes = hex::decode(&req.identity_id)
        .map_err(|e| anyhow::anyhow!("Invalid identity ID: {}", e))?;
    let identity_id = lib_crypto::Hash::from_bytes(&identity_id_bytes);

    if session.identity_id != identity_id {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::Forbidden,
            "Session does not match identity".to_string(),
        ));
    }

    // Verify identity exists
    let manager = identity_manager.read().await;
    if manager.get_identity(&identity_id).is_none() {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::NotFound,
            "Identity not found".to_string(),
        ));
    }
    drop(manager);

    // Generate recovery phrase (20 words, English)
    let options = PhraseGenerationOptions {
        word_count: 20,
        language: "english".to_string(),
        entropy_source: EntropySource::SystemRandom,
        include_checksum: true,
        custom_wordlist: None,
    };

    let mut phrase_manager = recovery_phrase_manager.write().await;
    let phrase = phrase_manager
        .generate_recovery_phrase(&req.identity_id, options)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to generate recovery phrase: {}", e))?;

    // Store encrypted recovery phrase
    let phrase_hash = phrase_manager
        .store_recovery_phrase(&req.identity_id, &phrase, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to store recovery phrase: {}", e))?;

    tracing::info!(
        "Recovery phrase generated for identity {} - phrase_hash: {}",
        &req.identity_id[..16],
        &phrase_hash[..16]
    );

    // SECURITY NOTE: Recovery phrase is returned ONCE and must be displayed client-side immediately
    // Client MUST:
    // 1. Show phrase in UI with "Write this down" warning
    // 2. NEVER log, cache, or store in browser localStorage
    // 3. Clear from memory after user confirms they wrote it down
    // 4. Use HTTPS only to prevent network sniffing

    // Build response - WARNING: phrase sent over HTTPS ONCE
    let response = GenerateRecoveryPhraseResponse {
        status: "success".to_string(),
        phrase_hash,
        recovery_phrase: Some(phrase.to_string()), // Shown ONCE - client must display securely
        instructions: "CRITICAL: Write down these words in order. You will need them to recover your identity. This phrase will NEVER be shown again. Keep it safe and private.".to_string(),
    };

    let json_response = serde_json::to_vec(&response)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

/// Handle POST /api/v1/identity/backup/verify
pub async fn handle_verify_recovery_phrase(
    request_body: &[u8],
    recovery_phrase_manager: Arc<RwLock<RecoveryPhraseManager>>,
) -> ZhtpResult<ZhtpResponse> {
    // Parse request
    let req: VerifyRecoveryPhraseRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

    // Use zeroizing for recovery phrase
    let recovery_phrase = Zeroizing::new(req.recovery_phrase.clone());

    // Parse recovery phrase into words
    let words: Vec<String> = recovery_phrase
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Validate word count
    if words.len() != 20 {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            "Recovery phrase must be 20 words".to_string(),
        ));
    }

    // Create RecoveryPhrase object for validation
    let phrase = RecoveryPhrase::from_words(words)
        .map_err(|e| anyhow::anyhow!("Invalid recovery phrase format: {}", e))?;

    // Validate phrase
    let phrase_manager = recovery_phrase_manager.read().await;
    let validation_result = phrase_manager
        .validate_phrase(&phrase)
        .await
        .map_err(|e| anyhow::anyhow!("Phrase validation failed: {}", e))?;

    tracing::info!(
        "Recovery phrase verified for identity {}: valid={}",
        &req.identity_id[..16],
        validation_result.valid
    );

    // Build response
    let response = VerifyRecoveryPhraseResponse {
        status: "success".to_string(),
        verified: validation_result.valid,
    };

    let json_response = serde_json::to_vec(&response)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

/// Handle POST /api/v1/identity/recover
pub async fn handle_recover_identity(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    recovery_phrase_manager: Arc<RwLock<RecoveryPhraseManager>>,
    rate_limiter: Arc<crate::api::middleware::RateLimiter>,
    request: &lib_protocols::types::ZhtpRequest,
) -> ZhtpResult<ZhtpResponse> {
    // Extract client IP for rate limiting
    let client_ip = request.headers.get("X-Real-IP")
        .or_else(|| request.headers.get("X-Forwarded-For").and_then(|f| {
            f.split(',').next().map(|s| s.trim().to_string())
        }))
        .unwrap_or_else(|| "unknown".to_string());

    // CRITICAL: Rate limit recovery attempts (3 per hour per IP)
    // This prevents brute force attacks on recovery phrases
    if let Err(_) = rate_limiter.check_rate_limit_aggressive(&client_ip, 3, 3600).await {
        tracing::warn!("Recovery rate limit exceeded for IP: {}", &client_ip);
        return Ok(ZhtpResponse::error(
            ZhtpStatus::TooManyRequests,
            "Too many recovery attempts. Please try again later.".to_string(),
        ));
    }

    // Parse request
    let req: RecoverIdentityRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

    // Use zeroizing for recovery phrase
    let recovery_phrase = Zeroizing::new(req.recovery_phrase.clone());

    // Parse recovery phrase into words
    let words: Vec<String> = recovery_phrase
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Validate word count
    if words.len() != 20 {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            "Recovery phrase must be 20 words".to_string(),
        ));
    }

    // Restore identity from phrase using RecoveryPhraseManager
    let phrase_manager = recovery_phrase_manager.read().await;
    let (identity_id, _private_key, _public_key, _seed) = phrase_manager
        .restore_from_phrase(&words)
        .await
        .map_err(|e| anyhow::anyhow!("Identity recovery failed: {}", e))?;
    drop(phrase_manager);

    // Verify identity exists in IdentityManager
    let manager = identity_manager.read().await;
    let identity = manager
        .get_identity(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("Identity not found in storage"))?;
    let did = identity.did.clone();
    drop(manager);

    // Create new session for recovered identity
    let session_token = session_manager
        .create_session(identity_id.clone(), "recovery", "recovery-client")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create session: {}", e))?;

    tracing::info!(
        "Identity recovered successfully: {}",
        hex::encode(&identity_id.0[..8])
    );

    // Build response
    let response = RecoverIdentityResponse {
        status: "success".to_string(),
        identity: IdentityInfo {
            identity_id: identity_id.to_string(),
            did,
        },
        session_token,
    };

    let json_response = serde_json::to_vec(&response)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

/// Handle GET /api/v1/identity/backup/status
pub async fn handle_backup_status(
    query_params: &str,
    _recovery_phrase_manager: Arc<RwLock<RecoveryPhraseManager>>,
) -> ZhtpResult<ZhtpResponse> {
    // Parse identity_id from query params
    let _identity_id = query_params
        .split('=')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Missing identity_id parameter"))?;

    // TODO: Check if recovery phrase exists for this identity
    // For now, return placeholder response
    // Will need to add public getter method to RecoveryPhraseManager
    let (has_recovery_phrase, backup_date, verified) = (false, None, false);

    // Build response
    let response = BackupStatusResponse {
        has_recovery_phrase,
        backup_date,
        verified,
    };

    let json_response = serde_json::to_vec(&response)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_request_parsing() {
        let json = r#"{"identity_id": "abc123", "session_token": "token123"}"#;
        let req: GenerateRecoveryPhraseRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.identity_id, "abc123");
        assert_eq!(req.session_token, "token123");
    }

    #[test]
    fn test_verify_request_parsing() {
        let json = r#"{"identity_id": "abc123", "recovery_phrase": "word1 word2 ... word20"}"#;
        let req: VerifyRecoveryPhraseRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.identity_id, "abc123");
        assert_eq!(req.recovery_phrase, "word1 word2 ... word20");
    }

    #[test]
    fn test_recover_request_parsing() {
        let json = r#"{"recovery_phrase": "word1 word2 ... word20"}"#;
        let req: RecoverIdentityRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.recovery_phrase, "word1 word2 ... word20");
    }
}
