//! Backup and Recovery Handlers (Issue #100, #115)
//!
//! Provides 7 endpoints for identity backup and recovery:
//! - POST /api/v1/identity/backup/generate - Generate recovery phrase
//! - POST /api/v1/identity/backup/verify - Verify recovery phrase
//! - POST /api/v1/identity/recover - Recover identity from phrase
//! - GET /api/v1/identity/backup/status - Check backup status
//! - POST /api/v1/identity/backup/export - Export encrypted identity backup (Issue #115)
//! - POST /api/v1/identity/backup/import - Restore identity from encrypted backup (Issue #115)
//! - POST /api/v1/identity/seed/verify - Verify seed phrase is correct (Issue #115)

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose};
use lib_storage;
use lib_blockchain;

// ZHTP protocol imports
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

// Identity management imports
use lib_identity::{IdentityManager, RecoveryPhraseManager, PhraseGenerationOptions, EntropySource, RecoveryPhrase};

// Session management
use crate::session_manager::SessionManager;

// BIP39 and deterministic root key generation for recovery
use super::bip39::entropy_from_mnemonic;
use lib_identity_core::{derive_root_secret64_from_recovery_entropy, did_from_root_signing_public_key, RecoveryEntropy32, RootSigningKeypair};

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
    let session = match session_manager.validate_session(&req.session_token, &client_ip, &user_agent).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                format!("Invalid session: {}", e),
            ));
        }
    };

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

    // Validate word count (accept both 20-word custom and 24-word BIP39 standard)
    if words.len() != 20 && words.len() != 24 {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            format!("Recovery phrase must be 20 or 24 words, got {}", words.len()),
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
    tracing::debug!("Recovery handler entered, body_len={}", request_body.len());

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

    // Validate word count (accept both 20-word custom and 24-word BIP39 standard)
    if words.len() != 20 && words.len() != 24 {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            format!("Recovery phrase must be 20 or 24 words, got {}", words.len()),
        ));
    }

    // Restore identity from phrase using appropriate method based on word count

    let identity_id = if words.len() == 24 {
        // 24-word BIP39 standard - derive identity using lib-client's method:
        // 1. Extract 32-byte entropy from mnemonic (NOT BIP39 PBKDF2)
        // 2. Generate Dilithium keypair from entropy (deterministic)
        // 3. Hash public key to get DID

        let phrase_str = words.join(" ");

        // Step 1: Extract 32-byte entropy from mnemonic
        let entropy = entropy_from_mnemonic(&phrase_str)
            .map_err(|e| anyhow::anyhow!("Failed to extract entropy: {}", e))?;

        // Step 2: Derive root signing public key via RootSecret HKDF step (NEW invariant; breaking change)
        let entropy32: [u8; 32] = entropy.as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Entropy must be 32 bytes"))?;
        let rs = derive_root_secret64_from_recovery_entropy(&RecoveryEntropy32(entropy32))?;
        let rsk = RootSigningKeypair::from_root_secret(&rs)?;

        // Step 3: DID is anchored to root signing public key
        let did = did_from_root_signing_public_key(&rsk.public_key);

        // Step 4: Extract identity_id from DID
        let id_hex = did.strip_prefix("did:zhtp:")
            .ok_or_else(|| anyhow::anyhow!("Invalid DID format"))?;
        lib_crypto::Hash::from_hex(id_hex)
            .map_err(|e| anyhow::anyhow!("Invalid identity hash: {}", e))?
    } else {
        // 20-word custom format - use legacy Blake3 derivation
        let phrase_manager = recovery_phrase_manager.read().await;
        let (id, _private_key, _public_key, _seed) = phrase_manager
            .restore_from_phrase(&words)
            .await
            .map_err(|e| anyhow::anyhow!("Identity recovery failed: {}", e))?;
        drop(phrase_manager);
        id
    };

    // Verify identity exists in IdentityManager
    let manager = identity_manager.read().await;

    let identity = match manager.get_identity(&identity_id) {
        Some(id) => id,
        None => {
            tracing::debug!("Recovery: identity not found for derived id");
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "Identity not found in storage".to_string(),
            ));
        }
    };
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
    let _identity_id = match query_params.split('=').nth(1) {
        Some(id) => id,
        None => {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Missing identity_id parameter".to_string(),
            ));
        }
    };

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

/// Request for exporting encrypted backup
#[derive(Debug, Deserialize)]
pub struct ExportBackupRequest {
    pub identity_id: String,
    pub passphrase: String,
}

/// Response for backup export
#[derive(Debug, Serialize)]
pub struct ExportBackupResponse {
    pub backup_data: String,
    pub created_at: u64,
}

/// Handle POST /api/v1/identity/backup/export
pub async fn handle_export_backup(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    request: &lib_protocols::types::ZhtpRequest,
) -> ZhtpResult<ZhtpResponse> {
    // Parse request
    let req: ExportBackupRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

    // Extract client IP and User-Agent for session validation
    let client_ip = request.headers.get("X-Real-IP")
        .or_else(|| request.headers.get("X-Forwarded-For").and_then(|f| {
            f.split(',').next().map(|s| s.trim().to_string())
        }))
        .unwrap_or_else(|| "unknown".to_string());

    let user_agent = request.headers.get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string());

    // Validate session via Authorization header
    let session_token = match request.headers.get("Authorization")
        .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
        Some(token) => token,
        None => {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                "Missing or invalid Authorization header".to_string(),
            ));
        }
    };

    let session = match session_manager.validate_session(&session_token, &client_ip, &user_agent).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                format!("Invalid session: {}", e),
            ));
        }
    };

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

    // Security: Validate passphrase strength (minimum 12 characters)
    if req.passphrase.len() < 12 {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            "Passphrase must be at least 12 characters".to_string(),
        ));
    }

    // Get identity data
    let manager = identity_manager.read().await;
    let identity = manager
        .get_identity(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;

    // Serialize identity data
    let identity_json = serde_json::to_string(&identity)
        .map_err(|e| anyhow::anyhow!("Failed to serialize identity: {}", e))?;
    drop(manager);

    // Encrypt identity data with passphrase using ChaCha20-Poly1305
    use lib_crypto::symmetric::chacha20::encrypt_data;
    let encrypted_data = encrypt_data(identity_json.as_bytes(), req.passphrase.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Encode as base64 for transport
    let backup_data = general_purpose::STANDARD.encode(&encrypted_data);
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    tracing::info!(
        "Identity backup exported for: {}",
        &req.identity_id[..16]
    );

    // Build response
    let response = ExportBackupResponse {
        backup_data,
        created_at,
    };

    let json_response = serde_json::to_vec(&response)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

/// Request for importing encrypted backup
#[derive(Debug, Deserialize)]
pub struct ImportBackupRequest {
    pub backup_data: String,
    pub passphrase: String,
}

/// Response for backup import
#[derive(Debug, Serialize)]
pub struct ImportBackupResponse {
    pub status: String,
    pub identity: IdentityInfo,
    pub session_token: String,
}

/// Handle POST /api/v1/identity/backup/import
pub async fn handle_import_backup(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<crate::api::middleware::RateLimiter>,
    request: &lib_protocols::types::ZhtpRequest,
) -> ZhtpResult<ZhtpResponse> {
    // Extract client IP for rate limiting
    let client_ip = request.headers.get("X-Real-IP")
        .or_else(|| request.headers.get("X-Forwarded-For").and_then(|f| {
            f.split(',').next().map(|s| s.trim().to_string())
        }))
        .unwrap_or_else(|| "unknown".to_string());

    // CRITICAL: Rate limit import attempts (3 per hour per IP)
    if let Err(_) = rate_limiter.check_rate_limit_aggressive(&client_ip, 3, 3600).await {
        tracing::warn!("Backup import rate limit exceeded for IP: {}", &client_ip);
        return Ok(ZhtpResponse::error(
            ZhtpStatus::TooManyRequests,
            "Too many import attempts. Please try again later.".to_string(),
        ));
    }

    // Parse request
    let req: ImportBackupRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

    // Decode base64 backup data
    let encrypted_data = general_purpose::STANDARD.decode(&req.backup_data)
        .map_err(|e| anyhow::anyhow!("Invalid backup data encoding: {}", e))?;

    // Decrypt with passphrase
    use lib_crypto::symmetric::chacha20::decrypt_data;
    let decrypted_data = decrypt_data(&encrypted_data, req.passphrase.as_bytes())
        .map_err(|_| anyhow::anyhow!("Decryption failed - invalid passphrase or corrupted backup"))?;

    let identity_json = String::from_utf8(decrypted_data)
        .map_err(|e| anyhow::anyhow!("Invalid backup data format: {}", e))?;

    // Deserialize identity
    let identity: lib_identity::ZhtpIdentity = serde_json::from_str(&identity_json)
        .map_err(|e| anyhow::anyhow!("Failed to parse identity data: {}", e))?;

    // Get identity_id from the identity
    let identity_id = identity.id.clone();
    let identity_id_str = identity_id.to_string();

    // Store the restored identity in IdentityManager
    let mut manager = identity_manager.write().await;
    manager.add_identity(identity.clone());
    drop(manager);

    // Index the imported identity in DHT storage for bootstrap persistence
    if let Ok(storage) = crate::runtime::storage_provider::get_global_storage().await {
        let mut guard = storage.write().await;

        // Store identity record
        let identity_record = serde_json::json!({
            "did": identity.did,
            "identity_type": format!("{:?}", identity.identity_type),
            "imported_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        if let Ok(identity_data) = serde_json::to_vec(&identity_record) {
            if let Err(e) = guard.store_identity_record(&identity_id_str, &identity_data).await {
                tracing::warn!("Failed to persist imported identity to DHT (non-fatal): {}", e);
            }
        }

        // Add to identity index
        if let Err(e) = guard.add_to_identity_index(&identity_id_str).await {
            tracing::warn!("Failed to add imported identity to index (non-fatal): {}", e);
        }

        // Index wallets from the imported identity
        for wallet_summary in identity.wallet_manager.list_wallets() {
            let wallet_id_str = wallet_summary.id.to_string();
            if let Err(e) = guard.add_to_wallet_index(&identity_id_str, &wallet_id_str).await {
                tracing::warn!("Failed to add wallet {} to index (non-fatal): {}", wallet_id_str, e);
            }
        }
    }

    // Create new session for imported identity
    let session_token = session_manager
        .create_session(identity_id.clone(), &client_ip, "import-client")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create session: {}", e))?;

    tracing::info!(
        "Identity imported successfully: {}",
        hex::encode(&identity_id.0[..8])
    );

    // Build response
    let response = ImportBackupResponse {
        status: "success".to_string(),
        identity: IdentityInfo {
            identity_id: identity_id.to_string(),
            did: identity.did.clone(),
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

/// Request for verifying seed phrase
#[derive(Debug, Deserialize)]
pub struct VerifySeedPhraseRequest {
    pub identity_id: String,
    pub seed_phrase: String,
}

/// Response for seed phrase verification
#[derive(Debug, Serialize)]
pub struct VerifySeedPhraseResponse {
    pub verified: bool,
}

/// Handle POST /api/v1/identity/seed/verify
pub async fn handle_verify_seed_phrase(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    request: &lib_protocols::types::ZhtpRequest,
) -> ZhtpResult<ZhtpResponse> {
    // Parse request
    let req: VerifySeedPhraseRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

    // Extract client IP and User-Agent for session validation
    let client_ip = request.headers.get("X-Real-IP")
        .or_else(|| request.headers.get("X-Forwarded-For").and_then(|f| {
            f.split(',').next().map(|s| s.trim().to_string())
        }))
        .unwrap_or_else(|| "unknown".to_string());

    let user_agent = request.headers.get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string());

    // Validate session via Authorization header
    let session_token = match request.headers.get("Authorization")
        .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
        Some(token) => token,
        None => {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                "Missing or invalid Authorization header".to_string(),
            ));
        }
    };

    let session = match session_manager.validate_session(&session_token, &client_ip, &user_agent).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                format!("Invalid session: {}", e),
            ));
        }
    };

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

    // Parse seed phrase (12 words for BIP39)
    let words: Vec<String> = req.seed_phrase
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Validate word count
    if words.len() != 12 {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            "Seed phrase must be 12 words".to_string(),
        ));
    }

    // Get identity to verify it exists
    let manager = identity_manager.read().await;
    let identity_exists = manager.get_identity(&identity_id).is_some();
    drop(manager);

    if !identity_exists {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::NotFound,
            "Identity not found".to_string(),
        ));
    }

    // TODO: Implement proper seed phrase verification
    // For now, just validate the format is correct (12 words from BIP39 wordlist)
    // A full implementation would derive the identity from the seed and compare
    let verified = words.len() == 12; // Basic validation only

    tracing::info!(
        "Seed phrase verification for identity {}: verified={}",
        &req.identity_id[..16],
        verified
    );

    // Build response
    let response = VerifySeedPhraseResponse { verified };

    let json_response = serde_json::to_vec(&response)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

// =============================================================================
// SEED-ONLY MIGRATION ENDPOINT
// One-time fix for users with broken seed phrases who lost their old private key.
// This is NOT proving ownership of old identity - it's controlled re-registration.
// =============================================================================

/// Request for seed-only migration (user has seed but no old private key)
#[derive(Debug, Deserialize, Serialize)]
pub struct MigrateIdentityRequest {
    /// Display name to claim from existing identity
    pub display_name: String,
    /// New Dilithium5 public key (hex encoded, derived from seed on client)
    pub new_public_key: String,
    /// Device ID
    pub device_id: String,
    /// Timestamp for signature freshness (unix seconds)
    pub timestamp: u64,
    /// Signature over "SEED_MIGRATE:{display_name}:{new_public_key}:{timestamp}"
    /// using the NEW seed-derived private key (proves control of seed)
    pub signature: String,
}

/// Response for migration
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrateIdentityResponse {
    pub status: String,
    pub new_did: String,
    pub old_did: String,
    pub display_name: String,
    pub message: String,
}

/// Handle POST /api/v1/identity/migrate
///
/// Seed-only migration for users who have their seed phrase but lost access to old private key.
/// This is NOT proving ownership of old identity - it's controlled re-registration.
///
/// Flow:
/// 1. Client derives NEW keypair from seed phrase
/// 2. Client signs request with NEW key (proves control of seed)
/// 3. Server finds identity by display_name
/// 4. Server creates new identity, transfers display_name
/// 5. Old identity is marked as migrated/abandoned
///
/// SECURITY:
/// - Signature verified with NEW public key (proves seed control)
/// - Rate limited: 3 attempts/hour per IP
/// - One migration per display_name ever
/// - 5-minute timestamp window prevents replay
pub async fn handle_migrate_identity(
    request_body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    rate_limiter: Arc<crate::api::middleware::RateLimiter>,
    request: &lib_protocols::types::ZhtpRequest,
    storage_system: Arc<RwLock<lib_storage::PersistentStorageSystem>>,
) -> ZhtpResult<ZhtpResponse> {
    const MIN_DILITHIUM_PK_LEN: usize = 1312;
    // Hard gate: this is a one-time migration operation. It must be explicitly enabled.
    if std::env::var("ZHTP_ENABLE_IDENTITY_MIGRATION")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false)
        != true
    {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::NotFound,
            "Migration endpoint disabled".to_string(),
        ));
    }
    // Safety: never allow this endpoint on mainnet.
    let chain_id = std::env::var("ZHTP_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0x03);
    if chain_id == 0x01 {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::NotFound,
            "Migration endpoint disabled".to_string(),
        ));
    }

    // Extract client IP for rate limiting and audit logging.
    let peer_addr = request.headers.get("peer_addr");
    let reported_ip = request.headers.get("X-Real-IP")
        .or_else(|| request.headers.get("X-Forwarded-For").and_then(|f| {
            f.split(',').next().map(|s| s.trim().to_string())
        }))
        .unwrap_or_else(|| "unknown".to_string());

    let user_agent = request.headers.get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string());
    let audit_ip = peer_addr.clone().unwrap_or_else(|| reported_ip.clone());

    // SECURITY: Rate limit migration attempts (3 per hour per IP)
    // Migrations are one-time operations, aggressive limiting is appropriate.
    let rate_limit_key = audit_ip.clone();
    if let Err(_) = rate_limiter.check_rate_limit_aggressive(&rate_limit_key, 3, 3600).await {
        tracing::warn!(
            "🔄 Migration rate limit exceeded for key: {} user_agent: {} reported_ip: {} audit_ip: {}",
            &rate_limit_key, &user_agent, &reported_ip, &audit_ip
        );
        return Ok(ZhtpResponse::error(
            ZhtpStatus::TooManyRequests,
            "Too many migration attempts. Please try again later.".to_string(),
        ));
    }

    // Parse request
    let req: MigrateIdentityRequest = serde_json::from_slice(request_body)
        .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

    // Validate timestamp freshness (within 5 minutes)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if req.timestamp > now + 60 || req.timestamp < now.saturating_sub(300) {
        rate_limiter.record_failed_attempt(&rate_limit_key).await;
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            "Timestamp out of range (must be within 5 minutes)".to_string(),
        ));
    }

    // Decode new public key
    let new_public_key_bytes = hex::decode(&req.new_public_key)
        .map_err(|_| anyhow::anyhow!("Invalid new public key hex"))?;

    if new_public_key_bytes.len() != 2592 {
        rate_limiter.record_failed_attempt(&rate_limit_key).await;
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            format!("Invalid Dilithium5 public key size: expected 2592, got {}", new_public_key_bytes.len()),
        ));
    }

    // Decode signature
    let signature_bytes = hex::decode(&req.signature)
        .map_err(|_| anyhow::anyhow!("Invalid signature hex"))?;

    // Convert to lib_crypto::PublicKey (computes key_id = Blake3(dilithium_pk))
    let new_public_key = lib_crypto::PublicKey::new(new_public_key_bytes.clone());
    let new_did = format!("did:zhtp:{}", hex::encode(new_public_key.key_id));

    // SECURITY: Verify signature using NEW public key (proves control of seed-derived key)
    // Message format: "SEED_MIGRATE:{display_name}:{new_public_key}:{timestamp}"
    let signed_message = format!("SEED_MIGRATE:{}:{}:{}", req.display_name, req.new_public_key, req.timestamp);

    tracing::info!(
        "🔄 MIGRATION DEBUG: msg_len={} sig_len={} pk_len={} msg_preview='{}'",
        signed_message.len(), signature_bytes.len(), new_public_key_bytes.len(),
        &signed_message[..std::cmp::min(80, signed_message.len())]
    );

    // Use crystals-dilithium verification for seed-derived signatures from lib-client
    let signature_valid = lib_crypto::post_quantum::dilithium::dilithium5_verify_crystals(
        signed_message.as_bytes(),
        &signature_bytes,
        &new_public_key_bytes,
    ).unwrap_or(false);

    if !signature_valid {
        tracing::warn!(
            "🔄 Migration failed: invalid signature for display_name='{}' sig_len={} pk_len={} msg_len={} key={} reported_ip={} audit_ip={}",
            &req.display_name, signature_bytes.len(), new_public_key_bytes.len(), signed_message.len(), &rate_limit_key, &reported_ip, &audit_ip
        );
        rate_limiter.record_failed_attempt(&rate_limit_key).await;
        return Ok(ZhtpResponse::error(
            ZhtpStatus::Unauthorized,
            "Invalid signature - could not verify control of seed-derived key".to_string(),
        ));
    }

    let manager = identity_manager.read().await;

    // Look up old identity by display_name
    let old_identity = manager.list_identities()
        .into_iter()
        .find(|id| {
            id.metadata.get("display_name")
                .map(|n| n == &req.display_name)
                .unwrap_or(false)
        })
        .cloned();

    let old_identity = match old_identity {
        Some(id) => id,
        None => {
            tracing::warn!(
                "🔄 Migration failed: display_name '{}' not found key={} reported_ip={} audit_ip={}",
                &req.display_name, &rate_limit_key, &reported_ip, &audit_ip
            );
            rate_limiter.record_failed_attempt(&rate_limit_key).await;
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("No identity found with display_name '{}'", req.display_name),
            ));
        }
    };
    drop(manager);

    let old_did = old_identity.did.clone();
    let display_name = old_identity.metadata.get("display_name").cloned()
        .unwrap_or_else(|| "unnamed".to_string());

    // Optional dry-run: validate inputs and compute what would change, but do not mutate state.
    let dry_run_enabled = std::env::var("ZHTP_IDENTITY_MIGRATION_DRY_RUN")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    if dry_run_enabled {
        let manager = identity_manager.read().await;
        let mut wallet_ids_all: std::collections::HashSet<String> = old_identity
            .wallet_manager
            .wallets
            .keys()
            .map(|wid| hex::encode(wid.0))
            .collect();

        let mut registry_owned_count = 0usize;
        let mut short_key_count = 0usize;
        let mut short_key_min_len: Option<usize> = None;
        let mut short_key_max_len: Option<usize> = None;
        let mut short_key_backfill_total: u64 = 0;
        let mut movable_balance_total: u64 = 0;
        let mut has_token_contract = false;

        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(shared_blockchain) => {
                let blockchain = shared_blockchain.read().await;
                let old_identity_id_chain = lib_blockchain::Hash::from_slice(old_identity.id.as_bytes());
                let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();
                let token_opt = blockchain.token_contracts.get(&sov_token_id);
                has_token_contract = token_opt.is_some();

                for (wallet_id_str, wallet_data) in blockchain.wallet_registry.iter() {
                    if wallet_data.owner_identity_id == Some(old_identity_id_chain.clone()) {
                        registry_owned_count += 1;
                        wallet_ids_all.insert(wallet_id_str.clone());

                        let key_len = wallet_data.public_key.len();
                        if key_len < MIN_DILITHIUM_PK_LEN {
                            short_key_count += 1;
                            short_key_backfill_total = short_key_backfill_total.saturating_add(wallet_data.initial_balance);
                            short_key_min_len = Some(short_key_min_len.map(|v| v.min(key_len)).unwrap_or(key_len));
                            short_key_max_len = Some(short_key_max_len.map(|v| v.max(key_len)).unwrap_or(key_len));
                        } else if let Some(token) = token_opt {
                            let old_pk = lib_crypto::PublicKey::new(wallet_data.public_key.clone());
                            let new_pk = lib_crypto::PublicKey::new(new_public_key_bytes.clone());
                            if old_pk != new_pk {
                                movable_balance_total = movable_balance_total.saturating_add(token.balance_of(&old_pk));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("🔄 Migration dry-run failed to access blockchain: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Blockchain not available for dry-run. Please retry.".to_string(),
                ));
            }
        }

        drop(manager);

        let message = format!(
            "Dry-run: would migrate {} wallets ({} from registry), fix {} short-key wallets (key_len_range={}-{}, threshold={}), backfill_total={}, {} SOV balance to move, token_present={}",
            wallet_ids_all.len(),
            registry_owned_count,
            short_key_count,
            short_key_min_len.unwrap_or(0),
            short_key_max_len.unwrap_or(0),
            MIN_DILITHIUM_PK_LEN,
            short_key_backfill_total,
            movable_balance_total,
            has_token_contract
        );

        let response = MigrateIdentityResponse {
            status: "dry-run".to_string(),
            new_did,
            old_did,
            display_name,
            message,
        };

        let json_response = serde_json::to_vec(&response)?;
        return Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ));
    }

    // Load the migration authority (validator) signing keypair.
    // This is used to sign on-chain WalletUpdate transactions so they are durable and replay-safe.
    let migration_authority_kp = load_migration_authority_keypair()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load migration authority keypair: {}", e))?;

    let mut manager = identity_manager.write().await;

    // If the display_name is currently owned by a migration target, block re-migration.
    // Otherwise, a second call would migrate the newly-created identity again.
    if old_identity.metadata.get("migrated_from").is_some() {
        let source = old_identity
            .metadata
            .get("migrated_from")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        tracing::warn!(
            "🔄 Migration blocked: display_name '{}' is already attached to a migrated identity (source={}) - key={} reported_ip={} audit_ip={} user_agent={}",
            &display_name, source,
            &rate_limit_key, &reported_ip, &audit_ip, &user_agent
        );
        rate_limiter.record_failed_attempt(&rate_limit_key).await;
        return Ok(ZhtpResponse::error(
            ZhtpStatus::Conflict,
            "This display_name has already been migrated. Only one migration is allowed.".to_string(),
        ));
    }

    // AUDIT LOG: Record migration attempt
    tracing::info!(
        "🔄 MIGRATION ATTEMPT: old_did={} new_did={} display_name='{}' key={} reported_ip={} audit_ip={} user_agent={}",
        &old_did, &new_did, &display_name, &rate_limit_key, &reported_ip, &audit_ip, &user_agent
    );

    // Check if already migrated
    if let Some(migrated_to) = old_identity.metadata.get("migrated_to") {
        tracing::warn!(
            "🔄 Migration blocked: {} already migrated to {} - key={} reported_ip={} audit_ip={} user_agent={}",
            &old_did, migrated_to, &rate_limit_key, &reported_ip, &audit_ip, &user_agent
        );
        rate_limiter.record_failed_attempt(&rate_limit_key).await;
        return Ok(ZhtpResponse::error(
            ZhtpStatus::Conflict,
            "This identity has already been migrated. Only one migration allowed.".to_string(),
        ));
    }

    // Check if new DID already exists
    if manager.get_identity_by_did(&new_did).is_some() {
        tracing::warn!(
            "🔄 Migration blocked: new DID {} already registered - key={} reported_ip={} audit_ip={} user_agent={}",
            &new_did, &rate_limit_key, &reported_ip, &audit_ip, &user_agent
        );
        rate_limiter.record_failed_attempt(&rate_limit_key).await;
        return Ok(ZhtpResponse::error(
            ZhtpStatus::Conflict,
            "New DID already registered".to_string(),
        ));
    }

    // Identity ID is the key_id encoded in the DID
    let new_identity_id = lib_crypto::Hash::from_bytes(&new_public_key.key_id);

    // Register new identity with the display_name from old identity
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Register external identity (client-side generated keys)
    if let Err(e) = manager.register_external_identity(
        new_identity_id.clone(),
        new_did.clone(),
        new_public_key,
        lib_identity::IdentityType::Human,
        req.device_id.clone(),
        Some(display_name.clone()),
        created_at,
    ) {
        rate_limiter.record_failed_attempt(&rate_limit_key).await;
        return Err(anyhow::anyhow!("Failed to register new identity: {}", e));
    }

    // Mark old identity as migrated and collect wallet info for transfer
    let mut wallet_ids_to_transfer: Vec<(lib_identity::wallets::WalletId, String, u64)> = Vec::new();
    let mut old_wallet_manager: Option<lib_identity::wallets::WalletManager> = None;

    if let Some(old_id) = manager.get_identity_mut(&old_identity.id) {
        old_id.metadata.insert("migrated_to".to_string(), new_did.clone());
        old_id.metadata.insert("migrated_at".to_string(), created_at.to_string());
        old_id.metadata.insert("migrated_ip".to_string(), audit_ip.clone());
        old_id.metadata.remove("display_name"); // Remove display_name from old

        // Collect wallet IDs from old identity for transfer
        for (wallet_id, wallet) in &old_id.wallet_manager.wallets {
            let wallet_type = format!("{:?}", wallet.wallet_type);
            let balance = wallet.balance;
            wallet_ids_to_transfer.push((wallet_id.clone(), wallet_type.clone(), balance));
            tracing::info!(
                "🔄 Wallet to transfer: id={} type={} balance={}",
                hex::encode(wallet_id.0),
                wallet_type,
                balance
            );
        }

        // Move wallets by cloning then clearing. This ensures wallets are owned by exactly one identity.
        old_wallet_manager = Some(old_id.wallet_manager.clone());
        old_id.wallet_manager.wallets.clear();
        old_id.wallet_manager.alias_map.clear();
        old_id.wallet_manager.total_balance = 0;
    }

    // Transfer wallets to new identity
    if let Some(mut wallet_manager) = old_wallet_manager {
        // Update owner_id to new identity (IdentityId is a type alias for Hash)
        wallet_manager.owner_id = Some(new_identity_id.clone());

        if let Some(new_id) = manager.get_identity_mut(&new_identity_id) {
            new_id.wallet_manager = wallet_manager;
            new_id.metadata.insert("migrated_from".to_string(), old_did.clone());
            new_id.metadata.insert("migration_type".to_string(), "seed-only".to_string());
            tracing::info!(
                "🔄 Transferred {} wallets to new identity",
                new_id.wallet_manager.wallets.len()
            );
        }
    }

    drop(manager);

    // ---------------------------------------------------------------------
    // CHAIN: Make the migration durable by encoding it into mined blocks.
    // - Register new DID on-chain (if not already present)
    // - Update wallet registry owner/public_key via WalletUpdate txs
    // - Mine a block immediately so restart/replay keeps the rebind
    // ---------------------------------------------------------------------
    match crate::runtime::blockchain_provider::get_global_blockchain().await {
        Ok(shared_blockchain) => {
            let mut blockchain = shared_blockchain.write().await;
            let old_identity_id_chain = lib_blockchain::Hash::from_slice(old_identity.id.as_bytes());
            let new_identity_id_chain = lib_blockchain::Hash::from_slice(new_identity_id.as_bytes());

            // Collect any wallets in the chain registry still owned by the old identity.
            // This fixes cases where wallet_manager is incomplete (e.g., short-key wallets).
            let mut wallet_ids_all: std::collections::HashSet<String> = wallet_ids_to_transfer
                .iter()
                .map(|(wid, _, _)| hex::encode(wid.0))
                .collect();
            for (wallet_id_str, wallet_data) in blockchain.wallet_registry.iter() {
                if wallet_data.owner_identity_id == Some(old_identity_id_chain.clone()) {
                    wallet_ids_all.insert(wallet_id_str.clone());
                }
            }

            // Ensure new DID exists on-chain so wallet owner references aren't dangling.
            if !blockchain.identity_exists(&new_did) {
                let identity_tx = lib_blockchain::transaction::IdentityTransactionData {
                    did: new_did.clone(),
                    display_name: display_name.clone(),
                    public_key: new_public_key_bytes.clone(),
                    ownership_proof: vec![], // system-style migration registration
                    identity_type: "human".to_string(),
                    did_document_hash: lib_blockchain::Hash::zero(),
                    created_at,
                    registration_fee: 0,
                    dao_fee: 0,
                    controlled_nodes: vec![],
                    owned_wallets: wallet_ids_all.iter().cloned().collect(),
                };

                if let Err(e) = blockchain.register_identity(identity_tx) {
                    tracing::warn!("🔄 Failed to register migrated identity on-chain (will still attempt wallet updates): {}", e);
                }
            }

                // Enqueue wallet updates (system transaction with explicit memo prefix).
                // Prepare TokenMint txs for balance fixes during migration.
                let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();
                let mut mint_txs: Vec<lib_blockchain::Transaction> = Vec::new();

            for wallet_id_str in wallet_ids_all.iter() {
                let wallet_id_bytes = match hex::decode(wallet_id_str) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        arr
                    }
                    _ => {
                        tracing::warn!(
                            "🪙 Migration skipped: invalid wallet_id {}",
                            &wallet_id_str[..16.min(wallet_id_str.len())]
                        );
                        continue;
                    }
                };
                let wallet_addr = lib_crypto::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id: wallet_id_bytes,
                };

                if let Some(existing) = blockchain.wallet_registry.get(wallet_id_str).cloned() {
                    let wallet_type = existing.wallet_type.clone();
                    let old_public_key = existing.public_key.clone();
                    let old_pk_is_short = old_public_key.len() < MIN_DILITHIUM_PK_LEN;

                    // Build TokenMint txs for balance fixes
                    if old_pk_is_short {
                        if existing.initial_balance > 0 {
                            let token_opt = blockchain.token_contracts.get(&sov_token_id);
                            let current_balance = token_opt.map(|t| t.balance_of(&wallet_addr)).unwrap_or(0);
                            if current_balance < existing.initial_balance {
                                let mint_amount = existing.initial_balance - current_balance;
                                let memo = format!("TOKEN_BACKFILL_V1:{}", wallet_id_str).into_bytes();
                                if let Ok(tx) = build_signed_sov_mint_tx(
                                    &migration_authority_kp,
                                    chain_id,
                                    &wallet_id_bytes,
                                    mint_amount,
                                    memo,
                                ) {
                                    mint_txs.push(tx);
                                    tracing::info!(
                                        "🪙 Migration SOV backfill queued: {} to wallet {} (short key, key_len={}, current={})",
                                        mint_amount,
                                        &wallet_id_str[..16.min(wallet_id_str.len())],
                                        old_public_key.len(),
                                        current_balance
                                    );
                                }
                            } else {
                                tracing::info!(
                                    "🪙 Migration backfill skipped: wallet {} already has {} SOV (short key, key_len={})",
                                    &wallet_id_str[..16.min(wallet_id_str.len())],
                                    current_balance,
                                    old_public_key.len()
                                );
                            }
                        }
                    } else {
                        if let Some(token) = blockchain.token_contracts.get(&sov_token_id) {
                            let old_pk = lib_crypto::PublicKey::new(old_public_key.clone());
                            if old_pk.key_id != wallet_addr.key_id {
                                let old_balance = token.balance_of(&old_pk);
                                if old_balance > 0 {
                                    let memo = format!("TOKEN_MIGRATE_V1:{}", hex::encode(&old_public_key)).into_bytes();
                                    if let Ok(tx) = build_signed_sov_mint_tx(
                                        &migration_authority_kp,
                                        chain_id,
                                        &wallet_id_bytes,
                                        old_balance,
                                        memo,
                                    ) {
                                        mint_txs.push(tx);
                                        tracing::info!(
                                            "🪙 Migration SOV move queued: {} from old key to new key for wallet {}",
                                            old_balance,
                                            &wallet_id_str[..16.min(wallet_id_str.len())]
                                        );
                                    }
                                }
                            }
                        }
                    }

                    let mut updated = existing.clone();
                    updated.owner_identity_id = Some(new_identity_id_chain.clone());
                    updated.public_key = new_public_key_bytes.clone();

                    // Ensure consensus-level chain_id matches the running chain configuration.
                    let mut tx = lib_blockchain::transaction::Transaction::new_wallet_update_with_chain_id(
                        chain_id,
                        updated.clone(),
                        vec![],
                        // Placeholder signature gets replaced below (WalletUpdate requires real signature).
                        lib_blockchain::integration::crypto_integration::Signature {
                            signature: Vec::new(),
                            public_key: migration_authority_kp.public_key.clone(),
                            algorithm: lib_blockchain::integration::crypto_integration::SignatureAlgorithm::Dilithium5,
                            timestamp: created_at,
                        },
                        format!("WALLET_UPDATE_V1:migrate:{}:{}:{}", old_did, new_did, wallet_id_str).into_bytes(),
                    );

                    // Sign the transaction hash (signing_hash excludes the signature field).
                    let signing_hash = tx.signing_hash();
                    let sig = lib_crypto::sign_message(&migration_authority_kp, signing_hash.as_bytes())
                        .map_err(|e| anyhow::anyhow!("Failed to sign WalletUpdate: {}", e))?;
                    tx.signature = sig;

                    if let Err(e) = blockchain.add_system_transaction(tx) {
                        tracing::warn!("🔄 Failed to enqueue wallet update tx for {} ({}): {}", &wallet_id_str[..16.min(wallet_id_str.len())], wallet_type, e);
                    } else {
                        // Update in-memory view immediately (the block will make it durable).
                        blockchain.wallet_registry.insert(wallet_id_str.clone(), updated);
                    }
                } else {
                    tracing::warn!("🔄 Wallet {} not found in blockchain registry; cannot rebind owner", &wallet_id_str[..16.min(wallet_id_str.len())]);
                }
            }

                for tx in mint_txs {
                    if let Err(e) = blockchain.add_pending_transaction(tx) {
                        tracing::warn!("🪙 Failed to enqueue migration TokenMint tx: {}", e);
                    }
                }

            // Mine immediately to persist to SledStore and make replay deterministic.
            if let Err(e) = crate::runtime::services::mining_service::MiningService::mine_block(&mut *blockchain).await {
                tracing::warn!("🔄 Failed to mine migration block (aborting persistence): {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Migration failed to persist on-chain. Please retry.".to_string(),
                ));
            }
        }
        Err(e) => {
            tracing::warn!("🔄 Failed to get blockchain for wallet update (aborting persistence): {}", e);
            return Ok(ZhtpResponse::error(
                ZhtpStatus::InternalServerError,
                "Blockchain not available for migration persistence. Please retry.".to_string(),
            ));
        }
    }

    // ---------------------------------------------------------------------
    // DHT: Persist identity records + indexes for bootstrap/recovery.
    // This is written only after the chain mutation is mined, to avoid divergence.
    // ---------------------------------------------------------------------
    let identity_id_str = hex::encode(new_identity_id.as_bytes());
    let old_identity_id_str = hex::encode(old_identity.id.as_bytes());

    let primary_wallet_id = wallet_ids_to_transfer
        .iter()
        .find(|(_, t, _)| t.contains("Primary"))
        .map(|(wid, _, _)| hex::encode(wid.0));
    let ubi_wallet_id = wallet_ids_to_transfer
        .iter()
        .find(|(_, t, _)| t.contains("UBI"))
        .map(|(wid, _, _)| hex::encode(wid.0));
    let savings_wallet_id = wallet_ids_to_transfer
        .iter()
        .find(|(_, t, _)| t.contains("Savings"))
        .map(|(wid, _, _)| hex::encode(wid.0));

    let identity_record = serde_json::json!({
        "did": new_did.clone(),
        "public_key": hex::encode(&new_public_key_bytes),
        "display_name": display_name.clone(),
        "device_id": req.device_id.clone(),
        "identity_type": "Human",
        "created_at": created_at,
        "migrated_from": old_did.clone(),
        "primary_wallet_id": primary_wallet_id,
        "ubi_wallet_id": ubi_wallet_id,
        "savings_wallet_id": savings_wallet_id,
    });

    if let Ok(identity_data) = serde_json::to_vec(&identity_record) {
        let mut storage = storage_system.write().await;
        if let Err(e) = storage.store_identity_record(&identity_id_str, &identity_data).await {
            tracing::warn!("Failed to persist migrated identity to storage (non-fatal): {}", e);
        } else {
            tracing::info!("🔄 Migrated identity {} persisted to storage", &new_did);
        }
        if let Err(e) = storage.add_to_identity_index(&identity_id_str).await {
            tracing::warn!("Failed to add migrated identity to index (non-fatal): {}", e);
        }

        // Ensure wallet indexes reflect the transfer across restarts.
        for (wallet_id, _wallet_type, _balance) in &wallet_ids_to_transfer {
            let wallet_id_str = hex::encode(wallet_id.0);
            if let Err(e) = storage.add_to_wallet_index(&identity_id_str, &wallet_id_str).await {
                tracing::warn!(
                    "Failed to add wallet {} to new identity index (non-fatal): {}",
                    &wallet_id_str[..16.min(wallet_id_str.len())],
                    e
                );
            }
        }
        if let Err(e) = storage.clear_wallet_index_for_identity(&old_identity_id_str).await {
            tracing::warn!("Failed to clear old identity wallet index (non-fatal): {}", e);
        }

        // Tombstone the old identity record.
        match storage.get_identity_record(&old_identity_id_str).await {
            Ok(Some(old_record_bytes)) => {
                if let Ok(mut old_json) = serde_json::from_slice::<serde_json::Value>(&old_record_bytes) {
                    if let Some(obj) = old_json.as_object_mut() {
                        obj.remove("display_name");
                        obj.remove("primary_wallet_id");
                        obj.remove("ubi_wallet_id");
                        obj.remove("savings_wallet_id");
                        obj.insert("migrated_to".to_string(), serde_json::Value::String(new_did.clone()));
                        obj.insert(
                            "migrated_at".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(created_at)),
                        );
                        obj.insert("migrated_ip".to_string(), serde_json::Value::String(audit_ip.clone()));
                    }
                    if let Ok(updated_bytes) = serde_json::to_vec(&old_json) {
                        if let Err(e) = storage.store_identity_record(&old_identity_id_str, &updated_bytes).await {
                            tracing::warn!("Failed to persist old identity tombstone (non-fatal): {}", e);
                        }
                    }
                }
            }
            Ok(None) => {
                let tombstone = serde_json::json!({
                    "did": old_did.clone(),
                    "identity_type": "Human",
                    "created_at": 0u64,
                    "migrated_to": new_did.clone(),
                    "migrated_at": created_at,
                    "migrated_ip": audit_ip.clone(),
                });
                if let Ok(tombstone_bytes) = serde_json::to_vec(&tombstone) {
                    if let Err(e) = storage.store_identity_record(&old_identity_id_str, &tombstone_bytes).await {
                        tracing::warn!("Failed to persist old identity tombstone (non-fatal): {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to load old identity record for tombstoning (non-fatal): {}", e);
            }
        }
    }

    // AUDIT LOG: Record successful migration
    tracing::info!(
        "🔄 MIGRATION SUCCESS: old_did={} new_did={} display_name='{}' key={} reported_ip={} audit_ip={} user_agent={}",
        &old_did, &new_did, &display_name, &rate_limit_key, &reported_ip, &audit_ip, &user_agent
    );

    let response = MigrateIdentityResponse {
        status: "success".to_string(),
        new_did,
        old_did,
        display_name,
        message: "Identity migrated successfully. Save your new seed phrase!".to_string(),
    };

    let json_response = serde_json::to_vec(&response)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

async fn load_migration_authority_keypair() -> anyhow::Result<lib_crypto::KeyPair> {
    use crate::keystore_names::{KeystorePrivateKey, NODE_PRIVATE_KEY_FILENAME};
    use std::path::PathBuf;

    let keystore_dir = std::env::var("ZHTP_KEYSTORE_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            dirs::home_dir().map(|h| h.join(".zhtp").join("keystore"))
        })
        .unwrap_or_else(|| PathBuf::from("."));

    let key_path = keystore_dir.join(NODE_PRIVATE_KEY_FILENAME);
    let key_json = tokio::fs::read_to_string(&key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", key_path, e))?;

    let ks: KeystorePrivateKey = serde_json::from_str(&key_json)
        .map_err(|e| anyhow::anyhow!("Invalid keystore key JSON {:?}: {}", key_path, e))?;

    if ks.dilithium_sk.is_empty() || ks.dilithium_pk.is_empty() {
        return Err(anyhow::anyhow!(
            "Keystore key {:?} missing dilithium_sk/dilithium_pk",
            key_path
        ));
    }

    let public_key = lib_crypto::PublicKey::new(ks.dilithium_pk.clone());
    let private_key = lib_crypto::PrivateKey {
        dilithium_sk: ks.dilithium_sk,
        dilithium_pk: ks.dilithium_pk,
        kyber_sk: ks.kyber_sk,
        master_seed: ks.master_seed,
    };

    Ok(lib_crypto::KeyPair { public_key, private_key })
}

// Build a signed TokenMint transaction using the provided validator keypair.
fn build_signed_sov_mint_tx(
    validator_kp: &lib_crypto::KeyPair,
    chain_id: u8,
    recipient_wallet_id: &[u8; 32],
    amount: u64,
    memo: Vec<u8>,
) -> anyhow::Result<lib_blockchain::Transaction> {
    let token_mint_data = lib_blockchain::transaction::TokenMintData {
        token_id: lib_blockchain::contracts::utils::generate_lib_token_id(),
        to: *recipient_wallet_id,
        amount: amount as u128,
    };

    let mut tx = lib_blockchain::Transaction::new_token_mint_with_chain_id(
        chain_id,
        token_mint_data,
        lib_blockchain::integration::crypto_integration::Signature {
            signature: Vec::new(),
            public_key: lib_blockchain::integration::crypto_integration::PublicKey::new(Vec::new()),
            algorithm: lib_blockchain::integration::crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        },
        memo,
    );

    let signing_hash = tx.signing_hash();
    let sig = lib_crypto::sign_message(validator_kp, signing_hash.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to sign TokenMint: {}", e))?;
    tx.signature = sig;

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use lib_protocols::types::{ZhtpHeaders, ZhtpMethod, ZhtpRequest, ZhtpStatus, ZHTP_VERSION};
    use zhtp_client::{build_migrate_identity_request_json, generate_identity};

    async fn build_persistent_storage() -> Arc<RwLock<lib_storage::PersistentStorageSystem>> {
        // Persist the tempdir path so sled keeps working for the duration of the test.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.into_path();
        let system = lib_storage::UnifiedStorageSystem::new_persistent(
            lib_storage::UnifiedStorageConfig::default(),
            path,
        )
        .await
        .expect("persistent storage init");
        Arc::new(RwLock::new(system))
    }

    fn build_identity_manager(
        old_pk_byte: u8,
        device_id: &str,
        display_name: &str,
    ) -> (IdentityManager, lib_crypto::Hash, String) {
        let old_pk_bytes = vec![old_pk_byte; 2592];
        let public_key = lib_crypto::PublicKey::new(old_pk_bytes);
        let did = format!("did:zhtp:{}", hex::encode(public_key.key_id));
        let identity_id = lib_crypto::Hash::from_bytes(&public_key.key_id);
        let identity = lib_identity::ZhtpIdentity::new_external(
            did.clone(),
            public_key,
            lib_identity::IdentityType::Human,
            device_id.to_string(),
            Some(display_name.to_string()),
            0,
        )
        .expect("failed to create identity");

        let mut manager = IdentityManager::new();
        manager.add_identity(identity);
        (manager, identity_id, did)
    }

    fn build_request(
        body: Vec<u8>,
        requester: Option<lib_crypto::Hash>,
        peer_addr: Option<&str>,
        forwarded_for: Option<&str>,
    ) -> ZhtpRequest {
        let mut headers = ZhtpHeaders::new();
        if let Some(addr) = peer_addr {
            headers = headers.with_custom_header("peer_addr".to_string(), addr.to_string());
        }
        if let Some(xff) = forwarded_for {
            headers = headers.with_custom_header("x-forwarded-for".to_string(), xff.to_string());
        }

        ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/migrate".to_string(),
            version: ZHTP_VERSION.to_string(),
            headers,
            body,
            timestamp: 0,
            requester,
            auth_proof: None,
        }
    }

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

    #[tokio::test]
    async fn test_migrate_requires_authentication() {
        let rate_limiter = Arc::new(crate::api::middleware::RateLimiter::new());
        let (manager, _identity_id, _did) = build_identity_manager(1, "device-old", "alice");
        let manager = Arc::new(RwLock::new(manager));
        let storage_system = build_persistent_storage().await;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let req = MigrateIdentityRequest {
            display_name: "alice".to_string(),
            new_public_key: hex::encode(vec![2u8; 2592]),
            device_id: "device-new".to_string(),
            timestamp,
            // Invalid signature to force Unauthorized
            signature: hex::encode(vec![0u8; 4595]),
        };
        let body = serde_json::to_vec(&req).unwrap();
        let request = build_request(body, None, Some("10.0.0.1:1234"), None);

        let response = handle_migrate_identity(
            &request.body,
            manager,
            rate_limiter,
            &request,
            storage_system,
        )
        .await
        .expect("handler failed");

        assert_eq!(response.status, ZhtpStatus::Unauthorized);
    }

    #[tokio::test]
    async fn test_migrate_derives_did_from_public_key() {
        let rate_limiter = Arc::new(crate::api::middleware::RateLimiter::new());
        let (manager, identity_id, _did) = build_identity_manager(3, "device-old", "alice");
        let manager = Arc::new(RwLock::new(manager));
        let storage_system = build_persistent_storage().await;

        // Generate a real crystals-dilithium keypair so signature verification succeeds.
        let seed = [7u8; 32];
        let kp = crystals_dilithium::dilithium5::Keypair::generate(Some(&seed));
        let new_pk_bytes = kp.public.to_bytes().to_vec();
        let expected_new_did = {
            let pk = lib_crypto::PublicKey::new(new_pk_bytes.clone());
            format!("did:zhtp:{}", hex::encode(pk.key_id))
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let signed_message = format!(
            "SEED_MIGRATE:{}:{}:{}",
            "alice",
            hex::encode(&new_pk_bytes),
            timestamp
        );
        let signature_bytes = kp.secret.sign(signed_message.as_bytes()).to_vec();

        let req = MigrateIdentityRequest {
            display_name: "alice".to_string(),
            new_public_key: hex::encode(new_pk_bytes),
            device_id: "device-new".to_string(),
            timestamp,
            signature: hex::encode(signature_bytes),
        };
        let body = serde_json::to_vec(&req).unwrap();
        let request = build_request(body, Some(identity_id.clone()), Some("10.0.0.2:5678"), None);

        let response = handle_migrate_identity(
            &request.body,
            manager.clone(),
            rate_limiter,
            &request,
            storage_system,
        )
        .await
        .expect("handler failed");

        assert_eq!(response.status, ZhtpStatus::Ok);
        let parsed: MigrateIdentityResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed.new_did, expected_new_did);

        let mgr = manager.read().await;
        let old_identity = mgr.get_identity(&identity_id).expect("old identity missing");
        assert!(old_identity.metadata.get("display_name").is_none());
        assert_eq!(
            old_identity.metadata.get("migrated_to"),
            Some(&parsed.new_did)
        );
    }

    #[tokio::test]
    async fn test_migrate_rate_limit_uses_peer_addr_not_forwarded_for() {
        let rate_limiter = Arc::new(crate::api::middleware::RateLimiter::new());
        let storage_system = build_persistent_storage().await;

        for i in 0..4u8 {
            let (manager, identity_id, _did) = build_identity_manager(10 + i, "device-old", "alice");
            let manager = Arc::new(RwLock::new(manager));

            let req = MigrateIdentityRequest {
                display_name: "alice".to_string(),
                // Invalid length to force failure and record rate limit attempts.
                new_public_key: hex::encode(vec![50 + i; 10]),
                device_id: "device-new".to_string(),
                timestamp: 1234567890u64,
                signature: hex::encode(vec![0u8; 4595]),
            };
            let body = serde_json::to_vec(&req).unwrap();
            let request = build_request(
                body,
                Some(identity_id),
                Some("192.0.2.1:4242"),
                Some(&format!("198.51.100.{}", i)),
            );

            let response = handle_migrate_identity(
                &request.body,
                manager,
                rate_limiter.clone(),
                &request,
                storage_system.clone(),
            )
            .await
            .expect("handler failed");

            if i < 3 {
                assert_eq!(response.status, ZhtpStatus::BadRequest);
            } else {
                assert_eq!(response.status, ZhtpStatus::TooManyRequests);
            }
        }
    }

    #[tokio::test]
    async fn test_migrate_end_to_end_payload_builder_transfers_wallets_exactly_once() {
        std::env::set_var("ZHTP_ENABLE_IDENTITY_MIGRATION", "1");
        std::env::set_var("ZHTP_CHAIN_ID", "3");

        let rate_limiter = Arc::new(crate::api::middleware::RateLimiter::new());
        let storage_system = build_persistent_storage().await;

        // Migration authority (validator) keypair + keystore wiring.
        // The handler loads `node_private_key.json` from `ZHTP_KEYSTORE_DIR`.
        let validator_kp = lib_crypto::KeyPair::generate().expect("validator keypair");
        let keystore_dir = tempfile::tempdir().expect("keystore tempdir");
        std::env::set_var("ZHTP_KEYSTORE_DIR", keystore_dir.path());
        let keystore_key = crate::keystore_names::KeystorePrivateKey {
            dilithium_sk: validator_kp.private_key.dilithium_sk.clone(),
            dilithium_pk: validator_kp.public_key.dilithium_pk.clone(),
            kyber_sk: validator_kp.private_key.kyber_sk.clone(),
            master_seed: validator_kp.private_key.master_seed.clone(),
        };
        std::fs::write(
            keystore_dir
                .path()
                .join(crate::keystore_names::NODE_PRIVATE_KEY_FILENAME),
            serde_json::to_vec(&keystore_key).expect("serialize keystore key"),
        )
        .expect("write node_private_key.json");

        // Old identity that currently owns display_name + wallets.
        let (mut manager, old_identity_id, old_did) = build_identity_manager(42, "device-old", "alice");
        let mut wallet_summaries: Vec<(lib_identity::wallets::WalletId, lib_identity::wallets::WalletType, String, Option<String>, Vec<u8>, u64, u64)> = Vec::new();
        {
            let old = manager
                .get_identity_mut(&old_identity_id)
                .expect("old identity missing");

            // Give the old identity a few wallets so we can verify "move" semantics.
            let (w1, _) = old
                .wallet_manager
                .create_wallet_with_seed_phrase(
                    lib_identity::wallets::WalletType::Primary,
                    "Primary".to_string(),
                    Some("primary".to_string()),
                )
                .await
                .expect("create primary wallet");
            if let Some(w) = old.wallet_manager.get_wallet_mut(&w1) {
                w.balance = 111;
                wallet_summaries.push((
                    w1.clone(),
                    lib_identity::wallets::WalletType::Primary,
                    w.name.clone(),
                    w.alias.clone(),
                    w.public_key.clone(),
                    w.created_at,
                    w.balance,
                ));
            }

            let (w2, _) = old
                .wallet_manager
                .create_wallet_with_seed_phrase(
                    lib_identity::wallets::WalletType::UBI,
                    "UBI".to_string(),
                    Some("ubi".to_string()),
                )
                .await
                .expect("create ubi wallet");
            if let Some(w) = old.wallet_manager.get_wallet_mut(&w2) {
                w.balance = 222;
                wallet_summaries.push((
                    w2.clone(),
                    lib_identity::wallets::WalletType::UBI,
                    w.name.clone(),
                    w.alias.clone(),
                    w.public_key.clone(),
                    w.created_at,
                    w.balance,
                ));
            }

            let (w3, _) = old
                .wallet_manager
                .create_wallet_with_seed_phrase(
                    lib_identity::wallets::WalletType::Savings,
                    "Savings".to_string(),
                    Some("savings".to_string()),
                )
                .await
                .expect("create savings wallet");
            if let Some(w) = old.wallet_manager.get_wallet_mut(&w3) {
                w.balance = 333;
                wallet_summaries.push((
                    w3.clone(),
                    lib_identity::wallets::WalletType::Savings,
                    w.name.clone(),
                    w.alias.clone(),
                    w.public_key.clone(),
                    w.created_at,
                    w.balance,
                ));
            }
        }

        let manager = Arc::new(RwLock::new(manager));

        // Seed the global blockchain provider with wallet records so the migration can persist
        // the rebind as an on-chain WalletUpdate + mined block.
        crate::runtime::blockchain_provider::initialize_global_blockchain_provider();
        let mut bc = lib_blockchain::Blockchain::new().expect("new blockchain");

        // Register an "active" validator so stateful WalletUpdate validation can authorize.
        let validator_did = {
            let pk = lib_crypto::PublicKey::new(validator_kp.public_key.dilithium_pk.clone());
            format!("did:zhtp:{}", hex::encode(pk.key_id))
        };
        // Use distinct byte patterns for each key role to satisfy the key separation invariant.
        let consensus_key = validator_kp.public_key.dilithium_pk.clone();
        let mut networking_key = validator_kp.public_key.dilithium_pk.clone();
        networking_key.iter_mut().for_each(|b| *b ^= 0xFF); // distinct from consensus_key
        let mut rewards_key = validator_kp.public_key.dilithium_pk.clone();
        rewards_key.iter_mut().for_each(|b| *b = b.wrapping_add(1)); // distinct from others
        bc.validator_registry.insert(
            validator_did.clone(),
            lib_blockchain::ValidatorInfo {
                identity_id: validator_did,
                stake: 1_000,
                storage_provided: 0,
                consensus_key,
                networking_key,
                rewards_key,
                network_address: "127.0.0.1:0".to_string(),
                commission_rate: 0,
                status: "active".to_string(),
                registered_at: 0,
                last_activity: 0,
                blocks_validated: 0,
                slash_count: 0,
                // Test helper: use genesis (off-chain) source since this is inserted
                // directly into the registry at height 0 for testing purposes.
                admission_source: lib_blockchain::blockchain::ADMISSION_SOURCE_OFFCHAIN_GENESIS.to_string(),
                governance_proposal_id: None,
            },
        );

        for (wid, wtype, name, alias, pk, created_at, balance) in &wallet_summaries {
            let wallet_id_hex = hex::encode(wid.0);
            let wallet_bytes = wid.0.clone();
            let wallet_hash = lib_blockchain::Hash::from_slice(&wallet_bytes);
            let seed_commitment = lib_blockchain::types::hash::blake3_hash(
                format!("seed_commitment:{}", wallet_id_hex).as_bytes(),
            );
            bc.wallet_registry.insert(
                wallet_id_hex,
                lib_blockchain::transaction::WalletTransactionData {
                    wallet_id: wallet_hash,
                    wallet_type: format!("{:?}", wtype),
                    wallet_name: name.clone(),
                    alias: alias.clone(),
                    public_key: pk.clone(),
                    owner_identity_id: Some(lib_blockchain::Hash::from_slice(&old_identity_id.0)),
                    seed_commitment,
                    created_at: *created_at,
                    registration_fee: 0,
                    capabilities: 0xFF,
                    initial_balance: *balance,
                },
            );
        }
        let bc = Arc::new(RwLock::new(bc));
        crate::runtime::blockchain_provider::set_global_blockchain(bc)
            .await
            .expect("set global blockchain");

        // First migration: build request JSON using lib-client helper.
        let new_identity_1 = generate_identity("device-new-1".to_string()).expect("generate identity");
        let body_json_1 = build_migrate_identity_request_json(&new_identity_1, "alice".to_string())
            .expect("build migrate json");
        let request_1 = build_request(body_json_1.into_bytes(), Some(old_identity_id.clone()), Some("10.0.0.10:1111"), None);

        let response_1 = handle_migrate_identity(
            &request_1.body,
            manager.clone(),
            rate_limiter.clone(),
            &request_1,
            storage_system.clone(),
        )
        .await
        .expect("handler failed");

        assert_eq!(response_1.status, ZhtpStatus::Ok);
        let parsed_1: MigrateIdentityResponse = serde_json::from_slice(&response_1.body).unwrap();
        assert_eq!(parsed_1.old_did, old_did);
        assert_eq!(parsed_1.new_did, new_identity_1.did);

        // Verify wallet ownership moved to the new identity, and old identity is empty.
        let new_identity_id_1 = {
            let pk = lib_crypto::PublicKey::new(new_identity_1.public_key.clone());
            lib_crypto::Hash::from_bytes(&pk.key_id)
        };

        {
            let mgr = manager.read().await;
            assert_eq!(mgr.list_identities().len(), 2);

            let old = mgr.get_identity(&old_identity_id).expect("old identity missing");
            assert!(old.metadata.get("display_name").is_none());
            assert_eq!(old.metadata.get("migrated_to"), Some(&parsed_1.new_did));
            assert!(old.wallet_manager.wallets.is_empty());

            let new = mgr.get_identity(&new_identity_id_1).expect("new identity missing");
            assert_eq!(new.metadata.get("migrated_from"), Some(&parsed_1.old_did));
            assert_eq!(new.wallet_manager.wallets.len(), 3);
        }

        // Second migration attempt for same display_name with a different new identity must fail,
        // and must not transfer wallets a second time.
        let new_identity_2 = generate_identity("device-new-2".to_string()).expect("generate identity");
        let body_json_2 = build_migrate_identity_request_json(&new_identity_2, "alice".to_string())
            .expect("build migrate json");
        let request_2 = build_request(body_json_2.into_bytes(), Some(old_identity_id.clone()), Some("10.0.0.11:2222"), None);

        let response_2 = handle_migrate_identity(
            &request_2.body,
            manager.clone(),
            rate_limiter.clone(),
            &request_2,
            storage_system.clone(),
        )
        .await
        .expect("handler failed");

        assert_eq!(response_2.status, ZhtpStatus::Conflict);

        {
            let mgr = manager.read().await;
            assert_eq!(mgr.list_identities().len(), 2);

            let old = mgr.get_identity(&old_identity_id).expect("old identity missing");
            assert!(old.wallet_manager.wallets.is_empty());

            let new = mgr.get_identity(&new_identity_id_1).expect("new identity missing");
            assert_eq!(new.wallet_manager.wallets.len(), 3);
        }
    }
}
