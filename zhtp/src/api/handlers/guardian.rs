//! Guardian Social Recovery HTTP Handler
//!
//! Implements 9 endpoints for guardian management and social recovery.
//! Security-focused with rate limiting, signature verification, and proper session management.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{info, warn, error};

use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_identity::{
    IdentityManager, GuardianStatus,
    SocialRecoveryManager,
};
use lib_crypto::{PublicKey, PostQuantumSignature, SignatureAlgorithm};

use crate::session_manager::SessionManager;
use crate::api::middleware::RateLimiter;

/// Guardian HTTP Handler
pub struct GuardianHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    recovery_manager: Arc<RwLock<SocialRecoveryManager>>,
    rate_limiter: Arc<RateLimiter>,
}

impl GuardianHandler {
    /// Create a new guardian handler
    pub fn new(
        identity_manager: Arc<RwLock<IdentityManager>>,
        session_manager: Arc<SessionManager>,
        recovery_manager: Arc<RwLock<SocialRecoveryManager>>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            identity_manager,
            session_manager,
            recovery_manager,
            rate_limiter,
        }
    }

    /// Handle: POST /api/v1/identity/guardians/add
    async fn handle_add_guardian(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_add_guardian(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle: DELETE /api/v1/identity/guardians/{guardian_id}
    async fn handle_remove_guardian(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_remove_guardian(
            &request.uri,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle: GET /api/v1/identity/guardians
    async fn handle_list_guardians(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_list_guardians(
            self.identity_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle: POST /api/v1/identity/recovery/initiate
    async fn handle_initiate_recovery(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_initiate_recovery(
            &request.body,
            self.identity_manager.clone(),
            self.recovery_manager.clone(),
            self.rate_limiter.clone(),
            &request,
        )
        .await
    }

    /// Handle: POST /api/v1/identity/recovery/{recovery_id}/approve
    async fn handle_approve_recovery(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_approve_recovery(
            &request.uri,
            &request.body,
            self.identity_manager.clone(),
            self.recovery_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle: POST /api/v1/identity/recovery/{recovery_id}/reject
    async fn handle_reject_recovery(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_reject_recovery(
            &request.uri,
            &request.body,
            self.identity_manager.clone(),
            self.recovery_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle: POST /api/v1/identity/recovery/{recovery_id}/complete
    async fn handle_complete_recovery(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_complete_recovery(
            &request.uri,
            self.identity_manager.clone(),
            self.recovery_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle: GET /api/v1/identity/recovery/{recovery_id}/status
    async fn handle_recovery_status(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_recovery_status(
            &request.uri,
            self.recovery_manager.clone(),
        )
        .await
    }

    /// Handle: GET /api/v1/identity/recovery/pending
    async fn handle_pending_recoveries(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_pending_recoveries(
            self.identity_manager.clone(),
            self.recovery_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for GuardianHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        match (&request.method, request.uri.as_str()) {
            (ZhtpMethod::Post, "/api/v1/identity/guardians/add") => {
                self.handle_add_guardian(request).await
            }
            (ZhtpMethod::Delete, uri) if uri.starts_with("/api/v1/identity/guardians/") => {
                self.handle_remove_guardian(request).await
            }
            (ZhtpMethod::Get, "/api/v1/identity/guardians") => {
                self.handle_list_guardians(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/recovery/initiate") => {
                self.handle_initiate_recovery(request).await
            }
            (ZhtpMethod::Post, uri) if uri.contains("/recovery/") && uri.ends_with("/approve") => {
                self.handle_approve_recovery(request).await
            }
            (ZhtpMethod::Post, uri) if uri.contains("/recovery/") && uri.ends_with("/reject") => {
                self.handle_reject_recovery(request).await
            }
            (ZhtpMethod::Post, uri) if uri.contains("/recovery/") && uri.ends_with("/complete") => {
                self.handle_complete_recovery(request).await
            }
            (ZhtpMethod::Get, uri) if uri.contains("/recovery/") && uri.ends_with("/status") => {
                self.handle_recovery_status(request).await
            }
            (ZhtpMethod::Get, "/api/v1/identity/recovery/pending") => {
                self.handle_pending_recoveries(request).await
            }
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Guardian endpoint not found: {}", request.uri),
            )),
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/identity/guardians")
            || request.uri.starts_with("/api/v1/identity/recovery")
    }

    fn priority(&self) -> u32 {
        100
    }
}

// Request/Response types

#[derive(Debug, Deserialize)]
struct AddGuardianRequest {
    identity_id: String,
    session_token: String,
    guardian_did: String,
    guardian_public_key: Vec<u8>,
    guardian_name: String,
}

#[derive(Debug, Serialize)]
struct AddGuardianResponse {
    status: String,
    guardian_id: String,
    total_guardians: usize,
}

#[derive(Debug, Serialize)]
struct ListGuardiansResponse {
    guardians: Vec<GuardianInfo>,
    threshold: usize,
}

#[derive(Debug, Serialize)]
struct GuardianInfo {
    guardian_id: String,
    guardian_did: String,
    name: String,
    added_at: i64,
    status: String,
}

#[derive(Debug, Deserialize)]
struct InitiateRecoveryRequest {
    identity_did: String,
    requester_device: String,
}

#[derive(Debug, Serialize)]
struct InitiateRecoveryResponse {
    status: String,
    recovery_id: String,
    guardians_required: usize,
    guardians_approved: usize,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct ApproveRecoveryRequest {
    guardian_did: String,
    session_token: String,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct ApproveRecoveryResponse {
    status: String,
    approvals: usize,
    required: usize,
}

#[derive(Debug, Serialize)]
struct RecoveryStatusResponse {
    recovery_id: String,
    status: String,
    approvals: usize,
    required: usize,
    expires_at: i64,
    identity_did: String,
}

#[derive(Debug, Serialize)]
struct PendingRecoveriesResponse {
    pending_requests: Vec<PendingRecoveryInfo>,
}

#[derive(Debug, Serialize)]
struct PendingRecoveryInfo {
    recovery_id: String,
    identity_did: String,
    initiated_at: i64,
    expires_at: i64,
}

// Endpoint implementations

async fn handle_add_guardian(
    body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Parse request
    let req: AddGuardianRequest = serde_json::from_slice(body).map_err(|e| {
        anyhow::anyhow!("Invalid request body: {}", e)
    })?;

    // Security: Validate inputs
    validate_did(&req.guardian_did)?;
    validate_guardian_name(&req.guardian_name)?;
    validate_public_key_length(&req.guardian_public_key)?;

    // Security: Extract real client IP
    let client_ip = extract_client_ip(request);
    let user_agent = extract_user_agent(request);

    // Security: Validate session
    let session_token_obj = session_manager
        .validate_session(&req.session_token, &client_ip, &user_agent)
        .await
        .map_err(|e| {
            warn!(
                client_ip = %client_ip,
                error = %e,
                "Session validation failed in add_guardian"
            );
            anyhow::anyhow!("Session validation failed: {}", e)
        })?;

    // Convert identity_id string to IdentityId (Hash)
    let identity_id_bytes = hex::decode(&req.identity_id)
        .map_err(|e| anyhow::anyhow!("Invalid identity_id format: {}", e))?;
    if identity_id_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Invalid identity_id length"));
    }
    let mut id_array = [0u8; 32];
    id_array.copy_from_slice(&identity_id_bytes);
    let identity_id = lib_crypto::Hash::from_bytes(&id_array);

    // Security: Verify session belongs to this identity
    if session_token_obj.identity_id != identity_id {
        error!(
            session_identity = %hex::encode(session_token_obj.identity_id.as_bytes()),
            requested_identity = %hex::encode(identity_id.as_bytes()),
            client_ip = %client_ip,
            "Authorization denied: session identity mismatch"
        );
        return Err(anyhow::anyhow!("Session identity mismatch - authorization denied"));
    }

    // Get or create guardian config and persist (use single write lock to prevent race conditions)
    let mut manager_write = identity_manager.write().await;
    let mut guardian_config = manager_write
        .get_guardian_config(&identity_id)
        .unwrap_or_default();

    // Add guardian
    let guardian_public_key = PublicKey::new(req.guardian_public_key);
    let guardian_did_clone = req.guardian_did.clone();
    let guardian_id = guardian_config
        .add_guardian(req.guardian_did, guardian_public_key, req.guardian_name)
        .map_err(|e| anyhow::anyhow!("Failed to add guardian: {}", e))?;

    let total_guardians = guardian_config.guardians.len();

    // Persist guardian config to identity private data
    manager_write.set_guardian_config(&identity_id, guardian_config)
        .map_err(|e| anyhow::anyhow!("Failed to persist guardian config: {}", e))?;
    drop(manager_write);

    // Security: Log guardian addition
    info!(
        identity_id = %hex::encode(identity_id.as_bytes()),
        guardian_did = %guardian_did_clone,
        guardian_id = %guardian_id,
        client_ip = %client_ip,
        "Guardian added successfully"
    );

    let response = AddGuardianResponse {
        status: "success".to_string(),
        guardian_id,
        total_guardians,
    };

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&response)?,
        None,
    ))
}

async fn handle_remove_guardian(
    uri: &str,
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Extract guardian_id from URI: /api/v1/identity/guardians/{guardian_id}
    let parts: Vec<&str> = uri.split('/').collect();
    let guardian_id = parts.get(5).ok_or_else(|| anyhow::anyhow!("Missing guardian_id"))?;

    // Security: Extract and validate session token from Authorization header
    let session_token = request
        .headers
        .get("Authorization")
        .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string()))
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid Authorization header"))?;

    // Security: Validate session and get identity_id
    let client_ip = extract_client_ip(request);
    let user_agent = extract_user_agent(request);

    let session_token_obj = session_manager
        .validate_session(&session_token, &client_ip, &user_agent)
        .await
        .map_err(|e| anyhow::anyhow!("Invalid or expired session: {}", e))?;

    let identity_id = session_token_obj.identity_id;

    // Load guardian config
    let manager_read = identity_manager.read().await;
    let mut guardian_config = manager_read
        .get_guardian_config(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("No guardian config found"))?;
    drop(manager_read);

    // Remove guardian from config
    guardian_config
        .remove_guardian(guardian_id)
        .map_err(|e| anyhow::anyhow!("Failed to remove guardian: {}", e))?;

    // Persist changes to identity private data
    let mut manager_write = identity_manager.write().await;
    manager_write
        .set_guardian_config(&identity_id, guardian_config)
        .map_err(|e| anyhow::anyhow!("Failed to persist guardian config: {}", e))?;

    // Security: Log guardian removal
    info!(
        identity_id = %hex::encode(identity_id.as_bytes()),
        guardian_id = %guardian_id,
        client_ip = %client_ip,
        "Guardian removed successfully"
    );

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&serde_json::json!({"status": "success"}))?,
        None,
    ))
}

async fn handle_list_guardians(
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Security: Extract session token from Authorization header
    let session_token = request
        .headers
        .get("Authorization")
        .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string()))
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid Authorization header"))?;

    // Security: Validate session and get identity_id
    let client_ip = extract_client_ip(request);
    let user_agent = extract_user_agent(request);

    let session_token_obj = session_manager
        .validate_session(&session_token, &client_ip, &user_agent)
        .await
        .map_err(|e| anyhow::anyhow!("Invalid or expired session: {}", e))?;

    let identity_id = session_token_obj.identity_id;

    // Load guardian config from identity storage
    let manager_read = identity_manager.read().await;
    let guardian_config = manager_read
        .get_guardian_config(&identity_id)
        .unwrap_or_default();
    drop(manager_read);

    // Convert guardians to response format
    let guardians: Vec<GuardianInfo> = guardian_config
        .guardians
        .values()
        .map(|g| GuardianInfo {
            guardian_id: g.guardian_id.clone(),
            guardian_did: g.guardian_did.clone(),
            name: g.name.clone(),
            added_at: g.added_at.timestamp(),
            status: format!("{:?}", g.status),
        })
        .collect();

    let response = ListGuardiansResponse {
        guardians,
        threshold: guardian_config.threshold,
    };

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&response)?,
        None,
    ))
}

async fn handle_initiate_recovery(
    body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    recovery_manager: Arc<RwLock<SocialRecoveryManager>>,
    rate_limiter: Arc<RateLimiter>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Parse request
    let req: InitiateRecoveryRequest = serde_json::from_slice(body).map_err(|e| {
        anyhow::anyhow!("Invalid request body: {}", e)
    })?;

    // Security: Validate inputs
    validate_did(&req.identity_did)?;
    validate_device_name(&req.requester_device)?;

    // Security: Extract real client IP
    let client_ip = extract_client_ip(request);

    // Security: Rate limit recovery initiation (3 attempts per 24 hours)
    if let Err(response) = rate_limiter.check_rate_limit_aggressive(&client_ip, 3, 86400).await {
        return Ok(response);
    }

    // Get identity ID from DID
    let identity_manager_read = identity_manager.read().await;
    let identity_id = identity_manager_read
        .get_identity_id_by_did(&req.identity_did)
        .ok_or_else(|| anyhow::anyhow!("Identity not found for DID: {}", req.identity_did))?;

    // Load guardian config from identity storage
    let guardian_config = identity_manager_read
        .get_guardian_config(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("No guardians configured for this identity. Please add guardians first."))?;
    drop(identity_manager_read);

    // Verify that guardians are configured
    if guardian_config.guardians.is_empty() {
        return Err(anyhow::anyhow!("No guardians configured for this identity"));
    }

    // Initiate recovery
    let mut manager = recovery_manager.write().await;
    let client_ip_clone = client_ip.clone();
    let recovery_id = manager
        .initiate_recovery(
            req.identity_did.clone(),
            &guardian_config,
            req.requester_device,
            client_ip,
        )
        .map_err(|e| anyhow::anyhow!("Failed to initiate recovery: {}", e))?;

    let recovery_request = manager
        .get_request(&recovery_id)
        .ok_or_else(|| anyhow::anyhow!("Recovery request not found"))?;

    // Security: Log recovery initiation
    info!(
        identity_did = %req.identity_did,
        recovery_id = %recovery_id,
        guardians_required = recovery_request.threshold,
        client_ip = %client_ip_clone,
        requester_device = %recovery_request.requester_device,
        "Recovery initiated"
    );

    let response = InitiateRecoveryResponse {
        status: "initiated".to_string(),
        recovery_id,
        guardians_required: recovery_request.threshold,
        guardians_approved: 0,
        expires_at: recovery_request.expires_at.timestamp(),
    };

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&response)?,
        None,
    ))
}

async fn handle_approve_recovery(
    uri: &str,
    body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    recovery_manager: Arc<RwLock<SocialRecoveryManager>>,
    session_manager: Arc<SessionManager>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Extract recovery_id from URI
    let recovery_id = extract_recovery_id(uri)?;

    // Parse request
    let req: ApproveRecoveryRequest = serde_json::from_slice(body).map_err(|e| {
        anyhow::anyhow!("Invalid request body: {}", e)
    })?;

    // Security: Validate inputs
    validate_did(&req.guardian_did)?;
    validate_signature_length(&req.signature)?;

    // Security: Extract real client IP
    let client_ip = extract_client_ip(request);
    let user_agent = extract_user_agent(request);

    // Security: Validate guardian's session
    session_manager
        .validate_session(&req.session_token, &client_ip, &user_agent)
        .await
        .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

    // Get the recovery request to find the identity being recovered
    let manager = recovery_manager.read().await;
    let recovery_request = manager
        .get_request(&recovery_id)
        .ok_or_else(|| anyhow::anyhow!("Recovery request not found"))?;
    let identity_did = recovery_request.identity_did.clone();
    drop(manager);

    // Get the identity ID from DID
    let identity_manager_read = identity_manager.read().await;
    let identity_id = identity_manager_read
        .get_identity_id_by_did(&identity_did)
        .ok_or_else(|| anyhow::anyhow!("Identity not found for DID: {}", identity_did))?;

    // Load guardian config and verify guardian exists
    let guardian_config = identity_manager_read
        .get_guardian_config(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("No guardian config found for this identity"))?;
    drop(identity_manager_read);

    // Verify the approver is actually an authorized guardian with Active status
    let guardian = guardian_config
        .guardians
        .values()
        .find(|g| g.guardian_did == req.guardian_did && g.status == GuardianStatus::Active)
        .ok_or_else(|| anyhow::anyhow!("Not an authorized guardian or guardian is not active"))?;

    // Add approval with signature verification
    let signature = PostQuantumSignature {
        signature: req.signature,
        public_key: guardian.public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    let mut manager = recovery_manager.write().await;
    let recovery_request = manager
        .get_request_mut(&recovery_id)
        .ok_or_else(|| anyhow::anyhow!("Recovery request not found"))?;

    recovery_request
        .add_approval(guardian, signature)
        .map_err(|e| {
            // Security: Log failed approval attempt
            warn!(
                recovery_id = %recovery_id,
                guardian_did = %req.guardian_did,
                client_ip = %client_ip,
                error = %e,
                "Failed guardian approval attempt"
            );
            anyhow::anyhow!("Failed to add approval: {}", e)
        })?;

    // Security: Log successful approval
    info!(
        recovery_id = %recovery_id,
        guardian_did = %req.guardian_did,
        approvals = recovery_request.approval_count(),
        required = recovery_request.threshold,
        client_ip = %client_ip,
        "Guardian approved recovery"
    );

    let response = ApproveRecoveryResponse {
        status: "approved".to_string(),
        approvals: recovery_request.approval_count(),
        required: recovery_request.threshold,
    };

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&response)?,
        None,
    ))
}

async fn handle_reject_recovery(
    uri: &str,
    body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    recovery_manager: Arc<RwLock<SocialRecoveryManager>>,
    session_manager: Arc<SessionManager>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Extract recovery_id from URI
    let recovery_id = extract_recovery_id(uri)?;

    // Parse request to get guardian_did
    let req: ApproveRecoveryRequest = serde_json::from_slice(body).map_err(|e| {
        anyhow::anyhow!("Invalid request body: {}", e)
    })?;

    // Security: Extract real client IP
    let client_ip = extract_client_ip(request);
    let user_agent = extract_user_agent(request);

    // Security: Validate guardian's session
    session_manager
        .validate_session(&req.session_token, &client_ip, &user_agent)
        .await
        .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

    // Get the recovery request to find the identity being recovered
    let manager = recovery_manager.read().await;
    let recovery_request = manager
        .get_request(&recovery_id)
        .ok_or_else(|| anyhow::anyhow!("Recovery request not found"))?;
    let identity_did = recovery_request.identity_did.clone();
    drop(manager);

    // Get the identity ID from DID
    let identity_manager_read = identity_manager.read().await;
    let identity_id = identity_manager_read
        .get_identity_id_by_did(&identity_did)
        .ok_or_else(|| anyhow::anyhow!("Identity not found for DID: {}", identity_did))?;

    // Load guardian config and verify guardian exists
    let guardian_config = identity_manager_read
        .get_guardian_config(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("No guardian config found for this identity"))?;
    drop(identity_manager_read);

    // Verify the rejecter is actually an authorized guardian with Active status
    let _guardian = guardian_config
        .guardians
        .values()
        .find(|g| g.guardian_did == req.guardian_did && g.status == GuardianStatus::Active)
        .ok_or_else(|| anyhow::anyhow!("Not an authorized guardian or guardian is not active"))?;

    // Reject the recovery
    let mut manager = recovery_manager.write().await;
    let recovery_request_mut = manager
        .get_request_mut(&recovery_id)
        .ok_or_else(|| anyhow::anyhow!("Recovery request not found"))?;

    recovery_request_mut
        .reject_approval(&req.guardian_did)
        .map_err(|e| anyhow::anyhow!("Failed to reject recovery: {}", e))?;

    // Security: Log recovery rejection
    warn!(
        recovery_id = %recovery_id,
        guardian_did = %req.guardian_did,
        client_ip = %client_ip,
        "Guardian rejected recovery"
    );

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&serde_json::json!({"status": "rejected"}))?,
        None,
    ))
}

async fn handle_complete_recovery(
    uri: &str,
    identity_manager: Arc<RwLock<IdentityManager>>,
    recovery_manager: Arc<RwLock<SocialRecoveryManager>>,
    session_manager: Arc<SessionManager>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Extract recovery_id from URI
    let recovery_id = extract_recovery_id(uri)?;

    // Security: Extract real client IP
    let client_ip = extract_client_ip(request);
    let user_agent = extract_user_agent(request);

    // FIX P0-4 TOCTOU: Get identity DID first, then validate + complete atomically
    let identity_did = {
        let manager = recovery_manager.read().await;
        let recovery_request = manager
            .get_request(&recovery_id)
            .ok_or_else(|| anyhow::anyhow!("Recovery request not found"))?;
        recovery_request.identity_did.clone()
    };

    // Get the identity ID from DID
    let identity_manager_read = identity_manager.read().await;
    let identity_id = identity_manager_read
        .get_identity_id_by_did(&identity_did)
        .ok_or_else(|| anyhow::anyhow!("Identity not found for DID: {}", identity_did))?;

    let guardian_config = identity_manager_read
        .get_guardian_config(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("No guardian config found"))?
        .clone();
    drop(identity_manager_read);

    // Complete recovery atomically (validate + complete under single write lock to prevent TOCTOU)
    {
        let mut manager = recovery_manager.write().await;
        let recovery_request = manager
            .get_request_mut(&recovery_id)
            .ok_or_else(|| anyhow::anyhow!("Recovery request not found"))?;

        // Security: Re-verify all guardian approvals are from currently active guardians
        // Do this WHILE holding the write lock to prevent race conditions
        for (guardian_did, _) in &recovery_request.approvals {
            let is_still_active = guardian_config
                .guardians
                .values()
                .any(|g| &g.guardian_did == guardian_did && g.status == GuardianStatus::Active);

            if !is_still_active {
                return Err(anyhow::anyhow!(
                    "Guardian {} is no longer active - recovery invalid",
                    guardian_did
                ));
            }
        }

        // Validation passed, complete the recovery
        recovery_request
            .complete()
            .map_err(|e| anyhow::anyhow!("Failed to complete recovery: {}", e))?;
    } // Lock dropped here automatically

    // Create session token for recovered identity
    let identity_id_clone = identity_id.clone();
    let session_token = session_manager
        .create_session(identity_id, &client_ip, &user_agent)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create session: {}", e))?;

    // Security: Log successful recovery completion
    info!(
        recovery_id = %recovery_id,
        identity_did = %identity_did,
        identity_id = %hex::encode(identity_id_clone.as_bytes()),
        client_ip = %client_ip,
        "Recovery completed successfully"
    );

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&serde_json::json!({
            "status": "success",
            "session_token": session_token,
            "identity_did": identity_did,
        }))?,
        None,
    ))
}

async fn handle_recovery_status(
    uri: &str,
    recovery_manager: Arc<RwLock<SocialRecoveryManager>>,
) -> Result<ZhtpResponse> {
    // Extract recovery_id from URI
    let recovery_id = extract_recovery_id(uri)?;

    let manager = recovery_manager.read().await;
    let recovery_request = manager
        .get_request(&recovery_id)
        .ok_or_else(|| anyhow::anyhow!("Recovery request not found"))?;

    let response = RecoveryStatusResponse {
        recovery_id: recovery_request.recovery_id.clone(),
        status: format!("{:?}", recovery_request.status),
        approvals: recovery_request.approval_count(),
        required: recovery_request.threshold,
        expires_at: recovery_request.expires_at.timestamp(),
        identity_did: recovery_request.identity_did.clone(),
    };

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&response)?,
        None,
    ))
}

async fn handle_pending_recoveries(
    identity_manager: Arc<RwLock<IdentityManager>>,
    recovery_manager: Arc<RwLock<SocialRecoveryManager>>,
    session_manager: Arc<SessionManager>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Security: Extract session token from Authorization header
    let session_token = request
        .headers
        .get("Authorization")
        .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string()))
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid Authorization header"))?;

    // Security: Validate guardian's session
    let client_ip = extract_client_ip(request);
    let user_agent = extract_user_agent(request);

    let session_token_obj = session_manager
        .validate_session(&session_token, &client_ip, &user_agent)
        .await
        .map_err(|e| anyhow::anyhow!("Invalid or expired session: {}", e))?;

    let guardian_identity_id = session_token_obj.identity_id;

    // Get the guardian's DID
    let identity_manager_read = identity_manager.read().await;
    let guardian_did = identity_manager_read
        .get_did_by_identity_id(&guardian_identity_id)
        .ok_or_else(|| anyhow::anyhow!("Guardian identity not found"))?;
    drop(identity_manager_read);

    // Get all pending recovery requests from recovery manager
    let all_requests = {
        let manager = recovery_manager.read().await;
        manager.get_all_pending_requests().iter().map(|r| (*r).clone()).collect::<Vec<_>>()
    }; // Lock dropped here automatically

    // Acquire identity manager lock once for all lookups
    let identity_manager_read = identity_manager.read().await;

    // Filter requests where this guardian is authorized
    let pending_requests: Vec<PendingRecoveryInfo> = all_requests
        .into_iter()
        .filter_map(|recovery_request| {
            // Get the identity being recovered
            let identity_id = identity_manager_read.get_identity_id_by_did(&recovery_request.identity_did)?;

            // Check if this guardian is authorized for this identity
            let guardian_config = identity_manager_read.get_guardian_config(&identity_id)?;

            // Check if guardian_did is in the authorized guardians list with Active status
            let is_authorized = guardian_config
                .guardians
                .values()
                .any(|g| g.guardian_did == guardian_did && g.status == GuardianStatus::Active);

            if is_authorized {
                Some(PendingRecoveryInfo {
                    recovery_id: recovery_request.recovery_id.clone(),
                    identity_did: recovery_request.identity_did.clone(),
                    initiated_at: recovery_request.initiated_at.timestamp(),
                    expires_at: recovery_request.expires_at.timestamp(),
                })
            } else {
                None
            }
        })
        .collect();

    drop(identity_manager_read);

    let response = PendingRecoveriesResponse {
        pending_requests,
    };

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&response)?,
        None,
    ))
}

// Helper functions

fn extract_client_ip(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("X-Real-IP")
        .or_else(|| {
            request.headers.get("X-Forwarded-For").and_then(|f| {
                f.split(',').next().map(|s| s.trim().to_string())
            })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_user_agent(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_recovery_id(uri: &str) -> Result<String> {
    // URI format: /api/v1/identity/recovery/{recovery_id}/action
    let parts: Vec<&str> = uri.split('/').collect();
    parts
        .get(5)
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Missing recovery_id in URI"))
}

// Security: Input Validation Functions

/// Validate DID format (must be "did:zhtp:...")
fn validate_did(did: &str) -> Result<()> {
    if !did.starts_with("did:zhtp:") {
        return Err(anyhow::anyhow!("Invalid DID format: must start with 'did:zhtp:'"));
    }
    if did.len() < 15 {
        return Err(anyhow::anyhow!("Invalid DID: too short"));
    }
    if did.len() > 200 {
        return Err(anyhow::anyhow!("Invalid DID: too long (max 200 characters)"));
    }
    // Check for valid characters (alphanumeric, colon, dash, underscore)
    if !did.chars().all(|c| c.is_alphanumeric() || c == ':' || c == '-' || c == '_') {
        return Err(anyhow::anyhow!("Invalid DID: contains invalid characters"));
    }
    Ok(())
}

/// Validate guardian name (length and safe characters)
fn validate_guardian_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow::anyhow!("Guardian name cannot be empty"));
    }
    if name.len() > 100 {
        return Err(anyhow::anyhow!("Guardian name too long (max 100 characters)"));
    }
    // Allow alphanumeric, spaces, and common punctuation
    if !name.chars().all(|c| c.is_alphanumeric() || c.is_whitespace() || "'-.,".contains(c)) {
        return Err(anyhow::anyhow!("Guardian name contains invalid characters"));
    }
    Ok(())
}

/// Validate device name (for recovery requests)
fn validate_device_name(device: &str) -> Result<()> {
    if device.is_empty() {
        return Err(anyhow::anyhow!("Device name cannot be empty"));
    }
    if device.len() > 100 {
        return Err(anyhow::anyhow!("Device name too long (max 100 characters)"));
    }
    // Allow alphanumeric, spaces, dashes, underscores
    if !device.chars().all(|c| c.is_alphanumeric() || c.is_whitespace() || c == '-' || c == '_') {
        return Err(anyhow::anyhow!("Device name contains invalid characters"));
    }
    Ok(())
}

/// Validate signature length (post-quantum signatures are typically 2-4KB)
fn validate_signature_length(signature: &[u8]) -> Result<()> {
    if signature.is_empty() {
        return Err(anyhow::anyhow!("Signature cannot be empty"));
    }
    if signature.len() > 10000 {
        return Err(anyhow::anyhow!("Signature too large (max 10KB)"));
    }
    Ok(())
}

/// Validate public key length (post-quantum keys are typically 1-2KB)
fn validate_public_key_length(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(anyhow::anyhow!("Public key cannot be empty"));
    }
    if key.len() > 5000 {
        return Err(anyhow::anyhow!("Public key too large (max 5KB)"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_recovery_id() {
        let uri = "/api/v1/identity/recovery/abc123/approve";
        let recovery_id = extract_recovery_id(uri).unwrap();
        assert_eq!(recovery_id, "abc123");
    }

    #[test]
    fn test_validate_did() {
        assert!(validate_did("did:zhtp:alice123").is_ok());
        assert!(validate_did("did:eth:alice").is_err()); // Wrong prefix
        assert!(validate_did("did:zhtp:").is_err()); // Too short
        assert!(validate_did("not-a-did").is_err()); // Invalid format
    }

    #[test]
    fn test_validate_guardian_name() {
        assert!(validate_guardian_name("Alice Smith").is_ok());
        assert!(validate_guardian_name("Bob-Jones").is_ok());
        assert!(validate_guardian_name("").is_err()); // Empty
        assert!(validate_guardian_name(&"x".repeat(101)).is_err()); // Too long
        assert!(validate_guardian_name("Alice<script>").is_err()); // Invalid chars
    }

    #[test]
    fn test_validate_device_name() {
        assert!(validate_device_name("iPhone-13").is_ok());
        assert!(validate_device_name("MacBook Pro").is_ok());
        assert!(validate_device_name("").is_err()); // Empty
        assert!(validate_device_name(&"x".repeat(101)).is_err()); // Too long
    }
}
