//! Mobile Authentication Handler (Issue #1877)
//!
//! Implements the HTTP side of the mobile-to-web authentication delegation
//! protocol across all three phases:
//!
//! ## Phase 1 — MVP session establishment
//! - `POST /api/v1/auth/mobile/challenge`  → issue CSPRNG challenge + QR payload
//! - `POST /api/v1/auth/mobile/verify`     → verify Dilithium signature, issue session
//! - `GET  /api/v1/auth/mobile/session`    → validate bearer and return session info
//! - `POST /api/v1/auth/mobile/signout`    → revoke session
//!
//! ## Phase 2 — Enhanced security
//! - `POST /api/v1/auth/mobile/refresh`    → rotate refresh token (one-time use)
//!
//! ## Phase 3 — Delegation
//! - `POST /api/v1/auth/delegate`          → register delegation certificate
//! - `GET  /api/v1/auth/delegate/:cert_id` → look up a certificate
//! - `POST /api/v1/auth/delegate/:cert_id/revoke` → revoke a certificate
//! - `GET  /api/v1/auth/delegate/list`     → list all active certs for a DID
//!
//! ## Security controls enforced here
//! - Rate limiting: 3 challenge requests per IP per minute
//! - Session binding: IP + User-Agent checked on every request
//! - Replay protection: challenge nonce consumed on successful verify
//! - Audit log: every action written to immutable in-memory log

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use lib_identity::auth::mobile_delegation::{
    AuditEventKind, AuditLogEntry, Capability, CrossDeviceSessionBinder, DelegationCertificate,
    MobileAuthChallenge, MobileAuthStore,
};
use lib_protocols::types::{ZhtpHeaders, ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

const NODE_ENDPOINT: &str = "http://localhost:9334"; // overrideable via config

/// Public API surface for the mobile auth handler.
pub struct MobileAuthHandler {
    store: Arc<MobileAuthStore>,
    node_endpoint: String,
}

impl MobileAuthHandler {
    pub fn new(store: Arc<MobileAuthStore>) -> Self {
        Self {
            store,
            node_endpoint: NODE_ENDPOINT.to_string(),
        }
    }

    pub fn with_endpoint(store: Arc<MobileAuthStore>, endpoint: &str) -> Self {
        Self {
            store,
            node_endpoint: endpoint.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Route dispatch
    // -----------------------------------------------------------------------

    async fn dispatch(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let uri = request.uri.trim_end_matches('/');
        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);

        match (&request.method, uri) {
            // Phase 1
            (ZhtpMethod::Post, "/api/v1/auth/mobile/challenge") => {
                self.handle_challenge(&request.body, &client_ip).await
            }
            (ZhtpMethod::Post, "/api/v1/auth/mobile/verify") => {
                self.handle_verify(&request.body, &client_ip, &user_agent).await
            }
            (ZhtpMethod::Get, "/api/v1/auth/mobile/session") => {
                self.handle_session_info(&request.headers, &client_ip, &user_agent).await
            }
            (ZhtpMethod::Post, "/api/v1/auth/mobile/signout") => {
                self.handle_signout(&request.headers, &client_ip, &user_agent).await
            }
            // Phase 2
            (ZhtpMethod::Post, "/api/v1/auth/mobile/refresh") => {
                self.handle_refresh(&request.body, &client_ip, &user_agent).await
            }
            // Phase 3
            (ZhtpMethod::Post, "/api/v1/auth/delegate") => {
                self.handle_delegate_issue(&request.body, &request.headers, &client_ip, &user_agent).await
            }
            (ZhtpMethod::Post, path) if path.starts_with("/api/v1/auth/delegate/") && path.ends_with("/revoke") => {
                let cert_id = path
                    .strip_prefix("/api/v1/auth/delegate/")
                    .and_then(|s| s.strip_suffix("/revoke"))
                    .unwrap_or("");
                self.handle_delegate_revoke(cert_id, &request.body, &request.headers, &client_ip, &user_agent).await
            }
            (ZhtpMethod::Get, "/api/v1/auth/delegate/list") => {
                self.handle_delegate_list(&request.headers, &client_ip, &user_agent).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/auth/delegate/") => {
                let cert_id = path
                    .strip_prefix("/api/v1/auth/delegate/")
                    .unwrap_or("");
                self.handle_delegate_get(cert_id).await
            }
            _ => Ok(json_error(ZhtpStatus::NotFound, "Not found")),
        }
    }

    // -----------------------------------------------------------------------
    // Phase 1: Challenge
    // POST /api/v1/auth/mobile/challenge
    // Body: { "capabilities": [...] }
    // -----------------------------------------------------------------------

    async fn handle_challenge(&self, body: &[u8], client_ip: &str) -> ZhtpResult<ZhtpResponse> {
        // Rate-limit per IP
        if let Err(e) = self.store.rate_limiter.check_and_record(client_ip).await {
            let entry = AuditLogEntry::new(
                AuditEventKind::ChallengeIssued,
                None,
                None,
                client_ip,
                &format!("rate_limited: {}", e),
            );
            self.store.append_audit(entry).await;
            return Ok(json_error(ZhtpStatus::TooManyRequests, &e.to_string()));
        }

        // Parse requested capabilities
        let capabilities: Vec<Capability> = if body.is_empty() {
            vec![]
        } else {
            match parse_capabilities(body) {
                Ok(caps) => caps,
                Err(e) => return Ok(json_error(ZhtpStatus::BadRequest, &e.to_string())),
            }
        };

        // Generate challenge
        let challenge =
            match MobileAuthChallenge::generate(capabilities, &self.node_endpoint) {
                Ok(c) => c,
                Err(e) => return Ok(json_error(ZhtpStatus::InternalServerError, &e.to_string())),
            };

        let session_id = challenge.session_id.clone();
        let challenge_nonce = challenge.challenge_nonce.clone();
        let expires_at = challenge.expires_at;
        let qr_payload = challenge.qr_payload.clone();

        // Persist
        self.store.insert_challenge(challenge).await;

        // Audit
        let entry = AuditLogEntry::new(
            AuditEventKind::ChallengeIssued,
            Some(&session_id),
            None,
            client_ip,
            "challenge_generated",
        );
        self.store.append_audit(entry).await;

        Ok(json_ok(json!({
            "session_id": session_id,
            "challenge_nonce": challenge_nonce,
            "expires_at": expires_at,
            "qr_payload": qr_payload,
            "node_endpoint": self.node_endpoint,
        })))
    }

    // -----------------------------------------------------------------------
    // Phase 1: Verify signature and issue session
    // POST /api/v1/auth/mobile/verify
    // Body: { "session_id": "...", "public_key_hex": "...", "signature_hex": "...", "device_id": "..." }
    // -----------------------------------------------------------------------

    async fn handle_verify(
        &self,
        body: &[u8],
        client_ip: &str,
        user_agent: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        #[derive(Deserialize)]
        struct VerifyRequest {
            session_id: String,
            /// Dilithium public key (hex)
            public_key_hex: String,
            /// Dilithium signature over challenge_nonce bytes (hex)
            signature_hex: String,
            /// Optional device label for concurrent-session disambiguation
            device_id: Option<String>,
            /// Identity ID (hex) the mobile key belongs to
            identity_hex: String,
        }

        let req: VerifyRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return Ok(json_error(ZhtpStatus::BadRequest, &e.to_string())),
        };

        // Retrieve and validate challenge
        let challenge = match self.store.get_challenge(&req.session_id).await {
            None => {
                return Ok(json_error(ZhtpStatus::BadRequest, "Challenge not found"))
            }
            Some(c) => c,
        };

        if challenge.is_expired() {
            let entry = AuditLogEntry::new(
                AuditEventKind::ChallengeExpired,
                Some(&req.session_id),
                None,
                client_ip,
                "challenge_expired_on_verify",
            );
            self.store.append_audit(entry).await;
            return Ok(json_error(ZhtpStatus::BadRequest, "Challenge expired"));
        }

        // Verify Dilithium signature (challenge_nonce is hex-encoded 32-byte nonce)
        let sig_valid = match CrossDeviceSessionBinder::verify_cross_device_binding(
            &challenge.challenge_nonce,
            &req.public_key_hex,
            &req.signature_hex,
        ) {
            Ok(v) => v,
            Err(e) => {
                let entry = AuditLogEntry::new(
                    AuditEventKind::ChallengeSigned,
                    Some(&req.session_id),
                    None,
                    client_ip,
                    &format!("signature_error: {}", e),
                );
                self.store.append_audit(entry).await;
                return Ok(json_error(ZhtpStatus::BadRequest, &format!("Signature error: {}", e)));
            }
        };

        if !sig_valid {
            let entry = AuditLogEntry::new(
                AuditEventKind::ChallengeSigned,
                Some(&req.session_id),
                None,
                client_ip,
                "signature_invalid",
            );
            self.store.append_audit(entry).await;
            return Ok(json_error(ZhtpStatus::Unauthorized, "Invalid signature"));
        }

        // Consume challenge (replay protection — must happen before session creation)
        if let Err(e) = self.store.consume_challenge(&req.session_id).await {
            return Ok(json_error(ZhtpStatus::BadRequest, &e.to_string()));
        }

        // Decode identity_id
        let identity_bytes = match hex::decode(&req.identity_hex) {
            Ok(b) => b,
            Err(_) => {
                return Ok(json_error(ZhtpStatus::BadRequest, "Invalid identity_hex"))
            }
        };
        let identity_id = lib_crypto::Hash::from_bytes(&identity_bytes);

        // Create session
        let session = match self
            .store
            .create_session(
                identity_id,
                req.public_key_hex,
                challenge.requested_capabilities.clone(),
                client_ip.to_string(),
                user_agent.to_string(),
                req.session_id.clone(),
                req.device_id.clone(),
            )
            .await
        {
            Ok(s) => s,
            Err(e) => return Ok(json_error(ZhtpStatus::InternalServerError, &e.to_string())),
        };

        // Audit
        let entry = AuditLogEntry::new(
            AuditEventKind::SessionCreated,
            Some(&req.session_id),
            Some(&req.identity_hex),
            client_ip,
            "session_created",
        );
        self.store.append_audit(entry).await;

        // SECURITY: Do NOT echo back identity details or public key in response
        Ok(json_ok(json!({
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "access_expires_at": session.access_expires_at,
            "refresh_expires_at": session.refresh_expires_at,
            "granted_capabilities": session.granted_capabilities,
        })))
    }

    // -----------------------------------------------------------------------
    // Phase 1: Session info (requires bearer)
    // GET /api/v1/auth/mobile/session
    // -----------------------------------------------------------------------

    async fn handle_session_info(
        &self,
        headers: &ZhtpHeaders,
        client_ip: &str,
        user_agent: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        let token = match extract_bearer(headers) {
            Some(t) => t,
            None => return Ok(json_error(ZhtpStatus::Unauthorized, "Missing Bearer token")),
        };

        match self.store.validate_access_token(&token, client_ip, user_agent).await {
            Err(e) => {
                let entry = AuditLogEntry::new(
                    AuditEventKind::SessionBindingViolation,
                    Some(&token[..std::cmp::min(16, token.len())]),
                    None,
                    client_ip,
                    &e.to_string(),
                );
                self.store.append_audit(entry).await;
                Ok(json_error(ZhtpStatus::Unauthorized, &e.to_string()))
            }
            Ok(session) => Ok(json_ok(json!({
                "identity_hex": hex::encode(session.identity_id.as_ref()),
                "granted_capabilities": session.granted_capabilities,
                "access_expires_at": session.access_expires_at,
                "device_id": session.device_id,
            }))),
        }
    }

    // -----------------------------------------------------------------------
    // Phase 1: Sign out (requires bearer)
    // POST /api/v1/auth/mobile/signout
    // -----------------------------------------------------------------------

    async fn handle_signout(
        &self,
        headers: &ZhtpHeaders,
        client_ip: &str,
        user_agent: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        let token = match extract_bearer(headers) {
            Some(t) => t,
            None => return Ok(json_error(ZhtpStatus::Unauthorized, "Missing Bearer token")),
        };

        // Validate first (ensure binding matches)
        if let Err(e) = self.store.validate_access_token(&token, client_ip, user_agent).await {
            return Ok(json_error(ZhtpStatus::Unauthorized, &e.to_string()));
        }

        match self.store.revoke_session(&token, "user_signout").await {
            Ok(_) => {
                let entry = AuditLogEntry::new(
                    AuditEventKind::SessionRevoked,
                    Some(&token[..std::cmp::min(16, token.len())]),
                    None,
                    client_ip,
                    "user_signout",
                );
                self.store.append_audit(entry).await;
                Ok(json_ok(json!({ "signed_out": true })))
            }
            Err(e) => Ok(json_error(ZhtpStatus::BadRequest, &e.to_string())),
        }
    }

    // -----------------------------------------------------------------------
    // Phase 2: Refresh token rotation
    // POST /api/v1/auth/mobile/refresh
    // Body: { "refresh_token": "..." }
    // -----------------------------------------------------------------------

    async fn handle_refresh(
        &self,
        body: &[u8],
        client_ip: &str,
        user_agent: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        #[derive(Deserialize)]
        struct RefreshRequest {
            refresh_token: String,
        }

        let req: RefreshRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return Ok(json_error(ZhtpStatus::BadRequest, &e.to_string())),
        };

        match self.store.rotate_refresh_token(&req.refresh_token, client_ip, user_agent).await {
            Err(e) => Ok(json_error(ZhtpStatus::Unauthorized, &e.to_string())),
            Ok(session) => {
                let entry = AuditLogEntry::new(
                    AuditEventKind::SessionRefreshed,
                    Some(&req.refresh_token[..std::cmp::min(16, req.refresh_token.len())]),
                    None,
                    client_ip,
                    "refresh_rotated",
                );
                self.store.append_audit(entry).await;

                Ok(json_ok(json!({
                    "access_token": session.access_token,
                    "refresh_token": session.refresh_token,
                    "access_expires_at": session.access_expires_at,
                    "refresh_expires_at": session.refresh_expires_at,
                })))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Phase 3: Issue delegation certificate
    // POST /api/v1/auth/delegate
    // Requires: Bearer (the delegator must already have an active session)
    // Body: {
    //   "delegate_id": "did:zhtp:...",
    //   "capabilities": [...],
    //   "expires_in_secs": 3600,
    //   "nonce": 12345,
    //   "signature_hex": "..."
    // }
    // -----------------------------------------------------------------------

    async fn handle_delegate_issue(
        &self,
        body: &[u8],
        headers: &ZhtpHeaders,
        client_ip: &str,
        user_agent: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        #[derive(Deserialize)]
        struct DelegateRequest {
            /// Client-generated certificate ID included in signing_bytes() before signing
            cert_id: String,
            delegate_id: String,
            capabilities: Vec<Capability>,
            expires_in_secs: u64,
            nonce: u64,
            signature_hex: String,
        }

        // Authenticator must have a valid session
        let token = match extract_bearer(headers) {
            Some(t) => t,
            None => return Ok(json_error(ZhtpStatus::Unauthorized, "Missing Bearer token")),
        };
        let session = match self.store.validate_access_token(&token, client_ip, user_agent).await {
            Err(e) => return Ok(json_error(ZhtpStatus::Unauthorized, &e.to_string())),
            Ok(s) => s,
        };

        let req: DelegateRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return Ok(json_error(ZhtpStatus::BadRequest, &e.to_string())),
        };

        if req.expires_in_secs == 0 || req.expires_in_secs > 30 * 24 * 3600 {
            return Ok(json_error(
                ZhtpStatus::BadRequest,
                "expires_in_secs must be 1–2592000 (30 days)",
            ));
        }

        // Build delegator DID from session identity
        let delegator_did = format!("did:zhtp:{}", hex::encode(session.identity_id.as_ref()));

        // The client generates the cert_id so it can include it in signing_bytes() before
        // sending the request.  We validate it is a non-empty, printable ASCII string.
        if req.cert_id.is_empty() || !req.cert_id.chars().all(|c| c.is_ascii_graphic()) {
            return Ok(json_error(ZhtpStatus::BadRequest, "cert_id must be a non-empty ASCII string"));
        }
        let cert_id = req.cert_id.clone();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build the candidate cert (signature_hex not yet verified)
        let cert = DelegationCertificate {
            cert_id: cert_id.clone(),
            delegator_did: delegator_did.clone(),
            delegate_id: req.delegate_id.clone(),
            capabilities: req.capabilities.clone(),
            expires_at: now + req.expires_in_secs,
            nonce: req.nonce,
            signature_hex: req.signature_hex.clone(),
            revoked: false,
            revocation_reason: None,
            registered_at_block: None,
        };

        // SECURITY: Verify the delegator's Dilithium signature over the canonical cert bytes
        // before persisting the certificate.  The client signs signing_bytes() with its private
        // key; we verify against the public key stored in the validated session.
        match CrossDeviceSessionBinder::verify_cross_device_binding(
            &hex::encode(cert.signing_bytes()),
            &session.public_key_hex,
            &req.signature_hex,
        ) {
            Err(e) => {
                return Ok(json_error(
                    ZhtpStatus::BadRequest,
                    &format!("Delegation signature verification error: {}", e),
                ))
            }
            Ok(false) => {
                let entry = AuditLogEntry::new(
                    AuditEventKind::UnauthorizedCapabilityAccess,
                    None,
                    Some(&hex::encode(session.identity_id.as_ref())),
                    client_ip,
                    "delegation_cert_invalid_signature",
                );
                self.store.append_audit(entry).await;
                return Ok(json_error(
                    ZhtpStatus::Unauthorized,
                    "Delegation certificate signature is invalid",
                ));
            }
            Ok(true) => {} // signature verified
        }

        match self.store.register_delegation_cert(cert).await {
            Err(e) => return Ok(json_error(ZhtpStatus::BadRequest, &e.to_string())),
            Ok(_) => {}
        }

        let entry = AuditLogEntry::new(
            AuditEventKind::DelegationIssued,
            None,
            Some(&hex::encode(session.identity_id.as_ref())),
            client_ip,
            &format!("cert_id={} delegate={}", cert_id, req.delegate_id),
        );
        self.store.append_audit(entry).await;

        Ok(json_ok(json!({
            "cert_id": cert_id,
            "delegator_did": delegator_did,
            "delegate_id": req.delegate_id,
            "capabilities": req.capabilities,
            "expires_at": now + req.expires_in_secs,
        })))
    }

    // -----------------------------------------------------------------------
    // Phase 3: Get delegation certificate
    // GET /api/v1/auth/delegate/:cert_id
    // -----------------------------------------------------------------------

    async fn handle_delegate_get(&self, cert_id: &str) -> ZhtpResult<ZhtpResponse> {
        match self.store.get_delegation_cert(cert_id).await {
            None => Ok(json_error(ZhtpStatus::NotFound, "Certificate not found")),
            Some(cert) => Ok(json_ok(serde_json::to_value(&cert).unwrap_or(Value::Null))),
        }
    }

    // -----------------------------------------------------------------------
    // Phase 3: Revoke delegation certificate
    // POST /api/v1/auth/delegate/:cert_id/revoke
    // Requires: Bearer (delegator's session)
    // Body: { "reason": "..." }
    // -----------------------------------------------------------------------

    async fn handle_delegate_revoke(
        &self,
        cert_id: &str,
        body: &[u8],
        headers: &ZhtpHeaders,
        client_ip: &str,
        user_agent: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        #[derive(Deserialize)]
        struct RevokeRequest {
            reason: Option<String>,
        }

        let token = match extract_bearer(headers) {
            Some(t) => t,
            None => return Ok(json_error(ZhtpStatus::Unauthorized, "Missing Bearer token")),
        };
        let session = match self.store.validate_access_token(&token, client_ip, user_agent).await {
            Err(e) => return Ok(json_error(ZhtpStatus::Unauthorized, &e.to_string())),
            Ok(s) => s,
        };

        // Verify the revoking identity owns this cert
        let cert = match self.store.get_delegation_cert(cert_id).await {
            None => return Ok(json_error(ZhtpStatus::NotFound, "Certificate not found")),
            Some(c) => c,
        };

        let caller_did = format!("did:zhtp:{}", hex::encode(session.identity_id.as_ref()));
        if cert.delegator_did != caller_did {
            return Ok(json_error(
                ZhtpStatus::Forbidden,
                "Only the delegator can revoke this certificate",
            ));
        }

        let req: RevokeRequest = serde_json::from_slice(body).unwrap_or(RevokeRequest { reason: None });
        let reason = req.reason.as_deref().unwrap_or("delegator_requested");

        match self.store.revoke_delegation_cert(cert_id, reason).await {
            Err(e) => return Ok(json_error(ZhtpStatus::BadRequest, &e.to_string())),
            Ok(_) => {}
        }

        let entry = AuditLogEntry::new(
            AuditEventKind::DelegationRevoked,
            None,
            Some(&hex::encode(session.identity_id.as_ref())),
            client_ip,
            &format!("cert_id={} reason={}", cert_id, reason),
        );
        self.store.append_audit(entry).await;

        Ok(json_ok(json!({ "revoked": true, "cert_id": cert_id })))
    }

    // -----------------------------------------------------------------------
    // Phase 3: List active delegations
    // GET /api/v1/auth/delegate/list
    // Requires: Bearer
    // -----------------------------------------------------------------------

    async fn handle_delegate_list(
        &self,
        headers: &ZhtpHeaders,
        client_ip: &str,
        user_agent: &str,
    ) -> ZhtpResult<ZhtpResponse> {
        let token = match extract_bearer(headers) {
            Some(t) => t,
            None => return Ok(json_error(ZhtpStatus::Unauthorized, "Missing Bearer token")),
        };
        let session = match self.store.validate_access_token(&token, client_ip, user_agent).await {
            Err(e) => return Ok(json_error(ZhtpStatus::Unauthorized, &e.to_string())),
            Ok(s) => s,
        };

        let delegator_did = format!("did:zhtp:{}", hex::encode(session.identity_id.as_ref()));
        let certs = self.store.list_active_certs_for(&delegator_did).await;

        Ok(json_ok(json!({ "certs": certs })))
    }
}

// ---------------------------------------------------------------------------
// ZhtpRequestHandler impl
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl ZhtpRequestHandler for MobileAuthHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        self.dispatch(&request).await
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        let uri = request.uri.trim_end_matches('/');
        uri.starts_with("/api/v1/auth/mobile") || uri.starts_with("/api/v1/auth/delegate")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn json_ok(body: Value) -> ZhtpResponse {
    ZhtpResponse::success_with_content_type(
        serde_json::to_vec(&body).unwrap_or_default(),
        "application/json".to_string(),
        None,
    )
}

fn json_error(status: ZhtpStatus, message: &str) -> ZhtpResponse {
    ZhtpResponse::error_json(status, &serde_json::json!({ "error": message }))
        .unwrap_or_else(|_| ZhtpResponse::error(status, message.to_string()))
}

fn extract_bearer(headers: &ZhtpHeaders) -> Option<String> {
    headers
        .authorization
        .as_deref()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

fn extract_client_ip(request: &ZhtpRequest) -> String {
    // Prefer X-Real-IP (set by trusted reverse-proxy to the true client IP).
    // Fall back to the first entry in X-Forwarded-For (may be a comma-separated chain).
    if let Some(real_ip) = request.headers.custom.get("X-Real-IP")
        .or_else(|| request.headers.custom.get("x-real-ip"))
    {
        return real_ip.trim().to_string();
    }
    if let Some(forwarded) = request.headers.custom.get("X-Forwarded-For")
        .or_else(|| request.headers.custom.get("x-forwarded-for"))
    {
        // Take only the leftmost (originating client) address
        if let Some(first) = forwarded.split(',').next() {
            return first.trim().to_string();
        }
    }
    "unknown".to_string()
}

fn extract_user_agent(request: &ZhtpRequest) -> String {
    request.headers.user_agent.clone()
        .unwrap_or_else(|| "unknown".to_string())
}

fn parse_capabilities(body: &[u8]) -> anyhow::Result<Vec<Capability>> {
    #[derive(Deserialize)]
    struct Body {
        capabilities: Vec<Capability>,
    }
    let b: Body = serde_json::from_slice(body)
        .map_err(|e| anyhow!("Invalid capabilities body: {}", e))?;
    Ok(b.capabilities)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::auth::mobile_delegation::MobileAuthStore;

    fn make_handler() -> MobileAuthHandler {
        MobileAuthHandler::new(Arc::new(MobileAuthStore::new()))
    }

    fn post(uri: &str, body: Value) -> ZhtpRequest {
        ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: uri.to_string(),
            version: "1.0".to_string(),
            headers: ZhtpHeaders::new(),
            body: serde_json::to_vec(&body).unwrap(),
            timestamp: 0,
            requester: None,
            auth_proof: None,
        }
    }

    fn get(uri: &str) -> ZhtpRequest {
        ZhtpRequest {
            method: ZhtpMethod::Get,
            uri: uri.to_string(),
            version: "1.0".to_string(),
            headers: ZhtpHeaders::new(),
            body: vec![],
            timestamp: 0,
            requester: None,
            auth_proof: None,
        }
    }

    // Phase 1 — challenge
    #[tokio::test]
    async fn challenge_returns_session_id_and_qr() {
        let h = make_handler();
        let req = post(
            "/api/v1/auth/mobile/challenge",
            json!({ "capabilities": [{ "type": "read_balance" }] }),
        );
        let resp = h.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Ok);
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(body["session_id"].is_string());
        assert!(body["qr_payload"].as_str().unwrap().starts_with("zhtp://auth"));
    }

    // Phase 1 — verify with wrong signature returns Unauthorized
    #[tokio::test]
    async fn verify_bad_signature_returns_401() {
        let h = make_handler();
        // Issue challenge
        let ch_req = post("/api/v1/auth/mobile/challenge", json!({}));
        let ch_resp = h.handle_request(ch_req).await.unwrap();
        let ch_body: Value = serde_json::from_slice(&ch_resp.body).unwrap();
        let session_id = ch_body["session_id"].as_str().unwrap().to_string();

        // Attempt verify with a garbage Dilithium-sized pk and signature
        let bad_pk = "ab".repeat(1312); // Dilithium2 pk = 1312 bytes → 2624 hex chars
        let bad_sig = "cd".repeat(2420); // Dilithium2 sig ≈ 2420 bytes
        let identity_hex = hex::encode([0u8; 32]);

        let verify_req = post(
            "/api/v1/auth/mobile/verify",
            json!({
                "session_id": session_id,
                "public_key_hex": bad_pk,
                "signature_hex": bad_sig,
                "identity_hex": identity_hex,
            }),
        );
        let v_resp = h.handle_request(verify_req).await.unwrap();
        // Should be Unauthorized or BadRequest (either is fine — signature invalid)
        assert!(
            v_resp.status == ZhtpStatus::Unauthorized
                || v_resp.status == ZhtpStatus::BadRequest,
            "Expected 401 or 400, got {:?}",
            v_resp.status
        );
    }

    // Phase 1 — unknown challenge id
    #[tokio::test]
    async fn verify_unknown_session_returns_400() {
        let h = make_handler();
        let req = post(
            "/api/v1/auth/mobile/verify",
            json!({
                "session_id": "nonexistent",
                "public_key_hex": "ab".repeat(1312),
                "signature_hex": "cd".repeat(2420),
                "identity_hex": hex::encode([0u8; 32]),
            }),
        );
        let resp = h.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::BadRequest);
    }

    // Phase 1 — session info without token
    #[tokio::test]
    async fn session_info_no_token_returns_401() {
        let h = make_handler();
        let resp = h.handle_request(get("/api/v1/auth/mobile/session")).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Unauthorized);
    }

    // Phase 2 — refresh without valid token
    #[tokio::test]
    async fn refresh_unknown_token_returns_401() {
        let h = make_handler();
        let req = post(
            "/api/v1/auth/mobile/refresh",
            json!({ "refresh_token": "nonexistent" }),
        );
        let resp = h.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Unauthorized);
    }

    // Phase 3 — delegate issue without bearer
    #[tokio::test]
    async fn delegate_issue_no_bearer_returns_401() {
        let h = make_handler();
        let req = post(
            "/api/v1/auth/delegate",
            json!({
                "cert_id": "00112233445566778899aabbccddeeff",
                "delegate_id": "did:zhtp:bob",
                "capabilities": [],
                "expires_in_secs": 3600,
                "nonce": 1,
                "signature_hex": "00",
            }),
        );
        let resp = h.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Unauthorized);
    }

    // Phase 3 — get nonexistent cert
    #[tokio::test]
    async fn delegate_get_unknown_cert_returns_404() {
        let h = make_handler();
        let resp = h
            .handle_request(get("/api/v1/auth/delegate/does-not-exist"))
            .await
            .unwrap();
        assert_eq!(resp.status, ZhtpStatus::NotFound);
    }
}
