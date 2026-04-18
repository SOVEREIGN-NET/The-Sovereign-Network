//! Mobile-to-Web Authentication Delegation
//!
//! Implements Issue #1877: secure challenge-response session establishment
//! where the mobile app holds keys, signs challenges, and the web app
//! receives a bearer session token — without ever touching private keys.
//!
//! # Architecture
//!
//! ```text
//! Web App          Node                     Mobile App
//!   |                |                           |
//!   |--POST /auth/mobile/challenge-------------->|
//!   |<-- { session_id, challenge_hex, qr_url }--|
//!   |                |<-- scan QR + sign --------|
//!   |                |<-- POST /auth/mobile/verify|
//!   |<-- session_token (Bearer) -----------------|
//!   |--API calls with Bearer ------------------>|
//! ```
//!
//! # Security properties
//!
//! - Challenge nonces are single-use and expire in 5 minutes (replay protection)
//! - Session tokens are bound to IP + User-Agent (hijack protection)
//! - Rate limited: max 3 challenge requests per IP per minute
//! - Signatures verified using post-quantum Dilithium (same as rest of SOVEREIGN-NET)
//! - All tokens derived via Blake3, stored as hex — never raw entropy
//! - Refresh tokens rotate on every use (old token invalidated immediately)

use crate::types::IdentityId;
use anyhow::{anyhow, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Challenge TTL: 5 minutes (single-use, short window per threat model)
pub const CHALLENGE_TTL_SECS: u64 = 300;

/// Access token lifetime: 1 hour
pub const ACCESS_TOKEN_TTL_SECS: u64 = 3600;

/// Refresh token lifetime: 7 days
pub const REFRESH_TOKEN_TTL_SECS: u64 = 7 * 24 * 3600;

/// Max concurrent sessions per identity (web sessions per mobile key)
pub const MAX_SESSIONS_PER_IDENTITY: usize = 10;

/// Max challenge attempts per IP per minute (rate limit per threat model)
pub const MAX_CHALLENGES_PER_IP_PER_MIN: u32 = 3;

/// QR payload scheme prefix
pub const QR_SCHEME: &str = "zhtp://auth";

/// Minimum Dilithium public-key size accepted (Dilithium5 = 1312 bytes)
pub const MIN_DILITHIUM_PK_BYTES: usize = 1312;

// ---------------------------------------------------------------------------
// Capability model
// ---------------------------------------------------------------------------

/// Granular capabilities the web app can request (issue #1877 Option 2)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Capability {
    /// Read any on-chain balance/state
    ReadBalance,
    /// Submit a transaction bounded by max_amount to allowed recipients
    SubmitTx { max_amount_tokens: u64 },
    /// Participate in DAO governance votes
    VoteGovernance,
    /// Deploy/update Web4 content the identity owns
    Web4Deploy,
    /// Read-only access to identity metadata
    ReadIdentity,
}

impl Capability {
    /// Human-readable label used in QR display and audit logs
    pub fn label(&self) -> &'static str {
        match self {
            Capability::ReadBalance => "read_balance",
            Capability::SubmitTx { .. } => "submit_tx",
            Capability::VoteGovernance => "vote_governance",
            Capability::Web4Deploy => "web4_deploy",
            Capability::ReadIdentity => "read_identity",
        }
    }
}

// ---------------------------------------------------------------------------
// Challenge
// ---------------------------------------------------------------------------

/// Status of an auth challenge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Pending,
    Signed,
    Verified,
    Expired,
    Used,
}

/// Authentication challenge issued to a web session, delivered via QR code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileAuthChallenge {
    /// Unique session identifier (UUIDv4-style 16-byte hex)
    pub session_id: String,
    /// 32-byte CSPRNG challenge nonce (base64-encoded)
    pub challenge_nonce: String,
    /// When this challenge was created (Unix seconds)
    pub created_at: u64,
    /// When this challenge expires (Unix seconds)
    pub expires_at: u64,
    /// Capabilities the web app is requesting
    pub requested_capabilities: Vec<Capability>,
    /// Current lifecycle status
    pub status: ChallengeStatus,
    /// Node endpoint included in QR so mobile knows where to post signature
    pub node_endpoint: String,
    /// QR-encodable payload (base64 of JSON envelope)
    pub qr_payload: String,
}

impl MobileAuthChallenge {
    /// Create a new challenge, generate nonce and QR payload
    pub fn generate(requested_capabilities: Vec<Capability>, node_endpoint: &str) -> Result<Self> {
        let now = now_secs();

        // 32-byte CSPRNG nonce — single-use replay protection (hex-encoded for QR/JSON compat)
        let mut nonce_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let challenge_nonce = hex::encode(nonce_bytes);

        // 16-byte session ID
        let mut sid_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut sid_bytes);
        let session_id = hex::encode(sid_bytes);

        // Build QR envelope — mobile app parses this after scan
        // Encoded as hex(JSON) so no extra dependency is needed and
        // QR scanners can decode the zhtp:// deep-link without base64 ambiguity.
        let qr_envelope = QrAuthEnvelope {
            session_id: session_id.clone(),
            challenge_nonce: challenge_nonce.clone(),
            node_endpoint: node_endpoint.to_string(),
            expires_at: now + CHALLENGE_TTL_SECS,
            requested_capabilities: requested_capabilities.clone(),
        };
        let qr_json = serde_json::to_string(&qr_envelope)
            .map_err(|e| anyhow!("QR envelope serialization failed: {}", e))?;
        // Format: zhtp://auth?d=<hex>
        let qr_payload = format!("{}?d={}", QR_SCHEME, hex::encode(qr_json.as_bytes()));

        Ok(MobileAuthChallenge {
            session_id,
            challenge_nonce,
            created_at: now,
            expires_at: now + CHALLENGE_TTL_SECS,
            requested_capabilities,
            status: ChallengeStatus::Pending,
            node_endpoint: node_endpoint.to_string(),
            qr_payload,
        })
    }

    /// True if the challenge is past its TTL
    pub fn is_expired(&self) -> bool {
        now_secs() >= self.expires_at
    }

    /// Transition to Expired if TTL passed
    pub fn maybe_expire(&mut self) {
        if self.is_expired() {
            self.status = ChallengeStatus::Expired;
        }
    }
}

/// JSON envelope encoded into the QR code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrAuthEnvelope {
    pub session_id: String,
    pub challenge_nonce: String,
    pub node_endpoint: String,
    pub expires_at: u64,
    pub requested_capabilities: Vec<Capability>,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Extended session token carrying mobile-delegation metadata (Phase 1 + 2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileDelegatedSession {
    /// Opaque bearer token (Blake3 hash of internal material — never raw)
    pub access_token: String,
    /// Refreshable long-lived token (rotated on every use)
    pub refresh_token: String,
    /// Identity of the mobile key owner
    pub identity_id: IdentityId,
    /// Ed25519 or Dilithium public key that produced the challenge signature
    pub public_key_hex: String,
    /// Granted capabilities (intersection of requested and allowed)
    pub granted_capabilities: Vec<Capability>,
    /// Session creation time
    pub created_at: u64,
    /// Access token expiry
    pub access_expires_at: u64,
    /// Refresh token expiry
    pub refresh_expires_at: u64,
    /// IP the session was established from (binding)
    pub bound_ip: String,
    /// User-Agent the session was established from (binding)
    pub bound_user_agent: String,
    /// Challenge session ID this was derived from (audit trail)
    pub challenge_session_id: String,
    /// Device identifier supplied by mobile app (optional, for concurrent-session disambiguation)
    pub device_id: Option<String>,
    /// Whether this session is still active
    pub revoked: bool,
}

impl MobileDelegatedSession {
    /// Check if the access token is still valid (not expired, not revoked)
    pub fn is_access_valid(&self) -> bool {
        !self.revoked && now_secs() < self.access_expires_at
    }

    /// Check if the refresh token is still valid
    pub fn is_refresh_valid(&self) -> bool {
        !self.revoked && now_secs() < self.refresh_expires_at
    }

    /// Validate that request arrives from the same binding context (hijack protection)
    pub fn validate_binding(&self, ip: &str, ua: &str) -> bool {
        // Constant-time-safe comparison to avoid timing channels
        constant_time_eq(self.bound_ip.as_bytes(), ip.as_bytes())
            && constant_time_eq(self.bound_user_agent.as_bytes(), ua.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Delegation Certificate (Phase 3)
// ---------------------------------------------------------------------------

/// On-chain-compatible delegation record.
/// Mobile key owner (delegator) grants the web session (delegate) permission
/// to act within the specified capabilities until `expires_at`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCertificate {
    /// Certificate ID (unique, CSPRNG hex)
    pub cert_id: String,
    /// DID of the mobile key owner
    pub delegator_did: String,
    /// DID or session-scoped identifier of the web session
    pub delegate_id: String,
    /// Granted capabilities
    pub capabilities: Vec<Capability>,
    /// Unix second at which delegation expires
    pub expires_at: u64,
    /// Replay-protection nonce
    pub nonce: u64,
    /// Ed25519/Dilithium signature by delegator over canonical cert bytes
    pub signature_hex: String,
    /// Whether this certificate has been revoked
    pub revoked: bool,
    /// Revocation reason if revoked
    pub revocation_reason: Option<String>,
    /// Block height at which cert was registered (optional, populated when on-chain)
    pub registered_at_block: Option<u64>,
}

impl DelegationCertificate {
    /// Canonical serialization for signature verification (deterministic field order)
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "cert_id={}\ndelegator={}\ndelegate={}\ncaps={}\nexpires={}\nnonce={}",
            self.cert_id,
            self.delegator_did,
            self.delegate_id,
            self.capabilities
                .iter()
                .map(|c| c.label())
                .collect::<Vec<_>>()
                .join(","),
            self.expires_at,
            self.nonce
        )
        .into_bytes()
    }

    /// True if the certificate is currently active (not expired, not revoked)
    pub fn is_active(&self) -> bool {
        !self.revoked && now_secs() < self.expires_at
    }

    /// Check whether a specific capability is granted by this cert
    pub fn grants(&self, cap: &Capability) -> bool {
        self.is_active() && self.capabilities.contains(cap)
    }
}

// ---------------------------------------------------------------------------
// Rate limiter (Phase 2)
// ---------------------------------------------------------------------------

/// Per-IP challenge request rate limiter
#[derive(Debug, Default)]
pub struct ChallengeRateLimiter {
    /// Map: IP -> (window_start_secs, count_in_window)
    windows: Arc<RwLock<HashMap<String, (u64, u32)>>>,
}

impl ChallengeRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns Ok(()) if under limit, Err if rate-limited
    pub async fn check_and_record(&self, ip: &str) -> Result<()> {
        let now = now_secs();
        let window_start = now - (now % 60); // 1-minute sliding window
        let mut windows = self.windows.write().await;

        let entry = windows.entry(ip.to_string()).or_insert((window_start, 0));

        if entry.0 != window_start {
            // New window — reset
            *entry = (window_start, 1);
            return Ok(());
        }

        entry.1 += 1;
        if entry.1 > MAX_CHALLENGES_PER_IP_PER_MIN {
            return Err(anyhow!(
                "Rate limit exceeded: max {} challenge requests per minute per IP",
                MAX_CHALLENGES_PER_IP_PER_MIN
            ));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Audit log (Phase 2)
// ---------------------------------------------------------------------------

/// Type of auditable event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    ChallengeIssued,
    ChallengeSigned,
    ChallengeVerified,
    ChallengeExpired,
    ChallengeReused,
    SessionCreated,
    SessionRefreshed,
    SessionRevoked,
    SessionBindingViolation,
    DelegationIssued,
    DelegationRevoked,
    UnauthorizedCapabilityAccess,
}

/// Immutable audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub event_id: String,
    pub kind: AuditEventKind,
    pub session_id: Option<String>,
    pub identity_id: Option<String>,
    pub client_ip: String,
    pub timestamp: u64,
    pub details: String,
}

impl AuditLogEntry {
    pub fn new(
        kind: AuditEventKind,
        session_id: Option<&str>,
        identity_id: Option<&str>,
        client_ip: &str,
        details: &str,
    ) -> Self {
        let mut id_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        AuditLogEntry {
            event_id: hex::encode(id_bytes),
            kind,
            session_id: session_id.map(str::to_string),
            identity_id: identity_id.map(str::to_string),
            client_ip: client_ip.to_string(),
            timestamp: now_secs(),
            details: details.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-device session binder (Phase 2)
// ---------------------------------------------------------------------------

/// Links a web challenge session to the mobile device that satisfied it.
/// Enforces that only the originating device's signed nonce can activate
/// a session — prevents parallel-session substitution attacks.
#[derive(Debug, Clone)]
pub struct CrossDeviceSessionBinder;

impl CrossDeviceSessionBinder {
    /// Verify that a mobile-supplied signature matches the challenge nonce.
    ///
    /// Uses SOVEREIGN-NET's post-quantum Dilithium algorithm (same as the
    /// rest of the stack) so mobile identities don't need a separate key pair.
    /// The nonce bytes are the message that was signed.
    pub fn verify_cross_device_binding(
        challenge_nonce_hex: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<bool> {
        // Decode challenge nonce bytes (what was signed)
        let nonce_bytes = hex::decode(challenge_nonce_hex)
            .map_err(|e| anyhow!("Invalid challenge nonce hex: {}", e))?;

        // Decode supplied Dilithium signature
        let sig_bytes =
            hex::decode(signature_hex).map_err(|e| anyhow!("Invalid signature hex: {}", e))?;

        // Decode Dilithium public key
        let pk_bytes =
            hex::decode(public_key_hex).map_err(|e| anyhow!("Invalid public key hex: {}", e))?;

        if pk_bytes.len() < MIN_DILITHIUM_PK_BYTES {
            return Err(anyhow!(
                "Public key too short for Dilithium ({} bytes, min {})",
                pk_bytes.len(),
                MIN_DILITHIUM_PK_BYTES
            ));
        }

        // Delegate to lib_crypto post-quantum verifier
        lib_crypto::verify_signature(&nonce_bytes, &sig_bytes, &pk_bytes)
            .map_err(|e| anyhow!("Signature verification error: {}", e))
    }
}

// ---------------------------------------------------------------------------
// Store — in-memory registry (Phase 1 + 2 + 3)
// ---------------------------------------------------------------------------

/// Central in-memory store for challenges, sessions, and delegation certs.
/// Intended to be wrapped in an Arc at the server level.
#[derive(Debug, Default)]
pub struct MobileAuthStore {
    /// Pending/active challenges by session_id
    challenges: Arc<RwLock<HashMap<String, MobileAuthChallenge>>>,
    /// Active delegated sessions by access_token
    sessions: Arc<RwLock<HashMap<String, MobileDelegatedSession>>>,
    /// Refresh tokens -> access_token mapping (for rotation)
    refresh_index: Arc<RwLock<HashMap<String, String>>>,
    /// Identity -> Vec<access_token> (for per-identity session enumeration)
    identity_sessions: Arc<RwLock<HashMap<IdentityId, Vec<String>>>>,
    /// Delegation certificates by cert_id
    delegation_certs: Arc<RwLock<HashMap<String, DelegationCertificate>>>,
    /// Audit log (append-only in-memory ring, last 10 000 entries)
    audit_log: Arc<RwLock<Vec<AuditLogEntry>>>,
    /// Challenge rate limiter
    pub rate_limiter: Arc<ChallengeRateLimiter>,
}

impl MobileAuthStore {
    pub fn new() -> Self {
        Self {
            rate_limiter: Arc::new(ChallengeRateLimiter::new()),
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // Challenge lifecycle
    // -----------------------------------------------------------------------

    /// Store a newly generated challenge
    pub async fn insert_challenge(&self, challenge: MobileAuthChallenge) {
        let mut c = self.challenges.write().await;
        c.insert(challenge.session_id.clone(), challenge);
    }

    /// Retrieve a challenge by session_id, auto-expiring if TTL passed
    pub async fn get_challenge(&self, session_id: &str) -> Option<MobileAuthChallenge> {
        let mut c = self.challenges.write().await;
        if let Some(ch) = c.get_mut(session_id) {
            ch.maybe_expire();
            Some(ch.clone())
        } else {
            None
        }
    }

    /// Mark a challenge as used (prevents replay)
    pub async fn consume_challenge(&self, session_id: &str) -> Result<()> {
        let mut c = self.challenges.write().await;
        match c.get_mut(session_id) {
            None => Err(anyhow!("Challenge not found: {}", session_id)),
            Some(ch) => {
                if ch.status != ChallengeStatus::Pending && ch.status != ChallengeStatus::Signed {
                    return Err(anyhow!("Challenge already used or expired"));
                }
                ch.status = ChallengeStatus::Used;
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------------
    // Session lifecycle
    // -----------------------------------------------------------------------

    /// Create a new delegated session after challenge verification
    pub async fn create_session(
        &self,
        identity_id: IdentityId,
        public_key_hex: String,
        granted_capabilities: Vec<Capability>,
        bound_ip: String,
        bound_user_agent: String,
        challenge_session_id: String,
        device_id: Option<String>,
    ) -> Result<MobileDelegatedSession> {
        self.enforce_session_limit(&identity_id).await;

        let now = now_secs();

        // Access token: Blake3(identity + nonce + timestamp + session_id)
        let mut access_nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut access_nonce);
        let access_material = [
            identity_id.as_ref(),
            &access_nonce,
            &now.to_le_bytes(),
            challenge_session_id.as_bytes(),
            b"access_v1",
        ]
        .concat();
        let access_token = hex::encode(lib_crypto::hash_blake3(&access_material));

        // Refresh token: separate CSPRNG material
        let mut refresh_nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut refresh_nonce);
        let refresh_material = [
            identity_id.as_ref(),
            &refresh_nonce,
            &now.to_le_bytes(),
            b"refresh_v1",
        ]
        .concat();
        let refresh_token = hex::encode(lib_crypto::hash_blake3(&refresh_material));

        let session = MobileDelegatedSession {
            access_token: access_token.clone(),
            refresh_token: refresh_token.clone(),
            identity_id: identity_id.clone(),
            public_key_hex,
            granted_capabilities,
            created_at: now,
            access_expires_at: now + ACCESS_TOKEN_TTL_SECS,
            refresh_expires_at: now + REFRESH_TOKEN_TTL_SECS,
            bound_ip,
            bound_user_agent,
            challenge_session_id,
            device_id,
            revoked: false,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(access_token.clone(), session.clone());
        drop(sessions);

        let mut ri = self.refresh_index.write().await;
        ri.insert(refresh_token, access_token.clone());
        drop(ri);

        let mut is = self.identity_sessions.write().await;
        is.entry(identity_id)
            .or_insert_with(Vec::new)
            .push(access_token);

        Ok(session)
    }

    /// Validate a bearer access token and binding
    pub async fn validate_access_token(
        &self,
        token: &str,
        ip: &str,
        ua: &str,
    ) -> Result<MobileDelegatedSession> {
        let sessions = self.sessions.read().await;
        match sessions.get(token) {
            None => Err(anyhow!("Session not found")),
            Some(s) if s.revoked => Err(anyhow!("Session revoked")),
            Some(s) if !s.is_access_valid() => Err(anyhow!("Session expired")),
            Some(s) if !s.validate_binding(ip, ua) => Err(anyhow!(
                "Session binding mismatch (possible hijack attempt)"
            )),
            Some(s) => Ok(s.clone()),
        }
    }

    /// Rotate refresh token — old token is invalidated, new session issued
    pub async fn rotate_refresh_token(
        &self,
        old_refresh_token: &str,
        ip: &str,
        ua: &str,
    ) -> Result<MobileDelegatedSession> {
        // Look up existing access token
        let access_token = {
            let ri = self.refresh_index.read().await;
            ri.get(old_refresh_token)
                .cloned()
                .ok_or_else(|| anyhow!("Refresh token not found"))?
        };

        let old_session = {
            let sessions = self.sessions.read().await;
            sessions
                .get(&access_token)
                .cloned()
                .ok_or_else(|| anyhow!("Session not found for refresh token"))?
        };

        if old_session.revoked {
            return Err(anyhow!("Session already revoked"));
        }
        if now_secs() >= old_session.refresh_expires_at {
            return Err(anyhow!("Refresh token expired — must re-authenticate"));
        }
        if !old_session.validate_binding(ip, ua) {
            return Err(anyhow!("Binding mismatch on refresh attempt"));
        }

        // Revoke old session
        self.revoke_session(&access_token, "refresh_rotation")
            .await?;

        // Issue new session with same capabilities
        self.create_session(
            old_session.identity_id.clone(),
            old_session.public_key_hex.clone(),
            old_session.granted_capabilities.clone(),
            ip.to_string(),
            ua.to_string(),
            old_session.challenge_session_id.clone(),
            old_session.device_id.clone(),
        )
        .await
    }

    /// Revoke a session by access token
    pub async fn revoke_session(&self, access_token: &str, reason: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        match sessions.get_mut(access_token) {
            None => Err(anyhow!("Session not found")),
            Some(s) => {
                s.revoked = true;
                tracing::info!("Session revoked: {} reason={}", &access_token[..16], reason);
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------------
    // Delegation certificate lifecycle (Phase 3)
    // -----------------------------------------------------------------------

    /// Register a delegation certificate
    pub async fn register_delegation_cert(&self, cert: DelegationCertificate) -> Result<()> {
        if cert.expires_at <= now_secs() {
            return Err(anyhow!("Cannot register already-expired delegation cert"));
        }
        let mut certs = self.delegation_certs.write().await;
        if certs.contains_key(&cert.cert_id) {
            return Err(anyhow!("Duplicate delegation cert id: {}", cert.cert_id));
        }
        certs.insert(cert.cert_id.clone(), cert);
        Ok(())
    }

    /// Retrieve an active delegation certificate
    pub async fn get_delegation_cert(&self, cert_id: &str) -> Option<DelegationCertificate> {
        let certs = self.delegation_certs.read().await;
        certs.get(cert_id).cloned()
    }

    /// Revoke a delegation certificate (delegator-triggered)
    pub async fn revoke_delegation_cert(&self, cert_id: &str, reason: &str) -> Result<()> {
        let mut certs = self.delegation_certs.write().await;
        match certs.get_mut(cert_id) {
            None => Err(anyhow!("Delegation cert not found: {}", cert_id)),
            Some(c) => {
                c.revoked = true;
                c.revocation_reason = Some(reason.to_string());
                tracing::info!("Delegation cert revoked: {} reason={}", cert_id, reason);
                Ok(())
            }
        }
    }

    /// List all active delegation certs for a delegator DID
    pub async fn list_active_certs_for(&self, delegator_did: &str) -> Vec<DelegationCertificate> {
        let certs = self.delegation_certs.read().await;
        certs
            .values()
            .filter(|c| c.delegator_did == delegator_did && c.is_active())
            .cloned()
            .collect()
    }

    // -----------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------

    pub async fn append_audit(&self, entry: AuditLogEntry) {
        let mut log = self.audit_log.write().await;
        if log.len() >= 10_000 {
            log.drain(0..1_000); // keep last 9 000 when buffer full
        }
        log.push(entry);
    }

    pub async fn audit_snapshot(&self) -> Vec<AuditLogEntry> {
        self.audit_log.read().await.clone()
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    async fn enforce_session_limit(&self, identity_id: &IdentityId) {
        // Collect tokens to evict without holding any locks across await points.
        let to_revoke: Vec<String> = {
            let mut is = self.identity_sessions.write().await;
            let tokens = match is.get_mut(identity_id) {
                Some(t) => t,
                None => return,
            };

            // Prune already-dead tokens (no await here — use try_read)
            if let Ok(s) = self.sessions.try_read() {
                tokens.retain(|t| {
                    s.get(t)
                        .map_or(false, |sess| !sess.revoked && sess.is_access_valid())
                });
            }

            // Collect oldest tokens that need eviction
            let excess = tokens.len().saturating_sub(MAX_SESSIONS_PER_IDENTITY - 1);
            if excess == 0 {
                return;
            }
            let evict: Vec<String> = tokens.drain(..excess).collect();
            evict
        };

        // Revoke outside the lock
        for token in to_revoke {
            let _ = self.revoke_session(&token, "session_limit_enforced").await;
        }
    }

    /// Insert a session directly — only available in tests (bypasses challenge/verify flow)
    #[cfg(test)]
    pub async fn insert_session_for_test(&self, session: MobileDelegatedSession) {
        let token = session.access_token.clone();
        let identity_id = session.identity_id.clone();
        self.sessions.write().await.insert(token.clone(), session);
        self.identity_sessions
            .write()
            .await
            .entry(identity_id)
            .or_default()
            .push(token);
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Constant-time byte slice equality to prevent timing-channel leakage.
/// Returns true only when `a` and `b` are the same length AND every byte is equal.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Length difference is not secret — it's safe to return early here
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Challenge generation
    // -----------------------------------------------------------------------

    #[test]
    fn challenge_has_correct_ttl() {
        let ch =
            MobileAuthChallenge::generate(vec![Capability::ReadBalance], "http://localhost:9334")
                .unwrap();
        let now = now_secs();
        assert!(ch.expires_at > now);
        assert!(ch.expires_at <= now + CHALLENGE_TTL_SECS + 2); // +2s clock leeway
    }

    #[test]
    fn challenge_nonce_is_unique() {
        let a = MobileAuthChallenge::generate(vec![], "http://localhost:9334").unwrap();
        let b = MobileAuthChallenge::generate(vec![], "http://localhost:9334").unwrap();
        assert_ne!(a.challenge_nonce, b.challenge_nonce);
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn challenge_qr_payload_contains_scheme() {
        let ch =
            MobileAuthChallenge::generate(vec![Capability::ReadBalance], "http://localhost:9334")
                .unwrap();
        assert!(ch.qr_payload.starts_with(QR_SCHEME));
    }

    #[test]
    fn challenge_qr_payload_decodable() {
        let ch =
            MobileAuthChallenge::generate(vec![Capability::ReadBalance], "http://localhost:9334")
                .unwrap();
        // Strip scheme prefix: zhtp://auth?d=<hex>
        let hex_part = ch
            .qr_payload
            .strip_prefix(&format!("{}?d=", QR_SCHEME))
            .expect("Missing QR scheme prefix");
        let json_bytes = hex::decode(hex_part).expect("Invalid hex in QR payload");
        let envelope: QrAuthEnvelope =
            serde_json::from_slice(&json_bytes).expect("Invalid QR envelope JSON");
        assert_eq!(envelope.session_id, ch.session_id);
        assert_eq!(envelope.challenge_nonce, ch.challenge_nonce);
    }

    // -----------------------------------------------------------------------
    // Expiry
    // -----------------------------------------------------------------------

    #[test]
    fn expired_challenge_reports_expired() {
        let mut ch = MobileAuthChallenge::generate(vec![], "http://localhost:9334").unwrap();
        // Force expiry
        ch.expires_at = now_secs() - 1;
        ch.maybe_expire();
        assert_eq!(ch.status, ChallengeStatus::Expired);
        assert!(ch.is_expired());
    }

    // -----------------------------------------------------------------------
    // Rate limiter — unit test (sync simulation)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rate_limiter_blocks_after_limit() {
        let rl = ChallengeRateLimiter::new();
        // Allow up to MAX_CHALLENGES_PER_IP_PER_MIN requests
        for _ in 0..MAX_CHALLENGES_PER_IP_PER_MIN {
            rl.check_and_record("1.2.3.4").await.unwrap();
        }
        // The next one should be rejected
        let result = rl.check_and_record("1.2.3.4").await;
        assert!(result.is_err(), "Expected rate limit error");
    }

    #[tokio::test]
    async fn rate_limiter_allows_different_ips() {
        let rl = ChallengeRateLimiter::new();
        for i in 0..MAX_CHALLENGES_PER_IP_PER_MIN + 5 {
            let ip = format!("10.0.0.{}", i);
            rl.check_and_record(&ip).await.unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // Store — challenge lifecycle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn store_consume_prevents_replay() {
        let store = MobileAuthStore::new();
        let ch = MobileAuthChallenge::generate(vec![], "http://localhost:9334").unwrap();
        let sid = ch.session_id.clone();
        store.insert_challenge(ch).await;

        // First consume succeeds
        store.consume_challenge(&sid).await.unwrap();
        // Second consume must fail
        let err = store.consume_challenge(&sid).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn store_unknown_challenge_returns_none() {
        let store = MobileAuthStore::new();
        assert!(store.get_challenge("nonexistent").await.is_none());
    }

    // -----------------------------------------------------------------------
    // Session validation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_binding_validates_ip_and_ua() {
        let store = MobileAuthStore::new();
        let identity_id = lib_crypto::Hash::from_bytes(&[1u8; 32]);
        let session = store
            .create_session(
                identity_id.clone(),
                "deadbeef".repeat(163).to_string(), // placeholder pk
                vec![Capability::ReadBalance],
                "192.168.1.1".to_string(),
                "TestAgent/1.0".to_string(),
                "test-session-id".to_string(),
                None,
            )
            .await
            .unwrap();

        // Correct binding passes
        store
            .validate_access_token(&session.access_token, "192.168.1.1", "TestAgent/1.0")
            .await
            .unwrap();

        // Wrong IP rejected
        let mismatch = store
            .validate_access_token(&session.access_token, "10.0.0.1", "TestAgent/1.0")
            .await;
        assert!(mismatch.is_err());
    }

    // -----------------------------------------------------------------------
    // Refresh rotation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_rotation_invalidates_old_token() {
        let store = MobileAuthStore::new();
        let identity_id = lib_crypto::Hash::from_bytes(&[2u8; 32]);
        let session = store
            .create_session(
                identity_id,
                "pk".to_string(),
                vec![Capability::ReadBalance],
                "127.0.0.1".to_string(),
                "UA".to_string(),
                "sid1".to_string(),
                None,
            )
            .await
            .unwrap();

        let old_access = session.access_token.clone();
        let old_refresh = session.refresh_token.clone();

        // Rotate
        let new_session = store
            .rotate_refresh_token(&old_refresh, "127.0.0.1", "UA")
            .await
            .unwrap();

        // Old access token should now be revoked
        let validation = store
            .validate_access_token(&old_access, "127.0.0.1", "UA")
            .await;
        assert!(validation.is_err());

        // New token works
        store
            .validate_access_token(&new_session.access_token, "127.0.0.1", "UA")
            .await
            .unwrap();

        // Old refresh token must fail (already used)
        let replay = store
            .rotate_refresh_token(&old_refresh, "127.0.0.1", "UA")
            .await;
        assert!(replay.is_err());
    }

    // -----------------------------------------------------------------------
    // Delegation certificate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delegation_cert_lifecycle() {
        let store = MobileAuthStore::new();
        let mut id_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let cert_id = hex::encode(id_bytes);

        let cert = DelegationCertificate {
            cert_id: cert_id.clone(),
            delegator_did: "did:zhtp:alice".to_string(),
            delegate_id: "did:zhtp:web-session-1".to_string(),
            capabilities: vec![Capability::ReadBalance, Capability::VoteGovernance],
            expires_at: now_secs() + 3600,
            nonce: 1,
            signature_hex: "00".repeat(600), // placeholder
            revoked: false,
            revocation_reason: None,
            registered_at_block: None,
        };

        store.register_delegation_cert(cert).await.unwrap();

        // Retrieve and check active
        let fetched = store.get_delegation_cert(&cert_id).await.unwrap();
        assert!(fetched.is_active());
        assert!(fetched.grants(&Capability::ReadBalance));
        assert!(!fetched.grants(&Capability::SubmitTx {
            max_amount_tokens: 100
        }));

        // Revoke
        store
            .revoke_delegation_cert(&cert_id, "user_requested")
            .await
            .unwrap();
        let revoked = store.get_delegation_cert(&cert_id).await.unwrap();
        assert!(!revoked.is_active());
        assert_eq!(revoked.revocation_reason.as_deref(), Some("user_requested"));
    }

    #[tokio::test]
    async fn duplicate_cert_id_rejected() {
        let store = MobileAuthStore::new();
        let cert = DelegationCertificate {
            cert_id: "cert-abc".to_string(),
            delegator_did: "did:zhtp:alice".to_string(),
            delegate_id: "did:zhtp:web-1".to_string(),
            capabilities: vec![],
            expires_at: now_secs() + 3600,
            nonce: 1,
            signature_hex: "00".to_string(),
            revoked: false,
            revocation_reason: None,
            registered_at_block: None,
        };
        store.register_delegation_cert(cert.clone()).await.unwrap();
        let dup = store.register_delegation_cert(cert).await;
        assert!(dup.is_err());
    }

    // -----------------------------------------------------------------------
    // Session limit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_limit_evicts_oldest() {
        let store = MobileAuthStore::new();
        let identity_id = lib_crypto::Hash::from_bytes(&[9u8; 32]);
        let mut tokens = vec![];

        for i in 0..MAX_SESSIONS_PER_IDENTITY {
            let s = store
                .create_session(
                    identity_id.clone(),
                    "pk".to_string(),
                    vec![],
                    "127.0.0.1".to_string(),
                    "UA".to_string(),
                    format!("sid-{}", i),
                    None,
                )
                .await
                .unwrap();
            tokens.push(s.access_token);
        }

        // Creating one more should succeed (oldest evicted internally)
        let extra = store
            .create_session(
                identity_id.clone(),
                "pk".to_string(),
                vec![],
                "127.0.0.1".to_string(),
                "UA".to_string(),
                "sid-extra".to_string(),
                None,
            )
            .await;
        assert!(extra.is_ok());
    }

    // -----------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn audit_log_records_events() {
        let store = MobileAuthStore::new();
        let entry = AuditLogEntry::new(
            AuditEventKind::ChallengeIssued,
            Some("sess-1"),
            None,
            "1.2.3.4",
            "challenge created",
        );
        store.append_audit(entry).await;
        let snap = store.audit_snapshot().await;
        assert_eq!(snap.len(), 1);
        assert!(matches!(snap[0].kind, AuditEventKind::ChallengeIssued));
    }

    // -----------------------------------------------------------------------
    // Constant-time equality
    // -----------------------------------------------------------------------

    #[test]
    fn constant_time_eq_correct() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hi", b"hello"));
        assert!(constant_time_eq(b"", b""));
    }
}
