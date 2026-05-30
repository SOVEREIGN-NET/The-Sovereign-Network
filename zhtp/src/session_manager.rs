//! Session Manager for ZHTP Server
//!
//! Manages authenticated user sessions with secure tokens

use anyhow::{anyhow, Result};
use lib_identity::{IdentityId, SessionToken};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use std::sync::OnceLock;

static GLOBAL_SESSION_MANAGER: OnceLock<Arc<SessionManager>> = OnceLock::new();

/// Set the global session manager instance. Called once during startup.
pub fn set_global_session_manager(manager: Arc<SessionManager>) {
    let _ = GLOBAL_SESSION_MANAGER.set(manager);
}

/// Access the global session manager. Returns `None` if startup hasn't yet
/// installed one — only happens in unit tests or during early bootstrap.
pub fn session_manager_handle() -> Option<Arc<SessionManager>> {
    GLOBAL_SESSION_MANAGER.get().cloned()
}

/// S6: if this request carries a Password (OPAQUE lobby) session bearer
/// token, return `(token, session_key)`. Returns `None` for unauthenticated
/// requests, Key sessions, or Password sessions without a stored key.
pub async fn request_password_session_with_key(
    request: &lib_protocols::types::ZhtpRequest,
) -> Option<(String, Vec<u8>)> {
    let auth = request.headers.get("Authorization")?;
    let token = auth.strip_prefix("Bearer ")?.to_string();
    let mgr = GLOBAL_SESSION_MANAGER.get()?;
    if !mgr.is_password_session(&token).await {
        return None;
    }
    let key = mgr.opaque_session_key(&token).await?;
    Some((token, key))
}

/// Check if a request's bearer token is from a password session (public zone only).
/// Returns true if the token is a password session → handler should reject wallet access.
pub async fn is_request_password_session(request: &lib_protocols::types::ZhtpRequest) -> bool {
    let token = match request.headers.get("Authorization") {
        Some(auth) => match auth.strip_prefix("Bearer ") {
            Some(t) => t.to_string(),
            None => return false,
        },
        None => return false,
    };
    if let Some(mgr) = GLOBAL_SESSION_MANAGER.get() {
        mgr.is_password_session(&token).await
    } else {
        false
    }
}

/// Session manager for the ZHTP server
#[derive(Debug)]
pub struct SessionManager {
    /// Active sessions by token
    sessions: Arc<RwLock<HashMap<String, SessionToken>>>,
    /// Sessions by identity ID for cleanup
    sessions_by_identity: Arc<RwLock<HashMap<IdentityId, Vec<String>>>>,
    /// Default session duration
    default_session_duration: u64,
    /// Maximum concurrent sessions per identity
    max_sessions_per_identity: usize,
    /// OPAQUE-derived session keys, keyed by session_token. Only present
    /// for sessions issued through the lobby OPAQUE login flow. Used for
    /// per-request HMAC channel binding (verified in S6 #2560).
    opaque_session_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Highest `X-OPAQUE-Seq` value seen for each OPAQUE-bound session.
    /// Strict monotonic — server rejects seq ≤ last seen as replay (S6).
    opaque_last_seq: Arc<RwLock<HashMap<String, u64>>>,
    /// Device QUIC key_id → canonical chain DID bindings.
    ///
    /// Mobiles generate an ephemeral QUIC keypair per device/session that
    /// does NOT match the chain-registered identity's keys. The msg/receive
    /// resolver scans identity_registry for entries whose
    /// `blake3(dilithium_pk)` or `blake3(dilithium_pk||kyber_pk)` match the
    /// requester's QUIC key_id — neither matches for ephemeral keys, so
    /// messages addressed to the canonical DID never reach the polling
    /// device.
    ///
    /// This map is populated on a successful OPAQUE login (password proves
    /// authority over the canonical DID; the QUIC key_id of the login
    /// connection is recorded as a device of that DID). The msg/receive
    /// resolver consults this map BEFORE the existing hash-based scan, so
    /// every subsequent /msg/* request on the same QUIC session (or any
    /// future session whose key_id has been bound) resolves to the
    /// canonical DID.
    ///
    /// Per-server state, in-memory only — cleared on restart. Mobile
    /// re-logs in OPAQUE on next session start, which re-establishes the
    /// binding. No chain transaction or schema change is needed.
    device_quic_key_canonical_did: Arc<RwLock<HashMap<[u8; 32], String>>>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            sessions_by_identity: Arc::new(RwLock::new(HashMap::new())),
            default_session_duration: 24 * 60 * 60, // 24 hours
            max_sessions_per_identity: 5,
            opaque_session_keys: Arc::new(RwLock::new(HashMap::new())),
            opaque_last_seq: Arc::new(RwLock::new(HashMap::new())),
            device_quic_key_canonical_did: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record that QUIC key_id `device_key` belongs to canonical chain DID
    /// `canonical_did`. Called from `handle_login_finish` after a successful
    /// OPAQUE login: the password proves authority, the QUIC key of the
    /// login connection is recorded as a device of that DID. Idempotent;
    /// repeat logins from the same device are no-ops.
    pub async fn bind_device_to_canonical_did(
        &self,
        device_key: [u8; 32],
        canonical_did: String,
    ) {
        let mut map = self.device_quic_key_canonical_did.write().await;
        map.insert(device_key, canonical_did);
    }

    /// Look up the canonical chain DID for a given QUIC key_id. Returns
    /// `None` if no OPAQUE login has bound this device key.
    ///
    /// Used by `/api/v1/msg/receive`'s recipient resolver to map an
    /// incoming polling device's ephemeral QUIC identity to the user's
    /// canonical DID, so messages addressed to the canonical DID reach the
    /// device.
    pub async fn canonical_did_for_quic_key(
        &self,
        device_key: &[u8; 32],
    ) -> Option<String> {
        self.device_quic_key_canonical_did
            .read()
            .await
            .get(device_key)
            .cloned()
    }

    /// S6: atomically verify and advance the per-session monotonic sequence
    /// counter. Returns `true` if `seq` is strictly greater than the last
    /// seen value (or this is the first request) — the counter is then
    /// updated to `seq`. Returns `false` for a replay or out-of-order seq.
    pub async fn check_and_advance_seq(&self, token: &str, seq: u64) -> bool {
        let mut map = self.opaque_last_seq.write().await;
        let last = map.get(token).copied().unwrap_or(0);
        if seq <= last {
            return false;
        }
        map.insert(token.to_string(), seq);
        true
    }

    /// Create a password-authenticated session AND store the OPAQUE-derived
    /// session_key alongside it. The key is later used by the per-request
    /// HMAC channel-binding check (S6 #2560).
    pub async fn create_password_session_with_key(
        &self,
        identity_id: IdentityId,
        client_ip: &str,
        user_agent: &str,
        session_key: Vec<u8>,
    ) -> Result<String> {
        let token = self
            .create_password_session(identity_id, client_ip, user_agent)
            .await?;
        let mut keys = self.opaque_session_keys.write().await;
        keys.insert(token.clone(), session_key);
        Ok(token)
    }

    /// Fetch the OPAQUE session_key for a token, if any. Used by the
    /// channel-binding middleware.
    pub async fn opaque_session_key(&self, token: &str) -> Option<Vec<u8>> {
        self.opaque_session_keys.read().await.get(token).cloned()
    }

    /// Create a new session for an authenticated identity
    pub async fn create_session(
        &self,
        identity_id: IdentityId,
        client_ip: &str,
        user_agent: &str,
    ) -> Result<String> {
        // Clean up expired sessions first
        self.cleanup_expired_sessions().await;

        // Check session limits
        let sessions_by_identity = self.sessions_by_identity.read().await;
        if let Some(existing_sessions) = sessions_by_identity.get(&identity_id) {
            if existing_sessions.len() >= self.max_sessions_per_identity {
                drop(sessions_by_identity);
                // Remove oldest session
                self.remove_oldest_session(&identity_id).await?;
            } else {
                drop(sessions_by_identity);
            }
        } else {
            drop(sessions_by_identity);
        }

        // Create new session token with IP/UA binding (P0-6)
        let session_token = SessionToken::new(
            identity_id.clone(),
            self.default_session_duration,
            Some(client_ip.to_string()),
            Some(user_agent.to_string()),
        )?;
        let token_string = session_token.token.clone();

        // Store session
        let mut sessions = self.sessions.write().await;
        sessions.insert(token_string.clone(), session_token);
        drop(sessions);

        // Update sessions by identity
        let mut sessions_by_identity = self.sessions_by_identity.write().await;
        sessions_by_identity
            .entry(identity_id.clone())
            .or_insert_with(Vec::new)
            .push(token_string.clone());
        drop(sessions_by_identity);

        tracing::info!(
            "🎫 New session created for identity {}: {} (IP: {})",
            hex::encode(&identity_id.0[..8]),
            &token_string[..16],
            client_ip
        );

        Ok(token_string)
    }

    /// Create a password-authenticated session (public zone only).
    pub async fn create_password_session(
        &self,
        identity_id: IdentityId,
        client_ip: &str,
        user_agent: &str,
    ) -> Result<String> {
        let token = self.create_session(identity_id, client_ip, user_agent).await?;
        // Mark as password session
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&token) {
            session.auth_method = lib_identity::auth::session::AuthMethod::Password;
        }
        Ok(token)
    }

    /// Check if a session was created via password (public zone only).
    pub async fn is_password_session(&self, token: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions
            .get(token)
            .map(|s| s.auth_method == lib_identity::auth::session::AuthMethod::Password)
            .unwrap_or(false)
    }

    /// Validate and get session token with IP/UA binding check (P0-6)
    pub async fn validate_session(
        &self,
        token: &str,
        current_ip: &str,
        current_ua: &str,
    ) -> Result<SessionToken> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(token) {
            if session.is_valid() {
                // P0-6: Validate IP/UA binding
                if !session.validate_binding(current_ip, current_ua) {
                    return Err(anyhow!("Session binding validation failed"));
                }

                session.touch(); // Update last used timestamp
                Ok(session.clone())
            } else {
                // Session expired, remove it
                let identity_id = session.identity_id.clone();
                sessions.remove(token);
                drop(sessions);

                // Remove from sessions by identity
                let mut sessions_by_identity = self.sessions_by_identity.write().await;
                if let Some(identity_sessions) = sessions_by_identity.get_mut(&identity_id) {
                    identity_sessions.retain(|t| t != token);
                    if identity_sessions.is_empty() {
                        sessions_by_identity.remove(&identity_id);
                    }
                }

                Err(anyhow!("Session expired"))
            }
        } else {
            Err(anyhow!("Invalid session token"))
        }
    }

    /// Remove a session (signout)
    pub async fn remove_session(&self, token: &str) -> Result<()> {
        // Clean up OPAQUE-side state alongside the session itself.
        self.opaque_session_keys.write().await.remove(token);
        self.opaque_last_seq.write().await.remove(token);

        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.remove(token) {
            let identity_id = session.identity_id;
            drop(sessions);

            // Remove from sessions by identity
            let mut sessions_by_identity = self.sessions_by_identity.write().await;
            if let Some(identity_sessions) = sessions_by_identity.get_mut(&identity_id) {
                identity_sessions.retain(|t| t != token);
                if identity_sessions.is_empty() {
                    sessions_by_identity.remove(&identity_id);
                }
            }

            tracing::info!(
                "🚪 Session removed for identity {}: {}",
                hex::encode(&identity_id.0[..8]),
                &token[..16]
            );

            Ok(())
        } else {
            Err(anyhow!("Session not found"))
        }
    }

    /// Remove all sessions for an identity
    pub async fn remove_all_sessions(&self, identity_id: &IdentityId) -> Result<usize> {
        let mut sessions_by_identity = self.sessions_by_identity.write().await;

        if let Some(identity_sessions) = sessions_by_identity.remove(identity_id) {
            let session_count = identity_sessions.len();
            drop(sessions_by_identity);

            // Remove all sessions for this identity
            let mut sessions = self.sessions.write().await;
            for token in identity_sessions {
                sessions.remove(&token);
            }

            tracing::info!(
                "🚪 All {} sessions removed for identity {}",
                session_count,
                hex::encode(&identity_id.0[..8])
            );

            Ok(session_count)
        } else {
            Ok(0)
        }
    }

    /// Get active session count for an identity
    pub async fn get_session_count(&self, identity_id: &IdentityId) -> usize {
        let sessions_by_identity = self.sessions_by_identity.read().await;
        sessions_by_identity
            .get(identity_id)
            .map(|sessions| sessions.len())
            .unwrap_or(0)
    }

    /// Get all active sessions for an identity
    pub async fn get_identity_sessions(&self, identity_id: &IdentityId) -> Vec<SessionToken> {
        let sessions_by_identity = self.sessions_by_identity.read().await;
        let sessions = self.sessions.read().await;

        if let Some(identity_sessions) = sessions_by_identity.get(identity_id) {
            identity_sessions
                .iter()
                .filter_map(|token| sessions.get(token).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let mut sessions_by_identity = self.sessions_by_identity.write().await;

        let mut expired_tokens = Vec::new();
        let mut identity_cleanup = HashMap::new();

        // Find expired sessions
        for (token, session) in sessions.iter() {
            if !session.is_valid() {
                expired_tokens.push(token.clone());
                identity_cleanup
                    .entry(session.identity_id.clone())
                    .or_insert_with(Vec::new)
                    .push(token.clone());
            }
        }

        // Remove expired sessions
        let mut removed_count = 0;
        for token in expired_tokens {
            sessions.remove(&token);
            removed_count += 1;
        }

        // Clean up sessions by identity mapping
        for (identity_id, expired_tokens) in identity_cleanup {
            if let Some(identity_sessions) = sessions_by_identity.get_mut(&identity_id) {
                for token in expired_tokens {
                    identity_sessions.retain(|t| t != &token);
                }
                if identity_sessions.is_empty() {
                    sessions_by_identity.remove(&identity_id);
                }
            }
        }

        if removed_count > 0 {
            tracing::info!(" Cleaned up {} expired sessions", removed_count);
        }
    }

    /// Get total active session count
    pub async fn get_total_session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Remove oldest session for an identity to enforce limits
    async fn remove_oldest_session(&self, identity_id: &IdentityId) -> Result<()> {
        let sessions_by_identity = self.sessions_by_identity.read().await;
        let sessions = self.sessions.read().await;

        if let Some(identity_sessions) = sessions_by_identity.get(identity_id) {
            // Find oldest session
            let mut oldest_token = None;
            let mut oldest_created = u64::MAX;

            for token in identity_sessions {
                if let Some(session) = sessions.get(token) {
                    if session.created_at < oldest_created {
                        oldest_created = session.created_at;
                        oldest_token = Some(token.clone());
                    }
                }
            }

            drop(sessions);
            drop(sessions_by_identity);

            if let Some(token) = oldest_token {
                self.remove_session(&token).await?;
            }
        }

        Ok(())
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(&self) {
        let session_manager = SessionManager {
            sessions: Arc::clone(&self.sessions),
            sessions_by_identity: Arc::clone(&self.sessions_by_identity),
            default_session_duration: self.default_session_duration,
            max_sessions_per_identity: self.max_sessions_per_identity,
            opaque_session_keys: Arc::clone(&self.opaque_session_keys),
            opaque_last_seq: Arc::clone(&self.opaque_last_seq),
            device_quic_key_canonical_did: Arc::clone(&self.device_quic_key_canonical_did),
        };

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;
                session_manager.cleanup_expired_sessions().await;
            }
        });

        tracing::info!(" Session cleanup task started (runs every 5 minutes)");
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
