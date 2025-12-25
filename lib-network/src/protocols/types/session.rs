//! Session management, keys, lifecycle, and replay protection

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::ConstantTimeEq;
use parking_lot::RwLock;
use super::security::CipherSuite;
use super::network::NetworkProtocol;
use super::peer::{PeerAddress, VerifiedPeerIdentity};

/// Session ID entropy size in bytes
pub const SESSION_ID_SIZE: usize = 32;

/// Default session lifetime in seconds (24 hours)
pub const DEFAULT_SESSION_LIFETIME_SECS: u64 = 86400;

/// Default idle timeout in seconds (15 minutes)
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900;

/// Default maximum messages before rekeying (1 million)
pub const DEFAULT_MAX_MESSAGES: u64 = 1_000_000;

/// Replay protection window size
pub const REPLAY_WINDOW_SIZE: usize = 128;

/// Cryptographically secure session identifier
///
/// Generated with 256 bits of entropy to prevent prediction and collision attacks.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionId([u8; SESSION_ID_SIZE]);

impl SessionId {
    /// Generate a new cryptographically random session ID
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut id = [0u8; SESSION_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        Self(id)
    }

    /// Create from existing bytes (for deserialization)
    pub fn from_bytes(bytes: [u8; SESSION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; SESSION_ID_SIZE] {
        &self.0
    }

    /// Constant-time equality comparison
    pub fn ct_eq(&self, other: &SessionId) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }

    /// Convert to hex string for logging (doesn't expose full ID)
    pub fn to_short_string(&self) -> String {
        format!("{}...", hex::encode(&self.0[..4]))
    }
}

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionId({}...)", hex::encode(&self.0[..4]))
    }
}

impl Serialize for SessionId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != SESSION_ID_SIZE {
            return Err(serde::de::Error::custom(format!(
                "Expected {} bytes for SessionId, got {}",
                SESSION_ID_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; SESSION_ID_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(SessionId(arr))
    }
}

/// Typed session keys with validation and zeroization
///
/// Keys are automatically zeroized when dropped to prevent memory leakage.
pub struct SessionKeys {
    /// Encryption key (32 bytes for AES-256 or ChaCha20)
    encryption_key: Option<[u8; 32]>,
    /// Authentication key (for HMAC if separate from AEAD)
    authentication_key: Option<[u8; 32]>,
    /// Key derivation salt
    kdf_salt: Option<[u8; 32]>,
    /// Whether keys were derived with forward secrecy (ephemeral DH/Kyber)
    has_forward_secrecy: bool,
    /// Rekeying generation counter
    rekey_generation: u32,
    /// Cipher suite these keys are valid for
    cipher_suite: CipherSuite,
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.encryption_key {
            key.zeroize();
        }
        if let Some(ref mut key) = self.authentication_key {
            key.zeroize();
        }
        if let Some(ref mut salt) = self.kdf_salt {
            salt.zeroize();
        }
    }
}

impl SessionKeys {
    /// Create new session keys for a cipher suite
    pub fn new(cipher_suite: CipherSuite, has_forward_secrecy: bool) -> Self {
        Self {
            encryption_key: None,
            authentication_key: None,
            kdf_salt: None,
            has_forward_secrecy,
            rekey_generation: 0,
            cipher_suite,
        }
    }

    /// Set the encryption key with validation
    pub fn set_encryption_key(&mut self, key: [u8; 32]) -> Result<()> {
        if key.iter().all(|&b| b == 0) {
            return Err(anyhow!("Invalid encryption key: all zeros (weak key)"));
        }
        self.encryption_key = Some(key);
        Ok(())
    }

    /// Set the authentication key with validation
    pub fn set_authentication_key(&mut self, key: [u8; 32]) -> Result<()> {
        if key.iter().all(|&b| b == 0) {
            return Err(anyhow!("Invalid authentication key: all zeros (weak key)"));
        }
        self.authentication_key = Some(key);
        Ok(())
    }

    /// Set the KDF salt
    pub fn set_kdf_salt(&mut self, salt: [u8; 32]) {
        self.kdf_salt = Some(salt);
    }

    /// Get the encryption key
    pub fn encryption_key(&self) -> Result<&[u8; 32]> {
        self.encryption_key
            .as_ref()
            .ok_or_else(|| anyhow!("Encryption key not set"))
    }

    /// Get the authentication key
    pub fn authentication_key(&self) -> Option<&[u8; 32]> {
        self.authentication_key.as_ref()
    }

    /// Check if keys provide forward secrecy
    pub fn has_forward_secrecy(&self) -> bool {
        self.has_forward_secrecy
    }

    /// Get the rekey generation
    pub fn rekey_generation(&self) -> u32 {
        self.rekey_generation
    }

    /// Increment rekey generation (called after successful rekey)
    pub fn increment_rekey_generation(&mut self) {
        self.rekey_generation = self.rekey_generation.saturating_add(1);
    }

    /// Get the cipher suite
    pub fn cipher_suite(&self) -> &CipherSuite {
        &self.cipher_suite
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("encryption_key", &self.encryption_key.as_ref().map(|_| "<redacted>"))
            .field("authentication_key", &self.authentication_key.as_ref().map(|_| "<redacted>"))
            .field("has_forward_secrecy", &self.has_forward_secrecy)
            .field("rekey_generation", &self.rekey_generation)
            .field("cipher_suite", &self.cipher_suite)
            .finish()
    }
}

/// Structured replay protection state with sliding window
///
/// Implements RFC 6479-style sliding window anti-replay protection.
pub struct ReplayProtectionState {
    /// Monotonic counter for sent messages (thread-safe)
    send_counter: AtomicU64,
    /// Highest received sequence number
    recv_counter: AtomicU64,
    /// Bitmap of recently received sequence numbers (sliding window)
    recv_window: RwLock<Vec<bool>>,
    /// Window size
    window_size: usize,
}

impl ReplayProtectionState {
    /// Create new replay protection state
    pub fn new(window_size: usize) -> Self {
        Self {
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            recv_window: RwLock::new(vec![false; window_size]),
            window_size,
        }
    }

    /// Get next send sequence number (thread-safe, atomic)
    pub fn next_send_sequence(&self) -> Result<u64> {
        let seq = self.send_counter.fetch_add(1, Ordering::SeqCst);
        if seq == u64::MAX {
            return Err(anyhow!("Sequence number overflow - session must be rekeyed"));
        }
        Ok(seq)
    }

    /// Get current send counter value (for diagnostics)
    pub fn current_send_sequence(&self) -> u64 {
        self.send_counter.load(Ordering::SeqCst)
    }

    /// Validate received sequence number (sliding window anti-replay)
    pub fn validate_recv_sequence(&self, seq: u64) -> Result<()> {
        let current = self.recv_counter.load(Ordering::SeqCst);

        if seq + (self.window_size as u64) < current {
            return Err(anyhow!(
                "Sequence number {} too old (current: {}, window: {}) - possible replay attack",
                seq,
                current,
                self.window_size
            ));
        }

        if seq > current {
            let mut window = self.recv_window.write();

            let shift = (seq - current) as usize;
            if shift >= self.window_size {
                window.fill(false);
            } else {
                window.rotate_left(shift);
                for i in (self.window_size - shift)..self.window_size {
                    window[i] = false;
                }
            }

            let offset = (seq % self.window_size as u64) as usize;
            window[offset] = true;

            self.recv_counter.store(seq, Ordering::SeqCst);

            return Ok(());
        }

        let window = self.recv_window.read();
        let offset = (seq % self.window_size as u64) as usize;

        if window[offset] {
            return Err(anyhow!(
                "Duplicate sequence number {} - replay attack detected",
                seq
            ));
        }

        drop(window);
        let mut window = self.recv_window.write();
        window[offset] = true;

        Ok(())
    }

    /// Reset state (for rekeying)
    pub fn reset(&self) {
        self.send_counter.store(0, Ordering::SeqCst);
        self.recv_counter.store(0, Ordering::SeqCst);
        let mut window = self.recv_window.write();
        window.fill(false);
    }
}

impl std::fmt::Debug for ReplayProtectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayProtectionState")
            .field("send_counter", &self.send_counter.load(Ordering::SeqCst))
            .field("recv_counter", &self.recv_counter.load(Ordering::SeqCst))
            .field("window_size", &self.window_size)
            .finish()
    }
}

/// Session renewal reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRenewalReason {
    /// No renewal needed
    None,
    /// Session lifetime expired
    LifetimeExpired,
    /// Idle timeout reached
    IdleTimeout,
    /// Maximum message count reached
    MessageLimitReached,
    /// Explicit rekey requested
    ExplicitRekey,
}

/// Session lifecycle configuration
#[derive(Debug)]
pub struct SessionLifecycle {
    /// Maximum session lifetime in seconds
    pub max_lifetime_seconds: u64,
    /// Idle timeout in seconds
    pub idle_timeout_seconds: u64,
    /// Maximum messages before rekeying required (None = unlimited)
    pub max_messages: Option<u64>,
    /// Current message count
    message_count: AtomicU64,
    /// Creation timestamp
    created_at: u64,
    /// Last activity timestamp
    last_activity: AtomicU64,
}

impl SessionLifecycle {
    /// Create new lifecycle with default settings
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            max_lifetime_seconds: DEFAULT_SESSION_LIFETIME_SECS,
            idle_timeout_seconds: DEFAULT_IDLE_TIMEOUT_SECS,
            max_messages: Some(DEFAULT_MAX_MESSAGES),
            message_count: AtomicU64::new(0),
            created_at: now,
            last_activity: AtomicU64::new(now),
        }
    }

    /// Create with custom settings
    pub fn with_settings(
        max_lifetime_seconds: u64,
        idle_timeout_seconds: u64,
        max_messages: Option<u64>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            max_lifetime_seconds,
            idle_timeout_seconds,
            max_messages,
            message_count: AtomicU64::new(0),
            created_at: now,
            last_activity: AtomicU64::new(now),
        }
    }

    /// Check if session needs renewal
    pub fn needs_renewal(&self) -> SessionRenewalReason {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now.saturating_sub(self.created_at) > self.max_lifetime_seconds {
            return SessionRenewalReason::LifetimeExpired;
        }

        let last = self.last_activity.load(Ordering::SeqCst);
        if now.saturating_sub(last) > self.idle_timeout_seconds {
            return SessionRenewalReason::IdleTimeout;
        }

        if let Some(max) = self.max_messages {
            if self.message_count.load(Ordering::SeqCst) >= max {
                return SessionRenewalReason::MessageLimitReached;
            }
        }

        SessionRenewalReason::None
    }

    /// Update last activity (call on send/receive)
    pub fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_activity.store(now, Ordering::SeqCst);
        self.message_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Get creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get last activity timestamp
    pub fn last_activity(&self) -> u64 {
        self.last_activity.load(Ordering::SeqCst)
    }

    /// Get message count
    pub fn message_count(&self) -> u64 {
        self.message_count.load(Ordering::SeqCst)
    }

    /// Reset for rekeying (resets message count, keeps timestamps)
    pub fn reset_for_rekey(&self) {
        self.message_count.store(0, Ordering::SeqCst);
    }
}

impl Default for SessionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

/// Session MAC for validation (prevents session hijacking)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SessionMac([u8; 32]);

/// Protocol session representing an authenticated/encrypted connection
///
/// Sessions bind messages to a specific peer identity with cryptographic keys,
/// replay protection, and protocol-specific state.
///
/// # Security Properties
///
/// - Keys are zeroized on drop
/// - Session validation via MAC
/// - Structured replay protection
/// - Lifecycle management with timeouts
/// - Mandatory verified peer identity
pub struct ProtocolSession {
    /// Unique session identifier (cryptographically random)
    session_id: SessionId,
    /// Peer address for this session
    peer_address: PeerAddress,
    /// Verified peer identity (mandatory)
    peer_identity: VerifiedPeerIdentity,
    /// Protocol type for this session
    protocol: NetworkProtocol,
    /// Session encryption keys (typed, validated, zeroized)
    session_keys: SessionKeys,
    /// Replay protection state (structured)
    replay_state: ReplayProtectionState,
    /// Session lifecycle (timeouts, message counts)
    lifecycle: SessionLifecycle,
    /// Authentication scheme used
    auth_scheme: super::security::AuthScheme,
    /// Session MAC for validation (prevents hijacking)
    session_mac: SessionMac,
}

impl ProtocolSession {
    /// Create a new protocol session
    pub fn new(
        peer_address: PeerAddress,
        peer_identity: VerifiedPeerIdentity,
        protocol: NetworkProtocol,
        session_keys: SessionKeys,
        auth_scheme: super::security::AuthScheme,
        mac_key: &[u8; 32],
    ) -> Self {
        let session_id = SessionId::generate();
        let replay_state = ReplayProtectionState::new(REPLAY_WINDOW_SIZE);
        let lifecycle = SessionLifecycle::new();

        let session_mac = Self::compute_mac(
            &session_id,
            &peer_address,
            &protocol,
            lifecycle.created_at(),
            mac_key,
        );

        Self {
            session_id,
            peer_address,
            peer_identity,
            protocol,
            session_keys,
            replay_state,
            lifecycle,
            auth_scheme,
            session_mac,
        }
    }

    /// Compute session MAC for validation
    fn compute_mac(
        session_id: &SessionId,
        peer_address: &PeerAddress,
        protocol: &NetworkProtocol,
        created_at: u64,
        mac_key: &[u8; 32],
    ) -> SessionMac {
        use sha2::{Sha256, Digest};
        use hmac::{Hmac, Mac};

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(mac_key)
            .expect("HMAC key length is valid");

        mac.update(session_id.as_bytes());
        mac.update(&created_at.to_le_bytes());
        mac.update(format!("{:?}", peer_address).as_bytes());
        mac.update(format!("{:?}", protocol).as_bytes());

        let result = mac.finalize();
        let mut mac_bytes = [0u8; 32];
        mac_bytes.copy_from_slice(&result.into_bytes());

        SessionMac(mac_bytes)
    }

    /// Validate session integrity (prevents hijacking)
    pub fn validate(&self, mac_key: &[u8; 32]) -> Result<()> {
        match self.lifecycle.needs_renewal() {
            SessionRenewalReason::None => {}
            reason => {
                return Err(anyhow!("Session needs renewal: {:?}", reason));
            }
        }

        let expected_mac = Self::compute_mac(
            &self.session_id,
            &self.peer_address,
            &self.protocol,
            self.lifecycle.created_at(),
            mac_key,
        );

        if !bool::from(self.session_mac.0.ct_eq(&expected_mac.0)) {
            return Err(anyhow!("Session validation failed: MAC mismatch (possible hijacking)"));
        }

        Ok(())
    }

    /// Get session ID
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get peer address
    pub fn peer_address(&self) -> &PeerAddress {
        &self.peer_address
    }

    /// Get verified peer identity
    pub fn peer_identity(&self) -> &VerifiedPeerIdentity {
        &self.peer_identity
    }

    /// Get protocol type
    pub fn protocol(&self) -> &NetworkProtocol {
        &self.protocol
    }

    /// Get session keys (crate-internal only)
    pub(crate) fn session_keys(&self) -> &SessionKeys {
        &self.session_keys
    }

    /// Get mutable session keys (crate-internal only, for rekeying)
    pub(crate) fn session_keys_mut(&mut self) -> &mut SessionKeys {
        &mut self.session_keys
    }

    /// Get replay protection state
    pub fn replay_state(&self) -> &ReplayProtectionState {
        &self.replay_state
    }

    /// Get lifecycle
    pub fn lifecycle(&self) -> &SessionLifecycle {
        &self.lifecycle
    }

    /// Get authentication scheme
    pub fn auth_scheme(&self) -> &super::security::AuthScheme {
        &self.auth_scheme
    }

    /// Touch session (update last activity)
    pub fn touch(&self) {
        self.lifecycle.touch();
    }

    /// Check if session has forward secrecy
    pub fn has_forward_secrecy(&self) -> bool {
        self.session_keys.has_forward_secrecy()
    }
}

impl std::fmt::Debug for ProtocolSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolSession")
            .field("session_id", &self.session_id)
            .field("peer_address", &self.peer_address)
            .field("peer_identity", &self.peer_identity)
            .field("protocol", &self.protocol)
            .field("session_keys", &"<redacted>")
            .field("replay_state", &self.replay_state)
            .field("lifecycle", &format!(
                "created: {}, messages: {}",
                self.lifecycle.created_at(),
                self.lifecycle.message_count()
            ))
            .field("auth_scheme", &self.auth_scheme)
            .finish()
    }
}
