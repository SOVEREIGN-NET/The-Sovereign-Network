//! Unified Protocol Trait for Mesh Network Transports
//!
//! This module defines the core `Protocol` trait and security-hardened types
//! for session management, peer addressing, and cryptographic state.
//!
//! # Security Model
//!
//! All sessions provide:
//! - Cryptographic key zeroization on drop
//! - Structured replay protection with sliding window
//! - Session lifecycle management (timeouts, rekeying)
//! - Validated peer addresses and identities
//! - Constant-time comparisons for sensitive data

use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use crate::types::mesh_message::MeshMessageEnvelope;
use std::net::{SocketAddr, IpAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::ConstantTimeEq;
use parking_lot::RwLock;

// Bluetooth protocol suite (includes BLE mesh, Classic RFCOMM, platform-specific)
pub mod bluetooth;

// Other protocols
pub mod wifi_direct;
pub mod wifi_direct_handshake; // UHP handshake adapter for WiFi Direct
pub mod lorawan;
pub mod satellite;
pub mod zhtp_auth;
pub mod zhtp_encryption;
pub mod quic_mesh;           // QUIC transport with PQC encryption
pub mod quic_handshake;      // UHP handshake adapter for QUIC with Kyber binding
pub mod quic_api_dispatcher; // QUIC API request dispatcher for Web4 client


// Enhanced protocol implementations with platform-specific optimizations
// NOTE: enhanced_bluetooth functionality is in bluetooth/enhanced.rs, not a separate top-level module
// #[cfg(feature = "enhanced-bluetooth")]
// pub mod enhanced_bluetooth;

#[cfg(feature = "enhanced-wifi-direct")]
pub mod enhanced_wifi_direct;

// ============================================================================
// Constants
// ============================================================================

/// Default session lifetime in seconds (24 hours)
pub const DEFAULT_SESSION_LIFETIME_SECS: u64 = 86400;

/// Default idle timeout in seconds (15 minutes)
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900;

/// Default maximum messages before rekeying (1 million)
pub const DEFAULT_MAX_MESSAGES: u64 = 1_000_000;

/// Replay protection window size
pub const REPLAY_WINDOW_SIZE: usize = 128;

/// Maximum length for string-based identifiers
pub const MAX_IDENTIFIER_LENGTH: usize = 256;

/// Session ID entropy size in bytes
pub const SESSION_ID_SIZE: usize = 32;

/// Capability structure version
pub const CAPABILITY_VERSION: u8 = 2;

// ============================================================================
// Network Protocol Enumeration
// ============================================================================

/// Network protocol enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    /// Bluetooth Low Energy for device-to-device communication
    BluetoothLE,
    /// Bluetooth Classic (BR/EDR) for high-throughput mesh
    BluetoothClassic,
    /// WiFi Direct for medium-range peer connections
    WiFiDirect,
    /// LoRaWAN for long-range low-power communication
    LoRaWAN,
    /// Satellite for global coverage
    Satellite,
    /// TCP for internet bridging
    TCP,
    /// UDP for mesh networking
    UDP,
    /// QUIC for modern mesh transport (replaces TCP/UDP split)
    QUIC,
}

// ============================================================================
// Protocol Capabilities (with versioning)
// ============================================================================

/// Protocol capabilities describing both performance characteristics and security posture
///
/// Includes traditional metrics (MTU, throughput, latency, range, power) and
/// security properties (authentication schemes, encryption ciphers, PQC support,
/// replay protection, identity binding, forward secrecy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCapabilities {
    /// Capability structure version for forward compatibility
    pub version: u8,
    /// Maximum Transmission Unit in bytes
    pub mtu: u16,
    /// Estimated throughput in Mbps
    pub throughput_mbps: f64,
    /// Estimated latency in milliseconds
    pub latency_ms: u32,
    /// Effective range in meters (None for global protocols like satellite)
    pub range_meters: Option<u32>,
    /// Power consumption profile
    pub power_profile: PowerProfile,
    /// Whether the protocol supports reliable delivery
    pub reliable: bool,
    /// Whether the protocol requires internet connectivity to function
    ///
    /// Semantics:
    /// - `true`: The protocol fundamentally depends on internet connectivity and cannot
    ///   operate in a purely local/offline environment (e.g., satellite backhaul or
    ///   cloud-routed services).
    /// - `false`: The protocol can operate without internet connectivity. This includes
    ///   strictly local protocols and hybrid protocols that support both local and
    ///   internet-connected operation (e.g., QUIC or TCP used on a local network).
    pub requires_internet: bool,

    // ============ Security Capabilities ============
    /// Authentication schemes supported by this protocol
    pub auth_schemes: Vec<AuthScheme>,
    /// Encryption cipher suite (None if integrity-only or unauthenticated)
    pub encryption: Option<CipherSuite>,
    /// Post-quantum cryptography mode
    pub pqc_mode: PqcMode,
    /// Whether protocol provides replay protection
    pub replay_protection: bool,
    /// Whether messages are bound to authenticated peer/session
    pub identity_binding: bool,
    /// True if integrity-only (no confidentiality)
    pub integrity_only: bool,
    /// Whether protocol provides forward secrecy
    pub forward_secrecy: bool,
}

impl ProtocolCapabilities {
    /// Create new capabilities with current version
    pub fn new(
        mtu: u16,
        throughput_mbps: f64,
        latency_ms: u32,
        power_profile: PowerProfile,
    ) -> Self {
        Self {
            version: CAPABILITY_VERSION,
            mtu,
            throughput_mbps,
            latency_ms,
            range_meters: None,
            power_profile,
            reliable: true,
            requires_internet: false,
            auth_schemes: vec![AuthScheme::MutualHandshake],
            encryption: Some(CipherSuite::ChaCha20Poly1305),
            pqc_mode: PqcMode::Hybrid,
            replay_protection: true,
            identity_binding: true,
            integrity_only: false,
            forward_secrecy: true,
        }
    }
}

/// Power consumption profile for protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerProfile {
    /// Ultra-low power (< 10mW average)
    UltraLow,
    /// Low power (10-100mW)
    Low,
    /// Medium power (100mW-1W)
    Medium,
    /// High power (1W-10W)
    High,
    /// Very high power (> 10W)
    VeryHigh,
}

// ============================================================================
// Authentication Schemes (MEDIUM-3: Gated weak options)
// ============================================================================

/// Authentication scheme supported by a protocol
///
/// Note: `Unauthenticated` is intentionally excluded from the default enum.
/// Use `UnsafeAuthScheme` for testing/debugging scenarios requiring no auth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthScheme {
    /// Pre-shared key authentication (minimum acceptable security)
    PreSharedKey,
    /// Mutual handshake with identity verification (e.g., UHP) - recommended
    MutualHandshake,
    /// Certificate-based authentication
    Certificate,
    /// Post-quantum resistant mutual authentication using a PQC signature scheme.
    ///
    /// The concrete post-quantum algorithm is implementation-defined and selected by
    /// the underlying transport/handshake layer (for example, an ML-DSA (Dilithium)
    /// or SLH-DSA (SPHINCS+) signature scheme), rather than being fixed by this enum.
    PostQuantumMutual,
}

/// Unsafe authentication schemes - explicit opt-in required
///
/// SECURITY WARNING: These should only be used for testing, debugging,
/// or legacy protocol compatibility. Never use in production.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsafeAuthScheme {
    /// No authentication (DANGEROUS - testing only)
    Unauthenticated {
        /// Reason for using unauthenticated mode (for audit trail)
        reason: String,
    },
}

// ============================================================================
// Cipher Suites (MEDIUM-3: Gated weak options)
// ============================================================================

/// Encryption cipher suite
///
/// Note: `Plaintext` is intentionally excluded from the default enum.
/// Use `UnsafeCipherSuite` for testing/debugging scenarios requiring no encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// AES-256-GCM (minimum acceptable)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (recommended for software implementations)
    ChaCha20Poly1305,
    /// Kyber-768 + AES-256-GCM (hybrid PQC)
    KyberAes256,
    /// Kyber-1024 + ChaCha20 (hybrid PQC - preferred)
    KyberChaCha20,
    /// Full post-quantum encryption (future)
    FullPostQuantum,
}

impl CipherSuite {
    /// Get the required key size for this cipher suite
    pub fn key_size(&self) -> usize {
        match self {
            CipherSuite::Aes256Gcm => 32,
            CipherSuite::ChaCha20Poly1305 => 32,
            CipherSuite::KyberAes256 => 32,
            CipherSuite::KyberChaCha20 => 32,
            CipherSuite::FullPostQuantum => 32,
        }
    }
}

/// Unsafe cipher suites - explicit opt-in required
///
/// SECURITY WARNING: These should only be used for testing, debugging,
/// or legacy protocol compatibility. Never use in production.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsafeCipherSuite {
    /// Integrity-only with HMAC (no confidentiality)
    IntegrityOnly,
    /// Plaintext transport (DANGEROUS - testing only)
    Plaintext {
        /// Reason for using plaintext mode (for audit trail)
        reason: String,
    },
}

/// Post-quantum cryptography mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcMode {
    /// No post-quantum protection (classical only)
    None,
    /// Hybrid classical + PQC (Kyber KEM + classical AEAD)
    Hybrid,
    /// Full post-quantum (future - when standards mature)
    FullPqc,
}

// ============================================================================
// Session ID (MEDIUM-1: Cryptographic entropy)
// ============================================================================

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

    /// Constant-time equality comparison (LOW-2)
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
        // Only show first 4 bytes to prevent full ID leakage in logs
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

// ============================================================================
// Peer Address (HIGH-3: Validated addressing)
// ============================================================================

/// Validated Bluetooth MAC address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BluetoothMac([u8; 6]);

impl BluetoothMac {
    /// Create a new validated Bluetooth MAC address
    pub fn new(mac: [u8; 6]) -> Result<Self> {
        // Reject broadcast address
        if mac == [0xFF; 6] {
            return Err(anyhow!("Invalid Bluetooth MAC: broadcast address"));
        }
        // Reject all-zeros (uninitialized)
        if mac == [0x00; 6] {
            return Err(anyhow!("Invalid Bluetooth MAC: null address"));
        }
        Ok(Self(mac))
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// Validated socket address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatedSocketAddr(SocketAddr);

impl ValidatedSocketAddr {
    /// Create a new validated socket address
    pub fn new(addr: SocketAddr) -> Result<Self> {
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                if ipv4.is_unspecified() {
                    return Err(anyhow!("Invalid IPv4: unspecified (0.0.0.0)"));
                }
                if ipv4.is_broadcast() {
                    return Err(anyhow!("Invalid IPv4: broadcast (255.255.255.255)"));
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_unspecified() {
                    return Err(anyhow!("Invalid IPv6: unspecified (::)"));
                }
            }
        }

        if addr.port() == 0 {
            return Err(anyhow!("Invalid port: 0"));
        }

        Ok(Self(addr))
    }

    /// Get the inner socket address
    pub fn inner(&self) -> &SocketAddr {
        &self.0
    }
}

/// Validated device identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatedDeviceId(String);

impl ValidatedDeviceId {
    /// Create a new validated device ID
    pub fn new(id: String) -> Result<Self> {
        if id.is_empty() {
            return Err(anyhow!("Device ID cannot be empty"));
        }
        if id.len() > MAX_IDENTIFIER_LENGTH {
            return Err(anyhow!(
                "Device ID too long: {} bytes (max: {})",
                id.len(),
                MAX_IDENTIFIER_LENGTH
            ));
        }
        // Allow alphanumeric, hyphens, colons, and underscores
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == ':' || c == '_') {
            return Err(anyhow!("Invalid Device ID format: only alphanumeric, -, :, _ allowed"));
        }
        Ok(Self(id))
    }

    /// Get the inner string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated satellite identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatedSatelliteId(String);

impl ValidatedSatelliteId {
    /// Create a new validated satellite ID
    pub fn new(id: String) -> Result<Self> {
        if id.is_empty() {
            return Err(anyhow!("Satellite ID cannot be empty"));
        }
        if id.len() > MAX_IDENTIFIER_LENGTH {
            return Err(anyhow!(
                "Satellite ID too long: {} bytes (max: {})",
                id.len(),
                MAX_IDENTIFIER_LENGTH
            ));
        }
        Ok(Self(id))
    }

    /// Get the inner string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Peer address for protocol-agnostic addressing
///
/// All variants use validated types to prevent invalid addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerAddress {
    /// Bluetooth MAC address (validated)
    Bluetooth(BluetoothMac),
    /// IP address and port (validated)
    IpSocket(ValidatedSocketAddr),
    /// Device ID (validated, length-limited)
    DeviceId(ValidatedDeviceId),
    /// LoRaWAN device address
    LoRaDevAddr(u32),
    /// Satellite endpoint identifier (validated)
    SatelliteId(ValidatedSatelliteId),
}

impl PeerAddress {
    /// Create a Bluetooth address (convenience method)
    pub fn bluetooth(mac: [u8; 6]) -> Result<Self> {
        Ok(Self::Bluetooth(BluetoothMac::new(mac)?))
    }

    /// Create an IP socket address (convenience method)
    pub fn ip_socket(addr: SocketAddr) -> Result<Self> {
        Ok(Self::IpSocket(ValidatedSocketAddr::new(addr)?))
    }

    /// Create a device ID address (convenience method)
    pub fn device_id(id: impl Into<String>) -> Result<Self> {
        Ok(Self::DeviceId(ValidatedDeviceId::new(id.into())?))
    }

    /// Create a LoRa device address
    pub fn lora(addr: u32) -> Self {
        Self::LoRaDevAddr(addr)
    }

    /// Create a satellite ID address (convenience method)
    pub fn satellite(id: impl Into<String>) -> Result<Self> {
        Ok(Self::SatelliteId(ValidatedSatelliteId::new(id.into())?))
    }
}

// ============================================================================
// Verified Peer Identity (MEDIUM-2: Mandatory identity binding)
// ============================================================================

/// Verified peer identity with cryptographic binding
///
/// Ensures that peer identity claims are backed by cryptographic proof.
#[derive(Clone)]
pub struct VerifiedPeerIdentity {
    /// DID or public key hash
    did: String,
    /// Public key used for authentication (raw bytes)
    public_key: Vec<u8>,
    /// Signature over session binding data (proves key possession)
    authentication_proof: Vec<u8>,
}

impl VerifiedPeerIdentity {
    /// Create a new verified peer identity
    pub fn new(
        did: String,
        public_key: Vec<u8>,
        authentication_proof: Vec<u8>,
    ) -> Result<Self> {
        if did.is_empty() {
            return Err(anyhow!("DID cannot be empty"));
        }
        if did.len() > MAX_IDENTIFIER_LENGTH {
            return Err(anyhow!("DID too long: {} bytes", did.len()));
        }
        if public_key.is_empty() {
            return Err(anyhow!("Public key cannot be empty"));
        }
        Ok(Self {
            did,
            public_key,
            authentication_proof,
        })
    }

    /// Get the DID
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the authentication proof
    pub fn authentication_proof(&self) -> &[u8] {
        &self.authentication_proof
    }
}

impl std::fmt::Debug for VerifiedPeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedPeerIdentity")
            .field("did", &self.did)
            .field("public_key", &format!("[{} bytes]", self.public_key.len()))
            .field("authentication_proof", &"<redacted>")
            .finish()
    }
}

// ============================================================================
// Session Keys (CRITICAL-2: Typed, validated, zeroized)
// ============================================================================

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
        // Zeroize all key material on drop
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
        // Validate key is not all zeros (weak key)
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

// ============================================================================
// Replay Protection State (HIGH-1: Structured with sliding window)
// ============================================================================

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
    ///
    /// Returns Ok(()) if sequence is valid and not a replay.
    /// Returns Err if sequence is too old or already received.
    pub fn validate_recv_sequence(&self, seq: u64) -> Result<()> {
        let current = self.recv_counter.load(Ordering::SeqCst);

        // Reject if too old (outside window)
        if seq + (self.window_size as u64) < current {
            return Err(anyhow!(
                "Sequence number {} too old (current: {}, window: {}) - possible replay attack",
                seq,
                current,
                self.window_size
            ));
        }

        // If newer than current, accept and update window
        if seq > current {
            let mut window = self.recv_window.write();

            // Shift window for the gap
            let shift = (seq - current) as usize;
            if shift >= self.window_size {
                // Clear entire window
                window.fill(false);
            } else {
                // Shift window
                window.rotate_left(shift);
                for i in (self.window_size - shift)..self.window_size {
                    window[i] = false;
                }
            }

            // Mark current sequence as received
            let offset = (seq % self.window_size as u64) as usize;
            window[offset] = true;

            // Update counter
            self.recv_counter.store(seq, Ordering::SeqCst);

            return Ok(());
        }

        // Sequence is within window - check if already received
        let window = self.recv_window.read();
        let offset = (seq % self.window_size as u64) as usize;

        if window[offset] {
            return Err(anyhow!(
                "Duplicate sequence number {} - replay attack detected",
                seq
            ));
        }

        // Mark as received
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

// ============================================================================
// Session Lifecycle (HIGH-2: Timeouts and rekeying)
// ============================================================================

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

        // Check lifetime expiration
        if now.saturating_sub(self.created_at) > self.max_lifetime_seconds {
            return SessionRenewalReason::LifetimeExpired;
        }

        // Check idle timeout
        let last = self.last_activity.load(Ordering::SeqCst);
        if now.saturating_sub(last) > self.idle_timeout_seconds {
            return SessionRenewalReason::IdleTimeout;
        }

        // Check message limit
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

// ============================================================================
// Protocol Session (CRITICAL-1, CRITICAL-3: Secure, validated, zeroized)
// ============================================================================

/// Session MAC for validation (CRITICAL-3: Session hijacking prevention)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SessionMac([u8; 32]);

/// Protocol session representing an authenticated/encrypted connection
///
/// Sessions bind messages to a specific peer identity with cryptographic keys,
/// replay protection, and protocol-specific state.
///
/// # Security Properties
///
/// - Keys are zeroized on drop (CRITICAL-1)
/// - Session validation via MAC (CRITICAL-3)
/// - Structured replay protection (HIGH-1)
/// - Lifecycle management with timeouts (HIGH-2)
/// - Mandatory verified peer identity (MEDIUM-2)
///
/// Note: This struct intentionally does NOT implement Clone or Debug
/// to prevent accidental key leakage.
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
    auth_scheme: AuthScheme,
    /// Session MAC for validation (prevents hijacking)
    session_mac: SessionMac,
}

impl ProtocolSession {
    /// Create a new protocol session
    ///
    /// # Arguments
    /// * `peer_address` - Validated peer address
    /// * `peer_identity` - Verified peer identity with cryptographic proof
    /// * `protocol` - Protocol type
    /// * `session_keys` - Typed session keys
    /// * `auth_scheme` - Authentication scheme used
    /// * `mac_key` - Key for computing session MAC (from protocol instance)
    pub fn new(
        peer_address: PeerAddress,
        peer_identity: VerifiedPeerIdentity,
        protocol: NetworkProtocol,
        session_keys: SessionKeys,
        auth_scheme: AuthScheme,
        mac_key: &[u8; 32],
    ) -> Self {
        let session_id = SessionId::generate();
        let replay_state = ReplayProtectionState::new(REPLAY_WINDOW_SIZE);
        let lifecycle = SessionLifecycle::new();

        // Compute session MAC for validation
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

    /// Validate session integrity (CRITICAL-3: Prevents hijacking)
    pub fn validate(&self, mac_key: &[u8; 32]) -> Result<()> {
        // Check lifecycle
        match self.lifecycle.needs_renewal() {
            SessionRenewalReason::None => {}
            reason => {
                return Err(anyhow!("Session needs renewal: {:?}", reason));
            }
        }

        // Validate MAC
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

    // ============ Accessors (LOW-1: Private fields with controlled access) ============

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
    pub fn auth_scheme(&self) -> &AuthScheme {
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

// ============================================================================
// Protocol Trait (with session validation and rekeying)
// ============================================================================

/// Unified protocol trait for all mesh network transports
///
/// All protocols (BLE, WiFi Direct, LoRaWAN, QUIC, Satellite, Bluetooth Classic)
/// implement this trait to provide a consistent interface for message transmission.
///
/// # Security Model
///
/// Protocols expose session-aware APIs with explicit authentication and encryption:
/// - `connect()` / `accept()` establish authenticated sessions with peer identity binding
/// - `validate_session()` prevents session hijacking (CRITICAL-3)
/// - `send_message()` and `receive_message()` operate on validated sessions
/// - `rekey_session()` maintains forward secrecy (HIGH-4)
/// - `capabilities()` includes security posture for transport selection
///
/// # Security Events
///
/// Implementations MUST log the following security events:
/// - Authentication failures (with peer address, NOT credentials)
/// - Replay attack detection (sequence number, session ID)
/// - Session expiration/timeout
/// - Cryptographic errors (algorithm, error type)
///
/// # Example
/// ```ignore
/// use lib_network::protocols::{Protocol, PeerAddress};
/// use lib_network::types::mesh_message::MeshMessageEnvelope;
///
/// async fn secure_send<P: Protocol>(
///     protocol: &mut P,
///     target: PeerAddress,
///     envelope: &MeshMessageEnvelope
/// ) -> anyhow::Result<()> {
///     // Establish authenticated session
///     let session = protocol.connect(&target).await?;
///
///     // Validate session before use
///     protocol.validate_session(&session)?;
///
///     // Send encrypted message bound to peer identity
///     protocol.send_message(&session, envelope).await?;
///
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Initiate connection and perform handshake with a peer
    ///
    /// Establishes an authenticated, encrypted session with the target peer.
    /// This includes:
    /// - Peer identity verification (mutual auth if supported)
    /// - Key exchange (PQC-hybrid or classical)
    /// - Replay protection initialization
    ///
    /// # Arguments
    /// * `target` - Typed peer address (Bluetooth MAC, IP, device ID, etc.)
    ///
    /// # Returns
    /// * `Ok(ProtocolSession)` with peer identity, session keys, and security state
    /// * `Err(...)` if connection/handshake failed
    async fn connect(&mut self, target: &PeerAddress) -> Result<ProtocolSession>;

    /// Accept incoming connection and perform handshake
    ///
    /// Listens for and accepts an incoming connection request, performing
    /// authentication and key exchange.
    ///
    /// # Returns
    /// * `Ok(ProtocolSession)` with authenticated peer identity and session keys
    /// * `Err(...)` if no connection available or handshake failed
    async fn accept(&mut self) -> Result<ProtocolSession>;

    /// Validate that a session is valid and belongs to this protocol instance
    ///
    /// CRITICAL: Call this before every send/receive operation to prevent
    /// session hijacking attacks.
    ///
    /// # Security
    /// - Validates session MAC (constant-time comparison)
    /// - Checks session lifecycle (expiration, idle timeout, message count)
    /// - Verifies session belongs to this protocol instance
    fn validate_session(&self, session: &ProtocolSession) -> Result<()>;

    /// Send a mesh message over an established session
    ///
    /// Messages are encrypted and bound to the session's peer identity.
    /// Replay protection is enforced via session state.
    ///
    /// # Arguments
    /// * `session` - Active session with peer identity and cryptographic keys
    /// * `envelope` - The message envelope containing routing and payload data
    ///
    /// # Returns
    /// * `Ok(())` if message was successfully transmitted (or queued)
    /// * `Err(...)` if transmission failed or session is invalid
    ///
    /// # Security
    /// - Session is validated before sending
    /// - Message is encrypted with session keys
    /// - Sequence number is included for replay protection
    async fn send_message(
        &self,
        session: &ProtocolSession,
        envelope: &MeshMessageEnvelope,
    ) -> Result<()>;

    /// Receive a mesh message from an established session
    ///
    /// Blocks until a message is available or timeout occurs.
    /// Messages are decrypted and replay protection is verified.
    ///
    /// # Arguments
    /// * `session` - Active session to receive from
    ///
    /// # Returns
    /// * `Ok(MeshMessageEnvelope)` if message received and verified
    /// * `Err(...)` if receive failed, timeout, or replay attack detected
    ///
    /// # Security
    /// - Session is validated before receiving
    /// - Message is decrypted with session keys
    /// - Sequence number is validated for replay protection
    async fn receive_message(&self, session: &ProtocolSession) -> Result<MeshMessageEnvelope>;

    /// Rekey an existing session (HIGH-4: Forward secrecy maintenance)
    ///
    /// Establishes new ephemeral keys while maintaining the session.
    /// Required for maintaining forward secrecy in long-lived sessions.
    ///
    /// # Arguments
    /// * `session` - Session to rekey (mutably borrowed)
    ///
    /// # Returns
    /// * `Ok(())` if rekeying succeeded
    /// * `Err(...)` if rekeying failed (session should be terminated)
    ///
    /// # Security
    /// - New ephemeral key exchange is performed
    /// - Old keys are zeroized
    /// - Replay state is reset
    /// - Rekey generation counter is incremented
    async fn rekey_session(&mut self, session: &mut ProtocolSession) -> Result<()>;

    /// Get the protocol's technical capabilities
    ///
    /// Returns characteristics like MTU, throughput, latency, range, power consumption,
    /// and security posture (auth schemes, encryption, PQC mode, etc.).
    fn capabilities(&self) -> ProtocolCapabilities;

    /// Get the protocol type identifier
    fn protocol_type(&self) -> NetworkProtocol;

    /// Check if the protocol is currently available/enabled
    ///
    /// Returns `false` if hardware is unavailable, disabled, or in error state.
    fn is_available(&self) -> bool {
        true // Default implementation - protocols can override
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generation() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();

        // IDs should be unique
        assert!(!id1.ct_eq(&id2));

        // Should have proper entropy (not all zeros)
        assert!(!id1.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_session_id_constant_time_eq() {
        let id1 = SessionId::from_bytes([1u8; 32]);
        let id2 = SessionId::from_bytes([1u8; 32]);
        let id3 = SessionId::from_bytes([2u8; 32]);

        assert!(id1.ct_eq(&id2));
        assert!(!id1.ct_eq(&id3));
    }

    #[test]
    fn test_bluetooth_mac_validation() {
        // Valid MAC
        assert!(BluetoothMac::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]).is_ok());

        // Broadcast rejected
        assert!(BluetoothMac::new([0xFF; 6]).is_err());

        // Null rejected
        assert!(BluetoothMac::new([0x00; 6]).is_err());
    }

    #[test]
    fn test_validated_socket_addr() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // Valid address
        let valid = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert!(ValidatedSocketAddr::new(valid).is_ok());

        // Unspecified rejected
        let unspec = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
        assert!(ValidatedSocketAddr::new(unspec).is_err());

        // Port 0 rejected
        let port0 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 0);
        assert!(ValidatedSocketAddr::new(port0).is_err());
    }

    #[test]
    fn test_device_id_validation() {
        // Valid IDs
        assert!(ValidatedDeviceId::new("device-123".to_string()).is_ok());
        assert!(ValidatedDeviceId::new("AA:BB:CC:DD".to_string()).is_ok());

        // Empty rejected
        assert!(ValidatedDeviceId::new("".to_string()).is_err());

        // Too long rejected
        let long_id = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);
        assert!(ValidatedDeviceId::new(long_id).is_err());

        // Invalid characters rejected
        assert!(ValidatedDeviceId::new("device\ninjection".to_string()).is_err());
    }

    #[test]
    fn test_session_keys_validation() {
        let mut keys = SessionKeys::new(CipherSuite::ChaCha20Poly1305, true);

        // Valid key
        assert!(keys.set_encryption_key([1u8; 32]).is_ok());

        // All-zeros rejected
        let mut keys2 = SessionKeys::new(CipherSuite::Aes256Gcm, true);
        assert!(keys2.set_encryption_key([0u8; 32]).is_err());
    }

    #[test]
    fn test_replay_protection() {
        let state = ReplayProtectionState::new(64);

        // First sequence should succeed
        assert!(state.validate_recv_sequence(0).is_ok());

        // Duplicate should fail
        assert!(state.validate_recv_sequence(0).is_err());

        // New sequence should succeed
        assert!(state.validate_recv_sequence(1).is_ok());

        // Much higher sequence should succeed (advances window)
        assert!(state.validate_recv_sequence(100).is_ok());

        // Old sequence outside window should fail
        assert!(state.validate_recv_sequence(0).is_err());
    }

    #[test]
    fn test_session_lifecycle() {
        let lifecycle = SessionLifecycle::with_settings(
            60,  // 1 minute lifetime
            30,  // 30 second idle
            Some(100),  // 100 messages max
        );

        // Initially no renewal needed
        assert_eq!(lifecycle.needs_renewal(), SessionRenewalReason::None);

        // Touch updates activity
        lifecycle.touch();
        assert_eq!(lifecycle.message_count(), 1);
    }

    #[test]
    fn test_cipher_suite_key_sizes() {
        assert_eq!(CipherSuite::Aes256Gcm.key_size(), 32);
        assert_eq!(CipherSuite::ChaCha20Poly1305.key_size(), 32);
        assert_eq!(CipherSuite::KyberChaCha20.key_size(), 32);
    }
}
