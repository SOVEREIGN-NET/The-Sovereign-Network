//! Unified Handshake Protocol (UHP)
//!
//! Single, secure handshake protocol for all network transports in The Sovereign Network.
//! This module provides a consistent authentication and capability negotiation mechanism
//! that works across TCP, UDP, BLE, WiFi Direct, LoRaWAN, QUIC, and Satellite protocols.
//!
//! # Architecture
//!
//! UHP supports two authentication modes:
//!
//! ## Full Handshake (Authenticated)
//! For nodes with existing Sovereign Identity (SID):
//! ```text
//! Client                                Server
//!   |                                     |
//!   |--- ClientHello ------------------>  |  (1) Send identity, capabilities, challenge
//!   |                                     |
//!   |<-- ServerHello -------------------  |  (2) Verify NodeId, send server identity, response
//!   |                                     |
//!   |--- ClientFinish ----------------->  |  (3) Verify server, confirm session
//!   |                                     |
//!   |<== Secure Session Established ===> |
//! ```
//!
//! ## Provisional Handshake (Unauthenticated)
//! For new nodes without SID (ephemeral path for onboarding):
//! ```text
//! New Node                              Bootstrap Server
//!   |                                     |
//!   |--- ProvisionalHello ------------->  |  (1) Ephemeral keypair, challenge
//!   |                                     |
//!   |<-- ChallengeResponse -------------  |  (2) Server challenge
//!   |                                     |
//!   |--- ChallengeProof --------------->  |  (3) Proof of work/stake
//!   |                                     |
//!   |<-- SID Issued -------------------   |  (4) SID issued, upgrade to full handshake
//!   |                                     |
//!   |=== Upgrade to Full Handshake ====> |
//! ```
//!
//! # Security Properties
//!
//! - **Identity Verification**: NodeId = Blake3(DID || device_name)
//! - **Mutual Authentication**: Both peers verify each other's signatures
//! - **Forward Secrecy**: Ephemeral session keys for each connection
//! - **Post-Quantum Security**: Hybrid classical + PQC key exchange (protocol-dependent)
//! - **Replay Protection**: Nonces and timestamps prevent replay attacks
//! - **Capability Negotiation**: Peers agree on protocol features before session starts
//!
//! # Protocol Versioning
//!
//! UHP version 1.0 is the initial release. Future versions maintain backwards compatibility
//! through negotiation in the ClientHello message.

use anyhow::{Result, anyhow};
use lib_crypto::{PublicKey, Signature, KeyPair};
use lib_identity::{ZhtpIdentity, NodeId};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;

// Security modules
mod security;
mod nonce_cache;
mod observability;
mod rate_limiter;

// Re-export security utilities
pub use security::{
    TimestampConfig, SessionContext,
    validate_timestamp, current_timestamp,
    derive_session_key_hkdf, ct_eq_bytes, ct_verify_eq,
};
pub use nonce_cache::{NonceCache, start_nonce_cleanup_task};
pub use observability::{
    HandshakeObserver, HandshakeEvent, HandshakeMetrics, FailureReason,
    NoOpObserver, LoggingObserver, Timer,
};
pub use rate_limiter::{RateLimiter, RateLimitConfig};

/// UHP Protocol Version
pub const UHP_VERSION: u8 = 1;

/// Protocol version string for compatibility
pub const UHP_VERSION_STRING: &str = "UHP/1.0";

/// Maximum supported protocol version (for future compatibility)
pub const MAX_SUPPORTED_VERSION: u8 = 1;

/// Minimum supported protocol version (for backwards compatibility)
pub const MIN_SUPPORTED_VERSION: u8 = 1;

/// Validate protocol version is within supported range
///
/// **VULN-004 FIX:** Prevents protocol downgrade attacks
///
/// # Returns
/// - `Ok(())` if version is valid
/// - `Err(...)` if version is outside supported range
fn validate_protocol_version(version: u8) -> Result<()> {
    if version < MIN_SUPPORTED_VERSION || version > MAX_SUPPORTED_VERSION {
        return Err(anyhow!(
            "Unsupported protocol version: {} (supported: {}-{})",
            version,
            MIN_SUPPORTED_VERSION,
            MAX_SUPPORTED_VERSION
        ));
    }
    Ok(())
}

// ============================================================================
// Handshake Context - FINDING 2 FIX
// ============================================================================

/// Handshake context that bundles all verification dependencies
///
/// **ARCHITECTURE FIX (FINDING 2):** Eliminates parameter threading anti-pattern
/// by grouping related configuration into a single context object.
///
/// **ARCHITECTURE FIX (FINDING 4):** Includes observability hooks for monitoring.
///
/// **ARCHITECTURE FIX (FINDING 8):** Includes optional rate limiting for DoS protection.
///
/// Benefits:
/// - Single parameter instead of 2-3 separate parameters
/// - Easy to extend with new configuration without changing all signatures
/// - Clearer ownership and lifecycle management
/// - Better encapsulation of verification state
/// - Built-in observability support
/// - Optional rate limiting for production deployments
#[derive(Clone)]
pub struct HandshakeContext {
    /// Nonce cache for replay attack prevention
    pub nonce_cache: NonceCache,

    /// Timestamp configuration (tolerance, max age, etc.)
    pub timestamp_config: TimestampConfig,

    /// Observer for metrics and events (default: NoOpObserver)
    pub observer: std::sync::Arc<dyn HandshakeObserver>,

    /// Optional rate limiter for DoS protection
    pub rate_limiter: Option<RateLimiter>,
}

impl HandshakeContext {
    /// Create a new handshake context with default configuration (no rate limiting)
    pub fn new(nonce_cache: NonceCache) -> Self {
        Self {
            nonce_cache,
            timestamp_config: TimestampConfig::default(),
            observer: std::sync::Arc::new(NoOpObserver),
            rate_limiter: None,
        }
    }

    /// Create with custom timestamp configuration
    pub fn with_timestamp_config(nonce_cache: NonceCache, timestamp_config: TimestampConfig) -> Self {
        Self {
            nonce_cache,
            timestamp_config,
            observer: std::sync::Arc::new(NoOpObserver),
            rate_limiter: None,
        }
    }

    /// Create with custom observer
    pub fn with_observer(nonce_cache: NonceCache, observer: std::sync::Arc<dyn HandshakeObserver>) -> Self {
        Self {
            nonce_cache,
            timestamp_config: TimestampConfig::default(),
            observer,
            rate_limiter: None,
        }
    }

    /// Create with rate limiting enabled
    pub fn with_rate_limiting(nonce_cache: NonceCache, rate_limiter: RateLimiter) -> Self {
        Self {
            nonce_cache,
            timestamp_config: TimestampConfig::default(),
            observer: std::sync::Arc::new(NoOpObserver),
            rate_limiter: Some(rate_limiter),
        }
    }

    /// Create with all custom configuration
    pub fn with_config(
        nonce_cache: NonceCache,
        timestamp_config: TimestampConfig,
        observer: std::sync::Arc<dyn HandshakeObserver>,
        rate_limiter: Option<RateLimiter>,
    ) -> Self {
        Self {
            nonce_cache,
            timestamp_config,
            observer,
            rate_limiter,
        }
    }

    /// Create a default context for testing (no rate limiting)
    #[cfg(test)]
    pub fn new_test() -> Self {
        Self {
            nonce_cache: NonceCache::new(300, 1000),
            timestamp_config: TimestampConfig::default(),
            observer: std::sync::Arc::new(NoOpObserver),
            rate_limiter: None,
        }
    }

    /// Helper to create metrics snapshot
    fn metrics_snapshot(&self, duration_micros: u64, protocol_version: u8) -> HandshakeMetrics {
        HandshakeMetrics {
            duration_micros,
            nonce_cache_size: self.nonce_cache.size(),
            nonce_cache_utilization: self.nonce_cache.utilization(),
            protocol_version,
        }
    }
}

// ============================================================================
// Core Identity Structures
// ============================================================================

/// Complete node identity for handshake
///
/// Node identity for UHP handshakes (public information only)
///
/// This is a lightweight struct containing only the public identity fields
/// needed for handshake protocol. It excludes sensitive data like private keys,
/// credentials, wallets, etc. from the full ZhtpIdentity.
///
/// # Security Note
/// This struct is safe to transmit over the network as it contains only
/// public cryptographic material and identity metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeIdentity {
    /// Decentralized Identifier (DID) - Sovereign Identity
    pub did: String,
    
    /// Cryptographic public key for signature verification
    pub public_key: PublicKey,
    
    /// Derived node identifier from lib-identity (Blake3(DID || device_name))
    pub node_id: NodeId,
    
    /// Device identifier (e.g., "laptop", "phone", "server-01")
    pub device_id: String,
    
    /// Optional display name for this node
    pub display_name: Option<String>,
    
    /// Timestamp of identity creation (Unix timestamp)
    pub created_at: u64,
}

impl NodeIdentity {
    /// Create NodeIdentity from ZhtpIdentity (extracts only public fields)
    ///
    /// This creates a lightweight handshake-safe identity by extracting only
    /// the public fields needed for peer verification, excluding all sensitive
    /// data like private keys, credentials, wallet seeds, etc.
    pub fn from_zhtp_identity(identity: &ZhtpIdentity) -> Self {
        Self {
            did: identity.did.clone(),
            public_key: identity.public_key.clone(),
            node_id: identity.node_id.clone(),
            device_id: identity.primary_device.clone(),
            display_name: identity.metadata.get("display_name").cloned(),
            created_at: identity.created_at,
        }
    }
    
    /// Verify that node_id matches Blake3(DID || device_id) per lib-identity rules
    ///
    /// SECURITY: Uses constant-time comparison to prevent timing side-channels.
    /// Error messages are intentionally generic to prevent information leakage.
    pub fn verify_node_id(&self) -> Result<()> {
        let expected = NodeId::from_did_device(&self.did, &self.device_id)?;

        let res = ct_verify_eq(
            self.node_id.as_bytes(),
            expected.as_bytes(),
            "Invalid NodeId"
        );

        #[cfg(feature = "identity-debug")]
        if res.is_err() {
            tracing::warn!(
                "NodeId verification failed for DID={}, device_id={}",
                self.did.redacted(),
                self.device_id.redacted()
            );
        }

        res
    }
    
    /// Get a compact string representation for logging
    pub fn to_compact_string(&self) -> String {
        format!("{}@{}", self.device_id, &self.did[..std::cmp::min(20, self.did.len())])
    }
}

// ============================================================================
// Capability Negotiation
// ============================================================================

/// Node capabilities and features for negotiation
///
/// Peers exchange capabilities during handshake to negotiate compatible
/// protocol features, encryption methods, and performance parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandshakeCapabilities {
    /// Supported network protocols (BLE, WiFi, LoRa, QUIC, etc.)
    pub protocols: Vec<String>,
    
    /// Maximum throughput in bytes/second
    pub max_throughput: u64,
    
    /// Maximum message size in bytes
    pub max_message_size: usize,
    
    /// Supported encryption methods (ChaCha20-Poly1305, AES-GCM, etc.)
    pub encryption_methods: Vec<String>,
    
    /// Post-quantum cryptography support
    pub pqc_support: bool,
    
    /// DHT participation capability
    pub dht_capable: bool,
    
    /// Relay capability (can forward messages for others)
    pub relay_capable: bool,
    
    /// Storage capacity offered (in bytes, 0 = none)
    pub storage_capacity: u64,
    
    /// Supports Web4 content serving
    pub web4_capable: bool,
    
    /// Custom features (protocol-specific extensions)
    pub custom_features: Vec<String>,
}

impl Default for HandshakeCapabilities {
    fn default() -> Self {
        Self {
            protocols: vec!["tcp".to_string()],
            max_throughput: 1_000_000, // 1 MB/s default
            max_message_size: 65536,   // 64 KB default
            encryption_methods: vec!["chacha20-poly1305".to_string()],
            pqc_support: false,
            dht_capable: false,
            relay_capable: false,
            storage_capacity: 0,
            web4_capable: false,
            custom_features: vec![],
        }
    }
}

impl HandshakeCapabilities {
    /// Create minimal capabilities for resource-constrained devices
    pub fn minimal() -> Self {
        Self {
            protocols: vec!["ble".to_string()],
            max_throughput: 10_000,    // 10 KB/s
            max_message_size: 512,     // 512 bytes
            encryption_methods: vec!["chacha20-poly1305".to_string()],
            pqc_support: false,
            dht_capable: false,
            relay_capable: false,
            storage_capacity: 0,
            web4_capable: false,
            custom_features: vec![],
        }
    }
    
    /// Create full-featured capabilities for desktop/server nodes
    pub fn full_featured() -> Self {
        Self {
            protocols: vec![
                "tcp".to_string(),
                "udp".to_string(),
                "quic".to_string(),
                "ble".to_string(),
                "wifi-direct".to_string(),
            ],
            max_throughput: 100_000_000, // 100 MB/s
            max_message_size: 10_485_760, // 10 MB
            encryption_methods: vec![
                "chacha20-poly1305".to_string(),
                "aes-256-gcm".to_string(),
            ],
            pqc_support: true,
            dht_capable: true,
            relay_capable: true,
            storage_capacity: 10_737_418_240, // 10 GB
            web4_capable: true,
            custom_features: vec![],
        }
    }
    
    /// Find compatible features between two capability sets
    pub fn negotiate(&self, other: &HandshakeCapabilities) -> NegotiatedCapabilities {
        let protocols: Vec<String> = self.protocols.iter()
            .filter(|p| other.protocols.contains(p))
            .cloned()
            .collect();
        
        let encryption_methods: Vec<String> = self.encryption_methods.iter()
            .filter(|e| other.encryption_methods.contains(e))
            .cloned()
            .collect();
        
        NegotiatedCapabilities {
            protocol: protocols.first().cloned().unwrap_or_default(),
            max_throughput: self.max_throughput.min(other.max_throughput),
            max_message_size: self.max_message_size.min(other.max_message_size),
            encryption_method: encryption_methods.first().cloned().unwrap_or_default(),
            pqc_enabled: self.pqc_support && other.pqc_support,
            dht_enabled: self.dht_capable && other.dht_capable,
            relay_enabled: self.relay_capable && other.relay_capable,
        }
    }
}

/// Result of capability negotiation between two peers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NegotiatedCapabilities {
    /// Selected protocol for this session
    pub protocol: String,
    
    /// Negotiated maximum throughput
    pub max_throughput: u64,
    
    /// Negotiated maximum message size
    pub max_message_size: usize,
    
    /// Selected encryption method
    pub encryption_method: String,
    
    /// Whether PQC is enabled for this session
    pub pqc_enabled: bool,
    
    /// Whether DHT participation is enabled
    pub dht_enabled: bool,
    
    /// Whether relay forwarding is enabled
    pub relay_enabled: bool,
}

// ============================================================================
// Handshake Message Types
// ============================================================================

/// Unified handshake message envelope
///
/// All handshake messages are wrapped in this envelope for consistent
/// parsing and versioning across different transports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// Protocol version
    pub version: u8,
    
    /// Message type and payload
    pub payload: HandshakePayload,
    
    /// Timestamp (Unix timestamp in seconds)
    pub timestamp: u64,
}

impl HandshakeMessage {
    /// Create a new handshake message with current timestamp
    pub fn new(payload: HandshakePayload) -> Self {
        Self {
            version: UHP_VERSION,
            payload,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Serialization failed: {}", e))
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Deserialization failed: {}", e))
    }
}

/// Handshake message payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakePayload {
    /// Client initiates handshake
    ClientHello(ClientHello),
    
    /// Server responds with identity and challenge response
    ServerHello(ServerHello),
    
    /// Client confirms and completes handshake
    ClientFinish(ClientFinish),
    
    /// Provisional handshake for nodes without SID
    ProvisionalHello(ProvisionalHello),
    
    /// Server challenge for provisional handshake
    ChallengeResponse(ChallengeResponse),
    
    /// Client proves challenge completion
    ChallengeProof(ChallengeProof),
    
    /// Handshake error
    Error(HandshakeErrorMessage),
}

/// ClientHello: Initial message from client to server
///
/// Contains client identity, capabilities, and a challenge nonce that
/// the server must sign to prove its identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// Client's node identity (public fields only, safe for network transmission)
    pub identity: NodeIdentity,

    /// Client's capabilities
    pub capabilities: HandshakeCapabilities,

    /// Random challenge nonce (32 bytes)
    pub challenge_nonce: [u8; 32],

    /// Client's signature over (identity + capabilities + nonce + timestamp + version)
    pub signature: Signature,

    /// Timestamp when message was created (Unix timestamp in seconds)
    /// Used for replay attack prevention
    pub timestamp: u64,

    /// Protocol version (UHP_VERSION = 1)
    /// Used for version negotiation and preventing downgrade attacks
    pub protocol_version: u8,
}

impl ClientHello {
    /// Create a new ClientHello message
    ///
    /// Takes full ZhtpIdentity for signing, but only stores public NodeIdentity fields
    pub fn new(
        zhtp_identity: &ZhtpIdentity,
        capabilities: HandshakeCapabilities,
    ) -> Result<Self> {
        let mut challenge_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge_nonce);

        // Get current timestamp
        let timestamp = current_timestamp()?;

        // Use current protocol version
        let protocol_version = UHP_VERSION;

        // Extract public-only identity for network transmission
        let identity = NodeIdentity::from_zhtp_identity(zhtp_identity);

        // Create keypair from ZhtpIdentity's keys for signing
        let keypair = KeyPair {
            public_key: zhtp_identity.public_key.clone(),
            private_key: zhtp_identity.private_key.clone().ok_or_else(|| anyhow!("Identity missing private key"))?,
        };

        // Sign the hello message (includes timestamp and version for replay protection)
        let data = Self::data_to_sign(&identity, &capabilities, &challenge_nonce, timestamp, protocol_version)?;
        let signature = keypair.sign(&data)?;

        Ok(Self {
            identity,
            capabilities,
            challenge_nonce,
            signature,
            timestamp,
            protocol_version,
        })
    }
    
    /// Verify the signature on this ClientHello
    ///
    /// SECURITY: Enforces NodeId verification, timestamp validation, protocol version check,
    /// and nonce replay detection.
    ///
    /// **VULN-001 FIX:** Uses nonce_cache for replay attack prevention.
    /// **FINDING 2 FIX:** Uses HandshakeContext to eliminate parameter threading.
    /// **FINDING 4 FIX:** Emits observability events for monitoring.
    pub fn verify_signature(&self, ctx: &HandshakeContext) -> Result<()> {
        use observability::{HandshakeEvent, FailureReason, Timer};

        let timer = Timer::start();
        ctx.observer.on_event(HandshakeEvent::ClientHelloVerificationStarted, None);

        // 0. CRITICAL: Validate protocol version (VULN-004 FIX)
        if let Err(e) = validate_protocol_version(self.protocol_version) {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_event(HandshakeEvent::InvalidProtocolVersionDetected, Some(metrics.clone()));
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::InvalidProtocolVersion,
                Some(metrics),
            );
            return Err(e);
        }

        // 1. CRITICAL: Verify NodeId derivation (prevent collision attacks)
        if let Err(e) = self.identity.verify_node_id() {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_event(HandshakeEvent::NodeIdVerificationFailed, Some(metrics.clone()));
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::NodeIdVerificationFailed,
                Some(metrics),
            );
            return Err(e);
        }

        // 2. CRITICAL: Validate timestamp (prevent replay attacks)
        if let Err(e) = validate_timestamp(self.timestamp, &ctx.timestamp_config) {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_event(HandshakeEvent::InvalidTimestampDetected, Some(metrics.clone()));
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::InvalidTimestamp,
                Some(metrics),
            );
            return Err(e);
        }

        // 3. CRITICAL: Check nonce cache - prevent replay attacks (VULN-001 FIX)
        if let Err(e) = ctx.nonce_cache.check_and_store(&self.challenge_nonce, self.timestamp) {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_event(HandshakeEvent::ReplayAttackDetected, Some(metrics.clone()));
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::ReplayAttack,
                Some(metrics),
            );
            return Err(e);
        }

        // 4. Verify signature includes all critical fields
        let data = Self::data_to_sign(
            &self.identity,
            &self.capabilities,
            &self.challenge_nonce,
            self.timestamp,
            self.protocol_version,
        )?;

        if self.identity.public_key.verify(&data, &self.signature)? {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_event(HandshakeEvent::ClientHelloVerificationSuccess, Some(metrics));
            Ok(())
        } else {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::InvalidSignature,
                Some(metrics),
            );
            Err(anyhow!("Signature verification failed"))
        }
    }

    /// Data to sign for ClientHello
    ///
    /// SECURITY: Includes timestamp and version to prevent manipulation
    fn data_to_sign(
        identity: &NodeIdentity,
        capabilities: &HandshakeCapabilities,
        nonce: &[u8; 32],
        timestamp: u64,
        protocol_version: u8,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        // Message type for context binding (prevent cross-message replay)
        data.push(0x01); // MessageType::ClientHello

        // Identity and capabilities
        data.extend_from_slice(identity.node_id.as_bytes());
        data.extend_from_slice(bincode::serialize(capabilities)?.as_slice());

        // Nonce
        data.extend_from_slice(nonce);

        // CRITICAL: Include timestamp (prevents timestamp manipulation)
        data.extend_from_slice(&timestamp.to_le_bytes());

        // CRITICAL: Include version (prevents version downgrade attacks)
        data.push(protocol_version);

        Ok(data)
    }
}

/// ServerHello: Server's response to ClientHello
///
/// Server verifies client's identity, sends its own identity and capabilities,
/// signs the client's challenge nonce, and provides a response nonce for the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    /// Server's node identity (public fields only, safe for network transmission)
    pub identity: NodeIdentity,

    /// Server's capabilities
    pub capabilities: HandshakeCapabilities,

    /// Response nonce for client to sign (32 bytes)
    pub response_nonce: [u8; 32],

    /// Server's signature over (client_challenge + server_identity + capabilities + timestamp + version)
    pub signature: Signature,

    /// Negotiated session capabilities
    pub negotiated: NegotiatedCapabilities,

    /// Timestamp when message was created (Unix timestamp in seconds)
    /// Used for replay attack prevention
    pub timestamp: u64,

    /// Protocol version (UHP_VERSION = 1)
    /// Used for version negotiation
    pub protocol_version: u8,
}

impl ServerHello {
    /// Create a new ServerHello message
    ///
    /// Takes full ZhtpIdentity for signing, but only stores public NodeIdentity fields
    pub fn new(
        zhtp_identity: &ZhtpIdentity,
        capabilities: HandshakeCapabilities,
        client_hello: &ClientHello,
    ) -> Result<Self> {
        let mut response_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut response_nonce);

        // Get current timestamp
        let timestamp = current_timestamp()?;

        // Use current protocol version
        let protocol_version = UHP_VERSION;

        let negotiated = capabilities.negotiate(&client_hello.capabilities);

        // Extract public-only identity for network transmission
        let identity = NodeIdentity::from_zhtp_identity(zhtp_identity);

        // Create keypair from ZhtpIdentity's keys for signing
        let keypair = KeyPair {
            public_key: zhtp_identity.public_key.clone(),
            private_key: zhtp_identity.private_key.clone().ok_or_else(|| anyhow!("Identity missing private key"))?,
        };

        // Sign: client's nonce + our identity + our capabilities + timestamp + version
        let data = Self::data_to_sign(
            &client_hello.challenge_nonce,
            &identity,
            &capabilities,
            timestamp,
            protocol_version,
        )?;
        let signature = keypair.sign(&data)?;

        Ok(Self {
            identity,
            capabilities,
            response_nonce,
            signature,
            negotiated,
            timestamp,
            protocol_version,
        })
    }

    /// Verify the server's signature
    ///
    /// SECURITY: Enforces NodeId verification, timestamp validation, protocol version check,
    /// and nonce replay detection.
    ///
    /// **VULN-001 FIX:** Uses nonce_cache for replay attack prevention.
    /// **FINDING 2 FIX:** Uses HandshakeContext to eliminate parameter threading.
    pub fn verify_signature(&self, client_nonce: &[u8; 32], ctx: &HandshakeContext) -> Result<()> {
        // 0. CRITICAL: Validate protocol version (VULN-004 FIX)
        validate_protocol_version(self.protocol_version)?;

        // 1. CRITICAL: Verify NodeId derivation
        self.identity.verify_node_id()?;

        // 2. CRITICAL: Validate timestamp
        validate_timestamp(self.timestamp, &ctx.timestamp_config)?;

        // 3. CRITICAL: Check nonce cache - prevent replay attacks (VULN-001 FIX)
        ctx.nonce_cache.check_and_store(&self.response_nonce, self.timestamp)?;

        // 4. Verify signature includes all critical fields
        let data = Self::data_to_sign(
            client_nonce,
            &self.identity,
            &self.capabilities,
            self.timestamp,
            self.protocol_version,
        )?;

        if self.identity.public_key.verify(&data, &self.signature)? {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }

    /// Data to sign for ServerHello
    ///
    /// SECURITY: Includes client nonce, timestamp, and version
    fn data_to_sign(
        client_nonce: &[u8; 32],
        identity: &NodeIdentity,
        capabilities: &HandshakeCapabilities,
        timestamp: u64,
        protocol_version: u8,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        // Message type for context binding
        data.push(0x02); // MessageType::ServerHello

        // Client's challenge nonce (proves we received ClientHello)
        data.extend_from_slice(client_nonce);

        // Server identity and capabilities
        data.extend_from_slice(identity.node_id.as_bytes());
        data.extend_from_slice(bincode::serialize(capabilities)?.as_slice());

        // CRITICAL: Include timestamp
        data.extend_from_slice(&timestamp.to_le_bytes());

        // CRITICAL: Include version
        data.push(protocol_version);

        Ok(data)
    }
}

/// ClientFinish: Client confirms handshake completion
///
/// Client signs the server's response nonce to prove receipt and agreement.
/// **CRITICAL**: Now includes mutual authentication - verifies server's signature
/// before completing handshake. After this message, the secure session is established.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFinish {
    /// Client's signature over server's response nonce
    pub signature: Signature,

    /// Timestamp when ClientFinish was created
    pub timestamp: u64,

    /// Protocol version
    pub protocol_version: u8,

    /// Optional session parameters
    pub session_params: Option<Vec<u8>>,
}

impl ClientFinish {
    /// Create a new ClientFinish message with mutual authentication
    ///
    /// **CRITICAL SECURITY**: This method now performs mutual authentication by:
    /// 1. Verifying server's NodeId derivation (prevents collision attacks)
    /// 2. Validating server's timestamp (prevents replay attacks)
    /// 3. Checking nonce cache (prevents replay attacks - VULN-001 FIX)
    /// 4. Verifying server's signature on ServerHello (prevents MitM attacks)
    ///
    /// Only after server is verified does the client sign the server nonce.
    ///
    /// **FINDING 2 FIX:** Uses HandshakeContext to eliminate parameter threading.
    pub fn new(
        server_hello: &ServerHello,
        client_hello: &ClientHello,
        keypair: &KeyPair,
        ctx: &HandshakeContext,
    ) -> Result<Self> {
        // === MUTUAL AUTHENTICATION: Verify server before completing handshake ===

        // 1. Verify server's NodeId derivation (collision attack prevention)
        server_hello.identity.verify_node_id()
            .map_err(|e| anyhow!("Server NodeId verification failed: {}", e))?;

        // 2. Validate server's timestamp (replay attack prevention)
        validate_timestamp(server_hello.timestamp, &ctx.timestamp_config)
            .map_err(|e| anyhow!("Server timestamp validation failed: {}", e))?;

        // 3. Verify server's signature on ServerHello (MitM + replay prevention)
        server_hello.verify_signature(&client_hello.challenge_nonce, ctx)
            .map_err(|e| anyhow!("Server signature verification failed: {}", e))?;

        // === Server verified! Now complete handshake ===

        let timestamp = current_timestamp()?;
        let protocol_version = UHP_VERSION;

        // Sign server's response nonce to complete handshake
        let data = Self::data_to_sign(
            &server_hello.response_nonce,
            timestamp,
            protocol_version,
        )?;
        let signature = keypair.sign(&data)?;

        Ok(Self {
            signature,
            timestamp,
            protocol_version,
            session_params: None,
        })
    }

    /// Verify client's signature on server nonce
    pub fn verify_signature(&self, server_nonce: &[u8; 32], client_pubkey: &PublicKey) -> Result<()> {
        // 0. CRITICAL: Validate protocol version (VULN-004 FIX)
        validate_protocol_version(self.protocol_version)?;

        // 1. Validate timestamp
        validate_timestamp(self.timestamp, &TimestampConfig::default())?;

        // 2. Verify signature
        let data = Self::data_to_sign(
            server_nonce,
            self.timestamp,
            self.protocol_version,
        )?;

        if client_pubkey.verify(&data, &self.signature)? {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }

    /// Build data to sign for ClientFinish
    fn data_to_sign(
        server_nonce: &[u8; 32],
        timestamp: u64,
        protocol_version: u8,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.push(0x03); // MessageType::ClientFinish for context binding
        data.extend_from_slice(server_nonce);
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.push(protocol_version);
        Ok(data)
    }
}

// ============================================================================
// Provisional Handshake (for nodes without SID)
// ============================================================================

/// ProvisionalHello: Initial message for nodes without SID
///
/// Used for bootstrapping new nodes that don't yet have a Sovereign Identity.
/// This creates an ephemeral session with limited privileges until a full SID is issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionalHello {
    /// Ephemeral public key (temporary, not tied to SID)
    pub ephemeral_pubkey: PublicKey,
    
    /// Random nonce for this provisional session
    pub nonce: [u8; 32],
    
    /// Signature over nonce with ephemeral key
    pub signature: Signature,
    
    /// Optional metadata (e.g., device type, reason for request)
    pub metadata: Option<Vec<u8>>,
}

impl ProvisionalHello {
    /// Create new provisional hello
    pub fn new(ephemeral_keypair: &KeyPair, metadata: Option<Vec<u8>>) -> Result<Self> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        
        let signature = ephemeral_keypair.sign(&nonce)?;
        
        Ok(Self {
            ephemeral_pubkey: ephemeral_keypair.public_key.clone(),
            nonce,
            signature,
            metadata,
        })
    }
    
    /// Verify signature
    pub fn verify_signature(&self) -> Result<()> {
        if self.ephemeral_pubkey.verify(&self.nonce, &self.signature)? {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }
}

/// ChallengeResponse: Server's challenge to provisional client
///
/// Server responds with a challenge that the client must complete to prove
/// legitimacy (e.g., proof of work, proof of stake, or other verification method).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Challenge data (depends on challenge type)
    pub challenge: Vec<u8>,
    
    /// Challenge type (e.g., "proof-of-work", "captcha", "email-verify")
    pub challenge_type: String,
    
    /// Difficulty or parameters for challenge
    pub difficulty: u32,
    
    /// Expiration timestamp for this challenge
    pub expires_at: u64,
}

/// ChallengeProof: Client's proof of challenge completion
///
/// Client submits proof that they completed the challenge. If accepted,
/// server issues a SID and the connection upgrades to full authenticated handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeProof {
    /// Proof data (format depends on challenge type)
    pub proof: Vec<u8>,
    
    /// Original challenge nonce for verification
    pub challenge_nonce: [u8; 32],
    
    /// Signature over proof with ephemeral key
    pub signature: Signature,
}

// ============================================================================
// Handshake Result
// ============================================================================

/// Result of a successful handshake
///
/// Contains all information needed to establish a secure session between peers.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// Peer's verified node identity (public fields only)
    pub peer_identity: NodeIdentity,
    
    /// Negotiated session capabilities
    pub capabilities: NegotiatedCapabilities,
    
    /// Session key for symmetric encryption (derived from handshake)
    pub session_key: [u8; 32],
    
    /// Session identifier
    pub session_id: [u8; 16],
    
    /// Timestamp when handshake completed
    pub completed_at: u64,
}

impl HandshakeResult {
    /// Create a new handshake result
    ///
    /// **VULN-003 FIX:** Uses ClientHello timestamp for deterministic session key derivation.
    /// Both client and server MUST use the same timestamp (from ClientHello) to derive
    /// identical session keys.
    ///
    /// # Arguments
    /// * `client_hello_timestamp` - Timestamp from ClientHello message (MUST be same on both sides)
    pub fn new(
        peer_identity: NodeIdentity,
        capabilities: NegotiatedCapabilities,
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
        client_did: &str,
        server_did: &str,
        client_hello_timestamp: u64,
    ) -> Result<Self> {
        // Build session context for HKDF domain separation
        // CRITICAL: Use ClientHello timestamp (deterministic, agreed by both parties)
        let context = SessionContext {
            protocol_version: UHP_VERSION as u32,
            client_did: client_did.to_string(),
            server_did: server_did.to_string(),
            timestamp: client_hello_timestamp, // VULN-003 FIX: Deterministic timestamp
        };

        // Derive session key using HKDF (NIST SP 800-108 compliant)
        let session_key = derive_session_key_hkdf(client_nonce, server_nonce, &context)?;

        // Generate session ID from first 16 bytes of session key
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&session_key[..16]);

        Ok(Self {
            peer_identity,
            capabilities,
            session_key,
            session_id,
            completed_at: current_timestamp()?, // Completion time (for logging only)
        })
    }
}

// ============================================================================
// Error Handling
// ============================================================================

/// Handshake error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeError {
    /// NodeId verification failed
    NodeIdMismatch {
        claimed: String,
        expected: String,
        did: String,
        device: String,
    },
    
    /// Signature verification failed
    InvalidSignature { peer: String },
    
    /// Protocol version not supported
    UnsupportedVersion {
        version: u8,
        min: u8,
        max: u8,
    },
    
    /// No compatible capabilities found
    IncompatibleCapabilities {
        client_caps: String,
        server_caps: String,
    },
    
    /// Handshake timeout
    Timeout { seconds: u64 },
    
    /// Challenge failed (provisional handshake)
    ChallengeFailed { reason: String },
    
    /// Connection closed during handshake
    ConnectionClosed { stage: String },
    
    /// Invalid message format
    InvalidMessage { reason: String },
    
    /// Replay attack detected
    ReplayDetected { timestamp: u64 },
    
    /// Internal error
    Internal { message: String },
}

/// Handshake error message (sent over wire)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeErrorMessage {
    /// Error code
    pub code: String,
    
    /// Human-readable error message
    pub message: String,
    
    /// Whether the connection should be closed
    pub fatal: bool,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::NodeIdMismatch { claimed, expected, did, device } => {
                write!(f, "NodeId mismatch: claimed {} but expected {} from DID '{}' + device '{}'", claimed, expected, did, device)
            }
            HandshakeError::InvalidSignature { peer } => write!(f, "Invalid signature from peer {}", peer),
            HandshakeError::UnsupportedVersion { version, min, max } => {
                write!(f, "Unsupported protocol version {} (supported: {}-{})", version, min, max)
            }
            HandshakeError::IncompatibleCapabilities { client_caps, server_caps } => {
                write!(f, "No compatible capabilities: client supports {}, server supports {}", client_caps, server_caps)
            }
            HandshakeError::Timeout { seconds } => write!(f, "Handshake timeout after {} seconds", seconds),
            HandshakeError::ChallengeFailed { reason } => write!(f, "Challenge verification failed: {}", reason),
            HandshakeError::ConnectionClosed { stage } => write!(f, "Connection closed during handshake at stage {}", stage),
            HandshakeError::InvalidMessage { reason } => write!(f, "Invalid handshake message: {}", reason),
            HandshakeError::ReplayDetected { timestamp } => write!(f, "Replay attack detected: timestamp {} is too old", timestamp),
            HandshakeError::Internal { message } => write!(f, "Internal handshake error: {}", message),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<HandshakeError> for HandshakeErrorMessage {
    fn from(err: HandshakeError) -> Self {
        let code = match &err {
            HandshakeError::NodeIdMismatch { .. } => "NODE_ID_MISMATCH",
            HandshakeError::InvalidSignature { .. } => "INVALID_SIGNATURE",
            HandshakeError::UnsupportedVersion { .. } => "UNSUPPORTED_VERSION",
            HandshakeError::IncompatibleCapabilities { .. } => "INCOMPATIBLE_CAPABILITIES",
            HandshakeError::Timeout { .. } => "TIMEOUT",
            HandshakeError::ChallengeFailed { .. } => "CHALLENGE_FAILED",
            HandshakeError::ConnectionClosed { .. } => "CONNECTION_CLOSED",
            HandshakeError::InvalidMessage { .. } => "INVALID_MESSAGE",
            HandshakeError::ReplayDetected { .. } => "REPLAY_DETECTED",
            HandshakeError::Internal { .. } => "INTERNAL_ERROR",
        };
        
        Self {
            code: code.to_string(),
            message: err.to_string(),
            fatal: true,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_uhp_version_constants() {
        assert_eq!(UHP_VERSION, 1);
        assert_eq!(UHP_VERSION_STRING, "UHP/1.0");
        assert!(MIN_SUPPORTED_VERSION <= UHP_VERSION);
        assert!(UHP_VERSION <= MAX_SUPPORTED_VERSION);
    }
    
    #[test]
    fn test_zhtp_identity_in_handshake() -> Result<()> {
        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "test-device",
            None,
        )?;
        
        // Verify ZhtpIdentity has all necessary fields for handshake
        assert!(!identity.did.is_empty());
        assert!(!identity.node_id.as_bytes().is_empty());
        assert!(!identity.public_key.dilithium_pk.is_empty());
        
        Ok(())
    }
    
    #[test]
    fn test_zhtp_identity_node_id_derivation() -> Result<()> {
        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "test-device",
            None,
        )?;
        
        // Verify node_id is properly derived from DID and device
        let expected = NodeId::from_did_device(&identity.did, &identity.primary_device)?;
        assert_eq!(identity.node_id.as_bytes(), expected.as_bytes());
        
        Ok(())
    }
    
    #[test]
    fn test_capability_negotiation() {
        let client_caps = HandshakeCapabilities {
            protocols: vec!["tcp".to_string(), "udp".to_string(), "quic".to_string()],
            max_throughput: 10_000_000,
            max_message_size: 1_000_000,
            encryption_methods: vec!["chacha20-poly1305".to_string(), "aes-256-gcm".to_string()],
            pqc_support: true,
            dht_capable: true,
            relay_capable: false,
            storage_capacity: 0,
            web4_capable: false,
            custom_features: vec![],
        };
        
        let server_caps = HandshakeCapabilities {
            protocols: vec!["tcp".to_string(), "quic".to_string()],
            max_throughput: 50_000_000,
            max_message_size: 5_000_000,
            encryption_methods: vec!["chacha20-poly1305".to_string()],
            pqc_support: true,
            dht_capable: false,
            relay_capable: true,
            storage_capacity: 1_000_000_000,
            web4_capable: true,
            custom_features: vec![],
        };
        
        let negotiated = client_caps.negotiate(&server_caps);
        
        // Should pick first common protocol
        assert_eq!(negotiated.protocol, "tcp");
        
        // Should pick minimum throughput
        assert_eq!(negotiated.max_throughput, 10_000_000);
        
        // Should pick minimum message size
        assert_eq!(negotiated.max_message_size, 1_000_000);
        
        // Should pick first common encryption
        assert_eq!(negotiated.encryption_method, "chacha20-poly1305");
        
        // Should enable PQC (both support it)
        assert!(negotiated.pqc_enabled);
        
        // Should disable DHT (server doesn't support)
        assert!(!negotiated.dht_enabled);
        
        // Should disable relay (client doesn't support)
        assert!(!negotiated.relay_enabled);
    }
    
    #[test]
    fn test_handshake_message_serialization() -> Result<()> {
        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "test-device",
            None,
        )?;
        
        let capabilities = HandshakeCapabilities::default();
        
        let client_hello = ClientHello::new(&identity, capabilities)?;
        let message = HandshakeMessage::new(HandshakePayload::ClientHello(client_hello));
        
        // Serialize
        let bytes = message.to_bytes()?;
        
        // Deserialize
        let deserialized = HandshakeMessage::from_bytes(&bytes)?;
        
        // Verify version matches
        assert_eq!(deserialized.version, UHP_VERSION);
        
        Ok(())
    }
    
    #[test]
    fn test_client_hello_signature_verification() -> Result<()> {
        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "test-device",
            None,
        )?;

        let capabilities = HandshakeCapabilities::default();

        let client_hello = ClientHello::new(&identity, capabilities)?;

        // Create handshake context for verification
        let ctx = HandshakeContext::new_test();

        // Signature should verify
        client_hello.verify_signature(&ctx)?;

        Ok(())
    }
    
    #[test]
    fn test_session_key_derivation() {
        let client_nonce = [0x42u8; 32];
        let server_nonce = [0x84u8; 32];

        let context = SessionContext {
            protocol_version: UHP_VERSION as u32,
            client_did: "did:zhtp:test_client".to_string(),
            server_did: "did:zhtp:test_server".to_string(),
            timestamp: 1234567890,
        };

        let key1 = derive_session_key_hkdf(&client_nonce, &server_nonce, &context).unwrap();
        let key2 = derive_session_key_hkdf(&client_nonce, &server_nonce, &context).unwrap();

        // Should be deterministic
        assert_eq!(key1, key2);

        // Should change if nonces change
        let different_client = [0x43u8; 32];
        let key3 = derive_session_key_hkdf(&different_client, &server_nonce, &context).unwrap();
        assert_ne!(key1, key3);
    }
    
    #[test]
    fn test_minimal_capabilities() {
        let minimal = HandshakeCapabilities::minimal();
        
        assert_eq!(minimal.protocols, vec!["ble".to_string()]);
        assert_eq!(minimal.max_throughput, 10_000);
        assert_eq!(minimal.max_message_size, 512);
        assert!(!minimal.pqc_support);
        assert!(!minimal.dht_capable);
    }
    
    #[test]
    fn test_full_featured_capabilities() {
        let full = HandshakeCapabilities::full_featured();

        assert!(full.protocols.len() >= 5);
        assert!(full.max_throughput >= 100_000_000);
        assert!(full.max_message_size >= 10_000_000);
        assert!(full.pqc_support);
        assert!(full.dht_capable);
        assert!(full.relay_capable);
    }

    // ============================================================================
    // Integration Tests - FINDING 6
    // ============================================================================

    /// Test full handshake flow from ClientHello to ClientFinish
    ///
    /// **FINDING 6 FIX:** End-to-end integration test of complete handshake
    #[test]
    fn test_full_handshake_flow() -> Result<()> {
        // Setup: Create client and server identities
        let client_identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "client-device",
            None,
        )?;

        let server_identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "server-device",
            None,
        )?;

        // Create handshake context (shared nonce cache)
        let ctx = HandshakeContext::new_test();

        // Step 1: Client sends ClientHello
        let client_capabilities = HandshakeCapabilities::default();
        let client_hello = ClientHello::new(&client_identity, client_capabilities)?;

        // Server verifies ClientHello
        client_hello.verify_signature(&ctx)?;

        // Step 2: Server sends ServerHello
        let server_capabilities = HandshakeCapabilities::default();
        let server_hello = ServerHello::new(&server_identity, server_capabilities, &client_hello)?;

        // Step 3: Client sends ClientFinish (includes mutual authentication of server)
        let client_keypair = KeyPair {
            public_key: client_identity.public_key.clone(),
            private_key: client_identity.private_key.clone().unwrap(),
        };

        let client_finish = ClientFinish::new(&server_hello, &client_hello, &client_keypair, &ctx)?;

        // Server verifies ClientFinish
        client_finish.verify_signature(&server_hello.response_nonce, &client_hello.identity.public_key)?;

        // Step 4: Both sides derive session key
        let client_session = HandshakeResult::new(
            server_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_identity.did,
            &server_identity.did,
            client_hello.timestamp,
        )?;

        let server_session = HandshakeResult::new(
            client_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_identity.did,
            &server_identity.did,
            client_hello.timestamp,
        )?;

        // Verify both parties derived the same session key
        assert_eq!(client_session.session_key, server_session.session_key);

        Ok(())
    }

    /// Test concurrent handshakes with shared nonce cache
    ///
    /// **FINDING 6 FIX:** Tests thread-safety of nonce cache under concurrent load
    #[test]
    fn test_concurrent_handshakes_with_shared_cache() -> Result<()> {
        // Create shared context
        let ctx = HandshakeContext::new(NonceCache::new(60, 10000));

        // Launch 50 concurrent handshakes
        let handles: Vec<_> = (0..50)
            .map(|i| {
                let ctx = ctx.clone();
                std::thread::spawn(move || -> Result<()> {
                    let client_device_name = format!("client-device-{}", i);
                    let server_device_name = format!("server-device-{}", i);

                    let client_identity = lib_identity::ZhtpIdentity::new_unified(
                        lib_identity::IdentityType::Human,
                        Some(25),
                        Some("US".to_string()),
                        &client_device_name,
                        None,
                    )?;

                    let server_identity = lib_identity::ZhtpIdentity::new_unified(
                        lib_identity::IdentityType::Human,
                        Some(30),
                        Some("US".to_string()),
                        &server_device_name,
                        None,
                    )?;

                    // Full handshake flow
                    let client_hello = ClientHello::new(&client_identity, HandshakeCapabilities::default())?;
                    client_hello.verify_signature(&ctx)?;

                    let server_hello = ServerHello::new(&server_identity, HandshakeCapabilities::default(), &client_hello)?;

                    let client_keypair = KeyPair {
                        public_key: client_identity.public_key.clone(),
                        private_key: client_identity.private_key.clone().unwrap(),
                    };

                    let _client_finish = ClientFinish::new(&server_hello, &client_hello, &client_keypair, &ctx)?;

                    Ok(())
                })
            })
            .collect();

        // Wait for all handshakes to complete
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // All should succeed
        for result in results {
            assert!(result.is_ok());
        }

        // Verify cache size (should have 100 nonces: 50 client + 50 server)
        assert_eq!(ctx.nonce_cache.size(), 100);

        Ok(())
    }

    /// Test replay attack prevention
    ///
    /// **FINDING 6 FIX:** Verifies nonce cache prevents replay attacks
    #[test]
    fn test_replay_attack_prevention() -> Result<()> {
        let ctx = HandshakeContext::new_test();

        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "test-device",
            None,
        )?;

        // Create ClientHello
        let client_hello = ClientHello::new(&identity, HandshakeCapabilities::default())?;

        // First verification should succeed
        assert!(client_hello.verify_signature(&ctx).is_ok());

        // Second verification with same nonce should fail (replay attack detected)
        let result = client_hello.verify_signature(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Replay detected"));

        Ok(())
    }
}
