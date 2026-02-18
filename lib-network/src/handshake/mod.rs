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
//! UHP v2 is the only supported handshake in alpha. There are no legacy fallbacks,
//! downgrade paths, or dual-version code paths in the critical path.

use anyhow::{Result, anyhow};
use lib_crypto::{PublicKey, Signature, KeyPair};
use lib_identity::{ZhtpIdentity, NodeId};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;
use tracing::error;

// Security modules
pub mod security;
mod nonce_cache;
mod observability;
mod rate_limiter;
pub mod blockchain;

// Core handshake I/O (Ticket #136)
pub mod core;

// Post-Quantum Cryptography support (Ticket #137)
pub mod pqc;

// Unified message framing for all transports
pub mod framing;

// Handshake orchestration helpers (reduces duplication)
pub mod orchestrator;

// Re-export security utilities
pub use security::{
    TimestampConfig, SessionContext,
    validate_timestamp, current_timestamp,
    derive_session_key_hkdf, ct_eq_bytes, ct_verify_eq,
    // UHP v2 key schedule and MAC
    v2_labels, V2SessionKeys, derive_v2_session_keys, derive_v2_key,
    CanonicalRequest, compute_v2_mac, verify_v2_mac,
};
pub use nonce_cache::{
    NonceCache, start_nonce_cleanup_task, NetworkEpoch,
    SeenResult, compute_nonce_fingerprint,
    // Global singleton functions [DB-013]
    init_global_nonce_cache, global_nonce_cache,
    is_global_nonce_cache_initialized, get_or_init_global_nonce_cache,
};
pub use observability::{
    HandshakeObserver, HandshakeEvent, HandshakeMetrics, FailureReason,
    NoOpObserver, LoggingObserver, Timer,
};
pub use rate_limiter::{RateLimiter, RateLimitConfig};

// Re-export blockchain handshake types
pub use blockchain::{
    BlockchainHandshakeContext, BlockchainHandshakeVerifier,
    BlockchainVerificationResult, PeerTier,
};

// Re-export PQC types and functions
pub use pqc::{
    PqcCapability, PqcHandshakeOffer, PqcHandshakeState,
    create_pqc_offer, verify_pqc_offer, encapsulate_pqc,
    decapsulate_pqc, derive_hybrid_session_key,
};

// Re-export core handshake functions
pub use core::{
    handshake_as_initiator, handshake_as_responder,
    NonceTracker, HandshakeIoError,
};

// Re-export message framing utilities
pub use framing::{
    send_framed, recv_framed, MAX_HANDSHAKE_MESSAGE_SIZE,
};

/// Default network identifier for handshake domain separation.
pub const DEFAULT_HANDSHAKE_NETWORK_ID: &str = "zhtp-mainnet";

/// Protocol identifier for UHP handshakes.
pub const DEFAULT_HANDSHAKE_PROTOCOL_ID: &str = "uhp";

/// Purpose string for node authentication handshakes.
pub const DEFAULT_HANDSHAKE_PURPOSE: &str = "zhtp-node-handshake";

/// UHP Protocol Version
pub const UHP_VERSION: u8 = 2;

/// Protocol version string for compatibility
pub const UHP_VERSION_STRING: &str = "UHP/2.0";

/// Maximum supported protocol version (for future compatibility)
pub const MAX_SUPPORTED_VERSION: u8 = 2;

/// Minimum supported protocol version (for backwards compatibility)
pub const MIN_SUPPORTED_VERSION: u8 = 2;

/// Backward compatibility policy for peers running older protocol versions.
///
/// # BFT-H Policy (Issue #1006)
///
/// The deterministic backward compatibility rules are:
/// - **Accept**: peer version is within `[MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION]`
/// - **Reject**: peer version is below `MIN_SUPPORTED_VERSION` or above `MAX_SUPPORTED_VERSION`
///
/// There is no quarantine state — mixed-version validators produce divergent
/// views and MUST be rejected immediately to preserve deterministic finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackwardCompatibilityPolicy {
    /// Peer version is acceptable; connection may proceed.
    Accept,
    /// Peer version is incompatible; connection MUST be refused.
    Reject,
}

impl BackwardCompatibilityPolicy {
    /// Evaluates the backward compatibility policy for a peer's protocol version.
    ///
    /// Callers should invoke this helper before accepting any block, vote, or
    /// validator registration from a peer, and enforce the returned policy in
    /// their respective acceptance logic.
    ///
    /// # Arguments
    /// * `peer_version` - The protocol version reported by the peer
    ///
    /// # Returns
    /// * `Accept` if peer version is within `[MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION]`
    /// * `Reject` otherwise
    pub fn check(peer_version: u8) -> Self {
        if peer_version >= MIN_SUPPORTED_VERSION && peer_version <= MAX_SUPPORTED_VERSION {
            BackwardCompatibilityPolicy::Accept
        } else {
            BackwardCompatibilityPolicy::Reject
        }
    }
}

#[cfg(test)]
mod backward_compat_tests {
    use super::*;

    #[test]
    fn test_accept_current_version() {
        assert_eq!(
            BackwardCompatibilityPolicy::check(UHP_VERSION),
            BackwardCompatibilityPolicy::Accept
        );
    }

    #[test]
    fn test_accept_minimum_version() {
        assert_eq!(
            BackwardCompatibilityPolicy::check(MIN_SUPPORTED_VERSION),
            BackwardCompatibilityPolicy::Accept
        );
    }

    #[test]
    fn test_reject_below_minimum() {
        // If the minimum supported version is 0, there is no lower version to test.
        if MIN_SUPPORTED_VERSION == 0 {
            return;
        }

        let old = MIN_SUPPORTED_VERSION - 1;
        assert_eq!(
            BackwardCompatibilityPolicy::check(old),
            BackwardCompatibilityPolicy::Reject
        );
    }

    #[test]
    fn test_reject_future_version() {
        assert_eq!(
            BackwardCompatibilityPolicy::check(MAX_SUPPORTED_VERSION + 1),
            BackwardCompatibilityPolicy::Reject
        );
    }
}

/// Declared role for handshake participants.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HandshakeRole {
    Client,
    Server,
    Router,
    Verifier,
}

impl HandshakeRole {
    fn as_u8(self) -> u8 {
        match self {
            Self::Client => 0,
            Self::Server => 1,
            Self::Router => 2,
            Self::Verifier => 3,
        }
    }
}

/// Domain separation inputs for handshake signatures.
#[derive(Debug, Clone)]
pub struct HandshakeDomain {
    pub network_id: String,
    pub protocol_id: String,
    pub purpose: String,
}

impl Default for HandshakeDomain {
    fn default() -> Self {
        Self {
            network_id: DEFAULT_HANDSHAKE_NETWORK_ID.to_string(),
            protocol_id: DEFAULT_HANDSHAKE_PROTOCOL_ID.to_string(),
            purpose: DEFAULT_HANDSHAKE_PURPOSE.to_string(),
        }
    }
}

/// Validate protocol version is within supported range
///
/// **VULN-004 FIX:** Prevents protocol downgrade attacks
///
/// This function enforces the backward compatibility policy defined in
/// `BackwardCompatibilityPolicy` for BFT-H consensus safety (Issue #1006).
///
/// # Returns
/// - `Ok(())` if version is valid
/// - `Err(...)` if version is outside supported range
fn validate_protocol_version(version: u8) -> Result<()> {
    match BackwardCompatibilityPolicy::check(version) {
        BackwardCompatibilityPolicy::Accept => Ok(()),
        BackwardCompatibilityPolicy::Reject => Err(anyhow!(
            "Unsupported protocol version: {} (supported: {}-{})",
            version,
            MIN_SUPPORTED_VERSION,
            MAX_SUPPORTED_VERSION
        )),
    }
}

fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

pub fn derive_channel_binding_from_addrs(local: std::net::SocketAddr, peer: std::net::SocketAddr) -> Vec<u8> {
    use lib_crypto::hash_blake3;

    let mut addrs = [local.to_string(), peer.to_string()];
    addrs.sort();

    let mut material = Vec::new();
    append_len_prefixed(&mut material, addrs[0].as_bytes());
    append_len_prefixed(&mut material, addrs[1].as_bytes());
    hash_blake3(&material).to_vec()
}

/// Compute UHP v2 transcript hash over raw handshake message bytes
///
/// Transcript order is protocol-defined and transport-agnostic.
pub fn compute_transcript_hash(parts: &[&[u8]]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
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

    /// Domain separation parameters
    pub domain: HandshakeDomain,

    /// Declared local role for this handshake
    pub local_role: HandshakeRole,

    /// Expected peer role for this handshake
    pub peer_role: HandshakeRole,

    /// Required capabilities that must be asserted in the handshake
    pub required_capabilities: Vec<String>,

    /// Channel binding token for this transport session
    pub channel_binding: Vec<u8>,

    /// Require channel binding to be present and verified
    pub require_channel_binding: bool,
}

impl HandshakeContext {
    /// Create a new handshake context with default configuration (no rate limiting)
    pub fn new(nonce_cache: NonceCache) -> Self {
        Self {
            nonce_cache,
            timestamp_config: TimestampConfig::default(),
            observer: std::sync::Arc::new(NoOpObserver),
            rate_limiter: None,
            domain: HandshakeDomain::default(),
            local_role: HandshakeRole::Client,
            peer_role: HandshakeRole::Server,
            required_capabilities: Vec::new(),
            channel_binding: Vec::new(),
            require_channel_binding: true,
        }
    }

    /// Create with custom timestamp configuration
    pub fn with_timestamp_config(nonce_cache: NonceCache, timestamp_config: TimestampConfig) -> Self {
        Self {
            nonce_cache,
            timestamp_config,
            observer: std::sync::Arc::new(NoOpObserver),
            rate_limiter: None,
            domain: HandshakeDomain::default(),
            local_role: HandshakeRole::Client,
            peer_role: HandshakeRole::Server,
            required_capabilities: Vec::new(),
            channel_binding: Vec::new(),
            require_channel_binding: true,
        }
    }

    /// Create with custom observer
    pub fn with_observer(nonce_cache: NonceCache, observer: std::sync::Arc<dyn HandshakeObserver>) -> Self {
        Self {
            nonce_cache,
            timestamp_config: TimestampConfig::default(),
            observer,
            rate_limiter: None,
            domain: HandshakeDomain::default(),
            local_role: HandshakeRole::Client,
            peer_role: HandshakeRole::Server,
            required_capabilities: Vec::new(),
            channel_binding: Vec::new(),
            require_channel_binding: true,
        }
    }

    /// Create with rate limiting enabled
    pub fn with_rate_limiting(nonce_cache: NonceCache, rate_limiter: RateLimiter) -> Self {
        Self {
            nonce_cache,
            timestamp_config: TimestampConfig::default(),
            observer: std::sync::Arc::new(NoOpObserver),
            rate_limiter: Some(rate_limiter),
            domain: HandshakeDomain::default(),
            local_role: HandshakeRole::Client,
            peer_role: HandshakeRole::Server,
            required_capabilities: Vec::new(),
            channel_binding: Vec::new(),
            require_channel_binding: true,
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
            domain: HandshakeDomain::default(),
            local_role: HandshakeRole::Client,
            peer_role: HandshakeRole::Server,
            required_capabilities: Vec::new(),
            channel_binding: Vec::new(),
            require_channel_binding: true,
        }
    }

    /// Create a default context for testing (no rate limiting)
    #[cfg(test)]
    pub fn new_test() -> Self {
        let epoch = crate::handshake::NetworkEpoch::from_chain_id(0);
        Self {
            nonce_cache: NonceCache::new_test(300, 1000, epoch),
            timestamp_config: TimestampConfig::default(),
            observer: std::sync::Arc::new(NoOpObserver),
            rate_limiter: None,
            domain: HandshakeDomain::default(),
            local_role: HandshakeRole::Client,
            peer_role: HandshakeRole::Server,
            required_capabilities: Vec::new(),
            channel_binding: vec![0u8; 32],
            require_channel_binding: true,
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

    pub fn with_domain(&self, domain: HandshakeDomain) -> Self {
        let mut updated = self.clone();
        updated.domain = domain;
        updated
    }

    pub fn with_roles(&self, local_role: HandshakeRole, peer_role: HandshakeRole) -> Self {
        let mut updated = self.clone();
        updated.local_role = local_role;
        updated.peer_role = peer_role;
        updated
    }

    pub fn with_required_capabilities(&self, required: Vec<String>) -> Self {
        let mut updated = self.clone();
        updated.required_capabilities = required;
        updated
    }

    pub fn with_channel_binding(&self, binding: Vec<u8>) -> Self {
        let mut updated = self.clone();
        updated.channel_binding = binding;
        updated
    }

    pub fn with_channel_binding_required(&self, required: bool) -> Self {
        let mut updated = self.clone();
        updated.require_channel_binding = required;
        updated
    }

    /// Composite builder for client-side handshake with transport configuration
    ///
    /// Combines common patterns: roles + channel binding + transport capability + binding required
    /// This eliminates repeated 4-method chains across TCP, QUIC, and other transports
    pub fn for_client_with_transport(&self, binding: Vec<u8>, transport: &str) -> Self {
        self.with_roles(HandshakeRole::Client, HandshakeRole::Server)
            .with_channel_binding(binding)
            .with_required_capabilities(vec![transport.to_string()])
            .with_channel_binding_required(true)
    }

    /// Composite builder for server-side handshake with transport configuration
    ///
    /// Combines common patterns: roles + channel binding + transport capability + binding required
    /// This eliminates repeated 4-method chains across TCP, QUIC, and other transports
    pub fn for_server_with_transport(&self, binding: Vec<u8>, transport: &str) -> Self {
        self.with_roles(HandshakeRole::Server, HandshakeRole::Client)
            .with_channel_binding(binding)
            .with_required_capabilities(vec![transport.to_string()])
            .with_channel_binding_required(true)
    }

    fn require_channel_binding(&self) -> Result<()> {
        if self.require_channel_binding && self.channel_binding.is_empty() {
            return Err(anyhow!("Missing channel binding for handshake"));
        }
        Ok(())
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
                &self.did[..self.did.len().min(16)],
                &self.device_id[..self.device_id.len().min(16)]
            );
        }

        res
    }

    /// Verify node is registered on-chain (stub for future implementation)
    ///
    /// TODO: Integrate with smart contract registry
    /// - Check if NodeId exists in on-chain registry
    /// - Verify minimum stake requirement
    /// - Check if node is slashed
    /// - Verify registration hasn't expired
    ///
    /// For now, this is a no-op that always succeeds.
    /// Production deployment MUST implement actual on-chain verification.
    #[allow(dead_code)]
    pub fn verify_onchain_registration(&self) -> Result<()> {
        // Stub: Always succeeds for now
        // PRODUCTION: Replace with actual smart contract call
        tracing::debug!(
            node_id = ?self.node_id,
            "On-chain verification stub called - implement before production"
        );
        Ok(())
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
    
    /// Post-quantum cryptography capability level (None, Kyber1024+Dilithium5, Hybrid)
    pub pqc_capability: PqcCapability,
    
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
            pqc_capability: PqcCapability::Kyber1024Dilithium5,
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
            pqc_capability: PqcCapability::Kyber1024Dilithium5,
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
            pqc_capability: PqcCapability::Kyber1024Dilithium5,
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
        
        // Negotiate PQC capability using the enum's negotiation logic
        let negotiated_pqc = PqcCapability::negotiate(
            self.pqc_capability.clone(),
            other.pqc_capability.clone(),
        );
        
        NegotiatedCapabilities {
            protocol: protocols.first().cloned().unwrap_or_default(),
            max_throughput: self.max_throughput.min(other.max_throughput),
            max_message_size: self.max_message_size.min(other.max_message_size),
            encryption_method: encryption_methods.first().cloned().unwrap_or_default(),
            pqc_capability: negotiated_pqc,
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
    
    /// Negotiated PQC capability for this session
    pub pqc_capability: PqcCapability,
    
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

    /// Network identifier for domain separation
    pub network_id: String,

    /// Protocol identifier for domain separation
    pub protocol_id: String,

    /// Purpose string for handshake domain separation
    pub purpose: String,

    /// Declared client role
    pub role: HandshakeRole,

    /// Channel binding token for this transport session
    pub channel_binding: Vec<u8>,

    /// Random challenge nonce (32 bytes)
    pub challenge_nonce: [u8; 32],

    /// Client's signature over (identity + capabilities + nonce + timestamp + version)
    pub signature: Signature,

    /// Timestamp when message was created (Unix timestamp in seconds)
    /// Used for replay attack prevention
    pub timestamp: u64,

    /// Protocol version (UHP_VERSION = 2)
    /// Used for version negotiation and preventing downgrade attacks
    pub protocol_version: u8,

    /// Optional PQC handshake offer (Kyber1024 public key + Dilithium5 binding)
    /// Present when client supports post-quantum cryptography
    pub pqc_offer: Option<PqcHandshakeOffer>,
}

impl ClientHello {
    /// Create a new ClientHello message
    ///
    /// Takes full ZhtpIdentity for signing, but only stores public NodeIdentity fields.
    /// PQC state is discarded - use `new_with_pqc()` if you need the state.
    pub fn new(
        zhtp_identity: &ZhtpIdentity,
        capabilities: HandshakeCapabilities,
        ctx: &HandshakeContext,
    ) -> Result<Self> {
        let (hello, _pqc_state) = Self::new_with_pqc(zhtp_identity, capabilities, ctx)?;
        Ok(hello)
    }

    /// Create a new ClientHello with PQC state returned
    ///
    /// Functional core pattern: caller manages PQC state for later use.
    /// Returns (ClientHello, Option<PqcHandshakeState>) so caller can keep the secret key.
    pub fn new_with_pqc(
        zhtp_identity: &ZhtpIdentity,
        capabilities: HandshakeCapabilities,
        ctx: &HandshakeContext,
    ) -> Result<(Self, Option<PqcHandshakeState>)> {
        ctx.require_channel_binding()?;
        let mut challenge_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge_nonce);

        let timestamp = current_timestamp()?;
        let protocol_version = UHP_VERSION;
        let identity = NodeIdentity::from_zhtp_identity(zhtp_identity);

        let keypair = KeyPair {
            public_key: zhtp_identity.public_key.clone(),
            private_key: zhtp_identity.private_key.clone().ok_or_else(|| anyhow!("Identity missing private key"))?,
        };

        let data = Self::data_to_sign(
            &identity,
            &capabilities,
            &ctx.domain,
            ctx.local_role,
            &ctx.channel_binding,
            &challenge_nonce,
            timestamp,
            protocol_version,
        )?;
        let signature = keypair.sign(&data)?;

        // Create PQC offer and preserve state for caller
        let (pqc_offer, pqc_state) = if capabilities.pqc_capability.is_enabled() {
            let (offer, state) = create_pqc_offer(capabilities.pqc_capability.clone())?;
            (Some(offer), Some(state))
        } else {
            (None, None)
        };

        Ok((Self {
            identity,
            capabilities,
            network_id: ctx.domain.network_id.clone(),
            protocol_id: ctx.domain.protocol_id.clone(),
            purpose: ctx.domain.purpose.clone(),
            role: ctx.local_role,
            channel_binding: ctx.channel_binding.clone(),
            challenge_nonce,
            signature,
            timestamp,
            protocol_version,
            pqc_offer,
        }, pqc_state))
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

        ctx.require_channel_binding()?;

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

        // 1. CRITICAL: Validate domain separation fields
        if self.network_id != ctx.domain.network_id
            || self.protocol_id != ctx.domain.protocol_id
            || self.purpose != ctx.domain.purpose
        {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_event(HandshakeEvent::InvalidProtocolVersionDetected, Some(metrics.clone()));
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::InvalidProtocolVersion,
                Some(metrics),
            );
            return Err(anyhow!("Domain separation mismatch"));
        }

        // 2. CRITICAL: Enforce declared role
        if self.role != ctx.peer_role {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::InvalidSignature,
                Some(metrics),
            );
            return Err(anyhow!("Unexpected peer role"));
        }

        // 3. CRITICAL: Verify channel binding
        if self.channel_binding != ctx.channel_binding {
            error!(
                client_cb_prefix = %hex::encode(&self.channel_binding.get(..8).unwrap_or(&[])),
                server_cb_prefix = %hex::encode(&ctx.channel_binding.get(..8).unwrap_or(&[])),
                client_cb_len = self.channel_binding.len(),
                server_cb_len = ctx.channel_binding.len(),
                "Channel binding MISMATCH - possible MITM or transport mismatch"
            );
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::InvalidSignature,
                Some(metrics),
            );
            return Err(anyhow!("Channel binding mismatch"));
        }

        // 4. CRITICAL: Verify NodeId derivation (prevent collision attacks)
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

        // 5. CRITICAL: Validate timestamp (prevent replay attacks)
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

        // 6. CRITICAL: Check nonce cache - prevent replay attacks (VULN-001 FIX)
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

        // 7. CRITICAL: Enforce required capabilities
        if !ctx.required_capabilities.is_empty() {
            let missing = ctx
                .required_capabilities
                .iter()
                .filter(|cap| !self.capabilities.protocols.contains(cap))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
                ctx.observer.on_failure(
                    HandshakeEvent::ClientHelloVerificationFailed,
                    FailureReason::InvalidSignature,
                    Some(metrics),
                );
                return Err(anyhow!("Missing required capabilities"));
            }
        }

        // 7b. CRITICAL: Enforce PQC capability (UHP v2 only)
        if self.capabilities.pqc_capability != PqcCapability::Kyber1024Dilithium5 {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::Other("PQC capability required (Kyber1024+Dilithium5)".to_string()),
                Some(metrics),
            );
            return Err(anyhow!("PQC capability required (Kyber1024+Dilithium5)"));
        }

        if self.pqc_offer.is_none() {
            let metrics = ctx.metrics_snapshot(timer.elapsed_micros(), self.protocol_version);
            ctx.observer.on_failure(
                HandshakeEvent::ClientHelloVerificationFailed,
                FailureReason::Other("Missing PQC offer in ClientHello".to_string()),
                Some(metrics),
            );
            return Err(anyhow!("Missing PQC offer in ClientHello"));
        }

        // 8. Verify signature includes all critical fields
        let data = Self::data_to_sign(
            &self.identity,
            &self.capabilities,
            &ctx.domain,
            self.role,
            &self.channel_binding,
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
        domain: &HandshakeDomain,
        role: HandshakeRole,
        channel_binding: &[u8],
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

        // Domain separation fields
        append_len_prefixed(&mut data, domain.network_id.as_bytes());
        append_len_prefixed(&mut data, domain.protocol_id.as_bytes());
        append_len_prefixed(&mut data, domain.purpose.as_bytes());
        data.push(role.as_u8());
        append_len_prefixed(&mut data, channel_binding);

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

    /// Network identifier for domain separation
    pub network_id: String,

    /// Protocol identifier for domain separation
    pub protocol_id: String,

    /// Purpose string for handshake domain separation
    pub purpose: String,

    /// Declared server role
    pub role: HandshakeRole,

    /// Channel binding token for this transport session
    pub channel_binding: Vec<u8>,

    /// Response nonce for client to sign (32 bytes)
    pub response_nonce: [u8; 32],

    /// Server's signature over (client_challenge + server_identity + capabilities + timestamp + version)
    pub signature: Signature,

    /// Negotiated session capabilities
    pub negotiated: NegotiatedCapabilities,

    /// Timestamp when message was created (Unix timestamp in seconds)
    /// Used for replay attack prevention
    pub timestamp: u64,

    /// Protocol version (UHP_VERSION = 2)
    /// Used for version negotiation
    pub protocol_version: u8,

    /// Optional PQC handshake offer from server
    /// Present when server supports post-quantum cryptography and client requested it
    pub pqc_offer: Option<PqcHandshakeOffer>,
}

impl ServerHello {
    /// Create a new ServerHello message
    ///
    /// Takes full ZhtpIdentity for signing, but only stores public NodeIdentity fields.
    /// PQC state is discarded - use `new_with_pqc()` if you need the state.
    pub fn new(
        zhtp_identity: &ZhtpIdentity,
        capabilities: HandshakeCapabilities,
        client_hello: &ClientHello,
        client_hello_hash: &[u8; 32],
        ctx: &HandshakeContext,
    ) -> Result<Self> {
        let (hello, _pqc_state) = Self::new_with_pqc(
            zhtp_identity,
            capabilities,
            client_hello,
            client_hello_hash,
            ctx,
        )?;
        Ok(hello)
    }

    /// Create a new ServerHello with PQC state returned
    ///
    /// Functional core pattern: caller manages PQC state for later decapsulation.
    /// Returns (ServerHello, Option<PqcHandshakeState>) so caller can keep the secret key.
    pub fn new_with_pqc(
        zhtp_identity: &ZhtpIdentity,
        capabilities: HandshakeCapabilities,
        client_hello: &ClientHello,
        client_hello_hash: &[u8; 32],
        ctx: &HandshakeContext,
    ) -> Result<(Self, Option<PqcHandshakeState>)> {
        ctx.require_channel_binding()?;
        let mut response_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut response_nonce);

        let timestamp = current_timestamp()?;
        let protocol_version = UHP_VERSION;
        let negotiated = capabilities.negotiate(&client_hello.capabilities);
        let identity = NodeIdentity::from_zhtp_identity(zhtp_identity);

        if negotiated.pqc_capability != PqcCapability::Kyber1024Dilithium5 {
            return Err(anyhow!("UHP v2 requires Kyber1024+Dilithium5"));
        }

        let keypair = KeyPair {
            public_key: zhtp_identity.public_key.clone(),
            private_key: zhtp_identity.private_key.clone().ok_or_else(|| anyhow!("Identity missing private key"))?,
        };

        let data = Self::data_to_sign(
            &client_hello.challenge_nonce,
            client_hello_hash,
            &identity,
            &capabilities,
            &ctx.domain,
            ctx.local_role,
            &ctx.channel_binding,
            timestamp,
            protocol_version,
        )?;
        let signature = keypair.sign(&data)?;

        // Create PQC offer and preserve state for caller
        let (pqc_offer, pqc_state) = if negotiated.pqc_capability.is_enabled() {
            let (offer, state) = create_pqc_offer(negotiated.pqc_capability.clone())?;
            (Some(offer), Some(state))
        } else {
            (None, None)
        };

        Ok((Self {
            identity,
            capabilities,
            network_id: ctx.domain.network_id.clone(),
            protocol_id: ctx.domain.protocol_id.clone(),
            purpose: ctx.domain.purpose.clone(),
            role: ctx.local_role,
            channel_binding: ctx.channel_binding.clone(),
            response_nonce,
            signature,
            negotiated,
            timestamp,
            protocol_version,
            pqc_offer,
        }, pqc_state))
    }

    /// Verify the server's signature
    ///
    /// SECURITY: Enforces NodeId verification, timestamp validation, protocol version check,
    /// and nonce replay detection.
    ///
    /// **VULN-001 FIX:** Uses nonce_cache for replay attack prevention.
    /// **FINDING 2 FIX:** Uses HandshakeContext to eliminate parameter threading.
    pub fn verify_signature(
        &self,
        client_nonce: &[u8; 32],
        client_hello_hash: &[u8; 32],
        ctx: &HandshakeContext,
    ) -> Result<()> {
        ctx.require_channel_binding()?;

        // 0. CRITICAL: Validate protocol version (VULN-004 FIX)
        validate_protocol_version(self.protocol_version)?;

        // 1. CRITICAL: Validate domain separation fields
        if self.network_id != ctx.domain.network_id
            || self.protocol_id != ctx.domain.protocol_id
            || self.purpose != ctx.domain.purpose
        {
            return Err(anyhow!("Domain separation mismatch"));
        }

        // 2. CRITICAL: Enforce declared role
        if self.role != ctx.peer_role {
            return Err(anyhow!("Unexpected peer role"));
        }

        // 3. CRITICAL: Verify channel binding
        if self.channel_binding != ctx.channel_binding {
            return Err(anyhow!("Channel binding mismatch"));
        }

        // 4. CRITICAL: Verify NodeId derivation
        self.identity.verify_node_id()?;

        // 5. CRITICAL: Validate timestamp
        validate_timestamp(self.timestamp, &ctx.timestamp_config)?;

        // 6. CRITICAL: Check nonce cache - prevent replay attacks (VULN-001 FIX)
        ctx.nonce_cache.check_and_store(&self.response_nonce, self.timestamp)?;

        // 7. CRITICAL: Enforce required capabilities
        if !ctx.required_capabilities.is_empty() {
            let missing = ctx
                .required_capabilities
                .iter()
                .filter(|cap| !self.capabilities.protocols.contains(cap))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                return Err(anyhow!("Missing required capabilities"));
            }
        }

        // 7b. CRITICAL: Enforce PQC capability (UHP v2 only)
        if self.negotiated.pqc_capability != PqcCapability::Kyber1024Dilithium5 {
            return Err(anyhow!("PQC capability required (Kyber1024+Dilithium5)"));
        }

        if self.pqc_offer.is_none() {
            return Err(anyhow!("Missing PQC offer in ServerHello"));
        }

        // 8. Verify signature includes all critical fields
        let data = Self::data_to_sign(
            client_nonce,
            client_hello_hash,
            &self.identity,
            &self.capabilities,
            &ctx.domain,
            self.role,
            &self.channel_binding,
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
    /// SECURITY: Includes client nonce, client transcript hash, timestamp, and version
    fn data_to_sign(
        client_nonce: &[u8; 32],
        client_hello_hash: &[u8; 32],
        identity: &NodeIdentity,
        capabilities: &HandshakeCapabilities,
        domain: &HandshakeDomain,
        role: HandshakeRole,
        channel_binding: &[u8],
        timestamp: u64,
        protocol_version: u8,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        // Message type for context binding
        data.push(0x02); // MessageType::ServerHello

        // Client's challenge nonce (proves we received ClientHello)
        // and transcript hash for binding to prior messages
        data.extend_from_slice(client_nonce);
        data.extend_from_slice(client_hello_hash);

        // Server identity and capabilities
        data.extend_from_slice(identity.node_id.as_bytes());
        data.extend_from_slice(bincode::serialize(capabilities)?.as_slice());

        // Domain separation fields
        append_len_prefixed(&mut data, domain.network_id.as_bytes());
        append_len_prefixed(&mut data, domain.protocol_id.as_bytes());
        append_len_prefixed(&mut data, domain.purpose.as_bytes());
        data.push(role.as_u8());
        append_len_prefixed(&mut data, channel_binding);

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

    /// Network identifier for domain separation
    pub network_id: String,

    /// Protocol identifier for domain separation
    pub protocol_id: String,

    /// Purpose string for handshake domain separation
    pub purpose: String,

    /// Declared client role
    pub role: HandshakeRole,

    /// Channel binding token for this transport session
    pub channel_binding: Vec<u8>,

    /// Timestamp when ClientFinish was created
    pub timestamp: u64,

    /// Protocol version
    pub protocol_version: u8,

    /// Optional session parameters
    pub session_params: Option<Vec<u8>>,

    /// Optional Kyber1024 ciphertext (encapsulated shared secret for PQC)
    /// Present when PQC was negotiated and client encapsulates to server's PQC offer
    pub pqc_ciphertext: Option<Vec<u8>>,
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
    /// PQC shared secret is discarded - use `new_with_pqc()` if you need it.
    pub fn new(
        server_hello: &ServerHello,
        client_hello: &ClientHello,
        client_hello_hash: &[u8; 32],
        transcript_hash: &[u8; 32],
        keypair: &KeyPair,
        ctx: &HandshakeContext,
    ) -> Result<Self> {
        let (finish, _pqc_secret) = Self::new_with_pqc(
            server_hello,
            client_hello,
            client_hello_hash,
            transcript_hash,
            keypair,
            ctx,
        )?;
        Ok(finish)
    }

    /// Create a new ClientFinish with PQC shared secret returned
    ///
    /// Functional core pattern: returns (ClientFinish, Option<[u8; 32]>) so caller can use
    /// the PQC shared secret for hybrid session key derivation.
    pub fn new_with_pqc(
        server_hello: &ServerHello,
        client_hello: &ClientHello,
        client_hello_hash: &[u8; 32],
        transcript_hash: &[u8; 32],
        keypair: &KeyPair,
        ctx: &HandshakeContext,
    ) -> Result<(Self, Option<[u8; 32]>)> {
        ctx.require_channel_binding()?;
        if server_hello.negotiated.pqc_capability != PqcCapability::Kyber1024Dilithium5 {
            return Err(anyhow!("UHP v2 requires Kyber1024+Dilithium5"));
        }

        if server_hello.pqc_offer.is_none() {
            return Err(anyhow!("Missing PQC offer in ServerHello"));
        }

        // === MUTUAL AUTHENTICATION: Verify server before completing handshake ===
        server_hello.identity.verify_node_id()
            .map_err(|e| anyhow!("Server NodeId verification failed: {}", e))?;

        validate_timestamp(server_hello.timestamp, &ctx.timestamp_config)
            .map_err(|e| anyhow!("Server timestamp validation failed: {}", e))?;

        server_hello.verify_signature(&client_hello.challenge_nonce, client_hello_hash, ctx)
            .map_err(|e| anyhow!("Server signature verification failed: {}", e))?;

        // === Server verified! Now complete handshake ===
        let timestamp = current_timestamp()?;
        let protocol_version = UHP_VERSION;

        let data = Self::data_to_sign(
            &server_hello.response_nonce,
            transcript_hash,
            &ctx.domain,
            ctx.local_role,
            &ctx.channel_binding,
            timestamp,
            protocol_version,
        )?;
        let signature = keypair.sign(&data)?;

        // Encapsulate to server's PQC offer and preserve shared secret
        let (pqc_ciphertext, pqc_shared_secret) = if let Some(ref pqc_offer) = server_hello.pqc_offer {
            verify_pqc_offer(pqc_offer)?;
            let (ciphertext, shared_secret) = encapsulate_pqc(pqc_offer)?;
            (Some(ciphertext), Some(shared_secret))
        } else {
            (None, None)
        };

        Ok((Self {
            signature,
            network_id: ctx.domain.network_id.clone(),
            protocol_id: ctx.domain.protocol_id.clone(),
            purpose: ctx.domain.purpose.clone(),
            role: ctx.local_role,
            channel_binding: ctx.channel_binding.clone(),
            timestamp,
            protocol_version,
            session_params: None,
            pqc_ciphertext,
        }, pqc_shared_secret))
    }

    /// Verify client's signature on server nonce
    pub fn verify_signature(
        &self,
        server_nonce: &[u8; 32],
        transcript_hash: &[u8; 32],
        client_pubkey: &PublicKey,
    ) -> Result<()> {
        // 0. CRITICAL: Validate protocol version (VULN-004 FIX)
        validate_protocol_version(self.protocol_version)?;

        // 1. Validate timestamp
        validate_timestamp(self.timestamp, &TimestampConfig::default())?;

        // 2. Verify signature
        let domain = HandshakeDomain {
            network_id: self.network_id.clone(),
            protocol_id: self.protocol_id.clone(),
            purpose: self.purpose.clone(),
        };
        let data = Self::data_to_sign(
            server_nonce,
            transcript_hash,
            &domain,
            self.role,
            &self.channel_binding,
            self.timestamp,
            self.protocol_version,
        )?;

        if client_pubkey.verify(&data, &self.signature)? {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }

    /// Verify client's signature on server nonce with handshake context
    pub fn verify_signature_with_context(
        &self,
        server_nonce: &[u8; 32],
        transcript_hash: &[u8; 32],
        client_pubkey: &PublicKey,
        ctx: &HandshakeContext,
    ) -> Result<()> {
        ctx.require_channel_binding()?;

        validate_protocol_version(self.protocol_version)?;

        if self.network_id != ctx.domain.network_id
            || self.protocol_id != ctx.domain.protocol_id
            || self.purpose != ctx.domain.purpose
        {
            return Err(anyhow!("Domain separation mismatch"));
        }

        if self.role != ctx.peer_role {
            return Err(anyhow!("Unexpected peer role"));
        }

        if self.channel_binding != ctx.channel_binding {
            return Err(anyhow!("Channel binding mismatch"));
        }

        // 1. Validate timestamp
        validate_timestamp(self.timestamp, &TimestampConfig::default())?;

        // 2. Verify signature
        let data = Self::data_to_sign(
            server_nonce,
            transcript_hash,
            &ctx.domain,
            self.role,
            &self.channel_binding,
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
        transcript_hash: &[u8; 32],
        domain: &HandshakeDomain,
        role: HandshakeRole,
        channel_binding: &[u8],
        timestamp: u64,
        protocol_version: u8,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.push(0x03); // MessageType::ClientFinish for context binding
        data.extend_from_slice(server_nonce);
        data.extend_from_slice(transcript_hash); // binds transcript so far
        append_len_prefixed(&mut data, domain.network_id.as_bytes());
        append_len_prefixed(&mut data, domain.protocol_id.as_bytes());
        append_len_prefixed(&mut data, domain.purpose.as_bytes());
        data.push(role.as_u8());
        append_len_prefixed(&mut data, channel_binding);
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

/// Session metadata verified during handshake
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeSessionInfo {
    pub network_id: String,
    pub protocol_id: String,
    pub purpose: String,
    pub client_role: HandshakeRole,
    pub server_role: HandshakeRole,
    pub channel_binding: Vec<u8>,
}

/// Verified peer identity and negotiated capabilities
#[derive(Debug, Clone)]
pub struct VerifiedPeer {
    pub identity: NodeIdentity,
    pub capabilities: NegotiatedCapabilities,
    pub session_info: HandshakeSessionInfo,
}

impl VerifiedPeer {
    pub fn new(
        identity: NodeIdentity,
        capabilities: NegotiatedCapabilities,
        session_info: HandshakeSessionInfo,
    ) -> Self {
        Self {
            identity,
            capabilities,
            session_info,
        }
    }
}

impl HandshakeSessionInfo {
    pub fn from_messages(client_hello: &ClientHello, server_hello: &ServerHello) -> Result<Self> {
        if client_hello.network_id != server_hello.network_id
            || client_hello.protocol_id != server_hello.protocol_id
            || client_hello.purpose != server_hello.purpose
        {
            return Err(anyhow!("Handshake domain mismatch"));
        }

        if client_hello.channel_binding != server_hello.channel_binding {
            return Err(anyhow!("Handshake channel binding mismatch"));
        }

        if client_hello.role != HandshakeRole::Client || server_hello.role != HandshakeRole::Server {
            return Err(anyhow!("Handshake role mismatch"));
        }

        Ok(Self {
            network_id: client_hello.network_id.clone(),
            protocol_id: client_hello.protocol_id.clone(),
            purpose: client_hello.purpose.clone(),
            client_role: client_hello.role,
            server_role: server_hello.role,
            channel_binding: client_hello.channel_binding.clone(),
        })
    }
}

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

    /// Session identifier (32 bytes, UHP v2)
    pub session_id: [u8; 32],

    /// Handshake transcript hash (SHA3-256 of all handshake messages)
    /// Used as salt for v2 key derivation: HKDF(session_key, handshake_hash, label)
    pub handshake_hash: [u8; 32],

    /// Timestamp when handshake completed
    pub completed_at: u64,

    /// Whether PQC hybrid mode was used
    pub pqc_hybrid_enabled: bool,

    /// Verified session metadata
    pub session_info: HandshakeSessionInfo,

    /// Protocol version used (1 or 2)
    pub protocol_version: u8,
}

impl HandshakeResult {
    /// Create a new handshake result with PQC hybrid key derivation
    ///
    /// When `pqc_shared_secret` is provided, the session key is derived using
    /// HKDF with both the classical nonces and the PQC shared secret, providing
    /// hybrid post-quantum security.
    ///
    /// # Arguments
    /// * `client_hello_timestamp` - Timestamp from ClientHello message (MUST be same on both sides)
    /// * `pqc_shared_secret` - Optional PQC shared secret for hybrid key derivation
    /// * `transcript_hash` - Handshake transcript hash for v2 key derivation
    pub fn new_with_pqc(
        peer_identity: NodeIdentity,
        capabilities: NegotiatedCapabilities,
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
        client_did: &str,
        server_did: &str,
        client_hello_timestamp: u64,
        session_info: &HandshakeSessionInfo,
        pqc_shared_secret: Option<&[u8; 32]>,
        transcript_hash: [u8; 32],
    ) -> Result<Self> {
        // Build session context for HKDF domain separation
        // CRITICAL: Use ClientHello timestamp (deterministic, agreed by both parties)
        let context = SessionContext {
            protocol_version: UHP_VERSION as u32,
            client_did: client_did.to_string(),
            server_did: server_did.to_string(),
            timestamp: client_hello_timestamp, // VULN-003 FIX: Deterministic timestamp
            network_id: session_info.network_id.clone(),
            protocol_id: session_info.protocol_id.clone(),
            purpose: session_info.purpose.clone(),
            client_role: session_info.client_role.as_u8(),
            server_role: session_info.server_role.as_u8(),
            channel_binding: session_info.channel_binding.clone(),
        };

        // Derive session key using HKDF (NIST SP 800-108 compliant)
        let classical_key = derive_session_key_hkdf(client_nonce, server_nonce, &context)?;

        // If PQC shared secret is provided, derive hybrid key
        let pqc_secret = pqc_shared_secret
            .ok_or_else(|| anyhow!("Missing PQC shared secret for UHP v2"))?;
        let hybrid_key = derive_hybrid_session_key(pqc_secret, &classical_key)?;
        let (session_key, pqc_hybrid_enabled) = (hybrid_key, true);

        // Generate 32-byte session ID (UHP v2)
        let session_id = Self::derive_session_id(&session_key, client_nonce, server_nonce);

        let handshake_hash = transcript_hash;
        let protocol_version = 2;

        Ok(Self {
            peer_identity,
            capabilities,
            session_key,
            session_id,
            handshake_hash,
            completed_at: current_timestamp()?, // Completion time (for logging only)
            pqc_hybrid_enabled,
            session_info: session_info.clone(),
            protocol_version,
        })
    }

    /// Create v2 handshake result with explicit transcript hash
    ///
    /// UHP v2 requires the transcript hash for proper key derivation.
    /// The transcript hash is SHA3-256(client_hello || server_hello || client_finish).
    pub fn new_v2(
        peer_identity: NodeIdentity,
        capabilities: NegotiatedCapabilities,
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
        client_did: &str,
        server_did: &str,
        client_hello_timestamp: u64,
        session_info: &HandshakeSessionInfo,
        pqc_shared_secret: Option<&[u8; 32]>,
        transcript_hash: [u8; 32],
    ) -> Result<Self> {
        Self::new_with_pqc(
            peer_identity,
            capabilities,
            client_nonce,
            server_nonce,
            client_did,
            server_did,
            client_hello_timestamp,
            session_info,
            pqc_shared_secret,
            transcript_hash,
        )
    }

    /// Derive 32-byte session ID from session key and nonces
    fn derive_session_id(session_key: &[u8; 32], client_nonce: &[u8; 32], server_nonce: &[u8; 32]) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(b"zhtp/v2/session_id");
        hasher.update(session_key);
        hasher.update(client_nonce);
        hasher.update(server_nonce);
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    pub fn verified_peer(&self) -> VerifiedPeer {
        VerifiedPeer::new(
            self.peer_identity.clone(),
            self.capabilities.clone(),
            self.session_info.clone(),
        )
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
        assert_eq!(UHP_VERSION, 2);
        assert_eq!(UHP_VERSION_STRING, "UHP/2.0");
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
            pqc_capability: PqcCapability::Kyber1024Dilithium5,
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
            pqc_capability: PqcCapability::Kyber1024Dilithium5,
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
        
        // Should negotiate PQC to Kyber1024+Dilithium5 (both support it)
        assert_eq!(negotiated.pqc_capability, PqcCapability::Kyber1024Dilithium5);
        
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
        
        let ctx = HandshakeContext::new_test()
            .with_roles(HandshakeRole::Client, HandshakeRole::Server);
        let client_hello = ClientHello::new(&identity, capabilities, &ctx)?;
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

        let base_ctx = HandshakeContext::new_test();
        let client_ctx = base_ctx.with_roles(HandshakeRole::Client, HandshakeRole::Server);
        let server_ctx = base_ctx.with_roles(HandshakeRole::Server, HandshakeRole::Client);
        let client_hello = ClientHello::new(&identity, capabilities, &client_ctx)?;

        // Signature should verify
        client_hello.verify_signature(&server_ctx)?;

        Ok(())
    }

    #[test]
    fn test_domain_mismatch_rejected() -> Result<()> {
        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "domain-test-device",
            None,
        )?;

        let base_ctx = HandshakeContext::new_test()
            .with_channel_binding(vec![9u8; 32]);
        let client_ctx = base_ctx.with_roles(HandshakeRole::Client, HandshakeRole::Server);
        let server_ctx = base_ctx.with_roles(HandshakeRole::Server, HandshakeRole::Client);
        let client_hello = ClientHello::new(&identity, HandshakeCapabilities::default(), &client_ctx)?;

        let mismatched_ctx = server_ctx.with_domain(HandshakeDomain {
            network_id: "zhtp-testnet".to_string(),
            protocol_id: DEFAULT_HANDSHAKE_PROTOCOL_ID.to_string(),
            purpose: DEFAULT_HANDSHAKE_PURPOSE.to_string(),
        });

        assert!(client_hello.verify_signature(&mismatched_ctx).is_err());
        Ok(())
    }

    #[test]
    fn test_role_mismatch_rejected() -> Result<()> {
        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "role-test-device",
            None,
        )?;

        let base_ctx = HandshakeContext::new_test()
            .with_channel_binding(vec![7u8; 32]);
        let client_ctx = base_ctx.with_roles(HandshakeRole::Client, HandshakeRole::Server);
        let server_ctx = base_ctx.with_roles(HandshakeRole::Server, HandshakeRole::Client);
        let client_hello = ClientHello::new(&identity, HandshakeCapabilities::default(), &client_ctx)?;

        let wrong_role_ctx = server_ctx.with_roles(HandshakeRole::Server, HandshakeRole::Server);
        assert!(client_hello.verify_signature(&wrong_role_ctx).is_err());
        Ok(())
    }

    #[test]
    fn test_channel_binding_mismatch_rejected() -> Result<()> {
        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "binding-test-device",
            None,
        )?;

        let base_ctx = HandshakeContext::new_test()
            .with_channel_binding(vec![1u8; 32]);
        let client_ctx = base_ctx.with_roles(HandshakeRole::Client, HandshakeRole::Server);
        let server_ctx = base_ctx.with_roles(HandshakeRole::Server, HandshakeRole::Client);
        let client_hello = ClientHello::new(&identity, HandshakeCapabilities::default(), &client_ctx)?;

        let mismatched_binding = server_ctx.with_channel_binding(vec![2u8; 32]);
        assert!(client_hello.verify_signature(&mismatched_binding).is_err());
        Ok(())
    }

    #[test]
    fn test_required_capability_rejected() -> Result<()> {
        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "cap-test-device",
            None,
        )?;

        let base_ctx = HandshakeContext::new_test()
            .with_channel_binding(vec![3u8; 32])
            .with_required_capabilities(vec!["quic".to_string()]);
        let client_ctx = base_ctx.with_roles(HandshakeRole::Client, HandshakeRole::Server);
        let server_ctx = base_ctx.with_roles(HandshakeRole::Server, HandshakeRole::Client);

        let capabilities = HandshakeCapabilities {
            protocols: vec!["tcp".to_string()],
            ..HandshakeCapabilities::default()
        };
        let client_hello = ClientHello::new(&identity, capabilities, &client_ctx)?;

        assert!(client_hello.verify_signature(&server_ctx).is_err());
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
            network_id: DEFAULT_HANDSHAKE_NETWORK_ID.to_string(),
            protocol_id: DEFAULT_HANDSHAKE_PROTOCOL_ID.to_string(),
            purpose: DEFAULT_HANDSHAKE_PURPOSE.to_string(),
            client_role: HandshakeRole::Client.as_u8(),
            server_role: HandshakeRole::Server.as_u8(),
            channel_binding: vec![0u8; 32],
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
        assert_eq!(minimal.pqc_capability, PqcCapability::Kyber1024Dilithium5);
        assert!(!minimal.dht_capable);
    }
    
    #[test]
    fn test_full_featured_capabilities() {
        let full = HandshakeCapabilities::full_featured();

        assert!(full.protocols.len() >= 5);
        assert!(full.max_throughput >= 100_000_000);
        assert!(full.max_message_size >= 10_000_000);
        assert_eq!(full.pqc_capability, PqcCapability::Kyber1024Dilithium5);
        assert!(full.dht_capable);
        assert!(full.relay_capable);
    }

    #[test]
    fn test_pqc_capability_negotiation() {
        use PqcCapability::*;
        
        // Both have full PQC -> full PQC
        let full1 = HandshakeCapabilities {
            pqc_capability: Kyber1024Dilithium5,
            ..HandshakeCapabilities::default()
        };
        let full2 = HandshakeCapabilities {
            pqc_capability: Kyber1024Dilithium5,
            ..HandshakeCapabilities::default()
        };
        let neg = full1.negotiate(&full2);
        assert_eq!(neg.pqc_capability, Kyber1024Dilithium5);
        
        // Full + Hybrid -> Hybrid (fallback)
        let hybrid = HandshakeCapabilities {
            pqc_capability: HybridEd25519Dilithium5,
            ..HandshakeCapabilities::default()
        };
        let neg = full1.negotiate(&hybrid);
        assert_eq!(neg.pqc_capability, HybridEd25519Dilithium5);
        
        // Hybrid + None -> None (no common support)
        let none = HandshakeCapabilities {
            pqc_capability: None,
            ..HandshakeCapabilities::default()
        };
        let neg = hybrid.negotiate(&none);
        assert_eq!(neg.pqc_capability, None);
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
        let base_ctx = HandshakeContext::new_test();
        let client_ctx = base_ctx.with_roles(HandshakeRole::Client, HandshakeRole::Server);
        let server_ctx = base_ctx.with_roles(HandshakeRole::Server, HandshakeRole::Client);

        // Step 1: Client sends ClientHello
        let client_capabilities = HandshakeCapabilities::default();
        let client_hello = ClientHello::new(&client_identity, client_capabilities, &client_ctx)?;
        let client_hello_msg = HandshakeMessage::new(HandshakePayload::ClientHello(client_hello.clone()));
        let client_hello_bytes = client_hello_msg.to_bytes()?;
        let client_hello_hash = compute_transcript_hash(&[&client_hello_bytes]);

        // Server verifies ClientHello
        client_hello.verify_signature(&server_ctx)?;

        // Step 2: Server sends ServerHello
        let server_capabilities = HandshakeCapabilities::default();
        let (server_hello, server_pqc_state) = ServerHello::new_with_pqc(
            &server_identity,
            server_capabilities,
            &client_hello,
            &client_hello_hash,
            &server_ctx,
        )?;
        let server_hello_msg = HandshakeMessage::new(HandshakePayload::ServerHello(server_hello.clone()));
        let server_hello_bytes = server_hello_msg.to_bytes()?;
        let pre_finish_hash = compute_transcript_hash(&[&client_hello_bytes, &server_hello_bytes]);

        // Step 3: Client sends ClientFinish (includes mutual authentication of server)
        let client_keypair = KeyPair {
            public_key: client_identity.public_key.clone(),
            private_key: client_identity.private_key.clone().unwrap(),
        };

        let (client_finish, client_pqc_secret) = ClientFinish::new_with_pqc(
            &server_hello,
            &client_hello,
            &client_hello_hash,
            &pre_finish_hash,
            &client_keypair,
            &client_ctx,
        )?;
        let client_finish_msg = HandshakeMessage::new(HandshakePayload::ClientFinish(client_finish.clone()));
        let client_finish_bytes = client_finish_msg.to_bytes()?;

        // Server verifies ClientFinish
        client_finish.verify_signature_with_context(
            &server_hello.response_nonce,
            &pre_finish_hash,
            &client_hello.identity.public_key,
            &server_ctx,
        )?;

        // Step 4: Both sides derive session key
        let session_info = HandshakeSessionInfo::from_messages(&client_hello, &server_hello)?;
        let transcript_hash = compute_transcript_hash(&[
            &client_hello_bytes,
            &server_hello_bytes,
            &client_finish_bytes,
        ]);

        let server_pqc_secret = match (&client_finish.pqc_ciphertext, &server_pqc_state) {
            (Some(ciphertext), Some(state)) => Some(decapsulate_pqc(ciphertext, state)?),
            _ => None,
        };

        let client_session = HandshakeResult::new_with_pqc(
            server_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_identity.did,
            &server_identity.did,
            client_hello.timestamp,
            &session_info,
            client_pqc_secret.as_ref(),
            transcript_hash,
        )?;

        let server_session = HandshakeResult::new_with_pqc(
            client_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_identity.did,
            &server_identity.did,
            client_hello.timestamp,
            &session_info,
            server_pqc_secret.as_ref(),
            transcript_hash,
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
        let epoch = crate::handshake::NetworkEpoch::from_chain_id(0);
        let ctx = HandshakeContext::new(NonceCache::new_test(60, 10000, epoch))
            .with_channel_binding(vec![1u8; 32]);

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
                    let client_ctx = ctx.with_roles(HandshakeRole::Client, HandshakeRole::Server);
                    let server_ctx = ctx.with_roles(HandshakeRole::Server, HandshakeRole::Client);

                    let client_hello = ClientHello::new(&client_identity, HandshakeCapabilities::default(), &client_ctx)?;
                    let client_hello_msg = HandshakeMessage::new(HandshakePayload::ClientHello(client_hello.clone()));
                    let client_hello_bytes = client_hello_msg.to_bytes()?;
                    let client_hello_hash = compute_transcript_hash(&[&client_hello_bytes]);

                    client_hello.verify_signature(&server_ctx)?;

                    let (server_hello, _pqc_state) = ServerHello::new_with_pqc(
                        &server_identity,
                        HandshakeCapabilities::default(),
                        &client_hello,
                        &client_hello_hash,
                        &server_ctx,
                    )?;
                    let server_hello_msg = HandshakeMessage::new(HandshakePayload::ServerHello(server_hello.clone()));
                    let server_hello_bytes = server_hello_msg.to_bytes()?;
                    let pre_finish_hash = compute_transcript_hash(&[&client_hello_bytes, &server_hello_bytes]);

                    let client_keypair = KeyPair {
                        public_key: client_identity.public_key.clone(),
                        private_key: client_identity.private_key.clone().unwrap(),
                    };

                    let _client_finish = ClientFinish::new_with_pqc(
                        &server_hello,
                        &client_hello,
                        &client_hello_hash,
                        &pre_finish_hash,
                        &client_keypair,
                        &client_ctx,
                    )?;

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
        let base_ctx = HandshakeContext::new_test();
        let client_ctx = base_ctx.with_roles(HandshakeRole::Client, HandshakeRole::Server);
        let server_ctx = base_ctx.with_roles(HandshakeRole::Server, HandshakeRole::Client);

        let identity = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "test-device",
            None,
        )?;

        // Create ClientHello
        let client_hello = ClientHello::new(&identity, HandshakeCapabilities::default(), &client_ctx)?;

        // First verification should succeed
        assert!(client_hello.verify_signature(&server_ctx).is_ok());

        // Second verification with same nonce should fail (replay attack detected)
        let result = client_hello.verify_signature(&server_ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Replay detected"));

        Ok(())
    }
}
