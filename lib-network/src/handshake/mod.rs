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

/// UHP Protocol Version
pub const UHP_VERSION: u8 = 1;

/// Protocol version string for compatibility
pub const UHP_VERSION_STRING: &str = "UHP/1.0";

/// Maximum supported protocol version (for future compatibility)
pub const MAX_SUPPORTED_VERSION: u8 = 1;

/// Minimum supported protocol version (for backwards compatibility)
pub const MIN_SUPPORTED_VERSION: u8 = 1;

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
    pub fn verify_node_id(&self) -> Result<()> {
        let expected = NodeId::from_did_device(&self.did, &self.device_id)?;
        if self.node_id.as_bytes() != expected.as_bytes() {
            return Err(anyhow!(
                "NodeId mismatch: expected {} but got {}",
                expected.to_hex(),
                self.node_id.to_hex()
            ));
        }
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
    
    /// Client's signature over (identity + capabilities + nonce)
    pub signature: Signature,
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
        
        // Extract public-only identity for network transmission
        let identity = NodeIdentity::from_zhtp_identity(zhtp_identity);
        
        // Create keypair from ZhtpIdentity's keys for signing
        let keypair = KeyPair {
            public_key: zhtp_identity.public_key.clone(),
            private_key: zhtp_identity.private_key.clone().ok_or_else(|| anyhow!("Identity missing private key"))?,
        };
        
        // Sign the hello message
        let data = Self::data_to_sign(&identity, &capabilities, &challenge_nonce)?;
        let signature = keypair.sign(&data)?;
        
        Ok(Self {
            identity,
            capabilities,
            challenge_nonce,
            signature,
        })
    }
    
    /// Verify the signature on this ClientHello
    pub fn verify_signature(&self) -> Result<()> {
        let data = Self::data_to_sign(&self.identity, &self.capabilities, &self.challenge_nonce)?;
        if self.identity.public_key.verify(&data, &self.signature)? {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }
    
    fn data_to_sign(
        identity: &NodeIdentity,
        capabilities: &HandshakeCapabilities,
        nonce: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(identity.node_id.as_bytes());
        data.extend_from_slice(bincode::serialize(capabilities)?.as_slice());
        data.extend_from_slice(nonce);
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
    
    /// Server's signature over (client_challenge + server_identity + capabilities)
    pub signature: Signature,
    
    /// Negotiated session capabilities
    pub negotiated: NegotiatedCapabilities,
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
        
        let negotiated = capabilities.negotiate(&client_hello.capabilities);
        
        // Extract public-only identity for network transmission
        let identity = NodeIdentity::from_zhtp_identity(zhtp_identity);
        
        // Create keypair from ZhtpIdentity's keys for signing
        let keypair = KeyPair {
            public_key: zhtp_identity.public_key.clone(),
            private_key: zhtp_identity.private_key.clone().ok_or_else(|| anyhow!("Identity missing private key"))?,
        };
        
        // Sign: client's nonce + our identity + our capabilities
        let data = Self::data_to_sign(
            &client_hello.challenge_nonce,
            &identity,
            &capabilities,
        )?;
        let signature = keypair.sign(&data)?;
        
        Ok(Self {
            identity,
            capabilities,
            response_nonce,
            signature,
            negotiated,
        })
    }
    
    /// Verify the server's signature
    pub fn verify_signature(&self, client_nonce: &[u8; 32]) -> Result<()> {
        let data = Self::data_to_sign(client_nonce, &self.identity, &self.capabilities)?;
        if self.identity.public_key.verify(&data, &self.signature)? {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }
    
    fn data_to_sign(
        client_nonce: &[u8; 32],
        identity: &NodeIdentity,
        capabilities: &HandshakeCapabilities,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(client_nonce);
        data.extend_from_slice(identity.node_id.as_bytes());
        data.extend_from_slice(bincode::serialize(capabilities)?.as_slice());
        Ok(data)
    }
}

/// ClientFinish: Client confirms handshake completion
///
/// Client signs the server's response nonce to prove receipt and agreement.
/// After this message, the secure session is established.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFinish {
    /// Client's signature over server's response nonce
    pub signature: Signature,
    
    /// Optional session parameters
    pub session_params: Option<Vec<u8>>,
}

impl ClientFinish {
    /// Create a new ClientFinish message
    pub fn new(server_nonce: &[u8; 32], keypair: &KeyPair) -> Result<Self> {
        let signature = keypair.sign(server_nonce)?;
        
        Ok(Self {
            signature,
            session_params: None,
        })
    }
    
    /// Verify client's signature on server nonce
    pub fn verify_signature(&self, server_nonce: &[u8; 32], client_pubkey: &PublicKey) -> Result<()> {
        if client_pubkey.verify(server_nonce, &self.signature)? {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
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
    pub fn new(
        peer_identity: NodeIdentity,
        capabilities: NegotiatedCapabilities,
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
    ) -> Self {
        // Derive session key from both nonces
        let session_key = Self::derive_session_key(client_nonce, server_nonce);
        
        // Generate session ID
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&session_key[..16]);
        
        Self {
            peer_identity,
            capabilities,
            session_key,
            session_id,
            completed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Derive session key from handshake nonces using Blake3 KDF
    fn derive_session_key(client_nonce: &[u8; 32], server_nonce: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(client_nonce);
        data.extend_from_slice(server_nonce);
        lib_crypto::hash_blake3(&data)
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
        
        // Signature should verify
        client_hello.verify_signature()?;
        
        Ok(())
    }
    
    #[test]
    fn test_session_key_derivation() {
        let client_nonce = [0x42u8; 32];
        let server_nonce = [0x84u8; 32];
        
        let key1 = HandshakeResult::derive_session_key(&client_nonce, &server_nonce);
        let key2 = HandshakeResult::derive_session_key(&client_nonce, &server_nonce);
        
        // Should be deterministic
        assert_eq!(key1, key2);
        
        // Should change if nonces change
        let different_client = [0x43u8; 32];
        let key3 = HandshakeResult::derive_session_key(&different_client, &server_nonce);
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
}
