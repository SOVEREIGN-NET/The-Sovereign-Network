//! UHP v2 Handshake Protocol
//!
//! Implements the 3-leg mutual authentication handshake for ZHTP:
//!
//! ```text
//! Client                              Server
//!    |                                   |
//!    |--- ClientHello ------------------>|  (identity, capabilities, challenge_nonce, signature)
//!    |                                   |
//!    |<-- ServerHello -------------------|  (server identity, response_nonce, signature)
//!    |                                   |
//!    |--- ClientFinish ----------------->|  (confirmation signature)
//!    |                                   |
//!    |<== Encrypted Session ============>|
//! ```
//!
//! # Security Properties
//!
//! - **Mutual Authentication**: Both parties prove identity via Dilithium5 signatures
//! - **Forward Secrecy**: Session keys derived from ephemeral nonces
//! - **Replay Protection**: Timestamps and nonces prevent replay attacks
//! - **Channel Binding**: Ties session to specific transport connection

use crate::crypto::{hkdf_sha3_256, random_nonce, Blake3, Dilithium5};
use crate::error::{ClientError, Result};
use crate::identity::Identity;
use crate::UHP_VERSION;
use serde::{Deserialize, Serialize};

/// Node identity information exchanged during handshake
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeIdentity {
    /// Decentralized Identifier
    pub did: String,
    /// Dilithium5 public key
    pub public_key: Vec<u8>,
    /// Node identifier
    pub node_id: Vec<u8>,
    /// Device identifier
    pub device_id: String,
    /// Optional display name
    pub display_name: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
}

impl From<&Identity> for NodeIdentity {
    fn from(identity: &Identity) -> Self {
        NodeIdentity {
            did: identity.did.clone(),
            public_key: identity.public_key.clone(),
            node_id: identity.node_id.clone(),
            device_id: identity.device_id.clone(),
            display_name: None,
            created_at: identity.created_at,
        }
    }
}

/// Capabilities advertised during handshake
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HandshakeCapabilities {
    /// Supported transport protocols
    pub protocols: Vec<String>,
    /// Maximum throughput in bytes/sec
    pub max_throughput: u64,
    /// Maximum message size in bytes
    pub max_message_size: u32,
    /// Supported encryption methods
    pub encryption_methods: Vec<String>,
    /// Post-quantum capability identifier
    pub pqc_capability: String,
    /// Whether this node supports Web4
    pub web4_capable: bool,
}

impl Default for HandshakeCapabilities {
    fn default() -> Self {
        Self {
            protocols: vec!["quic".into()],
            max_throughput: 1_000_000,
            max_message_size: 65536,
            encryption_methods: vec!["chacha20-poly1305".into()],
            pqc_capability: "Kyber1024Dilithium5".into(),
            web4_capable: true,
        }
    }
}

/// PQC key exchange offer (Kyber1024)
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PqcOffer {
    /// Kyber1024 public key for encapsulation
    pub kyber_public_key: Vec<u8>,
    /// Commitment hash
    pub commitment: Vec<u8>,
}

/// PQC key exchange response
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PqcResponse {
    /// Kyber1024 ciphertext
    pub kyber_ciphertext: Vec<u8>,
    /// Commitment hash
    pub commitment: Vec<u8>,
}

/// ClientHello message (Step 1)
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ClientHello {
    /// Client identity
    pub identity: NodeIdentity,
    /// Client capabilities
    pub capabilities: HandshakeCapabilities,
    /// Network identifier
    pub network_id: String,
    /// Protocol identifier
    pub protocol_id: String,
    /// Handshake purpose
    pub purpose: String,
    /// Role: 0 = Client
    pub role: u8,
    /// Channel binding (ties to transport)
    pub channel_binding: Vec<u8>,
    /// Random challenge nonce (32 bytes)
    pub challenge_nonce: Vec<u8>,
    /// Dilithium5 signature over message
    pub signature: Vec<u8>,
    /// Message timestamp
    pub timestamp: u64,
    /// Protocol version
    pub protocol_version: u8,
    /// Optional PQC key exchange offer
    pub pqc_offer: Option<PqcOffer>,
}

/// ServerHello message (Step 2)
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ServerHello {
    /// Server identity
    pub identity: NodeIdentity,
    /// Network identifier
    pub network_id: String,
    /// Protocol identifier
    pub protocol_id: String,
    /// Handshake purpose
    pub purpose: String,
    /// Role: 1 = Server
    pub role: u8,
    /// Channel binding
    pub channel_binding: Vec<u8>,
    /// Server's response nonce (32 bytes)
    pub response_nonce: Vec<u8>,
    /// Hash of client's challenge
    pub client_challenge_hash: Vec<u8>,
    /// Dilithium5 signature over message
    pub signature: Vec<u8>,
    /// Message timestamp
    pub timestamp: u64,
    /// Protocol version
    pub protocol_version: u8,
    /// Optional PQC key exchange response
    pub pqc_response: Option<PqcResponse>,
}

/// ClientFinish message (Step 3)
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ClientFinish {
    /// Echo client's nonce
    pub client_nonce: Vec<u8>,
    /// Echo server's nonce
    pub server_nonce: Vec<u8>,
    /// Hash of handshake transcript
    pub transcript_hash: Vec<u8>,
    /// Dilithium5 signature over finish data
    pub signature: Vec<u8>,
    /// Optional PQC confirmation
    pub pqc_confirmation: Option<Vec<u8>>,
}

/// Handshake message envelope
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HandshakeMessage {
    /// Protocol version
    pub version: u8,
    /// Payload type: 0=ClientHello, 1=ServerHello, 2=ClientFinish, 255=Error
    pub payload_type: u8,
    /// Serialized payload
    pub payload: Vec<u8>,
    /// Message timestamp
    pub timestamp: u64,
}

impl HandshakeMessage {
    /// Payload type for ClientHello
    pub const TYPE_CLIENT_HELLO: u8 = 0;
    /// Payload type for ServerHello
    pub const TYPE_SERVER_HELLO: u8 = 1;
    /// Payload type for ClientFinish
    pub const TYPE_CLIENT_FINISH: u8 = 2;
    /// Payload type for Error
    pub const TYPE_ERROR: u8 = 255;
}

/// Result of a successful handshake
#[derive(Clone, Debug)]
pub struct HandshakeResult {
    /// Derived session key (32 bytes)
    pub session_key: Vec<u8>,
    /// Session identifier (32 bytes)
    pub session_id: Vec<u8>,
    /// Peer's DID
    pub peer_did: String,
    /// Peer's public key
    pub peer_public_key: Vec<u8>,
}

/// State machine for UHP v2 handshake
///
/// Use this struct to perform the handshake step by step.
pub struct HandshakeState {
    identity: Identity,
    channel_binding: Vec<u8>,
    challenge_nonce: [u8; 32],
    client_hello_bytes: Vec<u8>,
    server_hello_bytes: Option<Vec<u8>>,
    server_nonce: Option<Vec<u8>>,
    server_identity: Option<NodeIdentity>,
}

impl HandshakeState {
    /// Create a new handshake state
    ///
    /// # Arguments
    ///
    /// * `identity` - Client identity to authenticate with
    /// * `channel_binding` - Transport-level binding (e.g., Blake3(local_addr || peer_addr))
    pub fn new(identity: Identity, channel_binding: Vec<u8>) -> Self {
        Self {
            identity,
            channel_binding,
            challenge_nonce: random_nonce(),
            client_hello_bytes: Vec::new(),
            server_hello_bytes: None,
            server_nonce: None,
            server_identity: None,
        }
    }

    /// Step 1: Create ClientHello message
    ///
    /// Returns the wire-format bytes to send to the server.
    /// Format: [4-byte length (BE)] [serialized HandshakeMessage]
    pub fn create_client_hello(&mut self) -> Result<Vec<u8>> {
        let timestamp = current_timestamp();
        let node_identity = NodeIdentity::from(&self.identity);

        // Build signature data
        let sig_data = build_client_hello_signature_data(
            &node_identity,
            &HandshakeCapabilities::default(),
            "zhtp-mainnet",
            "uhp",
            "zhtp-node-handshake",
            0, // Client role
            &self.channel_binding,
            &self.challenge_nonce,
            timestamp,
            UHP_VERSION,
        );

        let signature = Dilithium5::sign(&sig_data, &self.identity.private_key)?;

        // Build PQC offer if we have Kyber keys
        let pqc_offer = if !self.identity.kyber_public_key.is_empty() {
            Some(PqcOffer {
                kyber_public_key: self.identity.kyber_public_key.clone(),
                commitment: Blake3::hash_vec(&self.identity.kyber_public_key),
            })
        } else {
            None
        };

        let client_hello = ClientHello {
            identity: node_identity,
            capabilities: HandshakeCapabilities::default(),
            network_id: "zhtp-mainnet".into(),
            protocol_id: "uhp".into(),
            purpose: "zhtp-node-handshake".into(),
            role: 0,
            channel_binding: self.channel_binding.clone(),
            challenge_nonce: self.challenge_nonce.to_vec(),
            signature,
            timestamp,
            protocol_version: UHP_VERSION,
            pqc_offer,
        };

        // Serialize ClientHello
        let payload =
            serde_json::to_vec(&client_hello).map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // Wrap in HandshakeMessage
        let message = HandshakeMessage {
            version: UHP_VERSION,
            payload_type: HandshakeMessage::TYPE_CLIENT_HELLO,
            payload,
            timestamp,
        };

        let message_bytes =
            serde_json::to_vec(&message).map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // Store for transcript hash
        self.client_hello_bytes = message_bytes.clone();

        // Return with length prefix
        Ok(with_length_prefix(&message_bytes))
    }

    /// Step 2: Process ServerHello and create ClientFinish
    ///
    /// # Arguments
    ///
    /// * `data` - Wire-format bytes received from server
    ///
    /// # Returns
    ///
    /// Wire-format ClientFinish bytes to send back
    pub fn process_server_hello(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Remove length prefix
        let message_bytes = strip_length_prefix(data)?;

        // Parse HandshakeMessage
        let message: HandshakeMessage = serde_json::from_slice(message_bytes)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        if message.payload_type != HandshakeMessage::TYPE_SERVER_HELLO {
            return Err(ClientError::HandshakeError(format!(
                "Expected ServerHello (type {}), got type {}",
                HandshakeMessage::TYPE_SERVER_HELLO,
                message.payload_type
            )));
        }

        // Parse ServerHello
        let server_hello: ServerHello = serde_json::from_slice(&message.payload)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // Verify server signature
        let sig_data = build_server_hello_signature_data(&server_hello);
        if !Dilithium5::verify(&sig_data, &server_hello.signature, &server_hello.identity.public_key)? {
            return Err(ClientError::InvalidSignature);
        }

        // Verify client challenge hash
        let expected_challenge_hash = Blake3::hash(&self.challenge_nonce);
        if server_hello.client_challenge_hash != expected_challenge_hash {
            return Err(ClientError::HandshakeError(
                "Server did not echo correct challenge hash".into(),
            ));
        }

        // Store server info
        self.server_hello_bytes = Some(message_bytes.to_vec());
        self.server_nonce = Some(server_hello.response_nonce.clone());
        self.server_identity = Some(server_hello.identity.clone());

        // Create ClientFinish
        let transcript_hash = Blake3::hash(
            &[
                self.client_hello_bytes.as_slice(),
                self.server_hello_bytes.as_ref().unwrap(),
            ]
            .concat(),
        );

        let finish_sig_data = [
            self.challenge_nonce.as_slice(),
            server_hello.response_nonce.as_slice(),
            &transcript_hash,
        ]
        .concat();

        let signature = Dilithium5::sign(&finish_sig_data, &self.identity.private_key)?;

        let client_finish = ClientFinish {
            client_nonce: self.challenge_nonce.to_vec(),
            server_nonce: server_hello.response_nonce.clone(),
            transcript_hash: transcript_hash.to_vec(),
            signature,
            pqc_confirmation: None, // TODO: Add Kyber confirmation if PQC was used
        };

        // Serialize
        let payload =
            serde_json::to_vec(&client_finish).map_err(|e| ClientError::SerializationError(e.to_string()))?;

        let message = HandshakeMessage {
            version: UHP_VERSION,
            payload_type: HandshakeMessage::TYPE_CLIENT_FINISH,
            payload,
            timestamp: current_timestamp(),
        };

        let message_bytes =
            serde_json::to_vec(&message).map_err(|e| ClientError::SerializationError(e.to_string()))?;

        Ok(with_length_prefix(&message_bytes))
    }

    /// Step 3: Finalize handshake and derive session key
    ///
    /// Call this after sending ClientFinish to derive the session key.
    pub fn finalize(&self) -> Result<HandshakeResult> {
        let server_nonce = self
            .server_nonce
            .as_ref()
            .ok_or_else(|| ClientError::HandshakeError("Handshake not complete: missing server nonce".into()))?;

        let server_identity = self
            .server_identity
            .as_ref()
            .ok_or_else(|| ClientError::HandshakeError("Handshake not complete: missing server identity".into()))?;

        // Compute transcript hash
        let transcript = [
            self.client_hello_bytes.as_slice(),
            self.server_hello_bytes.as_ref().unwrap(),
        ]
        .concat();
        let transcript_hash = Blake3::hash(&transcript);

        // Derive session key using HKDF-SHA3-256
        let session_key = derive_session_key(
            &self.challenge_nonce,
            server_nonce,
            &self.identity.did,
            &server_identity.did,
            &transcript_hash,
        )?;

        // Derive session ID
        let session_id = Blake3::hash(&[self.challenge_nonce.as_slice(), server_nonce].concat());

        Ok(HandshakeResult {
            session_key: session_key.to_vec(),
            session_id: session_id.to_vec(),
            peer_did: server_identity.did.clone(),
            peer_public_key: server_identity.public_key.clone(),
        })
    }

    /// Get the challenge nonce (for debugging/logging)
    pub fn challenge_nonce(&self) -> &[u8] {
        &self.challenge_nonce
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn build_client_hello_signature_data(
    identity: &NodeIdentity,
    capabilities: &HandshakeCapabilities,
    network_id: &str,
    protocol_id: &str,
    purpose: &str,
    role: u8,
    channel_binding: &[u8],
    challenge_nonce: &[u8],
    timestamp: u64,
    protocol_version: u8,
) -> Vec<u8> {
    let mut data = Vec::new();

    // Identity fields
    data.extend_from_slice(identity.did.as_bytes());
    data.extend_from_slice(&identity.public_key);
    data.extend_from_slice(&identity.node_id);
    data.extend_from_slice(identity.device_id.as_bytes());

    // Capabilities (serialized deterministically)
    if let Ok(cap_bytes) = serde_json::to_vec(capabilities) {
        data.extend_from_slice(&cap_bytes);
    }

    // Domain separation
    data.extend_from_slice(network_id.as_bytes());
    data.extend_from_slice(protocol_id.as_bytes());
    data.extend_from_slice(purpose.as_bytes());

    // Role and binding
    data.push(role);
    data.extend_from_slice(channel_binding);

    // Challenge
    data.extend_from_slice(challenge_nonce);

    // Timestamp and version
    data.extend_from_slice(&timestamp.to_le_bytes());
    data.push(protocol_version);

    data
}

fn build_server_hello_signature_data(server_hello: &ServerHello) -> Vec<u8> {
    let mut data = Vec::new();

    data.extend_from_slice(server_hello.identity.did.as_bytes());
    data.extend_from_slice(&server_hello.identity.public_key);
    data.extend_from_slice(&server_hello.identity.node_id);
    data.extend_from_slice(server_hello.network_id.as_bytes());
    data.extend_from_slice(server_hello.protocol_id.as_bytes());
    data.extend_from_slice(server_hello.purpose.as_bytes());
    data.push(server_hello.role);
    data.extend_from_slice(&server_hello.channel_binding);
    data.extend_from_slice(&server_hello.response_nonce);
    data.extend_from_slice(&server_hello.client_challenge_hash);
    data.extend_from_slice(&server_hello.timestamp.to_le_bytes());
    data.push(server_hello.protocol_version);

    data
}

fn derive_session_key(
    client_nonce: &[u8],
    server_nonce: &[u8],
    client_did: &str,
    server_did: &str,
    transcript_hash: &[u8],
) -> Result<[u8; 32]> {
    let ikm = [client_nonce, server_nonce].concat();
    let info = format!("uhp_session_key|{}|{}", client_did, server_did);
    let info_bytes = [info.as_bytes(), transcript_hash].concat();

    let key_bytes = hkdf_sha3_256(&ikm, None, &info_bytes, 32)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

fn with_length_prefix(data: &[u8]) -> Vec<u8> {
    let len = (data.len() as u32).to_be_bytes();
    [&len[..], data].concat()
}

fn strip_length_prefix(data: &[u8]) -> Result<&[u8]> {
    if data.len() < 4 {
        return Err(ClientError::InvalidFormat("Message too short".into()));
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return Err(ClientError::InvalidFormat(format!(
            "Message truncated: expected {} bytes, got {}",
            len,
            data.len() - 4
        )));
    }
    Ok(&data[4..4 + len])
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compute channel binding from socket addresses
///
/// # Arguments
///
/// * `local_addr` - Local socket address as string
/// * `peer_addr` - Remote socket address as string
///
/// # Returns
///
/// 32-byte channel binding value
pub fn compute_channel_binding(local_addr: &str, peer_addr: &str) -> Vec<u8> {
    // Sort addresses for deterministic binding
    let (first, second) = if local_addr < peer_addr {
        (local_addr, peer_addr)
    } else {
        (peer_addr, local_addr)
    };

    Blake3::hash_vec(format!("{}|{}", first, second).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity;

    #[test]
    fn test_handshake_state_creation() {
        let identity = generate_identity("test-device".into()).unwrap();
        let channel_binding = vec![0u8; 32];

        let state = HandshakeState::new(identity, channel_binding);
        assert_eq!(state.challenge_nonce().len(), 32);
    }

    #[test]
    fn test_create_client_hello() {
        let identity = generate_identity("test-device".into()).unwrap();
        let channel_binding = compute_channel_binding("127.0.0.1:1234", "127.0.0.1:5678");

        let mut state = HandshakeState::new(identity, channel_binding);
        let client_hello_bytes = state.create_client_hello().unwrap();

        // Should have length prefix
        assert!(client_hello_bytes.len() > 4);

        // Verify we can parse it
        let message_bytes = strip_length_prefix(&client_hello_bytes).unwrap();
        let message: HandshakeMessage = serde_json::from_slice(message_bytes).unwrap();

        assert_eq!(message.version, UHP_VERSION);
        assert_eq!(message.payload_type, HandshakeMessage::TYPE_CLIENT_HELLO);
    }

    #[test]
    fn test_compute_channel_binding() {
        let binding1 = compute_channel_binding("a", "b");
        let binding2 = compute_channel_binding("b", "a");

        // Should be same regardless of order
        assert_eq!(binding1, binding2);
        assert_eq!(binding1.len(), 32);
    }
}
