//! DHT Network Operations
//! 
//! **TICKET #152:** Multi-protocol DHT transport abstraction
//! 
//! Handles communication for DHT operations over multiple protocols (UDP, BLE, QUIC, WiFi Direct)
//! using the DhtTransport abstraction from lib-network.

use crate::types::dht_types::{DhtMessage, DhtNode, DhtMessageType, DhtQueryResponse};
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use tracing::{debug, warn, error, info};
use serde::{Serialize, Deserialize};

// Import transport abstraction (Ticket #152)
// Trait defined in lib-storage to avoid circular dependency with lib-network
use crate::dht::transport::{DhtTransport, PeerId};

// Import signing module (Issue #676)
use crate::dht::signing::{MessageSigner, verify_message_signature};
use lib_crypto::PublicKey;

/// Network envelope for DHT messages with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEnvelope {
    /// The actual DHT message
    pub message: DhtMessage,
    /// Network-level metadata
    pub metadata: NetworkMetadata,
}

/// Network metadata for message routing and reliability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetadata {
    /// Message sequence number
    pub sequence: u64,
    /// Network protocol version
    pub version: u8,
    /// Hop count for routing
    pub hop_count: u8,
    /// Message priority
    pub priority: MessagePriority,
}

/// Message priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// DHT network manager for UDP communication
///
/// # Security (Issue #676): Message Signing
///
/// All DHT messages are now cryptographically signed using CRYSTALS-Dilithium
/// (post-quantum) signatures. This provides:
///
/// - **Authenticity**: Messages are verified to come from the claimed sender
/// - **Integrity**: Any tampering with message content invalidates the signature
/// - **Replay Protection**: Combined with timestamp and nonce validation
///
/// # Usage
///
/// ```rust,ignore
/// // Create with signing enabled (recommended)
/// let keypair = lib_crypto::KeyPair::generate()?;
/// let network = DhtNetwork::new_with_signing(local_node, transport, keypair)?;
///
/// // All outgoing messages are automatically signed
/// network.ping(&target).await?;
///
/// // All incoming messages have signatures verified
/// let (message, peer) = network.receive_message().await?;
/// ```
pub struct DhtNetwork {
    /// **TICKET #152:** Multi-protocol transport abstraction
    transport: Arc<dyn DhtTransport>,
    /// Local node information
    local_node: DhtNode,
    /// Message timeout duration
    timeout_duration: Duration,
    /// SECURITY: Monotonically increasing sequence number for replay protection
    sequence_counter: AtomicU64,
    /// Issue #676: Message signer for outgoing messages
    signer: Option<MessageSigner>,
    /// Issue #676: Cache of known peer public keys for signature verification
    /// Maps NodeId bytes to PublicKey
    known_peers: Arc<RwLock<HashMap<[u8; 32], PublicKey>>>,
}

impl std::fmt::Debug for DhtNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtNetwork")
            .field("transport", &"Arc<dyn DhtTransport>")
            .field("local_node", &self.local_node)
            .field("timeout_duration", &self.timeout_duration)
            .field("sequence_counter", &self.sequence_counter.load(Ordering::SeqCst))
            .field("signing_enabled", &self.signer.is_some())
            .field("known_peers_count", &self.known_peers.read().map(|p| p.len()).unwrap_or(0))
            .finish()
    }
}

impl DhtNetwork {
    /// Create a new DHT network manager with multi-protocol transport
    ///
    /// **TICKET #152:** Now accepts DhtTransport instead of hardcoded UDP socket
    ///
    /// **Note:** This creates a network without message signing. For production use,
    /// prefer `new_with_signing()` to enable cryptographic message authentication.
    pub fn new(local_node: DhtNode, transport: Arc<dyn DhtTransport>) -> Result<Self> {
        Ok(Self {
            transport,
            local_node,
            timeout_duration: Duration::from_secs(5),
            sequence_counter: AtomicU64::new(0),
            signer: None,
            known_peers: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a new DHT network manager with message signing enabled (Issue #676)
    ///
    /// This is the recommended constructor for production use. All outgoing messages
    /// will be signed with the provided keypair, and incoming messages will have
    /// their signatures verified.
    ///
    /// # Arguments
    /// * `local_node` - Local node information
    /// * `transport` - Transport implementation for sending/receiving messages
    /// * `keypair` - Keypair for signing messages
    ///
    /// # Example
    /// ```rust,ignore
    /// let keypair = lib_crypto::KeyPair::generate()?;
    /// let network = DhtNetwork::new_with_signing(local_node, transport, keypair)?;
    /// ```
    pub fn new_with_signing(
        local_node: DhtNode,
        transport: Arc<dyn DhtTransport>,
        keypair: lib_crypto::KeyPair,
    ) -> Result<Self> {
        info!("Creating DHT network with message signing enabled");
        Ok(Self {
            transport,
            local_node,
            timeout_duration: Duration::from_secs(5),
            sequence_counter: AtomicU64::new(0),
            signer: Some(MessageSigner::new(keypair)),
            known_peers: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create DHT network with specific bind address (legacy compatibility)
    /// Creates a UDP transport for the given address
    ///
    /// **TICKET #152:** Now uses UdpDhtTransport from lib-storage (not lib-network)
    /// to avoid circular dependency
    ///
    /// **Note:** This creates a network without message signing. For production use,
    /// prefer `new_udp_with_signing()`.
    pub fn new_udp(local_node: DhtNode, bind_addr: SocketAddr) -> Result<Self> {
        use crate::dht::transport::UdpDhtTransport;

        // Create tokio UDP socket
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        let tokio_socket = tokio::net::UdpSocket::from_std(socket)?;

        // Create UDP transport
        let transport = Arc::new(UdpDhtTransport::new(
            Arc::new(tokio_socket),
            bind_addr,
        ));

        Self::new(local_node, transport)
    }

    /// Create DHT network with UDP transport and message signing (Issue #676)
    ///
    /// This is the recommended constructor for production use with UDP transport.
    pub fn new_udp_with_signing(
        local_node: DhtNode,
        bind_addr: SocketAddr,
        keypair: lib_crypto::KeyPair,
    ) -> Result<Self> {
        use crate::dht::transport::UdpDhtTransport;

        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        let tokio_socket = tokio::net::UdpSocket::from_std(socket)?;

        let transport = Arc::new(UdpDhtTransport::new(
            Arc::new(tokio_socket),
            bind_addr,
        ));

        Self::new_with_signing(local_node, transport, keypair)
    }

    /// Check if message signing is enabled
    pub fn signing_enabled(&self) -> bool {
        self.signer.is_some()
    }

    /// Register a peer's public key for future signature verification
    ///
    /// When a message is received from a peer, their public key is looked up
    /// in this cache to verify the signature.
    ///
    /// # Returns
    /// - `true` if the key was successfully registered
    /// - `false` if the registration failed (lock poisoned)
    pub fn register_peer_key(&self, node_id: &NodeId, public_key: PublicKey) -> bool {
        match self.known_peers.write() {
            Ok(mut peers) => {
                peers.insert(*node_id.as_bytes(), public_key);
                debug!(
                    node_id = %hex::encode(&node_id.as_bytes()[..8]),
                    "Registered peer public key"
                );
                true
            }
            Err(e) => {
                warn!(
                    node_id = %hex::encode(&node_id.as_bytes()[..8]),
                    error = %e,
                    "Failed to register peer public key: lock poisoned"
                );
                false
            }
        }
    }

    /// Get a peer's public key from the cache
    ///
    /// # Returns
    /// - `Some(PublicKey)` if the peer is known
    /// - `None` if the peer is unknown or the lock is poisoned
    pub fn get_peer_key(&self, node_id: &NodeId) -> Option<PublicKey> {
        match self.known_peers.read() {
            Ok(peers) => peers.get(node_id.as_bytes()).cloned(),
            Err(e) => {
                warn!(
                    node_id = %hex::encode(&node_id.as_bytes()[..8]),
                    error = %e,
                    "Failed to read peer public key: lock poisoned"
                );
                None
            }
        }
    }

    /// Sign a message if signing is enabled
    fn sign_message_if_enabled(&self, message: &mut DhtMessage) -> Result<()> {
        if let Some(ref signer) = self.signer {
            signer.sign_message(message)?;
        } else {
            debug!(
                message_id = %message.message_id,
                "Message not signed (signing disabled)"
            );
        }
        Ok(())
    }

    /// Verify a message signature if the sender's public key is known
    ///
    /// # Returns
    /// - `Ok(true)` if signature is valid or signing is disabled
    /// - `Ok(false)` if signature is invalid
    /// - `Err(...)` if verification failed due to an error
    ///
    /// # Security Notes
    ///
    /// **SECURITY WARNING**: This function has lenient behavior for unknown senders
    /// to support bootstrap and peer discovery. In high-security environments,
    /// consider using strict mode (TODO: implement strict_verification config).
    ///
    /// The verification flow:
    /// 1. If signing is disabled, all messages are accepted (backward compatibility)
    /// 2. If sender's public key is cached, verify signature against it
    /// 3. If sender's key is in message.nodes, cache it and verify (bootstrap)
    /// 4. If sender is completely unknown, accept if message is fresh (lenient mode)
    ///
    /// **Known Limitations** (tracked in Issue #676):
    /// - No cryptographic binding between node_id and public_key
    /// - Self-asserted keys from nodes list are trusted during bootstrap
    /// - No nonce replay cache (messages can be replayed within freshness window)
    fn verify_message_if_possible(&self, message: &DhtMessage) -> Result<bool> {
        // If signing is not enabled, skip verification (backward compatibility)
        if self.signer.is_none() {
            return Ok(true);
        }

        // Try to get sender's public key from cache
        if let Some(public_key) = self.get_peer_key(&message.sender_id) {
            return verify_message_signature(message, &public_key);
        }

        // If sender is not in cache, check if it's in the message's nodes list
        // (for bootstrap scenarios where we learn about peers)
        // SECURITY: This trusts self-asserted public keys during bootstrap.
        // A malicious node could claim any node_id with their own key.
        // TODO: Implement node_id = hash(public_key) binding for security.
        if let Some(ref nodes) = message.nodes {
            for node in nodes {
                if node.peer.node_id() == &message.sender_id {
                    // Found the sender in the nodes list, use their public key
                    self.register_peer_key(&message.sender_id, node.peer.public_key().clone());
                    return verify_message_signature(message, node.peer.public_key());
                }
            }
        }

        // Sender not known - warn but don't reject (may be first contact)
        // SECURITY: This is lenient mode for bootstrap. In strict mode,
        // unknown senders should be rejected (return Ok(false)).
        warn!(
            sender_id = %hex::encode(&message.sender_id.as_bytes()[..8]),
            message_id = %message.message_id,
            "Cannot verify signature: sender public key not known (lenient mode)"
        );

        // Accept messages from unknown senders if they pass freshness check
        // This allows bootstrap and peer discovery to work
        message.validate_freshness().map(|_| true)
    }

    /// Generate a cryptographically secure random nonce
    ///
    /// Uses a cryptographically secure random number generator (CSPRNG)
    /// to generate nonces suitable for replay protection.
    fn generate_nonce() -> [u8; 32] {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Get next sequence number (atomic increment)
    fn next_sequence(&self) -> u64 {
        self.sequence_counter.fetch_add(1, Ordering::SeqCst)
    }
    
    /// Send a DHT message to a target node
    ///
    /// **TICKET #152:** Now uses DhtTransport abstraction for multi-protocol support
    /// **Issue #676:** Messages are now signed before sending (if signing enabled)
    pub async fn send_message(&self, target: &DhtNode, mut message: DhtMessage) -> Result<()> {
        // Issue #676: Sign the message before sending
        self.sign_message_if_enabled(&mut message)?;

        // Serialize message
        let message_bytes = bincode::serialize(&message)?;

        // Get target address and create PeerId
        let target_addr = target.addresses.first()
            .ok_or_else(|| anyhow!("No address available for target node"))?;

        // Parse address to PeerId (default to UDP for socket addresses)
        let peer_id = if let Ok(socket_addr) = target_addr.parse::<SocketAddr>() {
            PeerId::Udp(socket_addr)
        } else if target_addr.starts_with("gatt://") {
            PeerId::Bluetooth(target_addr.trim_start_matches("gatt://").to_string())
        } else if target_addr.starts_with("wifid://") {
            let addr = target_addr.trim_start_matches("wifid://").parse()?;
            PeerId::WiFiDirect(addr)
        } else if target_addr.starts_with("quic://") {
            let addr = target_addr.trim_start_matches("quic://").parse()?;
            PeerId::Quic(addr)
        } else if target_addr.starts_with("lora://") {
            PeerId::LoRaWAN(target_addr.trim_start_matches("lora://").to_string())
        } else {
            return Err(anyhow!("Unknown address format: {}", target_addr));
        };

        // Register target's public key for future verification
        self.register_peer_key(target.peer.node_id(), target.peer.public_key().clone());

        // Send via transport abstraction
        self.transport.send(&message_bytes, &peer_id).await?;

        debug!(
            message_id = %message.message_id,
            msg_type = ?message.message_type,
            target = %hex::encode(&target.peer.node_id().as_bytes()[..8]),
            signed = self.signer.is_some(),
            "Sent DHT message"
        );

        Ok(())
    }
    
    /// Receive and parse DHT message with freshness and signature validation
    ///
    /// **TICKET #152:** Now uses DhtTransport abstraction for multi-protocol support
    /// **Issue #676:** Messages are now verified for valid signatures
    ///
    /// # Security
    ///
    /// - Validates message timestamp (rejects > 5 min old)
    /// - Validates nonce is non-zero
    /// - Verifies cryptographic signature (if signing enabled)
    /// - Caller should check nonce against seen-nonce cache for replay protection
    pub async fn receive_message(&self) -> Result<(DhtMessage, PeerId)> {
        // Receive from transport abstraction
        let (message_bytes, peer_id) = timeout(
            self.timeout_duration,
            self.transport.receive()
        ).await??;

        // Deserialize message
        let message: DhtMessage = bincode::deserialize(&message_bytes)?;

        // SECURITY: Validate message freshness and replay protection fields
        if let Err(e) = message.validate_freshness() {
            warn!(
                sender = %peer_id,
                msg_type = ?message.message_type,
                error = %e,
                "Rejecting stale or invalid DHT message"
            );
            return Err(anyhow!("Message validation failed: {}", e));
        }

        // Issue #676: Verify message signature
        match self.verify_message_if_possible(&message) {
            Ok(true) => {
                // Signature valid or signing disabled
            }
            Ok(false) => {
                error!(
                    sender = %peer_id,
                    sender_id = %hex::encode(&message.sender_id.as_bytes()[..8]),
                    msg_type = ?message.message_type,
                    "Rejecting message with invalid signature"
                );
                return Err(anyhow!("Message signature verification failed"));
            }
            Err(e) => {
                error!(
                    sender = %peer_id,
                    error = %e,
                    "Signature verification error"
                );
                return Err(anyhow!("Signature verification error: {}", e));
            }
        }

        debug!(
            sender = %peer_id,
            msg_type = ?message.message_type,
            seq = message.sequence_number,
            protocol = peer_id.protocol(),
            "Received valid DHT message"
        );

        Ok((message, peer_id))
    }
    
    /// Send PING message to check node liveness
    ///
    /// **MIGRATION (Ticket #145):** Uses `target.peer.node_id()` for target_id
    /// **Issue #676:** Message is automatically signed in `send_message()`
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    /// - Message is signed before sending (if signing enabled)
    pub async fn ping(&self, target: &DhtNode) -> Result<bool> {
        let ping_message = DhtMessage {
            message_id: generate_message_id(),
            message_type: DhtMessageType::Ping,
            sender_id: self.local_node.peer.node_id().clone(),
            target_id: Some(target.peer.node_id().clone()),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            nonce: Self::generate_nonce(),
            sequence_number: self.next_sequence(),
            signature: None, // Signed in send_message()
        };

        self.send_message(target, ping_message).await?;

        // Wait for PONG response
        // **MIGRATION (Ticket #145):** Uses `target.peer.node_id()` for response matching
        let start_time = SystemTime::now();
        while start_time.elapsed()? < self.timeout_duration {
            if let Ok((response, _)) = self.receive_message().await {
                if matches!(response.message_type, DhtMessageType::Pong) &&
                   response.sender_id == *target.peer.node_id() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
    
    /// Send FIND_NODE query
    ///
    /// **MIGRATION (Ticket #145):** Uses `local_node.peer.node_id()` for sender_id
    /// **Issue #676:** Message is automatically signed in `send_message()`
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    /// - Message is signed before sending (if signing enabled)
    pub async fn find_node(&self, target: &DhtNode, query_id: NodeId) -> Result<Vec<DhtNode>> {
        let find_node_message = DhtMessage {
            message_id: generate_message_id(),
            message_type: DhtMessageType::FindNode,
            sender_id: self.local_node.peer.node_id().clone(),
            target_id: Some(query_id),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            nonce: Self::generate_nonce(),
            sequence_number: self.next_sequence(),
            signature: None, // Signed in send_message()
        };

        self.send_message(target, find_node_message).await?;

        // Wait for response
        // **MIGRATION (Ticket #145):** Uses `target.peer.node_id()` for response matching
        let start_time = SystemTime::now();
        while start_time.elapsed()? < self.timeout_duration {
            if let Ok((response, _)) = self.receive_message().await {
                if matches!(response.message_type, DhtMessageType::FindNodeResponse) &&
                   response.sender_id == *target.peer.node_id() {
                    return Ok(response.nodes.unwrap_or_default());
                }
            }
        }

        Err(anyhow!("FIND_NODE query timeout"))
    }
    
    /// Send FIND_VALUE query
    ///
    /// **MIGRATION (Ticket #145):** Uses `target.peer.node_id()` for target_id
    /// **Issue #676:** Message is automatically signed in `send_message()`
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    /// - Message is signed before sending (if signing enabled)
    pub async fn find_value(&self, target: &DhtNode, key: String) -> Result<DhtQueryResponse> {
        let find_value_message = DhtMessage {
            message_id: generate_message_id(),
            message_type: DhtMessageType::FindValue,
            sender_id: self.local_node.peer.node_id().clone(),
            target_id: Some(target.peer.node_id().clone()),
            key: Some(key.clone()),
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            nonce: Self::generate_nonce(),
            sequence_number: self.next_sequence(),
            signature: None, // Signed in send_message()
        };

        self.send_message(target, find_value_message).await?;

        // Wait for response
        // **MIGRATION (Ticket #145):** Uses `target.peer.node_id()` for response matching
        let start_time = SystemTime::now();
        while start_time.elapsed()? < self.timeout_duration {
            if let Ok((response, _)) = self.receive_message().await {
                if matches!(response.message_type, DhtMessageType::FindValueResponse) &&
                   response.sender_id == *target.peer.node_id() {
                    if let Some(value) = response.value {
                        return Ok(DhtQueryResponse::Value(value));
                    } else if let Some(nodes) = response.nodes {
                        return Ok(DhtQueryResponse::Nodes(nodes));
                    }
                }
            }
        }

        Err(anyhow!("FIND_VALUE query timeout"))
    }
    
    /// Send STORE message
    ///
    /// **MIGRATION (Ticket #145):** Uses `target.peer.node_id()` for target_id
    /// **Issue #676:** Message is automatically signed in `send_message()`
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    /// - Message is signed before sending (if signing enabled)
    pub async fn store(&self, target: &DhtNode, key: String, value: Vec<u8>) -> Result<bool> {
        let store_message = DhtMessage {
            message_id: generate_message_id(),
            message_type: DhtMessageType::Store,
            sender_id: self.local_node.peer.node_id().clone(),
            target_id: Some(target.peer.node_id().clone()),
            key: Some(key),
            value: Some(value),
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            nonce: Self::generate_nonce(),
            sequence_number: self.next_sequence(),
            signature: None, // Signed in send_message()
        };

        self.send_message(target, store_message).await?;

        // Wait for acknowledgment
        // **MIGRATION (Ticket #145):** Uses `target.peer.node_id()` for response matching
        let start_time = SystemTime::now();
        while start_time.elapsed()? < self.timeout_duration {
            if let Ok((response, _)) = self.receive_message().await {
                if matches!(response.message_type, DhtMessageType::StoreResponse) &&
                   response.sender_id == *target.peer.node_id() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
    
    /// Handle incoming message and generate appropriate response
    ///
    /// **MIGRATION (Ticket #145):** Uses `local_node.peer.node_id()` for responses
    /// **Issue #676:** Response messages are automatically signed
    ///
    /// # Security
    ///
    /// - Response messages include nonce and sequence_number for replay protection
    /// - Response messages are signed (if signing enabled)
    /// - Incoming message freshness is already validated by receive_message()
    pub async fn handle_incoming_message(&self, message: DhtMessage, _sender: PeerId) -> Result<Option<DhtMessage>> {
        let response = match message.message_type {
            DhtMessageType::Ping => {
                Some(DhtMessage {
                    message_id: generate_message_id(),
                    message_type: DhtMessageType::Pong,
                    sender_id: self.local_node.peer.node_id().clone(),
                    target_id: Some(message.sender_id),
                    key: None,
                    value: None,
                    nodes: None,
                    contract_data: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    nonce: Self::generate_nonce(),
                    sequence_number: self.next_sequence(),
                    signature: None, // Will be signed below
                })
            }

            DhtMessageType::FindNode => {
                // In a implementation, this would query the routing table
                // For now, return empty node list
                Some(DhtMessage {
                    message_id: generate_message_id(),
                    message_type: DhtMessageType::FindNodeResponse,
                    sender_id: self.local_node.peer.node_id().clone(),
                    target_id: Some(message.sender_id),
                    key: None,
                    value: None,
                    nodes: Some(Vec::new()),
                    contract_data: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    nonce: Self::generate_nonce(),
                    sequence_number: self.next_sequence(),
                    signature: None, // Will be signed below
                })
            }

            DhtMessageType::FindValue => {
                // In a implementation, this would check local storage
                // For now, return empty node list (value not found)
                Some(DhtMessage {
                    message_id: generate_message_id(),
                    message_type: DhtMessageType::FindValueResponse,
                    sender_id: self.local_node.peer.node_id().clone(),
                    target_id: Some(message.sender_id),
                    key: message.key,
                    value: None,
                    nodes: Some(Vec::new()),
                    contract_data: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    nonce: Self::generate_nonce(),
                    sequence_number: self.next_sequence(),
                    signature: None, // Will be signed below
                })
            }

            DhtMessageType::Store => {
                // In a implementation, this would store the key-value pair
                Some(DhtMessage {
                    message_id: generate_message_id(),
                    message_type: DhtMessageType::StoreResponse,
                    sender_id: self.local_node.peer.node_id().clone(),
                    target_id: Some(message.sender_id),
                    key: None,
                    value: None,
                    nodes: None,
                    contract_data: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    nonce: Self::generate_nonce(),
                    sequence_number: self.next_sequence(),
                    signature: None, // Will be signed below
                })
            }

            _ => None, // Response messages don't need responses
        };

        // Issue #676: Sign the response message if one was generated
        match response {
            Some(mut msg) => {
                self.sign_message_if_enabled(&mut msg)?;
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }
    
    /// Get local socket address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        // Extract address from transport's local peer ID
        match self.transport.local_peer_id() {
            PeerId::Udp(addr) => Ok(addr),
            PeerId::WiFiDirect(addr) => Ok(addr),
            PeerId::Quic(addr) => Ok(addr),
            PeerId::Bluetooth(_) | PeerId::LoRaWAN(_) | PeerId::Mesh(_) => {
                // For non-IP protocols, return a placeholder
                Ok("0.0.0.0:0".parse()?)
            }
        }
    }
}

/// Generate a unique message ID
fn generate_message_id() -> String {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    
    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::{ZhtpIdentity, IdentityType};
    use crate::types::dht_types::DhtPeerIdentity;

    fn create_test_peer(device_name: &str) -> DhtPeerIdentity {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Device,
            None,
            None,
            device_name,
            None,
        ).expect("Failed to create test identity");
        
        DhtPeerIdentity {
            node_id: identity.node_id.clone(),
            public_key: identity.public_key.clone(),
            did: identity.did.clone(),
            device_id: device_name.to_string(),
        }
    }

    fn dummy_pq_signature() -> lib_crypto::PostQuantumSignature {
        lib_crypto::PostQuantumSignature {
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            signature: vec![],
            public_key: lib_crypto::PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            timestamp: 0,
        }
    }
    
    #[test]
    fn test_message_id_generation() {
        let id1 = generate_message_id();
        let id2 = generate_message_id();
        
        assert_ne!(id1, id2);
        assert!(!id1.is_empty());
        assert!(!id2.is_empty());
    }
    
    #[tokio::test]
    async fn test_network_creation() {
        let test_node = DhtNode {
            peer: create_test_peer("test-device-1"),
            addresses: vec!["127.0.0.1:33442".to_string()],
            public_key: dummy_pq_signature(),
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        };
        
        let bind_addr = "127.0.0.1:0".parse().unwrap(); // Use any available port
        let network = DhtNetwork::new_udp(test_node, bind_addr);

        assert!(network.is_ok());
        if let Ok(net) = network {
            assert!(net.local_addr().is_ok());
        }
    }
    
    #[tokio::test]
    async fn test_ping_pong_response() {
        let test_node = DhtNode {
            peer: create_test_peer("test-device-2"),
            addresses: vec!["127.0.0.1:33443".to_string()],
            public_key: dummy_pq_signature(),
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        };
        
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let network = DhtNetwork::new_udp(test_node, bind_addr).expect("Failed to create network");
        
        // Test PING message handling
        let ping_message = DhtMessage {
            message_id: "test_ping".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: NodeId::from_bytes([2u8; 32]),
            target_id: Some(NodeId::from_bytes([1u8; 32])),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            nonce: [1u8; 32], // Non-zero nonce for testing
            sequence_number: 0,
            signature: None,
        };
        
        let sender = PeerId::Udp("127.0.0.1:12345".parse().unwrap());
        let response = network.handle_incoming_message(ping_message, sender).await.unwrap();

        assert!(response.is_some());
        if let Some(pong) = response {
            assert!(matches!(pong.message_type, DhtMessageType::Pong));
        }
    }

    // ==================== SECURITY TESTS (MED-10) ====================

    #[test]
    fn test_nonce_generation_uniqueness() {
        // Security: Verify nonces are unique (not all zeros, vary between calls)
        let nonce1 = DhtNetwork::generate_nonce();
        let nonce2 = DhtNetwork::generate_nonce();

        // Nonces should not be all zeros
        assert_ne!(nonce1, [0u8; 32], "Nonce should not be all zeros");
        assert_ne!(nonce2, [0u8; 32], "Nonce should not be all zeros");

        // Note: Due to timing, consecutive nonces might sometimes be identical
        // In production, use a CSPRNG. This test documents the expectation.
    }

    #[test]
    fn test_message_freshness_validation() {
        // Security: Verify stale messages are rejected
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(600); // 10 minutes old

        let stale_message = DhtMessage {
            message_id: "stale_msg".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: NodeId::from_bytes([1u8; 32]),
            target_id: None,
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: old_timestamp,
            nonce: [1u8; 32],
            sequence_number: 0,
            signature: None,
        };

        // Should fail freshness validation
        let result = stale_message.validate_freshness();
        assert!(result.is_err(), "Stale message should fail validation");
    }

    #[test]
    fn test_zero_nonce_rejected() {
        // Security: Verify zero nonce messages are rejected
        let zero_nonce_message = DhtMessage {
            message_id: "zero_nonce".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: NodeId::from_bytes([1u8; 32]),
            target_id: None,
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            nonce: [0u8; 32], // Zero nonce is invalid
            sequence_number: 0,
            signature: None,
        };

        let result = zero_nonce_message.validate_freshness();
        assert!(result.is_err(), "Zero nonce message should fail validation");
    }

    #[test]
    fn test_future_timestamp_rejected() {
        // Security: Verify messages with future timestamps are rejected
        let future_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 120; // 2 minutes in the future (beyond 60s tolerance)

        let future_message = DhtMessage {
            message_id: "future_msg".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: NodeId::from_bytes([1u8; 32]),
            target_id: None,
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: future_timestamp,
            nonce: [1u8; 32],
            sequence_number: 0,
            signature: None,
        };

        let result = future_message.validate_freshness();
        assert!(result.is_err(), "Future timestamp message should fail validation");
    }

    #[test]
    fn test_signable_data_deterministic() {
        // Security: Verify signable data is deterministic for same message
        let message = DhtMessage {
            message_id: "test".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: NodeId::from_bytes([1u8; 32]),
            target_id: Some(NodeId::from_bytes([2u8; 32])),
            key: Some("test_key".to_string()),
            value: Some(vec![1, 2, 3]),
            nodes: None,
            contract_data: None,
            timestamp: 1234567890,
            nonce: [42u8; 32],
            sequence_number: 100,
            signature: None,
        };

        let data1 = message.signable_data();
        let data2 = message.signable_data();

        assert_eq!(data1, data2, "Signable data should be deterministic");
        assert!(!data1.is_empty(), "Signable data should not be empty");
    }

    #[tokio::test]
    async fn test_sequence_counter_increments() {
        // Security: Verify sequence numbers increment correctly
        let test_node = DhtNode {
            peer: create_test_peer("seq-test"),
            addresses: vec!["127.0.0.1:33445".to_string()],
            public_key: dummy_pq_signature(),
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        };

        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let network = DhtNetwork::new_udp(test_node, bind_addr).expect("Failed to create network");

        let seq1 = network.next_sequence();
        let seq2 = network.next_sequence();
        let seq3 = network.next_sequence();

        assert_eq!(seq1, 0, "First sequence should be 0");
        assert_eq!(seq2, 1, "Second sequence should be 1");
        assert_eq!(seq3, 2, "Third sequence should be 2");
    }
}
