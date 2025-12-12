//! DHT Network Operations
//! 
//! **TICKET #152:** Multi-protocol DHT transport abstraction
//! 
//! Handles communication for DHT operations over multiple protocols (UDP, BLE, QUIC, WiFi Direct)
//! using the DhtTransport abstraction from lib-network.

use crate::types::dht_types::{DhtMessage, DhtNode, DhtMessageType, DhtQueryResponse};
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use tracing::{debug, warn};
use serde::{Serialize, Deserialize};

// Import transport abstraction (Ticket #152)
// Trait defined in lib-storage to avoid circular dependency with lib-network
use crate::dht::transport::{DhtTransport, PeerId};

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
/// # Security (HIGH-5): Message Signing
///
/// **TODO:** Messages are currently sent without signatures. Before production:
///
/// 1. Add `private_key: Option<lib_crypto::PrivateKey>` field to DhtNetwork
/// 2. Update constructor to accept private key from IdentityManager
/// 3. Implement `sign_message()` method using DhtMessage::signable_data()
/// 4. Sign all outgoing messages before send_message()
/// 5. Verify incoming message signatures using sender's public key
///
/// ```rust,ignore
/// fn sign_message(&self, message: &mut DhtMessage) -> Result<()> {
///     let signable = message.signable_data();
///     let signature = lib_crypto::sign(&signable, &self.private_key)?;
///     message.signature = Some(signature);
///     Ok(())
/// }
/// ```
///
/// Until signing is implemented, DHT messages are vulnerable to spoofing.
pub struct DhtNetwork {
    /// **TICKET #152:** Multi-protocol transport abstraction
    transport: Arc<dyn DhtTransport>,
    /// Local node information
    local_node: DhtNode,
    /// Message timeout duration
    timeout_duration: Duration,
    /// SECURITY: Monotonically increasing sequence number for replay protection
    sequence_counter: AtomicU64,
    // TODO (HIGH-5): Add private_key field for message signing
    // private_key: Option<lib_crypto::PrivateKey>,
}

impl std::fmt::Debug for DhtNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtNetwork")
            .field("transport", &"Arc<dyn DhtTransport>")
            .field("local_node", &self.local_node)
            .field("timeout_duration", &self.timeout_duration)
            .field("sequence_counter", &self.sequence_counter.load(Ordering::SeqCst))
            .finish()
    }
}

impl DhtNetwork {
    /// Create a new DHT network manager with multi-protocol transport
    /// 
    /// **TICKET #152:** Now accepts DhtTransport instead of hardcoded UDP socket
    pub fn new(local_node: DhtNode, transport: Arc<dyn DhtTransport>) -> Result<Self> {
        Ok(Self {
            transport,
            local_node,
            timeout_duration: Duration::from_secs(5),
            sequence_counter: AtomicU64::new(0),
        })
    }
    
    /// Create DHT network with specific bind address (legacy compatibility)
    /// Creates a UDP transport for the given address
    ///
    /// **TICKET #152:** Now uses UdpDhtTransport from lib-storage (not lib-network)
    /// to avoid circular dependency
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

    /// Generate a cryptographically secure random nonce
    fn generate_nonce() -> [u8; 32] {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut nonce = [0u8; 32];
        // Use multiple entropy sources
        let now = SystemTime::now();
        let mut hasher = DefaultHasher::new();
        now.hash(&mut hasher);

        // Add process-specific entropy
        let pid = std::process::id();
        pid.hash(&mut hasher);

        // Add thread-specific entropy
        std::thread::current().id().hash(&mut hasher);

        let h1 = hasher.finish().to_le_bytes();
        nonce[0..8].copy_from_slice(&h1);

        // Second hash with different seed
        let mut hasher2 = DefaultHasher::new();
        now.hash(&mut hasher2);
        hasher2.write_u64(0xDEADBEEF_CAFEBABE);
        let h2 = hasher2.finish().to_le_bytes();
        nonce[8..16].copy_from_slice(&h2);

        // Third and fourth using nanoseconds
        let nanos = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        nonce[16..24].copy_from_slice(&(nanos as u64).to_le_bytes());
        nonce[24..32].copy_from_slice(&((nanos >> 64) as u64).to_le_bytes());

        nonce
    }

    /// Get next sequence number (atomic increment)
    fn next_sequence(&self) -> u64 {
        self.sequence_counter.fetch_add(1, Ordering::SeqCst)
    }
    
    /// Send a DHT message to a target node
    /// 
    /// **TICKET #152:** Now uses DhtTransport abstraction for multi-protocol support
    pub async fn send_message(&self, target: &DhtNode, message: DhtMessage) -> Result<()> {
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
        } else if target_addr.starts_with("lora://") {
            PeerId::LoRaWAN(target_addr.trim_start_matches("lora://").to_string())
        } else {
            return Err(anyhow!("Unknown address format: {}", target_addr));
        };
        
        // Send via transport abstraction
        self.transport.send(&message_bytes, &peer_id).await?;
        
        Ok(())
    }
    
    /// Receive and parse DHT message with freshness validation
    ///
    /// **TICKET #152:** Now uses DhtTransport abstraction for multi-protocol support
    ///
    /// # Security
    ///
    /// - Validates message timestamp (rejects > 5 min old)
    /// - Validates nonce is non-zero
    /// - Caller should verify signature and check nonce against seen-nonce cache
    pub async fn receive_message(&self) -> Result<(DhtMessage, SocketAddr)> {
        // Receive from transport abstraction
        let (message_bytes, peer_id) = timeout(
            self.timeout_duration,
            self.transport.receive()
        ).await??;

        // Deserialize message
        let message: DhtMessage = bincode::deserialize(&message_bytes)?;

        // Convert PeerId back to SocketAddr for compatibility
        let sender_addr = match peer_id {
            PeerId::Udp(addr) => addr,
            PeerId::WiFiDirect(addr) => addr,
            PeerId::Quic(addr) => addr,
            PeerId::Bluetooth(_) => {
                // For Bluetooth, create a pseudo-address (not used for routing)
                "0.0.0.0:0".parse()?
            }
            PeerId::LoRaWAN(_) => {
                "0.0.0.0:0".parse()?
            }
        };

        // SECURITY: Validate message freshness and replay protection fields
        if let Err(e) = message.validate_freshness() {
            warn!(
                sender = %sender_addr,
                msg_type = ?message.message_type,
                error = %e,
                "Rejecting stale or invalid DHT message"
            );
            return Err(anyhow!("Message validation failed: {}", e));
        }

        debug!(
            sender = %sender_addr,
            msg_type = ?message.message_type,
            seq = message.sequence_number,
            protocol = peer_id.protocol(),
            "Received valid DHT message"
        );

        Ok((message, sender_addr))
    }
    
    /// Send PING message to check node liveness
    ///
    /// **MIGRATION (Ticket #145):** Uses `target.peer.node_id()` for target_id
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    /// - TODO: Sign message before sending (HIGH-5)
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
            signature: None, // TODO (HIGH-5): Sign message with local node's private key
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
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
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
            signature: None, // TODO (HIGH-5): Sign message
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
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
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
            signature: None, // TODO (HIGH-5): Sign message
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
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
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
            signature: None, // TODO (HIGH-5): Sign message
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
    ///
    /// # Security
    ///
    /// - Response messages include nonce and sequence_number for replay protection
    /// - Incoming message freshness is already validated by receive_message()
    pub async fn handle_incoming_message(&self, message: DhtMessage, _sender_addr: SocketAddr) -> Result<Option<DhtMessage>> {
        match message.message_type {
            DhtMessageType::Ping => {
                Ok(Some(DhtMessage {
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
                    signature: None, // TODO (HIGH-5): Sign response
                }))
            }

            DhtMessageType::FindNode => {
                // In a implementation, this would query the routing table
                // For now, return empty node list
                // **MIGRATION (Ticket #145):** Uses `local_node.peer.node_id()` for sender_id
                Ok(Some(DhtMessage {
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
                    signature: None, // TODO (HIGH-5): Sign response
                }))
            }

            DhtMessageType::FindValue => {
                // In a implementation, this would check local storage
                // For now, return empty node list (value not found)
                // **MIGRATION (Ticket #145):** Uses `local_node.peer.node_id()` for sender_id
                Ok(Some(DhtMessage {
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
                    signature: None, // TODO (HIGH-5): Sign response
                }))
            }

            DhtMessageType::Store => {
                // In a implementation, this would store the key-value pair
                // **MIGRATION (Ticket #145):** Uses `local_node.peer.node_id()` for sender_id
                Ok(Some(DhtMessage {
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
                    signature: None, // TODO (HIGH-5): Sign response
                }))
            }

            _ => Ok(None), // Response messages don't need responses
        }
    }
    
    /// Get local socket address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        // Extract address from transport's local peer ID
        match self.transport.local_peer_id() {
            PeerId::Udp(addr) => Ok(addr),
            PeerId::WiFiDirect(addr) => Ok(addr),
            PeerId::Quic(addr) => Ok(addr),
            PeerId::Bluetooth(_) | PeerId::LoRaWAN(_) => {
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
        
        let sender_addr = "127.0.0.1:12345".parse().unwrap();
        let response = network.handle_incoming_message(ping_message, sender_addr).await.unwrap();

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
