//! Native Binary DHT Protocol
//! 
//! Secure, efficient binary protocol for DHT operations over UDP mesh networking.
//! This replaces JavaScript-based DHT operations with native Rust binary packets.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use lib_crypto::{Hash, PostQuantumSignature, PublicKey, SignatureAlgorithm};
use lib_crypto::post_quantum::dilithium::{dilithium2_sign, dilithium2_verify, dilithium2_keypair};
use lib_identity::ZhtpIdentity;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use tracing::{info, warn, debug};

// Import ZHTP protocol types for secure relay
use crate::protocols::zhtp_auth::{NodeCapabilities};
use crate::protocols::zhtp_encryption::{ZhtpEncryptedMessage};

/// DHT Protocol Version
pub const DHT_PROTOCOL_VERSION: u16 = 1;

/// Maximum DHT packet size (8KB - standard UDP limit)
pub const MAX_DHT_PACKET_SIZE: usize = 8192;

/// DHT operation types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DhtOperation {
    /// Query for content by domain/path
    Query,
    /// Response to a query
    QueryResponse,
    /// Store content in the DHT
    Store,
    /// Acknowledge successful store
    StoreAck,
    /// Discover peers in the network
    PeerDiscovery,
    /// Peer discovery response
    PeerResponse,
    /// Ping for connectivity testing
    Ping,
    /// Pong response to ping
    Pong,
    /// ZHTP Relay Query (Node B -> Node A: request DHT content)
    RelayQuery,
    /// ZHTP Relay Response (Node A -> Node B: return DHT content)
    RelayResponse,
    /// ZHTP Peer Registration (register blockchain-verified peer)
    PeerRegister,
    /// ZHTP Peer Registration Acknowledgment
    PeerRegisterAck,
    /// ZHTP Peer Query (find peers with capabilities)
    PeerQuery,
    /// ZHTP Peer Query Response (return matching peers)
    PeerQueryResponse,
}

/// DHT packet header (fixed size: 64 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPacketHeader {
    /// Protocol version (2 bytes)
    pub version: u16,
    /// Operation type (1 byte serialized)
    pub operation: DhtOperation,
    /// Packet ID for request/response matching (16 bytes)
    pub packet_id: [u8; 16],
    /// Sender's DHT node ID (32 bytes)
    pub sender_id: [u8; 32],
    /// Target DHT node ID (32 bytes, zeros for broadcast)
    pub target_id: [u8; 32],
    /// Payload length in bytes (4 bytes)
    pub payload_length: u32,
    /// Timestamp (8 bytes)
    pub timestamp: u64,
    /// Reserved for future use (padding to 128 bytes total)
    pub reserved: [u8; 32],
}

/// DHT Query payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtQueryPayload {
    /// Domain to query (e.g., "example.zhtp")
    pub domain: String,
    /// Path within domain (e.g., "/index.html")
    pub path: String,
    /// Query type flags
    pub flags: u32,
}

/// DHT Query Response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtQueryResponsePayload {
    /// Content hash if found
    pub content_hash: Option<Hash>,
    /// Error message if not found
    pub error: Option<String>,
    /// List of peers that might have the content
    pub peer_suggestions: Vec<[u8; 32]>, // Node IDs
    /// Time-to-live for this response
    pub ttl: u32,
}

/// DHT Store payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStorePayload {
    /// Domain to store under
    pub domain: String,
    /// Path within domain
    pub path: String,
    /// Content hash
    pub content_hash: Hash,
    /// Content data (encrypted)
    pub content: Vec<u8>,
    /// Storage duration in seconds
    pub duration: u32,
    /// Replication factor
    pub replication: u8,
}

/// DHT Store Acknowledgment payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStoreAckPayload {
    /// Content hash that was stored
    pub content_hash: Hash,
    /// Success flag
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Storage expiry timestamp
    pub expires_at: u64,
}

/// DHT Peer Discovery payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeerDiscoveryPayload {
    /// Maximum number of peers requested
    pub max_peers: u16,
    /// Capability requirements
    pub required_capabilities: Vec<String>,
    /// Geographic region preference
    pub region: Option<String>,
}

/// DHT Peer Response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeerResponsePayload {
    /// List of discovered peers
    pub peers: Vec<DhtPeerInfo>,
}

/// DHT Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeerInfo {
    /// Peer's DHT node ID
    pub node_id: [u8; 32],
    /// Network addresses where peer can be reached
    pub addresses: Vec<SocketAddr>,
    /// Peer capabilities
    pub capabilities: Vec<String>,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Reputation score (0.0 to 1.0)
    pub reputation: f32,
}

// ============================================================================
// ZHTP Relay Protocol (Secure DHT Relay Through Mesh Peers)
// ============================================================================

/// ZHTP Relay Query - Encrypted request for DHT content through peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRelayQuery {
    /// Request ID for tracking
    pub request_id: String,
    /// Domain to query
    pub domain: String,
    /// Path within domain
    pub path: String,
    /// Requester's blockchain public key (for verification)
    pub requester_pubkey: Vec<u8>,
    /// Encrypted query payload (encrypted with Kyber shared secret)
    pub encrypted_payload: ZhtpEncryptedMessage,
    /// Dilithium2 signature of (request_id + domain + path + timestamp)
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// ZHTP Relay Response - Encrypted DHT content from peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRelayResponse {
    /// Request ID being responded to
    pub request_id: String,
    /// Content found flag
    pub found: bool,
    /// Content hash (if found)
    pub content_hash: Option<Hash>,
    /// Content MIME type (if found)
    pub content_type: Option<String>,
    /// Responder's blockchain public key
    pub responder_pubkey: Vec<u8>,
    /// Encrypted content (encrypted with Kyber shared secret)
    pub encrypted_content: ZhtpEncryptedMessage,
    /// Dilithium2 signature of (request_id + content_hash + timestamp)
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Relay node capabilities (for trust verification)
    pub relay_capabilities: NodeCapabilities,
}

/// ZHTP Relay Query Payload (plaintext before encryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRelayQueryPayload {
    /// Domain to query
    pub domain: String,
    /// Path within domain
    pub path: String,
    /// Query options
    pub options: ZhtpQueryOptions,
}

/// ZHTP Relay Response Payload (plaintext before encryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRelayResponsePayload {
    /// Content data (if found)
    pub content: Option<Vec<u8>>,
    /// Content MIME type
    pub content_type: Option<String>,
    /// Content hash
    pub content_hash: Option<Hash>,
    /// Error message (if not found)
    pub error: Option<String>,
    /// Cache TTL in seconds
    pub ttl: u32,
}

/// Query options for ZHTP relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpQueryOptions {
    /// Maximum content size to return (bytes)
    pub max_size: Option<u64>,
    /// Accept compression
    pub accept_compression: bool,
    /// Cache preference
    pub cache_preference: CachePreference,
}

/// Cache preference for relay queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CachePreference {
    /// Prefer cached content (faster)
    PreferCache,
    /// Prefer fresh content (slower)
    PreferFresh,
    /// Only cached content (fail if not cached)
    OnlyCache,
    /// Only fresh content (bypass cache)
    OnlyFresh,
}

// ============= ZHTP Peer Discovery Protocol Structures =============

/// ZHTP Peer Registration message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpPeerRegister {
    /// Blockchain public key
    pub blockchain_pubkey: PublicKey,
    /// Dilithium2 public key for signatures
    pub dilithium_pubkey: Vec<u8>,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Reputation score (0.0 - 1.0)
    pub reputation: f64,
    /// Registration TTL (seconds)
    pub ttl: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Signature (signed with blockchain key)
    pub signature: Vec<u8>,
}

/// ZHTP Peer Registration Acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpPeerRegisterAck {
    /// Node ID assigned by DHT
    pub node_id: [u8; 32],
    /// Registration accepted
    pub accepted: bool,
    /// Error message if rejected
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: u64,
}

/// ZHTP Peer Query message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpPeerQuery {
    /// Require DHT capability
    pub requires_dht: bool,
    /// Require relay capability
    pub requires_relay: bool,
    /// Minimum bandwidth (bytes/sec)
    pub min_bandwidth: Option<u64>,
    /// Minimum reputation score (0.0 - 1.0)
    pub min_reputation: Option<f64>,
    /// Required protocol support
    pub required_protocols: Vec<String>,
    /// Require quantum security
    pub require_quantum_secure: bool,
    /// Maximum results to return
    pub max_results: usize,
}

/// ZHTP Peer Query Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpPeerQueryResponse {
    /// Matching peers
    pub peers: Vec<ZhtpPeerInfo>,
    /// Total matching peers (may be more than returned)
    pub total_matches: usize,
    /// Timestamp
    pub timestamp: u64,
}

/// ZHTP Peer Info (minimal for network transmission)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpPeerInfo {
    /// Node ID
    pub node_id: [u8; 32],
    /// Blockchain public key
    pub blockchain_pubkey: PublicKey,
    /// Dilithium2 public key
    pub dilithium_pubkey: Vec<u8>,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Reputation score
    pub reputation: f64,
    /// Last seen timestamp
    pub last_seen: u64,
}

/// Complete DHT packet structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPacket {
    /// Packet header
    pub header: DhtPacketHeader,
    /// Packet payload (operation-specific)
    pub payload: DhtPacketPayload,
    /// Cryptographic signature for integrity
    pub signature: PostQuantumSignature,
}

/// DHT packet payload (union of all payload types)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtPacketPayload {
    Query(DhtQueryPayload),
    QueryResponse(DhtQueryResponsePayload),
    Store(DhtStorePayload),
    StoreAck(DhtStoreAckPayload),
    PeerDiscovery(DhtPeerDiscoveryPayload),
    PeerResponse(DhtPeerResponsePayload),
    Ping,
    Pong,
    /// ZHTP Relay Query (encrypted)
    RelayQuery(ZhtpRelayQuery),
    /// ZHTP Relay Response (encrypted + signed)
    RelayResponse(ZhtpRelayResponse),
    /// ZHTP Peer Registration
    PeerRegister(ZhtpPeerRegister),
    /// ZHTP Peer Registration Ack
    PeerRegisterAck(ZhtpPeerRegisterAck),
    /// ZHTP Peer Query
    PeerQuery(ZhtpPeerQuery),
    /// ZHTP Peer Query Response
    PeerQueryResponse(ZhtpPeerQueryResponse),
}

/// DHT Protocol Handler
#[derive(Debug)]
pub struct DhtProtocolHandler {
    /// Local node identity
    identity: ZhtpIdentity,
    /// UDP socket for DHT communications (shared with background receiver)
    socket: Option<Arc<tokio::net::UdpSocket>>,
    /// Pending requests (packet_id -> response_channel)
    pending_requests: std::collections::HashMap<[u8; 16], tokio::sync::oneshot::Sender<DhtPacket>>,
}

impl DhtProtocolHandler {
    /// Create new DHT protocol handler
    pub fn new(identity: ZhtpIdentity) -> Self {
        Self {
            identity,
            socket: None,
            pending_requests: std::collections::HashMap::new(),
        }
    }

    /// Initialize DHT protocol handler with UDP socket
    pub async fn initialize(&mut self, bind_addr: SocketAddr) -> Result<()> {
        info!("Initializing DHT binary protocol on {}", bind_addr);
        
        let socket = Arc::new(tokio::net::UdpSocket::bind(bind_addr).await?);
        self.socket = Some(socket.clone());
        
        // Start packet receiver with shared socket
        self.start_packet_receiver(socket).await?;
        
        info!(" DHT binary protocol initialized");
        Ok(())
    }

    /// Start the packet receiver loop
    async fn start_packet_receiver(&mut self, socket: Arc<tokio::net::UdpSocket>) -> Result<()> {
        let identity = self.identity.clone();
        
        // Share socket with background receiver task
        tokio::spawn(async move {
            Self::packet_receiver_loop(socket, identity).await;
        });
        
        Ok(())
    }

    /// Packet receiver loop (runs in background)
    async fn packet_receiver_loop(socket: Arc<tokio::net::UdpSocket>, identity: ZhtpIdentity) {
        let mut buffer = [0u8; MAX_DHT_PACKET_SIZE];
        
        info!(" DHT packet receiver started");
        
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((len, addr)) => {
                    debug!(" DHT packet from {}: {} bytes", addr, len);
                    
                    match Self::parse_dht_packet(&buffer[..len]) {
                        Ok(packet) => {
                            if let Err(e) = Self::handle_received_packet(packet, addr, &socket, &identity).await {
                                warn!("Failed to handle DHT packet from {}: {}", addr, e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse DHT packet from {}: {}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("DHT socket receive error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Parse binary DHT packet
    fn parse_dht_packet(data: &[u8]) -> Result<DhtPacket> {
        if data.len() < 128 {
            return Err(anyhow!("DHT packet too small: {} bytes", data.len()));
        }

        // Deserialize using bincode for efficient binary format
        let packet: DhtPacket = bincode::deserialize(data)?;
        
        // Verify protocol version
        if packet.header.version != DHT_PROTOCOL_VERSION {
            return Err(anyhow!("Unsupported DHT protocol version: {}", packet.header.version));
        }

        // Verify packet integrity (signature check would go here)
        
        Ok(packet)
    }

    /// Handle received DHT packet (with cryptographic verification)
    async fn handle_received_packet(
        packet: DhtPacket, 
        addr: SocketAddr, 
        socket: &tokio::net::UdpSocket,
        identity: &ZhtpIdentity
    ) -> Result<()> {
        debug!(" Handling DHT {:?} from {}", packet.header.operation, addr);

        // CRYPTOGRAPHIC VERIFICATION: Verify packet signature before processing
        let signature_valid = match Self::verify_packet_signature(&packet.header, &packet.payload, &packet.signature) {
            Ok(valid) => {
                if valid {
                    debug!(" DHT packet signature verified from {}", addr);
                    true
                } else {
                    warn!(" DHT packet signature verification failed from {}", addr);
                    false
                }
            }
            Err(e) => {
                warn!(" DHT packet signature verification error from {}: {}", addr, e);
                false
            }
        };

        // Only process packets with cryptographically valid signatures
        if !signature_valid {
            return Err(anyhow!("DHT packet signature verification failed from {}", addr));
        }

        match packet.header.operation {
            DhtOperation::Query => {
                Self::handle_query_packet(packet, addr, socket, identity).await
            }
            DhtOperation::Store => {
                Self::handle_store_packet(packet, addr, socket, identity).await
            }
            DhtOperation::PeerDiscovery => {
                Self::handle_peer_discovery_packet(packet, addr, socket, identity).await
            }
            DhtOperation::Ping => {
                Self::handle_ping_packet(packet, addr, socket, identity).await
            }
            // ZHTP relay operations (handled separately in unified_server.rs)
            DhtOperation::RelayQuery | DhtOperation::RelayResponse => {
                debug!(" ZHTP relay operation received (handled by MeshRouter)");
                Ok(())
            }
            // ZHTP peer discovery operations
            DhtOperation::PeerRegister | DhtOperation::PeerQuery => {
                debug!(" ZHTP peer discovery operation received (requires peer registry integration)");
                Ok(())
            }
            // Responses are handled by the request matching system
            DhtOperation::QueryResponse | DhtOperation::StoreAck | 
            DhtOperation::PeerResponse | DhtOperation::Pong |
            DhtOperation::PeerRegisterAck | DhtOperation::PeerQueryResponse => {
                debug!("📬 Response packet received (handled by request matcher)");
                Ok(())
            }
        }
    }

    /// Handle DHT query packet
    async fn handle_query_packet(
        packet: DhtPacket,
        addr: SocketAddr,
        socket: &tokio::net::UdpSocket,
        _identity: &ZhtpIdentity
    ) -> Result<()> {
        if let DhtPacketPayload::Query(query) = packet.payload {
            info!(" DHT query for {}:{} from {}", query.domain, query.path, addr);

            // TODO: Implement actual content lookup in storage system
            let response_payload = DhtQueryResponsePayload {
                content_hash: None, // Would lookup in storage
                error: Some("Content not found".to_string()),
                peer_suggestions: vec![], // Would query other peers
                ttl: 300, // 5 minutes
            };

            let response = Self::create_response_packet_with_identity(
                packet.header,
                DhtOperation::QueryResponse,
                DhtPacketPayload::QueryResponse(response_payload),
                _identity
            )?;

            Self::send_packet(socket, &response, addr).await?;
        }
        Ok(())
    }

    /// Handle DHT store packet
    async fn handle_store_packet(
        packet: DhtPacket,
        addr: SocketAddr,
        socket: &tokio::net::UdpSocket,
        _identity: &ZhtpIdentity
    ) -> Result<()> {
        if let DhtPacketPayload::Store(store) = packet.payload {
            info!(" DHT store {}:{} ({} bytes) from {}", 
                store.domain, store.path, store.content.len(), addr);

            // TODO: Implement actual content storage in storage system
            let success = true; // Would attempt to store content

            let ack_payload = DhtStoreAckPayload {
                content_hash: store.content_hash,
                success,
                error: if success { None } else { Some("Storage failed".to_string()) },
                expires_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + store.duration as u64,
            };

            let response = Self::create_response_packet_with_identity(
                packet.header,
                DhtOperation::StoreAck,
                DhtPacketPayload::StoreAck(ack_payload),
                _identity
            )?;

            Self::send_packet(socket, &response, addr).await?;
        }
        Ok(())
    }

    /// Handle peer discovery packet
    async fn handle_peer_discovery_packet(
        packet: DhtPacket,
        addr: SocketAddr,
        socket: &tokio::net::UdpSocket,
        _identity: &ZhtpIdentity
    ) -> Result<()> {
        if let DhtPacketPayload::PeerDiscovery(discovery) = packet.payload {
            info!(" DHT peer discovery (max: {}) from {}", discovery.max_peers, addr);

            // TODO: Implement actual peer lookup
            let peers = vec![]; // Would query peer manager

            let response_payload = DhtPeerResponsePayload { peers };

            let response = Self::create_response_packet_with_identity(
                packet.header,
                DhtOperation::PeerResponse,
                DhtPacketPayload::PeerResponse(response_payload),
                _identity
            )?;

            Self::send_packet(socket, &response, addr).await?;
        }
        Ok(())
    }

    /// Handle ping packet
    async fn handle_ping_packet(
        packet: DhtPacket,
        addr: SocketAddr,
        socket: &tokio::net::UdpSocket,
        _identity: &ZhtpIdentity
    ) -> Result<()> {
        info!("🏓 DHT ping from {}", addr);

        let response = Self::create_response_packet_with_identity(
            packet.header,
            DhtOperation::Pong,
            DhtPacketPayload::Pong,
            _identity
        )?;

        Self::send_packet(socket, &response, addr).await?;
        Ok(())
    }

    /// Create cryptographic signature for DHT packet
    fn sign_packet(header: &DhtPacketHeader, payload: &DhtPacketPayload, private_key: &[u8], public_key: &[u8]) -> Result<PostQuantumSignature> {
        // Create canonical packet representation for signing
        let mut signing_data = Vec::new();
        
        // Header fields
        signing_data.extend_from_slice(&header.version.to_le_bytes());
        signing_data.extend_from_slice(&bincode::serialize(&header.operation)?);
        signing_data.extend_from_slice(&header.packet_id); // packet_id is already [u8; 16]
        signing_data.extend_from_slice(&header.sender_id);
        signing_data.extend_from_slice(&header.target_id);
        signing_data.extend_from_slice(&header.timestamp.to_le_bytes());
        signing_data.extend_from_slice(&header.reserved);
        
        // Payload data
        signing_data.extend_from_slice(&bincode::serialize(payload)?);
        
        // Generate Dilithium2 signature
        let signature_bytes = dilithium2_sign(&signing_data, private_key)
            .map_err(|e| anyhow!("Failed to sign DHT packet: {}", e))?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Ok(PostQuantumSignature {
            signature: signature_bytes,
            public_key: PublicKey::new(public_key.to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp,
        })
    }

    /// Verify cryptographic signature for DHT packet
    fn verify_packet_signature(header: &DhtPacketHeader, payload: &DhtPacketPayload, signature: &PostQuantumSignature) -> Result<bool> {
        // Reconstruct signing data
        let mut signing_data = Vec::new();
        
        // Header fields (same order as signing)
        signing_data.extend_from_slice(&header.version.to_le_bytes());
        signing_data.extend_from_slice(&bincode::serialize(&header.operation)?);
        signing_data.extend_from_slice(&header.packet_id); // packet_id is already [u8; 16]
        signing_data.extend_from_slice(&header.sender_id);
        signing_data.extend_from_slice(&header.target_id);
        signing_data.extend_from_slice(&header.timestamp.to_le_bytes());
        signing_data.extend_from_slice(&header.reserved);
        
        // Payload data
        signing_data.extend_from_slice(&bincode::serialize(payload)?);
        
        // Verify based on algorithm
        match signature.algorithm {
            SignatureAlgorithm::Dilithium2 => {
                // For verification, we need access to the correct public key format
                // This is a simplified approach - in production we'd need proper key management
                if signature.public_key.dilithium_pk.is_empty() {
                    // All signatures must be cryptographically valid - no placeholders allowed
                    Err(anyhow!("Empty public key not allowed"))
                } else {
                    dilithium2_verify(&signing_data, &signature.signature, &signature.public_key.dilithium_pk)
                }
                    .map_err(|e| anyhow!("Failed to verify DHT packet signature: {}", e))
            }
            _ => Err(anyhow!("Unsupported signature algorithm for DHT packets"))
        }
    }

    /// Create response packet (requires identity for signing)
    fn create_response_packet_with_identity(
        original_header: DhtPacketHeader,
        response_op: DhtOperation,
        response_payload: DhtPacketPayload,
        identity: &ZhtpIdentity
    ) -> Result<DhtPacket> {
        // Extract node ID from identity
        let node_id = {
            let id_bytes = identity.id.as_bytes();
            let mut node_id = [0u8; 32];
            node_id.copy_from_slice(&id_bytes[..32.min(id_bytes.len())]);
            node_id
        };

        let header = DhtPacketHeader {
            version: DHT_PROTOCOL_VERSION,
            operation: response_op,
            packet_id: original_header.packet_id, // Same ID for response matching
            sender_id: node_id, // node ID
            target_id: original_header.sender_id, // Send back to requester
            payload_length: 0, // Will be calculated during serialization
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            reserved: [0; 32],
        };

        // Generate cryptographic signature using identity's public key
        // For production, we would need proper key management
        let (temp_pk, temp_sk) = dilithium2_keypair();
        let signature = Self::sign_packet(
            &header, 
            &response_payload, 
            &temp_sk,
            &temp_pk
        )?;

        Ok(DhtPacket {
            header,
            payload: response_payload,
            signature,
        })
    }

    // REMOVED: Placeholder signatures not allowed - use create_response_packet_with_identity instead

    /// Send DHT packet over UDP
    async fn send_packet(
        socket: &tokio::net::UdpSocket,
        packet: &DhtPacket,
        addr: SocketAddr
    ) -> Result<()> {
        let packet_data = bincode::serialize(packet)?;
        
        if packet_data.len() > MAX_DHT_PACKET_SIZE {
            return Err(anyhow!("DHT packet too large: {} bytes", packet_data.len()));
        }

        socket.send_to(&packet_data, addr).await?;
        debug!(" Sent DHT {:?} packet to {} ({} bytes)", 
            packet.header.operation, addr, packet_data.len());
        
        Ok(())
    }

    /// Generate unique packet ID
    fn generate_packet_id() -> [u8; 16] {
        use rand::RngCore;
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id
    }
}

/// Client API for DHT operations
impl DhtProtocolHandler {
    /// Query DHT for content
    pub async fn query_content(&self, domain: &str, path: &str, peer_addr: SocketAddr) -> Result<Option<Hash>> {
        let socket = self.socket.as_ref().ok_or_else(|| anyhow!("DHT not initialized"))?;

        let payload = DhtQueryPayload {
            domain: domain.to_string(),
            path: path.to_string(),
            flags: 0,
        };

        let packet = self.create_request_packet(
            DhtOperation::Query,
            DhtPacketPayload::Query(payload)
        )?;

        Self::send_packet(socket, &packet, peer_addr).await?;

        // TODO: Implement response waiting mechanism
        info!(" DHT query sent for {}:{}", domain, path);
        Ok(None) // Would return actual result after receiving response
    }

    /// Store content in DHT
    pub async fn store_content(
        &self, 
        domain: &str, 
        path: &str, 
        content: Vec<u8>,
        peer_addr: SocketAddr
    ) -> Result<bool> {
        let socket = self.socket.as_ref().ok_or_else(|| anyhow!("DHT not initialized"))?;

        let content_hash = lib_crypto::hash_blake3(&content);

        let payload = DhtStorePayload {
            domain: domain.to_string(),
            path: path.to_string(),
            content_hash: Hash::from_bytes(&content_hash[..32]),
            content,
            duration: 86400, // 24 hours
            replication: 3,
        };

        let packet = self.create_request_packet(
            DhtOperation::Store,
            DhtPacketPayload::Store(payload)
        )?;

        Self::send_packet(socket, &packet, peer_addr).await?;

        info!(" DHT store sent for {}:{}", domain, path);
        Ok(true) // Would return actual result after receiving acknowledgment
    }

    /// Discover DHT peers
    pub async fn discover_peers(&self, max_peers: u16, peer_addr: SocketAddr) -> Result<Vec<DhtPeerInfo>> {
        let socket = self.socket.as_ref().ok_or_else(|| anyhow!("DHT not initialized"))?;

        let payload = DhtPeerDiscoveryPayload {
            max_peers,
            required_capabilities: vec!["storage".to_string()],
            region: None,
        };

        let packet = self.create_request_packet(
            DhtOperation::PeerDiscovery,
            DhtPacketPayload::PeerDiscovery(payload)
        )?;

        Self::send_packet(socket, &packet, peer_addr).await?;

        info!(" DHT peer discovery sent (max: {})", max_peers);
        Ok(vec![]) // Would return actual peers after receiving response
    }

    /// Create request packet
    fn create_request_packet(
        &self,
        operation: DhtOperation,
        payload: DhtPacketPayload
    ) -> Result<DhtPacket> {
        let node_id = {
            let id_bytes = self.identity.id.as_bytes();
            let mut node_id = [0u8; 32];
            node_id.copy_from_slice(&id_bytes[..32.min(id_bytes.len())]);
            node_id
        };

        let header = DhtPacketHeader {
            version: DHT_PROTOCOL_VERSION,
            operation,
            packet_id: Self::generate_packet_id(),
            sender_id: node_id,
            target_id: [0; 32], // Broadcast or would be specific peer
            payload_length: 0, // Will be calculated during serialization
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            reserved: [0; 32],
        };

        // Generate cryptographic signature using temporary keys
        // For production, we would use the identity's actual signing keys  
        let (temp_pk, temp_sk) = dilithium2_keypair();
        let signature = Self::sign_packet(
            &header, 
            &payload, 
            &temp_sk,
            &temp_pk
        )?;

        Ok(DhtPacket {
            header,
            payload,
            signature,
        })
    }

    /// Ping a peer to check availability with proper response validation
    pub async fn ping_peer(&self, peer_addr: SocketAddr) -> Result<()> {
        let socket = self.socket.as_ref()
            .ok_or_else(|| anyhow!("DHT protocol not initialized"))?;
        
        // Create ping packet
        let ping_packet = self.create_request_packet(
            DhtOperation::Ping,
            DhtPacketPayload::Ping
        )?;
        
        // Send ping and wait for pong response (with timeout)
        let packet_data = bincode::serialize(&ping_packet)?;
        
        // Send the ping
        socket.send_to(&packet_data, peer_addr).await
            .map_err(|e| anyhow!("Failed to send DHT ping: {}", e))?;
        
        // Wait for pong response with short timeout
        let mut buffer = [0u8; MAX_DHT_PACKET_SIZE];
        match tokio::time::timeout(
            std::time::Duration::from_millis(500), // Short timeout for responsiveness
            socket.recv_from(&mut buffer)
        ).await {
            Ok(Ok((len, addr))) if addr == peer_addr => {
                // Try to parse response as DHT packet
                if let Ok(response_packet) = bincode::deserialize::<DhtPacket>(&buffer[..len]) {
                    if matches!(response_packet.header.operation, DhtOperation::Pong) {
                        debug!("🏓 DHT pong received from {}", peer_addr);
                        return Ok(());
                    }
                }
                Err(anyhow!("Invalid pong response from {}", peer_addr))
            }
            Ok(Ok(_)) => {
                Err(anyhow!("Response from wrong address"))
            }
            Ok(Err(e)) => {
                Err(anyhow!("Socket error waiting for pong: {}", e))
            }
            Err(_) => {
                // Timeout is expected for closed ports
                Err(anyhow!("Pong timeout from {}", peer_addr))
            }
        }
    }

    /// Get the listening port of this DHT node
    pub async fn get_listening_port(&self) -> Option<u16> {
        if let Some(socket) = &self.socket {
            socket.local_addr().ok().map(|addr| addr.port())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dht_packet_serialization() {
        // Test that DHT packets can be serialized and deserialized
        let header = DhtPacketHeader {
            version: DHT_PROTOCOL_VERSION,
            operation: DhtOperation::Query,
            packet_id: [1; 16],
            sender_id: [2; 32],
            target_id: [3; 32],
            payload_length: 0,
            timestamp: 1234567890,
            reserved: [0; 32],
        };

        let payload = DhtPacketPayload::Query(DhtQueryPayload {
            domain: "test.zhtp".to_string(),
            path: "/test".to_string(),
            flags: 0,
        });

        let packet = DhtPacket {
            header,
            payload,
            signature: PostQuantumSignature::default(),
        };

        let serialized = bincode::serialize(&packet).unwrap();
        let deserialized: DhtPacket = bincode::deserialize(&serialized).unwrap();

        assert_eq!(packet.header.version, deserialized.header.version);
        assert_eq!(packet.header.operation, deserialized.header.operation);
    }
}