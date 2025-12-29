//! Mesh Message Types for Multi-Hop Routing
//!
//! Defines message envelopes and payload types for mesh network communication
//!
//! **OPTIMIZED (Issue #479):** Single-pass serialization architecture
//! - Payload is pre-serialized to avoid double serialization overhead
//! - MessageType discriminator enables type identification without deserializing

use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::geographic::GeographicLocation;
use crate::types::mesh_capability::{MeshCapability, SharedResources};
use crate::types::connection_details::ConnectionDetails;
use lib_protocols::types::{ZhtpRequest as ProtocolZhtpRequest, ZhtpResponse as ProtocolZhtpResponse};
use lib_protocols::types::{ZhtpMethod, ZhtpStatus};

/// Default TTL for mesh messages (32 hops)
pub const DEFAULT_TTL: u8 = 32;

/// Maximum message size (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Message type discriminator for single-pass serialization (Issue #479)
///
/// Enables type identification without deserializing the payload.
/// Uses `repr(u8)` for stable binary representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    PeerDiscovery = 1,
    PeerAnnouncement = 2,
    ConnectivityRequest = 3,
    ConnectivityResponse = 4,
    LongRangeRoute = 5,
    UbiDistribution = 6,
    HealthReport = 7,
    ZhtpRequest = 8,
    ZhtpResponse = 9,
    BlockchainRequest = 10,
    BlockchainData = 11,
    NewBlock = 12,
    NewTransaction = 13,
    RouteProbe = 14,
    RouteResponse = 15,
    BootstrapProofRequest = 16,
    BootstrapProofResponse = 17,
    HeadersRequest = 18,
    HeadersResponse = 19,
    DhtStore = 20,
    DhtStoreAck = 21,
    DhtFindValue = 22,
    DhtFindValueResponse = 23,
    DhtFindNode = 24,
    DhtFindNodeResponse = 25,
    DhtPing = 26,
    DhtPong = 27,
    DhtGenericPayload = 28,
}

/// Message envelope for multi-hop routing
///
/// **OPTIMIZED (Issue #479):** Single-pass serialization
/// - `message_type`: Type discriminator for efficient routing decisions
/// - `payload`: Pre-serialized message bytes (avoids double serialization)
/// - ZHTP fields: Method, URI, and Status extracted for fast routing decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMessageEnvelope {
    /// Unique message identifier
    pub message_id: u64,
    /// Origin node public key
    pub origin: PublicKey,
    /// Destination node public key
    pub destination: PublicKey,
    /// Time-to-live (decremented at each hop)
    pub ttl: u8,
    /// Number of hops taken (for reward calculation)
    pub hop_count: u8,
    /// Route history for loop prevention
    pub route_history: Vec<PublicKey>,
    /// Message timestamp
    pub timestamp: u64,
    /// Message type discriminator (Issue #479)
    pub message_type: MessageType,
    /// Pre-serialized payload bytes (Issue #479)
    /// For ZHTP messages: contains (headers, body) tuple
    /// For other messages: contains full message
    pub payload: Vec<u8>,
    
    // ZHTP-specific fields for single-pass serialization (only populated for ZhtpRequest/Response)
    /// ZHTP request method (for routing decisions without deserializing)
    #[serde(default)]
    pub zhtp_method: Option<ZhtpMethod>,
    /// ZHTP request URI (for content routing without deserializing)
    #[serde(default)]
    pub zhtp_uri: Option<String>,
    /// ZHTP response status (for response routing without deserializing)
    #[serde(default)]
    pub zhtp_status: Option<ZhtpStatus>,
}


impl MeshMessageEnvelope {
    /// Create a new message envelope from pre-serialized payload
    ///
    /// **OPTIMIZED (Issue #479):** For single-pass serialization.
    /// Use `from_message()` helper if you have a `ZhtpMeshMessage`.
    pub fn new(
        message_id: u64,
        origin: PublicKey,
        destination: PublicKey,
        message_type: MessageType,
        payload: Vec<u8>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            message_id,
            origin,
            destination,
            ttl: DEFAULT_TTL,
            hop_count: 0,
            route_history: Vec::new(),
            timestamp,
            message_type,
            payload,
            zhtp_method: None,
            zhtp_uri: None,
            zhtp_status: None,
        }
    }

    /// Create envelope from ZhtpMeshMessage (Issue #479)
    ///
    /// **OPTIMIZED:** Serializes the message payload once and determines the type.
    /// This is the preferred way to create envelopes from message variants.
    pub fn from_message(
        message_id: u64,
        origin: PublicKey,
        destination: PublicKey,
        message: ZhtpMeshMessage,
    ) -> Result<Self> {
        // Special handling for ZHTP messages to enable single-pass serialization
        match &message {
            ZhtpMeshMessage::ZhtpRequest(request) => {
                Self::from_zhtp_request(message_id, origin, destination, request.clone())
            },
            ZhtpMeshMessage::ZhtpResponse(response) => {
                Self::from_zhtp_response(message_id, origin, destination, response.clone())
            },
            _ => {
                // For non-ZHTP messages, use standard serialization
                let (message_type, payload) = message.serialize_with_type()?;
                Ok(Self::new(message_id, origin, destination, message_type, payload))
            }
        }
    }

    /// Create envelope from ZHTP request with single-pass serialization
    ///
    /// **OPTIMIZED:** Only serializes headers + body, extracts method/URI to envelope fields
    pub fn from_zhtp_request(
        message_id: u64,
        origin: PublicKey,
        destination: PublicKey,
        request: ProtocolZhtpRequest,
    ) -> Result<Self> {
        // SECURITY: Serialize headers, body, requester, and auth_proof (not the full request)
        // This preserves authentication data through mesh routing
        let payload = bincode::serialize(&(&request.headers, &request.body, &request.requester, &request.auth_proof))
            .map_err(|e| anyhow!("Failed to serialize ZHTP request: {}", e))?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            message_id,
            origin,
            destination,
            ttl: DEFAULT_TTL,
            hop_count: 0,
            route_history: Vec::new(),
            timestamp,
            message_type: MessageType::ZhtpRequest,
            payload,
            zhtp_method: Some(request.method),
            zhtp_uri: Some(request.uri),
            zhtp_status: None,
        })
    }

    /// Create envelope from ZHTP response with single-pass serialization
    ///
    /// **OPTIMIZED:** Only serializes headers + body, extracts status to envelope field
    pub fn from_zhtp_response(
        message_id: u64,
        origin: PublicKey,
        destination: PublicKey,
        response: ProtocolZhtpResponse,
    ) -> Result<Self> {
        // SECURITY: Serialize headers, body, server, and validity_proof (not the full response)
        // This preserves response authentication data through mesh routing
        let payload = bincode::serialize(&(&response.headers, &response.body, &response.server, &response.validity_proof))
            .map_err(|e| anyhow!("Failed to serialize ZHTP response: {}", e))?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            message_id,
            origin,
            destination,
            ttl: DEFAULT_TTL,
            hop_count: 0,
            route_history: Vec::new(),
            timestamp,
            message_type: MessageType::ZhtpResponse,
            payload,
            zhtp_method: None,
            zhtp_uri: None,
            zhtp_status: Some(response.status),
        })
    }

    /// Deserialize the payload into a ZhtpMeshMessage (Issue #479)
    ///
    /// **OPTIMIZED:** Single deserialization pass using the type discriminator.
    /// For ZHTP messages, reconstructs from envelope fields + payload.
    pub fn deserialize_message(&self) -> Result<ZhtpMeshMessage> {
        match self.message_type {
            MessageType::ZhtpRequest => {
                let request = self.to_zhtp_request()?;
                Ok(ZhtpMeshMessage::ZhtpRequest(request))
            },
            MessageType::ZhtpResponse => {
                let response = self.to_zhtp_response()?;
                Ok(ZhtpMeshMessage::ZhtpResponse(response))
            },
            _ => {
                // For non-ZHTP messages, use standard deserialization
                ZhtpMeshMessage::deserialize_from_type(self.message_type, &self.payload)
            }
        }
    }

    /// Reconstruct ZHTP request from envelope with single-pass deserialization
    ///
    /// **OPTIMIZED:** Deserializes headers, body, requester, auth_proof; uses envelope fields for method/URI
    pub fn to_zhtp_request(&self) -> Result<ProtocolZhtpRequest> {
        if self.message_type != MessageType::ZhtpRequest {
            return Err(anyhow!("Not a ZhtpRequest message"));
        }

        // Deserialize headers, body, requester, auth_proof from payload
        let (headers, body, requester, auth_proof): (
            lib_protocols::types::ZhtpHeaders,
            Vec<u8>,
            Option<lib_identity::IdentityId>,
            Option<lib_proofs::ZeroKnowledgeProof>,
        ) = bincode::deserialize(&self.payload)
            .map_err(|e| anyhow!("Failed to deserialize ZHTP request payload: {}", e))?;

        // Extract version from headers if available, otherwise use default
        let version = headers.lib_version.clone().unwrap_or_else(|| "ZHTP/1.0".to_string());

        Ok(ProtocolZhtpRequest {
            method: self.zhtp_method.ok_or_else(|| anyhow!("Missing ZHTP method in envelope"))?,
            uri: self.zhtp_uri.clone().ok_or_else(|| anyhow!("Missing ZHTP URI in envelope"))?,
            version,
            headers,
            body,
            timestamp: self.timestamp,
            requester,   // SECURITY: Authentication preserved through mesh routing
            auth_proof,  // SECURITY: ZK proof preserved for validation
        })
    }

    /// Reconstruct ZHTP response from envelope with single-pass deserialization
    ///
    /// **OPTIMIZED:** Deserializes only headers + body, uses envelope field for status
    pub fn to_zhtp_response(&self) -> Result<ProtocolZhtpResponse> {
        if self.message_type != MessageType::ZhtpResponse {
            return Err(anyhow!("Not a ZhtpResponse message"));
        }

        // Deserialize headers, body, server, validity_proof from payload
        let (headers, body, server, validity_proof): (
            lib_protocols::types::ZhtpHeaders,
            Vec<u8>,
            Option<lib_identity::IdentityId>,
            Option<lib_proofs::ZeroKnowledgeProof>,
        ) = bincode::deserialize(&self.payload)
            .map_err(|e| anyhow!("Failed to deserialize ZHTP response payload: {}", e))?;

        // Extract version from headers if available, otherwise use default
        let version = headers.lib_version.clone().unwrap_or_else(|| "ZHTP/1.0".to_string());

        let status = self.zhtp_status.ok_or_else(|| anyhow!("Missing ZHTP status in envelope"))?;

        Ok(ProtocolZhtpResponse {
            version,
            status,
            status_message: status.to_string(),
            headers,
            body,
            timestamp: self.timestamp,
            server,          // SECURITY: Server identity preserved through mesh routing
            validity_proof,  // SECURITY: Validity proof preserved for verification
        })
    }

    /// Serialize to bytes using bincode
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| anyhow!("Failed to serialize envelope: {}", e))
    }

    /// Deserialize from bytes using bincode
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message exceeds maximum size"));
        }

        bincode::deserialize(bytes)
            .map_err(|e| anyhow!("Failed to deserialize envelope: {}", e))
    }

    /// Check if this message is for the current node
    pub fn is_for_me(&self, my_id: &PublicKey) -> bool {
        self.destination == *my_id
    }

    /// Increment hop count and decrement TTL
    pub fn increment_hop(&mut self, relay_id: PublicKey) {
        self.hop_count += 1;
        self.ttl = self.ttl.saturating_sub(1);
        self.route_history.push(relay_id);
    }

    /// Check if message should be dropped (TTL expired or in loop)
    pub fn should_drop(&self, my_id: &PublicKey) -> bool {
        // Drop if TTL expired
        if self.ttl == 0 {
            return true;
        }

        // Drop if we're already in the route history (loop detection)
        self.route_history.iter().any(|id| id == my_id)
    }

    /// Check if a node is already in the route (prevent loops)
    pub fn contains_in_route(&self, peer_id: &PublicKey) -> bool {
        self.route_history.iter().any(|p| p.key_id == peer_id.key_id)
    }

    /// Get message size in bytes
    pub fn size(&self) -> usize {
        self.to_bytes().map(|b| b.len()).unwrap_or(0)
    }

    /// Create envelope from ZHTP request (Issue #479)
    /// Extracts method/URI for fast routing without full deserialization
    pub fn from_zhtp_request(
        request: ProtocolZhtpRequest,
        origin: PublicKey,
        destination: PublicKey,
        hop_count: u8,
        ttl: u8,
    ) -> Result<Self> {
        let method = request.method.clone();
        let uri = request.uri.clone();
        let payload = bincode::serialize(&request)?;

        let mut envelope = Self::new(
            0, // Will be set by caller if needed
            origin,
            destination,
            MessageType::ZhtpRequest,
            payload,
        );

        envelope.ttl = ttl;
        envelope.hop_count = hop_count;
        envelope.zhtp_method = Some(method);
        envelope.zhtp_uri = Some(uri);

        Ok(envelope)
    }

    /// Create envelope from ZHTP response (Issue #479)
    /// Extracts status for fast routing without full deserialization
    pub fn from_zhtp_response(
        response: ProtocolZhtpResponse,
        origin: PublicKey,
        destination: PublicKey,
        hop_count: u8,
        ttl: u8,
    ) -> Result<Self> {
        let status = response.status.clone();
        let payload = bincode::serialize(&response)?;

        let mut envelope = Self::new(
            0, // Will be set by caller if needed
            origin,
            destination,
            MessageType::ZhtpResponse,
            payload,
        );

        envelope.ttl = ttl;
        envelope.hop_count = hop_count;
        envelope.zhtp_status = Some(status);

        Ok(envelope)
    }

    /// Reconstruct ZHTP request from envelope
    pub fn to_zhtp_request(&self) -> Result<ProtocolZhtpRequest> {
        if self.message_type != MessageType::ZhtpRequest {
            return Err(anyhow!("Message is not a ZHTP request"));
        }
        bincode::deserialize(&self.payload)
            .map_err(|e| anyhow!("Failed to deserialize ZHTP request: {}", e))
    }

    /// Reconstruct ZHTP response from envelope
    pub fn to_zhtp_response(&self) -> Result<ProtocolZhtpResponse> {
        if self.message_type != MessageType::ZhtpResponse {
            return Err(anyhow!("Message is not a ZHTP response"));
        }
        bincode::deserialize(&self.payload)
            .map_err(|e| anyhow!("Failed to deserialize ZHTP response: {}", e))
    }
}

/// Mesh message payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZhtpMeshMessage {

    /// Peer discovery and capability announcement
    PeerDiscovery {
        capabilities: Vec<MeshCapability>,
        location: Option<GeographicLocation>,
        shared_resources: SharedResources,
    },

    /// Simple peer announcement for establishing UDP mesh connections
    /// Signature proves ownership of the public key
    PeerAnnouncement {
        sender: PublicKey,
        timestamp: u64,
        signature: Vec<u8>, // Dilithium signature over (sender.key_id || timestamp)
    },

    /// Request for internet connectivity
    ConnectivityRequest {
        requester: PublicKey,
        bandwidth_needed_kbps: u32,
        duration_minutes: u32,
        payment_tokens: u64,
    },

    /// Response to connectivity request
    ConnectivityResponse {
        provider: PublicKey,
        accepted: bool,
        available_bandwidth_kbps: u32,
        cost_tokens_per_mb: u64,
        connection_details: Option<ConnectionDetails>,
    },

    /// Long-range routing message
    LongRangeRoute {
        destination: PublicKey,
        relay_chain: Vec<String>,
        payload: Vec<u8>,
        max_hops: u8,
    },

    /// UBI distribution message
    UbiDistribution {
        recipient: PublicKey,
        amount_tokens: u64,
        distribution_round: u64,
        proof: Vec<u8>, // ZK proof of contribution
    },

    /// Network health report
    HealthReport {
        reporter: PublicKey,
        network_quality: f64,
        available_bandwidth: u64,
        connected_peers: u32,
        uptime_hours: u32,
    },

    /// Native ZHTP protocol request from browser/API clients
    ZhtpRequest(ProtocolZhtpRequest),

    /// Native ZHTP protocol response to browser/API clients
    ZhtpResponse(ProtocolZhtpResponse),

    /// Request blockchain data from peer (for sync)
    BlockchainRequest {
        requester: PublicKey,
        request_id: u64,
        request_type: BlockchainRequestType,
    },

    /// Send blockchain data in chunked format
    BlockchainData {
        sender: PublicKey,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        /// Serialized blockchain data chunk (bincode format)
        data: Vec<u8>,
        /// Hash of the complete blockchain data (for verification)
        complete_data_hash: [u8; 32],
    },

    /// New block announcement for real-time propagation
    NewBlock {
        /// Serialized block (bincode format)
        block: Vec<u8>,
        /// Peer who created/relayed this block
        sender: PublicKey,
        /// Block height for quick filtering
        height: u64,
        /// Timestamp when block was created/received
        timestamp: u64,
    },

    /// New transaction announcement for mempool propagation
    NewTransaction {
        /// Serialized transaction (bincode format)
        transaction: Vec<u8>,
        /// Peer who created/relayed this transaction
        sender: PublicKey,
        /// Transaction hash for duplicate detection
        tx_hash: [u8; 32],
        /// Transaction fee for priority sorting
        fee: u64,
    },

    /// Route discovery probe
    RouteProbe {
        probe_id: u64,
        target: PublicKey,
    },

    /// Route discovery response
    RouteResponse {
        probe_id: u64,
        route_quality: f64,
        latency_ms: u32,
    },

    /// Request bootstrap proof for edge node sync (ZK proof + recent headers)
    /// **EDGE NODES ONLY** - Constrained devices (BLE phones/IoT) use this
    /// to get cryptographic proof of chain validity without downloading full blocks
    BootstrapProofRequest {
        requester: PublicKey,
        request_id: u64,
        /// Current block height known to requester
        current_height: u64,
    },

    /// Response with ZK bootstrap proof + recent headers
    /// **EDGE NODES ONLY** - Contains ChainRecursiveProof for O(1) verification
    /// plus recent headers for the rolling window (no full block data)
    BootstrapProofResponse {
        request_id: u64,
        /// Serialized ChainRecursiveProof (compressed ZK proof)
        proof_data: Vec<u8>,
        /// Height that the proof covers up to
        proof_height: u64,
        /// Recent block headers ONLY (typically last 500 or less)
        /// Edge nodes store only headers, not full blocks
        headers: Vec<Vec<u8>>, // Serialized BlockHeaders
    },

    /// Request specific block headers (for edge node incremental sync)
    /// **EDGE NODES ONLY** - For catching up when close to chain tip
    HeadersRequest {
        requester: PublicKey,
        request_id: u64,
        /// Starting block height
        start_height: u64,
        /// Number of headers to fetch
        count: u32,
    },

    /// Response with block headers
    /// **EDGE NODES ONLY** - Headers only, no transaction data
    HeadersResponse {
        request_id: u64,
        /// Serialized block headers (no full blocks)
        headers: Vec<Vec<u8>>,
        /// Starting height of the first header
        start_height: u64,
    },

    /// DHT Store operation - store key/value in distributed hash table
    /// Routes over any protocol (UDP, BLE, WiFi Direct)
    DhtStore {
        /// Requester's public key
        requester: PublicKey,
        /// Unique request ID
        request_id: u64,
        /// Key to store (typically domain name or content hash)
        key: Vec<u8>,
        /// Value to store (content hash, IP address, etc.)
        value: Vec<u8>,
        /// Time-to-live for this entry (seconds)
        ttl: u64,
        /// Signature proving ownership of requester key
        signature: Vec<u8>,
    },

    /// DHT Store acknowledgment
    DhtStoreAck {
        request_id: u64,
        success: bool,
        /// Number of nodes that stored the value
        stored_count: u32,
    },

    /// DHT FindValue - query for a key in the distributed hash table
    DhtFindValue {
        /// Requester's public key
        requester: PublicKey,
        /// Unique request ID
        request_id: u64,
        /// Key to find
        key: Vec<u8>,
        /// Maximum hops for query propagation
        max_hops: u8,
    },

    /// DHT FindValue response
    DhtFindValueResponse {
        request_id: u64,
        /// True if value was found
        found: bool,
        /// The value (if found)
        value: Option<Vec<u8>>,
        /// Closer nodes that might have the value
        closer_nodes: Vec<PublicKey>,
    },

    /// DHT FindNode - find nodes close to a given ID (Kademlia routing)
    DhtFindNode {
        /// Requester's public key
        requester: PublicKey,
        /// Unique request ID
        request_id: u64,
        /// Target node ID (20-byte Kademlia key)
        target_id: Vec<u8>,
        /// Maximum hops for query propagation
        max_hops: u8,
    },

    /// DHT FindNode response
    DhtFindNodeResponse {
        request_id: u64,
        /// Nodes closer to the target
        closer_nodes: Vec<(PublicKey, String)>, // (pubkey, address)
    },

    /// DHT Ping - check if node is alive
    DhtPing {
        requester: PublicKey,
        request_id: u64,
        timestamp: u64,
    },

    /// DHT Pong - response to ping
    DhtPong {
        request_id: u64,
        timestamp: u64,
    },

    /// DHT Generic Payload - serialized DHT message (Ticket #154)
    /// Used for routing DHT messages without circular dependencies
    DhtGenericPayload {
        requester: PublicKey,
        payload: Vec<u8>, // Bincode-serialized DhtMessage
        signature: Vec<u8>, // ED25519 signature of (requester + payload)
    },
}

impl ZhtpMeshMessage {
    /// Serialize message and return its type discriminator + payload (Issue #479)
    ///
    /// **OPTIMIZED:** Single-pass serialization - serializes just the inner data
    /// and returns the type separately, eliminating enum tag overhead.
    pub fn serialize_with_type(&self) -> Result<(MessageType, Vec<u8>)> {
        let (msg_type, payload) = match self {
            Self::PeerDiscovery { capabilities, location, shared_resources } => {
                (MessageType::PeerDiscovery, bincode::serialize(&(capabilities, location, shared_resources))?)
            },
            Self::PeerAnnouncement { sender, timestamp, signature } => {
                (MessageType::PeerAnnouncement, bincode::serialize(&(sender, timestamp, signature))?)
            },
            Self::ConnectivityRequest { requester, bandwidth_needed_kbps, duration_minutes, payment_tokens } => {
                (MessageType::ConnectivityRequest, bincode::serialize(&(requester, bandwidth_needed_kbps, duration_minutes, payment_tokens))?)
            },
            Self::ConnectivityResponse { provider, accepted, available_bandwidth_kbps, cost_tokens_per_mb, connection_details } => {
                (MessageType::ConnectivityResponse, bincode::serialize(&(provider, accepted, available_bandwidth_kbps, cost_tokens_per_mb, connection_details))?)
            },
            Self::LongRangeRoute { destination, relay_chain, payload: route_payload, max_hops } => {
                (MessageType::LongRangeRoute, bincode::serialize(&(destination, relay_chain, route_payload, max_hops))?)
            },
            Self::UbiDistribution { recipient, amount_tokens, distribution_round, proof } => {
                (MessageType::UbiDistribution, bincode::serialize(&(recipient, amount_tokens, distribution_round, proof))?)
            },
            Self::HealthReport { reporter, network_quality, available_bandwidth, connected_peers, uptime_hours } => {
                (MessageType::HealthReport, bincode::serialize(&(reporter, network_quality, available_bandwidth, connected_peers, uptime_hours))?)
            },
            Self::ZhtpRequest(request) => {
                // OPTIMIZED: Single-pass serialization - only serialize headers + body
                // Method, URI, timestamp extracted to envelope fields
                (MessageType::ZhtpRequest, bincode::serialize(&(&request.headers, &request.body))?)
            },
            Self::ZhtpResponse(response) => {
                // OPTIMIZED: Single-pass serialization - only serialize headers + body
                // Status extracted to envelope field
                (MessageType::ZhtpResponse, bincode::serialize(&(&response.headers, &response.body))?)
            },
            Self::BlockchainRequest { requester, request_id, request_type } => {
                (MessageType::BlockchainRequest, bincode::serialize(&(requester, request_id, request_type))?)
            },
            Self::BlockchainData { sender, request_id, chunk_index, total_chunks, data, complete_data_hash } => {
                (MessageType::BlockchainData, bincode::serialize(&(sender, request_id, chunk_index, total_chunks, data, complete_data_hash))?)
            },
            Self::NewBlock { block, sender, height, timestamp } => {
                (MessageType::NewBlock, bincode::serialize(&(block, sender, height, timestamp))?)
            },
            Self::NewTransaction { transaction, sender, tx_hash, fee } => {
                (MessageType::NewTransaction, bincode::serialize(&(transaction, sender, tx_hash, fee))?)
            },
            Self::RouteProbe { probe_id, target } => {
                (MessageType::RouteProbe, bincode::serialize(&(probe_id, target))?)
            },
            Self::RouteResponse { probe_id, route_quality, latency_ms } => {
                (MessageType::RouteResponse, bincode::serialize(&(probe_id, route_quality, latency_ms))?)
            },
            Self::BootstrapProofRequest { requester, request_id, current_height } => {
                (MessageType::BootstrapProofRequest, bincode::serialize(&(requester, request_id, current_height))?)
            },
            Self::BootstrapProofResponse { request_id, proof_data, proof_height, headers } => {
                (MessageType::BootstrapProofResponse, bincode::serialize(&(request_id, proof_data, proof_height, headers))?)
            },
            Self::HeadersRequest { requester, request_id, start_height, count } => {
                (MessageType::HeadersRequest, bincode::serialize(&(requester, request_id, start_height, count))?)
            },
            Self::HeadersResponse { request_id, headers, start_height } => {
                (MessageType::HeadersResponse, bincode::serialize(&(request_id, headers, start_height))?)
            },
            Self::DhtStore { requester, request_id, key, value, ttl, signature } => {
                (MessageType::DhtStore, bincode::serialize(&(requester, request_id, key, value, ttl, signature))?)
            },
            Self::DhtStoreAck { request_id, success, stored_count } => {
                (MessageType::DhtStoreAck, bincode::serialize(&(request_id, success, stored_count))?)
            },
            Self::DhtFindValue { requester, request_id, key, max_hops } => {
                (MessageType::DhtFindValue, bincode::serialize(&(requester, request_id, key, max_hops))?)
            },
            Self::DhtFindValueResponse { request_id, found, value, closer_nodes } => {
                (MessageType::DhtFindValueResponse, bincode::serialize(&(request_id, found, value, closer_nodes))?)
            },
            Self::DhtFindNode { requester, request_id, target_id, max_hops } => {
                (MessageType::DhtFindNode, bincode::serialize(&(requester, request_id, target_id, max_hops))?)
            },
            Self::DhtFindNodeResponse { request_id, closer_nodes } => {
                (MessageType::DhtFindNodeResponse, bincode::serialize(&(request_id, closer_nodes))?)
            },
            Self::DhtPing { requester, request_id, timestamp } => {
                (MessageType::DhtPing, bincode::serialize(&(requester, request_id, timestamp))?)
            },
            Self::DhtPong { request_id, timestamp } => {
                (MessageType::DhtPong, bincode::serialize(&(request_id, timestamp))?)
            },
            Self::DhtGenericPayload { requester, payload, signature } => {
                (MessageType::DhtGenericPayload, bincode::serialize(&(requester, payload, signature))?)
            },
        };
        Ok((msg_type, payload))
    }

    /// Deserialize from type discriminator and payload (Issue #479)
    ///
    /// **OPTIMIZED:** Single-pass deserialization using the type discriminator.
    pub fn deserialize_from_type(msg_type: MessageType, payload: &[u8]) -> Result<Self> {
        let message = match msg_type {
            MessageType::PeerDiscovery => {
                let (capabilities, location, shared_resources) = bincode::deserialize(payload)?;
                Self::PeerDiscovery { capabilities, location, shared_resources }
            },
            MessageType::PeerAnnouncement => {
                let (sender, timestamp, signature) = bincode::deserialize(payload)?;
                Self::PeerAnnouncement { sender, timestamp, signature }
            },
            MessageType::ConnectivityRequest => {
                let (requester, bandwidth_needed_kbps, duration_minutes, payment_tokens) = bincode::deserialize(payload)?;
                Self::ConnectivityRequest { requester, bandwidth_needed_kbps, duration_minutes, payment_tokens }
            },
            MessageType::ConnectivityResponse => {
                let (provider, accepted, available_bandwidth_kbps, cost_tokens_per_mb, connection_details) = bincode::deserialize(payload)?;
                Self::ConnectivityResponse { provider, accepted, available_bandwidth_kbps, cost_tokens_per_mb, connection_details }
            },
            MessageType::LongRangeRoute => {
                let (destination, relay_chain, route_payload, max_hops) = bincode::deserialize(payload)?;
                Self::LongRangeRoute { destination, relay_chain, payload: route_payload, max_hops }
            },
            MessageType::UbiDistribution => {
                let (recipient, amount_tokens, distribution_round, proof) = bincode::deserialize(payload)?;
                Self::UbiDistribution { recipient, amount_tokens, distribution_round, proof }
            },
            MessageType::HealthReport => {
                let (reporter, network_quality, available_bandwidth, connected_peers, uptime_hours) = bincode::deserialize(payload)?;
                Self::HealthReport { reporter, network_quality, available_bandwidth, connected_peers, uptime_hours }
            },
            MessageType::ZhtpRequest => {
                // OPTIMIZED: Should not be called directly - use MeshMessageEnvelope::deserialize_message() instead
                // This fallback deserializes headers + body and creates a minimal request
                let (headers, body): (lib_protocols::types::ZhtpHeaders, Vec<u8>) = bincode::deserialize(payload)?;
                Self::ZhtpRequest(ProtocolZhtpRequest {
                    method: lib_protocols::types::ZhtpMethod::Get, // Default, should be overridden from envelope
                    uri: "".to_string(), // Default, should be overridden from envelope
                    version: headers.lib_version.clone().unwrap_or_else(|| "ZHTP/1.0".to_string()),
                    headers,
                    body,
                    timestamp: 0, // Should be overridden from envelope
                    requester: None,
                    auth_proof: None,
                })
            },
            MessageType::ZhtpResponse => {
                // OPTIMIZED: Should not be called directly - use MeshMessageEnvelope::deserialize_message() instead
                // This fallback deserializes headers + body and creates a minimal response
                let (headers, body): (lib_protocols::types::ZhtpHeaders, Vec<u8>) = bincode::deserialize(payload)?;
                Self::ZhtpResponse(ProtocolZhtpResponse {
                    version: headers.lib_version.clone().unwrap_or_else(|| "ZHTP/1.0".to_string()),
                    status: lib_protocols::types::ZhtpStatus::Ok, // Default, should be overridden from envelope
                    status_message: "OK".to_string(),
                    headers,
                    body,
                    timestamp: 0, // Should be overridden from envelope
                    server: None,
                    validity_proof: None,
                })
            },
            MessageType::BlockchainRequest => {
                let (requester, request_id, request_type) = bincode::deserialize(payload)?;
                Self::BlockchainRequest { requester, request_id, request_type }
            },
            MessageType::BlockchainData => {
                let (sender, request_id, chunk_index, total_chunks, data, complete_data_hash) = bincode::deserialize(payload)?;
                Self::BlockchainData { sender, request_id, chunk_index, total_chunks, data, complete_data_hash }
            },
            MessageType::NewBlock => {
                let (block, sender, height, timestamp) = bincode::deserialize(payload)?;
                Self::NewBlock { block, sender, height, timestamp }
            },
            MessageType::NewTransaction => {
                let (transaction, sender, tx_hash, fee) = bincode::deserialize(payload)?;
                Self::NewTransaction { transaction, sender, tx_hash, fee }
            },
            MessageType::RouteProbe => {
                let (probe_id, target) = bincode::deserialize(payload)?;
                Self::RouteProbe { probe_id, target }
            },
            MessageType::RouteResponse => {
                let (probe_id, route_quality, latency_ms) = bincode::deserialize(payload)?;
                Self::RouteResponse { probe_id, route_quality, latency_ms }
            },
            MessageType::BootstrapProofRequest => {
                let (requester, request_id, current_height) = bincode::deserialize(payload)?;
                Self::BootstrapProofRequest { requester, request_id, current_height }
            },
            MessageType::BootstrapProofResponse => {
                let (request_id, proof_data, proof_height, headers) = bincode::deserialize(payload)?;
                Self::BootstrapProofResponse { request_id, proof_data, proof_height, headers }
            },
            MessageType::HeadersRequest => {
                let (requester, request_id, start_height, count) = bincode::deserialize(payload)?;
                Self::HeadersRequest { requester, request_id, start_height, count }
            },
            MessageType::HeadersResponse => {
                let (request_id, headers, start_height) = bincode::deserialize(payload)?;
                Self::HeadersResponse { request_id, headers, start_height }
            },
            MessageType::DhtStore => {
                let (requester, request_id, key, value, ttl, signature) = bincode::deserialize(payload)?;
                Self::DhtStore { requester, request_id, key, value, ttl, signature }
            },
            MessageType::DhtStoreAck => {
                let (request_id, success, stored_count) = bincode::deserialize(payload)?;
                Self::DhtStoreAck { request_id, success, stored_count }
            },
            MessageType::DhtFindValue => {
                let (requester, request_id, key, max_hops) = bincode::deserialize(payload)?;
                Self::DhtFindValue { requester, request_id, key, max_hops }
            },
            MessageType::DhtFindValueResponse => {
                let (request_id, found, value, closer_nodes) = bincode::deserialize(payload)?;
                Self::DhtFindValueResponse { request_id, found, value, closer_nodes }
            },
            MessageType::DhtFindNode => {
                let (requester, request_id, target_id, max_hops) = bincode::deserialize(payload)?;
                Self::DhtFindNode { requester, request_id, target_id, max_hops }
            },
            MessageType::DhtFindNodeResponse => {
                let (request_id, closer_nodes) = bincode::deserialize(payload)?;
                Self::DhtFindNodeResponse { request_id, closer_nodes }
            },
            MessageType::DhtPing => {
                let (requester, request_id, timestamp) = bincode::deserialize(payload)?;
                Self::DhtPing { requester, request_id, timestamp }
            },
            MessageType::DhtPong => {
                let (request_id, timestamp) = bincode::deserialize(payload)?;
                Self::DhtPong { request_id, timestamp }
            },
            MessageType::DhtGenericPayload => {
                let (requester, dht_payload, signature) = bincode::deserialize(payload)?;
                Self::DhtGenericPayload { requester, payload: dht_payload, signature }
            },
        };
        Ok(message)
    }
}

/// Types of blockchain data requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockchainRequestType {
    /// Request full blockchain (FULL NODES)
    /// Returns complete blocks with all transactions via BlockchainData chunks
    FullChain,
    
    /// Request blocks after a specific height (FULL NODES)
    /// Used for catching up to chain tip with complete block data
    BlocksAfter(u64),
    
    /// Request specific block by height (FULL NODES)
    /// Returns single complete block with all transactions
    Block(u64),
    
    /// Request transaction by ID (ANY NODE)
    /// Returns single transaction data
    Transaction(String),
    
    /// Request mempool contents (FULL NODES)
    /// Returns pending transactions not yet in blocks
    Mempool,
    
    /// Request headers only - DEPRECATED, use HeadersRequest message instead
    /// (EDGE NODES - use HeadersRequest message for better protocol design)
    HeadersOnly { start_height: u64, count: u32 },
    
    /// Request bootstrap proof with headers - DEPRECATED, use BootstrapProofRequest instead
    /// (EDGE NODES - use BootstrapProofRequest message for better protocol design)
    BootstrapWithHeaders { current_height: u64 },
}


#[cfg(test)]
mod tests {
    use super::*;
    use lib_protocols::types::{ZhtpHeaders, ZhtpRequest, ZhtpMethod};

    #[test]
    fn test_envelope_creation() {
        let origin = PublicKey::new(vec![1, 2, 3]);
        let dest = PublicKey::new(vec![4, 5, 6]);

        let msg = ZhtpMeshMessage::HealthReport {
            reporter: origin.clone(),
            network_quality: 0.95,
            available_bandwidth: 1_000_000,
            connected_peers: 5,
            uptime_hours: 24,
        };

        let envelope = MeshMessageEnvelope::from_message(123, origin.clone(), dest.clone(), msg)
            .expect("Failed to create envelope");

        assert_eq!(envelope.message_id, 123);
        assert_eq!(envelope.ttl, DEFAULT_TTL);
        assert_eq!(envelope.hop_count, 0);
        assert!(envelope.route_history.is_empty());
        assert_eq!(envelope.message_type, MessageType::HealthReport);
    }

    #[test]
    fn test_zhtp_request_single_serialization() {
        use lib_protocols::types::{ZhtpHeaders, ZhtpMethod};
        
        let origin = PublicKey::new(vec![1, 2, 3]);
        let dest = PublicKey::new(vec![4, 5, 6]);

        let request = ProtocolZhtpRequest {
            method: ZhtpMethod::Get,
            uri: "/test/endpoint".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: ZhtpHeaders::default(),
            body: b"test body".to_vec(),
            timestamp: 12345,
            requester: None,
            auth_proof: None,
        };

        let msg = ZhtpMeshMessage::ZhtpRequest(request.clone());
        let envelope = MeshMessageEnvelope::from_message(456, origin.clone(), dest.clone(), msg)
            .expect("Failed to create envelope");

        // Verify ZHTP fields are extracted
        assert_eq!(envelope.zhtp_method, Some(ZhtpMethod::Get));
        assert_eq!(envelope.zhtp_uri, Some("/test/endpoint".to_string()));
        assert_eq!(envelope.zhtp_status, None);

        // Serialize and deserialize
        let bytes = envelope.to_bytes().unwrap();
        let deserialized = MeshMessageEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(envelope.message_id, deserialized.message_id);
        assert_eq!(envelope.ttl, deserialized.ttl);
        assert_eq!(envelope.message_type, MessageType::ZhtpRequest);
        assert_eq!(deserialized.zhtp_method, Some(ZhtpMethod::Get));
        assert_eq!(deserialized.zhtp_uri, Some("/test/endpoint".to_string()));

        // Reconstruct request
        let reconstructed = deserialized.deserialize_message().unwrap();
        match reconstructed {
            ZhtpMeshMessage::ZhtpRequest(req) => {
                assert_eq!(req.method, ZhtpMethod::Get);
                assert_eq!(req.uri, "/test/endpoint");
                assert_eq!(req.body, b"test body");
            },
            _ => panic!("Wrong message type after deserialization"),
        }
    }

    #[test]
    fn test_hop_increment() {
        let origin = PublicKey::new(vec![1, 2, 3]);
        let dest = PublicKey::new(vec![4, 5, 6]);
        let relay = PublicKey::new(vec![7, 8, 9]);

        let msg = ZhtpMeshMessage::HealthReport {
            reporter: origin.clone(),
            network_quality: 0.95,
            available_bandwidth: 1_000_000,
            connected_peers: 5,
            uptime_hours: 24,
        };

        let mut envelope = MeshMessageEnvelope::from_message(789, origin, dest, msg)
            .expect("Failed to create envelope");
        envelope.increment_hop(relay.clone());

        assert_eq!(envelope.hop_count, 1);
        assert_eq!(envelope.ttl, DEFAULT_TTL - 1);
        assert_eq!(envelope.route_history.len(), 1);
    }

    #[test]
    fn test_zhtp_response_single_serialization() {
        use lib_protocols::types::{ZhtpHeaders, ZhtpStatus};
        
        let origin = PublicKey::new(vec![1, 2, 3]);
        let dest = PublicKey::new(vec![4, 5, 6]);

        let response = ProtocolZhtpResponse {
            version: "ZHTP/1.0".to_string(),
            status: ZhtpStatus::Ok,
            status_message: "OK".to_string(),
            headers: ZhtpHeaders::default(),
            body: b"response body".to_vec(),
            timestamp: 67890,
            server: None,
            validity_proof: None,
        };

        let msg = ZhtpMeshMessage::ZhtpResponse(response.clone());
        let envelope = MeshMessageEnvelope::from_message(999, origin, dest, msg)
            .expect("Failed to create envelope");

        // Verify ZHTP status is extracted
        assert_eq!(envelope.zhtp_status, Some(ZhtpStatus::Ok));
        assert_eq!(envelope.zhtp_method, None);
        assert_eq!(envelope.zhtp_uri, None);

        // Serialize and deserialize
        let envelope_bytes = envelope.to_bytes().unwrap();
        let restored = MeshMessageEnvelope::from_bytes(&envelope_bytes).unwrap();

        assert_eq!(restored.message_id, 999);
        assert_eq!(restored.message_type, MessageType::ZhtpResponse);
        assert_eq!(restored.zhtp_status, Some(ZhtpStatus::Ok));

        // Reconstruct response
        let restored_msg = restored.deserialize_message().unwrap();
        match restored_msg {
            ZhtpMeshMessage::ZhtpResponse(resp) => {
                assert_eq!(resp.status, ZhtpStatus::Ok);
                assert_eq!(resp.body, b"response body");
            },
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_multi_hop_routing_production_scenario() {
        use lib_crypto::Hash;
        use lib_proofs::ZeroKnowledgeProof;
        
        // Simulate a production request being routed through multiple hops
        let mut headers = ZhtpHeaders::new();
        headers.set("Host", "destination.zhtp".to_string());
        headers.set("X-Request-ID", "test-request-123".to_string());
        
        // SECURITY: POST requests MUST have authentication in production
        let requester_id = Hash::from_bytes(b"test-requester-identity-hash");
        let auth_proof = ZeroKnowledgeProof::empty(); // Mock proof for testing
        
        let original_request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/transaction".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: headers.clone(),
            body: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            timestamp: 0,
            requester: Some(requester_id),
            auth_proof: Some(auth_proof),
        };

        let sender = PublicKey::new(vec![10u8; 1952]); // Dilithium3 public key size
        let receiver = PublicKey::new(vec![20u8; 1952]);

        let mut envelope = MeshMessageEnvelope::from_zhtp_request(
            99,
            sender.clone(),
            receiver.clone(),
            original_request.clone(),
        ).expect("Failed to create envelope");

        // Simulate 10 hops through mesh network (typical production routing path)
        for hop in 1..=10 {
            // Serialize at current hop (forwarding)
            let serialized = bincode::serialize(&envelope).unwrap();
            
            // Deserialize at next hop (receiving)
            envelope = bincode::deserialize(&serialized).unwrap();
            
            // Increment hop count (relay behavior)
            envelope.increment_hop(sender.clone());
        }

        // Reconstruct at destination
        let final_request = envelope.to_zhtp_request()
            .expect("Failed to reconstruct after multi-hop");

        // Verify complete integrity
        assert_eq!(final_request.method, original_request.method);
        assert_eq!(final_request.uri, original_request.uri);
        assert_eq!(final_request.body, original_request.body);
        assert_eq!(final_request.headers.get("Host"), original_request.headers.get("Host"));
        
        // SECURITY: Verify authentication fields preserved through mesh routing
        assert_eq!(final_request.requester, original_request.requester, "Requester identity must survive multi-hop routing");
        assert!(final_request.auth_proof.is_some(), "Auth proof must survive multi-hop routing");
        
        println!("✅ Production test: ZHTP request routed through {} hops successfully", envelope.hop_count);
        println!("✅ Security test: Authentication preserved through {} hops", envelope.hop_count);
    }

    #[test]
    fn test_optimization_memory_benefit() {
        use lib_crypto::Hash;
        use lib_proofs::ZeroKnowledgeProof;
        
        // Verify single-pass serialization: the payload only contains (headers, body), not full request        
        let mut headers = ZhtpHeaders::new();
        headers.set("Host", "test.zhtp".to_string());
        headers.set("Authorization", "Bearer token123".to_string());
        
        // SECURITY: POST requests MUST have authentication in production
        let requester_id = Hash::from_bytes(b"test-uploader-identity-hash");
        let auth_proof = ZeroKnowledgeProof::empty(); // Mock proof for testing
        
        let payload = vec![b'X'; 1024]; // 1KB body
        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/upload".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: headers.clone(),
            body: payload.clone(),
            timestamp: 0,
            requester: Some(requester_id),
            auth_proof: Some(auth_proof),
        };

        let sender = PublicKey::new(vec![1u8; 1952]);
        let receiver = PublicKey::new(vec![2u8; 1952]);

        // OLD APPROACH: Double serialization - serialize full request into payload
        let full_request_serialized = bincode::serialize(&request).unwrap();
        
        // NEW APPROACH: Single-pass serialization - serialize (headers, body, requester, auth_proof) tuple
        // SECURITY: Must include authentication fields to preserve them through mesh routing
        let optimized_tuple = (&request.headers, &request.body, &request.requester, &request.auth_proof);
        let optimized_payload = bincode::serialize(&optimized_tuple).unwrap();
        
        let envelope = MeshMessageEnvelope::from_zhtp_request(
            100,
            sender,
            receiver,
            request.clone(),
        ).expect("Failed to create envelope");

        println!("📊 Memory optimization:");
        println!("   Old approach (full request serialized): {} bytes", full_request_serialized.len());
        println!("   New approach (headers+body+auth only): {} bytes", optimized_payload.len());
        println!("   Savings: {} bytes ({:.1}%)", 
            full_request_serialized.len() - optimized_payload.len(),
            (1.0 - optimized_payload.len() as f64 / full_request_serialized.len() as f64) * 100.0
        );
        
        // Verify payload contains (headers, body, requester, auth_proof) tuple, not full request
        assert_eq!(envelope.payload, optimized_payload, "Payload should contain (headers, body, requester, auth_proof) tuple");
        
        // Verify method and URI are extracted to envelope fields (not in payload)
        assert_eq!(envelope.zhtp_method, Some(ZhtpMethod::Post));
        assert_eq!(envelope.zhtp_uri, Some("/api/upload".to_string()));
        
        println!("✅ Production test: Single-pass serialization verified - payload preserves authentication through mesh routing");
    }
}
