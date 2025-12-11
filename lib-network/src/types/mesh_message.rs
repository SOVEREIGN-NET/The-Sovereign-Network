//! Mesh Message Types for Multi-Hop Routing
//! 
//! Defines message envelopes and payload types for mesh network communication

use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::geographic::GeographicLocation;
use crate::types::mesh_capability::{MeshCapability, SharedResources};
use crate::types::connection_details::ConnectionDetails;
use lib_protocols::types::{ZhtpRequest as ProtocolZhtpRequest, ZhtpResponse as ProtocolZhtpResponse};

/// Default TTL for mesh messages (32 hops)
pub const DEFAULT_TTL: u8 = 32;

/// Maximum message size (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Message envelope for multi-hop routing
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
    /// The actual message payload
    pub message: ZhtpMeshMessage,
}


impl MeshMessageEnvelope {
    /// Create a new message envelope
    pub fn new(
        message_id: u64,
        origin: PublicKey,
        destination: PublicKey,
        message: ZhtpMeshMessage,
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
            message,
        }
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
    },
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

        let envelope = MeshMessageEnvelope::new(123, origin.clone(), dest.clone(), msg);

        assert_eq!(envelope.message_id, 123);
        assert_eq!(envelope.ttl, DEFAULT_TTL);
        assert_eq!(envelope.hop_count, 0);
        assert!(envelope.route_history.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let origin = PublicKey::new(vec![1, 2, 3]);
        let dest = PublicKey::new(vec![4, 5, 6]);

        let msg = ZhtpMeshMessage::HealthReport {
            reporter: origin.clone(),
            network_quality: 0.95,
            available_bandwidth: 1_000_000,
            connected_peers: 5,
            uptime_hours: 24,
        };

        let envelope = MeshMessageEnvelope::new(456, origin.clone(), dest.clone(), msg);
        let bytes = envelope.to_bytes().unwrap();
        let deserialized = MeshMessageEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(envelope.message_id, deserialized.message_id);
        assert_eq!(envelope.ttl, deserialized.ttl);
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

        let mut envelope = MeshMessageEnvelope::new(789, origin, dest, msg);
        envelope.increment_hop(relay.clone());

        assert_eq!(envelope.hop_count, 1);
        assert_eq!(envelope.ttl, DEFAULT_TTL - 1);
        assert_eq!(envelope.route_history.len(), 1);
    }
}
