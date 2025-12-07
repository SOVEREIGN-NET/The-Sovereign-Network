//! DHT (Distributed Hash Table) type definitions
//! 
//! Contains all types related to the DHT layer foundation of the storage system,
//! including nodes, messages, routing, and zero-knowledge values.

use crate::types::{NodeId, DhtKey, ChunkMetadata};
use lib_crypto::PostQuantumSignature;
use lib_proofs::{ZeroKnowledgeProof, ZkProof};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use std::collections::HashMap;

/// Smart contract data for DHT operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDhtData {
    /// Contract address/identifier
    pub contract_id: String,
    /// Contract operation type
    pub operation: ContractOperation,
    /// Contract bytecode (for deployment)
    pub bytecode: Option<Vec<u8>>,
    /// Function name to call
    pub function_name: Option<String>,
    /// Function arguments (serialized)
    pub arguments: Option<Vec<u8>>,
    /// Gas limit for execution
    pub gas_limit: Option<u64>,
    /// Execution result (for responses)
    pub result: Option<ContractResult>,
    /// Contract metadata
    pub metadata: Option<ContractMetadata>,
    /// Zero-knowledge proofs for privacy
    pub zk_proofs: Vec<ZeroKnowledgeProof>,
}

/// Smart contract operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContractOperation {
    /// Deploy a new contract
    Deploy,
    /// Query contract state (read-only)
    Query,
    /// Execute contract function (state-changing)
    Execute,
    /// Find contract by ID or metadata
    Find,
    /// Get contract metadata
    GetInfo,
}

/// Contract execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractResult {
    /// Whether execution was successful
    pub success: bool,
    /// Return value (serialized)
    pub return_value: Option<Vec<u8>>,
    /// Gas used
    pub gas_used: u64,
    /// Error message (if any)
    pub error: Option<String>,
    /// Contract logs/events
    pub logs: Vec<ContractLog>,
    /// New contract state hash
    pub state_hash: Option<String>,
}

/// Contract log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractLog {
    /// Log level
    pub level: LogLevel,
    /// Log message
    pub message: String,
    /// Additional data
    pub data: HashMap<String, String>,
    /// Timestamp
    pub timestamp: u64,
}

/// Log levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
}

/// Contract metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    /// Contract name
    pub name: String,
    /// Contract version
    pub version: String,
    /// Contract author
    pub author: Option<String>,
    /// Contract description
    pub description: Option<String>,
    /// ABI (Application Binary Interface)
    pub abi: Option<Vec<u8>>,
    /// Source code hash
    pub source_hash: Option<String>,
    /// Deployment timestamp
    pub deployed_at: u64,
    /// Contract owner
    pub owner: Option<NodeId>,
    /// Contract permissions
    pub permissions: ContractPermissions,
    /// Contract tags for discovery
    pub tags: Vec<String>,
}

/// Contract permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractPermissions {
    /// Who can execute functions
    pub execute_policy: ExecutePolicy,
    /// Who can query state
    pub query_policy: QueryPolicy,
    /// Who can upgrade contract
    pub upgrade_policy: UpgradePolicy,
}

/// Execute permission policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutePolicy {
    /// Anyone can execute
    Public,
    /// Only owner can execute
    OwnerOnly,
    /// Specific nodes can execute
    Whitelist(Vec<NodeId>),
    /// Requires specific proofs
    ProofRequired(Vec<String>),
}

/// Query permission policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryPolicy {
    /// Anyone can query
    Public,
    /// Only owner can query
    OwnerOnly,
    /// Specific nodes can query
    Whitelist(Vec<NodeId>),
    /// Requires payment
    PayPerQuery(u64),
}

/// Upgrade permission policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpgradePolicy {
    /// Contract is immutable
    Immutable,
    /// Only owner can upgrade
    OwnerOnly,
    /// Requires governance vote
    Governance,
    /// Never upgradeable
    Locked,
}

/// Storage tier levels for storage capabilities
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum StorageTier {
    /// Hot storage - fast access, higher cost
    Hot,
    /// Warm storage - medium access speed
    Warm,
    /// Cold storage - slow access, lower cost
    Cold,
    /// Archive storage - very slow access, lowest cost
    Archive,
}

/// Access control levels for content
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessLevel {
    /// Public access (anyone can read)
    Public,
    /// Private access (only owner)
    Private,
    /// Restricted access (specific users)
    Restricted,
}

/// Storage capabilities of a DHT node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapabilities {
    /// Available storage space (bytes)
    pub available_space: u64,
    /// Total storage capacity (bytes)
    pub total_capacity: u64,
    /// Storage pricing (tokens per GB per day)
    pub price_per_gb_day: u64,
    /// Supported storage tiers
    pub supported_tiers: Vec<StorageTier>,
    /// Geographic region
    pub region: String,
    /// Node uptime percentage
    pub uptime: f64,
}

/// Unified Peer Identity for DHT operations
///
/// **MIGRATION (Ticket #145):** Consolidates NodeId, PublicKey, and DID
/// into a single structure for complete peer identification.
///
/// # Note
///
/// This is a storage-local version to avoid circular dependencies with lib-network.
/// The full `UnifiedPeerId` from lib-network can be converted to this type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DhtPeerIdentity {
    /// Canonical node identifier from lib-identity
    /// Used for Kademlia distance calculations
    pub node_id: NodeId,
    
    /// Cryptographic public key for signature verification
    pub public_key: lib_crypto::PublicKey,
    
    /// Decentralized Identifier (DID)
    /// Format: "did:zhtp:<hash>"
    pub did: String,
    
    /// Device identifier (e.g., "laptop", "phone")
    pub device_id: String,
}

impl DhtPeerIdentity {
    /// Create from ZhtpIdentity
    pub fn from_zhtp_identity(identity: &crate::types::NodeId) -> Result<Self, anyhow::Error> {
        // In practice, this would extract all components from ZhtpIdentity
        // For now, we create a minimal version
        Ok(Self {
            node_id: identity.clone(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            did: String::from("did:zhtp:placeholder"),
            device_id: String::from("default"),
        })
    }
    
    /// Get NodeId reference (for Kademlia routing)
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
    
    /// Get PublicKey reference (for signature verification)
    pub fn public_key(&self) -> &lib_crypto::PublicKey {
        &self.public_key
    }
    
    /// Get DID reference (for identity validation)
    pub fn did(&self) -> &str {
        &self.did
    }
    
    /// Get device ID reference
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

/// DHT node information with unified peer identity
///
/// **MIGRATION (Ticket #145):** Replaced NodeId-only identity with DhtPeerIdentity
/// to consolidate peer identification across the network.
///
/// # Security Properties
///
/// - **NodeId** - Used for Kademlia distance calculations (routing)
/// - **PublicKey** - Used for signature verification (security)
/// - **DID** - Used for identity validation (accountability)
///
/// # Compatibility
///
/// - Kademlia distance calculations still use NodeId (via `peer.node_id()`)
/// - Signature verification now uses `peer.public_key()` directly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNode {
    /// Unified peer identity (contains NodeId, PublicKey, DID, device_id)
    pub peer: DhtPeerIdentity,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Node public key for secure communication (post-quantum signature context)
    pub public_key: PostQuantumSignature,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Node reputation score
    pub reputation: u32,
    /// Storage capabilities
    pub storage_info: Option<StorageCapabilities>,
}

/// Zero-knowledge protected DHT value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkDhtValue {
    /// Encrypted content
    pub encrypted_data: Vec<u8>,
    /// Zero-knowledge proof of validity
    pub validity_proof: ZeroKnowledgeProof,
    /// Access control proof requirements
    pub access_requirements: Vec<String>,
    /// Content metadata (encrypted)
    pub encrypted_metadata: Vec<u8>,
    /// Storage timestamp
    pub stored_at: u64,
    /// Expiration timestamp (if any)
    pub expires_at: Option<u64>,
    /// Cryptographic nonce for security
    pub nonce: [u8; 32],
    /// Access level for the data
    pub access_level: AccessLevel,
    /// Timestamp for temporal ordering
    pub timestamp: u64,
}

/// DHT message types for peer communication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DhtMessageType {
    /// Ping to check node availability
    Ping,
    /// Pong response to ping
    Pong,
    /// Find nodes closest to target
    FindNode,
    /// Response with closest nodes
    FindNodeResponse,
    /// Store value
    Store,
    /// Store acknowledgment
    StoreResponse,
    /// Find value
    FindValue,
    /// Value found response
    FindValueResponse,
    /// Deploy smart contract
    ContractDeploy,
    /// Contract deployment response
    ContractDeployResponse,
    /// Query smart contract
    ContractQuery,
    /// Contract query response
    ContractQueryResponse,
    /// Execute smart contract function
    ContractExecute,
    /// Contract execution response
    ContractExecuteResponse,
    /// Find smart contract
    ContractFind,
    /// Contract find response
    ContractFindResponse,
}

/// DHT message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtMessage {
    /// Unique message identifier
    pub message_id: String,
    /// Type of message
    pub message_type: DhtMessageType,
    /// Sender node ID
    pub sender_id: NodeId,
    /// Target node ID (optional)
    pub target_id: Option<NodeId>,
    /// Key for store/find operations (optional)
    pub key: Option<String>,
    /// Value for store operations (optional)
    pub value: Option<Vec<u8>>,
    /// Node list for responses (optional)
    pub nodes: Option<Vec<DhtNode>>,
    /// Smart contract data (optional)
    pub contract_data: Option<ContractDhtData>,
    /// Message timestamp
    pub timestamp: u64,
    /// Digital signature (optional)
    pub signature: Option<Vec<u8>>,
}

/// DHT query response types
#[derive(Debug, Clone)]
pub enum DhtQueryResponse {
    /// Value found
    Value(Vec<u8>),
    /// Nodes found (value not found locally)
    Nodes(Vec<DhtNode>),
}

/// Storage entry in DHT
#[derive(Debug, Clone)]
pub struct StorageEntry {
    /// Storage key
    pub key: String,
    /// Stored value
    pub value: Vec<u8>,
    /// Storage timestamp
    pub timestamp: u64,
    /// Expiration timestamp (optional)
    pub expiry: Option<u64>,
    /// Chunk metadata
    pub metadata: ChunkMetadata,
    /// Zero-knowledge proof (optional)
    pub proof: Option<ZkProof>,
    /// Replica node IDs
    pub replicas: Vec<NodeId>,
    /// Access control information (optional)
    pub access_control: Option<String>,
}

/// Peer connection information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Node information
    pub node: DhtNode,
    /// Connection establishment time
    pub connection_time: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Connection status
    pub status: PeerStatus,
    /// Peer capabilities
    pub capabilities: Vec<String>,
}

/// Peer connection status
#[derive(Debug, Clone, PartialEq)]
pub enum PeerStatus {
    /// Connected and responsive
    Connected,
    /// Disconnected or unresponsive
    Disconnected,
    /// Connection in progress
    Connecting,
}

/// Peer statistics
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// Messages sent to peer
    pub messages_sent: u64,
    /// Messages received from peer
    pub messages_received: u64,
    /// Bytes sent to peer
    pub bytes_sent: u64,
    /// Bytes received from peer
    pub bytes_received: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average response time (seconds)
    pub avg_response_time: f64,
    /// Uptime percentage
    pub uptime_percentage: f64,
    /// Last statistics update
    pub last_updated: u64,
}

/// Replication policy configuration
#[derive(Debug, Clone)]
pub struct ReplicationPolicy {
    /// Number of replicas to maintain
    pub replication_factor: usize,
    /// Consistency level required
    pub consistency_level: ConsistencyLevel,
    /// Minimum replicas before repair is needed
    pub repair_threshold: usize,
    /// Maximum repair attempts
    pub max_repair_attempts: u32,
}

/// Consistency levels for replication
#[derive(Debug, Clone, PartialEq)]
pub enum ConsistencyLevel {
    /// Eventual consistency
    Eventual,
    /// Strong consistency
    Strong,
    /// Quorum consistency
    Quorum,
}

/// Replication status for a stored item
#[derive(Debug, Clone)]
pub struct ReplicationStatus {
    /// Storage key
    pub key: String,
    /// Current number of replicas
    pub total_replicas: usize,
    /// Required number of replicas
    pub required_replicas: usize,
    /// Nodes holding replicas
    pub replica_nodes: Vec<NodeId>,
    /// Nodes that failed to store replicas
    pub failed_nodes: Vec<NodeId>,
    /// Last replication update
    pub last_update: u64,
    /// Whether repair is needed
    pub repair_needed: bool,
}

/// DHT message types for peer communication (legacy enum for compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessageLegacy {
    /// Ping to check node availability
    Ping {
        sender: DhtNode,
        timestamp: u64,
    },
    /// Pong response to ping
    Pong {
        sender: DhtNode,
        timestamp: u64,
    },
    /// Find nodes closest to target
    FindNode {
        target: NodeId,
        sender: DhtNode,
    },
    /// Response with closest nodes
    NodesFound {
        nodes: Vec<DhtNode>,
        sender: DhtNode,
    },
    /// Store value with zero-knowledge privacy
    Store {
        key: DhtKey,
        value: ZkDhtValue,
        sender: DhtNode,
    },
    /// Store acknowledgment
    StoreAck {
        key: DhtKey,
        success: bool,
        sender: DhtNode,
    },
    /// Find value with privacy protection
    FindValue {
        key: DhtKey,
        sender: DhtNode,
        access_proof: ZeroKnowledgeProof,
    },
    /// Value found response
    ValueFound {
        key: DhtKey,
        value: Option<ZkDhtValue>,
        nodes: Vec<DhtNode>,
        sender: DhtNode,
    },
}

/// Kademlia-style K-bucket for DHT routing
#[derive(Debug, Clone)]
pub struct KBucket {
    /// Maximum number of nodes in bucket
    pub k: usize,
    /// Nodes in this bucket
    pub nodes: Vec<RoutingEntry>,
    /// Last bucket update time
    pub last_updated: SystemTime,
}

/// Entry in routing table
#[derive(Debug, Clone)]
pub struct RoutingEntry {
    /// Node information
    pub node: DhtNode,
    /// Distance from local node
    pub distance: u32,
    /// Last contact timestamp
    pub last_contact: u64,
    /// Failed ping attempts
    pub failed_attempts: u32,
}
