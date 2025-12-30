//! NodeRuntime - The Policy Authority
//!
//! # Architecture
//!
//! NodeRuntime is responsible for ALL "should we?" policy decisions:
//! - Should we discover peers via this method?
//! - Should we sync with this peer?
//! - Should we prefer QUIC over BLE for this peer?
//! - Should we use edge sync or full sync?
//! - Should we retry this failed connection?
//!
//! ZhtpUnifiedServer is responsible for ALL "can we?" execution:
//! - Can we open a QUIC socket? (yes/execute it)
//! - Can we send bytes to peer X? (yes/execute it)
//! - Can we listen on Bluetooth? (yes/execute it)
//!
//! # Invariants (CRITICAL)
//!
//! **NR-1: Policy Ownership Invariant**
//! All "should we?" decisions MUST live in NodeRuntime.
//! All "can we?" operations MUST live in ZhtpUnifiedServer.
//! If server answers "should", boundary is broken.
//!
//! **NR-2: Server Purity Invariant**
//! ZhtpUnifiedServer MUST NOT contain:
//! - protocol preference logic
//! - sync thresholds
//! - discovery strategy
//! - bootstrap heuristics
//!
//! **NR-3: Deterministic Runtime Invariant**
//! Given same inputs, NodeRuntime decisions MUST be deterministic.
//! Enables: reproducible tests, simulation, formal verification, offline reasoning.
//!
//! **NR-4: No Hidden Background Behavior Invariant**
//! NodeRuntime MUST be ONLY component allowed to initiate background activity:
//! - discovery loops
//! - sync retries
//! - periodic heartbeats
//! - bootstrap escalation
//!
//! **NR-5: Role Awareness Invariant**
//! NodeRuntime defines node role. Server is role-agnostic.
//! Examples: full validator, observer, bootstrap-only, light/mobile, archival.
//!
//! **NR-6: Replaceability Invariant**
//! Must be possible to replace NodeRuntime without modifying ZhtpUnifiedServer.
//! Enables: multiple runtimes (desktop, mobile, test, simulation).

use std::sync::Arc;
use std::time::SystemTime;
use lib_crypto::PublicKey;
use lib_network::protocols::NetworkProtocol;

// ============================================================================
// NodeRole - Defines what kind of node this is
// ============================================================================

/// Role of this node in the network
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeRole {
    /// Full validator - stores complete blockchain
    FullValidator,
    /// Observer - validates but doesn't participate in consensus
    Observer,
    /// Light node - stores only headers + ZK proofs
    LightNode,
    /// Mobile node - minimal storage, BLE-optimized
    MobileNode,
    /// Bootstrap node - helps new nodes join
    BootstrapNode,
    /// Archival node - stores all historical data
    ArchivalNode,
}

impl NodeRole {
    pub fn is_full_node(&self) -> bool {
        matches!(self, NodeRole::FullValidator | NodeRole::Observer)
    }

    pub fn is_light_node(&self) -> bool {
        matches!(self, NodeRole::LightNode | NodeRole::MobileNode)
    }

    pub fn stores_full_blockchain(&self) -> bool {
        matches!(self, NodeRole::FullValidator | NodeRole::Observer | NodeRole::ArchivalNode)
    }
}

// ============================================================================
// PeerInfo - Information about a discovered peer
// ============================================================================

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub public_key: PublicKey,
    pub addresses: Vec<String>,
    pub discovered_via: DiscoveryProtocol,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub capabilities: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryProtocol {
    UdpMulticast,
    BluetoothLE,
    BluetoothClassic,
    WiFiDirect,
    LoRaWAN,
    Bootstrap,
}

// ============================================================================
// PeerState - Current state of a peer
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Peer discovered but not yet connected
    Discovered,
    /// Actively syncing with peer
    Syncing,
    /// Connection established but idle
    Connected,
    /// Connection failed, waiting to retry
    Failed,
    /// Peer explicitly dropped
    Dropped,
}

#[derive(Clone, Debug)]
pub struct PeerStateChange {
    pub peer: PublicKey,
    pub old_state: PeerState,
    pub new_state: PeerState,
    pub reason: Option<String>,
}

// ============================================================================
// NodeAction - Atomic actions for server to execute
// ============================================================================

#[derive(Clone, Debug)]
pub enum NodeAction {
    /// Connect to peer via specific protocol
    Connect {
        peer: PublicKey,
        protocol: NetworkProtocol,
        address: Option<String>,
    },

    /// Start blockchain sync with peer
    StartSync {
        peer: PublicKey,
        protocol: NetworkProtocol,
        full_sync: bool, // true=full blockchain, false=edge mode (headers only)
    },

    /// Initiate peer discovery via specific method
    DiscoverVia(DiscoveryProtocol),

    /// Drop peer from active set
    DropPeer(PublicKey),

    /// Advertise our capabilities to peer
    AdvertiseCapabilities {
        peer: PublicKey,
        role: NodeRole,
    },

    /// Retry failed connection to peer
    RetryConnection {
        peer: PublicKey,
        protocol: NetworkProtocol,
    },

    /// Start background discovery loop
    StartDiscoveryLoop {
        protocol: DiscoveryProtocol,
        interval_secs: u64,
    },

    /// Bootstrap from specific peers
    BootstrapFrom(Vec<String>),

    /// Promote peer from casual to sync-ready
    PromotePeer(PublicKey),

    /// Demote peer (back off, throttle)
    DemotePeer {
        peer: PublicKey,
        reason: String,
    },
}

// ============================================================================
// Tick - Periodic events
// ============================================================================

#[derive(Clone, Debug)]
pub enum Tick {
    /// Every 5 seconds
    FiveSecond,
    /// Every 30 seconds
    ThirtySecond,
    /// Every minute
    OneMinute,
    /// Every 5 minutes
    FiveMinute,
}

// ============================================================================
// NodeRuntime Trait - Policy Authority
// ============================================================================

/// NodeRuntime is the policy authority for the node.
///
/// It answers all "should we?" questions:
/// - Should we discover peers now?
/// - Should we sync with this peer?
/// - Should we prefer QUIC over BLE?
/// - What is our role?
///
/// The server executes the actions it returns.
///
/// # Invariants
/// All implementations MUST be deterministic (NR-3).
/// All implementations MUST NOT spawn background tasks directly (NR-4).
/// Implementations are replaceable (NR-6) - server doesn't care which impl.
#[async_trait::async_trait]
pub trait NodeRuntime: Send + Sync {
    /// Get this node's role in the network
    fn get_role(&self) -> NodeRole;

    /// Peer discovery - decide what to do with newly discovered peer
    async fn on_peer_discovered(&self, peer: PeerInfo) -> Vec<NodeAction>;

    /// Peer state change - decide what to do when peer state changes
    async fn on_peer_state_changed(&self, change: PeerStateChange) -> Vec<NodeAction>;

    /// Periodic decision-making
    async fn on_timer(&self, tick: Tick) -> Vec<NodeAction>;

    /// Choose preferred protocol for this peer (deterministic ranking)
    /// Returns protocols in preference order
    fn get_preferred_protocols(&self, peer: &PeerInfo) -> Vec<NetworkProtocol>;

    /// Check if we should sync with this peer
    fn should_sync_with(&self, peer: &PeerInfo) -> bool;

    /// Get max concurrent syncs allowed
    fn max_concurrent_syncs(&self) -> usize {
        match self.get_role() {
            NodeRole::FullValidator | NodeRole::Observer => 16,
            NodeRole::LightNode | NodeRole::MobileNode => 4,
            NodeRole::BootstrapNode => 32,
            NodeRole::ArchivalNode => 8,
        }
    }

    /// Should we retry failed connection to this peer
    fn should_retry(&self, peer: &PublicKey, attempt: u32) -> bool;

    /// Get sync type for this peer (full or edge mode)
    fn get_sync_type(&self, _peer: &PeerInfo) -> SyncType {
        if self.get_role().is_light_node() {
            SyncType::EdgeNode
        } else {
            SyncType::FullBlockchain
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncType {
    FullBlockchain,
    EdgeNode, // headers + ZK proofs only
}

// ============================================================================
// DefaultNodeRuntime - Sensible defaults
// ============================================================================

pub struct DefaultNodeRuntime {
    role: NodeRole,
}

impl DefaultNodeRuntime {
    pub fn new(role: NodeRole) -> Self {
        Self { role }
    }

    pub fn full_validator() -> Self {
        Self::new(NodeRole::FullValidator)
    }

    pub fn light_node() -> Self {
        Self::new(NodeRole::LightNode)
    }
}

#[async_trait::async_trait]
impl NodeRuntime for DefaultNodeRuntime {
    fn get_role(&self) -> NodeRole {
        self.role.clone()
    }

    async fn on_peer_discovered(&self, peer: PeerInfo) -> Vec<NodeAction> {
        let mut actions = vec![];

        // Should we try to connect to this peer?
        if self.should_sync_with(&peer) {
            // Choose best protocol
            for protocol in self.get_preferred_protocols(&peer) {
                actions.push(NodeAction::Connect {
                    peer: peer.public_key.clone(),
                    protocol,
                    address: peer.addresses.first().cloned(),
                });
                break; // Try only preferred protocol first
            }
        }

        actions
    }

    async fn on_peer_state_changed(&self, change: PeerStateChange) -> Vec<NodeAction> {
        match change.new_state {
            PeerState::Failed => {
                // Don't immediately retry - let coordinator decide via timer
                vec![]
            }
            PeerState::Connected => {
                // Once connected, ask if we should sync
                if self.should_sync_with(&PeerInfo {
                    public_key: change.peer.clone(),
                    addresses: vec![],
                    discovered_via: DiscoveryProtocol::Bootstrap,
                    first_seen: SystemTime::now(),
                    last_seen: SystemTime::now(),
                    capabilities: None,
                }) {
                    vec![NodeAction::StartSync {
                        peer: change.peer,
                        protocol: NetworkProtocol::QUIC, // Should use best available
                        full_sync: self.get_role().stores_full_blockchain(),
                    }]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    async fn on_timer(&self, tick: Tick) -> Vec<NodeAction> {
        match tick {
            Tick::ThirtySecond => {
                // Every 30 seconds, maybe start a discovery loop
                vec![NodeAction::DiscoverVia(DiscoveryProtocol::UdpMulticast)]
            }
            _ => vec![],
        }
    }

    fn get_preferred_protocols(&self, peer: &PeerInfo) -> Vec<NetworkProtocol> {
        // Smart protocol selection based on peer discovery method
        // and peer capabilities
        match peer.discovered_via {
            DiscoveryProtocol::BluetoothLE => {
                // For BLE-discovered peers, check if they have better protocols available
                let has_quic_or_tcp = peer
                    .addresses
                    .iter()
                    .any(|addr| addr.contains("tcp://") || addr.contains("quic://"));

                if has_quic_or_tcp {
                    vec![NetworkProtocol::QUIC, NetworkProtocol::BluetoothLE]
                } else {
                    vec![NetworkProtocol::BluetoothLE]
                }
            }
            DiscoveryProtocol::UdpMulticast | DiscoveryProtocol::WiFiDirect => {
                vec![NetworkProtocol::QUIC, NetworkProtocol::UDP]
            }
            DiscoveryProtocol::BluetoothClassic => {
                vec![NetworkProtocol::BluetoothClassic]
            }
            DiscoveryProtocol::LoRaWAN => {
                vec![NetworkProtocol::LoRaWAN]
            }
            DiscoveryProtocol::Bootstrap => {
                vec![NetworkProtocol::QUIC, NetworkProtocol::UDP]
            }
        }
    }

    fn should_sync_with(&self, _peer: &PeerInfo) -> bool {
        // For now, sync with all discovered peers
        // More sophisticated implementations can filter
        true
    }

    fn should_retry(&self, _peer: &PublicKey, attempt: u32) -> bool {
        // Exponential backoff: retry up to 5 times
        attempt < 5
    }
}
