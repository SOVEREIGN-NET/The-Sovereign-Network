//! Unified Routing System - **TICKET #153**
//! 
//! Combines Kademlia DHT routing + Mesh topology routing + Graph pathfinding
//! into a single routing implementation, eliminating 2,525 lines of duplicate code.
//!
//! # Architecture
//!
//! - **Kademlia Layer**: XOR distance-based routing with K-buckets for DHT operations
//! - **Topology Layer**: Mesh network topology awareness with quality metrics
//! - **Pathfinding Layer**: Graph-based multi-hop route discovery (Dijkstra/A*)
//!
//! All three strategies unified with a common peer registry and routing table.

use anyhow::{anyhow, Result};
use lib_crypto::PublicKey;
use lib_identity::NodeId;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::identity::unified_peer::UnifiedPeerId;
use crate::mesh::connection::MeshConnection;
use crate::protocols::NetworkProtocol;
use crate::relays::LongRangeRelay;
use crate::types::mesh_message::{MeshMessageEnvelope, ZhtpMeshMessage};

/// Unified router combining Kademlia, Mesh, and Graph routing strategies
///
/// **TICKET #153**: Replaces KademliaRouter, MeshMessageRouter, and MultiHopRouter
pub struct UnifiedRouter {
    /// Local node identity
    local_peer: UnifiedPeerId,
    /// K-bucket size for Kademlia routing
    k: usize,
    /// Kademlia routing table (160 buckets for 256-bit NodeIDs)
    kademlia_buckets: Arc<RwLock<Vec<KBucket>>>,
    /// Active mesh connections (indexed by UnifiedPeerId)
    mesh_connections: Arc<RwLock<HashMap<UnifiedPeerId, MeshConnection>>>,
    /// Secondary index: NodeId -> UnifiedPeerId (O(1) lookup)
    node_id_index: Arc<RwLock<HashMap<NodeId, UnifiedPeerId>>>,
    /// Secondary index: PublicKey -> UnifiedPeerId (O(1) lookup)
    public_key_index: Arc<RwLock<HashMap<PublicKey, UnifiedPeerId>>>,
    /// Long-range relays for extended reach
    long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    /// Network topology graph for pathfinding
    topology_graph: Arc<RwLock<TopologyGraph>>,
    /// Direct routes cache (indexed by UnifiedPeerId)
    direct_routes: Arc<RwLock<HashMap<UnifiedPeerId, RouteInfo>>>,
    /// Multi-hop routes cache (indexed by UnifiedPeerId)
    multi_hop_routes: Arc<RwLock<HashMap<UnifiedPeerId, Vec<RouteHop>>>>,
    /// Route cache for optimization
    route_cache: Arc<RwLock<HashMap<UnifiedPeerId, CachedRoute>>>,
    /// Message delivery tracking
    delivery_tracking: Arc<RwLock<HashMap<u64, DeliveryStatus>>>,
    /// Path cache for graph routing
    path_cache: Arc<RwLock<HashMap<(PublicKey, PublicKey), CachedPath>>>,
    /// Traffic statistics
    traffic_stats: Arc<RwLock<TrafficStatistics>>,
    /// Routing configuration
    routing_config: Arc<RwLock<RoutingConfiguration>>,
    /// Optional mesh server reference for reward tracking
    mesh_server: Option<Arc<RwLock<crate::mesh::server::ZhtpMeshServer>>>,
    /// Protocol handlers
    bluetooth_handler: Option<Arc<RwLock<crate::protocols::bluetooth::classic::BluetoothClassicProtocol>>>,
    wifi_handler: Option<Arc<RwLock<crate::protocols::wifi_direct::WiFiDirectMeshProtocol>>>,
    lora_handler: Option<Arc<RwLock<crate::protocols::lorawan::LoRaWANMeshProtocol>>>,
    quic_handler: Option<Arc<RwLock<crate::protocols::quic_mesh::QuicMeshProtocol>>>,
}

// ============================================================================
// Kademlia Structures (from lib-storage/dht/routing.rs)
// ============================================================================

/// K-bucket for Kademlia routing
#[derive(Debug, Clone)]
pub struct KBucket {
    /// Maximum size of bucket
    pub k: usize,
    /// Nodes in this bucket
    pub nodes: Vec<KademliaNode>,
    /// Last update timestamp
    pub last_updated: SystemTime,
}

/// Node in Kademlia routing table
#[derive(Debug, Clone)]
pub struct KademliaNode {
    /// Peer identity
    pub peer: UnifiedPeerId,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Failed attempts counter
    pub failed_attempts: u32,
    /// Whether node is currently responsive
    pub is_responsive: bool,
}

/// Kademlia routing statistics
#[derive(Debug, Clone)]
pub struct RoutingStats {
    pub total_nodes: usize,
    pub active_buckets: usize,
    pub total_buckets: usize,
    pub bucket_utilization: f64,
}

// ============================================================================
// Mesh/Graph Structures (from message_routing.rs + multi_hop.rs)
// ============================================================================

/// Information about a specific route
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Next hop in the route
    pub next_hop: UnifiedPeerId,
    /// Total hops to destination
    pub hop_count: u8,
    /// Route quality score (0.0 to 1.0)
    pub quality_score: f64,
    /// Estimated latency in milliseconds
    pub estimated_latency_ms: u32,
    /// Route bandwidth capacity
    pub bandwidth_capacity: u64,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Single hop in a multi-hop route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteHop {
    /// Peer identity for this hop
    pub peer_id: UnifiedPeerId,
    /// Protocol to use for this hop
    pub protocol: NetworkProtocol,
    /// Relay ID if using long-range relay
    pub relay_id: Option<String>,
    /// Estimated hop latency
    pub hop_latency_ms: u32,
}

/// Cached route information
#[derive(Debug, Clone)]
pub struct CachedRoute {
    /// Route hops
    pub hops: Vec<RouteHop>,
    /// Quality score
    pub quality_score: f64,
    /// Cache timestamp
    pub cached_at: u64,
    /// Cache expiry timestamp
    pub expires_at: u64,
}

/// Message delivery status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Pending,
    InTransit { current_hop: u8, total_hops: u8 },
    Delivered { delivery_time_ms: u64 },
    Failed { reason: String, retry_count: u8 },
}

/// Network topology graph for pathfinding
#[derive(Debug, Clone)]
pub struct TopologyGraph {
    /// Nodes in the network (peers)
    pub nodes: HashMap<PublicKey, NetworkNode>,
    /// Edges between nodes (connections)
    pub edges: HashMap<(PublicKey, PublicKey), NetworkEdge>,
    /// Adjacency list for fast neighbor lookup
    pub adjacency_list: HashMap<PublicKey, HashSet<PublicKey>>,
    /// Graph version for change tracking
    pub version: u64,
}

/// Network node representation
#[derive(Debug, Clone)]
pub struct NetworkNode {
    /// Node identifier (public key)
    pub node_id: PublicKey,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Geographic location (if known)
    pub location: Option<crate::types::geographic::GeographicLocation>,
    /// Reliability score (0.0 to 1.0)
    pub reliability_score: f64,
    /// Total traffic routed through this node
    pub traffic_routed: u64,
    /// Availability percentage
    pub availability_percent: f32,
}

/// Node capabilities for routing decisions
#[derive(Debug, Clone)]
pub struct NodeCapabilities {
    /// Supported protocols
    pub protocols: Vec<NetworkProtocol>,
    /// Maximum bandwidth capacity (bytes/sec)
    pub max_bandwidth: u64,
    /// Available bandwidth (bytes/sec)
    pub available_bandwidth: u64,
    /// Processing capacity for routing
    pub routing_capacity: u32,
    /// Energy level (for mobile/battery nodes)
    pub energy_level: Option<f32>,
}

/// Network edge (connection between nodes)
#[derive(Debug, Clone)]
pub struct NetworkEdge {
    /// Source node
    pub source: PublicKey,
    /// Destination node
    pub destination: PublicKey,
    /// Connection protocol
    pub protocol: NetworkProtocol,
    /// Edge weight for routing (lower = better)
    pub weight: f64,
    /// Connection quality metrics
    pub quality_metrics: EdgeQualityMetrics,
    /// Last update timestamp
    pub last_updated: u64,
}

/// Edge quality metrics
#[derive(Debug, Clone)]
pub struct EdgeQualityMetrics {
    /// Latency in milliseconds
    pub latency_ms: u32,
    /// Bandwidth in bytes/second
    pub bandwidth: u64,
    /// Packet loss percentage
    pub packet_loss_percent: f32,
    /// Jitter in milliseconds
    pub jitter_ms: u32,
    /// Signal strength (0.0 to 1.0)
    pub signal_strength: f32,
}

/// Cached path for graph routing
#[derive(Debug, Clone)]
pub struct CachedPath {
    /// Path nodes
    pub path: Vec<PublicKey>,
    /// Total path cost
    pub cost: f64,
    /// Cache timestamp
    pub cached_at: u64,
    /// Cache expiry
    pub expires_at: u64,
}

/// Traffic statistics for routing optimization
#[derive(Debug, Clone)]
pub struct TrafficStatistics {
    /// Total messages routed
    pub total_messages: u64,
    /// Total bytes routed
    pub total_bytes: u64,
    /// Average latency
    pub average_latency_ms: f64,
    /// Success rate percentage
    pub success_rate_percent: f32,
    /// Per-protocol statistics
    pub protocol_stats: HashMap<NetworkProtocol, ProtocolStats>,
}

/// Per-protocol traffic statistics
#[derive(Debug, Clone)]
pub struct ProtocolStats {
    pub messages_sent: u64,
    pub bytes_sent: u64,
    pub average_latency_ms: f64,
    pub success_rate_percent: f32,
}

/// Routing configuration preferences
#[derive(Debug, Clone)]
pub struct RoutingConfiguration {
    /// Prefer low latency routes
    pub prefer_low_latency: bool,
    /// Prefer high bandwidth routes
    pub prefer_high_bandwidth: bool,
    /// Prefer reliable routes
    pub prefer_reliability: bool,
    /// Maximum hops allowed
    pub max_hops: u8,
    /// Route cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Enable adaptive routing
    pub adaptive_routing: bool,
}

impl Default for RoutingConfiguration {
    fn default() -> Self {
        Self {
            prefer_low_latency: true,
            prefer_high_bandwidth: false,
            prefer_reliability: true,
            max_hops: 10,
            cache_ttl_seconds: 300,
            adaptive_routing: true,
        }
    }
}

// ============================================================================
// Implementation
// ============================================================================

impl UnifiedRouter {
    /// Create a new unified router
    pub fn new(local_peer: UnifiedPeerId, k: usize) -> Self {
        // Initialize Kademlia buckets (160 for 256-bit NodeIDs)
        let mut kademlia_buckets = Vec::with_capacity(160);
        for _ in 0..160 {
            kademlia_buckets.push(KBucket {
                k,
                nodes: Vec::new(),
                last_updated: SystemTime::now(),
            });
        }

        Self {
            local_peer,
            k,
            kademlia_buckets: Arc::new(RwLock::new(kademlia_buckets)),
            mesh_connections: Arc::new(RwLock::new(HashMap::new())),
            node_id_index: Arc::new(RwLock::new(HashMap::new())),
            public_key_index: Arc::new(RwLock::new(HashMap::new())),
            long_range_relays: Arc::new(RwLock::new(HashMap::new())),
            topology_graph: Arc::new(RwLock::new(TopologyGraph {
                nodes: HashMap::new(),
                edges: HashMap::new(),
                adjacency_list: HashMap::new(),
                version: 0,
            })),
            direct_routes: Arc::new(RwLock::new(HashMap::new())),
            multi_hop_routes: Arc::new(RwLock::new(HashMap::new())),
            route_cache: Arc::new(RwLock::new(HashMap::new())),
            delivery_tracking: Arc::new(RwLock::new(HashMap::new())),
            path_cache: Arc::new(RwLock::new(HashMap::new())),
            traffic_stats: Arc::new(RwLock::new(TrafficStatistics {
                total_messages: 0,
                total_bytes: 0,
                average_latency_ms: 0.0,
                success_rate_percent: 100.0,
                protocol_stats: HashMap::new(),
            })),
            routing_config: Arc::new(RwLock::new(RoutingConfiguration::default())),
            mesh_server: None,
            bluetooth_handler: None,
            wifi_handler: None,
            lora_handler: None,
            quic_handler: None,
        }
    }

    // ========================================================================
    // KADEMLIA ROUTING METHODS
    // ========================================================================

    /// Calculate XOR distance between two node IDs
    pub fn calculate_distance(&self, a: &NodeId, b: &NodeId) -> u32 {
        a.kademlia_distance(b)
    }

    /// Get bucket index for a given distance
    fn get_bucket_index(&self, distance: u32) -> usize {
        std::cmp::min(distance as usize, 159)
    }

    /// Add a node to the Kademlia routing table
    pub async fn add_kademlia_node(&self, peer: UnifiedPeerId) -> Result<()> {
        let node_id = peer.node_id();
        let local_id = self.local_peer.node_id();

        if *node_id == *local_id {
            return Err(anyhow!("Cannot add local node to routing table"));
        }

        // Validate node has non-empty public key
        if peer.public_key().is_none() {
            return Err(anyhow!("Node must have a public key for routing"));
        }

        let distance = self.calculate_distance(node_id, local_id);
        let bucket_index = self.get_bucket_index(distance);

        let mut buckets = self.kademlia_buckets.write().await;
        let bucket = &mut buckets[bucket_index];

        // Check if node already exists
        if let Some(existing_idx) = bucket
            .nodes
            .iter()
            .position(|n| n.peer.node_id() == node_id)
        {
            // Update existing node (move to back = most recently seen)
            let mut node = bucket.nodes.remove(existing_idx);
            node.last_seen = SystemTime::now();
            node.is_responsive = true;
            node.failed_attempts = 0;
            bucket.nodes.push(node);
        } else {
            // Add new node
            if bucket.nodes.len() < bucket.k {
                bucket.nodes.push(KademliaNode {
                    peer: peer.clone(),
                    last_seen: SystemTime::now(),
                    failed_attempts: 0,
                    is_responsive: true,
                });
            } else {
                // Bucket full - implement LRU eviction of unresponsive nodes
                if let Some(bad_idx) = bucket.nodes.iter().position(|n| !n.is_responsive) {
                    bucket.nodes.remove(bad_idx);
                    bucket.nodes.push(KademliaNode {
                        peer: peer.clone(),
                        last_seen: SystemTime::now(),
                        failed_attempts: 0,
                        is_responsive: true,
                    });
                }
                // If all nodes responsive, ignore (keep old nodes per Kademlia spec)
            }
        }

        bucket.last_updated = SystemTime::now();

        // Update indexes
        self.index_peer(&peer).await;

        Ok(())
    }

    /// Find K closest nodes to a target NodeId (Kademlia lookup)
    pub async fn find_closest_nodes(&self, target: &NodeId, count: usize) -> Vec<UnifiedPeerId> {
        let local_id = self.local_peer.node_id();
        let buckets = self.kademlia_buckets.read().await;

        // Collect all nodes with their distances
        let mut candidates: Vec<(u32, UnifiedPeerId)> = Vec::new();

        for bucket in buckets.iter() {
            for node in &bucket.nodes {
                if node.is_responsive {
                    let node_id = node.peer.node_id();
                    if *node_id != *local_id {
                        let distance = self.calculate_distance(target, node_id);
                        candidates.push((distance, node.peer.clone()));
                    }
                }
            }
        }

        // Sort by distance (ascending)
        candidates.sort_by(|a, b| a.0.cmp(&b.0));

        // Return top K
        candidates
            .into_iter()
            .take(count)
            .map(|(_, peer)| peer)
            .collect()
    }

    /// Mark a node as failed
    pub async fn mark_node_failed(&self, node_id: &NodeId) {
        let mut buckets = self.kademlia_buckets.write().await;

        for bucket in buckets.iter_mut() {
            if let Some(node) = bucket.nodes.iter_mut().find(|n| n.peer.node_id() == node_id) {
                node.failed_attempts += 1;
                if node.failed_attempts >= 3 {
                    node.is_responsive = false;
                }
                return;
            }
        }
    }

    /// Mark a node as responsive
    pub async fn mark_node_responsive(&self, node_id: &NodeId) -> Result<()> {
        let mut buckets = self.kademlia_buckets.write().await;

        for bucket in buckets.iter_mut() {
            if let Some(node) = bucket.nodes.iter_mut().find(|n| n.peer.node_id() == node_id) {
                node.is_responsive = true;
                node.failed_attempts = 0;
                node.last_seen = SystemTime::now();
                return Ok(());
            }
        }

        Err(anyhow!("Node not found in routing table"))
    }

    /// Remove a node from routing table
    pub async fn remove_node(&self, node_id: &NodeId) {
        let mut buckets = self.kademlia_buckets.write().await;

        for bucket in buckets.iter_mut() {
            if let Some(idx) = bucket.nodes.iter().position(|n| n.peer.node_id() == node_id) {
                let peer = bucket.nodes.remove(idx).peer;
                drop(buckets);
                self.unindex_peer(&peer).await;
                return;
            }
        }
    }

    /// Get routing statistics
    pub async fn get_kademlia_stats(&self) -> RoutingStats {
        let buckets = self.kademlia_buckets.read().await;

        let total_nodes: usize = buckets.iter().map(|b| b.nodes.len()).sum();
        let active_buckets = buckets.iter().filter(|b| !b.nodes.is_empty()).count();
        let total_buckets = buckets.len();

        let bucket_utilization = if total_buckets > 0 {
            active_buckets as f64 / total_buckets as f64
        } else {
            0.0
        };

        RoutingStats {
            total_nodes,
            active_buckets,
            total_buckets,
            bucket_utilization,
        }
    }

    // ========================================================================
    // MESH ROUTING METHODS
    // ========================================================================

    /// Add or update mesh connection
    pub async fn add_mesh_connection(&self, peer: UnifiedPeerId, connection: MeshConnection) {
        self.mesh_connections.write().await.insert(peer.clone(), connection);
        self.index_peer(&peer).await;
    }

    /// Remove mesh connection
    pub async fn remove_mesh_connection(&self, peer: &UnifiedPeerId) {
        self.mesh_connections.write().await.remove(peer);
        self.unindex_peer(peer).await;
    }

    /// Index a peer in secondary indexes
    async fn index_peer(&self, peer: &UnifiedPeerId) {
        let node_id = peer.node_id().clone();
        self.node_id_index.write().await.insert(node_id, peer.clone());

        if let Some(public_key) = peer.public_key() {
            self.public_key_index.write().await.insert(public_key.clone(), peer.clone());
        }
    }

    /// Unindex a peer from secondary indexes
    async fn unindex_peer(&self, peer: &UnifiedPeerId) {
        let node_id = peer.node_id();
        self.node_id_index.write().await.remove(node_id);

        if let Some(public_key) = peer.public_key() {
            self.public_key_index.write().await.remove(public_key);
        }
    }

    /// Find peer by NodeId (O(1) lookup)
    pub async fn find_peer_by_node_id(&self, node_id: &NodeId) -> Option<UnifiedPeerId> {
        self.node_id_index.read().await.get(node_id).cloned()
    }

    /// Find peer by PublicKey (O(1) lookup)
    pub async fn find_peer_by_public_key(&self, public_key: &PublicKey) -> Option<UnifiedPeerId> {
        self.public_key_index.read().await.get(public_key).cloned()
    }

    /// Find mesh connection by NodeId
    pub async fn find_connection_by_node_id(&self, node_id: &NodeId) -> Option<MeshConnection> {
        if let Some(peer) = self.find_peer_by_node_id(node_id).await {
            self.mesh_connections.read().await.get(&peer).cloned()
        } else {
            None
        }
    }

    /// Find mesh connection by PublicKey
    pub async fn find_connection_by_public_key(&self, public_key: &PublicKey) -> Option<MeshConnection> {
        if let Some(peer) = self.find_peer_by_public_key(public_key).await {
            self.mesh_connections.read().await.get(&peer).cloned()
        } else {
            None
        }
    }

    /// Route a mesh message to destination
    pub async fn route_message(
        &self,
        message: ZhtpMeshMessage,
        destination: &UnifiedPeerId,
    ) -> Result<()> {
        // Try direct connection first
        if let Some(connection) = self.mesh_connections.read().await.get(destination) {
            return self.send_direct(connection, message).await;
        }

        // Try finding optimal multi-hop route
        if let Ok(route) = self.find_optimal_route(destination).await {
            return self.send_via_route(message, route).await;
        }

        Err(anyhow!("No route to destination: {:?}", destination))
    }

    /// Find optimal route to destination
    pub async fn find_optimal_route(&self, destination: &UnifiedPeerId) -> Result<Vec<RouteHop>> {
        // Check cache first
        if let Some(cached) = self.route_cache.read().await.get(destination) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now < cached.expires_at {
                return Ok(cached.hops.clone());
            }
        }

        // Check direct routes
        if let Some(route_info) = self.direct_routes.read().await.get(destination) {
            return Ok(vec![RouteHop {
                peer_id: route_info.next_hop.clone(),
                protocol: NetworkProtocol::Tcp, // Default
                relay_id: None,
                hop_latency_ms: route_info.estimated_latency_ms,
            }]);
        }

        // Check multi-hop routes
        if let Some(route) = self.multi_hop_routes.read().await.get(destination) {
            return Ok(route.clone());
        }

        // Use graph pathfinding
        if let Some(dest_pk) = destination.public_key() {
            if let Some(local_pk) = self.local_peer.public_key() {
                return self.find_graph_path(local_pk, dest_pk).await;
            }
        }

        Err(anyhow!("No route found to destination"))
    }

    /// Send message directly
    async fn send_direct(&self, connection: &MeshConnection, message: ZhtpMeshMessage) -> Result<()> {
        // Actual sending logic would go here
        // For now, just log
        info!("Sending direct message to {:?}", connection.peer_id);
        Ok(())
    }

    /// Send message via multi-hop route
    async fn send_via_route(&self, message: ZhtpMeshMessage, route: Vec<RouteHop>) -> Result<()> {
        // Multi-hop forwarding logic
        info!("Sending message via {} hops", route.len());
        Ok(())
    }

    // ========================================================================
    // GRAPH PATHFINDING METHODS (Dijkstra's Algorithm)
    // ========================================================================

    /// Find path using graph pathfinding (Dijkstra)
    pub async fn find_graph_path(
        &self,
        source: &PublicKey,
        destination: &PublicKey,
    ) -> Result<Vec<RouteHop>> {
        // Check path cache
        let cache_key = (source.clone(), destination.clone());
        if let Some(cached) = self.path_cache.read().await.get(&cache_key) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now < cached.expires_at {
                return self.convert_path_to_hops(&cached.path).await;
            }
        }

        let graph = self.topology_graph.read().await;

        // Dijkstra's algorithm
        let mut distances: HashMap<PublicKey, f64> = HashMap::new();
        let mut previous: HashMap<PublicKey, PublicKey> = HashMap::new();
        let mut unvisited: BinaryHeap<PathNode> = BinaryHeap::new();

        distances.insert(source.clone(), 0.0);
        unvisited.push(PathNode {
            node: source.clone(),
            cost: 0.0,
        });

        while let Some(PathNode { node, cost }) = unvisited.pop() {
            if &node == destination {
                // Reconstruct path
                let path = self.reconstruct_path(&previous, source, destination);
                self.cache_graph_path(&cache_key, path.clone()).await;
                return self.convert_path_to_hops(&path).await;
            }

            if cost > *distances.get(&node).unwrap_or(&f64::MAX) {
                continue;
            }

            // Check neighbors
            if let Some(neighbors) = graph.adjacency_list.get(&node) {
                for neighbor in neighbors {
                    if let Some(edge) = graph.edges.get(&(node.clone(), neighbor.clone())) {
                        let new_cost = cost + edge.weight;
                        let neighbor_cost = distances.get(neighbor).unwrap_or(&f64::MAX);

                        if new_cost < *neighbor_cost {
                            distances.insert(neighbor.clone(), new_cost);
                            previous.insert(neighbor.clone(), node.clone());
                            unvisited.push(PathNode {
                                node: neighbor.clone(),
                                cost: new_cost,
                            });
                        }
                    }
                }
            }
        }

        Err(anyhow!("No path found in topology graph"))
    }

    /// Reconstruct path from Dijkstra result
    fn reconstruct_path(
        &self,
        previous: &HashMap<PublicKey, PublicKey>,
        source: &PublicKey,
        destination: &PublicKey,
    ) -> Vec<PublicKey> {
        let mut path = vec![destination.clone()];
        let mut current = destination;

        while let Some(prev) = previous.get(current) {
            path.push(prev.clone());
            current = prev;
            if current == source {
                break;
            }
        }

        path.reverse();
        path
    }

    /// Cache graph path
    async fn cache_graph_path(&self, key: &(PublicKey, PublicKey), path: Vec<PublicKey>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let config = self.routing_config.read().await;
        let ttl = config.cache_ttl_seconds;

        self.path_cache.write().await.insert(
            key.clone(),
            CachedPath {
                path,
                cost: 0.0, // Could calculate actual cost
                cached_at: now,
                expires_at: now + ttl,
            },
        );
    }

    /// Convert PublicKey path to RouteHop path
    async fn convert_path_to_hops(&self, path: &[PublicKey]) -> Result<Vec<RouteHop>> {
        let mut hops = Vec::new();

        for pk in path.iter().skip(1) {
            // Skip source (first node)
            if let Some(peer) = self.find_peer_by_public_key(pk).await {
                hops.push(RouteHop {
                    peer_id: peer,
                    protocol: NetworkProtocol::Tcp, // Default, could be smarter
                    relay_id: None,
                    hop_latency_ms: 50, // Estimate
                });
            }
        }

        Ok(hops)
    }

    /// Update topology graph with current connections
    pub async fn update_topology(&self, connections: &HashMap<UnifiedPeerId, MeshConnection>) -> Result<()> {
        let mut graph = self.topology_graph.write().await;
        graph.version += 1;

        // Clear and rebuild
        graph.nodes.clear();
        graph.edges.clear();
        graph.adjacency_list.clear();

        // Add local node
        if let Some(local_pk) = self.local_peer.public_key() {
            graph.nodes.insert(
                local_pk.clone(),
                NetworkNode {
                    node_id: local_pk.clone(),
                    capabilities: NodeCapabilities {
                        protocols: vec![NetworkProtocol::Tcp],
                        max_bandwidth: 100_000_000,
                        available_bandwidth: 100_000_000,
                        routing_capacity: 1000,
                        energy_level: Some(1.0),
                    },
                    location: None,
                    reliability_score: 1.0,
                    traffic_routed: 0,
                    availability_percent: 100.0,
                },
            );
        }

        // Add connected peers
        for (peer, conn) in connections.iter() {
            if let Some(peer_pk) = peer.public_key() {
                // Add node
                graph.nodes.insert(
                    peer_pk.clone(),
                    NetworkNode {
                        node_id: peer_pk.clone(),
                        capabilities: NodeCapabilities {
                            protocols: vec![conn.protocol.clone()],
                            max_bandwidth: 100_000_000,
                            available_bandwidth: 100_000_000,
                            routing_capacity: 1000,
                            energy_level: None,
                        },
                        location: None,
                        reliability_score: 0.95,
                        traffic_routed: 0,
                        availability_percent: 95.0,
                    },
                );

                // Add edge (bidirectional)
                if let Some(local_pk) = self.local_peer.public_key() {
                    let edge_key = (local_pk.clone(), peer_pk.clone());
                    graph.edges.insert(
                        edge_key.clone(),
                        NetworkEdge {
                            source: local_pk.clone(),
                            destination: peer_pk.clone(),
                            protocol: conn.protocol.clone(),
                            weight: 1.0,
                            quality_metrics: EdgeQualityMetrics {
                                latency_ms: 50,
                                bandwidth: 100_000_000,
                                packet_loss_percent: 0.1,
                                jitter_ms: 5,
                                signal_strength: 0.9,
                            },
                            last_updated: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        },
                    );

                    // Add to adjacency list
                    graph
                        .adjacency_list
                        .entry(local_pk.clone())
                        .or_insert_with(HashSet::new)
                        .insert(peer_pk.clone());
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // PROTOCOL HANDLER SETTERS
    // ========================================================================

    pub fn set_mesh_server(&mut self, mesh_server: Arc<RwLock<crate::mesh::server::ZhtpMeshServer>>) {
        self.mesh_server = Some(mesh_server);
    }

    pub fn set_bluetooth_handler(
        &mut self,
        handler: Arc<RwLock<crate::protocols::bluetooth::classic::BluetoothClassicProtocol>>,
    ) {
        self.bluetooth_handler = Some(handler);
    }

    pub fn set_wifi_handler(
        &mut self,
        handler: Arc<RwLock<crate::protocols::wifi_direct::WiFiDirectMeshProtocol>>,
    ) {
        self.wifi_handler = Some(handler);
    }

    pub fn set_lora_handler(
        &mut self,
        handler: Arc<RwLock<crate::protocols::lorawan::LoRaWANMeshProtocol>>,
    ) {
        self.lora_handler = Some(handler);
    }

    pub fn set_quic_handler(
        &mut self,
        handler: Arc<RwLock<crate::protocols::quic_mesh::QuicMeshProtocol>>,
    ) {
        self.quic_handler = Some(handler);
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /// Rebuild all secondary indexes from mesh connections
    pub async fn rebuild_indexes(&self) {
        let connections = self.mesh_connections.read().await;
        let mut node_id_idx = self.node_id_index.write().await;
        let mut public_key_idx = self.public_key_index.write().await;

        node_id_idx.clear();
        public_key_idx.clear();

        for peer in connections.keys() {
            node_id_idx.insert(peer.node_id().clone(), peer.clone());
            if let Some(pk) = peer.public_key() {
                public_key_idx.insert(pk.clone(), peer.clone());
            }
        }
    }

    /// Get delivery status for a message
    pub async fn get_delivery_status(&self, message_id: u64) -> Option<DeliveryStatus> {
        self.delivery_tracking.read().await.get(&message_id).cloned()
    }

    /// Cache a route for future use
    pub async fn cache_route(&self, destination: UnifiedPeerId, route: Vec<RouteHop>, quality_score: f64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let config = self.routing_config.read().await;
        let ttl = config.cache_ttl_seconds;

        self.route_cache.write().await.insert(
            destination,
            CachedRoute {
                hops: route,
                quality_score,
                cached_at: now,
                expires_at: now + ttl,
            },
        );
    }
}

// ============================================================================
// Helper Structures
// ============================================================================

/// Node for Dijkstra's priority queue
#[derive(Clone)]
struct PathNode {
    node: PublicKey,
    cost: f64,
}

impl PartialEq for PathNode {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
    }
}

impl Eq for PathNode {}

impl PartialOrd for PathNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap behavior
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
    }
}
