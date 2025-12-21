//! Mesh Message Routing Implementation
//! 
//! Advanced peer-to-peer message delivery with intelligent routing

use anyhow::{anyhow, Result};
use bincode;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use lib_crypto::PublicKey;
use serde::{Serialize, Deserialize};

use crate::types::mesh_message::{ZhtpMeshMessage, MeshMessageEnvelope};
use crate::mesh::connection::MeshConnection;
use crate::relays::LongRangeRelay;
use crate::protocols::NetworkProtocol;
use crate::identity::unified_peer::UnifiedPeerId;
use crate::transport::TransportManager;
use lib_identity::NodeId;

/// Maximum cached routes to bound memory and prevent cache abuse
const MAX_ROUTE_CACHE_ENTRIES: usize = 1024;

/// Intelligent mesh message router
///
/// **MIGRATION (Ticket #149):** Now uses unified PeerRegistry instead of separate mesh_connections.
/// This provides single source of truth for peer data shared across mesh, DHT, and routing.
///
/// **Previous (Ticket #146):** Updated to use UnifiedPeerId for routing table keys
/// instead of PublicKey-only, enabling routing by NodeId or PublicKey interchangeably.
///
/// # Security (HIGH-1 Fix)
///
/// PeerRegistry has built-in secondary indexes for O(1) constant-time lookups,
/// preventing timing side-channel attacks where attackers could determine
/// peer presence by measuring lookup latency.
pub struct MeshMessageRouter {
    /// Unified peer registry (Ticket #149: replaces mesh_connections and secondary indexes)
    pub peer_registry: crate::peer_registry::SharedPeerRegistry,
    /// Long-range relays for extended reach
    pub long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    /// Routing table for efficient path finding
    pub routing_table: Arc<RwLock<RoutingTable>>,
    /// Message delivery tracking
    pub delivery_tracking: Arc<RwLock<HashMap<u64, DeliveryStatus>>>,
    /// Route cache for optimization (indexed by UnifiedPeerId)
    pub route_cache: Arc<RwLock<HashMap<UnifiedPeerId, CachedRoute>>>,
    /// Optional mesh server reference for reward tracking
    pub mesh_server: Option<Arc<RwLock<crate::mesh::server::ZhtpMeshServer>>>,
    /// Transport manager for enforcing secure handler selection
    pub transport_manager: Option<TransportManager>,
}

/// Routing table for mesh network
///
/// **MIGRATION (Ticket #146):** Uses UnifiedPeerId for all routing operations
#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// Direct connections to peers (indexed by UnifiedPeerId)
    pub direct_routes: HashMap<UnifiedPeerId, RouteInfo>,
    /// Multi-hop routes to distant peers (indexed by UnifiedPeerId)
    pub multi_hop_routes: HashMap<UnifiedPeerId, Vec<RouteHop>>,
    /// Network topology understanding
    pub topology_map: TopologyMap,
}

/// Information about a specific route
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Next hop in the route (UnifiedPeerId)
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
///
/// **MIGRATION (Ticket #146):** Changed peer_id from PublicKey to UnifiedPeerId
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteHop {
    /// Peer identity for this hop (full UnifiedPeerId)
    pub peer_id: UnifiedPeerId,
    /// Protocol to use for this hop
    pub protocol: NetworkProtocol,
    /// Relay ID if using long-range relay
    pub relay_id: Option<String>,
    /// Estimated hop latency
    pub latency_ms: u32,
}

/// Network topology map
///
/// **MIGRATION (Ticket #146):** Uses UnifiedPeerId for topology mapping
#[derive(Debug, Clone)]
pub struct TopologyMap {
    /// Known peers and their connections (indexed by UnifiedPeerId)
    pub peer_connections: HashMap<UnifiedPeerId, HashSet<UnifiedPeerId>>,
    /// Geographic clustering information
    pub geographic_clusters: Vec<GeographicCluster>,
    /// Network coverage areas
    pub coverage_areas: Vec<CoverageArea>,
}

/// Geographic cluster of nearby nodes
#[derive(Debug, Clone)]
pub struct GeographicCluster {
    /// Cluster center coordinates
    pub center_lat: f64,
    pub center_lon: f64,
    /// Cluster radius in kilometers
    pub radius_km: f64,
    /// Peers in this cluster
    pub peers: HashSet<PublicKey>,
    /// Cluster connectivity score
    pub connectivity_score: f64,
}

/// Network coverage area
#[derive(Debug, Clone)]
pub struct CoverageArea {
    /// Coverage type (WiFi, LoRa, Satellite, etc.)
    pub coverage_type: String,
    /// Coverage radius in kilometers
    pub radius_km: f64,
    /// Center coordinates
    pub center_lat: f64,
    pub center_lon: f64,
    /// Responsible relay or node
    pub provider: PublicKey,
}

/// Cached route information
#[derive(Debug, Clone)]
pub struct CachedRoute {
    /// Route hops
    pub hops: Vec<RouteHop>,
    /// Route quality score
    pub quality_score: f64,
    /// Cache timestamp
    pub cached_at: u64,
    /// Cache validity duration in seconds
    pub validity_duration: u64,
    /// Maximum MTU across all hops (helps enforce fragmentation)
    pub max_mtu: u64,
}

/// Message delivery status tracking
#[derive(Debug, Clone)]
pub struct DeliveryStatus {
    /// Message ID being tracked
    pub message_id: u64,
    /// Destination peer
    pub destination: PublicKey,
    /// Current routing stage
    pub stage: DeliveryStage,
    /// Route being used
    pub route: Vec<RouteHop>,
    /// Current hop index
    pub current_hop: usize,
    /// Delivery attempts
    pub attempts: u32,
    /// Started timestamp
    pub started_at: u64,
    /// Last update timestamp
    pub last_update: u64,
}

/// Delivery stage enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryStage {
    Planning,      // Route planning
    Routing,       // Active routing
    LongRange,     // Using long-range relay
    Delivered,     // Successfully delivered
    Failed,        // Delivery failed
    Retrying,      // Retrying delivery
}

impl MeshMessageRouter {
    /// Create new mesh message router
    ///
    /// **MIGRATION (Ticket #149):** Now accepts SharedPeerRegistry instead of mesh_connections
    ///
    /// # Security (HIGH-1 Fix)
    ///
    /// PeerRegistry provides built-in secondary indexes for O(1) constant-time lookups.
    pub fn new(
        peer_registry: crate::peer_registry::SharedPeerRegistry,
        long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    ) -> Self {
        Self {
            peer_registry,
            long_range_relays,
            routing_table: Arc::new(RwLock::new(RoutingTable {
                direct_routes: HashMap::new(),
                multi_hop_routes: HashMap::new(),
                topology_map: TopologyMap {
                    peer_connections: HashMap::new(),
                    geographic_clusters: Vec::new(),
                    coverage_areas: Vec::new(),
                },
            })),
            delivery_tracking: Arc::new(RwLock::new(HashMap::new())),
            route_cache: Arc::new(RwLock::new(HashMap::new())),
            mesh_server: None, // Can be set later with set_mesh_server()
            transport_manager: None,
        }
    }

    /// DEPRECATED (Ticket #149): No longer needed with PeerRegistry
    ///
    /// PeerRegistry automatically maintains indexes when peers are added.
    /// This method is kept for backwards compatibility but does nothing.
    #[deprecated(since = "0.1.0", note = "PeerRegistry handles indexing automatically. This is a no-op.")]
    pub async fn index_peer(&self, _peer: &UnifiedPeerId) {
        // No-op: PeerRegistry handles indexing automatically
    }

    /// DEPRECATED (Ticket #149): No longer needed with PeerRegistry
    ///
    /// PeerRegistry automatically maintains indexes when peers are removed.
    /// This method is kept for backwards compatibility but does nothing.
    #[deprecated(since = "0.1.0", note = "PeerRegistry handles indexing automatically. This is a no-op.")]
    pub async fn unindex_peer(&self, _peer: &UnifiedPeerId) {
        // No-op: PeerRegistry handles indexing automatically
    }

    /// DEPRECATED (Ticket #149): No longer needed with PeerRegistry
    ///
    /// PeerRegistry automatically maintains indexes. No rebuild needed.
    /// This method is kept for backwards compatibility but does nothing.
    #[deprecated(since = "0.1.0", note = "PeerRegistry handles indexing automatically. This is a no-op.")]
    pub async fn rebuild_indexes(&self) {
        // No-op: PeerRegistry handles indexing automatically
    }

    /// Convert PeerEntry to MeshConnection for backwards compatibility
    ///
    /// **Ticket #149:** Helper method to construct MeshConnection from PeerEntry data.
    /// This allows existing routing code to continue working while migrating to PeerRegistry.
    fn peer_entry_to_mesh_connection(entry: &crate::peer_registry::PeerEntry) -> Option<crate::mesh::connection::MeshConnection> {
        // Get primary endpoint if available
        let endpoint = entry.endpoints.first()?;
        
        Some(crate::mesh::connection::MeshConnection {
            peer: entry.peer_id.clone(),
            protocol: endpoint.protocol.clone(),
            peer_address: Some(endpoint.address.to_address_string()),
            signal_strength: entry.connection_metrics.signal_strength,
            bandwidth_capacity: entry.connection_metrics.bandwidth_capacity,
            latency_ms: entry.connection_metrics.latency_ms,
            connected_at: entry.connection_metrics.connected_at,
            data_transferred: entry.get_data_transferred(),
            tokens_earned: entry.get_tokens_earned(),
            stability_score: entry.connection_metrics.stability_score,
            zhtp_authenticated: entry.authenticated,
            quantum_secure: entry.quantum_secure,
            peer_dilithium_pubkey: None, // Not stored in PeerEntry
            kyber_shared_secret: None, // Not stored in PeerEntry
            trust_score: entry.trust_score,
            bootstrap_mode: false, // Default
        })
    }

    fn transport_manager(&self) -> Result<TransportManager> {
        self.transport_manager
            .clone()
            .ok_or_else(|| anyhow!("TransportManager not configured"))
    }

    /// **ACCEPTANCE CRITERIA (Ticket #146):** Find connection by NodeId
    ///
    /// Allows routing using NodeId interchangeably with UnifiedPeerId
    ///
    /// # Security (HIGH-1 Fix)
    ///
    /// Uses PeerRegistry's built-in index for O(1) constant-time lookup, preventing timing side-channel attacks.
    pub async fn find_connection_by_node_id(&self, node_id: &NodeId) -> Option<MeshConnection> {
        // Ticket #149: Use PeerRegistry's built-in index
        let registry = self.peer_registry.read().await;
        let peer_entry = registry.find_by_node_id(node_id)?;
        Self::peer_entry_to_mesh_connection(peer_entry)
    }

    /// **ACCEPTANCE CRITERIA (Ticket #146):** Find connection by PublicKey
    ///
    /// Allows routing using PublicKey interchangeably with UnifiedPeerId
    ///
    /// # Security (HIGH-1 Fix)
    ///
    /// Uses PeerRegistry's built-in index for O(1) constant-time lookup, preventing timing side-channel attacks.
    pub async fn find_connection_by_public_key(&self, public_key: &PublicKey) -> Option<MeshConnection> {
        // Ticket #149: Use PeerRegistry's built-in index
        let registry = self.peer_registry.read().await;
        let peer_entry = registry.find_by_public_key(public_key)?;
        Self::peer_entry_to_mesh_connection(peer_entry)
    }

    /// **ACCEPTANCE CRITERIA (Ticket #146):** Find peer by NodeId
    ///
    /// Returns the full UnifiedPeerId for a given NodeId
    ///
    /// # Security (HIGH-1 Fix)
    ///
    /// Uses PeerRegistry index for O(1) constant-time lookup.
    pub async fn find_peer_by_node_id(&self, node_id: &NodeId) -> Option<UnifiedPeerId> {
        // Ticket #149: Use PeerRegistry's built-in index
        let registry = self.peer_registry.read().await;
        registry.find_by_node_id(node_id).map(|entry| entry.peer_id.clone())
    }

    /// **ACCEPTANCE CRITERIA (Ticket #146):** Find peer by PublicKey
    ///
    /// Returns the full UnifiedPeerId for a given PublicKey
    ///
    /// # Security (HIGH-1 Fix)
    ///
    /// Uses PeerRegistry index for O(1) constant-time lookup.
    pub async fn find_peer_by_public_key(&self, public_key: &PublicKey) -> Option<UnifiedPeerId> {
        // Ticket #149: Use PeerRegistry's built-in index
        let registry = self.peer_registry.read().await;
        registry.find_by_public_key(public_key).map(|entry| entry.peer_id.clone())
    }
    
    /// Set mesh server reference for reward tracking
    pub fn set_mesh_server(&mut self, mesh_server: Arc<RwLock<crate::mesh::server::ZhtpMeshServer>>) {
        self.mesh_server = Some(mesh_server);
    }
    
    /// Set TransportManager to enforce handler availability and no-downgrade
    pub fn set_transport_manager(&mut self, manager: TransportManager) {
        self.transport_manager = Some(manager);
    }
    
    /// Estimate message size in bytes
    fn estimate_message_size(message: &ZhtpMeshMessage) -> usize {
        match message {
            ZhtpMeshMessage::ZhtpRequest(request) => {
                request.body.len() + request.headers.iter().into_iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() + 100
            },
            ZhtpMeshMessage::ZhtpResponse(response) => {
                response.body.len() + response.headers.iter().into_iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() + 100
            },
            ZhtpMeshMessage::LongRangeRoute { payload, relay_chain, .. } => {
                payload.len() + relay_chain.iter().map(|s| s.len()).sum::<usize>() + 64
            },
            ZhtpMeshMessage::BlockchainData { data, .. } => data.len() + 100,
            ZhtpMeshMessage::NewBlock { block, .. } => block.len() + 100,
            ZhtpMeshMessage::NewTransaction { transaction, .. } => transaction.len() + 100,
            ZhtpMeshMessage::UbiDistribution { proof, .. } => proof.len() + 100,
            _ => 256, // Default estimate for other message types
        }
    }
    
    /// Route message to destination with intelligent path selection
    pub async fn route_message(
        &self,
        message: ZhtpMeshMessage,
        destination: PublicKey,
        sender: PublicKey,
    ) -> Result<u64> {
        let message_id = rand::random::<u64>();

        info!(" Routing message {} to destination {:?}",
              message_id, hex::encode(&destination.key_id[0..4]));

        // Create delivery tracking
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        let delivery_status = DeliveryStatus {
            message_id,
            destination: destination.clone(),
            stage: DeliveryStage::Planning,
            route: Vec::new(),
            current_hop: 0,
            attempts: 0,
            started_at: now,
            last_update: now,
        };

        {
            let mut tracking = self.delivery_tracking.write().await;
            tracking.insert(message_id, delivery_status);
        }

        // Convert PublicKey to UnifiedPeerId for route finding
        let dest_unified = UnifiedPeerId::from_public_key_legacy(destination.clone());
        let sender_unified = UnifiedPeerId::from_public_key_legacy(sender.clone());

        // Find optimal route to destination
        let route = self.find_optimal_route(&dest_unified, &sender_unified).await?;
        
        // Update delivery status with route
        {
            let mut tracking: tokio::sync::RwLockWriteGuard<HashMap<u64, DeliveryStatus>> = self.delivery_tracking.write().await;
            if let Some(status) = tracking.get_mut(&message_id) {
                status.route = route.clone();
                status.stage = DeliveryStage::Routing;
            }
        }
        
        // Execute routing
        self.execute_routing(message_id, message, route).await?;
        
        Ok(message_id)
    }
    
    /// Find optimal route to destination
    pub async fn find_optimal_route(
        &self,
        destination: &UnifiedPeerId,
        sender: &UnifiedPeerId,
    ) -> Result<Vec<RouteHop>> {
        debug!("Finding optimal route to {:?}", hex::encode(&destination.public_key().key_id[0..4]));
        
        // Check route cache first
        if let Some(cached_route) = self.get_cached_route(destination).await {
            info!("Using cached route to destination (quality: {:.2})", 
                  cached_route.quality_score);
            return Ok(cached_route.hops);
        }
        
        // Check for direct connection (Ticket #149: use peer_registry)
        let registry = self.peer_registry.read().await;
        if let Some(peer_entry) = registry.get(destination) {
            // Enforce secure routing only: authenticated + quantum secure
            if !peer_entry.authenticated || !peer_entry.quantum_secure {
                return Err(anyhow::anyhow!(
                    "Direct route rejected: insecure transport for peer {}",
                    destination.to_compact_string()
                ));
            }

            info!("Direct connection available to destination");
            let endpoint = peer_entry.endpoints.first()
                .ok_or_else(|| anyhow::anyhow!("Peer has no endpoints"))?;
            return Ok(vec![RouteHop {
                peer_id: destination.clone(),
                protocol: endpoint.protocol.clone(),
                relay_id: None,
                latency_ms: peer_entry.connection_metrics.latency_ms,
            }]);
        }
        drop(registry); // Release lock before calling other methods
        
        // Find multi-hop route through mesh network
        if let Ok(mesh_route) = self.find_mesh_route(destination, sender).await {
            info!("Found multi-hop mesh route ({} hops)", mesh_route.len());
            return Ok(mesh_route);
        }
        
        // Try long-range relay routing
        if let Ok(relay_route) = self.find_long_range_route(destination).await {
            info!("Using long-range relay route");
            return Ok(relay_route);
        }
        
        // Use global satellite routing as last resort
        if let Ok(satellite_route) = self.find_satellite_route(destination).await {
            info!("🛰️ Using GLOBAL satellite routing - PLANETARY reach!");
            return Ok(satellite_route);
        }
        
        Err(anyhow!("No route found to destination"))
    }
    
    /// Find multi-hop route through mesh network
    ///
    /// **MIGRATION (Ticket #146):** Updated to use UnifiedPeerId for routing
    async fn find_mesh_route(
        &self,
        destination: &UnifiedPeerId,
        sender: &UnifiedPeerId,
    ) -> Result<Vec<RouteHop>> {
        debug!("Searching mesh network for route");
        
        // Ticket #149: Use peer_registry instead of mesh_connections
        let registry = self.peer_registry.read().await;
        let routing_table = self.routing_table.read().await;
        
        // Use Dijkstra's algorithm for optimal path finding
        let mut distances: HashMap<UnifiedPeerId, f64> = HashMap::new();
        let mut previous: HashMap<UnifiedPeerId, Option<UnifiedPeerId>> = HashMap::new();
        let mut unvisited: HashSet<UnifiedPeerId> = HashSet::new();
        
        // Initialize distances
        for peer_entry in registry.all_peers() {
            let peer_id = &peer_entry.peer_id;
            distances.insert(peer_id.clone(), f64::INFINITY);
            previous.insert(peer_id.clone(), None);
            unvisited.insert(peer_id.clone());
        }
        distances.insert(sender.clone(), 0.0);
        unvisited.insert(sender.clone());
        
        // Dijkstra's algorithm
        while !unvisited.is_empty() {
            // Find unvisited node with minimum distance
            let current = unvisited.iter()
                .min_by(|a, b| {
                    let dist_a = distances.get(a).unwrap_or(&f64::INFINITY);
                    let dist_b = distances.get(b).unwrap_or(&f64::INFINITY);
                    dist_a
                        .partial_cmp(dist_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .cloned();
            
            if let Some(current_peer) = current {
                if current_peer == *destination {
                    // Found route to destination (Ticket #149: pass registry instead of connections)
                    return self.construct_route_from_path(&previous, destination, &registry).await;
                }
                
                unvisited.remove(&current_peer);
                
                // Check neighbors
                if let Some(neighbors) = routing_table.topology_map.peer_connections.get(&current_peer) {
                    for neighbor in neighbors {
                        if unvisited.contains(neighbor) {
                            let edge_weight = self.calculate_edge_weight(&current_peer, neighbor, &registry).await;
                            let alt_distance = distances.get(&current_peer).unwrap_or(&f64::INFINITY) + edge_weight;
                            
                            if alt_distance < *distances.get(neighbor).unwrap_or(&f64::INFINITY) {
                                distances.insert(neighbor.clone(), alt_distance);
                                previous.insert(neighbor.clone(), Some(current_peer.clone()));
                            }
                        }
                    }
                }
            } else {
                break; // No more reachable nodes
            }
        }
        
        Err(anyhow!("No mesh route found to destination"))
    }
    
    /// Calculate edge weight for routing algorithm
    ///
    /// **MIGRATION (Ticket #149):** Updated to use PeerRegistry
    async fn calculate_edge_weight(
        &self,
        _from: &UnifiedPeerId,
        to: &UnifiedPeerId,
        registry: &crate::peer_registry::PeerRegistry,
    ) -> f64 {
        // Weight based on latency, stability, and bandwidth
        if let Some(peer_entry) = registry.get(to) {
            let latency_weight = peer_entry.connection_metrics.latency_ms as f64 / 1000.0; // Convert to seconds
            let stability_weight = 1.0 - peer_entry.connection_metrics.stability_score; // Lower stability = higher weight
            let bandwidth_weight = 1.0 / (peer_entry.connection_metrics.bandwidth_capacity as f64 / 1_000_000.0); // Favor higher bandwidth
            
            latency_weight + stability_weight + bandwidth_weight
        } else {
            f64::INFINITY // No connection
        }
    }
    
    /// Construct route from pathfinding result
    ///
    /// **MIGRATION (Ticket #149):** Updated to use PeerRegistry
    async fn construct_route_from_path(
        &self,
        previous: &HashMap<UnifiedPeerId, Option<UnifiedPeerId>>,
        destination: &UnifiedPeerId,
        registry: &crate::peer_registry::PeerRegistry,
    ) -> Result<Vec<RouteHop>> {
        let mut route = Vec::new();
        let mut current = destination.clone();
        
        // Trace back from destination to source
        while let Some(Some(prev)) = previous.get(&current) {
            if let Some(peer_entry) = registry.get(&current) {
                let endpoint = peer_entry.endpoints.first()
                    .ok_or_else(|| anyhow::anyhow!("Peer has no endpoints"))?;
                route.push(RouteHop {
                    peer_id: current.clone(),
                    protocol: endpoint.protocol.clone(),
                    relay_id: None,
                    latency_ms: peer_entry.connection_metrics.latency_ms,
                });
            }
            current = prev.clone();
        }
        
        // Reverse to get source-to-destination order
        route.reverse();
        
        if route.is_empty() {
            return Err(anyhow!("Could not construct route"));
        }
        
        Ok(route)
    }
    
    /// Find long-range relay route
    ///
    /// **MIGRATION (Ticket #146):** Updated to use UnifiedPeerId
    async fn find_long_range_route(&self, destination: &UnifiedPeerId) -> Result<Vec<RouteHop>> {
        debug!("Searching long-range relays for route");
        
        let relays = self.long_range_relays.read().await;
        let mut best_relay = None;
        let mut best_score = 0.0f64;
        
        // Find best relay for this destination
        for (relay_id, relay) in relays.iter() {
            // Score based on coverage, throughput, and cost
            let coverage_score = (relay.coverage_radius_km / 1000.0).min(1.0); // Normalize to 1000km
            let throughput_score = (relay.max_throughput_mbps as f64 / 100.0).min(1.0); // Normalize to 100 Mbps
            let cost_score = 1.0 / (relay.cost_per_mb_tokens as f64 / 10.0 + 1.0); // Lower cost = higher score
            
            let total_score = (coverage_score + throughput_score + cost_score) / 3.0;
            
            if total_score > best_score {
                best_score = total_score;
                best_relay = Some((relay_id.clone(), relay.clone()));
            }
        }
        
        if let Some((relay_id, relay)) = best_relay {
            info!("Selected relay {} for long-range routing (score: {:.2})", 
                  relay_id, best_score);
            
            Ok(vec![RouteHop {
                peer_id: destination.clone(),
                protocol: NetworkProtocol::LoRaWAN, // Long-range protocol
                relay_id: Some(relay_id),
                latency_ms: 500, // Typical long-range latency
            }])
        } else {
            Err(anyhow!("No suitable long-range relay found"))
        }
    }
    
    /// Find satellite route for GLOBAL coverage
    ///
    /// **MIGRATION (Ticket #146):** Updated to use UnifiedPeerId
    async fn find_satellite_route(&self, destination: &UnifiedPeerId) -> Result<Vec<RouteHop>> {
        debug!("🛰️ Searching for satellite uplink route");
        
        let relays = self.long_range_relays.read().await;
        
        // Find satellite relay
        for (relay_id, relay) in relays.iter() {
            if matches!(relay.relay_type, crate::types::relay_type::LongRangeRelayType::Satellite) {
                info!("🛰️ Found satellite uplink {} - GLOBAL reach enabled!", relay_id);
                
                return Ok(vec![RouteHop {
                    peer_id: destination.clone(),
                    protocol: NetworkProtocol::Satellite,
                    relay_id: Some(relay_id.clone()),
                    latency_ms: 600, // Satellite latency (LEO satellites)
                }]);
            }
        }
        
        Err(anyhow!("No satellite uplink available"))
    }
    
    /// Execute routing with selected route
    async fn execute_routing(
        &self,
        message_id: u64,
        message: ZhtpMeshMessage,
        route: Vec<RouteHop>,
    ) -> Result<()> {
        info!(" Executing routing for message {} ({} hops)", message_id, route.len());
        
        // Update delivery status
        {
            let mut tracking = self.delivery_tracking.write().await;
            if let Some(status) = tracking.get_mut(&message_id) {
                status.stage = DeliveryStage::Routing;
                status.attempts += 1;
                status.last_update = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                    .as_secs();
            }
        }
        
        // Route through each hop
        for (hop_index, hop) in route.iter().enumerate() {
            info!(" Routing to hop {}: {:?} via {:?}", 
                  hop_index + 1, hex::encode(&hop.peer_id.public_key().key_id[0..4]), hop.protocol);
            
            // Update current hop
            {
                let mut tracking = self.delivery_tracking.write().await;
                if let Some(status) = tracking.get_mut(&message_id) {
                    status.current_hop = hop_index;
                }
            }
            
            // Execute hop-specific routing
            match hop.protocol {
                NetworkProtocol::Satellite => {
                    self.route_via_satellite(message_id, &message, hop).await?;
                },
                NetworkProtocol::LoRaWAN => {
                    self.route_via_long_range(message_id, &message, hop).await?;
                },
                _ => {
                    self.route_via_mesh(message_id, &message, hop).await?;
                }
            }
            
            // Simulate routing delay
            tokio::time::sleep(tokio::time::Duration::from_millis(hop.latency_ms as u64)).await;
        }
        
        // Mark as delivered
        {
            let mut tracking = self.delivery_tracking.write().await;
            if let Some(status) = tracking.get_mut(&message_id) {
                status.stage = DeliveryStage::Delivered;
                status.last_update = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                    .as_secs();
            }
        }
        
        // Record routing activity for rewards (if mesh server available)
        if let Some(mesh_server) = &self.mesh_server {
            let message_size = Self::estimate_message_size(&message);
            let hop_count = route.len() as u8;
            
            // Use the protocol of the first hop (or most significant protocol)
            let primary_protocol = route.first()
                .map(|hop| hop.protocol.clone())
                .unwrap_or(NetworkProtocol::TCP);
            
            // Calculate average latency across all hops
            let total_latency: u64 = route.iter().map(|hop| hop.latency_ms as u64).sum();
            let avg_latency = if !route.is_empty() { 
                total_latency / route.len() as u64 
            } else { 
                0 
            };
            
            // Record the routing activity with rewards
            if let Err(e) = mesh_server.read().await.record_routing_activity(
                message_size,
                hop_count,
                primary_protocol,
                avg_latency,
            ).await {
                warn!("Failed to record routing activity: {}", e);
            } else {
                info!(" Routing rewards recorded: {} bytes, {} hops, avg {}ms latency", 
                      message_size, hop_count, avg_latency);
            }
        }
        
        info!("Message {} successfully delivered", message_id);
        Ok(())
    }
    
    /// Route via satellite for GLOBAL reach
    async fn route_via_satellite(
        &self,
        message_id: u64,
        message: &ZhtpMeshMessage,
        hop: &RouteHop,
    ) -> Result<()> {
        info!("🛰️ GLOBAL satellite routing: message {} to ANYWHERE on Earth", message_id);
        
        {
            let mut tracking = self.delivery_tracking.write().await;
            if let Some(status) = tracking.get_mut(&message_id) {
                status.stage = DeliveryStage::LongRange;
            }
        }
        
        // Satellite routing enables PLANETARY reach
        info!("Satellite uplink active - message can reach ANY location on Earth!");
        info!(" ZHTP revolutionizing global communications - no ISP needed!");
        
        Err(anyhow::anyhow!(
            "Satellite routing not configured: no uplink handler available"
        ))
    }
    
    /// Route via long-range relay
    async fn route_via_long_range(
        &self,
        message_id: u64,
        message: &ZhtpMeshMessage,
        hop: &RouteHop,
    ) -> Result<()> {
        info!("Long-range relay routing: message {}", message_id);
        
        if let Some(relay_id) = &hop.relay_id {
            let relays = self.long_range_relays.read().await;
            if let Some(relay) = relays.get(relay_id) {
                info!("Using {} relay: {:.0}km range, {} Mbps", 
                      relay_id, relay.coverage_radius_km, relay.max_throughput_mbps);
            }
        }
        
        Err(anyhow::anyhow!(
            "Long-range routing not configured: no relay send implementation"
        ))
    }
    
    /// Route via mesh connection
    async fn route_via_mesh(
        &self,
        message_id: u64,
        message: &ZhtpMeshMessage,
        hop: &RouteHop,
    ) -> Result<()> {
        debug!("Mesh routing: message {} to {:?}", 
               message_id, hex::encode(&hop.peer_id.public_key().key_id[0..4]));
        
        // Ticket #149: Use peer_registry instead of mesh_connections
        let registry = self.peer_registry.read().await;
        let peer_entry = registry
            .get(&hop.peer_id)
            .ok_or_else(|| anyhow!("Mesh route rejected: destination not in peer registry"))?;

        // Enforce secure link requirements
        if !peer_entry.authenticated || !peer_entry.quantum_secure {
                return Err(anyhow!(
                    "Mesh route rejected: insecure link to peer {}",
                    hop.peer_id.to_compact_string()
                ));
            }

        // Pick endpoint matching the chosen protocol
        let endpoint = peer_entry
            .endpoints
            .iter()
            .find(|e| e.protocol == hop.protocol)
            .ok_or_else(|| anyhow!("No endpoint for {:?} to {}", hop.protocol, hop.peer_id.to_compact_string()))?;

        debug!(
            " Forwarding via {:?} (quality: {:.2})",
            endpoint.protocol, peer_entry.connection_metrics.stability_score
        );

        // Serialize message once for transports that take raw bytes
        let message_bytes = bincode::serialize(message)
            .map_err(|e| anyhow!("Failed to serialize mesh message: {}", e))?;

        let manager = self.transport_manager()?;
        manager
            .send(&hop.protocol, endpoint, &hop.peer_id, message, &message_bytes)
            .await?;

        Ok(())
    }
    
    /// Get cached route if available and valid
    ///
    /// **MIGRATION (Ticket #146):** Updated to use UnifiedPeerId
    async fn get_cached_route(&self, destination: &UnifiedPeerId) -> Option<CachedRoute> {
        let cache = self.route_cache.read().await;
        if let Some(cached) = cache.get(destination) {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs();
            
            if current_time - cached.cached_at < cached.validity_duration {
                return Some(cached.clone());
            }
        }
        None
    }
    
    /// Cache route for future use
    ///
    /// **MIGRATION (Ticket #146):** Updated to use UnifiedPeerId
    pub async fn cache_route(&self, destination: UnifiedPeerId, route: Vec<RouteHop>, quality_score: f64) {
        // Compute max MTU across hops; fallback to min latency_ms as proxy if not available
        let max_mtu = route.iter().map(|h| h.latency_ms as u64).max().unwrap_or(0);
        let cached_route = CachedRoute {
            hops: route,
            quality_score,
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
            validity_duration: 300, // 5 minutes
            max_mtu,
        };
        
        let mut cache = self.route_cache.write().await;
        if cache.len() >= MAX_ROUTE_CACHE_ENTRIES {
            // Evict the oldest entry to respect the bound
            if let Some((oldest_key, _)) = cache
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, v)| (k.clone(), v.cached_at))
            {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(destination, cached_route);
    }
    
    /// Get delivery status for message
    pub async fn get_delivery_status(&self, message_id: u64) -> Option<DeliveryStatus> {
        let tracking = self.delivery_tracking.read().await;
        tracking.get(&message_id).cloned()
    }
    
    /// Update routing table with topology information
    pub async fn update_topology(&self, topology_updates: Vec<TopologyUpdate>) -> Result<()> {
        let mut routing_table = self.routing_table.write().await;
        
        for update in topology_updates {
            match update {
                TopologyUpdate::PeerConnection { peer_a, peer_b } => {
                    routing_table.topology_map.peer_connections
                        .entry(peer_a.clone())
                        .or_insert_with(HashSet::new)
                        .insert(peer_b.clone());
                    
                    routing_table.topology_map.peer_connections
                        .entry(peer_b)
                        .or_insert_with(HashSet::new)
                        .insert(peer_a);
                },
                TopologyUpdate::PeerDisconnection { peer_a, peer_b } => {
                    if let Some(connections) = routing_table.topology_map.peer_connections.get_mut(&peer_a) {
                        connections.remove(&peer_b);
                    }
                    if let Some(connections) = routing_table.topology_map.peer_connections.get_mut(&peer_b) {
                        connections.remove(&peer_a);
                    }
                },
            }
        }
        
        Ok(())
    }
    
    // ==================== PHASE 2: Multi-Hop Routing Integration ====================
    
    /// Find next hop for destination (simplified from full route) - Phase 2
    ///
    /// **MIGRATION (Ticket #146):** Updated to use UnifiedPeerId
    pub async fn find_next_hop_for_destination(&self, destination: &UnifiedPeerId) -> Result<UnifiedPeerId> {
        debug!("Finding next hop for destination {:?}", hex::encode(&destination.public_key().key_id[0..4]));
        
        // Check for direct connection first (Ticket #149: use peer_registry)
        let registry = self.peer_registry.read().await;
        if registry.get(destination).is_some() {
            info!(" Direct connection to destination available");
            return Ok(destination.clone());
        }
        
        // Check cached route
        if let Some(cached) = self.get_cached_route(destination).await {
            if let Some(first_hop) = cached.hops.first() {
                info!(" Using cached route, next hop: {:?}", hex::encode(&first_hop.peer_id.public_key().key_id[0..4]));
                return Ok(first_hop.peer_id.clone());
            }
        }
        
        // Calculate new route - need a sender, use any connected peer or destination
        let sender = registry.all_peers().next()
            .map(|p| p.peer_id.clone())
            .unwrap_or_else(|| destination.clone());
        drop(registry); // Release lock before calling find_optimal_route
        let full_route = self.find_optimal_route(destination, &sender).await?;
        
        if full_route.is_empty() {
            return Err(anyhow!("No route found to destination"));
        }
        
        // Cache the route
        let quality_score = self.calculate_route_quality(&full_route).await;
        self.cache_route(destination.clone(), full_route.clone(), quality_score).await;
        
        // Return first hop
        let first_hop = full_route.first().unwrap();
        info!(" Calculated new route, first hop: {:?}", hex::encode(&first_hop.peer_id.public_key().key_id[0..4]));
        Ok(first_hop.peer_id.clone())
    }
    
    /// Calculate route quality score - Phase 2
    async fn calculate_route_quality(&self, route: &[RouteHop]) -> f64 {
        if route.is_empty() {
            return 0.0;
        }
        
        let total_latency: u32 = route.iter().map(|h| h.latency_ms).sum();
        let hop_count = route.len();
        
        // Quality = (1 / latency) × (1 / hops) × 1000
        // Higher is better, normalized to 0.0-1.0
        let base_score = 1000.0 / ((total_latency as f64 + 1.0) * (hop_count as f64 + 1.0));
        base_score.min(1.0).max(0.0)
    }
    
    /// Full route execution with forwarding - Phase 2
    pub async fn route_message_with_forwarding(
        &self,
        destination: PublicKey,
        message: ZhtpMeshMessage,
        origin: PublicKey,
    ) -> Result<u64> {
        info!(" Routing message to {:?}", hex::encode(&destination.key_id[0..4]));

        // Create envelope
        let message_id = self.generate_message_id().await;
        let envelope = MeshMessageEnvelope::new(
            message_id,
            origin.clone(),
            destination.clone(),
            message,
        );

        info!(" Created envelope {} (TTL: {})", message_id, envelope.ttl);

        // Convert destination PublicKey to UnifiedPeerId for routing (Ticket #146)
        let dest_unified = UnifiedPeerId::from_public_key_legacy(destination.clone());

        // Find next hop
        let next_hop = self.find_next_hop_for_destination(&dest_unified).await?;

        info!("📤 Sending to next hop: {:?}", hex::encode(&next_hop.public_key().key_id[0..4]));
        
        // Send to next hop
        self.send_to_peer(&next_hop, &envelope).await?;
        
        // Track delivery
        self.track_delivery(envelope).await;
        
        info!(" Message routing initiated successfully");
        
        Ok(message_id)
    }
    
    /// Send envelope to peer (delegates to protocol layer) - Phase 2
    async fn send_to_peer(&self, peer_id: &UnifiedPeerId, envelope: &MeshMessageEnvelope) -> Result<()> {
        debug!("Sending envelope {} to peer {:?}", envelope.message_id, hex::encode(&peer_id.public_key().key_id[0..4]));
        
        // Ticket #149: Use peer_registry instead of mesh_connections
        let registry = self.peer_registry.read().await;
        let peer_entry = registry.get(peer_id)
            .ok_or_else(|| anyhow!("No connection to peer"))?;
        if !peer_entry.authenticated || !peer_entry.quantum_secure {
            return Err(anyhow!(
                "Mesh route rejected: insecure link to peer {}",
                peer_id.to_compact_string()
            ));
        }
        let endpoint = peer_entry
            .endpoints
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("Peer has no endpoints"))?;
        let protocol = endpoint.protocol.clone();
        drop(registry); // Release lock before protocol handler calls

        // Enforce handler availability and transport policy through TransportManager
        let manager = self.transport_manager()?;
        let message_bytes = bincode::serialize(&envelope.message)
            .map_err(|e| anyhow!("Failed to serialize envelope message: {}", e))?;
        manager
            .send(&protocol, &endpoint, peer_id, &envelope.message, &message_bytes)
            .await?;
        info!(" Sent via {:?} (TransportManager enforced)", protocol);

        Ok(())
    }
    
    /// Track message delivery - Phase 2
    async fn track_delivery(&self, envelope: MeshMessageEnvelope) {
        let status = DeliveryStatus {
            message_id: envelope.message_id,
            destination: envelope.destination.clone(),
            stage: DeliveryStage::Routing,
            route: vec![], // Will be filled as message traverses network
            current_hop: 0,
            attempts: 1,
            started_at: envelope.timestamp,
            last_update: envelope.timestamp,
        };
        
        let mut tracking = self.delivery_tracking.write().await;
        tracking.insert(envelope.message_id, status);
        
        debug!(" Tracking message {}", envelope.message_id);
    }
    
    /// Generate unique message ID - Phase 2
    async fn generate_message_id(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_nanos() as u64;
        
        // Combine timestamp with random bits for uniqueness
        timestamp ^ (rand::random::<u64>() >> 16)
    }
}

/// Topology update events
#[derive(Debug, Clone)]
/// Topology update events for routing table maintenance
///
/// **MIGRATION (Ticket #146):** Updated to use UnifiedPeerId for consistency
/// with TopologyMap's peer_connections HashMap.
pub enum TopologyUpdate {
    PeerConnection { peer_a: UnifiedPeerId, peer_b: UnifiedPeerId },
    PeerDisconnection { peer_a: UnifiedPeerId, peer_b: UnifiedPeerId },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    #[tokio::test]
    async fn test_message_router_creation() {
        // Ticket #149: Use peer_registry instead of mesh_connections
        let peer_registry = Arc::new(RwLock::new(crate::peer_registry::PeerRegistry::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        
        let router = MeshMessageRouter::new(peer_registry, long_range_relays);
        
        assert!(router.routing_table.read().await.direct_routes.is_empty());
    }
    
    #[tokio::test]
    async fn test_route_caching() {
        // Ticket #149: Use peer_registry instead of mesh_connections
        let peer_registry = Arc::new(RwLock::new(crate::peer_registry::PeerRegistry::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));

        let router = MeshMessageRouter::new(peer_registry, long_range_relays);
        let destination_key = PublicKey::new(vec![1, 2, 3]);
        // Ticket #146: Use UnifiedPeerId for routing
        let destination = crate::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(destination_key);
        let route = vec![RouteHop {
            peer_id: destination.clone(),
            protocol: NetworkProtocol::BluetoothLE,
            relay_id: None,
            latency_ms: 100,
        }];

        router.cache_route(destination.clone(), route.clone(), 0.9).await;

        let cached = router.get_cached_route(&destination).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().hops.len(), 1);
    }
}
