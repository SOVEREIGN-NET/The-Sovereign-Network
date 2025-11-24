//! Multi-Hop Routing Algorithms
//! 
//! Advanced mesh network traversal and pathfinding algorithms

use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet, BinaryHeap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::cmp::Ordering;
use tracing::{info, warn, debug};
use lib_crypto::PublicKey;
use serde::{Serialize, Deserialize};

use crate::mesh::connection::MeshConnection;
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
use crate::routing::message_routing::RouteHop;

/// Multi-hop routing engine for mesh network traversal
pub struct MultiHopRouter {
    /// Network topology graph
    pub topology_graph: Arc<RwLock<TopologyGraph>>,
    /// Routing cache for frequently used paths
    pub path_cache: Arc<RwLock<HashMap<(PublicKey, PublicKey), CachedPath>>>,
    /// Traffic statistics for path optimization
    pub traffic_stats: Arc<RwLock<TrafficStatistics>>,
    /// Routing preferences and configuration
    pub routing_config: Arc<RwLock<RoutingConfiguration>>,
}

/// Network topology graph representation
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
    /// Node capabilities and resources
    pub capabilities: NodeCapabilities,
    /// Geographic location (if known)
    pub location: Option<crate::types::geographic::GeographicLocation>,
    /// Node reliability score (0.0 to 1.0)
    pub reliability_score: f64,
    /// Total traffic routed through this node
    pub traffic_routed: u64,
    /// Node availability percentage
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

/// Edge quality metrics for routing decisions
#[derive(Debug, Clone)]
pub struct EdgeQualityMetrics {
    /// Latency in milliseconds
    pub latency_ms: u32,
    /// Bandwidth in bytes/second
    pub bandwidth: u64,
    /// Packet loss percentage
    pub packet_loss_percent: f32,
    /// Connection stability (0.0 to 1.0)
    pub stability: f64,
    /// Signal strength (if applicable)
    pub signal_strength: Option<f64>,
}

/// Cached path for routing optimization
#[derive(Debug, Clone)]
pub struct CachedPath {
    /// Path hops
    pub hops: Vec<PublicKey>,
    /// Path quality score
    pub quality_score: f64,
    /// Total path latency
    pub total_latency_ms: u32,
    /// Path bandwidth (bottleneck)
    pub bandwidth: u64,
    /// Cache timestamp
    pub cached_at: u64,
    /// Cache validity duration
    pub validity_seconds: u64,
    /// Path usage count
    pub usage_count: u32,
}

/// Traffic statistics for routing optimization
#[derive(Debug, Clone)]
pub struct TrafficStatistics {
    /// Per-node traffic statistics
    pub node_traffic: HashMap<PublicKey, NodeTraffic>,
    /// Per-edge traffic statistics
    pub edge_traffic: HashMap<(PublicKey, PublicKey), EdgeTraffic>,
    /// Global traffic metrics
    pub global_metrics: GlobalTrafficMetrics,
}

/// Traffic statistics for a specific node
#[derive(Debug, Clone)]
pub struct NodeTraffic {
    /// Messages routed through this node
    pub messages_routed: u64,
    /// Bytes routed through this node
    pub bytes_routed: u64,
    /// Current load percentage
    pub current_load_percent: f32,
    /// Average latency for messages through this node
    pub average_latency_ms: u32,
    /// Node congestion level (0.0 to 1.0)
    pub congestion_level: f64,
}

/// Traffic statistics for a specific edge
#[derive(Debug, Clone)]
pub struct EdgeTraffic {
    /// Messages sent over this edge
    pub messages_sent: u64,
    /// Bytes sent over this edge
    pub bytes_sent: u64,
    /// Current utilization percentage
    pub utilization_percent: f32,
    /// Successful delivery rate
    pub delivery_success_rate: f64,
    /// Average delivery time
    pub average_delivery_time_ms: u32,
}

/// Global traffic metrics
#[derive(Debug, Clone)]
pub struct GlobalTrafficMetrics {
    /// Total messages routed in network
    pub total_messages_routed: u64,
    /// Total bytes routed in network
    pub total_bytes_routed: u64,
    /// Average path length (hops)
    pub average_path_length: f64,
    /// Network utilization percentage
    pub network_utilization_percent: f32,
    /// Overall delivery success rate
    pub overall_delivery_success_rate: f64,
}

/// Routing configuration and preferences
#[derive(Debug, Clone)]
pub struct RoutingConfiguration {
    /// Maximum hop count for paths
    pub max_hop_count: u8,
    /// Routing algorithm preference
    pub algorithm_preference: RoutingAlgorithm,
    /// Quality vs. speed trade-off (0.0 = speed, 1.0 = quality)
    pub quality_preference: f64,
    /// Load balancing enabled
    pub load_balancing_enabled: bool,
    /// Adaptive routing enabled
    pub adaptive_routing_enabled: bool,
    /// Cache timeout in seconds
    pub cache_timeout_seconds: u64,
}

/// Available routing algorithms
#[derive(Debug, Clone, PartialEq)]
pub enum RoutingAlgorithm {
    /// Dijkstra's shortest path (quality-focused)
    Dijkstra,
    /// A* search with heuristics
    AStar,
    /// Breadth-first search (hop-count focused)
    BreadthFirst,
    /// Load-aware routing
    LoadAware,
    /// Adaptive routing based on network conditions
    Adaptive,
}

/// Path scoring criteria
#[derive(Debug, Clone)]
pub struct PathScoringCriteria {
    /// Weight for latency in scoring
    pub latency_weight: f64,
    /// Weight for bandwidth in scoring
    pub bandwidth_weight: f64,
    /// Weight for reliability in scoring
    pub reliability_weight: f64,
    /// Weight for hop count in scoring
    pub hop_count_weight: f64,
    /// Weight for node load in scoring
    pub load_weight: f64,
}

/// Pathfinding state for algorithms
#[derive(Debug, Clone)]
struct PathfindingState {
    pub node: PublicKey,
    pub cost: f64,
    pub hops: u8,
    pub path: Vec<PublicKey>,
}

impl Eq for PathfindingState {}

impl PartialEq for PathfindingState {
    fn eq(&self, other: &Self) -> bool {
        self.cost.eq(&other.cost)
    }
}

impl Ord for PathfindingState {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap behavior
        other.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for PathfindingState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl MultiHopRouter {
    /// Create new multi-hop router
    pub fn new() -> Self {
        Self {
            topology_graph: Arc::new(RwLock::new(TopologyGraph {
                nodes: HashMap::new(),
                edges: HashMap::new(),
                adjacency_list: HashMap::new(),
                version: 0,
            })),
            path_cache: Arc::new(RwLock::new(HashMap::new())),
            traffic_stats: Arc::new(RwLock::new(TrafficStatistics {
                node_traffic: HashMap::new(),
                edge_traffic: HashMap::new(),
                global_metrics: GlobalTrafficMetrics {
                    total_messages_routed: 0,
                    total_bytes_routed: 0,
                    average_path_length: 0.0,
                    network_utilization_percent: 0.0,
                    overall_delivery_success_rate: 1.0,
                },
            })),
            routing_config: Arc::new(RwLock::new(RoutingConfiguration {
                max_hop_count: 10,
                algorithm_preference: RoutingAlgorithm::Adaptive,
                quality_preference: 0.7,
                load_balancing_enabled: true,
                adaptive_routing_enabled: true,
                cache_timeout_seconds: 300,
            })),
        }
    }
    
    /// Find optimal multi-hop path between source and destination
    pub async fn find_multi_hop_path(
        &self,
        source: &PublicKey,
        destination: &PublicKey,
        message_size: u64,
    ) -> Result<Vec<RouteHop>> {
        debug!("Finding multi-hop path: {:?} → {:?}", 
               hex::encode(&source.key_id[0..4]), hex::encode(&destination.key_id[0..4]));
        
        // Check cache first
        if let Some(cached_path) = self.get_cached_path(source, destination).await {
            info!("Using cached path ({} hops, quality: {:.2})", 
                  cached_path.hops.len(), cached_path.quality_score);
            return self.convert_path_to_route_hops(&cached_path.hops).await;
        }
        
        // Select routing algorithm based on configuration and network conditions
        let config = self.routing_config.read().await;
        let algorithm = if config.adaptive_routing_enabled {
            self.select_adaptive_algorithm(source, destination).await
        } else {
            config.algorithm_preference.clone()
        };
        
        drop(config);
        
        // Find path using selected algorithm
        let path = match algorithm {
            RoutingAlgorithm::Dijkstra => {
                self.dijkstra_pathfinding(source, destination).await?
            },
            RoutingAlgorithm::AStar => {
                self.astar_pathfinding(source, destination).await?
            },
            RoutingAlgorithm::BreadthFirst => {
                self.breadth_first_pathfinding(source, destination).await?
            },
            RoutingAlgorithm::LoadAware => {
                self.load_aware_pathfinding(source, destination, message_size).await?
            },
            RoutingAlgorithm::Adaptive => {
                self.adaptive_pathfinding(source, destination, message_size).await?
            },
        };
        
        // Cache the path for future use
        self.cache_path(source.clone(), destination.clone(), &path).await;
        
        // Convert to route hops
        let route_hops = self.convert_path_to_route_hops(&path).await?;
        
        info!("Found multi-hop path: {} hops using {:?} algorithm", 
              route_hops.len(), algorithm);
        
        Ok(route_hops)
    }
    
    /// Dijkstra's shortest path algorithm
    async fn dijkstra_pathfinding(
        &self,
        source: &PublicKey,
        destination: &PublicKey,
    ) -> Result<Vec<PublicKey>> {
        debug!("Using Dijkstra's algorithm for pathfinding");
        
        let graph = self.topology_graph.read().await;
        let mut distances: HashMap<PublicKey, f64> = HashMap::new();
        let mut previous: HashMap<PublicKey, Option<PublicKey>> = HashMap::new();
        let mut heap = BinaryHeap::new();
        
        // Initialize distances
        for node_id in graph.nodes.keys() {
            distances.insert(node_id.clone(), f64::INFINITY);
            previous.insert(node_id.clone(), None);
        }
        distances.insert(source.clone(), 0.0);
        
        heap.push(PathfindingState {
            node: source.clone(),
            cost: 0.0,
            hops: 0,
            path: vec![source.clone()],
        });
        
        while let Some(current_state) = heap.pop() {
            let current_node = &current_state.node;
            
            if current_node == destination {
                return Ok(current_state.path);
            }
            
            if current_state.cost > *distances.get(current_node).unwrap_or(&f64::INFINITY) {
                continue;
            }
            
            // Check neighbors
            if let Some(neighbors) = graph.adjacency_list.get(current_node) {
                for neighbor in neighbors {
                    if let Some(edge) = graph.edges.get(&(current_node.clone(), neighbor.clone())) {
                        let alt_cost = current_state.cost + edge.weight;
                        
                        if alt_cost < *distances.get(neighbor).unwrap_or(&f64::INFINITY) {
                            distances.insert(neighbor.clone(), alt_cost);
                            previous.insert(neighbor.clone(), Some(current_node.clone()));
                            
                            let mut new_path = current_state.path.clone();
                            new_path.push(neighbor.clone());
                            
                            heap.push(PathfindingState {
                                node: neighbor.clone(),
                                cost: alt_cost,
                                hops: current_state.hops + 1,
                                path: new_path,
                            });
                        }
                    }
                }
            }
        }
        
        Err(anyhow!("No path found using Dijkstra's algorithm"))
    }
    
    /// A* search algorithm with heuristics
    async fn astar_pathfinding(
        &self,
        source: &PublicKey,
        destination: &PublicKey,
    ) -> Result<Vec<PublicKey>> {
        debug!("⭐ Using A* algorithm for pathfinding");
        
        let graph = self.topology_graph.read().await;
        let mut g_score: HashMap<PublicKey, f64> = HashMap::new();
        let mut f_score: HashMap<PublicKey, f64> = HashMap::new();
        let mut heap = BinaryHeap::new();
        
        g_score.insert(source.clone(), 0.0);
        f_score.insert(source.clone(), self.heuristic_cost(source, destination, &graph).await);
        
        heap.push(PathfindingState {
            node: source.clone(),
            cost: f_score[source],
            hops: 0,
            path: vec![source.clone()],
        });
        
        while let Some(current_state) = heap.pop() {
            let current_node = &current_state.node;
            
            if current_node == destination {
                return Ok(current_state.path);
            }
            
            if let Some(neighbors) = graph.adjacency_list.get(current_node) {
                for neighbor in neighbors {
                    if let Some(edge) = graph.edges.get(&(current_node.clone(), neighbor.clone())) {
                        let tentative_g_score = g_score.get(current_node).unwrap_or(&f64::INFINITY) + edge.weight;
                        
                        if tentative_g_score < *g_score.get(neighbor).unwrap_or(&f64::INFINITY) {
                            g_score.insert(neighbor.clone(), tentative_g_score);
                            let h_score = self.heuristic_cost(neighbor, destination, &graph).await;
                            f_score.insert(neighbor.clone(), tentative_g_score + h_score);
                            
                            let mut new_path = current_state.path.clone();
                            new_path.push(neighbor.clone());
                            
                            heap.push(PathfindingState {
                                node: neighbor.clone(),
                                cost: f_score[neighbor],
                                hops: current_state.hops + 1,
                                path: new_path,
                            });
                        }
                    }
                }
            }
        }
        
        Err(anyhow!("No path found using A* algorithm"))
    }
    
    /// Breadth-first search for minimum hop count
    async fn breadth_first_pathfinding(
        &self,
        source: &PublicKey,
        destination: &PublicKey,
    ) -> Result<Vec<PublicKey>> {
        debug!("🌊 Using BFS for minimum hop pathfinding");
        
        let graph = self.topology_graph.read().await;
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        
        queue.push_back(vec![source.clone()]);
        visited.insert(source.clone());
        
        while let Some(path) = queue.pop_front() {
            let current_node = path.last().unwrap();
            
            if current_node == destination {
                return Ok(path);
            }
            
            if let Some(neighbors) = graph.adjacency_list.get(current_node) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        let mut new_path = path.clone();
                        new_path.push(neighbor.clone());
                        queue.push_back(new_path);
                    }
                }
            }
        }
        
        Err(anyhow!("No path found using BFS"))
    }
    
    /// Load-aware pathfinding that considers node and edge congestion
    async fn load_aware_pathfinding(
        &self,
        source: &PublicKey,
        destination: &PublicKey,
        message_size: u64,
    ) -> Result<Vec<PublicKey>> {
        debug!("⚖️ Using load-aware pathfinding (message size: {} bytes)", message_size);
        
        let graph = self.topology_graph.read().await;
        let traffic_stats = self.traffic_stats.read().await;
        
        let mut distances: HashMap<PublicKey, f64> = HashMap::new();
        let mut heap = BinaryHeap::new();
        
        // Initialize with load-adjusted costs
        for node_id in graph.nodes.keys() {
            distances.insert(node_id.clone(), f64::INFINITY);
        }
        distances.insert(source.clone(), 0.0);
        
        heap.push(PathfindingState {
            node: source.clone(),
            cost: 0.0,
            hops: 0,
            path: vec![source.clone()],
        });
        
        while let Some(current_state) = heap.pop() {
            let current_node = &current_state.node;
            
            if current_node == destination {
                return Ok(current_state.path);
            }
            
            if let Some(neighbors) = graph.adjacency_list.get(current_node) {
                for neighbor in neighbors {
                    if let Some(edge) = graph.edges.get(&(current_node.clone(), neighbor.clone())) {
                        // Calculate load-adjusted edge weight
                        let base_weight = edge.weight;
                        let load_multiplier = self.calculate_load_multiplier(
                            neighbor, 
                            &(current_node.clone(), neighbor.clone()),
                            &traffic_stats,
                            message_size,
                        ).await;
                        
                        let adjusted_weight = base_weight * load_multiplier;
                        let alt_cost = current_state.cost + adjusted_weight;
                        
                        if alt_cost < *distances.get(neighbor).unwrap_or(&f64::INFINITY) {
                            distances.insert(neighbor.clone(), alt_cost);
                            
                            let mut new_path = current_state.path.clone();
                            new_path.push(neighbor.clone());
                            
                            heap.push(PathfindingState {
                                node: neighbor.clone(),
                                cost: alt_cost,
                                hops: current_state.hops + 1,
                                path: new_path,
                            });
                        }
                    }
                }
            }
        }
        
        Err(anyhow!("No path found using load-aware algorithm"))
    }
    
    /// Adaptive pathfinding that selects best algorithm based on conditions
    async fn adaptive_pathfinding(
        &self,
        source: &PublicKey,
        destination: &PublicKey,
        message_size: u64,
    ) -> Result<Vec<PublicKey>> {
        debug!("🧠 Using adaptive pathfinding");
        
        // Analyze network conditions to select best algorithm
        let network_conditions = self.analyze_network_conditions().await;
        
        let selected_algorithm = if network_conditions.high_congestion {
            RoutingAlgorithm::LoadAware
        } else if network_conditions.low_connectivity {
            RoutingAlgorithm::Dijkstra
        } else if network_conditions.requires_fast_routing {
            RoutingAlgorithm::BreadthFirst
        } else {
            RoutingAlgorithm::AStar
        };
        
        debug!("Adaptive algorithm selected: {:?}", selected_algorithm);
        
        match selected_algorithm {
            RoutingAlgorithm::LoadAware => self.load_aware_pathfinding(source, destination, message_size).await,
            RoutingAlgorithm::Dijkstra => self.dijkstra_pathfinding(source, destination).await,
            RoutingAlgorithm::BreadthFirst => self.breadth_first_pathfinding(source, destination).await,
            RoutingAlgorithm::AStar => self.astar_pathfinding(source, destination).await,
            _ => self.dijkstra_pathfinding(source, destination).await, // Fallback
        }
    }
    
    /// Calculate heuristic cost for A* algorithm
    async fn heuristic_cost(
        &self,
        from: &PublicKey,
        to: &PublicKey,
        graph: &TopologyGraph,
    ) -> f64 {
        // Simple heuristic based on direct connection if available
        if let Some(edge) = graph.edges.get(&(from.clone(), to.clone())) {
            return edge.weight * 0.8; // Optimistic estimate
        }
        
        // Fallback heuristic based on node capabilities
        let from_node = graph.nodes.get(from);
        let to_node = graph.nodes.get(to);
        
        match (from_node, to_node) {
            (Some(from_n), Some(to_n)) => {
                // Estimate based on node capabilities and locations
                let capability_factor = (from_n.reliability_score + to_n.reliability_score) / 2.0;
                1.0 / capability_factor // Lower cost for more reliable nodes
            },
            _ => 10.0, // Default heuristic for unknown nodes
        }
    }
    
    /// Calculate load multiplier for edge weight adjustment
    async fn calculate_load_multiplier(
        &self,
        node: &PublicKey,
        edge: &(PublicKey, PublicKey),
        traffic_stats: &TrafficStatistics,
        _message_size: u64,
    ) -> f64 {
        let mut multiplier = 1.0;
        
        // Adjust for node congestion
        if let Some(node_traffic) = traffic_stats.node_traffic.get(node) {
            multiplier *= 1.0 + node_traffic.congestion_level;
        }
        
        // Adjust for edge utilization
        if let Some(edge_traffic) = traffic_stats.edge_traffic.get(edge) {
            multiplier *= 1.0 + (edge_traffic.utilization_percent / 100.0) as f64;
        }
        
        multiplier
    }
    
    /// Analyze current network conditions for adaptive routing
    async fn analyze_network_conditions(&self) -> NetworkConditions {
        let traffic_stats = self.traffic_stats.read().await;
        let graph = self.topology_graph.read().await;
        
        // Calculate network metrics
        let avg_congestion = if !traffic_stats.node_traffic.is_empty() {
            traffic_stats.node_traffic.values()
                .map(|n| n.congestion_level)
                .sum::<f64>() / traffic_stats.node_traffic.len() as f64
        } else {
            0.0
        };
        
        let avg_connectivity = if !graph.adjacency_list.is_empty() {
            graph.adjacency_list.values()
                .map(|neighbors| neighbors.len())
                .sum::<usize>() as f64 / graph.adjacency_list.len() as f64
        } else {
            0.0
        };
        
        NetworkConditions {
            high_congestion: avg_congestion > 0.7,
            low_connectivity: avg_connectivity < 3.0,
            requires_fast_routing: traffic_stats.global_metrics.network_utilization_percent > 80.0,
            network_stability: traffic_stats.global_metrics.overall_delivery_success_rate,
        }
    }
    
    /// Select adaptive algorithm based on source and destination
    async fn select_adaptive_algorithm(
        &self,
        _source: &PublicKey,
        _destination: &PublicKey,
    ) -> RoutingAlgorithm {
        // For now, use load-aware as default adaptive choice
        RoutingAlgorithm::LoadAware
    }
    
    /// Convert path to route hops
    async fn convert_path_to_route_hops(&self, path: &[PublicKey]) -> Result<Vec<RouteHop>> {
        let graph = self.topology_graph.read().await;
        let mut route_hops = Vec::new();
        
        for i in 1..path.len() {
            let from = &path[i - 1];
            let to = &path[i];
            
            if let Some(edge) = graph.edges.get(&(from.clone(), to.clone())) {
                route_hops.push(RouteHop {
                    peer_id: to.clone(),
                    protocol: edge.protocol.clone(),
                    relay_id: None,
                    latency_ms: edge.quality_metrics.latency_ms,
                });
            } else {
                return Err(anyhow!("Missing edge in path: {:?} → {:?}", 
                                   hex::encode(&from.key_id[0..4]), 
                                   hex::encode(&to.key_id[0..4])));
            }
        }
        
        Ok(route_hops)
    }
    
    /// Get cached path if available and valid
    async fn get_cached_path(&self, source: &PublicKey, destination: &PublicKey) -> Option<CachedPath> {
        let cache = self.path_cache.read().await;
        let key = (source.clone(), destination.clone());
        
        if let Some(cached_path) = cache.get(&key) {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            if current_time - cached_path.cached_at < cached_path.validity_seconds {
                return Some(cached_path.clone());
            }
        }
        
        None
    }
    
    /// Cache path for future use
    async fn cache_path(&self, source: PublicKey, destination: PublicKey, path: &[PublicKey]) {
        let quality_score = self.calculate_path_quality(path).await;
        
        let cached_path = CachedPath {
            hops: path.to_vec(),
            quality_score,
            total_latency_ms: self.calculate_path_latency(path).await,
            bandwidth: self.calculate_path_bandwidth(path).await,
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            validity_seconds: 300, // 5 minutes
            usage_count: 0,
        };
        
        let mut cache = self.path_cache.write().await;
        cache.insert((source, destination), cached_path);
    }
    
    /// Calculate path quality score
    async fn calculate_path_quality(&self, path: &[PublicKey]) -> f64 {
        let graph = self.topology_graph.read().await;
        let mut total_quality = 0.0;
        let mut edge_count = 0;
        
        for i in 1..path.len() {
            if let Some(edge) = graph.edges.get(&(path[i-1].clone(), path[i].clone())) {
                total_quality += edge.quality_metrics.stability;
                edge_count += 1;
            }
        }
        
        if edge_count > 0 {
            total_quality / edge_count as f64
        } else {
            0.0
        }
    }
    
    /// Calculate total path latency
    async fn calculate_path_latency(&self, path: &[PublicKey]) -> u32 {
        let graph = self.topology_graph.read().await;
        let mut total_latency = 0u32;
        
        for i in 1..path.len() {
            if let Some(edge) = graph.edges.get(&(path[i-1].clone(), path[i].clone())) {
                total_latency += edge.quality_metrics.latency_ms;
            }
        }
        
        total_latency
    }
    
    /// Calculate path bandwidth (bottleneck)
    async fn calculate_path_bandwidth(&self, path: &[PublicKey]) -> u64 {
        let graph = self.topology_graph.read().await;
        let mut min_bandwidth = u64::MAX;
        
        for i in 1..path.len() {
            if let Some(edge) = graph.edges.get(&(path[i-1].clone(), path[i].clone())) {
                min_bandwidth = min_bandwidth.min(edge.quality_metrics.bandwidth);
            }
        }
        
        if min_bandwidth == u64::MAX { 0 } else { min_bandwidth }
    }
    
    /// Update topology graph with new connections
    pub async fn update_topology(&self, connections: &HashMap<PublicKey, MeshConnection>) -> Result<()> {
        let mut graph = self.topology_graph.write().await;
        graph.version += 1;
        
        // Clear existing graph
        graph.nodes.clear();
        graph.edges.clear();
        graph.adjacency_list.clear();
        
        // Add nodes from connections
        for (peer_id, connection) in connections {
            let node = NetworkNode {
                node_id: peer_id.clone(),
                capabilities: NodeCapabilities {
                    protocols: vec![connection.protocol.clone()],
                    max_bandwidth: connection.bandwidth_capacity,
                    available_bandwidth: connection.bandwidth_capacity / 2, // Estimate 50% available
                    routing_capacity: 100,
                    energy_level: None,
                },
                location: None,
                reliability_score: connection.stability_score,
                traffic_routed: connection.data_transferred,
                availability_percent: 95.0, // Default availability
            };
            
            graph.nodes.insert(peer_id.clone(), node);
        }
        
        // Add edges and adjacency relationships
        for (peer_id, connection) in connections {
            // Create bidirectional edges
            let edge = NetworkEdge {
                source: peer_id.clone(),
                destination: connection.peer_id.clone(),
                protocol: connection.protocol.clone(),
                weight: self.calculate_edge_weight(connection),
                quality_metrics: EdgeQualityMetrics {
                    latency_ms: connection.latency_ms,
                    bandwidth: connection.bandwidth_capacity,
                    packet_loss_percent: 1.0 - (connection.stability_score as f32),
                    stability: connection.stability_score,
                    signal_strength: Some(connection.signal_strength),
                },
                last_updated: connection.connected_at,
            };
            
            graph.edges.insert((peer_id.clone(), connection.peer_id.clone()), edge.clone());
            
            // Add to adjacency list
            graph.adjacency_list
                .entry(peer_id.clone())
                .or_insert_with(HashSet::new)
                .insert(connection.peer_id.clone());
        }
        
        info!(" Updated topology graph: {} nodes, {} edges", 
              graph.nodes.len(), graph.edges.len());
        
        Ok(())
    }
    
    /// Calculate edge weight for routing
    fn calculate_edge_weight(&self, connection: &MeshConnection) -> f64 {
        // Combine multiple factors into edge weight
        let latency_factor = connection.latency_ms as f64 / 1000.0; // Convert to seconds
        let stability_factor = 1.0 - connection.stability_score; // Lower stability = higher weight
        let bandwidth_factor = 1.0 / (connection.bandwidth_capacity as f64 / 1_000_000.0); // Favor higher bandwidth
        
        latency_factor + stability_factor + bandwidth_factor
    }
    
    /// Get routing statistics
    pub async fn get_routing_statistics(&self) -> RoutingStatistics {
        let traffic_stats = self.traffic_stats.read().await;
        let graph = self.topology_graph.read().await;
        let cache = self.path_cache.read().await;
        
        RoutingStatistics {
            total_nodes: graph.nodes.len(),
            total_edges: graph.edges.len(),
            cached_paths: cache.len(),
            total_messages_routed: traffic_stats.global_metrics.total_messages_routed,
            average_path_length: traffic_stats.global_metrics.average_path_length,
            network_utilization: traffic_stats.global_metrics.network_utilization_percent,
            delivery_success_rate: traffic_stats.global_metrics.overall_delivery_success_rate,
        }
    }
}

/// Network conditions for adaptive routing
#[derive(Debug, Clone)]
struct NetworkConditions {
    pub high_congestion: bool,
    pub low_connectivity: bool,
    pub requires_fast_routing: bool,
    pub network_stability: f64,
}

/// Routing statistics
#[derive(Debug, Clone)]
pub struct RoutingStatistics {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub cached_paths: usize,
    pub total_messages_routed: u64,
    pub average_path_length: f64,
    pub network_utilization: f32,
    pub delivery_success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_multi_hop_router_creation() {
        let router = MultiHopRouter::new();
        let stats = router.get_routing_statistics().await;
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.total_edges, 0);
    }
    
    #[tokio::test]
    async fn test_path_caching() {
        let router = MultiHopRouter::new();
        let source = PublicKey::new(vec![1, 2, 3]);
        let destination = PublicKey::new(vec![4, 5, 6]);
        let path = vec![source.clone(), destination.clone()];
        
        router.cache_path(source.clone(), destination.clone(), &path).await;
        
        let cached = router.get_cached_path(&source, &destination).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().hops.len(), 2);
    }
}
