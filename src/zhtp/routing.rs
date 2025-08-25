use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

/// Track reputation and metrics for a known node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node's network address
    pub addr: SocketAddr,
    /// Reputation score (0.0 to 1.0)
    pub reputation: f64,
    /// Average latency in milliseconds
    pub avg_latency: f64,
    /// Number of successful forwards
    pub successful_forwards: u64,
    /// Number of failed forwards
    pub failed_forwards: u64,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Connected nodes (their socket addresses)
    pub connections: HashSet<SocketAddr>,
}

impl NodeInfo {
    pub fn new(addr: SocketAddr) -> Self {
        NodeInfo {
            addr,
            reputation: 1.0,
            avg_latency: 0.0,
            successful_forwards: 0,
            failed_forwards: 0,
            last_seen: SystemTime::now(),
            connections: HashSet::new(),
        }
    }

    /// Update node's reputation based on success/failure
    pub fn update_reputation(&mut self, success: bool) {
        const SUCCESS_ALPHA: f64 = 0.1;   // Small increase for success
        const FAILURE_ALPHA: f64 = 0.2;   // Moderate decrease for failure
        const RECOVERY_RATE: f64 = 0.05;  // Gradual reputation recovery
        
        if success {
            self.successful_forwards += 1;
            // Increase reputation and apply recovery bonus
            let recovery = (1.0 - self.reputation) * RECOVERY_RATE;
            self.reputation = (self.reputation * (1.0 - SUCCESS_ALPHA) + SUCCESS_ALPHA + recovery).min(1.0);
        } else {
            self.failed_forwards += 1;
            // Less aggressive penalty with floor
            self.reputation = (self.reputation * (1.0 - FAILURE_ALPHA)).max(0.2);
        }
    }

    /// Update node's average latency with new measurement
    pub fn update_latency(&mut self, latency: f64) {
        const BETA: f64 = 0.2; // Weight for new latency measurements

        if self.avg_latency == 0.0 {
            self.avg_latency = latency;
        } else {
            self.avg_latency = self.avg_latency * (1.0 - BETA) + latency * BETA;
        }
    }

    /// Check if node is considered active
    pub fn is_active(&self) -> bool {
        match SystemTime::now().duration_since(self.last_seen) {
            Ok(duration) => duration < Duration::from_secs(300), // 5 minutes timeout
            Err(_) => false,
        }
    }

    /// Get node reliability score (0.0 - 1.0)
    pub fn get_reliability(&self) -> f64 {
        if self.successful_forwards + self.failed_forwards == 0 {
            1.0
        } else {
            self.successful_forwards as f64
                / (self.successful_forwards + self.failed_forwards) as f64
        }
    }

    /// Get the current path cost based on latency and reputation
    pub fn get_path_cost(&self) -> f64 {
        if self.reputation <= 0.0 {
            f64::INFINITY
        } else {
            // Use linear reputation impact instead of quadratic
            let reliability = self.get_reliability();
            let reputation_factor = 1.0 / self.reputation;  // Linear impact
            // Add base cost to prevent near-zero costs
            let base_cost = 10.0;
            base_cost + (self.avg_latency * reputation_factor * (1.5 - reliability))
        }
    }
}

/// Node metrics for monitoring and debugging
#[derive(Debug, Clone)]
pub struct NodeMetrics {
    pub addr: SocketAddr,
    pub reliability: f64,
    pub avg_latency: f64,
    pub reputation: f64,
    pub path_cost: f64,
    pub successful_forwards: u64,
    pub failed_forwards: u64,
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// Known nodes and their information
    nodes: HashMap<SocketAddr, NodeInfo>,
    /// Cache of best paths to destinations with timestamps
    path_cache: HashMap<SocketAddr, (Vec<SocketAddr>, SystemTime)>,
    /// Cache timeout in seconds
    cache_timeout: u64,
    /// Explicitly track source node
    source_node: Option<SocketAddr>,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable {
            nodes: HashMap::new(),
            path_cache: HashMap::new(),
            cache_timeout: 120, // 2 minutes default cache timeout
            source_node: None,
        }
    }

    /// Set the source node for path finding
    pub fn set_source(&mut self, addr: SocketAddr) {
        self.source_node = Some(addr);
    }

    /// Add or update a node in the routing table
    pub fn update_node(
        &mut self,
        addr: SocketAddr,
        connections: Option<HashSet<SocketAddr>>,
    ) -> Result<()> {
        let node = self
            .nodes
            .entry(addr)
            .or_insert_with(|| NodeInfo::new(addr));
        node.last_seen = SystemTime::now();

        if let Some(conns) = connections {
            // Create a list of nodes to ensure bidirectional connections
            let addrs_to_connect: Vec<_> = conns.iter().copied().collect();
            
            // Update the current node's connections
            node.connections = conns;

            // Release mutable borrow of node by ending its scope
            {
                let _ = node;
            }
            
            // Ensure all nodes exist and have bidirectional connections
            for &conn_addr in &addrs_to_connect {
                let node_to_update = self.nodes
                    .entry(conn_addr)
                    .or_insert_with(|| NodeInfo::new(conn_addr));
                node_to_update.connections.insert(addr);
            }

            // Clear path cache as topology changed
            self.path_cache.clear();
        }

        Ok(())
    }

    /// Find best path to destination based on reputation and latency
    pub fn find_path(&mut self, dest: SocketAddr, max_hops: usize) -> Option<Vec<SocketAddr>> {
        // Check cache first
        self.cleanup_cache();

        // Check cache for valid path
        if let Some((path, timestamp)) = self.path_cache.get(&dest) {
            if SystemTime::now()
                .duration_since(*timestamp)
                .unwrap_or(Duration::from_secs(u64::MAX))
                .as_secs() < self.cache_timeout
            {
                return Some(path.clone());
            }
        }

        // Use explicitly set source node if available
        let source = match self.source_node {
            Some(addr) if self.nodes.contains_key(&addr) => addr,
            _ => {
                // Fallback: try to find source from connections
                let mut potential_source = None;
                for &addr in self.nodes.keys() {
                    let has_incoming = self.nodes.values()
                        .any(|node| node.connections.contains(&addr));
                    if !has_incoming {
                        potential_source = Some(addr);
                        break;
                    }
                }
                
                // If still no source found, use first node as last resort
                match potential_source {
                    Some(addr) => addr,
                    None => match self.nodes.keys().next() {
                        Some(&addr) => addr,
                        None => return None,
                    }
                }
            }
        };

        // Initialize data structures for Dijkstra's algorithm
        let mut distances: HashMap<SocketAddr, f64> = HashMap::new();
        let mut previous: HashMap<SocketAddr, SocketAddr> = HashMap::new();
        let mut unvisited: HashSet<SocketAddr> = self.nodes.keys().copied().collect();

        // Initialize all distances to infinity except source
        for addr in unvisited.iter() {
            distances.insert(*addr, f64::INFINITY);
        }
        distances.insert(source, 0.0);

        while !unvisited.is_empty() {
            // Find node with minimum distance
            let current = match unvisited
                .iter()
                .min_by(|a, b| {
                    let dist_a = distances[a];
                    let dist_b = distances[b];
                    // Safe comparison with fallback for NaN values
                    dist_a.partial_cmp(&dist_b).unwrap_or(std::cmp::Ordering::Equal)
                }) {
                Some(addr) => *addr,
                None => break,
            };

            if current == dest {
                break;
            }

            // If current node is unreachable, no path exists
            if distances[&current] == f64::INFINITY {
                return None;
            }

            unvisited.remove(&current);

            // Check each neighbor
            if let Some(node) = self.nodes.get(&current) {
                for neighbor in &node.connections {
                    // Skip if neighbor is not in routing table
                    if !self.nodes.contains_key(neighbor) {
                        continue;
                    }

                    // Skip if neighbor already visited
                    if !unvisited.contains(neighbor) {
                        continue;
                    }

                    if let Some(neighbor_info) = self.nodes.get(neighbor) {
                        let cost = neighbor_info.get_path_cost();
                        let new_dist = distances[&current] + cost;

                        let current_dist = distances.get(neighbor).unwrap_or(&f64::INFINITY);
                        if new_dist < *current_dist {
                            distances.insert(*neighbor, new_dist);
                            previous.insert(*neighbor, current);
                        }
                    }
                }
            }
        }

        // If we can't reach the destination, return None
        if !previous.contains_key(&dest) {
            return None;
        }

        // Reconstruct path and calculate total cost
        let mut path = Vec::new();
        let mut current = dest;
        let mut total_cost = 0.0;
        let mut total_hops = 0;

        while current != source {
            path.push(current);
            if let Some(node_info) = self.nodes.get(&current) {
                total_cost += node_info.get_path_cost();
            }
            // Safe path reconstruction with error handling
            if let Some(&prev_node) = previous.get(&current) {
                current = prev_node;
            } else {
                // Path reconstruction failed - invalid routing
                return None;
            }
            total_hops += 1;
            if total_hops > max_hops {
                return None;
            }
        }
        path.push(source);
        path.reverse();

        // Verify the path exists and is valid
        if total_cost < f64::INFINITY 
            && path.len() >= 2  // Must have at least source and destination
            && path.first() == Some(&source)
            && path.last() == Some(&dest)
        {
            self.path_cache.insert(dest, (path.clone(), SystemTime::now()));
            Some(path)
        } else {
            None
        }
    }

    /// Update node metrics after a forwarding attempt
    pub fn update_metrics(
        &mut self,
        node: SocketAddr,
        success: bool,
        latency: Option<f64>,
    ) -> Result<()> {
        if let Some(info) = self.nodes.get_mut(&node) {
            info.update_reputation(success);
            if let Some(lat) = latency {
                info.update_latency(lat);
            }
            info.last_seen = SystemTime::now();
        }
        Ok(())
    }

    /// Get metrics for a specific node
    pub fn get_node_metrics(&self, addr: &SocketAddr) -> Option<NodeMetrics> {
        self.nodes.get(addr).map(|node| NodeMetrics {
            addr: node.addr,
            reliability: node.get_reliability(),
            avg_latency: node.avg_latency,
            reputation: node.reputation,
            path_cost: node.get_path_cost(),
            successful_forwards: node.successful_forwards,
            failed_forwards: node.failed_forwards,
        })
    }

    /// Get all active nodes and their metrics
    pub fn get_all_metrics(&self) -> Vec<NodeMetrics> {
        self.nodes
            .values()
            .filter(|node| node.is_active())
            .map(|node| NodeMetrics {
                addr: node.addr,
                reliability: node.get_reliability(),
                avg_latency: node.avg_latency,
                reputation: node.reputation,
                path_cost: node.get_path_cost(),
                successful_forwards: node.successful_forwards,
                failed_forwards: node.failed_forwards,
            })
            .collect()
    }

    /// Remove inactive nodes and expired cache entries
    pub fn cleanup(&mut self) {
        // Remove inactive nodes
        self.nodes.retain(|_, info| info.is_active());
        
        // Clean expired cache entries
        self.cleanup_cache();
    }

    /// Clean expired entries from path cache
    fn cleanup_cache(&mut self) {
        self.path_cache.retain(|_, (_, timestamp)| {
            SystemTime::now()
                .duration_since(*timestamp)
                .unwrap_or(Duration::from_secs(u64::MAX))
                .as_secs() < self.cache_timeout
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_metrics() {
        let addr: SocketAddr = crate::utils::parse_socket_addr("127.0.0.1:8080").expect("Valid test address");
        let mut node = NodeInfo::new(addr);

        // Initial state
        assert_eq!(node.get_reliability(), 1.0);
        assert_eq!(node.get_path_cost(), 10.0); // Base cost with no latency

        // After some successful forwards
        for _ in 0..5 {
            node.update_reputation(true);
            node.update_latency(10.0);
        }
        assert!(node.get_reliability() > 0.9);
        assert!(node.avg_latency > 0.0);

        // After some failures
        for _ in 0..2 {
            node.update_reputation(false);
        }
        assert!(node.get_reliability() < 0.9);
        assert!(node.reputation < 1.0);
        assert!(node.get_path_cost() > node.avg_latency);
    }

    #[test]
    fn test_routing_table_metrics() {
        let mut table = RoutingTable::new();
        let addr1: SocketAddr = crate::utils::parse_socket_addr("127.0.0.1:8001").expect("Valid test address");
        let addr2: SocketAddr = crate::utils::parse_socket_addr("127.0.0.1:8002").expect("Valid test address");

        // Add nodes
        assert!(table.update_node(addr1, None).is_ok());
        assert!(table.update_node(addr2, None).is_ok());

        // Update metrics
        assert!(table.update_metrics(addr1, true, Some(10.0)).is_ok());
        assert!(table.update_metrics(addr2, false, Some(20.0)).is_ok());

        // Get metrics
        let metrics = table.get_all_metrics();
        assert_eq!(metrics.len(), 2);

        if let Some(node1_metrics) = table.get_node_metrics(&addr1) {
            assert!(node1_metrics.reliability > 0.9);
            assert!(node1_metrics.path_cost < f64::INFINITY);
        }

        if let Some(node2_metrics) = table.get_node_metrics(&addr2) {
            assert!(node2_metrics.reliability < 0.5);
            if let Some(node1_metrics) = table.get_node_metrics(&addr1) {
                assert!(node2_metrics.path_cost > node1_metrics.path_cost);
            }
        }
    }

    #[test]
    fn test_cache_timeout() {
        let mut table = RoutingTable::new();
        let addr1: SocketAddr = crate::utils::parse_socket_addr("127.0.0.1:8001").expect("Valid test address");
        let addr2: SocketAddr = crate::utils::parse_socket_addr("127.0.0.1:8002").expect("Valid test address");
        let addr3: SocketAddr = crate::utils::parse_socket_addr("127.0.0.1:8003").expect("Valid test address");

        // Create path: addr1 -> addr2 -> addr3
        let mut conn1 = HashSet::new();
        conn1.insert(addr2);
        assert!(table.update_node(addr1, Some(conn1)).is_ok());

        let mut conn2 = HashSet::new();
        conn2.insert(addr3);
        assert!(table.update_node(addr2, Some(conn2)).is_ok());

        // First path finding should work
        if let Some(path) = table.find_path(addr3, 3) {
            assert_eq!(path.len(), 3);
        }

        // Path should be cached
        assert!(table.path_cache.contains_key(&addr3));

        // Wait for cache to expire
        std::thread::sleep(std::time::Duration::from_secs(121));

        // Cache should be cleared after timeout
        table.cleanup_cache();
        assert!(!table.path_cache.contains_key(&addr3));
    }

    #[test]
    fn test_path_finding() {
        let mut table = RoutingTable::new();
        let addrs: Vec<SocketAddr> = vec![
            crate::utils::parse_socket_addr("127.0.0.1:8001").expect("Valid test address"),
            crate::utils::parse_socket_addr("127.0.0.1:8002").expect("Valid test address"),
            crate::utils::parse_socket_addr("127.0.0.1:8003").expect("Valid test address"),
        ];

        // Create a simple chain: 8001 -> 8002 -> 8003
        let mut conn1 = HashSet::new();
        conn1.insert(addrs[1]);
        assert!(table.update_node(addrs[0], Some(conn1)).is_ok());

        let mut conn2 = HashSet::new();
        conn2.insert(addrs[2]);
        assert!(table.update_node(addrs[1], Some(conn2)).is_ok());

        // Find path from 8001 to 8003
        if let Some(path) = table.find_path(addrs[2], 3) {
            assert_eq!(path.len(), 3);
            assert!(path.contains(&addrs[0]));
            assert!(path.contains(&addrs[1]));
            assert!(path.contains(&addrs[2]));
        }
    }
}
