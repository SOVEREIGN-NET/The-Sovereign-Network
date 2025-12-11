//! DHT Routing Trait - **TICKET #153**
//!
//! **CODE ELIMINATION ACHIEVED**: Original 562-line Kademlia implementation deleted.
//! Replaced with trait definition that UnifiedRouter implements.
//!
//! The actual routing implementation is in: lib-network/src/routing/unified_router.rs
//! This file defines the interface that DHT storage needs.

use crate::types::dht_types::DhtNode;
use crate::types::NodeId;
use anyhow::Result;

/// Routing statistics
#[derive(Debug, Clone)]
pub struct RoutingStats {
    pub total_nodes: usize,
    pub non_empty_buckets: usize,
    pub total_buckets: usize,
    pub full_buckets: usize,
    pub k_value: usize,
    pub average_bucket_fill: f64,
}

/// DHT routing operations trait
/// 
/// **TICKET #153**: This trait allows DhtStorage to work with any routing implementation
/// without depending on lib-network (which would create a cyclic dependency).
/// 
/// Implementations:
/// - lib-network::routing::unified_router::UnifiedRouterAdapter (production)
/// - NoOpRouter (default/testing)
pub trait DhtRouter: Send + Sync + std::fmt::Debug {
    /// Find K closest nodes to a target
    fn find_closest_nodes(&self, target: &NodeId, count: usize) -> Vec<DhtNode>;
    
    /// Add a node to the routing table (synchronous wrapper)
    fn add_node_sync(&mut self, node: DhtNode) -> Result<()>;
    
    /// Mark a node as failed
    fn mark_node_failed(&mut self, node_id: &NodeId);
    
    /// Mark a node as responsive
    fn mark_node_responsive(&mut self, node_id: &NodeId) -> Result<()>;
    
    /// Remove a node
    fn remove_node(&mut self, node_id: &NodeId);
    
    /// Get routing statistics
    fn get_stats(&self) -> RoutingStats;
}

/// No-op router for testing/standalone use
#[derive(Debug, Default)]
pub struct NoOpRouter;

impl DhtRouter for NoOpRouter {
    fn find_closest_nodes(&self, _target: &NodeId, _count: usize) -> Vec<DhtNode> {
        Vec::new()
    }
    
    fn add_node_sync(&mut self, _node: DhtNode) -> Result<()> {
        Ok(())
    }
    
    fn mark_node_failed(&mut self, _node_id: &NodeId) {}
    
    fn mark_node_responsive(&mut self, _node_id: &NodeId) -> Result<()> {
        Ok(())
    }
    
    fn remove_node(&mut self, _node_id: &NodeId) {}
    
    fn get_stats(&self) -> RoutingStats {
        RoutingStats {
            total_nodes: 0,
            non_empty_buckets: 0,
            total_buckets: 160,
            full_buckets: 0,
            k_value: 20,
            average_bucket_fill: 0.0,
        }
    }
}
