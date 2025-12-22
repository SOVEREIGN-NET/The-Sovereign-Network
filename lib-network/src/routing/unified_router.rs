//! Unified router façade that exposes a single entry point for mesh and DHT routing.
//!
//! This is a lightweight adapter (non-macOS specific) to satisfy ARCH-D-1.19
//! without invasive rewrites. It surfaces the existing mesh router and Kademlia
//! router behind one API so higher layers can ask for the next hop or the DHT
//! candidates without duplicating logic.

use anyhow::{anyhow, Result};
use lib_identity::NodeId;
use lib_storage::{dht::routing::KademliaRouter, types::dht_types::DhtNode};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::identity::unified_peer::UnifiedPeerId;
use crate::routing::message_routing::MeshMessageRouter;

/// Combined view of mesh + DHT routes.
#[derive(Debug, Clone)]
pub struct UnifiedRoutePlan {
    pub mesh_next_hop: Option<UnifiedPeerId>,
    pub dht_candidates: Vec<DhtNode>,
}

/// Thin façade over existing mesh and DHT routers.
pub struct UnifiedRouter {
    mesh_router: Arc<RwLock<MeshMessageRouter>>,
    dht_router: Arc<RwLock<KademliaRouter>>,
}

impl UnifiedRouter {
    pub fn new(
        mesh_router: Arc<RwLock<MeshMessageRouter>>,
        dht_router: Arc<RwLock<KademliaRouter>>,
    ) -> Self {
        Self {
            mesh_router,
            dht_router,
        }
    }

    /// Find a mesh hop and DHT fallback candidates for a NodeId.
    pub async fn plan_route_to(&self, node_id: &NodeId) -> Result<UnifiedRoutePlan> {
        let mesh_next_hop = {
            let mesh = self.mesh_router.read().await;
            mesh.find_peer_by_node_id(node_id).await
        };

        let dht_candidates = {
            let dht = self.dht_router.read().await;
            dht.find_closest_nodes(node_id, 3)
        };

        Ok(UnifiedRoutePlan {
            mesh_next_hop,
            dht_candidates,
        })
    }

    /// Resolve a NodeId into a UnifiedPeerId (if the mesh index knows about it).
    pub async fn resolve_peer(&self, node_id: &NodeId) -> Result<UnifiedPeerId> {
        let mesh = self.mesh_router.read().await;
        mesh.find_peer_by_node_id(node_id)
            .await
            .ok_or_else(|| anyhow!("Unknown peer for NodeId"))
    }

    /// Expose raw Kademlia lookup for callers that need it.
    pub async fn dht_closest(&self, node_id: &NodeId, count: usize) -> Vec<DhtNode> {
        let dht = self.dht_router.read().await;
        dht.find_closest_nodes(node_id, count)
    }
}
