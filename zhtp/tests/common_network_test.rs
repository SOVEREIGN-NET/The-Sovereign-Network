// Shared network test logic for mesh, dht, and multi-node tests
// Move all common setup, orchestration, and assertion logic here

use anyhow::Result;
use std::collections::{HashSet, HashMap};
use std::time::Duration;
use uuid::Uuid;
use lib_identity::{IdentityType, NodeId, ZhtpIdentity};

// ═══════════════════════════════════════════════════════════════════════════════
// IDENTITY CREATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Create a test identity with optional seed (Human type).
/// Used by multi-node tests.
pub fn create_test_identity(device: &str, seed: Option<[u8; 64]>) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        device,
        seed,
    )
}

/// Create a test identity with required seed (Device type).
/// Used by mesh and DHT tests.
pub fn create_test_identity_with_seed(device: &str, seed: [u8; 64]) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        device,
        Some(seed),
    )
}

/// Convert NodeId to UUID for peer identification.
pub fn peer_id_from_node_id(node_id: &NodeId) -> Uuid {
    Uuid::from_slice(&node_id.as_bytes()[..16])
        .expect("NodeId::as_bytes() must return at least 16 bytes for UUID conversion")
}

// --- Mesh Formation Shared Logic ---
#[derive(Debug, Clone)]
pub struct MeshNode {
    pub node_id: NodeId,
    pub peers: HashSet<NodeId>,
    pub is_active: bool,
    pub join_cycle: u32,
}

impl MeshNode {
    pub fn new(node_id: NodeId, cycle: u32) -> Self {
        Self {
            node_id,
            peers: HashSet::new(),
            is_active: true,
            join_cycle: cycle,
        }
    }
    pub fn add_peer(&mut self, peer_id: NodeId) {
        self.peers.insert(peer_id);
    }
    pub fn remove_peer(&mut self, peer_id: &NodeId) {
        self.peers.remove(peer_id);
    }
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    pub fn has_peer(&self, peer_id: &NodeId) -> bool {
        self.peers.contains(peer_id)
    }
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
    pub fn reactivate(&mut self, cycle: u32) {
        self.is_active = true;
        self.join_cycle = cycle;
    }
}

pub struct MeshTopology {
    pub nodes: Vec<MeshNode>,
    pub cycle: u32,
}

impl MeshTopology {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            cycle: 0,
        }
    }
    pub fn add_node(&mut self, node_id: NodeId) {
        let mesh_node = MeshNode::new(node_id, self.cycle);
        self.nodes.push(mesh_node);
    }
    pub fn connect_all_peers(&mut self) {
        for i in 0..self.nodes.len() {
            for j in 0..self.nodes.len() {
                if i != j && self.nodes[j].is_active {
                    let peer_id = self.nodes[j].node_id.clone();
                    self.nodes[i].add_peer(peer_id);
                }
            }
        }
    }
    pub fn is_fully_connected(&self) -> bool {
        let active_count = self.nodes.iter().filter(|n| n.is_active).count();
        self.nodes.iter().all(|node| {
            !node.is_active || node.peer_count() == active_count - 1
        })
    }
}

pub async fn run_shared_mesh_formation_test() -> Result<()> {
    // TODO: Move mesh formation orchestration logic here
    Ok(())
}

// --- DHT Persistence Shared Logic ---
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhtEntry {
    pub node_id: NodeId,
    pub peer_uuid: Uuid,
    pub discovered_at_cycle: u32,
}

impl DhtEntry {
    pub fn new(node_id: NodeId, peer_uuid: Uuid, cycle: u32) -> Self {
        Self {
            node_id,
            peer_uuid,
            discovered_at_cycle: cycle,
        }
    }
}

pub struct DhtRoutingState {
    pub self_node_id: NodeId,
    pub routing_table: HashMap<NodeId, DhtEntry>,
    pub last_convergence_cycle: u32,
}

impl DhtRoutingState {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            self_node_id: node_id,
            routing_table: HashMap::new(),
            last_convergence_cycle: 0,
        }
    }
    pub fn add_peer(&mut self, node_id: NodeId, peer_uuid: Uuid, cycle: u32) {
        self.routing_table.insert(
            node_id.clone(),
            DhtEntry::new(node_id, peer_uuid, cycle),
        );
    }
    pub fn has_peer(&self, node_id: &NodeId) -> bool {
        self.routing_table.contains_key(node_id)
    }
    pub fn peer_count(&self) -> usize {
        self.routing_table.len()
    }
    pub fn set_convergence_cycle(&mut self, cycle: u32) {
        self.last_convergence_cycle = cycle;
    }
    pub fn get_convergence_cycle(&self) -> u32 {
        self.last_convergence_cycle
    }
    pub fn verify_peers_persisted(&self, other_node_ids: &[NodeId]) -> bool {
        other_node_ids.iter().all(|id| self.has_peer(id))
    }
}

pub async fn run_shared_dht_persistence_test() -> Result<()> {
    // TODO: Move DHT persistence orchestration logic here
    Ok(())
}

// --- Multi-Node Network Shared Logic ---
pub async fn run_shared_multi_node_network_test() -> Result<()> {
    // TODO: Move multi-node network orchestration logic here
    Ok(())
}
