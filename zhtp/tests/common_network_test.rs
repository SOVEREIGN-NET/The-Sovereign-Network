// Shared network test logic for mesh, dht, and multi-node tests
// Move all common setup, orchestration, and assertion logic here

use anyhow::Result;
use std::collections::{HashSet, HashMap};
use std::time::Duration;
use uuid::Uuid;
use lib_identity::{NodeId, ZhtpIdentity};

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

// --- Shared Helper Functions ---

/// Create test identities from a list of (device, seed) tuples
pub fn create_test_identities<F>(
    nodes: &[(&str, [u8; 64])],
    identity_fn: F,
) -> Vec<ZhtpIdentity>
where
    F: Fn(&str, [u8; 64]) -> Result<ZhtpIdentity>,
{
    nodes
        .iter()
        .filter_map(|(device, seed)| identity_fn(device, *seed).ok())
        .collect()
}

/// Build mesh topology from identities
pub fn build_mesh_topology(identities: &[ZhtpIdentity]) -> MeshTopology {
    let mut topology = MeshTopology::new();
    for identity in identities {
        topology.add_node(identity.node_id.clone());
    }
    topology.connect_all_peers();
    topology
}

/// Assert mesh is fully connected with expected peer count
pub fn assert_fully_connected(topology: &MeshTopology, expected_peer_count: usize) {
    assert!(topology.is_fully_connected(), "Mesh should be fully connected");
    for (i, node) in topology.nodes.iter().enumerate() {
        assert_eq!(
            node.peer_count(),
            expected_peer_count,
            "Node {} should have {} peers",
            i,
            expected_peer_count
        );
    }
}

/// Build DHT states from identities
pub fn build_dht_states(identities: &[ZhtpIdentity], convergence_cycle: u32) -> Vec<DhtRoutingState> {
    identities
        .iter()
        .map(|id| {
            let mut dht = DhtRoutingState::new(id.node_id.clone());
            dht.set_convergence_cycle(convergence_cycle);
            dht
        })
        .collect()
}

/// Populate DHT peers for all nodes
pub fn populate_dht_peers(dht_states: &mut [DhtRoutingState], identities: &[ZhtpIdentity], cycle: u32) {
    for i in 0..identities.len() {
        for j in 0..identities.len() {
            if i != j {
                let peer_node_id = identities[j].node_id.clone();
                if let Ok(peer_uuid) = Uuid::from_slice(&peer_node_id.as_bytes()[..16]) {
                    dht_states[i].add_peer(peer_node_id, peer_uuid, cycle);
                }
            }
        }
    }
}

/// Assert all DHT states have expected peer count
pub fn assert_dht_peer_counts(dht_states: &[DhtRoutingState], expected_count: usize) {
    for (i, dht) in dht_states.iter().enumerate() {
        assert_eq!(
            dht.peer_count(),
            expected_count,
            "Node {} should have {} peers",
            i,
            expected_count
        );
    }
}

/// Assert node IDs are stable across restart
pub fn assert_node_id_stability(before: &[ZhtpIdentity], after: &[ZhtpIdentity]) {
    for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
        assert_eq!(
            b.node_id, a.node_id,
            "Node {} NodeId must survive restart",
            i
        );
    }
}

/// Assert node IDs match baseline
pub fn assert_node_ids_match(identities: &[ZhtpIdentity], baseline: &[NodeId], cycle: usize) {
    for (i, identity) in identities.iter().enumerate() {
        assert_eq!(
            identity.node_id, baseline[i],
            "Node {} NodeId must be consistent in cycle {}",
            i,
            cycle
        );
    }
}

/// Assert convergence cycle for all DHT states
pub fn assert_convergence_cycle(dht_states: &[DhtRoutingState], expected_cycle: u32) {
    for dht in dht_states {
        assert_eq!(
            dht.get_convergence_cycle(),
            expected_cycle,
            "All nodes should have convergence cycle {}",
            expected_cycle
        );
    }
}

/// Assert convergence progressed between two DHT state snapshots
pub fn assert_convergence_progressed(before: &[DhtRoutingState], after: &[DhtRoutingState]) {
    for (b, a) in before.iter().zip(after.iter()) {
        assert!(
            a.get_convergence_cycle() > b.get_convergence_cycle(),
            "Convergence cycle must progress"
        );
    }
}

/// Assert DHT routing table consistency
pub fn assert_dht_consistency(
    dht_states: &[DhtRoutingState],
    stored_routing_tables: &[Vec<NodeId>],
    cycle: usize,
) {
    for (i, dht) in dht_states.iter().enumerate() {
        for peer_node_id in &stored_routing_tables[i] {
            assert!(
                dht.has_peer(peer_node_id),
                "Node {} should have consistent peer entry in cycle {}",
                i,
                cycle
            );
        }
    }
}

/// Assert mesh routing paths exist between all node pairs
pub fn assert_mesh_routing_paths(topology: &MeshTopology) {
    for i in 0..topology.nodes.len() {
        for j in 0..topology.nodes.len() {
            if i != j {
                assert!(
                    topology.nodes[i].has_peer(&topology.nodes[j].node_id),
                    "Node {} should have direct route to Node {}",
                    i,
                    j
                );
            }
        }
    }
}
