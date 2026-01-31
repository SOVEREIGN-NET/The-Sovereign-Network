/// Simulate node departure and rejoin in a mesh
pub fn simulate_node_departure_and_rejoin(nodes: &[(&str, [u8; 64])]) -> anyhow::Result<()> {
    let (identities, mut topology) = create_mesh_topology_from_nodes(nodes)?;
    assert!(topology.is_fully_connected(), "Initial mesh should be fully connected");
    // Remove node B from network
    topology.deactivate_node(1);
    assert_eq!(topology.get_active_node_count(), nodes.len() - 1, "Should have {} active nodes", nodes.len() - 1);
    // Node B rejoins with same NodeId
    let node_b_restarted = create_test_identity_with_seed(nodes[1].0, nodes[1].1)?;
    assert_eq!(identities[1].node_id, node_b_restarted.node_id, "Node B must have same NodeId after restart");
    // Reactivate in topology
    topology.reactivate_node(1);
    assert!(topology.is_fully_connected(), "Mesh should be fully connected after node rejoin");
    Ok(())
}

/// Simulate random node restarts in a mesh
pub fn simulate_random_restarts(nodes: &[(&str, [u8; 64])], deactivate: &[usize]) -> anyhow::Result<()> {
    let (_identities, mut topology) = create_mesh_topology_from_nodes(nodes)?;
    assert!(topology.is_fully_connected(), "Initial mesh should be connected");
    // Deactivate nodes
    for &idx in deactivate { topology.deactivate_node(idx); }
    assert_eq!(topology.get_active_node_count(), nodes.len() - deactivate.len(), "Should have {} active nodes after deactivation", nodes.len() - deactivate.len());
    // Reactivate nodes
    for &idx in deactivate { topology.reactivate_node(idx); }
    // Verify all nodes reconnected
    assert_eq!(topology.get_active_node_count(), nodes.len(), "All nodes should be active again");
    assert!(verify_mesh_fully_connected(&topology, nodes.len() - 1), "Network should be fully connected after restarts");
    Ok(())
}

/// Simulate mesh partition and recovery
pub fn simulate_partition_and_recovery(nodes: &[(&str, [u8; 64])], partition: &[usize]) -> anyhow::Result<()> {
    let (_identities, mut topology) = create_mesh_topology_from_nodes(nodes)?;
    assert!(topology.is_fully_connected(), "Initial mesh fully connected");
    // Simulate partition - remove nodes
    for &idx in partition { topology.deactivate_node(idx); }
    assert_eq!(topology.get_active_node_count(), nodes.len() - partition.len(), "{} nodes should remain active", nodes.len() - partition.len());
    // Heal partition - reactivate nodes
    for &idx in partition { topology.reactivate_node(idx); }
    // Verify network is whole again
    assert!(topology.is_fully_connected(), "Mesh should recover after partition healing");
    assert_eq!(topology.get_active_node_count(), nodes.len(), "All nodes should be reconnected");
    Ok(())
}

/// Simulate mesh routing verification
pub fn simulate_routing_verification(nodes: &[(&str, [u8; 64])]) -> anyhow::Result<()> {
    let (_identities, topology) = create_mesh_topology_from_nodes(nodes)?;
    verify_all_routing_paths(&topology);
    Ok(())
}
/// Build mesh incrementally and verify full connectivity after each addition
pub fn build_incremental_mesh_and_verify(identities: &[lib_identity::ZhtpIdentity]) {
    let mut topology = MeshTopology::new();
    topology.add_node(identities[0].node_id.clone());
    topology.advance_cycle();

    for i in 1..identities.len() {
        topology.add_node(identities[i].node_id.clone());
        topology.connect_all_peers();
        topology.advance_cycle();
        assert!(topology.is_fully_connected(), "Mesh should be fully connected after adding node {}", i + 1);
    }

    assert_eq!(topology.nodes.len(), identities.len(), "Should have {} nodes", identities.len());
    assert!(verify_mesh_fully_connected(&topology, identities.len() - 1), "All nodes should have {} peers in mesh", identities.len() - 1);
}

/// Simulate N cycles of stable mesh operation and verify connectivity
pub fn simulate_stable_cycles_and_verify(topology: &mut MeshTopology, cycles: usize, expected_active: usize) {
    for cycle in 0..cycles {
        topology.connect_all_peers();
        topology.advance_cycle();
        assert!(topology.is_fully_connected(), "Mesh should remain stable in cycle {}", cycle);
        assert_eq!(topology.get_active_node_count(), expected_active, "Should have {} active nodes in cycle {}", expected_active, cycle);
    }
}
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
    pub fn peer_count(&self, index: usize) -> usize {
        self.nodes[index].peer_count()
    }
    pub fn get_active_node_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_active).count()
    }
    pub fn deactivate_node(&mut self, index: usize) {
        let node_id = self.nodes[index].node_id.clone();
        self.nodes[index].deactivate();
        for i in 0..self.nodes.len() {
            if i != index {
                self.nodes[i].remove_peer(&node_id);
            }
        }
    }
    pub fn reactivate_node(&mut self, index: usize) {
        self.cycle += 1;
        self.nodes[index].reactivate(self.cycle);
        let node_id_to_add = self.nodes[index].node_id.clone();
        for j in 0..self.nodes.len() {
            if j != index && self.nodes[j].is_active {
                let peer_id = self.nodes[j].node_id.clone();
                self.nodes[index].add_peer(peer_id);
                self.nodes[j].add_peer(node_id_to_add.clone());
            }
        }
    }
    pub fn advance_cycle(&mut self) {
        self.cycle += 1;
    }
}

pub async fn run_shared_mesh_formation_test() -> Result<()> {
    // TODO: Move mesh formation orchestration logic here
    Ok(())
}

// --- Mesh Formation Helper Functions ---

/// Helper: Create identities and build a connected mesh topology
pub fn create_mesh_topology_from_nodes(nodes: &[(&str, [u8; 64])]) -> Result<(Vec<ZhtpIdentity>, MeshTopology)> {
    let identities = create_identities_from_nodes(nodes)?;
    let mut topology = MeshTopology::new();
    for identity in &identities {
        topology.add_node(identity.node_id.clone());
    }
    topology.connect_all_peers();
    Ok((identities, topology))
}

/// Helper: Verify mesh is fully connected with expected peer count
pub fn verify_mesh_fully_connected(topology: &MeshTopology, expected_peer_count: usize) -> bool {
    topology.is_fully_connected() 
        && topology.nodes.iter().all(|n| !n.is_active || n.peer_count() == expected_peer_count)
}

/// Helper: Verify all routing paths exist between all node pairs
pub fn verify_all_routing_paths(topology: &MeshTopology) {
    for i in 0..topology.nodes.len() {
        for j in 0..topology.nodes.len() {
            if i != j && topology.nodes[i].is_active && topology.nodes[j].is_active {
                assert!(
                    topology.nodes[i].has_peer(&topology.nodes[j].node_id),
                    "Node {} should have direct route to Node {}", i, j
                );
            }
        }
    }
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

// --- DHT Helper Functions ---

/// Helper: Create identities from a list of (device_name, seed) tuples
pub fn create_identities_from_nodes(nodes: &[(&str, [u8; 64])]) -> Result<Vec<lib_identity::ZhtpIdentity>> {
    nodes.iter()
        .map(|(device, seed)| create_test_identity_with_seed(device, *seed))
        .collect()
}

/// Helper: Create DHT routing states for a list of identities
pub fn create_dht_states(identities: &[lib_identity::ZhtpIdentity]) -> Vec<DhtRoutingState> {
    identities.iter()
        .map(|id| DhtRoutingState::new(id.node_id.clone()))
        .collect()
}

/// Helper: Populate DHT routing tables with all peers (full mesh)
pub fn populate_dht_full_mesh(
    dht_states: &mut [DhtRoutingState],
    identities: &[lib_identity::ZhtpIdentity],
    cycle: u32,
) -> Result<()> {
    for i in 0..identities.len() {
        for j in 0..identities.len() {
            if i != j {
                let peer_node_id = identities[j].node_id.clone();
                let peer_uuid = peer_id_from_node_id(&peer_node_id);
                dht_states[i].add_peer(peer_node_id, peer_uuid, cycle);
            }
        }
    }
    Ok(())
}

/// Helper: Verify all NodeIds match between two identity lists
pub fn verify_node_ids_match(
    identities_a: &[lib_identity::ZhtpIdentity],
    identities_b: &[lib_identity::ZhtpIdentity],
) -> bool {
    identities_a.len() == identities_b.len()
        && identities_a.iter()
            .zip(identities_b.iter())
            .all(|(a, b)| a.node_id == b.node_id)
}

/// Helper: Verify all DHT states have expected peer count
pub fn verify_dht_peer_counts(dht_states: &[DhtRoutingState], expected_count: usize) -> bool {
    dht_states.iter().all(|dht| dht.peer_count() == expected_count)
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
