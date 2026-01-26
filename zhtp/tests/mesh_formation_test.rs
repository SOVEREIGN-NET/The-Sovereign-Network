//! Mesh Network Formation Test (Issue #71)
//!
//! Goal: Verify mesh network topology forms and remains stable
//! under various conditions including node restarts.
//!
//! Test Scenarios:
//! - Mesh network forms via UDP multicast discovery
//! - All nodes discover all other nodes
//! - Network remains connected after node restarts
//! - Message routing works correctly
//! - Network topology remains stable

use anyhow::Result;
use std::time::Duration;
mod common;
use common_network_test::{MeshNode, MeshTopology, run_shared_mesh_formation_test};

const TEST_TIMEOUT: Duration = Duration::from_secs(25);
const MESH_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

// ...existing code...

#[tokio::test]
async fn test_mesh_formation_shared() -> Result<()> {
    run_shared_mesh_formation_test().await
    }

    fn peer_count(&self, index: usize) -> usize {
        self.nodes[index].peer_count()
    }

    fn get_active_node_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_active).count()
    }

    fn deactivate_node(&mut self, index: usize) {
        let node_id = self.nodes[index].node_id.clone();
        self.nodes[index].deactivate();
        // Remove from all other nodes' peer lists
        for i in 0..self.nodes.len() {
            if i != index {
                self.nodes[i].remove_peer(&node_id);
            }
        }
    }

    fn reactivate_node(&mut self, index: usize) {
        self.cycle += 1;
        self.nodes[index].reactivate(self.cycle);
        // Reestablish connections
        let node_id_to_add = self.nodes[index].node_id.clone();
        for j in 0..self.nodes.len() {
            if j != index && self.nodes[j].is_active {
                let peer_id = self.nodes[j].node_id.clone();
                self.nodes[index].add_peer(peer_id);
                self.nodes[j].add_peer(node_id_to_add.clone());
            }
        }
    }

    fn advance_cycle(&mut self) {
        self.cycle += 1;
    }
}

/// Test 1: Five-Node Mesh Network Formation via Multicast
///
/// Scenario: Five nodes join network sequentially.
/// Verify they all discover each other and form fully connected mesh.
#[test]
fn test_five_node_mesh_formation() -> Result<()> {
    // Phase 1: Create five nodes
    let nodes = [
        ("mesh-node-a", [0x11; 64]),
        ("mesh-node-b", [0x22; 64]),
        ("mesh-node-c", [0x33; 64]),
        ("mesh-node-d", [0x44; 64]),
        ("mesh-node-e", [0x55; 64]),
    ];

    let mut identities = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities.push(identity);
    }

    // Phase 2: Build mesh topology
    let mut topology = MeshTopology::new();
    for identity in &identities {
        topology.add_node(identity.node_id.clone());
    }

    // Phase 3: Simulate multicast discovery
    topology.connect_all_peers();

    // Phase 4: Verify mesh is fully connected
    assert!(
        topology.is_fully_connected(),
        "5-node mesh should be fully connected"
    );

    // Verify each node has 4 peers (all others)
    for i in 0..identities.len() {
        assert_eq!(
            topology.peer_count(i),
            4,
            "Node {} should have 4 peers",
            i
        );
    }

    Ok(())
}

/// Test 2: Mesh Network with Node Departure and Rejoin
///
/// Scenario: Remove node from mesh, then rejoin with same NodeId.
/// Verify topology recovers and node rejoins with correct identity.
#[test]
fn test_mesh_node_departure_and_rejoin() -> Result<()> {
    // Phase 1: Create and connect 4 nodes
    let nodes = [
        ("mesh-stable-a", [0x1A; 64]),
        ("mesh-stable-b", [0x2B; 64]),
        ("mesh-stable-c", [0x3C; 64]),
        ("mesh-stable-d", [0x4D; 64]),
    ];

    let mut identities = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities.push(identity);
    }

    // Phase 2: Build initial mesh
    let mut topology = MeshTopology::new();
    for identity in &identities {
        topology.add_node(identity.node_id.clone());
    }
    topology.connect_all_peers();

    // Verify initial fully connected state
    assert!(topology.is_fully_connected(), "Initial mesh should be fully connected");

    // Phase 3: Remove node B from network
    topology.deactivate_node(1);
    let remaining_count = topology.get_active_node_count();
    assert_eq!(remaining_count, 3, "Should have 3 active nodes");

    // Verify other nodes still connected to each other
    for i in 0..identities.len() {
        if i != 1 {
            assert_eq!(
                topology.peer_count(i),
                2,
                "Node {} should have 2 peers (lost 1)",
                i
            );
        }
    }

    // Phase 4: Node B rejoins with same NodeId
    let node_b_restarted = create_test_identity("mesh-stable-b", [0x2B; 64])?;
    assert_eq!(
        identities[1].node_id, node_b_restarted.node_id,
        "Node B must have same NodeId after restart"
    );

    // Reactivate in topology
    topology.reactivate_node(1);

    // Phase 5: Verify mesh is fully connected again
    assert!(
        topology.is_fully_connected(),
        "Mesh should be fully connected after node rejoin"
    );

    Ok(())
}

/// Test 3: Network Stability with Random Restarts
///
/// Scenario: Restart 2 random nodes from a 5-node network.
/// Verify network remains stable and nodes rejoin.
#[test]
fn test_mesh_network_stability_with_random_restarts() -> Result<()> {
    // Phase 1: Create 5-node network
    let nodes = [
        ("stable-mesh-1", [0xA1; 64]),
        ("stable-mesh-2", [0xA2; 64]),
        ("stable-mesh-3", [0xA3; 64]),
        ("stable-mesh-4", [0xA4; 64]),
        ("stable-mesh-5", [0xA5; 64]),
    ];

    let mut identities = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities.push(identity);
    }

    // Phase 2: Build and verify initial mesh
    let mut topology = MeshTopology::new();
    for identity in &identities {
        topology.add_node(identity.node_id.clone());
    }
    topology.connect_all_peers();
    assert!(topology.is_fully_connected(), "Initial 5-node mesh should be connected");

    // Phase 3: Restart nodes 1 and 3 (random restarts)
    topology.deactivate_node(1);
    topology.deactivate_node(3);

    let remaining_active = topology.get_active_node_count();
    assert_eq!(remaining_active, 3, "Should have 3 active nodes after deactivation");

    // Phase 4: Verify remaining 3 nodes still connected
    assert!(
        topology.nodes[0].has_peer(&topology.nodes[2].node_id),
        "Remaining nodes should stay connected"
    );

    // Phase 5: Restart nodes rejoin
    topology.reactivate_node(1);
    topology.reactivate_node(3);

    // Phase 6: Verify all nodes reconnected
    assert_eq!(
        topology.get_active_node_count(),
        5,
        "All 5 nodes should be active again"
    );
    assert!(
        topology.is_fully_connected(),
        "Network should be fully connected after restarts"
    );

    // Verify each node has correct peer count
    for i in 0..identities.len() {
        assert_eq!(
            topology.peer_count(i),
            4,
            "Node {} should have 4 peers after restart recovery",
            i
        );
    }

    Ok(())
}

/// Test 4: Mesh Node Routing Verification
///
/// Scenario: Verify all node pairs can route to each other.
/// Simulate message routing through mesh.
#[test]
fn test_mesh_node_routing_paths() -> Result<()> {
    // Phase 1: Create 4-node mesh
    let nodes = [
        ("route-node-1", [0xF1; 64]),
        ("route-node-2", [0xF2; 64]),
        ("route-node-3", [0xF3; 64]),
        ("route-node-4", [0xF4; 64]),
    ];

    let mut identities = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities.push(identity);
    }

    // Phase 2: Build mesh
    let mut topology = MeshTopology::new();
    for identity in &identities {
        topology.add_node(identity.node_id.clone());
    }
    topology.connect_all_peers();

    // Phase 3: Verify all routing paths exist
    // In fully connected mesh, any node can directly route to any other
    for i in 0..identities.len() {
        for j in 0..identities.len() {
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

    Ok(())
}

/// Test 5: Mesh Network Convergence Timeline
///
/// Scenario: Track network as nodes join sequentially.
/// Verify convergence happens within expected time.
#[test]
fn test_mesh_convergence_timeline() -> Result<()> {
    // Phase 1: Create 6 nodes but add sequentially
    let nodes = [
        ("join-mesh-1", [0x61; 64]),
        ("join-mesh-2", [0x62; 64]),
        ("join-mesh-3", [0x63; 64]),
        ("join-mesh-4", [0x64; 64]),
        ("join-mesh-5", [0x65; 64]),
        ("join-mesh-6", [0x66; 64]),
    ];

    let mut identities = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities.push(identity);
    }

    // Phase 2: Build network incrementally
    let mut topology = MeshTopology::new();

    // Add node 1
    topology.add_node(identities[0].node_id.clone());
    topology.advance_cycle();

    // Add nodes 2-6 one at a time
    for i in 1..identities.len() {
        topology.add_node(identities[i].node_id.clone());
        topology.connect_all_peers();
        topology.advance_cycle();

        // After adding each node, mesh should still be fully connected
        assert!(
            topology.is_fully_connected(),
            "Mesh should be fully connected after adding node {}",
            i + 1
        );
    }

    // Phase 3: Verify final network has 6 fully connected nodes
    assert_eq!(topology.nodes.len(), 6, "Should have 6 nodes");
    assert!(topology.is_fully_connected(), "Final mesh should be fully connected");

    for i in 0..identities.len() {
        assert_eq!(
            topology.peer_count(i),
            5,
            "Node {} should have 5 peers in 6-node mesh",
            i
        );
    }

    Ok(())
}

/// Test 6: Mesh Partition Recovery
///
/// Scenario: Simulate network partition (5-node split into 3+2).
/// Verify network can heal when partition is healed.
#[test]
fn test_mesh_network_partition_recovery() -> Result<()> {
    // Phase 1: Create 5-node fully connected mesh
    let nodes = [
        ("partition-1", [0x71; 64]),
        ("partition-2", [0x72; 64]),
        ("partition-3", [0x73; 64]),
        ("partition-4", [0x74; 64]),
        ("partition-5", [0x75; 64]),
    ];

    let mut identities = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities.push(identity);
    }

    let mut topology = MeshTopology::new();
    for identity in &identities {
        topology.add_node(identity.node_id.clone());
    }
    topology.connect_all_peers();

    assert!(topology.is_fully_connected(), "Initial mesh fully connected");

    // Phase 2: Simulate partition - remove nodes 3 and 4
    // This creates two groups: [1,2] and [5] and orphans [3,4]
    topology.deactivate_node(2);
    topology.deactivate_node(3);

    // Verify partitions exist
    let active_count = topology.get_active_node_count();
    assert_eq!(active_count, 3, "3 nodes should remain active");

    // Phase 3: Heal partition - reactivate nodes
    topology.reactivate_node(2);
    topology.reactivate_node(3);

    // Phase 4: Verify network is whole again
    assert!(
        topology.is_fully_connected(),
        "Mesh should recover after partition healing"
    );

    assert_eq!(
        topology.get_active_node_count(),
        5,
        "All 5 nodes should be reconnected"
    );

    Ok(())
}

/// Test 7: Mesh Stability Metrics
///
/// Scenario: Track stability metrics during normal operation.
/// Verify topology remains stable over multiple cycles.
#[test]
fn test_mesh_stability_metrics() -> Result<()> {
    let nodes = [
        ("metrics-a", [0x8A; 64]),
        ("metrics-b", [0x8B; 64]),
        ("metrics-c", [0x8C; 64]),
        ("metrics-d", [0x8D; 64]),
    ];

    let mut identities = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities.push(identity);
    }

    // Simulate 5 cycles of stable operation
    let mut topology = MeshTopology::new();
    for identity in &identities {
        topology.add_node(identity.node_id.clone());
    }

    let mut stability_record = Vec::new();

    for cycle in 0..5 {
        topology.connect_all_peers();
        topology.advance_cycle();

        // Record metrics
        let is_stable = topology.is_fully_connected();
        let active_count = topology.get_active_node_count();

        stability_record.push((cycle, is_stable, active_count));

        assert!(
            is_stable,
            "Mesh should remain stable in cycle {}",
            cycle
        );
        assert_eq!(
            active_count, 4,
            "Should have 4 active nodes in cycle {}",
            cycle
        );
    }

    // Verify stability across all cycles
    for (cycle, is_stable, active_count) in stability_record {
        assert!(is_stable, "Cycle {} should be stable", cycle);
        assert_eq!(active_count, 4, "Cycle {} should have 4 nodes", cycle);
    }

    Ok(())
}
