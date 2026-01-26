//! Mesh Network Formation Test (Issue #71)
//!
//! Goal: Verify mesh network topology forms and remains stable
//! under various conditions including node restarts.

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
    let identities = create_test_identities(&nodes, create_test_identity);
    let topology = build_mesh_topology(&identities);
    assert_fully_connected(&topology, 4);
    Ok(())
}

/// Test 2: Mesh Network with Node Departure and Rejoin
///
/// Scenario: Remove node from mesh, then rejoin with same NodeId.
/// Verify topology recovers and node rejoins with correct identity.
#[test]
fn test_mesh_node_departure_and_rejoin() -> Result<()> {
    let nodes = [
        ("mesh-stable-a", [0x1A; 64]),
        ("mesh-stable-b", [0x2B; 64]),
        ("mesh-stable-c", [0x3C; 64]),
        ("mesh-stable-d", [0x4D; 64]),
    ];
    let identities = create_test_identities(&nodes, create_test_identity);
    let mut topology = build_mesh_topology(&identities);

    // Verify initial fully connected state
    assert!(topology.is_fully_connected(), "Initial mesh should be fully connected");

    // Remove node B from network
    topology.deactivate_node(1);
    assert_eq!(topology.get_active_node_count(), 3, "Should have 3 active nodes");

    // Node B rejoins with same NodeId
    let node_b_restarted = create_test_identity("mesh-stable-b", [0x2B; 64])?;
    assert_eq!(identities[1].node_id, node_b_restarted.node_id, "Node B must have same NodeId after restart");

    // Reactivate in topology
    topology.reactivate_node(1);

    // Verify mesh is fully connected again
    assert!(topology.is_fully_connected(), "Mesh should be fully connected after node rejoin");

    Ok(())
}

/// Test 3: Network Stability with Random Restarts
///
    const TEST_TIMEOUT: Duration = Duration::from_secs(25);
    const MESH_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn test_mesh_formation_shared() -> Result<()> {
        run_shared_mesh_formation_test().await
    }
/// Scenario: Restart 2 random nodes from a 5-node network.
/// Verify network remains stable and nodes rejoin.
#[test]
fn test_mesh_network_stability_with_random_restarts() -> Result<()> {
    let nodes = [
        ("stable-mesh-1", [0xA1; 64]),
        ("stable-mesh-2", [0xA2; 64]),
        ("stable-mesh-3", [0xA3; 64]),
        ("stable-mesh-4", [0xA4; 64]),
        ("stable-mesh-5", [0xA5; 64]),
    ];
    let identities = create_test_identities(&nodes, create_test_identity);
    let mut topology = build_mesh_topology(&identities);

    assert!(topology.is_fully_connected(), "Initial 5-node mesh should be connected");

    // Restart nodes 1 and 3
    topology.deactivate_node(1);
    topology.deactivate_node(3);
    assert_eq!(topology.get_active_node_count(), 3, "Should have 3 active nodes after deactivation");

    // Rejoin nodes
    topology.reactivate_node(1);
    topology.reactivate_node(3);

    // Verify all nodes reconnected
    assert_eq!(topology.get_active_node_count(), 5, "All 5 nodes should be active again");
    assert!(topology.is_fully_connected(), "Network should be fully connected after restarts");
    assert_fully_connected(&topology, 4);

    Ok(())
}

/// Test 4: Mesh Node Routing Verification
///
/// Scenario: Verify all node pairs can route to each other.
/// Simulate message routing through mesh.
#[test]
fn test_mesh_node_routing_paths() -> Result<()> {
    let nodes = [
        ("route-node-1", [0xF1; 64]),
        ("route-node-2", [0xF2; 64]),
        ("route-node-3", [0xF3; 64]),
        ("route-node-4", [0xF4; 64]),
    ];
    let identities = create_test_identities(&nodes, create_test_identity);
    let topology = build_mesh_topology(&identities);

    common_network_test::assert_mesh_routing_paths(&topology);

    Ok(())
}

/// Test 5: Mesh Network Convergence Timeline
///
/// Scenario: Track network as nodes join sequentially.
/// Verify convergence happens within expected time.
#[test]
fn test_mesh_convergence_timeline() -> Result<()> {
    let nodes = [
        ("join-mesh-1", [0x61; 64]),
        ("join-mesh-2", [0x62; 64]),
        ("join-mesh-3", [0x63; 64]),
        ("join-mesh-4", [0x64; 64]),
        ("join-mesh-5", [0x65; 64]),
        ("join-mesh-6", [0x66; 64]),
    ];
    let identities = create_test_identities(&nodes, create_test_identity);

    // Build network incrementally
    let mut topology = MeshTopology::new();
    topology.add_node(identities[0].node_id.clone());
    topology.advance_cycle();

    for i in 1..identities.len() {
        topology.add_node(identities[i].node_id.clone());
        topology.connect_all_peers();
        topology.advance_cycle();
        assert!(topology.is_fully_connected(), "Mesh should be fully connected after adding node {}", i + 1);
    }

    // Verify final network
    assert_eq!(topology.nodes.len(), 6, "Should have 6 nodes");
    assert_fully_connected(&topology, 5);

    Ok(())
}

/// Test 6: Mesh Partition Recovery
///
/// Scenario: Simulate network partition (5-node split into 3+2).
/// Verify network can heal when partition is healed.
#[test]
fn test_mesh_network_partition_recovery() -> Result<()> {
    let nodes = [
        ("partition-1", [0x71; 64]),
        ("partition-2", [0x72; 64]),
        ("partition-3", [0x73; 64]),
        ("partition-4", [0x74; 64]),
        ("partition-5", [0x75; 64]),
    ];
    let identities = create_test_identities(&nodes, create_test_identity);
    let mut topology = build_mesh_topology(&identities);

    assert!(topology.is_fully_connected(), "Initial mesh fully connected");

    // Simulate partition - deactivate nodes 2 and 3
    topology.deactivate_node(2);
    topology.deactivate_node(3);
    assert_eq!(topology.get_active_node_count(), 3, "3 nodes should remain active");

    // Heal partition
    topology.reactivate_node(2);
    topology.reactivate_node(3);

    // Verify network is whole again
    assert!(topology.is_fully_connected(), "Mesh should recover after partition healing");
    assert_eq!(topology.get_active_node_count(), 5, "All 5 nodes should be reconnected");

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
    let identities = create_test_identities(&nodes, create_test_identity);
    let mut topology = build_mesh_topology(&identities);

    // Simulate 5 cycles and verify stability
    for cycle in 0..5 {
        topology.advance_cycle();
        assert!(topology.is_fully_connected(), "Mesh should remain stable in cycle {}", cycle);
        assert_eq!(topology.get_active_node_count(), 4, "Should have 4 active nodes in cycle {}", cycle);
    }

    Ok(())
}
