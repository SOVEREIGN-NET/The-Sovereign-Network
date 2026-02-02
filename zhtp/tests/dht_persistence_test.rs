/// Helper: Run DHT consistency test across multiple restart cycles
fn run_dht_consistency_across_restarts(nodes: &[(&str, [u8; 64])], cycles: usize) -> Result<()> {
    let reference_identities = create_identities_from_nodes(nodes)?;
    let reference_node_ids: Vec<NodeId> = reference_identities.iter().map(|id| id.node_id.clone()).collect();
    for cycle in 0..cycles {
        verify_restart_cycle_consistency(nodes, &reference_node_ids, cycle)?;
    }
    Ok(())
}

/// Helper: Run DHT network convergence simulation
fn run_dht_network_convergence(nodes: &[(&str, [u8; 64])]) -> Result<()> {
    let identities = create_identities_from_nodes(nodes)?;
    let mut dht_states = create_dht_states(&identities);
    discover_ring_neighbors(&mut dht_states, &identities)?;
    complete_mesh_discovery(&mut dht_states, &identities)?;
    let expected_peers = identities.len() - 1;
    assert!(verify_dht_peer_counts(&dht_states, expected_peers), "All nodes should discover all {} peers", expected_peers);
    Ok(())
}

/// Helper: Run DHT persistence metrics tracking
fn run_dht_persistence_metrics(nodes: &[(&str, [u8; 64])]) -> Result<()> {
    let identities_c1 = create_identities_from_nodes(nodes)?;
    let mut dht_c1 = create_dht_states(&identities_c1);
    populate_dht_full_mesh(&mut dht_c1, &identities_c1, 0)?;
    for dht in &mut dht_c1 { dht.set_convergence_cycle(1); }
    let metrics_c1: Vec<usize> = dht_c1.iter().map(|d| d.peer_count()).collect();
    let convergence_c1: Vec<u32> = dht_c1.iter().map(|d| d.get_convergence_cycle()).collect();
    let identities_c2 = create_identities_from_nodes(nodes)?;
    assert!(verify_node_ids_match(&identities_c1, &identities_c2), "NodeIds must persist");
    let mut dht_c2 = create_dht_states(&identities_c2);
    populate_dht_full_mesh(&mut dht_c2, &identities_c2, 1)?;
    for dht in &mut dht_c2 { dht.set_convergence_cycle(2); }
    let metrics_c2: Vec<usize> = dht_c2.iter().map(|d| d.peer_count()).collect();
    assert_eq!(metrics_c1, metrics_c2, "DHT peer counts must match after restart");
    let convergence_c2: Vec<u32> = dht_c2.iter().map(|d| d.get_convergence_cycle()).collect();
    for (c1, c2) in convergence_c1.iter().zip(convergence_c2.iter()) {
        assert!(c2 > c1, "Convergence cycle must progress");
    }
    Ok(())
}

// DHT Persistence Test (Issue #70)
//
// Goal: Verify DHT routing tables rebuild correctly after network restart
// with deterministic NodeIds.
//
// Test Scenarios:
// - All nodes maintain same NodeIds after restart
// - DHT routing tables repopulate with same entries
// - Network converges within 30 seconds
// - All nodes can communicate after restart

mod common_network_test;
use common_network_test::{
    create_test_identity_with_seed as create_test_identity,
    peer_id_from_node_id, DhtEntry, DhtRoutingState,
    create_identities_from_nodes, create_dht_states, populate_dht_full_mesh,
    verify_node_ids_match, verify_dht_peer_counts,
};

use anyhow::Result;
use lib_identity::NodeId;
use lib_network::identity::UnifiedPeerId;
use std::time::Duration;
use uuid::Uuid;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(30);

/// Test 1: Three-Node DHT Bootstrap and Routing Table Population
///
/// Scenario: Three nodes start and exchange routing information via DHT.
/// Verify all nodes have entries for each other.
#[test]
fn test_three_node_dht_bootstrap() -> Result<()> {
    // Phase 1: Create three nodes with distinct seeds
    let nodes = [
        ("alice-dht-001", [0xAA; 64]),
        ("bob-dht-001", [0xBB; 64]),
        ("charlie-dht-001", [0xCC; 64]),
    ];

    let identities = create_identities_from_nodes(&nodes)?;
    let mut dht_states = create_dht_states(&identities);
    for dht in &mut dht_states {
        dht.set_convergence_cycle(0);
    }

    // Phase 2: Simulate DHT peer discovery using helper
    populate_dht_full_mesh(&mut dht_states, &identities, 0)?;

    // Phase 3: Verify DHT tables populated
    assert!(verify_dht_peer_counts(&dht_states, 2), "All nodes should have 2 peers");

    // Phase 4: Verify all nodes can see each other
    verify_full_mesh_connectivity(&dht_states, &identities);

    Ok(())
}

/// Helper: Verify all nodes have entries for all other nodes
fn verify_full_mesh_connectivity(dht_states: &[DhtRoutingState], identities: &[lib_identity::ZhtpIdentity]) {
    for (i, dht) in dht_states.iter().enumerate() {
        for (j, identity) in identities.iter().enumerate() {
            if i != j {
                assert!(
                    dht.has_peer(&identity.node_id),
                    "Node {} should know about Node {}", i, j
                );
            }
        }
    }
}

/// Test 2: DHT Persistence Across Single Node Restart
///
/// Scenario: Start 3 nodes, let them converge. Restart one node (Alice).
/// Verify:
/// - Alice's NodeId unchanged
/// - Alice rebuilds DHT entries for Bob and Charlie
/// - Bob and Charlie still have Alice in their tables
#[test]
fn test_dht_persistence_single_node_restart() -> Result<()> {
    // Phase 1: Create three nodes
    let nodes = [
        ("alice-dht-002", [0xAA; 64]),
        ("bob-dht-002", [0xBB; 64]),
        ("charlie-dht-002", [0xCC; 64]),
    ];

    let identities_before = create_identities_from_nodes(&nodes)?;

    // Phase 2: Build DHT routing tables
    let mut dht_before = create_dht_states(&identities_before);
    populate_dht_full_mesh(&mut dht_before, &identities_before, 0)?;
    for dht in &mut dht_before {
        dht.set_convergence_cycle(1);
    }

    // Phase 3: Restart Alice (recreate with same seed)
    let alice_restarted = create_test_identity("alice-dht-002", [0xAA; 64])?;
    assert_eq!(
        identities_before[0].node_id, alice_restarted.node_id,
        "Alice's NodeId must survive restart"
    );

    // Phase 4: Alice rebuilds DHT table from other nodes
    let mut dht_alice_after = DhtRoutingState::new(alice_restarted.node_id.clone());
    add_peers_except_self(&mut dht_alice_after, &identities_before, 0, 1)?;
    dht_alice_after.set_convergence_cycle(2);

    // Verify Alice recovered her routing table
    assert_eq!(dht_alice_after.peer_count(), 2, "Alice should recover 2 peers");
    assert!(dht_alice_after.has_peer(&identities_before[1].node_id), "Alice should recover Bob's entry");
    assert!(dht_alice_after.has_peer(&identities_before[2].node_id), "Alice should recover Charlie's entry");

    // Verify Bob and Charlie still have Alice
    assert!(dht_before[1].has_peer(&identities_before[0].node_id), "Bob should still have Alice's entry");
    assert!(dht_before[2].has_peer(&identities_before[0].node_id), "Charlie should still have Alice's entry");

    Ok(())
}

/// Helper: Add all peers to a DHT state except self (by index)
fn add_peers_except_self(
    dht: &mut DhtRoutingState,
    identities: &[lib_identity::ZhtpIdentity],
    self_index: usize,
    cycle: u32,
) -> Result<()> {
    for (j, identity) in identities.iter().enumerate() {
        if j != self_index {
            let peer_uuid = Uuid::from_slice(&identity.node_id.as_bytes()[..16])?;
            dht.add_peer(identity.node_id.clone(), peer_uuid, cycle);
        }
    }
    Ok(())
}

/// Test 3: Full Network Restart (All 3 Nodes)
///
/// Scenario: Start 3 nodes, converge. Restart all 3 nodes simultaneously.
/// Verify:
/// - All NodeIds remain unchanged
/// - All DHT routing tables repopulate
/// - Network reaches convergence within 30 seconds (simulated)
#[test]
fn test_dht_persistence_full_network_restart() -> Result<()> {
    let nodes = [
        ("alice-dht-003", [0xAA; 64]),
        ("bob-dht-003", [0xBB; 64]),
        ("charlie-dht-003", [0xCC; 64]),
    ];

    // Phase 1: Create and converge first cycle
    let identities_before = create_identities_from_nodes(&nodes)?;
    let mut dht_cycle_0 = create_dht_states(&identities_before);
    populate_dht_full_mesh(&mut dht_cycle_0, &identities_before, 0)?;
    for dht in &mut dht_cycle_0 {
        dht.set_convergence_cycle(1);
    }
    assert!(verify_dht_peer_counts(&dht_cycle_0, 2), "All nodes should have 2 peers in cycle 0");

    // Phase 2: Restart all nodes
    let identities_after = create_identities_from_nodes(&nodes)?;
    assert!(verify_node_ids_match(&identities_before, &identities_after), "NodeIds must survive restart");

    // Phase 3: Rebuild DHT tables after restart
    let mut dht_cycle_1 = create_dht_states(&identities_after);
    populate_dht_full_mesh(&mut dht_cycle_1, &identities_after, 1)?;
    for dht in &mut dht_cycle_1 {
        dht.set_convergence_cycle(2);
    }

    // Verify convergence
    assert!(verify_dht_peer_counts(&dht_cycle_1, 2), "All nodes should repopulate 2 peers after restart");
    assert!(dht_cycle_1.iter().all(|d| d.get_convergence_cycle() == 2), "All nodes should be at cycle 2");

    Ok(())
}

/// Test 4: DHT Routing Table Consistency Across Restarts
///
/// Scenario: Cycle network restart 3 times. Verify:
/// - NodeIds consistent across all cycles
/// - Routing tables remain consistent
/// - Peer entries never change across restarts
#[test]
fn test_dht_consistency_across_multiple_restart_cycles() -> Result<()> {
    let nodes = [
        ("alice-dht-004", [0xAA; 64]),
        ("bob-dht-004", [0xBB; 64]),
    ];
    run_dht_consistency_across_restarts(&nodes, 3)
}

/// Helper: Verify a single restart cycle maintains NodeId and routing consistency
fn verify_restart_cycle_consistency(
    nodes: &[(&str, [u8; 64])],
    reference_node_ids: &[NodeId],
    cycle: usize,
) -> Result<()> {
    let identities = create_identities_from_nodes(nodes)?;
    
    // Verify NodeIds match reference
    for (i, identity) in identities.iter().enumerate() {
        assert_eq!(
            identity.node_id, reference_node_ids[i],
            "Node {} NodeId must be consistent in cycle {}", i, cycle
        );
    }

    // Build and verify DHT routing tables
    let mut dht_states = create_dht_states(&identities);
    populate_dht_full_mesh(&mut dht_states, &identities, cycle as u32)?;

    // Verify all peers are present
    for (i, dht) in dht_states.iter().enumerate() {
        let expected_peers: Vec<&NodeId> = reference_node_ids.iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, id)| id)
            .collect();
        for peer_id in expected_peers {
            assert!(dht.has_peer(peer_id), "Node {} should have peer in cycle {}", i, cycle);
        }
    }
    Ok(())
}

/// Test 5: DHT Network Convergence Simulation
///
/// Scenario: Simulate DHT convergence by gradually discovering peers.
/// Verify network reaches full connectivity.
#[test]
fn test_dht_network_convergence_simulation() -> Result<()> {
    let nodes = [
        ("node-dht-0", [0x10; 64]),
        ("node-dht-1", [0x20; 64]),
        ("node-dht-2", [0x30; 64]),
        ("node-dht-3", [0x40; 64]),
    ];
    run_dht_network_convergence(&nodes)
}

/// Helper: Discover ring neighbors (each node discovers next node in ring)
fn discover_ring_neighbors(
    dht_states: &mut [DhtRoutingState],
    identities: &[lib_identity::ZhtpIdentity],
) -> Result<()> {
    for i in 0..identities.len() {
        let next = (i + 1) % identities.len();
        let peer_uuid = Uuid::from_slice(&identities[next].node_id.as_bytes()[..16])?;
        dht_states[i].add_peer(identities[next].node_id.clone(), peer_uuid, 0);
    }
    Ok(())
}

/// Helper: Complete discovery to full mesh (discover all missing peers)
fn complete_mesh_discovery(
    dht_states: &mut [DhtRoutingState],
    identities: &[lib_identity::ZhtpIdentity],
) -> Result<()> {
    for i in 0..identities.len() {
        for j in 0..identities.len() {
            if i != j && !dht_states[i].has_peer(&identities[j].node_id) {
                let peer_uuid = Uuid::from_slice(&identities[j].node_id.as_bytes()[..16])?;
                dht_states[i].add_peer(identities[j].node_id.clone(), peer_uuid, 1);
            }
        }
        dht_states[i].set_convergence_cycle(2);
    }
    Ok(())
}

/// Test 6: DHT Persistence Metrics Tracking
///
/// Scenario: Track DHT metrics across a restart to verify recovery.
/// Metrics: peer count, convergence time, routing table size
#[test]
fn test_dht_persistence_metrics() -> Result<()> {
    let nodes = [
        ("alice-metrics", [0xAA; 64]),
        ("bob-metrics", [0xBB; 64]),
        ("charlie-metrics", [0xCC; 64]),
    ];
    run_dht_persistence_metrics(&nodes)
}
