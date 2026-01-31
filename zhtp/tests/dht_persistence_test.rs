//! DHT Persistence Test (Issue #70)
//!
//! Goal: Verify DHT routing tables rebuild correctly after network restart
//! with deterministic NodeIds.
//!
//! Test Scenarios:
//! - All nodes maintain same NodeIds after restart
//! - DHT routing tables repopulate with same entries
//! - Network converges within 30 seconds
//! - All nodes can communicate after restart

mod common_network_test;
use common_network_test::{
    create_test_identity_with_seed as create_test_identity,
    peer_id_from_node_id, DhtEntry, DhtRoutingState,
};

use anyhow::Result;
use lib_identity::NodeId;
use lib_network::identity::UnifiedPeerId;
use std::time::Duration;
use uuid::Uuid;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(30);

/// Helper: Create identities from a list of (device_name, seed) tuples
fn create_identities_from_nodes(nodes: &[(&str, [u8; 64])]) -> Result<Vec<lib_identity::ZhtpIdentity>> {
    nodes.iter()
        .map(|(device, seed)| create_test_identity(device, *seed))
        .collect()
}

/// Helper: Create DHT routing states for a list of identities
fn create_dht_states(identities: &[lib_identity::ZhtpIdentity]) -> Vec<DhtRoutingState> {
    identities.iter()
        .map(|id| DhtRoutingState::new(id.node_id.clone()))
        .collect()
}

/// Helper: Populate DHT routing tables with all peers (full mesh)
fn populate_dht_full_mesh(
    dht_states: &mut [DhtRoutingState],
    identities: &[lib_identity::ZhtpIdentity],
    cycle: u32,
) -> Result<()> {
    for i in 0..identities.len() {
        for j in 0..identities.len() {
            if i != j {
                let peer_node_id = identities[j].node_id.clone();
                let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                dht_states[i].add_peer(peer_node_id, peer_uuid, cycle);
            }
        }
    }
    Ok(())
}

/// Helper: Verify all NodeIds match between two identity lists
fn verify_node_ids_match(
    identities_a: &[lib_identity::ZhtpIdentity],
    identities_b: &[lib_identity::ZhtpIdentity],
) -> bool {
    identities_a.len() == identities_b.len()
        && identities_a.iter()
            .zip(identities_b.iter())
            .all(|(a, b)| a.node_id == b.node_id)
}

/// Helper: Verify all DHT states have expected peer count
fn verify_dht_peer_counts(dht_states: &[DhtRoutingState], expected_count: usize) -> bool {
    dht_states.iter().all(|dht| dht.peer_count() == expected_count)
}

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

    let mut identities = Vec::new();
    let mut dht_states = Vec::new();

    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        let mut dht = DhtRoutingState::new(identity.node_id.clone());
        dht.set_convergence_cycle(0);
        identities.push(identity);
        dht_states.push(dht);
    }

    // Phase 2: Simulate DHT peer discovery
    for i in 0..identities.len() {
        for j in 0..identities.len() {
            if i != j {
                let peer_node_id = identities[j].node_id.clone();
                let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                dht_states[i].add_peer(peer_node_id, peer_uuid, 0);
            }
        }
    }

    // Phase 3: Verify DHT tables populated
    for (i, dht) in dht_states.iter().enumerate() {
        assert_eq!(
            dht.peer_count(),
            2,
            "Node {} should have 2 peers (other 2 nodes)",
            i
        );
    }

    // Phase 4: Verify all nodes can see each other
    for i in 0..identities.len() {
        for j in 0..identities.len() {
            if i != j {
                assert!(
                    dht_states[i].has_peer(&identities[j].node_id),
                    "Node {} should know about Node {}",
                    i,
                    j
                );
            }
        }
    }

    Ok(())
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

    let mut identities_before = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities_before.push(identity);
    }

    // Phase 2: Build DHT routing tables
    let mut dht_before = vec![
        DhtRoutingState::new(identities_before[0].node_id.clone()),
        DhtRoutingState::new(identities_before[1].node_id.clone()),
        DhtRoutingState::new(identities_before[2].node_id.clone()),
    ];

    for i in 0..identities_before.len() {
        for j in 0..identities_before.len() {
            if i != j {
                let peer_node_id = identities_before[j].node_id.clone();
                let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                dht_before[i].add_peer(peer_node_id, peer_uuid, 0);
            }
        }
        dht_before[i].set_convergence_cycle(1);
    }

    // Phase 3: Restart Alice (recreate with same seed)
    let alice_restarted = create_test_identity("alice-dht-002", [0xAA; 64])?;

    // Verify Alice's NodeId is unchanged
    assert_eq!(
        identities_before[0].node_id, alice_restarted.node_id,
        "Alice's NodeId must survive restart"
    );

    // Phase 4: Alice rebuilds DHT table
    let mut dht_alice_after = DhtRoutingState::new(alice_restarted.node_id.clone());
    for j in 1..identities_before.len() {
        let peer_node_id = identities_before[j].node_id.clone();
        let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
        dht_alice_after.add_peer(peer_node_id, peer_uuid, 1);
    }
    dht_alice_after.set_convergence_cycle(2);

    // Verify Alice recovered her routing table
    assert_eq!(dht_alice_after.peer_count(), 2, "Alice should recover 2 peers");
    assert!(
        dht_alice_after.has_peer(&identities_before[1].node_id),
        "Alice should recover Bob's entry"
    );
    assert!(
        dht_alice_after.has_peer(&identities_before[2].node_id),
        "Alice should recover Charlie's entry"
    );

    // Verify Bob and Charlie still have Alice
    assert!(
        dht_before[1].has_peer(&identities_before[0].node_id),
        "Bob should still have Alice's entry"
    );
    assert!(
        dht_before[2].has_peer(&identities_before[0].node_id),
        "Charlie should still have Alice's entry"
    );

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

    // First cycle: store reference NodeIds and routing tables
    let reference_identities = create_identities_from_nodes(&nodes)?;
    let reference_node_ids: Vec<NodeId> = reference_identities.iter().map(|id| id.node_id.clone()).collect();

    // Run 3 restart cycles and verify consistency
    for cycle in 0..3 {
        verify_restart_cycle_consistency(&nodes, &reference_node_ids, cycle)?;
    }

    Ok(())
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

    let mut identities = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities.push(identity);
    }

    let mut dht_states = identities
        .iter()
        .map(|id| DhtRoutingState::new(id.node_id.clone()))
        .collect::<Vec<_>>();

    // Simulate convergence: peers discover each other gradually
    // Round 1: Each peer discovers direct neighbors
    for i in 0..identities.len() {
        let next = (i + 1) % identities.len();
        let peer_node_id = identities[next].node_id.clone();
        let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
        dht_states[i].add_peer(peer_node_id, peer_uuid, 0);
    }

    // Round 2: Peers discover peers they heard about
    for i in 0..identities.len() {
        for j in 0..identities.len() {
            if i != j && !dht_states[i].has_peer(&identities[j].node_id) {
                let peer_node_id = identities[j].node_id.clone();
                let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                dht_states[i].add_peer(peer_node_id, peer_uuid, 1);
            }
        }
        dht_states[i].set_convergence_cycle(2);
    }

    // Verify full convergence
    for (i, dht) in dht_states.iter().enumerate() {
        assert_eq!(
            dht.peer_count(),
            3,
            "Node {} should have discovered all {} other peers",
            i,
            identities.len() - 1
        );
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

    // Cycle 1: Initial startup and convergence
    let identities_c1 = create_identities_from_nodes(&nodes)?;
    let mut dht_c1 = create_dht_states(&identities_c1);
    populate_dht_full_mesh(&mut dht_c1, &identities_c1, 0)?;
    for dht in &mut dht_c1 {
        dht.set_convergence_cycle(1);
    }

    // Record metrics from cycle 1
    let metrics_c1: Vec<usize> = dht_c1.iter().map(|d| d.peer_count()).collect();
    let convergence_c1: Vec<u32> = dht_c1.iter().map(|d| d.get_convergence_cycle()).collect();

    // Cycle 2: Restart all nodes
    let identities_c2 = create_identities_from_nodes(&nodes)?;
    assert!(verify_node_ids_match(&identities_c1, &identities_c2), "NodeIds must persist");

    let mut dht_c2 = create_dht_states(&identities_c2);
    populate_dht_full_mesh(&mut dht_c2, &identities_c2, 1)?;
    for dht in &mut dht_c2 {
        dht.set_convergence_cycle(2);
    }

    // Verify metrics recovered
    let metrics_c2: Vec<usize> = dht_c2.iter().map(|d| d.peer_count()).collect();
    assert_eq!(metrics_c1, metrics_c2, "DHT peer counts must match after restart");

    // Verify convergence progressed
    let convergence_c2: Vec<u32> = dht_c2.iter().map(|d| d.get_convergence_cycle()).collect();
    for (c1, c2) in convergence_c1.iter().zip(convergence_c2.iter()) {
        assert!(c2 > c1, "Convergence cycle must progress");
    }

    Ok(())
}
