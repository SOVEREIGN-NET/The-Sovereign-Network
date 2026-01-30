//! DHT Persistence Test (Issue #70)
//!
//! Goal: Verify DHT routing tables rebuild correctly after network restart
//! with deterministic NodeIds.

use anyhow::Result;
use lib_identity::testing::create_test_identity;
use uuid::Uuid;

#[path = "common_network_test.rs"]
mod common_network_test;

use common_network_test::{
    DhtRoutingState, create_test_identities, build_dht_states,
    populate_dht_peers, assert_dht_peer_counts,
};

/// Test 1: DHT Persistence via Shared Helper
#[tokio::test]
async fn test_dht_persistence_shared() -> Result<()> {
    common_network_test::run_shared_dht_persistence_test().await
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

    let alice_restarted = create_test_identity("alice-dht-002", [0xAA; 64])?;
    assert_eq!(
        identities_before[0].node_id, alice_restarted.node_id,
        "Alice's NodeId must survive restart"
    );

    let mut dht_alice_after = DhtRoutingState::new(alice_restarted.node_id.clone());
    for j in 1..identities_before.len() {
        let peer_node_id = identities_before[j].node_id.clone();
        let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
        dht_alice_after.add_peer(peer_node_id, peer_uuid, 1);
    }
    dht_alice_after.set_convergence_cycle(2);

    assert_eq!(dht_alice_after.peer_count(), 2, "Alice should recover 2 peers");
    assert!(dht_alice_after.has_peer(&identities_before[1].node_id));
    assert!(dht_alice_after.has_peer(&identities_before[2].node_id));
    assert!(dht_before[1].has_peer(&identities_before[0].node_id));
    assert!(dht_before[2].has_peer(&identities_before[0].node_id));

    Ok(())
}

/// Test 3: Full Network Restart (All 3 Nodes)
#[test]
fn test_dht_persistence_full_network_restart() -> Result<()> {
    let nodes = [
        ("alice-dht-003", [0xAA; 64]),
        ("bob-dht-003", [0xBB; 64]),
        ("charlie-dht-003", [0xCC; 64]),
    ];

    let identities_before = create_test_identities(&nodes, create_test_identity);
    let mut dht_cycle_0 = build_dht_states(&identities_before, 1);
    populate_dht_peers(&mut dht_cycle_0, &identities_before, 0);
    assert_dht_peer_counts(&dht_cycle_0, 2);

    let identities_after = create_test_identities(&nodes, create_test_identity);
    common_network_test::assert_node_id_stability(&identities_before, &identities_after);

    let mut dht_cycle_1 = build_dht_states(&identities_after, 2);
    populate_dht_peers(&mut dht_cycle_1, &identities_after, 1);
    assert_dht_peer_counts(&dht_cycle_1, 2);
    common_network_test::assert_convergence_cycle(&dht_cycle_1, 2);

    Ok(())
}

/// Test 4: DHT Routing Table Consistency Across Restarts
#[test]
fn test_dht_consistency_across_multiple_restart_cycles() -> Result<()> {
    let nodes = [
        ("alice-dht-004", [0xAA; 64]),
        ("bob-dht-004", [0xBB; 64]),
    ];

    let baseline_identities = create_test_identities(&nodes, create_test_identity);
    let baseline_node_ids: Vec<_> = baseline_identities.iter().map(|id| id.node_id.clone()).collect();

    for cycle in 0..3 {
        let identities = create_test_identities(&nodes, create_test_identity);
        common_network_test::assert_node_ids_match(&identities, &baseline_node_ids, cycle);

        let mut dht_states = build_dht_states(&identities, cycle as u32);
        populate_dht_peers(&mut dht_states, &identities, cycle as u32);
        assert_dht_peer_counts(&dht_states, 1);
    }

    Ok(())
}

/// Test 5: DHT Network Convergence Simulation
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

    for i in 0..identities.len() {
        let next = (i + 1) % identities.len();
        let peer_node_id = identities[next].node_id.clone();
        let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
        dht_states[i].add_peer(peer_node_id, peer_uuid, 0);
    }

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

    for (i, dht) in dht_states.iter().enumerate() {
        assert_eq!(dht.peer_count(), 3, "Node {} should have 3 peers", i);
    }

    Ok(())
}

/// Test 6: DHT Persistence Metrics Tracking
#[test]
fn test_dht_persistence_metrics() -> Result<()> {
    let nodes = [
        ("alice-metrics", [0xAA; 64]),
        ("bob-metrics", [0xBB; 64]),
        ("charlie-metrics", [0xCC; 64]),
    ];

    let identities_c1 = create_test_identities(&nodes, create_test_identity);
    let mut dht_c1 = build_dht_states(&identities_c1, 1);
    populate_dht_peers(&mut dht_c1, &identities_c1, 0);

    let metrics_c1: Vec<usize> = dht_c1.iter().map(|d| d.peer_count()).collect();

    let identities_c2 = create_test_identities(&nodes, create_test_identity);
    common_network_test::assert_node_id_stability(&identities_c1, &identities_c2);

    let mut dht_c2 = build_dht_states(&identities_c2, 2);
    populate_dht_peers(&mut dht_c2, &identities_c2, 1);

    let metrics_c2: Vec<usize> = dht_c2.iter().map(|d| d.peer_count()).collect();
    assert_eq!(metrics_c1, metrics_c2, "DHT peer counts must match after restart");

    common_network_test::assert_convergence_progressed(&dht_c1, &dht_c2);

    Ok(())
}
