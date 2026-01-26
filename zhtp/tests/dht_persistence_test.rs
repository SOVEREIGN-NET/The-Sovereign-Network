//! DHT Persistence Test (Issue #70)
//!
//! Goal: Verify DHT routing tables rebuild correctly after network restart
//! with deterministic NodeIds.

use anyhow::Result;
use std::time::Duration;
mod common;
use common_network_test::{DhtEntry, DhtRoutingState, run_shared_dht_persistence_test, create_test_identities, build_dht_states, populate_dht_peers, assert_dht_peer_counts};

use anyhow::Result;
<<<<<<< HEAD
use lib_identity::{NodeId, ZhtpIdentity, testing::create_test_identity};
use lib_network::identity::UnifiedPeerId;
use std::{collections::HashMap, time::Duration};
use uuid::Uuid;
=======
const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(30);

mod common;
use common_network_test::{DhtEntry, DhtRoutingState, run_shared_dht_persistence_test};
}
#[tokio::test]
async fn test_dht_persistence_shared() -> Result<()> {
    run_shared_dht_persistence_test().await
}

/// Test 1: Three-Node DHT Bootstrap and Routing Table Population
///
/// Scenario: Three nodes start and exchange routing information via DHT.
/// Verify all nodes have entries for each other.
=======
// ...existing code...

#[tokio::test]
async fn test_dht_persistence_shared() -> Result<()> {
    run_shared_dht_persistence_test().await
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
    // Phase 1: Create three nodes with fixed seeds
    let nodes = [
        ("alice-dht-003", [0xAA; 64]),
        ("bob-dht-003", [0xBB; 64]),
        ("charlie-dht-003", [0xCC; 64]),
    ];

    let mut identities_before = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities_before.push(identity);
    }

    // Phase 2: Simulate first convergence
    let mut dht_cycle_0 = vec![
        DhtRoutingState::new(identities_before[0].node_id.clone()),
        DhtRoutingState::new(identities_before[1].node_id.clone()),
        DhtRoutingState::new(identities_before[2].node_id.clone()),
    ];

    for i in 0..identities_before.len() {
        for j in 0..identities_before.len() {
            if i != j {
                let peer_node_id = identities_before[j].node_id.clone();
                let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                dht_cycle_0[i].add_peer(peer_node_id, peer_uuid, 0);
            }
        }
        dht_cycle_0[i].set_convergence_cycle(1);
    }

    // Verify first convergence succeeded
    for (i, dht) in dht_cycle_0.iter().enumerate() {
        assert_eq!(dht.peer_count(), 2, "Node {} should have 2 peers in cycle 0", i);
    }

    // Phase 3: Restart all nodes simultaneously
    let mut identities_after = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities_after.push(identity);
    }

    // Phase 4: Verify all NodeIds unchanged
    for i in 0..identities_before.len() {
        assert_eq!(
            identities_before[i].node_id, identities_after[i].node_id,
            "Node {} NodeId must survive full network restart",
            i
        );
    }

    // Phase 5: Rebuild DHT tables after restart
    let mut dht_cycle_1 = vec![
        DhtRoutingState::new(identities_after[0].node_id.clone()),
        DhtRoutingState::new(identities_after[1].node_id.clone()),
        DhtRoutingState::new(identities_after[2].node_id.clone()),
    ];

    for i in 0..identities_after.len() {
        for j in 0..identities_after.len() {
            if i != j {
                let peer_node_id = identities_after[j].node_id.clone();
                let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                dht_cycle_1[i].add_peer(peer_node_id, peer_uuid, 1);
            }
        }
        dht_cycle_1[i].set_convergence_cycle(2);
    }

    // Phase 6: Verify second convergence succeeded
    for (i, dht) in dht_cycle_1.iter().enumerate() {
        assert_eq!(
            dht.peer_count(),
            2,
            "Node {} should repopulate 2 peers after restart",
            i
        );
    }

    // Phase 7: Verify convergence cycle tracking
    for dht in &dht_cycle_1 {
        assert_eq!(
            dht.get_convergence_cycle(),
            2,
            "All nodes should have progressed to convergence cycle 2"
        );
    }

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

    let mut stored_node_ids = Vec::new();
    let mut stored_routing_tables: Vec<Vec<NodeId>> = vec![Vec::new(), Vec::new()];

    // Cycle through 3 restart cycles
    for cycle in 0..3 {
        // Create identities
        let mut identities = Vec::new();
        for (device, seed) in &nodes {
            let identity = create_test_identity(device, *seed)?;
            identities.push(identity);
        }

        // Store NodeIds on first cycle
        if cycle == 0 {
            for identity in &identities {
                stored_node_ids.push(identity.node_id.clone());
            }
        }

        // Verify NodeIds are consistent
        for i in 0..identities.len() {
            assert_eq!(
                identities[i].node_id, stored_node_ids[i],
                "Node {} NodeId must be consistent in cycle {}",
                i,
                cycle
            );
        }

        // Build DHT routing tables
        let mut dht_states = vec![
            DhtRoutingState::new(identities[0].node_id.clone()),
            DhtRoutingState::new(identities[1].node_id.clone()),
        ];

        for i in 0..identities.len() {
            for j in 0..identities.len() {
                if i != j {
                    let peer_node_id = identities[j].node_id.clone();
                    let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                    dht_states[i].add_peer(peer_node_id.clone(), peer_uuid, cycle as u32);

                    // Store first cycle routing
                    if cycle == 0 {
                        stored_routing_tables[i].push(peer_node_id);
                    }
                }
            }
        }

        // Verify routing tables are consistent with first cycle
        for i in 0..dht_states.len() {
            for peer_node_id in &stored_routing_tables[i] {
                assert!(
                    dht_states[i].has_peer(peer_node_id),
                    "Node {} should have consistent peer entry in cycle {}",
                    i,
                    cycle
                );
            }
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

    // Cycle 1: Initial startup
    let mut identities_c1 = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities_c1.push(identity);
    }

    let mut dht_c1 = vec![
        DhtRoutingState::new(identities_c1[0].node_id.clone()),
        DhtRoutingState::new(identities_c1[1].node_id.clone()),
        DhtRoutingState::new(identities_c1[2].node_id.clone()),
    ];

    // Populate routing tables
    for i in 0..identities_c1.len() {
        for j in 0..identities_c1.len() {
            if i != j {
                let peer_node_id = identities_c1[j].node_id.clone();
                let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                dht_c1[i].add_peer(peer_node_id, peer_uuid, 0);
            }
        }
        dht_c1[i].set_convergence_cycle(1);
    }

    // Record metrics from cycle 1
    let metrics_c1: Vec<usize> = dht_c1.iter().map(|d| d.peer_count()).collect();
    let convergence_c1: Vec<u32> = dht_c1.iter().map(|d| d.get_convergence_cycle()).collect();

    // Cycle 2: Restart all nodes
    let mut identities_c2 = Vec::new();
    for (device, seed) in &nodes {
        let identity = create_test_identity(device, *seed)?;
        identities_c2.push(identity);
    }

    // Verify NodeIds unchanged
    for i in 0..identities_c1.len() {
        assert_eq!(
            identities_c1[i].node_id, identities_c2[i].node_id,
            "NodeId must persist"
        );
    }

    let mut dht_c2 = vec![
        DhtRoutingState::new(identities_c2[0].node_id.clone()),
        DhtRoutingState::new(identities_c2[1].node_id.clone()),
        DhtRoutingState::new(identities_c2[2].node_id.clone()),
    ];

    // Repopulate routing tables
    for i in 0..identities_c2.len() {
        for j in 0..identities_c2.len() {
            if i != j {
                let peer_node_id = identities_c2[j].node_id.clone();
                let peer_uuid = Uuid::from_slice(&peer_node_id.as_bytes()[..16])?;
                dht_c2[i].add_peer(peer_node_id, peer_uuid, 1);
            }
        }
        dht_c2[i].set_convergence_cycle(2);
    }

    // Verify metrics recovered
    let metrics_c2: Vec<usize> = dht_c2.iter().map(|d| d.peer_count()).collect();

    assert_eq!(
        metrics_c1, metrics_c2,
        "DHT peer counts must match after restart"
    );

    // Verify convergence progressed
    let convergence_c2: Vec<u32> = dht_c2.iter().map(|d| d.get_convergence_cycle()).collect();
    for i in 0..convergence_c2.len() {
        assert!(
            convergence_c2[i] > convergence_c1[i],
            "Convergence cycle must progress"
        );
    }

    Ok(())
}
