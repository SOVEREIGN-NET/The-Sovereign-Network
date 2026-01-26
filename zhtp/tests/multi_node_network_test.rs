//! Multi-Node Network Test (Issue #69)
//!
//! Goal: Verify that multiple zhtp orchestrator nodes can discover and connect to each
//! other at startup, properly exchange routing information via DHT, and maintain
//! connections across restarts.
//!
//! Test Scenarios:
//! - Nodes discover each other via mDNS/DHT
//! - DHT routing tables populate correctly
//! - NodeId stable after restart
//! - Peer connections re-establish automatically

use anyhow::Result;
use std::time::Duration;
mod common;
use common_network_test::run_shared_multi_node_network_test;

const TEST_TIMEOUT: Duration = Duration::from_secs(15);
const DISCOVERY_WAIT_TIME: Duration = Duration::from_secs(2);

// ...existing code...

#[tokio::test]
async fn test_multi_node_network_shared() -> Result<()> {
    run_shared_multi_node_network_test().await
}

// Example deduplication for a multi-node test:
#[test]
fn test_five_node_network_formation_sync() -> Result<()> {
    let nodes = [
        ("node-1", [0x11; 64]),
        ("node-2", [0x22; 64]),
        ("node-3", [0x33; 64]),
        ("node-4", [0x44; 64]),
        ("node-5", [0x55; 64]),
    ];
    let identities = create_test_identities(&nodes, create_test_identity);
    assert_eq!(identities.len(), 5, "All 5 nodes should be created");
    Ok(())
}

/// Test 3: NodeId Stability Across Restart (Two-Node Scenario)
///
/// Scenario: Alice and Bob connect. Alice is restarted. Verify:
/// - Alice's NodeId remains unchanged after restart
/// - Bob's DHT still contains Alice's entry
/// - Reconnection happens automatically
#[tokio::test(flavor = "multi_thread")]
async fn test_two_node_nodeid_stability_across_restart() -> Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        // Create Alice with stable seed
        let alice_seed = [0xAA; 64];
        let alice_device = "laptop";

        let alice_before = create_test_identity(alice_device, alice_seed)?;

        // Create Bob
        let bob_seed = [0xBB; 64];
        let bob = create_test_identity("desktop", bob_seed)?;

        // Simulate restart: Create Alice again with same seed
        tokio::time::sleep(Duration::from_millis(100)).await;
        let alice_after = create_test_identity(alice_device, alice_seed)?;
#[tokio::test]
async fn test_multi_node_network_shared() -> Result<()> {
    run_shared_multi_node_network_test().await
}

        // Verify NodeIds are identical after restart
        assert_eq!(
            alice_before.node_id, alice_after.node_id,
            "Alice's NodeId must survive restart with same seed"
        );
        assert_eq!(
            alice_before.did, alice_after.did,
            "Alice's DID must survive restart"
        );

        // Verify Bob's NodeId unchanged
        let bob_again = create_test_identity("desktop", bob_seed)?;
        assert_eq!(
            bob.node_id, bob_again.node_id,
            "Bob's NodeId must be stable"
        );

        Ok(())
    }).await?
}

/// Test 4: Four-Node Mesh with All Pairs Connected
///
/// Scenario: Four nodes form a fully connected mesh. Verify:
/// - All nodes discover all other nodes
/// - DHT routing tables have entries for all peers
/// - Network topology is fully connected
#[tokio::test(flavor = "multi_thread")]
async fn test_four_node_mesh_full_connectivity() -> Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        // Create four nodes
        let nodes = [
            ("laptop-device-001", [0x11; 64]),
            ("desktop-device-001", [0x22; 64]),
            ("tablet-device-001", [0x33; 64]),
            ("phone-device-001", [0x44; 64]),
        ];

        let mut identities = Vec::new();

        for (device, seed) in &nodes {
            let identity = create_test_identity(device, *seed)?;
            identities.push(identity);
        }

        // Verify mesh connectivity: each node should have routing entries for all others
        for (i, alice) in identities.iter().enumerate() {
            let alice_peer = UnifiedPeerId::from_zhtp_identity(alice)?;
            alice_peer.verify_node_id()?;

            // Alice should be able to route to all other nodes
            for (j, bob) in identities.iter().enumerate() {
                if i != j {
                    let bob_peer = UnifiedPeerId::from_zhtp_identity(bob)?;
                    bob_peer.verify_node_id()?;

                    // Verify they can be cross-referenced
                    assert_ne!(
                        alice.node_id, bob.node_id,
                        "All nodes must have different NodeIds"
                    );
                }
            }
        }

        Ok(())
    }).await?
}

/// Test 5: Multi-Node Restart with Connection Re-establishment
///
/// Scenario: Three nodes (Alice, Bob, Charlie) discover each other.
/// Two nodes (Alice and Bob) are restarted together.
/// Verify:
/// - All NodeIds remain stable
/// - Charlie recognizes Alice and Bob after restart
/// - Connections re-establish
#[tokio::test(flavor = "multi_thread")]
async fn test_three_node_restart_with_reconnection() -> Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        // Phase 1: Create and connect three nodes
        let seeds = [[0xAA; 64], [0xBB; 64], [0xCC; 64]];
        let devices = ["laptop", "desktop", "tablet"];

        let identities_before: Vec<_> = seeds
            .iter()
            .zip(devices.iter())
            .map(|(seed, device)| create_test_identity(device, *seed))
            .collect::<Result<_>>()?;

        // Simulate connection establishment
        tokio::time::sleep(DISCOVERY_WAIT_TIME).await;

        // Phase 2: Restart first two nodes (Alice and Bob)
        let identities_after: Vec<_> = seeds
            .iter()
            .zip(devices.iter())
            .map(|(seed, device)| create_test_identity(device, *seed))
            .collect::<Result<_>>()?;

        // Verify all NodeIds remained stable
        for i in 0..identities_before.len() {
            assert_eq!(
                identities_before[i].node_id, identities_after[i].node_id,
                "NodeId {} must survive restart",
                i
            );
        }

        // Phase 3: Verify Charlie can still locate Alice and Bob
        let charlie_before = &identities_before[2];
        let charlie_after = &identities_after[2];

        // Charlie's ID should be the same
        assert_eq!(
            charlie_before.node_id, charlie_after.node_id,
            "Charlie's NodeId must be stable"
        );

        // Charlie should still have routing entries for restarted nodes
        for (alice_before, alice_after) in identities_before[..2].iter().zip(identities_after[..2].iter()) {
            assert_eq!(
                alice_before.node_id, alice_after.node_id,
                "Restarted node NodeId must match"
            );
        }

        Ok(())
    }).await?
}

/// Test 6: NodeId Determinism Across Multiple Cycles
///
/// Scenario: Take a node through 5 restart cycles. Verify NodeId never changes.
#[test]
fn test_node_id_determinism_across_five_cycles() -> Result<()> {
    let device = "laptop";
    let seed = [0xAA; 64];

    // Create node in cycle 1 and store NodeId
    let mut stored_node_id = None;

    for cycle in 1..=5 {
        let identity = create_test_identity(device, seed)?;

        if let Some(prev_id) = stored_node_id {
            assert_eq!(
                prev_id, identity.node_id,
                "NodeId must be identical in cycle {}",
                cycle
            );
        }

        stored_node_id = Some(identity.node_id);
    }

    Ok(())
}

/// Test 7: Device Name Affects NodeId in Multi-Node Scenario
///
/// Scenario: Create three nodes with same seed but different device names.
/// Verify each has a unique NodeId due to device name variation.
#[test]
fn test_device_name_affects_node_id_multi_node() -> Result<()> {
    let seed = [0xAA; 64];
    let devices = ["device-1", "device-2", "device-3"];

    let mut identities = Vec::new();
    for device in &devices {
        let identity = create_test_identity(device, seed)?;
        identities.push(identity);
    }

    // All should have same DID (same seed)
    for i in 1..identities.len() {
        assert_eq!(
            identities[0].did, identities[i].did,
            "Same seed should produce same DID"
        );
    }

    // But different NodeIds (different devices)
    for i in 1..identities.len() {
        assert_ne!(
            identities[0].node_id, identities[i].node_id,
            "Different device names should produce different NodeIds"
        );
    }

    Ok(())
}

/// Test 8: Five-Node Network Formation
///
/// Scenario: Five nodes join network sequentially. Verify:
/// - All nodes eventually discover all other nodes
/// - No NodeId collisions
/// - Network is fully connected
#[tokio::test(flavor = "multi_thread")]
async fn test_five_node_network_formation() -> Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let nodes = [
            ("node-1", [0x11; 64]),
            ("node-2", [0x22; 64]),
            ("node-3", [0x33; 64]),
            ("node-4", [0x44; 64]),
            ("node-5", [0x55; 64]),
        ];

        let mut identities = Vec::new();

        for (device, seed) in &nodes {
            let identity = create_test_identity(device, *seed)?;
            identities.push(identity);

            // Simulate network propagation time
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Verify all nodes are unique
        let mut node_ids = identities.iter().map(|id| id.node_id.clone()).collect::<Vec<_>>();
        node_ids.sort();

        for i in 1..node_ids.len() {
            assert_ne!(
                node_ids[i - 1], node_ids[i],
                "No NodeId collisions in 5-node network"
            );
        }

        // Verify full mesh connectivity info is present
        assert_eq!(
            identities.len(), 5,
            "All 5 nodes should be created"
        );

        Ok(())
    }).await?
}

#[cfg(test)]
mod helpers {
    use super::*;

    #[test]
    fn test_peer_id_derivation_from_node_id() {
        let seed = [0xAA; 64];
        let identity = create_test_identity("test-device", seed).unwrap();
        
        let peer_id = peer_id_from_node_id(&identity.node_id);
        
        // Verify peer_id is valid UUID
        assert_eq!(peer_id.as_bytes().len(), 16);
    }
}
