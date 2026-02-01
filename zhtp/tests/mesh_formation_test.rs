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

mod common_network_test;
use common_network_test::{
    create_test_identity_with_seed as create_test_identity,
    create_identities_from_nodes, create_mesh_topology_from_nodes,
    verify_mesh_fully_connected, verify_all_routing_paths,
    build_incremental_mesh_and_verify, simulate_stable_cycles_and_verify,
    MeshTopology,
};

use anyhow::Result;


#[test]
fn test_mesh_scenarios() -> Result<()> {
    use common_network_test::MeshTestScenario::*;
    let scenarios = [
        FiveNodeMesh,
        NodeDepartureAndRejoin,
        RandomRestarts,
        RoutingVerification,
        ConvergenceTimeline,
        PartitionRecovery,
        StabilityMetrics,
    ];
    for scenario in scenarios.iter() {
        common_network_test::run_mesh_scenario(scenario.clone())?;
    }
    Ok(())
}
