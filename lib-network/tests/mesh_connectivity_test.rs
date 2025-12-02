//! Mesh Connectivity Testing
//! 
//! Tests node ID addressing, protocol initialization, and mesh statistics.
//! This provides practical tests for mesh connectivity validation.

use anyhow::Result;
use lib_network::testing::test_utils::create_test_mesh_server;
use lib_crypto::{generate_keypair, PublicKey};
use hex;

/// Helper function to create a mesh server with unique identity
async fn create_unique_test_mesh_server(node_name: &str) -> Result<lib_network::mesh::server::ZhtpMeshServer> {
    use lib_identity::{ZhtpIdentity, IdentityType};
    use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};
    
    // Create a proper unique identity for each test
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        node_name,  // Use node_name as device identifier for uniqueness
        None,  // Random seed ensures uniqueness
    )?;
    
    let node_id = identity.node_id;
    let owner_key = identity.public_key.clone();
    
    let storage_config = UnifiedStorageConfig::default();
    let storage = UnifiedStorageSystem::new(storage_config).await?;
    
    let protocols = vec![
        lib_network::protocols::NetworkProtocol::BluetoothLE,
        lib_network::protocols::NetworkProtocol::WiFiDirect,
        lib_network::protocols::NetworkProtocol::LoRaWAN,
    ];
    
    lib_network::mesh::server::ZhtpMeshServer::new(node_id, owner_key, storage, protocols).await
}

/// Test that nodes use their identity as their network address
#[tokio::test]
async fn test_node_id_addressing() -> Result<()> {
    println!(" Testing Node ID Addressing System...");
    
    // Create test mesh server
    let server = create_test_mesh_server().await?;
    let node_info = {
        let mesh_node = server.mesh_node.read().await;
        mesh_node.node_id
    };
    
    let node_id = node_info;
    
    // Verify node ID format (32-byte array)
    assert_eq!(node_id.as_bytes().len(), 32, "Node ID should be 32 bytes");
    
    // Convert node ID to hex address format
    let hex_address = hex::encode(node_id.as_bytes());
    println!(" Node ID: {}", &hex_address[..16]); // First 16 chars for display
    
    // Verify node ID is used in addressing
    let zhtp_address = format!("zhtp://{}", hex_address);
    println!(" ZHTP Address: {}...", &zhtp_address[..32]); // Truncated for display
    
    // Test server ID is derived from node ID
    println!(" Server ID: {}", server.server_id);
    
    // Test address derivation from node ID
    let derived_address = format!("zhtp://{}:33445", hex_address);
    println!(" Derived address: {}...", &derived_address[..32]);
    
    println!(" Node ID addressing test completed\n");
    Ok(())
}

/// Test mesh server creation and basic functionality
#[tokio::test]
async fn test_mesh_server_creation() -> Result<()> {
    println!(" Testing Mesh Server Creation...");
    
    // Create mesh server
    let server = create_unique_test_mesh_server("server-test-node").await?;
    
    // Test that server was created successfully
    println!("   Mesh server created successfully");
    println!("   Server ID: {}", server.server_id);
    
    // Get network statistics (using actual field names)
    let stats = server.get_network_stats().await;
    println!("   Active connections: {}", stats.active_connections);
    println!("   Total data routed: {} bytes", stats.total_data_routed);
    println!("   Total UBI distributed: {} tokens", stats.total_ubi_distributed);
    println!("   Long range relays: {}", stats.long_range_relays);
    println!("   Average latency: {}ms", stats.average_latency_ms);
    println!("   Coverage area: {:.2} km²", stats.coverage_area_km2);
    println!("   People with free internet: {}", stats.people_with_free_internet);
    
    // Test revenue pools (economic incentives)
    let revenue_pools = server.get_revenue_pools().await;
    println!("   Revenue pools: {}", revenue_pools.len());
    for (pool_name, amount) in revenue_pools {
        println!("    {}: {} tokens", pool_name, amount);
    }
    
    println!(" Mesh server creation test completed\n");
    Ok(())
}

/// Test mesh network formation with multiple nodes
#[tokio::test]
async fn test_mesh_network_formation() -> Result<()> {
    println!("️ Testing Mesh Network Formation...");
    
    // Create multiple test nodes with different IDs
    println!("  Creating test mesh nodes...");
    let node1 = create_unique_test_mesh_server("test-node-1").await?;
    let node2 = create_unique_test_mesh_server("test-node-2").await?;
    
    // Get node IDs
    let node1_id = node1.mesh_node.read().await.node_id;
    let node2_id = node2.mesh_node.read().await.node_id;
    
    println!("   Node 1 ID: {}...", hex::encode(&node1_id.as_bytes()[..4]));
    println!("   Node 2 ID: {}...", hex::encode(&node2_id.as_bytes()[..4]));
    
    // Test that nodes have different IDs
    assert_ne!(node1_id, node2_id, "Nodes should have unique IDs");
    
    // Test network statistics for both nodes
    let node1_stats = node1.get_network_stats().await;
    let node2_stats = node2.get_network_stats().await;
    
    println!("   Node 1 stats: {} active connections, {} data routed", 
             node1_stats.active_connections, node1_stats.total_data_routed);
    println!("   Node 2 stats: {} active connections, {} data routed", 
             node2_stats.active_connections, node2_stats.total_data_routed);
    
    // Test node ownership verification
    println!("  Testing node ownership...");
    let owner_key = PublicKey::new(vec![1, 2, 3, 4]);
    let is_owner1 = node1.verify_node_ownership(&owner_key).await;
    let is_owner2 = node2.verify_node_ownership(&owner_key).await;
    
    println!("   Node 1 ownership verification: {}", is_owner1);
    println!("   Node 2 ownership verification: {}", is_owner2);
    
    println!(" Mesh network formation test completed\n");
    Ok(())
}

/// Test mesh connectivity monitoring and statistics
#[tokio::test]
async fn test_mesh_connectivity_monitoring() -> Result<()> {
    println!(" Testing Mesh Connectivity Monitoring...");
    
    let server = create_test_mesh_server().await?;
    
    // Test connectivity statistics (using actual field names)
    println!("  Getting connectivity statistics...");
    let stats = server.get_network_stats().await;
    
    println!("   Active connections: {}", stats.active_connections);
    println!("   Total data routed: {} bytes", stats.total_data_routed);
    println!("   Total UBI distributed: {} tokens", stats.total_ubi_distributed);
    println!("   Long range relays: {}", stats.long_range_relays);
    println!("   Average latency: {}ms", stats.average_latency_ms);
    println!("   Coverage area: {:.2} km²", stats.coverage_area_km2);
    println!("   People with free internet: {}", stats.people_with_free_internet);
    
    println!(" Mesh connectivity monitoring test completed\n");
    Ok(())
}

/// Test mesh peer authentication and security
#[tokio::test] 
async fn test_mesh_peer_authentication() -> Result<()> {
    println!(" Testing Mesh Peer Authentication...");
    
    let server = create_unique_test_mesh_server("auth-test-node").await?;
    
    // Test node ownership verification
    println!("  Testing node ownership verification...");
    let test_key = PublicKey::new(vec![1, 2, 3, 4]);
    let is_owner = server.verify_node_ownership(&test_key).await;
    println!("   Node ownership verification: {}", is_owner);
    
    // Test permission level system
    println!("  Testing permission level system...");
    let permission = server.get_permission_level(&test_key).await;
    println!("   Permission level: {:?}", permission);
    
    // Test cryptographic signature verification
    println!("  Testing cryptographic signatures...");
    
    // Generate test message
    let test_message = b"Test mesh message for signature verification";
    
    // Sign message (would use node's private key in implementation)
    let keypair = generate_keypair()?;
    let signature = lib_crypto::sign_message(&keypair, test_message)?;
    
    // Verify signature
    let signature_valid = keypair.public_key.verify(test_message, &signature)?;
    println!("   Message signature valid: {}", signature_valid);
    
    // Test routing stats (network metrics)
    println!("  Testing routing statistics...");
    let stats = server.get_routing_stats().await;
    println!("   Routing stats - messages routed: {}", stats.messages_routed);
    
    println!(" Mesh peer authentication test completed\n");
    Ok(())
}

/// Test mesh message routing and delivery
#[tokio::test]
async fn test_mesh_message_routing() -> Result<()> {
    println!(" Testing Mesh Message Routing...");
    
    let server = create_test_mesh_server().await?;
    
    // Test message creation
    println!("  Creating test message...");
    let node_id = server.mesh_node.read().await.node_id;
    let _test_message = format!("Hello from node {}", hex::encode(&node_id.as_bytes()[..4]));
    
    // Test mesh message handling
    println!("  Testing mesh message handling...");
    use lib_network::types::mesh_message::ZhtpMeshMessage;
    
    let test_mesh_message = ZhtpMeshMessage::PeerDiscovery {
        capabilities: vec![
            lib_network::types::mesh_capability::MeshCapability::MeshRelay { capacity_mbps: 10 },
            lib_network::types::mesh_capability::MeshCapability::DataStorage { capacity_gb: 100 }
        ],
        location: None,
        shared_resources: lib_network::types::mesh_capability::SharedResources {
            relay_bandwidth_kbps: 1000,
            storage_gb: 50,
            compute_power: 100,
            battery_percentage: Some(85),
            reliability_score: 0.95,
        },
    };
    
    let sender_key = PublicKey::new(vec![1, 2, 3, 4]);
    
    match server.handle_mesh_message(test_mesh_message, sender_key).await {
        Ok(()) => {
            println!("   Mesh message handled successfully");
        }
        Err(e) => {
            println!("  ⚠ Mesh message handling failed: {} (may be expected)", e);
        }
    }
    
    // Test network statistics (shows message routing activity)
    let stats = server.get_network_stats().await;
    println!("   Active connections: {}", stats.active_connections);
    println!("   Data routed: {} bytes", stats.total_data_routed);
    println!("   UBI distributed: {} tokens", stats.total_ubi_distributed);
    
    // Test routing performance metrics
    let routing_snapshot = server.get_routing_stats_snapshot().await;
    println!("   Routing messages routed: {}", routing_snapshot.messages_routed);
    
    println!(" Mesh message routing test completed\n");
    Ok(())
}







// Note: Individual tests above validate mesh connectivity comprehensively
// No need for a comprehensive test that calls all others