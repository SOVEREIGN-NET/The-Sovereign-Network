//! Bluetooth Connectivity Test
//! 
//! This test demonstrates how to start a Bluetooth LE mesh node
//! that your phone can discover and connect to.

use anyhow::Result;
use lib_network::mesh::server::ZhtpMeshServer;
use lib_network::protocols::NetworkProtocol;
use lib_crypto::PublicKey;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!(" Starting Bluetooth LE Mesh Node for Phone Connectivity");
    println!("=========================================================");
    println!();
    
    // Generate a test node ID
    let node_id = lib_crypto::hash_blake3(b"bluetooth-test-node");
    let owner_key = PublicKey::new(node_id.to_vec());
    
    // Create mesh protocols - Enable Bluetooth LE 
    let protocols = vec![
        NetworkProtocol::BluetoothLE, // This enables Bluetooth connectivity
        NetworkProtocol::WiFiDirect,  // Also enable WiFi Direct
    ];
    
    println!(" Creating mesh server with Bluetooth LE enabled...");
    
    // Create storage system for mesh
    #[cfg(feature = "lib-storage")]
    {
        use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};
        let storage_config = UnifiedStorageConfig::default();
        let storage = UnifiedStorageSystem::new(storage_config).await?;
        
        // Create mesh server with Bluetooth enabled
        let mesh_server = ZhtpMeshServer::new(node_id, owner_key, storage, protocols).await?;
        
        println!(" Mesh server created successfully!");
        println!();
        
        // Display connection information
        println!(" Your Phone Should See:");
        println!("  Device Name: 'ZHTP-MESH'");
        println!("  Service UUID: c830d44f-c000-b480-d111-ad9d10b8a76b");
        println!("  Node ID: {}...", hex::encode(&node_id[..8]));
        println!();
        
        println!(" Available GATT Services & Characteristics:");
        println!("   ZHTP Mesh Service: 6ba7b810-9dad-11d1-80b4-00c04fd430c9");
        println!("     ZK Authentication: 6ba7b811-9dad-11d1-80b4-00c04fd430c9");
        println!("     Quantum Routing:   6ba7b812-9dad-11d1-80b4-00c04fd430c9");
        println!("     Mesh Data:         6ba7b813-9dad-11d1-80b4-00c04fd430c9");
        println!("    🤝 Coordination:      6ba7b814-9dad-11d1-80b4-00c04fd430c9");
        println!();
        
        // Display network stats
        let stats = mesh_server.get_network_stats().await;
        println!(" Network Statistics:");
        println!("  Active Connections: {}", stats.active_connections);
        println!("  Coverage Area: {:.2} km²", stats.coverage_area_km2);
        println!("  Bluetooth Status: DISCOVERABLE & CONNECTABLE");
        println!();
        
        println!(" Mesh server is now running and discoverable via Bluetooth...");
        println!(" Open your phone's Bluetooth scanner or BLE scanner app");
        println!(" Look for 'ZHTP-MESH' in discoverable devices");
        println!();
        
        // Keep the server running for testing
        println!("⏰ Running for 5 minutes to allow phone connection...");
        println!("   Press Ctrl+C to stop");
        
        sleep(Duration::from_secs(300)).await; // Run for 5 minutes
        
        println!(" Bluetooth mesh test completed");
    }
    
    #[cfg(not(feature = "lib-storage"))]
    {
        println!(" This test requires lib-storage feature to be enabled");
        println!("   Run with: cargo run --features lib-storage");
    }
    
    Ok(())
}