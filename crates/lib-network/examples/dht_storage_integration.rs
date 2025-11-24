//! DHT Client Integration with lib-storage Backend
//! 
//! This example demonstrates how lib-network acts as a DHT client layer
//! that uses lib-storage as the DHT implementation backend, providing
//! the correct architectural separation between client and implementation.

use anyhow::Result;
use lib_network::{initialize_dht_client, serve_web4_page_through_mesh, DHTClient};
use lib_identity::{ZhtpIdentity, IdentityId, types::{IdentityType, AccessLevel}, wallets::WalletManager};
use lib_proofs::ZeroKnowledgeProof;
use std::collections::HashMap;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!(" Starting DHT Client + Storage Backend Integration Demo");
    
    // Create a test identity for DHT operations
    let identity = create_demo_identity();
    
    // Initialize DHT client with lib-storage backend
    info!("Initializing DHT client with lib-storage backend...");
    let mut dht_client = initialize_dht_client(identity.clone()).await?;
    
    // Demonstrate DHT operations through storage backend
    demo_dht_operations(&mut dht_client).await?;
    
    // Demonstrate Web4 page serving
    demo_web4_serving(&mut dht_client).await?;
    
    // Demonstrate storage integration
    demo_storage_integration(&mut dht_client).await?;
    
    // Show statistics
    demo_statistics(&mut dht_client).await?;
    
    info!("DHT Client + Storage Backend Integration Demo completed successfully!");
    Ok(())
}

/// Demonstrate basic DHT operations through storage backend
async fn demo_dht_operations(dht_client: &mut DHTClient) -> Result<()> {
    info!("=== DHT Operations Demo ===");
    
    // Store some content
    let domain = "example.zhtp";
    let path = "/homepage";
    let content = b"<h1>Welcome to ZHTP Web4</h1><p>This content is stored in the DHT through lib-storage!</p>";
    
    info!(" Storing content for {}{}...", domain, path);
    let content_hash = dht_client.store_content(domain, path, content.to_vec()).await?;
    info!("Content stored with hash: {}", content_hash);
    
    // Resolve the same content
    info!("Resolving content for {}{}...", domain, path);
    let resolved_hash = dht_client.resolve_content(domain, path).await?;
    info!("Content resolved to hash: {}", resolved_hash);
    
    // Fetch the content
    info!("Fetching content with hash: {}", resolved_hash);
    let fetched_content = dht_client.fetch_content(&resolved_hash).await?;
    let content_str = String::from_utf8_lossy(&fetched_content);
    info!("Fetched content: {}", content_str);
    
    // Verify it matches
    if fetched_content == content {
        info!("Content verification successful - DHT storage working correctly!");
    } else {
        warn!("Content mismatch - verification failed");
    }
    
    Ok(())
}

/// Demonstrate Web4 page serving through DHT + storage
async fn demo_web4_serving(dht_client: &mut DHTClient) -> Result<()> {
    info!("=== Web4 Page Serving Demo ===");
    
    // First, store a Web4 page
    let domain = "webapp.zhtp";
    let path = "/";
    let web4_content = r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZHTP Web4 Demo</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f0f8ff; }
            .zhtp-header { color: #2E86AB; border-bottom: 2px solid #A23B72; padding-bottom: 10px; }
            .content { background: white; padding: 20px; border-radius: 8px; margin-top: 20px; }
            .feature { margin: 10px 0; padding: 10px; background: #f9f9f9; border-left: 4px solid #F18F01; }
        </style>
    </head>
    <body>
        <h1 class="zhtp-header">ZHTP Web4 Application</h1>
        <div class="content">
            <h2>Internet Replacement</h2>
            <p>This page is served through the ZHTP mesh network using:</p>
            <div class="feature">
                <strong>lib-network:</strong> DHT client layer for mesh networking
            </div>
            <div class="feature">
                <strong> lib-storage:</strong> DHT implementation backend with economic incentives
            </div>
            <div class="feature">
                <strong>lib-crypto:</strong> Post-quantum cryptographic security
            </div>
            <div class="feature">
                <strong>lib-identity:</strong> Zero-knowledge identity management
            </div>
            <p><em>No ISPs required - pure mesh networking!</em></p>
        </div>
    </body>
    </html>
    "#;
    
    info!(" Storing Web4 page at {}{}...", domain, path);
    let page_hash = dht_client.store_content(domain, path, web4_content.as_bytes().to_vec()).await?;
    info!("Web4 page stored with hash: {}", page_hash);
    
    // Serve the Web4 page
    let zhtp_url = format!("zhtp://{}{}", domain, path);
    info!("Serving Web4 page: {}", zhtp_url);
    
    let page_response = serve_web4_page_through_mesh(dht_client, &zhtp_url).await?;
    
    // Display the response
    info!("Web4 page response:");
    println!("{}", serde_json::to_string_pretty(&page_response)?);
    
    Ok(())
}

/// Demonstrate storage backend integration
async fn demo_storage_integration(dht_client: &mut DHTClient) -> Result<()> {
    info!(" === Storage Backend Integration Demo ===");
    
    // Access the underlying storage system
    let storage_system = dht_client.get_storage_system();
    let node_info = {
        let storage_system = storage_system.clone();
        let storage = storage_system.read().await;
        storage.get_node_info().clone()
    };
    
    info!("Storage Node Information:");
    info!("  Node ID: {}", hex::encode(&node_info.id));
    info!("  Addresses: {:?}", node_info.addresses);
    info!("  Reputation: {}", node_info.reputation);
    
    if let Some(storage_info) = &node_info.storage_info {
        info!("  Available Space: {} bytes", storage_info.available_space);
        info!("  Total Capacity: {} bytes", storage_info.total_capacity);
        info!("  Price per GB/day: {} tokens", storage_info.price_per_gb_day);
        info!("  Supported Tiers: {:?}", storage_info.supported_tiers);
        info!("  Uptime: {:.2}%", storage_info.uptime * 100.0);
    }
    
    // Get storage statistics
    let storage_stats = {
        let storage_system = dht_client.get_storage_system().clone();
        let mut storage = storage_system.write().await;
        storage.get_statistics().await?
    };
    info!(" Storage System Statistics:");
    info!("  DHT Nodes: {}", storage_stats.dht_stats.total_nodes);
    info!("  DHT Connections: {}", storage_stats.dht_stats.total_connections);
    info!("  Storage Used: {} bytes", storage_stats.storage_stats.total_storage_used);
    info!("  Total Content: {}", storage_stats.storage_stats.total_content_count);
    info!("  Economic Contracts: {}", storage_stats.economic_stats.total_contracts);
    info!("  Total Value Locked: {} tokens", storage_stats.economic_stats.total_value_locked);
    
    Ok(())
}

/// Demonstrate statistics and monitoring
async fn demo_statistics(dht_client: &mut DHTClient) -> Result<()> {
    info!("=== Statistics and Monitoring Demo ===");
    
    // Get DHT client statistics
    let dht_stats = dht_client.get_dht_statistics().await?;
    info!("DHT Client Statistics:");
    for (key, value) in &dht_stats {
        info!("  {}: {}", key, value);
    }
    
    // Get cache statistics
    let cache_stats = dht_client.get_cache_stats().await;
    info!(" Cache Statistics:");
    for (key, value) in &cache_stats {
        info!("  {}: {}", key, value);
    }
    
    // Get network status
    let network_status = dht_client.get_network_status().await?;
    info!("Network Status:");
    info!("  Connected: {}", network_status.connected);
    info!("  Peer Count: {}", network_status.peer_count);
    info!("  Cache Size: {}", network_status.cache_size);
    info!("  Storage Available: {} bytes", network_status.storage_available);
    
    Ok(())
}

/// Create a demo identity for testing
fn create_demo_identity() -> ZhtpIdentity {
    let identity_id = IdentityId::from_bytes(&[42u8; 32]);
    
    ZhtpIdentity {
        id: identity_id.clone(),
        identity_type: IdentityType::Human,
        public_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
        ownership_proof: ZeroKnowledgeProof {
            proof_system: "demo".to_string(),
            proof_data: vec![],
            public_inputs: vec![],
            verification_key: vec![],
            plonky2_proof: None,
            proof: vec![],
        },
        credentials: HashMap::new(),
        reputation: 100,
        age: Some(25),
        access_level: AccessLevel::FullCitizen,
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("demo".to_string(), "true".to_string());
            meta
        },
        private_data_id: None,
        wallet_manager: WalletManager::new(identity_id),
        did_document_hash: None,
        attestations: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        last_active: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        recovery_keys: vec![],
    }
}
