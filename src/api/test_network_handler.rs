// Simple test for NetworkHandler without complex routing
use std::sync::Arc;
use lib_protocols::types::{ZhtpRequest, ZhtpMethod, ZhtpHeaders};
use lib_protocols::zhtp::ZhtpRequestHandler;
use crate::api::handlers::network::NetworkHandler;
use crate::runtime::RuntimeOrchestrator;
use crate::config::NodeConfig;

pub async fn test_network_apis() -> anyhow::Result<()> {
    println!(" Testing Network APIs directly...");
    
    // Create runtime and network handler
    let runtime = Arc::new(RuntimeOrchestrator::new(NodeConfig::default()).await?);
    let network_handler = NetworkHandler::new(runtime);
    
    // Test GET /api/v1/blockchain/network/peers
    let peers_request = ZhtpRequest {
        method: ZhtpMethod::Get,
        uri: "/api/v1/blockchain/network/peers".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: vec![],
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        requester: None,
    };
    
    let response = network_handler.handle_request(peers_request).await?;
    println!("GET /api/v1/blockchain/network/peers: {:?}", response.status);
    
    // Test GET /api/v1/blockchain/network/stats
    let stats_request = ZhtpRequest {
        method: ZhtpMethod::Get,
        uri: "/api/v1/blockchain/network/stats".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: vec![],
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        requester: None,
    };
    
    let response = network_handler.handle_request(stats_request).await?;
    println!("GET /api/v1/blockchain/network/stats: {:?}", response.status);
    
    // Test POST /api/v1/blockchain/network/peer/add
    let add_peer_body = serde_json::json!({
        "peer_id": "test_peer_001",
        "address": "127.0.0.1:8001"
    });
    
    let add_request = ZhtpRequest {
        method: ZhtpMethod::Post,
        uri: "/api/v1/blockchain/network/peer/add".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: add_peer_body.to_string().into_bytes(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        requester: None,
    };
    
    let response = network_handler.handle_request(add_request).await?;
    println!("POST /api/v1/blockchain/network/peer/add: {:?}", response.status);
    
    // Test DELETE /api/v1/blockchain/network/peer/test_peer_001
    let delete_request = ZhtpRequest {
        method: ZhtpMethod::Delete,
        uri: "/api/v1/blockchain/network/peer/test_peer_001".to_string(),
        version: "ZHTP/1.0".to_string(),
        headers: ZhtpHeaders::new(),
        body: vec![],
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        requester: None,
    };
    
    let response = network_handler.handle_request(delete_request).await?;
    println!("DELETE /api/v1/blockchain/network/peer/test_peer_001: {:?}", response.status);
    
    println!(" All network API tests completed!");
    Ok(())
}