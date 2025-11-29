//! Test DHT API Endpoints
//! 
//! Simple test to verify the DHT HTTP API endpoints are working correctly

use serde_json::json;
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic test of DHT API endpoints
    println!(" Testing DHT API Endpoints");
    
    let client = reqwest::Client::new();
    let base_url = "http://127.0.0.1:9333";
    
    // Test 1: Initialize DHT
    println!("\n Testing DHT Initialize...");
    let init_response = client
        .post(format!("{}/api/v1/dht/initialize", base_url))
        .json(&json!({
            "identity": {
                "id": "test-dht-client",
                "public_key": "test-public-key"
            }
        }))
        .send()
        .await;
    
    match init_response {
        Ok(resp) => {
            println!(" DHT Initialize: Status {}", resp.status());
            if let Ok(body) = resp.text().await {
                println!("   Response: {}", body);
            }
        }
        Err(e) => println!(" DHT Initialize failed: {}", e)
    }
    
    // Test 2: Get DHT Status  
    println!("\n Testing DHT Status...");
    let status_response = client
        .get(format!("{}/api/v1/dht/status", base_url))
        .send()
        .await;
        
    match status_response {
        Ok(resp) => {
            println!(" DHT Status: Status {}", resp.status());
            if let Ok(body) = resp.text().await {
                println!("   Response: {}", body);
            }
        }
        Err(e) => println!(" DHT Status failed: {}", e)
    }
    
    // Test 3: Get DHT Statistics
    println!("\n Testing DHT Statistics...");
    let stats_response = client
        .get(format!("{}/api/v1/dht/statistics", base_url))
        .send()
        .await;
        
    match stats_response {
        Ok(resp) => {
            println!(" DHT Statistics: Status {}", resp.status());
            if let Ok(body) = resp.text().await {
                println!("   Response: {}", body);
            }
        }
        Err(e) => println!(" DHT Statistics failed: {}", e)
    }
    
    // Test 4: Discover Peers
    println!("\n Testing DHT Peer Discovery...");
    let peers_response = client
        .get(format!("{}/api/v1/dht/peers", base_url))
        .send()
        .await;
        
    match peers_response {
        Ok(resp) => {
            println!(" DHT Peers: Status {}", resp.status());
            if let Ok(body) = resp.text().await {
                println!("   Response: {}", body);
            }
        }
        Err(e) => println!(" DHT Peers failed: {}", e)
    }
    
    println!("\n DHT API Test Complete!");
    
    Ok(())
}