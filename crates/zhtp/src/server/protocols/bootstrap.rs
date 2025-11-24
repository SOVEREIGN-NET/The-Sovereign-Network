//! Bootstrap Protocol Router
//!
//! Extracted from unified_server.rs (lines 5894-5969)
//! 
//! Handles network bootstrap discovery with:
//! - TCP bootstrap handshakes
//! - UDP service discovery
//! - Server capability announcement
//! - Endpoint advertisement

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;
use tracing::{debug, error, info};

/// Network bootstrap handling for service discovery
#[derive(Debug)]
pub struct BootstrapRouter {
    server_id: Uuid,
}

impl BootstrapRouter {
    pub fn new(server_id: Uuid) -> Self {
        Self { server_id }
    }
    
    /// Handle TCP bootstrap connection
    pub async fn handle_tcp_bootstrap(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("🚀 Processing TCP bootstrap connection from: {}", addr);
        
        let mut buffer = vec![0; 1024];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read bootstrap request")?;
        
        if bytes_read > 0 {
            debug!("Bootstrap request: {} bytes", bytes_read);
            
            // Send bootstrap response
            let response = format!("ZHTP Bootstrap Response\nServer ID: {}\n", self.server_id);
            let _ = stream.write_all(response.as_bytes()).await;
        }
        
        Ok(())
    }
    
    /// Handle UDP bootstrap discovery with capability announcement
    pub async fn handle_udp_bootstrap(
        &self, 
        data: &[u8], 
        addr: SocketAddr, 
        http_port: u16, 
        zhtp_port: u16, 
        socket: &UdpSocket
    ) -> Result<Vec<u8>> {
        info!("🚀 Processing UDP bootstrap packet from: {} ({} bytes)", addr, data.len());
        
        // Parse bootstrap request and send response
        let request_str = String::from_utf8_lossy(data);
        debug!("Bootstrap request content: {}", request_str);
        
        // Check if this is a bootstrap RESPONSE (not a request) - don't respond to responses!
        if request_str.contains("\"server_id\"") && request_str.contains("\"capabilities\"") {
            debug!("Received bootstrap response from {} - not responding to avoid loop", addr);
            return Ok(vec![]); // Return empty response to indicate no action needed
        }
        
        // Create bootstrap response with server capabilities
        let response_data = serde_json::json!({
            "server_id": self.server_id,
            "server_type": "zhtp_unified",
            "protocol_version": "ZHTP/1.0",
            "capabilities": [
                "blockchain_api",
                "storage_api", 
                "identity_api",
                "mesh_networking",
                "wifi_direct",
                "dht_operations"
            ],
            "endpoints": {
                "http": format!("http://localhost:{}", http_port),
                "zhtp": format!("zhtp://localhost:{}", zhtp_port),
                "websocket": format!("ws://localhost:{}/ws", http_port)
            },
            "network_info": {
                "node_type": "full_node",
                "uptime": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                "peers_connected": 0
            },
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
        });
        
        // Convert to bytes for UDP transmission
        let response_bytes = serde_json::to_vec(&response_data)
            .context("Failed to serialize bootstrap response")?;
        
        // Send the actual UDP response back to the client
        match socket.send_to(&response_bytes, addr).await {
            Ok(sent_bytes) => {
                info!("✅ Sent UDP bootstrap response to {} ({} bytes)", addr, sent_bytes);
                debug!("Bootstrap response: {}", response_data);
            }
            Err(e) => {
                error!("❌ Failed to send UDP bootstrap response to {}: {}", addr, e);
                return Err(anyhow::anyhow!("UDP send failed: {}", e));
            }
        }
        
        Ok(response_bytes)
    }
}

impl Clone for BootstrapRouter {
    fn clone(&self) -> Self {
        Self {
            server_id: self.server_id,
        }
    }
}
