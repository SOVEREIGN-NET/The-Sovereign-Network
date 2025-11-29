//! WiFi Direct Protocol Router
//!
//! Extracted from unified_server.rs (lines 4985-5157)
//! 
//! Handles WiFi Direct P2P mesh connections with:
//! - mDNS/Bonjour service discovery
//! - Group Owner negotiation
//! - Direct device-to-device connectivity
//! - WPA2/WPA3 security

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use std::net::SocketAddr;
use uuid::Uuid;
use tracing::{debug, info, warn};
use lib_network::protocols::wifi_direct::WiFiDirectMeshProtocol;

/// WiFi Direct device connections
/// WiFi Direct handling with basic group owner detection
pub struct WiFiRouter {
    connected_devices: Arc<RwLock<HashMap<String, String>>>,
    node_id: [u8; 32],
    protocol: Arc<RwLock<Option<WiFiDirectMeshProtocol>>>,
    initialized: Arc<RwLock<bool>>, // Track if already initialized to prevent re-creating protocol
    peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
}

impl WiFiRouter {
    pub fn new() -> Self {
        Self::new_with_peer_notification(None)
    }
    
    pub fn new_with_peer_notification(
        peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>
    ) -> Self {
        let node_id = {
            let mut id = [0u8; 32];
            let uuid = Uuid::new_v4();
            let uuid_bytes = uuid.as_bytes();
            id[..16].copy_from_slice(uuid_bytes);
            id[16..].copy_from_slice(uuid_bytes); // Fill remaining with same UUID
            id
        };
        
        Self {
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            node_id,
            protocol: Arc::new(RwLock::new(None)),
            initialized: Arc::new(RwLock::new(false)),
            peer_discovery_tx,
        }
    }
    
    /// Initialize WiFi Direct with mDNS service discovery
    pub async fn initialize(&self) -> Result<()> {
        // Check if already initialized - prevent re-creating protocol and losing discovered peers
        {
            let already_initialized = *self.initialized.read().await;
            if already_initialized {
                debug!("WiFi Direct already initialized, skipping re-initialization");
                return Ok(());
            }
        }
        
        info!("🌐 Initializing WiFi Direct P2P + mDNS service discovery...");
        info!("   Node ID: {:?}", hex::encode(&self.node_id[..8]));
        
        // Create WiFi Direct mesh protocol instance with peer discovery notification
        match WiFiDirectMeshProtocol::new_with_peer_notification(self.node_id, self.peer_discovery_tx.clone()) {
            Ok(mut wifi_protocol) => {
                info!("✅ WiFi Direct protocol created successfully");
                
                // Start enhanced service discovery (mDNS + P2P)
                // Note: WiFi Direct starts disabled by default for security
                match wifi_protocol.start_discovery().await {
                    Ok(_) => {
                        info!("✅ WiFi Direct P2P discovery started");
                        info!("📡 mDNS service advertising on _zhtp._tcp.local");
                        
                        // Store the initialized protocol
                        *self.protocol.write().await = Some(wifi_protocol);
                        
                        // Mark as initialized to prevent re-initialization
                        *self.initialized.write().await = true;
                        
                        info!("✅ WiFi Direct mesh fully initialized:");
                        info!("   ✓ P2P device discovery active");
                        info!("   ✓ mDNS/Bonjour service advertising");
                        info!("   ✓ Direct device-to-device connections enabled");
                        
                        Ok(())
                    }
                    Err(e) => {
                        // Check if error is due to WiFi Direct being disabled (security default)
                        if e.to_string().contains("disabled") {
                            info!("🔒 WiFi Direct protocol ready but DISABLED (security default)");
                            info!("   Use /api/v1/protocols/wifi-direct/enable to activate");
                            
                            // Store the protocol anyway so it can be enabled later via API
                            *self.protocol.write().await = Some(wifi_protocol);
                            *self.initialized.write().await = true;
                            
                            Ok(())
                        } else {
                            warn!("⚠️  WiFi Direct discovery failed: {}", e);
                            warn!("   This is normal if:");
                            warn!("   - WiFi adapter doesn't support P2P mode");
                            warn!("   - Running without administrator privileges");
                            warn!("   - Driver doesn't expose WiFi Direct capabilities");
                            warn!("   Falling back to multicast + Bluetooth discovery");
                            Err(e)
                        }
                    }
                }
            }
            Err(e) => {
                warn!("⚠️  Failed to create WiFi Direct protocol: {}", e);
                warn!("   WiFi Direct P2P not available on this system");
                warn!("   Using multicast UDP + Bluetooth for peer discovery");
                Err(e)
            }
        }
    }
    
    /// Check if this device is currently a group owner
    pub async fn is_group_owner(&self) -> bool {
        // Simulate group owner detection based on network configuration
        // In a real implementation, this would check WiFi Direct interface status
        debug!("Checking WiFi Direct group owner status");
        
        // For demonstration, alternate based on node_id to simulate detection
        let is_owner = (self.node_id[0] % 2) == 0;
        debug!("WiFi Direct group owner status: {} (simulated based on node_id)", is_owner);
        is_owner
    }
    
    /// Handle incoming WiFi Direct TCP connection
    pub async fn handle_wifi_direct(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("Processing WiFi Direct connection from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read WiFi Direct data")?;
        
        if bytes_read > 0 {
            debug!("WiFi Direct data: {} bytes", bytes_read);
            
            let is_owner = self.is_group_owner().await;
            let device_role = if is_owner { "Group Owner" } else { "Client" };
            
            info!("WiFi Direct role: {} for connection from {}", device_role, addr);
            
            // Send role-aware acknowledgment
            let response = format!(
                "ZHTP/1.0 200 OK\r\nX-WiFi-Role: {}\r\nX-Node-ID: {:?}\r\n\r\nWiFi Direct connection established as {}",
                device_role, &self.node_id[..8], device_role
            );
            
            let _ = stream.write_all(response.as_bytes()).await;
            
            // Store connection info
            let mut devices = self.connected_devices.write().await;
            devices.insert(addr.to_string(), device_role.to_string());
            
            info!("WiFi Direct connection established with {} as {}", addr, device_role);
        }
        
        Ok(())
    }
    
    /// Get a read guard for the WiFi protocol
    pub async fn get_protocol(&self) -> tokio::sync::RwLockReadGuard<'_, Option<WiFiDirectMeshProtocol>> {
        self.protocol.read().await
    }
}

impl Clone for WiFiRouter {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id,
            connected_devices: self.connected_devices.clone(),
            protocol: self.protocol.clone(),
            initialized: self.initialized.clone(),
            peer_discovery_tx: self.peer_discovery_tx.clone(),
        }
    }
}
