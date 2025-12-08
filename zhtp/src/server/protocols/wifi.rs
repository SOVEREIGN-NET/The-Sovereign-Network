//! WiFi Direct Protocol Router
//!
//! Extracted from unified_server.rs (lines 4985-5157)
//! 
//! Handles WiFi Direct P2P mesh connections with:
//! - mDNS/Bonjour service discovery
//! - Group Owner negotiation
//! - Direct device-to-device connectivity
//! - UHP handshake for authentication
//! - WPA2/WPA3 security

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use std::net::SocketAddr;
use uuid::Uuid;
use tracing::{debug, info, warn};
use lib_network::protocols::wifi_direct::WiFiDirectMeshProtocol;
use lib_network::protocols::wifi_direct_handshake::{handshake_as_initiator, handshake_as_responder};
use lib_network::handshake::{HandshakeContext, NonceCache};
use lib_identity::IdentityManager;

/// WiFi Direct device connections
/// WiFi Direct handling with UHP authentication
pub struct WiFiRouter {
    connected_devices: Arc<RwLock<HashMap<String, String>>>,
    node_id: [u8; 32],
    protocol: Arc<RwLock<Option<WiFiDirectMeshProtocol>>>,
    initialized: Arc<RwLock<bool>>, // Track if already initialized to prevent re-creating protocol
    peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    identity_manager: Arc<RwLock<Option<Arc<RwLock<IdentityManager>>>>>, // For UHP handshake
    handshake_context: Arc<RwLock<Option<HandshakeContext>>>, // Shared nonce cache for WiFi Direct
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
        
        // Create shared nonce cache for WiFi Direct handshakes
        // SECURITY (HIGH-2): Increased capacity from 10,000 to 50,000 entries for mesh scale
        // Supports larger mesh networks without nonce collision risks
        // 3600 second (1 hour) expiration, 50000 entry capacity
        let nonce_cache = NonceCache::new(3600, 50000);
        let handshake_context = HandshakeContext::new(nonce_cache);
        
        Self {
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            node_id,
            protocol: Arc::new(RwLock::new(None)),
            initialized: Arc::new(RwLock::new(false)),
            peer_discovery_tx,
            identity_manager: Arc::new(RwLock::new(None)),
            handshake_context: Arc::new(RwLock::new(Some(handshake_context))),
        }
    }
    
    /// Set identity manager for UHP handshake authentication
    pub async fn set_identity_manager(&self, identity_manager: Arc<RwLock<IdentityManager>>) {
        *self.identity_manager.write().await = Some(identity_manager);
        info!("✅ WiFi Direct: Identity manager configured for UHP handshake");
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
    
    /// Handle incoming WiFi Direct TCP connection with UHP handshake
    ///
    /// Performs cryptographic verification of peer identity before accepting connection.
    /// Replaces old unverified text-based "ZHTP/1.0 200 OK" response with secure UHP handshake.
    ///
    /// # Security
    ///
    /// - Verifies peer's NodeId derivation (prevents collision attacks)
    /// - Verifies peer's signature on all handshake messages
    /// - Uses nonce cache for replay attack prevention
    /// - Derives session key for encrypted communication
    /// - Rejects connections if identity_manager not configured
    pub async fn handle_wifi_direct(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("🔐 WiFi Direct connection from {}, performing UHP handshake...", addr);

        // SECURITY (HIGH-3): Validate WiFi Direct subnet (192.168.49.0/24)
        // Ensures connection comes from WiFi Direct P2P interface, not arbitrary source
        if let std::net::IpAddr::V4(ip) = addr.ip() {
            let octets = ip.octets();
            if octets[0] != 192 || octets[1] != 168 || octets[2] != 49 {
                warn!("❌ WiFi Direct: Connection rejected - not from WiFi Direct subnet: {}", addr);
                return Err(anyhow::anyhow!("Connection not from WiFi Direct subnet (192.168.49.0/24)"));
            }
        } else {
            warn!("❌ WiFi Direct: Connection rejected - IPv6 not supported: {}", addr);
            return Err(anyhow::anyhow!("WiFi Direct only supports IPv4"));
        }

        // Check if identity manager is configured
        let identity_manager = {
            let guard = self.identity_manager.read().await;
            match &*guard {
                Some(mgr) => mgr.clone(),
                None => {
                    warn!("❌ WiFi Direct: Identity manager not configured - rejecting connection from {}", addr);
                    return Err(anyhow::anyhow!("Identity manager not configured for WiFi Direct"));
                }
            }
        };
        
        // Get our ZhtpIdentity for handshake
        let our_identity = {
            let mgr_guard = identity_manager.read().await;
            mgr_guard.get_primary_identity()
                .context("Failed to get primary identity for WiFi Direct handshake")?
                .clone()
        };
        
        // Get handshake context (shared nonce cache)
        let ctx = {
            let guard = self.handshake_context.read().await;
            guard.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Handshake context not initialized"))?
                .clone()
        };
        
        // Determine if we're group owner (for logging)
        let is_owner = self.is_group_owner().await;
        let device_role = if is_owner { "Group Owner" } else { "Client" };
        
        info!("📱 WiFi Direct role: {} for connection from {}", device_role, addr);

        // SECURITY (HIGH-1): Wrap handshake with timeout for defense in depth
        // Prevents hanging connections and DoS attacks via slow handshakes
        // Perform UHP handshake as responder (we're accepting the connection)
        let handshake_result = tokio::time::timeout(
            Duration::from_secs(30),
            handshake_as_responder(&mut stream, &our_identity, &ctx)
        ).await;

        match handshake_result {
            Ok(Ok(result)) => {
                info!("✅ WiFi Direct handshake successful with {}", addr);
                info!("   Peer: {} ({})", result.peer_identity.device_id, result.peer_identity.did);
                info!("   Session ID: {:02x?}", &result.session_id[..8]);
                
                // Store authenticated peer connection
                // SECURITY (HIGH-4): Session key derivation and encryption
                // The handshake result includes session_key derived via HKDF from ephemeral secrets
                // This session_key can be used for AEAD encryption of post-handshake messages
                // Currently stored but not used for message encryption - consider implementing
                // TLS 1.3 style record encryption for all subsequent WiFi Direct frames
                let _session_key = &result.session_key;

                let mut devices = self.connected_devices.write().await;
                devices.insert(
                    addr.to_string(),
                    format!("{} (authenticated)", result.peer_identity.device_id)
                );

                info!("✅ WiFi Direct: Verified peer {} added to connected devices", result.peer_identity.device_id);

                Ok(())
            }
            Ok(Err(e)) => {
                warn!("❌ WiFi Direct handshake failed with {}: {}", addr, e);
                warn!("   Rejecting unauthenticated connection");
                Err(e).context("WiFi Direct UHP handshake failed")
            }
            Err(_elapsed) => {
                warn!("❌ WiFi Direct handshake timeout with {} (exceeded 30s)", addr);
                warn!("   Rejecting connection due to handshake timeout");
                Err(anyhow::anyhow!("Handshake timeout")).context("WiFi Direct handshake took too long")
            }
        }
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
            identity_manager: self.identity_manager.clone(),
            handshake_context: self.handshake_context.clone(),
        }
    }
}
