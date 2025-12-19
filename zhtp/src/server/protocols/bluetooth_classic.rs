//! Bluetooth Classic RFCOMM Protocol Router
//!
//! Extracted from unified_server.rs (lines 5596-5893)
//! 
//! Handles Bluetooth Classic high-throughput mesh with:
//! - RFCOMM channel connections (375 KB/s)
//! - Service discovery protocol (SDP)
//! - Peer device discovery and auto-connect
//! - Active stream management for bidirectional communication

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use std::net::SocketAddr;
use uuid::Uuid;
use tracing::{debug, info, warn};
use crate::server::mesh::core::MeshRouter;

/// Bluetooth Classic RFCOMM router for high-throughput mesh
#[derive(Clone)]
pub struct BluetoothClassicRouter {
    connected_devices: Arc<RwLock<HashMap<String, String>>>,
    active_streams: Arc<RwLock<HashMap<String, Arc<tokio::sync::Mutex<lib_network::protocols::bluetooth::classic::RfcommStream>>>>>, // Store RFCOMM streams
    node_id: [u8; 32],
    protocol: Arc<RwLock<Option<lib_network::protocols::bluetooth::classic::BluetoothClassicProtocol>>>,
}

// Public type alias for cleaner code
pub type ClassicProtocol = lib_network::protocols::bluetooth::classic::BluetoothClassicProtocol;

impl BluetoothClassicRouter {
    pub fn new() -> Self {
        let node_id = {
            let mut id = [0u8; 32];
            let uuid = Uuid::new_v4();
            let uuid_bytes = uuid.as_bytes();
            id[..16].copy_from_slice(uuid_bytes);
            id[16..].copy_from_slice(uuid_bytes);
            id
        };
        
        Self {
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            node_id,
            protocol: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Initialize Bluetooth Classic RFCOMM protocol for high-throughput mesh
    pub async fn initialize(&self) -> Result<()> {
        info!("📻 Initializing Bluetooth Classic RFCOMM protocol for high-throughput mesh...");
        
        // Check if Windows Bluetooth feature is enabled on Windows
        #[cfg(all(target_os = "windows", not(feature = "windows-bluetooth")))]
        {
            warn!("⚠️  Windows: Bluetooth Classic requires --features windows-bluetooth");
            warn!("   Current build will NOT support RFCOMM discovery or connections");
            warn!("   Rebuild with: cargo build --features windows-bluetooth");
            warn!("   Skipping Bluetooth Classic initialization");
            return Err(anyhow::anyhow!("Windows Bluetooth feature not enabled"));
        }
        
        #[cfg(any(not(target_os = "windows"), feature = "windows-bluetooth"))]
        {
            use lib_network::protocols::bluetooth::classic::BluetoothClassicProtocol;
            use lib_crypto::PublicKey;
            
            // Create Bluetooth Classic protocol instance
            let bluetooth_classic = BluetoothClassicProtocol::new(self.node_id)?;
            
            // Initialize ZHTP authentication with blockchain public key
            info!("🔐 Initializing ZHTP authentication for Bluetooth Classic...");
            let blockchain_pubkey = PublicKey::new(self.node_id.to_vec());
            if let Err(e) = bluetooth_classic.initialize_zhtp_auth(blockchain_pubkey).await {
                warn!("⚠️  Bluetooth Classic auth initialization failed: {}", e);
                warn!("Continuing without authentication - connections may be insecure");
            } else {
                info!("✅ Bluetooth Classic ZHTP authentication initialized");
            }
        
            // Initialize RFCOMM advertising
            if let Err(e) = bluetooth_classic.start_advertising().await {
                warn!("Bluetooth Classic advertising failed to start: {}", e);
                return Err(anyhow::anyhow!("Bluetooth Classic advertising initialization failed: {}", e));
            }
            
            // Store the protocol instance
            *self.protocol.write().await = Some(bluetooth_classic);
            
            info!("✅ Bluetooth Classic RFCOMM initialized - discoverable as 'ZHTP-CLASSIC-{}'", 
                  hex::encode(&self.node_id[..4]));
            info!("📡 High-throughput mesh (375 KB/s) available via Bluetooth Classic");
            
            Ok(())
        }
    }
    
    /// Handle incoming Bluetooth Classic RFCOMM connection
    /// Uses same authentication flow as BLE but over RFCOMM transport
    ///
    /// # Security (HIGH-4 Fix)
    ///
    /// Rate limiting enforced before processing Bluetooth connections
    pub async fn handle_rfcomm_connection(
        &self,
        mut stream: TcpStream, // TODO: Replace with RfcommStream when implemented
        addr: SocketAddr,
        mesh_router: &MeshRouter,
    ) -> Result<()> {
        info!("📻 Processing Bluetooth Classic RFCOMM connection from: {}", addr);

        // HIGH-4 FIX: Check rate limit BEFORE processing handshake
        if let Err(block_duration) = mesh_router.connection_rate_limiter.check_ip(addr.ip()).await {
            warn!("🚫 Bluetooth connection rejected: IP {} rate limited for {:?}", addr.ip(), block_duration);
            return Ok(());
        }

        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read RFCOMM data")?;
        
        if bytes_read > 0 {
            debug!("RFCOMM data received: {} bytes", bytes_read);
            
            // Try to parse as binary mesh handshake (IDENTICAL to BLE!)
            if let Ok(handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(&buffer[..bytes_read]) {
                info!("🤝 Received RFCOMM mesh handshake from peer: {}", handshake.node_id);
                info!("   Version: {}, Port: {}, Protocols: {:?}", 
                    handshake.version, handshake.mesh_port, handshake.protocols);
                
                // Create peer identity
                let peer_pubkey = lib_crypto::PublicKey::new(handshake.node_id.as_bytes().to_vec());
                
                // Use BluetoothClassic protocol type
                let protocol = lib_network::protocols::NetworkProtocol::BluetoothClassic;
                
                // Create mesh connection with higher bandwidth (Ticket #146: Use UnifiedPeerId)
                let unified_peer = lib_network::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(peer_pubkey.clone());
                let connection = lib_network::mesh::connection::MeshConnection {
                    peer: unified_peer,
                    protocol,
                    peer_address: Some(addr.to_string()),
                    signal_strength: 0.8, // Classic typically better than BLE
                    bandwidth_capacity: 375_000, // 375 KB/s - Bluetooth Classic EDR
                    latency_ms: 50, // Lower latency than BLE
                    connected_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    data_transferred: 0,
                    tokens_earned: 0,
                    stability_score: 0.85,
                    zhtp_authenticated: false,
                    quantum_secure: false,
                    peer_dilithium_pubkey: None,
                    kyber_shared_secret: None,
                    trust_score: 0.5,
                    bootstrap_mode: false,
                };
                
                // Add to mesh connections (Ticket #146: Use UnifiedPeerId as key)
                {
                    let mut connections = mesh_router.connections.write().await;
                    let peer_key = connection.peer.clone();
                    // Ticket #149: Use peer_registry upsert instead of connections.insert
                    // connections is already a write guard, use it directly
                    let peer_entry = lib_network::peer_registry::PeerEntry::new(
                        peer_key,
                        vec![lib_network::peer_registry::PeerEndpoint {
                            address: String::new(), // TODO: Add actual address
                            protocol: connection.protocol.clone(),
                            signal_strength: 0.8,
                            latency_ms: 50,
                        }],
                        vec![connection.protocol.clone()],
                        lib_network::peer_registry::ConnectionMetrics {
                            signal_strength: 0.8,
                            bandwidth_capacity: 1_000_000,
                            latency_ms: 50,
                            stability_score: 0.9,
                            connected_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        },
                        true,
                        true,
                        None,
                        1,
                        0.8,
                        lib_network::peer_registry::NodeCapabilities {
                            protocols: vec![connection.protocol.clone()],
                            max_bandwidth: 1_000_000,
                            available_bandwidth: 800_000,
                            routing_capacity: 100,
                            energy_level: None,
                            availability_percent: 95.0,
                        },
                        None,
                        0.9,
                        None,
                        lib_network::peer_registry::DiscoveryMethod::MeshScan,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        lib_network::peer_registry::PeerTier::Tier3,
                        0.8,
                    );
                    connections.upsert(peer_entry).await.expect("Failed to upsert peer");
                    // No need to drop(connections) as it will be dropped automatically
                    
                    info!("✅ Bluetooth Classic peer {} added to mesh network ({} total peers)",
                        handshake.node_id, connections.all_peers().count());
                }
                
                // Run SAME authentication flow as BLE (transport-agnostic!)
                info!("🔐 Starting automatic authentication over RFCOMM");
                let _ = mesh_router.authenticate_and_register_peer(&peer_pubkey, &handshake, &addr, &mut stream).await;
                
                // Send acknowledgment
                let ack = bincode::serialize(&true)?;
                let _ = stream.write_all(&ack).await;
                
                info!("✅ Bluetooth Classic peer fully integrated - high-throughput mesh active!");
                
            } else {
                warn!("Failed to parse RFCOMM handshake");
            }
        }
        
        Ok(())
    }
    
    /// Get Bluetooth Classic service name
    pub fn get_service_name(&self) -> String {
        format!("ZHTP-CLASSIC-{}", hex::encode(&self.node_id[..4]))
    }
    
    /// Check if Bluetooth Classic is advertising
    pub async fn is_advertising(&self) -> bool {
        let protocol_guard: tokio::sync::RwLockReadGuard<Option<ClassicProtocol>> = self.protocol.read().await;
        protocol_guard.is_some()
    }
    
    /// Discover and connect to Bluetooth Classic peers
    /// Actively discovers paired devices, queries RFCOMM services, and connects to ZHTP nodes
    pub async fn discover_and_connect_peers(&self, mesh_router: &MeshRouter) -> Result<usize> {
        info!("🔍 Starting Bluetooth Classic peer discovery...");
        
        let protocol_guard: tokio::sync::RwLockReadGuard<Option<ClassicProtocol>> = self.protocol.read().await;
        let protocol: &ClassicProtocol = match protocol_guard.as_ref() {
            Some(p) => p,
            None => {
                warn!("Bluetooth Classic protocol not initialized");
                return Ok(0);
            }
        };
        
        // Step 1: Discover paired devices
        let devices: Vec<lib_network::protocols::bluetooth::classic::BluetoothDevice> = match protocol.discover_paired_devices().await {
            Ok(devs) => {
                info!("✅ Discovered {} paired Bluetooth devices", devs.len());
                devs
            }
            Err(e) => {
                warn!("Failed to discover Bluetooth devices: {}", e);
                return Ok(0);
            }
        };
        
        let mut connected_count = 0;
        
        // Step 2: Query each device for RFCOMM services and connect
        for device in devices {
            info!("🔍 Checking device: {} ({})", 
                device.name.as_deref().unwrap_or("Unknown"),
                device.address
            );
            
            // Only connect to paired and available devices
            if !device.is_paired {
                continue;
            }
            
            // Query RFCOMM services on this device
            let services = match protocol.query_rfcomm_services(&device.address).await {
                Ok(svcs) => svcs,
                Err(e) => {
                    debug!("Failed to query services on {}: {}", device.address, e);
                    continue;
                }
            };
            
            // Look for ZHTP services
            for service in services {
                if service.service_name.contains("ZHTP") || 
                   service.service_uuid.contains("6ba7b810") {
                    info!("✨ Found ZHTP service on {} (channel {})", 
                        device.address, service.channel);
                    
                    // Attempt to connect
                    match protocol.connect_to_peer(&device.address, service.channel).await {
                        Ok(stream) => {
                            info!("✅ Connected to {} via Bluetooth Classic RFCOMM!", device.address);
                            connected_count += 1;
                            
                            // Create mesh connection entry (Ticket #146: Use UnifiedPeerId)
                            let peer_pubkey = lib_crypto::PublicKey::new(device.address.as_bytes().to_vec());
                            let unified_peer = lib_network::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(peer_pubkey.clone());
                            let connection = lib_network::mesh::connection::MeshConnection {
                                peer: unified_peer,
                                protocol: lib_network::protocols::NetworkProtocol::BluetoothClassic,
                                peer_address: Some(device.address.clone()),
                                signal_strength: device.rssi.map(|r| (r + 127) as f64 / 127.0).unwrap_or(0.7),
                                bandwidth_capacity: 375_000, // 375 KB/s
                                latency_ms: 50,
                                connected_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                data_transferred: 0,
                                tokens_earned: 0,
                                stability_score: 0.8,
                                zhtp_authenticated: false,
                                quantum_secure: false,
                                peer_dilithium_pubkey: None,
                                kyber_shared_secret: None,
                                trust_score: 0.5,
                                bootstrap_mode: false,
                            };
                            
                            // Add to mesh network (Ticket #146: Use UnifiedPeerId as key)
                            // Ticket #149: Use PeerRegistry upsert instead of connections.insert
                            let mut registry = mesh_router.connections.write().await;
                            let peer_entry = lib_network::peer_registry::PeerEntry::new(
                                connection.peer.clone(),
                                vec![lib_network::peer_registry::PeerEndpoint {
                                    address: device.address.clone(),
                                    protocol: connection.protocol.clone(),
                                    signal_strength: 0.8,
                                    latency_ms: 50,
                                }],
                                vec![connection.protocol.clone()],
                                lib_network::peer_registry::ConnectionMetrics {
                                    signal_strength: 0.8,
                                    bandwidth_capacity: 1_000_000,
                                    latency_ms: 50,
                                    stability_score: 0.9,
                                    connected_at: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                },
                                true,
                                true,
                                None,
                                1,
                                0.8,
                                lib_network::peer_registry::NodeCapabilities {
                                    protocols: vec![connection.protocol.clone()],
                                    max_bandwidth: 1_000_000,
                                    available_bandwidth: 800_000,
                                    routing_capacity: 100,
                                    energy_level: None,
                                    availability_percent: 95.0,
                                },
                                None,
                                0.9,
                                None,
                                lib_network::peer_registry::DiscoveryMethod::MeshScan,
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                lib_network::peer_registry::PeerTier::Tier3,
                                0.8,
                            );
                            registry.upsert(peer_entry).await.expect("Failed to upsert peer");

                            info!("✅ Added {} to mesh network", device.address);
                            
                            // Store the stream for bidirectional communication
                            let stream_arc = Arc::new(tokio::sync::Mutex::new(stream));
                            self.active_streams.write().await.insert(
                                device.address.clone(),
                                stream_arc.clone()
                            );
                            self.connected_devices.write().await.insert(
                                device.address.clone(),
                                "bluetooth-classic-active".to_string()
                            );
                            
                            info!("✅ Stream stored for bidirectional communication with {}", device.address);
                        }
                        Err(e) => {
                            debug!("Failed to connect to {}: {}", device.address, e);
                        }
                    }
                    
                    // Only connect to first ZHTP service per device
                    break;
                }
            }
        }
        
        if connected_count > 0 {
            info!("🎊 Successfully connected to {} Bluetooth Classic peers", connected_count);
        } else {
            info!("No new Bluetooth Classic peers discovered");
        }
        
        Ok(connected_count)
    }
    
    /// Get connected devices via Bluetooth Classic
    pub async fn get_connected_devices(&self) -> HashMap<String, String> {
        self.connected_devices.read().await.clone()
    }
    
    /// Get a read guard for the Bluetooth Classic protocol
    pub async fn get_protocol(&self) -> tokio::sync::RwLockReadGuard<'_, Option<ClassicProtocol>> {
        self.protocol.read().await
    }
}
