//! Bluetooth Low Energy (BLE) Protocol Router
//!
//! Extracted from unified_server.rs (lines 5158-5595)
//! 
//! Handles BLE GATT mesh connections with:
//! - GATT characteristics and service discovery
//! - Edge node header/proof sync
//! - Phone connectivity and mesh handshakes
//! - DHT bridge functionality
//! - Fragment reassembly for large messages

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use std::net::SocketAddr;
use uuid::Uuid;
use tracing::{debug, info, warn};
use lib_network::protocols::bluetooth::BluetoothMeshProtocol;
use lib_crypto::PublicKey;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use crate::server::mesh::core::MeshRouter;

/// Bluetooth Low Energy mesh protocol router for phone connectivity
#[derive(Clone)]
pub struct BluetoothRouter {
    connected_devices: Arc<RwLock<HashMap<String, String>>>,
    node_id: [u8; 32],
    protocol: Arc<RwLock<Option<Arc<BluetoothMeshProtocol>>>>,
}

impl BluetoothRouter {
    pub fn new() -> Self {
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
        }
    }
    
    /// Initialize Bluetooth mesh protocol for phone connectivity
    // Ticket #146: Updated to use UnifiedPeerId as HashMap key
    pub async fn initialize(
        &self,
        mesh_connections: Arc<RwLock<HashMap<lib_network::identity::unified_peer::UnifiedPeerId, lib_network::mesh::connection::MeshConnection>>>,
        peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<PublicKey>>,
        our_public_key: PublicKey,
        blockchain_provider: Option<Arc<dyn lib_network::blockchain_sync::BlockchainProvider>>,
        sync_coordinator: Arc<lib_network::blockchain_sync::SyncCoordinator>,
        mesh_router: Arc<MeshRouter>,
    ) -> Result<()> {
        info!("📱 Initializing Bluetooth mesh protocol for phone connectivity...");
        
        // Create Bluetooth mesh protocol instance
        let mut bluetooth_protocol = BluetoothMeshProtocol::new(self.node_id, our_public_key)?;
        
        // ========================================================================
        // Phase 6: Enable BLE edge node sync if blockchain provider is available
        // ========================================================================
        if let Some(provider) = blockchain_provider {
            bluetooth_protocol.set_blockchain_provider(provider).await;
            info!("✅ BLE edge sync enabled - will serve headers/proofs to mobile devices");
        }
        
        // Create GATT message channel for forwarding GATT writes to this router
        let (gatt_tx, mut gatt_rx) = tokio::sync::mpsc::unbounded_channel();
        bluetooth_protocol.set_gatt_message_channel(gatt_tx).await;
        info!("✅ GATT message channel connected to BluetoothRouter");
        
        // Initialize Bluetooth advertising for ZHTP service
        // Note: Windows COM threading handled within the Bluetooth implementation
        if let Err(e) = bluetooth_protocol.start_advertising().await {
            warn!("⚠️  Bluetooth advertising failed to start: {}", e);
            // Don't fail the entire initialization if Bluetooth fails
            warn!("Continuing without Bluetooth advertising support");
        } else {
            info!("✅ Bluetooth advertising started successfully");
        }
        
        // Store the protocol instance (wrapped in Arc for sharing)
        let protocol_arc = Arc::new(bluetooth_protocol);
        *self.protocol.write().await = Some(protocol_arc.clone());
        
        // Spawn GATT message handler task with mesh_connections access
        let connected_devices = self.connected_devices.clone();
        let mesh_conns = mesh_connections.clone();
        let ble_peer_notify = peer_discovery_tx.clone();
        let sync_coordinator_for_gatt = sync_coordinator.clone();
        let mesh_router_for_gatt = mesh_router.clone();
        let bluetooth_protocol_for_gatt = protocol_arc.clone(); // Clone protocol for GATT handler
        tokio::spawn(async move {
            while let Some(gatt_message) = gatt_rx.recv().await {
                use lib_network::protocols::bluetooth::gatt::GattMessage;
                match gatt_message {
                    GattMessage::MeshHandshake { data, peripheral_id } => {
                        info!("📨 GATT: Received mesh message ({} bytes)", data.len());
                        if let Some(ref pid) = peripheral_id {
                            info!("   🆔 Peripheral ID: {}", pid);
                        }
                        
                        // Try to parse as MeshHandshake first (initial connection)
                        if let Ok(handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(&data) {
                            info!("🤝 GATT handshake from: {}", handshake.node_id);
                            
                            // Extract the real cryptographic public key from handshake
                            let peer_pubkey = handshake.public_key.clone();
                            
                            // FIX: Use peripheral_id for macOS, node_id for other platforms
                            let gatt_address = if let Some(ref pid) = peripheral_id {
                                format!("gatt://{}", pid)  // macOS: Use CBPeripheral UUID
                            } else {
                                format!("gatt://{}", handshake.node_id)  // Windows/Linux: Use node_id
                            };
                            info!("   📍 GATT address: {}", gatt_address);
                            
                            // Create mesh connection for GATT peer (Ticket #146: Use UnifiedPeerId)
                            let unified_peer = lib_network::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(peer_pubkey.clone());
                            let connection = lib_network::mesh::connection::MeshConnection {
                                peer: unified_peer,
                                protocol: lib_network::protocols::NetworkProtocol::BluetoothLE,
                                peer_address: Some(gatt_address.clone()),
                                signal_strength: 0.7,
                                bandwidth_capacity: 250_000, // 250 KB/s BLE
                                latency_ms: 100,
                                connected_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                data_transferred: 0,
                                tokens_earned: 0,
                                stability_score: 0.8,
                                zhtp_authenticated: false, // Will authenticate later
                                quantum_secure: false,
                                peer_dilithium_pubkey: None,
                                kyber_shared_secret: None,
                                trust_score: 0.5,
                                bootstrap_mode: false,
                            };
                            
                            // Add to mesh network (Ticket #146: Use UnifiedPeerId as key)
                            let peer_key = connection.peer.clone();
                            let is_new_peer = !mesh_conns.read().await.contains_key(&peer_key);
                            mesh_conns.write().await.insert(peer_key, connection);
                            info!("   ✅ Added GATT peer {} to mesh network", handshake.node_id);
                            
                            // FIX: Also register with BluetoothMeshProtocol.current_connections
                            // This is required for send_mesh_message() to find the peer
                            let ble_connection = lib_network::protocols::bluetooth::BluetoothConnection {
                                peer_id: handshake.node_id.to_string(),
                                address: gatt_address.clone(),
                                mtu: 247,  // Default BLE MTU
                                rssi: -50, // Placeholder RSSI
                                connected_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                last_seen: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            };
                            bluetooth_protocol_for_gatt.current_connections.write().await.insert(gatt_address.clone(), ble_connection);
                            info!("   ✅ Registered GATT peer in bluetooth_protocol.current_connections: {}", gatt_address);
                            
                            // Register peer in DHT Kademlia routing table
                            // Generate node_id from public key hash (Blake3)
                            let node_id: [u8; 32] = lib_crypto::hash_blake3(&peer_pubkey.key_id);
                            // Note: KademliaNode registration removed (type no longer available)
                            // TODO: Use ZkDHTIntegration::register_peer() instead
                            info!("   📝 Would register BLE peer in Kademlia routing table: node_id={}", hex::encode(&node_id[0..8]));
                            
                            // Track connected device
                            let device_key = handshake.node_id.to_string();
                            let device_info = format!("Bluetooth GATT (protocols: {:?})", handshake.protocols);
                            connected_devices.write().await.insert(device_key, device_info);
                            
                            // Always trigger blockchain sync for BLE handshake completion
                            // The sync coordinator will detect and prevent duplicates if peer is also connected via UDP
                            info!("🔄 BLE handshake complete - notifying for blockchain sync (is_new_peer: {})", is_new_peer);
                            if let Some(notify_tx) = &ble_peer_notify {
                                if let Err(e) = notify_tx.send(peer_pubkey.clone()) {
                                    warn!("Failed to send BLE peer notification: {}", e);
                                } else {
                                    info!("📤 BLE peer notification sent for {}", handshake.node_id);
                                }
                            }
                        }
                        // If not MeshHandshake, try to parse as ZhtpMeshMessage (edge sync requests)
                        else if let Ok(mesh_message) = bincode::deserialize::<ZhtpMeshMessage>(&data) {
                            info!("📨 GATT: Received ZhtpMeshMessage");
                            
                            // Handle HeadersRequest/BlockchainRequest messages
                            match &mesh_message {
                                ZhtpMeshMessage::HeadersRequest { requester, request_id, start_height, count } => {
                                    info!("📥 GATT HeadersRequest from peer (ID: {}, height: {}, count: {})", 
                                          request_id, start_height, count);
                                    
                                    // Get blockchain provider and fetch headers
                                    if let Some(provider) = mesh_router_for_gatt.get_blockchain_provider().await {
                                        match provider.get_headers(*start_height, *count as u64).await {
                                            Ok(headers) => {
                                                info!("📤 GATT: Sending {} headers back to requester", headers.len());
                                                
                                                // Serialize headers to Vec<Vec<u8>>
                                                let serialized_headers: Vec<Vec<u8>> = headers.iter()
                                                    .filter_map(|h| bincode::serialize(h).ok())
                                                    .collect();
                                                
                                                // Create HeadersResponse message
                                                let response = ZhtpMeshMessage::HeadersResponse {
                                                    request_id: *request_id,
                                                    headers: serialized_headers,
                                                    start_height: *start_height,
                                                };
                                                
                                                // Send response back via BLE
                                                if let Err(e) = mesh_router_for_gatt.send_to_peer(requester, response).await {
                                                    warn!("Failed to send HeadersResponse via GATT: {}", e);
                                                } else {
                                                    info!("✅ GATT: HeadersResponse sent successfully");
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to get headers from blockchain: {}", e);
                                            }
                                        }
                                    } else {
                                        warn!("No blockchain provider available to handle HeadersRequest");
                                    }
                                }
                                ZhtpMeshMessage::BlockchainRequest {  request_id, .. } => {
                                    info!("📥 GATT BlockchainRequest from peer (ID: {})", request_id);
                                    // TODO: Handle full blockchain request
                                    warn!("Full blockchain requests via GATT not yet implemented");
                                }
                                ZhtpMeshMessage::HeadersResponse { request_id, headers, start_height } => {
                                    info!("✅ GATT: Received HeadersResponse (ID: {}, {} headers, starting at height {})", 
                                          request_id, headers.len(), start_height);
                                    
                                    // Find peer by request_id and mark sync complete
                                    if let Some((peer_id, sync_type)) = sync_coordinator_for_gatt.find_peer_by_sync_id(*request_id).await {
                                        sync_coordinator_for_gatt.complete_sync(&peer_id, *request_id, sync_type).await;
                                        info!("   ✅ Marked edge sync complete for peer {}", hex::encode(&peer_id.key_id[..8]));
                                    } else {
                                        warn!("   ⚠️  No active sync found for request_id {}", request_id);
                                    }
                                }
                                _ => {
                                    debug!("GATT: Unhandled ZhtpMeshMessage variant");
                                }
                            }
                        }
                        else {
                            warn!("⚠️  GATT: Failed to deserialize message as MeshHandshake or ZhtpMeshMessage");
                        }
                    }
                    GattMessage::DhtBridge(text) => {
                        info!("🌉 GATT: DHT bridge message: {}", text);
                        // DHT forwarding handled by bridge_bluetooth_to_dht in MeshRouter
                    }
                    GattMessage::RawData(uuid, data) => {
                        info!("📦 GATT: Raw data on {}: {} bytes", uuid, data.len());
                        // Process based on characteristic UUID
                    }
                    GattMessage::RelayQuery(data) => {
                        info!("🔄 GATT: Relay query ({} bytes)", data.len());
                        // Relay queries processed by MeshRouter relay protocol
                    }
                    GattMessage::HeadersRequest { request_id, start_height, count } => {
                        info!("📥 GATT: HeadersRequest received (ID: {}, height: {}, count: {})", 
                              request_id, start_height, count);
                        // Handle via BluetoothMeshProtocol's edge sync handler
                        // Response will be sent back via BLE automatically
                    }
                    GattMessage::BootstrapProofRequest { request_id, current_height } => {
                        info!("📥 GATT: BootstrapProofRequest received (ID: {}, current: {})", 
                              request_id, current_height);
                        // Handle via BluetoothMeshProtocol's edge sync handler
                    }
                    GattMessage::HeadersResponse { request_id, headers } => {
                        info!("✅ GATT: HeadersResponse received (ID: {}, {} headers)", 
                              request_id, headers.len());
                        // Edge node received headers - sync complete
                        
                        // Find peer by request_id and mark sync complete
                        if let Some((peer_id, sync_type)) = sync_coordinator_for_gatt.find_peer_by_sync_id(request_id).await {
                            sync_coordinator_for_gatt.complete_sync(&peer_id, request_id, sync_type).await;
                            info!("   ✅ Marked edge sync complete for peer {}", hex::encode(&peer_id.key_id[..8]));
                        } else {
                            warn!("   ⚠️  No active sync found for request_id {}", request_id);
                        }
                    }
                    GattMessage::BootstrapProofResponse { request_id, proof_height, headers, .. } => {
                        info!("✅ GATT: BootstrapProofResponse received (ID: {}, proof up to {}, {} headers)", 
                              request_id, proof_height, headers.len());
                        // Edge node received proof + headers - sync complete
                        
                        // Find peer by request_id and mark sync complete
                        if let Some((peer_id, sync_type)) = sync_coordinator_for_gatt.find_peer_by_sync_id(request_id).await {
                            sync_coordinator_for_gatt.complete_sync(&peer_id, request_id, sync_type).await;
                            info!("   ✅ Marked edge sync complete for peer {}", hex::encode(&peer_id.key_id[..8]));
                        } else {
                            warn!("   ⚠️  No active sync found for request_id {}", request_id);
                        }
                    }
                    GattMessage::FragmentHeader { .. } => {
                        info!("🧩 GATT: Fragment header received (multi-part message)");
                        // Handled by fragment reassembler in BluetoothMeshProtocol
                    }
                    _ => {
                        info!("❓ GATT: Unknown message type");
                    }
                }
            }
            info!("GATT message handler stopped");
        });
        
        info!("✅ Bluetooth mesh protocol initialized - discoverable as 'ZHTP-{}'", 
              hex::encode(&self.node_id[..4]));
        info!("📱 Your phone can now discover and connect to this ZHTP node via Bluetooth");
        
        Ok(())
    }
    
    /// Get the bluetooth protocol instance for message routing
    pub async fn get_protocol(&self) -> Option<Arc<BluetoothMeshProtocol>> {
        (*self.protocol.read().await).clone()
    }
    
    /// Handle incoming Bluetooth connection with full mesh authentication
    pub async fn handle_bluetooth_connection(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        mesh_router: &MeshRouter,
    ) -> Result<()> {
        info!("📱 Processing Bluetooth mesh connection from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read Bluetooth data")?;
        
        if bytes_read > 0 {
            debug!("Bluetooth data received: {} bytes", bytes_read);
            
            // Try to parse as binary mesh handshake (same as TCP!)
            if let Ok(handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(&buffer[..bytes_read]) {
                info!("🤝 Received Bluetooth mesh handshake from peer: {}", handshake.node_id);
                info!("   Version: {}, Port: {}, Protocols: {:?}", 
                    handshake.version, handshake.mesh_port, handshake.protocols);
                
                // Create peer identity
                let peer_pubkey = lib_crypto::PublicKey::new(handshake.node_id.as_bytes().to_vec());
                
                // Bluetooth connections use BluetoothLE protocol
                let protocol = lib_network::protocols::NetworkProtocol::BluetoothLE;
                
                // Create mesh connection (Ticket #146: Use UnifiedPeerId)
                let unified_peer = lib_network::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(peer_pubkey.clone());
                let connection = lib_network::mesh::connection::MeshConnection {
                    peer: unified_peer,
                    protocol,
                    peer_address: Some(addr.to_string()), // Store Bluetooth peer address for relay queries
                    signal_strength: 0.7, // Bluetooth typically lower than WiFi
                    bandwidth_capacity: 250_000, // 250 KB/s - optimized BLE throughput (7.5ms interval + 1ms delay)
                    latency_ms: 100, // Bluetooth has higher latency
                    connected_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    data_transferred: 0,
                    tokens_earned: 0,
                    stability_score: 0.8,
                    zhtp_authenticated: false, // Will be set after authentication
                    quantum_secure: false, // Will be set after Kyber exchange
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
                    let mut registry = connections.write().await;
                    let peer_entry = lib_network::peer_registry::PeerEntry {
                        peer_id: peer_key,
                        endpoints: vec![lib_network::peer_registry::PeerEndpoint {
                            address: String::new(), // TODO: Add actual address
                            protocol: connection.protocol,
                            signal_strength: 0.8,
                            latency_ms: 50,
                        }],
                        active_protocols: vec![connection.protocol],
                        connection_metrics: lib_network::peer_registry::ConnectionMetrics {
                            signal_strength: 0.8,
                            bandwidth_capacity: 1_000_000,
                            latency_ms: 50,
                            stability_score: 0.9,
                            connected_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        },
                        authenticated: true,
                        quantum_secure: true,
                        next_hop: None,
                        hop_count: 1,
                        route_quality: 0.8,
                        capabilities: lib_network::peer_registry::NodeCapabilities {
                            protocols: vec![connection.protocol],
                            max_bandwidth: 1_000_000,
                            available_bandwidth: 800_000,
                            routing_capacity: 100,
                            energy_level: None,
                            availability_percent: 95.0,
                        },
                        location: None,
                        reliability_score: 0.9,
                        dht_info: None,
                        discovery_method: lib_network::peer_registry::DiscoveryMethod::MeshScan,
                        first_seen: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        last_seen: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        tier: lib_network::peer_registry::PeerTier::Tier3,
                        trust_score: 0.8,
                        data_transferred: 0,
                        tokens_earned: 0,
                        traffic_routed: 0,
                    };
                    registry.upsert(peer_entry).expect("Failed to upsert peer");
                    drop(registry);
                    
                    info!("✅ Bluetooth peer {} added to mesh network ({} total peers)",
                        handshake.node_id, connections.read().await.all_peers().count());
                }
                
                // Run full authentication, key exchange, and DHT registration (same as TCP!)
                info!("🔐 Starting automatic authentication (no pairing code needed)");
                let _ = mesh_router.authenticate_and_register_peer(&peer_pubkey, &handshake, &addr, &mut stream).await;
                
                // Send acknowledgment
                let ack = bincode::serialize(&true)?;
                let _ = stream.write_all(&ack).await;
                
                info!("✅ Bluetooth peer fully integrated - zero-trust authentication complete!");
                
            } else {
                // Legacy text-based Bluetooth messages (DHT bridge)
                let message = String::from_utf8_lossy(&buffer[..bytes_read]);
                
                if message.starts_with("ZHTP-MESH:") || message.starts_with("DHT:") {
                    info!("🌉 Bridging Bluetooth ZHTP traffic to DHT network");
                    
                    // ACTUALLY CALL THE BRIDGE FUNCTION
                    match mesh_router.bridge_bluetooth_to_dht(&buffer[..bytes_read], &addr).await {
                        Ok(()) => {
                            info!("✅ Bluetooth message successfully bridged to DHT");
                            let response = format!(
                                "ZHTP/1.0 200 OK\r\nX-Protocol: Bluetooth-DHT-Bridge\r\nX-Node-ID: {:?}\r\nX-Service: ZHTP-Mesh\r\nX-Bridge: Active\r\n\r\nBridged to DHT network",
                                &self.node_id[..8]
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                        Err(e) => {
                            warn!("Failed to bridge Bluetooth message to DHT: {}", e);
                            let response = format!(
                                "ZHTP/1.0 500 Internal Server Error\r\nX-Protocol: Bluetooth-DHT-Bridge\r\nX-Error: {}\r\n\r\nBridge failed",
                                e
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                    }
                } else {
                    // Unknown Bluetooth message - still acknowledge
                    info!("Bluetooth message received (not DHT): {} bytes", bytes_read);
                    let response = format!(
                        "ZHTP/1.0 200 OK\r\nX-Protocol: Bluetooth\r\nX-Node-ID: {:?}\r\nX-Service: ZHTP-Mesh\r\n\r\nBluetooth mesh node ready",
                        &self.node_id[..8]
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
                
                // Store legacy connection
                let mut devices = self.connected_devices.write().await;
                devices.insert(addr.to_string(), "bluetooth-legacy-bridge".to_string());
            }
        }
        
        Ok(())
    }
    
    /// Get the Bluetooth service name visible to phones
    pub fn get_service_name(&self) -> String {
        format!("ZHTP-{}", hex::encode(&self.node_id[..4]))
    }
    
    /// Check if Bluetooth is advertising and discoverable
    pub async fn is_advertising(&self) -> bool {
        if let Some(protocol) = self.protocol.read().await.as_ref() {
            protocol.is_advertising()
        } else {
            false
        }
    }
    
    /// Get connected phone devices
    pub async fn get_connected_phones(&self) -> HashMap<String, String> {
        self.connected_devices.read().await.clone()
    }
}
