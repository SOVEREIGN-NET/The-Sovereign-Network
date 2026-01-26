//! Mesh Helper Methods
//!
//! This module contains utility methods for the MeshRouter:
//! - UDP chunking for large responses
//! - Bluetooth-to-DHT bridging
//! - DHT-to-Bluetooth bridging
//! - TCP mesh connection handling
//!
//! These methods support cross-protocol communication and large data transfers.

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::net::{UdpSocket, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};

use lib_crypto::PublicKey;
use lib_network::MeshConnection;

/// Send large UDP response as multiple chunks
/// Each chunk is a JSON packet with: { "chunk_id", "total_chunks", "sequence", "data" }
pub async fn send_chunked_udp_response(
    udp_socket: &Arc<RwLock<Option<Arc<UdpSocket>>>>,
    data: &[u8],
    addr: SocketAddr
) -> Result<Option<Vec<u8>>> {
    const MAX_CHUNK_DATA_SIZE: usize = 50000; // 50KB per chunk
    
    let total_bytes = data.len();
    let total_chunks = (total_bytes + MAX_CHUNK_DATA_SIZE - 1) / MAX_CHUNK_DATA_SIZE;
    let chunk_id = Uuid::new_v4().to_string();
    
    info!("📦 Chunking {} bytes into {} chunks (chunk_id: {})", total_bytes, total_chunks, chunk_id);
    
    let socket = udp_socket.read().await;
    let sock = socket.as_ref().ok_or_else(|| anyhow::anyhow!("UDP socket not available"))?;
    
    for sequence in 0..total_chunks {
        let start = sequence * MAX_CHUNK_DATA_SIZE;
        let end = (start + MAX_CHUNK_DATA_SIZE).min(total_bytes);
        let chunk_data = &data[start..end];
        
        // Encode chunk data as base64 for safe JSON transport
        let chunk_data_b64 = general_purpose::STANDARD.encode(chunk_data);
        
        let chunk_packet = serde_json::json!({
            "ZhtpChunk": {
                "chunk_id": chunk_id,
                "sequence": sequence,
                "total_chunks": total_chunks,
                "data": chunk_data_b64,
                "data_size": chunk_data.len(),
                "total_size": total_bytes,
            }
        });
        
        let chunk_bytes = serde_json::to_vec(&chunk_packet)?;
        
        match sock.send_to(&chunk_bytes, addr).await {
            Ok(sent) => {
                info!("📤 Sent chunk {}/{} ({} bytes) to {}", 
                    sequence + 1, total_chunks, sent, addr);
            }
            Err(e) => {
                error!("❌ Failed to send chunk {}/{}: {}", sequence + 1, total_chunks, e);
                return Err(e.into());
            }
        }
        
        // Small delay between chunks to avoid overwhelming receiver
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    
    info!("✅ All {} chunks sent successfully", total_chunks);
    
    // Return None because we already sent the response via UDP
    Ok(None)
}

/// Handle TCP mesh connection with handshake and optional authentication
pub async fn handle_tcp_mesh(
    connections: &Arc<RwLock<std::collections::HashMap<PublicKey, MeshConnection>>>,
    quic_protocol: &Arc<RwLock<Option<Arc<lib_network::protocols::quic_mesh::QuicMeshProtocol>>>>,
    authenticate_peer_fn: impl std::future::Future<Output = Result<bool>>,
    mut stream: TcpStream,
    addr: SocketAddr
) -> Result<()> {
    info!("🔌 Processing TCP mesh connection from: {}", addr);
    
    let mut buffer = vec![0; 8192];
    let bytes_read = stream.read(&mut buffer).await
        .context("Failed to read TCP mesh data")?;
    
    if bytes_read > 0 {
        debug!("TCP mesh data: {} bytes", bytes_read);
        
        // Try to parse as binary mesh handshake (from local discovery)
        if let Ok(handshake) = bincode::deserialize::<lib_network::protocols::bluetooth::MeshHandshake>(&buffer[..bytes_read]) {
            info!("🤝 Received binary mesh handshake from peer: {}", handshake.node_id);
            info!("   Version: {}, Port: {}, Protocols: {:?}", 
                handshake.version, handshake.mesh_port, handshake.protocols);
            
            let discovery_method = match handshake.discovered_via {
                0 => "local_multicast",
                1 => "bluetooth",
                2 => "wifi_direct",
                3 => "manual",
                _ => "unknown",
            };
            info!("   Discovered via: {}", discovery_method);
            
            // Add peer to mesh connections (like blockchain nodes do)
            let peer_pubkey = lib_crypto::PublicKey::new(handshake.node_id.as_bytes().to_vec());
            
            // Determine protocol from discovery method
            let protocol = match handshake.discovered_via {
                0 => lib_network::protocols::NetworkProtocol::QUIC,
                1 => lib_network::protocols::NetworkProtocol::BluetoothLE,
                2 => lib_network::protocols::NetworkProtocol::WiFiDirect,
                _ => lib_network::protocols::NetworkProtocol::QUIC,
            };
            
            // Create mesh connection (Ticket #146: Use UnifiedPeerId)
            let unified_peer = lib_network::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(peer_pubkey.clone());
            let connection = lib_network::mesh::connection::MeshConnection {
                peer: unified_peer,
                protocol,
                peer_address: Some(addr.to_string()),
                signal_strength: 0.8,
                bandwidth_capacity: 1_000_000,
                latency_ms: 50,
                connected_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                data_transferred: 0,
                tokens_earned: 0,
                stability_score: 1.0,
                zhtp_authenticated: false,
                quantum_secure: false,
                peer_dilithium_pubkey: None,
                kyber_shared_secret: None,
                trust_score: 0.5,
                bootstrap_mode: false,
            };
            
            // Add to mesh connections
            {
                let mut conns = connections.write().await;
                conns.insert(peer_pubkey.clone(), connection);
                info!("✅ Peer {} added to mesh network ({} total peers)", 
                    handshake.node_id, conns.len());
            }
            
            // Register peer in DHT Kademlia routing table
            let node_id_hash: [u8; 32] = lib_crypto::hash_blake3(&peer_pubkey.key_id);
            info!("📍 Would register TCP/UDP peer in Kademlia routing table: node_id={}", hex::encode(&node_id_hash[0..8]));
            
            // Send acknowledgment
            let ack = bincode::serialize(&true)?;
            if let Err(e) = stream.write_all(&ack).await {
                warn!("Failed to send ack to peer: {}", e);
                return Ok(());
            }
            
            // Establish QUIC connection
            info!("🔐 Establishing QUIC connection to peer {} at {}", handshake.node_id, addr);
            
            if let Some(ref quic) = *quic_protocol.read().await {
                match quic.connect_to_peer(addr).await {
                    Ok(_) => {
                        info!("✅ QUIC connection established (TLS 1.3 + Kyber PQC)");
                        let mut conns = connections.write().await;
                        if let Some(conn) = conns.get_mut(&peer_pubkey) {
                            conn.protocol = lib_network::protocols::NetworkProtocol::QUIC;
                            conn.quantum_secure = true;
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ QUIC connection failed (using TCP fallback): {}", e);
                    }
                }
            } else {
                warn!("⚠️ QUIC protocol not available, using TCP");
            }
            
            // Optional authentication
            info!("🔑 Attempting blockchain authentication with peer {} (optional for new nodes)", handshake.node_id);
            info!("   New nodes can:");
            info!("     ✅ Create blockchain identity via /api/v1/identity/create");
            info!("     ✅ Access bootstrap info via /api/v1/bootstrap");
            info!("   After identity creation, full authentication unlocks:");
            info!("     → DHT content storage/retrieval");
            info!("     → Blockchain transaction submission");
            info!("     → Mesh routing and relay services");
            
            match authenticate_peer_fn.await {
                Ok(true) => {
                    info!("✅ Peer {} AUTHENTICATED - Full network access granted", handshake.node_id);
                    info!("   → Can submit transactions");
                    info!("   → Can store/retrieve DHT content");
                    info!("   → Can participate in blockchain consensus");
                }
                Ok(false) | Err(_) => {
                    info!("ℹ️ Peer {} connected WITHOUT authentication - Bootstrap mode active", handshake.node_id);
                    info!("   → Can create blockchain identity");
                    info!("   → Can query bootstrap nodes");
                    info!("   → Cannot access DHT or submit transactions until authenticated");
                }
            }
        } else {
            debug!("TCP data is not a binary mesh handshake, ignoring");
        }
    }
    
    Ok(())
}

/// Bridge Bluetooth messages to DHT network
pub async fn bridge_bluetooth_to_dht(message_data: &[u8], source_addr: &SocketAddr) -> Result<()> {
    info!("🌉 Bridging Bluetooth message to DHT network from {}", source_addr);
    
    // Parse the Bluetooth message
    let message_str = String::from_utf8_lossy(message_data);
    debug!("Bluetooth message content: {}", message_str.chars().take(100).collect::<String>());
    
    // Extract DHT operation from Bluetooth message
    if message_str.starts_with("DHT:STORE:") {
        // DHT store operation via Bluetooth
        let parts: Vec<&str> = message_str.splitn(4, ':').collect();
        if parts.len() >= 4 {
            let key = parts[2];
            let value = parts[3].as_bytes();
            
            // Forward to DHT network
            let (domain, path) = if key.contains('/') {
                let parts: Vec<&str> = key.splitn(2, '/').collect();
                (parts[0], parts[1])
            } else {
                ("bluetooth-bridge", key)
            };
            
            info!("Bridging DHT STORE operation: domain={}, path={}, {} bytes", domain, path, value.len());
            
            // Get mutable access to DHT client for store operation
            if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
                let mut dht = dht_client.write().await;
                if let Err(e) = dht.store_content(domain, path, value.to_vec()).await {
                    warn!("Failed to store DHT content via Bluetooth bridge: {}", e);
                } else {
                    info!("✅ Stored DHT content via Bluetooth bridge: domain={}, path={}", domain, path);
                }
            } else {
                warn!("DHT client not available for Bluetooth bridge operation");
            }
        }
    } else if message_str.starts_with("DHT:GET:") {
        // DHT get operation via Bluetooth
        let parts: Vec<&str> = message_str.splitn(3, ':').collect();
        if parts.len() >= 3 {
            let key = parts[2];
            
            // Retrieve from DHT network
            if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
                let mut dht = dht_client.write().await;
                match dht.fetch_content(key).await {
                    Ok(Some(data)) => {
                        info!("✅ Retrieved DHT data via Bluetooth bridge: {} bytes", data.len());
                        // TODO: Send response back to Bluetooth client
                    },
                    Ok(None) => {
                        warn!("No DHT content found via Bluetooth bridge");
                    },
                    Err(e) => {
                        warn!("Failed to get DHT content via Bluetooth bridge: {}", e);
                    }
                }
            } else {
                warn!("DHT client not available for Bluetooth bridge operation");
            }
        }
    } else if message_str.starts_with("ZHTP-MESH:") {
        // General ZHTP mesh message forwarding
        info!("🌉 Forwarding ZHTP mesh message to DHT network");
        // TODO: Implement mesh message forwarding
    }
    
    Ok(())
}

/// Bridge DHT/Internet messages to Bluetooth clients
pub async fn bridge_dht_to_bluetooth(message_data: &[u8], source_addr: &SocketAddr) -> Result<()> {
    debug!("🌉 Attempting to bridge DHT message to Bluetooth clients from {}", source_addr);
    
    // Parse message to see if it's DHT traffic
    if let Ok(message_str) = std::str::from_utf8(message_data) {
        let _bluetooth_message = if message_str.contains("DHT") {
            format!("BRIDGED-DHT:{}", message_str)
        } else if message_str.contains("ZHTP") {
            format!("BRIDGED-ZHTP:{}", message_str)
        } else {
            format!("BRIDGED-MESH:{}", message_str)
        };
        
        info!("Would forward {} message to Bluetooth clients", 
            if message_str.contains("DHT") { "DHT" } else { "MESH" });
        
        // TODO: Implement actual Bluetooth message forwarding
        // This would require maintaining active Bluetooth connections
        // and implementing the reverse TCP connection mechanism
    }
    
    Ok(())
}
