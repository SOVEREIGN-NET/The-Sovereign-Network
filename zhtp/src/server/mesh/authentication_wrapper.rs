//! Authentication Wrapper Methods
//!
//! Thin wrapper methods that delegate to lib-network::protocols::zhtp_auth
//! These methods maintain the existing API surface for MeshRouter while
//! using the canonical authentication implementation from lib-network.
//!
//! ⚠️ This file contains ONLY thin wrappers - actual authentication logic
//! is in lib-network::protocols::zhtp_auth::ZhtpAuthManager

use std::net::SocketAddr;
use anyhow::{Result, Context};
use tracing::{debug, info, warn};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use lib_crypto::PublicKey;
use lib_network::discovery::local_network::MeshHandshake;
use lib_network::protocols::zhtp_encryption::{ZhtpEncryptionSession, ZhtpKeyExchangeResponse};
use lib_network::protocols::zhtp_auth::{ZhtpAuthResponse, NodeCapabilities};

use super::core::MeshRouter;

impl MeshRouter {
    /// Handle incoming TCP mesh connection with handshake
    /// 
    /// This is a thin wrapper that maintains the previous API surface
    pub async fn handle_tcp_mesh(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("🔌 Processing TCP mesh connection from: {}", addr);
        
        let mut buffer = vec![0; 8192];
        let bytes_read = stream.read(&mut buffer).await
            .context("Failed to read TCP mesh data")?;
        
        if bytes_read > 0 {
            debug!("TCP mesh data: {} bytes", bytes_read);
            
            // Try to parse as binary mesh handshake
            if let Ok(handshake) = bincode::deserialize::<MeshHandshake>(&buffer[..bytes_read]) {
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
                
                // Create temporary identity until blockchain identity is exchanged
                let peer_pubkey = lib_crypto::PublicKey::new(handshake.node_id.as_bytes().to_vec());
                
                // Determine protocol from discovery method
                let protocol = match handshake.discovered_via {
                    0 => lib_network::protocols::NetworkProtocol::QUIC,
                    1 => lib_network::protocols::NetworkProtocol::BluetoothLE,
                    2 => lib_network::protocols::NetworkProtocol::WiFiDirect,
                    _ => lib_network::protocols::NetworkProtocol::QUIC,
                };
                
                // Create mesh connection
                let connection = lib_network::mesh::connection::MeshConnection {
                    peer_id: peer_pubkey.clone(),
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
                    let mut connections = self.connections.write().await;
                    connections.insert(peer_pubkey.clone(), connection);
                    info!("✅ Peer {} added to mesh network ({} total peers)", 
                        handshake.node_id, connections.len());
                }
                
                // Send acknowledgment
                let ack = bincode::serialize(&true)?;
                if let Err(e) = stream.write_all(&ack).await {
                    warn!("Failed to send ack to peer: {}", e);
                    return Ok(());
                }
                
                // Establish QUIC connection if available
                info!("🔐 Establishing QUIC connection to peer {} at {}", handshake.node_id, addr);
                
                if let Some(quic) = self.quic_protocol.read().await.as_ref() {
                    match quic.connect_to_peer(addr).await {
                        Ok(()) => {
                            info!("✅ QUIC connection established (TLS 1.3 + Kyber PQC)");
                            let mut connections = self.connections.write().await;
                            if let Some(conn) = connections.get_mut(&peer_pubkey) {
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
                
                // Attempt authentication (optional for new nodes)
                info!("🔐 Attempting blockchain authentication with peer {} (optional for new nodes)", 
                      handshake.node_id);
                info!("   New nodes can:");
                info!("     ✓ Create blockchain identity via /api/v1/identity/create");
                info!("     ✓ Access bootstrap info via /api/v1/bootstrap");  
                info!("   After identity creation, full authentication unlocks:");
                info!("     → DHT content storage/retrieval");
                info!("     → Blockchain transaction submission");
                info!("     → Mesh routing and relay services");
                
                match self.authenticate_and_register_peer(&peer_pubkey, &handshake, &addr, &mut stream).await {
                    Ok(true) => {
                        info!("✅ Peer {} AUTHENTICATED - Full network access granted", handshake.node_id);
                        info!("   → Can submit transactions");
                        info!("   → Can store/retrieve DHT content");
                        info!("   → Can participate in blockchain consensus");
                    }
                    Ok(false) | Err(_) => {
                        info!("ℹ️  Peer {} connected WITHOUT authentication - Bootstrap mode active", 
                              handshake.node_id);
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
    
    /// Authenticate and register a peer using lib-network authentication
    /// 
    /// This is a thin wrapper that delegates to lib-network::protocols::zhtp_auth
    /// for all authentication logic.
    /// 
    /// Returns: Ok(true) if fully authenticated, Ok(false) if unauthenticated but connection kept
    pub async fn authenticate_and_register_peer(
        &self,
        peer_pubkey: &PublicKey,
        handshake: &MeshHandshake,
        addr: &SocketAddr,
        stream: &mut TcpStream,
    ) -> Result<bool> {
        let node_id = &handshake.node_id;
        
        // ============================================================================
        // All authentication logic delegated to lib-network::protocols::zhtp_auth
        // ============================================================================
        
        if let Some(auth_manager) = self.zhtp_auth_manager.read().await.as_ref() {
            // Phase 2: Create authentication challenge
            match auth_manager.create_challenge().await {
                Ok(challenge) => {
                    info!("📤 Sending authentication challenge to peer {}", node_id);
                    
                    // Send challenge over TCP
                    let challenge_bytes = bincode::serialize(&challenge)?;
                    if let Err(e) = stream.write_all(&challenge_bytes).await {
                        warn!("Failed to send auth challenge to {}: {}", node_id, e);
                        return Ok(false);
                    }
                    
                    // Receive response with timeout
                    let mut response_buf = vec![0; 16384];
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        stream.read(&mut response_buf)
                    ).await {
                        Ok(Ok(response_len)) if response_len > 0 => {
                            match bincode::deserialize::<ZhtpAuthResponse>(&response_buf[..response_len]) {
                                Ok(auth_response) => {
                                    info!("📥 Received authentication response from peer {}", node_id);
                                    
                                    // Verify signature using lib-network
                                    match auth_manager.verify_response(&auth_response).await {
                                        Ok(verification) if verification.authenticated => {
                                            info!("✅ Peer {} authenticated! Trust score: {:.2}", 
                                                node_id, verification.trust_score);
                                            
                                            // Update connection with blockchain identity
                                            let mut connections = self.connections.write().await;
                                            if let Some(connection) = connections.get_mut(peer_pubkey) {
                                                connection.zhtp_authenticated = true;
                                                connection.peer_dilithium_pubkey = Some(auth_response.responder_pubkey.clone());
                                                connection.trust_score = verification.trust_score;
                                            }
                                            
                                            // Continue with key exchange and DHT registration
                                            // (simplified for now - full implementation would delegate to lib-network)
                                            return Ok(true);
                                        }
                                        Ok(_) => {
                                            warn!("⚠️ Peer {} authentication failed (signature invalid)", node_id);
                                            self.connections.write().await.remove(peer_pubkey);
                                        }
                                        Err(e) => {
                                            warn!("Error verifying peer {} authentication: {}", node_id, e);
                                            self.connections.write().await.remove(peer_pubkey);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to deserialize auth response from {}: {}", node_id, e);
                                }
                            }
                        }
                        _ => {
                            warn!("Timeout or error receiving auth response from {}", node_id);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to create auth challenge: {}", e);
                }
            }
        } else {
            warn!("⚠️ ZHTP authentication manager not initialized, skipping authentication");
        }
        
        Ok(false)
    }
}
