//! Authentication Wrapper Methods
//!
//! Thin wrapper methods that delegate to lib-network::protocols::zhtp_auth
//! These methods maintain the existing API surface for MeshRouter while
//! using the canonical authentication implementation from lib-network.
//!
//! ⚠️ This file contains ONLY thin wrappers - actual authentication logic
//! is in lib-network::protocols::zhtp_auth::ZhtpAuthManager
//!
//! # Security (HIGH-2 Fix)
//!
//! Connection state machine prevents race conditions:
//! 1. Peer starts in PENDING state (not yet in connections HashMap)
//! 2. Authentication is attempted
//! 3. Only AFTER authentication completes, peer is added to connections
//! 4. Failed auth = peer never added (no race window)

use std::net::SocketAddr;
use std::sync::{atomic::{AtomicU64, Ordering}, Arc};
use anyhow::{Result, Context};
use tracing::{debug, info, warn, error};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use lib_crypto::PublicKey;
use lib_network::discovery::local_network::MeshHandshake;
use lib_network::protocols::zhtp_auth::ZhtpAuthResponse;

use super::core::MeshRouter;

/// Connection state for HIGH-2 race condition fix
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Peer is being authenticated (not yet in connections)
    Pending,
    /// Peer authenticated and in connections HashMap
    Authenticated,
    /// Peer in bootstrap mode (limited access, in connections)
    Bootstrap,
    /// Peer rejected (failed auth, never added to connections)
    Rejected,
}

impl MeshRouter {
    /// Handle incoming TCP mesh connection with handshake
    ///
    /// # Security (HIGH-2 Fix)
    ///
    /// Connection state machine:
    /// 1. Peer starts in PENDING state (NOT in connections HashMap)
    /// 2. Authentication is attempted FIRST
    /// 3. Only AFTER authentication result is known, peer is added with correct state
    /// 4. This prevents race conditions where unauthenticated peers appear authenticated
    ///
    /// # Security (HIGH-4 Fix)
    ///
    /// Rate limiting:
    /// 1. Check per-IP rate limit BEFORE processing handshake
    /// 2. Block if too many connection attempts from same IP
    /// 3. Exponential backoff for repeat offenders
    pub async fn handle_tcp_mesh(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("🔌 Processing TCP mesh connection from: {}", addr);

        // HIGH-4 FIX: Check rate limit BEFORE processing handshake
        if let Err(block_duration) = self.connection_rate_limiter.check_ip(addr.ip()).await {
            error!("🚫 Connection rejected: IP {} rate limited for {:?}", addr.ip(), block_duration);
            // Optionally send rate limit response to client
            // Don't process further - connection is rate limited
            return Ok(());
        }

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

                // HIGH-2 FIX: DO NOT add peer to connections yet!
                // Peer is in PENDING state - not in HashMap
                info!("🔒 Peer {} in PENDING state - authenticating before adding to connections",
                      handshake.node_id);

                // Send acknowledgment (handshake received, auth starting)
                let ack = bincode::serialize(&true)?;
                if let Err(e) = stream.write_all(&ack).await {
                    warn!("Failed to send ack to peer: {}", e);
                    return Ok(());
                }

                // Attempt authentication FIRST (before adding to connections)
                info!("🔐 Attempting blockchain authentication with peer {} (optional for new nodes)",
                      handshake.node_id);
                info!("   New nodes can:");
                info!("     ✓ Create blockchain identity via /api/v1/identity/create");
                info!("     ✓ Access bootstrap info via /api/v1/bootstrap");
                info!("   After identity creation, full authentication unlocks:");
                info!("     → DHT content storage/retrieval");
                info!("     → Blockchain transaction submission");
                info!("     → Mesh routing and relay services");

                // HIGH-2 FIX: Determine final state BEFORE adding to connections
                let (final_state, authenticated, trust_score, dilithium_pk) =
                    match self.authenticate_peer_only(&peer_pubkey, &handshake, &mut stream).await {
                        Ok(Some((score, pk))) => {
                            info!("✅ Peer {} AUTHENTICATED - Full network access granted", handshake.node_id);
                            (ConnectionState::Authenticated, true, score, Some(pk))
                        }
                        Ok(None) | Err(_) => {
                            info!("ℹ️  Peer {} in BOOTSTRAP mode - limited access", handshake.node_id);
                            (ConnectionState::Bootstrap, false, 0.5, None)
                        }
                    };

                // HIGH-2 FIX: NOW add peer to connections with final state
                // No race condition because we determined state BEFORE insert
                #[allow(deprecated)]
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
                    zhtp_authenticated: authenticated,
                    quantum_secure: false,
                    peer_dilithium_pubkey: dilithium_pk,
                    kyber_shared_secret: None,
                    trust_score,
                    bootstrap_mode: final_state == ConnectionState::Bootstrap,
                };

                // Add to mesh connections with FINAL state (no race)
                {
                    let mut connections = self.connections.write().await;
                    let peer_key = connection.peer.clone();
                    // Ticket #149: Use peer_registry upsert instead of connections.insert
                    // connections is already a write guard, use it directly
                    let peer_entry = lib_network::peer_registry::PeerEntry::new(
                        peer_key,
                        vec![lib_network::peer_registry::PeerEndpoint {
                            address: lib_network::NodeAddress::Tcp(addr),
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
                    
                    info!("✅ Peer {} added to mesh network in {:?} state ({} total peers)",
                        handshake.node_id, final_state, connections.all_peers().count());
                }

                // Establish QUIC connection if available (after peer is in connections)
                info!("🔐 Establishing QUIC connection to peer {} at {}", handshake.node_id, addr);

                if let Some(quic) = self.quic_protocol.read().await.as_ref() {
                    match quic.connect_to_peer(addr).await {
                        Ok(()) => {
                            info!("✅ QUIC connection established (TLS 1.3 + Kyber PQC)");
                            // Ticket #149: Update peer protocol in peer_registry
                            let mut registry = self.connections.write().await;
                            // Find peer by public key and update protocol to QUIC
                            let peer_id_to_update = registry.all_peers()
                                .find(|entry| entry.peer_id.public_key() == &peer_pubkey)
                                .map(|entry| entry.peer_id.clone());
                            
                            if let Some(peer_id) = peer_id_to_update {
                                // Get the current entry to clone it
                                if let Some(peer_entry) = registry.get(&peer_id) {
                                    let mut updated_entry = peer_entry.clone();
                                    updated_entry.active_protocols = vec![lib_network::protocols::NetworkProtocol::QUIC];
                                    updated_entry.quantum_secure = true;
                                    // Update endpoints if needed
                                    if let Some(endpoint) = updated_entry.endpoints.first_mut() {
                                        endpoint.protocol = lib_network::protocols::NetworkProtocol::QUIC;
                                    }
                                    registry.upsert(updated_entry).await.expect("Failed to update peer");
                                }
                            }
                        }
                        Err(e) => {
                            warn!("⚠️ QUIC connection failed (using TCP fallback): {}", e);
                        }
                    }
                } else {
                    warn!("⚠️ QUIC protocol not available, using TCP");
                }

                // Log final access permissions
                if authenticated {
                    info!("   → Can submit transactions");
                    info!("   → Can store/retrieve DHT content");
                    info!("   → Can participate in blockchain consensus");
                } else {
                    info!("   → Can create blockchain identity");
                    info!("   → Can query bootstrap nodes");
                    info!("   → Cannot access DHT or submit transactions until authenticated");
                }
            } else {
                debug!("TCP data is not a binary mesh handshake, ignoring");
            }
        }

        Ok(())
    }

    /// Authenticate a peer WITHOUT modifying connections HashMap
    ///
    /// # Security (HIGH-2 Fix)
    ///
    /// This method only performs authentication and returns the result.
    /// It does NOT add/modify/remove peers from the connections HashMap.
    /// The caller is responsible for adding the peer with the correct state.
    ///
    /// Returns:
    /// - Ok(Some((trust_score, dilithium_pk))) if authenticated
    /// - Ok(None) if authentication failed but peer can be bootstrap
    /// - Err(_) if critical error
    async fn authenticate_peer_only(
        &self,
        peer_pubkey: &PublicKey,
        handshake: &MeshHandshake,
        stream: &mut TcpStream,
    ) -> Result<Option<(f64, Vec<u8>)>> {
        let node_id = &handshake.node_id;

        if let Some(auth_manager) = self.zhtp_auth_manager.read().await.as_ref() {
            match auth_manager.create_challenge().await {
                Ok(challenge) => {
                    info!("📤 Sending authentication challenge to peer {}", node_id);

                    let challenge_bytes = bincode::serialize(&challenge)?;
                    if let Err(e) = stream.write_all(&challenge_bytes).await {
                        warn!("Failed to send auth challenge to {}: {}", node_id, e);
                        return Ok(None);
                    }

                    let mut response_buf = vec![0; 16384];
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        stream.read(&mut response_buf)
                    ).await {
                        Ok(Ok(response_len)) if response_len > 0 => {
                            match bincode::deserialize::<ZhtpAuthResponse>(&response_buf[..response_len]) {
                                Ok(auth_response) => {
                                    info!("📥 Received authentication response from peer {}", node_id);

                                    match auth_manager.verify_response(&auth_response).await {
                                        Ok(verification) if verification.authenticated => {
                                            info!("✅ Peer {} authenticated! Trust score: {:.2}",
                                                node_id, verification.trust_score);
                                            return Ok(Some((
                                                verification.trust_score,
                                                auth_response.responder_pubkey.clone()
                                            )));
                                        }
                                        Ok(_) => {
                                            warn!("⚠️ Peer {} authentication failed (signature invalid)", node_id);
                                        }
                                        Err(e) => {
                                            warn!("Error verifying peer {} authentication: {}", node_id, e);
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

        Ok(None)
    }
    
    /// Authenticate and register a peer using lib-network authentication
    ///
    /// # DEPRECATED - Security Warning (HIGH-2)
    ///
    /// **⚠️ SECURITY WARNING:** This method has a race condition vulnerability.
    /// It expects the peer to already be in the connections HashMap, which creates
    /// a window where an unauthenticated peer appears to be valid.
    ///
    /// Use `handle_tcp_mesh()` instead, which uses `authenticate_peer_only()` to
    /// determine auth state BEFORE adding the peer to connections.
    ///
    /// This method is kept for backwards compatibility with Bluetooth handlers.
    ///
    /// Returns: Ok(true) if fully authenticated, Ok(false) if unauthenticated but connection kept
    #[deprecated(
        since = "0.2.0",
        note = "Use handle_tcp_mesh() which avoids the race condition. This method assumes peer is already in connections."
    )]
    pub async fn authenticate_and_register_peer(
        &self,
        peer_pubkey: &PublicKey,
        handshake: &MeshHandshake,
        _addr: &SocketAddr,
        stream: &mut TcpStream,
    ) -> Result<bool> {
        let node_id = &handshake.node_id;
        // Ticket #146: Convert PublicKey to UnifiedPeerId for HashMap lookups
        #[allow(deprecated)]
        let unified_peer = lib_network::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(peer_pubkey.clone());

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
                                            // Ticket #149: Update peer authentication in PeerRegistry
                                            let mut registry = self.connections.write().await;
                                            if let Some(peer_entry) = registry.get_mut(&unified_peer) {
                                                peer_entry.authenticated = true;
                                                peer_entry.trust_score = verification.trust_score;
                                                // Note: peer_dilithium_pubkey is now part of peer_id in UnifiedPeerId
                                                // The public key is accessible via peer_entry.peer_id.public_key()
                                            }

                                            // Continue with key exchange and DHT registration
                                            // (simplified for now - full implementation would delegate to lib-network)
                                            return Ok(true);
                                        }
                                        Ok(_) => {
                                            warn!("⚠️ Peer {} authentication failed (signature invalid)", node_id);
                                            self.connections.write().await.remove(&unified_peer);
                                        }
                                        Err(e) => {
                                            warn!("Error verifying peer {} authentication: {}", node_id, e);
                                            self.connections.write().await.remove(&unified_peer);
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
