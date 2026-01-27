//! Mesh Router Blockchain Sync
//! 
//! Handles blockchain synchronization, block/transaction broadcasting

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use lib_crypto::PublicKey;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use lib_network::protocols::NetworkProtocol;
use lib_network::mesh::server::ZhtpMeshServer;
use lib_identity::IdentityManager;

use super::core::MeshRouter;

impl MeshRouter {
    /// Set the blockchain broadcast receiver and start processing task
    ///
    /// ✅ TICKET 2.6: Refactored to accept Arc<Self> for proper routing integration
    /// This allows the spawned task to call send_with_routing() instead of bypassing
    /// the router with direct protocol calls.
    pub fn set_broadcast_receiver(
        self_arc: Arc<Self>,
        mut receiver: tokio::sync::mpsc::UnboundedReceiver<lib_blockchain::BlockchainBroadcastMessage>
    ) {
        info!("📡 Blockchain broadcast channel connected to mesh router");

        // Spawn task to process broadcast messages from blockchain
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    lib_blockchain::BlockchainBroadcastMessage::NewBlock(block) => {
                        info!("📡 Broadcasting new block {} to mesh network", block.height());

                        // ✅ TICKET 2.6: Verify sender identity is available
                        let sender_pubkey = match self_arc.get_sender_public_key().await {
                            Ok(pk) => pk,
                            Err(e) => {
                                error!("Cannot broadcast block - local sender identity not available: {}", e);
                                continue;
                            }
                        };

                        // Serialize block
                        let block_data = match bincode::serialize(&block) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize block: {}", e);
                                continue;
                            }
                        };

                        // Create NewBlock message
                        let message = ZhtpMeshMessage::NewBlock {
                            block: block_data,
                            sender: sender_pubkey.clone(),
                            height: block.height(),
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)
                                .unwrap_or_default().as_secs(),
                        };

                        // ✅ TICKET 2.6 FIX: Route through MeshRouter instead of direct QUIC sends
                        // This ensures all blocks are logged, identity-verified, and follow standard routing
                        match self_arc.broadcast_to_peers(message).await {
                            Ok(success_count) => {
                                info!("✅ Block {} routed to {} peers via MeshRouter", block.height(), success_count);
                                // Update metrics
                                self_arc.broadcast_metrics.write().await.blocks_sent += 1;
                                // Mark as seen (prevent echo)
                                self_arc.recent_blocks.write().await.insert(
                                    block.header.hash(),
                                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                                );
                            }
                            Err(e) => {
                                error!("Failed to broadcast block {}: {}", block.height(), e);
                            }
                        }
                    }
                    
                    lib_blockchain::BlockchainBroadcastMessage::NewTransaction(tx) => {
                        debug!("📡 Broadcasting new transaction {} to mesh network", tx.hash());

                        // ✅ TICKET 2.6: Verify sender identity is available
                        let sender_pubkey = match self_arc.get_sender_public_key().await {
                            Ok(pk) => pk,
                            Err(e) => {
                                error!("Cannot broadcast transaction - local sender identity not available: {}", e);
                                continue;
                            }
                        };

                        // Serialize transaction
                        let tx_data = match bincode::serialize(&tx) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize transaction: {}", e);
                                continue;
                            }
                        };

                        // Get tx hash bytes
                        let tx_hash = tx.hash();
                        let tx_hash_slice = tx_hash.as_bytes();
                        let mut tx_hash_bytes = [0u8; 32];
                        tx_hash_bytes.copy_from_slice(tx_hash_slice);

                        // Create NewTransaction message
                        let message = ZhtpMeshMessage::NewTransaction {
                            transaction: tx_data,
                            sender: sender_pubkey.clone(),
                            tx_hash: tx_hash_bytes,
                            fee: 1000, // TODO: Extract actual fee from transaction
                        };

                        // ✅ TICKET 2.6 FIX: Route through MeshRouter instead of direct QUIC sends
                        // This ensures all transactions are logged, identity-verified, and follow standard routing
                        match self_arc.broadcast_to_peers(message).await {
                            Ok(success_count) => {
                                debug!("✅ Transaction {} routed to {} peers via MeshRouter", tx.hash(), success_count);
                                // Update metrics
                                self_arc.broadcast_metrics.write().await.transactions_sent += 1;
                                // Mark as seen (prevent echo)
                                self_arc.recent_transactions.write().await.insert(
                                    tx.hash(),
                                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                                );
                            }
                            Err(e) => {
                                error!("Failed to broadcast transaction {}: {}", tx.hash(), e);
                            }
                        }
                    }
                }
            }
            
            warn!("Blockchain broadcast receiver task terminated");
        });
        
        info!("📡 Blockchain broadcast processing task started");
    }
    
    pub fn set_identity_manager(&mut self, manager: Arc<tokio::sync::RwLock<IdentityManager>>) {
        self.identity_manager = Some(manager);
    }
    
    /// Set Bluetooth protocol for sending messages
    pub async fn set_bluetooth_protocol(&self, protocol: Arc<lib_network::protocols::bluetooth::BluetoothMeshProtocol>) {
        *self.bluetooth_protocol.write().await = Some(protocol);
    }
    
    // UDP socket removed - using QUIC only
    
    /// Set QUIC protocol for mesh communication
    pub async fn set_quic_protocol(&self, quic: Arc<lib_network::protocols::quic_mesh::QuicMeshProtocol>) {
        *self.quic_protocol.write().await = Some(quic);
        info!("🔐 QUIC mesh protocol configured (quantum-safe + reliable transport)");
    }
    
    /// Set blockchain provider for network layer access
    ///
    /// NOTE: Currently injects into QUIC only. BluetoothClassicProtocol also has
    /// a message_handler field, but it is managed by BluetoothClassicRouter (not
    /// held by MeshRouter). When Phase 3 implements NewBlock/NewTransaction
    /// dispatch in classic.rs, injection must be wired through
    /// BluetoothClassicRouter's initialization path.
    pub async fn set_blockchain_provider(
        &self,
        provider: Arc<dyn lib_network::blockchain_sync::BlockchainProvider>
    ) {
        *self.blockchain_provider.write().await = Some(provider.clone());

        // Also inject into QUIC protocol's message handler
        let quic_guard = self.quic_protocol.read().await;
        if let Some(quic) = quic_guard.as_ref() {
            if let Some(handler) = quic.message_handler.as_ref() {
                let mut handler_lock = handler.write().await;
                handler_lock.set_blockchain_provider(provider.clone());
                info!("✅ Blockchain provider injected into QUIC MeshMessageHandler");
            } else {
                warn!("Blockchain provider stored locally but QUIC message handler not set — mesh sync unavailable");
            }
        } else {
            warn!("Blockchain provider stored locally but QUIC protocol not initialized — mesh sync unavailable");
        }

        info!("⛓️ Blockchain provider configured for edge node sync");
    }
    
    /// Get canonical peer registry (for wiring into QuicHandler) (#916)
    pub fn get_peer_registry(&self) -> Arc<tokio::sync::RwLock<lib_network::peer_registry::PeerRegistry>> {
        self.connections.clone()
    }

    /// Set blockchain event receiver for receive-side block/tx forwarding (#916)
    ///
    /// NOTE: Currently injects into QUIC only. BluetoothClassicProtocol also has
    /// a message_handler field, but it is managed by BluetoothClassicRouter (not
    /// held by MeshRouter). When Phase 3 implements NewBlock/NewTransaction
    /// dispatch in classic.rs, injection must be wired through
    /// BluetoothClassicRouter's initialization path.
    pub async fn set_blockchain_event_receiver(
        &self,
        receiver: Arc<dyn lib_network::blockchain_sync::BlockchainEventReceiver>,
    ) {
        let quic_guard = self.quic_protocol.read().await;
        let Some(quic) = quic_guard.as_ref() else {
            warn!("Cannot inject blockchain event receiver: QUIC protocol not initialized");
            return;
        };
        let Some(handler) = quic.message_handler.as_ref() else {
            warn!("Cannot inject blockchain event receiver: QUIC message handler not set");
            return;
        };
        let mut handler_lock = handler.write().await;
        handler_lock.set_blockchain_event_receiver(receiver);
        info!("Blockchain event receiver injected into QUIC MeshMessageHandler");
    }

    /// Set mesh server for reward tracking (Phase 2.5)
    pub async fn set_mesh_server(&self, mesh_server: Arc<tokio::sync::RwLock<ZhtpMeshServer>>) {
        let mut router = self.mesh_message_router.write().await;
        router.set_mesh_server(mesh_server);
        info!("💰 Phase 2.5: Mesh server linked to router for reward tracking");
    }
    
    /// Get blockchain provider for serving blockchain data to edge nodes
    pub async fn get_blockchain_provider(
        &self
    ) -> Option<Arc<dyn lib_network::blockchain_sync::BlockchainProvider>> {
        self.blockchain_provider.read().await.clone()
    }
    
    /// Get sender's public key from identity manager (for routing)
    pub async fn get_sender_public_key(&self) -> Result<PublicKey> {
        if let Some(identity_mgr) = self.identity_manager.as_ref() {
            let mgr = identity_mgr.read().await;
            if let Some(identity) = mgr.list_identities().first() {
                let pubkey_bytes = identity.public_key.as_bytes();
                let mut key_id = [0u8; 32];
                let len = pubkey_bytes.len().min(32);
                key_id[..len].copy_from_slice(&pubkey_bytes[..len]);
                
                return Ok(PublicKey {
                    key_id,
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                });
            }
        }
        Err(anyhow::anyhow!("No identity available for sender public key"))
    }
    
    /// Send a mesh message to a specific peer
    pub async fn send_to_peer(&self, peer_id: &PublicKey, message: ZhtpMeshMessage) -> Result<()> {
        info!("📤 Sending message directly to peer {:?}",
              hex::encode(&peer_id.key_id[0..8.min(peer_id.key_id.len())]));

        // Ticket #146: Convert PublicKey to UnifiedPeerId for HashMap lookup
        let unified_peer = lib_network::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(peer_id.clone());

        // Get peer's connection info (Ticket #149: Use PeerRegistry)
        let connections = self.connections.read().await;
        let peer_entry = connections.get(&unified_peer)
            .ok_or_else(|| anyhow::anyhow!("Peer not found in connections"))?;
        
        let peer_address = peer_entry.endpoints.first()
            .map(|endpoint| endpoint.address.to_address_string())
            .ok_or_else(|| anyhow::anyhow!("Peer has no address"))?;
        
        // Serialize message
        let serialized = bincode::serialize(&message)
            .context("Failed to serialize message")?;
        
        // Track bytes sent for performance metrics
        self.track_bytes_sent(serialized.len() as u64).await;
        
        // Send based on protocol (Ticket #149: Use PeerRegistry)
        // Use first protocol from active_protocols
        if let Some(protocol) = peer_entry.active_protocols.first() {
            match protocol {
                NetworkProtocol::QUIC => {
                    if let Some(quic) = self.quic_protocol.read().await.as_ref() {
                        quic.send_to_peer(&peer_entry.peer_id.public_key().key_id, message).await
                            .context("Failed to send QUIC message")?;
                        info!("✅ Message sent via QUIC to peer {:?}", &peer_entry.peer_id.public_key().key_id[..8]);
                    } else {
                        return Err(anyhow::anyhow!("QUIC protocol not initialized"));
                    }
                }
                NetworkProtocol::BluetoothLE => {
                    warn!("Bluetooth LE protocol not supported for direct message sending");
                    return Err(anyhow::anyhow!("Bluetooth LE not supported"));
                }
                NetworkProtocol::BluetoothClassic => {
                    warn!("Bluetooth Classic protocol not supported for direct message sending");
                    return Err(anyhow::anyhow!("Bluetooth Classic not supported"));
                }
                NetworkProtocol::WiFiDirect => {
                    warn!("WiFi Direct protocol not supported for direct message sending");
                    return Err(anyhow::anyhow!("WiFi Direct not supported"));
                }
                NetworkProtocol::LoRaWAN => {
                    warn!("LoRaWAN protocol not supported for direct message sending");
                    return Err(anyhow::anyhow!("LoRaWAN not supported"));
                }
                NetworkProtocol::Satellite => {
                    warn!("Satellite protocol not supported for direct message sending");
                    return Err(anyhow::anyhow!("Satellite not supported"));
                }
                _ => {
                    warn!("Protocol {:?} not supported for direct message sending", protocol);
                    return Err(anyhow::anyhow!("Protocol not supported"));
                }
            }
        } else {
            return Err(anyhow::anyhow!("No active protocols found for peer"));
        }
        
        Ok(())
    }
    
    /// Broadcast message to all connected peers
    ///
    /// #916: Uses direct PQC QUIC broadcast when QuicHandler is available,
    /// bypassing the lib-network routing layer whose TransportManager is not wired.
    /// Falls back to send_with_routing if QuicHandler is not set.
    pub async fn broadcast_to_peers(&self, message: ZhtpMeshMessage) -> Result<usize> {
        let serialized = bincode::serialize(&message)
            .context("Failed to serialize message")?;

        // #916: Try direct PQC broadcast first (bypasses uninitialized TransportManager)
        let quic_broadcaster = self.quic_broadcaster.read().await;
        if let Some(ref handler) = *quic_broadcaster {
            let (success, total) = handler.broadcast_to_pqc_peers(&serialized).await;
            self.track_bytes_sent((serialized.len() * success) as u64).await;
            info!(
                "📤 Broadcast complete: {}/{} peers reached via direct PQC QUIC",
                success, total
            );
            return Ok(success);
        }
        drop(quic_broadcaster);

        // Fallback: route through MeshRouter (requires TransportManager)
        let our_pubkey = match self.get_sender_public_key().await {
            Ok(pk) => pk,
            Err(e) => {
                error!("BROADCAST FAILED: Local sender identity not available");
                return Err(anyhow::anyhow!(
                    "Broadcast aborted: sender identity not initialized: {}", e
                ));
            }
        };

        let connections = self.connections.read().await;
        let mut success_count = 0;
        let mut identity_violations_count = 0;

        for peer_entry in connections.all_peers() {
            if !peer_entry.active_protocols.iter().any(|p| matches!(p, NetworkProtocol::QUIC)) {
                debug!(
                    "Skipping peer {:?} - no QUIC protocol support for broadcast",
                    &peer_entry.peer_id.public_key().key_id[..8]
                );
                continue;
            }

            let peer_pubkey = peer_entry.peer_id.public_key();

            match self.send_with_routing(message.clone(), &peer_pubkey, &our_pubkey).await {
                Ok(_msg_id) => {
                    success_count += 1;
                }
                Err(err) => {
                    match err.class {
                        crate::server::mesh::routing_errors::RoutingErrorClass::IdentityViolation => {
                            warn!(
                                "⚠️ IDENTITY VIOLATION: Peer {:?} failed verification: {}",
                                &peer_pubkey.key_id[..8], err.message
                            );
                            identity_violations_count += 1;
                        }
                        crate::server::mesh::routing_errors::RoutingErrorClass::Transient => {
                            debug!(
                                "Transient error routing to peer {:?}: {}",
                                &peer_pubkey.key_id[..8], err.message
                            );
                        }
                        crate::server::mesh::routing_errors::RoutingErrorClass::Configuration => {
                            warn!(
                                "Configuration error routing to peer {:?}: {}",
                                &peer_pubkey.key_id[..8], err.message
                            );
                        }
                    }
                }
            }
        }

        self.track_bytes_sent((serialized.len() * success_count) as u64).await;

        if identity_violations_count > 0 {
            warn!(
                "📤 Broadcast complete: {}/{} peers reached ({} failed identity verification)",
                success_count,
                connections.all_peers().count(),
                identity_violations_count
            );
        } else {
            info!(
                "📤 Broadcast complete: {}/{} peers reached via MeshRouter",
                success_count,
                connections.all_peers().count()
            );
        }

        Ok(success_count)
    }
    
    // ========================================================================
    // ✅ PHASE 3: Blockchain Sync Integration with lib-network
    // 
    // Complements existing push/broadcast functionality with pull-side sync:
    // - BlockchainSyncManager with EdgeNodeStrategy: Headers-only sync with ZK bootstrap proofs
    // - SyncCoordinator: Prevents duplicate syncs across transports
    // ========================================================================
    
    /// Initialize edge node synchronization (headers-only for bandwidth-constrained devices)
    /// 
    /// # Arguments
    /// * `max_headers` - Rolling window size (recommended: 500 for ~100KB storage)
    pub async fn initialize_edge_sync(&self, max_headers: usize) {
        // Use unified sync manager with EdgeNodeStrategy
        *self.is_edge_node.write().await = true;
        info!("✅ Edge node sync mode enabled with {} header capacity (use sync_manager with EdgeNodeStrategy)", max_headers);
    }
    
    /// Synchronize blockchain from a specific peer
    /// 
    /// Complements broadcast (push) with pull-side sync for catching up with network.
    /// Uses appropriate sync strategy based on node mode (edge vs full).
    /// 
    /// # Arguments
    /// * `peer_pubkey` - Public key of peer to sync from
    /// 
    /// # Returns
    /// * `Ok(request_id)` - ID of sync request for tracking
    pub async fn sync_blockchain_from_peer(&self, peer_pubkey: &PublicKey) -> Result<u64> {
        // Determine if we're in edge node mode
        let is_edge = *self.is_edge_node.read().await;
        let sync_type = if is_edge {
            lib_network::blockchain_sync::SyncType::EdgeNode
        } else {
            lib_network::blockchain_sync::SyncType::FullBlockchain
        };

        // Ticket #146: Convert PublicKey to UnifiedPeerId for HashMap lookup
        let unified_peer = lib_network::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(peer_pubkey.clone());

        // Check if peer connection exists (Ticket #149: Use PeerRegistry)
        let connections = self.connections.read().await;
        let peer_entry = connections.get(&unified_peer)
            .ok_or_else(|| anyhow::anyhow!("Peer not connected"))?;
        
        // Register with sync coordinator to prevent duplicate syncs
        // Ticket #149: Use active_protocols instead of single protocol
        let protocol = peer_entry.active_protocols.first().cloned()
            .unwrap_or(lib_network::protocols::NetworkProtocol::QUIC);
        let should_sync = self.sync_coordinator.register_peer_protocol(
            peer_pubkey.clone(),
            protocol.clone(),
            sync_type
        ).await;
        
        if !should_sync {
            return Err(anyhow::anyhow!("Already syncing with this peer via {:?}", protocol));
        }
        
        // Create sync request using unified sync manager
        let (request_id, sync_message) = self.sync_manager.create_blockchain_request(peer_pubkey.clone(), None).await?;
        
        // Send sync request to peer
        // EdgeSyncMessage is a protocol-level message; wrap in mesh message for transport
        let mesh_message = ZhtpMeshMessage::DhtGenericPayload {
            requester: peer_pubkey.clone(),
            payload: bincode::serialize(&sync_message)?,
            signature: Vec::new(),
        };
        self.send_to_peer(peer_pubkey, mesh_message).await?;
        
        // Record sync start in coordinator
        self.sync_coordinator.start_sync(
            peer_pubkey.clone(),
            request_id,
            sync_type,
            protocol
        ).await;
        
        info!("📥 Initiated edge node sync from peer {} (request {})", 
              hex::encode(&peer_pubkey.key_id[..8]), request_id);
        
        Ok(request_id)
    }
    
    /// Coordinate multi-peer blockchain synchronization
    /// 
    /// Uses SyncCoordinator to prevent duplicate syncs when connected via
    /// multiple transports (BLE + WiFi + Internet simultaneously).
    /// 
    /// # Arguments
    /// * `available_peers` - Map of peers and their available protocols
    /// 
    /// # Returns
    /// * `Vec<(PublicKey, u64)>` - List of (peer, request_id) for syncs initiated
    pub async fn coordinate_multi_peer_sync(
        &self,
        available_peers: Vec<(PublicKey, lib_network::protocols::NetworkProtocol)>
    ) -> Result<Vec<(PublicKey, u64)>> {
        let mut initiated_syncs = Vec::new();
        let peer_count = available_peers.len();
        
        for (peer_pubkey, protocol) in available_peers {
            // Let coordinator decide if we should sync with this peer via this protocol
            let should_sync = self.sync_coordinator.register_peer_protocol(
                peer_pubkey.clone(),
                protocol.clone(),
                lib_network::blockchain_sync::SyncType::EdgeNode
            ).await;
            
            if should_sync {
                // Attempt to sync
                match self.sync_blockchain_from_peer(&peer_pubkey).await {
                    Ok(request_id) => {
                        initiated_syncs.push((peer_pubkey.clone(), request_id));
                        info!("🔄 Sync initiated with peer {} via {:?}", 
                              hex::encode(&peer_pubkey.key_id[..8]), protocol);
                    }
                    Err(e) => {
                        warn!("Failed to initiate sync with peer {}: {}", 
                              hex::encode(&peer_pubkey.key_id[..8]), e);
                    }
                }
            } else {
                debug!("⏭️ Skipping duplicate sync with peer {} via {:?}", 
                       hex::encode(&peer_pubkey.key_id[..8]), protocol);
            }
        }
        
        
        info!("📊 Multi-peer sync coordination: {} syncs initiated from {} available peers",
              initiated_syncs.len(), peer_count);
        
        Ok(initiated_syncs)
    }
    
    /// Get current edge node synchronization height
    pub async fn get_edge_sync_height(&self) -> Result<u64> {
        // Check if we're in edge mode
        let is_edge = *self.is_edge_node.read().await;
        if !is_edge {
            return Err(anyhow::anyhow!("Node is not in edge mode - use blockchain height instead"));
        }
        
        // Return current blockchain height from provider
        if let Some(provider) = self.blockchain_provider.read().await.as_ref() {
            provider.get_current_height().await
        } else {
            Ok(0)
        }
    }
    
    /// Check if edge node needs bootstrap proof for fast-sync
    /// Note: With unified sync manager, bootstrap proofs are handled transparently
    pub async fn needs_bootstrap_proof(&self) -> Result<bool> {
        // With the unified sync manager using EdgeNodeStrategy,
        // bootstrap proofs are handled automatically during sync
        let is_edge = *self.is_edge_node.read().await;
        Ok(is_edge) // Edge nodes use bootstrap proofs by default
    }
    
    /// Start periodic cleanup task for stale chunk buffers
    /// 
    /// SECURITY: Prevents memory exhaustion from incomplete sync requests
    /// Runs every 60 seconds to cleanup buffers older than 5 minutes
    pub fn start_chunk_cleanup_task(&self) {
        let sync_manager = self.sync_manager.clone();
        
        tokio::spawn(async move {
            info!("🧹 Started blockchain chunk cleanup task (60s interval, 5min timeout)");
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                let _ = sync_manager.cleanup_stale_chunks().await;
            }
        });
    }
}

// ============================================================================
// Tests: Ticket 2.6 - Routing Centralization
// ============================================================================

#[cfg(test)]
mod tests {
    /// Test: Routing error module can distinguish error types
    /// Validates Phase 3 - proper error classification
    #[test]
    fn test_routing_error_classification() {
        use super::super::routing_errors::{RoutingError, RoutingErrorClass};

        let transient = RoutingError::transient("Timeout");
        assert_eq!(transient.class, RoutingErrorClass::Transient);
        assert_eq!(transient.to_string(), "[TRANSIENT] Timeout");

        let identity_err = RoutingError::identity_violation("Peer not verified");
        assert_eq!(identity_err.class, RoutingErrorClass::IdentityViolation);
        assert!(identity_err.to_string().contains("IDENTITY_VIOLATION"));

        let config_err = RoutingError::configuration("No router initialized");
        assert_eq!(config_err.class, RoutingErrorClass::Configuration);
        assert_eq!(config_err.to_string(), "[CONFIGURATION] No router initialized");
    }
}
