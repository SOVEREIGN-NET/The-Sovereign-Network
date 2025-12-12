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
    /// # Ticket #162
    /// Routes all broadcasts through mesh_message_router instead of calling QUIC directly.
    pub async fn set_broadcast_receiver(
        &self, 
        mut receiver: tokio::sync::mpsc::UnboundedReceiver<lib_blockchain::BlockchainBroadcastMessage>
    ) {
        info!("📡 Blockchain broadcast channel connected to mesh router");
        
        let connections = self.connections.clone();
        let recent_blocks = self.recent_blocks.clone();
        let recent_transactions = self.recent_transactions.clone();
        let mesh_message_router = self.mesh_message_router.clone(); // Ticket #162: Use mesh router
        let broadcast_metrics = self.broadcast_metrics.clone();
        let identity_manager = self.identity_manager.clone();
        
        // Spawn task to process broadcast messages from blockchain
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    lib_blockchain::BlockchainBroadcastMessage::NewBlock(block) => {
                        info!("📡 Broadcasting new block {} to mesh network", block.height());
                        
                        // Serialize block
                        let block_data = match bincode::serialize(&block) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize block: {}", e);
                                continue;
                            }
                        };
                        
                        // Get local node's public key from identity manager
                        let sender_pubkey = if let Some(identity_mgr) = identity_manager.as_ref() {
                            let mgr = identity_mgr.read().await;
                            if let Some(identity) = mgr.list_identities().first() {
                                let pubkey_bytes = identity.public_key.as_bytes();
                                let mut key_id = [0u8; 32];
                                let len = pubkey_bytes.len().min(32);
                                key_id[..len].copy_from_slice(&pubkey_bytes[..len]);
                                lib_crypto::PublicKey {
                                    key_id,
                                    dilithium_pk: vec![],
                                    kyber_pk: vec![],
                                }
                            } else {
                                warn!("No identity available for sender - skipping block broadcast");
                                continue;
                            }
                        } else {
                            warn!("Identity manager not available - skipping block broadcast");
                            continue;
                        };
                        
                        // Create NewBlock message
                        let message = ZhtpMeshMessage::NewBlock {
                            block: block_data,
                            sender: sender_pubkey.clone(),
                            height: block.height(),
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)
                                .unwrap_or_default().as_secs(),
                        };
                        
                        // Ticket #162: Broadcast via mesh_message_router instead of calling QUIC directly
                        let conns = connections.read().await;
                        let router = mesh_message_router.read().await;
                        let mut success_count = 0;
                        
                        for peer_entry in conns.all_peers() {
                            let peer_pubkey = peer_entry.peer_id.public_key().clone();
                            
                            // Route through mesh network
                            match router.route_message(
                                message.clone(),
                                peer_pubkey.clone(),
                                sender_pubkey.clone()
                            ).await {
                                Ok(_) => {
                                    success_count += 1;
                                }
                                Err(e) => {
                                    debug!("Failed to route block to peer {:?}: {}",
                                           hex::encode(&peer_pubkey.key_id[..8]), e);
                                }
                            }
                        }
                        
                        info!("📤 Block {} broadcast to {} peers via mesh router", block.height(), success_count);
                        
                        // Update metrics
                        broadcast_metrics.write().await.blocks_sent += 1;
                        
                        // Mark as seen (prevent echo)
                        recent_blocks.write().await.insert(
                            block.header.hash(),
                            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                        );
                    }
                    
                    lib_blockchain::BlockchainBroadcastMessage::NewTransaction(tx) => {
                        debug!("📡 Broadcasting new transaction {} to mesh network", tx.hash());
                        
                        // Serialize transaction
                        let tx_data = match bincode::serialize(&tx) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize transaction: {}", e);
                                continue;
                            }
                        };
                        
                        // Get local node's public key from identity manager
                        let sender_pubkey = if let Some(identity_mgr) = identity_manager.as_ref() {
                            let mgr = identity_mgr.read().await;
                            if let Some(identity) = mgr.list_identities().first() {
                                let pubkey_bytes = identity.public_key.as_bytes();
                                let mut key_id = [0u8; 32];
                                let len = pubkey_bytes.len().min(32);
                                key_id[..len].copy_from_slice(&pubkey_bytes[..len]);
                                lib_crypto::PublicKey {
                                    key_id,
                                    dilithium_pk: vec![],
                                    kyber_pk: vec![],
                                }
                            } else {
                                warn!("No identity available for sender - skipping transaction broadcast");
                                continue;
                            }
                        } else {
                            warn!("Identity manager not available - skipping transaction broadcast");
                            continue;
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
                            fee: tx.fee, // Ticket #162: Extract actual fee from transaction
                        };
                        
                        // Ticket #162: Broadcast via mesh_message_router instead of calling QUIC directly
                        let conns = connections.read().await;
                        let router = mesh_message_router.read().await;
                        let mut success_count = 0;
                        
                        for peer_entry in conns.all_peers() {
                            let peer_pubkey = peer_entry.peer_id.public_key().clone();
                            
                            // Route through mesh network
                            match router.route_message(
                                message.clone(),
                                peer_pubkey.clone(),
                                sender_pubkey.clone()
                            ).await {
                                Ok(_) => {
                                    success_count += 1;
                                }
                                Err(e) => {
                                    debug!("Failed to route transaction to peer {:?}: {}",
                                           hex::encode(&peer_pubkey.key_id[..8]), e);
                                }
                            }
                        }
                        
                        debug!("📤 Transaction {} broadcast to {} peers via mesh router", tx.hash(), success_count);
                        
                        // Update metrics
                        broadcast_metrics.write().await.transactions_sent += 1;
                        
                        // Mark as seen (prevent echo)
                        recent_transactions.write().await.insert(
                            tx.hash(),
                            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                        );
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
    pub async fn set_blockchain_provider(
        &self, 
        provider: Arc<dyn lib_network::blockchain_sync::BlockchainProvider>
    ) {
        *self.blockchain_provider.write().await = Some(provider.clone());
        
        // Also inject into QUIC protocol's message handler
        if let Some(quic) = self.quic_protocol.read().await.as_ref() {
            if let Some(handler) = quic.message_handler.as_ref() {
                let mut handler_lock = handler.write().await;
                handler_lock.set_blockchain_provider(provider.clone());
                info!("✅ Blockchain provider injected into QUIC MeshMessageHandler");
            }
        }
        
        info!("⛓️ Blockchain provider configured for edge node sync");
    }
    
    /// Set edge sync manager for BLE device support
    pub async fn set_edge_sync_manager(
        &self, 
        manager: Arc<lib_network::blockchain_sync::EdgeNodeSyncManager>
    ) {
        *self.edge_sync_manager.write().await = Some(manager);
        info!("📱 Edge node sync manager configured for BLE support");
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
    /// 
    /// # Ticket #162
    /// Refactored to route through mesh_message_router instead of calling protocol methods directly.
    /// This ensures all messages are logged and can use any available transport (BLE, QUIC, WiFi).
    pub async fn send_to_peer(&self, peer_id: &PublicKey, message: ZhtpMeshMessage) -> Result<()> {
        info!("📤 Routing message to peer {:?} via mesh router",
              hex::encode(&peer_id.key_id[0..8.min(peer_id.key_id.len())]));

        // Get sender public key from identity manager
        let sender_pubkey = self.get_sender_public_key().await?;
        
        // Ticket #162: Route through mesh_message_router instead of calling protocols directly
        let router = self.mesh_message_router.read().await;
        let message_id = router.route_message(
            message,
            peer_id.clone(),
            sender_pubkey.clone()
        ).await.context("Failed to route message via mesh router")?;
        
        info!("✅ Message {} routed to peer {:?} via mesh", 
              message_id,
              hex::encode(&peer_id.key_id[..8]));
        
        // Track bytes sent for performance metrics (estimate 1KB per message)
        self.track_bytes_sent(1024).await;
        
        Ok(())
    }
    
    /// Broadcast message to all connected peers
    /// 
    /// # Ticket #162
    /// Refactored to route through mesh_message_router instead of calling QUIC protocol directly.
    /// This ensures all messages are logged and can use any available transport.
    pub async fn broadcast_to_peers(&self, message: ZhtpMeshMessage) -> Result<usize> {
        info!("📡 Broadcasting message to all connected peers via mesh router");
        
        // Get sender public key
        let sender_pubkey = self.get_sender_public_key().await?;
        
        // Get all connected peers
        let connections = self.connections.read().await;
        let all_peers = connections.all_peers();
        let peer_count = all_peers.len();
        
        info!("📤 Broadcasting to {} connected peers", peer_count);
        
        // Route message to each peer via mesh router
        let router = self.mesh_message_router.read().await;
        let mut success_count = 0;
        
        for peer_entry in all_peers {
            let peer_pubkey = peer_entry.peer_id.public_key().clone();
            
            // Ticket #162: Route through mesh_message_router
            match router.route_message(
                message.clone(),
                peer_pubkey.clone(),
                sender_pubkey.clone()
            ).await {
                Ok(message_id) => {
                    debug!("✅ Broadcast message {} routed to peer {:?}",
                           message_id,
                           hex::encode(&peer_pubkey.key_id[..8]));
                    success_count += 1;
                }
                Err(e) => {
                    warn!("⚠️  Failed to route broadcast to peer {:?}: {}",
                          hex::encode(&peer_pubkey.key_id[..8]), e);
                }
            }
        }
        
        // Track bytes sent (estimate 1KB per successful message)
        self.track_bytes_sent((1024 * success_count) as u64).await;
        info!("📤 Broadcast complete: {}/{} peers reached", success_count, peer_count);
        
        Ok(success_count)
    }
    
    // ========================================================================
    // ✅ PHASE 3: Blockchain Sync Integration with lib-network
    // 
    // Complements existing push/broadcast functionality with pull-side sync:
    // - EdgeNodeSyncManager: Headers-only sync with ZK bootstrap proofs
    // - SyncCoordinator: Prevents duplicate syncs across transports
    // ========================================================================
    
    /// Initialize edge node synchronization (headers-only for bandwidth-constrained devices)
    /// 
    /// # Arguments
    /// * `max_headers` - Rolling window size (recommended: 500 for ~100KB storage)
    pub async fn initialize_edge_sync(&self, max_headers: usize) {
        let sync_manager = Arc::new(lib_network::blockchain_sync::EdgeNodeSyncManager::new(max_headers));
        *self.edge_sync_manager.write().await = Some(sync_manager);
        info!("✅ Edge node sync manager initialized with {} header capacity", max_headers);
    }
    
    /// Synchronize blockchain from a specific peer using EdgeNodeSyncManager
    /// 
    /// Complements broadcast (push) with pull-side sync for catching up with network.
    /// Uses headers-only sync for bandwidth efficiency.
    /// 
    /// # Arguments
    /// * `peer_pubkey` - Public key of peer to sync from
    /// 
    /// # Returns
    /// * `Ok(request_id)` - ID of sync request for tracking
    pub async fn sync_blockchain_from_peer(&self, peer_pubkey: &PublicKey) -> Result<u64> {
        // Get edge sync manager
        let edge_sync = self.edge_sync_manager.read().await;
        let edge_sync_mgr = edge_sync.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Edge sync manager not initialized. Call initialize_edge_sync() first."))?;

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
            peer_pubkey,
            protocol.clone(),
            lib_network::blockchain_sync::SyncType::EdgeNode
        ).await;
        
        if !should_sync {
            return Err(anyhow::anyhow!("Already syncing with this peer via {:?}", protocol));
        }
        
        // Create sync request
        let (request_id, sync_message) = edge_sync_mgr.create_sync_request(peer_pubkey.clone()).await?;
        
        // Send sync request to peer
        self.send_to_peer(peer_pubkey, sync_message).await?;
        
        // Record sync start in coordinator
        self.sync_coordinator.start_sync(
            peer_pubkey,
            request_id,
            lib_network::blockchain_sync::SyncType::EdgeNode,
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
                &peer_pubkey,
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
    
    /// Add address to edge node sync tracking (for UTXO monitoring)
    pub async fn add_edge_sync_address(&self, address: Vec<u8>) -> Result<()> {
        let edge_sync = self.edge_sync_manager.read().await;
        let edge_sync_mgr = edge_sync.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Edge sync manager not initialized"))?;
        
        edge_sync_mgr.add_address(address).await;
        Ok(())
    }
    
    /// Get current edge node synchronization height
    pub async fn get_edge_sync_height(&self) -> Result<u64> {
        let edge_sync = self.edge_sync_manager.read().await;
        let edge_sync_mgr = edge_sync.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Edge sync manager not initialized"))?;
        
        Ok(edge_sync_mgr.current_height().await)
    }
    
    /// Check if edge node needs bootstrap proof for fast-sync
    pub async fn needs_bootstrap_proof(&self) -> Result<bool> {
        let edge_sync = self.edge_sync_manager.read().await;
        let edge_sync_mgr = edge_sync.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Edge sync manager not initialized"))?;
        
        Ok(edge_sync_mgr.needs_bootstrap_proof().await)
    }
}
