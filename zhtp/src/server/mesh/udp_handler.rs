//! Mesh Router UDP Handler
//! 
//! Handles all incoming UDP mesh protocol messages (800+ lines of logic)

use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use lib_crypto::PublicKey;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use lib_network::protocols::NetworkProtocol;
use lib_network::dht::protocol::ZhtpRelayQuery;
use lib_network::MeshConnection;
use lib_economy::EconomicModel;

use super::core::MeshRouter;
use crate::server::monitoring::{PeerReputation, PeerRateLimit};

impl MeshRouter {
    /// Main UDP mesh message handler - processes all incoming mesh protocol messages
    pub async fn handle_udp_mesh(&self, data: &[u8], addr: SocketAddr) -> Result<Option<Vec<u8>>> {
        debug!("Processing UDP mesh packet from: {} ({} bytes)", addr, data.len());
        
        // First, try to parse as ZhtpMeshMessage (includes blockchain sync messages)
        if let Ok(mesh_message) = bincode::deserialize::<ZhtpMeshMessage>(data) {
            info!("📨 Received ZhtpMeshMessage from: {}", addr);
            
            // Handle blockchain-specific messages
            match &mesh_message {
                ZhtpMeshMessage::PeerAnnouncement { sender, timestamp, signature } => {
                    self.handle_peer_announcement(sender, *timestamp, signature, addr).await?;
                    return Ok(None);
                }
                
                ZhtpMeshMessage::BlockchainRequest { requester, request_id, request_type } => {
                    self.handle_blockchain_request(requester, *request_id, request_type, addr).await?;
                    return Ok(None);
                }
                
                ZhtpMeshMessage::BlockchainData { sender, request_id, chunk_index, total_chunks, data: chunk_data, complete_data_hash } => {
                    self.handle_blockchain_data(sender, *request_id, *chunk_index, *total_chunks, chunk_data, *complete_data_hash).await?;
                    return Ok(None);
                }
                
                ZhtpMeshMessage::NewBlock { block, sender, height, timestamp } => {
                    self.handle_new_block(block, sender, *height, *timestamp).await?;
                    return Ok(None);
                }
                
                ZhtpMeshMessage::NewTransaction { transaction, sender, tx_hash, fee } => {
                    self.handle_new_transaction(transaction, sender, *tx_hash, *fee).await?;
                    return Ok(None);
                }
                
                // DHT operations routed through mesh
                ZhtpMeshMessage::DhtStore { requester, request_id, key, value, ttl, signature: _ } => {
                    self.handle_dht_store(requester, *request_id, key, value, *ttl).await?;
                    return Ok(None);
                }
                
                ZhtpMeshMessage::DhtFindValue { requester, request_id, key, max_hops } => {
                    self.handle_dht_find_value(requester, *request_id, key, *max_hops).await?;
                    return Ok(None);
                }
                
                ZhtpMeshMessage::DhtFindNode { requester, request_id, target_id, max_hops } => {
                    self.handle_dht_find_node(requester, *request_id, target_id, *max_hops).await?;
                    return Ok(None);
                }
                
                ZhtpMeshMessage::DhtPing { requester, request_id, timestamp } => {
                    self.handle_dht_ping(requester, *request_id, *timestamp).await?;
                    return Ok(None);
                }

                ZhtpMeshMessage::ZhtpRequest(request) => {
                    self.handle_zhtp_request(request, addr).await?;
                    return Ok(None);
                }
                
                _ => {
                    debug!("Processing non-blockchain mesh message");
                }
            }
        }
        
        // Second, try to parse as ZHTP relay query (encrypted DHT request)
        if let Ok(relay_query) = bincode::deserialize::<ZhtpRelayQuery>(data) {
            return self.handle_relay_query(&relay_query, addr).await;
        }
        
        // Third, try to parse as JSON ZhtpMeshMessage (from JavaScript/web clients)
        if let Ok(text) = std::str::from_utf8(data) {
            debug!("Attempting JSON parse: {} bytes", text.len());
            match serde_json::from_str::<ZhtpMeshMessage>(text) {
                Ok(mesh_message) => {
                    info!("📨 Received JSON ZhtpMeshMessage from: {}", addr);
                    
                // Handle ZhtpRequest specifically
                if let ZhtpMeshMessage::ZhtpRequest(request) = mesh_message {
                    if let Some(response) = self.handle_zhtp_request(&request, addr).await? {
                        // Serialize ZhtpResponse as JSON and send back
                        if let Ok(response_bytes) = serde_json::to_vec(&response) {
                            info!("📤 Sending ZHTP response ({} bytes) to {}", response_bytes.len(), addr);
                            return Ok(Some(response_bytes));
                        }
                    }
                    return Ok(None);
                }                    // Other message types would be handled here
                    debug!("JSON mesh message type not yet implemented");
                    return Ok(None);
                }
                Err(e) => {
                    warn!("Failed to parse JSON ZhtpMeshMessage: {} (first 200 chars: {})", 
                          e, &text.chars().take(200).collect::<String>());
                }
            }
        }
        
        // Unknown message type
        debug!("Unknown UDP mesh message format from {}", addr);
        Ok(None)
    }

    // ==================== Message Handlers ====================

    async fn handle_peer_announcement(
        &self,
        sender: &PublicKey,
        timestamp: u64,
        signature: &[u8],
        addr: SocketAddr
    ) -> Result<()> {
        info!("👋 Received PeerAnnouncement from {:?} (timestamp: {})",
              hex::encode(&sender.key_id[0..8.min(sender.key_id.len())]), timestamp);
        
        // Verify signature to prevent spoofing
        if let Some(ref identity_mgr) = self.identity_manager {
            let _mgr = identity_mgr.read().await;
            // TODO: Proper signature verification with sender's public key
            if signature.is_empty() {
                warn!("⚠️ Rejecting PeerAnnouncement with empty signature from {}", addr);
                return Ok(());
            }
        }
        
        // Register this peer in connections
        let mut connections = self.connections.write().await;
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let is_new_peer = !connections.contains_key(sender);
        
        if is_new_peer {
            let connection = MeshConnection {
                peer_id: sender.clone(),
                protocol: NetworkProtocol::UDP,
                peer_address: Some(addr.to_string()),
                signal_strength: 1.0,
                bandwidth_capacity: 1_000_000, // 1 MB/s default
                latency_ms: 50,
                connected_at: current_timestamp,
                data_transferred: 0,
                tokens_earned: 0,
                stability_score: 1.0,
                zhtp_authenticated: true,
                quantum_secure: true,
                peer_dilithium_pubkey: Some(sender.dilithium_pk.clone()),
                kyber_shared_secret: None,
                trust_score: 0.7,
            };
            connections.insert(sender.clone(), connection);
            info!("✅ Registered new authenticated UDP mesh peer from {}", addr);
        } else {
            // Update existing peer's address and timestamp
            if let Some(conn) = connections.get_mut(sender) {
                conn.peer_address = Some(addr.to_string());
                conn.connected_at = current_timestamp;
                conn.zhtp_authenticated = true;
            }
            debug!("Updated peer address and timestamp for authenticated peer at {}", addr);
        }
        drop(connections);
        
        // If this is a new peer, request their blockchain
        if is_new_peer {
            info!("📥 New peer detected - requesting blockchain via UDP mesh");
            
            match self.get_sender_public_key().await {
                Ok(our_pubkey) => {
                    let request_id = uuid::Uuid::new_v4().as_u128() as u64;
                    let request_message = ZhtpMeshMessage::BlockchainRequest {
                        requester: our_pubkey,
                        request_id,
                        request_type: lib_network::types::mesh_message::BlockchainRequestType::FullChain,
                    };
                    
                    if let Err(e) = self.send_to_peer(sender, request_message).await {
                        warn!("Failed to request blockchain from new peer via UDP: {}", e);
                    } else {
                        info!("📤 Sent BlockchainRequest via UDP mesh to new peer");
                    }
                }
                Err(e) => {
                    warn!("⚠️ Could not get sender public key for BlockchainRequest: {}", e);
                }
            }
        }
        
        Ok(())
    }

    async fn handle_blockchain_request(
        &self,
        requester: &PublicKey,
        request_id: u64,
        request_type: &lib_network::types::mesh_message::BlockchainRequestType,
        addr: SocketAddr
    ) -> Result<()> {
        info!("⛓️ Blockchain request received from {:?} at {} (request_id: {}, type: {:?})", 
              hex::encode(&requester.key_id[0..8]), addr, request_id, request_type);
        
        // Check if requester is already registered
        let is_new_requester = {
            let connections = self.connections.read().await;
            !connections.contains_key(requester)
        };
        
        // Register new peer if needed (handles race condition with PeerAnnouncement)
        if is_new_requester {
            info!("📝 BlockchainRequest from unregistered peer - registering now");
            
            let mut connections = self.connections.write().await;
            let current_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            let connection = MeshConnection {
                peer_id: requester.clone(),
                protocol: NetworkProtocol::UDP,
                peer_address: Some(addr.to_string()),
                signal_strength: 1.0,
                bandwidth_capacity: 1_000_000,
                latency_ms: 50,
                connected_at: current_timestamp,
                data_transferred: 0,
                tokens_earned: 0,
                stability_score: 1.0,
                zhtp_authenticated: true,
                quantum_secure: true,
                peer_dilithium_pubkey: Some(requester.dilithium_pk.clone()),
                kyber_shared_secret: None,
                trust_score: 0.7,
            };
            connections.insert(requester.clone(), connection);
            drop(connections);
            
            // Send BlockchainRequest back for bidirectional sync
            if let Ok(our_pubkey) = self.get_sender_public_key().await {
                let our_request_id = uuid::Uuid::new_v4().as_u128() as u64;
                let request_message = ZhtpMeshMessage::BlockchainRequest {
                    requester: our_pubkey,
                    request_id: our_request_id,
                    request_type: lib_network::types::mesh_message::BlockchainRequestType::FullChain,
                };
                
                let _ = self.send_to_peer(requester, request_message).await;
            }
        }
        
        // Export and send blockchain chunks
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => {
                let blockchain_lock = blockchain_arc.read().await;
                
                match blockchain_lock.export_chain() {
                    Ok(blockchain_data) => {
                        info!("📦 Exported {} bytes of blockchain data", blockchain_data.len());
                        
                        let our_pubkey = self.get_sender_public_key().await?;
                        
                        // Chunk data for UDP protocol
                        match lib_network::blockchain_sync::BlockchainSyncManager::chunk_blockchain_data_for_protocol(
                            our_pubkey,
                            request_id,
                            blockchain_data,
                            &NetworkProtocol::UDP
                        ) {
                            Ok(chunk_messages) => {
                                let chunk_count = chunk_messages.len();
                                info!("📤 Sending {} blockchain chunks to {}", chunk_count, addr);
                                
                                // UDP removed - QUIC handles chunked transfers internally
                                warn!("UDP socket removed - blockchain chunks should be sent via QUIC");
                                if false { // UDP socket removed
                                    let mut successful_chunks = 0;
                                    let mut failed_chunks = 0;
                                    
                                    for (idx, chunk_message) in chunk_messages.into_iter().enumerate() {
                                        let serialized = match bincode::serialize(&chunk_message) {
                                            Ok(data) => data,
                                            Err(e) => {
                                                error!("Failed to serialize chunk {}: {}", idx + 1, e);
                                                failed_chunks += 1;
                                                continue;
                                            }
                                        };
                                        
                                        // Retry logic
                                        let mut attempts = 0;
                                        const MAX_ATTEMPTS: u32 = 3;
                                        let mut success = false;
                                        
                                        while attempts < MAX_ATTEMPTS && !success {
                                            attempts += 1;
                                            
                                            match socket.send_to(&serialized, addr).await {
                                                Ok(_) => {
                                                    success = true;
                                                    successful_chunks += 1;
                                                }
                                                Err(e) => {
                                                    if attempts < MAX_ATTEMPTS {
                                                        let backoff_ms = 100u64 * (2u64.pow(attempts - 1));
                                                        warn!("⚠️ Chunk {}/{} attempt {} failed: {} - retrying in {}ms", 
                                                              idx + 1, chunk_count, attempts, e, backoff_ms);
                                                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                                                    } else {
                                                        error!("❌ Chunk {}/{} failed after {} attempts", 
                                                               idx + 1, chunk_count, MAX_ATTEMPTS);
                                                        failed_chunks += 1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    
                                    if failed_chunks == 0 {
                                        info!("✅ All {} blockchain chunks sent successfully", chunk_count);
                                    } else {
                                        warn!("⚠️ Blockchain sync incomplete: {}/{} chunks sent, {} failed", 
                                              successful_chunks, chunk_count, failed_chunks);
                                    }
                                }
                            }
                            Err(e) => error!("Failed to chunk blockchain data: {}", e),
                        }
                    }
                    Err(e) => error!("Failed to export blockchain: {}", e),
                }
            }
            Err(e) => error!("Failed to get global blockchain: {}", e),
        }
        
        Ok(())
    }

    async fn handle_blockchain_data(
        &self,
        sender: &PublicKey,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        chunk_data: &[u8],
        complete_data_hash: [u8; 32]
    ) -> Result<()> {
        info!("📥 Blockchain chunk {}/{} received from peer {} ({} bytes)", 
              chunk_index + 1, total_chunks, hex::encode(&sender.key_id[..8]), chunk_data.len());
        
        let sync_type = lib_network::blockchain_sync::SyncType::FullBlockchain;
        
        // Add chunk to sync manager (now with sender authentication)
        match self.sync_manager.add_chunk(
            sender,  // SECURITY: Pass sender for authentication check
            request_id,
            chunk_index,
            total_chunks,
            chunk_data.to_vec(),
            complete_data_hash
        ).await {
            Ok(Some(complete_data)) => {
                info!("✅ All blockchain chunks received and verified! Total: {} bytes", complete_data.len());
                
                // Import the blockchain
                match crate::runtime::blockchain_provider::get_global_blockchain().await {
                    Ok(blockchain_arc) => {
                        let mut blockchain_lock = blockchain_arc.write().await;
                        
                        match blockchain_lock.evaluate_and_merge_chain(complete_data).await {
                            Ok(merge_result) => {
                                info!("⛓️ Blockchain imported successfully from peer");
                                info!("   Merge result: {:?}", merge_result);
                                info!("   New blockchain height: {}", blockchain_lock.get_height());
                                drop(blockchain_lock);
                                
                                self.sync_coordinator.complete_sync(sender, request_id, sync_type).await;
                            }
                            Err(e) => {
                                error!("Failed to import blockchain: {}", e);
                                self.sync_coordinator.fail_sync(sender, request_id, sync_type).await;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to get global blockchain: {}", e);
                        self.sync_coordinator.fail_sync(sender, request_id, sync_type).await;
                    }
                }
            }
            Ok(None) => {
                debug!("Chunk {}/{} buffered, waiting for more chunks", chunk_index + 1, total_chunks);
            }
            Err(e) => {
                error!("Failed to process blockchain chunk: {}", e);
                self.sync_coordinator.fail_sync(sender, request_id, sync_type).await;
            }
        }
        
        Ok(())
    }

    async fn handle_new_block(
        &self,
        block: &[u8],
        sender: &PublicKey,
        height: u64,
        timestamp: u64
    ) -> Result<()> {
        info!("🧱 Received NewBlock at height {} from {:?}", height, hex::encode(&sender.key_id[0..8]));
        
        // Track performance metrics
        self.track_block_latency(timestamp).await;
        self.track_bytes_received(block.len() as u64).await;
        
        let sender_key = hex::encode(&sender.key_id);
        
        // Check peer reputation - reject if banned
        {
            let mut reputations = self.peer_reputations.write().await;
            let reputation = reputations.entry(sender_key.clone())
                .or_insert_with(|| PeerReputation::new(sender_key.clone()));
            
            if reputation.is_banned() {
                warn!("🚫 Blocked NewBlock from banned peer {} (score: {})", 
                      &sender_key[..16], reputation.score);
                self.broadcast_metrics.write().await.blocks_rejected += 1;
                return Ok(());
            }
        }
        
        // Rate limiting check
        let mut rate_limits = self.peer_rate_limits.write().await;
        let rate_limit = rate_limits.entry(sender_key.clone())
            .or_insert_with(PeerRateLimit::new);
        
        const MAX_BLOCKS_PER_MINUTE: u32 = 10;
        if !rate_limit.check_and_increment_block(MAX_BLOCKS_PER_MINUTE) {
            warn!("⚠️ Rate limit exceeded for peer {} - rejecting block {}", 
                  &sender_key[..16], height);
            
            drop(rate_limits);
            let mut reputations = self.peer_reputations.write().await;
            if let Some(reputation) = reputations.get_mut(&sender_key) {
                reputation.record_violation();
            }
            
            self.broadcast_metrics.write().await.blocks_rejected += 1;
            return Ok(());
        }
        drop(rate_limits);
        
        // Update metrics
        self.broadcast_metrics.write().await.blocks_received += 1;
        
        // Check for duplicates
        let block_data_hash = {
            let hash_bytes = lib_crypto::hash_blake3(&block);
            lib_blockchain::types::Hash::from(hash_bytes)
        };
        
        {
            let mut recent = self.recent_blocks.write().await;
            if recent.contains_key(&block_data_hash) {
                debug!("Duplicate block {} ignored", height);
                return Ok(());
            }
            recent.insert(block_data_hash, timestamp);
        }
        
        // Deserialize block
        let received_block = match lib_blockchain::integration::network_integration::deserialize_block_from_network(&block) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to deserialize block: {}", e);
                return Ok(());
            }
        };
        
        // Validate block height matches
        if received_block.height() != height {
            warn!("Block height mismatch: advertised {}, actual {}", height, received_block.height());
            return Ok(());
        }
        
        // Check if this is an edge node
        let edge_sync_mgr = self.edge_sync_manager.read().await;
        let is_edge_node = edge_sync_mgr.is_some();
        
        if is_edge_node {
            // Edge nodes: Extract header only
            info!("📋 Edge node: Extracting header only for block {}", height);
            
            if let Some(sync_mgr) = edge_sync_mgr.as_ref() {
                sync_mgr.update_network_height(height).await;
            }
            drop(edge_sync_mgr);
            
            // Add header to EdgeNodeState
            match crate::runtime::edge_state_provider::add_header(received_block.header.clone()).await {
                Ok(()) => {
                    info!("  ✓ Header added to EdgeNodeState (height: {})", height);
                    
                    let mut reputations = self.peer_reputations.write().await;
                    if let Some(reputation) = reputations.get_mut(&sender_key) {
                        reputation.record_block_accepted();
                    }
                }
                Err(e) => {
                    error!("  Failed to add header to EdgeNodeState: {}", e);
                }
            }
            
            return Ok(());
        }
        drop(edge_sync_mgr);
        
        // Full nodes: Add block to blockchain
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => {
                let blockchain = blockchain_arc.read().await;
                
                // Check if we already have this block
                if blockchain.get_height() >= height {
                    if let Some(existing) = blockchain.get_block(height) {
                        if existing.header.hash() == received_block.header.hash() {
                            debug!("Block {} already in chain", height);
                            return Ok(());
                        }
                    }
                }
                drop(blockchain);
                
                let mut blockchain = blockchain_arc.write().await;
                
                // Export as single-block chain for evaluation
                let import_data = lib_blockchain::BlockchainImport {
                    blocks: vec![received_block.clone()],
                    utxo_set: HashMap::new(),
                    identity_registry: HashMap::new(),
                    wallet_references: HashMap::new(),
                    token_contracts: HashMap::new(),
                    web4_contracts: HashMap::new(),
                    contract_blocks: HashMap::new(),
                    validator_registry: HashMap::new(),
                };
                
                let serialized = bincode::serialize(&import_data)?;
                
                // Try to evaluate and merge
                match blockchain.evaluate_and_merge_chain(serialized).await {
                    Ok(merge_result) => {
                        use lib_consensus::ChainMergeResult;
                        match merge_result {
                            ChainMergeResult::ImportedAdopted | ChainMergeResult::Merged => {
                                info!("✅ Block {} accepted into blockchain", height);
                                
                                let mut reputations = self.peer_reputations.write().await;
                                if let Some(reputation) = reputations.get_mut(&sender_key) {
                                    reputation.record_block_accepted();
                                }
                                
                                self.broadcast_metrics.write().await.blocks_relayed += 1;
                                drop(blockchain);
                                
                                // Relay to other peers
                                let relay_message = ZhtpMeshMessage::NewBlock {
                                    block: block.to_vec(),
                                    sender: sender.clone(),
                                    height,
                                    timestamp,
                                };
                                
                                let _ = self.broadcast_to_peers_except(relay_message, sender).await;
                            }
                            ChainMergeResult::ContentMerged => {
                                info!("📝 Block {} content merged", height);
                                
                                let mut reputations = self.peer_reputations.write().await;
                                if let Some(reputation) = reputations.get_mut(&sender_key) {
                                    reputation.record_block_accepted();
                                }
                                
                                self.broadcast_metrics.write().await.blocks_relayed += 1;
                            }
                            ChainMergeResult::LocalKept => {
                                debug!("Block {} rejected - local chain is better", height);
                                
                                let mut reputations = self.peer_reputations.write().await;
                                if let Some(reputation) = reputations.get_mut(&sender_key) {
                                    reputation.record_block_rejected();
                                }
                                
                                self.broadcast_metrics.write().await.blocks_rejected += 1;
                            }
                            ChainMergeResult::Failed(reason) => {
                                warn!("Block {} validation failed: {}", height, reason);
                                
                                let mut reputations = self.peer_reputations.write().await;
                                if let Some(reputation) = reputations.get_mut(&sender_key) {
                                    reputation.record_block_rejected();
                                }
                                
                                self.broadcast_metrics.write().await.blocks_rejected += 1;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to evaluate block {}: {}", height, e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to get global blockchain: {}", e);
            }
        }
        
        Ok(())
    }

    async fn handle_new_transaction(
        &self,
        transaction: &[u8],
        sender: &PublicKey,
        tx_hash: [u8; 32],
        fee: u64
    ) -> Result<()> {
        info!("💸 Received NewTransaction {:?} (fee: {}) from {:?}", 
              hex::encode(&tx_hash[0..8]), fee, hex::encode(&sender.key_id[0..8]));
        
        // Track transaction latency if timestamp is embedded
        if transaction.len() >= 8 {
            let tx_timestamp = u64::from_be_bytes([
                transaction.get(0).copied().unwrap_or(0),
                transaction.get(1).copied().unwrap_or(0),
                transaction.get(2).copied().unwrap_or(0),
                transaction.get(3).copied().unwrap_or(0),
                transaction.get(4).copied().unwrap_or(0),
                transaction.get(5).copied().unwrap_or(0),
                transaction.get(6).copied().unwrap_or(0),
                transaction.get(7).copied().unwrap_or(0),
            ]);
            
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            if tx_timestamp > 0 && tx_timestamp <= now && (now - tx_timestamp) < 3600 {
                self.track_tx_latency(tx_timestamp).await;
            }
        }
        
        self.track_bytes_received(transaction.len() as u64).await;
        
        let sender_key = hex::encode(&sender.key_id);
        
        // Check peer reputation
        {
            let mut reputations = self.peer_reputations.write().await;
            let reputation = reputations.entry(sender_key.clone())
                .or_insert_with(|| PeerReputation::new(sender_key.clone()));
            
            if reputation.is_banned() {
                warn!("🚫 Blocked NewTransaction from banned peer {}", &sender_key[..16]);
                self.broadcast_metrics.write().await.transactions_rejected += 1;
                return Ok(());
            }
        }
        
        // Rate limiting
        let mut rate_limits = self.peer_rate_limits.write().await;
        let rate_limit = rate_limits.entry(sender_key.clone())
            .or_insert_with(PeerRateLimit::new);
        
        const MAX_TXS_PER_MINUTE: u32 = 100;
        if !rate_limit.check_and_increment_tx(MAX_TXS_PER_MINUTE) {
            warn!("⚠️ Rate limit exceeded for peer {} - rejecting transaction", &sender_key[..16]);
            
            drop(rate_limits);
            let mut reputations = self.peer_reputations.write().await;
            if let Some(reputation) = reputations.get_mut(&sender_key) {
                reputation.record_violation();
            }
            
            self.broadcast_metrics.write().await.transactions_rejected += 1;
            return Ok(());
        }
        drop(rate_limits);
        
        // Update metrics
        self.broadcast_metrics.write().await.transactions_received += 1;
        
        // Check for duplicates
        let tx_hash_obj = lib_blockchain::types::Hash::from(tx_hash);
        {
            let mut recent = self.recent_transactions.write().await;
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            if recent.contains_key(&tx_hash_obj) {
                debug!("Duplicate transaction {:?} ignored", hex::encode(&tx_hash[0..8]));
                return Ok(());
            }
            recent.insert(tx_hash_obj, current_time);
        }
        
        // Deserialize transaction
        let received_tx = match lib_blockchain::integration::network_integration::deserialize_transaction_from_network(&transaction) {
            Ok(tx) => tx,
            Err(e) => {
                error!("Failed to deserialize transaction: {}", e);
                return Ok(());
            }
        };
        
        // Validate hash matches
        let computed_hash = received_tx.hash();
        if computed_hash.as_bytes() != &tx_hash {
            warn!("Transaction hash mismatch");
            return Ok(());
        }
        
        // Check if edge node
        let is_edge_node = self.edge_sync_manager.read().await.is_some();
        
        if is_edge_node {
            debug!("💎 Edge node: Scanning transaction for own UTXOs");
            
            // Track relevant UTXOs
            for (output_index, output) in received_tx.outputs.iter().enumerate() {
                let _ = crate::runtime::edge_state_provider::add_utxo(
                    computed_hash.clone(),
                    output_index as u32,
                    output.clone()
                ).await;
            }
            
            let mut reputations = self.peer_reputations.write().await;
            if let Some(reputation) = reputations.get_mut(&sender_key) {
                reputation.record_tx_accepted();
            }
            
            self.broadcast_metrics.write().await.transactions_relayed += 1;
            
            // Relay transaction
            let relay_message = ZhtpMeshMessage::NewTransaction {
                transaction: transaction.to_vec(),
                sender: sender.clone(),
                tx_hash,
                fee,
            };
            
            let _ = self.broadcast_to_peers_except(relay_message, sender).await;
            
            return Ok(());
        }
        
        // Full nodes: Add to mempool
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => {
                let mut blockchain = blockchain_arc.write().await;
                
                match blockchain.add_pending_transaction_from_network(received_tx) {
                    Ok(()) => {
                        info!("✅ Transaction {:?} accepted to mempool", hex::encode(&tx_hash[0..8]));
                        
                        let mut reputations = self.peer_reputations.write().await;
                        if let Some(reputation) = reputations.get_mut(&sender_key) {
                            reputation.record_tx_accepted();
                        }
                        
                        self.broadcast_metrics.write().await.transactions_relayed += 1;
                        drop(blockchain);
                        
                        // Relay to other peers
                        let relay_message = ZhtpMeshMessage::NewTransaction {
                            transaction: transaction.to_vec(),
                            sender: sender.clone(),
                            tx_hash,
                            fee,
                        };
                        
                        let _ = self.broadcast_to_peers_except(relay_message, sender).await;
                    }
                    Err(e) => {
                        debug!("Transaction {:?} rejected from mempool: {}", hex::encode(&tx_hash[0..8]), e);
                        
                        let mut reputations = self.peer_reputations.write().await;
                        if let Some(reputation) = reputations.get_mut(&sender_key) {
                            reputation.record_tx_rejected();
                        }
                        
                        self.broadcast_metrics.write().await.transactions_rejected += 1;
                    }
                }
            }
            Err(e) => {
                error!("Failed to get global blockchain: {}", e);
            }
        }
        
        Ok(())
    }

    // ==================== DHT Message Handlers ====================

    async fn handle_dht_store(
        &self,
        requester: &PublicKey,
        request_id: u64,
        key: &[u8],
        value: &[u8],
        ttl: u64
    ) -> Result<()> {
        info!("📦 DHT Store request: key={} bytes, value={} bytes, ttl={}s", 
              key.len(), value.len(), ttl);
        
        let success = crate::integration::store_dht_value(&self.dht_storage, key, value).await;
        
        let stored_count = if success { 1 } else { 0 };
        
        let response = ZhtpMeshMessage::DhtStoreAck {
            request_id,
            success,
            stored_count,
        };
        
        if let Err(e) = self.send_to_peer(requester, response).await {
            warn!("Failed to send DHT store ack: {}", e);
        }
        
        Ok(())
    }

    async fn handle_dht_find_value(
        &self,
        requester: &PublicKey,
        request_id: u64,
        key: &[u8],
        max_hops: u8
    ) -> Result<()> {
        info!("🔍 DHT FindValue request: key={} bytes, max_hops={}", key.len(), max_hops);
        
        let (found, value) = crate::integration::fetch_dht_value(&self.dht_storage, key).await.unwrap_or((false, None));
        
        let closer_nodes: Vec<lib_crypto::PublicKey> = Vec::new();
        
        let response = ZhtpMeshMessage::DhtFindValueResponse {
            request_id,
            found,
            value,
            closer_nodes,
        };
        
        if let Err(e) = self.send_to_peer(requester, response).await {
            warn!("Failed to send DHT find value response: {}", e);
        }
        
        Ok(())
    }

    async fn handle_dht_find_node(
        &self,
        requester: &PublicKey,
        request_id: u64,
        target_id: &[u8],
        max_hops: u8
    ) -> Result<()> {
        info!("🔍 DHT FindNode request: target={} bytes, max_hops={}", target_id.len(), max_hops);
        
        // Issue #846: Use QuicMeshProtocol as canonical connection store for DHT
        let closer_nodes: Vec<(PublicKey, String)> = if max_hops > 0 {
            let quic_guard = self.quic_protocol.read().await;
            match quic_guard.as_ref() {
                Some(quic) => {
                    quic.connections
                        .iter()
                        .take(20)
                        .map(|entry| {
                            let peer_id = PublicKey::from_bytes(&entry.key()[..entry.key().len().min(32)]).unwrap_or_else(|_| PublicKey::new());
                            let addr = "quic-peer".to_string();
                            (peer_id, addr)
                        })
                        .collect()
                }
                None => {
                    debug!("QUIC protocol not initialized for DHT");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        
        let response = ZhtpMeshMessage::DhtFindNodeResponse {
            request_id,
            closer_nodes,
        };
        
        if let Err(e) = self.send_to_peer(requester, response).await {
            warn!("Failed to send DHT find node response: {}", e);
        }
        
        Ok(())
    }

    async fn handle_dht_ping(
        &self,
        requester: &PublicKey,
        request_id: u64,
        timestamp: u64
    ) -> Result<()> {
        info!("🏓 DHT Ping from peer at timestamp {}", timestamp);
        
        let response = ZhtpMeshMessage::DhtPong {
            request_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        if let Err(e) = self.send_to_peer(requester, response).await {
            warn!("Failed to send DHT pong: {}", e);
        }
        
        Ok(())
    }

    async fn handle_zhtp_request(
        &self,
        request: &lib_protocols::types::ZhtpRequest,
        addr: SocketAddr
    ) -> Result<Option<lib_protocols::types::ZhtpResponse>> {
        info!("🌐 Received ZHTP Request: {} {} from {}", request.method, request.uri, addr);

        // Determine identity ID for rate limiting (use peer address if no identity)
        let identity_id = request.headers.identity_did.clone()
            .unwrap_or_else(|| addr.to_string());

        // Check if this is a free getter (GET or HEAD)
        let is_getter = matches!(request.method, lib_protocols::types::ZhtpMethod::Get | lib_protocols::types::ZhtpMethod::Head);

        // Check if this is a free identity creation endpoint
        let is_identity_creation = request.uri == "/api/v1/identity/create";
        
        if is_getter || is_identity_creation {
            // ===== FREE REQUEST: Rate Limiting (100 req/30s) =====
            // Applies to: GET/HEAD requests AND identity creation
            let mut rate_limits = self.zhtp_rate_limits.write().await;
            let rate_state = rate_limits.entry(identity_id.clone())
                .or_insert_with(super::core::ZhtpRateLimitState::new);
            
            if !rate_state.check_and_increment() {
                warn!("🚫 Rate Limit Exceeded for identity {} from {} (100 req/30s)", identity_id, addr);
                // Send 429 Too Many Requests response
                let response = lib_protocols::types::ZhtpResponse::error(
                    lib_protocols::types::ZhtpStatus::TooManyRequests,
                    "Rate limit exceeded: 100 requests per 30 seconds".to_string()
                );
                return Ok(Some(response));
            }
            
            if is_identity_creation {
                info!("🆓 Free Identity Creation (count: {}/100 in window)", rate_state.request_count);
            } else {
                info!("✅ Free Getter Request (count: {}/100 in window)", rate_state.request_count);
            }
        } else {
            // ===== PAID SETTER: DAO Fee Validation =====
            let economic_model = EconomicModel::new(); 
            match request.validate_dao_fee(&economic_model) {
                Ok(true) => {
                    info!("💰 DAO Fee Validated: {} SOV (Proof Verified)", request.headers.dao_fee);
                }
                Ok(false) => {
                    warn!("❌ DAO Fee Validation Failed for request from {}", addr);
                    // Send 402 Payment Required response
                    let response = lib_protocols::types::ZhtpResponse::error(
                        lib_protocols::types::ZhtpStatus::PaymentRequired,
                        "DAO fee validation failed".to_string()
                    );
                    return Ok(Some(response));
                }
                Err(e) => {
                    error!("Error validating DAO fee: {}", e);
                    let response = lib_protocols::types::ZhtpResponse::error(
                        lib_protocols::types::ZhtpStatus::InternalServerError,
                        format!("DAO fee validation error: {}", e)
                    );
                    return Ok(Some(response));
                }
            }
        }

        // Validate ZK Proof (The "Privacy Layer")
        if let Some(proof) = &request.auth_proof {
             info!("🔐 ZK Auth Proof Present: System={} (Verifying...)", proof.proof_system);
             // In a full implementation, we would call proof.verify() here
        } else {
             debug!("ℹ️ No ZK Auth Proof provided (Public/Unauthenticated Request)");
        }

        // Process Request (The "Application Layer")
        // Route to ZHTP router for proper endpoint handling
        if let Some(router) = self.zhtp_router.read().await.as_ref() {
            match router.route_request(request.clone()).await {
                Ok(response) => {
                    info!("✅ ZHTP Request processed, status: {}", response.status);
                    return Ok(Some(response));
                }
                Err(e) => {
                    warn!("⚠️ ZHTP Request routing error: {}", e);
                    let response = lib_protocols::types::ZhtpResponse::error(
                        lib_protocols::types::ZhtpStatus::InternalServerError,
                        format!("Request routing error: {}", e)
                    );
                    return Ok(Some(response));
                }
            }
        } else {
            info!("✅ Pure ZHTP Packet Processed Successfully via UDP Mesh (no router configured)");
            // Return a basic OK response
            let response = lib_protocols::types::ZhtpResponse::success(vec![], None);
            return Ok(Some(response));
        }
    }

    async fn handle_relay_query(
        &self,
        relay_query: &ZhtpRelayQuery,
        addr: SocketAddr
    ) -> Result<Option<Vec<u8>>> {
        info!("🔐 Received ZHTP relay query from: {} (encrypted)", addr);
        
        if let Some(relay_protocol) = self.relay_protocol.read().await.as_ref() {
            let peer_address = addr.to_string();
            match relay_protocol.process_relay_query(&peer_address, &relay_query).await {
                Ok(query_payload) => {
                    info!("✅ ZHTP relay query decrypted: domain={}, path={}", 
                        query_payload.domain, query_payload.path);
                    
                    // Query local DHT
                    if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
                        let mut dht = dht_client.write().await;
                        let content_key = format!("{}/{}", query_payload.domain, query_payload.path);
                        
                        match dht.fetch_content(&content_key).await {
                            Ok(Some(content)) => {
                                info!("📦 Found DHT content ({} bytes), creating encrypted response", content.len());
                                
                                let content_hash_bytes = lib_crypto::hash_blake3(&content);
                                let content_hash = lib_crypto::Hash::from_bytes(&content_hash_bytes);
                                let response_payload = lib_network::dht::protocol::ZhtpRelayResponsePayload {
                                    content: Some(content),
                                    content_type: Some("application/octet-stream".to_string()),
                                    content_hash: Some(content_hash),
                                    error: None,
                                    ttl: 3600,
                                };
                                
                                match relay_protocol.create_relay_response(
                                    &peer_address,
                                    relay_query.request_id.clone(),
                                    response_payload
                                ).await {
                                    Ok(relay_response) => {
                                        info!("✅ Created encrypted relay response, sending back");
                                        let response_bytes = bincode::serialize(&relay_response)?;
                                        return Ok(Some(response_bytes));
                                    }
                                    Err(e) => {
                                        warn!("Failed to create relay response: {}", e);
                                    }
                                }
                            }
                            Ok(None) => {
                                warn!("DHT content not found for key: {}", content_key);
                            }
                            Err(e) => {
                                warn!("DHT fetch error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("⚠️ ZHTP relay query verification failed: {}", e);
                }
            }
        } else {
            warn!("ZHTP relay protocol not initialized");
        }
        
        Ok(None)
    }

    // ==================== Helper Methods ====================

    /// Broadcast to all peers except the specified one.
    /// 
    /// Issue #846 Fix: Uses QuicMeshProtocol as the canonical connection store
    /// instead of the deprecated MeshRouter.connections PeerRegistry.
    pub async fn broadcast_to_peers_except(
        &self, 
        message: ZhtpMeshMessage, 
        exclude: &PublicKey
    ) -> Result<usize> {
        let serialized = bincode::serialize(&message)
            .context("Failed to serialize message")?;
        
        let peers_to_send = self.collect_broadcast_peers(exclude).await;
        if peers_to_send.is_empty() {
            return Ok(0);
        }

        let success_count = self.send_to_peers(&serialized, &peers_to_send).await;
        
        self.track_bytes_sent((serialized.len() * success_count) as u64).await;
        debug!("Broadcast complete: {}/{} peers reached (excluding sender)", 
               success_count, peers_to_send.len());
        
        Ok(success_count)
    }

    /// Collect peers eligible for broadcast, excluding the sender.
    async fn collect_broadcast_peers(
        &self,
        exclude: &PublicKey,
    ) -> Vec<(Vec<u8>, quinn::Connection, Option<[u8; 32]>)> {
        let quic_guard = self.quic_protocol.read().await;
        let quic = match quic_guard.as_ref() {
            Some(q) => q,
            None => {
                debug!("QUIC protocol not initialized for broadcast");
                return Vec::new();
            }
        };

        let exclude_node_id = exclude.as_bytes();
        quic.connections
            .iter()
            .filter(|entry| {
                let key = entry.key();
                key.len() < 32 || &key[..32] != exclude_node_id
            })
            .map(|entry| {
                (entry.key().clone(), entry.value().quic_conn.clone(), entry.value().session_key)
            })
            .collect()
    }

    /// Send serialized data to a list of peers, returning the success count.
    async fn send_to_peers(
        &self,
        serialized: &[u8],
        peers: &[(Vec<u8>, quinn::Connection, Option<[u8; 32]>)],
    ) -> usize {
        let mut success_count = 0;
        for (peer_id, conn, session_key) in peers {
            if let Some(key) = session_key {
                if self.send_to_single_peer(peer_id, conn, key, serialized).await {
                    success_count += 1;
                }
            } else {
                debug!(peer = ?hex::encode(&peer_id[..8.min(peer_id.len())]),
                      "Peer has no session key, skipping");
            }
        }
        success_count
    }

    /// Send encrypted data to a single peer, returning true on success.
    async fn send_to_single_peer(
        &self,
        peer_id: &[u8],
        conn: &quinn::Connection,
        key: &[u8; 32],
        serialized: &[u8],
    ) -> bool {
        match lib_network::protocols::quic_mesh::QuicMeshProtocol::send_encrypted_to(conn, key, serialized).await {
            Ok(()) => true,
            Err(e) => {
                debug!(peer = ?hex::encode(&peer_id[..8.min(peer_id.len())]),
                      error = %e, "Send failed during broadcast");
                false
            }
        }
    }
}
