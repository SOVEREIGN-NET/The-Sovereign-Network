//! Unified blockchain sync manager with pluggable strategy pattern

use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};

use super::{
    SyncStrategy, FullNodeStrategy, EdgeNodeStrategy,
    get_chunk_size_for_protocol, BLE_CHUNK_SIZE,
    MAX_CHUNK_BUFFER_SIZE, MAX_PENDING_REQUESTS, CHUNK_TIMEOUT, MAX_CHUNKS_PER_SECOND,
};
use super::chunk_buffer::BlockchainChunkBuffer;
use super::rate_limiter::ChunkRateLimiter;

/// Blockchain sync request/response coordinator with pluggable strategy
pub struct BlockchainSyncManager {
    /// Sync strategy (full node or edge node)
    strategy: Arc<RwLock<Box<dyn SyncStrategy>>>,
    /// Pending blockchain requests (request_id -> requester)
    pending_requests: Arc<RwLock<HashMap<u64, PublicKey>>>,
    /// Received chunks for reassembly (request_id -> chunks)
    received_chunks: Arc<RwLock<HashMap<u64, BlockchainChunkBuffer>>>,
    /// Next request ID
    next_request_id: Arc<RwLock<u64>>,
    /// Authenticated peers (peers allowed to send chunks)
    authenticated_peers: Arc<RwLock<HashMap<Vec<u8>, bool>>>,
    /// Chunk rate limiters per peer (peer_key_id -> rate_limiter)
    chunk_rate_limiters: Arc<RwLock<HashMap<Vec<u8>, ChunkRateLimiter>>>,
}

impl BlockchainSyncManager {
    /// Create a new sync manager with the given strategy
    pub fn new(strategy: Box<dyn SyncStrategy>) -> Self {
        Self {
            strategy: Arc::new(RwLock::new(strategy)),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            received_chunks: Arc::new(RwLock::new(HashMap::new())),
            next_request_id: Arc::new(RwLock::new(1)),
            authenticated_peers: Arc::new(RwLock::new(HashMap::new())),
            chunk_rate_limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a full node sync manager
    pub fn new_full_node() -> Self {
        Self::new(Box::new(FullNodeStrategy::new()))
    }

    /// Create an edge node sync manager
    pub fn new_edge_node(max_headers: usize) -> Self {
        Self::new(Box::new(EdgeNodeStrategy::new(max_headers)))
    }

    /// Create a blockchain request message using the strategy
    pub async fn create_blockchain_request(&self, requester: PublicKey, from_height: Option<u64>) -> Result<(u64, ZhtpMeshMessage)> {
        let mut next_id = self.next_request_id.write().await;
        let request_id = *next_id;
        *next_id += 1;

        // Store pending request
        self.pending_requests.write().await.insert(request_id, requester.clone());

        // Delegate to strategy
        let mut strategy = self.strategy.write().await;
        let message = strategy.create_sync_request(requester, request_id, from_height).await?;

        info!("📤 Created blockchain request (ID: {})", request_id);
        Ok((request_id, message))
    }

    /// Process sync response using the strategy
    pub async fn process_sync_response(&self, message: &ZhtpMeshMessage) -> Result<()> {
        let mut strategy = self.strategy.write().await;
        strategy.process_sync_response(message).await
    }

    /// Chunk blockchain data with protocol-specific chunk size
    pub fn chunk_blockchain_data_for_protocol(
        sender: PublicKey,
        request_id: u64,
        data: Vec<u8>,
        protocol: &NetworkProtocol,
    ) -> Result<Vec<ZhtpMeshMessage>> {
        let chunk_size = get_chunk_size_for_protocol(protocol);
        Self::chunk_blockchain_data_with_size(sender, request_id, data, chunk_size)
    }

    /// Chunk blockchain data for mesh transmission (legacy - uses BLE size)
    pub fn chunk_blockchain_data(sender: PublicKey, request_id: u64, data: Vec<u8>) -> Result<Vec<ZhtpMeshMessage>> {
        Self::chunk_blockchain_data_with_size(sender, request_id, data, BLE_CHUNK_SIZE)
    }

    /// Chunk blockchain data with specific chunk size
    fn chunk_blockchain_data_with_size(
        sender: PublicKey,
        request_id: u64,
        data: Vec<u8>,
        chunk_size: usize,
    ) -> Result<Vec<ZhtpMeshMessage>> {
        let total_size = data.len();
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let total_chunks = chunks.len() as u32;

        // Calculate hash of complete data
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash_result = hasher.finalize();
        let mut complete_data_hash = [0u8; 32];
        complete_data_hash.copy_from_slice(&hash_result);

        info!(" Chunking blockchain data: {} bytes into {} chunks ({} bytes each)", 
            total_size, total_chunks, chunk_size);

        let mut messages = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let message = ZhtpMeshMessage::BlockchainData {
                sender: sender.clone(),
                request_id,
                chunk_index: index as u32,
                total_chunks,
                data: chunk.to_vec(),
                complete_data_hash,
            };
            messages.push(message);
        }

        Ok(messages)
    }

    /// Add received chunk to buffer with security checks
    /// 
    /// SECURITY FEATURES:
    /// - Verifies sender is authenticated peer
    /// - Enforces rate limiting per peer
    /// - Checks buffer size limits
    /// - Validates sender matches original requester
    /// - SHA256 hash verification on complete data
    pub async fn add_chunk(
        &self,
        sender: &PublicKey,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        // SECURITY CHECK 1: Verify sender is authenticated
        let sender_key_id = sender.key_id.to_vec();
        {
            let auth_peers = self.authenticated_peers.read().await;
            if !auth_peers.get(&sender_key_id).unwrap_or(&false) {
                error!("🚫 SECURITY: Chunk from unauthenticated peer rejected (request_id: {})", request_id);
                return Err(anyhow!("Chunk from unauthenticated peer"));
            }
        }

        // SECURITY CHECK 2: Rate limiting
        {
            let mut rate_limiters = self.chunk_rate_limiters.write().await;
            let rate_limiter = rate_limiters
                .entry(sender_key_id.clone())
                .or_insert_with(ChunkRateLimiter::new);
            
            if !rate_limiter.check_and_increment(MAX_CHUNKS_PER_SECOND) {
                warn!("⚠️ SECURITY: Chunk rate limit exceeded for peer {} (request_id: {})",
                      hex::encode(&sender_key_id[..8.min(sender_key_id.len())]), request_id);
                return Err(anyhow!("Chunk rate limit exceeded"));
            }
        }

        // SECURITY CHECK 3: Verify sender matches original requester
        {
            let pending = self.pending_requests.read().await;
            if let Some(expected_sender) = pending.get(&request_id) {
                if expected_sender.key_id != sender.key_id {
                    error!("🚫 SECURITY: Chunk sender doesn't match requester (request_id: {})", request_id);
                    return Err(anyhow!("Chunk sender mismatch"));
                }
            } else {
                warn!("⚠️ Received chunk for unknown request_id: {}", request_id);
                // Allow this for now - might be late arrival after cleanup
            }
        }

        // SECURITY CHECK 4: Check max pending requests
        let mut buffers = self.received_chunks.write().await;
        if buffers.len() >= MAX_PENDING_REQUESTS && !buffers.contains_key(&request_id) {
            warn!("⚠️ SECURITY: Max pending requests limit reached ({})", MAX_PENDING_REQUESTS);
            return Err(anyhow!("Max pending requests limit reached"));
        }

        let buffer = buffers.entry(request_id).or_insert_with(|| {
            BlockchainChunkBuffer::new(total_chunks, complete_data_hash, sender.clone())
        });

        // SECURITY CHECK 5: Verify sender matches buffer requester (defense-in-depth)
        if sender.key_id != buffer.requester.key_id {
            error!("🚫 SECURITY: Chunk sender doesn't match buffer requester (request_id: {})", request_id);
            buffers.remove(&request_id);
            return Err(anyhow!("Chunk sender mismatch with buffer"));
        }

        // SECURITY CHECK 6: Buffer size limit
        let chunk_size = data.len();
        if buffer.total_bytes + chunk_size > MAX_CHUNK_BUFFER_SIZE {
            error!("🚫 SECURITY: Chunk buffer size limit exceeded for request_id: {} ({} + {} > {})",
                   request_id, buffer.total_bytes, chunk_size, MAX_CHUNK_BUFFER_SIZE);
            buffers.remove(&request_id);
            return Err(anyhow!("Chunk buffer size limit exceeded"));
        }

        // Add chunk
        buffer.total_bytes += chunk_size;
        buffer.chunks.insert(chunk_index, data);
        debug!("Added chunk {}/{} for request {} ({} bytes total)", 
               chunk_index + 1, total_chunks, request_id, buffer.total_bytes);

        // Check if all chunks received
        if buffer.is_complete() {
            info!("✅ All chunks received for request {}, reassembling...", request_id);
            
            // Reassemble in order
            let mut complete_data = Vec::new();
            for i in 0..total_chunks {
                if let Some(chunk) = buffer.chunks.get(&i) {
                    complete_data.extend_from_slice(chunk);
                } else {
                    buffers.remove(&request_id);
                    return Err(anyhow!("Missing chunk {} during reassembly", i));
                }
            }

            // Verify hash using buffer's stored hash (defense-in-depth)
            let mut hasher = Sha256::new();
            hasher.update(&complete_data);
            let hash_result = hasher.finalize();
            let mut computed_hash = [0u8; 32];
            computed_hash.copy_from_slice(&hash_result);

            if computed_hash != buffer.complete_data_hash {
                buffers.remove(&request_id);
                error!("🚫 SECURITY: Blockchain data hash mismatch - data corrupted or tampered");
                return Err(anyhow!("Blockchain data hash mismatch"));
            }

            info!("✅ Blockchain data verified: {} bytes (SHA256 match)", complete_data.len());
            
            // Remove from buffers
            buffers.remove(&request_id);
            
            return Ok(Some(complete_data));
        }

        Ok(None)
    }

    /// Register an authenticated peer (allows them to send chunks)
    pub async fn register_authenticated_peer(&self, peer: &PublicKey) {
        let peer_key_id = peer.key_id.to_vec();
        self.authenticated_peers.write().await.insert(peer_key_id.clone(), true);
        info!("🔐 Registered authenticated peer: {}", hex::encode(&peer_key_id[..8.min(peer_key_id.len())]));
    }

    /// Unregister an authenticated peer
    pub async fn unregister_authenticated_peer(&self, peer: &PublicKey) {
        let peer_key_id = peer.key_id.to_vec();
        self.authenticated_peers.write().await.remove(&peer_key_id);
        self.chunk_rate_limiters.write().await.remove(&peer_key_id);
        info!("🔓 Unregistered authenticated peer: {}", hex::encode(&peer_key_id[..8.min(peer_key_id.len())]));
    }

    /// Check if a peer is authenticated
    pub async fn is_authenticated_peer(&self, peer: &PublicKey) -> bool {
        let peer_key_id = peer.key_id.to_vec();
        self.authenticated_peers.read().await.get(&peer_key_id).copied().unwrap_or(false)
    }

    /// Cleanup stale chunk buffers (should be called periodically)
    pub async fn cleanup_stale_chunks(&self) -> usize {
        let mut buffers = self.received_chunks.write().await;
        let initial_count = buffers.len();
        
        buffers.retain(|request_id, buffer| {
            let elapsed = buffer.age();
            if elapsed > CHUNK_TIMEOUT {
                warn!("🗑️ Cleaning up stale chunk buffer for request_id: {} (age: {:?})",
                      request_id, elapsed);
                false
            } else {
                true
            }
        });
        
        let cleaned = initial_count - buffers.len();
        if cleaned > 0 {
            info!("🧹 Cleaned up {} stale chunk buffers", cleaned);
        }
        cleaned
    }

    /// Check if a request is pending
    pub async fn is_request_pending(&self, request_id: u64) -> bool {
        self.pending_requests.read().await.contains_key(&request_id)
    }

    /// Complete a request
    pub async fn complete_request(&self, request_id: u64) {
        self.pending_requests.write().await.remove(&request_id);
        self.received_chunks.write().await.remove(&request_id);
        info!("Request {} completed and cleaned up", request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    #[tokio::test]
    async fn test_chunk_and_reassemble() {
        let sync_manager = BlockchainSyncManager::new_full_node();

        // Create test peer (same peer requests and responds)
        let peer_keypair = lib_crypto::KeyPair::generate().unwrap();
        let peer_pubkey = peer_keypair.public_key.clone();

        // SECURITY: Register peer as authenticated before accepting chunks
        sync_manager.register_authenticated_peer(&peer_pubkey).await;

        // Create request (we request blockchain from this peer)
        let (request_id, _message) = sync_manager.create_blockchain_request(peer_pubkey.clone(), None).await.unwrap();

        // Create test data
        let test_data = vec![0u8; 500]; // 500 bytes should create 3 chunks

        // Chunk the data (peer responds with chunks)
        let chunks = BlockchainSyncManager::chunk_blockchain_data(peer_pubkey.clone(), request_id, test_data.clone()).unwrap();
        
        assert_eq!(chunks.len(), 3); // 500 bytes / 200 = 3 chunks

        // Simulate receiving chunks (with sender parameter for security check)
        for message in chunks {
            if let ZhtpMeshMessage::BlockchainData { sender: _, request_id, chunk_index, total_chunks, data, complete_data_hash } = message {
                let result = sync_manager.add_chunk(&peer_pubkey, request_id, chunk_index, total_chunks, data, complete_data_hash).await.unwrap();
                
                // Last chunk should return complete data
                if chunk_index == total_chunks - 1 {
                    assert!(result.is_some());
                    let reassembled = result.unwrap();
                    assert_eq!(reassembled, test_data);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_unauthenticated_peer_rejected() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let requester = PublicKey::new(vec![1, 2, 3]);
        
        // Create request but DON'T register peer as authenticated
        let (request_id, _message) = sync_manager.create_blockchain_request(requester.clone(), None).await.unwrap();
        
        // Try to send chunk from unauthenticated peer
        let sender_keypair = lib_crypto::KeyPair::generate().unwrap();
        let sender_pubkey = sender_keypair.public_key;
        
        let test_data = vec![0u8; 100];
        let chunks = BlockchainSyncManager::chunk_blockchain_data(sender_pubkey.clone(), request_id, test_data).unwrap();
        
        if let ZhtpMeshMessage::BlockchainData { sender: _, request_id, chunk_index, total_chunks, data, complete_data_hash } = &chunks[0] {
            // Should fail with authentication error
            let result = sync_manager.add_chunk(&sender_pubkey, *request_id, *chunk_index, *total_chunks, data.clone(), *complete_data_hash).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("unauthenticated"));
        }
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let requester = PublicKey::new(vec![1, 2, 3]);
        
        sync_manager.register_authenticated_peer(&requester).await;
        let (request_id, _message) = sync_manager.create_blockchain_request(requester.clone(), None).await.unwrap();
        
        // Try to send more than MAX_CHUNKS_PER_SECOND chunks
        for i in 0..(MAX_CHUNKS_PER_SECOND + 10) {
            let test_data = vec![i as u8; 10];
            let mut hasher = Sha256::new();
            hasher.update(&test_data);
            let hash_result = hasher.finalize();
            let mut complete_data_hash = [0u8; 32];
            complete_data_hash.copy_from_slice(&hash_result);
            
            let result = sync_manager.add_chunk(
                &requester,
                request_id,
                i,
                MAX_CHUNKS_PER_SECOND + 10,
                test_data,
                complete_data_hash
            ).await;
            
            if i >= MAX_CHUNKS_PER_SECOND {
                // Should be rate limited
                assert!(result.is_err(), "Expected rate limit error at chunk {}", i);
                if let Err(e) = result {
                    assert!(e.to_string().contains("rate limit"), "Expected rate limit error, got: {}", e);
                }
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_buffer_size_limit() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let requester = PublicKey::new(vec![1, 2, 3]);
        
        sync_manager.register_authenticated_peer(&requester).await;
        let (request_id, _message) = sync_manager.create_blockchain_request(requester.clone(), None).await.unwrap();
        
        // Try to send chunks that exceed MAX_CHUNK_BUFFER_SIZE
        let large_chunk = vec![0u8; MAX_CHUNK_BUFFER_SIZE / 2 + 1];
        let mut hasher = Sha256::new();
        hasher.update(&large_chunk);
        let hash_result = hasher.finalize();
        let mut complete_data_hash = [0u8; 32];
        complete_data_hash.copy_from_slice(&hash_result);
        
        // First chunk should succeed
        let result1 = sync_manager.add_chunk(&requester, request_id, 0, 3, large_chunk.clone(), complete_data_hash).await;
        assert!(result1.is_ok());
        
        // Second chunk should exceed buffer limit
        let result2 = sync_manager.add_chunk(&requester, request_id, 1, 3, large_chunk, complete_data_hash).await;
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("buffer size limit"));
    }
}
