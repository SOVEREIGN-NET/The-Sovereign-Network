//! Unified blockchain sync manager with pluggable strategy pattern

use anyhow::{Result, anyhow, bail};
use lib_crypto::{PublicKey, hash_blake3};
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};

use super::{
    SyncStrategy, FullNodeStrategy, EdgeNodeStrategy,
    get_chunk_size_for_protocol, BLE_CHUNK_SIZE,
    MAX_CHUNK_BUFFER_SIZE, MAX_PENDING_REQUESTS, CHUNK_TIMEOUT, MAX_CHUNKS_PER_SECOND,
    MAX_CHUNK_SIZE, MAX_BLOCKCHAIN_DATA_SIZE, MAX_CHUNKS_PER_REQUEST, MAX_REQUESTS_PER_PEER,
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
    /// Per-peer active buffer count for enforcing MAX_REQUESTS_PER_PEER
    peer_buffer_counts: Arc<RwLock<HashMap<Vec<u8>, usize>>>,
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
            peer_buffer_counts: Arc::new(RwLock::new(HashMap::new())),
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
    ///
    /// # Security Validations
    /// - Validates data size limits (MAX_BLOCKCHAIN_DATA_SIZE)
    /// - Validates chunk size limits (MAX_CHUNK_SIZE)
    /// - Prevents excessive chunk creation (MAX_CHUNKS_PER_REQUEST)
    /// - Uses Blake3 cryptographic hash for integrity
    fn chunk_blockchain_data_with_size(
        sender: PublicKey,
        request_id: u64,
        data: Vec<u8>,
        chunk_size: usize,
    ) -> Result<Vec<ZhtpMeshMessage>> {
        let total_size = data.len();

        // Security: Validate total data size
        if total_size == 0 {
            bail!("Cannot chunk empty data");
        }
        if total_size > MAX_BLOCKCHAIN_DATA_SIZE {
            bail!("Blockchain data size {} exceeds maximum allowed size {}",
                total_size, MAX_BLOCKCHAIN_DATA_SIZE);
        }

        // Security: Validate chunk size
        if chunk_size == 0 {
            bail!("Chunk size cannot be zero");
        }
        if chunk_size > MAX_CHUNK_SIZE {
            bail!("Chunk size {} exceeds maximum allowed size {}",
                chunk_size, MAX_CHUNK_SIZE);
        }

        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let total_chunks = chunks.len() as u32;

        // Security: Prevent excessive chunk creation
        if total_chunks > MAX_CHUNKS_PER_REQUEST {
            bail!("Data would create {} chunks, exceeds maximum {} chunks per request",
                total_chunks, MAX_CHUNKS_PER_REQUEST);
        }

        // Calculate cryptographic hash using Blake3 (lib-crypto standard)
        let complete_data_hash = hash_blake3(&data);

        info!("🔐 Chunking blockchain data: {} bytes into {} chunks ({} bytes each, hash: {:02x}...)",
            total_size, total_chunks, chunk_size, complete_data_hash[0]);

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
    /// - Rejects duplicate chunks
    /// - Validates chunk parameters
    /// - Blake3 hash verification on complete data (lib-crypto standard)
    ///
    /// LOCK STRATEGY (deadlock + TOCTOU prevention):
    /// - All buffer-state-dependent checks happen under received_chunks write lock
    /// - pending_requests READ lock is taken briefly while holding received_chunks WRITE lock
    ///   (safe because cleanup functions release pending before acquiring received_chunks)
    /// - peer_buffer_counts is updated atomically with buffer creation under the same lock
    pub async fn add_chunk(
        &self,
        sender: &PublicKey,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        // SECURITY CHECK 0: Validate basic parameters (no locks needed)
        if total_chunks == 0 {
            bail!("Total chunks cannot be zero");
        }
        if total_chunks > MAX_CHUNKS_PER_REQUEST {
            bail!("Total chunks {} exceeds maximum {}", total_chunks, MAX_CHUNKS_PER_REQUEST);
        }
        if chunk_index >= total_chunks {
            bail!("Chunk index {} is out of bounds (total: {})", chunk_index, total_chunks);
        }
        if data.is_empty() {
            bail!("Chunk data cannot be empty");
        }
        if data.len() > MAX_CHUNK_SIZE {
            bail!("Chunk size {} exceeds maximum {}", data.len(), MAX_CHUNK_SIZE);
        }

        let sender_key_id = sender.key_id.to_vec();

        // SECURITY CHECK 1: Verify sender is authenticated (brief lock)
        {
            let auth_peers = self.authenticated_peers.read().await;
            if !auth_peers.get(&sender_key_id).unwrap_or(&false) {
                error!("🚫 SECURITY: Chunk from unauthenticated peer rejected (request_id: {})", request_id);
                return Err(anyhow!("Chunk from unauthenticated peer"));
            }
        } // Lock released

        // SECURITY CHECK 2: Rate limiting (brief lock)
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
        } // Lock released

        // PHASE 1: Main buffer operations with atomic validation
        // All security checks that depend on buffer state must happen under the write lock
        // to prevent TOCTOU races
        let result = {
            let mut buffers = self.received_chunks.write().await;

            // Check buffer existence UNDER the write lock (atomic)
            let buffer_exists_now = buffers.contains_key(&request_id);

            // SECURITY CHECK 3: Re-validate pending_requests under lock (TOCTOU fix)
            // This prevents race where cleanup removes both buffer and pending between our checks.
            // NOTE: Taking pending_requests READ lock while holding received_chunks WRITE lock
            // is safe because cleanup_stale_chunks/complete_request release pending_requests
            // BEFORE acquiring received_chunks (no write-lock inversions possible).
            {
                let pending = self.pending_requests.read().await;
                match pending.get(&request_id) {
                    Some(expected_sender) => {
                        // Request exists - verify sender matches
                        if expected_sender.key_id != sender.key_id {
                            error!("🚫 SECURITY: Chunk sender doesn't match requester (request_id: {})", request_id);
                            return Err(anyhow!("Chunk sender mismatch"));
                        }
                    }
                    None => {
                        // No pending request - only allow if buffer already exists (late arrival)
                        if !buffer_exists_now {
                            error!("🚫 SECURITY: Unsolicited chunk rejected - no pending request for request_id: {}", request_id);
                            return Err(anyhow!("Unsolicited chunk - no pending request"));
                        }
                    }
                }
            } // pending_requests lock released

            // SECURITY CHECK 4: Check max pending requests (global limit)
            if buffers.len() >= MAX_PENDING_REQUESTS && !buffer_exists_now {
                warn!("⚠️ SECURITY: Max pending requests limit reached ({})", MAX_PENDING_REQUESTS);
                return Err(anyhow!("Max pending requests limit reached"));
            }

            // SECURITY CHECK 5: Per-peer request limit (atomic with buffer creation - TOCTOU fix)
            // Compute is_new_buffer UNDER the write lock to prevent races
            let is_new_buffer = !buffer_exists_now;
            if is_new_buffer {
                let mut peer_counts = self.peer_buffer_counts.write().await;
                let peer_count = peer_counts.entry(sender_key_id.clone()).or_insert(0);
                if *peer_count >= MAX_REQUESTS_PER_PEER {
                    error!("🚫 SECURITY: Peer {} exceeded max requests per peer limit ({})",
                           hex::encode(&sender_key_id[..8.min(sender_key_id.len())]), MAX_REQUESTS_PER_PEER);
                    return Err(anyhow!("Max requests per peer limit exceeded"));
                }
                *peer_count += 1;
            } // peer_buffer_counts lock released

            let buffer = buffers.entry(request_id).or_insert_with(|| {
                BlockchainChunkBuffer::new(total_chunks, complete_data_hash, sender.clone())
            });

            // SECURITY CHECK 6: Verify sender matches buffer requester
            // FIX: Use buffer.requester.key_id for decrement, not sender_key_id
            if sender.key_id != buffer.requester.key_id {
                let buffer_owner_key_id = buffer.requester.key_id.to_vec();
                error!("🚫 SECURITY: Chunk sender doesn't match buffer requester (request_id: {})", request_id);
                buffers.remove(&request_id);
                drop(buffers);
                // Decrement the BUFFER OWNER's count, not the attacker's
                self.decrement_peer_buffer_count_sync(&buffer_owner_key_id).await;
                return Err(anyhow!("Chunk sender mismatch with buffer"));
            }

            // SECURITY CHECK 7: Validate total_chunks/hash consistency
            if buffer.total_chunks != total_chunks {
                error!("🚫 SECURITY: total_chunks mismatch for request_id: {} (buffer: {}, chunk: {})",
                       request_id, buffer.total_chunks, total_chunks);
                return Err(anyhow!("total_chunks mismatch - possible attack"));
            }
            if buffer.complete_data_hash != complete_data_hash {
                error!("🚫 SECURITY: complete_data_hash mismatch for request_id: {}", request_id);
                return Err(anyhow!("complete_data_hash mismatch - possible attack"));
            }

            // SECURITY CHECK 8: Buffer size limit
            let chunk_size = data.len();
            if buffer.total_bytes + chunk_size > MAX_CHUNK_BUFFER_SIZE {
                let buffer_owner_key_id = buffer.requester.key_id.to_vec();
                error!("🚫 SECURITY: Chunk buffer size limit exceeded for request_id: {} ({} + {} > {})",
                       request_id, buffer.total_bytes, chunk_size, MAX_CHUNK_BUFFER_SIZE);
                buffers.remove(&request_id);
                drop(buffers);
                self.decrement_peer_buffer_count_sync(&buffer_owner_key_id).await;
                return Err(anyhow!("Chunk buffer size limit exceeded"));
            }

            // SECURITY CHECK 9: Reject duplicate chunks
            if buffer.has_chunk(chunk_index) {
                warn!("⚠️ SECURITY: Duplicate chunk {} for request {} rejected", chunk_index, request_id);
                return Err(anyhow!("Duplicate chunk received"));
            }

            // Add chunk
            buffer.total_bytes += chunk_size;
            buffer.add_chunk(chunk_index, data);
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
                        let buffer_owner_key_id = buffer.requester.key_id.to_vec();
                        buffers.remove(&request_id);
                        drop(buffers);
                        self.decrement_peer_buffer_count_sync(&buffer_owner_key_id).await;
                        return Err(anyhow!("Missing chunk {} during reassembly", i));
                    }
                }

                // Verify hash using Blake3
                let computed_hash = hash_blake3(&complete_data);
                if computed_hash != buffer.complete_data_hash {
                    let buffer_owner_key_id = buffer.requester.key_id.to_vec();
                    buffers.remove(&request_id);
                    drop(buffers);
                    self.decrement_peer_buffer_count_sync(&buffer_owner_key_id).await;
                    error!("🚫 SECURITY: Blockchain data hash mismatch - data corrupted or tampered");
                    return Err(anyhow!("Blockchain data hash mismatch"));
                }

                info!("✅ Blockchain data verified: {} bytes (Blake3 hash: {:02x}...)",
                    complete_data.len(), computed_hash[0]);

                // Success - capture owner key before removing
                let buffer_owner_key_id = buffer.requester.key_id.to_vec();
                buffers.remove(&request_id);

                Ok((Some(complete_data), buffer_owner_key_id))
            } else {
                Ok((None, sender_key_id.clone()))
            }
        }; // received_chunks lock released

        // PHASE 4: Post-completion cleanup (separate locks, following lock order)
        match result {
            Ok((Some(complete_data), buffer_owner_key_id)) => {
                // pending_requests first
                self.pending_requests.write().await.remove(&request_id);
                // peer_buffer_counts second
                self.decrement_peer_buffer_count_sync(&buffer_owner_key_id).await;
                Ok(Some(complete_data))
            }
            Ok((None, _)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Decrement peer buffer count (helper for cleanup) - takes lock briefly
    async fn decrement_peer_buffer_count_sync(&self, peer_key_id: &[u8]) {
        let mut peer_counts = self.peer_buffer_counts.write().await;
        if let Some(count) = peer_counts.get_mut(peer_key_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                peer_counts.remove(peer_key_id);
            }
        }
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
        self.peer_buffer_counts.write().await.remove(&peer_key_id);
        info!("🔓 Unregistered authenticated peer: {}", hex::encode(&peer_key_id[..8.min(peer_key_id.len())]));
    }

    /// Check if a peer is authenticated
    pub async fn is_authenticated_peer(&self, peer: &PublicKey) -> bool {
        let peer_key_id = peer.key_id.to_vec();
        self.authenticated_peers.read().await.get(&peer_key_id).copied().unwrap_or(false)
    }

    /// Cleanup stale chunk buffers (should be called periodically)
    ///
    /// LOCK ORDER: pending_requests → received_chunks → peer_buffer_counts
    pub async fn cleanup_stale_chunks(&self) -> usize {
        // PHASE 1: Identify stale buffers (brief read lock)
        let stale_entries: Vec<(u64, Vec<u8>)> = {
            let buffers = self.received_chunks.read().await;
            buffers.iter()
                .filter(|(_, buffer)| buffer.age() > CHUNK_TIMEOUT)
                .map(|(request_id, buffer)| (*request_id, buffer.requester.key_id.to_vec()))
                .collect()
        }; // Lock released

        if stale_entries.is_empty() {
            return 0;
        }

        let stale_request_ids: Vec<u64> = stale_entries.iter().map(|(id, _)| *id).collect();

        // PHASE 2: Following lock order - pending_requests first
        {
            let mut pending = self.pending_requests.write().await;
            for request_id in &stale_request_ids {
                pending.remove(request_id);
            }
        } // Lock released

        // PHASE 3: received_chunks second
        {
            let mut buffers = self.received_chunks.write().await;
            for request_id in &stale_request_ids {
                warn!("🗑️ Cleaning up stale chunk buffer for request_id: {}", request_id);
                buffers.remove(request_id);
            }
        } // Lock released

        // PHASE 4: peer_buffer_counts last
        for (_, peer_key_id) in &stale_entries {
            self.decrement_peer_buffer_count_sync(peer_key_id).await;
        }

        let cleaned = stale_entries.len();
        info!("🧹 Cleaned up {} stale chunk buffers", cleaned);
        cleaned
    }

    /// Check if a request is pending
    pub async fn is_request_pending(&self, request_id: u64) -> bool {
        self.pending_requests.read().await.contains_key(&request_id)
    }

    /// Complete a request (also cleans up peer buffer count)
    ///
    /// LOCK ORDER: pending_requests → received_chunks → peer_buffer_counts
    pub async fn complete_request(&self, request_id: u64) {
        // PHASE 1: Get peer key (brief read lock)
        let peer_key_id = {
            let buffers = self.received_chunks.read().await;
            buffers.get(&request_id).map(|b| b.requester.key_id.to_vec())
        }; // Lock released

        // PHASE 2: Following lock order - pending_requests first
        self.pending_requests.write().await.remove(&request_id);

        // PHASE 3: received_chunks second
        self.received_chunks.write().await.remove(&request_id);

        // PHASE 4: peer_buffer_counts last
        if let Some(key_id) = peer_key_id {
            self.decrement_peer_buffer_count_sync(&key_id).await;
        }

        info!("Request {} completed and cleaned up", request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            // Use Blake3 for hash (lib-crypto standard)
            let complete_data_hash = hash_blake3(&test_data);

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
        // Use Blake3 for hash (lib-crypto standard)
        let complete_data_hash = hash_blake3(&large_chunk);

        // First chunk should succeed
        let result1 = sync_manager.add_chunk(&requester, request_id, 0, 3, large_chunk.clone(), complete_data_hash).await;
        assert!(result1.is_ok());

        // Second chunk should exceed buffer limit
        let result2 = sync_manager.add_chunk(&requester, request_id, 1, 3, large_chunk, complete_data_hash).await;
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("buffer size limit"));
    }

    #[tokio::test]
    async fn test_duplicate_chunk_rejected() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let requester = PublicKey::new(vec![1, 2, 3]);

        sync_manager.register_authenticated_peer(&requester).await;
        let (request_id, _message) = sync_manager.create_blockchain_request(requester.clone(), None).await.unwrap();

        let test_data = vec![0u8; 100];
        let complete_data_hash = hash_blake3(&test_data);

        // Add first chunk successfully
        let result1 = sync_manager.add_chunk(&requester, request_id, 0, 2, test_data.clone(), complete_data_hash).await;
        assert!(result1.is_ok());

        // Try to add same chunk again - should fail
        let result2 = sync_manager.add_chunk(&requester, request_id, 0, 2, test_data, complete_data_hash).await;
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("Duplicate"));
    }

    #[tokio::test]
    async fn test_chunk_validation() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let requester = PublicKey::new(vec![1, 2, 3]);

        sync_manager.register_authenticated_peer(&requester).await;
        let (_request_id, _message) = sync_manager.create_blockchain_request(requester.clone(), None).await.unwrap();

        // Test empty data rejected
        let result = BlockchainSyncManager::chunk_blockchain_data(requester.clone(), 1, vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[tokio::test]
    async fn test_unsolicited_chunk_rejected() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let attacker = PublicKey::new(vec![1, 2, 3]);

        // Register attacker as authenticated peer (they passed authentication)
        sync_manager.register_authenticated_peer(&attacker).await;

        // But DON'T create a request - attacker tries to inject chunks without a request
        let fake_request_id = 9999u64;
        let test_data = vec![0u8; 100];
        let complete_data_hash = hash_blake3(&test_data);

        // Should fail - no pending request for this request_id
        let result = sync_manager.add_chunk(&attacker, fake_request_id, 0, 2, test_data, complete_data_hash).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsolicited chunk"));
    }

    #[tokio::test]
    async fn test_per_peer_request_limit() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let peer = PublicKey::new(vec![1, 2, 3]);

        sync_manager.register_authenticated_peer(&peer).await;

        // Create MAX_REQUESTS_PER_PEER requests
        for i in 0..MAX_REQUESTS_PER_PEER {
            let (_request_id, _message) = sync_manager.create_blockchain_request(peer.clone(), None).await.unwrap();

            // Send first chunk to create buffer
            let test_data = vec![i as u8; 100];
            let complete_data_hash = hash_blake3(&test_data);
            let result = sync_manager.add_chunk(&peer, (i + 1) as u64, 0, 10, test_data, complete_data_hash).await;
            assert!(result.is_ok(), "Request {} should succeed", i);
        }

        // Next request should fail due to per-peer limit
        let (_request_id, _message) = sync_manager.create_blockchain_request(peer.clone(), None).await.unwrap();
        let test_data = vec![0u8; 100];
        let complete_data_hash = hash_blake3(&test_data);
        let result = sync_manager.add_chunk(&peer, (MAX_REQUESTS_PER_PEER + 1) as u64, 0, 10, test_data, complete_data_hash).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Max requests per peer"));
    }

    #[tokio::test]
    async fn test_chunk_consistency_validation() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let peer = PublicKey::new(vec![1, 2, 3]);

        sync_manager.register_authenticated_peer(&peer).await;
        let (request_id, _message) = sync_manager.create_blockchain_request(peer.clone(), None).await.unwrap();

        let test_data = vec![0u8; 100];
        let correct_hash = hash_blake3(&test_data);

        // First chunk with correct values
        let result1 = sync_manager.add_chunk(&peer, request_id, 0, 5, test_data.clone(), correct_hash).await;
        assert!(result1.is_ok());

        // Second chunk with different total_chunks - should fail
        let result2 = sync_manager.add_chunk(&peer, request_id, 1, 10, test_data.clone(), correct_hash).await;
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("total_chunks mismatch"));
    }

    #[tokio::test]
    async fn test_hash_consistency_validation() {
        let sync_manager = BlockchainSyncManager::new_full_node();
        let peer = PublicKey::new(vec![1, 2, 3]);

        sync_manager.register_authenticated_peer(&peer).await;
        let (request_id, _message) = sync_manager.create_blockchain_request(peer.clone(), None).await.unwrap();

        let test_data = vec![0u8; 100];
        let correct_hash = hash_blake3(&test_data);
        let wrong_hash = hash_blake3(&vec![1u8; 100]);

        // First chunk with correct hash
        let result1 = sync_manager.add_chunk(&peer, request_id, 0, 5, test_data.clone(), correct_hash).await;
        assert!(result1.is_ok());

        // Second chunk with different hash - should fail
        let result2 = sync_manager.add_chunk(&peer, request_id, 1, 5, test_data, wrong_hash).await;
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("complete_data_hash mismatch"));
    }
}
