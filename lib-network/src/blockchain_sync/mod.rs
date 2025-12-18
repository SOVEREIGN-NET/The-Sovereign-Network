//! Blockchain Synchronization over Mesh Protocols
//!
//! Provides peer-to-peer blockchain synchronization using bincode messages
//! over any mesh protocol (Bluetooth, WiFi Direct, LoRaWAN, etc.)
//!
//! # Security Features
//! - Authenticated peer validation
//! - Rate limiting per peer (DoS protection)
//! - Sender/requester validation
//! - Buffer size limits
//! - Chunk timeout cleanup

pub mod edge_sync;
pub mod blockchain_provider;
pub mod sync_coordinator;
pub mod chunk_buffer;
pub mod rate_limiter;

use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};

pub use edge_sync::EdgeNodeSyncManager;
pub use blockchain_provider::{BlockchainProvider, NullBlockchainProvider};
pub use sync_coordinator::{SyncCoordinator, PeerSyncState, SyncStats, SyncType};
pub use chunk_buffer::BlockchainChunkBuffer;
pub use rate_limiter::ChunkRateLimiter;

/// Chunk sizes based on protocol capabilities
pub const BLE_CHUNK_SIZE: usize = 200;       // Conservative for BLE GATT (247-byte MTU)
pub const CLASSIC_CHUNK_SIZE: usize = 1000;  // Bluetooth Classic RFCOMM (larger MTU)
pub const WIFI_CHUNK_SIZE: usize = 1400;     // WiFi Direct (can handle more)
pub const DEFAULT_CHUNK_SIZE: usize = 200;   // Safe fallback

/// Security constraints
pub const MAX_CHUNK_BUFFER_SIZE: usize = 10_000_000;  // 10MB max buffer per request
pub const MAX_PENDING_REQUESTS: usize = 100;          // Max concurrent sync requests
pub const CHUNK_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
pub const MAX_CHUNKS_PER_SECOND: u32 = 100;           // Rate limit per peer

/// Get optimal chunk size for protocol
pub fn get_chunk_size_for_protocol(protocol: &NetworkProtocol) -> usize {
    match protocol {
        NetworkProtocol::BluetoothLE => BLE_CHUNK_SIZE,
        NetworkProtocol::BluetoothClassic => CLASSIC_CHUNK_SIZE,
        NetworkProtocol::WiFiDirect => WIFI_CHUNK_SIZE,
        NetworkProtocol::TCP | NetworkProtocol::UDP => WIFI_CHUNK_SIZE,
        _ => DEFAULT_CHUNK_SIZE,
    }
}

/// Sync strategy trait for pluggable sync modes (full node vs edge node)
#[async_trait::async_trait]
pub trait SyncStrategy: Send + Sync {
    /// Create a sync request message based on current state
    async fn create_sync_request(&mut self, requester: PublicKey, request_id: u64, from_height: Option<u64>) -> Result<ZhtpMeshMessage>;

    /// Process sync response data
    async fn process_sync_response(&mut self, message: &ZhtpMeshMessage) -> Result<()>;

    /// Check if sync is needed
    async fn should_sync(&self) -> bool;

    /// Get current blockchain height
    async fn get_current_height(&self) -> u64;
}

/// Blockchain sync request/response coordinator with security features
pub struct BlockchainSyncManager {
    /// Pending blockchain requests (request_id -> requester)
    pending_requests: Arc<RwLock<HashMap<u64, PublicKey>>>,
    /// Received chunks for reassembly (request_id -> buffer)
    received_chunks: Arc<RwLock<HashMap<u64, BlockchainChunkBuffer>>>,
    /// Next request ID
    next_request_id: Arc<RwLock<u64>>,
    /// Authenticated peers (peer_key_id -> allowed)
    authenticated_peers: Arc<RwLock<HashMap<Vec<u8>, bool>>>,
    /// Rate limiters per peer (peer_key_id -> limiter)
    chunk_rate_limiters: Arc<RwLock<HashMap<Vec<u8>, ChunkRateLimiter>>>,
}

impl std::fmt::Debug for BlockchainSyncManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockchainSyncManager")
            .field("pending_requests", &"<locked>")
            .field("received_chunks", &"<locked>")
            .finish()
    }
}

impl BlockchainSyncManager {
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            received_chunks: Arc::new(RwLock::new(HashMap::new())),
            next_request_id: Arc::new(RwLock::new(1)),
            authenticated_peers: Arc::new(RwLock::new(HashMap::new())),
            chunk_rate_limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a peer as authenticated (allowed to send chunks)
    pub async fn register_authenticated_peer(&self, peer: &PublicKey) {
        let peer_key_id = peer.key_id.to_vec();
        self.authenticated_peers.write().await.insert(peer_key_id, true);
        debug!("Registered authenticated peer for sync");
    }

    /// Unregister an authenticated peer
    pub async fn unregister_peer(&self, peer: &PublicKey) {
        let peer_key_id = peer.key_id.to_vec();
        self.authenticated_peers.write().await.remove(&peer_key_id);
        self.chunk_rate_limiters.write().await.remove(&peer_key_id);
    }

    /// Create a blockchain request message
    pub async fn create_blockchain_request(&self, requester: PublicKey, from_height: Option<u64>) -> Result<(u64, ZhtpMeshMessage)> {
        let mut next_id = self.next_request_id.write().await;
        let request_id = *next_id;
        *next_id += 1;

        // Store pending request
        self.pending_requests.write().await.insert(request_id, requester.clone());

        let request_type = if let Some(height) = from_height {
            crate::types::mesh_message::BlockchainRequestType::BlocksAfter(height)
        } else {
            crate::types::mesh_message::BlockchainRequestType::FullChain
        };

        let message = ZhtpMeshMessage::BlockchainRequest {
            requester,
            request_id,
            request_type,
        };

        info!("📤 Created blockchain request (ID: {})", request_id);
        Ok((request_id, message))
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

        info!("📦 Chunking blockchain data: {} bytes into {} chunks ({} bytes each)",
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
    /// # Security Features
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
        let sender_key_id = sender.key_id.to_vec();

        // SECURITY CHECK 1: Verify sender is authenticated
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
                warn!("⚠️ SECURITY: Chunk rate limit exceeded for peer (request_id: {})", request_id);
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
            }
            // Allow chunks for unknown request_id - might be late arrival
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

        // SECURITY CHECK 5: Buffer size limit
        if buffer.total_bytes + data.len() > MAX_CHUNK_BUFFER_SIZE {
            error!("🚫 SECURITY: Chunk buffer size limit exceeded ({} bytes)", MAX_CHUNK_BUFFER_SIZE);
            return Err(anyhow!("Chunk buffer size limit exceeded"));
        }

        // Add chunk
        buffer.add_chunk(chunk_index, data);
        debug!("Added chunk {}/{} for request {}", chunk_index + 1, total_chunks, request_id);

        // Check if all chunks received
        if buffer.is_complete() {
            info!("✅ All chunks received for request {}, reassembling...", request_id);

            // Reassemble
            let complete_data = buffer.reassemble()
                .ok_or_else(|| anyhow!("Failed to reassemble chunks"))?;

            // Verify hash
            let mut hasher = Sha256::new();
            hasher.update(&complete_data);
            let hash_result = hasher.finalize();
            let mut computed_hash = [0u8; 32];
            computed_hash.copy_from_slice(&hash_result);

            if computed_hash != complete_data_hash {
                error!("🚫 SECURITY: Blockchain data hash mismatch - data corrupted");
                return Err(anyhow!("Blockchain data hash mismatch - data corrupted"));
            }

            info!("✅ Blockchain data verified: {} bytes", complete_data.len());

            // Remove from buffers
            buffers.remove(&request_id);

            return Ok(Some(complete_data));
        }

        Ok(None)
    }

    /// Legacy add_chunk without sender validation (for backward compatibility)
    /// Prefer add_chunk with sender parameter for new code
    pub async fn add_chunk_legacy(
        &self,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let mut buffers = self.received_chunks.write().await;

        let buffer = buffers.entry(request_id).or_insert_with(|| {
            BlockchainChunkBuffer::new(total_chunks, complete_data_hash, PublicKey::new(vec![0; 32]))
        });

        buffer.add_chunk(chunk_index, data);
        debug!("Added chunk {}/{} for request {}", chunk_index + 1, total_chunks, request_id);

        if buffer.is_complete() {
            info!("✅ All chunks received for request {}, reassembling...", request_id);

            let complete_data = buffer.reassemble()
                .ok_or_else(|| anyhow!("Failed to reassemble chunks"))?;

            // Verify hash
            let mut hasher = Sha256::new();
            hasher.update(&complete_data);
            let hash_result = hasher.finalize();
            let mut computed_hash = [0u8; 32];
            computed_hash.copy_from_slice(&hash_result);

            if computed_hash != complete_data_hash {
                return Err(anyhow!("Blockchain data hash mismatch - data corrupted"));
            }

            info!("✅ Blockchain data verified: {} bytes", complete_data.len());
            buffers.remove(&request_id);

            return Ok(Some(complete_data));
        }

        Ok(None)
    }

    /// Cleanup stale chunk buffers (call periodically)
    pub async fn cleanup_stale_buffers(&self) -> usize {
        let mut buffers = self.received_chunks.write().await;
        let initial_count = buffers.len();

        buffers.retain(|_request_id, buffer| {
            buffer.age() < CHUNK_TIMEOUT
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

    /// Get number of pending requests
    pub async fn pending_count(&self) -> usize {
        self.pending_requests.read().await.len()
    }

    /// Get number of authenticated peers
    pub async fn authenticated_peer_count(&self) -> usize {
        self.authenticated_peers.read().await.len()
    }
}

impl Default for BlockchainSyncManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_chunk_and_reassemble() {
        let sync_manager = BlockchainSyncManager::new();
        let requester = PublicKey::new(vec![1, 2, 3]);

        // Register peer as authenticated
        sync_manager.register_authenticated_peer(&requester).await;

        // Create request
        let (request_id, _message) = sync_manager.create_blockchain_request(requester.clone(), None).await.unwrap();

        // Create test data
        let test_data = vec![0u8; 500]; // 500 bytes should create 3 chunks

        // Chunk the data
        let chunks = BlockchainSyncManager::chunk_blockchain_data(requester.clone(), request_id, test_data.clone()).unwrap();

        assert_eq!(chunks.len(), 3); // 500 bytes / 200 = 3 chunks

        // Simulate receiving chunks
        for message in chunks {
            if let ZhtpMeshMessage::BlockchainData { sender: _, request_id, chunk_index, total_chunks, data, complete_data_hash } = message {
                let result = sync_manager.add_chunk(&requester, request_id, chunk_index, total_chunks, data, complete_data_hash).await.unwrap();

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
        let sync_manager = BlockchainSyncManager::new();
        let requester = PublicKey::new(vec![1, 2, 3]);

        // Create request but DON'T register peer
        let (request_id, _message) = sync_manager.create_blockchain_request(requester.clone(), None).await.unwrap();

        let test_data = vec![0u8; 100];
        let chunks = BlockchainSyncManager::chunk_blockchain_data(requester.clone(), request_id, test_data).unwrap();

        if let ZhtpMeshMessage::BlockchainData { sender: _, request_id, chunk_index, total_chunks, data, complete_data_hash } = &chunks[0] {
            let result = sync_manager.add_chunk(&requester, *request_id, *chunk_index, *total_chunks, data.clone(), *complete_data_hash).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("unauthenticated"));
        }
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let sync_manager = BlockchainSyncManager::new();
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
                assert!(result.is_err(), "Expected rate limit error at chunk {}", i);
                assert!(result.unwrap_err().to_string().contains("rate limit"));
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_buffer_size_limit() {
        let sync_manager = BlockchainSyncManager::new();
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
