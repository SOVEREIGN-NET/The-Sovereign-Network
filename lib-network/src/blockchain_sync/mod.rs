//! Blockchain Synchronization over Mesh Protocols
//!
//! Provides peer-to-peer blockchain synchronization using bincode messages
//! over any mesh protocol (Bluetooth, WiFi Direct, LoRaWAN, etc.)

pub mod edge_sync;
pub mod blockchain_provider;
pub mod sync_coordinator;
pub mod chunking;

use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use std::path::PathBuf;
use crate::types::mesh_message::ZhtpMeshMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

pub use edge_sync::EdgeNodeSyncManager;
pub use blockchain_provider::{BlockchainProvider, NullBlockchainProvider};
pub use sync_coordinator::{SyncCoordinator, PeerSyncState, SyncStats, SyncType};
pub use chunking::{
    BlockchainChunker, ChunkingStats, get_chunk_size_for_protocol,
    BLE_CHUNK_SIZE, CLASSIC_CHUNK_SIZE, WIFI_CHUNK_SIZE, DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE, MAX_BLOCKCHAIN_DATA_SIZE, MAX_CHUNKS_PER_REQUEST,
    MAX_REQUESTS_PER_PEER,
};

/// Blockchain sync request/response coordinator
#[derive(Debug)]
pub struct BlockchainSyncManager {
    /// Pending blockchain requests (request_id -> requester)
    pending_requests: Arc<RwLock<HashMap<u64, PublicKey>>>,
    /// Secure chunker for data assembly
    chunker: Arc<BlockchainChunker>,
    /// Next request ID
    next_request_id: Arc<RwLock<u64>>,
}

impl BlockchainSyncManager {
    pub async fn new(persistence_path: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            chunker: Arc::new(BlockchainChunker::new(persistence_path).await?),
            next_request_id: Arc::new(RwLock::new(1)),
        })
    }

    /// Get reference to the chunker for advanced operations
    pub fn chunker(&self) -> Arc<BlockchainChunker> {
        self.chunker.clone()
    }
}

impl Default for BlockchainSyncManager {
    fn default() -> Self {
        Self {
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            chunker: Arc::new(BlockchainChunker::default()),
            next_request_id: Arc::new(RwLock::new(1)),
        }
    }
}

impl BlockchainSyncManager {
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

        info!(" Created blockchain request (ID: {})", request_id);
        Ok((request_id, message))
    }

    /// Chunk blockchain data for transmission (delegates to secure chunker)
    /// 
    /// # Parameters
    /// * `sender` - Public key of the sender (must be authenticated)
    /// * `request_id` - Unique request identifier
    /// * `data` - Blockchain data to chunk
    /// * `protocol` - Optional protocol for automatic chunk sizing
    /// * `chunk_size` - Optional manual chunk size override
    /// 
    /// # Security
    /// See `BlockchainChunker::chunk_blockchain_data` for security features
    pub fn chunk_blockchain_data(
        sender: PublicKey,
        request_id: u64,
        data: Vec<u8>,
        protocol: Option<&crate::protocols::NetworkProtocol>,
        chunk_size: Option<usize>,
    ) -> Result<Vec<ZhtpMeshMessage>> {
        BlockchainChunker::chunk_blockchain_data(sender, request_id, data, protocol, chunk_size)
    }

    /// Add received chunk to buffer (delegates to secure chunker)
    /// 
    /// # Security
    /// See `BlockchainChunker::add_chunk` for security features
    pub async fn add_chunk(
        &self,
        requester: PublicKey,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        self.chunker.add_chunk(requester, request_id, chunk_index, total_chunks, data, complete_data_hash).await
    }

    /// Check if a request is pending
    pub async fn is_request_pending(&self, request_id: u64) -> bool {
        self.pending_requests.read().await.contains_key(&request_id)
    }

    /// Complete a request
    pub async fn complete_request(&self, request_id: u64) {
        self.pending_requests.write().await.remove(&request_id);
        info!("Request {} completed and cleaned up", request_id);
    }

    /// Get chunking statistics
    pub async fn get_chunking_stats(&self) -> ChunkingStats {
        self.chunker.get_stats().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_chunk_and_reassemble() {
        let sync_manager = BlockchainSyncManager::default();
        let requester = PublicKey::new(vec![1, 2, 3]);

        // Create request
        let (request_id, _message) = sync_manager.create_blockchain_request(requester.clone(), None).await.unwrap();

        // Create test data
        let test_data = vec![0u8; 500]; // 500 bytes should create 3 chunks
        
        // Create test sender
        let sender_keypair = lib_crypto::KeyPair::generate().unwrap();
        let sender_pubkey = sender_keypair.public_key.clone();
        
        // Chunk the data
        let chunks = BlockchainSyncManager::chunk_blockchain_data(
            sender_pubkey, 
            request_id, 
            test_data.clone(), 
            None,  // Use default BLE chunk size
            None
        ).unwrap();
        
        assert_eq!(chunks.len(), 3); // 500 bytes / 200 = 3 chunks

        // Simulate receiving chunks
        for message in chunks {
            if let ZhtpMeshMessage::BlockchainData { sender: _, request_id, chunk_index, total_chunks, data, complete_data_hash } = message {
                let result = sync_manager.add_chunk(
                    requester.clone(),
                    request_id, 
                    chunk_index, 
                    total_chunks, 
                    data, 
                    complete_data_hash
                ).await.unwrap();
                
                // Last chunk should return complete data
                if chunk_index == total_chunks - 1 {
                    assert!(result.is_some());
                    let reassembled = result.unwrap();
                    assert_eq!(reassembled, test_data);
                }
            }
        }
    }
}
