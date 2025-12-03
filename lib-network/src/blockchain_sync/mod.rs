//! Blockchain Synchronization over Mesh Protocols
//!
//! Provides peer-to-peer blockchain synchronization using bincode messages
//! over any mesh protocol (Bluetooth, WiFi Direct, LoRaWAN, etc.)

pub mod edge_sync;
pub mod blockchain_provider;
pub mod sync_coordinator;

use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug};

pub use edge_sync::EdgeNodeSyncManager;
pub use blockchain_provider::{BlockchainProvider, NullBlockchainProvider};
pub use sync_coordinator::{SyncCoordinator, PeerSyncState, SyncStats, SyncType};

/// Chunk sizes based on protocol capabilities
pub const BLE_CHUNK_SIZE: usize = 200;       // Conservative for BLE GATT (247-byte MTU)
pub const CLASSIC_CHUNK_SIZE: usize = 1000;  // Bluetooth Classic RFCOMM (larger MTU)
pub const WIFI_CHUNK_SIZE: usize = 1400;     // WiFi Direct (can handle more)
pub const DEFAULT_CHUNK_SIZE: usize = 200;   // Safe fallback

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

/// Blockchain sync request/response coordinator
#[derive(Debug)]
pub struct BlockchainSyncManager {
    /// Pending blockchain requests (request_id -> requester)
    pending_requests: Arc<RwLock<HashMap<u64, PublicKey>>>,
    /// Received chunks for reassembly (request_id -> chunks)
    received_chunks: Arc<RwLock<HashMap<u64, BlockchainChunkBuffer>>>,
    /// Next request ID
    next_request_id: Arc<RwLock<u64>>,
}

/// Buffer for reassembling blockchain chunks
#[derive(Debug)]
struct BlockchainChunkBuffer {
    chunks: HashMap<u32, Vec<u8>>,
    total_chunks: u32,
    complete_data_hash: [u8; 32],
    requester: PublicKey,
}

impl BlockchainSyncManager {
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            received_chunks: Arc::new(RwLock::new(HashMap::new())),
            next_request_id: Arc::new(RwLock::new(1)),
        }
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

        info!(" Created blockchain request (ID: {})", request_id);
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

    /// Add received chunk to buffer
    pub async fn add_chunk(
        &self,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let mut buffers = self.received_chunks.write().await;
        
        let buffer = buffers.entry(request_id).or_insert_with(|| {
            // Get requester from pending requests
            let requester = PublicKey::new(vec![0; 32]); // Placeholder
            BlockchainChunkBuffer {
                chunks: HashMap::new(),
                total_chunks,
                complete_data_hash,
                requester,
            }
        });

        // Add chunk
        buffer.chunks.insert(chunk_index, data);
        debug!("Added chunk {}/{} for request {}", chunk_index + 1, total_chunks, request_id);

        // Check if all chunks received
        if buffer.chunks.len() as u32 == total_chunks {
            info!(" All chunks received for request {}, reassembling...", request_id);
            
            // Reassemble in order
            let mut complete_data = Vec::new();
            for i in 0..total_chunks {
                if let Some(chunk) = buffer.chunks.get(&i) {
                    complete_data.extend_from_slice(chunk);
                } else {
                    return Err(anyhow!("Missing chunk {} during reassembly", i));
                }
            }

            // Verify hash
            let mut hasher = Sha256::new();
            hasher.update(&complete_data);
            let hash_result = hasher.finalize();
            let mut computed_hash = [0u8; 32];
            computed_hash.copy_from_slice(&hash_result);

            if computed_hash != complete_data_hash {
                return Err(anyhow!("Blockchain data hash mismatch - data corrupted"));
            }

            info!(" Blockchain data verified: {} bytes", complete_data.len());
            
            // Remove from buffers
            buffers.remove(&request_id);
            
            return Ok(Some(complete_data));
        }

        Ok(None)
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

    #[tokio::test]
    async fn test_chunk_and_reassemble() {
        let sync_manager = BlockchainSyncManager::new();
        let requester = PublicKey::new(vec![1, 2, 3]);

        // Create request
        let (request_id, _message) = sync_manager.create_blockchain_request(requester, None).await.unwrap();

        // Create test data
        let test_data = vec![0u8; 500]; // 500 bytes should create 3 chunks
        
        // Create test sender
        let keypair = lib_crypto::KeyPair::generate().unwrap();
        let sender_pubkey = keypair.public_key;
        
        // Chunk the data
        let chunks = BlockchainSyncManager::chunk_blockchain_data(sender_pubkey, request_id, test_data.clone()).unwrap();
        
        assert_eq!(chunks.len(), 3); // 500 bytes / 200 = 3 chunks

        // Simulate receiving chunks
        for message in chunks {
            if let ZhtpMeshMessage::BlockchainData { sender: _, request_id, chunk_index, total_chunks, data, complete_data_hash } = message {
                let result = sync_manager.add_chunk(request_id, chunk_index, total_chunks, data, complete_data_hash).await.unwrap();
                
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
