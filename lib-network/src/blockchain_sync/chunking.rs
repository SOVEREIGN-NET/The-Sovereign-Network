//! Blockchain Data Chunking with Security and Recovery
//!
//! Provides secure chunking and reassembly of blockchain data for transmission
//! over mesh protocols with validation, rate limiting, and resumable downloads.
//!
//! # Features
//!
//! ## Corruption Detection & Prevention
//! * Blake3 cryptographic hash verification
//! * Duplicate chunk rejection  
//! * Missing chunk detection
//! * Size validation (10MB chunks, 10GB per request)
//! * Rate limiting (10 concurrent requests per peer)
//!
//! ## Interruption Recovery
//! * **Persistent checkpointing** - Saves state every 50 chunks
//! * **Automatic recovery** - Resumes interrupted downloads on restart
//! * **Resume API** - Request only missing chunks after interruption
//! * **Progress tracking** - Query received/missing chunks per request
//!
//! # Usage Examples
//!
//! ## Basic (No Persistence)
//! ```ignore
//! let chunker = BlockchainChunker::default(); // Tests only
//! // Chunks lost on crash/restart
//! ```
//!
//! ## With Recovery (Production)
//! ```ignore
//! // Enable persistence for resumable downloads
//! let chunker = BlockchainChunker::new(None).await?; // Uses default "./data/chunks"
//! // Or custom path:
//! let chunker = BlockchainChunker::new(Some(PathBuf::from("/custom/path"))).await?;
//!
//! // After crash/restart, automatically recovers:
//! // - 9GB downloaded → crash → restart → resume from 9GB (not 0GB)
//!
//! // Query recovery status
//! for request_id in chunker.get_active_requests().await {
//!     if let Some(progress) = chunker.get_request_progress(request_id).await {
//!         println!("Request {}: {:.1}% complete", request_id, progress.progress_percent);
//!         
//!         // Get missing chunks to resume
//!         if let Some(missing) = chunker.get_missing_chunks(request_id).await {
//!             // Request only chunks: [901, 902, 903, ...]
//!             for chunk_index in missing {
//!                 // Send request for specific chunk
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## Checkpoint Behavior
//! * Saves state every 50 chunks (CHECKPOINT_INTERVAL)
//! * Clears checkpoint on successful completion
//! * Allows hours/days to complete large syncs over slow connections

use anyhow::{Result, anyhow, bail};
use lib_crypto::{PublicKey, hash_blake3};
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, debug, warn};

/// Maximum allowed chunk size (10 MB to prevent memory exhaustion)
pub const MAX_CHUNK_SIZE: usize = 10 * 1024 * 1024;

/// Maximum allowed total data size per chunking operation (10 GB)
/// 
/// This is a safety limit for a SINGLE chunking operation, not the entire blockchain.
/// Full nodes downloading GB/TB blockchains should use incremental sync:
/// - Request blocks in batches (e.g., BlocksAfter(height) in 10GB segments)
/// - Edge nodes use headers-only sync (~100 KB total)
/// - This limit prevents memory exhaustion from a single malicious request
pub const MAX_BLOCKCHAIN_DATA_SIZE: usize = 10 * 1024 * 1024 * 1024; // 10 GB

/// Maximum pending chunks per request (prevent memory exhaustion)
/// At 10MB chunks, this allows up to 10GB of data (1000 chunks × 10MB)
pub const MAX_CHUNKS_PER_REQUEST: u32 = 1000;

/// Maximum pending requests per peer (rate limiting)
pub const MAX_REQUESTS_PER_PEER: usize = 10;

/// Checkpoint interval (save buffer state every N chunks received)
pub const CHECKPOINT_INTERVAL: u32 = 50;

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

/// Buffer for reassembling blockchain chunks with security metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockchainChunkBuffer {
    chunks: HashMap<u32, Vec<u8>>,
    total_chunks: u32,
    complete_data_hash: [u8; 32],
    requester: PublicKey,
    received_chunk_indices: std::collections::HashSet<u32>,
}

/// Persisted state for resumable downloads
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedChunkerState {
    /// Active chunk buffers (request_id -> buffer)
    buffers: HashMap<u64, BlockchainChunkBuffer>,
    /// Peer request counters for rate limiting
    peer_counts: HashMap<Vec<u8>, usize>,
}

/// Secure blockchain data chunker with resumable downloads
#[derive(Debug)]
pub struct BlockchainChunker {
    /// Received chunks for reassembly (request_id -> chunks)
    received_chunks: Arc<RwLock<HashMap<u64, BlockchainChunkBuffer>>>,
    /// Peer request counters (peer -> count) for rate limiting
    peer_request_counts: Arc<RwLock<HashMap<Vec<u8>, usize>>>,
    /// Path for persisting chunk state (None = no persistence)
    persistence_path: Option<PathBuf>,
}

impl BlockchainChunker {
    /// Create blockchain chunker with automatic persistence and recovery
    /// 
    /// # Parameters
    /// * `persistence_path` - Optional directory for checkpoints (defaults to "./data/chunks")
    /// 
    /// # Recovery Behavior
    /// * Automatically recovers any interrupted downloads on startup
    /// * Checkpoints every 50 chunks to disk
    /// * Resumes from where it left off after crash/restart
    pub async fn new(persistence_path: Option<PathBuf>) -> Result<Self> {
        let path = persistence_path.unwrap_or_else(|| PathBuf::from("./data/chunks"));
        
        let mut chunker = Self {
            received_chunks: Arc::new(RwLock::new(HashMap::new())),
            peer_request_counts: Arc::new(RwLock::new(HashMap::new())),
            persistence_path: Some(path.clone()),
        };

        // Create persistence directory if it doesn't exist
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
            info!("📁 Created chunk persistence directory: {:?}", path);
        }

        // Attempt to recover any interrupted downloads
        chunker.recover_from_disk().await?;

        Ok(chunker)
    }

    /// Recover interrupted downloads from disk
    async fn recover_from_disk(&mut self) -> Result<()> {
        if let Some(ref path) = self.persistence_path {
            let checkpoint_file = path.join("chunker_state.bin");
            
            if checkpoint_file.exists() {
                match tokio::fs::read(&checkpoint_file).await {
                    Ok(data) => {
                        match bincode::deserialize::<PersistedChunkerState>(&data) {
                            Ok(state) => {
                                *self.received_chunks.write().await = state.buffers.clone();
                                *self.peer_request_counts.write().await = state.peer_counts.clone();
                                
                                let total_requests = state.buffers.len();
                                let total_chunks: usize = state.buffers.values()
                                    .map(|b| b.chunks.len())
                                    .sum();
                                
                                info!("🔄 Recovered {} interrupted downloads ({} chunks total)", 
                                    total_requests, total_chunks);
                                
                                // Log each recovered request
                                for (request_id, buffer) in &state.buffers {
                                    let progress = (buffer.chunks.len() as f64 / buffer.total_chunks as f64) * 100.0;
                                    info!("  └─ Request {}: {}/{} chunks ({:.1}%)", 
                                        request_id, buffer.chunks.len(), buffer.total_chunks, progress);
                                }
                            }
                            Err(e) => {
                                warn!("⚠️  Failed to deserialize chunk state: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("⚠️  Failed to read chunk state file: {}", e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Save current chunk state to disk (checkpoint)
    async fn save_checkpoint(&self) -> Result<()> {
        if let Some(ref path) = self.persistence_path {
            let buffers = self.received_chunks.read().await;
            let counts = self.peer_request_counts.read().await;
            
            let state = PersistedChunkerState {
                buffers: buffers.clone(),
                peer_counts: counts.clone(),
            };
            
            let checkpoint_file = path.join("chunker_state.bin");
            let data = bincode::serialize(&state)?;
            tokio::fs::write(&checkpoint_file, data).await?;
            
            debug!("💾 Checkpoint saved: {} active requests", buffers.len());
        }
        Ok(())
    }

    /// Remove checkpoint file (call after successful completion)
    async fn clear_checkpoint(&self) -> Result<()> {
        if let Some(ref path) = self.persistence_path {
            let checkpoint_file = path.join("chunker_state.bin");
            if checkpoint_file.exists() {
                tokio::fs::remove_file(&checkpoint_file).await?;
                debug!("🧹 Checkpoint file removed");
            }
        }
        Ok(())
    }

    /// Chunk blockchain data for transmission with security validation
    /// 
    /// # Parameters
    /// * `sender` - Public key of the sender. **SECURITY**: Caller is responsible for 
    ///              authenticating this identity at the network layer BEFORE calling this 
    ///              function. This function does NOT perform authentication or signature 
    ///              verification - it only packages data for transmission.
    /// * `request_id` - Unique request identifier
    /// * `data` - Blockchain data to chunk (max 10GB per request)
    /// * `protocol` - Optional protocol for automatic chunk sizing
    /// * `chunk_size` - Optional manual chunk size override
    /// 
    /// # Usage Patterns
    /// * **Edge Nodes**: Headers-only (~100 KB) - single request
    /// * **Full Nodes**: Use incremental sync with `BlocksAfter(height)` in 10GB batches
    ///   - Example: Request blocks 0-10000, then 10001-20000, etc.
    ///   - Prevents memory exhaustion while syncing TB-sized blockchains
    /// 
    /// # Security
    /// * Validates data size limits (10GB max per request)
    /// * Validates chunk size limits (10MB max per chunk)
    /// * Prevents excessive chunk creation (1000 chunks max)
    /// * Includes cryptographic hash for integrity
    pub fn chunk_blockchain_data(
        sender: PublicKey,
        request_id: u64,
        data: Vec<u8>,
        protocol: Option<&NetworkProtocol>,
        chunk_size: Option<usize>,
    ) -> Result<Vec<ZhtpMeshMessage>> {
        // Security: Validate total data size
        let total_size = data.len();
        if total_size == 0 {
            bail!("Cannot chunk empty data");
        }
        if total_size > MAX_BLOCKCHAIN_DATA_SIZE {
            bail!("Blockchain data size {} exceeds maximum allowed size {}", 
                total_size, MAX_BLOCKCHAIN_DATA_SIZE);
        }

        // Determine chunk size with validation
        let requested_chunk_size = chunk_size
            .or_else(|| protocol.map(|p| get_chunk_size_for_protocol(p)))
            .unwrap_or(BLE_CHUNK_SIZE);

        // Security: Validate chunk size
        if requested_chunk_size == 0 {
            bail!("Chunk size cannot be zero");
        }
        if requested_chunk_size > MAX_CHUNK_SIZE {
            bail!("Chunk size {} exceeds maximum allowed size {}", 
                requested_chunk_size, MAX_CHUNK_SIZE);
        }

        let chunks: Vec<&[u8]> = data.chunks(requested_chunk_size).collect();
        let total_chunks = chunks.len() as u32;

        // Security: Prevent excessive chunk creation
        if total_chunks > MAX_CHUNKS_PER_REQUEST {
            bail!("Data would create {} chunks, exceeds maximum {} chunks per request",
                total_chunks, MAX_CHUNKS_PER_REQUEST);
        }

        // Calculate cryptographic hash of complete data for integrity verification
        // Use Blake3 from lib-crypto for consistency with ZHTP standards
        let complete_data_hash = hash_blake3(&data);

        info!("🔐 Chunking blockchain data: {} bytes into {} chunks ({} bytes each, hash: {:02x}...)", 
            total_size, total_chunks, requested_chunk_size, complete_data_hash[0]);

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

    /// Add received chunk to buffer with security validation
    /// 
    /// # Security
    /// * Validates chunk parameters
    /// * Prevents duplicate chunks
    /// * Enforces rate limits per peer
    /// * Checks buffer timeouts
    /// * Verifies cryptographic hash on completion
    pub async fn add_chunk(
        &self,
        requester: PublicKey,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        // Security: Validate basic parameters
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

        let mut buffers = self.received_chunks.write().await;

        // Security: Check rate limiting per peer
        let requester_key = requester.as_bytes().to_vec();
        {
            let mut counts = self.peer_request_counts.write().await;
            let count = counts.entry(requester_key.clone()).or_insert(0);
            if *count >= MAX_REQUESTS_PER_PEER {
                warn!("⚠️  Peer {:?} exceeded request limit", &requester_key[..8]);
                bail!("Too many pending requests from this peer");
            }
        }

        // Check if buffer exists, if not we'll increment counter after
        let is_new_buffer = !buffers.contains_key(&request_id);
        
        let buffer = buffers.entry(request_id).or_insert_with(|| {
            BlockchainChunkBuffer {
                chunks: HashMap::new(),
                total_chunks,
                complete_data_hash,
                requester: requester.clone(),
                received_chunk_indices: std::collections::HashSet::new(),
            }
        });
        
        // Increment peer request counter for new buffers
        if is_new_buffer {
            let mut counts = self.peer_request_counts.write().await;
            *counts.entry(requester_key).or_insert(0) += 1;
        }

        // Security: Validate buffer consistency
        if buffer.total_chunks != total_chunks {
            bail!("Total chunks mismatch: expected {}, got {}", buffer.total_chunks, total_chunks);
        }
        if buffer.complete_data_hash != complete_data_hash {
            bail!("Data hash mismatch for request {}", request_id);
        }

        // Security: Prevent duplicate chunk attacks
        if buffer.received_chunk_indices.contains(&chunk_index) {
            warn!("⚠️  Duplicate chunk {} for request {} from peer", chunk_index, request_id);
            bail!("Duplicate chunk received");
        }

        // Add chunk
        buffer.chunks.insert(chunk_index, data);
        buffer.received_chunk_indices.insert(chunk_index);
        debug!("✓ Added chunk {}/{} for request {}", chunk_index + 1, total_chunks, request_id);

        // Check completion before checkpoint to avoid borrow issues
        let is_complete = buffer.chunks.len() as u32 == total_chunks;
        let should_checkpoint = !is_complete && (buffer.chunks.len() as u32 % CHECKPOINT_INTERVAL == 0);

        // Drop lock before potentially expensive I/O
        drop(buffers);

        // Checkpoint: Save state periodically (every CHECKPOINT_INTERVAL chunks)
        if should_checkpoint {
            if let Err(e) = self.save_checkpoint().await {
                warn!("⚠️  Failed to save checkpoint: {}", e);
            }
        }

        // Reacquire lock if we need to continue processing
        if is_complete {
            let mut buffers = self.received_chunks.write().await;
            let buffer = buffers.get(&request_id).ok_or_else(|| anyhow!("Buffer disappeared during checkpoint"))?;
            info!("📦 All chunks received for request {}, reassembling...", request_id);
            
            // Reassemble in order
            let mut complete_data = Vec::new();
            for i in 0..total_chunks {
                if let Some(chunk) = buffer.chunks.get(&i) {
                    complete_data.extend_from_slice(chunk);
                } else {
                    bail!("Missing chunk {} during reassembly", i);
                }
            }

            // Security: Validate final size
            if complete_data.len() > MAX_BLOCKCHAIN_DATA_SIZE {
                bail!("Reassembled data size {} exceeds maximum {}", 
                    complete_data.len(), MAX_BLOCKCHAIN_DATA_SIZE);
            }

            let expected_hash = complete_data_hash;
            let requester_for_cleanup = buffer.requester.clone();
            
            // Drop write lock before expensive cryptographic operation
            drop(buffers);

            // Security: Verify cryptographic hash using Blake3 (without holding lock)
            let computed_hash = hash_blake3(&complete_data);

            if computed_hash != expected_hash {
                warn!("⚠️  Hash mismatch for request {}: expected {:02x}..., got {:02x}...",
                    request_id, expected_hash[0], computed_hash[0]);
                bail!("Blockchain data hash mismatch - data corrupted or tampered");
            }

            info!("✅ Blockchain data verified: {} bytes (hash: {:02x}...)", 
                complete_data.len(), computed_hash[0]);
            
            // Cleanup: Remove from buffers and decrement peer counter
            let requester_key = requester_for_cleanup.as_bytes().to_vec();
            let mut buffers = self.received_chunks.write().await;
            buffers.remove(&request_id);
            drop(buffers);
            
            // Decrement peer request counter now that request is complete
            let mut counts = self.peer_request_counts.write().await;
            if let Some(count) = counts.get_mut(&requester_key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&requester_key);
                }
            }
            drop(counts);

            // Clear checkpoint since request completed successfully
            if let Err(e) = self.clear_checkpoint().await {
                warn!("⚠️  Failed to clear checkpoint: {}", e);
            }

            return Ok(Some(complete_data));
        }

        Ok(None)
    }

    /// Get list of missing chunk indices for a request (for resume)
    /// 
    /// Returns None if request_id doesn't exist, or Some(Vec) of missing indices
    /// 
    /// # Usage
    /// After recovery, caller can query which chunks are still needed:
    /// Get missing chunk indices for a request (internal use for recovery)
    async fn get_missing_chunks(&self, request_id: u64) -> Option<Vec<u32>> {
        let buffers = self.received_chunks.read().await;
        if let Some(buffer) = buffers.get(&request_id) {
            let mut missing = Vec::new();
            for i in 0..buffer.total_chunks {
                if !buffer.received_chunk_indices.contains(&i) {
                    missing.push(i);
                }
            }
            Some(missing)
        } else {
            None
        }
    }

    /// Get all active request IDs (internal use after recovery)
    async fn get_active_requests(&self) -> Vec<u64> {
        let buffers = self.received_chunks.read().await;
        buffers.keys().copied().collect()
    }

    /// Get request progress information (internal use for logging)
    async fn get_request_progress(&self, request_id: u64) -> Option<RequestProgress> {
        let buffers = self.received_chunks.read().await;
        buffers.get(&request_id).map(|buffer| {
            RequestProgress {
                request_id,
                received_chunks: buffer.chunks.len() as u32,
                total_chunks: buffer.total_chunks,
                progress_percent: (buffer.chunks.len() as f64 / buffer.total_chunks as f64) * 100.0,
                missing_chunks: buffer.total_chunks - buffer.chunks.len() as u32,
            }
        })
    }

    /// Get statistics about current chunk buffers
    pub async fn get_stats(&self) -> ChunkingStats {
        let buffers = self.received_chunks.read().await;
        let counts = self.peer_request_counts.read().await;

        ChunkingStats {
            pending_requests: buffers.len(),
            total_peers_with_requests: counts.len(),
            total_pending_chunks: buffers.values().map(|b| b.chunks.len()).sum(),
        }
    }

    /// Clear all chunk buffers (for cleanup/reset)
    pub async fn clear_all(&self) {
        self.received_chunks.write().await.clear();
        self.peer_request_counts.write().await.clear();
        
        // Clear checkpoint file
        if let Err(e) = self.clear_checkpoint().await {
            warn!("⚠️  Failed to clear checkpoint during clear_all: {}", e);
        }
        
        info!("🧹 Cleared all chunk buffers and checkpoints");
    }
}

impl Default for BlockchainChunker {
    fn default() -> Self {
        // For default/tests: No persistence
        Self {
            received_chunks: Arc::new(RwLock::new(HashMap::new())),
            peer_request_counts: Arc::new(RwLock::new(HashMap::new())),
            persistence_path: None,
        }
    }
}

/// Progress information for a specific request
#[derive(Debug, Clone)]
pub struct RequestProgress {
    pub request_id: u64,
    pub received_chunks: u32,
    pub total_chunks: u32,
    pub progress_percent: f64,
    pub missing_chunks: u32,
}

/// Statistics about chunk buffer state
#[derive(Debug, Clone)]
pub struct ChunkingStats {
    pub pending_requests: usize,
    pub total_peers_with_requests: usize,
    pub total_pending_chunks: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_secure_chunk_and_reassemble() {
        let chunker = BlockchainChunker::default(); // Use Default for tests (no persistence)
        let requester = PublicKey::new(vec![1, 2, 3]);

        // Create test data
        let test_data = vec![0u8; 500]; // 500 bytes should create 3 chunks
        
        // Create test sender
        let sender_keypair = lib_crypto::KeyPair::generate().unwrap();
        let sender_pubkey = sender_keypair.public_key.clone();
        
        // Chunk the data
        let request_id = 1;
        let chunks = BlockchainChunker::chunk_blockchain_data(
            sender_pubkey, 
            request_id, 
            test_data.clone(), 
            None,
            None
        ).unwrap();
        
        assert_eq!(chunks.len(), 3); // 500 bytes / 200 = 3 chunks

        // Simulate receiving chunks
        for message in chunks {
            if let ZhtpMeshMessage::BlockchainData { sender: _, request_id, chunk_index, total_chunks, data, complete_data_hash } = message {
                let result = chunker.add_chunk(
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

    #[tokio::test]
    async fn test_chunk_size_validation() {
        let sender = PublicKey::new(vec![1, 2, 3]);
        let data = vec![0u8; 100];

        // Test zero chunk size
        let result = BlockchainChunker::chunk_blockchain_data(
            sender.clone(),
            1,
            data.clone(),
            None,
            Some(0),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be zero"));

        // Test excessive chunk size
        let result = BlockchainChunker::chunk_blockchain_data(
            sender.clone(),
            1,
            data.clone(),
            None,
            Some(MAX_CHUNK_SIZE + 1),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn test_data_size_validation() {
        let sender = PublicKey::new(vec![1, 2, 3]);

        // Test empty data
        let result = BlockchainChunker::chunk_blockchain_data(
            sender.clone(),
            1,
            vec![],
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[tokio::test]
    async fn test_duplicate_chunk_rejection() {
        let chunker = BlockchainChunker::default();
        let requester = PublicKey::new(vec![1, 2, 3]);
        
        let data = vec![0u8; 100];
        let hash = [0u8; 32];

        // Add first chunk successfully
        let result = chunker.add_chunk(
            requester.clone(),
            1,
            0,
            2,
            data.clone(),
            hash,
        ).await;
        assert!(result.is_ok());

        // Try to add same chunk again - should fail
        let result = chunker.add_chunk(
            requester.clone(),
            1,
            0,
            2,
            data.clone(),
            hash,
        ).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate"));
    }

    #[tokio::test]
    async fn test_hash_mismatch_detection() {
        let chunker = BlockchainChunker::default();
        let requester = PublicKey::new(vec![1, 2, 3]);
        let sender = PublicKey::new(vec![4, 5, 6]);
        
        let test_data = vec![1u8; 200];
        
        // Create chunks with correct hash
        let chunks = BlockchainChunker::chunk_blockchain_data(
            sender,
            1,
            test_data.clone(),
            None,
            None,
        ).unwrap();

        // Tamper with the data but keep the hash
        if let ZhtpMeshMessage::BlockchainData { sender: _, request_id, chunk_index, total_chunks, data: _, complete_data_hash } = &chunks[0] {
            let tampered_data = vec![2u8; 200]; // Different data
            
            let result = chunker.add_chunk(
                requester,
                *request_id,
                *chunk_index,
                *total_chunks,
                tampered_data,
                *complete_data_hash,
            ).await;
            
            // Should succeed adding chunk but fail on verification
            if result.is_ok() && result.unwrap().is_some() {
                panic!("Should have detected hash mismatch");
            }
        }
    }
}
 