//! Blockchain Synchronization over Mesh Protocols
//!
//! Provides peer-to-peer blockchain synchronization using bincode messages
//! over any mesh protocol (Bluetooth, WiFi Direct, LoRaWAN, etc.)
//!
//! Uses strategy pattern to support both full node and edge node sync modes.
//!
//! # Architecture
//!
//! - **Strategy Pattern**: `SyncStrategy` trait with `FullNodeStrategy` and `EdgeNodeStrategy`
//! - **Unified Manager**: `BlockchainSyncManager` handles all sync operations
//! - **Security**: Authentication, rate limiting, buffer limits, and hash verification
//! - **Protocol-Aware**: Automatic chunk sizing based on transport protocol
//!
//! # Example
//!
//! ```no_run
//! use lib_network::blockchain_sync::BlockchainSyncManager;
//!
//! // Create a full node sync manager
//! let sync_manager = BlockchainSyncManager::new_full_node();
//!
//! // Or create an edge node sync manager with limited headers
//! let edge_sync = BlockchainSyncManager::new_edge_node(500);
//! ```

// Public modules
pub mod blockchain_provider;
pub mod sync_coordinator;

// Private implementation modules
mod sync_manager;
mod chunk_buffer;
mod rate_limiter;
mod full_node_strategy;
mod edge_node_strategy;

// Re-exports
pub use blockchain_provider::{BlockchainProvider, NullBlockchainProvider};
pub use sync_coordinator::{SyncCoordinator, PeerSyncState, SyncStats, SyncType};
pub use sync_manager::BlockchainSyncManager;
pub use full_node_strategy::FullNodeStrategy;
pub use edge_node_strategy::EdgeNodeStrategy;

use anyhow::Result;
use lib_crypto::PublicKey;
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
use std::time::Duration;

/// Chunk sizes based on protocol capabilities
pub const BLE_CHUNK_SIZE: usize = 200;       // Conservative for BLE GATT (247-byte MTU)
pub const CLASSIC_CHUNK_SIZE: usize = 1000;  // Bluetooth Classic RFCOMM (larger MTU)
pub const WIFI_CHUNK_SIZE: usize = 1400;     // WiFi Direct (can handle more)
pub const DEFAULT_CHUNK_SIZE: usize = 200;   // Safe fallback

/// Security constraints
pub const MAX_CHUNK_BUFFER_SIZE: usize = 10_000_000;  // 10MB max buffer per request
pub const MAX_PENDING_REQUESTS: usize = 100;          // Max concurrent sync requests
pub const CHUNK_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
pub const MAX_CHUNKS_PER_SECOND: u32 = 100;          // Rate limit per peer

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
    /// If from_height is provided, request data starting from that height
    async fn create_sync_request(&mut self, requester: PublicKey, request_id: u64, from_height: Option<u64>) -> Result<ZhtpMeshMessage>;
    
    /// Process sync response data
    async fn process_sync_response(&mut self, message: &ZhtpMeshMessage) -> Result<()>;
    
    /// Check if sync is needed
    async fn should_sync(&self) -> bool;
    
    /// Get estimated sync size in bytes
    async fn estimate_sync_size(&self) -> usize;
    
    /// Get current blockchain height
    async fn get_current_height(&self) -> u64;
}
