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
use crate::mtu::{
    BLE_CHUNK_SIZE, BLUETOOTH_CLASSIC_CHUNK_SIZE, WIFI_DIRECT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE,
};
use std::time::Duration;

/// Re-export chunk sizes for backward compatibility
#[deprecated(since = "0.1.0", note = "Use crate::mtu::BLE_CHUNK_SIZE instead")]
pub const BLE_CHUNK_SIZE_COMPAT: usize = BLE_CHUNK_SIZE;

#[deprecated(since = "0.1.0", note = "Use crate::mtu::BLUETOOTH_CLASSIC_CHUNK_SIZE instead")]
pub const CLASSIC_CHUNK_SIZE: usize = BLUETOOTH_CLASSIC_CHUNK_SIZE;

#[deprecated(since = "0.1.0", note = "Use crate::mtu::WIFI_DIRECT_CHUNK_SIZE instead")]
pub const WIFI_CHUNK_SIZE: usize = WIFI_DIRECT_CHUNK_SIZE;

/// Security constraints - Original limits
pub const MAX_CHUNK_BUFFER_SIZE: usize = 10_000_000;  // 10MB max buffer per request
pub const MAX_PENDING_REQUESTS: usize = 100;          // Max concurrent sync requests
pub const CHUNK_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
pub const MAX_CHUNKS_PER_SECOND: u32 = 100;          // Rate limit per peer

/// Security constraints - Stricter limits (Issue #484)
/// Maximum allowed chunk size (10 MB to prevent memory exhaustion per chunk)
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

/// Get optimal chunk size for protocol
pub fn get_chunk_size_for_protocol(protocol: &NetworkProtocol) -> usize {
    use crate::mtu::Protocol;
    
    match protocol {
        NetworkProtocol::BluetoothLE => Protocol::BluetoothLE.chunk_size(),
        NetworkProtocol::BluetoothClassic => Protocol::BluetoothClassic.chunk_size(),
        NetworkProtocol::WiFiDirect => Protocol::WiFiDirect.chunk_size(),
        NetworkProtocol::TCP | NetworkProtocol::UDP => Protocol::Udp.chunk_size(),
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
