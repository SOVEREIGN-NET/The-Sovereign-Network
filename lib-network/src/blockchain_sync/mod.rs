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

// ============================================================================
// BFT BOOTSTRAP STRATEGY
// ============================================================================
//
// When a new or restarting BFT node joins the network it must reconstruct a
// trustworthy view of the chain state before participating in consensus. The
// strategy defined here balances security (full cryptographic verification)
// with practical startup time (checkpoint-assisted fast sync).
//
// ## Overview: "checkpoint-then-sync"
//
// The default bootstrap mode is "checkpoint-then-sync":
//
//   1. VERIFY GENESIS
//      The node independently constructs the genesis block using the
//      hardcoded parameters in `lib-blockchain` and verifies that its hash
//      matches the well-known genesis hash published via social consensus.
//      This step has zero network dependency — any mismatch is a fatal
//      configuration error and the node MUST abort.
//
//   2. FIND HIGHEST COMMITTED CHECKPOINT
//      The node queries its peers for the highest BFT-committed checkpoint
//      (a block height for which a quorum certificate / commit proof exists).
//      Peers MUST supply the full quorum certificate so the node can verify
//      it without trusting any single peer.
//      - A checkpoint is only accepted if its age (in blocks from the chain
//        tip) is at least `MIN_CHECKPOINT_AGE_BLOCKS`. Setting this to 0
//        permits using the very latest committed checkpoint.
//      - If no valid checkpoint is found the node falls back to full replay
//        from genesis (see step 3).
//
//   3. SYNC FORWARD (FULL REPLAY OR INCREMENTAL)
//      Starting from the accepted checkpoint height the node downloads and
//      fully validates every subsequent block up to the chain tip.
//      - If the distance from the checkpoint to the tip exceeds
//        `FULL_REPLAY_MAX_BLOCKS`, the node SHOULD request a newer
//        checkpoint rather than replaying an unbounded number of blocks.
//      - Block validation includes BFT quorum certificate checks, merkle
//        root verification, transaction signature verification, and UTXO
//        consistency checks.
//
// ## Security Properties
//
// - The genesis block is NEVER downloaded from peers. It is always constructed
//   locally from hardcoded parameters (social consensus trust root).
// - Checkpoints are only trusted after verifying the embedded quorum
//   certificate against the known validator set.
// - No block is accepted without full cryptographic validation.
//
// ## Assertions
//
// `assert_bootstrap_constants` (below) checks that the constants defined here
// are internally consistent and should be called during node startup.
// ============================================================================

/// Bootstrap mode identifier.
///
/// The only supported value is `"checkpoint-then-sync"`. This constant is
/// intentionally a `&str` rather than an enum so it can be logged and
/// compared to configuration files without additional dependencies.
pub const BOOTSTRAP_MODE: &str = "checkpoint-then-sync";

/// Minimum checkpoint age in blocks before it may be used for bootstrap.
///
/// A value of 0 permits using the most recently committed checkpoint (i.e. the
/// checkpoint at the very tip of the committed chain). Raise this value if the
/// deployment requires extra finality depth before trusting a checkpoint.
pub const MIN_CHECKPOINT_AGE_BLOCKS: u64 = 0;

/// Maximum number of blocks to replay forward from a checkpoint before
/// requiring a newer checkpoint.
///
/// If the gap between the accepted checkpoint height and the network tip
/// exceeds this limit, the bootstrapping node SHOULD request a more recent
/// checkpoint rather than performing an unbounded forward replay. This
/// prevents slow startup on heavily-loaded networks.
pub const FULL_REPLAY_MAX_BLOCKS: u64 = 1_000;

/// Assert that the bootstrap strategy constants are internally consistent.
///
/// Call this once during node initialisation (e.g. in the network subsystem
/// `new()` constructor) so that configuration regressions are caught early.
///
/// # Panics
///
/// Panics if any constant violates a well-formedness condition.
pub fn assert_bootstrap_constants() {
    assert_eq!(
        BOOTSTRAP_MODE, "checkpoint-then-sync",
        "BOOTSTRAP INVARIANT VIOLATED: BOOTSTRAP_MODE must be \"checkpoint-then-sync\""
    );
    // MIN_CHECKPOINT_AGE_BLOCKS is always valid as a u64; document that 0 is
    // intentional (use the most recent committed checkpoint).
    assert!(
        FULL_REPLAY_MAX_BLOCKS > 0,
        "BOOTSTRAP INVARIANT VIOLATED: FULL_REPLAY_MAX_BLOCKS must be greater than zero"
    );
}

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
