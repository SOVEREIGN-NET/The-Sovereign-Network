use crate::types::mesh_message::ZhtpMeshMessage;
use anyhow::{anyhow, Result};
use lib_crypto::PublicKey;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::SyncStrategy;

/// Full node sync strategy - synchronizes complete blockchain up to the
/// highest BFT-committed height reported by the peer (Issue #950).
///
/// Sync target selection:
/// 1. If the caller supplies an explicit `from_height`, that height is used.
/// 2. Otherwise the strategy uses `highest_committed_bft_height`, which is
///    updated whenever a peer announces its committed BFT tip via
///    `set_highest_committed_bft_height`.
/// 3. If no committed height has been recorded yet, falls back to
///    `current_height` (local tip) so that an incremental request is still
///    issued rather than a full-chain download.
///
/// There is intentionally NO longest-chain or total-work scoring here.
pub struct FullNodeStrategy {
    /// Local blockchain height (our own tip)
    current_height: Arc<RwLock<u64>>,
    /// Highest BFT-committed block height seen from any peer.
    /// This is the primary sync target (Issue #950).
    highest_committed_bft_height: Arc<RwLock<u64>>,
}

impl FullNodeStrategy {
    pub fn new() -> Self {
        Self {
            current_height: Arc::new(RwLock::new(0)),
            highest_committed_bft_height: Arc::new(RwLock::new(0)),
        }
    }

    /// Update the highest committed BFT height seen from peers.
    ///
    /// Should be called whenever a peer advertisement or block announcement
    /// carries a `committed_height` field. Only advances (never decreases).
    pub async fn set_highest_committed_bft_height(&self, height: u64) {
        let mut current = self.highest_committed_bft_height.write().await;
        if height > *current {
            info!(
                "Sync target updated: highest committed BFT height {} -> {}",
                *current, height
            );
            *current = height;
        }
    }

    /// Update our local chain tip height.
    pub async fn set_current_height(&self, height: u64) {
        let mut h = self.current_height.write().await;
        *h = height;
    }
}

#[async_trait::async_trait]
impl SyncStrategy for FullNodeStrategy {
    async fn create_sync_request(
        &mut self,
        requester: PublicKey,
        request_id: u64,
        from_height: Option<u64>,
    ) -> Result<ZhtpMeshMessage> {
        // Determine the sync target height.
        //
        // Priority order (Issue #950 – target highest committed BFT height):
        //   1. Explicit override supplied by the caller.
        //   2. Highest committed BFT height reported by peers.
        //   3. Local chain tip (incremental fallback so we never stall).
        let committed = *self.highest_committed_bft_height.read().await;
        let local = *self.current_height.read().await;

        let sync_from = match from_height {
            Some(h) => h,
            None => {
                // Request blocks after our local tip; committed height is used only in should_sync()
                local
            }
        };

        let request_type = if sync_from > 0 {
            crate::types::mesh_message::BlockchainRequestType::BlocksAfter(sync_from)
        } else {
            crate::types::mesh_message::BlockchainRequestType::FullChain
        };

        info!(
            "Full node sync request: from_height={} committed_bft={} local={} request_type={:?}",
            sync_from, committed, local, request_type
        );

        Ok(ZhtpMeshMessage::BlockchainRequest {
            requester,
            request_id,
            request_type,
        })
    }

    async fn process_sync_response(&mut self, message: &ZhtpMeshMessage) -> Result<()> {
        match message {
            ZhtpMeshMessage::BlockchainData { .. } => {
                // Full node processes complete blockchain data chunks.
                // Actual reassembly is handled by BlockchainSyncManager::add_chunk.
                debug!("Full node received blockchain data chunk");
                Ok(())
            }
            _ => Err(anyhow!("Unexpected message type for full node sync")),
        }
    }

    async fn should_sync(&self) -> bool {
        // Sync whenever the peer's committed BFT height is ahead of our local tip,
        // or on bootstrap when both are 0.
        let committed = *self.highest_committed_bft_height.read().await;
        let local = *self.current_height.read().await;
        committed > local || (committed == 0 && local == 0)
    }

    async fn estimate_sync_size(&self) -> usize {
        // Full blockchain can be very large (GBs).
        usize::MAX
    }

    async fn get_current_height(&self) -> u64 {
        *self.current_height.read().await
    }
}
