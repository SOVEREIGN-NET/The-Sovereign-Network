use crate::types::mesh_message::ZhtpMeshMessage;
use anyhow::{anyhow, Result};
use lib_crypto::PublicKey;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use super::SyncStrategy;

/// Full node sync strategy - synchronizes complete blockchain
pub struct FullNodeStrategy {
    /// Current blockchain height
    current_height: Arc<RwLock<u64>>,
}

impl FullNodeStrategy {
    pub fn new() -> Self {
        Self {
            current_height: Arc::new(RwLock::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl SyncStrategy for FullNodeStrategy {
    async fn create_sync_request(&mut self, requester: PublicKey, request_id: u64, from_height: Option<u64>) -> Result<ZhtpMeshMessage> {
        // Use provided from_height, or fall back to current height
        let height = match from_height {
            Some(h) => h,
            None => *self.current_height.read().await,
        };
        
        let request_type = if height > 0 {
            crate::types::mesh_message::BlockchainRequestType::BlocksAfter(height)
        } else {
            crate::types::mesh_message::BlockchainRequestType::FullChain
        };

        Ok(ZhtpMeshMessage::BlockchainRequest {
            requester,
            request_id,
            request_type,
        })
    }

    async fn process_sync_response(&mut self, message: &ZhtpMeshMessage) -> Result<()> {
        match message {
            ZhtpMeshMessage::BlockchainData { .. } => {
                // Full node processes complete blockchain data chunks
                debug!("Full node received blockchain data chunk");
                // Processing handled by BlockchainSyncManager::add_chunk
                Ok(())
            }
            _ => Err(anyhow!("Unexpected message type for full node sync")),
        }
    }

    async fn should_sync(&self) -> bool {
        // Full nodes always want to stay synced
        true
    }

    async fn estimate_sync_size(&self) -> usize {
        // Full blockchain can be very large (GBs)
        usize::MAX
    }

    async fn get_current_height(&self) -> u64 {
        *self.current_height.read().await
    }
}
