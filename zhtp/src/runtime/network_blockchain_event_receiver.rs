//! Receive-side blockchain event receiver (#916)
//!
//! Implements lib-network's BlockchainEventReceiver trait to forward
//! blocks and transactions received from mesh peers into the local blockchain.

use anyhow::Result;
use async_trait::async_trait;
use lib_network::blockchain_sync::BlockchainEventReceiver;
use tracing::{info, warn, error, debug};

use super::blockchain_provider::get_global_blockchain;

/// Application-layer receiver that imports mesh-received blocks/transactions
/// into the local blockchain instance.
pub struct ZhtpBlockchainEventReceiver;

impl ZhtpBlockchainEventReceiver {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl BlockchainEventReceiver for ZhtpBlockchainEventReceiver {
    async fn on_block_received(
        &self,
        block_bytes: Vec<u8>,
        height: u64,
        _timestamp: u64,
        _sender_key: Vec<u8>,
    ) -> Result<()> {
        let blockchain = get_global_blockchain().await?;
        let local_height = {
            blockchain.read().await.get_height()
        };

        if height <= local_height {
            debug!("Ignoring block {} (local height {})", height, local_height);
            return Ok(());
        }

        // Deserialize the block
        let block: lib_blockchain::Block = bincode::deserialize(&block_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize received block: {}", e))?;

        // Verify and add to chain (with persistence)
        let mut bc = blockchain.write().await;
        match bc.add_block_with_persistence(block).await {
            Ok(()) => {
                info!("Imported block {} from mesh peer", height);
                Ok(())
            }
            Err(e) => {
                warn!("Rejected block {} from mesh peer: {}", height, e);
                Err(e)
            }
        }
    }

    async fn on_transaction_received(
        &self,
        tx_bytes: Vec<u8>,
        tx_hash: [u8; 32],
        _fee: u64,
        _sender_key: Vec<u8>,
    ) -> Result<()> {
        let tx: lib_blockchain::Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize received transaction: {}", e))?;

        let blockchain = get_global_blockchain().await?;
        let mut bc = blockchain.write().await;
        match bc.add_pending_transaction(tx) {
            Ok(()) => {
                info!("Added transaction {} to mempool from mesh peer",
                      hex::encode(&tx_hash[..8]));
                Ok(())
            }
            Err(e) => {
                debug!("Rejected transaction {} from mesh peer: {}",
                       hex::encode(&tx_hash[..8]), e);
                Err(e)
            }
        }
    }
}
