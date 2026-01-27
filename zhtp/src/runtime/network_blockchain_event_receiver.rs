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

        // Verify and add to chain (with persistence, without re-broadcasting)
        let mut bc = blockchain.write().await;
        match bc.add_block_from_network_with_persistence(block).await {
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
        match bc.add_pending_transaction_from_network(tx) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: ensure the global blockchain provider is initialized with a
    /// fresh blockchain. Safe to call multiple times (OnceLock + Option swap).
    async fn ensure_global_blockchain() {
        let blockchain = lib_blockchain::Blockchain::new()
            .expect("Failed to create test blockchain");
        let bc_arc = std::sync::Arc::new(tokio::sync::RwLock::new(blockchain));
        let _ = super::super::blockchain_provider::set_global_blockchain(bc_arc).await;
    }

    #[test]
    fn test_new_creates_receiver() {
        let _receiver = ZhtpBlockchainEventReceiver::new();
    }

    // -- Block tests ----------------------------------------------------------

    #[tokio::test]
    async fn test_on_block_received_stale_height_is_ignored() {
        ensure_global_blockchain().await;
        let receiver = ZhtpBlockchainEventReceiver::new();

        // Local blockchain has height 0.
        // Sending height 0 (== local) → silently ignored, Ok returned.
        // Garbage bytes are never deserialized because the height check
        // short-circuits before deserialization.
        let result = receiver
            .on_block_received(vec![0xDE, 0xAD], 0, 0, vec![])
            .await;
        assert!(result.is_ok(), "Stale block should be silently ignored");
    }

    #[tokio::test]
    async fn test_on_block_received_invalid_bytes_at_future_height() {
        ensure_global_blockchain().await;
        let receiver = ZhtpBlockchainEventReceiver::new();

        // Height 999 > local 0 → passes height check, attempts deserialization.
        // Garbage bytes → deserialization error.
        let result = receiver
            .on_block_received(vec![0xDE, 0xAD], 999, 0, vec![])
            .await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("deserialize"),
            "Expected deserialization error for garbage block bytes"
        );
    }

    #[tokio::test]
    async fn test_on_block_received_empty_bytes_at_future_height() {
        ensure_global_blockchain().await;
        let receiver = ZhtpBlockchainEventReceiver::new();

        // Empty bytes also fail deserialization.
        let result = receiver
            .on_block_received(vec![], 999, 0, vec![])
            .await;
        assert!(result.is_err(), "Empty bytes should fail deserialization");
    }

    // -- Transaction tests ----------------------------------------------------

    #[tokio::test]
    async fn test_on_transaction_received_invalid_bytes() {
        // Transaction path deserializes BEFORE looking up global blockchain,
        // so this fails with a deserialization error regardless of global state.
        let receiver = ZhtpBlockchainEventReceiver::new();
        let result = receiver
            .on_transaction_received(vec![0xDE, 0xAD], [0u8; 32], 0, vec![])
            .await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("deserialize"),
            "Expected deserialization error for garbage transaction bytes"
        );
    }

    #[tokio::test]
    async fn test_on_transaction_received_empty_bytes() {
        let receiver = ZhtpBlockchainEventReceiver::new();
        let result = receiver
            .on_transaction_received(vec![], [0u8; 32], 0, vec![])
            .await;
        assert!(result.is_err(), "Empty bytes should fail deserialization");
    }
}
