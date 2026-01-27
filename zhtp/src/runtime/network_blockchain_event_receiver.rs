//! Receive-side blockchain event receiver (#916)
//!
//! Implements lib-network's BlockchainEventReceiver trait to forward
//! blocks and transactions received from mesh peers into the local blockchain.

use anyhow::Result;
use async_trait::async_trait;
use lib_network::blockchain_sync::BlockchainEventReceiver;
use tracing::{info, warn, debug};

use super::blockchain_provider::get_global_blockchain;

/// Application-layer receiver that imports mesh-received blocks/transactions
/// into the local blockchain instance.
pub struct ZhtpBlockchainEventReceiver;

impl Default for ZhtpBlockchainEventReceiver {
    fn default() -> Self {
        Self
    }
}

impl ZhtpBlockchainEventReceiver {
    pub fn new() -> Self {
        Self::default()
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
        // Deserialize before acquiring any lock (no shared state needed)
        let block: lib_blockchain::Block = bincode::deserialize(&block_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize received block: {}", e))?;

        let blockchain = get_global_blockchain().await?;

        // Acquire write lock and perform height check + import atomically.
        // This prevents a race where another thread imports the same block
        // between a read-lock height check and a subsequent write-lock import.
        let mut bc = blockchain.write().await;
        let local_height = bc.get_height();

        if height <= local_height {
            debug!("Ignoring block {} (local height {})", height, local_height);
            return Ok(());
        }

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

    /// Build a minimal valid serialized block for testing.
    fn make_serialized_block(height: u64) -> Vec<u8> {
        let header = lib_blockchain::BlockHeader::new(
            1, // version
            lib_blockchain::Hash::zero(),
            lib_blockchain::Hash::zero(),
            0, // timestamp
            lib_blockchain::Difficulty::default(),
            height,
            0, // transaction_count
            0, // block_size
            lib_blockchain::Difficulty::default(),
        );
        let block = lib_blockchain::Block::new(header, vec![]);
        bincode::serialize(&block).expect("Failed to serialize test block")
    }

    // -- Block tests ----------------------------------------------------------

    #[tokio::test]
    async fn test_on_block_received_stale_height_is_ignored() {
        ensure_global_blockchain().await;
        let receiver = ZhtpBlockchainEventReceiver::new();

        // Local blockchain has height 0.
        // Sending a valid block at height 0 (== local) → silently ignored.
        let block_bytes = make_serialized_block(0);
        let result = receiver
            .on_block_received(block_bytes, 0, 0, vec![])
            .await;
        assert!(result.is_ok(), "Stale block should be silently ignored");
    }

    #[tokio::test]
    async fn test_on_block_received_invalid_bytes() {
        ensure_global_blockchain().await;
        let receiver = ZhtpBlockchainEventReceiver::new();

        // Garbage bytes → deserialization error (happens before any lock).
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
    async fn test_on_block_received_empty_bytes() {
        ensure_global_blockchain().await;
        let receiver = ZhtpBlockchainEventReceiver::new();

        // Empty bytes fail deserialization (before any lock).
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
