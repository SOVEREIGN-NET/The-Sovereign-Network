use anyhow::{Result, anyhow};
use async_trait::async_trait;
use lib_network::blockchain_sync::BlockchainProvider as NetworkBlockchainProvider;
use lib_network::blockchain_sync::{BlockHeader, ChainProof};
use tracing::{debug, warn};

use super::blockchain_provider::{get_global_blockchain, is_global_blockchain_available};

/// Implementation of lib-network's BlockchainProvider trait using zhtp's global blockchain
/// This bridges the application layer blockchain access to the network layer's needs
pub struct ZhtpBlockchainProvider;

impl ZhtpBlockchainProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NetworkBlockchainProvider for ZhtpBlockchainProvider {
    async fn get_current_height(&self) -> Result<u64> {
        debug!("Network layer requesting current blockchain height");
        
        let blockchain = get_global_blockchain().await?;
        let blockchain_lock = blockchain.read().await;
        let height = blockchain_lock.get_height();
        
        debug!("Current blockchain height: {}", height);
        Ok(height)
    }

    async fn get_headers(&self, start_height: u64, count: u64) -> Result<Vec<BlockHeader>> {
        debug!("Network layer requesting {} headers starting from height {}", count, start_height);
        
        let blockchain = get_global_blockchain().await?;
        let blockchain_lock = blockchain.read().await;
        let current_height = blockchain_lock.get_height();
        
        // Calculate how many headers we can actually return
        let end_height = (start_height + count - 1).min(current_height);
        let actual_count = if start_height > current_height {
            0
        } else {
            (end_height - start_height + 1) as usize
        };
        
        debug!("Fetching headers: start={}, end={}, count={}", start_height, end_height, actual_count);
        
        let mut headers = Vec::with_capacity(actual_count);
        for height in start_height..=end_height {
            match blockchain_lock.get_block(height) {
                Some(block) => {
                    // Serialize the header into bytes to match the data-only interface
                    let encoded = bincode::serialize(&block.header)
                        .map_err(|e| anyhow!("Failed to serialize block header: {}", e))?;
                    headers.push(encoded);
                }
                None => {
                    warn!("Block at height {} not found", height);
                    break;
                }
            }
        }
        
        debug!("Successfully retrieved {} headers", headers.len());
        Ok(headers)
    }

    async fn get_full_blockchain(&self) -> Result<Vec<u8>> {
        debug!("Network layer requesting full blockchain");
        
        let blockchain = get_global_blockchain().await?;
        let blockchain_lock = blockchain.read().await;
        
        // Serialize the entire blockchain
        let serialized = bincode::serialize(&*blockchain_lock)
            .map_err(|e| anyhow!("Failed to serialize blockchain: {}", e))?;
        
        debug!("Serialized blockchain: {} bytes", serialized.len());
        Ok(serialized)
    }

    async fn get_chain_proof(&self, up_to_height: u64) -> Result<ChainProof> {
        debug!("Network layer requesting chain proof up to height {}", up_to_height);
        
        let blockchain = get_global_blockchain().await?;
        let mut blockchain_lock = blockchain.write().await;
        
        // Get or initialize the proof aggregator
        let aggregator_arc = blockchain_lock.get_proof_aggregator().await?;
        let aggregator_lock = aggregator_arc.read().await;
        
        // Try to get the cached recursive proof at the requested height
        if let Some(cached_proof) = aggregator_lock.get_recursive_proof(up_to_height) {
            debug!("Found cached chain proof at height {}", up_to_height);
            return Ok(ChainProof {
                chain_tip_height: up_to_height,
                proof: bincode::serialize(&cached_proof)
                    .map_err(|e| anyhow!("Failed to serialize cached chain proof: {}", e))?,
            });
        }
        
        // If no proof at exact height, find the most recent proof <= up_to_height
        // Check a few recent heights in case proofs aren't generated for every block
        for offset in 0..10 {
            if offset > up_to_height {
                break;
            }
            let check_height = up_to_height - offset;
            if let Some(cached_proof) = aggregator_lock.get_recursive_proof(check_height) {
                debug!("Found cached chain proof at height {} (requested {})", check_height, up_to_height);
                return Ok(ChainProof {
                    chain_tip_height: check_height,
                    proof: bincode::serialize(&cached_proof)
                        .map_err(|e| anyhow!("Failed to serialize cached chain proof: {}", e))?,
                });
            }
        }
        
        drop(aggregator_lock);
        drop(blockchain_lock);
        
        // No cached proof found - need to generate one
        // This is a simplified implementation that assumes proofs were generated during block creation
        // In a production system, you'd want to:
        // 1. Generate proofs asynchronously during block validation
        // 2. Cache them at checkpoint intervals (every N blocks)
        // 3. Use consensus-generated proofs from validators
        
        warn!("No cached chain proof found for height {} - blockchain sync coordination may be limited", up_to_height);
        warn!("Note: Proofs should be generated during block validation/consensus");
        
        Err(anyhow::anyhow!(
            "Chain proof not available at height {}. Proofs are generated during consensus. \
             Edge nodes should request proofs from validators that have completed proof generation.",
            up_to_height
        ))
    }

    async fn is_available(&self) -> bool {
        let available = is_global_blockchain_available().await;
        if !available {
            debug!("Blockchain not available to network layer");
        }
        available
    }
}

impl Default for ZhtpBlockchainProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blockchain_not_available_initially() {
        let provider = ZhtpBlockchainProvider::new();
        
        // Should fail gracefully when blockchain not set
        let result = provider.get_current_height().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_available_returns_false_initially() {
        let provider = ZhtpBlockchainProvider::new();
        assert!(!provider.is_available().await);
    }
}
