//! Blockchain Provider Trait for Application Layer Integration
//! 
//! This trait allows the network layer to access blockchain data without
//! creating circular dependencies with lib-blockchain. The application layer
//! (zhtp) implements this trait and passes it to the network layer.
//!
//! ## Use Cases:
//! - **Edge Node Bootstrap**: Get ChainRecursiveProof + recent headers
//! - **Edge Node Incremental Sync**: Get specific headers for rolling window
//! - **Full Node Bootstrap**: Full nodes can ALSO use ChainRecursiveProof to verify
//!   chain validity quickly, then request full blocks via BlockchainRequest
//!
//! ## Full Node vs Edge Node:
//! - **Edge Nodes**: Use BootstrapProofRequest/HeadersRequest (headers only, ~20-100 KB)
//! - **Full Nodes**: Use ChainRecursiveProof for validation, then BlockchainRequest
//!   for complete block data (full blockchain, GBs)

use anyhow::Result;
use async_trait::async_trait;
use lib_blockchain::block::BlockHeader;
use lib_proofs::ChainRecursiveProof;

/// Blockchain provider trait for accessing blockchain data from network layer
#[async_trait]
pub trait BlockchainProvider: Send + Sync {
    /// Get current blockchain height
    async fn get_current_height(&self) -> Result<u64>;
    
    /// Get block headers starting from a specific height
    /// Returns up to `count` headers
    async fn get_headers(&self, start_height: u64, count: u64) -> Result<Vec<BlockHeader>>;
    
    /// Get or generate a recursive chain proof for bootstrapping edge nodes
    /// This should return a cached proof if available, or generate a new one
    async fn get_chain_proof(&self, up_to_height: u64) -> Result<ChainRecursiveProof>;
    
    /// Get the full blockchain data (for bootstrap sync)
    /// This returns the serialized blockchain for new nodes to download
    async fn get_full_blockchain(&self) -> Result<Vec<u8>>;
    
    /// Check if blockchain is available
    async fn is_available(&self) -> bool;
}

/// No-op blockchain provider for testing/when blockchain is not available
#[derive(Debug, Clone)]
pub struct NullBlockchainProvider;

#[async_trait]
impl BlockchainProvider for NullBlockchainProvider {
    async fn get_current_height(&self) -> Result<u64> {
        Err(anyhow::anyhow!("Blockchain not available"))
    }
    
    async fn get_headers(&self, _start_height: u64, _count: u64) -> Result<Vec<BlockHeader>> {
        Err(anyhow::anyhow!("Blockchain not available"))
    }
    
    async fn get_chain_proof(&self, _up_to_height: u64) -> Result<ChainRecursiveProof> {
        Err(anyhow::anyhow!("Blockchain not available"))
    }
    
    async fn get_full_blockchain(&self) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("Blockchain not available"))
    }
    
    async fn is_available(&self) -> bool {
        false
    }
}
