//! Temporary blockchain sync stub to keep lib-network protocol-only.
//! TODO (relocation pass): move real sync logic to the integration layer.

use anyhow::Result;
use async_trait::async_trait;
use lib_crypto::PublicKey;

pub type BlockHeader = Vec<u8>;

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ChainProof {
    pub chain_tip_height: u64,
    pub proof: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct BlockchainSyncManager;

impl BlockchainSyncManager {
    pub fn new_full_node() -> Self {
        Self
    }

    pub fn new_edge_node(_max_headers: usize) -> Self {
        Self
    }

    pub async fn add_chunk(
        &self,
        _sender: &PublicKey,
        _request_id: u64,
        _chunk_index: u32,
        _total_chunks: u32,
        _data: Vec<u8>,
        _complete_data_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

#[async_trait]
pub trait BlockchainProvider: Send + Sync {
    async fn get_current_height(&self) -> Result<u64>;
    async fn get_headers(&self, start_height: u64, count: u64) -> Result<Vec<BlockHeader>>;
    async fn get_chain_proof(&self, up_to_height: u64) -> Result<ChainProof>;
    async fn get_full_blockchain(&self) -> Result<Vec<u8>>;
    async fn is_available(&self) -> bool;
}

#[derive(Clone, Default)]
pub struct NullBlockchainProvider;

#[async_trait]
impl BlockchainProvider for NullBlockchainProvider {
    async fn get_current_height(&self) -> Result<u64> {
        Ok(0)
    }

    async fn get_headers(&self, _start_height: u64, _count: u64) -> Result<Vec<BlockHeader>> {
        Ok(Vec::new())
    }

    async fn get_chain_proof(&self, _up_to_height: u64) -> Result<ChainProof> {
        Ok(ChainProof::default())
    }

    async fn get_full_blockchain(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn is_available(&self) -> bool {
        false
    }
}

#[derive(Clone, Default)]
pub struct SyncCoordinator;

impl SyncCoordinator {
    pub fn new() -> Self {
        Self
    }
}
