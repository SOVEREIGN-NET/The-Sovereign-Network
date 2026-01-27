//! Temporary blockchain sync stub to keep lib-network protocol-only.
//! TODO (relocation pass): move real sync logic to the integration layer.

use anyhow::Result;
use async_trait::async_trait;
use lib_crypto::PublicKey;
use crate::protocols::bluetooth::gatt::EdgeSyncMessage;
use crate::types::mesh_message::BlockchainRequestType;

pub type BlockHeader = Vec<u8>;

#[derive(Clone, Copy, Debug)]
pub enum SyncType {
    EdgeNode,
    FullBlockchain,
}

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

    pub async fn cleanup_stale_chunks(&self) -> Result<()> {
        Ok(())
    }

    pub async fn register_authenticated_peer(&self, _peer: &PublicKey) -> Result<()> {
        Ok(())
    }

    pub async fn create_blockchain_request(
        &self,
        _peer: PublicKey,
        _maybe_type: Option<BlockchainRequestType>,
    ) -> Result<(u64, EdgeSyncMessage)> {
        Ok((
            1,
            EdgeSyncMessage::HeadersRequest {
                request_id: 1,
                start_height: 0,
                count: 0,
            },
        ))
    }

    /// Stub: chunk data for protocol-appropriate sizes (no-op, returns empty)
    pub fn chunk_blockchain_data_for_protocol(
        _sender: PublicKey,
        _request_id: u64,
        _data: Vec<u8>,
        _protocol: &crate::protocols::NetworkProtocol,
    ) -> Result<Vec<crate::types::mesh_message::ZhtpMeshMessage>> {
        Ok(Vec::new())
    }

    /// Stub: chunk data with default size (no-op, returns empty)
    pub fn chunk_blockchain_data(
        _sender: PublicKey,
        _request_id: u64,
        _data: Vec<u8>,
    ) -> Result<Vec<crate::types::mesh_message::ZhtpMeshMessage>> {
        Ok(Vec::new())
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

/// Receive-side event sink for blocks and transactions arriving over the mesh.
/// Implemented by the application layer (zhtp) and injected into MeshMessageHandler.
/// lib-network emits facts; the application layer decides what to do with them.
#[async_trait]
pub trait BlockchainEventReceiver: Send + Sync {
    /// A peer announced a new block over the mesh network.
    async fn on_block_received(
        &self,
        block_bytes: Vec<u8>,
        height: u64,
        timestamp: u64,
        sender_key: Vec<u8>,
    ) -> Result<()>;

    /// A peer announced a new transaction over the mesh network.
    async fn on_transaction_received(
        &self,
        transaction_bytes: Vec<u8>,
        tx_hash: [u8; 32],
        fee: u64,
        sender_key: Vec<u8>,
    ) -> Result<()>;
}

/// No-op receiver for when blockchain integration is not wired
#[derive(Clone, Default)]
pub struct NullBlockchainEventReceiver;

#[async_trait]
impl BlockchainEventReceiver for NullBlockchainEventReceiver {
    async fn on_block_received(&self, _: Vec<u8>, height: u64, _: u64, _: Vec<u8>) -> Result<()> {
        tracing::warn!("Block {} received but no event receiver configured", height);
        Ok(())
    }
    async fn on_transaction_received(&self, _: Vec<u8>, _: [u8; 32], _: u64, _: Vec<u8>) -> Result<()> {
        tracing::warn!("Transaction received but no event receiver configured");
        Ok(())
    }
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

    pub async fn register_peer_protocol(
        &self,
        _peer: PublicKey,
        _protocol: crate::protocols::NetworkProtocol,
        _sync_type: SyncType,
    ) -> bool {
        true
    }

    pub async fn start_sync(
        &self,
        _peer: PublicKey,
        _request_id: u64,
        _sync_type: SyncType,
        _protocol: crate::protocols::NetworkProtocol,
    ) {
    }

    pub async fn fail_sync(&self, _peer: &PublicKey, _request_id: u64, _sync_type: SyncType) {
    }

    pub async fn complete_sync(&self, _peer: &PublicKey, _request_id: u64, _sync_type: SyncType) {
    }

    pub async fn find_peer_by_sync_id(&self, _request_id: u64) -> Option<(PublicKey, SyncType)> {
        None
    }
}
