use std::time::Duration;
use crate::storage_network_integration::{
    channel_handler,
    spawn_network_output_processor,
    NetworkOutputHandler,
};
use lib_network::NetworkOutput;
use lib_crypto::PublicKey;
use lib_network::types::mesh_message::{BlockchainRequestType, ZhtpMeshMessage};
use lib_network::protocols::bluetooth::gatt::EdgeSyncMessage;
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{info, warn, error, debug};

/// Application-level handler mapping NetworkOutput to storage/blockchain actions.
///
/// This handler serves blockchain data to peers requesting sync via mesh messages.
/// It reads from the local blockchain and sends BlockchainData chunks back.
///
/// Uses the global mesh router provider to send responses, so it doesn't need
/// to be constructed with any dependencies.
pub struct AppNetworkOutputHandler;

impl AppNetworkOutputHandler {
    /// Create a new handler
    pub fn new() -> Self {
        Self
    }

    /// Send blockchain data chunks to a peer via the global mesh router
    async fn send_blockchain_data(
        requester: &PublicKey,
        request_id: u64,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        // Get global mesh router
        let mesh_router = crate::runtime::mesh_router_provider::get_global_mesh_router().await
            .map_err(|e| anyhow::anyhow!("Mesh router not available: {}", e))?;

        // Create sender PublicKey from server_id UUID
        // The actual identity verification happens at the transport layer (UHP)
        let server_id_bytes = mesh_router.server_id.as_bytes();
        let mut key_id = Vec::with_capacity(32);
        key_id.extend_from_slice(server_id_bytes);
        key_id.extend_from_slice(server_id_bytes); // Repeat to fill 32 bytes
        let sender = PublicKey::new(key_id);

        // Calculate complete data hash using lib_crypto
        let hash_bytes = lib_crypto::hash_blake3(&data);
        let complete_data_hash: [u8; 32] = hash_bytes[..32].try_into()
            .unwrap_or([0u8; 32]);

        // Chunk size for mesh messages (conservative for BLE compatibility)
        const CHUNK_SIZE: usize = 512;
        let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
        let total_chunks = chunks.len() as u32;

        info!(
            "📤 Sending {} bytes in {} chunks to peer {:?} (request_id: {})",
            data.len(),
            total_chunks,
            hex::encode(&requester.key_id[..8.min(requester.key_id.len())]),
            request_id
        );

        for (i, chunk) in chunks.into_iter().enumerate() {
            let message = ZhtpMeshMessage::BlockchainData {
                sender: sender.clone(),
                request_id,
                chunk_index: i as u32,
                total_chunks,
                data: chunk.to_vec(),
                complete_data_hash,
            };

            if let Err(e) = mesh_router.send_to_peer(requester, message).await {
                warn!("Failed to send chunk {}/{} to peer: {}", i + 1, total_chunks, e);
                // Continue trying to send remaining chunks
            } else {
                debug!("Sent chunk {}/{}", i + 1, total_chunks);
            }
        }

        Ok(())
    }
}

impl Default for AppNetworkOutputHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkOutputHandler for AppNetworkOutputHandler {
    async fn handle_blockchain_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        request: BlockchainRequestType,
    ) {
        info!(
            "📥 BlockchainRequest {:?} req_id={} from {:?}",
            request,
            request_id,
            hex::encode(&requester.key_id[..8.min(requester.key_id.len())])
        );

        // Get blockchain from global provider
        let blockchain = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Cannot serve blockchain request: {}", e);
                return;
            }
        };

        let blockchain_guard = blockchain.read().await;

        match request {
            BlockchainRequestType::FullChain => {
                info!("Serving full blockchain ({} blocks)", blockchain_guard.height);
                match bincode::serialize(&blockchain_guard.blocks) {
                    Ok(data) => {
                        drop(blockchain_guard);
                        if let Err(e) = Self::send_blockchain_data(&requester, request_id, data).await {
                            error!("Failed to send full chain: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize blockchain: {}", e);
                    }
                }
            }
            BlockchainRequestType::BlocksAfter(height) => {
                let current_height = blockchain_guard.height;
                if height >= current_height {
                    info!("Peer already up to date (requested after {}, current {})", height, current_height);
                    return;
                }

                let start_idx = (height + 1) as usize;
                let blocks_to_send: Vec<_> = blockchain_guard.blocks
                    .iter()
                    .skip(start_idx)
                    .cloned()
                    .collect();

                info!("Serving {} blocks after height {}", blocks_to_send.len(), height);
                match bincode::serialize(&blocks_to_send) {
                    Ok(data) => {
                        drop(blockchain_guard);
                        if let Err(e) = Self::send_blockchain_data(&requester, request_id, data).await {
                            error!("Failed to send blocks: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize blocks: {}", e);
                    }
                }
            }
            BlockchainRequestType::Block(height) => {
                if let Some(block) = blockchain_guard.blocks.get(height as usize) {
                    info!("Serving block at height {}", height);
                    match bincode::serialize(block) {
                        Ok(data) => {
                            drop(blockchain_guard);
                            if let Err(e) = Self::send_blockchain_data(&requester, request_id, data).await {
                                error!("Failed to send block: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to serialize block: {}", e);
                        }
                    }
                } else {
                    warn!("Block at height {} not found", height);
                }
            }
            BlockchainRequestType::Transaction(tx_id) => {
                // Search for transaction in all blocks
                for block in &blockchain_guard.blocks {
                    for tx in &block.transactions {
                        let tx_hash = hex::encode(tx.hash().as_bytes());
                        if tx_hash == tx_id || tx_hash.starts_with(&tx_id) {
                            info!("Serving transaction {}", tx_id);
                            match bincode::serialize(tx) {
                                Ok(data) => {
                                    drop(blockchain_guard);
                                    if let Err(e) = Self::send_blockchain_data(&requester, request_id, data).await {
                                        error!("Failed to send transaction: {}", e);
                                    }
                                    return;
                                }
                                Err(e) => {
                                    error!("Failed to serialize transaction: {}", e);
                                    return;
                                }
                            }
                        }
                    }
                }
                warn!("Transaction {} not found", tx_id);
            }
            BlockchainRequestType::Mempool => {
                info!("Serving mempool ({} pending transactions)", blockchain_guard.pending_transactions.len());
                match bincode::serialize(&blockchain_guard.pending_transactions) {
                    Ok(data) => {
                        drop(blockchain_guard);
                        if let Err(e) = Self::send_blockchain_data(&requester, request_id, data).await {
                            error!("Failed to send mempool: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize mempool: {}", e);
                    }
                }
            }
            BlockchainRequestType::HeadersOnly { start_height, count } => {
                let _end_height = (start_height + count as u64).min(blockchain_guard.height);
                let headers: Vec<_> = blockchain_guard.blocks
                    .iter()
                    .skip(start_height as usize)
                    .take(count as usize)
                    .map(|b| b.header.clone())
                    .collect();

                info!("Serving {} headers from height {}", headers.len(), start_height);
                match bincode::serialize(&headers) {
                    Ok(data) => {
                        drop(blockchain_guard);
                        if let Err(e) = Self::send_blockchain_data(&requester, request_id, data).await {
                            error!("Failed to send headers: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize headers: {}", e);
                    }
                }
            }
            BlockchainRequestType::BootstrapWithHeaders { current_height: _ } => {
                // This is for edge nodes - send a proof + recent headers
                warn!("BootstrapWithHeaders not fully implemented yet (edge node sync)");
                // TODO: Generate ChainRecursiveProof and recent headers
            }
        }
    }

    async fn handle_bootstrap_proof_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        current_height: u64,
    ) {
        info!(
            "📥 BootstrapProofRequest req_id={} current_height={} from {:?}",
            request_id,
            current_height,
            hex::encode(&requester.key_id[..8.min(requester.key_id.len())])
        );
        // TODO: Generate ChainRecursiveProof for edge node verification
        warn!("BootstrapProofRequest not yet implemented (edge node ZK proof sync)");
    }

    async fn handle_edge_sync_request(
        &self,
        peer: String,
        message: EdgeSyncMessage,
    ) {
        warn!("EdgeSyncRequest from {} message {:?} (not implemented)", peer, message);
        // TODO: Forward to edge sync subsystem
    }
}

/// Spawn background processor using the app handler.
///
/// This starts serving blockchain data to peers who request it via mesh messages.
/// Uses global providers for mesh router and node identity.
pub fn spawn_app_network_output_processor() {
    // drain every 500ms; adjust as needed
    spawn_network_output_processor(AppNetworkOutputHandler::new(), Duration::from_millis(500));
    info!("📤 Block sync responder started (serving blockchain data to peers)");
}

/// Example of using channel-based fan-out for outputs.
pub fn channel_dispatcher() -> UnboundedReceiver<NetworkOutput> {
    let (handler, rx) = channel_handler();
    // Start processor with channel handler
    spawn_network_output_processor(handler, Duration::from_millis(500));
    rx
}
