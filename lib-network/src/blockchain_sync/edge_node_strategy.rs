use crate::types::mesh_message::ZhtpMeshMessage;
use anyhow::{anyhow, Result};
use lib_blockchain::edge_node_state::{EdgeNodeState, SyncStrategy as EdgeSyncStrategy};
use lib_blockchain::BlockHeader;
use lib_crypto::PublicKey;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::SyncStrategy;

/// Edge node sync strategy - headers-only with ZK proofs
pub struct EdgeNodeStrategy {
    /// Core edge node state (rolling header window)
    edge_state: Arc<RwLock<EdgeNodeState>>,
    /// Current network height (updated from peers)
    network_height: Arc<RwLock<u64>>,
}

impl EdgeNodeStrategy {
    pub fn new(max_headers: usize) -> Self {
        info!("🔧 Initializing EdgeNodeStrategy with {} header capacity", max_headers);
        Self {
            edge_state: Arc::new(RwLock::new(EdgeNodeState::new(max_headers))),
            network_height: Arc::new(RwLock::new(0)),
        }
    }

    /// Update the known network height (from peer announcements)
    pub async fn update_network_height(&self, height: u64) {
        let mut current = self.network_height.write().await;
        if height > *current {
            *current = height;
            debug!("📊 Network height updated to {}", height);
        }
    }

    /// Get the current sync strategy based on network state
    async fn get_edge_sync_strategy(&self) -> Result<EdgeSyncStrategy> {
        let edge_state = self.edge_state.read().await;
        let network_height = *self.network_height.read().await;
        
        if network_height == 0 {
            return Err(anyhow!("Network height unknown - no peers connected"));
        }

        Ok(edge_state.get_sync_strategy(network_height))
    }

    /// Process received block headers with validation and reorg detection
    async fn process_headers(&self, headers: Vec<BlockHeader>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }
        
        // CRITICAL: Verify headers are in sequential order
        for i in 1..headers.len() {
            if headers[i].height != headers[i-1].height + 1 {
                return Err(anyhow!(
                    "Headers not sequential: {}th header has height {}, previous was {}",
                    i, headers[i].height, headers[i-1].height
                ));
            }
            if headers[i].previous_block_hash != headers[i-1].block_hash {
                return Err(anyhow!(
                    "Headers chain broken at index {}: previous_hash mismatch",
                    i
                ));
            }
        }
        
        let mut edge_state = self.edge_state.write().await;
        
        // Check for chain reorganization before accepting headers
        if let Some(first_header) = headers.first() {
            if edge_state.detect_reorg(first_header) {
                warn!("⚠️  CHAIN REORGANIZATION DETECTED!");
                
                let rollback_height = if first_header.height > 0 {
                    first_header.height - 1
                } else {
                    0
                };
                
                if let Err(e) = edge_state.rollback_to_height(rollback_height) {
                    return Err(anyhow!("Rollback failed during reorg: {}", e));
                }
                
                info!("✅ Rolled back to height {} to handle reorg", rollback_height);
            }
        }
        
        let mut added_count = 0;
        for header in headers {
            match edge_state.add_header(header.clone()) {
                Ok(()) => added_count += 1,
                Err(e) => {
                    warn!("⚠️  Failed to add header at height {}: {}", header.height, e);
                    return Err(anyhow!("Header validation failed: {}", e));
                }
            }
        }
        
        info!("✅ Processed {} headers, current height: {}", added_count, edge_state.current_height);
        Ok(())
    }

    /// Process bootstrap proof response with ZK verification
    async fn process_bootstrap_proof(
        &self,
        proof_data: Vec<u8>,
        proof_height: u64,
        headers: Vec<BlockHeader>,
    ) -> Result<()> {
        info!("🔐 Processing bootstrap proof up to height {}", proof_height);
        
        // STEP 1: Verify ZK proof (if proof_data is not empty)
        if !proof_data.is_empty() {
            match self.verify_chain_recursive_proof(&proof_data, proof_height, &headers).await {
                Ok(true) => {
                    info!("✅ Bootstrap ZK proof verified successfully");
                }
                Ok(false) => {
                    return Err(anyhow!("Bootstrap proof verification failed: proof is invalid"));
                }
                Err(e) => {
                    warn!("⚠️  ZK proof verification error: {} - REJECTING bootstrap", e);
                    return Err(anyhow!("Bootstrap proof verification error: {}", e));
                }
            }
        } else {
            warn!("⚠️  No ZK proof provided - accepting headers without cryptographic verification (INSECURE)");
        }
        
        // STEP 2: Validate headers are sequential before accepting
        if headers.len() > 1 {
            for i in 1..headers.len() {
                if headers[i].height != headers[i-1].height + 1 {
                    return Err(anyhow!("Bootstrap headers not sequential at index {}", i));
                }
                if headers[i].previous_block_hash != headers[i-1].block_hash {
                    return Err(anyhow!("Bootstrap headers chain broken at index {}", i));
                }
            }
        }
        
        // STEP 3: Add headers to edge state
        let mut edge_state = self.edge_state.write().await;
        for header in headers {
            if let Err(e) = edge_state.add_header(header) {
                return Err(anyhow!("Failed to add bootstrap header: {}", e));
            }
        }

        info!("✅ Bootstrap complete at height {}", edge_state.current_height);
        Ok(())
    }
    
    /// Verify a ChainRecursiveProof using lib-proofs RecursiveProofAggregator
    async fn verify_chain_recursive_proof(
        &self,
        proof_data: &[u8],
        claimed_height: u64,
        headers: &[BlockHeader],
    ) -> Result<bool> {
        use lib_proofs::RecursiveProofAggregator;
        
        let chain_proof: lib_proofs::ChainRecursiveProof = bincode::deserialize(proof_data)
            .map_err(|e| anyhow!("Failed to deserialize ChainRecursiveProof: {}", e))?;
        
        if chain_proof.chain_tip_height != claimed_height {
            return Err(anyhow!(
                "Proof height mismatch: claimed {} but proof is for {}",
                claimed_height,
                chain_proof.chain_tip_height
            ));
        }
        
        let aggregator = RecursiveProofAggregator::new()
            .map_err(|e| anyhow!("Failed to create proof aggregator: {}", e))?;
        
        let is_valid = aggregator.verify_recursive_chain_proof(&chain_proof)
            .map_err(|e| anyhow!("Recursive proof verification failed: {}", e))?;
        
        if !is_valid {
            warn!("⚠️  Recursive proof cryptographic verification FAILED");
            return Ok(false);
        }
        
        if let Some(first_header) = headers.first() {
            if first_header.height < chain_proof.chain_tip_height {
                warn!("⚠️  Header sequence doesn't align with proof height");
                return Ok(false);
            }
        }
        
        info!("✅ ChainRecursiveProof CRYPTOGRAPHICALLY VERIFIED: genesis {} -> tip {} ({} total txs)",
            chain_proof.genesis_height,
            chain_proof.chain_tip_height,
            chain_proof.total_transaction_count
        );
        
        Ok(true)
    }
}

#[async_trait::async_trait]
impl SyncStrategy for EdgeNodeStrategy {
    async fn create_sync_request(&mut self, requester: PublicKey, request_id: u64, from_height: Option<u64>) -> Result<ZhtpMeshMessage> {
        let strategy = self.get_edge_sync_strategy().await?;

        let message = match strategy {
            EdgeSyncStrategy::HeadersOnly { start_height, count } => {
                // Use provided from_height if available, otherwise use strategy's start_height
                let height = from_height.unwrap_or(start_height);
                info!("📥 Creating HeadersOnly request: height {} count {}", height, count);
                ZhtpMeshMessage::HeadersRequest {
                    requester,
                    request_id,
                    start_height: height,
                    count: count as u32,
                }
            }
            EdgeSyncStrategy::BootstrapProof { proof_up_to_height, .. } => {
                let current_height = self.edge_state.read().await.current_height;
                info!("📥 Creating BootstrapProof request: current {} proof up to {}", 
                    current_height, proof_up_to_height);
                ZhtpMeshMessage::BootstrapProofRequest {
                    requester,
                    request_id,
                    current_height,
                }
            }
        };

        Ok(message)
    }

    async fn process_sync_response(&mut self, message: &ZhtpMeshMessage) -> Result<()> {
        match message {
            ZhtpMeshMessage::HeadersResponse { headers, .. } => {
                // Deserialize headers from Vec<Vec<u8>>
                let block_headers: Result<Vec<BlockHeader>, _> = headers.iter()
                    .map(|h| bincode::deserialize(h))
                    .collect();
                let block_headers = block_headers.map_err(|e| anyhow!("Failed to deserialize headers: {}", e))?;
                self.process_headers(block_headers).await
            }
            ZhtpMeshMessage::BootstrapProofResponse { proof_data, proof_height, headers, .. } => {
                // Deserialize headers from Vec<Vec<u8>>
                let block_headers: Result<Vec<BlockHeader>, _> = headers.iter()
                    .map(|h| bincode::deserialize(h))
                    .collect();
                let block_headers = block_headers.map_err(|e| anyhow!("Failed to deserialize headers: {}", e))?;
                self.process_bootstrap_proof(proof_data.clone(), *proof_height, block_headers).await
            }
            _ => Err(anyhow!("Unexpected message type for edge node sync")),
        }
    }

    async fn should_sync(&self) -> bool {
        let edge_state = self.edge_state.read().await;
        let network_height = *self.network_height.read().await;
        
        if network_height == 0 {
            return false;
        }
        
        network_height > edge_state.current_height
    }

    async fn estimate_sync_size(&self) -> usize {
        let edge_state = self.edge_state.read().await;
        edge_state.get_stats().storage_estimate_bytes
    }

    async fn get_current_height(&self) -> u64 {
        self.edge_state.read().await.current_height
    }
}
