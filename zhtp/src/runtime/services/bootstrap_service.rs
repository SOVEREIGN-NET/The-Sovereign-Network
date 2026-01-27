use anyhow::{Result, Context, anyhow};
use lib_blockchain::Blockchain;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use lib_network::client::ZhtpClient;

/// Service for bootstrapping blockchain from network peers via QUIC
pub struct BootstrapService;

impl BootstrapService {
    /// Try to sync blockchain from a specific peer using QUIC (ZhtpClient).
    ///
    /// The caller must provide an already-connected ZhtpClient.
    /// Uses incremental sync: fetches chain tip, compares, then fetches
    /// only the missing blocks (or full export for genesis mismatch).
    pub async fn try_bootstrap_blockchain_from_peer(
        blockchain: &Arc<RwLock<Blockchain>>,
        client: &ZhtpClient,
        peer_label: &str,
    ) -> Result<Blockchain> {
        use serde::Deserialize;

        info!("Attempting incremental blockchain sync from peer: {}", peer_label);

        // Step 1: Get peer's chain tip info
        #[derive(Deserialize)]
        struct ChainTipInfo {
            height: u64,
            #[allow(dead_code)]
            head_hash: String,
            genesis_hash: String,
            validator_count: usize,
            identity_count: usize,
        }

        let tip_response = timeout(Duration::from_secs(10), async {
            info!("GET /api/v1/blockchain/tip (fetching chain tip)");
            client.get("/api/v1/blockchain/tip").await
        }).await
            .map_err(|_| anyhow!("Timeout fetching chain tip from {}", peer_label))?
            .context("Failed to fetch chain tip")?;

        if !tip_response.is_success() {
            return Err(anyhow!("Peer {} returned error for chain tip: {}", peer_label, tip_response.status_message));
        }

        let peer_tip: ChainTipInfo = serde_json::from_slice(&tip_response.body)
            .context("Failed to parse chain tip JSON")?;

        info!("Peer chain tip: height={}, identities={}, validators={}",
              peer_tip.height, peer_tip.identity_count, peer_tip.validator_count);

        // Step 2: Compare with local chain
        let local_blockchain = blockchain.read().await;
        let local_height = local_blockchain.height;
        let local_genesis = local_blockchain.blocks.first()
            .map(|b| hex::encode(b.header.merkle_root.as_bytes()))
            .unwrap_or_else(|| "none".to_string());

        info!("Chain comparison:");
        info!("  Local:  height={}, genesis={}", local_height, local_genesis);
        info!("  Peer:   height={}, genesis={}", peer_tip.height, peer_tip.genesis_hash);

        // Step 3: Determine sync strategy
        if peer_tip.genesis_hash != local_genesis {
            info!("Different genesis detected - fetching full chain for merge evaluation");
            drop(local_blockchain); // Release lock before fetching

            let export_response = timeout(Duration::from_secs(30), async {
                info!("GET /api/v1/blockchain/export (full chain for merge)");
                client.get("/api/v1/blockchain/export").await
            }).await
                .map_err(|_| anyhow!("Timeout fetching full chain from {}", peer_label))?
                .context("Failed to fetch blockchain export")?;

            if !export_response.is_success() {
                return Err(anyhow!("Peer {} returned error for export: {}", peer_label, export_response.status_message));
            }

            let blockchain_data = export_response.body;
            info!("Received {} bytes for merge evaluation", blockchain_data.len());

            let mut blockchain_clone = blockchain.read().await.clone();
            info!("Evaluating and merging different genesis chains...");
            blockchain_clone.evaluate_and_merge_chain(blockchain_data).await?;
            info!("Successfully synced and merged from {} (genesis mismatch)", peer_label);
            return Ok(blockchain_clone);
        }

        // Step 4: Check if we need to sync even at same height
        if peer_tip.height < local_height {
            info!("Local chain is ahead (peer: {}, local: {})", peer_tip.height, local_height);
            drop(local_blockchain);
            return Ok(blockchain.read().await.clone());
        }

        // If same height, check if peer has more identities/data
        if peer_tip.height == local_height {
            let local_identity_count = local_blockchain.identity_registry.len();
            drop(local_blockchain); // Release lock before any network I/O

            if peer_tip.identity_count > local_identity_count {
                info!("Same height but peer has more identities ({} vs {}) - syncing full chain for merge",
                      peer_tip.identity_count, local_identity_count);

                let export_response = timeout(Duration::from_secs(30), async {
                    info!("GET /api/v1/blockchain/export (full chain for merge)");
                    client.get("/api/v1/blockchain/export").await
                }).await
                    .map_err(|_| anyhow!("Timeout fetching full chain for merge from {}", peer_label))?
                    .context("Failed to fetch blockchain export for merge")?;

                if export_response.is_success() {
                    let blockchain_data = export_response.body;
                    info!("Received {} bytes for merge evaluation", blockchain_data.len());
                    let mut blockchain_clone = blockchain.read().await.clone();
                    info!("Evaluating and merging chains with more peer data...");
                    blockchain_clone.evaluate_and_merge_chain(blockchain_data).await?;
                    info!("Successfully synced and merged additional data from {}", peer_label);
                    return Ok(blockchain_clone);
                } else {
                    warn!("Failed to fetch full chain for merge: {}", export_response.status_message);
                }
            } else {
                info!("Local chain is up-to-date (peer: {} identities, local: {} identities)",
                      peer_tip.identity_count, local_identity_count);
            }
            return Ok(blockchain.read().await.clone());
        }

        info!("Peer is ahead - fetching missing blocks {} to {}", local_height + 1, peer_tip.height);
        drop(local_blockchain); // Release lock

        // Fetch missing blocks incrementally
        let start = local_height + 1;
        let end = peer_tip.height;
        let blocks_path = format!("/api/v1/blockchain/blocks/{}/{}", start, end);

        let blocks_response = timeout(Duration::from_secs(30), async {
            info!("GET {} ({} blocks)", blocks_path, end - start + 1);
            client.get(&blocks_path).await
        }).await
            .map_err(|_| anyhow!("Timeout fetching blocks from {}", peer_label))?
            .context("Failed to fetch block range")?;

        if !blocks_response.is_success() {
            return Err(anyhow!("Peer {} returned error for blocks: {}", peer_label, blocks_response.status_message));
        }

        let blocks_data = blocks_response.body;
        info!("Received {} bytes ({} blocks requested)", blocks_data.len(), end - start + 1);

        // Deserialize blocks
        let new_blocks: Vec<lib_blockchain::block::Block> = bincode::deserialize(&blocks_data)
            .context("Failed to deserialize blocks")?;

        info!("Appending {} new blocks to local chain", new_blocks.len());

        // Append blocks to local chain
        let mut blockchain_guard = blockchain.write().await;
        for block in new_blocks {
            blockchain_guard.blocks.push(block);
            blockchain_guard.height += 1;
        }

        info!("Successfully synced {} blocks from {} (incremental)", blockchain_guard.height - local_height, peer_label);
        info!("  New height: {}", blockchain_guard.height);
        info!("  Identities: {}", blockchain_guard.identity_registry.len());

        Ok(blockchain_guard.clone())
    }
}
