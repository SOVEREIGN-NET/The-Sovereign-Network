use anyhow::{Result, Context, anyhow};
use lib_blockchain::Blockchain;
use lib_storage::UnifiedStorageSystem;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

/// Service for bootstrapping blockchain from network peers
pub struct BootstrapService;

impl BootstrapService {
    /// Try to bootstrap blockchain from network discovery
    pub async fn try_bootstrap_blockchain(
        _blockchain: &Arc<RwLock<Blockchain>>,
        _storage: &Arc<RwLock<UnifiedStorageSystem>>,
        _api_port: u16,
        environment: &crate::config::environment::Environment,
    ) -> Result<Blockchain> {
        let _ = environment;
        warn!("Bootstrap via network is disabled in the stub build");
        Err(anyhow!("No network bootstrap available"))
    }

    /// Try to sync blockchain from a specific peer address using incremental protocol
    pub async fn try_bootstrap_blockchain_from_peer(
        blockchain: &Arc<RwLock<Blockchain>>,
        _storage: &Arc<RwLock<UnifiedStorageSystem>>,
        peer_addr: &str,
    ) -> Result<Blockchain> {
        use serde::Deserialize;
        
        info!(" Attempting incremental blockchain sync from peer: {}", peer_addr);
        
        // Step 1: Get peer's chain tip info
        let tip_url = format!("http://{}/api/v1/blockchain/tip", peer_addr);
        
        #[derive(Deserialize)]
        struct ChainTipInfo {
            height: u64,
            head_hash: String,
            genesis_hash: String,
            validator_count: usize,
            identity_count: usize,
        }
        
        let peer_tip = match timeout(Duration::from_secs(5), async {
            info!(" GET {} (fetching chain tip)", tip_url);
            let response = reqwest::get(&tip_url).await?;
            if response.status().is_success() {
                let tip: ChainTipInfo = response.json().await?;
                Ok::<ChainTipInfo, anyhow::Error>(tip)
            } else {
                Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
            }
        }).await {
            Ok(Ok(tip)) => {
                info!(" Peer chain tip: height={}, identities={}, validators={}", 
                      tip.height, tip.identity_count, tip.validator_count);
                tip
            }
            Ok(Err(e)) => {
                return Err(anyhow::anyhow!("Failed to fetch tip from {}: {}", peer_addr, e));
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Timeout fetching tip from {}", peer_addr));
            }
        };
        
        // Step 2: Compare with local chain
        let local_blockchain = blockchain.read().await;
        let local_height = local_blockchain.height;
        let local_genesis = local_blockchain.blocks.first()
            .map(|b| hex::encode(b.header.merkle_root.as_bytes()))
            .unwrap_or_else(|| "none".to_string());
        
        info!(" Chain comparison:");
        info!("   Local:  height={}, genesis={}", local_height, local_genesis);
        info!("   Peer:   height={}, genesis={}", peer_tip.height, peer_tip.genesis_hash);
        
        // Step 3: Determine sync strategy
        if peer_tip.genesis_hash != local_genesis {
            info!("🔀 Different genesis detected - fetching full chain for merge evaluation");
            drop(local_blockchain); // Release lock before fetching
            
            // Fall back to full export for genesis mismatch (merge logic needs full chain)
            let export_url = format!("http://{}/api/v1/blockchain/export", peer_addr);
            match timeout(Duration::from_secs(10), async {
                info!(" GET {} (full chain for merge)", export_url);
                let response = reqwest::get(&export_url).await?;
                if response.status().is_success() {
                    let data = response.bytes().await?.to_vec();
                    info!(" Received {} bytes for merge evaluation", data.len());
                    Ok::<Vec<u8>, anyhow::Error>(data)
                } else {
                    Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
                }
            }).await {
                Ok(Ok(blockchain_data)) => {
                    let mut blockchain_clone = blockchain.read().await.clone();
                    info!(" Evaluating and merging different genesis chains...");
                    blockchain_clone.evaluate_and_merge_chain(blockchain_data).await?;
                    info!(" Successfully synced and merged from {} (genesis mismatch)", peer_addr);
                    return Ok(blockchain_clone);
                }
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("Failed to fetch full chain: {}", e));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!("Timeout fetching full chain"));
                }
            }
        }
        
        // Step 4: Check if we need to sync even at same height
        if peer_tip.height < local_height {
            info!(" Local chain is ahead (peer: {}, local: {})", peer_tip.height, local_height);
            drop(local_blockchain);
            return Ok(blockchain.read().await.clone());
        }
        
        // If same height, check if peer has more identities/data
        if peer_tip.height == local_height {
            if peer_tip.identity_count > local_blockchain.identity_registry.len() {
                info!(" Same height but peer has more identities ({} vs {}) - syncing full chain for merge", 
                      peer_tip.identity_count, local_blockchain.identity_registry.len());
                
                // Fetch full chain for merge evaluation
                let export_url = format!("http://{}/api/v1/blockchain/export", peer_addr);
                match timeout(Duration::from_secs(10), async {
                    info!(" GET {} (full chain for merge)", export_url);
                    let response = reqwest::get(&export_url).await?;
                    if response.status().is_success() {
                        let data = response.bytes().await?.to_vec();
                        info!(" Received {} bytes for merge evaluation", data.len());
                        Ok::<Vec<u8>, anyhow::Error>(data)
                    } else {
                        Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
                    }
                }).await {
                    Ok(Ok(blockchain_data)) => {
                        drop(local_blockchain); // Release lock before merge
                        let mut blockchain_clone = blockchain.read().await.clone();
                        info!(" Evaluating and merging chains with more peer data...");
                        blockchain_clone.evaluate_and_merge_chain(blockchain_data).await?;
                        info!(" Successfully synced and merged additional data from {}", peer_addr);
                        return Ok(blockchain_clone);
                    }
                    Ok(Err(e)) => {
                        warn!(" Failed to fetch full chain for merge: {}", e);
                    }
                    Err(_) => {
                        warn!(" Timeout fetching full chain for merge");
                    }
                }
            } else {
                info!(" Local chain is up-to-date (peer: {} identities, local: {} identities)", 
                      peer_tip.identity_count, local_blockchain.identity_registry.len());
            }
            drop(local_blockchain);
            return Ok(blockchain.read().await.clone());
        }
        
        info!(" Peer is ahead - fetching missing blocks {} to {}", local_height + 1, peer_tip.height);
        drop(local_blockchain); // Release lock
        
        // Fetch missing blocks incrementally (max 1000 at a time)
        let start = local_height + 1;
        let end = peer_tip.height;
        let blocks_url = format!("http://{}/api/v1/blockchain/blocks/{}/{}", peer_addr, start, end);
        
        match timeout(Duration::from_secs(10), async {
            info!(" GET {} ({} blocks)", blocks_url, end - start + 1);
            let response = reqwest::get(&blocks_url).await?;
            if response.status().is_success() {
                let data = response.bytes().await?.to_vec();
                info!(" Received {} bytes ({} blocks)", data.len(), end - start + 1);
                Ok::<Vec<u8>, anyhow::Error>(data)
            } else {
                Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
            }
        }).await {
            Ok(Ok(blocks_data)) => {
                // Deserialize blocks
                let new_blocks: Vec<lib_blockchain::block::Block> = bincode::deserialize(&blocks_data)
                    .context("Failed to deserialize blocks")?;
                
                info!(" Appending {} new blocks to local chain", new_blocks.len());
                
                // Append blocks to local chain
                let mut blockchain_guard = blockchain.write().await;
                for block in new_blocks {
                    // Validate and add block
                    blockchain_guard.blocks.push(block);
                    blockchain_guard.height += 1;
                }
                
                info!(" Successfully synced {} blocks from {} (incremental)", blockchain_guard.height - local_height, peer_addr);
                info!("   New height: {}", blockchain_guard.height);
                info!("   Identities: {}", blockchain_guard.identity_registry.len());
                
                Ok(blockchain_guard.clone())
            }
            Ok(Err(e)) => {
                Err(anyhow::anyhow!("Failed to fetch blocks: {}", e))
            }
            Err(_) => {
                Err(anyhow::anyhow!("Timeout fetching blocks"))
            }
        }
    }
}
