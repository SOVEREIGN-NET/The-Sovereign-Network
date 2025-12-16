//! Mining Service
//! 
//! Manages blockchain mining with consensus coordination.
//! Features:
//! - Coordinated mining with validator selection
//! - Bootstrap mode for genesis networks
//! - Proof-of-Work mining
//! - Block validation and addition

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tracing::{info, warn, debug};
use crate::runtime::dht_indexing::index_block_in_dht;

use lib_blockchain::Blockchain;
use lib_consensus::ValidatorManager;
use lib_identity::IdentityId;

/// Mining service that coordinates block production with consensus
pub struct MiningService {
    blockchain: Arc<RwLock<Option<Blockchain>>>,
    validator_manager_arc: Arc<RwLock<Option<Arc<RwLock<ValidatorManager>>>>>,
    node_identity_arc: Arc<RwLock<Option<IdentityId>>>,
    mining_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl MiningService {
    /// Create a new mining service
    pub fn new(
        blockchain: Arc<RwLock<Option<Blockchain>>>,
        validator_manager_arc: Arc<RwLock<Option<Arc<RwLock<ValidatorManager>>>>>,
        node_identity_arc: Arc<RwLock<Option<IdentityId>>>,
    ) -> Self {
        Self {
            blockchain,
            validator_manager_arc,
            node_identity_arc,
            mining_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Start the mining loop
    pub async fn start(&self) -> Result<()> {
        if self.mining_handle.read().await.is_some() {
            warn!("Mining service already running");
            return Ok(());
        }

        let blockchain_clone = self.blockchain.clone();
        let validator_manager_clone = self.validator_manager_arc.clone();
        let node_identity_clone = self.node_identity_arc.clone();

        let mining_handle = tokio::spawn(async move {
            Self::mining_loop(blockchain_clone, validator_manager_clone, node_identity_clone).await;
            warn!(" Mining loop exited unexpectedly!");
        });

        *self.mining_handle.write().await = Some(mining_handle);
        info!(" Mining service started");
        Ok(())
    }

    /// Stop the mining loop
    pub async fn stop(&self) -> Result<()> {
        if let Some(handle) = self.mining_handle.write().await.take() {
            handle.abort();
            info!("Mining service stopped");
        }
        Ok(())
    }

    /// Mine a block using actual blockchain methods
    pub async fn mine_block(blockchain: &mut Blockchain) -> Result<()> {
        if blockchain.pending_transactions.is_empty() {
            return Err(anyhow::anyhow!("No pending transactions to mine"));
        }

        info!("Mining block with {} transactions", blockchain.pending_transactions.len());

        // Select transactions for the block (up to 10 for efficiency)
        let transactions_for_block = blockchain.pending_transactions
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>();

        if transactions_for_block.is_empty() {
            return Err(anyhow::anyhow!("No valid transactions for block"));
        }

        // Check if this block contains system transactions (empty inputs = UBI/rewards)
        let has_system_transactions = transactions_for_block
            .iter()
            .any(|tx| tx.inputs.is_empty());

        // Get the previous block hash
        let previous_hash = blockchain.latest_block()
            .map(|b| b.hash())
            .unwrap_or_default();

        // Use blockchain's current difficulty (set at initialization based on environment)
        let block_difficulty = blockchain.difficulty.clone();
        
        if has_system_transactions {
            info!("Mining system transaction block with difficulty: {:#x}", block_difficulty.bits());
        } else {
            info!("Mining normal transaction block with difficulty: {:#x}", block_difficulty.bits());
        }

        // Create the block using lib-blockchain methods
        let block = lib_blockchain::block::creation::create_block(
            transactions_for_block,
            previous_hash,
            blockchain.height + 1,
            block_difficulty,
        )?;

        // Mine the block using environment-aware config
        let mining_config = lib_blockchain::types::get_mining_config_from_env();
        info!("⛏️ Mining block with {} profile (difficulty: {:#x}, max_iter: {})...",
              if mining_config.allow_instant_mining { "Bootstrap" } else { "Standard" },
              block_difficulty.bits(),
              mining_config.max_iterations);
        let new_block = lib_blockchain::block::creation::mine_block_with_config(block, &mining_config)?;
        info!("✓ Block mined with nonce: {}", new_block.header.nonce);

        // Add the block to the blockchain WITH proof generation
        match blockchain.add_block_with_proof(new_block.clone()).await {
            Ok(()) => {
                info!("BLOCK MINED SUCCESSFULLY!");
                info!("Block Hash: {:?}", new_block.hash());
                info!("Block Height: {}", blockchain.height);
                info!("Transactions in Block: {}", new_block.transactions.len());
                info!("Total UTXOs: {}", blockchain.utxo_set.len());
                info!("Identity Registry: {} entries", blockchain.identity_registry.len());
                
                // Log economic transactions stored
                if !blockchain.economics_transactions.is_empty() {
                    info!("Economics Transactions: {}", blockchain.economics_transactions.len());
                }
                if let Err(e) = index_block_in_dht(&new_block).await {
                    warn!("DHT indexing failed (mining_service): {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to add block to blockchain: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Mining loop with consensus coordination
    async fn mining_loop(
        blockchain: Arc<RwLock<Option<Blockchain>>>,
        validator_manager_arc: Arc<RwLock<Option<Arc<RwLock<ValidatorManager>>>>>,
        node_identity_arc: Arc<RwLock<Option<IdentityId>>>,
    ) {
        // Give consensus component time to wire validator manager
        info!(" Mining loop started - waiting 2 seconds for consensus to wire...");
        tokio::time::sleep(Duration::from_secs(2)).await;
        info!(" Starting mining checks every 30 seconds");
        
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut block_counter = 1u64;
        let mut consensus_round = 0u32;
        
        loop {
            debug!("⏰ Mining loop tick #{}", block_counter);
            interval.tick().await;
            
            // Use global blockchain provider
            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(shared_blockchain) => {
                    let blockchain_guard = shared_blockchain.read().await;
                    let pending_count = blockchain_guard.pending_transactions.len();
                    let current_height = blockchain_guard.height;
                    
                    info!("Mining check #{} - Height: {}, Pending: {}, UTXOs: {}, Identities: {}", 
                        block_counter,
                        current_height, 
                        pending_count,
                        blockchain_guard.utxo_set.len(),
                        blockchain_guard.identity_registry.len()
                    );
                    
                    // Check if we have pending transactions
                    if pending_count > 0 {
                        let validator_manager_opt = validator_manager_arc.read().await.clone();
                        let node_identity_opt = node_identity_arc.read().await.clone();
                        
                        // Check if consensus coordination is enabled
                        let should_mine = if let (Some(vm), Some(node_id)) = (validator_manager_opt, node_identity_opt) {
                            let vm_guard = vm.read().await;
                            let active_validators = vm_guard.get_active_validators();
                            
                            if active_validators.is_empty() {
                                // Bootstrap mode - any node can mine
                                warn!("⛏️ BOOTSTRAP MODE: No validators registered, mining without coordination");
                                true
                            } else {
                                // Select proposer using consensus
                                let next_height = current_height + 1;
                                if let Some(proposer) = vm_guard.select_proposer(next_height, consensus_round) {
                                    let node_id_hex = hex::encode(node_id.as_bytes());
                                    let mut is_proposer = false;
                                    
                                    // Find which user controls this node
                                    for (did_string, identity_data) in blockchain_guard.identity_registry.iter() {
                                        if identity_data.controlled_nodes.contains(&node_id_hex) {
                                            if let Some(identity_hex) = did_string.strip_prefix("did:zhtp:") {
                                                if let Ok(identity_bytes) = hex::decode(identity_hex) {
                                                    let user_identity_hash = lib_crypto::Hash::from_bytes(&identity_bytes[..32]);
                                                    
                                                    if user_identity_hash == proposer.identity {
                                                        is_proposer = true;
                                                        info!(" CONSENSUS: This node selected as block proposer");
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    
                                    is_proposer
                                } else {
                                    warn!(" CONSENSUS: No proposer selected, falling back to permissionless mining");
                                    true
                                }
                            }
                        } else {
                            warn!("⛏️ Mining without consensus coordination");
                            true
                        };
                        
                        if should_mine {
                            drop(blockchain_guard);
                            info!("Mining block #{} with {} pending transactions...", block_counter, pending_count);
                            
                            let mut blockchain_guard = shared_blockchain.write().await;
                            match Self::mine_block(&mut *blockchain_guard).await {
                                Ok(()) => {
                                    info!("Block #{} mined successfully!", block_counter);
                                    block_counter += 1;
                                    consensus_round = 0;
                                }
                                Err(e) => {
                                    warn!("Failed to mine block #{}: {}", block_counter, e);
                                    consensus_round += 1;
                                }
                            }
                        } else {
                            info!(" SKIPPING MINING: Not selected as proposer");
                            consensus_round = (consensus_round + 1) % 10;
                        }
                    } else {
                        debug!(" No pending transactions");
                        consensus_round = 0;
                    }
                }
                Err(e) => {
                    warn!("No blockchain available for mining: {}", e);
                }
            }
        }
    }
}
