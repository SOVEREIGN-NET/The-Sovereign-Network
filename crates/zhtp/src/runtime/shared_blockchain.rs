//! Shared blockchain service for cross-component blockchain access
//!
//! Provides a centralized blockchain service that can be accessed by all components
//! without creating separate blockchain instances.

use std::sync::Arc;
use anyhow::Result;
use tokio::sync::{RwLock, mpsc::{self, UnboundedSender}};
use tracing::{info, error};
use lib_blockchain::{Blockchain, Transaction, Block, BlockHeader, Hash, Difficulty};

/// Shared blockchain service that manages a single blockchain instance
/// across all ZHTP components
#[derive(Debug, Clone)]
pub struct SharedBlockchainService {
    blockchain: Arc<RwLock<Blockchain>>,
    operation_tx: UnboundedSender<BlockchainOperation>,
}/// Blockchain operation request
#[derive(Debug)]
pub enum BlockchainOperation {
    AddTransaction {
        transaction: Transaction,
        response_tx: mpsc::UnboundedSender<Result<String>>,
    },
    GetBlock {
        height: u64,
        response_tx: mpsc::UnboundedSender<Result<Option<Block>>>,
    },
    GetTransaction {
        hash: String,
        response_tx: mpsc::UnboundedSender<Result<Option<Transaction>>>,
    },
    GetMempool {
        response_tx: mpsc::UnboundedSender<Result<Vec<Transaction>>>,
    },
    GetHeight {
        response_tx: mpsc::UnboundedSender<Result<u64>>,
    },
    MineBlock {
        response_tx: mpsc::UnboundedSender<Result<Block>>,
    },
}

impl SharedBlockchainService {
    /// Create a new shared blockchain service
    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Self {
        let (operation_tx, mut operation_rx) = mpsc::unbounded_channel();
        
        // Spawn background task to handle operations
        let blockchain_clone = blockchain.clone();
        tokio::spawn(async move {
            while let Some(operation) = operation_rx.recv().await {
                if let Err(e) = Self::handle_operation(&blockchain_clone, operation).await {
                    error!("Error handling blockchain operation: {}", e);
                }
            }
        });
        
        Self {
            blockchain,
            operation_tx,
        }
    }
    
    /// Handle a blockchain operation
    async fn handle_operation(
        blockchain_arc: &Arc<RwLock<Blockchain>>,
        operation: BlockchainOperation,
    ) -> Result<()> {
        match operation {
            BlockchainOperation::AddTransaction { transaction, response_tx } => {
                let result = {
                    let mut blockchain = blockchain_arc.write().await;
                    match blockchain.add_pending_transaction(transaction.clone()) {
                        Ok(()) => {
                            let tx_hash = format!("{:?}", transaction.hash());
                            info!("Transaction added to shared blockchain: {}", tx_hash);
                            Ok(tx_hash)
                        }
                        Err(e) => {
                            error!("Failed to add transaction to shared blockchain: {}", e);
                            Err(anyhow::anyhow!("Failed to add transaction: {}", e))
                        }
                    }
                };
                let _ = response_tx.send(result);
            }
            
            BlockchainOperation::GetBlock { height, response_tx } => {
                let result = {
                    let blockchain = blockchain_arc.read().await;
                    if height < blockchain.blocks.len() as u64 {
                        Ok(Some(blockchain.blocks[height as usize].clone()))
                    } else {
                        Ok(None)
                    }
                };
                let _ = response_tx.send(result);
            }
            
            BlockchainOperation::GetTransaction { hash, response_tx } => {
                let result = {
                    let blockchain = blockchain_arc.read().await;
                    // Search for transaction in all blocks
                    let mut found_tx = None;
                    for block in &blockchain.blocks {
                        for tx in &block.transactions {
                            if format!("{:?}", tx.hash()) == hash {
                                found_tx = Some(tx.clone());
                                break;
                            }
                        }
                        if found_tx.is_some() { break; }
                    }
                    
                    // Also check pending transactions if not found in blocks
                    if found_tx.is_none() {
                        for tx in &blockchain.pending_transactions {
                            if format!("{:?}", tx.hash()) == hash {
                                found_tx = Some(tx.clone());
                                break;
                            }
                        }
                    }
                    
                    found_tx
                };
                
                // Send result using the found transaction
                let _ = response_tx.send(Ok(result));
            }
            
            BlockchainOperation::GetMempool { response_tx } => {
                let result = {
                    let blockchain = blockchain_arc.read().await;
                    Ok(blockchain.pending_transactions.clone())
                };
                let _ = response_tx.send(result);
            }
            
            BlockchainOperation::GetHeight { response_tx } => {
                let result = {
                    let blockchain = blockchain_arc.read().await;
                    Ok(blockchain.height)
                };
                let _ = response_tx.send(result);
            }
            
            BlockchainOperation::MineBlock { response_tx } => {
                let result = {
                    let mut blockchain = blockchain_arc.write().await;
                    // Create a simple block with pending transactions
                    if !blockchain.pending_transactions.is_empty() {
                        info!("Mining block with {} transactions", blockchain.pending_transactions.len());
                        
                        // For this implementation, we'll just create a simple block
                        // mining would involve proof of work
                        let transactions = blockchain.pending_transactions.clone();
                        blockchain.pending_transactions.clear();
                        
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        
                        // Create block header
                        let header = BlockHeader::new(
                            1, // version
                            blockchain.blocks.last().map(|b| b.hash()).unwrap_or_default(), // previous hash
                            Hash::default(), // merkle root (simplified)
                            timestamp,
                            Difficulty::default(), // difficulty (simplified)
                            blockchain.height + 1, // height
                            transactions.len() as u32, // transaction count
                            1024, // block size (simplified)
                            Difficulty::default(), // cumulative difficulty (simplified)
                        );
                        
                        // Create a new block
                        let new_block = Block::new(header, transactions);
                        
                        match blockchain.add_block_with_proof(new_block.clone()).await {
                            Ok(()) => {
                                info!("Block mined successfully at height {} with recursive proof", blockchain.height);
                                Ok(new_block)
                            }
                            Err(e) => {
                                error!("Failed to add mined block: {}", e);
                                Err(anyhow::anyhow!("Failed to mine block: {}", e))
                            }
                        }
                    } else {
                        Err(anyhow::anyhow!("No transactions to mine"))
                    }
                };
                let _ = response_tx.send(result);
            }
        }
        
        Ok(())
    }
    
    /// Add a transaction to the blockchain
    pub async fn add_transaction(&self, transaction: Transaction) -> Result<String> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();
        
        let operation = BlockchainOperation::AddTransaction {
            transaction,
            response_tx,
        };
        
        self.operation_tx.send(operation)
            .map_err(|_| anyhow::anyhow!("Failed to send blockchain operation"))?;
        
        response_rx.recv().await
            .ok_or_else(|| anyhow::anyhow!("No response received"))?
    }
    
    /// Get a block by height
    pub async fn get_block(&self, height: u64) -> Result<Option<Block>> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();
        
        let operation = BlockchainOperation::GetBlock {
            height,
            response_tx,
        };
        
        self.operation_tx.send(operation)
            .map_err(|_| anyhow::anyhow!("Failed to send blockchain operation"))?;
        
        response_rx.recv().await
            .ok_or_else(|| anyhow::anyhow!("No response received"))?
    }
    
    /// Get a transaction by hash
    pub async fn get_transaction(&self, hash: String) -> Result<Option<Transaction>> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();
        
        let operation = BlockchainOperation::GetTransaction {
            hash,
            response_tx,
        };
        
        self.operation_tx.send(operation)
            .map_err(|_| anyhow::anyhow!("Failed to send blockchain operation"))?;
        
        response_rx.recv().await
            .ok_or_else(|| anyhow::anyhow!("No response received"))?
    }
    
    /// Get the mempool (pending transactions)
    pub async fn get_mempool(&self) -> Result<Vec<Transaction>> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();
        
        let operation = BlockchainOperation::GetMempool {
            response_tx,
        };
        
        self.operation_tx.send(operation)
            .map_err(|_| anyhow::anyhow!("Failed to send blockchain operation"))?;
        
        response_rx.recv().await
            .ok_or_else(|| anyhow::anyhow!("No response received"))?
    }
    
    /// Get the current blockchain height
    pub async fn get_height(&self) -> Result<u64> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();
        
        let operation = BlockchainOperation::GetHeight {
            response_tx,
        };
        
        self.operation_tx.send(operation)
            .map_err(|_| anyhow::anyhow!("Failed to send blockchain operation"))?;
        
        response_rx.recv().await
            .ok_or_else(|| anyhow::anyhow!("No response received"))?
    }
    
    /// Mine a new block
    pub async fn mine_block(&self) -> Result<Block> {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();
        
        let operation = BlockchainOperation::MineBlock {
            response_tx,
        };
        
        self.operation_tx.send(operation)
            .map_err(|_| anyhow::anyhow!("Failed to send blockchain operation"))?;
        
        response_rx.recv().await
            .ok_or_else(|| anyhow::anyhow!("No response received"))?
    }
    
    /// Get direct access to the blockchain Arc (for advanced operations)
    pub fn get_blockchain_arc(&self) -> Arc<RwLock<Blockchain>> {
        self.blockchain.clone()
    }
}

/// Get the shared blockchain service (global accessor)
/// This provides access to the blockchain from anywhere in the application
pub fn get_shared_blockchain() -> Result<SharedBlockchainService> {
    // For simplicity, create a new blockchain instance if not available
    // In production, this would be managed by the global service container
    let blockchain = Blockchain::new()?;
    let blockchain_arc = Arc::new(RwLock::new(blockchain));
    Ok(SharedBlockchainService::new(blockchain_arc))
}
