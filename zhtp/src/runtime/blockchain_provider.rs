use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use lib_blockchain::{Blockchain, Transaction, Block, IdentityTransactionData, Hash};
use anyhow::Result;
use tracing::{info, error};

/// Global blockchain provider for shared access across components
/// This allows the protocols component to access the shared blockchain instance
/// without directly coupling to the orchestrator
#[derive(Debug, Clone)]
pub struct BlockchainProvider {
    blockchain: Arc<RwLock<Option<Arc<RwLock<Blockchain>>>>>,
}

impl BlockchainProvider {
    /// Create a new empty blockchain provider
    pub fn new() -> Self {
        Self {
            blockchain: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the blockchain instance
    pub async fn set_blockchain(&self, blockchain: Arc<RwLock<Blockchain>>) -> Result<()> {
        *self.blockchain.write().await = Some(blockchain);
        info!("Global blockchain instance set");
        Ok(())
    }

    /// Get the blockchain instance
    pub async fn get_blockchain(&self) -> Result<Arc<RwLock<Blockchain>>> {
        self.blockchain.read().await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Blockchain not available"))
    }

    /// Check if blockchain is available
    pub async fn is_available(&self) -> bool {
        self.blockchain.read().await.is_some()
    }
}

/// Global blockchain provider instance
static GLOBAL_BLOCKCHAIN_PROVIDER: OnceLock<BlockchainProvider> = OnceLock::new();

/// Initialize the global blockchain provider
pub fn initialize_global_blockchain_provider() -> &'static BlockchainProvider {
    GLOBAL_BLOCKCHAIN_PROVIDER.get_or_init(|| {
        info!("Initializing global blockchain provider");
        BlockchainProvider::new()
    })
}

/// Get the global blockchain provider
pub fn get_global_blockchain_provider() -> Option<&'static BlockchainProvider> {
    GLOBAL_BLOCKCHAIN_PROVIDER.get()
}

/// Set the global blockchain instance
pub async fn set_global_blockchain(blockchain: Arc<RwLock<Blockchain>>) -> Result<()> {
    let provider = initialize_global_blockchain_provider();
    provider.set_blockchain(blockchain).await
}

/// Get the global blockchain instance
pub async fn get_global_blockchain() -> Result<Arc<RwLock<Blockchain>>> {
    let provider = get_global_blockchain_provider()
        .ok_or_else(|| anyhow::anyhow!("Global blockchain provider not initialized"))?;
    provider.get_blockchain().await
}

/// Check if global blockchain is available
pub async fn is_global_blockchain_available() -> bool {
    if let Some(provider) = get_global_blockchain_provider() {
        provider.is_available().await
    } else {
        false
    }
}

/// Add a transaction to the global blockchain
pub async fn add_transaction(transaction: Transaction) -> Result<String> {
    let blockchain = get_global_blockchain().await?;
    let mut blockchain_lock = blockchain.write().await;
    
    // Add transaction to blockchain and mempool
    let transaction_hash = transaction.hash().to_string();
    if let Err(e) = blockchain_lock.add_pending_transaction(transaction.clone()) {
        error!("Failed to add pending transaction {}: {}", transaction_hash, e);
        error!("Transaction details: inputs={}, outputs={}, fee={}, type={:?}", 
            transaction.inputs.len(), 
            transaction.outputs.len(), 
            transaction.fee,
            transaction.transaction_type);
        return Err(anyhow::anyhow!("Failed to add transaction to mempool: {}", e));
    }
    
    info!("Transaction {} successfully added to mempool", transaction_hash);
    
    Ok(transaction_hash)
}

/// Get a block by height from the global blockchain
pub async fn get_block(height: u64) -> Result<Option<Block>> {
    let blockchain = get_global_blockchain().await?;
    let blockchain_lock = blockchain.read().await;
    Ok(blockchain_lock.get_block(height).cloned())
}

/// Get a transaction by hash from the global blockchain
pub async fn get_transaction(hash: String) -> Result<Option<Transaction>> {
    let blockchain = get_global_blockchain().await?;
    let blockchain_lock = blockchain.read().await;
    // For now, search through pending transactions since get_transaction doesn't exist
    Ok(blockchain_lock.get_pending_transactions().into_iter().find(|tx| tx.hash().to_string() == hash))
}

/// Get mempool transactions from the global blockchain
pub async fn get_mempool() -> Result<Vec<Transaction>> {
    let blockchain = get_global_blockchain().await?;
    let blockchain_lock = blockchain.read().await;
    Ok(blockchain_lock.get_pending_transactions())
}

/// Get current blockchain height
pub async fn get_height() -> Result<u64> {
    let blockchain = get_global_blockchain().await?;
    let blockchain_lock = blockchain.read().await;
    Ok(blockchain_lock.get_height())
}

/// Register an identity in the global blockchain
pub async fn register_identity(identity_data: IdentityTransactionData) -> Result<Hash> {
    let blockchain = get_global_blockchain().await?;
    let mut blockchain_lock = blockchain.write().await;
    let tx_hash = blockchain_lock.register_identity(identity_data)?;
    Ok(tx_hash)
}

/// Get all identities from the global blockchain
pub async fn get_all_identities() -> Result<std::collections::HashMap<String, IdentityTransactionData>> {
    let blockchain = get_global_blockchain().await?;
    let blockchain_lock = blockchain.read().await;
    Ok(blockchain_lock.get_all_identities().clone())
}

/// Get the latest block number from the global blockchain
pub async fn get_latest_block_number() -> Result<u64> {
    let blockchain = get_global_blockchain().await?;
    let bc = blockchain.read().await;
    Ok(bc.get_height())
}

/// Get identity data from the global blockchain
pub async fn get_identity(did: &str) -> Result<Option<IdentityTransactionData>> {
    let blockchain = get_global_blockchain().await?;
    let bc = blockchain.read().await;
    Ok(bc.get_identity(did).cloned())
}

/// Check if identity exists on the global blockchain
pub async fn identity_exists(did: &str) -> Result<bool> {
    let blockchain = get_global_blockchain().await?;
    let bc = blockchain.read().await;
    Ok(bc.identity_exists(did))
}

/// Get transactions for an address from the global blockchain
pub async fn get_transactions_for_address(address: &str) -> Result<Vec<serde_json::Value>> {
    let blockchain = get_global_blockchain().await?;
    let bc = blockchain.read().await;
    Ok(bc.get_transactions_for_address(address))
}
