use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use lib_blockchain::events::{BlockchainEvent, BlockchainEventListener};
use lib_blockchain::{Block, Blockchain, Hash, IdentityTransactionData, Transaction};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Access mode for global blockchain mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockchainAccessMode {
    /// Allows read/write operations on consensus state entrypoints.
    ReadWrite,
    /// Allows read-only operations; all mutation entrypoints fail closed.
    ReadOnly,
}

/// Global blockchain provider for shared access across components
/// This allows the protocols component to access the shared blockchain instance
/// without directly coupling to the orchestrator
#[derive(Debug, Clone)]
pub struct BlockchainProvider {
    blockchain: Arc<RwLock<Option<Arc<RwLock<Blockchain>>>>>,
    access_mode: Arc<RwLock<BlockchainAccessMode>>,
}

impl BlockchainProvider {
    /// Create a new empty blockchain provider
    pub fn new() -> Self {
        Self {
            blockchain: Arc::new(RwLock::new(None)),
            access_mode: Arc::new(RwLock::new(BlockchainAccessMode::ReadOnly)),
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
        self.blockchain
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Blockchain not available"))
    }

    /// Check if blockchain is available
    pub async fn is_available(&self) -> bool {
        self.blockchain.read().await.is_some()
    }

    /// Configure blockchain mutation access mode.
    pub async fn set_access_mode(&self, access_mode: BlockchainAccessMode) {
        *self.access_mode.write().await = access_mode;
        info!("Global blockchain access mode set to {:?}", access_mode);
    }

    async fn ensure_write_access(&self, operation: &str) -> Result<()> {
        match *self.access_mode.read().await {
            BlockchainAccessMode::ReadWrite => Ok(()),
            BlockchainAccessMode::ReadOnly => Err(anyhow::anyhow!(
                "Rejected blockchain mutation '{}': global provider is in read-only mode",
                operation
            )),
        }
    }
}

/// Global blockchain provider instance
static GLOBAL_BLOCKCHAIN_PROVIDER: OnceLock<BlockchainProvider> = OnceLock::new();

/// Global catch-up sync trigger: when a non-consecutive block is received via mesh
/// (or any component detects height lag), fire this to kick the catch-up sync task.
static GLOBAL_CATCHUP_TRIGGER: OnceLock<tokio::sync::mpsc::Sender<u64>> = OnceLock::new();
static BLOCKCHAIN_LISTENER_ATTACHMENTS: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
static PENDING_IDENTITY_PROJECTIONS: OnceLock<Mutex<HashMap<String, PendingIdentityProjection>>> =
    OnceLock::new();
static PENDING_WALLET_PROJECTIONS: OnceLock<Mutex<HashMap<String, PendingWalletProjection>>> =
    OnceLock::new();

#[derive(Debug, Clone)]
pub struct PendingIdentityProjection {
    pub identity_id: String,
    pub display_name: String,
    pub device_id: String,
    pub node_id: String,
    pub kyber_public_key: Option<String>,
    pub primary_wallet_id: String,
    pub ubi_wallet_id: String,
    pub savings_wallet_id: String,
    pub registered_at: u64,
}

#[derive(Debug, Clone)]
pub struct PendingWalletProjection {
    pub identity_id: String,
    pub wallet_id: String,
    pub wallet_record: Option<serde_json::Value>,
    pub wallet_private_record: Option<Vec<u8>>,
}

#[derive(Default)]
struct IdentityProjectionListener;

fn listener_attachments() -> &'static Mutex<HashSet<usize>> {
    BLOCKCHAIN_LISTENER_ATTACHMENTS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn pending_identity_projections() -> &'static Mutex<HashMap<String, PendingIdentityProjection>> {
    PENDING_IDENTITY_PROJECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pending_wallet_projections() -> &'static Mutex<HashMap<String, PendingWalletProjection>> {
    PENDING_WALLET_PROJECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn identity_id_from_did(did: &str) -> Option<String> {
    did.strip_prefix("did:zhtp:").map(str::to_string)
}

fn tx_hash_hex(tx_hash: [u8; 32]) -> String {
    hex::encode(tx_hash)
}

async fn handle_identity_registered(
    tx_hash: [u8; 32],
    identity_data: lib_blockchain::transaction::IdentityTransactionData,
) -> Result<()> {
    let pending = pending_identity_projections()
        .lock()
        .expect("pending identity projection mutex poisoned")
        .remove(&tx_hash_hex(tx_hash));
    let identity_id = pending
        .as_ref()
        .map(|p| p.identity_id.clone())
        .or_else(|| identity_id_from_did(&identity_data.did))
        .ok_or_else(|| anyhow::anyhow!("IdentityRegistered event carried unexpected DID"))?;

    let mut record = serde_json::json!({
        "did": identity_data.did,
        "display_name": pending
            .as_ref()
            .map(|p| p.display_name.clone())
            .unwrap_or_else(|| identity_data.display_name.clone()),
        "public_key": base64::engine::general_purpose::STANDARD.encode(&identity_data.public_key),
        "identity_type": identity_data.identity_type,
        "created_at": identity_data.created_at,
    });

    if let Some(ref pending) = pending {
        if let Some(obj) = record.as_object_mut() {
            obj.insert(
                "device_id".to_string(),
                serde_json::Value::String(pending.device_id.clone()),
            );
            obj.insert(
                "node_id".to_string(),
                serde_json::Value::String(pending.node_id.clone()),
            );
            obj.insert(
                "kyber_public_key".to_string(),
                pending
                    .kyber_public_key
                    .clone()
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            );
            obj.insert(
                "registered_at".to_string(),
                serde_json::Value::Number(pending.registered_at.into()),
            );
            obj.insert(
                "primary_wallet_id".to_string(),
                serde_json::Value::String(pending.primary_wallet_id.clone()),
            );
            obj.insert(
                "ubi_wallet_id".to_string(),
                serde_json::Value::String(pending.ubi_wallet_id.clone()),
            );
            obj.insert(
                "savings_wallet_id".to_string(),
                serde_json::Value::String(pending.savings_wallet_id.clone()),
            );
        }
    }

    let storage = crate::runtime::storage_provider::get_global_storage().await?;
    let mut storage = storage.write().await;
    let record_bytes = serde_json::to_vec(&record)?;
    storage
        .store_identity_record(&identity_id, &record_bytes)
        .await?;
    storage.add_to_identity_index(&identity_id).await?;

    if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
        let mut dht = dht_client.write().await;
        let did_doc = serde_json::json!({
            "@context": "https://www.w3.org/ns/did/v1",
            "id": identity_data.did,
            "created": identity_data.created_at,
        });
        let did_doc_bytes = serde_json::to_vec(&did_doc)?;
        let did_path = format!("/did/{}", identity_id);
        dht.store_content("identity.zhtp", &did_path, did_doc_bytes, 86400)
            .await?;

        if let Some(ref pending) = pending {
            let wallet_registry = serde_json::json!({
                "owner_did": identity_data.did,
                "wallets": {
                    "primary": pending.primary_wallet_id,
                    "ubi": pending.ubi_wallet_id,
                    "savings": pending.savings_wallet_id,
                },
                "created_at": pending.registered_at,
            });
            let wallet_registry_bytes = serde_json::to_vec(&wallet_registry)?;
            let registry_path = format!("/registry/{}", identity_id);
            dht.store_content("wallet.zhtp", &registry_path, wallet_registry_bytes, 86400)
                .await?;
        }
    }

    Ok(())
}

async fn handle_wallet_registered(
    tx_hash: [u8; 32],
    wallet_data: lib_blockchain::transaction::WalletTransactionData,
) -> Result<()> {
    let Some(owner_identity_id) = wallet_data.owner_identity_id else {
        return Ok(());
    };
    let owner_identity_id_hex = hex::encode(owner_identity_id.as_bytes());
    let wallet_id_hex = hex::encode(wallet_data.wallet_id.as_bytes());

    let storage = crate::runtime::storage_provider::get_global_storage().await?;
    let mut storage = storage.write().await;
    storage
        .add_to_wallet_index(
            &owner_identity_id_hex,
            &wallet_id_hex,
        )
        .await?;

    let pending = pending_wallet_projections()
        .lock()
        .expect("pending wallet projection mutex poisoned")
        .remove(&tx_hash_hex(tx_hash));

    if let Some(pending) = pending.as_ref() {
        if let Some(wallet_record) = &pending.wallet_record {
            storage
                .store_wallet_record(
                    &pending.identity_id,
                    &pending.wallet_id,
                    &serde_json::to_vec(wallet_record)?,
                )
                .await?;
        }
        if let Some(wallet_private_record) = &pending.wallet_private_record {
            storage
                .store_wallet_private_record(
                    &pending.identity_id,
                    &pending.wallet_id,
                    wallet_private_record,
                )
                .await?;
        }
    }

    if let Ok(dht_client) = crate::runtime::shared_dht::get_dht_client().await {
        let mut dht = dht_client.write().await;
        if let Some(pending) = pending {
            if let Some(wallet_record) = pending.wallet_record {
                let path = format!(
                    "/identity/{}/wallet/{}/",
                    &pending.identity_id[..16.min(pending.identity_id.len())],
                    &pending.wallet_id[..16.min(pending.wallet_id.len())]
                );
                dht.store_content(
                    "wallet.zhtp",
                    &path,
                    serde_json::to_vec(&wallet_record)?,
                    86400,
                )
                .await?;
            }
            if let Some(wallet_private_record) = pending.wallet_private_record {
                let path = format!("/wallet_private/{}/{}", pending.identity_id, pending.wallet_id);
                dht.store_content("wallet.zhtp", &path, wallet_private_record, 86400)
                    .await?;
            }
        }
    }

    Ok(())
}

#[async_trait]
impl BlockchainEventListener for IdentityProjectionListener {
    async fn on_event(&mut self, event: BlockchainEvent) -> Result<()> {
        match event {
            BlockchainEvent::IdentityRegistered {
                tx_hash,
                identity_data,
                ..
            } => {
                if let Err(e) = handle_identity_registered(tx_hash, identity_data).await {
                    warn!(
                        "Failed to rebuild identity projection from committed event: {}",
                        e
                    );
                }
            }
            BlockchainEvent::WalletRegistered {
                tx_hash,
                wallet_data,
                ..
            } => {
                if let Err(e) = handle_wallet_registered(tx_hash, wallet_data).await {
                    warn!("Failed to rebuild wallet index from committed event: {}", e);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

async fn attach_projection_listener(blockchain: &Arc<RwLock<Blockchain>>) -> Result<()> {
    let key = Arc::as_ptr(blockchain) as usize;
    {
        let mut attached = listener_attachments()
            .lock()
            .expect("listener attachment mutex poisoned");
        if !attached.insert(key) {
            return Ok(());
        }
    }

    let publisher = {
        let blockchain = blockchain.read().await;
        blockchain.event_publisher.clone()
    };
    publisher
        .subscribe(Box::new(IdentityProjectionListener))
        .await?;
    Ok(())
}

/// Register the catch-up sync channel sender.  Called once from consensus setup.
pub fn set_global_catchup_trigger(tx: tokio::sync::mpsc::Sender<u64>) {
    let _ = GLOBAL_CATCHUP_TRIGGER.set(tx);
}

/// Fire the catch-up trigger with the current local height.
/// Non-blocking: silently dropped if the channel is already full (sync in-flight).
pub fn trigger_global_catchup(local_height: u64) {
    if let Some(tx) = GLOBAL_CATCHUP_TRIGGER.get() {
        let _ = tx.try_send(local_height);
    }
}

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
    attach_projection_listener(&blockchain).await?;
    provider.set_blockchain(blockchain).await
}

pub fn register_pending_identity_projection(tx_hash: &str, projection: PendingIdentityProjection) {
    pending_identity_projections()
        .lock()
        .expect("pending identity projection mutex poisoned")
        .insert(tx_hash.to_string(), projection);
}

pub fn register_pending_wallet_projection(tx_hash: &str, projection: PendingWalletProjection) {
    pending_wallet_projections()
        .lock()
        .expect("pending wallet projection mutex poisoned")
        .insert(tx_hash.to_string(), projection);
}

/// Set global blockchain access mode.
pub async fn set_global_blockchain_access_mode(access_mode: BlockchainAccessMode) -> Result<()> {
    let provider = initialize_global_blockchain_provider();
    provider.set_access_mode(access_mode).await;
    Ok(())
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
    let provider = initialize_global_blockchain_provider();
    provider.ensure_write_access("add_transaction").await?;

    let blockchain = get_global_blockchain().await?;
    let mut blockchain_lock = blockchain.write().await;

    // Add transaction to blockchain and mempool
    let transaction_hash = transaction.hash().to_string();
    if let Err(e) = blockchain_lock.add_pending_transaction(transaction.clone()) {
        error!(
            "Failed to add pending transaction {}: {}",
            transaction_hash, e
        );
        error!(
            "Transaction details: inputs={}, outputs={}, fee={}, type={:?}",
            transaction.inputs.len(),
            transaction.outputs.len(),
            transaction.fee,
            transaction.transaction_type
        );
        return Err(anyhow::anyhow!(
            "Failed to add transaction to mempool: {}",
            e
        ));
    }

    info!(
        "Transaction {} successfully added to mempool",
        transaction_hash
    );

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
    Ok(blockchain_lock
        .get_pending_transactions()
        .into_iter()
        .find(|tx| tx.hash().to_string() == hash))
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
    let provider = initialize_global_blockchain_provider();
    provider.ensure_write_access("register_identity").await?;

    let blockchain = get_global_blockchain().await?;
    let mut blockchain_lock = blockchain.write().await;
    let tx_hash = blockchain_lock.register_identity(identity_data)?;
    Ok(tx_hash)
}

/// Get all identities from the global blockchain
pub async fn get_all_identities(
) -> Result<std::collections::HashMap<String, IdentityTransactionData>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn test_guard() -> &'static tokio::sync::Mutex<()> {
        static TEST_GUARD: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        TEST_GUARD.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn install_test_storage() -> Arc<RwLock<lib_storage::PersistentStorageSystem>> {
        let temp = tempfile::tempdir().unwrap();
        let config = crate::runtime::components::identity::create_default_storage_config().unwrap();
        let storage = lib_storage::UnifiedStorageSystem::new_persistent(config, temp.path())
            .await
            .unwrap();
        let storage = Arc::new(RwLock::new(storage));
        crate::runtime::storage_provider::set_global_storage(storage.clone())
            .await
            .unwrap();
        storage
    }

    #[tokio::test]
    async fn default_mode_is_read_only_and_blocks_writes() {
        let provider = BlockchainProvider::new();
        let result = provider.ensure_write_access("unit_test_mutation").await;
        assert!(result.is_err(), "default provider mode must reject writes");
    }

    #[tokio::test]
    async fn read_write_mode_allows_writes() {
        let provider = BlockchainProvider::new();
        provider
            .set_access_mode(BlockchainAccessMode::ReadWrite)
            .await;
        let result = provider.ensure_write_access("unit_test_mutation").await;
        assert!(result.is_ok(), "read-write mode should allow writes");
    }

    #[tokio::test]
    async fn committed_identity_event_populates_cache_from_pending_projection() {
        let _guard = test_guard().lock().await;
        let storage = install_test_storage().await;
        let tx_hash = [0xaa; 32];
        register_pending_identity_projection(
            &tx_hash_hex(tx_hash),
            PendingIdentityProjection {
                identity_id: "11".repeat(32),
                display_name: "Event User".to_string(),
                device_id: "device-a".to_string(),
                node_id: "node-a".to_string(),
                kyber_public_key: Some("kyber".to_string()),
                primary_wallet_id: "22".repeat(32),
                ubi_wallet_id: "33".repeat(32),
                savings_wallet_id: "44".repeat(32),
                registered_at: 1234,
            },
        );

        handle_identity_registered(
            tx_hash,
            lib_blockchain::transaction::IdentityTransactionData {
                did: format!("did:zhtp:{}", "11".repeat(32)),
                display_name: "Canonical User".to_string(),
                public_key: vec![0x55; 32],
                ownership_proof: vec![],
                identity_type: "human".to_string(),
                did_document_hash: lib_blockchain::Hash::zero(),
                created_at: 1234,
                registration_fee: 0,
                dao_fee: 0,
                controlled_nodes: vec![],
                owned_wallets: vec![],
            },
        )
        .await
        .unwrap();

        let mut guard = storage.write().await;
        let record = guard
            .get_identity_record(&"11".repeat(32))
            .await
            .unwrap()
            .expect("identity cache record should exist");
        let value: serde_json::Value = serde_json::from_slice(&record).unwrap();
        assert_eq!(value.get("display_name").and_then(|v| v.as_str()), Some("Event User"));
        assert_eq!(value.get("device_id").and_then(|v| v.as_str()), Some("device-a"));
        assert!(guard
            .list_identity_ids()
            .await
            .unwrap()
            .contains(&"11".repeat(32)));
    }

    #[tokio::test]
    async fn committed_wallet_event_populates_cache_from_pending_projection() {
        let _guard = test_guard().lock().await;
        let storage = install_test_storage().await;
        let tx_hash = [0xbb; 32];
        register_pending_wallet_projection(
            &tx_hash_hex(tx_hash),
            PendingWalletProjection {
                identity_id: "11".repeat(32),
                wallet_id: "22".repeat(32),
                wallet_record: Some(serde_json::json!({
                    "wallet_id": "22".repeat(32),
                    "wallet_name": "Event Wallet"
                })),
                wallet_private_record: Some(vec![1, 2, 3, 4]),
            },
        );

        handle_wallet_registered(
            tx_hash,
            lib_blockchain::transaction::WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from_slice(&[0x22; 32]),
                wallet_type: "Primary".to_string(),
                wallet_name: "Canonical Wallet".to_string(),
                alias: None,
                public_key: vec![0x66; 32],
                owner_identity_id: Some(lib_blockchain::Hash::from_slice(&[0x11; 32])),
                seed_commitment: lib_blockchain::Hash::zero(),
                created_at: 1234,
                registration_fee: 0,
                capabilities: 0,
                initial_balance: 0,
            },
        )
        .await
        .unwrap();

        let mut guard = storage.write().await;
        assert!(guard
            .list_wallet_ids_for_identity(&"11".repeat(32))
            .await
            .unwrap()
            .contains(&"22".repeat(32)));
        assert!(guard
            .get_wallet_record(&"11".repeat(32), &"22".repeat(32))
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            guard.get_wallet_private_record(&"11".repeat(32), &"22".repeat(32))
                .await
                .unwrap(),
            Some(vec![1, 2, 3, 4])
        );
    }

    #[tokio::test]
    async fn committed_wallet_event_without_pending_projection_does_not_materialize_cache_records() {
        let _guard = test_guard().lock().await;
        let storage = install_test_storage().await;

        handle_wallet_registered(
            [0xcc; 32],
            lib_blockchain::transaction::WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from_slice(&[0x22; 32]),
                wallet_type: "Primary".to_string(),
                wallet_name: "Canonical Wallet".to_string(),
                alias: None,
                public_key: vec![0x66; 32],
                owner_identity_id: Some(lib_blockchain::Hash::from_slice(&[0x11; 32])),
                seed_commitment: lib_blockchain::Hash::zero(),
                created_at: 1234,
                registration_fee: 0,
                capabilities: 0,
                initial_balance: 0,
            },
        )
        .await
        .unwrap();

        let mut guard = storage.write().await;
        assert!(guard
            .list_wallet_ids_for_identity(&"11".repeat(32))
            .await
            .unwrap()
            .contains(&"22".repeat(32)));
        assert_eq!(
            guard.get_wallet_record(&"11".repeat(32), &"22".repeat(32))
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            guard.get_wallet_private_record(&"11".repeat(32), &"22".repeat(32))
                .await
                .unwrap(),
            None
        );
    }
}
