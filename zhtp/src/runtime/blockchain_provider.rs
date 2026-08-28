use anyhow::Result;
use base64::Engine;
use lib_blockchain::events::BlockchainEvent;
use lib_blockchain::{Block, Blockchain, Hash, IdentityTransactionData, Transaction};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, RwLock as StdRwLock};
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
    /// Sync-readable council DID set refreshed from chain state. Role checks read
    /// this first so `extract_principal_from_request` never needs a nested tokio
    /// `blockchain.read()` while a handler already holds the same guard (tokio
    /// RwLock is not re-entrant — a second read on the same task deadlocks).
    council_member_cache: Arc<StdRwLock<HashSet<String>>>,
}

impl BlockchainProvider {
    /// Create a new empty blockchain provider
    pub fn new() -> Self {
        Self {
            blockchain: Arc::new(RwLock::new(None)),
            access_mode: Arc::new(RwLock::new(BlockchainAccessMode::ReadOnly)),
            council_member_cache: Arc::new(StdRwLock::new(HashSet::new())),
        }
    }

    /// Set the blockchain instance
    pub async fn set_blockchain(&self, blockchain: Arc<RwLock<Blockchain>>) -> Result<()> {
        *self.blockchain.write().await = Some(blockchain);
        self.refresh_council_member_cache().await;
        info!("Global blockchain instance set");
        Ok(())
    }

    /// Drop the blockchain instance (tests that need a deterministic "chain down" path).
    #[cfg(test)]
    pub async fn clear_blockchain_for_tests(&self) {
        *self.blockchain.write().await = None;
    }

    /// Refresh the sync council cache from live `blockchain.council_members`.
    ///
    /// Council membership is in-memory only (not sled-persisted). A
    /// `load_from_store` swap can temporarily leave `council_members` empty while
    /// a config-seeded cache is still valid — do not clobber a non-empty cache
    /// with an empty chain read (the 15s background refresh loop).
    pub async fn refresh_council_member_cache(&self) {
        let outer = self.blockchain.read().await;
        let Some(arc) = outer.as_ref() else {
            return;
        };
        let bc = arc.read().await;
        let members: HashSet<String> = bc
            .get_council_members()
            .iter()
            .map(|m| m.identity_id.clone())
            .collect();
        if members.is_empty() {
            if let Ok(cache) = self.council_member_cache.read() {
                if !cache.is_empty() {
                    return;
                }
            }
        }
        self.replace_council_member_cache(members);
    }

    /// Seed the sync council cache from config (no blockchain lock). Call after
    /// `ensure_council_bootstrap` — `set_global_blockchain` runs *before* bootstrap
    /// and would otherwise leave an empty cache until the 15s refresh loop.
    pub fn seed_council_member_cache(&self, identity_ids: impl IntoIterator<Item = String>) {
        self.store_council_member_cache(identity_ids);
    }

    fn store_council_member_cache(&self, identity_ids: impl IntoIterator<Item = String>) {
        self.replace_council_member_cache(identity_ids.into_iter().collect());
    }

    fn replace_council_member_cache(&self, members: HashSet<String>) {
        if let Ok(mut cache) = self.council_member_cache.write() {
            *cache = members;
        }
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

    /// Async council membership check against live chain state. Awaits the
    /// blockchain read lock. Prefer [`Self::is_council_member_blocking`] from
    /// sync principal extraction (uses cache first).
    pub async fn is_council_member(&self, did: &str) -> Option<bool> {
        let outer = self.blockchain.read().await;
        let arc = outer.as_ref()?;
        let bc = arc.read().await;
        let is_member = bc.is_council_member(did);
        self.store_council_member_cache(
            bc.get_council_members()
                .iter()
                .map(|m| m.identity_id.clone()),
        );
        Some(is_member)
    }

    /// Callable from sync code. Prefer a warmed [`Self::council_member_cache`].
    ///
    /// Lookup order (per DID variant):
    /// 1. Sync council cache (deadlock-safe under an existing blockchain read guard)
    /// 2. `try_read` chain snapshot (no await; populates cache on success)
    /// 3. Fail closed (`None` → Citizen) when cache is cold and `try_read` is contended
    pub fn is_council_member_blocking(&self, did: &str) -> Option<bool> {
        for candidate in Self::council_did_lookup_variants(did) {
            if let Some(true) = self.is_council_member_blocking_one(&candidate) {
                return Some(true);
            }
        }
        // Definitive non-member once any path returned Some(false) with warm data.
        self.is_council_member_blocking_one(did)
    }

    fn is_council_member_blocking_one(&self, did: &str) -> Option<bool> {
        if let Ok(cache) = self.council_member_cache.read() {
            if !cache.is_empty() {
                return Some(cache.contains(did));
            }
        }

        if let Some(is_member) = self.try_read_council_membership(did) {
            return Some(is_member);
        }

        warn!(
            "council membership for {} unresolved: cache cold and blockchain read lock \
             contended; failing closed (Citizen). Seed council_member_cache at startup.",
            did
        );
        None
    }

    fn try_read_council_membership(&self, did: &str) -> Option<bool> {
        let outer = self.blockchain.try_read().ok()?;
        let arc = outer.as_ref()?;
        let bc = arc.try_read().ok()?;
        let members: HashSet<String> = bc
            .get_council_members()
            .iter()
            .map(|m| m.identity_id.clone())
            .collect();
        let is_member = members.contains(did);
        self.store_council_member_cache(members.into_iter());
        Some(is_member)
    }

    /// Resolve a 32-byte QUIC device key (the `request.requester` blob set by
    /// `quic_handler.rs:729` from `session.peer_did()`) to the canonical chain
    /// DID it represents. Mirrors the resolver `/msg/receive` uses
    /// (`messaging/handler.rs:279-326`) so every owner-gated endpoint sees the
    /// same canonical DID instead of the per-device peer_did.
    ///
    /// Resolution order:
    /// 1. Direct match — chain has identity registered under
    ///    `did:zhtp:<device_key_hex>`.
    /// 2. Public-key hash match — iterate identities, hash each public key
    ///    (and combined Dilithium+Kyber bytes) and look for a match against
    ///    the device key id.
    ///
    /// Returns the canonical DID on hit, `None` on miss.
    pub async fn resolve_device_key_to_canonical_did(
        &self,
        device_key: &[u8; 32],
    ) -> Option<String> {
        let arc = self.blockchain.read().await.as_ref().cloned()?;
        let bc = arc.read().await;
        let key_id_hex = hex::encode(device_key);

        // #58: sled-first resolution. The facade does the same direct-match +
        // Dilithium / Dilithium+Kyber hash scan this used to open-code over the
        // in-memory `identity_registry`, but reads the durable `identity_metadata`
        // set so a store-backed node still resolves the recipient after a restart
        // (the in-memory registry is empty then).
        bc.did_by_device_key_id(&key_id_hex)
    }

    /// Configure blockchain mutation access mode.
    pub async fn set_access_mode(&self, access_mode: BlockchainAccessMode) {
        *self.access_mode.write().await = access_mode;
        info!("Global blockchain access mode set to {:?}", access_mode);
    }

    fn council_did_lookup_variants(did: &str) -> Vec<String> {
        let mut variants = vec![did.to_string()];
        if let Some(hex) = did.strip_prefix("did:zhtp:") {
            if hex.len() == 64 {
                variants.push(hex.to_string());
            }
        } else if did.len() == 64 && did.chars().all(|c| c.is_ascii_hexdigit()) {
            variants.push(format!("did:zhtp:{}", did));
        }
        variants
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
static COUNCIL_CACHE_REFRESH_STARTED: OnceLock<()> = OnceLock::new();

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
        .add_to_wallet_index(&owner_identity_id_hex, &wallet_id_hex)
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
                let path = format!(
                    "/wallet_private/{}/{}",
                    pending.identity_id, pending.wallet_id
                );
                dht.store_content("wallet.zhtp", &path, wallet_private_record, 86400)
                    .await?;
            }
        }
    }

    Ok(())
}

/// Spawn the projection listener as an independent tokio task that reads
/// from the broadcast channel. This runs outside the blockchain write lock.
fn spawn_projection_listener(mut rx: tokio::sync::broadcast::Receiver<BlockchainEvent>) {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => match event {
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
                },
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    error!(
                        "Projection listener lagged, skipped {} events — \
                         identity/wallet projections may be inconsistent until next restart",
                        n
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    info!("Blockchain event channel closed, projection listener exiting");
                    break;
                }
            }
        }
    });
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

    let rx = {
        let blockchain = blockchain.read().await;
        blockchain.event_publisher.subscribe()
    };
    spawn_projection_listener(rx);
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

/// Clear the global blockchain instance (unit tests only).
#[cfg(test)]
pub async fn clear_global_blockchain_for_tests() {
    if let Some(provider) = get_global_blockchain_provider() {
        provider.clear_blockchain_for_tests().await;
    }
}

/// Set the global blockchain instance
pub async fn set_global_blockchain(blockchain: Arc<RwLock<Blockchain>>) -> Result<()> {
    let provider = initialize_global_blockchain_provider();
    attach_projection_listener(&blockchain).await?;

    // Start IPC server for out-of-process services (Phase 4)
    let socket_path = crate::node_data_dir().join("blockchain.sock");
    if let Err(e) =
        lib_blockchain::ipc::server::start_ipc_server(&socket_path, blockchain.clone()).await
    {
        warn!(
            "Failed to start blockchain IPC server: {} (services will use in-process path)",
            e
        );
    } else {
        info!("Blockchain IPC server started at {}", socket_path.display());
    }

    provider.set_blockchain(blockchain).await?;

    // Keep the sync council cache fresh for role checks without nested tokio reads.
    let _ = COUNCIL_CACHE_REFRESH_STARTED.get_or_init(|| {
        let provider = initialize_global_blockchain_provider().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                provider.refresh_council_member_cache().await;
            }
        });
    });

    Ok(())
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
    Ok(blockchain_lock.get_block(height))
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
        let storage =
            lib_storage::UnifiedStorageSystem::new_persistent(config, temp.path()).unwrap();
        let storage = Arc::new(RwLock::new(storage));
        crate::runtime::storage_provider::set_global_storage(storage.clone())
            .await
            .unwrap();
        storage
    }

    #[tokio::test]
    async fn is_council_member_async_awaits_write_lock() {
        use lib_blockchain::dao::{CouncilBootstrapConfig, CouncilBootstrapEntry};

        let council_did = "did:zhtp:alice";
        let mut bc = Blockchain::new().expect("genesis");
        bc.ensure_council_bootstrap(&CouncilBootstrapConfig {
            members: vec![CouncilBootstrapEntry {
                identity_id: council_did.to_string(),
                wallet_id: "aaaa".to_string(),
                stake_amount: 1_000_000,
            }],
            threshold: 1,
        });

        let bc_arc = Arc::new(RwLock::new(bc));
        let provider = BlockchainProvider::new();
        provider.set_blockchain(bc_arc.clone()).await.unwrap();

        // Simulate block-commit writer hold: try_read would return Err here.
        let write_guard = bc_arc.write().await;

        let provider_for_check = provider.clone();
        let did = council_did.to_string();
        let membership_check =
            tokio::spawn(async move { provider_for_check.is_council_member(&did).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !membership_check.is_finished(),
            "council check must await the write lock, not fail on try_read contention"
        );

        drop(write_guard);
        assert_eq!(
            membership_check.await.expect("join"),
            Some(true),
            "council DID must resolve after the write lock is released"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn is_council_member_blocking_fails_closed_on_cold_cache_under_write_lock() {
        use lib_blockchain::dao::{CouncilBootstrapConfig, CouncilBootstrapEntry};

        let council_did = "did:zhtp:bob";
        let mut bc = Blockchain::new().expect("genesis");
        bc.ensure_council_bootstrap(&CouncilBootstrapConfig {
            members: vec![CouncilBootstrapEntry {
                identity_id: council_did.to_string(),
                wallet_id: "bbbb".to_string(),
                stake_amount: 1_000_000,
            }],
            threshold: 1,
        });

        let bc_arc = Arc::new(RwLock::new(bc));
        let provider = BlockchainProvider::new();
        provider.set_blockchain(bc_arc.clone()).await.unwrap();

        let _write_guard = bc_arc.write().await;
        provider.council_member_cache.write().unwrap().clear();

        assert_eq!(
            provider.is_council_member_blocking(council_did),
            None,
            "cold cache + write contention must fail closed without blocking a runtime worker"
        );
    }

    #[tokio::test]
    async fn refresh_council_cache_does_not_clobber_seeded_cache_when_chain_empty() {
        let council_did =
            "did:zhtp:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let mut bc = Blockchain::new().expect("genesis");
        // load_from_store replaces bc; council_members is not sled-persisted.
        bc.council_members.clear();
        let bc_arc = Arc::new(RwLock::new(bc));
        let provider = BlockchainProvider::new();
        provider.set_blockchain(bc_arc.clone()).await.unwrap();
        provider.seed_council_member_cache([council_did.to_string()]);
        assert!(
            provider
                .council_member_cache
                .read()
                .expect("cache lock")
                .contains(council_did),
            "seed must populate cache before refresh"
        );

        // Simulate load_from_store replacing bc with empty council_members.
        provider.refresh_council_member_cache().await;
        assert_eq!(
            provider
                .council_member_cache
                .read()
                .expect("cache lock")
                .len(),
            1,
            "refresh must not clobber config-seeded cache"
        );

        assert_eq!(
            provider.is_council_member_blocking_one(council_did),
            Some(true),
            "cache hit must resolve council DID"
        );
        assert_eq!(
            provider.is_council_member_blocking(council_did),
            Some(true),
            "periodic refresh must not wipe config-seeded cache when council_members is empty"
        );
    }

    #[tokio::test]
    async fn seed_council_cache_after_bootstrap_startup_order() {
        use lib_blockchain::dao::{CouncilBootstrapConfig, CouncilBootstrapEntry};

        let council_did =
            "did:zhtp:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut bc = Blockchain::new().expect("genesis");
        let bc_arc = Arc::new(RwLock::new(bc));
        let provider = BlockchainProvider::new();

        // Mirrors runtime/mod.rs: set_global_blockchain, then bootstrap after any reload.
        provider.set_blockchain(bc_arc.clone()).await.unwrap();
        assert!(
            provider.is_council_member_blocking(council_did) != Some(true),
            "council DID must not match before bootstrap + seed"
        );

        {
            let mut bc = bc_arc.write().await;
            bc.ensure_council_bootstrap(&CouncilBootstrapConfig {
                members: vec![CouncilBootstrapEntry {
                    identity_id: council_did.to_string(),
                    wallet_id: "aaaa".to_string(),
                    stake_amount: 1_000_000,
                }],
                threshold: 1,
            });
        }
        provider.seed_council_member_cache([council_did.to_string()]);
        provider.refresh_council_member_cache().await;

        assert_eq!(
            provider.is_council_member_blocking(council_did),
            Some(true),
            "post-bootstrap seed must recognize council DID without try_read/await"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn is_council_member_blocking_uses_cache_under_held_blockchain_read() {
        use lib_blockchain::dao::{CouncilBootstrapConfig, CouncilBootstrapEntry};

        let council_did = "did:zhtp:carol";
        let mut bc = Blockchain::new().expect("genesis");
        bc.ensure_council_bootstrap(&CouncilBootstrapConfig {
            members: vec![CouncilBootstrapEntry {
                identity_id: council_did.to_string(),
                wallet_id: "cccc".to_string(),
                stake_amount: 1_000_000,
            }],
            threshold: 1,
        });

        let bc_arc = Arc::new(RwLock::new(bc));
        let provider = BlockchainProvider::new();
        provider.set_blockchain(bc_arc.clone()).await.unwrap();

        // Handler-shaped: hold blockchain read, then run sync role check.
        let read_guard = bc_arc.read().await;
        assert_eq!(
            provider.is_council_member_blocking(council_did),
            Some(true),
            "warmed cache must answer without nested tokio read acquire"
        );
        drop(read_guard);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cold_cache_nested_read_falls_back_without_deadlocking_when_writer_absent() {
        use lib_blockchain::dao::{CouncilBootstrapConfig, CouncilBootstrapEntry};

        let council_did = "did:zhtp:dave";
        let mut bc = Blockchain::new().expect("genesis");
        bc.ensure_council_bootstrap(&CouncilBootstrapConfig {
            members: vec![CouncilBootstrapEntry {
                identity_id: council_did.to_string(),
                wallet_id: "dddd".to_string(),
                stake_amount: 1_000_000,
            }],
            threshold: 1,
        });

        let bc_arc = Arc::new(RwLock::new(bc));
        let provider = BlockchainProvider::new();
        provider.set_blockchain(bc_arc.clone()).await.unwrap();
        provider.council_member_cache.write().unwrap().clear();

        let read_guard = bc_arc.read().await;
        let provider_clone = provider.clone();
        let did = council_did.to_string();
        let check =
            tokio::task::spawn_blocking(move || provider_clone.is_council_member_blocking(&did));

        let result = tokio::time::timeout(std::time::Duration::from_millis(500), check).await;
        drop(read_guard);
        assert!(
            result.is_ok(),
            "nested-read + cold cache must not deadlock when no writer is queued"
        );
        assert_eq!(result.unwrap().expect("join"), Some(true));
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
                kyber_public_key: vec![],
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
        assert_eq!(
            value.get("display_name").and_then(|v| v.as_str()),
            Some("Event User")
        );
        assert_eq!(
            value.get("device_id").and_then(|v| v.as_str()),
            Some("device-a")
        );
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
                kyber_public_key: vec![],
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
            guard
                .get_wallet_private_record(&"11".repeat(32), &"22".repeat(32))
                .await
                .unwrap(),
            Some(vec![1, 2, 3, 4])
        );
    }

    #[tokio::test]
    async fn committed_wallet_event_without_pending_projection_does_not_materialize_cache_records()
    {
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
                kyber_public_key: vec![],
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
            guard
                .get_wallet_record(&"11".repeat(32), &"22".repeat(32))
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            guard
                .get_wallet_private_record(&"11".repeat(32), &"22".repeat(32))
                .await
                .unwrap(),
            None
        );
    }
}
