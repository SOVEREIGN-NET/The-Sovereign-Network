use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{debug, info};

use crate::api::handlers::constants::{SOV_WELCOME_BONUS, SOV_WELCOME_BONUS_SOV};
use crate::runtime::node_runtime::NodeRole;
use crate::runtime::{Component, ComponentHealth, ComponentId, ComponentMessage, ComponentStatus};
use lib_identity::IdentityManager;

/// Identity component implementation using lib-identity package
pub struct IdentityComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    identity_manager: Arc<RwLock<Option<IdentityManager>>>,
    genesis_identities: Arc<RwLock<Vec<lib_identity::ZhtpIdentity>>>,
    genesis_private_data: Arc<
        RwLock<
            Vec<(
                lib_identity::IdentityId,
                lib_identity::identity::PrivateIdentityData,
            )>,
        >,
    >,
    /// Whether this node can mine blocks. Only FullValidator nodes mine startup backfill blocks.
    can_mine: bool,
    /// Whether this node is the bootstrap mining leader (first entry in bootstrap_validators).
    /// Only the leader creates SOV backfill TokenMint transactions.
    is_bootstrap_leader: bool,
}

impl std::fmt::Debug for IdentityComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityComponent")
            .field("status", &"<RwLock<ComponentStatus>>")
            .field("start_time", &"<RwLock<Option<Instant>>>")
            .field("identity_manager", &"<RwLock<Option<IdentityManager>>>")
            .field("genesis_identities", &"<RwLock<Vec<ZhtpIdentity>>>")
            .field(
                "genesis_private_data",
                &"<RwLock<Vec<(IdentityId, PrivateIdentityData)>>>",
            )
            .field("can_mine", &self.can_mine)
            .field("is_bootstrap_leader", &self.is_bootstrap_leader)
            .finish()
    }
}

impl IdentityComponent {
    pub fn new(node_role: NodeRole, is_bootstrap_leader: bool) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(Vec::new())),
            genesis_private_data: Arc::new(RwLock::new(Vec::new())),
            can_mine: node_role.can_mine(),
            is_bootstrap_leader,
        }
    }

    pub fn new_with_identities(
        node_role: NodeRole,
        genesis_identities: Vec<lib_identity::ZhtpIdentity>,
        is_bootstrap_leader: bool,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(genesis_identities)),
            genesis_private_data: Arc::new(RwLock::new(Vec::new())),
            can_mine: node_role.can_mine(),
            is_bootstrap_leader,
        }
    }

    pub fn new_with_identities_and_private_data(
        node_role: NodeRole,
        genesis_identities: Vec<lib_identity::ZhtpIdentity>,
        genesis_private_data: Vec<(
            lib_identity::IdentityId,
            lib_identity::identity::PrivateIdentityData,
        )>,
        is_bootstrap_leader: bool,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(genesis_identities)),
            genesis_private_data: Arc::new(RwLock::new(genesis_private_data)),
            can_mine: node_role.can_mine(),
            is_bootstrap_leader,
        }
    }

    pub fn get_identity_manager_arc(&self) -> Arc<RwLock<Option<IdentityManager>>> {
        self.identity_manager.clone()
    }
}

#[async_trait::async_trait]
impl Component for IdentityComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Identity
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting identity component with lib-identity implementation...");

        *self.status.write().await = ComponentStatus::Starting;

        let genesis_ids = self.genesis_identities.read().await.clone();
        let _genesis_private = self.genesis_private_data.read().await.clone();

        let mut identity_manager = lib_identity::initialize_identity_system().await?;

        if !genesis_ids.is_empty() {
            info!(
                " Adding {} genesis identities to IdentityManager",
                genesis_ids.len()
            );
            for identity in &genesis_ids {
                identity_manager.add_identity(identity.clone());
                info!(
                    " Added identity: {} (type: {:?})",
                    hex::encode(&identity.id.0[..8]),
                    identity.identity_type
                );
            }
        } else {
            info!("No genesis identities - IdentityManager initialized empty");
        }

        // Register identity manager globally BEFORE bootstrap
        let identity_manager_arc = Arc::new(RwLock::new(identity_manager));
        crate::runtime::set_global_identity_manager(identity_manager_arc.clone()).await?;
        info!(" Identity manager registered globally for component access");

        // Bootstrap identities from DHT storage
        info!("🔄 Bootstrapping identities from DHT storage...");
        match bootstrap_identities_from_dht(&identity_manager_arc).await {
            Ok(result) => {
                info!(
                    "✅ Bootstrap complete: {} identities, {} wallets loaded",
                    result.identities_loaded, result.wallets_loaded
                );
                if !result.errors.is_empty() {
                    for err in &result.errors {
                        debug!("  Bootstrap warning: {}", err);
                    }
                }
            }
            Err(e) => {
                // Non-fatal - log and continue
                info!("⚠️ DHT bootstrap skipped (non-fatal): {}", e);
            }
        }

        // Backfill identities from blockchain.identity_registry that are missing from IdentityManager.
        // This ensures all nodes have consistent identity state regardless of DHT storage gaps.
        match backfill_identities_from_blockchain(&identity_manager_arc).await {
            Ok(count) if count > 0 => {
                info!("✅ Blockchain identity backfill: {} identities synced to IdentityManager", count);
            }
            Ok(_) => {}
            Err(e) => {
                info!("⚠️ Blockchain identity backfill skipped (non-fatal): {}", e);
            }
        }

        info!("🪙 Startup SOV backfill disabled; canonical genesis/state must already be complete");

        if !genesis_ids.is_empty() {
            info!(
                "Funding genesis primary wallets with {} SOV welcome bonus...",
                SOV_WELCOME_BONUS_SOV
            );
            for genesis_identity in &genesis_ids {
                if genesis_identity.identity_type == lib_identity::IdentityType::Human {
                    let wallet_summaries = genesis_identity.wallet_manager.list_wallets();
                    if wallet_summaries.first().is_some() {
                        // Wallet funding handled via blockchain wallet_registry sync
                    }
                }
            }
        }

        info!("Identity management system initialized");
        info!("Ready for citizen onboarding and zero-knowledge identity verification");

        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;

        info!("Identity component started with ZK identity system");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping identity component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.identity_manager.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Identity component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);

        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::Custom(msg, data) if msg == "create_identity" => {
                if let Some(ref mut manager) = self.identity_manager.write().await.as_mut() {
                    info!("Creating new citizen identity...");
                    let identity_name =
                        String::from_utf8(data).unwrap_or_else(|_| "AnonymousCitizen".to_string());
                    let identities = manager.list_identities();
                    info!(
                        "Identity system ready for '{}' (current identities: {})",
                        identity_name,
                        identities.len()
                    );
                }
                Ok(())
            }
            ComponentMessage::HealthCheck => {
                debug!("Identity component health check");
                Ok(())
            }
            _ => {
                debug!("Identity component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time
            .map(|t| t.elapsed().as_secs() as f64)
            .unwrap_or(0.0);

        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert(
            "is_running".to_string(),
            if matches!(*self.status.read().await, ComponentStatus::Running) {
                1.0
            } else {
                0.0
            },
        );

        if let Some(ref manager) = *self.identity_manager.read().await {
            metrics.insert(
                "registered_identities".to_string(),
                manager.list_identities().len() as f64,
            );
        } else {
            metrics.insert("registered_identities".to_string(), 0.0);
        }

        Ok(metrics)
    }
}

/// Helper function to create default storage configuration
pub fn create_default_storage_config() -> Result<lib_storage::UnifiedStorageConfig> {
    use lib_identity::NodeId;
    use lib_storage::{ErasureConfig, StorageConfig, StorageTier, UnifiedStorageConfig};

    // Set up persistence path under ~/.zhtp/storage/
    // Note: sled requires a DIRECTORY path, not a file path
    let zhtp_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zhtp")
        .join("storage");
    let dht_persist_path = zhtp_dir.join("dht_db");

    Ok(UnifiedStorageConfig {
        node_id: NodeId::from_bytes([1u8; 32]),
        addresses: vec![],
        economic_config: Default::default(),
        storage_config: StorageConfig {
            max_storage_size: 1024 * 1024 * 1024,
            default_tier: StorageTier::Hot,
            enable_compression: true,
            enable_encryption: true,
            dht_persist_path: Some(dht_persist_path),
        },
        erasure_config: ErasureConfig {
            data_shards: 4,
            parity_shards: 2,
        },
    })
}

/// Result of bootstrapping identities from DHT
#[derive(Debug)]
pub struct DhtBootstrapResult {
    pub identities_loaded: u32,
    pub wallets_loaded: u32,
    pub errors: Vec<String>,
}

/// Safe string truncation for display (avoids panic on short strings)
fn truncate_for_display(s: &str, max_len: usize) -> &str {
    let len = max_len.min(s.len());
    &s[..len]
}

fn parse_identity_type(identity_type: &str) -> lib_identity::IdentityType {
    match identity_type.to_ascii_lowercase().as_str() {
        "human" => lib_identity::IdentityType::Human,
        "device" => lib_identity::IdentityType::Device,
        "organization" => lib_identity::IdentityType::Organization,
        "agent" => lib_identity::IdentityType::Agent,
        "contract" => lib_identity::IdentityType::Contract,
        _ => lib_identity::IdentityType::Human,
    }
}

fn parse_wallet_type(wallet_type: &str) -> lib_identity::wallets::WalletType {
    match wallet_type.to_ascii_lowercase().as_str() {
        "primary" => lib_identity::wallets::WalletType::Primary,
        "ubi" => lib_identity::wallets::WalletType::UBI,
        "savings" => lib_identity::wallets::WalletType::Savings,
        "business" => lib_identity::wallets::WalletType::Business,
        "stealth" => lib_identity::wallets::WalletType::Stealth,
        "dao" | "nonprofitdao" | "non_profit_dao" | "non-profit-dao" => {
            lib_identity::wallets::WalletType::NonProfitDAO
        }
        "forprofitdao" | "for_profit_dao" | "for-profit-dao" => {
            lib_identity::wallets::WalletType::ForProfitDAO
        }
        "standard" => lib_identity::wallets::WalletType::Standard,
        _ => lib_identity::wallets::WalletType::Primary,
    }
}

fn reconstruct_identity_manager_from_blockchain_state(
    identity_manager: &mut IdentityManager,
    identity_registry: &HashMap<String, lib_blockchain::transaction::IdentityTransactionData>,
    wallet_registry: &HashMap<String, lib_blockchain::transaction::WalletTransactionData>,
) -> Result<(u32, u32)> {
    let mut wallets_by_owner: HashMap<String, Vec<&lib_blockchain::transaction::WalletTransactionData>> =
        HashMap::new();
    for wallet in wallet_registry.values() {
        if let Some(owner_identity_id) = wallet.owner_identity_id {
            wallets_by_owner
                .entry(hex::encode(owner_identity_id.as_bytes()))
                .or_default()
                .push(wallet);
        }
    }

    let mut identities_loaded = 0u32;
    let mut wallets_loaded = 0u32;

    for identity_data in identity_registry.values() {
        let identity_id = match lib_identity::did::parse_did_to_identity_id(&identity_data.did) {
            Ok(id) => id,
            Err(_) => continue,
        };

        if identity_manager.get_identity(&identity_id).is_some() {
            continue;
        }

        let public_key = lib_crypto::PublicKey::new(identity_data.public_key.clone());
        let display_name = if identity_data.display_name.is_empty() {
            None
        } else {
            Some(identity_data.display_name.clone())
        };
        let mut identity = lib_identity::ZhtpIdentity::new_external(
            identity_data.did.clone(),
            public_key,
            parse_identity_type(&identity_data.identity_type),
            identity_data
                .did
                .trim_start_matches("did:zhtp:")
                .to_string(),
            display_name,
            identity_data.created_at,
        )?;
        identity.did_document_hash =
            Some(lib_crypto::Hash::from_bytes(identity_data.did_document_hash.as_bytes()));
        identity.wallet_manager.wallets.clear();
        identity.wallet_manager.total_balance = 0;

        let owner_key = hex::encode(identity_id.as_bytes());
        if let Some(wallets) = wallets_by_owner.get(&owner_key) {
            for wallet_data in wallets {
                if let Ok(wallet_id) = identity.wallet_manager.add_restored_wallet(
                    &hex::encode(wallet_data.wallet_id.as_bytes()),
                    parse_wallet_type(&wallet_data.wallet_type),
                    wallet_data.created_at,
                ) {
                    if let Some(wallet) = identity.wallet_manager.get_wallet_mut(&wallet_id) {
                        wallet.name = wallet_data.wallet_name.clone();
                        wallet.alias = wallet_data.alias.clone();
                        wallet.public_key = wallet_data.public_key.clone();
                        wallet.seed_commitment =
                            Some(hex::encode(wallet_data.seed_commitment.as_bytes()));
                        wallet.balance = wallet_data.initial_balance;
                    }
                    wallets_loaded += 1;
                }
            }
        }

        identity_manager.add_identity(identity);
        identities_loaded += 1;
    }

    Ok((identities_loaded, wallets_loaded))
}

/// Rebuild identity index from backup file (~/.zhtp/backup/identities.json)
/// This ensures identities created before indexing was implemented get indexed
async fn rebuild_index_from_backup(
    storage: &mut lib_storage::PersistentStorageSystem,
) -> Result<u32> {
    use std::io::BufReader;

    let backup_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zhtp")
        .join("backup")
        .join("identities.json");

    if !backup_path.exists() {
        debug!("No backup file found at {:?}", backup_path);
        return Ok(0);
    }

    info!("📂 Reading identity backup from {:?}", backup_path);

    let file = std::fs::File::open(&backup_path)
        .map_err(|e| anyhow::anyhow!("Failed to open backup: {}", e))?;
    let reader = BufReader::new(file);
    let backup: serde_json::Map<String, serde_json::Value> = serde_json::from_reader(reader)
        .map_err(|e| anyhow::anyhow!("Failed to parse backup: {}", e))?;

    let mut indexed = 0u32;
    for identity_id in backup.keys() {
        if let Err(e) = storage.add_to_identity_index(identity_id).await {
            debug!(
                "Failed to index {}: {}",
                truncate_for_display(identity_id, 16),
                e
            );
        } else {
            indexed += 1;
        }
    }

    info!("📋 Indexed {} identities from backup file", indexed);
    Ok(indexed)
}

/// One-time migration: Register identities from backup file to blockchain
///
/// Enable by setting environment variable: ZHTP_MIGRATE_IDENTITIES=1
/// This reads ~/.zhtp/backup/identities.json and registers any identities
/// that are not yet on the blockchain.
///
/// SAFE: Only adds missing identities, never overwrites existing ones.
async fn migrate_identities_to_blockchain() -> Result<(u32, u32)> {
    use std::io::BufReader;

    // Check if migration is enabled
    let migrate_enabled = std::env::var("ZHTP_MIGRATE_IDENTITIES")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if !migrate_enabled {
        return Ok((0, 0));
    }

    info!("🔄 MIGRATION MODE: ZHTP_MIGRATE_IDENTITIES=1 detected");

    let backup_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zhtp")
        .join("backup")
        .join("identities.json");

    if !backup_path.exists() {
        info!("⚠️  No backup file found at {:?}", backup_path);
        return Ok((0, 0));
    }

    info!("📂 Reading identities from {:?}", backup_path);

    let file = std::fs::File::open(&backup_path)
        .map_err(|e| anyhow::anyhow!("Failed to open backup: {}", e))?;
    let reader = BufReader::new(file);
    let backup: serde_json::Map<String, serde_json::Value> = serde_json::from_reader(reader)
        .map_err(|e| anyhow::anyhow!("Failed to parse backup: {}", e))?;

    info!("📋 Found {} identities in backup file", backup.len());

    // Get blockchain for registration
    let blockchain_arc = match crate::runtime::blockchain_provider::get_global_blockchain().await {
        Ok(bc) => bc,
        Err(e) => {
            info!("⚠️  Blockchain not available for migration: {}", e);
            return Ok((0, 0));
        }
    };

    let mut migrated = 0u32;
    let mut skipped = 0u32;

    for (identity_id, entry) in &backup {
        let id_preview = truncate_for_display(identity_id, 16);

        // Navigate nested structure: entry.data.data contains actual identity
        let identity_data = match entry.get("data").and_then(|d| d.get("data")) {
            Some(data) => data,
            None => {
                debug!("Skipping {} - invalid structure", id_preview);
                continue;
            }
        };

        // Extract identity fields
        let did = match identity_data.get("did").and_then(|v| v.as_str()) {
            Some(d) => d,
            None => {
                debug!("Skipping {} - no DID", id_preview);
                continue;
            }
        };

        // Check if already on blockchain
        {
            let bc = blockchain_arc.read().await;
            if bc.identity_registry.contains_key(did) {
                debug!("Identity {} already on blockchain, skipping", id_preview);
                skipped += 1;
                continue;
            }
        }

        // Extract required fields for registration
        let display_name = identity_data
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Migrated User");

        let identity_type = identity_data
            .get("identity_type")
            .and_then(|v| v.as_str())
            .unwrap_or("human");

        let created_at = identity_data
            .get("created_at")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Get public key (try dilithium_public_key first, then public_key)
        let public_key_data = identity_data
            .get("dilithium_public_key")
            .or_else(|| identity_data.get("public_key"))
            .and_then(|v| v.as_str());

        let public_key_bytes = match public_key_data {
            Some(pk_str) => {
                // Try base64 first (iOS format), then hex
                if pk_str.contains('+') || pk_str.contains('/') || pk_str.ends_with('=') {
                    use base64::{engine::general_purpose::STANDARD, Engine};
                    STANDARD.decode(pk_str).unwrap_or_default()
                } else {
                    hex::decode(pk_str).unwrap_or_default()
                }
            }
            None => {
                debug!("Skipping {} - no public key", id_preview);
                continue;
            }
        };

        if public_key_bytes.is_empty() {
            debug!("Skipping {} - empty public key", id_preview);
            continue;
        }

        // Create identity transaction data
        let identity_tx_data = lib_blockchain::transaction::IdentityTransactionData {
            did: did.to_string(),
            display_name: display_name.to_string(),
            public_key: public_key_bytes,
            ownership_proof: vec![],
            identity_type: identity_type.to_string(),
            did_document_hash: lib_blockchain::Hash::zero(),
            created_at,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: vec![],
            owned_wallets: vec![],
        };

        // Register on blockchain
        let mut bc = blockchain_arc.write().await;
        match bc.register_identity(identity_tx_data) {
            Ok(_) => {
                info!("✅ Migrated identity: {} ({})", id_preview, display_name);
                migrated += 1;
            }
            Err(e) => {
                debug!("Failed to migrate {}: {}", id_preview, e);
            }
        }
    }

    info!(
        "🎉 Migration complete: {} migrated, {} already existed",
        migrated, skipped
    );

    // Mine a block to persist the identity transactions to sled
    if migrated > 0 {
        info!("⛏️  Mining migration block to persist identities to sled...");

        let mut bc = blockchain_arc.write().await;
        let pending_count = bc.pending_transactions.len();

        if pending_count > 0 {
            // Use BlockBuilder to create and mine a block
            let mining_config = lib_blockchain::types::MiningConfig::bootstrap();

            // Get previous block info
            let prev_hash = bc
                .blocks
                .last()
                .map(|b| b.hash())
                .unwrap_or(lib_blockchain::Hash::zero());
            let height = bc.height + 1;
            let difficulty = bc.difficulty.clone();

            // Create block using BlockBuilder
            let transactions = bc.pending_transactions.clone();
            let block = lib_blockchain::block::BlockBuilder::new(prev_hash, height, difficulty)
                .transactions(transactions)
                .build();

            match block {
                Ok(block) => {
                    // Mine the block
                    match lib_blockchain::block::creation::mine_block_with_config(
                        block,
                        &mining_config,
                    ) {
                        Ok(mined_block) => {
                            let block_height = mined_block.height();
                            // Add block - this handles sled persistence internally
                            if let Err(e) = bc.add_block(mined_block).await {
                                info!("⚠️  Failed to add migration block: {}", e);
                                // Fallback: save to file (deprecated, for legacy mode only)
                                #[allow(deprecated)]
                                if let Err(e2) = bc.save_to_file(std::path::Path::new(
                                    "./data/testnet/blockchain.dat",
                                )) {
                                    info!("⚠️  Fallback save also failed: {}", e2);
                                }
                            } else {
                                info!("✅ Migration block mined at height {} with {} identity transactions",
                                    block_height, pending_count);
                            }
                        }
                        Err(e) => {
                            info!("⚠️  Failed to mine migration block: {}", e);
                            // Fallback: save to file (deprecated, for legacy mode only)
                            #[allow(deprecated)]
                            if let Err(e2) = bc
                                .save_to_file(std::path::Path::new("./data/testnet/blockchain.dat"))
                            {
                                info!("⚠️  Fallback save also failed: {}", e2);
                            }
                        }
                    }
                }
                Err(e) => {
                    info!("⚠️  Failed to build migration block: {}", e);
                }
            }
        } else {
            info!("📋 No pending transactions to mine");
        }
    }

    Ok((migrated, skipped))
}

/// Bootstrap identities and wallets from DHT storage
///
/// This function loads all identities and their wallets from the persistent
/// DHT storage index. Since identities contain private keys that only exist
/// on the client device, we cannot fully reconstruct ZhtpIdentity objects.
/// Instead, we verify the stored records exist and are valid, making them
/// available for API queries and peer discovery.
async fn bootstrap_identities_from_dht(
    identity_manager: &Arc<RwLock<IdentityManager>>,
) -> Result<DhtBootstrapResult> {
    use crate::runtime::storage_provider;

    info!("🔄 Starting DHT identity bootstrap...");

    // Get unified storage (retry up to 10 times with 500ms delay — storage may
    // not be ready immediately after StorageComponent starts)
    let storage = match storage_provider::get_global_storage().await {
        Ok(s) => s,
        Err(_) => {
            info!("⏳ Waiting for storage provider to become available...");
            let mut attempts = 0;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                attempts += 1;
                if let Ok(s) = storage_provider::get_global_storage().await {
                    info!(" ✓ Storage became available after {} attempts", attempts);
                    break s;
                }
                if attempts >= 10 {
                    return Err(anyhow::anyhow!(
                        "Storage not available after {} attempts (5s timeout)",
                        attempts
                    ));
                }
            }
        }
    };

    let mut identities_loaded = 0u32;
    let mut wallets_loaded = 0u32;
    let mut errors = Vec::new();

    // Hold write lock for entire bootstrap to avoid repeated lock acquisition
    let mut guard = storage.write().await;

    // First: rebuild index from backup file (catches pre-indexing identities)
    if let Err(e) = rebuild_index_from_backup(&mut *guard).await {
        debug!("Backup index rebuild skipped: {}", e);
    }

    // Drop storage lock before blockchain migration (needs blockchain lock)
    drop(guard);

    // One-time migration: register identities from backup to blockchain
    // Enable with: ZHTP_MIGRATE_IDENTITIES=1
    match migrate_identities_to_blockchain().await {
        Ok((migrated, skipped)) if migrated > 0 => {
            info!(
                "🔄 Blockchain migration: {} new, {} existing",
                migrated, skipped
            );
        }
        Ok(_) => {
            // Migration disabled or no new identities
        }
        Err(e) => {
            debug!("Blockchain migration skipped: {}", e);
        }
    }

    // Re-acquire storage lock for rest of bootstrap
    let mut guard = storage.write().await;

    // 1. Load identity index
    let mut identity_ids = match guard.list_identity_ids().await {
        Ok(ids) => ids,
        Err(e) => {
            info!("No identity index found (first run): {}", e);
            Vec::new()
        }
    };

    // 2. If index is empty, try migration from existing DHT keys
    if identity_ids.is_empty() {
        info!("📋 Index empty, attempting migration from existing DHT keys...");
        match guard.rebuild_identity_index_from_dht().await {
            Ok(count) if count > 0 => {
                info!("✅ Migrated {} identities from DHT storage", count);
                // Reload the index after migration
                identity_ids = guard.list_identity_ids().await.unwrap_or_default();
            }
            Ok(_) => {
                info!("📋 No identities in DHT storage (fresh start)");
            }
            Err(e) => {
                debug!("DHT migration failed: {}", e);
            }
        }
    }

    if identity_ids.is_empty() {
        info!("📋 No identities found after migration attempts");
        return Ok(DhtBootstrapResult {
            identities_loaded: 0,
            wallets_loaded: 0,
            errors: vec![],
        });
    }

    info!("📋 Found {} identities in DHT index", identity_ids.len());

    // 2. For each identity, load record and verify
    for identity_id in &identity_ids {
        let id_preview = truncate_for_display(identity_id, 16);

        // Load identity record
        let identity_data = match guard.get_identity_record(identity_id).await {
            Ok(Some(data)) => data,
            Ok(None) => {
                debug!("Identity {} in index but no record found", id_preview);
                continue;
            }
            Err(e) => {
                errors.push(format!("Failed to load identity {}: {}", id_preview, e));
                continue;
            }
        };

        // Validate data is not corrupted
        if identity_data.is_empty() {
            errors.push(format!("Empty identity record for {}", id_preview));
            continue;
        }

        // Parse identity ID hash for manager lookup
        let identity_hash = match lib_crypto::Hash::from_hex(identity_id) {
            Ok(h) => h,
            Err(e) => {
                debug!("Invalid identity ID format {}: {}", id_preview, e);
                continue;
            }
        };

        // Check if already in manager (from genesis or prior load)
        {
            let mgr = identity_manager.read().await;
            if mgr.get_identity(&identity_hash).is_some() {
                debug!("Identity {} already in manager, skipping", id_preview);
                continue;
            }
        }

        // Parse the stored data to extract identity info
        let identity_json: serde_json::Value = match serde_json::from_slice(&identity_data) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("Corrupted identity JSON for {}: {}", id_preview, e));
                continue;
            }
        };

        // Extract fields needed to register identity
        let did = identity_json.get("did").and_then(|v| v.as_str());
        let public_key_hex = identity_json.get("public_key").and_then(|v| v.as_str());
        let device_id = identity_json.get("device_id").and_then(|v| v.as_str());
        let display_name = identity_json.get("display_name").and_then(|v| v.as_str());
        let identity_type_str = identity_json.get("identity_type").and_then(|v| v.as_str());
        let created_at = identity_json
            .get("created_at")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Try to register identity into IdentityManager
        if let (Some(did_str), Some(pk_data), Some(dev_id)) = (did, public_key_hex, device_id) {
            // Parse public key - try base64 first (iOS format), then hex
            let pk_bytes =
                if pk_data.contains('+') || pk_data.contains('/') || pk_data.ends_with('=') {
                    // Base64 encoded (iOS client format)
                    use base64::{engine::general_purpose::STANDARD, Engine};
                    STANDARD.decode(pk_data).ok()
                } else {
                    // Hex encoded
                    hex::decode(pk_data).ok()
                };

            match pk_bytes {
                Some(bytes) => {
                    let pk_bytes_for_migration = bytes.clone();
                    let public_key = lib_crypto::PublicKey::new(bytes);
                    // Parse identity type
                    let identity_type = match identity_type_str {
                        Some("Device") => lib_identity::IdentityType::Device,
                        Some("Organization") => lib_identity::IdentityType::Organization,
                        _ => lib_identity::IdentityType::Human,
                    };

                    // Register into IdentityManager
                    let mut mgr = identity_manager.write().await;
                    if let Err(e) = mgr.register_external_identity(
                        identity_hash.clone(),
                        did_str.to_string(),
                        public_key,
                        identity_type,
                        dev_id.to_string(),
                        display_name.map(|s| s.to_string()),
                        created_at,
                    ) {
                        debug!(
                            "Failed to register identity {} (may already exist): {}",
                            id_preview, e
                        );
                    } else {
                        // Restore wallets from stored data - balances come from blockchain
                        let primary_wallet_id = identity_json
                            .get("primary_wallet_id")
                            .and_then(|v| v.as_str());
                        let ubi_wallet_id =
                            identity_json.get("ubi_wallet_id").and_then(|v| v.as_str());
                        let savings_wallet_id = identity_json
                            .get("savings_wallet_id")
                            .and_then(|v| v.as_str());

                        // Get blockchain for balance lookup and migration
                        let blockchain_arc =
                            crate::runtime::blockchain_provider::get_global_blockchain()
                                .await
                                .ok();

                        // Migrate missing wallets to blockchain (for identities created before fix)
                        if let Some(ref bc_arc) = blockchain_arc {
                            let mut bc = bc_arc.write().await;

                            // Migrate primary wallet if missing
                            if let Some(wid) = primary_wallet_id {
                                if !bc.wallet_registry.contains_key(wid) {
                                    let wallet_bytes = hex::decode(wid).unwrap_or_default();
                                    if wallet_bytes.len() >= 32 {
                                        const WELCOME_BONUS: u64 = SOV_WELCOME_BONUS;
                                        let wallet_data =
                                            lib_blockchain::transaction::WalletTransactionData {
                                                wallet_id: lib_blockchain::Hash::from_slice(
                                                    &wallet_bytes[..32],
                                                ),
                                                wallet_type: "Primary".to_string(),
                                                wallet_name: "Primary Wallet".to_string(),
                                                alias: Some("primary".to_string()),
                                                public_key: pk_bytes_for_migration.clone(),
                                                owner_identity_id: Some(
                                                    lib_blockchain::Hash::from_slice(
                                                        &identity_hash.0,
                                                    ),
                                                ),
                                                seed_commitment:
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        b"migrated_wallet",
                                                    ),
                                                created_at,
                                                registration_fee: 0,
                                                capabilities: 0xFF,
                                                initial_balance: WELCOME_BONUS,
                                            };
                                        if bc.register_wallet(wallet_data).is_ok() {
                                            // Create spendable UTXO (not just registry entry)
                                            bc.create_funding_utxo(
                                                wid,
                                                &identity_hash.0,
                                                WELCOME_BONUS,
                                            );
                                            info!("💰 MIGRATED primary wallet {} with {} SOV (spendable)", &wid[..16], SOV_WELCOME_BONUS_SOV);
                                        }
                                    }
                                }
                            }

                            // Migrate UBI wallet if missing
                            if let Some(wid) = ubi_wallet_id {
                                if !bc.wallet_registry.contains_key(wid) {
                                    let wallet_bytes = hex::decode(wid).unwrap_or_default();
                                    if wallet_bytes.len() >= 32 {
                                        let wallet_data =
                                            lib_blockchain::transaction::WalletTransactionData {
                                                wallet_id: lib_blockchain::Hash::from_slice(
                                                    &wallet_bytes[..32],
                                                ),
                                                wallet_type: "UBI".to_string(),
                                                wallet_name: "UBI Wallet".to_string(),
                                                alias: Some("ubi".to_string()),
                                                public_key: pk_bytes_for_migration.clone(),
                                                owner_identity_id: Some(
                                                    lib_blockchain::Hash::from_slice(
                                                        &identity_hash.0,
                                                    ),
                                                ),
                                                seed_commitment:
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        b"migrated_wallet",
                                                    ),
                                                created_at,
                                                registration_fee: 0,
                                                capabilities: 0x01,
                                                initial_balance: 0,
                                            };
                                        let _ = bc.register_wallet(wallet_data);
                                    }
                                }
                            }

                            // Migrate savings wallet if missing
                            if let Some(wid) = savings_wallet_id {
                                if !bc.wallet_registry.contains_key(wid) {
                                    let wallet_bytes = hex::decode(wid).unwrap_or_default();
                                    if wallet_bytes.len() >= 32 {
                                        let wallet_data =
                                            lib_blockchain::transaction::WalletTransactionData {
                                                wallet_id: lib_blockchain::Hash::from_slice(
                                                    &wallet_bytes[..32],
                                                ),
                                                wallet_type: "Savings".to_string(),
                                                wallet_name: "Savings Wallet".to_string(),
                                                alias: Some("savings".to_string()),
                                                public_key: pk_bytes_for_migration.clone(),
                                                owner_identity_id: Some(
                                                    lib_blockchain::Hash::from_slice(
                                                        &identity_hash.0,
                                                    ),
                                                ),
                                                seed_commitment:
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        b"migrated_wallet",
                                                    ),
                                                created_at,
                                                registration_fee: 0,
                                                capabilities: 0x02,
                                                initial_balance: 0,
                                            };
                                        let _ = bc.register_wallet(wallet_data);
                                    }
                                }
                            }
                        }

                        // Now restore wallets and read balances from blockchain
                        if let Some(identity) = mgr.get_identity_mut(&identity_hash) {
                            if let Some(wid) = primary_wallet_id {
                                if let Ok(wallet_id) = identity.wallet_manager.add_restored_wallet(
                                    wid,
                                    lib_identity::wallets::WalletType::Primary,
                                    created_at,
                                ) {
                                    if let Some(ref bc_arc) = blockchain_arc {
                                        let bc = bc_arc.read().await;
                                        if let Some(wallet_data) = bc.wallet_registry.get(wid) {
                                            if let Some(wallet) =
                                                identity.wallet_manager.get_wallet_mut(&wallet_id)
                                            {
                                                wallet.balance = wallet_data.initial_balance;
                                                debug!("Restored primary wallet {} with balance {} from blockchain", wid, wallet_data.initial_balance);
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(wid) = ubi_wallet_id {
                                if let Ok(wallet_id) = identity.wallet_manager.add_restored_wallet(
                                    wid,
                                    lib_identity::wallets::WalletType::UBI,
                                    created_at,
                                ) {
                                    if let Some(ref bc_arc) = blockchain_arc {
                                        let bc = bc_arc.read().await;
                                        if let Some(wallet_data) = bc.wallet_registry.get(wid) {
                                            if let Some(wallet) =
                                                identity.wallet_manager.get_wallet_mut(&wallet_id)
                                            {
                                                wallet.balance = wallet_data.initial_balance;
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(wid) = savings_wallet_id {
                                if let Ok(wallet_id) = identity.wallet_manager.add_restored_wallet(
                                    wid,
                                    lib_identity::wallets::WalletType::Savings,
                                    created_at,
                                ) {
                                    if let Some(ref bc_arc) = blockchain_arc {
                                        let bc = bc_arc.read().await;
                                        if let Some(wallet_data) = bc.wallet_registry.get(wid) {
                                            if let Some(wallet) =
                                                identity.wallet_manager.get_wallet_mut(&wallet_id)
                                            {
                                                wallet.balance = wallet_data.initial_balance;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        info!(
                            "🔄 Loaded identity: {} (DID: {}{})",
                            id_preview,
                            truncate_for_display(did_str, 32),
                            display_name
                                .map(|n| format!(", name: {}", n))
                                .unwrap_or_default()
                        );
                        identities_loaded += 1;
                    }
                }
                None => {
                    debug!("Failed to parse public key for {}", id_preview);
                    // Still count as verified even if we can't register
                    identities_loaded += 1;
                }
            }
        } else {
            // Fallback: identity without required fields (legacy format)
            info!(
                "🔄 Verified identity record: {} (missing registration data)",
                id_preview
            );
            identities_loaded += 1;
        }

        // Load wallet indexes for this identity
        let wallet_ids = guard
            .list_wallet_ids_for_identity(identity_id)
            .await
            .unwrap_or_default();

        for wallet_id in &wallet_ids {
            let wallet_preview = truncate_for_display(wallet_id, 16);

            match guard.get_wallet_record(identity_id, wallet_id).await {
                Ok(Some(data)) => {
                    if let Ok(wallet_json) = serde_json::from_slice::<serde_json::Value>(&data) {
                        let wallet_type = wallet_json
                            .get("wallet_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown");
                        debug!("  Verified wallet {} ({})", wallet_preview, wallet_type);
                        wallets_loaded += 1;
                    }
                }
                Ok(None) => {
                    debug!("  Wallet {} in index but no record", wallet_preview);
                }
                Err(e) => {
                    errors.push(format!("Failed to load wallet {}: {}", wallet_preview, e));
                }
            }
        }
    }

    // Release lock
    drop(guard);

    info!(
        "✅ DHT bootstrap: {} identities, {} wallets verified ({} errors)",
        identities_loaded,
        wallets_loaded,
        errors.len()
    );

    Ok(DhtBootstrapResult {
        identities_loaded,
        wallets_loaded,
        errors,
    })
}

/// Backfill identities from blockchain.identity_registry into the IdentityManager.
///
/// When DHT storage is missing or incomplete (e.g. after a sled wipe), identities that were
/// committed in consensus blocks still exist in blockchain.identity_registry but are absent
/// from the IdentityManager. This function bridges that gap so all nodes have consistent state.
async fn backfill_identities_from_blockchain(
    identity_manager: &Arc<RwLock<IdentityManager>>,
) -> Result<usize> {
    let blockchain_arc = match crate::runtime::blockchain_provider::get_global_blockchain().await {
        Ok(arc) => arc,
        Err(_) => return Ok(0),
    };

    let bc = blockchain_arc.read().await;
    let identity_registry = bc.identity_registry.clone();
    let wallet_registry = bc.wallet_registry.clone();
    drop(bc);

    if identity_registry.is_empty() {
        return Ok(0);
    }

    let mut mgr = identity_manager.write().await;
    let (identities_loaded, wallets_loaded) = reconstruct_identity_manager_from_blockchain_state(
        &mut mgr,
        &identity_registry,
        &wallet_registry,
    )?;
    if identities_loaded > 0 || wallets_loaded > 0 {
        info!(
            "🔄 Blockchain backfill restored {} identities and {} wallets into IdentityManager",
            identities_loaded, wallets_loaded
        );
    }

    Ok(identities_loaded as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::transaction::{IdentityTransactionData, WalletTransactionData};
    use lib_blockchain::Hash;

    #[test]
    fn reconstruct_identity_manager_from_blockchain_state_restores_wallets() {
        let did = "did:zhtp:1111111111111111111111111111111111111111111111111111111111111111";
        let identity_id =
            lib_identity::did::parse_did_to_identity_id(did).expect("identity id should parse");
        let mut manager = IdentityManager::new();

        let mut identities = HashMap::new();
        identities.insert(
            did.to_string(),
            IdentityTransactionData {
                did: did.to_string(),
                did_document_hash: Hash::new([0x21; 32]),
                public_key: vec![0x22; 32],
                ownership_proof: vec![],
                identity_type: "Human".to_string(),
                display_name: "Backfilled".to_string(),
                registration_fee: 0,
                dao_fee: 0,
                created_at: 1_700_000_000,
                controlled_nodes: vec![],
                owned_wallets: vec![],
            },
        );

        let wallet_id = Hash::new([0x31; 32]);
        let mut wallets = HashMap::new();
        wallets.insert(
            hex::encode(wallet_id.as_bytes()),
            WalletTransactionData {
                wallet_id,
                wallet_type: "Primary".to_string(),
                wallet_name: "Primary Wallet".to_string(),
                alias: Some("main".to_string()),
                public_key: vec![0x41; 32],
                owner_identity_id: Some(Hash::from_slice(identity_id.as_bytes())),
                seed_commitment: Hash::new([0x51; 32]),
                created_at: 1_700_000_001,
                registration_fee: 0,
                capabilities: 0,
                initial_balance: 77,
            },
        );

        let (identities_loaded, wallets_loaded) =
            reconstruct_identity_manager_from_blockchain_state(&mut manager, &identities, &wallets)
                .expect("blockchain reconstruction should succeed");

        assert_eq!(identities_loaded, 1);
        assert_eq!(wallets_loaded, 1);

        let identity = manager
            .get_identity(&identity_id)
            .expect("identity should be restored");
        let restored_wallets = identity.wallet_manager.list_wallets();
        assert_eq!(restored_wallets.len(), 1);
        assert_eq!(restored_wallets[0].name, "Primary Wallet");
        assert_eq!(restored_wallets[0].balance, 77);
    }
}
