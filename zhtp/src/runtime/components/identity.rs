use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, debug};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use lib_identity::IdentityManager;

/// Identity component implementation using lib-identity package
pub struct IdentityComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    identity_manager: Arc<RwLock<Option<IdentityManager>>>,
    genesis_identities: Arc<RwLock<Vec<lib_identity::ZhtpIdentity>>>,
    genesis_private_data: Arc<RwLock<Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>>>,
}

impl std::fmt::Debug for IdentityComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityComponent")
            .field("status", &"<RwLock<ComponentStatus>>")
            .field("start_time", &"<RwLock<Option<Instant>>>")
            .field("identity_manager", &"<RwLock<Option<IdentityManager>>>")
            .field("genesis_identities", &"<RwLock<Vec<ZhtpIdentity>>>")
            .field("genesis_private_data", &"<RwLock<Vec<(IdentityId, PrivateIdentityData)>>>")
            .finish()
    }
}

impl IdentityComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(Vec::new())),
            genesis_private_data: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    pub fn new_with_identities(genesis_identities: Vec<lib_identity::ZhtpIdentity>) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(genesis_identities)),
            genesis_private_data: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    pub fn new_with_identities_and_private_data(
        genesis_identities: Vec<lib_identity::ZhtpIdentity>,
        genesis_private_data: Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(genesis_identities)),
            genesis_private_data: Arc::new(RwLock::new(genesis_private_data)),
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
        let genesis_private = self.genesis_private_data.read().await.clone();

        let mut identity_manager = lib_identity::initialize_identity_system().await?;

        if !genesis_ids.is_empty() {
            info!(" Adding {} genesis identities to IdentityManager", genesis_ids.len());
            for identity in &genesis_ids {
                identity_manager.add_identity(identity.clone());
                info!(" Added identity: {} (type: {:?})",
                    hex::encode(&identity.id.0[..8]), identity.identity_type);
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
                info!("✅ Bootstrap complete: {} identities, {} wallets loaded",
                    result.identities_loaded, result.wallets_loaded);
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

        if !genesis_ids.is_empty() {
            info!("Funding genesis primary wallets with 5000 ZHTP welcome bonus...");
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
                    let identity_name = String::from_utf8(data).unwrap_or_else(|_| "AnonymousCitizen".to_string());
                    let identities = manager.list_identities();
                    info!("Identity system ready for '{}' (current identities: {})", identity_name, identities.len());
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
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        if let Some(ref manager) = *self.identity_manager.read().await {
            metrics.insert("registered_identities".to_string(), manager.list_identities().len() as f64);
        } else {
            metrics.insert("registered_identities".to_string(), 0.0);
        }
        
        Ok(metrics)
    }
}

/// Helper function to create default storage configuration
pub fn create_default_storage_config() -> Result<lib_storage::UnifiedStorageConfig> {
    use lib_storage::{UnifiedStorageConfig, StorageConfig, ErasureConfig, StorageTier};
    use lib_identity::NodeId;

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
            debug!("Failed to index {}: {}", truncate_for_display(identity_id, 16), e);
        } else {
            indexed += 1;
        }
    }

    info!("📋 Indexed {} identities from backup file", indexed);
    Ok(indexed)
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

    // Get unified storage
    let storage = storage_provider::get_global_storage().await
        .map_err(|e| anyhow::anyhow!("Storage not available: {}", e))?;

    let mut identities_loaded = 0u32;
    let mut wallets_loaded = 0u32;
    let mut errors = Vec::new();

    // Hold write lock for entire bootstrap to avoid repeated lock acquisition
    let mut guard = storage.write().await;

    // First: rebuild index from backup file (catches pre-indexing identities)
    if let Err(e) = rebuild_index_from_backup(&mut *guard).await {
        debug!("Backup index rebuild skipped: {}", e);
    }

    // 1. Load identity index
    let identity_ids = match guard.list_identity_ids().await {
        Ok(ids) => ids,
        Err(e) => {
            info!("No identity index found (first run): {}", e);
            return Ok(DhtBootstrapResult {
                identities_loaded: 0,
                wallets_loaded: 0,
                errors: vec![],
            });
        }
    };

    if identity_ids.is_empty() {
        info!("📋 No identities in DHT index (fresh start)");
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

        // Extract DID and other metadata for logging
        let did = identity_json.get("did").and_then(|v| v.as_str());
        let display_name = identity_json.get("display_name").and_then(|v| v.as_str());

        // Note: Full ZhtpIdentity reconstruction requires private keys that only
        // exist on the client device. We verify the record exists and is valid.
        // The identity data remains available in DHT storage for API queries.
        if let Some(did_str) = did {
            info!("🔄 Verified identity: {} (DID: {}{})",
                id_preview,
                truncate_for_display(did_str, 32),
                display_name.map(|n| format!(", name: {}", n)).unwrap_or_default()
            );
            identities_loaded += 1;
        } else {
            // Fallback: identity without DID (legacy format)
            info!("🔄 Verified identity record: {}", id_preview);
            identities_loaded += 1;
        }

        // Load wallet indexes for this identity
        let wallet_ids = guard.list_wallet_ids_for_identity(identity_id).await.unwrap_or_default();

        for wallet_id in &wallet_ids {
            let wallet_preview = truncate_for_display(wallet_id, 16);

            match guard.get_wallet_record(identity_id, wallet_id).await {
                Ok(Some(data)) => {
                    if let Ok(wallet_json) = serde_json::from_slice::<serde_json::Value>(&data) {
                        let wallet_type = wallet_json.get("wallet_type")
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

    info!("✅ DHT bootstrap: {} identities, {} wallets verified ({} errors)",
        identities_loaded, wallets_loaded, errors.len());

    Ok(DhtBootstrapResult {
        identities_loaded,
        wallets_loaded,
        errors,
    })
}
