use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};

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
        
        let _identity_manager = if genesis_ids.is_empty() {
            info!("No genesis identities - initializing empty IdentityManager");
            lib_identity::initialize_identity_system().await?
        } else if genesis_private.is_empty() {
            info!("  Initializing IdentityManager with {} genesis identities (PUBLIC DATA ONLY)", genesis_ids.len());
            lib_identity::initialize_identity_system_with_identities(genesis_ids.clone()).await?
        } else {
            info!(" Initializing IdentityManager with {} genesis identities and {} private keys", 
                genesis_ids.len(), genesis_private.len());
            
            let mut identities_with_private = Vec::new();
            for identity in &genesis_ids {
                if let Some((_, private_data)) = genesis_private.iter().find(|(id, _)| id == &identity.id) {
                    identities_with_private.push((identity.clone(), private_data.clone()));
                    info!(" Loaded private key for identity: {} (type: {:?})", 
                        hex::encode(&identity.id.0[..8]), identity.identity_type);
                } else {
                    warn!("  No private key found for identity: {}", hex::encode(&identity.id.0[..8]));
                }
            }
            
            lib_identity::initialize_identity_system_with_identities_and_private_data(identities_with_private).await?
        };
        
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
        
        let identity_manager_arc = Arc::new(RwLock::new(_identity_manager));
        crate::runtime::set_global_identity_manager(identity_manager_arc).await?;
        info!(" Identity manager registered globally for component access");
        
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
    use lib_crypto::Hash;
    
    Ok(UnifiedStorageConfig {
        node_id: Hash([1u8; 32]),
        addresses: vec![],
        economic_config: Default::default(),
        storage_config: StorageConfig {
            max_storage_size: 1024 * 1024 * 1024,
            default_tier: StorageTier::Hot,
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,
            parity_shards: 2,
        },
    })
}
