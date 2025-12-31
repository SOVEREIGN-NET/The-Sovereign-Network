use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use lib_consensus::{ConsensusEngine, ConsensusConfig, ValidatorManager, NoOpBroadcaster};
use lib_blockchain::Blockchain;

/// Adapter to make blockchain ValidatorInfo compatible with consensus ValidatorInfo trait
pub struct BlockchainValidatorAdapter(pub lib_blockchain::ValidatorInfo);

impl lib_consensus::validators::ValidatorInfo for BlockchainValidatorAdapter {
    fn identity_id(&self) -> lib_crypto::Hash {
        let identity_hex = self.0.identity_id
            .strip_prefix("did:zhtp:")
            .unwrap_or(&self.0.identity_id);
        
        if let Ok(bytes) = hex::decode(identity_hex) {
            if bytes.len() >= 32 {
                lib_crypto::Hash::from_bytes(&bytes[..32])
            } else {
                lib_crypto::Hash(lib_crypto::hash_blake3(self.0.identity_id.as_bytes()))
            }
        } else {
            lib_crypto::Hash(lib_crypto::hash_blake3(self.0.identity_id.as_bytes()))
        }
    }
    
    fn stake(&self) -> u64 {
        self.0.stake
    }
    
    fn storage_provided(&self) -> u64 {
        self.0.storage_provided
    }
    
    fn consensus_key(&self) -> Vec<u8> {
        self.0.consensus_key.clone()
    }
    
    fn commission_rate(&self) -> u8 {
        self.0.commission_rate
    }
}

/// Consensus component implementation using lib-consensus package
pub struct ConsensusComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    consensus_engine: Arc<RwLock<Option<ConsensusEngine>>>,
    validator_manager: Arc<RwLock<ValidatorManager>>,
    blockchain: Arc<RwLock<Option<Arc<RwLock<Blockchain>>>>>,
    environment: crate::config::Environment,
}

// Manual Debug implementation because ConsensusEngine doesn't derive Debug
impl std::fmt::Debug for ConsensusComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusComponent")
            .field("status", &self.status)
            .field("start_time", &self.start_time)
            .field("consensus_engine", &"<ConsensusEngine>")
            .field("validator_manager", &"<ValidatorManager>")
            .field("blockchain", &"<Blockchain>")
            .field("environment", &self.environment)
            .finish()
    }
}

impl ConsensusComponent {
    pub fn new(environment: crate::config::Environment) -> Self {
        let development_mode = matches!(environment, crate::config::Environment::Development);
        
        let min_stake = if development_mode {
            1_000
        } else {
            100_000_000
        };
        
        let validator_manager = ValidatorManager::new_with_development_mode(
            100,
            min_stake,
            development_mode,
        );
        
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            consensus_engine: Arc::new(RwLock::new(None)),
            validator_manager: Arc::new(RwLock::new(validator_manager)),
            blockchain: Arc::new(RwLock::new(None)),
            environment,
        }
    }
    
    pub async fn set_blockchain(&self, blockchain: Arc<RwLock<Blockchain>>) {
        *self.blockchain.write().await = Some(blockchain);
    }
    
    pub async fn sync_validators_from_blockchain(&self) -> Result<()> {
        let blockchain_opt = self.blockchain.read().await;
        let blockchain = match blockchain_opt.as_ref() {
            Some(bc) => bc,
            None => {
                warn!("Cannot sync validators: blockchain not set");
                return Ok(());
            }
        };
        
        let bc = blockchain.read().await;
        let active_validators = bc.get_active_validators();
        
        if active_validators.is_empty() {
            debug!("No active validators found in blockchain registry");
            return Ok(());
        }
        
        let validator_adapters: Vec<BlockchainValidatorAdapter> = active_validators
            .into_iter()
            .map(|v| BlockchainValidatorAdapter(v.clone()))
            .collect();
        
        let mut validator_manager = self.validator_manager.write().await;
        let (synced_count, skipped_count) = validator_manager
            .sync_from_validator_list(validator_adapters)
            .context("Failed to sync validators from blockchain")?;
        
        info!(
            "Validator sync complete: {} new validators registered, {} already registered",
            synced_count, skipped_count
        );
        
        Ok(())
    }
    
    pub async fn get_validator_manager(&self) -> Arc<RwLock<ValidatorManager>> {
        self.validator_manager.clone()
    }
}

#[async_trait::async_trait]
impl Component for ConsensusComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Consensus
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting consensus component with lib-consensus implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        let mut config = ConsensusConfig::default();
        
        config.development_mode = matches!(self.environment, crate::config::Environment::Development);
        if config.development_mode {
            info!(" Development mode enabled - single validator consensus allowed for testing");
            info!("    Production deployment requires minimum 4 validators for BFT");
        } else {
            info!(" Production mode: Full consensus validation required (minimum 4 validators for BFT)");
        }
        
        // Note: Edge nodes will still initialize consensus component but won't participate in validation
        // Edge node check happens at validator registration (requires min stake + storage)

        let broadcaster = Arc::new(NoOpBroadcaster);
        let consensus_engine = lib_consensus::init_consensus(config, broadcaster)?;
        
        info!("Consensus engine initialized with hybrid PoS");
        info!("Validator management ready");
        info!("Byzantine fault tolerance active");
        
        *self.consensus_engine.write().await = Some(consensus_engine);
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Consensus component started with consensus mechanisms");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping consensus component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.consensus_engine.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Consensus component stopped");
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
            ComponentMessage::HealthCheck => {
                debug!("Consensus component health check");
                Ok(())
            }
            _ => {
                debug!("Consensus component received message: {:?}", message);
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
        
        Ok(metrics)
    }
}
