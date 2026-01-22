use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug, error};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use crate::runtime::node_runtime::NodeRole;
use lib_consensus::{ConsensusEngine, ConsensusConfig, ConsensusEvent, ValidatorManager, NoOpBroadcaster};
use crate::monitoring::{Alert, AlertLevel, AlertManager};
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
    /// Node role determines whether this node participates in consensus validation
    /// This is IMMUTABLE and set at construction time based on configuration
    /// The role cannot change after the component is created
    node_role: Arc<NodeRole>,
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
            .field("node_role", &*self.node_role)
            .finish()
    }
}

impl ConsensusComponent {
    /// Create a new ConsensusComponent with the specified node role
    /// CRITICAL: node_role must be derived from configuration before calling this
    pub fn new(environment: crate::config::Environment, node_role: NodeRole) -> Self {
        let development_mode = matches!(environment, crate::config::Environment::Development);
        let is_testnet = matches!(environment, crate::config::Environment::Testnet);

        // Low stake for development and testnet, high stake for production
        let min_stake = if development_mode || is_testnet {
            1_000  // 1000 micro-ZHTP for dev/testnet
        } else {
            100_000_000  // 100M micro-ZHTP for production
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
            node_role: Arc::new(node_role),
        }
    }

    #[deprecated = "Use new(environment, node_role) instead to properly initialize node role from config"]
    pub fn new_deprecated(environment: crate::config::Environment) -> Self {
        Self::new(environment, NodeRole::Observer)
    }

    /// Get the current node role (immutable)
    pub fn get_node_role(&self) -> NodeRole {
        (*self.node_role).clone()
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

async fn handle_liveness_event(alert_manager: &AlertManager, event: ConsensusEvent) {
    match event {
        ConsensusEvent::ConsensusStalled {
            height,
            round,
            timed_out_validators,
            total_validators,
            timestamp,
        } => {
            let mut metadata = HashMap::new();
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("round".to_string(), round.to_string());
            metadata.insert(
                "timed_out_validators".to_string(),
                timed_out_validators.len().to_string(),
            );
            metadata.insert("total_validators".to_string(), total_validators.to_string());

            let alert = Alert {
                id: format!("consensus-stalled-{}-{}", height, round),
                level: AlertLevel::Critical,
                title: "Consensus stalled".to_string(),
                message: format!(
                    "Consensus stalled at height {} round {} ({} of {} validators timed out)",
                    height,
                    round,
                    timed_out_validators.len(),
                    total_validators
                ),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        ConsensusEvent::ConsensusRecovered { height, round, timestamp } => {
            let mut metadata = HashMap::new();
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("round".to_string(), round.to_string());

            let alert = Alert {
                id: format!("consensus-recovered-{}-{}", height, round),
                level: AlertLevel::Info,
                title: "Consensus recovered".to_string(),
                message: format!("Consensus recovered at height {} round {}", height, round),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        _ => {}
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
        
        // Check if this node can participate in consensus validation
        // Only FullValidator nodes should run the consensus engine
        if !self.node_role.can_validate() {
            let role_desc = match &*self.node_role {
                crate::runtime::node_runtime::NodeRole::Observer => "observer (verifies blocks, no voting)",
                crate::runtime::node_runtime::NodeRole::LightNode => "light (trusts validators)",
                _ => "non-validator",
            };
            info!(
                "ℹ️ Node type {:?} does not participate in consensus - running as {} node",
                *self.node_role,
                role_desc
            );
            // Node starts successfully but skips consensus engine
            *self.status.write().await = ComponentStatus::Running;
            return Ok(());
        }

        info!("✓ Node role {:?} can validate - starting consensus engine", *self.node_role);
        
        let mut config = ConsensusConfig::default();
        
        config.development_mode = matches!(self.environment, crate::config::Environment::Development);
        if config.development_mode {
            info!("🔧 Development mode enabled - single validator consensus allowed for testing");
            info!("   Production deployment requires minimum 4 validators for BFT");
        } else {
            info!("🛡️ Production mode: Full consensus validation required (minimum 4 validators for BFT)");
        }

        let broadcaster = Arc::new(NoOpBroadcaster);
        let mut consensus_engine = lib_consensus::init_consensus(config, broadcaster)?;
        let (liveness_tx, mut liveness_rx) = tokio::sync::mpsc::unbounded_channel();
        consensus_engine.set_liveness_event_sender(liveness_tx);

        // **Start-order independent alert wiring**
        //
        // CRITICAL: Always spawn the alert receiver task, even if monitoring is not running yet.
        // This prevents the problem where:
        // 1. Consensus starts before monitoring
        // 2. No global manager exists → receiver task is not spawned
        // 3. Monitoring starts later
        // 4. Liveness events are dropped silently (no receiver to deliver them)
        //
        // Solution: Always create the receiver. At each event, resolve the manager:
        // - If monitoring is running: emit alert
        // - If not: drop alert and log at ERROR level (not WARN - these are critical events)
        //
        // This makes alert delivery robust to start order and monitoring restarts.
        tokio::spawn(async move {
            let mut dropped_events = Vec::new();
            let mut drop_warning_emitted = false;

            while let Some(event) = liveness_rx.recv().await {
                if let Some(alert_manager) = crate::monitoring::get_global_alert_manager() {
                    // Manager exists now - emit alert (works even if monitoring restarted)
                    // Also catch up on any previously dropped events
                    if !dropped_events.is_empty() {
                        error!(
                            "Consensus recovery: {} liveness events were dropped while monitoring was unavailable",
                            dropped_events.len()
                        );
                        dropped_events.clear();
                        drop_warning_emitted = false;
                    }

                    handle_liveness_event(&alert_manager, event).await;
                } else {
                    // CRITICAL: No manager - this is a Byzantine fault event that cannot be delivered
                    // Log at ERROR level because this is a consensus-critical failure
                    dropped_events.push(event.clone());

                    if !drop_warning_emitted {
                        error!(
                            "CRITICAL: Consensus liveness alert cannot be delivered - monitoring system not started. \
                             Byzantine faults occurring now will not be reported to operators."
                        );
                        drop_warning_emitted = true;
                    }
                }
            }
        });
        
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

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[tokio::test]
    async fn test_liveness_alert_bridge_stalled() {
        let alert_manager = AlertManager::new()
            .await
            .expect("Failed to create alert manager");
        alert_manager.start().await.expect("Failed to start alert manager");

        let event = ConsensusEvent::ConsensusStalled {
            height: 42,
            round: 7,
            timed_out_validators: vec![Hash::from_bytes(&[1u8; 32])],
            total_validators: 4,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        handle_liveness_event(&alert_manager, event).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let alerts = alert_manager
            .get_recent_alerts(1)
            .await
            .expect("Failed to fetch alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].title, "Consensus stalled");
        assert_eq!(alerts[0].level, AlertLevel::Critical);
    }
}
