// Protocols component - delegates to unified server and bootstrap service
// This file is a stub - full implementation to be extracted from components.rs

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use crate::runtime::services::BootstrapService;
use crate::runtime::components::identity::create_default_storage_config;
use lib_protocols::{ZdnsServer, ZhtpIntegration};

/// Protocols component - thin wrapper for unified server
pub struct ProtocolsComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    unified_server: Arc<RwLock<Option<crate::unified_server::ZhtpUnifiedServer>>>,
    zdns_server: Arc<RwLock<Option<ZdnsServer>>>,
    lib_integration: Arc<RwLock<Option<ZhtpIntegration>>>,
    environment: crate::config::environment::Environment,
    api_port: u16,
    is_edge_node: bool,
}

impl std::fmt::Debug for ProtocolsComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolsComponent")
            .field("status", &"<ComponentStatus>")
            .field("environment", &self.environment)
            .field("api_port", &self.api_port)
            .finish()
    }
}

impl ProtocolsComponent {
    pub fn new(environment: crate::config::environment::Environment, api_port: u16) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,
            api_port,
            is_edge_node: false,
        }
    }
    
    pub fn new_with_node_type(environment: crate::config::environment::Environment, api_port: u16, is_edge_node: bool) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,
            api_port,
            is_edge_node,
        }
    }
}

#[async_trait::async_trait]
impl Component for ProtocolsComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Protocols
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting protocols component with ZHTP Unified Server...");
        *self.status.write().await = ComponentStatus::Starting;
        
        lib_protocols::initialize().await?;
        
        info!("Initializing backend components for unified server...");
        
        // Use existing global blockchain (already initialized and syncing in Phase 2)
        info!(" Using existing global blockchain instance...");
        let blockchain = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(shared_blockchain) => {
                info!(" ✓ Global blockchain found - continuing with synced data");
                shared_blockchain
            }
            Err(_) => {
                info!("⏳ Waiting for BlockchainComponent...");
                let mut attempts = 0;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    attempts += 1;
                    if let Ok(shared_blockchain) = crate::runtime::blockchain_provider::get_global_blockchain().await {
                        info!(" ✓ Global blockchain initialized");
                        break shared_blockchain;
                    }
                    if attempts >= 60 {
                        return Err(anyhow::anyhow!("Timeout waiting for BlockchainComponent"));
                    }
                }
            }
        };
        
        // Get shared IdentityManager
        info!(" Getting shared IdentityManager...");
        let identity_manager = match crate::runtime::get_global_identity_manager().await {
            Ok(shared) => shared,
            Err(_) => {
                info!("⏳ Waiting for IdentityComponent...");
                let mut attempts = 0;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    attempts += 1;
                    if let Ok(shared) = crate::runtime::get_global_identity_manager().await {
                        break shared;
                    }
                    if attempts >= 60 {
                        return Err(anyhow::anyhow!("Timeout waiting for IdentityComponent"));
                    }
                }
            }
        };
        
        // Initialize economic model and storage
        let economic_model = Arc::new(RwLock::new(lib_economy::EconomicModel::new()));
        let storage_config = create_default_storage_config()?;
        let storage = Arc::new(RwLock::new(lib_storage::UnifiedStorageSystem::new(storage_config).await?));
        
        info!("Creating ZHTP Unified Server...");
        let (peer_discovery_tx, _peer_discovery_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        
        let mut unified_server = crate::unified_server::ZhtpUnifiedServer::new_with_peer_notification(
            blockchain.clone(),
            storage.clone(),
            identity_manager.clone(),
            economic_model.clone(),
            self.api_port,
            Some(peer_discovery_tx),
        ).await?;
        
        // Initialize blockchain provider
        info!(" Setting up blockchain provider...");
        let blockchain_provider = Arc::new(crate::runtime::network_blockchain_provider::ZhtpBlockchainProvider::new());
        unified_server.set_blockchain_provider(blockchain_provider).await;
        
        // Initialize edge sync manager if needed
        if self.is_edge_node {
            info!(" Initializing Edge Node sync manager...");
            let edge_sync_manager = Arc::new(lib_network::EdgeNodeSyncManager::new(500));
            unified_server.set_edge_sync_manager(edge_sync_manager.clone()).await;
        }
        
        // Initialize auth manager
        let mgr = identity_manager.read().await;
        let identities = mgr.list_identities();
        if !identities.is_empty() {
            let node_identity = if identities.len() >= 2 { &identities[1] } else { &identities[0] };
            let blockchain_pubkey = node_identity.public_key.clone();
            let _ = unified_server.initialize_auth_manager(blockchain_pubkey).await;
        }
        drop(mgr);
        
        // Initialize relay protocol
        let _ = unified_server.initialize_relay_protocol().await;
        
        // Initialize WiFi Direct auth
        let _ = unified_server.initialize_wifi_direct_auth(identity_manager.clone()).await;
        
        info!("Starting unified server on port {}...", self.api_port);
        unified_server.start().await?;
        
        // Connect to bootstrap peers if configured
        let bootstrap_peers = crate::runtime::bootstrap_peers_provider::get_bootstrap_peers().await;
        if let Some(peers) = bootstrap_peers {
            if !peers.is_empty() {
                info!("Connecting to bootstrap peers via QUIC...");
                if let Err(e) = unified_server.connect_to_bootstrap_peers(peers).await {
                    warn!("Failed to connect to some bootstrap peers: {}", e);
                }
            }
        }
        
        *self.unified_server.write().await = Some(unified_server);
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Protocols component started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping protocols component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        if let Some(mut server) = self.unified_server.write().await.take() {
            let _ = server.stop().await;
        }
        
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
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
                debug!("Protocols component health check");
                Ok(())
            }
            _ => {
                debug!("Protocols component received message: {:?}", message);
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
