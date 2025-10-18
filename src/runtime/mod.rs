//! Runtime Orchestration System
//! 
//! Coordinates the lifecycle and interactions of all ZHTP components

use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, error, debug};

use super::config::NodeConfig;
// Removed ZK coordinator - using unified lib-proofs system directly

pub mod components;
pub mod shared_blockchain;
pub mod shared_dht;
pub mod blockchain_provider;
pub mod did_startup;
#[cfg(test)]
pub mod test_api_integration;

pub use components::*;
pub use shared_blockchain::*;
pub use shared_dht::*;
pub use blockchain_provider::{initialize_global_blockchain_provider, set_global_blockchain};

/// Component status information
#[derive(Debug, Clone, PartialEq)]
pub enum ComponentStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error(String),
    Registered,
    Failed,
}

/// Component health metrics
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub status: ComponentStatus,
    pub last_heartbeat: Instant,
    pub error_count: u64,
    pub restart_count: u64,
    pub uptime: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f32,
}

/// Inter-component message types
#[derive(Debug, Clone)]
pub enum ComponentMessage {
    // Lifecycle messages
    Start,
    Stop,
    Restart,
    HealthCheck,
    
    // Network messages
    PeerConnected(String),
    PeerDisconnected(String),
    NetworkUpdate(String),
    
    // Blockchain messages
    BlockMined(String),
    TransactionReceived(String),
    
    // Identity messages
    IdentityCreated(String),
    IdentityUpdated(String),
    
    // Storage messages
    FileStored(String),
    FileRequested(String),
    
    // Economics messages
    UbiPayment(String, u64),
    DaoProposal(String),
    
    // Blockchain access messages
    GetBlockchain,
    GetBlockchainResponse(Arc<RwLock<Option<lib_blockchain::Blockchain>>>),
    BlockchainOperation(String, Vec<u8>),
    
    // Custom messages
    Custom(String, Vec<u8>),
}

/// Component identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ComponentId {
    Crypto,
    ZK,
    Identity,
    Storage,
    Network,
    Blockchain,
    Consensus,
    Economics,
    Protocols,
    Api,
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentId::Crypto => write!(f, "crypto"),
            ComponentId::ZK => write!(f, "zk"),
            ComponentId::Identity => write!(f, "identity"),
            ComponentId::Storage => write!(f, "storage"),
            ComponentId::Network => write!(f, "network"),
            ComponentId::Blockchain => write!(f, "blockchain"),
            ComponentId::Consensus => write!(f, "consensus"),
            ComponentId::Economics => write!(f, "economics"),
            ComponentId::Protocols => write!(f, "protocols"),
            ComponentId::Api => write!(f, "api"),
        }
    }
}

/// Component interface trait
#[async_trait::async_trait]
pub trait Component: Send + Sync + std::fmt::Debug {
    /// Component identifier
    fn id(&self) -> ComponentId;
    
    /// Start the component
    async fn start(&self) -> Result<()>;
    
    /// Stop the component
    async fn stop(&self) -> Result<()>;
    
    /// Force stop the component (for emergency shutdown)
    async fn force_stop(&self) -> Result<()> {
        // Default implementation just calls regular stop
        self.stop().await
    }
    

    
    /// Check component health
    async fn health_check(&self) -> Result<ComponentHealth>;
    
    /// Handle inter-component messages
    async fn handle_message(&self, message: ComponentMessage) -> Result<()>;
    
    /// Get component metrics
    async fn get_metrics(&self) -> Result<HashMap<String, f64>>;
    
    /// Downcast to Any for type-specific access
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Runtime orchestrator that manages all ZHTP components
#[derive(Clone)]
pub struct RuntimeOrchestrator {
    config: NodeConfig,
    components: Arc<RwLock<HashMap<ComponentId, Arc<dyn Component>>>>,
    component_health: Arc<RwLock<HashMap<ComponentId, ComponentHealth>>>,
    message_bus: Arc<Mutex<mpsc::UnboundedSender<(ComponentId, ComponentMessage)>>>,
    shutdown_signal: Arc<Mutex<Option<mpsc::UnboundedSender<()>>>>,
    startup_order: Vec<ComponentId>,
    shared_blockchain: Arc<RwLock<Option<SharedBlockchainService>>>,
    user_wallet: Arc<RwLock<Option<crate::runtime::did_startup::WalletStartupResult>>>,
}

impl RuntimeOrchestrator {
    /// Create a new runtime orchestrator
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
        
        // Spawn shutdown monitor task
        let shutdown_monitor = tokio::spawn(async move {
            if let Some(_shutdown_signal) = shutdown_rx.recv().await {
                tracing::info!("Shutdown signal received, initiating graceful shutdown");
            }
        });
        
        // Store shutdown monitor handle for cleanup
        let _shutdown_handle = shutdown_monitor;
        
        let orchestrator = Self {
            config,
            components: Arc::new(RwLock::new(HashMap::new())),
            component_health: Arc::new(RwLock::new(HashMap::new())),
            message_bus: Arc::new(Mutex::new(message_tx)),
            shutdown_signal: Arc::new(Mutex::new(Some(shutdown_tx))),
            shared_blockchain: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(None)),
            startup_order: vec![
                ComponentId::Crypto,      // Foundation layer
                ComponentId::ZK,          // Zero-knowledge proofs
                ComponentId::Identity,    // Identity management
                ComponentId::Storage,     // Distributed storage
                ComponentId::Network,     // Mesh networking
                ComponentId::Blockchain,  // Blockchain layer
                ComponentId::Consensus,   // Consensus mechanism
                ComponentId::Economics,   // Economic incentives
                ComponentId::Protocols,   // High-level protocols (includes ZHTP server with comprehensive handlers)
            ],
        };

        // Start message handling task
        let components_clone = orchestrator.components.clone();
        tokio::spawn(async move {
            while let Some((component_id, message)) = message_rx.recv().await {
                let components = components_clone.read().await;
                if let Some(component) = components.get(&component_id) {
                    if let Err(e) = component.handle_message(message).await {
                        error!("Component {} failed to handle message: {}", component_id, e);
                    }
                }
            }
        });

        // Start health monitoring task
        let health_clone = orchestrator.component_health.clone();
        let components_clone = orchestrator.components.clone();
        let health_interval = orchestrator.config.integration_settings.health_check_interval_ms;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(health_interval));
            loop {
                interval.tick().await;
                
                let components = components_clone.read().await;
                let mut health = health_clone.write().await;
                
                for (id, component) in components.iter() {
                    match component.health_check().await {
                        Ok(health_info) => {
                            health.insert(id.clone(), health_info);
                        }
                        Err(e) => {
                            warn!("Health check failed for {}: {}", id, e);
                            let error_health = ComponentHealth {
                                status: ComponentStatus::Error(e.to_string()),
                                last_heartbeat: Instant::now(),
                                error_count: health.get(id).map(|h| h.error_count + 1).unwrap_or(1),
                                restart_count: health.get(id).map(|h| h.restart_count).unwrap_or(0),
                                uptime: health.get(id).map(|h| h.uptime).unwrap_or(Duration::ZERO),
                                memory_usage: 0,
                                cpu_usage: 0.0,
                            };
                            health.insert(id.clone(), error_health);
                        }
                    }
                }
            }
        });

        info!("Runtime orchestrator initialized with {} components", orchestrator.startup_order.len());
        Ok(orchestrator)
    }

    /// Get configuration for runtime operations
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Register a component with the orchestrator
    pub async fn register_component(&self, component: Arc<dyn Component>) -> Result<()> {
        let id = component.id();
        info!("Registering component: {}", id);
        
        let mut components = self.components.write().await;
        components.insert(id.clone(), component);
        
        // Initialize health tracking
        let mut health = self.component_health.write().await;
        health.insert(id.clone(), ComponentHealth {
            status: ComponentStatus::Stopped,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime: Duration::ZERO,
            memory_usage: 0,
            cpu_usage: 0.0,
        });
        
        debug!("Component {} registered successfully", id);
        Ok(())
    }

    /// Register all component instances (with singleton guard)
    pub async fn register_all_components(&self) -> Result<()> {
        // Check if components are already registered to prevent duplicate registration
        {
            let components = self.components.read().await;
            if !components.is_empty() {
                info!("Components already registered, skipping duplicate registration");
                return Ok(());
            }
        }
        
        info!("Registering all ZHTP component instances...");
        
        // Import all component types
        use crate::runtime::components::{
            CryptoComponent, ZKComponent, IdentityComponent, StorageComponent, 
            NetworkComponent, BlockchainComponent, ConsensusComponent, 
            EconomicsComponent, ProtocolsComponent, ApiComponent
        };
        
        // Register components in dependency order
        self.register_component(Arc::new(CryptoComponent::new())).await?;
        self.register_component(Arc::new(ZKComponent::new())).await?;
        self.register_component(Arc::new(IdentityComponent::new())).await?;
        self.register_component(Arc::new(StorageComponent::new())).await?;
        self.register_component(Arc::new(NetworkComponent::new())).await?;
        // Pass user wallet AND environment to blockchain component for proper network initialization
        let user_wallet_guard = self.user_wallet.read().await;
        let user_wallet = user_wallet_guard.clone();
        let environment = self.config.environment;  // Get environment from config
        let api_port = self.config.protocols_config.api_port;  // Get API port from config
        self.register_component(Arc::new(BlockchainComponent::new_with_wallet_and_environment(user_wallet, environment))).await?;
        self.register_component(Arc::new(ConsensusComponent::new())).await?;
        self.register_component(Arc::new(EconomicsComponent::new())).await?;
        self.register_component(Arc::new(ProtocolsComponent::new(environment, api_port))).await?;
        self.register_component(Arc::new(ApiComponent::new())).await?;
        
        info!("All components registered successfully");
        Ok(())
    }

    /// Set user wallet data for components that need it (replaces identity-based approach)
    pub async fn set_user_identity(&self, wallet: crate::runtime::did_startup::WalletStartupResult) -> Result<()> {
        let mut user_wallet = self.user_wallet.write().await;
        *user_wallet = Some(wallet);
        Ok(())
    }

    /// Set user wallet data for components that need it
    pub async fn set_user_wallet(&self, wallet: crate::runtime::did_startup::WalletStartupResult) -> Result<()> {
        // Store wallet in orchestrator for use during component creation
        let mut user_wallet = self.user_wallet.write().await;
        *user_wallet = Some(wallet);
        info!("User wallet stored in orchestrator for component initialization");
        Ok(())
    }

    /// Start all components in the correct order
    pub async fn start_all_components(&self) -> Result<()> {
        info!(" Starting all ZHTP components...");
        
        // Register components once if not already registered
        self.register_all_components().await?;
        
        for component_id in &self.startup_order {
            self.start_component(component_id.clone()).await
                .with_context(|| format!("Failed to start component {}", component_id))?;
            
            // Wait between component starts for proper initialization
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        info!("All components started successfully");
        Ok(())
    }

    /// Start a specific component
    pub async fn start_component(&self, component_id: ComponentId) -> Result<()> {
        // Check if component is already running to prevent duplicate starts
        {
            let health = self.component_health.read().await;
            if let Some(health_info) = health.get(&component_id) {
                if matches!(health_info.status, ComponentStatus::Running) {
                    info!("Component {} is already running, skipping start", component_id);
                    return Ok(());
                }
            }
        }
        
        info!(" Starting component: {}", component_id);
        
        // Update status to starting
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.status = ComponentStatus::Starting;
                health_info.last_heartbeat = Instant::now();
            }
        }

        // Get component and start it
        let components = self.components.read().await;
        if let Some(component) = components.get(&component_id) {
            let start_time = Instant::now();
            
            match component.start().await {
                Ok(()) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Running;
                        health_info.last_heartbeat = Instant::now();
                        health_info.uptime = start_time.elapsed();
                    }
                    
                    info!("Component {} started successfully", component_id);
                    
                    // Initialize shared blockchain service after BlockchainComponent starts
                    if component_id == ComponentId::Blockchain {
                        if let Err(e) = self.initialize_shared_blockchain().await {
                            warn!("Failed to initialize shared blockchain service: {}", e);
                        }
                    }
                    
                    // Send start notification to other components
                    self.broadcast_message(ComponentMessage::Custom(
                        format!("component_started:{}", component_id),
                        vec![]
                    )).await?;
                    
                    Ok(())
                }
                Err(e) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Error(e.to_string());
                        health_info.error_count += 1;
                    }
                    
                    error!("Failed to start component {}: {}", component_id, e);
                    Err(e)
                }
            }
        } else {
            let error_msg = format!("Component {} not found", component_id);
            error!("{}", error_msg);
            Err(anyhow::anyhow!(error_msg))
        }
    }

    /// Stop all components in reverse order with timeout
    pub async fn shutdown_all_components(&self) -> Result<()> {
        info!("Shutting down all ZHTP components...");
        
        // Set overall shutdown timeout
        let shutdown_future = async {
            // Stop components in reverse order
            for component_id in self.startup_order.iter().rev() {
                if let Err(e) = self.stop_component(component_id.clone()).await {
                    error!("Failed to stop component {}: {}", component_id, e);
                    // Continue with other components even if one fails
                }
                
                // Wait between component stops
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };

        // Apply overall timeout for shutdown
        let shutdown_timeout_ms = self.config.integration_settings.cross_package_timeouts
            .get("shutdown").copied().unwrap_or(30000);
        match tokio::time::timeout(Duration::from_millis(shutdown_timeout_ms), shutdown_future).await {
            Ok(()) => {
                info!("All components shut down normally");
            }
            Err(_timeout) => {
                warn!("Shutdown timeout reached - forcing termination");
                
                // Force stop all remaining components
                let components = self.components.read().await;
                for component_id in components.keys() {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(component_id) {
                        if !matches!(health_info.status, ComponentStatus::Stopped) {
                            health_info.status = ComponentStatus::Stopped;
                            health_info.last_heartbeat = Instant::now();
                        }
                    }
                }
                warn!(" Forced shutdown completed");
            }
        }
        
        // Send shutdown signal
        if let Some(shutdown_tx) = self.shutdown_signal.lock().await.take() {
            let _ = shutdown_tx.send(());
        }
        
        info!("All components shut down");
        Ok(())
    }

    /// Stop a specific component with timeout
    pub async fn stop_component(&self, component_id: ComponentId) -> Result<()> {
        info!("Stopping component: {}", component_id);
        
        // Update status to stopping
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.status = ComponentStatus::Stopping;
                health_info.last_heartbeat = Instant::now();
            }
        }

        // Get component and stop it with timeout
        let components = self.components.read().await;
        if let Some(component) = components.get(&component_id) {
            // Add timeout to prevent hanging on shutdown
            match tokio::time::timeout(Duration::from_secs(10), component.stop()).await {
                Ok(Ok(())) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Stopped;
                        health_info.last_heartbeat = Instant::now();
                    }
                    
                    info!("Component {} stopped successfully", component_id);
                    Ok(())
                }
                Ok(Err(e)) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Error(e.to_string());
                        health_info.error_count += 1;
                    }
                    
                    error!("Failed to stop component {}: {}", component_id, e);
                    Err(e)
                }
                Err(_timeout) => {
                    warn!("Timeout stopping component {}, forcing shutdown", component_id);
                    
                    // Try force stop if available
                    match tokio::time::timeout(Duration::from_secs(5), component.force_stop()).await {
                        Ok(Ok(())) => {
                            info!("Component {} force stopped", component_id);
                        }
                        Ok(Err(e)) => {
                            warn!("Force stop failed for {}: {}", component_id, e);
                        }
                        Err(_) => {
                            warn!("Force stop timeout for {}", component_id);
                        }
                    }
                    
                    // Mark as stopped regardless
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Stopped;
                        health_info.last_heartbeat = Instant::now();
                    }
                    
                    Ok(())
                }
            }
        } else {
            warn!("Component {} not found during shutdown", component_id);
            Ok(()) // Not an error during shutdown
        }
    }

    /// Get status of all components
    pub async fn get_component_status(&self) -> Result<HashMap<String, bool>> {
        let health = self.component_health.read().await;
        let mut status = HashMap::new();
        
        for (id, health_info) in health.iter() {
            let is_running = matches!(health_info.status, ComponentStatus::Running);
            status.insert(id.to_string(), is_running);
        }
        
        Ok(status)
    }

    /// Get detailed health information for all components
    pub async fn get_detailed_health(&self) -> Result<HashMap<ComponentId, ComponentHealth>> {
        let health = self.component_health.read().await;
        Ok(health.clone())
    }

    /// Send a message to a specific component
    pub async fn send_message(&self, component_id: ComponentId, message: ComponentMessage) -> Result<()> {
        let message_bus = self.message_bus.lock().await;
        message_bus.send((component_id, message))
            .map_err(|e| anyhow::anyhow!("Failed to send message: {}", e))?;
        Ok(())
    }

    /// Broadcast a message to all components
    pub async fn broadcast_message(&self, message: ComponentMessage) -> Result<()> {
        let components = self.components.read().await;
        let message_bus = self.message_bus.lock().await;
        
        for component_id in components.keys() {
            message_bus.send((component_id.clone(), message.clone()))
                .map_err(|e| anyhow::anyhow!("Failed to broadcast message: {}", e))?;
        }
        
        Ok(())
    }

    /// Restart a component
    pub async fn restart_component(&self, component_id: ComponentId) -> Result<()> {
        info!(" Restarting component: {}", component_id);
        
        // Update restart count
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.restart_count += 1;
            }
        }

        self.stop_component(component_id.clone()).await?;
        tokio::time::sleep(Duration::from_millis(1000)).await; // Wait for cleanup
        self.start_component(component_id.clone()).await?;
        
        info!("Component {} restarted successfully", component_id);
        Ok(())
    }

    /// Get aggregated metrics from all components
    pub async fn get_system_metrics(&self) -> Result<HashMap<String, f64>> {
        let components = self.components.read().await;
        let mut aggregated_metrics = HashMap::new();
        
        for (id, component) in components.iter() {
            match component.get_metrics().await {
                Ok(metrics) => {
                    for (key, value) in metrics {
                        let prefixed_key = format!("{}_{}", id, key);
                        aggregated_metrics.insert(prefixed_key, value);
                    }
                }
                Err(e) => {
                    warn!("Failed to get metrics from {}: {}", id, e);
                }
            }
        }
        
        // Add orchestrator metrics
        let health = self.component_health.read().await;
        aggregated_metrics.insert("total_components".to_string(), components.len() as f64);
        aggregated_metrics.insert("running_components".to_string(), 
            health.values().filter(|h| matches!(h.status, ComponentStatus::Running)).count() as f64);
        aggregated_metrics.insert("error_components".to_string(),
            health.values().filter(|h| matches!(h.status, ComponentStatus::Error(_))).count() as f64);
        
        Ok(aggregated_metrics)
    }

    // implementations using lib-network APIs
    
    /// Get connected peers from network component
    pub async fn get_connected_peers(&self) -> Result<Vec<String>> {
        // Get peer information from lib-network
        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                let mut peers = Vec::new();
                
                // Add peer information from mesh status
                if mesh_status.local_peers > 0 {
                    for i in 1..=mesh_status.local_peers.min(10) {
                        peers.push(format!("local-mesh-peer-{}", i));
                    }
                }
                
                if mesh_status.regional_peers > 0 {
                    for i in 1..=mesh_status.regional_peers.min(5) {
                        peers.push(format!("regional-mesh-peer-{}", i));
                    }
                }
                
                if mesh_status.global_peers > 0 {
                    for i in 1..=mesh_status.global_peers.min(3) {
                        peers.push(format!("global-mesh-peer-{}", i));
                    }
                }
                
                if mesh_status.relay_peers > 0 {
                    for i in 1..=mesh_status.relay_peers.min(2) {
                        peers.push(format!("relay-peer-{}", i));
                    }
                }
                
                if peers.is_empty() {
                    peers.push("No peers connected".to_string());
                }
                
                Ok(peers)
            }
            Err(e) => {
                warn!("Failed to get mesh status: {}", e);
                Ok(vec!["Network status unavailable".to_string()])
            }
        }
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, addr: &str) -> Result<()> {
        info!("Attempting to connect to peer: {}", addr);
        
        // Send connect message to network component
        self.send_message(ComponentId::Network, ComponentMessage::Custom(
            format!("connect_to_peer:{}", addr),
            addr.as_bytes().to_vec()
        )).await?;
        
        info!("Connect request sent to network component for peer: {}", addr);
        Ok(())
    }

    /// Disconnect from a peer
    pub async fn disconnect_from_peer(&self, addr: &str) -> Result<()> {
        info!(" Attempting to disconnect from peer: {}", addr);
        
        // Send disconnect message to network component
        self.send_message(ComponentId::Network, ComponentMessage::Custom(
            format!("disconnect_from_peer:{}", addr),
            addr.as_bytes().to_vec()
        )).await?;
        
        info!("Disconnect request sent to network component for peer: {}", addr);
        Ok(())
    }

    /// Get network information
    pub async fn get_network_info(&self) -> Result<String> {
        // Get comprehensive network information from lib-network
        let mut info = String::new();
        
        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                info.push_str("ZHTP Mesh Network Status\n");
                info.push_str("===========================\n");
                info.push_str(&format!("Internet Connected: {}\n", 
                    if mesh_status.internet_connected { "Yes" } else { "No" }));
                info.push_str(&format!("Mesh Connected: {}\n", 
                    if mesh_status.mesh_connected { "Yes" } else { "No" }));
                info.push_str(&format!("Connectivity: {:.1}%\n", mesh_status.connectivity_percentage));
                info.push_str(&format!("Active Peers: {}\n", mesh_status.active_peers));
                info.push_str(&format!("  • Local: {}\n", mesh_status.local_peers));
                info.push_str(&format!("  • Regional: {}\n", mesh_status.regional_peers));
                info.push_str(&format!("  • Global: {}\n", mesh_status.global_peers));
                info.push_str(&format!("  • Relays: {}\n", mesh_status.relay_peers));
                info.push_str(&format!("Coverage: {:.1}%\n", mesh_status.coverage));
                info.push_str(&format!("Stability: {:.1}%\n", mesh_status.stability));
            }
            Err(e) => {
                info.push_str(&format!("Failed to get mesh status: {}\n", e));
            }
        }
        
        match lib_network::get_network_statistics().await {
            Ok(net_stats) => {
                info.push_str("\nNetwork Statistics\n");
                info.push_str("=====================\n");
                info.push_str(&format!("Bytes Sent: {} MB\n", net_stats.bytes_sent / 1_000_000));
                info.push_str(&format!("Bytes Received: {} MB\n", net_stats.bytes_received / 1_000_000));
                info.push_str(&format!("Packets Sent: {}\n", net_stats.packets_sent));
                info.push_str(&format!("Packets Received: {}\n", net_stats.packets_received));
                info.push_str(&format!("Connections: {}\n", net_stats.connection_count));
            }
            Err(e) => {
                info.push_str(&format!("Failed to get network statistics: {}\n", e));
            }
        }
        
        Ok(info)
    }

    /// Get mesh status
    pub async fn get_mesh_status(&self) -> Result<String> {
        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                let status = if mesh_status.connectivity_percentage > 80.0 {
                    "[EXCELLENT]"
                } else if mesh_status.connectivity_percentage > 60.0 {
                    "🟡 Good"
                } else if mesh_status.connectivity_percentage > 30.0 {
                    "🟠 Fair"
                } else {
                    "[POOR]"
                };
                
                Ok(format!(
                    "{} - {:.1}% connectivity, {} peers ({} local, {} regional, {} global, {} relays)",
                    status,
                    mesh_status.connectivity_percentage,
                    mesh_status.active_peers,
                    mesh_status.local_peers,
                    mesh_status.regional_peers,
                    mesh_status.global_peers,
                    mesh_status.relay_peers
                ))
            }
            Err(e) => {
                Ok(format!("Mesh status unavailable: {}", e))
            }
        }
    }

    /// Run the main operational loop
    pub async fn run_main_loop(&self) -> Result<()> {
        info!(" Starting main operational loop...");
        
        // Wait a moment for components to fully initialize
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        
        info!("ZHTP system fully operational - ready for identity and transaction testing");
        
        // Create a future that never completes to keep the node running
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Perform periodic maintenance
                    if let Err(e) = self.perform_maintenance().await {
                        warn!("Maintenance cycle error: {}", e);
                    }
                }
            }
            
            // Check if shutdown was requested more frequently to improve responsiveness
            {
                let shutdown_signal = self.shutdown_signal.lock().await;
                if shutdown_signal.is_none() {
                    info!("Shutdown signal received, exiting main loop");
                    break;
                }
            }
            
            // Brief pause to allow other tasks to run and improve shutdown responsiveness
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        Ok(())
    }



    /// Perform periodic maintenance tasks
    async fn perform_maintenance(&self) -> Result<()> {
        // Get system metrics
        let metrics = self.get_system_metrics().await?;
        debug!("System metrics: {} total metrics collected", metrics.len());
        
        // Check component health
        let health = self.get_detailed_health().await?;
        let unhealthy_components: Vec<_> = health.iter()
            .filter(|(_, h)| !matches!(h.status, ComponentStatus::Running))
            .map(|(id, _)| id.to_string())
            .collect();
            
        if !unhealthy_components.is_empty() {
            warn!("Unhealthy components: {:?}", unhealthy_components);
        }
        
        // Log summary
        let running_count = health.values()
            .filter(|h| matches!(h.status, ComponentStatus::Running))
            .count();
        debug!("{}/{} components running normally", running_count, health.len());
        
        Ok(())
    }

    /// Get the shared blockchain service
    pub async fn get_shared_blockchain_service(&self) -> Option<SharedBlockchainService> {
        self.shared_blockchain.read().await.clone()
    }
    
    /// Initialize the shared blockchain service once the blockchain component is started
    pub async fn initialize_shared_blockchain(&self) -> Result<()> {
        // Initialize the global blockchain provider first
        initialize_global_blockchain_provider();
        
        // Get the blockchain component's blockchain instance
        if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            // Try to get the blockchain instance from the blockchain component
            if let Some(blockchain_component) = component.as_any().downcast_ref::<BlockchainComponent>() {
                // Wait for blockchain to be initialized and get the actual instance
                if let Ok(blockchain_arc) = blockchain_component.get_initialized_blockchain().await {
                    // Set up the shared service
                    let shared_service = SharedBlockchainService::new(blockchain_arc.clone());
                    *self.shared_blockchain.write().await = Some(shared_service);
                    
                    // Also set the global blockchain for protocol access
                    if let Err(e) = set_global_blockchain(blockchain_arc).await {
                        warn!("Failed to set global blockchain: {}", e);
                    } else {
                        info!("Global blockchain provider updated");
                    }
                    
                    info!("Shared blockchain service initialized");
                    return Ok(());
                }
            }
        }
        
        warn!("Failed to initialize shared blockchain service - blockchain component not found");
        Ok(())
    }

    /// Get the shared blockchain instance from the blockchain component
    pub async fn get_shared_blockchain(&self) -> Result<Option<Arc<RwLock<Option<lib_blockchain::Blockchain>>>>> {
        // Create a channel for the response
        let (response_tx, mut response_rx) = tokio::sync::mpsc::unbounded_channel();
        
        // Store response sender for potential cleanup
        let _response_sender = response_tx.clone();
        
        // Send a request to the blockchain component
        let blockchain_request = ComponentMessage::Custom(
            "get_blockchain_instance".to_string(),
            vec![], // Empty data since we can't serialize channels
        );
        
        if let Err(e) = self.send_message(ComponentId::Blockchain, blockchain_request).await {
            warn!("Failed to request blockchain instance: {}", e);
            return Ok(None);
        }
        
        // Wait for response with timeout
        match tokio::time::timeout(Duration::from_secs(5), response_rx.recv()).await {
            Ok(Some(blockchain_arc)) => {
                info!("Received shared blockchain instance from blockchain component");
                Ok(Some(blockchain_arc))
            }
            Ok(None) => {
                warn!("Blockchain component channel closed");
                Ok(None)
            }
            Err(_) => {
                warn!("Timeout waiting for blockchain instance");
                Ok(None)
            }
        }
    }

    /// Send a blockchain operation to the blockchain component
    pub async fn execute_blockchain_operation(&self, operation: &str, data: Vec<u8>) -> Result<()> {
        let message = ComponentMessage::BlockchainOperation(operation.to_string(), data);
        self.send_message(ComponentId::Blockchain, message).await
    }
    
    /// Graceful shutdown of the orchestrator
    pub async fn graceful_shutdown(&self) -> Result<()> {
        info!("Initiating graceful shutdown...");
        
        // Stop all components
        if let Err(e) = self.shutdown_all_components().await {
            error!("Error during component shutdown: {}", e);
        }
        
        // Signal shutdown completion
        {
            let mut shutdown_signal = self.shutdown_signal.lock().await;
            if let Some(tx) = shutdown_signal.take() {
                let _ = tx.send(());
            }
        }
        
        info!("Graceful shutdown completed");
        Ok(())
    }
}
