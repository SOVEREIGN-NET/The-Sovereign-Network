//! Integration Layer for ZHTP Components
//!
//! Provides integration patterns and orchestration for all ZHTP packages

pub mod service_container;
pub mod event_bus;
pub mod component_manager;
pub mod dependency_injection;
pub mod dht_dispatcher;
pub mod dht_integration;

use anyhow::{Result, Context};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{info, warn, debug};

pub use service_container::*;
pub use event_bus::*;
pub use component_manager::*;
pub use dependency_injection::*;
pub use dht_dispatcher::*;
pub use dht_integration::*;

use crate::runtime::{ComponentId, Component};

/// Integration manager for coordinating all ZHTP components
pub struct IntegrationManager {
    service_container: Arc<ServiceContainer>,
    event_bus: Arc<EventBus>,
    component_manager: Arc<ComponentManager>,
    dependency_injector: Arc<DependencyInjector>,
}

impl IntegrationManager {
    /// Create a new integration manager
    pub async fn new() -> Result<Self> {
        let service_container = Arc::new(ServiceContainer::new().await?);
        let event_bus = Arc::new(EventBus::new().await?);
        let component_manager = Arc::new(ComponentManager::new().await?);
        let dependency_injector = Arc::new(DependencyInjector::new().await?);

        Ok(Self {
            service_container,
            event_bus,
            component_manager,
            dependency_injector,
        })
    }

    /// Initialize the integration layer
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing ZHTP integration layer...");

        // Start event bus
        self.event_bus.start().await?;

        // Configure dependency injection
        self.setup_dependency_injection().await?;

        // Initialize service container
        self.service_container.initialize().await?;

        // Setup component manager
        self.component_manager.initialize().await?;

        // Setup event handlers
        self.setup_event_handlers().await?;

        info!("ZHTP integration layer initialized");
        Ok(())
    }

    /// Shutdown the integration layer
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down ZHTP integration layer...");

        // Shutdown components in reverse order
        self.component_manager.shutdown_all().await?;
        self.service_container.shutdown().await?;
        self.event_bus.stop().await?;

        info!("ZHTP integration layer shut down");
        Ok(())
    }

    /// Get the service container
    pub fn service_container(&self) -> Arc<ServiceContainer> {
        self.service_container.clone()
    }

    /// Get the event bus
    pub fn event_bus(&self) -> Arc<EventBus> {
        self.event_bus.clone()
    }

    /// Get the component manager
    pub fn component_manager(&self) -> Arc<ComponentManager> {
        self.component_manager.clone()
    }

    /// Setup dependency injection
    async fn setup_dependency_injection(&self) -> Result<()> {
        // Register core services
        self.dependency_injector.register_singleton::<ServiceContainer>(
            self.service_container.clone()
        ).await?;

        self.dependency_injector.register_singleton::<EventBus>(
            self.event_bus.clone()
        ).await?;

        self.dependency_injector.register_singleton::<ComponentManager>(
            self.component_manager.clone()
        ).await?;

        info!("Dependency injection configured");
        Ok(())
    }

    /// Setup event handlers for component communication
    async fn setup_event_handlers(&self) -> Result<()> {
        // Setup inter-component event handlers
        self.setup_crypto_events().await?;
        self.setup_network_events().await?;
        self.setup_blockchain_events().await?;
        self.setup_storage_events().await?;
        self.setup_identity_events().await?;
        self.setup_economics_events().await?;
        self.setup_consensus_events().await?;

        info!("Event handlers configured");
        Ok(())
    }

    /// Setup crypto component events
    async fn setup_crypto_events(&self) -> Result<()> {
        // Key generation events
        self.event_bus.subscribe("crypto.key_generated", Box::new(|event| {
            let future = async move {
                info!("New cryptographic key generated: {:?}", event);
                // Notify identity system
                // Notify storage system for backup
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        // Encryption/decryption events
        self.event_bus.subscribe("crypto.data_encrypted", Box::new(|event| {
            let future = async move {
                info!("Data encrypted: {:?}", event);
                // Update metrics
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        Ok(())
    }

    /// Setup network component events
    async fn setup_network_events(&self) -> Result<()> {
        // Peer connection events
        self.event_bus.subscribe("network.peer_connected", Box::new(|event| {
            let future = async move {
                info!("Peer connected: {:?}", event);
                // Notify consensus system
                // Update routing tables
                // Trigger sync if needed
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        self.event_bus.subscribe("network.peer_disconnected", Box::new(|event| {
            let future = async move {
                warn!("Peer disconnected: {:?}", event);
                // Update routing tables
                // Check connectivity health
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        // Message events
        self.event_bus.subscribe("network.message_received", Box::new(|event: crate::integration::event_bus::Event| {
            let future = async move {
                // Route messages to appropriate components based on message type
                if let Some(message_type) = event.data.get("type").and_then(|v| v.as_str()) {
                    match message_type {
                        "blockchain_transaction" => {
                            debug!("Routing blockchain transaction from {}", event.source);
                            // TODO: Route to blockchain handler
                        }
                        "dht_query" => {
                            debug!("Routing DHT query from {}", event.source);
                            // TODO: Route to DHT handler  
                        }
                        "mesh_message" => {
                            debug!("Routing mesh message from {}", event.source);
                            // TODO: Route to mesh handler
                        }
                        _ => {
                            debug!("Unknown message type '{}' from {}", message_type, event.source);
                        }
                    }
                } else {
                    warn!("Message received without type field from {}", event.source);
                }
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        Ok(())
    }

    /// Setup blockchain component events
    async fn setup_blockchain_events(&self) -> Result<()> {
        // Block events
        self.event_bus.subscribe("blockchain.block_mined", Box::new(|event| {
            let future = async move {
                info!("Block mined: {:?}", event);
                // Notify network for propagation
                // Update storage
                // Trigger UBI distribution
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        // Transaction events
        self.event_bus.subscribe("blockchain.transaction_received", Box::new(|event| {
            let future = async move {
                info!(" Transaction received: {:?}", event);
                // Validate with identity system
                // Add to mempool
                // Notify relevant parties
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        Ok(())
    }

    /// Setup storage component events
    async fn setup_storage_events(&self) -> Result<()> {
        // File storage events
        self.event_bus.subscribe("storage.file_stored", Box::new(|event| {
            let future = async move {
                info!("File stored: {:?}", event);
                // Update blockchain record
                // Notify network of availability
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        self.event_bus.subscribe("storage.file_requested", Box::new(|event| {
            let future = async move {
                info!("File requested: {:?}", event);
                // Check permissions with identity system
                // Log access for economics
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        Ok(())
    }

    /// Setup identity component events
    async fn setup_identity_events(&self) -> Result<()> {
        // Identity creation events
        self.event_bus.subscribe("identity.identity_created", Box::new(|event| {
            let future = async move {
                info!("Identity created: {:?}", event);
                // Register in blockchain
                // Setup UBI eligibility
                // Generate crypto keys
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        // Authentication events
        self.event_bus.subscribe("identity.authentication_success", Box::new(|event| {
            let future = async move {
                info!("Authentication successful: {:?}", event);
                // Log access
                // Update session
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        })).await?;

        Ok(())
    }

    /// Setup economics component events
    async fn setup_economics_events(&self) -> Result<()> {
        // UBI events
        self.event_bus.subscribe("economics.ubi_distributed", Box::new(|event| {
            let future = async move {
                info!("UBI distributed: {:?}", event);
                // Record transaction
                // Update citizen status
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn futures::Future<Output = Result<()>> + Send>>
        })).await?;

        // DAO events
        self.event_bus.subscribe("economics.proposal_created", Box::new(|event| {
            let future = async move {
                info!("DAO proposal created: {:?}", event);
                // Notify all citizens
                // Schedule voting period
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn futures::Future<Output = Result<()>> + Send>>
        })).await?;

        Ok(())
    }

    /// Setup consensus component events
    async fn setup_consensus_events(&self) -> Result<()> {
        // Consensus events
        self.event_bus.subscribe("consensus.round_started", Box::new(|event| {
            let future = async move {
                info!("Consensus round started: {:?}", event);
                // Notify validators
                // Prepare proposals
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn futures::Future<Output = Result<()>> + Send>>
        })).await?;

        self.event_bus.subscribe("consensus.block_finalized", Box::new(|event| {
            let future = async move {
                info!("Block finalized: {:?}", event);
                // Commit to blockchain
                // Update state
                Ok(())
            };
            Box::pin(future) as Pin<Box<dyn futures::Future<Output = Result<()>> + Send>>
        })).await?;

        Ok(())
    }

    /// Register a component with the integration layer
    pub async fn register_component(&self, component: Arc<dyn Component>) -> Result<()> {
        let component_id = component.id();
        info!("Registering component: {}", component_id);

        // Register with component manager
        self.component_manager.register_component(component.clone()).await?;

        // Register with service container
        self.service_container.register_component(component_id.clone(), component).await?;

        // Setup component-specific integrations
        self.setup_component_integration(component_id.clone()).await?;

        info!("Component {} registered successfully", component_id);
        Ok(())
    }

    /// Setup integration for a specific component
    async fn setup_component_integration(&self, component_id: ComponentId) -> Result<()> {
        match component_id {
            ComponentId::Crypto => {
                // Setup crypto-specific integrations
                // Connect to identity, storage, network
            }
            ComponentId::Network => {
                // Setup network-specific integrations
                // Connect to all components for communication
            }
            ComponentId::Blockchain => {
                // Setup blockchain-specific integrations
                // Connect to crypto, consensus, storage, economics
            }
            ComponentId::Storage => {
                // Setup storage-specific integrations
                // Connect to crypto, blockchain, network
            }
            ComponentId::Identity => {
                // Setup identity-specific integrations
                // Connect to crypto, blockchain, economics
            }
            ComponentId::Economics => {
                // Setup economics-specific integrations
                // Connect to blockchain, identity, consensus
            }
            ComponentId::Consensus => {
                // Setup consensus-specific integrations
                // Connect to blockchain, network, identity
            }
            ComponentId::ZK => {
                // Setup ZK-specific integrations
                // Connect to crypto, identity, blockchain
            }
            ComponentId::Protocols => {
                // Setup protocols-specific integrations
                // Connect to network, storage, economics
            }
            ComponentId::Api => {
                // Setup API-specific integrations
                // Connect to all components for API endpoints
            }
        }

        Ok(())
    }

    /// Get component dependencies
    pub async fn get_component_dependencies(&self, component_id: ComponentId) -> Result<Vec<ComponentId>> {
        Ok(match component_id {
            ComponentId::Crypto => vec![], // No dependencies - foundation layer
            ComponentId::ZK => vec![ComponentId::Crypto],
            ComponentId::Identity => vec![ComponentId::Crypto, ComponentId::ZK],
            ComponentId::Storage => vec![ComponentId::Crypto, ComponentId::Identity],
            ComponentId::Network => vec![ComponentId::Crypto, ComponentId::Identity],
            ComponentId::Blockchain => vec![
                ComponentId::Crypto, 
                ComponentId::Storage, 
                ComponentId::Identity
            ],
            ComponentId::Consensus => vec![
                ComponentId::Crypto, 
                ComponentId::Network, 
                ComponentId::Blockchain,
                ComponentId::Identity
            ],
            ComponentId::Economics => vec![
                ComponentId::Blockchain, 
                ComponentId::Identity, 
                ComponentId::Consensus
            ],
            ComponentId::Protocols => vec![
                ComponentId::Network, 
                ComponentId::Storage, 
                ComponentId::Economics
            ],
            ComponentId::Api => vec![
                ComponentId::Identity,
                ComponentId::Blockchain, 
                ComponentId::Storage,
                ComponentId::Protocols
            ],
        })
    }

    /// Validate component dependencies
    pub async fn validate_dependencies(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();
        let components = self.component_manager.get_registered_components().await?;

        for component_id in components {
            let dependencies = self.get_component_dependencies(component_id.clone()).await?;
            
            for dependency in dependencies {
                if !self.component_manager.is_component_registered(&dependency).await? {
                    issues.push(format!(
                        "Component {} requires dependency {} which is not registered",
                        component_id, dependency
                    ));
                }
            }
        }

        Ok(issues)
    }

    /// Start all components in dependency order
    pub async fn start_all_components(&self) -> Result<()> {
        info!(" Starting all components in dependency order...");

        // Get dependency-sorted component order
        let startup_order = self.get_startup_order().await?;

        for component_id in startup_order {
            if let Some(component) = self.component_manager.get_component(&component_id).await? {
                info!(" Starting component: {}", component_id);
                component.start().await
                    .with_context(|| format!("Failed to start component {}", component_id))?;
                
                // Emit component started event
                self.event_bus.publish(&format!("component.{}.started", component_id), 
                    serde_json::json!({"component": component_id.to_string()})).await?;
            }
        }

        info!("All components started successfully");
        Ok(())
    }

    /// Get the correct startup order based on dependencies
    pub async fn get_startup_order(&self) -> Result<Vec<ComponentId>> {
        // Topological sort of dependencies
        Ok(vec![
            ComponentId::Crypto,      // Foundation
            ComponentId::ZK,          // Zero-knowledge system
            ComponentId::Identity,    // Identity management
            ComponentId::Storage,     // Distributed storage
            ComponentId::Network,     // Mesh networking
            ComponentId::Blockchain,  // Blockchain layer
            ComponentId::Consensus,   // Consensus mechanism
            ComponentId::Economics,   // Economic incentives
            ComponentId::Protocols,   // High-level protocols
        ])
    }

    /// Health check for integration layer
    pub async fn health_check(&self) -> Result<IntegrationHealth> {
        let service_container_health = self.service_container.health_check().await?;
        let event_bus_health = self.event_bus.health_check().await?;
        let component_manager_health = self.component_manager.health_check().await?;
        let dependency_issues = self.validate_dependencies().await?;

        let overall_healthy = service_container_health && 
                             event_bus_health && 
                             component_manager_health && 
                             dependency_issues.is_empty();

        Ok(IntegrationHealth {
            overall_healthy,
            service_container_healthy: service_container_health,
            event_bus_healthy: event_bus_health,
            component_manager_healthy: component_manager_health,
            dependency_issues,
            registered_components: self.component_manager.get_registered_components().await?,
        })
    }
}

/// Integration layer health status
#[derive(Debug, Clone)]
pub struct IntegrationHealth {
    pub overall_healthy: bool,
    pub service_container_healthy: bool,
    pub event_bus_healthy: bool,
    pub component_manager_healthy: bool,
    pub dependency_issues: Vec<String>,
    pub registered_components: Vec<ComponentId>,
}
