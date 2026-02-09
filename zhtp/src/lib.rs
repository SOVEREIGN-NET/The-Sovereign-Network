//! ZHTP Library Interface
//! 
//! Public exports and integration patterns for the ZHTP node orchestrator

pub mod config;
pub mod runtime;
pub mod monitoring;
pub mod integration;
pub mod pouw; // Proof-of-Useful-Work (Phase 1: Challenge Generation)
pub mod ren_ai; // Ren AI LLM inference service node
// CLI module moved to separate zhtp-cli crate
pub mod api;
pub mod server;
pub mod unified_server;
pub mod session_manager;
pub mod security;
pub mod discovery_coordinator;
pub mod utils;
pub mod network_output_dispatcher;
pub mod storage_network_integration;
pub mod web4_stub;
pub mod web4_manifest;
pub mod keystore_names;

// Re-export key types for external use
pub use config::{NodeConfig, CliArgs, Environment, MeshMode, SecurityLevel};
pub use runtime::{RuntimeOrchestrator, ComponentStatus, ComponentId, Component};
pub use monitoring::{MonitoringSystem, SystemMetrics, HealthStatus as MonitoringHealth};
pub use integration::{IntegrationManager, ServiceContainer, EventBus};
pub use api::{ZhtpServer, IdentityHandler, BlockchainHandler, StorageHandler, ProtocolHandler, MiddlewareStack};
pub use unified_server::ZhtpUnifiedServer;
pub use server::IncomingProtocol;
pub use session_manager::SessionManager;
pub use security::{Protocol, ProtocolFilter};
pub use discovery_coordinator::{DiscoveryCoordinator, DiscoveryProtocol, DiscoveryStrategy, DiscoveredPeer};

/// ZHTP node version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum number of concurrent package operations
pub const MAX_CONCURRENT_OPERATIONS: usize = 11;

/// Default mesh networking port
pub const DEFAULT_MESH_PORT: u16 = 33444;

/// Default configuration file path
pub const DEFAULT_CONFIG_PATH: &str = "lib-node.toml";

/// ZHTP protocol magic bytes for network identification
pub const ZHTP_MAGIC: [u8; 4] = [0x5A, 0x48, 0x54, 0x50]; // "ZHTP"

/// Node initialization result
#[derive(Debug)]
pub enum InitializationResult {
    Success,
    PartialFailure(Vec<String>),
    Failure(String),
}

/// Component health status
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Critical,
    Offline,
}

/// Main error types for ZHTP node operations
#[derive(thiserror::Error, Debug)]
pub enum ZhtpError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Component initialization failed: {0}")]
    ComponentInit(String),
    
    #[error("Runtime orchestration error: {0}")]
    Runtime(String),
    
    #[error("Integration error between packages: {0}")]
    Integration(String),
    
    #[error("Monitoring system error: {0}")]
    Monitoring(String),
    
    #[error("Network coordination error: {0}")]
    Network(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
