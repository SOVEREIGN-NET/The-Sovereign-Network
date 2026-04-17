//! ZHTP Library Interface
//!
//! Public exports and integration patterns for the ZHTP node orchestrator

use std::path::PathBuf;
use std::sync::OnceLock;

/// Global node data directory — set once at startup from --data-dir arg or home_dir default.
/// All components that need the data path must read from here instead of calling
/// dirs::home_dir() directly, so the path is consistent regardless of how the OS
/// home directory is configured for the service account.
static NODE_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Set the global node data directory. Must be called once from main() before
/// any components start. Panics if called more than once.
pub fn set_node_data_dir(path: PathBuf) {
    NODE_DATA_DIR.set(path).expect("NODE_DATA_DIR already set");
}

/// Get the global node data directory. Falls back to ~/.zhtp if not set (tests/dev).
pub fn node_data_dir() -> PathBuf {
    NODE_DATA_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .map(|d| d.join(".zhtp"))
                .unwrap_or_else(|| PathBuf::from(".zhtp"))
        })
}

pub mod config;
pub mod integration;
pub mod monitoring;
pub mod pouw;
pub mod rewards;
pub mod runtime; // Proof-of-Useful-Work (Phase 1: Challenge Generation)
                 // CLI module moved to separate zhtp-cli crate
pub mod api;
pub mod discovery_coordinator;
pub mod keyfile_names;
pub use keyfile_names as keystore_names;
pub mod network_output_dispatcher;
pub mod security;
pub mod server;
pub mod session_manager;
pub mod storage_network_integration;
pub mod unified_server;
pub mod utils;
pub mod web4_manifest;
pub mod web4_stub;

// Re-export key types for external use
pub use api::{
    BlockchainHandler, IdentityHandler, MiddlewareStack, ProtocolHandler, StorageHandler,
    ZhtpServer,
};
pub use config::{CliArgs, Environment, MeshMode, NodeConfig, SecurityLevel};
pub use discovery_coordinator::{
    DiscoveredPeer, DiscoveryCoordinator, DiscoveryProtocol, DiscoveryStrategy,
};
pub use integration::{EventBus, IntegrationManager, ServiceContainer};
pub use monitoring::{HealthStatus as MonitoringHealth, MonitoringSystem, SystemMetrics};
pub use runtime::{Component, ComponentId, ComponentStatus, RuntimeOrchestrator};
pub use security::{Protocol, ProtocolFilter};
pub use server::IncomingProtocol;
pub use session_manager::SessionManager;
pub use unified_server::ZhtpUnifiedServer;

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
