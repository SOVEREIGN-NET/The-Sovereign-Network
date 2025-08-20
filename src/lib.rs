pub mod blockchain;
pub mod browser;
pub mod config;
pub mod contracts;
pub mod network;
pub mod storage;
pub mod utils;
pub mod zhtp;
pub mod discovery;
pub mod input_validation; // Input validation module
pub mod security_monitor; // Production security monitoring
pub mod health_monitor;   // Production health monitoring
pub mod api_server;       // Production API server with security
pub mod auth;             // Authentication and authorization
pub mod tls;              // TLS/HTTPS security
pub mod security_middleware; // Security middleware
pub mod audit;            // Audit logging
pub mod errors;           // Secure error handling

// Backward compatibility consensus module alias
pub mod consensus {
    pub use crate::zhtp::consensus_engine::{
        ZkNetworkMetrics, ZhtpConsensusEngine, ZkValidator, ZkBlock
    };
}

pub use blockchain::{Block, Blockchain, Transaction, ZkBlockchainStats};
pub use zhtp::{
    consensus_engine::{ZhtpConsensusEngine, ZkValidator, ZkBlock, ZkNetworkMetrics},
    zk_transactions::{ZkTransaction, ZkBalance, ZkTransactionPool},
};
pub use network::{Network, NetworkCondition, NetworkId, Node, Packet};
pub use storage::{
    dht::{DhtNode, DhtNetwork as StorageManager},
    StorageConfig,
    ZhtpStorageManager,
    ContentMetadata,
    ContentId,
};
// Re-export key types
pub use std::sync::Arc;
pub use tokio::sync::Mutex;

// Re-export key components
pub use zhtp::{
    Keypair, ZhtpNode, ZhtpPacket, SharedNode,
    economics::{ZhtpEconomics, EconomicMetrics, TokenSupply, RewardPool, FeeMarket},
};
pub use browser::ZhtpBrowser;
pub use contracts::ContractExecutor;
pub use api_server::{ZhtpApiServer, ApiConfig, ApiServerState};
pub use auth::{AuthSystem, AuthConfig, UserRole, Permission};
pub use security_monitor::ZhtpSecurityMonitor;
pub use health_monitor::ZhtpHealthMonitor;
pub use audit::AuditTrail;
pub use tls::{ZhtpTlsManager, TlsConfig};
pub use errors::{ZhtpError, ZhtpResult};

#[cfg(test)]
mod tests {
}

#[cfg(test)]
pub mod integration_tests;
